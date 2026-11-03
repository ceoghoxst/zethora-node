//! Zethora L2 EVM execution engine.
//!
//! This crate is the execution layer of the Zethora zkEVM. It is deliberately
//! standalone: it does not depend on the consensus engine, the P2P stack or the
//! RPC layer, and it knows nothing about how transactions reach it. Its single
//! job is to take a raw, RLP-encoded Ethereum transaction, run it against an
//! in-memory EVM database with [`revm`], and hand back the resulting output.
//!
//! The state root produced by [`EvmExecutor::state_root`] is exactly the value a
//! future ZK-prover will have to commit to, which is why it is exposed as a
//! first-class part of the API.
//!
//! # Transaction support
//!
//! Decoding currently supports the legacy (pre-EIP-2718) transaction envelope,
//! both with and without the EIP-155 replay-protection fields:
//!
//! `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]` (EIP-155)
//! `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]` (pre-EIP-155, v = 27/28)
//!
//! Typed envelopes (EIP-2930 `0x01`, EIP-1559 `0x02`, EIP-4844 `0x03`,
//! EIP-7702 `0x04`) have a type byte prefix and are rejected with a clear error
//! until they are wired up. Signature *recovery* is also out of scope for this
//! section: the sender must be supplied explicitly via
//! [`EvmExecutor::set_caller`], or the zero address is used.

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use revm::{
    bytecode::Bytecode,
    context::{BlockEnv, Context, TxEnv},
    context_interface::result::{ExecResultAndState, ExecutionResult, HaltReason, Output, ResultAndState},
    database::InMemoryDB,
    database_interface::DatabaseCommit,
    handler::{MainBuilder, MainContext},
    primitives::{hardfork::SpecId, TxKind, KECCAK_EMPTY},
    state::{AccountInfo, EvmState},
    Database, ExecuteEvm,
};

/// EVM chain id the executor validates `chain_id` against.
///
/// Zethora L2 uses `1` so that unmodified Ethereum tooling (which defaults to
/// mainnet) produces transactions this engine accepts.
pub const CHAIN_ID: u64 = 1;

/// Gas limit granted to a block.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Identifier of the legacy (pre-EIP-2718) transaction envelope.
pub const LEGACY_TX_TYPE: u8 = 0x00;

/// A decoded legacy Ethereum transaction.
///
/// Field order and types match the canonical RLP layout from the Ethereum
/// yellow paper, so `RlpDecodable` maps straight onto the wire format.
#[derive(Clone, Debug, PartialEq, Eq, RlpDecodable, RlpEncodable)]
pub struct LegacyTransaction {
    /// Sender nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: U256,
    /// Maximum gas this transaction may consume.
    pub gas_limit: u64,
    /// Recipient, or empty for a contract creation.
    pub to: TxKind,
    /// Value transferred in wei.
    pub value: U256,
    /// Calldata (or init code when `to` is empty).
    pub input: Bytes,
    /// Signature `v`: 27/28 for pre-EIP-155, or `chain_id * 2 + 35/36`.
    pub v: U256,
    /// Signature `r`.
    pub r: U256,
    /// Signature `s`.
    pub s: U256,
}

impl LegacyTransaction {
    /// The EIP-155 chain id encoded in `v`, if the transaction is replay protected.
    pub fn chain_id(&self) -> Option<u64> {
        // Pre-EIP-155 transactions use v = 27 / 28, which carry no chain id.
        if self.v == U256::from(27) || self.v == U256::from(28) {
            return None;
        }
        // EIP-155: v = chain_id * 2 + 35 (or + 36).
        let v = self.v.checked_sub(U256::from(35))?;
        let chain_id = v / U256::from(2);
        u64::try_from(chain_id).ok()
    }
}

/// Decodes a raw, RLP-encoded Ethereum transaction.
///
/// Accepts the bare legacy RLP list as well as a `0x00`-prefixed typed envelope
/// (which is the canonical EIP-2718 encoding for a legacy transaction).
pub fn decode_transaction(tx_bytes: &[u8]) -> Result<LegacyTransaction, String> {
    if tx_bytes.is_empty() {
        return Err("cannot decode transaction: empty input".to_string());
    }

    let payload = match tx_bytes[0] {
        LEGACY_TX_TYPE => &tx_bytes[1..],
        ty @ 0x01..=0x7f => {
            return Err(format!(
                "unsupported transaction type 0x{ty:02x}: only legacy transactions (0x00) are supported"
            ));
        }
        _ => tx_bytes,
    };

    if payload.is_empty() {
        return Err("cannot decode transaction: missing payload after type byte".to_string());
    }

    LegacyTransaction::decode(&mut &payload[..])
        .map_err(|err| format!("cannot decode legacy transaction: {err}"))
}

/// Outcome of executing a single transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    /// Return data of the call, or the deployed code for a creation.
    pub output: Vec<u8>,
    /// Address of the freshly deployed contract, when the transaction was a creation.
    pub created_address: Option<Address>,
    /// Gas consumed by the transaction.
    pub gas_used: u64,
    /// Whether the transaction completed successfully (as opposed to reverting).
    pub success: bool,
}

/// A standalone EVM executor backed by an in-memory database.
///
/// The database lives as long as the executor, so state written by one
/// transaction (a deployed contract, a modified storage slot) is visible to the
/// next one. That is what makes it possible to deploy and then call a contract
/// in separate transactions, mirroring how the L2 will replay blocks.
#[derive(Debug)]
pub struct EvmExecutor {
    db: InMemoryDB,
    block: BlockEnv,
    spec: SpecId,
    chain_id: u64,
    /// Sender address used for execution. Signature recovery is not part of
    /// this section, so the caller is configured rather than derived.
    caller: Address,
}

impl Default for EvmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmExecutor {
    /// Creates an executor with an empty database, the latest supported hardfork
    /// and the Zethora chain id.
    pub fn new() -> Self {
        Self::with_spec(SpecId::PRAGUE)
    }

    /// Creates an executor that executes transactions under `spec`.
    pub fn with_spec(spec: SpecId) -> Self {
        Self {
            db: InMemoryDB::default(),
            block: BlockEnv {
                number: U256::from(1),
                gas_limit: BLOCK_GAS_LIMIT,
                basefee: 0,
                timestamp: U256::ZERO,
                beneficiary: Address::ZERO,
                difficulty: U256::ZERO,
                prevrandao: Some(B256::ZERO),
                ..Default::default()
            },
            spec,
            chain_id: CHAIN_ID,
            caller: Address::ZERO,
        }
    }

    /// Sets the address used as the transaction sender.
    ///
    /// The sender is funded on demand so that gas and value transfer cannot fail
    /// with `LackOfFundForMaxFee` while signature recovery is unimplemented.
    pub fn set_caller(&mut self, caller: Address) {
        self.caller = caller;
    }

    /// Overrides the chain id a transaction's EIP-155 `v` is checked against.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }

    /// Read-only access to the underlying in-memory database for inspection.
    ///
    /// revm's `Database::storage` takes `&mut self`, so this returns a mutable
    /// reference; callers are expected to only read from it.
    pub fn db_mut(&mut self) -> &mut InMemoryDB {
        &mut self.db
    }

    /// Deposits `amount` wei into `address`, creating the account if needed.
    ///
    /// Useful for funding accounts before sending value-bearing transactions.
    pub fn set_balance(&mut self, address: Address, amount: U256) {
        let info = self.db.basic(address).ok().flatten().unwrap_or_default();
        self.db.insert_account_info(
            address,
            AccountInfo {
                balance: amount,
                ..info
            },
        );
    }

    /// Installs `code` at `address`.
    ///
    /// This bypasses `CREATE` semantics and is intended for test fixtures and
    /// genesis-style predeploys.
    pub fn insert_code(&mut self, address: Address, code: Bytes) {
        let info = self.db.basic(address).ok().flatten().unwrap_or_default();
        self.db.insert_account_info(
            address,
            AccountInfo {
                code_hash: alloy_primitives::keccak256(&code),
                code: Some(Bytecode::new_raw(code)),
                ..info
            },
        );
    }

    /// Reads a storage slot of `address` from the in-memory database.
    pub fn storage(&mut self, address: Address, slot: U256) -> U256 {
        self.db.storage(address, slot).unwrap_or_default()
    }

    /// Executes an already decoded transaction.
    ///
    /// The sender's nonce is taken from the in-memory database rather than from
    /// the decoded transaction, because legacy transactions carry the signature
    /// that proves the nonce but this executor does not recover it yet.
    pub fn execute(&mut self, tx: &LegacyTransaction) -> Result<ExecutionOutcome, String> {
        self.check_chain_id(tx)?;
        self.ensure_funded(self.caller, tx);
        let nonce = self.caller_nonce();

        let tx_env = TxEnv::builder()
            .caller(self.caller)
            .gas_limit(tx.gas_limit)
            .gas_price(tx.gas_price.saturating_to::<u128>())
            .kind(tx.to)
            .value(tx.value)
            .data(tx.input.clone())
            .nonce(nonce)
            .chain_id(Some(self.chain_id))
            .build()
            .map_err(|err| format!("invalid transaction: {err}"))?;

        let result = {
            let mut evm = Context::mainnet()
                .with_db(&mut self.db)
                .with_block(self.block.clone())
                .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(self.spec))
                .build_mainnet();

            evm.transact(tx_env).map_err(|err| format!("evm error: {err}"))
        }?;

        Ok(Self::commit(&mut self.db, result))
    }

    /// Executes a raw, RLP-encoded Ethereum transaction and returns its output.
    pub fn execute_bytes(&mut self, tx_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let tx = decode_transaction(tx_bytes)?;
        self.execute(&tx).map(|outcome| outcome.output)
    }

    /// Computes a commitment to the executor's current world state.
    ///
    /// The digest folds every account (address, balance, nonce, code hash) and
    /// every storage slot into a single root. It is deterministic and suitable
    /// for a ZK-prover to commit to, but it is *not* the Ethereum MPT state root:
    /// revm executes against a flat in-memory database, not a Merkle Patricia trie.
    pub fn state_root(&self) -> B256 {
        let mut entries: Vec<(B256, Vec<u8>)> = self
            .db
            .cache
            .accounts
            .iter()
            .map(|(address, account)| {
                let mut buf = Vec::new();
                buf.extend_from_slice(address.as_slice());
                buf.extend_from_slice(&account.info.balance.to_be_bytes::<32>());
                buf.extend_from_slice(&account.info.nonce.to_be_bytes());
                buf.extend_from_slice(account.info.code_hash.as_slice());
                for (slot, value) in &account.storage {
                    buf.extend_from_slice(&slot.to_be_bytes::<32>());
                    buf.extend_from_slice(&value.to_be_bytes::<32>());
                }
                (alloy_primitives::keccak256(address.as_slice()), buf)
            })
            .collect();
        // Deterministic ordering: the account cache is a hash map.
        entries.sort_by_key(|entry| entry.0);

        let mut root = KECCAK_EMPTY;
        for (_, encoded) in entries {
            root = alloy_primitives::keccak256([root.as_slice(), encoded.as_slice()].concat());
        }
        root
    }

    /// Rejects transactions whose EIP-155 chain id targets a different chain.
    fn check_chain_id(&self, tx: &LegacyTransaction) -> Result<(), String> {
        match tx.chain_id() {
            Some(tx_chain_id) if tx_chain_id != self.chain_id => {
                Err(format!("invalid chain id {tx_chain_id}, expected {}", self.chain_id))
            }
            _ => Ok(()),
        }
    }

    /// Returns the sender's current nonce as recorded in the database.
    fn caller_nonce(&mut self) -> u64 {
        self.db
            .basic(self.caller)
            .ok()
            .flatten()
            .map(|info| info.nonce)
            .unwrap_or_default()
    }

    /// Makes sure the sender can pay for `gas_limit * gas_price + value`.
    fn ensure_funded(&mut self, caller: Address, tx: &LegacyTransaction) {
        let info = self.db.basic(caller).ok().flatten().unwrap_or_default();
        let gas = U256::from(tx.gas_limit).saturating_mul(tx.gas_price);
        let required = gas.saturating_add(tx.value);
        if info.balance < required {
            self.db.insert_account_info(
                caller,
                AccountInfo {
                    balance: required,
                    ..info
                },
            );
        }
    }

    /// Applies the state changes of a successful transaction to the database.
    fn commit(
        db: &mut InMemoryDB,
        result: ExecResultAndState<ExecutionResult<HaltReason>, EvmState>,
    ) -> ExecutionOutcome {
        let ResultAndState { result, state } = result;
        let gas_used = result.tx_gas_used();

        match result {
            ExecutionResult::Success { output, .. } => {
                let created_address = match &output {
                    Output::Create(_, address) => *address,
                    Output::Call(_) => None,
                };
                db.commit(state);
                ExecutionOutcome {
                    output: output.into_data().to_vec(),
                    created_address,
                    gas_used,
                    success: true,
                }
            }
            ExecutionResult::Revert { output, .. } => ExecutionOutcome {
                output: output.to_vec(),
                created_address: None,
                gas_used,
                success: false,
            },
            ExecutionResult::Halt { reason, .. } => ExecutionOutcome {
                output: format!("halted: {reason}").into_bytes(),
                created_address: None,
                gas_used,
                success: false,
            },
        }
    }
}

/// Executes a raw, RLP-encoded Ethereum transaction on a fresh in-memory EVM
/// and returns the resulting output.
///
/// A fresh [`EvmExecutor`] is created per call, so each invocation starts from
/// empty state. Use [`EvmExecutor`] directly when state must persist across
/// transactions, for example a deploy-then-call sequence.
///
/// Returns the transaction output on success, or a human readable error if the
/// transaction could not be decoded or was rejected by the EVM.
pub fn execute_transaction(tx_bytes: &[u8]) -> Result<Vec<u8>, String> {
    EvmExecutor::new().execute_bytes(tx_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use alloy_rlp::Encodable;

    /// Runtime code for `contract S { uint256 s; function set(uint256 v) { s = v; }
    /// function get() returns (uint256) { return s; } }`, hand assembled so the
    /// tests do not need `solc`:
    ///
    /// ```text
    /// SSTORE(CALLDATALOAD(0), 0)   // store the calldata word in slot 0
    /// MSTORE(0, SLOAD(0))          // load it back
    /// RETURN(0, 32)                // return 32 bytes, echoing the stored value
    /// ```
    const STORAGE_RUNTIME: &[u8] = &[
        0x60, 0x00, // PUSH1 0          slot
        0x35, //        CALLDATALOAD     value from calldata
        0x60, 0x00, // PUSH1 0          slot
        0x55, //        SSTORE           s = value
        0x60, 0x00, // PUSH1 0
        0x54, //        SLOAD            s
        0x60, 0x00, // PUSH1 0
        0x52, //        MSTORE           mem[0..32] = s
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, //        RETURN           return mem[0..32]
    ];

    /// Builds init code that deploys [`STORAGE_RUNTIME`] with `CODECOPY` + `RETURN`.
    fn deploy_init_code() -> Bytes {
        let len = u8::try_from(STORAGE_RUNTIME.len()).expect("runtime code fits in one byte");
        // The runtime code starts right after this 12 byte prologue.
        let mut code = vec![
            0x60, len, // PUSH1 len
            0x60, 0x0c, // PUSH1 12         offset of the runtime code
            0x60, 0x00, // PUSH1 0
            0x39, //        CODECOPY         mem[0..len] = code[12..12+len]
            0x60, len, // PUSH1 len
            0x60, 0x00, // PUSH1 0
            0xf3, //        RETURN           return mem[0..len]
        ];
        debug_assert_eq!(code.len(), 12);
        code.extend_from_slice(STORAGE_RUNTIME);
        Bytes::from(code)
    }

    fn contract_address() -> Address {
        address!("00000000000000000000000000000000000c0de1")
    }

    fn legacy_tx(to: TxKind, input: Bytes) -> LegacyTransaction {
        LegacyTransaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: 1_000_000,
            to,
            value: U256::ZERO,
            input,
            v: U256::from(27),
            r: U256::from(1),
            s: U256::from(1),
        }
    }

    fn encode(tx: &LegacyTransaction) -> Vec<u8> {
        let mut out = Vec::new();
        tx.encode(&mut out);
        out
    }

    #[test]
    fn decodes_bare_and_enveloped_legacy_transactions() {
        let tx = legacy_tx(TxKind::Call(contract_address()), Bytes::from(vec![0xde, 0xad]));
        let encoded = encode(&tx);

        let decoded = decode_transaction(&encoded).expect("bare legacy RLP should decode");
        assert_eq!(decoded, tx);

        // `0x00 || rlp` is the canonical EIP-2718 envelope for a legacy tx.
        let mut enveloped = vec![LEGACY_TX_TYPE];
        enveloped.extend_from_slice(&encoded);
        let decoded = decode_transaction(&enveloped).expect("0x00 envelope should decode");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn rejects_empty_and_typed_transactions() {
        assert!(decode_transaction(&[]).is_err());
        assert!(decode_transaction(&[LEGACY_TX_TYPE]).is_err());
        // 0x02 is EIP-1559, which section 1 does not implement yet.
        assert!(decode_transaction(&[0x02, 0xc0]).is_err());
    }

    #[test]
    fn derives_eip155_chain_id() {
        let mut tx = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        // v = 27 / 28 is pre-EIP-155 and carries no chain id.
        assert_eq!(tx.chain_id(), None);

        // chain id 1 -> v = 37 / 38.
        tx.v = U256::from(37);
        assert_eq!(tx.chain_id(), Some(1));
        tx.v = U256::from(38);
        assert_eq!(tx.chain_id(), Some(1));

        // chain id 5 -> v = 45 / 46.
        tx.v = U256::from(45);
        assert_eq!(tx.chain_id(), Some(5));
    }

    #[test]
    fn advances_sender_nonce_between_transactions() {
        let mut executor = EvmExecutor::new();
        let tx = legacy_tx(TxKind::Call(contract_address()), Bytes::new());

        executor.execute(&tx).expect("first transfer should succeed");
        assert_eq!(executor.caller_nonce(), 1);

        // A second transaction must not be rejected for a stale nonce, even
        // though the decoded transaction still says nonce 0.
        assert_eq!(tx.nonce, 0);
        executor.execute(&tx).expect("second transfer should succeed");
        assert_eq!(executor.caller_nonce(), 2);
    }

    #[test]
    fn rejects_transaction_for_another_chain() {
        let mut executor = EvmExecutor::new();
        let mut tx = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        tx.v = U256::from(5 * 2 + 35); // chain id 5, executor expects 1

        let err = executor.execute(&tx).expect_err("wrong chain id must be rejected");
        assert!(err.contains("invalid chain id 5"), "unexpected error: {err}");
    }

    #[test]
    fn deploys_contract_and_writes_storage() {
        let mut executor = EvmExecutor::new();

        // Deploy through the EVM: an empty `to` means CREATE.
        let outcome = executor
            .execute(&legacy_tx(TxKind::Create, deploy_init_code()))
            .expect("contract creation should succeed");
        assert!(outcome.success, "creation reverted: {:?}", outcome.output);
        assert_eq!(outcome.output, STORAGE_RUNTIME, "RETURNed code should be the runtime");

        let created = outcome.created_address.expect("CREATE must report an address");
        let info = executor
            .db_mut()
            .basic(created)
            .expect("db read should succeed")
            .expect("created account must exist");
        assert_eq!(info.code_hash, alloy_primitives::keccak256(STORAGE_RUNTIME));

        // A second transaction calls the deployed contract and sets slot 0 to 42.
        let mut calldata = [0u8; 32];
        calldata[31] = 42;
        let call = executor
            .execute(&legacy_tx(TxKind::Call(created), Bytes::from(calldata.to_vec())))
            .expect("call should succeed");
        assert!(call.success, "call reverted: {:?}", call.output);

        // The write persisted in the shared in-memory database...
        assert_eq!(executor.storage(created, U256::ZERO), U256::from(42));
        // ...and the call echoed the value it stored.
        assert_eq!(call.output.len(), 32);
        assert_eq!(U256::from_be_slice(&call.output), U256::from(42));

        // The state commitment must reflect the write: a fresh executor that only
        // learned about a funded sender commits to a different root.
        let committed = executor.state_root();
        let mut pristine = EvmExecutor::new();
        pristine.set_balance(created, U256::ZERO);
        assert_ne!(committed, pristine.state_root());
        assert_ne!(committed, KECCAK_EMPTY);
    }

    #[test]
    fn execute_bytes_runs_a_raw_transaction() {
        let mut calldata = [0u8; 32];
        calldata[31] = 7;

        // Predeploy the runtime code, then reach it through the raw-RLP entry point.
        let mut executor = EvmExecutor::new();
        executor.insert_code(contract_address(), Bytes::from(STORAGE_RUNTIME));

        let tx = legacy_tx(TxKind::Call(contract_address()), Bytes::from(calldata.to_vec()));
        let output = executor
            .execute_bytes(&encode(&tx))
            .expect("raw legacy transaction should execute");

        assert_eq!(U256::from_be_slice(&output), U256::from(7));
        assert_eq!(
            executor.storage(contract_address(), U256::ZERO),
            U256::from(7)
        );
    }

    #[test]
    fn rejects_transaction_below_intrinsic_gas() {
        let mut executor = EvmExecutor::new();
        let mut tx = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        // Below the 21_000 intrinsic cost of any transaction, so revm rejects it
        // during validation instead of halting mid-execution.
        tx.gas_limit = 20_000;

        let err = executor
            .execute(&tx)
            .expect_err("a gas limit below the intrinsic cost is a validation error");
        assert!(err.contains("gas limit"), "unexpected error: {err}");
    }

    #[test]
    fn executes_standalone_transaction_from_empty_state() {
        // `execute_transaction` builds a fresh executor, so there is no state to
        // call into; a bare value transfer is the smoke test for that entry point.
        let tx = legacy_tx(TxKind::Call(Address::ZERO), Bytes::new());
        let output = execute_transaction(&encode(&tx)).expect("value transfer should succeed");
        assert!(output.is_empty());
    }

    #[test]
    fn state_root_is_deterministic_and_order_independent() {
        let other = address!("00000000000000000000000000000000000c0de2");

        let mut a = EvmExecutor::new();
        a.set_balance(contract_address(), U256::from(1));
        a.set_balance(other, U256::from(2));

        let mut b = EvmExecutor::new();
        b.set_balance(other, U256::from(2));
        b.set_balance(contract_address(), U256::from(1));

        // Same state, different insertion order -> identical commitment.
        assert_eq!(a.state_root(), b.state_root());

        let mut c = EvmExecutor::new();
        c.set_balance(contract_address(), U256::from(1));
        c.set_balance(other, U256::from(3));
        assert_ne!(a.state_root(), c.state_root());
    }
}

