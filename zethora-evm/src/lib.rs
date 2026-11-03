//! Zethora L2 EVM execution engine.
//!
//! This crate is the execution layer of the Zethora zkEVM. It is deliberately
//! standalone: it does not depend on the consensus engine, the P2P stack or the
//! RPC layer, and it knows nothing about how transactions reach it. Its job is
//! to take a raw, RLP-encoded Ethereum transaction, run it against an in-memory
//! EVM database with [`revm`], and hand back the resulting output.
//!
//! The state root produced by [`EvmExecutor::state_root`] is the value a future
//! ZK-prover has to commit to, which is why it is a first-class part of the API.
//!
//! # Transaction support
//!
//! Decoding is delegated wholesale to [`TxEnvelope`], the EIP-2718 envelope type
//! from `alloy-consensus`. That one type natively understands every Ethereum
//! envelope, so the executor never hand-rolls RLP parsing. Two envelopes are
//! accepted:
//!
//! * legacy (pre-EIP-2718), both with and without EIP-155 replay protection:
//!   `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`, including the
//!   typed `0x00 || rlp` form;
//! * EIP-1559 (type `0x02`), which carries `max_fee_per_gas` /
//!   `max_priority_fee_per_gas` instead of a single gas price and always carries
//!   a `chain_id`.
//!
//! Everything else (`0x01`, `0x03`, `0x04`) is rejected at decode time, because
//! the executor cannot yet price or execute it correctly.
//!
//! # Sender authentication
//!
//! The sender is **never** supplied by the caller. It is recovered
//! cryptographically from the transaction signature by [`recover_sender`], and
//! the recovered address is the account revm charges gas to and checks the
//! nonce of. That closes the class of impersonation bugs where a caller could
//! name any sender it liked.
//!
//! Recovery deliberately goes through
//! [`SignerRecoverable::recover_signer`] on the envelope, not
//! `recover_signer_unchecked`, because the former enforces the
//! [EIP-2](https://eips.ethereum.org/EIPS/eip-2) low-`s` rule that makes
//! signatures non-malleable.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Signed, Transaction as ConsensusTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use revm::{
    bytecode::Bytecode,
    context::{BlockEnv, Context, TxEnv},
    context_interface::result::{
        ExecResultAndState, ExecutionResult, HaltReason, Output, ResultAndState,
    },
    database::InMemoryDB,
    database_interface::DatabaseCommit,
    handler::{MainBuilder, MainContext},
    primitives::{hardfork::SpecId, KECCAK_EMPTY},
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

/// Identifier of the EIP-1559 transaction envelope.
pub const EIP1559_TX_TYPE: u8 = 0x02;

/// Half of the secp256k1 group order, `floor(N / 2)`.
///
/// [EIP-2](https://eips.ethereum.org/EIPS/eip-2) requires a signature's `s`
/// component to be at most this value. Without that bound every signature has a
/// second, equally valid encoding `(r, N - s)`, so a transaction could be
/// re-broadcast with a different hash while expressing the same intent.
pub const SECP256K1N_HALF: U256 = U256::from_be_bytes(alloy_primitives::hex!(
    "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
));


/// A decoded, signature-bearing Ethereum transaction.
///
/// Only the envelopes the executor can price and execute are modelled. Typed
/// transactions that need state this engine does not model yet (EIP-2930 access
/// lists, EIP-4844 blob sidecars, EIP-7702 delegation lists) are rejected at
/// decode time.
///
/// The payload is kept as alloy's signed wrapper because that type owns sender
/// recovery: `Signed<TxLegacy>` and `Signed<TxEip1559>` each know how to
/// recompute their own signing hash and recover the address behind the
/// signature.
#[derive(Clone, Debug)]
pub enum Transaction {
    /// A legacy (pre-EIP-2718) transaction. Its EIP-155 chain id is derived from
    /// `v`, so it may legitimately have no chain id at all.
    Legacy(Signed<TxLegacy>),
    /// An EIP-1559 (type `0x02`) transaction.
    Eip1559(Signed<TxEip1559>),
}

impl Transaction {
    /// The chain id this transaction is bound to.
    ///
    /// `None` means the transaction predates EIP-155 and carries no replay
    /// protection, so it would be executable on any chain.
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Self::Legacy(tx) => tx.chain_id(),
            Self::Eip1559(tx) => tx.chain_id(),
        }
    }

    /// The sender nonce this transaction declares.
    ///
    /// This is the value the sender *claims*. It is only trusted once
    /// [`recover_sender`] has proven the sender owns the signature, after which
    /// revm additionally checks it against the account's real nonce.
    pub fn nonce(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.tx().nonce,
            Self::Eip1559(tx) => tx.tx().nonce,
        }
    }

    /// The maximum gas this transaction may consume.
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.tx().gas_limit,
            Self::Eip1559(tx) => tx.tx().gas_limit,
        }
    }

    /// Recipient, or [`TxKind::Create`] for a contract deployment.
    pub fn kind(&self) -> TxKind {
        match self {
            Self::Legacy(tx) => tx.tx().to,
            Self::Eip1559(tx) => tx.tx().to,
        }
    }

    /// Value transferred in wei.
    pub fn value(&self) -> U256 {
        match self {
            Self::Legacy(tx) => tx.tx().value,
            Self::Eip1559(tx) => tx.tx().value,
        }
    }

    /// Calldata, or init code for a deployment.
    pub fn input(&self) -> &Bytes {
        match self {
            Self::Legacy(tx) => &tx.tx().input,
            Self::Eip1559(tx) => &tx.tx().input,
        }
    }

    /// The gas price of a legacy transaction.
    ///
    /// For an EIP-1559 transaction this is the fee cap, `max_fee_per_gas`.
    pub fn max_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy(tx) => tx.tx().gas_price,
            Self::Eip1559(tx) => tx.tx().max_fee_per_gas,
        }
    }

    /// The EIP-1559 priority fee, or `None` for a legacy transaction.
    pub fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            Self::Legacy(_) => None,
            Self::Eip1559(tx) => Some(tx.tx().max_priority_fee_per_gas),
        }
    }

    /// The EIP-2718 transaction type byte.
    pub fn tx_type(&self) -> u8 {
        match self {
            Self::Legacy(_) => LEGACY_TX_TYPE,
            Self::Eip1559(_) => EIP1559_TX_TYPE,
        }
    }

    /// The signature attached to this transaction.
    pub fn signature(&self) -> Signature {
        match self {
            Self::Legacy(tx) => *tx.signature(),
            Self::Eip1559(tx) => *tx.signature(),
        }
    }

    /// The signing hash, i.e. the keccak256 digest the sender signed.
    ///
    /// Exposed so callers (and the Red Team suite) can verify exactly which
    /// prehash a signature commits to.
    pub fn signature_hash(&self) -> B256 {
        match self {
            Self::Legacy(tx) => tx.signature_hash(),
            Self::Eip1559(tx) => tx.signature_hash(),
        }
    }
}

/// Compares transactions by content, deliberately ignoring alloy's cached
/// signing hash.
///
/// `Signed<T>`'s own `PartialEq` also compares the `OnceLock` holding that hash.
/// A decoded transaction has an empty cache while a locally signed one has it
/// pre-filled, so the derived comparison would report two identical transactions
/// as different. Equality here means "same envelope, same fields, same
/// signature".
impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Legacy(a), Self::Legacy(b)) => {
                a.tx() == b.tx() && a.signature() == b.signature()
            }
            (Self::Eip1559(a), Self::Eip1559(b)) => {
                a.tx() == b.tx() && a.signature() == b.signature()
            }
            _ => false,
        }
    }
}

impl Eq for Transaction {}


/// Converts an already-decoded consensus envelope into a [`Transaction`].
///
/// This is the single funnel through which wire bytes become executable
/// transactions, so it is also where unsupported envelope types are refused.
fn from_envelope(envelope: TxEnvelope) -> Result<Transaction, String> {
    match envelope {
        // Each envelope variant already wraps the signed payload, so no
        // re-signing or hash recomputation is needed here.
        TxEnvelope::Legacy(signed) => Ok(Transaction::Legacy(signed)),
        TxEnvelope::Eip1559(signed) => Ok(Transaction::Eip1559(signed)),
        other => Err(format!(
            "unsupported transaction type 0x{:02x}: only legacy (0x00) and EIP-1559 (0x02) are supported",
            other.tx_type() as u8
        )),
    }
}

/// Decodes a raw, RLP-encoded Ethereum transaction.
///
/// Accepts a bare legacy list (no type prefix) as well as the canonical
/// EIP-2718 envelope form for both supported types: `0x00 || rlp` for legacy and
/// `0x02 || rlp` for EIP-1559.
pub fn decode_transaction(tx_bytes: &[u8]) -> Result<Transaction, String> {
    if tx_bytes.is_empty() {
        return Err("cannot decode transaction: empty input".to_string());
    }

    // EIP-2718 reserves every byte below 0x80 in the first position for
    // envelope type identifiers (>= 0x80 would start an RLP string, and a bare
    // legacy transaction starts with an RLP list, i.e. >= 0xc0). Checking the
    // type byte up front turns alloy's opaque "unexpected tx type" into an
    // error that names the offending type, and guarantees an unsupported
    // envelope can never be mistaken for something executable.
    let first = tx_bytes[0];
    if first < 0xc0 && first != LEGACY_TX_TYPE && first != EIP1559_TX_TYPE {
        return Err(format!(
            "unsupported transaction type 0x{first:02x}: only legacy (0x00) and EIP-1559 (0x02) are supported"
        ));
    }

    // `network_decode` resolves the ambiguity where a bare legacy list could be
    // mistaken for a `0x00` envelope, exactly as the network does.
    let envelope = TxEnvelope::network_decode(&mut &tx_bytes[..])
        .map_err(|err| format!("cannot decode transaction: {err}"))?;
    from_envelope(envelope)
}

/// Recovers the Ethereum address that signed `tx`.
///
/// This is the only place a sender enters the system. Recovery happens on the
/// `TxEnvelope` itself, via the built-in
/// [`SignerRecoverable::recover_signer`], which:
///
/// * recomputes the transaction's signing hash from the transaction fields,
/// * enforces the [EIP-2](https://eips.ethereum.org/EIPS/eip-2) low-`s` rule,
/// * rejects `r == 0`, `s == 0`, and out-of-range `v`,
/// * returns the unique public key that could have produced the signature.
///
/// An attacker who tampers with *any* field of a signed transaction (nonce,
/// value, gas, recipient, chain id) changes the signing hash, so recovery yields
/// either an error or an address that does not own the funds it is trying to
/// move.
pub fn recover_sender(tx: &Transaction) -> Result<Address, String> {
    // Rebuild an envelope view so recovery runs through the same
    // `TxEnvelope::recover_signer` path that a full node would use. This keeps
    // EIP-2 enforcement (low-s) in one place: alloy's `recover_signer`
    // (not `recover_signer_unchecked`) refuses high-s signatures with
    // `InvalidSignatureS`.
    let envelope: TxEnvelope = match tx {
        Transaction::Legacy(signed) => TxEnvelope::Legacy(signed.clone()),
        Transaction::Eip1559(signed) => TxEnvelope::Eip1559(signed.clone()),
    };

    // Defence in depth: assert the EIP-2 bound ourselves as well, so the rule is
    // enforced even if a future alloy release relaxes its own check.
    let s = tx.signature().s();
    if s > SECP256K1N_HALF {
        return Err(format!(
            "invalid signature: s value {s:#x} is not in the lower half of the secp256k1 order (EIP-2)"
        ));
    }
    if s.is_zero() || tx.signature().r().is_zero() {
        return Err("invalid signature: r and s must be non-zero".to_string());
    }

    envelope
        .recover_signer()
        .map_err(|err| format!("cannot recover sender: {err}"))
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
    /// The address recovered from the transaction signature.
    pub sender: Address,
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
        }
    }

    /// Overrides the chain id a transaction is checked against.
    ///
    /// This is the knob the replay-protection attack pulls: a transaction signed
    /// for chain 1 must be rejected once the executor expects chain 2.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }

    /// The chain id this executor validates transactions against.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Read-only access to the underlying in-memory database for inspection.
    ///
    /// revm's `Database::storage` takes `&mut self`, so this returns a mutable
    /// reference; callers are expected to only read from it.
    pub fn db_mut(&mut self) -> &mut InMemoryDB {
        &mut self.db
    }

    /// Reads an account from the underlying database.
    ///
    /// Returns `None` when the account has never been touched, which is how the
    /// attack suite proves that e.g. the victim was never charged.
    pub fn account(&mut self, address: Address) -> Option<AccountInfo> {
        self.db.basic(address).ok().flatten()
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
}


impl EvmExecutor {
    /// Executes an already decoded transaction.
    ///
    /// The sender is recovered from the transaction signature, never supplied by
    /// the caller. Everything downstream — the account revm debits for gas, the
    /// account whose nonce is checked, the address that pays for a `CREATE` — is
    /// derived from that recovered address.
    ///
    /// Validation order matters and mirrors a real node:
    ///
    /// 1. recover the sender (rejects forged/malleable/zero signatures),
    /// 2. check the chain id (rejects cross-chain replays),
    /// 3. fund the sender (the executor is a controlled test harness),
    /// 4. hand the transaction to revm, which enforces nonce and gas rules.
    pub fn execute(&mut self, tx: &Transaction) -> Result<ExecutionOutcome, String> {
        let sender = recover_sender(tx)?;
        self.check_chain_id(tx)?;
        self.ensure_funded(sender, tx);

        // revm 43 derives the transaction type from the fields that are set:
        // a priority fee makes it EIP-1559, otherwise it stays legacy.
        let mut builder = TxEnv::builder()
            .caller(sender)
            .gas_limit(tx.gas_limit())
            .kind(tx.kind())
            .value(tx.value())
            .data(tx.input().clone())
            .nonce(tx.nonce())
            .chain_id(Some(self.chain_id));

        builder = match tx {
            // Legacy: a single gas price, no priority fee.
            Transaction::Legacy(legacy) => builder.gas_price(legacy.tx().gas_price),
            // EIP-1559: a fee cap plus a priority fee. `max_fee_per_gas` is the
            // cap revm compares against `basefee`; the tip is the block
            // producer's cut.
            Transaction::Eip1559(eip1559) => builder
                .max_fee_per_gas(eip1559.tx().max_fee_per_gas)
                .gas_priority_fee(Some(eip1559.tx().max_priority_fee_per_gas)),
        };

        let tx_env = builder
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

        let mut outcome = Self::commit(&mut self.db, result);
        outcome.sender = sender;
        Ok(outcome)
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
    /// revm executes against a flat in-memory database, not a Merkle Patricia
    /// trie.
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
}


impl EvmExecutor {
    /// Rejects transactions bound to a different chain.
    ///
    /// A pre-EIP-155 legacy transaction (`v` of 27/28) has no chain id and
    /// therefore no replay protection; it is rejected too, because accepting it
    /// would let anyone replay a mainnet transaction on Zethora.
    fn check_chain_id(&self, tx: &Transaction) -> Result<(), String> {
        match tx.chain_id() {
            Some(tx_chain_id) if tx_chain_id != self.chain_id => {
                Err(format!("invalid chain id {tx_chain_id}, expected {}", self.chain_id))
            }
            Some(_) => Ok(()),
            None => Err("invalid chain id: transaction is not EIP-155 replay protected".to_string()),
        }
    }

    /// Makes sure the sender can pay for `gas_limit * gas_price + value`.
    ///
    /// The executor is a controlled test harness, so it tops the account up
    /// rather than rejecting the transaction. What matters for the attack suite
    /// is that the *recovered* address is the one that gets charged.
    fn ensure_funded(&mut self, sender: Address, tx: &Transaction) {
        let info = self.db.basic(sender).ok().flatten().unwrap_or_default();
        let gas = U256::from(tx.gas_limit()).saturating_mul(U256::from(tx.max_fee_per_gas()));
        let required = gas.saturating_add(tx.value());
        if info.balance < required {
            self.db.insert_account_info(
                sender,
                AccountInfo {
                    balance: required,
                    ..info
                },
            );
        }
    }

    /// Applies the state changes of a transaction to the database.
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
                    sender: Address::ZERO,
                }
            }
            // A revert or a halt must NOT commit: any `SSTORE` staged before the
            // failure has to roll back with the rest of the frame.
            ExecutionResult::Revert { output, .. } => ExecutionOutcome {
                output: output.to_vec(),
                created_address: None,
                gas_used,
                success: false,
                sender: Address::ZERO,
            },
            ExecutionResult::Halt { reason, .. } => ExecutionOutcome {
                output: format!("halted: {reason}").into_bytes(),
                created_address: None,
                gas_used,
                success: false,
                sender: Address::ZERO,
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
    use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
    use alloy_primitives::{Signature, TxKind, B256, U256};

    /// Deterministic key material, so the tests never depend on randomness.
    const KEY: B256 = B256::repeat_byte(0x11);

    /// The address that owns [`KEY`].
    fn signer_address() -> Address {
        alloy_signer_local::PrivateKeySigner::from_bytes(&KEY)
            .expect("valid scalar")
            .address()
    }

    /// Signs `tx` with [`KEY`], producing a legacy transaction.
    fn sign_legacy(tx: TxLegacy) -> Transaction {
        let signer = alloy_signer_local::PrivateKeySigner::from_bytes(&KEY).expect("valid scalar");
        let hash = tx.signature_hash();
        let signature = alloy_signer::SignerSync::sign_hash_sync(&signer, &hash).expect("sign");
        Transaction::Legacy(alloy_consensus::Signed::new_unchecked(tx, signature, hash))
    }

    /// Signs `tx` with [`KEY`], producing an EIP-1559 transaction.
    fn sign_eip1559(tx: TxEip1559) -> Transaction {
        let signer = alloy_signer_local::PrivateKeySigner::from_bytes(&KEY).expect("valid scalar");
        let hash = tx.signature_hash();
        let signature = alloy_signer::SignerSync::sign_hash_sync(&signer, &hash).expect("sign");
        Transaction::Eip1559(alloy_consensus::Signed::new_unchecked(tx, signature, hash))
    }

    fn contract_address() -> Address {
        Address::repeat_byte(0xaa)
    }

    fn legacy_tx(to: TxKind, input: Bytes) -> TxLegacy {
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 1,
            gas_limit: 1_000_000,
            to,
            value: U256::ZERO,
            input,
        }
    }

    fn eip1559_tx(to: TxKind, input: Bytes) -> TxEip1559 {
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 1_000_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to,
            value: U256::ZERO,
            input,
            access_list: Default::default(),
        }
    }

    /// Runtime code for `contract S { uint256 s; function set(uint256 v) { s = v; } }`,
    /// hand assembled so the suite needs no `solc`.
    const STORAGE_RUNTIME: &[u8] = &[
        0x60, 0x00, // PUSH1 0
        0x35, //        CALLDATALOAD
        0x60, 0x00, // PUSH1 0
        0x55, //        SSTORE
        0x60, 0x00, // PUSH1 0
        0x54, //        SLOAD
        0x60, 0x00, // PUSH1 0
        0x52, //        MSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, //        RETURN
    ];

    /// Init code that deploys [`STORAGE_RUNTIME`] with `CODECOPY` + `RETURN`.
    fn deploy_init_code() -> Bytes {
        let len = u8::try_from(STORAGE_RUNTIME.len()).expect("runtime fits in one byte");
        // The runtime code starts right after this 12 byte prologue.
        let mut code = vec![
            0x60, len, // PUSH1 len
            0x60, 0x0c, // PUSH1 12        offset of the runtime code
            0x60, 0x00, // PUSH1 0
            0x39, //        CODECOPY
            0x60, len, // PUSH1 len
            0x60, 0x00, // PUSH1 0
            0xf3, //        RETURN
        ];
        assert_eq!(code.len(), 12);
        code.extend_from_slice(STORAGE_RUNTIME);
        Bytes::from(code)
    }


    #[test]
    fn recovers_sender_from_legacy_signature() {
        let tx = sign_legacy(legacy_tx(TxKind::Call(contract_address()), Bytes::new()));
        assert_eq!(
            recover_sender(&tx).expect("valid signature"),
            signer_address()
        );
    }

    #[test]
    fn recovers_sender_from_eip1559_signature() {
        let tx = sign_eip1559(eip1559_tx(TxKind::Call(contract_address()), Bytes::new()));
        assert_eq!(
            recover_sender(&tx).expect("valid signature"),
            signer_address()
        );
        assert_eq!(tx.tx_type(), EIP1559_TX_TYPE);
    }

    #[test]
    fn rejects_high_s_signature() {
        let base = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        let hash = base.signature_hash();
        let signer = alloy_signer_local::PrivateKeySigner::from_bytes(&KEY).expect("valid scalar");
        let good = alloy_signer::SignerSync::sign_hash_sync(&signer, &hash).expect("sign");

        // Mirror the signature over the curve: (r, N - s) with flipped parity.
        let n = U256::from_be_bytes(alloy_primitives::hex!(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        let high_s = n - good.s();
        assert!(high_s > SECP256K1N_HALF, "fixture must be high-s");
        let malleable = Signature::new(good.r(), high_s, !good.v());

        let forged =
            Transaction::Legacy(alloy_consensus::Signed::new_unchecked(base, malleable, hash));
        let err = recover_sender(&forged).expect_err("high-s must be rejected");
        assert!(err.contains("EIP-2"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_zero_signature() {
        let base = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        let hash = base.signature_hash();
        let forged = Transaction::Legacy(alloy_consensus::Signed::new_unchecked(
            base,
            Signature::new(U256::ZERO, U256::ZERO, false),
            hash,
        ));
        assert!(
            recover_sender(&forged).is_err(),
            "the zero signature must not recover a sender"
        );
    }

    #[test]
    fn rejects_chain_id_mismatch() {
        let mut executor = EvmExecutor::new();
        executor.set_chain_id(5);
        let tx = sign_legacy(legacy_tx(TxKind::Call(contract_address()), Bytes::new()));
        let err = executor
            .execute(&tx)
            .expect_err("wrong chain id must be rejected");
        assert!(err.contains("invalid chain id 1"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_unprotected_transactions() {
        // `chain_id: None` makes alloy produce a pre-EIP-155 signature (v = 27/28),
        // which has no replay protection at all.
        let mut tx = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        tx.chain_id = None;
        let signed = sign_legacy(tx);
        assert_eq!(signed.chain_id(), None);

        let mut executor = EvmExecutor::new();
        let err = executor
            .execute(&signed)
            .expect_err("unprotected transaction must be rejected");
        assert!(err.contains("not EIP-155"), "unexpected error: {err}");
    }


    #[test]
    fn eip1559_transfer_charges_the_recovered_sender() {
        let mut executor = EvmExecutor::new();
        let tx = sign_eip1559(eip1559_tx(TxKind::Call(contract_address()), Bytes::new()));

        let outcome = executor.execute(&tx).expect("transfer should succeed");
        assert!(outcome.success);
        assert_eq!(outcome.sender, signer_address());
        assert_eq!(outcome.gas_used, 21_000);

        let info = executor
            .db_mut()
            .basic(signer_address())
            .expect("db read")
            .expect("sender account must exist");
        assert_eq!(info.nonce, 1, "the recovered sender's nonce must advance");
    }

    #[test]
    fn deploys_contract_and_writes_storage() {
        let mut executor = EvmExecutor::new();

        // Deploy through the EVM: an empty `to` means CREATE.
        let outcome = executor
            .execute(&sign_legacy(legacy_tx(TxKind::Create, deploy_init_code())))
            .expect("contract creation should succeed");
        assert!(outcome.success, "creation reverted: {:?}", outcome.output);
        assert_eq!(
            outcome.output, STORAGE_RUNTIME,
            "RETURNed code should be the runtime"
        );

        let created = outcome
            .created_address
            .expect("CREATE must report an address");
        let info = executor
            .db_mut()
            .basic(created)
            .expect("db read should succeed")
            .expect("created account must exist");
        assert_eq!(info.code_hash, alloy_primitives::keccak256(STORAGE_RUNTIME));

        // A second transaction calls the deployed contract and sets slot 0 to 42.
        let mut calldata = [0u8; 32];
        calldata[31] = 42;
        let mut call = legacy_tx(TxKind::Call(created), Bytes::from(calldata.to_vec()));
        call.nonce = 1;
        let outcome = executor
            .execute(&sign_legacy(call))
            .expect("call should succeed");
        assert!(outcome.success, "call reverted: {:?}", outcome.output);
        assert_eq!(executor.storage(created, U256::ZERO), U256::from(42));
    }

    #[test]
    fn state_root_is_deterministic_across_executors() {
        let mut first = EvmExecutor::new();
        let mut second = EvmExecutor::new();

        // Same transaction, same chain: identical roots.
        let tx = sign_eip1559(eip1559_tx(TxKind::Call(contract_address()), Bytes::new()));
        first.execute(&tx).expect("first executor");
        second.execute(&tx).expect("second executor");
        assert_eq!(first.state_root(), second.state_root());

        // Any state change must move the root.
        let before = first.state_root();
        let mut next = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        next.nonce = 1;
        next.value = U256::from(1);
        first.execute(&sign_legacy(next)).expect("value transfer");
        assert_ne!(before, first.state_root());
    }

    #[test]
    fn rejects_intrinsic_gas_underflow() {
        let mut executor = EvmExecutor::new();
        let mut tx = legacy_tx(TxKind::Call(contract_address()), Bytes::new());
        tx.gas_limit = 1_000; // below the 21_000 intrinsic cost

        let err = executor
            .execute(&sign_legacy(tx))
            .expect_err("intrinsic gas must be enforced");
        assert!(
            err.contains("gas cost") && err.contains("21000"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_transaction_type() {
        // 0x7e is EIP-7702 (delegation list), which this engine does not support.
        let err = decode_transaction(&[0x7e, 0xc0]).expect_err("unsupported type must be rejected");
        assert!(err.contains("unsupported transaction type"), "unexpected error: {err}");
    }

    #[test]
    fn round_trips_rlp_encoding() {
        let original = sign_eip1559(eip1559_tx(TxKind::Call(contract_address()), Bytes::new()));
        let envelope = TxEnvelope::Eip1559(match &original {
            Transaction::Eip1559(signed) => signed.clone(),
            _ => unreachable!(),
        });
        let mut encoded = Vec::new();
        alloy_eips::eip2718::Encodable2718::encode_2718(&envelope, &mut encoded);

        let decoded = decode_transaction(&encoded).expect("encoded transaction must decode");
        assert_eq!(decoded, original, "round trip must preserve the transaction");

        // Re-encoding must also be byte-identical on the wire.
        let round_tripped = TxEnvelope::Eip1559(match &decoded {
            Transaction::Eip1559(signed) => signed.clone(),
            _ => unreachable!(),
        });
        let mut reencoded = Vec::new();
        alloy_eips::eip2718::Encodable2718::encode_2718(&round_tripped, &mut reencoded);
        assert_eq!(reencoded, encoded, "round trip must be byte-identical");

        assert_eq!(
            recover_sender(&decoded).expect("valid signature"),
            signer_address()
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert!(decode_transaction(&[]).is_err());
    }
}

