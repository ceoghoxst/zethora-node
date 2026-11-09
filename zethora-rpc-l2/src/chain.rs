//! The chain the endpoint serves: one executor, one head block, one lock.
//!
//! `zethora-evm` is a library of state transitions; this module is the state
//! itself. It is split in two on purpose:
//!
//! * [`L2Chain`] owns the [`EvmExecutor`] and the block number. Every method
//!   takes `&mut self`, because reading a balance also mutates revm's cache and
//!   because two transactions may never execute at the same time.
//! * [`L2Rpc`] is the handle the HTTP layer holds: a cloneable `Arc<Mutex<..>>`
//!   around the chain, so the router can clone it per connection the way `axum`
//!   requires without ever handing out a second executor.

use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, U256, keccak256};
use revm::context::BlockEnv;
use zethora_evm::{BLOCK_GAS_LIMIT, EvmExecutor, LEGACY_TX_TYPE, decode_transaction};

use crate::L2_CHAIN_ID;

/// Why a chain refused to include a transaction.
///
/// The split matters on the wire: a payload that is not a transaction at all is
/// the caller's mistake (JSON-RPC `invalid params`), while a transaction that
/// decoded but that the EVM refused is the node's refusal (`server error`, the
/// range real Ethereum nodes use for "I will not include this"). Collapsing the
/// two would tell a wallet to fix its encoding when the problem was the nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum L2Error {
    /// The bytes are not a transaction this chain can decode and price.
    InvalidTransaction(String),
    /// The transaction decoded, but the EVM refused to execute it.
    Rejected(String),
}

impl std::fmt::Display for L2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransaction(reason) => write!(formatter, "invalid transaction: {reason}"),
            Self::Rejected(reason) => write!(formatter, "transaction rejected: {reason}"),
        }
    }
}

impl std::error::Error for L2Error {}

/// What the chain learned from accepting a transaction.
///
/// A revert is *not* an error here: it cost gas, it changed the sender's nonce
/// and it is part of a block, exactly as on Ethereum. It is reported as
/// `success: false` with a hash a client can look up, not as a JSON-RPC error
/// that would tell the wallet the transaction never happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmittedTransaction {
    /// The canonical transaction hash the client is answered with.
    pub hash: B256,
    /// The number of the block the transaction was sealed into.
    pub block_number: u64,
    /// Gas the transaction consumed.
    pub gas_used: u64,
    /// Whether the EVM call succeeded, as opposed to reverting or halting.
    pub success: bool,
}

/// The L2 chain: an in-memory EVM plus the number of its newest block.
#[derive(Debug)]
pub struct L2Chain {
    executor: EvmExecutor,
    /// Number of the newest sealed block. `0` means no transaction has ever been
    /// accepted, i.e. the chain is at its genesis state.
    head: u64,
}

impl Default for L2Chain {
    fn default() -> Self {
        Self::new(L2_CHAIN_ID)
    }
}

impl L2Chain {
    /// A chain with an empty database that validates transactions against
    /// `chain_id`.
    ///
    /// The executor is re-pointed at `chain_id` here, before anything can be
    /// executed: [`L2_CHAIN_ID`] is what `eth_chainId` reports, and a transaction
    /// signed for another chain has to be refused rather than replayed.
    pub fn new(chain_id: u64) -> Self {
        let mut executor = EvmExecutor::new();
        executor.set_chain_id(chain_id);
        executor.set_block(block_env(0, unix_timestamp()));
        Self { executor, head: 0 }
    }

    /// The chain id transactions are validated against.
    pub fn chain_id(&self) -> u64 {
        self.executor.chain_id()
    }

    /// The number of the newest sealed block.
    pub fn block_number(&self) -> u64 {
        self.head
    }

    /// The balance of `address`, in wei.
    ///
    /// An account that has never been touched has no entry in the database at
    /// all, which is a balance of zero rather than an error: asking about an
    /// address is not a claim that it exists.
    pub fn balance(&mut self, address: Address) -> U256 {
        self.executor.account(address).map(|account| account.balance).unwrap_or_default()
    }

    /// Executes a raw, signed transaction and seals it into the next block.
    ///
    /// The order of the steps is the whole safety argument:
    ///
    /// 1. **Decode.** A payload that is not a legacy or EIP-1559 envelope is
    ///    refused before anything is touched, so junk cannot advance the head.
    /// 2. **Hash.** Computed from the bytes the client sent, by the EIP-2718 rule
    ///    (`transaction_hash`), so the hash returned is the hash every other
    ///    Ethereum client computes for the same transaction.
    /// 3. **Execute.** `zethora-evm` recovers the sender from the signature,
    ///    checks the chain id and hands the transaction to revm, which enforces
    ///    the nonce and gas rules and commits the state change.
    /// 4. **Seal.** Only now does the head advance, so a refused transaction can
    ///    never appear to have been mined.
    pub fn submit_raw_transaction(&mut self, raw: &[u8]) -> Result<SubmittedTransaction, L2Error> {
        let transaction = decode_transaction(raw).map_err(L2Error::InvalidTransaction)?;
        let hash = transaction_hash(raw);

        // One accepted transaction, one block: the sequencer has instant finality,
        // so there is no state in which a transaction is mined but not yet part of
        // a block.
        let number = self.head.saturating_add(1);
        self.executor.set_block(block_env(number, unix_timestamp()));

        let outcome = self.executor.execute(&transaction).map_err(L2Error::Rejected)?;
        self.head = number;

        Ok(SubmittedTransaction { hash, block_number: number, gas_used: outcome.gas_used, success: outcome.success })
    }
}

/// The canonical hash of a raw transaction, i.e. `keccak256` over its EIP-2718
/// envelope.
///
/// A typed envelope is hashed whole (`0x02 || rlp`). A legacy transaction has no
/// type prefix in its canonical form, but [`decode_transaction`] also accepts the
/// `0x00 || rlp` form, so that prefix is stripped before hashing: hashing it
/// would report a hash no other Ethereum client recognises for the same
/// transaction, and a wallet that stored it could never find the transaction
/// again.
fn transaction_hash(raw: &[u8]) -> B256 {
    match raw.first() {
        Some(&LEGACY_TX_TYPE) => keccak256(raw.get(1..).unwrap_or_default()),
        _ => keccak256(raw),
    }
}

/// The block environment a transaction executes in.
///
/// `beneficiary` is the zero address and `basefee` is zero: the L2 has no fee
/// market yet, so there is no burned base fee to deduct and nobody to credit a
/// block reward to. What is left of a gas price is pure tip, and the executor's
/// own split still applies to it — see `zethora_evm::MINER_TREASURY_FEE_BPS`; the
/// RPC does not configure a treasury, so that slice goes to the zero address until
/// a node wires one in.
///
/// `gas_limit` is the same budget `zethora-evm` enforces for a batch, so a
/// transaction here is priced against exactly the block size the engine
/// documents.
fn block_env(number: u64, timestamp: u64) -> BlockEnv {
    BlockEnv {
        number: U256::from(number),
        gas_limit: BLOCK_GAS_LIMIT,
        basefee: 0,
        timestamp: U256::from(timestamp),
        beneficiary: Address::ZERO,
        difficulty: U256::ZERO,
        prevrandao: Some(B256::ZERO),
        // The remaining fields (blob prices and the EIP-4844 excess) are zero,
        // which is what a chain that does not carry blobs wants them to be.
        ..Default::default()
    }
}

/// Seconds since the Unix epoch, or `0` for a clock set before it.
///
/// A clock reading is never allowed to fail a transaction: an unusable system
/// clock should make `block.timestamp` wrong, not make the node stop accepting
/// transactions.
fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_secs())
        .unwrap_or_default()
}

/// The handle the HTTP layer holds: the chain behind a mutex.
///
/// Cloning is cheap and shares one chain, which is what `axum` wants: it clones
/// the state once per connection.
#[derive(Clone, Debug)]
pub struct L2Rpc {
    chain: Arc<Mutex<L2Chain>>,
}

impl Default for L2Rpc {
    fn default() -> Self {
        Self::new()
    }
}

impl L2Rpc {
    /// A handle to a fresh, empty chain using [`L2_CHAIN_ID`].
    pub fn new() -> Self {
        Self::from_chain(L2Chain::default())
    }

    /// A handle to a fresh, empty chain that validates transactions against
    /// `chain_id`.
    pub fn with_chain_id(chain_id: u64) -> Self {
        Self::from_chain(L2Chain::new(chain_id))
    }

    /// A handle to an already-built chain.
    pub fn from_chain(chain: L2Chain) -> Self {
        Self { chain: Arc::new(Mutex::new(chain)) }
    }

    /// Runs `action` against the chain while holding the state lock.
    ///
    /// One mutex guards the whole executor because the executor *is* the state: a
    /// flat in-memory database and a block number. Two requests may not execute at
    /// the same time, or they would each build on the other's half-written state.
    /// The critical section is a single transaction — bounded by
    /// [`BLOCK_GAS_LIMIT`] — not the life of the server.
    ///
    /// A poisoned lock is reported as an error rather than recovered from. A panic
    /// inside revm would leave the database in an unknown state, and continuing to
    /// serve that state as if nothing had happened is worse than one failed
    /// request.
    pub fn with_chain<R>(&self, action: impl FnOnce(&mut L2Chain) -> R) -> Result<R, String> {
        let mut chain = self
            .chain
            .lock()
            .map_err(|_| "the chain state is unavailable: a previous request panicked while holding it".to_string())?;
        Ok(action(&mut chain))
    }
}
