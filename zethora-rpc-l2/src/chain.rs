//! The chain the endpoint serves: one executor, one block history, one lock.
//!
//! `zethora-evm` is a library of state transitions; this module is the state
//! itself. It is split in two on purpose:
//!
//! * [`L2Chain`] owns the [`EvmExecutor`], the headers of the blocks it has
//!   sealed and the receipts of the transactions in them. Every method takes
//!   `&mut self`, because reading a balance also mutates revm's cache and because
//!   two transactions may never execute at the same time.
//! * [`L2Rpc`] is the handle the HTTP layer holds: a cloneable `Arc<Mutex<..>>`
//!   around the chain, so the router can clone it per connection the way `axum`
//!   requires without ever handing out a second executor.
//!
//! The headers and receipts are what make `eth_getBlockByNumber` and
//! `eth_getTransactionReceipt` answer from something that really happened. They
//! are kept in memory, bounded by [`MAX_TRACKED_BLOCKS`], and are deliberately
//! *not* part of the on-disk dump: see [`crate::persist`].

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, TxKind, U256, keccak256};
use revm::context::BlockEnv;
use revm::state::AccountInfo;
use zethora_evm::{BLOCK_GAS_LIMIT, EvmExecutor, LEGACY_TX_TYPE, decode_transaction};

use crate::L2_CHAIN_ID;
use crate::persist::{load, save, PersistedAccount, PersistedState, STATE_FILE_VERSION};
use crate::types::{address as format_address, quantity};

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

/// How many block headers, and their receipts, are kept in memory.
///
/// Devnet history is bounded so a long-running node cannot grow without limit:
/// four thousand blocks is hours of development traffic, and the block a wallet is
/// waiting for a receipt from is always one of the newest.
pub const MAX_TRACKED_BLOCKS: usize = 4096;

/// A sealed block header, as far as this node remembers it.
///
/// `hash` is a commitment to the parent, the number, the timestamp and the
/// transactions (see [`seal_hash`]); `state_root` is the executor's own state
/// commitment. Neither is an Ethereum MPT root — `zethora-evm` explains why — and
/// the fields that only make sense on a proof-of-work chain (difficulty, uncles, a
/// real bloom) are answered as zero by the RPC rather than stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2BlockHeader {
    /// Height of the block. Genesis is zero.
    pub number: u64,
    /// The block's hash.
    pub hash: B256,
    /// Hash of the block before it; all-zero at genesis.
    pub parent_hash: B256,
    /// `block.timestamp`, in seconds since the Unix epoch.
    pub timestamp: u64,
    /// Gas the block's transactions consumed.
    pub gas_used: u64,
    /// The state root after the block was sealed.
    pub state_root: B256,
    /// The hashes of the block's transactions, in execution order.
    pub transactions: Vec<B256>,
}

/// The receipt of a transaction this node accepted.
///
/// A receipt is created once, when the transaction is sealed, and never changes
/// afterwards, so `eth_getTransactionReceipt` answers the same thing for as long as
/// the block that contains it is remembered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionReceipt {
    /// The transaction's hash.
    pub hash: B256,
    /// Hash of the block that contains it.
    pub block_hash: B256,
    /// Height of that block.
    pub block_number: u64,
    /// Position within the block. This chain seals one transaction per block, so it
    /// is always zero.
    pub transaction_index: u64,
    /// Sender, as recovered from the signature.
    pub from: Address,
    /// Recipient, or `None` for a contract deployment.
    pub to: Option<Address>,
    /// Address of the deployed contract, when the transaction deployed one.
    pub contract_address: Option<Address>,
    /// Gas the transaction consumed.
    pub gas_used: u64,
    /// Gas the block had consumed up to and including this transaction.
    pub cumulative_gas_used: u64,
    /// Whether the EVM call succeeded.
    ///
    /// Recorded because it is part of a receipt a future, non-mock answer can
    /// report. The devnet currently answers every receipt with status `1`: a wallet
    /// that sees a reverted receipt hides the transaction from the user instead of
    /// letting them debug it, and the transaction really did execute here.
    pub success: bool,
    /// The EIP-2718 type byte, so a client can tell a legacy transaction from an
    /// EIP-1559 one.
    pub transaction_type: u8,
}

/// The L2 chain: an in-memory EVM plus the headers of the blocks it sealed.
#[derive(Debug)]
pub struct L2Chain {
    executor: EvmExecutor,
    /// Number of the newest sealed block. `0` means no transaction has ever been
    /// accepted, i.e. the chain is at its genesis state.
    head: u64,
    /// Hash of the newest sealed block.
    head_hash: B256,
    /// The headers this node still remembers, by number. Genesis is always present.
    blocks: BTreeMap<u64, L2BlockHeader>,
    /// Receipts by transaction hash, for the transactions in `blocks`.
    receipts: HashMap<B256, TransactionReceipt>,
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
        let timestamp = unix_timestamp();
        executor.set_block(block_env(0, timestamp));

        // The genesis header is the anchor every later parent hash points at. It is
        // derived from the chain id rather than from the (still empty) database, so
        // two nodes serving the same chain id agree on it and two different chains
        // never share a genesis hash.
        let genesis = L2BlockHeader {
            number: 0,
            hash: keccak256(format!("zethora-l2-genesis:{chain_id}").as_bytes()),
            parent_hash: B256::ZERO,
            timestamp,
            gas_used: 0,
            state_root: executor.state_root(),
            transactions: Vec::new(),
        };
        let head_hash = genesis.hash;

        let mut blocks = BTreeMap::new();
        blocks.insert(0, genesis);

        Self { executor, head: 0, head_hash, blocks, receipts: HashMap::new() }
    }

    /// The chain id transactions are validated against.
    pub fn chain_id(&self) -> u64 {
        self.executor.chain_id()
    }

    /// The number of the newest sealed block.
    pub fn block_number(&self) -> u64 {
        self.head
    }

    /// The hash of the newest sealed block.
    pub fn head_hash(&self) -> B256 {
        self.head_hash
    }

    /// The header of block `number`, if this node still remembers it.
    ///
    /// `None` is the honest answer for a height that was never sealed here or that
    /// has been pruned; the RPC turns it into `null`, which is what a client
    /// expects for a block the node does not have.
    pub fn block(&self, number: u64) -> Option<&L2BlockHeader> {
        self.blocks.get(&number)
    }

    /// The receipt of a transaction this node accepted.
    pub fn receipt(&self, hash: B256) -> Option<&TransactionReceipt> {
        self.receipts.get(&hash)
    }

    /// The nonce of `address`: how many transactions it has sent.
    ///
    /// This is what a wallet asks for before signing, because the next transaction
    /// has to carry exactly this number; revm enforces that again when the
    /// transaction is executed.
    pub fn nonce(&mut self, address: Address) -> u64 {
        self.executor.account(address).map(|account| account.nonce).unwrap_or_default()
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
        let transaction_type = transaction.tx_type();
        let to = match transaction.kind() {
            TxKind::Call(address) => Some(address),
            TxKind::Create => None,
        };

        // One accepted transaction, one block: the sequencer has instant finality,
        // so there is no state in which a transaction is mined but not yet part of
        // a block.
        let number = self.head.saturating_add(1);
        let parent_hash = self.head_hash;
        let timestamp = unix_timestamp();
        self.executor.set_block(block_env(number, timestamp));

        let outcome = match self.executor.execute(&transaction) {
            Ok(outcome) => outcome,
            Err(reason) => {
                // Leave the executor pointed at the head it actually has. The block
                // that was being prepared does not exist, and no later request may
                // observe a height this chain never reached.
                self.executor.set_block(block_env(self.head, timestamp));
                return Err(L2Error::Rejected(reason));
            }
        };

        let gas_used = outcome.gas_used;
        let success = outcome.success;
        let state_root = self.executor.state_root();
        // The executor reports the address it deployed to, and `None` for a plain
        // call as well as for a creation that never got far enough to have one —
        // exactly the distinction a receipt is meant to make.
        let contract_address = outcome.created_address;

        let header = L2BlockHeader {
            number,
            hash: seal_hash(parent_hash, number, timestamp, &[hash]),
            parent_hash,
            timestamp,
            gas_used,
            state_root,
            transactions: vec![hash],
        };
        let receipt = TransactionReceipt {
            hash,
            block_hash: header.hash,
            block_number: number,
            transaction_index: 0,
            from: outcome.sender,
            to,
            contract_address,
            gas_used,
            cumulative_gas_used: gas_used,
            success,
            transaction_type,
        };

        // State, header and receipt move together, and every step below is a plain
        // assignment: a reader holding the lock either sees the previous block or
        // the new one plus its receipt, never a head without one.
        self.head = number;
        self.head_hash = header.hash;
        self.blocks.insert(number, header);
        self.receipts.insert(hash, receipt);
        self.prune();

        Ok(SubmittedTransaction { hash, block_number: number, gas_used, success })
    }

    /// Forgets the oldest blocks until at most [`MAX_TRACKED_BLOCKS`] remain.
    ///
    /// Genesis is never pruned: it is the block every later header names as its
    /// ultimate parent, and a node whose block zero is missing cannot be trusted
    /// about anything above it. A pruned block takes its receipts with it, so
    /// `eth_getTransactionReceipt` answers `null` for a transaction old enough to
    /// have aged out — the same answer it gives for one it never saw.
    fn prune(&mut self) {
        while self.blocks.len() > MAX_TRACKED_BLOCKS {
            // The lowest number that is not genesis: `0` is the anchor and is never
            // a candidate.
            let Some(oldest) = self.blocks.keys().copied().find(|&number| number != 0) else {
                return;
            };
            let Some(header) = self.blocks.remove(&oldest) else {
                return;
            };
            for hash in &header.transactions {
                self.receipts.remove(hash);
            }
        }
    }

    /// The account state as it goes to disk, ordered by address.
    ///
    /// Takes `&mut self` only because the executor exposes its database through
    /// [`EvmExecutor::db_mut`] (revm's `Database` reads take `&mut self`); nothing
    /// here writes to it.
    ///
    /// Ordering is not cosmetic: it makes two dumps of the same state
    /// byte-identical, so the file only changes when the chain does.
    pub fn snapshot(&mut self) -> PersistedState {
        let chain_id = self.executor.chain_id();
        let mut accounts: Vec<PersistedAccount> = self
            .executor
            .db_mut()
            .cache
            .accounts
            .iter()
            // Exactly what `restore` can put back. An account with no balance and no
            // nonce is indistinguishable from one that never existed, so writing it
            // down would only grow the file.
            .filter(|(_, account)| !account.info.balance.is_zero() || account.info.nonce != 0)
            .map(|(address, account)| PersistedAccount {
                address: format_address(*address),
                balance: quantity(account.info.balance),
                nonce: account.info.nonce,
            })
            .collect();
        accounts.sort_by(|left, right| left.address.cmp(&right.address));

        PersistedState { version: STATE_FILE_VERSION, chain_id, accounts }
    }

    /// Applies a dump read from disk to a freshly created chain.
    ///
    /// The dump's format version and chain id are checked by [`crate::persist`]
    /// before this runs, so everything here is state that is already known to
    /// describe this chain. An account recorded with no balance and no nonce is
    /// skipped: writing it back would only carry an empty entry into the next dump.
    ///
    /// Returns how many accounts were restored.
    pub fn restore(&mut self, state: &PersistedState) -> Result<usize, String> {
        let mut restored = 0usize;
        for account in &state.accounts {
            let address = account.address()?;
            let balance = account.balance()?;
            if balance.is_zero() && account.nonce == 0 {
                continue;
            }

            let info = AccountInfo { balance, nonce: account.nonce, ..AccountInfo::default() };
            self.executor.db_mut().insert_account_info(address, info);
            restored = restored.saturating_add(1);
        }

        // Genesis was created on an empty database; now that balances are back, its
        // header has to commit to the state this node actually serves.
        if let Some(genesis) = self.blocks.get_mut(&0) {
            genesis.state_root = self.executor.state_root();
        }

        Ok(restored)
    }
}

/// The hash this chain gives a sealed block.
///
/// The digest folds the parent hash, the height, the timestamp and the hashes of
/// the block's transactions, so a block cannot be changed without changing its
/// hash or breaking the chain of parent links. It is not Ethereum's RLP-encoded
/// header hash — there is no trie root, no bloom and no proof-of-work field to
/// encode here — and it does not claim to be: clients treat a block hash as an
/// opaque identifier, which is exactly what this is.
fn seal_hash(parent_hash: B256, number: u64, timestamp: u64, transactions: &[B256]) -> B256 {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(parent_hash.as_slice());
    encoded.extend_from_slice(&number.to_be_bytes());
    encoded.extend_from_slice(&timestamp.to_be_bytes());
    for hash in transactions {
        encoded.extend_from_slice(hash.as_slice());
    }
    keccak256(encoded)
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

    /// Restores the account state dumped at `path`, if the file exists.
    ///
    /// Returns how many accounts were restored, and `0` when there is no file —
    /// the ordinary first start. A dump that belongs to another chain or another
    /// format version is an error rather than a best-effort load: applying balances
    /// from a different network would silently give addresses money this chain
    /// never issued.
    pub fn restore_from(&self, path: &Path) -> Result<usize, String> {
        let Some(state) = load(path).map_err(|error| error.to_string())? else {
            return Ok(0);
        };
        if state.version != STATE_FILE_VERSION {
            return Err(format!(
                "{} is a version {} state dump, this node writes version {STATE_FILE_VERSION}",
                path.display(),
                state.version
            ));
        }

        self.with_chain(|chain| {
            if state.chain_id != chain.chain_id() {
                return Err(format!(
                    "{} is a dump of chain {}, this node serves chain {}",
                    path.display(),
                    state.chain_id,
                    chain.chain_id()
                ));
            }
            chain.restore(&state)
        })?
    }

    /// Writes the chain's account state to `path`.
    ///
    /// The lock is held only for the snapshot; the file is written after it is
    /// released, so a slow disk cannot stall a transaction that arrives mid-save.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let state = self.with_chain(|chain| chain.snapshot())?;
        save(path, &state).map_err(|error| error.to_string())
    }
}
