//! Zethora L1 <-> L2 bridge: the wZTHR mint contract and the L1 watcher.
//!
//! # The shape of the bridge
//!
//! Value has to get from a UTXO chain that knows nothing about accounts to an EVM
//! chain that knows nothing about UTXOs. The bridge is the only place the two
//! ledgers touch, and it touches them in opposite directions:
//!
//! * **L1 lock** (funds leave circulation) — a deposit is a UTXO locked under
//!   [`FederationLock::lock_script`], which only the bridge's threshold federation
//!   can spend. The locked output is what [`L1Watcher::scan_for_locks`]
//!   recognises.
//! * **L2 mint** (funds enter circulation) — [`mint_calldata`] turns one lock into
//!   a call to the `mint(address,uint256,bytes)` entry point of the L2 contract,
//!   which credits `wZTHR` to the depositor's account.
//!
//! Between the two sits a proof. The L2 cannot see the L1 chain, so it must be told
//! about a lock in a way it can *check* rather than in a way it has to trust.
//! [`L1Watcher::generate_mint_proof`] produces that artifact; today it is a mock,
//! and it will become an SP1 proof that the lock is in the L1 UTXO set, confirmed
//! and unspent.
//!
//! # The contract is Rust, executed by revm
//!
//! There is no Solidity compiler in this repository, so the contract cannot be a
//! `.sol` file compiled to bytecode. It is instead modelled the way the rest of the
//! L2 is: as a Rust-native contract whose ABI is declared with
//! [`alloy_sol_types::sol`]. `sol!` is the same macro that parses a compiled
//! contract's ABI, so the selector and the argument encoding here are derived from
//! the Solidity signature `mint(address,uint256,bytes)` exactly as a real
//! deployment would be. What is mocked is the *bytecode*, not the interface: a mint
//! still carries real ABI calldata, and it is applied to
//! [`zethora_evm::EvmExecutor`] state the same way the sequencer applies a
//! transaction.
//!
//! The contract's storage layout is ours to choose too. It is a single mapping at
//! slot [`MINT_STORAGE_INITIAL_SLOT`], which is where a Solidity
//! `mapping(address => uint256) balances` declared first in the contract would
//! live, so the mock is a faithful stand-in for the real deployment rather than
//! just a balance table in disguise.
//!
//! # What is not here
//!
//! Nothing in this crate reads the L1 consensus engine, and nothing writes to it.
//! Locked outputs arrive as bytes; how they were validated is the L1's business.

mod contract;
mod federation;
mod watcher;

pub use contract::{
    MINT_STORAGE_INITIAL_SLOT, MintError, WZthrBridge, balances_selector, decode_mint_calldata, mint, mint_calldata,
    mint_selector, mint_storage_slot, minted_slot, wzthr_balance,
};
pub use federation::{FederationLock, MAX_KEYS};
pub use watcher::{
    BLOCK_MAGIC, BlockOutput, L1Watcher, LockEvent, LockStatus, MAX_LOCKS_PER_BLOCK, MAX_OUTPUTS_PER_BLOCK, MintProof,
    ScanReport, decode_block,
};

/// Name of the L2 token the contract mints.
///
/// The bridge does not mint ZTHR itself: it mints a claim on ZTHR backed by a UTXO
/// locked on L1, which is why the asset is a separate, wrapped token.
pub const WRAPPED_TOKEN_SYMBOL: &str = "wZTHR";

/// Domain separator mixed into every proof, so a proof made for this bridge can
/// never be replayed into another contract or another chain.
pub const PROOF_DOMAIN: &[u8] = b"zethora-bridge/wzthr/v1";

/// The chain id every mint proof is bound to.
///
/// The chain id the L2 validates transactions against is also the chain id the
/// proof commits to, so a proof cannot cross chains any more than a transaction
/// can.
pub const PROOF_CHAIN_ID: u64 = zethora_evm::CHAIN_ID;

/// The largest amount a single mint may credit, in the smallest unit of ZTHR.
///
/// The mint credits the L1 amount one-to-one and an L2 balance is a `u256`, so an
/// amount that does not fit must be refused rather than silently truncated into a
/// mint of the wrong size. A `u128` of base units is already far beyond any total
/// supply, which keeps this ceiling out of the way while still being a real limit.
pub const AMOUNT_CEILING: alloy_primitives::U256 = alloy_primitives::U256::from_limbs([u64::MAX, u64::MAX, 0, 0]);

/// The largest locking script the watcher will accept from a block.
///
/// Bounded so a malformed length field cannot make the decoder allocate its way
/// through a hostile block, and generous enough for a full 16-key federation.
pub const MAX_LOCK_SCRIPT_LEN: usize = 1024;
