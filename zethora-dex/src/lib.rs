//! Zethora's private DEX: a constant-product AMM with shielded LP positions.
//!
//! # What this crate is
//!
//! One pair, two assets, one invariant. A depositor adds both sides and receives
//! liquidity tokens; a trader swaps one side for the other at the price the
//! reserves imply, paying 0.3% of the input to the pool; a withdrawer burns
//! liquidity and takes both sides out pro rata. The pool's claim on those reserves
//! can be held by an address, or by a *note* — a commitment under a tag the holder
//! derives from themselves — which is what makes LP ownership unlinkable on a
//! chain whose whole point is that trading is not.
//!
//! # How it runs
//!
//! The canonical contract is `contracts/ZethoraPairAMM.sol`: storage layout, ABI,
//! event and error set. [`contract`] implements it against [`zethora_evm::EvmExecutor`]'s
//! state — real EVM storage at the declared slots, real ABI calldata through
//! [`contract::dispatch`], real state roots — the same way `zethora-bridge` drives
//! its bridge, because this workspace builds without a Solidity compiler.
//!
//! # The three files that matter
//!
//! * [`math`] — `x * y = k` with the 0.3% fee, as pure arithmetic with its own
//!   tests. If the maths is wrong nothing else can be right.
//! * [`contract`] — the pair's entry points, each shaped as *plan, validate, then
//!   write*, so no call can leave a half-applied trade behind.
//! * [`token`] — the two ERC20 ledgers the pair holds, at the storage slots a
//!   Solidity `balanceOf` mapping would use.
//!
//! The `zethora-dex` binary deploys a pair into an in-memory executor, seeds it,
//! and prints the state its calls produce, so the whole flow can be watched
//! without a node.
//!
//! # Example
//!
//! ```
//! use alloy_primitives::{Address, U256};
//! use zethora_dex::{add_liquidity, deploy, reserves, swap, token};
//! use zethora_evm::EvmExecutor;
//!
//! let mut executor = EvmExecutor::new();
//! let zthr = Address::repeat_byte(0x21);
//! let wzthr = Address::repeat_byte(0x22);
//! let alice = Address::repeat_byte(0xa1);
//!
//! let pair = deploy(&mut executor, zthr, wzthr).unwrap();
//! token::mint_to(&mut executor, pair.token0, alice, U256::from(10_000_000u64)).unwrap();
//! token::mint_to(&mut executor, pair.token1, alice, U256::from(10_000_000u64)).unwrap();
//!
//! let liquidity = add_liquidity(&mut executor, pair.pair, alice, U256::from(1_000_000u64), U256::from(2_000_000u64)).unwrap();
//! assert_eq!(liquidity, U256::from(1_413_213u64)); // sqrt(2e12) - 1_000 locked
//!
//! let out = swap(&mut executor, pair.pair, alice, pair.token0, U256::from(10_000u64)).unwrap();
//! assert_eq!(out, U256::from(19_743u64)); // 0.3% fee taken from the input
//! assert_eq!(reserves(&mut executor, pair.pair), (U256::from(1_010_000u64), U256::from(1_980_257u64)));
//! ```

pub mod contract;
pub mod math;
pub mod token;

pub use contract::{
    Deployment, DexError, add_liquidity, add_liquidity_calldata, add_liquidity_shielded,
    add_liquidity_shielded_calldata, deploy, dispatch, lp_balance, note_amount, note_commitment, note_count,
    note_depositor, note_log_digest, note_owner, nullifier_spent, pair_address, preview_liquidity, preview_removal,
    preview_swap, redeem_shielded_liquidity, redeem_shielded_liquidity_calldata, remove_liquidity,
    remove_liquidity_calldata, reserves, shield_liquidity, shield_liquidity_calldata, swap, swap_calldata, tokens,
    total_supply,
};
pub use math::{FEE_DENOMINATOR, FEE_NUMERATOR, MINIMUM_LIQUIDITY, MathError};
pub use token::TokenError;
