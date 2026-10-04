//! Zethora fees: base fee vs tip, fee pool and burn (ZTH-SPEC-008).
//!
//! For every accepted transaction:
//!     base = min(fee, compute_mass * BASE_FEE_PER_KG / 1000)
//!     tip  = fee - base
//! Tips go 100% to the miner. Base fees are split: 60% into the fee pool, 40% burned.
//!
//! The pool is carried in each block's coinbase payload and flows along the selected chain:
//!     payout   = pool_in / POOL_PAYOUT_DIVISOR        (paid to this block's miner)
//!     to_pool  = base_total * 60 / 100
//!     burned   = base_total - to_pool                 (destroyed: paid to no one)
//!     pool_out = pool_in - payout + to_pool
//!
//! Prototype: the base fee rate is fixed. The demand-based base fee (SPEC-008 §4.1) comes later.

use kaspa_consensus_core::coinbase::PoolState;

/// Base fee rate in zets per 1,000 grams of compute mass (matches the default mempool minimum).
pub const BASE_FEE_PER_KG: u64 = 100_000;
/// Share of base fees that goes into the pool, in percent. The rest is burned.
pub const POOL_SHARE_PERCENT: u64 = 60;
/// Each block pays this fraction of the pool to its miner (~30 days at 1 block/sec).
pub const POOL_PAYOUT_DIVISOR: u64 = 2_592_000;

/// The base-fee part of a transaction's fee.
#[inline]
pub fn base_fee(fee: u64, compute_mass: u64) -> u64 {
    let base_required = ((compute_mass as u128 * BASE_FEE_PER_KG as u128) / 1000).min(u64::MAX as u128) as u64;
    fee.min(base_required)
}

/// The result of applying one chain block's base fees to the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStep {
    /// Paid from the pool to this block's miner.
    pub payout: u64,
    /// Destroyed in this block.
    pub burned: u64,
    /// Pool state after this block.
    pub next: PoolState,
}

/// Applies a chain block's total base fees to the pool state of its selected parent.
pub fn pool_step(parent: PoolState, base_total: u64) -> PoolStep {
    let payout = parent.pool_balance / POOL_PAYOUT_DIVISOR;
    let to_pool = ((base_total as u128 * POOL_SHARE_PERCENT as u128) / 100) as u64;
    let burned = base_total - to_pool;
    let next = PoolState {
        pool_balance: parent.pool_balance - payout + to_pool,
        total_burned: parent.total_burned.checked_add(burned).expect("burn counter overflow"),
        ..parent // the supply ledger fields are updated by zethora_supply::ledger_step
    };
    PoolStep { payout, burned, next }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fee_never_exceeds_fee() {
        assert_eq!(base_fee(1_000, 2_000), 1_000); // fee below required base: all of it is base
        assert_eq!(base_fee(250_000, 2_000), 200_000); // 2,000 grams * 100 = 200,000 base; 50,000 tip
        assert_eq!(base_fee(0, 2_000), 0);
        assert_eq!(base_fee(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn split_is_60_40_and_conserves_value() {
        let s = pool_step(PoolState::default(), 1_000);
        assert_eq!(s.next.pool_balance, 600);
        assert_eq!(s.burned, 400);
        assert_eq!(s.payout, 0);
        for base in [0u64, 1, 3, 7, 99, 12_345, 1 << 40] {
            let parent = PoolState { pool_balance: 9_876_543_210, total_burned: 5, ..Default::default() };
            let s = pool_step(parent, base);
            // pool_in + base fees == pool_out + payout + burned
            assert_eq!(parent.pool_balance + base, s.next.pool_balance + s.payout + s.burned);
            assert_eq!(s.next.total_burned, parent.total_burned + s.burned);
        }
    }

    #[test]
    fn pool_pays_out_over_about_30_days() {
        // One deposit, no new fees: after 30 days of blocks about 1/e (36.8%) remains.
        let mut state = PoolState { pool_balance: 1_000_000 * 10_000_000_000, ..Default::default() };
        let start = state.pool_balance;
        for _ in 0..POOL_PAYOUT_DIVISOR {
            state = pool_step(state, 0).next;
        }
        let left = state.pool_balance as f64 / start as f64;
        assert!((left - 0.3679).abs() < 0.001, "got {left}");
    }
}
