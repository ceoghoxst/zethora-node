//! Zethora (ZTHR) fees: reference implementation of ZTH-SPEC-008.
//! Tip: 100% to the miner. Base fee: 60% to the fee pool, 40% burned.
//! Fee pool pays floor(pool / P) to each block's miner, P = 2,592,000 (~30 days at 1 block/sec).
//! Integer math only. Run: cargo run --release   Test: cargo test

/// 1 ZTHR = 10^10 zets.
pub const ZETS_PER_ZTHR: u64 = 10_000_000_000;
/// Burn share of the base fee, in percent.
pub const BURN_PERCENT: u64 = 40;
/// Pool payout divisor: 30 days of 1-second blocks.
pub const P: u64 = 2_592_000;

/// Split a base fee into (to_pool, burned). Any rounding remainder goes to the pool,
/// so no unit is ever created or lost.
pub fn split_base_fee(base_fee: u64) -> (u64, u64) {
    let burned = ((base_fee as u128 * BURN_PERCENT as u128) / 100) as u64;
    (base_fee - burned, burned)
}

/// Payout from the pool to this block's miner.
pub fn pool_payout(pool: u64) -> u64 { pool / P }

/// Running totals for the fee system.
#[derive(Default, Debug, Clone)]
pub struct FeeState {
    pub pool: u64,
    pub total_burned: u64,
}

/// What one block's miner receives from fees (block reward is separate, ZTH-SPEC-001).
#[derive(Debug, PartialEq)]
pub struct BlockFees {
    pub tips: u64,
    pub pool_payout: u64,
    pub burned: u64,
}

impl FeeState {
    /// Process one block's fees. The payout is taken from the pool before this block's
    /// base fees are added, so a miner can never pay itself from its own block's fees.
    pub fn apply_block(&mut self, base_fees: u64, tips: u64) -> BlockFees {
        let payout = pool_payout(self.pool);
        self.pool -= payout;
        let (to_pool, burned) = split_base_fee(base_fees);
        self.pool = self.pool.checked_add(to_pool).expect("pool overflow");
        self.total_burned = self.total_burned.checked_add(burned).expect("burn overflow");
        BlockFees { tips, pool_payout: payout, burned }
    }
}

fn zthr(units: u64) -> f64 { units as f64 / ZETS_PER_ZTHR as f64 }

fn main() {
    println!("Zethora fees (ZTH-SPEC-008)\n");
    let (pool, burn) = split_base_fee(1_000_000);
    println!("Base fee 1,000,000 zets -> pool {pool}, burned {burn}  (tips go 100% to the miner)\n");

    // Scenario: every block pays 0.0001 ZTHR in base fees for 90 days.
    let base_per_block = ZETS_PER_ZTHR / 10_000;
    let mut s = FeeState::default();
    println!("Steady usage: {} ZTHR base fees per block", zthr(base_per_block));
    println!("{:>5} {:>16} {:>22} {:>16}", "Day", "Pool (ZTHR)", "Miner payout/block", "Burned (ZTHR)");
    for day in 1..=90u64 {
        let mut last = 0;
        for _ in 0..86_400 { last = s.apply_block(base_per_block, 0).pool_payout; }
        if [1, 7, 30, 60, 90].contains(&day) {
            println!("{:>5} {:>16.4} {:>22.10} {:>16.4}", day, zthr(s.pool), zthr(last), zthr(s.total_burned));
        }
    }
    println!("\nLong run: pool payout per block approaches 60% of base fees per block ({} ZTHR).",
        zthr(base_per_block * 60 / 100));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_is_60_40() {
        assert_eq!(split_base_fee(1_000), (600, 400));
        assert_eq!(split_base_fee(0), (0, 0));
    }

    #[test]
    fn split_never_creates_or_loses_units() {
        for fee in [1, 2, 3, 7, 99, 101, 12_345, u64::MAX] {
            let (pool, burn) = split_base_fee(fee);
            assert_eq!(pool + burn, fee);
            assert_eq!(burn as u128, fee as u128 * 40 / 100);
        }
    }

    #[test]
    fn block_conserves_value() {
        let mut s = FeeState { pool: 5_000_000_000_000, total_burned: 0 };
        let before = s.pool;
        let f = s.apply_block(1_000_000, 500);
        assert_eq!(f.tips, 500);
        // pool_after + paid out + burned == pool_before + base fees
        assert_eq!(s.pool + f.pool_payout + s.total_burned, before + 1_000_000);
    }

    #[test]
    fn miner_cannot_pay_itself_from_own_fees() {
        let mut s = FeeState::default();
        let f = s.apply_block(10_000_000_000, 0);
        assert_eq!(f.pool_payout, 0);
    }

    #[test]
    fn pool_spreads_over_about_30_days() {
        // One deposit, no new fees: after P blocks about 1/e (36.8%) remains.
        let mut s = FeeState { pool: 1_000_000 * ZETS_PER_ZTHR, total_burned: 0 };
        let start = s.pool;
        for _ in 0..P { s.apply_block(0, 0); }
        let left = s.pool as f64 / start as f64;
        assert!((left - 0.3679).abs() < 0.001, "got {left}");
    }

    #[test]
    fn steady_fees_reach_steady_payout() {
        // Constant base fees: payout per block approaches the 60% pool share.
        let base = 1_000_000_000u64;
        let mut s = FeeState::default();
        let mut last = 0;
        for _ in 0..(10 * P) { last = s.apply_block(base, 0).pool_payout; }
        let target = base * 60 / 100;
        assert!(last >= target * 999 / 1000 && last <= target, "got {last}, target {target}");
    }
}
