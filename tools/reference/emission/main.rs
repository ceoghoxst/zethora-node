//! Zethora (ZTHR) emission schedule: reference implementation of ZTH-SPEC-001 Section 5.
//! Integer math only. Anyone can run this to verify the supply schedule.
//! Run: cargo run --release

/// 1 ZTHR = 10^10 zets.
pub const ZETS_PER_ZTHR: u64 = 10_000_000_000;
/// Hard cap: 100,000,000 ZTHR = 10^18 zets (fits in i64 and u64).
pub const CAP_UNITS: u64 = 100_000_000 * ZETS_PER_ZTHR;
/// Never mined; guarantees the cap under BlockDAG parallelism (ZTH-SPEC-001 §5.7).
pub const SUPPLY_RESERVE: u64 = 1_000 * ZETS_PER_ZTHR;
/// Remaining supply at genesis.
pub const EMISSION_START: u64 = CAP_UNITS - SUPPLY_RESERVE;
/// Divisor at 1 block per second: round(8 years in seconds / ln 2).
pub const D: u64 = 364_223_944;
/// Blocks per year at 1 block per second (365.25 days).
pub const BLOCKS_PER_YEAR: u64 = 31_557_600;

/// Block reward given total emitted so far. reward = floor(Remaining / D),
/// Remaining = CAP_UNITS - SUPPLY_RESERVE - emitted.
pub fn reward(emitted: u64) -> u64 {
    let remaining = EMISSION_START.checked_sub(emitted).expect("emitted exceeds emission limit");
    remaining / D
}

/// Total emitted after `blocks` blocks, computed block by block.
pub fn emitted_after(blocks: u64) -> u64 {
    let mut emitted: u64 = 0;
    for _ in 0..blocks {
        let r = reward(emitted);
        if r == 0 { break; }
        emitted = emitted.checked_add(r).expect("overflow");
        assert!(emitted <= CAP_UNITS, "cap exceeded");
    }
    emitted
}

fn zthr(units: u64) -> f64 { units as f64 / ZETS_PER_ZTHR as f64 }

fn main() {
    println!("Zethora emission schedule (ZTH-SPEC-001, 1 block/sec)");
    println!("Cap: {} ZTHR | never-mined reserve: {} ZTHR | D = {}", CAP_UNITS / ZETS_PER_ZTHR, SUPPLY_RESERVE / ZETS_PER_ZTHR, D);
    println!("First block reward: {:.10} ZTHR\n", zthr(reward(0)));
    println!("{:>6} {:>18} {:>8} {:>16}", "Year", "Total mined", "% cap", "Reward/block");
    let mut emitted: u64 = 0;
    let mut year = 0u64;
    for target in [1u64, 8, 16, 27, 50] {
        while year < target {
            for _ in 0..BLOCKS_PER_YEAR {
                emitted += reward(emitted);
            }
            year += 1;
        }
        println!("{:>6} {:>18.0} {:>7.2}% {:>16.10}",
            year, zthr(emitted), 100.0 * emitted as f64 / CAP_UNITS as f64, zthr(reward(emitted)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_fits_in_i64() { assert!(CAP_UNITS <= i64::MAX as u64); }

    #[test]
    fn d_matches_formula() {
        let secs = 8.0 * 365.25 * 86_400.0;
        assert_eq!((secs / std::f64::consts::LN_2).round() as u64, D);
    }

    #[test]
    fn first_reward_is_about_0_2746() {
        let r = zthr(reward(0));
        assert!((r - 0.2746).abs() < 0.0001, "got {r}");
    }

    #[test]
    fn half_mined_at_8_years() {
        let pct = emitted_after(8 * BLOCKS_PER_YEAR) as f64 / CAP_UNITS as f64;
        assert!((pct - 0.5).abs() < 0.001, "got {pct}");
    }

    #[test]
    fn reward_never_exceeds_remaining() {
        for e in [0, EMISSION_START / 2, EMISSION_START - D, EMISSION_START - 1, EMISSION_START] {
            assert!(reward(e) <= EMISSION_START - e);
        }
        assert_eq!(reward(EMISSION_START - D + 1), 0, "emission ends when Remaining < D");
    }

    #[test]
    fn first_reward_matches_node() {
        // Same value as the zethora-node consensus code.
        assert_eq!(reward(0), 2_745_536_136);
    }

    #[test]
    fn reserve_is_1000_zthr_and_never_mined() {
        assert_eq!(EMISSION_START + SUPPLY_RESERVE, CAP_UNITS);
        assert_eq!(SUPPLY_RESERVE, 1_000 * ZETS_PER_ZTHR);
    }
}
