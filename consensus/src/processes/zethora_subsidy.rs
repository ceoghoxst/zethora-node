//! Zethora block subsidy (ZTH-SPEC-001 Section 5), for the Kaspa-based prototype node.
//!
//! Spec rule: reward(n) = floor(Remaining_n / D), Remaining_{n+1} = Remaining_n - reward(n),
//! Remaining_0 = CAP_UNITS. Integer math only.
//!
//! In the BlockDAG, `n` is the block's DAA score (one step per block in the DAA window, ~1 per second).
//! Remaining_n is found from a checkpoint every 2^20 scores (~12 days) plus a short walk,
//! with a cache of the last answer so sequential blocks cost a few steps.

use std::sync::Mutex;

/// 1 ZTHR = 10^10 zets.
pub const ZETS_PER_ZTHR: u64 = 10_000_000_000;
/// 100,000,000 ZTHR in zets.
pub const CAP_UNITS: u64 = 100_000_000 * ZETS_PER_ZTHR;
/// Divisor at 1 block per second: round(8 years in seconds / ln 2).
pub const D: u64 = 364_223_944;
/// Checkpoint spacing (2^20 DAA scores).
const CHECKPOINT_SHIFT: u32 = 20;
const CHECKPOINT_INTERVAL: u64 = 1 << CHECKPOINT_SHIFT;

#[inline]
fn step(remaining: u64) -> u64 {
    remaining - remaining / D
}

struct State {
    /// checkpoints[k] = Remaining at DAA score k * CHECKPOINT_INTERVAL
    checkpoints: Vec<u64>,
    /// (score, Remaining at score) of the last lookup
    last: (u64, u64),
}

pub struct ZethoraSubsidy {
    state: Mutex<State>,
}

impl Default for ZethoraSubsidy {
    fn default() -> Self {
        Self::new()
    }
}

impl ZethoraSubsidy {
    pub fn new() -> Self {
        Self { state: Mutex::new(State { checkpoints: vec![CAP_UNITS], last: (0, CAP_UNITS) }) }
    }

    /// Remaining supply (zets) before the block at `score` is rewarded.
    pub fn remaining_at(&self, score: u64) -> u64 {
        let mut s = self.state.lock().unwrap();
        // Fast path: walk forward from the last answer if close.
        let (last_score, last_rem) = s.last;
        if score >= last_score && score - last_score <= CHECKPOINT_INTERVAL {
            let mut r = last_rem;
            for _ in last_score..score {
                r = step(r);
            }
            s.last = (score, r);
            return r;
        }
        // Extend checkpoints as needed.
        let k = (score >> CHECKPOINT_SHIFT) as usize;
        while s.checkpoints.len() <= k {
            let mut r = *s.checkpoints.last().unwrap();
            for _ in 0..CHECKPOINT_INTERVAL {
                r = step(r);
            }
            s.checkpoints.push(r);
        }
        let mut r = s.checkpoints[k];
        for _ in 0..(score & (CHECKPOINT_INTERVAL - 1)) {
            r = step(r);
        }
        s.last = (score, r);
        r
    }

    /// Block subsidy (zets) for a block with this DAA score.
    pub fn subsidy(&self, daa_score: u64) -> u64 {
        self.remaining_at(daa_score) / D
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_reward_matches_spec() {
        let z = ZethoraSubsidy::new();
        assert_eq!(z.subsidy(0), CAP_UNITS / D); // ~0.2746 ZTHR
        assert_eq!(z.subsidy(0), 2_745_563_592);
    }

    #[test]
    fn matches_plain_recurrence() {
        // Same numbers as tools/emission (the reference implementation).
        let z = ZethoraSubsidy::new();
        let mut r = CAP_UNITS;
        for n in 0..3_000_000u64 {
            if n % 99_991 == 0 {
                assert_eq!(z.remaining_at(n), r, "score {n}");
            }
            r = step(r);
        }
    }

    #[test]
    fn random_access_equals_sequential() {
        let a = ZethoraSubsidy::new();
        let b = ZethoraSubsidy::new();
        let scores = [5_000_000u64, 17, 2_000_000, 4_194_305, 3];
        for s in scores {
            assert_eq!(a.remaining_at(s), b.remaining_at(s));
            let fresh = ZethoraSubsidy::new();
            assert_eq!(fresh.remaining_at(s), a.remaining_at(s));
        }
    }

    #[test]
    fn rewards_sum_to_emitted_and_never_exceed_cap() {
        let z = ZethoraSubsidy::new();
        let mut emitted: u64 = 0;
        for n in 0..1_000_000u64 {
            emitted = emitted.checked_add(z.subsidy(n)).unwrap();
        }
        assert_eq!(emitted, CAP_UNITS - z.remaining_at(1_000_000));
        assert!(emitted <= CAP_UNITS);
    }

    #[test]
    fn half_mined_at_8_years() {
        let z = ZethoraSubsidy::new();
        let eight_years = 8 * 31_557_600u64;
        let pct = 1.0 - z.remaining_at(eight_years) as f64 / CAP_UNITS as f64;
        assert!((pct - 0.5).abs() < 0.001, "got {pct}");
    }
}
