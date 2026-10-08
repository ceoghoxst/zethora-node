//! Zethora block subsidy (ZTH-SPEC-001 Section 5), for the Kaspa-based prototype node.
//!
//! Spec rule: reward(n) = floor(Remaining_n / D), Remaining_{n+1} = Remaining_n - reward(n),
//! Remaining_0 = CAP_UNITS - SUPPLY_RESERVE. Integer math only.
//!
//! The whole schedule (computed exactly, see `full_emission_schedule`): half mined at 8 years, 75% at 16, 99.6% at
//! 64; the reward reaches 0 at DAA score 8,126,002,948 (about 257.5 years at 1 block/sec), having paid exactly
//! `TOTAL_EMISSION` = 99,998,999.9635776057 ZTHR. The rewards always add up to Remaining_0 - Remaining_n (each
//! reward is what leaves Remaining), and Remaining never goes below 0, so the schedule can never pay more than
//! Remaining_0 = 99,999,000 ZTHR, whatever happens.
//!
//! SUPPLY_RESERVE: in a BlockDAG every block is paid the reward of its OWN DAA score (checked in body validation,
//! paid by the chain block that merges it), and blocks in each other's anticone can share a score. Compared with
//! paying every block at its place in line, a block paid at an earlier score s instead of its place p gets
//! reward(s) - reward(p) extra = the sum of the per-step drops between s and p. A merged block is only paid while it
//! is inside the merging block's difficulty window (older ones are "non-DAA" and unpaid), so s lags p by at most
//! about L = difficulty window (661 x 4 = 2,644 blocks on devnet) + mergeset limit (180). Each step's drop is then
//! counted at most L times, and all the drops together add up to the first reward (they telescope), so the total
//! extra over the whole schedule is at most L x reward(0) ~ 2,824 x 0.2746 ZTHR ~ 775 ZTHR, below the 1,000 ZTHR
//! that is never mined. On top of that the supply ledger refuses any block that would bring the total issued above
//! 100,000,000 ZTHR (`zethora_supply::SupplyError::CapExceeded`), so the hard cap holds no matter what. (That backstop
//! makes an over-paying block invalid, so if it ever fired the chain would stall rather than pay too much; at
//! 1 block/sec it cannot fire.)
//!
//! The schedule assumes 1 block per second (it is indexed by DAA score). The devnet runs at 1 block/sec; the
//! testnet and mainnet parameters are still Kaspa's 10 blocks/sec and must be set to 1 block/sec before either
//! launches, or rewards would come 10x faster (the cap would still hold).
//!
//! In the BlockDAG, `n` is the block's DAA score (one step per block in the DAA window, ~1 per second).
//! Remaining_n is found from a checkpoint every 2^20 scores (~12 days) plus a short walk,
//! with a cache of the last answer so sequential blocks cost a few steps.

use std::sync::Mutex;

/// 1 ZTHR = 10^10 zets.
pub const ZETS_PER_ZTHR: u64 = 10_000_000_000;
/// 100,000,000 ZTHR in zets.
pub const CAP_UNITS: u64 = 100_000_000 * ZETS_PER_ZTHR;
/// Never mined; guarantees the hard cap under BlockDAG parallelism (see module docs).
pub const SUPPLY_RESERVE: u64 = 1_000 * ZETS_PER_ZTHR;
/// Remaining supply at genesis.
pub const EMISSION_START: u64 = CAP_UNITS - SUPPLY_RESERVE;
/// Divisor at 1 block per second: round(8 years in seconds / ln 2).
pub const D: u64 = 364_223_944;
/// DAA score at which the reward first becomes 0 (it stays 0 after): about 257.5 years at 1 block/sec.
pub const EMISSION_END_SCORE: u64 = 8_126_002_948;
/// Everything the schedule ever pays, in zets: Remaining_0 minus what is left when the reward reaches 0
/// (99,998,999.9635776057 ZTHR). Computed exactly by `full_emission_schedule`.
pub const TOTAL_EMISSION: u64 = 999_989_999_635_776_057;
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
        Self { state: Mutex::new(State { checkpoints: vec![EMISSION_START], last: (0, EMISSION_START) }) }
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
        assert_eq!(z.subsidy(0), EMISSION_START / D); // ~0.2746 ZTHR
        assert_eq!(z.subsidy(0), 2_745_536_136);
    }

    #[test]
    fn matches_plain_recurrence() {
        // Same numbers as tools/emission (the reference implementation).
        let z = ZethoraSubsidy::new();
        let mut r = EMISSION_START;
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
        assert_eq!(emitted, EMISSION_START - z.remaining_at(1_000_000));
        assert!(emitted <= CAP_UNITS);
    }

    #[test]
    fn reserve_covers_worst_case_dag_overshoot() {
        // See the module docs: a paid block's own score lags its place by at most the difficulty window plus a
        // mergeset, each per-step drop is counted at most that many times, and the drops add up to the first reward.
        let p = kaspa_consensus_core::config::params::DEVNET_PARAMS;
        let lag = p.difficulty_window_size as u64 * p.difficulty_sample_rate() + p.mergeset_size_limit();
        assert_eq!(lag, 2_644 + 180);
        let worst_extra = lag * (EMISSION_START / D);
        assert!(worst_extra < SUPPLY_RESERVE, "worst extra {worst_extra} zets"); // ~775 of 1,000 ZTHR
        assert_eq!(EMISSION_START + SUPPLY_RESERVE, CAP_UNITS);
    }

    #[test]
    fn the_drops_add_up_to_the_first_reward() {
        // The telescoping step of the bound: reward(0) - reward(n) is the sum of the first n drops
        let z = ZethoraSubsidy::new();
        let mut drops = 0u64;
        let mut prev = z.subsidy(0);
        for n in 1..200_000u64 {
            let next = z.subsidy(n);
            drops += prev - next;
            prev = next;
        }
        assert_eq!(drops, z.subsidy(0) - prev);
    }

    #[test]
    fn the_drop_per_step_is_small() {
        // The overshoot bound above uses: reward(n) - reward(n+1) <= 1 + Remaining_n / D^2 (at most 8 zets at the start)
        let mut r = EMISSION_START;
        for _ in 0..2_000_000 {
            let next = step(r);
            assert!(r / D - next / D <= 1 + r / (D * D));
            r = next;
        }
        assert!(1 + EMISSION_START / (D * D) <= 8);
    }

    /// Walks the schedule exactly, many steps at a time: while floor(Remaining / D) stays q, every step takes q.
    /// Records Remaining at each of `at` (ascending). With `to_the_end` it keeps going until the reward reaches 0 and
    /// returns that score and the Remaining left then; otherwise it stops after the last of `at`.
    fn walk(at: &[u64], to_the_end: bool) -> (u64, u64, Vec<u64>) {
        let (mut r, mut n) = (EMISSION_START, 0u64);
        let mut seen = Vec::new();
        loop {
            if !to_the_end && seen.len() == at.len() {
                break;
            }
            let q = r / D;
            if q == 0 {
                break;
            }
            let steps = (r - q * D) / q + 1; // steps until floor(Remaining / D) drops below q
            if let Some(&next) = at.get(seen.len())
                && n + steps >= next
            {
                seen.push(r - (next - n) * q);
                continue;
            }
            r -= steps * q;
            n += steps;
        }
        (n, r, seen)
    }

    #[test]
    fn full_emission_schedule() {
        const YEAR: u64 = 31_557_600; // DAA scores per year at 1 block/sec
        // The fast walk agrees with the node's own step-by-step lookup
        let (_, _, early) = walk(&[1, 99_991, YEAR], false);
        let z = ZethoraSubsidy::new();
        assert_eq!(early, vec![z.remaining_at(1), z.remaining_at(99_991), z.remaining_at(YEAR)]);
        if cfg!(debug_assertions) {
            println!("full_emission_schedule: the whole 257-year walk only runs in release mode (cargo test --release)");
            return;
        }
        // The whole schedule (a billion jumps: a few seconds in release mode)
        let (end, left, at) = walk(&[YEAR, 8 * YEAR, 32 * YEAR, 128 * YEAR], true);
        assert_eq!(at, vec![916_994_873_031_269_329, 499_994_999_445_101_369, 62_499_374_847_745_337, 15_258_818_268_144]);
        assert_eq!(end, EMISSION_END_SCORE);
        assert!(left < D, "the reward is 0 from here on");
        assert_eq!(EMISSION_START - left, TOTAL_EMISSION);
        assert!(TOTAL_EMISSION + SUPPLY_RESERVE <= CAP_UNITS);
        // The node's step-by-step lookup agrees 8 years in too (a quarter billion steps)
        assert_eq!(z.remaining_at(8 * YEAR), at[1]);
        println!(
            "full_emission_schedule: reward reaches 0 at DAA score {end} ({:.1} years); total ever paid {TOTAL_EMISSION} zets = {}.{:010} ZTHR; never paid: {} zets",
            end as f64 / YEAR as f64,
            TOTAL_EMISSION / ZETS_PER_ZTHR,
            TOTAL_EMISSION % ZETS_PER_ZTHR,
            CAP_UNITS - TOTAL_EMISSION
        );
    }

    #[test]
    fn half_mined_at_8_years() {
        let z = ZethoraSubsidy::new();
        let eight_years = 8 * 31_557_600u64;
        let pct = 1.0 - z.remaining_at(eight_years) as f64 / EMISSION_START as f64;
        assert!((pct - 0.5).abs() < 0.001, "got {pct}");
    }
}
