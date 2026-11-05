ZETHORA SEAM REVIEW PACK: 5. Supply ledger <-> Kaspa coinbase (cap, emission, fee pool, BALANCED)
Branch f2-hardening (final pre-merge code), commit 1cd9398. Real line numbers.
FULL FILE = complete file. EXCERPTS = only the Zethora-related sections (+-25 lines) of large Kaspa files.

======== FULL FILE: consensus/src/processes/zethora_subsidy.rs ========
     1	//! Zethora block subsidy (ZTH-SPEC-001 Section 5), for the Kaspa-based prototype node.
     2	//!
     3	//! Spec rule: reward(n) = floor(Remaining_n / D), Remaining_{n+1} = Remaining_n - reward(n),
     4	//! Remaining_0 = CAP_UNITS - SUPPLY_RESERVE. Integer math only.
     5	//!
     6	//! The whole schedule (computed exactly, see `full_emission_schedule`): half mined at 8 years, 75% at 16, 99.6% at
     7	//! 64; the reward reaches 0 at DAA score 8,126,002,948 (about 257.5 years at 1 block/sec), having paid exactly
     8	//! `TOTAL_EMISSION` = 99,998,999.9635776057 ZTHR. The rewards always add up to Remaining_0 - Remaining_n (each
     9	//! reward is what leaves Remaining), and Remaining never goes below 0, so the schedule can never pay more than
    10	//! Remaining_0 = 99,999,000 ZTHR, whatever happens.
    11	//!
    12	//! SUPPLY_RESERVE: in a BlockDAG every block is paid the reward of its OWN DAA score (checked in body validation,
    13	//! paid by the chain block that merges it), and blocks in each other's anticone can share a score. Compared with
    14	//! paying every block at its place in line, a block paid at an earlier score s instead of its place p gets
    15	//! reward(s) - reward(p) extra = the sum of the per-step drops between s and p. A merged block is only paid while it
    16	//! is inside the merging block's difficulty window (older ones are "non-DAA" and unpaid), so s lags p by at most
    17	//! about L = difficulty window (661 x 4 = 2,644 blocks on devnet) + mergeset limit (180). Each step's drop is then
    18	//! counted at most L times, and all the drops together add up to the first reward (they telescope), so the total
    19	//! extra over the whole schedule is at most L x reward(0) ~ 2,824 x 0.2746 ZTHR ~ 775 ZTHR, below the 1,000 ZTHR
    20	//! that is never mined. On top of that the supply ledger refuses any block that would bring the total issued above
    21	//! 100,000,000 ZTHR, and the coinbase pays each merged block min(its subsidy, what is left under the cap)
    22	//! (`CoinbaseManager::expected_coinbase_transaction`, F2 2026-10-28), so the hard cap holds exactly no matter what and
    23	//! an honest block is never invalid because of it (`zethora_supply::SupplyError::CapExceeded` stays as a backstop).
    24	//!
    25	//! The schedule assumes 1 block per second (it is indexed by DAA score). Devnet, testnet and mainnet all run at
    26	//! 1 block/sec (params.rs, checked by `mainnet_and_testnet_run_at_one_block_per_second_with_anchor_depth_600`);
    27	//! only simnet (tests) runs at 10.
    28	//!
    29	//! In the BlockDAG, `n` is the block's DAA score (one step per block in the DAA window, ~1 per second).
    30	//! Remaining_n is found from a checkpoint every 2^20 scores (~12 days) plus a short walk,
    31	//! with a cache of the last answer so sequential blocks cost a few steps.
    32	
    33	use std::sync::Mutex;
    34	
    35	/// 1 ZTHR = 10^10 zets, and the 100,000,000 ZTHR hard cap in zets (defined in consensus-core, also read by the RPC).
    36	pub use kaspa_consensus_core::constants::{CAP_UNITS, ZETS_PER_ZTHR};
    37	/// Never mined; guarantees the hard cap under BlockDAG parallelism (see module docs).
    38	pub const SUPPLY_RESERVE: u64 = 1_000 * ZETS_PER_ZTHR;
    39	/// Remaining supply at genesis.
    40	pub const EMISSION_START: u64 = CAP_UNITS - SUPPLY_RESERVE;
    41	/// Divisor at 1 block per second: round(8 years in seconds / ln 2).
    42	pub const D: u64 = 364_223_944;
    43	/// DAA score at which the reward first becomes 0 (it stays 0 after): about 257.5 years at 1 block/sec.
    44	pub const EMISSION_END_SCORE: u64 = 8_126_002_948;
    45	/// Everything the schedule ever pays, in zets: Remaining_0 minus what is left when the reward reaches 0
    46	/// (99,998,999.9635776057 ZTHR). Computed exactly by `full_emission_schedule`.
    47	pub const TOTAL_EMISSION: u64 = 999_989_999_635_776_057;
    48	/// Checkpoint spacing (2^20 DAA scores).
    49	const CHECKPOINT_SHIFT: u32 = 20;
    50	const CHECKPOINT_INTERVAL: u64 = 1 << CHECKPOINT_SHIFT;
    51	
    52	#[inline]
    53	fn step(remaining: u64) -> u64 {
    54	    remaining - remaining / D
    55	}
    56	
    57	struct State {
    58	    /// checkpoints[k] = Remaining at DAA score k * CHECKPOINT_INTERVAL
    59	    checkpoints: Vec<u64>,
    60	    /// (score, Remaining at score) of the last lookup
    61	    last: (u64, u64),
    62	}
    63	
    64	pub struct ZethoraSubsidy {
    65	    state: Mutex<State>,
    66	}
    67	
    68	impl Default for ZethoraSubsidy {
    69	    fn default() -> Self {
    70	        Self::new()
    71	    }
    72	}
    73	
    74	impl ZethoraSubsidy {
    75	    pub fn new() -> Self {
    76	        Self { state: Mutex::new(State { checkpoints: vec![EMISSION_START], last: (0, EMISSION_START) }) }
    77	    }
    78	
    79	    /// Remaining supply (zets) before the block at `score` is rewarded.
    80	    pub fn remaining_at(&self, score: u64) -> u64 {
    81	        let mut s = self.state.lock().unwrap();
    82	        // Fast path: walk forward from the last answer if close.
    83	        let (last_score, last_rem) = s.last;
    84	        if score >= last_score && score - last_score <= CHECKPOINT_INTERVAL {
    85	            let mut r = last_rem;
    86	            for _ in last_score..score {
    87	                r = step(r);
    88	            }
    89	            s.last = (score, r);
    90	            return r;
    91	        }
    92	        // Extend checkpoints as needed.
    93	        let k = (score >> CHECKPOINT_SHIFT) as usize;
    94	        while s.checkpoints.len() <= k {
    95	            let mut r = *s.checkpoints.last().unwrap();
    96	            for _ in 0..CHECKPOINT_INTERVAL {
    97	                r = step(r);
    98	            }
    99	            s.checkpoints.push(r);
   100	        }
   101	        let mut r = s.checkpoints[k];
   102	        for _ in 0..(score & (CHECKPOINT_INTERVAL - 1)) {
   103	            r = step(r);
   104	        }
   105	        s.last = (score, r);
   106	        r
   107	    }
   108	
   109	    /// Block subsidy (zets) for a block with this DAA score.
   110	    pub fn subsidy(&self, daa_score: u64) -> u64 {
   111	        self.remaining_at(daa_score) / D
   112	    }
   113	}
   114	
   115	#[cfg(test)]
   116	mod tests {
   117	    use super::*;
   118	
   119	    #[test]
   120	    fn first_reward_matches_spec() {
   121	        let z = ZethoraSubsidy::new();
   122	        assert_eq!(z.subsidy(0), EMISSION_START / D); // ~0.2746 ZTHR
   123	        assert_eq!(z.subsidy(0), 2_745_536_136);
   124	    }
   125	
   126	    #[test]
   127	    fn matches_plain_recurrence() {
   128	        // Same numbers as tools/emission (the reference implementation).
   129	        let z = ZethoraSubsidy::new();
   130	        let mut r = EMISSION_START;
   131	        for n in 0..3_000_000u64 {
   132	            if n % 99_991 == 0 {
   133	                assert_eq!(z.remaining_at(n), r, "score {n}");
   134	            }
   135	            r = step(r);
   136	        }
   137	    }
   138	
   139	    #[test]
   140	    fn random_access_equals_sequential() {
   141	        let a = ZethoraSubsidy::new();
   142	        let b = ZethoraSubsidy::new();
   143	        let scores = [5_000_000u64, 17, 2_000_000, 4_194_305, 3];
   144	        for s in scores {
   145	            assert_eq!(a.remaining_at(s), b.remaining_at(s));
   146	            let fresh = ZethoraSubsidy::new();
   147	            assert_eq!(fresh.remaining_at(s), a.remaining_at(s));
   148	        }
   149	    }
   150	
   151	    #[test]
   152	    fn rewards_sum_to_emitted_and_never_exceed_cap() {
   153	        let z = ZethoraSubsidy::new();
   154	        let mut emitted: u64 = 0;
   155	        for n in 0..1_000_000u64 {
   156	            emitted = emitted.checked_add(z.subsidy(n)).unwrap();
   157	        }
   158	        assert_eq!(emitted, EMISSION_START - z.remaining_at(1_000_000));
   159	        assert!(emitted <= CAP_UNITS);
   160	    }
   161	
   162	    #[test]
   163	    fn reserve_covers_worst_case_dag_overshoot() {
   164	        // See the module docs: a paid block's own score lags its place by at most the difficulty window plus a
   165	        // mergeset, each per-step drop is counted at most that many times, and the drops add up to the first reward.
   166	        let p = kaspa_consensus_core::config::params::DEVNET_PARAMS;
   167	        let lag = p.difficulty_window_size as u64 * p.difficulty_sample_rate() + p.mergeset_size_limit();
   168	        assert_eq!(lag, 2_644 + 180);
   169	        let worst_extra = lag * (EMISSION_START / D);
   170	        assert!(worst_extra < SUPPLY_RESERVE, "worst extra {worst_extra} zets"); // ~775 of 1,000 ZTHR
   171	        assert_eq!(EMISSION_START + SUPPLY_RESERVE, CAP_UNITS);
   172	    }
   173	
   174	    #[test]
   175	    fn the_drops_add_up_to_the_first_reward() {
   176	        // The telescoping step of the bound: reward(0) - reward(n) is the sum of the first n drops
   177	        let z = ZethoraSubsidy::new();
   178	        let mut drops = 0u64;
   179	        let mut prev = z.subsidy(0);
   180	        for n in 1..200_000u64 {
   181	            let next = z.subsidy(n);
   182	            drops += prev - next;
   183	            prev = next;
   184	        }
   185	        assert_eq!(drops, z.subsidy(0) - prev);
   186	    }
   187	
   188	    #[test]
   189	    fn the_drop_per_step_is_small() {
   190	        // The overshoot bound above uses: reward(n) - reward(n+1) <= 1 + Remaining_n / D^2 (at most 8 zets at the start)
   191	        let mut r = EMISSION_START;
   192	        for _ in 0..2_000_000 {
   193	            let next = step(r);
   194	            assert!(r / D - next / D <= 1 + r / (D * D));
   195	            r = next;
   196	        }
   197	        const { assert!(EMISSION_START / (D * D) < 8) }; // i.e. 1 + EMISSION_START / D^2 <= 8
   198	    }
   199	
   200	    /// Walks the schedule exactly, many steps at a time: while floor(Remaining / D) stays q, every step takes q.
   201	    /// Records Remaining at each of `at` (ascending). With `to_the_end` it keeps going until the reward reaches 0 and
   202	    /// returns that score and the Remaining left then; otherwise it stops after the last of `at`.
   203	    fn walk(at: &[u64], to_the_end: bool) -> (u64, u64, Vec<u64>) {
   204	        let (mut r, mut n) = (EMISSION_START, 0u64);
   205	        let mut seen = Vec::new();
   206	        loop {
   207	            if !to_the_end && seen.len() == at.len() {
   208	                break;
   209	            }
   210	            let q = r / D;
   211	            if q == 0 {
   212	                break;
   213	            }
   214	            let steps = (r - q * D) / q + 1; // steps until floor(Remaining / D) drops below q
   215	            if let Some(&next) = at.get(seen.len())
   216	                && n + steps >= next
   217	            {
   218	                seen.push(r - (next - n) * q);
   219	                continue;
   220	            }
   221	            r -= steps * q;
   222	            n += steps;
   223	        }
   224	        (n, r, seen)
   225	    }
   226	
   227	    #[test]
   228	    fn full_emission_schedule() {
   229	        const YEAR: u64 = 31_557_600; // DAA scores per year at 1 block/sec
   230	        // The fast walk agrees with the node's own step-by-step lookup
   231	        let (_, _, early) = walk(&[1, 99_991, YEAR], false);
   232	        let z = ZethoraSubsidy::new();
   233	        assert_eq!(early, vec![z.remaining_at(1), z.remaining_at(99_991), z.remaining_at(YEAR)]);
   234	        if cfg!(debug_assertions) {
   235	            println!("full_emission_schedule: the whole 257-year walk only runs in release mode (cargo test --release)");
   236	            return;
   237	        }
   238	        // The whole schedule (a billion jumps: a few seconds in release mode)
   239	        let (end, left, at) = walk(&[YEAR, 8 * YEAR, 32 * YEAR, 128 * YEAR], true);
   240	        assert_eq!(at, vec![916_994_873_031_269_329, 499_994_999_445_101_369, 62_499_374_847_745_337, 15_258_818_268_144]);
   241	        assert_eq!(end, EMISSION_END_SCORE);
   242	        assert!(left < D, "the reward is 0 from here on");
   243	        assert_eq!(EMISSION_START - left, TOTAL_EMISSION);
   244	        const { assert!(TOTAL_EMISSION + SUPPLY_RESERVE <= CAP_UNITS) };
   245	        // The node's step-by-step lookup agrees 8 years in too (a quarter billion steps)
   246	        assert_eq!(z.remaining_at(8 * YEAR), at[1]);
   247	        println!(
   248	            "full_emission_schedule: reward reaches 0 at DAA score {end} ({:.1} years); total ever paid {TOTAL_EMISSION} zets = {}.{:010} ZTHR; never paid: {} zets",
   249	            end as f64 / YEAR as f64,
   250	            TOTAL_EMISSION / ZETS_PER_ZTHR,
   251	            TOTAL_EMISSION % ZETS_PER_ZTHR,
   252	            CAP_UNITS - TOTAL_EMISSION
   253	        );
   254	    }
   255	
   256	    #[test]
   257	    fn half_mined_at_8_years() {
   258	        let z = ZethoraSubsidy::new();
   259	        let eight_years = 8 * 31_557_600u64;
   260	        let pct = 1.0 - z.remaining_at(eight_years) as f64 / EMISSION_START as f64;
   261	        assert!((pct - 0.5).abs() < 0.001, "got {pct}");
   262	    }
   263	}

======== FULL FILE: consensus/src/processes/zethora_fees.rs ========
     1	//! Zethora fees: base fee vs tip, fee pool and burn (ZTH-SPEC-008).
     2	//!
     3	//! For every accepted transaction:
     4	//!     base = min(fee, compute_mass * BASE_FEE_PER_KG / 1000)
     5	//!     tip  = fee - base
     6	//! Tips go 100% to the miner. Base fees are split: 60% into the fee pool, 40% burned.
     7	//!
     8	//! The pool is carried in each block's coinbase payload and flows along the selected chain:
     9	//!     payout   = pool_in / POOL_PAYOUT_DIVISOR        (paid to this block's miner)
    10	//!     to_pool  = base_total * 60 / 100
    11	//!     burned   = base_total - to_pool                 (destroyed: paid to no one)
    12	//!     pool_out = pool_in - payout + to_pool
    13	//!
    14	//! Prototype: the base fee rate is fixed. The demand-based base fee (SPEC-008 §4.1) comes later.
    15	
    16	use kaspa_consensus_core::coinbase::PoolState;
    17	
    18	/// Base fee rate in zets per 1,000 grams of compute mass (matches the default mempool minimum).
    19	pub const BASE_FEE_PER_KG: u64 = 100_000;
    20	/// Share of base fees that goes into the pool, in percent. The rest is burned.
    21	pub const POOL_SHARE_PERCENT: u64 = 60;
    22	/// Each block pays this fraction of the pool to its miner (~30 days at 1 block/sec).
    23	pub const POOL_PAYOUT_DIVISOR: u64 = 2_592_000;
    24	
    25	/// The base-fee part of a transaction's fee.
    26	#[inline]
    27	pub fn base_fee(fee: u64, compute_mass: u64) -> u64 {
    28	    let base_required = ((compute_mass as u128 * BASE_FEE_PER_KG as u128) / 1000).min(u64::MAX as u128) as u64;
    29	    fee.min(base_required)
    30	}
    31	
    32	/// The result of applying one chain block's base fees to the pool.
    33	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    34	pub struct PoolStep {
    35	    /// Paid from the pool to this block's miner.
    36	    pub payout: u64,
    37	    /// Destroyed in this block.
    38	    pub burned: u64,
    39	    /// Pool state after this block.
    40	    pub next: PoolState,
    41	}
    42	
    43	/// Applies a chain block's total base fees to the pool state of its selected parent.
    44	pub fn pool_step(parent: PoolState, base_total: u64) -> PoolStep {
    45	    let payout = parent.pool_balance / POOL_PAYOUT_DIVISOR;
    46	    let to_pool = ((base_total as u128 * POOL_SHARE_PERCENT as u128) / 100) as u64;
    47	    let burned = base_total - to_pool;
    48	    let next = PoolState {
    49	        pool_balance: parent.pool_balance - payout + to_pool,
    50	        total_burned: parent.total_burned.checked_add(burned).expect("burn counter overflow"),
    51	        ..parent // the supply ledger fields are updated by zethora_supply::ledger_step
    52	    };
    53	    PoolStep { payout, burned, next }
    54	}
    55	
    56	#[cfg(test)]
    57	mod tests {
    58	    use super::*;
    59	
    60	    #[test]
    61	    fn base_fee_never_exceeds_fee() {
    62	        assert_eq!(base_fee(1_000, 2_000), 1_000); // fee below required base: all of it is base
    63	        assert_eq!(base_fee(250_000, 2_000), 200_000); // 2,000 grams * 100 = 200,000 base; 50,000 tip
    64	        assert_eq!(base_fee(0, 2_000), 0);
    65	        assert_eq!(base_fee(u64::MAX, u64::MAX), u64::MAX);
    66	    }
    67	
    68	    #[test]
    69	    fn split_is_60_40_and_conserves_value() {
    70	        let s = pool_step(PoolState::default(), 1_000);
    71	        assert_eq!(s.next.pool_balance, 600);
    72	        assert_eq!(s.burned, 400);
    73	        assert_eq!(s.payout, 0);
    74	        for base in [0u64, 1, 3, 7, 99, 12_345, 1 << 40] {
    75	            let parent = PoolState { pool_balance: 9_876_543_210, total_burned: 5, ..Default::default() };
    76	            let s = pool_step(parent, base);
    77	            // pool_in + base fees == pool_out + payout + burned
    78	            assert_eq!(parent.pool_balance + base, s.next.pool_balance + s.payout + s.burned);
    79	            assert_eq!(s.next.total_burned, parent.total_burned + s.burned);
    80	        }
    81	    }
    82	
    83	    #[test]
    84	    fn pool_pays_out_over_about_30_days() {
    85	        // One deposit, no new fees: after 30 days of blocks about 1/e (36.8%) remains.
    86	        let mut state = PoolState { pool_balance: 1_000_000 * 10_000_000_000, ..Default::default() };
    87	        let start = state.pool_balance;
    88	        for _ in 0..POOL_PAYOUT_DIVISOR {
    89	            state = pool_step(state, 0).next;
    90	        }
    91	        let left = state.pool_balance as f64 / start as f64;
    92	        assert!((left - 0.3679).abs() < 0.001, "got {left}");
    93	    }
    94	}

======== FULL FILE: consensus/src/processes/zethora_supply.rs ========
     1	//! Zethora supply ledger and turnstile (ZTH-SPEC-006 §7.1-7.2).
     2	//!
     3	//! Every chain block carries a ledger of where every zet is, in its coinbase payload:
     4	//!
     5	//! ```text
     6	//! transparent_supply + pool_balance + total_burned + shielded_balance == total_issued
     7	//! ```
     8	//!
     9	//! All values describe the moment after the block's coinbase is counted. Nodes rebuild the ledger
    10	//! from what the block actually did (the real UTXO changes, the rewards it pays, the fee pool step)
    11	//! and reject the block if it does not balance. Two independent counts must agree:
    12	//!   * what the UTXO set really gained or lost (`visible_change`), and
    13	//!   * what the reward and fee rules say should have happened (issued, tips, pool, burn).
    14	//!
    15	//! A bookkeeping bug that creates or loses even one zet makes the ledger unbalanced, and the
    16	//! private pool's public balance (the turnstile) can never go below zero.
    17	//!
    18	//! The hard cap (ZTH-SPEC-001 §5): no block may bring the total ever issued above 100,000,000 ZTHR
    19	//! (`CAP_UNITS`). The reward schedule itself stops ~1,000 ZTHR short of it (see `zethora_subsidy`), and the coinbase
    20	//! clamps every merged block's subsidy to what is left under the cap (`CoinbaseManager::expected_coinbase_transaction`,
    21	//! CEO decision 2026-10-28), so issued reaches the cap at most exactly and an honest block can never trip this rule.
    22	//! It stays as the backstop that keeps the cap even if a future bug paid too much: such a block is invalid.
    23	
    24	use crate::processes::zethora_subsidy::CAP_UNITS;
    25	use kaspa_consensus_core::coinbase::PoolState;
    26	use std::fmt;
    27	
    28	#[derive(Debug, Clone, PartialEq, Eq)]
    29	pub enum SupplyError {
    30	    /// More value tried to leave the private pool than is inside it.
    31	    ShieldedPoolNegative { balance: u64, value_in: u64, value_out: u64 },
    32	    /// The visible supply would be negative or too large.
    33	    VisibleSupplyOutOfRange(i128),
    34	    /// A running counter would overflow.
    35	    CounterOverflow(&'static str),
    36	    /// The ledger does not add up.
    37	    Unbalanced { transparent: u64, pool: u64, burned: u64, shielded: u64, issued: u64 },
    38	    /// The block would bring the total ever issued above the 100,000,000 ZTHR hard cap.
    39	    CapExceeded { issued: u64 },
    40	}
    41	
    42	impl fmt::Display for SupplyError {
    43	    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    44	        match self {
    45	            SupplyError::ShieldedPoolNegative { balance, value_in, value_out } => {
    46	                write!(f, "private pool would go below zero: balance {balance} + in {value_in} < out {value_out} zets")
    47	            }
    48	            SupplyError::VisibleSupplyOutOfRange(v) => write!(f, "visible supply out of range: {v} zets"),
    49	            SupplyError::CounterOverflow(name) => write!(f, "{name} counter overflow"),
    50	            SupplyError::Unbalanced { transparent, pool, burned, shielded, issued } => write!(
    51	                f,
    52	                "ledger does not balance: visible {transparent} + fee pool {pool} + burned {burned} + private pool {shielded} != issued {issued} zets"
    53	            ),
    54	            SupplyError::CapExceeded { issued } => {
    55	                write!(f, "total issued would be {issued} zets, above the 100,000,000 ZTHR hard cap ({CAP_UNITS} zets)")
    56	            }
    57	        }
    58	    }
    59	}
    60	
    61	impl std::error::Error for SupplyError {}
    62	
    63	/// The turnstile: a private pool's public balance. More can never leave than went in.
    64	pub fn turnstile(balance: u64, value_in: u64, value_out: u64) -> Result<u64, SupplyError> {
    65	    let available = balance as u128 + value_in as u128;
    66	    if value_out as u128 > available {
    67	        return Err(SupplyError::ShieldedPoolNegative { balance, value_in, value_out });
    68	    }
    69	    u64::try_from(available - value_out as u128).map_err(|_| SupplyError::CounterOverflow("private pool"))
    70	}
    71	
    72	/// The turnstile for one transaction (ZTH-SPEC-006 §7.1), applied in consensus merge order. `remaining` is the private
    73	/// pool's public balance after the transactions accepted before this one. If the transaction's private payment would
    74	/// take the pool below zero (or overflow it), returns false and leaves `remaining` unchanged: the transaction is then
    75	/// not accepted, so none of its effects happen. Otherwise applies its pool flows to `remaining` and returns true.
    76	/// Ordinary transactions always pass. A payload whose value balance can't be read never passes (validation refuses it).
    77	pub fn turnstile_accepts(remaining: &mut u64, payload: &[u8]) -> bool {
    78	    match kaspa_consensus_core::zethora_private::pool_flows(payload) {
    79	        Ok(None) => true,
    80	        Ok(Some((value_in, value_out))) => match turnstile(*remaining, value_in, value_out) {
    81	            Ok(next) => {
    82	                *remaining = next;
    83	                true
    84	            }
    85	            Err(_) => false,
    86	        },
    87	        Err(()) => false,
    88	    }
    89	}
    90	
    91	/// Everything one chain block changes in the ledger, apart from the fee pool step.
    92	#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    93	pub struct BlockFlows {
    94	    /// New zets created by the block rewards paid in this block's coinbase.
    95	    pub issued: u64,
    96	    /// Fees nobody could be paid (destroyed, so counted as burned).
    97	    pub unpaid: u64,
    98	    /// Net change in visible coins from the transactions this block accepts, measured from the real
    99	    /// UTXO changes (not counting the selected parent's coinbase). With correct bookkeeping this is
   100	    /// minus the total fees.
   101	    pub visible_change: i128,
   102	    /// Total value of this block's coinbase outputs.
   103	    pub coinbase_out: u64,
   104	    /// Value moved into the private pool (0 until private transactions exist).
   105	    pub shielded_in: u64,
   106	    /// Value moved out of the private pool (0 until private transactions exist).
   107	    pub shielded_out: u64,
   108	}
   109	
   110	/// Builds this block's ledger and checks that it balances.
   111	///
   112	/// `parent` is the selected parent's ledger. `after_pool` is the fee pool step applied to it
   113	/// (see `zethora_fees::pool_step`), which updates only `pool_balance` and `total_burned`.
   114	pub fn ledger_step(parent: PoolState, after_pool: PoolState, flows: BlockFlows) -> Result<PoolState, SupplyError> {
   115	    let total_burned = after_pool.total_burned.checked_add(flows.unpaid).ok_or(SupplyError::CounterOverflow("total burned"))?;
   116	    let total_issued = parent.total_issued.checked_add(flows.issued).ok_or(SupplyError::CounterOverflow("total issued"))?;
   117	    if total_issued > CAP_UNITS {
   118	        return Err(SupplyError::CapExceeded { issued: total_issued });
   119	    }
   120	    let visible = parent.transparent_supply as i128 + flows.visible_change + flows.coinbase_out as i128;
   121	    let transparent_supply = u64::try_from(visible).map_err(|_| SupplyError::VisibleSupplyOutOfRange(visible))?;
   122	    let shielded_balance = turnstile(parent.shielded_balance, flows.shielded_in, flows.shielded_out)?;
   123	    let next = PoolState { pool_balance: after_pool.pool_balance, total_burned, total_issued, transparent_supply, shielded_balance };
   124	    check_balanced(&next)?;
   125	    Ok(next)
   126	}
   127	
   128	/// Checks: visible + fee pool + burned + private pool == issued.
   129	pub fn check_balanced(l: &PoolState) -> Result<(), SupplyError> {
   130	    let held = l.transparent_supply as u128 + l.pool_balance as u128 + l.total_burned as u128 + l.shielded_balance as u128;
   131	    if held == l.total_issued as u128 {
   132	        Ok(())
   133	    } else {
   134	        Err(SupplyError::Unbalanced {
   135	            transparent: l.transparent_supply,
   136	            pool: l.pool_balance,
   137	            burned: l.total_burned,
   138	            shielded: l.shielded_balance,
   139	            issued: l.total_issued,
   140	        })
   141	    }
   142	}
   143	
   144	#[cfg(test)]
   145	mod tests {
   146	    use super::*;
   147	    use crate::processes::zethora_fees::pool_step;
   148	
   149	    /// One simulated chain block, built the same way the coinbase builder does it.
   150	    /// Returns the next ledger. `cheat` adds zets out of thin air to the visible change.
   151	    fn simulate_block(
   152	        parent: PoolState,
   153	        subsidy: u64,
   154	        tips: u64,
   155	        base: u64,
   156	        unpaid: u64,
   157	        cheat: i128,
   158	    ) -> Result<PoolState, SupplyError> {
   159	        let pool = pool_step(parent, base);
   160	        let fees = tips + base;
   161	        let coinbase_out = subsidy + (tips - unpaid) + pool.payout;
   162	        let flows =
   163	            BlockFlows { issued: subsidy, unpaid, visible_change: -(fees as i128) + cheat, coinbase_out, ..Default::default() };
   164	        ledger_step(parent, pool.next, flows)
   165	    }
   166	
   167	    #[test]
   168	    fn genesis_ledger_balances() {
   169	        assert_eq!(check_balanced(&PoolState::default()), Ok(()));
   170	    }
   171	
   172	    #[test]
   173	    fn honest_chain_always_balances() {
   174	        // 20,000 blocks with varied rewards and fees; fees can only be paid from coins that exist.
   175	        let mut ledger = PoolState::default();
   176	        let mut seed: u64 = 0x5eed_2e7a;
   177	        for i in 0..20_000u64 {
   178	            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
   179	            let subsidy = 2_745_536_136 - (i % 1000);
   180	            let spendable = ledger.transparent_supply;
   181	            let base = (seed >> 20) % 2_000_000 % (spendable / 2 + 1);
   182	            let tips = (seed >> 40) % 500_000 % (spendable / 2 - base.min(spendable / 2) + 1);
   183	            let unpaid = if i % 997 == 0 { tips } else { 0 }; // rare non-DAA blue: its tips are lost
   184	            ledger = simulate_block(ledger, subsidy, tips, base, unpaid, 0).expect("honest block must balance");
   185	        }
   186	        assert!(ledger.pool_balance > 0 && ledger.total_burned > 0);
   187	        assert_eq!(check_balanced(&ledger), Ok(()));
   188	    }
   189	
   190	    #[test]
   191	    fn one_counterfeit_zet_is_caught() {
   192	        let ledger = simulate_block(PoolState::default(), 1_000_000, 0, 0, 0, 0).unwrap();
   193	        let err = simulate_block(ledger, 1_000_000, 10_000, 50_000, 0, 1).unwrap_err();
   194	        assert!(matches!(err, SupplyError::Unbalanced { .. }), "got {err:?}");
   195	        // Losing a zet is caught too
   196	        let err = simulate_block(ledger, 1_000_000, 10_000, 50_000, 0, -1).unwrap_err();
   197	        assert!(matches!(err, SupplyError::Unbalanced { .. }), "got {err:?}");
   198	    }
   199	
   200	    #[test]
   201	    fn unpaid_tips_count_as_burned() {
   202	        let ledger = simulate_block(PoolState::default(), 1_000_000, 0, 0, 0, 0).unwrap();
   203	        let next = simulate_block(ledger, 0, 7_000, 0, 7_000, 0).unwrap();
   204	        assert_eq!(next.total_burned, ledger.total_burned + 7_000);
   205	    }
   206	
   207	    #[test]
   208	    fn turnstile_never_goes_below_zero() {
   209	        assert_eq!(turnstile(0, 100, 100), Ok(0));
   210	        assert_eq!(turnstile(50, 0, 50), Ok(0));
   211	        assert_eq!(turnstile(10, 5, 3), Ok(12));
   212	        assert!(matches!(turnstile(0, 100, 101), Err(SupplyError::ShieldedPoolNegative { .. })));
   213	        assert!(matches!(turnstile(u64::MAX, 1, 0), Err(SupplyError::CounterOverflow(_))));
   214	    }
   215	
   216	    #[test]
   217	    fn private_pool_moves_keep_ledger_balanced() {
   218	        let ledger = simulate_block(PoolState::default(), 1_000_000, 0, 0, 0, 0).unwrap();
   219	        // 400,000 visible zets go into the private pool (no fees in this example)
   220	        let flows = BlockFlows { visible_change: -400_000, shielded_in: 400_000, ..Default::default() };
   221	        let inside = ledger_step(ledger, ledger, flows).unwrap();
   222	        assert_eq!(inside.shielded_balance, 400_000);
   223	        // Taking out more than went in is rejected even if the visible side "adds up"
   224	        let flows = BlockFlows { visible_change: 400_001, shielded_out: 400_001, ..Default::default() };
   225	        assert!(matches!(ledger_step(inside, inside, flows), Err(SupplyError::ShieldedPoolNegative { .. })));
   226	    }
   227	
   228	    /// A private payment payload with this value balance (positive: leaves the pool; negative: enters it)
   229	    fn payment(value_balance: i64) -> Vec<u8> {
   230	        let mut p = kaspa_consensus_core::zethora_private::PRIVATE_PAYMENT_MAGIC.to_vec();
   231	        p.extend([1u8, 1, 0]); // pool version, one action
   232	        p.extend(vec![0u8; kaspa_consensus_core::zethora_private::ACTION_SIZE]);
   233	        p.push(0); // flags
   234	        p.extend(value_balance.to_le_bytes());
   235	        p
   236	    }
   237	
   238	    #[test]
   239	    fn turnstile_accepts_one_transaction_at_a_time() {
   240	        // Positive control: payments that fit are accepted and move the balance by exactly their value balance
   241	        let mut remaining = 50_000;
   242	        assert!(turnstile_accepts(&mut remaining, &payment(1_000)));
   243	        assert_eq!(remaining, 49_000);
   244	        assert!(turnstile_accepts(&mut remaining, &payment(-500)));
   245	        assert_eq!(remaining, 49_500);
   246	        // Taking out exactly what is left is fine
   247	        assert!(turnstile_accepts(&mut remaining, &payment(49_500)));
   248	        assert_eq!(remaining, 0);
   249	        // One zet more than the pool holds is refused and leaves the balance untouched
   250	        let mut remaining = 49_000;
   251	        assert!(!turnstile_accepts(&mut remaining, &payment(49_001)));
   252	        assert_eq!(remaining, 49_000);
   253	        // ... and the next payment that fits is still accepted from the untouched balance
   254	        assert!(turnstile_accepts(&mut remaining, &payment(49_000)));
   255	        assert_eq!(remaining, 0);
   256	        // Ordinary transactions always pass and never move the balance
   257	        assert!(turnstile_accepts(&mut remaining, b"hello"));
   258	        assert!(turnstile_accepts(&mut remaining, &[]));
   259	        assert_eq!(remaining, 0);
   260	        // An unreadable value balance never passes
   261	        let mut remaining = 10;
   262	        assert!(!turnstile_accepts(&mut remaining, b"ZSHP"));
   263	        assert_eq!(remaining, 10);
   264	        // Overflow is refused, not wrapped
   265	        let mut remaining = u64::MAX;
   266	        assert!(!turnstile_accepts(&mut remaining, &payment(-1)));
   267	        assert_eq!(remaining, u64::MAX);
   268	    }
   269	
   270	    #[test]
   271	    fn turnstile_order_decides_which_payment_is_accepted() {
   272	        // 50,000 in the pool; two payments each fit alone (1,000 and 49,500) but not together: the first in merge
   273	        // order is accepted, the second is not, and the balance never goes below zero
   274	        let (honest, other) = (payment(1_000), payment(49_500));
   275	        let mut remaining = 50_000;
   276	        let accepted: Vec<bool> = [&honest, &other].iter().map(|p| turnstile_accepts(&mut remaining, p)).collect();
   277	        assert_eq!(accepted, vec![true, false]);
   278	        assert_eq!(remaining, 49_000);
   279	        let mut remaining = 50_000;
   280	        let accepted: Vec<bool> = [&other, &honest].iter().map(|p| turnstile_accepts(&mut remaining, p)).collect();
   281	        assert_eq!(accepted, vec![true, false]);
   282	        assert_eq!(remaining, 500);
   283	        // Value brought in earlier in merge order can be taken out later
   284	        let mut remaining = 0;
   285	        assert!(!turnstile_accepts(&mut remaining, &payment(700)));
   286	        assert!(turnstile_accepts(&mut remaining, &payment(-700)));
   287	        assert!(turnstile_accepts(&mut remaining, &payment(700)));
   288	        assert_eq!(remaining, 0);
   289	    }
   290	
   291	    #[test]
   292	    fn issuing_past_the_hard_cap_is_refused() {
   293	        // A ledger with 5 zets left under the cap (kept balanced: everything issued is visible)
   294	        let near = PoolState { total_issued: CAP_UNITS - 5, transparent_supply: CAP_UNITS - 5, ..Default::default() };
   295	        assert_eq!(check_balanced(&near), Ok(()));
   296	        // Issuing exactly up to the cap is fine...
   297	        let ok = BlockFlows { issued: 5, coinbase_out: 5, ..Default::default() };
   298	        assert_eq!(ledger_step(near, near, ok).unwrap().total_issued, CAP_UNITS);
   299	        // ...one zet more is refused, even though the ledger itself would balance
   300	        let over = BlockFlows { issued: 6, coinbase_out: 6, ..Default::default() };
   301	        assert_eq!(ledger_step(near, near, over), Err(SupplyError::CapExceeded { issued: CAP_UNITS + 1 }));
   302	    }
   303	
   304	    #[test]
   305	    fn negative_visible_supply_is_rejected() {
   306	        let flows = BlockFlows { visible_change: -1, ..Default::default() };
   307	        let err = ledger_step(PoolState::default(), PoolState::default(), flows).unwrap_err();
   308	        assert_eq!(err, SupplyError::VisibleSupplyOutOfRange(-1));
   309	    }
   310	}
   311	
   312	#[cfg(test)]
   313	mod zethora_task4_smoke {
   314	    use super::turnstile;
   315	    use kaspa_consensus_core::zethora_private::private_state_spent_element;
   316	
   317	    #[test]
   318	    fn spent_element_is_deterministic_and_distinct() {
   319	        let n1 = [7u8; 32];
   320	        let n2 = [9u8; 32];
   321	
   322	        let e1a = private_state_spent_element(&n1);
   323	        let e1b = private_state_spent_element(&n1);
   324	        let e2 = private_state_spent_element(&n2);
   325	
   326	        assert_eq!(e1a, e1b, "same nullifier must map to same spent-element");
   327	        assert_ne!(e1a, e2, "different nullifiers must map to different spent-elements");
   328	        assert_eq!(e1a.len(), 33, "spent-element must be 33 bytes (tag + nullifier)");
   329	    }
   330	
   331	    #[test]
   332	    fn turnstile_is_sequential_and_rejects_second_debit() {
   333	        let start = 100u64;
   334	        let spend = 60u64;
   335	
   336	        let after_a = turnstile(start, 0, spend).expect("first spend should succeed");
   337	        assert_eq!(after_a, 40);
   338	
   339	        let after_b = turnstile(after_a, 0, spend);
   340	        assert!(after_b.is_err(), "second sequential spend must underflow");
   341	
   342	        let buggy_a = turnstile(start, 0, spend);
   343	        let buggy_b = turnstile(start, 0, spend);
   344	        assert!(buggy_a.is_ok() && buggy_b.is_ok(), "both succeed against parent");
   345	    }
   346	}

======== FULL FILE: consensus/src/processes/coinbase.rs ========
     1	use kaspa_consensus_core::{
     2	    BlockHashMap, BlockHashSet,
     3	    coinbase::*,
     4	    errors::coinbase::{CoinbaseError, CoinbaseResult},
     5	    subnets,
     6	    tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput},
     7	};
     8	use std::convert::TryInto;
     9	
    10	use crate::{
    11	    constants,
    12	    model::stores::ghostdag::GhostdagData,
    13	    processes::{
    14	        zethora_fees,
    15	        zethora_subsidy::{CAP_UNITS, ZethoraSubsidy},
    16	        zethora_supply::{self, BlockFlows},
    17	    },
    18	};
    19	use std::sync::Arc;
    20	
    21	const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
    22	const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
    23	/// Zethora supply ledger: pool balance, total burned, total issued, transparent supply, shielded balance (5 x u64)
    24	const LENGTH_OF_POOL_STATE: usize = 5 * size_of::<u64>();
    25	/// Zethora: root of the private coin list (32 bytes)
    26	const LENGTH_OF_NOTE_ROOT: usize = 32;
    27	/// Zethora: private state fingerprint: spent coin tags and coin list snapshots (32 bytes)
    28	const LENGTH_OF_PRIVATE_STATE: usize = 32;
    29	const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
    30	const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();
    31	
    32	const MIN_PAYLOAD_LENGTH: usize = LENGTH_OF_BLUE_SCORE
    33	    + LENGTH_OF_SUBSIDY
    34	    + LENGTH_OF_POOL_STATE
    35	    + LENGTH_OF_NOTE_ROOT
    36	    + LENGTH_OF_PRIVATE_STATE
    37	    + LENGTH_OF_SCRIPT_PUB_KEY_VERSION
    38	    + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;
    39	
    40	// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
    41	// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60
    42	
    43	#[derive(Clone)]
    44	pub struct CoinbaseManager {
    45	    coinbase_payload_script_public_key_max_len: u8,
    46	    max_coinbase_payload_len: usize,
    47	
    48	    /// Zethora: smooth-decay subsidy, ZTH-SPEC-001 Section 5
    49	    zethora_subsidy: Arc<ZethoraSubsidy>,
    50	}
    51	
    52	/// Struct used to streamline payload parsing
    53	struct PayloadParser<'a> {
    54	    remaining: &'a [u8], // The unparsed remainder
    55	}
    56	
    57	impl<'a> PayloadParser<'a> {
    58	    fn new(data: &'a [u8]) -> Self {
    59	        Self { remaining: data }
    60	    }
    61	
    62	    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    63	    fn take(&mut self, n: usize) -> &[u8] {
    64	        let (segment, remaining) = self.remaining.split_at(n);
    65	        self.remaining = remaining;
    66	        segment
    67	    }
    68	}
    69	
    70	impl CoinbaseManager {
    71	    pub fn new(coinbase_payload_script_public_key_max_len: u8, max_coinbase_payload_len: usize) -> Self {
    72	        Self { coinbase_payload_script_public_key_max_len, max_coinbase_payload_len, zethora_subsidy: Arc::new(ZethoraSubsidy::new()) }
    73	    }
    74	
    75	    #[allow(clippy::too_many_arguments)]
    76	    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
    77	        &self,
    78	        daa_score: u64,
    79	        miner_data: MinerData<T>,
    80	        ghostdag_data: &GhostdagData,
    81	        mergeset_rewards: &BlockHashMap<BlockRewardData>,
    82	        mergeset_non_daa: &BlockHashSet,
    83	        parent_pool: PoolState,
    84	        visible_change: i128,
    85	        note_root: [u8; 32],
    86	        private_state: [u8; 32],
    87	    ) -> CoinbaseResult<CoinbaseTransactionTemplate> {
    88	        let mut outputs = Vec::with_capacity(ghostdag_data.mergeset_blues.len() + 1); // + 1 for possible red reward
    89	
    90	        // Zethora (ZTH-SPEC-008): miners get subsidy + tips; base fees go 60% to the pool, 40% burned.
    91	        let base_total: u64 = mergeset_rewards.values().map(|r| r.base_fees).sum();
    92	        let pool = zethora_fees::pool_step(parent_pool, base_total);
    93	
    94	        // Zethora supply ledger (ZTH-SPEC-006 §7.2): count every zet this coinbase creates or destroys
    95	        let mut issued = 0u64;
    96	        let mut unpaid = 0u64;
    97	
    98	        // Zethora hard cap clamp (ZTH-SPEC-001 §5, CEO decision 2026-10-28): each merged block is paid
    99	        // min(its subsidy, what is left under the cap), in mergeset order (blues, then reds). Total issued then reaches
   100	        // CAP_UNITS exactly and never passes it, so the CapExceeded backstop in ledger_step can't fire for an honest
   101	        // block and the chain never stalls at the cap. Tips and fee pool payouts are not new zets and are never clamped.
   102	        let mut cap_room = CAP_UNITS.saturating_sub(parent_pool.total_issued);
   103	        let mut paid_subsidy = |claimed: u64| -> u64 {
   104	            let paid = claimed.min(cap_room);
   105	            cap_room -= paid;
   106	            paid
   107	        };
   108	
   109	        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
   110	        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA
   111	        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
   112	            let reward_data = mergeset_rewards.get(blue).unwrap();
   113	            let subsidy = paid_subsidy(reward_data.subsidy);
   114	            issued += subsidy;
   115	            if subsidy + reward_data.tips() > 0 {
   116	                outputs.push(TransactionOutput::new(subsidy + reward_data.tips(), reward_data.script_public_key.clone()));
   117	            }
   118	        }
   119	
   120	        // Zethora: a blue block outside the DAA window is paid nothing, so its tips are destroyed (counted as burned).
   121	        // Such a block may have no reward data at all (e.g. genesis in the very first virtual state): nothing is lost then.
   122	        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| mergeset_non_daa.contains(h)) {
   123	            unpaid += mergeset_rewards.get(blue).map_or(0, |r| r.tips());
   124	        }
   125	
   126	        // Collect all rewards from mergeset reds ∩ DAA window and create a
   127	        // single output rewarding all to the current block (the "merging" block)
   128	        let mut red_reward = 0u64;
   129	
   130	        for red in ghostdag_data.mergeset_reds.iter() {
   131	            let reward_data = mergeset_rewards.get(red).unwrap();
   132	            if mergeset_non_daa.contains(red) {
   133	                red_reward += reward_data.tips();
   134	            } else {
   135	                let subsidy = paid_subsidy(reward_data.subsidy);
   136	                red_reward += subsidy + reward_data.tips();
   137	                issued += subsidy;
   138	            }
   139	        }
   140	
   141	        // Zethora: this block's payout from the fee pool goes to this block's miner (same output as red rewards)
   142	        red_reward += pool.payout;
   143	
   144	        if red_reward > 0 {
   145	            outputs.push(TransactionOutput::new(red_reward, miner_data.script_public_key.clone()));
   146	        }
   147	
   148	        // Zethora: build this block's supply ledger from what it really does, and refuse it if it does not balance
   149	        let coinbase_out: u64 = outputs.iter().map(|o| o.value).sum();
   150	        // Zethora: value moved into / out of the private pool by the accepted transactions (the turnstile)
   151	        let shielded_in: u64 = mergeset_rewards.values().map(|r| r.pool_in).sum();
   152	        let shielded_out: u64 = mergeset_rewards.values().map(|r| r.pool_out).sum();
   153	        let flows = BlockFlows { issued, unpaid, visible_change, coinbase_out, shielded_in, shielded_out };
   154	        let ledger =
   155	            zethora_supply::ledger_step(parent_pool, pool.next, flows).map_err(|e| CoinbaseError::ZethoraSupply(e.to_string()))?;
   156	
   157	        // Build the current block's payload
   158	        let subsidy = self.calc_block_subsidy(daa_score);
   159	        let payload = self.serialize_coinbase_payload(&CoinbaseData {
   160	            blue_score: ghostdag_data.blue_score,
   161	            subsidy,
   162	            pool: ledger,
   163	            note_root,
   164	            private_state,
   165	            miner_data,
   166	        })?;
   167	
   168	        Ok(CoinbaseTransactionTemplate {
   169	            tx: Transaction::new(constants::TX_VERSION_TOCCATA, vec![], outputs, 0, subnets::SUBNETWORK_ID_COINBASE, 0, payload),
   170	            has_red_reward: red_reward > 0,
   171	        })
   172	    }
   173	
   174	    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
   175	        let script_pub_key_len = data.miner_data.script_public_key.script().len();
   176	        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
   177	            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
   178	                script_pub_key_len,
   179	                self.coinbase_payload_script_public_key_max_len,
   180	            ));
   181	        }
   182	        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
   183	            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
   184	            .chain(data.pool.pool_balance.to_le_bytes().iter().copied())                        // Zethora: pool balance        (u64)
   185	            .chain(data.pool.total_burned.to_le_bytes().iter().copied())                        // Zethora: total burned        (u64)
   186	            .chain(data.pool.total_issued.to_le_bytes().iter().copied())                        // Zethora: total issued        (u64)
   187	            .chain(data.pool.transparent_supply.to_le_bytes().iter().copied())                  // Zethora: transparent supply  (u64)
   188	            .chain(data.pool.shielded_balance.to_le_bytes().iter().copied())                    // Zethora: shielded balance    (u64)
   189	            .chain(data.note_root.iter().copied())                                              // Zethora: private coin list root ([u8; 32])
   190	            .chain(data.private_state.iter().copied())                                          // Zethora: private state fingerprint ([u8; 32])
   191	            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
   192	            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
   193	            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
   194	            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
   195	            .collect();
   196	
   197	        Ok(payload)
   198	    }
   199	
   200	    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
   201	        let script_pub_key_len = miner_data.script_public_key.script().len();
   202	        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
   203	            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
   204	                script_pub_key_len,
   205	                self.coinbase_payload_script_public_key_max_len,
   206	            ));
   207	        }
   208	
   209	        // Keep only blue score, subsidy and the Zethora supply ledger. Note that truncate does not modify capacity, so
   210	        // the usual case where the payloads are the same size will not trigger a reallocation
   211	        payload
   212	            .truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_POOL_STATE + LENGTH_OF_NOTE_ROOT + LENGTH_OF_PRIVATE_STATE);
   213	        payload.extend(
   214	            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
   215	                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
   216	                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
   217	                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
   218	        );
   219	
   220	        Ok(payload)
   221	    }
   222	
   223	    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
   224	        if payload.len() < MIN_PAYLOAD_LENGTH {
   225	            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
   226	        }
   227	
   228	        if payload.len() > self.max_coinbase_payload_len {
   229	            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
   230	        }
   231	
   232	        let mut parser = PayloadParser::new(payload);
   233	
   234	        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
   235	        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
   236	        let pool_balance = u64::from_le_bytes(parser.take(8).try_into().unwrap());
   237	        let total_burned = u64::from_le_bytes(parser.take(8).try_into().unwrap());
   238	        let total_issued = u64::from_le_bytes(parser.take(8).try_into().unwrap());
   239	        let transparent_supply = u64::from_le_bytes(parser.take(8).try_into().unwrap());
   240	        let shielded_balance = u64::from_le_bytes(parser.take(8).try_into().unwrap());
   241	        let note_root: [u8; 32] = parser.take(LENGTH_OF_NOTE_ROOT).try_into().unwrap();
   242	        let private_state: [u8; 32] = parser.take(LENGTH_OF_PRIVATE_STATE).try_into().unwrap();
   243	        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
   244	        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());
   245	
   246	        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
   247	            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
   248	                script_pub_key_len as usize,
   249	                self.coinbase_payload_script_public_key_max_len,
   250	            ));
   251	        }
   252	
   253	        if parser.remaining.len() < script_pub_key_len as usize {
   254	            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
   255	                payload.len(),
   256	                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
   257	            ));
   258	        }
   259	
   260	        let script_public_key =
   261	            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
   262	        let extra_data = parser.remaining;
   263	
   264	        Ok(CoinbaseData {
   265	            blue_score,
   266	            subsidy,
   267	            pool: PoolState { pool_balance, total_burned, total_issued, transparent_supply, shielded_balance },
   268	            note_root,
   269	            private_state,
   270	            miner_data: MinerData { script_public_key, extra_data },
   271	        })
   272	    }
   273	
   274	    pub fn calc_block_subsidy(&self, daa_score: u64) -> u64 {
   275	        // Zethora: reward = floor(Remaining / D), indexed by DAA score (ZTH-SPEC-001 Section 5)
   276	        self.zethora_subsidy.subsidy(daa_score)
   277	    }
   278	}
   279	
   280	#[cfg(test)]
   281	mod tests {
   282	    use super::*;
   283	    use crate::params::MAINNET_PARAMS;
   284	    use kaspa_consensus_core::{config::params::Params, tx::scriptvec};
   285	
   286	    #[test]
   287	    fn payload_serialization_test() {
   288	        let cbm = create_manager(&MAINNET_PARAMS);
   289	
   290	        let script_data = [33u8, 255];
   291	        let extra_data = [2u8, 3];
   292	        let data = CoinbaseData {
   293	            blue_score: 56,
   294	            subsidy: 44000000000,
   295	            pool: PoolState { pool_balance: 123, total_burned: 456, total_issued: 789, transparent_supply: 10, shielded_balance: 11 },
   296	            note_root: [3; 32],
   297	            private_state: [5; 32],
   298	            miner_data: MinerData {
   299	                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
   300	                extra_data: &extra_data as &[u8],
   301	            },
   302	        };
   303	
   304	        let payload = cbm.serialize_coinbase_payload(&data).unwrap();
   305	        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();
   306	
   307	        assert_eq!(data, deserialized_data);
   308	
   309	        // (Kaspa's mainnet payload vector removed: Zethora's payload adds the pool state.)
   310	    }
   311	
   312	    #[test]
   313	    fn modify_payload_test() {
   314	        let cbm = create_manager(&MAINNET_PARAMS);
   315	
   316	        let script_data = [33u8, 255];
   317	        let extra_data = [2u8, 3, 23, 98];
   318	        let data = CoinbaseData {
   319	            blue_score: 56345,
   320	            subsidy: 44000000000,
   321	            pool: PoolState { pool_balance: 7, total_burned: 8, total_issued: 9, transparent_supply: 10, shielded_balance: 11 },
   322	            note_root: [4; 32],
   323	            private_state: [6; 32],
   324	            miner_data: MinerData {
   325	                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
   326	                extra_data: &extra_data,
   327	            },
   328	        };
   329	
   330	        let data2 = CoinbaseData {
   331	            blue_score: data.blue_score,
   332	            subsidy: data.subsidy,
   333	            pool: data.pool,
   334	            note_root: data.note_root,
   335	            private_state: data.private_state,
   336	            miner_data: MinerData {
   337	                // Modify only miner data
   338	                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[33u8, 255, 33])),
   339	                extra_data: &[2u8, 3, 23, 98, 34, 34] as &[u8],
   340	            },
   341	        };
   342	
   343	        let mut payload = cbm.serialize_coinbase_payload(&data).unwrap();
   344	        payload = cbm.modify_coinbase_payload(payload, &data2.miner_data).unwrap(); // Update the payload with the modified miner data
   345	        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();
   346	
   347	        assert_eq!(data2, deserialized_data);
   348	    }
   349	
   350	    #[test]
   351	    fn expected_coinbase_transaction_uses_toccata_version() {
   352	        let params = MAINNET_PARAMS.clone();
   353	        let cbm = create_manager(&params);
   354	        let miner_data = MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![4, 5, 6]);
   355	        let ghostdag_data = GhostdagData::default();
   356	        let mergeset_rewards = Default::default();
   357	        let mergeset_non_daa = Default::default();
   358	
   359	        let tx = cbm
   360	            .expected_coinbase_transaction(
   361	                100,
   362	                miner_data,
   363	                &ghostdag_data,
   364	                &mergeset_rewards,
   365	                &mergeset_non_daa,
   366	                PoolState::default(),
   367	                0,
   368	                [0; 32],
   369	                [0; 32],
   370	            )
   371	            .unwrap();
   372	
   373	        assert_eq!(tx.tx.version, constants::TX_VERSION_TOCCATA);
   374	    }
   375	
   376	    /// One chain block merging `merged` (blue, (subsidy claimed, tips)) and `reds`, built by the same function the
   377	    /// template builder and the coinbase check use. Returns the coinbase outputs' values and the new ledger.
   378	    fn cap_block(
   379	        cbm: &CoinbaseManager,
   380	        parent: PoolState,
   381	        blues: &[(u64, u64)],
   382	        reds: &[(u64, u64)],
   383	    ) -> Result<(Vec<u64>, PoolState), CoinbaseError> {
   384	        use kaspa_consensus_core::{BlockHashMap, Hash};
   385	        let miner = MinerData::new(ScriptPublicKey::new(0, scriptvec![0x51]), vec![]);
   386	        let mut rewards = BlockHashMap::default();
   387	        let mut hashes = |list: &[(u64, u64)], offset: u64| -> Vec<Hash> {
   388	            list.iter()
   389	                .enumerate()
   390	                .map(|(i, &(subsidy, tips))| {
   391	                    let h = Hash::from_u64_word(offset + i as u64);
   392	                    rewards.insert(h, BlockRewardData::new(subsidy, tips, 0, ScriptPublicKey::new(0, scriptvec![i as u8])));
   393	                    h
   394	                })
   395	                .collect()
   396	        };
   397	        let blue_hashes = hashes(blues, 1);
   398	        let red_hashes = hashes(reds, 1_000);
   399	        let ghostdag = GhostdagData::new(
   400	            7,
   401	            Default::default(),
   402	            blue_hashes[0],
   403	            std::sync::Arc::new(blue_hashes),
   404	            std::sync::Arc::new(red_hashes),
   405	            Default::default(),
   406	        );
   407	        // No transactions accepted: the visible supply changes only by what the coinbase pays (fees are tips only and
   408	        // come out of the merged blocks' own transactions, so count them as already spent: visible change = -tips)
   409	        let tips: u64 = blues.iter().chain(reds).map(|&(_, t)| t).sum();
   410	        let template = cbm.expected_coinbase_transaction(
   411	            100,
   412	            miner,
   413	            &ghostdag,
   414	            &rewards,
   415	            &Default::default(),
   416	            parent,
   417	            -(tips as i128),
   418	            [0; 32],
   419	            [0; 32],
   420	        )?;
   421	        let ledger = cbm.deserialize_coinbase_payload(&template.tx.payload).unwrap().pool;
   422	        Ok((template.tx.outputs.iter().map(|o| o.value).collect(), ledger))
   423	    }
   424	
   425	    /// A balanced ledger with `left` zets still to be issued under the cap.
   426	    fn ledger_below_cap(left: u64) -> PoolState {
   427	        PoolState { total_issued: CAP_UNITS - left, transparent_supply: CAP_UNITS - left, ..Default::default() }
   428	    }
   429	
   430	    #[test]
   431	    fn subsidy_is_clamped_to_reach_the_cap_exactly() {
   432	        let cbm = create_manager(&MAINNET_PARAMS);
   433	
   434	        // Positive control: far below the cap nothing is clamped; each merged block gets its full subsidy + tips
   435	        let (outs, ledger) = cap_block(&cbm, ledger_below_cap(1_000_000), &[(300, 5), (200, 0)], &[]).unwrap();
   436	        assert_eq!(outs, vec![305, 200]);
   437	        assert_eq!(ledger.total_issued, CAP_UNITS - 1_000_000 + 500);
   438	
   439	        // 250 zets left: the first blue (in mergeset order) gets 200 of its 300 and keeps its tips, the second blue gets
   440	        // 50 of 200, the red gets 0 of 100 but keeps its tips (paid to the merging miner). Issued lands exactly on the cap.
   441	        let (outs, at_cap) = cap_block(&cbm, ledger_below_cap(250), &[(200, 7), (200, 0)], &[(100, 3)]).unwrap();
   442	        assert_eq!(outs, vec![207, 50, 3]);
   443	        assert_eq!(at_cap.total_issued, CAP_UNITS);
   444	        assert_eq!(zethora_supply::check_balanced(&at_cap), Ok(()));
   445	
   446	        // The next block at the cap pays 0 subsidy (tips still paid), is valid, and issued stays exactly at the cap
   447	        let (outs, next) = cap_block(&cbm, at_cap, &[(2_745_536_136, 11)], &[]).unwrap();
   448	        assert_eq!(outs, vec![11]);
   449	        assert_eq!(next.total_issued, CAP_UNITS);
   450	        // A block whose merged blocks have no tips pays nothing at all (no outputs) and is still valid
   451	        let (outs, next) = cap_block(&cbm, next, &[(2_745_536_136, 0), (2_745_536_136, 0)], &[(9, 0)]).unwrap();
   452	        assert_eq!(outs, Vec::<u64>::new());
   453	        assert_eq!(next.total_issued, CAP_UNITS);
   454	
   455	        // The chain continues past the cap: 100 more blocks, issued never moves
   456	        let mut ledger = next;
   457	        for i in 0..100u64 {
   458	            let (outs, l) = cap_block(&cbm, ledger, &[(1_000 + i, i)], &[]).unwrap();
   459	            assert_eq!(outs, if i == 0 { vec![] } else { vec![i] });
   460	            assert_eq!(l.total_issued, CAP_UNITS);
   461	            ledger = l;
   462	        }
   463	    }
   464	
   465	    #[test]
   466	    fn a_coinbase_claiming_more_than_the_clamp_is_refused() {
   467	        let cbm = create_manager(&MAINNET_PARAMS);
   468	        // 50 zets left; the merged block claims 300
   469	        let parent = ledger_below_cap(50);
   470	        let (outs, ledger) = cap_block(&cbm, parent, &[(300, 0)], &[]).unwrap();
   471	        assert_eq!(outs, vec![50]);
   472	        assert_eq!(ledger.total_issued, CAP_UNITS);
   473	
   474	        // A miner's coinbase paying the unclamped 300 is not the expected coinbase (verify_coinbase_transaction
   475	        // compares hashes and returns BadCoinbaseTransaction), and its ledger is refused by the CapExceeded backstop
   476	        let unclamped = BlockFlows { issued: 300, coinbase_out: 300, ..Default::default() };
   477	        assert_eq!(
   478	            zethora_supply::ledger_step(parent, parent, unclamped),
   479	            Err(zethora_supply::SupplyError::CapExceeded { issued: CAP_UNITS + 250 })
   480	        );
   481	        // ... one zet over the clamp is refused too, exactly the clamp is accepted
   482	        let one_over = BlockFlows { issued: 51, coinbase_out: 51, ..Default::default() };
   483	        assert_eq!(
   484	            zethora_supply::ledger_step(parent, parent, one_over),
   485	            Err(zethora_supply::SupplyError::CapExceeded { issued: CAP_UNITS + 1 })
   486	        );
   487	        let exact = BlockFlows { issued: 50, coinbase_out: 50, ..Default::default() };
   488	        assert_eq!(zethora_supply::ledger_step(parent, parent, exact).unwrap().total_issued, CAP_UNITS);
   489	    }
   490	
   491	    fn create_manager(params: &Params) -> CoinbaseManager {
   492	        CoinbaseManager::new(params.coinbase_payload_script_public_key_max_len, params.max_coinbase_payload_len)
   493	    }
   494	}

======== FULL FILE: consensus/core/src/coinbase.rs ========
     1	use crate::tx::{ScriptPublicKey, Transaction};
     2	use serde::{Deserialize, Serialize};
     3	
     4	#[derive(PartialEq, Eq, Debug, Clone)]
     5	pub struct MinerData<T: AsRef<[u8]> = Vec<u8>> {
     6	    pub script_public_key: ScriptPublicKey,
     7	    pub extra_data: T,
     8	}
     9	
    10	impl<T: AsRef<[u8]>> MinerData<T> {
    11	    pub fn new(script_public_key: ScriptPublicKey, extra_data: T) -> Self {
    12	        Self { script_public_key, extra_data }
    13	    }
    14	}
    15	
    16	/// Zethora supply ledger, carried in every coinbase payload along the selected chain
    17	/// (fee pool: ZTH-SPEC-008; supply check and turnstile: ZTH-SPEC-006 §7.1-7.2).
    18	///
    19	/// All values describe the moment after this block's coinbase is counted, and every block must satisfy:
    20	///     transparent_supply + pool_balance + total_burned + shielded_balance == total_issued
    21	#[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    22	pub struct PoolState {
    23	    /// Zets currently held in the fee pool (controlled by no key).
    24	    pub pool_balance: u64,
    25	    /// Total zets ever burned (SPEC-001 §15.2).
    26	    pub total_burned: u64,
    27	    /// Total zets ever created by block rewards (paid out so far).
    28	    pub total_issued: u64,
    29	    /// Zets held in ordinary (visible) coins.
    30	    pub transparent_supply: u64,
    31	    /// Zets inside the private pool: its public turnstile balance. Always 0 until private transactions exist.
    32	    pub shielded_balance: u64,
    33	}
    34	
    35	#[derive(PartialEq, Eq, Debug)]
    36	pub struct CoinbaseData<T: AsRef<[u8]> = Vec<u8>> {
    37	    pub blue_score: u64,
    38	    pub subsidy: u64,
    39	    /// Zethora: pool state after this block
    40	    pub pool: PoolState,
    41	    /// Zethora: root of the private coin list after this block's mergeset (ZTH-SPEC-006 §6.1)
    42	    pub note_root: [u8; 32],
    43	    /// Zethora: fingerprint of every spent private coin tag and every coin list snapshot after this block's mergeset
    44	    /// (ZTH-SPEC-006 §6.4), so nodes joining from a pruning point can check the private state they download
    45	    pub private_state: [u8; 32],
    46	    pub miner_data: MinerData<T>,
    47	}
    48	
    49	#[derive(Clone, Serialize, Deserialize, Debug)]
    50	pub struct BlockRewardData {
    51	    pub subsidy: u64,
    52	    pub total_fees: u64,
    53	    /// Zethora: the base-fee part of `total_fees`. The rest (tips) goes to the miner.
    54	    pub base_fees: u64,
    55	    pub script_public_key: ScriptPublicKey,
    56	    /// Zethora: zets this block's accepted transactions moved into the private pool (ZTH-SPEC-006 §7.1).
    57	    pub pool_in: u64,
    58	    /// Zethora: zets this block's accepted transactions moved out of the private pool.
    59	    pub pool_out: u64,
    60	}
    61	
    62	impl BlockRewardData {
    63	    pub fn new(subsidy: u64, total_fees: u64, base_fees: u64, script_public_key: ScriptPublicKey) -> Self {
    64	        Self { subsidy, total_fees, base_fees, script_public_key, pool_in: 0, pool_out: 0 }
    65	    }
    66	
    67	    /// Zethora: records the private pool flows of this block's accepted transactions.
    68	    pub fn with_pool_flows(mut self, pool_in: u64, pool_out: u64) -> Self {
    69	        self.pool_in = pool_in;
    70	        self.pool_out = pool_out;
    71	        self
    72	    }
    73	
    74	    /// Tips: the part of fees paid directly to the block's miner.
    75	    pub fn tips(&self) -> u64 {
    76	        self.total_fees - self.base_fees
    77	    }
    78	}
    79	
    80	/// Holds a coinbase transaction along with meta-data obtained during creation
    81	pub struct CoinbaseTransactionTemplate {
    82	    pub tx: Transaction,
    83	    pub has_red_reward: bool, // Does the last output contain reward for red blocks
    84	}

======== EXCERPTS (zethora|subsidy|coinbase|cap_units|fee_pool|pool_state|ledger|issued|burn): consensus/core/src/constants.rs ========
---- lines 1-57 ----
     1	/// BLOCK_VERSION represents the current block version. This denotes the use of
     2	/// the new sequencing commit described in KIP-21.
     3	pub const BLOCK_VERSION: u16 = 2;
     4	
     5	/// TX_VERSION is the current latest supported transaction version.
     6	pub const TX_VERSION: u16 = 0;
     7	
     8	/// The transaction version activated by the Toccata hardfork.
     9	///
    10	/// Main changes enabled relative to [`TX_VERSION`] (0):
    11	/// - output covenant bindings,
    12	/// - input compute-budget mass,
    13	/// - non-native/non-coinbase subnetworks (user lanes),
    14	/// - gas commitments.
    15	pub const TX_VERSION_TOCCATA: u16 = 1;
    16	
    17	pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;
    18	
    19	/// MAX_SCRIPT_PUBLIC_KEY_VERSION is the current latest supported public key script version.
    20	pub const MAX_SCRIPT_PUBLIC_KEY_VERSION: u16 = 0;
    21	
    22	/// SompiPerKaspa is the number of sompi in one kaspa (1 KAS).
    23	pub const SOMPI_PER_KASPA: u64 = 100_000_000;
    24	
    25	/// The parameter for scaling inverse KAS value to mass units (KIP-0009)
    26	pub const STORAGE_MASS_PARAMETER: u64 = SOMPI_PER_KASPA * 10_000;
    27	
    28	/// The parameter defining how much mass per byte to charge for when calculating
    29	/// transient storage mass. Since normally the block mass limit is 500_000, this limits
    30	/// block body byte size to 125_000 (KIP-0013).
    31	pub const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;
    32	
    33	/// MaxSompi is the maximum transaction amount allowed in sompi.
    34	pub const MAX_SOMPI: u64 = 29_000_000_000 * SOMPI_PER_KASPA;
    35	
    36	/// Zethora: 1 ZTHR = 10^10 zets (the base unit).
    37	pub const ZETS_PER_ZTHR: u64 = 10_000_000_000;
    38	/// Zethora: the hard cap, 100,000,000 ZTHR in zets (ZTH-SPEC-001 §5). Consensus never issues more
    39	/// (`kaspa_consensus::processes::zethora_subsidy`, the coinbase cap clamp and the supply ledger's CapExceeded rule).
    40	pub const CAP_UNITS: u64 = 100_000_000 * ZETS_PER_ZTHR;
    41	
    42	// MAX_TX_IN_SEQUENCE_NUM is the maximum sequence number the sequence field
    43	// of a transaction input can be.
    44	pub const MAX_TX_IN_SEQUENCE_NUM: u64 = u64::MAX;
    45	
    46	// SEQUENCE_LOCK_TIME_MASK is a mask that extracts the relative lock time
    47	// when masked against the transaction input sequence number.
    48	pub const SEQUENCE_LOCK_TIME_MASK: u64 = 0x00000000ffffffff;
    49	
    50	// SEQUENCE_LOCK_TIME_DISABLED is a flag that if set on a transaction
    51	// input's sequence number, the sequence number will not be interpreted
    52	// as a relative lock time.
    53	pub const SEQUENCE_LOCK_TIME_DISABLED: u64 = 1 << 63;
    54	
    55	/// UNACCEPTED_DAA_SCORE is used to for UtxoEntries that were created by
    56	/// transactions in the mempool, or otherwise not-yet-accepted transactions.
    57	pub const UNACCEPTED_DAA_SCORE: u64 = u64::MAX;

======== EXCERPTS (zethora|subsidy|coinbase|cap_units|fee_pool|pool_state|ledger|issued|burn): consensus/src/pipeline/body_processor/body_validation_in_context.rs ========
---- lines 1-107 ----
     1	use super::BlockBodyProcessor;
     2	use crate::{
     3	    errors::{BlockProcessResult, RuleError},
     4	    model::stores::statuses::StatusesStoreReader,
     5	    processes::{
     6	        transaction_validator::{
     7	            TransactionValidator,
     8	            tx_validation_in_header_context::{LockTimeArg, LockTimeType},
     9	        },
    10	        window::WindowManager,
    11	    },
    12	};
    13	use kaspa_consensus_core::block::Block;
    14	use kaspa_database::prelude::StoreResultExt;
    15	use kaspa_hashes::Hash;
    16	use once_cell::unsync::Lazy;
    17	use std::sync::Arc;
    18	
    19	impl BlockBodyProcessor {
    20	    pub fn validate_body_in_context(self: &Arc<Self>, block: &Block) -> BlockProcessResult<()> {
    21	        self.check_parent_bodies_exist(block)?;
    22	        self.check_coinbase_blue_score_and_subsidy(block)?;
    23	        self.check_block_transactions_in_context(block)
    24	    }
    25	
    26	    pub fn validate_trusted_body_in_context(self: &Arc<Self>, block: &Block) -> BlockProcessResult<()> {
    27	        self.check_coinbase_blue_score_and_subsidy(block)
    28	    }
    29	
    30	    fn check_block_transactions_in_context(self: &Arc<Self>, block: &Block) -> BlockProcessResult<()> {
    31	        // Use lazy evaluation to avoid unnecessary work, as most of the time we expect the txs not to have lock time.
    32	        let lazy_pmt_res = Lazy::new(|| self.window_manager.calc_past_median_time_for_known_hash(block.hash()));
    33	
    34	        for tx in block.transactions.iter() {
    35	            let lock_time_arg = match TransactionValidator::get_lock_time_type(tx) {
    36	                LockTimeType::Finalized => LockTimeArg::Finalized,
    37	                LockTimeType::DaaScore => LockTimeArg::DaaScore(block.header.daa_score),
    38	                // We only evaluate the pmt calculation when actually needed
    39	                LockTimeType::Time => LockTimeArg::MedianTime((*lazy_pmt_res).clone()?),
    40	            };
    41	            if let Err(e) = self.transaction_validator.validate_tx_in_header_context(tx, lock_time_arg) {
    42	                return Err(RuleError::TxInContextFailed(tx.id(), e));
    43	            };
    44	        }
    45	        Ok(())
    46	    }
    47	
    48	    fn check_parent_bodies_exist(self: &Arc<Self>, block: &Block) -> BlockProcessResult<()> {
    49	        let statuses_read_guard = self.statuses_store.read();
    50	        let missing: Vec<Hash> = block
    51	            .header
    52	            .direct_parents()
    53	            .iter()
    54	            .copied()
    55	            .filter(|parent| {
    56	                let status_option = statuses_read_guard.get(*parent).optional().unwrap();
    57	                status_option.is_none_or(|s| !s.has_block_body())
    58	            })
    59	            .collect();
    60	        if !missing.is_empty() {
    61	            return Err(RuleError::MissingParents(missing));
    62	        }
    63	
    64	        Ok(())
    65	    }
    66	
    67	    fn check_coinbase_blue_score_and_subsidy(self: &Arc<Self>, block: &Block) -> BlockProcessResult<()> {
    68	        match self.coinbase_manager.deserialize_coinbase_payload(&block.transactions[0].payload) {
    69	            Ok(data) => {
    70	                if data.blue_score != block.header.blue_score {
    71	                    return Err(RuleError::BadCoinbasePayloadBlueScore(data.blue_score, block.header.blue_score));
    72	                }
    73	
    74	                let expected_subsidy = self.coinbase_manager.calc_block_subsidy(block.header.daa_score);
    75	
    76	                if data.subsidy != expected_subsidy {
    77	                    return Err(RuleError::WrongSubsidy(expected_subsidy, data.subsidy));
    78	                }
    79	
    80	                Ok(())
    81	            }
    82	            Err(e) => Err(RuleError::BadCoinbasePayload(e)),
    83	        }
    84	    }
    85	}
    86	
    87	#[cfg(test)]
    88	mod tests {
    89	
    90	    use crate::{
    91	        config::ConfigBuilder,
    92	        consensus::test_consensus::TestConsensus,
    93	        constants::TX_VERSION,
    94	        errors::RuleError,
    95	        model::stores::ghostdag::GhostdagStoreReader,
    96	        processes::{transaction_validator::errors::TxRuleError, window::WindowManager},
    97	    };
    98	    use kaspa_consensus_core::{
    99	        api::ConsensusApi,
   100	        config::params::MAINNET_PARAMS,
   101	        merkle::calc_hash_merkle_root,
   102	        subnets::SUBNETWORK_ID_NATIVE,
   103	        tx::{Transaction, TransactionInput, TransactionOutpoint},
   104	    };
   105	    use kaspa_core::assert_match;
   106	    use kaspa_hashes::Hash;
   107	
---- lines 110-248 ----
   110	        let config = ConfigBuilder::new(MAINNET_PARAMS)
   111	            .skip_proof_of_work()
   112	            .edit_consensus_params(|p| p.deflationary_phase_daa_score = p.genesis.daa_score + 2)
   113	            .build();
   114	        let consensus = TestConsensus::new(&config);
   115	        let wait_handles = consensus.init();
   116	        let body_processor = consensus.block_body_processor();
   117	
   118	        consensus.add_header_only_block_with_parents(1.into(), vec![config.genesis.hash]).await.unwrap();
   119	
   120	        {
   121	            let block = consensus.build_block_with_parents_and_transactions(2.into(), vec![1.into()], vec![]);
   122	            // We expect a missing parents error since the parent is header only.
   123	            assert_match!(body_processor.validate_body_in_context(&block.to_immutable()), Err(RuleError::MissingParents(_)));
   124	        }
   125	
   126	        let valid_block = consensus.build_block_with_parents_and_transactions(3.into(), vec![config.genesis.hash], vec![]);
   127	        consensus.validate_and_insert_block(valid_block.to_immutable()).virtual_state_task.await.unwrap();
   128	        {
   129	            let mut block = consensus.build_block_with_parents_and_transactions(2.into(), vec![3.into()], vec![]);
   130	            block.transactions[0].payload[8..16].copy_from_slice(&(5_u64).to_le_bytes());
   131	            block.header.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
   132	
   133	            assert_match!(
   134	                consensus.validate_and_insert_block(block.clone().to_immutable()).virtual_state_task.await,
   135	                Err(RuleError::WrongSubsidy(_, _))
   136	            );
   137	
   138	            // The second time we send an invalid block we expect it to be a known invalid.
   139	            assert_match!(
   140	                consensus.validate_and_insert_block(block.to_immutable()).virtual_state_task.await,
   141	                Err(RuleError::KnownInvalid)
   142	            );
   143	        }
   144	
   145	        {
   146	            let mut block = consensus.build_block_with_parents_and_transactions(4.into(), vec![3.into()], vec![]);
   147	            block.transactions[0].payload[0..8].copy_from_slice(&(100_u64).to_le_bytes());
   148	            block.header.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
   149	
   150	            assert_match!(
   151	                consensus.validate_and_insert_block(block.to_immutable()).virtual_state_task.await,
   152	                Err(RuleError::BadCoinbasePayloadBlueScore(_, _))
   153	            );
   154	        }
   155	
   156	        {
   157	            let mut block = consensus.build_block_with_parents_and_transactions(5.into(), vec![3.into()], vec![]);
   158	            block.transactions[0].payload = vec![];
   159	            block.header.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
   160	
   161	            assert_match!(
   162	                consensus.validate_and_insert_block(block.to_immutable()).virtual_state_task.await,
   163	                Err(RuleError::BadCoinbasePayload(_))
   164	            );
   165	        }
   166	
   167	        let valid_block_child = consensus.build_block_with_parents_and_transactions(6.into(), vec![3.into()], vec![]);
   168	        consensus.validate_and_insert_block(valid_block_child.clone().to_immutable()).virtual_state_task.await.unwrap();
   169	        {
   170	            // The block DAA score is 2, so the subsidy should be calculated according to the deflationary stage.
   171	            let mut block = consensus.build_block_with_parents_and_transactions(7.into(), vec![6.into()], vec![]);
   172	            block.transactions[0].payload[8..16].copy_from_slice(&(5_u64).to_le_bytes());
   173	            block.header.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
   174	            assert_match!(
   175	                consensus.validate_and_insert_block(block.to_immutable()).virtual_state_task.await,
   176	                Err(RuleError::WrongSubsidy(_, _))
   177	            );
   178	        }
   179	
   180	        {
   181	            // Check that the same daa score as the block's daa score or higher fails, but lower passes.
   182	            let tip_daa_score = valid_block_child.header.daa_score + 1;
   183	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 8.into(), tip_daa_score + 1, 0, false).await;
   184	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 9.into(), tip_daa_score, 0, false).await;
   185	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 10.into(), tip_daa_score - 1, 0, true).await;
   186	
   187	            let valid_block_child_gd = consensus.ghostdag_store().get_data(valid_block_child.header.hash).unwrap();
   188	            let (valid_block_child_gd_pmt, _) = consensus.window_manager().calc_past_median_time(&valid_block_child_gd).unwrap();
   189	            let past_median_time = valid_block_child_gd_pmt + 1;
   190	
   191	            // Check that the same past median time as the block's or higher fails, but lower passes.
   192	            let tip_daa_score = valid_block_child.header.daa_score + 1;
   193	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 11.into(), past_median_time + 1, 0, false)
   194	                .await;
   195	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 12.into(), past_median_time, 0, false).await;
   196	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 13.into(), past_median_time - 1, 0, true)
   197	                .await;
   198	
   199	            // We check that if the transaction is marked as finalized it'll pass for any lock time.
   200	            check_for_lock_time_and_sequence(
   201	                &consensus,
   202	                valid_block_child.header.hash,
   203	                14.into(),
   204	                past_median_time + 1,
   205	                u64::MAX,
   206	                true,
   207	            )
   208	            .await;
   209	
   210	            check_for_lock_time_and_sequence(&consensus, valid_block_child.header.hash, 15.into(), tip_daa_score + 1, u64::MAX, true)
   211	                .await;
   212	        }
   213	
   214	        consensus.shutdown(wait_handles);
   215	    }
   216	
   217	    async fn check_for_lock_time_and_sequence(
   218	        consensus: &TestConsensus,
   219	        parent: Hash,
   220	        block_hash: Hash,
   221	        lock_time: u64,
   222	        sequence: u64,
   223	        should_pass: bool,
   224	    ) {
   225	        // The block DAA score is 2, so the subsidy should be calculated according to the deflationary stage.
   226	        let block = consensus.build_block_with_parents_and_transactions(
   227	            block_hash,
   228	            vec![parent],
   229	            vec![Transaction::new(
   230	                TX_VERSION,
   231	                vec![TransactionInput::new(TransactionOutpoint::new(1.into(), 0), vec![], sequence, 0)],
   232	                vec![],
   233	                lock_time,
   234	                SUBNETWORK_ID_NATIVE,
   235	                0,
   236	                vec![],
   237	            )],
   238	        );
   239	
   240	        if should_pass {
   241	            consensus.validate_and_insert_block(block.to_immutable()).virtual_state_task.await.unwrap();
   242	        } else {
   243	            assert_match!(
   244	                consensus.validate_and_insert_block(block.to_immutable()).virtual_state_task.await,
   245	                Err(RuleError::TxInContextFailed(_, e)) if matches!(e, TxRuleError::NotFinalized(_)));
   246	        }
   247	    }
   248	}

======== EXCERPTS (zethora|subsidy|coinbase|cap_units|fee_pool|pool_state|ledger|issued|burn): consensus/src/pipeline/virtual_processor/utxo_validation.rs ========
---- lines 1-615 ----
     1	use super::{VirtualStateProcessor, bounds::SeqCommitBounds};
     2	use crate::{
     3	    errors::{
     4	        BlockProcessResult,
     5	        RuleError::{
     6	            BadAcceptedIDMerkleRoot, BadCoinbaseTransaction, BadUTXOCommitment, InvalidTransactionsInUtxoContext,
     7	            WrongHeaderPruningPoint, WrongSelectedParentOrder, ZethoraSupplyMismatch,
     8	        },
     9	    },
    10	    model::stores::{
    11	        block_transactions::BlockTransactionsStoreReader,
    12	        daa::DaaStoreReader,
    13	        ghostdag::{CompactGhostdagData, GhostdagData},
    14	        headers::HeaderStoreReader,
    15	        zethora_note_trees::ZethoraNoteTreesStoreReader,
    16	        zethora_private_states::ZethoraPrivateStatesStoreReader,
    17	    },
    18	    processes::{
    19	        pruning::PruningPointReply,
    20	        transaction_validator::{
    21	            errors::{TxResult, TxRuleError},
    22	            tx_validation_in_utxo_context::TxValidationFlags,
    23	        },
    24	        zethora_supply,
    25	    },
    26	};
    27	use kaspa_consensus_core::{
    28	    BlockHashMap, BlockHashSet, HashMapCustomHasher,
    29	    acceptance_data::{AcceptedTxEntry, MergesetBlockAcceptanceData},
    30	    api::args::TransactionValidationArgs,
    31	    coinbase::*,
    32	    errors::coinbase::CoinbaseError,
    33	    hashing,
    34	    header::Header,
    35	    muhash::MuHashExtensions,
    36	    tx::{MutableTransaction, PopulatedTransaction, Transaction, ValidatedTransaction, VerifiableTransaction},
    37	    utxo::{
    38	        utxo_diff::UtxoDiff,
    39	        utxo_view::{UtxoView, UtxoViewComposition},
    40	    },
    41	};
    42	use kaspa_core::{info, trace, warn};
    43	use kaspa_hashes::Hash;
    44	use kaspa_muhash::MuHash;
    45	use kaspa_utils::refs::Refs;
    46	
    47	use crate::model::services::reachability::ReachabilityService;
    48	use crate::model::services::seq_commit_accessor::SeqCommitAccessor;
    49	use kaspa_consensus_core::zethora_private;
    50	use rayon::prelude::*;
    51	use smallvec::SmallVec;
    52	use std::collections::HashSet;
    53	use std::{iter::once, ops::Deref};
    54	
    55	/// Per-lane activity and miner payload data extracted from a mergeset.
    56	pub(super) struct MergesetSeqData {
    57	    /// Per-lane activity leaves: lane_id → [activity_leaf hashes].
    58	    /// BTreeMap gives sorted iteration over lanes.
    59	    pub lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>>,
    60	    /// One payload leaf hash per merged block, in mergeset order.
    61	    pub miner_payload_leaves: Vec<Hash>,
    62	}
    63	
    64	/// A resolved lane update ready for SMT processing.
    65	pub(super) struct ResolvedLaneUpdate {
    66	    pub lane_key: kaspa_smt_store::LaneKey,
    67	    pub new_tip: Hash,
    68	    /// True if this lane had no active canonical version (new or reactivated).
    69	    pub is_new: bool,
    70	}
    71	
    72	/// Selected-parent state the current block inherits when building its seq_commit.
    73	pub(super) struct ParentBlockSeqState {
    74	    /// `accepted_id_merkle_root` of the selected parent.
    75	    pub seq_commit: Hash,
    76	    pub blue_score: u64,
    77	    pub lanes_root: Hash,
    78	    pub active_lanes_count: u64,
    79	}
    80	
    81	/// A context for processing the UTXO state of a block with respect to its selected parent.
    82	/// Note this can also be the virtual block.
    83	pub(super) struct UtxoProcessingContext<'a> {
    84	    pub ghostdag_data: Refs<'a, GhostdagData>,
    85	    pub multiset_hash: MuHash,
    86	    pub mergeset_diff: UtxoDiff,
    87	    pub mergeset_acceptance_data: Vec<MergesetBlockAcceptanceData>,
    88	    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
    89	    pub pruning_sample_from_pov: Option<Hash>,
    90	    /// Zethora: the private coin list after this block's mergeset (ZTH-SPEC-006 §6.1)
    91	    pub note_tree: zethora_shielded::NoteCommitmentTree,
    92	    /// Zethora: whether this mergeset added private coins, i.e. produced a new coin list snapshot (anchor, §6.2)
    93	    pub note_tree_grew: bool,
    94	    /// Zethora: private coin tags (nullifiers) accepted by this mergeset so far, as a set and in order (§6.3)
    95	    pub nullifiers: HashSet<[u8; 32]>,
    96	    pub nullifier_list: Vec<[u8; 32]>,
    97	    /// Zethora: the private state fingerprint (ZTH-SPEC-006 §6.4) after this mergeset: every coin tag spent and every
    98	    /// coin list snapshot produced on the chain so far. Unfinalized, so the next chain block can add to it.
    99	    pub private_state: MuHash,
   100	    /// Zethora: the private pool's public balance (the turnstile, ZTH-SPEC-006 §7.1) after the transactions this mergeset
   101	    /// accepted so far. Starts at the selected parent's sealed balance; a transaction that would take it below zero is
   102	    /// not accepted at all.
   103	    pub shielded_balance: u64,
   104	}
   105	
   106	impl<'a> UtxoProcessingContext<'a> {
   107	    pub fn new(ghostdag_data: Refs<'a, GhostdagData>, selected_parent_multiset_hash: MuHash) -> Self {
   108	        let mergeset_size = ghostdag_data.mergeset_size();
   109	        Self {
   110	            ghostdag_data,
   111	            multiset_hash: selected_parent_multiset_hash,
   112	            mergeset_diff: UtxoDiff::default(),
   113	
   114	            mergeset_rewards: BlockHashMap::with_capacity(mergeset_size),
   115	            mergeset_acceptance_data: Vec::with_capacity(mergeset_size),
   116	            pruning_sample_from_pov: Default::default(),
   117	            note_tree: zethora_shielded::NoteCommitmentTree::new(),
   118	            note_tree_grew: false,
   119	            nullifiers: HashSet::new(),
   120	            nullifier_list: Vec::new(),
   121	            private_state: MuHash::new(),
   122	            shielded_balance: 0,
   123	        }
   124	    }
   125	
   126	    pub fn selected_parent(&self) -> Hash {
   127	        self.ghostdag_data.selected_parent
   128	    }
   129	}
   130	
   131	impl VirtualStateProcessor {
   132	    /// Calculates UTXO state and transaction acceptance data relative to the selected parent state
   133	    pub(super) fn calculate_utxo_state<V: UtxoView + Sync>(
   134	        &self,
   135	        ctx: &mut UtxoProcessingContext,
   136	        selected_parent_utxo_view: &V,
   137	        pov_daa_score: u64,
   138	    ) {
   139	        // Zethora: start from the selected parent's private coin list (ZTH-SPEC-006 §6.1)
   140	        let selected_parent = ctx.selected_parent();
   141	        ctx.note_tree = self
   142	            .zethora_note_trees_store
   143	            .get(selected_parent)
   144	            .unwrap_or_else(|e| panic!("{}", missing_private_state_message("private coin list", selected_parent, &e)));
   145	        ctx.private_state = self
   146	            .zethora_private_states_store
   147	            .get(selected_parent)
   148	            .unwrap_or_else(|e| panic!("{}", missing_private_state_message("private state fingerprint", selected_parent, &e)));
   149	
   150	        // Zethora: the private pool's balance before this mergeset, as the selected parent sealed it (ZTH-SPEC-006 §7.1)
   151	        ctx.shielded_balance = self.pool_state_of(selected_parent).shielded_balance;
   152	
   153	        let selected_parent_transactions = self.block_transactions_store.get(ctx.selected_parent()).unwrap();
   154	        let validated_coinbase = ValidatedTransaction::new_coinbase(&selected_parent_transactions[0]);
   155	
   156	        ctx.mergeset_diff.add_transaction(&validated_coinbase, pov_daa_score).unwrap();
   157	        ctx.multiset_hash.add_transaction(&validated_coinbase, pov_daa_score);
   158	        let validated_coinbase_id = validated_coinbase.id();
   159	
   160	        for (i, (merged_block, txs)) in once((ctx.selected_parent(), selected_parent_transactions))
   161	            .chain(
   162	                ctx.ghostdag_data
   163	                    .consensus_ordered_mergeset_without_selected_parent(self.ghostdag_store.deref())
   164	                    .map(|b| (b, self.block_transactions_store.get(b).unwrap())),
   165	            )
   166	            .enumerate()
   167	        {
   168	            // Create a composed UTXO view from the selected parent UTXO view + the mergeset UTXO diff
   169	            let composed_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);
   170	
   171	            // The first block in the mergeset is always the selected parent
   172	            let is_selected_parent = i == 0;
   173	
   174	            // No need to fully validate selected parent transactions: they were already fully validated when
   175	            // the selected parent passed verify_expected_utxo_state, using its own DAA score for both POV and
   176	            // block DAA score, and its selected parent as the seqcommit context.
   177	            //
   178	            // Here we only replay them while building the child's UTXO state. The child's POV DAA score is
   179	            // safe for non-script checks because maturity and sequence-lock checks are monotonic. Seqcommit
   180	            // context is not monotonic (the threshold can be crossed), but it is only used by script checks,
   181	            // which we skip for selected-parent transactions.
   182	            let validation_flags = if is_selected_parent { TxValidationFlags::SkipScriptChecks } else { TxValidationFlags::Full };
   183	            let (validated_transactions, inner_multiset) = self.validate_transactions_with_muhash_in_parallel(
   184	                &txs,
   185	                &composed_view,
   186	                pov_daa_score,
   187	                self.headers_store.get_daa_score(merged_block).unwrap(),
   188	                validation_flags,
   189	                ctx.selected_parent(),
   190	                &ctx.nullifiers,
   191	                &mut ctx.shielded_balance,
   192	            );
   193	
   194	            ctx.multiset_hash.combine(&inner_multiset);
   195	
   196	            let mut block_fee = 0u64;
   197	            let mut block_base_fee = 0u64; // Zethora: base-fee part (ZTH-SPEC-008)
   198	            let (mut block_pool_in, mut block_pool_out) = (0u64, 0u64); // Zethora: private pool flows (ZTH-SPEC-006)
   199	            for (validated_tx, _) in validated_transactions.iter() {
   200	                ctx.mergeset_diff.add_transaction(validated_tx, pov_daa_score).unwrap();
   201	                block_fee += validated_tx.calculated_fee;
   202	                let compute_mass = self.transaction_validator.mass_calculator.calc_non_contextual_masses(validated_tx.tx).compute_mass;
   203	                block_base_fee += crate::processes::zethora_fees::base_fee(validated_tx.calculated_fee, compute_mass);
   204	                // Already validated, so the value balance is readable
   205	                if let Ok(Some((value_in, value_out))) = kaspa_consensus_core::zethora_private::pool_flows(&validated_tx.tx.payload) {
   206	                    block_pool_in += value_in;
   207	                    block_pool_out += value_out;
   208	                }
   209	            }
   210	
   211	            // Zethora: remember the private coin tags this block's accepted transactions spent, so a later block in
   212	            // the same mergeset can't spend them again (ZTH-SPEC-006 §6.3). Within one block they are unique (body rule).
   213	            for (vtx, _) in validated_transactions.iter() {
   214	                for nf in zethora_private::nullifiers(&vtx.tx.payload) {
   215	                    if ctx.nullifiers.insert(nf) {
   216	                        ctx.nullifier_list.push(nf);
   217	                        ctx.private_state.add_element(&zethora_private::private_state_spent_element(&nf));
   218	                    }
   219	                }
   220	            }
   221	
   222	            // Zethora: add this block's new private coins to the list, in block order (ZTH-SPEC-006 §6.1).
   223	            // Every node walks the mergeset in the same consensus order, so every node builds the same list.
   224	            let mut private_txs: Vec<_> = validated_transactions
   225	                .iter()
   226	                .filter(|(vtx, _)| kaspa_consensus_core::zethora_private::private_payment_bytes(&vtx.tx.payload).is_some())
   227	                .map(|(vtx, idx)| (*idx, vtx.tx))
   228	                .collect();
   229	            private_txs.sort_by_key(|(idx, _)| *idx);
   230	            for (_, tx) in private_txs {
   231	                let encoded = kaspa_consensus_core::zethora_private::private_payment_bytes(&tx.payload).expect("filtered above");
   232	                for cmx in zethora_shielded::codec::note_commitments(encoded).expect("accepted private payments are well-formed") {
   233	                    ctx.note_tree.append(&cmx).expect("private coin list is full: migrate to a new pool version");
   234	                    ctx.note_tree_grew = true;
   235	                }
   236	            }
   237	
   238	            ctx.mergeset_acceptance_data.push(MergesetBlockAcceptanceData {
   239	                block_hash: merged_block,
   240	                // For the selected parent, we prepend the coinbase tx
   241	                accepted_transactions: is_selected_parent
   242	                    .then_some(AcceptedTxEntry { transaction_id: validated_coinbase_id, index_within_block: 0 })
   243	                    .into_iter()
   244	                    .chain(
   245	                        validated_transactions
   246	                            .into_iter()
   247	                            .map(|(tx, tx_idx)| AcceptedTxEntry { transaction_id: tx.id(), index_within_block: tx_idx }),
   248	                    )
   249	                    .collect(),
   250	            });
   251	
   252	            let coinbase_data = self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).unwrap();
   253	            ctx.mergeset_rewards.insert(
   254	                merged_block,
   255	                BlockRewardData::new(coinbase_data.subsidy, block_fee, block_base_fee, coinbase_data.miner_data.script_public_key)
   256	                    .with_pool_flows(block_pool_in, block_pool_out),
   257	            );
   258	        }
   259	
   260	        // Zethora: this mergeset's final coin list is a new snapshot (anchor) if it grew; add it to the fingerprint with
   261	        // this block's blue score (the anchors store records the same root and score for this block when it is committed)
   262	        if ctx.note_tree_grew {
   263	            ctx.private_state.add_element(&zethora_private::private_state_anchor_element(
   264	                &ctx.note_tree.root().to_bytes(),
   265	                ctx.ghostdag_data.blue_score,
   266	            ));
   267	        }
   268	    }
   269	
   270	    /// Verify that the current block fully respects its own UTXO view. We define a block as
   271	    /// UTXO valid if all the following conditions hold:
   272	    ///     1. The block header includes the expected `utxo_commitment`.
   273	    ///     2. The block header includes the expected `accepted_id_merkle_root`.
   274	    ///     3. The block header includes the expected `pruning_point`.
   275	    ///     4. The block coinbase transaction rewards the mergeset blocks correctly.
   276	    ///     5. All non-coinbase block transactions are valid against its own UTXO view.
   277	    pub(super) fn verify_expected_utxo_state<V: UtxoView + Sync>(
   278	        &self,
   279	        ctx: &mut UtxoProcessingContext,
   280	        selected_parent_utxo_view: &V,
   281	        header: &Header,
   282	    ) -> BlockProcessResult<Option<kaspa_smt_store::processor::SmtBuild>> {
   283	        // Verify header UTXO commitment
   284	        let expected_commitment = ctx.multiset_hash.finalize();
   285	        if expected_commitment != header.utxo_commitment {
   286	            return Err(BadUTXOCommitment(header.hash, header.utxo_commitment, expected_commitment));
   287	        }
   288	        trace!("correct commitment: {}, {}", header.hash, expected_commitment);
   289	
   290	        // KIP-21: compute seq_commit from SMT lane processing
   291	        let (expected_accepted_id_merkle_root, smt_build) = self.recompute_seq_commit(ctx, header)?;
   292	        let smt_build = Some(smt_build);
   293	
   294	        // Verify header accepted_id_merkle_root
   295	        if expected_accepted_id_merkle_root != header.accepted_id_merkle_root {
   296	            return Err(BadAcceptedIDMerkleRoot(header.hash, header.accepted_id_merkle_root, expected_accepted_id_merkle_root));
   297	        }
   298	
   299	        let txs = self.block_transactions_store.get(header.hash).unwrap();
   300	
   301	        // Verify coinbase transaction (including the Zethora supply ledger, measured from the real UTXO changes)
   302	        self.verify_coinbase_transaction(
   303	            &txs[0],
   304	            header.daa_score,
   305	            &ctx.ghostdag_data,
   306	            &ctx.mergeset_rewards,
   307	            &self.daa_excluded_store.get_mergeset_non_daa(header.hash).unwrap(),
   308	            self.visible_change_of(&ctx.mergeset_diff, ctx.selected_parent()),
   309	            ctx.note_tree.root().to_bytes(),
   310	            ctx.private_state.clone().finalize().as_bytes(),
   311	        )?;
   312	
   313	        // Verify the header pruning point
   314	        let reply = self.verify_header_pruning_point(header, ctx.ghostdag_data.to_compact())?;
   315	        ctx.pruning_sample_from_pov = Some(reply.pruning_sample);
   316	
   317	        // Verify the first parent is the selected parent
   318	        //
   319	        // Purpose: Enables seqcommit opcode verification for syncees. By enforcing this rule,
   320	        // a node can trustlessly verify the selected chain segment below the pruning point
   321	        // (PP) simply by walking back through first-parents, avoiding a full GHOSTDAG
   322	        // computation over the historical DAG.
   323	        //
   324	        // Design Note: This is enforced as a chain-qualification rule rather than
   325	        // header-validity. This maintains compatibility with protocols like DAGKNIGHT,
   326	        // which may not compute selected parents for every block, while still securing
   327	        // the pruning point (which is a qualified chain block by definition).
   328	        let selected_parent = ctx.ghostdag_data.selected_parent;
   329	        let first_parent = header.direct_parents()[0];
   330	        if first_parent != selected_parent {
   331	            return Err(WrongSelectedParentOrder(header.hash, selected_parent, first_parent));
   332	        }
   333	
   334	        // Final chain qualification condition: verify all transactions are valid in context.
   335	        //
   336	        // We verify this chain block's transactions in the same way they were built and checked by
   337	        // build_block_template -> validate_block_template_transaction: use the block DAA score as the
   338	        // POV DAA score, and use the selected parent as the seqcommit context. Later, calculate_utxo_state
   339	        // relies on this check when replaying this block as a selected parent.
   340	        let current_utxo_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);
   341	        let validated_transactions = self.validate_transactions_in_parallel(
   342	            &txs,
   343	            &current_utxo_view,
   344	            header.daa_score,
   345	            header.daa_score,
   346	            TxValidationFlags::Full,
   347	            ctx.selected_parent(),
   348	        );
   349	        // Zethora: the block's own transactions may not spend private coin tags its mergeset already spent (§6.3), and,
   350	        // one at a time in block order, may not take the private pool below the balance its mergeset leaves (the
   351	        // turnstile, §7.1), exactly as the next chain block replays them
   352	        let mut validated_transactions = validated_transactions;
   353	        validated_transactions.sort_unstable_by_key(|(_, idx)| *idx);
   354	        let mut shielded_balance = ctx.shielded_balance;
   355	        let valid = validated_transactions
   356	            .iter()
   357	            .filter(|(vtx, _)| {
   358	                !zethora_private::nullifiers(&vtx.tx.payload).iter().any(|nf| ctx.nullifiers.contains(nf))
   359	                    && zethora_supply::turnstile_accepts(&mut shielded_balance, &vtx.tx.payload)
   360	            })
   361	            .count();
   362	        if valid < txs.len() - 1 {
   363	            // Some non-coinbase transactions are invalid
   364	            return Err(InvalidTransactionsInUtxoContext(txs.len() - 1 - valid, txs.len() - 1));
   365	        }
   366	
   367	        Ok(smt_build)
   368	    }
   369	
   370	    fn verify_header_pruning_point(
   371	        &self,
   372	        header: &Header,
   373	        ghostdag_data: CompactGhostdagData,
   374	    ) -> BlockProcessResult<PruningPointReply> {
   375	        let reply = self.pruning_point_manager.expected_header_pruning_point(ghostdag_data);
   376	        if reply.pruning_point != header.pruning_point {
   377	            return Err(WrongHeaderPruningPoint(reply.pruning_point, header.pruning_point));
   378	        }
   379	        Ok(reply)
   380	    }
   381	
   382	    fn verify_coinbase_transaction(
   383	        &self,
   384	        coinbase: &Transaction,
   385	        daa_score: u64,
   386	        ghostdag_data: &GhostdagData,
   387	        mergeset_rewards: &BlockHashMap<BlockRewardData>,
   388	        mergeset_non_daa: &BlockHashSet,
   389	        visible_change: i128,
   390	        note_root: [u8; 32],
   391	        private_state: [u8; 32],
   392	    ) -> BlockProcessResult<()> {
   393	        // Extract only miner data from the provided coinbase
   394	        let miner_data = self.coinbase_manager.deserialize_coinbase_payload(&coinbase.payload).unwrap().miner_data;
   395	        let parent_pool = self.pool_state_of(ghostdag_data.selected_parent);
   396	        let expected_coinbase = match self.coinbase_manager.expected_coinbase_transaction(
   397	            daa_score,
   398	            miner_data,
   399	            ghostdag_data,
   400	            mergeset_rewards,
   401	            mergeset_non_daa,
   402	            parent_pool,
   403	            visible_change,
   404	            note_root,
   405	            private_state,
   406	        ) {
   407	            Ok(template) => template.tx,
   408	            // Zethora: the block's coins do not add up, so it is invalid (ZTH-SPEC-006 §7.2)
   409	            Err(CoinbaseError::ZethoraSupply(reason)) => return Err(ZethoraSupplyMismatch(reason)),
   410	            Err(e) => panic!("unexpected coinbase error: {e}"),
   411	        };
   412	        if hashing::tx::hash(coinbase) != hashing::tx::hash(&expected_coinbase) { Err(BadCoinbaseTransaction) } else { Ok(()) }
   413	    }
   414	
   415	    /// Zethora: net change in visible coins from the transactions a mergeset accepts, measured from the
   416	    /// real UTXO diff. The diff also holds the selected parent's coinbase outputs, which are already
   417	    /// counted in the parent's ledger, so they are taken out here. With correct bookkeeping the result
   418	    /// is minus the mergeset's total fees (ZTH-SPEC-006 §7.2).
   419	    pub(crate) fn visible_change_of(&self, mergeset_diff: &UtxoDiff, selected_parent: Hash) -> i128 {
   420	        let added: i128 = mergeset_diff.add.values().map(|e| e.amount as i128).sum();
   421	        let removed: i128 = mergeset_diff.remove.values().map(|e| e.amount as i128).sum();
   422	        let parent_coinbase: i128 =
   423	            self.block_transactions_store.get(selected_parent).unwrap()[0].outputs.iter().map(|o| o.value as i128).sum();
   424	        added - removed - parent_coinbase
   425	    }
   426	
   427	    /// Zethora: is this private coin tag already spent on the selected chain ending at `selected_parent`?
   428	    /// A tag counts as spent if any chain block that accepted it is a chain ancestor of (or is) `selected_parent`.
   429	    /// Records of pruned chain blocks are rewritten to `SPENT_FOR_GOOD` by the pruning processor, so every node
   430	    /// gives the same answer whether or not it has pruned. If reachability is unexpectedly missing, it counts as spent.
   431	    pub(crate) fn nullifier_spent_on_chain(&self, nullifier: &[u8; 32], selected_parent: Hash) -> bool {
   432	        use crate::model::stores::zethora_nullifiers::SPENT_FOR_GOOD;
   433	        self.zethora_nullifiers_store.accepting_blocks(nullifier).into_iter().any(|block| {
   434	            block == SPENT_FOR_GOOD || self.reachability_service.try_is_chain_ancestor_of(block, selected_parent).unwrap_or(true)
   435	        })
   436	    }
   437	
   438	    /// Zethora: does this transaction spend a private coin tag that is already spent, either on the chain of
   439	    /// `selected_parent` or in `pending` (tags accepted earlier in the same mergeset / block template)?
   440	    pub(crate) fn private_double_spend(&self, tx: &Transaction, selected_parent: Hash, pending: &HashSet<[u8; 32]>) -> bool {
   441	        zethora_private::nullifiers(&tx.payload)
   442	            .iter()
   443	            .any(|nf| pending.contains(nf) || self.nullifier_spent_on_chain(nf, selected_parent))
   444	    }
   445	
   446	    /// Zethora: is `anchor` a private coin list snapshot that a spend accepted on top of `selected_parent` may use?
   447	    /// It must have been produced by a chain ancestor of (or by) `selected_parent` whose blue score is at least
   448	    /// `ANCHOR_DEPTH` below it (ZTH-SPEC-006 §6.2). Records of pruned chain blocks are rewritten to `ANCHORED_FOR_GOOD`
   449	    /// (keeping the blue score) by the pruning processor, and a node joining from a pruning point stores the snapshots
   450	    /// it downloads the same way, so every node gives the same answer whether or not it has pruned or joined late.
   451	    /// If reachability or the tip's header is unexpectedly missing, the anchor does not count.
   452	    pub(crate) fn anchor_matured_on_chain(&self, anchor: &[u8; 32], selected_parent: Hash) -> bool {
   453	        use crate::model::stores::zethora_anchors::ANCHORED_FOR_GOOD;
   454	        let producers = self.zethora_anchors_store.producing_blocks(anchor);
   455	        if producers.is_empty() {
   456	            return false;
   457	        }
   458	        let Ok(tip_blue_score) = self.headers_store.get_blue_score(selected_parent) else { return false };
   459	        producers.into_iter().any(|p| {
   460	            p.blue_score.saturating_add(self.anchor_depth) <= tip_blue_score
   461	                && (p.block == ANCHORED_FOR_GOOD
   462	                    || self.reachability_service.try_is_chain_ancestor_of(p.block, selected_parent).unwrap_or(false))
   463	        })
   464	    }
   465	
   466	    /// Zethora: the private payment rules that depend on the chain a transaction is accepted on (ZTH-SPEC-006):
   467	    /// none of its coin tags is already spent on the chain of `selected_parent` or in `pending` (§6.3), and if it
   468	    /// spends private coins, its anchor is a matured snapshot of that chain's coin list (§6.2).
   469	    pub(crate) fn check_private_payment_in_context(
   470	        &self,
   471	        tx: &Transaction,
   472	        selected_parent: Hash,
   473	        pending: &HashSet<[u8; 32]>,
   474	    ) -> TxResult<()> {
   475	        if self.private_double_spend(tx, selected_parent, pending) {
   476	            return Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string()));
   477	        }
   478	        if let Some(anchor) = zethora_private::spend_anchor(&tx.payload)
   479	            && !self.anchor_matured_on_chain(&anchor, selected_parent)
   480	        {
   481	            return Err(TxRuleError::InvalidPrivatePayment(format!(
   482	                "spend uses an unknown or too recent private coin list snapshot (it must be at least {} blocks deep)",
   483	                self.anchor_depth
   484	            )));
   485	        }
   486	        Ok(())
   487	    }
   488	
   489	    /// Zethora: the turnstile at mempool admission (ZTH-SPEC-006 §7.1), the same rule the block template applies: a
   490	    /// private payment may not take more out of the private pool than `pool_left`, the pool's public balance after the
   491	    /// virtual's mergeset. Value it brings in is not counted. Such a payment could never be accepted on top of the
   492	    /// current chain, so keeping it would only waste mempool space and template slots. Chain-dependent: never a ban.
   493	    pub(crate) fn check_private_payment_fits_pool(&self, tx: &Transaction, pool_left: u64) -> TxResult<()> {
   494	        match zethora_private::pool_flows(&tx.payload) {
   495	            Ok(Some((_, value_out))) if value_out > pool_left => Err(TxRuleError::InvalidPrivatePayment(format!(
   496	                "would take {value_out} zets out of the private pool, which holds {pool_left}"
   497	            ))),
   498	            // An unreadable value balance is refused by the in-isolation checks
   499	            _ => Ok(()),
   500	        }
   501	    }
   502	
   503	    /// Zethora: the fee pool state recorded in a block's coinbase (ZTH-SPEC-008).
   504	    /// The pool flows along the selected chain: each chain block reads its selected parent's state.
   505	    pub(crate) fn pool_state_of(&self, block: Hash) -> PoolState {
   506	        let txs = self.block_transactions_store.get(block).unwrap();
   507	        self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).map(|d| d.pool).unwrap()
   508	    }
   509	
   510	    /// Validates transactions against the provided `utxo_view` and returns a vector with all transactions
   511	    /// which passed the validation along with their original index within the containing block
   512	    pub(crate) fn validate_transactions_in_parallel<'a, V: UtxoView + Sync>(
   513	        &self,
   514	        txs: &'a Vec<Transaction>,
   515	        utxo_view: &V,
   516	        pov_daa_score: u64,
   517	        block_daa_score: u64,
   518	        flags: TxValidationFlags,
   519	        selected_parent: Hash,
   520	    ) -> Vec<(ValidatedTransaction<'a>, u32)> {
   521	        self.thread_pool.install(|| {
   522	            txs
   523	                .par_iter() // We can do this in parallel without complications since block body validation already ensured
   524	                            // that all txs within each block are independent
   525	                .enumerate()
   526	                .skip(1) // Skip the coinbase tx.
   527	                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score,block_daa_score, flags, selected_parent).ok().map(|vtx| (vtx, i as u32)))
   528	                .collect()
   529	        })
   530	    }
   531	
   532	    /// Same as validate_transactions_in_parallel except this will also calculate the muhash in parallel for the
   533	    /// accepted transactions.
   534	    ///
   535	    /// Zethora: also applies the private pool turnstile (ZTH-SPEC-006 §7.1) to the valid transactions one at a time, in
   536	    /// block order, starting from `shielded_balance` (the balance after the earlier blocks of the mergeset). A transaction
   537	    /// that would take the pool below zero is not accepted: it is left out of the result, so none of its effects (UTXO
   538	    /// diff, muhash, coin tags, coin list, fees, pool flows, acceptance data, seq-commit) ever happen. `shielded_balance`
   539	    /// is left at the balance after the accepted ones.
   540	    #[allow(clippy::too_many_arguments)]
   541	    pub(crate) fn validate_transactions_with_muhash_in_parallel<'a, V: UtxoView + Sync>(
   542	        &self,
   543	        txs: &'a Vec<Transaction>,
   544	        utxo_view: &V,
   545	        pov_daa_score: u64,
   546	        block_daa_score: u64,
   547	        flags: TxValidationFlags,
   548	        selected_parent: Hash,
   549	        pending_nullifiers: &HashSet<[u8; 32]>,
   550	        shielded_balance: &mut u64,
   551	    ) -> (SmallVec<[(ValidatedTransaction<'a>, u32); 2]>, MuHash) {
   552	        self.thread_pool.install(|| {
   553	            let mut validated: Vec<(ValidatedTransaction<'a>, u32)> = txs
   554	                .par_iter() // We can do this in parallel without complications since block body validation already ensured
   555	                            // that all txs within each block are independent
   556	                .enumerate()
   557	                .skip(1) // Skip the coinbase tx.
   558	                // Zethora: a private coin tag already spent earlier in this mergeset makes the transaction not accepted
   559	                .filter(|(_, tx)| !zethora_private::nullifiers(&tx.payload).iter().any(|nf| pending_nullifiers.contains(nf)))
   560	                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score, block_daa_score, flags, selected_parent).ok().map(|vtx| (vtx, i as u32)))
   561	                .collect();
   562	            // Zethora: the turnstile depends on order, so it runs sequentially in block order, before any effect
   563	            validated.sort_unstable_by_key(|(_, idx)| *idx);
   564	            validated.retain(|(vtx, _)| {
   565	                let accepted = zethora_supply::turnstile_accepts(shielded_balance, &vtx.tx.payload);
   566	                if !accepted {
   567	                    // Can't happen with sound private payments: worth a warning, it points at a counterfeit
   568	                    warn!("Zethora: transaction {} not accepted: it would take more out of the private pool than it holds", vtx.id());
   569	                }
   570	                accepted
   571	            });
   572	            let multiset = validated.par_iter().map(|(vtx, _)| MuHash::from_transaction(vtx, pov_daa_score)).reduce(MuHash::new, |mut a, b| {
   573	                a.combine(&b);
   574	                a
   575	            });
   576	            (SmallVec::from_vec(validated), multiset)
   577	        })
   578	    }
   579	
   580	    /// Attempts to populate the transaction with UTXO entries and performs all utxo-related tx validations
   581	    pub(super) fn validate_transaction_in_utxo_context<'a>(
   582	        &self,
   583	        transaction: &'a Transaction,
   584	        utxo_view: &impl UtxoView,
   585	        pov_daa_score: u64,
   586	        block_daa_score: u64,
   587	        flags: TxValidationFlags,
   588	        selected_parent: Hash,
   589	    ) -> TxResult<ValidatedTransaction<'a>> {
   590	        // Zethora: private payment rules that depend on the chain: no spent coin tag reused (§6.3), anchor matured (§6.2)
   591	        self.check_private_payment_in_context(transaction, selected_parent, &HashSet::new())?;
   592	        let mut entries = Vec::with_capacity(transaction.inputs.len());
   593	        for input in transaction.inputs.iter() {
   594	            if let Some(entry) = utxo_view.get(&input.previous_outpoint) {
   595	                entries.push(entry);
   596	            } else {
   597	                // Missing at least one input. For perf considerations, we report once a single miss is detected and avoid collecting all possible misses.
   598	                return Err(TxRuleError::MissingTxOutpoints);
   599	            }
   600	        }
   601	
   602	        let populated_tx = PopulatedTransaction::new(transaction, entries);
   603	
   604	        let seq_commit_accessor =
   605	            SeqCommitAccessor::new(selected_parent, &self.reachability_service, &self.headers_store, self.finality_depth);
   606	        let res = self.transaction_validator.validate_populated_transaction_and_get_fee(
   607	            &populated_tx,
   608	            pov_daa_score,
   609	            block_daa_score,
   610	            flags,
   611	            None,
   612	            Some(&seq_commit_accessor),
   613	        );
   614	        match res {
   615	            Ok(calculated_fee) => Ok(ValidatedTransaction::new(populated_tx, calculated_fee)),
---- lines 684-738 ----
   684	            mass_and_feerate_threshold,
   685	            Some(&seq_commit_accessor),
   686	        )?;
   687	        mutable_tx.calculated_fee = Some(calculated_fee);
   688	        Ok(())
   689	    }
   690	
   691	    // =========================================================================
   692	    // KIP-21: Sequencing commitment — shared helpers
   693	    // =========================================================================
   694	
   695	    /// Collect per-lane activity leaves and miner payload leaves from the mergeset.
   696	    pub(super) fn collect_mergeset_seq_data(&self, ctx: &UtxoProcessingContext) -> MergesetSeqData {
   697	        use kaspa_seq_commit::hashing::{activity_leaf, miner_payload_leaf};
   698	        use kaspa_seq_commit::types::MinerPayloadLeafInput;
   699	
   700	        let mut lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>> = std::collections::BTreeMap::new();
   701	        let mut miner_payload_leaves = Vec::new();
   702	        let mut global_merge_idx: u32 = 0;
   703	
   704	        for block_acceptance in ctx.mergeset_acceptance_data.iter() {
   705	            let merged_block = block_acceptance.block_hash;
   706	            let merged_header = self.headers_store.get_header(merged_block).unwrap();
   707	            let block_txs = self.block_transactions_store.get(merged_block).unwrap();
   708	
   709	            let coinbase_payload = &block_txs[0].payload;
   710	            let mpl = miner_payload_leaf(MinerPayloadLeafInput {
   711	                block_hash: &merged_block,
   712	                blue_work_be_bytes: &merged_header.blue_work.to_be_bytes(),
   713	                payload: coinbase_payload,
   714	            });
   715	            miner_payload_leaves.push(mpl);
   716	
   717	            for accepted_tx in block_acceptance.accepted_transactions.iter() {
   718	                let tx = &block_txs[accepted_tx.index_within_block as usize];
   719	                let lane_id: [u8; 20] = *tx.subnetwork_id.as_bytes();
   720	                let al = activity_leaf(&accepted_tx.transaction_id, tx.version, global_merge_idx);
   721	                lane_activities.entry(lane_id).or_default().push(al);
   722	                global_merge_idx += 1;
   723	            }
   724	        }
   725	
   726	        MergesetSeqData { lane_activities, miner_payload_leaves }
   727	    }
   728	
   729	    /// Resolve lane activities into concrete lane updates: look up existing tips
   730	    /// from DB at the current block's POV, compute new tips via `lane_tip_next`.
   731	    pub(super) fn resolve_lane_updates(
   732	        &self,
   733	        data: &MergesetSeqData,
   734	        context_hash: &Hash,
   735	        current_blue_score: u64,
   736	        parent_blue_score: u64,
   737	        selected_parent: Hash,
   738	        parent_seq_commit: Hash,
---- lines 861-917 ----
   861	            parent_seq_commit,
   862	        );
   863	        let (parent_lanes_root, parent_active_lanes) = self.get_parent_lanes_root_and_count(selected_parent, parent_header.blue_score);
   864	        let parent_state = ParentBlockSeqState {
   865	            seq_commit: parent_seq_commit,
   866	            blue_score: parent_header.blue_score,
   867	            lanes_root: parent_lanes_root,
   868	            active_lanes_count: parent_active_lanes,
   869	        };
   870	
   871	        let (hash, build) = self.build_seq_commit(
   872	            &parent_state,
   873	            context_hash,
   874	            current_blue_score,
   875	            &lane_updates,
   876	            data.miner_payload_leaves,
   877	            selected_parent,
   878	            inactivity_shortcut_block,
   879	            inactivity_shortcut,
   880	        );
   881	
   882	        Ok((hash, build))
   883	    }
   884	}
   885	
   886	/// Zethora: what the node says, in plain words, when a chain block's private payment record is missing from its
   887	/// database (F2 item 5). Every normal path writes these records together with the block's other state, and a pruning
   888	/// point sync downloads them before anything needs them, so this means a damaged database (or a bug). The node stops:
   889	/// a plain restart would hit the same missing record again, while --reset-db rebuilds the database from the network.
   890	pub(crate) fn missing_private_state_message(record: &str, block: Hash, error: &impl std::fmt::Display) -> String {
   891	    format!(
   892	        "Zethora node stopped: this node's private payment records are incomplete (the {record} of block {block} is \
   893	         missing: {error}). This usually means the node's database was damaged, for example by a disk problem or a \
   894	         crash while it was saving. Restarting alone will not fix it. To fix it, start the node again with --reset-db \
   895	         (add --yes to skip the question): it deletes this node's database and downloads the chain again. Your miner \
   896	         key file is not touched, and your coins are recorded on the chain, so they are back once the node has caught up."
   897	    )
   898	}
   899	
   900	#[cfg(test)]
   901	mod tests {
   902	    use itertools::Itertools;
   903	    use smallvec::smallvec;
   904	
   905	    use super::*;
   906	
   907	    #[test]
   908	    fn test_rayon_reduce_retains_order() {
   909	        // this is an independent test to replicate the behavior of
   910	        // validate_txs_in_parallel and validate_txs_with_muhash_in_parallel
   911	        // and assert that the order of data is retained when doing par_iter
   912	        let data: Vec<u16> = (1..=1000).collect();
   913	
   914	        let collected: Vec<u16> = data
   915	            .par_iter()
   916	            .filter_map(|a| {
   917	                let chance: f64 = rand::random();
---- lines 939-973 ----
   939	                Some(smallvec![*a])
   940	            })
   941	            .reduce(
   942	                || smallvec![],
   943	                |mut arr, mut curr_data| {
   944	                    arr.append(&mut curr_data);
   945	                    arr
   946	                },
   947	            );
   948	
   949	        println!("reduced len: {}", reduced.len());
   950	
   951	        reduced.iter().tuple_windows().for_each(|(prev, curr)| {
   952	            // Data was originally sorted, so we check if they remain sorted after filtering
   953	            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
   954	        });
   955	    }
   956	
   957	    #[test]
   958	    fn missing_private_state_message_is_plain_english() {
   959	        let block = kaspa_hashes::Hash::from_u64_word(7);
   960	        let message = super::missing_private_state_message("private coin list", block, &"key not found");
   961	        assert_eq!(
   962	            message,
   963	            format!(
   964	                "Zethora node stopped: this node's private payment records are incomplete (the private coin list of block \
   965	                 {block} is missing: key not found). This usually means the node's database was damaged, for example by a \
   966	                 disk problem or a crash while it was saving. Restarting alone will not fix it. To fix it, start the node \
   967	                 again with --reset-db (add --yes to skip the question): it deletes this node's database and downloads the \
   968	                 chain again. Your miner key file is not touched, and your coins are recorded on the chain, so they are \
   969	                 back once the node has caught up."
   970	            )
   971	        );
   972	    }
   973	}

======== EXCERPTS (zethora|subsidy|coinbase|cap_units|fee_pool|pool_state|ledger|issued|burn): consensus/core/src/config/params.rs ========
---- lines 22-72 ----
    22	// bytes for the entire block, so a larger signature script cannot be accepted anyway.
    23	// TODO: check whether this early signature-script length guard can be
    24	// removed entirely, or whether it remains useful as cheap early protection.
    25	const MAX_SIGNATURE_SCRIPT_LEN: usize = 250_000;
    26	
    27	#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    28	pub struct ForkActivation(u64);
    29	
    30	impl ForkActivation {
    31	    const NEVER: u64 = u64::MAX;
    32	    const ALWAYS: u64 = 0;
    33	
    34	    pub const fn new(daa_score: u64) -> Self {
    35	        Self(daa_score)
    36	    }
    37	
    38	    pub const fn never() -> Self {
    39	        Self(Self::NEVER)
    40	    }
    41	
    42	    pub const fn always() -> Self {
    43	        Self(Self::ALWAYS)
    44	    }
    45	
    46	    /// Returns the actual DAA score triggering the activation. Should be used only
    47	    /// for cases where the explicit value is required for computations (e.g., coinbase subsidy).
    48	    /// Otherwise, **activation checks should always go through `self.is_active(..)`**
    49	    pub fn daa_score(self) -> u64 {
    50	        self.0
    51	    }
    52	
    53	    pub fn is_active(self, current_daa_score: u64) -> bool {
    54	        current_daa_score >= self.0
    55	    }
    56	
    57	    pub fn delayed_by(self, daa_score_delta: u64) -> Self {
    58	        match self.0 {
    59	            Self::ALWAYS | Self::NEVER => self,
    60	            daa_score => Self(daa_score.saturating_add(daa_score_delta)),
    61	        }
    62	    }
    63	
    64	    pub fn early_by(self, daa_score_delta: u64) -> Self {
    65	        match self.0 {
    66	            Self::ALWAYS | Self::NEVER => self,
    67	            daa_score => Self(daa_score.saturating_sub(daa_score_delta)),
    68	        }
    69	    }
    70	
    71	    /// Checks if the fork was "recently" activated, i.e., in the time frame of the provided range.
    72	    /// This function returns false for forks that were always active, since they were never activated.
---- lines 165-462 ----
   165	    pub fn upper_bound(&self) -> T {
   166	        match self.activation.0 {
   167	            ForkActivation::NEVER => self.pre,
   168	            ForkActivation::ALWAYS => self.post,
   169	            _ => self.pre.max(self.post),
   170	        }
   171	    }
   172	}
   173	
   174	/// Blockrate-related consensus params.
   175	/// Grouped together under a single struct because they are logically related and
   176	/// in order to easily support **future BPS acceleration hardforks** (by simply adding
   177	/// a forked instance of blockrate params to the main [`Params`]).
   178	#[derive(Clone, Debug, Serialize, Deserialize)]
   179	#[serde(deny_unknown_fields)]
   180	pub struct BlockrateParams {
   181	    pub target_time_per_block: u64, // (milliseconds)
   182	    pub ghostdag_k: KType,
   183	    pub past_median_time_sample_rate: u64,
   184	    pub difficulty_sample_rate: u64,
   185	    pub max_block_parents: u8,
   186	    pub mergeset_size_limit: u64,
   187	    pub merge_depth: u64,
   188	    pub finality_depth: u64,
   189	    pub pruning_depth: u64,
   190	    pub coinbase_maturity: u64,
   191	}
   192	
   193	impl BlockrateParams {
   194	    pub const fn new<const BPS: u64>() -> Self {
   195	        Self {
   196	            target_time_per_block: Bps::<BPS>::target_time_per_block(),
   197	            ghostdag_k: Bps::<BPS>::ghostdag_k(),
   198	            past_median_time_sample_rate: Bps::<BPS>::past_median_time_sample_rate(),
   199	            difficulty_sample_rate: Bps::<BPS>::difficulty_adjustment_sample_rate(),
   200	            max_block_parents: Bps::<BPS>::max_block_parents(),
   201	            mergeset_size_limit: Bps::<BPS>::mergeset_size_limit(),
   202	            merge_depth: Bps::<BPS>::merge_depth_bound(),
   203	            finality_depth: Bps::<BPS>::finality_depth(),
   204	            pruning_depth: Bps::<BPS>::pruning_depth(),
   205	            coinbase_maturity: Bps::<BPS>::coinbase_maturity(),
   206	        }
   207	    }
   208	
   209	    pub const fn increase_max_block_parents(mut self, max_block_parents: u8) -> Self {
   210	        if self.max_block_parents < max_block_parents {
   211	            self.max_block_parents = max_block_parents;
   212	        }
   213	        self
   214	    }
   215	}
   216	
   217	#[derive(Clone, Debug, Serialize, Deserialize)]
   218	#[serde(deny_unknown_fields)]
   219	pub struct OverrideParams {
   220	    /// Timestamp deviation tolerance (in seconds)
   221	    pub timestamp_deviation_tolerance: Option<u64>,
   222	
   223	    /// Size of the sampled block window that is used to calculate the past median time of each block
   224	    pub past_median_time_window_size: Option<usize>,
   225	
   226	    /// Size of the sampled block window that is used to calculate the required difficulty of each block
   227	    pub difficulty_window_size: Option<usize>,
   228	
   229	    /// The minimum size a difficulty window (full or sampled) must have to trigger a DAA calculation
   230	    pub min_difficulty_window_size: Option<usize>,
   231	
   232	    pub coinbase_payload_script_public_key_max_len: Option<u8>,
   233	    pub max_coinbase_payload_len: Option<usize>,
   234	
   235	    pub max_tx_inputs: Option<usize>,
   236	    pub max_tx_outputs: Option<usize>,
   237	    pub max_signature_script_len: Option<usize>,
   238	    pub max_script_public_key_len: Option<usize>,
   239	    pub mass_per_tx_byte: Option<u64>,
   240	    pub mass_per_script_pub_key_byte: Option<u64>,
   241	    pub mass_per_sig_op: Option<u64>,
   242	    pub block_mass_limits: Option<BlockMassLimits>,
   243	    pub block_lane_limits: Option<BlockLaneLimits>,
   244	
   245	    /// The parameter for scaling inverse KAS value to mass units (KIP-0009)
   246	    pub storage_mass_parameter: Option<u64>,
   247	
   248	    /// DAA score after which the pre-deflationary period switches to the deflationary period
   249	    pub deflationary_phase_daa_score: Option<u64>,
   250	
   251	    pub pre_deflationary_phase_base_subsidy: Option<u64>,
   252	    pub skip_proof_of_work: Option<bool>,
   253	    pub max_block_level: Option<BlockLevel>,
   254	    pub pruning_proof_m: Option<u64>,
   255	
   256	    /// Blockrate-related params
   257	    pub blockrate: Option<BlockrateParams>,
   258	
   259	    /// Target time per block prior to the crescendo hardfork (in milliseconds)
   260	    pub pre_crescendo_target_time_per_block: Option<u64>,
   261	
   262	    /// Crescendo activation DAA score
   263	    pub crescendo_activation: Option<ForkActivation>,
   264	}
   265	
   266	impl From<Params> for OverrideParams {
   267	    fn from(p: Params) -> Self {
   268	        Self {
   269	            timestamp_deviation_tolerance: Some(p.timestamp_deviation_tolerance),
   270	            pre_crescendo_target_time_per_block: Some(p.pre_crescendo_target_time_per_block),
   271	            difficulty_window_size: Some(p.difficulty_window_size),
   272	            past_median_time_window_size: Some(p.past_median_time_window_size),
   273	            min_difficulty_window_size: Some(p.min_difficulty_window_size),
   274	            coinbase_payload_script_public_key_max_len: Some(p.coinbase_payload_script_public_key_max_len),
   275	            max_coinbase_payload_len: Some(p.max_coinbase_payload_len),
   276	            max_tx_inputs: Some(p.max_tx_inputs),
   277	            max_tx_outputs: Some(p.max_tx_outputs),
   278	            max_signature_script_len: Some(p.max_signature_script_len),
   279	            max_script_public_key_len: Some(p.max_script_public_key_len),
   280	            mass_per_tx_byte: Some(p.mass_per_tx_byte),
   281	            mass_per_script_pub_key_byte: Some(p.mass_per_script_pub_key_byte),
   282	            mass_per_sig_op: Some(p.mass_per_sig_op),
   283	            block_mass_limits: Some(p.block_mass_limits),
   284	            block_lane_limits: Some(p.block_lane_limits),
   285	            storage_mass_parameter: Some(p.storage_mass_parameter),
   286	            deflationary_phase_daa_score: Some(p.deflationary_phase_daa_score),
   287	            pre_deflationary_phase_base_subsidy: Some(p.pre_deflationary_phase_base_subsidy),
   288	            skip_proof_of_work: Some(p.skip_proof_of_work),
   289	            max_block_level: Some(p.max_block_level),
   290	            pruning_proof_m: Some(p.pruning_proof_m),
   291	            blockrate: Some(p.blockrate),
   292	            crescendo_activation: Some(p.crescendo_activation),
   293	        }
   294	    }
   295	}
   296	
   297	/// Consensus parameters. Contains settings and configurations which are consensus-sensitive.
   298	/// Changing one of these on a network node would exclude and prevent it from reaching consensus
   299	/// with the other unmodified nodes.
   300	#[derive(Clone, Debug)]
   301	pub struct Params {
   302	    pub dns_seeders: &'static [&'static str],
   303	    pub net: NetworkId,
   304	    pub genesis: GenesisBlock,
   305	
   306	    /// Timestamp deviation tolerance (in seconds)
   307	    pub timestamp_deviation_tolerance: u64,
   308	
   309	    /// Defines the highest allowed proof of work difficulty value for a block as a [`Uint256`]
   310	    pub max_difficulty_target: Uint256,
   311	
   312	    /// Highest allowed proof of work difficulty as a floating number
   313	    pub max_difficulty_target_f64: f64,
   314	
   315	    /// Size of the sampled block window that is used to calculate the past median time of each block
   316	    pub past_median_time_window_size: usize,
   317	
   318	    /// Size of the sampled block window that is used to calculate the required difficulty of each block
   319	    pub difficulty_window_size: usize,
   320	
   321	    /// The minimum size a difficulty window must have to trigger a DAA calculation
   322	    pub min_difficulty_window_size: usize,
   323	
   324	    pub coinbase_payload_script_public_key_max_len: u8,
   325	    pub max_coinbase_payload_len: usize,
   326	
   327	    pub max_tx_inputs: usize,
   328	    pub max_tx_outputs: usize,
   329	    pub max_signature_script_len: usize,
   330	    pub max_script_public_key_len: usize,
   331	
   332	    pub mass_per_tx_byte: u64,
   333	    pub mass_per_script_pub_key_byte: u64,
   334	    pub mass_per_sig_op: u64,
   335	    pub block_mass_limits: BlockMassLimits,
   336	    pub block_lane_limits: BlockLaneLimits,
   337	
   338	    /// The parameter for scaling inverse KAS value to mass units (KIP-0009)
   339	    pub storage_mass_parameter: u64,
   340	
   341	    /// DAA score after which the pre-deflationary period switches to the deflationary period
   342	    pub deflationary_phase_daa_score: u64,
   343	
   344	    pub pre_deflationary_phase_base_subsidy: u64,
   345	    pub skip_proof_of_work: bool,
   346	    pub max_block_level: BlockLevel,
   347	    pub pruning_proof_m: u64,
   348	
   349	    /// Zethora (ZTH-SPEC-006 §6.2): minimum blue score depth of a private coin list
   350	    /// snapshot before it can be spent. 600 on all real networks. Tests may override.
   351	    pub anchor_depth: u64,
   352	
   353	    /// Blockrate-related params
   354	    pub blockrate: BlockrateParams,
   355	
   356	    /// Target time per block prior to the crescendo hardfork (in milliseconds).
   357	    /// Required permanently in order to calculate the subsidy month from the current DAA score
   358	    pub pre_crescendo_target_time_per_block: u64,
   359	
   360	    /// Crescendo activation DAA score
   361	    pub crescendo_activation: ForkActivation,
   362	}
   363	
   364	impl Params {
   365	    /// Returns the past median time sample rate
   366	    #[inline]
   367	    #[must_use]
   368	    pub fn past_median_time_sample_rate(&self) -> u64 {
   369	        self.blockrate.past_median_time_sample_rate
   370	    }
   371	
   372	    /// Returns the difficulty sample rate
   373	    #[inline]
   374	    #[must_use]
   375	    pub fn difficulty_sample_rate(&self) -> u64 {
   376	        self.blockrate.difficulty_sample_rate
   377	    }
   378	
   379	    /// Returns the target time per block (milliseconds)
   380	    #[inline]
   381	    #[must_use]
   382	    pub fn target_time_per_block(&self) -> u64 {
   383	        self.blockrate.target_time_per_block
   384	    }
   385	
   386	    /// Returns the expected number of blocks per second
   387	    #[inline]
   388	    #[must_use]
   389	    pub fn bps(&self) -> u64 {
   390	        1000 / self.blockrate.target_time_per_block
   391	    }
   392	
   393	    /// Returns the expected number of blocks per second throughout history (currently represented as [`ForkedParam`]).
   394	    /// Required permanently in order to calculate the subsidy month from the current DAA score.
   395	    #[inline]
   396	    #[must_use]
   397	    pub fn bps_history(&self) -> ForkedParam<u64> {
   398	        ForkedParam::new(
   399	            1000 / self.pre_crescendo_target_time_per_block,
   400	            1000 / self.blockrate.target_time_per_block,
   401	            self.crescendo_activation,
   402	        )
   403	    }
   404	
   405	    /// Returns the cofactors for normalizing block mass dimensions.
   406	    #[inline]
   407	    #[must_use]
   408	    pub fn block_mass_cofactors(&self) -> MassCofactors {
   409	        self.block_mass_limits.cofactors()
   410	    }
   411	
   412	    pub fn ghostdag_k(&self) -> KType {
   413	        self.blockrate.ghostdag_k
   414	    }
   415	
   416	    pub fn max_block_parents(&self) -> u8 {
   417	        self.blockrate.max_block_parents
   418	    }
   419	
   420	    pub fn mergeset_size_limit(&self) -> u64 {
   421	        self.blockrate.mergeset_size_limit
   422	    }
   423	
   424	    pub fn merge_depth(&self) -> u64 {
   425	        self.blockrate.merge_depth
   426	    }
   427	
   428	    pub fn finality_depth(&self) -> u64 {
   429	        self.blockrate.finality_depth
   430	    }
   431	
   432	    pub fn pruning_depth(&self) -> u64 {
   433	        self.blockrate.pruning_depth
   434	    }
   435	
   436	    pub fn coinbase_maturity(&self) -> u64 {
   437	        self.blockrate.coinbase_maturity
   438	    }
   439	
   440	    pub fn finality_duration_in_milliseconds(&self) -> u64 {
   441	        self.blockrate.target_time_per_block * self.blockrate.finality_depth
   442	    }
   443	
   444	    pub fn difficulty_window_duration_in_block_units(&self) -> u64 {
   445	        self.blockrate.difficulty_sample_rate * self.difficulty_window_size as u64
   446	    }
   447	
   448	    pub fn expected_difficulty_window_duration_in_milliseconds(&self) -> u64 {
   449	        self.blockrate.target_time_per_block * self.blockrate.difficulty_sample_rate * self.difficulty_window_size as u64
   450	    }
   451	
   452	    /// Returns the depth at which the anticone of a chain block is final (i.e., is a permanently closed set).
   453	    /// Based on the analysis at <https://github.com/kaspanet/docs/blob/main/Reference/prunality/Prunality.pdf>
   454	    /// and on the decomposition of merge depth (rule R-I therein) from finality depth (φ)
   455	    pub fn anticone_finalization_depth(&self) -> u64 {
   456	        let anticone_finalization_depth = self.blockrate.finality_depth
   457	            + self.blockrate.merge_depth
   458	            + 4 * self.blockrate.mergeset_size_limit * self.blockrate.ghostdag_k as u64
   459	            + 2 * self.blockrate.ghostdag_k as u64
   460	            + 2;
   461	
   462	        // In mainnet it's guaranteed that `self.pruning_depth` is greater
---- lines 481-553 ----
   481	
   482	    pub fn default_p2p_port(&self) -> u16 {
   483	        self.net.default_p2p_port()
   484	    }
   485	
   486	    pub fn default_rpc_port(&self) -> u16 {
   487	        self.net.default_rpc_port()
   488	    }
   489	
   490	    pub fn override_params(self, overrides: OverrideParams) -> Self {
   491	        Self {
   492	            dns_seeders: self.dns_seeders,
   493	            net: self.net,
   494	            genesis: self.genesis.clone(),
   495	            anchor_depth: self.anchor_depth,
   496	
   497	            timestamp_deviation_tolerance: overrides.timestamp_deviation_tolerance.unwrap_or(self.timestamp_deviation_tolerance),
   498	
   499	            max_difficulty_target: self.max_difficulty_target,
   500	            max_difficulty_target_f64: self.max_difficulty_target_f64,
   501	
   502	            difficulty_window_size: overrides.difficulty_window_size.unwrap_or(self.difficulty_window_size),
   503	            past_median_time_window_size: overrides.past_median_time_window_size.unwrap_or(self.past_median_time_window_size),
   504	            min_difficulty_window_size: overrides.min_difficulty_window_size.unwrap_or(self.min_difficulty_window_size),
   505	
   506	            coinbase_payload_script_public_key_max_len: overrides
   507	                .coinbase_payload_script_public_key_max_len
   508	                .unwrap_or(self.coinbase_payload_script_public_key_max_len),
   509	
   510	            max_coinbase_payload_len: overrides.max_coinbase_payload_len.unwrap_or(self.max_coinbase_payload_len),
   511	
   512	            max_tx_inputs: overrides.max_tx_inputs.unwrap_or(self.max_tx_inputs),
   513	            max_tx_outputs: overrides.max_tx_outputs.unwrap_or(self.max_tx_outputs),
   514	            max_signature_script_len: overrides.max_signature_script_len.unwrap_or(self.max_signature_script_len),
   515	            max_script_public_key_len: overrides.max_script_public_key_len.unwrap_or(self.max_script_public_key_len),
   516	            mass_per_tx_byte: overrides.mass_per_tx_byte.unwrap_or(self.mass_per_tx_byte),
   517	            mass_per_script_pub_key_byte: overrides.mass_per_script_pub_key_byte.unwrap_or(self.mass_per_script_pub_key_byte),
   518	            mass_per_sig_op: overrides.mass_per_sig_op.unwrap_or(self.mass_per_sig_op),
   519	            block_mass_limits: overrides.block_mass_limits.unwrap_or(self.block_mass_limits),
   520	            block_lane_limits: overrides.block_lane_limits.unwrap_or(self.block_lane_limits),
   521	
   522	            storage_mass_parameter: overrides.storage_mass_parameter.unwrap_or(self.storage_mass_parameter),
   523	
   524	            deflationary_phase_daa_score: overrides.deflationary_phase_daa_score.unwrap_or(self.deflationary_phase_daa_score),
   525	
   526	            pre_deflationary_phase_base_subsidy: overrides
   527	                .pre_deflationary_phase_base_subsidy
   528	                .unwrap_or(self.pre_deflationary_phase_base_subsidy),
   529	
   530	            skip_proof_of_work: overrides.skip_proof_of_work.unwrap_or(self.skip_proof_of_work),
   531	
   532	            max_block_level: overrides.max_block_level.unwrap_or(self.max_block_level),
   533	
   534	            pruning_proof_m: overrides.pruning_proof_m.unwrap_or(self.pruning_proof_m),
   535	
   536	            blockrate: overrides.blockrate.clone().unwrap_or(self.blockrate.clone()),
   537	
   538	            pre_crescendo_target_time_per_block: overrides
   539	                .pre_crescendo_target_time_per_block
   540	                .unwrap_or(self.pre_crescendo_target_time_per_block),
   541	
   542	            crescendo_activation: overrides.crescendo_activation.unwrap_or(self.crescendo_activation),
   543	        }
   544	    }
   545	}
   546	
   547	impl Deref for Params {
   548	    type Target = BlockrateParams;
   549	
   550	    fn deref(&self) -> &Self::Target {
   551	        &self.blockrate
   552	    }
   553	}
---- lines 563-878 ----
   563	        match value {
   564	            NetworkType::Mainnet => MAINNET_PARAMS,
   565	            NetworkType::Testnet => TESTNET_PARAMS,
   566	            NetworkType::Devnet => DEVNET_PARAMS,
   567	            NetworkType::Simnet => SIMNET_PARAMS,
   568	        }
   569	    }
   570	}
   571	
   572	impl From<NetworkId> for Params {
   573	    fn from(value: NetworkId) -> Self {
   574	        match value.network_type {
   575	            NetworkType::Mainnet => MAINNET_PARAMS,
   576	            NetworkType::Testnet => match value.suffix {
   577	                Some(10) => TESTNET_PARAMS,
   578	                Some(x) => panic!("Testnet suffix {} is not supported", x),
   579	                None => panic!("Testnet suffix not provided"),
   580	            },
   581	            NetworkType::Devnet => DEVNET_PARAMS,
   582	            NetworkType::Simnet => SIMNET_PARAMS,
   583	        }
   584	    }
   585	}
   586	
   587	pub const MAINNET_PARAMS: Params = Params {
   588	    // Zethora seed nodes (hostnames or IPs answering on the default P2P port). Kaspa's seeders were removed: they
   589	    // point at Kaspa nodes, which a Zethora node can't talk to. Zethora's own seeds are added before mainnet launch.
   590	    dns_seeders: &[],
   591	    net: NetworkId::new(NetworkType::Mainnet),
   592	    genesis: GENESIS,
   593	    anchor_depth: 600,
   594	    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
   595	    max_difficulty_target: MAX_DIFFICULTY_TARGET,
   596	    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
   597	    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
   598	    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
   599	    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
   600	    coinbase_payload_script_public_key_max_len: 150,
   601	    max_coinbase_payload_len: 300, // Zethora: room for the supply ledger, coin list root and private state fingerprint
   602	
   603	    // Limit the cost of calculating compute/transient/storage masses
   604	    max_tx_inputs: 1000,
   605	    max_tx_outputs: 1000,
   606	    // Transient mass caps the entire block's transient footprint at 250KB, so no individual signature script can exceed it.
   607	    max_signature_script_len: MAX_SIGNATURE_SCRIPT_LEN,
   608	    // Retain a 10KB per-output guard; compute mass caps aggregate script-public-key bytes at roughly 45.5KB per block.
   609	    // Note that storage mass will kick in and gradually penalize also for lower lengths (generalized KIP-0009, plurality will be high).
   610	    max_script_public_key_len: 10_000,
   611	
   612	    mass_per_tx_byte: 1,
   613	    mass_per_script_pub_key_byte: 10,
   614	    mass_per_sig_op: 1000,
   615	    block_mass_limits: BlockMassLimits { compute: 500_000, storage: 500_000, transient: 1_000_000 },
   616	    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },
   617	
   618	    storage_mass_parameter: STORAGE_MASS_PARAMETER,
   619	
   620	    // deflationary_phase_daa_score is the DAA score after which the pre-deflationary period
   621	    // switches to the deflationary period. This number is calculated as follows:
   622	    // We define a year as 365.25 days
   623	    // Half a year in seconds = 365.25 / 2 * 24 * 60 * 60 = 15778800
   624	    // The network was down for three days shortly after launch
   625	    // Three days in seconds = 3 * 24 * 60 * 60 = 259200
   626	    deflationary_phase_daa_score: 15778800 - 259200,
   627	    pre_deflationary_phase_base_subsidy: 50000000000,
   628	    skip_proof_of_work: false,
   629	    max_block_level: 225,
   630	    pruning_proof_m: 1000,
   631	
   632	    blockrate: BlockrateParams::new::<1>(),
   633	
   634	    pre_crescendo_target_time_per_block: 1000,
   635	
   636	    // Roughly 2025-05-05 1500 UTC
   637	    crescendo_activation: ForkActivation::new(110_165_000),
   638	};
   639	
   640	pub const TESTNET_PARAMS: Params = Params {
   641	    // Zethora testnet seeds are added before the testnet launch (Kaspa's testnet seeders were removed).
   642	    dns_seeders: &[],
   643	    net: NetworkId::with_suffix(NetworkType::Testnet, 10),
   644	    genesis: TESTNET_GENESIS,
   645	    anchor_depth: 600,
   646	    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
   647	    max_difficulty_target: MAX_DIFFICULTY_TARGET,
   648	    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
   649	    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
   650	    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
   651	    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
   652	    coinbase_payload_script_public_key_max_len: 150,
   653	    max_coinbase_payload_len: 300, // Zethora: room for the supply ledger, coin list root and private state fingerprint
   654	
   655	    // Limit the cost of calculating compute/transient/storage masses
   656	    max_tx_inputs: 1000,
   657	    max_tx_outputs: 1000,
   658	    // Transient mass caps the entire block's transient footprint at 250KB, so no individual signature script can exceed it.
   659	    max_signature_script_len: MAX_SIGNATURE_SCRIPT_LEN,
   660	    // Retain a 10KB per-output guard; compute mass caps aggregate script-public-key bytes at roughly 45.5KB per block.
   661	    // Note that storage mass will kick in and gradually penalize also for lower lengths (generalized KIP-0009, plurality will be high).
   662	    max_script_public_key_len: 10_000,
   663	
   664	    mass_per_tx_byte: 1,
   665	    mass_per_script_pub_key_byte: 10,
   666	    mass_per_sig_op: 1000,
   667	    block_mass_limits: BlockMassLimits { compute: 500_000, storage: 500_000, transient: 1_000_000 },
   668	    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },
   669	
   670	    storage_mass_parameter: STORAGE_MASS_PARAMETER,
   671	    // deflationary_phase_daa_score is the DAA score after which the pre-deflationary period
   672	    // switches to the deflationary period. This number is calculated as follows:
   673	    // We define a year as 365.25 days
   674	    // Half a year in seconds = 365.25 / 2 * 24 * 60 * 60 = 15778800
   675	    // The network was down for three days shortly after launch
   676	    // Three days in seconds = 3 * 24 * 60 * 60 = 259200
   677	    deflationary_phase_daa_score: 15778800 - 259200,
   678	    pre_deflationary_phase_base_subsidy: 50000000000,
   679	    skip_proof_of_work: false,
   680	    max_block_level: 250,
   681	    pruning_proof_m: 1000,
   682	
   683	    blockrate: BlockrateParams::new::<1>(),
   684	
   685	    pre_crescendo_target_time_per_block: 1000,
   686	
   687	    // 18:30 UTC, March 6, 2025
   688	    crescendo_activation: ForkActivation::new(88_657_000),
   689	};
   690	
   691	pub const SIMNET_PARAMS: Params = Params {
   692	    dns_seeders: &[],
   693	    net: NetworkId::new(NetworkType::Simnet),
   694	    genesis: SIMNET_GENESIS,
   695	    anchor_depth: 600,
   696	    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
   697	    max_difficulty_target: MAX_DIFFICULTY_TARGET,
   698	    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
   699	    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
   700	    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
   701	    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
   702	
   703	    deflationary_phase_daa_score: TenBps::deflationary_phase_daa_score(),
   704	    pre_deflationary_phase_base_subsidy: TenBps::pre_deflationary_phase_base_subsidy(),
   705	    coinbase_payload_script_public_key_max_len: 150,
   706	    max_coinbase_payload_len: 300, // Zethora: room for the supply ledger, coin list root and private state fingerprint
   707	
   708	    max_tx_inputs: 1000,
   709	    max_tx_outputs: 1000,
   710	    max_signature_script_len: MAX_SIGNATURE_SCRIPT_LEN,
   711	    max_script_public_key_len: 10_000,
   712	
   713	    mass_per_tx_byte: 1,
   714	    mass_per_script_pub_key_byte: 10,
   715	    mass_per_sig_op: 1000,
   716	    // Transient mass is increased for stark proofs
   717	    block_mass_limits: BlockMassLimits { compute: 500_000, storage: 500_000, transient: 1_000_000 },
   718	    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },
   719	
   720	    storage_mass_parameter: STORAGE_MASS_PARAMETER,
   721	
   722	    skip_proof_of_work: true, // For simnet only, PoW can be simulated by default
   723	    max_block_level: 250,
   724	    pruning_proof_m: PRUNING_PROOF_M,
   725	
   726	    // For simnet, we deviate from default 10BPS configuration and allow at least 64 parents in order to support mempool benchmarks out of the box
   727	    blockrate: BlockrateParams::new::<10>().increase_max_block_parents(64),
   728	
   729	    pre_crescendo_target_time_per_block: TenBps::target_time_per_block(),
   730	
   731	    crescendo_activation: ForkActivation::always(),
   732	};
   733	
   734	pub const DEVNET_PARAMS: Params = Params {
   735	    dns_seeders: &[],
   736	    net: NetworkId::new(NetworkType::Devnet),
   737	    genesis: DEVNET_GENESIS,
   738	    anchor_depth: 600,
   739	    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
   740	    max_difficulty_target: MAX_DIFFICULTY_TARGET,
   741	    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
   742	    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
   743	    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
   744	    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
   745	    coinbase_payload_script_public_key_max_len: 150,
   746	    max_coinbase_payload_len: 300, // Zethora: room for the supply ledger, coin list root and private state fingerprint
   747	
   748	    max_tx_inputs: 1000,
   749	    max_tx_outputs: 1000,
   750	    max_signature_script_len: MAX_SIGNATURE_SCRIPT_LEN,
   751	    max_script_public_key_len: 10_000,
   752	
   753	    mass_per_tx_byte: 1,
   754	    mass_per_script_pub_key_byte: 10,
   755	    mass_per_sig_op: 1000,
   756	
   757	    // Transient mass is increased for stark proofs
   758	    block_mass_limits: BlockMassLimits { compute: 500_000, storage: 500_000, transient: 1_000_000 },
   759	    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },
   760	
   761	    storage_mass_parameter: STORAGE_MASS_PARAMETER,
   762	
   763	    deflationary_phase_daa_score: 0,
   764	    pre_deflationary_phase_base_subsidy: TenBps::pre_deflationary_phase_base_subsidy(),
   765	    skip_proof_of_work: false,
   766	    max_block_level: 250,
   767	    pruning_proof_m: 1000,
   768	
   769	    // Zethora: 1 block per second (ZTH-SPEC-005)
   770	    blockrate: BlockrateParams::new::<1>(),
   771	
   772	    pre_crescendo_target_time_per_block: Bps::<1>::target_time_per_block(),
   773	
   774	    crescendo_activation: ForkActivation::always(),
   775	};
   776	
   777	#[cfg(test)]
   778	mod tests {
   779	    use super::*;
   780	
   781	    #[test]
   782	    fn all_real_networks_use_anchor_depth_600() {
   783	        assert_eq!(MAINNET_PARAMS.anchor_depth, 600);
   784	        assert_eq!(TESTNET_PARAMS.anchor_depth, 600);
   785	        assert_eq!(SIMNET_PARAMS.anchor_depth, 600);
   786	        assert_eq!(DEVNET_PARAMS.anchor_depth, 600);
   787	    }
   788	
   789	    #[test]
   790	    fn mainnet_and_testnet_run_at_one_block_per_second_with_anchor_depth_600() {
   791	        // The reward divisor (zethora_subsidy::D) and the snapshot depth both assume 1 block per second
   792	        for params in [&MAINNET_PARAMS, &TESTNET_PARAMS] {
   793	            assert_eq!(params.blockrate.target_time_per_block, 1_000, "{}", params.net);
   794	            let one_bps = serde_json::to_value(BlockrateParams::new::<1>()).unwrap();
   795	            assert_eq!(serde_json::to_value(&params.blockrate).unwrap(), one_bps, "{}", params.net);
   796	            assert_eq!(params.anchor_depth, 600, "{}", params.net);
   797	        }
   798	        // Control: a 10 blocks/sec network is told apart
   799	        assert_ne!(
   800	            serde_json::to_value(BlockrateParams::new::<10>()).unwrap(),
   801	            serde_json::to_value(BlockrateParams::new::<1>()).unwrap()
   802	        );
   803	        assert_eq!(BlockrateParams::new::<10>().target_time_per_block, 100);
   804	    }
   805	
   806	    #[test]
   807	    fn override_params_cannot_change_anchor_depth() {
   808	        let err = serde_json::from_str::<OverrideParams>(r#"{"anchor_depth":10}"#).unwrap_err();
   809	        assert!(err.to_string().contains("unknown field `anchor_depth`"), "{err}");
   810	    }
   811	
   812	    #[test]
   813	    fn override_params_rejects_unknown_top_level_fields() {
   814	        let err = serde_json::from_str::<OverrideParams>(r#"{"toccata_activation":42}"#).unwrap_err();
   815	
   816	        assert!(err.to_string().contains("unknown field `toccata_activation`"), "{err}");
   817	    }
   818	
   819	    #[test]
   820	    fn override_params_rejects_unknown_nested_blockrate_fields() {
   821	        let err = serde_json::from_str::<OverrideParams>(
   822	            r#"{
   823	                "blockrate": {
   824	                    "target_time_per_block": 100,
   825	                    "ghostdag_k": 124,
   826	                    "past_median_time_sample_rate": 10,
   827	                    "difficulty_sample_rate": 2,
   828	                    "max_block_parents": 16,
   829	                    "mergeset_size_limit": 248,
   830	                    "merge_depth": 36000,
   831	                    "finality_depth": 432000,
   832	                    "pruning_depth": 1080000,
   833	                    "coinbase_maturity": 200,
   834	                    "unexpected": 1
   835	                }
   836	            }"#,
   837	        )
   838	        .unwrap_err();
   839	
   840	        assert!(err.to_string().contains("unknown field `unexpected`"), "{err}");
   841	    }
   842	
   843	    #[test]
   844	    fn override_params_rejects_unknown_nested_mass_limit_fields() {
   845	        let err = serde_json::from_str::<OverrideParams>(
   846	            r#"{
   847	                "block_mass_limits": {
   848	                    "storage": 500000,
   849	                    "compute": 500000,
   850	                    "transient": 500000,
   851	                    "unexpected": 1
   852	                }
   853	            }"#,
   854	        )
   855	        .unwrap_err();
   856	
   857	        assert!(err.to_string().contains("unknown field `unexpected`"), "{err}");
   858	    }
   859	
   860	    /// Zethora step 3c: devnet/fast-pruning.json (a devnet that prunes after about 1,300 blocks instead of ~30 hours, for
   861	    /// testing a second node joining from a pruning point) must load and keep the depths consistent.
   862	    #[test]
   863	    fn zethora_fast_pruning_devnet_file_is_valid() {
   864	        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devnet/fast-pruning.json");
   865	        let overrides: OverrideParams = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
   866	        let p = DEVNET_PARAMS.override_params(overrides);
   867	        let (pruning, finality, k) = (p.pruning_depth(), p.finality_depth(), p.ghostdag_k() as u64);
   868	        let m = pruning % finality;
   869	        assert!(k < m && m < finality - k, "pruning depth must not be a multiple of the finality depth (+- k)");
   870	        assert!(p.merge_depth() < finality);
   871	        assert!(p.difficulty_window_duration_in_block_units() < pruning, "difficulty window must fit above the pruning point");
   872	        assert!(p.past_median_time_window_size as u64 * p.past_median_time_sample_rate < pruning);
   873	        assert!(p.min_difficulty_window_size <= p.difficulty_window_size);
   874	        assert!(pruning > p.anchor_depth, "private coin snapshots must mature above the pruning point too");
   875	        assert_eq!(p.target_time_per_block, DEVNET_PARAMS.target_time_per_block, "same block rate as the normal devnet");
   876	        assert_eq!(p.genesis.hash, DEVNET_PARAMS.genesis.hash);
   877	    }
   878	}
