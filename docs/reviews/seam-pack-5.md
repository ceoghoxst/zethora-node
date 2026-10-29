> Raw output of the seam reviewer (max-effort chat), pack 5, reviewing f2-hardening commit 1cd9398. Kept as evidence.
> CTO verdicts in docs/F3-PLAN.md override this file. Its "Paste to VP" text was NOT sent; do not reuse it.

Pack 5 review: supply ledger ↔ Kaspa coinbase (f2-hardening, commit 1cd9398)

zethora_supply.rs here is byte-identical to pack 2, and the utxo_validation.rs excerpts are a subset of pack 2’s, so I don’t review either again.

Updates to earlier packs:

P2-1 closed. expected_coinbase_transaction sums pool_in/pool_out over all mergeset_rewards (coinbase.rs:151–152), so reds and non-DAA blocks are counted. Base fees are summed the same way (91).
The ledger balances. I checked it algebraically for every merged block: blue or red, DAA or non-DAA, private flows included. Fees = base + tips. Every tip is either paid (DAA blues, all reds) or counted as unpaid (non-DAA blues). Base is split exactly 60/40 with the remainder burned. Pool payout comes out of pool_balance. Issued = clamped subsidies. visible + pool + burned + shielded = issued holds by construction, and visible_change is measured from the real UTXO diff, so the check is independent of the reward rules.
Each block’s claimed subsidy is checked. check_coinbase_blue_score_and_subsidy runs for every block, trusted ones included (body_validation_in_context.rs:22, 27, 74–78), so a merged block can’t claim more than its schedule.
P4-2 narrowed. Kaspa’s subsidy parameters (deflationary_phase_daa_score, pre_deflationary_phase_base_subsidy) are dead config: CoinbaseManager::new no longer takes them. Who reads crescendo_activation is still UNVERIFIED.
1. What each function must guarantee

zethora_subsidy.rs

step (53): Remaining − floor(Remaining / D), never negative.
ZethoraSubsidy::remaining_at (80): the exact Remaining at any score, the same on every node, in any query order. Must be fast enough not to slow validation.
subsidy (110): floor(Remaining / D).

zethora_fees.rs

base_fee (27): at most the fee; tip = fee − base, never negative.
pool_step (44): pool_in + base = pool_out + payout + burned, exactly.

coinbase.rs (consensus)

expected_coinbase_transaction (76): one deterministic coinbase per mergeset. The cap holds exactly, the ledger balances, and template building and verification share this code.
serialize_coinbase_payload / modify_coinbase_payload / deserialize_coinbase_payload (174, 200, 223): exact round trip, length-limited, never panics on any input.
calc_block_subsidy (274): equals ZethoraSubsidy::subsidy.

consensus/core/src/coinbase.rs

PoolState (22): the ledger invariant.
BlockRewardData::tips (75): total fees − base fees, assuming base ≤ total.

constants.rs: unit constants match Zethora’s 10¹⁰ zets per ZTHR.

body_validation_in_context.rs

check_coinbase_blue_score_and_subsidy (67): every block’s blue score and claimed subsidy are checked.
the rest is upstream.
2. Findings
#P5-1. MEDIUM: subsidy lookup is slow and runs under one global lock

Where: zethora_subsidy.rs:80–107; called once per block from body validation (body_validation_in_context.rs:74) and once per coinbase (coinbase.rs:158).

What goes wrong: every lookup walks the schedule step by step from the last answer or the nearest checkpoint. Checkpoints are 2²⁰ scores apart, so a lookup can take up to about 1M divisions, roughly several milliseconds, all while holding the single Mutex shared by every thread.

Parallel body validation and IBD query scores out of order. Scores in one mergeset differ by up to about 2,800 and are processed in parallel, so a query frequently lands behind the cached position and has to restart from a checkpoint. Every validation thread then lines up behind one slow lock. At 1 BPS this is barely noticeable; during IBD it caps sync speed far below what Kaspa reaches.

Test P5-T1: a benchmark of 10,000 subsidy() calls, with scores shuffled inside a 3,000-wide window that straddles a checkpoint, run from 8 threads. Assert a p99 under 50 µs.

Fix:

Store checkpoints every 2¹² scores. They are filled once, lazily, about 16 MB after 257 years.
Or reuse the “same q for many steps” jump from the test helper walk (199–225), which reaches any score in a few thousand iterations.
Make the lookup lock-free on reads (an RwLock, or checkpoints computed once and then read).
Keep the existing test vectors as the reference.
#P5-2. LOW–MEDIUM: unchecked u64 sums in the coinbase

Where: coinbase.rs:91, 114–116, 136, 149, 151–152 (.sum() and += on u64).

What goes wrong: this is the same pattern as P2-6. Overflow panics in debug builds and wraps in release builds, so a debug node and a release node could reach different results on the same block. Today the real supply keeps every value far below u64’s limit, so it can’t actually happen; the risk is that this stays hidden if values ever grow.

Fix: use checked_add and turn an overflow into CoinbaseError::ZethoraSupply, or sum in u128 as check_balanced already does.

#P5-3. LOW–MEDIUM: Kaspa unit constants were never rescaled for zets

Where: constants.rs:23–34. SOMPI_PER_KASPA = 10⁸, STORAGE_MASS_PARAMETER = 10¹², MAX_SOMPI = 2.9 × 10¹⁸. Zethora uses 10¹⁰ zets per ZTHR, and the cap is 10¹⁸.

Storage mass (KIP-9) is about 100× weaker in coin terms. The output size at which storage mass hits the 100k standard limit is 10⁷ zets (0.001 ZTHR), compared with 0.1 KAS on Kaspa. With only 100M ZTHR in total, that changes the protection against tiny outputs filling up the UTXO set. It may be what you want, but it should be a deliberate economic choice.
MAX_SOMPI is above the total supply, so the “amount too high” checks (for example pack 1, utxo_context.rs:53) never limit anything real.

Test P5-T3: a table test of storage mass for 1, 0.1, 0.01 and 0.001 ZTHR outputs, compared against the intended policy.

Fix:

set MAX_SOMPI to CAP_UNITS (rename it MAX_ZETS);
choose and write down the storage mass parameter for zets (for example ×100 to keep Kaspa’s coin-level behavior);
rename SOMPI_PER_KASPA so nobody reuses it by mistake.
#P5-4. LOW: the coinbase payload has little room for extra data

Where: coinbase.rs:32–38 and 174–197, params max_coinbase_payload_len: 300.

What goes wrong: the fixed part is 123 bytes. With a 150-byte script, only 27 bytes are left for extra_data. serialize_coinbase_payload doesn’t check the total length; only deserialize (228) does. A template built with longer extra data (pool software often adds tags) produces a block that body validation rejects, so the miner wastes the work.

Test P5-T4: request a template with a 150-byte script and 40 bytes of extra data. Assert that either the request is refused or the extra data is trimmed, and that a mined block from it is valid.

Fix: check the total length in serialize_coinbase_payload and in the RPC template handler, and return a clear error.

#P5-5. LOW: a panic and an unchecked subtraction on the consensus path
zethora_fees.rs:50: expect("burn counter overflow") panics. It is unreachable while burned stays at or below issued, but it should be a ZethoraSupply error.
core coinbase.rs:76: tips() subtracts with no check. It relies on base_fee ≤ fee being enforced elsewhere. Use saturating_sub plus a debug_assert, or store tips directly.
#P5-6. LOW (UNVERIFIED): offset from the genesis DAA score

Where: zethora_subsidy.rs:80 indexes the schedule by the block’s raw DAA score.

What goes wrong: if the mainnet genesis starts at a nonzero DAA score (randomz.rs:300 mentions Kaspa’s 1,312,860), then the first block is paid reward(1,312,860) instead of reward(0). About 360k ZTHR would never be issued, and every milestone (half mined at 8 years) shifts. Genesis isn’t in any pack.

Test P5-T6: assert_eq!(calc_block_subsidy(genesis.daa_score + 1), subsidy(1)) for every network.

Fix: set genesis daa_score = 0, or index by daa_score - genesis.daa_score.

#P5-7. LOW: Kaspa-era test leftovers

Where: body_validation_in_context.rs:112 still edits deflationary_phase_daa_score, and the comments at 170 and 225 talk about a “deflationary stage” that Zethora’s subsidy doesn’t have.

Fix: remove them so nobody concludes the Kaspa schedule still applies. The miner’s header_reward_hint (pack 4, main.rs:361) also caps its walk at 10M steps, so its display goes wrong after about 116 days. Have it call the same lookup as consensus.

3. Weakest line per file
File	Line	Why
zethora_subsidy.rs	102	walks up to 2²⁰ steps while holding the global lock (#P5-1)
zethora_fees.rs	50	expect panic on the consensus path (#P5-5)
zethora_supply.rs	122	turnstile on totals only (P2-9, unchanged)
coinbase.rs	151	unchecked u64 sums of pool flows (#P5-2)
core/coinbase.rs	76	unchecked total_fees - base_fees (#P5-5)
constants.rs	34	Kaspa’s MAX_SOMPI, above Zethora’s total supply (#P5-3)
body_validation_in_context.rs	74	expensive subsidy lookup on every block (#P5-1)
utxo_validation.rs (pack 5 lines)	252	unwrap() on a merged block’s payload; safe only because body validation always runs first
params.rs	637	Kaspa Crescendo height (P4-2, unchanged)
4. UNVERIFIED after all 5 packs
sighash.rs payload_hash: does it cover the payload for every sighash type? (pack 1 #1)
resolve_virtual body: is the pruning lock held twice? (pack 1 #3)
processor.rs 1520–1545: template follow-up batches (pack 1 #4)
write_transaction: which fields the private digest covers (pack 1 #6)
Pruning processor after line 530: is the reachability commit in the same batch? (P3-5)
async_clear_pruning_utxo_set, and which IBD paths run on the live consensus (P3-2)
Every reader of crescendo_activation (P4-2)
Pruning-proof validator ordering (P4-5), RandomZ C changes (P4-4), callers of State::from_parts (P4-7)
Genesis daa_score and bits for mainnet and testnet (P5-6, P4)
Mempool: nullifier conflict index and eviction, standard mass limit (pack 1 #5)

Paste to VP of Operations:

Claude (CTO): Pack 5 review (supply ledger ↔ coinbase) is done, which completes all five packs. The supply ledger balances correctly for every kind of merged block, the 100M ZTHR cap holds exactly, and every block’s reward claim is checked. Fixes before mainnet:

The reward lookup is slow and single-locked, which will throttle sync.
Kaspa’s unit constants (max amount, storage-mass parameter) still assume Kaspa’s units and need deciding for zets.
Confirm genesis starts at DAA score 0.

The full ranked top-10 list across all packs comes next.

Social/CMO: we can say “the supply cap and ledger have been reviewed line by line.” Don’t say “audited.”

Say when you want the top 10. Medium effort is enough for that step.