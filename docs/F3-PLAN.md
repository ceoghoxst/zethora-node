# F3 plan: fix every seam-review finding

Written 2026-10-28 by Claude (CTO). This is the hand-off file for the next session. Read CLAUDE.md first, then this.

## Where this came from
A max-effort reviewer chat read the code where Zethora meets Kaspa, in 5 packs (f2-hardening commit 1cd9398).
The raw reviews are in docs/reviews/seam-pack-1.md to seam-pack-5.md. The CTO checked every claim against the code;
the verdicts below are the ones that count. CEO rule (Oct 28): **fix every finding, high or low. A finding that is
not a bug still gets a permanent test proving it.** Every security test follows the standing test rule
(positive control, exact assertions, shown failing with the protection removed).

## How the work is done
- Branch per PR, based on `zethora`. Never push to `zethora` directly; Deion merges after CTO review.
- The cloud sandbox can't reach crates.io: GitHub CI is the compiler. Push, read the CI log, fix, repeat.
  A full CI run takes ~1.5 h, so batch fixes and check the code by reading before each push.
- Consensus changes take effect from the public testnet genesis (T11 clarification). No devnet live network to split.
- If a fix changes stored state or block shape: say DEVNET RESET REQUIRED in the commit and CLAUDE.md.

## Status (2026-10-28 20:30 PT)
- F2 (PR #4) MERGED into zethora (7bd7d20).
- **F3a** (branch `f3a-seam-pack1`, commits a5de9b4 + d24c0a0): pack 1 items #1 #3 #4 #7 #10 #11 #12 #13 #15 #16.
  CI round 2 (run #63) was in progress. Next: if red, fix; if green, rebase/merge onto zethora, do the
  fail-when-removed proofs for each new test (record them in the PR description), open the PR, CTO review.

## Status update (2026-10-28 21:00 PT)
- F3a run #63 red on one test (template batch test built its over-pool payment through the mempool, which F2 now
  refuses). Fixed; zethora merged in; CI now runs with --no-fail-fast (one run shows every failure). Run #71 pending.
- The cloud sandbox CAN now download crates: compile and run the affected tests locally before every push.
- F3e branch `f3e-pow-dos` (stacked on F3a): P4-1 done in code (difficulty/DAA checked before RandomZ for headers with
  known parents; strikes for unearned PoW in relay, IBD and orphan revalidation; per-IP orphan budget = 2x the block rate per 10 min, 1,200 at 1 bps; over it the peer is disconnected, not banned).
- P5-3 table + recommendation (C = 10^13): docs/decisions/P5-3-storage-mass.md. Waiting for the CEO/VP decision.

## Status update (2026-10-29)
- F3a (PR #7), F3e (PR #8) and P4-4 (PR #9) MERGED. zethora CI green after the merges (Tests #80, #81, #84).
- F3c (branch `f3c-sync-robustness`): all pack 3 items and pack 1 #2 #8 #9 done in code and tested locally, with
  fail-when-removed proofs (PR description). Next: F3f, then F3d, then F3b.

## Status update (2026-10-29 PT, CTO session)
- F3a (PR #7), F3e (PR #8), P4-4 (PR #9) merged. F3c = PR #10 MERGED (552bd06). Website PR #11 MERGED.
- P5-3 DECIDED: C = 10^13 (CEO + VP, Oct 29); recorded in docs/decisions/P5-3-storage-mass.md.
- F3f + F3d batched into ONE PR (branch `f3f-f3d-supply-dag`, VP: one merge in the morning).
- Website copy: PR #11 (GitHub Pages, `site/`).

## VP notes (2026-10-28, approved breakdown)
- Batch CI so Deion merges PRs at most once a day. No messages at night (3 AM).
- P5-3 table and recommendation due this week, before F3f.
- P4-4 cross-platform RandomZ hash check (Linux x86_64, Windows, ARM must agree) is HIGH PRIORITY for the release.

## Verdicts and assignments

### Pack 1: Orchard and Kaspa transactions
| # | Verdict | PR |
|---|---|---|
| 1 payload swap on shielding | Not a bug: sighash always commits payload_hash (sighash.rs:277). Proof test added | F3a done |
| 2 proof checks amplified for free | Real (CPU DoS). Proof-result cache keyed by tx id + cheap checks before proof | F3c |
| 3 nested pruning-lock deadlock | Not a bug: RfRwLock is readers-first. Proof test added | F3a done |
| 4 template follow-up batches skip tag check | Not a bug. Proof test added (BatchedSelector) | F3a done |
| 5 no per-proof base mass; mempool vs consensus | Partly real. Add per-proof base mass (benchmark first, use the item 16 speed numbers) | F3b |
| 6 private digest domain / coverage | Real. Separate domain + bind network/genesis | F3b |
| 7 expect on consensus path | Real. VerifyError::Commitment, plain reject, no ban | F3a done |
| 8 private-state import not atomic | Real. Import-in-progress marker + wipe on startup (with P3-2) | F3c |
| 9 bans turn a version mismatch into a partition | Real. Version-gated strikes, not instant bans | F3c |
| 10 mempool batch turnstile not cumulative | Real. cumulative_mempool_turnstile | F3a done |
| 11 precheck work when spends are off | Real. Skip precheck | F3a done |
| 12 coinbase payload could look like "ZSHP" | Real. private_payload() returns empty for coinbase | F3a done |
| 13 nullifiers() drops unreadable actions | Real. All-or-nothing | F3a done |
| 14 kill switch is a static network type | Real. Goes with the testnet privacy switch (activation by DAA score, testnet only, mainnet refuses) | privacy-switch PR |
| 15 wrong argument in TooManyOutputs | Real (upstream). Fixed | F3a done |
| 16 attempts map unbounded | Real. Capped map + window fix | F3a done |

### Pack 2: Orchard and the BlockDAG
| # | Verdict | PR |
|---|---|---|
| P2-1 red / non-DAA pool flows | Not a bug: coinbase sums all mergeset_rewards (coinbase.rs:151-152). Add test with a red block carrying a shield | F3d |
| P2-2 full note tree halts the network (expect) | Real. Make "tree full" an acceptance rule (tx not accepted), not a panic | F3d |
| P2-3 reachability vs record rewrite at pruning | Not a bug: same WriteBatch (pruning processor.rs:479-571). Add test | F3d |
| P2-4 iter_all returns all records | Mostly covered by the ancestor filter. Add mixed-snapshot test | F3d |
| P2-5 old virtual-state rows convert to genesis private state | Real. Bump POST_TOCCATA_VIRTUAL_STATE_VERSION; recompute virtual before serving templates; remove misleading Default | F3d |
| P2-6 unchecked u64 sums in accept loop | Real (unreachable today). checked_add / u128 | F3d |
| P2-7 anchor depth reference point | Consistent but spec wording wrong. Fix wording + 599/600/601 boundary test | F3d |
| P2-8 inclusive chain-ancestor check | Not a bug (interval contains). Add test from the review (P2-T5) | F3d |
| P2-9 ledger turnstile only on totals | Correct (accept loop enforces per tx). Add hidden-negative test | F3d |
| P2-10 anchor store keeps first FOR_GOOD score | Real, low. Keep the minimum blue score | F3d |
| misleading expect messages | Rewrite in plain English | F3d |

### Pack 3: Orchard, pruning and sync
| # | Verdict | PR |
|---|---|---|
| P3-1 private-state server rebuilds on every request | Real cost (the "writer starvation" claim is wrong: readers-first lock). Cache per pruning point + per-peer rate limit | F3c |
| P3-2 failed/retried import leaves stale records | Real: clear_pruning_utxo_set (consensus/mod.rs:1732) clears only the UTXO set. Clear the Zethora stores too + import marker (with #8). Careful: those stores also hold records above P | F3c |
| P3-3 no size cap on download | Real. Cap counts, check while streaming | F3c |
| P3-4 no strike for a bad snapshot | Real. Strike + cooldown (with #9) | F3c |
| P3-5 reachability deletion batch | Not a bug (one batch). Test + clear error instead of unwrap at processor.rs:483 | F3c |
| P3-6 mid-pruning reader sees a mix | Low. Document + debug_assert | F3c |
| P3-7 note_tree bytes not length-checked early | Real, low. Refuse > 1,066 bytes up front | F3c |
| P3-8 Default on a consensus type | Real, low. Remove it | F3c |

### Pack 4: RandomZ and mining
| # | Verdict | PR |
|---|---|---|
| P4-1 invalid-PoW headers cheap to send, slow to check | Real, biggest item. Reject bits far easier than current difficulty BEFORE PoW; strikes for InvalidPoW / epoch out of range; rate-limit block requests per peer | F3e |
| P4-2 Kaspa Crescendo heights on mainnet/testnet | Leftover, not live: crescendo_activation is only read by bps_history(), which nothing calls. Set always() on all networks + test | F3e |
| P4-3 randomx-rs writes through an immutable buffer; null VM unchecked | Real (randomz/src/lib.rs:379, 422-423, 457-480). `let mut arr` + as_mut_ptr; Err on null VM; test | F3e |
| P4-4 no cross-platform hash check | Real gap. CI matrix: x86_64 Linux, Windows, aarch64 Linux (macOS if runners allow); same vectors, epochs 0/1/1000, light/fast/JIT/interpreter | own workflow PR |
| P4-5 pruning proof builds every epoch before checking | Real (pruning_proof/validate.rs:123). Check deciding headers first, stop at first failure; strike invalid-PoW proofs; size workers by memory | F3e |
| P4-6 wasm build uses kHeavyHash | Real, low. Refuse on wasm32 | F3e |
| P4-7 State::from_parts epoch 0 | Not a bug: no callers. Make it #[cfg(test)] | F3e |
| P4-8 epoch-change stall, cache wipes | Real, low. Prebuild next epoch's light setup; separate memo for proofs; document 4 GB RAM minimum | F3e |
| P4-9 epoch range grows if pruning lags | Real, low. Cap range around the tip | F3e |
| P4-10 miner key file perms, slice panic, stale chain | Real, low. Owner-only file, parse errors, refuse to mine unsynced on testnet/mainnet | F3e |
| P4-11 no mainnet seeders | Launch item (testnet first) | launch |
| extra | --override-params-file already refused on mainnet (daemon.rs:313); on testnet it only affects that node | none |

### Pack 5: supply ledger and coinbase
| # | Verdict | PR |
|---|---|---|
| ledger / cap / subsidy claims | Reviewer confirms all balance; P2-1 closed | none |
| P5-1 subsidy lookup slow, one global Mutex | Real (zethora_subsidy.rs:80-107: up to 2^20 steps under the lock). Dense checkpoints computed once + lock-free reads, or the jump walk; keep vectors; benchmark | F3f |
| P5-2 unchecked u64 sums in coinbase | Real (unreachable today). checked/u128 -> CoinbaseError | F3f |
| P5-3 Kaspa unit constants | Real. MAX_SOMPI -> CAP_UNITS; rename SOMPI_PER_KASPA; storage mass parameter for zets = CTO decision with a written table (1 / 0.1 / 0.01 / 0.001 ZTHR outputs) before choosing | F3f |
| P5-4 coinbase payload length not checked when building | Real. Check in serialize + template RPC, clear error | F3f |
| P5-5 expect in zethora_fees.rs:50; unchecked tips() | Real, low. Error instead of panic; saturating_sub + debug_assert | F3f |
| P5-6 genesis DAA score offset | Not a bug: all four genesis daa_score = 0 (genesis.rs). Add test per network | F3f |
| P5-7 Kaspa-era test leftovers; miner reward hint walk cap | Real, low. Remove; miner uses consensus lookup | F3f |

## PR order
1. F3a (in CI). 2. F3e (P4-1 first: biggest DoS) and P4-4 workflow. 3. F3c (sync robustness). 4. F3f. 5. F3d. 6. F3b.
Then: final ranked top 10 for the VP (only when a whole section is done), privacy-switch PR (#14 + option B).
