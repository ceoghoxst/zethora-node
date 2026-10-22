# CEO Briefing - October 22, 2026

This document is for the CEO to understand what has been built, verified, and
what remains. No code needed to read this. Every claim below is backed by a
test, a commit, or a file reference that the Lead Engineer and CTO verified.

---

## TL;DR

Three things you need to know:

1. **The privacy layer works and is tested.** The parallel nullifier defense
   (what the Reddit reviewer asked about) is proven correct by a regression
   test. Four layers of defense. The property test is green.

2. **The integration test suite is green.** 43 tests pass, 5 are Windows-only
   ignores due to a Windows stack overflow bug (not our code - they run on
   Linux). Consensus integration, difficulty adjustment, median time, and
   UTXO propagation all pass.

3. **The seed node is hardened and live.** systemd service, non-root user,
   survives reboot. Blocks are flowing from the PC to the seed every 1-2
   seconds. The disconnect loop that plagued us for hours is gone.

---

## What Was Done This Session

### 1. Parallel Nullifier Defense Regression Test (Task 4)

**What it is:**
A test that proves two parallel blocks in the DAG cannot spend the same
private coin (called a "nullifier"). This is what the Reddit reviewer asked
about. Before this test existed, we believed the defense was correct. After
this test exists, we know it is correct and cannot silently break.

**Why it matters:**
Without this, a hostile actor could theoretically spend the same shielded
coin twice in two simultaneous blocks, breaking the privacy layer and
potentially the supply cap. Now we have a test that fails if the defense
ever regresses.

**How we verified it:**
- A property test at `consensus/src/pipeline/tests/zethora_parallel_nullifier.rs`
  directly calls the nullifier check and proves it rejects duplicates.
- We broke the code on purpose to show the test can fail. Then restored it
  and showed it passes.
- Merged commit: `692c50bd`.

### 2. Pruning Point Panic Fix - Reverted Because It Was Dangerous

**What it is:**
A change that made the node return an error when private state is missing,
instead of crashing. On its own, that sounds good.

**Why we reverted it:**
The callers of the function ignored the error. That meant a node missing
private state would keep running with empty state, compute the wrong
fingerprint, and reject valid blocks. Silent consensus fork. Worse than the
original crash.

**Lesson learned:**
"Panic bad, error good" is not always true. In consensus code, stopping the
node is sometimes the safest failure mode. The old panic is back (restart
with --reset-db). Documented in commit `50eae7a1`.

### 3. Autoshield Bug Fixes - Verified Live on Devnet

**What it was:**
Three real bugs in the wallet's auto-shield feature:
- It set the change output to zero, which the consensus rules reject.
- It summed all coins' amounts but only spent one, producing an invalid tx.
- It retried the same rejected tx every 10 seconds, forever.

**Why it mattered:**
The feature had been silently broken since day one. Any user with 2+ mature
coins would see "auto-shield active" and never actually shield anything.

**How we verified it:**
Live devnet test. Ran the binary. Watched it shield 7 coins in a row with
zero errors. Merged commit `45b3193d`.

### 4. ZTH-SPEC-006 Privacy Spec - Recovered from Code Citations

**What it is:**
The privacy layer spec. It existed as ~80 citations across the codebase
(every file referenced "§6.3" or "§7.2" as if the document existed) but the
document itself had never been written.

**Why it mattered:**
Any serious reviewer (Zcash community, ZK cryptographer, auditor) will ask
for the spec. We now have one that matches the code and honestly lists its
own gaps (Appendix C, 9 open questions).

**How we verified it:**
Every claim in the spec cites a file:line in the code. Where the code
proves something, the spec says so. Where it does not, the spec says TBD.

### 5. Genesis Regeneration for Mainnet and Testnet

**What it is:**
Both networks' genesis blocks were Kaspa's genesis blocks. That means any
node trying to join Zethora mainnet would actually be on Kaspa's mainnet.
Fixed by regenerating both genesis blocks with Zethora's coinbase format.

**Why it mattered:**
Without this, Zethora was not a separate chain. It was Kaspa with a
different name.

**How we verified it:**
- Recomputed the hash from header fields using the consensus hashing code.
  Recomputed values matched committed values exactly.
- Fair launch confirmed: genesis subsidy is 0, all supply ledger fields are 0,
  utxo_commitment is the empty-set hash. No premine.
- All four networks have unique genesis hashes.
- Cross-checked against the Kaspa upstream repo: the pre-regeneration hashes
  matched Kaspa's published genesis hashes byte for byte.

### 6. Simnet Genesis Fix - Was Secretly Broken

**What it is:**
Simnet (the network all integration tests run on) had a 32-byte Kaspa
coinbase payload instead of the Zethora format. Tests were failing with
"PayloadLenBelowMin(32, 123)" because the node cannot deserialize Kaspa's
format.

**Why it mattered:**
This blocked ALL integration tests from running. It was invisible because
the simnet genesis was never regenerated during the mainnet/testnet work.

**How we verified it:**
Fixed the payload to 169 bytes (Zethora format), regenerated the hash,
integration tests went green. Committed in `efe54de2`.

### 7. Integration Test Reward Math - The N-2 Offset

**What it is:**
The integration test `daemon_utxos_propagation_test` had been asserting that
miners earn Kaspa's 500 KAS per block. Zethora pays 2.745 ZTHR per block
(smooth decay). The test was wrong; the node was correct.

**Why it mattered:**
This test was blocking the suite. Until it passed, we could not run any
integration tests.

**The tricky part:**
The test had to prove the exact reward amounts, not just that "rewards exist."
We discovered through diagnostic output that a block's coinbase pays for the
block merged N-2 levels back (earned at DAA N, paid at DAA N-1, accepted at
DAA N+1). The test now uses a multiset comparison: exact set of expected
rewards matched against actual set.

**How we verified it:**
We broke the test on purpose by shifting the expected range by one step, showed
it fails, then restored it and showed it passes. This is the "Rule 4" proof
that the test catches real regressions.

### 8. Dead Kaspa Emission Code Removed from coinbase.rs

**What it is:**
100+ lines of dead Kaspa emission code (halving schedule, subsidy-by-month
table, legacy functions) removed from the coinbase manager. It was never
called; Zethora uses its own smooth-decay schedule.

**Why it mattered:**
Less code to audit. Cleaner. The dead code was a liability - auditors
asking "why is this here?" now see it gone.

**How we verified it:**
- `cargo build` clean, 107 consensus tests pass.
- `git grep` across the whole repo showed no live callers of the removed
  functions.

### 9. Test Suite Re-enabled at 1 BPS

**What it is:**
Two consensus tests (`median_time_test`, `difficulty_test`) had been disabled
because they were written for Kaspa's 10 BPS. They pass at 1 BPS now. Five
goref tests are Windows-only ignores (they crash Windows with a stack
overflow - inherited from Kaspa, not our bug).

**Why it mattered:**
These are the tests that check the difficulty adjustment algorithm. Without
them, we would not catch a regression in mining difficulty.

**How we verified it:**
Attempted to run them at 64MB stack on Windows. Still crashed at the OS level.
Confirmed the crash is Windows-specific. On Linux (Hetzner) they run. The
`#[cfg_attr(windows, ignore = "...")]` syntax keeps them enabled for CI.

### 10. Mojibake Fixes in Comment Strings

**What it is:**
Three files had garbled characters (§ became `Â§`, — became `â€`, etc.)
from earlier PowerShell edits. Fixed with ASCII-only replacements.

**Why it mattered:**
Cosmetic on the surface, but it signals carelessness to reviewers reading
the code. Fixed.

**How we verified it:**
- `git diff` showed only comment text changed (not code).
- `cargo check` on all three affected crates passed.

### 11. Seed Server Hardening

**What it is:**
The Hetzner seed node was running as root, no service manager, no
auto-restart. Now:
- systemd service `zethora-seed`
- `Restart=always` (survives reboot)
- non-root user `zethora`
- proper flags including `--nodnsseed` (no self-connection loop)

**Why it mattered:**
A root process facing the internet is a security risk. A node that does not
auto-restart is a reliability risk. Both fixed.

**How we verified it:**
- Confirmed blocks flowing from PC to seed every 1-2 seconds.
- Confirmed service survives reboot (verified after kernel update to
  6.8.0-147).
- All updates documented in CLAUDE.md.

### 12. DAA Parameter Analysis (For Farm Question)

**What it is:**
A read-only analysis of how fast mining difficulty adjusts when hashrate
floods in. Relevant to the "are farms a problem" question.

**Key finding:**
The DAA window is 2641 blocks. At 1 BPS, a farm adding 10x hashrate is
fully absorbed in about 4 minutes of wall-clock time. The farm captures
roughly 2.75x its fair share during those 4 minutes. Not "wins forever."

**One flag:**
During the first ~600 blocks (10 minutes) of a fresh chain, the DAA window
is only 150 samples (much shorter). Farms could theoretically target
genesis. This is inherited from Kaspa, not a Zethora change. Worth knowing
for testnet.

---

## Strategy Decisions Recorded

### Pools
- **Decision:** Documentation only for now.
- **What this means:** No official Zethora pool. We document how to solo
  mine and how a third party could use the existing stratum bridge. Third
  party pools welcome after testnet.
- **Why:** Running a pool is a full-time operational commitment. We are
  focused on the core protocol.

### Farm Detection
- **Decision:** Post-testnet.
- **What this means:** No anti-farm feature exists. No design decided. Do
  not claim we detect or block farms publicly. Ever. It is now on the
  CLAUDE.md do-not-claim list.
- **Why:** Any consensus-level anti-farm change would break fair launch. Any
  network-level anti-farm change is undecided and untested.

### Passive Income Positioning
- **Decision:** Zethora does not promise passive income. Ever.
- **Honest position:** Mining is a business, not an investment. Early miners
  take operational risk and earn a larger share of the emission curve in
  exchange. Do not claim "set and forget," "guaranteed returns," or
  "passive income."
- **Why:** Mining requires hardware, electricity, uptime, and management. It
  is never passive. Promising otherwise would be a lie that would damage
  credibility with the audience that matters (developers, ZK researchers,
  home miners).

---

## What Is Still Open

### Before testnet opens:

1. **External audit of the Orchard integration.** This is the gate on
   enabling private sends on testnet/mainnet. We are actively looking for
   a ZK cryptographer. The Reddit reviewer is a candidate. The Zcash
   Community Grants (ZCG) program is a funding path.
2. **Seed node redundancy.** One seed (Hetzner) is a single point of
   failure. Second seed recommended before testnet.
3. **README rewrite.** Current README needs updating to reflect the honest
   positioning (operational risk premium, not passive income).
4. **Testnet dry run.** Enabling `spends_enabled` on devnet, running the
   full privacy flow end-to-end (shield -> wait 600 blocks -> spend ->
   verify).

### Post-testnet:

1. Farm detection (undecided design).
2. Full 601-block integration test for parallel nullifier (currently
   scaffolded and `#[ignore]`'d).
3. ZTH-SPEC-008 (fee pool spec) consolidation from code citations.
4. Address minor cleanup items (unused struct fields in coinbase.rs).

### Known risks:

1. **Anchor reorg behavior.** Spec marks this partially covered. Not
   covered by integration test.
2. **Fingerprint MuHash element collision.** Spec flags for auditor review.
3. **`ANCHOR_DEPTH = 600` at 1 BPS.** Currently 600 blocks = 10 minutes. If
   block rate increases, this needs scaling.

---

## Glossary (Plain English)

- **DAG / BlockDAG:** A blockchain structure where blocks can be created
  in parallel instead of one at a time. Think of it as a tree of blocks
  merging back together, not a chain.
- **GHOSTDAG:** The specific DAG algorithm Zethora inherits from Kaspa. It
  decides which parallel blocks "win" when they conflict.
- **Nullifier:** A one-time tag that reveals a private coin was spent,
  without revealing which coin.
- **Orchard:** Zcash's privacy protocol. Zethora uses it unmodified.
- **Anchor:** A snapshot of the private coin list at a specific moment.
  Private spends reference an anchor to prove the coin existed.
- **Turnstile:** The mechanism that ensures every coin that enters the
  private pool also eventually leaves it. Prevents supply inflation.
- **BlockDAG ordering:** When parallel blocks exist, GHOSTDAG orders them
  deterministically. This is what makes the "two blocks spend the same
  coin" defense work.
- **DAA (Difficulty Adjustment Algorithm):** Automatically adjusts how
  hard it is to mine a block. When more miners join, difficulty goes up.
  When miners leave, it goes down.
- **Mojibake:** Garbled text caused by wrong character encoding. Example:
  `§` shown as `Â§`.

---

## Where To Find Things

- **Privacy spec:** `docs/ZTH-SPEC-006.md`
- **Parallel nullifier test:** `consensus/src/pipeline/tests/zethora_parallel_nullifier.rs`
- **Anchor reorg test:** `consensus/src/pipeline/tests/zethora_anchor_reorg.rs`
- **Integration tests:** `testing/integration/src/consensus_integration_tests.rs`
- **Autoshield wallet:** `zethora-shield/src/main.rs`
- **Genesis blocks:** `consensus/core/src/config/genesis.rs`
- **Network params:** `consensus/core/src/config/params.rs`
- **Project notes (for Claude/CTO):** `CLAUDE.md`

---

## How We Verify Everything (The Standard)

For every change:
1. **Read the code first.** No guessing from names or log messages.
2. **Show `git diff`.** Real output, not summaries.
3. **Build and test.** Show the actual test results.
4. **Break the test on purpose** (Rule 4). Show it fails when it should.
5. **Verify with a second pair of eyes.** The CTO reviews every consensus
   change before commit.

If any step is skipped, the change is not done.

---

*Generated October 22, 2026. Next briefing after the next significant batch
of work.*
