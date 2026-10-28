# F2 task: pre-testnet hardening from red-team Round 1 (Claude Code cloud session)

Read CLAUDE.md first (test discipline / Rule 4, git rules, T11 rule) and
docs/THREAT-MODEL.md. F1 (per-tx turnstile) is merged; build on zethora.
Round 1 red team (6 AI attackers) found no exploit; these items harden what
they flagged. Do them in this order; each item gets its own commit.

## A. Consensus-adjacent (careful, tests first)
1. **One source of truth for private-payment byte layout (TOP PRIORITY).**
   consensus/core/src/zethora_private.rs reads nullifiers, value_balance and
   the anchor at hand-copied offsets; zethora-shielded/src/codec.rs encodes and
   decodes the same layout separately. Export the offsets (e.g.
   NULLIFIER_OFFSET, VALUE_BALANCE_OFFSET, ANCHOR_OFFSET, ACTION_SIZE) from one
   place and use them in both. Add a test that builds REAL payments with 1, 2
   and 16 actions, decodes them with the codec, and asserts
   nullifiers()/value_balance()/spend_anchor()/action_count() equal the
   decoded bundle's values exactly. Fail-when-removed: shift one offset by 1
   and show the test fails.
2. **Cap clamp instead of chain halt (CEO decision 2026-10-28).** Today a
   block whose coinbase would push total issued above CAP_UNITS is invalid
   (zethora_supply ledger_step CapExceeded), which could stall the chain.
   Change the subsidy so a block is paid min(subsidy, CAP_UNITS - issued_before),
   never more. The cap must still hold exactly; keep CapExceeded as a backstop
   that can no longer fire for honest blocks. Tests: issued exactly reaches
   the cap and stays there; the block at the cap pays 0 subsidy and is valid;
   chain continues past it; a miner claiming more than the clamp is refused.
   T11 note: no public network exists yet, so this activates at genesis of
   the public testnet (no activation height needed); say so in the PR.
3. **Mempool runs the turnstile.** Reject at mempool admission a private
   payment whose pool_out exceeds the virtual pool balance (same rule as the
   template). Test: such a tx is refused by the mempool; an honest one is
   accepted.
4. **Initial-sync path check.** Trace the trusted-block / headers-proof IBD
   import path and confirm private payments in those blocks get the full
   isolation + context checks (proof, nullifiers, anchors, turnstile). If any
   path skips them, fix it and add a test. If all paths check, write the trace
   (file:function) in the PR.
5. **Missing private state recovery.** Today a node whose selected parent has
   no note tree / fingerprint panics. Find what a user would see and whether
   restart recovers. If not, make it fail with a clear error and a documented
   recovery (e.g. resync from the pruning point) instead of a panic. Report
   what you found before large changes.

## B. Integration tests (prove the invariants end to end)
6. **Anchor reorg end to end:** create an anchor, let it mature, accept a
   spend against it, reorg the producer off the selected chain, and assert:
   the spend is no longer accepted on the new chain, the coin is spendable
   again only there, nullifier store / fingerprint / pool balance match a node
   that never saw the old branch. (Existing partial test:
   pipeline/tests/zethora_anchor_reorg.rs.)
7. **Snapshot import end to end:** a fresh node imports the pruning-point
   private state; a tampered copy (one nullifier hidden, one invented, one
   anchor age changed) is refused before any write; the honest copy is
   accepted and a spend of an already-spent coin is then refused.
8. **Mint-attack regression tests** from the red team (re-implement, do not
   copy unreviewed patches): extreme value balances (i64::MAX/MIN) cannot wrap
   the fee; a forged value-balance byte is refused; fee paid from the pool is
   not counted twice; many small withdrawals stop exactly at the pool balance.

## C. Cleanup
9. Fix stale comments: zethora_subsidy.rs (says testnet/mainnet are
   10 blocks/sec; params.rs sets both to 1) and the ANCHOR_DEPTH TODO in
   zethora_private.rs. Add a test asserting MAINNET and TESTNET blockrate are
   1 block/sec and anchor_depth is 600.
10. **Dependency vulnerabilities (cargo-audit, first scan 2026-10-28):** 6
    vulnerabilities: ctutils (RUSTSEC-2026-0385, >=0.4.4), rustls-webpki
    (RUSTSEC-2026-0382, >=0.103.16), tracing-subscriber (RUSTSEC-2025-0055,
    >=0.3.20), webpki-roots (RUSTSEC-2026-0381, >=1.0.10), zstd-sys
    (RUSTSEC-2026-0410, >=2.1.2), plus the 6th in the log. Upgrade each with
    `cargo update -p <crate>` where semver allows; for any that cannot be
    upgraded, add it to an audit.toml ignore list WITH a one-line reason
    (e.g. code path not used). List the 17 "unmaintained" warnings in the PR
    without changing them. cargo audit must pass at the end.
11. Explorer/RPC: confirm any supply numbers shown come only from chain
    (selected) blocks, never from a merged side block's coinbase fields. Fix
    and test if not.

## T11 clarification (CTO, 2026-10-28)
T11 (activation heights) applies once a public network is live. Before the
public testnet launches there is no live network to split, so consensus
changes (F1, F2, the testnet privacy switch) take effect from the public
testnet genesis. Add this clarification to CLAUDE.md in your first commit.
PR #3 decision: F1 accepted as is (option a).

## Rules
- Branch `f2-hardening`. Never push to `zethora`. One PR, do NOT merge.
- Do not change Orchard, G11, genesis, or anything not listed.
- Every item: positive control, exact asserts, fail-when-removed where it
  applies (Rule 4). Paste the outputs in the PR.
- If an item needs a design decision, stop that item, note it in the PR, and
  continue with the others.
- PR description: per item: files, what changed, tests, fail-when-removed
  output, and anything uncertain. Plus full `cargo test -p kaspa-consensus`
  summary and `cargo audit` result.
