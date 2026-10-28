# F1 task: per-transaction turnstile (for a Claude Code cloud session)

Read CLAUDE.md first (test discipline, Rule 4, git rules) and
docs/CI-AND-TURNSTILE-PLAN-2026-10-25.md (Item 2) - that is the design.

## Problem
The private-pool turnstile is checked as a per-block sum
(consensus/src/processes/coinbase.rs ~167-168, zethora_supply.rs ~102).
One overdrawing private payment can make a whole block invalid and stall
the chain. Fix: check per transaction, in consensus merge order.

## Required behaviour
- Running accumulator, starting from the pool balance before the mergeset.
  For each private payment in merge order: new = remaining + value_balance.
  If new < 0, SKIP the transaction (filtered like the existing nullifier
  filter in consensus/src/pipeline/virtual_processor/utxo_validation.rs
  ~521). Otherwise accept and set remaining = new.
- A skipped transaction must have NONE of its effects: nullifier insert,
  private-state fingerprint, note-tree appends, UTXO diff, fees / coinbase
  payout, pool flows, accepted_transactions, seq-commit state.
- Deterministic: the same blocks give the same state in AB and BA arrival order.
- Do not change Orchard. Do not change G11 (testnet/mainnet still refuse
  all private payments before decode). Do not touch the genesis.

## Tests (Rule 4: positive control, exact asserts, fail-when-removed)
1. Overdrawing tx is skipped and the block is still valid (chain continues).
2. Compare against the same block without that tx: nullifier count,
   fingerprint, note-tree root, UTXO diff, fees, pool balance, acceptance
   data, seq-commit all EXACTLY equal.
3. AB vs BA sibling order gives identical final state
   (see consensus/src/pipeline/tests/zethora_parallel_nullifier.rs).
4. Show each test fails when the new check is removed (paste the output).
5. Existing turnstile / supply tests still pass.

## Rules
- Work on a new branch `f1-per-tx-turnstile`. Never push to `zethora`.
- Open a PR into `zethora` in ceoghoxst/zethora-node. Do not merge it.
- No secrets, no key files, no new dependencies unless unavoidable.
- PR description: files changed, why, test names, fail-when-removed proof,
  `cargo test -p kaspa-consensus` summary, and anything you were unsure about.
- If you cannot make the full design work, stop and write up what you
  found instead of shipping a partial fix.
