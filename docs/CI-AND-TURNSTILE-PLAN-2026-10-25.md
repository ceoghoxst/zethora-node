ITEMS FROM CTO 2026-10-25 (plan only, no code)

ITEM 1: CI Tests workflow has failed every run (1-5). Diagnose + plan.

Diagnostic paths:
A. Paste latest Tests Actions log (GitHub UI -> Actions -> Tests -> failing run -> red step).
B. Run `cargo nextest run --workspace` locally, paste summary + failures.

Known at pause: daemon_integration_tests fails on 32-byte coinbase payloads (PayloadLenBelowMin). May be the only failure, may be more.

Fix plan by category:
A. Only daemon_integration_tests:
   - Real fix: update the daemon test helper to build Zethora-shaped coinbases (same as test_consensus.rs was fixed on Oct 13). 1-2 hours.
   - Interim: #[ignore = "known: stale 32-byte coinbase; tracking issue"] on the specific failing tests, with tracked issue. CI green now, real fix in own session. RECOMMENDED interim.
B. daemon + others: triage each separately (Windows, timeout, or real regression).
C. Workflow itself broken: pin versions, fix missing deps.

Packet to CTO should include: failing test names + errors, exact change, cargo nextest local run green, git diff --stat, note on what is temporarily excluded and why.

ITEM 2: Turnstile per-tx effects exclusion (Carlos/Zealynx requirement).

Requirement: if a transaction is skipped because it would overdraw the pool, NONE of its per-tx effects fire.

Complete list of per-tx effects that must be excluded:
1. Nullifier set insert (zethora_nullifiers_store)
2. Private-state fingerprint update (MuHash, zethora_private_state.rs)
3. Note-tree appends (zethora_note_trees_store)
4. UTXO diff (visible input removal + output addition)
5. Fee accounting (fee pool, burned, coinbase payout accumulation)
6. Pool flows (value_balance)
7. Acceptance data (accepted_transactions)
8. Seq-commit / fee pool state (post-KIP21, calculate_utxo_state)

Design principle: check must fire BEFORE any effect, at same point as current nullifier filter (utxo_validation.rs:521-522). Tx is filtered out of merge loop entirely, downstream never sees it. All 8 effects naturally excluded.

Only subtlety: pool flow (effect 6) IS the thing checked. Running accumulator:
  remaining_pool_balance = pool_balance_before_mergeset
  for each accepted private payment in merge order:
    new_balance = remaining_pool_balance + value_balance
    if new_balance < 0: skip tx (return None from filter)
    else: remaining_pool_balance = new_balance, accept tx
  end: remaining_pool_balance = new pool state

Two implementation constraints:
1. Deterministic and order-independent. Merge order is consensus-ordered, so AB and BA see same sequence.
2. Tests required:
   - Positive: overdrawing tx is REJECTED, block still valid
   - Negative: same tx with all effects - assert nullifier count, fingerprint, note tree, UTXO diff, fees, pool flows, acceptance, seq-commit ALL unchanged vs block without overdraw
   - Order-independence: AB and BA same final state

Files to inspect in implementation:
- consensus/src/pipeline/virtual_processor/utxo_validation.rs (merge loop, insertion point)
- consensus/src/processes/zethora_private_state.rs (fingerprint)
- consensus/src/model/stores/zethora_note_trees.rs (tree append)
- consensus/src/processes/zethora_supply.rs (ledger)
- seq-commit / MuHash assembly after merge loop
All flagged as "to be read in implementation," not "seen."

Deferred per CTO: turnstile before private payments enabled, not before testnet.