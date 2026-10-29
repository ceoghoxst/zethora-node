# CEO briefing, 2026-10-28: F1 per-transaction turnstile

## What was done
The private pool's "turnstile" says more can never leave the pool than went in. It used to be checked once per
block, as a total. So a single bad private payment that took out too much made the whole block that merged it
invalid. Every later block has to merge that block, so the chain would have stopped.

Now the check runs per transaction, in the order every node merges them. A payment that would take the pool below
zero is simply not accepted, and it has none of its effects: no coins move, no fee is paid, nothing is recorded.
The block stays valid and the chain keeps going. The old per-block check stays in place as a second safety net.

## Why
This was the Carlos/Zealynx requirement (docs/CI-AND-TURNSTILE-PLAN-2026-10-25.md, Item 2) and the CTO's F1 task
(docs/F1-TASK.md). It has to be done before private payments are turned on anywhere public.

## How it was verified
- An honest payment cannot overdraw the pool. So the tests make a counterfeit: they spend a coin that was never
  shielded, and tell the test node to trust its coin list (pretending there is a bug in the proof or snapshot rules).
- Positive control: on its own, the counterfeit passes every other check and is accepted.
- In the tests, the payment that overdraws is skipped, the block stays valid and the chain continues. The final state
  is exactly the same as a block without that payment. Both arrival orders give the same result.
- Each test was run with its protection removed and failed. The outputs are in the PR.
- Full `cargo test -p kaspa-consensus` run; result in the PR.

## Status
A PR is open into `zethora` and is not merged. It needs CTO review. Private payments stay OFF on testnet and mainnet.
No devnet reset is needed.

# CEO briefing, 2026-10-28 (second session): F2 pre-testnet hardening

## What was done
The red team (Round 1) found no way to break the chain, but flagged places to make stronger. All 11 items from
docs/F2-TASK.md were worked through, one change per item:
- The byte layout of a private payment is now written in one place, so the part that checks payments and the part
  that reads them can never drift apart.
- Instead of stopping the chain if a block would ever pay past the 100,000,000 ZTHR cap, the reward is cut to exactly
  what is left. The cap still holds exactly; the chain never stops because of it.
- The waiting room (mempool) now refuses a private payment that takes more out of the private pool than it holds.
- New end-to-end tests: a chain reorganisation that removes a coin snapshot, a new node importing the private state
  (and refusing a tampered copy), and the red team's money-printing attempts (all refused).
- Six vulnerable libraries updated; the security scan now passes. One old library is accepted with a written reason
  (it is not in the node).
- Old comments that still said "10 blocks per second" fixed, with a test that the networks run at 1 per second.

## Decisions needed
1. Item 5: if a node's private state record were ever missing (only possible through disk damage or a bug), the node
   stops and needs `--reset-db`. Should we build an automatic resync instead? It is a bigger change.
2. The RPC "coin supply" answer still reports Kaspa's maximum supply number, not ours. Fix it as a follow-up?

## How it was verified
Every new test was also run with its protection removed and failed. The outputs are in the PR. The full consensus
test suite, the formatting and lint checks (with CI's compiler version) and the security scan were run.

## Status
A PR is open into `zethora` and is not merged. It needs CTO review. Private payments stay OFF on testnet and mainnet.
No devnet reset is needed.

## Update after CTO review
Both open questions were decided and done: the RPC now reports Zethora's 100,000,000 ZTHR cap as the maximum supply,
and the "records missing" stop keeps stopping the node but now explains in plain words what happened and how to fix
it (start once with --reset-db). The same help is in docs/FAQ.md. The PR is still not merged.
