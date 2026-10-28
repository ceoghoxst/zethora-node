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
