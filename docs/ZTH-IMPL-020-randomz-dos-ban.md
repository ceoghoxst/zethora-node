# ZTH-IMPL-020: RandomZ DoS Ban

Status: Draft for review
Author: DeionRaven Labs
Date: Oct 13, 2026
Related: ZTH-SPEC-012 (Security), CLAUDE.md pre-testnet checklist

## Problem

A peer can send a bogus pruning proof. Validating a pruning proof requires the receiving
node to build one RandomZ light setup per epoch since genesis.

Costs measured on a Ryzen 5 2600:
- One light setup: 256 MB memory, ~1.8 s CPU
- One year of chain at 1 BPS: ~30 epochs
- The node builds up to 4 setups in parallel
- Total per bogus proof: ~15 s CPU + up to 1 GB peak memory

Today, an invalid proof causes the node to disconnect the peer but NOT ban it.
The peer can reconnect and repeat indefinitely.

## Attack surface

Three places where a peer's proof/data triggers epoch setup building:

1. Pruning proof submitted during P2P handshake
2. Past pruning points in headers (beyond the proof's)
3. Header-only chain segments during IBD

## Proposed fix

Ban the peer's IP for 24 hours when a proof fails validation due to:
- Invalid RandomZ work
- Epoch out of plausible range
- Pruning proof structure invalid

Do NOT ban for:
- Unreadable bytes (newer node's format after upgrade)
- Chain-dependent refusals (network switch, spend disabled)
- Network timeouts

[Continue designing below.]

## Options

Option A: Ban on any PruningImportError::ZethoraPowEpochImplausible
- Simple
- Risk: bans honest nodes after a format change

Option B: Ban only if the proof fails structural OR work verification
- More precise
- Requires distinguishing error types

Option C: Rate limit proof requests per peer (e.g., 3 per hour)
- Doesn't ban but throttles
- Attacker with many IPs still gets through

Option D: A + C combined: ban on structural failure, rate limit on soft failures

## Questions for the founder

1. Which error types should be "hard" (ban) vs "soft" (throttle)?
2. Ban duration: 24 hours, 1 hour, exponential backoff?
3. Should bans be per-IP only, or also per-peer-id?
4. What happens on upgrade? How do we avoid banning honest nodes after format changes?
5. Do we log banned peers locally, and how long do we keep the log?
6. Should we notify the community of the ban list, or keep it private?

## Test plan

- Unit: mock a peer sending a malformed proof, assert the ban triggers
- Unit: mock a peer sending a valid proof, assert no ban
- Unit: mock an upgrade scenario (new format), assert no ban
- Live: two devnet nodes, deliberately send bad proof, verify ban
- Live: after ban, verify peer cannot reconnect for the ban window
- Live: verify honest peer is not affected

## Rollout

1. Land on devnet only (skip mainnet/testnet enforcement)
2. Observe for 2 weeks on devnet
3. If no false positives, extend to testnet
4. Before mainnet: review logs, add to launch checklist