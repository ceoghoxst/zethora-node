# ZTH-IMPL-020: RandomZ DoS Ban (v2)

Status: Design approved for implementation
Author: DeionRaven Labs
Date: Oct 13, 2026
Related: ZTH-SPEC-012 (Security), ZTH-IMPL-019 (RandomZ key rotation)

## Problem

A peer can send a bogus pruning proof. Verifying one requires building one RandomZ
light setup per epoch since genesis. On a Ryzen 5 2600: ~1.8 s CPU + 256 MB per
setup, ~30 setups per year at 1 BPS, up to 4 in parallel, so ~15 s CPU and up to
1 GB peak memory per bogus proof. A peer that fails verification is disconnected
but not banned, and can reconnect and repeat indefinitely.

This is an asymmetric DoS: cheap for the attacker, expensive for the honest node.

## Decisions

D1. Hard ban only on errors honest software cannot produce.
D2. Ban duration: 24h base, doubling on repeat to 1 week max, reset after 24h clean.
D3. Ban by IP via AddressManager. Peer ID tracked for logging, not for banning.
D4. Two protections against false positives: version-aware classification and a
    3-failures-in-10-minutes threshold.
D5. Local logging only. Rotating file, 30-day retention.
D6. Per-node ban list. No central or published list. Publishing would create a
    centralization vector and violate the "no owner" principle.

## Hard vs soft error classification

Hard (ban after threshold):
- Malformed proof structure (unless the peer announced a newer protocol version)
- Invalid RandomZ work

Soft (disconnect only, no ban):
- Unknown error variants (default-safe)
- Chain-dependent refusals (network switch, spends disabled)
- Unreadable bytes
- Network timeouts

New error variants added in the future default to soft until explicitly classified.

## Protection 1: Version-aware classification

A peer whose announced protocol version exceeds ours never triggers a hard ban.
Any error from a newer version falls back to soft. This prevents honest nodes
from being banned after a future format change.

## Protection 2: Threshold-based banning

A single hard error does not ban. Three hard errors within 10 minutes from the
same IP trigger the ban. A quiet 10-minute window resets the counter to zero.

## Ban schedule

- 1st ban: 24 hours
- 2nd ban: 48 hours
- 3rd ban: 7 days
- 4th and beyond: 7 days (capped)
- 24 hours without incident: counter resets to 0

## Logging

Path: <appdir>/zethora-bans.log
Format: rotating, 30-day retention
Fields: ISO8601 timestamp, IP, error variant, ban duration, peer version

## Non-goals

- Preventing all forms of DoS
- Detecting coordinated multi-IP attacks (future work)
- Publishing or sharing ban lists

## Test plan

Unit tests:
- Malformed proof triggers a hard classification
- Valid proof does not
- Newer protocol version falls back to soft
- Two failures do not ban; third does
- Counter resets after 10 quiet minutes
- Ban log entry is written with correct fields

Live devnet:
- Node A sends a deliberately malformed proof to Node B
- Node B disconnects A
- After 3 attempts, Node B bans A for 24 hours
- A cannot reconnect for the ban window
- An honest Node C is unaffected

## Rollout

1. Land on devnet only (skip mainnet/testnet enforcement)
2. Observe 2 weeks on devnet for false positives
3. If clean, extend to testnet
4. Before mainnet: review ban logs, add to launch checklist