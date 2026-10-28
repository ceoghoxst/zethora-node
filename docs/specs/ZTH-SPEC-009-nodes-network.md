# ZTH-SPEC-009: Nodes and Network

**Project:** Zethora (ZTHR). Built by DeionRaven, developed in the open with the community.
**Status: LOCKED (Oct 2, 2026).** Numeric targets OPEN (set on testnet).
**Depends on:** ZTH-SPEC-000, ZTH-SPEC-005, ZTH-SPEC-006.

## 1. Purpose
Keep Zethora runnable by ordinary people so no one can control or shut it down.

## 2. Locked decisions

| Decision | Value |
|---|---|
| Node types | Full node (home computers), miner (full node that mines), light node (phones), archive node (optional) |
| Hardware target | Normal home computer: ~4-8 cores, 16 GB RAM, SSD, home internet |
| Storage | Pruning: keep current state + recent history; older data dropped with cryptographic proof of validity. Archive nodes optional |
| Sharding | FUTURE research track, built in the background; adopted only via the public upgrade process (SPEC-011) once proven |
| Peer discovery | Many independent seed operators worldwide; no official or central server |
| Network privacy | Dandelion++ relaying; Tor/I2P support |
| Node rewards | None in protocol (miners are paid; nodes run for privacy, self-verification, support) |
| Software | Open source; reference implementation in Rust, starting from Kaspa's open-source code where suitable (license permitting) |

## 3. Rules
3.1 Capacity limits (block size, throughput) must keep the hardware target viable. If the two conflict, the hardware target wins.
3.2 Pruned nodes must be able to prove the validity of everything they dropped; new nodes can join without trusting anyone.
3.3 No seed list may be controlled by a single party, including DeionRaven.
3.4 Light nodes on phones verify block headers and proofs, not trust a server.

## 4. Threats

| Threat | Mitigation |
|---|---|
| Eclipse attack (isolating a node with fake peers) | Diverse seeds, peer rotation, outbound connection limits |
| Data bloat pushing out home users | Pruning; hardware-target rule 3.1 |
| IP tracking | Dandelion++, Tor/I2P |
| Single seed operator pressured | Many independent operators |
| Sybil node farms | No node rewards to farm |

## 5. Open issues
1. Pruning window length.
2. Exact hardware and bandwidth targets (benchmarked on testnet).
3. Seed operator list and diversity rules.
4. Kaspa code license review and fork plan.
5. Sharding research milestones.

## 6. Changelog
- Oct 2, 2026: LOCKED: home-computer nodes, pruning (sharding as background research), independent seeds, no node rewards, Rust.
