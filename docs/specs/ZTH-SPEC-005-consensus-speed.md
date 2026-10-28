# ZTH-SPEC-005: Consensus, Mining and Speed

**Project:** Zethora (ZTHR). Built by DeionRaven Labs.
**Status: Speed direction LOCKED (Oct 2, 2026).** Mining direction LOCKED in ZTH-SPEC-000. Engineering parameters OPEN, marked inline.
**Depends on:** ZTH-SPEC-000, ZTH-SPEC-001.

---

## 1. Purpose
Define how Zethora produces blocks, how fast payments confirm, and how it stays decentralized while doing so.

## 2. Locked decisions

| Decision | Value | Status |
|---|---|---|
| Consensus | Proof-of-work | LOCKED |
| Mining algorithm | Tuned RandomX variant ("RandomZ"), CPU-friendly | LOCKED |
| Block structure | BlockDAG (GHOSTDAG-family ordering; reference: Kaspa) | LOCKED |
| Target block rate | **1 block per second** at launch | LOCKED |
| Practical confirmation | ~10 seconds for everyday payments | LOCKED target |
| Instant micropayments | Payment channels (Lightning-style), after launch | LOCKED, FUTURE delivery |
| Node rule | A normal home computer must always be able to run a full node | LOCKED, non-negotiable |
| Built-in decentralized pool | P2Pool-style, no operator holds funds | LOCKED |
| Emission divisor | D = 364,223,944 (from ZTH-SPEC-001, at 1 block/sec) | LOCKED |

## 3. How it works (plain language)
3.1 **Blocks.** Miners bundle transactions into blocks. About one block is produced every second across the whole network.
3.2 **BlockDAG.** On a normal chain, two blocks found at the same moment means one is thrown away, so blocks must be spaced minutes apart. In a BlockDAG, both are kept and woven together in a fixed order everyone agrees on. That is what makes 1-second blocks safe with proof-of-work.
3.3 **Confirmation.** A payment appears in about a second. After about 10 seconds, enough blocks build on top that reversing it becomes impractical for everyday amounts. Large amounts wait longer (Section 6).
3.4 **Payment channels.** For machines paying per second (EV charging, AI calls), two parties open a channel, make thousands of instant off-chain payments, and settle the total on-chain.

## 4. Rules
4.1 Every block must reference all known recent blocks it can see (tips), so parallel blocks join the DAG instead of being discarded.
4.2 The ordering of blocks is decided by a deterministic rule all nodes compute identically. OPEN: exact GHOSTDAG parameter k, tuned to network delay.
4.3 Difficulty adjusts continuously to keep the average at 1 block per second. OPEN: adjustment window.
4.4 Each block's miner receives the reward in ZTH-SPEC-001 Section 5. Parallel blocks each earn their own reward; the emission formula is applied per block in DAG order so total emission still follows the schedule exactly.
4.5 Block size and transaction limits are set so a normal home computer and home internet can keep up (Section 7). OPEN: exact limits.

## 5. Mining
5.1 RandomZ: RandomX design with Zethora-specific parameters, so Monero hardware can mine it but Monero's existing hashrate cannot switch over instantly in full.
5.2 If specialized chips (ASICs) appear, a pre-defined public rule triggers a parameter change. OPEN: exact trigger and process (ZTH-SPEC-011 Upgrades). No discretionary changes.
5.3 Verification of RandomZ must be fast enough for nodes to check ~1 block per second on ordinary hardware. OPEN: benchmark target.

## 6. Finality guidance (OPEN numbers)
| Amount | Suggested wait |
|---|---|
| Everyday (coffee, small transfers) | ~10 seconds |
| Large (thousands of dollars) | ~1-10 minutes |
| Exchanges / bridges | set by each, published |
Proof-of-work is never 100% final; risk drops with every block.

## 7. Node requirements (LOCKED principle, OPEN numbers)
7.1 A full node must run on a typical home computer with home internet. Draft targets: 4-8 CPU cores, 16 GB RAM, SSD, ~10-25 Mbps.
7.2 Old data may be pruned so storage stays manageable; full archives are optional.
7.3 Phones run light nodes that verify headers and proofs without trusting anyone.

## 8. Threats

| Threat | Mitigation |
|---|---|
| 51% attack while network is small | Tuned RandomX (no instant Monero takeover), announced launch, many home miners, confirmation guidance |
| Botnets / cloud renters | Unavoidable for CPU coins; slow emission limits any single actor's share |
| Selfish mining / ordering games | GHOSTDAG ordering rules; OPEN analysis |
| Speed pushes out home nodes | Node rule 4.5 / 7.1 is non-negotiable |
| Network spam | Fees (ZTH-SPEC-008) |

## 9. Open issues
1. GHOSTDAG k parameter and propagation assumptions.
2. Difficulty adjustment algorithm and window.
3. Block size / throughput limits.
4. RandomZ parameters and verification benchmarks.
5. ASIC-response rule (SPEC-011).
6. Payment channel design (later spec).

## 10. Changelog
- Oct 2, 2026: Speed direction LOCKED: BlockDAG, 1 block/sec, ~10 s confirmation, payment channels later, home-node rule.
