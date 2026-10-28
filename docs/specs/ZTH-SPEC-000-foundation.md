# ZTH-SPEC-000: Foundation

**Project:** Zethora (X: @ZethoraNetwork). Built by DeionRaven Labs.
**Status: LOCKED (direction), Oct 1, 2026.** This document fixes WHAT Zethora is. Later specs decide HOW. Any later spec that conflicts with this one is wrong, not this one.

Status labels: LOCKED, DRAFT, PROPOSED, FUTURE, OPEN.

---

## 1. Mission (LOCKED)
Zethora is fair money for people and machines: Bitcoin's strength, Ethereum's programmability, Solana's speed, and Monero-style privacy, in one network that no one owns.

## 2. Non-negotiables (LOCKED)
2.1 **Fair launch.** Every coin is mined from block one. No premine, no insider allocation, no founder coins.
2.2 **No owner.** No person or company, including the founder and DeionRaven, has special power in the protocol: no admin key, no pause, no veto, no fee share.
2.3 **Fixed supply.** A hard cap enforced by consensus. Amount set in ZTH-SPEC-001.
2.4 **Provable supply.** Anyone can verify the total supply at any time, even when balances are private. Privacy must never be able to hide inflation (lesson of the 2018 Zcash counterfeiting bug).
2.5 **Announced launch.** Launch date and software published in advance, open to everyone at once.
2.6 **No price claims.** The project never promises price or returns.

## 3. Layered architecture (LOCKED)

| Layer | Inspired by | Job |
|---|---|---|
| Base layer | Bitcoin | Proof-of-work consensus, fixed supply, settlement. Simple, near-frozen |
| Privacy | Monero / Zcash | Private transfers by default |
| Execution layer | Ethereum | Smart contracts and programmable rules |
| Native assets | Ethereum / Solana | Anyone can create a token, permissionless |
| Apps | Solana's pump.fun, wallets, DeionRaven products | Launchpads, trading, machine payments. Built on top, no special rights |

The base layer is kept simple so the money is safe even if a higher layer has a bug.

## 4. Mining (LOCKED direction)
4.1 Proof-of-work.
4.2 CPU-friendly: ordinary computers can mine. Reference model: RandomX (Monero).
4.3 OPEN: what happens if specialized mining chips (ASICs) appear anyway. Any algorithm change must follow a public, pre-defined rule, never discretion. Decided in SPEC-005.
4.4 LOCKED (Oct 1, 2026): Algorithm is a tuned RandomX variant (working name "RandomZ"), not RandomX as-is (avoids instant takeover by Monero's existing miners) and not a brand-new algorithm (unproven).
4.5 LOCKED: A decentralized pool (P2Pool-style) ships with the node, so small miners get steady payouts without a pool operator holding funds.
4.6 LOCKED: Pure "useful work" is NOT used for consensus. Reason: AI work is slow to verify, can be faked, and needs someone to choose the jobs.

## 4A. AI compute marketplace (LOCKED direction, Phase 3)
4A.1 Useful AI work happens in a marketplace on top of the chain, outside consensus. Buyers lock payment in an on-chain escrow; computers run jobs automatically in a sandbox; payment releases on delivery.
4A.2 The same app mines by default and switches to AI jobs when they pay more ("Auto: best pay"). Users never do manual work.
4A.3 Anti-cheating: duplicate spot-checks, worker deposits, reputation.
4A.4 Phasing: Phase 1 chain + mining. Phase 2 programmable layer (needed for escrow). Phase 3 marketplace beta with easy-to-check jobs, DeionRaven as first buyer. Phase 4 open to outside buyers.
4A.5 Adding the marketplace requires no change to mining or monetary rules.

## 5. Speed (LOCKED Oct 2, 2026; details in ZTH-SPEC-005)
5.1 Fast confirmations with proof-of-work, using a BlockDAG design (reference model: Kaspa) rather than one block every few minutes.
5.2 Parallel execution for independent transactions in the execution layer.
5.3 Exact targets decided in SPEC-005 (consensus) and SPEC-002 (execution). Speed may never cost decentralization: ordinary people must be able to run a node.

## 6. Privacy (LOCKED direction)
6.1 Private transfers by default.
6.2 Private smart contracts are FUTURE. Not promised at launch.

## 7. Token creation (LOCKED)
7.1 Anyone can create a token on Zethora, paying a fee in the base coin.
7.2 Launchpads and trading apps (pump.fun-style) are apps, not protocol. DeionRaven may build one; it gets no special rights.

## 8. Ecosystem (LOCKED)
8.1 DeionRaven builds the network and real-world products on top of it: AI first, then devices (phones, laptops, robots, vehicles).
8.2 Machines are first-class users: devices can hold wallets and pay under rules their owner sets.

## 9. Spec map
- ZTH-SPEC-000 Foundation (this document)
- ZTH-SPEC-001 Monetary policy (LOCKED)
- ZTH-SPEC-002 Execution / programmability (LOCKED; includes the state model)
- ZTH-SPEC-003 Native tokens and launchpad standards (LOCKED)
- ZTH-SPEC-004 Reserved (state model folded into 002)
- ZTH-SPEC-005 Consensus, mining and speed (LOCKED)
- ZTH-SPEC-006 Privacy and provable supply (LOCKED)
- ZTH-SPEC-007 Reserved: AI compute marketplace (Phase 3; direction in Section 4A)
- ZTH-SPEC-008 Fees, fee pool and burn (LOCKED)
- ZTH-SPEC-009 Nodes and network (LOCKED)
- ZTH-SPEC-010 Wallets, recovery, inheritance, device wallets (LOCKED)
- ZTH-SPEC-011 Upgrades and governance (LOCKED)
- ZTH-SPEC-012 Security review and launch gates (LOCKED)
- ZTH-SPEC-013 Genesis and launch (LOCKED)

## 10. What success requires (LOCKED, Oct 2, 2026)
10.1 Stay true to the people: home-computer mining, fair launch, no insiders.
10.2 Avoid blacklisting: transparent mode available so exchanges can list Zethora.
10.3 Security over speed of launch: multiple audits, formal verification, bug bounty, turnstile protection, long public testnet.
10.4 Privacy as the base; transparent mode is an honest opt-out with clear disclosure.
10.5 Beyond technology: a real team, community and awareness, exchange relationships, useful apps that give people a reason to come, and patience.
10.6 Build in phases: base layer (mining, speed, private payments, supply) first; apps and tokens next; AI marketplace and devices last. Each phase must work on its own.
10.7 Funding: no presale and no coin sales by the project. Start from open-source code where possible; volunteers, grants, and later equity investment in DeionRaven (company shares, with legal counsel).

## 11. Community-built (LOCKED, Oct 2, 2026)
11.1 After the core specs are set, all specs are published openly as Draft v0.1 for public comment, before any code is final.
11.2 Changes and open parameters are handled through public Zethora Improvement Proposals (ZIPs).
11.3 Contributors receive credit, never coins. The fair launch stays fair.
11.4 DeionRaven Labs is the lead builder and biggest user, not the owner.
