# ZTH-SPEC-006: Privacy and Provable Supply

**Project:** Zethora (ZTHR). Built by DeionRaven Labs.
**Status:** Direction LOCKED (Oct 2, 2026). Technology LOCKED (Oct 3, 2026). Numbers marked PROPOSED are starting values, tuned on testnet.
**Depends on:** ZTH-SPEC-000, ZTH-SPEC-001, ZTH-SPEC-005, ZTH-SPEC-008.
**Research basis:** "Zethora privacy design options" report (Oct 3, 2026), which includes a 21-incident lessons ledger covering Zcash, Monero, Firo, Grin and others.

## 1. Purpose
Make Zethora private by default without ever allowing hidden inflation.

## 2. Locked decisions

| Decision | Value |
|---|---|
| What is hidden | Sender, receiver, and amount (Monero-level) |
| Default | Private by default in every standard wallet |
| Transparent mode | Optional, for parties who need it (e.g. exchanges, businesses). Using it exposes only that party's own activity. Wallets must show: "Transparent mode: anyone in the world can see this address's balance and history. This cannot be undone for past transactions." |
| View keys | Users may create read-only keys and share them voluntarily (taxes, audits). No master key exists for anyone |
| **Technology** | **Zcash Orchard shielded actions on Halo 2 (zcash/halo2, IPA, no trusted setup). Used UNMODIFIED: zero changes to the circuit.** Minimum versions: `orchard` 0.14.0, `halo2_gadgets` 0.5.0 (the June 2026 fix for CVE-2026-54496). Benchmarked version: `orchard` 0.16.0 |
| Banned | Any proof system that needs a trusted setup, including the PSE/KZG fork of halo2 |
| Network privacy | Dandelion++-style relaying plus Tor/I2P support, hiding transaction origin IPs |
| Supply | Always provable; privacy can never hide inflation |

**Why Orchard (summary).** It is the only option that meets all four tests: no trusted setup, hides each spend among every coin in the pool, verification cost does not grow as the pool grows, and permissively licensed Rust. Monero FCMP++ is the fallback to re-check in 2027 (not on Monero mainnet yet; conflicts with pruning). Firo Spark, Mimblewimble and ring signatures are rejected. See the research report for the full comparison.

## 3. How privacy works for a user (plain language)
3.1 Inside your wallet: balances, senders, receivers and amounts are hidden from everyone, including DeionRaven.
3.2 Exchanges and payment providers know their own customers (ID checks), as with every coin. They do not see what happens after coins reach a private wallet.
3.3 Nobody, including governments or the founder, can use the chain to see a private wallet's history unless its owner shares a view key.
3.4 Coins you receive privately can be spent again after they are about 10 minutes deep (see 6.2).

## 4. Measured performance (Oct 3, 2026)
Official `orchard` 0.16.0 benchmark (`cargo bench --bench circuit`, fixed post-NU6.2 circuit) on the founder's PC: AMD Ryzen 5 2600 (6 cores, 2018), 16 GB RAM, Windows 11, all cores.

| Transaction size | Make the proof (wallet) | Check the proof (node) |
|---|---|---|
| 2 actions (normal payment; 1 recipient is padded to 2) | 1.37 s | 10.3 ms |
| 3 actions | 1.95 s | 12.2 ms |
| 4 actions | 2.50 s | 14.0 ms |

Marginal cost: about 0.57 s proving and 1.85 ms checking per extra action.
Meaning: one node on this PC can check about 97 normal private payments per second at 100% CPU. Batch verification is expected to improve this; NOT yet measured.
Size: about 9.1 KB for a 2-in/2-out private transaction (computed from Orchard's published sizes).

## 5. Consensus limits (PROPOSED, tuned on testnet)

| Limit | Starting value | Reason |
|---|---|---|
| Private payments per block | About 15 (about 30 actions) | Keeps checking a full block under ~0.15 s on the reference PC, leaving room for parallel blocks and the rest of the node's work |
| CPU budget for proof checking | At most 25% of one second of blocks on the reference PC | Leaves headroom for spam, reorgs and slower machines |
| Proof mass | A fixed mass per action, set so the cap above is enforced by Kaspa's existing mass limit | Uses the mechanism Kaspa already has instead of a new one |
| Storage mass | Flat mass per new private output AND per nullifier | Kaspa's anti-dust formula (KIP-9) cannot see hidden amounts |
| Minimum fee | Per action (ZIP-317 style), not per transaction | Zcash 2022 spam lesson: price by work done |
| Worst-case growth | ~12 GB/day if every block is full of private payments | Old block data is pruned; the nullifier set is never pruned, so the cap also protects disk space |

## 6. BlockDAG integration rules (LOCKED direction, details OPEN for cryptographer review)
6.1 **Commitment tree order.** New notes are added to the global commitment tree only inside the virtual processor, in GHOSTDAG accepted order. Every node must reach the same tree root. The root is committed in the header/virtual state.
6.2 **Matured anchors.** A spend must reference a tree snapshot (anchor) buried at least N blocks deep. PROPOSED N = 600 (about 10 minutes, as ZKas uses). N must stay well inside Kaspa's merge depth and finality.
6.3 **Conflicting spends.** A nullifier is treated like a spent UTXO. In merge order, the first transaction using a nullifier is accepted; later ones are not accepted, and their blocks stay valid. The nullifier set gets an undo/diff layer like Kaspa's UtxoDiff.
6.4 **Pruning-point sync.** A node syncing from the pruning point receives the nullifier set, tree frontier, anchor-window roots and every pool's turnstile balance. All four are committed in headers and checked on sync.

## 7. Hack protections (LOCKED)
History shows privacy can hide inflation bugs: Bytecoin 2017 (exploited, ~693M coins), Firo/Zcoin 2017 (exploited, ~370K coins), Zcash 2018 (counterfeiting bug, fixed quietly), Zcash Orchard 2026 (unlimited-counterfeit bug undetected 4 years through three audits; exploitation cannot be ruled out), Firo Spark 2026 (forgery flaw, emergency fork). Zethora therefore requires:

7.1 **Turnstile accounting.** Every private pool has a public balance: value in minus value out. Consensus rejects any block that would make it negative. Computed in accepted order, committed in the header, shown on the explorer home page.
7.2 **Continuous supply check.** Every block, nodes verify: `issued − burned = transparent coins + sum of all private pool balances`, with every pool balance ≥ 0. A public RPC returns these numbers so anyone can recompute them.
7.3 **Emergency switch.** A consensus flag with three levels: (a) all private spends off, (b) private spends with more than 1 input off, (c) new deposits into the private pool off. Turned on by a node software release, never by a key, so no one holds a kill key. Drilled on testnet before mainnet.
7.4 **Pool versions and migration.** Every private transaction carries a pool version byte. Each version has its own tree, nullifier set and turnstile balance. Moving everyone to a fresh pool through a turnstile is a built and tested routine, not an emergency invention. Old pools become exit-only with no deadline.
7.5 **Multiple independent audits** of the integration code before launch and after every change, plus AI-assisted adversarial review every release (the 2026 Orchard bug was found this way).
7.6 **Formal verification.** Reuse Zcash's machine-checked proofs by shipping the identical circuit. Gate: the circuit diff against the upstream tag must be zero.
7.7 **Bug bounty** live from public testnet, top tier for counterfeiting or supply-check bypass, sized so reporting pays more than exploiting. Funded without breaking the fair launch.
7.8 **Private disclosure process.** `SECURITY.md` with a contact key, a ready list of top pools and exchanges to warn quietly, a 90-day disclosure norm, and a request to Zcash for advance notice of Orchard/Halo2 bugs.
7.9 **Staged rollout.** Conservative per-block caps at launch (Section 5), raised only after real data.

## 8. Spam and denial-of-service rules (LOCKED)
8.1 Run all cheap checks (format, size, fee, nullifier not already spent, anchor matured) before the expensive proof check.
8.2 Cache proof-check results by the hash of the whole transaction, never by the proof alone (Grin 2021 lesson).
8.3 Disconnect and temporarily ban peers that relay transactions with invalid proofs.
8.4 Bound memory when reading proofs from the network, and reject proofs of non-standard size (Zcash 2026 lessons).
8.5 Wallets must stay usable under a spam flood (Zcash 2022 lesson). Scanning approach is OPEN (Section 11).

## 9. Fees with private transactions
The fee is a public number in every private transaction (Orchard's value balance), so the SPEC-008 rules (base fee + tip, 60% to the fee pool, 40% burned) apply with no circuit change. Only accepted transactions count toward the pool and the burn.

## 10. Threats

| Threat | Mitigation |
|---|---|
| Counterfeit coins via circuit bug | Unmodified audited circuit, turnstile 7.1, supply check 7.2, emergency switch 7.3, pool migration 7.4 |
| Proof-check flooding (DoS) | Section 8, per-block cap, per-action fees |
| Wallet sync collapse under spam | Per-action fees, storage mass, scanning research (Section 11) |
| Nodes disagreeing on note order | Rule 6.1 plus multi-node simulation tests |
| Spends broken by reorgs | Matured anchors 6.2 |
| Double spend in parallel blocks | Rule 6.3 |
| Bad sync from pruning point | Rule 6.4 commitments |
| Small private crowd | Private by default |
| Exchanges delisting | Transparent mode for exchanges |
| IP tracking | Dandelion++ / Tor / I2P |
| Coerced disclosure | No master key; view keys only by owner |
| Wallet bugs leaking data | Wallet audits; open-source reference wallet |
| Upstream bug disclosed late to forks | Disclosure process 7.8; track every Zcash advisory |

## 11. Open issues (for a cryptographer)
1. Is the three-tier commitment tree sound under GHOSTDAG reorgs, and is N = 600 safe?
2. Confirm the fee split and burn need zero circuit changes (Section 9).
3. Adopt Ironwood's exact circuit version (quantum-recoverable notes) instead of plain Orchard?
4. Pool rotation schedule, and any supply check inside a pool beyond the turnstile.
5. Safe batching of proof checks across parallel blocks.
6. Wallet scanning at 86,400 blocks/day (fuzzy message detection, oblivious sync, light-wallet servers).
7. Network-layer protection strength at 1 block/sec.
8. Transparent mode for everyone, or exchange-only addresses?
9. Conditions for a later switch to FCMP++.
10. Loss-allocation rule if a turnstile shortfall ever appears.
11. Staged-rollout cap schedule after launch.

## 12. Licenses (verified Oct 3, 2026 from source repositories)

| Code | License |
|---|---|
| `halo2_proofs`, `halo2_gadgets` | MIT OR Apache-2.0 |
| `orchard` | MIT OR Apache-2.0 |
| `pasta_curves` | MIT OR Apache-2.0 |
| `incrementalmerkletree`, `shardtree` | MIT OR Apache-2.0 |
| `zcash_primitives` (avoid if possible) | MIT OR Apache-2.0 |
| `rusty-kaspa` (our base) | ISC |

All are compatible with an open-source fork. Keep the original copyright notices.

## 13. Interactions
- SPEC-001: supply must stay provable; prohibition on privacy hiding inflation.
- SPEC-002 (Execution): private smart contracts are FUTURE (SPEC-000 6.2).
- SPEC-003 (Assets): user tokens may be private; same turnstile rule applies per asset.
- SPEC-005: 1 block/sec, GHOSTDAG ordering, merge depth and finality bound N.
- SPEC-008: fee pool and burn apply to private transactions via the public fee.
- SPEC-010 (Wallets): view keys, recovery, device wallets, migration flow.

## 14. Changelog
- Oct 2, 2026: Direction LOCKED: full privacy by default, optional transparent mode, view keys, ZK without trusted setup, network privacy, six hack protections.
- Oct 3, 2026: Technology LOCKED: Orchard on Halo 2, unmodified, minimum fixed versions. Added measured performance (Section 4), proposed consensus limits (5), DAG integration rules (6), expanded hack protections incl. emergency switch and pool versioning (7), spam rules (8), fees (9), verified licenses (12).
