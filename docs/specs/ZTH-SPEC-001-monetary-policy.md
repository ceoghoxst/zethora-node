# ZTH-SPEC-001: Monetary Policy

**Project:** Zethora (X: @ZethoraNetwork). Built by DeionRaven Labs.
**Status: LOCKED (Oct 2, 2026)** for Sections 1-8, 10-12, 15. Sections 9 and 13 hold parameters still OPEN, marked inline.
**Depends on:** ZTH-SPEC-000 (Foundation). **Constrains:** every later spec.

Status labels: LOCKED, DRAFT, PROPOSED, FUTURE, OPEN.

---

## Summary

| Rule | Value |
|---|---|
| Final cap | **100,000,000 Zethora** (ticker **ZTHR**, pending pre-launch recheck) |
| Decimals | **10** (1 Zethora = 10,000,000,000 zets) |
| Supply at genesis | **0** |
| Premine / insider / founder coins | **None** |
| How coins are created | Mining only, block rewards |
| Release curve | Smooth decay, no halving cliffs |
| Half mined | ~8 years |
| 90% mined | ~27 years |
| Never-mined reserve | **1,000 ZTHR** (guarantees the cap under BlockDAG parallelism) |
| First block reward (at 1 block/sec) | ~0.2746 ZTHR |
| Coins mined per day at launch | ~23,719 ZTHR |
| After rewards fade | Miners paid by fees + protocol fee pool |
| Tail emission | None |
| Treasury | None |

---

## 1. Purpose (LOCKED)
1.1 ZTHR is the base asset of the Zethora network. It is designed to be held, spent, and used to pay for activity on the network by anyone, without permission.
1.2 Its total supply has a fixed final cap. New ZTHR enters circulation only through mining, under public rules that apply equally to every participant from block 1.
1.3 No person, company, or group, including the founder and DeionRaven, has special rights in the protocol: no fee share, no reserved or premined coins, no veto, no pause, no upgrade key.
1.4 The monetary rules are enforced by consensus, not by promises, governance votes, or any party's discretion.
1.5 Applications and businesses, including DeionRaven's, are built on top of the protocol and have exactly the same rights as anyone else's.
1.6 This spec makes no statement about the price or future value of ZTHR.

## 2. Scope (LOCKED)
2.1 Covers ZTHR only: total supply, how it is created, how it is destroyed, and what can never happen to it.
2.2 Does not cover assets other people create on Zethora (ZTH-SPEC-003). Those never count toward the ZTHR cap.
2.3 Does not cover block production (ZTH-SPEC-005), execution (ZTH-SPEC-002), or privacy (ZTH-SPEC-006). Those specs must obey this one.
2.4 The pump.fun $ZERO token is not ZTHR, is not part of Zethora, and has no claim on it.

## 3. Definitions (LOCKED)
- **ZTHR:** the base asset of Zethora.
- **Zet:** the smallest indivisible amount (like Bitcoin's "sat"). 1 Zethora = 10^10 zets. Plural: zets.
- **Ticker:** ZTHR (LOCKED Oct 2, 2026; ZTH avoided because Zenith Protocol uses it on exchanges). Recheck availability before launch.
- **CAP_UNITS:** 100,000,000 x 10^10 = 10^18 units. Fits in a signed 64-bit integer (max ~9.22 x 10^18) with ~9x headroom.
- **Genesis:** the first block. Contains 0 ZTHR.
- **Emitted:** total units ever created by block rewards.
- **SUPPLY_RESERVE:** 1,000 ZTHR (10^13 units). Never mined. See 5.7.
- **Remaining:** CAP_UNITS - SUPPLY_RESERVE - Emitted.
- **Block reward:** new units paid to the miner of a block, per Section 5.
- **Fees:** units paid by users for transactions and token creation.
- **Fee pool:** a protocol-held balance, controlled by no key, defined in Section 8.
- **Burn:** permanent destruction of units. Burned units are never recreated.

## 4. Supply cap (LOCKED)
4.1 Emitted MUST never exceed CAP_UNITS. A block that would cause this is invalid.
4.2 The cap is enforced by every node independently. No party can change it.
4.3 Burns reduce circulating supply but never raise the cap and never allow re-emission (Section 7).

## 5. Issuance schedule (LOCKED)
5.1 **Formula.** Each block's reward is a fixed fraction of what remains:

    reward(block) = floor(Remaining / D)

Integer math only. No floating point anywhere in consensus.

5.2 **Divisor.** D is chosen so half of all remaining supply is emitted every 8 years:

    D = round(8 years in seconds x blocks_per_second / ln 2)

At the proposed 1 block per second (ZTH-SPEC-005): **D = 364,223,944**.
If SPEC-005 finalizes a different block rate before genesis, D is recalculated with this same formula so the time schedule is unchanged. D is fixed at genesis and never changes after.

5.3 **Resulting schedule** (at 1 block/sec):

| Time | Total mined | % of cap | Reward per block |
|---|---|---|---|
| Block 1 | 0 | 0% | ~0.2746 ZTHR |
| Year 1 | ~8.3M | 8.3% | ~0.252 |
| Year 8 | 50M | 50% | ~0.137 |
| Year 16 | 75M | 75% | ~0.069 |
| Year 27 | ~90.4M | 90.4% | ~0.026 |
| Year 50 | ~98.7M | 98.7% | ~0.004 |
| ~Year 250 | ~100M | ~100% | reward reaches 0 units |

5.4 **End state.** When Remaining < D, the reward rounds to 0 and emission ends. Up to D units (~0.036 ZTHR) are never emitted, so the cap is never exceeded.
5.5 **No cliffs.** No halvings. The reward shrinks slightly every block (~8.3% per year).
5.6 **Comparison.** Bitcoin: 50% mined in 4 years, ~90% in ~11. Zethora: 50% in 8, ~90% in ~27. The slower curve gives later participants worldwide a fairer share.

5.7 **Never-mined reserve (LOCKED Oct 3, 2026).** Emission starts from CAP_UNITS - SUPPLY_RESERVE (99,999,000 ZTHR). In a BlockDAG, parallel blocks can share a DAA score and each earn that step's reward; the worst-case lifetime overshoot is about 10 ZTHR at 1 block/sec. The 1,000 ZTHR reserve covers this 100x, so total supply can never exceed 100,000,000 ZTHR. The index n in 5.1 is the block's DAA score.

## 6. Genesis (LOCKED)
6.1 Genesis contains 0 ZTHR. The first coins are created by the miner of block 1.
6.2 No premine, no founder allocation, no investor allocation, no presale, no airdrop of ZTHR.
6.3 The launch date, software, and genesis parameters are published in advance, so anyone in the world can mine from block 1.
6.4 No one, including the founder, may mine the real network before public launch. The genesis block commits to a dated public message proving it was created no earlier than that date.
6.5 LOCKED: genesis message "Wake Up From The Dream World", plus the hash of the latest Bitcoin block at launch time (ZTH-SPEC-013).

## 7. Explicit prohibitions (LOCKED)
The protocol MUST make each of the following invalid:
- Creating ZTHR beyond the Section 5 formula.
- Any block reward larger than floor(Remaining / D).
- Hidden minting, including by overflow or rounding bugs. All supply arithmetic is checked.
- Governance-based or vote-based issuance. No such power exists.
- Restoring or re-minting burned ZTHR.
- Creating ZTHR through bridges. Bridges may only lock and wrap existing ZTHR.
- Creating ZTHR through upgrades (Section 12).
- Privacy hiding inflation. Shielded transactions must prove no ZTHR was created (ZTH-SPEC-006).
- Paying anyone other than the block's miner from the block reward.

## 8. Miner pay (LOCKED, parameters OPEN)
8.1 The miner of each block receives: the block reward + a share of that block's fees + a payout from the fee pool.
8.2 **Fee pool.** A share of every fee goes into a protocol balance controlled by no key. Each block pays a small fixed fraction of the pool to that block's miner. This smooths miner income and keeps miners paid after rewards fade, without creating new coins.
8.3 OPEN: fee share to pool vs miner (SPEC-008); pool payout fraction per block.
8.4 The built-in decentralized pool (SPEC-000 Section 4.5) shares rewards among small miners with no operator holding funds.

## 9. Fees and burns (OPEN)
9.1 All fees are paid in ZTHR.
9.2 LOCKED (Oct 2, 2026): 40% of every base fee is burned; 60% goes to the fee pool; tips go 100% to the miner. Details in ZTH-SPEC-008.
9.3 No burn may depend on an outside data feed (oracle).

## 10. User-created assets (LOCKED principle, details in SPEC-003)
10.1 Anyone can create a token on Zethora, paying a fee in ZTHR.
10.2 Created tokens have their own declared supply and never affect ZTHR.
10.3 Any mint power on a created token must be declared and visible to all.
10.4 The ZTHR asset identifier is reserved and cannot be imitated.

## 11. Treasury (LOCKED)
No protocol treasury and no account holding funds for anyone's discretionary use. Development is funded outside the protocol (e.g. DeionRaven's businesses).

## 12. Immutability (LOCKED)
12.1 Sections 4, 5, 6 and 7 are frozen at genesis and can never change.
12.2 Software that changes them is a different coin, not ZTHR.
12.3 Other layers may upgrade through the public process in ZTH-SPEC-011.

## 13. Reorgs and finality (OPEN, see SPEC-005)
13.1 Rewards and burns follow the canonical chain. If a block is reorganized out, its reward and burns are undone with it.
13.2 OPEN: confirmation depth before exchanges and bridges treat a payment as final.

## 14. Threat analysis

| Threat | Mitigation | Status |
|---|---|---|
| Bug mints extra ZTHR | Integer-only formula, checked math, per-block supply check | LOCKED |
| Founder/insider premine | Genesis = 0; dated genesis message; public launch | LOCKED |
| Privacy hides inflation (Zcash 2018 lesson) | Shielded pools must prove supply conservation | SPEC-006 |
| Bridge duplicates supply | Bridges lock/wrap only | LOCKED |
| Early large miner (cloud/botnet) grabs supply | 8-year half-life; CPU mining; announced launch | LOCKED |
| Monero miners swamp the chain at launch | Tuned RandomX variant | SPEC-000 |
| Security thins as rewards fade | Fee pool | LOCKED |
| Scam token imitates ZTHR | Reserved asset ID | LOCKED |

## 15. Verification (LOCKED)
15.1 Every node checks, every block: Emitted <= CAP_UNITS, and the block reward equals floor(Remaining / D) exactly.
15.2 Every node can report total emitted, total burned, and fee pool balance at any block.
15.3 Anyone can recompute the full schedule from this document alone.

## 16. Interactions with other specs
- SPEC-002 (Execution): no program can mint or alter ZTHR. ZTHR exposes transfer and burn only.
- SPEC-003 (Assets): user tokens are separate from ZTHR.
- SPEC-005 (Consensus): sets block rate; D derived from it before genesis.
- SPEC-006 (Privacy): supply must remain provable.
- SPEC-008 (Fees): fee split and burn.

## 17. Open issues
1. (Resolved: ticker ZTHR, unit "zet".)
2. Fee split: miner / pool / burn (SPEC-008).
3. Fee pool payout fraction.
4. (Resolved: genesis message set in SPEC-013.)
5. Confirm block rate in SPEC-005 (D recalculated if not 1/sec).

## 18. Changelog
- Oct 3, 2026: added 1,000 ZTHR never-mined reserve (5.7); reward index is the DAA score. First reward now 0.2745536136 ZTHR.
- Oct 2, 2026: ticker ZTHR, smallest unit "zet".
- Oct 2, 2026: LOCKED 100M cap, 10 decimals, smooth decay (8-year half-life), fee pool, no premine, no treasury, no tail emission.
- Oct 1, 2026: renamed to Zethora; fair launch from zero confirmed.
- Sep 30, 2026: restarted from scratch.
