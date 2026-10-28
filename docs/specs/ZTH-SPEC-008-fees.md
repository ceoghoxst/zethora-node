# ZTH-SPEC-008: Fees, Fee Pool and Burn

**Project:** Zethora (ZTHR). Built by DeionRaven Labs.
**Status: LOCKED (Oct 2, 2026).** Numeric tuning OPEN (set on testnet).
**Depends on:** ZTH-SPEC-001 (Sections 8-9), ZTH-SPEC-002, ZTH-SPEC-005.

## 1. Purpose
Keep everyday fees tiny, stop spam, pay miners for decades, and reward holders by reducing supply as usage grows.

## 2. Locked decisions

| Decision | Value |
|---|---|
| Fee currency | ZTHR only |
| Pricing | Automatic base fee (rises when blocks are full, falls when not) + optional tip |
| Target | Normal payments cost a fraction of a cent |
| Capacity first | Low fees come from capacity (BlockDAG + parallel execution), not from subsidies |
| Tip | 100% to the miner of the block |
| Base fee split | **60% to the fee pool, 40% burned forever** |
| Fee pool payout | Each block pays a fixed fraction of the pool, so funds spread over ~30 days |
| Token creation fee | A fixed multiple of the current base fee (e.g. 10,000x), tuned on testnet |
| Dollar pegging | None (would require an outside price feed; prohibited) |

## 3. Flow of one fee (example: 1 cent base + 0.5 cent tip)

| Part | Destination |
|---|---|
| 0.5c tip | Miner of the block, immediately |
| 0.6c (60% of base) | Fee pool, paid to miners over ~30 days |
| 0.4c (40% of base) | Burned permanently |

## 4. Rules
4.1 **Base fee adjustment.** Each block, the base fee moves up when recent blocks are above a target fullness and down when below, by a bounded percentage per block. OPEN: target fullness, max change rate, floor value.
4.2 **Burn.** Burned units are destroyed and counted in a public "total burned" figure (SPEC-001 15.2). They can never be re-minted.
4.3 **Fee pool payout.** payout(block) = floor(PoolBalance / P), with P = 2,592,000 at 1 block/sec (~30 days). The pool is controlled by no key.
4.4 **Computation pricing.** App actions pay per unit of computation and storage (SPEC-002), so heavy apps pay more than simple payments.
4.5 **Private transactions** pay for their larger size and proof verification at the same rates.

## 5. Holder reward (plain language)
Burning shrinks total supply. Holders' coins stay the same, so their share of all ZTHR grows, like a share buyback. Nothing is printed. The effect grows with usage. It does not guarantee price.

## 6. Threats

| Threat | Mitigation |
|---|---|
| Spam | Base fee rises under load; creation fee multiple |
| Fee spikes like Ethereum 2021 | High capacity; bounded base-fee changes |
| Miners stuffing fake transactions to raise fees | 60% of base fee leaves the miner (pool + burn), removing most of the incentive |
| Security thins as block rewards fade | Fee pool smooths and sustains miner income |

## 7. Changelog
- Oct 2, 2026: LOCKED: base fee + tip, tip 100% to miner, 60/40 pool/burn, ~30-day pool payout, creation fee as base-fee multiple.
