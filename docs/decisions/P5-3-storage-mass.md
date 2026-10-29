# P5-3: storage mass parameter for zets (dust protection) — table and CTO recommendation

Written 2026-10-28 by Claude (CTO). Decision owner: CEO/VP. **DECIDED 2026-10-29: C = 10^13** (see the end).

## What the parameter does
Kaspa's storage mass (KIP-9) charges each transaction `C / amount` for every output it creates (minus a credit for
the inputs it uses). Small outputs ("dust") cost a lot of mass, so nobody can cheaply fill every node's disk with
millions of tiny coins. Two limits apply: a transaction above 100,000 mass is not relayed (standard limit), and a
block can hold at most 500,000 storage mass.

Zethora still uses Kaspa's value, `C = 10^12` (consensus/core/src/constants.rs, `STORAGE_MASS_PARAMETER`). Kaspa sized
it for 1 KAS = 10^8 sompi. 1 ZTHR = 10^10 zets, so the same `C` lets Zethora outputs be **100x smaller in coin
terms** than Kaspa allows. This is a consensus rule (blocks are checked against it), so a change takes effect from
the public testnet genesis (T11 clarification).

## Table
Numbers computed from the formula in consensus/core/src/mass/mod.rs (`calc_storage_mass`). Starting block reward
= 0.2746 ZTHR (`zethora_subsidy`, DAA score 0), so a home miner's coins start as ~0.27 ZTHR outputs.

| C | mass of a 1 ZTHR output | 0.1 ZTHR | 0.01 ZTHR | 0.001 ZTHR | smallest output a standard tx can create | pay 0.1 / 0.01 / 0.001 ZTHR from one fresh 0.2746 reward (with change) | dust outputs/year an attacker with 1,000 ZTHR can create (rough KIP-9 bound) |
|---|---|---|---|---|---|---|---|
| 10^12 (today, Kaspa's) | 100 | 1,000 | 10,000 | 100,000 | 0.001 ZTHR | 1,208 / 10,013 / 100,001 (last one just over) | ~12.6 million |
| **10^13 (recommended)** | 1,000 | 10,000 | 100,000 | 1,000,000 | 0.01 ZTHR | 12,086 / 100,137 (just over) / no | ~4.0 million |
| 10^14 | 10,000 | 100,000 | 1,000,000 | 10,000,000 | 0.1 ZTHR | 120,866 (NOT standard) / no / no | ~1.3 million |
| 10^15 | 100,000 | 1,000,000 | 10,000,000 | 100,000,000 | 1 ZTHR | no / no / no | ~0.4 million |

"Just over" means the payment needs a slightly bigger input (or two inputs) to be standard. The attacker bound is
sqrt(seconds x block storage limit x attacker's zets / C) at 1 block per second; it shrinks with the square root of C.
Fees: at the default relay fee (100 zets per gram), a full 100,000-mass transaction pays 0.001 ZTHR.

Private payments are not affected: their outputs are notes in the coin list, not visible outputs; their size is
limited by the proof mass (`PROOF_MASS_PER_ACTION`, item 16 / F3b).

## Recommendation: C = 10^13
- Smallest practical visible payment becomes ~0.01 ZTHR (about 1/27 of the starting block reward). Home miners can
  still pay 0.1 ZTHR straight out of a single block reward.
- Dust growth bound is ~3.2x tighter than today.
- 10^14 (Kaspa-equivalent per coin) is rejected: a miner could not pay 0.1 ZTHR from one block reward without
  combining coins first, which hurts exactly the home miners Zethora is for.
- Keeping 10^12 is defensible but allows outputs 100x smaller than Kaspa ever intended, for no user benefit.

## If approved (F3f)
Add `ZETHORA_STORAGE_MASS_PARAMETER = 10^13` next to `ZETS_PER_ZTHR`, use it in all four networks' params, update the
mass tests and the wallet's mass estimate (wallet/core/src/tx/mass.rs), test the 0.01 ZTHR boundary exactly
(standard at 0.0101 ZTHR from a 0.2746 coin, refused at 0.01), and state it in STATUS.md. Takes effect from the
public testnet genesis.

## Decision (2026-10-29)
- **Approved: C = 10^13** (CEO, 2026-10-29 12:00 PT; VP approved the same day). Built in F3f as
  `ZETHORA_STORAGE_MASS_PARAMETER` (consensus/core/src/constants.rs), used by mainnet, testnet, devnet and simnet.
- **Rule:** revisit if 0.01 ZTHR becomes meaningful money (the smallest practical visible payment is ~0.01 ZTHR).
- **Lowering it is a planned upgrade with an activation height** (a consensus change: standing rule T11, announced
  before the release, old and new nodes agree until the activation point). Never lowered in a surprise release.
- Takes effect from the public testnet genesis (no live network before it).
- Tests: `zethora_storage_mass_table_and_the_0_01_zthr_boundary` (the table above, exactly; 0.0101 ZTHR from a fresh
  0.2746 reward is standard at 99,148 mass, 0.01 ZTHR is not at 100,137) and
  `every_network_uses_the_zethora_storage_mass_parameter` (consensus/core/src/mass/mod.rs).
- Same PR (seam review P5-3): `MAX_SOMPI` (Kaspa's 2.9 x 10^18) is now `MAX_ZETS` = the 100M ZTHR cap (10^18 zets);
  `SOMPI_PER_KASPA` renamed `KASPA_SOMPI_PER_KAS`, Kaspa's `STORAGE_MASS_PARAMETER` renamed
  `KASPA_STORAGE_MASS_PARAMETER`, so neither is reused by mistake.
