# ZTH-SPEC-002: Execution Model (Programmability)

**Project:** Zethora (ZTHR). Built by DeionRaven Labs.
**Status: Direction LOCKED (Oct 2, 2026).** VM details OPEN.
**Depends on:** ZTH-SPEC-000, ZTH-SPEC-001, ZTH-SPEC-005, ZTH-SPEC-006.

## 1. Purpose
Let anyone build apps (smart contracts) on Zethora safely and in parallel, without ever endangering ZTHR's supply.

## 2. Locked decisions

| Decision | Value |
|---|---|
| State model | Object/resource model: every asset is an object with an owner (Sui/Aptos style) |
| Language family | Move-family resource language: assets cannot be copied, silently destroyed, or moved except by their owner's authority |
| Parallel execution | Transactions touching different objects run simultaneously; shared objects are ordered by consensus |
| Ethereum compatibility | FUTURE add-on (EVM layer) so Ethereum developers can port apps |
| App upgrades | Locked (immutable) by default. Upgradeable only if declared at deployment; wallets must display the upgrade authority |
| App fees | Paid in ZTHR (details in ZTH-SPEC-008) |
| ZTHR protection | No app can mint ZTHR or change its supply. ZTHR exposes transfer and burn only |

## 3. Core rules
3.1 **Owned objects** (coins, NFTs, device wallets) can be used only by their owner's signature.
3.2 **Shared objects** (trading pools, marketplaces) can be used by anyone under the object's rules; access is ordered by consensus.
3.3 Every transaction declares which objects it reads and writes. Non-overlapping transactions execute in parallel; conflicts are resolved deterministically by DAG order (SPEC-005).
3.4 **Capabilities.** Powers such as "mint this token" or "upgrade this app" exist only as explicit capability objects created at deployment. If no capability exists, the power does not exist. Wallets show which capabilities exist.
3.5 Execution is deterministic: same inputs give the same result on every node.

## 4. Built-in object types (planned)
- **ZTHR coin** (protocol-defined, reserved)
- **User token** (SPEC-003)
- **Device wallet** with owner-set spending rules (SPEC-010)
- **Recovery / inheritance** policy object (SPEC-010)
- **Escrow** (lockbox) for AI marketplace jobs
- **Payment channel** (SPEC-005, later)

## 5. Privacy interaction
5.1 Private ZTHR transfers use the shielded pool (SPEC-006).
5.2 Private smart contracts are FUTURE. Contracts interact with transparent objects or with shielded value via turnstile-checked boundaries.

## 6. Threats

| Threat | Mitigation |
|---|---|
| Hidden mint in a token | Mint capability must exist at creation and is visible |
| Rug via secret code upgrade | Immutable by default; declared upgrade authority shown in wallets |
| Re-entrancy / double-spend bugs | Resource language rules; objects can't be duplicated |
| App drains funds it doesn't own | Owned objects require owner signature |
| Spam / infinite loops | Fees per computation step (SPEC-008) |

## 7. Open issues
1. Exact VM: adopt Move (Sui/Aptos dialect) vs fork vs new Move-family VM.
2. Limits on computation and storage per transaction.
3. EVM compatibility design and timing.
4. Storage rent / state growth (keeps home nodes viable).

## 8. Changelog
- Oct 2, 2026: Direction LOCKED: object model, Move-family, parallel execution, immutable-by-default apps, fees in ZTHR, EVM compatibility later.
