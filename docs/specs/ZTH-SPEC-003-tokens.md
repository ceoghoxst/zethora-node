# ZTH-SPEC-003: Native Tokens and Launchpad Standards

**Project:** Zethora (ZTHR). Built by DeionRaven Labs.
**Status: LOCKED (Oct 2, 2026).** Fee amounts and risk-card thresholds OPEN.
**Depends on:** ZTH-SPEC-001 (Section 10), ZTH-SPEC-002, ZTH-SPEC-006.

## 1. Purpose
Let anyone create tokens on Zethora, with protocol rules that make hidden tricks impossible, while never affecting ZTHR.

## 2. Protocol rules (apply to every token)
2.1 Anyone can create a token by paying a creation fee in ZTHR (amount in SPEC-008).
2.2 **Fixed supply by default.** New units can be minted only if a mint capability was created at launch. Wallets show whether it exists.
2.3 **No freeze by default.** A freeze capability is allowed only if declared at launch (needed for regulated dollar tokens). Wallets display a warning when it exists.
2.4 **No hidden upgrades.** Token code is immutable unless an upgrade capability was declared (SPEC-002 3.4).
2.5 Tokens can be private (shielded) under the same turnstile rule as ZTHR (SPEC-006 4.1).
2.6 Names and symbols are not unique at protocol level. The ZTHR identifier is reserved and cannot be imitated. Wallets mark verified tokens.
2.7 No token can mint, burn or alter ZTHR. ZTHR is created only by mining (SPEC-001).

## 3. DeionRaven launchpad (app level, not protocol)
3.1 Fair bonding-curve pricing: everyone buys and sells on the same automatic curve.
3.2 Launchpad tokens are created with no mint, no freeze, and no upgrade capability, permanently.
3.3 Liquidity is locked automatically when a token graduates to open trading.
3.4 Creator holdings are public; optional creator lock-up.
3.5 **Risk card** on every token, generated from on-chain facts:
- Creator share of supply (warning above a threshold)
- Top-10 holder concentration
- Mint / freeze / upgrade capability status
- Liquidity lock status
- Token age and trading activity
- Overall safety score (CryptoCheck)
3.6 Launchpad fees are DeionRaven revenue; other launchpads may compete on equal terms.
3.7 Legal review required before launch (launchpad operators have faced lawsuits).

## 4. What this cannot prevent (disclosed to users)
- Creators selling their own tokens.
- Misleading marketing and hype.
- Losses from price movement.

## 5. Open issues
1. Creation fee amount (SPEC-008).
2. Risk-card thresholds and scoring method.
3. Verified-token process (who verifies, how disputes work) without a central gatekeeper.

## 6. Changelog
- Oct 2, 2026: LOCKED: protocol token rules, launchpad standards, risk card.
