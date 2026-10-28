# ZTH-SPEC-010: Wallets, Recovery, Inheritance and Device Wallets

**Project:** Zethora (ZTHR). Built by DeionRaven Labs.
**Status: LOCKED (Oct 2, 2026).** Timing parameters OPEN (set on testnet).
**Depends on:** ZTH-SPEC-002, ZTH-SPEC-006.

## 1. Purpose
Make Zethora the coin people can't lose, can pass on to family, and can safely give to their devices, while users always hold their own keys.

## 2. Locked principles
2.1 **Self-custody.** Users hold their own keys. No company, including DeionRaven, can access or move user funds.
2.2 **Default key storage:** the phone's secure chip (Secure Enclave / StrongBox), unlocked by face or fingerprint.
2.3 **Hardware wallets** (Ledger/Trezor-style) fully supported.
2.4 **Private by default;** transparent mode only with the SPEC-006 warning.
2.5 **View keys** created and shared only by the owner.

## 3. Recovery (LOCKED)
3.1 Setup walks every user through recovery (skippable). Any one configured path can restore a wallet:

| Path | Status | Depends on |
|---|---|---|
| Backup phrase (written words) | Default, strongly prompted | Only the user |
| Passkey synced via Apple/Google | Optional | User's Apple/Google account |
| User's own spare devices | Optional | Only the user |
| Trusted people (2 of 3) | Optional | Other people |

3.2 The app recommends at least one path that does not depend on other people.
3.3 Guardians (people or devices) hold only a share of a recovery key. They can never move funds; they can only help restore the owner's wallet to the owner's new key.
3.4 Guardian-based recovery has a waiting period (proposed 7 days) with alerts to all of the owner's devices; any owner action cancels it.
3.5 Yearly "guardian check-up" reminder; inactive guardians are flagged for replacement. Guardians can be changed any time.
3.6 Protocol support required: passkey signature type (P-256 / secp256r1) as a native signature scheme.

## 4. Inheritance (LOCKED)
4.1 Optional. The owner sets beneficiaries and percentage splits.
4.2 Beneficiaries can be existing wallets, newly created wallets, or claim codes (for people without wallets yet, e.g. young children).
4.3 Inactivity timer: default 1 year, adjustable by the owner. Any owner activity resets it.
4.4 When the timer expires: warnings to the owner first; then beneficiaries may start a claim; a second waiting period follows; any owner activity cancels.
4.5 If uncancelled, coins transfer automatically per the splits.
4.6 Beneficiary lists are private (encrypted) until a claim is made.
4.7 Cash-out and mailed checks to heirs are an off-chain DeionRaven service via licensed partners (money-transmitter licensing, identity and death-certificate checks). Not protocol.
4.8 Does not replace a legal will; users should coordinate with an estate attorney.

## 5. Device wallets (LOCKED)
5.1 Devices (cars, robots, AI agents) can hold their own wallets as objects (SPEC-002).
5.2 Owners set spending rules: limits per day/transaction, allowed recipients, allowed categories, expiry.
5.3 Owners can pause or revoke a device wallet instantly.

## 6. Family features (app level, DeionRaven)
Family vaults, kids' funds unlocking at a set age, allowances, shared family treasury (2-of-3 adults), recurring savings. Built on SPEC-002 objects. Any yield products require legal review.

## 7. Threats

| Threat | Mitigation |
|---|---|
| Lost phone | Any recovery path |
| Guardians collude | Guardians can't move funds; waiting period with alerts and cancel |
| Falling out with guardians | Guardians optional; change anytime; non-people paths recommended |
| Apple/Google account compromise | Passkey optional; other paths available |
| Inheritance triggered by mistake | Warnings, long default timer, cancel windows |
| Phishing / user tricked into signing | Clear transaction previews and warnings in wallet |
| Device wallet hacked | Spending limits; instant revoke |

## 8. Open issues
1. Waiting-period lengths (recovery, inheritance claim).
2. Exact guardian cryptography (threshold scheme).
3. Claim-code format and security.
4. Device wallet rule language.

## 9. Changelog
- Oct 2, 2026: LOCKED: self-custody, secure-chip default, hardware wallets, multi-path recovery (phrase default; passkey, own devices, guardians optional), inheritance with claim codes, device wallets.
