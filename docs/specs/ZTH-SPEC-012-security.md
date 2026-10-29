# ZTH-SPEC-012: Security Review and Launch Gates

**Project:** Zethora (ZTHR).
**Status: LOCKED (Oct 2, 2026).**
**Depends on:** all prior specs.

> **AMENDED 2026-10-28 (CEO decision, published openly).** Zethora is a
> bootstrapped project with no funding. Some gates below cannot be met
> without money, so they changed. Original text is kept below for the record.
>
> - **Gate 1 (paid audits) and gate 2 (formal verification): replaced.**
>   Mainnet launches without a paid audit and says so plainly ("not
>   audited"). Instead: public testnet, published threat model
>   (docs/THREAT-MODEL.md), internal AI-assisted red-team rounds turned into
>   tests, and open review invited through SECURITY.md.
> - **Privacy on mainnet:** private payments stay OFF at mainnet launch and
>   turn on only after an independent review of the private-pool integration
>   (by volunteers, or paid later from grants or donations if they come).
> - **Gate 4 and 3.4 (bug bounty in dollars):** credit and public thanks now;
>   a paid bounty only if funding exists. We will not promise money we do not have.
> - **Gate 6(c) (object engine):** not applicable; smart contracts are not built.
> - **Unchanged:** at least 6 months of public testnet (3.1), testnet attack
>   drills (gate 5), supply checks verified on testnet (gate 3), the
>   home-computer test (gate 7), wallet recovery testing (gate 8), and
>   testnet coins never converting to mainnet coins (3.3).
> - Why: an honest smaller promise we can keep beats a bigger one we cannot.

## 1. Purpose
Nothing reaches mainnet until it has been attacked, audited, and proven on a public testnet.

## 2. Launch gates (all required)
1. At least 2 independent security audits of the node software, plus a dedicated audit of the privacy cryptography.
2. Formal verification of privacy circuits and supply rules.
3. Turnstile accounting and per-block supply checks running and verified on testnet.
4. Public bug bounty live before mainnet.
5. Testnet attack drills: 51% attempt, spam/fee spikes, counterfeit attempts, eclipse/network isolation, reorgs.
6. The three hard joints solved and tested: (a) private-transaction verification at 1 block/sec, (b) RandomZ verification at 1 block/sec, (c) shielded value inside the object engine.
7. Home-computer test: a normal laptop meeting the SPEC-009 target runs a full node at full network load.
8. Wallet recovery and inheritance flows tested end to end.

## 3. Testnet
3.1 Public testnet runs a minimum of 6 months before mainnet.
3.2 Mainnet launches only when all gates pass, even if that takes longer than 6 months.
3.3 Testnet coins have no value and never convert to mainnet coins.
3.4 Testers are recognized with credit, badges, and dollar bug bounties funded by DeionRaven. No coins.

## 4. Consolidated threat list (see individual specs)

| Area | Main threats | Spec |
|---|---|---|
| Money | Hidden minting, overflow, premine | 001 |
| Execution | Hidden mint/upgrade, re-entrancy, spam | 002, 003 |
| Consensus | 51% attack, selfish mining, ASICs | 005, 011 |
| Privacy | Counterfeit via circuit bug, IP tracking | 006 |
| Fees | Spam, fee spikes, miner fee stuffing | 008 |
| Network | Eclipse, Sybil, bloat | 009 |
| Wallets | Lost keys, guardian collusion, phishing | 010 |
| Governance | Miner veto, chain split, developer capture | 011 |

## 5. After launch
5.1 Bug bounty stays open permanently.
5.2 Re-audit before every consensus upgrade.
5.3 Public incident reports for every security event.

## 6. Changelog
- Oct 2, 2026: LOCKED: 8 launch gates, 6-month minimum testnet, launch only when all gates pass.
