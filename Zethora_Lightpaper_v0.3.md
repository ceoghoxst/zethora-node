# ZETHORA
### Fair money for people and machines.
### Lightpaper v0.3 · Draft for public comment · October 2026

---

## 1. Summary

Zethora is a Layer-1 proof-of-work blockchain that combines three properties no single network has brought together before:

- **Bitcoin's fair scarcity** — 100,000,000 ZTHR, ever. No premine. No VC allocation. Every coin is mined.
- **Kaspa's speed** — a BlockDAG ordered by GHOSTDAG, target ~1 block per second.
- **Monero's home mining** — CPU-friendly proof-of-work (RandomZ) that any home computer can run.

It adds **Zcash-grade privacy** using Orchard 0.16.0. Privacy is integrated and working on the private devnet. Private sending is disabled on testnet and mainnet until an independent cryptographic review is complete — that review is being arranged now.

**Programmability (smart contracts) is planned research, not a current feature.** See Section 5.3. It requires a dedicated engineering team and will be pursued when resources allow. It is not promised for testnet or mainnet.

**Status: prototype.** A private Zethora devnet runs on a home PC. There is no public network yet.

---

## 2. Why Zethora

Bitcoin began on home computers. Today it is mined in warehouses and every balance is public forever. Ethereum made money programmable but began with a presale. Solana is fast but asks for data-center hardware. Monero is private and home-mineable but slow. Zcash is private but CPU mining is impractical.

Each excels at one or two things. None is **fair, fast, home-mineable, and private** at once.

| Property | Inspired by | In Zethora |
|---|---|---|
| Scarcity | Bitcoin | 100,000,000 ZTHR, every coin mined, no premine |
| Speed | Kaspa / Solana | BlockDAG, ~1 block per second |
| Home mining | Monero | RandomZ CPU proof-of-work |
| Privacy | Zcash | Orchard 0.16.0 (integrated; under review) |
| Programmability | Ethereum | **Planned research, not built** |

---

## 3. Principles

- **Fair launch.** Genesis holds 0 coins. No premine, presale, founder, or investor allocation.
- **No owner.** No admin key, pause switch, freeze power, or upgrade override exists for anyone. Not for the builders. Not for any company.
- **Fixed money rules.** Supply and issuance can never change. Software that changes them is not Zethora.
- **Privacy by default, honestly disclosed.** Anyone choosing transparency is clearly told what becomes public.
- **Security over speed of launch.** Audits, formal verification, and a long public testnet come first.
- **Home-computer rule.** If speed and decentralization conflict, a normal home computer must still be able to run a node and mine.
- **No price promises.** Zethora makes no claims about the future value of ZTHR.

---

## 4. Monetary Policy

*(unchanged from v0.2 — see previous sections)*

---

## 5. Design Overview

*(5.1, 5.2, 5.4, 5.5, 5.6, 5.7 unchanged)*

### 5.3 Programmability — planned research

Zethora does not currently support smart contracts. The `simpa` crate in the repository is a Kaspa network simulator inherited with the fork; it is not a virtual machine and provides no smart-contract execution.

**If** programmability is added in the future, the design direction is an object-model language in the Move family (as used by Sui and Aptos) — where every asset is an object with an owner and the language prevents copying or silently destroying assets. Ethereum compatibility would be considered only after that.

**What this requires:**

- A bytecode execution engine with a formal specification
- Independent cryptographic and formal-methods review of VM semantics
- A wallet and tooling ecosystem
- A dedicated engineering team, funded over multiple years

**What this is not:**

- It is not promised for testnet.
- It is not promised for mainnet.
- It is not a current feature.
- It may not ship at all if it cannot be built to a safety standard the community accepts.

Any future proposal will go through a public Zethora Improvement Proposal (ZIP) and will be evaluated on its own merits, including whether the security case is strong enough to ship.

---

## 6. Governance and Upgrades

*(unchanged)*

---

## 7. Security and Launch

*(unchanged)*

---

## 8. Ecosystem

**What DeionRaven Labs builds.** DeionRaven Labs is the lead builder of Zethora, not its owner. It holds no coins except those it mines or buys like anyone else. It earns through products built on top:

- The Zethora app: wallet, home-mining dashboard, phone remote
- A block explorer
- Family money tools: vaults, kids' funds, allowances, inheritance
- Later: any AI or device products that use Zethora natively

**What DeionRaven Labs does not have.** No protocol privileges. No admin keys. No ability to change supply, freeze accounts, or pause the network. If the company disappeared tomorrow, the chain would continue running.

---

## 9. Roadmap

| Phase | Focus |
|---|---|
| 1. Specification | Core specs published for public comment |
| 2. Prototype | Working private devnet (current) |
| 3. Public testnet | Minimum six months, open to all |
| 4. Mainnet | Only when every launch gate passes |
| 5. Ecosystem | Apps, launchpad, tools |
| Research | Programmability, if pursued |

---

## 10. Get Involved

Read the specifications, open issues, and propose changes through ZIPs. Builders in Rust, cryptography, consensus, wallets, and security are welcome. Contributors receive credit — never coins. The fair launch stays fair.

---

**Disclaimer.** This document describes a proposed design that may change. It is not an offer to sell, not investment advice, and makes no representation about the future price or value of any asset.

*Wake Up From The Dream World.*