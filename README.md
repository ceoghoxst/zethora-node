# Zethora (Testnet)

**Zethora Testnet is currently LIVE.**
- **Version:** v0.1.1-testnet.1
- **Download:** https://tinyurl.com/Zethora-Testnet
- **Live Network Commit Hash:** e0c180c55d6094be568f73f7eebf1d6c324d1e36
- **Network Status:** Mining & Syncing
- **Privacy Status:** Shielded transactions are disabled on this build. See
  [Privacy status](#privacy-status) below.

---

## Overview

Zethora is a proof-of-work Layer 1 derived from the Kaspa codebase. It keeps
Kaspa's GHOSTDAG BlockDAG consensus and 1 block-per-second cadence, and adds
its own emission schedule, a RandomZ proof-of-work algorithm, and an optional
shielded-transaction layer built on Zcash Orchard.

- **Supply:** 100,000,000 ZTHR hard cap, enforced by consensus rules. No
  premine, no allocation, no owner.
- **Consensus:** GHOSTDAG, 1 BPS on public networks.
- **Mining:** RandomZ, a RandomX variant tuned for Zethora. CPU-mineable and
  ASIC-resistant by design.
- **Base layer:** Kaspa's Rust implementation. Zethora forks it rather than
  reimplementing consensus.

No token sale, no presale, no smart contracts.

---

## Why Zethora

Satoshi built Bitcoin so people could hold value no one could freeze, seize,
or print away. Somewhere along the way, crypto drifted back toward the system
it was meant to escape: companies chasing profit and permission, and launches
built to drain regular people who cannot afford the loss.

In 1933, Executive Order 6102 required Americans to surrender privately held
gold to the Federal Reserve. It was legal, and it happened. The lesson for
Zethora is about self-custody: when you hold your own keys, no third party
can move or freeze your balance.

---

## What Zethora takes from the chains before it

**Scarcity from Bitcoin.** 100,000,000 ZTHR hard cap. No premine. No
allocation. No owner. The supply is enforced by consensus rules, not by a
foundation or a company.

**Home mining from Monero.** RandomZ, a RandomX variant tuned for Zethora.
Designed for ordinary CPUs (ASIC-resistant).

**Privacy from Zcash: built, currently disabled.** Orchard 0.16.0, used
unmodified: shielded sends, shielded receives, unshielding back to
transparent. The primitive is upstream Zcash code, unchanged. It is disabled
on testnet and mainnet; see [Privacy status](#privacy-status).

**Fast settlement from Kaspa.** GHOSTDAG BlockDAG, configured for 1 block per
second on the public networks. Kaspa's Rust codebase is the base; Zethora
forks it rather than reinventing consensus.

**Programmability from Ethereum: future research, not built.** Private
payments come first. Contracts may never come. We will not promise what we
cannot deliver.

---

## Emission: smooth decay, not halving

The block reward shrinks slightly every block and halves about every 8 years
(no sudden halvings). About 50 percent of the 100M supply is mined in the
first 8 years, 75 percent by 16 years. See
consensus/src/processes/zethora_subsidy.rs for the schedule.

The smooth decay means the door stays open longer. People who arrive later
are not stuck at the bottom while early insiders hold everything. Compare to
Bitcoin, where about 75 percent is mined by year 8.

---

## Who controls Zethora

**The protocol has no admin key and no pause key.** Rules change only through
new node software that operators choose to run. There is no RPC, transaction,
or upgrade mechanism that lets any party alter consensus rules on a running
node.

**The reference implementation is maintained by DeionRaven (Deion Smith).**
Anyone can run it. Anyone can fork it. Anyone can propose changes. The network
belongs to whoever runs a node.

**Private sends are currently disabled on testnet and mainnet.** (Plan, CEO
decision 2026-10-27: testnet enables them as an experimental, unreviewed
feature after F2; mainnet stays disabled until an independent review. Today's
code still disables both.) The switch
is compile-time, set by network type in
consensus/src/consensus/services.rs:147-151. It is enabled only on devnet
and simnet. To change it for testnet or mainnet, operators must install new
node software that chooses to run the updated rules; operators who do not
upgrade continue on the old rules and fork. When the switch is off, any transaction that carries a private payment is
rejected with TxRuleError::InvalidPrivatePayment (see check_private_payment in
consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs).
This includes shielding (adding coins to the pool), private sends, and unshielding.
This behavior is emergency switch level (a) as described in ZTH-SPEC-006 Section 7.3.

---

## What is live today

**Live on testnet:**
- Full node with GHOSTDAG consensus at 1 BPS
- CPU mining with RandomZ
- `zethora-wallet` CLI: `balance`, `receive`, `send`, `history`, `sync`
- Tabbed Windows GUI (Miner Dashboard + Wallet) with a transaction-history grid

**Live on devnet only:**
- Shielding (transparent to private)
- Private sends and unshielding

**Not live:**
- **Shielded transactions on testnet and mainnet.** See
  [Privacy status](#privacy-status).
- **Mainnet.** Not launched.
- **Any token.** There is no token. There will be no presale. There will be
  no airdrop. ZTHR is created only by mining.
- **Smart contracts.** Not built, not planned. Future research only.

---

## The application

The Windows build ships a single-window GUI, launched from `Zethora.cmd`
(installed shortcut: **Zethora**). It manages the node and miner processes
directly; there is no separate console to watch.

**Tab 1 - Miner Dashboard.** Start/stop controls for the node and miner, live
status tiles (node sync, miner state, block height, blocks found), the current
balance, and a scrolling log.

**Tab 2 - Wallet.** Balance read from the wallet itself, a transaction-history
grid, and the Receive and Send actions.

The GUI does not parse the miner's log to find your balance. It asks the wallet,
so the figure on screen is the figure the wallet would spend.

### Wallet

The wallet is a separate binary, `zethora-wallet.exe`, shipped alongside the
node and miner. It is currently testnet-only: it refuses to run against any
other network unless `--testnet` is passed.

| Command | Purpose |
| --- | --- |
| `balance` | Current spendable balance, read from the node |
| `receive` | Prints your address; derived from your key file, never changes |
| `send <address> <amount>` | Sends ZTHR; supports `--dry-run` |
| `history` | Transaction ledger; `--limit N` and `--json` supported |
| `sync` | Reconciles local wallet state with the chain |

```powershell
zethora-wallet balance --testnet
zethora-wallet receive --testnet
zethora-wallet send zethoratest:... 1.5 --testnet
zethora-wallet history --limit 50 --json
```

The GUI's history grid is driven by `history --limit 50 --json`. Amounts are
printed newest first, with the full transaction id available on hover.

Wallet and GUI walkthrough: [docs/WALLET-WALKTHROUGH.md](docs/WALLET-WALKTHROUGH.md)

---

## Privacy status

Zcash Orchard (Halo2) privacy is currently disabled pending independent
cryptographic review. The UI toggle is locked.

The switch is compile-time and set by network type
(consensus/src/consensus/services.rs). When it is off, any transaction
carrying a private payment is rejected with
`TxRuleError::InvalidPrivatePayment`, covering shielding, private sends, and
unshielding. The GUI exposes the control but disables it.

Regression tests cover parallel nullifier defense, turnstile accounting, anchor
maturity, and private state fingerprint. That test coverage is not a substitute
for review by an outside party. See [docs/ZTH-SPEC-006.md](docs/ZTH-SPEC-006.md)
for the spec and Appendix C for the open questions.

If you are a ZK cryptographer or know one, we would like to hear from you. DM
us on X at @ZethoraNetwork, or open an issue at
github.com/ceoghoxst/zethora-node/issues. Reviewers get named credit in the
specs.

---

## Seed nodes

Testnet nodes discover peers through community-operated seed nodes. Running one
is the most direct way to help the network stay reachable without depending on
a single operator.

Guide for community members, written for a small Linux VPS (Ubuntu 22.04 or
24.04): [docs/RUN-A-SEED-NODE.md](docs/RUN-A-SEED-NODE.md)

---

## Mining is a business, not passive income

Mining requires hardware, electricity, uptime, and management. It is not
passive income. Early miners who take operational risk earn a larger share of
the emission curve in exchange. Difficulty adjusts upward as more hashrate
joins the network; this is by design.

**We do not promise returns, yields, passive income, or guaranteed rewards.
This is not an investment. There is no promise of value or returns.** If you
are looking for an investment product, Zethora is not that.

---

## What we do not claim

This README is written to match what the code actually does. We will not
claim any of the following, and if you see these claims in the wild, they
are not from us:

- **No independent-review claim.** Shielded transactions are disabled pending
  an external cryptographic review that has not yet happened. No part of the
  privacy layer is presented as reviewed by an outside party.
- **No farm detection claim.** Zethora does not detect or block industrial
  mining. Any anti-farm feature is undecided and post-testnet.
- **No timeline claim.** Testnet and mainnet ship when the code is ready.
  We do not publish dates. Public testnet runs at least 6 months before
  mainnet.
- **Launch promises changed 2026-10-28, openly.** Mainnet launches without a
  paid audit and says so; private payments stay off on mainnet until an
  independent review. Details and the original promises:
  docs/specs/ZTH-SPEC-012-security.md.
- **No passive income claim.** Mining is operational work.
- **No price or token claim.** No token exists. No presale. No airdrop.
- **No Solana-level speed claim yet.** We say fast until we spec and
  benchmark it publicly.
- **Not an investment.** No promise of value or returns.

---

## Documentation

- Getting started (Windows): docs/WINDOWS-GETTING-STARTED.md
- Mining walkthrough: docs/MINING-WALKTHROUGH.md
- Wallet and GUI walkthrough: docs/WALLET-WALKTHROUGH.md
- Running a seed node: docs/RUN-A-SEED-NODE.md
- Privacy layer spec: docs/ZTH-SPEC-006.md
- Lightpaper: Zethora_Lightpaper_v0.3.md
- Testnet roadmap: docs/TESTNET-ROADMAP.md
- RandomZ DoS protection: docs/ZTH-IMPL-020-randomz-dos-ban.md
- Internal notes / audit trail: CLAUDE.md
- Persistence rules: docs/PERSISTENCE-RULES.md

Devnet is a private team test network, not for public use. Coins have no value
and nothing carries over to testnet or mainnet. No token exists.

---

## License

ISC License, inherited from the Kaspa codebase. See LICENSE for the full text.

This project also includes third-party components under their own licenses:
  - RandomX and RandomZ: see randomz/LICENSE and randomz/RandomX/LICENSE
  - Zcash Orchard: see zethora-shielded/Cargo.toml for the pinned version (upstream crate license applies)

The Orchard cryptographic library and RandomX are the property of their
respective upstream projects. Zethora's only modification to RandomX is
documented in randomz/.