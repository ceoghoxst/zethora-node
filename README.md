# Zethora (ZTHR)

**Self-custodied digital property.**

Status: devnet phase. Private sends are disabled on testnet and mainnet until
an independent review of the Orchard integration is complete. No token, no
presale, no smart contracts.

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

**Privacy from Zcash.** Orchard 0.16.0, used unmodified. Shielded sends,
shielded receives, unshielding back to transparent. The Orchard primitive is
the audited, battle-tested Zcash code. We did not change it.

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

**Private sends are currently disabled on testnet and mainnet.** The switch
is compile-time, set by network type in
consensus/src/consensus/services.rs:147-151. It is enabled only on devnet
and simnet. To change it for testnet or mainnet, operators must install new
node software that chooses to run the updated rules; operators who do not
upgrade continue on the old rules and fork. When the switch is off, any
transaction whose payload attempts to spend from the private pool is rejected
with TxRuleError::InvalidPrivatePayment (see
consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs:171-175).
Coins can still move INTO the pool (shielding). They cannot move OUT. This
behavior is emergency switch level (a) as described in ZTH-SPEC-006 Section
7.3.

---

## What is live today

**Live on devnet:**
- Full node with GHOSTDAG consensus at 1 BPS
- Shielding (transparent to private) fully working
- Private sends and unshielding fully working on devnet only
- CPU mining with RandomZ
- Reference wallet

**Not live:**
- **Private sends on testnet and mainnet.** See the section above.
- **Public testnet.** Not open yet.
- **Mainnet.** Not launched.
- **Any token.** There is no token. There will be no presale. There will be
  no airdrop. ZTHR is created only by mining.
- **Smart contracts.** Not built, not planned. Future research only.

---

## The privacy review is the gate

Private sends are disabled until an independent ZK cryptographer reviews the
Orchard integration. The internal review is complete and backed by regression
tests. See docs/ZTH-SPEC-006.md for the spec, the mechanism descriptions,
and an honest list of open questions (Appendix C).

The tests cover parallel nullifier defense, turnstile accounting, anchor
maturity, and private state fingerprint.

If you are a ZK cryptographer or know one, we would like to hear from you.
DM us on X at @ZethoraNetwork, or open a GitHub issue at
github.com/ceoghoxst/zethora-node/issues. We are bootstrapped. Reviewers get
named credit in the specs.

---

## Team devnet docs (devnet is a private test network, not for public use)

Devnet is a private test network for the Zethora team. It is not public, coins have no value, and nothing carries over to testnet or mainnet. No token exists.

Setup guide: [docs/WINDOWS-GETTING-STARTED.md](docs/WINDOWS-GETTING-STARTED.md)

For mining: [docs/MINING-WALKTHROUGH.md](docs/MINING-WALKTHROUGH.md)
For wallet: [docs/WALLET-WALKTHROUGH.md](docs/WALLET-WALKTHROUGH.md)

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

- **No audit claim.** Private sends are gated on an external review that has
  not yet happened.
- **No farm detection claim.** Zethora does not detect or block industrial
  mining. Any anti-farm feature is undecided and post-testnet.
- **No timeline claim.** Testnet and mainnet ship when the code is ready and
  the audit is complete. We do not publish dates.
- **No passive income claim.** Mining is operational work.
- **No price or token claim.** No token exists. No presale. No airdrop.
- **No Solana-level speed claim yet.** We say fast until we spec and
  benchmark it publicly.
- **Not an investment.** No promise of value or returns.

---

## Documentation

- Privacy layer spec: docs/ZTH-SPEC-006.md
- Lightpaper: Zethora_Lightpaper_v0.3.md
- Testnet roadmap: docs/TESTNET-ROADMAP.md
- RandomZ DoS protection: docs/ZTH-IMPL-020-randomz-dos-ban.md
- Internal notes / audit trail: CLAUDE.md
- Persistence rules: docs/PERSISTENCE-RULES.md

---

## License

ISC License, inherited from the Kaspa codebase. See LICENSE for the full text.

This project also includes third-party components under their own licenses:
  - RandomX and RandomZ: see randomz/LICENSE and randomz/RandomX/LICENSE
  - Zcash Orchard: see zethora-shielded/Cargo.toml for the pinned version (upstream crate license applies)

The Orchard cryptographic library and RandomX are the property of their
respective upstream projects. Zethora's only modification to RandomX is
documented in randomz/.