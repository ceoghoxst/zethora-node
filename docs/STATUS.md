# Zethora status and known risks

Plain English, kept up to date. If something here is out of date, open an
issue. We publish this because trust comes before growth: you should know
what is unfinished before you spend any time on Zethora.

Last updated: 2026-10-27

## What works today (testnet, not launched yet)

- The node and CPU miner run on 64-bit Windows 10/11.
- One-window miner app (Zethora.cmd). It runs the miner at below-normal
  priority so your PC stays usable, and restarts the node or miner if one
  crashes (up to 3 times).
- Supply check on every block. The miner shows `BALANCED` when every coin
  in existence is accounted for. If it ever does not, stop and report it.
- Balance lookup for your mining address.
- No premine. Nobody, including the team, gets coins without mining.

## What is turned OFF on purpose

- **Private payments.** The private pool (based on Zcash Orchard, unmodified)
  is in the code, but testnet and mainnet refuse every private payment. It
  stays off until the two items below are done.

## Open items before private payments can be turned on

1. **Per-transaction turnstile (F1).** Today the private-pool safety check
   adds up a whole block at once. A single bad transaction could make a
   block invalid and stall the chain. The fix checks each transaction on
   its own. In progress.
2. **Independent cryptography review.** Nobody outside the project has
   reviewed the private-pool code yet. We are looking for a zero-knowledge
   cryptographer to do it.

## Not done yet (before mainnet)

- No independent security audit of the whole chain.
- Binaries are not code-signed, so Windows shows a warning the first time.
  Check the SHA256 hashes in SHA256SUMS.txt instead (see README.txt).
- Only one seed node. A second one is planned.
- One bundled library (malachite) is LGPL-3.0. We believe our use is
  compliant (source is available, notice included); a lawyer will confirm
  before mainnet.
- The miner is slower than the best RandomX miners. Speed work is planned.
- Some edge cases around block reorganizations in the private pool are
  only partly covered by tests (documented in docs/ZTH-SPEC-006.md).

## No token sale

No token is for sale. There is no presale, no airdrop and no ICO. Every
coin will be created by mining. Testnet coins cannot be sold or traded.

## Things we will never claim

- That testnet coins are worth anything. They are worth zero.
- Guaranteed income, "passive income", or any price.
- That Zethora is audited, until an audit is actually published.
- Launch dates before they are ready. We do not publish hard dates.

DeionRaven Labs is a project name, not a registered company.
