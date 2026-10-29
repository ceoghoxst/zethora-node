# CTO hand-off (things not recorded elsewhere)

Written 2026-10-28 by Claude (CTO). Read after CLAUDE.md and docs/F3-PLAN.md.

## Team and roles
- Deion (CEO): doesn't write code. Merges PRs on GitHub, runs commands on his PCs, relays messages.
- Claude (CTO / auditor): reviews all code and claims, writes the code (via branches + GitHub CI), checks
  things itself instead of asking Deion. Starts every message forwarded to other AIs with "Claude (CTO):".
- DeepSeek = TE (planning only). Its drafts are never published unchecked: it once wrote false claims
  ("audit in progress", "seed live") and signed as Claude. Check every TE claim against the repo.
- VP of Operations directs the CMO. Send ONE paste-ready VP update only when a whole section is done or the
  VP must know something; social guidance goes inside it. No separate CMO update.
- Cloud Claude coding sessions: the $100 credit is down to about $4. Emergency only; do the work in the
  CTO session with CI as the compiler.

## Public-claim rules
Only say what can be checked today. Never: "audited", "secure", farm detection, passive income, prices,
dates, "nobody else does this", positioning against Monero/Zcash. "In progress" only if someone is
actually doing it. DeionRaven Labs is a project name, not a company.

## Decisions on record (Oct 28)
- Bootstrapped: no paid audit. Mainnet launches with privacy OFF and says "not audited". Mainnet privacy only
  after a volunteer or grant-funded review of the private-pool glue. 6-month minimum testnet kept
  (ZTH-SPEC-012 amended openly).
- Option B: experimental privacy on TESTNET only, after F1 (merged) and the privacy-switch PR (pack 1 #14).
- Idle game: removed from the app (looked bad). Post-testnet: a real Godot game, off by default, removed if it
  costs over 1% hash speed. GPU mining: "later maybe".

## After F3 (pending list)
- Privacy-switch PR (testnet only, activation by DAA score, mainnet refuses; update STATUS/FAQ/site same day).
- Wallet Receive/Send in the Windows app.
- Threat-model tests T7, T10, T11. Second seed node. Red-team Round 2.
- Jordan's stranger test of the installer with docs/TESTNET-GUIDE.md. Website screenshots.
- Confirm the old repo ceoghoxst/zethora is archived (README already points here).
- Launch day: regen testnet genesis (TESTNET-LAUNCH G9), tag v0.1.0-testnet.1 (installer built by deploy.yaml),
  seed to testnet (port 26211), download button on the site, announce, founder address.
- Before mainnet: code signing, view keys, legal opinion before mainnet privacy, mainnet DNS seeders.

## PCs
Ryzen 5 2600 (C:\Users\deion) = reference for speed numbers (app baseline ~760 H/s). 2-core PC
(C:\Users\Rac436, repo at C:\Users\Rac436\zethora-node) = correctness tests only.
