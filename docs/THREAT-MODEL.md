# Zethora threat model

One line per known way a chain gets hurt: our defense, the proof we have,
and what is still open. "Proof" means a test or a check anyone can rerun.
Nothing here counts as an audit. Last updated: 2026-10-27.

Status key: DONE (defense + proof) / PARTIAL / OPEN / LIVE-ONLY (defense can
be built now, but only a real network with many miners can prove it).

| # | Threat (real-world example) | Defense | Proof today | Status | Next action |
|---|---|---|---|---|---|
| T1 | Supply / inflation bug (Bitcoin 2010 overflow, Monero 2017) | Supply ledger checked every block; turnstile on private pool; checked arithmetic (docs/ARITH-SAFETY.md) | BALANCED on every block; ledger tests | DONE | Outside audit |
| T2 | Private-pool double spend | Nullifier set, parallel-sibling filter | zethora_parallel_nullifier.rs (AB/BA) | DONE | Outside review |
| T3 | One bad tx stalls the chain (F1) | Per-transaction turnstile in merge order | 6 tests + fail-when-removed (PR pending) | PARTIAL | CTO review, merge |
| T4 | Counterfeit via ZK flaw (Zcash 2018) | Orchard unmodified; privacy OFF on mainnet (G11); testnet experimental after F2 | G11 refuses before decode | PARTIAL | ZK cryptographer review before privacy ON |
| T5 | Junk-block / bad-PoW spam (DoS) | Peer ban on invalid RandomZ PoW | G5 live ban test | DONE | Load test on testnet |
| T6 | Secret premine accusation | Genesis stamped with a fresh Bitcoin block hash; no premine | Genesis audit doc | PARTIAL | Regen on launch day, publish how to verify |
| T7 | Deep reorg / 51% with rented hashrate (common for small CPU coins) | Kaspa finality depth: blocks older than the finality window cannot be reorged; RandomZ = rented hashrate must be rented as CPU (RandomX market exists) | Not tested for Zethora | OPEN | Confirm finality_depth value; test a finality-violating reorg is rejected; publish "wait N confirmations" guidance; LIVE-ONLY to prove |
| T8 | Selfish mining | GHOSTDAG gives less advantage than a single chain (Kaspa research) | None of our own | LIVE-ONLY | Monitor orphan/red-block rate on testnet |
| T9 | Eclipse attack (new node fed fake chain) | More than one seed; peers from different sources | One seed only | OPEN | Second seed before testnet if a free server is found; before mainnet at latest |
| T10 | Timestamp / difficulty manipulation | Kaspa past-median-time and timestamp deviation tolerance; difficulty window | Inherited Kaspa tests only | PARTIAL | Run inherited DAA/timestamp tests on Zethora params; add one test with Zethora 1 bps values |
| T11 | Chain split between software versions (Bitcoin 2013) | Explicit network/version checks; one release at a time | Not tested | OPEN | Rule: any consensus change ships as a coordinated activation height; test old vs new node behaviour |
| T12 | Fake download / malware miner | One official link (site); SHA256SUMS; readable scripts | Checksums verified per release | PARTIAL | Show checksums on the site; code signing before mainnet |
| T13 | Key file theft / loss | Key stays local, warning in app, FAQ | Docs | PARTIAL | Backup reminder in app; encrypted key option later |
| T14 | Botnets mining on hacked PCs (Monero) | Cannot be fully prevented on any CPU coin | n/a | ACCEPTED | Never claim farm or botnet detection |
| T15 | Dependency / supply-chain attack (malicious crate) | Pinned Cargo.lock; Orchard pinned to a rev; license scan (G12) | cargo-about inventory | PARTIAL | Add cargo-audit (known-vulnerability scan) to CI |
| T16 | AI-agent mistakes or prompt injection in our own code | Agents on branches only; CTO review before merge; Rule 4 tests; no secrets in repo | CLAUDE.md rules | DONE (process) | Keep enforcing |

## Before testnet (required, CEO decision 2026-10-27)
T3 merged; T7 finality test; T10 timestamp/difficulty test on Zethora params;
T11 activation rule (in CLAUDE.md) plus old-vs-new test; T12 verify section on
site (done) plus hashes posted at launch; T13 backup reminder in the app;
T15 cargo-audit workflow (added); T9 second seed; T6 genesis verify steps.

## Privacy (CEO decision 2026-10-27, option B)
Testnet: experimental privacy ON after T3 is merged and reviewed, labeled
unreviewed; G11 changed for testnet only, with a test that mainnet still refuses.
Mainnet: privacy ON only after T4 independent ZK review.

## Before mainnet (CEO decision 2026-10-28: bootstrapped, no paid audit)
- Mainnet launches with private payments OFF, stated plainly as "not audited".
  The public side is Kaspa's engine plus our supply ledger, covered by tests
  and red-team rounds.
- Private payments turn on for mainnet only after an independent review of
  the private-pool integration code (the "glue": ledger, turnstile,
  nullifiers, anchors, Orchard-in-merge-order). Sought from volunteers who
  like the project (Zcash community, reviewers), funded later by grants or
  donations if they come. No paid full audit is planned.
- Every item above DONE or explicitly ACCEPTED before mainnet.
