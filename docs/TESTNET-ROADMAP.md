# Zethora Testnet Roadmap

Status: Draft
Author: DeionRaven Labs
Date: Oct 14, 2026

## What "testnet launched" means

A stranger can clone the repo, follow the getting-started guide, run a node, connect to a seed, mine, see their balance, and send coins to another person.

Mining is the core activity on day one. Everything else is secondary.

Private sending stays DISABLED on testnet until the crypto review is complete. The crypto review does not block testnet launch.

## Mandatory before testnet opens

|#|Item|Why|Effort|
|-|-|-|-|
|1|Seed node running|Without one, strangers cannot find each other|1 hour (blocked on Oracle; $5 VPS solves it)|
|2|RandomZ DoS ban implemented|Without it, one attacker can take the network down|4-6 hours (Piece 1 done)|
|3|Windows getting-started guide|Most home miners use Windows|2-3 hours|
|4|Prebuilt Windows binary|Removes the 30-minute Rust compile barrier|1-2 hours setup, ongoing|
|5|Mining walkthrough|What to expect, expected hashrate, troubleshooting|1-2 hours|
|6|Wallet walkthrough|How to see balance, send, receive|1-2 hours|
|7|Testnet genesis verification|Confirm the regenerated genesis is what runs|30 min|

## Nice-to-have, not blocking launch

* B8 miner prebuild (30s stall every \~12 days)
* Multiple independent seed nodes (1 is enough; 3+ is better)
* Streaming private state download (matters at scale, not at launch)
* Basic block explorer
* Fix daemon integration test
* Prebuilt Linux binary

## Not needed for testnet

* Crypto review (only gates private sending)
* Smart contracts (simpa is work in progress)
* Launchpad, AI marketplace, mobile apps
* Any mainnet-specific hardening

## Suggested timeline

2-4 weeks of consistent work.

* Week 1: Seed node + finish ZTH-IMPL-020 DoS ban
* Week 2: Windows getting-started guide + prebuilt binary
* Week 3: Mining and wallet walkthroughs, tested by you on a fresh folder
* Week 4: Buffer. Fix what breaks. Announce.

Faster is fine. Slower is fine. Do not compress into less than 2 weeks: docs tested by strangers always surface surprises.

## What actually kills the project

Ranked by realistic probability:

1. Founder burnout. Four 20-hour days are not sustainable. The project needs 2-4 hour sessions over months, not sprints.
2. Nobody cares. A perfect testnet means nothing if nobody shows up. Solve this by shipping things people can try, not by writing more code.
3. A critical bug found after mainnet. Mitigated by fuzzing, audits, crypto review.
4. Money. Realistic cost is $5-20/month for a VPS. Least likely to kill it.

## Testnet launch gates

All must be true:

* \[ ] Seed node reachable from the public internet on TCP 26211
* \[ ] A fresh Windows PC can follow the guide and reach a running node
* \[ ] The same PC can start mining and see its balance grow
* \[ ] Two nodes on different networks can sync via the seed
* \[ ] ZTH-IMPL-020 DoS ban active and tested on devnet
* \[ ] Testnet genesis hash matches what is committed
* \[ ] Getting-started guide tested by someone who is not the author

## Open questions

* Prebuilt binaries or expect compilation? (Recommendation: binaries for Windows, source for Linux)
* Who runs the second seed? (Community or DeionRaven Labs)
* Announcement channel? (X, Reddit, Zcash forum, or all three)

