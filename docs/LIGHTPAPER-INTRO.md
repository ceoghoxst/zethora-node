# Lightpaper Introduction (DRAFT)

## Why this chain exists

Satoshi Nakamoto's Bitcoin paper was published in 2008. It described a system
where value could be held by anyone, transferred without permission, and
verified by everyone. The core promise was simple: money you control.

Since then, crypto has drifted. Some projects became companies with boards
and quarterly targets. Some launches became lotteries structured to extract
from late arrivals. The permissionless promise survived, but the self-custody
promise eroded. Users can move tokens; they cannot necessarily hold them.

In 1933, Executive Order 6102 required Americans to surrender privately held
gold to the Federal Reserve. It was legal, and it happened. The lesson for
Zethora is about self-custody: when you hold your own keys, no third party
can move or freeze your balance.

## What we built, and from what

We did not start from scratch. The good ideas already existed, scattered
across chains that each got part of the answer right.

Bitcoin proved that scarcity with no owner is possible. 21 million coins,
no company, no pause button. We take that: 100 million ZTHR, hard cap, no
premine, no allocation, enforced by consensus.

Kaspa proved that a BlockDAG at high block rate can work in production.
Its Rust codebase is the base Zethora is built on. We did not rewrite the
consensus. We inherited it, and configured it for 1 block per second.

Zcash proved that strong privacy can be built on real cryptography. Orchard,
their latest shielded pool, uses Halo2 and does not trust a setup ceremony
for soundness. We take Orchard unmodified. The privacy primitive is theirs;
we put it in a different consensus envelope.

Monero proved that CPU mining is viable at scale. RandomZ, our variant of
RandomX, is tuned so that a modern laptop can participate. Designed for
ordinary CPUs (ASIC-resistant). No permissioned hashrate.

What Zethora adds is the integration: Orchard inside GHOSTDAG, with a
turnstile that tracks the supply flowing into and out of the private pool.
That integration is the work.

## What we will not do

We will not launch private sends on mainnet until an independent reviewer
checks the Orchard integration. On testnet, where coins are worth zero, they
will run as a clearly labeled experimental, unreviewed feature so bugs are
found early. The gate is enforced by node software, not by a marketing
decision. See ZTH-SPEC-006 Section 7.3 for
the emergency switch details.

We will not sell a token. ZTHR is created only by mining. No presale, no
airdrop.

We will not promise passive income from mining. Mining is a business. Early
miners take operational risk and earn a larger share of the emission curve
in exchange. Anyone who tells you mining is passive is selling you something.

We will not publish dates for testnet or mainnet. They ship when the code is
ready and the audit is complete. "When it's done" is a real answer.

We will not detect or block industrial mining. Any anti-farm feature is
undecided and post-testnet.

We will not promise a return on anything. This is not an investment. There
is no promise of value or returns.

---

The rest of this paper describes the mechanism: the consensus, the privacy
layer, the emission curve, the supply ledger, and the open questions we want
independent reviewers to attack. Read it as a working document, not a
promise. The code is the truth; the paper is the map.

If you are a cryptographer, a privacy researcher, or a home miner, and you
want to help test this, we want to talk to you. The protocol is open. The
review is welcome. The chain belongs to whoever runs it.