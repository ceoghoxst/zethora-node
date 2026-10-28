# Zethora Testnet Launch

Status: Approved by CTO 2026-10-22 (revision 5)
Author: Lead Engineer
Date: 2026-10-22
Audience: CTO (sign-off), CEO (decision), future sessions

## 0. Purpose and scope

This document defines how Zethora testnet is launched: the gates that must
pass before the genesis is finalized, the exact regeneration steps, the
decision on a fresh public genesis message, the launch order, and the
rollback policy for the first hours. It does not change consensus code. The
testnet genesis timestamp stays provisional until the gates in Section 1
pass.

Private sending is NOT live on testnet. It is devnet-only until an outside
crypto review (CLAUDE.md:46; docs/TESTNET-ROADMAP.md:13).

Revision history:
- rev 3 incorporated the first CTO audit (fixes 1-3, decisions O1-O4).
- rev 4 resolved the four open items O5-O8.
- rev 5 applied the CTO final-audit fixes: seed rebuild wording (Section
  4), payload math correction (Section 3), Hetzner firewall citation (G1),
  and the values-file deletion note (Section 2).

## 1. Gates before final genesis regeneration

Regenerate the testnet genesis only after ALL of the following are true.

G1. Testnet seed reachable from the public internet on TCP 26211, running
    --testnet.
    Network: testnet-10. Source: params.rs:637 with_suffix(Testnet, 10);
    params.rs:571-574 refuses any other testnet suffix. P2P port 26211
    (CLAUDE.md:173).
    Today: PC-to-devnet-seed sync verified (CLAUDE.md:399-406), devnet seed
    hardened (CLAUDE.md:408-414). The current Hetzner seed runs --devnet
    (CLAUDE.md:411). Per CTO decision O7 it is rebuilt for testnet at
    launch (Section 4 step 2). A testnet seed is NOT running today.
    Hetzner server firewall: open TCP 26211 (today only devnet 26611 is
    open).
    Client side: --seed=<host or IP> (CLAUDE.md:176-177); the flag takes no
    port and uses the network default P2P port. Clients must pass
    --testnet.
    One seed is sufficient for launch (docs/TESTNET-ROADMAP.md:30; CTO
    decision O7). A second independent seed is a nice-to-have, not a gate.

G2. A fresh Windows PC can follow the guide and reach a running node.
    Source: docs/TESTNET-ROADMAP.md:68. NOT verified.

G3. The same PC can start mining and see its balance grow.
    Source: docs/TESTNET-ROADMAP.md:69. NOT verified.

G4. Two nodes on different networks can sync via the seed.
    Source: docs/TESTNET-ROADMAP.md:70. Partially verified: one PC plus
    one seed (CLAUDE.md:401). Two independent strangers NOT tested.

G5. ZTH-IMPL-020 DoS ban active AND verified with a LIVE evil-peer test
    on devnet.
    Source: docs/TESTNET-ROADMAP.md:71; CLAUDE.md:293-298 (unit tests pass,
    devnet startup clean). Per CTO decision O2 (2026-10-22), the existing
    unit tests are necessary but NOT sufficient. The live evil-peer test
    (CLAUDE.md:300-301, estimated 3-4 hours) is required before strangers
    connect. G5 is NOT met today.

G6. Testnet genesis hash matches what is committed.
    Source: docs/TESTNET-ROADMAP.md:72. Satisfied only after Section 2 runs
    on the final commit.

G7. Getting-started guide tested by someone who is not the author.
    Source: docs/TESTNET-ROADMAP.md:73. NOT verified.

G8. Prebuilt Windows binary published.
    Source: docs/TESTNET-ROADMAP.md:22 ("Removes the 30-minute Rust compile
    barrier"). NOT built.

G9. cargo test --release -p kaspa-consensus-core test_genesis_hashes passes
    on the FINAL regen commit.
    Per CTO decision O3 (2026-10-22), only a pass on the final commit
    counts. A pass on any earlier commit (Section 10) is historical
    evidence only, not satisfying G9.

G10. Testnet keeps private spends OFF at launch.
    Per CTO decision O8 (2026-10-22): there is no params field for this.
    Spends are switched by network type. consensus/src/consensus/services.rs:147-151
    turns private spends on only for Devnet | Simnet; testnet and mainnet
    are off. Enforcement is at tx_validation_in_isolation.rs:171-174.
    Check at the final commit: services.rs still lists ONLY Devnet and
    Simnet. No consensus change is needed. Source of the requirement:
    CLAUDE.md:45-46 ("spends ON for devnet/simnet only, OFF for
    testnet/mainnet until an outside audit").

G11. Testnet and mainnet refuse ALL private payments until audit.
    (Updated 2026-10-28, CEO decision option B: after F2, a testnet-only
    change enables private payments on testnet as experimental and
    unreviewed, with a test proving mainnet still refuses. Mainnet keeps
    G11 until an independent review.)
    Refusal fires at isolation time, before decode and proof. No
    shielding, no spend, no unshield. Side effect: no proof-based peer
    bans on testnet/mainnet (refusal costs no proof work). Devnet and
    simnet unchanged. Source: tx_validation_in_isolation.rs:168-170;
    ZTH-SPEC-006 Section 7.3.

G12. Release v0.1.0-testnet.1 ships a cargo about-generated
    THIRD-PARTY-NOTICES.txt covering the entire dependency tree.
    Preflight zip is exempt (throwaway build, not distributed).

G13. Before v0.1.0-testnet.1: a verified copy-paste balance command
    (JSON-RPC getUtxosByAddresses on the testnet port) in the README,
    or a wallet tool ships. Gate G3 cannot pass without one of these.

If any gate is false, do not regenerate. A regeneration that lands before
the gates pass must be redone, and every hash in CLAUDE.md:186 and in any
announcement draft goes stale.

## 2. Exact regeneration steps

File to edit: consensus/core/src/config/genesis.rs
    Source: docs/CEO-BRIEFING-2026-10-22.md:342.

Fields to set for the TESTNET genesis only:
- timestamp: provisional today; replaced with the final value at regen.
- coinbase payload message: see Section 3. ASCII only.
- coinbase value and supply ledger fields: remain zero; utxo_commitment
  remains the empty-set hash.
    Source: docs/CEO-BRIEFING-2026-10-22.md:114-115.

Do NOT regenerate mainnet or devnet in this step. Mainnet is not launched.
Devnet hash 5563e86a is fixed by the earlier resets (CLAUDE.md:87-88).

Steps, in this order (CTO decision O6, 2026-10-22):

  1. Edit the TESTNET genesis header fields in genesis.rs: timestamp and
     message (Section 3). Leave the hash constant untouched for now.

  2. Run the print helper. Node window, one command in one box:

        cargo test --release -p kaspa-consensus-core print_zethora_testnet_genesis -- --nocapture

     The helper is print_zethora_testnet_genesis at genesis.rs:273 (CTO
     read of the code, 2026-10-22). It recomputes the merkle root and the
     hash and writes them to zethora_testnet_genesis_values.txt. Delete
     zethora_testnet_genesis_values.txt afterwards; never commit it.

  3. Paste the printed merkle root and hash into the TESTNET_GENESIS
     constants in genesis.rs, in the representation the file expects.

  4. Run the required test (node window):

        cargo test --release -p kaspa-consensus-core test_genesis_hashes

     Required: passes on the same commit that will be tagged for launch.

  5. Record the resulting testnet hash in CLAUDE.md as a dated line and in
     this document.

Current recorded testnet hash (pre-final): d52ed6a6...
    Source: CLAUDE.md:186. Passing on the current commit 2026-10-22
    (Section 10). This does NOT satisfy G9; see O3.

## 3. Genesis message: fresh public value

CTO decision O1 (2026-10-22): APPROVED. Use a fresh Bitcoin block hash,
encoded as ASCII hex, with total coinbase payload <= 300 bytes.

Why:
- Fair-launch claim: zero genesis subsidy, all supply ledger fields zero,
  empty-set utxo commitment (docs/CEO-BRIEFING-2026-10-22.md:114-115).
- A fresh public value (a recent Bitcoin block hash) proves the testnet
  genesis could not have existed before that Bitcoin block, so nobody
  could have pre-mined it.
- Cost is one string field. Verifiable by outsiders without trusting
  DeionRaven.
- It gives the provisional timestamp an external anchor.

Constraints:
- Payload length: <= 300 bytes total coinbase payload (CLAUDE.md:89).
  About 177 bytes remain for the message after the 123-byte ledger fields
  (CLAUDE.md:244); a 64-char hex hash leaves about 110 for the label. The
  print helper and test_genesis_hashes confirm the final length.
- ASCII only. Lowercase hex. No section sign, no smart quotes.
- Pick the Bitcoin block at the moment of final regen, after G1-G10 pass.
  The block must already exist. Never a future block.
- Record in CLAUDE.md (dated line) and in this document: Bitcoin height,
  block hash, block time, and the exact ASCII string embedded.
- Devnet keeps its current message and 5563e86a hash (CLAUDE.md:87-88).
  Do NOT change devnet in this step.

## 4. Launch order

Strict order. Nobody mines before the testnet seed is live.

1. Final testnet genesis regen (Section 2). Gates G6, G9, G10 pass.
2. Rebuild the seed from the final regen commit (CLAUDE.md:412 update
   procedure), change the service flags to --testnet, open TCP 26211 in
   the firewall, then restart zethora-seed. Once testnet opens, devnet
   stays on Deion's PC only; no public devnet seed.
3. Verify the testnet seed is reachable from outside on TCP 26211 (G1).
4. Publish the release Windows binary (G8) built from the same commit.
5. Announce. The announcement states the seed address, TCP 26211, and the
   final testnet genesis hash so a stranger can verify they are on the
   right chain.

Between step 1 and step 5, only internal test machines mine. If a stranger
mines the old chain in that window, their blocks are abandoned by the
announcement, not by a rule.

## 5. Rollback policy, first hours

Principle: testnet has no monetary value. A clean restart is always
acceptable. A silent restart is not.

Who decides:
- Consensus change or genesis change: CTO sign-off (CTO handoff: every
  consensus change and every public claim needs sign-off).
- Operational halt, restart timing, announcement wording: CEO.
- Lead Engineer executes and records.

Triggers:
- Chain stall, split, or supply ledger mismatch: the miner's Supply check
  line no longer says BALANCED (CLAUDE.md:24).
- Seed down and not recoverable within 30 minutes.
- A bug that can only be fixed by a consensus change.

Default response:
1. Freeze: stop miners. Keep nodes running to preserve logs.
2. Snapshot: save logs, tip height, genesis hash, and the failing evidence.
3. Decide within 4 hours: patch forward (non-consensus) or restart with a
   new genesis.
4. Announce plainly: testnet restarted, old chain abandoned, new genesis
   hash and seed address. Do not promise to preserve testnet balances.

If a restart happens, repeat Section 2 and Section 4 from step 1.

## 6. Out of scope

- Private sending on mainnet: off until an outside review (testnet:
  experimental after F2, per CEO decision 2026-10-27)
  (CLAUDE.md:46; docs/TESTNET-ROADMAP.md:13;
  docs/CEO-BRIEFING-2026-10-22.md:280-283).
- Mainnet: not launched.
- Pools: documentation only (CLAUDE.md:220).
- Farm detection: no such feature; do not claim it (CLAUDE.md:219;
  docs/CEO-BRIEFING-2026-10-22.md:255-261).
- DeionRaven Labs is a project name, not a registered company
  (CLAUDE.md:221).
- tools/faucet (CTO decision O5): a 28-line stub, untracked, no key or
  amount logic found by the CTO on 2026-10-22. Leave untracked. Do not
  deploy. Not a launch gate. Revisit as its own item if a testnet faucet
  is wanted later.

## 7. CTO decisions (2026-10-22)

O1. APPROVED. Fresh Bitcoin block hash as the testnet genesis message.
    ASCII hex. Coinbase payload <= 300 bytes. Devnet unchanged.
O2. APPROVED. Live evil-peer ban test is required before strangers
    connect. Unit tests alone do not satisfy G5. Estimated 3-4 hours
    (CLAUDE.md:301).
O3. APPROVED. Only a test_genesis_hashes pass on the FINAL regen commit
    satisfies G9.
O4. APPROVED, limited scope. Remove exact duplicates only in CLAUDE.md;
    mark stale lines with a dated correction, append-only. Cleanup applied
    in this commit.
O5. RESOLVED. tools/faucet is a stub. Untracked, not deployed, not a gate.
O6. RESOLVED. Print helper exists: print_zethora_testnet_genesis at
    genesis.rs:273. Command in Section 2 step 2.
O7. RESOLVED. Testnet-10, P2P port 26211 (params.rs:637,
    params.rs:571-574; CLAUDE.md:173). Hetzner seed rebuilt for testnet at
    launch. TCP 26211 opened. Devnet stays on Deion's PC only after
    launch. Second seed is nice-to-have, not a gate.
O8. RESOLVED. There is no params field. Spends are switched by network
    type: consensus/src/consensus/services.rs:147-151 turns spends on
    only for Devnet | Simnet. Enforcement:
    tx_validation_in_isolation.rs:171-174. G10 check is to confirm those
    services.rs lines at the final commit. No consensus change needed.

Fixes from the first audit (rev 3), all incorporated:
(1) Testnet port and --testnet seed flags and firewall: G1, Section 4.
(2) Print helper before test_genesis_hashes: Section 2 step 2.
(3) New gate G10 (spends off on testnet): G10.

Fixes from the final audit (rev 5), all incorporated:
(F1) Section 4 step 2 now says "Rebuild the seed from the final regen
     commit".
(F2) Section 3 payload math corrected: 123-byte ledger fields, 177 left,
     ~110 for the label.
(F3) G1 firewall citation now points at the Hetzner server (TCP 26211),
     not the old Oracle note.
(F4) Section 2 step 2 now says "Delete zethora_testnet_genesis_values.txt
     afterwards; never commit it."

## 8. Applied doc corrections

R1. APPLIED in this commit. docs/TESTNET-ROADMAP.md:67 changed from
    "TCP 26611" to "TCP 26211". 26611 is devnet (CLAUDE.md:173-174);
    testnet-10 P2P is 26211 (CLAUDE.md:173; params.rs:637).

CLAUDE.md cleanup per O4, APPLIED in this commit:
- Removed lines 365-398 (exact byte-identical duplicate of 330-363,
  verified with Compare-Object on 2026-10-22).
- Appended dated correction at end of Security verification log for the
  stale 10-bps/Kaspa-genesis paragraph at CLAUDE.md:189-196.
- Appended session line for this work. Both appended items are below in
  CLAUDE.md itself; see that file.

## 9. Evidence log

2026-10-22 - test_genesis_hashes passes on the CURRENT commit (not the
final regen commit; does NOT satisfy G9, per O3).

    PS C:\Users\Rac436\zethora-node> cargo test --release -p kaspa-consensus-core test_genesis_hashes
    running 1 test
    test config::genesis::tests::test_genesis_hashes ... ok
    test result: ok. 1 passed; 0 failed; 0 ignored
    (74 total in crate; 73 filtered out)
    tests\db_compat.rs: 0 run, 7 filtered out
