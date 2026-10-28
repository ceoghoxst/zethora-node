## Recently completed (Oct 12, 2026)
- Item 20 verified: Second node synced 74%+ of the chain from the first node via --connect. --seed code reads the flag and queries the DNS seeder correctly. Live internet test pending a real VPS/seed server.
- 1 BPS fix: TESTNET_PARAMS and MAINNET_PARAMS changed from 10 to 1.
- Genesis regenerated: TESTNET_GENESIS and GENESIS for 1 BPS. Both pass test_genesis_hashes.
- Seed/connect code verified: --seed reads the flag; --connect establishes live P2P. Local sync deferred until chain has 1000+ blocks.
- subsidy_test removed from consensus/src/processes/coinbase.rs.


# Zethora node: project notes for Claude

Read this first in any new session. Zethora (ZTHR) is a fair-launch, home-mined privacy coin by DeionRaven Labs.
Repo: github.com/ceoghoxst/zethora-node, branch `zethora` (a rusty-kaspa fork). Docs/specs: github.com/ceoghoxst/zethora.

## How we work
- Deion doesn't write code. Claude writes each change as one tested patch, gets it independently reviewed, and puts
  the patch plus a one-command script in `C:\Users\deion\zethora-node` when the PC is linked.
- Deion runs it on his Windows PC (PowerShell): `git am <patch>`, tests, devnet run, then
  `git push https://github.com/ceoghoxst/zethora-node.git HEAD:zethora`.
- Always say which window each command goes in (node window, miner window, third window), one command per box.
- PC: Ryzen 5 2600, 16 GB, Windows 11. Devnet runs at about 1 block per second with his one miner.

2026-10-24 - Two PCs: Ryzen 5 2600 (12 threads, C:\Users\deion) = reference
for performance numbers and launch gates; 2-core PC (C:\Users\Rac436) =
valid for correctness tests only. Every performance number must name the PC.

## Run commands (devnet)
- Node: `cargo run --release --bin kaspad -- --devnet --utxoindex --enable-unsynced-mining` (add `--reset-db --yes` only when a patch changes stored state)
- Miner: `cargo run --release -p zethora-miner` (prints a Supply check line per block: must say BALANCED)
- Private wallet tool: `cargo run --release -p zethora-shield -- <0.1 | balance | send 0.05 | unshield 0.05 | attack | replay | bump 0.02 | compare>`
  (`-- node2 <command>` sends to the second node; the chain is always read from node 1)
- Step 3c test (fast pruning, node 1 archival so the wallet can still read old blocks):
  node 1 `cargo run --release --bin kaspad -- --devnet --utxoindex --enable-unsynced-mining --archival --override-params-file=devnet\fast-pruning.json` (+ `--reset-db --yes` the first time),
  node 2 `.\target\release\kaspad.exe --devnet --appdir=C:\Users\deion\zethora-node2-data --listen=127.0.0.1:26621 --rpclisten=127.0.0.1:26620 --connect=127.0.0.1:26611 --override-params-file=devnet\fast-pruning.json --disable-upnp`.
  Going back to the normal devnet afterwards needs `--reset-db --yes` without the override file.

- Seed node (step 7): Oracle Cloud Always Free Ampere A1 (ARM), Ubuntu, home region US West (San Jose), tenancy ceoghoxst.
  Setup/update on the server: `curl -fsSL https://raw.githubusercontent.com/ceoghoxst/zethora-node/zethora/seed/setup-seed.sh | bash`
  (service `zethora-seed` runs with --yes so a devnet-reset update wipes and re-downloads instead of looping; binary
  /usr/local/bin/zethora-node, data ~/zethora-data, RPC on the server's 127.0.0.1 only;
  logs `journalctl -u zethora-seed -f`). Cloud firewall: ingress TCP 26611 in the VCN security list.
  PC node with the seed: add `--seed=<server IP> --disable-upnp` to the node command. `compare` against the server:
  third window `ssh -N -L 26620:127.0.0.1:26610 ubuntu@<server IP>` (forwards the server's RPC to the PC's 26620 = "node 2").

## Done and verified on his devnet (as of Oct 7, 2026)
1. Supply ledger: every block proves visible + fee pool + burned + private == issued (BALANCED). Planted-bug attack test caught 20 fake zets.
2. Private pool = Zcash Orchard 0.16.0 (pinned rev 616a669), fixed circuit, used unmodified. Payload "ZSHP" + encoded bundle.
3. Shielding (visible -> private), coin list (note commitment tree, root sealed in coinbase bytes 56..88).
4. Double-spend guard (nullifier store, prefix 91/92).
5. Private sending (commit "Private sending: spend private coins on devnet, with matured anchors"): anchor store (prefix 93),
   anchors must be >= 600 blue blocks deep; spends ON for devnet/simnet only, OFF for testnet/mainnet until an outside audit.
   Wallet scanner in zethora-shielded (feature "wallet"). Verified: send worked, `attack` blocked 2 of 2 (counterfeit coin, double spend).
6. Mempool double-spend check (commit "Mempool: one waiting spend per private coin"): nullifier -> tx index in the mempool
   UTXO set; second waiting spend refused (RejectZethoraNullifierInMempool) unless it replaces the first by fee (same visible
   fee input); a block spending a coin evicts waiting spends of it. Orphans are checked when unorphaned. No stored-state change.
7. Fully private payments (commit "Fully private payments: pay the fee from private coins"): a tx with NO visible input is
   allowed if its private payment takes value out of the pool (value balance > 0 pays the fee, ZTH-SPEC-006 §9).
   Storage mass with zero inputs = outputs' harmonic part (no divide by zero). Wallet `send`/`unshield` are now fully
   private; `attack` has 3 checks (counterfeit, same coin twice at once -> mempool, same coin after it landed -> chain).
   Shielding still pays its fee from a visible coin (it has to: value enters the pool). No stored-state change.
8. Ban peers relaying forged private payments (SPEC-006 §8.3): new TxRuleError::InvalidPrivatePaymentProof only when the
   proof/signatures fail or a coin tag repeats inside one payment. The tx relay flow checks a peer's private payments in
   groups of 8 (after its ordinary txs), and at the first forged one bans the peer's IP for 24h (address manager;
   --connect/--addpeer peers exempt) and disconnects. No ban for: unreadable bytes (a newer node's format after an
   upgrade), chain-dependent refusals (coin spent, snapshot too recent), network switches (spends off, lock time).
   Only unit-tested: a live test needs a deliberately evil peer.
9. Hardening (commit "Hardening: cheap private checks first, proof checks outside the virtual lock"): mempool
   validation now runs (1) cheap private checks (coin tags unspent, snapshot matured; SPEC-006 §8.1) under a brief
   virtual lock, (2) in-isolation checks incl. proof checks with NO virtual lock, (3) the rest under the lock, then the
   private checks again. Address manager never re-learns a banned IP (gossip or DNS seeds; --connect/--addpeer peers
   are still dialed by design). No stored-state change.
10. Ban for forged private payments inside blocks too (relay and IBD): ProtocolError::is_forged_private_payment()
   (RuleError::TxInIsolationValidationFailed(_, InvalidPrivatePaymentProof)) checked in the block relay and IBD flows'
   start(); one helper FlowContext::ban_if_forged_private_payment used by tx relay, block relay and IBD.
   Orphan blocks remember their sender's IP (OrphanBlock.sender), so a forged block sent before its parent still gets
   its sender banned when it is finally validated (unorphan_blocks / revalidate_orphans).
   Gap: in add_orphan's NoRoots path the orphan ancestors' senders are dropped (the relaying peer, who vouched for
   them, is banned instead).
   RULE: whenever the proof rules change (circuit, what counts as InvalidPrivatePaymentProof), reset the devnet, or
   new nodes would ban honest peers serving old blocks valid under the old rules.
11. Mempool in-isolation checks (incl. proofs) run on their own rayon pool (VirtualStateProcessor.mempool_check_pool,
   a quarter of the CPU threads, "mempool-check-N", created on first use), not the virtual processor's pool. Caps the
   CPU a proof flood can take; does not reserve cores for blocks. In-context checks still use the virtual pool.
12. Fee bump for private payments: mempool DoubleSpend now has `spent: Spent::{Outpoint, PrivateCoin(nullifier)}`;
   utxo_set get_first_double_spend / get_double_spend_transaction_ids include coin-tag conflicts, so the normal RBF
   rules (higher fee rate wins; Forbidden refuses; Mandatory needs exactly one) cover private coins. Wallet: `bump 0.02`
   sends with a low fee then replaces it (submit_transaction_replacement) with 3x the fee.
13. Private state fingerprint (SPEC-006 §6.4, step 3a of pruning-point sync): every coinbase now seals, after the
   note root, a 32-byte MuHash over {'N'||nullifier spent on chain} ∪ {'A'||anchor root produced on chain}
   (processes/zethora_private_state.rs). Per-block unfinalized MuHash in store prefix 94 (zethora_private_states,
   deleted when pruned); ctx.private_state in calculate_utxo_state; VirtualState.private_state for templates.
   Coinbase layout: ... note_root 56..88, private_state 88..120, then script. DEVNET RESET REQUIRED (new block shape;
   new devnet genesis hash 5563e86a…, recomputed in Python from the Rust hashing rules and checked against the old
   values first). max_coinbase_payload_len raised 204 -> 300 on all networks (none launched).
   Next: 3b download+verify the private state at the pruning point (P2P), 3c live test with fast devnet pruning.
14. Private state download at the pruning point (SPEC-006 §6.4, step 3b): a node joining from a pruning point P asks a
   peer for P's private state (new P2P messages RequestZethoraPrivateState / ZethoraPrivateStateHeader /
   ZethoraPrivateStateChunk / RequestNextZethoraPrivateStateChunk, oneof fields 90-93; server flow
   v10/request_zethora_private_state.rs, client ibd::receive_zethora_private_state called at the start of
   sync_new_utxo_set, BEFORE the UTXO import because that computes the virtual state on top of P). Consensus
   get_zethora_private_state picks every coin tag / snapshot record whose block is SPENT/ANCHORED_FOR_GOOD or a chain
   ancestor of P; import_zethora_private_state checks it against P's coinbase (note root + fingerprint; genesis is
   special-cased) BEFORE writing, then writes the tags/snapshots as "for good" and note_trees[P], private_states[P].
   Fingerprint anchor element is now 'A'||root||blue score (u64 LE) of the producing block, and the anchors store keeps
   (block, blue score) pairs (also for ANCHORED_FOR_GOOD), because the youngest snapshots at P are not yet 600 deep
   for the first blocks after P; maturity now uses the stored score. DEVNET RESET REQUIRED (fingerprint + store format).
   The note root does not seal the tree size (appending Orchard's empty leaf, value 2, keeps the root), so a downloaded
   coin list ending in the empty leaf is refused (NoteCommitmentTree::ends_in_empty_leaf). Block commits and the import
   take turns on VirtualStateProcessor::zethora_records_lock (both share the pruning lock).
   Unit-tested only; 3c = live test with fast devnet pruning and a second node.
15. Step 3c tooling: devnet/fast-pruning.json (pruning depth 1000, finality 300, merge 100, difficulty window 150x2;
   same block rate, genesis and coinbase maturity; validated by params test zethora_fast_pruning_devnet_file_is_valid).
   Wallet: `replay` re-spends your oldest already-spent private coin (Scanner::spent_coins; must be refused with
   "private coin already spent"), `compare` shows both nodes' tip, pruning point and the fingerprint sealed in it,
   `node2 <cmd>` submits to node 2 (127.0.0.1:26620) while reading history from node 1 (pruned nodes can't be scanned).
   The real 3c check: node 2 logs "Zethora: imported and checked the private state of pruning point ...", compare
   says AGREE, and `node2 replay` is BLOCKED for a coin spent before the pruning point.
   Run-order rules (else it passes without testing the download): start node 2 only when node 1's pruning point height
   is above the tip height noted right after the send landed (pruning point = newest 300-multiple sample >= 1000 below
   the tip), and start node 2 fresh (`--reset-db --yes`); a node 2 joining while node 1's pruning point is genesis
   just syncs from genesis. The "imported and checked" log line is the proof, AGREE alone is not.
   Also STOP THE MINER while node 2 joins: node 2 needs ~10 min to check the proof's RandomZ work, and with fast
   pruning node 1's pruning point moves every ~4 min, so IBD fails "the proof pruning point is not equal to the last
   pruning point in the list" and retries forever. Restart the miner after the "imported and checked" line.
   VERIFIED LIVE Oct 7, 2026: node 2 imported 4 spent tags + 3 snapshots at pruning point 9711653a, validated 1067
   blocks above it, compare AGREE (same tip/pruning point/fingerprint after node 1 pruned again), `node2 replay`
   BLOCKED (tag spent before the pruning point), `node2 attack` 3/3.
16. Privacy step 4, speed test tooling: `zethora-shield speed` (no node needed; stop the miner first) makes 6 payments
   (2 Orchard actions each) and times: making one, checking one at a time (verify_payment, as the node does), checking
   on all CPU threads, and Orchard batch checking (new zethora_shielded::verify_payments_batch, not used by consensus
   yet). Compares with the most private payments a block can carry (devnet block mass limits vs. the payment's compute
   and transient mass, PROOF_MASS_PER_ACTION 15,000) at the devnet block rate, and the mempool checker's quarter of
   the threads. Result feeds step 18 (tune speed settings).
   RESULT on his Ryzen 5 2600 (12 threads), Oct 7, 2026: making 1.49 s/payment (9,144 bytes, 2 actions); checking one
   at a time 13 ms = 77.7/s; all 12 threads 123.2/s (halo2 already multithreads each check, so parallel gains little);
   Orchard batch of 6 on one thread 220.6/s (2.8x). Payment mass: compute 39,242 of 500,000, transient 36,968 of
   1,000,000 -> 12 private payments per block = 12/s at 1 bps. PC has 10.3x headroom over full blocks; mempool
   checker (3 threads) ~31/s. For step 18: blocks, not CPU, cap private throughput (PROOF_MASS_PER_ACTION 15,000 is
   conservative); switching block/mempool checks to batch checking is the big speed win. Privacy section A DONE.
17. B5 reward schedule = 100M check (ZTH-SPEC-001 §5): consensus rule in zethora_supply::ledger_step: a block that
   would bring total_issued above CAP_UNITS (100,000,000 ZTHR) is invalid (SupplyError::CapExceeded); never fires on
   an honest chain (backstop). zethora_subsidy: exact full-schedule walk (jumps while floor(R/D) is constant; matches
   a C reference and the node's step-by-step lookup): 50% at 8 y, 75% at 16, 93.75% at 32, 99.6% at 64; reward hits 0
   at DAA score EMISSION_END_SCORE 8,126,002,948 (~257.5 y at 1 bps); TOTAL_EMISSION = 999,989,999,635,776,057 zets
   = 99,998,999.9635776057 ZTHR (+1,000 ZTHR reserve never mined). DAG overshoot bound: each block is paid at its own
   DAA score; a paid merged block lags its place by <= difficulty window + mergeset (2,644 + 180 on devnet); the
   per-step drops telescope to reward(0), so total extra <= 2,824 x 0.2746 ~ 775 ZTHR < 1,000 reserve. The CapExceeded
   backstop makes an over-paying block invalid (the chain would stall, never overpay). full_emission_schedule walks
   the whole schedule only in release mode. No reset needed.
18. B6a RandomZ (ZTH-SPEC-000 §4.4, SPEC-005 §5.1): randomx-rs v1.6.0 (tari, commit 6733ed4) vendored in ./randomz
   (workspace dep `randomx-rs = { path = "randomz" }`, upstream tests removed since they check stock hashes). RandomX
   config changed only where RandomX documents it as safe: salt "RandomZ\x01", IROR/IROL 6/4, FADD_R/FSUB_R 15/17,
   FADD_M/FSUB_M 6/4 (configuration.h AND src/asm/configuration.asm for Windows MASM). Same memory/time cost as RandomX.
   Checked in the sandbox: stock build reproduces RandomX's official vector; RandomZ interpreter = JIT = fast mode.
   Tests (kaspa-pow randomz): RandomZ vectors, "not stock RandomX" guard, devnet PoW vector. DEVNET RESET REQUIRED
   (every PoW hash changed). Miner speed test: `cargo run --release -p zethora-miner -- bench` (light-mode setup and
   per-block check time, dataset time, fast-mode H/s on 1, half, all threads). Key rotation = step 6b (not done: the
   key must be computable for any header incl. pruning-proof headers, and per-epoch 256 MB cache inits cost ~1 s).
   BENCH on his Ryzen 5 2600 (Oct 7, 2026): light mode ready 1.79 s; one block's PoW check 18.0 ms (1.8% of a thread at
   1 bps; full sync ~56 blocks/s/thread); dataset 29 s on one thread; fast mode agrees with light; mining 300 H/s on
   1 thread, 1,144 on 6, 1,217 on 8, 1,291 on 12 (no large pages, no pipelining; XMRig-class miners get more: B8).
19. B6b RandomZ key rotation (consensus/pow/src/randomz.rs): key = "ZethoraRandomZ" ++ epoch (u64 LE), epoch =
   daa_score >> 20 (~12 days at 1 bps), a fixed public sequence as RandomX's README allows; the header's DAA score is
   checked exactly by consensus, so miners can't pick keys. Node: LRU of 4 light setups (256 MB each, ~1.8 s to build)
   + thread-local VM per epoch + memo of 200k recent (epoch,input)->value; precompute_light/precompute_pow compute many
   headers grouped by epoch (<= 4 temporary setups in parallel) for pruning proofs and past pruning points. DoS guards:
   (a) header processor (check_pow_epoch_plausible, before PoW): ordinary headers must be in epochs
   [epoch(pp)-1, epoch(max(pp, headers tip))+1], trusted ones epoch(pp)+-1; outside -> MissingParents if a parent is
   unknown (orphan/IBD path), else RuleError::ZethoraPowEpochOutOfRange. (b) a peer's proof and past pruning points:
   every header epoch <= min(epoch(proof pp)+1, EpochClock::max_plausible_epoch(now)) (2x the blocks the time since
   genesis allows, +2 epochs); trusted blocks + header-only chain segment (apply_proof): epoch(pp)+-1; else
   PruningImportError::ZethoraPowEpochImplausible. The node's own (defender) proof uses stored block levels, no PoW.
   Memo keeps whole precomputed batches (clears before a batch that doesn't fit). All skipped with skip_proof_of_work. Miner
   keeps (epoch, dataset) and rebuilds (~30 s) when the template's epoch changes. Tests: kaspa-pow randomz (epoch
   vectors e1b60624... epoch 0 / 60fae6cc... epoch 1 for pow_input([7;32],1000,1)), kaspa-consensus
   zethora_pow_epoch. DEVNET RESET REQUIRED (every key changed).
20. B7 seed nodes, part 1 (network identity + seed option + server script): mainnet/testnet/simnet ports moved off
   Kaspa's (Kaspa + 10,000: P2P 26111 / testnet-10 26211 / -12 26311 / other 26411 / simnet 26511, gRPC 26110/26210/26510,
   wRPC borsh 27x10, json 28x10; devnet already 26610/26611/27610/28610), test zethora_ports_never_use_kaspa_defaults.
   Kaspa's DNS seeders removed from mainnet/testnet (they lead to Kaspa nodes; the handshake already refuses them since
   the network name is "zethora-..."). New kaspad option `--seed=<hostname or IP>` (repeatable, no port: seed lookups
   use the default P2P port; IP literals resolve without DNS) replaces the network's seed list; ignored with --connect /
   --nodnsseed. Startup logs "Seed nodes: ..." or "No seed nodes for this network". seed/setup-seed.sh builds and runs a
   seed node on Ubuntu (checks RandomZ vectors on the server's CPU first, systemd service, iptables port). No stored-state
   change, no reset. NOT live-tested yet: part 2 = run the server, PC joins via --seed, compare AGREE over the SSH tunnel,
   then bake the server's (reserved) IP or a hostname into DEVNET_PARAMS.dns_seeders.

## Recently completed (Oct 12, 2026)
- Item 20 verified: Second node synced 74%+ of the chain from the first node via --connect. --seed code reads the flag and queries the DNS seeder correctly. Live internet test pending a real VPS/seed server.
- **1 BPS fix**: TESTNET_PARAMS and MAINNET_PARAMS changed from `BlockrateParams::new::<10>()` to `::<1>()`.
- **Genesis regenerated**: TESTNET_GENESIS (hash d52ed6a6...) and GENESIS (hash b819b739...) regenerated for 1 BPS. Both pass `test_genesis_hashes`.
- **Seed/connect code verified**: `--seed` reads the flag and queries the DNS seeder; `--connect` establishes a live P2P connection. Local node-to-node sync deferred until the chain has 1000+ blocks (IBD refuses to request headers proof on a very short chain).
- **subsidy_test removed**: obsolete Kaspa 50-coin test removed from `consensus/src/processes/coinbase.rs`.
## Known gaps / next steps
- ANCHOR_DEPTH 600 assumes ~1 block/s; scale with real block rate before testnet.
- TESTNET_PARAMS and MAINNET_PARAMS are still Kaspa's 10 blocks/sec (BlockrateParams::new::<10>()), and their genesis
  is Kaspa's. The reward divisor D assumes 1 block/sec: set both to 1 block/sec with Zethora genesis blocks before any
  testnet launch (rewards would otherwise come 10x faster; the 100M cap rule still holds, but at 10 bps the DAG
  overshoot bound (window 661x40 + 248) is ~7,300 ZTHR > the 1,000 reserve, so the CapExceeded backstop could fire
  near the end of emission and STALL the chain). Simnet is also 10 bps (tests only). Kaspa tests that use
  MAINNET/TESTNET params will need care when that changes.
- Pruning-point sync of shielded state: 3a, 3b, 3c done and verified live (item 15). Privacy step 4 speed test done (item 16). Privacy section A complete. B5 (100M check) done (item 17). B6a RandomZ params + bench (item 18); B6b key rotation (item 19); B7 part 1 (item 20), live test next.
  The whole private state is held in memory on both sides during the download, and the server builds it before
  sending the header (client waits DEFAULT_TIMEOUT); fine now, stream it before mainnet.
- RandomZ: a node joining by pruning proof builds one 256 MB light setup per epoch since genesis (~30 per year at
  1 bps, 4 in parallel: ~15 s per year of chain); a bogus proof can make it build up to ~2x that before failing, and
  nothing bans for that yet, so a peer can repeat it on every reconnect (ban for invalid proofs before testnet). At
  10 bps (testnet/mainnet params today) an epoch is ~29 h: fix the block rate first. The miner stalls ~30 s at each
  key change; prebuild the next epoch's dataset in the miner app (B8).
- Banning by IP: two nodes on one PC share 127.0.0.1, so a ban there hits both. Fine for devnet.
- Seeds: one seed run by DeionRaven Labs is a single point of failure and sees every new node's IP; add independent
  seeds (community-run, DNS seeders with several A records) before mainnet. Seed nodes only hand out addresses, they
  can't change the chain. The wallet code (wallet/core) still has Kaspa's public-node resolver; not used by our tools.
- Before testnet: bans are per IP only; other invalid blocks (not forged payments) only disconnect.
- Needs a human crypto reviewer before private sending reaches a public network, then a professional audit before launch.
- Miner app ideas (demos only, not linked to the real miner): "Raven Room" (pixel room + mine) and "Zethora Miner"
  (GoMining-style rig app). Rule: upgrades are earned/cosmetic; never pay to mine more ZTHR (fair launch).

- Known old failing test: consensus processes::coinbase::tests::subsidy_test checks Kaspa's 50-coin schedule, which
  Zethora replaced (zethora_subsidy). Don't use a bare "coinbase" test filter in scripts.

## Safety rules for Claude
- Never promise coins, staking returns or paid hashrate. No token exists yet.
- Do not claim "we detect farms", "we block farms" or "we prevent industrial mining". No such feature exists; any anti-farm idea is undecided and post-testnet.
- Pools (decided Oct 22, 2026): documentation only (solo mining, and how a pool could use the stratum bridge). No official DeionRaven pool. Third-party pools welcome after testnet.
- DeionRaven Labs is a project name, not a registered company (as of Oct 22, 2026). Do not describe it as a company, firm or legal entity in public docs; use "Maintained by DeionRaven (Deion Smith)".
- Persistence rule: every decision goes to disk. See docs/PERSISTENCE-RULES.md for the standing rule and file map. Sessions are ephemeral; files are permanent.
- Don't route around network blocks; if crates.io is blocked in the sandbox, his PC compiles and Claude checks against library sources.

## Security verification log

### Oct 13, 2026: Subsidy fields verified dead in production
- **Finding**: Mainnet/Testnet pre_deflationary_phase_base_subsidy (50000000000) and deflationary_phase_daa_score are not read on any production code path.
- **Impact**: Mainnet cannot accidentally pay Kaspa's 500 KAS/block reward. Risk closed.
- **Proof**: calc_block_subsidy (consensus/src/processes/coinbase.rs) delegates to zethora_subsidy.subsidy(daa_score). Kaspa's emission code (kaspa_calc_block_subsidy, legacy_calc_block_subsidy, SUBSIDY_BY_MONTH_TABLE) was removed on Oct 20, 2026, so nothing in the node reads Kaspa's subsidy schedule.
- **Remaining cleanup (low priority)**: the params fields pre_deflationary_phase_base_subsidy / deflationary_phase_daa_score still exist. Do NOT remove them alone - Simnet integration tests reference SIMNET_PARAMS.pre_deflationary_phase_base_subsidy.

## Pre-testnet security checklist
- [ ] **RandomZ DoS ban**: a peer can send bogus pruning proofs, forcing ~30 light setups (256 MB each). Add a ban rule for invalid proofs before testnet opens.
- [ ] **Independent seed nodes**: currently only one seed (DeionRaven Labs). Add community-run or DNS seeder redundancy before mainnet.
- [ ] **Human crypto review**: private sending is off for testnet/mainnet until an outside cryptographer reviews the Orchard/Halo2 integration.
- [ ] **Stream private state download**: currently held fully in memory during P2P sync. Stream it before mainnet.
- [ ] **B8 miner prebuild**: miner stalls ~30 s at each epoch key rotation (~12 days). Prebuild next epoch's dataset in the background.

## Known test failures (as of Oct 14, 2026)

### kaspa-testing-integration: daemon_integration_tests uses stale short coinbase payloads
- Symptom: PayloadLenBelowMin(32, 123) at consensus/src/pipeline/virtual_processor/utxo_validation.rs:478
- Cause: daemon_integration_tests builds blocks with a 32-byte coinbase payload. Zethora requires 123+ (supply ledger + coin list root + private state fingerprint).
- Impact: 1 test binary fails. Does not affect devnet, node startup, P2P, mining, or any Zethora-specific code.
- Fix path: update the daemon test helper to build Zethora-shaped coinbases (similar to what was done for consensus test_consensus.rs on Oct 13).
- Status: deferred. Not blocking testnet.

### How to run tests
The workspace test suite passes except for the above. Run per-crate rather than --workspace to skip the known failure:
  cargo test -p kaspa-consensus --lib
  cargo test -p kaspa-txscript --lib
  cargo test -p kaspa-wallet-core --lib

## Dependency security status (Oct 14, 2026)

### Fixed
Ran cargo audit, found 13 vulnerabilities. Updated 12 of them:
- ruint 1.17.2 -> 1.20.1 (arithmetic correctness)
- rustls 0.23.39 -> 0.23.46 (4 CVEs)
- h2 0.4.6 -> 0.4.20 (DoS)
- quinn-proto 0.11.14 -> 0.11.19 (5 CVEs)
- crossbeam-epoch 0.9.18 -> 0.9.21
- anyhow 1.0.97 -> 1.0.104

### Accepted risk
- tracing-subscriber 0.2.25 (RUSTSEC-2025-0055): log poisoning via ANSI escapes. Low severity (cosmetic log issue, not remotely exploitable). Pinned transitively; updating requires dependency archaeology not worth the effort now. Revisit before mainnet.

### Non-blocking warnings
16 unmaintained/unsound/yanked warnings from inherited Kaspa deps. Not exploitable. Tracked but not blocking.

Re-run with: cargo audit

## ZTH-IMPL-020 progress + DB reset note (Oct 15, 2026)

Pieces 1-5 implemented and committed:
- ProtocolError::is_implausible_pow_epoch classifier
- FlowContext::ban_if_implausible_pow_epoch helpers
- Ban fires on bogus pruning proof (DoS mitigated)
- Threshold: 3 failures in 10 min before banning
- Escalating schedule: 24h -> 48h -> 7d, resets after 24h clean

### DB RESET REQUIRED on next devnet start
The ban record format in components/addressmanager changed from a bare u64
to a struct { timestamp_ms: u64, escalation: u8 }. Nodes reading old devnet
databases will fail to deserialize ban entries. Use --reset-db --yes when
starting devnet until the new format is the only one in use.

### Remaining
- Piece 6: unit tests for the classifier, threshold, and escalation.
- Full testnet compliance requires this before strangers connect.

## ZTH-IMPL-020 verified (Oct 15, 2026)

All 6 pieces implemented, tested, and committed. Verified:
- Unit tests: classifier (2 pass), ban escalation (3 pass)
- Devnet startup with new ban record format: clean (no panic, no deserialize error)
- --reset-db --yes handles the format change gracefully

### Still TODO before testnet
- Live ban test: a malicious-peer tool that sends a malformed pruning proof to a real node and verifies the ban fires after 3 attempts within 10 minutes. Estimated 3-4 hours of test-infrastructure work. Not a blocker for devnet.
- Restart the miner (it's been off for hours).

## Oracle seed node status (Oct 15, 2026)

Oracle Always Free ARM (VM.Standard.A1.Flex) in US-San Jose: out of capacity in AD-1
at both 4 OCPU and 1 OCPU. Tried twice across two sessions.

Plan:
- Retry once at 5-7 AM Pacific (off-peak) tomorrow
- If still failing, use Hetzner CAX11 (ARM, 2 vCPU, 4 GB) at ~\.64/month
- The seed node is a pre-testnet item, not blocking dev work

Seed setup script already exists at seed/setup-seed.sh.

## simpa is NOT a smart contract VM (Oct 15, 2026)

The simpa crate in the workspace is Kaspa's network simulator, inherited with the fork.
Its Cargo.toml description is literally "Kaspa Network Simulator". It contains:
- src/main.rs (22 KB) - a CLI for running simulated networks
- src/simulator/miner.rs, network.rs - network simulation logic
- tests/smt_repro.rs - SMT pruning diagnostics

It has NO virtual machine, NO bytecode execution, NO smart contract capability.
The name sounds like a smart contract layer, but it is not.

Programmability is now correctly labeled in the Lightpaper v0.3 as
"planned research, not built". Do not represent it as a current feature.

## Pre-shield boundary verified (Oct 16, 2026)

Question: can a forged value_balance reach the supply ledger without Orchard
verification? (This is the Pirate Chain class of bug.)

Answer: No. Verified by reading the code path end to end.

Data flow for every non-coinbase transaction:

  raw payload bytes
      |
      +-> decode() -> Bundle -> verify_payment() -> spend sigs + binding sig + proof
      |
      +-> value_balance(raw bytes) -> pool_flows -> ledger_step -> turnstile

verify_payment (zethora-shielded/src/lib.rs) does three checks:
  1. Each action's spend signature (covers the value_balance via sighash)
  2. The binding signature (proves value_balance matches value commitments)
  3. The Orchard proof (bundle.verify_proof)

check_private_payment (tx_validation_in_isolation.rs:149) runs this before
the ledger sees anything. A transaction that fails any check is rejected and
its sender is banned (ZTH-SPEC-006 §8.3).

Result: the value the ledger trusts is provably the same value the proof
verifies. A single-byte change to the value balance fails both the spend
signature and the binding signature. The turnstile cannot be tricked into
releasing more than entered the pool.

This closes the "turnstile accounting exploit" attack class for Zethora.
The code is correct as written. No fix needed.

Reference: zethora-supply ledger_step, zethora_private::pool_flows,
zethora-shielded::verify_payment, tx_validation_in_isolation::check_private_payment.

### Oct 21, 2026: Live PC <-> Seed Sync Verified
- **Hetzner Seed (95.216.185.137)**: Running --devnet --utxoindex --disable-upnp --nodnsseed as root at the time (fixed Oct 22, see below). Rebuilt to commit 3f5bfb7.
- **Sync Verified**: Seed node is accepting blocks from Deion's PC via relay every 1-2 seconds.
- **Root Causes Fixed**:
    1. Seed was running an old build (Oct 17).
    2. Hardcoded seed IP in params.rs made the seed dial itself.
    3. No miner was running on the PC.
- **Outcome**: The disconnect loop is fixed. (Not an IBD deadlock).

### Oct 22, 2026: Seed Server Hardened
- **Service**: systemd unit `zethora-seed` (`/etc/systemd/system/zethora-seed.service`), enabled, `Restart=always`; survives reboot (verified after kernel update to 6.8.0-147).
- **Non-root user**: system user `zethora` (not root); binary `/usr/local/bin/zethora-node`; data `/var/lib/zethora`.
- **Flags**: `--devnet --appdir=/var/lib/zethora --utxoindex --disable-upnp --nodnsseed --yes`
- **Update procedure**: `cd /root/zethora-node && git pull && cargo build --release --bin kaspad && install -m 0755 target/release/kaspad /usr/local/bin/zethora-node && systemctl restart zethora-seed`
- **Logs**: `journalctl -u zethora-seed -f`
- **Old root data dir** (`~/.rusty-kaspa` under `/root`) is unused and can be deleted later.

2026-10-22 - docs\TESTNET-LAUNCH.md v0.1 drafted; CTO audit: CHANGES REQUIRED.
Fixes due: (1) G1/seed use devnet port 26611; testnet needs its own port,
--testnet seed flags and firewall rule; (2) regen steps need a print helper
that computes the new merkle root and hash before test_genesis_hashes;
(3) add G10 spends-off check for testnet params. Decisions: O1 approved
(fresh Bitcoin block hash, ASCII hex, payload <= 300); O2 live evil-peer
ban test required before strangers connect; O3 only the final-commit test
result counts; O4 approved: remove exact duplicates only, mark stale lines
with a dated correction (append-only). Timestamp stays provisional. No
consensus code changed.

2026-10-22 - Roadmap #7 (provisional): test_genesis_hashes PASS on current
commit (1 passed, 0 failed). Hashes in genesis.rs: mainnet b819b739,
testnet d52ed6a6 (provisional), devnet 5563e86a; all 0 coins, Zethora
messages. Must pass again on the final testnet regen commit (TESTNET-LAUNCH G9).


2026-10-22 - Correction (append-only). The "Known gaps" paragraph that
states TESTNET/MAINNET are still 10 bps and their genesis is Kaspa's is
STALE. Both were changed to 1 bps with Zethora genesis on 2026-10-12
(see the two "Recently completed (Oct 12, 2026)" blocks). Read those
known-gap lines as historical only. Also: the two "Recently completed
(Oct 12, 2026)" blocks describe the same work but differ in detail and
formatting; both remain in place. Evidence: CTO audit 2026-10-22
(decision O4).

2026-10-22 - docs/TESTNET-LAUNCH.md rev 5 saved and committed after CTO
final audit. All O5-O8 answers and all three final-audit fixes
incorporated. G1 testnet-10 / TCP 26211. G10 is a services.rs check (no
params field). Section 2 uses print_zethora_testnet_genesis at
genesis.rs:273; the values file is deleted, never committed.
tools/faucet marked stub, untracked, not a gate. TESTNET-ROADMAP.md:67
26611 -> 26211. Timestamp provisional. Next: roadmap #4 Windows binary
plan. CTO APPROVED with 3 fixes. Note: the exact-duplicate removal
CLAUDE.md:365-398 approved by CTO was NOT applied this session (line
counts changed since the audit; deferred to avoid touching the wrong
lines). Follow-up needed.

2026-10-23 - zethora-miner: --testnet option (gRPC 26210, key file
zethora-miner-key-testnet.txt, zethoratest: prefix, exit 3 on prefix
mismatch); strict args (unknown -> usage, exit 2). Verified: devnet
regression (zethoradev:, old key, BALANCED), local testnet smoke
(zethoratest:, DAA 0, BALANCED), --tesnet rejected. CTO APPROVED.
Not consensus code. Deferred: 2-thread reading under cargo run (check at
preflight); devnet seed resets every ~15 s (low priority).

2026-10-23 - crypto/addresses: Prefix serde renames kaspa* -> zethora*
(matching Display/FromStr); doc comment fixed; test
prefix_serde_name_matches_display (failed before: "unknown variant
zethora", passes after). Address JSON already used Display; no behavior
change on any current path. Commit 660b2437. CTO APPROVED.

2026-10-24 - G11: testnet/mainnet refuse ALL private payments (shield,
send, unshield) before decode (tx_validation_in_isolation.rs:168-170).
Closes the one-way shielding trap. Side effect: no proof-based peer bans
on testnet/mainnet (refusal costs no proof work). Verified: new test
failed pre-G11 and passes; kaspa-consensus lib 108/108; devnet shield,
send, attack 3/3 BALANCED; testnet 116 blocks BALANCED; zethora-shield
refuses on testnet (exit 2). Commit 02a0b383. Audit packet re-frozen.
CTO APPROVED.

2026-10-25 - STANDING RULE (test discipline): any test that claims a
security property must have (1) a positive control (the honest case is
accepted), (2) exact assertions (== not <=), and (3) a
fail-when-protection-removed proof shown in the packet. Reason: the
sibling double-spend e2e passed while proving nothing (coin never on
chain; <= 1 passed with 0).

2026-10-25 - anchor_depth is a locked Params field (600 on mainnet,
testnet, simnet, devnet); not in OverrideParams, so override files cannot
change it (tests all_real_networks_use_anchor_depth_600,
override_params_cannot_change_anchor_depth). Commit dbfea66. CTO APPROVED.

2026-10-25 - Sibling double-spend e2e REBUILT (replaces the invalid
#[ignore] test). Coin shielded ON CHAIN (scanner root == sealed coinbase
root), anchor_depth 10 via test params. Positive control: one spend
accepted once, nullifier store lists one block, pool 50,000 -> 49,000.
Siblings A/B (proven non-ancestors), C merges {A,B}: exactly one spend
accepted, pool 49,000, both arrival orders. Negative control: merge-loop
filter (utxo_validation.rs:522) removed -> both sibling tests fail
2 != 1; restored -> kaspa-consensus lib 111/111. Written and run by a
Claude Code cloud session on branch test/sibling-e2e, squash-merged.
CTO APPROVED. Turnstile per-transaction fix (F1) still open; required
before private payments are enabled.

2026-10-25 - STANDING RULE (step zero): every session starts with
`git fetch` and `git log origin/zethora -10` before touching any file.
Work may land from other sessions (DeepSeek, Claude Code cloud) in
between. Reason: a merged test (9cda50b) was overwritten locally by a
session that didn't know it existed.

2026-10-26 - STANDING RULE (AI agents): never run an AI agent (DeepSeek,
Claude Code) on untrusted files or pull requests; no secrets (miner keys,
server passwords, SSH keys) anywhere an agent can read; agents work on
branches only, never push to zethora directly.
2026-10-26 - Future items (logged): (1) one-time incoming viewing keys in
any privacy wallet (Zcash Zakura approach, wallet-level) against quantum
linkability; (2) hashed-pubkey addresses before mainnet (miner pays to
PubKey addresses today; cf. Kaspa KIP-22); (3) add post-quantum
linkability to ZTH-SPEC-006 Appendix C.

2026-10-26 - STANDING RULE (agent commits): every commit produced by an
AI agent (DeepSeek, Claude Code cloud, any other) gets CTO review before
it is merged to zethora, same as any other change. Precedent: 9cda50b
(cloud-built test, reviewed on its branch, then squash-merged).
2026-10-26 - Positioning (VP ruling): lead with fair launch / no
premine, 100M cap, home CPU mining, Zcash Orchard privacy that stays OFF
until an outside reviewer signs off. Say what we do, never "nobody else
does this". Do-not-claim: "digital wealth" (rejected); use
"self-custodied digital property". Test for any public sentence: does it
still work if ZTHR is worth zero? If not, don't publish it.

2026-10-26 - CI GREEN (Tests run #15 on 269eeb3, all 5 jobs), merged via
PR #1. Changes: WASM32 jobs removed (no WASM target); cargo fmt; clippy
-D warnings clean on 1.93.0 (unused Kaspa CoinbaseManager reward fields
removed - dead code per the Oct 13 log; Params fields untouched); 5
goref_* tests #[ignore]d (Kaspa Go DAG vectors use Kaspa-PoW block
levels, incompatible with RandomZ; future item: Zethora-generated
replacement dataset); Test Suite timeout 120 min. New test
identical_sibling_blocks_give_identical_state_in_both_arrival_orders
(Carlos/Zealynx request): same blocks, opposite arrival orders, same
winner and identical state; negative control (arrival-dependent merge
order) caught the split. consensus lib 112/112.
2026-10-26 - Correction (append-only): the "Known test failures" entry
for daemon_integration_tests (32-byte coinbase) is STALE; those tests
mine through RPC and pass. The full workspace test suite passes in CI.

2026-10-27 - GATE G5 PASSED (PR #2, commit 5bfd5ae): live RandomZ DoS
ban test over real P2P (testing/integration/src/zethora_g5_ban_test.rs,
common/evil_peer.rs). Real devnet node; evil peer from 127.0.0.2 sends
bogus pruning proofs (impossible RandomZ epoch). Positive control: not
banned after 1 and 2 (node logs 1/3, 2/3). Banned after the 3rd,
reconnect refused ("peer is banned"). Honest control: 127.0.0.3
handshakes; honest node syncs a mined block. Negative control: ban call
in ibd/flow.rs commented out -> test fails on "must be banned". Test-only
change; CI green (runs #20, #21). Built by a Claude Code cloud session,
CTO reviewed before merge.

2026-10-27 - GATE G13 DONE: zethora-miner `balance` / `--testnet balance`
(GetBalanceByAddress on the node; needs --utxoindex; never creates a key;
exit 4 with a clear message on missing key or no index). Verified on
devnet: printed zethoradev: address and 21361.19 ZTHR; bad arg ->
usage, exit 2. Release README explains it. Testnet run checked at the
v0.1.0-testnet.1 Ryzen check.
2026-10-27 - GATE G12 DONE: cargo-about (about.toml + about.hbs, target
x86_64-pc-windows-msvc) generates build-assets/THIRD-PARTY-CRATES.txt
(750 crate entries); release zip + SHA256SUMS include it. LGPL-3.0
accepted for malachite-base/-nz (inherited via kaspa-math, used for the
MuHash modular inverse; replacing consensus math is riskier). Notices
point to the public source as LGPL requires. CTO decision; lawyer to
confirm before mainnet. Regenerate the file whenever Cargo.lock changes:
cargo about generate --workspace about.hbs -o build-assets\THIRD-PARTY-CRATES.txt

## Standing rule: trust comes before growth
Nothing ships that a stranger can't verify, and nothing in the user experience may look hidden, pressured, or misleading. If a feature grows faster but costs trust, it waits. (Launchers are readable .cmd scripts for this reason; a GUI ships only with code signing.)

## Standing rule: no surprise chain splits (threat model T11)
Any change to consensus rules ships with a fixed activation height (or DAA score) announced before the release, so old and new nodes agree until that point. Never ship a consensus change that activates immediately on a live network. Test old-vs-new behaviour around the activation point before release.

## Standing rule: pre-testnet hardening
Every threat-model item that can be fixed or tested in code (docs/THREAT-MODEL.md) is done before public testnet opens, not deferred to mainnet. Exceptions only: items that need an outside party (ZK review, audit) or a live network to prove.

## Decision 2026-10-27: experimental privacy on testnet (option B)
CEO decision: after F1 is merged and CTO-reviewed, private payments are enabled on TESTNET ONLY, labeled "experimental, unreviewed, testnet coins are worth zero". Mainnet stays locked (G11 unchanged for mainnet) until an independent ZK cryptography review is complete. Purpose: find Orchard integration bugs early. Testnet cannot find silent soundness bugs (e.g. Zcash 2018 counterfeiting); the turnstile caps damage to the pool and the review remains mandatory. Before enabling: G11 change for testnet only with tests proving mainnet still refuses; update STATUS.md, FAQ.md, website and app wording the same day.

2026-10-28 - F1 per-transaction turnstile (branch f1-per-tx-turnstile,
PR open, NOT merged, PENDING CTO REVIEW). Merge loop keeps a running
private pool balance from the selected parent's sealed balance; each
merged block's valid txs are walked in block order with
zethora_supply::turnstile_accepts; a tx that would go below zero is
dropped before ANY effect (UTXO diff + muhash, coin tags, fingerprint,
note tree, fees, pool flows, acceptance data, seq-commit). Chain
block's own txs get the same running check (else disqualified, like the
own-tx coin tag rule). Template refuses pool_out above what is left
(ignores same-block pool_in). Per-block ledger_step turnstile kept as
backstop. No stored-state change, no devnet reset. Tests:
pipeline/tests/zethora_turnstile.rs (6) + 2 zethora_supply unit tests;
counterfeit = spend of a local-only coin whose anchor the test registers
as matured (TestConsensus::zethora_insert_anchor_for_good). Each new
test shown failing with its check removed (PR description). Written by
a Claude Code cloud session; needs CTO review before merge (standing
rule). Private payments stay OFF on testnet/mainnet (G11 unchanged).
