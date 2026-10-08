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

## Run commands (devnet)
- Node: `cargo run --release --bin kaspad -- --devnet --utxoindex --enable-unsynced-mining` (add `--reset-db --yes` only when a patch changes stored state)
- Miner: `cargo run --release -p zethora-miner` (prints a Supply check line per block: must say BALANCED)
- Private wallet tool: `cargo run --release -p zethora-shield -- <0.1 | balance | send 0.05 | unshield 0.05 | attack | replay | bump 0.02 | compare>`
  (`-- node2 <command>` sends to the second node; the chain is always read from node 1)
- Step 3c test (fast pruning, node 1 archival so the wallet can still read old blocks):
  node 1 `cargo run --release --bin kaspad -- --devnet --utxoindex --enable-unsynced-mining --archival --override-params-file=devnet\fast-pruning.json` (+ `--reset-db --yes` the first time),
  node 2 `.\target\release\kaspad.exe --devnet --appdir=C:\Users\deion\zethora-node2-data --listen=127.0.0.1:26621 --rpclisten=127.0.0.1:26620 --connect=127.0.0.1:26611 --override-params-file=devnet\fast-pruning.json --disable-upnp`.
  Going back to the normal devnet afterwards needs `--reset-db --yes` without the override file.

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

## Known gaps / next steps
- ANCHOR_DEPTH 600 assumes ~1 block/s; scale with real block rate before testnet.
- TESTNET_PARAMS and MAINNET_PARAMS are still Kaspa's 10 blocks/sec (BlockrateParams::new::<10>()), and their genesis
  is Kaspa's. The reward divisor D assumes 1 block/sec: set both to 1 block/sec with Zethora genesis blocks before any
  testnet launch (rewards would otherwise come 10x faster; the 100M cap rule still holds, but at 10 bps the DAG
  overshoot bound (window 661x40 + 248) is ~7,300 ZTHR > the 1,000 reserve, so the CapExceeded backstop could fire
  near the end of emission and STALL the chain). Simnet is also 10 bps (tests only). Kaspa tests that use
  MAINNET/TESTNET params will need care when that changes.
- Pruning-point sync of shielded state: 3a, 3b, 3c done and verified live (item 15). Privacy step 4 speed test done (item 16). Privacy section A complete. B5 (100M check) done (item 17). B6a RandomZ params + bench (item 18); 6b key rotation next.
  The whole private state is held in memory on both sides during the download, and the server builds it before
  sending the header (client waits DEFAULT_TIMEOUT); fine now, stream it before mainnet.
- Banning by IP: two nodes on one PC share 127.0.0.1, so a ban there hits both. Fine for devnet.
- Before testnet: bans are per IP only; other invalid blocks (not forged payments) only disconnect.
- Needs a human crypto reviewer before private sending reaches a public network, then a professional audit before launch.
- Miner app ideas (demos only, not linked to the real miner): "Raven Room" (pixel room + mine) and "Zethora Miner"
  (GoMining-style rig app). Rule: upgrades are earned/cosmetic; never pay to mine more ZTHR (fair launch).

- Known old failing test: consensus processes::coinbase::tests::subsidy_test checks Kaspa's 50-coin schedule, which
  Zethora replaced (zethora_subsidy). Don't use a bare "coinbase" test filter in scripts.

## Safety rules for Claude
- Never promise coins, staking returns or paid hashrate. No token exists yet.
- Don't route around network blocks; if crates.io is blocked in the sandbox, his PC compiles and Claude checks against library sources.
