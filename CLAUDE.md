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
- Private wallet tool: `cargo run --release -p zethora-shield -- <0.1 | balance | send 0.05 | unshield 0.05 | attack>`

## Done and verified on his devnet (as of Oct 5, 2026)
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

## Known gaps / next steps
- ANCHOR_DEPTH 600 assumes ~1 block/s; scale with real block rate before testnet.
- Pruning-point sync of shielded state not supported (node halts with a message).
- Fully private payments can't be fee-bumped yet (no visible input to replace by fee; the mempool refuses a re-send
  that reuses the coin tags). Needs RBF keyed on coin tags.
- Blocks carrying a forged private payment get their peer disconnected (Kaspa default) but not banned.
- Banning by IP: two nodes on one PC share 127.0.0.1, so a ban there hits both. Fine for devnet.
- Before testnet: outbound dialing doesn't skip banned IPs (address gossip can bring one back); bans are per IP only;
  proof checks run under the virtual-state read lock (move them out); forged blocks are cheap on devnet PoW.
- Needs a human crypto reviewer before private sending reaches a public network, then a professional audit before launch.
- Miner app ideas (demos only, not linked to the real miner): "Raven Room" (pixel room + mine) and "Zethora Miner"
  (GoMining-style rig app). Rule: upgrades are earned/cosmetic; never pay to mine more ZTHR (fair launch).

## Safety rules for Claude
- Never promise coins, staking returns or paid hashrate. No token exists yet.
- Don't route around network blocks; if crates.io is blocked in the sandbox, his PC compiles and Claude checks against library sources.
