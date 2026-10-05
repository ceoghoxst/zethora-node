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

## Known gaps / next steps
- ANCHOR_DEPTH 600 assumes ~1 block/s; scale with real block rate before testnet.
- Pruning-point sync of shielded state not supported (node halts with a message).
- Fees for private payments are paid from a visible coin; fully private payments (no visible part) later.
- Needs a human crypto reviewer before private sending reaches a public network, then a professional audit before launch.
- Miner app ideas (demos only, not linked to the real miner): "Raven Room" (pixel room + mine) and "Zethora Miner"
  (GoMining-style rig app). Rule: upgrades are earned/cosmetic; never pay to mine more ZTHR (fair launch).

## Safety rules for Claude
- Never promise coins, staking returns or paid hashrate. No token exists yet.
- Don't route around network blocks; if crates.io is blocked in the sandbox, his PC compiles and Claude checks against library sources.
