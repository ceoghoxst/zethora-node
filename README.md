# Zethora Node

**Prototype node for Zethora — a fair-launch, home-mined, privacy-focused Layer-1.**

This is a Rust implementation forked from Kaspa's open-source BlockDAG node. It runs the Zethora devnet and is the reference node for the Zethora network.

## Status

**Prototype. No public network yet.**

- Private devnet: working
- Testnet: not live
- Mainnet: not live

## What is Zethora

Zethora combines:

- **Bitcoin's scarcity** — 100M ZTHR, no premine, every coin mined
- **Kaspa's speed** — BlockDAG, ~1 block per second
- **Monero's home mining** — RandomZ CPU proof-of-work
- **Zcash-grade privacy** — Orchard 0.16.0 (integrated; disabled on public networks pending cryptographic review)

Read the full design: github.com/ceoghoxst/Zethora

## Running a devnet node

Prerequisites: Rust toolchain (stable), Clang/LLVM 15+, protobuf compiler.

    cargo build --release --bin kaspad
    cargo run --release --bin kaspad -- --devnet --utxoindex --enable-unsynced-mining

The node listens on:

- P2P: 0.0.0.0:26611
- gRPC: 127.0.0.1:26610

## Mining

    cargo run --release -p zethora-miner

Mining uses RandomZ (a variant of RandomX) and runs on any modern CPU. Every block prints a supply check that must say BALANCED.

## Privacy

Private sending uses Zcash's Orchard 0.16.0. It is disabled on testnet and mainnet until an independent cryptographic review is complete. On devnet it works:

    cargo run --release -p zethora-shield -- balance
    cargo run --release -p zethora-shield -- send 0.05
    cargo run --release -p zethora-shield -- unshield 0.05

## No owner

There is no admin key, no pause button, no freeze power, and no upgrade override. Not for the builders, not for any company. The money rules cannot be changed by anyone.

## Repository layout

- kaspad/ — the node binary
- consensus/ — consensus rules, BlockDAG, PoW
- zethora-miner/ — Zethora's home-CPU miner
- zethora-shield/ — the shielded wallet tool
- zethora-shielded/ — the Orchard-based privacy layer
- randomz/ — the RandomZ mining algorithm
- protocol/ — P2P networking and flows
- wallet/ — wallet primitives

## Documentation

- Zethora Lightpaper v0.3: github.com/ceoghoxst/Zethora
- Specifications: github.com/ceoghoxst/Zethora/tree/main/specs
- CLAUDE.md — project notes and known gaps

## Contributing

Zethora is built in the open. Contributors receive credit — never coins. The fair launch stays fair.

## Disclaimer

This repository describes a proposed design. It is not an offer to sell anything, not investment advice, and makes no claims about the future price or value of any asset.

---

Wake Up From The Dream World.

X: @ZethoraNetwork · Built by DeionRaven Labs