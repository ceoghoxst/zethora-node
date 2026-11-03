# Zethora Architecture & Vision

Zethora is not a clone; it is the apex modular ecosystem combining the best traits of the industry's leading blockchains.

## The 3 Locked Pillars

### Pillar 1: Private by Default (The UX War)
Zcash failed because privacy was an optional toggle, creating a tiny anonymity set. Zethora fixes this at the wallet level:
*   The default wallet (CLI and GUI) generates Orchard (Halo2) **shielded addresses** (zs...).
*   Transparent addresses (zethoratest:) are hidden in an "Exchange Bridge" flow.
*   This forces 99% of network activity into the shielded pool, creating a massive anonymity set.
*   Exchanges still get AML compliance because the Exchange Bridge generates a transparent deposit address only when needed.

### Pillar 2: Shielded Coinbase (The Miner's Shield)
In Bitcoin, Kaspa, and Monero, block rewards go to transparent addresses. Anyone can track a miner's balance and hashrate.
*   Zethora modifies the mining reward routing so that **block rewards are sent directly into the Orchard shielded pool**.
*   Miners remain completely anonymous from block 1.

### Pillar 3: The zkEVM Execution Layer (The Ethereum Threat)
Kaspa's UTXO model cannot natively run Ethereum smart contracts without breaking consensus.
*   Zethora L1 remains the pure, fast GHOSTDAG PoW settlement layer.
*   Zethora L2 will be a **zkEVM Rollup** (like zkSync or Scroll) that executes smart contracts off-chain and posts ZK-proofs back to the Zethora L1 in 1 second.
*   Result: Ethereum programmability + Zcash privacy + Kaspa speed.

## The Roadmap
1. **Phase 1 (Current):** Live Testnet, Rust Wallet, Tabbed Windows GUI.
2. **Phase 2 (Audit):** Independent cryptographic audit of the Orchard integration (ZCG Grant).
3. **Phase 3 (UX Pivot):** Flip the wallet to Private-by-Default. Implement Shielded Coinbase.
4. **Phase 4 (Execution):** Testnet deployment of the zkEVM L2.
