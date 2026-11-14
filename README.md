# Zethora: The Private Execution Layer

Zethora is a fair-launch Layer-1 Proof-of-Work network fused with a native Rust EVM and Zcash Orchard privacy. 

**No VC. No premine. 100M hard cap.**

## Architecture
- **L1 (Kaspa Fork):** 1-second blocks via GHOSTDAG, mined with RandomZ (CPU-only).
- **L2 (Rust EVM):** Full Solidity support, EIP-1559, Chain ID 2600.
- **Privacy Layer:** Opt-in Zcash Orchard ZK circuits for shielded transactions.

## Public Testnet
The testnet is currently live and accepting remote miners.

- **Seed Node:** grpc://95.216.185.137:26210
- **L2 RPC:** https://95.216.185.137.nip.io (Chain ID: 2600)
- **Faucet:** http://95.216.185.137:8080

### How to Mine
Download the latest miner from the [Releases](https://github.com/ceoghoxst/zethora-node/releases) page or the Discord.

**Windows:**
.\zethora-miner.exe --testnet --node grpc://95.216.185.137:26210

**Linux:**
./zethora-miner --testnet --node grpc://95.216.185.137:26210

For more detailed instructions, see [SENTINELS.md](SENTINELS.md).

## Development
To build the node from source:
cargo build --release

## Security
We do not claim to be audited. We are actively patching vulnerabilities found by our internal Red Team and community Sentinels. 

If you find a bug, please refer to [CONTRIBUTING.md](CONTRIBUTING.md).