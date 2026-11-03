# Zethora: The Private Execution Layer for Proof-of-Work

## Abstract
Zethora is a fair-launch, Proof-of-Work Layer 1 blockchain built on the GHOSTDAG consensus (Kaspa fork). It features 1-second block times, a 100,000,000 ZTHR hard cap with no premine, and CPU-friendly RandomZ mining. Zethora integrates Zcash Orchard 0.16.0 (Halo2) to provide a privacy-first network with a compliance bridge for exchanges. Furthermore, Zethora is developing a native Rust zkEVM Layer 2 to bring programmable, private smart contracts to a PoW environment.

## 1. Compliance and Exchange Readiness
Privacy coins fail when they cannot be listed on regulated exchanges due to Anti-Money Laundering (AML) requirements. Zethora is designed for CEX integration.

**Private by Default, Transparent for Compliance:**
- **Shielded Default:** The wallet defaults to Orchard shielded addresses.
- **Exchange Transparency Bridge:** The wallet includes an `exchange-deposit` command. This generates a transparent address specifically for depositing to a centralized exchange.
- **Selective Disclosure:** Users can generate View Keys to prove the source of funds to an auditor or exchange without exposing their entire wallet history.
- **Privacy Status:** The Orchard privacy flag is currently **locked** on testnet and mainnet pending an independent cryptographic review. 

## 2. Privacy Architecture (Zcash Orchard)
Zethora integrates the upstream Zcash Orchard (Halo2) library. 
- **Shielded Coinbase:** The consensus rules have been modified to allow miners to route block rewards directly into an Orchard shielded address. 
- **Status:** The shielded coinbase logic is coded and integrated, but execution remains gated behind the global privacy flag until the external audit is complete.

## 3. Consensus and Mining
- **Consensus:** GHOSTDAG BlockDAG (derived from Kaspa). This allows parallel block creation and 1-second block times without sacrificing decentralization.
- **Mining:** RandomZ (RandomX variant). ASIC-resistant and CPU-friendly, allowing home miners to secure the network.
- **Emission:** Smooth decay. 50% of the supply is mined in the first 8 years. No halving cliff.

## 4. The zkEVM Execution Layer
Zethora is developing a native Rust zkEVM (Zero-Knowledge Ethereum Virtual Machine) as a Layer 2.
- **Execution Engine:** The `zethora-evm` crate implements a full EVM execution environment using `revm` and `alloy-consensus`. It supports EIP-1559 transactions, native signature recovery, and batch state transitions.
- **Security:** The execution engine has been subjected to internal adversarial red-teaming (including replay attacks, signature malleability, and state corruption on rollback).
- **Status:** The execution engine is functional. The SP1 Zero-Knowledge Prover is integrated. The L1 settlement bridge is currently in development.

## 5. Security and Auditing
- **Adversarial Testing:** The Orchard integration and consensus rules have undergone internal adversarial testing. A critical consensus bypass (allowing shielded coinbases when privacy was disabled) was discovered and patched during this process.
- **External Review:** Zethora does not claim to be audited or secure. An application has been submitted to the Zcash Community Grants program to fund an independent audit of the Orchard integration. 

## 6. Tokenomics and Governance
- **Supply:** 100,000,000 ZTHR.
- **Distribution:** 100% Proof-of-Work. No ICO, no VC allocations, no founder premine.
- **Governance:** The protocol has no admin keys and no pause key. Upgrades only occur through voluntary node operator adoption.

## 7. Roadmap
1. **Current:** Testnet v0.1.2. Cross-platform builds (Windows/Linux). EVM execution engine complete.
2. **Q1:** Zcash Orchard Audit (pending grant funding). ZK-Prover (SP1) integration.
3. **Q2:** Mainnet launch (conditional on successful audit).
4. **Q3+:** zkEVM L2 deployment and DeFi ecosystem onboarding.

*Maintained by DeionRaven (Deion Smith).*
