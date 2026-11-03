# Zethora Shielded Coinbase Specification

## The Problem
In Bitcoin, Kaspa, and Monero, block rewards are paid to transparent addresses. Anyone can track a miner's wallet, calculate their exact hashrate, and see how much they are earning. This is a security risk for industrial miners.

## The Zethora Solution
Zethora will modify the mining reward routing so that block rewards are sent directly into the Orchard shielded pool. 

### How it works
1. The miner connects to the node and generates an Orchard shielded address.
2. The miner passes this shielded address to the node via the coinbase payload.
3. When a block is found, the node constructs the coinbase transaction with the output pointing to the Orchard shielded address.
4. The miner is completely invisible from block 1.

## Current Status (Testnet)
Because the Orchard integration is disabled, this feature is mocked on testnet. Once the ZCG grant funds the audit, the coinbase payload will be updated to support `zs...` addresses.
