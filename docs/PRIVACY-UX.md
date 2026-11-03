# Zethora Privacy UX & Exchange Bridge Specification

## The Problem
Zcash failed to achieve mass privacy because transparent addresses are the default. Monero achieved mass privacy but was delisted by exchanges due to a lack of AML compliance.

## The Zethora Solution: Private by Default, Transparent by Bridge

### 1. The Default State (Shielded)
When a user runs `zethora-wallet receive`, the wallet will **only** generate an Orchard shielded address (`zs...`). 
When a user runs `zethora-wallet send <address> <amount>`, the wallet will automatically route the transaction through the Orchard shielded pool. 
To the user, this is as simple as using Monero. To the network, the anonymity set is massive because *everyone* is using it.

### 2. The Exchange Bridge (Transparent)
Exchanges (Binance, Coinbase) require transparent addresses for AML compliance. 
The Zethora wallet includes a specific command: `zethora-wallet exchange-deposit`.
This command unshields the requested amount and generates a one-time transparent address (`zethoratest...`) that the user can then deposit to a CEX. 
The CEX sees a standard transparent transaction. They are happy.

### 3. View Keys for Auditors
Zethora inherits Zcash's "View Key" feature. A user can generate a viewing key for a specific transaction or timeframe and share it with an exchange's compliance team, proving the source of funds without revealing their entire wallet history to the public.

## Current Status (Testnet)
Because the Orchard integration is disabled pending an independent audit, the `receive` command currently falls back to a transparent address. Once the audit is complete and funded via the ZCG grant, this UX will be flipped.
