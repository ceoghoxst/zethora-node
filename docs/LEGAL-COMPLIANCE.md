# Zethora Legal & Compliance Strategy

Zethora is designed to be the most legally defensible privacy network in the world. We do not compromise on user privacy, but we provide the cryptographic and architectural tools required for institutional compliance.

## 1. Non-Custodial Architecture
Zethora is open-source, non-custodial software. The Zethora Foundation (or core developers) do not hold user funds, do not operate a money transmitter business, and cannot freeze or seize user assets. The network is secured by physical Proof-of-Work (RandomZ).

## 2. The Exchange Bridge (AML/CFT Compliance)
Exchanges are required by the FATF (Financial Action Task Force) to implement Anti-Money Laundering (AML) checks. Pure privacy coins like Monero fail this requirement.
Zethora solves this with the **Exchange Bridge**:
- Exchanges integrate ONLY with the transparent address format (`zethoratest:`).
- When a user wants to sell, they use `zethora-wallet exchange-deposit` to unshield funds to a transparent address.
- The exchange sees a standard, traceable UTXO transaction, satisfying their regulatory obligations.

## 3. View Keys (Transaction-Level Auditability)
Zethora inherits Zcash Orchard's View Key technology. Users can generate a View Key that reveals only the sender, receiver, and amount of a specific transaction (or timeframe) to a third party (e.g., an auditor or law enforcement).
This allows users to prove the legitimate source of their funds without doxxing their entire wallet history to the public.

## 4. Commodity Classification
Zethora has no premine, no ICO, and no central allocation. 100% of the supply is mined through Proof-of-Work. Under the Howey Test, ZTHR is a commodity (like Bitcoin), not a security.
