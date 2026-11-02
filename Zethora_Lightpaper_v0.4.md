\# ZETHORA

\### Fair money for people and machines.

\### Lightpaper v0.4 · Live Testnet Edition · November 2026



\---



\## 1. Summary



Zethora is a Layer-1 proof-of-work blockchain that combines three properties no single network has brought together before:



\- \*\*Bitcoin's fair scarcity\*\* — 100,000,000 ZTHR, ever. No premine. No VC allocation. Every coin is mined.

\- \*\*Kaspa's speed\*\* — a BlockDAG ordered by GHOSTDAG, target \~1 block per second.

\- \*\*Monero's home mining\*\* — CPU-friendly proof-of-work (RandomZ) that any home computer can run.



It adds \*\*Zcash-grade privacy\*\* using Orchard 0.16.0. Privacy is integrated and working. Private sending is currently disabled on the public testnet and will be enabled as an experimental, unreviewed feature in a future testnet update. Mainnet keeps it disabled until an independent review is complete. We are looking for a reviewer.



\*\*Programmability (smart contracts) is planned research, not a current feature.\*\* See Section 5.3. It requires a dedicated engineering team and will be pursued when resources allow. It is not promised for testnet or mainnet.



\*\*Status: Live Public Testnet.\*\* The v0.1.0 testnet is live and open to the public. The one-click Windows installer is available for download. Mainnet will launch only after a minimum six-month public testing period and all security gates pass.



\---



\## 2. Why Zethora



Bitcoin began on home computers. Today it is mined in warehouses and every balance is public forever. Ethereum made money programmable but began with a presale. Solana is fast but asks for data-center hardware. Monero is private and home-mineable but slow. Zcash is private but CPU mining is impractical.



Each excels at one or two things. None is \*\*fair, fast, home-mineable, and private\*\* at once.



| Property | Inspired by | In Zethora |

|---|---|---|

| Scarcity | Bitcoin | 100,000,000 ZTHR, every coin mined, no premine |

| Speed | Kaspa / Solana | BlockDAG, \~1 block per second |

| Home mining | Monero | RandomZ CPU proof-of-work |

| Privacy | Zcash | Orchard 0.16.0 (integrated; under review) |

| Programmability | Ethereum | \*\*Planned research, not built\*\* |



\---



\## 3. Principles



\- \*\*Fair launch.\*\* Genesis holds 0 coins. No premine, presale, founder, or investor allocation.

\- \*\*No owner.\*\* No admin key, pause switch, freeze power, or upgrade override exists for anyone. Not for the builders. Not for any company.

\- \*\*Fixed money rules.\*\* Supply and issuance can never change. Software that changes them is not Zethora.

\- \*\*Privacy by default, honestly disclosed.\*\* Anyone choosing transparency is clearly told what becomes public.

\- \*\*Security over speed of launch.\*\* Audits, formal verification, and a long public testnet come first.

\- \*\*Home-computer rule.\*\* If speed and decentralization conflict, a normal home computer must still be able to run a node and mine.

\- \*\*No price promises.\*\* Zethora makes no claims about the future value of ZTHR.



\---



\## 4. Monetary Policy



Zethora has a strict, immutable hard cap of \*\*100,000,000 ZTHR\*\*. 



\- \*\*Smallest Unit:\*\* The "zet" (1 ZTHR = 10,000,000,000 zets).

\- \*\*No Premine:\*\* Genesis block yields 0 coins to the founders.

\- \*\*Emission Schedule:\*\* Zethora uses a smooth decay emission curve (similar to Kaspa), but stretched to a \*\*8-year halving cycle\*\* (instead of the traditional 4-year cycle) to give home miners a longer window of fair rewards.

\- \*\*Starting Reward:\*\* The block reward begins at \~0.2745 ZTHR per block.

\- \*\*Supply Check:\*\* Every single block validates the total supply against the hard cap. If the math does not balance perfectly (BALANCED), the block is rejected by the network.



\---



\## 5. Design Overview



\### 5.1 BlockDAG Architecture

Zethora uses the GHOSTDAG protocol inherited from Kaspa. Instead of a single chain of blocks, it is a directed acyclic graph (BlockDAG). This allows blocks to be mined in parallel without orphaning them, enabling a target speed of \*\*1 block per second\*\* while maintaining high security and decentralization.



\### 5.2 Mining (RandomZ)

Zethora uses \*\*RandomZ\*\*, a variant of RandomX. It is optimized for standard x86-64 CPUs. The algorithm forces miners to use general-purpose hardware, resisting ASIC and GPU centralization. A normal home computer can mine effectively. The one-click Windows installer handles all node and miner setup automatically.



\### 5.3 Programmability — planned research

Zethora does not currently support smart contracts. The `simpa` crate in the repository is a Kaspa network simulator inherited with the fork; it is not a virtual machine and provides no smart-contract execution.



\*\*If\*\* programmability is added in the future, the design direction is an object-model language in the Move family. Ethereum compatibility would be considered only after that. 



\*\*What this requires:\*\*

\- A bytecode execution engine with a formal specification.

\- Independent cryptographic and formal-methods review of VM semantics.

\- A dedicated engineering team funded over multiple years.



\*\*What this is not:\*\*

\- It is not promised for testnet or mainnet.

\- It is not a current feature.

\- It may not ship at all if it cannot be built to a safety standard the community accepts.



\### 5.4 Privacy (Zcash Orchard)

Zethora integrates \*\*Zcash Orchard 0.16.0 (Halo2)\*\* for base-layer private transactions. 

\- \*\*Devnet:\*\* Fully private.

\- \*\*Testnet:\*\* Private sending is currently hard-refused (off) while the network stabilizes. It will be enabled as an experimental, unreviewed feature in a future update to help find bugs.

\- \*\*Mainnet:\*\* Private sending will remain \*\*OFF\*\* until an independent, third-party cryptographic review is completed.



\---



\## 6. Governance and Upgrades



Zethora has no central governance. There is no foundation, DAO, or admin key that can alter the chain state or the monetary policy. 



Upgrades to the consensus layer require a hard fork. Protocol improvements are proposed via \*\*Zethora Improvement Proposals (ZIPs)\*\*, discussed openly in the repository, and only adopted if the economic majority of node operators choose to run the updated software.



\---



\## 7. Security and Launch



Zethora prioritizes verifiable structural integrity. Before testnet, the codebase underwent an intensive, line-by-line "Seam Review" to ensure the integration between Kaspa's BlockDAG and Zcash's Orchard privacy did not introduce consensus bugs or inflation exploits. 



\- All 54 findings from the seam review were resolved.

\- Every security test adheres to a strict "fail-when-removed" standard (proving the test fails if the protection is deleted).

\- \*\*Mainnet Gates:\*\* Mainnet will not launch until: (1) The public testnet has run securely for a minimum of 6 months, (2) The independent ZK/Orchard audit is complete, (3) The privacy layer is reviewed and approved.



\---



\## 8. Ecosystem



\*\*What DeionRaven Labs builds.\*\* DeionRaven Labs is the lead builder of Zethora, not its owner. It holds no coins except those it mines or buys like anyone else. It earns through products built on top:



\- The Zethora app: wallet, home-mining dashboard, phone remote.

\- A block explorer.

\- Family money tools: vaults, kids' funds, allowances, inheritance.

\- Later: any AI or device products that use Zethora natively.



\*\*What DeionRaven Labs does not have.\*\* No protocol privileges. No admin keys. No ability to change supply, freeze accounts, or pause the network. If the company disappeared tomorrow, the chain would continue running.



\---



\## 9. Roadmap



| Phase | Focus | Status |

|---|---|---|

| 1. Specification | Core specs published for public comment | ✅ Complete |

| 2. Prototype | Working private devnet | ✅ Complete |

| 3. Public testnet | Minimum six months, open to all | 🟢 \*\*LIVE (v0.1.0)\*\* |

| 4. Mainnet | Only when every launch gate passes | ⏸️ Pending Audit |

| 5. Ecosystem | Apps, launchpad, tools, wallet GUI | ⏳ In Progress |

| Research | Programmability, if pursued | ⏸️ Deferred |



\---



\## 10. Get Involved



Read the specifications, open issues, and propose changes through ZIPs. Builders in Rust, cryptography, consensus, wallets, and security are welcome. Contributors receive credit — never coins. The fair launch stays fair.



\*\*Download the Testnet:\*\* https://tinyurl.com/Zethora-Testnet



\---



\*\*Disclaimer.\*\* This document describes a proposed design that may change. It is not an offer to sell, not investment advice, and makes no representation about the future price or value of any asset.



\*Wake Up From The Dream World.\*

