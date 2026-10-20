\# Genesis Regeneration Audit — 2026-10-19



\*\*Scope:\*\* Genesis block regeneration for mainnet and testnet, commits `43c51cf` and `e6562d1`.

\*\*Baseline:\*\* `1505e5c` (last commit before regeneration).

\*\*Audited against:\*\* `ff83657d` (HEAD at audit time).

\*\*Status:\*\* PASS for hash correctness, fair launch, and layout. PROVISIONAL for mainnet (see Residual Risks).



\## Verdict



Mainnet and testnet genesis values are cryptographically correct as of `ff83657d`. All five required checks pass. However, the mainnet genesis is \*\*provisional\*\* — it reuses devnet's timestamp and difficulty bits and must be regenerated at mainnet launch with a fresh timestamp and a dated headline in the tag.



1\. Hash verification (independent recompute) — PASS

2\. Network hash diversity — PASS

3\. Fair launch (zero premine) — PASS

4\. Zethora payload layout (byte offsets 56..88, 88..120) — PASS

5\. Generation method (code-driven) — PASS



\## Method



The `print\_zethora\_mainnet\_genesis` and `print\_zethora\_testnet\_genesis` tests in `consensus/core/src/config/genesis.rs` rebuild the `Block` from `GenesisBlock` fields, recompute `hash\_merkle\_root` from the coinbase transaction, then compute `block.hash()` via the consensus hashing path. Recomputed values match the committed constants:



| Field | Mainnet committed = recomputed |

|---|---|

| `hash\_merkle\_root` | `77a916f9a705f7d8f7ea622b81d0ef3167f16525263de4a25e93222248f7d13b` |

| `hash` | `b819b73927907518b0c8c22952128e6c8ab84e839c3a188c0e663e89a83713fe` |



| Field | Testnet committed = recomputed |

|---|---|

| `hash\_merkle\_root` | `0f786b71fcdc7b128dae39b0a0f01dddfa4c16f11c248bda657538991ab5928e` |

| `hash` | `d52ed6a66d825c3f5b5161c14d278d6ac5e0241793a664a21c42017208d2781b` |



`test\_genesis\_hashes` asserts the same property for all four networks (mainnet, testnet, simnet, devnet). Full test suite: `107 passed; 0 failed; 1 ignored; 344.46s`.



\## Baseline verification against upstream Kaspa



The baseline `1505e5c` mainnet genesis (pre-regeneration) was verified byte-for-byte against the published genesis at `kaspanet/rusty-kaspa` master (`consensus/core/src/config/genesis.rs`), fetched 2026-10-19:



| Field | Baseline (1505e5c) | Upstream Kaspa | Match |

|---|---|---|---|

| `hash` | `58c2d4199e21f910…2999` | same | ✅ |

| `hash\_merkle\_root` | `8ec89856…eb32` | same | ✅ |

| `utxo\_commitment` | `710f27df…e820` | same | ✅ |

| `timestamp` | `1637609671037` | same | ✅ |

| `bits` | `486722099` | same | ✅ |

| `nonce` | `0x3392c` | same | ✅ |

| `daa\_score` | `1312860` | same | ✅ |



\*\*Conclusion:\*\* Zethora's regenerated mainnet and testnet genesis blocks are provably distinct from Kaspa's published genesis. The fork inherits Kaspa's genesis field structure but not its hash — which is the intent of genesis regeneration.



\## Change set — mainnet (`e6562d1`)



| Field | Before | After |

|---|---|---|

| `hash` | `58c2d419…2999` | `b819b739…13fe` |

| `hash\_merkle\_root` | `8ec89856…eb32` | `77a916f9…d13b` |

| `utxo\_commitment` | `710f27df…e820` | `EMPTY\_MUHASH` |

| `timestamp` | `1637609671037` | `0x1a100cdff60` (Oct 3, 2026, same as devnet) |

| `bits` | `486722099` (approx 2^32 hashes) | `0x1f20c49b` (approx 2,000 hashes per block, same as devnet) |

| `nonce` | `0x3392c` | `0` |

| `daa\_score` | `1312860` | `0` |

| `coinbase\_payload` | Kaspa mainnet payload | Zethora layout, zero subsidy, zero ledger, zero note\_root/private\_state |



\## Change set — testnet (`43c51cf`)



| Field | Before | After |

|---|---|---|

| `hash` | `f896a303…4370` | `d52ed6a6…781b` |

| `hash\_merkle\_root` | `17341408…0c2a` | `0f786b71…928e` |

| `timestamp` | `0x17c5f62fbb6` (Dec 2022) | `0x1a100cdff60` (Oct 3, 2026, same as devnet) |

| `bits` | `0x1e7fffff` | `0x1f20c49b` (approx 2,000 hashes per block, same as devnet) |

| `nonce` | `0x14582` | `0` |

| `coinbase\_payload` | Kaspa testnet payload | Zethora layout, zero subsidy, zero ledger, zero note\_root/private\_state |



\## Fair launch confirmation



Genesis coinbase subsidy at bytes 8..16 of the payload is `00 00 00 00 00 00 00 00` for both mainnet and testnet. All supply ledger fields (bytes 16..56) are zero. `utxo\_commitment = EMPTY\_MUHASH` (hash of empty UTXO set). \*\*No premine, no genesis allocation, no initial UTXOs.\*\*



\## Zethora layout confirmation



Genesis coinbase payload follows the Zethora layout at documented byte offsets:



\- 56..88: `note\_root` (all zero for a fresh network)

\- 88..120: `private\_state` (all zero for a fresh network)

\- 120..122: script version

\- 122..123: varint (script length)

\- 123..124: OP-FALSE

\- 124..end: tag + message (`zethora-mainnet | Wake Up From The Dream World`)



Same layout as devnet genesis (unchanged at baseline and HEAD).



\## Commit Message Discrepancies



Both commits underreport their actual scope. The commit messages are preserved as historical record; this section is the audit-trail addendum.



\*\*`43c51cf` — message says "Set Testnet to 1 BPS and regenerate Genesis"\*\*



Actual change in `params.rs`:

MAINNET\_PARAMS: BlockrateParams::new::<10>() → BlockrateParams::new::<1>()

TESTNET\_PARAMS: BlockrateParams::new::<10>() → BlockrateParams::new::<1>()

SIMNET\_PARAMS: BlockrateParams::new::<10>() → BlockrateParams::new::<1>()





Three networks' block rate changed, not one. `genesis.rs` change is testnet genesis regeneration only.



\*\*`e6562d1` — message says "Set Mainnet to 1 BPS and regenerate Genesis"\*\*



Actual change in `genesis.rs` only. Mainnet BPS was already changed by the preceding commit `43c51cf`. The mainnet genesis regeneration is the entire change in this commit.



\## Residual risks and open items



\*\*1. Mainnet genesis is PROVISIONAL.\*\* The current mainnet genesis reuses devnet's `timestamp: 0x1a100cdff60` (Oct 3, 2026) and `bits: 0x1f20c49b` (approx 2,000 hashes per block). Both values are visible in the code comments at `genesis.rs:192`. This is acceptable for testnet and devnet but \*\*must be regenerated at mainnet launch\*\* with:

\- A fresh timestamp set to the actual mainnet launch moment.

\- A dated headline in the coinbase tag (e.g. `zethora-mainnet | <launch date> | Wake Up From The Dream World`) so the launch moment is publicly timestamped and no early mining could have occurred before it.



Until this regeneration is done, no claim that the current mainnet genesis is the permanent one can be made.



\*\*2. Genesis initial difficulty is devnet-scale.\*\* Genesis `bits` for mainnet and testnet is `0x1f20c49b`, which the code comment at `genesis.rs:192` describes as \*\*approx 2,000 RandomX hashes per block\*\* — the same easy difficulty used for devnet. This is standard for regenerated genesis (the genesis block must be trivially mineable for the chain to start), and Kaspa's DAA adjusts difficulty upward as blocks are mined. Verify the DAA climbs fast enough during the first hour of testnet that the network does not spend extended time at devnet-scale difficulty. This is an observation to make during testnet, not a defect.



\*\*3. Simnet block rate changed to 1 BPS but its pre-Crescendo target comment still says 10 BPS.\*\* Commit `43c51cf` changed `SIMNET\_PARAMS.blockrate` from `BlockrateParams::new::<10>()` to `BlockrateParams::new::<1>()`, but `SIMNET\_PARAMS.pre\_crescendo\_target\_time\_per\_block` still uses `TenBps::target\_time\_per\_block()` and the accompanying comment still describes "default 10BPS configuration". This is an internal inconsistency to reconcile, not a functional bug (simnet is for local testing). Flagged for cleanup in a future commit.



\*\*4. Hash diversity test.\*\* A `test\_genesis\_hash\_diversity` test is included in `consensus/core/src/config/genesis.rs` alongside this audit (added by the same remediation work), asserting all four network genesis hashes are pairwise distinct.



\## Verification commands



Anyone auditing this record can rerun the verification:

cargo test -p kaspa-consensus-core print\_zethora\_mainnet\_genesis -- --nocapture

cargo test -p kaspa-consensus-core print\_zethora\_testnet\_genesis -- --nocapture

cargo test -p kaspa-consensus-core test\_genesis\_hashes -- --nocapture

cargo test -p kaspa-consensus-core test\_genesis\_hash\_diversity -- --nocapture





\## Sign-off



Prepared by: DeepSeek (AI).

Reviewed by: Claude (AI).

Approved by: Deion Smith.



This is an internal AI-assisted review, not a professional security audit. The genesis regeneration was reviewed for cryptographic correctness, fair-launch properties, and payload layout. The mainnet genesis is provisional pending launch-time regeneration. A professional third-party audit of the full consensus layer (including this genesis regeneration) remains the gate for mainnet launch and enabling private sends.