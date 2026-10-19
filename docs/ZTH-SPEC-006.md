# ZTH-SPEC-006 — Zethora Privacy Layer

| Field   | Value |
|---------|-------|
| Status  | Draft (devnet phase) |
| Version | 0.1 (consolidated from code citations) |
| Date    | 2026-10-19 |
| Authors | Zethora contributors |
| Related | ZTH-SPEC-008 (fee pool), ZTH-IMPL-020 (RandomZ DoS ban), Zethora_Lightpaper_v0.3 |

## Honesty block

This spec describes a mechanism in the **devnet phase**. State of the world:

- **No token exists.** No premine. No presale. No smart contracts.
- **Private sends are disabled on testnet and mainnet.** They are enabled only on devnet and simnet. See §7.3.
- The mechanism described here has not been externally audited. An external review of the Orchard integration is the gate for enabling private sends on public networks.

This document is a consolidation of the `ZTH-SPEC-006` citations that appear across the codebase. Where a section is fully specified by code, the mechanism is described. Where a section is cited but the code carries the detail, a code reference is given. Where a section is cited but neither spec text nor code fully specifies it, it is marked **TBD**.

## Scope

This spec defines the Zethora private-money layer: how a coin moves from the transparent pool into the Orchard pool, how it moves within the Orchard pool, how it comes back out, and how DAG consensus enforces that no private coin is spent twice despite the parallel structure of a BlockDAG.

## Non-goals

- The Orchard cryptographic primitive itself (see the Zcash Orchard specification, version 0.16.0). This document treats Orchard as a black box with a defined byte interface (§4).
- The fee-market accounting for base fees (see ZTH-SPEC-008).
- Wallet UX (see the `zethora-shield` tool).

## Threat model

Adversary who can:

- Mine blocks, including parallel siblings in the same merge window (§6.3).
- Craft arbitrary private payloads, including forged proofs and replayed nullifiers.
- Attempt to reference a stale or fabricated coin-list anchor (§6.2).
- Flood the mempool with private-payment proof checks (§8.1).

Assumed not possible:

- Breaking Orchard soundness.
- Majority hash-rate reorg (standard PoW assumption).

Out of scope:

- Network-layer traffic analysis.
- Side-channel attacks on the wallet host.

---

## §4 — Wire format

A private payment travels inside a native-subnetwork transaction's `payload` field, prefixed by `PRIVATE_PAYMENT_MAGIC`, then an Orchard bundle encoded to mirror Zcash v5 Orchard with fixed-size counts.

- **Byte layout and encoding:** see `zethora-shielded/src/codec.rs`.
- **Size:** a 2-action bundle encodes to 9,144 bytes (`zethora-shielded/tests/pool.rs`).
- **Binding to the transaction:** the bundle's signature covers `zethora_private_payment_digest(tx)` (see `consensus/core/src/hashing/tx.rs`), which is the transaction with signature scripts, mass commitments, and payload excluded. This binds the private payment to its transaction; transparent-input signatures in turn cover the payload, so the two sides lock each other in.
- **Parse failures:** `private_payment_bytes` returns `None` for ordinary transactions and `Err` for malformed magic-prefixed payloads (`consensus/core/src/zethora_private.rs`).

**TBD:** the byte-level field ordering is not reproduced here; `codec.rs` is the reference.

## §5 — Compute mass

Each action pays a fixed compute-mass price for its share of proof verification:

- `PROOF_MASS_PER_ACTION = 15_000` (`consensus/core/src/zethora_private.rs`).
- Measured at ~1.85 ms per action on the reference PC, keeping a full block's proof checks to a small share of a second.
- **Fully private payments** have no visible inputs, so the standard storage-mass formula would divide by zero. Handled explicitly: the input side is empty, and the outputs' harmonic part is the whole storage mass (`consensus/core/src/mass/mod.rs`).

---

## §6 — Private state

The "private state" is the projection of the Orchard coin set that consensus must verify without learning coin contents. It is committed into the coinbase of every block (§6.4) and reconstructed by nodes joining from a pruning point.

### §6.1 — The coin list (note-commitment tree)

Every private payment output produces a note commitment. Zethora maintains an append-only Merkle tree of these commitments called the **coin list** or **note tree**, implemented as `zethora_shielded::NoteCommitmentTree` and stored per chain block in `DbZethoraNoteTreesStore`.

Rules:

- **Append-only.** Once a commitment is added, it is never removed. The tree root changes only by appending.
- **Ordered by consensus.** Commitments are appended in the order transactions are accepted by the mergeset loop, which walks `consensus_ordered_mergeset_without_selected_parent` (`utxo_validation.rs`). Every node builds the identical tree and reaches the identical root.
- **Deduplicated.** Orchard soundness plus the nullifier rules (§6.3) guarantee each commitment appears at most once.
- **Committed.** The tree root at the end of each mergeset is sealed into the block's coinbase as `CoinbaseData::note_root` and exposed on `VirtualState::note_root`.

### §6.2 — Coin list snapshots (anchors)

An **anchor** is a historical coin-list root. A private spend references the anchor corresponding to the coin-list state at the moment the spent note was created.

Rules:

- **Depth.** An anchor is usable only when the block that produced it is at least `ANCHOR_DEPTH = 600` blue scores below the current tip (`utxo_validation.rs::anchor_matured_on_chain`). At 1 BPS this is roughly 10 minutes. **TODO before testnet:** scale with the network's real block rate (10x at 10 blocks/s), per the code comment in `zethora_private.rs`.
- **Provenance.** The producing block must be a chain ancestor of the selected parent, or the anchor must have been rewritten to `ANCHORED_FOR_GOOD` by the pruning processor (blue score preserved).
- **Storage.** `DbZethoraAnchorsStore` maps `anchor_root -> Vec<ProducerRecord>` where each record is `(block, blue_score)`. Genesis produces the first (empty-list) anchor.
- **Pruning rewrite.** When the producing block is pruned, its record is rewritten to `ANCHORED_FOR_GOOD` preserving blue score, so a node that joined from a pruning point makes the same maturity decision as a node with full history.
- **Fingerprint inclusion.** Anchors are added to the fingerprint with their blue score (§6.4).

**TBD:** behavior of anchors under a reorg that disconnects the producing block. `try_is_chain_ancestor_of` is used in the maturity check but the reorg case is not covered by an integration test.

### §6.3 — Nullifiers and parallel-spend rejection

A private spend reveals a nullifier — a deterministic value tied to the spent note. A valid spend can only reveal each nullifier once. In a DAG, enforcement must happen in **merge order**, so that two parallel siblings both spending the same nullifier cannot each be accepted.

Zethora's enforcement is **five layers deep** (four in consensus, one in mempool):

1. **Within a payment.** A single Orchard bundle may not contain the same nullifier twice (`tx_validation_in_isolation.rs`, `check_private_payment`).

2. **Within a block.** `check_block_nullifier_reuse` rejects any block containing the same nullifier twice (`body_validation_in_isolation.rs`). Body-in-isolation rule.

3. **Mergeset merge order.** The virtual processor's merge loop walks the mergeset via `consensus_ordered_mergeset_without_selected_parent`. For each block, before the next block is validated, every nullifier in its accepted transactions is inserted into `ctx.nullifiers` and added to `ctx.private_state` as a spent-element. A later block in the same mergeset sees the earlier block's nullifiers as already-spent.

4. **Contextual check.** `private_double_spend(tx, selected_parent, pending)` returns true if any of the tx's nullifiers is in `pending` or has been spent on chain from `selected_parent` (`nullifier_spent_on_chain`). Invoked from `check_private_payment_in_context`.

5. **Mempool.** `nullifier_owner_id: HashMap<[u8; 32], TransactionId>` in the mempool's UTXO set tracks which waiting transaction reveals each nullifier. Two waiting payments may not spend the same private coin, just like two may not spend the same visible output (`mining/src/mempool/model/utxo_set.rs`).

Because layers 3 and 4 are ordered, the outcome is deterministic: given the same set of blocks, all nodes reject the same second spend and the virtual state converges. `VirtualState::mergeset_nullifiers: Vec<[u8; 32]>` exposes the nullifiers spent in the virtual's mergeset, in order, as the readable record of what layer 3 accepted.

**Test coverage.** Property test at `consensus/src/pipeline/tests/zethora_parallel_nullifier.rs` directly exercises `private_double_spend`: any tx whose nullifier appears in `pending` is rejected; a tx whose nullifiers are all absent from `pending` is accepted; an unrelated nullifier in `pending` does not trigger rejection. The full end-to-end parallel-sibling integration test is scaffolded and `#[ignore]`'d pending 601-block anchor-maturity setup.

### §6.4 — Private state fingerprint

The private state is committed into each block via two 32-byte fields in the coinbase payload:

- `note_root` — the current coin-list Merkle root (§6.1).
- `private_state` — a MuHash accumulator called the **private state fingerprint**.

The fingerprint accumulates two kinds of element, each tagged so the two kinds cannot collide:

- **Spent elements.** For each nullifier accepted by the mergeset loop, one element is added: `private_state_spent_element(nf) = [tag_spent] || nf` (33 bytes).
- **Anchor elements.** For each coin-list root produced in the mergeset, one element is added: `private_state_anchor_element(root, blue_score) = [tag_anchor] || root || blue_score` (41 bytes).

Both are added in merge order. MuHash is order-independent, so the fingerprint after a mergeset is deterministic given the set of spends and the set of anchors.

Purposes:

1. **State commitment.** Nodes with identical chains must produce identical `private_state` values. A mismatch indicates a consensus bug.
2. **Pruning-point download verification.** A node joining from a pruning point downloads the private state from a peer, and verifies it against the fingerprint sealed in the pruning-point block's coinbase (`check_downloaded_private_state`). A node with a manipulated state refuses to sync.

The per-chain-block fingerprint is stored in `DbZethoraPrivateStatesStore`, kept unfinalized so the next chain block can add to it.

---

## §7 — Supply accounting

The privacy layer is the only mechanism that can move value without a transparent on-chain record. The turnstile keeps that movement consistent with the 100M hard cap.

### §7.1 — Pool flows

Each block carries a ledger of where every zet is, in its coinbase payload. The pool state has five 8-byte fields:

| Offset | Field | Meaning |
|---|---|---|
| 16 | `pool_balance` | Fee-pool balance |
| 24 | `total_burned` | Total burned |
| 32 | `total_issued` | Total issued to date |
| 40 | `transparent_supply` | Visible supply |
| 48 | `shielded_balance` | Private-pool balance |

Invariant, enforced by `check_balanced`:

```
transparent_supply + pool_balance + total_burned + shielded_balance == total_issued
```

Per-block flows are captured in `BlockFlows`:

- `pool_in` — value moving into the private pool from this block's accepted transactions.
- `pool_out` — value moving out of the private pool.

`shielded_out` for a block is `sum(mergeset_rewards[*].pool_out)`, and `shielded_in` is `sum(mergeset_rewards[*].pool_in)`. These feed `ledger_step`.

### §7.2 — The turnstile and the supply ledger

Every block, the consensus computes four quantities from its accepted transactions and its mergeset:

- `issued` — new zets created by coinbases paid in this mergeset.
- `unpaid` — fees that no miner could be paid (burned).
- `coinbase_out` — total value of coinbase outputs.
- `visible_change` — net change in visible coins (equals minus the total fees when accounting is correct).

`ledger_step(parent_pool, after_pool, flows) -> Result<PoolState, SupplyError>` enforces:

- **Sequential.** Called **once per block**, taking the previous block's `PoolState` as input. Never parallel per transaction. Parallel application would double-count a spend.
- **Cap enforcement.** If `total_issued + issued > CAP_UNITS`, the block is rejected with `SupplyError::CapExceeded`. `CAP_UNITS` corresponds to the 100M ZTHR hard cap.
- **Balance.** `check_balanced(&PoolState)` verifies the invariant in §7.1 after each step.

The turnstile arithmetic itself is a pure function, unit-tested (`turnstile_is_sequential_and_rejects_second_debit`).

**Known open question:** the interaction between a mid-mergeset-rejected private transaction and the pool accounting is believed correct from code inspection (`block_pool_out` accumulates only from `validated_transactions`), but not covered by an integration test.

### §7.3 — The emergency switch

Private spends are gated behind a per-network flag (`private_spends_enabled`), set at the consensus-parameter level:

- **`spends_enabled = false` (level a).** Private sends are rejected at isolation time. Shielding still works (one-way INTO the pool). Testnet and mainnet run this setting until an external audit of the Orchard integration is complete.
- **`spends_enabled = true`.** Private sends are allowed. Isolation checks pass, and contextual rules (§6.2, §6.3) enforce correctness. Devnet and simnet run this setting.

Shielding works regardless of the switch, because adding coins to the pool is bounded in failure mode — the coin either enters correctly or the tx is rejected. Withdrawing requires the full spend machinery, whose failure mode includes money creation, so it is gated.

**TBD:** the code comment "level (a)" implies additional planned levels. Their semantics and gating rules are not specified.

### §7.4 — Pool versions

Each pool **version** has its own coin list, its own spent-coin-tag set, and its own public balance. A pool version can be retired and replaced if a bug is found. `zethora-shielded/src/lib.rs` defines the current versions the node understands. Wire-format encoding is version-aware.

---

## §8 — Network behavior

### §8.1 — Cheap precheck before proof check

A private payment requires an Orchard proof check whose cost scales with the bundle's action count. To keep a flood of replays or stale payments from costing proof checks, consensus runs `private_precheck` first: cheap checks against the virtual state (coin tags unspent, coin list snapshot matured). Only payments that pass the precheck proceed to the proof check, which runs in a dedicated worker pool (`mempool_check_pool`) so it never holds the virtual lock and never blocks block processing.

### §8.2 — TBD

Cited in code but no detail recovered from citations. Likely relates to proof-check batching or worker-pool sizing. `verify_payments_batch` exists in `zethora-shielded/src/lib.rs` and may be the intended reference.

### §8.3 — Peer banning on forged proofs

A private payment that fails its proof or its signatures is not merely rejected — the sending peer is banned (24 hours, per `ban_if_forged_private_payment`). Peers added with `--connect` / `--addpeer` are never banned.

Rationale: an honest peer cannot accidentally produce a forged Orchard proof. Format errors and chain-dependent refusals (coin already spent, snapshot too recent) are **not** banning events — an honest peer can produce those in a race, or after a future format upgrade.

The distinction is encoded in `TxRuleError::InvalidPrivatePaymentProof` (ban) vs. `TxRuleError::InvalidPrivatePayment` (reject only). Tx relay in `txrelay/flow.rs` groups private transactions so a lying peer's cost is bounded to one group before it is banned.

---

## §9 — Fully private payments

A fully private payment has no visible inputs and no visible outputs. The transaction's `inputs` and `outputs` vectors are empty; the entire transfer happens through the Orchard payload.

Rules:

- **Value balance.** For a fully private payment, `pool_flows(payload) = (0, fee)`: no value enters the pool, `fee` leaves it.
- **No visible coin required.** A shielded-only wallet can send without holding any transparent coins. Enforced in `tx_validation_in_isolation.rs` (`pays_from_private_pool` exempts the tx from `NoTxInputs`).
- **Fee = value leaving the pool.** The turnstile treats the value balance as `shielded_out`.
- **Isolation rules still apply.** §6.2 (mature anchor), §6.3 (unspent nullifiers), and §8.3 (forged proof → ban).
- **Fee bump.** A stuck fully-private tx is replaced by reusing the same coins with a higher fee (`zethora-shield/src/main.rs::bump`).

Test: `fully_private_payment_needs_no_visible_coin` in `tx_validation_in_isolation.rs`.

---

## Appendix A — Implementation reference

| Mechanism | File |
|---|---|
| Wire format | `zethora-shielded/src/codec.rs` |
| Note commitment tree | `consensus/src/model/stores/zethora_note_trees.rs` |
| Anchor store | `consensus/src/model/stores/zethora_anchors.rs` |
| Nullifier store | `consensus/src/model/stores/zethora_nullifiers.rs` |
| Private state fingerprints | `consensus/src/model/stores/zethora_private_states.rs` |
| Virtual state fields | `consensus/src/model/stores/virtual_state.rs` |
| Mergeset loop | `consensus/src/pipeline/virtual_processor/utxo_validation.rs` |
| Nullifier contextual check | `utxo_validation.rs::private_double_spend` |
| Intra-block nullifier check | `consensus/src/pipeline/body_processor/body_validation_in_isolation.rs::check_block_nullifier_reuse` |
| Spent-element encoding | `consensus/core/src/zethora_private.rs::private_state_spent_element` |
| Anchor-element encoding | `consensus/core/src/zethora_private.rs::private_state_anchor_element` |
| Payload parsing | `consensus/core/src/zethora_private.rs` |
| Isolation checks + ban distinction | `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs::check_private_payment` |
| Turnstile arithmetic | `consensus/src/processes/zethora_supply.rs::ledger_step`, `check_balanced` |
| Supply cap | `consensus/src/processes/zethora_supply.rs::CAP_UNITS` |
| Emergency switch | `consensus/src/processes/transaction_validator/mod.rs::private_spends_enabled` |
| Fingerprint commitments | `consensus/core/src/coinbase.rs::CoinbaseData` |
| Pruning-point verification | `consensus/src/processes/zethora_private_state.rs::check_downloaded_private_state` |
| Pruning-point download | `consensus/src/consensus/mod.rs::import_zethora_private_state` |
| P2P private state sync | `protocol/flows/src/v10/request_zethora_private_state.rs` |
| Mempool nullifier tracking | `mining/src/mempool/model/utxo_set.rs::nullifier_owner_id` |
| Peer ban | `protocol/flows/src/flow_context.rs::ban_if_forged_private_payment` |
| Recoverable missing state | `consensus/src/pipeline/virtual_processor/utxo_validation.rs::calculate_utxo_state` |

## Appendix B — Regression tests

| Test | Location | Covers |
|---|---|---|
| `turnstile_is_sequential_and_rejects_second_debit` | `zethora_supply.rs` | §7.2 |
| `spent_element_is_deterministic_and_distinct` | `zethora_supply.rs` | §6.4 |
| `nullifier_in_pending_set_is_rejected_by_private_double_spend` | `pipeline/tests/zethora_parallel_nullifier.rs` | §6.3 |
| `parallel_blocks_spending_same_nullifier_are_counted_once` (ignored) | `pipeline/tests/zethora_parallel_nullifier.rs` | §6.3 (needs 601-block setup) |
| `fully_private_payment_needs_no_visible_coin` | `tx_validation_in_isolation.rs` | §9 |
| `valid_shielding_payment_is_accepted_and_bound_to_its_transaction` | `tx_validation_in_isolation.rs` | §4 |
| `shielding_is_accepted_with_spends_on_or_off` | `tx_validation_in_isolation.rs` | §7.3 |

## Appendix C — Open questions for review

Specific questions an external reviewer should examine. These are the "here is where we are unsure" list.

1. **Parallel nullifier end-to-end.** Layers 3 and 4 of §6.3 are believed correct from code inspection. The end-to-end integration test requires 601 blocks of anchor-maturity setup and is not automated.
2. **Anchor reorg behavior.** `try_is_chain_ancestor_of` handles the producing-block case, but the reorg that disconnects a producing block is not tested.
3. **Emergency switch levels.** Only level (a) is implemented; (b)/(c) are implied but not defined.
4. **Payload wire format byte layout.** Implemented in `codec.rs`; the spec defers to code.
5. **Pruning-point download resumability.** Missing state returns a recoverable error and the node needs restart to retry. Auto-retry is deferred. A malicious peer could repeatedly interrupt download to deny service to a joining node.
6. **Fingerprint MuHash element collision.** Spent-element is 33 bytes (1-byte tag + 32 nullifier); anchor-element is 41 bytes (1-byte tag + 32 root + 8 blue score). Reviewer should verify these cannot collide.
7. **Turnstile mid-mergeset rejection interaction.** §7.2 open question.
8. **`ANCHOR_DEPTH` at 1 BPS vs. future higher rates.** Currently hardcoded 600; TODO in code to scale.
9. **§8.2.** Cited but not recovered from citations. Likely proof-check batching.

## Appendix D — Change log

| Version | Date | Changes |
|---|---|---|
| 0.1 | 2026-10-19 | Initial consolidation from code citations. Sections §4, §5, §6.1–§6.4, §7.1–§7.4, §8.1, §8.3, §9 specified. §8.2 and parts of §4 marked TBD. |
