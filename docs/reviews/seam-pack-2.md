> Raw output of the seam reviewer (max-effort chat), pack 2, reviewing f2-hardening commit 1cd9398. Kept as evidence.
> CTO verdicts in docs/F3-PLAN.md override this file. Its "Paste to VP" text was NOT sent; do not reuse it.

Pack 2 review: Orchard ↔ BlockDAG (f2-hardening, commit 1cd9398)

The processor.rs excerpts in this pack are the same as pack 1 (I diffed them), except lines 286–307 and 725–959. I don’t repeat the pack 1 findings here.

Pack 1 updates from this pack:

Pack 1 #12 (coinbase ZSHP prefix) is closed. Every Zethora reader in the acceptance path skips the coinbase: utxo_validation.rs:526 and 557 skip index 0, and 199–236 only read validated non-coinbase transactions.
check_private_payment_in_context, fits_pool, pool_state_of and turnstile are now verified. The template, mempool and consensus apply the same rules to them.
Pack 1 #3 (nested lock) is still UNVERIFIED. worker (299) calls resolve_virtual() without a guard, so whether a guard is held depends on code inside resolve_virtual, which isn’t in either pack.
Pack 1 #4 (lines 1526–1532) is still not provided.
1. What each function must guarantee

utxo_validation.rs

UtxoProcessingContext::new (107): starts empty. Every Zethora field is overwritten by calculate_utxo_state before anything reads it.
calculate_utxo_state (133): every node, for the same block, ends with the same accepted set, UTXO diff, note tree, tag list, fingerprint, pool balance and rewards, whatever order it was processed in.
verify_expected_utxo_state (277): a chain block qualifies only if its commitments, coinbase, pruning point and first parent are right, and every one of its own transactions would be accepted by its child.
verify_header_pruning_point (370): upstream.
verify_coinbase_transaction (382): the coinbase equals the expected one exactly, ledger included.
visible_change_of (419): the net visible coin change of the mergeset, excluding the selected parent’s coinbase.
nullifier_spent_on_chain (431): true exactly when the tag was accepted by a block on the selected chain of selected_parent, that block included.
private_double_spend (440): the same check, plus the pending set.
anchor_matured_on_chain (452): true exactly when a producer is on the chain and at least anchor_depth blue score deep.
check_private_payment_in_context (469): the tag and anchor rules, identical in mempool, template and consensus.
check_private_payment_fits_pool (493): mempool-only pre-filter, never stricter than consensus.
pool_state_of (505): returns the ledger the selected parent sealed.
validate_transactions_in_parallel (512): returns the valid transactions with their block index. Order doesn’t matter here.
validate_transactions_with_muhash_in_parallel (541): the tag filter, then validation, then the turnstile in block order. Only accepted transactions affect anything.
validate_transaction_in_utxo_context (581): private context checks (cheap) before UTXO population, then fee.
populate_* and validate_mempool_transaction_in_utxo_context (625, 650): upstream, plus the mass setter.
collect_mergeset_seq_data, resolve_lane_updates, build_seq_commit, recompute_seq_commit (696–883): upstream KIP-21. They see exactly the accepted transactions.
missing_private_state_message (890): a fixed message for a corrupt DB.

zethora_nullifiers.rs

accepting_blocks (38): every chain block that accepted the tag.
add_batch (47): adds a block exactly once and writes the reverse index.
add_spent_for_good_batch (64): idempotent.
iter_all (74): reads raw DB rows.
prune_block_batch (85): after pruning, the spent/unspent answer is unchanged for every chain at or above the new pruning point.

zethora_anchors.rs

producing_blocks, add_batch, add_for_good_batch, prune_block_batch, iter_all (45–106): the same guarantees as the tag store, plus the blue score is kept exactly.

zethora_note_trees.rs / zethora_private_states.rs

set_batch, get, delete_batch: exact round trip for each block.

zethora_supply.rs

turnstile (64): balance + in − out, never negative and never wrapping.
turnstile_accepts (77): applies only if the transaction fits, otherwise leaves the balance untouched.
ledger_step (114): next ledger = parent + flows. The cap holds, visible supply is at least 0, and the ledger balances.
check_balanced (129): visible + fee pool + burned + private pool = issued, computed in u128.

processor.rs (new lines)

worker (286): one resolve_virtual call per batch of messages.
genesis seq-commit (725–775), inactivity_shortcut_block_for_pov (914), get_parent_lanes_root_and_count (943), expire_stale_lanes (953): upstream KIP-21 code with no private-pool interaction.

virtual_state.rs

VirtualState::new / from_genesis (58, 94): the private fields match what the coinbase of a block built on this virtual state must seal.
From<PreToccataVirtualState> (156): an upgrade must never produce private fields that disagree with the chain.
LkgVirtualState (184–215): lock-free snapshot, upstream.
2. Findings
#P2-1. HIGH (cross-pack, UNVERIFIED in pack 5): pool flows of red and non-DAA merged blocks

Where: utxo_validation.rs:198–207 and 253–257.

Pool flows are recorded for every merged block in mergeset_rewards. The running balance (ctx.shielded_balance) also counts every accepted transaction, whatever color its block is. But expected_coinbase_transaction (pack 5) builds the sealed ledger. If it sums shielded_in/shielded_out only over paid blue blocks, it skips reds and mergeset_non_daa. The unshielded zets would then show up in visible_change while missing from shielded_out.

The result would be Unbalanced. Every honest chain block that merges a red or non-DAA block containing a private payment is rejected, and the chain stops.

Attack: none needed. A private payment that lands in a red block is enough, and that happens naturally at 1 BPS.

Test P2-T1: a simpa/devnet DAG where block R (red) contains an unshield, and a second case where the unshielding block is non-DAA. Assert that the merging chain block is UTXO-valid, the ledger balances, and the sealed shielded_balance equals ctx.shielded_balance.

Fix: sum pool flows over all mergeset_rewards entries, separately from reward eligibility. Also add debug_assert_eq!(sealed.shielded_balance, ctx.shielded_balance) in verify_expected_utxo_state.

#P2-2. MEDIUM: a full coin list halts the whole network

Where: utxo_validation.rs:233, ctx.note_tree.append(..).expect("private coin list is full ..").

Every node panics on the same block, and only a hard fork recovers.

Attack: fill 2³² leaves with cheap zero-value output-only actions. At roughly 18k mass per action and about 500k block mass (UNVERIFIED), that is about 27 leaves per block, or around 5 years of saturated blocks at 1 BPS. That’s slow, but the outcome is a guaranteed chain halt on a known date.

Test P2-T2: use a tree that is 2 leaves from full (Frontier::from_parts at position 2³²−3), then accept a 2-output payment followed by a 1-output payment. Assert there is no panic, the first payment is accepted and the second is not.

Fix: make this an acceptance rule. A transaction whose outputs don’t fit is not accepted (checked during the turnstile pass, in block order). Also put the planned pool-migration path in the spec.

#P2-3. MEDIUM (cross-pack, pack 3): reachability defaults that differ, and when records are rewritten at pruning

Where: utxo_validation.rs:434 (unwrap_or(true), missing reachability counts as spent) and 462 (unwrap_or(false), missing reachability means the anchor doesn’t count).

This is safe only if the pruning processor deletes reachability data and rewrites the records (prune_block_batch) in the same WriteBatch, under the pruning write lock. If there is any gap, a node mid-pruning gives a different answer from a node that has finished pruning or has just synced:

a dead-chain tag reads as “spent”, freezing an honest coin;
an on-chain anchor reads as “unknown”, rejecting honest spends.

That is a chain split triggered by timing.

Test P2-T3: inject a crash or failpoint between reachability deletion and the record rewrite. Compare nullifier_spent_on_chain and anchor_matured_on_chain answers against a node that pruned without the crash.

Fix: enforce that single batch (verify in pack 3). Make the fallbacks log at error level and refuse to accept the transaction, rather than silently returning a spent/unspent answer.

#P2-4. MEDIUM (cross-pack, pack 3): iter_all returns every record, not the pruning point’s set

Where: zethora_nullifiers.rs:74, zethora_anchors.rs:99.

These return all records. That includes tags and anchors from blocks above the pruning point and from dead chains. If the code that serves the private state to syncing peers uses them unfiltered, the downloaded set won’t match the pruning point’s fingerprint, and honest syncs fail. If it filters with a rule different from the fingerprint’s (“FOR_GOOD, or chain ancestor of the pruning point, inclusive”), that also fails or is inconsistent.

Test P2-T4: build a chain with spends both above and below the pruning point, plus a reorged-out spend. Serve the private state at the pruning point and assert that its MuHash equals the fingerprint sealed in the pruning point’s coinbase.

Fix: a single shared filter function, used both by the server and by the fingerprint builder.

#P2-5. LOW: the pre-Toccata upgrade path resets private state to genesis

Where: virtual_state.rs:168–170. Converting an old row sets note_root, private_state and mergeset_nullifiers to their genesis values. Separately, #[derive(Default)] (27) gives note_root = [0; 32], which is not even the empty-tree root.

If that path ever runs on a chain that has private activity, then until the next resolve_virtual:

templates seal the wrong root, so blocks mined in that window are invalid;
mempool and template lose the pending tags.

Separately, adding Zethora fields without bumping POST_TOCCATA_VIRTUAL_STATE_VERSION (25) means an older Zethora version-1 row fails to deserialize.

Fix: bump the version. On a conversion, force the virtual state to be recomputed before any template is served.

#P2-6. LOW: unchecked u64 sums in the accept loop

Where: utxo_validation.rs:201 and 206–207.

block_fee and block_pool_in/out use += on u64. Overflow panics in debug builds and wraps in release builds, so a debug node and a release node would reach different verdicts. Real supply bounds keep this unreachable today.

Fix: use checked_add, and treat overflow as “transaction not accepted”, or use u128 as the ledger does.

#P2-7. LOW: the anchor-depth reference point differs from the spec

Where: utxo_validation.rs:458–460.

Depth is measured from selected_parent’s blue score, but the spec text (zethora_private.rs:108) says “the block that accepts it”. Mempool, template and consensus all use the selected parent, so behavior is consistent. But a future “fix” to just one side would split the chain.

Fix: change the spec wording to “selected parent of the accepting chain block” and add a boundary test for 599, 600 and 601.

#P2-8. LOW: verify that the reachability check is inclusive

Where: utxo_validation.rs:434.

The tags accepted by the selected parent’s own mergeset count as spent only if try_is_chain_ancestor_of(sp, sp) is true. Upstream Kaspa documents that a block is its own ancestor, but the implementation isn’t in the pack (UNVERIFIED). If it were exclusive, a tag could be spent twice, one chain block apart.

Test P2-T5: chain block A accepts tag N. In A’s child B, a merged blue block contains another transaction spending N. Assert it is not accepted. Run the same check through the mempool with the sink equal to A.

#P2-9. LOW: the ledger rechecks the turnstile only in aggregate

Where: zethora_supply.rs:122. ledger_step checks the turnstile on the totals for the block, which can’t detect a balance that went negative partway through. It is correct only because the accept loop already enforces it per transaction.

Fix: keep this as is, but add a test where totals that look fine hide a negative balance partway through, and assert that the accept loop rejects it.

#P2-10. LOW: the anchor store keeps the first FOR_GOOD blue score

Where: zethora_anchors.rs:67 and 88.

If a FOR_GOOD entry already exists, any later blue score for the same root is ignored. Roots are unique on one chain only while the “no empty leaf” invariant holds (pack 1, lib.rs:161). If that invariant ever broke, a node that pruned and a node that synced could store different ages.

Fix: keep the minimum blue score (the most conservative), or assert that the two are equal.

3. Weakest line per file
File	Line	Why
utxo_validation.rs	233	expect on a full tree halts the whole network (#P2-2)
zethora_nullifiers.rs	52	read-modify-write inside a batch; correct only because callers hold the records lock and the cache is updated before the write
zethora_anchors.rs	67	keeps the first FOR_GOOD blue score silently (#P2-10)
zethora_note_trees.rs	43	expect on corrupt bytes gives a bare panic, not the plain-English reset message
zethora_private_states.rs	39	wrong expect message (“finalized”); the stored state is deliberately unfinalized, so the message misleads during an incident
zethora_supply.rs	122	turnstile only on totals (#P2-9)
processor.rs (new lines)	299	resolve_virtual() is where pack 1 #3’s lock question hides, and it isn’t shown
virtual_state.rs	168	conversion silently sets the private state to genesis (#P2-5)
4. UNVERIFIED: still need
pack 5: expected_coinbase_transaction, i.e. how pool flows are summed over reds and non-DAA blocks (#P2-1)
pack 3: the pruning processor’s batch and lock covering reachability deletion plus prune_block_batch (#P2-3), and the private-state server and its filter (#P2-4)
reachability try_is_chain_ancestor_of: is it inclusive (#P2-8)?
resolve_virtual body (pack 1 #3) and processor.rs:1520–1545 (pack 1 #4)

Paste to VP of Operations:

Claude (CTO): Pack 2 review (private pool ↔ BlockDAG) is done. Reorg and parallel-block handling for nullifiers, anchors and the turnstile looks consistent across mempool, template and consensus. 10 findings. Most important:

Confirm the coinbase counts private-pool flows from red and non-DAA blocks. If it doesn’t, the chain halts the first time a private payment lands in a red block.
The note tree filling up (about 5 years out) panics every node. Make it a transaction-acceptance rule instead.
Pruning must update reachability and nullifier/anchor records in one atomic step.

Still off on mainnet, no change to messaging.

Say next for pack 3. Keep effort on high.