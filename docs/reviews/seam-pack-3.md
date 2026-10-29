> Raw output of the seam reviewer (max-effort chat), pack 3, reviewing f2-hardening commit 1cd9398. Kept as evidence.
> CTO verdicts in docs/F3-PLAN.md override this file. Its "Paste to VP" text was NOT sent; do not reuse it.

Pack 3 review: Orchard ↔ pruning and sync (f2-hardening, commit 1cd9398)

From here on, for each issue I describe what goes wrong, the test that proves it, and the fix. I’m leaving out step-by-step attack instructions; the tests cover the same ground. The virtual-processor excerpts in this pack match pack 2 (I diffed them), so I don’t review them again.

Updates to earlier packs:

P2-4 closed. private_state_as_of (zethora_private_state.rs:55) uses the same rule as the fingerprint: FOR_GOOD, or a chain ancestor of the pruning point, counting the pruning point itself. Serving and checking now agree.
P2-3 mostly closed. The pruning processor rewrites tag and anchor records in the same WriteBatch, before that block’s reachability is deleted (processor.rs:479–494). It is still UNVERIFIED that the reachability deletion is committed in that same batch, because lines after 530 aren’t in the pack.
Pack 1 #8 raised to HIGH. See #P3-2 below: the import can run on a live database, not only on a staging copy.
1. What each function must guarantee

consensus/src/processes/zethora_private_state.rs

genesis_private_state (23): equals what process_genesis seals: only the empty-root anchor, at blue score 0.
private_state_of (31): the set hash of exactly the given tags and anchors, independent of order.
private_state_as_of (55): exactly the tags and anchors on the pruning point’s chain, pruning point included. Any reachability error is returned as an error, never guessed.
check_downloaded_private_state (97): accepts only a state whose tree root, tree size, sets and fingerprint all match what the pruning point sealed.

protocol/flows/src/v10/request_zethora_private_state.rs

start_impl / handle_request (45, 52): serves one consistent snapshot for the current pruning point, or UnexpectedPruningPoint. Must not let peers exhaust node resources.

consensus/src/consensus/mod.rs

acquire_session (385): blocks pruning while the session is held.
zethora_private_state_at (409): the private state as of block, computed from the store records.
get_zethora_private_state (1175): the pruning point is unchanged before and after the read.
import_zethora_private_state (1190): check first, then store. Must leave no partial or stale state behind.
append_imported_pruning_point_utxos, import_pruning_point_utxo_set, import_pruning_point_smt (1156–1249): upstream.

pruning_processor/processor.rs (455–530)

After pruning a block, every spent/unspent and anchor-valid answer is unchanged for all future chains. Each block’s rewrite is atomic.

protocol/flows/src/ibd/flow.rs

start (57): a ban fires only for forged proofs.
sync_new_utxo_set (790): the private state is imported before the UTXO set, and any old state is cleared first.
sync_zethora_private_state (872): download, then consensus check, then store.
sync_pruning_point_utxoset (886): upstream.

protocol/flows/src/ibd/streams.rs

receive_zethora_private_state (389): checks the shape of each chunk. Memory used must be bounded no matter what the peer announces.

v10/mod.rs (39–131): the request flow is registered with exactly the message types it handles.

consensus/core/src/api/mod.rs (72–82, 340–350): the shape of ZethoraPrivateState and the ordering contract (private state imported before UTXO set).

2. Findings
#P3-1. HIGH: serving the private state is expensive and unthrottled

Where: request_zethora_private_state.rs:55–63 and consensus/mod.rs:409–421.

What goes wrong: every request rebuilds the whole private state from scratch. It scans every tag and anchor record ever stored (a list that grows forever), runs a reachability query for each one, and builds everything in memory. All of this happens while holding a consensus session. There is no cache, no per-peer limit, and no check that the requesting peer is actually syncing.

The pruning lock is writer-fair, so if the pruning thread is waiting for its write lock while the session is held, other readers queue behind it, and block processing can stall. Repeated requests from peers multiply this cost.

Test P3-T1: fill the stores with 1M tags and 100k anchors. Time 20 concurrent requests. Assert that block processing latency stays within budget and that pruning still makes progress.

Fix:

Compute the state once per pruning point and cache it, along with its fingerprint. Invalidate the cache when the pruning point moves.
Serve only from the cached copy, without holding a session.
Allow each peer one request per pruning point.
Only serve peers that are in IBD with us.
#P3-2. HIGH: an import can leave stale “for good” records in the live database

Where: ibd/flow.rs:792–794, consensus/mod.rs:1218, processor.rs:1727–1746 (pack 1).

What goes wrong:

sync_new_utxo_set clears the old UTXO set. Whether async_clear_pruning_utxo_set also clears the four Zethora stores is UNVERIFIED; it looks like upstream Kaspa code, which doesn’t know about them.
On the catch-up path (IbdType::Sync with is_utxo_stable = false), this can run on the live consensus, not only on a staging copy that gets deleted on failure.

So if an import is interrupted, retried against a different pruning point, or retried with a different peer after a partial store, FOR_GOOD tags and anchors from the earlier attempt stay behind. They are never checked against the new fingerprint.

This node would then disagree with the network about which coins are spent and which anchors are valid. Honest spends could be refused, and spends that the rest of the network refuses could be accepted. That is a consensus split for that node.

Test P3-T2:

Import the private state for pruning point A.
Make the UTXO import fail.
Re-run IBD so it imports pruning point B from a different chain.
Assert that the stores hold exactly B’s state: iterate iter_all and compare the MuHash to B’s fingerprint.

Fix:

Clear all four Zethora stores in the same step that clears the UTXO set.
Write an import_in_progress marker before any store write and clear it in the final batch.
At startup, if the marker is present, wipe the Zethora stores and mark the UTXO set unstable, so IBD runs again.
#P3-3. MEDIUM: the downloaded state has no size limit

Where: streams.rs:411–415 and 422–460.

What goes wrong: the announced counts are accepted up to u64. Memory grows as data arrives, which is good, but the only limit on total size is the announced count itself. The fingerprint is checked only after everything has downloaded (consensus/mod.rs:1216). A peer that sends a huge but well-formed state can use up the joining node’s memory before the check ever runs.

Test P3-T3: a mock peer announces 10⁹ tags and streams valid-shaped chunks. Assert that the joiner aborts at a set limit, with memory below a threshold.

Fix:

Cap the counts at what is physically possible. Blue score of the pruning point × max actions per block, with a safety margin, gives a limit on tags. The number of chain blocks below the pruning point gives a limit on anchors.
Better: add items to a running MuHash and write them to a temporary store as they arrive, instead of holding them all in memory. Then memory stays flat whatever the size.
#P3-4. MEDIUM: a bad private state costs the sender nothing

Where: ibd/flow.rs:57–63 and consensus/mod.rs:1196.

What goes wrong: ZethoraPrivateStateMismatch fails the IBD, but nothing bans or scores the peer. is_forged_private_payment only matches proof errors. The joiner may pick the same peer again and repeat a full download each time.

Honest nodes compute this state deterministically. A mismatch therefore means the peer is either malicious or has a bug, and in both cases the peer shouldn’t be retried.

Test P3-T4: a peer serves a state with one extra tag. Assert that the joiner disconnects from it and won’t choose it again for IBD during a cooldown period.

Fix: treat the mismatch as a score-based strike (consistent with pack 1 #9), with a cooldown on choosing that peer for IBD.

#P3-5. LOW (UNVERIFIED): reachability deletion should be in the same batch

Where: pruning processor 479–530. The record rewrite is clearly in batch. The commit of staging_reachability and the db.write(batch) come after line 530, which isn’t in the pack.

If reachability were written in a separate batch, the pack 2 split (#P2-3) would come back.

Also, line 483 .unwrap() panics if reachability is already gone for current. That is fine only if it truly can’t happen.

Test P3-T5: with a failpoint between the record rewrite and the reachability commit, assert they are always both present or both absent.

Fix: confirm they share one batch. Replace the unwrap with a clear error that names the block.

#P3-6. LOW: a pruning yield between blocks is visible to readers

Where: processor.rs:457–468. Pruning releases its lock every 5 ms, between blocks. Each block is atomic, so the spent/unspent answers stay correct. But any reader that iterates all records without a session would see a mix of pruned and unpruned records. zethora_private_state_at holds a session, so it is safe.

Fix: document that every iter_all caller must hold a session, and add a debug_assert that checks it.

#P3-7. LOW: the note tree bytes are parsed without a length check

Where: streams.rs:474 and zethora_private_state.rs:102. header.note_tree is passed straight through to from_bytes. That function does validate the bytes, but a valid frontier is at most 42 + 32×32 = 1,066 bytes, and anything longer should be refused when the header arrives, before anything else is downloaded.

Fix: reject note_tree.len() > 1066 immediately.

#P3-8. LOW: ZethoraPrivateState derives Default

Where: api/mod.rs:74. A default (empty) state could be passed by mistake somewhere. It would fail the fingerprint check, so this is not dangerous, but nothing needs Default.

Fix: remove the derive.

3. Weakest line per file
File	Line	Why
zethora_private_state.rs	79	“first match” depends on the invariant that a root has at most one producer per chain
request_zethora_private_state.rs	56	full rebuild on every request, while holding a session (#P3-1)
consensus/mod.rs	1218	the store after the check is multi-batch and doesn’t clear old state (#P3-2)
pruning_processor/processor.rs	483	unwrap() on reachability; correctness depends on the rest of the batch, which isn’t shown (#P3-5)
ibd/flow.rs	792	clears the UTXO set but (UNVERIFIED) not the Zethora stores (#P3-2)
ibd/streams.rs	411	the announced count is the only limit on size (#P3-3)
v10/mod.rs	124	private-state flow registered for every peer, no rate limit (#P3-1)
api/mod.rs	74	needless Default on a consensus-critical type (#P3-8)
4. UNVERIFIED: still need
pruning processor lines after 530: reachability commit and db.write (#P3-5)
async_clear_pruning_utxo_set, and which IbdType paths call sync_new_utxo_set on the live consensus versus a staging copy (#P3-2)
carried over: resolve_virtual body (pack 1 #3), processor.rs 1520–1545 (pack 1 #4), expected_coinbase_transaction (P2-1, probably in pack 5), reachability inclusiveness (P2-8)

Paste to VP of Operations:

Claude (CTO): Pack 3 review (private pool ↔ pruning and sync) is done. The fingerprint check that joining nodes run is sound: it catches hidden, invented, duplicated or re-dated records and padded coin lists. Two high items before privacy is turned on:

Serving the private state rebuilds it from scratch on every request with no limit, so it needs a cache and rate limits.
A failed or retried sync can leave old private-state records behind on a live node, so the Zethora stores must be cleared with the UTXO set and an import marker added.

No change to messaging. Privacy stays off.

Say next for pack 4. Keep effort on high.