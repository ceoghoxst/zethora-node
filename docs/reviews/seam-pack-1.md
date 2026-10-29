> Raw output of the seam reviewer (max-effort chat), pack 1, reviewing f2-hardening commit 1cd9398. Kept as evidence.
> CTO verdicts in docs/F3-PLAN.md override this file. Its "Paste to VP" text was NOT sent; do not reuse it.

Pack 1 review: Orchard ↔ Kaspa transactions (f2-hardening, commit 1cd9398)

Scope note: private payments are off on testnet and mainnet, and they are refused before decode. So every finding below except #3 only becomes live when spends are switched on (devnet/simnet today, mainnet later). Several of them should block switching spends on.

1. What each function must guarantee

zethora-shielded/layout/src/lib.rs

action_offset(i) (61): returns the exact byte start of action i, or None on overflow, never a wrapped value.
trailer_offset(n) (69): returns the first byte after n actions. It must equal what codec::decode reaches after reading n actions.
encoded_size(n, p) (74): returns the exact total length that encode writes for n actions and a proof of p bytes.
const asserts (78–80): the layout can never silently drift from 820 / 3 / 45.

consensus/core/src/zethora_private.rs

private_payment_bytes (29): a payload is a private payment exactly when it starts with ZSHP.
action_count (34): reads the same u16 that decode reads, and never panics.
trailer_offset (40): uses the same offset as the codec for the declared n.
value_balance (46): returns the same i64 that decode puts into the bundle (the one the binding signature proves).
pool_flows (56): splits the balance into (in, out) with no loss at i64::MIN, and returns Err when it can’t be read.
pays_from_private_pool (65): true only if the declared balance is greater than 0. Isolation must later prove that declaration is real.
nullifiers (73): returns every action’s tag in action order, and never panics.
private_state_spent_element / private_state_anchor_element (88, 100): fixed-width, type-tagged MuHash members that can never collide.
spend_anchor (122): returns the anchor exactly when Orchard’s enableSpends bit is set (bit 0 matches Orchard).
proof_mass (134): returns a mass that covers the real cost of verifying the proof.

zethora-shielded/src/codec.rs

encoded_size (48): the canonical size for n actions.
encode (84): writes exactly the layout, and only for 1..=16 actions.
Reader::take/array/u8/pos (136–156): never reads past the end; returns Truncated instead.
point (160): maps an invalid point to an error, never a panic.
note_commitments (167): returns the same cmx list decode would. It may only be called on payloads that already passed decode.
decode (183): accepts exactly the canonical encodings. That means 1..=16 actions, valid points, known flags, canonical proof length, and no trailing bytes.

zethora-shielded/src/lib.rs

SupportedPool::from_byte / bundle_version (36, 43): only pool 1 exists, and it always maps to orchard_v2.
sighash (53): binds the payment to exactly one transaction and its own effects.
verify_payment (76): returns Ok only if every spend signature, the binding signature and the proof are valid. Must never panic on decoded input.
verify_payments_batch (93): returns the same verdict as calling verify_payment on each one (not used by consensus).
pool_flows (116): same split as the consensus-side pool_flows.
NoteCommitmentTree::append/root/size (143–155): an append-only frontier in GHOSTDAG accepted order.
ends_in_empty_leaf (161): detects trailing padding that leaves the root unchanged.
to_bytes / from_bytes (168, 186): exact round trip; malformed bytes are refused.

consensus/core/src/hashing/tx.rs

zethora_private_payment_digest (38): commits to every field of the transaction an attacker could change, except the payload and signature scripts. It must never be equal to any other hash of the same transaction.
hash, hash_pre_crescendo, id, id_v0 (20–63): upstream Kaspa, unchanged.

tx_validation_in_isolation.rs

validate_tx_in_isolation (18): context-free and deterministic, so the result is the same on every node and at every DAA score.
check_transaction_inputs_count (79): zero inputs is allowed only for a declared pool-out payment, and only with lock_time 0.
check_coinbase_in_isolation, outputs/inputs/scripts/duplicate checks (42–125): upstream Kaspa.
private_payment_verifying_key (133): built once without deadlocking rayon.
check_private_payment (149): spends off means refuse before decoding. Spends on means a canonical decode, no duplicate tag inside the payment, and a valid proof plus signatures bound to this transaction.
check_gas, check_transaction_version (182, 200): upstream.

tx_validation_in_utxo_context.rs

validate_populated_transaction_and_get_fee (37): fee = transparent in + pool out − transparent out − pool in, with no overflow and never negative.

consensus/core/src/mass/mod.rs

non-contextual mass (341–372): charges for proof cost too.
calc_contextual_masses (380) / calc_storage_mass (441): never divides by zero when there are no inputs.

body_validation_in_isolation.rs

validate_body_in_isolation (17): the checks run in an order where every raw-parser call comes after decode.
check_block_nullifier_reuse (138): no tag appears twice in one block.
the rest is upstream.

consensus/services.rs (130–146)

spends on for Devnet and Simnet only, and the same on every validator instance.

virtual_processor/processor.rs

mempool_check_threads (204): caps CPU used by mempool proof checks.
commit_utxo_state (542): atomically writes the coin list, anchors, tags and fingerprint for a chain block, without deadlocking.
calculate_and_commit_virtual_state (611): the virtual carries the correct note root, fingerprint and mergeset tags.
private_precheck (1287): cheap rejections before the proof, with a bounded number of lookups.
validate_mempool_transaction (1313) and ..._in_parallel (1343): mempool accepts exactly what consensus would accept next.
build_block_template (1457): the template never contains a tag conflict or a pool overdraw.
virtual_shielded_balance (1561): returns the pool balance after the virtual’s mergeset.
build_block_template_from_virtual_state (1585): coinbase seals the correct supply and private state.
process_genesis (1679): seeds the empty tree as the first anchor.
store_zethora_private_state (1719): the import is all-or-nothing, as seen by everything that reads it.

protocol/flows/src/flow_context.rs

ban_(ip_)if_forged_private_payment (421, 426): bans only peers that provably sent a forged proof.
ban_ip_if_implausible_pow_epoch (444): bounded memory.
unorphan_blocks (562): pins the blame on the original sender.

protocol/p2p/src/common.rs

is_forged_private_payment (90): true only for proof or signature failures, never for format or context errors.
2. Findings
#1. CRITICAL if the assumption fails: payload swap on shielding transactions

Where: consensus/core/src/hashing/tx.rs:35–36 (the assumption) and 38–46. The code that would prove it, sighash.rs payload_hash, is UNVERIFIED because it is not in the pack.

The private digest deliberately leaves out the payload. The whole binding therefore rests on the transparent signatures covering the payload, for every sighash type.

Attack (if they don’t):

Watch the mempool for a shielding transaction T from a victim.
Build your own output-only bundle that shields the same value to your own private address. Sign it over zethora_private_payment_digest(T). That digest is public, and it doesn’t change when the payload changes.
Put your bundle in as T’s payload and keep the victim’s signature scripts.
Relay it. It is valid and you receive the victim’s shielded funds.

Test T1: build a real P2PK shielding transaction and sign the input. Swap in a second valid bundle that pays a different address. Run full utxo-context validation with scripts on. It must fail with a script or signature error. Repeat for SIGHASH_ALL, NONE, SINGLE and each ANYONECANPAY variant.

Fix: if any variant passes, make payload_hash commit to the payload unconditionally whenever it starts with ZSHP, whatever the sighash type.

#2. HIGH: proof checks can be amplified for free (CPU DoS)

Where:

tx_validation_in_isolation.rs:177–179: the proof is checked before any UTXO, fee or script check.
processor.rs:1316–1317 and 1350–1357: mempool order is precheck → proof → context.

An Orchard proof’s public inputs are anchor, cv, nf, rk, cmx and flags. The sighash is not one of them. One proof can therefore be re-signed over any number of digests.

Attack:

Make one output-only proof (anyone can, no coins needed).
For k = 1..∞, change something the digest covers (for example an output value, or an input outpoint that doesn’t exist). Re-sign the spend and binding signatures, which takes milliseconds because you know the dummy keys.
Each variant is a new tx ID with a valid proof. Every receiving node spends a full proof verification on it, and only then finds missing inputs (orphan) or a bad script.
The owner of a single real note can do the same with fully private transactions by varying the output scripts. The precheck doesn’t check tags already in the mempool.

The mempool_check_threads cap (n/4) limits the damage, but honest private payments then queue behind the flood.

Test T2: build one bundle with create_proof, then call apply_signatures 100 times with different digests. Assert that all 100 pass check_private_payment. Then add a verifier call counter and submit the 100 to the mempool. Today the counter reads 100; after the fix it should read 1.

Fix:

(a) Cache proof results keyed by blake2b(proof ‖ instance). Instance means anchor, flags, and each action’s cv/nf/rk/cmx. Signatures are still checked per transaction, so the cache is sound.
(b) Move the cheap checks before the proof: input outpoints exist, fee ≥ min relay fee from mass, no tag conflict with the mempool, transparent scripts.
(c) Give each peer a budget of proof checks.
#3. HIGH (conditional): nested pruning-lock read can deadlock

Where: processor.rs:558. commit_utxo_state calls pruning_lock.blocking_read().

It is called from the chain-block loop (489–522). If that loop’s caller (resolve_virtual, UNVERIFIED, not in the pack) already holds a read guard, and SessionLock is writer-fair (upstream Kaspa’s lock is), you get a deadlock:

The virtual thread holds read #1.
The pruning thread asks for write and waits.
The virtual thread asks for read #2. It queues behind the writer, and nothing moves again.

Attack: none needed. It happens on its own the first time pruning lines up with block processing, which a short devnet run may never have reached. Once it happens the node halts.

Test T3:

Unit test: take r1 = read; a second thread blocks on write; after 100 ms try read #2 with a 2 s timeout. It must not hang.
Integration test: run simpa with a tiny pruning depth and private payments for 10k blocks.

Fix: delete the inner acquisition. Pass the caller’s guard in, or a &SessionReadGuard token. Keep the records lock.

#4. HIGH if missing (UNVERIFIED): template follow-up batches may skip tag_check

Where: processor.rs:1526–1532 are not in the pack. The first batch goes through tag_check (1504), but I can’t see whether the batches inside the while loop do.

Attack, if they don’t: an owner puts two payments that spend the same tag into the mempool, and a third invalid transaction forces a second selection round. The second spend gets into the template. The miner’s block then fails check_block_nullifier_reuse, and the miner loses the block. The same gap would allow a turnstile overdraw.

Test T4: use a selector whose first batch is [A (tag X), Z (invalid)] and whose second batch is [B (tag X)]. Assert that the template contains only one of A or B, and that the block passes validate_body_in_isolation.

Fix: run tag_check on every batch. Send me lines 1520–1545 so I can confirm.

#5. MEDIUM: proof mass has no per-proof base cost, and mempool disagrees with consensus

Where: zethora_private.rs:26 and 134–136; mass/mod.rs:367.

Base cost: mass is charged per action only. The fixed part of verifying a halo2 proof is free, so a 1-action payment buys the most verification per unit of mass. A 1-action payment is about 21k mass, which allows about 23 per block if the block limit is 500k (UNVERIFIED, params not in the pack). That has to be benchmarked against the “small share of a second” claim on a 6-core Ryzen-class machine.

Mempool vs consensus: a 16-action payment has about 293k compute mass. If the standard mempool limit is still Kaspa’s 100k (UNVERIFIED), anything above about 5 actions is valid in consensus but can never be relayed. Wallets would build payments that get stuck.

Test T5: a criterion benchmark of verify_payment for n = 1, 2, 4, 8, 16 on the reference PC. Assert that the worst-case time per block (block mass ÷ mass of each n, times the time for that n) fits the stated budget.

Fix:

Charge PROOF_MASS_BASE per payment plus a per-action amount, both taken from the benchmark.
Either lower MAX_ACTIONS_PER_TX to what fits the standard mass limit, or raise the standard limit for private payments.
#6. MEDIUM: digest domain and field coverage

Where: tx.rs:39 and 43.

Domain: the digest uses the same hasher domain as id_v0. If EXCLUDE_PAYLOAD writes an empty payload, then digest(T) = id_v0(T with no payload). That is not exploitable today, but nothing keeps the two domains apart.

Network: there is no network or genesis binding, so testnet and mainnet signatures over the same visible part would match.

Coverage: whether write_transaction covers Toccata-era fields (covenant on outputs, compute_commit, sequence) is UNVERIFIED. For a fully private transaction there are no transparent signatures, so any field the digest misses can be changed by anyone. Changing a missed covenant on an unshield output would change who can spend it.

Test T6: on fully_private_tx, mutate each field one at a time (version, lock_time, gas, subnetwork, each output’s value / spk version / spk / covenant, each input’s sequence / compute_commit). Every mutation must fail with InvalidPrivatePaymentProof.

Fix: use a dedicated hasher (ZethoraPrivateDigest), add the network ID or genesis hash, and write down an explicit list of covered fields.

#7. MEDIUM: expect in the consensus path

Where: zethora-shielded/src/lib.rs:77, bundle.commitment(TxVersion::V5).expect(..).

This runs on every relayed transaction. If any decoded bundle can make commitment return Err (the orchard crate’s internals are UNVERIFIED), a single relayed transaction panics the validator.

Test T7: fuzz decode followed by verify_payment with cargo-fuzz, and assert there is never a panic.

Fix: use map_err into a new VerifyError::Commitment, and treat it as a plain refusal, not a ban.

#8. MEDIUM: the private-state import is not atomic

Where: processor.rs:1727–1746. The import writes tags and anchors in 10k-item batches, each committed separately, and writes the tree and fingerprint last. There is no marker that an import is in progress.

If the node is killed partway through, it is left with “for good” records but no tree. Safety then depends on the staging consensus being deleted on restart (UNVERIFIED, not in the pack). Any path that calls this outside staging would leave stale “for good” anchors and tags behind.

Test T8: add a failpoint after the first batch, then restart. Assert that the Zethora stores are wiped, or ignored until a complete import finishes.

Fix: write an import_in_progress marker first and clear it in the final batch. At startup, if the marker is present, wipe the four Zethora stores.

#9. MEDIUM: banning can turn a version mismatch into a network partition

Where: common.rs:90–96 and flow_context.rs:426–434.

If any future change alters how the digest or encoding is computed (for example a Toccata field), nodes on the old version will see honest new-version transactions as “forged” and ban those peers’ IPs for 24 hours. A bug that should only reject transactions then splits the network. Separately, honest users behind a shared IP (NAT, VPN) get banned along with the attacker.

Test T9: two node versions with different digest rules. Assert there are no bans and only plain refusals.

Fix: ban only when the transaction version is at most the one this node knows. Use a score-based ban (for example 3 strikes) instead of a ban on the first offence.

#10. LOW: mempool batch turnstile is not cumulative

Where: processor.rs:1366 and 1383. Each transaction in a batch is compared against the same pool_left, so N transactions that each take the whole pool are all accepted. The template catches this (1494), but the mempool keeps the overdrawing transactions. This requires an inflation bug to matter at all.

Fix: keep a running pool_left and tag set across the batch.

#11. LOW: precheck work on networks with spends off

Where: processor.rs:1287–1311. On testnet and mainnet, garbage ZSHP transactions with 1..16 actions still take the virtual read lock and do store lookups before isolation refuses them.

Fix: if !private_spends_enabled, return Ok from the precheck straight away (isolation still refuses them).

#12. LOW: coinbase payload can collide with the magic prefix

A coinbase payload begins with the blue score in little-endian. When blue_score mod 2³² = 0x5048535A (about 42.7 years in at 1 BPS, then every 136 years), the payload starts with ZSHP.

check_private_payment (150) and check_block_nullifier_reuse (140, skip(1)) both guard against this. Whether the mergeset accept loop and the fee/turnstile code also skip the coinbase is UNVERIFIED (pack 2).

Fix: have the helpers take &Transaction and return None for a coinbase.

#13. LOW: nullifiers() silently drops unreadable actions

Where: zethora_private.rs:77–80. On a truncated payload it returns fewer tags than n. Every caller today runs after decode, so this is safe today. A future mempool conflict index built on unchecked payloads would miss conflicts.

Fix: return Option<Vec<_>> and give None when any action can’t be read.

#14. LOW: the kill switch is a static network type

Where: services.rs:143–146. Turning spends on for mainnet later will need an activation point by DAA score. A rule that changes with DAA score cannot stay in isolation (see the warning in isolation.rs:13–17). Plan where the check will move before you turn it on.

#15. LOW: wrong argument in an error (upstream bug)

Where: isolation.rs:73. TooManyOutputs is given max_tx_inputs instead of max_tx_outputs. It only affects the error message.

#16. LOW: attempts map can grow without bound

Where: flow_context.rs:456–460. The map is only trimmed once it passes 10k entries, and the trim keeps every entry still inside the window. An attacker cycling IPv6 addresses inside one /64 can keep adding live entries. The rest of the function is UNVERIFIED (cut at line 461).

Fix: a hard cap on entries, with LRU eviction.

3. Weakest line per file
File	Line	Why
layout/lib.rs	75	encoded_size uses unchecked math while the functions next to it are checked
zethora_private.rs	77–80	filter_map silently drops tags (#13)
codec.rs	90	n as u16 with only a debug_assert; release encode never checks 1..=16
shielded/lib.rs	77	expect on the consensus path (#7)
hashing/tx.rs	39	shared hasher domain, no network binding (#6)
tx_validation_in_isolation.rs	178	expensive proof before any cheap context check (#2)
tx_validation_in_utxo_context.rs	50	a second, separate parse of the value balance; safe only while the layout crate and codec agree
mass/mod.rs	367	per-action proof mass, no base cost (#5)
body_validation_in_isolation.rs	140	raw parser plus skip(1) coinbase assumption
services.rs	143	static switch based on network type (#14)
processor.rs	558	nested pruning-lock read (#3)
flow_context.rs	432	immediate 24 h IP ban (#9)
common.rs	93	any isolation proof error in any block counts as ban-worthy, with no check of the version
4. UNVERIFIED: code I need to close these
sighash.rs payload_hash and the sighash-type handling (#1)
write_transaction body (#6)
the caller of the chain loop at processor.rs:489, and how SessionLock behaves (#3)
processor.rs:1520–1545 (#4)
check_private_payment_in_context, check_private_payment_fits_pool, pool_state_of, zethora_supply::turnstile
mempool conflict and eviction by nullifier
standard mass limit and block mass limit
the default of TransactionValidator::new() for spends
staging-consensus deletion on startup (#8)

Packs 2, 3 and 5 may cover some of these. Anything they don’t cover, I’ll list again at the end.

Paste to VP of Operations:

Claude (CTO): Pack 1 review (Orchard ↔ transactions) is done: 16 findings. Mainnet launches with private payments off, and that is still safe. Before privacy is ever turned on, these must be closed:

Prove that transparent signatures cover the private payload (possible theft if they don’t).
Add a proof-result cache and run the cheap checks before the proof (DoS).
Fix a possible deadlock between block commit and pruning. This one matters even with privacy off.
Confirm that the template checks tags on every batch.

Social/CMO: do not claim the private pool is “reviewed” or “audited” yet. Say “community review in progress, privacy stays off until it is done.”

Say next when ready. Keep effort on high for pack 2.