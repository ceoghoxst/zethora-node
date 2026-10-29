> Raw output of the seam reviewer (max-effort chat), pack 4, reviewing f2-hardening commit 1cd9398. Kept as evidence.
> CTO verdicts in docs/F3-PLAN.md override this file. Its "Paste to VP" text was NOT sent; do not reuse it.

Pack 4 review: RandomZ ↔ Kaspa mining (f2-hardening, commit 1cd9398)

Same format as pack 3: what goes wrong, the test that proves it, and the fix.

1. What each function must guarantee

consensus/pow/src/lib.rs

State::new (38): the epoch comes from the header’s DAA score, and the input is the hash of the header without nonce and time. It must give exactly the value every node computes.
State::from_parts (50): only for callers that don’t check real headers (its epoch is fixed at 0).
epoch / target / pow_input (58–71): pass-through accessors.
calculate_pow (76): the RandomZ light value, read little-endian. It must be identical on every platform the node runs on.
check_pow (94): passes if the value is at most the target.
calc_block_level(_check_pow) (101, 106): the level comes from the PoW value. Genesis gets the maximum level.
precompute_pow (121): the same values as checking each header one by one, just cheaper.
calc_level_from_pow (133): upstream.

consensus/pow/src/randomz.rs

epoch_of / key_for_epoch (42, 48): a fixed, public key schedule. Miners can’t choose their key.
EpochClock::max_plausible_epoch (68): never below an honest header’s epoch.
light_cache / kept_light_cache (104, 122): at most 4 kept setups, each built once even under concurrency.
memo_get / memo_put (143, 150): an exact cache, never wrong. Its size is bounded.
pow_input (162): the 48-byte layout documented in the file header.
pow_value_light / light_hash (177, 189): deterministic, thread-safe.
precompute_light (206): results in input order, equal to calling light_hash on each, with memory bounded.
try_new_mining_dataset / new_mining_dataset / FastHasher (254–277): fast mode must equal light mode.

randomz/src/lib.rs + bindings.rs (vendored randomx-rs)

Cache, Dataset and VM creation: return an error, never an invalid handle.
calculate_hash: always the real hash, or an error. No undefined behavior.

zethora-miner/src/main.rs

load_or_create_key (37): the key is created safely and stored privately.
bench (51): reports light vs fast agreement.
main (136): mines with the template’s epoch and target, and submits only blocks that meet the target.
header_reward_hint (361): display only.

pre_ghostdag_validation.rs

validate_header_in_isolation (19): cheap rejections come before the expensive PoW check.
check_pow_epoch_plausible (118): never refuses a valid header, and limits the epochs an untrusted header can make the node build.
check_pow_and_calc_block_level (158): PoW against the claimed bits.

header_processor/processor.rs

validate_header (286): the order is isolation, then parents, then GHOSTDAG, then the DAA/bits checks.
validate_trusted_header (302): isolation and GHOSTDAG only.
worker, ghostdag, commit_header: upstream.

flow_context.rs / common.rs: the implausible-epoch ban needs 3 strikes in 10 minutes, and memory used for the counters stays bounded.

params.rs: every activation and parameter fits Zethora’s own chain history, with nothing carried over from Kaspa.

2. Findings
#P4-1. HIGH: invalid-PoW headers are cheap to send and costly to check

Where: pre_ghostdag_validation.rs:24–25 and 158–161; header processor.rs:287–291; flow_context.rs:444–476.

What goes wrong: checking one RandomX light-mode hash costs milliseconds. Kaspa’s kHeavyHash costs microseconds, and Kaspa’s ordering assumes that. Two consequences:

A header with a bad nonce costs a full light hash before it is rejected.
The claimed bits is only checked against the real difficulty after GHOSTDAG (pre_pow_validation, 291). A header that claims a very easy target passes the PoW check almost for free to produce, and the node then also spends GHOSTDAG work before rejecting it.

Neither error leads to a ban or a score, so the same peer can repeat this cheaply. Honest nodes validate before relaying, so a valid peer never sends an invalid-PoW block.

Test P4-T1: feed 1,000 headers with known parents: half with random nonces, half claiming the maximum target. Measure CPU used per rejected header and assert it stays under a budget, for example 1 ms, after the fix.

Fix:

Before PoW, reject any bits easier than a bound from the current difficulty. For example, at most 4× easier than the virtual state’s bits; both difficulty and DAA move slowly.
Score InvalidPoW and ZethoraPowEpochOutOfRange from non-whitelisted peers, banning after N strikes.
Rate-limit block requests sent in response to each peer’s inv messages.
#P4-2. HIGH: activation heights copied from Kaspa

Where: params.rs:637 (mainnet crescendo_activation: ForkActivation::new(110_165_000)) and 688 (testnet 88_657_000). Devnet and simnet use ForkActivation::always() (731, 774).

What goes wrong: these are Kaspa’s own activation DAA scores. At 1 BPS, Zethora mainnet would run pre-Crescendo rules for about 3.5 years, testnet for about 2.8 years. All your testing so far has been under Crescendo rules on devnet.

Which code still switches on this activation is UNVERIFIED. Candidates include hash_pre_crescendo (pack 1, tx.rs:27), payload rules for native transactions, mass commitment, and bps_history in the difficulty calculation. Any of them would make mainnet behave differently from what you tested.

The same block also carries Kaspa-only history: deflationary_phase_daa_score with the “network was down three days” comment (620–627), and the inherited subsidy parameters.

Test P4-T2: run the full devnet test suite with crescendo_activation set to mainnet’s value. Then grep for every reader of crescendo_activation and deflationary_phase_daa_score.

Fix:

Set ForkActivation::always() on every Zethora network.
Delete or zero the Kaspa-history parameters that Zethora’s own subsidy doesn’t use.
Add a test asserting that mainnet and testnet activations equal devnet’s.
#P4-3. MEDIUM: undefined behavior and a missing null check in the vendored randomx-rs

Where: randomz/src/lib.rs, RandomXVM::new (pack lines 370–381) and calculate_hash (416–435).

randomx_create_vm can return null, for example when JIT pages can’t be made executable or memory runs out. That is never checked. A null VM is stored and later used, which crashes the process instead of returning an error.
calculate_hash gets its output buffer from an immutable let arr and casts it to *mut. Writing through that pointer is undefined behavior in Rust. A future compiler could keep treating arr as all zeros, so every hash would come back as “empty”, and the expect at randomz.rs:198 would then panic on every block. Whether that happens depends on the compiler version, so different builds could behave differently.

Test P4-T3:

run cargo +nightly miri test on a mocked hash call, and enable the clippy lint invalid_reference_casting;
add a unit test where VM creation fails (force it with flags that can’t work) and assert an Err, not a crash.

Fix:

use let mut arr = [0u8; 32] and arr.as_mut_ptr();
return Err when vm.is_null();
keep the all-zero check only as an extra sanity check.
#P4-4. MEDIUM: RandomZ determinism across CPU architectures isn’t tested

Where: randomz.rs:307–355 (test vectors computed on one machine: interpreter, JIT and fast mode).

What goes wrong: RandomZ changes RandomX’s instruction frequencies and Argon2 salt (the C code isn’t in the pack, so UNVERIFIED). If either change behaves differently on the ARM64 JIT, or on any platform-specific code path, ARM nodes compute different hashes from x86 nodes, and the network splits along CPU type. You planned an Oracle A1 seed node, which is ARM.

Test P4-T4: a CI matrix covering x86_64 Linux, x86_64 Windows, aarch64 Linux and aarch64 macOS. Run the existing vectors plus Zethora epoch keys 0, 1 and 1000, in light, fast, JIT and interpreter modes, and assert identical bytes.

Fix: make that matrix a merge requirement.

#P4-5. MEDIUM: verifying a pruning proof computes PoW for every epoch before checking any of them

Where: randomz.rs:206–249, called from precompute_pow (pow lib.rs:121). The pruning-proof validator that calls it is UNVERIFIED.

What goes wrong: every header’s PoW is computed, building a temporary 256 MiB setup for each epoch and up to 4 in parallel, before any result is compared with its target. A proof whose epochs are all plausible but whose PoW is wrong costs about 1–2 s per epoch before it is rejected. After N years that is about 60N epochs, because the plausible range is doubled. Only implausible epochs count toward a ban (flow_context.rs:445). Peak memory is about 1 GiB for temporary setups on top of the 4 kept ones.

Test P4-T5: a proof with 120 plausible epochs where the first-checked header has a bad nonce. Assert rejection in under 5 s and peak RSS under a budget.

Fix:

Check the headers that decide the outcome first, one at a time (the pruning point header, then the highest-level headers), and stop at the first failure.
Only then precompute the rest.
Score invalid-PoW proofs the same way as implausible ones.
Size the worker count by available memory as well as CPU count.
#P4-6. LOW–MEDIUM: the wasm build silently uses a different PoW

Where: pow lib.rs:82–89. On wasm32, calculate_pow returns Kaspa’s kHeavyHash. Any WASM wallet, explorer or SDK that checks a header or computes a block level disagrees with consensus, without any error to show it.

Fix: on wasm32, have calculate_pow and check_pow return an “unsupported” error (or fail to compile), never a different algorithm.

#P4-7. LOW–MEDIUM: State::from_parts always uses epoch 0

Where: pow lib.rs:50–55. A caller that checks a real header through from_parts (RPC, mining code, the wasm SDK: UNVERIFIED which ones exist) gets the wrong key once the chain passes DAA 2²⁰ (about 12 days), so valid blocks fail and miners waste work.

Fix: make epoch a required argument, or make from_parts test-only.

#P4-8. LOW: epoch change and memory
randomz.rs:118: at every epoch boundary, all header-processing threads wait about 1–2 s on the new setup.
Fix: build the next epoch’s light setup in the background when the tip is within about 10k DAA of the boundary.
randomz.rs:92: if the 256 MiB allocation fails, expect panics and the node crashes, which is at least fail-stop.
Fix: document a minimum of 4 GB RAM for nodes (4 kept setups, temporary precompute setups, and thread-local VMs that still hold evicted setups).
randomz.rs:152–154: when the memo is full, everything in it is cleared. During a proof check, other threads’ inserts can wipe the batch the precompute just stored, which means slow rebuilds of old epochs that also push live setups out of the kept slots.
Fix: keep proof results in their own memo.
#P4-9. LOW: epoch range when pruning falls behind

Where: pre_ghostdag_validation.rs:136–145. The accepted range runs from the pruning point’s epoch to the tip’s. That is at most 4 epochs only while pruning keeps up (about 30 h against 12 days per epoch). If pruning lags by weeks, the range grows, and in-range headers from more than 4 epochs can keep evicting kept setups.

Fix: cap the range at KEPT_LIGHT_CACHES around the tip, or derive the low end from the tip instead of the pruning point.

#P4-10. LOW: miner

Where: zethora-miner/src/main.rs.

37–47: the key is written as plain hex with default file permissions (on Linux, readable by any user).
39: slicing hex.trim()[i..i+2] panics on a short or corrupted key file.
9–10, 138: testnet requires --enable-unsynced-mining, so the miner can build on a stale chain.

Fix:

create the key file with owner-only permissions;
parse with error messages instead of panicking;
for testnet and mainnet, refuse to mine while the node reports it isn’t synced.
#P4-11. LOW (ops): mainnet has no DNS seeders

Where: params.rs:590. dns_seeders: &[], so new mainnet nodes find no peers without --addpeer. List the seed nodes before launch.

3. Weakest line per file
File	Line	Why
consensus/pow/src/lib.rs	54	from_parts hard-codes epoch 0 (#P4-7)
consensus/pow/src/randomz.rs	231	builds a temporary setup per epoch before any PoW is compared (#P4-5)
randomz/src/lib.rs	422–425	writes through a pointer to an immutable buffer: undefined behavior on the consensus path (#P4-3)
randomz/src/bindings.rs	57	randomx_calculate_hash returns nothing, which forces the all-zero heuristic
zethora-miner/src/main.rs	39	unchecked slicing of the key file (#P4-10)
pre_ghostdag_validation.rs	160	PoW against a claimed bits that hasn’t been checked yet (#P4-1)
header_processor/processor.rs	287	the expensive isolation check runs before the cheap parent and relation checks
flow_context.rs	445	only implausible epochs are scored; invalid PoW never is (#P4-1, #P4-5)
p2p/common.rs	103	is_implausible_pow_epoch covers pruning import only
params.rs	637	Kaspa’s mainnet Crescendo height on Zethora mainnet (#P4-2)
4. UNVERIFIED: still need
every reader of crescendo_activation and deflationary_phase_daa_score (#P4-2)
the pruning-proof validator that calls precompute_pow, and its order of checks (#P4-5)
RandomZ C changes in randomz/RandomX (#P4-4)
callers of State::from_parts (#P4-7)
genesis bits for mainnet and testnet. At CPU hash rates, a badly chosen starting difficulty either floods the first blocks or stalls the chain until the difficulty window fills.
whether kaspad limits --override-params-file (including skip_proof_of_work) to devnet
carried over from earlier packs: resolve_virtual body, processor.rs 1520–1545, expected_coinbase_transaction (P2-1), the pruning batch commit (P3-5), async_clear_pruning_utxo_set (P3-2)

Paste to VP of Operations:

Claude (CTO): Pack 4 review (RandomZ ↔ mining) is done: 11 findings. Two matter for mainnet launch even with privacy off:

Mainnet and testnet still use Kaspa’s Crescendo activation heights, so mainnet would run older rules for years, unlike everything we tested on devnet. Set them to “always”.
RandomX verification is slow per hash. Headers need cheap difficulty checks before PoW, and repeated invalid PoW should count against a peer.

Also before launch:

fix the undefined behavior in the vendored RandomX wrapper;
add ARM and Windows hash test vectors to CI (the seed node may be ARM);
list mainnet DNS seeders.

Social/CMO: no claims of “launch-ready mining” until these are closed.

Say next for pack 5. Keep effort on high. For the top-10 summary after pack 5, medium is enough.