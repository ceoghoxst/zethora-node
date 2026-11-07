//! Adversarial (black-hat) integration tests against the Zethora difficulty / DAA / timestamp validation, at the
//! CONSENSUS layer: they drive the real `SampledDifficultyManager` a node runs, with real block windows and a header
//! store, so they fail if the node's retarget rules -- not the test's arithmetic -- are what is wrong.
//!
//! Run: `cargo test -p kaspa-consensus --test zethora_difficulty_blackhat -- --nocapture`
//!
//! The invariants under attack:
//!   I-D1  A window shorter than `min_difficulty_window_size` freezes the difficulty at the selected parent's bits
//!         (never easier than genesis).
//!   I-D2  `measured_duration = max(max_ts - min_ts, 1)`: an all-equal-timestamp window cannot drive the target to 0.
//!   I-D3  The retargeted target is clamped to `max_difficulty_target` -- the only ceiling on how EASY it may go.
//!   I-D4  `daa_score = sp_daa_score + (mergeset_size - |mergeset_non_daa|)`, and it must match exactly
//!         (`UnexpectedHeaderDaaScore`), so the DAA/difficulty window cannot be walked forward on a forged score.
//!   I-D5  Only an upper bound on timestamps exists (`TimeTooFarIntoTheFuture`); there is NO lower bound, so an
//!         attacker who drags the window's `min_ts` backwards inflates `measured_duration` and lowers the difficulty
//!         chain-wide.
use kaspa_consensus::{
    model::stores::{
        block_window_cache::BlockWindowHeap,
        ghostdag::{GhostdagData, GhostdagStore, MemoryGhostdagStore},
        headers::{CompactHeaderData, HeaderStoreReader, HeaderWithBlockLevel},
    },
    processes::{
        difficulty::SampledDifficultyManager,
        ghostdag::ordering::SortableBlock,
    },
};
use kaspa_consensus_core::{header::Header, BlockHashSet, BlueWorkType};
use kaspa_database::prelude::StoreResult;
use kaspa_hashes::Hash;
use kaspa_math::Uint256;
use std::{cell::RefCell, cmp::Reverse, collections::HashMap, sync::Arc};

/// The genesis target, which is also `max_difficulty_target`: the EASIEST target any retarget may ever produce.
const GENESIS_BITS: u32 = 0x1F00_FFFF;
/// A target 2^32 times harder than genesis -- what a chain looks like after a few honest retargets.
const HARDER_BITS: u32 = 0x1B00_FFFF;
/// An attacker's dream target, 256x easier than genesis. No retarget may ever hand this out.
const DREAM_BITS: u32 = 0x2000_FFFF;

/// A window of `WINDOW_SIZE` blocks, each expected `TARGET_TIME_PER_BLOCK` ms apart.
const WINDOW_SIZE: usize = 8;
/// Below this many blocks the difficulty is frozen at the selected parent's bits (I-D1).
const MIN_WINDOW_SIZE: usize = 4;
const SAMPLE_RATE: u64 = 1;
const TARGET_TIME_PER_BLOCK: u64 = 1_000;
/// `target_time_per_block * sample_rate * (window_size - 1)` for an on-schedule window: 7_000 ms.
const EXPECTED_WINDOW_DURATION: u64 = TARGET_TIME_PER_BLOCK * SAMPLE_RATE * (WINDOW_SIZE as u64 - 1);
/// A neutral wall clock for fabricated blocks (only differences matter to the difficulty manager).
const BASE_TS: u64 = 1_000_000_000_000;

fn genesis_hash() -> Hash {
    Hash::from_u64_word(0x6E)
}

fn target(bits: u32) -> Uint256 {
    Uint256::from_compact_target_bits(bits)
}

/// A header store holding only the compact data the difficulty manager reads. Any other read is a bug in the code
/// under test, not in this mock.
#[derive(Default)]
struct MockHeadersStore {
    compact: RefCell<HashMap<Hash, CompactHeaderData>>,
}

impl MockHeadersStore {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&self, hash: Hash, timestamp: u64, bits: u32, daa_score: u64) {
        self.compact.borrow_mut().insert(hash, CompactHeaderData { daa_score, timestamp, bits, blue_score: 0 });
    }

    fn get(&self, hash: Hash) -> CompactHeaderData {
        *self.compact.borrow().get(&hash).unwrap_or_else(|| panic!("mock header store: unknown header {hash:?}"))
    }
}

impl HeaderStoreReader for MockHeadersStore {
    fn get_daa_score(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.get(hash).daa_score)
    }

    fn get_blue_score(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.get(hash).blue_score)
    }

    fn get_timestamp(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.get(hash).timestamp)
    }

    fn get_bits(&self, hash: Hash) -> StoreResult<u32> {
        Ok(self.get(hash).bits)
    }

    fn get_header(&self, _hash: Hash) -> StoreResult<Arc<Header>> {
        unimplemented!("the difficulty manager never reads full headers")
    }

    fn get_header_with_block_level(&self, _hash: Hash) -> StoreResult<HeaderWithBlockLevel> {
        unimplemented!("the difficulty manager never reads full headers")
    }

    fn get_compact_header_data(&self, hash: Hash) -> StoreResult<CompactHeaderData> {
        Ok(self.get(hash))
    }
}

/// The real difficulty manager, configured the way a node configures it: `max_difficulty_target` is the genesis target.
fn manager(headers: &Arc<MockHeadersStore>) -> SampledDifficultyManager<MockHeadersStore, MemoryGhostdagStore> {
    SampledDifficultyManager::new(
        Arc::clone(headers),
        Arc::new(MemoryGhostdagStore::new()),
        genesis_hash(),
        GENESIS_BITS,
        target(GENESIS_BITS),
        WINDOW_SIZE,
        MIN_WINDOW_SIZE,
        SAMPLE_RATE,
        TARGET_TIME_PER_BLOCK,
    )
}

/// Registers `(timestamp, bits)` pairs in the mock header store and returns the matching difficulty window.
fn window(headers: &MockHeadersStore, blocks: &[(u64, u32)]) -> BlockWindowHeap {
    let mut heap = BlockWindowHeap::new();
    for (i, (timestamp, bits)) in blocks.iter().enumerate() {
        let hash = Hash::from_u64_word(i as u64 + 1);
        headers.insert(hash, *timestamp, *bits, 0);
        heap.push(Reverse(SortableBlock::new(hash, BlueWorkType::from_u64(1))));
    }
    heap
}

/// Block timestamps one target interval apart, all at `bits`: an honest, on-schedule window.
fn on_schedule(bits: u32) -> Vec<(u64, u32)> {
    (0..WINDOW_SIZE as u64).map(|i| (BASE_TS + i * TARGET_TIME_PER_BLOCK, bits)).collect()
}

/// Ghostdag data whose only field the difficulty manager reads is the selected parent.
fn ghostdag(selected_parent: Hash) -> GhostdagData {
    GhostdagData::new(0, BlueWorkType::from_u64(0), selected_parent, Arc::new(Vec::new()), Arc::new(Vec::new()), Default::default())
}

// ---------------------------------------------------------------------------
// I-D5 — the min_ts drag: no timestamp has a lower bound, so difficulty is
//        pushed down chain-wide by one forged old timestamp.
// ---------------------------------------------------------------------------

/// Attack (I-D5): `pre_ghostdag_validation.rs` only enforces `TimeTooFarIntoTheFuture`; nothing rejects a timestamp
/// that is *too old* -- `post_pow_validation.rs`'s `TimeTooOld` compares against the past median time. So an attacker
/// stamps the earliest block of the DAA window far in the past. `measured_duration = max_ts - min_ts` inflates and
/// `new_target = average_target * measured_duration / expected_duration` hands every subsequent block an easier
/// target: the difficulty of the whole chain drops, not just the attacker's block.
///
/// Fail-when-removed: this goes red if a lower timestamp bound is added upstream (the window could no longer be
/// dragged, so the arithmetic would stop re-rating), or if the retarget stops reacting to `min_ts`. The final leg
/// pins the only remaining defence: the I-D3 clamp, which confines even an absurd 15,000-year drag to the genesis
/// target.
#[test]
fn dragging_the_window_min_timestamp_backwards_halves_the_difficulty() {
    let headers = Arc::new(MockHeadersStore::new());
    let manager = manager(&headers);
    let gd = ghostdag(genesis_hash());

    // Baseline: an on-schedule window is a retarget no-op.
    let honest_bits = manager.calculate_difficulty_bits(&window(&headers, &on_schedule(HARDER_BITS)), &gd);
    assert_eq!(honest_bits, HARDER_BITS, "sanity: an on-schedule window must keep the difficulty unchanged");
    let honest_target = target(honest_bits);

    // Attack: the earliest block claims it was produced one whole window duration earlier than it was.
    let mutated: Vec<(u64, u32)> = on_schedule(HARDER_BITS)
        .into_iter()
        .enumerate()
        .map(|(i, (ts, bits))| (if i == 0 { ts - EXPECTED_WINDOW_DURATION } else { ts }, bits))
        .collect();
    let dragged_bits = manager.calculate_difficulty_bits(&window(&headers, &mutated), &gd);
    let dragged_target = target(dragged_bits);
    assert!(
        dragged_target > honest_target,
        "I-D5: a stale min_ts must make the chain EASIER (that is the attack); got {dragged_bits:#010x} vs {honest_bits:#010x}"
    );
    assert_eq!(
        dragged_target,
        honest_target * Uint256::from(2u64),
        "I-D5: dragging min_ts back by exactly one window duration must double the target (halve the difficulty)"
    );

    // The attacker's ideal: drag by 2^36 window durations (~15,000 years). Nothing in the timestamp rules stops it,
    // so this must be stopped -- and held -- by `max_difficulty_target`.
    let lethal: Vec<(u64, u32)> = on_schedule(HARDER_BITS)
        .into_iter()
        .enumerate()
        .map(|(i, (ts, bits))| (if i == 0 { ts.saturating_sub(EXPECTED_WINDOW_DURATION << 36) } else { ts }, bits))
        .collect();
    let clamped_bits = manager.calculate_difficulty_bits(&window(&headers, &lethal), &gd);
    assert!(
        target(clamped_bits) <= target(GENESIS_BITS),
        "I-D5: an ~15,000-year min_ts drag must be clamped to the genesis target, not granted {DREAM_BITS:#010x}-style ease"
    );
    assert!(
        target(clamped_bits) <= target(GENESIS_BITS),
        "I-D5: no drag, however large, may take the target above max_difficulty_target"
    );
}

// ---------------------------------------------------------------------------
// I-D2 — the same-timestamp window: `max(max_ts - min_ts, 1)` is the floor that
//        keeps a zero-duration window from driving the target to zero.
// ---------------------------------------------------------------------------

/// Attack (I-D2): grind a whole DAA window of blocks that all claim the *same* wall-clock time. If `measured_duration`
/// were plain `max_ts - min_ts`, the span would be 0, `new_target` would be 0, and every block after the window would
/// need a target-0 proof: the chain stalls outright (and any node with a different rounding forks off).
///
/// The invariant: the duration floors at 1 ms, so a zero-span window retargets to `average_target / expected_duration`
/// -- strictly harder than the window it came from, and never zero.
///
/// Fail-when-removed: this goes red if the `max(..., 1)` in `calculate_difficulty_bits` is dropped (the exact-target
/// leg then expects 0), or if someone "fixes" the zero span by freezing the difficulty instead (the strictly-harder
/// leg fails).
#[test]
fn a_same_timestamp_window_cannot_drive_the_target_to_zero() {
    let headers = Arc::new(MockHeadersStore::new());
    let manager = manager(&headers);
    let gd = ghostdag(genesis_hash());

    // Every block in the window claims the very same timestamp: the measured span is exactly zero.
    let stampede: Vec<(u64, u32)> = (0..WINDOW_SIZE as u64).map(|_| (BASE_TS, HARDER_BITS)).collect();
    let bits = manager.calculate_difficulty_bits(&window(&headers, &stampede), &gd);
    let new_target = target(bits);

    // With the 1 ms floor the retarget is deterministic: the min block is dropped from the average, so the target is
    // average_target / expected_duration.
    let blocks_after_min = WINDOW_SIZE as u64 - 1;
    let expected_duration = TARGET_TIME_PER_BLOCK * SAMPLE_RATE * blocks_after_min;
    let exact = target(HARDER_BITS) / Uint256::from(expected_duration);
    let tol_hi = exact * Uint256::from(1001u64) / Uint256::from(1000u64);
    let tol_lo = exact * Uint256::from(999u64) / Uint256::from(1000u64);
    assert!(
        new_target >= tol_lo && new_target <= tol_hi,
        "I-D2: a zero-span window must retarget as measured_duration = 1 ms (target = average / {expected_duration}); \
         any other value means the span was taken raw"
    );
    assert_ne!(
        new_target,
        Uint256::from(0u64),
        "I-D2: a same-timestamp window must never produce target 0 -- that freezes every following block (chain stall)"
    );
    assert!(
        new_target < target(HARDER_BITS),
        "I-D2: a zero-span window may only make the chain harder, never easier; got {bits:#010x} vs {HARDER_BITS:#010x}"
    );
    assert_ne!(
        bits, GENESIS_BITS,
        "I-D2: the zero span must be handled by the 1 ms floor, not quietly absorbed by the I-D3 clamp"
    );
}

// ---------------------------------------------------------------------------
// I-D3 — the ceiling: `max_difficulty_target` is the only limit on how EASY a
//        retarget may go.
// ---------------------------------------------------------------------------

/// Attack (I-D3): submit a window whose timestamps are spread over millennia (only the *upper* timestamp bound exists,
/// and even that is wall-clock-relative, so old timestamps are free). `new_target = average_target * measured_duration /
/// expected_duration` then explodes; the sole thing standing between the attacker and a chain of near-free blocks is the
/// `min(max_difficulty_target)` clamp.
///
/// Fail-when-removed: this goes red if the clamp is dropped or loosened (the glacial window would return something easier
/// than genesis), or if the clamp is replaced by a freeze (the 2x-slow control leg stops doubling).
#[test]
fn a_glacial_window_is_held_at_the_genesis_ceiling() {
    let headers = Arc::new(MockHeadersStore::new());
    let manager = manager(&headers);
    let gd = ghostdag(genesis_hash());
    let honest_target = target(HARDER_BITS);

    // Control: a window twice as slow as scheduled doubles the target and stays well below the ceiling, so the clamp is
    // not masking a retarget that simply never reacts.
    let slow: Vec<(u64, u32)> =
        (0..WINDOW_SIZE as u64).map(|i| (BASE_TS + i * 2 * TARGET_TIME_PER_BLOCK * SAMPLE_RATE, HARDER_BITS)).collect();
    let slow_bits = manager.calculate_difficulty_bits(&window(&headers, &slow), &gd);
    assert_eq!(
        target(slow_bits),
        honest_target * Uint256::from(2u64),
        "I-D3 control: a window twice as slow must double the target (before the ceiling is reached)"
    );

    // The attack: one gap of ~557 years between consecutive blocks, ~3,900 years across the window. The unclamped target
    // would be ~10^10 times easier than the honest one.
    const GLACIAL_GAP_MS: u64 = 1 << 44;
    let glacial: Vec<(u64, u32)> =
        (0..WINDOW_SIZE as u64).map(|i| (BASE_TS + i * GLACIAL_GAP_MS, HARDER_BITS)).collect();
    let bits = manager.calculate_difficulty_bits(&window(&headers, &glacial), &gd);

    assert_eq!(
        bits, GENESIS_BITS,
        "I-D3: a millennia-wide window must be clamped to max_difficulty_target (genesis); it must never reach \
         {DREAM_BITS:#010x}-style ease"
    );
    assert_ne!(bits, DREAM_BITS, "I-D3: no retarget may ever hand out a target easier than the genesis target");
    assert!(
        target(bits) <= target(GENESIS_BITS),
        "I-D3: the clamp is a ceiling on EASE -- target {:#x} exceeds max_difficulty_target {:#x}",
        target(bits),
        target(GENESIS_BITS)
    );

    // The ceiling is hard: an even more absurd window returns exactly the same bits, never a little easier.
    let dead_chain: Vec<(u64, u32)> =
        (0..WINDOW_SIZE as u64).map(|i| (BASE_TS + i * (GLACIAL_GAP_MS * 8), HARDER_BITS)).collect();
    assert_eq!(
        manager.calculate_difficulty_bits(&window(&headers, &dead_chain), &gd),
        GENESIS_BITS,
        "I-D3: past the ceiling, more slowness must buy the attacker nothing"
    );
}

// ---------------------------------------------------------------------------
// I-D4 — the DAA score: `sp_daa_score + (mergeset_size - |mergeset_non_daa|)`,
//        declared exactly. A forged score cannot walk the window forward.
// ---------------------------------------------------------------------------

/// Attack (I-D4): declare a DAA score the block did not earn. `daa_score` selects the DAA/difficulty window (blocks
/// below `blue_score - full_window` stop counting towards the score, and the header's score must match the computed one
/// exactly -- `UnexpectedHeaderDaaScore`). Getting the score to run ahead is the cheapest way to pick a *different*
/// difficulty window, so a forger who can inflate it can try to choose an easier history.
///
/// This pins the formula, including the `mergeset_non_daa` subtraction: non-DAA mergeset blocks are counted in the
/// window but must NOT advance the score. Skipping the subtraction (the classic mistake) overstates the score by the
/// number of non-DAA blocks, which is exactly what this test asserts away.
///
/// Fail-when-removed: this goes red if the non-DAA blocks are dropped from the `mergeset_size()` term (a forged-looking
/// score would then be the "correct" one), if the selected parent's score stops being the base, or if the score is no
/// longer required to match exactly.
#[test]
fn a_forged_daa_score_cannot_walk_the_window_forward() {
    const SP_DAA_SCORE: u64 = 1_000;
    let headers = Arc::new(MockHeadersStore::new());
    let manager = manager(&headers);
    let ghostdag_store = MemoryGhostdagStore::new();

    // A coinbase/spend-history shaped block: one selected parent, two more blues, two reds.
    let sp = Hash::from_u64_word(0xA1);
    let blue1 = Hash::from_u64_word(0xB1);
    let blue2 = Hash::from_u64_word(0xB2);
    let red1 = Hash::from_u64_word(0xC1);
    let red2 = Hash::from_u64_word(0xC2);
    headers.insert(sp, BASE_TS, HARDER_BITS, SP_DAA_SCORE);

    // The new block's blue score is 100, and the DAA window is 8 blocks deep, so anything blue-scored below 92 is
    // outside the DAA window and must be excluded from the score while still being part of the mergeset.
    let gd = GhostdagData::new(
        100,
        BlueWorkType::from_u64(0),
        sp,
        Arc::new(vec![sp, blue1, blue2]),
        Arc::new(vec![red1, red2]),
        Default::default(),
    );
    for (hash, blue_score) in [(sp, 95u64), (blue1, 93), (blue2, 92), (red1, 91), (red2, 60)] {
        let data = GhostdagData::new(
            blue_score,
            BlueWorkType::from_u64(0),
            sp,
            Arc::new(Vec::new()),
            Arc::new(Vec::new()),
            Default::default(),
        );
        ghostdag_store.insert(hash, Arc::new(data)).unwrap();
    }

    let (daa_score, non_daa) = manager.calc_daa_score_and_mergeset_non_daa_blocks(&gd, &ghostdag_store);
    assert_eq!(
        non_daa,
        BlockHashSet::from_iter([red1, red2]),
        "I-D4: only the two mergeset blocks below the DAA window (blue score < 92) may be non-DAA"
    );
    assert_eq!(
        daa_score,
        SP_DAA_SCORE + 3,
        "I-D4: daa_score must be sp_daa_score + (mergeset_size - |mergeset_non_daa|) = {SP_DAA_SCORE} + (5 - 2)"
    );

    // Ignoring the subtraction (the forger's shortcut) overstates the score by exactly the non-DAA count: that value is
    // what a node must refuse with UnexpectedHeaderDaaScore, which is why the exact match above is load-bearing.
    let overstated = manager.calc_daa_score(&gd, &BlockHashSet::default());
    assert_eq!(
        overstated,
        SP_DAA_SCORE + 5,
        "I-D4: the raw mergeset size (5) is what an off-by-non_daa score would claim"
    );

    // Only the exact score is acceptable; each forged candidate is a different value, so equality (not a range) is what
    // stops a forger from steering the difficulty window.
    for forged in [daa_score + 1, daa_score - 1, SP_DAA_SCORE + 5, SP_DAA_SCORE] {
        assert_ne!(
            forged, daa_score,
            "I-D4: a header declaring daa_score {forged} instead of {daa_score} must fail the exact check \
             (UnexpectedHeaderDaaScore), or the DAA/difficulty window could be walked forward on a forged score"
        );
    }
}

