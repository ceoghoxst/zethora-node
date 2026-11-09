//! Black-hat adversarial tests for Zethora proof-of-work: RandomZ key epochs, the
//! `daa_score -> epoch` derivation, and DAA-score epoch plausibility (ZTH-SPEC-000 §4.4,
//! ZTH-SPEC-005 §5.1).
//!
//! Threat model. A miner chooses `header.daa_score` freely. Every RandomZ key epoch is a
//! fixed, *public* key (`randomz::key_for_epoch`), so work in an old (already cached by the
//! node) epoch, or in a far-future epoch the node should never have looked at, is cheap for
//! the attacker. Two things must therefore hold:
//!  - the header's key epoch is derived from its own `daa_score` (so the key cannot be picked
//!    independently of the header), and
//!  - the epoch plausibility bound is enforced BEFORE any RandomZ work is spent, so forging a
//!    DAA score into an out-of-window epoch is refused for free rather than after a hash.
//!
//! Invariants pinned here (recon I-P1..I-P5):
//!  - I-P1: PoW is `calculate_pow(nonce) <= target(bits)` under `epoch_of(header.daa_score)`,
//!          and the epoch bound is enforced BEFORE PoW.
//!  - I-P2: the block level is derived from the PoW value only; level 0 is exactly 0 (a high
//!          declared level must not fabricate work).
//!  - I-P3: `RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)` outside
//!          [epoch(pp)-1, epoch(max(pp, tip))+1] for ordinary headers.
//!  - I-P4: proof-reachable headers obey the same epoch window (net of the clock bound, which
//!          can only tighten it), so a header past `epoch(proof_pp)+1` cannot be a valid
//!          pruning-proof header.
//!  - I-P5: `skip_proof_of_work` is the ONLY PoW bypass and must not bypass the I-P3 window.
//!
//! Run with:
//! `cargo test -p kaspa-consensus --test zethora_pow_epoch_blackhat -j 4 -- --nocapture`

use kaspa_consensus_core::errors::block::RuleError;
use kaspa_consensus::{
    config::ConfigBuilder,
    consensus::test_consensus::TestConsensus,
    params::DEVNET_PARAMS,
};
// `validate_and_insert_block` / `get_block_status` are methods of the `ConsensusApi` trait, so the
// trait must be in scope for the calls in these tests to resolve (same as the in-crate reference).
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_hashes::Hash;
use kaspa_math::Uint256;
use kaspa_pow::{
    calc_block_level_check_pow,
    calc_level_from_pow,
    randomz::{epoch_of, key_for_epoch, pow_input, pow_value_light, EPOCH_LENGTH, EPOCH_SHIFT},
    State,
};

/// Compact form of target 1: the hardest target the header format can express, and one that no
/// nonce will meet. Used as a tripwire — a header carrying it cannot have valid PoW, so any
/// error other than `InvalidPoW` proves the node never spent RandomZ work on it.
const UNMINEABLE_BITS: u32 = 0x0300_0001;

/// Attack: claim a DAA score whose RandomZ key epoch is far in the future, i.e. an epoch the
/// node must reject before it does any hashing. The header is deliberately unmineable, so the
/// only error this test may see is a pre-PoW one; if the epoch bound were applied after PoW the
/// node would answer `InvalidPoW` (and would already have paid for the hash).
///
/// Fail-when-removed: goes red if `check_pow_epoch_plausible` stops running before the PoW
/// check, or if the window stops excluding epochs above `epoch(max(pp, tip)) + 1`. It then
/// reports the wrong error — or, worse, accepts the header.
#[tokio::test]
async fn forging_daa_score_into_a_far_future_epoch_is_refused_before_any_pow() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;

    // The parent (== pruning point here) is the genesis block: its epoch fixes the low edge of
    // the plausibility window, and the current tip fixes the high one.
    let honest = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    let pp_epoch = epoch_of(honest.header.daa_score);

    // An epoch the node can have no honest DAA score for: 100k epochs past the parent's epoch.
    let forged_epoch = pp_epoch + 100_000;
    let forged_daa_score = forged_epoch << EPOCH_SHIFT;

    let mut forged = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    forged.header.bits = UNMINEABLE_BITS; // no nonce can satisfy this: PoW can never pass
    forged.header.daa_score = forged_daa_score;
    assert_eq!(epoch_of(forged.header.daa_score), forged_epoch, "the forged header really claims a different epoch");

    // Sanity: the header genuinely has no valid PoW, so only a pre-PoW rule can reject it.
    assert!(
        !State::new(&forged.header).check_pow(forged.header.nonce).0,
        "I-P1: the forged header must carry no valid PoW, otherwise this test cannot tell whether the epoch bound ran first"
    );

    let result = consensus.validate_and_insert_block(forged.to_immutable()).block_task.await;

    let reported = match result {
        Err(RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)) => Some((daa_score, epoch, low, high)),
        _ => None,
    };
    let (daa_score, epoch, low, high) = match reported {
        Some(reported) => reported,
        None => panic!(
            "I-P1/I-P3: a header forging daa_score into epoch {forged_epoch} (checksum {forged_daa_score}) must be \
             refused with ZethoraPowEpochOutOfRange before any RandomZ work is spent, not accepted and not with a \
             PoW/difficulty error"
        ),
    };

    assert_eq!(daa_score, forged_daa_score, "I-P3: the error must report the forged DAA score");
    assert_eq!(epoch, forged_epoch, "I-P3: the error must report the epoch derived from the forged DAA score");
    assert!(
        epoch < low || epoch > high,
        "I-P3: the reported window [{low}, {high}] must exclude the forged epoch {epoch}"
    );
    assert!(
        low >= pp_epoch.saturating_sub(1),
        "I-P3: the low edge of the window must not reach below epoch(pp) - 1 (got {low}, epoch(pp) = {pp_epoch})"
    );

    // The refused header never entered the store (it never reached the post-PoW checks).
    assert_eq!(
        consensus.get_block_status(Hash::from(2)),
        None,
        "I-P3: a header refused for its epoch must not be stored"
    );

    consensus.shutdown(wait_handles);
}

/// Attack: turn on the node's PoW bypass (`skip_proof_of_work`) and then forge the DAA score.
/// The bypass exists so tests and trusted imports need not mine; it must never disable the
/// epoch plausibility window. The first half proves the bypass is really active (an unmined but
/// otherwise honest header is accepted), so the rejection in the second half can only come from
/// the I-P3 window check — not from PoW, not from difficulty.
///
/// Fail-when-removed: goes red if `skip_proof_of_work` short-circuits the whole isolation check
/// instead of only the RandomZ call, i.e. if the epoch bound becomes reachable-around by an
/// attacker who simply claims to skip mining.
#[tokio::test]
async fn skip_proof_of_work_does_not_bypass_the_epoch_window() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;

    // Control: an unmined-but-honest header passes. This is what "the PoW bypass is on" means;
    // without it the test below could not distinguish the epoch check from the PoW check.
    let mut honest = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    let honest_bits = honest.header.bits;
    let honest_daa_score = honest.header.daa_score;
    honest.header.nonce = 0;
    let control = consensus.validate_and_insert_block(honest.to_immutable()).block_task.await;
    assert!(
        control.is_ok(),
        "I-P5 control: with skip_proof_of_work an unmined but honest header must be accepted; otherwise this test \
         would not prove that the epoch bound (and not PoW) is what stops the forged header"
    );

    let pp_epoch = epoch_of(honest_daa_score);

    // Same difficulty as an honest header (so the difficulty check is not the blocker), only the
    // DAA score is forged out of the window, and the nonce is left unmined.
    let forged_epoch = pp_epoch + 3;
    let mut forged = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    forged.header.bits = honest_bits;
    forged.header.daa_score = forged_epoch << EPOCH_SHIFT;
    forged.header.nonce = 0;

    let result = consensus.validate_and_insert_block(forged.to_immutable()).block_task.await;

    let reported = match result {
        Err(RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)) => Some((daa_score, epoch, low, high)),
        _ => None,
    };
    let (_, epoch, low, high) = match reported {
        Some(reported) => reported,
        None => panic!(
            "I-P5: skip_proof_of_work must not bypass the epoch window — a header claiming epoch {forged_epoch} \
             must still be refused with ZethoraPowEpochOutOfRange"
        ),
    };
    assert!(
        epoch < low || epoch > high,
        "I-P5: the reported window [{low}, {high}] must exclude the forged epoch {epoch}"
    );

    // Still not stored: the bypass did not let a forged epoch through.
    assert_eq!(
        consensus.get_block_status(Hash::from(2)),
        None,
        "I-P5: a forged-epoch header must not be stored even with the PoW bypass enabled"
    );

    consensus.shutdown(wait_handles);
}

/// Attack: mine (or replay) somewhere else. Two levers are checked here.
///
/// (1) I-P1 — the key epoch is *exactly* `daa_score >> EPOCH_SHIFT` at every boundary, with no
/// rounding, clamping or off-by-one a miner could hide behind, and the PoW value depends on the
/// declared epoch: the same block input does not hash to the same value in two epochs, so work
/// done in one epoch (a cached one, cheap to mine) cannot be replayed into another.
///
/// (2) I-P2 — the block level comes from the PoW value alone; declaring harder bits does not
/// raise it, and level 0 is exactly 0 (no underflow into a huge level, no fabricated work).
///
/// Fail-when-removed: goes red if `State::new` stops deriving the epoch from the header's DAA
/// score, if keys stop being per-epoch, or if `calc_level_from_pow` starts crediting level to a
/// block whose PoW earns no level.
#[tokio::test]
async fn pow_epoch_follows_daa_score_and_level_zero_is_zero_work() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;

    let template = consensus.build_header_only_block_with_parents(7.into(), vec![genesis]).header;

    // (1) I-P1: epoch_of must match the declared DAA score exactly, at and around every boundary.
    let daa_scores =
        [0u64, 1, EPOCH_LENGTH - 1, EPOCH_LENGTH, EPOCH_LENGTH + 1, 3 * EPOCH_LENGTH + 7, u64::MAX];
    for daa_score in daa_scores {
        let mut header = template.clone();
        header.daa_score = daa_score;
        let state = State::new(&header);

        assert_eq!(
            state.epoch(),
            daa_score >> EPOCH_SHIFT,
            "I-P1: the RandomZ key epoch must be daa_score >> EPOCH_SHIFT exactly (daa_score = {daa_score})"
        );
        assert_eq!(
            state.epoch(),
            epoch_of(daa_score),
            "I-P1: the state epoch and epoch_of must agree (daa_score = {daa_score})"
        );

        // The node hashes in the header's declared epoch and in no other: substituting any other
        // epoch's (public, cacheable) key would let a miner reuse cheap work.
        assert_eq!(
            state.calculate_pow(0),
            pow_value_light(epoch_of(daa_score), &state.pow_input(0)),
            "I-P1: the PoW must be evaluated in the epoch derived from this header's daa_score (daa_score = {daa_score})"
        );
    }

    // Distinct epochs must have distinct keys, and the same block input must not collide across
    // epochs — otherwise work mined in one (cached) epoch would be valid in another.
    let input = pow_input(&[0x5A; 32], 42, 7);
    let epoch_a = 11u64;
    let epoch_b = 12u64;
    assert_ne!(key_for_epoch(epoch_a), key_for_epoch(epoch_b), "I-P1: each epoch needs its own RandomZ key");
    assert_ne!(
        pow_value_light(epoch_a, &input),
        pow_value_light(epoch_b, &input),
        "I-P1: the same block input must not hash identically in two epochs, or cached work could be replayed"
    );

    let mut in_epoch_a = template.clone();
    in_epoch_a.daa_score = epoch_a << EPOCH_SHIFT;
    let mut in_epoch_b = template.clone();
    in_epoch_b.daa_score = epoch_b << EPOCH_SHIFT;
    assert_ne!(
        State::new(&in_epoch_a).calculate_pow(7),
        State::new(&in_epoch_b).calculate_pow(7),
        "I-P1: a header's PoW must depend on the epoch its declared DAA score falls in"
    );

    // (2) I-P2: level 0 is exactly 0 — a PoW worth no level must never underflow into a large level.
    let max_level = DEVNET_PARAMS.max_block_level;
    assert!(
        Uint256::MAX.bits() >= max_level as u32,
        "I-P2: test precondition — the maximum PoW value must be at least the max block level's bit count"
    );
    assert_eq!(
        calc_level_from_pow(Uint256::MAX, max_level),
        0,
        "I-P2: a PoW at or above the max block level must yield level 0, never an underflowed level"
    );

    // The level is a function of the observed PoW value, not of the declared difficulty bits: a
    // header declaring the hardest possible target must still be credited a level no higher than
    // `max_block_level`, and re-deriving the level from that same observed PoW must reproduce it.
    // (Declared `bits` do change the measured PoW via the header hash, so we must never compare
    // levels across two headers that differ in `bits`; we only bound the level of one such header.)
    let mut declared_hard = template.clone();
    declared_hard.bits = UNMINEABLE_BITS;
    let (level_hard, _) = calc_block_level_check_pow(&declared_hard, max_level);
    assert!(
        level_hard <= max_level,
        "I-P2: declaring the hardest bits must not credit a level/work above max_block_level \
         ({level_hard} > {max_level})"
    );
    let observed_pow = State::new(&declared_hard).calculate_pow(declared_hard.nonce);
    assert_eq!(
        level_hard,
        calc_level_from_pow(observed_pow, max_level),
        "I-P2: the block level must be derived from the observed PoW value alone, so a header \
         cannot fake work by how it declares its difficulty"
    );

    consensus.shutdown(wait_handles);
}

/// Attack: get a header into a pruning proof (or any proof-reachable position) whose DAA score
/// lands an epoch past the one the proof's own pruning point allows. Proof headers are validated
/// in isolation with the same epoch window (epoch(pp) +/- 1), additionally cut by the node's clock
/// bound; the clock bound can only tighten the window, so a header that is already outside the
/// pp window can never be a valid proof header. This test pins the exact edges of that window:
/// one epoch forward is tolerated, two are not.
///
/// Fail-when-removed: goes red if the epoch window widens by even a single epoch (proof headers
/// then reach into epochs no honest DAA score can have).
#[tokio::test]
async fn pruning_proof_header_with_out_of_window_epoch_is_refused() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;

    // proof_pp == genesis here, so epoch(proof_pp) anchors the window.
    let proof_pp = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    let proof_pp_epoch = epoch_of(proof_pp.header.daa_score);

    // Edge case A: one epoch past the proof's parent is inside the window (I-P3: epoch(pp)+1), so
    // the rejection below must NOT be the epoch rule. Unmineable bits keep the distinction
    // visible: if the epoch rule fired we would see ZethoraPowEpochOutOfRange here.
    let mut one_past = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    one_past.header.bits = UNMINEABLE_BITS;
    one_past.header.daa_score = (proof_pp_epoch + 1) << EPOCH_SHIFT;
    let result = consensus.validate_and_insert_block(one_past.to_immutable()).block_task.await;
    assert!(
        !matches!(result, Err(RuleError::ZethoraPowEpochOutOfRange(..))),
        "I-P3/I-P4: epoch(pp)+1 must stay inside the plausible window — narrowing it would reject honest headers"
    );

    // Edge case B: two epochs past the proof's parent is outside any honest window; a proof header
    // claiming it must be refused for its epoch (pre-PoW, so nothing is hashed).
    let forged_epoch = proof_pp_epoch + 2;
    assert!(
        forged_epoch > proof_pp_epoch + 1,
        "I-P4: the forged epoch must be past the proof-reachable bound epoch(proof_pp)+1"
    );
    let forged_daa_score = forged_epoch << EPOCH_SHIFT;

    let mut two_past = consensus.build_header_only_block_with_parents(3.into(), vec![genesis]);
    two_past.header.bits = UNMINEABLE_BITS;
    two_past.header.daa_score = forged_daa_score;
    assert_eq!(
        epoch_of(two_past.header.daa_score),
        forged_epoch,
        "the forged proof header really claims a different epoch"
    );
    assert!(
        !State::new(&two_past.header).check_pow(two_past.header.nonce).0,
        "I-P4: the forged proof header must carry no valid PoW, so only a pre-PoW epoch rule can refuse it"
    );

    let result = consensus.validate_and_insert_block(two_past.to_immutable()).block_task.await;
    let reported = match result {
        Err(RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)) => Some((daa_score, epoch, low, high)),
        _ => None,
    };
    let (daa_score, epoch, low, high) = match reported {
        Some(reported) => reported,
        None => panic!(
            "I-P4: a header claiming epoch {forged_epoch}, past epoch(proof_pp)+1, must be refused with \
             ZethoraPowEpochOutOfRange so it can never become a pruning-proof header"
        ),
    };
    assert_eq!(daa_score, forged_daa_score, "I-P4: the error must report the forged DAA score");
    assert_eq!(epoch, forged_epoch, "I-P4: the error must report the epoch derived from the forged DAA score");
    assert!(
        epoch < low || epoch > high,
        "I-P4: the reported window [{low}, {high}] must exclude the forged proof epoch {epoch}"
    );

    assert_eq!(
        consensus.get_block_status(Hash::from(3)),
        None,
        "I-P4: a proof-style header refused for its epoch must not be stored"
    );

    consensus.shutdown(wait_handles);
}

