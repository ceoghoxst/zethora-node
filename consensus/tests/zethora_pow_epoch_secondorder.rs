//! Second-order black-hat probes for the Zethora PoW epoch window (ZTH-SPEC-000 §4.4), written
//! against the patched `check_pow_epoch_plausible` (consensus/src/pipeline/header_processor/
//! pre_ghostdag_validation.rs:129-175), where the early `if self.skip_proof_of_work { return
//! Ok(()) }` was removed and only the RandomZ hash work is now skippable (line 177-181).
//!
//! Where `zethora_pow_epoch_blackhat.rs` pins the *first-order* properties (a forged epoch is
//! refused; the skip flag does not disable the window), these tests pin the *second-order* edges
//! the patch can break on either side:
//!  - relaxing: an attacker who legitimately holds a parent (or a bypass) walks a header into the
//!    window one epoch at a time and re-mines in an already-cached (cheap) key epoch;
//!  - tightening: an honest node whose pruning point and tip straddle an epoch boundary — and
//!    which therefore re-validates headers of the pruning point's own epoch during sync, pruning
//!    proof import or trusted-header import — loses the low edge and stalls forever.
//!
//! Every assertion below states an *invariant* (relations between the reported window edges and
//! the epoch the node actually used), never equality against a hardcoded constant (Section 150.4),
//! so the tests keep their meaning if `EPOCH_LENGTH` or the devnet DAA score of genesis changes.
//!
//! Run with:
//! `cargo test -p kaspa-consensus --test zethora_pow_epoch_secondorder -j 4 -- --nocapture`

use kaspa_consensus::{config::ConfigBuilder, consensus::test_consensus::TestConsensus, params::DEVNET_PARAMS};
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::errors::block::RuleError;
use kaspa_hashes::Hash;
use kaspa_pow::{
    randomz::{epoch_of, EPOCH_SHIFT},
    State,
};

/// Compact form of target 1: no nonce satisfies it. Used as a tripwire — a header carrying these
/// bits cannot have valid PoW, so any error other than `InvalidPoW`/`UnexpectedDifficulty` proves
/// the node never spent a RandomZ light setup (256 MiB) on it.
const UNMINEABLE_BITS: u32 = 0x0300_0001;

/// Attack vector I-P5-2O-1 — *the skip flag plus an orphan-shaped header*.
///
/// The patched code keeps the epoch window alive under `skip_proof_of_work` (line 130-133), but the
/// out-of-range branch only pre-empts the PoW check when the header has *known* parents
/// (line 170-173: `if !trusted { self.check_parents_exist(header)?; }`). The second-order question
/// is whether an attacker can pair the flag with an unknown parent so the header is neither
/// epoch-refused nor PoW-refused and quietly enters the orphan pool, from where it is retried (and
/// its forged epoch re-hashed) on every parent arrival — free CPU/memory against every honest node
/// that is one block behind.
///
/// Invariant asserted: a header with an unattributable parent and a DAA score outside the window is
/// refused *without* a RandomZ hash and is never stored, whether the refusal is reported as an
/// orphan (`MissingParents`, so a lagging node still syncs) or as an out-of-window epoch. What must
/// never happen is acceptance, or a PoW/difficulty verdict, which would mean work was done.
///
/// Fail-when-removed: goes red if the window stops running under the flag (the header is accepted),
/// if it starts running *after* the PoW check (the verdict becomes `InvalidPoW`/`UnexpectedDifficulty`
/// — the setup and the hashing were already paid), or if a refused header is stored.
#[tokio::test]
async fn i_p5_2o_1_skip_flag_orphan_cannot_smuggle_a_forged_epoch_past_the_window() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;

    // Control: the bypass is really active, so anything refused below is refused by the epoch
    // window (or by the parent rule), never by proof of work.
    let mut control = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    control.header.nonce = 0;
    let control_daa_score = control.header.daa_score;
    let control_result = consensus.validate_and_insert_block(control.to_immutable()).block_task.await;
    assert!(
        control_result.is_ok(),
        "I-P5-2O-1 control: with skip_proof_of_work an unmined but honest header must be accepted, \
         otherwise this test cannot attribute the refusal below to the epoch window (got {control_result:?})"
    );
    let tip_epoch = epoch_of(control_daa_score);

    // The attack: the same cheap, unattributable shape an attacker floods with. The declared DAA
    // score is several epochs ahead of anything an honest tip can hold, and the parent is unknown,
    // so a node that trusted the flag alone would hash it and park it in the orphan pool.
    let unknown_parent = Hash::from(99u64);
    let forged_epoch = tip_epoch + 5;
    let forged_daa_score = (forged_epoch << EPOCH_SHIFT).saturating_add(7);
    let mut forged = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    forged.header.daa_score = forged_daa_score;
    forged.header.nonce = 0;
    forged.header.parents_by_level = vec![vec![unknown_parent]].try_into().unwrap();
    assert_eq!(
        epoch_of(forged.header.daa_score),
        forged_epoch,
        "I-P5-2O-1: the forged header must really claim a different key epoch, or this test proves nothing"
    );

    let result = consensus.validate_and_insert_block(forged.to_immutable()).block_task.await;

    match result {
        // Preferred: reported as an orphan, so a node that is behind still syncs instead of
        // penalising the peer — but refused all the same, and without any RandomZ work.
        Err(RuleError::MissingParents(missing)) => assert_eq!(
            missing,
            vec![unknown_parent],
            "I-P5-2O-1: the orphan refusal must report exactly the unknown parent, so the caller \
             queues the header instead of accepting it"
        ),
        // Also acceptable: the window itself refuses it. Still pre-PoW, still no setup paid.
        Err(RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)) => {
            assert_eq!(daa_score, forged_daa_score, "I-P5-2O-1: the refusal must report the forged DAA score");
            assert_eq!(epoch, forged_epoch, "I-P5-2O-1: the refusal must report the forged epoch");
            assert!(
                epoch < low || epoch > high,
                "I-P5-2O-1: the reported window [{low}, {high}] must exclude the forged epoch {epoch}, \
                 otherwise an attacker holding a parent inside the window re-mines it for free"
            );
        }
        // Anything else means either the flag let the header through, or the node hashed first and
        // asked questions later — both are the hole.
        Ok(_) => panic!(
            "I-P5-2O-1: skip_proof_of_work plus an unknown parent must not admit a header claiming \
             epoch {forged_epoch}; an attacker could park such headers in the orphan pool and make \
             every honest node re-hash them on each parent arrival (stall + cheap-work replay)"
        ),
        Err(other) => panic!(
            "I-P5-2O-1: a header claiming epoch {forged_epoch} was refused only after PoW/difficulty \
             work ({other:?}); the RandomZ light setup for a bogus epoch was already paid, which is \
             the exact cost the epoch window exists to prevent"
        ),
    }

    assert_eq!(
        consensus.get_block_status(Hash::from(2u64)),
        None,
        "I-P5-2O-1: a forged-epoch header must not be stored, not even under the PoW bypass"
    );

    consensus.shutdown(wait_handles);
}

/// Attack vector I-P5-2O-2 — *the window now runs unconditionally, so its edges must be exact in
/// both directions.*
///
/// The patch turned the epoch bound into an always-on rule (pre_ghostdag_validation.rs:130-133).
/// Every honest header that follows a tip sits in `epoch(tip)` or `epoch(tip)+1` (DAA scores grow by
/// one per block, and a header in flight can straddle an epoch boundary), and every header a node
/// re-validates around its pruning point sits at `epoch(pp)` — never below `epoch(pp)-1`. If the
/// patched window were tightened by a single epoch on the high side, an ordinary miner / a syncing
/// node is refused for free (no PoW, no DAA analysis) and the chain stalls one block before every
/// epoch boundary. If it were loosened by one, an attacker re-mines in an already-cached epoch.
///
/// Invariants asserted here (no constants — everything is related to the epoch the node itself used
/// for the honest control header):
///  1. a header one epoch above the tip is *not* epoch-refused (the edge stays open; tightening it
///     stalls mining and header sync at every epoch boundary);
///  2. a header two epochs above the tip *is* epoch-refused, with a reported window whose upper edge
///     does not exceed `epoch(tip) + 1` (loosening it hands back the cached-epoch replay);
///  3. a header at `epoch(pp)` (the low edge, what pruning-proof / trusted-header import
///     re-validates) is *not* epoch-refused.
///
/// Fail-when-removed: goes red if either edge moves. High edge too tight => (1) or (3) fires
/// `ZethoraPowEpochOutOfRange` and honest mining/sync is stalled for free; high edge too loose =>
/// (2) no longer refuses, and work mined in a cached epoch becomes replayable one epoch at a time.
#[tokio::test]
async fn i_p5_2o_2_epoch_window_keeps_both_edges_exactly_where_honest_headers_live() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;

    // Honest control header: accepted, and it is the tip the window must be anchored on.
    let mut control = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    control.header.nonce = 0;
    let control_bits = control.header.bits;
    let control_daa_score = control.header.daa_score;
    let control_result = consensus.validate_and_insert_block(control.to_immutable()).block_task.await;
    assert!(
        control_result.is_ok(),
        "I-P5-2O-2 control: an unmined honest header must be accepted under skip_proof_of_work (got {control_result:?})"
    );
    let tip_epoch = epoch_of(control_daa_score);
    let pp_epoch = epoch_of(config.genesis.daa_score);

    // (1) One epoch above the tip: honest headers land here as the DAA score crosses a boundary.
    // This must not be refused by the epoch rule, or mining/sync stalls exactly at the boundary.
    let mut next_epoch = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    next_epoch.header.bits = control_bits;
    next_epoch.header.daa_score = (tip_epoch + 1) << EPOCH_SHIFT;
    next_epoch.header.nonce = 0;
    let next_result = consensus.validate_and_insert_block(next_epoch.to_immutable()).block_task.await;
    assert!(
        !matches!(next_result, Err(RuleError::ZethoraPowEpochOutOfRange(..))),
        "I-P5-2O-2: a header claiming epoch(tip)+1 = {} was refused by the epoch window ({next_result:?}); \
         tightening the high edge by one epoch stalls honest mining and header sync at every epoch boundary \
         — the node rejects the first header of the new epoch for free, forever",
        tip_epoch + 1
    );
    assert!(
        next_result.is_err(),
        "I-P5-2O-2: the forged DAA score must still be refused by the exact check after the window; \
         accepting it (got {next_result:?}) means the epoch window became a substitute for the DAA rule"
    );

    // (2) Two epochs above the tip: no honest header in flight can claim this, and allowing it would
    // re-open the cached-epoch replay the patch exists to close.
    let mut two_ahead = consensus.build_header_only_block_with_parents(3.into(), vec![genesis]);
    two_ahead.header.bits = control_bits;
    two_ahead.header.daa_score = (tip_epoch + 2) << EPOCH_SHIFT;
    two_ahead.header.nonce = 0;
    let two_ahead_result = consensus.validate_and_insert_block(two_ahead.to_immutable()).block_task.await;
    match two_ahead_result {
        Err(RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)) => {
            assert_eq!(daa_score, (tip_epoch + 2) << EPOCH_SHIFT, "I-P5-2O-2: the refusal must report the forged DAA score");
            assert_eq!(epoch, tip_epoch + 2, "I-P5-2O-2: the refusal must report the epoch of the forged DAA score");
            assert!(epoch > high, "I-P5-2O-2: the reported window [{low}, {high}] does not exclude epoch {epoch}");
            assert!(
                high <= tip_epoch + 1,
                "I-P5-2O-2: the high edge {high} exceeds epoch(tip)+1 = {}; an attacker can then walk a \
                 forged header into an old, already-cached RandomZ epoch one step at a time and replay cheap work",
                tip_epoch + 1
            );
            assert!(
                low <= pp_epoch,
                "I-P5-2O-2: the low edge {low} sits above epoch(pp) = {pp_epoch}, so pruning-point-era headers would be refused"
            );
        }
        other => panic!(
            "I-P5-2O-2: a header claiming epoch {tp} past the tip must be refused by the epoch window before \
             any RandomZ work (got {other:?}); if this passes, an attacker re-mines in a cached epoch",
            tp = tip_epoch + 2
        ),
    }

    // (3) The low edge: epoch(pp) itself. Pruning-proof import and trusted-header import re-validate
    // headers that are at or one below the pruning point's epoch; refusing epoch(pp) locks out the
    // authoritative chain and the node can never import a pruning point again.
    let mut at_pp = consensus.build_header_only_block_with_parents(4.into(), vec![genesis]);
    at_pp.header.bits = control_bits;
    at_pp.header.daa_score = pp_epoch << EPOCH_SHIFT;
    at_pp.header.nonce = 0;
    let at_pp_result = consensus.validate_and_insert_block(at_pp.to_immutable()).block_task.await;
    assert!(
        !matches!(at_pp_result, Err(RuleError::ZethoraPowEpochOutOfRange(..))),
        "I-P4-2O: a header claiming epoch(pp) = {pp_epoch} was refused by the epoch window \
         ({at_pp_result:?}); pruning-proof / trusted-header import re-validates that epoch, so raising \
         the low edge above epoch(pp) stalls pruning forever (I-P4 regression)"
    );

    consensus.shutdown(wait_handles);
}

/// Attack vector I-P4-2O-3 / I-P5-2O-3 — *the anchor arithmetic itself, and the ordering between the
/// always-on epoch window and the cheap exact checks it must protect.*
///
/// The window is computed from `header.daa_score` (pre_ghostdag_validation.rs:159) and from the
/// pruning point's / tip's DAA score (lines 134-158). DAA scores are attacker-chosen `u64`s, so the
/// two ways to break the patch are arithmetic and ordering:
///  - arithmetic: a DAA score at the top of the epoch space must not wrap/saturate the window into
///    admitting itself (`epoch_of(u64::MAX)` is the largest epoch the type can express; a
///    `saturating_add` on the high edge must never make `high` overflow into a small number that
///    *contains* the forged epoch);
///  - ordering: after the patch the window runs for *every* header, so an in-window header must
///    still fall through to the cheap exact DAA/difficulty checks (pre_pow_validation.rs:26-43) and
///    be refused there — never reach the RandomZ hash. If the window were consulted last, an
///    easy-target header claiming an in-window epoch would cost a full 256 MiB setup before refusal.
///
/// Invariants asserted: the reported window is well formed (`low <= high`), it never starts above
/// `epoch(pp)` (else pruning-era/trusted headers are refused), it never ends at or above a maximal
/// forged epoch (else the top of the DAA space is a bypass), and an in-window header with an
/// unmineable target is refused by a DAA/difficulty rule rather than by PoW.
///
/// Fail-when-removed: goes red if an extreme DAA score is admitted (wrapping window), if the low edge
/// rises above `epoch(pp)`, or if an in-window cheap-refusal case degrades into `InvalidPoW` — the
/// latter means the node hashed first and asked questions later, i.e. the DoS the window cannot stop.
#[tokio::test]
async fn i_p4_2o_3_epoch_anchor_survives_extreme_daa_scores_and_still_precedes_pow() {
    // PoW is enforced here (no skip flag): the tripwire bits below can therefore fail only if the
    // header ever reaches the hashing code.
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;
    let pp_epoch = epoch_of(config.genesis.daa_score);

    // (1) The top of the epoch space. A maximal DAA score is a real epoch boundary, so the only thing
    // that can refuse it is the window — and the window must not wrap around it.
    let max_epoch = u64::MAX >> EPOCH_SHIFT;
    let max_daa_score = max_epoch << EPOCH_SHIFT;
    assert_eq!(
        epoch_of(max_daa_score),
        max_epoch,
        "I-P4-2O-3: the maximal DAA score must be a real epoch boundary deriving the maximal epoch, \
         otherwise this test is measuring the epoch derivation instead of the window"
    );

    let mut maximal = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    maximal.header.bits = UNMINEABLE_BITS;
    maximal.header.daa_score = max_daa_score;
    maximal.header.nonce = 0;
    assert!(
        !State::new(&maximal.header).check_pow(maximal.header.nonce).0,
        "I-P4-2O-3: the maximal header must carry no valid PoW, so any pre-PoW refusal proves no RandomZ \
         setup was spent on the highest epoch the type can express"
    );

    let maximal_result = consensus.validate_and_insert_block(maximal.to_immutable()).block_task.await;
    match maximal_result {
        Err(RuleError::ZethoraPowEpochOutOfRange(daa_score, epoch, low, high)) => {
            assert_eq!(daa_score, max_daa_score, "I-P4-2O-3: the refusal must report the forged DAA score");
            assert_eq!(epoch, max_epoch, "I-P4-2O-3: the refusal must report the epoch of the forged DAA score");
            assert!(low <= high, "I-P4-2O-3: the reported window [{low}, {high}] is malformed — the anchor arithmetic wrapped");
            assert!(
                epoch > high,
                "I-P4-2O-3: the maximal epoch {epoch} is inside the reported window [{low}, {high}]; a saturated \
                 high edge turns the top of the DAA space into a bypass of the whole rule"
            );
            assert!(
                high < max_epoch,
                "I-P4-2O-3: the high edge {high} reaches the maximal epoch {max_epoch}; a peer could then mine \
                 in the last epoch forever and replay that cheap work"
            );
            assert!(
                low <= pp_epoch,
                "I-P4-2O-3: the low edge {low} sits above epoch(pp) = {pp_epoch}; pruning-era headers (and \
                 pruning-proof import) would be refused, stalling the node permanently"
            );
        }
        other => panic!(
            "I-P4-2O-3: a header claiming the maximal epoch {max_epoch} must be refused by the epoch window \
             before any RandomZ work (got {other:?})"
        ),
    }

    // (2) Ordering: a header that *is* inside the window must fall through to the cheap exact checks
    // (pre_pow_validation.rs:26-43) and be refused there. With unmineable bits and a wrong DAA score,
    // the only way to reach `InvalidPoW` is to hash first — a full RandomZ setup per submission.
    let mut in_window = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    in_window.header.bits = UNMINEABLE_BITS;
    in_window.header.daa_score = pp_epoch << EPOCH_SHIFT;
    in_window.header.nonce = 0;
    let in_window_result = consensus.validate_and_insert_block(in_window.to_immutable()).block_task.await;
    assert!(
        matches!(in_window_result, Err(RuleError::UnexpectedHeaderDaaScore(..)) | Err(RuleError::UnexpectedDifficulty(..))),
        "I-P4-2O-1: an in-window header with an easy/unmineable target must be refused by the exact DAA or \
         difficulty check before any RandomZ work, got {in_window_result:?}; if this degrades into InvalidPoW, \
         a spammer makes every node pay a 256 MiB setup per submission — the DoS the always-on window cannot stop"
    );

    consensus.shutdown(wait_handles);
}
