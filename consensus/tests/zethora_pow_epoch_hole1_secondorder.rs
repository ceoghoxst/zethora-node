//! Black-hat second-order tests against the `check_pow_epoch_plausible` fail-open patch
//! (`consensus/src/pipeline/header_processor/pre_ghostdag_validation.rs`).
//!
//! The patch split one `let Some(..) else { return Ok(()) }` into two:
//!   1. no pruning point (`pruning_point()` == `None`)  -> `Ok(())`   ("genesis, no window")
//!   2. pruning point set but `get_daa_score(pp)` == `None`
//!                                                      -> `Err(PruningPointHeaderUnavailable(pp))`
//!
//! Ground truth read from the five permitted files:
//!  - `consensus/src/consensus/mod.rs:523-577`: pruning-point advance is one `WriteBatch`, and its
//!    only caller is gated on `get_ghostdag_data` / `get_header(new_pruning_point)` succeeding, so
//!    the batch cannot publish a pruning point whose header is absent. Branch 2 is therefore
//!    structurally unreachable from outside the database layer.
//!  - `header_processor/mod.rs` contains only `mod`/`pub use` declarations; the callers of
//!    `validate_header_in_isolation{,_before_pow}` live in `header_processor/processor.rs`, which is
//!    outside the read set for this task. Caller-fate of the new variant is therefore NOT traced
//!    here (see the "deliberately not tested" note) instead of being guessed.
//!
//! Vectors pinned here:
//!  - I-H1-2O-1: branch 1 is not merely "no window at genesis" — at first boot it is the only
//!    branch that can be taken before the pruning point is readable, and taking it silently
//!    disables the epoch bound. A first-boot node must therefore neither be (a) failed closed nor
//!    (b) left without the window: (b) makes every far-epoch header cost a 256 MiB / ~2 s RandomZ
//!    setup, the exact DoS the bound exists to stop.
//!  - I-H1-2O-2: no attacker-chosen header may synthesize `PruningPointHeaderUnavailable`. If it
//!    can, the fail-closed branch is reachable from wire data and any caller that treats a
//!    structural error as fatal (abort / quarantine / "peer lied") stalls or blames honest peers.
//!  - I-H1-2O-3: the new variant's `#[error]` string must stay triage-safe: it must identify the
//!    pruning point it could not read and stay distinguishable from `PruningViolation` and
//!    `ZethoraPowEpochOutOfRange`, or a database-corruption event is silently merged with a normal
//!    validation rejection in logs and alerts.
//!
//! Deliberately NOT tested (unreachable / out of scope, not fabricated):
//!  - branch 2 itself: needs `pruning_point_store` written without `headers_store`, i.e. internal
//!    `pub(crate)` store state that no `ConsensusApi`/`TestConsensus` call can create.
//!  - `trusted == true` (pruning-proof / trusted-sync headers): its caller lives in
//!    `header_processor/processor.rs`, outside the allowed read set, so its error handling is not
//!    assumed here.
//!
//! Run with:
//! `cargo test -p kaspa-consensus --test zethora_pow_epoch_hole1_secondorder -j 4 -- --nocapture`

use kaspa_consensus::{config::ConfigBuilder, consensus::test_consensus::TestConsensus, params::DEVNET_PARAMS};
use kaspa_consensus_core::{api::ConsensusApi, block::Block, errors::block::RuleError, header::Header};
use kaspa_hashes::Hash;
use kaspa_pow::randomz::{epoch_of, EPOCH_LENGTH, EPOCH_SHIFT};

/// Compact form of target 1: the hardest target the header format can express and one no nonce
/// meets. A header carrying it cannot have valid PoW, so any error *other* than `InvalidPoW`
/// proves the node refused it without spending RandomZ work.
const UNMINEABLE_BITS: u32 = 0x0300_0001;

/// I-H1-2O-1 — first boot must neither be failed closed nor lose the epoch window.
///
/// Fail-when-removed: goes red if a first-boot node answers `PruningPointHeaderUnavailable` for
/// ordinary headers (a fail-closed fix that stalls first sync), or if the pruning-point anchor is
/// absent/unreadable at first boot so a far-epoch header reaches the PoW stage (the epoch bound is
/// bypassed and each forged epoch buys a fresh 256 MiB RandomZ setup).
#[tokio::test]
async fn i_h1_2o_1_first_boot_is_not_failed_closed_and_keeps_the_epoch_window() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;
    let genesis_epoch = epoch_of(config.genesis.daa_score);

    // (a) A header in the genesis epoch is never refused by the epoch bound and never produces the
    //     structural variant. Unmineable bits keep PoW out of the comparison.
    let mut in_window = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
    in_window.header.bits = UNMINEABLE_BITS;
    // Pin the DAA score to the anchor's own, so the control cannot straddle an epoch boundary.
    in_window.header.daa_score = config.genesis.daa_score;
    assert_eq!(
        epoch_of(in_window.header.daa_score),
        genesis_epoch,
        "I-H1-2O-1: the control header must sit in the genesis epoch, otherwise this test proves nothing"
    );
    let result = consensus.validate_and_insert_block(in_window.to_immutable()).block_task.await;
    assert!(
        !matches!(result, Err(RuleError::PruningPointHeaderUnavailable(..))),
        "I-H1-2O-1: first boot must not fail closed — an in-window header produced the \
         database-corruption error, which would stall first sync. Got: {result:?}"
    );
    assert!(
        !matches!(result, Err(RuleError::ZethoraPowEpochOutOfRange(..))),
        "I-H1-2O-1: the first-boot window must not exclude the genesis epoch itself, otherwise \
         first boot rejects its own chain. Got: {result:?}"
    );
    assert!(
        matches!(result, Ok(_) | Err(RuleError::InvalidPoW) | Err(RuleError::UnexpectedDifficulty(..))),
        "I-H1-2O-1: an in-window first-boot header must be stopped BEFORE RandomZ setup. \
         Any pre-PoW rejection (UnexpectedDifficulty, ZethoraPowEpochOutOfRange, MissingParents) \
         or acceptance is acceptable; only post-RandomZ InvalidPoW or a stored header would be a finding. Got: {result:?}"
    );

    // (b) Two epochs past the genesis anchor is outside any honest window. If the
    //     `pruning_point() == None` branch is taken at first boot this becomes `InvalidPoW`, i.e.
    //     the node paid the RandomZ setup for a forged epoch — the DoS the bound prevents.
    let far_epoch = genesis_epoch + 2;
    let mut far = consensus.build_header_only_block_with_parents(2.into(), vec![genesis]);
    far.header.bits = UNMINEABLE_BITS;
    far.header.daa_score = far_epoch * EPOCH_LENGTH;
    assert_eq!(
        epoch_of(far.header.daa_score),
        far_epoch,
        "I-H1-2O-1: the forged header must really claim epoch {far_epoch}"
    );
    let result = consensus.validate_and_insert_block(far.to_immutable()).block_task.await;
    assert!(
        !matches!(result, Err(RuleError::PruningPointHeaderUnavailable(..))),
        "I-H1-2O-1: attacker-chosen DAA scores must not produce the corruption-only variant. \
         Got: {result:?}"
    );
    assert!(
        matches!(result, Err(RuleError::ZethoraPowEpochOutOfRange(..))),
        "I-H1-2O-1: at first boot the epoch window must be anchored on a readable pruning-point \
         DAA score, so a header in epoch {far_epoch} is refused BEFORE any RandomZ work. Seeing \
         `InvalidPoW` here means the `pruning_point() == None` branch returned Ok(()) and the window \
         was skipped: every forged epoch then costs a 256 MiB setup and first boot is DoS-able. \
         Got: {result:?}"
    );

    // A refused first-boot header must not be stored, so it cannot be revived after sync.
    for hash in [1u64, 2] {
        assert_eq!(
            consensus.get_block_status(Hash::from(hash)),
            None,
            "I-H1-2O-1: a header refused pre-PoW at first boot must not be stored (hash {hash})"
        );
    }

    consensus.shutdown(wait_handles);
}

/// I-H1-2O-2 — network data must never synthesize `PruningPointHeaderUnavailable`.
///
/// Fail-when-removed: goes red if any attacker-shaped header (far future, far past, huge DAA
/// score, orphan) makes the node report the pruning point's DAA score as unreadable. That would
/// make the fail-closed branch reachable from the wire, and any caller treating a structural
/// `RuleError` as fatal (abort / sync stall / peer ban) could then be triggered at will.
#[tokio::test]
async fn i_h1_2o_2_no_header_class_synthesizes_pruning_point_header_unavailable() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let genesis = config.genesis.hash;
    let genesis_epoch = epoch_of(config.genesis.daa_score);

    // A template header, used only for version/timestamp on the orphan variants.
    let template = consensus.build_header_only_block_with_parents(10.into(), vec![genesis]);
    let (version, timestamp) = (template.header.version, template.header.timestamp);

    // Known parent, far-future DAA score.
    let mut far = consensus.build_header_only_block_with_parents(11.into(), vec![genesis]);
    far.header.bits = UNMINEABLE_BITS;
    far.header.daa_score = (genesis_epoch + 5) * EPOCH_LENGTH;

    // Known parent, the largest DAA score a u64 header field can express.
    let mut huge = consensus.build_header_only_block_with_parents(12.into(), vec![genesis]);
    huge.header.bits = UNMINEABLE_BITS;
    huge.header.daa_score = u64::MAX;

    // Unknown parent, far-future DAA score (the "node is behind, sync" shape).
    let mut far_orphan = Header::from_precomputed_hash(13.into(), vec![99.into()]);
    far_orphan.version = version;
    far_orphan.timestamp = timestamp;
    far_orphan.bits = UNMINEABLE_BITS;
    far_orphan.daa_score = (genesis_epoch + 5) * EPOCH_LENGTH;

    // Unknown parent, oldest epoch an attacker can pick.
    let mut past_orphan = Header::from_precomputed_hash(14.into(), vec![98.into()]);
    past_orphan.version = version;
    past_orphan.timestamp = timestamp;
    past_orphan.bits = UNMINEABLE_BITS;
    past_orphan.daa_score = genesis_epoch.saturating_sub(3) << EPOCH_SHIFT;

    let cases: [(&str, Block, u64); 4] = [
        ("far-future known parent", far.to_immutable(), 11),
        ("u64::MAX DAA score", huge.to_immutable(), 12),
        ("far-future orphan", Block::from_header(far_orphan), 13),
        ("old-epoch orphan", Block::from_header(past_orphan), 14),
    ];

    for (vector, block, hash) in cases {
        let result = consensus.validate_and_insert_block(block).block_task.await;
        assert!(
            !matches!(result, Err(RuleError::PruningPointHeaderUnavailable(..))),
            "I-H1-2O-2: header class [{vector}] (hash {hash}) made the node report the pruning \
             point's DAA score as unreadable. The fail-closed branch would then be reachable from \
             the wire: a caller treating it as a structural/fatal error would abort or stall sync \
             and could be driven by any peer. Got: {result:?}"
        );
        assert_eq!(
            consensus.get_block_status(Hash::from(hash)),
            None,
            "I-H1-2O-2: header class [{vector}] must not be stored after being refused pre-PoW"
        );
    }

    consensus.shutdown(wait_handles);
}

/// I-H1-2O-3 — the new variant's display must stay triage-safe and distinguishable.
///
/// Fail-when-removed: goes red if the message stops naming the pruning point it could not read
/// (operators/log assertions cannot locate the corrupted key), or if it collapses into the wording
/// of a normal validation rejection (`PruningViolation`, `ZethoraPowEpochOutOfRange`), hiding a
/// database-level inconsistency inside ordinary "bad block" noise.
#[test]
fn i_h1_2o_3_new_variant_display_identifies_the_pruning_point_and_stays_distinct() {
    let pp = Hash::from(0xABCD_1234u64);
    let unreadable = RuleError::PruningPointHeaderUnavailable(pp).to_string();

    // Invariant: the message identifies the offending pruning point (the only datum an operator
    // needs to inspect the database) and names the missing DAA score rather than the block.
    let pp_text = pp.to_string();
    assert!(
        unreadable.contains(&pp_text),
        "I-H1-2O-3: `PruningPointHeaderUnavailable` must name the pruning point {pp_text} whose \
         DAA score could not be read, otherwise the corrupted key is untraceable from logs. \
         Message: {unreadable:?}"
    );
    assert!(
        unreadable.to_ascii_lowercase().contains("daa"),
        "I-H1-2O-3: the message must say which datum is missing (the DAA score), otherwise it is \
         indistinguishable from a generic storage failure. Message: {unreadable:?}"
    );

    // Invariant: distinguishable from neighbouring rejections sharing the same hash argument, so
    // alerting on "pruning point" does not merge corruption with normal validation.
    assert_ne!(
        unreadable,
        RuleError::PruningViolation(pp).to_string(),
        "I-H1-2O-3: `PruningPointHeaderUnavailable` must not render identically to \
         `PruningViolation` — corruption must not look like a routine bad block"
    );
    assert_ne!(
        unreadable,
        RuleError::InvalidPoW.to_string(),
        "I-H1-2O-3: the structural variant must not render as a PoW rejection"
    );
    assert_ne!(
        unreadable,
        RuleError::ZethoraPowEpochOutOfRange(0, 0, 0, 0).to_string(),
        "I-H1-2O-3: the structural variant must not render as an epoch-window rejection"
    );

    // Invariant: the epoch-window message keeps exposing its parameters, so pre-PoW triage and any
    // test keying on the window bounds do not silently lose them.
    let window = RuleError::ZethoraPowEpochOutOfRange(123, 456, 400, 500).to_string();
    for needle in ["123", "456", "400", "500"] {
        assert!(
            window.contains(needle),
            "I-H1-2O-3: `ZethoraPowEpochOutOfRange` must still expose its parameters (missing \
             {needle}); losing them would break pre-PoW triage of the epoch bound. Message: {window:?}"
        );
    }
}
