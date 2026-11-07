//! Zethora integration test (real pipeline, no replicas): the node refuses a block whose
//! `direct_parents()[0]` is not the GHOSTDAG selected parent — `RuleError::WrongSelectedParentOrder`,
//! enforced while the virtual processor qualifies a chain block
//! (`pipeline/virtual_processor/utxo_validation.rs:345-349`).
//!
//! Threat (invariant I-G3). `direct_parents()[0]` is what a syncee walks below the pruning point to verify
//! seq-commits, and what seq-commit replay and the turnstile assume is "the" chain. An attacker can mine a
//! block whose parent *set* is honest, but whose first entry is a weaker (lower blue-work) peer. A node that
//! trusted the header would then walk the attacker's branch while a full GHOSTDAG view walks the honest one:
//! one header, two blue scores, paid blocks reorged out.
//!
//! Why this file exists next to `zethora_ghostdag_blackhat.rs`: that suite pins I-G3 with *replicas* of the
//! rule body (it cannot reach a real `UtxoProcessingContext`). This test drives the real `TestConsensus`
//! pipeline end to end — real `GhostdagManager`, real selected-parent selection, real UTXO/virtual
//! processing — so it goes red if the *node* stops enforcing the rule, not merely if a restatement is wrong.
//!
//! Shape of the test. `genesis -> a1 -> a2` is the heavier chain; `side` is a weaker child of genesis. Two
//! blocks with the *same* parent set `{a2, side}` are built from the *same* virtual state by the real block
//! builder: the honest twin in GHOSTDAG order `[a2, side]` and the attack block, which is identical except
//! that level 0 is swapped to `[side, a2]`. The test first asserts the two headers carry the same
//! commitments and the same deeper parent levels (so the order is provably the only difference), then that
//! the attack block is disqualified and never moves the sink, and — in a second, identical run — that the
//! honest twin is accepted and does become the sink.
//!
//! Fail-when-removed: delete the `first_parent != selected_parent` check in `verify_expected_utxo_state`
//! and `a_block_whose_first_parent_is_not_the_selected_parent_is_disqualified` goes red — the attack block
//! becomes `StatusUTXOValid` and the virtual sink follows `direct_parents()[0]` onto the weaker branch.
//!
//! Run with:
//! `cargo test -p kaspa-consensus --test zethora_ghostdag_integration -j 4 -- --nocapture`

use std::collections::HashSet;

use kaspa_consensus::{config::ConfigBuilder, consensus::test_consensus::TestConsensus, params::DEVNET_PARAMS};
// `validate_and_insert_block`, `get_sink` and `get_block_status` are `ConsensusApi` methods (reached through
// `Deref<Target = Arc<Consensus>>`), so the trait must be in scope.
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::block::MutableBlock;
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_hashes::Hash;

/// Hash labels for the blocks this test submits. Everything else about them (commitments, scores, bits,
/// timestamps) is produced by the real block builder, never by hand.
const CHAIN_1: u64 = 0xa1;
const CHAIN_2: u64 = 0xa2;
const SIDE: u64 = 0xb0;
const HONEST_TWIN: u64 = 0x0c;
const ATTACK: u64 = 0xbad;
const HONEST_CHILD: u64 = 0xc1;

/// Empty pay-to-nothing script: these blocks carry no payments, so the test never depends on reward values.
fn miner_data() -> MinerData {
    MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![])
}

/// Unwraps the status of an inserted block, panicking with the rule error if the pipeline refused the block
/// outright. A chain disqualification is *not* reported as `Err` (see `calculate_utxo_state_relatively`), so
/// an `Err` here would mean the block never reached the virtual processor at all — a different failure than
/// the one under test, and it must be surfaced as such.
fn expect_accepted<E: std::fmt::Debug>(result: Result<BlockStatus, E>, what: &str) -> BlockStatus {
    match result {
        Ok(status) => status,
        Err(err) => panic!("{what} was refused before virtual processing: {err:?}"),
    }
}


/// Builds the DAG the attack needs, on the real pipeline:
///
/// ```text
/// genesis -- a1 -- a2   (heavier chain: a2 is the tip with the most blue work)
///         \-- side      (weaker branch, merged into the virtual state)
/// ```
///
/// Returns `(a2, side)` — the two tips a third block can name, in either order.
async fn build_forked_dag(tc: &TestConsensus) -> (Hash, Hash) {
    let genesis = tc.params().genesis.hash;
    let a1 = Hash::from_u64_word(CHAIN_1);
    let a2 = Hash::from_u64_word(CHAIN_2);
    let side = Hash::from_u64_word(SIDE);

    // The heavier chain: every block must actually qualify for the virtual chain.
    for (hash, parents) in [(a1, vec![genesis]), (a2, vec![a1])] {
        let status = expect_accepted(tc.add_empty_utxo_valid_block_with_parents(hash, parents).await, "a chain block");
        assert_eq!(status, BlockStatus::StatusUTXOValid, "a block on the selected chain must qualify for the chain");
    }

    // The weaker branch: accepted, but with less blue work than a2 so it never takes the sink.
    expect_accepted(tc.add_empty_utxo_valid_block_with_parents(side, vec![genesis]).await, "the side block");

    assert_eq!(
        tc.get_sink(),
        a2,
        "premise: the two-block chain must be the virtual sink, i.e. its tip carries more blue work than side"
    );
    (a2, side)
}


/// Builds the honest twin and the attack block from the same virtual state, and asserts that parent order is
/// their only difference. Returns `(honest, attack)`.
fn build_twin_blocks(tc: &TestConsensus, a2: Hash, side: Hash) -> (MutableBlock, MutableBlock) {
    // `build_block_template_from_virtual_state` asserts that the selected parent is `parents[0]`
    // (processor.rs:1644/1646), so `[a2, side]` is the GHOSTDAG order: `a2` is the heavier of the two.
    let honest =
        tc.build_utxo_valid_block_with_parents(Hash::from_u64_word(HONEST_TWIN), vec![a2, side], miner_data(), vec![]);
    let mut attack = tc.build_utxo_valid_block_with_parents(Hash::from_u64_word(ATTACK), vec![a2, side], miner_data(), vec![]);

    // The attack: swap level 0 only. `set_direct_parents` keeps every deeper level untouched.
    attack.header.parents_by_level.set_direct_parents(vec![side, a2]);
    // A real attacker's header hash commits to the order they chose, so re-finalize instead of keeping the
    // precomputed label.
    attack.header.finalize();

    assert_eq!(honest.header.direct_parents(), &[a2, side][..], "the honest twin must name the selected parent first");
    assert_eq!(attack.header.direct_parents(), &[side, a2][..], "the attack block must name the weaker peer first");
    assert_eq!(
        honest.header.direct_parents().iter().copied().collect::<HashSet<_>>(),
        attack.header.direct_parents().iter().copied().collect::<HashSet<_>>(),
        "both blocks must name the same parent set — otherwise a set-based parent/incest check, not the order rule, could be what rejects the attack"
    );
    assert_eq!(
        honest.header.parents_by_level.expanded_iter().skip(1).collect::<Vec<_>>(),
        attack.header.parents_by_level.expanded_iter().skip(1).collect::<Vec<_>>(),
        "only level 0 may differ: every deeper parent level must match the honest twin exactly"
    );
    assert_eq!(
        attack.header.utxo_commitment, honest.header.utxo_commitment,
        "the attack must carry the honest UTXO commitment, otherwise it would be rejected for the commitment rather than for the parent order"
    );
    assert_eq!(
        attack.header.accepted_id_merkle_root, honest.header.accepted_id_merkle_root,
        "the attack must carry the honest seq-commit (accepted-id merkle root), otherwise it would be rejected for that instead"
    );
    assert_eq!(attack.header.hash_merkle_root, honest.header.hash_merkle_root, "the transaction sets must be identical");
    assert_eq!(attack.header.blue_work, honest.header.blue_work, "blue work depends on the parent set, not on its order");
    assert_eq!(attack.header.blue_score, honest.header.blue_score, "blue score depends on the parent set, not on its order");
    assert_eq!(attack.header.daa_score, honest.header.daa_score, "the DAA score depends on the parent set, not on its order");
    assert_eq!(attack.header.pruning_point, honest.header.pruning_point, "the claimed pruning point must match the honest twin");
    assert_ne!(attack.header.hash, honest.header.hash, "the two blocks must be distinct blocks");

    (honest, attack)
}


/// I-G3: a block that names a weaker peer as `direct_parents()[0]` — with an otherwise perfect header — is
/// disqualified from the virtual chain and never takes the sink, while the honest chain keeps progressing
/// from the very selected parent the attack named second.
#[tokio::test]
async fn a_block_whose_first_parent_is_not_the_selected_parent_is_disqualified() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();

    let (a2, side) = build_forked_dag(&tc).await;
    let (_honest, attack) = build_twin_blocks(&tc, a2, side);
    let attack_hash = attack.header.hash;

    // --- the attack ---
    let status =
        expect_accepted(tc.validate_and_insert_block(attack.to_immutable()).virtual_state_task.await, "the swapped-first-parent block");
    assert_eq!(
        status,
        BlockStatus::StatusDisqualifiedFromChain,
        "I-G3: a block whose direct_parents()[0] is not the GHOSTDAG selected parent must be disqualified from the chain"
    );
    assert_eq!(
        tc.get_block_status(attack_hash),
        Some(BlockStatus::StatusDisqualifiedFromChain),
        "the disqualification must be recorded, or every later sink search would re-qualify the block"
    );
    assert_eq!(
        tc.get_sink(),
        a2,
        "the attack must not move the sink — following direct_parents()[0] would hand the chain to the weaker branch"
    );

    // The chain keeps building on the honest selected parent, the one the attack listed *second*.
    let child = Hash::from_u64_word(HONEST_CHILD);
    let child_status =
        expect_accepted(tc.add_empty_utxo_valid_block_with_parents(child, vec![a2]).await, "the honest block after the attack");
    assert_eq!(child_status, BlockStatus::StatusUTXOValid, "the honest chain must still be able to extend a2 after the attack");
    assert_eq!(
        tc.get_sink(),
        child,
        "the virtual chain must continue on the honest branch, even though the disqualified block carries more blue work"
    );
    assert_eq!(
        tc.get_block_status(attack_hash),
        Some(BlockStatus::StatusDisqualifiedFromChain),
        "the attack must stay disqualified after the chain moved on"
    );

    tc.shutdown(handles);
}

/// Positive control: the *same* parent set in GHOSTDAG order (selected parent first) is accepted and becomes
/// the sink. Without this, the disqualification above could be blamed on anything in the twin block — this
/// control proves the only thing the node objects to is the order of `direct_parents()`.
#[tokio::test]
async fn the_same_block_is_accepted_when_the_first_parent_is_the_selected_parent() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();

    let (a2, side) = build_forked_dag(&tc).await;
    let (honest, _attack) = build_twin_blocks(&tc, a2, side);
    let honest_hash = honest.header.hash;

    let status = expect_accepted(tc.validate_and_insert_block(honest.to_immutable()).virtual_state_task.await, "the honest twin");
    assert_eq!(
        status,
        BlockStatus::StatusUTXOValid,
        "control: with the GHOSTDAG selected parent listed first, the very same block qualifies for the chain"
    );
    assert_eq!(tc.get_sink(), honest_hash, "control: the honest twin must become the virtual sink");

    tc.shutdown(handles);
}
