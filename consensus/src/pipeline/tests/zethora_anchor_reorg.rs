// Zethora: anchor reorg regression test (ZTH-SPEC-006 §6.2, Appendix C item 2).
//
// anchor_matured_on_chain (utxo_validation.rs) rejects an anchor whose
// producing block is not on the selected chain of the tip:
//
//     producers.any(|p|
//         p.blue_score + ANCHOR_DEPTH <= tip_blue_score
//         && (p.block == ANCHORED_FOR_GOOD
//             || try_is_chain_ancestor_of(p.block, tip)))
//
// The reorg case is: producer was on-chain, then got disconnected. In that
// state try_is_chain_ancestor_of returns false, so anchor_matured_on_chain
// returns false, and the spend is rejected. That transition is what this
// test proves. Appendix C item 2 of ZTH-SPEC-006 marks it untested.
//
// Not covered here:
//   - The full end-to-end path (real Orchard anchor + spend + reorg) —
//     requires 601 blocks of anchor-maturity setup and ~200 s of Orchard
//     proof time. Tracked as Appendix C item 1.
//   - ANCHORED_FOR_GOOD (pruned producers) — pruning is out of scope; the
//     pruning processor's rewrite is orthogonal to reorg.

use crate::config::ConfigBuilder;
use crate::consensus::test_consensus::TestConsensus;
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::headers::HeaderStoreReader;
use crate::params::DEVNET_PARAMS;
use kaspa_consensus_core::Hash;

#[tokio::test]
async fn reorg_disconnects_anchor_producer_from_selected_chain() {
    // skip_proof_of_work: five empty blocks, no need to burn CPU on PoW.
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let tc = TestConsensus::new(&config);
    let tc_handles = tc.init();

    let genesis = tc.params().genesis.hash;

    // --- b-chain: genesis -> b1 -> b2 ---
    // b1 is the hypothetical anchor producer. Before reorg it is on b2's
    // selected chain — the state anchor_matured_on_chain expects when it
    // accepts a spend.
    let b1 = Hash::from_bytes([0xB1; 32]);
    let b2 = Hash::from_bytes([0xB2; 32]);

    tc.add_empty_utxo_valid_block_with_parents(b1, vec![genesis])
        .await
        .expect("b1 must be accepted");
    tc.add_empty_utxo_valid_block_with_parents(b2, vec![b1])
        .await
        .expect("b2 must be accepted");

    let before = tc
        .reachability_service()
        .try_is_chain_ancestor_of(b1, b2)
        .expect("reachability must be available for b1 -> b2");
    assert!(
        before,
        "b1 must be on b2's selected chain before reorg. \
         anchor_matured_on_chain depends on this; if it is false here, \
         the reachability query itself is broken."
    );

    // --- c-chain: genesis -> c1 -> c2 -> c3 ---
    // One block longer than b-chain, so c3 becomes the new selected tip and
    // the reorg disconnects b1 and b2 from the selected chain.
    let c1 = Hash::from_bytes([0xC1; 32]);
    let c2 = Hash::from_bytes([0xC2; 32]);
    let c3 = Hash::from_bytes([0xC3; 32]);

    tc.add_empty_utxo_valid_block_with_parents(c1, vec![genesis])
        .await
        .expect("c1 must be accepted");
    tc.add_empty_utxo_valid_block_with_parents(c2, vec![c1])
        .await
        .expect("c2 must be accepted");
    tc.add_empty_utxo_valid_block_with_parents(c3, vec![c2])
        .await
        .expect("c3 must be accepted");

    let after = tc
        .reachability_service()
        .try_is_chain_ancestor_of(b1, c3)
        .expect("reachability must be available for b1 -> c3");
    assert!(
        !after,
        "b1 must NOT be on c3's selected chain after reorg. \
         If this fails, either the reorg did not switch tips, or \
         try_is_chain_ancestor_of has DAG-ancestor semantics (not \
         selected-chain semantics) — either way, anchor_matured_on_chain \
         would incorrectly accept a spend against a stale anchor. This is \
         the exact scenario Appendix C item 2 of ZTH-SPEC-006 flags."
    );

    // Sanity: reorg removes b1 from the selected chain, not from the DAG.
    assert!(
        tc.headers_store().get_header(b1).is_ok(),
        "reorg must remove b1 from the selected chain, not delete it from the DAG"
    );

    tc.shutdown(tc_handles);
}