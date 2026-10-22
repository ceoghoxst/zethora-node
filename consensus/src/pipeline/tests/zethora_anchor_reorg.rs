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
// The rule the test protects: "on the selected chain of" — not "in the DAG
// past of". try_is_chain_ancestor_of must return false for a block that is
// in the tip's DAG past but not on its selected chain.
//
// Test setup (after strengthening):
//   - b-chain: genesis -> b1 -> b2
//   - c-chain: genesis -> c1 -> c2 -> c3, and c3 has TWO parents [c2, b2]
//   - b1 is now in c3's DAG past (via b2), but NOT on c3's selected chain
//   - assert try_is_chain_ancestor_of(b1, b2) == true   (before merge)
//   - assert try_is_chain_ancestor_of(b1, c3) == false  (DAG-ancestor,
//     not selected-chain — this is the exact rule the fix protects)
//
// The old test had c3 with only [c2] as parent, so b1 was NOT in c3's DAG
// past at all. In that version try_is_chain_ancestor_of(b1, c3) returned
// false for the WRONG reason (not an ancestor at all). Adding b2 as a
// second parent of c3 makes the test meaningful: b1 IS in c3's past, and
// the function still correctly returns false because it has selected-chain
// semantics, not DAG-ancestor semantics.

use crate::config::ConfigBuilder;
use crate::consensus::test_consensus::TestConsensus;
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::headers::HeaderStoreReader;
use crate::params::DEVNET_PARAMS;
use kaspa_consensus_core::Hash;

#[tokio::test]
async fn reorg_disconnects_anchor_producer_from_selected_chain() {
    // skip_proof_of_work: eight empty blocks, no need to burn CPU on PoW.
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let tc = TestConsensus::new(&config);
    let tc_handles = tc.init();

    let genesis = tc.params().genesis.hash;

    // --- b-chain: genesis -> b1 -> b2 ---
    let b1 = Hash::from_bytes([0xB1; 32]);
    let b2 = Hash::from_bytes([0xB2; 32]);

    tc.add_empty_utxo_valid_block_with_parents(b1, vec![genesis]).await.expect("b1 must be accepted");
    tc.add_empty_utxo_valid_block_with_parents(b2, vec![b1]).await.expect("b2 must be accepted");

    let before = tc.reachability_service().try_is_chain_ancestor_of(b1, b2).expect("reachability must be available for b1 -> b2");
    assert!(
        before,
        "b1 must be on b2's selected chain before any merge. \
         anchor_matured_on_chain depends on this."
    );

    // --- c-chain: genesis -> c1 -> c2 -> c3, and c3 also has parent b2 ---
    let c1 = Hash::from_bytes([0xC1; 32]);
    let c2 = Hash::from_bytes([0xC2; 32]);
    let c3 = Hash::from_bytes([0xC3; 32]);

    tc.add_empty_utxo_valid_block_with_parents(c1, vec![genesis]).await.expect("c1 must be accepted");
    tc.add_empty_utxo_valid_block_with_parents(c2, vec![c1]).await.expect("c2 must be accepted");
    // THE KEY CHANGE: c3 has parents [c2, b2], merging the b-chain into
    // its DAG past. Without b2 here, b1 is not in c3's past at all and
    // the assertion below would be trivially true.
    tc.add_empty_utxo_valid_block_with_parents(c3, vec![c2, b2]).await.expect("c3 must be accepted");

    let after = tc.reachability_service().try_is_chain_ancestor_of(b1, c3).expect("reachability must be available for b1 -> c3");
    assert!(
        !after,
        "b1 must NOT be on c3's selected chain after the merge. \
         If this fails, try_is_chain_ancestor_of has DAG-ancestor semantics \
         (not selected-chain semantics) — and anchor_matured_on_chain \
         would incorrectly accept a spend against a stale anchor. This is \
         the exact scenario Appendix C item 2 of ZTH-SPEC-006 flags."
    );

    // Sanity: b1 still exists in the DAG (it's a valid side branch).
    assert!(
        tc.headers_store().get_header(b1).is_ok(),
        "reorg/merge must not delete b1 from the DAG, only remove it from the selected chain"
    );

    tc.shutdown(tc_handles);
}
