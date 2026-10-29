// Seam review pack 2 (F3d) proof tests that need a real DAG: P2-7 (anchor depth reference point, boundary) and P2-8
// (the chain-ancestor check counts the selected parent itself). Both were verdict "not a bug"; these tests keep it so.
// CLAUDE.md standing rule: positive control, exact assertions, fail-when-protection-removed (see the PR).

use crate::config::ConfigBuilder;
use crate::consensus::test_consensus::TestConsensus;
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::headers::HeaderStoreReader;
use crate::params::DEVNET_PARAMS;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::constants::TX_VERSION;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::Transaction;
use kaspa_consensus_core::zethora_private::{ACTION_SIZE, PRIVATE_PAYMENT_MAGIC, layout};
use std::collections::HashSet;

const DEPTH: u64 = 10;

/// A transaction carrying a private payment that spends coin tag `nullifier` against snapshot `anchor` (only the fields
/// the in-context rules read are real: they run before, and independently of, the proof check).
fn spend(nullifier: [u8; 32], anchor: [u8; 32]) -> Transaction {
    let mut p = PRIVATE_PAYMENT_MAGIC.to_vec();
    p.push(1); // pool version
    p.extend_from_slice(&1u16.to_le_bytes());
    let mut action = vec![0u8; ACTION_SIZE];
    action[layout::NULLIFIER_OFFSET..layout::NULLIFIER_OFFSET + 32].copy_from_slice(&nullifier);
    p.extend(action);
    p.push(0x01); // flags: spends enabled
    p.extend_from_slice(&0i64.to_le_bytes()); // value balance
    p.extend_from_slice(&anchor);
    Transaction::new(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, p)
}

/// genesis -> b1 -> ... -> b{n}: chain block k has blue score k.
async fn chain(tc: &TestConsensus, n: u64) -> Vec<Hash> {
    let mut blocks = vec![tc.params().genesis.hash];
    for k in 1..=n {
        let h = Hash::from_u64_word(1_000 + k);
        tc.add_empty_utxo_valid_block_with_parents(h, vec![*blocks.last().unwrap()]).await.unwrap();
        assert_eq!(tc.headers_store().get_blue_score(h).unwrap(), k);
        blocks.push(h);
    }
    blocks
}

/// P2-7: a spend's snapshot must be at least anchor_depth blue score below the SELECTED PARENT of the chain block that
/// accepts it (mempool and template use the virtual's selected parent, the merge loop the chain block's). Boundary:
/// depth - 1 no, depth yes, depth + 1 yes; for an on-chain producer and for a pruned ("for good") one.
#[tokio::test]
async fn anchor_depth_boundary_is_measured_from_the_selected_parent() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().edit_consensus_params(|p| p.anchor_depth = DEPTH).build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let b = chain(&tc, DEPTH + 3).await;
    let vp = tc.virtual_processor().clone();

    // Snapshot produced by b2 (blue score 2) on the chain, and one known only "for good" with blue score 2
    let (on_chain_root, for_good_root) = ([0xA1; 32], [0xA2; 32]);
    tc.zethora_insert_anchor(b[2], 2, &on_chain_root);
    tc.zethora_insert_anchor_for_good(&for_good_root, 2);

    for root in [on_chain_root, for_good_root] {
        // Selected parent b11: 11 - 2 = 9 = depth - 1: too young
        assert!(!vp.anchor_matured_on_chain(&root, b[(DEPTH + 1) as usize]));
        // b12: exactly depth: matured; b13: depth + 1: matured
        assert!(vp.anchor_matured_on_chain(&root, b[(DEPTH + 2) as usize]));
        assert!(vp.anchor_matured_on_chain(&root, b[(DEPTH + 3) as usize]));
        // The same answers through the rule the mempool, the template and the merge loop all call
        let tx = spend([0x5E; 32], root);
        let none = HashSet::new();
        assert!(vp.check_private_payment_in_context(&tx, b[(DEPTH + 1) as usize], &none).is_err());
        assert!(vp.check_private_payment_in_context(&tx, b[(DEPTH + 2) as usize], &none).is_ok());
    }
    // An unknown snapshot never counts (positive control for the lookup)
    assert!(!vp.anchor_matured_on_chain(&[0xA3; 32], b[(DEPTH + 3) as usize]));

    tc.shutdown(handles);
}

/// P2-8 (test P2-T5): chain block A accepted a payment spending coin tag N. A block built on A (A is its selected
/// parent) may not spend N again: the chain-ancestor check counts A itself. A block on a sibling chain may (positive
/// control: the tag is only spent on A's chain).
#[tokio::test]
async fn a_tag_spent_by_the_selected_parent_itself_counts_as_spent() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let genesis = tc.params().genesis.hash;
    let (a, sibling) = (Hash::from_u64_word(1), Hash::from_u64_word(2));
    tc.add_empty_utxo_valid_block_with_parents(a, vec![genesis]).await.unwrap();
    tc.add_empty_utxo_valid_block_with_parents(sibling, vec![genesis]).await.unwrap();
    let n = [0x4E; 32];
    tc.zethora_insert_nullifiers(a, &[n]);
    let vp = tc.virtual_processor().clone();

    // Inclusive: A is its own chain ancestor
    assert!(tc.reachability_service().is_chain_ancestor_of(a, a));
    assert!(vp.nullifier_spent_on_chain(&n, a));
    assert!(!vp.nullifier_spent_on_chain(&n, sibling));
    // Through the rule mempool (sink = A), template and merge loop call
    let tx = spend(n, [0; 32]);
    let none = HashSet::new();
    assert!(vp.private_double_spend(&tx, a, &none));
    assert!(!vp.private_double_spend(&tx, sibling, &none));
    match vp.check_private_payment_in_context(&tx, a, &none) {
        Err(kaspa_consensus_core::errors::tx::TxRuleError::InvalidPrivatePayment(msg)) => {
            assert_eq!(msg, "private coin already spent")
        }
        other => panic!("expected 'private coin already spent', got {other:?}"),
    }

    tc.shutdown(handles);
}
