//! Seam review P3-2 and pack 1 #8: a pruning-point private state import must leave the stores holding exactly the new
//! pruning point's state, whatever an earlier (interrupted, or other pruning point's) import left behind.

use crate::{
    config::ConfigBuilder,
    consensus::test_consensus::TestConsensus,
    model::stores::{
        zethora_anchors::{ANCHORED_FOR_GOOD, AnchorProducer},
        zethora_nullifiers::SPENT_FOR_GOOD,
    },
};
use kaspa_consensus_core::config::params::DEVNET_PARAMS;
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use std::collections::BTreeMap;

fn tags(tc: &TestConsensus) -> BTreeMap<[u8; 32], Vec<Hash>> {
    tc.storage.zethora_nullifiers_store.iter_all().map(|r| r.unwrap()).collect()
}

fn anchors(tc: &TestConsensus) -> BTreeMap<[u8; 32], Vec<AnchorProducer>> {
    tc.storage.zethora_anchors_store.iter_all().map(|r| r.unwrap()).collect()
}

/// `expected` plus what a fresh node already holds (genesis produced the empty coin list snapshot).
fn with<K: Ord + Clone, V: Clone>(base: &BTreeMap<K, V>, expected: impl IntoIterator<Item = (K, V)>) -> BTreeMap<K, V> {
    let mut all = base.clone();
    all.extend(expected);
    all
}

fn for_good(blue_score: u64) -> Vec<AnchorProducer> {
    vec![AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score }]
}

/// One live block's own records (not for good) that every import must keep.
fn add_live_block_records(tc: &TestConsensus, block: Hash) {
    let mut batch = rocksdb::WriteBatch::default();
    tc.storage.zethora_nullifiers_store.add_batch(&mut batch, block, &[[0x55; 32]]).unwrap();
    tc.storage.zethora_anchors_store.add_batch(&mut batch, block, 70, &[0x66; 32]).unwrap();
    tc.db.write(batch).unwrap();
}

#[tokio::test]
async fn a_new_private_state_import_leaves_nothing_of_an_earlier_one() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let live = Hash::from(77);
    let tree = zethora_shielded::NoteCommitmentTree::new();
    let (base_tags, base_anchors) = (tags(&tc), anchors(&tc));
    assert!(base_tags.is_empty());
    add_live_block_records(&tc, live);

    // Import for pruning point A
    tc.virtual_processor.store_zethora_private_state(Hash::from(1), &tree, MuHash::new(), &[[1; 32], [2; 32]], &[([9; 32], 5)]);
    // Positive control: A's state is there, next to the live block's records
    assert_eq!(
        tags(&tc),
        BTreeMap::from([([1; 32], vec![SPENT_FOR_GOOD]), ([2; 32], vec![SPENT_FOR_GOOD]), ([0x55; 32], vec![live])])
    );
    assert_eq!(
        anchors(&tc),
        with(&base_anchors, [([9; 32], for_good(5)), ([0x66; 32], vec![AnchorProducer { block: live, blue_score: 70 }])])
    );

    // An interrupted import for another pruning point wrote one more tag before stopping
    let mut batch = rocksdb::WriteBatch::default();
    tc.storage.zethora_nullifiers_store.add_spent_for_good_batch(&mut batch, &[3; 32]).unwrap();
    tc.db.write(batch).unwrap();

    // Import for pruning point B (shares tag 2 with A): exactly B's state remains, plus the live block's records
    tc.virtual_processor.store_zethora_private_state(Hash::from(2), &tree, MuHash::new(), &[[2; 32], [4; 32]], &[([8; 32], 6)]);
    assert_eq!(
        tags(&tc),
        BTreeMap::from([([2; 32], vec![SPENT_FOR_GOOD]), ([4; 32], vec![SPENT_FOR_GOOD]), ([0x55; 32], vec![live])])
    );
    assert_eq!(
        anchors(&tc),
        with(&base_anchors, [([8; 32], for_good(6)), ([0x66; 32], vec![AnchorProducer { block: live, blue_score: 70 }])])
    );

    tc.shutdown(handles);
}

#[tokio::test]
async fn an_unfinished_import_is_cleared_at_startup_and_by_every_utxo_set_clear() {
    use kaspa_consensus_core::api::ConsensusApi;
    let config = ConfigBuilder::new(DEVNET_PARAMS).build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let live = Hash::from(77);
    let tree = zethora_shielded::NoteCommitmentTree::new();
    let base_anchors = anchors(&tc);
    add_live_block_records(&tc, live);
    let live_tags = BTreeMap::from([([0x55; 32], vec![live])]);
    let live_anchors = with(&base_anchors, [([0x66; 32], vec![AnchorProducer { block: live, blue_score: 70 }])]);

    // Positive control: with a stable UTXO set, the startup check leaves the imported state alone
    tc.virtual_processor.store_zethora_private_state(Hash::from(1), &tree, MuHash::new(), &[[1; 32]], &[([9; 32], 5)]);
    assert!(tc.pruning_meta_stores.read().pruning_utxoset_stable_flag());
    tc.zethora_clear_unfinished_private_state_import();
    assert_eq!(tags(&tc).len(), 2);
    assert_eq!(anchors(&tc), with(&live_anchors, [([9; 32], for_good(5))]));

    // A node stopped in the middle of a state sync restarts with the flag down: the startup check clears the import
    tc.set_pruning_utxoset_stable_flag(false);
    tc.zethora_clear_unfinished_private_state_import();
    assert_eq!(tags(&tc), live_tags);
    assert_eq!(anchors(&tc), live_anchors);

    // Every state sync starts by clearing the pruning point UTXO set, which clears the private state with it
    tc.set_pruning_utxoset_stable_flag(true);
    tc.virtual_processor.store_zethora_private_state(Hash::from(1), &tree, MuHash::new(), &[[1; 32]], &[([9; 32], 5)]);
    tc.clear_pruning_utxo_set();
    assert_eq!(tags(&tc), live_tags);
    assert_eq!(anchors(&tc), live_anchors);

    tc.shutdown(handles);
}

/// Seam review P3-3: the physical limits on a downloaded private state, exactly.
#[test]
fn private_state_limits_follow_the_chain() {
    use crate::consensus::private_state_limits;
    // 100 chain blocks, mergesets of at most 180 blocks, 500,000 compute mass per block = 33 actions of 15,000
    assert_eq!(private_state_limits(99, 180, 500_000), (100 * 180 * 33, 100));
    // Genesis as the pruning point: one chain block
    assert_eq!(private_state_limits(0, 180, 500_000), (180 * 33, 1));
    // Never overflows
    assert_eq!(private_state_limits(u64::MAX, 180, 500_000), (u64::MAX, u64::MAX));
}
