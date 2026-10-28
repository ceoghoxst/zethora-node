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

// ---------------------------------------------------------------------------
// F2 item 6: the same rule END TO END, with a real coin, a real matured snapshot and a real spend.
//
//   shared chain ... F
//   branch A: F -> S [shield] -> P (accepts it, produces snapshot R) -> 11 blocks (R matures) -> X [spend] -> Y (accepts it)
//   branch B: F -> 16 empty blocks (more blue work than A's 15: the node reorgs to B)
//             -> [the same shield tx] -> producer of R on B -> ... -> [the same spend] -> accepting block
//
// (B's blocks are built on B alone. The node's virtual also merges A's tips; once R matures on B it would re-accept
// A's original spend, which the test checks too.)
//
// After the reorg: the spend is no longer accepted (its snapshot's producer P left the selected chain, so R is unknown
// there), the coin is unspent again, and the pool holds nothing (the shield is not on B). Once B shields the same coin
// and R matures on B, the same spend is accepted again, exactly once, there. A second node that only ever saw the
// shared chain and branch B ends up with the same coin tags, snapshots, fingerprint, coin list and pool balance.
// ---------------------------------------------------------------------------

use super::zethora_parallel_nullifier::{
    Node, SHIELDED, SPEND_FEE, TEST_ANCHOR_DEPTH, note_root, shield_one_coin_on_chain, shielded_balance,
};
use crate::model::stores::virtual_state::VirtualStateStoreReader;
use crate::model::stores::zethora_anchors::ANCHORED_FOR_GOOD;
use crate::model::stores::zethora_nullifiers::SPENT_FOR_GOOD;
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::api::args::TransactionValidationArgs;
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::errors::tx::TxRuleError;
use kaspa_consensus_core::tx::MutableTransaction;
use kaspa_consensus_core::zethora_private::{nullifiers, spend_anchor};
use std::collections::{BTreeSet, HashSet};

/// Inserts an empty block on `parent` without requiring it to become the sink (a side branch may not be, yet).
async fn add_on(node: &mut Node, parent: Hash, txs: Vec<kaspa_consensus_core::tx::Transaction>) -> Hash {
    let hash = node.fresh_hash();
    node.insert(hash, vec![parent], txs).await;
    hash
}

/// Snapshot roots with their (producing block, blue score) records
type AnchorRecords = Vec<([u8; 32], Vec<(Hash, u64)>)>;

/// What a node's private state looks like from the selected chain ending at its sink
#[derive(Debug, PartialEq)]
struct ChainView {
    sink: Hash,
    sink_coinbase_payload: Vec<u8>,
    sink_utxo_commitment: Hash,
    /// Coin tag records that count on this chain (accepted by a chain block of the sink, or for good)
    chain_nullifiers: Vec<([u8; 32], Vec<Hash>)>,
    /// Snapshot records that count on this chain, with their producers' blue scores
    chain_anchors: AnchorRecords,
    virtual_note_root: [u8; 32],
    virtual_private_state: [u8; 32],
    virtual_mergeset_nullifiers: Vec<[u8; 32]>,
}

fn chain_view(node: &Node) -> ChainView {
    let sink = node.tc.get_sink();
    let on_chain = |b: Hash| b == SPENT_FOR_GOOD || node.tc.reachability_service().is_chain_ancestor_of(b, sink);
    let chain_nullifiers = node
        .tc
        .zethora_nullifiers_store()
        .iter_all()
        .map(|r| r.unwrap())
        .map(|(nf, blocks)| (nf, blocks.into_iter().filter(|b| on_chain(*b)).collect::<Vec<_>>()))
        .filter(|(_, blocks)| !blocks.is_empty())
        .collect();
    let chain_anchors = node
        .tc
        .zethora_anchors_store()
        .iter_all()
        .map(|r| r.unwrap())
        .map(|(root, producers)| {
            let producers = producers
                .into_iter()
                .filter(|p| p.block == ANCHORED_FOR_GOOD || on_chain(p.block))
                .map(|p| (p.block, p.blue_score))
                .collect::<Vec<_>>();
            (root, producers)
        })
        .filter(|(_, producers)| !producers.is_empty())
        .collect();
    let stores = node.tc.virtual_stores();
    let read = stores.read();
    let state = read.state.get().unwrap();
    ChainView {
        sink,
        sink_coinbase_payload: node.coinbase_payload(sink),
        sink_utxo_commitment: node.tc.headers_store().get_header(sink).unwrap().utxo_commitment,
        chain_nullifiers,
        chain_anchors,
        virtual_note_root: state.note_root,
        virtual_private_state: state.private_state,
        virtual_mergeset_nullifiers: state.mergeset_nullifiers.clone(),
    }
}

fn mempool(node: &Node, tx: &kaspa_consensus_core::tx::Transaction) -> Result<(), TxRuleError> {
    node.tc.validate_mempool_transaction(&mut MutableTransaction::from_tx(tx.clone()), &TransactionValidationArgs::default())
}

#[tokio::test]
async fn anchor_reorg_end_to_end() {
    let stale_snapshot = Err(TxRuleError::InvalidPrivatePayment(format!(
        "spend uses an unknown or too recent private coin list snapshot (it must be at least {TEST_ANCHOR_DEPTH} blocks deep)"
    )));

    // --- shared chain + branch A: shield, snapshot R matures, spend accepted ---
    let mut f = shield_one_coin_on_chain().await;
    let nf = f.coin.nullifier;
    let built: Vec<Block> = f.node.inserted.lock().unwrap().clone();
    let shield_at = built.iter().position(|b| b.transactions.iter().any(|t| t.id() == f.shield.id())).unwrap();
    let fork = built[shield_at].header.direct_parents()[0];
    let shared: Vec<Block> = built[..shield_at].to_vec();
    assert_eq!(shared.last().unwrap().hash(), fork);
    let producer_a = built[shield_at + 1].hash();

    let spend = f.spend(30_000);
    let anchor = spend_anchor(&spend.payload).unwrap();
    assert_eq!(anchor, note_root(&f.node.coinbase_payload(producer_a)), "the spend uses the snapshot P produced");
    let x = f.node.mine(vec![spend.clone()]).await;
    let y = f.node.mine(vec![]).await;
    // Positive control: accepted once on A, coin tag recorded, pool debited
    assert_eq!(f.node.accepted_count(y, spend.id()), 1);
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![y]);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(y)), SHIELDED - SPEND_FEE);
    let a_len = built.len() - shield_at + 2; // S, P, the maturing blocks, X, Y
    assert_eq!(a_len as u64, 2 + TEST_ANCHOR_DEPTH + 1 + 2);
    let _ = x;

    // --- branch B from the fork point, one block longer than A: the node reorgs to it ---
    let b_from = f.node.inserted.lock().unwrap().len();
    let mut b_tip = fork;
    for _ in 0..=a_len {
        b_tip = add_on(&mut f.node, b_tip, vec![]).await;
    }
    assert_eq!(f.node.tc.get_sink(), b_tip, "the node reorged to branch B");
    assert_eq!(f.node.tc.get_block_status(b_tip), Some(BlockStatus::StatusUTXOValid));
    assert!(!f.node.tc.reachability_service().is_chain_ancestor_of(producer_a, b_tip), "P left the selected chain");

    // The spend is no longer accepted on the new chain: no B block accepted it, its snapshot is unknown there, the coin
    // is unspent there and the pool holds nothing (the shield itself is not on B)
    let vp = f.node.tc.virtual_processor().clone();
    assert_eq!(vp.check_private_payment_in_context(&spend, b_tip, &HashSet::new()), stale_snapshot);
    assert!(!vp.nullifier_spent_on_chain(&nf, b_tip));
    assert!(!vp.anchor_matured_on_chain(&anchor, b_tip));
    assert_eq!(mempool(&f.node, &spend), stale_snapshot);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(b_tip)), 0);
    assert_eq!(note_root(&f.node.coinbase_payload(b_tip)), note_root(&f.node.coinbase_payload(fork)));
    // The stale records stay in the stores but no longer count
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![y]);
    assert_eq!(chain_view(&f.node).chain_nullifiers, vec![]);
    assert!(chain_view(&f.node).chain_anchors.iter().all(|(root, _)| *root != anchor), "R has no producer on B");

    // --- B shields the same coin (its visible input is unspent on B): same coin list, so the same snapshot R ---
    f.node.tip = b_tip;
    f.node.mine(vec![f.shield.clone()]).await;
    let producer_b = f.node.mine(vec![]).await;
    assert_eq!(shielded_balance(&f.node.coinbase_payload(producer_b)), SHIELDED);
    assert_eq!(note_root(&f.node.coinbase_payload(producer_b)), anchor);
    // R is not mature on B yet: one block short of the depth the spend is still refused, at the depth it is accepted
    f.node.mine_empty(TEST_ANCHOR_DEPTH - 1).await;
    assert_eq!(vp.check_private_payment_in_context(&spend, f.node.tip, &HashSet::new()), stale_snapshot);
    assert_eq!(mempool(&f.node, &spend), stale_snapshot);
    f.node.mine(vec![]).await;
    assert_eq!(vp.check_private_payment_in_context(&spend, f.node.tip, &HashSet::new()), Ok(()));
    // Node 1's virtual also merges the old branch A. With R now matured on B, the virtual re-accepts the ORIGINAL spend
    // from A's block X (as for any transaction of a reorged-off block), so the mempool already sees the coin as taken
    let virtual_nullifiers = f.node.tc.virtual_stores().read().state.get().unwrap().mergeset_nullifiers.clone();
    assert!(virtual_nullifiers.contains(&nf));
    assert_eq!(mempool(&f.node, &spend), Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string())));

    // The coin is spendable again, only on B: the same spend is accepted exactly once there
    f.node.mine(vec![spend.clone()]).await;
    let w = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(w, spend.id()), 1);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(w)), SHIELDED - SPEND_FEE);
    assert_eq!(
        f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([y, w])
    );
    assert!(vp.nullifier_spent_on_chain(&nf, w));
    assert_eq!(
        vp.check_private_payment_in_context(&spend, w, &HashSet::new()),
        Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string()))
    );
    let b_blocks: Vec<Block> = f.node.inserted.lock().unwrap()[b_from..].to_vec();
    for b in b_blocks.iter().take_while(|b| b.hash() != w) {
        assert_eq!(f.node.accepted_count(b.hash(), spend.id()), 0, "accepted on B before w");
    }

    // --- a node that never saw branch A ---
    let node2 = Node::new();
    for block in shared.iter().chain(b_blocks.iter()) {
        assert_eq!(node2.insert_block(block.clone()).await, BlockStatus::StatusUTXOValid);
    }
    let (view1, view2) = (chain_view(&f.node), chain_view(&node2));
    assert_eq!(view1.sink, w);
    // On B: the shield's own tags (its actions carry dummy spends) at B's producer, the spend's tags at w
    let mut expected_tags: Vec<([u8; 32], Vec<Hash>)> = nullifiers(&f.shield.payload)
        .into_iter()
        .map(|t| (t, vec![producer_b]))
        .chain(nullifiers(&spend.payload).into_iter().map(|t| (t, vec![w])))
        .collect();
    expected_tags.sort();
    assert!(expected_tags.contains(&(nf, vec![w])));
    assert_eq!(view1.chain_nullifiers, expected_tags);
    assert_eq!(view1.chain_anchors.iter().filter(|(root, _)| *root == anchor).count(), 1);
    assert_eq!(view1.sink_coinbase_payload[56..88], view2.sink_coinbase_payload[56..88], "note root");
    assert_eq!(view1.sink_coinbase_payload[88..120], view2.sink_coinbase_payload[88..120], "fingerprint");
    assert_eq!(shielded_balance(&view2.sink_coinbase_payload), SHIELDED - SPEND_FEE);
    assert_eq!(view1, view2);
    // ...and node 2 holds no stale record at all
    assert_eq!(node2.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![w]);

    drop(vp);
    f.node.shutdown();
    node2.shutdown();
}
