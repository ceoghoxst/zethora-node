// F2 item 7: pruning-point private state import, end to end (ZTH-SPEC-006 §6.4).
//
// Node 1 builds a real chain: a coin is shielded, spent (its coin tag lands on chain), and the spend's own new coins
// get a matured snapshot. P is node 1's tip. Node 2 is a fresh node that, like a node joining by headers proof, has
// every header and only P's body (the trusted-block step), and none of the private records. It is given P's private
// state, exactly as a peer serves it (Consensus::zethora_private_state_at, the function behind
// get_zethora_private_state), through the same import call the IBD flow makes (import_zethora_private_state).
//
//   * tampered copies (one spent coin tag hidden, one invented, one snapshot's age changed) are refused, and leave no
//     trace: every private store of node 2 is exactly as before,
//   * the honest copy is accepted, and node 2 then refuses a spend of the coin already spent before P, while it
//     accepts a spend of an unspent coin against a snapshot it only knows from the import (positive control),
//   * node 1, which saw the whole chain, gives the same answers.
//
// CLAUDE.md standing rule: positive control, exact asserts, fail-when-protection-removed (see the PR).

use super::zethora_parallel_nullifier::{
    Node, SHIELDED, SPEND_FEE, TEST_ANCHOR_DEPTH, note_root, shield_one_coin_on_chain, shielded_balance,
};
use crate::model::stores::zethora_anchors::AnchorProducer;
use crate::model::stores::zethora_note_trees::ZethoraNoteTreesStoreReader;
use crate::model::stores::zethora_nullifiers::SPENT_FOR_GOOD;
use crate::model::stores::zethora_private_states::ZethoraPrivateStatesStoreReader;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::api::{ConsensusApi, ZethoraPrivateState};
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::constants::TX_VERSION;
use kaspa_consensus_core::errors::pruning::PruningImportError;
use kaspa_consensus_core::errors::tx::TxRuleError;
use kaspa_consensus_core::hashing::tx::zethora_private_payment_digest;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::Transaction;
use kaspa_consensus_core::zethora_private::{PRIVATE_PAYMENT_MAGIC, nullifiers, private_payment_bytes, spend_anchor};
use std::collections::{BTreeSet, HashSet};
use zethora_shielded::scan::Scanner;
use zethora_shielded::wallet::PrivateWallet;

/// Everything node 2 stores about private payments (to show a refused import writes nothing)
#[derive(Debug, PartialEq)]
struct PrivateStores {
    nullifiers: Vec<([u8; 32], Vec<Hash>)>,
    anchors: Vec<([u8; 32], Vec<AnchorProducer>)>,
    note_tree_at_p: Option<[u8; 32]>,
    fingerprint_at_p: Option<[u8; 32]>,
}

fn private_stores(node: &Node, p: Hash) -> PrivateStores {
    PrivateStores {
        nullifiers: node.tc.zethora_nullifiers_store().iter_all().map(|r| r.unwrap()).collect(),
        anchors: node.tc.zethora_anchors_store().iter_all().map(|r| r.unwrap()).collect(),
        note_tree_at_p: node.tc.zethora_note_trees_store().get(p).ok().map(|t| t.root().to_bytes()),
        fingerprint_at_p: node.tc.zethora_private_states_store().get(p).ok().map(|mut m| m.finalize().as_bytes()),
    }
}

/// The import must fail with exactly this reason, for pruning point `p`
fn assert_refused(result: Result<(), PruningImportError>, p: Hash, reason: &str) {
    match result {
        Err(PruningImportError::ZethoraPrivateStateMismatch(hash, why)) => {
            assert_eq!(hash, p);
            assert_eq!(why, reason);
        }
        other => panic!("expected ZethoraPrivateStateMismatch({p}, {reason:?}), got {other:?}"),
    }
}

#[tokio::test]
async fn pruning_point_private_state_import_end_to_end() {
    let stale_snapshot = Err(TxRuleError::InvalidPrivatePayment(format!(
        "spend uses an unknown or too recent private coin list snapshot (it must be at least {TEST_ANCHOR_DEPTH} blocks deep)"
    )));
    let already_spent = Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string()));

    // --- node 1: shield, spend (coin tag on chain), then let the spend's own coins get a matured snapshot ---
    let mut f = shield_one_coin_on_chain().await;
    let spend = f.spend(30_000);
    let nf = f.coin.nullifier;
    f.node.mine(vec![spend.clone()]).await;
    let accepting = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(accepting, spend.id()), 1);
    f.node.mine_empty(TEST_ANCHOR_DEPTH).await;
    let p = f.node.tip;
    assert_eq!(shielded_balance(&f.node.coinbase_payload(p)), SHIELDED - SPEND_FEE);

    // A spend of the change coin (19,000 zets, unspent) against the snapshot `accepting` produced
    let wallets = vec![PrivateWallet::from_seed(&[5; 32]), PrivateWallet::friend_of(&[5; 32])];
    let me = wallets[0].address();
    let mut scanner = Scanner::new(wallets);
    scanner.add_payment(private_payment_bytes(&f.shield.payload).unwrap()).unwrap();
    scanner.add_payment(private_payment_bytes(&spend.payload).unwrap()).unwrap();
    scanner.checkpoint().unwrap();
    assert_eq!(scanner.root(), note_root(&f.node.coinbase_payload(accepting)));
    let change = scanner.pick_coins(0, 1).unwrap();
    assert_eq!(change.iter().map(|c| c.value()).collect::<Vec<_>>(), vec![SHIELDED - SPEND_FEE - 30_000]);
    let mut unspent = Transaction::new_non_finalized(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let digest = zethora_private_payment_digest(&unspent);
    let payment = scanner.spend_payment(0, &change, &[(me, change[0].value() - SPEND_FEE)], &digest.as_bytes()).unwrap();
    unspent.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
    unspent.finalize();
    let unspent = f.node.mempool_checked(unspent);
    assert_eq!(spend_anchor(&unspent.payload), Some(note_root(&f.node.coinbase_payload(accepting))));

    // Node 1's answers on top of P
    let vp1 = f.node.tc.virtual_processor().clone();
    assert_eq!(vp1.check_private_payment_in_context(&spend, p, &HashSet::new()), already_spent);
    assert_eq!(vp1.check_private_payment_in_context(&unspent, p, &HashSet::new()), Ok(()));

    // What a peer serves for P
    let honest: ZethoraPrivateState = f.node.tc.zethora_private_state_at(p);
    // Every action's tag counts, also the shield's (its actions carry dummy spends)
    let expected_spent: BTreeSet<[u8; 32]> = nullifiers(&f.shield.payload).into_iter().chain(nullifiers(&spend.payload)).collect();
    assert_eq!(expected_spent.len(), 4);
    assert_eq!(honest.spent.iter().copied().collect::<BTreeSet<_>>(), expected_spent);
    assert!(honest.spent.contains(&nf));
    let r2 = note_root(&f.node.coinbase_payload(accepting));
    let r2_age = f.node.tc.get_header(accepting).unwrap().blue_score;
    assert!(honest.anchors.contains(&(r2, r2_age)));

    // --- node 2: every header, P's body only, no private records ---
    let node2 = Node::new();
    let chain: Vec<Block> = f.node.inserted.lock().unwrap().clone();
    for block in &chain {
        let status =
            node2.tc.validate_and_insert_block(Block::from_header_arc(block.header.clone())).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusHeaderOnly);
    }
    let p_body = chain.iter().find(|b| b.hash() == p).unwrap().transactions.as_ref().clone();
    node2.tc.zethora_insert_block_body(p, p_body);
    let vp2 = node2.tc.virtual_processor().clone();
    let before = private_stores(&node2, p);
    assert_eq!(before.nullifiers, vec![]);
    assert_eq!(before.note_tree_at_p, None);
    assert_eq!(before.fingerprint_at_p, None);
    // Without the private state node 2 knows neither the spent tag nor the snapshots
    assert_eq!(vp2.check_private_payment_in_context(&spend, p, &HashSet::new()), stale_snapshot);
    assert_eq!(vp2.check_private_payment_in_context(&unspent, p, &HashSet::new()), stale_snapshot);

    // --- tampered copies: refused before any write ---
    let fingerprint_mismatch = "the spent coin tags and snapshots do not match the fingerprint sealed in the pruning point";
    let mut hidden = honest.clone();
    hidden.spent.retain(|tag| *tag != nf);
    assert_eq!(hidden.spent.len(), honest.spent.len() - 1);
    assert_refused(node2.tc.import_zethora_private_state(p, hidden), p, fingerprint_mismatch);
    assert_eq!(private_stores(&node2, p), before);

    let mut invented = honest.clone();
    invented.spent.push([0x42; 32]);
    assert_refused(node2.tc.import_zethora_private_state(p, invented), p, fingerprint_mismatch);
    assert_eq!(private_stores(&node2, p), before);

    // Seam review P3-3: the import is streamed (each chunk stored as it arrives), so a repeated tag is no longer caught by
    // a set held in memory; the fingerprint is a set hash, so a repeat can never match it, and the copy is refused and
    // cleared again like any other
    let mut repeated = honest.clone();
    repeated.spent.push(nf);
    assert_refused(node2.tc.import_zethora_private_state(p, repeated), p, fingerprint_mismatch);
    assert_eq!(private_stores(&node2, p), before);

    // Seam review P3-7: a coin list longer than a valid one can be is refused before anything is written
    let mut long_list = honest.clone();
    long_list.note_tree.resize(1_067, 0);
    assert_refused(
        node2.tc.import_zethora_private_state(p, long_list),
        p,
        "the private coin list is 1067 bytes, more than a valid one can be (1066)",
    );
    assert_eq!(private_stores(&node2, p), before);

    let mut younger = honest.clone();
    let at = younger.anchors.iter().position(|(root, _)| *root == r2).unwrap();
    younger.anchors[at].1 -= 1; // claims the snapshot is one block older than it is, so spends could use it earlier
    assert_refused(node2.tc.import_zethora_private_state(p, younger), p, fingerprint_mismatch);
    assert_eq!(private_stores(&node2, p), before);

    // --- the honest copy is accepted ---
    node2.tc.import_zethora_private_state(p, honest.clone()).unwrap();
    let after = private_stores(&node2, p);
    assert_eq!(after.note_tree_at_p, Some(note_root(&f.node.coinbase_payload(p))));
    assert_eq!(after.fingerprint_at_p.unwrap()[..], f.node.coinbase_payload(p)[88..120]);
    let expected_tags: Vec<([u8; 32], Vec<Hash>)> = {
        let mut tags: Vec<_> = honest.spent.iter().map(|nf| (*nf, vec![SPENT_FOR_GOOD])).collect();
        tags.sort();
        tags
    };
    let mut stored_tags = after.nullifiers.clone();
    stored_tags.sort();
    assert_eq!(stored_tags, expected_tags);

    // A spend of the coin spent before P is refused; the unspent coin can be spent against the imported snapshot
    assert_eq!(vp2.check_private_payment_in_context(&spend, p, &HashSet::new()), already_spent);
    assert_eq!(vp2.check_private_payment_in_context(&unspent, p, &HashSet::new()), Ok(()));
    assert!(vp2.nullifier_spent_on_chain(&nf, p));

    drop((vp1, vp2));
    f.node.shutdown();
    node2.shutdown();
}
