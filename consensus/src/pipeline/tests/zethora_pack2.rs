// Seam review pack 2 (F3d) proof tests that need a real DAG: P2-7 (anchor depth reference point, boundary), P2-8
// (the chain-ancestor check counts the selected parent itself) and P2-3 (a node stopped in the middle of pruning gives
// the same answers as one that finished). All three were verdict "not a bug"; these tests keep it so.
// CLAUDE.md standing rule: positive control, exact assertions, fail-when-protection-removed (see the PR).

use crate::config::ConfigBuilder;
use crate::consensus::test_consensus::TestConsensus;
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::headers::HeaderStoreReader;
use crate::params::DEVNET_PARAMS;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::constants::TX_VERSION;
use kaspa_consensus_core::errors::tx::TxRuleError;
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
        // Positive control first: b12 is exactly depth blue score below the selected parent (12 - 2 = 10) and b13
        // deeper, so the snapshot is matured and the spend is accepted by the rule the mempool, the template and the
        // merge loop all call
        assert!(vp.anchor_matured_on_chain(&root, b[(DEPTH + 2) as usize]));
        assert!(vp.anchor_matured_on_chain(&root, b[(DEPTH + 3) as usize]));
        let tx = spend([0x5E; 32], root);
        let none = HashSet::new();
        assert_eq!(vp.check_private_payment_in_context(&tx, b[(DEPTH + 2) as usize], &none), Ok(()));
        // Attack: b11 is only depth - 1 below the selected parent: refused with the exact stale-snapshot error
        assert!(!vp.anchor_matured_on_chain(&root, b[(DEPTH + 1) as usize]));
        assert_eq!(
            vp.check_private_payment_in_context(&tx, b[(DEPTH + 1) as usize], &none),
            Err(TxRuleError::InvalidPrivatePayment(format!(
                "spend uses an unknown or too recent private coin list snapshot (it must be at least {} blocks deep)",
                DEPTH
            )))
        );
    }
    // An unknown snapshot never counts (positive control for the lookup), and the spend is refused with the same error
    assert!(!vp.anchor_matured_on_chain(&[0xA3; 32], b[(DEPTH + 3) as usize]));
    assert_eq!(
        vp.check_private_payment_in_context(&spend([0x6E; 32], [0xA3; 32]), b[(DEPTH + 3) as usize], &HashSet::new()),
        Err(TxRuleError::InvalidPrivatePayment(format!(
            "spend uses an unknown or too recent private coin list snapshot (it must be at least {} blocks deep)",
            DEPTH
        )))
    );

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

const TAG_AT_10: [u8; 32] = [0x0A; 32];
const TAG_AT_20: [u8; 32] = [0x14; 32];
const TAG_ON_SIDE: [u8; 32] = [0x5E; 32];

/// What the private rules answer on top of `tip`.
#[derive(Debug, PartialEq)]
struct Answers {
    spent_at_10: bool,
    spent_at_20: bool,
    spent_on_side: bool,
}

/// One node for the P2-3 test: a chain with pruning depth 100 (as in Kaspa's pruning_test), a side block, and three
/// coin tag records: accepted by chain block 10, by chain block 20 and by the side block (off the chain at block 15).
/// `crash_at_side`: pruning stops right before the side block, as if the node crashed there (test failpoint).
/// Returns the node, its handles, the chain and the side block.
async fn pruned_node(offset: u64, crash_at_side: bool) -> (TestConsensus, Vec<std::thread::JoinHandle<()>>, Vec<Hash>, Hash) {
    let config = ConfigBuilder::new(DEVNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.finality_depth = 2;
            p.mergeset_size_limit = 2;
            p.ghostdag_k = 2;
            p.merge_depth = 3;
            p.pruning_depth = 100;
        })
        .build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let block = |i: u64| Hash::from_u64_word(offset + i);
    let side = block(100_000);
    if crash_at_side {
        crate::pipeline::pruning_processor::processor::ZETHORA_CRASH_BEFORE.lock().unwrap().push(side);
    }
    let mut chain = vec![config.genesis.hash];
    for i in 1..config.pruning_depth() + config.finality_depth() + 100 {
        tc.add_empty_utxo_valid_block_with_parents(block(i), vec![*chain.last().unwrap()]).await.unwrap();
        chain.push(block(i));
        match i {
            10 => tc.zethora_insert_nullifiers(block(10), &[TAG_AT_10]),
            15 => {
                // A side block off the chain: its record is what a chain block leaves behind after a reorg
                tc.add_empty_utxo_valid_block_with_parents(side, vec![block(14)]).await.unwrap();
                tc.zethora_insert_nullifiers(side, &[TAG_ON_SIDE]);
            }
            20 => tc.zethora_insert_nullifiers(block(20), &[TAG_AT_20]),
            _ => {}
        }
    }
    (tc, handles, chain, side)
}

fn answers(tc: &TestConsensus, tip: Hash) -> Answers {
    let vp = tc.virtual_processor();
    Answers {
        spent_at_10: vp.nullifier_spent_on_chain(&TAG_AT_10, tip),
        spent_at_20: vp.nullifier_spent_on_chain(&TAG_AT_20, tip),
        spent_on_side: vp.nullifier_spent_on_chain(&TAG_ON_SIDE, tip),
    }
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < std::time::Duration::from_secs(120), "timed out waiting for {what}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// P2-3 (test P2-T3): pruning rewrites a block's coin tag records and deletes its reachability in ONE batch per block,
/// so a node stopped in the middle of pruning (here: right before the side block, every block before it fully pruned)
/// gives exactly the same spent / not spent answers as a node that finished: a tag spent on the chain stays spent, a tag
/// only a side block accepted stays unspent. (If the side block's reachability were deleted without its record being
/// rewritten, the "missing reachability counts as spent" fallback would wrongly call its tag spent.)
#[tokio::test]
async fn a_node_stopped_mid_pruning_answers_like_one_that_finished() {
    use crate::model::stores::zethora_nullifiers::SPENT_FOR_GOOD;
    let (finished, finished_handles, finished_chain, _) = pruned_node(20_000, false).await;
    let (stopped, stopped_handles, stopped_chain, stopped_side) = pruned_node(30_000, true).await;

    // The finished node pruned blocks 10 and 20 and the side block: records rewritten "for good" / dropped
    wait_for("pruning on the finished node", || {
        finished.zethora_nullifiers_store().accepting_blocks(&TAG_AT_20) == vec![SPENT_FOR_GOOD]
            && finished.zethora_nullifiers_store().accepting_blocks(&TAG_ON_SIDE).is_empty()
    })
    .await;
    assert_eq!(finished.zethora_nullifiers_store().accepting_blocks(&TAG_AT_10), vec![SPENT_FOR_GOOD]);

    // The stopped node: pruning reached the side block and stopped there; its record is untouched (still points at the
    // block) and its reachability still exists, so the two nodes really are in different states
    wait_for("the failpoint on the stopped node", || {
        crate::pipeline::pruning_processor::processor::ZETHORA_CRASHED_AT.lock().unwrap().contains(&stopped_side)
    })
    .await;
    assert_eq!(stopped.zethora_nullifiers_store().accepting_blocks(&TAG_ON_SIDE), vec![stopped_side]);
    assert_eq!(
        stopped.reachability_service().try_is_chain_ancestor_of(stopped_side, *stopped_chain.last().unwrap()).ok(),
        Some(false)
    );

    // Same answers on top of each node's tip (positive control: the chain tags are spent, the side tag is not)
    let expected = Answers { spent_at_10: true, spent_at_20: true, spent_on_side: false };
    assert_eq!(answers(&finished, *finished_chain.last().unwrap()), expected);
    assert_eq!(answers(&stopped, *stopped_chain.last().unwrap()), expected);

    finished.shutdown(finished_handles);
    stopped.shutdown(stopped_handles);
}
