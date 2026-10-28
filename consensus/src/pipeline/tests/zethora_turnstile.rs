// Zethora F1: the private pool turnstile is checked per transaction, in consensus merge order (ZTH-SPEC-006 §7.1).
//
// Before F1 the turnstile was a per-block sum (coinbase.rs ledger_step): one payment taking more out of the private pool
// than it holds made the whole merging block invalid, and since every later chain block has to merge it, the chain
// stalled. Now the merge loop keeps a running balance, starting from the selected parent's sealed balance, and a
// transaction that would take it below zero is simply not accepted: none of its effects happen.
//
// An overdrawing payment cannot be made honestly (Orchard's value balance and the anchor rule prevent it), so these
// tests make a COUNTERFEIT: a spend of a coin that only exists in a local coin list. Its proof is valid against that
// list's root, and the test registers that root as a matured snapshot (zethora_insert_anchor_for_good), simulating a
// broken anchor or proof rule: exactly the bug the turnstile is the backstop for.
//
// CLAUDE.md standing rule: positive control, exact asserts, fail-when-protection-removed (see the PR for the outputs).

use super::zethora_parallel_nullifier::{Funded, Node, SHIELDED, SPEND_FEE, shield_one_coin_on_chain, shielded_balance};
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::ghostdag::GhostdagStoreReader;
use crate::model::stores::headers::HeaderStoreReader;
use crate::model::stores::utxo_diffs::UtxoDiffsStoreReader;
use crate::model::stores::virtual_state::VirtualStateStoreReader;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::block::{Block, TemplateBuildMode, TemplateTransactionSelector};
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::constants::TX_VERSION;
use kaspa_consensus_core::hashing::tx::zethora_private_payment_digest;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::utxo::utxo_diff::UtxoDiff;
use kaspa_consensus_core::zethora_private::{PRIVATE_PAYMENT_MAGIC, nullifiers, pool_flows, spend_anchor};
use kaspa_txscript::opcodes::codes::OpTrue;
use std::sync::{Arc, Mutex};
use zethora_shielded::scan::Scanner;
use zethora_shielded::wallet::{PrivateWallet, shielding_payment};

/// Taken out of the pool by the counterfeit. Alone it fits (50,000 in the pool); after the honest spend (1,000 out) it
/// does not: 50,000 - 1,000 - 49,500 < 0.
const OVERDRAW: u64 = 49_500;
/// Exactly what is left after the honest spend: 50,000 - 1,000.
const EXACT_FIT: u64 = SHIELDED - SPEND_FEE;

/// A counterfeit fully private payment taking `value_out` zets out of the private pool (all of it as the network fee).
/// Valid in every way except that the coin it spends was never shielded on chain. Registers its anchor in `nodes`.
/// Checked through the mempool path of `nodes[0]`, so the pool must hold at least `value_out` when it is made.
fn counterfeit(value_out: u64, seed: u8, nodes: &[&Node]) -> Transaction {
    nodes[0].mempool_checked(counterfeit_unchecked(value_out, seed, nodes))
}

/// `counterfeit` without the mempool check.
fn counterfeit_unchecked(value_out: u64, seed: u8, nodes: &[&Node]) -> Transaction {
    let forger = PrivateWallet::from_seed(&[seed; 32]);
    let address = forger.address();
    let mut scanner = Scanner::new(vec![forger]);
    scanner.add_payment(&shielding_payment(address, value_out, &[0; 32]).unwrap()).unwrap();
    scanner.checkpoint().unwrap();
    let coins = scanner.pick_coins(0, value_out).unwrap();
    let mut tx = Transaction::new_non_finalized(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let digest = zethora_private_payment_digest(&tx);
    let payment = scanner.spend_payment(0, &coins, &[], &digest.as_bytes()).unwrap();
    tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
    tx.finalize();
    assert_eq!(pool_flows(&tx.payload), Ok(Some((0, value_out))));
    let anchor = spend_anchor(&tx.payload).expect("a spend has an anchor");
    for node in nodes {
        node.tc.zethora_insert_anchor_for_good(&anchor, 0);
    }
    tx
}

/// An ordinary visible transaction spending the shielding transaction's change.
fn visible_tx(f: &Funded) -> Transaction {
    let change = f.shield.outputs[0].value;
    let input = TransactionInput::new(TransactionOutpoint::new(f.shield.id(), 0), vec![], 0, 0);
    let output = TransactionOutput::new(change - 10_000, ScriptPublicKey::from_vec(0, vec![OpTrue]));
    let tx = Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    f.node.mempool_checked(tx)
}

/// Two fresh sibling hashes: (the one GHOSTDAG makes the merging block's selected parent, the other one). With equal
/// blue work the larger hash is the selected parent, and the merge loop accepts its transactions first.
fn sibling_hashes(node: &mut Node) -> (Hash, Hash) {
    let (h1, h2) = (node.fresh_hash(), node.fresh_hash());
    (h1.max(h2), h1.min(h2))
}

/// Two different blocks given the same hash (the skipped-payment comparison) still have their own block level, because
/// the level comes from the PoW of the header contents (consensus/pow/src/lib.rs calc_block_level). Indirect parents of
/// a merging block depend on its parents' levels, so both versions are ground to level 0 (a different nonce; the hash
/// stays the forced one) to keep the comparison about the transactions alone.
fn at_level_zero(node: &Node, block: Block) -> Block {
    let max_block_level = node.tc.params().max_block_level;
    let mut header = (*block.header).clone();
    while kaspa_pow::calc_block_level(&header, max_block_level) != 0 {
        header.nonce += 1;
    }
    Block::from_arcs(Arc::new(header), block.transactions)
}

/// Ids of a chain block's accepted transactions, per merged block, in merge order
fn acceptance(node: &Node, block: Hash) -> Vec<(Hash, Vec<(TransactionId, u32)>)> {
    node.tc
        .get_block_acceptance_data(block)
        .unwrap()
        .iter()
        .map(|m| (m.block_hash, m.accepted_transactions.iter().map(|e| (e.transaction_id, e.index_within_block)).collect()))
        .collect()
}

/// The selected parent's coinbase is the first transaction its merging chain block accepts
fn coinbase_id(node: &Node, block: Hash) -> TransactionId {
    node.tc.get_block(block).unwrap().transactions[0].id()
}

fn recorded_tags(node: &Node, tx: &Transaction) -> Vec<Vec<Hash>> {
    nullifiers(&tx.payload).iter().map(|nf| node.tc.zethora_nullifiers_store().accepting_blocks(nf)).collect()
}

#[tokio::test]
async fn counterfeit_alone_passes_every_other_check() {
    // Positive control for the tests below: the counterfeit is refused there ONLY by the turnstile
    let mut f = shield_one_coin_on_chain().await;
    let fake = counterfeit(OVERDRAW, 66, &[&f.node]);
    let block = f.node.mine(vec![fake.clone()]).await;
    let accepting = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(accepting, fake.id()), 1);
    assert_eq!(recorded_tags(&f.node, &fake), vec![vec![accepting]; nullifiers(&fake.payload).len()]);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(block)), SHIELDED);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(accepting)), SHIELDED - OVERDRAW);
    f.node.shutdown();
}

#[tokio::test]
async fn overdrawing_payment_is_skipped_and_the_merging_block_stays_valid() {
    let mut f = shield_one_coin_on_chain().await;
    let honest = f.spend(30_000);
    let fake = counterfeit(OVERDRAW, 66, &[&f.node]);

    // Siblings on the same tip, each valid on its own (each fits the 50,000 pool), merged by C
    let parent = f.node.tip;
    let (x, y) = sibling_hashes(&mut f.node);
    assert_eq!(f.node.insert(x, vec![parent], vec![honest.clone()]).await, BlockStatus::StatusUTXOValid);
    f.node.insert(y, vec![parent], vec![fake.clone()]).await;
    assert!(!f.node.tc.reachability_service().is_dag_ancestor_of(x, y));
    assert!(!f.node.tc.reachability_service().is_dag_ancestor_of(y, x));
    let c = f.node.fresh_hash();
    assert_eq!(f.node.insert(c, vec![x, y], vec![]).await, BlockStatus::StatusUTXOValid);
    assert_eq!(f.node.tc.get_sink(), c);
    assert_eq!(f.node.tc.ghostdag_store().get_selected_parent(c).unwrap(), x);

    // The honest spend (first in merge order) is accepted, the counterfeit is not; the pool never goes below zero
    assert_eq!(f.node.accepted_count(c, honest.id()), 1);
    assert_eq!(f.node.accepted_count(c, fake.id()), 0);
    assert_eq!(acceptance(&f.node, c), vec![(x, vec![(coinbase_id(&f.node, x), 0), (honest.id(), 1)]), (y, vec![])]);
    assert_eq!(recorded_tags(&f.node, &honest), vec![vec![c]; nullifiers(&honest.payload).len()]);
    assert_eq!(recorded_tags(&f.node, &fake), vec![Vec::<Hash>::new(); nullifiers(&fake.payload).len()]);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(c)), SHIELDED - SPEND_FEE);

    // The chain continues on top of C
    f.node.tip = c;
    let d = f.node.mine(vec![]).await;
    assert_eq!(f.node.tc.get_sink(), d);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(d)), SHIELDED - SPEND_FEE);

    f.node.shutdown();
}

/// Everything a node computed for chain block C and the virtual on top of it
#[derive(Debug, PartialEq)]
struct Outcome {
    status_c: BlockStatus,
    sink: Hash,
    acceptance: Vec<(Hash, Vec<(TransactionId, u32)>)>,
    nullifier_store: Vec<([u8; 32], Vec<Hash>)>,
    c_utxo_diff: UtxoDiff,
    c_coinbase_payload: Vec<u8>,
    c_utxo_commitment: Hash,
    c_accepted_id_merkle_root: Hash,
    c_smt_metadata: crate::model::stores::smt_metadata::SmtBlockMetadata,
    virtual_note_root: [u8; 32],
    virtual_private_state: [u8; 32],
    virtual_mergeset_nullifiers: Vec<[u8; 32]>,
    virtual_utxo_commitment: Hash,
    virtual_utxos: Vec<(TransactionOutpoint, UtxoEntry)>,
}

fn outcome(node: &Node, c: Hash, status_c: BlockStatus) -> Outcome {
    let (virtual_note_root, virtual_private_state, virtual_mergeset_nullifiers, virtual_utxo_commitment) = {
        let stores = node.tc.virtual_stores();
        let read = stores.read();
        let state = read.state.get().unwrap();
        (state.note_root, state.private_state, state.mergeset_nullifiers.clone(), state.multiset.clone().finalize())
    };
    let header = node.tc.headers_store().get_header(c).unwrap();
    Outcome {
        status_c,
        sink: node.tc.get_sink(),
        acceptance: acceptance(node, c),
        nullifier_store: node.tc.zethora_nullifiers_store().iter_all().map(|r| r.unwrap()).collect(),
        c_utxo_diff: (*node.tc.utxo_diffs_store().get(c).unwrap()).clone(),
        c_coinbase_payload: node.coinbase_payload(c),
        c_utxo_commitment: header.utxo_commitment,
        c_accepted_id_merkle_root: header.accepted_id_merkle_root,
        c_smt_metadata: node.tc.smt_block_metadata(c),
        virtual_note_root,
        virtual_private_state,
        virtual_mergeset_nullifiers,
        virtual_utxo_commitment,
        virtual_utxos: node.tc.get_virtual_utxos(None, usize::MAX, false),
    }
}

async fn replay_chain(chain: &[Block], node: &Node) {
    for block in chain {
        assert_eq!(node.insert_block(block.clone()).await, BlockStatus::StatusUTXOValid);
    }
}

#[tokio::test]
async fn skipped_payment_leaves_exactly_the_state_of_the_block_without_it() {
    // Node 1: siblings X = [honest spend] and Y = [visible tx, counterfeit]. Node 2: the same chain, the same X, and a
    // block with Y's hash and parents but WITHOUT the counterfeit. C is built by node 2 and fed to both nodes.
    let mut f = shield_one_coin_on_chain().await;
    let chain: Vec<Block> = f.node.inserted.lock().unwrap().clone();
    let parent = f.node.tip;
    let node2 = Node::new();
    replay_chain(&chain, &node2).await;

    let honest = f.spend(30_000);
    let visible = visible_tx(&f);
    let fake = counterfeit(OVERDRAW, 66, &[&f.node, &node2]);
    let (x, y) = sibling_hashes(&mut f.node);
    let block_x = f.node.build(x, vec![parent], vec![honest.clone()]);
    let block_y = at_level_zero(&f.node, f.node.build(y, vec![parent], vec![visible.clone(), fake.clone()]));
    let block_y_without = at_level_zero(&node2, node2.build(y, vec![parent], vec![visible.clone()]));
    assert_eq!(block_y.hash(), block_y_without.hash());
    assert_eq!(block_y.transactions.len(), 3);
    assert_eq!(block_y_without.transactions.len(), 2);
    assert_eq!(block_y.transactions[1].id(), block_y_without.transactions[1].id());

    for (node, y_block) in [(&f.node, &block_y), (&node2, &block_y_without)] {
        assert_eq!(node.insert_block(block_x.clone()).await, BlockStatus::StatusUTXOValid);
        node.insert_block(y_block.clone()).await;
    }
    let c = f.node.fresh_hash();
    let block_c = node2.build(c, vec![x, y], vec![]);

    // Node 1 accepts the C that node 2 computed without the counterfeit: its UTXO commitment, seq-commit
    // (accepted_id_merkle_root) and coinbase (rewards and fees, fee pool, supply ledger incl. the private pool balance,
    // note root, private state fingerprint) are exactly what node 1 computes with the counterfeit in Y
    let status1 = f.node.insert_block(block_c.clone()).await;
    let status2 = node2.insert_block(block_c.clone()).await;
    assert_eq!(status1, BlockStatus::StatusUTXOValid, "node 1 (with the counterfeit) refused C");
    assert_eq!(status2, BlockStatus::StatusUTXOValid);

    let (with, without) = (outcome(&f.node, c, status1), outcome(&node2, c, status2));
    assert_eq!(with.sink, c);
    assert_eq!(with.acceptance, without.acceptance, "acceptance data");
    assert_eq!(with.acceptance, vec![(x, vec![(coinbase_id(&f.node, x), 0), (honest.id(), 1)]), (y, vec![(visible.id(), 1)])]);
    assert_eq!(with.nullifier_store, without.nullifier_store, "nullifier store");
    assert_eq!(recorded_tags(&f.node, &fake), vec![Vec::<Hash>::new(); nullifiers(&fake.payload).len()]);
    assert_eq!(with.c_utxo_diff, without.c_utxo_diff, "UTXO diff");
    assert_eq!(with.c_coinbase_payload[56..88], without.c_coinbase_payload[56..88], "note root");
    assert_eq!(with.c_coinbase_payload[88..120], without.c_coinbase_payload[88..120], "private state fingerprint");
    assert_eq!(shielded_balance(&with.c_coinbase_payload), SHIELDED - SPEND_FEE);
    assert_eq!(with.c_accepted_id_merkle_root, without.c_accepted_id_merkle_root, "seq-commit");
    assert_eq!(with.c_smt_metadata, without.c_smt_metadata, "seq-commit SMT metadata");
    assert_eq!(with.virtual_utxos.len(), without.virtual_utxos.len());
    assert_eq!(with, without);

    f.node.shutdown();
    node2.shutdown();
}

#[tokio::test]
async fn overdraw_siblings_give_identical_state_in_both_arrival_orders() {
    // Build everything ONCE: the funded chain, X = [honest spend] and Y = [counterfeit] on the same tip, C on [X, Y]
    let mut f = shield_one_coin_on_chain().await;
    let chain: Vec<Block> = f.node.inserted.lock().unwrap().clone();
    let parent = f.node.tip;
    let honest = f.spend(30_000);
    let fake = counterfeit(OVERDRAW, 66, &[&f.node]);
    let anchor = spend_anchor(&fake.payload).unwrap();
    let (x, y) = sibling_hashes(&mut f.node);
    let block_x = f.node.build(x, vec![parent], vec![honest.clone()]);
    let block_y = f.node.build(y, vec![parent], vec![fake.clone()]);
    f.node.insert_block(block_x.clone()).await;
    f.node.insert_block(block_y.clone()).await;
    let c = f.node.fresh_hash();
    let block_c = f.node.build(c, vec![x, y], vec![]);
    f.node.shutdown();

    // Two fresh nodes (with the same broken anchor rule), identical blocks, opposite sibling arrival orders
    let mut results = Vec::new();
    for siblings in [[&block_x, &block_y], [&block_y, &block_x]] {
        let node = Node::new();
        node.tc.zethora_insert_anchor_for_good(&anchor, 0);
        replay_chain(&chain, &node).await;
        for sibling in siblings {
            node.insert_block(sibling.clone()).await;
        }
        let status = node.insert_block(block_c.clone()).await;
        results.push((outcome(&node, c, status), node));
    }
    let (ab, ba) = (&results[0].0, &results[1].0);
    assert_eq!(ab.acceptance, ba.acceptance, "the two arrival orders accepted different transactions");
    assert_eq!(ab.nullifier_store, ba.nullifier_store);
    assert_eq!(ab.c_utxo_diff, ba.c_utxo_diff);
    assert_eq!(ab.virtual_private_state, ba.virtual_private_state);
    assert_eq!(ab, ba);

    // And the shared outcome is the correct one: C valid, the honest spend accepted from the selected parent X, the
    // counterfeit not accepted, the pool debited once
    for (state, node) in &results {
        assert_eq!(state.status_c, BlockStatus::StatusUTXOValid);
        assert_eq!(state.sink, c);
        assert_eq!(node.tc.ghostdag_store().get_selected_parent(c).unwrap(), x);
        assert_eq!(state.acceptance, vec![(x, vec![(coinbase_id(node, x), 0), (honest.id(), 1)]), (y, vec![])]);
        assert_eq!(recorded_tags(node, &fake), vec![Vec::<Hash>::new(); nullifiers(&fake.payload).len()]);
        assert_eq!(shielded_balance(&state.c_coinbase_payload), SHIELDED - SPEND_FEE);
    }
    for (_, node) in results {
        node.shutdown();
    }
}

#[tokio::test]
async fn chain_block_whose_own_payment_overdraws_is_disqualified() {
    let mut f = shield_one_coin_on_chain().await;
    let honest = f.spend(30_000);
    // Made (and mempool-checked) while the pool still holds 50,000: once it holds less, the mempool refuses `over` (F2)
    let over = counterfeit(EXACT_FIT + 1, 66, &[&f.node]);
    let fit = counterfeit(EXACT_FIT, 67, &[&f.node]);
    f.node.mine(vec![honest.clone()]).await;
    let tip = f.node.mine(vec![]).await;
    assert_eq!(shielded_balance(&f.node.coinbase_payload(tip)), EXACT_FIT);

    // One zet more than the pool holds: the block may not join the chain (like any block with an invalid transaction)
    let bad = f.node.fresh_hash();
    assert_eq!(f.node.insert(bad, vec![tip], vec![over.clone()]).await, BlockStatus::StatusDisqualifiedFromChain);
    assert_eq!(f.node.tc.get_sink(), tip);

    // Positive control: exactly what the pool holds is fine, and the pool ends at exactly zero
    let good = f.node.fresh_hash();
    assert_eq!(f.node.insert(good, vec![tip], vec![fit.clone()]).await, BlockStatus::StatusUTXOValid);
    assert_eq!(f.node.tc.get_sink(), good);
    f.node.tip = good;
    let accepting = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(accepting, fit.id()), 1);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(accepting)), 0);

    f.node.shutdown();
}

/// Hands out one batch of transactions and records which ones the template builder rejects
struct RecordingSelector {
    txs: Option<Vec<Transaction>>,
    rejected: Arc<Mutex<Vec<TransactionId>>>,
}

impl TemplateTransactionSelector for RecordingSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap_or_default()
    }

    fn reject_selection(&mut self, tx_id: TransactionId) {
        self.rejected.lock().unwrap().push(tx_id);
    }

    fn is_successful(&self) -> bool {
        true
    }
}

fn template_txs(f: &Funded, txs: Vec<Transaction>) -> (Block, Vec<TransactionId>) {
    let rejected = Arc::new(Mutex::new(Vec::new()));
    let selector = RecordingSelector { txs: Some(txs), rejected: rejected.clone() };
    let template = f.node.tc.build_block_template(f.node.miner.clone(), Box::new(selector), TemplateBuildMode::Standard).unwrap();
    let rejected = rejected.lock().unwrap().clone();
    (template.block.to_immutable(), rejected)
}

#[tokio::test]
async fn block_template_leaves_out_a_payment_the_pool_cannot_cover() {
    let mut f = shield_one_coin_on_chain().await;
    let honest = f.spend(30_000);
    let over = counterfeit(EXACT_FIT + 1, 66, &[&f.node]);
    let fit = counterfeit(EXACT_FIT, 67, &[&f.node]);

    // Together they take one zet more than the pool holds: the second is left out
    let (block, rejected) = template_txs(&f, vec![honest.clone(), over.clone()]);
    assert_eq!(block.transactions.iter().skip(1).map(|tx| tx.id()).collect::<Vec<_>>(), vec![honest.id()]);
    assert_eq!(rejected, vec![over.id()]);

    // Positive control: exactly what the pool holds is taken; the block is valid and empties the pool exactly
    let (block, rejected) = template_txs(&f, vec![honest.clone(), fit.clone()]);
    assert_eq!(block.transactions.iter().skip(1).map(|tx| tx.id()).collect::<Vec<_>>(), vec![honest.id(), fit.id()]);
    assert_eq!(rejected, Vec::<TransactionId>::new());
    let hash = block.hash();
    assert_eq!(f.node.insert_block(block).await, BlockStatus::StatusUTXOValid);
    f.node.tip = hash;
    let accepting = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(accepting, honest.id()), 1);
    assert_eq!(f.node.accepted_count(accepting, fit.id()), 1);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(accepting)), 0);

    f.node.shutdown();
}

/// The mempool's answer for one transaction, through the single and the batch admission paths (they must agree).
fn mempool_result(node: &Node, tx: &Transaction) -> Result<(), kaspa_consensus_core::errors::tx::TxRuleError> {
    use kaspa_consensus_core::api::args::{TransactionValidationArgs, TransactionValidationBatchArgs};
    use kaspa_consensus_core::tx::MutableTransaction;
    let single =
        node.tc.validate_mempool_transaction(&mut MutableTransaction::from_tx(tx.clone()), &TransactionValidationArgs::default());
    let mut batch = vec![MutableTransaction::from_tx(tx.clone())];
    let batch = node.tc.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());
    assert_eq!(batch, vec![single.clone()], "single and batch admission disagree");
    single
}

#[tokio::test]
async fn mempool_refuses_a_payment_the_pool_cannot_cover() {
    use kaspa_consensus_core::errors::tx::TxRuleError;
    let mut f = shield_one_coin_on_chain().await;
    assert_eq!(shielded_balance(&f.node.coinbase_payload(f.node.tip)), SHIELDED);

    // One zet more than the pool holds: refused at admission, with the template's rule
    let over = counterfeit_unchecked(SHIELDED + 1, 66, &[&f.node]);
    let refused = Err(TxRuleError::InvalidPrivatePayment(format!(
        "would take {} zets out of the private pool, which holds {SHIELDED}",
        SHIELDED + 1
    )));
    assert_eq!(mempool_result(&f.node, &over), refused);

    // ... before the proof check: the same payment with a broken proof gets the same (cheap) refusal, not a proof error
    let mut broken = over.clone();
    let proof_at = PRIVATE_PAYMENT_MAGIC.len()
        + kaspa_consensus_core::zethora_private::layout::trailer_offset(
            kaspa_consensus_core::zethora_private::action_count(&broken.payload[4..]).unwrap(),
        )
        .unwrap()
        + kaspa_consensus_core::zethora_private::layout::PROOF_OFFSET
        + 100;
    broken.payload[proof_at] ^= 1;
    broken.finalize();
    assert_eq!(mempool_result(&f.node, &broken), refused);

    // Positive controls: exactly what the pool holds is admitted, and so is an honest spend
    let fit = counterfeit_unchecked(SHIELDED, 67, &[&f.node]);
    assert_eq!(mempool_result(&f.node, &fit), Ok(()));
    let honest = f.spend(30_000);
    assert_eq!(mempool_result(&f.node, &honest), Ok(()));

    // The pool shrinks on chain: what fit before no longer does (the mempool reads the current virtual balance)
    f.node.mine(vec![honest]).await;
    f.node.mine(vec![]).await;
    assert_eq!(shielded_balance(&f.node.coinbase_payload(f.node.tip)), EXACT_FIT);
    assert_eq!(
        mempool_result(&f.node, &fit),
        Err(TxRuleError::InvalidPrivatePayment(format!(
            "would take {SHIELDED} zets out of the private pool, which holds {EXACT_FIT}"
        )))
    );
    let fit_now = counterfeit_unchecked(EXACT_FIT, 68, &[&f.node]);
    assert_eq!(mempool_result(&f.node, &fit_now), Ok(()));

    f.node.shutdown();
}
