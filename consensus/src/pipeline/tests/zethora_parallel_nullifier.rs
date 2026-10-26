// Zethora Task 4 — parallel DAG nullifier double-spend regression tests (ZTH-SPEC-006 §6.3).
//
// Property test: private_double_spend() rejects any tx whose nullifier appears in the pending set.
//
// End-to-end tests (CLAUDE.md standing rule: positive control, exact asserts, fail-when-protection-removed):
//   * a real coin is shielded ON CHAIN and its coin list snapshot matures (anchor_depth = 10 in these tests),
//   * positive control: one spend in one block is accepted exactly once and the private pool drops 50,000 -> 49,000,
//   * siblings: two different spends of that coin in parallel blocks A and B, merged by C, in both arrival orders:
//     exactly one is accepted, the coin tag is recorded once, and the pool is 49,000 (48,000 = counted twice).

use crate::config::ConfigBuilder;
use crate::consensus::test_consensus::TestConsensus;
use crate::constants::TX_VERSION_TOCCATA;
use crate::model::services::reachability::ReachabilityService;
use crate::params::DEVNET_PARAMS;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::api::args::TransactionValidationArgs;
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::constants::TX_VERSION;
use kaspa_consensus_core::hashing::tx::zethora_private_payment_digest;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_consensus_core::zethora_private::{PRIVATE_PAYMENT_MAGIC, nullifiers, private_payment_bytes};
use kaspa_txscript::opcodes::codes::OpTrue;
use std::collections::HashSet;
use std::thread::JoinHandle;
use zethora_shielded::orchard::Address;
use zethora_shielded::scan::{OwnedCoin, Scanner};
use zethora_shielded::wallet::{PrivateWallet, shielding_payment};

fn private_spend_tx(fee: u64) -> Transaction {
    use zethora_shielded::scan::Scanner;
    use zethora_shielded::wallet::{PrivateWallet, shielding_payment};

    let (me, friend) = (PrivateWallet::from_seed(&[5; 32]), PrivateWallet::friend_of(&[5; 32]));
    let (me_address, friend_address) = (me.address(), friend.address());
    let mut scanner = Scanner::new(vec![me, friend]);
    scanner.add_payment(&shielding_payment(me_address, 50_000, &[0; 32]).unwrap()).unwrap();
    scanner.checkpoint().unwrap();
    let coins = scanner.pick_coins(0, 50_000).unwrap();

    let mut tx = Transaction::new_non_finalized(TX_VERSION_TOCCATA, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let digest = zethora_private_payment_digest(&tx);
    let payment =
        scanner.spend_payment(0, &coins, &[(friend_address, 30_000), (me_address, 20_000 - fee)], &digest.as_bytes()).unwrap();
    tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
    tx.finalize();
    tx
}

// ---------------------------------------------------------------------------
// PROPERTY TEST — runs in CI, proves the double-spend check itself.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn nullifier_in_pending_set_is_rejected_by_private_double_spend() {
    use kaspa_consensus_core::zethora_private::nullifiers;
    use std::collections::HashSet;

    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let consensus = TestConsensus::new(&config);
    let handles = consensus.init();

    let tx = private_spend_tx(1_000);
    let nfs = nullifiers(&tx.payload);

    // A private spend carries >= 1 nullifier (Orchard may pad with dummy
    // nullifiers from additional actions). All must be rejected on replay.
    assert!(!nfs.is_empty(), "test tx must have at least one nullifier, got {}", nfs.len());

    let genesis = consensus.params().genesis.hash;

    // Case 1: pending contains ANY of the tx's nullifiers -> must reject.
    for nf in &nfs {
        let mut pending = HashSet::new();
        pending.insert(*nf);
        assert!(
            consensus.virtual_processor().private_double_spend(&tx, genesis, &pending),
            "REDDIT BUG: tx with nullifier {:?} in pending was not rejected",
            nf
        );
    }

    // Case 2: empty pending -> MUST accept (no false positive).
    let empty: HashSet<[u8; 32]> = HashSet::new();
    assert!(
        !consensus.virtual_processor().private_double_spend(&tx, genesis, &empty),
        "false positive: empty pending triggered double-spend detection"
    );

    // Case 3: unrelated nullifier in pending -> MUST accept.
    let mut other = HashSet::new();
    other.insert([0xFFu8; 32]);
    assert!(
        !consensus.virtual_processor().private_double_spend(&tx, genesis, &other),
        "false positive: unrelated nullifier triggered rejection"
    );

    consensus.shutdown(handles);

    eprintln!("\n=== Property test result ===");
    eprintln!("Tx carries {} nullifier(s): all rejected when in pending", nfs.len());
    eprintln!("Empty pending:             accepted");
    eprintln!("Unrelated nullifier:       accepted");
    eprintln!("\nReddit concern answered at the nullifier-check layer.");
    eprintln!("Merge-order determinism proven by inspection of");
    eprintln!("  utxo_validation.rs:171 consensus_ordered_mergeset_without_selected_parent");
}

// ---------------------------------------------------------------------------
// END-TO-END TESTS — real coin shielded on chain, real blocks, real merge.
// ---------------------------------------------------------------------------

/// Snapshot depth for these tests only (real networks: 600, locked in Params).
const TEST_ANCHOR_DEPTH: u64 = 10;
/// Zets shielded into the private pool, and the fee each private spend pays out of it.
const SHIELDED: u64 = 50_000;
const SPEND_FEE: u64 = 1_000;
/// Fee of the shielding transaction (paid from the visible coin).
const SHIELD_FEE: u64 = 10_000;

/// Coinbase payload offsets (consensus/core/src/coinbase.rs): shielded balance 48..56, note root 56..88.
fn shielded_balance(coinbase_payload: &[u8]) -> u64 {
    u64::from_le_bytes(coinbase_payload[48..56].try_into().unwrap())
}

fn note_root(coinbase_payload: &[u8]) -> [u8; 32] {
    coinbase_payload[56..88].try_into().unwrap()
}

/// One fresh consensus instance with a single chain of blocks mined to an OpTrue script.
struct Node {
    tc: TestConsensus,
    handles: Vec<JoinHandle<()>>,
    miner: MinerData,
    tip: Hash,
    next_word: u64,
    coinbase_maturity: u64,
}

impl Node {
    fn new() -> Self {
        let config = ConfigBuilder::new(DEVNET_PARAMS)
            .skip_proof_of_work()
            .edit_consensus_params(|p| p.anchor_depth = TEST_ANCHOR_DEPTH)
            .build();
        assert_eq!(config.params.anchor_depth, TEST_ANCHOR_DEPTH);
        let tc = TestConsensus::new(&config);
        let handles = tc.init();
        let miner = MinerData::new(ScriptPublicKey::from_vec(0, vec![OpTrue]), vec![]);
        Self { tc, handles, miner, tip: config.genesis.hash, next_word: 0, coinbase_maturity: config.params.coinbase_maturity() }
    }

    fn fresh_hash(&mut self) -> Hash {
        self.next_word += 1;
        Hash::from_u64_word(self.next_word)
    }

    /// Builds a block with these parents and transactions (the builder refuses txs invalid on top of `parents`)
    /// and inserts it through validate_and_insert_block, waiting for the virtual state.
    async fn insert(&self, hash: Hash, parents: Vec<Hash>, txs: Vec<Transaction>) -> BlockStatus {
        let block = self.tc.build_utxo_valid_block_with_parents(hash, parents, self.miner.clone(), txs);
        self.tc.validate_and_insert_block(block.to_immutable()).virtual_state_task.await.unwrap()
    }

    /// Mines one block on the tip; it must become the new UTXO-valid tip.
    async fn mine(&mut self, txs: Vec<Transaction>) -> Hash {
        let hash = self.fresh_hash();
        assert_eq!(self.insert(hash, vec![self.tip], txs).await, BlockStatus::StatusUTXOValid);
        self.tip = hash;
        hash
    }

    async fn mine_empty(&mut self, count: u64) {
        for _ in 0..count {
            self.mine(vec![]).await;
        }
    }

    fn coinbase_payload(&self, block: Hash) -> Vec<u8> {
        self.tc.get_block(block).unwrap().transactions[0].payload.clone()
    }

    /// How many times chain block `block` accepted transaction `id` (over its whole mergeset).
    fn accepted_count(&self, block: Hash, id: TransactionId) -> usize {
        let data = self.tc.get_block_acceptance_data(block).unwrap();
        data.iter().flat_map(|m| m.accepted_transactions.iter()).filter(|e| e.transaction_id == id).count()
    }

    /// The real mempool path: in-isolation checks (incl. the Orchard proof) and UTXO-context checks against the
    /// virtual. Also fills in the storage mass commitment the block builder checks.
    fn mempool_checked(&self, tx: Transaction) -> Transaction {
        let mut mtx = MutableTransaction::from_tx(tx);
        self.tc.validate_mempool_transaction(&mut mtx, &TransactionValidationArgs::default()).unwrap();
        (*mtx.tx).clone()
    }

    fn shutdown(self) {
        self.tc.shutdown(self.handles);
    }
}

/// A node whose private pool holds one real 50,000-zet coin, shielded on chain, with a matured snapshot.
struct Funded {
    node: Node,
    scanner: Scanner,
    coin: OwnedCoin,
    me: Address,
    friend: Address,
}

async fn shield_one_coin_on_chain() -> Funded {
    let mut node = Node::new();

    // Funding: the coinbase of block 3 (it pays block 2's reward to the OpTrue script)
    node.mine_empty(2).await;
    let funding = node.mine(vec![]).await;
    let cb = node.tc.get_block(funding).unwrap().transactions[0].clone();
    assert_eq!(cb.outputs.len(), 1);
    let (cb_id, cb_amount) = (cb.id(), cb.outputs[0].value);
    assert!(cb_amount > SHIELDED + SHIELD_FEE);
    // The next chain block accepts the coinbase into the UTXO set; it is spendable coinbase_maturity later
    node.mine_empty(node.coinbase_maturity + 2).await;

    // Shielding tx: the real visible input and change output first, then the private payment bound to them
    let wallet = PrivateWallet::from_seed(&[5; 32]);
    let (me, friend) = (wallet.address(), PrivateWallet::friend_of(&[5; 32]).address());
    let change = TransactionOutput::new(cb_amount - SHIELDED - SHIELD_FEE, ScriptPublicKey::from_vec(0, vec![OpTrue]));
    let input = TransactionInput::new(TransactionOutpoint::new(cb_id, 0), vec![], 0, 0);
    let mut shield = Transaction::new_non_finalized(TX_VERSION, vec![input], vec![change], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let digest = zethora_private_payment_digest(&shield);
    let payment = shielding_payment(me, SHIELDED, &digest.as_bytes()).unwrap();
    shield.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
    shield.finalize();
    let shield = node.mempool_checked(shield);

    // Mine it; the next chain block accepts it and produces the coin list snapshot (anchor)
    let shield_block = node.mine(vec![shield.clone()]).await;
    let producer = node.mine(vec![]).await;
    assert_eq!(node.accepted_count(producer, shield.id()), 1);
    assert_eq!(shielded_balance(&node.coinbase_payload(shield_block)), 0);
    assert_eq!(shielded_balance(&node.coinbase_payload(producer)), SHIELDED);

    // The wallet scanner, fed the same coins in the same order, reaches the root sealed in the producer's coinbase
    let mut scanner = Scanner::new(vec![wallet, PrivateWallet::friend_of(&[5; 32])]);
    let empty_root = scanner.root();
    assert_eq!(note_root(&node.coinbase_payload(shield_block)), empty_root);
    scanner.add_payment(private_payment_bytes(&shield.payload).unwrap()).unwrap();
    assert_ne!(scanner.root(), empty_root);
    assert_eq!(scanner.root(), note_root(&node.coinbase_payload(producer)));
    scanner.checkpoint().unwrap();

    // anchor_depth + 2 blocks after the shield block (the producer was the first of them)
    node.mine_empty(TEST_ANCHOR_DEPTH + 1).await;

    let coins = scanner.pick_coins(0, SHIELDED).unwrap();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].value(), SHIELDED);
    let coin = coins[0].clone();
    Funded { node, scanner, coin, me, friend }
}

impl Funded {
    /// A fully private spend of the coin: `to_friend` to the friend, the rest minus the fee back to me.
    /// Checked through the mempool path against the current virtual.
    fn spend(&self, to_friend: u64) -> Transaction {
        let mut tx = Transaction::new_non_finalized(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let digest = zethora_private_payment_digest(&tx);
        let outputs = [(self.friend, to_friend), (self.me, SHIELDED - SPEND_FEE - to_friend)];
        let payment = self.scanner.spend_payment(0, std::slice::from_ref(&self.coin), &outputs, &digest.as_bytes()).unwrap();
        tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
        tx.finalize();
        let tx = self.node.mempool_checked(tx);
        assert!(nullifiers(&tx.payload).contains(&self.coin.nullifier));
        tx
    }
}

#[tokio::test]
async fn one_spend_on_chain_is_accepted_once() {
    let mut f = shield_one_coin_on_chain().await;
    let spend = f.spend(30_000);
    let nf = f.coin.nullifier;

    assert_eq!(shielded_balance(&f.node.coinbase_payload(f.node.tip)), SHIELDED);
    let spend_block = f.node.mine(vec![spend.clone()]).await;
    let accepting = f.node.mine(vec![]).await;

    assert_eq!(f.node.accepted_count(spend_block, spend.id()), 0);
    assert_eq!(f.node.accepted_count(accepting, spend.id()), 1);
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![accepting]);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(spend_block)), 50_000);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(accepting)), 49_000);

    f.node.shutdown();
}

enum Arrival {
    AB,
    BA,
}

async fn siblings_spending_one_coin(arrival: Arrival) {
    let mut f = shield_one_coin_on_chain().await;
    let nf = f.coin.nullifier;
    // Two different payments of the same coin, both valid against the same tip
    let (spend_a, spend_b) = (f.spend(30_000), f.spend(25_000));
    assert_ne!(spend_a.id(), spend_b.id());

    let parent = f.node.tip;
    let (a, b, c) = (f.node.fresh_hash(), f.node.fresh_hash(), f.node.fresh_hash());
    let (block_a, block_b) = ((a, vec![spend_a.clone()]), (b, vec![spend_b.clone()]));
    let order = match arrival {
        Arrival::AB => [block_a, block_b],
        Arrival::BA => [block_b, block_a],
    };
    for (hash, txs) in order {
        f.node.insert(hash, vec![parent], txs).await;
    }
    // A and B do not see each other
    assert!(!f.node.tc.reachability_service().is_dag_ancestor_of(a, b));
    assert!(!f.node.tc.reachability_service().is_dag_ancestor_of(b, a));

    assert_eq!(f.node.insert(c, vec![a, b], vec![]).await, BlockStatus::StatusUTXOValid);
    assert_eq!(f.node.tc.get_sink(), c);

    // C merged both siblings
    let merged: HashSet<Hash> = f.node.tc.get_block_acceptance_data(c).unwrap().iter().map(|m| m.block_hash).collect();
    assert_eq!(merged, HashSet::from([a, b]));

    // Exactly one of the two spends is accepted, the coin tag is recorded once, and the pool is debited once
    let (accepted_a, accepted_b) = (f.node.accepted_count(c, spend_a.id()), f.node.accepted_count(c, spend_b.id()));
    assert_eq!(accepted_a + accepted_b, 1, "accepted A {accepted_a} times and B {accepted_b} times");
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![c]);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(a)), 50_000);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(b)), 50_000);
    assert_eq!(shielded_balance(&f.node.coinbase_payload(c)), 49_000);

    f.node.shutdown();
}

#[tokio::test]
async fn sibling_spends_of_one_coin_accept_exactly_one_arrival_ab() {
    siblings_spending_one_coin(Arrival::AB).await;
}

#[tokio::test]
async fn sibling_spends_of_one_coin_accept_exactly_one_arrival_ba() {
    siblings_spending_one_coin(Arrival::BA).await;
}
