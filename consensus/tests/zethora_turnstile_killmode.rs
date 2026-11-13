//! Kill-Mode adversarial tests: the Turnstile (supply ledger) and the Nullifier Store (reorg handling).
//!
//! Two attack families, played by an attacker who controls raw transaction payloads and block order:
//!
//!   1. TURNSTILE OVERFLOW — forge a private payment whose public `value_balance` is `i64::MIN`, `i64::MAX`, or the
//!      raw bytes of `u64::MAX`, and try to make the `widen-to-u128` arithmetic in
//!      `consensus/src/processes/zethora_supply.rs` panic or wrap, so a block is accepted whose ledger satisfies
//!      `visible + pool + burned + private > issued` (coins minted from thin air).
//!
//!   2. REORG DOUBLE-SPEND — mine a block that accepts a real private spend (nullifier N), reorg that block off the
//!      selected chain, then resubmit a spend of N on the new chain. If the nullifier store's reorg handling is wrong,
//!      either the respend is refused forever (liveness) or a second spend of N is accepted on one chain (double-spend).
//!
//! These are integration tests: they drive the REAL `zethora_supply` functions and the REAL `TestConsensus` pipeline
//! (real block builder, real virtual processor, real nullifier store) — no mocks. Every assertion names the invariant
//! it protects and the exact outcome an attacker would steal if the production code regressed.
//!
//! Run: `cargo test -p kaspa-consensus --test zethora_turnstile_killmode -- --nocapture`

use kaspa_consensus::{
    model::stores::virtual_state::VirtualStateStoreReader,
    config::ConfigBuilder,
    consensus::test_consensus::TestConsensus,
    params::DEVNET_PARAMS,
    processes::zethora_supply::{self, BlockFlows, NotAccepted, SupplyError},
};
use kaspa_consensus_core::{
    api::ConsensusApi,
    api::args::TransactionValidationArgs,
    block::Block,
    blockstatus::BlockStatus,
    coinbase::{MinerData, PoolState},
    constants::TX_VERSION,
    errors::tx::TxRuleError,
    hashing::tx::zethora_private_payment_digest,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
        TransactionOutput,
    },
    zethora_private::{ACTION_SIZE, PRIVATE_PAYMENT_MAGIC, nullifiers, pool_flows, private_payment_bytes, value_balance},
};
use kaspa_hashes::Hash;
use kaspa_txscript::opcodes::codes::OpTrue;
use std::thread::JoinHandle;
use zethora_shielded::{
    orchard::Address,
    scan::{OwnedCoin, Scanner},
    wallet::{PrivateWallet, shielding_payment},
};

// ---------------------------------------------------------------------------------------------------------------
// Scenario 1 — The Turnstile Overflow (zethora_supply.rs)
// ---------------------------------------------------------------------------------------------------------------

/// A private payment payload with `actions` actions and an 8-byte little-endian `value_balance`, laid out exactly as
/// consensus reads it (`PRIVATE_PAYMENT_MAGIC || version || action_count || actions || flags || value_balance || anchor`).
/// The Orchard proof of such a payment would never check out for these extreme balances; the turnstile must be safe even
/// against a forged proof, which is the whole point of the backstop.
fn private_payment_vb(actions: u16, value_balance_bytes: [u8; 8]) -> Vec<u8> {
    let mut p = PRIVATE_PAYMENT_MAGIC.to_vec();
    p.push(1); // pool version: Orchard1
    p.extend_from_slice(&actions.to_le_bytes());
    p.extend(std::iter::repeat_n(0u8, actions as usize * ACTION_SIZE));
    p.push(0x02); // flags: outputs enabled, spends disabled
    p.extend_from_slice(&value_balance_bytes);
    p.extend_from_slice(&[0u8; 32]); // anchor (unused: no spends)
    p
}

/// I-T1: `i64::MIN` shields 2^63 zets into the private pool. An empty pool holds it, but a full pool must overflow
/// cleanly (CounterOverflow), never wrap to a small balance. A wrapping u64 implementation would return
/// `(u64::MAX + 2^63) mod 2^64 == 2^63 - 1`, minting coins the ledger would then seal.
#[test]
fn i64_min_value_balance_overflows_a_full_pool_as_counter_overflow_not_a_wrap() {
    let payload = private_payment_vb(1, i64::MIN.to_le_bytes());
    let encoded = private_payment_bytes(&payload).unwrap();
    assert_eq!(value_balance(encoded), Some(i64::MIN), "the forged balance must decode to i64::MIN");
    assert_eq!(pool_flows(&payload), Ok(Some((1u64 << 63, 0))), "i64::MIN is a shield of 2^63 zets");

    // An empty pool genuinely holds 2^63 zets after this shield (no overflow: 2^63 < u64::MAX).
    assert_eq!(zethora_supply::turnstile(0, 1u64 << 63, 0), Ok(1u64 << 63));
    // A full pool must refuse it, not wrap.
    assert!(matches!(
        zethora_supply::turnstile(u64::MAX, 1u64 << 63, 0),
        Err(SupplyError::CounterOverflow("private pool"))
    ));
    // The payload-level turnstile refuses it too and leaves the pool untouched.
    let mut pool = u64::MAX;
    assert!(!zethora_supply::turnstile_accepts(&mut pool, &payload));
    assert_eq!(pool, u64::MAX, "a refused payment must not move the pool");
}

/// I-T2: `i64::MAX` unshields 2^63 - 1 zets. That can only ever be paid from a pool that already holds at least that
/// much; an empty pool refuses it (ShieldedPoolNegative). The successful case leaves exactly 2^63 — arithmetic is
/// exact in u128, with no wrap at either extreme.
#[test]
fn i64_max_value_balance_unshields_huge_amount_only_from_a_real_pool() {
    let payload = private_payment_vb(1, i64::MAX.to_le_bytes());
    let encoded = private_payment_bytes(&payload).unwrap();
    assert_eq!(value_balance(encoded), Some(i64::MAX));
    assert_eq!(pool_flows(&payload), Ok(Some((0, i64::MAX as u64))));

    // An empty pool cannot pay 2^63 - 1 zets: the turnstile refuses, no mint.
    assert!(matches!(
        zethora_supply::turnstile(0, 0, i64::MAX as u64),
        Err(SupplyError::ShieldedPoolNegative { value_out, .. }) if value_out == i64::MAX as u64
    ));
    // A pool holding the maximum can pay it, leaving exactly 2^63 (exact u128 arithmetic, no wrap).
    assert_eq!(zethora_supply::turnstile(u64::MAX, 0, i64::MAX as u64), Ok(1u64 << 63));

    let mut pool = 0u64;
    assert!(!zethora_supply::turnstile_accepts(&mut pool, &payload));
    assert_eq!(pool, 0);
    let mut pool = u64::MAX;
    assert!(zethora_supply::turnstile_accepts(&mut pool, &payload));
    assert_eq!(pool, 1u64 << 63);
}

/// I-T3: the raw bytes of `u64::MAX` decode as the *signed* value balance -1, not a gigantic 2^64 - 1 unshield. An
/// attacker who stuffs `u64::MAX` into the value-balance field actually shields a single zet, and even that still
/// overflows a full pool cleanly rather than wrapping.
#[test]
fn u64_max_value_balance_is_signed_minus_one_not_a_huge_unshield() {
    // u64::MAX.to_le_bytes() == (-1i64).to_le_bytes() == [0xFF; 8]
    let payload = private_payment_vb(1, u64::MAX.to_le_bytes());
    let encoded = private_payment_bytes(&payload).unwrap();
    assert_eq!(value_balance(encoded), Some(-1));
    assert_eq!(pool_flows(&payload), Ok(Some((1, 0))), "u64::MAX reads as a shield of 1 zet, not a 2^64-1 unshield");

    assert_eq!(zethora_supply::turnstile(0, 1, 0), Ok(1));
    assert!(matches!(
        zethora_supply::turnstile(u64::MAX, 1, 0),
        Err(SupplyError::CounterOverflow("private pool"))
    ));
}

/// I-T4: `check_balanced` sums the four held counters in u128. A naive u64 sum of `u64::MAX + 1 + 0 + 0` wraps to 0
/// and would "balance" against `issued = 0`, minting a ledger that passes. The u128 widening must reject it.
#[test]
fn check_balanced_widens_to_u128_so_a_wrapping_u64_sum_cannot_balance() {
    let state = PoolState { transparent_supply: u64::MAX, pool_balance: 1, total_burned: 0, shielded_balance: 0, total_issued: 0 };
    assert_eq!(
        zethora_supply::check_balanced(&state),
        Err(SupplyError::Unbalanced { transparent: u64::MAX, pool: 1, burned: 0, shielded: 0, issued: 0 }),
        "u64::MAX + 1 must not wrap to 0 and balance against issued = 0"
    );

    // Positive control: the same magnitude of numbers, when they genuinely add up, is accepted — the check is exact,
    // not a blanket rejection of big numbers.
    let balanced = PoolState {
        transparent_supply: u64::MAX - 2,
        pool_balance: 1,
        total_burned: 1,
        shielded_balance: 0,
        total_issued: u64::MAX,
    };
    assert_eq!(zethora_supply::check_balanced(&balanced), Ok(()));
}

/// I-T5: `ledger_step` uses `checked_add`, `u64::try_from`, the cap and the turnstile so that an overflowing block is
/// refused with a precise error — never a panic and never a wrapped value the block would then seal.
#[test]
fn ledger_step_refuses_overflowing_flows_with_errors_not_wraps() {
    // Issuing u64::MAX zets in one block is caught by the hard cap, not wrapped into a small "issued".
    assert!(matches!(
        zethora_supply::ledger_step(PoolState::default(), PoolState::default(), BlockFlows { issued: u64::MAX, ..Default::default() }),
        Err(SupplyError::CapExceeded { issued }) if issued == u64::MAX
    ));

    // A parent already at u64::MAX issued plus one more is a counter overflow, not a wrap.
    let parent = PoolState { total_issued: u64::MAX, ..Default::default() };
    assert!(matches!(
        zethora_supply::ledger_step(parent, PoolState::default(), BlockFlows { issued: 1, ..Default::default() }),
        Err(SupplyError::CounterOverflow("total issued"))
    ));

    // Pulling u64::MAX out of an empty private pool is a negative-pool refusal, not a mint.
    assert!(matches!(
        zethora_supply::ledger_step(PoolState::default(), PoolState::default(), BlockFlows { shielded_out: u64::MAX, ..Default::default() }),
        Err(SupplyError::ShieldedPoolNegative { value_out, .. }) if value_out == u64::MAX
    ));

    // A visible-supply wrap (u64::MAX visible + 1) must be caught by the i128 -> u64 try_from.
    let parent = PoolState { transparent_supply: u64::MAX, ..Default::default() };
    assert!(matches!(
        zethora_supply::ledger_step(parent, PoolState::default(), BlockFlows { visible_change: 1, ..Default::default() }),
        Err(SupplyError::VisibleSupplyOutOfRange(v)) if v == u64::MAX as i128 + 1
    ));
}

/// I-T6: the in-order turnstile (`private_in_order_accepts`) refuses an `i64::MAX` unshield against an empty pool
/// without consuming coin-list room or touching the balance — the same rule that stops a reordered block from dipping
/// the pool below zero.
#[test]
fn in_order_rule_refuses_an_i64_max_unshield_without_touching_the_pool() {
    let payload = private_payment_vb(1, i64::MAX.to_le_bytes());
    let (mut pool, mut room) = (0u64, u64::MAX);
    assert_eq!(
        zethora_supply::private_in_order_accepts(&mut pool, &mut room, &payload),
        Err(NotAccepted::Turnstile)
    );
    assert_eq!((pool, room), (0, u64::MAX), "a refused payment changes neither the pool nor the coin-list room");
}

// ---------------------------------------------------------------------------------------------------------------
// Scenario 2 — The Reorg Double-Spend (nullifier store + real pipeline)
// ---------------------------------------------------------------------------------------------------------------

/// Snapshot depth for these tests (real networks lock 600 in Params; tests may override).
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
        Self {
            tc,
            handles,
            miner,
            tip: config.genesis.hash,
            next_word: 0,
            coinbase_maturity: config.params.coinbase_maturity(),
        }
    }

    fn fresh_hash(&mut self) -> Hash {
        self.next_word += 1;
        Hash::from_u64_word(self.next_word)
    }

    async fn insert(&self, hash: Hash, parents: Vec<Hash>, txs: Vec<Transaction>) -> BlockStatus {
        let block = self.build(hash, parents, txs);
        self.insert_block(block).await
    }

    fn build(&self, hash: Hash, parents: Vec<Hash>, txs: Vec<Transaction>) -> Block {
        self.tc.build_utxo_valid_block_with_parents(hash, parents, self.miner.clone(), txs).to_immutable()
    }

    async fn insert_block(&self, block: Block) -> BlockStatus {
        self.tc.validate_and_insert_block(block).virtual_state_task.await.unwrap()
    }

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

    fn accepted_count(&self, block: Hash, id: TransactionId) -> usize {
        let data = self.tc.get_block_acceptance_data(block).unwrap();
        data.iter().flat_map(|m| m.accepted_transactions.iter()).filter(|e| e.transaction_id == id).count()
    }

    fn mempool_checked(&self, tx: Transaction) -> Transaction {
        let mut mtx = MutableTransaction::from_tx(tx);
        self.tc.validate_mempool_transaction(&mut mtx, &TransactionValidationArgs::default()).unwrap();
        (*mtx.tx).clone()
    }

    fn shutdown(self) {
        self.tc.shutdown(self.handles);
    }
}

/// The real mempool path for a transaction, returning the node's error instead of panicking (so a double-spend can be
/// asserted, not merely observed as a panic).
fn mempool(node: &Node, tx: &Transaction) -> Result<(), TxRuleError> {
    node.tc.validate_mempool_transaction(&mut MutableTransaction::from_tx(tx.clone()), &TransactionValidationArgs::default())
}

/// Inserts a block on `parent` without requiring it to become the sink (a reorg branch may not be the sink yet).
async fn add_on(node: &mut Node, parent: Hash, txs: Vec<Transaction>) -> Hash {
    let hash = node.fresh_hash();
    node.insert(hash, vec![parent], txs).await;
    hash
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

    // Funding: the coinbase of block 3 pays block 2's reward to the OpTrue script.
    node.mine_empty(2).await;
    let funding = node.mine(vec![]).await;
    let cb = node.tc.get_block(funding).unwrap().transactions[0].clone();
    assert_eq!(cb.outputs.len(), 1);
    let (cb_id, cb_amount) = (cb.id(), cb.outputs[0].value);
    assert!(cb_amount > SHIELDED + SHIELD_FEE);
    node.mine_empty(node.coinbase_maturity + 2).await;

    // The shield: a real visible input and change output, then the private payment bound to them.
    let wallet = PrivateWallet::from_seed(&[5; 32]);
    let (me, friend) = (wallet.address(), PrivateWallet::friend_of(&[5; 32]).address());
    let change = TransactionOutput::new(cb_amount - SHIELDED - SHIELD_FEE, ScriptPublicKey::from_vec(0, vec![OpTrue]));
    let input = TransactionInput::new(TransactionOutpoint::new(cb_id, 0), vec![], 0, 0);
    let mut shield = Transaction::new_non_finalized(TX_VERSION, vec![input], vec![change], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let digest = zethora_private_payment_digest(&shield, &DEVNET_PARAMS.genesis.hash);
    let payment = shielding_payment(me, SHIELDED, &digest.as_bytes()).unwrap();
    shield.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
    shield.finalize();
    let shield = node.mempool_checked(shield);

    let shield_block = node.mine(vec![shield.clone()]).await;
    let producer = node.mine(vec![]).await;
    assert_eq!(node.accepted_count(producer, shield.id()), 1);
    assert_eq!(shielded_balance(&node.coinbase_payload(shield_block)), 0);
    assert_eq!(shielded_balance(&node.coinbase_payload(producer)), SHIELDED);

    // The wallet scanner, fed the same payment in the same order, reaches the root sealed in the producer's coinbase.
    let mut scanner = Scanner::new(vec![wallet, PrivateWallet::friend_of(&[5; 32])]);
    let empty_root = scanner.root();
    assert_eq!(note_root(&node.coinbase_payload(shield_block)), empty_root);
    scanner.add_payment(private_payment_bytes(&shield.payload).unwrap()).unwrap();
    assert_ne!(scanner.root(), empty_root);
    assert_eq!(scanner.root(), note_root(&node.coinbase_payload(producer)));
    scanner.checkpoint().unwrap();

    // anchor_depth + 2 blocks after the shield block (the producer was the first of them).
    node.mine_empty(TEST_ANCHOR_DEPTH + 1).await;

    let coins = scanner.pick_coins(0, SHIELDED).unwrap();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].value(), SHIELDED);
    let coin = coins[0].clone();
    Funded { node, scanner, coin, me, friend }
}

impl Funded {
    /// A fully private spend of the coin: `to_friend` to the friend, the rest minus the fee back to me. Checked through
    /// the mempool path against the current virtual, so it is valid exactly while the coin is unspent there.
    fn spend(&self, to_friend: u64) -> Transaction {
        let mut tx = Transaction::new_non_finalized(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let digest = zethora_private_payment_digest(&tx, &DEVNET_PARAMS.genesis.hash);
        let outputs = [(self.friend, to_friend), (self.me, SHIELDED - SPEND_FEE - to_friend)];
        let payment = self.scanner.spend_payment(0, std::slice::from_ref(&self.coin), &outputs, &digest.as_bytes()).unwrap();
        tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
        tx.finalize();
        let tx = self.node.mempool_checked(tx);
        assert!(nullifiers(&tx.payload).contains(&self.coin.nullifier));
        tx
    }
}

/// I-R1: one private coin, two spends. The first is accepted exactly once and recorded in the nullifier store; the
/// second, submitted to the mempool on the same chain, is refused with the node's exact double-spend error. This is the
/// "mint infinite / double-spend a shielded note" attack, stopped at the UTXO context.
#[tokio::test]
async fn a_second_spend_of_the_same_nullifier_on_one_chain_is_refused() {
    let mut f = shield_one_coin_on_chain().await;
    let nf = f.coin.nullifier;
    let s1 = f.spend(30_000);
    let s2 = f.spend(25_000);

    // Positive control: the first spend is accepted exactly once, and the store records the accepting block.
    let _carrier = f.node.mine(vec![s1.clone()]).await;
    let w = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(w, s1.id()), 1);
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![w]);

    // Attack: resubmit the second spend of the same coin (same nullifier) on the same chain.
    assert_eq!(
        mempool(&f.node, &s2),
        Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string()))
    );

    f.node.shutdown();
}

/// I-R2: reorg the block that accepted a spend off the selected chain. The nullifier store keeps the stale record (no
/// undo log — a block that falls off simply stops counting), so the coin becomes spendable again on the new chain;
/// re-spending it there is accepted exactly once, and a third spend is refused. Any deviation here is a mint or a
/// permanent freeze.
#[tokio::test]
async fn a_reorg_unspends_the_nullifier_and_the_coin_is_spendable_once_on_the_new_chain() {
    let mut f = shield_one_coin_on_chain().await;
    let nf = f.coin.nullifier;
    let fork = f.node.tip; // common ancestor both branches extend
    let s1 = f.spend(30_000);
    let s2 = f.spend(25_000);
    let s3 = f.spend(20_000);

    // Branch A: the first spend is accepted at w.
    let _carrier_a = f.node.mine(vec![s1.clone()]).await;
    let w = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(w, s1.id()), 1);
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![w]);

    // Branch B: three empty blocks from the fork point — one longer than branch A's two — so the node reorgs to it.
    let mut b_tip = fork;
    for _ in 0..3 {
        b_tip = add_on(&mut f.node, b_tip, vec![]).await;
    }
    assert_eq!(f.node.tc.get_sink(), b_tip, "the node must reorg onto branch B, invalidating the spend block");
    f.node.tip = b_tip;

    // The store was not cleaned on the reorg: the stale accepting block w is still recorded ...
    assert_eq!(f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf), vec![w]);
    // The virtual still re-merges the reorged-off branch and re-accepts s1's spend (its tag lands in the mergeset) ...
    let virtual_nullifiers = f.node.tc.virtual_stores().read().state.get().unwrap().mergeset_nullifiers.clone();
    assert!(virtual_nullifiers.contains(&nf), "the virtual re-accepts the reorged-off spend");
    // ... but that re-acceptance no longer counts: w is off the selected chain, so the double-spend check must verify
    // that an accepting block is a chain ancestor of the tip before refusing, and the mempool accepts s2.
    assert_eq!(mempool(&f.node, &s2), Ok(()), "the reorg must un-spend the nullifier on the new chain");

    // Re-spending on the new chain is accepted exactly once, and the store lists both accepting blocks.
    let _carrier_b = f.node.mine(vec![s2.clone()]).await;
    let w2 = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(w2, s2.id()), 1);
    let accepting = f.node.tc.zethora_nullifiers_store().accepting_blocks(&nf);
    assert_eq!(accepting.len(), 2, "both the stale and the new accepting blocks must be recorded");
    assert!(accepting.contains(&w), "the stale accepting block must stay recorded (it no longer counts)");
    assert!(accepting.contains(&w2), "the new accepting block must be recorded");

    // And a third spend of the same nullifier on the new chain is refused again: no double-spend, ever.
    assert_eq!(
        mempool(&f.node, &s3),
        Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string()))
    );

    f.node.shutdown();
}
