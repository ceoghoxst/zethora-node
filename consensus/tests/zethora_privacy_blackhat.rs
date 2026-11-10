//! Black-hat (red-team) integration tests against Zethora's private layer (ZTH-SPEC-006), run against the consensus
//! code a node really executes. Each test plays the attacker, asserts the attack FAILS, and names the rule that stops
//! it, so removing the rule turns the test red.
//!
//! Run: `cargo test -p kaspa-consensus --test zethora_privacy_blackhat -- --nocapture`
//!
//! The three attacks are the ones that hide where a single transaction's own checks cannot see:
//!   * B.1 cross-mergeset nullifier reuse — the same private coin spent twice, split between a block and its mergeset;
//!   * B.2 mempool turnstile crowding — a batch of unshields that only looks affordable in aggregate;
//!   * B.3 coinbase `SHD1` tag smuggling — hiding a "pay me privately" request from a node whose private pool is off.
//!
//! And two second-order attacks, aimed at the fixes themselves:
//!   * S3 padding-nullifier laundering — every payment is padded with an extra action; that action's coin tag, used as a
//!     stand-in for a real coin (so one coin is spent twice) or pointed at a coin someone else owns (so it is poisoned);
//!   * S5 turnstile inflation — the one value balance the pool accounting reads, rewritten to buy a larger unshield than
//!     the pool can pay.
//!
//! What drives them: the real `TransactionValidator` (the isolation check every node runs on every transaction) and
//! the private accounting primitives the private rules are built from — `zethora_supply::{turnstile_accepts,
//! private_in_order_accepts, NotAccepted}` and `zethora_private::{nullifiers, pool_flows, new_coin_count,
//! NOTE_TREE_CAPACITY}`. Three of the rules live in functions that are not public (`check_block_nullifier_reuse`,
//! `check_own_transactions_qualify`, `cumulative_mempool_turnstile`) because they run inside a `BlockBodyProcessor` /
//! `VirtualStateProcessor`, which need a live database and cannot be built from an integration test. Where that is the
//! case the test re-runs the same predicate over the same primitives the node uses, with the source location written
//! next to it, so the two can be diffed line by line.
use kaspa_consensus::{
    params::DEVNET_PARAMS,
    processes::{
        transaction_validator::TransactionValidator,
        zethora_supply::{NotAccepted, private_in_order_accepts, turnstile_accepts},
    },
};
use kaspa_consensus_core::{
    constants::TX_VERSION,
    errors::{block::RuleError, tx::TxRuleError},
    hashing::tx::zethora_private_payment_digest,
    mass::MassCalculator,
    subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE},
    tx::{ComputeCommit, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput},
    zethora_private::{self, ACTION_SIZE, NOTE_TREE_CAPACITY, PRIVATE_PAYMENT_MAGIC},
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::TxScriptCacheCounters;
use std::{collections::HashSet, sync::Arc};
use zethora_shielded::{
    orchard::Address,
    scan::{OwnedCoin, Scanner},
    wallet::{PrivateWallet, shielding_payment},
};

/// The genesis hash this test's "network" signs into every private payment (seam review pack 1 #6).
const GENESIS: Hash = Hash::from_bytes([0x6E; 32]);

/// The attacker's own wallet seed.
const ATTACKER: [u8; 32] = [0xA1; 32];

/// A validator configured the way a node builds it, with private spends toggled as a network would (ZTH-SPEC-006 §7.3:
/// off on testnet and mainnet until the pool has had an outside audit, on for devnet and simnet).
fn validator(private_spends: bool) -> TransactionValidator {
    let params = &DEVNET_PARAMS;
    TransactionValidator::new(
        params.max_tx_inputs,
        params.max_tx_outputs,
        params.max_signature_script_len,
        params.max_script_public_key_len,
        params.coinbase_payload_script_public_key_max_len,
        params.coinbase_maturity(),
        params.ghostdag_k(),
        Arc::new(TxScriptCacheCounters::default()),
        MassCalculator::new_with_consensus_params(params),
        params.mass_per_sig_op,
    )
    .with_zethora_genesis(GENESIS)
    .with_private_spends(private_spends)
}

/// A plain transparent transaction (no private payment). `nonce` only changes its inputs, so two calls give two
/// different transactions — and therefore two different private payment digests, which is what a double spend across
/// two transactions needs.
fn transparent_tx(nonce: u64) -> Transaction {
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint::new(Hash::from_u64_word(7 + nonce), 0),
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::SigopCount(1.into()),
    };
    let output = TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::from_vec(0, vec![0x51]), covenant: None };
    Transaction::new_non_finalized(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

/// A scanner over a chain holding one real coin of `amount` zets for the attacker, snapshotted so it is spendable.
fn funded_scanner(amount: u64) -> (Scanner, PrivateWallet) {
    let me = PrivateWallet::from_seed(&ATTACKER);
    let mut scanner = Scanner::new(vec![PrivateWallet::from_seed(&ATTACKER)]);
    scanner.add_payment(&shielding_payment(me.address(), amount, &[0x77; 32]).unwrap()).unwrap();
    scanner.checkpoint().unwrap();
    (scanner, me)
}

// ---------------------------------------------------------------------------------------------------------------
// B.1 — Cross-mergeset nullifier reuse: one private coin, spent twice.
// ---------------------------------------------------------------------------------------------------------------

/// The block-level rule `check_block_nullifier_reuse` (pipeline/body_processor/body_validation_in_isolation.rs:138):
/// a private coin tag may appear only once per block. It takes the whole block and skips the coinbase, whose payload is
/// the supply ledger rather than a private payment; here only those non-coinbase transactions are passed in, which is
/// the same set of tags.
fn block_nullifier_reuse(transactions: &[Transaction]) -> Result<(), RuleError> {
    let mut existing = HashSet::new();
    for tag in transactions.iter().flat_map(|tx| zethora_private::nullifiers(zethora_private::private_payload(tx))) {
        if !existing.insert(tag) {
            return Err(RuleError::NullifierReusedInSameBlock(Hash::from_bytes(tag)));
        }
    }
    Ok(())
}

/// The chain-qualification rule `check_own_transactions_qualify` (pipeline/virtual_processor/utxo_validation.rs:901)
/// for a chain block's own non-coinbase transactions, applied in block order: a transaction whose coin tag the block's
/// mergeset already spent, or that the in-order private rules refuse, is not accepted, and the block is disqualified
/// with the node's exact `(invalid, total)` counts. The node hands over the transactions it has already validated in
/// isolation (sorted by index) plus the coinbase, and counts `txs.len() - 1`; the coinbase has no private payment, so
/// passing the non-coinbase transactions in block order is the same rule.
fn own_transactions_qualify(
    transactions: &[Transaction],
    mergeset_nullifiers: &HashSet<[u8; 32]>,
    shielded_balance: u64,
    note_tree_size: u64,
) -> Result<(), RuleError> {
    let mut shielded_balance = shielded_balance;
    let mut coin_room = NOTE_TREE_CAPACITY - note_tree_size;
    let valid = transactions
        .iter()
        .filter(|tx| {
            !zethora_private::nullifiers(zethora_private::private_payload(tx)).iter().any(|tag| mergeset_nullifiers.contains(tag))
                && private_in_order_accepts(&mut shielded_balance, &mut coin_room, &tx.payload).is_ok()
        })
        .count();
    if valid < transactions.len() {
        return Err(RuleError::InvalidTransactionsInUtxoContext(transactions.len() - valid, transactions.len()));
    }
    Ok(())
}

/// Attack: spend one private coin twice. Both spends are genuinely valid transactions — neither knows about the other —
/// so the attacker's hope is that they pass whichever route they take: into one block together, or into two blocks that
/// are processed together (the second one being in the first one's mergeset).
///
/// The attack IS stopped, by the coin's tag (nullifier), which comes out identical in both spends: a block may carry a
/// tag only once (`check_block_nullifier_reuse`), and a chain block's own transaction may not spend a tag its mergeset
/// already spent (`check_own_transactions_qualify`, via `private_double_spend`). Both refusals are asserted below with
/// the node's exact errors.
///
/// Fail-when-removed: if a spend ever produced a fresh tag per payment, the two spends would not share a tag and neither
/// rule would fire — this test goes red.
#[test]
fn the_same_private_coin_cannot_be_spent_twice_across_a_mergeset() {
    // One 50,000-zet private coin, known to the attacker's scanner and snapshotted so it can be spent.
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();

    // The attacker spends it twice, each time in its own transaction and each time paying the coin back to itself, so
    // both spends look harmless on their own (value balance 0: nothing enters or leaves the pool).
    let mut first = transparent_tx(1);
    let first_digest = zethora_private_payment_digest(&first, &GENESIS);
    let first_payment = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &first_digest.as_bytes()).unwrap();
    first.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(first_payment).collect();
    first.finalize();

    let mut second = transparent_tx(2);
    let second_digest = zethora_private_payment_digest(&second, &GENESIS);
    let second_payment = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &second_digest.as_bytes()).unwrap();
    second.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(second_payment).collect();
    second.finalize();
    assert_ne!(first.id(), second.id(), "precondition: two different transactions");

    // Both are valid in isolation. The cryptography cannot see the other spend, so it cannot be the thing that stops
    // this attack: that is the whole point of the attack.
    let pool_open = validator(true);
    assert_eq!(pool_open.validate_tx_in_isolation(&first), Ok(()), "the first spend is valid on its own");
    assert_eq!(pool_open.validate_tx_in_isolation(&second), Ok(()), "the second spend is valid on its own");

    // What ties the two together is the coin's tag, and it is the same in both payments. An Orchard payment of one coin
    // to one address uses two actions (a spend and an output cannot share one), so the payment also carries a padding
    // spend: exactly one tag is shared, and that one is the coin the attacker spent twice.
    let first_tags = zethora_private::nullifiers(&first.payload);
    let second_tags = zethora_private::nullifiers(&second.payload);
    assert_eq!(first_tags.len(), second_tags.len(), "precondition: both payments have the same shape");
    let shared: Vec<[u8; 32]> = first_tags.iter().copied().filter(|tag| second_tags.contains(tag)).collect();
    assert_eq!(shared.len(), 1, "exactly one tag is shared across the two payments: the coin spent twice");
    let tag = shared[0];

    // Route 1 — both spends in one block: refused, naming the reused tag.
    match block_nullifier_reuse(&[first.clone(), second.clone()]) {
        Err(RuleError::NullifierReusedInSameBlock(reused)) => {
            assert_eq!(reused, Hash::from_bytes(tag), "the refusal must name the tag that was reused");
        }
        other => panic!("a block carrying the same private coin tag twice must be refused, got {other:?}"),
    }

    // Route 2 — the spends split across a block and its mergeset: the chain block's own transaction may not spend a tag
    // its mergeset already spent.
    let mergeset: HashSet<[u8; 32]> = [tag].into_iter().collect();
    match own_transactions_qualify(&[second.clone()], &mergeset, 1_000_000, 0) {
        Err(RuleError::InvalidTransactionsInUtxoContext(invalid, total)) => {
            assert_eq!((invalid, total), (1, 1), "the node disqualifies the block with the exact (invalid, total) counts");
        }
        other => panic!("a block whose own transaction re-spends a mergeset tag must be disqualified, got {other:?}"),
    }

    // Controls, so the refusals above are about the tag and not about the transactions: with an empty mergeset the very
    // same transaction qualifies. That also pins the honest limit of route 2 — the mergeset rule does NOT de-duplicate
    // inside the block it is judging (neither spend is in the mergeset, both are value-balance 0), which is exactly why
    // route 1 exists as a separate block rule that runs before any transaction is validated.
    assert!(
        own_transactions_qualify(&[second.clone()], &HashSet::new(), 1_000_000, 0).is_ok(),
        "an unspent tag qualifies: the refusal above is about the mergeset, not about the transaction"
    );
    assert!(
        own_transactions_qualify(&[first.clone(), second.clone()], &HashSet::new(), 1_000_000, 0).is_ok(),
        "the mergeset rule alone does not catch two spends in one block: check_block_nullifier_reuse does"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// B.2 — Mempool turnstile crowding: a batch of unshields that only looks affordable in aggregate.
// ---------------------------------------------------------------------------------------------------------------

/// An encoded private payment (magic included) with `actions` actions and public value balance `value_balance`, laid
/// out byte for byte like the shared `zethora-payment-layout`: `1` pool version, `2` action count (LE), `actions ×
/// ACTION_SIZE`, then the trailer `flags (1) | value balance (8, LE) | anchor (32)`.
///
/// The actions are zeroed on purpose: every rule below reads only the action count (for the coin list) and the value
/// balance (for the pool), and a real payment's actions are covered by its own proof — the cryptographic half of this
/// attack is in `zethora-shielded/tests/attack_tests.rs`, the accounting half is here.
fn payment_payload(actions: u16, value_balance: i64) -> Vec<u8> {
    let mut payload = PRIVATE_PAYMENT_MAGIC.to_vec();
    payload.push(1); // pool version: Orchard
    payload.extend_from_slice(&actions.to_le_bytes());
    payload.extend_from_slice(&vec![0u8; actions as usize * ACTION_SIZE]);
    payload.push(0b11); // flags: this payment has spends and outputs
    payload.extend_from_slice(&value_balance.to_le_bytes());
    payload.extend_from_slice(&[0u8; 32]); // spend anchor
    payload
}

/// A native transaction carrying `payload` — the shape a node's mempool holds a private payment in.
fn tx_with_payment(actions: u16, value_balance: i64) -> Transaction {
    Transaction::new_non_finalized(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, payment_payload(actions, value_balance))
}

/// The mempool batch rule `cumulative_mempool_turnstile` (pipeline/virtual_processor/processor.rs:2001, seam review
/// pack 1 #10): walk the batch in order, refuse every private payment that would take out more than the pool has left,
/// and count only what *leaves* the pool — value brought in does not refill the batch's budget (the same rule the block
/// template uses). Returns, in order, which transactions are accepted and how much pool is left afterwards.
fn mempool_batch(batch: &[Transaction], pool_left: u64) -> (Vec<bool>, u64) {
    let mut left = pool_left;
    let mut accepted = Vec::with_capacity(batch.len());
    for tx in batch {
        let ok = match zethora_private::pool_flows(zethora_private::private_payload(tx)) {
            Ok(Some((_, value_out))) if value_out > left => false,
            Ok(Some((_, value_out))) => {
                left -= value_out;
                true
            }
            // Ordinary transactions always pass (and an unreadable payload is refused by isolation before this rule).
            _ => true,
        };
        accepted.push(ok);
    }
    (accepted, left)
}

/// Attack: crowd the turnstile. The pool holds 500 zets, and the attacker posts a batch of
/// [unshield 400, shield 10,000, unshield 400]. Judged one at a time against the *pool's total*, the shield in the
/// middle looks like it pays for the second unshield (10,000 in, 800 out); judged against its own payment, every
/// unshield is affordable. The attacker's hope is that a node sums the batch, sees a healthy pool and accepts all three,
/// leaving the pool 300 zets short the moment the shield is reorged out or never mined.
///
/// The attack IS stopped, twice: the mempool walk (`cumulative_mempool_turnstile`) budgets only what leaves the pool, so
/// the second unshield is refused once the batch has 100 left; and the in-order rules (`private_in_order_accepts`) refuse
/// a payment that would take the pool below zero and leave the pool and the coin list untouched when they do.
///
/// Fail-when-removed: if the batch rule counted value brought in, the batch would pass and the second unshield would be
/// relayed — this test goes red.
#[test]
fn a_mempool_batch_cannot_crowd_the_turnstile() {
    /// The pool's public balance when the attacker strikes.
    const POOL_LEFT: u64 = 500;

    // The attack batch, exactly in the order the attacker sends it.
    let batch = [
        tx_with_payment(1, 400),     // takes 400 out
        tx_with_payment(1, -10_000), // brings 10,000 in — the "refill" the attacker is counting on
        tx_with_payment(1, 400),     // takes another 400 out
    ];

    // The mempool rule budgets only what leaves the pool, so the middle payment cannot refill it.
    let (accepted, left) = mempool_batch(&batch, POOL_LEFT);
    assert_eq!(accepted, vec![true, true, false], "the second unshield must be refused: the batch has only 100 left");
    assert_eq!(left, 100, "the shield in the middle cannot refill the batch's budget");

    // The block rules do count value in (`turnstile_accepts`, zethora_supply.rs:77), so the same three payments are fine
    // once a block orders them that way: that is why crowding is a mempool rule and not a block rule, and why a decided
    // mempool must not promise more than a block will pay.
    let mut remaining = POOL_LEFT;
    let in_block: Vec<bool> = batch.iter().map(|tx| turnstile_accepts(&mut remaining, &tx.payload)).collect();
    assert_eq!(in_block, vec![true, true, true], "with value in counted, all three fit");
    assert_eq!(remaining, 9_700);

    // In-order private rules (`private_in_order_accepts`, zethora_supply.rs:108): a refused payment changes nothing —
    // not the pool, and not the coin list.
    let mut pool = POOL_LEFT;
    let mut room = NOTE_TREE_CAPACITY;
    assert_eq!(private_in_order_accepts(&mut pool, &mut room, &batch[0].payload), Ok(()));
    assert_eq!((pool, room), (100, NOTE_TREE_CAPACITY - 1), "an accepted payment moves both counters");
    assert_eq!(private_in_order_accepts(&mut pool, &mut room, &batch[2].payload), Err(NotAccepted::Turnstile));
    assert_eq!((pool, room), (100, NOTE_TREE_CAPACITY - 1), "a refused payment changes nothing");

    // Order is part of the rule's input, so the same payments can verdict differently — the rule must be the one that
    // refuses the order in which the pool would go below zero, never the innocent one.
    let mut remaining = POOL_LEFT;
    let drain_first: Vec<bool> = [400i64, 400, -800]
        .iter()
        .map(|value_balance| turnstile_accepts(&mut remaining, &payment_payload(1, *value_balance)))
        .collect();
    assert_eq!(drain_first, vec![true, false, true], "the second unshield of the same batch cannot fit");
    let mut remaining = POOL_LEFT;
    let refill_first: Vec<bool> = [-800i64, 400, 400]
        .iter()
        .map(|value_balance| turnstile_accepts(&mut remaining, &payment_payload(1, *value_balance)))
        .collect();
    assert_eq!(refill_first, vec![true, true, true], "in the other order the pool never runs dry");

    // The same crowding aimed at the coin list (seam review P2-2): a payment may not add more private coins than the
    // list has room for, and a batch cannot spend the room twice.
    let mut pool = POOL_LEFT;
    let mut room = 2;
    assert_eq!(private_in_order_accepts(&mut pool, &mut room, &payment_payload(16, -1)), Err(NotAccepted::CoinListFull));
    assert_eq!((pool, room), (POOL_LEFT, 2), "a refused payment changes nothing");
    assert_eq!(private_in_order_accepts(&mut pool, &mut room, &payment_payload(2, 0)), Ok(()));
    assert_eq!(room, 0, "the two places are gone");
    assert_eq!(private_in_order_accepts(&mut pool, &mut room, &payment_payload(1, 0)), Err(NotAccepted::CoinListFull));
}

// ---------------------------------------------------------------------------------------------------------------
// B.3 — Coinbase `SHD1` tag smuggling: hiding a "pay me privately" request from a node whose private pool is off.
// ---------------------------------------------------------------------------------------------------------------

/// The first four bytes of the miner tag a coinbase carries when the miner wants its reward in a private address
/// (`check_coinbase_shielded_tag`, tx_validation_in_isolation.rs:197).
const SHIELDED_TAG_PREFIX: [u8; 4] = *b"SHD1";

/// The fixed-width head of a coinbase payload: blue score (8) + subsidy (8) + pool state (5 × 8) + coin list root (32) +
/// private state fingerprint (32) + script public key version (2). It ends with the script public key's *length* byte
/// (`processes/coinbase.rs`, `serialize_coinbase_payload`).
const COINBASE_HEAD_LEN: usize = 8 + 8 + 5 * 8 + 32 + 32 + 2;

/// The miner tag `zethora-miner --shielded` writes: `SHD1 | pool version | Orchard address`.
fn shielded_tag() -> Vec<u8> {
    let mut tag = SHIELDED_TAG_PREFIX.to_vec();
    tag.push(1); // Orchard pool version
    tag.extend_from_slice(&[0x33u8; 43]); // Orchard address: diversifier (11) + transmission key (32)
    tag
}

/// The payout script of the coinbases below: a 25-byte pay-to-pubkey-hash script that does NOT contain `SHD1`, so a
/// refusal can only be about the miner tag.
fn payout_script() -> Vec<u8> {
    vec![
        0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16,
    ]
}

/// A coinbase payload laid out byte for byte like `CoinbaseManager::serialize_coinbase_payload`: the fixed head, the
/// script public key version, the script length byte, the script, then the miner tag.
fn coinbase_payload(script: &[u8], miner_tag: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(COINBASE_HEAD_LEN + 1 + script.len() + miner_tag.len());
    payload.extend_from_slice(&9u64.to_le_bytes()); // blue score
    payload.extend_from_slice(&1_000_000u64.to_le_bytes()); // subsidy
    payload.extend_from_slice(&[0u8; 5 * 8]); // Zethora pool state
    payload.extend_from_slice(&[0x11u8; 32]); // coin list root
    payload.extend_from_slice(&[0x22u8; 32]); // private state fingerprint
    payload.extend_from_slice(&0u16.to_le_bytes()); // script public key version
    payload.push(script.len() as u8);
    payload.extend_from_slice(script);
    payload.extend_from_slice(miner_tag);
    payload
}

/// A coinbase paying `script` exactly `1_000_000` zets, carrying `payload`. The node's parser checks the payload's script
/// against this output's script, so the two must be the same bytes (that check is half of what stops the attack).
fn coinbase(payload: Vec<u8>, script: &[u8]) -> Transaction {
    let output =
        TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::from_vec(0, script.to_vec()), covenant: None };
    Transaction::new(TX_VERSION, vec![], vec![output], 0, SUBNETWORK_ID_COINBASE, 0, payload)
}

/// Asserts the coinbase is refused for the reason a closed pool gives: paying a shielded reward needs the private pool,
/// so the refusal is a plain `InvalidPrivatePayment` (never a proof error, so no peer is banned for it).
fn assert_shielded_refusal(v: &TransactionValidator, coinbase: &Transaction) {
    match v.validate_tx_in_isolation(coinbase) {
        Err(TxRuleError::InvalidPrivatePayment(msg)) => {
            assert!(msg.contains("shielded"), "the refusal must say the reward is shielded, got: {msg}");
            assert!(msg.contains("disabled"), "the refusal must say private payments are disabled, got: {msg}");
        }
        other => panic!("a shielded coinbase reward must be refused while the pool is closed, got {other:?}"),
    }
}

/// Attack: get a private reward paid on a network where the private pool is closed (testnet and mainnet until the pool
/// has had an outside audit, ZTH-SPEC-006 §7.3 level (a)). The miner writes `SHD1` in its coinbase and then tries to
/// hide it from the node's parser, so the reward is paid privately while the pool is officially off — a coin nobody can
/// spend. Three shapes are tried: a lying script length byte, the tag smuggled into the fixed head, and a truncated or
/// malformed tag the parser cannot place.
///
/// The attack IS stopped: `check_coinbase_shielded_tag` refuses a payload that carries the tag anywhere a miner tag
/// cannot be placed, so a crafted length byte can never hide the request, and it does not refuse anything that asks for
/// nothing (tag bytes inside the payout script, a payload cut before the miner tag), so one miner's address can never
/// decide whether another miner's block is valid.
///
/// Fail-when-removed: this goes red if the check starts trusting the length byte, or stops consulting the switch.
#[test]
fn a_coinbase_cannot_smuggle_a_shielded_tag_past_a_closed_pool() {
    let script = payout_script();
    let tag = shielded_tag();
    let closed = validator(false);
    let open = validator(true);
    assert!(!closed.private_spends_enabled(), "precondition: this network has the pool closed");

    // Control: an ordinary coinbase is accepted on both networks. Every refusal below is about the request, not about
    // coinbases.
    let ordinary = coinbase(coinbase_payload(&script, b"zethora-miner/v1"), &script);
    assert_eq!(closed.validate_tx_in_isolation(&ordinary), Ok(()), "an ordinary reward is untouched");
    assert_eq!(open.validate_tx_in_isolation(&ordinary), Ok(()));

    // The honest attack: a miner tag that asks for a private reward. Refused, before any other work.
    assert_shielded_refusal(&closed, &coinbase(coinbase_payload(&script, &tag), &script));

    // Smuggling a: a lying script length byte, which is what a parser would use to find the miner tag. Every one of the
    // 256 values must be refused — overstated (the window can't be placed), understated (the window lands inside the
    // script) and the honest length alike, because a length byte is not what decides.
    for script_len in 0u8..=255 {
        let mut smuggled = coinbase_payload(&script, &tag);
        smuggled[COINBASE_HEAD_LEN] = script_len;
        assert_shielded_refusal(&closed, &coinbase(smuggled, &script));
    }

    // Smuggling b: the tag written into the fixed head (here inside the pool-state counters), where no miner tag can
    // ever be, with an honest length byte and an honest-looking miner tag after the script. The node cannot place it,
    // and a payload that carries the bytes is refused.
    let mut in_head = coinbase_payload(&script, b"zethora-miner/v1");
    in_head[30..34].copy_from_slice(&SHIELDED_TAG_PREFIX);
    assert_shielded_refusal(&closed, &coinbase(in_head, &script));

    // Smuggling c: `SHD1` inside the payout script *and* in the extra data, with a length byte that hides the extra
    // data. Counting occurrences decides this one: the payload has the tag more often than the script does, so it is a
    // request even though the parser cannot place it.
    let mut tagged_script = payout_script();
    tagged_script[2..6].copy_from_slice(&SHIELDED_TAG_PREFIX);
    let mut both = coinbase_payload(&tagged_script, &tag);
    both[COINBASE_HEAD_LEN] = 255;
    assert_shielded_refusal(&closed, &coinbase(both, &tagged_script));

    // Smuggling d: a tag with no pool version and no address behind it — the four bytes on their own. A truncated
    // request is still a request: the node cannot say what it means, so it does not accept it on a closed network.
    assert_shielded_refusal(&closed, &coinbase(b"SHD1".to_vec(), &script));

    // The false refusals the fix must not create. (i) `SHD1` inside the payout script only: that is an address, not a
    // request, so the reward is paid. (ii) A payload cut before the miner tag: it carries no request at all.
    assert_eq!(
        closed.validate_tx_in_isolation(&coinbase(coinbase_payload(&tagged_script, b"zethora-miner/v1"), &tagged_script)),
        Ok(()),
        "tag bytes inside the payout script are an address, not a request"
    );
    let mut cut = coinbase_payload(&script, &tag);
    cut.truncate(COINBASE_HEAD_LEN + 1 + script.len());
    assert!(!cut.windows(4).any(|w| w == SHIELDED_TAG_PREFIX), "precondition: the tag was cut off");
    assert_eq!(closed.validate_tx_in_isolation(&coinbase(cut, &script)), Ok(()), "a payload with no tag is never refused");

    // And the documented gap, pinned down so a change to it is noticed: with the pool open the tag is accepted, because
    // paying it out is not implemented yet — the reward still goes to the transparent script the miner named. This is
    // why the smuggling attack only matters while the pool is closed, and why the check must come back the moment the
    // payout is implemented.
    assert_eq!(open.validate_tx_in_isolation(&coinbase(coinbase_payload(&script, &tag), &script)), Ok(()));
    assert_eq!(open.validate_tx_in_isolation(&coinbase(b"SHD1".to_vec(), &script)), Ok(()));
}

// ---------------------------------------------------------------------------------------------------------------
// S3 and S5 — second-order attacks: not against a rule, but against the shape the fix gives a payment.
// ---------------------------------------------------------------------------------------------------------------

/// Where an encoded payment starts inside a transaction payload: right after the `ZSHP` magic. Every offset below is read
/// from the shared `zethora-payment-layout` crate (the one `zethora_private` and the wallet codec both go through) and
/// never from a literal, so a layout change can never silently point a test at the wrong bytes.
const PAYMENT_HEAD: usize = PRIVATE_PAYMENT_MAGIC.len();

/// The bytes of action `action`'s coin tag inside a payload — the window `zethora_private::nullifiers` reads.
fn tag_window(action: usize) -> std::ops::Range<usize> {
    let at = PAYMENT_HEAD
        + zethora_private::layout::action_offset(action).expect("action offset fits")
        + zethora_private::layout::NULLIFIER_OFFSET;
    at..at + zethora_private::layout::FIELD_32
}

/// The bytes of action `action`'s value commitment inside a payload: the only value an action carries, and a commitment
/// rather than a number (ZTH-SPEC-006 §7.4).
fn commitment_window(action: usize) -> std::ops::Range<usize> {
    let at = PAYMENT_HEAD
        + zethora_private::layout::action_offset(action).expect("action offset fits")
        + zethora_private::layout::CV_OFFSET;
    at..at + zethora_private::layout::FIELD_32
}

/// The bytes of the payment-wide value balance in a payload of `actions` actions: the trailer field that starts only after
/// the last action, and the only number `zethora_private::pool_flows` — and so the turnstile — reads.
fn value_balance_window(actions: usize) -> std::ops::Range<usize> {
    let at = PAYMENT_HEAD
        + zethora_private::layout::trailer_offset(actions).expect("trailer offset fits")
        + zethora_private::layout::VALUE_BALANCE_OFFSET;
    at..at + 8
}

/// The transaction `nonce` carrying `payload`, finalized the way a node receives it. The digest a private payment signs
/// does not cover the payload (`zethora_private_payment_digest` encodes with `EXCLUDE_PAYLOAD`), so a payment built for
/// `transparent_tx(nonce)` is valid in every transaction with that nonce — including a doctored copy of its own payload,
/// which is what both attacks below need in order to compare honest bytes against attacked ones.
fn tx_with_payload(nonce: u64, payload: Vec<u8>) -> Transaction {
    let mut tx = transparent_tx(nonce);
    tx.payload = payload;
    tx.finalize();
    tx
}

/// A real private payment built by the wallet's own spend path (`Scanner::spend_payment`): it spends `coins` of wallet 0
/// of `scanner` into `outputs` inside the transaction `nonce`, and comes back as the transaction a node would receive.
/// The digest is taken from the bare transaction first and the payload is attached afterwards, in the order the wallet
/// and the node agree on.
fn real_spend(nonce: u64, scanner: &Scanner, coins: &[OwnedCoin], outputs: &[(Address, u64)]) -> Transaction {
    let digest = zethora_private_payment_digest(&transparent_tx(nonce), &GENESIS);
    let payment = scanner.spend_payment(0, coins, outputs, &digest.as_bytes()).unwrap();
    tx_with_payload(nonce, PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect())
}

/// Which action spends `tag` and which one is the padding Orchard adds (`None` if the payment is not shaped like that,
/// which every caller asserts before relying on it).
fn action_slots(payload: &[u8], tag: [u8; 32]) -> (Option<usize>, Option<usize>) {
    let tags = zethora_private::nullifiers(payload);
    (tags.iter().position(|t| *t == tag), tags.iter().position(|t| *t != tag))
}

// ---------------------------------------------------------------------------------------------------------------
// S3 — Padding-nullifier laundering: the action Orchard pads a payment with, used as a stand-in for a real coin.
// ---------------------------------------------------------------------------------------------------------------

/// Attack: launder a spend through the padding action. An Orchard payment of one coin to one address takes two actions
/// (a spend and an output cannot share one), so the wallet pads it with an action that spends a coin of the payment's own
/// making and adds a second output. That padding action reveals a coin tag like every other action (§6.3), and the attack
/// comes in two directions:
///   a) false negative — write the *real* coin's tag into the padding slot, so one payment spends the same coin twice
///      while showing a single spend;
///   b) false positive — write a *victim's* tag into the padding slot, so the victim's coin looks spent on the chain and
///      can never be spent again (the spent set is sealed into the private state fingerprint of every coinbase, §6.4, so
///      the poisoning would be permanent). Nothing of the attacker's own has to be at stake.
///
/// The attack IS stopped at three layers, each asserted below: the tag list consensus reads is position-blind and is not
/// de-duplicated, so a padding tag is a spent-coin claim exactly like a real one (the accounting rules see both); a
/// payment carrying one tag twice is refused in isolation *before* its proof is checked (§6.3), and refused again by the
/// block rule; and a tag the attacker chose cannot be carried at all, because the tags are public inputs of the payment's
/// proof and are covered by its signatures — the only thing that can stop the censorship direction.
///
/// Fail-when-removed: if `nullifiers` skipped the padding action, the collision would look like an ordinary single spend
/// and the mergeset rule would let one coin be spent twice; if isolation lost its duplicate-tag check, the doctored
/// payment would reach the accounting at all. Either change turns this test red.
#[test]
fn a_padding_action_cannot_stand_in_for_a_real_coin() {
    // The attacker's wallet holds one 50,000-zet private coin, and the payment below pays it back to itself: value
    // balance 0, so nothing here can move a pool number and every refusal is about a coin tag.
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();
    assert_eq!(coins.len(), 1, "precondition: one coin is spent");
    let real_tag = coins[0].nullifier;
    let honest = real_spend(31, &scanner, &coins, &[(me.address(), 50_000)]);

    // The pool open network accepts it, and the digest it signed is the one the bare transaction has: the payload is not
    // part of what a payment signs, so every doctored copy below is a transaction the very same payment claims.
    let pool_open = validator(true);
    assert_eq!(pool_open.validate_tx_in_isolation(&honest), Ok(()), "the honest payment is valid");
    assert_eq!(
        zethora_private_payment_digest(&honest, &GENESIS),
        zethora_private_payment_digest(&transparent_tx(31), &GENESIS),
        "evidence: the digest a payment signs does not cover its own payload"
    );

    // What the payment really carries: two actions, one spending the attacker's coin and one padding.
    let tags = zethora_private::nullifiers(&honest.payload);
    assert_eq!(tags.len(), 2, "one coin to one address is padded to two actions");
    assert_eq!(tags.iter().filter(|tag| **tag == real_tag).count(), 1, "exactly one action spends the real coin");
    let (real_action, padding_action) = action_slots(&honest.payload, real_tag);
    let real_action = real_action.expect("the real spend's tag is listed");
    let padding_action = padding_action.expect("the padding action's tag is listed too");
    let padding_tag = tags[padding_action];
    assert_ne!(padding_action, real_action);
    assert_ne!(padding_tag, real_tag, "the padding action spends a coin of its own, so it reveals a tag of its own");

    // Layer 1 — the accounting cannot tell the slots apart, and must not try. A mergeset that spent the *padding* tag
    // refuses the payment exactly as one that spent the real tag does: there is no inert slot to hide a spend in.
    for (slot, tag) in [("real", real_tag), ("padding", padding_tag)] {
        match own_transactions_qualify(&[honest.clone()], &HashSet::from([tag]), 1_000_000, 0) {
            Err(RuleError::InvalidTransactionsInUtxoContext(invalid, total)) => {
                assert_eq!((invalid, total), (1, 1), "a mergeset that spent the {slot} tag disqualifies the payment");
            }
            other => panic!("a payment whose {slot} tag its mergeset already spent must be refused, got {other:?}"),
        }
    }
    assert!(
        own_transactions_qualify(&[honest.clone()], &HashSet::new(), 1_000_000, 0).is_ok(),
        "control: with neither tag spent the same payment qualifies"
    );

    // Attack a — the false-negative direction. The bytes stay readable and the tags keep decoding, because a real coin
    // tag is a real curve point: this is not a malformed payload, it is a well-formed one that lies about its slots.
    let mut laundered = honest.payload.clone();
    laundered[tag_window(padding_action)].copy_from_slice(&real_tag);
    assert_eq!(laundered.len(), honest.payload.len(), "the attack does not change the payment's size");
    assert_eq!(
        zethora_private::nullifiers(&laundered).iter().filter(|tag| **tag == real_tag).count(),
        2,
        "the readers report the coin twice: the padding slot is neither skipped nor de-duplicated"
    );

    // Layer 2a — a block may carry a coin tag only once, and this is one payment carrying it twice.
    match block_nullifier_reuse(&[tx_with_payload(31, laundered.clone())]) {
        Err(RuleError::NullifierReusedInSameBlock(reused)) => {
            assert_eq!(reused, Hash::from_bytes(real_tag), "the refusal names the coin that was spent twice");
        }
        other => panic!("a block carrying the same private coin tag twice must be refused, got {other:?}"),
    }

    // Layer 2b — and the node refuses the payment itself, before its proof is even checked: no spent-coin tag may appear
    // twice inside one payment (tx_validation_in_isolation.rs:181). That check is what owns the padding slot.
    match pool_open.validate_tx_in_isolation(&tx_with_payload(31, laundered)) {
        Err(TxRuleError::InvalidPrivatePaymentProof(reason)) => {
            assert!(reason.contains("twice"), "the refusal must name the duplicated tag, got: {reason}");
        }
        other => panic!("a payment carrying one coin tag twice must be refused as forged, got {other:?}"),
    }

    // Attack b — the false-positive direction: point the padding slot at a coin somebody else owns. Nothing in the
    // accounting would notice, because the tags still number two and no rule de-duplicates them.
    const VICTIM: [u8; 32] = [0xB2; 32];
    let victim = PrivateWallet::from_seed(&VICTIM);
    let mut victim_scanner = Scanner::new(vec![PrivateWallet::from_seed(&VICTIM)]);
    victim_scanner.add_payment(&shielding_payment(victim.address(), 70_000, &[0x99; 32]).unwrap()).unwrap();
    victim_scanner.checkpoint().unwrap();
    let victim_coins = victim_scanner.holdings(0).spendable;
    assert_eq!(victim_coins.len(), 1, "precondition: the victim holds one coin");
    let victim_tag = victim_coins[0].nullifier;
    assert_ne!(victim_tag, real_tag, "precondition: two different coins");
    assert_ne!(victim_tag, padding_tag, "precondition: the padding tag is not the victim's");

    let mut poisoned = honest.payload.clone();
    poisoned[tag_window(padding_action)].copy_from_slice(&victim_tag);
    assert!(
        zethora_private::nullifiers(&poisoned).contains(&victim_tag),
        "the doctored payment claims the victim's coin is spent: a reader that trusted it would poison that coin"
    );

    // Layer 3 — what stops this is the cryptography, and here it is the only thing that can: the tags are public inputs
    // of the payment's proof and are covered by its signatures, so a tag the attacker chose cannot be carried at all.
    // Both tags differ here, so the duplication check above cannot fire: the refusal is the proof/signature itself.
    match pool_open.validate_tx_in_isolation(&tx_with_payload(31, poisoned)) {
        Err(TxRuleError::InvalidPrivatePaymentProof(reason)) => {
            assert!(!reason.contains("twice"), "the tag is bound into the payment, not caught by the collision rule: {reason}");
        }
        other => panic!("a payment whose padding tag was rewritten must be refused as forged, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// S5 — Turnstile inflation: rewriting the one value balance the pool accounting reads.
// ---------------------------------------------------------------------------------------------------------------

/// Attack: buy a larger unshield than the pool can pay by inflating the pool from the payment itself. The intuition the
/// attacker bets on is that value sits on *actions* — so the padding action, which adds and takes nothing, could be given
/// a value of its own, or the payment's own number could be edited, and the pool the turnstile reads would grow.
///
/// The attack IS stopped, and not by the accounting: an action's bytes carry a value *commitment* and never a number, and
/// the payment has exactly one value balance, in the trailer after every action (§7.4) — so rewriting an action's
/// commitment leaves the turnstile's number untouched, and rewriting the number itself is caught by the binding signature,
/// which covers both. The order matters and is part of the rule: `zethora_private::{pool_flows, nullifiers}` read bytes
/// and are only trustworthy for payments already checked in isolation.
///
/// The accounting rules are then shown on the forged bytes anyway, because that is what the attacker would be facing if
/// the signature check were ever dropped: the mempool walk is immune (it budgets outflows only, so a batch has no inflow
/// to inflate), while the block walk's turnstile would believe the forged number and accept the oversize unshield. That
/// is the reason the signature — not the accounting — has to be the thing that stops this.
///
/// Fail-when-removed: if isolation stopped covering the value balance (or the commitments) in the signature, the forged
/// payment would be accepted and a 1,800-zet unshield would pass against a pool of 500 — this test goes red.
#[test]
fn a_padding_action_cannot_inflate_the_pool_the_turnstile_reads() {
    // There is no per-action value balance to point at: the payment's trailer starts only after the last action, and an
    // action's bytes end with its encrypted note. The only value an action carries is its commitment.
    assert_eq!(
        zethora_private::layout::trailer_offset(2).unwrap(),
        zethora_private::layout::action_offset(1).unwrap() + ACTION_SIZE,
        "the payment's one value balance starts only after the last action: no action owns one"
    );
    assert_eq!(
        zethora_private::layout::OUT_CIPHERTEXT_OFFSET + zethora_private::layout::OUT_CIPHERTEXT_SIZE,
        ACTION_SIZE,
        "an action's bytes end with its encrypted note: there is no value field inside an action"
    );

    // A real, fully private payment: the attacker's 50,000-zet coin, paid back to itself. The pool neither gains nor
    // loses, so every number below is one the payment does not really have.
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();
    let honest = real_spend(41, &scanner, &coins, &[(me.address(), 50_000)]);
    let pool_open = validator(true);
    assert_eq!(pool_open.validate_tx_in_isolation(&honest), Ok(()), "the honest payment is valid");
    assert_eq!(zethora_private::pool_flows(&honest.payload), Ok(Some((0, 0))), "it moves nothing into or out of the pool");
    let actions = zethora_private::action_count(zethora_private::private_payment_bytes(&honest.payload).expect("a payment"))
        .expect("a readable action count");
    assert_eq!(actions, 2, "precondition: a spend and an output, padded to two actions");
    let (real_action, padding_action) = action_slots(&honest.payload, coins[0].nullifier);
    let real_action = real_action.expect("the real spend's tag is listed");
    let padding_action = padding_action.expect("the padding action's tag is listed too");

    // Attempt 1 — give the padding action a value by rewriting its commitment (to the real action's, so the bytes stay a
    // valid curve point). The turnstile's number does not move, because it never came from an action...
    let mut revalued = honest.payload.clone();
    revalued[commitment_window(padding_action)].copy_from_slice(&honest.payload[commitment_window(real_action)]);
    assert_ne!(revalued, honest.payload, "precondition: the bytes changed");
    assert_eq!(
        zethora_private::pool_flows(&revalued),
        zethora_private::pool_flows(&honest.payload),
        "an action's commitment is not a number the turnstile reads: the padding action cannot move the pool"
    );

    // ...and the payment is refused, because a commitment is a public input of the proof and all of them are tied to the
    // payment's one value balance by the binding signature.
    match pool_open.validate_tx_in_isolation(&tx_with_payload(41, revalued)) {
        Err(TxRuleError::InvalidPrivatePaymentProof(reason)) => {
            assert!(!reason.contains("twice"), "the commitment is bound into the payment, not caught by a format rule: {reason}");
        }
        other => panic!("a payment whose action commitment was rewritten must be refused as forged, got {other:?}"),
    }

    // Attempt 2 — the attack proper: rewrite the one value balance, so the payment claims to bring 10,000 zets into the
    // pool while really bringing nothing. `pool_flows` believes it — that reader trusts the bytes — which is exactly why
    // it runs only on payments that already passed isolation.
    let mut inflated = honest.payload.clone();
    inflated[value_balance_window(actions)].copy_from_slice(&(-10_000i64).to_le_bytes());
    assert_eq!(zethora_private::pool_flows(&inflated), Ok(Some((10_000, 0))), "the raw reader believes the forged number");

    // ...and isolation refuses it: the value balance is part of what the payment proves and signs.
    match pool_open.validate_tx_in_isolation(&tx_with_payload(41, inflated.clone())) {
        Err(TxRuleError::InvalidPrivatePaymentProof(_)) => {}
        other => panic!("a value balance changed by hand must be refused as forged, got {other:?}"),
    }

    // What the accounting would do with the forged bytes if the signature were not there to stop them first. The pool
    // holds 500 zets and the attacker posts [unshield 400, the inflated payment, unshield 1,800]: 1,800 out of what is
    // left of 500 only works if the inflation is believed. (The three transactions are only ever fed to the accounting
    // primitives: each walk reads nothing but the declared value balance, so these bytes are the whole input they see.)
    const POOL_LEFT: u64 = 500;
    let batch = [tx_with_payment(1, 400), tx_with_payload(41, inflated), tx_with_payment(1, 1_800)];

    // The mempool walk budgets only what leaves the pool (`cumulative_mempool_turnstile`), so a batch has no inflow to
    // inflate: the 1,800-zet unshield is refused even with the forged number sitting in front of it.
    let (accepted, left) = mempool_batch(&batch, POOL_LEFT);
    assert_eq!(accepted, vec![true, true, false], "an inflated inflow buys nothing in the batch walk");
    assert_eq!(left, 100, "the batch's budget is its own outflows, and the forgery is not one of them");

    // The block walk does count value in (`turnstile_accepts`, zethora_supply.rs:77), so with the forged number all three
    // payments fit and leave 8,300 zets of pool behind...
    let mut remaining = POOL_LEFT;
    let forged: Vec<bool> = batch.iter().map(|tx| turnstile_accepts(&mut remaining, &tx.payload)).collect();
    assert_eq!(forged, vec![true, true, true], "the forged inflation is exactly what the block turnstile believes");
    assert_eq!(remaining, 8_300);

    // ...and with the number the payment really has, they do not. The forgery is the only difference between a refused
    // block and an accepted one, which is why the binding signature is load-bearing here and the accounting cannot be.
    let mut honest_batch = batch.clone();
    honest_batch[1] = tx_with_payload(41, honest.payload.clone());
    let mut remaining = POOL_LEFT;
    let truthful: Vec<bool> = honest_batch.iter().map(|tx| turnstile_accepts(&mut remaining, &tx.payload)).collect();
    assert_eq!(truthful, vec![true, true, false], "with the number the payment really has, the unshield does not fit");
    assert_eq!(remaining, 100, "the pool keeps the 100 zets it had left: 1,800 never fits");
}
