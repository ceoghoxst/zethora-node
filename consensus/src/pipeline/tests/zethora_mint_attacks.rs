// F2 item 8: mint-attack regression tests from red-team Round 1 (re-implemented, not copied).
//
//   1. extreme value balances (i64::MAX / i64::MIN) cannot wrap the fee,
//   2. a forged value-balance byte in a real payment is refused (its signatures no longer match),
//   3. a fee paid from the private pool is counted exactly once in the supply ledger,
//   4. many small withdrawals stop exactly at the pool balance.
//
// CLAUDE.md standing rule: positive control, exact asserts, fail-when-protection-removed (see the PR).

use super::zethora_parallel_nullifier::{SHIELDED, SPEND_FEE, shield_one_coin_on_chain};
use crate::processes::transaction_validator::{TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags};
use crate::processes::zethora_supply::turnstile_accepts;
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::api::args::TransactionValidationArgs;
use kaspa_consensus_core::coinbase::PoolState;
use kaspa_consensus_core::constants::{MAX_ZETS, TX_VERSION};
use kaspa_consensus_core::errors::tx::TxRuleError;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::zethora_private::{PRIVATE_PAYMENT_MAGIC, layout, pool_flows, value_balance};
use kaspa_hashes::Hash;

/// A payload declaring a private payment with `value_balance` (only the fields consensus reads without decoding)
fn fake_payment(value_balance: i64) -> Vec<u8> {
    let mut p = PRIVATE_PAYMENT_MAGIC.to_vec();
    p.push(1); // pool version
    p.extend_from_slice(&1u16.to_le_bytes()); // one action
    p.extend(std::iter::repeat_n(0u8, layout::ACTION_SIZE));
    p.push(0); // flags
    p.extend_from_slice(&value_balance.to_le_bytes());
    p
}

fn validator() -> TransactionValidator {
    TransactionValidator::new_for_tests(1000, 1000, 10_000, 150, 150, 100, 18, Default::default())
}

/// The fee rule (fee = visible in + pool out - visible out - pool in) for a transaction with these visible amounts
fn fee(visible_in: &[u64], visible_out: &[u64], payload: Vec<u8>) -> Result<u64, TxRuleError> {
    let inputs = visible_in
        .iter()
        .enumerate()
        .map(|(i, _)| TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(i as u64 + 1), 0), vec![], 0, 0))
        .collect();
    let outputs = visible_out.iter().map(|v| TransactionOutput::new(*v, ScriptPublicKey::from_vec(0, vec![0x51]))).collect();
    let tx = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload);
    let entries: Vec<UtxoEntry> =
        visible_in.iter().map(|v| UtxoEntry::new(*v, ScriptPublicKey::from_vec(0, vec![0x51]), 0, false, None)).collect();
    let tv = validator();
    // Commit the storage mass the way a wallet does, so only the fee rule is under test
    let populated = PopulatedTransaction::new(&tx, entries);
    tx.set_storage_mass(tv.mass_calculator.calc_contextual_masses(&populated).unwrap().storage_mass);
    tv.validate_populated_transaction_and_get_fee(&populated, 1_000, 1_000, TxValidationFlags::SkipScriptChecks, None, None)
}

#[test]
fn extreme_value_balances_cannot_wrap_the_fee() {
    // Positive controls: the fee is exactly what leaves the pool, or what is left after shielding
    assert_eq!(fee(&[], &[], fake_payment(1_000)), Ok(1_000));
    assert_eq!(fee(&[10_000], &[], fake_payment(-9_000)), Ok(1_000));
    assert_eq!(fee(&[10_000], &[4_000], fake_payment(-6_000)), Ok(0));
    assert_eq!(fee(&[], &[], fake_payment(MAX_ZETS as i64)), Ok(MAX_ZETS)); // the turnstile, not the fee rule, caps this

    // The readers never wrap either: i64::MIN is 2^63 zets INTO the pool
    assert_eq!(value_balance(&fake_payment(i64::MIN)[4..]), Some(i64::MIN));
    assert_eq!(pool_flows(&fake_payment(i64::MIN)), Ok(Some((1u64 << 63, 0))));
    assert_eq!(pool_flows(&fake_payment(i64::MAX)), Ok(Some((0, i64::MAX as u64))));

    // i64::MAX out of the pool: above the most value that can exist
    assert_eq!(fee(&[], &[], fake_payment(i64::MAX)), Err(TxRuleError::InputAmountTooHigh));
    assert_eq!(fee(&[], &[], fake_payment(MAX_ZETS as i64 + 1)), Err(TxRuleError::InputAmountTooHigh));
    // ... also when added to visible inputs
    assert_eq!(fee(&[MAX_ZETS], &[], fake_payment(1)), Err(TxRuleError::InputAmountTooHigh));
    // i64::MIN into the pool: more than the transaction has
    assert_eq!(fee(&[], &[], fake_payment(i64::MIN)), Err(TxRuleError::SpendTooHigh(1u64 << 63, 0)));
    assert_eq!(fee(&[10_000], &[], fake_payment(i64::MIN)), Err(TxRuleError::SpendTooHigh(1u64 << 63, 10_000)));
    assert_eq!(fee(&[10_000], &[1], fake_payment(i64::MIN + 1)), Err(TxRuleError::SpendTooHigh(1u64 << 63, 10_000)));
    // One zet more into the pool than the visible side has
    assert_eq!(fee(&[10_000], &[], fake_payment(-10_001)), Err(TxRuleError::SpendTooHigh(10_001, 10_000)));
}

#[test]
fn many_small_withdrawals_stop_exactly_at_the_pool_balance() {
    // 10,000 zets in the pool, 2,000 withdrawals of 7: exactly floor(10,000 / 7) = 1,428 are accepted, 4 zets stay
    let mut remaining = 10_000u64;
    let small = fake_payment(7);
    let accepted = (0..2_000).filter(|_| turnstile_accepts(&mut remaining, &small)).count();
    assert_eq!(accepted, 1_428);
    assert_eq!(remaining, 4);
    // The 4 left can be taken exactly, then nothing more, not even one zet
    assert!(!turnstile_accepts(&mut remaining, &fake_payment(5)));
    assert!(turnstile_accepts(&mut remaining, &fake_payment(4)));
    assert_eq!(remaining, 0);
    assert!(!turnstile_accepts(&mut remaining, &fake_payment(1)));
    assert_eq!(remaining, 0);
    // Extreme withdrawals are refused without touching the balance
    let mut remaining = 10_000u64;
    assert!(!turnstile_accepts(&mut remaining, &fake_payment(i64::MAX)));
    assert_eq!(remaining, 10_000);
    // A huge deposit into an almost full counter is refused, not wrapped
    let mut remaining = u64::MAX - 5;
    assert!(!turnstile_accepts(&mut remaining, &fake_payment(i64::MIN)));
    assert_eq!(remaining, u64::MAX - 5);
}

/// Coinbase payload ledger fields (consensus/src/processes/coinbase.rs serialize_coinbase_payload)
fn ledger(payload: &[u8]) -> PoolState {
    let at = |i: usize| u64::from_le_bytes(payload[16 + 8 * i..24 + 8 * i].try_into().unwrap());
    PoolState { pool_balance: at(0), total_burned: at(1), total_issued: at(2), transparent_supply: at(3), shielded_balance: at(4) }
}

/// Zets outside the private pool: visible coins, the fee pool and what was burned
fn outside(l: &PoolState) -> u128 {
    l.transparent_supply as u128 + l.pool_balance as u128 + l.total_burned as u128
}

#[tokio::test]
async fn a_fee_paid_from_the_pool_is_counted_once_and_forged_value_balances_are_refused() {
    let mut f = shield_one_coin_on_chain().await;
    let spend = f.spend(30_000);
    assert_eq!(pool_flows(&spend.payload), Ok(Some((0, SPEND_FEE))));

    // --- a forged value-balance byte: the payment no longer matches its signatures ---
    let vb_at = PRIVATE_PAYMENT_MAGIC.len()
        + layout::trailer_offset(kaspa_consensus_core::zethora_private::action_count(&spend.payload[4..]).unwrap()).unwrap()
        + layout::VALUE_BALANCE_OFFSET;
    let forge = |value_balance: i64| {
        let mut tx = spend.clone();
        tx.payload[vb_at..vb_at + 8].copy_from_slice(&value_balance.to_le_bytes());
        tx.finalize();
        tx
    };
    let mempool = |tx: &Transaction| {
        f.node.tc.validate_mempool_transaction(&mut MutableTransaction::from_tx(tx.clone()), &TransactionValidationArgs::default())
    };
    let forged_proof = Err(TxRuleError::InvalidPrivatePaymentProof("SpendSignature(0)".to_string()));
    // Positive control: the real payment is admitted
    assert_eq!(mempool(&spend), Ok(()));
    // One zet more taken out (1,000 -> 1,001: the miner would get a zet nobody paid)
    assert_eq!(pool_flows(&forge(SPEND_FEE as i64 + 1).payload), Ok(Some((0, SPEND_FEE + 1))));
    assert_eq!(mempool(&forge(SPEND_FEE as i64 + 1)), forged_proof);
    // One zet less, and a big jump: the signatures catch any change
    assert_eq!(mempool(&forge(SPEND_FEE as i64 - 1)), forged_proof);
    assert_eq!(mempool(&forge(SPEND_FEE as i64 + 20_000)), forged_proof); // still fits the pool: reaches the proof check
    // Value balance flipped to "into the pool" (the pool would grow from nothing), or i64::MIN: a payment with no
    // visible input that takes nothing out of the pool has nothing to pay with, refused before the proof check
    assert_eq!(mempool(&forge(-(SPEND_FEE as i64))), Err(TxRuleError::NoTxInputs));
    assert_eq!(mempool(&forge(i64::MIN)), Err(TxRuleError::NoTxInputs));
    // i64::MAX is refused already by the cheap turnstile precheck
    assert_eq!(
        mempool(&forge(i64::MAX)),
        Err(TxRuleError::InvalidPrivatePayment(format!(
            "would take {} zets out of the private pool, which holds {SHIELDED}",
            i64::MAX
        )))
    );

    // --- the honest fee is counted exactly once ---
    let parent = f.node.tip;
    let spend_block = f.node.mine(vec![spend.clone()]).await;
    let accepting = f.node.mine(vec![]).await;
    assert_eq!(f.node.accepted_count(accepting, spend.id()), 1);
    let (before, after) = (ledger(&f.node.coinbase_payload(spend_block)), ledger(&f.node.coinbase_payload(accepting)));
    assert_eq!(after.shielded_balance, before.shielded_balance - SPEND_FEE);
    // Everything outside the pool grew by the new rewards plus the fee that left the pool: once, not twice
    let issued = (after.total_issued - before.total_issued) as u128;
    assert_eq!(outside(&after) - outside(&before), issued + SPEND_FEE as u128);
    // Control: a chain block accepting no private payment moves exactly the new rewards
    let control = (ledger(&f.node.coinbase_payload(parent)), before);
    assert_eq!(outside(&control.1) - outside(&control.0), (control.1.total_issued - control.0.total_issued) as u128);
    // The same, split by where the fee went: the accepting coinbase (subsidies, tips, fee pool payout) plus what the fee
    // pool kept and what was burned is exactly the new rewards plus SPEND_FEE
    let fee_split = (after.pool_balance as i128 - before.pool_balance as i128) + (after.total_burned - before.total_burned) as i128;
    let accepting_cb_out: u64 = f.node.tc.get_block(accepting).unwrap().transactions[0].outputs.iter().map(|o| o.value).sum();
    let visible_growth = after.transparent_supply as i128 - before.transparent_supply as i128;
    assert_eq!(visible_growth, accepting_cb_out as i128); // no visible input or output: only the coinbase adds visible coins
    assert_eq!(visible_growth + fee_split, issued as i128 + SPEND_FEE as i128);

    f.node.shutdown();
}
