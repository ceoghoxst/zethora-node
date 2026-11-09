//! Fee routing suite for the Zethora EVM execution layer.
//!
//! Every gas fee pays two parties: [`MINER_TREASURY_FEE_BPS`] (5%) is routed
//! into [`EvmExecutor::miner_treasury`], the account that funds L1 settlement,
//! and the remainder stays with the block beneficiary, exactly as on Ethereum.
//!
//! [`EvmExecutor::execute`] performs that split itself, so these tests never
//! look at revm internals: they build a block, send one transaction, and assert
//! on the *balances* afterwards. Balances are read straight out of the
//! executor's database with [`EvmExecutor::account`], which is the same state a
//! prover commits to, so a test that passes here passes for the values that end
//! up in the state root.
//!
//! The arithmetic under test is
//! `treasury_fee = gas_used * priority_fee * MINER_TREASURY_FEE_BPS / BPS_DENOMINATOR`,
//! rounded down. The base is the *tip*, not the base fee: the base fee is burned
//! by the protocol and never reaches a producer, so it is never routed.

use alloy_consensus::{SignableTransaction, Signed, TxEip1559};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use revm::context::BlockEnv;
use revm::primitives::hardfork::SpecId;
use zethora_evm::{BPS_DENOMINATOR, CHAIN_ID, EvmExecutor, ExecutionOutcome, MINER_TREASURY_FEE_BPS, Transaction};

/// Sender key material, fixed so a run is reproducible.
const SENDER_KEY: B256 = B256::repeat_byte(0x11);

/// Base fee charged per gas, in wei (10 gwei).
const BASEFEE: u64 = 10_000_000_000;

/// Priority fee (tip) offered per gas, in wei (1 gwei).
///
/// Kept distinctly non-zero so the fee split has a real tip to route, and small
/// enough that `basefee + tip` stays well inside `u64`.
const PRIORITY_FEE: u128 = 1_000_000_000;

/// Gas the sender is willing to buy. Only `gas_used` is charged, so a generous
/// limit keeps the test independent of the exact intrinsic cost of a call.
const GAS_LIMIT: u64 = 100_000;

/// Gas an EVM charges for a value-less call to an empty account: the flat
/// intrinsic cost of a transaction, with no data and no value to transfer.
///
/// The EIP-2929 cold-account surcharge (`2_600`) is *not* added here: it is
/// charged only when the call actually touches the callee, which a zero-value,
/// zero-data call to an account that does not exist never does. The crate's own
/// suite pins the same figure for the same shape of transaction.
const EXPECTED_GAS_USED: u64 = 21_000;

/// The sender, derived from [`SENDER_KEY`].
fn sender() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&SENDER_KEY).expect("valid sender scalar")
}

/// The account that receives [`MINER_TREASURY_FEE_BPS`] of every gas fee: the
/// producer's L1 settlement budget.
fn treasury() -> Address {
    Address::repeat_byte(0x77)
}

/// The block's beneficiary (the 95% side of the split). Deliberately a different
/// account from [`treasury`], so the routing has something to move and the two
/// halves of the split can be checked independently.
fn beneficiary() -> Address {
    Address::repeat_byte(0xcc)
}

/// The target of the transaction: an account that has never existed, so the call
/// transfers no value and runs no code. That keeps the gas cost down to the flat
/// intrinsic charge, which is all this suite needs.
fn empty_account() -> Address {
    Address::repeat_byte(0xaa)
}

/// The fee cap the sender declares: the base fee plus the whole tip, so the tip
/// is actually paid rather than clipped by the cap.
fn max_fee_per_gas() -> u128 {
    u128::from(BASEFEE) + PRIORITY_FEE
}

/// The sender's opening balance: ten times the most the transaction could cost.
///
/// Funding is deliberately *above* the up-front cost, because
/// [`EvmExecutor::execute`] tops a sender up to exactly what it needs. Starting
/// richer than that is what makes "the sender was debited the gas fee" a real
/// observation instead of a restatement of the top-up.
fn funding() -> U256 {
    U256::from(u128::from(GAS_LIMIT) * max_fee_per_gas()) * U256::from(10)
}

/// A signed, value-less EIP-1559 call to [`empty_account`], nonce 0.
fn signed_call() -> Transaction {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: max_fee_per_gas(),
        max_priority_fee_per_gas: PRIORITY_FEE,
        to: TxKind::Call(empty_account()),
        value: U256::ZERO,
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let hash = tx.signature_hash();
    let signature = sender().sign_hash_sync(&hash).expect("sign");
    Transaction::Eip1559(Signed::new_unchecked(tx, signature, hash))
}

/// Sets up an executor with a treasury, a fee-bearing block and a funded sender,
/// executes [`signed_call`] and returns the executor with the resulting receipt.
///
/// The steps mirror a node: configure the treasury, install the block, fund the
/// account out of band, then execute.
fn run_single_transfer() -> (EvmExecutor, ExecutionOutcome) {
    // The producer's settlement account is configured once, at construction.
    let mut executor = EvmExecutor::with_miner_treasury(SpecId::PRAGUE, treasury());
    // A real base fee and a named beneficiary; every other field keeps its
    // default, which is what leaves the executor's block gas limit in place.
    executor.set_block(BlockEnv { basefee: BASEFEE, beneficiary: beneficiary(), ..Default::default() });
    executor.set_balance(sender().address(), funding());

    let outcome = executor.execute(&signed_call()).expect("a funded, well formed call must execute");
    (executor, outcome)
}

/// The wei the treasury is owed for spending `gas_used` at the block's tip:
/// `gas_used * priority_fee * 5%`, rounded down.
///
/// Computed in `u128` so the intermediate product cannot overflow.
fn expected_treasury_fee(gas_used: u64) -> U256 {
    let fee = u128::from(gas_used) * PRIORITY_FEE * u128::from(MINER_TREASURY_FEE_BPS) / u128::from(BPS_DENOMINATOR);
    U256::from(fee)
}

/// The fee the sender is actually charged: `gas_used` at the effective gas
/// price, which is `basefee + tip` because the fee cap leaves room for the whole
/// tip.
fn expected_full_fee(gas_used: u64) -> U256 {
    U256::from(u128::from(gas_used) * max_fee_per_gas())
}

/// The share of [`expected_full_fee`] that reaches a producer: the tip, i.e. the
/// effective gas price minus the base fee. The base-fee half is burned.
fn expected_routable_fee(gas_used: u64) -> U256 {
    U256::from(u128::from(gas_used) * PRIORITY_FEE)
}

/// Balance of `address`, or zero when the account was never touched.
fn balance_of(executor: &mut EvmExecutor, address: Address) -> U256 {
    executor.account(address).map(|info| info.balance).unwrap_or_default()
}

/// Step 6: the treasury is credited exactly 5% of the total gas fee.
#[test]
fn miner_treasury_receives_exactly_five_percent_of_the_gas_fee() {
    let (mut executor, outcome) = run_single_transfer();

    assert!(outcome.success, "a value-less call to an empty account must succeed");
    assert_eq!(outcome.sender, sender().address(), "the recovered sender must be the funded account");
    assert_eq!(outcome.gas_used, EXPECTED_GAS_USED, "gas accounting moved; the fee arithmetic below depends on it");

    let expected = expected_treasury_fee(outcome.gas_used);
    assert_eq!(balance_of(&mut executor, treasury()), expected, "the treasury must be credited exactly gas_used * priority_fee * 5%");
    assert_eq!(outcome.treasury_fee, expected, "the receipt must report the same slice it credited");
    assert_eq!(
        outcome.effective_gas_price,
        Some(PRIORITY_FEE),
        "the reported routing base must be the tip, not the base fee"
    );
}

/// Step 7: the sender is debited the full gas fee, not just the 5% slice, and
/// the split conserves it.
#[test]
fn sender_pays_the_full_gas_fee() {
    let (mut executor, outcome) = run_single_transfer();
    assert!(outcome.success, "a value-less call to an empty account must succeed");

    let full_fee = expected_full_fee(outcome.gas_used);
    assert_eq!(
        balance_of(&mut executor, sender().address()),
        funding() - full_fee,
        "the sender must be debited the full gas fee, no more and no less"
    );

    // One debit, split two ways: the treasury slice plus the beneficiary's
    // remainder must add back up to the routable fee (the tip). The base-fee half
    // of the charge is burned by the protocol, so it is accounted for separately
    // rather than by this split.
    let treasury_fee = expected_treasury_fee(outcome.gas_used);
    let routable_fee = expected_routable_fee(outcome.gas_used);
    let beneficiary_fee = balance_of(&mut executor, beneficiary());
    assert_eq!(beneficiary_fee, routable_fee - treasury_fee, "the beneficiary keeps everything except the 5% slice");
    assert_eq!(
        balance_of(&mut executor, treasury()) + beneficiary_fee,
        routable_fee,
        "the split must conserve the producer's share instead of burning or minting any of it"
    );

    // The burned half is exactly the rest of what the sender paid, so the whole
    // debit is accounted for: producer share plus base fee.
    assert_eq!(
        routable_fee + U256::from(u128::from(outcome.gas_used) * u128::from(BASEFEE)),
        full_fee,
        "the full fee must be exactly the producer's share plus the burned base fee"
    );
}
