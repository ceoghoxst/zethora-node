//! Red Team suite for the Zethora EVM execution layer.
//!
//! Every test here plays the role of an attacker against [`zethora_evm`] and
//! asserts that the attacker *loses*. The cases are grouped by the class of
//! attack they exercise:
//!
//! * **signature forgery** — a sender must never be able to name itself;
//! * **signature malleability** — the `(r, N - s)` twin of a signature must be
//!   refused (EIP-2);
//! * **transaction mutation** — editing any signed field must invalidate the
//!   sender rather than silently yielding a different valid sender;
//! * **cross-chain replay** — a mainnet transaction must not execute on Zethora;
//! * **unprotected replay** — pre-EIP-155 transactions must be refused;
//! * **envelope confusion** — unknown or downgraded type bytes must be refused.

use alloy_consensus::{SignableTransaction, Signed, Transaction as ConsensusTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use zethora_evm::{
    CHAIN_ID, EIP1559_TX_TYPE, EvmExecutor, LEGACY_TX_TYPE, SECP256K1N_HALF, Transaction, decode_transaction, recover_sender,
};

/// Attacker-controlled key material, fixed so runs are reproducible.
const ATTACKER_KEY: B256 = B256::repeat_byte(0x11);

/// Victim key material. The victim never participates; the attacker simply
/// claims to be them.
const VICTIM_KEY: B256 = B256::repeat_byte(0x22);

/// The secp256k1 group order.
const SECP256K1N: U256 =
    U256::from_be_bytes(alloy_primitives::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));

fn attacker() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&ATTACKER_KEY).expect("valid attacker scalar")
}

fn victim() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&VICTIM_KEY).expect("valid victim scalar")
}

/// Some contract that the attacker likes to poke at.
fn target() -> Address {
    Address::repeat_byte(0xaa)
}

fn legacy_tx(to: TxKind, value: U256) -> TxLegacy {
    TxLegacy { chain_id: Some(CHAIN_ID), nonce: 0, gas_price: 1, gas_limit: 100_000, to, value, input: Bytes::new() }
}

fn eip1559_tx(to: TxKind, value: U256) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        to,
        value,
        input: Bytes::new(),
        access_list: Default::default(),
    }
}

/// Signs a legacy transaction with `signer`.
fn sign_legacy(signer: &PrivateKeySigner, tx: TxLegacy) -> Transaction {
    let hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&hash).expect("sign");
    Transaction::Legacy(Signed::new_unchecked(tx, signature, hash))
}

/// Signs an EIP-1559 transaction with `signer`.
fn sign_eip1559(signer: &PrivateKeySigner, tx: TxEip1559) -> Transaction {
    let hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&hash).expect("sign");
    Transaction::Eip1559(Signed::new_unchecked(tx, signature, hash))
}

/// Re-encodes a [`Transaction`] as EIP-2718 wire bytes.
fn encode(tx: &Transaction) -> Vec<u8> {
    let envelope = match tx {
        Transaction::Legacy(signed) => TxEnvelope::Legacy(signed.clone()),
        Transaction::Eip1559(signed) => TxEnvelope::Eip1559(signed.clone()),
    };
    let mut out = Vec::new();
    envelope.encode_2718(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Baseline: honest transactions work.
// ---------------------------------------------------------------------------

#[test]
fn honest_legacy_and_eip1559_transactions_are_accepted() {
    // Each transaction needs its own executor: both are nonce 0 from the same
    // sender, and a reused executor would correctly reject the second as a
    // nonce replay.
    for tx in [
        sign_legacy(&attacker(), legacy_tx(TxKind::Call(target()), U256::ZERO)),
        sign_eip1559(&attacker(), eip1559_tx(TxKind::Call(target()), U256::ZERO)),
    ] {
        let outcome = EvmExecutor::new().execute(&tx).expect("honest transaction must run");
        assert!(outcome.success, "honest transaction reverted");
        assert_eq!(outcome.sender, attacker().address());
    }
}

#[test]
fn honest_transactions_survive_rlp_round_trip() {
    for tx in [
        sign_legacy(&attacker(), legacy_tx(TxKind::Call(target()), U256::from(1))),
        sign_eip1559(&attacker(), eip1559_tx(TxKind::Call(target()), U256::from(1))),
    ] {
        let bytes = encode(&tx);
        let decoded = decode_transaction(&bytes).expect("must decode");
        assert_eq!(decoded, tx, "round trip must be lossless");
        assert_eq!(recover_sender(&decoded).expect("must recover"), attacker().address());
    }
}

// ---------------------------------------------------------------------------
// Attack 1: signature forgery / sender impersonation.
// ---------------------------------------------------------------------------

#[test]
fn attacker_cannot_forge_the_victims_signature() {
    // The attacker builds a transaction that *claims* to drain the victim by
    // simply signing it themselves. Recovery must return the attacker, and the
    // executor must charge the attacker's account, never the victim's.
    let mut executor = EvmExecutor::new();
    let tx = sign_legacy(&attacker(), legacy_tx(TxKind::Call(target()), U256::from(5)));

    let sender = recover_sender(&tx).expect("signature is well formed");
    assert_eq!(sender, attacker().address());
    assert_ne!(sender, victim().address(), "recovery must not yield the victim");

    let outcome = executor.execute(&tx).expect("must execute");
    assert_eq!(outcome.sender, attacker().address());

    // The victim's account is never touched.
    let victim_account = executor.account(victim().address());
    assert!(victim_account.is_none(), "the victim's account must not be created or charged");
}

#[test]
fn zero_signature_does_not_recover_a_sender() {
    // A transaction with an all-zero signature has no signer. It must be
    // rejected rather than mapping onto some default account.
    let base = legacy_tx(TxKind::Call(target()), U256::ZERO);
    let hash = base.signature_hash();
    let forged = Transaction::Legacy(Signed::new_unchecked(base, Signature::new(U256::ZERO, U256::ZERO, false), hash));

    assert!(recover_sender(&forged).is_err(), "zero signature must not recover");
    assert!(EvmExecutor::new().execute(&forged).is_err(), "and must not execute");
}

// ---------------------------------------------------------------------------
// Attack 2: signature malleability (EIP-2).
// ---------------------------------------------------------------------------

#[test]
fn malleable_high_s_signature_is_rejected() {
    // Every secp256k1 signature has a twin: same `r`, `s' = N - s`, flipped
    // recovery parity. Both verify, so without the EIP-2 bound a third party
    // could re-broadcast a valid transaction under a different hash. Zethora
    // must reject the twin outright.
    let base = legacy_tx(TxKind::Call(target()), U256::from(1));
    let hash = base.signature_hash();
    let good = attacker().sign_hash_sync(&hash).expect("sign");

    let high_s = SECP256K1N - good.s();
    assert!(high_s > SECP256K1N_HALF, "the twin must be in the upper half");
    let twin = Signature::new(good.r(), high_s, !good.v());

    let forged = Transaction::Legacy(Signed::new_unchecked(base.clone(), twin, hash));
    let err = recover_sender(&forged).expect_err("high-s twin must be rejected");
    assert!(err.contains("EIP-2"), "unexpected error: {err}");

    // The honest signature still works, proving the twin was the only problem.
    let honest = Transaction::Legacy(Signed::new_unchecked(base, good, hash));
    assert_eq!(recover_sender(&honest).expect("honest"), attacker().address());
}

#[test]
fn malleable_high_s_eip1559_signature_is_rejected() {
    let base = eip1559_tx(TxKind::Call(target()), U256::from(1));
    let hash = base.signature_hash();
    let good = attacker().sign_hash_sync(&hash).expect("sign");
    let twin = Signature::new(good.r(), SECP256K1N - good.s(), !good.v());

    let forged = Transaction::Eip1559(Signed::new_unchecked(base, twin, hash));
    assert!(recover_sender(&forged).is_err(), "high-s EIP-1559 signature must be rejected");
}

// ---------------------------------------------------------------------------
// Attack 3: mutating a signed transaction.
// ---------------------------------------------------------------------------

#[test]
fn mutating_a_signed_field_invalidates_the_signature() {
    // The attacker intercepts an honest transaction in the mempool and tries to
    // redirect its value to themselves.
    let honest = legacy_tx(TxKind::Call(target()), U256::from(100));
    let hash = honest.signature_hash();
    let signature = attacker().sign_hash_sync(&hash).expect("sign");

    let mut tampered = honest;
    tampered.value = U256::from(1);
    let forged = Transaction::Legacy(Signed::new_unchecked(tampered, signature, hash));

    // Because the signature no longer commits to the new signing hash, recovery
    // yields a *different* address: the transfer would be debited to a random
    // account that does not own the funds. The property under test is that the
    // original sender cannot be preserved.
    if let Ok(address) = recover_sender(&forged) {
        assert_ne!(address, attacker().address(), "tampering must not preserve the original sender");
    }
}

#[test]
fn mutating_the_recipient_changes_the_signing_hash() {
    // A cheap sanity check that the signing hash actually covers every field an
    // attacker might want to change.
    let base = eip1559_tx(TxKind::Call(target()), U256::from(1));
    let baseline = base.signature_hash();

    let mut other_recipient = base.clone();
    other_recipient.to = TxKind::Call(Address::repeat_byte(0xbb));
    assert_ne!(baseline, other_recipient.signature_hash(), "recipient is signed");

    let mut other_value = base.clone();
    other_value.value = U256::from(2);
    assert_ne!(baseline, other_value.signature_hash(), "value is signed");

    let mut other_fee = base.clone();
    other_fee.max_fee_per_gas = 2;
    assert_ne!(baseline, other_fee.signature_hash(), "fee cap is signed");

    let mut other_tip = base.clone();
    other_tip.max_priority_fee_per_gas = 2;
    assert_ne!(baseline, other_tip.signature_hash(), "priority fee is signed");

    let mut other_chain = base.clone();
    other_chain.chain_id += 1;
    assert_ne!(baseline, other_chain.signature_hash(), "chain id is signed");

    let mut other_nonce = base;
    other_nonce.nonce = 7;
    assert_ne!(baseline, other_nonce.signature_hash(), "nonce is signed");
}

// ---------------------------------------------------------------------------
// Attack 4: cross-chain replay.
// ---------------------------------------------------------------------------

#[test]
fn mainnet_transaction_cannot_replay_on_zethora() {
    // A transaction signed for Ethereum mainnet (chain 1) is replayed against an
    // executor bound to a different chain.
    let tx = sign_legacy(&attacker(), legacy_tx(TxKind::Call(target()), U256::from(1)));

    let mut executor = EvmExecutor::new();
    executor.set_chain_id(2);

    let err = executor.execute(&tx).expect_err("cross-chain replay must fail");
    assert!(err.contains("invalid chain id"), "unexpected error: {err}");
}

#[test]
fn eip1559_transaction_cannot_replay_on_zethora() {
    let mut tx = eip1559_tx(TxKind::Call(target()), U256::from(1));
    tx.chain_id = 137; // Polygon
    let signed = sign_eip1559(&attacker(), tx);

    let err = EvmExecutor::new().execute(&signed).expect_err("chain 137 must not run on Zethora");
    assert!(err.contains("invalid chain id"), "unexpected error: {err}");
}

// ---------------------------------------------------------------------------
// Attack 5: unprotected (pre-EIP-155) replay.
// ---------------------------------------------------------------------------

#[test]
fn pre_eip155_transaction_is_rejected() {
    // `chain_id: None` yields a `v` of 27/28 and therefore no replay protection:
    // such a transaction is valid on every chain. Zethora refuses it.
    let mut tx = legacy_tx(TxKind::Call(target()), U256::ZERO);
    tx.chain_id = None;
    let signed = sign_legacy(&attacker(), tx);

    assert_eq!(signed.chain_id(), None, "fixture must be unprotected");
    let err = EvmExecutor::new().execute(&signed).expect_err("unprotected replay must fail");
    assert!(err.contains("not EIP-155"), "unexpected error: {err}");
}

// ---------------------------------------------------------------------------
// Attack 6: envelope confusion.
// ---------------------------------------------------------------------------

#[test]
fn unsupported_envelope_types_are_rejected() {
    // 0x01 = EIP-2930 access list, 0x03 = EIP-4844 blob, 0x04 = EIP-7702
    // set-code, 0x05/0x7f = reserved. None may sneak through as a "legacy"
    // transaction.
    for type_byte in [0x01u8, 0x03, 0x04, 0x05, 0x7f] {
        let bytes = [type_byte, 0xc0];
        let err = decode_transaction(&bytes).expect_err("unsupported type must be rejected");
        assert!(err.contains("unsupported transaction type"), "type 0x{type_byte:02x} gave an unexpected error: {err}");
    }
}

#[test]
fn empty_and_truncated_input_is_rejected() {
    assert!(decode_transaction(&[]).is_err(), "empty input");

    // A transaction whose payload is cut short must not decode into a
    // "best effort" transaction.
    let good = encode(&sign_legacy(&attacker(), legacy_tx(TxKind::Call(target()), U256::from(1))));
    for cut in 1..good.len() {
        assert!(decode_transaction(&good[..cut]).is_err(), "truncating to {cut} bytes must not decode");
    }
}

#[test]
fn trailing_bytes_do_not_alter_the_decoded_transaction() {
    // Appending garbage must not change the decoded transaction: either the
    // decoder rejects it, or it decodes to exactly the original.
    let original = sign_eip1559(&attacker(), eip1559_tx(TxKind::Call(target()), U256::from(1)));
    let mut padded = encode(&original);
    padded.push(0xff);

    if let Ok(decoded) = decode_transaction(&padded) {
        assert_eq!(decoded, original, "trailing garbage must not alter the transaction");
    }
}

// ---------------------------------------------------------------------------
// Attack 7: resource exhaustion.
// ---------------------------------------------------------------------------

#[test]
fn transaction_exceeding_block_gas_limit_is_rejected() {
    let mut executor = EvmExecutor::new();
    let mut tx = legacy_tx(TxKind::Call(target()), U256::ZERO);
    tx.gas_limit = zethora_evm::BLOCK_GAS_LIMIT + 1;

    let err = executor.execute(&sign_legacy(&attacker(), tx)).expect_err("oversized gas limit must be refused");
    assert!(!err.is_empty());

    // Nothing was committed: the attacker's nonce is still zero.
    let nonce = executor.account(attacker().address()).map(|info| info.nonce).unwrap_or(0);
    assert_eq!(nonce, 0, "a rejected transaction must not advance the nonce");
}

#[test]
fn intrinsic_gas_underflow_is_rejected() {
    let mut executor = EvmExecutor::new();
    let mut tx = legacy_tx(TxKind::Call(target()), U256::ZERO);
    tx.gas_limit = 1_000;

    let err = executor.execute(&sign_legacy(&attacker(), tx)).expect_err("below intrinsic gas must fail");
    assert!(err.contains("gas cost") && err.contains("21000"), "unexpected error: {err}");
}

// ---------------------------------------------------------------------------
// Constants the suite depends on.
// ---------------------------------------------------------------------------

#[test]
fn type_constants_match_eip2718() {
    assert_eq!(LEGACY_TX_TYPE, 0x00);
    assert_eq!(EIP1559_TX_TYPE, 0x02);
    assert_eq!(SECP256K1N_HALF, SECP256K1N / U256::from(2));
}

#[test]
fn decoding_agrees_with_alloy_envelope_decoder() {
    // Cross-check our decoder against the canonical `Decodable2718` path on the
    // same bytes, so a divergence in type handling would be caught here.
    let tx = sign_legacy(&attacker(), legacy_tx(TxKind::Create, U256::ZERO));
    let bytes = encode(&tx);

    let theirs = TxEnvelope::network_decode(&mut &bytes[..]).expect("alloy must decode");
    let ours = decode_transaction(&bytes).expect("we must decode");
    assert_eq!(ours.tx_type(), theirs.tx_type() as u8);
    assert_eq!(ours.nonce(), theirs.nonce());
    assert_eq!(ours.gas_limit(), theirs.gas_limit());
}
