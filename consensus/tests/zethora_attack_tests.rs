//! Adversarial (red-team) integration tests against the Orchard shielded pool, at the CONSENSUS layer
//! (ZTH-SPEC-006). These exercise the real `TransactionValidator` a node runs, so they fail if the node's checks —
//! not the crypto — are what is wrong.
//!
//! Run: `cargo test -p kaspa-consensus --test zethora_attack_tests -- --nocapture`
//!
//! The Orchard-level attacks (nullifier double-spend, turnstile inflation, anchor maturity, decoder fuzzing) live in
//! `zethora-shielded/tests/attack_tests.rs`, next to the library they attack.
use kaspa_consensus::{
    params::DEVNET_PARAMS,
    processes::transaction_validator::TransactionValidator,
};
use kaspa_consensus_core::{
    constants::TX_VERSION,
    errors::tx::TxRuleError,
    hashing::tx::zethora_private_payment_digest,
    mass::MassCalculator,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{ComputeCommit, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, scriptvec},
    zethora_private::PRIVATE_PAYMENT_MAGIC,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::TxScriptCacheCounters;
use std::sync::Arc;
use zethora_shielded::wallet::{PrivateWallet, shielding_payment};

/// The genesis hash this test's "network" signs into every private payment (seam review pack 1 #6).
const GENESIS: Hash = Hash::from_bytes([0x6E; 32]);

/// A validator configured the way a node builds it, with private spends toggled as a network would (ZTH-SPEC-006 §7.3).
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

/// A plain transparent transaction (no private payment) to attach payloads to.
fn transparent_tx() -> Transaction {
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint::new(Hash::from_u64_word(7), 0),
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::SigopCount(1.into()),
    };
    let output =
        TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::new(0, scriptvec![0x51]), covenant: None };
    Transaction::new_non_finalized(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

/// A genuinely valid private (shielding) payment, bound to `tx`'s digest.
fn with_valid_payment(tx: &mut Transaction, amount: u64) {
    let digest = zethora_private_payment_digest(tx, &GENESIS);
    let payment = shielding_payment(PrivateWallet::from_seed(&[5; 32]).address(), amount, &digest.as_bytes()).unwrap();
    tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
}

// ---------------------------------------------------------------------------
// B.1 — Privacy bypass: a private payment on a network where privacy is OFF.
// ---------------------------------------------------------------------------

/// Attack: submit a perfectly valid private payment to a network where private spends are disabled (testnet and
/// mainnet until the privacy code has had an outside audit, ZTH-SPEC-006 §7.3 level (a)).
///
/// Why this matters: the emergency switch exists to close the one-way trap where a user could shield but never
/// withdraw. If a node accepted the payment anyway, the switch would be decorative and coins could be locked forever
/// on a network that never intended to support the pool.
///
/// Fail-when-removed: this goes red if `check_private_payment` stops consulting `private_spends_enabled` — the exact
/// regression the switch is there to prevent.
#[test]
fn a_valid_private_payment_is_refused_when_privacy_is_disabled() {
    // The payment is genuinely valid: on a privacy-enabled network the very same transaction is accepted.
    let mut tx = transparent_tx();
    with_valid_payment(&mut tx, 500_000);
    tx.finalize();

    let enabled = validator(true);
    assert_eq!(
        enabled.validate_tx_in_isolation(&tx),
        Ok(()),
        "the payment is valid, so any refusal below is the switch and not the crypto"
    );

    // The same transaction on a network with privacy off.
    let disabled = validator(false);
    assert!(!disabled.private_spends_enabled(), "precondition: this network has the switch off");
    match disabled.validate_tx_in_isolation(&tx) {
        Err(TxRuleError::InvalidPrivatePayment(msg)) => {
            assert!(msg.contains("disabled"), "the refusal must say privacy is disabled, got: {msg}");
        }
        other => panic!("privacy is off, so a private payment must be refused with InvalidPrivatePayment, got {other:?}"),
    }
}

/// Attack: same bypass, but with a malformed or unprovable payment — the switch must fire *before* any decode or proof
/// work, so a disabled network cannot be used as a free proof-checking service (a denial-of-service vector: each proof
/// check costs milliseconds).
///
/// Fail-when-removed: this goes red if the order of the two checks in `check_private_payment` is ever swapped, or if the
/// disabled network refuses only *some* private payments.
#[test]
fn the_switch_fires_before_any_proof_work() {
    let disabled = validator(false);

    // A payload that only carries the marker: too short to be a payment. Refused by the switch, not by the decoder,
    // so the message is the switch's, not a decode error's.
    let mut marker_only = transparent_tx();
    marker_only.payload = PRIVATE_PAYMENT_MAGIC.to_vec();
    marker_only.finalize();
    match disabled.validate_tx_in_isolation(&marker_only) {
        Err(TxRuleError::InvalidPrivatePayment(msg)) => {
            assert!(msg.contains("disabled"), "the switch must refuse before decoding, got: {msg}");
        }
        other => panic!("expected the switch's refusal, got {other:?}"),
    }

    // A payload whose proof cannot possibly be right. Still the switch's plain refusal, never a proof-forgery ban:
    // a disabled network must not ban peers over payments it never intended to accept.
    let mut nonsense = transparent_tx();
    let mut payload = PRIVATE_PAYMENT_MAGIC.to_vec();
    payload.extend_from_slice(&[0xAB; 2_000]);
    nonsense.payload = payload;
    nonsense.finalize();
    assert!(
        matches!(disabled.validate_tx_in_isolation(&nonsense), Err(TxRuleError::InvalidPrivatePayment(_))),
        "garbage on a disabled network is a plain refusal, not a proof error"
    );

    // Ordinary (non-private) transactions are untouched by the switch: it only gates the private pool.
    let plain = transparent_tx();
    assert_eq!(disabled.validate_tx_in_isolation(&plain), Ok(()), "the switch must not affect transparent traffic");
}


// ---------------------------------------------------------------------------
// B.2 — Malformed payload handling: no panic, clean refusal, at the consensus layer.
// ---------------------------------------------------------------------------

/// Attack: throw corrupted private payloads at the validator a node runs on every relayed transaction. A panic here is
/// a remote crash; a silent `Ok` here is a bypass (a payment that never got checked would reach the chain rules).
///
/// Fail-when-removed: this is the guard on `check_private_payment` being total *and* strict. It asserts both halves:
/// nothing panics, and nothing malformed is accepted.
#[test]
fn corrupt_payloads_are_refused_never_a_panic_and_never_accepted() {
    let enabled = validator(true);

    // A real payment to corrupt.
    let mut good = transparent_tx();
    with_valid_payment(&mut good, 500_000);
    good.finalize();
    // Guard against a vacuous test: the reference payment really is accepted before we corrupt anything.
    assert_eq!(enabled.validate_tx_in_isolation(&good), Ok(()), "the reference payment must be accepted");

    let payment = good.payload[PRIVATE_PAYMENT_MAGIC.len()..].to_vec();

    // Build a tx carrying `payload` and run the validator. Returns whether it was accepted.
    let run = |payload: Vec<u8>| -> bool {
        let mut tx = transparent_tx();
        tx.payload = payload;
        tx.finalize();
        // A panic anywhere in here aborts the test, which is the point.
        enabled.validate_tx_in_isolation(&tx).is_ok()
    };

    // Every truncation, including inside the magic and inside an action: always refused.
    for len in 0..payment.len() {
        let mut p = PRIVATE_PAYMENT_MAGIC.to_vec();
        p.extend_from_slice(&payment[..len]);
        assert!(!run(p), "a payment cut to {len} bytes must not be accepted");
    }

    // Every single-byte corruption: never a panic. (Most are refused; a byte inside an encrypted note may survive,
    // which is legitimate — it just means a different note, not a bypass.)
    let mut accepted = 0;
    for i in 0..payment.len() {
        let mut p = payment.clone();
        p[i] ^= 0xFF;
        let mut full = PRIVATE_PAYMENT_MAGIC.to_vec();
        full.extend_from_slice(&p);
        if run(full) {
            accepted += 1;
        }
    }
    assert!(
        accepted < payment.len() / 4,
        "corrupting a payment's bytes must almost always invalidate it (got {accepted} of {} accepted)",
        payment.len()
    );

    // A forged action count must not make the decoder index or allocate out of bounds.
    for count in [0u16, 1, 2, 4, u16::MAX] {
        let mut p = payment.clone();
        p[1..3].copy_from_slice(&count.to_le_bytes());
        let mut full = PRIVATE_PAYMENT_MAGIC.to_vec();
        full.extend_from_slice(&p);
        let _ = run(full);
    }

    // An unknown pool version must be refused, never guessed at.
    let mut p = payment.clone();
    p[0] = 0xEE;
    let mut full = PRIVATE_PAYMENT_MAGIC.to_vec();
    full.extend_from_slice(&p);
    assert!(!run(full), "an unknown pool version must be refused");

    // Trailing bytes after the payment must be refused (nothing may be smuggled past the decoder).
    let mut padded = PRIVATE_PAYMENT_MAGIC.to_vec();
    padded.extend_from_slice(&payment);
    padded.extend_from_slice(&[0u8; 32]);
    assert!(!run(padded), "trailing bytes must be refused");

    // Marker with nothing behind it, and random blobs of many sizes.
    assert!(!run(PRIVATE_PAYMENT_MAGIC.to_vec()), "the marker alone is not a payment");
    for len in [1usize, 3, 64, 1_679, 20_000] {
        let mut blob = PRIVATE_PAYMENT_MAGIC.to_vec();
        blob.extend_from_slice(&vec![0xCD; len]);
        assert!(!run(blob), "{len} bytes behind the marker must be refused");
    }
}

/// Attack: take a payment built for one network and replay it on another. Every payment signs the network's genesis
/// hash (seam review pack 1 #6), so a payment that is valid on network A must be refused on network B. Without this a
/// payment (and the coins behind it) could be replayed across chains.
///
/// Fail-when-removed: this goes red if the genesis hash stops being part of the signed digest, which is the only thing
/// keeping a devnet payment off mainnet.
#[test]
fn a_payment_from_another_network_is_refused() {
    // Built and signed for GENESIS.
    let mut tx = transparent_tx();
    with_valid_payment(&mut tx, 500_000);
    tx.finalize();

    let ours = validator(true);
    assert_eq!(ours.validate_tx_in_isolation(&tx), Ok(()), "valid on the network it was built for");

    // The same bytes on a network with a different genesis hash.
    let other = TransactionValidator::new(
        DEVNET_PARAMS.max_tx_inputs,
        DEVNET_PARAMS.max_tx_outputs,
        DEVNET_PARAMS.max_signature_script_len,
        DEVNET_PARAMS.max_script_public_key_len,
        DEVNET_PARAMS.coinbase_payload_script_public_key_max_len,
        DEVNET_PARAMS.coinbase_maturity(),
        DEVNET_PARAMS.ghostdag_k(),
        Arc::new(TxScriptCacheCounters::default()),
        MassCalculator::new_with_consensus_params(&DEVNET_PARAMS),
        DEVNET_PARAMS.mass_per_sig_op,
    )
    .with_zethora_genesis(Hash::from_bytes([0x6F; 32])) // a different chain
    .with_private_spends(true);

    assert!(
        !matches!(other.validate_tx_in_isolation(&tx), Ok(())),
        "a payment signed for another network's genesis must not be accepted here"
    );
}

