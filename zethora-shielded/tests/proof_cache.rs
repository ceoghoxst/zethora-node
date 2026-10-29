//! Seam review pack 1 #2 (test T2): one valid proof re-signed over many transactions costs ONE proof check, not one per
//! transaction, and the cache never lets a bad proof through. Its own test binary, so the process-wide check counter
//! is not shared with other tests.

use incrementalmerkletree::Hashable;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags, TxVersion},
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    tree::MerkleHashOrchard,
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zethora_shielded::{CIRCUIT, SupportedPool, VerifyError, codec, proof_checks_run, proof_key, sighash, verify_payment};

#[test]
fn a_proof_re_signed_over_many_transactions_is_checked_once() {
    let mut rng = UnwrapErr(SysRng);
    let pk = ProvingKey::build(CIRCUIT);
    let vk = VerifyingKey::build(CIRCUIT);
    let me = FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap()).address_at(0u32, Scope::External);

    // One output-only payment (anyone can make one, no coins needed), proven once
    let empty_anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut builder = Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, empty_anchor).unwrap();
    builder.add_output(None, me, NoteValue::from_raw(5_000), [0u8; 512]).unwrap();
    let (unauthorized, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let commitment: [u8; 32] = unauthorized.commitment(TxVersion::V5).unwrap().into();
    let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();

    // ... re-signed over 100 different transactions
    let digests: Vec<[u8; 32]> = (0..100u8).map(|i| [i; 32]).collect();
    let bundles: Vec<_> = digests
        .iter()
        .map(|digest| proven.clone().apply_signatures(UnwrapErr(SysRng), sighash(digest, commitment), &[]).unwrap())
        .collect();
    assert!(bundles.windows(2).all(|w| proof_key(&w[0]) == proof_key(&w[1])), "same proof, same public inputs");

    // Every one is a valid payment for its own transaction (the signatures cover the digest) ...
    let before = proof_checks_run();
    for (bundle, digest) in bundles.iter().zip(&digests) {
        assert_eq!(verify_payment(bundle, &vk, digest), Ok(()));
    }
    // ... and the proof was checked exactly once
    assert_eq!(proof_checks_run() - before, 1);

    // The signatures are still checked every time: a payment under another transaction's digest is refused
    assert!(matches!(
        verify_payment(&bundles[0], &vk, &digests[1]),
        Err(VerifyError::SpendSignature(_) | VerifyError::BindingSignature)
    ));
    assert_eq!(proof_checks_run() - before, 1, "refused before the proof check");

    // A changed proof is a different key: it is checked (and fails), the cached success never covers it
    let n = bundles[0].actions().len();
    let mut bytes = codec::encode(&bundles[0], SupportedPool::Orchard1);
    let proof_at = zethora_payment_layout::trailer_offset(n).unwrap() + zethora_payment_layout::PROOF_OFFSET + 100;
    bytes[proof_at] ^= 1;
    let (tampered, _) = codec::decode(&bytes).expect("still well-formed");
    assert_ne!(proof_key(&tampered), proof_key(&bundles[0]));
    assert_eq!(verify_payment(&tampered, &vk, &digests[0]), Err(VerifyError::Proof));
    assert_eq!(proof_checks_run() - before, 2);
    // ... and a failure is never remembered: the same bad proof is checked again
    assert_eq!(verify_payment(&tampered, &vk, &digests[0]), Err(VerifyError::Proof));
    assert_eq!(proof_checks_run() - before, 3);
}
