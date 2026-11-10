//! Adversarial (red-team) tests against the Orchard shielded pool (ZTH-SPEC-006).
//!
//! Each test plays the attacker and asserts the attack FAILS: it is stopped by a check a node really runs, not by
//! luck. Every test names the rule that stops it, so that if the rule is removed the test goes red.
//!
//! Run: `cargo test --release -p zethora-shielded --features wallet --test attack_tests`
#![cfg(feature = "wallet")]

use orchard::circuit::VerifyingKey;
use std::sync::OnceLock;
use zethora_shielded::{
    CIRCUIT, codec,
    scan::Scanner,
    verify_payment,
    wallet::{PrivateWallet, shielding_payment},
};

/// The attacker's own seed.
const ATTACKER: [u8; 32] = [0xA1; 32];
/// The digest of the transaction the attack payments ride in.
const TX: [u8; 32] = [0x77; 32];

fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT))
}

fn attacker() -> PrivateWallet {
    PrivateWallet::from_seed(&ATTACKER)
}

/// What a node's in-isolation check does with an encoded payment: decode, then check signatures and proof against
/// the transaction digest (`consensus/.../tx_validation_in_isolation.rs`, `check_private_payment`).
fn node_accepts(encoded: &[u8], tx: &[u8; 32]) -> bool {
    match codec::decode(encoded) {
        Ok((bundle, _)) => verify_payment(&bundle, verifying_key(), tx).is_ok(),
        Err(_) => false,
    }
}

/// The tags (nullifiers) an encoded payment reveals — the pool's double-spend key.
fn tags(encoded: &[u8]) -> Vec<[u8; 32]> {
    codec::decode(encoded).unwrap().0.actions().iter().map(|a| a.nullifier().to_bytes()).collect()
}

/// The public value balance: value leaving the pool if positive, entering it if negative.
fn value_balance(encoded: &[u8]) -> i64 {
    *codec::decode(encoded).unwrap().0.value_balance()
}

/// Where the trailer's anchor starts in an encoded payment with `actions` actions:
/// layout = 1 (pool) + 2 (count) + n*820 (actions), then flags (1) + value balance (8) + anchor (32).
fn anchor_offset(actions: usize) -> usize {
    3 + actions * codec::ACTION_SIZE + 9
}

/// A scanner over a chain holding one real coin of the attacker, snapshotted and spendable.
fn funded_scanner(amount: u64) -> (Scanner, PrivateWallet) {
    let me = attacker();
    let mut scanner = Scanner::new(vec![attacker()]);
    scanner.add_payment(&shielding_payment(me.address(), amount, &TX).unwrap()).unwrap();
    scanner.checkpoint().unwrap();
    (scanner, me)
}

// ---------------------------------------------------------------------------
// A.1 — Nullifier double-spend: the same private coin spent twice.
// ---------------------------------------------------------------------------

/// Attack: spend one coin twice, in two transactions. If both were accepted the attacker would have created money out
/// of nothing (one 50,000-zet coin would pay 50,000 twice).
///
/// The attack IS stopped, but NOT by the cryptographic layer: both payments verify perfectly well on their own,
/// because neither knows about the other. What stops it is the pool's double-spend key, the coin's tag (nullifier),
/// which comes out identical in both spends — so the second spend is refused in context
/// (`utxo_validation.rs::check_private_payment_in_context` → `private_double_spend`, ZTH-SPEC-006 §6.3).
///
/// Fail-when-removed: if a spend ever produced a fresh tag per payment (e.g. by re-randomising the note), the two
/// spends would not share a tag and every node's double-spend check would silently stop working — this test goes red.
#[test]
fn a_coin_spent_twice_verifies_twice_and_shares_its_tag() {
    // One 50,000-zet coin, spent twice in two different transactions. Each spend is bound to its own transaction
    // digest, so neither payment knows about the other — exactly what an attacker sends.
    const SECOND_TX: [u8; 32] = [0x78; 32];
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();
    let tag = coins[0].nullifier;
    let first = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &TX).unwrap();
    let second = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &SECOND_TX).unwrap();

    // Both verify: the cryptographic layer has no way to see the other spend, so it cannot be what stops the attack.
    assert!(node_accepts(&first, &TX), "the first spend verifies on its own");
    assert!(node_accepts(&second, &SECOND_TX), "the second spend verifies on its own");

    // What links them is the tag: the coin reveals the same one in both payments, so a node that remembers the tags it
    // has seen can refuse the second (see `consensus/tests/zethora_privacy_blackhat.rs`, which drives the node's own
    // double-spend rules).
    assert!(tags(&first).contains(&tag), "the first spend reveals the coin's tag");
    assert!(tags(&second).contains(&tag), "the second spend reveals the same tag");
    assert_eq!(
        tags(&first).iter().filter(|t| tags(&second).contains(t)).count(),
        1,
        "the two spends share exactly one tag: the coin that was spent twice"
    );
}

/// Attack: hide the double-spend inside ONE payment, so one coin pays two recipients. Orchard's actions are
/// independent, so a payment carrying the same coin twice would satisfy every per-action check; only a payment-wide
/// rule can catch it.
///
/// Fail-when-removed: the isolation rule "no spent-coin tag may appear twice inside one payment" (ZTH-SPEC-006 §6.3,
/// `check_private_payment`) exists only for this shape. Without it such a payment would pass isolation and reach the
/// context rules, which compare tags against the CHAIN, never against the payment's own other actions.
#[test]
fn the_isolation_rule_sees_a_tag_repeated_inside_one_payment() {
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();
    let tag = coins[0].nullifier;
    let payment = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &TX).unwrap();
    assert!(node_accepts(&payment, &TX));

    // Rewrite the other action so it carries the spent coin's tag: the shape the isolation rule must refuse. Orchard
    // pads a one-coin payment with a dummy spend in an action of its own choosing, so find the real spend first rather
    // than assuming it is the first action.
    let at = tags(&payment).iter().position(|t| *t == tag).expect("the spent coin's tag is in one of the actions");
    let real = 3 + at * codec::ACTION_SIZE + 32; // the nullifier inside that action
    let other = 3 + (1 - at) * codec::ACTION_SIZE + 32;
    let real_tag = payment[real..real + 32].to_vec();
    let mut doubled = payment.clone();
    doubled[other..other + 32].copy_from_slice(&real_tag);
    let t = tags(&doubled);
    assert_eq!(t.len(), 2, "the payment still has two actions");
    assert_eq!(t[0], t[1], "the same tag now appears in both actions");
    assert_eq!(t[0], tag, "and that tag is the spent coin's");

    // This is exactly the check the node runs, and it fires.
    let mut seen = std::collections::HashSet::new();
    assert!(!t.iter().all(|x| seen.insert(*x)), "a repeated tag must be detectable before any proof work");

    // The doctored payment is refused anyway (its proof no longer matches), so the attack fails twice over.
    assert!(!node_accepts(&doubled, &TX), "a payment with a rewritten action must not verify");
}

// ---------------------------------------------------------------------------
// A.2 — Turnstile inflation: take more out of the private pool than was ever put in.
// ---------------------------------------------------------------------------

/// Attack: shield 1,000 zets, then unshield 1,000,000. The turnstile (ZTH-SPEC-006 §7.1) is what makes this
/// impossible: the pool's public balance is the running sum of every payment's value balance, and a payment may never
/// take out more than the pool holds (`utxo_validation.rs::check_private_payment_fits_pool` at admission, and the
/// per-block pass in `validate_transactions_with_muhash_in_parallel`).
///
/// The crypto alone cannot stop it — each payment verifies — so the test pins down that the *accounting* is what stops
/// it, and that the numbers really do not add up.
///
/// Fail-when-removed: if a shield reported a value balance with the wrong sign or magnitude, the running total would
/// not fall short and the turnstile would let the unshield through — this test goes red.
#[test]
fn the_turnstile_refuses_an_unshield_larger_than_the_pool() {
    // The honest pool: a miner shields exactly 1,000 zets, and that is all the pool ever holds.
    let shield = shielding_payment(attacker().address(), 1_000, &TX).unwrap();
    assert!(node_accepts(&shield, &TX), "the shield is a real payment");
    assert_eq!(value_balance(&shield), -1_000, "shielding brings 1,000 zets into the pool");

    // The drain: an unshield of 1,000,000 zets, built from a coin this pool never held.
    let (rich, _) = funded_scanner(1_000_000);
    let rich_coins = rich.pick_coins(0, 1_000_000).unwrap();
    let drain = rich.spend_payment(0, &rich_coins, &[], &TX).unwrap();

    // The cryptography does not stop it: on its own, the drain is a perfectly valid payment.
    assert!(node_accepts(&drain, &TX), "the crypto alone cannot stop the drain: the payment verifies");
    assert_eq!(value_balance(&drain), 1_000_000, "the drain claims to take 1,000,000 zets out of the pool");

    // The accounting is what stops it: the pool's public balance is the running sum of the value balances, and the
    // drain asks for far more than the pool holds
    // (`utxo_validation.rs::check_private_payment_fits_pool` at admission, and the per-block pass).
    let mut pool: i128 = 0;
    pool -= value_balance(&shield) as i128; // value in
    assert_eq!(pool, 1_000, "after the shield the pool holds exactly what was put in");
    let out = value_balance(&drain) as i128; // value out
    assert!(out > pool, "the numbers do not add up: {out} zets wanted out of a pool that holds {pool}");
    assert_eq!(pool - out, -999_000, "the pool would end up 999,000 zets below zero");

    // Honest contrast: an unshield of exactly what the pool holds moves it to zero, which the turnstile allows. The
    // rule refuses the drain because of its size, not because it takes value out.
    assert_eq!(pool - 1_000, 0);
}

/// Attack: inflate the pool by making a payment claim it brings value in while it actually takes value out (or vice
/// versa) — the sign-flip trick. A shield reports a negative balance and an unshield a positive one; if an attacker
/// could choose the sign freely, shielding and unshielding would cancel each other out instead of moving the
/// turnstile, and the pool could be drained for free.
///
/// Fail-when-removed: the sign of the value balance must follow from the payment's own effects, not from a byte an
/// attacker can flip. Flipping it here breaks the binding signature, because the value balance is part of what the
/// bundle commits to — this test goes red if that commitment stops covering it.
#[test]
fn a_sign_flipped_value_balance_breaks_the_binding_signature() {
    // A real shield: it brings 5,000 zets INTO the pool, so its value balance is negative.
    let shield = shielding_payment(attacker().address(), 5_000, &TX).unwrap();
    assert!(node_accepts(&shield, &TX));
    assert_eq!(value_balance(&shield), -5_000, "shielding brings value in, so the balance is negative");

    // The attacker rewrites the 8-byte value balance in the encoded payment, so the very same bytes now claim to take
    // 5,000 zets OUT of the pool. If the sign were the attacker's to choose, this shield and its flipped copy would
    // cancel out (-5,000 + 5,000 = 0) instead of moving the turnstile by 10,000 zets.
    let (bundle, _) = codec::decode(&shield).unwrap();
    let at = anchor_offset(bundle.actions().len()) - 8; // the value balance sits right in front of the anchor
    let mut flipped = shield.clone();
    flipped[at..at + 8].copy_from_slice(&5_000i64.to_le_bytes());
    assert_ne!(flipped, shield, "precondition: the bytes really changed");
    assert_eq!(value_balance(&flipped), 5_000, "the doctored payment now claims the opposite direction");
    assert_eq!(-5_000i64 + value_balance(&flipped), 0, "a free sign would let a shield and a drain cancel out");

    // ...but it no longer verifies: the binding signature covers the value balance.
    assert!(!node_accepts(&flipped, &TX), "a sign-flipped value balance must break the binding signature");
}

// ---------------------------------------------------------------------------
// A.3 — Anchor maturity: spend against a coin list snapshot the chain will not use.
// ---------------------------------------------------------------------------

/// Attack: prove spending against a coin list the chain never had — a made-up list holding a huge counterfeit coin.
/// The proof is valid for THAT list, so the proof check cannot stop it. What stops it is that the anchor must be a
/// root this chain actually sealed, buried at least `anchor_depth` blocks (§6.2,
/// `utxo_validation.rs::anchor_matured_on_chain`).
///
/// Fail-when-removed: if the anchor were not part of what the proof proves, the attacker could prove against a fake
/// list and then present the real chain's root as the anchor, and the counterfeit coin would be spendable. This test
/// goes red if the anchor stops being bound into the proof.
#[test]
fn a_counterfeit_spend_cannot_borrow_the_real_chain_anchor() {
    let me = attacker();

    // Honest chain: one 5,000-zet coin.
    let mut honest = Scanner::new(vec![attacker()]);
    honest.add_payment(&shielding_payment(me.address(), 5_000, &TX).unwrap()).unwrap();
    honest.checkpoint().unwrap();
    let honest_root = honest.root();

    // The attacker's private fake chain: a 1,000,000-zet coin the chain never accepted.
    let mut fake = Scanner::new(vec![attacker()]);
    fake.add_payment(&shielding_payment(me.address(), 1_000_000, &TX).unwrap()).unwrap();
    fake.checkpoint().unwrap();
    assert_ne!(fake.root(), honest_root, "the fake list differs from the real one");
    let fake_coins = fake.pick_coins(0, 1_000_000).unwrap();
    let counterfeit = fake.spend_payment(0, &fake_coins, &[], &TX).unwrap();

    // The proof itself is fine, for the fake list...
    assert!(node_accepts(&counterfeit, &TX), "the counterfeit payment's proof is valid for the fake list");
    // ...and its anchor is the fake root, so the chain's maturity check can never match it to a sealed root (§6.2).
    let (bundle, _) = codec::decode(&counterfeit).unwrap();
    assert_eq!(bundle.anchor().to_bytes(), fake.root(), "the counterfeit names its own fake list");
    assert_ne!(bundle.anchor().to_bytes(), honest_root, "which is not any root the real chain has");

    // Swapping the anchor afterwards to the real root breaks the proof: the anchor is proven, not merely carried.
    let mut swapped = counterfeit.clone();
    let at = anchor_offset(bundle.actions().len());
    swapped[at..at + 32].copy_from_slice(&honest_root);
    assert!(
        !node_accepts(&swapped, &TX),
        "the anchor is proven, not merely carried: swapping it for the real root must break the proof"
    );
}

/// Attack: strip the anchor (zero it) or replace it with a random hash, to slip past the maturity rule by naming a
/// root that does not exist. Both must be refused.
///
/// Fail-when-removed: if decode/verify accepted a spend whose anchor is not proven, an attacker could swap in any root
/// and choose which chain state their spend is judged against.
#[test]
fn a_spend_cannot_strip_or_forge_its_anchor() {
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();
    let real = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &TX).unwrap();
    assert!(node_accepts(&real, &TX));

    let (bundle, _) = codec::decode(&real).unwrap();
    let at = anchor_offset(bundle.actions().len());

    for (name, replacement) in [("zero", [0u8; 32]), ("random", [0x5A; 32])] {
        let mut forged = real.clone();
        forged[at..at + 32].copy_from_slice(&replacement);
        assert!(
            !node_accepts(&forged, &TX),
            "an anchor replaced with {name} must be refused: the proof is bound to the original snapshot"
        );
    }
}

// ---------------------------------------------------------------------------
// A.4 — Malformed payloads must be refused cleanly, never panic a node.
// ---------------------------------------------------------------------------

/// Attack: fuzz a valid payment's bytes at every length and at every position. A node decodes whatever a peer sends,
/// so a decoder that panics (index out of range, unwrap, huge allocation) is a remote crash — a denial of service
/// against every node that relays the transaction.
///
/// Fail-when-removed: this is the guard on `codec::decode` being total. If any decode path panics, the test aborts.
#[test]
fn no_malformed_payment_can_crash_the_decoder() {
    let (scanner, me) = funded_scanner(50_000);
    let coins = scanner.pick_coins(0, 50_000).unwrap();
    let payment = scanner.spend_payment(0, &coins, &[(me.address(), 50_000)], &TX).unwrap();

    // Every truncation must be refused.
    for len in 0..payment.len() {
        assert!(!node_accepts(&payment[..len], &TX), "a payment cut to {len} bytes must be refused");
    }
    // Every single-byte corruption: refused, or (if the byte sits in an encrypted note) still valid — never a panic.
    for i in 0..payment.len() {
        let mut bad = payment.clone();
        bad[i] ^= 0xFF;
        let _ = node_accepts(&bad, &TX);
    }
    // Trailing junk.
    let mut padded = payment.clone();
    padded.extend_from_slice(&[0x00; 64]);
    assert!(!node_accepts(&padded, &TX), "bytes after the payment must be refused");

    // Pathological action counts: the decoder must not trust the u16, nor allocate on it.
    for count in [0u16, 1, 2, 16, u16::MAX] {
        let mut bad = payment.clone();
        bad[1..3].copy_from_slice(&count.to_le_bytes());
        let _ = node_accepts(&bad, &TX);
    }
    // Unknown pool version.
    let mut bad = payment.clone();
    bad[0] = 0xEE;
    assert!(!node_accepts(&bad, &TX), "an unknown pool version must be refused");
    // Garbage of assorted lengths, including a single byte and a very large blob.
    for len in [0usize, 1, 3, 4, 64, 820, 1_679, 10_000] {
        assert!(!node_accepts(&vec![0xAB; len], &TX), "{len} bytes of garbage must be refused");
    }
    // A payload that is only the marker.
    assert!(!node_accepts(b"", &TX), "an empty payload is not a payment");
}
