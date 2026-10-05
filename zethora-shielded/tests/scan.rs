//! Wallet scanning and private spends on the real Orchard circuit (ZTH-SPEC-006).
//! Run: `cargo test --release -p zethora-shielded --features wallet`
#![cfg(feature = "wallet")]

use orchard::circuit::VerifyingKey;
use std::sync::OnceLock;
use zethora_shielded::{
    CIRCUIT, codec,
    scan::Scanner,
    verify_payment,
    wallet::{PrivateWallet, shielding_payment},
};

const SEED: [u8; 32] = [9; 32];
const TX: [u8; 32] = [77; 32];

fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT))
}

fn me() -> PrivateWallet {
    PrivateWallet::from_seed(&SEED)
}

fn friend() -> PrivateWallet {
    PrivateWallet::friend_of(&SEED)
}

fn node_accepts(encoded: &[u8], tx: &[u8; 32]) -> bool {
    let (bundle, _) = codec::decode(encoded).expect("well-formed");
    verify_payment(&bundle, verifying_key(), tx).is_ok()
}

#[test]
fn friend_is_a_different_wallet() {
    assert_ne!(me().address(), friend().address());
    assert_eq!(friend().address(), PrivateWallet::friend_of(&SEED).address());
}

#[test]
fn scan_spend_and_rescan() {
    // Chain so far: two shields to me and one to a stranger
    let stranger = PrivateWallet::from_seed(&[1; 32]);
    let chain = vec![
        shielding_payment(me().address(), 5_000, &TX).unwrap(),
        shielding_payment(stranger.address(), 1_000, &TX).unwrap(),
        shielding_payment(me().address(), 7_000, &TX).unwrap(),
    ];

    let mut scanner = Scanner::new(vec![me(), friend()]);
    for p in &chain {
        scanner.add_payment(p).unwrap();
    }
    scanner.checkpoint().unwrap();
    assert_eq!(scanner.size(), 6, "each shielding payment has 2 actions (one is padding)");
    assert_eq!(scanner.holdings(0).spendable_total(), 12_000);
    assert_eq!(scanner.holdings(1).spendable_total(), 0);
    // The snapshot is the same list the nodes keep
    assert_eq!(scanner.anchor().unwrap().to_bytes(), scanner.root());

    // Send 6,000 to the friend: needs both coins (7,000 then 5,000), 6,000 change back to me, nothing leaves the pool
    let coins = scanner.pick_coins(0, 6_000).unwrap();
    assert_eq!(coins.len(), 1, "largest coin first: 7,000 covers it");
    let coins = scanner.pick_coins(0, 9_000).unwrap();
    assert_eq!(coins.len(), 2);
    let send = scanner.spend_payment(0, &coins, &[(friend().address(), 9_000), (me().address(), 3_000)], &TX).unwrap();
    assert!(node_accepts(&send, &TX), "a real spend verifies");
    let (bundle, _) = codec::decode(&send).unwrap();
    assert_eq!(*bundle.value_balance(), 0, "private to private: nothing enters or leaves the pool");
    assert!(bundle.flags().spends_enabled());
    assert_eq!(bundle.anchor().to_bytes(), scanner.root(), "spend proves membership in the snapshot");
    // The payment is bound to its transaction
    assert!(!node_accepts(&send, &[78; 32]));

    // The chain accepts the payment: my two coins are spent, the friend's coin and my change are maturing
    scanner.add_payment(&send).unwrap();
    assert_eq!(scanner.holdings(0).spendable_total(), 0);
    assert_eq!(scanner.holdings(0).maturing_total(), 3_000);
    assert_eq!(scanner.holdings(1).maturing_total(), 9_000);
    assert!(scanner.pick_coins(0, 1).is_err(), "nothing spendable until the next snapshot");

    // A fresh scan with the snapshot after the spend: the new coins are spendable
    let mut rescan = Scanner::new(vec![me(), friend()]);
    for p in chain.iter().chain(std::iter::once(&send)) {
        rescan.add_payment(p).unwrap();
    }
    rescan.checkpoint().unwrap();
    assert_eq!(rescan.holdings(0).spendable_total(), 3_000);
    assert_eq!(rescan.holdings(1).spendable_total(), 9_000);
    assert_eq!(rescan.root(), scanner.root(), "same payments in the same order, same list");

    // The friend unshields 4,000 (leaves the pool) and keeps 5,000 private
    let friend_scanner_coins = rescan.pick_coins(1, 9_000).unwrap();
    let unshield = rescan.spend_payment(1, &friend_scanner_coins, &[(friend().address(), 5_000)], &TX).unwrap();
    assert!(node_accepts(&unshield, &TX));
    let (bundle, _) = codec::decode(&unshield).unwrap();
    assert_eq!(*bundle.value_balance(), 4_000, "4,000 leaves the private pool");
}

#[test]
fn spending_the_same_coin_twice_reveals_the_same_tag() {
    let chain = [shielding_payment(me().address(), 5_000, &TX).unwrap()];
    let mut scanner = Scanner::new(vec![me(), friend()]);
    scanner.add_payment(&chain[0]).unwrap();
    scanner.checkpoint().unwrap();
    let coins = scanner.pick_coins(0, 5_000).unwrap();
    let a = scanner.spend_payment(0, &coins, &[(friend().address(), 5_000)], &TX).unwrap();
    let b = scanner.spend_payment(0, &coins, &[(me().address(), 5_000)], &TX).unwrap();
    assert!(node_accepts(&a, &TX) && node_accepts(&b, &TX), "each payment is valid on its own");
    let tags = |p: &[u8]| -> Vec<[u8; 32]> {
        codec::decode(p).unwrap().0.actions().iter().map(|a| a.nullifier().to_bytes()).collect::<Vec<_>>()
    };
    let shared: Vec<_> = tags(&a).into_iter().filter(|t| tags(&b).contains(t)).collect();
    assert_eq!(shared, vec![coins[0].nullifier], "both reveal the coin's tag, so the network accepts only one");
}

#[test]
fn counterfeit_coin_proves_against_a_made_up_list() {
    // An attacker "shields" 1,000,000 zets in a payment the chain never accepts, then spends that coin.
    let real_chain = [shielding_payment(me().address(), 5_000, &TX).unwrap()];
    let mut honest = Scanner::new(vec![me()]);
    honest.add_payment(&real_chain[0]).unwrap();
    honest.checkpoint().unwrap();

    let mut fake = Scanner::new(vec![me()]);
    fake.add_payment(&shielding_payment(me().address(), 1_000_000, &TX).unwrap()).unwrap();
    fake.checkpoint().unwrap();
    let coins = fake.pick_coins(0, 1_000_000).unwrap();
    let counterfeit = fake.spend_payment(0, &coins, &[], &TX).unwrap();
    // The proof itself is fine...
    assert!(node_accepts(&counterfeit, &TX));
    // ...but its anchor is not any root the real chain ever had: only the chain's anchor rule can stop it
    let (bundle, _) = codec::decode(&counterfeit).unwrap();
    assert_ne!(bundle.anchor().to_bytes(), honest.root());
}

