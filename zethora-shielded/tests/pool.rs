//! Zethora private pool tests on the real Orchard circuit (ZTH-SPEC-006).
//! Run in release mode: `cargo test --release -p zethora-shielded` (making proofs is slow in debug mode).

use incrementalmerkletree::{Hashable, Marking, Retention};
use orchard::{
    Bundle,
    builder::{Builder, BundleType},
    bundle::{Authorized, BundleVersion, Flags, TxVersion},
    circuit::{Instance, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::OrchardDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use std::sync::OnceLock;
use zcash_note_encryption::try_note_decryption;
use zethora_shielded::{CIRCUIT, NoteCommitmentTree, pool_flows};

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

fn proving_key() -> &'static ProvingKey {
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    PK.get_or_init(|| ProvingKey::build(CIRCUIT))
}

fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT))
}

/// Full node-side check of a private transaction: proof, spend signatures and binding signature.
fn node_accepts(bundle: &Bundle<Authorized, i64>) -> bool {
    if bundle.verify_proof(verifying_key()).is_err() {
        return false;
    }
    let sighash: [u8; 32] = bundle.commitment(TxVersion::V5).expect("representable flags").into();
    let spends_ok = bundle.actions().iter().all(|a| a.rk().verify(&sighash, a.authorization()).is_ok());
    let binding_ok = bundle.binding_validating_key().verify(&sighash, bundle.authorization().binding_signature()).is_ok();
    spends_ok && binding_ok
}

fn instances(bundle: &Bundle<Authorized, i64>) -> Vec<Instance> {
    bundle.actions().iter().map(|a| a.to_instance(*bundle.flags(), *bundle.anchor())).collect()
}

/// A tree holding exactly one coin, plus the wallet's proof that the coin is in it.
fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (MerkleHashOrchard, MerklePath) {
    let leaf = MerkleHashOrchard::from_cmx(cmx);
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> = ShardTree::new(MemoryShardStore::empty(), 100);
    tree.append(leaf, Retention::Checkpoint { id: 0, marking: Marking::Marked }).unwrap();
    let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
    let position = tree.max_leaf_position(None).unwrap().unwrap();
    let path = tree.witness_at_checkpoint_id(position, &0).unwrap().unwrap();
    (root, path.into())
}

struct Payments {
    shield: Bundle<Authorized, i64>,
    unshield: Bundle<Authorized, i64>,
    /// The anchor the spend used, from the wallet's tree
    wallet_root: MerkleHashOrchard,
}

/// Shields 5,000 zets into the private pool, then spends that private coin:
/// 3,000 stay private (new coin), 2,000 leave the pool.
fn make_payments() -> Payments {
    let mut rng = OsRng;
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let me = fvk.address_at(0u32, Scope::External);

    // 1. Shield: 5,000 zets enter the private pool (no spends allowed in this bundle)
    let shield = {
        let empty_anchor = MerkleHashOrchard::empty_root(32.into()).into();
        let mut builder = Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, empty_anchor).unwrap();
        builder.add_output(None, me, NoteValue::from_raw(5_000), [0u8; 512]).unwrap();
        let (unauthorized, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let sighash = unauthorized.commitment(TxVersion::V5).expect("representable flags").into();
        unauthorized.create_proof(proving_key(), &mut rng).unwrap().apply_signatures(rng, sighash, &[]).unwrap()
    };

    // The wallet finds its private coin by trial decryption
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let (note, _, _) = shield
        .actions()
        .iter()
        .find_map(|action| try_note_decryption(&OrchardDomain::for_action(action), &ivk, action))
        .expect("wallet finds its coin");
    assert_eq!(note.value(), NoteValue::from_raw(5_000));

    // 2. Spend it: 3,000 to a new private coin, 2,000 leave the pool
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let (wallet_root, path) = single_leaf_witness(&cmx);
    let unshield = {
        let mut builder =
            Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v2(), BundleVersion::orchard_v2().default_flags(), wallet_root.into())
                .unwrap();
        builder.add_spend(fvk, note, path).unwrap();
        builder.add_output(None, me, NoteValue::from_raw(3_000), [0u8; 512]).unwrap();
        let (unauthorized, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let sighash = unauthorized.commitment(TxVersion::V5).expect("representable flags").into();
        unauthorized
            .create_proof(proving_key(), &mut rng)
            .unwrap()
            .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sk)])
            .unwrap()
    };

    Payments { shield, unshield, wallet_root }
}

fn payments() -> &'static Payments {
    static P: OnceLock<Payments> = OnceLock::new();
    P.get_or_init(make_payments)
}

#[test]
fn shield_and_spend_are_accepted() {
    let p = payments();
    assert!(node_accepts(&p.shield), "shielding payment must verify");
    assert!(node_accepts(&p.unshield), "private spend must verify");
}

#[test]
fn turnstile_sees_value_in_and_out() {
    let p = payments();
    // 5,000 entered the pool, then 2,000 left it: the pool's public balance is 3,000
    assert_eq!(pool_flows(*p.shield.value_balance()), (5_000, 0));
    assert_eq!(pool_flows(*p.unshield.value_balance()), (0, 2_000));
    let mut balance: u64 = 0;
    for b in [&p.shield, &p.unshield] {
        let (value_in, value_out) = pool_flows(*b.value_balance());
        balance = balance + value_in - value_out;
    }
    assert_eq!(balance, 3_000);
}

#[test]
fn proof_cannot_be_reused_for_another_transaction() {
    let p = payments();
    // The shielding proof checked against the spend's public data must fail
    assert!(p.shield.authorization().proof().verify(verifying_key(), &instances(&p.unshield)).is_err());
    // ...while each proof passes against its own data
    assert!(p.shield.authorization().proof().verify(verifying_key(), &instances(&p.shield)).is_ok());
    assert!(p.unshield.authorization().proof().verify(verifying_key(), &instances(&p.unshield)).is_ok());
}

#[test]
fn node_tree_matches_wallet_anchor() {
    let p = payments();
    // The node adds the shielded coin(s) to its tree; the coin the wallet spent is the real (non-dummy) output.
    // A node with only that coin must reach the exact root the wallet used as its anchor.
    let found = p.shield.actions().iter().any(|a| {
        let mut tree = NoteCommitmentTree::new();
        tree.append(a.cmx()).unwrap();
        tree.root() == p.wallet_root
    });
    assert!(found, "node-side tree must produce the wallet's anchor");
}

#[test]
fn same_order_same_tree_different_order_different_tree() {
    let p = payments();
    let coins: Vec<ExtractedNoteCommitment> = p.shield.actions().iter().chain(p.unshield.actions().iter()).map(|a| *a.cmx()).collect();
    assert!(coins.len() >= 4);

    let build = |order: &[usize]| {
        let mut tree = NoteCommitmentTree::new();
        for &i in order {
            tree.append(&coins[i]).unwrap();
        }
        tree
    };
    let node_a = build(&[0, 1, 2, 3]);
    let node_b = build(&[0, 1, 2, 3]);
    let node_c = build(&[1, 0, 2, 3]); // two coins swapped, as if blocks arrived in another order

    assert_eq!(node_a.size(), 4);
    assert_eq!(node_a.root(), node_b.root(), "same order: nodes agree");
    assert_ne!(node_a.root(), node_c.root(), "different order: nodes disagree, so consensus must fix the order");
}
