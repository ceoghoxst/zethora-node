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
use zethora_shielded::{
    CIRCUIT, NoteCommitmentTree, SupportedPool, VerifyError,
    codec::{self, DecodeError},
    pool_flows, sighash, verify_payment, verify_payments_batch,
};

/// Stand-in for the digest of the rest of the Zethora transaction that carries the private payment.
const TX: [u8; 32] = [42; 32];

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

/// Full node-side check of a private payment inside transaction `TX`.
fn node_accepts(bundle: &Bundle<Authorized, i64>) -> bool {
    verify_payment(bundle, verifying_key(), &TX).is_ok()
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
        let sighash = sighash(&TX, unauthorized.commitment(TxVersion::V5).expect("representable flags").into());
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
        let sighash = sighash(&TX, unauthorized.commitment(TxVersion::V5).expect("representable flags").into());
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

// ---- Byte format (codec) -------------------------------------------------------------------------

/// Where fields sit in an encoded payment with `n` actions.
fn value_balance_offset(n: usize) -> usize {
    1 + 2 + n * codec::ACTION_SIZE + 1
}
fn proof_len_offset(n: usize) -> usize {
    value_balance_offset(n) + 8 + 32
}

#[test]
fn bytes_round_trip_and_still_verify() {
    let p = payments();
    for bundle in [&p.shield, &p.unshield] {
        let n = bundle.actions().len();
        let bytes = codec::encode(bundle, SupportedPool::Orchard1);
        assert_eq!(bytes.len(), codec::encoded_size(n));
        let (decoded, pool) = codec::decode(&bytes).expect("own encoding decodes");
        assert_eq!(pool, SupportedPool::Orchard1);
        assert_eq!(codec::encode(&decoded, pool), bytes, "re-encoding gives the same bytes");
        assert!(node_accepts(&decoded), "decoded payment still verifies");
    }
    // A normal 2-action private payment is about 9.1 KB, as in ZTH-SPEC-006 §4
    assert_eq!(codec::encoded_size(2), 9_144);
}

#[test]
fn changing_the_amount_breaks_the_signatures() {
    let p = payments();
    let mut bytes = codec::encode(&p.unshield, SupportedPool::Orchard1);
    let at = value_balance_offset(p.unshield.actions().len());
    bytes[at] ^= 0x01; // 2,000 zets out of the pool becomes 2,001
    let (tampered, _) = codec::decode(&bytes).expect("still well-formed");
    assert_eq!(*tampered.value_balance(), 2_001);
    assert!(verify_payment(&tampered, verifying_key(), &TX).is_err(), "a changed amount must be rejected");
}

#[test]
fn changing_the_proof_is_caught_by_the_proof_check() {
    let p = payments();
    let mut bytes = codec::encode(&p.shield, SupportedPool::Orchard1);
    let at = proof_len_offset(p.shield.actions().len()) + 4 + 100;
    bytes[at] ^= 0x01;
    let (tampered, _) = codec::decode(&bytes).expect("still well-formed");
    assert_eq!(verify_payment(&tampered, verifying_key(), &TX), Err(VerifyError::Proof));
}

#[test]
fn payment_cannot_be_moved_to_another_transaction() {
    let p = payments();
    let other_tx = [43u8; 32];
    assert!(verify_payment(&p.shield, verifying_key(), &other_tx).is_err());
    assert!(verify_payment(&p.unshield, verifying_key(), &other_tx).is_err());
}

#[test]
fn malformed_bytes_are_rejected() {
    let p = payments();
    let good = codec::encode(&p.shield, SupportedPool::Orchard1);
    let n = p.shield.actions().len();

    let mut cut = good.clone();
    cut.pop();
    assert_eq!(codec::decode(&cut).unwrap_err(), DecodeError::Truncated);

    let mut extra = good.clone();
    extra.push(0);
    assert_eq!(codec::decode(&extra).unwrap_err(), DecodeError::TrailingBytes(1));

    let mut pool = good.clone();
    pool[0] = 2;
    assert_eq!(codec::decode(&pool).unwrap_err(), DecodeError::UnknownPoolVersion(2));

    let mut zero = good.clone();
    zero[1] = 0;
    zero[2] = 0;
    assert_eq!(codec::decode(&zero).unwrap_err(), DecodeError::BadActionCount(0));

    let mut many = good.clone();
    many[1] = 17;
    many[2] = 0;
    assert_eq!(codec::decode(&many).unwrap_err(), DecodeError::BadActionCount(17));

    // A padded proof (the Zcash 2026 non-canonical proof size issue) is refused before any checking
    let mut padded = good.clone();
    let at = proof_len_offset(n);
    let len = u32::from_le_bytes(padded[at..at + 4].try_into().unwrap()) + 1;
    padded[at..at + 4].copy_from_slice(&len.to_le_bytes());
    assert!(matches!(codec::decode(&padded).unwrap_err(), DecodeError::BadProofLength { .. }));

    assert_eq!(codec::decode(&[]).unwrap_err(), DecodeError::Truncated);
}

#[test]
fn wallet_builds_a_shielding_payment_the_node_accepts() {
    use zethora_shielded::wallet::{PrivateWallet, shielding_payment};
    let wallet = PrivateWallet::from_seed(&[9; 32]);
    let bytes = shielding_payment(wallet.address(), 1_234_567, &TX).expect("payment builds");
    let (bundle, pool) = codec::decode(&bytes).expect("decodes");
    assert_eq!(pool, SupportedPool::Orchard1);
    assert!(!bundle.flags().spends_enabled(), "spends must be off");
    assert_eq!(*bundle.value_balance(), -1_234_567, "1,234,567 zets enter the private pool");
    assert_eq!(verify_payment(&bundle, verifying_key(), &TX), Ok(()));
    // Same seed, same private address
    assert_eq!(PrivateWallet::from_seed(&[9; 32]).address(), wallet.address());
}

#[test]
fn coin_list_survives_saving_and_loading() {
    let p = payments();
    let mut tree = NoteCommitmentTree::new();
    assert_eq!(NoteCommitmentTree::from_bytes(&tree.to_bytes()).unwrap(), tree);
    for bundle in [&p.shield, &p.unshield] {
        // The cheap reader finds the same new coins as the full decoder
        let bytes = codec::encode(bundle, SupportedPool::Orchard1);
        let cheap = codec::note_commitments(&bytes).unwrap();
        let full: Vec<_> = bundle.actions().iter().map(|a| *a.cmx()).collect();
        assert_eq!(cheap.iter().map(|c| c.to_bytes()).collect::<Vec<_>>(), full.iter().map(|c| c.to_bytes()).collect::<Vec<_>>());
        for cmx in &cheap {
            tree.append(cmx).unwrap();
            let reloaded = NoteCommitmentTree::from_bytes(&tree.to_bytes()).unwrap();
            assert_eq!(reloaded, tree);
            assert_eq!(reloaded.root(), tree.root());
        }
    }
    assert_eq!(tree.size(), 4);
    // Continuing from a reloaded tree gives the same result as never saving it
    let mut a = tree.clone();
    let mut b = NoteCommitmentTree::from_bytes(&tree.to_bytes()).unwrap();
    let extra = *p.shield.actions().first().cmx();
    a.append(&extra).unwrap();
    b.append(&extra).unwrap();
    assert_eq!(a.root(), b.root());
    assert!(NoteCommitmentTree::from_bytes(&[2]).is_err());
    assert!(NoteCommitmentTree::from_bytes(&[]).is_err());
}

#[test]
fn batch_check_accepts_valid_payments_and_catches_a_bad_one() {
    let p = payments();
    let good = vec![(p.shield.clone(), TX), (p.unshield.clone(), TX)];
    assert!(verify_payments_batch(&good, verifying_key()), "valid payments pass together");
    // The same payments claimed for another transaction: their signatures no longer match, and the batch fails
    let mut bad = good.clone();
    bad[1].1 = [43; 32];
    assert!(!verify_payments_batch(&bad, verifying_key()), "one wrong payment fails the whole batch");
    assert!(verify_payments_batch(&[], verifying_key()), "an empty batch is trivially fine");
}
