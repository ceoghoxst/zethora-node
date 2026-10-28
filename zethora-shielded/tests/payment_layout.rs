//! F2 item 1: consensus and the codec read the private payment byte layout from ONE place (`zethora-payment-layout`).
//!
//! Consensus never decodes a whole payment to find its coin tags (nullifiers), value balance, snapshot (anchor) or
//! action count: it reads them at fixed offsets (kaspa-consensus-core zethora_private). This test builds REAL payments
//! (real Orchard proofs and signatures) with 1, 2 and 16 actions, decodes them with the codec, and checks that every
//! consensus reader returns exactly the decoded bundle's values.
//!
//! Slow in debug mode (it makes four real proofs, 35 actions in all).

use incrementalmerkletree::{Hashable, Marking, Retention};
use kaspa_consensus_core::zethora_private::{
    PRIVATE_PAYMENT_MAGIC, action_count, nullifiers, pays_from_private_pool, pool_flows, spend_anchor, value_balance,
};
use orchard::{
    Bundle, Note,
    builder::{Builder, BundleType},
    bundle::{Authorized, BundleVersion, Flags, TxVersion},
    circuit::VerifyingKey,
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note_encryption::OrchardDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zethora_shielded::{CIRCUIT, SupportedPool, codec, sighash, verify_payment, wallet::proving_key};

const TX: [u8; 32] = [9; 32];
/// Value of each of the 16 coins shielded first.
const COIN: u64 = 1_000;

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

fn prove(builder: Builder, signers: &[SpendAuthorizingKey]) -> Bundle<Authorized, i64> {
    let mut rng = OsRng;
    let (unauthorized, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash = sighash(&TX, unauthorized.commitment(TxVersion::V5).unwrap().into());
    unauthorized.create_proof(proving_key(), &mut rng).unwrap().apply_signatures(rng, sighash, signers).unwrap()
}

fn padded_to(n: u8) -> BundleType {
    BundleType::Transactional { bundle_required: false, pad_to_minimum: Some(n) }
}

/// Every consensus reader against the codec's decoding of the same bytes. Returns the action count.
fn check_layout(name: &str, bundle: &Bundle<Authorized, i64>, vk: &VerifyingKey) -> usize {
    assert!(verify_payment(bundle, vk, &TX).is_ok(), "{name}: positive control, the payment is real and verifies");

    let encoded = codec::encode(bundle, SupportedPool::Orchard1);
    let n = bundle.actions().len();
    assert_eq!(encoded.len(), codec::encoded_size(n), "{name}: size");
    let (decoded, _) = codec::decode(&encoded).expect("own encoding decodes");
    let payload: Vec<u8> = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(encoded.iter().copied()).collect();

    // action count
    assert_eq!(action_count(&encoded), Some(decoded.actions().len()), "{name}: action_count");
    // value balance
    let vb = *decoded.value_balance();
    assert_eq!(value_balance(&encoded), Some(vb), "{name}: value_balance");
    let expected_flows = if vb < 0 { (vb.unsigned_abs(), 0) } else { (0, vb as u64) };
    assert_eq!(pool_flows(&payload), Ok(Some(expected_flows)), "{name}: pool_flows");
    assert_eq!(pays_from_private_pool(&payload), vb > 0, "{name}: pays_from_private_pool");
    // coin tags, in action order
    let decoded_nullifiers: Vec<[u8; 32]> = decoded.actions().iter().map(|a| a.nullifier().to_bytes()).collect();
    assert_eq!(decoded_nullifiers.len(), n);
    assert_eq!(nullifiers(&payload), decoded_nullifiers, "{name}: nullifiers");
    // snapshot, only when the payment spends
    let expected_anchor = decoded.flags().spends_enabled().then(|| decoded.anchor().to_bytes());
    assert_eq!(spend_anchor(&payload), expected_anchor, "{name}: spend_anchor");
    // new coins (the codec's own fixed-offset reader)
    let decoded_cmx: Vec<[u8; 32]> = decoded.actions().iter().map(|a| a.cmx().to_bytes()).collect();
    let read_cmx: Vec<[u8; 32]> = codec::note_commitments(&encoded).unwrap().iter().map(|c| c.to_bytes()).collect();
    assert_eq!(read_cmx, decoded_cmx, "{name}: note_commitments");
    n
}

#[test]
fn consensus_readers_match_the_codec_on_real_payments_with_1_2_and_16_actions() {
    let vk = VerifyingKey::build(CIRCUIT);
    let sk = SpendingKey::from_bytes([3; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let me = fvk.address_at(0u32, Scope::External);
    let ask = SpendAuthorizingKey::from(&sk);
    let version = BundleVersion::orchard_v2();
    let empty_anchor = MerkleHashOrchard::empty_root(32.into()).into();

    // 16 actions, shielding (spends off, value enters the pool): 16 coins of COIN zets
    let mut builder = Builder::new(padded_to(1), version, Flags::SPENDS_DISABLED, empty_anchor).unwrap();
    for _ in 0..16 {
        builder.add_output(None, me, NoteValue::from_raw(COIN), [0u8; 512]).unwrap();
    }
    let shield16 = prove(builder, &[]);
    assert_eq!(*shield16.value_balance(), -16 * COIN as i64);

    // The wallet finds its 16 coins and puts them in a coin list with one snapshot
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let notes: Vec<Note> =
        shield16.actions().iter().map(|a| try_note_decryption(&OrchardDomain::for_action(a), &ivk, a).expect("own coin").0).collect();
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> = ShardTree::new(MemoryShardStore::empty(), 100);
    for (i, a) in shield16.actions().iter().enumerate() {
        let retention = if i == 15 { Retention::Checkpoint { id: 0, marking: Marking::Marked } } else { Retention::Marked };
        tree.append(MerkleHashOrchard::from_cmx(a.cmx()), retention).unwrap();
    }
    let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
    let path = |i: u64| -> MerklePath { tree.witness_at_checkpoint_id(i.into(), &0).unwrap().unwrap().into() };

    // 1 action, a spend (spend and change share the one action), 300 zets leave the pool
    let mut builder = Builder::new(padded_to(1), version, version.default_flags(), root.into()).unwrap();
    builder.add_spend(fvk.clone(), notes[0], path(0)).unwrap();
    builder.add_output(None, me, NoteValue::from_raw(COIN - 300), [0u8; 512]).unwrap();
    let spend1 = prove(builder, std::slice::from_ref(&ask));
    assert_eq!(*spend1.value_balance(), 300);

    // 2 actions, shielding with the default padding (one real output, one dummy)
    let mut builder = Builder::new(BundleType::DEFAULT, version, Flags::SPENDS_DISABLED, empty_anchor).unwrap();
    builder.add_output(None, me, NoteValue::from_raw(4_321), [0u8; 512]).unwrap();
    let shield2 = prove(builder, &[]);
    assert_eq!(*shield2.value_balance(), -4_321);

    // 16 actions, a spend of all 16 coins with one change output: 16,000 - 5,000 = 11,000 leave the pool
    let mut builder = Builder::new(padded_to(1), version, version.default_flags(), root.into()).unwrap();
    for (i, note) in notes.iter().enumerate() {
        builder.add_spend(fvk.clone(), *note, path(i as u64)).unwrap();
    }
    builder.add_output(None, me, NoteValue::from_raw(5_000), [0u8; 512]).unwrap();
    let spend16 = prove(builder, &[ask]);
    assert_eq!(*spend16.value_balance(), 11_000);

    let counts: Vec<usize> = [("shield16", &shield16), ("spend1", &spend1), ("shield2", &shield2), ("spend16", &spend16)]
        .into_iter()
        .map(|(name, b)| check_layout(name, b, &vk))
        .collect();
    assert_eq!(counts, vec![16, 1, 2, 16]);

    // The spends' real coin tags are the ones the wallet expects (not just "whatever both sides read")
    let spent: Vec<[u8; 32]> = notes.iter().map(|n| n.nullifier(&fvk).to_bytes()).collect();
    let payload16: Vec<u8> = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(codec::encode(&spend16, SupportedPool::Orchard1)).collect();
    let read16 = nullifiers(&payload16);
    assert!(spent.iter().all(|nf| read16.contains(nf)), "all 16 spent coin tags are read");
    let payload1: Vec<u8> = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(codec::encode(&spend1, SupportedPool::Orchard1)).collect();
    assert_eq!(nullifiers(&payload1), vec![spent[0]]);
    assert_eq!(spend_anchor(&payload1), Some(root.to_bytes()));
}
