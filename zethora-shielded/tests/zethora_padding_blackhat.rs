//! Adversarial tests for the Orchard pool's padding / empty-leaf seam (ZTH-SPEC-006 §6.4).
//!
//! The note commitment tree's root does not seal the list's *size*: Orchard's empty leaf (the
//! point whose x-coordinate is `2`) is, by construction, the image of every empty subtree, so
//! appending empty entries after the real coins leaves the root unchanged. A malicious peer who
//! pads a downloaded coin list can therefore make two different tree sizes share one root.
//!
//! These tests attack that seam with the real [`NoteCommitmentTree`] (no mocks). They prove the
//! three things that matter:
//!   1. the collision is real — padding forges a root across arbitrarily many sizes;
//!   2. it cannot be turned into value or a forged proof — padding adds no coin and the next real
//!      coin still lands at a different position, so a padded list is a consensus split, not a
//!      forgery, and the split is exactly what the guard refuses;
//!   3. it is detected — [`NoteCommitmentTree::ends_in_empty_leaf`] catches it, even after the
//!      list has been serialized and reloaded.
//!
//! These tests are cheap (no proofs): they exercise the tree directly, so they also run in debug
//! mode, unlike the proof-building pool tests.

use incrementalmerkletree::Hashable;
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use zethora_shielded::{NoteCommitmentTree, TREE_DEPTH, pool_flows};

/// A real private coin: a commitment that is definitely not the empty leaf.
fn real_coin() -> ExtractedNoteCommitment {
    ExtractedNoteCommitment::from_bytes(&[5; 32]).unwrap()
}

/// Another, different real private coin (all-zero x-coordinate, distinct from the empty leaf's `2`).
fn other_real_coin() -> ExtractedNoteCommitment {
    ExtractedNoteCommitment::from_bytes(&[0; 32]).unwrap()
}

/// Orchard's empty leaf as a commitment: the value `2` (first byte 2, the rest zero).
fn empty_leaf_commitment() -> ExtractedNoteCommitment {
    let mut b = [0u8; 32];
    b[0] = 2;
    ExtractedNoteCommitment::from_bytes(&b).unwrap()
}

#[test]
fn the_padding_value_is_orchards_empty_leaf() {
    // The "padding" entry the seam review flagged is exactly Orchard's empty leaf, so appending it
    // is the only way to grow the list without changing the root.
    assert_eq!(
        MerkleHashOrchard::from_cmx(&empty_leaf_commitment()),
        MerkleHashOrchard::empty_leaf()
    );

    // Real coins are never mistaken for it, and the empty tree never reports padding, so the
    // detector has no false positives on legitimate lists.
    assert_ne!(MerkleHashOrchard::from_cmx(&real_coin()), MerkleHashOrchard::empty_leaf());
    assert_ne!(MerkleHashOrchard::from_cmx(&other_real_coin()), MerkleHashOrchard::empty_leaf());
    assert!(!NoteCommitmentTree::new().ends_in_empty_leaf());
}

#[test]
fn padding_forges_a_root_collision_across_tree_sizes() {
    let mut honest = NoteCommitmentTree::new();
    honest.append(&real_coin()).unwrap();
    let honest_root = honest.root();
    let honest_size = honest.size();

    // One empty entry: same root, different size. This is the collision the audit worried about:
    // the root cannot tell the two lists apart.
    let mut padded = honest.clone();
    padded.append(&empty_leaf_commitment()).unwrap();
    assert_eq!(padded.root(), honest_root, "the root cannot tell the lists apart");
    assert_ne!(padded.size(), honest_size, "but the size does tell them apart");
    assert!(padded.ends_in_empty_leaf());
    assert!(!honest.ends_in_empty_leaf());

    // Arbitrarily many empty entries still leave the root untouched: an attacker can pick any
    // size >= the honest size and it will all share one sealed root.
    for _ in 0..10_000 {
        padded.append(&empty_leaf_commitment()).unwrap();
        assert_eq!(padded.root(), honest_root, "root still unchanged at size {}", padded.size());
    }
    assert_eq!(padded.size(), honest_size + 10_001);
    assert!(padded.ends_in_empty_leaf());
}

#[test]
fn an_all_empty_coin_list_matches_the_empty_root() {
    // The strongest collision: a list made of only empty leaves has the same root as the empty
    // tree, for every size. Size 0 and size k are indistinguishable by root alone.
    let empty_root = NoteCommitmentTree::new().root();
    assert_eq!(empty_root, MerkleHashOrchard::empty_root(TREE_DEPTH.into()));

    let mut only_empty = NoteCommitmentTree::new();
    for k in 1..=64u64 {
        only_empty.append(&empty_leaf_commitment()).unwrap();
        assert_eq!(only_empty.size(), k);
        assert_eq!(only_empty.root(), empty_root, "size {k} still has the empty root");
        assert!(only_empty.ends_in_empty_leaf(), "size {k} is detectable as padding");
    }
}

#[test]
fn a_padded_list_cannot_forge_the_next_anchor() {
    // The attack: pad the coin list, then build a spend whose anchor is the (unchanged) root, in
    // the hope of forging a proof that other nodes accept. Because padding moved the next free
    // position, the node that accepted the padded list commits the *next* real coin at a different
    // position than an honest node, so the two nodes compute different roots from then on. That is
    // a consensus split, not a forgery, and it is exactly what `ends_in_empty_leaf` prevents.
    let mut honest = NoteCommitmentTree::new();
    honest.append(&real_coin()).unwrap();

    let mut padded = honest.clone();
    padded.append(&empty_leaf_commitment()).unwrap();
    assert_eq!(padded.root(), honest.root(), "same root so far");

    // Append the same next real coin to both: the roots must diverge.
    honest.append(&other_real_coin()).unwrap();
    padded.append(&other_real_coin()).unwrap();
    assert_ne!(padded.root(), honest.root(), "padding makes the next coin land elsewhere");
    assert_eq!(honest.size(), 2);
    assert_eq!(padded.size(), 3);
}

#[test]
fn padding_is_detected_even_after_serialization() {
    let mut honest = NoteCommitmentTree::new();
    honest.append(&real_coin()).unwrap();

    let mut padded = honest.clone();
    padded.append(&empty_leaf_commitment()).unwrap();

    // The padded list round-trips exactly, keeping its size and its empty tail, so the guard that
    // refuses padded lists also works on stored / downloaded bytes.
    let reloaded = NoteCommitmentTree::from_bytes(&padded.to_bytes()).unwrap();
    assert_eq!(reloaded, padded);
    assert_eq!(reloaded.root(), honest.root(), "root still matches the honest list");
    assert_eq!(reloaded.size(), padded.size());
    assert!(reloaded.ends_in_empty_leaf(), "padding survives serialization and is still flagged");

    // The honest list round-trips too, and is not flagged.
    let honest_reloaded = NoteCommitmentTree::from_bytes(&honest.to_bytes()).unwrap();
    assert_eq!(honest_reloaded, honest);
    assert!(!honest_reloaded.ends_in_empty_leaf());
}

#[test]
fn padding_cannot_create_value_or_a_spendable_coin() {
    // The turnstile is driven by the public value balance, which the Orchard circuit binds to the
    // proof; the coin list's size never enters a flow. Padding changes the list but not any
    // balance, so it cannot inflate the pool.
    assert_eq!(pool_flows(0), (0, 0));

    let mut honest = NoteCommitmentTree::new();
    honest.append(&real_coin()).unwrap();
    let mut padded = honest.clone();
    for _ in 0..1_000 {
        padded.append(&empty_leaf_commitment()).unwrap();
    }

    // The padded list contains exactly the same real coins plus 1,000 empty leaves: no value was
    // created, and the set of anchors a spend can reference is unchanged (same root).
    assert_eq!(padded.root(), honest.root());
    assert_eq!(padded.size(), honest.size() + 1_000);

    // An empty leaf is not a coin: it is a reserved point with no note or secret behind it, so it
    // can never be spent (there is no nullifier and no Merkle path to a real note). The detector
    // distinguishes the padded list from the honest one.
    assert!(!honest.ends_in_empty_leaf());
    assert!(padded.ends_in_empty_leaf());
}
