//! Zethora: the private state fingerprint (ZTH-SPEC-006 §6.4).
//!
//! A MuHash set hash over every private coin tag (nullifier) spent on the chain and every private coin list snapshot
//! (anchor) the chain produced, with the blue score of the block that produced it, sealed in every coinbase. Being a
//! set hash, it does not depend on order, so a node joining from a pruning point can rebuild it from the two downloaded
//! sets and compare it with the pruning point's coinbase, just like the UTXO commitment.

use crate::model::stores::{
    zethora_anchors::{ANCHORED_FOR_GOOD, AnchorProducer},
    zethora_nullifiers::SPENT_FOR_GOOD,
};
use kaspa_consensus_core::{
    api::ZethoraPrivateState,
    zethora_private::{private_state_anchor_element, private_state_spent_element},
};
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use std::collections::HashSet;
use zethora_shielded::NoteCommitmentTree;

/// The fingerprint at genesis: no spent coin tags, and the empty coin list as the only snapshot (genesis has blue
/// score 0).
pub fn genesis_private_state() -> MuHash {
    let mut state = MuHash::new();
    state.add_element(&private_state_anchor_element(&NoteCommitmentTree::new().root().to_bytes(), 0));
    state
}

/// Builds the fingerprint of a whole private state: the spent coin tags and the coin list snapshots with their blue
/// scores.
pub fn private_state_of<'a>(
    spent: impl IntoIterator<Item = &'a [u8; 32]>,
    anchors: impl IntoIterator<Item = &'a ([u8; 32], u64)>,
) -> MuHash {
    let mut state = MuHash::new();
    for nf in spent {
        state.add_element(&private_state_spent_element(nf));
    }
    for (root, blue_score) in anchors {
        state.add_element(&private_state_anchor_element(root, *blue_score));
    }
    state
}

/// Picks, out of every record in the coin tag and snapshot stores, the private state as of a pruning point: the tags
/// spent and the snapshots produced on its chain. `on_chain(block)` says whether a block is a chain ancestor of (or is)
/// the pruning point. Records already rewritten as "for good" belong to every chain through the pruning point.
pub fn private_state_as_of<E>(
    nullifier_records: impl IntoIterator<Item = Result<([u8; 32], Vec<Hash>), E>>,
    anchor_records: impl IntoIterator<Item = Result<([u8; 32], Vec<AnchorProducer>), E>>,
    mut on_chain: impl FnMut(Hash) -> Result<bool, E>,
) -> Result<(Vec<[u8; 32]>, Vec<([u8; 32], u64)>), E> {
    // "For good" markers are checked first: they answer on their own, without asking about any block
    let mut spent = Vec::new();
    for record in nullifier_records {
        let (nullifier, blocks) = record?;
        let mut counts = blocks.contains(&SPENT_FOR_GOOD);
        for block in blocks {
            if counts {
                break;
            }
            counts = on_chain(block)?;
        }
        if counts {
            spent.push(nullifier);
        }
    }
    let mut anchors = Vec::new();
    for record in anchor_records {
        let (root, producers) = record?;
        // A root is produced at most once on one chain (the list only grows), so the first match is the one
        let mut found = producers.iter().find(|p| p.block == ANCHORED_FOR_GOOD).copied();
        for p in producers {
            if found.is_some() {
                break;
            }
            if on_chain(p.block)? {
                found = Some(p);
            }
        }
        if let Some(p) = found {
            anchors.push((root, p.blue_score));
        }
    }
    Ok((spent, anchors))
}

/// Checks a private state downloaded from a peer against what the pruning point's coinbase seals: its coin list root
/// and its private state fingerprint. On success returns the coin list and the (unfinalized) fingerprint to store.
pub fn check_downloaded_private_state(
    state: &ZethoraPrivateState,
    expected_note_root: &[u8; 32],
    expected_fingerprint: &[u8; 32],
) -> Result<(NoteCommitmentTree, MuHash), String> {
    let tree = NoteCommitmentTree::from_bytes(&state.note_tree).map_err(|_| "the private coin list is unreadable".to_string())?;
    if tree.root().to_bytes() != *expected_note_root {
        return Err("the private coin list does not match the root sealed in the pruning point".to_string());
    }
    // The root does not seal the list's size: padding it with empty entries keeps the root but would make this node
    // compute different roots from the next private coin on, splitting it from the network
    if tree.ends_in_empty_leaf() {
        return Err("the private coin list is padded with empty entries".to_string());
    }
    let mut seen_tags = HashSet::with_capacity(state.spent.len());
    if !state.spent.iter().all(|nf| seen_tags.insert(*nf)) {
        return Err("a spent private coin tag is listed twice".to_string());
    }
    let mut seen_roots = HashSet::with_capacity(state.anchors.len());
    if !state.anchors.iter().all(|(root, _)| seen_roots.insert(*root)) {
        return Err("a private coin list snapshot is listed twice".to_string());
    }
    if !seen_roots.contains(&tree.root().to_bytes()) {
        return Err("the current private coin list is missing from the snapshots".to_string());
    }
    let fingerprint = private_state_of(&state.spent, &state.anchors);
    if fingerprint.clone().finalize().as_bytes() != *expected_fingerprint {
        return Err("the spent coin tags and snapshots do not match the fingerprint sealed in the pruning point".to_string());
    }
    Ok((tree, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zethora_shielded::orchard::note::ExtractedNoteCommitment;

    fn empty_root() -> [u8; 32] {
        NoteCommitmentTree::new().root().to_bytes()
    }

    #[test]
    fn order_does_not_matter_and_every_member_counts() {
        let a = private_state_of(&[[1; 32], [2; 32]], &[([9; 32], 7)]).finalize();
        let b = private_state_of(&[[2; 32], [1; 32]], &[([9; 32], 7)]).finalize();
        assert_eq!(a, b, "a set: order does not matter");
        assert_ne!(a, private_state_of(&[[1; 32]], &[([9; 32], 7)]).finalize(), "a missing spent tag changes it");
        assert_ne!(a, private_state_of(&[[1; 32], [2; 32]], &[]).finalize(), "a missing snapshot changes it");
        // A tag and a snapshot with the same bytes are different members
        assert_ne!(private_state_of(&[[5; 32]], &[]).finalize(), private_state_of(&[], &[([5; 32], 0)]).finalize());
    }

    #[test]
    fn a_snapshots_age_is_sealed_too() {
        // A peer lying about when a snapshot was made (so spends could use it too early) changes the fingerprint
        assert_ne!(private_state_of(&[], &[([9; 32], 7)]).finalize(), private_state_of(&[], &[([9; 32], 8)]).finalize());
    }

    #[test]
    fn genesis_holds_only_the_empty_coin_list() {
        assert_eq!(genesis_private_state().finalize(), private_state_of(&[], &[(empty_root(), 0)]).finalize());
    }

    #[test]
    fn built_step_by_step_equals_built_at_once() {
        // What block processing does (start from the parent, add this mergeset's members) equals the whole set
        let mut step = genesis_private_state();
        step.add_element(&private_state_spent_element(&[3; 32]));
        step.add_element(&private_state_anchor_element(&[4; 32], 12));
        assert_eq!(step.finalize(), private_state_of(&[[3; 32]], &[(empty_root(), 0), ([4; 32], 12)]).finalize());
    }

    #[test]
    fn picks_only_what_is_on_the_pruning_points_chain() {
        let (on, off, good) = (Hash::from_u64_word(1), Hash::from_u64_word(2), SPENT_FOR_GOOD);
        let tags: Vec<Result<([u8; 32], Vec<Hash>), String>> = vec![
            Ok(([1; 32], vec![on])),        // spent on the chain: counts
            Ok(([2; 32], vec![off])),       // spent only on a side chain: does not
            Ok(([3; 32], vec![off, good])), // spent for good: counts
            Ok(([4; 32], vec![])),          // no record left: does not
        ];
        let snaps: Vec<Result<([u8; 32], Vec<AnchorProducer>), String>> = vec![
            Ok(([7; 32], vec![AnchorProducer { block: off, blue_score: 5 }, AnchorProducer { block: on, blue_score: 6 }])),
            Ok(([8; 32], vec![AnchorProducer { block: off, blue_score: 9 }])),
            Ok(([9; 32], vec![AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score: 2 }])),
        ];
        let (spent, anchors) = private_state_as_of(tags, snaps, |b| Ok(b == on)).unwrap();
        assert_eq!(spent, vec![[1; 32], [3; 32]]);
        assert_eq!(anchors, vec![([7; 32], 6), ([9; 32], 2)], "the on-chain producer's blue score is the one sent");

        // A block with no reachability data is an error, never a guess, unless a "for good" marker already answers
        let tags: Vec<Result<([u8; 32], Vec<Hash>), String>> = vec![Ok(([1; 32], vec![off]))];
        assert!(private_state_as_of(tags, vec![], |_| Err("missing".to_string())).is_err());
        let tags: Vec<Result<([u8; 32], Vec<Hash>), String>> = vec![Ok(([1; 32], vec![off, good]))];
        let snaps: Vec<Result<([u8; 32], Vec<AnchorProducer>), String>> = vec![Ok((
            [7; 32],
            vec![AnchorProducer { block: off, blue_score: 5 }, AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score: 4 }],
        ))];
        let (spent, anchors) = private_state_as_of(tags, snaps, |_| Err("missing".to_string())).unwrap();
        assert_eq!((spent, anchors), (vec![[1; 32]], vec![([7; 32], 4)]));
    }

    #[test]
    fn a_downloaded_private_state_must_match_the_pruning_point() {
        let tree = NoteCommitmentTree::new();
        let root = tree.root().to_bytes();
        let good = ZethoraPrivateState { note_tree: tree.to_bytes(), spent: vec![[1; 32]], anchors: vec![(root, 0), ([4; 32], 30)] };
        let fingerprint = private_state_of(&good.spent, &good.anchors).finalize().as_bytes();

        let (got_tree, got_state) = check_downloaded_private_state(&good, &root, &fingerprint).expect("an honest download passes");
        assert_eq!(got_tree, tree);
        assert_eq!(got_state.clone().finalize().as_bytes(), fingerprint);

        let fails = |s: &ZethoraPrivateState| check_downloaded_private_state(s, &root, &fingerprint).is_err();
        assert!(fails(&ZethoraPrivateState { spent: vec![], ..good.clone() }), "a hidden spent tag (would allow a double spend)");
        assert!(fails(&ZethoraPrivateState { spent: vec![[1; 32], [2; 32]], ..good.clone() }), "an invented spent tag");
        assert!(fails(&ZethoraPrivateState { spent: vec![[1; 32], [1; 32]], ..good.clone() }), "a tag listed twice");
        assert!(
            fails(&ZethoraPrivateState { anchors: vec![(root, 0), ([4; 32], 1)], ..good.clone() }),
            "a snapshot made to look older"
        );
        assert!(
            fails(&ZethoraPrivateState { anchors: vec![(root, 0), ([4; 32], 30), ([5; 32], 31)], ..good.clone() }),
            "an invented snapshot"
        );
        assert!(fails(&ZethoraPrivateState { anchors: vec![([4; 32], 30)], ..good.clone() }), "the current coin list missing");
        assert!(fails(&ZethoraPrivateState { note_tree: vec![7], ..good.clone() }), "unreadable coin list");
        // A coin list padded with an empty entry: same root, wrong size
        let mut padded = tree.clone();
        let mut empty_entry = [0u8; 32];
        empty_entry[0] = 2; // the value Orchard uses for empty positions
        padded.append(&ExtractedNoteCommitment::from_bytes(&empty_entry).unwrap()).unwrap();
        assert_eq!(padded.root().to_bytes(), root);
        assert!(fails(&ZethoraPrivateState { note_tree: padded.to_bytes(), ..good.clone() }), "a padded coin list");
        assert!(check_downloaded_private_state(&good, &[3; 32], &fingerprint).is_err(), "a coin list that is not the pruning point's");
    }
}
