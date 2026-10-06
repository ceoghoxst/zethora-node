//! Zethora: the private state fingerprint (ZTH-SPEC-006 §6.4).
//!
//! A MuHash set hash over every private coin tag (nullifier) spent on the chain and every private coin list snapshot
//! (anchor) the chain produced, sealed in every coinbase. Being a set hash, it does not depend on order, so a node
//! joining from a pruning point can rebuild it from the two downloaded sets and compare it with the pruning point's
//! coinbase, just like the UTXO commitment.

use kaspa_consensus_core::zethora_private::{private_state_anchor_element, private_state_spent_element};
use kaspa_muhash::MuHash;

/// The fingerprint at genesis: no spent coin tags, and the empty coin list as the only snapshot.
pub fn genesis_private_state() -> MuHash {
    let mut state = MuHash::new();
    state.add_element(&private_state_anchor_element(&zethora_shielded::NoteCommitmentTree::new().root().to_bytes()));
    state
}

/// Builds the fingerprint of a whole private state: the spent coin tags and the coin list snapshots.
pub fn private_state_of<'a>(spent: impl IntoIterator<Item = &'a [u8; 32]>, anchors: impl IntoIterator<Item = &'a [u8; 32]>) -> MuHash {
    let mut state = MuHash::new();
    for nf in spent {
        state.add_element(&private_state_spent_element(nf));
    }
    for root in anchors {
        state.add_element(&private_state_anchor_element(root));
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_does_not_matter_and_every_member_counts() {
        let a = private_state_of(&[[1; 32], [2; 32]], &[[9; 32]]).finalize();
        let b = private_state_of(&[[2; 32], [1; 32]], &[[9; 32]]).finalize();
        assert_eq!(a, b, "a set: order does not matter");
        assert_ne!(a, private_state_of(&[[1; 32]], &[[9; 32]]).finalize(), "a missing spent tag changes it");
        assert_ne!(a, private_state_of(&[[1; 32], [2; 32]], &[]).finalize(), "a missing snapshot changes it");
        // A tag and a snapshot with the same bytes are different members
        assert_ne!(private_state_of(&[[5; 32]], &[]).finalize(), private_state_of(&[], &[[5; 32]]).finalize());
    }

    #[test]
    fn genesis_holds_only_the_empty_coin_list() {
        let empty_root = zethora_shielded::NoteCommitmentTree::new().root().to_bytes();
        assert_eq!(genesis_private_state().finalize(), private_state_of(&[], &[empty_root]).finalize());
    }

    #[test]
    fn built_step_by_step_equals_built_at_once() {
        // What block processing does (start from the parent, add this mergeset's members) equals the whole set
        let mut step = genesis_private_state();
        step.add_element(&private_state_spent_element(&[3; 32]));
        step.add_element(&private_state_anchor_element(&[4; 32]));
        let empty_root = zethora_shielded::NoteCommitmentTree::new().root().to_bytes();
        assert_eq!(step.finalize(), private_state_of(&[[3; 32]], &[empty_root, [4; 32]]).finalize());
    }
}
