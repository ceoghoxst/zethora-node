//! Zethora private pool building blocks (ZTH-SPEC-006), built on Zcash Orchard used unmodified.
//!
//! Not wired into consensus yet. This crate proves, inside the Zethora codebase, that:
//!   * private payments can be made and checked with the fixed Orchard circuit,
//!   * the public value balance of each private transaction maps onto the turnstile
//!     (value into and out of the private pool),
//!   * the list of every private coin (the note commitment tree) depends on the order
//!     coins are added, which is why every node must add them in the same order (SPEC-006 §6.1).

use incrementalmerkletree::frontier::Frontier;
use orchard::{circuit::OrchardCircuitVersion, note::ExtractedNoteCommitment, tree::MerkleHashOrchard};

pub use orchard;

/// The only Orchard circuit Zethora accepts: Zcash's fixed circuit (after CVE-2026-54496).
pub const CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::FixedPostNu6_2;

/// Depth of the note commitment tree (same as Zcash Orchard: room for about 4.3 billion private coins per pool).
pub const TREE_DEPTH: u8 = 32;

/// Splits a private transaction's public value balance into turnstile flows.
///
/// Orchard's value balance is (value spent from the pool) - (value created in the pool):
/// negative means value entered the private pool, positive means value left it.
/// Returns (value_in, value_out) in zets.
pub fn pool_flows(value_balance: i64) -> (u64, u64) {
    if value_balance < 0 { (value_balance.unsigned_abs(), 0) } else { (0, value_balance as u64) }
}

/// The tree is full: no more private coins fit in this pool version (time to migrate to a new pool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeFull;

/// The list of every private coin ever created in one pool, kept as a compact Merkle frontier.
/// Spends prove their coin is in this list by referring to one of its roots (an anchor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteCommitmentTree {
    frontier: Frontier<MerkleHashOrchard, TREE_DEPTH>,
}

impl Default for NoteCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteCommitmentTree {
    pub fn new() -> Self {
        Self { frontier: Frontier::empty() }
    }

    /// Adds one new private coin. Order matters: every node must add coins in GHOSTDAG accepted order.
    pub fn append(&mut self, cmx: &ExtractedNoteCommitment) -> Result<(), TreeFull> {
        if self.frontier.append(MerkleHashOrchard::from_cmx(cmx)) { Ok(()) } else { Err(TreeFull) }
    }

    /// The current root: the value spends use as their anchor.
    pub fn root(&self) -> MerkleHashOrchard {
        self.frontier.root()
    }

    /// Number of private coins ever added.
    pub fn size(&self) -> u64 {
        self.frontier.tree_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flows_follow_the_sign_of_the_value_balance() {
        assert_eq!(pool_flows(-5_000), (5_000, 0)); // shielding: coins enter the private pool
        assert_eq!(pool_flows(2_000), (0, 2_000)); // unshielding: coins leave it
        assert_eq!(pool_flows(0), (0, 0)); // fully private payment
        assert_eq!(pool_flows(i64::MIN), (1u64 << 63, 0));
    }

    #[test]
    fn empty_tree() {
        use incrementalmerkletree::Hashable;
        let tree = NoteCommitmentTree::new();
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.root(), MerkleHashOrchard::empty_root(TREE_DEPTH.into()));
    }
}
