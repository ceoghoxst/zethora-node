//! Zethora private pool building blocks (ZTH-SPEC-006), built on Zcash Orchard used unmodified.
//!
//! Not wired into consensus yet. This crate proves, inside the Zethora codebase, that:
//!   * private payments can be made and checked with the fixed Orchard circuit,
//!   * the public value balance of each private transaction maps onto the turnstile
//!     (value into and out of the private pool),
//!   * the list of every private coin (the note commitment tree) depends on the order
//!     coins are added, which is why every node must add them in the same order (SPEC-006 §6.1).

use incrementalmerkletree::frontier::Frontier;
use orchard::{
    Bundle,
    bundle::{Authorized, BundleVersion, TxVersion},
    circuit::{OrchardCircuitVersion, VerifyingKey},
    note::ExtractedNoteCommitment,
    tree::MerkleHashOrchard,
};

pub use orchard;

pub mod codec;
#[cfg(feature = "wallet")]
pub mod scan;
pub mod wallet;

/// Private pool versions this node understands (ZTH-SPEC-006 §7.4). Each version has its own coin list,
/// spent-coin tags and public balance, so a pool can be retired and replaced if a bug is ever found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SupportedPool {
    /// Zethora pool 1: Orchard actions with Zcash's fixed circuit (Zcash calls this bundle version "orchard v2").
    Orchard1 = 1,
}

impl SupportedPool {
    pub fn from_byte(b: u8) -> Result<Self, codec::DecodeError> {
        match b {
            1 => Ok(SupportedPool::Orchard1),
            v => Err(codec::DecodeError::UnknownPoolVersion(v)),
        }
    }

    pub fn bundle_version(self) -> BundleVersion {
        match self {
            SupportedPool::Orchard1 => BundleVersion::orchard_v2(),
        }
    }
}

/// What a private payment's signatures sign: the rest of the Zethora transaction (`tx_digest`)
/// together with the private payment's own effects (`bundle_commitment`). This ties a private
/// payment to its transaction, so it cannot be cut out and attached to another one.
pub fn sighash(tx_digest: &[u8; 32], bundle_commitment: [u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZethoraShieldSig")
        .to_state()
        .update(tx_digest)
        .update(&bundle_commitment)
        .finalize();
    hash.as_bytes().try_into().expect("32-byte hash")
}

/// Why a node refused a private payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// A spend signature is wrong (index of the action).
    SpendSignature(usize),
    /// The signature that proves the values add up is wrong.
    BindingSignature,
    /// The zero-knowledge proof is wrong.
    Proof,
}

/// Checks a private payment the way a node will: signatures first (cheap), then the proof (expensive).
pub fn verify_payment(bundle: &Bundle<Authorized, i64>, vk: &VerifyingKey, tx_digest: &[u8; 32]) -> Result<(), VerifyError> {
    let commitment = bundle.commitment(TxVersion::V5).expect("pool 1 bundles are always committable as v5");
    let sighash = sighash(tx_digest, commitment.into());
    for (i, action) in bundle.actions().iter().enumerate() {
        action.rk().verify(&sighash, action.authorization()).map_err(|_| VerifyError::SpendSignature(i))?;
    }
    bundle.binding_validating_key().verify(&sighash, bundle.authorization().binding_signature()).map_err(|_| VerifyError::BindingSignature)?;
    bundle.verify_proof(vk).map_err(|_| VerifyError::Proof)
}

/// Checks many private payments together with Orchard's batch check, which combines their proofs and signatures and is
/// much cheaper per payment than checking them one by one. `payments` pairs each payment with the digest of the
/// transaction carrying it. True only if every payment is valid; it does not say which one failed (check them one by
/// one for that). Not used by consensus yet: measured by the wallet tool's `speed` command (ZTH-SPEC-006 §8, step 4).
pub fn verify_payments_batch(payments: &[(Bundle<Authorized, i64>, [u8; 32])], vk: &VerifyingKey) -> bool {
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    let mut batch = orchard::bundle::BatchValidator::new(vk);
    for (bundle, tx_digest) in payments {
        let commitment = bundle.commitment(TxVersion::V5).expect("pool 1 bundles are always committable as v5");
        if batch.add_bundle(bundle, sighash(tx_digest, commitment.into())).is_err() {
            return false;
        }
    }
    batch.validate(UnwrapErr(SysRng))
}

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

    /// True if the newest entry is the value the tree uses for empty positions. No real private coin can have it
    /// (it would need a note whose commitment is that exact value), but appending it leaves the root unchanged, so a
    /// peer could send a padded copy of the list that matches the sealed root yet has the wrong size. Downloaded lists
    /// that end in it are refused (ZTH-SPEC-006 §6.4).
    pub fn ends_in_empty_leaf(&self) -> bool {
        use incrementalmerkletree::Hashable;
        self.frontier.value().is_some_and(|f| *f.leaf() == MerkleHashOrchard::empty_leaf())
    }

    /// Compact bytes for storing the tree in the node's database:
    /// `0` for an empty tree, or `1 || position (u64) || leaf (32) || ommer count (u8) || ommers (32 each)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.frontier.value() {
            None => vec![0],
            Some(f) => {
                let mut out = Vec::with_capacity(1 + 8 + 32 + 1 + 32 * f.ommers().len());
                out.push(1);
                out.extend_from_slice(&u64::from(f.position()).to_le_bytes());
                out.extend_from_slice(&f.leaf().to_bytes());
                out.push(f.ommers().len() as u8);
                for o in f.ommers() {
                    out.extend_from_slice(&o.to_bytes());
                }
                out
            }
        }
    }

    /// Reads bytes written by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TreeBytesError> {
        let hash_at = |at: usize| -> Result<MerkleHashOrchard, TreeBytesError> {
            let b: [u8; 32] = bytes.get(at..at + 32).ok_or(TreeBytesError)?.try_into().map_err(|_| TreeBytesError)?;
            Option::from(MerkleHashOrchard::from_bytes(&b)).ok_or(TreeBytesError)
        };
        match bytes.first() {
            Some(0) if bytes.len() == 1 => Ok(Self::new()),
            Some(1) => {
                let position = u64::from_le_bytes(bytes.get(1..9).ok_or(TreeBytesError)?.try_into().map_err(|_| TreeBytesError)?);
                let leaf = hash_at(9)?;
                let n = *bytes.get(41).ok_or(TreeBytesError)? as usize;
                if bytes.len() != 42 + 32 * n {
                    return Err(TreeBytesError);
                }
                let ommers = (0..n).map(|i| hash_at(42 + 32 * i)).collect::<Result<Vec<_>, _>>()?;
                let frontier = Frontier::from_parts(incrementalmerkletree::Position::from(position), leaf, ommers)
                    .map_err(|_| TreeBytesError)?;
                Ok(Self { frontier })
            }
            _ => Err(TreeBytesError),
        }
    }
}

/// Stored tree bytes are malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeBytesError;

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
    fn padding_with_empty_entries_keeps_the_root_but_is_detected() {
        let coin = ExtractedNoteCommitment::from_bytes(&[5; 32]).unwrap();
        let empty_entry = ExtractedNoteCommitment::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 2; // the value Orchard uses for empty positions
            b
        })
        .unwrap();
        let mut honest = NoteCommitmentTree::new();
        honest.append(&coin).unwrap();
        let mut padded = honest.clone();
        padded.append(&empty_entry).unwrap();
        assert_eq!(padded.root(), honest.root(), "the root cannot tell them apart");
        assert_ne!(padded.size(), honest.size());
        assert!(padded.ends_in_empty_leaf());
        assert!(!honest.ends_in_empty_leaf());
        assert!(!NoteCommitmentTree::new().ends_in_empty_leaf());
    }

    #[test]
    fn empty_tree() {
        use incrementalmerkletree::Hashable;
        let tree = NoteCommitmentTree::new();
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.root(), MerkleHashOrchard::empty_root(TREE_DEPTH.into()));
    }
}
