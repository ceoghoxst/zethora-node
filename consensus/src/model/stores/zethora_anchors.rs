//! Zethora: which private coin list snapshots (anchors) a private spend may use (ZTH-SPEC-006 §6.2).
//!
//! Maps every root the private coin list has had to the chain block(s) whose mergeset produced it (genesis for the
//! empty list). A spend's anchor is valid as of a block if one of those producing blocks is on that block's selected
//! chain and at least `ANCHOR_DEPTH` blue score below it. Like the double-spend guard's store, keeping the producing
//! blocks (instead of a plain set) makes reorgs safe without undo logs: a block that falls off the chain stops counting.
//!
//! When a producing block is pruned its reference is rewritten so the answer never changes: a pruned block that was on
//! the selected chain becomes `ANCHORED_FOR_GOOD` (on every future chain, and far deeper than `ANCHOR_DEPTH`), and a
//! pruned block that was not is removed from the list.

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::{Hash, ZERO_HASH};
use rocksdb::WriteBatch;
use std::sync::Arc;

/// Marks an anchor whose producing chain block has been pruned: valid for good.
pub const ANCHORED_FOR_GOOD: Hash = ZERO_HASH;

#[derive(Clone)]
pub struct DbZethoraAnchorsStore {
    access: CachedDbAccess<Hash, Vec<Hash>, BlockHasher>,
}

impl DbZethoraAnchorsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ZethoraAnchors.into()) }
    }

    /// The chain blocks whose mergeset produced this coin list root (empty if never seen).
    pub fn producing_blocks(&self, root: &[u8; 32]) -> Vec<Hash> {
        match self.access.read(Hash::from_bytes(*root)) {
            Ok(blocks) => blocks,
            Err(StoreError::KeyNotFound(_)) => Vec::new(),
            Err(e) => panic!("Zethora anchor store read failed: {e}"),
        }
    }

    /// Records that `block` (a chain block) produced coin list `root`.
    pub fn add_batch(&self, batch: &mut WriteBatch, block: Hash, root: &[u8; 32]) -> Result<(), StoreError> {
        let mut blocks = self.producing_blocks(root);
        if !blocks.contains(&block) {
            blocks.push(block);
            self.access.write(BatchDbWriter::new(batch), Hash::from_bytes(*root), blocks)?;
        }
        Ok(())
    }

    /// Called when `block` is pruned. `root`: the coin list root stored for it. `was_on_chain`: whether it is a chain
    /// ancestor of the new pruning point. Rewrites the record so valid/invalid answers stay the same after pruning.
    pub fn prune_block_batch(&self, batch: &mut WriteBatch, block: Hash, root: &[u8; 32], was_on_chain: bool) -> Result<(), StoreError> {
        let mut blocks = self.producing_blocks(root);
        if !blocks.contains(&block) {
            return Ok(()); // this block did not change the list, so it produced no anchor
        }
        blocks.retain(|b| *b != block);
        if was_on_chain && !blocks.contains(&ANCHORED_FOR_GOOD) {
            blocks.push(ANCHORED_FOR_GOOD);
        }
        if blocks.is_empty() {
            self.access.delete(BatchDbWriter::new(batch), Hash::from_bytes(*root))
        } else {
            self.access.write(BatchDbWriter::new(batch), Hash::from_bytes(*root), blocks)
        }
    }
}
