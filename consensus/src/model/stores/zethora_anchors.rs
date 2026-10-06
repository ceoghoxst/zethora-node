//! Zethora: which private coin list snapshots (anchors) a private spend may use (ZTH-SPEC-006 §6.2).
//!
//! Maps every root the private coin list has had to the chain block(s) whose mergeset produced it (genesis for the
//! empty list), each with that block's blue score. A spend's anchor is valid as of a block if one of those producing
//! blocks is on that block's selected chain and at least `ANCHOR_DEPTH` blue score below it. Like the double-spend
//! guard's store, keeping the producing blocks (instead of a plain set) makes reorgs safe without undo logs: a block
//! that falls off the chain stops counting.
//!
//! When a producing block is pruned its reference is rewritten so the answer never changes: a pruned block that was on
//! the selected chain becomes `ANCHORED_FOR_GOOD` (on every future chain) with its blue score kept, and a pruned block
//! that was not is removed from the list. A node joining from a pruning point stores the snapshots it downloads the
//! same way. The blue score is kept because the youngest snapshots at the pruning point are not yet `ANCHOR_DEPTH`
//! deep for the first blocks after it.

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::{Hash, ZERO_HASH};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Marks an anchor whose producing chain block has been pruned (or was below the pruning point a node joined from):
/// on every future chain.
pub const ANCHORED_FOR_GOOD: Hash = ZERO_HASH;

/// A chain block that produced a coin list snapshot (or `ANCHORED_FOR_GOOD`), and that block's blue score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorProducer {
    pub block: Hash,
    pub blue_score: u64,
}

#[derive(Clone)]
pub struct DbZethoraAnchorsStore {
    access: CachedDbAccess<Hash, Vec<AnchorProducer>, BlockHasher>,
}

impl DbZethoraAnchorsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ZethoraAnchors.into()) }
    }

    /// The chain blocks that produced this coin list root, with their blue scores (empty if never seen).
    pub fn producing_blocks(&self, root: &[u8; 32]) -> Vec<AnchorProducer> {
        match self.access.read(Hash::from_bytes(*root)) {
            Ok(blocks) => blocks,
            Err(StoreError::KeyNotFound(_)) => Vec::new(),
            Err(e) => panic!("Zethora anchor store read failed: {e}"),
        }
    }

    /// Records that `block` (a chain block with this blue score) produced coin list `root`.
    pub fn add_batch(&self, batch: &mut WriteBatch, block: Hash, blue_score: u64, root: &[u8; 32]) -> Result<(), StoreError> {
        let mut blocks = self.producing_blocks(root);
        if !blocks.iter().any(|p| p.block == block) {
            blocks.push(AnchorProducer { block, blue_score });
            self.access.write(BatchDbWriter::new(batch), Hash::from_bytes(*root), blocks)?;
        }
        Ok(())
    }

    /// Records that `root` was produced on the chain of a pruning point this node joined from, by a block with this
    /// blue score (ZTH-SPEC-006 §6.4). The pruning point is on every future chain, so the snapshot is too.
    pub fn add_for_good_batch(&self, batch: &mut WriteBatch, root: &[u8; 32], blue_score: u64) -> Result<(), StoreError> {
        let mut blocks = self.producing_blocks(root);
        if !blocks.iter().any(|p| p.block == ANCHORED_FOR_GOOD) {
            blocks.push(AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score });
            self.access.write(BatchDbWriter::new(batch), Hash::from_bytes(*root), blocks)?;
        }
        Ok(())
    }

    /// Called when `block` is pruned. `root`: the coin list root stored for it. `was_on_chain`: whether it is a chain
    /// ancestor of the new pruning point. Rewrites the record so valid/invalid answers stay the same after pruning.
    pub fn prune_block_batch(
        &self,
        batch: &mut WriteBatch,
        block: Hash,
        root: &[u8; 32],
        was_on_chain: bool,
    ) -> Result<(), StoreError> {
        let mut blocks = self.producing_blocks(root);
        let Some(pruned) = blocks.iter().copied().find(|p| p.block == block) else {
            return Ok(()); // this block did not change the list, so it produced no anchor
        };
        blocks.retain(|p| p.block != block);
        if was_on_chain && !blocks.iter().any(|p| p.block == ANCHORED_FOR_GOOD) {
            blocks.push(AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score: pruned.blue_score });
        }
        if blocks.is_empty() {
            self.access.delete(BatchDbWriter::new(batch), Hash::from_bytes(*root))
        } else {
            self.access.write(BatchDbWriter::new(batch), Hash::from_bytes(*root), blocks)
        }
    }

    /// Every coin list root ever recorded, with its producing blocks (read straight from the database).
    pub fn iter_all(&self) -> impl Iterator<Item = Result<([u8; 32], Vec<AnchorProducer>), StoreError>> + '_ {
        self.access.iterator().map(|item| {
            let (key, blocks) = item.map_err(|e| StoreError::DataInconsistency(e.to_string()))?;
            let root: [u8; 32] =
                key.as_ref().try_into().map_err(|_| StoreError::DataInconsistency("anchor key is not 32 bytes".into()))?;
            Ok((root, blocks))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::stores::zethora_nullifiers::{DbZethoraNullifiersStore, SPENT_FOR_GOOD};
    use kaspa_database::{create_temp_db, prelude::ConnBuilder};

    #[test]
    fn records_survive_pruning_and_joining_with_their_age() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let anchors = DbZethoraAnchorsStore::new(Arc::clone(&db), CachePolicy::Count(16));
        let tags = DbZethoraNullifiersStore::new(Arc::clone(&db), CachePolicy::Count(16));
        let (on, off) = (Hash::from_u64_word(1), Hash::from_u64_word(2));

        let mut batch = WriteBatch::default();
        anchors.add_batch(&mut batch, on, 50, &[7; 32]).unwrap();
        anchors.add_batch(&mut batch, off, 51, &[8; 32]).unwrap();
        anchors.add_for_good_batch(&mut batch, &[9; 32], 3).unwrap();
        tags.add_batch(&mut batch, on, &[[1; 32], [2; 32]]).unwrap(); // also writes the block -> tags index (another prefix)
        tags.add_spent_for_good_batch(&mut batch, &[3; 32]).unwrap();
        db.write(batch).unwrap();

        // Pruning: the on-chain producer becomes "for good" and keeps its blue score; the side-chain one is dropped
        let mut batch = WriteBatch::default();
        anchors.prune_block_batch(&mut batch, on, &[7; 32], true).unwrap();
        anchors.prune_block_batch(&mut batch, off, &[8; 32], false).unwrap();
        db.write(batch).unwrap();
        assert_eq!(anchors.producing_blocks(&[7; 32]), vec![AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score: 50 }]);
        assert!(anchors.producing_blocks(&[8; 32]).is_empty());

        // Joining twice from the same pruning point adds nothing new
        let mut batch = WriteBatch::default();
        anchors.add_for_good_batch(&mut batch, &[9; 32], 3).unwrap();
        tags.add_spent_for_good_batch(&mut batch, &[3; 32]).unwrap();
        db.write(batch).unwrap();
        assert_eq!(anchors.producing_blocks(&[9; 32]).len(), 1);
        assert_eq!(tags.accepting_blocks(&[3; 32]), vec![SPENT_FOR_GOOD]);

        // Reading everything back sees exactly each store's own records, keys intact
        let mut all_anchors: Vec<_> = anchors.iter_all().map(|r| r.unwrap()).collect();
        all_anchors.sort_by_key(|(root, _)| *root);
        assert_eq!(
            all_anchors,
            vec![
                ([7; 32], vec![AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score: 50 }]),
                ([9; 32], vec![AnchorProducer { block: ANCHORED_FOR_GOOD, blue_score: 3 }]),
            ]
        );
        let mut all_tags: Vec<_> = tags.iter_all().map(|r| r.unwrap()).collect();
        all_tags.sort_by_key(|(tag, _)| *tag);
        assert_eq!(all_tags, vec![([1; 32], vec![on]), ([2; 32], vec![on]), ([3; 32], vec![SPENT_FOR_GOOD])]);
    }
}
