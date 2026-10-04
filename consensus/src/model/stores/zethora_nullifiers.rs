//! Zethora: the double-spend guard's memory (ZTH-SPEC-006 §6.3).
//!
//! Maps every private coin tag (nullifier) ever accepted to the chain block(s) that accepted it.
//! A tag counts as spent "as of" a block if any of its accepting blocks is on that block's selected chain.
//! Keeping the accepting blocks (instead of a plain set) makes reorgs safe without undo logs: a block that
//! falls off the chain simply stops counting.
//!
//! The spent-tag set itself is kept forever (a known cost of Orchard-style privacy). When an accepting block is
//! pruned, its reference is rewritten so the answer never changes: a pruned block that was on the selected chain
//! becomes `ZERO_HASH` ("spent for good"), and a pruned block that was not is removed from the list.

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::{Hash, ZERO_HASH};
use rocksdb::WriteBatch;
use std::sync::Arc;

/// Marks a tag whose accepting chain block has been pruned: spent for good.
pub const SPENT_FOR_GOOD: Hash = ZERO_HASH;

#[derive(Clone)]
pub struct DbZethoraNullifiersStore {
    access: CachedDbAccess<Hash, Vec<Hash>, BlockHasher>,
    /// Reverse index: chain block -> tags its mergeset accepted (needed to rewrite records when pruning)
    by_block: CachedDbAccess<Hash, Vec<Hash>, BlockHasher>,
}

impl DbZethoraNullifiersStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            access: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::ZethoraNullifiers.into()),
            by_block: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ZethoraBlockNullifiers.into()),
        }
    }

    /// The chain blocks that accepted this tag (empty if never seen).
    pub fn accepting_blocks(&self, nullifier: &[u8; 32]) -> Vec<Hash> {
        match self.access.read(Hash::from_bytes(*nullifier)) {
            Ok(blocks) => blocks,
            Err(StoreError::KeyNotFound(_)) => Vec::new(),
            Err(e) => panic!("Zethora nullifier store read failed: {e}"),
        }
    }

    /// Records that `block` (a chain block) accepted these tags. Each tag must appear once in `nullifiers`.
    pub fn add_batch(&self, batch: &mut WriteBatch, block: Hash, nullifiers: &[[u8; 32]]) -> Result<(), StoreError> {
        if nullifiers.is_empty() {
            return Ok(());
        }
        for nf in nullifiers {
            let mut blocks = self.accepting_blocks(nf);
            if !blocks.contains(&block) {
                blocks.push(block);
                self.access.write(BatchDbWriter::new(batch), Hash::from_bytes(*nf), blocks)?;
            }
        }
        self.by_block.write(BatchDbWriter::new(batch), block, nullifiers.iter().map(|nf| Hash::from_bytes(*nf)).collect())?;
        Ok(())
    }

    /// Called when `block` is pruned. `was_on_chain`: whether it is a chain ancestor of the new pruning point.
    /// Rewrites every record that mentions it so spent/unspent answers stay the same after pruning.
    pub fn prune_block_batch(&self, batch: &mut WriteBatch, block: Hash, was_on_chain: bool) -> Result<(), StoreError> {
        let tags = match self.by_block.read(block) {
            Ok(tags) => tags,
            Err(StoreError::KeyNotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        for tag in tags {
            let mut blocks = self.accepting_blocks(&tag.as_bytes());
            blocks.retain(|b| *b != block);
            if was_on_chain && !blocks.contains(&SPENT_FOR_GOOD) {
                blocks.push(SPENT_FOR_GOOD);
            }
            if blocks.is_empty() {
                self.access.delete(BatchDbWriter::new(batch), tag)?;
            } else {
                self.access.write(BatchDbWriter::new(batch), tag, blocks)?;
            }
        }
        self.by_block.delete(BatchDbWriter::new(batch), block)
    }
}
