//! Zethora: the private coin list (note commitment tree frontier) after each chain block (ZTH-SPEC-006 §6.1).
//! Stored as compact bytes (see `zethora_shielded::NoteCommitmentTree::to_bytes`).

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use rocksdb::WriteBatch;
use std::sync::Arc;
use zethora_shielded::NoteCommitmentTree;

pub trait ZethoraNoteTreesStoreReader {
    fn get(&self, hash: Hash) -> Result<NoteCommitmentTree, StoreError>;
}

#[derive(Clone)]
pub struct DbZethoraNoteTreesStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, Vec<u8>, BlockHasher>,
}

impl DbZethoraNoteTreesStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ZethoraNoteTrees.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, hash: Hash, tree: &NoteCommitmentTree) -> Result<(), StoreError> {
        self.access.write(BatchDbWriter::new(batch), hash, tree.to_bytes())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl ZethoraNoteTreesStoreReader for DbZethoraNoteTreesStore {
    fn get(&self, hash: Hash) -> Result<NoteCommitmentTree, StoreError> {
        let bytes = self.access.read(hash)?;
        Ok(NoteCommitmentTree::from_bytes(&bytes).expect("stored note tree bytes are valid"))
    }
}
