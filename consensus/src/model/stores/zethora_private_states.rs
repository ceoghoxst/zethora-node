//! Zethora: the private state fingerprint after each chain block (ZTH-SPEC-006 §6.4).
//!
//! A MuHash set hash over every private coin tag spent on the chain and every coin list snapshot (anchor) the chain
//! produced, up to and including the block's mergeset. Kept unfinalized (like the UTXO multisets) so the next chain
//! block can add to it. Its finalized hash is sealed in the block's coinbase.

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_math::Uint3072;
use kaspa_muhash::MuHash;
use rocksdb::WriteBatch;
use std::sync::Arc;

pub trait ZethoraPrivateStatesStoreReader {
    fn get(&self, hash: Hash) -> Result<MuHash, StoreError>;
}

#[derive(Clone)]
pub struct DbZethoraPrivateStatesStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, Uint3072, BlockHasher>,
}

impl DbZethoraPrivateStatesStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ZethoraPrivateStates.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, hash: Hash, state: MuHash) -> Result<(), StoreError> {
        self.access.write(
            BatchDbWriter::new(batch),
            hash,
            state.try_into().expect("private state multiset is expected to be finalized"),
        )
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl ZethoraPrivateStatesStoreReader for DbZethoraPrivateStatesStore {
    fn get(&self, hash: Hash) -> Result<MuHash, StoreError> {
        Ok(self.access.read(hash)?.into())
    }
}
