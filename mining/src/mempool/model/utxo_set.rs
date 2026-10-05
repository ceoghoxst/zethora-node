use std::collections::{HashMap, HashSet};

use crate::{
    mempool::{
        errors::RuleResult,
        model::{map::OutpointIndex, tx::DoubleSpend},
    },
    model::TransactionIdSet,
};
use kaspa_consensus_core::{
    constants::UNACCEPTED_DAA_SCORE,
    tx::{MutableTransaction, TransactionId, TransactionOutpoint, UtxoEntry},
    utxo::utxo_collection::UtxoCollection,
    zethora_private,
};

pub(crate) struct MempoolUtxoSet {
    pool_unspent_outputs: UtxoCollection,
    outpoint_owner_id: OutpointIndex,
    /// Zethora: which mempool transaction reveals each private coin tag (nullifier), ZTH-SPEC-006 §6.3.
    /// Two waiting payments may not spend the same private coin, just like two may not spend the same visible output.
    nullifier_owner_id: HashMap<[u8; 32], TransactionId>,
}

impl MempoolUtxoSet {
    pub(crate) fn new() -> Self {
        Self {
            pool_unspent_outputs: UtxoCollection::default(),
            outpoint_owner_id: OutpointIndex::default(),
            nullifier_owner_id: HashMap::new(),
        }
    }

    pub(crate) fn add_transaction(&mut self, transaction: &MutableTransaction) {
        let transaction_id = transaction.id();
        let mut outpoint = TransactionOutpoint::new(transaction_id, 0);

        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            outpoint.index = i as u32;

            // Delete the output this input spends, in case it was created by mempool.
            // If the outpoint doesn't exist in self.pool_unspent_outputs - this means
            // it was created in the DAG (a.k.a. in consensus).
            self.pool_unspent_outputs.remove(&outpoint);

            self.outpoint_owner_id.insert(input.previous_outpoint, transaction_id);
        }

        for (i, output) in transaction.tx.outputs.iter().enumerate() {
            let outpoint = TransactionOutpoint::new(transaction_id, i as u32);
            let entry = UtxoEntry::new(
                output.value,
                output.script_public_key.clone(),
                UNACCEPTED_DAA_SCORE,
                false,
                output.covenant.map(|x| x.covenant_id),
            );
            self.pool_unspent_outputs.insert(outpoint, entry);
        }

        for nullifier in zethora_private::nullifiers(&transaction.tx.payload) {
            let previous_owner = self.nullifier_owner_id.insert(nullifier, transaction_id);
            debug_assert!(
                previous_owner.is_none_or(|id| id == transaction_id),
                "Zethora: private coin tag already held by another mempool transaction; insertion skipped the conflict check"
            );
        }
    }

    pub(crate) fn remove_transaction(&mut self, transaction: &MutableTransaction, parent_ids_in_pool: &TransactionIdSet) {
        let transaction_id = transaction.id();
        // We cannot assume here that the transaction is fully populated.
        // Notably, this is not the case when revalidate_transaction fails and leads the execution path here.
        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            if let Some(ref entry) = transaction.entries[i] {
                // If the transaction creating the output spent by this input is in the mempool - restore it's UTXO
                if parent_ids_in_pool.contains(&input.previous_outpoint.transaction_id) {
                    self.pool_unspent_outputs.insert(input.previous_outpoint, entry.clone());
                }
            }
            self.outpoint_owner_id.remove(&input.previous_outpoint);
        }

        let mut outpoint = TransactionOutpoint::new(transaction_id, 0);
        for i in 0..transaction.tx.outputs.len() {
            outpoint.index = i as u32;
            self.pool_unspent_outputs.remove(&outpoint);
        }

        for nullifier in zethora_private::nullifiers(&transaction.tx.payload) {
            if self.nullifier_owner_id.get(&nullifier) == Some(&transaction_id) {
                self.nullifier_owner_id.remove(&nullifier);
            }
        }
    }

    /// Zethora: the mempool transaction already revealing this private coin tag, if any.
    pub(crate) fn get_nullifier_owner_id(&self, nullifier: &[u8; 32]) -> Option<&TransactionId> {
        self.nullifier_owner_id.get(nullifier)
    }

    /// Zethora: every other mempool transaction spending one of the private coins this transaction spends,
    /// once each, with the first shared coin tag (ZTH-SPEC-006 §6.3). Empty for ordinary transactions.
    pub(crate) fn get_nullifier_conflicts(&self, transaction: &MutableTransaction) -> Vec<([u8; 32], TransactionId)> {
        let transaction_id = transaction.id();
        let mut conflicts = vec![];
        let mut visited = HashSet::new();
        for nullifier in zethora_private::nullifiers(&transaction.tx.payload) {
            if let Some(owner_id) = self.nullifier_owner_id.get(&nullifier)
                && *owner_id != transaction_id
                && visited.insert(*owner_id)
            {
                conflicts.push((nullifier, *owner_id));
            }
        }
        conflicts
    }

    pub(crate) fn get_outpoint_owner_id(&self, outpoint: &TransactionOutpoint) -> Option<&TransactionId> {
        self.outpoint_owner_id.get(outpoint)
    }

    /// Make sure no other transaction in the mempool is already spending an output which one of this transaction inputs spends
    pub(crate) fn check_double_spends(&self, transaction: &MutableTransaction) -> RuleResult<()> {
        match self.get_first_double_spend(transaction) {
            Some(double_spend) => Err(double_spend.into()),
            None => Ok(()),
        }
    }

    pub(crate) fn get_first_double_spend(&self, transaction: &MutableTransaction) -> Option<DoubleSpend> {
        let transaction_id = transaction.id();
        for input in transaction.tx.inputs.iter() {
            if let Some(existing_transaction_id) = self.get_outpoint_owner_id(&input.previous_outpoint)
                && *existing_transaction_id != transaction_id
            {
                return Some(DoubleSpend::new(input.previous_outpoint, *existing_transaction_id));
            }
        }
        None
    }

    /// Returns the first double spend of every transaction in the mempool double spending on `transaction`
    pub(crate) fn get_double_spend_transaction_ids(&self, transaction: &MutableTransaction) -> Vec<DoubleSpend> {
        let transaction_id = transaction.id();
        let mut double_spends = vec![];
        let mut visited = HashSet::new();
        for input in transaction.tx.inputs.iter() {
            if let Some(existing_transaction_id) = self.get_outpoint_owner_id(&input.previous_outpoint)
                && *existing_transaction_id != transaction_id
                && visited.insert(*existing_transaction_id)
            {
                double_spends.push(DoubleSpend::new(input.previous_outpoint, *existing_transaction_id));
            }
        }
        double_spends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{
        constants::TX_VERSION,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::Transaction,
        zethora_private::{ACTION_SIZE, PRIVATE_PAYMENT_MAGIC},
    };

    /// A transaction whose payload reveals these private coin tags (only the fields the index reads are filled in).
    fn private_tx(nullifiers: &[[u8; 32]], salt: u8) -> MutableTransaction {
        let mut payload = PRIVATE_PAYMENT_MAGIC.to_vec();
        payload.push(1); // pool version
        payload.extend_from_slice(&(nullifiers.len() as u16).to_le_bytes());
        for nullifier in nullifiers {
            let mut action = vec![salt; ACTION_SIZE];
            action[32..64].copy_from_slice(nullifier);
            payload.extend(action);
        }
        MutableTransaction::from_tx(Transaction::new(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, payload))
    }

    #[test]
    fn tracks_private_coin_tags_of_waiting_transactions() {
        let mut set = MempoolUtxoSet::new();
        let first = private_tx(&[[0xAA; 32], [0xBB; 32]], 1);
        set.add_transaction(&first);
        assert_eq!(set.get_nullifier_owner_id(&[0xAA; 32]), Some(&first.id()));
        assert_eq!(set.get_nullifier_owner_id(&[0xBB; 32]), Some(&first.id()));
        assert!(set.get_nullifier_conflicts(&first).is_empty(), "a transaction never conflicts with itself");

        // Shares one coin tag: one conflict, reported once, with the shared tag
        let second = private_tx(&[[0xCC; 32], [0xBB; 32]], 2);
        assert_eq!(set.get_nullifier_conflicts(&second), vec![([0xBB; 32], first.id())]);
        // Shares both coin tags: still one conflict per conflicting transaction
        let third = private_tx(&[[0xAA; 32], [0xBB; 32]], 3);
        assert_eq!(set.get_nullifier_conflicts(&third), vec![([0xAA; 32], first.id())]);
        // Ordinary transactions and fresh coin tags never conflict
        assert!(set.get_nullifier_conflicts(&private_tx(&[[0xDD; 32]], 4)).is_empty());
        let ordinary =
            MutableTransaction::from_tx(Transaction::new(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![7; 80]));
        assert!(set.get_nullifier_conflicts(&ordinary).is_empty());

        // Removing a transaction frees its coin tags, but never tags another transaction now holds
        set.remove_transaction(&third, &TransactionIdSet::default()); // never added: must not touch first's tags
        assert_eq!(set.get_nullifier_owner_id(&[0xAA; 32]), Some(&first.id()));
        set.remove_transaction(&first, &TransactionIdSet::default());
        assert_eq!(set.get_nullifier_owner_id(&[0xAA; 32]), None);
        assert_eq!(set.get_nullifier_owner_id(&[0xBB; 32]), None);
        assert!(set.get_nullifier_conflicts(&second).is_empty());
    }
}
