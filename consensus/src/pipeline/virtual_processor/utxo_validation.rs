use super::{VirtualStateProcessor, bounds::SeqCommitBounds};
use crate::{
    errors::{
        BlockProcessResult,
        RuleError::{
            BadAcceptedIDMerkleRoot, BadCoinbaseTransaction, BadUTXOCommitment, InvalidTransactionsInUtxoContext,
            WrongHeaderPruningPoint, WrongSelectedParentOrder, ZethoraSupplyMismatch,
        },
    },
    model::stores::{
        block_transactions::BlockTransactionsStoreReader,
        daa::DaaStoreReader,
        ghostdag::{CompactGhostdagData, GhostdagData},
        headers::HeaderStoreReader,
        zethora_note_trees::ZethoraNoteTreesStoreReader,
        zethora_private_states::ZethoraPrivateStatesStoreReader,
    },
    processes::{
        pruning::PruningPointReply,
        transaction_validator::{
            errors::{TxResult, TxRuleError},
            tx_validation_in_utxo_context::TxValidationFlags,
        },
    },
};
use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
    acceptance_data::{AcceptedTxEntry, MergesetBlockAcceptanceData},
    api::args::TransactionValidationArgs,
    coinbase::*,
    errors::coinbase::CoinbaseError,
    hashing,
    header::Header,
    muhash::MuHashExtensions,
    tx::{MutableTransaction, PopulatedTransaction, Transaction, ValidatedTransaction, VerifiableTransaction},
    utxo::{
        utxo_diff::UtxoDiff,
        utxo_view::{UtxoView, UtxoViewComposition},
    },
};
use kaspa_core::{info, trace};
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use kaspa_utils::refs::Refs;

use crate::model::services::reachability::ReachabilityService;
use crate::model::services::seq_commit_accessor::SeqCommitAccessor;
use kaspa_consensus_core::zethora_private;
use rayon::prelude::*;
use smallvec::{SmallVec, smallvec};
use std::collections::HashSet;
use std::{iter::once, ops::Deref};

/// Per-lane activity and miner payload data extracted from a mergeset.
pub(super) struct MergesetSeqData {
    /// Per-lane activity leaves: lane_id → [activity_leaf hashes].
    /// BTreeMap gives sorted iteration over lanes.
    pub lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>>,
    /// One payload leaf hash per merged block, in mergeset order.
    pub miner_payload_leaves: Vec<Hash>,
}

/// A resolved lane update ready for SMT processing.
pub(super) struct ResolvedLaneUpdate {
    pub lane_key: kaspa_smt_store::LaneKey,
    pub new_tip: Hash,
    /// True if this lane had no active canonical version (new or reactivated).
    pub is_new: bool,
}

/// Selected-parent state the current block inherits when building its seq_commit.
pub(super) struct ParentBlockSeqState {
    /// `accepted_id_merkle_root` of the selected parent.
    pub seq_commit: Hash,
    pub blue_score: u64,
    pub lanes_root: Hash,
    pub active_lanes_count: u64,
}

/// A context for processing the UTXO state of a block with respect to its selected parent.
/// Note this can also be the virtual block.
pub(super) struct UtxoProcessingContext<'a> {
    pub ghostdag_data: Refs<'a, GhostdagData>,
    pub multiset_hash: MuHash,
    pub mergeset_diff: UtxoDiff,
    pub mergeset_acceptance_data: Vec<MergesetBlockAcceptanceData>,
    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
    pub pruning_sample_from_pov: Option<Hash>,
    /// Zethora: the private coin list after this block's mergeset (ZTH-SPEC-006 §6.1)
    pub note_tree: zethora_shielded::NoteCommitmentTree,
    /// Zethora: whether this mergeset added private coins, i.e. produced a new coin list snapshot (anchor, §6.2)
    pub note_tree_grew: bool,
    /// Zethora: private coin tags (nullifiers) accepted by this mergeset so far, as a set and in order (§6.3)
    pub nullifiers: HashSet<[u8; 32]>,
    pub nullifier_list: Vec<[u8; 32]>,
    /// Zethora: the private state fingerprint (ZTH-SPEC-006 §6.4) after this mergeset: every coin tag spent and every
    /// coin list snapshot produced on the chain so far. Unfinalized, so the next chain block can add to it.
    pub private_state: MuHash,
}

impl<'a> UtxoProcessingContext<'a> {
    pub fn new(ghostdag_data: Refs<'a, GhostdagData>, selected_parent_multiset_hash: MuHash) -> Self {
        let mergeset_size = ghostdag_data.mergeset_size();
        Self {
            ghostdag_data,
            multiset_hash: selected_parent_multiset_hash,
            mergeset_diff: UtxoDiff::default(),

            mergeset_rewards: BlockHashMap::with_capacity(mergeset_size),
            mergeset_acceptance_data: Vec::with_capacity(mergeset_size),
            pruning_sample_from_pov: Default::default(),
            note_tree: zethora_shielded::NoteCommitmentTree::new(),
            note_tree_grew: false,
            nullifiers: HashSet::new(),
            nullifier_list: Vec::new(),
            private_state: MuHash::new(),
        }
    }

    pub fn selected_parent(&self) -> Hash {
        self.ghostdag_data.selected_parent
    }
}

impl VirtualStateProcessor {
    /// Calculates UTXO state and transaction acceptance data relative to the selected parent state
    pub(super) fn calculate_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        pov_daa_score: u64,
    ) {
        // Zethora: start from the selected parent's private coin list (ZTH-SPEC-006 §6.1)
        let selected_parent = ctx.selected_parent();
        ctx.note_tree = self.zethora_note_trees_store.get(selected_parent).unwrap_or_else(|e| {
            panic!(
                "Zethora: private coin list missing for {selected_parent} ({e}). (If this node joined from a pruning point, its private state download did not finish.) Restart with --reset-db"
            )
        });
        ctx.private_state = self.zethora_private_states_store.get(selected_parent).unwrap_or_else(|e| {
            panic!(
                "Zethora: private state fingerprint missing for {selected_parent} ({e}). (If this node joined from a pruning point, its private state download did not finish.) Restart with --reset-db"
            )
        });

        let selected_parent_transactions = self.block_transactions_store.get(ctx.selected_parent()).unwrap();
        let validated_coinbase = ValidatedTransaction::new_coinbase(&selected_parent_transactions[0]);

        ctx.mergeset_diff.add_transaction(&validated_coinbase, pov_daa_score).unwrap();
        ctx.multiset_hash.add_transaction(&validated_coinbase, pov_daa_score);
        let validated_coinbase_id = validated_coinbase.id();

        for (i, (merged_block, txs)) in once((ctx.selected_parent(), selected_parent_transactions))
            .chain(
                ctx.ghostdag_data
                    .consensus_ordered_mergeset_without_selected_parent(self.ghostdag_store.deref())
                    .map(|b| (b, self.block_transactions_store.get(b).unwrap())),
            )
            .enumerate()
        {
            // Create a composed UTXO view from the selected parent UTXO view + the mergeset UTXO diff
            let composed_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);

            // The first block in the mergeset is always the selected parent
            let is_selected_parent = i == 0;

            // No need to fully validate selected parent transactions: they were already fully validated when
            // the selected parent passed verify_expected_utxo_state, using its own DAA score for both POV and
            // block DAA score, and its selected parent as the seqcommit context.
            //
            // Here we only replay them while building the child's UTXO state. The child's POV DAA score is
            // safe for non-script checks because maturity and sequence-lock checks are monotonic. Seqcommit
            // context is not monotonic (the threshold can be crossed), but it is only used by script checks,
            // which we skip for selected-parent transactions.
            let validation_flags = if is_selected_parent { TxValidationFlags::SkipScriptChecks } else { TxValidationFlags::Full };
            let (validated_transactions, inner_multiset) = self.validate_transactions_with_muhash_in_parallel(
                &txs,
                &composed_view,
                pov_daa_score,
                self.headers_store.get_daa_score(merged_block).unwrap(),
                validation_flags,
                ctx.selected_parent(),
                &ctx.nullifiers,
            );

            ctx.multiset_hash.combine(&inner_multiset);

            let mut block_fee = 0u64;
            let mut block_base_fee = 0u64; // Zethora: base-fee part (ZTH-SPEC-008)
            let (mut block_pool_in, mut block_pool_out) = (0u64, 0u64); // Zethora: private pool flows (ZTH-SPEC-006)
            for (validated_tx, _) in validated_transactions.iter() {
                ctx.mergeset_diff.add_transaction(validated_tx, pov_daa_score).unwrap();
                block_fee += validated_tx.calculated_fee;
                let compute_mass = self.transaction_validator.mass_calculator.calc_non_contextual_masses(validated_tx.tx).compute_mass;
                block_base_fee += crate::processes::zethora_fees::base_fee(validated_tx.calculated_fee, compute_mass);
                // Already validated, so the value balance is readable
                if let Ok(Some((value_in, value_out))) = kaspa_consensus_core::zethora_private::pool_flows(&validated_tx.tx.payload) {
                    block_pool_in += value_in;
                    block_pool_out += value_out;
                }
            }

            // Zethora: remember the private coin tags this block's accepted transactions spent, so a later block in
            // the same mergeset can't spend them again (ZTH-SPEC-006 §6.3). Within one block they are unique (body rule).
            for (vtx, _) in validated_transactions.iter() {
                for nf in zethora_private::nullifiers(&vtx.tx.payload) {
                    if ctx.nullifiers.insert(nf) {
                        ctx.nullifier_list.push(nf);
                        ctx.private_state.add_element(&zethora_private::private_state_spent_element(&nf));
                    }
                }
            }

            // Zethora: add this block's new private coins to the list, in block order (ZTH-SPEC-006 §6.1).
            // Every node walks the mergeset in the same consensus order, so every node builds the same list.
            let mut private_txs: Vec<_> = validated_transactions
                .iter()
                .filter(|(vtx, _)| kaspa_consensus_core::zethora_private::private_payment_bytes(&vtx.tx.payload).is_some())
                .map(|(vtx, idx)| (*idx, vtx.tx))
                .collect();
            private_txs.sort_by_key(|(idx, _)| *idx);
            for (_, tx) in private_txs {
                let encoded = kaspa_consensus_core::zethora_private::private_payment_bytes(&tx.payload).expect("filtered above");
                for cmx in zethora_shielded::codec::note_commitments(encoded).expect("accepted private payments are well-formed") {
                    ctx.note_tree.append(&cmx).expect("private coin list is full: migrate to a new pool version");
                    ctx.note_tree_grew = true;
                }
            }

            ctx.mergeset_acceptance_data.push(MergesetBlockAcceptanceData {
                block_hash: merged_block,
                // For the selected parent, we prepend the coinbase tx
                accepted_transactions: is_selected_parent
                    .then_some(AcceptedTxEntry { transaction_id: validated_coinbase_id, index_within_block: 0 })
                    .into_iter()
                    .chain(
                        validated_transactions
                            .into_iter()
                            .map(|(tx, tx_idx)| AcceptedTxEntry { transaction_id: tx.id(), index_within_block: tx_idx }),
                    )
                    .collect(),
            });

            let coinbase_data = self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).unwrap();
            ctx.mergeset_rewards.insert(
                merged_block,
                BlockRewardData::new(coinbase_data.subsidy, block_fee, block_base_fee, coinbase_data.miner_data.script_public_key)
                    .with_pool_flows(block_pool_in, block_pool_out),
            );
        }

        // Zethora: this mergeset's final coin list is a new snapshot (anchor) if it grew; add it to the fingerprint with
        // this block's blue score (the anchors store records the same root and score for this block when it is committed)
        if ctx.note_tree_grew {
            ctx.private_state.add_element(&zethora_private::private_state_anchor_element(
                &ctx.note_tree.root().to_bytes(),
                ctx.ghostdag_data.blue_score,
            ));
        }
    }

    /// Verify that the current block fully respects its own UTXO view. We define a block as
    /// UTXO valid if all the following conditions hold:
    ///     1. The block header includes the expected `utxo_commitment`.
    ///     2. The block header includes the expected `accepted_id_merkle_root`.
    ///     3. The block header includes the expected `pruning_point`.
    ///     4. The block coinbase transaction rewards the mergeset blocks correctly.
    ///     5. All non-coinbase block transactions are valid against its own UTXO view.
    pub(super) fn verify_expected_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        header: &Header,
    ) -> BlockProcessResult<Option<kaspa_smt_store::processor::SmtBuild>> {
        // Verify header UTXO commitment
        let expected_commitment = ctx.multiset_hash.finalize();
        if expected_commitment != header.utxo_commitment {
            return Err(BadUTXOCommitment(header.hash, header.utxo_commitment, expected_commitment));
        }
        trace!("correct commitment: {}, {}", header.hash, expected_commitment);

        // KIP-21: compute seq_commit from SMT lane processing
        let (expected_accepted_id_merkle_root, smt_build) = self.recompute_seq_commit(ctx, header)?;
        let smt_build = Some(smt_build);

        // Verify header accepted_id_merkle_root
        if expected_accepted_id_merkle_root != header.accepted_id_merkle_root {
            return Err(BadAcceptedIDMerkleRoot(header.hash, header.accepted_id_merkle_root, expected_accepted_id_merkle_root));
        }

        let txs = self.block_transactions_store.get(header.hash).unwrap();

        // Verify coinbase transaction (including the Zethora supply ledger, measured from the real UTXO changes)
        self.verify_coinbase_transaction(
            &txs[0],
            header.daa_score,
            &ctx.ghostdag_data,
            &ctx.mergeset_rewards,
            &self.daa_excluded_store.get_mergeset_non_daa(header.hash).unwrap(),
            self.visible_change_of(&ctx.mergeset_diff, ctx.selected_parent()),
            ctx.note_tree.root().to_bytes(),
            ctx.private_state.clone().finalize().as_bytes(),
        )?;

        // Verify the header pruning point
        let reply = self.verify_header_pruning_point(header, ctx.ghostdag_data.to_compact())?;
        ctx.pruning_sample_from_pov = Some(reply.pruning_sample);

        // Verify the first parent is the selected parent
        //
        // Purpose: Enables seqcommit opcode verification for syncees. By enforcing this rule,
        // a node can trustlessly verify the selected chain segment below the pruning point
        // (PP) simply by walking back through first-parents, avoiding a full GHOSTDAG
        // computation over the historical DAG.
        //
        // Design Note: This is enforced as a chain-qualification rule rather than
        // header-validity. This maintains compatibility with protocols like DAGKNIGHT,
        // which may not compute selected parents for every block, while still securing
        // the pruning point (which is a qualified chain block by definition).
        let selected_parent = ctx.ghostdag_data.selected_parent;
        let first_parent = header.direct_parents()[0];
        if first_parent != selected_parent {
            return Err(WrongSelectedParentOrder(header.hash, selected_parent, first_parent));
        }

        // Final chain qualification condition: verify all transactions are valid in context.
        //
        // We verify this chain block's transactions in the same way they were built and checked by
        // build_block_template -> validate_block_template_transaction: use the block DAA score as the
        // POV DAA score, and use the selected parent as the seqcommit context. Later, calculate_utxo_state
        // relies on this check when replaying this block as a selected parent.
        let current_utxo_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);
        let validated_transactions = self.validate_transactions_in_parallel(
            &txs,
            &current_utxo_view,
            header.daa_score,
            header.daa_score,
            TxValidationFlags::Full,
            ctx.selected_parent(),
        );
        // Zethora: the block's own transactions may not spend private coin tags its mergeset already spent (§6.3)
        let reused = validated_transactions
            .iter()
            .filter(|(vtx, _)| zethora_private::nullifiers(&vtx.tx.payload).iter().any(|nf| ctx.nullifiers.contains(nf)))
            .count();
        let valid = validated_transactions.len() - reused;
        if valid < txs.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(InvalidTransactionsInUtxoContext(txs.len() - 1 - valid, txs.len() - 1));
        }

        Ok(smt_build)
    }

    fn verify_header_pruning_point(
        &self,
        header: &Header,
        ghostdag_data: CompactGhostdagData,
    ) -> BlockProcessResult<PruningPointReply> {
        let reply = self.pruning_point_manager.expected_header_pruning_point(ghostdag_data);
        if reply.pruning_point != header.pruning_point {
            return Err(WrongHeaderPruningPoint(reply.pruning_point, header.pruning_point));
        }
        Ok(reply)
    }

    fn verify_coinbase_transaction(
        &self,
        coinbase: &Transaction,
        daa_score: u64,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
        visible_change: i128,
        note_root: [u8; 32],
        private_state: [u8; 32],
    ) -> BlockProcessResult<()> {
        // Extract only miner data from the provided coinbase
        let miner_data = self.coinbase_manager.deserialize_coinbase_payload(&coinbase.payload).unwrap().miner_data;
        let parent_pool = self.pool_state_of(ghostdag_data.selected_parent);
        let expected_coinbase = match self.coinbase_manager.expected_coinbase_transaction(
            daa_score,
            miner_data,
            ghostdag_data,
            mergeset_rewards,
            mergeset_non_daa,
            parent_pool,
            visible_change,
            note_root,
            private_state,
        ) {
            Ok(template) => template.tx,
            // Zethora: the block's coins do not add up, so it is invalid (ZTH-SPEC-006 §7.2)
            Err(CoinbaseError::ZethoraSupply(reason)) => return Err(ZethoraSupplyMismatch(reason)),
            Err(e) => panic!("unexpected coinbase error: {e}"),
        };
        if hashing::tx::hash(coinbase) != hashing::tx::hash(&expected_coinbase) { Err(BadCoinbaseTransaction) } else { Ok(()) }
    }

    /// Zethora: net change in visible coins from the transactions a mergeset accepts, measured from the
    /// real UTXO diff. The diff also holds the selected parent's coinbase outputs, which are already
    /// counted in the parent's ledger, so they are taken out here. With correct bookkeeping the result
    /// is minus the mergeset's total fees (ZTH-SPEC-006 §7.2).
    pub(crate) fn visible_change_of(&self, mergeset_diff: &UtxoDiff, selected_parent: Hash) -> i128 {
        let added: i128 = mergeset_diff.add.values().map(|e| e.amount as i128).sum();
        let removed: i128 = mergeset_diff.remove.values().map(|e| e.amount as i128).sum();
        let parent_coinbase: i128 =
            self.block_transactions_store.get(selected_parent).unwrap()[0].outputs.iter().map(|o| o.value as i128).sum();
        added - removed - parent_coinbase
    }

    /// Zethora: is this private coin tag already spent on the selected chain ending at `selected_parent`?
    /// A tag counts as spent if any chain block that accepted it is a chain ancestor of (or is) `selected_parent`.
    /// Records of pruned chain blocks are rewritten to `SPENT_FOR_GOOD` by the pruning processor, so every node
    /// gives the same answer whether or not it has pruned. If reachability is unexpectedly missing, it counts as spent.
    pub(crate) fn nullifier_spent_on_chain(&self, nullifier: &[u8; 32], selected_parent: Hash) -> bool {
        use crate::model::stores::zethora_nullifiers::SPENT_FOR_GOOD;
        self.zethora_nullifiers_store.accepting_blocks(nullifier).into_iter().any(|block| {
            block == SPENT_FOR_GOOD || self.reachability_service.try_is_chain_ancestor_of(block, selected_parent).unwrap_or(true)
        })
    }

    /// Zethora: does this transaction spend a private coin tag that is already spent, either on the chain of
    /// `selected_parent` or in `pending` (tags accepted earlier in the same mergeset / block template)?
    pub(crate) fn private_double_spend(&self, tx: &Transaction, selected_parent: Hash, pending: &HashSet<[u8; 32]>) -> bool {
        zethora_private::nullifiers(&tx.payload)
            .iter()
            .any(|nf| pending.contains(nf) || self.nullifier_spent_on_chain(nf, selected_parent))
    }

    /// Zethora: is `anchor` a private coin list snapshot that a spend accepted on top of `selected_parent` may use?
    /// It must have been produced by a chain ancestor of (or by) `selected_parent` whose blue score is at least
    /// `ANCHOR_DEPTH` below it (ZTH-SPEC-006 §6.2). Records of pruned chain blocks are rewritten to `ANCHORED_FOR_GOOD`
    /// (keeping the blue score) by the pruning processor, and a node joining from a pruning point stores the snapshots
    /// it downloads the same way, so every node gives the same answer whether or not it has pruned or joined late.
    /// If reachability or the tip's header is unexpectedly missing, the anchor does not count.
    pub(crate) fn anchor_matured_on_chain(&self, anchor: &[u8; 32], selected_parent: Hash) -> bool {
        use crate::model::stores::zethora_anchors::ANCHORED_FOR_GOOD;
        let producers = self.zethora_anchors_store.producing_blocks(anchor);
        if producers.is_empty() {
            return false;
        }
        let Ok(tip_blue_score) = self.headers_store.get_blue_score(selected_parent) else { return false };
        producers.into_iter().any(|p| {
            p.blue_score.saturating_add(zethora_private::ANCHOR_DEPTH) <= tip_blue_score
                && (p.block == ANCHORED_FOR_GOOD
                    || self.reachability_service.try_is_chain_ancestor_of(p.block, selected_parent).unwrap_or(false))
        })
    }

    /// Zethora: the private payment rules that depend on the chain a transaction is accepted on (ZTH-SPEC-006):
    /// none of its coin tags is already spent on the chain of `selected_parent` or in `pending` (§6.3), and if it
    /// spends private coins, its anchor is a matured snapshot of that chain's coin list (§6.2).
    pub(crate) fn check_private_payment_in_context(
        &self,
        tx: &Transaction,
        selected_parent: Hash,
        pending: &HashSet<[u8; 32]>,
    ) -> TxResult<()> {
        if self.private_double_spend(tx, selected_parent, pending) {
            return Err(TxRuleError::InvalidPrivatePayment("private coin already spent".to_string()));
        }
        if let Some(anchor) = zethora_private::spend_anchor(&tx.payload)
            && !self.anchor_matured_on_chain(&anchor, selected_parent)
        {
            return Err(TxRuleError::InvalidPrivatePayment(format!(
                "spend uses an unknown or too recent private coin list snapshot (it must be at least {} blocks deep)",
                zethora_private::ANCHOR_DEPTH
            )));
        }
        Ok(())
    }

    /// Zethora: the fee pool state recorded in a block's coinbase (ZTH-SPEC-008).
    /// The pool flows along the selected chain: each chain block reads its selected parent's state.
    pub(crate) fn pool_state_of(&self, block: Hash) -> PoolState {
        let txs = self.block_transactions_store.get(block).unwrap();
        self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).map(|d| d.pool).unwrap()
    }

    /// Validates transactions against the provided `utxo_view` and returns a vector with all transactions
    /// which passed the validation along with their original index within the containing block
    pub(crate) fn validate_transactions_in_parallel<'a, V: UtxoView + Sync>(
        &self,
        txs: &'a Vec<Transaction>,
        utxo_view: &V,
        pov_daa_score: u64,
        block_daa_score: u64,
        flags: TxValidationFlags,
        selected_parent: Hash,
    ) -> Vec<(ValidatedTransaction<'a>, u32)> {
        self.thread_pool.install(|| {
            txs
                .par_iter() // We can do this in parallel without complications since block body validation already ensured
                            // that all txs within each block are independent
                .enumerate()
                .skip(1) // Skip the coinbase tx.
                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score,block_daa_score, flags, selected_parent).ok().map(|vtx| (vtx, i as u32)))
                .collect()
        })
    }

    /// Same as validate_transactions_in_parallel except during the iteration this will also
    /// calculate the muhash in parallel for valid transactions
    pub(crate) fn validate_transactions_with_muhash_in_parallel<'a, V: UtxoView + Sync>(
        &self,
        txs: &'a Vec<Transaction>,
        utxo_view: &V,
        pov_daa_score: u64,
        block_daa_score: u64,
        flags: TxValidationFlags,
        selected_parent: Hash,
        pending_nullifiers: &HashSet<[u8; 32]>,
    ) -> (SmallVec<[(ValidatedTransaction<'a>, u32); 2]>, MuHash) {
        self.thread_pool.install(|| {
            txs
                .par_iter() // We can do this in parallel without complications since block body validation already ensured
                            // that all txs within each block are independent
                .enumerate()
                .skip(1) // Skip the coinbase tx.
                // Zethora: a private coin tag already spent earlier in this mergeset makes the transaction not accepted
                .filter(|(_, tx)| !zethora_private::nullifiers(&tx.payload).iter().any(|nf| pending_nullifiers.contains(nf)))
                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score, block_daa_score, flags, selected_parent).ok().map(|vtx| {
                    let mh = MuHash::from_transaction(&vtx, pov_daa_score);
                    (smallvec![(vtx, i as u32)], mh)
                }
                ))
                .reduce(
                    || (smallvec![], MuHash::new()),
                    |mut a, mut b| {
                        a.0.append(&mut b.0);
                        a.1.combine(&b.1);
                        a
                    },
                )
        })
    }

    /// Attempts to populate the transaction with UTXO entries and performs all utxo-related tx validations
    pub(super) fn validate_transaction_in_utxo_context<'a>(
        &self,
        transaction: &'a Transaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        block_daa_score: u64,
        flags: TxValidationFlags,
        selected_parent: Hash,
    ) -> TxResult<ValidatedTransaction<'a>> {
        // Zethora: private payment rules that depend on the chain: no spent coin tag reused (§6.3), anchor matured (§6.2)
        self.check_private_payment_in_context(transaction, selected_parent, &HashSet::new())?;
        let mut entries = Vec::with_capacity(transaction.inputs.len());
        for input in transaction.inputs.iter() {
            if let Some(entry) = utxo_view.get(&input.previous_outpoint) {
                entries.push(entry);
            } else {
                // Missing at least one input. For perf considerations, we report once a single miss is detected and avoid collecting all possible misses.
                return Err(TxRuleError::MissingTxOutpoints);
            }
        }

        let populated_tx = PopulatedTransaction::new(transaction, entries);

        let seq_commit_accessor =
            SeqCommitAccessor::new(selected_parent, &self.reachability_service, &self.headers_store, self.finality_depth);
        let res = self.transaction_validator.validate_populated_transaction_and_get_fee(
            &populated_tx,
            pov_daa_score,
            block_daa_score,
            flags,
            None,
            Some(&seq_commit_accessor),
        );
        match res {
            Ok(calculated_fee) => Ok(ValidatedTransaction::new(populated_tx, calculated_fee)),
            Err(tx_rule_error) => {
                // TODO (relaxed): aggregate by error types and log through the monitor (in order to not flood the logs)
                info!("Rejecting transaction {} due to transaction rule error: {}", transaction.id(), tx_rule_error);
                Err(tx_rule_error)
            }
        }
    }

    /// Populates the mempool transaction with maximally found UTXO entry data
    pub(crate) fn populate_mempool_transaction_in_utxo_context(
        &self,
        mutable_tx: &mut MutableTransaction,
        utxo_view: &impl UtxoView,
    ) -> TxResult<()> {
        let mut has_missing_outpoints = false;
        for i in 0..mutable_tx.tx.inputs.len() {
            if mutable_tx.entries[i].is_some() {
                // We prefer a previously populated entry if such exists
                continue;
            }
            if let Some(entry) = utxo_view.get(&mutable_tx.tx.inputs[i].previous_outpoint) {
                mutable_tx.entries[i] = Some(entry);
            } else {
                // We attempt to fill as much as possible UTXO entries, hence we do not break in this case but rather continue looping
                has_missing_outpoints = true;
            }
        }
        if has_missing_outpoints {
            return Err(TxRuleError::MissingTxOutpoints);
        }
        Ok(())
    }

    /// Populates the mempool transaction with maximally found UTXO entry data and proceeds to validation if all found
    pub(super) fn validate_mempool_transaction_in_utxo_context(
        &self,
        mutable_tx: &mut MutableTransaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        args: &TransactionValidationArgs,
        selected_parent: Hash,
    ) -> TxResult<()> {
        self.populate_mempool_transaction_in_utxo_context(mutable_tx, utxo_view)?;

        // Calc the contextual storage mass
        let contextual_mass = self
            .transaction_validator
            .mass_calculator
            .calc_contextual_masses(&mutable_tx.as_verifiable())
            .ok_or(TxRuleError::MassIncomputable)?;

        // Set the inner mass field
        mutable_tx.tx.set_storage_mass(contextual_mass.storage_mass);

        // At this point we know all UTXO entries are populated, so we can safely pass the tx as verifiable
        let mass_and_feerate_threshold = args.feerate_threshold.map(|threshold| {
            let mass = kaspa_consensus_core::mass::Mass::new(mutable_tx.calculated_non_contextual_masses.unwrap(), contextual_mass);
            (mass.normalized_max(&self.mempool_mass_cofactors), threshold)
        });

        let seq_commit_accessor =
            SeqCommitAccessor::new(selected_parent, &self.reachability_service, &self.headers_store, self.finality_depth);

        let calculated_fee = self.transaction_validator.validate_populated_transaction_and_get_fee(
            &mutable_tx.as_verifiable(),
            pov_daa_score,
            pov_daa_score,
            TxValidationFlags::SkipMassCheck, // we can skip the mass check since we just set it
            mass_and_feerate_threshold,
            Some(&seq_commit_accessor),
        )?;
        mutable_tx.calculated_fee = Some(calculated_fee);
        Ok(())
    }

    // =========================================================================
    // KIP-21: Sequencing commitment — shared helpers
    // =========================================================================

    /// Collect per-lane activity leaves and miner payload leaves from the mergeset.
    pub(super) fn collect_mergeset_seq_data(&self, ctx: &UtxoProcessingContext) -> MergesetSeqData {
        use kaspa_seq_commit::hashing::{activity_leaf, miner_payload_leaf};
        use kaspa_seq_commit::types::MinerPayloadLeafInput;

        let mut lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>> = std::collections::BTreeMap::new();
        let mut miner_payload_leaves = Vec::new();
        let mut global_merge_idx: u32 = 0;

        for block_acceptance in ctx.mergeset_acceptance_data.iter() {
            let merged_block = block_acceptance.block_hash;
            let merged_header = self.headers_store.get_header(merged_block).unwrap();
            let block_txs = self.block_transactions_store.get(merged_block).unwrap();

            let coinbase_payload = &block_txs[0].payload;
            let mpl = miner_payload_leaf(MinerPayloadLeafInput {
                block_hash: &merged_block,
                blue_work_be_bytes: &merged_header.blue_work.to_be_bytes(),
                payload: coinbase_payload,
            });
            miner_payload_leaves.push(mpl);

            for accepted_tx in block_acceptance.accepted_transactions.iter() {
                let tx = &block_txs[accepted_tx.index_within_block as usize];
                let lane_id: [u8; 20] = *tx.subnetwork_id.as_bytes();
                let al = activity_leaf(&accepted_tx.transaction_id, tx.version, global_merge_idx);
                lane_activities.entry(lane_id).or_default().push(al);
                global_merge_idx += 1;
            }
        }

        MergesetSeqData { lane_activities, miner_payload_leaves }
    }

    /// Resolve lane activities into concrete lane updates: look up existing tips
    /// from DB at the current block's POV, compute new tips via `lane_tip_next`.
    pub(super) fn resolve_lane_updates(
        &self,
        data: &MergesetSeqData,
        context_hash: &Hash,
        current_blue_score: u64,
        parent_blue_score: u64,
        selected_parent: Hash,
        parent_seq_commit: Hash,
    ) -> Vec<ResolvedLaneUpdate> {
        use kaspa_seq_commit::hashing::{activity_digest_lane, lane_key, lane_tip_next};
        use kaspa_seq_commit::types::LaneTipInput;
        let mut updates = Vec::with_capacity(data.lane_activities.len());
        let bounds = SeqCommitBounds::new(parent_blue_score, current_blue_score, self.finality_depth);
        let read_bounds = bounds.selected_parent_read_bounds(); // -> [current - F, parent]

        for (lane_id, activity_leaves) in &data.lane_activities {
            let lk = lane_key(lane_id);
            let ad = activity_digest_lane(activity_leaves.iter().copied());

            // Look up an existing canonical lane tip in [current - F, parent]:
            // the current block supplies the lower cutoff, while target=parent filters
            // anticone entries at (parent, current] at the seek level.
            let existing = self.smt_stores.get_lane(lk, read_bounds, |bh| self.is_smt_canonical(bh, selected_parent));
            // A lane at the window boundary (bs = current - F - 1) is invisible here
            // even though it was active in the parent's window. This is correct: from
            // the current block's POV the lane expired, so a re-touch is a re-activation
            // anchored on parent_seq_commit. The matching expire in `expire_stale_lanes`
            // and this is_new=true cancel in the active_lanes_count arithmetic.
            let is_new = existing.is_none();
            let parent_ref = existing.map(|v| *v.data()).unwrap_or(parent_seq_commit);

            let new_tip = lane_tip_next(&LaneTipInput { parent_ref: &parent_ref, lane_key: &lk, activity_digest: &ad, context_hash });

            updates.push(ResolvedLaneUpdate { lane_key: lk, new_tip, is_new });
        }

        updates
    }

    /// Build the SMT from lane updates + expirations, compute the final seq_commit hash.
    ///
    /// Works with an immutable view of DB state. Returns the commit hash and an `SmtBuild`
    /// containing the diff (updated branches, lane versions, score index) for later persistence.
    ///
    /// `inactivity_shortcut` is folded into `activity_root` next to the active-lanes root.
    pub(super) fn build_seq_commit(
        &self,
        parent: &ParentBlockSeqState,
        context_hash: Hash,
        current_blue_score: u64,
        lane_updates: &[ResolvedLaneUpdate],
        miner_payload_leaves: Vec<Hash>,
        selected_parent: Hash,
        inactivity_shortcut_block: Hash,
        inactivity_shortcut: Hash,
    ) -> (Hash, kaspa_smt_store::processor::SmtBuild) {
        use kaspa_seq_commit::hashing::{activity_root_hash, miner_payload_root, seq_commit, seq_state_root};
        use kaspa_seq_commit::types::{SeqCommitInput, SeqState};
        use kaspa_smt_store::processor::SmtProcessor;

        let bounds = SeqCommitBounds::new(parent.blue_score, current_blue_score, self.finality_depth);
        // 1. Create processor starting from the parent's lanes root
        let mut proc =
            SmtProcessor::new(&self.smt_stores, current_blue_score, bounds.selected_parent_read_bounds(), parent.lanes_root);

        // 2. Expire stale lanes (scans [parent-F, current-F) for lanes with no newer version)
        let expired_count = self.expire_stale_lanes(&mut proc, bounds, selected_parent);

        // 3. Apply lane updates.
        // A lane at the boundary (bs = current-F-1) gets both expired (step 2) and re-added
        // here as is_new=true. This is not wasteful: BlockLaneChanges uses a BTreeMap keyed
        // by lane_key, so update_lane overwrites the expire_lane entry: the walk sees only
        // the final leaf. The two count operations cancel: expired+1, new+1 net zero.
        let mut new_lane_count = 0;
        for lu in lane_updates {
            if lu.is_new {
                new_lane_count += 1;
            }
            proc.update_lane(lu.lane_key, lu.new_tip);
        }

        // 4. Build SMT (skips entirely when no pending leaves: no expirations, no touches)
        let mut build = proc.build(|bh| self.is_smt_canonical(bh, selected_parent)).unwrap();

        // 5. Compute final hash: activity_root -> state_root -> seq_commit.
        let payload_root = miner_payload_root(miner_payload_leaves.into_iter());
        let pd = kaspa_seq_commit::hashing::payload_and_context_digest(&context_hash, &payload_root);
        let activity_root = activity_root_hash(&inactivity_shortcut, &build.root);
        let state_root = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
        let commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent.seq_commit, state_root: &state_root });

        // 6. Store metadata on the build for persistence
        build.payload_and_ctx_digest = pd;
        build.active_lanes_count = parent.active_lanes_count + new_lane_count - expired_count;
        build.inactivity_shortcut_block = inactivity_shortcut_block;

        (commit, build)
    }

    /// KIP-21: Recompute the seq_commit for a chain block from its mergeset acceptance
    /// data and SMT state. The caller compares the result against the header to verify
    /// correctness. Returns the SmtBuild to flush so subsequent blocks can read updated state.
    fn recompute_seq_commit(
        &self,
        ctx: &UtxoProcessingContext,
        header: &Header,
    ) -> BlockProcessResult<(Hash, kaspa_smt_store::processor::SmtBuild)> {
        use kaspa_seq_commit::hashing::mergeset_context_hash;
        use kaspa_seq_commit::types::MergesetContext;

        let selected_parent = ctx.selected_parent();
        let parent_header = self.headers_store.get_header(selected_parent).unwrap();
        let current_blue_score = ctx.ghostdag_data.blue_score;

        let inactivity_shortcut_block = self.compute_inactivity_shortcut_block(&ctx.ghostdag_data);
        let context_hash = mergeset_context_hash(&MergesetContext {
            timestamp: parent_header.timestamp,
            daa_score: header.daa_score,
            blue_score: current_blue_score,
        });
        let inactivity_shortcut = self.inactivity_shortcut(inactivity_shortcut_block);

        let parent_seq_commit = parent_header.accepted_id_merkle_root;
        let data = self.collect_mergeset_seq_data(ctx);
        let lane_updates = self.resolve_lane_updates(
            &data,
            &context_hash,
            current_blue_score,
            parent_header.blue_score,
            selected_parent,
            parent_seq_commit,
        );
        let (parent_lanes_root, parent_active_lanes) = self.get_parent_lanes_root_and_count(selected_parent, parent_header.blue_score);
        let parent_state = ParentBlockSeqState {
            seq_commit: parent_seq_commit,
            blue_score: parent_header.blue_score,
            lanes_root: parent_lanes_root,
            active_lanes_count: parent_active_lanes,
        };

        let (hash, build) = self.build_seq_commit(
            &parent_state,
            context_hash,
            current_blue_score,
            &lane_updates,
            data.miner_payload_leaves,
            selected_parent,
            inactivity_shortcut_block,
            inactivity_shortcut,
        );

        Ok((hash, build))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn test_rayon_reduce_retains_order() {
        // this is an independent test to replicate the behavior of
        // validate_txs_in_parallel and validate_txs_with_muhash_in_parallel
        // and assert that the order of data is retained when doing par_iter
        let data: Vec<u16> = (1..=1000).collect();

        let collected: Vec<u16> = data
            .par_iter()
            .filter_map(|a| {
                let chance: f64 = rand::random();
                if chance < 0.05 {
                    return None;
                }
                Some(*a)
            })
            .collect();

        println!("collected len: {}", collected.len());

        collected.iter().tuple_windows().for_each(|(prev, curr)| {
            // Data was originally sorted, so we check if they remain sorted after filtering
            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
        });

        let reduced: SmallVec<[u16; 2]> = data
            .par_iter()
            .filter_map(|a: &u16| {
                let chance: f64 = rand::random();
                if chance < 0.05 {
                    return None;
                }
                Some(smallvec![*a])
            })
            .reduce(
                || smallvec![],
                |mut arr, mut curr_data| {
                    arr.append(&mut curr_data);
                    arr
                },
            );

        println!("reduced len: {}", reduced.len());

        reduced.iter().tuple_windows().for_each(|(prev, curr)| {
            // Data was originally sorted, so we check if they remain sorted after filtering
            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
        });
    }
}
