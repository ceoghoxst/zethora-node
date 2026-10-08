use super::*;
use crate::errors::{BlockProcessResult, RuleError};
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::{
    headers::HeaderStoreReader, headers_selected_tip::HeadersSelectedTipStoreReader, pruning::PruningStoreReader,
    statuses::StatusesStoreReader,
};
use kaspa_consensus_core::BlockLevel;
use kaspa_consensus_core::blockhash::BlockHashExtensions;
use kaspa_consensus_core::blockstatus::BlockStatus::StatusInvalid;
use kaspa_consensus_core::header::Header;
use kaspa_core::time::unix_now;
use kaspa_database::prelude::StoreResultExt;
use kaspa_pow::calc_level_from_pow;

impl HeaderProcessor {
    /// Validates the header in isolation including pow check against header declared bits.
    /// Returns the block level as computed from pow state or a rule error if such was encountered
    pub(super) fn validate_header_in_isolation(&self, header: &Header, trusted: bool) -> BlockProcessResult<BlockLevel> {
        self.check_header_version(header)?;
        self.check_block_timestamp_in_isolation(header)?;
        self.check_parents_limit(header)?;
        Self::check_parents_not_origin(header)?;
        self.check_pow_epoch_plausible(header, trusted)?;
        self.check_pow_and_calc_block_level(header)
    }

    pub(super) fn validate_parent_relations(&self, header: &Header) -> BlockProcessResult<()> {
        self.check_parents_exist(header)?;
        self.check_parents_incest(header)?;
        Ok(())
    }

    fn check_header_version(&self, header: &Header) -> BlockProcessResult<()> {
        let expected_version = self.block_version;
        if header.version != expected_version {
            return Err(RuleError::WrongBlockVersion(header.version, expected_version));
        }
        Ok(())
    }

    fn check_block_timestamp_in_isolation(&self, header: &Header) -> BlockProcessResult<()> {
        // Timestamp deviation tolerance is in seconds so we multiply by 1000 to get milliseconds (without BPS dependency)
        let max_block_time = unix_now() + self.timestamp_deviation_tolerance * 1000;
        if header.timestamp > max_block_time {
            return Err(RuleError::TimeTooFarIntoTheFuture(header.timestamp, max_block_time));
        }
        Ok(())
    }

    fn check_parents_limit(&self, header: &Header) -> BlockProcessResult<()> {
        if header.direct_parents().is_empty() {
            return Err(RuleError::NoParents);
        }

        let max_block_parents = self.max_block_parents as usize;
        if header.direct_parents().len() > max_block_parents {
            return Err(RuleError::TooManyParents(header.direct_parents().len(), max_block_parents));
        }

        Ok(())
    }

    fn check_parents_not_origin(header: &Header) -> BlockProcessResult<()> {
        if header.direct_parents().iter().any(|&parent| parent.is_origin()) {
            return Err(RuleError::OriginParent);
        }

        Ok(())
    }

    fn check_parents_exist(&self, header: &Header) -> BlockProcessResult<()> {
        let mut missing_parents = Vec::new();
        for parent in header.direct_parents() {
            match self.statuses_store.read().get(*parent).optional().unwrap() {
                None => missing_parents.push(*parent),
                Some(StatusInvalid) => {
                    return Err(RuleError::InvalidParent(*parent));
                }
                Some(_) => {}
            }
        }
        if !missing_parents.is_empty() {
            return Err(RuleError::MissingParents(missing_parents));
        }
        Ok(())
    }

    fn check_parents_incest(&self, header: &Header) -> BlockProcessResult<()> {
        let parents = header.direct_parents();
        for parent_a in parents.iter() {
            for parent_b in parents.iter() {
                if parent_a == parent_b {
                    continue;
                }

                if self.reachability_service.is_dag_ancestor_of(*parent_a, *parent_b) {
                    return Err(RuleError::InvalidParentsRelation(*parent_a, *parent_b));
                }
            }
        }

        Ok(())
    }

    /// Zethora (step 6b): the RandomZ key, and so the cost of checking the PoW, depends on the epoch of the header's DAA
    /// score, which is only checked exactly later (after GHOSTDAG). Checking a header from a new epoch costs a 256 MiB,
    /// ~2 s light-mode setup, so before that we only accept DAA scores in the epochs a valid header can currently have:
    /// - trusted headers (sent with a pruning point during sync): the pruning point's epoch, give or take one;
    /// - ordinary headers: from one epoch below the pruning point's (every valid header is in the pruning point's
    ///   future) to one epoch above the highest known header (the tip moves by far less than an epoch while the header
    ///   is in flight).
    ///
    /// That is at most 4 epochs, which is how many setups `randomz` keeps, so bogus headers cannot make a node rebuild
    /// setups over and over. An ordinary header outside the range is refused without checking its PoW: as missing its
    /// parents when some are unknown (a node that is behind treats it like any far-ahead block and syncs), otherwise as
    /// invalid. Valid headers are never refused here: the range only rules out DAA scores that consensus rejects anyway.
    fn check_pow_epoch_plausible(&self, header: &Header, trusted: bool) -> BlockProcessResult<()> {
        if self.skip_proof_of_work {
            return Ok(());
        }
        let Some(pruning_point_daa_score) = self
            .pruning_point_store
            .read()
            .pruning_point()
            .optional()
            .unwrap()
            .and_then(|pruning_point| self.headers_store.get_daa_score(pruning_point).optional().unwrap())
        else {
            return Ok(()); // Not initialized yet (nothing to compare with)
        };
        let pruning_point_epoch = kaspa_pow::randomz::epoch_of(pruning_point_daa_score);
        let (low, high) = if trusted {
            (pruning_point_epoch.saturating_sub(1), pruning_point_epoch.saturating_add(1))
        } else {
            let tip_daa_score = self
                .headers_selected_tip_store
                .read()
                .get()
                .optional()
                .unwrap()
                .and_then(|tip| self.headers_store.get_daa_score(tip.hash).optional().unwrap())
                .unwrap_or(pruning_point_daa_score);
            let highest_epoch = kaspa_pow::randomz::epoch_of(tip_daa_score.max(pruning_point_daa_score));
            (pruning_point_epoch.saturating_sub(1), highest_epoch.saturating_add(1))
        };
        let epoch = kaspa_pow::randomz::epoch_of(header.daa_score);
        if (low..=high).contains(&epoch) {
            return Ok(());
        }
        if !trusted {
            // Reports unknown parents (or an invalid one) first, so a far-ahead block is handled as an orphan
            self.check_parents_exist(header)?;
        }
        Err(RuleError::ZethoraPowEpochOutOfRange(header.daa_score, epoch, low, high))
    }

    fn check_pow_and_calc_block_level(&self, header: &Header) -> BlockProcessResult<BlockLevel> {
        let state = kaspa_pow::State::new(header);
        let (passed, pow) = state.check_pow(header.nonce);
        if passed || self.skip_proof_of_work { Ok(calc_level_from_pow(pow, self.max_block_level)) } else { Err(RuleError::InvalidPoW) }
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::ConfigBuilder, consensus::test_consensus::TestConsensus, errors::RuleError};
    use kaspa_consensus_core::{api::ConsensusApi, block::Block, config::params::DEVNET_PARAMS, header::Header};
    use kaspa_core::assert_match;
    use kaspa_hashes::Hash;
    use kaspa_pow::randomz::{EPOCH_LENGTH, epoch_of};

    /// Zethora (step 6b): headers claiming a DAA score in a far key epoch are refused before their PoW is checked (which
    /// would cost a new 256 MiB light-mode setup), and headers in range still get the normal PoW check.
    #[tokio::test]
    async fn zethora_pow_epoch_out_of_range_is_refused_before_pow() {
        let config = ConfigBuilder::new(DEVNET_PARAMS).build();
        let consensus = TestConsensus::new(&config);
        let wait_handles = consensus.init();
        let genesis = config.genesis.hash;
        let genesis_epoch = epoch_of(config.genesis.daa_score);
        let far_daa_score = (genesis_epoch + 2) * EPOCH_LENGTH;

        // Known parent, DAA score two epochs past the tip's: invalid, refused without a PoW check
        let mut far = consensus.build_header_only_block_with_parents(1.into(), vec![genesis]);
        far.header.daa_score = far_daa_score;
        let (version, timestamp) = (far.header.version, far.header.timestamp);
        let result = consensus.validate_and_insert_block(far.to_immutable()).block_task.await;
        assert_match!(result, Err(RuleError::ZethoraPowEpochOutOfRange(score, epoch, _, high)) if score == far_daa_score && epoch == genesis_epoch + 2 && high == genesis_epoch + 1);

        // Unknown parent and far ahead: reported as an orphan (so a node that is behind syncs), without a PoW check
        let mut orphan = Header::from_precomputed_hash(2.into(), vec![99.into()]);
        orphan.version = version;
        orphan.timestamp = timestamp;
        orphan.daa_score = far_daa_score;
        let result = consensus.validate_and_insert_block(Block::from_header(orphan)).block_task.await;
        assert_match!(result, Err(RuleError::MissingParents(missing)) if missing == vec![Hash::from(99)]);

        // In range: goes on to the normal checks (this test header's nonce is not mined, so its PoW may fail)
        let near = consensus.build_header_only_block_with_parents(3.into(), vec![genesis]);
        let result = consensus.validate_and_insert_block(near.to_immutable()).block_task.await;
        assert!(matches!(result, Ok(_) | Err(RuleError::InvalidPoW)), "in-range header was refused: {result:?}");

        consensus.shutdown(wait_handles);
    }
}
