use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet,
    coinbase::*,
    config::params::ForkedParam,
    errors::coinbase::{CoinbaseError, CoinbaseResult},
    subnets,
    tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput},
};
use std::convert::TryInto;

use crate::{
    constants,
    model::stores::ghostdag::GhostdagData,
    processes::{
        zethora_fees,
        zethora_subsidy::ZethoraSubsidy,
        zethora_supply::{self, BlockFlows},
    },
};
use std::sync::Arc;

const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
/// Zethora supply ledger: pool balance, total burned, total issued, transparent supply, shielded balance (5 x u64)
const LENGTH_OF_POOL_STATE: usize = 5 * size_of::<u64>();
/// Zethora: root of the private coin list (32 bytes)
const LENGTH_OF_NOTE_ROOT: usize = 32;
/// Zethora: private state fingerprint: spent coin tags and coin list snapshots (32 bytes)
const LENGTH_OF_PRIVATE_STATE: usize = 32;
const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();

const MIN_PAYLOAD_LENGTH: usize = LENGTH_OF_BLUE_SCORE
    + LENGTH_OF_SUBSIDY
    + LENGTH_OF_POOL_STATE
    + LENGTH_OF_NOTE_ROOT
    + LENGTH_OF_PRIVATE_STATE
    + LENGTH_OF_SCRIPT_PUB_KEY_VERSION
    + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60

#[derive(Clone)]
pub struct CoinbaseManager {
    coinbase_payload_script_public_key_max_len: u8,
    max_coinbase_payload_len: usize,
    deflationary_phase_daa_score: u64,
    pre_deflationary_phase_base_subsidy: u64,
    bps_history: ForkedParam<u64>,

    /// The crescendo activation DAA score where BPS increased from 1 to 10.
    /// This score is required here long-term (and not only for the actual forking), in
    /// order to correctly determine the subsidy month from the live DAA score of the network   
    crescendo_activation_daa_score: u64,

    /// Zethora: smooth-decay subsidy, ZTH-SPEC-001 Section 5
    zethora_subsidy: Arc<ZethoraSubsidy>,
}

/// Struct used to streamline payload parsing
struct PayloadParser<'a> {
    remaining: &'a [u8], // The unparsed remainder
}

impl<'a> PayloadParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    fn take(&mut self, n: usize) -> &[u8] {
        let (segment, remaining) = self.remaining.split_at(n);
        self.remaining = remaining;
        segment
    }
}

impl CoinbaseManager {
    pub fn new(
        coinbase_payload_script_public_key_max_len: u8,
        max_coinbase_payload_len: usize,
        deflationary_phase_daa_score: u64,
        pre_deflationary_phase_base_subsidy: u64,
        bps_history: ForkedParam<u64>,
    ) -> Self {
        Self {
            coinbase_payload_script_public_key_max_len,
            max_coinbase_payload_len,
            deflationary_phase_daa_score,
            pre_deflationary_phase_base_subsidy,
            bps_history,
            crescendo_activation_daa_score: bps_history.activation().daa_score(),
            zethora_subsidy: Arc::new(ZethoraSubsidy::new()),
        }
    }

    #[cfg(test)]
    #[inline]
    pub fn bps(&self) -> ForkedParam<u64> {
        self.bps_history
    }

    #[allow(clippy::too_many_arguments)]
    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
        &self,
        daa_score: u64,
        miner_data: MinerData<T>,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
        parent_pool: PoolState,
        visible_change: i128,
        note_root: [u8; 32],
        private_state: [u8; 32],
    ) -> CoinbaseResult<CoinbaseTransactionTemplate> {
        let mut outputs = Vec::with_capacity(ghostdag_data.mergeset_blues.len() + 1); // + 1 for possible red reward

        // Zethora (ZTH-SPEC-008): miners get subsidy + tips; base fees go 60% to the pool, 40% burned.
        let base_total: u64 = mergeset_rewards.values().map(|r| r.base_fees).sum();
        let pool = zethora_fees::pool_step(parent_pool, base_total);

        // Zethora supply ledger (ZTH-SPEC-006 §7.2): count every zet this coinbase creates or destroys
        let mut issued = 0u64;
        let mut unpaid = 0u64;

        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(blue).unwrap();
            issued += reward_data.subsidy;
            if reward_data.subsidy + reward_data.tips() > 0 {
                outputs.push(TransactionOutput::new(reward_data.subsidy + reward_data.tips(), reward_data.script_public_key.clone()));
            }
        }

        // Zethora: a blue block outside the DAA window is paid nothing, so its tips are destroyed (counted as burned).
        // Such a block may have no reward data at all (e.g. genesis in the very first virtual state): nothing is lost then.
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| mergeset_non_daa.contains(h)) {
            unpaid += mergeset_rewards.get(blue).map_or(0, |r| r.tips());
        }

        // Collect all rewards from mergeset reds ∩ DAA window and create a
        // single output rewarding all to the current block (the "merging" block)
        let mut red_reward = 0u64;

        for red in ghostdag_data.mergeset_reds.iter() {
            let reward_data = mergeset_rewards.get(red).unwrap();
            if mergeset_non_daa.contains(red) {
                red_reward += reward_data.tips();
            } else {
                red_reward += reward_data.subsidy + reward_data.tips();
                issued += reward_data.subsidy;
            }
        }

        // Zethora: this block's payout from the fee pool goes to this block's miner (same output as red rewards)
        red_reward += pool.payout;

        if red_reward > 0 {
            outputs.push(TransactionOutput::new(red_reward, miner_data.script_public_key.clone()));
        }

        // Zethora: build this block's supply ledger from what it really does, and refuse it if it does not balance
        let coinbase_out: u64 = outputs.iter().map(|o| o.value).sum();
        // Zethora: value moved into / out of the private pool by the accepted transactions (the turnstile)
        let shielded_in: u64 = mergeset_rewards.values().map(|r| r.pool_in).sum();
        let shielded_out: u64 = mergeset_rewards.values().map(|r| r.pool_out).sum();
        let flows = BlockFlows { issued, unpaid, visible_change, coinbase_out, shielded_in, shielded_out };
        let ledger =
            zethora_supply::ledger_step(parent_pool, pool.next, flows).map_err(|e| CoinbaseError::ZethoraSupply(e.to_string()))?;

        // Build the current block's payload
        let subsidy = self.calc_block_subsidy(daa_score);
        let payload = self.serialize_coinbase_payload(&CoinbaseData {
            blue_score: ghostdag_data.blue_score,
            subsidy,
            pool: ledger,
            note_root,
            private_state,
            miner_data,
        })?;

        Ok(CoinbaseTransactionTemplate {
            tx: Transaction::new(constants::TX_VERSION_TOCCATA, vec![], outputs, 0, subnets::SUBNETWORK_ID_COINBASE, 0, payload),
            has_red_reward: red_reward > 0,
        })
    }

    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = data.miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }
        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
            .chain(data.pool.pool_balance.to_le_bytes().iter().copied())                        // Zethora: pool balance        (u64)
            .chain(data.pool.total_burned.to_le_bytes().iter().copied())                        // Zethora: total burned        (u64)
            .chain(data.pool.total_issued.to_le_bytes().iter().copied())                        // Zethora: total issued        (u64)
            .chain(data.pool.transparent_supply.to_le_bytes().iter().copied())                  // Zethora: transparent supply  (u64)
            .chain(data.pool.shielded_balance.to_le_bytes().iter().copied())                    // Zethora: shielded balance    (u64)
            .chain(data.note_root.iter().copied())                                              // Zethora: private coin list root ([u8; 32])
            .chain(data.private_state.iter().copied())                                          // Zethora: private state fingerprint ([u8; 32])
            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
            .collect();

        Ok(payload)
    }

    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Keep only blue score, subsidy and the Zethora supply ledger. Note that truncate does not modify capacity, so
        // the usual case where the payloads are the same size will not trigger a reallocation
        payload
            .truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_POOL_STATE + LENGTH_OF_NOTE_ROOT + LENGTH_OF_PRIVATE_STATE);
        payload.extend(
            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
        );

        Ok(payload)
    }

    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
        }

        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        let mut parser = PayloadParser::new(payload);

        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
        let pool_balance = u64::from_le_bytes(parser.take(8).try_into().unwrap());
        let total_burned = u64::from_le_bytes(parser.take(8).try_into().unwrap());
        let total_issued = u64::from_le_bytes(parser.take(8).try_into().unwrap());
        let transparent_supply = u64::from_le_bytes(parser.take(8).try_into().unwrap());
        let shielded_balance = u64::from_le_bytes(parser.take(8).try_into().unwrap());
        let note_root: [u8; 32] = parser.take(LENGTH_OF_NOTE_ROOT).try_into().unwrap();
        let private_state: [u8; 32] = parser.take(LENGTH_OF_PRIVATE_STATE).try_into().unwrap();
        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        if parser.remaining.len() < script_pub_key_len as usize {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        }

        let script_public_key =
            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
        let extra_data = parser.remaining;

        Ok(CoinbaseData {
            blue_score,
            subsidy,
            pool: PoolState { pool_balance, total_burned, total_issued, transparent_supply, shielded_balance },
            note_root,
            private_state,
            miner_data: MinerData { script_public_key, extra_data },
        })
    }

    pub fn calc_block_subsidy(&self, daa_score: u64) -> u64 {
        // Zethora: reward = floor(Remaining / D), indexed by DAA score (ZTH-SPEC-001 Section 5)
        self.zethora_subsidy.subsidy(daa_score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAINNET_PARAMS;
    use kaspa_consensus_core::{config::params::Params, tx::scriptvec};

    #[test]
    fn payload_serialization_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3];
        let data = CoinbaseData {
            blue_score: 56,
            subsidy: 44000000000,
            pool: PoolState { pool_balance: 123, total_burned: 456, total_issued: 789, transparent_supply: 10, shielded_balance: 11 },
            note_root: [3; 32],
            private_state: [5; 32],
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data as &[u8],
            },
        };

        let payload = cbm.serialize_coinbase_payload(&data).unwrap();
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data, deserialized_data);

        // (Kaspa's mainnet payload vector removed: Zethora's payload adds the pool state.)
    }

    #[test]
    fn modify_payload_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3, 23, 98];
        let data = CoinbaseData {
            blue_score: 56345,
            subsidy: 44000000000,
            pool: PoolState { pool_balance: 7, total_burned: 8, total_issued: 9, transparent_supply: 10, shielded_balance: 11 },
            note_root: [4; 32],
            private_state: [6; 32],
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data,
            },
        };

        let data2 = CoinbaseData {
            blue_score: data.blue_score,
            subsidy: data.subsidy,
            pool: data.pool,
            note_root: data.note_root,
            private_state: data.private_state,
            miner_data: MinerData {
                // Modify only miner data
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[33u8, 255, 33])),
                extra_data: &[2u8, 3, 23, 98, 34, 34] as &[u8],
            },
        };

        let mut payload = cbm.serialize_coinbase_payload(&data).unwrap();
        payload = cbm.modify_coinbase_payload(payload, &data2.miner_data).unwrap(); // Update the payload with the modified miner data
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data2, deserialized_data);
    }

    #[test]
    fn expected_coinbase_transaction_uses_toccata_version() {
        let params = MAINNET_PARAMS.clone();
        let cbm = create_manager(&params);
        let miner_data = MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![4, 5, 6]);
        let ghostdag_data = GhostdagData::default();
        let mergeset_rewards = Default::default();
        let mergeset_non_daa = Default::default();

        let tx = cbm
            .expected_coinbase_transaction(
                100,
                miner_data,
                &ghostdag_data,
                &mergeset_rewards,
                &mergeset_non_daa,
                PoolState::default(),
                0,
                [0; 32],
                [0; 32],
            )
            .unwrap();

        assert_eq!(tx.tx.version, constants::TX_VERSION_TOCCATA);
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(
            params.coinbase_payload_script_public_key_max_len,
            params.max_coinbase_payload_len,
            params.deflationary_phase_daa_score,
            params.pre_deflationary_phase_base_subsidy,
            params.bps_history(),
        )
    }
}
