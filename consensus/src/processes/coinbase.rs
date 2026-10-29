use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet,
    coinbase::*,
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
        zethora_subsidy::{CAP_UNITS, ZethoraSubsidy},
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
    pub fn new(coinbase_payload_script_public_key_max_len: u8, max_coinbase_payload_len: usize) -> Self {
        Self { coinbase_payload_script_public_key_max_len, max_coinbase_payload_len, zethora_subsidy: Arc::new(ZethoraSubsidy::new()) }
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

        // Zethora hard cap clamp (ZTH-SPEC-001 §5, CEO decision 2026-10-28): each merged block is paid
        // min(its subsidy, what is left under the cap), in mergeset order (blues, then reds). Total issued then reaches
        // CAP_UNITS exactly and never passes it, so the CapExceeded backstop in ledger_step can't fire for an honest
        // block and the chain never stalls at the cap. Tips and fee pool payouts are not new zets and are never clamped.
        let mut cap_room = CAP_UNITS.saturating_sub(parent_pool.total_issued);
        let mut paid_subsidy = |claimed: u64| -> u64 {
            let paid = claimed.min(cap_room);
            cap_room -= paid;
            paid
        };

        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(blue).unwrap();
            let subsidy = paid_subsidy(reward_data.subsidy);
            issued += subsidy;
            if subsidy + reward_data.tips() > 0 {
                outputs.push(TransactionOutput::new(subsidy + reward_data.tips(), reward_data.script_public_key.clone()));
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
                let subsidy = paid_subsidy(reward_data.subsidy);
                red_reward += subsidy + reward_data.tips();
                issued += subsidy;
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

    /// One chain block merging `merged` (blue, (subsidy claimed, tips)) and `reds`, built by the same function the
    /// template builder and the coinbase check use. Returns the coinbase outputs' values and the new ledger.
    fn cap_block(
        cbm: &CoinbaseManager,
        parent: PoolState,
        blues: &[(u64, u64)],
        reds: &[(u64, u64)],
    ) -> Result<(Vec<u64>, PoolState), CoinbaseError> {
        use kaspa_consensus_core::{BlockHashMap, Hash};
        let miner = MinerData::new(ScriptPublicKey::new(0, scriptvec![0x51]), vec![]);
        let mut rewards = BlockHashMap::default();
        let mut hashes = |list: &[(u64, u64)], offset: u64| -> Vec<Hash> {
            list.iter()
                .enumerate()
                .map(|(i, &(subsidy, tips))| {
                    let h = Hash::from_u64_word(offset + i as u64);
                    rewards.insert(h, BlockRewardData::new(subsidy, tips, 0, ScriptPublicKey::new(0, scriptvec![i as u8])));
                    h
                })
                .collect()
        };
        let blue_hashes = hashes(blues, 1);
        let red_hashes = hashes(reds, 1_000);
        let ghostdag = GhostdagData::new(
            7,
            Default::default(),
            blue_hashes[0],
            std::sync::Arc::new(blue_hashes),
            std::sync::Arc::new(red_hashes),
            Default::default(),
        );
        // No transactions accepted: the visible supply changes only by what the coinbase pays (fees are tips only and
        // come out of the merged blocks' own transactions, so count them as already spent: visible change = -tips)
        let tips: u64 = blues.iter().chain(reds).map(|&(_, t)| t).sum();
        let template = cbm.expected_coinbase_transaction(
            100,
            miner,
            &ghostdag,
            &rewards,
            &Default::default(),
            parent,
            -(tips as i128),
            [0; 32],
            [0; 32],
        )?;
        let ledger = cbm.deserialize_coinbase_payload(&template.tx.payload).unwrap().pool;
        Ok((template.tx.outputs.iter().map(|o| o.value).collect(), ledger))
    }

    /// A balanced ledger with `left` zets still to be issued under the cap.
    fn ledger_below_cap(left: u64) -> PoolState {
        PoolState { total_issued: CAP_UNITS - left, transparent_supply: CAP_UNITS - left, ..Default::default() }
    }

    #[test]
    fn subsidy_is_clamped_to_reach_the_cap_exactly() {
        let cbm = create_manager(&MAINNET_PARAMS);

        // Positive control: far below the cap nothing is clamped; each merged block gets its full subsidy + tips
        let (outs, ledger) = cap_block(&cbm, ledger_below_cap(1_000_000), &[(300, 5), (200, 0)], &[]).unwrap();
        assert_eq!(outs, vec![305, 200]);
        assert_eq!(ledger.total_issued, CAP_UNITS - 1_000_000 + 500);

        // 250 zets left: the first blue (in mergeset order) gets 200 of its 300 and keeps its tips, the second blue gets
        // 50 of 200, the red gets 0 of 100 but keeps its tips (paid to the merging miner). Issued lands exactly on the cap.
        let (outs, at_cap) = cap_block(&cbm, ledger_below_cap(250), &[(200, 7), (200, 0)], &[(100, 3)]).unwrap();
        assert_eq!(outs, vec![207, 50, 3]);
        assert_eq!(at_cap.total_issued, CAP_UNITS);
        assert_eq!(zethora_supply::check_balanced(&at_cap), Ok(()));

        // The next block at the cap pays 0 subsidy (tips still paid), is valid, and issued stays exactly at the cap
        let (outs, next) = cap_block(&cbm, at_cap, &[(2_745_536_136, 11)], &[]).unwrap();
        assert_eq!(outs, vec![11]);
        assert_eq!(next.total_issued, CAP_UNITS);
        // A block whose merged blocks have no tips pays nothing at all (no outputs) and is still valid
        let (outs, next) = cap_block(&cbm, next, &[(2_745_536_136, 0), (2_745_536_136, 0)], &[(9, 0)]).unwrap();
        assert_eq!(outs, Vec::<u64>::new());
        assert_eq!(next.total_issued, CAP_UNITS);

        // The chain continues past the cap: 100 more blocks, issued never moves
        let mut ledger = next;
        for i in 0..100u64 {
            let (outs, l) = cap_block(&cbm, ledger, &[(1_000 + i, i)], &[]).unwrap();
            assert_eq!(outs, if i == 0 { vec![] } else { vec![i] });
            assert_eq!(l.total_issued, CAP_UNITS);
            ledger = l;
        }
    }

    #[test]
    fn a_coinbase_claiming_more_than_the_clamp_is_refused() {
        let cbm = create_manager(&MAINNET_PARAMS);
        // 50 zets left; the merged block claims 300
        let parent = ledger_below_cap(50);
        let (outs, ledger) = cap_block(&cbm, parent, &[(300, 0)], &[]).unwrap();
        assert_eq!(outs, vec![50]);
        assert_eq!(ledger.total_issued, CAP_UNITS);

        // A miner's coinbase paying the unclamped 300 is not the expected coinbase (verify_coinbase_transaction
        // compares hashes and returns BadCoinbaseTransaction), and its ledger is refused by the CapExceeded backstop
        let unclamped = BlockFlows { issued: 300, coinbase_out: 300, ..Default::default() };
        assert_eq!(
            zethora_supply::ledger_step(parent, parent, unclamped),
            Err(zethora_supply::SupplyError::CapExceeded { issued: CAP_UNITS + 250 })
        );
        // ... one zet over the clamp is refused too, exactly the clamp is accepted
        let one_over = BlockFlows { issued: 51, coinbase_out: 51, ..Default::default() };
        assert_eq!(
            zethora_supply::ledger_step(parent, parent, one_over),
            Err(zethora_supply::SupplyError::CapExceeded { issued: CAP_UNITS + 1 })
        );
        let exact = BlockFlows { issued: 50, coinbase_out: 50, ..Default::default() };
        assert_eq!(zethora_supply::ledger_step(parent, parent, exact).unwrap().total_issued, CAP_UNITS);
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(params.coinbase_payload_script_public_key_max_len, params.max_coinbase_payload_len)
    }
}
