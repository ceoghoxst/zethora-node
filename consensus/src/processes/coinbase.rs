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

/// Zethora extended payload layout:
///     blue score (8) | subsidy (8) | pool state (40) | coin list root (32) | private state (32) | spk version (2) |
///     spk length (1) | spk | extra data
const MIN_PAYLOAD_LENGTH: usize = LENGTH_OF_BLUE_SCORE
    + LENGTH_OF_SUBSIDY
    + LENGTH_OF_POOL_STATE
    + LENGTH_OF_NOTE_ROOT
    + LENGTH_OF_PRIVATE_STATE
    + LENGTH_OF_SCRIPT_PUB_KEY_VERSION
    + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

/// Standard Kaspa payload layout, as built by third-party mining software (e.g. the Kaspa stratum bridge in `bridge/`),
/// which knows nothing about the Zethora fields:
///     blue score (8) | subsidy (8) | spk version (2) | spk length (1) | spk | extra data
///
/// A standard payload can be ANY length (it is 19 bytes plus a script of up to 255 bytes plus any extra data), so its
/// length says nothing about which layout it is. The two layouts are told apart by trying the extended reading first
/// and falling back to this one only when that reading cannot be exact (see `deserialize_coinbase_payload`).
const MIN_STANDARD_PAYLOAD_LENGTH: usize = LENGTH_OF_BLUE_SCORE
    + LENGTH_OF_SUBSIDY
    + LENGTH_OF_SCRIPT_PUB_KEY_VERSION
    + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

/// Zethora: what a standard (non-Zethora) payload says about the pool. Such a payload carries no supply ledger, so it
/// counts as a block that creates and destroys nothing: every ledger field is zero.
const ZERO_POOL_STATE: PoolState =
    PoolState { pool_balance: 0, total_burned: 0, total_issued: 0, transparent_supply: 0, shielded_balance: 0 };

/// Zethora: the coin list root and private state fingerprint of a standard (non-Zethora) payload. Such a payload seals
/// neither, so it counts as sealing the empty tree and the empty fingerprint.
const ZERO_PRIVATE_STATE: [u8; 32] = [0u8; 32];

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60

/// Seam review P5-2: a checked addition; an overflow refuses the coinbase instead of panicking or wrapping.
fn add(a: u64, b: u64, what: &str) -> CoinbaseResult<u64> {
    a.checked_add(b).ok_or_else(|| CoinbaseError::ZethoraSupply(format!("{what} overflows u64")))
}

/// Seam review P5-2: a checked sum.
fn checked_sum(values: impl IntoIterator<Item = u64>, what: &str) -> CoinbaseResult<u64> {
    values.into_iter().try_fold(0u64, |a, b| add(a, b, what))
}

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

    /// Zethora: a strict read of the first `n` bytes of `remaining`, while setting `remaining` to the remaining part.
    /// Returns `None` instead of panicking when `remaining` is too short, so every layout reading is exact: a payload
    /// that cannot hold `n` more bytes is refused, never read past its end.
    fn try_take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (segment, remaining) = self.remaining.split_at_checked(n)?;
        self.remaining = remaining;
        Some(segment)
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
        // Seam review P5-2: every sum here is checked. Real values stay far below u64::MAX, but an unchecked sum would
        // panic in a debug build and wrap in a release build, so two nodes could disagree on the same block.
        let base_total = checked_sum(mergeset_rewards.values().map(|r| r.base_fees), "base fees")?;
        let pool = zethora_fees::pool_step(parent_pool, base_total).map_err(|e| CoinbaseError::ZethoraSupply(e.to_string()))?;

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
            issued = add(issued, subsidy, "issued")?;
            let value = add(subsidy, reward_data.tips(), "blue reward")?;
            if value > 0 {
                outputs.push(TransactionOutput::new(value, reward_data.script_public_key.clone()));
            }
        }

        // Zethora: a blue block outside the DAA window is paid nothing, so its tips are destroyed (counted as burned).
        // Such a block may have no reward data at all (e.g. genesis in the very first virtual state): nothing is lost then.
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| mergeset_non_daa.contains(h)) {
            unpaid = add(unpaid, mergeset_rewards.get(blue).map_or(0, |r| r.tips()), "unpaid tips")?;
        }

        // Collect all rewards from mergeset reds ∩ DAA window and create a
        // single output rewarding all to the current block (the "merging" block)
        let mut red_reward = 0u64;

        for red in ghostdag_data.mergeset_reds.iter() {
            let reward_data = mergeset_rewards.get(red).unwrap();
            if mergeset_non_daa.contains(red) {
                red_reward = add(red_reward, reward_data.tips(), "red reward")?;
            } else {
                let subsidy = paid_subsidy(reward_data.subsidy);
                red_reward = add(red_reward, add(subsidy, reward_data.tips(), "red reward")?, "red reward")?;
                issued = add(issued, subsidy, "issued")?;
            }
        }

        // Zethora: this block's payout from the fee pool goes to this block's miner (same output as red rewards)
        red_reward = add(red_reward, pool.payout, "red reward")?;

        if red_reward > 0 {
            outputs.push(TransactionOutput::new(red_reward, miner_data.script_public_key.clone()));
        }

        // Zethora: build this block's supply ledger from what it really does, and refuse it if it does not balance
        let coinbase_out = checked_sum(outputs.iter().map(|o| o.value), "coinbase outputs")?;
        // Zethora: value moved into / out of the private pool by the accepted transactions (the turnstile)
        let shielded_in = checked_sum(mergeset_rewards.values().map(|r| r.pool_in), "private pool inflow")?;
        let shielded_out = checked_sum(mergeset_rewards.values().map(|r| r.pool_out), "private pool outflow")?;
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

        // Seam review P5-4: refuse here, with a clear error, a payload that body validation would refuse anyway
        // (deserialize_coinbase_payload), so a template never wastes a miner's work.
        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

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

        // Seam review P5-4: same length rule as serialize_coinbase_payload (a template's miner data can be swapped)
        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        Ok(payload)
    }

    /// Zethora: reads BOTH coinbase payload layouts, so Zethora's own miners (`zethora-miner`, which submits the
    /// extended layout) and third-party Kaspa mining software (`bridge/`, which submits the standard layout) can mine
    /// the same chain.
    ///
    /// A payload can be ANY length in either layout, so no reading is chosen by length: a payload of at least
    /// [`MIN_PAYLOAD_LENGTH`] (the shortest possible extended payload) is tried as extended first. The extended reading
    /// is strict (every field bounds-checked, a script that does not fit is refused), so it accepts exactly the payloads
    /// it can read completely.
    ///
    /// Only one failure means "this is not an extended payload": `PayloadCantContainScriptPublicKey`, raised when the
    /// script length read from the extended positions runs past the end of the payload -- the structure is that of a
    /// standard payload. Every other extended error (an oversized script length, say) is a validation failure of a
    /// payload that *is* extended, so it is returned as is instead of being masked by a fallback reading.
    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        if payload.len() >= MIN_PAYLOAD_LENGTH {
            match self.deserialize_zethora_coinbase_payload(payload) {
                Ok(data) => return Ok(data),
                // The payload cannot hold the script the extended layout claims: it is not an extended payload
                Err(CoinbaseError::PayloadCantContainScriptPublicKey(..)) => {}
                // A genuine validation error of an extended payload: refuse it, do not fall back
                Err(e) => return Err(e),
            }
        }

        // Standard Kaspa layout: the block carries no supply ledger, so it seals an all-zero pool and no private state.
        // A payload too short or too long for a standard layout is refused here with the usual errors.
        self.deserialize_standard_coinbase_payload(payload)
    }

    /// Zethora extended layout (built by `serialize_coinbase_payload`, `zethora-miner`) -- see [`MIN_PAYLOAD_LENGTH`].
    ///
    /// Strict: a field, the script or the script length that the payload cannot hold refuses the reading at once with
    /// `Err` and never panics, so a payload of any other shape (a standard one, say) fails here instead of being read
    /// as garbage.
    fn deserialize_zethora_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        let mut parser = PayloadParser::new(payload);

        // A field that runs past the end of the payload means the payload is not an extended one
        let too_short = || CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH);
        let blue_score = u64::from_le_bytes(parser.try_take(LENGTH_OF_BLUE_SCORE).ok_or_else(too_short)?.try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.try_take(LENGTH_OF_SUBSIDY).ok_or_else(too_short)?.try_into().unwrap());
        let pool_balance = u64::from_le_bytes(parser.try_take(8).ok_or_else(too_short)?.try_into().unwrap());
        let total_burned = u64::from_le_bytes(parser.try_take(8).ok_or_else(too_short)?.try_into().unwrap());
        let total_issued = u64::from_le_bytes(parser.try_take(8).ok_or_else(too_short)?.try_into().unwrap());
        let transparent_supply = u64::from_le_bytes(parser.try_take(8).ok_or_else(too_short)?.try_into().unwrap());
        let shielded_balance = u64::from_le_bytes(parser.try_take(8).ok_or_else(too_short)?.try_into().unwrap());
        let note_root: [u8; 32] = parser.try_take(LENGTH_OF_NOTE_ROOT).ok_or_else(too_short)?.try_into().unwrap();
        let private_state: [u8; 32] = parser.try_take(LENGTH_OF_PRIVATE_STATE).ok_or_else(too_short)?.try_into().unwrap();
        let script_pub_key_version =
            u16::from_le_bytes(parser.try_take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).ok_or_else(too_short)?.try_into().unwrap());
        let script_pub_key_len =
            u8::from_le_bytes(parser.try_take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).ok_or_else(too_short)?.try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // The script length says how many bytes follow it: when the payload cannot hold that many, the payload is not an
        // extended one, and nothing is read past its end.
        let Some(script) = parser.try_take(script_pub_key_len as usize) else {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                script_pub_key_len as usize,
                payload.len() - parser.remaining.len(),
            ));
        };

        Ok(CoinbaseData {
            blue_score,
            subsidy,
            pool: PoolState { pool_balance, total_burned, total_issued, transparent_supply, shielded_balance },
            note_root,
            private_state,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(script)),
                extra_data: parser.remaining,
            },
        })
    }

    /// Standard Kaspa layout (built by third-party mining software such as the stratum bridge in `bridge/`) -- see
    /// [`MIN_STANDARD_PAYLOAD_LENGTH`]. The Zethora-only fields default to zero.
    ///
    /// Strict: every read is bounds-checked, so no payload of any length can panic here.
    fn deserialize_standard_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_STANDARD_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_STANDARD_PAYLOAD_LENGTH));
        }

        let mut parser = PayloadParser::new(payload);

        let too_short = || CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_STANDARD_PAYLOAD_LENGTH);
        let blue_score = u64::from_le_bytes(parser.try_take(LENGTH_OF_BLUE_SCORE).ok_or_else(too_short)?.try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.try_take(LENGTH_OF_SUBSIDY).ok_or_else(too_short)?.try_into().unwrap());
        let script_pub_key_version =
            u16::from_le_bytes(parser.try_take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).ok_or_else(too_short)?.try_into().unwrap());
        let script_pub_key_len =
            u8::from_le_bytes(parser.try_take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).ok_or_else(too_short)?.try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Never panic here: the byte after the fixed bytes is the script length, so a script that does not fit is
        // refused with the length it would need rather than read past the end of the payload.
        let Some(script) = parser.try_take(script_pub_key_len as usize) else {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_STANDARD_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        };

        Ok(CoinbaseData {
            blue_score,
            subsidy,
            pool: ZERO_POOL_STATE,
            note_root: ZERO_PRIVATE_STATE,
            private_state: ZERO_PRIVATE_STATE,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(script)),
                extra_data: parser.remaining,
            },
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

    /// The stratum bridge (and any other standard Kaspa mining software) knows nothing about the Zethora fields: it
    /// submits `blue score | subsidy | spk version | spk length | spk | extra data`. Such a payload must read back with
    /// every pool field at zero, instead of failing with PayloadCantContainScriptPublicKey.
    #[test]
    fn standard_kaspa_payload_parses_with_zero_pool() {
        let cbm = create_manager(&MAINNET_PARAMS);
        let script = [0x21u8, 0x02, 0xab, 0xcd, 0x88]; // a pay-to-pubkey script
        let extra = b"RK-Stratum";

        // Built by hand, exactly as the bridge's template's coinbase carries it (no Zethora fields at all)
        let mut payload = Vec::new();
        payload.extend_from_slice(&1234u64.to_le_bytes()); // blue score
        payload.extend_from_slice(&44_000_000_000u64.to_le_bytes()); // subsidy
        payload.extend_from_slice(&0u16.to_le_bytes()); // script public key version
        payload.push(script.len() as u8); // script public key length
        payload.extend_from_slice(&script); // script public key
        payload.extend_from_slice(extra); // extra data

        // 8 + 8 + 2 + 1 + 5 + 10 = 34 bytes: far below the 123-byte minimum of the extended layout
        assert_eq!(payload.len(), 34);
        assert!(payload.len() < MIN_PAYLOAD_LENGTH);

        let data = cbm.deserialize_coinbase_payload(&payload).expect("a standard Kaspa payload must be readable");
        assert_eq!(data.blue_score, 1234);
        assert_eq!(data.subsidy, 44_000_000_000);
        assert_eq!(data.pool, PoolState::default(), "a standard payload carries no supply ledger");
        assert_eq!(data.note_root, [0u8; 32], "a standard payload seals no coin list root");
        assert_eq!(data.private_state, [0u8; 32], "a standard payload seals no private state fingerprint");
        assert_eq!(data.miner_data.script_public_key.version(), 0);
        assert_eq!(data.miner_data.script_public_key.script(), &script);
        assert_eq!(data.miner_data.extra_data, extra);
    }

    /// Same shape, but with an empty script and no extra data: the shortest payload a standard miner can build.
    #[test]
    fn shortest_standard_payload_parses_with_zero_pool() {
        let cbm = create_manager(&MAINNET_PARAMS);
        let mut payload = Vec::new();
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.push(0);
        assert_eq!(payload.len(), MIN_STANDARD_PAYLOAD_LENGTH);

        let data = cbm.deserialize_coinbase_payload(&payload).expect("19 bytes are a complete standard payload");
        assert_eq!(data.blue_score, 7);
        assert_eq!(data.pool, PoolState::default());
        assert!(data.miner_data.script_public_key.script().is_empty());
        assert!(data.miner_data.extra_data.is_empty());
    }

    /// A standard payload that happens to be long enough for the extended layout (a script of 115 bytes or more) still
    /// reads as standard: the extended reading is tried first, finds a script too long, and falls back.
    #[test]
    fn long_script_standard_payload_falls_back_to_zero_pool() {
        let cbm = create_manager(&MAINNET_PARAMS);
        let script = vec![0x51u8; 120];
        let mut payload = Vec::new();
        payload.extend_from_slice(&900u64.to_le_bytes());
        payload.extend_from_slice(&500u64.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(script.len() as u8);
        payload.extend_from_slice(&script);
        payload.extend_from_slice(b"tag");
        assert!(payload.len() >= MIN_PAYLOAD_LENGTH);

        let data = cbm.deserialize_coinbase_payload(&payload).expect("a long standard payload must be readable");
        assert_eq!(data.blue_score, 900);
        assert_eq!(data.subsidy, 500);
        assert_eq!(data.pool, PoolState::default());
        assert_eq!(data.miner_data.script_public_key.version(), 1);
        assert_eq!(data.miner_data.script_public_key.script(), script.as_slice());
        assert_eq!(data.miner_data.extra_data, b"tag");
    }

    /// Trailing bytes past a standard payload stay extra data (the node appends its version string there), so the
    /// standard reading covers payloads well above the 123-byte extended minimum too.
    #[test]
    fn standard_payload_with_long_extra_data_parses_with_zero_pool() {
        let cbm = create_manager(&MAINNET_PARAMS);
        let script = [0x21u8, 0x02, 0xab];
        let extra = vec![0x7au8; 200];
        let mut payload = Vec::new();
        payload.extend_from_slice(&4321u64.to_le_bytes());
        payload.extend_from_slice(&99u64.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.push(script.len() as u8);
        payload.extend_from_slice(&script);
        payload.extend_from_slice(&extra);
        assert!(payload.len() > MIN_PAYLOAD_LENGTH && payload.len() <= MAINNET_PARAMS.max_coinbase_payload_len);

        let data = cbm.deserialize_coinbase_payload(&payload).expect("extra data may fill the payload");
        assert_eq!(data.blue_score, 4321);
        assert_eq!(data.subsidy, 99);
        assert_eq!(data.pool, PoolState::default());
        assert_eq!(data.note_root, [0u8; 32]);
        assert_eq!(data.private_state, [0u8; 32]);
        assert_eq!(data.miner_data.script_public_key.script(), &script);
        assert_eq!(data.miner_data.extra_data, extra.as_slice());
    }

    /// An extended payload whose script length declares an oversized script must be refused, never panic.
    #[test]
    fn unreadable_payload_is_refused_without_panicking() {
        let cbm = create_manager(&MAINNET_PARAMS);
        // The extended layout's script length byte: blue score (8) + subsidy (8) + pool state (40) +
        // coin list root (32) + private state (32) + spk version (2) = 122, then the spk length
        const EXTENDED_SCRIPT_LEN_AT: usize = 8 + 8 + 5 * 8 + 32 + 32 + 2;
        let mut payload = vec![0u8; MIN_PAYLOAD_LENGTH];
        payload[EXTENDED_SCRIPT_LEN_AT] = 200;

        assert!(matches!(
            cbm.deserialize_coinbase_payload(&payload),
            Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(200, 150))
        ));

        // Below both minimums: still refused, with the standard minimum quoted
        assert!(matches!(
            cbm.deserialize_coinbase_payload(&payload[..10]),
            Err(CoinbaseError::PayloadLenBelowMin(10, MIN_STANDARD_PAYLOAD_LENGTH))
        ));
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

    /// Seam review P5-2: an overflowing sum refuses the coinbase with a supply error (before the fix: a panic in
    /// debug builds, a silent wrap in release builds).
    #[test]
    fn an_overflowing_coinbase_sum_is_refused_not_wrapped() {
        let cbm = create_manager(&MAINNET_PARAMS);
        // Positive control: the largest tips that still fit are paid exactly
        let (outs, _) = cap_block(&cbm, ledger_below_cap(1_000), &[(0, u64::MAX - 1_000)], &[]).unwrap();
        assert_eq!(outs, vec![u64::MAX - 1_000]);
        // One zet more than u64 can hold (subsidy 1 + tips u64::MAX): refused, with the reason
        match cap_block(&cbm, ledger_below_cap(1_000), &[(1, u64::MAX)], &[]) {
            Err(CoinbaseError::ZethoraSupply(msg)) => assert_eq!(msg, "blue reward overflows u64"),
            other => panic!("expected a supply error, got {other:?}"),
        }
        // Same for a red block
        match cap_block(&cbm, ledger_below_cap(1_000), &[(0, 0)], &[(1, u64::MAX)]) {
            Err(CoinbaseError::ZethoraSupply(msg)) => assert_eq!(msg, "red reward overflows u64"),
            other => panic!("expected a supply error, got {other:?}"),
        }
    }

    /// Seam review P5-4 (test P5-T4): with the longest allowed script (150 bytes) only 27 bytes of extra data fit in the
    /// 300-byte payload. Building a payload that body validation would refuse is refused at once, with the reason.
    #[test]
    fn a_too_long_coinbase_payload_is_refused_when_building() {
        let params = MAINNET_PARAMS.clone();
        assert_eq!((params.max_coinbase_payload_len, params.coinbase_payload_script_public_key_max_len), (300, 150));
        let cbm = create_manager(&params);
        let script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51; 150]));
        let data = |extra: &[u8]| CoinbaseData {
            blue_score: 1,
            subsidy: 2,
            pool: PoolState::default(),
            note_root: [0; 32],
            private_state: [0; 32],
            miner_data: MinerData { script_public_key: script.clone(), extra_data: extra.to_vec() },
        };
        // Positive control: exactly 300 bytes is built, and body validation's reader accepts it
        let payload = cbm.serialize_coinbase_payload(&data(&[7; 27])).unwrap();
        assert_eq!(payload.len(), 300);
        assert_eq!(cbm.deserialize_coinbase_payload(&payload).unwrap().miner_data.extra_data, &[7u8; 27][..]);
        // One byte more: refused when building (the reader refuses it too, so a mined block would have been invalid)
        match cbm.serialize_coinbase_payload(&data(&[7; 28])) {
            Err(CoinbaseError::PayloadLenAboveMax(301, 300)) => {}
            other => panic!("expected PayloadLenAboveMax(301, 300), got {other:?}"),
        }
        // The review's case: 150-byte script + 40 bytes of extra data
        assert!(matches!(cbm.serialize_coinbase_payload(&data(&[7; 40])), Err(CoinbaseError::PayloadLenAboveMax(313, 300))));
        // Swapping the miner data of a good payload follows the same rule
        let swapped = MinerData { script_public_key: script.clone(), extra_data: vec![7u8; 28] };
        assert!(matches!(cbm.modify_coinbase_payload(payload.clone(), &swapped), Err(CoinbaseError::PayloadLenAboveMax(301, 300))));
        let fits = MinerData { script_public_key: script.clone(), extra_data: vec![9u8; 27] };
        assert_eq!(cbm.modify_coinbase_payload(payload, &fits).unwrap().len(), 300);
    }

    /// Seam review P5-6 (test P5-T6): every network's genesis has DAA score 0, so the first mined block (score 1) is
    /// paid reward(1) of the schedule, not a reward from far into it (Kaspa's mainnet genesis had score 1,312,860).
    #[test]
    fn every_genesis_starts_the_reward_schedule_at_zero() {
        use crate::params::{DEVNET_PARAMS, SIMNET_PARAMS, TESTNET_PARAMS};
        use crate::processes::zethora_subsidy::{D, EMISSION_START};
        let schedule = ZethoraSubsidy::new();
        for p in [&MAINNET_PARAMS, &TESTNET_PARAMS, &DEVNET_PARAMS, &SIMNET_PARAMS] {
            assert_eq!(p.genesis.daa_score, 0, "{} genesis DAA score", p.net);
            let cbm = create_manager(p);
            assert_eq!(cbm.calc_block_subsidy(p.genesis.daa_score), EMISSION_START / D, "{}", p.net);
            assert_eq!(cbm.calc_block_subsidy(p.genesis.daa_score + 1), schedule.subsidy(1), "{}", p.net);
            assert_eq!(schedule.subsidy(1), (EMISSION_START - EMISSION_START / D) / D);
        }
    }

    /// Seam review P2-1 (not a bug, proof test): the private pool flows of EVERY merged block are counted, whatever
    /// its colour or DAA status. A red block shields 700 zets, a non-DAA blue unshields 200, the paid blue moves
    /// nothing: the sealed private pool grows by exactly 500 and the ledger balances. Counting only paid blues would
    /// leave the 500 in the visible change and the block would be refused as unbalanced.
    #[test]
    fn pool_flows_of_red_and_non_daa_blocks_are_counted() {
        use kaspa_consensus_core::{BlockHashMap, BlockHashSet, Hash};
        let cbm = create_manager(&MAINNET_PARAMS);
        let miner = MinerData::new(ScriptPublicKey::new(0, scriptvec![0x51]), vec![]);
        let (blue, non_daa_blue, red) = (Hash::from_u64_word(1), Hash::from_u64_word(2), Hash::from_u64_word(3));
        let spk = ScriptPublicKey::new(0, scriptvec![0x52]);
        let build = |red_in: u64, non_daa_out: u64| {
            let mut rewards = BlockHashMap::default();
            rewards.insert(blue, BlockRewardData::new(100, 0, 0, spk.clone()));
            rewards.insert(non_daa_blue, BlockRewardData::new(100, 0, 0, spk.clone()).with_pool_flows(0, non_daa_out));
            rewards.insert(red, BlockRewardData::new(100, 0, 0, spk.clone()).with_pool_flows(red_in, 0));
            let non_daa: BlockHashSet = [non_daa_blue].into_iter().collect();
            let ghostdag = GhostdagData::new(
                7,
                Default::default(),
                blue,
                std::sync::Arc::new(vec![blue, non_daa_blue]),
                std::sync::Arc::new(vec![red]),
                Default::default(),
            );
            let parent = PoolState { total_issued: 1_000, transparent_supply: 700, shielded_balance: 300, ..Default::default() };
            // Visible coins: -700 shielded by the red block, +200 unshielded by the non-DAA blue
            let visible_change = -(red_in as i128) + non_daa_out as i128;
            cbm.expected_coinbase_transaction(
                100,
                miner.clone(),
                &ghostdag,
                &rewards,
                &non_daa,
                parent,
                visible_change,
                [0; 32],
                [0; 32],
            )
            .map(|t| cbm.deserialize_coinbase_payload(&t.tx.payload).unwrap().pool)
        };
        // Positive control: no private flows at all
        let plain = build(0, 0).unwrap();
        assert_eq!(plain.shielded_balance, 300);
        // The red block's shield and the non-DAA block's unshield both reach the sealed private pool
        let ledger = build(700, 200).unwrap();
        assert_eq!(ledger.shielded_balance, 300 + 700 - 200);
        assert_eq!(ledger.transparent_supply, plain.transparent_supply - 500);
        assert_eq!(zethora_supply::check_balanced(&ledger), Ok(()));
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(params.coinbase_payload_script_public_key_max_len, params.max_coinbase_payload_len)
    }
}
