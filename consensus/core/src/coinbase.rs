use crate::tx::{ScriptPublicKey, Transaction};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct MinerData<T: AsRef<[u8]> = Vec<u8>> {
    pub script_public_key: ScriptPublicKey,
    pub extra_data: T,
}

impl<T: AsRef<[u8]>> MinerData<T> {
    pub fn new(script_public_key: ScriptPublicKey, extra_data: T) -> Self {
        Self { script_public_key, extra_data }
    }
}

/// Zethora fee pool state, carried in every coinbase payload along the selected chain (ZTH-SPEC-008).
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PoolState {
    /// Zets currently held in the fee pool (controlled by no key).
    pub pool_balance: u64,
    /// Total zets ever burned (SPEC-001 §15.2).
    pub total_burned: u64,
}

#[derive(PartialEq, Eq, Debug)]
pub struct CoinbaseData<T: AsRef<[u8]> = Vec<u8>> {
    pub blue_score: u64,
    pub subsidy: u64,
    /// Zethora: pool state after this block
    pub pool: PoolState,
    pub miner_data: MinerData<T>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockRewardData {
    pub subsidy: u64,
    pub total_fees: u64,
    /// Zethora: the base-fee part of `total_fees`. The rest (tips) goes to the miner.
    pub base_fees: u64,
    pub script_public_key: ScriptPublicKey,
}

impl BlockRewardData {
    pub fn new(subsidy: u64, total_fees: u64, base_fees: u64, script_public_key: ScriptPublicKey) -> Self {
        Self { subsidy, total_fees, base_fees, script_public_key }
    }

    /// Tips: the part of fees paid directly to the block's miner.
    pub fn tips(&self) -> u64 {
        self.total_fees - self.base_fees
    }
}

/// Holds a coinbase transaction along with meta-data obtained during creation
pub struct CoinbaseTransactionTemplate {
    pub tx: Transaction,
    pub has_red_reward: bool, // Does the last output contain reward for red blocks
}
