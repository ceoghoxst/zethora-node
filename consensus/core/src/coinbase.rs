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

/// Zethora supply ledger, carried in every coinbase payload along the selected chain
/// (fee pool: ZTH-SPEC-008; supply check and turnstile: ZTH-SPEC-006 §7.1-7.2).
///
/// All values describe the moment after this block's coinbase is counted, and every block must satisfy:
///     transparent_supply + pool_balance + total_burned + shielded_balance == total_issued
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PoolState {
    /// Zets currently held in the fee pool (controlled by no key).
    pub pool_balance: u64,
    /// Total zets ever burned (SPEC-001 §15.2).
    pub total_burned: u64,
    /// Total zets ever created by block rewards (paid out so far).
    pub total_issued: u64,
    /// Zets held in ordinary (visible) coins.
    pub transparent_supply: u64,
    /// Zets inside the private pool: its public turnstile balance. Always 0 until private transactions exist.
    pub shielded_balance: u64,
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
    /// Zethora: zets this block's accepted transactions moved into the private pool (ZTH-SPEC-006 §7.1).
    pub pool_in: u64,
    /// Zethora: zets this block's accepted transactions moved out of the private pool.
    pub pool_out: u64,
}

impl BlockRewardData {
    pub fn new(subsidy: u64, total_fees: u64, base_fees: u64, script_public_key: ScriptPublicKey) -> Self {
        Self { subsidy, total_fees, base_fees, script_public_key, pool_in: 0, pool_out: 0 }
    }

    /// Zethora: records the private pool flows of this block's accepted transactions.
    pub fn with_pool_flows(mut self, pool_in: u64, pool_out: u64) -> Self {
        self.pool_in = pool_in;
        self.pool_out = pool_out;
        self
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
