#![allow(clippy::arithmetic_side_effects)]

// public for benchmarks
#[doc(hidden)]
pub mod matrix;
#[cfg(not(target_arch = "wasm32"))]
pub mod randomz;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;

use crate::matrix::Matrix;
use kaspa_consensus_core::{BlockLevel, hashing, header::Header};
use kaspa_hashes::PowHash;
use kaspa_math::Uint256;

/// State is an intermediate data structure with pre-computed values to speed up mining.
pub struct State {
    pub(crate) matrix: Matrix,
    pub(crate) target: Uint256,
    // PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE
    pub(crate) hasher: PowHash,
    pub(crate) pre_pow_hash: [u8; 32],
    pub(crate) timestamp: u64,
    /// Zethora: the RandomZ key epoch of the block (from its DAA score, see `randomz`)
    pub(crate) epoch: u64,
}

impl State {
    #[inline]
    pub fn new(header: &Header) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        // Zero out the time and nonce.
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        let state = Self::from_parts(pre_pow_hash, header.timestamp, target);
        #[cfg(not(target_arch = "wasm32"))]
        let state = Self { epoch: randomz::epoch_of(header.daa_score), ..state };
        state
    }

    /// Note (Zethora): the RandomZ key epoch is 0 here; use `State::new` to check a real header (its DAA score sets the
    /// epoch).
    pub fn from_parts(pre_pow_hash: kaspa_hashes::Hash, timestamp: u64, target: Uint256) -> Self {
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, timestamp);
        let matrix = Matrix::generate(pre_pow_hash);
        Self { matrix, target, hasher, pre_pow_hash: pre_pow_hash.as_bytes(), timestamp, epoch: 0 }
    }

    /// Zethora: the RandomZ key epoch this block's PoW uses.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The target this block's PoW must meet.
    pub fn target(&self) -> Uint256 {
        self.target
    }

    /// Zethora: the 48-byte RandomX input for a nonce (see `randomz`).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn pow_input(&self, nonce: u64) -> [u8; 48] {
        randomz::pow_input(&self.pre_pow_hash, self.timestamp, nonce)
    }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Zethora: RandomX proof of work on native builds (ZTH-SPEC-000 §4.4)
        #[cfg(not(target_arch = "wasm32"))]
        {
            randomz::pow_value_light(self.epoch, &self.pow_input(nonce))
        }
        // Original kHeavyHash, kept only for the wasm SDK build
        #[cfg(target_arch = "wasm32")]
        {
            // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
            let hash = self.hasher.clone().finalize_with_nonce(nonce);
            let hash = self.matrix.heavy_hash(hash);
            Uint256::from_le_bytes(hash.as_bytes())
        }
    }

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        // The pow hash must be less or equal than the claimed target.
        (pow <= self.target, pow)
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel) -> BlockLevel {
    let (block_level, _) = calc_block_level_check_pow(header, max_block_level);
    block_level
}

pub fn calc_block_level_check_pow(header: &Header, max_block_level: BlockLevel) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }

    let state = State::new(header);
    let (passed, pow) = state.check_pow(header.nonce);
    let block_level = calc_level_from_pow(pow, max_block_level);
    (block_level, passed)
}

/// Zethora: computes (and remembers) the PoW of many headers at once, grouped by RandomZ key epoch, so that checking
/// them one by one afterwards (e.g. the headers of a pruning proof, which span every epoch since genesis) builds each
/// epoch's light-mode setup only once.
#[cfg(not(target_arch = "wasm32"))]
pub fn precompute_pow<'a>(headers: impl IntoIterator<Item = &'a Header>) {
    let items: Vec<_> = headers
        .into_iter()
        .filter(|header| !header.parents_by_level.is_empty()) // genesis needs no PoW
        .map(|header| {
            let state = State::new(header);
            (state.epoch, state.pow_input(header.nonce))
        })
        .collect();
    randomz::precompute_light(&items);
}

pub fn calc_level_from_pow(pow: Uint256, max_block_level: BlockLevel) -> BlockLevel {
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
