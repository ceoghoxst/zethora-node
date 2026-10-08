//! Zethora proof of work: RandomZ, Monero's CPU-friendly RandomX with Zethora's own parameters (ZTH-SPEC-000 §4.4,
//! ZTH-SPEC-005 §5.1). The library is the vendored crate in `randomz/` (see randomz/ZETHORA.md): a unique Argon2 salt
//! and swapped frequencies of equivalent instructions, the changes RandomX documents as safe. Memory and time costs are
//! exactly RandomX's, but stock RandomX miners (Monero's hashpower, rental services) cannot mine it without new
//! software.
//!
//! PoW input (48 bytes): PRE_POW_HASH (32) || TIMESTAMP (8, LE) || NONCE (8, LE).
//! PoW value: the 32-byte RandomX hash read as a little-endian 256-bit number.
//! A block is valid when that value is <= the target from the header bits.
//!
//! Two modes:
//! - Light (256 MiB cache): used by nodes to verify one hash per block.
//! - Fast (~2 GiB dataset): used by miners for many hashes per second.
//!
//! TODO(before testnet, step 6b): rotate the key periodically (RandomX recommends it); designed separately because a
//! key must be computable when checking any header, including the far-apart headers of a pruning proof.

use kaspa_math::Uint256;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
use std::{cell::RefCell, sync::OnceLock};

/// Fixed RandomX key for the Zethora devnet.
pub const RANDOMZ_KEY: &[u8] = b"Zethora devnet RandomZ key v0";
pub const POW_INPUT_LEN: usize = 48;

// SAFETY: a RandomX cache and dataset are read-only after initialization, and the
// RandomX API allows many VMs on different threads to use them at once. Only the
// VMs (which hold per-thread scratchpads) are kept thread-local.
struct SharedCache(RandomXCache);
unsafe impl Send for SharedCache {}
unsafe impl Sync for SharedCache {}

#[derive(Clone)]
pub struct SharedDataset(RandomXDataset);
unsafe impl Send for SharedDataset {}
unsafe impl Sync for SharedDataset {}

static CACHE: OnceLock<SharedCache> = OnceLock::new();

fn flags() -> RandomXFlag {
    RandomXFlag::get_recommended_flags()
}

fn cache() -> RandomXCache {
    CACHE.get_or_init(|| SharedCache(RandomXCache::new(flags(), RANDOMZ_KEY).expect("RandomX cache init failed"))).0.clone()
}

thread_local! {
    static LIGHT_VM: RefCell<Option<RandomXVM>> = const { RefCell::new(None) };
}

/// Builds the 48-byte PoW input.
#[inline]
pub fn pow_input(pre_pow_hash: &[u8; 32], timestamp: u64, nonce: u64) -> [u8; POW_INPUT_LEN] {
    let mut input = [0u8; POW_INPUT_LEN];
    input[..32].copy_from_slice(pre_pow_hash);
    input[32..40].copy_from_slice(&timestamp.to_le_bytes());
    input[40..].copy_from_slice(&nonce.to_le_bytes());
    input
}

#[inline]
fn to_value(hash: Vec<u8>) -> Uint256 {
    let bytes: [u8; 32] = hash.try_into().expect("RandomX hash is 32 bytes");
    Uint256::from_le_bytes(bytes)
}

/// Verifies with light mode. Used by every node for every block.
pub fn pow_value_light(input: &[u8]) -> Uint256 {
    LIGHT_VM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(RandomXVM::new(flags(), Some(cache()), None).expect("RandomX VM init failed"));
        }
        to_value(slot.as_ref().unwrap().calculate_hash(input).expect("RandomX hash failed"))
    })
}

/// Builds the full ~2 GiB dataset for fast mining. Takes about a minute.
pub fn new_mining_dataset() -> SharedDataset {
    SharedDataset(RandomXDataset::new(flags() | RandomXFlag::FLAG_FULL_MEM, cache(), 0).expect("RandomX dataset init failed"))
}

/// A fast-mode hasher for one mining thread. Create it on the thread that uses it.
pub struct FastHasher(RandomXVM);

impl FastHasher {
    pub fn new(dataset: &SharedDataset) -> Self {
        let vm =
            RandomXVM::new(flags() | RandomXFlag::FLAG_FULL_MEM, None, Some(dataset.0.clone())).expect("RandomX fast VM init failed");
        Self(vm)
    }

    #[inline]
    pub fn pow_value(&self, input: &[u8]) -> Uint256 {
        to_value(self.0.calculate_hash(input).expect("RandomX hash failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RandomZ test vectors, using RandomX's own test key and inputs (tevador/RandomX tests.cpp). Computed with the
    /// RandomZ configuration in randomz/RandomX, and checked to be identical in the interpreter, the JIT compiler and
    /// fast (full dataset) mode.
    #[test]
    fn randomz_matches_its_test_vectors() {
        let cache = RandomXCache::new(flags(), b"test key 000").unwrap();
        let vm = RandomXVM::new(flags(), Some(cache), None).unwrap();
        for (input, expected) in [
            (&b"This is a test"[..], "6d835dab67ebaeae05c4d9c6c945574660345800540d0c89cd2c188d4d8486b0"),
            (&b"Lorem ipsum dolor sit amet"[..], "2f8f0f2098571d21c6afdb699178bb262a1c490bc037f5c96fed83cce491da00"),
            (
                &b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"[..],
                "b5f2ccade1bab4f729977bdfc4e09c18e6342e8ab03ee60f17fb69a1fd431904",
            ),
        ] {
            assert_eq!(hex(&vm.calculate_hash(input).unwrap()), expected, "input {:?}", String::from_utf8_lossy(input));
        }
    }

    /// The build really uses RandomZ: stock RandomX gives the official vector for the same key and input, so a stale
    /// stock RandomX library left over from an earlier build would be caught here.
    #[test]
    fn randomz_is_not_stock_randomx() {
        let cache = RandomXCache::new(flags(), b"test key 000").unwrap();
        let vm = RandomXVM::new(flags(), Some(cache), None).unwrap();
        assert_ne!(
            hex(&vm.calculate_hash(b"This is a test").unwrap()),
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
            "this is stock RandomX's hash: the RandomZ parameters are not in this build"
        );
    }

    /// Zethora's own PoW input and devnet key give the expected value (the bytes are read little-endian).
    #[test]
    fn devnet_pow_matches_its_test_vector() {
        let value = pow_value_light(&pow_input(&[7u8; 32], 1_000, 1));
        let expected: [u8; 32] = [
            0x68, 0x29, 0xca, 0xd1, 0x26, 0x8c, 0x4d, 0xe8, 0x67, 0xaf, 0x7f, 0xd3, 0xea, 0x03, 0xe4, 0x8a, 0x33, 0xb7, 0xbd, 0xd3,
            0x20, 0xb8, 0x07, 0x06, 0x02, 0x00, 0xa1, 0xf6, 0x99, 0x95, 0xa0, 0x6c,
        ];
        assert_eq!(value, Uint256::from_le_bytes(expected));
    }

    #[test]
    fn light_pow_is_deterministic_and_nonce_sensitive() {
        let a = pow_value_light(&pow_input(&[7u8; 32], 1_000, 1));
        let b = pow_value_light(&pow_input(&[7u8; 32], 1_000, 1));
        let c = pow_value_light(&pow_input(&[7u8; 32], 1_000, 2));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn light_pow_works_from_many_threads() {
        let expected = pow_value_light(&pow_input(&[9u8; 32], 5, 5));
        let handles: Vec<_> = (0..4).map(|_| std::thread::spawn(|| pow_value_light(&pow_input(&[9u8; 32], 5, 5)))).collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    }
}
