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
//! Key rotation (step 6b): RandomX needs its key to change regularly and not be chosen by miners ("if blockchain data
//! cannot be used, use a predefined sequence of keys", RandomX README). The key is fixed per epoch of `EPOCH_LENGTH`
//! DAA scores (2^20, about 12 days at 1 block per second): `key_for_epoch(daa_score >> EPOCH_SHIFT)`. A block's DAA
//! score is checked exactly by consensus, so miners cannot pick their key, and the key comes from the header alone,
//! so any header can be checked on its own, including the far-apart headers of a pruning proof. Each new key costs a
//! node one 256 MiB light-mode setup (~1-2 s) and a miner one dataset build (~30 s), so epochs are long: a node
//! joining after N years builds about 30 x N setups once (see `precompute_light`).

use kaspa_math::Uint256;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock},
};

pub const POW_INPUT_LEN: usize = 48;
/// One key per 2^20 DAA scores (about 12 days at 1 block per second).
pub const EPOCH_SHIFT: u32 = 20;
pub const EPOCH_LENGTH: u64 = 1 << EPOCH_SHIFT;
/// How many light-mode setups (256 MiB each) a node keeps ready. Live blocks need only one or two (the pruning depth,
/// about 30 hours, is far shorter than an epoch); 4 covers every epoch the header checks accept at any time (one below
/// the pruning point's to one above the tip's), so bogus headers can't make a node rebuild setups over and over.
const KEPT_LIGHT_CACHES: usize = 4;

/// The key epoch of a block with this DAA score.
#[inline]
pub fn epoch_of(daa_score: u64) -> u64 {
    daa_score >> EPOCH_SHIFT
}

/// The RandomZ key of an epoch: a fixed, public sequence (the same on every network; the PoW input itself commits to
/// the block, and so to its network).
pub fn key_for_epoch(epoch: u64) -> [u8; 22] {
    let mut key = [0u8; 22];
    key[..14].copy_from_slice(b"ZethoraRandomZ");
    key[14..].copy_from_slice(&epoch.to_le_bytes());
    key
}

/// What a node knows about its network's clock, to bound the key epochs a header can honestly have.
#[derive(Clone, Copy, Debug)]
pub struct EpochClock {
    pub genesis_daa_score: u64,
    pub genesis_timestamp_ms: u64,
    pub target_time_per_block_ms: u64,
}

impl EpochClock {
    /// The highest key epoch a header can honestly have at time `now_ms`. Difficulty adjustment keeps DAA scores
    /// growing at the target block rate, so this allows twice the blocks the time since genesis allows, plus 2 epochs.
    /// Used on pruning proofs and past pruning points, whose headers reach back to genesis: without it a bogus proof
    /// could claim a different epoch for every header and make a joining node prepare thousands of keys.
    pub fn max_plausible_epoch(&self, now_ms: u64) -> u64 {
        let blocks = now_ms.saturating_sub(self.genesis_timestamp_ms) / self.target_time_per_block_ms.max(1);
        epoch_of(self.genesis_daa_score.saturating_add(blocks.saturating_mul(2))).saturating_add(2)
    }
}

// SAFETY: a RandomX cache and dataset are read-only after initialization, and the
// RandomX API allows many VMs on different threads to use them at once. Only the
// VMs (which hold per-thread scratchpads) are kept thread-local.
#[derive(Clone)]
struct SharedCache(RandomXCache);
unsafe impl Send for SharedCache {}
unsafe impl Sync for SharedCache {}

#[derive(Clone)]
pub struct SharedDataset(RandomXDataset);
unsafe impl Send for SharedDataset {}
unsafe impl Sync for SharedDataset {}

fn flags() -> RandomXFlag {
    RandomXFlag::get_recommended_flags()
}

fn new_cache(epoch: u64) -> SharedCache {
    SharedCache(RandomXCache::new(flags(), &key_for_epoch(epoch)).expect("RandomX cache init failed"))
}

/// The kept light-mode setups, by epoch, with when each was last used. Each slot is filled once (by whichever thread
/// asks first; others asking for the same epoch wait for it instead of building their own).
struct LightCaches {
    slots: BTreeMap<u64, (Arc<OnceLock<SharedCache>>, u64)>,
    clock: u64,
}

static LIGHT_CACHES: Mutex<LightCaches> = Mutex::new(LightCaches { slots: BTreeMap::new(), clock: 0 });

fn light_cache(epoch: u64) -> RandomXCache {
    let slot = {
        let mut caches = LIGHT_CACHES.lock().unwrap();
        caches.clock += 1;
        let now = caches.clock;
        if !caches.slots.contains_key(&epoch) && caches.slots.len() >= KEPT_LIGHT_CACHES {
            // Forget the least recently used setup (threads still using it keep their own handle until done)
            let oldest = caches.slots.iter().min_by_key(|(_, (_, used))| *used).map(|(e, _)| *e).expect("not empty");
            caches.slots.remove(&oldest);
        }
        let entry = caches.slots.entry(epoch).or_insert_with(|| (Arc::new(OnceLock::new()), now));
        entry.1 = now;
        entry.0.clone()
    };
    slot.get_or_init(|| new_cache(epoch)).0.clone()
}

/// The kept setup of `epoch` if it is ready, without counting this as a use.
fn kept_light_cache(epoch: u64) -> Option<RandomXCache> {
    let caches = LIGHT_CACHES.lock().unwrap();
    caches.slots.get(&epoch).and_then(|(slot, _)| slot.get()).map(|cache| cache.0.clone())
}

thread_local! {
    /// This thread's light-mode VM and the epoch it was made for.
    static LIGHT_VM: RefCell<Option<(u64, RandomXVM)>> = const { RefCell::new(None) };
}

/// Recently computed light-mode values by (epoch, input), so a header checked twice (a pruning proof is checked, then
/// applied) costs one hash, and `precompute_light` can hand its results to later one-by-one lookups. Exact: the key is
/// everything the value depends on. Cleared when full.
const MEMO_CAPACITY: usize = 200_000;
type MemoKey = (u64, [u8; POW_INPUT_LEN]);

fn memo() -> &'static Mutex<HashMap<MemoKey, Uint256>> {
    static MEMO: OnceLock<Mutex<HashMap<MemoKey, Uint256>>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

fn memo_get(epoch: u64, input: &[u8]) -> Option<Uint256> {
    let key: [u8; POW_INPUT_LEN] = input.try_into().ok()?;
    memo().lock().unwrap().get(&(epoch, key)).copied()
}

/// Remembers a batch of values. When the batch doesn't fit, older entries are dropped first, so a batch (e.g. a whole
/// pruning proof from `precompute_light`) stays complete for the one-by-one checks that follow it.
fn memo_put(entries: Vec<(u64, [u8; POW_INPUT_LEN], Uint256)>) {
    let mut memo = memo().lock().unwrap();
    if memo.len() + entries.len() > MEMO_CAPACITY {
        memo.clear();
    }
    for (epoch, input, value) in entries.into_iter().take(MEMO_CAPACITY) {
        memo.insert((epoch, input), value);
    }
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

/// Verifies with light mode, using the key of `epoch`. Used by every node for every block.
pub fn pow_value_light(epoch: u64, input: &[u8]) -> Uint256 {
    if let Some(value) = memo_get(epoch, input) {
        return value;
    }
    let value = light_hash(epoch, input);
    if let Ok(input) = input.try_into() {
        memo_put(vec![(epoch, input, value)]);
    }
    value
}

/// One light-mode hash with this thread's VM (made for `epoch` when needed), without the memo.
fn light_hash(epoch: u64, input: &[u8]) -> Uint256 {
    LIGHT_VM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.as_ref().is_none_or(|(e, _)| *e != epoch) {
            // Drop the old VM first, so its setup can be freed before a new one is made
            *slot = None;
            let vm = RandomXVM::new(flags(), Some(light_cache(epoch)), None).expect("RandomX VM init failed");
            *slot = Some((epoch, vm));
        }
        to_value(slot.as_ref().unwrap().1.calculate_hash(input).expect("RandomX hash failed"))
    })
}

/// Light-mode PoW values for many `(epoch, input)` pairs at once, e.g. the headers of a pruning proof, which can span
/// every epoch since genesis. Builds each epoch's setup only once (a few epochs at a time, in parallel) without
/// pushing the live epochs out of the kept setups. Results are in the same order as `items`, and are remembered, so
/// `pow_value_light` on the same input right after costs nothing.
pub fn precompute_light(items: &[(u64, [u8; POW_INPUT_LEN])]) -> Vec<Uint256> {
    let mut results: Vec<Option<Uint256>> = items.iter().map(|(epoch, input)| memo_get(*epoch, input)).collect();
    // Group the items not computed yet by epoch, each distinct input once (a proof lists a header on many levels)
    let mut first_seen: HashMap<(u64, [u8; POW_INPUT_LEN]), usize> = HashMap::new();
    let mut groups: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, item) in items.iter().enumerate() {
        if results[i].is_none() && first_seen.insert(*item, i).is_none() {
            groups.entry(item.0).or_default().push(i);
        }
    }
    if groups.is_empty() {
        return results.into_iter().map(|v| v.expect("all remembered")).collect();
    }
    let groups: Vec<(u64, Vec<usize>)> = groups.into_iter().collect();
    // At most 4 setups (4 x 256 MiB) at a time
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, 4);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let computed = Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let g = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((epoch, indexes)) = groups.get(g) else { break };
                    // Reuse a kept setup when there is one, else build a temporary one for this group only
                    let cache = kept_light_cache(*epoch).unwrap_or_else(|| new_cache(*epoch).0);
                    let vm = RandomXVM::new(flags(), Some(cache), None).expect("RandomX VM init failed");
                    let values: Vec<(usize, Uint256)> =
                        indexes.iter().map(|&i| (i, to_value(vm.calculate_hash(&items[i].1).expect("RandomX hash failed")))).collect();
                    computed.lock().unwrap().extend(values);
                }
            });
        }
    });
    let computed = computed.into_inner().unwrap();
    let values: HashMap<(u64, [u8; POW_INPUT_LEN]), Uint256> = computed.iter().map(|&(i, value)| (items[i], value)).collect();
    memo_put(computed.iter().map(|&(i, value)| (items[i].0, items[i].1, value)).collect());
    for (i, item) in items.iter().enumerate() {
        if results[i].is_none() {
            results[i] = values.get(item).copied();
        }
    }
    results.into_iter().map(|v| v.expect("every item computed")).collect()
}

/// Builds the full ~2 GiB dataset for fast mining with the key of `epoch`. Takes about half a minute.
pub fn new_mining_dataset(epoch: u64) -> SharedDataset {
    SharedDataset(
        RandomXDataset::new(flags() | RandomXFlag::FLAG_FULL_MEM, new_cache(epoch).0, 0).expect("RandomX dataset init failed"),
    )
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

    #[test]
    fn plausible_epochs_follow_the_clock() {
        let clock = EpochClock { genesis_daa_score: 0, genesis_timestamp_ms: 1_000_000, target_time_per_block_ms: 1000 };
        // Before or at genesis: only the first epochs
        assert_eq!(clock.max_plausible_epoch(0), 2);
        assert_eq!(clock.max_plausible_epoch(1_000_000), 2);
        // One epoch of time at 1 block per second allows 2 epochs of DAA scores, plus 2
        assert_eq!(clock.max_plausible_epoch(1_000_000 + EPOCH_LENGTH * 1000), 4);
        // Ten years at 1 block per second: about 30 epochs a year, doubled
        let ten_years_ms = 10 * 365 * 24 * 3600 * 1000;
        assert_eq!(clock.max_plausible_epoch(1_000_000 + ten_years_ms), (2 * ten_years_ms / 1000) / EPOCH_LENGTH + 2);
        // A genesis DAA score carried over from Kaspa counts too
        let kaspa = EpochClock { genesis_daa_score: 1_312_860, ..clock };
        assert_eq!(kaspa.max_plausible_epoch(0), 3);
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

    /// Zethora's own PoW input with the epoch 0 and epoch 1 keys gives the expected values (read little-endian).
    #[test]
    fn epoch_pow_matches_its_test_vectors() {
        let input = pow_input(&[7u8; 32], 1_000, 1);
        let epoch0: [u8; 32] = [
            0xe1, 0xb6, 0x06, 0x24, 0x1b, 0xad, 0xec, 0x13, 0x53, 0x52, 0xde, 0x94, 0xf1, 0x94, 0x1a, 0x17, 0x06, 0xa5, 0x98, 0xda,
            0xe4, 0x48, 0xa7, 0x94, 0x03, 0x98, 0xf7, 0x24, 0xeb, 0x06, 0x6f, 0xc6,
        ];
        let epoch1: [u8; 32] = [
            0x60, 0xfa, 0xe6, 0xcc, 0x92, 0x76, 0xbe, 0x53, 0x11, 0x64, 0x47, 0xc0, 0xd8, 0xf5, 0x20, 0xa6, 0x97, 0x8e, 0x26, 0xc8,
            0xe0, 0xb8, 0x34, 0x00, 0x91, 0x55, 0x70, 0x7b, 0x4a, 0x4e, 0xa1, 0x61,
        ];
        // Hashed by this thread's VM (not the memo), switching keys and back
        assert_eq!(light_hash(0, &input), Uint256::from_le_bytes(epoch0));
        assert_eq!(light_hash(1, &input), Uint256::from_le_bytes(epoch1));
        assert_eq!(light_hash(0, &input), Uint256::from_le_bytes(epoch0));
        // And through the public, remembering entry point
        assert_eq!(pow_value_light(1, &input), Uint256::from_le_bytes(epoch1));
        assert_eq!(pow_value_light(1, &input), Uint256::from_le_bytes(epoch1));
    }

    #[test]
    fn epochs_follow_the_daa_score() {
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(EPOCH_LENGTH - 1), 0);
        assert_eq!(epoch_of(EPOCH_LENGTH), 1);
        assert_eq!(EPOCH_LENGTH, 1_048_576); // about 12 days at 1 block per second
        assert_ne!(key_for_epoch(0), key_for_epoch(1));
        assert_eq!(&key_for_epoch(2)[..14], b"ZethoraRandomZ");
    }

    #[test]
    fn light_pow_is_deterministic_and_nonce_sensitive() {
        let a = pow_value_light(0, &pow_input(&[7u8; 32], 1_000, 1));
        let b = pow_value_light(0, &pow_input(&[7u8; 32], 1_000, 1));
        let c = pow_value_light(0, &pow_input(&[7u8; 32], 1_000, 2));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn light_pow_works_from_many_threads() {
        let expected = pow_value_light(0, &pow_input(&[9u8; 32], 5, 5));
        let handles: Vec<_> = (0..4).map(|_| std::thread::spawn(|| pow_value_light(0, &pow_input(&[9u8; 32], 5, 5)))).collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    }

    #[test]
    fn precompute_matches_one_by_one_across_epochs() {
        // Mixed epochs, out of order, a repeated item, more epochs than the kept setups: the batch answer equals hashing
        // each item on its own (without the memo)
        let mut items: Vec<(u64, [u8; POW_INPUT_LEN])> =
            [3u64, 0, 4, 3, 1, 0, 2, 5].iter().enumerate().map(|(i, &e)| (e, pow_input(&[i as u8; 32], 7, i as u64))).collect();
        items.push(items[2]);
        let batch = precompute_light(&items);
        assert_eq!(batch.len(), items.len());
        for ((epoch, input), value) in items.iter().zip(&batch) {
            assert_eq!(light_hash(*epoch, input), *value, "epoch {epoch}");
        }
        // Remembered, and a second batch gives the same answers
        assert_eq!(memo_get(items[0].0, &items[0].1), Some(batch[0]));
        assert_eq!(precompute_light(&items), batch);
    }
}
