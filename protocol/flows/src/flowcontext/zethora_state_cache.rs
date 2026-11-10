//! Zethora (seam review P3-1): serving the pruning point's private state must be cheap and bounded.
//!
//! Building the state scans every coin tag and snapshot record ever stored, so it is built once per pruning point and
//! kept (`SingleEntryCache`); concurrent requests wait for the one build instead of each starting their own. Each
//! connection may ask for the same pruning point's state only a few times (`RequestLimiter`): an honest joiner asks once
//! per sync attempt. The limiter refuses rather than forgets when a connection has named as many pruning points as it is
//! willing to track, so a peer cannot re-arm a spent quota by naming pruning points it does not want (OBS-3).

use std::{collections::HashMap, future::Future, hash::Hash, sync::Arc};
use tokio::sync::Mutex;

/// Keeps the value for one key (the current pruning point). A request for another key rebuilds it.
pub struct SingleEntryCache<K, V> {
    entry: Mutex<Option<(K, Arc<V>)>>,
}

impl<K: Copy + Eq, V> Default for SingleEntryCache<K, V> {
    fn default() -> Self {
        Self { entry: Mutex::new(None) }
    }
}

impl<K: Copy + Eq, V> SingleEntryCache<K, V> {
    /// The value for `key`, built with `build` only if it is not the kept one. The lock is held while building, so
    /// concurrent callers for the same key share one build. A failed build keeps nothing.
    pub async fn get_or_build<E, F, Fut>(&self, key: K, build: F) -> Result<Arc<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let mut entry = self.entry.lock().await;
        if let Some((kept, value)) = entry.as_ref()
            && *kept == key
        {
            return Ok(value.clone());
        }
        let value = Arc::new(build().await?);
        *entry = Some((key, value.clone()));
        Ok(value)
    }
}

/// Counts one connection's requests per key and refuses past `max_per_key`. Only a few distinct keys are remembered (a
/// connection only ever asks about the current pruning point).
///
/// Zethora (OBS-3): the remembered keys are bounded by refusing, never by forgetting. Dropping the counts of the keys
/// already seen would let a peer spend its quota on the pruning point it wants and then re-arm it by naming a few
/// unrelated pruning points, which are answered cheaply (`UnexpectedPruningPoint`) and do not close the connection.
/// A request for a new key while the map is full is therefore refused, which the flow reports as a protocol error and
/// disconnects the peer. An honest joiner asks about the current pruning point (plus the previous one across a sync
/// attempt), so it never reaches the bound.
pub struct RequestLimiter<K> {
    max_per_key: usize,
    counts: HashMap<K, usize>,
}

impl<K: Copy + Eq + Hash> RequestLimiter<K> {
    pub fn new(max_per_key: usize) -> Self {
        Self { max_per_key, counts: HashMap::new() }
    }

    /// Records a request for `key`; false once there have been more than `max_per_key` of them, or once the map is
    /// full and `key` is not one of the keys it already counts.
    pub fn allow(&mut self, key: K) -> bool {
        if let Some(count) = self.counts.get_mut(&key) {
            *count = count.saturating_add(1);
            return *count <= self.max_per_key;
        }
        if self.counts.len() >= KEYS_KEPT {
            return false;
        }
        self.counts.insert(key, 1);
        self.max_per_key > 0
    }
}

/// How many distinct keys one connection may name before further new keys are refused.
const KEYS_KEPT: usize = 8;

#[cfg(test)]
mod tests {
    use super::{KEYS_KEPT, RequestLimiter, SingleEntryCache};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    /// Seam review P3-1: one build per pruning point, however many requests; a new pruning point builds again.
    #[tokio::test]
    async fn the_private_state_is_built_once_per_pruning_point() {
        let cache = Arc::new(SingleEntryCache::<u64, String>::default());
        let builds = Arc::new(AtomicUsize::new(0));
        let build = |key: u64, builds: Arc<AtomicUsize>| async move {
            builds.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok::<_, ()>(format!("state of {key}"))
        };
        // 20 concurrent requests for pruning point 1: exactly one build, every caller gets the same value
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let (cache, builds) = (cache.clone(), builds.clone());
                tokio::spawn(async move { cache.get_or_build(1, || build(1, builds)).await.unwrap() })
            })
            .collect();
        for h in handles {
            assert_eq!(*h.await.unwrap(), "state of 1");
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        // The pruning point moves: one more build
        assert_eq!(*cache.get_or_build(2, || build(2, builds.clone())).await.unwrap(), "state of 2");
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        // A failed build keeps nothing (the next request builds again)
        assert!(cache.get_or_build(3, || async { Err::<String, ()>(()) }).await.is_err());
        assert_eq!(*cache.get_or_build(3, || build(3, builds.clone())).await.unwrap(), "state of 3");
        assert_eq!(builds.load(Ordering::SeqCst), 3);
    }

    /// Seam review P3-1: a connection gets each pruning point's state at most `max_per_key` times.
    #[test]
    fn a_connection_may_ask_only_a_few_times_per_pruning_point() {
        let mut limiter = RequestLimiter::new(3);
        assert!(limiter.allow(1));
        assert!(limiter.allow(1));
        assert!(limiter.allow(1));
        assert!(!limiter.allow(1));
        assert!(!limiter.allow(1));
        // Another pruning point has its own count
        assert!(limiter.allow(2));
        // Bounded memory: many keys never grow the map past its cap
        for k in 10..1_000 {
            limiter.allow(k);
            assert!(limiter.counts.len() <= 8);
        }
    }

    /// Seam review / OBS-3: naming unrelated pruning points must not give the spent quota back.
    #[test]
    fn a_full_limiter_refuses_new_pruning_points_instead_of_forgetting_the_old_ones() {
        let mut limiter = RequestLimiter::new(3);
        // Spend the quota of the pruning point the peer actually wants
        for _ in 0..3 {
            assert!(limiter.allow(1));
        }
        assert!(!limiter.allow(1));
        // Fill the map with unrelated pruning points: the first `KEYS_KEPT - 1` still fit, the next must be refused
        // rather than evicting the counts already held.
        for k in 1..=KEYS_KEPT as u64 {
            limiter.allow(100 + k);
        }
        assert_eq!(limiter.counts.len(), 8, "the map must stay bounded");
        assert!(!limiter.allow(999), "a new key must be refused once the map is full");
        // The refused key did not enter the map, and the spent quota is still spent
        assert_eq!(limiter.counts.len(), 8);
        assert!(!limiter.allow(1), "the bypass key must not have reset the count of the wanted pruning point");
    }
}
