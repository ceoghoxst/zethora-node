//! Zethora (seam review P3-1): serving the pruning point's private state must be cheap and bounded.
//!
//! Building the state scans every coin tag and snapshot record ever stored, so it is built once per pruning point and
//! kept (`SingleEntryCache`); concurrent requests wait for the one build instead of each starting their own. Each
//! connection may ask for the same pruning point's state only a few times (`RequestLimiter`): an honest joiner asks once
//! per sync attempt.

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

/// Counts one connection's requests per key and refuses past `max_per_key`. Only the last few keys are remembered (a
/// connection only ever asks about the current pruning point).
pub struct RequestLimiter<K> {
    max_per_key: usize,
    counts: HashMap<K, usize>,
}

impl<K: Copy + Eq + Hash> RequestLimiter<K> {
    pub fn new(max_per_key: usize) -> Self {
        Self { max_per_key, counts: HashMap::new() }
    }

    /// Records a request for `key`; false once there have been more than `max_per_key` of them.
    pub fn allow(&mut self, key: K) -> bool {
        const KEYS_KEPT: usize = 8;
        if !self.counts.contains_key(&key) && self.counts.len() >= KEYS_KEPT {
            self.counts.clear();
        }
        let count = self.counts.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        *count <= self.max_per_key
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestLimiter, SingleEntryCache};
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
}
