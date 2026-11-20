//! Zethora (seam review P3-1): serving the pruning point's private state must be cheap and bounded.
//!
//! Building the state scans every coin tag and snapshot record ever stored, so it is built once per pruning point and
//! kept (`SingleEntryCache`); concurrent requests share the one build instead of each starting their own. Each
//! connection may ask for the same pruning point's state only a few times (`RequestLimiter`): an honest joiner asks once
//! per sync attempt.
//!
//! DoS fix (P2P): the expensive build must never run while the cache's lock is held. Holding the lock across the
//! O(chain-history) scan let one peer stall the private-state flow for every other peer on the node (the cache is a
//! single global `Arc`, shared by all connections). The cache now uses a single-flight pattern: the lock guards only
//! short state transitions with no `.await` under it, exactly one task is elected to run the heavy build with the
//! lock released, and the rest wait on a `watch` channel and reuse its result.

use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::watch;

/// What the cache is currently doing for its one key.
enum Slot<V> {
    /// Nothing built yet, or the last build failed: the next caller may build.
    Empty,
    /// A build is in flight; waiters observe the completion through `done`.
    Building { done: watch::Sender<u64> },
    /// The kept value.
    Ready(Arc<V>),
}

struct Inner<K, V> {
    slot: Slot<V>,
    /// The key the current `slot` refers to (meaningful once `slot` is not `Empty`).
    key: Option<K>,
}

/// Keeps the value for one key (the current pruning point). A request for another key rebuilds it.
///
/// The lock is a *synchronous* `StdMutex` guarding only short state transitions; the value itself is built
/// with the lock released so a slow build cannot block unrelated callers.
pub struct SingleEntryCache<K, V> {
    inner: StdMutex<Inner<K, V>>,
}

impl<K: Copy + Eq, V> Default for SingleEntryCache<K, V> {
    fn default() -> Self {
        Self { inner: StdMutex::new(Inner { slot: Slot::Empty, key: None }) }
    }
}

/// What a caller should do after inspecting the slot.
enum Step<V> {
    /// The value is already kept.
    Ready(Arc<V>),
    /// Another build is in flight; wait for `done` to change, then re-check.
    Wait(watch::Receiver<u64>),
    /// This caller is the elected builder.
    Build { done: watch::Sender<u64> },
}

impl<K: Copy + Eq, V> SingleEntryCache<K, V> {
    /// The value for `key`, built with `build` only if it is not the kept one.
    ///
    /// Exactly one caller builds for a given key at a time; concurrent callers for the same key wait for
    /// that build and share its result. The expensive `build` future runs with the lock released, so it never
    /// blocks callers of other keys or other parts of the node. A failed build keeps nothing, and the next
    /// caller builds again.
    pub async fn get_or_build<E, F, Fut>(&self, key: K, build: F) -> Result<Arc<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let mut build = Some(build);
        loop {
            // Phase 1: cheap fast-path / election. The lock is held only for a few instructions and no
            // `.await` occurs while it is held.
            let step = {
                let mut inner = self.inner.lock().expect("private state cache poisoned");
                let same_key = inner.key.as_ref().is_some_and(|k| *k == key);
                match &inner.slot {
                    Slot::Ready(value) if same_key => Step::Ready(value.clone()),
                    Slot::Building { done } if same_key => Step::Wait(done.subscribe()),
                    _ => {
                        // Nothing built, the previous build failed, or the pruning point moved: elect this
                        // caller as the sole builder.
                        let (done, _rx) = watch::channel(0u64);
                        inner.slot = Slot::Building { done: done.clone() };
                        inner.key = Some(key);
                        Step::Build { done }
                    }
                }
            };

            match step {
                Step::Ready(value) => return Ok(value),
                Step::Wait(mut done) => {
                    // A build for this key is already in flight. Wait for the completion signal, then
                    // re-check the slot (it is `Ready` on success or `Empty` on failure, in which case we
                    // build). `changed()` resolves only after the sender ticks, so the wakeup cannot be lost.
                    let _ = done.changed().await;
                    continue;
                }
                Step::Build { done } => {
                    // We are the elected builder. Run the heavy build with NO lock held.
                    let result = build.take().expect("builder runs exactly once")().await;
                    match result {
                        Ok(value) => {
                            let value = Arc::new(value);
                            // Publish under the lock (still no `.await` held), then wake the waiters.
                            {
                                let mut inner = self.inner.lock().expect("private state cache poisoned");
                                inner.slot = Slot::Ready(value.clone());
                            }
                            let _ = done.send(*done.borrow() + 1);
                            return Ok(value);
                        }
                        Err(e) => {
                            // A failed build keeps nothing, so the next caller builds again.
                            {
                                let mut inner = self.inner.lock().expect("private state cache poisoned");
                                inner.key = None;
                                inner.slot = Slot::Empty;
                            }
                            let _ = done.send(*done.borrow() + 1);
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

/// Counts one connection's requests per key and refuses past `max_per_key`. Only the last few keys are
/// remembered (a connection only ever asks about the current pruning point).
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
