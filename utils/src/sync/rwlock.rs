use super::semaphore::Semaphore;
use std::sync::Arc;

/// Readers-first Reader-writer Lock. If the lock is acquired by readers, then additional readers
/// will always be able to acquire the lock as well even if a writer is already in the queue. Note
/// that this makes it safe to make recursive read calls.
///
/// We currently only use this lock over an empty tuple, however it can easily contain data by
/// using `UnsafeCell<T>` and passing it to the various guards with or without mutable access
pub struct RfRwLock {
    // The low-level "non-fair" semaphore used to prioritize readers
    ll_sem: Semaphore,
}

impl Default for RfRwLock {
    fn default() -> Self {
        Self::new()
    }
}

impl RfRwLock {
    pub fn new() -> Self {
        Self { ll_sem: Semaphore::new(Semaphore::MAX_PERMITS) }
    }

    pub async fn read(&self) -> RfRwLockReadGuard<'_> {
        self.ll_sem.acquire(1).await;
        RfRwLockReadGuard(self)
    }

    pub fn blocking_read(&self) -> RfRwLockReadGuard<'_> {
        self.ll_sem.blocking_acquire(1);
        RfRwLockReadGuard(self)
    }

    pub async fn read_owned(self: Arc<Self>) -> RfRwLockOwnedReadGuard {
        self.ll_sem.acquire(1).await;
        RfRwLockOwnedReadGuard(self)
    }

    pub async fn write(&self) -> RfRwLockWriteGuard<'_> {
        // Writes acquire all possible permits, hence they ensure exclusiveness. On the other hand, this allows
        // late readers to get in front of them since readers request only a single permit and the semaphore is
        // non-fair
        self.ll_sem.acquire(Semaphore::MAX_PERMITS).await;
        RfRwLockWriteGuard(self)
    }

    pub fn blocking_write(&self) -> RfRwLockWriteGuard<'_> {
        self.ll_sem.blocking_acquire(Semaphore::MAX_PERMITS);
        RfRwLockWriteGuard(self)
    }

    pub async fn write_owned(self: Arc<Self>) -> RfRwLockOwnedWriteGuard {
        self.ll_sem.acquire(Semaphore::MAX_PERMITS).await;
        RfRwLockOwnedWriteGuard(self)
    }

    fn release_read(&self) {
        self.ll_sem.release(1);
    }

    fn release_write(&self) {
        self.ll_sem.release(Semaphore::MAX_PERMITS);
    }

    fn blocking_yield_writer(&self) {
        self.ll_sem.blocking_yield(Semaphore::MAX_PERMITS);
    }
}

pub struct RfRwLockReadGuard<'a>(&'a RfRwLock);

impl Drop for RfRwLockReadGuard<'_> {
    fn drop(&mut self) {
        self.0.release_read();
    }
}

pub struct RfRwLockOwnedReadGuard(Arc<RfRwLock>);

impl Drop for RfRwLockOwnedReadGuard {
    fn drop(&mut self) {
        self.0.release_read();
    }
}

pub struct RfRwLockWriteGuard<'a>(&'a RfRwLock);

impl Drop for RfRwLockWriteGuard<'_> {
    fn drop(&mut self) {
        self.0.release_write();
    }
}

impl RfRwLockWriteGuard<'_> {
    /// Releases and recaptures the write lock. Makes sure that other pending readers/writers get a
    /// chance to capture the lock before this thread does so.
    pub fn blocking_yield(&mut self) {
        self.0.blocking_yield_writer();
    }
}

pub struct RfRwLockOwnedWriteGuard(Arc<RfRwLock>);

impl Drop for RfRwLockOwnedWriteGuard {
    fn drop(&mut self) {
        self.0.release_write();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::println;
    use std::{
        sync::atomic::{AtomicBool, Ordering::SeqCst},
        time::Duration,
    };
    use tokio::{sync::oneshot, time::sleep, time::timeout};

    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
    #[tokio::test]
    async fn test_writer_reentrance() {
        for i in 0..16 {
            let l = Arc::new(RfRwLock::new());
            let (tx, rx) = oneshot::channel();
            let l_clone = l.clone();
            let h = std::thread::spawn(move || {
                let mut write = l_clone.blocking_write();
                tx.send(()).unwrap();
                for _ in 0..10 {
                    std::thread::sleep(Duration::from_millis(2));
                    write.blocking_yield();
                }
            });
            rx.await.unwrap();
            // Make sure the reader acquires the lock during writer yields. We give the test a few chances to acquire
            // in order to make sure it passes also in slow CI environments where the OS thread-scheduler might take its time
            let read = timeout(Duration::from_millis(36), l.read()).await.unwrap_or_else(|_| panic!("failed at iteration {i}"));
            drop(read);
            timeout(Duration::from_millis(1000), tokio::task::spawn_blocking(move || h.join())).await.unwrap().unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn test_readers_preferred() {
        let l = Arc::new(RfRwLock::new());
        let read1 = l.read().await;
        let read2 = l.read().await;
        let read3 = l.read().await;

        let (tx, rx) = oneshot::channel();
        let (tx_back, rx_back) = oneshot::channel();
        let l_clone = l.clone();
        let h = tokio::spawn(async move {
            let fut = l_clone.write();
            tx.send(()).unwrap();
            let _write = fut.await;
            println!("writer acquired");
            rx_back.await.unwrap();
            println!("releasing writer");
        });

        // Wait for the writer to request writing before registering more readers
        rx.await.unwrap();

        let read4 = timeout(ACQUIRE_TIMEOUT, l.read()).await.unwrap();
        let read5 = timeout(ACQUIRE_TIMEOUT, l.read()).await.unwrap();

        drop(read1);
        drop(read2);
        drop(read3);
        drop(read4);
        drop(read5);
        println!("dropped all readers");

        let f = Arc::new(AtomicBool::new(false));
        let f_clone = f.clone();
        let l_clone = l.clone();
        tokio::spawn(async move {
            let _read = l_clone.read().await;
            assert!(f_clone.load(SeqCst), "reader acquired before writer release");
            println!("late reader acquired");
        });

        sleep(Duration::from_secs(1)).await;
        f.store(true, SeqCst);
        tx_back.send(()).unwrap();
        timeout(ACQUIRE_TIMEOUT, h).await.unwrap().unwrap();
    }

    /// Zethora (seam review pack 1, #3): the exact pattern in VirtualStateProcessor::commit_utxo_state. A thread holding
    /// a blocking read takes a second blocking read while a writer (the pruning thread) is already waiting. The lock is
    /// readers-first, so this must not deadlock; and the writer must still get in once both reads are released.
    #[test]
    fn recursive_blocking_read_with_a_waiting_writer_does_not_deadlock() {
        use std::sync::mpsc;
        let l = Arc::new(RfRwLock::new());
        let read1 = l.blocking_read();

        // The writer queues up behind read1
        let (writer_started, writer_started_rx) = mpsc::channel();
        let (writer_done, writer_done_rx) = mpsc::channel();
        let l_writer = l.clone();
        let writer = std::thread::spawn(move || {
            writer_started.send(()).unwrap();
            let _w = l_writer.blocking_write();
            writer_done.send(()).unwrap();
        });
        writer_started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100)); // let the writer block on the semaphore

        // Positive control: the writer is really waiting (it can't get in while read1 is held)
        assert!(writer_done_rx.try_recv().is_err());

        // The second read on another thread standing in for the same call chain: must not hang
        let (read2_taken, read2_taken_rx) = mpsc::channel();
        let l_reader = l.clone();
        let reader = std::thread::spawn(move || {
            let _read2 = l_reader.blocking_read();
            read2_taken.send(()).unwrap();
        });
        read2_taken_rx.recv_timeout(ACQUIRE_TIMEOUT).expect("second read deadlocked behind a waiting writer");
        reader.join().unwrap();

        // Release the first read: now the writer gets the lock
        drop(read1);
        writer_done_rx.recv_timeout(ACQUIRE_TIMEOUT).expect("writer never acquired after readers released");
        writer.join().unwrap();
    }
}
