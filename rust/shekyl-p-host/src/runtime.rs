// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serving runtime (`SH-3`, `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.8).
//!
//! Serving runs inside the wallet process. Before this module the endpoint
//! was bound on whatever runtime the engine was running on, and its
//! read-and-fold and sign hops went to that runtime's shared blocking
//! pool, so there was no thread whose priority was *serving's* to lower.
//! Now the host builds one runtime and blocking pool for serving, through
//! the single constructor (D5), and every thread of it lowers its own CPU
//! priority as it starts. The accept loop, every per-connection task, the
//! read-and-fold hops and the sign hop run here and nowhere else.
//!
//! What this runtime does not cover: the `SF-D13` countersignature is made
//! inside the stake actor, which holds the key and runs at engine
//! priority. The hop crosses; the key does not.
//!
//! Lowering is unconditional (rule 75): priority shows only under
//! contention, timing already reveals load, and a population of personas
//! that could opt out would be a fingerprint. When the platform refuses,
//! the thread serves at normal priority for as long as it keeps running.
//! It is recorded on [`PriorityFailures`] until it exits. The first
//! refusal's cause is kept beside that set, under the same lock, and the
//! counter wakes the engine, which logs one warning per host (rule 82).
//! This crate is on `P`'s serving path and writes no log line of its own
//! (`WSS-20`). Serving is never refused for it.

use std::collections::HashSet;
use std::io;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::ThreadId;
use std::time::Duration;

use shekyl_p_serve::MAX_INFLIGHT;
use shekyl_runtime::{runtime_with_thread_hooks, Pool, RuntimeBudget, ThreadHooks, ThreadName};
use shekyl_thread_priority::{lower_current_thread, NotLowered};
use tokio::sync::Notify;

/// The serving runtime's async workers.
///
/// A structural floor, labelled unmeasured in the ledger until the
/// confirming floor run (§9.8): the executor work per response is small —
/// the frame head, the digest's start and finish, the socket writes — and
/// `BA-T5` showed the path CPU-bound on the blocking side, so two workers
/// keep the accept loop and the writes moving while the blocking pool does
/// the reading and hashing.
pub const SERVING_WORKERS: usize = 2;

/// The serving runtime's blocking-pool cap: one thread per permitted
/// connection, because each connection has at most one hop (a chunk read
/// and fold, or the sign round trip) in flight at a time.
pub const SERVING_BLOCKING: usize = MAX_INFLIGHT;

/// The OS thread name and ledger label of the serving runtime.
const SERVING_THREAD_NAME: &str = "sk-serving";

/// Worker budget as the non-zero count the runtime constructor takes.
///
/// Zero is not a budget. The match is a const, so a zero
/// [`SERVING_WORKERS`] fails compilation rather than the first start.
const SERVING_WORKER_THREADS: NonZeroUsize = match NonZeroUsize::new(SERVING_WORKERS) {
    Some(count) => count,
    None => panic!("SERVING_WORKERS is zero"),
};

/// Blocking budget as the non-zero count the runtime constructor takes.
const SERVING_BLOCKING_THREADS: NonZeroUsize = match NonZeroUsize::new(SERVING_BLOCKING) {
    Some(count) => count,
    None => panic!("SERVING_BLOCKING is zero"),
};

/// How long the runtime's shutdown waits for a blocking hop still running.
///
/// A hop is one chunk read and folded, or one sign round trip into the
/// stake actor; both are bounded well inside this. A hop still running at
/// the end of the wait keeps its thread until it returns, detached, as
/// [`Pool::shutdown`] documents.
const SERVING_SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// Serving threads currently at normal priority because lowering failed.
///
/// Born by the caller that reports serving status and handed to the host,
/// so the count outlives any one host and is readable without holding it.
/// The start hook records a thread whose call failed. The stop hook
/// removes it when that thread exits, including when the runtime retires
/// an idle blocking thread and starts another for the next hop. The count
/// is that live set. Steady state stays within the runtime's budget
/// ([`SERVING_WORKERS`] plus [`SERVING_BLOCKING`]). A thread whose stop
/// has not yet run can still be in the set for a moment beside the thread
/// that replaced it — Tokio drops its blocking-pool count before the stop
/// hook — and the set is not clamped to hide that. Zero is the expected
/// reading on every supported platform. It is the OS call's result for the
/// threads that are still running, and nothing more: it does not say
/// whether the lowered priority yields CPU to the daemon, which depends on
/// the two processes being in one scheduling group (§9.8, the confirming
/// run).
///
/// The first refusal's cause sits in the same state as the set
/// ([`Self::first_refusal`]), so a reader that sees a count sees the cause.
/// [`Self::until_first_refusal`] wakes on that first record. This crate
/// logs nothing itself (`WSS-20`).
#[derive(Clone, Debug, Default)]
pub struct PriorityFailures(Arc<Refusals>);

/// The set of threads whose lowering failed, the first cause, and the
/// wake that publishes the cause.
///
/// One mutex, not a counter beside a separate cell: on aarch64 a relaxed
/// increment can be observed while an earlier store to a different atomic
/// is still invisible, and the warning would then burn its only line on a
/// missing cause. The cause and the set change together or not at all.
#[derive(Debug, Default)]
struct Refusals {
    state: Mutex<RefusalState>,
    /// Wakes every [`PriorityFailures::until_first_refusal`] subscribed
    /// when the first cause is stored. A level, not a permit: the cause
    /// stays set, `notify_waiters` wakes every waiter parked at that
    /// moment, and a waiter that arrives later reads the cause. Tokio
    /// 1.51 snapshots this call's generation inside `notified()`, so a
    /// future created before the call completes on its first poll even
    /// when it had not yet registered a waiter.
    notify: Notify,
}

/// Threads at normal priority, and why the first of them was not lowered.
#[derive(Debug, Default)]
struct RefusalState {
    /// Threads whose call failed and that have not yet exited.
    ///
    /// A [`ThreadId`] is not reused, so a thread that has exited cannot
    /// be removed by a later thread's stop, and a stop that never
    /// retained finds nothing to remove.
    unlowered: HashSet<ThreadId>,
    /// Why the first call failed, as the platform put it.
    first_cause: Option<String>,
}

impl PriorityFailures {
    /// A fresh counter: no thread unlowered, no cause.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The refusal state, recovering a poisoned lock.
    ///
    /// The critical sections insert or remove one thread id and, once,
    /// store a cause. A panic while holding the lock cannot leave a torn
    /// pair, and propagating the poison would turn that panic into a
    /// serving thread that stops answering — a slash.
    fn lock(&self) -> std::sync::MutexGuard<'_, RefusalState> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serving threads running at normal priority because lowering failed.
    #[must_use]
    pub fn count(&self) -> u32 {
        let live = self.lock().unlowered.len();
        u32::try_from(live).unwrap_or(u32::MAX)
    }

    /// Why the first thread that failed was not lowered, as the platform
    /// put it, or `None` while every thread's call has succeeded. Stored
    /// once per counter; a later refusal does not replace it.
    #[must_use]
    pub fn first_refusal(&self) -> Option<String> {
        self.lock().first_cause.clone()
    }

    /// The first cause, once a thread has failed to lower.
    ///
    /// The wait is created before the read. Tokio 1.51's `notified()`
    /// snapshots `notify_waiters`'s generation at that moment, so a
    /// refusal that lands between the snapshot and the read is either
    /// observed by the read or delivered when the wait is polled. A cause
    /// already stored returns without waiting. The notification is a
    /// level: every waiter subscribed when the first cause is stored is
    /// woken, and a second waiter is not left asleep on a single permit.
    #[must_use]
    pub async fn until_first_refusal(&self) -> String {
        loop {
            let notified = self.0.notify.notified();
            if let Some(cause) = self.first_refusal() {
                return cause;
            }
            notified.await;
        }
    }

    /// This thread is one of the live set. The first call also stores
    /// the cause and wakes every subscriber.
    fn retain(&self, cause: &NotLowered) {
        let first = {
            let mut state = self.lock();
            let first = state.first_cause.is_none();
            if first {
                state.first_cause = Some(cause.to_string());
            }
            state.unlowered.insert(std::thread::current().id());
            first
        };
        if first {
            self.0.notify.notify_waiters();
        }
    }

    /// This thread has exited. A release that does not match a retain
    /// removes nothing: the id was never inserted, so the set cannot wrap.
    fn release(&self) {
        self.lock().unlowered.remove(&std::thread::current().id());
    }

    /// The start and stop hooks that keep [`Self::count`] equal to the
    /// threads still at normal priority.
    ///
    /// The pair is one value. The start hook cannot be installed without
    /// the stop hook that removes the same thread, so a retired blocking
    /// thread cannot stay in the count. The stop hook runs on every
    /// thread of the pool; a thread that was lowered is not in the set,
    /// and removing it changes nothing.
    fn thread_hooks(
        &self,
        lower: impl Fn() -> Result<(), NotLowered> + Send + Sync + 'static,
    ) -> ThreadHooks {
        let retained = self.clone();
        let released = self.clone();
        ThreadHooks::pair(
            move || {
                if let Err(cause) = lower() {
                    retained.retain(&cause);
                }
            },
            move || released.release(),
        )
    }
}

/// The serving runtime, owned by the host for the host's life.
///
/// **Dropping this never blocks the dropping thread and never panics in an
/// async context.** A runtime cannot be dropped from inside a task, and the
/// host is dropped from the engine's runtime on every path that is not the
/// ordered shutdown — a failed start after the pool exists, a panic
/// unwinding through the serving task. Drop therefore stops the pool with
/// [`Pool::shutdown_background`]: a zero wait, which returns before Tokio's
/// check that a blocking wait is not allowed, including while a panic is
/// already unwinding. In-flight blocking hops keep their threads, detached,
/// the same as an ordered shutdown whose wait expired. The value that
/// owns this pool owns the endpoint ahead of it, so the endpoint and its
/// accept task are gone before the pool that ran them is told to stop.
pub(crate) struct ServingPool(Option<Pool>);

impl ServingPool {
    /// Build the serving runtime with the shipped priority setter.
    ///
    /// # Errors
    ///
    /// The runtime builder's I/O error: the OS refused the threads.
    pub(crate) fn build(failures: &PriorityFailures) -> io::Result<Self> {
        Self::build_with(failures, lower_current_thread)
    }

    /// [`Self::build`] with the priority setter injected, so a test can
    /// drive the failure path without a platform that refuses.
    pub(crate) fn build_with(
        failures: &PriorityFailures,
        lower: impl Fn() -> Result<(), NotLowered> + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let name = ThreadName::new(SERVING_THREAD_NAME).map_err(io::Error::other)?;
        let budget = RuntimeBudget {
            workers: SERVING_WORKER_THREADS,
            blocking: SERVING_BLOCKING_THREADS,
        };
        let hooks = failures.thread_hooks(lower);
        Ok(Self(Some(runtime_with_thread_hooks(budget, &name, hooks)?)))
    }

    /// The runtime, to spawn the bind onto.
    pub(crate) fn handle(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("the pool is present until drop")
    }

    /// The ordered shutdown's stop: wait, off this thread, for the runtime
    /// to stop — at most [`SERVING_SHUTDOWN_WAIT`] for a blocking hop.
    ///
    /// Awaited by [`PersonaServingHost::shutdown`](crate::PersonaServingHost::shutdown)
    /// after the endpoint is dropped, so that when shutdown resolves the
    /// accept task has been dropped with the runtime and the listener is
    /// closed, not merely told to close. The wait runs on the calling
    /// runtime's blocking pool: a non-zero wait is not allowed on an async
    /// worker. Drop is the zero-wait fallback for every other path, and
    /// that one is safe on the worker itself.
    pub(crate) async fn stop(mut self) {
        if let Some(pool) = self.0.take() {
            tokio::task::spawn_blocking(move || pool.shutdown(SERVING_SHUTDOWN_WAIT))
                .await
                .ok();
        }
    }
}

impl Drop for ServingPool {
    fn drop(&mut self) {
        if let Some(pool) = self.0.take() {
            pool.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// The first refusal wakes every waiter subscribed before it, keeps
    /// that cause, and a release of the same thread brings the count to
    /// zero. A second refusal does not replace the cause or grow the set.
    #[tokio::test]
    async fn the_first_refusal_wakes_every_waiter_and_keeps_its_cause() {
        let failures = PriorityFailures::new();
        let mut first = std::pin::pin!(failures.until_first_refusal());
        let mut second = std::pin::pin!(failures.until_first_refusal());
        tokio::select! {
            biased;
            _ = &mut first => panic!("the first waiter woke with no refusal"),
            _ = &mut second => panic!("the second waiter woke with no refusal"),
            () = tokio::time::sleep(Duration::from_millis(30)) => {}
        }

        failures.retain(&NotLowered::Unsupported);
        let cause = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("the first refusal wakes every subscribed waiter");
        let also = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("a second waiter is not left asleep on one permit");
        assert_eq!(cause, also);
        assert!(
            cause.contains("no per-thread priority under normal scheduling"),
            "{cause}"
        );
        assert_eq!(failures.count(), 1);
        assert_eq!(failures.first_refusal().as_deref(), Some(cause.as_str()));

        // The same thread, a different cause: one member, and the first
        // cause is the one the warning will name.
        failures.retain(&NotLowered::Refused(io::Error::from_raw_os_error(1)));
        assert_eq!(failures.count(), 1);
        assert_eq!(failures.first_refusal().as_deref(), Some(cause.as_str()));

        failures.release();
        assert_eq!(failures.count(), 0);
        // A release that matches no retain leaves the set alone.
        failures.release();
        assert_eq!(failures.count(), 0);

        // The cause stays after the thread has exited. A waiter that
        // arrives then reads it and does not wait.
        let late = tokio::time::timeout(Duration::from_millis(50), failures.until_first_refusal())
            .await
            .expect("a cause already kept returns without waiting");
        assert_eq!(late, cause);
    }

    /// Every thread the serving runtime hands work to reads back at the
    /// serving nice value, and the test's own runtime's threads do not move.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serving_threads_run_at_the_serving_nice_and_the_caller_does_not() {
        use shekyl_thread_priority::{current_thread_nice, SERVING_NICE};

        let caller_before = current_thread_nice().expect("read nice");
        let failures = PriorityFailures::new();
        let pool = ServingPool::build(&failures).expect("serving runtime");
        let readings: Arc<Mutex<Vec<(std::thread::ThreadId, i32)>>> = Default::default();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let worker = Arc::clone(&readings);
            tasks.push(pool.handle().spawn(async move {
                worker.lock().expect("readings").push((
                    std::thread::current().id(),
                    current_thread_nice().expect("read nice"),
                ));
            }));
            let blocking = Arc::clone(&readings);
            tasks.push(pool.handle().spawn(async move {
                tokio::task::spawn_blocking(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    blocking.lock().expect("readings").push((
                        std::thread::current().id(),
                        current_thread_nice().expect("read nice"),
                    ));
                })
                .await
                .expect("blocking");
            }));
        }
        for task in tasks {
            task.await.expect("task");
        }
        let readings = readings.lock().expect("readings").clone();
        let threads: std::collections::HashSet<_> = readings.iter().map(|(id, _)| *id).collect();
        assert!(
            threads.len() >= 2,
            "a worker and a blocking thread: {readings:?}"
        );
        for (id, nice) in &readings {
            assert_eq!(*nice, SERVING_NICE, "thread {id:?} serves at nice {nice}");
        }
        assert_eq!(failures.count(), 0);
        // The engine's threads: this test's runtime, on which nothing was
        // lowered.
        assert_eq!(current_thread_nice().expect("read nice"), caller_before);
        let engine_nice = tokio::task::spawn_blocking(|| current_thread_nice().expect("read nice"))
            .await
            .expect("blocking");
        assert_eq!(engine_nice, caller_before);
        drop(pool);
    }

    /// The failure path: the setter refuses on every thread, every thread
    /// is counted once, the first cause is kept, and an endpoint bound on
    /// that runtime still answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_lowering_is_counted_once_per_thread_and_serving_goes_on() {
        let failures = PriorityFailures::new();
        assert_eq!(failures.first_refusal(), None, "nothing refused yet");
        let pool = ServingPool::build_with(&failures, || {
            Err(NotLowered::Refused(io::Error::from_raw_os_error(13)))
        })
        .expect("serving runtime");
        let threads: Arc<Mutex<std::collections::HashSet<std::thread::ThreadId>>> =
            Default::default();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let seen = Arc::clone(&threads);
            tasks.push(pool.handle().spawn(async move {
                let seen_blocking = Arc::clone(&seen);
                tokio::task::spawn_blocking(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    seen_blocking
                        .lock()
                        .expect("seen")
                        .insert(std::thread::current().id());
                })
                .await
                .expect("blocking");
                seen.lock()
                    .expect("seen")
                    .insert(std::thread::current().id());
            }));
        }
        for task in tasks {
            task.await.expect("the runtime still runs work");
        }
        let seen = threads.lock().expect("seen").len();
        assert!(seen >= 2, "a worker and a blocking thread ran: {seen}");
        // Sampled after the work has finished, while those threads are still
        // inside the pool: the live set is within the budget. Threads start
        // as work arrives, so the count is at least the threads that took
        // work. A thread whose stop hook has not yet run can sit beside its
        // replacement for a moment; that overlap is not clamped, and this
        // sample is not it.
        let counted = failures.count() as usize;
        assert!(counted >= seen, "counted {counted}, saw {seen} threads");
        assert!(counted <= SERVING_WORKERS + SERVING_BLOCKING);

        // The accept loop has to be the serving runtime's. A 400 is enough:
        // an invalid request is answered before the store or the key, and
        // any answer means the loop is running.
        let signer = crate::signer_at_synced_tip(
            Arc::new(crate::RefusingKey),
            shekyl_types::BlockHeight::from_raw(10_000),
            Duration::from_secs(60),
        );
        let endpoint =
            pool.handle()
                .spawn(async move {
                    shekyl_p_serve::PServeEndpoint::bind(Arc::new(NoShards), signer).await
                })
                .await
                .expect("bind task")
                .expect("endpoint");
        let response = request_status(endpoint.addr()).await;
        assert!(
            response.starts_with("HTTP/1.1 400 "),
            "the endpoint answered {response:?}"
        );
        drop(endpoint);

        // The cause is kept once, for the engine's one warning; this crate
        // logs nothing (WSS-20).
        let cause = failures.first_refusal().expect("the first refusal is kept");
        assert!(
            cause.starts_with("the platform refused to lower this thread's priority"),
            "kept cause: {cause}"
        );
        drop(pool);
    }

    /// An idle blocking thread leaves the count when Tokio retires it,
    /// and the thread that replaces it is counted on its own call.
    ///
    /// Tokio's blocking pool exits a thread that sits idle for
    /// [`BLOCKING_THREAD_KEEP_ALIVE`] (the default; the serving runtime
    /// does not set one) and runs the start hook again for the next hop.
    /// The count is the threads still in that state, so after the idle
    /// gap it is the workers alone, and after the next hop it is the
    /// workers plus the new blocking thread. Shutdown then brings it to
    /// zero.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retired_blocking_thread_leaves_the_unlowered_count() {
        let failures = PriorityFailures::new();
        let workers = u32::try_from(SERVING_WORKERS).expect("worker count");
        let pool = ServingPool::build_with(&failures, || {
            Err(NotLowered::Refused(io::Error::from_raw_os_error(13)))
        })
        .expect("serving runtime");

        assert!(
            wait_until(|| failures.count() == workers, Duration::from_secs(2)).await,
            "workers did not all start: {}",
            failures.count()
        );

        let first = pool
            .handle()
            .spawn(async { tokio::task::spawn_blocking(|| std::thread::current().id()).await })
            .await
            .expect("task")
            .expect("blocking");
        assert_eq!(failures.count(), workers + 1);

        let retired = wait_until(
            || failures.count() == workers,
            BLOCKING_THREAD_KEEP_ALIVE + Duration::from_secs(5),
        )
        .await;
        assert!(
            retired,
            "the idle blocking thread is still counted: {}",
            failures.count()
        );

        let second = pool
            .handle()
            .spawn(async { tokio::task::spawn_blocking(|| std::thread::current().id()).await })
            .await
            .expect("task")
            .expect("blocking");
        assert_ne!(first, second, "the replacement is a new thread");
        assert_eq!(failures.count(), workers + 1);

        pool.stop().await;
        assert!(
            wait_until(|| failures.count() == 0, Duration::from_secs(2)).await,
            "every serving thread has stopped: {}",
            failures.count()
        );
    }

    /// Tokio 1.51's blocking-pool default (`KEEP_ALIVE` in
    /// `runtime/blocking/pool.rs`). The serving runtime does not set
    /// `thread_keep_alive`.
    const BLOCKING_THREAD_KEEP_ALIVE: Duration = Duration::from_secs(10);

    async fn wait_until(mut pred: impl FnMut() -> bool, limit: Duration) -> bool {
        let start = std::time::Instant::now();
        loop {
            if pred() {
                return true;
            }
            if start.elapsed() >= limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Dropping the pool from inside an async context does not panic and
    /// does not wait for a blocking hop. This is the path a failed start
    /// and an unwinding serving task both take. The hop stays detached;
    /// unordered drop does not join it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_pool_inside_a_task_does_not_panic() {
        let failures = PriorityFailures::new();
        let pool = ServingPool::build(&failures).expect("serving runtime");
        let (tx, rx) = std::sync::mpsc::channel();
        pool.handle().spawn(async move {
            tokio::task::spawn_blocking(move || {
                tx.send(()).expect("started");
                std::thread::sleep(Duration::from_millis(200));
            })
            .await
            .ok();
        });
        rx.recv().expect("a blocking hop is running");
        let began = std::time::Instant::now();
        drop(pool);
        assert!(
            began.elapsed() < Duration::from_millis(150),
            "drop waited for the blocking hop"
        );
    }

    /// No shard is held. The refusal test's request is answered before the
    /// store is opened, so this body is never read.
    struct NoShards;

    impl shekyl_p_serve::ShardProvider for NoShards {
        fn shard_bytes(
            &self,
            _shard_id: u64,
        ) -> Result<Option<shekyl_p_serve::ShardBody>, shekyl_p_serve::ProviderError> {
            Ok(None)
        }
    }

    async fn request_status(addr: std::net::SocketAddr) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .expect("write");
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        let read = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = stream.read(&mut tmp).await.expect("read");
                assert!(n > 0, "the endpoint closed without answering");
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
        });
        read.await.expect("the endpoint answered");
        String::from_utf8(buf).expect("response bytes")
    }
}
