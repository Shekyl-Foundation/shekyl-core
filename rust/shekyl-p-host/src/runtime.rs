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
//! the thread serves at normal priority, the refusal is counted on
//! [`PriorityFailures`] for the serving status, and one warning is logged
//! per host (rule 82). Serving is never refused for it.

use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_p_serve::MAX_INFLIGHT;
use shekyl_runtime::{runtime, Pool, RuntimeBudget, ThreadName, ThreadStart};
use shekyl_thread_priority::{lower_current_thread, NotLowered};

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

/// How long the runtime's shutdown waits for a blocking hop still running.
///
/// A hop is one chunk read and folded, or one sign round trip into the
/// stake actor; both are bounded well inside this. A hop still running at
/// the end of the wait keeps its thread until it returns, detached, as
/// [`Pool::shutdown`] documents.
const SERVING_SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// Threads of the serving runtime whose priority-lowering call the OS
/// refused.
///
/// Born by the caller that reports serving status and handed to the host,
/// so the count outlives any one host and is readable without holding it.
/// Each thread whose call failed adds one; a thread whose call succeeded
/// adds nothing. Zero is the expected reading on every supported platform.
/// It is the OS call's result and nothing more: it does not say whether
/// the lowered priority yields CPU to the daemon, which depends on the two
/// processes being in one scheduling group (§9.8, the confirming run).
#[derive(Clone, Debug, Default)]
pub struct PriorityFailures(Arc<AtomicU32>);

impl PriorityFailures {
    /// A fresh counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Threads that serve at normal priority because lowering failed.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    fn record(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
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
/// the same as an ordered shutdown whose wait expired. The host declares
/// this as its last field, so the endpoint and its accept task are gone
/// before the pool that ran them is told to stop.
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
            workers: NonZeroUsize::new(SERVING_WORKERS)
                .ok_or_else(|| io::Error::other("zero workers"))?,
            blocking: NonZeroUsize::new(SERVING_BLOCKING)
                .ok_or_else(|| io::Error::other("zero blocking"))?,
        };
        let failures = failures.clone();
        // One warning per host: the first thread that fails says so, with
        // the cause; the rest only count. A persona whose platform refuses
        // on every thread would otherwise log once per thread per start.
        let warned = Arc::new(AtomicBool::new(false));
        let on_thread_start = ThreadStart::new(move || {
            if let Err(cause) = lower() {
                failures.record();
                if !warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        %cause,
                        "the OS refused to lower a serving thread's CPU priority; it serves at \
                         normal priority, and the count of such threads is on the serving status"
                    );
                }
            }
        });
        Ok(Self(Some(runtime(budget, &name, on_thread_start)?)))
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
    /// is counted once, one warning is logged, and the runtime still runs
    /// work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_lowering_is_counted_once_per_thread_and_serving_goes_on() {
        let failures = PriorityFailures::new();
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
        // Every started thread failed once. Threads start lazily, so the
        // count is at least the threads that took work, and never more than
        // the budget.
        let counted = failures.count() as usize;
        assert!(counted >= seen, "counted {counted}, saw {seen} threads");
        assert!(counted <= SERVING_WORKERS + SERVING_BLOCKING);
        drop(pool);
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
}
