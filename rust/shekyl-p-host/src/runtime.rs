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
//! It is counted on [`PriorityFailures`] until it exits, and one warning
//! is logged per host (rule 82). Serving is never refused for it.

use std::cell::Cell;
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_p_serve::MAX_INFLIGHT;
use shekyl_runtime::{runtime_with_thread_hooks, Pool, RuntimeBudget, ThreadHooks, ThreadName};
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

// Set by the start hook, cleared by the stop hook. A thread that exits
// — shutdown, or Tokio retiring an idle blocking thread — leaves the
// gauge only when this is set, so a thread that was lowered is not
// subtracted and a stop without a start cannot wrap the count.
// `thread_local!` does not take a doc comment.
std::thread_local! {
    static THIS_THREAD_NOT_LOWERED: Cell<bool> = const { Cell::new(false) };
}

/// The one warning a host logs when lowering fails.
///
/// The failure-path test counts this text. One host logs it once; a
/// second wording would be a second alarm.
const SERVING_PRIORITY_REFUSAL: &str = "the OS refused to lower a serving thread's CPU priority; \
     it serves at normal priority, and the count of such threads is on the serving status";

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
/// The start hook adds a thread whose call failed. The stop hook removes
/// it when that thread exits, including when the runtime retires an idle
/// blocking thread and starts another for the next hop. The count is
/// therefore the live set, at most [`SERVING_WORKERS`] plus
/// [`SERVING_BLOCKING`], and zero is the expected reading on every
/// supported platform. It is the OS call's result for the threads that
/// are still running, and nothing more: it does not say whether the
/// lowered priority yields CPU to the daemon, which depends on the two
/// processes being in one scheduling group (§9.8, the confirming run).
#[derive(Clone, Debug, Default)]
pub struct PriorityFailures(Arc<AtomicU32>);

impl PriorityFailures {
    /// A fresh counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serving threads running at normal priority because lowering failed.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    /// This thread is one of the live set.
    fn retain(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// This thread has exited. A release without a retain leaves the
    /// gauge where it is: wrapping would publish a huge count for a set
    /// that got smaller.
    fn release(&self) {
        // `Err` is a release that found zero. The gauge stays: wrapping
        // would publish a huge count for a set that got smaller. The
        // returned value is the reading the update observed.
        match self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_sub(1)
            }) {
            Ok(previous) => debug_assert!(previous > 0),
            Err(already_zero) => debug_assert_eq!(already_zero, 0),
        }
    }

    /// The start and stop hooks that keep [`Self::count`] equal to the
    /// threads still at normal priority.
    ///
    /// The pair is one value. The start hook cannot be installed without
    /// the stop hook that removes the same thread, so a retired blocking
    /// thread cannot stay in the count.
    fn thread_hooks(
        &self,
        lower: impl Fn() -> Result<(), NotLowered> + Send + Sync + 'static,
    ) -> ThreadHooks {
        let retained = self.clone();
        let released = self.clone();
        // One warning per host: the first thread that fails says so, with
        // the cause; the rest only count. A persona whose platform refuses
        // on every thread would otherwise log once per thread per start.
        let warned = Arc::new(AtomicBool::new(false));
        ThreadHooks::pair(
            move || {
                if let Err(cause) = lower() {
                    THIS_THREAD_NOT_LOWERED.with(|slot| slot.set(true));
                    retained.retain();
                    if !warned.swap(true, Ordering::Relaxed) {
                        tracing::warn!(%cause, "{SERVING_PRIORITY_REFUSAL}");
                    }
                }
            },
            move || {
                if THIS_THREAD_NOT_LOWERED.with(|slot| slot.replace(false)) {
                    released.release();
                }
            },
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
    /// is counted once, one warning is logged, and an endpoint bound on
    /// that runtime still answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_lowering_is_counted_once_per_thread_and_serving_goes_on() {
        let _warning = refusal_warning_lock().await;
        let warnings = refusal_warning_log();
        // A sibling test can register this callsite with no subscriber
        // first. Interest is cached process-wide from that first hit, so
        // recompute it against the subscriber installed above before any
        // serving thread starts.
        tracing::callsite::rebuild_interest_cache();
        let warnings_before = refusal_warnings(&warnings);

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
        // The count is the threads still up whose call failed, so it
        // cannot pass the budget. Threads start as work arrives, so the
        // count is at least the threads that took work.
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

        let warnings_after = refusal_warnings(&warnings);
        assert_eq!(
            warnings_after - warnings_before,
            1,
            "one warning for the host, not one per thread"
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
        let _warning = refusal_warning_lock().await;
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

    /// The two tests that refuse lowering both log the one warning into
    /// the process-wide subscriber. They hold this for the whole test so
    /// one test's warning is not the other's extra line. A tokio mutex,
    /// because the guard stays across the awaits that run the runtime.
    async fn refusal_warning_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
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

    /// Process-wide, because a worker thread does not see a thread-local
    /// subscriber. Installed once: `set_global_default` has no uninstall.
    fn refusal_warning_log() -> Arc<Mutex<Vec<u8>>> {
        use std::io::Write;
        use std::sync::OnceLock;

        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);

        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("warning log").extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
            type Writer = Self;

            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
        LOG.get_or_init(|| {
            let sink = SharedBuf::default();
            let buf = Arc::clone(&sink.0);
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(sink)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("this test process has no other global tracing subscriber");
            buf
        })
        .clone()
    }

    fn refusal_warnings(log: &Mutex<Vec<u8>>) -> usize {
        let text = log.lock().expect("warning log");
        String::from_utf8_lossy(&text)
            .matches(SERVING_PRIORITY_REFUSAL)
            .count()
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
