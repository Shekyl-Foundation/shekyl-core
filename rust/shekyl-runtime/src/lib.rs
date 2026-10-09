// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one constructor for a daemon Tokio runtime (D5).
//!
//! The caller passes a [`RuntimeBudget`]. This crate does not contain a
//! worker count, a blocking cap, a deadline, or a socket. The I/O driver
//! and the time driver are enabled, so the runtime can host sockets and
//! deadlines.
//!
//! The pool's row lives on [`shekyl_thread_ledger`]. A dedicated thread is
//! spawned there, not here: that crate has no Tokio dependency, and the
//! timing engine depends on it alone. The row this constructor records
//! has no join. Daemon-RPC, Tor-control, and the transport each call this
//! constructor. Their budgets are the caller's, labelled unmeasured until
//! the D5 pin names them. This crate holds neither number.

#![deny(unsafe_code)]

use std::fmt;
use std::io;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use shekyl_thread_ledger::{LedgerId, RuntimeRow};
use tokio::runtime::{Builder, Runtime};

pub use shekyl_thread_ledger::{RuntimeBudget, ThreadName, ThreadNameError};

/// One live runtime.
///
/// [`shutdown`](Self::shutdown) is how a daemon stops it: the wait for a
/// blocking task is bounded by the timeout the caller passes. Drop is the
/// unbounded fallback. Tokio waits forever for a `spawn_blocking` task that
/// is still running, and it panics if that wait happens inside an
/// asynchronous context (`Cannot drop a runtime in a context where blocking
/// is not allowed`). A `Pool` is therefore never dropped from inside a task,
/// including a task on this pool. Call `shutdown` from outside the pool.
///
/// Fields drop in declaration order, so the runtime is first and the ledger
/// row covers that shutdown. The row has no join of its own.
#[must_use = "call shutdown from outside the pool; drop waits forever for a blocking task"]
pub struct Pool {
    runtime: Runtime,
    row: RuntimeRow,
}

impl Pool {
    /// The ledger row of this pool, for the life of the pool.
    pub fn ledger_id(&self) -> LedgerId {
        self.row.id()
    }

    /// Stop the workers and wait at most `timeout` for blocking tasks.
    ///
    /// The ledger row leaves after that wait. `timeout` is the caller's
    /// bound. This crate does not contain one. A call from inside a task
    /// panics for the same reason drop does: the wait is not allowed in an
    /// asynchronous context.
    ///
    /// A blocking task still running when the wait ends keeps its OS
    /// thread. That thread is detached, and the row is already gone, so
    /// the ledger undercounts until the thread exits. At process exit that
    /// does not matter. A pool shut down and replaced while the daemon
    /// keeps running is a different case: the replacement's total omits
    /// those detached threads.
    pub fn shutdown(self, timeout: Duration) {
        let Pool { runtime, row } = self;
        runtime.shutdown_timeout(timeout);
        drop(row);
    }
}

impl Deref for Pool {
    type Target = Runtime;

    fn deref(&self) -> &Runtime {
        &self.runtime
    }
}

/// What every thread of a runtime runs once, as it starts and before it
/// takes work — worker and blocking threads alike.
///
/// The one use today is the serving runtime's threads lowering their own
/// CPU priority (`SH-3`, `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.8). This
/// crate does not know what the hook does; it only guarantees where it
/// runs. [`ThreadStart::none`] is the ordinary runtime.
#[derive(Clone, Default)]
pub struct ThreadStart(Option<Arc<dyn Fn() + Send + Sync>>);

impl ThreadStart {
    /// No hook: threads start as Tokio starts them.
    #[must_use]
    pub fn none() -> Self {
        Self(None)
    }

    /// Run `hook` on every thread of the runtime as it starts.
    #[must_use]
    pub fn new(hook: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(hook)))
    }
}

impl fmt::Debug for ThreadStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "ThreadStart(hook)"
        } else {
            "ThreadStart(none)"
        })
    }
}

/// Build one multi-thread runtime and record its budget.
///
/// `name` is the OS thread name and the ledger label. The ledger row
/// lives as long as the returned [`Pool`], including the workers'
/// shutdown. A name that is empty or contains a NUL is a [`ThreadName`]
/// error, so this function never builds a runtime for one. `on_thread_start`
/// runs on each of the runtime's threads before it takes work.
pub fn runtime(
    budget: RuntimeBudget,
    name: &ThreadName,
    on_thread_start: ThreadStart,
) -> io::Result<Pool> {
    let row = shekyl_thread_ledger::record_runtime(name, budget);
    let mut builder = Builder::new_multi_thread();
    builder
        .worker_threads(budget.workers.get())
        .max_blocking_threads(budget.blocking.get())
        .thread_name(name.as_str())
        .enable_io()
        .enable_time();
    if let Some(hook) = on_thread_start.0 {
        builder.on_thread_start(move || hook());
    }
    let runtime = builder.build()?;
    Ok(Pool { runtime, row })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::num::NonZeroUsize;
    use std::time::{Duration, Instant};

    use shekyl_thread_ledger::{ledger, RowKind};

    use super::{runtime, RuntimeBudget, ThreadName, ThreadStart};

    #[test]
    fn the_thread_start_hook_runs_on_every_worker_and_blocking_thread() {
        use std::collections::HashSet;
        use std::sync::Mutex;
        use std::thread::ThreadId;

        let seen: std::sync::Arc<Mutex<HashSet<ThreadId>>> = Default::default();
        let hook_seen = std::sync::Arc::clone(&seen);
        let pool = runtime(
            budget(2, 2),
            &thread_name("sk-rt-hook"),
            ThreadStart::new(move || {
                hook_seen
                    .lock()
                    .expect("set")
                    .insert(std::thread::current().id());
            }),
        )
        .expect("runtime");
        // Threads report their own ids from inside a task and a blocking
        // task; every one of them must have run the hook first.
        let (tx, rx) = std::sync::mpsc::channel();
        pool.block_on(async {
            let mut tasks = Vec::new();
            for _ in 0..4 {
                let worker_tx = tx.clone();
                tasks.push(tokio::spawn(async move {
                    worker_tx.send(std::thread::current().id()).expect("report");
                }));
                let blocking_tx = tx.clone();
                tasks.push(tokio::task::spawn_blocking(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    blocking_tx
                        .send(std::thread::current().id())
                        .expect("report");
                }));
            }
            for task in tasks {
                task.await.expect("task");
            }
        });
        drop(tx);
        let working: HashSet<ThreadId> = rx.iter().collect();
        let hooked = seen.lock().expect("set").clone();
        assert!(!working.is_empty());
        assert!(
            working.is_subset(&hooked),
            "a thread took work without running the start hook: {working:?} vs {hooked:?}"
        );
        drop(pool);
    }

    fn budget(workers: usize, blocking: usize) -> RuntimeBudget {
        RuntimeBudget {
            workers: NonZeroUsize::new(workers).expect("worker count"),
            blocking: NonZeroUsize::new(blocking).expect("blocking cap"),
        }
    }

    fn thread_name(text: &str) -> ThreadName {
        ThreadName::new(text).expect("thread name")
    }

    #[test]
    fn the_budget_is_recorded_and_built() {
        let pool = runtime(
            budget(2, 3),
            &thread_name("sk-rt-budget"),
            ThreadStart::none(),
        )
        .expect("runtime");
        assert_eq!(pool.metrics().num_workers(), 2);
        let id = pool.ledger_id();
        let row = ledger().into_iter().find(|row| row.id == id).expect("row");
        assert_eq!(row.name.as_str(), "sk-rt-budget");
        assert_eq!(row.kind, RowKind::Runtime(budget(2, 3)));
        let name = pool
            .block_on(async {
                tokio::spawn(async { std::thread::current().name().map(str::to_owned) }).await
            })
            .expect("worker");
        assert_eq!(name.as_deref(), Some("sk-rt-budget"));
        drop(pool);
        assert!(ledger().iter().all(|row| row.id != id));
    }

    #[test]
    fn one_worker_is_one_thread() {
        let pool =
            runtime(budget(1, 1), &thread_name("sk-rt-one"), ThreadStart::none()).expect("runtime");
        assert_eq!(pool.metrics().num_workers(), 1);
        let ids = pool.block_on(async {
            let mut tasks = Vec::new();
            for _ in 0..4 {
                tasks.push(tokio::spawn(async { std::thread::current().id() }));
            }
            let mut out = Vec::new();
            for task in tasks {
                out.push(task.await.expect("worker"));
            }
            out
        });
        let distinct: HashSet<_> = ids.iter().collect();
        assert_eq!(distinct.len(), 1);
    }

    #[test]
    fn shutdown_returns_while_a_blocking_task_is_still_running() {
        let pool = runtime(
            budget(1, 1),
            &thread_name("sk-rt-stop"),
            ThreadStart::none(),
        )
        .expect("runtime");
        let id = pool.ledger_id();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        pool.block_on(async move {
            tokio::task::spawn_blocking(move || {
                started_tx.send(()).expect("test thread");
                std::thread::sleep(Duration::from_secs(5));
            });
        });
        started_rx.recv().expect("blocking task started");
        let began = Instant::now();
        pool.shutdown(Duration::from_millis(50));
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "shutdown waited for the blocking task"
        );
        assert!(ledger().iter().all(|row| row.id != id));
    }
}
