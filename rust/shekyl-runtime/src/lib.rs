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
//! has no join. Daemon-RPC, Tor-control, and the transport each call
//! [`runtime`]. Their budgets are the caller's, labelled unmeasured until
//! the D5 pin names them. This crate holds neither number.
//!
//! A runtime whose threads must do something as they start and as they
//! exit calls [`runtime_with_thread_hooks`] instead. The ordinary
//! constructor does not take a hook. The one caller is the serving
//! runtime (`SH-3`).

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
/// blocking task is bounded by the timeout the caller passes.
/// [`shutdown_background`](Self::shutdown_background) stops it without
/// waiting, and that call is safe from inside a task. Drop is the unbounded
/// fallback. Tokio waits forever for a `spawn_blocking` task that is still
/// running, and it panics if that wait happens inside an asynchronous
/// context (`Cannot drop a runtime in a context where blocking is not
/// allowed`). A `Pool` is therefore never dropped from inside a task,
/// including a task on this pool. Call `shutdown` from outside the pool, or
/// `shutdown_background` when the caller is inside a task and must not wait.
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
    /// bound. This crate does not contain one. A **non-zero** timeout from
    /// inside a task panics for the same reason drop does: the wait is not
    /// allowed in an asynchronous context. A zero timeout does not wait;
    /// that is [`Self::shutdown_background`].
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

    /// Stop the workers and return without waiting.
    ///
    /// Safe from inside a task. Tokio treats a zero timeout as "do not
    /// block" and returns before the check that refuses a blocking wait
    /// (`shutdown_timeout(Duration::ZERO)` is its `shutdown_background`).
    /// A blocking task still running keeps its OS thread, detached, and
    /// the ledger row drops immediately — the same undercount
    /// [`Self::shutdown`] documents when a wait expires.
    pub fn shutdown_background(self) {
        self.shutdown(Duration::ZERO);
    }
}

impl Deref for Pool {
    type Target = Runtime;

    fn deref(&self) -> &Runtime {
        &self.runtime
    }
}

/// What every thread of a runtime runs as it starts and as it exits.
///
/// Worker threads and blocking threads both. The start hook runs before
/// the thread takes work. The stop hook runs before the thread exits,
/// including when Tokio retires an idle blocking thread. The two are one
/// value: a start that records a thread has the exit that releases it.
/// [`Self::none`] is what [`runtime`] installs.
///
/// This crate does not know what the hooks do. The one caller is the
/// serving runtime, whose threads lower their own CPU priority and whose
/// failure count is the threads still in that state (`SH-3`).
#[derive(Clone, Default)]
pub struct ThreadHooks {
    on_start: Option<Arc<dyn Fn() + Send + Sync>>,
    on_stop: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ThreadHooks {
    /// No hooks: threads start and exit as Tokio starts and exits them.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Run `on_start` as each thread starts and `on_stop` as it exits.
    #[must_use]
    pub fn pair(
        on_start: impl Fn() + Send + Sync + 'static,
        on_stop: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Self {
            on_start: Some(Arc::new(on_start)),
            on_stop: Some(Arc::new(on_stop)),
        }
    }
}

impl fmt::Debug for ThreadHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.on_start.is_some() {
            "ThreadHooks(pair)"
        } else {
            "ThreadHooks(none)"
        })
    }
}

/// Build one multi-thread runtime and record its budget.
///
/// `name` is the OS thread name and the ledger label. The ledger row
/// lives as long as the returned [`Pool`], including the workers'
/// shutdown. A name that is empty or contains a NUL is a [`ThreadName`]
/// error, so this function never builds a runtime for one. Threads start
/// as Tokio starts them. A runtime that needs [`ThreadHooks`] calls
/// [`runtime_with_thread_hooks`].
pub fn runtime(budget: RuntimeBudget, name: &ThreadName) -> io::Result<Pool> {
    runtime_with_thread_hooks(budget, name, ThreadHooks::none())
}

/// [`runtime`] with hooks on every worker and blocking thread.
///
/// The start hook runs before the thread takes work. The stop hook runs
/// before the thread exits. [`ThreadHooks::none`] is [`runtime`].
pub fn runtime_with_thread_hooks(
    budget: RuntimeBudget,
    name: &ThreadName,
    hooks: ThreadHooks,
) -> io::Result<Pool> {
    let row = shekyl_thread_ledger::record_runtime(name, budget);
    let mut builder = Builder::new_multi_thread();
    builder
        .worker_threads(budget.workers.get())
        .max_blocking_threads(budget.blocking.get())
        .thread_name(name.as_str())
        .enable_io()
        .enable_time();
    let ThreadHooks { on_start, on_stop } = hooks;
    if let Some(hook) = on_start {
        builder.on_thread_start(move || hook());
    }
    if let Some(hook) = on_stop {
        builder.on_thread_stop(move || hook());
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

    use super::{runtime, runtime_with_thread_hooks, RuntimeBudget, ThreadHooks, ThreadName};

    #[test]
    fn thread_hooks_run_as_a_thread_starts_and_as_it_exits() {
        use std::sync::Mutex;
        use std::thread::ThreadId;

        let started: std::sync::Arc<Mutex<HashSet<ThreadId>>> = Default::default();
        let stopped: std::sync::Arc<Mutex<HashSet<ThreadId>>> = Default::default();
        let on_start = std::sync::Arc::clone(&started);
        let on_stop = std::sync::Arc::clone(&stopped);
        let pool = runtime_with_thread_hooks(
            budget(2, 2),
            &thread_name("sk-rt-hooks"),
            ThreadHooks::pair(
                move || {
                    on_start
                        .lock()
                        .expect("set")
                        .insert(std::thread::current().id());
                },
                move || {
                    on_stop
                        .lock()
                        .expect("set")
                        .insert(std::thread::current().id());
                },
            ),
        )
        .expect("runtime");
        // Threads report their own ids from inside a task and a blocking
        // task; every one of them must have run the start hook first.
        // Shutdown runs the stop hook, including on a blocking thread that
        // has already finished its task and is only waiting out its
        // keep-alive.
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
        let started = started.lock().expect("set").clone();
        assert!(!working.is_empty());
        assert!(
            working.is_subset(&started),
            "a thread took work without running the start hook: {working:?} vs {started:?}"
        );
        drop(pool);
        let stopped = stopped.lock().expect("set").clone();
        assert!(
            started.is_subset(&stopped),
            "a thread that started did not run the stop hook: {started:?} vs {stopped:?}"
        );
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
        let pool = runtime(budget(2, 3), &thread_name("sk-rt-budget")).expect("runtime");
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
        let pool = runtime(budget(1, 1), &thread_name("sk-rt-one")).expect("runtime");
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
        let pool = runtime(budget(1, 1), &thread_name("sk-rt-stop")).expect("runtime");
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

    /// A zero wait is the shutdown a task may call. The blocking hop keeps
    /// its thread; this task returns without joining it.
    #[test]
    fn shutdown_background_from_inside_a_task_returns_without_waiting() {
        let outer = runtime(budget(1, 1), &thread_name("sk-rt-outer")).expect("outer runtime");
        let inner = runtime(budget(1, 1), &thread_name("sk-rt-inner")).expect("inner runtime");
        let id = inner.ledger_id();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        inner.block_on(async move {
            tokio::task::spawn_blocking(move || {
                started_tx.send(()).expect("test thread");
                std::thread::sleep(Duration::from_millis(500));
            });
        });
        started_rx.recv().expect("blocking task started");
        let began = Instant::now();
        outer.block_on(async move {
            inner.shutdown_background();
        });
        assert!(
            began.elapsed() < Duration::from_millis(200),
            "shutdown_background waited for the blocking task"
        );
        assert!(ledger().iter().all(|row| row.id != id));
        drop(outer);
    }
}
