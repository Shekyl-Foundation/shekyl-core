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
//! has no join. Daemon-RPC and Tor-control still build their own runtimes.
//! The clearnet connector will be the first caller that keeps one. That
//! call is not in the tree yet. Its blocking cap and its shutdown timeout
//! are both labelled unmeasured until a measurement names them. This crate
//! holds neither number.

#![deny(unsafe_code)]

use std::io;
use std::ops::Deref;
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

/// Build one multi-thread runtime and record its budget.
///
/// `name` is the OS thread name and the ledger label. The ledger row
/// lives as long as the returned [`Pool`], including the workers'
/// shutdown. A name that is empty or contains a NUL is a [`ThreadName`]
/// error, so this function never builds a runtime for one.
pub fn runtime(budget: RuntimeBudget, name: &ThreadName) -> io::Result<Pool> {
    let row = shekyl_thread_ledger::record_runtime(name, budget);
    let runtime = Builder::new_multi_thread()
        .worker_threads(budget.workers.get())
        .max_blocking_threads(budget.blocking.get())
        .thread_name(name.as_str())
        .enable_io()
        .enable_time()
        .build()?;
    Ok(Pool { runtime, row })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::num::NonZeroUsize;
    use std::time::{Duration, Instant};

    use shekyl_thread_ledger::{ledger, RowKind};

    use super::{runtime, RuntimeBudget, ThreadName};

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
}
