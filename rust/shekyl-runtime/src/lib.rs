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
//! call is not in the tree yet. Its blocking cap will be labelled
//! unmeasured until D6's measurement names it.

#![deny(unsafe_code)]

use std::io;
use std::ops::Deref;

use shekyl_thread_ledger::{LedgerId, RuntimeRow};
use tokio::runtime::{Builder, Runtime};

pub use shekyl_thread_ledger::{RuntimeBudget, ThreadName, ThreadNameError};

/// One live runtime. Dropping it shuts the workers down, then removes the
/// ledger row. Fields drop in declaration order, so the runtime is first.
/// The row has no join of its own.
#[must_use = "dropping the pool shuts the runtime down and removes its ledger row"]
pub struct Pool {
    runtime: Runtime,
    row: RuntimeRow,
}

impl Pool {
    /// The ledger row of this pool, for the life of the pool.
    pub fn ledger_id(&self) -> LedgerId {
        self.row.id()
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
}
