// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one constructor for a daemon runtime, and the ledger of every
//! pool it has built (D5).
//!
//! Tokio's multi-thread builder, with no worker count, starts one worker
//! per core, and with no blocking cap allows 512 blocking threads. Both
//! are defaults this crate refuses to leave implicit. The caller passes
//! [`Budget`]. This crate does not contain a count, a deadline, or a
//! socket.
//!
//! `net` and `time` are enabled so the runtime can host sockets and
//! deadlines. A dedicated thread has no blocking pool: it registers with
//! [`register_thread`], whose blocking count is 0. Tokio itself refuses
//! a blocking cap of 0, so a runtime's cap is at least one.
//!
//! The daemon-RPC and Tor-control call sites still build their own
//! runtimes. Moving them here is the follow-up. The clearnet connector
//! is the first caller that keeps a runtime, and it passes its blocking
//! cap labelled unmeasured until D6's measurement replaces that value.
//! The daemon prints [`report`] once at startup.

#![deny(unsafe_code)]

use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::runtime::{Builder, Runtime};

/// Worker threads and the blocking-pool cap for one runtime.
///
/// Neither field has a default. The caller names both, including a cap
/// that has not been measured yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Async worker threads. Tokio's per-core default is not used.
    pub workers: NonZeroUsize,
    /// Maximum threads `spawn_blocking` may add. Tokio's 512 is not used.
    pub blocking: NonZeroUsize,
}

/// One live pool. Dropping it removes the row from [`ledger`].
pub struct Pool {
    runtime: Runtime,
    id: u64,
}

impl std::ops::Deref for Pool {
    type Target = Runtime;

    fn deref(&self) -> &Runtime {
        &self.runtime
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        remove(self.id);
    }
}

/// A dedicated thread's row. Dropping it removes the row from [`ledger`].
pub struct Registration {
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        remove(self.id);
    }
}

/// One row of the ledger: the name, the worker threads, and the blocking cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolRecord {
    /// The name the pool's threads carry.
    pub name: String,
    /// Async workers, or 1 for a dedicated thread.
    pub workers: usize,
    /// Blocking-pool cap. 0 for a dedicated thread, which has none.
    pub blocking: usize,
}

struct Row {
    id: u64,
    name: String,
    workers: usize,
    blocking: usize,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static LEDGER: Mutex<Vec<Row>> = Mutex::new(Vec::new());

fn rows() -> std::sync::MutexGuard<'static, Vec<Row>> {
    LEDGER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn insert(name: &str, workers: usize, blocking: usize) -> u64 {
    assert!(!name.is_empty(), "a runtime's threads carry a name");
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    rows().push(Row {
        id,
        name: name.to_owned(),
        workers,
        blocking,
    });
    id
}

fn remove(id: u64) {
    rows().retain(|row| row.id != id);
}

/// Build one multi-thread runtime and record it.
///
/// The ledger row lives as long as the returned [`Pool`].
///
/// # Panics
///
/// Panics if `thread_name` is empty.
pub fn runtime(budget: Budget, thread_name: &str) -> io::Result<Pool> {
    assert!(!thread_name.is_empty(), "a runtime's threads carry a name");
    let runtime = Builder::new_multi_thread()
        .worker_threads(budget.workers.get())
        .max_blocking_threads(budget.blocking.get())
        .thread_name(thread_name)
        .enable_all()
        .build()?;
    let id = insert(thread_name, budget.workers.get(), budget.blocking.get());
    Ok(Pool { runtime, id })
}

/// Record a dedicated thread. It has one worker and no blocking pool.
///
/// # Panics
///
/// Panics if `thread_name` is empty.
pub fn register_thread(thread_name: &str) -> Registration {
    Registration {
        id: insert(thread_name, 1, 0),
    }
}

/// The live pools, in registration order.
pub fn ledger() -> Vec<PoolRecord> {
    rows()
        .iter()
        .map(|row| PoolRecord {
            name: row.name.clone(),
            workers: row.workers,
            blocking: row.blocking,
        })
        .collect()
}

/// Workers plus blocking caps, across every live pool.
pub fn total_threads() -> usize {
    rows().iter().map(|row| row.workers + row.blocking).sum()
}

/// One line: each pool, then the total. The daemon prints this once at startup.
pub fn report() -> String {
    let guard = rows();
    let mut records: Vec<_> = guard
        .iter()
        .map(|row| (row.name.clone(), row.workers, row.blocking))
        .collect();
    let total: usize = records
        .iter()
        .map(|(_, workers, blocking)| workers + blocking)
        .sum();
    records.sort_by(|a, b| a.0.cmp(&b.0));
    drop(guard);
    if records.is_empty() {
        return format!("thread budget: none; total {total}");
    }
    let body = records
        .iter()
        .map(|(name, workers, blocking)| format!("{name} workers={workers} blocking={blocking}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("thread budget: {body}; total {total}")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::num::NonZeroUsize;

    use super::{ledger, register_thread, report, runtime, Budget};

    fn budget(workers: usize, blocking: usize) -> Budget {
        Budget {
            workers: NonZeroUsize::new(workers).expect("workers"),
            blocking: NonZeroUsize::new(blocking).expect("blocking"),
        }
    }

    #[test]
    fn the_budget_is_recorded_and_built() {
        let pool = runtime(budget(2, 3), "sk-rt-budget").expect("runtime");
        assert_eq!(pool.metrics().num_workers(), 2);
        let row = ledger()
            .into_iter()
            .find(|row| row.name == "sk-rt-budget")
            .expect("row");
        assert_eq!(row.workers, 2);
        assert_eq!(row.blocking, 3);
        let name = pool
            .block_on(async {
                tokio::spawn(async { std::thread::current().name().map(str::to_owned) }).await
            })
            .expect("worker");
        assert_eq!(name.as_deref(), Some("sk-rt-budget"));
        drop(pool);
        assert!(ledger().iter().all(|row| row.name != "sk-rt-budget"));
    }

    #[test]
    fn one_worker_is_one_thread() {
        let pool = runtime(budget(1, 1), "sk-rt-one").expect("runtime");
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
    fn a_dedicated_thread_has_no_blocking_pool() {
        let registration = register_thread("sk-thread");
        let row = ledger()
            .into_iter()
            .find(|row| row.name == "sk-thread")
            .expect("row");
        assert_eq!(row.workers, 1);
        assert_eq!(row.blocking, 0);
        let line = report();
        assert!(line.contains("sk-thread workers=1 blocking=0"));
        assert!(line.contains("total "));
        drop(registration);
        assert!(ledger().iter().all(|row| row.name != "sk-thread"));
    }

    #[test]
    fn the_total_adds_workers_and_blocking_caps() {
        let first = runtime(budget(2, 3), "sk-rt-sum-a").expect("runtime");
        let second = register_thread("sk-rt-sum-b");
        let mine: usize = ledger()
            .iter()
            .filter(|row| row.name == "sk-rt-sum-a" || row.name == "sk-rt-sum-b")
            .map(|row| row.workers + row.blocking)
            .sum();
        assert_eq!(mine, 2 + 3 + 1);
        drop(first);
        drop(second);
    }

    #[test]
    #[should_panic(expected = "a runtime's threads carry a name")]
    fn a_runtime_without_a_name_is_not_built() {
        let _pool = runtime(budget(1, 1), "");
    }

    #[test]
    #[should_panic(expected = "a runtime's threads carry a name")]
    fn a_thread_without_a_name_is_not_recorded() {
        let _registration = register_thread("");
    }
}
