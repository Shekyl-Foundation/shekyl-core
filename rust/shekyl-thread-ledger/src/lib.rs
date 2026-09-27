// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The process ledger of thread budgets (D5).
//!
//! This crate does not build a Tokio runtime and does not open a socket.
//! [`spawn_dedicated`] starts one OS thread and holds its [`JoinHandle`] in
//! the guard, so the ledger row and the thread are one value. A Tokio pool
//! is recorded with [`record_runtime`] by `shekyl-runtime`, which keeps the
//! guard inside the pool. The timing engine depends on this crate and does
//! not gain a runtime by doing so.
//!
//! Names are labels. Two rows may share a name. [`LedgerId`] is the identity.
//!
//! The daemon prints [`report`] once every runtime it builds is recorded
//! here. Daemon-RPC and Tor-control still build their own, so that print is
//! not wired yet: a total taken before the move would omit those pools.

#![deny(unsafe_code)]

use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

/// Threads one dedicated thread contributes. It is one OS thread and it has
/// no Tokio blocking pool.
pub const DEDICATED_THREAD_COUNT: usize = 1;

/// Identity of one ledger row. Names are not unique; this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerId(u64);

/// Worker threads and the blocking-pool cap of one Tokio runtime.
///
/// Neither field has a default. The caller names both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeBudget {
    /// Async worker threads.
    pub workers: NonZeroUsize,
    /// Maximum threads `spawn_blocking` may add.
    pub blocking: NonZeroUsize,
}

/// What one row contributes to the process budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// A Tokio runtime whose caps the caller named.
    Runtime(RuntimeBudget),
    /// One OS thread and no blocking pool.
    DedicatedThread,
}

impl RowKind {
    /// Threads this row contributes.
    ///
    /// A runtime contributes its workers and its blocking cap. A dedicated
    /// thread contributes [`DEDICATED_THREAD_COUNT`].
    pub fn threads(self) -> usize {
        match self {
            RowKind::Runtime(RuntimeBudget { workers, blocking }) => workers
                .get()
                .checked_add(blocking.get())
                .expect("thread budget fits in usize"),
            RowKind::DedicatedThread => DEDICATED_THREAD_COUNT,
        }
    }
}

/// One row as observed by a reader. The guard is what keeps it alive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRow {
    /// Identity. Stable for the life of the guard.
    pub id: LedgerId,
    /// OS thread name, and the label [`report`] prints.
    pub name: String,
    /// Which budget this row is.
    pub kind: RowKind,
}

struct StoredRow {
    id: LedgerId,
    name: String,
    kind: RowKind,
}

struct GuardState {
    id: Option<LedgerId>,
    thread: Option<JoinHandle<()>>,
}

/// Keeps one row on the ledger.
///
/// Drop joins a dedicated thread this guard spawned, then removes the row.
/// A runtime guard has no thread. The pool in `shekyl-runtime` drops its
/// runtime first and this guard after, so the row covers the workers'
/// shutdown.
#[must_use = "dropping the guard joins a dedicated thread and removes its ledger row"]
pub struct RowGuard {
    state: Mutex<GuardState>,
}

impl RowGuard {
    fn live(id: LedgerId, thread: Option<JoinHandle<()>>) -> Self {
        Self {
            state: Mutex::new(GuardState {
                id: Some(id),
                thread,
            }),
        }
    }

    /// The row, while this guard still holds it.
    pub fn id(&self) -> Option<LedgerId> {
        self.lock().id
    }

    /// Join the dedicated thread, if this guard spawned one, then remove the row.
    ///
    /// A second call does nothing. Drop calls this.
    pub fn join(&self) {
        self.finish();
    }

    fn finish(&self) {
        let (thread, id) = {
            let mut state = self.lock();
            (state.thread.take(), state.id.take())
        };
        if let Some(thread) = thread {
            drop(thread.join());
        }
        if let Some(id) = id {
            remove(id);
        }
    }

    fn lock(&self) -> MutexGuard<'_, GuardState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for RowGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static LEDGER: Mutex<Vec<StoredRow>> = Mutex::new(Vec::new());

fn rows() -> MutexGuard<'static, Vec<StoredRow>> {
    LEDGER.lock().unwrap_or_else(PoisonError::into_inner)
}

fn require_name(name: &str) {
    assert!(!name.is_empty(), "a ledger row carries the thread's name");
}

fn insert(name: &str, kind: RowKind) -> LedgerId {
    let id = LedgerId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
    rows().push(StoredRow {
        id,
        name: name.to_owned(),
        kind,
    });
    id
}

fn remove(id: LedgerId) {
    rows().retain(|row| row.id != id);
}

/// Spawn one dedicated thread and record it.
///
/// `name` is the OS thread name and the ledger label. The row stays until
/// the guard is joined or dropped, and the join happens before the row
/// leaves.
///
/// # Panics
///
/// Panics if `name` is empty. The thread is not spawned in that case.
pub fn spawn_dedicated(name: &str, body: impl FnOnce() + Send + 'static) -> io::Result<RowGuard> {
    require_name(name);
    let id = insert(name, RowKind::DedicatedThread);
    match std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
    {
        Ok(handle) => Ok(RowGuard::live(id, Some(handle))),
        Err(err) => {
            remove(id);
            Err(err)
        }
    }
}

/// Record a Tokio runtime's budget.
///
/// `shekyl-runtime::runtime` is the constructor that calls this and stores
/// the guard in the pool. The guard does not own the runtime.
///
/// # Panics
///
/// Panics if `name` is empty.
pub fn record_runtime(name: &str, budget: RuntimeBudget) -> RowGuard {
    require_name(name);
    RowGuard::live(insert(name, RowKind::Runtime(budget)), None)
}

/// Live rows, in registration order.
pub fn ledger() -> Vec<LedgerRow> {
    rows()
        .iter()
        .map(|row| LedgerRow {
            id: row.id,
            name: row.name.clone(),
            kind: row.kind,
        })
        .collect()
}

/// One line: each row, then the total of [`RowKind::threads`].
///
/// Rows are ordered by name, then by [`LedgerId`], so the line does not
/// depend on which pool registered first. An empty ledger is
/// `thread budget: none; total 0`.
pub fn report() -> String {
    format_report(&ledger())
}

fn format_report(rows: &[LedgerRow]) -> String {
    if rows.is_empty() {
        return "thread budget: none; total 0".to_owned();
    }
    let mut ordered = rows.to_vec();
    ordered.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    let mut total = 0usize;
    for row in &ordered {
        total = total
            .checked_add(row.kind.threads())
            .expect("thread budget fits in usize");
    }
    let body = ordered
        .iter()
        .map(LedgerRow::label)
        .collect::<Vec<_>>()
        .join(", ");
    format!("thread budget: {body}; total {total}")
}

impl LedgerRow {
    fn label(&self) -> String {
        match self.kind {
            RowKind::DedicatedThread => format!("{} dedicated", self.name),
            RowKind::Runtime(RuntimeBudget { workers, blocking }) => {
                format!("{} workers={workers} blocking={blocking}", self.name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::mpsc;

    use super::*;

    fn budget(workers: usize, blocking: usize) -> RuntimeBudget {
        RuntimeBudget {
            workers: NonZeroUsize::new(workers).expect("worker count"),
            blocking: NonZeroUsize::new(blocking).expect("blocking cap"),
        }
    }

    fn row(id: u64, name: &str, kind: RowKind) -> LedgerRow {
        LedgerRow {
            id: LedgerId(id),
            name: name.to_owned(),
            kind,
        }
    }

    #[test]
    fn the_line_names_a_dedicated_thread_and_a_pool() {
        let rows = [
            row(2, "b-pool", RowKind::Runtime(budget(2, 3))),
            row(1, "a-thread", RowKind::DedicatedThread),
        ];
        let total = DEDICATED_THREAD_COUNT + 2 + 3;
        assert_eq!(
            format_report(&rows),
            format!(
                "thread budget: a-thread dedicated, b-pool workers=2 blocking=3; total {total}"
            )
        );
    }

    #[test]
    fn an_empty_ledger_reports_no_rows() {
        assert_eq!(format_report(&[]), "thread budget: none; total 0");
    }

    #[test]
    fn a_dedicated_thread_is_named_and_joined_with_its_row() {
        let (tx, rx) = mpsc::channel();
        let guard = spawn_dedicated("sk-ledger-name", move || {
            tx.send(std::thread::current().name().map(str::to_owned))
                .expect("test thread");
        })
        .expect("spawn");
        let id = guard.id().expect("row");
        let found = ledger()
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("recorded");
        assert_eq!(found.name, "sk-ledger-name");
        assert_eq!(found.kind, RowKind::DedicatedThread);
        assert_eq!(found.kind.threads(), DEDICATED_THREAD_COUNT);
        assert_eq!(rx.recv().expect("name").as_deref(), Some("sk-ledger-name"));
        guard.join();
        assert!(guard.id().is_none());
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    fn dropping_the_guard_removes_the_row() {
        let guard = spawn_dedicated("sk-ledger-drop", || {}).expect("spawn");
        let id = guard.id().expect("row");
        drop(guard);
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    fn the_same_name_is_two_rows() {
        let first = spawn_dedicated("sk-ledger-dup", || {}).expect("first");
        let second = spawn_dedicated("sk-ledger-dup", || {}).expect("second");
        let first_id = first.id().expect("first id");
        let second_id = second.id().expect("second id");
        assert_ne!(first_id, second_id);
        drop(first);
        let left: Vec<_> = ledger()
            .into_iter()
            .filter(|entry| entry.id == first_id || entry.id == second_id)
            .map(|entry| entry.id)
            .collect();
        assert_eq!(left, vec![second_id]);
        drop(second);
    }

    #[test]
    fn a_runtime_row_records_both_caps() {
        let guard = record_runtime("sk-ledger-rt", budget(2, 3));
        let id = guard.id().expect("row");
        let found = ledger()
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("recorded");
        assert_eq!(found.kind, RowKind::Runtime(budget(2, 3)));
        assert_eq!(found.kind.threads(), 2 + 3);
        drop(guard);
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    #[should_panic(expected = "a ledger row carries the thread's name")]
    fn a_dedicated_thread_without_a_name_is_not_spawned() {
        let _guard = spawn_dedicated("", || {});
    }

    #[test]
    #[should_panic(expected = "a ledger row carries the thread's name")]
    fn a_runtime_row_without_a_name_is_not_recorded() {
        let _guard = record_runtime("", budget(1, 1));
    }
}
