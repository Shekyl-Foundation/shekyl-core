// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The process ledger of thread budgets (D5).
//!
//! This crate does not build a Tokio runtime and does not open a socket.
//! [`spawn_dedicated`] starts one OS thread and returns a [`DedicatedThread`],
//! which joins that thread before the row leaves. A Tokio pool is recorded
//! with [`record_runtime`] by `shekyl-runtime`, which keeps the [`RuntimeRow`]
//! inside the pool. A runtime row has no join. A socketless executor is
//! recorded with [`record_executor`]: [`ExecutorBudget`] names its worker
//! count and has no blocking cap, and [`ExecutorRow`] does not spawn or join.
//! The timing engine depends on this crate and does not gain a runtime by
//! doing so.
//!
//! Names are labels. Two rows may share a name. [`LedgerId`] is the identity.
//! A name is a [`ThreadName`]: non-empty, and no interior NUL.
//!
//! The daemon prints [`report`] once, before the p2p loop, after every
//! runtime it builds has been recorded here.

#![deny(unsafe_code)]

use std::fmt;
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

/// Why [`ThreadName::new`] refused a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadNameError {
    /// The string was empty.
    Empty,
    /// The string contained a `NUL` byte.
    InteriorNul,
}

impl fmt::Display for ThreadNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreadNameError::Empty => formatter.write_str("a thread name is empty"),
            ThreadNameError::InteriorNul => {
                formatter.write_str("a thread name contains a NUL byte")
            }
        }
    }
}

impl std::error::Error for ThreadNameError {}

/// OS thread name and ledger label.
///
/// Empty is refused because a row with no name is not a row. An interior
/// NUL is refused because [`std::thread::Builder`] panics on one, and that
/// panic would otherwise land after the row had been inserted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadName(String);

impl ThreadName {
    /// Refuse an empty string and a string that contains a NUL byte.
    pub fn new(name: &str) -> Result<Self, ThreadNameError> {
        if name.is_empty() {
            return Err(ThreadNameError::Empty);
        }
        if name.as_bytes().contains(&0) {
            return Err(ThreadNameError::InteriorNul);
        }
        Ok(Self(name.to_owned()))
    }

    /// The name as the OS thread builder and the report see it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ThreadName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for ThreadName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

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

/// Threads of one executor that can block waiting for a post that same
/// executor has to run.
///
/// [`ExecutorBudget::above_floor`] adds one to this count. The extra thread
/// is what runs the post. Zero lanes is a floor of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockingLanes(usize);

impl BlockingLanes {
    /// `lanes` threads may sit blocked. The executor needs one more.
    #[must_use]
    pub const fn new(lanes: usize) -> Self {
        Self(lanes)
    }

    /// The lane count the caller passed.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Why [`ExecutorBudget::above_floor`] refused the worker count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorBudgetError {
    /// `lanes + 1` does not fit in `usize`.
    FloorOverflow(BlockingLanes),
    /// `workers` is below one more than the blocking lanes.
    BelowFloor {
        /// The lanes the caller named.
        lanes: BlockingLanes,
        /// The worker count the caller asked for.
        workers: usize,
        /// One more than `lanes`.
        floor: usize,
    },
}

impl fmt::Display for ExecutorBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FloorOverflow(lanes) => write!(
                formatter,
                "executor floor overflows usize at {} blocking lanes",
                lanes.get()
            ),
            Self::BelowFloor {
                lanes,
                workers,
                floor,
            } => write!(
                formatter,
                "executor workers {workers} are below the floor {floor} for {} blocking lanes",
                lanes.get()
            ),
        }
    }
}

impl std::error::Error for ExecutorBudgetError {}

/// Worker threads of one socketless executor.
///
/// There is no Tokio blocking pool on this budget. The ledger counts
/// `workers` once. [`record_executor`] inserts that row and does not spawn
/// or join the threads: the executor owns their lifetime, the way a Tokio
/// runtime owns its workers under [`RuntimeRow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorBudget {
    workers: NonZeroUsize,
}

impl ExecutorBudget {
    /// Accept `workers` when it is at least one more than `lanes`.
    ///
    /// A smaller pool leaves every thread blocked on a post the pool itself
    /// would have to run. `lanes` of zero still requires one worker.
    pub fn above_floor(lanes: BlockingLanes, workers: usize) -> Result<Self, ExecutorBudgetError> {
        let Some(floor) = lanes.get().checked_add(1) else {
            return Err(ExecutorBudgetError::FloorOverflow(lanes));
        };
        if workers < floor {
            return Err(ExecutorBudgetError::BelowFloor {
                lanes,
                workers,
                floor,
            });
        }
        let workers = NonZeroUsize::new(workers).expect("the floor is at least one worker");
        Ok(Self { workers })
    }

    /// The worker count this budget contributes.
    #[must_use]
    pub const fn workers(self) -> NonZeroUsize {
        self.workers
    }
}

/// What one row contributes to the process budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// A Tokio runtime whose caps the caller named.
    Runtime(RuntimeBudget),
    /// One OS thread and no blocking pool. [`spawn_dedicated`] owns the join.
    DedicatedThread,
    /// A socketless executor. Workers only. No join on this row.
    Executor(ExecutorBudget),
}

/// Order of two budgets that share a name. A dedicated thread comes first,
/// then an executor with fewer workers, then a runtime with fewer workers,
/// then a runtime with a smaller blocking cap. [`LedgerId`] is the tie-break
/// after this.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BudgetOrder {
    Dedicated,
    Executor {
        workers: NonZeroUsize,
    },
    Runtime {
        workers: NonZeroUsize,
        blocking: NonZeroUsize,
    },
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
            RowKind::Executor(budget) => budget.workers().get(),
        }
    }

    fn budget_order(self) -> BudgetOrder {
        match self {
            RowKind::DedicatedThread => BudgetOrder::Dedicated,
            RowKind::Executor(budget) => BudgetOrder::Executor {
                workers: budget.workers(),
            },
            RowKind::Runtime(RuntimeBudget { workers, blocking }) => {
                BudgetOrder::Runtime { workers, blocking }
            }
        }
    }
}

/// One row as observed by a reader. The owner is what keeps it alive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRow {
    /// Identity. Stable for the life of the owner.
    pub id: LedgerId,
    /// OS thread name, and the label [`report`] prints.
    pub name: ThreadName,
    /// Which budget this row is.
    pub kind: RowKind,
}

struct StoredRow {
    id: LedgerId,
    name: ThreadName,
    kind: RowKind,
}

enum DedicatedState {
    /// The row is on the ledger. The OS thread has not been spawned, or
    /// spawning it has not returned.
    Reserved { id: LedgerId },
    /// The row is on the ledger and this value owns the thread.
    Live {
        id: LedgerId,
        thread: JoinHandle<()>,
    },
    /// The thread has been joined, or the reservation was dropped, and the
    /// row has been removed.
    Finished,
}

/// One OS thread and its ledger row.
///
/// [`join`](Self::join) takes `&mut self`, so a second caller cannot
/// observe the thread while the first join is still in progress. Drop
/// joins too. The row leaves after the thread has been joined.
#[must_use = "dropping the thread joins it and removes its ledger row"]
pub struct DedicatedThread {
    state: DedicatedState,
}

/// Removes a row when dropped, including when [`JoinHandle::join`] unwinds.
struct RemoveAfterJoin(Option<LedgerId>);

impl Drop for RemoveAfterJoin {
    fn drop(&mut self) {
        if let Some(id) = self.0.take() {
            remove(id);
        }
    }
}

impl DedicatedThread {
    fn reserve(id: LedgerId) -> Self {
        Self {
            state: DedicatedState::Reserved { id },
        }
    }

    fn attach(&mut self, thread: JoinHandle<()>) {
        let DedicatedState::Reserved { id } =
            std::mem::replace(&mut self.state, DedicatedState::Finished)
        else {
            unreachable!("a dedicated thread is attached once, from the reserved row");
        };
        self.state = DedicatedState::Live { id, thread };
    }

    /// The row, while this thread still holds it.
    pub fn id(&self) -> Option<LedgerId> {
        match self.state {
            DedicatedState::Reserved { id } | DedicatedState::Live { id, .. } => Some(id),
            DedicatedState::Finished => None,
        }
    }

    /// Join the thread, then remove the row.
    ///
    /// A panic in the thread is the `Err` this returns. A second call
    /// returns `Ok(())`: the first call is the one that reports the panic.
    /// Drop calls this and ignores that result.
    pub fn join(&mut self) -> std::thread::Result<()> {
        match std::mem::replace(&mut self.state, DedicatedState::Finished) {
            DedicatedState::Finished => Ok(()),
            DedicatedState::Reserved { id } => {
                remove(id);
                Ok(())
            }
            DedicatedState::Live { id, thread } => {
                let removal = RemoveAfterJoin(Some(id));
                let joined = thread.join();
                drop(removal);
                joined
            }
        }
    }
}

impl Drop for DedicatedThread {
    fn drop(&mut self) {
        drop(self.join());
    }
}

/// The ledger row of one Tokio runtime.
///
/// This value does not own the runtime and has no join. Dropping it
/// removes the row. The pool in `shekyl-runtime` stores the runtime
/// before this row, so the workers shut down first. This crate has no
/// Tokio type; that field order is what keeps the shutdown inside the row.
#[must_use = "dropping the row removes it from the ledger"]
pub struct RuntimeRow {
    id: LedgerId,
}

impl RuntimeRow {
    /// The row, for the life of this value.
    pub fn id(&self) -> LedgerId {
        self.id
    }
}

impl Drop for RuntimeRow {
    fn drop(&mut self) {
        remove(self.id);
    }
}

/// The ledger row of one socketless executor.
///
/// This value does not own the threads and has no join. Dropping it removes
/// the row. The executor joins its own threads; recording them again as
/// [`DedicatedThread`] rows would count each worker twice.
#[must_use = "dropping the row removes it from the ledger"]
pub struct ExecutorRow {
    id: LedgerId,
}

impl ExecutorRow {
    /// The row, for the life of this value.
    pub fn id(&self) -> LedgerId {
        self.id
    }
}

impl Drop for ExecutorRow {
    fn drop(&mut self) {
        remove(self.id);
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static LEDGER: Mutex<Vec<StoredRow>> = Mutex::new(Vec::new());

fn rows() -> MutexGuard<'static, Vec<StoredRow>> {
    LEDGER.lock().unwrap_or_else(PoisonError::into_inner)
}

fn insert(name: &ThreadName, kind: RowKind) -> LedgerId {
    let id = LedgerId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
    rows().push(StoredRow {
        id,
        name: name.clone(),
        kind,
    });
    id
}

fn remove(id: LedgerId) {
    rows().retain(|row| row.id != id);
}

/// Spawn one dedicated thread and record it.
///
/// `name` is the OS thread name and the ledger label. The row is reserved
/// before [`std::thread::Builder::spawn`] runs, so a failure or a panic
/// from the builder drops the reservation and the row leaves. The returned
/// thread joins the worker before the row leaves.
pub fn spawn_dedicated(
    name: &ThreadName,
    body: impl FnOnce() + Send + 'static,
) -> io::Result<DedicatedThread> {
    let mut dedicated = DedicatedThread::reserve(insert(name, RowKind::DedicatedThread));
    let thread = std::thread::Builder::new()
        .name(name.as_str().to_owned())
        .spawn(body)?;
    dedicated.attach(thread);
    Ok(dedicated)
}

/// Record a Tokio runtime's budget.
///
/// `shekyl-runtime::runtime` is the constructor that calls this and stores
/// the row in the pool. The row does not own the runtime. Dropping it
/// removes the budget. There is no join.
pub fn record_runtime(name: &ThreadName, budget: RuntimeBudget) -> RuntimeRow {
    RuntimeRow {
        id: insert(name, RowKind::Runtime(budget)),
    }
}

/// Record a socketless executor's worker count.
///
/// The caller has already built the budget with [`ExecutorBudget::above_floor`].
/// This function does not spawn threads and does not check the floor again.
/// Dropping the returned row removes the budget. There is no join.
pub fn record_executor(name: &ThreadName, budget: ExecutorBudget) -> ExecutorRow {
    ExecutorRow {
        id: insert(name, RowKind::Executor(budget)),
    }
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
/// Rows are ordered by name, then by budget (a dedicated thread, then a
/// runtime's worker count, then its blocking cap), then by [`LedgerId`].
/// Registration order decides only when the name and the budget are the
/// same. An empty ledger is `thread budget: none; total 0`.
pub fn report() -> String {
    format_report(&ledger())
}

fn sort_rows(rows: &mut [LedgerRow]) {
    rows.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.kind.budget_order().cmp(&right.kind.budget_order()))
            .then(left.id.cmp(&right.id))
    });
}

fn format_report(rows: &[LedgerRow]) -> String {
    if rows.is_empty() {
        return "thread budget: none; total 0".to_owned();
    }
    let mut ordered = rows.to_vec();
    sort_rows(&mut ordered);
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
            RowKind::Executor(budget) => {
                format!("{} executor workers={}", self.name, budget.workers())
            }
            RowKind::Runtime(RuntimeBudget { workers, blocking }) => {
                format!("{} workers={workers} blocking={blocking}", self.name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;

    fn budget(workers: usize, blocking: usize) -> RuntimeBudget {
        RuntimeBudget {
            workers: NonZeroUsize::new(workers).expect("worker count"),
            blocking: NonZeroUsize::new(blocking).expect("blocking cap"),
        }
    }

    fn thread_name(text: &str) -> ThreadName {
        ThreadName::new(text).expect("thread name")
    }

    fn row(id: u64, name: &str, kind: RowKind) -> LedgerRow {
        LedgerRow {
            id: LedgerId(id),
            name: thread_name(name),
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
    fn a_shared_name_orders_by_budget_then_id() {
        let mut rows = vec![
            row(2, "same", RowKind::Runtime(budget(4, 1))),
            row(1, "same", RowKind::DedicatedThread),
            row(4, "same", RowKind::Runtime(budget(4, 1))),
            row(3, "same", RowKind::Runtime(budget(1, 9))),
        ];
        sort_rows(&mut rows);
        assert_eq!(
            rows.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![LedgerId(1), LedgerId(3), LedgerId(2), LedgerId(4)]
        );
        let total = DEDICATED_THREAD_COUNT + (1 + 9) + (4 + 1) + (4 + 1);
        assert_eq!(
            format_report(&rows),
            format!(
                "thread budget: same dedicated, same workers=1 blocking=9, same workers=4 blocking=1, same workers=4 blocking=1; total {total}"
            )
        );
    }

    #[test]
    fn an_empty_ledger_reports_no_rows() {
        assert_eq!(format_report(&[]), "thread budget: none; total 0");
    }

    #[test]
    fn an_empty_name_is_refused() {
        assert_eq!(ThreadName::new("").unwrap_err(), ThreadNameError::Empty);
    }

    #[test]
    fn a_name_with_a_nul_is_refused_and_is_not_a_row() {
        let text = "sk-ledger-\0nul";
        assert_eq!(
            ThreadName::new(text).unwrap_err(),
            ThreadNameError::InteriorNul
        );
        assert!(ledger().iter().all(|entry| entry.name.as_str() != text));
    }

    #[test]
    fn a_dedicated_thread_is_named_and_joined_with_its_row() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut guard = spawn_dedicated(&thread_name("sk-ledger-name"), move || {
            tx.send(std::thread::current().name().map(str::to_owned))
                .expect("test thread");
        })
        .expect("spawn");
        let id = guard.id().expect("row");
        let found = ledger()
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("recorded");
        assert_eq!(found.name.as_str(), "sk-ledger-name");
        assert_eq!(found.kind, RowKind::DedicatedThread);
        assert_eq!(found.kind.threads(), DEDICATED_THREAD_COUNT);
        assert_eq!(rx.recv().expect("name").as_deref(), Some("sk-ledger-name"));
        assert!(guard.join().is_ok());
        assert!(guard.id().is_none());
        assert!(guard.join().is_ok());
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    fn joining_a_panicked_thread_returns_the_panic() {
        let mut guard = spawn_dedicated(&thread_name("sk-ledger-panic"), || {
            panic!("ledger worker failed");
        })
        .expect("spawn");
        let id = guard.id().expect("row");
        assert!(guard.join().is_err());
        assert!(guard.id().is_none());
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    fn dropping_the_thread_removes_the_row() {
        let guard = spawn_dedicated(&thread_name("sk-ledger-drop"), || {}).expect("spawn");
        let id = guard.id().expect("row");
        drop(guard);
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    fn the_same_name_is_two_rows() {
        let name = thread_name("sk-ledger-dup");
        let first = spawn_dedicated(&name, || {}).expect("first");
        let second = spawn_dedicated(&name, || {}).expect("second");
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
    fn an_executor_at_the_floor_counts_workers_and_leaves_on_drop() {
        let lanes = BlockingLanes::new(1);
        let budget = ExecutorBudget::above_floor(lanes, 2).expect("floor");
        assert_eq!(budget.workers().get(), 2);
        assert_eq!(
            ExecutorBudget::above_floor(lanes, 1).expect_err("below"),
            ExecutorBudgetError::BelowFloor {
                lanes,
                workers: 1,
                floor: 2,
            }
        );
        assert_eq!(
            ExecutorBudget::above_floor(BlockingLanes::new(0), 1)
                .expect("one worker")
                .workers()
                .get(),
            1
        );
        assert_eq!(
            ExecutorBudget::above_floor(BlockingLanes::new(usize::MAX), 1).expect_err("overflow"),
            ExecutorBudgetError::FloorOverflow(BlockingLanes::new(usize::MAX))
        );

        let name = thread_name("sk-ledger-executor");
        let row = record_executor(&name, budget);
        let id = row.id();
        let found = ledger()
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("recorded");
        assert_eq!(found.kind, RowKind::Executor(budget));
        assert_eq!(found.kind.threads(), 2);
        drop(row);
        assert!(ledger().iter().all(|entry| entry.id != id));
    }

    #[test]
    fn a_shared_name_orders_a_dedicated_thread_then_an_executor_then_a_runtime() {
        let mut rows = vec![
            row(3, "same", RowKind::Runtime(budget(1, 1))),
            row(
                2,
                "same",
                RowKind::Executor(
                    ExecutorBudget::above_floor(BlockingLanes::new(1), 2).expect("floor"),
                ),
            ),
            row(1, "same", RowKind::DedicatedThread),
        ];
        sort_rows(&mut rows);
        assert_eq!(
            rows.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![LedgerId(1), LedgerId(2), LedgerId(3)]
        );
        let executor_workers = 2;
        let total = DEDICATED_THREAD_COUNT + executor_workers + (1 + 1);
        assert_eq!(
            format_report(&rows),
            format!(
                "thread budget: same dedicated, same executor workers=2, same workers=1 blocking=1; total {total}"
            )
        );
    }

    #[test]
    fn a_runtime_row_records_both_caps_and_has_its_id_until_drop() {
        let name = thread_name("sk-ledger-rt");
        let row = record_runtime(&name, budget(2, 3));
        let id = row.id();
        let found = ledger()
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("recorded");
        assert_eq!(found.kind, RowKind::Runtime(budget(2, 3)));
        assert_eq!(found.kind.threads(), 2 + 3);
        drop(row);
        assert!(ledger().iter().all(|entry| entry.id != id));
    }
}
