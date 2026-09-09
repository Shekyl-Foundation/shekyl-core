// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`RefreshHandle`]: RAII cancel-on-drop wrapper around the async
//! refresh producer task.

use tokio_util::sync::CancellationToken;

use super::{RefreshOptions, RefreshProgress, RefreshSummary};
use crate::engine::error::RefreshError;

/// RAII handle to a refresh task spawned by
/// [`crate::engine::Engine::start_refresh`].
///
/// Cancellation is RAII: dropping the handle fires the
/// cancel token; the producer observes it at the next batch
/// boundary, returns `Err(Cancelled)`, and exits. The handle does
/// not block in `Drop` — the wind-down happens on the runtime that
/// owns the task.
///
/// Single-flight is enforced via [`crate::engine::refresh_slot::RefreshSlot`]: at most one
/// refresh task per `Engine<S>` exists at a time. A racing
/// `start_refresh` returns
/// [`crate::engine::RefreshError::AlreadyRunning`].
///
/// # Methods
///
/// - [`progress()`](Self::progress) — subscribe to per-batch
///   progress updates. Returns a [`tokio::sync::watch::Receiver`].
/// - [`cancel()`](Self::cancel) — fire the cancel token explicitly;
///   idempotent. Equivalent to dropping the handle, but lets the
///   caller continue to observe progress and `join()` the result.
/// - [`is_running()`](Self::is_running) — non-blocking check
///   whether the producer task has completed.
/// - [`join()`](Self::join) — async — await the terminal
///   [`RefreshSummary`] or [`RefreshError`]. Consumes the handle.
///
/// # Stage-4 invariance
///
/// `RefreshHandle`'s public surface — `progress()`, `cancel()`,
/// `is_running()`, `join()`, and `Drop` semantics — is invariant
/// across the Stage 4 actor cutover. Today, `start_refresh` takes
/// `Arc<RwLock<Self>>` and returns this type directly. After Stage
/// 4, `actor.ask(StartRefresh { opts }).send().await?` returns the
/// same `RefreshHandle`; the actor message-passing replaces the
/// shared-handle plumbing inside the type, but every method
/// signature on the handle stays bit-identical. Callers above the
/// engine binary boundary do not change.
///
/// This invariance is the contract that lets Branch 2 ship before
/// the actor cutover without forcing an API break later.
///
/// [`RefreshSlot`]: crate::engine::refresh_slot::RefreshSlot
pub struct RefreshHandle {
    /// Receive-end of the oneshot the producer task sends its
    /// terminal result on. `join()` consumes the handle and awaits
    /// this. `Some(_)` until `join()` is called; `None` after
    /// `join()` consumes it (handle is also consumed at that point,
    /// so this isn't really observable post-`join`, but the option
    /// shape keeps the field's lifetime story explicit).
    completion_rx: Option<tokio::sync::oneshot::Receiver<Result<RefreshSummary, RefreshError>>>,

    /// Cancel token shared with the producer task. `cancel()` and
    /// `Drop` both fire it. The token is internally `Arc`'d so
    /// dropping the handle's clone after firing does not abort the
    /// producer's observation; the token's `Arc` stays alive as
    /// long as the producer holds its clone.
    cancel_token: CancellationToken,

    /// Receive-end of the watch channel the producer publishes
    /// per-batch progress on. Cloned out of the handle by
    /// [`progress()`](Self::progress); the original lives here so
    /// callers that don't subscribe still keep the channel from
    /// closing prematurely on the producer's side.
    progress_rx: tokio::sync::watch::Receiver<RefreshProgress>,

    /// `JoinHandle` of the spawned producer task. Retained for two
    /// reasons:
    ///
    /// 1. Test wind-down assertions: corner-case unit tests
    ///    (commit 5) need to await the producer's exit to assert
    ///    that the slot was released, the progress channel closed,
    ///    etc. The `JoinHandle` is the only way to do that
    ///    deterministically.
    /// 2. Stage-4 transition reference: the actor cutover replaces
    ///    `tokio::spawn` with `kameo::actor::spawn`, which returns
    ///    an `ActorRef` that is observable similarly. Keeping the
    ///    field on the handle marks the migration site explicitly.
    ///
    /// Not used for primary synchronization — `join()` awaits
    /// `completion_rx`, not this. The producer task's lifecycle
    /// extends slightly past `completion_tx.send(...)` (slot guard
    /// drop, etc.); awaiting `JoinHandle` would observe a different
    /// completion semantic than the user-visible "the refresh is
    /// done" point.
    producer_join: tokio::task::JoinHandle<()>,

    /// Snapshot of the [`RefreshOptions`] the handle was started
    /// with. Retained for diagnostics (debug printing, test
    /// assertions) and Stage-4 actor-message reconstruction (the
    /// actor's `StartRefresh` message must carry the same opts so
    /// the actor can re-invoke the same loop logic). Not used by
    /// the methods on the handle today.
    opts: RefreshOptions,
}

impl RefreshHandle {
    /// Subscribe to per-batch progress updates.
    ///
    /// The returned [`tokio::sync::watch::Receiver`] always observes
    /// the **latest** [`RefreshProgress`] — never an intermediate
    /// one. Subscribers may clone the receiver freely; the channel
    /// stays open as long as the producer task is alive.
    ///
    /// When the producer exits (success, error, or cancellation),
    /// its `Sender` drops and subsequent `changed().await` calls
    /// return `Err(_)` ("the producer is done; no more progress").
    pub fn progress(&self) -> tokio::sync::watch::Receiver<RefreshProgress> {
        self.progress_rx.clone()
    }

    /// Fire the cancel token. Idempotent — multiple calls are
    /// no-ops after the first.
    ///
    /// The producer observes the token at the next batch boundary
    /// or backoff `select!`, returns
    /// [`RefreshError::Cancelled`], and exits. After cancellation,
    /// `join().await` surfaces `Err(Cancelled)`.
    ///
    /// Equivalent to dropping the handle, except that the caller
    /// can continue to observe `progress()` and await `join()`.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Non-blocking check whether the producer task has completed.
    ///
    /// Returns `true` while the task is alive (scanning, merging,
    /// retrying, or cancelling), `false` once it has exited and
    /// the `JoinHandle` is finished. UI code can poll this on a
    /// timer to drive a "Refresh in progress" indicator without
    /// blocking on `join()`.
    pub fn is_running(&self) -> bool {
        !self.producer_join.is_finished()
    }

    /// Await the terminal result of the refresh.
    ///
    /// Consumes the handle. Returns the [`RefreshSummary`] on
    /// success, or the terminal [`RefreshError`] on failure or
    /// cancellation.
    ///
    /// # Panics
    ///
    /// Does not panic in normal operation. If the producer task
    /// panicked (which would be an internal-consistency bug), the
    /// oneshot's `Sender` is dropped without sending; this surface
    /// returns
    /// [`RefreshError::InternalInvariantViolation`] with a static
    /// context pointing at the panic site so audit reads a typed
    /// contract failure rather than a silent loss.
    pub async fn join(mut self) -> Result<RefreshSummary, RefreshError> {
        let rx = self
            .completion_rx
            .take()
            .expect("RefreshHandle::join is called at most once: the type consumes self");
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(RefreshError::InternalInvariantViolation {
                context:
                    "RefreshHandle::join: producer task dropped completion sender without delivery",
            }),
        }
    }

    /// Assemble a handle from already-built channel ends and a producer
    /// [`JoinHandle`](tokio::task::JoinHandle).
    ///
    /// Production construction lives in
    /// [`crate::engine::Engine::spawn_refresh_producer`]; tests inject
    /// stand-in ends via [`Self::for_test`]. The `Option` around
    /// `completion_rx` exists so [`Self::join`] can move the receiver
    /// out of a type that implements [`Drop`] — a non-optional field
    /// cannot be moved out.
    pub(crate) fn from_parts(
        completion_rx: tokio::sync::oneshot::Receiver<Result<RefreshSummary, RefreshError>>,
        cancel_token: CancellationToken,
        progress_rx: tokio::sync::watch::Receiver<RefreshProgress>,
        producer_join: tokio::task::JoinHandle<()>,
        opts: RefreshOptions,
    ) -> Self {
        Self {
            completion_rx: Some(completion_rx),
            cancel_token,
            progress_rx,
            producer_join,
            opts,
        }
    }

    /// Test-only constructor that injects pre-built channels and a
    /// stand-in `JoinHandle`.
    ///
    /// `RefreshHandle`'s production constructor lives entirely
    /// inside [`crate::engine::Engine::start_refresh`], which spawns a real
    /// producer task driving an `Arc<RwLock<Engine<S>>>`. Unit tests
    /// of the handle's public surface (`progress`, `cancel`,
    /// `is_running`, `join`, `Drop`) do not need a real engine and
    /// would not benefit from one — the surface is a thin wrapper
    /// around the four channel ends. This constructor lets a test
    /// supply each end directly so it can drive the handle's
    /// observable state deterministically.
    ///
    /// `producer_join` is conventionally either:
    /// - `tokio::spawn(async move { /* loop on cancel */ })` for
    ///   tests that need `is_running()` to start `true`, or
    /// - `tokio::spawn(async {})` (already-finished) for tests that
    ///   just want to assert on the join's terminal state.
    ///
    /// Single-flight semantics are out-of-scope for handle-level
    /// unit tests: the slot is owned by `Engine<S>`, not the
    /// handle, and is exercised via the integration tests in
    /// commit 6 that go through the real `start_refresh`.
    #[cfg(test)]
    pub(crate) fn for_test(
        completion_rx: tokio::sync::oneshot::Receiver<Result<RefreshSummary, RefreshError>>,
        cancel_token: CancellationToken,
        progress_rx: tokio::sync::watch::Receiver<RefreshProgress>,
        producer_join: tokio::task::JoinHandle<()>,
        opts: RefreshOptions,
    ) -> Self {
        Self::from_parts(
            completion_rx,
            cancel_token,
            progress_rx,
            producer_join,
            opts,
        )
    }
}

impl std::fmt::Debug for RefreshHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshHandle")
            .field("opts", &self.opts)
            .field("is_running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl Drop for RefreshHandle {
    /// Cancel-on-drop. Sequence:
    ///
    /// 1. Fire the cancel token. The producer task observes it at
    ///    the next batch boundary or backoff `select!`, returns
    ///    [`RefreshError::Cancelled`], and exits.
    /// 2. Remaining handle fields drop in declaration order:
    ///    `completion_rx` (the oneshot receive end goes away),
    ///    `progress_rx`, `producer_join`. Dropping
    ///    `producer_join` detaches the task without aborting it
    ///    (tokio semantics): the task continues running until it
    ///    observes the cancel token and exits naturally. Note that
    ///    the progress `Sender` lives on the producer task, not on
    ///    the handle, so dropping the handle does not close the
    ///    progress channel — the producer's final `Cancelled`
    ///    publish still reaches any retained `Receiver` clones.
    ///
    /// The wind-down between `cancel.cancel()` and task exit is
    /// bounded by the longest-running operation in the task (one
    /// block fetch's RPC timeout, ~30 s worst case). During this
    /// window, a racing [`crate::engine::Engine::start_refresh`] returns
    /// [`RefreshError::AlreadyRunning`] because the producer's
    /// [`crate::engine::refresh_slot::SlotGuard`] is still held. Callers that want to spawn a
    /// new refresh immediately after dropping a handle should hold
    /// the previous handle and `await join()` instead of relying on
    /// `Drop`.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

// Static asserts: trait bounds the Branch 2 surface depends on.
// Failure here means a downstream type lost its Send/Sync/Clone
// invariant; surface the violation at the engine-core build rather
// than at the spawn / channel-construction site in start_refresh.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_send::<RefreshHandle>();
    assert_clone_send_sync::<RefreshProgress>();
    // RefreshOptions: Clone is required for opts.clone() at task
    // spawn (start_refresh body retains a copy on the handle for
    // diagnostics).
    fn assert_clone<T: Clone>() {}
    assert_clone::<RefreshOptions>();
    // RefreshError: Send + Sync is required for the oneshot
    // payload to cross the spawn boundary. Trivially holds —
    // every variant carries primitive types or owned strings; the
    // `ConcurrentMutation` variant's `wallet: u64, result: u64`
    // does not bleed engine state into the error.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RefreshError>();
    assert_send_sync::<RefreshSummary>();
};
