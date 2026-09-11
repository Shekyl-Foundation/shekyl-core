// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sync and async [`Engine`](crate::engine::Engine) refresh entry points.
//!
//! One `impl` — `start_refresh` / `spawn_refresh_producer` and
//! `refresh` / `refresh_with` share the `LocalLedger` specialization
//! (the M3b merge post-pass needs `view_secret`; FOLLOWUPS P1).

use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{
    summarize, LedgerSnapshot, MergeRetry, RefreshHandle, RefreshOptions, RefreshPhase,
    RefreshProgress, RefreshSummary, SlotGuard,
};
use crate::engine::error::RefreshError;
use crate::engine::local_ledger::LocalLedger;
use crate::engine::signer::EngineSignerKind;
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use crate::engine::Engine;
use crate::scan::ScanResult;

// `D: DaemonEngine` private-bound: see the rationale on the
// `pub struct Engine` definition in `engine/mod.rs`.
// Specialized to `LocalLedger` because both the async producer
// ([`super::task::run_refresh_task`]) and the sync
// [`Engine::apply_scan_result`] merge need the M3b engine post-pass
// under the merge guard (FOLLOWUPS P1). The snapshot read still
// dispatches through [`LedgerEngine`]; the merge cannot — the trait
// implementor has no `view_secret`.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: crate::engine::traits::EconomicsEngine,
        R: RefreshEngine + crate::engine::scan_floor::ScanStartFloorProvider,
        P: crate::engine::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
{
    /// Spawn an async refresh task and return a [`RefreshHandle`]
    /// for observing and controlling it.
    ///
    /// The handle exposes a [`tokio::sync::watch`] receiver for
    /// progress updates, an `async fn join` future for the terminal
    /// `Result<RefreshSummary, RefreshError>`, an explicit
    /// [`RefreshHandle::cancel`] hook, and cancel-on-drop semantics.
    /// Single-flight is enforced by the engine's `RefreshSlot`:
    /// concurrent calls return [`RefreshError::AlreadyRunning`].
    ///
    /// # Shape
    ///
    /// Takes `Arc<RwLock<Self>>` (a "self-arc") rather than `&self`
    /// or `&mut self` because the spawned producer task needs to
    /// outlive any borrow of `Engine<S>` taken at the call site —
    /// the task acquires the read lock per-attempt for snapshot,
    /// drops it across the network-bound scan, then takes the write
    /// lock briefly for the merge. The shared-handle parameter shape
    /// is transitional infrastructure; at Stage 4 it becomes
    /// `actor.ask(StartRefresh { opts }).send().await?`. See the
    /// `Path B engine binary boundary as pure message-passing`
    /// decision-log entry (2026-04-27).
    ///
    /// # No I/O in this method
    ///
    /// `start_refresh` does not call the daemon, does not scan, and
    /// does not lock for longer than the slot-claim. The first
    /// network call (`daemon.get_height` for tip) happens inside the
    /// spawned producer task, so a slow or unreachable daemon does
    /// not stall slot claim or the caller's `start_refresh.await`.
    ///
    /// # Errors
    ///
    /// - [`RefreshError::AlreadyRunning`] if another refresh is
    ///   already in flight (slot was already claimed). All other
    ///   `RefreshError` variants are surfaced via
    ///   [`RefreshHandle::join`], not from this method.
    ///
    /// # Trait bounds
    ///
    /// `Engine<S>: Send + Sync` (and `S: Send + Sync + 'static`) is
    /// required for the `Arc<RwLock<Engine<S>>>` to cross the
    /// `tokio::spawn` boundary into the producer task. The bound is
    /// surfaced here at the API rather than at the spawn site so
    /// violations show up at a callable signature.
    pub async fn start_refresh(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        opts: RefreshOptions,
    ) -> Result<RefreshHandle, RefreshError>
    where
        S: EngineSignerKind + Send + Sync + 'static,
        Self: Send + Sync,
    {
        // Brief shared read borrow to clone the slot **and** capture
        // the wallet's current `synced_height`. The slot is its own
        // `Arc<AtomicBool>`, independent of the engine's RwLock, so
        // the read borrow only lives long enough to copy out the
        // values needed to seed the refresh task. CAS happens after
        // the borrow drops.
        //
        // `synced_height` is captured here (rather than re-read
        // inside the producer's first attempt) so the watch
        // channel's seed value matches the wallet baseline that the
        // contract on `RefreshProgress::height` promises: "on
        // initial publish this is `synced_height` itself." A caller
        // that does `progress().borrow()` before the producer
        // emits its first per-attempt `Scanning` update sees an
        // accurate baseline rather than a misleading `height: 0`.
        let (slot, synced_height) = {
            let engine = self_arc.read().await;
            (engine.refresh_slot.clone(), engine.ledger.synced_height())
        };
        let slot_guard = slot.try_claim().ok_or(RefreshError::AlreadyRunning)?;

        Ok(Self::spawn_refresh_producer(
            self_arc,
            opts,
            slot_guard,
            synced_height,
        ))
    }

    /// Spawn the refresh producer task and assemble its [`RefreshHandle`].
    ///
    /// Shared by [`Self::start_refresh`] and
    /// [`Engine::start_rescan`](Self::start_rescan): both run the **same**
    /// producer over the **same** single-flight slot, so the tail of the two
    /// entry points is one implementation rather than two that drift. Only
    /// the state each hands the producer differs — rescan empties the
    /// scan-derived ledger first (see `engine/rescan.rs`).
    ///
    /// Takes the already-claimed [`SlotGuard`] by value: the guard moves into
    /// the spawned task and releases the slot when the task winds down, so a
    /// caller cannot claim the slot and then forget to spawn.
    ///
    /// `synced_height` seeds the progress watch channel with the wallet
    /// baseline that [`RefreshProgress::height`]'s contract promises ("on
    /// initial publish this is `synced_height` itself"), so a caller that
    /// reads `progress().borrow()` before the producer's first per-attempt
    /// update sees a real baseline rather than a misleading `0`.
    pub(crate) fn spawn_refresh_producer(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        opts: RefreshOptions,
        slot_guard: SlotGuard,
        synced_height: u64,
    ) -> RefreshHandle
    where
        S: EngineSignerKind + Send + Sync + 'static,
        Self: Send + Sync,
    {
        // Channels:
        // - `progress`: watch (latest-only); seeded with the
        //   wallet's current `synced_height` so the first
        //   `progress().borrow()` returns a usable baseline before
        //   the producer publishes its first per-attempt update.
        //   `blocks_processed` and `blocks_total` are zero because
        //   no work has been done on this attempt yet; the producer
        //   re-bases `blocks_total` against `daemon_tip` before any
        //   per-block emission begins.
        // - `completion`: oneshot for the terminal
        //   `RefreshSummary` / `RefreshError`. `RefreshHandle::join`
        //   awaits this.
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(RefreshProgress::phase_only(
            synced_height,
            0,
            0,
            RefreshPhase::Scanning,
        ));
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let cancel_token = CancellationToken::new();

        let task_cancel = cancel_token.clone();
        // `self_arc` and `progress_tx` both move into the task. The producer
        // is the sole progress `Sender`; the handle keeps only a `Receiver`,
        // so when the task exits its `Sender` drops and downstream
        // `Receiver::changed().await` returns `Err(_)` to signal "no more
        // progress." Taking the arc by value (rather than cloning a borrow)
        // makes the handoff explicit: after this call the caller has no
        // engine reference left to accidentally use.
        let producer_join = tokio::spawn(super::task::run_refresh_task(
            self_arc,
            opts.clone(),
            task_cancel,
            progress_tx,
            completion_tx,
            slot_guard,
        ));

        RefreshHandle::from_parts(
            completion_rx,
            cancel_token,
            progress_rx,
            producer_join,
            opts,
        )
    }

    /// Drive a refresh against the configured daemon: pull a snapshot
    /// of the wallet's ledger, ask the producer to scan
    /// `synced_height + 1 .. daemon_tip + 1`, and merge the result
    /// back under `&mut self`. Retries on snapshot-race
    /// (`RefreshError::ConcurrentMutation`) up to `opts.max_retries`
    /// times before surfacing the last race. `MalformedScanResult` is
    /// terminal — re-running the scan would re-encounter the same
    /// producer-contract violation, so the caller is informed
    /// immediately.
    ///
    /// # Why synchronous, why a runtime handle
    ///
    /// `Engine::refresh` takes `&self`: as of Stage 1 PR 2 commit 5,
    /// wallet-state mutation lives inside [`LocalLedger`]'s interior
    /// `RwLock`, so the merge no longer needs an exclusive borrow on
    /// the outer engine. The cross-cutting locking discipline still
    /// applies — the implementor's write guard is the audited
    /// mutation point — but the engine surface itself takes `&self`
    /// for both queries and the refresh primitive. The signature
    /// stays synchronous: an `async fn refresh(&self, …)` would mean
    /// callers could `await` other futures across a refresh in
    /// progress, complicating cancellation and cooperative scheduling
    /// without a corresponding design win for the sync entry point.
    ///
    /// Instead, the synchronous entry point takes a
    /// [`tokio::runtime::Handle`] and runs the producer's async work
    /// via [`Handle::block_on`]. This means **`refresh` must not be
    /// called from inside an async context on the same runtime** —
    /// `block_on` panics in that case. Async callers
    /// (`tokio::spawn_blocking`, dedicated worker thread,
    /// branch-2's `RefreshHandle`) drive `refresh` from a sync
    /// context; the JSON-RPC server's RPC handler is the typical
    /// example via `spawn_blocking`.
    ///
    /// Branch 2 lands `RefreshHandle`, which spawns a producer-driven
    /// loop on the caller's runtime and exposes cancellation +
    /// progress channels. `Engine::refresh` (this method) remains the
    /// underlying primitive.
    ///
    /// # Errors
    ///
    /// - [`RefreshError::ConcurrentMutation`] — `opts.max_retries`
    ///   exhausted on snapshot races.
    /// - [`RefreshError::MalformedScanResult`] — producer-contract
    ///   violation; not retried.
    /// - [`RefreshError::Cancelled`] — surfaced when the producer is
    ///   driven through [`Engine::start_refresh`]'s cancel-on-drop
    ///   [`RefreshHandle`]. The synchronous [`Engine::refresh`]
    ///   signature itself never returns this variant in V3.0+: by
    ///   design, the sync path uses an internal token that never
    ///   fires. Cooperative cancellation is the async surface's
    ///   responsibility, not the sync surface's. See the
    ///   *Cancellation contract* section below.
    /// - [`RefreshError::Io`] — daemon RPC budget exhausted, or
    ///   scanner rejected a block as structurally invalid.
    ///
    /// # Cancellation contract (long-term, not transitional)
    ///
    /// The synchronous signature does **not** take a cancellation
    /// token, and the split between the sync and async surfaces is
    /// pinned for the lifetime of `Engine`:
    ///
    /// - **Sync path ([`Engine::refresh`], this method):**
    ///   cancel-internal. The token is created fresh per call and
    ///   never fires. Callers driving this from a sync context (CLI,
    ///   JSON-RPC handler running under `spawn_blocking`) accept that
    ///   they wait for the producer to settle naturally — typically
    ///   at the next scanner block boundary in the underlying loop.
    /// - **Async path ([`Engine::start_refresh`] returning
    ///   [`RefreshHandle`]):** the cancellation surface. The handle's
    ///   `cancel()` method and cancel-on-drop `Drop` impl fire the
    ///   shared [`CancellationToken`] that the producer observes at
    ///   every await point and at the four documented checkpoints in
    ///   `run_refresh_task`.
    ///
    /// This is a deliberate split, not a TBD. Threading a token
    /// argument into the sync signature would push cancellation
    /// plumbing into every caller for no design win — the async
    /// surface already exists for any caller that needs cooperative
    /// shutdown. The two surfaces compose: the async handle drives
    /// the producer directly, and the sync method drives the same
    /// producer behind an inert internal token. Both share one
    /// implementation; they differ only in who owns the token.
    pub fn refresh(
        &self,
        opts: &RefreshOptions,
        runtime: &tokio::runtime::Handle,
    ) -> Result<RefreshSummary, RefreshError> {
        let floor = self.refresh.scan_start_floor();
        runtime.block_on(crate::engine::scan_floor::ensure_birthday_anchor(
            &self.ledger,
            &self.daemon,
            floor,
        ))?;
        // Producer dispatch via the [`RefreshEngine`] trait surface
        // (`R: RefreshEngine`, default `LocalRefresh`). The trait
        // implementor owns scanner construction, daemon-tip read,
        // per-block fetch + retry, per-block progress emission, and
        // the producer-side cancellation checkpoints; the sync
        // `Engine::refresh` surface only drives the
        // snapshot-merge-with-retry orchestration around it.
        //
        // The sync path's cancellation token is created fresh per
        // call and never fires — see the function rustdoc's
        // "Cancellation contract" section: the async surface
        // ([`Engine::start_refresh`]) is the cancellation surface,
        // not this one.
        //
        // Producer observability: the sync path does not expose a
        // [`DiagnosticSink`] to its callers, so the producer's
        // diagnostic stream is discarded via [`NoopDiagnosticSink`].
        // Callers that want producer-side observability use the async
        // path, which routes through [`TracingDiagnosticSink`] in
        // `run_refresh_task`.
        let cancel = CancellationToken::new();
        let sink = crate::engine::diagnostics::NoopDiagnosticSink::new();

        // Throwaway progress channel: the sync path has no
        // subscriber, but the trait surface requires a
        // `watch::Sender<RefreshProgress>` to emit per-block updates
        // into. Constructed once per call and dropped at the end of
        // the closure scope; the receiver immediately drops as well,
        // so the producer's `progress.send(...)` calls are no-ops
        // (best-effort sends to a no-subscriber watch channel
        // silently succeed by replacing the buffered latest value).
        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(RefreshProgress::phase_only(
            0,
            0,
            0,
            RefreshPhase::Scanning,
        ));

        self.refresh_with(opts, |_attempt, snapshot| {
            let mut result = runtime
                .block_on(self.refresh.produce_scan_result(
                    snapshot.clone(),
                    &self.daemon,
                    opts.clone(),
                    cancel.clone(),
                    progress_tx.clone(),
                    &sink,
                ))
                .map_err(Into::<RefreshError>::into)?;
            // CT-5a §3.2 (R1-Q2): feed the curve tree this result's range
            // before `refresh_with` merges it (ack-before-commit, O2).
            // Cursor-driven + idempotent, so re-running it on a retried
            // attempt is safe. Mirrors the async `run_refresh_task` path,
            // including the R1-Q4 respawn-and-retry on a fail-stop / poison.
            runtime.block_on(self.ingest_scan_result_with_respawn(&mut result))?;
            Ok(result)
        })
    }

    /// Snapshot-merge-with-retry driver, generic over the producer.
    ///
    /// Factored out of [`Engine::refresh`] so integration tests can
    /// exercise the loop's retry / classification behaviour without
    /// standing up a real RPC fixture: the scripted producer just
    /// returns canned `ScanResult` / `RefreshError` values per
    /// attempt. Production callers go through [`Engine::refresh`],
    /// which builds the live producer closure (daemon RPC + scanner)
    /// and forwards into here.
    ///
    /// The closure receives `(attempt, &snapshot)`. `attempt` is
    /// 1-indexed and matches the value the loop will record into
    /// [`RefreshSummary::merge_attempts`] if the merge that follows
    /// succeeds. `snapshot` is freshly captured each attempt — the
    /// retry loop's contract is that every attempt produces against
    /// a snapshot that was current at the start of that attempt.
    ///
    /// # Error semantics
    ///
    /// - Producer returns `Err(_)` → propagate immediately. The
    ///   producer's only `ConcurrentMutation` source is the merge,
    ///   which runs inside this loop, so producer-side `Err` values
    ///   are by construction non-race terminal failures.
    /// - Merge returns `Err(ConcurrentMutation { … })` → retry up to
    ///   `opts.max_retries` more times; on exhaustion, surface the
    ///   last observed `ConcurrentMutation`.
    /// - Merge returns `Err(MalformedScanResult { … })` or any other
    ///   `RefreshError` → propagate immediately.
    pub(crate) fn refresh_with<F>(
        &self,
        opts: &RefreshOptions,
        mut produce: F,
    ) -> Result<RefreshSummary, RefreshError>
    where
        F: FnMut(u32, &LedgerSnapshot) -> Result<ScanResult, RefreshError>,
    {
        let mut retry = MergeRetry::new(opts);

        // The first attempt always runs. After a snapshot race,
        // `MergeRetry::after_race` is `Some(next)` while extra
        // retries remain and `None` when this race exhausted the
        // budget — so exhaustion always has a race in hand.
        loop {
            let attempt = retry.attempt();
            // Snapshot via [`LedgerEngine::snapshot`] on the
            // implementor field; the implementor manages its own
            // read guard internally. `&self` on the outer engine is
            // sufficient because mutation lives inside the
            // implementor's write guard.
            let snapshot = self.ledger.snapshot();
            let result = produce(attempt, &snapshot)?;
            let summary = summarize(&result, retry.attempt_nz());

            match self.apply_scan_result(result) {
                Ok(()) => return Ok(summary),
                Err(RefreshError::ConcurrentMutation { wallet, result }) => {
                    debug!(
                        attempt,
                        max_retries = opts.max_retries,
                        wallet,
                        result,
                        "Engine::refresh: snapshot race, retrying with fresh snapshot",
                    );
                    match retry.after_race() {
                        Some(next) => {
                            retry = next;
                            continue;
                        }
                        None => {
                            return Err(RefreshError::ConcurrentMutation { wallet, result });
                        }
                    }
                }
                Err(other) => return Err(other),
            }
        }
    }
}
