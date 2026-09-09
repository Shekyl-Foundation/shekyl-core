// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Async producer task spawned by [`crate::engine::Engine::start_refresh`].

use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{
    membership_rebuilding, summarize, MergeRetry, RefreshOptions, RefreshPhase, RefreshProgress,
    RefreshSummary, SlotGuard,
};
use crate::engine::diagnostics::TracingDiagnosticSink;
use crate::engine::error::RefreshError;
use crate::engine::local_ledger::LocalLedger;
use crate::engine::signer::EngineSignerKind;
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use crate::engine::Engine;

/// Best-effort `Cancelled` progress ping + oneshot delivery. Shared by
/// every cancel checkpoint so a missed phase override cannot drift
/// between sites.
fn complete_cancelled(
    progress: &tokio::sync::watch::Sender<RefreshProgress>,
    completion: tokio::sync::oneshot::Sender<Result<RefreshSummary, RefreshError>>,
) {
    let mut terminal = *progress.borrow();
    terminal.phase = RefreshPhase::Cancelled;
    _ = progress.send(terminal);
    _ = completion.send(Err(RefreshError::Cancelled));
}

/// Producer task entry point.
///
/// Spawned by [`Engine::start_refresh`]. Drives the snapshot-merge
/// loop end-to-end: fetch tip, snapshot, scan (without holding the
/// engine lock), merge under write lock, retry on
/// `ConcurrentMutation` until `opts.max_retries` is reached, and
/// publish a terminal result on `completion`.
///
/// ## Parameters
///
/// - `engine_arc`: shared handle to the engine. The task holds the
///   read lock briefly per attempt for the snapshot, drops it
///   across the network-bound scan, then re-acquires the write
///   lock for the merge. Stage 4 replaces this with actor message
///   passing.
/// - `opts`: the same `RefreshOptions` `start_refresh` was called
///   with. Carries `max_retries` for the snapshot-race retry
///   budget.
/// - `cancel`: cooperative cancel token; observed at every batch
///   boundary and during retry-backoff `select!`s. Fired by
///   `RefreshHandle::cancel()` and by `Drop`.
/// - `progress`: the producer's sole `Sender` for the watch
///   channel. Published per-batch while scanning; the final
///   `Cancelled` / terminal phase publish runs before the task
///   exits.
/// - `completion`: oneshot the producer sends its terminal result
///   on. Awaited by `RefreshHandle::join`.
/// - `_slot_guard`: held by name only — the parameter exists so
///   the slot stays claimed for the **full lifetime** of this
///   function, including post-`completion.send(...)` wind-down.
///   When the function returns (success, error, or cancellation),
///   the guard drops and releases the engine's `RefreshSlot` flag.
///   This is the mechanism that ensures single-flight semantics:
///   the slot stays claimed until the task exits, so a racing
///   `start_refresh` returns `AlreadyRunning` even during cancel-
///   then-cleanup wind-down. The `_` prefix is the standard Rust
///   idiom for "RAII guard, intentionally unused in the function
///   body but held for `Drop` semantics."
///
/// Drive the asynchronous snapshot–scan–merge–retry loop on behalf of
/// [`Engine::start_refresh`].
///
/// # Locking topology
///
/// Per attempt:
/// 1. **Read lock** — acquired briefly to clone [`DaemonClient`] (for the
///    network calls below) and to take a fresh [`LedgerSnapshot`]. The
///    lock is released before any I/O.
/// 2. **No lock** — daemon `get_height`, scanner construction (first
///    attempt only), and `RefreshEngine::produce_scan_result` run with no engine
///    borrow held. This is the long phase, on the order of network
///    round-trips per block, and is exactly why the function exists in
///    the first place.
/// 3. **Write lock** — acquired briefly to call
///    [`Engine::apply_scan_result`]. The merge fails with
///    [`RefreshError::ConcurrentMutation`] iff another writer
///    interleaved between the snapshot and the merge; that variant
///    is the loop's signal to retry, not a terminal error.
///
/// # `_slot_guard`
///
/// The [`SlotGuard`] returned by [`RefreshSlot::try_claim`] in
/// [`Engine::start_refresh`] is moved into this task and held by name
/// for the task's entire body. Its [`Drop`] impl flips the
/// `refresh_slot` flag back to `false`, releasing single-flight
/// exclusion. Releasing on task exit (rather than on
/// [`RefreshHandle::drop`]) is what guarantees a fresh
/// [`Engine::start_refresh`] cannot observe `AlreadyRunning` after a
/// cancelled handle is dropped but before the producer task has
/// actually noticed the cancellation and unwound — which would race
/// the task against the next refresh on the same engine. The
/// underscore prefix is a deliberate signal that the binding is held
/// for its `Drop` side-effect, not read.
///
/// # Cancellation
///
/// The cancellation token is checked at five points:
///
/// 0. **Pre-anchor** — before the birthday-anchor preflight. The
///    anchor fetches a block hash from the daemon and advances
///    `LocalLedger` to `floor - 1`; both are refresh-side side
///    effects. A cancel observed here short-circuits to `Cancelled`
///    without committing them, so an already-cancelled task does not
///    mutate wallet state.
/// 1. **Top of each attempt** — covers the boundary between attempts,
///    including the gap between a `Retrying` publish and the next
///    snapshot.
/// 2. **Post-tip-fetch**, immediately after `daemon.get_height()`
///    returns `Ok` — covers cancels that fire during the daemon RPC
///    itself. The RPC isn't cancel-aware, so the await runs to
///    completion; this checkpoint is what makes a cancel-during-tip-
///    fetch deterministically surface as `Cancelled` rather than
///    leak into the per-block scan.
/// 3. **Mid-scan**, inside `RefreshEngine::produce_scan_result` — covers between
///    blocks during the long scan, which is where the bulk of the
///    elapsed time lives.
/// 4. **Pre-merge**, between `RefreshEngine::produce_scan_result` returning `Ok`
///    and the write-lock acquisition for [`Engine::apply_scan_result`]
///    — covers the post-scan window where the producer holds a
///    valid `ScanResult` but has not yet mutated wallet state. A
///    cancel observed here is honoured because the merge has not
///    committed; the in-flight `ScanResult` is discarded along with
///    the work that produced it. This is the trade-off cancellation
///    asks us to make.
///
/// On observation at any of these points, a final `Cancelled`
/// progress update is best-effort emitted — preserving the last
/// published `height` / `blocks_processed` / `blocks_total` so
/// subscribers don't observe a misleading rollback to zero — and
/// `RefreshError::Cancelled` is delivered via the completion
/// oneshot.
///
/// There is **no** post-merge cancel checkpoint. Once
/// [`Engine::apply_scan_result`] commits under the write lock the
/// state mutation is authoritative, and a cancel token observed
/// after that point cannot un-mutate the wallet. The post-merge
/// path always delivers `Ok(summary)`; consumers that want to
/// abandon a successful refresh in flight have to drop the handle
/// and reconcile against the next `progress().borrow()`.
#[allow(clippy::type_complexity)]
pub(crate) async fn run_refresh_task<S, D: DaemonEngine, E, R, P>(
    engine_arc: std::sync::Arc<tokio::sync::RwLock<Engine<S, D, LocalLedger, E, R, P>>>,
    opts: RefreshOptions,
    cancel: CancellationToken,
    progress: tokio::sync::watch::Sender<RefreshProgress>,
    completion: tokio::sync::oneshot::Sender<Result<RefreshSummary, RefreshError>>,
    _slot_guard: SlotGuard,
) where
    S: EngineSignerKind + Send + Sync + 'static,
    E: crate::engine::traits::EconomicsEngine,
    R: RefreshEngine + crate::engine::scan_floor::ScanStartFloorProvider + Send + Sync + 'static,
    P: crate::engine::traits::PendingTxEngine + Send + Sync + 'static,
    Engine<S, D, LocalLedger, E, R, P>: Send + Sync,
{
    // Pre-anchor cancellation checkpoint (point 0 in the cancellation
    // contract above). The birthday anchor fetches a block hash from
    // the daemon and advances `LocalLedger` to `floor - 1`; both are
    // refresh-side side effects. A cancel observed before the anchor
    // must short-circuit to `Cancelled` without committing them, so a
    // handle dropped or cancelled before the task runs does not mutate
    // wallet state.
    if cancel.is_cancelled() {
        complete_cancelled(&progress, completion);
        return;
    }
    // Clone the ledger handle and daemon under a brief read guard, then
    // drop the guard before the network-bound anchor await. The rest of
    // this driver follows the same clone-then-drop discipline so daemon
    // I/O never holds the outer `engine_arc` read lock and never blocks
    // a writer for the duration of an RPC round-trip.
    {
        let (ledger, daemon, floor) = {
            let g = engine_arc.read().await;
            (
                std::sync::Arc::clone(&g.ledger),
                g.daemon().clone(),
                g.refresh.scan_start_floor(),
            )
        };
        if let Err(e) =
            crate::engine::scan_floor::ensure_birthday_anchor(&ledger, &daemon, floor).await
        {
            _ = completion.send(Err(e));
            return;
        }
    }

    // Producer-side observability sink. `TracingDiagnosticSink` is the
    // V3.0 canonical projection per `engine/diagnostics/sink.rs` F9: each
    // RefreshDiagnostic variant is routed to a typed `tracing` span
    // with bucketed labels. Constructed once per refresh and shared
    // by reference into every attempt's `RefreshEngine::produce_scan_result` call —
    // the sink is a unit struct (`Copy`), so the inline ceremony is
    // free.
    let sink = TracingDiagnosticSink::new();

    let mut retry = MergeRetry::new(&opts);

    loop {
        let attempt = retry.attempt();
        if cancel.is_cancelled() {
            // Best-effort terminal progress. Preserve the last
            // published baseline (height / counters) and override
            // only `phase`, so subscribers don't observe a
            // misleading rollback to `height: 0` when the wallet
            // was already synced above zero. `Receiver::changed`
            // wakes once before the channel closes.
            complete_cancelled(&progress, completion);
            return;
        }

        // Snapshot + daemon clone + refresh-impl Arc-clone. Take the
        // engine read-lock once per attempt to extract three
        // independently-owned values, then drop the guard before
        // dispatching the producer body:
        //
        // - `snapshot: LedgerSnapshot` — owned snapshot of wallet
        //   state at the attempt's start.
        // - `daemon: D` — daemon-trait implementor (cheap Arc-clone
        //   in the production `DaemonClient` case).
        // - `refresh: Arc<R>` — producer-trait implementor handle.
        //   `Engine::refresh` is `Arc<R>` precisely so the long-
        //   running scan can dispatch through the trait surface
        //   without holding the engine read-lock through the
        //   `RefreshEngine::produce_scan_result(...).await` (which would block the merge
        //   path's write-lock acquisition).
        //
        // Snapshot acquisition goes through [`LedgerEngine::snapshot`]
        // on the implementor field (the trait-dispatch path); the
        // implementor manages its own guard internally. Outer engine
        // borrow is shared (`read().await`) per the §5 commit-5
        // relaxation: with mutation interior to `LocalLedger`, the
        // refresh driver no longer needs an exclusive engine borrow.
        let (snapshot, daemon, refresh) = {
            let g = engine_arc.read().await;
            (
                g.ledger.snapshot(),
                g.daemon().clone(),
                std::sync::Arc::clone(&g.refresh),
            )
        };
        let current_synced = snapshot.synced_height;

        // Trait dispatch: the producer body lives in the
        // [`RefreshEngine`] implementor (production default
        // [`crate::engine::LocalRefresh`]), per
        // `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X C5. The
        // implementor owns scanner construction, the daemon-tip read,
        // per-block fetch + retry, per-block progress emission on the
        // `watch::Sender<RefreshProgress>`, and the producer-side
        // cancellation checkpoints 2/3/4/5 (per `traits/refresh.rs`
        // §"Cancellation discipline"). The orchestrator owns
        // checkpoints 1 (top-of-attempt, above) and the pre-merge
        // checkpoint (below).
        let produced = refresh
            .produce_scan_result(
                snapshot,
                &daemon,
                opts.clone(),
                cancel.clone(),
                progress.clone(),
                &sink,
            )
            .await;

        let mut result = match produced.map_err(Into::into) {
            Ok(r) => r,
            Err(RefreshError::Cancelled) => {
                // Mid-scan cancel: the producer observed the cancel
                // token at one of its internal checkpoints (2, 3,
                // or 5) and bailed. Mirror the top-of-attempt
                // cancel emission — preserve the last published
                // baseline (which the producer's per-block emit
                // advanced as the scan ran) and override only
                // `phase`.
                complete_cancelled(&progress, completion);
                return;
            }
            Err(e) => {
                _ = completion.send(Err(e));
                return;
            }
        };

        let summary = summarize(&result, retry.attempt_nz());

        // Pending-incoming ("you have received") display summary for this
        // attempt (CT-5 §3.2.1 D3). Detection is decoupled from
        // spendability: these outputs surface on the progress channel as
        // soon as the scan finds them, independent of whether the curve
        // tree can yet prove their membership. `u64`-summed with
        // saturation so a pathological amount set can never panic the
        // refresh task.
        let pending_incoming_count = summary.transfers_detected as u64;
        let pending_incoming_atomic_units = result.new_transfers.iter().fold(0u64, |acc, dt| {
            acc.saturating_add(dt.output.amount().to_raw())
        });
        let merge_height = summary
            .processed_height_range
            .end
            .saturating_sub(1)
            .max(current_synced);

        // Pre-merge cancel checkpoint. The producer returned a valid
        // `ScanResult`, but the user fired `cancel` between the last
        // per-block check inside `RefreshEngine::produce_scan_result` and now. The
        // merge has not yet acquired the write lock, so wallet state
        // is unmutated and we can still honour the cancellation
        // without rolling anything back. After this point the merge
        // is authoritative — see the function docstring.
        if cancel.is_cancelled() {
            complete_cancelled(&progress, completion);
            return;
        }

        // Best-effort `Merging` ping right before the write-lock. The
        // merge is bounded by compute (no I/O), so subscribers
        // observing this phase are usually about to immediately
        // observe success or a retry. `blocks_total` mirrors
        // `blocks_processed`: the producer is done, so total equals
        // processed at this phase transition.
        //
        // `rebuilding_membership` is read from the tree cursor *before*
        // the ingest pre-pass below runs: it is the adopting / tree-wiped
        // wallet's state (ledger ahead of a lagging tree) and is the
        // window during which the backfill is in flight. On a long
        // adopting backfill this is the phase a subscriber observes for
        // the entire catch-up, so the "rebuilding membership data" status
        // surfaces here, not after the pre-pass has already healed it.
        let rebuilding_membership = {
            let curve_tree = {
                let g = engine_arc.read().await;
                g.curve_tree.clone()
            };
            let cursor = curve_tree.ingested_tip_height().await;
            // A cursor read failure is not fatal to the display ping
            // (the ingest pre-pass below surfaces a real fault
            // terminally); treat an unreadable cursor as not-rebuilding
            // so a transient actor hiccup cannot flip the UI to a
            // spurious "rebuilding" state.
            cursor
                .ok()
                .is_some_and(|c| membership_rebuilding(c, current_synced))
        };
        _ = progress.send(RefreshProgress {
            height: merge_height,
            blocks_processed: summary.blocks_processed,
            blocks_total: summary.blocks_processed,
            phase: RefreshPhase::Merging,
            pending_incoming_count,
            pending_incoming_atomic_units,
            rebuilding_membership,
        });

        // Merge under the **read** lock on the outer engine: per the
        // §5 commit-5 outer-lock relaxation, the wallet-state mutation
        // is interior to `LocalLedger`'s own write guard — the outer
        // `Arc<RwLock<Engine<S, D, LocalLedger>>>` only needs a shared
        // borrow for the merge call. The interior write guard
        // serializes mutation against any concurrent reader on the
        // same engine. On `ConcurrentMutation` we loop with a fresh
        // snapshot.
        //
        // The merge goes through the LocalLedger-specialized
        // [`Engine::apply_scan_result`] (in `engine/merge.rs`), **not**
        // a `LedgerEngine` trait method (FOLLOWUPS P1). The trait
        // implementor has no access to the engine's `view_secret`, so
        // a trait-dispatched merge could only run the bookkeeping fold
        // and would skip the M3b engine post-pass
        // ([`populate_engine_handle_fields`]) that populates
        // `source_ciphertext` / `output_handle` on freshly-merged
        // transfers. `Engine::apply_scan_result` runs the fold and the
        // post-pass under a single `LocalLedger` write guard, keeping
        // the two atomic against external readers
        // (`docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §3 rejected
        // alternative (ζ): no non-atomic intermediate state). It is a
        // synchronous call (the post-pass is a pure cryptographic
        // primitive at M3b), so the outer engine read-guard `g` is
        // held only for the bounded, compute-only merge — no `.await`
        // runs while it is held.
        // CT-5a §3.2 (R1-Q2): feed the curve tree this result's height
        // range (genesis/birthday catch-up + per-range ingest, cursor-
        // driven) BEFORE the ledger merge, so the ledger tip never
        // advances past the tree (ack-before-commit, O2). The ingest is
        // idempotent under the retry loop — a re-produced result is
        // skipped up to the tree's own cursor — and terminal on failure
        // (the loop retries only `ConcurrentMutation`). Clone the
        // curve-tree handle and daemon under a brief read guard, then
        // drop the guard before the long-running ingest `.await`s so
        // close / mutation paths are not blocked during backfill.
        let (curve_tree, daemon) = {
            let g = engine_arc.read().await;
            (g.curve_tree.clone(), g.daemon.clone())
        };
        let producer_leaves = match crate::engine::merge::index_block_leaves(std::mem::take(
            &mut result.block_leaves,
        )) {
            Ok(map) => map,
            Err(e) => {
                _ = completion.send(Err(e));
                return;
            }
        };
        if let Err(e) = crate::engine::merge::curve_tree_ingest_scan_result_with_respawn(
            &curve_tree,
            &daemon,
            &result,
            &producer_leaves,
        )
        .await
        {
            _ = completion.send(Err(e));
            return;
        }

        let merge = {
            let g = engine_arc.read().await;
            g.apply_scan_result(result)
        };

        match merge {
            Ok(()) => {
                // Final `Merging`-phase frame carrying the per-attempt
                // pending-incoming summary with `rebuilding_membership:
                // false` — the ingest pre-pass above acked the full range
                // before this merge (ack-before-commit), so the tree is
                // now caught up to the ledger and any rebuild window has
                // closed. This lets a subscriber that samples only the
                // terminal frame still observe "you received X" without a
                // stale rebuilding flag. The completion oneshot remains
                // the authoritative success signal; there is no terminal
                // `Done` phase (dropping `progress` on return yields
                // `RecvError`, the watch idiom for "no further updates").
                _ = progress.send(RefreshProgress {
                    height: merge_height,
                    blocks_processed: summary.blocks_processed,
                    blocks_total: summary.blocks_processed,
                    phase: RefreshPhase::Merging,
                    pending_incoming_count,
                    pending_incoming_atomic_units,
                    rebuilding_membership: false,
                });
                _ = completion.send(Ok(summary));
                return;
            }
            Err(RefreshError::ConcurrentMutation { wallet, result }) => {
                debug!(
                    attempt,
                    max_retries = opts.max_retries,
                    wallet,
                    result,
                    "run_refresh_task: snapshot race, retrying with fresh snapshot",
                );
                // Re-baseline progress with current_synced and zeroed
                // counters. The next attempt's `RefreshEngine::produce_scan_result`
                // re-derives `blocks_total` from a fresh snapshot +
                // daemon-tip read; the orchestrator no longer owns
                // that value after the C5 trait-dispatch migration.
                _ = progress.send(RefreshProgress::phase_only(
                    current_synced,
                    0,
                    0,
                    RefreshPhase::Retrying,
                ));
                match retry.after_race() {
                    Some(next) => {
                        retry = next;
                        continue;
                    }
                    None => {
                        // Budget exhausted: the race just observed *is*
                        // the terminal error. `MergeRetry` makes a
                        // fall-through-with-no-race unrepresentable.
                        _ = completion
                            .send(Err(RefreshError::ConcurrentMutation { wallet, result }));
                        return;
                    }
                }
            }
            Err(other) => {
                _ = completion.send(Err(other));
                return;
            }
        }
    }
}
