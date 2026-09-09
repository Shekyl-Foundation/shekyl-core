// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the [`RefreshHandle`] public surface.
//!
//! Every test here builds a handle via
//! [`RefreshHandle::for_test`] with hand-rolled channel ends
//! and a stand-in `JoinHandle`. No real producer task or
//! `Engine<S>` is involved — this module exercises the handle
//! itself, which is a thin wrapper around four channel ends
//! plus the cancel token.
//!
//! Corner-case tests (cancel-on-drop, concurrent
//! `start_refresh`, idempotent cancel, `mem::forget` leak
//! semantics) live in commit 5. Integration coverage for the
//! real producer through `Engine::start_refresh` lives in
//! `start_refresh_integration_tests` below, which carries
//! both fixture flavours: an unreachable-`DaemonClient`
//! flavour for handle-shape invariants and daemon-IO error
//! mapping, and a `TestDaemon`-driven hybrid flavour
//! (added in Stage 1 PR 1, per
//! `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.3) that exercises
//! the producer end-to-end against synthetic chain state.
//!
//! Wired as a `#[path]` child of `engine/refresh.rs`, so `use super::*`
//! and `super::` paths resolve into the refresh module and private items
//! stay testable; the sibling file exists so the decomposition ratchet
//! counts the workflow file, not its test suite (the
//! `local_refresh_tests.rs` pattern).
use super::{
    RefreshError, RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress, RefreshSummary,
};
use tokio_util::sync::CancellationToken;

/// Test-fixture return shape for [`handle_with`]: the
/// caller-owned channel ends and observation join handle paired
/// with a [`RefreshHandle`] whose internal channels point at
/// them. Extracted as a type alias to keep `handle_with`'s
/// signature within `clippy::type_complexity`'s threshold.
type RefreshHandleFixture = (
    RefreshHandle,
    tokio::sync::oneshot::Sender<Result<RefreshSummary, RefreshError>>,
    tokio::sync::watch::Sender<RefreshProgress>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
);

/// Build a handle whose channels are entirely caller-owned, so
/// the test can fire each one explicitly. Returns a separate
/// observation `JoinHandle` (parked on the same cancel token
/// as the one inside the handle) for assertions about producer
/// wind-down — the handle's own `JoinHandle` is consumed by
/// `is_running()` checks and may not be awaited directly
/// without breaking the move-out story.
fn handle_with(opts: RefreshOptions) -> RefreshHandleFixture {
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let (progress_tx, progress_rx) = tokio::sync::watch::channel(RefreshProgress::initial());
    let cancel = CancellationToken::new();

    // Stand-in producer: park forever on the cancel token, so
    // `is_running()` reads `true` until the test fires cancel
    // (or drops the handle, which fires it via `Drop`).
    let producer_cancel = cancel.clone();
    let producer = tokio::spawn(async move {
        producer_cancel.cancelled().await;
    });
    let producer_for_assert = tokio::spawn({
        let observe = cancel.clone();
        async move { observe.cancelled().await }
    });

    let handle =
        RefreshHandle::for_test(completion_rx, cancel.clone(), progress_rx, producer, opts);
    (
        handle,
        completion_tx,
        progress_tx,
        cancel,
        producer_for_assert,
    )
}

/// `progress()` returns a receiver that observes the seeded
/// `RefreshProgress::initial()` baseline before any update is
/// published. `borrow()` is non-blocking and always sees the
/// latest value.
#[tokio::test]
async fn progress_returns_seeded_baseline() {
    let (handle, _completion, _progress, _cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    let rx = handle.progress();
    let snap = *rx.borrow();
    assert_eq!(snap.height, 0);
    assert_eq!(snap.blocks_processed, 0);
    assert_eq!(snap.blocks_total, 0);
    // `RefreshProgress::initial()` seeds the phase as
    // `Scanning` so callers don't see `Cancelled` before the
    // producer has run.
    assert!(matches!(snap.phase, RefreshPhase::Scanning));
}

/// `progress()` updates land on every cloned receiver.
#[tokio::test]
async fn progress_updates_propagate_to_subscribers() {
    let (handle, _completion, progress_tx, _cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    let mut rx = handle.progress();
    progress_tx
        .send(RefreshProgress::phase_only(
            42,
            7,
            100,
            RefreshPhase::Scanning,
        ))
        .expect("subscriber alive");
    rx.changed().await.expect("update delivered");
    let snap = *rx.borrow();
    assert_eq!(snap.height, 42);
    assert_eq!(snap.blocks_processed, 7);
    assert_eq!(snap.blocks_total, 100);
}

/// `cancel()` fires the shared cancel token, which the
/// producer task observes. `is_running()` flips to `false`
/// once the producer task has exited.
#[tokio::test]
async fn cancel_fires_token_and_is_running_flips() {
    let (handle, _completion, _progress, cancel, producer_assert) =
        handle_with(RefreshOptions::default());

    assert!(
        handle.is_running(),
        "producer is parked on cancel; should be running"
    );
    assert!(!cancel.is_cancelled(), "no cancel observed yet");

    handle.cancel();
    assert!(cancel.is_cancelled(), "cancel() fires the shared token");

    producer_assert.await.expect("producer wakes on cancel");
    tokio::task::yield_now().await;
    assert!(!handle.is_running(), "JoinHandle has finished");
}

/// `join()` consumes the handle and returns the value sent on
/// the completion oneshot.
#[tokio::test]
async fn join_delivers_summary_from_completion_oneshot() {
    let (handle, completion, _progress, _cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    let summary = RefreshSummary {
        processed_height_range: 100..105,
        blocks_processed: 5,
        transfers_detected: 0,
        key_images_observed: 0,
        reorg: None,
        merge_attempts: 1,
    };
    completion
        .send(Ok(summary.clone()))
        .expect("oneshot receiver still alive on handle");

    let returned = handle.join().await.expect("Ok delivered");
    assert_eq!(
        returned.processed_height_range,
        summary.processed_height_range
    );
    assert_eq!(returned.blocks_processed, summary.blocks_processed);
    assert_eq!(returned.merge_attempts, summary.merge_attempts);
}

/// `join()` propagates a terminal error sent on the
/// completion oneshot unchanged.
#[tokio::test]
async fn join_propagates_terminal_error() {
    let (handle, completion, _progress, _cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    completion
        .send(Err(RefreshError::Cancelled))
        .expect("oneshot receiver still alive on handle");

    let result = handle.join().await;
    assert!(matches!(result, Err(RefreshError::Cancelled)));
}

/// If the producer task drops its completion sender without
/// sending (which would only happen on a panic — a contract
/// violation), `join()` surfaces a typed
/// `InternalInvariantViolation` rather than panicking. (Migrated
/// from `MalformedScanResult` at C5 per
/// `STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X C5 — producer panic is
/// an orchestrator control-flow invariant violation, not a
/// merge-gate scan-result invariant violation.)
#[tokio::test]
async fn join_maps_dropped_sender_to_internal_invariant_violation() {
    let (handle, completion, _progress, _cancel, _producer_assert) =
        handle_with(RefreshOptions::default());
    drop(completion);

    let result = handle.join().await;
    match result {
        Err(RefreshError::InternalInvariantViolation { context }) => {
            assert!(
                context.contains("dropped completion sender"),
                "context was: {context}"
            );
        }
        other => panic!("expected InternalInvariantViolation, got {other:?}"),
    }
}

// ── Corner-case tests (commit 5) ────────────────────────────

/// Dropping the handle fires the shared cancel token. The
/// `Drop` impl is the cancel-on-drop contract: anyone holding
/// a clone of the token (the producer task in production)
/// observes it and unwinds.
#[tokio::test]
async fn drop_fires_cancel_token() {
    let (handle, _completion, _progress, cancel, _producer_assert) =
        handle_with(RefreshOptions::default());
    assert!(!cancel.is_cancelled(), "no cancel observed pre-drop");

    drop(handle);
    assert!(cancel.is_cancelled(), "Drop fires cancel token");
}

/// Calling `cancel()` twice is a no-op after the first.
/// `CancellationToken::cancel` is documented as idempotent;
/// this test pins the contract at the [`RefreshHandle`]
/// surface so a future internal change cannot regress it
/// silently.
#[tokio::test]
async fn idempotent_cancel_is_no_op() {
    let (handle, _completion, _progress, cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    handle.cancel();
    assert!(cancel.is_cancelled());
    // Second call returns without panicking and without
    // re-firing (the token tracks its own state internally).
    handle.cancel();
    assert!(cancel.is_cancelled());
}

/// `mem::forget` skips the `Drop` impl entirely. The cancel
/// token does not fire and the producer task continues running
/// — exactly the leak semantics any Rust handle has under
/// `forget`. The test pins this so a reviewer reading the
/// code can confirm the cancel-on-drop contract is `Drop`-
/// scoped, not embedded in another method that runs
/// implicitly.
///
/// Operational note: in production this would leak the
/// `_slot_guard` held by the producer task too — `forget` is
/// a programmer error, not a supported flow. We test the
/// behaviour to make the leak surface explicit, not to
/// endorse it.
#[tokio::test]
async fn mem_forget_does_not_fire_cancel() {
    let (handle, _completion, _progress, cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    std::mem::forget(handle);
    assert!(!cancel.is_cancelled(), "Drop did not run; token unfired");

    // Manually fire the token to clean up the parked
    // observation tasks.
    cancel.cancel();
}

/// When the producer observes cancellation mid-scan and bails,
/// it publishes a terminal `RefreshPhase::Cancelled` progress
/// update **before** the watch sender drops, and that update
/// preserves the last published `height` / counters so
/// subscribers don't observe a misleading rollback to zero.
///
/// This test mirrors the production sequence exactly: the
/// per-block progress emitter inside `RefreshEngine::produce_scan_result` advances `height` during the
/// scan, and on `Err(RefreshError::Cancelled)` from
/// the producer, `run_refresh_task` clones the latest
/// published progress, overrides only `phase`, and sends. We
/// drive the same shape through the test's caller-owned
/// `progress_tx` so the assertion lands on the public surface
/// (`progress().borrow()`) rather than internals.
#[tokio::test]
async fn cancel_during_scan_emits_terminal_cancelled_phase() {
    let (handle, _completion, progress_tx, _cancel, _producer_assert) =
        handle_with(RefreshOptions::default());

    let mut rx = handle.progress();

    progress_tx
        .send(RefreshProgress::phase_only(
            100,
            50,
            200,
            RefreshPhase::Scanning,
        ))
        .expect("subscriber alive");
    rx.changed().await.expect("scanning update delivered");
    let mid = *rx.borrow();
    assert_eq!(mid.height, 100);
    assert!(matches!(mid.phase, RefreshPhase::Scanning));

    let mut terminal = *progress_tx.borrow();
    terminal.phase = RefreshPhase::Cancelled;
    progress_tx.send(terminal).expect("subscriber alive");
    rx.changed().await.expect("terminal update delivered");

    let last = *rx.borrow();
    assert!(
        matches!(last.phase, RefreshPhase::Cancelled),
        "phase preserved as Cancelled"
    );
    assert_eq!(
        last.height, 100,
        "height preserved across the Scanning→Cancelled transition"
    );
    assert_eq!(
        last.blocks_processed, 50,
        "blocks_processed preserved across the transition"
    );
    assert_eq!(
        last.blocks_total, 200,
        "blocks_total preserved across the transition"
    );
}
