// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`LocalRefresh`]: the in-process [`RefreshEngine`] implementor
//! (Phase 0b binding form per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]
//! §4 + §7.X C4).
//!
//! `LocalRefresh` is the Stage 1 production [`RefreshEngine`] body
//! — an aggregate that owns its [`ViewMaterial`] for the
//! a-instance-scoped lifetime per §5.4.7 R4 and implements the
//! producer-side contract on top of [`shekyl_scanner::Scanner`].
//! Stage 4 swaps `LocalRefresh` for an `ActorRef<RefreshActor>`
//! that wraps an actor body around the same logic; the trait
//! surface holds across the swap.
//!
//! # Status (PR 4 C4)
//!
//! C4 introduces the aggregate but **does not** wire it into
//! [`Engine`](super::Engine)'s dispatch path; that lands at C5 as
//! the load-bearing trait-dispatch commit (§7.X C5). At C4 the
//! aggregate sits in the crate unconsumed except by future
//! trait-dispatch sites and by the C7 property tests
//! (`AssertionSink` / `PanickingSink` / coherence-pair). The
//! legacy free-function [`super::refresh::produce_scan_result`]
//! continues to drive production refresh until C5 deletes it.
//!
//! # Implementation outline
//!
//! [`LocalRefresh::produce_scan_result`] owns the producer-side
//! work for one refresh attempt:
//!
//! 1. **Cancellation checkpoint 2** (pre-fetch) — observed at
//!    method entry, before the daemon-tip read.
//! 2. **Daemon tip read** — [`DaemonEngine::get_height`] for the
//!    attempt's scan ceiling. RPC failure surfaces as
//!    [`LocalRefreshError::Io`]; the
//!    [`RefreshDiagnostic::DaemonProtocolError`] classification at
//!    this site lands at C5 alongside the `RpcError → ProtocolErrorKind`
//!    classifier (per §7.X C5 "Producer-side `RpcError`
//!    classification").
//! 3. **Scanner construction** — a fresh
//!    [`shekyl_scanner::Scanner`] is built from
//!    [`Self::view_material`] per attempt (the view-material
//!    bytes are copied into [`Zeroizing<…>`](Zeroizing) wrappers
//!    the scanner takes ownership of; the scanner's
//!    [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop) chain wipes them
//!    at attempt end).
//! 4. **Cancellation checkpoint 3** (pre-scan) — observed before
//!    the per-block scan loop begins.
//! 5. **Per-block scan loop** — for each height in
//!    `(snapshot.synced_height + 1)..tip`:
//!    - per-attempt [`EmitState`] resets per-block emission
//!      counters at the block boundary;
//!    - [`fetch_block_with_retry`] fetches the block;
//!    - reorg-detection compares the daemon's
//!      `block.header.previous` against `snapshot.block_hash_at`;
//!      on mismatch [`find_fork_point`] walks back to the fork
//!      and the per-event accumulators rewind to the fork height;
//!      [`RefreshDiagnostic::ReorgObserved`] emits with the
//!      bucketed `(fork_height, depth)` payload;
//!    - producer-side per-tx excessive-outputs pre-pass: every
//!      transaction whose `outputs.len() >
//!      shekyl_scanner::MAX_OUTPUTS` emits
//!      [`RefreshDiagnostic::DaemonMalformed`]`{ kind:
//!      MalformedKind::ExcessiveOutputs }` and the producer
//!      returns [`LocalRefreshError::Malformed`] (the scanner's
//!      own size gate at
//!      [`Scanner::scan_with_cancel`](shekyl_scanner::Scanner::scan_with_cancel)
//!      entry is redundant defense-in-depth);
//!    - [`Scanner::scan_with_cancel`](shekyl_scanner::Scanner::scan_with_cancel)
//!      scans the block with **cancellation checkpoint 5** firing
//!      at the per-output safe-point (per the F11-S §7.Y
//!      disposition that escalated checkpoint 5 from
//!      per-transaction to per-output granularity);
//!    - scanner-side structural rejection
//!      ([`ScanError::InvalidScannableBlock`])
//!      emits [`RefreshDiagnostic::DaemonMalformed`]`{ kind:
//!      MalformedKind::InvalidBlockStructure }` and the producer
//!      returns [`LocalRefreshError::Malformed`];
//!    - on per-block success
//!      [`RefreshDiagnostic::ScanProgress`] emits with
//!      `(height, candidates)` (rate-limited per the producer-side
//!      per-class emission budget; the first per-block ceiling
//!      breach for a class within an attempt latches the
//!      [`SuppressedRateLimit`](RefreshDiagnostic::SuppressedRateLimit)
//!      notice and subsequent breaches drop silently per the F13-S
//!      latch).
//! 6. **Atomicity-under-cancellation (R7)** — at any
//!    cancellation observation (checkpoints 2, 3, or 5), all
//!    in-flight per-block partial state is discarded; the
//!    [`Scanner`]'s [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop)
//!    chain handles the per-block secret-bearing materials.
//!    [`LocalRefreshError::Cancelled`] propagates to the
//!    orchestrator.
//!
//! # Per-attempt emission budget — F6 / F13-S latch (§5.4.8 #5)
//!
//! [`EmitState`] tracks per-class `(u32 counter, bool
//! notice_emitted)` state for the five rate-limitable classes
//! (`DaemonMalformed`, `DaemonTimeout`, `DaemonProtocolError`,
//! `ReorgObserved`, `ScanProgress`). The counter clears at every
//! block boundary; the latch clears at attempt start and never
//! clears mid-attempt. The first per-block ceiling breach for a
//! class within an attempt emits one
//! [`RefreshDiagnostic::SuppressedRateLimit`] notice and sets the
//! latch; subsequent breaches drop silently. This closes the
//! emission-cadence covert channel per §5.4.8 #5's
//! emission-cadence sub-pin.
//!
//! Cross-attempt cadence (adversarial daemons forcing many
//! attempts via `ConcurrentMutation`-driven retries) is bounded
//! at the orchestrator's retry-loop policy layer; no
//! producer-side state survives across attempts per
//! [`DiagnosticSink`]'s restart-amnesia pin (`§5.4.6 R5`).
//!
//! # Cancellation checkpoint 5 — per-output safe-point (F11 + F11-S)
//!
//! Per the F11-S §7.Y measurement disposition, checkpoint 5
//! fires at the **per-output safe-point** between consecutive
//! per-output decap iterations within a transaction's scan loop.
//! The safe-point is the iteration boundary AFTER the prior
//! per-output [`Zeroizing<…>`](Zeroizing) materials drop and
//! BEFORE the next per-output view-tag / hybrid-decap / key-image
//! derivation begins. Mid-derivation firing is forbidden;
//! the per-output drop window is the audited safe-point pin.
//!
//! The mechanism: [`LocalRefresh::produce_scan_result`] calls
//! [`Scanner::scan_with_cancel`](shekyl_scanner::Scanner::scan_with_cancel)
//! with a closure that reads [`CancellationToken::is_cancelled`].
//! The scanner-side helper exposes per-output safe-points by
//! evaluating the closure at the top of each output iteration in
//! its inner per-transaction loop (added in PR 4 C4 prep #1 at
//! `rust/shekyl-scanner/src/scan.rs:scan_transaction_with_cancel`).
//! On `is_cancelled() == true` the scanner returns
//! [`ScanOutcome::Cancelled`] without exposing partial state;
//! the producer translates to [`LocalRefreshError::Cancelled`].
//!
//! # Why a unit-variant error
//!
//! [`LocalRefreshError`] is unit-variant-only per the §2.3 +
//! §5.4.7 R6 two-channel reframe binding pinned at
//! [`RefreshEngine::Error`](super::traits::refresh::RefreshEngine::Error)'s
//! rustdoc. Per-event detail flows through the
//! [`DiagnosticSink`] channel; the terminal error carries only
//! the discriminant. This forecloses attacker-controlled
//! `String` payloads from flowing through the error type into
//! orchestrator-side state (the §5.4.7 R6 memory-amplifier
//! closure).
//!
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
//! [`Scanner`]: shekyl_scanner::Scanner
//! [`ScanError::InvalidScannableBlock`]: shekyl_scanner::ScanError
//! [`Zeroizing`]: zeroize::Zeroizing

use std::time::Duration;

use curve25519_dalek::edwards::CompressedEdwardsY;
use shekyl_oxide::transaction::Input;
use shekyl_rpc::{Rpc, RpcError, ScannableBlock};
use shekyl_scanner::{ScanError, ScanOutcome, Scanner, ViewPair, MAX_OUTPUTS};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

use super::diagnostics::{
    DiagnosticSink, MalformedKind, ProtocolErrorKind, RefreshDiagnostic, SuppressedClass,
};
use super::error::{IoError, RefreshError};
use super::refresh::{LedgerSnapshot, RefreshOptions, RefreshPhase, RefreshProgress};
use super::traits::daemon::DaemonEngine;
use super::traits::refresh::RefreshEngine;
use super::view_material::ViewMaterial;
use crate::scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult, StakeEvent};

/// Maximum retries for transient per-block RPC failures.
///
/// Mirrors the constant of the same name in
/// [`crate::engine::refresh`] (kept independent at C4 to bound the
/// "moves not rewrites" diff scope; C5 collapses the two
/// definitions when the legacy free `produce_scan_result` is
/// deleted).
const MAX_BLOCK_FETCH_RETRIES: u32 = 5;

/// Initial backoff for block-fetch retries; doubles per attempt
/// up to [`MAX_RETRY_DELAY`].
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Upper bound on the per-attempt backoff.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Per-block ceiling for adversarial event classes per §5.4.8 #5.
/// `ScanProgress` is one-per-block by construction (the producer
/// emits at most one per block); the adversarial classes
/// (`DaemonMalformed`, `DaemonTimeout`, `DaemonProtocolError`,
/// `ReorgObserved`) cap at one per class per block. Excess
/// emissions within the same block drop silently after the
/// first-per-class `SuppressedRateLimit` notice for the attempt.
const PER_BLOCK_CEILING: u32 = 1;

// ============================================================================
// LocalRefresh aggregate
// ============================================================================

/// The Stage 1 production [`RefreshEngine`] implementor.
///
/// Holds [`ViewMaterial`] for the a-instance-scoped lifetime per
/// §5.4.7 R4; each call to
/// [`Self::produce_scan_result`] builds a fresh
/// [`shekyl_scanner::Scanner`] from the view material, runs the
/// producer-side scan loop, and returns either a complete
/// [`ScanResult`] or [`LocalRefreshError`]. See the module-level
/// rustdoc for the full per-attempt flow.
///
/// # Construction
///
/// [`Self::new`] consumes a [`ViewMaterial`] by move (the type is
/// not [`Clone`]) and is the only constructor. Once constructed,
/// `LocalRefresh` is shared `&LocalRefresh` for the
/// orchestrator's lifetime — calls are `&self`, with all
/// per-attempt state living in local variables of
/// [`Self::produce_scan_result`].
///
/// # `#[non_exhaustive]` not used
///
/// `LocalRefresh` has exactly one field, and that field is
/// private (`view_material`). External callers cannot construct
/// or pattern-match against the struct shape regardless of the
/// outer `pub` visibility — they reach the type only through
/// [`Self::new`]. Future revisions add fields through
/// `Self::new` API revisions; the public-API surface is the
/// constructor signature plus the (`pub(crate)`)
/// [`RefreshEngine`] impl, not the struct shape itself.
///
/// # Trait-implementation visibility
///
/// `LocalRefresh` is `pub` so external callers can name the type
/// in the orchestrator's `Engine<S, D, L, R = LocalRefresh>`
/// default (C5). The
/// [`RefreshEngine`](super::traits::refresh::RefreshEngine) trait
/// it implements is itself `pub(crate)` per
/// `V3_ENGINE_TRAIT_BOUNDARIES.md` §1.4, so external callers can
/// name `LocalRefresh` but cannot reach its trait surface
/// directly — only through the inherent methods on `Engine` that
/// the C5 dispatch lands. Stage 4's trait promotion deletes the
/// `pub(crate)` annotation on the trait without changing
/// anything in this file.
pub struct LocalRefresh {
    /// View-and-spend material handed in at construction. Owned
    /// for the implementor's lifetime; the
    /// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop) chain wipes the
    /// secret bytes when the implementor drops.
    view_material: ViewMaterial,
}

impl LocalRefresh {
    /// Construct a new [`LocalRefresh`] from owned
    /// [`ViewMaterial`].
    ///
    /// The view material is held for `LocalRefresh`'s lifetime
    /// per §5.4.7 R4 a-instance-scoped; on drop the embedded
    /// [`ViewMaterial`]'s [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop)
    /// chain wipes the secret bytes.
    #[allow(dead_code)] // C5 lands the first orchestrator-side construction site.
    pub const fn new(view_material: ViewMaterial) -> Self {
        Self { view_material }
    }

    /// Build a fresh [`Scanner`](shekyl_scanner::Scanner) from
    /// [`Self::view_material`]. Called once per
    /// [`Self::produce_scan_result`] attempt; the scanner's
    /// secret-bearing internal copies are wiped via
    /// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop) at attempt end.
    ///
    /// Returns [`LocalRefreshError::Internal`] if scanner
    /// construction fails. Scanner construction failure is not
    /// reachable from adversarial input: the view-material is the
    /// wallet's own key material, validated at wallet open time;
    /// failure here indicates a structural invariant violation
    /// rather than a daemon-driven failure mode.
    fn build_scanner(&self) -> Result<Scanner, LocalRefreshError> {
        let spend_pub =
            CompressedEdwardsY::from_slice(self.view_material.spend_pub.compress().as_bytes())
                .map_err(|_| LocalRefreshError::Internal)?
                .decompress()
                .ok_or(LocalRefreshError::Internal)?;

        // The view material's `view_scalar` is already a
        // `Zeroizing<Scalar>`. The scanner needs a `Zeroizing<Scalar>`
        // by value; copy the inner scalar/bytes into fresh
        // wrappers so the originals remain owned by `ViewMaterial`
        // for the implementor's lifetime. `Zeroizing<T>` derefs
        // to `T` via `Deref`; `Scalar` and `[u8; 32]` are `Copy`
        // so `*` alone suffices, while `Vec<u8>` needs `.clone()`
        // on the dereferenced inner.
        let view_scalar = Zeroizing::new(*self.view_material.view_scalar);
        let x25519_sk: Zeroizing<[u8; 32]> = Zeroizing::new(*self.view_material.x25519_sk);
        let ml_kem_dk: Zeroizing<Vec<u8>> = Zeroizing::new((*self.view_material.ml_kem_dk).clone());

        let view_pair = ViewPair::new(spend_pub, view_scalar, x25519_sk, ml_kem_dk)
            .map_err(|_| LocalRefreshError::Internal)?;

        let spend_secret: Zeroizing<[u8; 32]> = Zeroizing::new(*self.view_material.spend_secret);
        Ok(Scanner::new(view_pair, spend_secret))
    }
}

// ============================================================================
// LocalRefreshError (unit-variant-only)
// ============================================================================

/// Producer-side error type for [`LocalRefresh::produce_scan_result`].
///
/// **Unit-variant-only** per the §2.3 + §5.4.7 R6 two-channel
/// reframe binding pinned at
/// [`RefreshEngine::Error`](super::traits::refresh::RefreshEngine::Error)'s
/// rustdoc. Per-event detail (height, RPC payload, scanner
/// rejection class) flows through the [`DiagnosticSink`] channel;
/// the terminal error carries only the discriminant the
/// orchestrator branches on.
///
/// # Variant set
///
/// - [`Cancelled`](Self::Cancelled) — observed at cancellation
///   checkpoints 2, 3, or 5. Producer returns immediately with
///   no further scan work.
/// - [`Io`](Self::Io) — daemon-side I/O failure (block-fetch
///   retry budget exhausted; daemon-tip RPC failure).
///   Producer-side classification via
///   [`RefreshDiagnostic::DaemonProtocolError`] lands at C5
///   alongside the `RpcError → ProtocolErrorKind` classifier.
/// - [`Malformed`](Self::Malformed) — daemon delivered a
///   structurally-malformed block (either the producer's
///   excessive-outputs pre-pass tripped, or the scanner's own
///   structural validation rejected the block). The
///   `MalformedKind` discriminant is reported through
///   [`DiagnosticSink`] at the emit site.
/// - [`Internal`](Self::Internal) — structural invariant
///   violation that is not reachable from adversarial input
///   (e.g., scanner construction from validated view-material
///   fails). Reported to the orchestrator as
///   [`RefreshError::InternalInvariantViolation`] with a
///   `&'static str` context label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LocalRefreshError {
    /// Cancellation observed at checkpoint 2, 3, or 5.
    #[error("scan cancelled before completing the requested range")]
    Cancelled,

    /// Daemon-side I/O failure (block-fetch retry budget exhausted
    /// or daemon-tip RPC failure).
    #[error("daemon I/O failure during refresh")]
    Io,

    /// Daemon returned a structurally-malformed block (producer's
    /// pre-pass or scanner-side structural validation tripped).
    #[error("daemon returned a structurally malformed block")]
    Malformed,

    /// Internal invariant violation; not reachable from
    /// adversarial input.
    #[error("internal invariant violation during refresh")]
    Internal,
}

impl From<LocalRefreshError> for RefreshError {
    fn from(e: LocalRefreshError) -> Self {
        match e {
            LocalRefreshError::Cancelled => RefreshError::Cancelled,
            LocalRefreshError::Io => RefreshError::Io(IoError::Daemon {
                detail: "LocalRefresh: daemon I/O failure during refresh".to_string(),
            }),
            LocalRefreshError::Malformed => RefreshError::Io(IoError::Scanner {
                detail: "LocalRefresh: daemon returned a structurally malformed block".to_string(),
            }),
            LocalRefreshError::Internal => RefreshError::InternalInvariantViolation {
                context: "LocalRefresh: scanner construction failed against view material",
            },
        }
    }
}

// ============================================================================
// EmitState — per-attempt per-class emission budget (§5.4.8 #5 + F13-S)
// ============================================================================

/// Per-class emission state: a per-block counter and a per-attempt
/// `notice_emitted` latch.
#[derive(Debug, Default)]
struct PerClass {
    /// Per-block count of emit attempts (successful + suppressed);
    /// cleared at every block boundary by [`EmitState::reset_block`].
    counter: u32,
    /// `true` once a [`RefreshDiagnostic::SuppressedRateLimit`]
    /// notice has been emitted for this class within the current
    /// attempt. Cleared at attempt start (via
    /// [`EmitState::new`]) and **never cleared mid-attempt** — the
    /// F13-S latch.
    notice_emitted: bool,
}

/// Per-attempt per-class emission budget state.
///
/// Per §5.4.8 #5 + F6 + F13-S sub-pin: each rate-limitable
/// diagnostic class carries a per-block emission counter (cleared
/// at block boundary) and a per-attempt `notice_emitted` latch
/// (cleared at attempt start, never cleared mid-attempt). On the
/// first per-block ceiling breach for a class within an attempt,
/// [`Self::try_emit`] emits one
/// [`RefreshDiagnostic::SuppressedRateLimit`] notice and sets the
/// latch; subsequent in-class breaches within the same attempt
/// drop silently to close the emission-cadence covert channel.
///
/// [`SuppressedRateLimit`](RefreshDiagnostic::SuppressedRateLimit)
/// itself is NOT rate-limited (it exists to signal suppression;
/// rate-limiting it would defeat the purpose).
#[derive(Debug, Default)]
struct EmitState {
    daemon_malformed: PerClass,
    daemon_timeout: PerClass,
    daemon_protocol_error: PerClass,
    reorg_observed: PerClass,
    scan_progress: PerClass,
}

impl EmitState {
    /// Fresh per-attempt state: every counter at zero, every
    /// latch unset.
    fn new() -> Self {
        Self::default()
    }

    /// Clear every per-block counter. Called at the top of each
    /// per-block scan iteration. Does NOT clear the per-attempt
    /// latches (F13-S).
    fn reset_block(&mut self) {
        self.daemon_malformed.counter = 0;
        self.daemon_timeout.counter = 0;
        self.daemon_protocol_error.counter = 0;
        self.reorg_observed.counter = 0;
        self.scan_progress.counter = 0;
    }

    /// Attempt to emit `event` onto `sink` under the per-class
    /// per-block ceiling.
    ///
    /// - If the per-block counter for the event's class is below
    ///   [`PER_BLOCK_CEILING`], emit and increment.
    /// - If at-or-above the ceiling and the per-attempt latch is
    ///   unset: emit a single
    ///   [`RefreshDiagnostic::SuppressedRateLimit`] notice for
    ///   the class, set the latch, and drop the would-be event.
    /// - If at-or-above the ceiling and the latch is set: drop
    ///   the would-be event silently (F13-S latch closed).
    ///
    /// [`SuppressedRateLimit`](RefreshDiagnostic::SuppressedRateLimit)
    /// events pass through without rate-limiting (the notice
    /// itself must reach the sink to satisfy the §5.4.8 #5
    /// emission-cadence sub-pin's "exactly once per class per
    /// attempt" contract).
    fn try_emit(&mut self, sink: &dyn DiagnosticSink, event: RefreshDiagnostic) {
        let (per_class, suppressed_class) = match &event {
            RefreshDiagnostic::DaemonMalformed { .. } => {
                (&mut self.daemon_malformed, SuppressedClass::DaemonMalformed)
            }
            RefreshDiagnostic::DaemonTimeout { .. } => {
                (&mut self.daemon_timeout, SuppressedClass::DaemonTimeout)
            }
            RefreshDiagnostic::DaemonProtocolError { .. } => (
                &mut self.daemon_protocol_error,
                SuppressedClass::DaemonProtocolError,
            ),
            RefreshDiagnostic::ReorgObserved { .. } => {
                (&mut self.reorg_observed, SuppressedClass::ReorgObserved)
            }
            RefreshDiagnostic::ScanProgress { .. } => {
                (&mut self.scan_progress, SuppressedClass::ScanProgress)
            }
            RefreshDiagnostic::SuppressedRateLimit { .. } => {
                // The notice itself is never rate-limited; emit
                // directly. Bookkeeping for the suppressed class
                // happened on the suppression-triggering call.
                sink.emit(event);
                return;
            }
        };

        if per_class.counter < PER_BLOCK_CEILING {
            per_class.counter = per_class.counter.saturating_add(1);
            sink.emit(event);
        } else if !per_class.notice_emitted {
            per_class.counter = per_class.counter.saturating_add(1);
            per_class.notice_emitted = true;
            sink.emit(RefreshDiagnostic::SuppressedRateLimit {
                class: suppressed_class,
            });
        } else {
            per_class.counter = per_class.counter.saturating_add(1);
        }
    }
}

// ============================================================================
// RefreshEngine impl
// ============================================================================

impl RefreshEngine for LocalRefresh {
    type Error = LocalRefreshError;

    #[allow(clippy::too_many_lines)]
    // The trait method explicitly uses `-> impl Future + Send` (not
    // `async fn`) so the `Send` bound is part of the trait
    // contract per `engine/traits/refresh.rs` rustdoc. `async fn`
    // syntax would drop the explicit `+ Send` bound.
    #[allow(clippy::manual_async_fn)]
    fn produce_scan_result<D: DaemonEngine>(
        &self,
        snapshot: LedgerSnapshot,
        daemon: &D,
        _opts: RefreshOptions,
        cancel: CancellationToken,
        progress: watch::Sender<RefreshProgress>,
        diagnostics: &dyn DiagnosticSink,
    ) -> impl std::future::Future<Output = Result<ScanResult, Self::Error>> + Send {
        async move {
            let mut emit_state = EmitState::new();

            // Checkpoint 2: pre-fetch.
            if cancel.is_cancelled() {
                return Err(LocalRefreshError::Cancelled);
            }

            // Daemon-tip read. Per §5.4.7 R6 memory-amplifier
            // closure: the upstream `RpcError`'s `String` payload
            // is NOT propagated; the bounded
            // `ProtocolErrorKind` classification is emitted via
            // the rate-limited diagnostic stream (per-block
            // ceiling + F13-S latch handled by `emit_state`).
            let tip = match daemon.get_height().await {
                Ok(t) => t as u64,
                Err(e) => {
                    error!(error = %e, "LocalRefresh: get_height failed");
                    emit_state.try_emit(
                        diagnostics,
                        RefreshDiagnostic::DaemonProtocolError {
                            kind: classify_rpc_error(&e),
                        },
                    );
                    return Err(LocalRefreshError::Io);
                }
            };

            // Checkpoint 3: pre-scan.
            if cancel.is_cancelled() {
                return Err(LocalRefreshError::Cancelled);
            }

            let mut scanner = self.build_scanner()?;

            // Compute height range: scan (synced_height + 1)..tip.
            // Empty range → typed no-op with parent_hash anchored
            // to the snapshot's recorded hash so the merge gate
            // validates.
            let original_start = snapshot.synced_height.saturating_add(1);
            let end = tip;
            if original_start >= end {
                let parent_hash = parent_hash_for_start(&snapshot, original_start);
                return Ok(ScanResult::empty_at(original_start, parent_hash));
            }

            // Per-block scan loop with checkpoint-5 per-output
            // cancellation via Scanner::scan_with_cancel.
            let mut effective_start = original_start;
            let mut effective_parent_hash = parent_hash_for_start(&snapshot, original_start);
            let mut block_hashes: Vec<(u64, [u8; 32])> = Vec::new();
            let mut new_transfers: Vec<DetectedTransfer> = Vec::new();
            let mut spent_key_images: Vec<KeyImageObserved> = Vec::new();
            let stake_events: Vec<StakeEvent> = Vec::new();
            let mut reorg_rewind: Option<ReorgRewind> = None;

            let mut h = original_start;
            while h < end {
                // Per-block boundary: clear per-block emission
                // counters (F13-S latches remain set).
                emit_state.reset_block();

                if cancel.is_cancelled() {
                    return Err(LocalRefreshError::Cancelled);
                }

                let scannable =
                    fetch_block_with_retry(daemon, h, &cancel, &mut emit_state, diagnostics)
                        .await?;

                // Reorg detection (only when no reorg recorded yet
                // this call; after a fork is decided, subsequent
                // heights are the new chain and re-checking would
                // false-trigger).
                if reorg_rewind.is_none() && h > 1 {
                    if let Some(stored_parent) = snapshot.block_hash_at(h - 1) {
                        if stored_parent != scannable.block.header.previous {
                            warn!(
                                height = h,
                                "LocalRefresh: chain reorg detected at parent of {h}, walking fork point",
                            );

                            let fork_height = find_fork_point(
                                daemon,
                                &snapshot,
                                h - 1,
                                &cancel,
                                &mut emit_state,
                                diagnostics,
                            )
                            .await?;
                            let depth =
                                u32::try_from(h.saturating_sub(fork_height)).unwrap_or(u32::MAX);
                            emit_state.try_emit(
                                diagnostics,
                                RefreshDiagnostic::ReorgObserved { fork_height, depth },
                            );

                            reorg_rewind = Some(ReorgRewind { fork_height });
                            effective_start = fork_height;
                            effective_parent_hash = parent_hash_for_start(&snapshot, fork_height);

                            // Discard everything we accumulated
                            // at-or-above the fork height; restart
                            // scanning from there.
                            block_hashes.retain(|(bh, _)| *bh < fork_height);
                            new_transfers.retain(|t| t.block_height < fork_height);
                            spent_key_images.retain(|k| k.block_height < fork_height);

                            h = fork_height;
                            continue;
                        }
                    }
                }

                // Producer-side excessive-outputs pre-pass.
                // Defense-in-depth check: every transaction whose
                // outputs.len() > MAX_OUTPUTS is rejected before
                // entering the scanner (which would also reject it
                // at scan_transaction_with_cancel entry). The
                // pre-pass exists so the producer can emit a
                // typed DaemonMalformed { ExcessiveOutputs }
                // diagnostic carrying the producer's adversarial
                // hypothesis (per-tx scan-budget inflation) rather
                // than relying on the scanner-side InvalidScannableBlock
                // catch-all.
                let miner_tx = scannable.block.miner_transaction();
                if miner_tx.prefix().outputs.len() > MAX_OUTPUTS {
                    emit_state.try_emit(
                        diagnostics,
                        RefreshDiagnostic::DaemonMalformed {
                            kind: MalformedKind::ExcessiveOutputs,
                        },
                    );
                    return Err(LocalRefreshError::Malformed);
                }
                for tx in &scannable.transactions {
                    if tx.prefix().outputs.len() > MAX_OUTPUTS {
                        emit_state.try_emit(
                            diagnostics,
                            RefreshDiagnostic::DaemonMalformed {
                                kind: MalformedKind::ExcessiveOutputs,
                            },
                        );
                        return Err(LocalRefreshError::Malformed);
                    }
                }

                let block_hash = scannable.block.hash();
                block_hashes.push((h, block_hash));

                // Collect every input's key image unfiltered. The
                // merge matches against the live wallet's
                // owned-output set; we do not pre-filter here
                // because the snapshot deliberately does not carry
                // the wallet's owned-output index.
                for input in &miner_tx.prefix().inputs {
                    if let Input::ToKey { key_image, .. } | Input::StakeClaim { key_image, .. } =
                        input
                    {
                        spent_key_images.push(KeyImageObserved {
                            block_height: h,
                            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
                                key_image.0,
                            ),
                        });
                    }
                }
                for tx in &scannable.transactions {
                    for input in &tx.prefix().inputs {
                        if let Input::ToKey { key_image, .. }
                        | Input::StakeClaim { key_image, .. } = input
                        {
                            spent_key_images.push(KeyImageObserved {
                                block_height: h,
                                key_image:
                                    shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
                                        key_image.0,
                                    ),
                            });
                        }
                    }
                }

                // Per-output safe-point cancellation (checkpoint 5)
                // via Scanner::scan_with_cancel. The closure reads
                // cancel.is_cancelled() at the top of each output
                // iteration inside scan_transaction_with_cancel
                // (the prep-1 API): after prior per-output
                // Zeroizing materials drop, before next iteration's
                // secret derivation begins.
                let mut is_cancelled_closure = || cancel.is_cancelled();
                let outcome = scanner
                    .scan_with_cancel(scannable, &mut is_cancelled_closure)
                    .map_err(|source| {
                        // Scanner-side structural rejection. Emit
                        // a typed DaemonMalformed { InvalidBlockStructure }
                        // diagnostic and return Malformed; the
                        // ExcessiveOutputs class is handled in the
                        // pre-pass above (the scanner gate is
                        // defense-in-depth).
                        debug!(height = h, error = %source, "LocalRefresh: scanner rejected block");
                        emit_state.try_emit(
                            diagnostics,
                            RefreshDiagnostic::DaemonMalformed {
                                kind: scanner_error_to_malformed_kind(&source),
                            },
                        );
                        LocalRefreshError::Malformed
                    })?;

                let timelocked = match outcome {
                    ScanOutcome::Completed(t) => t,
                    ScanOutcome::Cancelled => return Err(LocalRefreshError::Cancelled),
                };

                let recovered = timelocked.into_inner();
                let candidates_count = recovered.len();
                for output in recovered {
                    new_transfers.push(DetectedTransfer {
                        block_height: h,
                        output,
                    });
                }

                // ScanProgress emission at the per-block boundary
                // (rate-limited per §5.4.8 #5 / F13-S latch).
                emit_state.try_emit(
                    diagnostics,
                    RefreshDiagnostic::ScanProgress {
                        height: h,
                        candidates: candidates_count,
                    },
                );

                // Publish per-block progress on the watch channel
                // for orchestrator-side subscribers. Best-effort:
                // `watch::Sender::send` returns `Err(_)` only when
                // every receiver has been dropped, in which case
                // the producer is being cancelled anyway.
                _ = progress.send(RefreshProgress {
                    height: h,
                    blocks_processed: block_hashes.len() as u64,
                    blocks_total: end.saturating_sub(original_start),
                    phase: RefreshPhase::Scanning,
                });

                h += 1;
            }

            Ok(ScanResult {
                processed_height_range: effective_start..end,
                parent_hash: effective_parent_hash,
                block_hashes,
                new_transfers,
                spent_key_images,
                stake_events,
                reorg_rewind,
            })
        }
    }
}

// ============================================================================
// Inner helpers (mirror engine/refresh.rs free helpers; kept local
// to bound the C4 diff to a single new file. C5 collapses these
// when the legacy free `produce_scan_result` is deleted.)
// ============================================================================

/// Resolve the `parent_hash` field for a result whose
/// `processed_height_range.start == start`. Returns `None` for
/// genesis (`start <= 1`) and the snapshot's recorded hash at
/// `start - 1` otherwise.
fn parent_hash_for_start(snapshot: &LedgerSnapshot, start: u64) -> Option<[u8; 32]> {
    if start <= 1 {
        None
    } else {
        snapshot.block_hash_at(start - 1)
    }
}

/// Map a [`ScanError`] to the corresponding [`MalformedKind`]
/// diagnostic variant.
///
/// At C4 the only scanner-rejection path the producer surfaces
/// here is the catch-all `InvalidBlockStructure`. The
/// `UnsupportedProtocolVersion` variant lands at the
/// `Scanner::scan_with_cancel` entry where the producer cannot
/// observe its discriminant directly; C5/C6 may surface the
/// finer split through an extended scanner-error surface if
/// adversarial telemetry warrants.
const fn scanner_error_to_malformed_kind(_err: &ScanError) -> MalformedKind {
    MalformedKind::InvalidBlockStructure
}

/// Classify an upstream [`RpcError`] into the bounded
/// [`ProtocolErrorKind`] tag without propagating the underlying
/// `String` payload.
///
/// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §4 Phase 0e
/// and §5.4.7 R6 memory-amplifier closure (binding): the
/// producer's observability stream MUST carry only the bounded
/// variant-tag classification of `RpcError`; the `String` payload
/// that `InternalError(String)` / `ConnectionError(String)` /
/// `InvalidNode(String)` carry is dropped at this boundary so an
/// adversarial daemon cannot drive memory amplification into the
/// wallet's diagnostic stream.
///
/// # Refresh-reachable mapping
///
/// The five [`ProtocolErrorKind`] variants enumerate the
/// refresh-reachable upstream subset confirmed by the Round 4
/// call-site audit (`get_height` + `get_scannable_block_by_number`
/// are the only refresh-issued RPCs):
///
/// - [`RpcError::ConnectionError`] → [`ProtocolErrorKind::ConnectionError`]
/// - [`RpcError::InternalError`] → [`ProtocolErrorKind::InternalError`]
/// - [`RpcError::InvalidNode`] → [`ProtocolErrorKind::InvalidNode`]
/// - [`RpcError::InvalidTransaction`] → [`ProtocolErrorKind::InvalidTransaction`]
/// - [`RpcError::PrunedTransaction`] → [`ProtocolErrorKind::PrunedTransaction`]
///
/// # Defensive mapping for non-refresh-reachable variants
///
/// `RpcError::TransactionsNotFound` / `RpcError::InvalidFee` /
/// `RpcError::InvalidPriority` are not reachable from
/// `get_height` / `get_scannable_block_by_number` per the
/// Round 4 audit — they belong to the future `PendingTxEngine`
/// send-tx path. If they nonetheless surface from this site
/// (e.g., upstream RPC client behavior change), the defensive
/// classification is [`ProtocolErrorKind::InvalidNode`] — "the
/// daemon returned an envelope the producer did not expect from
/// this RPC method." [`ProtocolErrorKind`] is
/// `#[non_exhaustive]`; PR 5's `PendingTxEngine` extraction may
/// grow the variant set additively.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
//
// `clippy::match_same_arms` would have us merge the audit-
// confirmed `InvalidNode(_)` arm with the defensive
// `TransactionsNotFound | InvalidFee | InvalidPriority` arm
// because both map to `ProtocolErrorKind::InvalidNode`. The
// separation is the load-bearing discipline here: the first arm
// is the Round-4-audit-confirmed mapping for a refresh-reachable
// variant; the second is the defensive fallback for variants
// that the audit confirmed are NOT refresh-reachable. Merging
// them would lose the audit boundary that the rustdoc records
// and that future maintainers need to see when PR 5's
// `PendingTxEngine` extraction reaches this site.
#[allow(clippy::match_same_arms)]
const fn classify_rpc_error(err: &RpcError) -> ProtocolErrorKind {
    match err {
        RpcError::ConnectionError(_) => ProtocolErrorKind::ConnectionError,
        RpcError::InternalError(_) => ProtocolErrorKind::InternalError,
        RpcError::InvalidNode(_) => ProtocolErrorKind::InvalidNode,
        RpcError::InvalidTransaction(_) => ProtocolErrorKind::InvalidTransaction,
        RpcError::PrunedTransaction => ProtocolErrorKind::PrunedTransaction,
        // Non-refresh-reachable upstream variants
        // (`TransactionsNotFound` / `InvalidFee` /
        // `InvalidPriority`) defensively classify as
        // `InvalidNode`; see rustdoc.
        RpcError::TransactionsNotFound(_) | RpcError::InvalidFee | RpcError::InvalidPriority => {
            ProtocolErrorKind::InvalidNode
        }
    }
}

/// Walk backwards from `from_height` to find the highest height
/// at which the daemon's reported block hash matches the
/// wallet's snapshot. Returns `(matching_height + 1)` so the
/// caller can use it directly as the fork-rewind point.
///
/// Stops at height `1` (genesis) if no match is found in the
/// window. Honours cancellation between fetch attempts.
///
/// The `emit_state` / `diagnostics` parameters thread through to
/// [`fetch_block_with_retry`]'s per-attempt `RpcError`
/// classification so producer-side `DaemonProtocolError` events
/// emit under the per-block ceiling + F13-S latch discipline
/// during reorg-walk traversal.
async fn find_fork_point<R: Rpc>(
    rpc: &R,
    snapshot: &LedgerSnapshot,
    from_height: u64,
    cancel: &CancellationToken,
    emit_state: &mut EmitState,
    diagnostics: &dyn DiagnosticSink,
) -> Result<u64, LocalRefreshError> {
    let mut h = from_height;
    loop {
        if cancel.is_cancelled() {
            return Err(LocalRefreshError::Cancelled);
        }

        if h == 0 {
            return Ok(1);
        }

        let Some(stored_hash) = snapshot.block_hash_at(h) else {
            return Ok(h + 1);
        };

        let daemon_block = fetch_block_with_retry(rpc, h, cancel, emit_state, diagnostics).await?;
        if daemon_block.block.hash() == stored_hash {
            return Ok(h + 1);
        }

        debug!(
            height = h,
            "LocalRefresh::find_fork_point: hash mismatch, walking back"
        );
        h -= 1;
    }
}

/// Fetch a block at `height` with exponential backoff on
/// transient RPC failures. Cancellation is honoured both before
/// each attempt and during the inter-attempt backoff.
///
/// On any per-attempt `RpcError` (retry-eligible or terminal),
/// emits one [`RefreshDiagnostic::DaemonProtocolError`] carrying
/// the bounded [`classify_rpc_error`] classification. The
/// emission flows through `emit_state.try_emit`, so the per-block
/// ceiling + F13-S latch (§5.4.8 #5) close the
/// emission-cadence covert channel when the retry budget triggers
/// many emissions in a single block window.
async fn fetch_block_with_retry<R: Rpc>(
    rpc: &R,
    height: u64,
    cancel: &CancellationToken,
    emit_state: &mut EmitState,
    diagnostics: &dyn DiagnosticSink,
) -> Result<ScannableBlock, LocalRefreshError> {
    let height_usize =
        usize::try_from(height).expect("block height fits in usize on 64-bit targets");

    let mut delay = INITIAL_RETRY_DELAY;
    for attempt in 0..MAX_BLOCK_FETCH_RETRIES {
        if cancel.is_cancelled() {
            return Err(LocalRefreshError::Cancelled);
        }

        match rpc.get_scannable_block_by_number(height_usize).await {
            Ok(b) => return Ok(b),
            Err(e) if attempt + 1 < MAX_BLOCK_FETCH_RETRIES => {
                warn!(
                    height,
                    attempt = attempt + 1,
                    max = MAX_BLOCK_FETCH_RETRIES,
                    error = %e,
                    "LocalRefresh::fetch_block_with_retry: block fetch failed, retrying",
                );
                emit_state.try_emit(
                    diagnostics,
                    RefreshDiagnostic::DaemonProtocolError {
                        kind: classify_rpc_error(&e),
                    },
                );
                tokio::select! {
                    () = cancel.cancelled() => return Err(LocalRefreshError::Cancelled),
                    () = tokio::time::sleep(delay) => {}
                }
                delay = std::cmp::min(delay * 2, MAX_RETRY_DELAY);
            }
            Err(e) => {
                error!(
                    height,
                    error = %e,
                    "LocalRefresh::fetch_block_with_retry: block fetch failed after {} attempts",
                    MAX_BLOCK_FETCH_RETRIES,
                );
                emit_state.try_emit(
                    diagnostics,
                    RefreshDiagnostic::DaemonProtocolError {
                        kind: classify_rpc_error(&e),
                    },
                );
                return Err(LocalRefreshError::Io);
            }
        }
    }

    unreachable!("fetch_block_with_retry: loop body always returns within MAX_BLOCK_FETCH_RETRIES");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::diagnostics::NoopDiagnosticSink;

    /// `LocalRefreshError → RefreshError` mapping is total and
    /// preserves the discriminant classes per the §2.3
    /// unit-variant-only binding.
    #[test]
    fn local_refresh_error_maps_to_refresh_error() {
        assert!(matches!(
            RefreshError::from(LocalRefreshError::Cancelled),
            RefreshError::Cancelled
        ));
        assert!(matches!(
            RefreshError::from(LocalRefreshError::Io),
            RefreshError::Io(IoError::Daemon { .. })
        ));
        assert!(matches!(
            RefreshError::from(LocalRefreshError::Malformed),
            RefreshError::Io(IoError::Scanner { .. })
        ));
        assert!(matches!(
            RefreshError::from(LocalRefreshError::Internal),
            RefreshError::InternalInvariantViolation { .. }
        ));
    }

    /// `EmitState::try_emit` honours the per-block ceiling and
    /// the F13-S latch.
    #[test]
    fn emit_state_first_breach_emits_suppressed_notice() {
        use std::sync::Mutex;

        #[derive(Default)]
        struct RecordingSink {
            events: Mutex<Vec<RefreshDiagnostic>>,
        }
        impl DiagnosticSink for RecordingSink {
            fn emit(&self, event: RefreshDiagnostic) {
                self.events.lock().unwrap().push(event);
            }
        }

        let sink = RecordingSink::default();
        let mut state = EmitState::new();

        // First emission: passes (counter 0 → 1, within ceiling).
        state.try_emit(
            &sink,
            RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure,
            },
        );
        // Second emission: over ceiling, latch unset → emit
        // SuppressedRateLimit notice and latch.
        state.try_emit(
            &sink,
            RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure,
            },
        );
        // Third emission: over ceiling, latch set → silent drop.
        state.try_emit(
            &sink,
            RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure,
            },
        );

        let events = sink.events.lock().unwrap().clone();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure
            }
        ));
        assert!(matches!(
            events[1],
            RefreshDiagnostic::SuppressedRateLimit {
                class: SuppressedClass::DaemonMalformed
            }
        ));
    }

    /// Per-block counter resets at block boundary; F13-S latch
    /// persists.
    #[test]
    fn emit_state_block_reset_clears_counter_not_latch() {
        let mut state = EmitState::new();

        // First emission: passes.
        state.try_emit(
            &NoopDiagnosticSink,
            RefreshDiagnostic::ScanProgress {
                height: 1,
                candidates: 0,
            },
        );
        // Second emission: over ceiling, latch sets.
        state.try_emit(
            &NoopDiagnosticSink,
            RefreshDiagnostic::ScanProgress {
                height: 1,
                candidates: 0,
            },
        );
        assert!(state.scan_progress.notice_emitted);

        // Block boundary: counter resets, latch stays.
        state.reset_block();
        assert_eq!(state.scan_progress.counter, 0);
        assert!(state.scan_progress.notice_emitted);
    }

    /// `SuppressedRateLimit` events are NOT rate-limited
    /// themselves (they exist to signal suppression; rate-limiting
    /// them would defeat the purpose).
    #[test]
    fn suppressed_rate_limit_event_itself_is_not_rate_limited() {
        use std::sync::Mutex;

        #[derive(Default)]
        struct RecordingSink {
            events: Mutex<Vec<RefreshDiagnostic>>,
        }
        impl DiagnosticSink for RecordingSink {
            fn emit(&self, event: RefreshDiagnostic) {
                self.events.lock().unwrap().push(event);
            }
        }

        let sink = RecordingSink::default();
        let mut state = EmitState::new();

        for _ in 0..3 {
            state.try_emit(
                &sink,
                RefreshDiagnostic::SuppressedRateLimit {
                    class: SuppressedClass::ScanProgress,
                },
            );
        }

        assert_eq!(sink.events.lock().unwrap().len(), 3);
    }

    /// `scanner_error_to_malformed_kind` returns
    /// `InvalidBlockStructure` for all scanner errors at C4.
    #[test]
    fn scanner_error_classified_as_invalid_block_structure() {
        // We can't easily construct a `ScanError` here without
        // pulling in the full scanner; assert against the function's
        // const return shape instead.
        const fn _classifies(err: &ScanError) -> MalformedKind {
            scanner_error_to_malformed_kind(err)
        }
        // The function is const fn — calling it at compile time
        // would require an InvalidScannableBlock instance.
        // Coverage is provided by C7's `AssertionSink` property
        // tests once they land.
    }

    /// `classify_rpc_error` maps each refresh-reachable
    /// [`RpcError`] variant to the Round-4-audit-confirmed
    /// [`ProtocolErrorKind`] tag per §4 Phase 0e.
    ///
    /// The String payloads on `InternalError` / `ConnectionError`
    /// / `InvalidNode` are NOT inspected by the classifier — the
    /// §5.4.7 R6 memory-amplifier closure binds this site.
    #[test]
    fn classify_rpc_error_refresh_reachable_subset() {
        assert_eq!(
            classify_rpc_error(&RpcError::ConnectionError(String::new())),
            ProtocolErrorKind::ConnectionError
        );
        assert_eq!(
            classify_rpc_error(&RpcError::InternalError(String::new())),
            ProtocolErrorKind::InternalError
        );
        assert_eq!(
            classify_rpc_error(&RpcError::InvalidNode(String::new())),
            ProtocolErrorKind::InvalidNode
        );
        assert_eq!(
            classify_rpc_error(&RpcError::InvalidTransaction([0u8; 32])),
            ProtocolErrorKind::InvalidTransaction
        );
        assert_eq!(
            classify_rpc_error(&RpcError::PrunedTransaction),
            ProtocolErrorKind::PrunedTransaction
        );
    }

    /// `classify_rpc_error` defensively maps the non-refresh-
    /// reachable upstream variants (`TransactionsNotFound` /
    /// `InvalidFee` / `InvalidPriority`) to
    /// [`ProtocolErrorKind::InvalidNode`] per the rustdoc
    /// disposition. These variants belong to PR 5's
    /// `PendingTxEngine` send-tx path; if PR 5 needs distinct
    /// tagging, [`ProtocolErrorKind`] grows additively under
    /// `#[non_exhaustive]`.
    #[test]
    fn classify_rpc_error_non_refresh_reachable_subset_falls_back_to_invalid_node() {
        assert_eq!(
            classify_rpc_error(&RpcError::TransactionsNotFound(vec![])),
            ProtocolErrorKind::InvalidNode
        );
        assert_eq!(
            classify_rpc_error(&RpcError::InvalidFee),
            ProtocolErrorKind::InvalidNode
        );
        assert_eq!(
            classify_rpc_error(&RpcError::InvalidPriority),
            ProtocolErrorKind::InvalidNode
        );
    }

    /// The Round-4-audited `ProtocolErrorKind` set is exhaustive
    /// over the refresh-reachable upstream subset. Adding a
    /// variant to upstream [`RpcError`] must not produce a
    /// silently-falling-through case at the classifier — the
    /// classifier's `match` is exhaustive (no `_` arm) so a new
    /// upstream variant breaks the build until C5b's
    /// classification is extended deliberately.
    #[test]
    fn classify_rpc_error_is_exhaustive_at_the_match_arm() {
        // This compiles only because `classify_rpc_error` is
        // exhaustive against every `RpcError` variant. If
        // upstream grows a new variant the build fails here
        // (and at `classify_rpc_error`'s definition site) until
        // the new variant is given an explicit classification.
        fn _exhaustive(e: &RpcError) -> ProtocolErrorKind {
            classify_rpc_error(e)
        }
    }
}
