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
use shekyl_rpc_client::RpcError;
use shekyl_scanner::{ScanError, ScanOutcome, ScannableBlock, Scanner, ViewPair, MAX_OUTPUTS};
use shekyl_types::PCanonicalId;
use shekyl_wire::Input;
use std::collections::BTreeMap;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

use super::curve_tree_decode;
use super::diagnostics::{
    DiagnosticSink, MalformedKind, ProtocolErrorKind, RefreshDiagnostic, SuppressedClass,
};
use super::error::{IoError, RefreshError};
use super::refresh::{LedgerSnapshot, RefreshOptions, RefreshPhase, RefreshProgress};
use super::traits::daemon::DaemonEngine;
use super::traits::refresh::RefreshEngine;
use super::view_material::ViewMaterial;
use crate::engine::bond_watch::sightings_in;
use crate::scan::{
    BondSightingObserved, DetectedTransfer, KeyImageObserved, OwnedTxLeaves, ReorgRewind,
    ScanResult,
};

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

/// Upper bound on intra-attempt reorg rewinds absorbed by a single
/// `produce_scan_result` call. Each detected reorg rewinds `h` backward,
/// so an *unbounded* count would let a daemon that reorgs between every
/// pair of fetches — a reorg storm, or a hostile daemon deliberately
/// spinning the wallet — stall one attempt forever. The common real case
/// is a single reorg per attempt; this budget covers legitimate
/// multi-reorg bursts while the bound guarantees termination.
///
/// Detection stays armed past the budget; only *rewinding* is bounded. A
/// reorg detected with the budget spent **fails the attempt**
/// ([`LocalRefreshError::ReorgStorm`]) rather than scanning on with
/// detection disarmed: blocks accumulated blind would merge, and while
/// ledger state is reorg-rewindable at the next refresh, the bond watch's
/// sightings are not — adoption raises the monotone cursor permanently,
/// so a stale abandoned-fork sighting collected in a blind region would
/// pass the merge's O5 checks and burn cursor slots on fork-only
/// evidence. Failing the attempt keeps every consumer consistent; the
/// retry starts clean once the chain calms.
const MAX_REORG_REWINDS_PER_ATTEMPT: u32 = 8;

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
/// not [`Clone`]) and is the empty-watch constructor. The assemble
/// path uses [`Self::with_bond_watch`] to arm the probe-id map.
/// Once constructed, `LocalRefresh` is shared `&LocalRefresh` for
/// the orchestrator's lifetime — calls are `&self`, with all
/// per-attempt state living in local variables of
/// [`Self::produce_scan_result`].
///
/// # `#[non_exhaustive]` not used
///
/// Every `LocalRefresh` field is private (`view_material`,
/// `scan_start_floor`, `bond_watch`). External callers cannot
/// construct or pattern-match against the struct shape regardless
/// of the outer `pub` visibility — they reach the type only through
/// [`Self::new`] / [`Self::with_bond_watch`]. The public-API surface
/// is the constructor signatures plus the (`pub(crate)`)
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
    /// Minimum block height for the producer scan loop (wallet
    /// birthday + session overrides). Zero means scan from
    /// `synced_height + 1` only. The orchestrator anchors the ledger
    /// when this exceeds `synced_height + 1` before taking a
    /// snapshot; see [`super::scan_floor`].
    scan_start_floor: u64,
    /// The bond watch's candidate set (SA-R-6): persona canonical id →
    /// slot, inverted from the open-built `StakingBlock::persona_id_cache`
    /// (durably-retired slots already excluded at open). Public
    /// identifiers, no secret, no zeroize burden — but the id↔slot
    /// association is persona history, so the map never renders through
    /// `Debug` (the enclosing engine's hand-written `Debug` skips the
    /// refresh aggregate entirely). Empty for a wallet whose window has
    /// no cached ids; the per-block cost of a populated watch is a map
    /// lookup only for transactions that carry `Input::BondPost` (rare).
    bond_watch: BTreeMap<PCanonicalId, u32>,
}

impl LocalRefresh {
    /// Construct a [`LocalRefresh`] from owned [`ViewMaterial`] and the
    /// scan floor, with an empty bond watch. Test doubles and wrappers
    /// that do not reconstruct staking use this; assemble uses
    /// [`Self::with_bond_watch`] — EXCEPT when the sealed staking
    /// evidence is unreadable, where assemble deliberately falls back
    /// here: the retired refusal set is unknown, so an armed watch could
    /// re-adopt durably retired slots (see the open-time reconcile in
    /// `lifecycle.rs`).
    ///
    /// The view material is held for `LocalRefresh`'s lifetime
    /// per §5.4.7 R4 a-instance-scoped; on drop the embedded
    /// [`ViewMaterial`]'s [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop)
    /// chain wipes the secret bytes.
    pub const fn new(view_material: ViewMaterial, scan_start_floor: u64) -> Self {
        Self::with_bond_watch(view_material, scan_start_floor, BTreeMap::new())
    }

    /// Arm the principal scan's bond watch (SA-R-6): `id → slot` inverted
    /// from the open-built probe-id cache. The only production caller is
    /// `assemble`, the seam that already holds the cache.
    pub const fn with_bond_watch(
        view_material: ViewMaterial,
        scan_start_floor: u64,
        bond_watch: BTreeMap<PCanonicalId, u32>,
    ) -> Self {
        Self {
            view_material,
            scan_start_floor,
            bond_watch,
        }
    }

    /// Persisted/session scan floor wired at wallet open.
    pub(crate) const fn scan_start_floor(&self) -> u64 {
        self.scan_start_floor
    }

    /// Test-only oracle for the open path's watch gating: whether this
    /// instance was armed with a non-empty watch map. Production code
    /// never branches on this — the empty map already behaves as "off".
    #[cfg(test)]
    pub(crate) fn bond_watch_is_armed(&self) -> bool {
        !self.bond_watch.is_empty()
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

    /// A further reorg was detected after the per-attempt rewind budget
    /// (`MAX_REORG_REWINDS_PER_ATTEMPT`) was spent. The attempt aborts
    /// rather than scanning on with detection disarmed — see the budget
    /// constant's docs for why merging a blind region is unsound for the
    /// bond watch's monotone adoptions.
    #[error("reorg storm: rewind budget exhausted and the chain diverged again")]
    ReorgStorm,

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
            LocalRefreshError::ReorgStorm => RefreshError::Io(IoError::Daemon {
                detail: "LocalRefresh: reorg storm — the chain served by the daemon diverged \
                         again after the per-attempt rewind budget; retry when it stabilizes"
                    .to_string(),
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

            // Scan from the snapshot's `synced_height + 1`. The birthday
            // floor skip is realized entirely by the orchestrator's pre-scan
            // anchor (`scan_floor::ensure_birthday_anchor`), which advances
            // `synced_height` to the floor boundary — clamped to the daemon's
            // highest block — before this snapshot is taken. Deriving the
            // start from the anchored `synced_height` rather than re-applying
            // the floor against a freshly fetched tip keeps the start
            // gate-consistent (`start == synced_height + 1`) by construction:
            // a re-derivation could disagree with the anchored height if the
            // daemon advanced between the anchor's height read and this one,
            // breaking the merge gate.
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
            if original_start > 1 && effective_parent_hash.is_none() {
                // Boundary parent-hash fetch for a floored/birthday-anchored
                // start: the snapshot's reorg window doesn't carry the hash
                // at `original_start - 1`. Route through the same retry /
                // cancellation / diagnostic helper the per-block scan uses so
                // a transient failure here is retried with backoff rather than
                // terminating refresh as `Io` on the first error.
                let parent = fetch_block_with_retry(
                    daemon,
                    original_start - 1,
                    &cancel,
                    &mut emit_state,
                    diagnostics,
                )
                .await?;
                effective_parent_hash = Some(parent.block.hash());
            }
            let mut block_hashes: Vec<(u64, [u8; 32])> = Vec::new();
            let mut new_transfers: Vec<DetectedTransfer> = Vec::new();
            let mut spent_key_images: Vec<KeyImageObserved> = Vec::new();
            let mut bond_sightings: Vec<BondSightingObserved> = Vec::new();
            let mut sighted_slots: std::collections::BTreeSet<u32> =
                std::collections::BTreeSet::new();
            // The rewind target carried out to the merge (the *latest* fork, which
            // is always the correct one — `find_fork_point` re-measures divergence
            // from the fixed persisted window each call). `reorg_rewinds` bounds how
            // many times detection may re-fire this attempt (termination).
            let mut reorg_rewind: Option<ReorgRewind> = None;
            let mut reorg_rewinds: u32 = 0;
            // CT-5 §3.2 transit fields (A1 frozen-contract): the full per-block
            // leaf set and the consensus header `curve_tree_root`, materialized
            // here where the `ScannableBlock` is in hand and carried on
            // `ScanResult` for the merge-driven ingest (CT-5a commit 4).
            let mut block_leaves: Vec<(u64, Vec<OwnedTxLeaves>)> = Vec::new();
            let mut block_curve_tree_roots: Vec<(u64, [u8; 32])> = Vec::new();

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

                // Reorg detection via running prev-hash linkage. The
                // expected parent of `h` is the hash of `h - 1` from
                // wherever it was most recently seen: the block fetched
                // earlier *in this attempt* (a reorg can land between two
                // consecutive single-height fetches — the intra-attempt
                // straddle; each fetch is atomic, but atomic reads do not
                // make the *sequence* coherent), else the persisted reorg
                // window (a reorg that landed between attempts), else the
                // explicitly fetched boundary parent of a floored start.
                // The running-tail and window sources are disjoint by
                // construction (tail heights are > `synced_height`, the
                // window's are ≤ it).
                //
                // BOUND: up to `MAX_REORG_REWINDS_PER_ATTEMPT` reorgs are
                // absorbed per attempt, not just the first. Each detection
                // rewinds and re-scans; a *further* reorg landing during
                // that re-scan is caught the same way. This is sound
                // because the fork walk anchors at `synced_height`, so
                // every `fork_height <= synced_height + 1 <= every block
                // this attempt accumulated` — the `clear()` below therefore
                // empties the accumulators on every reorg, and the re-scan
                // re-derives `effective_start`, keeping the result
                // internally consistent no matter how many times detection
                // fires. Detection itself is NEVER disarmed: the counter
                // bounds only how many *rewinds* the attempt absorbs, and a
                // detection past the budget aborts the attempt (`ReorgStorm`
                // below) — scanning on blind would merge blocks no linkage
                // check vouched for, which the bond watch's monotone
                // sighting adoption cannot survive (a stale fork sighting
                // would pass O5 and burn cursor slots permanently).
                if h > 1 {
                    let expected_parent = match block_hashes.last() {
                        Some(&(prev_h, prev_hash)) if prev_h + 1 == h => Some(prev_hash),
                        _ => snapshot.block_hash_at(h - 1).or(if h == effective_start {
                            effective_parent_hash
                        } else {
                            None
                        }),
                    };
                    if let Some(expected_parent) = expected_parent {
                        if expected_parent != scannable.block.header.previous {
                            // Budget check FIRST: a further divergence with the
                            // rewind budget spent is the reorg-storm abort. The
                            // attempt merges nothing (all-or-nothing result), so
                            // no consumer sees the blind region.
                            if reorg_rewinds == MAX_REORG_REWINDS_PER_ATTEMPT {
                                warn!(
                                    height = h,
                                    max = MAX_REORG_REWINDS_PER_ATTEMPT,
                                    "LocalRefresh: reorg detected after the rewind budget was \
                                     spent; aborting the attempt (reorg storm)",
                                );
                                return Err(LocalRefreshError::ReorgStorm);
                            }
                            warn!(
                                height = h,
                                "LocalRefresh: chain reorg detected at parent of {h}, walking fork point",
                            );

                            // Anchor the fork-walk at the persisted-window
                            // top (`synced_height`), not `h - 1`. An
                            // intra-attempt straddle's fork can sit *above*
                            // the window, where `find_fork_point` (which
                            // walks only the window) would return
                            // `from_height + 1` immediately and splice
                            // *around* the fork instead of behind it.
                            // Anchoring at `synced_height` makes the
                            // conservative answer the attempt boundary:
                            // refetch the attempt range rather than keep
                            // possibly-stale intra-attempt blocks. The
                            // anchor is unconditionally `synced_height` (the
                            // window top), never `h - 1`, and this holds for
                            // *every* reorg this attempt, not only the first:
                            // the rewind target is where the current chain
                            // diverges from the persisted window — a function
                            // of window-vs-daemon alone, independent of the
                            // detection height `h` — and `find_fork_point`
                            // measures exactly that. It follows that every
                            // `fork_height <= synced_height + 1`, which is
                            // what makes the clear-and-re-scan below sound
                            // across repeated detection.
                            let fork_height = find_fork_point(
                                daemon,
                                &snapshot,
                                snapshot.synced_height,
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

                            // The latest fork wins: it is the current
                            // divergence-from-window, so it is the correct
                            // merge rewind target even after earlier reorgs.
                            reorg_rewind = Some(ReorgRewind { fork_height });
                            reorg_rewinds += 1;
                            if reorg_rewinds == MAX_REORG_REWINDS_PER_ATTEMPT {
                                warn!(
                                    fork_height,
                                    max = MAX_REORG_REWINDS_PER_ATTEMPT,
                                    "LocalRefresh: reorg-rewind budget spent; a further \
                                     divergence this attempt aborts as a reorg storm",
                                );
                            }
                            effective_start = fork_height;
                            effective_parent_hash = parent_hash_for_start(&snapshot, fork_height);

                            // Discard every block accumulated this attempt and
                            // restart from the fork. On the first reorg
                            // `fork_height <= original_start <= every accumulated
                            // height`, so `clear()` matches the height-keyed
                            // `retain(< fork_height)` it replaces. It is also
                            // correct across a *second, shallower* reorg (a fork
                            // above the first's): there a height-keyed retain would
                            // keep now-stale lower blocks from the first-reorg
                            // chain, while the truth on that range is the new chain
                            // — which the re-scan re-fetches from `fork_height`.
                            block_hashes.clear();
                            new_transfers.clear();
                            spent_key_images.clear();
                            block_leaves.clear();
                            block_curve_tree_roots.clear();
                            // Bond sightings from the abandoned fork must go
                            // with it: their heights sit inside the final
                            // processed range, so a stale row would pass the
                            // merge's O5 contract checks and be ADOPTED as
                            // chain evidence — wrongly re-arming staking and
                            // permanently burning cursor slots (the raise is
                            // monotone by design). The canonical chain's posts
                            // are re-sighted by the re-scan from the fork
                            // (the dedup set resets with it, else the re-sight
                            // would be suppressed as a duplicate).
                            bond_sightings.clear();
                            sighted_slots.clear();

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
                let miner_tx = &scannable.block.miner_transaction;
                if miner_tx.prefix.outputs.len() > MAX_OUTPUTS {
                    emit_state.try_emit(
                        diagnostics,
                        RefreshDiagnostic::DaemonMalformed {
                            kind: MalformedKind::ExcessiveOutputs,
                        },
                    );
                    return Err(LocalRefreshError::Malformed);
                }
                for tx in &scannable.transactions {
                    if tx.prefix.outputs.len() > MAX_OUTPUTS {
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
                // The containing txid rides along (spend-quadruple leg,
                // F-9): the merge writes it into the spent row's
                // `spending_tx_hash`. Miner txs carry no wire hash, so
                // hash lazily — a `ToKey` input in a miner tx is not a
                // shape Shekyl produces, but the collection is
                // deliberately unfiltered (see comment above).
                let mut miner_tx_hash: Option<shekyl_types::TxHash> = None;
                for input in &miner_tx.prefix.inputs {
                    if let Input::ToKey { key_image, .. } = input {
                        let containing_tx_hash = *miner_tx_hash.get_or_insert_with(|| {
                            shekyl_types::TxHash::from_bytes(miner_tx.hash())
                        });
                        spent_key_images.push(KeyImageObserved {
                            block_height: h,
                            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
                                *key_image,
                            ),
                            containing_tx_hash,
                        });
                    }
                }
                // `Block::transaction_hashes` pairs positionally with
                // `scannable.transactions` (the scanner enforces the
                // length match at construction).
                for (tx, tx_hash) in scannable
                    .transactions
                    .iter()
                    .zip(&scannable.block.transaction_hashes)
                {
                    for input in &tx.prefix.inputs {
                        if let Input::ToKey { key_image, .. } = input {
                            spent_key_images.push(KeyImageObserved {
                                block_height: h,
                                key_image:
                                    shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
                                        *key_image,
                                    ),
                                containing_tx_hash: shekyl_types::TxHash::from_bytes(*tx_hash),
                            });
                        }
                    }
                    // Bond watch (SA-R-6): match against the probe-id map
                    // (`bond_watch::sightings_in`). One row per slot per
                    // attempt: the scan walks heights ascending, so the
                    // first occurrence is the earliest height — the one
                    // the merge's first-sighting semantics would keep —
                    // and duplicates stay off the channel.
                    for sighting in sightings_in(tx, h, &self.bond_watch) {
                        if sighted_slots.insert(sighting.slot) {
                            bond_sightings.push(sighting);
                        }
                    }
                }

                // CT-5 §3.2 (R1-Q2/Q3): materialize the full per-block leaf
                // set and capture the consensus header `curve_tree_root`
                // *before* `scan_with_cancel` consumes `scannable`. The decode
                // reproduces the daemon's drain order; the per-tx X7 buffer
                // bound is defense-in-depth behind the excessive-outputs
                // pre-pass above, so a `DecodeError` here maps to the same
                // `Malformed` disposition.
                let leaves = curve_tree_decode::decode_block_leaves(&scannable).map_err(|e| {
                    let curve_tree_decode::DecodeError::ExcessiveOutputs { .. } = e;
                    emit_state.try_emit(
                        diagnostics,
                        RefreshDiagnostic::DaemonMalformed {
                            kind: MalformedKind::ExcessiveOutputs,
                        },
                    );
                    LocalRefreshError::Malformed
                })?;
                block_leaves.push((h, leaves));
                block_curve_tree_roots.push((h, scannable.block.header.curve_tree_root));

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
                // Per-block scanning ping: the pending-incoming summary is
                // assembled once at the orchestrator from the full
                // `ScanResult` (see `run_refresh_task`), so the streaming
                // per-block frame carries the zeroed display fields.
                _ = progress.send(RefreshProgress::phase_only(
                    h,
                    block_hashes.len() as u64,
                    end.saturating_sub(original_start),
                    RefreshPhase::Scanning,
                ));

                h += 1;
            }

            Ok(ScanResult {
                processed_height_range: effective_start..end,
                parent_hash: effective_parent_hash,
                block_hashes,
                new_transfers,
                spent_key_images,
                reorg_rewind,
                block_leaves,
                block_curve_tree_roots,
                bond_sightings,
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
/// Refresh issues `get_height` and `fetch_scannable_block`, the
/// latter composing the `Rpc` transport primitives `get_block` /
/// `get_transactions` / `get_o_indexes` (the §8 step-4 `shekyl-wire`
/// migration replaced the single-call `get_scannable_block_by_number`
/// the Round 4 audit was written against). The refresh-reachable
/// upstream variants and their tags:
///
/// - [`RpcError::ConnectionError`] → [`ProtocolErrorKind::ConnectionError`]
/// - [`RpcError::InternalError`] → [`ProtocolErrorKind::InternalError`]
/// - [`RpcError::InvalidNode`] → [`ProtocolErrorKind::InvalidNode`]
/// - [`RpcError::InvalidTransaction`] → [`ProtocolErrorKind::InvalidTransaction`]
/// - [`RpcError::PrunedTransaction`] → [`ProtocolErrorKind::PrunedTransaction`]
/// - [`RpcError::TransactionsNotFound`] → [`ProtocolErrorKind::InvalidNode`]
///   (reachable via the `get_transactions` leg of the block fetch: a
///   daemon that names transaction hashes in a block and then reports
///   them missing is internally inconsistent, which from the refresh
///   path is the "unexpected envelope" `InvalidNode` signal).
///
/// # Defensive mapping for non-refresh-reachable variants
///
/// `RpcError::InvalidFee` / `RpcError::InvalidPriority` are not
/// reachable from refresh — they belong to the future
/// `PendingTxEngine` send-tx path. If they nonetheless surface from
/// this site (e.g., upstream RPC client behavior change), the
/// defensive classification is [`ProtocolErrorKind::InvalidNode`] —
/// "the daemon returned an envelope the producer did not expect from
/// this RPC method." [`ProtocolErrorKind`] is `#[non_exhaustive]`;
/// PR 5's `PendingTxEngine` extraction may grow the variant set
/// additively.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
//
// `clippy::match_same_arms` would have us merge the
// `InvalidNode(_)` arm with the
// `TransactionsNotFound | InvalidFee | InvalidPriority` arm
// because both map to `ProtocolErrorKind::InvalidNode`. Keeping
// them separate preserves the rustdoc's reachability boundary:
// the grouped arm carries `TransactionsNotFound` (refresh-reachable
// via the block fetch's `get_transactions` leg — an inconsistent
// daemon, mapped to `InvalidNode`) alongside the genuinely
// non-refresh-reachable `InvalidFee` / `InvalidPriority` defensive
// fallbacks (send-tx path). Merging would lose that boundary, which
// future maintainers need when PR 5's `PendingTxEngine` extraction
// reaches this site.
#[allow(clippy::match_same_arms)]
const fn classify_rpc_error(err: &RpcError) -> ProtocolErrorKind {
    match err {
        RpcError::ConnectionError(_) => ProtocolErrorKind::ConnectionError,
        RpcError::InternalError(_) => ProtocolErrorKind::InternalError,
        RpcError::InvalidNode(_) => ProtocolErrorKind::InvalidNode,
        RpcError::InvalidTransaction(_) => ProtocolErrorKind::InvalidTransaction,
        RpcError::PrunedTransaction => ProtocolErrorKind::PrunedTransaction,
        // All map to `InvalidNode`: `TransactionsNotFound` is
        // refresh-reachable (block fetch's `get_transactions` leg;
        // inconsistent daemon), while `InvalidFee` / `InvalidPriority`
        // are non-refresh-reachable defensive fallbacks. See rustdoc.
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
async fn find_fork_point<R: DaemonEngine>(
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
async fn fetch_block_with_retry<R: DaemonEngine>(
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

        match rpc.fetch_scannable_block(height_usize).await {
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
#[path = "local_refresh_tests.rs"]
mod tests;

// ============================================================================
// Producer property tests (§5.4.6: emission/return coherence +
// producer-panic-safety)
// ============================================================================

/// End-to-end property tests for [`LocalRefresh::produce_scan_result`].
///
/// These tests are the **executable definition** of two §5.4.6
/// producer-side contracts:
///
/// 1. **Emission/return coherence** ([`§5.4.6 emission/return
///    coherence pin`]): every non-[`RefreshError::Cancelled`]
///    [`LocalRefreshError`] return is preceded by at least one
///    corresponding [`RefreshDiagnostic`] emission of the
///    appropriate class; no error-class
///    `RefreshDiagnostic` (`DaemonProtocolError`, `DaemonMalformed`,
///    `DaemonTimeout`) is followed by an `Ok` return. The
///    [`coherence_*`](self) tests pin specific classes; the
///    [`coherence_proptest_fuzz_chain_and_injection`](self) proptest
///    fuzzes the input space.
/// 2. **Producer-panic-safety** ([`§5.4.6 producer-panic-safety pin`]):
///    a [`PanickingSink`] that unwinds at the first emission
///    propagates the panic out of `produce_scan_result` without
///    leaking half-emitted scan state and without leaving the
///    cancellation token in an inconsistent state. The
///    [`panic_safety_*`](self) tests pin one scenario per
///    [`PanickingSinkTrigger`] class.
///
/// Per the §5.4.6 canonical-reference pin: when prose and test
/// behavior diverge, test behavior is authoritative; a PR that
/// changes producer-side error/emission shapes must re-anchor the
/// prose against the test, not the reverse.
///
/// [`§5.4.6 emission/return coherence pin`]: ../../../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
/// [`§5.4.6 producer-panic-safety pin`]: ../../../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
#[cfg(test)]
#[path = "local_refresh_property_tests.rs"]
mod producer_property_tests;
