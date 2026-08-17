// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Send / build / tx error vocabulary.

use crate::engine::pending::ReservationId;

use super::{FeeEstimatorError, IoError, TerminalErrorKind};

// --- Send / build / submit / discard --------------------------------------

/// Failures from [`Engine::build_pending_tx`](crate::engine::Engine) and the
/// rest of the send-side surface (excluding the `PendingTx` lifecycle
/// state machine, which has its own [`PendingTxError`]).
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Fee-estimator refusal or fee-query failure. Wraps
    /// [`FeeEstimatorError`] so the estimator's taxonomy is not
    /// restated here; the RPC layer maps it once.
    #[error(transparent)]
    Fee(#[from] FeeEstimatorError),

    /// Selected output set could not cover `amount + fee`.
    #[error("insufficient funds: need {needed} atomic units, available {available}")]
    InsufficientFunds {
        /// Total amount-plus-fee the build attempted to cover.
        needed: u64,
        /// Spendable balance currently visible to the wallet (matured,
        /// non-reserved).
        available: u64,
    },

    /// The `TxRequest` named a destination that does not parse as a
    /// Shekyl address for the wallet's network, or that is on a
    /// different network than the wallet itself.
    #[error("invalid recipient: {reason}")]
    InvalidRecipient {
        /// Human-readable reason. (Intentionally a `&'static str` so
        /// every branch is named in source rather than synthesized at
        /// runtime.)
        reason: &'static str,
    },

    /// Tx-builder layer failed: range proofs, FCMP++ membership proofs,
    /// hybrid PQC signatures, or assembly. Carries [`TxError`] for
    /// upstream detail.
    #[error("transaction construction failure: {0}")]
    Tx(#[from] TxError),

    /// Daemon-side failure during build (typically: `get_fee_estimates`
    /// or output-spend-status RPC) or submit. Carries [`IoError`] for
    /// upstream detail.
    #[error("daemon IO failure: {0}")]
    Io(#[from] IoError),

    /// Spend-key material was not available to sign. This is the path
    /// taken when a `Engine<SoloSigner>` is asked to send but the
    /// capability is `ViewOnly`, or when an `HardwareOffload` wallet
    /// receives a build call without an out-of-band approval.
    #[error("wallet cannot sign: {reason}")]
    CannotSign {
        /// Human-readable reason as named at the call site.
        reason: &'static str,
    },

    /// The wallet holds enough matured, non-reserved balance to cover the
    /// spend, but the funds are **not yet spendable** because the FCMP++
    /// curve tree is still rebuilding the membership data behind the
    /// already-synced ledger tip (CT-5 §3.2.1, D3). This is the
    /// adopting-wallet / tree-store-rebuild case: `synced_height` is ahead
    /// of the tree's `ingested_tip_height`, so a membership proof cannot be
    /// built for outputs the tree has not yet covered.
    ///
    /// Distinct from [`Self::InsufficientFunds`] precisely so the wallet does
    /// **not** show a misleading "insufficient funds" when the real, honest
    /// state is "spending temporarily unavailable while membership data
    /// rebuilds" (`82-failure-mode-ux.mdc`). The shortfall resolves on its
    /// own as the background backfill catches the tree up to `synced_height`;
    /// no user action is required beyond waiting for the rebuild to finish.
    #[error(
        "spending temporarily unavailable: rebuilding membership data \
         (need {needed} atomic units, {spendable_now} spendable now, \
         {pending_rebuild} pending rebuild)"
    )]
    SpendUnavailableRebuilding {
        /// Total amount-plus-fee the build attempted to cover.
        needed: u64,
        /// Balance spendable right now — matured, non-reserved, **and**
        /// already covered by the curve tree.
        spendable_now: u64,
        /// Matured, non-reserved balance that is blocked only by the
        /// in-progress tree rebuild and becomes spendable as the backfill
        /// advances the tree to `synced_height`.
        pending_rebuild: u64,
    },

    /// The FCMP++ curve-tree actor could not be queried for its
    /// `ingested_tip_height` at build time, so the spendable set cannot be
    /// computed (CT-5 §3.2.1). Distinct from
    /// [`Self::SpendUnavailableRebuilding`]: that is the *benign, self-healing*
    /// "tree is behind" state (the cursor read **succeeded** and returned a
    /// height below `synced_height`); this is a *hard* infrastructure failure
    /// (the cursor read **failed** — the actor is fail-stopped). It is terminal
    /// until the engine-side actor respawn (R1-Q4) lands; a retry against a
    /// dead actor reproduces it.
    #[error("curve-tree unavailable: {detail}")]
    CurveTreeUnavailable {
        /// Stringified [`CurveTreeHandleError`](crate::engine::curve_tree_actor::CurveTreeHandleError).
        detail: String,
    },

    /// An output the wallet would otherwise spend is **not yet spendable at the
    /// reference block** (C2; 2A §3.7.5, CT-5 §3.2): its `eligible_height` lands
    /// *after* the reference height (`tip − REF_ANCHOR_AGE`), so although the
    /// output is matured at the tip its leaf is absent from the curve tree as of
    /// the reference block the proof anchors to. A clean wait-N-blocks signal —
    /// **not** an opaque assembly miss. Distinct from
    /// [`Self::SpendUnavailableRebuilding`] (tree lag, self-heals as the backfill
    /// advances) and [`Self::InsufficientFunds`] (genuinely short): the funds
    /// exist and the tree covers them; they are simply too fresh for the
    /// reference anchor and become spendable as the tip advances.
    #[error(
        "output not yet spendable at the reference block: eligible at height \
         {eligible_height}, reference block at {reference_block_height} \
         (spendable in ~{wait_blocks} block(s))"
    )]
    OutputNotYetSpendable {
        /// The height at which the output enters the tree (matures).
        eligible_height: u64,
        /// The reference-block height the proof anchors to (`tip − REF_ANCHOR_AGE`).
        reference_block_height: u64,
        /// Blocks the tip must still advance before the output's
        /// `eligible_height` reaches the reference height and it becomes
        /// spendable (`eligible_height − reference_block_height`).
        wait_blocks: u64,
    },

    /// The chain is too short to anchor a reference block: `synced_height <
    /// REF_ANCHOR_AGE`, so [`select_reference_height`](shekyl_curve_tree::select_reference_height)
    /// returns `None` and no output can be proven yet (the pre-maturity window).
    /// A clean "wait for the chain to mature" signal rather than a misleading
    /// insufficiency; resolves on its own as the tip advances past
    /// `REF_ANCHOR_AGE`.
    #[error(
        "wallet too young to spend: synced height {synced_height} is below the \
         reference-anchor depth {ref_anchor_age} (no reference block yet)"
    )]
    WalletTooYoungToSpend {
        /// The wallet's current synced height.
        synced_height: u64,
        /// `REF_ANCHOR_AGE` — the minimum synced height to anchor a reference.
        ref_anchor_age: u64,
    },

    /// The F28/F37 rebuild-loop circuit breaker is tripped
    /// (`DAEMON_SUBMIT_VERDICT.md` §2.5): two consecutive daemon
    /// rejections of the same kind (`Malformed`, `FeeTooLow`, or
    /// `Unrecognized`) indicate a systematic wallet/daemon disagreement,
    /// and further automatic builds are refused — a third build burns
    /// fees and multiplies linking artifacts (§7.1) without resolving
    /// the disagreement. The operator investigates the alarm and resets
    /// via `acknowledge_submit_loop_breaker`.
    #[error(
        "submit loop-breaker tripped: two consecutive daemon rejections \
         of the same kind ({kind:?}); builds refused until the operator \
         acknowledges"
    )]
    SubmitLoopBreakerTripped {
        /// The rejection kind the breaker tripped on.
        kind: TerminalErrorKind,
    },
}

// --- PendingTx lifecycle ---------------------------------------------------

/// Failures from
/// [`Engine::submit_pending_tx`](crate::engine::Engine) /
/// [`Engine::discard_pending_tx`](crate::engine::Engine) and from the
/// reservation-bookkeeping logic of `build_pending_tx`. Cross-cutting
/// lock 4 binds the variants
/// [`Self::TooOld`] and [`Self::ChainStateChanged`].
///
/// `#[non_exhaustive]` per the Phase 0a binding form
/// (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4) so V3.x variant additions
/// land without a major-version break. The V3.0 audited surface is the
/// variant set below.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PendingTxError {
    /// The `PendingTx`'s `built_at_height` is below
    /// `wallet.synced_height - max_reorg_depth` — the build is too old
    /// to safely submit. Caller must rebuild against current chain
    /// state.
    #[error(
        "pending tx too old: built_at_height = {built}, current_synced = {current}, max_reorg = {max_reorg}"
    )]
    TooOld {
        /// `PendingTx.built_at_height` of the offending handle.
        built: u64,
        /// `wallet.synced_height` observed at submit time.
        current: u64,
        /// Network's `max_reorg_depth` per `NetworkSafetyConstants`
        /// (after any per-wallet override).
        max_reorg: u64,
    },

    /// The wallet's recorded block hash at `built_at_height` no longer
    /// matches the `built_at_tip_hash` the `PendingTx` carries. A reorg
    /// orphaned the build's input set; rebuild required.
    #[error(
        "pending tx anchored to a chain state that no longer matches: built_at_height = {height}"
    )]
    ChainStateChanged {
        /// `PendingTx.built_at_height` of the offending handle.
        height: u64,
    },

    /// `submit_pending_tx` or `discard_pending_tx` was called with a
    /// handle that the wallet's reservation ledger does not recognize.
    /// `discard_pending_tx` is **idempotent and silent** on this case
    /// per cross-cutting lock 4; `submit_pending_tx` raises this error.
    ///
    /// Phase 1 handler-bodies emit this variant via the existing
    /// reservation-bookkeeping helpers. C5β rewrites the handler
    /// bodies under the (γ) three-collection lean shape; from C5β on,
    /// `discard` and `submit` discriminate "rid is unknown" via
    /// [`Self::ReservationNotFound`] (with the rid carried in the
    /// variant), and the unit `UnknownHandle` variant is retired
    /// from new emission sites. The variant is retained on the
    /// `#[non_exhaustive]` enum surface for the Phase 1 helpers'
    /// continued use; the C5β deletion target is named in
    /// `docs/FOLLOWUPS.md`.
    #[error("unknown PendingTx handle")]
    UnknownHandle,

    /// Submit-side: caller-initiated `discard_pending_tx` against a
    /// reservation that is currently `in_flight` (a daemon round-trip
    /// is outstanding). Per the F2 ownership-boundary adjudication
    /// (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F2) the consumer
    /// does not own discard authority on `in_flight` reservations —
    /// the daemon does. The R8 TTL safety-net is the eventual
    /// release path when the daemon never resolves.
    #[error("discard blocked: reservation {reservation_id:?} is in_flight pending daemon ack")]
    DiscardBlockedPendingDaemonAck {
        /// The reservation whose discard was refused.
        reservation_id: ReservationId,
    },

    /// Submit-side: second `submit_pending_tx` against a reservation
    /// whose first submit is still in-flight. P2 disposition per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.6.
    #[error("submit already pending for reservation {reservation_id:?}")]
    SubmitAlreadyPending {
        /// The reservation whose duplicate submit was refused.
        reservation_id: ReservationId,
    },

    /// Submit / discard / `signal_mempool_evicted`: the rid is in
    /// neither `consumer_held` nor `in_flight`. P3 disposition per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.6 — discriminates
    /// "never existed or already resolved" from the unit
    /// [`Self::UnknownHandle`] by carrying the rid for diagnostics.
    /// `discard_pending_tx`'s idempotent-and-silent contract is
    /// preserved at the trait surface: the engine maps the
    /// `ReservationNotFound` outcome to `Ok(())` on the discard
    /// path, surfacing it as an error only on `submit` and
    /// `signal_mempool_evicted`.
    #[error("reservation {reservation_id:?} not found")]
    ReservationNotFound {
        /// The rid the caller passed to the operation.
        reservation_id: ReservationId,
    },

    /// The submit RPC failed at the daemon. Carries [`IoError`] for
    /// detail; the reservation is **kept** until the caller chooses to
    /// retry submit or discard explicitly.
    #[error("daemon submit failure: {0}")]
    Io(#[from] IoError),
}

// --- Tx ---------------------------------------------------------------------

/// Failures from the transaction-construction layer
/// (`shekyl-tx-builder`) and from the wallet's pre-build sanity
/// checks against daemon-supplied fee estimates.
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    /// Range-proof construction failed (likely indicates a bug in the
    /// builder or a corrupt input). The variant is named separately
    /// from the catch-all so audit can distinguish proof-system
    /// failures from input-selection failures.
    #[error("range proof construction failed: {detail}")]
    RangeProof {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },

    /// FCMP++ membership-proof construction failed. Same audit-distinct
    /// rationale as [`Self::RangeProof`].
    #[error("FCMP++ membership proof construction failed: {detail}")]
    Membership {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },

    /// Hybrid PQC signature production failed (Ed25519 path or ML-DSA-65
    /// path). Same audit-distinct rationale.
    #[error("hybrid PQC signature failed: {detail}")]
    Signature {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },

    /// Builder-level assembly produced a transaction that fails
    /// internal consistency checks (sums, key-image uniqueness, etc.).
    /// Should be unreachable in practice; surfaced as a typed error so
    /// it cannot silently land on the wire.
    #[error("transaction failed internal consistency check: {detail}")]
    InternalConsistency {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },
}
