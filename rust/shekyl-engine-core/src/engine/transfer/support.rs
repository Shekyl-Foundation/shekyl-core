// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Free helpers shared by the transfer implementor.

use std::sync::{Mutex, PoisonError};

use super::super::curve_tree_actor::CurveTreeHandleError;
use super::super::diagnostics::{
    emit_pending_tx_diagnostic, BuildErrorKind, DiagnosticSink, PendingTxDiagnostic,
};
use super::super::error::{FeeEstimatorError, OutputSelectorError, SendError, SignerError};
use super::super::pending::{ReservationId, TxHash};

use super::types::{PendingTxState, ReanchorError};

#[allow(private_bounds)]
pub(super) fn release_output_locks_for(state: &mut PendingTxState, rid: ReservationId) {
    state.output_locks.retain(|_, owner| *owner != rid);
}

/// Best-effort state access for cleanup paths (sign/commit failure).
///
/// Mutating handlers fail loud on poison; cleanup must still release
/// `output_locks` so a poisoned mutex does not strand spendable outputs.
pub(super) fn with_pending_tx_state_mut<R>(
    mutex: &Mutex<PendingTxState>,
    f: impl FnOnce(&mut PendingTxState) -> R,
) -> R {
    let mut state = mutex.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut state)
}

/// Spend-time gate on curve-tree membership coverage (CT-5 §3.2.1 D1/D3).
///
/// The spendable set is capped at `min(synced_height, tree_cursor)` so a wallet
/// whose ledger tip has outrun the curve tree — an adopting wallet, or any
/// wallet whose `.curvetree` store was rebuilt — does not select outputs for
/// which the local tree cannot yet assemble a membership path. Coverage is
/// keyed on the output's `eligible_height` (the height at which it enters the
/// tree and `is_spendable` already admits it), so this gate is exactly the
/// curve-tree projection of `min(synced_height, tree_cursor)`.
#[derive(Clone, Copy)]
pub(super) enum TreeSpendGate {
    /// No curve tree wired into this builder (direct-construction unit tests).
    /// The gate is inert; every matured output is selectable (pre-4b behavior).
    Unenforced,
    /// Curve tree present, with the last-ingested height it reported. An output
    /// is tree-covered iff its `eligible_height <= covered_through`;
    /// `covered_through == None` means the tree is fresh/empty and covers
    /// nothing (the adopting-wallet pre-backfill state).
    Enforced { covered_through: Option<u64> },
}

impl TreeSpendGate {
    /// Whether an output maturing at `eligible_height` is covered by the tree.
    pub(super) fn covers(self, eligible_height: u64) -> bool {
        match self {
            TreeSpendGate::Unenforced => true,
            TreeSpendGate::Enforced { covered_through } => {
                covered_through.is_some_and(|cap| eligible_height <= cap)
            }
        }
    }
}

/// Map a build-time [`CurveTreeHandleError`] (a failed `ingested_tip_height`
/// cursor read) into the terminal [`SendError::CurveTreeUnavailable`]. This is
/// the *hard-failure* path (the actor is fail-stopped); the benign "tree is
/// behind" lag is the cursor-read-**succeeds**-with-a-low-value path and
/// surfaces as [`SendError::SpendUnavailableRebuilding`] instead.
pub(super) fn map_curve_tree_handle_error_for_send(err: &CurveTreeHandleError) -> SendError {
    // `detail` is documented as the stringified `CurveTreeHandleError`
    // (`error.rs`); render the actual variant — including the inner
    // `ClientError` the previous hand-strings dropped — so the diagnostic is
    // actionable. The error carries no secret material.
    SendError::CurveTreeUnavailable {
        detail: format!("{err:?}"),
    }
}

/// Classify a curve-tree handle error encountered during a CT-5d re-anchor
/// (`docs/design/CT5D_REANCHOR.md` §3): the two `CurveTreeHandleError` variants
/// map to the two re-anchor failure modes.
pub(super) fn map_handle_err_to_reanchor(err: &CurveTreeHandleError) -> ReanchorError {
    match err {
        // The client returned an error *inside* the handler: the selected input
        // is not resolvable at the fresh reference — almost always a
        // reorg-orphaned output. Content-preserving reprove is impossible;
        // reselection (CT-5d-deferred) is the fix, so tell the consumer to
        // discard and rebuild rather than carry a proof that cannot be built.
        CurveTreeHandleError::Client(_) => ReanchorError::ReselectionRequired {
            detail:
                "membership assembly failed at the fresh reference (input likely reorg-orphaned); discard and rebuild",
        },
        // The actor is fail-stopped / timed out — transient, recoverable by
        // respawn; retriable once the tree resyncs.
        CurveTreeHandleError::Unavailable => ReanchorError::ReferenceResyncing {
            detail: "curve tree actor unavailable; retry once it resyncs",
        },
    }
}

pub(super) fn build_error_kind(err: &SendError) -> BuildErrorKind {
    match err {
        SendError::InvalidRecipient { .. } | SendError::Tx(_) => BuildErrorKind::InvalidRecipient,
        SendError::Fee(
            FeeEstimatorError::DaemonFeeUnreasonable(_) | FeeEstimatorError::CustomFeeOutOfRange(_),
        ) => BuildErrorKind::FeeRefused,
        SendError::InsufficientFunds { .. } => BuildErrorKind::InsufficientFunds,
        SendError::SpendUnavailableRebuilding { .. } => BuildErrorKind::RebuildingMembershipData,
        SendError::OutputNotYetSpendable { .. } => BuildErrorKind::OutputNotYetSpendable,
        // The chain is too short to anchor a reference block — a ledger-maturity
        // readiness condition, projected like the other "ledger not ready" case.
        SendError::WalletTooYoungToSpend { .. } => BuildErrorKind::LedgerNotReady,
        SendError::CannotSign { reason } if *reason == "wallet has not ingested any block yet" => {
            BuildErrorKind::LedgerNotReady
        }
        SendError::CannotSign { .. } => BuildErrorKind::SignerUnavailable,
        // A curve-tree actor that cannot be queried is an infrastructure
        // outage indistinguishable, to the caller, from the daemon being down.
        SendError::CurveTreeUnavailable { .. } | SendError::Io(_) | SendError::Fee(_) => {
            BuildErrorKind::DaemonUnavailable
        }
        SendError::SubmitLoopBreakerTripped { .. } => BuildErrorKind::SubmitLoopBreakerTripped,
    }
}

pub(super) fn emit_build_failed(sink: &dyn DiagnosticSink, err: &SendError) {
    emit_pending_tx_diagnostic(
        sink,
        PendingTxDiagnostic::BuildFailed {
            kind: build_error_kind(err),
        },
    );
}

pub(super) fn fail_build_after_attempted(sink: &dyn DiagnosticSink, err: SendError) -> SendError {
    emit_build_failed(sink, &err);
    err
}

pub(super) fn map_output_selector_error(err: &OutputSelectorError) -> SendError {
    match *err {
        OutputSelectorError::InsufficientFunds { needed, available } => {
            SendError::InsufficientFunds { needed, available }
        }
        OutputSelectorError::NoEligibleOutputs => SendError::InsufficientFunds {
            needed: 0,
            available: 0,
        },
        OutputSelectorError::ReturnedIndicesNotSubset { .. } => SendError::InvalidRecipient {
            reason: "output selector returned indices outside candidate set",
        },
    }
}

pub(super) fn map_fee_estimator_error(err: &FeeEstimatorError) -> SendError {
    SendError::Fee(*err)
}

pub(super) fn map_signer_error(err: &SignerError) -> SendError {
    match err {
        SignerError::Unavailable => SendError::CannotSign {
            reason: "signer unavailable",
        },
        SignerError::RemoteFailure { reason } => SendError::CannotSign { reason },
    }
}

pub(super) fn phase1_tx_hash(id: ReservationId) -> TxHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.raw().to_le_bytes());
    TxHash::from_bytes(bytes)
}
