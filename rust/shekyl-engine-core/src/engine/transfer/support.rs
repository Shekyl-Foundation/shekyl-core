// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Free helpers shared by the transfer implementor.

use std::sync::{Mutex, PoisonError};

use shekyl_curve_tree::{AssembleInput, ClientError, CommitmentBytes, OneTimePubkey};
use shekyl_engine_state::TransferDetails;

use super::super::curve_tree_actor::CurveTreeHandleError;
use super::super::diagnostics::{
    emit_pending_tx_diagnostic, BuildErrorKind, DiagnosticSink, PendingTxDiagnostic,
};
use super::super::error::{FeeEstimatorError, OutputSelectorError, SendError, SignerError};
use super::super::pending::ReservationId;

use super::types::{PendingTxState, ReanchorError};

/// Curve-tree leaf operands from a selected [`TransferDetails`].
///
/// One minting site so the two assemble paths (build and re-anchor) cannot
/// wrap the compressed key and commitment two ways.
pub(super) fn assemble_input(td: &TransferDetails) -> AssembleInput {
    AssembleInput {
        gindex: td.global_output_index,
        output_key: OneTimePubkey::from_bytes(td.key.compress().to_bytes()),
        commitment: CommitmentBytes::from_bytes(td.commitment.calculate().compress().to_bytes()),
    }
}

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
    Enforced {
        covered_through: Option<shekyl_types::BlockHeight>,
    },
}

impl TreeSpendGate {
    /// Whether an output maturing at `eligible_height` is covered by the tree.
    pub(super) fn covers(self, eligible_height: shekyl_types::BlockHeight) -> bool {
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
        // The wallet's two views of one tree disagree (`CT-6` §11.6): the
        // assembled path did not hash to the root it claimed. Reselection is
        // the *wrong* remedy and saying it would be actively misleading —
        // the selected inputs are fine, and rebuilding with different ones
        // reproduces the same inconsistency, because the fault is in the
        // tree rather than in what was picked from it. Terminal, like the
        // other hard curve-tree failures, and the reservation stays intact
        // so the user does not lose a selection to an internal defect
        // (rule 82: name the remedy, and do not name a false one).
        CurveTreeHandleError::Client(ClientError::PathRootMismatch { .. }) => {
            ReanchorError::Failed(map_curve_tree_handle_error_for_send(err))
        }
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
        SendError::InvalidRecipient { .. } => BuildErrorKind::InvalidRecipient,
        SendError::Fee(
            FeeEstimatorError::DaemonFeeUnreasonable(_) | FeeEstimatorError::CustomFeeOutOfRange(_),
        ) => BuildErrorKind::FeeRefused,
        SendError::InsufficientFunds { .. } => BuildErrorKind::InsufficientFunds,
        SendError::SpendUnavailableRebuilding { .. } => BuildErrorKind::RebuildingMembershipData,
        SendError::OutputNotYetSpendable { .. } => BuildErrorKind::OutputNotYetSpendable,
        // No block ingested yet, or a chain too short to anchor a reference
        // block: both are ledger readiness, not faults.
        SendError::WalletTooYoungToSpend { .. } | SendError::NotSynced => {
            BuildErrorKind::LedgerNotReady
        }
        SendError::SignerUnavailable | SendError::SignerFailed { .. } => {
            BuildErrorKind::SignerUnavailable
        }
        // A failed proof or signature, or a broken precondition: a bug, not a
        // state the request put the wallet in.
        SendError::Tx(_) | SendError::BuildInvariant { .. } => BuildErrorKind::InternalInvariant,
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
        SignerError::Unavailable => SendError::SignerUnavailable,
        SignerError::RemoteFailure { reason } => SendError::SignerFailed { reason },
    }
}

#[cfg(test)]
mod reanchor_classification_tests {
    use super::{map_handle_err_to_reanchor, CurveTreeHandleError, ReanchorError};
    use shekyl_curve_tree::{ClientError, CurveTreeRoot, Gindex, OneTimePubkey};

    /// A tree inconsistency must not be reported as "reselect your inputs".
    ///
    /// `PathRootMismatch` means the assembled path did not hash to the root
    /// it claimed — the wallet's two views of one tree disagree. The selected
    /// inputs are not implicated, and a rebuild with different ones
    /// reproduces it, so `ReselectionRequired` would send the user to do work
    /// that cannot help and would lose their selection on the way. Rule 82:
    /// a named remedy that is wrong is worse than a generic failure.
    #[test]
    fn a_path_root_mismatch_is_not_a_reselection() {
        let err = CurveTreeHandleError::Client(ClientError::PathRootMismatch {
            claimed: CurveTreeRoot::EMPTY,
            reason: "the branches do not hash to the root the path claims",
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::Failed(_) => {}
            other => panic!(
                "a tree inconsistency must be terminal, not a reselection request; got {other:?}"
            ),
        }
    }

    /// The arm above is specific, not a widening: an unresolvable input still
    /// asks for reselection, which is the case that remedy exists for.
    #[test]
    fn an_unresolvable_input_still_asks_for_reselection() {
        let err = CurveTreeHandleError::Client(ClientError::OutputNotDrained {
            gindex: Gindex::from_raw(7),
            output_key: OneTimePubkey::from_bytes([0u8; 32]),
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::ReselectionRequired { .. } => {}
            other => panic!("an orphaned input is the reselection case; got {other:?}"),
        }
    }
}
