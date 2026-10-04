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

/// How a [`ClientError`] is reported on the re-anchor path.
///
/// One arm per remedy. [`client_reanchor_class`] names every
/// [`ClientError`] variant, so a new one does not compile until it is
/// placed.
enum ClientReanchorClass {
    /// Discard the selection and rebuild.
    ///
    /// [`ClientError::OutputNotDrained`] is the case this remedy describes:
    /// the selected input is not in the tree at the fresh reference.
    /// The other variants on this arm keep the remedy this path gave every
    /// client error before the artifact fold existed. They are listed so a
    /// new variant cannot join them by falling through.
    Reselect,
    /// The assembled path does not commit to the root it claims.
    ///
    /// A different selection reproduces it. The reservation stays, and the
    /// failure is terminal (rule 82: do not name a remedy that cannot help).
    Terminal,
}

/// Classify `err` for [`map_handle_err_to_reanchor`].
///
/// [`ClientError::PathRootMismatch`],
/// [`ClientError::CaptureIdentitiesIncomplete`] and
/// [`ClientError::OwnedPositionDrift`] are [`ClientReanchorClass::Terminal`].
/// Every other variant is [`ClientReanchorClass::Reselect`].
fn client_reanchor_class(err: &ClientError) -> ClientReanchorClass {
    match err {
        // Two capture-path refusals share this arm because they share the
        // verdict, and for both, reselecting inputs is a remedy that does
        // nothing (rule 82). `CaptureIdentitiesIncomplete` is a store
        // missing leaf bytes (`prune_frozen`), and no other input is served
        // by a store in that state. `OwnedPositionDrift` is the client's own
        // two views of drain order disagreeing, which a different input
        // reproduces.
        ClientError::PathRootMismatch { .. }
        | ClientError::CaptureIdentitiesIncomplete { .. }
        | ClientError::OwnedPositionDrift { .. } => ClientReanchorClass::Terminal,
        // A registration disagreeing with the client's chain view is the
        // reselection family: the wallet's rescan re-registers against the
        // chain it now sees, which is the same remedy a stale input gets.
        // A reference outside the snapshot ring is older than the daemon
        // accepts, so re-anchoring at a fresh reference is the remedy — the
        // reselection family's. A missing capture is also not terminal: the
        // store is sound, and the remedy is reconciliation, which the
        // registrant runs on open; until then a rebuilt path is what the
        // consumer gets by discarding this one.
        // An unregistered input at assembly means the batch's sync reported
        // it stale: the client holds a different output at that gindex, and
        // the wallet's view is behind. Reselecting after the rescan is the
        // remedy, so this is the reselection family.
        ClientError::RegistrationIdentityMismatch { .. }
        | ClientError::OutputNotRegistered { .. }
        | ClientError::ReferenceOutsideSnapshotRing { .. }
        | ClientError::CaptureMissing { .. }
        | ClientError::RootMismatch { .. }
        | ClientError::OutputNotDrained { .. }
        | ClientError::IdentityMismatch { .. }
        | ClientError::TooManyInputs { .. }
        | ClientError::Store(_)
        | ClientError::NonConsecutiveBlockHeight { .. }
        | ClientError::ReferenceBeyondIngestedTip { .. }
        | ClientError::ResumeFromPrunedStore { .. }
        | ClientError::ResumeFromCorruptStore { .. }
        | ClientError::Poisoned
        | ClientError::LeafEntries { .. }
        | ClientError::LeafPoint { .. }
        | ClientError::Frontier { .. }
        | ClientError::SnapshotLeafCountMismatch { .. } => ClientReanchorClass::Reselect,
    }
}

/// Classify a curve-tree handle error encountered during a CT-5d re-anchor
/// (`docs/design/CT5D_REANCHOR.md` §3).
///
/// Three outcomes. [`ClientReanchorClass::Terminal`] keeps the reservation
/// and reports the tree unavailable. [`ClientReanchorClass::Reselect`] tells
/// the consumer to discard and rebuild. [`CurveTreeHandleError::Unavailable`]
/// is a stopped actor: retry once it resyncs.
pub(super) fn map_handle_err_to_reanchor(err: &CurveTreeHandleError) -> ReanchorError {
    match err {
        CurveTreeHandleError::Client(client) => match client_reanchor_class(client) {
            ClientReanchorClass::Terminal => {
                ReanchorError::Failed(map_curve_tree_handle_error_for_send(err))
            }
            ClientReanchorClass::Reselect => ReanchorError::ReselectionRequired {
                detail:
                    "membership assembly failed at the fresh reference (input likely reorg-orphaned); discard and rebuild",
            },
        },
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
    use shekyl_curve_tree::{ClientError, CurveTreeRoot, Gindex, OneTimePubkey, PathRootFault};

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
            fault: PathRootFault::RootDisagrees,
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::Failed(_) => {}
            other => panic!(
                "a tree inconsistency must be terminal, not a reselection request; got {other:?}"
            ),
        }
    }

    /// A store missing the leaf bytes capture needs is terminal too.
    ///
    /// It shares `PathRootMismatch`'s arm, and an arm shared by two variants
    /// is one a later edit can move for the wrong reason. The remedy is the
    /// reason: reselecting inputs cannot help, because no other input is
    /// served by a store in that state (rule 82).
    #[test]
    fn a_short_capture_read_is_not_a_reselection() {
        let err = CurveTreeHandleError::Client(ClientError::CaptureIdentitiesIncomplete {
            end_leaf: 683,
            want: 38,
            got: 18,
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::Failed(_) => {}
            other => panic!(
                "a store missing leaf bytes must be terminal, not a reselection \
                 request; got {other:?}"
            ),
        }
    }

    /// The two capture-path refusals that are NOT terminal.
    ///
    /// A reference outside the ring is one the daemon would reject as too
    /// old, so a fresh anchor is the remedy. A missing capture leaves the
    /// store sound and is repaired by reconciliation. Neither is a store
    /// missing leaf bytes, which is what the terminal arm is for, and a test
    /// pinning that keeps a later edit from sweeping them into it.
    #[test]
    fn a_stale_reference_and_a_missing_capture_ask_for_reselection() {
        for err in [
            ClientError::ReferenceOutsideSnapshotRing {
                height: shekyl_curve_tree::BlockHeight::from_raw(5),
            },
            ClientError::CaptureMissing {
                end_leaf: 683,
                layer: 1,
            },
        ] {
            let err = CurveTreeHandleError::Client(err);
            match map_handle_err_to_reanchor(&err) {
                ReanchorError::ReselectionRequired { .. } => {}
                other => panic!("expected the reselection family; got {other:?}"),
            }
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
