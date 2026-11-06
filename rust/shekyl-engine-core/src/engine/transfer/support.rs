// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Free helpers shared by the transfer implementor.

use std::sync::{Mutex, PoisonError};

use shekyl_curve_tree::{
    AssembleInput, ClientError, CommitmentBytes, OneTimePubkey, StoreOpenFault,
};
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
/// One arm per remedy this path can actually perform. [`client_reanchor_class`]
/// names every [`ClientError`] variant, so a new one does not compile until
/// it is placed.
enum ClientReanchorClass {
    /// Discard the selection and rebuild.
    ///
    /// [`ClientError::OutputNotDrained`] is the case this remedy describes:
    /// the selected input is not in the tree at the fresh reference.
    /// [`ClientError::RegistrationIdentityMismatch`] belongs here too: the
    /// wallet's rescan re-registers against the chain it now sees, which is
    /// the same remedy a stale input gets, and the registrant has to
    /// preserve it. A store fault whose remedy is a retry, another process,
    /// or a bug stays here as well. Those variants are listed so a new one
    /// cannot join them by falling through.
    Reselect,
    /// Keep the reservation and report the tree unavailable.
    ///
    /// A different selection reproduces the failure, or the remedy is one
    /// this path does not perform: reconciling a missing capture, filling a
    /// hole in the snapshot ring, deleting a corrupt store. Naming
    /// reselection for any of those would discard a sound selection (rule
    /// 82).
    Terminal,
}

/// Classify `err` for [`map_handle_err_to_reanchor`].
///
/// Terminal keeps the reservation: the path does not commit to its root, the
/// store is missing the leaf bytes a capture needs, the client's two drain
/// orders disagree, a closed chunk the path needs was never written, the
/// snapshot ring has no row at the height re-anchor already chose, or a
/// persisted capture body is corrupt. Reselect is everything whose remedy is
/// a new selection or a retry of the same one.
fn client_reanchor_class(err: &ClientError) -> ClientReanchorClass {
    match err {
        // Reselecting inputs does nothing for any of these (rule 82).
        //
        // `CaptureIdentitiesIncomplete` is a store missing leaf bytes
        // (`prune_frozen`); no other input is served by a store in that
        // state. `OwnedPositionDrift` is the client's own two views of drain
        // order disagreeing, which a different input reproduces.
        // `CaptureMissing` is a closed chunk the registrant should have
        // written, by the fold or by `reconcile_captures`. This path has no
        // reconcile step, and a new outcome submit cannot honor would be a
        // remedy in name only. The reservation stays; the registrant owns
        // the reconcile.
        // `ReferenceOutsideSnapshotRing` meets a height
        // `two_sided_reference_height` already chose, at most `REBUILD_AT`
        // behind the tip. The ring covers
        // `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`. A miss inside that window is
        // a hole, and retrying the same height does not write the row.
        // `ReferenceResyncing` is the actor-stopped outcome, which this is
        // not: the actor answered.
        ClientError::PathRootMismatch { .. }
        | ClientError::CaptureIdentitiesIncomplete { .. }
        | ClientError::OwnedPositionDrift { .. }
        | ClientError::CaptureMissing { .. }
        | ClientError::ReferenceOutsideSnapshotRing { .. } => ClientReanchorClass::Terminal,
        // A body that does not decode is corruption: delete the store and
        // rebuild it. Io, a lock held elsewhere, and an internal fault have
        // different remedies, and they stay on the reselection arm below.
        ClientError::Store(store) if store.open_fault() == StoreOpenFault::Corrupt => {
            ClientReanchorClass::Terminal
        }
        // A registration the client's chain view does not hold is the
        // reselection family. The wallet's rescan re-registers against the
        // chain it now sees, the same remedy a stale input gets, and the
        // registrant preserves this class.
        // An unregistered input at assembly is the same family: the batch's
        // sync reported it stale, the wallet's view is behind, and the rescan
        // re-registers against the chain it now sees.
        ClientError::RegistrationIdentityMismatch { .. }
        | ClientError::OutputNotRegistered { .. }
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
        | ClientError::TxHashMissing { .. }
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
    use shekyl_curve_tree::{
        ClientError, CurveTreeRoot, Gindex, OneTimePubkey, PathRootFault, StoreError,
    };

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

    /// A closed chunk the path needs was never written.
    ///
    /// Reselecting inputs does not call `reconcile_captures`. The registrant
    /// owns that call. Reporting reselection would discard a sound selection
    /// and name a remedy this path cannot perform, so the reservation stays.
    #[test]
    fn a_missing_capture_keeps_the_reservation() {
        let err = CurveTreeHandleError::Client(ClientError::CaptureMissing {
            end_leaf: 683,
            layer: 1,
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::Failed(_) => {}
            other => panic!(
                "a missing capture is reconciled by the registrant, not by \
                 discarding the selection; got {other:?}"
            ),
        }
    }

    /// Re-anchor already chose this height. A ring with no row there is a hole.
    ///
    /// `two_sided_reference_height` picks a height at most `REBUILD_AT` behind
    /// the tip, and the ring holds `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`.
    /// Retrying that height does not write the row, and
    /// [`ReanchorError::ReferenceResyncing`] is the actor-stopped outcome.
    /// The actor answered. The reservation stays.
    #[test]
    fn a_hole_in_the_snapshot_ring_keeps_the_reservation() {
        let err = CurveTreeHandleError::Client(ClientError::ReferenceOutsideSnapshotRing {
            height: shekyl_curve_tree::BlockHeight::from_raw(5),
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::Failed(_) => {}
            other => panic!(
                "a missing snapshot at the fresh reference is a hole, not a \
                 cue to pick another input or to wait for a resync; got {other:?}"
            ),
        }
    }

    /// A capture body that is not one full width is corruption.
    ///
    /// The remedy is to delete the store. The guard is the corrupt open
    /// fault, so a lock, an I/O failure, and an internal disagreement stay
    /// on reselection — pinned by the conflict test below.
    #[test]
    fn a_corrupt_capture_body_keeps_the_reservation() {
        let err = CurveTreeHandleError::Client(ClientError::Store(StoreError::CorruptMeta(
            "captured leaf chunk is not one full width",
        )));
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::Failed(_) => {}
            other => panic!("a corrupt capture body must be terminal; got {other:?}"),
        }
    }

    /// Two captures disagreeing at one coordinate is `StoreOpenFault::Internal`.
    ///
    /// The terminal store arm is the corrupt open fault alone. Widening it
    /// to every `Store` would report a lock and an I/O failure as a tree
    /// to delete.
    #[test]
    fn a_capture_conflict_still_asks_for_reselection() {
        let err =
            CurveTreeHandleError::Client(ClientError::Store(StoreError::ConflictingCapture {
                end_leaf: 683,
                layer: 1,
            }));
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::ReselectionRequired { .. } => {}
            other => panic!("an internal capture conflict is not store corruption; got {other:?}"),
        }
    }

    /// A registration the client's chain view does not hold is a stale caller.
    ///
    /// The rescan re-registers against the chain it now sees. That is the
    /// reselection family, and the registrant preserves it.
    #[test]
    fn a_registration_the_chain_does_not_hold_asks_for_reselection() {
        let err = CurveTreeHandleError::Client(ClientError::RegistrationIdentityMismatch {
            gindex: Gindex::from_raw(7),
            expected: OneTimePubkey::from_bytes([1u8; 32]),
            got: OneTimePubkey::from_bytes([2u8; 32]),
        });
        match map_handle_err_to_reanchor(&err) {
            ReanchorError::ReselectionRequired { .. } => {}
            other => panic!(
                "a registration the chain does not hold is a stale caller view; got {other:?}"
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
