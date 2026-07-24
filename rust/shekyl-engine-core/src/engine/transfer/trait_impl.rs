// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`PendingTxEngine`] and [`WatchdogHost`] implementations.

use std::collections::HashSet;
use std::future::Future;

use shekyl_curve_tree::{select_reference_height, BlockHeight, ReferenceBlock};
use shekyl_engine_state::LedgerBlock;

use super::super::diagnostics::{emit_pending_tx_diagnostic, DiscardReason, PendingTxDiagnostic};
use super::super::error::{PendingTxError, SendError, SignerError, SubmitError};
use super::super::fee_estimator::FeeEstimator;
use super::super::fee_snapshot::FeeSnapshotSource;
use super::super::output_selector::OutputSelector;
use super::super::pending::{PendingTx, ReservationId, TxHash, TxRequest};
use super::super::signer::{Signer, TransferSigningContext};
use super::super::signing_assembly::assemble_tx_to_sign;
use super::super::submit_lifecycle::WatchdogHost;
use super::super::submit_watchdog::{self, HeldSubmit};
use super::super::traits::{LedgerEngine, PendingTxEngine};
use super::super::transaction_submitter::TransactionSubmitter;
use super::engine::{BuildReservationCleanup, BuildSelected, LocalPendingTx};
use super::support::{
    build_error_kind, emit_build_failed, fail_build_after_attempted,
    map_curve_tree_handle_error_for_send, map_fee_estimator_error, map_signer_error, TreeSpendGate,
};
use super::types::{RescanRequest, Stage1LedgerSpendableAccess};

// ============================================================================
// PendingTxEngine impl
// ============================================================================

/// The §5.3 submit-lifecycle driver reaches the wallet through this
/// narrow object-safe surface rather than the six-parameter
/// `LocalPendingTx` generic (`DAEMON_SUBMIT_VERDICT.md` §5.3). The ledger
/// reads bridge the driver's `synced_height` / `block_hash_at` /
/// `held_submits` / `release_awaiting_confirmation` to the guarded
/// `LedgerBlock` via the same [`Stage1LedgerSpendableAccess`] path the
/// build path uses; the byte / queue accessors delegate to the inherent
/// methods; `emit` routes through the diagnostic sink.
///
/// `#[allow(private_bounds)]`: [`Stage1LedgerSpendableAccess`] is a
/// private trait (crate-internal ledger-access seam); the public
/// `WatchdogHost` impl carries it as a where-bound exactly as the
/// inherent impl and the `PendingTxEngine` impl do.
#[allow(private_bounds)]
impl<S, O, F, FS, TS, L> WatchdogHost for LocalPendingTx<S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    fn held_submits(&self) -> Vec<HeldSubmit> {
        self.ledger.with_ledger_block(submit_watchdog::held_submits)
    }

    fn synced_height(&self) -> u64 {
        self.ledger.with_ledger_block(LedgerBlock::height)
    }

    fn block_hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.ledger
            .with_ledger_block(|ledger| ledger.block_hash_at(height).copied())
    }

    fn held_bytes_for(&self, tx_hash: &TxHash) -> Option<Vec<u8>> {
        LocalPendingTx::held_bytes_for(self, tx_hash)
    }

    fn prune_held_bytes(&self, live: &HashSet<TxHash>) {
        LocalPendingTx::prune_held_bytes(self, live);
    }

    fn drain_rescan_queue(&self) -> Vec<RescanRequest> {
        LocalPendingTx::drain_rescan_queue(self)
    }

    fn release_awaiting_confirmation(&self, tx_hashes: &HashSet<TxHash>) -> usize {
        // Whole-`WalletLedger` guard: the confirmed-absent verdict
        // releases the F14 locks *and* retires the WI-RPC-3 retention
        // record in the same atomic write — the tx provably never
        // confirmed, so its `tx_meta.tx_keys` secret has no future
        // OUTBOUND proof to serve and its `pending_tx_hashes` entry
        // has no confirmation to await (retention lifecycle pin 2,
        // `docs/api/wallet_rpc.yaml` OUTBOUND PREREQUISITE).
        self.ledger.with_wallet_ledger_mut(|wallet| {
            let released =
                submit_watchdog::release_awaiting_confirmation(&mut wallet.ledger, tx_hashes);
            for tx_hash in tx_hashes {
                let hash_bytes = tx_hash.to_bytes();
                wallet.tx_meta.tx_keys.remove(&hash_bytes);
                wallet
                    .sync_state
                    .pending_tx_hashes
                    .retain(|h| *h != hash_bytes);
            }
            released
        })
    }

    fn emit(&self, event: PendingTxDiagnostic) {
        emit_pending_tx_diagnostic(self.sink.as_ref(), event);
    }
}

impl<S, O, F, FS, TS, L> PendingTxEngine for LocalPendingTx<S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    async fn build(&self, request: TxRequest) -> Result<PendingTx, SendError> {
        if request.recipients.is_empty() {
            let err = SendError::InvalidRecipient {
                reason: "TxRequest must carry at least one recipient",
            };
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::BuildFailed {
                    kind: build_error_kind(&err),
                },
            );
            return Err(err);
        }

        // F28/F37 loop-breaker gate (§2.5): while tripped, automatic
        // builds are refused — the alarm was raised at trip time and only
        // operator acknowledgment re-enables building.
        {
            let tripped = self
                .state
                .lock()
                .map_err(|_| SendError::CannotSign {
                    reason: "pending-tx state lock poisoned",
                })?
                .loop_breaker
                .tripped();
            if let Some(kind) = tripped {
                let err = SendError::SubmitLoopBreakerTripped { kind };
                emit_build_failed(self.sink.as_ref(), &err);
                return Err(err);
            }
        }

        let fee_snapshot = self.fee_snapshot_source.fetch().await.map_err(|err| {
            fail_build_after_attempted(self.sink.as_ref(), map_fee_estimator_error(&err))
        })?;
        // CT-5 §3.2.1 D1/D3 (commit 4b): read the curve-tree resume cursor
        // *before* the synchronous selection so the spendable set is gated on
        // `min(synced_height, tree_cursor)`. This is the only `.await` the gate
        // needs — `build_assemble_sync` then runs entirely under the state lock
        // with the cursor snapshot in hand. A failed read is the hard-failure
        // path (`CurveTreeUnavailable`), distinct from the benign "tree behind"
        // lag the gate itself surfaces (`SpendUnavailableRebuilding`).
        let tree_gate = match &self.curve_tree {
            None => TreeSpendGate::Unenforced,
            Some(handle) => {
                let covered_through = handle.ingested_tip_height().await.map_err(|err| {
                    fail_build_after_attempted(
                        self.sink.as_ref(),
                        map_curve_tree_handle_error_for_send(&err),
                    )
                })?;
                TreeSpendGate::Enforced {
                    covered_through: covered_through.map(|bh| bh.0),
                }
            }
        };
        // CT-5b §3.2 / CT-5c: bind the reference block the proof anchors to and
        // read the tree depth there. The reference root is never persisted
        // (derive>hold, R1-Q6) — read `(root, depth)` from the actor at
        // `reference_height = tip − REF_ANCHOR_AGE` in one snapshot
        // (`reference_root_and_depth`, Q1). Only when a tree is enforced, the
        // chain is old enough, and the tree has reached the reference height (so
        // the root is reconstructable); otherwise leave it unresolved and the
        // synchronous selection classifies the condition (`WalletTooYoungToSpend`
        // / `SpendUnavailableRebuilding`) or, with no tree, the assembly step
        // below refuses (a spend requires the curve tree — no synthetic
        // fallback). The depth sizes the FCMP++ proof weight for fee estimation;
        // its `1` default is inert because those unresolved cases never assemble.
        let (reference, tree_depth) = match &self.curve_tree {
            Some(handle) => {
                let synced = self.ledger.with_ledger_block(LedgerBlock::height);
                match select_reference_height(synced) {
                    Some(rh)
                        if matches!(
                            tree_gate,
                            TreeSpendGate::Enforced { covered_through: Some(c) } if c >= rh
                        ) =>
                    {
                        let (curve_tree_root, depth) = handle
                            .reference_root_and_depth(BlockHeight(rh))
                            .await
                            .map_err(|err| {
                                fail_build_after_attempted(
                                    self.sink.as_ref(),
                                    map_curve_tree_handle_error_for_send(&err),
                                )
                            })?;
                        let block_hash = self
                            .ledger
                            .with_ledger_block(|ledger| ledger.block_hash_at(rh).copied())
                            .ok_or_else(|| {
                                fail_build_after_attempted(
                                    self.sink.as_ref(),
                                    SendError::CannotSign {
                                        reason: "reference-height block hash missing from ledger",
                                    },
                                )
                            })?;
                        (
                            Some(ReferenceBlock {
                                height: BlockHeight(rh),
                                curve_tree_root,
                                block_hash,
                            }),
                            depth,
                        )
                    }
                    _ => (None, 1u8),
                }
            }
            None => (None, 1u8),
        };
        let BuildSelected {
            assemble_inputs,
            fee_directive,
            meta,
        } = self.build_select_sync(&request, fee_snapshot, tree_gate, reference, tree_depth)?;
        let mut reservation_cleanup = BuildReservationCleanup::new(self, meta.reservation_id);

        // CT-5c: assemble the real FCMP++ membership paths for the whole tx in
        // one actor round-trip (`AssembleTx`, T3), then fold them into the
        // signing context. A spend requires the curve tree and a resolved
        // reference; both hold whenever the C2 gate admitted a candidate, so
        // their absence here is a not-yet-spendable / no-tree condition the gate
        // already classified — a defensive refusal, not a user-facing path. The
        // reservation cleanup (armed above) releases the output locks if any of
        // these steps fail.
        let handle = self.curve_tree.as_ref().ok_or_else(|| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "curve tree required to assemble a membership proof",
                },
            )
        })?;
        let reference = reference.ok_or_else(|| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "no reference block resolved for membership assembly",
                },
            )
        })?;
        let paths = handle
            .assemble_tx(reference, assemble_inputs.clone())
            .await
            .map_err(|err| {
                fail_build_after_attempted(
                    self.sink.as_ref(),
                    map_curve_tree_handle_error_for_send(&err),
                )
            })?;
        // Q1: the assembled depth must equal the depth the fee was sized against.
        // Both are read at the one reference height, so a divergence means the
        // tree moved under the reference — refuse rather than sign a proof whose
        // weight the fee did not cover. Holds as a tautology under a valid
        // reference; never fires benignly. Check *every* path (all share the one
        // reference's tree, so they should agree — verifying all closes the gap
        // if that invariant ever breaks).
        if paths.iter().any(|p| p.tree.tree_depth != tree_depth) {
            return Err(fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "assembled tree depth diverged from the fee estimate",
                },
            ));
        }
        // Fold the real paths into the signing context, re-reading the selected
        // transfers by index for their secret-pathway fields (`TransferDetails`
        // is not `Clone`). `assemble_tx_to_sign` guards each re-read with a
        // `gindex` check against `assemble_inputs`, so an index shift under a
        // reorg during the assemble round-trip is refused, not mis-signed.
        let tx_to_sign = self.ledger.with_ledger_block(|ledger| {
            assemble_tx_to_sign(
                self.network,
                &request,
                &meta.selected.indices,
                ledger.transfers(),
                &assemble_inputs,
                &paths,
                fee_directive,
            )
        })?;
        let signed = self
            .signer
            .sign_transfer(TransferSigningContext::from_tx(tx_to_sign))
            .await
            .map_err(|err| {
                let signer_err: SignerError = err.into();
                fail_build_after_attempted(self.sink.as_ref(), map_signer_error(&signer_err))
            })?;
        let pending = self.commit_built_sync(&request, &meta, reference, signed)?;
        reservation_cleanup.disarm();
        Ok(pending)
    }

    fn submit(
        &self,
        id: ReservationId,
        seen_gen: u64,
    ) -> impl Future<Output = Result<TxHash, SubmitError>> + Send {
        let this = self;
        async move { this.submit_async(id, seen_gen).await }
    }

    fn discard(&self, id: ReservationId, reason: DiscardReason) -> Result<(), PendingTxError> {
        self.discard_sync(id, reason)
    }

    fn signal_mempool_evicted(&self, rid: ReservationId) -> Result<(), PendingTxError> {
        self.signal_mempool_evicted_sync(rid)
    }

    fn outstanding(&self) -> usize {
        let state = self.state.lock().expect("pending-tx state lock poisoned");
        state.consumer_held.len() + state.in_flight.len()
    }
}
