// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The send's dispatch record and its saved bytes (A19): the save that
//! must succeed before the bytes can leave ([`LocalPendingTx::save_dispatch`]),
//! and the reads and edits of the saved sends the watchdog and the user's
//! resend act on. Carved out of `transfer/engine.rs` by workflow, as the
//! decomposition ratchet asks.

use super::super::diagnostics::{emit_pending_tx_diagnostic, PendingTxDiagnostic};
use super::super::dispatch_durability::{commit_dispatch, DurableTxBytes, LedgerCommit};
use super::super::error::SubmitError;
use super::super::fee_estimator::FeeEstimator;
use super::super::fee_snapshot::FeeSnapshotSource;
use super::super::output_selector::OutputSelector;
use super::super::pending::{ReservationId, TxHash};
use super::super::signer::Signer;
use super::super::traits::LedgerEngine;
use super::super::transaction_submitter::TransactionSubmitter;
use super::engine::LocalPendingTx;
use super::types::{OutputId, Stage1LedgerSpendableAccess};

/// What a dispatch records, gathered under the state lock at the flip and
/// written under the ledger guard by `commit_dispatch` (A19).
pub(super) struct DispatchFacts {
    pub(super) txid: TxHash,
    pub(super) fee: u64,
    pub(super) tx_bytes: Vec<u8>,
    pub(super) selected: Vec<OutputId>,
    pub(super) retained: shekyl_engine_state::TxSecretKey,
    pub(super) recipients: Vec<shekyl_engine_state::SendRecipient>,
}

#[allow(private_bounds)]
impl<S, O, F, FS, TS, L> LocalPendingTx<S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    /// Write the dispatch record and save it before the bytes can leave
    /// (A19; WI-RPC-3 pin 1, dispatch form), minting the [`DurableTxBytes`]
    /// the submitter requires.
    ///
    /// The accept verdict is an *observation* about network exposure,
    /// not its start: a crash, a kill or a dropped connection between
    /// the send and the verdict leaves a tx the network may still mine.
    /// So the journal row (with the signed bytes), the retained per-tx
    /// secret (the OUTBOUND proof) and the input set the F14 lock holds
    /// are written and the whole ledger saved, under one write guard,
    /// before the bytes can leave; only that save mints the
    /// `DurableTxBytes` the submitter requires. Definite refusals
    /// (terminal / retryable — provably unrelayed under single-egress,
    /// §2.5) retire the record in their finalizers, so a never-accepted
    /// build still leaves no secret residue.
    ///
    /// Second copy of the secret, accounted: from here the saved record
    /// is the durable holder; the runtime copy stays on the in-flight
    /// entry only so a §2.5 retryable restoration can re-dispatch, and
    /// is wiped when the entry drops (`TxSecretKey` is zeroize-on-drop).
    ///
    /// On a failed save nothing left the wallet and the record is undone:
    /// the reservation goes back to `consumer_held` with its output locks,
    /// exactly as before the flip, and the submit is refused
    /// [`SubmitError::DispatchNotSaved`]. On success the send is marked as
    /// this session's: the watchdog may resend its bytes on its own (rung
    /// 1). A held send outside that set was dispatched before a restart, and
    /// resending it is the user's decision (§5.3).
    pub(super) fn save_dispatch<C: LedgerCommit>(
        &self,
        id: ReservationId,
        dispatch: DispatchFacts,
        commit: &C,
    ) -> Result<DurableTxBytes, SubmitError> {
        let DispatchFacts {
            txid: dispatch_txid,
            fee: realized_fee,
            tx_bytes,
            selected,
            retained,
            recipients,
        } = dispatch;
        let saved = self.ledger.with_wallet_ledger_mut(|wallet| {
            commit_dispatch(
                wallet,
                commit,
                dispatch_txid.to_bytes(),
                tx_bytes.clone(),
                |wallet| {
                    wallet.record_retained_tx_key(dispatch_txid.to_bytes(), retained);
                    // PR-SJ-1: the journal row is born in the same guard as
                    // the retention record. C2: the journal owns these
                    // facts; the F14 lock set is derived from them.
                    let inputs: Vec<shekyl_engine_state::SendInputRef> = selected
                        .iter()
                        .map(|&idx| {
                            let td = wallet.ledger.transfers().get(idx).unwrap_or_else(|| {
                                panic!(
                                    "dispatch: output_locks references missing transfer index {idx}"
                                )
                            });
                            shekyl_engine_state::SendInputRef {
                                gindex: td.global_output_index.to_raw(),
                                amount: td.amount().to_raw(),
                            }
                        })
                        .collect();
                    wallet.record_dispatched_send(
                        dispatch_txid.to_bytes(),
                        realized_fee,
                        recipients,
                        inputs,
                        tx_bytes,
                    );
                },
            )
        });

        let mut state = self
            .state
            .lock()
            .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;
        match saved {
            Ok(durable) => {
                state.dispatched_this_session.insert(dispatch_txid);
                emit_pending_tx_diagnostic(
                    self.sink.as_ref(),
                    PendingTxDiagnostic::SubmitAttempted { reservation_id: id },
                );
                Ok(durable)
            }
            Err(source) => {
                if let Some(flight) = state.in_flight.remove(&id) {
                    state.consumer_held.insert(id, flight.entry);
                }
                emit_pending_tx_diagnostic(
                    self.sink.as_ref(),
                    PendingTxDiagnostic::SubmitNotSaved { reservation_id: id },
                );
                Err(SubmitError::DispatchNotSaved {
                    reservation_id: id,
                    source,
                })
            }
        }
    }

    /// The saved network-exposed bytes of the held send `tx_hash`, cloned
    /// for the watchdog's resubmit-same-bytes probe. They live on the
    /// send's journal row, saved at dispatch (A19), so they survive a
    /// restart; `None` only for a row that holds none
    /// ([`SendRecord::tx_bytes`](shekyl_engine_state::SendRecord::tx_bytes)).
    pub(crate) fn held_bytes_for(&self, tx_hash: &TxHash) -> Option<Vec<u8>> {
        self.ledger.with_wallet_ledger(|wallet| {
            wallet
                .send_journal
                .tx_bytes(&tx_hash.to_bytes())
                .map(<[u8]>::to_vec)
        })
    }

    /// Drop the saved bytes of every send that can no longer need them
    /// ([`SendJournalBlock::prune_settled_tx_bytes`](shekyl_engine_state::SendJournalBlock::prune_settled_tx_bytes)):
    /// by row state, with confirmations kept until they are deeper than the
    /// wallet's reorg margin. Re-derivable housekeeping: it rides the next
    /// save.
    pub(crate) fn prune_settled_send_bytes(&self) {
        let margin = shekyl_engine_state::WalletSafetyConstants::DEFAULTS
            .max_reorg_depth
            .to_raw();
        self.ledger.with_wallet_ledger_mut(|wallet| {
            let synced = wallet.ledger.height();
            wallet.send_journal.prune_settled_tx_bytes(synced, margin);
        });
    }

    /// Whether `tx_hash` was dispatched (or resent by the user) in this
    /// session. A held send outside this set was dispatched before a
    /// restart: the watchdog does not resend it on its own (§5.3).
    pub(crate) fn dispatched_this_session(&self, tx_hash: &TxHash) -> bool {
        self.state
            .lock()
            .expect("pending-tx state lock poisoned")
            .dispatched_this_session
            .contains(tx_hash)
    }

    /// Record the user's decision to resend the held send `tx_hash`: from
    /// here this session owns it, and the watchdog's automatic rung 1
    /// applies to it again.
    pub(crate) fn adopt_into_session(&self, tx_hash: TxHash) {
        self.state
            .lock()
            .expect("pending-tx state lock poisoned")
            .dispatched_this_session
            .insert(tx_hash);
    }
}
