// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The engine's submit, and the two saves around it (A19).
//!
//! The dispatch record is saved before the bytes leave, inside
//! [`PendingTxEngine::submit`] through the [`LedgerCommit`] the engine lends
//! it ([`dispatch_durability`](super::dispatch_durability)); what the
//! daemon's verdict changed is saved before [`Engine::submit_pending_tx`]
//! returns, and reported in the [`SubmitReceipt`]. Specialized to
//! [`LocalLedger`], like `abandon_tx_persisted` and `persist_bond_record`:
//! the verdict save writes the whole `WalletLedger`, which only the local
//! ledger hands out.

use super::dispatch_durability::{EngineLedgerCommit, LedgerCommit};
use super::error::SubmitError;
use super::pending::{ReservationId, SubmitOutcome};
use super::traits::{DaemonEngine, PendingTxEngine, RefreshEngine};
use super::{Engine, EngineSignerKind, LocalLedger};

/// What [`Engine::submit_pending_tx`]
/// returns on success: the daemon's verdict, and whether the wallet saved
/// what that verdict changed (A19).
///
/// The dispatch itself was saved before the bytes left — a submit whose
/// dispatch save fails sends nothing and returns
/// [`SubmitError::DispatchNotSaved`].
/// The verdict save (the F14 lock baseline the accept stamped) runs after
/// the bytes left, so its failure cannot undo the send: it is reported
/// here instead. The send stands, the record of it is on disk, and the
/// next successful save writes the baseline; until then a restart treats
/// the send as one whose verdict never arrived (locked at its dispatch
/// height, and a resend is the user's decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitReceipt {
    /// The daemon's verdict.
    pub outcome: SubmitOutcome,
    /// `false` when the save of the verdict's changes failed (see the
    /// type docs). The cause is in the wallet's log.
    pub verdict_saved: bool,
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        F: super::traits::PersistenceEngine,
    > Engine<S, D, LocalLedger, E, R, P, F>
{
    /// Submit a [`PendingTx`] handle via [`PendingTxEngine::submit`].
    ///
    /// `seen_gen` is the [`PendingTx::content_gen`] the consumer last reviewed;
    /// it gates broadcast against a submit-time re-anchor that changed the
    /// authorized content (CT-5d, [`docs/design/CT5D_REANCHOR.md`] §4).
    ///
    /// Success is the identity-bearing [`SubmitOutcome`] — fresh accept,
    /// pool-resident duplicate, or the daemon's already-in-chain claim
    /// with its claimed height (all sharing the §2.5 lock disposition) —
    /// inside a [`SubmitReceipt`] that says whether the verdict was saved.
    ///
    /// `&self` (same interior-mutability insight as build, W-B review):
    /// submit mutates only under the implementor's own state lock and
    /// the ledger guard, and awaits the daemon RPC without needing an
    /// exclusive Engine borrow.
    ///
    /// `&self`: the daemon round-trip is implementor-owned interior
    /// mutability, so embedders may hold a shared Engine borrow across
    /// submit (wallet-RPC uses a read guard) without stalling concurrent
    /// read RPCs for the duration of the network call.
    ///
    /// Two saves (A19): the dispatch record is saved before the bytes
    /// leave (inside [`PendingTxEngine::submit`]; a failure is
    /// [`SubmitError::DispatchNotSaved`] and nothing was sent), and what
    /// the verdict changed is saved before this returns
    /// ([`SubmitReceipt::verdict_saved`]).
    pub async fn submit_pending_tx(
        &self,
        id: ReservationId,
        seen_gen: u64,
    ) -> Result<SubmitReceipt, SubmitError> {
        let commit = EngineLedgerCommit::new(&self.persistence, self.state_wrap_key());
        let result = self.pending.submit(id, seen_gen, &commit).await;
        self.save_verdict(&commit, result)
    }

    /// Save what a definite verdict changed: the F14 lock baseline an
    /// accept or an already-in-chain claim stamped, or the record a
    /// terminal or retryable refusal retired. An ambiguous verdict, and
    /// every refusal before the dispatch, changed nothing on disk.
    ///
    /// The bytes have left, so a failure here does not undo the send. On
    /// success it is reported in [`SubmitReceipt::verdict_saved`]; on a
    /// refusal it is logged — the saved row still says dispatched, so a
    /// restart locks it and lists it among the held sends, and a resend
    /// returns the same refusal and releases it.
    fn save_verdict(
        &self,
        commit: &EngineLedgerCommit<'_, F>,
        result: Result<SubmitOutcome, SubmitError>,
    ) -> Result<SubmitReceipt, SubmitError> {
        let definite = matches!(
            result,
            Ok(_)
                | Err(SubmitError::DaemonRejectedTerminal { .. }
                    | SubmitError::DaemonRejectedRetryable { .. })
        );
        let saved = if definite {
            let guard = self.ledger.read();
            match commit.commit(&guard.ledger) {
                Ok(()) => true,
                Err(error) => {
                    tracing::error!(
                        %error,
                        "submit: the send left and stands, but saving its verdict failed; \
                         the next save writes it"
                    );
                    false
                }
            }
        } else {
            true
        };
        result.map(|outcome| SubmitReceipt {
            outcome,
            verdict_saved: saved,
        })
    }
}
