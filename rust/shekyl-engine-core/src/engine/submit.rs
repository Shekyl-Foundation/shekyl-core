// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The engine's submit.
//!
//! Specialized to [`LocalLedger`], like `abandon_tx_persisted` and
//! `persist_bond_record`: both saves write the whole `WalletLedger`,
//! which only the local ledger hands out. The dispatch record is saved
//! before the bytes leave, and the verdict's journal edit is saved with
//! that edit, inside [`PendingTxEngine::submit`]
//! ([`dispatch_durability`](super::dispatch_durability)). The receipt
//! reports whether the verdict save confirmed.

pub use super::pending::SubmitReceipt;

use super::dispatch_durability::EngineLedgerCommit;
use super::error::SubmitError;
use super::pending::ReservationId;
use super::traits::{DaemonEngine, PendingTxEngine, RefreshEngine};
use super::{Engine, EngineSignerKind, LocalLedger};

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
    /// Submit a [`PendingTx`](super::pending::PendingTx) handle via [`PendingTxEngine::submit`].
    ///
    /// `seen_gen` is the [`PendingTx::content_gen`] the consumer last reviewed;
    /// it gates broadcast against a submit-time re-anchor that changed the
    /// authorized content (CT-5d, [`docs/design/CT5D_REANCHOR.md`] §4).
    ///
    /// Success is the identity-bearing [`SubmitOutcome`](super::pending::SubmitOutcome) — fresh accept,
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
    /// The dispatch record is saved before the bytes leave. A failure is
    /// [`SubmitError::DispatchNotSaved`] and nothing was sent. The
    /// verdict's journal edit is saved with that edit;
    /// [`SubmitReceipt::verdict_saved`] says whether the save confirmed.
    /// A refusal's save failure is logged: the receipt is the refusal.
    pub async fn submit_pending_tx(
        &self,
        id: ReservationId,
        seen_gen: u64,
    ) -> Result<SubmitReceipt, SubmitError> {
        let commit = EngineLedgerCommit::new(&self.persistence, self.state_wrap_key());
        self.pending.submit(id, seen_gen, &commit).await
    }
}
