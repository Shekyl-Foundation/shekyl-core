// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment-request bookkeeping API (FA-8d engine surface).

use shekyl_address::{format_payment_uri, parse_payment_uri, PaymentUri};
use shekyl_engine_state::{LocalLabel, PaymentRequest, PaymentRequestId, PaymentRequestState};
use shekyl_units::AtomicUnits;

use super::error::PersistenceError;
use super::lifecycle::drive_persistence;
use super::traits::{DaemonEngine, PendingTxEngine, PersistenceEngine, RefreshEngine};
use super::{Engine, EngineSignerKind, LocalLedger};

/// Input for creating an off-chain payment request.
#[derive(Clone, Debug)]
pub struct NewPaymentRequest {
    pub label: String,
    pub amount_atomic: AtomicUnits,
    pub created_at: u64,
    pub expiry: Option<u64>,
}

/// Filter for listing payment requests (minimal V3.0).
#[derive(Clone, Copy, Debug, Default)]
pub enum PaymentRequestFilter {
    #[default]
    All,
    Pending,
    Matched,
}

// Generic over `F: PersistenceEngine` (rather than the `F = WalletFile`
// default) so `create_payment_request_persisted` can drive the normal
// crash-atomic ledger save path — the same widening `stake_persist.rs` uses
// for `persist_bond_record`. `WalletFile` satisfies the bound, so every
// existing caller is unaffected.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, LocalLedger, E, R, P, F>
{
    /// Persist a new pending payment request and return its opaque id.
    pub fn create_payment_request(&self, req: NewPaymentRequest) -> PaymentRequestId {
        const MAX_ID_COLLISION_RETRIES: u32 = 64;
        let mut guard = self.ledger.write();
        let requests = &guard.ledger.bookkeeping.payment_requests;
        let mut collisions = 0u32;
        let id = loop {
            let candidate = PaymentRequestId::new_random();
            if requests.iter().all(|r| r.id != candidate) {
                break candidate;
            }
            collisions += 1;
            if collisions >= MAX_ID_COLLISION_RETRIES {
                panic!("PaymentRequestId: exhausted collision retries");
            }
        };
        let pr = PaymentRequest {
            id,
            label: LocalLabel::from_owned(req.label),
            amount_atomic: req.amount_atomic,
            created_at: req.created_at,
            expiry: req.expiry,
            state: PaymentRequestState::Pending,
            matched_tx_hash: None,
            matched_output_index: None,
        };
        guard.ledger.bookkeeping.payment_requests.push(pr);
        id
    }

    /// Create a payment request **and durably commit it** via the normal
    /// crash-atomic ledger save path ([`PersistenceEngine::save_state`] →
    /// `atomic_write_file`), so the request survives a restart.
    ///
    /// This is the RPC-facing entry point: a merchant handing out a URI must
    /// be able to match the payment after a wallet restart, so the bookkeeping
    /// write is not left to ride the next incidental save. There is **no
    /// second writer path** — this is the same `save_state` every other ledger
    /// commit uses (mirrors `stake_persist::persist_bond_record`).
    ///
    /// The in-memory mutation happens first under a scoped write guard (via
    /// [`Self::create_payment_request`]), which is dropped before the
    /// read-guarded save (same `RwLock`; overlapping would deadlock).
    ///
    /// # Errors
    ///
    /// [`PersistenceError`] if the durable save fails. The in-memory request
    /// is rolled back in that case, so a failed create leaves no phantom
    /// request that would silently vanish at the next restart (fail closed).
    pub fn create_payment_request_persisted(
        &self,
        req: NewPaymentRequest,
    ) -> Result<PaymentRequestId, PersistenceError> {
        let id = self.create_payment_request(req);

        let save_result = {
            let ledger_guard = self.ledger.read();
            drive_persistence(
                self.persistence
                    .save_state(self.state_wrap_key(), &ledger_guard.ledger),
            )
        };

        if let Err(e) = save_result {
            // Fail closed: remove the in-memory request so the caller never
            // hands out a `rid` that would not survive a restart.
            let mut guard = self.ledger.write();
            guard
                .ledger
                .bookkeeping
                .payment_requests
                .retain(|r| r.id != id);
            return Err(e.into());
        }

        Ok(id)
    }

    /// List payment requests matching `filter`.
    pub fn list_payment_requests(&self, filter: PaymentRequestFilter) -> Vec<PaymentRequest> {
        self.ledger
            .read()
            .ledger
            .bookkeeping
            .payment_requests
            .iter()
            .filter(|r| match filter {
                PaymentRequestFilter::All => true,
                PaymentRequestFilter::Pending => r.state == PaymentRequestState::Pending,
                PaymentRequestFilter::Matched => r.state == PaymentRequestState::Matched,
            })
            .cloned()
            .collect()
    }

    /// Build a `shekyl:…` URI for a persisted request (`address` is the payee).
    ///
    /// Amount, label, and expiry are taken from bookkeeping so the on-wire `rid`
    /// cannot drift from the stored request. Returns `None` when `id` is unknown.
    pub fn format_request_uri(&self, address: &str, id: PaymentRequestId) -> Option<String> {
        let guard = self.ledger.read();
        let req = guard
            .ledger
            .bookkeeping
            .payment_requests
            .iter()
            .find(|r| r.id == id)?;
        let label = (!req.label.is_empty()).then(|| req.label.expose().as_str());
        Some(format_payment_uri(
            address,
            Some(req.amount_atomic.to_raw()),
            label,
            Some(req.id.as_u64()),
            req.expiry,
        ))
    }

    /// Parse a cooperative payment URI from user input.
    pub fn parse_request_uri(uri: &str) -> Result<PaymentUri, shekyl_address::PaymentUriError> {
        parse_payment_uri(uri)
    }
}
