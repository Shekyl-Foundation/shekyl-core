// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment-request bookkeeping API (FA-8d engine surface).

use shekyl_address::{format_payment_uri, parse_payment_uri, PaymentUri};
use shekyl_engine_state::{LocalLabel, PaymentRequest, PaymentRequestId, PaymentRequestState};

use super::traits::{DaemonEngine, PendingTxEngine, RefreshEngine};
use super::{Engine, EngineSignerKind, LocalLedger};

/// Input for creating an off-chain payment request.
#[derive(Clone, Debug)]
pub struct NewPaymentRequest {
    pub label: String,
    pub amount_atomic: u64,
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

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
{
    /// Persist a new pending payment request and return its opaque id.
    pub fn create_payment_request(&self, req: NewPaymentRequest) -> PaymentRequestId {
        let id = PaymentRequestId::new_random();
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
        let mut guard = self.ledger.write();
        guard.ledger.bookkeeping.payment_requests.push(pr);
        id
    }

    /// List payment requests matching `filter`.
    pub fn list_payment_requests(&self, filter: PaymentRequestFilter) -> Vec<PaymentRequest> {
        self.ledger()
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

    /// Build a `shekyl:…` URI for sharing a request (address must be supplied).
    pub fn format_request_uri(
        &self,
        address: &str,
        id: PaymentRequestId,
        amount_atomic: u64,
        label: Option<&str>,
        expiry: Option<u64>,
    ) -> String {
        format_payment_uri(
            address,
            Some(amount_atomic),
            label,
            Some(id.as_u64()),
            expiry,
        )
    }

    /// Parse a cooperative payment URI from user input.
    pub fn parse_request_uri(uri: &str) -> Result<PaymentUri, shekyl_address::PaymentUriError> {
        parse_payment_uri(uri)
    }
}
