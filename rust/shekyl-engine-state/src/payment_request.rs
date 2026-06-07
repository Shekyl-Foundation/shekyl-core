// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment requests and inbound receive attribution (FA-8).
//!
//! Normative: `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7.9, §5.7.11.

use serde::{Deserialize, Serialize};

use crate::local_label::LocalLabel;

/// Opaque wallet-local payment-request identifier (`rid` on wire).
///
/// Assigned with CSPRNG — never sequential (`SUBADDRESS_UNDER_PQC.md`
/// §5.7.11). `0` is reserved invalid.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, postcard_schema::Schema,
)]
pub struct PaymentRequestId(pub u64);

/// Maximum `rid` encodable in the 6-byte REQUEST plaintext field (u48 LE).
pub const PAYMENT_REQUEST_RID_U48_MAX: u64 = (1u64 << 48) - 1;

impl PaymentRequestId {
    /// Reserved invalid value; must not appear on wire or in URIs.
    pub const INVALID: PaymentRequestId = PaymentRequestId(0);

    /// True when `rid` is non-zero and fits the on-wire u48 LE encoding.
    #[must_use]
    pub const fn rid_fits_wire(rid: u64) -> bool {
        rid != 0 && rid <= PAYMENT_REQUEST_RID_U48_MAX
    }

    /// Generate a new opaque id from the OS CSPRNG.
    ///
    /// Draws six bytes (u48 LE), retrying until a non-reserved value is drawn.
    pub fn new_random() -> Self {
        const MAX_ATTEMPTS: u32 = 64;
        let mut buf = [0u8; 6];
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                panic!("PaymentRequestId CSPRNG exhausted after {MAX_ATTEMPTS} attempts");
            }
            if getrandom::getrandom(&mut buf).is_err() {
                continue;
            }
            let mut le = [0u8; 8];
            le[..6].copy_from_slice(&buf);
            let id = u64::from_le_bytes(le);
            if Self::rid_fits_wire(id) {
                return Self(id);
            }
        }
    }

    /// Raw `u64` for URI / wire encoding (u48 LE in label plaintext).
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Lifecycle state of an off-chain payment request.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema,
)]
pub enum PaymentRequestState {
    #[default]
    Pending,
    Matched,
    Expired,
    Cancelled,
}

/// Off-chain invoice persisted in [`crate::bookkeeping_block::BookkeepingBlock`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub id: PaymentRequestId,
    #[serde(with = "crate::serde_helpers::local_label")]
    pub label: LocalLabel,
    pub amount_atomic: u64,
    pub created_at: u64,
    #[serde(default)]
    pub expiry: Option<u64>,
    pub state: PaymentRequestState,
    #[serde(default)]
    pub matched_tx_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub matched_output_index: Option<u64>,
}

#[derive(postcard_schema::Schema)]
#[allow(dead_code)]
struct PaymentRequestSchema {
    id: PaymentRequestId,
    label: String,
    amount_atomic: u64,
    created_at: u64,
    expiry: Option<u64>,
    state: PaymentRequestState,
    matched_tx_hash: Option<[u8; 32]>,
    matched_output_index: Option<u64>,
}

impl postcard_schema::Schema for PaymentRequest {
    const SCHEMA: &'static postcard_schema::schema::NamedType =
        &postcard_schema::schema::NamedType {
            name: "PaymentRequest",
            ty: <PaymentRequestSchema as postcard_schema::Schema>::SCHEMA.ty,
        };
}

impl PaymentRequest {
    /// True when `expiry` has passed at `current_height` (block-height clock).
    #[must_use]
    pub fn is_expired_at(&self, current_height: u64) -> bool {
        self.expiry.is_some_and(|e| current_height > e)
    }
}

/// Why the user flagged a receive as disputed (bookkeeping only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub enum DisputeReason {
    WrongLabel,
    WrongAmount,
    Other(String),
}

/// Bookkeeping attribution for an inbound transfer (`TransferDetails`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub enum ReceiveAttribution {
    /// No cooperative label echo (sentinel or feature off).
    #[default]
    Unattributed,
    /// Cooperative `REQUEST` tag matched exactly one request (`Pending` or
    /// `Expired` per `SUBADDRESS_UNDER_PQC.md` §5.7.9 — UI warns on expired).
    Matched(PaymentRequestId),
    /// Label echoed but no unambiguous request match.
    LabelUnknown { echoed_label_hash: [u8; 32] },
    /// User manually linked transfer to a request.
    ManualMatch(PaymentRequestId),
    /// User flagged suspicious label; funds remain spendable.
    Disputed { reason: DisputeReason },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_request_id_never_zero_from_random() {
        for _ in 0..32 {
            let id = PaymentRequestId::new_random();
            assert_ne!(id, PaymentRequestId::INVALID);
            assert!(PaymentRequestId::rid_fits_wire(id.as_u64()));
        }
    }

    #[test]
    fn payment_request_postcard_roundtrip() {
        let req = PaymentRequest {
            id: PaymentRequestId(0x0000_1234_5678_9ABC),
            label: LocalLabel::from_str("INV-2026-0042"),
            amount_atomic: 150_000_000_000,
            created_at: 100,
            expiry: Some(200),
            state: PaymentRequestState::Pending,
            matched_tx_hash: None,
            matched_output_index: None,
        };
        let bytes = postcard::to_allocvec(&req).unwrap();
        let back: PaymentRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn receive_attribution_variants_roundtrip() {
        let cases = [
            ReceiveAttribution::Unattributed,
            ReceiveAttribution::Matched(PaymentRequestId(42)),
            ReceiveAttribution::LabelUnknown {
                echoed_label_hash: [7u8; 32],
            },
            ReceiveAttribution::ManualMatch(PaymentRequestId(99)),
            ReceiveAttribution::Disputed {
                reason: DisputeReason::WrongAmount,
            },
        ];
        for case in cases {
            let bytes = postcard::to_allocvec(&case).unwrap();
            let back: ReceiveAttribution = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(back, case);
        }
    }
}
