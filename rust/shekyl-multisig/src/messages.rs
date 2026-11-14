// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! The Option E′ ceremony's message types (`SHEKYL_MULTISIG_WIRE_FORMAT.md`
//! §2; `PQC_MULTISIG.md` §12.2).
//!
//! A type travels inside a ceremony file's ciphertext (`crate::envelope`), so
//! nothing that carries a file sees which step it is (R-10). This module fixes
//! the discriminants; PR-C defines each body.
//!
//! Retired values are never reused: `0x02` and `0x04`–`0x07`, `0x0A` were the
//! Option D prover-output, veto, prover-receipt, heartbeat, counter-proof and
//! rotation-intent types; `0x01` (`SpendIntent`) is replaced by `Proposal`,
//! which carries the intent together with the proposer's first round; `0x08`
//! (`GroupStateSummary`) had no producer or reader. The wire format's table
//! records each as REJECTED.

/// A ceremony message's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// A FROST signature share.
    SignatureShare = 0x03,
    /// Evidence that a member saw an invariant fail.
    InvariantViolation = 0x09,
    /// Two conflicting messages signed by one member.
    EquivocationProof = 0x0B,
    /// The intent, and the proposer's preprocesses.
    Proposal = 0x0C,
    /// A holder's preprocesses.
    Commitment = 0x0D,
    /// The preprocess set the responder signs over.
    SigningSet = 0x0E,
    /// The responder's preprocesses and shares.
    ResponderShare = 0x0F,
    /// The finished transaction.
    FinalTx = 0x10,
    /// Per input: the signer's per-output public key and hybrid signature.
    HybridSig = 0x11,
}

impl MessageType {
    /// Every type, in discriminant order.
    pub const ALL: [Self; 9] = [
        Self::SignatureShare,
        Self::InvariantViolation,
        Self::EquivocationProof,
        Self::Proposal,
        Self::Commitment,
        Self::SigningSet,
        Self::ResponderShare,
        Self::FinalTx,
        Self::HybridSig,
    ];

    /// The type a discriminant names, or `None` for a retired or unassigned
    /// value.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| *t as u8 == v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_type_round_trips_and_no_retired_value_decodes() {
        for t in MessageType::ALL {
            assert_eq!(MessageType::from_u8(t as u8), Some(t));
        }
        for retired in [
            0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x12, 0xFF,
        ] {
            assert_eq!(MessageType::from_u8(retired), None, "{retired:#04x}");
        }
    }
}
