// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Engine-level DKG session orchestration.
//!
//! Wraps `shekyl_fcmp::frost_dkg::DkgSession` with file-based transport:
//! each round produces a serializable message bundle that can be exchanged
//! via JSON files between air-gapped participants.

use std::collections::HashMap;

use shekyl_fcmp::frost_dkg::{
    DkgParams, DkgRound1Message, DkgRound2Message, DkgSession, SerializedThresholdKeys,
};
use shekyl_fcmp::proof::ProveError;

use modular_frost::Participant;

use super::group::MultisigGroup;

/// Engine-level DKG session.
///
/// Manages the DKG state machine and provides convenience methods for
/// serializing/deserializing round messages as JSON for file transport.
pub struct MultisigDkgSession {
    pub threshold: u16,
    pub total: u16,
    pub our_index: u16,
    pub context: [u8; 32],
    session: Option<DkgSession>,
    our_round1_msg: Option<DkgRound1Message>,
}

impl MultisigDkgSession {
    /// Start a new DKG session.
    ///
    /// `context` should be derived from all participants' public identifiers
    /// to prevent replay attacks across different DKG instances.
    pub fn new(
        threshold: u16,
        total: u16,
        our_index: u16,
        context: [u8; 32],
    ) -> Result<Self, ProveError> {
        let params = DkgParams {
            threshold,
            total,
            our_index,
        };
        let session = DkgSession::new(&params, context)?;
        Ok(Self {
            threshold,
            total,
            our_index,
            context,
            session: Some(session),
            our_round1_msg: None,
        })
    }

    /// Generate round 1 message (polynomial commitments).
    ///
    /// The returned message must be broadcast to all other participants.
    pub fn round1(&mut self) -> Result<DkgRound1Message, ProveError> {
        let session = self
            .session
            .take()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;
        let (next, msg) = session.generate_coefficients()?;
        self.our_round1_msg = Some(msg.clone());
        self.session = Some(next);
        Ok(msg)
    }

    /// Process all round 1 messages and produce round 2 shares.
    ///
    /// `others`: round 1 messages from all *other* participants.
    /// Returns a map of per-recipient encrypted secret shares.
    pub fn round2(
        &mut self,
        others: HashMap<Participant, DkgRound1Message>,
    ) -> Result<HashMap<Participant, DkgRound2Message>, ProveError> {
        let session = self
            .session
            .take()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;
        let (next, shares) = session.generate_secret_shares(others)?;
        self.session = Some(next);
        Ok(shares)
    }

    /// Process received shares and prepare for confirmation.
    pub fn process_shares(
        &mut self,
        shares: HashMap<Participant, DkgRound2Message>,
    ) -> Result<(), ProveError> {
        let session = self
            .session
            .take()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;
        let next = session.calculate_share(shares)?;
        self.session = Some(next);
        Ok(())
    }

    /// Finalize the DKG after all participants confirm success.
    ///
    /// Returns a `MultisigGroup` with the generated threshold keys.
    pub fn finalize(&mut self) -> Result<MultisigGroup, ProveError> {
        let session = self
            .session
            .take()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;
        let keys = session.confirm_complete()?;
        let serialized = SerializedThresholdKeys::from_keys(&keys);

        let group = MultisigGroup::new(
            self.context,
            self.threshold,
            self.total,
            self.our_index,
            &serialized,
        );

        Ok(group)
    }
}
