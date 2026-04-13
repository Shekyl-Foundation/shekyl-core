// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Wallet-level FROST signing session orchestration.
//!
//! Coordinates the multi-round FROST signing protocol between M participants:
//!
//! 1. Coordinator creates sessions, broadcasts signing request.
//! 2. Each signer preprocesses, returns nonce commitments.
//! 3. Coordinator aggregates nonces, broadcasts nonce sums.
//! 4. Each signer produces a partial share + PQC signature.
//! 5. Coordinator aggregates shares into SAL proofs, builds FCMP++ proof.

use modular_frost::Participant;
use shekyl_fcmp::frost_sal::{
    FrostPreprocessResult, FrostSalInput, FrostSalSession, FrostSignShareResult,
    FrostSigningCoordinator,
};
use shekyl_fcmp::proof::ProveError;
use shekyl_fcmp::{Input, SpendAuthAndLinkability};

use super::group::MultisigGroup;

/// Coordinator-side signing session for a multisig transaction.
///
/// Manages per-input `FrostSalSession`s and a `FrostSigningCoordinator`
/// to collect nonce commitments and partial shares from M signers.
pub struct MultisigSigningSession {
    our_index: u16,
    sessions: Vec<FrostSalSession>,
    coordinator: FrostSigningCoordinator,
    included: Vec<Participant>,
    state: SigningState,
}

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
enum SigningState {
    AwaitingPreprocesses,
    AwaitingSigning,
    AwaitingShares,
    Complete,
}

/// A signer's response to preprocessing (nonce commitments for all inputs).
pub struct PreprocessResponse {
    pub participant: u16,
    pub commitments: Vec<Vec<u8>>,
}

/// A signer's partial signature response.
pub struct ShareResponse {
    pub participant: u16,
    pub shares: Vec<[u8; 32]>,
}

impl MultisigSigningSession {
    /// Create a new signing session as the coordinator.
    ///
    /// Creates `FrostSalSession`s for each input and initializes the
    /// `FrostSigningCoordinator` for nonce/share aggregation.
    pub fn new_coordinator(
        group: &MultisigGroup,
        inputs: Vec<FrostSalInput>,
        included: Vec<u16>,
    ) -> Result<Self, ProveError> {
        if inputs.is_empty() {
            return Err(ProveError::EmptyInputs);
        }

        let participants: Vec<Participant> = included
            .iter()
            .filter_map(|&i| Participant::new(i))
            .collect();

        if participants.len() != included.len() {
            return Err(ProveError::UpstreamError(
                "invalid participant index (0 is not valid)".into(),
            ));
        }

        let mut sessions = Vec::with_capacity(inputs.len());
        for input in &inputs {
            sessions.push(FrostSalSession::new(input)?);
        }

        let coordinator =
            FrostSigningCoordinator::new_for_sal(sessions.len(), participants.clone())?;

        Ok(Self {
            our_index: group.our_index,
            sessions,
            coordinator,
            included: participants,
            state: SigningState::AwaitingPreprocesses,
        })
    }

    /// Coordinator-side: preprocess our own sessions and return commitments.
    ///
    /// Must be called before collecting other participants' preprocesses.
    pub fn preprocess_own(
        &mut self,
        group: &MultisigGroup,
    ) -> Result<PreprocessResponse, ProveError> {
        if self.state != SigningState::AwaitingPreprocesses {
            return Err(ProveError::UpstreamError(
                "wrong state for preprocess".into(),
            ));
        }

        let keys = group.threshold_keys().deserialize()?;
        let mut commitments = Vec::with_capacity(self.sessions.len());

        for session in &mut self.sessions {
            let result = session.preprocess(&keys)?;
            commitments.push(result.nonce_commitments);
        }

        let our_participant = Participant::new(self.our_index)
            .ok_or(ProveError::UpstreamError("invalid our_index".into()))?;

        let preprocesses: Vec<FrostPreprocessResult> = commitments
            .iter()
            .map(|c| FrostPreprocessResult {
                nonce_commitments: c.clone(),
                addendum: Vec::new(),
            })
            .collect();

        self.coordinator
            .collect_preprocesses(our_participant, preprocesses)?;

        Ok(PreprocessResponse {
            participant: self.our_index,
            commitments,
        })
    }

    /// Coordinator-side: collect a remote signer's nonce commitments.
    pub fn add_preprocess(&mut self, response: PreprocessResponse) -> Result<(), ProveError> {
        if self.state != SigningState::AwaitingPreprocesses {
            return Err(ProveError::UpstreamError(
                "wrong state for preprocess".into(),
            ));
        }

        let p = Participant::new(response.participant)
            .ok_or(ProveError::UpstreamError("invalid participant".into()))?;

        let preprocesses: Vec<FrostPreprocessResult> = response
            .commitments
            .into_iter()
            .map(|c| FrostPreprocessResult {
                nonce_commitments: c,
                addendum: Vec::new(),
            })
            .collect();

        self.coordinator.collect_preprocesses(p, preprocesses)?;

        if self.coordinator.all_preprocesses_collected() {
            self.state = SigningState::AwaitingSigning;
        }

        Ok(())
    }

    /// Get the aggregated nonce sums for distribution to remote signers.
    ///
    /// Each entry is a serialized byte blob for one input.
    pub fn nonce_sums_bytes(&mut self) -> Result<Vec<Vec<u8>>, ProveError> {
        if self.state != SigningState::AwaitingSigning {
            return Err(ProveError::UpstreamError(
                "nonce sums not ready (collect all preprocesses first)".into(),
            ));
        }

        self.coordinator.nonce_sums_bytes()
    }

    /// Coordinator-side: produce our own partial shares using the
    /// coordinator's already-aggregated nonce sums.
    pub fn sign_own(&mut self, group: &MultisigGroup) -> Result<ShareResponse, ProveError> {
        let keys = group.threshold_keys().deserialize()?;
        let view = keys
            .view(self.included.clone())
            .map_err(|e| ProveError::UpstreamError(format!("view error: {e}")))?;

        let mut shares = Vec::with_capacity(self.sessions.len());

        for idx in 0..self.sessions.len() {
            let nonce_sums = self.coordinator.nonce_sums_for_input(idx)?;
            let result = self.sessions[idx].sign_share(&view, &nonce_sums)?;
            shares.push(result.share);
        }

        let our_participant = Participant::new(self.our_index)
            .ok_or(ProveError::UpstreamError("invalid our_index".into()))?;

        let share_results: Vec<FrostSignShareResult> = shares
            .iter()
            .map(|s| FrostSignShareResult { share: *s })
            .collect();

        self.coordinator
            .collect_shares(our_participant, share_results)?;

        self.state = SigningState::AwaitingShares;

        Ok(ShareResponse {
            participant: self.our_index,
            shares,
        })
    }

    /// Coordinator-side: collect a remote signer's partial shares.
    pub fn add_shares(&mut self, response: ShareResponse) -> Result<(), ProveError> {
        let p = Participant::new(response.participant)
            .ok_or(ProveError::UpstreamError("invalid participant".into()))?;

        let share_results: Vec<FrostSignShareResult> = response
            .shares
            .into_iter()
            .map(|s| FrostSignShareResult { share: s })
            .collect();

        self.coordinator.collect_shares(p, share_results)?;
        Ok(())
    }

    /// Whether all shares have been collected.
    pub fn all_shares_collected(&self) -> bool {
        self.coordinator.all_shares_collected()
    }

    /// Aggregate all shares and produce SAL proofs for each input.
    ///
    /// Consumes the session. Returns `(Input, SpendAuthAndLinkability)` pairs
    /// suitable for passing to `prove_with_sal`.
    pub fn aggregate(
        self,
        group: &MultisigGroup,
    ) -> Result<Vec<(Input, SpendAuthAndLinkability)>, ProveError> {
        let keys = group.threshold_keys().deserialize()?;
        let group_key = keys.group_key();

        let mut coordinator = self.coordinator;
        coordinator.aggregate_all(self.sessions, group_key)
    }
}
