// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! FROST Distributed Key Generation (DKG) for Ed25519T threshold signing.
//!
//! Wraps `dkg-pedpop` (PedPoP protocol) and `modular-frost` `ThresholdKeys<Ed25519T>`
//! to provide a complete DKG round state machine plus serialization helpers.
//!
//! ## Protocol Rounds
//!
//! 1. **Round 1** (`generate_coefficients`): Each participant produces polynomial
//!    commitments and an encryption key. The resulting `DkgRound1Message` is
//!    broadcast to all other participants.
//!
//! 2. **Round 2** (`generate_secret_shares`): Each participant processes the
//!    collected round-1 messages and produces per-participant encrypted secret
//!    shares. Each `DkgRound2Message` is sent to its intended recipient over an
//!    authenticated channel.
//!
//! 3. **Finalize** (`complete`): Each participant processes the secret shares they
//!    received and outputs `ThresholdKeys<Ed25519T>`.

use std::collections::HashMap;

use rand_core::OsRng;
use zeroize::Zeroizing;

use modular_frost::{Participant, ThresholdKeys, ThresholdParams};
use dkg_pedpop::{
    BlameMachine, Commitments, EncryptedMessage, EncryptionKeyMessage, KeyGenMachine,
    KeyMachine, PedPoPError, SecretShare, SecretShareMachine,
};

use shekyl_fcmp_plus_plus::sal::multisig::Ed25519T;

use crate::proof::ProveError;

// ---------------------------------------------------------------------------
// Re-export types callers need without importing dkg-pedpop directly
// ---------------------------------------------------------------------------

/// Round 1 broadcast message: polynomial commitments + encryption key.
pub type DkgRound1Message = EncryptionKeyMessage<Ed25519T, Commitments<Ed25519T>>;

/// Round 2 per-recipient message: encrypted secret share.
pub type DkgRound2Message = EncryptedMessage<Ed25519T, SecretShare<<Ed25519T as ciphersuite::Ciphersuite>::F>>;

// ---------------------------------------------------------------------------
// DKG Session (type-state enum)
// ---------------------------------------------------------------------------

/// DKG session state machine.
///
/// Tracks which protocol round the session is in and holds the underlying
/// `dkg-pedpop` machine for the current round. Each `advance_*` method
/// consumes the current state and produces the next.
pub enum DkgSession {
    /// Initial state: ready to generate coefficients.
    Ready(KeyGenMachine<Ed25519T>),
    /// Round 1 complete: waiting for all participants' commitments.
    AwaitingCommitments(SecretShareMachine<Ed25519T>),
    /// Round 2 complete: waiting for secret shares addressed to us.
    AwaitingShares(KeyMachine<Ed25519T>),
    /// Shares processed: awaiting confirmation from all participants before
    /// extracting keys. Call `confirm_complete()` after all parties report success.
    AwaitingConfirmation(BlameMachine<Ed25519T>),
    /// Terminal state after finalization.
    Complete,
}

impl DkgSession {
    /// Create a new DKG session for an M-of-N threshold group.
    ///
    /// `context` is a 32-byte value unique to this multisig group (e.g. a hash
    /// of all participants' public identifiers). It prevents replaying round
    /// messages across different DKG instances.
    pub fn new(params: &DkgParams, context: [u8; 32]) -> Result<Self, ProveError> {
        let (frost_params, _participant) = params.to_frost_params()?;
        let machine = KeyGenMachine::new(frost_params, context);
        Ok(DkgSession::Ready(machine))
    }

    /// **Round 1**: Generate polynomial commitments.
    ///
    /// Returns `DkgRound1Message` to broadcast to all other participants.
    /// Transitions the session to `AwaitingCommitments`.
    pub fn generate_coefficients(self) -> Result<(Self, DkgRound1Message), ProveError> {
        match self {
            DkgSession::Ready(machine) => {
                let (next, msg) = machine.generate_coefficients(&mut OsRng);
                Ok((DkgSession::AwaitingCommitments(next), msg))
            }
            _ => Err(ProveError::UpstreamError(
                "DKG session not in Ready state".into(),
            )),
        }
    }

    /// **Round 2**: Process all participants' commitments and produce secret shares.
    ///
    /// `commitments` maps each *other* participant to their round-1 message.
    /// Returns a map of encrypted secret shares, one per participant (send each
    /// to its intended recipient). Transitions to `AwaitingShares`.
    pub fn generate_secret_shares(
        self,
        commitments: HashMap<Participant, DkgRound1Message>,
    ) -> Result<(Self, HashMap<Participant, DkgRound2Message>), ProveError> {
        match self {
            DkgSession::AwaitingCommitments(machine) => {
                let (next, shares) = machine
                    .generate_secret_shares(&mut OsRng, commitments)
                    .map_err(|e| map_pedpop_error(e))?;
                Ok((DkgSession::AwaitingShares(next), shares))
            }
            _ => Err(ProveError::UpstreamError(
                "DKG session not in AwaitingCommitments state".into(),
            )),
        }
    }

    /// **Round 3**: Process received secret shares, yielding a blame-capable machine.
    ///
    /// `shares` maps each *other* participant to the encrypted secret share
    /// they sent to us. On success, transitions to `AwaitingConfirmation`.
    /// Call `confirm_complete()` after all parties confirm success.
    pub fn calculate_share(
        self,
        shares: HashMap<Participant, DkgRound2Message>,
    ) -> Result<Self, ProveError> {
        match self {
            DkgSession::AwaitingShares(machine) => {
                let blame_machine = machine
                    .calculate_share(&mut OsRng, shares)
                    .map_err(|e| map_pedpop_error(e))?;
                Ok(DkgSession::AwaitingConfirmation(blame_machine))
            }
            _ => Err(ProveError::UpstreamError(
                "DKG session not in AwaitingShares state".into(),
            )),
        }
    }

    /// **Finalize**: After all participants confirm successful completion,
    /// extract the `ThresholdKeys`.
    ///
    /// This must only be called after external consensus that every participant
    /// reached the `AwaitingConfirmation` state without errors.
    pub fn confirm_complete(self) -> Result<ThresholdKeys<Ed25519T>, ProveError> {
        match self {
            DkgSession::AwaitingConfirmation(blame_machine) => {
                Ok(blame_machine.complete())
            }
            _ => Err(ProveError::UpstreamError(
                "DKG session not in AwaitingConfirmation state".into(),
            )),
        }
    }
}

fn map_pedpop_error(e: PedPoPError<Ed25519T>) -> ProveError {
    ProveError::UpstreamError(format!("DKG PedPoP error: {e:?}"))
}

// ---------------------------------------------------------------------------
// Serialized threshold keys (for wallet storage)
// ---------------------------------------------------------------------------

/// Serialized threshold keys for storage (wallet file, encrypted).
#[derive(Clone)]
pub struct SerializedThresholdKeys {
    data: Zeroizing<Vec<u8>>,
}

impl SerializedThresholdKeys {
    pub fn from_keys(keys: &ThresholdKeys<Ed25519T>) -> Self {
        Self {
            data: keys.serialize(),
        }
    }

    pub fn deserialize(&self) -> Result<ThresholdKeys<Ed25519T>, ProveError> {
        let mut cursor = std::io::Cursor::new(self.data.as_slice());
        ThresholdKeys::read(&mut cursor)
            .map_err(|e| ProveError::UpstreamError(format!("ThresholdKeys deserialization: {e}")))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: Zeroizing::new(data.to_vec()),
        }
    }
}

// ---------------------------------------------------------------------------
// DKG parameters
// ---------------------------------------------------------------------------

/// DKG parameters for creating a FROST multisig group.
pub struct DkgParams {
    pub threshold: u16,
    pub total: u16,
    pub our_index: u16,
}

impl DkgParams {
    pub fn to_frost_params(&self) -> Result<(ThresholdParams, Participant), ProveError> {
        let participant = Participant::new(self.our_index).ok_or_else(|| {
            ProveError::UpstreamError(format!(
                "Invalid participant index: {} (must be 1..={})",
                self.our_index, self.total
            ))
        })?;
        let params = ThresholdParams::new(self.threshold, self.total, participant).map_err(
            |_| {
                ProveError::UpstreamError(format!(
                    "Invalid threshold params: {}-of-{}",
                    self.threshold, self.total
                ))
            },
        )?;
        Ok((params, participant))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the group public key (compressed Ed25519T point, 32 bytes) from threshold keys.
pub fn group_key_bytes(keys: &ThresholdKeys<Ed25519T>) -> [u8; 32] {
    use ciphersuite::group::GroupEncoding;
    let gk = keys.group_key();
    let repr = gk.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Validate that threshold keys are consistent with expected parameters.
pub fn validate_keys(
    keys: &ThresholdKeys<Ed25519T>,
    expected_m: u16,
    expected_n: u16,
) -> Result<(), ProveError> {
    let params = keys.params();
    if params.t() != expected_m {
        return Err(ProveError::UpstreamError(format!(
            "Threshold mismatch: keys have t={}, expected {}",
            params.t(),
            expected_m
        )));
    }
    if params.n() != expected_n {
        return Err(ProveError::UpstreamError(format!(
            "Total mismatch: keys have n={}, expected {}",
            params.n(),
            expected_n
        )));
    }
    Ok(())
}

/// Generate test threshold keys for N participants with threshold M.
/// Only available in test builds; uses modular-frost's built-in key_gen.
#[cfg(test)]
pub fn generate_test_keys(
    _m: u16,
    _n: u16,
) -> HashMap<Participant, ThresholdKeys<Ed25519T>> {
    use modular_frost::tests::key_gen;
    key_gen::<_, Ed25519T>(&mut OsRng)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_serialization_roundtrip() {
        let keys_map = generate_test_keys(2, 3);
        for (_participant, keys) in &keys_map {
            let serialized = SerializedThresholdKeys::from_keys(keys);
            let deserialized = serialized.deserialize().unwrap();

            use ciphersuite::group::GroupEncoding;
            assert_eq!(
                keys.group_key().to_bytes().as_ref(),
                deserialized.group_key().to_bytes().as_ref(),
            );
            assert_eq!(keys.params().t(), deserialized.params().t());
            assert_eq!(keys.params().n(), deserialized.params().n());
        }
    }

    #[test]
    fn test_group_key_extraction() {
        let keys_map = generate_test_keys(2, 3);
        let mut group_keys: Vec<[u8; 32]> = Vec::new();
        for (_, keys) in &keys_map {
            group_keys.push(group_key_bytes(keys));
        }
        assert!(
            group_keys.windows(2).all(|w| w[0] == w[1]),
            "All participants should have the same group key"
        );
    }

    #[test]
    fn test_validate_keys() {
        let keys_map = generate_test_keys(4, 5);
        let (_, keys) = keys_map.iter().next().unwrap();
        assert!(validate_keys(keys, 4, 5).is_ok());
        assert!(validate_keys(keys, 3, 5).is_err());
        assert!(validate_keys(keys, 4, 3).is_err());
    }

    #[test]
    fn test_serialized_from_bytes_roundtrip() {
        let keys_map = generate_test_keys(2, 3);
        let (_, keys) = keys_map.iter().next().unwrap();
        let serialized = SerializedThresholdKeys::from_keys(keys);
        let bytes = serialized.as_bytes().to_vec();
        let restored = SerializedThresholdKeys::from_bytes(&bytes);
        let deserialized = restored.deserialize().unwrap();

        use ciphersuite::group::GroupEncoding;
        assert_eq!(
            keys.group_key().to_bytes().as_ref(),
            deserialized.group_key().to_bytes().as_ref(),
        );
    }

    #[test]
    fn test_dkg_full_roundtrip() {
        let threshold = 2u16;
        let total = 3u16;
        let context = [0xABu8; 32];

        let mut sessions = HashMap::new();
        let mut round1_msgs: HashMap<Participant, DkgRound1Message> = HashMap::new();

        for i in 1..=total {
            let params = DkgParams { threshold, total, our_index: i };
            let session = DkgSession::new(&params, context).unwrap();
            let (session, msg) = session.generate_coefficients().unwrap();
            let p = Participant::new(i).unwrap();
            sessions.insert(p, session);
            round1_msgs.insert(p, msg);
        }

        let mut round2_outgoing: HashMap<Participant, HashMap<Participant, DkgRound2Message>> = HashMap::new();

        for i in 1..=total {
            let p = Participant::new(i).unwrap();
            let session = sessions.remove(&p).unwrap();
            let others: HashMap<Participant, DkgRound1Message> = round1_msgs
                .iter()
                .filter(|(k, _)| **k != p)
                .map(|(k, v)| (*k, v.clone()))
                .collect();

            let (session, shares) = session.generate_secret_shares(others).unwrap();
            sessions.insert(p, session);
            round2_outgoing.insert(p, shares);
        }

        for i in 1..=total {
            let p = Participant::new(i).unwrap();
            let session = sessions.remove(&p).unwrap();

            let my_shares: HashMap<Participant, DkgRound2Message> = round2_outgoing
                .iter()
                .filter_map(|(sender, shares_map)| {
                    shares_map.get(&p).map(|s| (*sender, s.clone()))
                })
                .collect();

            let session = session.calculate_share(my_shares).unwrap();
            sessions.insert(p, session);
        }

        let mut all_keys = Vec::new();
        for i in 1..=total {
            let p = Participant::new(i).unwrap();
            let session = sessions.remove(&p).unwrap();
            let keys = session.confirm_complete().unwrap();
            all_keys.push(keys);
        }

        let group_keys: Vec<[u8; 32]> = all_keys.iter().map(|k| group_key_bytes(k)).collect();
        assert!(
            group_keys.windows(2).all(|w| w[0] == w[1]),
            "All participants must agree on the group key"
        );

        for keys in &all_keys {
            assert_eq!(keys.params().t(), threshold);
            assert_eq!(keys.params().n(), total);
        }
    }

    #[test]
    fn test_dkg_wrong_state_errors() {
        let params = DkgParams { threshold: 2, total: 3, our_index: 1 };
        let session = DkgSession::new(&params, [0; 32]).unwrap();

        let result = session.generate_secret_shares(HashMap::new());
        assert!(result.is_err(), "Should fail: not in AwaitingCommitments state");
    }
}
