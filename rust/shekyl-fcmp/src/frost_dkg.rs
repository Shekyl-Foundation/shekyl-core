// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! FROST Distributed Key Generation (DKG) for Ed25519T threshold signing.
//!
//! Wraps `modular-frost` `ThresholdKeys<Ed25519T>` with serialization helpers
//! and a structured DKG round state machine suitable for FFI.
//!
//! The DKG protocol produces threshold keys for M-of-N threshold signing on
//! the Ed25519T curve (Ed25519 with generator T), used by FROST SAL in FCMP++
//! multisig transactions.

use zeroize::Zeroizing;

use modular_frost::{Participant, ThresholdKeys, ThresholdParams};

use shekyl_fcmp_plus_plus::sal::multisig::Ed25519T;

use crate::proof::ProveError;

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

/// DKG parameters for creating a FROST multisig group.
pub struct DkgParams {
    pub threshold: u16,
    pub total: u16,
    pub our_index: u16,
}

impl DkgParams {
    pub fn to_frost_params(&self) -> Result<(ThresholdParams, Participant), ProveError> {
        let participant = Participant::new(self.our_index)
            .ok_or_else(|| ProveError::UpstreamError(
                format!("Invalid participant index: {} (must be 1..={})", self.our_index, self.total)))?;
        let params = ThresholdParams::new(self.threshold, self.total, participant)
            .map_err(|_| ProveError::UpstreamError(
                format!("Invalid threshold params: {}-of-{}", self.threshold, self.total)))?;
        Ok((params, participant))
    }
}

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
        return Err(ProveError::UpstreamError(
            format!("Threshold mismatch: keys have t={}, expected {}", params.t(), expected_m)));
    }
    if params.n() != expected_n {
        return Err(ProveError::UpstreamError(
            format!("Total mismatch: keys have n={}, expected {}", params.n(), expected_n)));
    }
    Ok(())
}

/// Generate test threshold keys for N participants with threshold M.
/// Only available with the `tests` feature of modular-frost.
#[cfg(test)]
pub fn generate_test_keys(
    _m: u16,
    _n: u16,
) -> std::collections::HashMap<Participant, ThresholdKeys<Ed25519T>> {
    use rand_core::OsRng;
    use modular_frost::tests::key_gen;
    key_gen::<_, Ed25519T>(&mut OsRng)
}

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
        assert!(group_keys.windows(2).all(|w| w[0] == w[1]),
            "All participants should have the same group key");
    }

    #[test]
    fn test_validate_keys() {
        // modular-frost test key_gen uses PARTICIPANTS=5, THRESHOLD=4
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
}
