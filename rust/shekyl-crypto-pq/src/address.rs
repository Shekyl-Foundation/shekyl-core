// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bech32m address encoding for Shekyl.
//!
//! Format: `<classical_bech32m>/<pqc_a_bech32m>/<pqc_b_bech32m>`
//!
//! The full address consists of three Bech32m segments joined by `/`:
//!
//! 1. **Classical**: `shekyl1<version><spend_key><view_key>` (~113 chars)
//! 2. **PQC-A**: `skpq1<first_half_ml_kem_key>` (~960 chars)
//! 3. **PQC-B**: `skpq21<second_half_ml_kem_key>` (~960 chars)
//!
//! Each segment stays within Bech32m's proven checksum detection range
//! (~1023 characters). The classical segment alone is sufficient for
//! human identification; the PQC segments are machine-handled.

use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};

use crate::CryptoError;

/// Human-readable part for the classical segment.
pub const HRP_CLASSICAL: &str = "shekyl";

/// Human-readable part for PQC segment A (first half).
pub const HRP_PQC_A: &str = "skpq";

/// Human-readable part for PQC segment B (second half).
pub const HRP_PQC_B: &str = "skpq2";

/// Current address version byte.
pub const ADDRESS_VERSION_V1: u8 = 0x01;

/// Ed25519 spend + view key total size.
pub const CLASSICAL_PAYLOAD_LEN: usize = 64;

/// ML-KEM-768 encapsulation key size.
pub const PQC_PAYLOAD_LEN: usize = 1184;

/// Split point for PQC payload (half of 1184).
const PQC_SPLIT: usize = 592;

/// Separator between segments.
pub const SEGMENT_SEPARATOR: char = '/';

/// A decoded Shekyl address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShekylAddress {
    pub version: u8,
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub ml_kem_encap_key: Vec<u8>,
}

fn bech32m_encode(hrp: &Hrp, data: &[u8]) -> Result<String, CryptoError> {
    let s: String = data
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(hrp)
        .chars()
        .collect();
    Ok(s)
}

fn bech32m_decode(encoded: &str) -> Result<(Hrp, Vec<u8>), CryptoError> {
    let (hrp, data) = bech32::decode(encoded)
        .map_err(|e| CryptoError::SerializationError(format!("bech32m decode: {e}")))?;
    Ok((hrp, data))
}

impl ShekylAddress {
    /// Encode the full address as `<classical>/<pqc_a>/<pqc_b>`.
    pub fn encode(&self) -> Result<String, CryptoError> {
        if self.ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(CryptoError::SerializationError(format!(
                "ML-KEM encap key must be {PQC_PAYLOAD_LEN} bytes, got {}",
                self.ml_kem_encap_key.len()
            )));
        }

        let classical = self.encode_classical()?;

        let hrp_a = Hrp::parse(HRP_PQC_A)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;
        let hrp_b = Hrp::parse(HRP_PQC_B)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;

        let pqc_a = bech32m_encode(&hrp_a, &self.ml_kem_encap_key[..PQC_SPLIT])?;
        let pqc_b = bech32m_encode(&hrp_b, &self.ml_kem_encap_key[PQC_SPLIT..])?;

        Ok(format!("{classical}{SEGMENT_SEPARATOR}{pqc_a}{SEGMENT_SEPARATOR}{pqc_b}"))
    }

    /// Encode just the classical segment (short form for display).
    pub fn encode_classical_display(&self) -> Result<String, CryptoError> {
        self.encode_classical()
    }

    fn encode_classical(&self) -> Result<String, CryptoError> {
        let hrp = Hrp::parse(HRP_CLASSICAL)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;
        let mut payload = Vec::with_capacity(1 + CLASSICAL_PAYLOAD_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.spend_key);
        payload.extend_from_slice(&self.view_key);
        bech32m_encode(&hrp, &payload)
    }

    /// Decode a Shekyl address from its encoded form.
    ///
    /// Accepts `<classical>/<pqc_a>/<pqc_b>` (full) or `<classical>` (display-only).
    pub fn decode(encoded: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = encoded.split(SEGMENT_SEPARATOR).collect();

        match parts.len() {
            1 => Self::decode_classical_only(parts[0]),
            3 => Self::decode_full(parts[0], parts[1], parts[2]),
            n => Err(CryptoError::SerializationError(format!(
                "expected 1 or 3 segments, got {n}"
            ))),
        }
    }

    fn decode_full(
        classical: &str,
        pqc_a: &str,
        pqc_b: &str,
    ) -> Result<Self, CryptoError> {
        let expected_c = Hrp::parse(HRP_CLASSICAL)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;
        let expected_a = Hrp::parse(HRP_PQC_A)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;
        let expected_b = Hrp::parse(HRP_PQC_B)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;

        let (c_hrp, c_data) = bech32m_decode(classical)?;
        if c_hrp != expected_c {
            return Err(CryptoError::SerializationError(format!(
                "wrong classical HRP: expected '{HRP_CLASSICAL}', got '{c_hrp}'"
            )));
        }

        let (a_hrp, a_data) = bech32m_decode(pqc_a)?;
        if a_hrp != expected_a {
            return Err(CryptoError::SerializationError(format!(
                "wrong PQC-A HRP: expected '{HRP_PQC_A}', got '{a_hrp}'"
            )));
        }

        let (b_hrp, b_data) = bech32m_decode(pqc_b)?;
        if b_hrp != expected_b {
            return Err(CryptoError::SerializationError(format!(
                "wrong PQC-B HRP: expected '{HRP_PQC_B}', got '{b_hrp}'"
            )));
        }

        if c_data.len() != 1 + CLASSICAL_PAYLOAD_LEN {
            return Err(CryptoError::SerializationError(format!(
                "classical: expected {} bytes, got {}",
                1 + CLASSICAL_PAYLOAD_LEN,
                c_data.len()
            )));
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(CryptoError::SerializationError(format!(
                "unsupported address version 0x{version:02x} -- update your wallet"
            )));
        }

        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&c_data[1..33]);
        view_key.copy_from_slice(&c_data[33..65]);

        let mut ml_kem_encap_key = Vec::with_capacity(PQC_PAYLOAD_LEN);
        ml_kem_encap_key.extend_from_slice(&a_data);
        ml_kem_encap_key.extend_from_slice(&b_data);

        if ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(CryptoError::SerializationError(format!(
                "PQC total: expected {PQC_PAYLOAD_LEN} bytes, got {}",
                ml_kem_encap_key.len()
            )));
        }

        Ok(ShekylAddress { version, spend_key, view_key, ml_kem_encap_key })
    }

    fn decode_classical_only(encoded: &str) -> Result<Self, CryptoError> {
        let expected = Hrp::parse(HRP_CLASSICAL)
            .map_err(|e| CryptoError::SerializationError(format!("HRP: {e}")))?;
        let (c_hrp, c_data) = bech32m_decode(encoded)?;
        if c_hrp != expected {
            return Err(CryptoError::SerializationError(format!(
                "wrong HRP: expected '{HRP_CLASSICAL}', got '{c_hrp}'"
            )));
        }
        if c_data.len() != 1 + CLASSICAL_PAYLOAD_LEN {
            return Err(CryptoError::SerializationError(format!(
                "classical: expected {} bytes, got {}",
                1 + CLASSICAL_PAYLOAD_LEN,
                c_data.len()
            )));
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(CryptoError::SerializationError(format!(
                "unsupported address version 0x{version:02x} -- update your wallet"
            )));
        }

        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&c_data[1..33]);
        view_key.copy_from_slice(&c_data[33..65]);

        Ok(ShekylAddress {
            version,
            spend_key,
            view_key,
            ml_kem_encap_key: Vec::new(),
        })
    }

    /// Whether this address has the full PQC segment (required for sending).
    pub fn has_pqc_segment(&self) -> bool {
        self.ml_kem_encap_key.len() == PQC_PAYLOAD_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_address() -> ShekylAddress {
        ShekylAddress {
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            ml_kem_encap_key: vec![0xcc; PQC_PAYLOAD_LEN],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let addr = make_test_address();
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert_eq!(parts.len(), 3);

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn classical_display_shorter() {
        let addr = make_test_address();
        let full = addr.encode().unwrap();
        let classical = addr.encode_classical_display().unwrap();
        assert!(classical.len() < full.len());
        assert!(classical.starts_with("shekyl1"));
    }

    #[test]
    fn classical_only_roundtrip() {
        let addr = make_test_address();
        let classical = addr.encode_classical_display().unwrap();
        let decoded = ShekylAddress::decode(&classical).unwrap();
        assert_eq!(decoded.spend_key, addr.spend_key);
        assert_eq!(decoded.view_key, addr.view_key);
        assert!(!decoded.has_pqc_segment());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut addr = make_test_address();
        addr.version = 0x02;
        if let Ok(enc) = addr.encode() {
            assert!(ShekylAddress::decode(&enc).is_err());
        }
    }

    #[test]
    fn rejects_invalid_pqc_length() {
        let addr = ShekylAddress {
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            ml_kem_encap_key: vec![0xcc; 100],
        };
        assert!(addr.encode().is_err());
    }

    #[test]
    fn has_pqc_segment_check() {
        assert!(make_test_address().has_pqc_segment());

        let partial = ShekylAddress {
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            ml_kem_encap_key: Vec::new(),
        };
        assert!(!partial.has_pqc_segment());
    }

    #[test]
    fn each_segment_within_bech32m_limit() {
        let addr = make_test_address();
        let encoded = addr.encode().unwrap();
        for (i, part) in encoded.split(SEGMENT_SEPARATOR).enumerate() {
            assert!(
                part.len() < 1023,
                "segment {i} exceeds Bech32m limit: {} chars",
                part.len()
            );
        }
    }
}
