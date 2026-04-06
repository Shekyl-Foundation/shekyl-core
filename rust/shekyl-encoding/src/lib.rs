// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! General-purpose Bech32m blob encoding for Shekyl.
//!
//! This crate provides a thin, domain-agnostic wrapper around Bech32m
//! encoding/decoding for arbitrary binary data with arbitrary HRPs.
//! It has no knowledge of addresses, networks, or proof types.
//!
//! # Examples
//!
//! ```
//! use shekyl_encoding::{encode_blob, decode_blob};
//!
//! let data = b"hello world";
//! let encoded = encode_blob("example", data).unwrap();
//! let (hrp, decoded) = decode_blob(&encoded).unwrap();
//! assert_eq!(hrp, "example");
//! assert_eq!(decoded, data);
//! ```

use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};

/// HRP for spend proof encoding.
pub const HRP_SPEND_PROOF: &str = "shekylspendproof";

/// HRP for transaction proof encoding.
pub const HRP_TX_PROOF: &str = "shekyltxproof";

/// HRP for reserve proof encoding.
pub const HRP_RESERVE_PROOF: &str = "shekylreserveproof";

/// HRP for message signature encoding.
pub const HRP_MESSAGE_SIG: &str = "shekylsig";

/// HRP for multisig signature encoding.
pub const HRP_MULTISIG_SIG: &str = "shekylmultisig";

/// HRP for signer key encoding.
pub const HRP_SIGNER_KEY: &str = "shekylsigner";

/// Errors that can occur during Bech32m encoding or decoding.
#[derive(Debug, thiserror::Error)]
pub enum EncodingError {
    #[error("invalid HRP '{hrp}': {source}")]
    InvalidHrp {
        hrp: String,
        source: bech32::primitives::hrp::Error,
    },

    #[error("bech32m encode failed: {0}")]
    Encode(#[from] std::fmt::Error),

    #[error("bech32m decode failed: {0}")]
    Decode(bech32::DecodeError),

    #[error("empty input data")]
    EmptyData,
}

/// Encode arbitrary bytes as a Bech32m string with the given HRP.
///
/// # Errors
///
/// Returns [`EncodingError::InvalidHrp`] if `hrp` is not a valid Bech32m
/// human-readable part, or [`EncodingError::Encode`] on encoding failure.
pub fn encode_blob(hrp: &str, data: &[u8]) -> Result<String, EncodingError> {
    let parsed_hrp = Hrp::parse(hrp).map_err(|e| EncodingError::InvalidHrp {
        hrp: hrp.to_string(),
        source: e,
    })?;

    let encoded: String = data
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&parsed_hrp)
        .chars()
        .collect();

    Ok(encoded)
}

/// Decode a Bech32m string, returning the HRP and payload bytes.
///
/// # Errors
///
/// Returns [`EncodingError::Decode`] if the string is not valid Bech32m.
pub fn decode_blob(encoded: &str) -> Result<(String, Vec<u8>), EncodingError> {
    let (hrp, data) =
        bech32::decode(encoded).map_err(EncodingError::Decode)?;
    Ok((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let data = b"hello world";
        let encoded = encode_blob("test", data).unwrap();
        assert!(encoded.starts_with("test1"));
        let (hrp, decoded) = decode_blob(&encoded).unwrap();
        assert_eq!(hrp, "test");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let encoded = encode_blob("empty", &[]).unwrap();
        let (hrp, decoded) = decode_blob(&encoded).unwrap();
        assert_eq!(hrp, "empty");
        assert!(decoded.is_empty());
    }

    #[test]
    fn roundtrip_medium_payload() {
        let data: Vec<u8> = (0..=255).cycle().take(500).collect();
        let encoded = encode_blob("med", &data).unwrap();
        let (hrp, decoded) = decode_blob(&encoded).unwrap();
        assert_eq!(hrp, "med");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_proof_hrps() {
        let data = vec![0xab; 64];
        for hrp in [
            HRP_SPEND_PROOF,
            HRP_TX_PROOF,
            HRP_RESERVE_PROOF,
            HRP_MESSAGE_SIG,
            HRP_MULTISIG_SIG,
            HRP_SIGNER_KEY,
        ] {
            let encoded = encode_blob(hrp, &data).unwrap();
            assert!(encoded.starts_with(hrp));
            let (decoded_hrp, decoded_data) = decode_blob(&encoded).unwrap();
            assert_eq!(decoded_hrp, hrp);
            assert_eq!(decoded_data, data);
        }
    }

    #[test]
    fn invalid_hrp_rejected() {
        assert!(encode_blob("", &[0x01]).is_err());
    }

    #[test]
    fn corrupt_checksum_rejected() {
        let encoded = encode_blob("test", b"data").unwrap();
        let mut corrupted = encoded.clone();
        // Flip last char to corrupt checksum
        let last = corrupted.pop().unwrap();
        corrupted.push(if last == 'q' { 'p' } else { 'q' });
        assert!(decode_blob(&corrupted).is_err());
        // Original still decodes
        assert!(decode_blob(&encoded).is_ok());
    }

    #[test]
    fn garbage_string_rejected() {
        assert!(decode_blob("not_bech32m_at_all").is_err());
        assert!(decode_blob("").is_err());
    }

    #[test]
    fn case_insensitive_decode() {
        let data = b"\x01\x02\x03";
        let encoded = encode_blob("ci", data).unwrap();
        let upper = encoded.to_uppercase();
        let (hrp, decoded) = decode_blob(&upper).unwrap();
        assert_eq!(hrp.to_lowercase(), "ci");
        assert_eq!(decoded, data);
    }
}
