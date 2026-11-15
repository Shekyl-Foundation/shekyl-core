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
//! # One string per blob
//!
//! A blob has exactly one Bech32m string: the lowercase one
//! [`encode_blob`] writes. [`decode_blob`] accepts that string and
//! nothing else. Bech32m as specified also admits an all-uppercase
//! spelling, and the `bech32` crate's own decoders admit the older Bech32
//! checksum and non-zero padding bits; each would give one blob several
//! strings, and so several things a user could compare, a hash could
//! cover, or a wallet could store. They are refused by name
//! ([`EncodingError::NotLowercase`]) or by re-encoding
//! ([`EncodingError::NotCanonical`]): a string that decodes but is not
//! what its contents encode to is not a Shekyl string, whatever the
//! library would make of it.
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

use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
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

    /// The string holds an uppercase letter. A Shekyl Bech32m string is
    /// written in lowercase, and that is its only form.
    #[error("not lowercase: a Shekyl bech32m string is written in lowercase only")]
    NotLowercase,

    /// Not a Bech32m string: malformed, or its checksum is not Bech32m's
    /// (the older Bech32 checksum included).
    #[error("bech32m decode failed: {0}")]
    Decode(#[from] CheckedHrpstringError),

    /// A valid Bech32m string that is not the one its contents encode to
    /// (non-zero padding bits, for one).
    #[error("not the canonical bech32m encoding of its contents")]
    NotCanonical,
}

/// The one Bech32m writer: lowercase, Bech32m checksum, zero padding.
fn encode(hrp: &Hrp, data: &[u8]) -> String {
    data.iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(hrp)
        .chars()
        .collect()
}

/// Encode arbitrary bytes as a Bech32m string with the given HRP.
///
/// # Errors
///
/// Returns [`EncodingError::InvalidHrp`] if `hrp` is not a valid Bech32m
/// human-readable part.
pub fn encode_blob(hrp: &str, data: &[u8]) -> Result<String, EncodingError> {
    let parsed_hrp = Hrp::parse(hrp).map_err(|e| EncodingError::InvalidHrp {
        hrp: hrp.to_string(),
        source: e,
    })?;
    Ok(encode(&parsed_hrp, data))
}

/// Decode a Bech32m string, returning the HRP and payload bytes.
///
/// Accepts exactly the string [`encode_blob`] writes for the HRP and
/// bytes it carries (see the crate docs).
///
/// # Errors
///
/// [`EncodingError::NotLowercase`] for any uppercase letter,
/// [`EncodingError::Decode`] if the string is not Bech32m, and
/// [`EncodingError::NotCanonical`] if it decodes to bytes that encode to
/// a different string.
pub fn decode_blob(encoded: &str) -> Result<(String, Vec<u8>), EncodingError> {
    if encoded.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EncodingError::NotLowercase);
    }
    let checked = CheckedHrpstring::new::<Bech32m>(encoded)?;
    let hrp = checked.hrp();
    let data: Vec<u8> = checked.byte_iter().collect();
    if encode(&hrp, &data) != encoded {
        return Err(EncodingError::NotCanonical);
    }
    Ok((hrp.as_str().to_owned(), data))
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

    /// The blob the refusal tests below spell non-canonically. Three
    /// bytes are 24 bits in five 5-bit characters, so the last character
    /// carries one padding bit.
    const CASE_HRP: &str = "ci";
    const CASE_DATA: &[u8] = b"\x01\x02\x03";

    #[test]
    fn uppercase_is_refused() {
        let encoded = encode_blob(CASE_HRP, CASE_DATA).unwrap();
        assert!(matches!(
            decode_blob(&encoded.to_uppercase()),
            Err(EncodingError::NotLowercase)
        ));
    }

    #[test]
    fn mixed_case_is_refused() {
        let encoded = encode_blob(CASE_HRP, CASE_DATA).unwrap();
        let mut mixed = encoded.into_bytes();
        let last = mixed.len() - 1;
        mixed[last].make_ascii_uppercase();
        let mixed = String::from_utf8(mixed).unwrap();
        assert!(matches!(
            decode_blob(&mixed),
            Err(EncodingError::NotLowercase)
        ));
    }

    #[test]
    fn the_bech32_checksum_is_refused() {
        let hrp = Hrp::parse(CASE_HRP).unwrap();
        let as_bech32 = bech32::encode::<bech32::Bech32>(hrp, CASE_DATA).unwrap();
        assert!(matches!(
            decode_blob(&as_bech32),
            Err(EncodingError::Decode(CheckedHrpstringError::Checksum(_)))
        ));
    }

    /// Setting [`CASE_DATA`]'s one padding bit changes the string and not
    /// the bytes the library reads back.
    #[test]
    fn non_zero_padding_is_refused() {
        let hrp = Hrp::parse(CASE_HRP).unwrap();
        let mut fes: Vec<bech32::Fe32> = CASE_DATA.iter().copied().bytes_to_fes().collect();
        let last = fes.pop().unwrap();
        fes.push(bech32::Fe32::try_from(last.to_u8() | 1).unwrap());
        let padded: String = fes
            .into_iter()
            .with_checksum::<Bech32m>(&hrp)
            .chars()
            .collect();
        let checked = CheckedHrpstring::new::<Bech32m>(&padded).unwrap();
        assert_eq!(
            checked.byte_iter().collect::<Vec<u8>>(),
            CASE_DATA,
            "the library reads the padded string as the same bytes"
        );
        assert!(matches!(
            decode_blob(&padded),
            Err(EncodingError::NotCanonical)
        ));
    }
}
