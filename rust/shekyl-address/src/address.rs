// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl address encoding and decoding.
//!
//! A Shekyl address consists of up to three Bech32m segments joined by `/`:
//!
//! 1. **Classical**: `<hrp>1<version><spend_key><view_key>` (~113 chars)
//! 2. **PQC-A**: `<pqc_a_hrp>1<first_half_ml_kem_key>` (~960 chars)
//! 3. **PQC-B**: `<pqc_b_hrp>1<second_half_ml_kem_key>` (~960 chars)
//!
//! Each segment stays within Bech32m's proven checksum detection range
//! (~1023 characters). The classical segment alone is sufficient for
//! human identification; the PQC segments are machine-handled.

use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};

use crate::network::{self, Network};

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

/// Errors specific to address encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("{0}")]
    Encoding(String),

    #[error("wrong HRP: expected '{expected}', got '{got}'")]
    WrongHrp { expected: String, got: String },

    #[error("unsupported address version 0x{version:02x} -- update your wallet")]
    UnsupportedVersion { version: u8 },

    #[error("expected {expected} bytes in {segment}, got {got}")]
    BadLength {
        segment: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("expected 1 or 3 segments, got {0}")]
    BadSegmentCount(usize),

    #[error("network mismatch: address is {addr_net}, expected {expected_net}")]
    NetworkMismatch {
        addr_net: Network,
        expected_net: Network,
    },

    #[error("unrecognized address HRP '{0}'")]
    UnknownHrp(String),
}

/// A decoded Shekyl address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShekylAddress {
    pub network: Network,
    pub version: u8,
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub ml_kem_encap_key: Vec<u8>,
}

fn bech32m_encode(hrp: &Hrp, data: &[u8]) -> String {
    data.iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(hrp)
        .chars()
        .collect()
}

fn bech32m_decode(encoded: &str) -> Result<(Hrp, Vec<u8>), AddressError> {
    let (hrp, data) = bech32::decode(encoded)
        .map_err(|e| AddressError::Encoding(format!("bech32m decode: {e}")))?;
    Ok((hrp, data))
}

fn parse_hrp(s: &str) -> Result<Hrp, AddressError> {
    Hrp::parse(s).map_err(|e| AddressError::Encoding(format!("invalid HRP '{s}': {e}")))
}

impl ShekylAddress {
    /// Create a new address for the given network.
    pub fn new(
        network: Network,
        spend_key: [u8; 32],
        view_key: [u8; 32],
        ml_kem_encap_key: Vec<u8>,
    ) -> Self {
        ShekylAddress {
            network,
            version: ADDRESS_VERSION_V1,
            spend_key,
            view_key,
            ml_kem_encap_key,
        }
    }

    /// Encode the full address as `<classical>/<pqc_a>/<pqc_b>`.
    pub fn encode(&self) -> Result<String, AddressError> {
        if self.ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(AddressError::BadLength {
                segment: "ML-KEM encap key",
                expected: PQC_PAYLOAD_LEN,
                got: self.ml_kem_encap_key.len(),
            });
        }

        let classical = self.encode_classical()?;

        let hrp_a = parse_hrp(network::pqc_a_hrp(self.network))?;
        let hrp_b = parse_hrp(network::pqc_b_hrp(self.network))?;

        let pqc_a = bech32m_encode(&hrp_a, &self.ml_kem_encap_key[..PQC_SPLIT]);
        let pqc_b = bech32m_encode(&hrp_b, &self.ml_kem_encap_key[PQC_SPLIT..]);

        Ok(format!("{classical}{SEGMENT_SEPARATOR}{pqc_a}{SEGMENT_SEPARATOR}{pqc_b}"))
    }

    /// Encode just the classical segment (short form for display).
    pub fn encode_classical_display(&self) -> Result<String, AddressError> {
        self.encode_classical()
    }

    fn encode_classical(&self) -> Result<String, AddressError> {
        let hrp = parse_hrp(network::classical_hrp(self.network))?;
        let mut payload = Vec::with_capacity(1 + CLASSICAL_PAYLOAD_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.spend_key);
        payload.extend_from_slice(&self.view_key);
        Ok(bech32m_encode(&hrp, &payload))
    }

    /// Decode a Shekyl address from its encoded form.
    ///
    /// Accepts `<classical>/<pqc_a>/<pqc_b>` (full) or `<classical>` (display-only).
    /// The network is inferred from the classical segment's HRP.
    pub fn decode(encoded: &str) -> Result<Self, AddressError> {
        let parts: Vec<&str> = encoded.split(SEGMENT_SEPARATOR).collect();

        match parts.len() {
            1 => Self::decode_classical_only(parts[0]),
            3 => Self::decode_full(parts[0], parts[1], parts[2]),
            n => Err(AddressError::BadSegmentCount(n)),
        }
    }

    /// Decode and validate that the address belongs to the expected network.
    pub fn decode_for_network(encoded: &str, expected: Network) -> Result<Self, AddressError> {
        let addr = Self::decode(encoded)?;
        if addr.network != expected {
            return Err(AddressError::NetworkMismatch {
                addr_net: addr.network,
                expected_net: expected,
            });
        }
        Ok(addr)
    }

    fn decode_full(classical: &str, pqc_a: &str, pqc_b: &str) -> Result<Self, AddressError> {
        let (c_hrp, c_data) = bech32m_decode(classical)?;
        let net = network::network_from_hrp(&c_hrp.to_string())
            .ok_or_else(|| AddressError::UnknownHrp(c_hrp.to_string()))?;

        let expected_a = parse_hrp(network::pqc_a_hrp(net))?;
        let expected_b = parse_hrp(network::pqc_b_hrp(net))?;

        let (a_hrp, a_data) = bech32m_decode(pqc_a)?;
        if a_hrp != expected_a {
            return Err(AddressError::WrongHrp {
                expected: network::pqc_a_hrp(net).to_string(),
                got: a_hrp.to_string(),
            });
        }

        let (b_hrp, b_data) = bech32m_decode(pqc_b)?;
        if b_hrp != expected_b {
            return Err(AddressError::WrongHrp {
                expected: network::pqc_b_hrp(net).to_string(),
                got: b_hrp.to_string(),
            });
        }

        let expected_classical_len = 1 + CLASSICAL_PAYLOAD_LEN;
        if c_data.len() != expected_classical_len {
            return Err(AddressError::BadLength {
                segment: "classical",
                expected: expected_classical_len,
                got: c_data.len(),
            });
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }

        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&c_data[1..33]);
        view_key.copy_from_slice(&c_data[33..65]);

        let mut ml_kem_encap_key = Vec::with_capacity(PQC_PAYLOAD_LEN);
        ml_kem_encap_key.extend_from_slice(&a_data);
        ml_kem_encap_key.extend_from_slice(&b_data);

        if ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(AddressError::BadLength {
                segment: "PQC total",
                expected: PQC_PAYLOAD_LEN,
                got: ml_kem_encap_key.len(),
            });
        }

        Ok(ShekylAddress {
            network: net,
            version,
            spend_key,
            view_key,
            ml_kem_encap_key,
        })
    }

    fn decode_classical_only(encoded: &str) -> Result<Self, AddressError> {
        let (c_hrp, c_data) = bech32m_decode(encoded)?;
        let net = network::network_from_hrp(&c_hrp.to_string())
            .ok_or_else(|| AddressError::UnknownHrp(c_hrp.to_string()))?;

        let expected_len = 1 + CLASSICAL_PAYLOAD_LEN;
        if c_data.len() != expected_len {
            return Err(AddressError::BadLength {
                segment: "classical",
                expected: expected_len,
                got: c_data.len(),
            });
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }

        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&c_data[1..33]);
        view_key.copy_from_slice(&c_data[33..65]);

        Ok(ShekylAddress {
            network: net,
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

    fn make_test_address(net: Network) -> ShekylAddress {
        ShekylAddress {
            network: net,
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            ml_kem_encap_key: vec![0xcc; PQC_PAYLOAD_LEN],
        }
    }

    #[test]
    fn encode_decode_roundtrip_mainnet() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].starts_with("shekyl1"));
        assert!(parts[1].starts_with("skpq1"));
        assert!(parts[2].starts_with("skpq21"));

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_testnet() {
        let addr = make_test_address(Network::Testnet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert!(parts[0].starts_with("tshekyl1"));
        assert!(parts[1].starts_with("tskpq1"));
        assert!(parts[2].starts_with("tskpq21"));

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert_eq!(decoded.network, Network::Testnet);
    }

    #[test]
    fn encode_decode_roundtrip_stagenet() {
        let addr = make_test_address(Network::Stagenet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert!(parts[0].starts_with("sshekyl1"));
        assert!(parts[1].starts_with("sskpq1"));
        assert!(parts[2].starts_with("sskpq21"));

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert_eq!(decoded.network, Network::Stagenet);
    }

    #[test]
    fn classical_display_shorter() {
        let addr = make_test_address(Network::Mainnet);
        let full = addr.encode().unwrap();
        let classical = addr.encode_classical_display().unwrap();
        assert!(classical.len() < full.len());
        assert!(classical.starts_with("shekyl1"));
    }

    #[test]
    fn classical_only_roundtrip() {
        let addr = make_test_address(Network::Mainnet);
        let classical = addr.encode_classical_display().unwrap();
        let decoded = ShekylAddress::decode(&classical).unwrap();
        assert_eq!(decoded.spend_key, addr.spend_key);
        assert_eq!(decoded.view_key, addr.view_key);
        assert_eq!(decoded.network, Network::Mainnet);
        assert!(!decoded.has_pqc_segment());
    }

    #[test]
    fn decode_for_network_enforces_match() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();

        assert!(ShekylAddress::decode_for_network(&encoded, Network::Mainnet).is_ok());
        let err = ShekylAddress::decode_for_network(&encoded, Network::Testnet).unwrap_err();
        assert!(matches!(err, AddressError::NetworkMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut addr = make_test_address(Network::Mainnet);
        addr.version = 0x02;
        if let Ok(enc) = addr.encode() {
            assert!(ShekylAddress::decode(&enc).is_err());
        }
    }

    #[test]
    fn rejects_invalid_pqc_length() {
        let addr = ShekylAddress {
            network: Network::Mainnet,
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            ml_kem_encap_key: vec![0xcc; 100],
        };
        assert!(addr.encode().is_err());
    }

    #[test]
    fn has_pqc_segment_check() {
        assert!(make_test_address(Network::Mainnet).has_pqc_segment());

        let partial = ShekylAddress {
            network: Network::Mainnet,
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            ml_kem_encap_key: Vec::new(),
        };
        assert!(!partial.has_pqc_segment());
    }

    #[test]
    fn each_segment_within_bech32m_limit() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        for (i, part) in encoded.split(SEGMENT_SEPARATOR).enumerate() {
            assert!(
                part.len() < 1023,
                "segment {i} exceeds Bech32m limit: {} chars",
                part.len()
            );
        }
    }

    #[test]
    fn decode_rejects_wrong_segment_count() {
        let result = ShekylAddress::decode("shekyl1abc/skpq1def");
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_empty_string() {
        assert!(ShekylAddress::decode("").is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(ShekylAddress::decode("not_a_valid_address").is_err());
        assert!(ShekylAddress::decode("shekyl1invalidchecksum").is_err());
    }

    #[test]
    fn cross_network_pqc_hrp_mismatch_rejected() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();

        // Construct a frankenstein with mainnet classical + testnet PQC
        let testnet_addr = make_test_address(Network::Testnet);
        let testnet_encoded = testnet_addr.encode().unwrap();
        let testnet_parts: Vec<&str> = testnet_encoded.split('/').collect();

        let mixed = format!("{}/{}/{}", parts[0], testnet_parts[1], testnet_parts[2]);
        assert!(ShekylAddress::decode(&mixed).is_err());
    }

    #[test]
    fn new_constructor_sets_v1() {
        let addr = ShekylAddress::new(
            Network::Mainnet,
            [0x11; 32],
            [0x22; 32],
            vec![0x33; PQC_PAYLOAD_LEN],
        );
        assert_eq!(addr.version, ADDRESS_VERSION_V1);
        assert_eq!(addr.network, Network::Mainnet);
    }

    #[test]
    fn different_keys_produce_different_addresses() {
        let addr1 = make_test_address(Network::Mainnet);
        let mut addr2 = make_test_address(Network::Mainnet);
        addr2.spend_key = [0xdd; 32];
        let enc1 = addr1.encode().unwrap();
        let enc2 = addr2.encode().unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn different_networks_produce_different_addresses() {
        let main = make_test_address(Network::Mainnet);
        let test = make_test_address(Network::Testnet);
        assert_ne!(main.encode().unwrap(), test.encode().unwrap());
    }
}
