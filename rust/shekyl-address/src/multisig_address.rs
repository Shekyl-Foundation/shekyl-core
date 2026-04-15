// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Multisig address encoding, fingerprint, and provenance (PQC_MULTISIG.md SS6).
//!
//! Multisig addresses use the `shekyl1m` / `shekyltest1m` / `sshekyl1m` HRP
//! family. Due to their size (10 + N * 3200 bytes), they are file-based:
//! the canonical payload is written to a file and transferred via an
//! authenticated channel.
//!
//! The fingerprint is `cn_fast_hash(canonical(MultisigAddressPayload))`.

use crate::network::Network;

/// X25519 (32) + ML-KEM-768 (1184).
pub const HYBRID_KEM_PUBKEY_LEN: usize = 1216;

/// Ed25519 (32) + ML-DSA-65 (1952).
pub const HYBRID_SIGN_PUBKEY_LEN: usize = 1984;

/// Per-participant total: KEM + sign.
pub const PER_PARTICIPANT_LEN: usize = HYBRID_KEM_PUBKEY_LEN + HYBRID_SIGN_PUBKEY_LEN;

/// Header: version + group_version + spend_auth_version + network + n_total + m_required.
const HEADER_LEN: usize = 6;

/// Current multisig address payload version.
pub const MULTISIG_ADDRESS_VERSION: u8 = 0x01;

/// Current group protocol version.
pub const GROUP_VERSION: u8 = 0x01;

/// Current spend-auth version (Ed25519).
pub const SPEND_AUTH_VERSION: u8 = 0x01;

/// Errors specific to multisig address operations.
#[derive(Debug, thiserror::Error)]
pub enum MultisigAddressError {
    #[error("participant count {n} out of range 1..=7")]
    InvalidParticipantCount { n: u8 },

    #[error("threshold {m} out of range 1..={n}")]
    InvalidThreshold { m: u8, n: u8 },

    #[error("expected {expected} KEM pubkeys, got {got}")]
    KemPubkeyCount { expected: u8, got: usize },

    #[error("expected {expected} sign pubkeys, got {got}")]
    SignPubkeyCount { expected: u8, got: usize },

    #[error("KEM pubkey {index} has wrong length: expected {HYBRID_KEM_PUBKEY_LEN}, got {got}")]
    KemPubkeyLength { index: usize, got: usize },

    #[error("sign pubkey {index} has wrong length: expected {HYBRID_SIGN_PUBKEY_LEN}, got {got}")]
    SignPubkeyLength { index: usize, got: usize },

    #[error("payload too short: need at least {HEADER_LEN} bytes, got {got}")]
    PayloadTooShort { got: usize },

    #[error("unsupported address version 0x{version:02x}")]
    UnsupportedVersion { version: u8 },

    #[error("payload length mismatch: header implies {expected} bytes, got {got}")]
    PayloadLengthMismatch { expected: usize, got: usize },

    #[error("unknown network byte 0x{byte:02x}")]
    UnknownNetwork { byte: u8 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Canonical multisig address payload (PQC_MULTISIG.md SS6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigAddressPayload {
    pub version: u8,
    pub group_version: u8,
    pub spend_auth_version: u8,
    pub network: Network,
    pub n_total: u8,
    pub m_required: u8,
    pub hybrid_kem_pubkeys: Vec<Vec<u8>>,
    pub hybrid_sign_pubkeys: Vec<Vec<u8>>,
}

impl MultisigAddressPayload {
    /// Create a new payload, validating all invariants.
    pub fn new(
        network: Network,
        n_total: u8,
        m_required: u8,
        hybrid_kem_pubkeys: Vec<Vec<u8>>,
        hybrid_sign_pubkeys: Vec<Vec<u8>>,
    ) -> Result<Self, MultisigAddressError> {
        if n_total == 0 || n_total > 7 {
            return Err(MultisigAddressError::InvalidParticipantCount { n: n_total });
        }
        if m_required == 0 || m_required > n_total {
            return Err(MultisigAddressError::InvalidThreshold {
                m: m_required,
                n: n_total,
            });
        }
        if hybrid_kem_pubkeys.len() != n_total as usize {
            return Err(MultisigAddressError::KemPubkeyCount {
                expected: n_total,
                got: hybrid_kem_pubkeys.len(),
            });
        }
        if hybrid_sign_pubkeys.len() != n_total as usize {
            return Err(MultisigAddressError::SignPubkeyCount {
                expected: n_total,
                got: hybrid_sign_pubkeys.len(),
            });
        }
        for (i, pk) in hybrid_kem_pubkeys.iter().enumerate() {
            if pk.len() != HYBRID_KEM_PUBKEY_LEN {
                return Err(MultisigAddressError::KemPubkeyLength {
                    index: i,
                    got: pk.len(),
                });
            }
        }
        for (i, pk) in hybrid_sign_pubkeys.iter().enumerate() {
            if pk.len() != HYBRID_SIGN_PUBKEY_LEN {
                return Err(MultisigAddressError::SignPubkeyLength {
                    index: i,
                    got: pk.len(),
                });
            }
        }

        Ok(MultisigAddressPayload {
            version: MULTISIG_ADDRESS_VERSION,
            group_version: GROUP_VERSION,
            spend_auth_version: SPEND_AUTH_VERSION,
            network,
            n_total,
            m_required,
            hybrid_kem_pubkeys,
            hybrid_sign_pubkeys,
        })
    }

    /// Expected canonical byte length for this payload.
    pub fn canonical_len(&self) -> usize {
        HEADER_LEN + (self.n_total as usize) * PER_PARTICIPANT_LEN
    }

    /// Serialize to canonical bytes.
    ///
    /// Layout: `version(1) || group_version(1) || spend_auth_version(1) ||
    ///          network(1) || n_total(1) || m_required(1) ||
    ///          kem_pk[0] || ... || kem_pk[N-1] ||
    ///          sign_pk[0] || ... || sign_pk[N-1]`
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let len = self.canonical_len();
        let mut buf = Vec::with_capacity(len);
        buf.push(self.version);
        buf.push(self.group_version);
        buf.push(self.spend_auth_version);
        buf.push(self.network.as_u8());
        buf.push(self.n_total);
        buf.push(self.m_required);
        for pk in &self.hybrid_kem_pubkeys {
            buf.extend_from_slice(pk);
        }
        for pk in &self.hybrid_sign_pubkeys {
            buf.extend_from_slice(pk);
        }
        debug_assert_eq!(buf.len(), len);
        buf
    }

    /// Deserialize from canonical bytes.
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self, MultisigAddressError> {
        if data.len() < HEADER_LEN {
            return Err(MultisigAddressError::PayloadTooShort { got: data.len() });
        }

        let version = data[0];
        if version != MULTISIG_ADDRESS_VERSION {
            return Err(MultisigAddressError::UnsupportedVersion { version });
        }

        let group_version = data[1];
        let spend_auth_version = data[2];
        let network_byte = data[3];
        let n_total = data[4];
        let m_required = data[5];

        let network = Network::from_u8(network_byte)
            .ok_or(MultisigAddressError::UnknownNetwork { byte: network_byte })?;

        if n_total == 0 || n_total > 7 {
            return Err(MultisigAddressError::InvalidParticipantCount { n: n_total });
        }
        if m_required == 0 || m_required > n_total {
            return Err(MultisigAddressError::InvalidThreshold {
                m: m_required,
                n: n_total,
            });
        }

        let expected_len = HEADER_LEN + (n_total as usize) * PER_PARTICIPANT_LEN;
        if data.len() != expected_len {
            return Err(MultisigAddressError::PayloadLengthMismatch {
                expected: expected_len,
                got: data.len(),
            });
        }

        let mut offset = HEADER_LEN;
        let mut hybrid_kem_pubkeys = Vec::with_capacity(n_total as usize);
        for _ in 0..n_total {
            hybrid_kem_pubkeys.push(data[offset..offset + HYBRID_KEM_PUBKEY_LEN].to_vec());
            offset += HYBRID_KEM_PUBKEY_LEN;
        }

        let mut hybrid_sign_pubkeys = Vec::with_capacity(n_total as usize);
        for _ in 0..n_total {
            hybrid_sign_pubkeys.push(data[offset..offset + HYBRID_SIGN_PUBKEY_LEN].to_vec());
            offset += HYBRID_SIGN_PUBKEY_LEN;
        }
        debug_assert_eq!(offset, data.len());

        Ok(MultisigAddressPayload {
            version,
            group_version,
            spend_auth_version,
            network,
            n_total,
            m_required,
            hybrid_kem_pubkeys,
            hybrid_sign_pubkeys,
        })
    }

    /// Write the canonical payload to a file.
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<(), MultisigAddressError> {
        std::fs::write(path, self.to_canonical_bytes())?;
        Ok(())
    }

    /// Read and parse a canonical payload from a file.
    pub fn read_from_file(path: &std::path::Path) -> Result<Self, MultisigAddressError> {
        let data = std::fs::read(path)?;
        Self::from_canonical_bytes(&data)
    }
}

/// Compute the 32-byte address fingerprint: `cn_fast_hash(canonical payload)`.
///
/// This is the primary human-verifiable identifier for a multisig group
/// address (PQC_MULTISIG.md SS6.3).
pub fn address_fingerprint(payload: &MultisigAddressPayload) -> [u8; 32] {
    shekyl_crypto_hash::cn_fast_hash(&payload.to_canonical_bytes())
}

/// Format a fingerprint as grouped hex (4-char blocks separated by spaces).
pub fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    let hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a fingerprint as the structured metadata badge: `(m)-of-(n), spend_auth v(X), group v(Y)`.
pub fn fingerprint_badge(payload: &MultisigAddressPayload) -> String {
    format!(
        "{}-of-{}, spend_auth v{}, group v{}",
        payload.m_required, payload.n_total, payload.spend_auth_version, payload.group_version,
    )
}

/// Address provenance record persisted in the wallet (PQC_MULTISIG.md SS6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddressProvenance {
    pub address_fingerprint: [u8; 32],
    pub first_imported_at: u64,
    pub imported_from_source: String,
    pub user_assigned_label: String,
    pub last_used_at: u64,
    pub prior_fingerprints: Vec<[u8; 32]>,
}

impl AddressProvenance {
    /// Whether the fingerprint has changed since the initial import.
    pub fn fingerprint_changed(&self) -> bool {
        !self.prior_fingerprints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_payload(n: u8, m: u8) -> MultisigAddressPayload {
        MultisigAddressPayload::new(
            Network::Mainnet,
            n,
            m,
            (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
            (0..n)
                .map(|i| vec![0x80 + i; HYBRID_SIGN_PUBKEY_LEN])
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_roundtrip_2_of_3() {
        let payload = make_test_payload(3, 2);
        let bytes = payload.to_canonical_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + 3 * PER_PARTICIPANT_LEN);
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn canonical_roundtrip_1_of_1() {
        let payload = make_test_payload(1, 1);
        let bytes = payload.to_canonical_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + PER_PARTICIPANT_LEN);
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn canonical_roundtrip_7_of_7() {
        let payload = make_test_payload(7, 7);
        let bytes = payload.to_canonical_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + 7 * PER_PARTICIPANT_LEN);
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn rejects_n_zero() {
        assert!(MultisigAddressPayload::new(Network::Mainnet, 0, 0, vec![], vec![]).is_err());
    }

    #[test]
    fn rejects_n_over_7() {
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            8,
            3,
            (0..8).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
            (0..8).map(|i| vec![i; HYBRID_SIGN_PUBKEY_LEN]).collect(),
        )
        .is_err());
    }

    #[test]
    fn rejects_m_exceeds_n() {
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            3,
            vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
            vec![vec![0; HYBRID_SIGN_PUBKEY_LEN]; 2],
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_kem_pubkey_length() {
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            vec![vec![0; 100], vec![0; HYBRID_KEM_PUBKEY_LEN]],
            vec![vec![0; HYBRID_SIGN_PUBKEY_LEN]; 2],
        )
        .is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = make_test_payload(2, 2);
        let bytes = payload.to_canonical_bytes();
        assert!(MultisigAddressPayload::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = make_test_payload(2, 2).to_canonical_bytes();
        bytes[0] = 0xFF;
        assert!(MultisigAddressPayload::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn fingerprint_deterministic() {
        let p = make_test_payload(3, 2);
        let fp1 = address_fingerprint(&p);
        let fp2 = address_fingerprint(&p);
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, [0; 32]);
    }

    #[test]
    fn fingerprint_changes_with_keys() {
        let p1 = make_test_payload(3, 2);
        let mut p2 = make_test_payload(3, 2);
        p2.hybrid_kem_pubkeys[0] = vec![0xFF; HYBRID_KEM_PUBKEY_LEN];
        assert_ne!(address_fingerprint(&p1), address_fingerprint(&p2));
    }

    #[test]
    fn fingerprint_hex_format() {
        let p = make_test_payload(2, 2);
        let fp = address_fingerprint(&p);
        let hex = fingerprint_hex(&fp);
        assert_eq!(hex.len(), 64 + 15); // 64 hex chars + 15 spaces (16 groups of 4)
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }

    #[test]
    fn fingerprint_badge_format() {
        let p = make_test_payload(3, 2);
        let badge = fingerprint_badge(&p);
        assert_eq!(badge, "2-of-3, spend_auth v1, group v1");
    }

    #[test]
    fn provenance_fingerprint_changed() {
        let prov = AddressProvenance {
            address_fingerprint: [0; 32],
            first_imported_at: 1000,
            imported_from_source: "file:///tmp/multisig.addr".into(),
            user_assigned_label: "Alice+Bob".into(),
            last_used_at: 1000,
            prior_fingerprints: vec![],
        };
        assert!(!prov.fingerprint_changed());

        let prov2 = AddressProvenance {
            prior_fingerprints: vec![[1; 32]],
            ..prov
        };
        assert!(prov2.fingerprint_changed());
    }

    #[test]
    fn file_roundtrip() {
        let payload = make_test_payload(2, 2);
        let dir = std::env::temp_dir().join("shekyl_test_multisig_addr");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_addr.bin");

        payload.write_to_file(&path).unwrap();
        let loaded = MultisigAddressPayload::read_from_file(&path).unwrap();
        assert_eq!(payload, loaded);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn different_networks_different_payloads() {
        let p_main = MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
            vec![vec![0; HYBRID_SIGN_PUBKEY_LEN]; 2],
        )
        .unwrap();
        let p_test = MultisigAddressPayload::new(
            Network::Testnet,
            2,
            2,
            vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
            vec![vec![0; HYBRID_SIGN_PUBKEY_LEN]; 2],
        )
        .unwrap();
        assert_ne!(p_main.to_canonical_bytes(), p_test.to_canonical_bytes());
        assert_ne!(address_fingerprint(&p_main), address_fingerprint(&p_test));
    }
}
