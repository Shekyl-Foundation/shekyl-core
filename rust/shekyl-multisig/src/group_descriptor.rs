// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Group descriptor: one file of a multisig group's public identity.
//!
//! It holds the threshold, the participants' public keys, the group KEM
//! public key and the address fingerprint. It does not hold a FROST share,
//! `b`, or a KEM secret. Those live in the member file (`member_file`),
//! and a wallet seed does not regenerate them. Restoring a member is that
//! file plus a rescan (`PQC_MULTISIG.md` §6.6, §8.4).

use serde::{Deserialize, Serialize};

/// File format version. `2` adds the group KEM public key. A file of any
/// other version is refused with [`GroupDescriptorError::UnsupportedVersion`],
/// whatever fields it has: [`GroupDescriptor::from_json`] reads the version
/// before the rest of the schema.
pub const GROUP_DESCRIPTOR_VERSION: u8 = 2;

/// The one field every descriptor version shares. Serde ignores the rest.
#[derive(Deserialize)]
struct VersionProbe {
    version: u8,
}

/// The group's public identity, in one file.
///
/// Importing one restores the public fields a wallet shows and compares.
/// Spending still needs that member's file: the share and the KEM secrets
/// are not in this file and are not derived from a seed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupDescriptor {
    pub version: u8,
    pub m_required: u8,
    pub n_total: u8,
    pub spend_auth_version: u8,
    pub participant_pubkeys: Vec<String>,
    /// The group's hybrid KEM public key (hex): the key a payer's `0x06`
    /// ciphertext goes to. Every member holds its secret. Absent reads as
    /// empty, so [`GroupDescriptor::from_json`] names it missing.
    #[serde(default)]
    pub group_kem_pubkey: String,
    /// The group's identity: the hex of `shekyl_address::address_fingerprint`
    /// over the group's `MultisigAddressPayload`. This is the single group
    /// identifier — it replaces the former opaque `group_id: String`, which was
    /// carried but never produced by anything (the synthesis: one value, one
    /// producer, independently derivable by every participant from the address).
    /// Absent reads as empty, so [`GroupDescriptor::from_json`] names it missing.
    #[serde(default)]
    pub address_fingerprint: String,
    pub created_at: u64,
    pub notes: Option<String>,
}

impl GroupDescriptor {
    pub fn new(
        m_required: u8,
        n_total: u8,
        spend_auth_version: u8,
        participant_pubkeys: Vec<String>,
        group_kem_pubkey: String,
        address_fingerprint: String,
    ) -> Self {
        Self {
            version: GROUP_DESCRIPTOR_VERSION,
            m_required,
            n_total,
            spend_auth_version,
            participant_pubkeys,
            group_kem_pubkey,
            address_fingerprint,
            created_at: 0,
            notes: None,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, GroupDescriptorError> {
        let parse_failed = |e: serde_json::Error| GroupDescriptorError::ParseFailed(e.to_string());
        let VersionProbe { version } = serde_json::from_str(json).map_err(parse_failed)?;
        if version != GROUP_DESCRIPTOR_VERSION {
            return Err(GroupDescriptorError::UnsupportedVersion(version));
        }
        let desc: Self = serde_json::from_str(json).map_err(parse_failed)?;

        if desc.m_required == 0 || desc.m_required > desc.n_total {
            return Err(GroupDescriptorError::InvalidThreshold {
                m: desc.m_required,
                n: desc.n_total,
            });
        }
        if desc.participant_pubkeys.len() != desc.n_total as usize {
            return Err(GroupDescriptorError::PubkeyCountMismatch {
                expected: desc.n_total,
                // Diagnostic-only field on an error we are already returning;
                // saturate rather than widen the error type (house telemetry
                // idiom). n_total is u8, so any real mismatch is representable.
                got: u8::try_from(desc.participant_pubkeys.len()).unwrap_or(u8::MAX),
            });
        }
        if desc.group_kem_pubkey.is_empty() {
            return Err(GroupDescriptorError::MissingGroupKemPubkey);
        }
        if desc.address_fingerprint.is_empty() {
            return Err(GroupDescriptorError::MissingFingerprint);
        }

        Ok(desc)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GroupDescriptorError {
    #[error("unsupported descriptor version: {0}")]
    UnsupportedVersion(u8),
    #[error("failed to parse descriptor: {0}")]
    ParseFailed(String),
    #[error("invalid threshold: m={m} must be 1..=n={n}")]
    InvalidThreshold { m: u8, n: u8 },
    #[error("pubkey count mismatch: expected {expected}, got {got}")]
    PubkeyCountMismatch { expected: u8, got: u8 },
    #[error("group_kem_pubkey is required")]
    MissingGroupKemPubkey,
    #[error("address_fingerprint is required")]
    MissingFingerprint,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_descriptor() -> GroupDescriptor {
        GroupDescriptor {
            version: GROUP_DESCRIPTOR_VERSION,
            m_required: 2,
            n_total: 3,
            spend_auth_version: 2,
            participant_pubkeys: vec!["pk1".into(), "pk2".into(), "pk3".into()],
            group_kem_pubkey: "gk".into(),
            address_fingerprint: "deadbeef".into(),
            created_at: 1713000000,
            notes: Some("Test group".into()),
        }
    }

    #[test]
    fn json_roundtrip() {
        let desc = make_test_descriptor();
        let json = desc.to_json().unwrap();
        let parsed = GroupDescriptor::from_json(&json).unwrap();
        assert_eq!(parsed.address_fingerprint, desc.address_fingerprint);
        assert_eq!(parsed.m_required, 2);
        assert_eq!(parsed.n_total, 3);
        assert_eq!(parsed.participant_pubkeys.len(), 3);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut desc = make_test_descriptor();
        desc.version = 99;
        let json = serde_json::to_string(&desc).unwrap();
        assert!(matches!(
            GroupDescriptor::from_json(&json),
            Err(GroupDescriptorError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn rejects_invalid_threshold() {
        let mut desc = make_test_descriptor();
        desc.m_required = 5;
        let json = serde_json::to_string(&desc).unwrap();
        assert!(matches!(
            GroupDescriptor::from_json(&json),
            Err(GroupDescriptorError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn rejects_pubkey_count_mismatch() {
        let mut desc = make_test_descriptor();
        desc.participant_pubkeys = vec!["pk1".into(), "pk2".into()];
        let json = serde_json::to_string(&desc).unwrap();
        assert!(matches!(
            GroupDescriptor::from_json(&json),
            Err(GroupDescriptorError::PubkeyCountMismatch { .. })
        ));
    }

    /// The descriptor as JSON with `field` removed and `version` set.
    fn json_without(field: &str, version: u8) -> String {
        let mut value = serde_json::to_value(make_test_descriptor()).unwrap();
        let object = value.as_object_mut().unwrap();
        assert!(object.remove(field).is_some(), "no field {field}");
        object.insert("version".into(), version.into());
        value.to_string()
    }

    #[test]
    fn a_version_1_file_is_refused_by_its_version() {
        // A version-1 descriptor has no group KEM key at all.
        assert!(matches!(
            GroupDescriptor::from_json(&json_without("group_kem_pubkey", 1)),
            Err(GroupDescriptorError::UnsupportedVersion(1))
        ));
        // Another version is refused by version whatever its fields are.
        assert!(matches!(
            GroupDescriptor::from_json(r#"{"version": 3}"#),
            Err(GroupDescriptorError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn a_file_without_a_version_does_not_parse() {
        let mut value = serde_json::to_value(make_test_descriptor()).unwrap();
        value.as_object_mut().unwrap().remove("version");
        assert!(matches!(
            GroupDescriptor::from_json(&value.to_string()),
            Err(GroupDescriptorError::ParseFailed(_))
        ));
    }

    #[test]
    fn rejects_a_missing_group_kem_pubkey() {
        assert!(matches!(
            GroupDescriptor::from_json(&json_without("group_kem_pubkey", 2)),
            Err(GroupDescriptorError::MissingGroupKemPubkey)
        ));
        let mut desc = make_test_descriptor();
        desc.group_kem_pubkey = String::new();
        let json = serde_json::to_string(&desc).unwrap();
        assert!(matches!(
            GroupDescriptor::from_json(&json),
            Err(GroupDescriptorError::MissingGroupKemPubkey)
        ));
    }

    #[test]
    fn rejects_an_absent_address_fingerprint() {
        assert!(matches!(
            GroupDescriptor::from_json(&json_without("address_fingerprint", 2)),
            Err(GroupDescriptorError::MissingFingerprint)
        ));
    }

    #[test]
    fn rejects_empty_address_fingerprint() {
        let mut desc = make_test_descriptor();
        desc.address_fingerprint = String::new();
        let json = serde_json::to_string(&desc).unwrap();
        assert!(matches!(
            GroupDescriptor::from_json(&json),
            Err(GroupDescriptorError::MissingFingerprint)
        ));
    }
}
