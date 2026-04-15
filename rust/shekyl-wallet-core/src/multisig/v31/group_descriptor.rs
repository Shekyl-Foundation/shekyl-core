// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Group Descriptor: single canonical backup file for multisig group state.
//!
//! Analogous to Bitcoin's output script descriptors (BIP 380). One file
//! contains everything needed to reconstruct group state from seeds.

use serde::{Deserialize, Serialize};

/// File format version.
pub const GROUP_DESCRIPTOR_VERSION: u8 = 1;

/// A relay entry in the group descriptor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayEntry {
    pub url: String,
    pub operator_id: String,
}

/// Group descriptor: everything needed to restore a multisig group.
///
/// This is the "descriptor" file — one file, importable into any
/// conforming wallet, restores the group without scattered persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupDescriptor {
    pub version: u8,
    pub group_id: String,
    pub m_required: u8,
    pub n_total: u8,
    pub spend_auth_version: u8,
    pub participant_pubkeys: Vec<String>,
    pub address_fingerprint: String,
    pub relays: Vec<RelayEntry>,
    pub created_at: u64,
    pub notes: Option<String>,
}

impl GroupDescriptor {
    pub fn new(
        group_id: String,
        m_required: u8,
        n_total: u8,
        spend_auth_version: u8,
        participant_pubkeys: Vec<String>,
        address_fingerprint: String,
    ) -> Self {
        Self {
            version: GROUP_DESCRIPTOR_VERSION,
            group_id,
            m_required,
            n_total,
            spend_auth_version,
            participant_pubkeys,
            address_fingerprint,
            relays: Vec::new(),
            created_at: 0,
            notes: None,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, GroupDescriptorError> {
        let desc: Self = serde_json::from_str(json)
            .map_err(|e| GroupDescriptorError::ParseFailed(e.to_string()))?;

        if desc.version != GROUP_DESCRIPTOR_VERSION {
            return Err(GroupDescriptorError::UnsupportedVersion(desc.version));
        }
        if desc.m_required == 0 || desc.m_required > desc.n_total {
            return Err(GroupDescriptorError::InvalidThreshold {
                m: desc.m_required,
                n: desc.n_total,
            });
        }
        if desc.participant_pubkeys.len() != desc.n_total as usize {
            return Err(GroupDescriptorError::PubkeyCountMismatch {
                expected: desc.n_total,
                got: desc.participant_pubkeys.len() as u8,
            });
        }
        if desc.group_id.is_empty() {
            return Err(GroupDescriptorError::MissingGroupId);
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
    #[error("group_id is required")]
    MissingGroupId,
    #[error("address_fingerprint is required")]
    MissingFingerprint,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_descriptor() -> GroupDescriptor {
        GroupDescriptor {
            version: GROUP_DESCRIPTOR_VERSION,
            group_id: "abcd1234".into(),
            m_required: 2,
            n_total: 3,
            spend_auth_version: 2,
            participant_pubkeys: vec!["pk1".into(), "pk2".into(), "pk3".into()],
            address_fingerprint: "deadbeef".into(),
            relays: vec![
                RelayEntry {
                    url: "wss://relay1.example.com".into(),
                    operator_id: "op1".into(),
                },
                RelayEntry {
                    url: "wss://relay2.example.com".into(),
                    operator_id: "op2".into(),
                },
            ],
            created_at: 1713000000,
            notes: Some("Test group".into()),
        }
    }

    #[test]
    fn json_roundtrip() {
        let desc = make_test_descriptor();
        let json = desc.to_json().unwrap();
        let parsed = GroupDescriptor::from_json(&json).unwrap();
        assert_eq!(parsed.group_id, desc.group_id);
        assert_eq!(parsed.m_required, 2);
        assert_eq!(parsed.n_total, 3);
        assert_eq!(parsed.participant_pubkeys.len(), 3);
        assert_eq!(parsed.relays.len(), 2);
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

    #[test]
    fn rejects_empty_group_id() {
        let mut desc = make_test_descriptor();
        desc.group_id = String::new();
        let json = serde_json::to_string(&desc).unwrap();
        assert!(matches!(
            GroupDescriptor::from_json(&json),
            Err(GroupDescriptorError::MissingGroupId)
        ));
    }
}
