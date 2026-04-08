// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Multisig group metadata and key storage.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use shekyl_fcmp::frost_dkg::SerializedThresholdKeys;

/// Persistent metadata for an M-of-N FROST multisig group.
///
/// Stored alongside the wallet file (encrypted). The threshold keys
/// are kept in their serialized form and deserialized on demand.
#[derive(Serialize, Deserialize)]
pub struct MultisigGroup {
    pub group_id: [u8; 32],
    pub threshold: u16,
    pub total: u16,
    pub our_index: u16,
    #[serde(with = "hex_bytes")]
    serialized_keys: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub pqc_public_key: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pqc_secret_key: Vec<u8>,
}

impl MultisigGroup {
    /// Create a new group from freshly completed DKG keys.
    pub fn new(
        group_id: [u8; 32],
        threshold: u16,
        total: u16,
        our_index: u16,
        keys: &SerializedThresholdKeys,
    ) -> Self {
        Self {
            group_id,
            threshold,
            total,
            our_index,
            serialized_keys: keys.as_bytes().to_vec(),
            pqc_public_key: Vec::new(),
            pqc_secret_key: Vec::new(),
        }
    }

    /// Set the PQC hybrid keypair for this participant.
    pub fn set_pqc_keypair(&mut self, public_key: Vec<u8>, secret_key: Vec<u8>) {
        self.pqc_public_key = public_key;
        self.pqc_secret_key = secret_key;
    }

    /// Get the serialized threshold keys.
    pub fn threshold_keys(&self) -> SerializedThresholdKeys {
        SerializedThresholdKeys::from_bytes(&self.serialized_keys)
    }

    /// Get the PQC secret key (for signing).
    pub fn pqc_secret_key(&self) -> &[u8] {
        &self.pqc_secret_key
    }

    /// Get the 32-byte group public key from threshold keys.
    pub fn group_public_key(&self) -> Option<[u8; 32]> {
        let keys = self.threshold_keys().deserialize().ok()?;
        Some(shekyl_fcmp::frost_dkg::group_key_bytes(&keys))
    }
}

impl Drop for MultisigGroup {
    fn drop(&mut self) {
        self.serialized_keys.zeroize();
        self.pqc_secret_key.zeroize();
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
