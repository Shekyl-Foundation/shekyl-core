// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! MultisigEnvelope and the 11 message types (PQC_MULTISIG.md SS12.1–SS12.2).
//!
//! The envelope wraps all inter-participant communication. The `message_type`
//! is encrypted inside the payload to prevent role-pattern leakage.

use serde::{Deserialize, Serialize};

/// Envelope version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Message type discriminators (encrypted in payload per SS12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    SpendIntent = 0x01,
    ProverOutput = 0x02,
    SignatureShare = 0x03,
    Veto = 0x04,
    ProverReceipt = 0x05,
    Heartbeat = 0x06,
    CounterProof = 0x07,
    GroupStateSummary = 0x08,
    InvariantViolation = 0x09,
    RotationIntent = 0x0A,
    EquivocationProof = 0x0B,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::SpendIntent),
            0x02 => Some(Self::ProverOutput),
            0x03 => Some(Self::SignatureShare),
            0x04 => Some(Self::Veto),
            0x05 => Some(Self::ProverReceipt),
            0x06 => Some(Self::Heartbeat),
            0x07 => Some(Self::CounterProof),
            0x08 => Some(Self::GroupStateSummary),
            0x09 => Some(Self::InvariantViolation),
            0x0A => Some(Self::RotationIntent),
            0x0B => Some(Self::EquivocationProof),
            _ => None,
        }
    }

    pub fn is_reserved(&self) -> bool {
        matches!(self, Self::RotationIntent)
    }
}

/// MultisigEnvelope: the common wrapper for all inter-participant messages
/// (SS12.1).
///
/// Cleartext fields: version, group_id, intent_hash, sender_index,
/// sender_sig, encrypted payload. The message_type is inside the
/// encrypted payload to prevent role-pattern leakage (SS12.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigEnvelope {
    pub version: u8,
    pub group_id: [u8; 32],
    pub intent_hash: [u8; 32],
    pub sender_index: u8,
    pub sender_sig: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

impl MultisigEnvelope {
    /// Bytes that the sender signs: version || group_id || intent_hash ||
    /// sender_index || payload_len || encrypted_payload.
    ///
    /// payload_len is included to prevent framing attacks where an attacker
    /// swaps the length prefix while preserving the ciphertext. sig_len is
    /// NOT included because it is metadata about the signature itself.
    pub fn signable_header(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(70 + self.encrypted_payload.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.group_id);
        buf.extend_from_slice(&self.intent_hash);
        buf.push(self.sender_index);
        buf.extend_from_slice(&(self.encrypted_payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Serialize to canonical bytes for transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + self.encrypted_payload.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.group_id);
        buf.extend_from_slice(&self.intent_hash);
        buf.push(self.sender_index);
        buf.extend_from_slice(&(self.sender_sig.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.sender_sig);
        buf.extend_from_slice(&(self.encrypted_payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Parse from canonical bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnvelopeError> {
        if data.len() < 67 {
            return Err(EnvelopeError::TooShort);
        }

        let version = data[0];
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }

        let group_id: [u8; 32] = data[1..33]
            .try_into()
            .map_err(|_| EnvelopeError::TooShort)?;
        let intent_hash: [u8; 32] = data[33..65]
            .try_into()
            .map_err(|_| EnvelopeError::TooShort)?;
        let sender_index = data[65];

        let mut offset = 66;
        if offset + 4 > data.len() {
            return Err(EnvelopeError::TooShort);
        }
        let sig_len_raw =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        if sig_len_raw > MAX_SIG_LEN {
            return Err(EnvelopeError::SigTooLong(sig_len_raw));
        }
        let sig_len = sig_len_raw as usize;
        offset += 4;
        if offset + sig_len > data.len() {
            return Err(EnvelopeError::TooShort);
        }
        let sender_sig = data[offset..offset + sig_len].to_vec();
        offset += sig_len;

        if offset + 4 > data.len() {
            return Err(EnvelopeError::TooShort);
        }
        let payload_len_raw =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        if payload_len_raw > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::PayloadTooLong(payload_len_raw));
        }
        let payload_len = payload_len_raw as usize;
        offset += 4;
        if offset + payload_len > data.len() {
            return Err(EnvelopeError::TooShort);
        }
        let encrypted_payload = data[offset..offset + payload_len].to_vec();

        Ok(MultisigEnvelope {
            version,
            group_id,
            intent_hash,
            sender_index,
            sender_sig,
            encrypted_payload,
        })
    }
}

/// Maximum signature length (hybrid sigs are ~3,385 bytes; headroom for future).
pub const MAX_SIG_LEN: u32 = 8192;

/// Maximum encrypted payload length (1 MiB).
pub const MAX_PAYLOAD_LEN: u32 = 1_048_576;

/// Errors during envelope parsing.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope too short")]
    TooShort,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("sig_len {0} exceeds maximum {MAX_SIG_LEN}")]
    SigTooLong(u32),
    #[error("payload_len {0} exceeds maximum {MAX_PAYLOAD_LEN}")]
    PayloadTooLong(u32),
}

/// Decrypted payload: message_type + type-specific body.
#[derive(Clone, Debug)]
pub struct DecryptedPayload {
    pub message_type: MessageType,
    pub body: Vec<u8>,
}

impl DecryptedPayload {
    /// Encode: prepend message_type byte to body.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.body.len());
        buf.push(self.message_type as u8);
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Decode from plaintext bytes.
    pub fn decode(plaintext: &[u8]) -> Result<Self, EnvelopeError> {
        if plaintext.is_empty() {
            return Err(EnvelopeError::TooShort);
        }
        let message_type = MessageType::from_u8(plaintext[0])
            .ok_or(EnvelopeError::UnsupportedVersion(plaintext[0]))?;
        Ok(DecryptedPayload {
            message_type,
            body: plaintext[1..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_roundtrip() {
        for byte in 0x01..=0x0Bu8 {
            let mt = MessageType::from_u8(byte).unwrap();
            assert_eq!(mt as u8, byte);
        }
        assert!(MessageType::from_u8(0x00).is_none());
        assert!(MessageType::from_u8(0x0C).is_none());
    }

    #[test]
    fn rotation_intent_is_reserved() {
        assert!(MessageType::RotationIntent.is_reserved());
        assert!(!MessageType::SpendIntent.is_reserved());
    }

    #[test]
    fn envelope_roundtrip() {
        let env = MultisigEnvelope {
            version: ENVELOPE_VERSION,
            group_id: [0xAA; 32],
            intent_hash: [0xBB; 32],
            sender_index: 2,
            sender_sig: vec![0xCC; 64],
            encrypted_payload: vec![0xDD; 128],
        };
        let bytes = env.to_bytes();
        let parsed = MultisigEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, ENVELOPE_VERSION);
        assert_eq!(parsed.group_id, [0xAA; 32]);
        assert_eq!(parsed.intent_hash, [0xBB; 32]);
        assert_eq!(parsed.sender_index, 2);
        assert_eq!(parsed.sender_sig, vec![0xCC; 64]);
        assert_eq!(parsed.encrypted_payload, vec![0xDD; 128]);
    }

    #[test]
    fn envelope_rejects_too_short() {
        assert!(MultisigEnvelope::from_bytes(&[0; 10]).is_err());
    }

    #[test]
    fn envelope_rejects_wrong_version() {
        let mut bytes = vec![0; 100];
        bytes[0] = 99;
        assert!(matches!(
            MultisigEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn decrypted_payload_roundtrip() {
        let dp = DecryptedPayload {
            message_type: MessageType::ProverOutput,
            body: vec![1, 2, 3, 4],
        };
        let encoded = dp.encode();
        assert_eq!(encoded[0], 0x02);
        let decoded = DecryptedPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::ProverOutput);
        assert_eq!(decoded.body, vec![1, 2, 3, 4]);
    }

    #[test]
    fn decrypted_payload_rejects_empty() {
        assert!(DecryptedPayload::decode(&[]).is_err());
    }
}
