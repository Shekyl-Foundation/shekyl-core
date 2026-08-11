// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! MultisigEnvelope and the E′ message types (PQC_MULTISIG.md SS12.1–SS12.2).
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
    SignatureShare = 0x03,
    GroupStateSummary = 0x08,
    InvariantViolation = 0x09,
    EquivocationProof = 0x0B,
    // Discriminants 0x02/0x04/0x05/0x06/0x07/0x0A were the Option-D
    // prover-output / veto / prover-receipt / heartbeat / counter-proof /
    // rotation-intent types. Excised under MS-5: Option E′ has no prover,
    // veto, heartbeat, counter-proof, or rotation. Surviving discriminant
    // values are left unchanged (a deletion, not a renumbering); the E′
    // FROST-round and hybrid-sig message types are assigned when the ceremony
    // lands.
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::SpendIntent),
            0x03 => Some(Self::SignatureShare),
            0x08 => Some(Self::GroupStateSummary),
            0x09 => Some(Self::InvariantViolation),
            0x0B => Some(Self::EquivocationProof),
            _ => None,
        }
    }
}

/// MultisigEnvelope: the common wrapper for all inter-participant messages
/// (SS12.1).
///
/// Cleartext fields: version, address_fingerprint, intent_hash, sender_index,
/// sender_sig, encrypted payload. The message_type is inside the
/// encrypted payload to prevent role-pattern leakage (SS12.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigEnvelope {
    pub version: u8,
    /// The group's identity (see `SpendIntent::address_fingerprint`): the
    /// `shekyl_address::address_fingerprint` value, signed into the envelope
    /// header. Carried, not computed, here.
    pub address_fingerprint: [u8; 32],
    pub intent_hash: [u8; 32],
    pub sender_index: u8,
    /// Sender's signature slot (wire §1.2 defines its preimage). **No
    /// production signer exists today** — every live path carries it empty,
    /// and the bare preimage builder was deleted rather than left as dead
    /// code inviting a bare signer (rule 15; SA-2 §2.1 census / SA-3b).
    ///
    /// **Forward-guard.** A future signer MUST route through the
    /// domain-separated hybrid scheme (`shekyl_crypto_pq::signature`, a
    /// distinct `…-scheme-v1` domain, per SA-R-2) and register that domain in
    /// `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` — signing the §1.2 bytes bare
    /// would re-introduce the caller-supplied-separation weakness the SA round
    /// removed, and would let an envelope signature be replayed as a
    /// same-shape signature over unrelated bytes. Do not populate this field
    /// without minting its domain.
    pub sender_sig: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

impl MultisigEnvelope {
    /// Serialize to canonical bytes for transport.
    ///
    /// Fails with `FieldTooLong` rather than truncating a length that
    /// overflows the u32 wire prefix.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut buf = Vec::with_capacity(128 + self.encrypted_payload.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.address_fingerprint);
        buf.extend_from_slice(&self.intent_hash);
        buf.push(self.sender_index);
        let sig_len = u32::try_from(self.sender_sig.len())
            .map_err(|_| EnvelopeError::FieldTooLong("sender_sig"))?;
        buf.extend_from_slice(&sig_len.to_le_bytes());
        buf.extend_from_slice(&self.sender_sig);
        let payload_len = u32::try_from(self.encrypted_payload.len())
            .map_err(|_| EnvelopeError::FieldTooLong("encrypted_payload"))?;
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        Ok(buf)
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

        let address_fingerprint: [u8; 32] = data[1..33]
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
        let sig_len_raw = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
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
        let payload_len_raw = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
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
            address_fingerprint,
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
    #[error("field '{0}' too long to serialize (length exceeds u32 wire prefix)")]
    FieldTooLong(&'static str),
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
        // The E′ surviving discriminants round-trip; the six excised Option-D
        // discriminants and out-of-range bytes decode to None.
        for byte in [0x01, 0x03, 0x08, 0x09, 0x0Bu8] {
            let mt = MessageType::from_u8(byte).unwrap();
            assert_eq!(mt as u8, byte);
        }
        for excised in [0x00, 0x02, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x0Cu8] {
            assert!(MessageType::from_u8(excised).is_none());
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let env = MultisigEnvelope {
            version: ENVELOPE_VERSION,
            address_fingerprint: [0xAA; 32],
            intent_hash: [0xBB; 32],
            sender_index: 2,
            sender_sig: vec![0xCC; 64],
            encrypted_payload: vec![0xDD; 128],
        };
        let bytes = env.to_bytes().unwrap();
        let parsed = MultisigEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, ENVELOPE_VERSION);
        assert_eq!(parsed.address_fingerprint, [0xAA; 32]);
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
            message_type: MessageType::SignatureShare,
            body: vec![1, 2, 3, 4],
        };
        let encoded = dp.encode();
        assert_eq!(encoded[0], 0x03);
        let decoded = DecryptedPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::SignatureShare);
        assert_eq!(decoded.body, vec![1, 2, 3, 4]);
    }

    #[test]
    fn decrypted_payload_rejects_empty() {
        assert!(DecryptedPayload::decode(&[]).is_err());
    }
}
