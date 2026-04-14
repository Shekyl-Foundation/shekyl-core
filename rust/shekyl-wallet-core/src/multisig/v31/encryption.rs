// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Per-message AEAD encryption for multisig group communication
//! (PQC_MULTISIG.md SS12.3).
//!
//! Key derivation: HKDF-Expand from group_shared_secret with
//! intent_hash || message_type || sender_index as info.
//!
//! AEAD: ChaCha20-Poly1305, 96-bit nonce derived from
//! group_shared_secret || "nonce" || sender_index || message_counter.

use zeroize::Zeroize;

use super::messages::MessageType;

/// AEAD tag length for ChaCha20-Poly1305.
pub const AEAD_TAG_LEN: usize = 16;

/// Nonce length for ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;

/// Errors during encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("HKDF expand failed")]
    HkdfFailed,
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD decryption failed (tampered or wrong key)")]
    DecryptFailed,
    #[error("ciphertext too short")]
    CiphertextTooShort,
}

/// Derive the per-message symmetric key (SS12.3).
///
/// ```text
/// message_key = HKDF_Expand(
///     group_shared_secret,
///     intent_hash || u8(message_type) || u8(sender_index),
///     32
/// )
/// ```
pub fn derive_message_key(
    group_shared_secret: &[u8; 32],
    intent_hash: &[u8; 32],
    message_type: MessageType,
    sender_index: u8,
) -> Result<[u8; 32], EncryptionError> {
    let mut info = Vec::with_capacity(34);
    info.extend_from_slice(intent_hash);
    info.push(message_type as u8);
    info.push(sender_index);

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, group_shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| EncryptionError::HkdfFailed)?;
    Ok(key)
}

/// Derive the 96-bit nonce for AEAD (SS12.3).
///
/// ```text
/// nonce = HKDF_Expand(
///     group_shared_secret,
///     b"nonce" || u8(sender_index) || u64_le(message_counter),
///     12
/// )
/// ```
pub fn derive_nonce(
    group_shared_secret: &[u8; 32],
    sender_index: u8,
    message_counter: u64,
) -> Result<[u8; NONCE_LEN], EncryptionError> {
    let mut info = Vec::with_capacity(14);
    info.extend_from_slice(b"nonce");
    info.push(sender_index);
    info.extend_from_slice(&message_counter.to_le_bytes());

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, group_shared_secret);
    let mut nonce = [0u8; NONCE_LEN];
    hkdf.expand(&info, &mut nonce)
        .map_err(|_| EncryptionError::HkdfFailed)?;
    Ok(nonce)
}

/// Encrypt a plaintext payload with ChaCha20-Poly1305.
///
/// Returns ciphertext || 16-byte tag.
pub fn encrypt_payload(
    group_shared_secret: &[u8; 32],
    intent_hash: &[u8; 32],
    message_type: MessageType,
    sender_index: u8,
    message_counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

    let mut key = derive_message_key(group_shared_secret, intent_hash, message_type, sender_index)?;
    let nonce_bytes = derive_nonce(group_shared_secret, sender_index, message_counter)?;

    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptFailed)?;

    key.zeroize();
    Ok(ciphertext)
}

/// Decrypt a ciphertext payload with ChaCha20-Poly1305.
///
/// Input is ciphertext || 16-byte tag (as produced by `encrypt_payload`).
pub fn decrypt_payload(
    group_shared_secret: &[u8; 32],
    intent_hash: &[u8; 32],
    message_type: MessageType,
    sender_index: u8,
    message_counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(EncryptionError::CiphertextTooShort);
    }

    let mut key = derive_message_key(group_shared_secret, intent_hash, message_type, sender_index)?;
    let nonce_bytes = derive_nonce(group_shared_secret, sender_index, message_counter)?;

    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce_bytes.into();

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptFailed)?;

    key.zeroize();
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [0x42; 32];
    const INTENT: [u8; 32] = [0xAA; 32];

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello multisig world";
        let ct = encrypt_payload(
            &SECRET,
            &INTENT,
            MessageType::SpendIntent,
            0,
            1,
            plaintext,
        )
        .unwrap();

        assert_ne!(ct.as_slice(), plaintext);
        assert!(ct.len() > plaintext.len());

        let pt = decrypt_payload(
            &SECRET,
            &INTENT,
            MessageType::SpendIntent,
            0,
            1,
            &ct,
        )
        .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn different_keys_produce_different_ciphertexts() {
        let plaintext = b"test";
        let ct1 = encrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 0, 1, plaintext)
            .unwrap();
        let ct2 = encrypt_payload(&[0x99; 32], &INTENT, MessageType::SpendIntent, 0, 1, plaintext)
            .unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn different_message_types_produce_different_ciphertexts() {
        let plaintext = b"test";
        let ct1 = encrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 0, 1, plaintext)
            .unwrap();
        let ct2 = encrypt_payload(&SECRET, &INTENT, MessageType::ProverOutput, 0, 1, plaintext)
            .unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn different_sender_indices_produce_different_ciphertexts() {
        let plaintext = b"test";
        let ct1 = encrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 0, 1, plaintext)
            .unwrap();
        let ct2 = encrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 1, 1, plaintext)
            .unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let plaintext = b"secret data";
        let ct = encrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 0, 1, plaintext)
            .unwrap();
        let result =
            decrypt_payload(&[0x99; 32], &INTENT, MessageType::SpendIntent, 0, 1, &ct);
        assert!(matches!(result, Err(EncryptionError::DecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let plaintext = b"secret data";
        let mut ct = encrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 0, 1, plaintext)
            .unwrap();
        ct[0] ^= 0xFF;
        let result = decrypt_payload(&SECRET, &INTENT, MessageType::SpendIntent, 0, 1, &ct);
        assert!(matches!(result, Err(EncryptionError::DecryptFailed)));
    }

    #[test]
    fn too_short_ciphertext_rejected() {
        let result = decrypt_payload(
            &SECRET,
            &INTENT,
            MessageType::SpendIntent,
            0,
            1,
            &[0; 10],
        );
        assert!(matches!(result, Err(EncryptionError::CiphertextTooShort)));
    }

    #[test]
    fn message_key_deterministic() {
        let k1 = derive_message_key(&SECRET, &INTENT, MessageType::Heartbeat, 2).unwrap();
        let k2 = derive_message_key(&SECRET, &INTENT, MessageType::Heartbeat, 2).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, [0; 32]);
    }

    #[test]
    fn nonce_deterministic() {
        let n1 = derive_nonce(&SECRET, 0, 42).unwrap();
        let n2 = derive_nonce(&SECRET, 0, 42).unwrap();
        assert_eq!(n1, n2);
    }

    #[test]
    fn nonce_varies_with_counter() {
        let n1 = derive_nonce(&SECRET, 0, 1).unwrap();
        let n2 = derive_nonce(&SECRET, 0, 2).unwrap();
        assert_ne!(n1, n2);
    }
}
