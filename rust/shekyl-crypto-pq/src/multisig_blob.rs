// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The AEAD for an Option E′ ceremony blob (`docs/PQC_MULTISIG.md` §12.3;
//! Round 0 ruling R-4).
//!
//! Every member holds the group transport secret (the member file,
//! `derivation::derive_group_transport_secret`, derived under `salt_for`).
//! A blob's payload is sealed under a key expanded from that secret for one
//! `(intent, message type, sender)`, with XChaCha20-Poly1305 and a **random**
//! 24-byte nonce carried at the front of the sealed bytes:
//!
//! ```text
//! key    = HKDF-SHA-512(ikm = transport_secret)
//!            .expand(LABEL_MULTISIG_BLOB_KEY ‖ intent_hash ‖ u8(message_type) ‖ u8(sender_index), 32)
//! sealed = nonce(24) ‖ XChaCha20-Poly1305(key, nonce, aad, payload) ‖ tag(16)
//! ```
//!
//! The nonce is random because the alternative, a nonce derived from a
//! persisted counter, repeats when a wallet is restored from a backup, and a
//! repeated nonce under ChaCha20-Poly1305 leaks the XOR of two payloads and
//! the Poly1305 key. At 192 bits a random nonce does not repeat. A
//! ceremony's counter still orders blobs and refuses replays; it no longer
//! keeps the AEAD safe.
//!
//! `aad` is the blob's cleartext header, which the caller binds; a header
//! edited in transit fails to open.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroizing;

/// The HKDF info label a ceremony blob's key expands under
/// (`CRYPTO_DOMAIN_REGISTRY.tsv`, mechanism 2).
pub const LABEL_MULTISIG_BLOB_KEY: &[u8] = b"shekyl/multisig-blob-key-v1";

/// Bytes of the random nonce at the front of a sealed blob.
pub const BLOB_NONCE_LEN: usize = 24;

/// Bytes of the Poly1305 tag at the end of a sealed blob.
pub const BLOB_TAG_LEN: usize = 16;

/// Who sealed a blob, and for what: the key is expanded for exactly this
/// triple, so a payload sealed for one intent, message type or sender does
/// not open as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobContext {
    /// The intent the ceremony is for.
    pub intent_hash: [u8; 32],
    /// The ceremony message type.
    pub message_type: u8,
    /// The sending member's index.
    pub sender_index: u8,
}

/// Why a blob cannot be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    /// Shorter than a nonce and a tag: not a sealed blob.
    #[error("a sealed blob is at least {} bytes", BLOB_NONCE_LEN + BLOB_TAG_LEN)]
    Truncated,
    /// The tag does not verify: wrong secret, wrong context, an edited
    /// header, or an edited ciphertext. One variant for all four, so the
    /// failure is no oracle for which.
    #[error("the blob does not open under this group's key for this context")]
    Unauthentic,
    /// The AEAD refused to seal (a payload past the cipher's length limit).
    #[error("the blob could not be sealed")]
    Seal,
}

/// Seal `payload` for `context`, binding `aad`.
///
/// # Errors
///
/// [`BlobError::Seal`] if the AEAD refuses the payload.
pub fn seal_blob(
    transport_secret: &[u8; 32],
    context: &BlobContext,
    aad: &[u8],
    payload: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, BlobError> {
    let key = blob_key(transport_secret, context);
    let mut nonce = [0u8; BLOB_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut sealed = Vec::with_capacity(BLOB_NONCE_LEN + payload.len() + BLOB_TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(payload);
    let tag = XChaCha20Poly1305::new((&*key).into())
        .encrypt_in_place_detached(&XNonce::from(nonce), aad, &mut sealed[BLOB_NONCE_LEN..])
        .map_err(|_| BlobError::Seal)?;
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open a blob [`seal_blob`] made for `context` with `aad`. The plaintext
/// may carry a member's FROST share or signature material, so it is
/// returned wiped-on-drop.
///
/// # Errors
///
/// [`BlobError::Truncated`] for bytes too short to be a sealed blob;
/// [`BlobError::Unauthentic`] when the tag does not verify.
pub fn open_blob(
    transport_secret: &[u8; 32],
    context: &BlobContext,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BlobError> {
    if sealed.len() < BLOB_NONCE_LEN + BLOB_TAG_LEN {
        return Err(BlobError::Truncated);
    }
    let (nonce, rest) = sealed.split_at(BLOB_NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - BLOB_TAG_LEN);
    let nonce: [u8; BLOB_NONCE_LEN] = nonce.try_into().expect("split at the nonce length");
    let tag: [u8; BLOB_TAG_LEN] = tag.try_into().expect("split at the tag length");
    let key = blob_key(transport_secret, context);
    let mut payload = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new((&*key).into())
        .decrypt_in_place_detached(
            &XNonce::from(nonce),
            aad,
            payload.as_mut_slice(),
            &Tag::from(tag),
        )
        .map_err(|_| BlobError::Unauthentic)?;
    Ok(payload)
}

/// The blob key for `context`, expanded from the transport secret.
fn blob_key(transport_secret: &[u8; 32], context: &BlobContext) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(LABEL_MULTISIG_BLOB_KEY.len() + 34);
    info.extend_from_slice(LABEL_MULTISIG_BLOB_KEY);
    info.extend_from_slice(&context.intent_hash);
    info.push(context.message_type);
    info.push(context.sender_index);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha512>::new(None, transport_secret)
        .expand(&info, key.as_mut())
        .expect("32 bytes is within HKDF-SHA-512's output limit");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const SECRET: [u8; 32] = [0x7A; 32];
    const CONTEXT: BlobContext = BlobContext {
        intent_hash: [0x11; 32],
        message_type: 3,
        sender_index: 1,
    };
    const AAD: &[u8] = b"header";

    fn sealed(payload: &[u8]) -> Vec<u8> {
        seal_blob(&SECRET, &CONTEXT, AAD, payload, &mut OsRng).unwrap()
    }

    /// The key derivation, pinned: HKDF-SHA-512 with an empty salt over the
    /// transport secret, info = label ‖ intent ‖ type ‖ sender. The vector
    /// was computed with Python's `hmac`/`hashlib`, independently of this
    /// crate's HKDF.
    #[test]
    fn the_blob_key_is_pinned() {
        let expected: [u8; 32] = [
            0xf5, 0x07, 0xd7, 0x74, 0xbe, 0xfd, 0x95, 0x43, 0xeb, 0x9f, 0x06, 0xfa, 0x92, 0xc6,
            0x8e, 0x83, 0xb0, 0x73, 0x20, 0x58, 0x83, 0xa3, 0x51, 0xee, 0x8b, 0xfb, 0xe5, 0x8c,
            0xd2, 0x5c, 0xe9, 0xaf,
        ];
        assert!(*blob_key(&SECRET, &CONTEXT) == expected);
    }

    #[test]
    fn a_sealed_blob_opens_to_its_payload() {
        for payload in [&b""[..], b"x", &[0x55; 4096]] {
            let blob = sealed(payload);
            assert_eq!(blob.len(), BLOB_NONCE_LEN + payload.len() + BLOB_TAG_LEN);
            assert_eq!(
                open_blob(&SECRET, &CONTEXT, AAD, &blob).unwrap().as_slice(),
                payload
            );
        }
    }

    /// Two seals of one payload under one context differ: the nonce is
    /// random, not a function of anything a restored wallet repeats.
    #[test]
    fn every_seal_draws_a_fresh_nonce() {
        let a = sealed(b"same");
        let b = sealed(b"same");
        assert_ne!(a[..BLOB_NONCE_LEN], b[..BLOB_NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn a_blob_opens_only_for_its_secret_context_and_header() {
        let blob = sealed(b"payload");
        let other = |edit: &dyn Fn(&mut BlobContext)| {
            let mut context = CONTEXT;
            edit(&mut context);
            open_blob(&SECRET, &context, AAD, &blob).err()
        };
        assert_eq!(
            other(&|c| c.intent_hash[0] ^= 1),
            Some(BlobError::Unauthentic)
        );
        assert_eq!(
            other(&|c| c.message_type += 1),
            Some(BlobError::Unauthentic)
        );
        assert_eq!(
            other(&|c| c.sender_index += 1),
            Some(BlobError::Unauthentic)
        );
        assert_eq!(
            open_blob(&[0x7B; 32], &CONTEXT, AAD, &blob).err(),
            Some(BlobError::Unauthentic)
        );
        assert_eq!(
            open_blob(&SECRET, &CONTEXT, b"edited", &blob).err(),
            Some(BlobError::Unauthentic)
        );
    }

    #[test]
    fn an_edited_or_short_blob_is_refused() {
        let blob = sealed(b"payload");
        for at in [0, BLOB_NONCE_LEN, blob.len() - 1] {
            let mut edited = blob.clone();
            edited[at] ^= 1;
            assert_eq!(
                open_blob(&SECRET, &CONTEXT, AAD, &edited).err(),
                Some(BlobError::Unauthentic),
                "byte {at}"
            );
        }
        assert_eq!(
            open_blob(
                &SECRET,
                &CONTEXT,
                AAD,
                &blob[..BLOB_NONCE_LEN + BLOB_TAG_LEN - 1]
            )
            .err(),
            Some(BlobError::Truncated)
        );
    }
}
