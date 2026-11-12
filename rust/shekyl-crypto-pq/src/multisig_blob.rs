// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The AEAD for an Option E′ ceremony blob (`docs/PQC_MULTISIG.md` §12.3;
//! `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md` §4; Round 0 ruling R-4).
//!
//! Every member holds the group transport secret (the member file,
//! `derivation::derive_group_transport_secret`, derived under `salt_for`).
//! A blob is sealed under a key expanded from that secret for one
//! [`BlobHeader`], with XChaCha20-Poly1305 and a **random** 24-byte nonce
//! carried at the front of the sealed bytes:
//!
//! ```text
//! key    = HKDF-SHA-512(ikm = transport_secret)
//!            .expand(LABEL_MULTISIG_BLOB_KEY ‖ intent_hash ‖ u8(message_type) ‖ u8(sender_index), 32)
//! aad    = version ‖ address_fingerprint ‖ intent_hash ‖ u8(sender_index)
//! sealed = nonce(24) ‖ XChaCha20-Poly1305(key, nonce, aad, payload) ‖ tag(16)
//! ```
//!
//! The associated data is those four fields and no others. They are known
//! before the ciphertext exists, and they are the envelope's first
//! [`BLOB_AAD_LEN`] bytes (`MultisigEnvelope::to_bytes`). The message type
//! stays out of the associated data: it lives inside the payload so a
//! relay cannot see the role (SS12.5), and the key binds it instead. The
//! sender's signature stays out too. Its preimage is the sealed payload, so
//! putting the signature in the associated data would make sealing and
//! signing depend on each other. When that signer lands it authenticates
//! the ciphertext on its own; it does not re-enter this AEAD.
//!
//! The nonce is random because a nonce derived from a persisted counter
//! repeats when a wallet is restored from a backup, and a repeated nonce
//! under ChaCha20-Poly1305 leaks the XOR of two payloads and the Poly1305
//! key. At 192 bits a random nonce does not repeat. A ceremony's counter
//! still orders blobs and refuses replays; it is not an input to this AEAD.

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

/// Bytes of an intent hash, in the key and in the associated data.
pub const INTENT_HASH_LEN: usize = 32;

/// Bytes of a group's address fingerprint, in the associated data.
pub const ADDRESS_FINGERPRINT_LEN: usize = 32;

/// Bytes of the envelope version in the associated data.
const VERSION_LEN: usize = 1;

/// Bytes of the sender index, in the key and in the associated data.
const SENDER_INDEX_LEN: usize = 1;

/// Bytes of the message type in the key. It is not associated data.
const MESSAGE_TYPE_LEN: usize = 1;

const FINGERPRINT_AT: usize = VERSION_LEN;
const INTENT_AT: usize = FINGERPRINT_AT + ADDRESS_FINGERPRINT_LEN;
const SENDER_AT: usize = INTENT_AT + INTENT_HASH_LEN;

/// Bytes of the associated data: the envelope prefix through `sender_index`.
///
/// `SHEKYL_MULTISIG_WIRE_FORMAT.md` §4.3 and `PQC_MULTISIG.md` §12.3 both
/// state this width as 66.
pub const BLOB_AAD_LEN: usize = SENDER_AT + SENDER_INDEX_LEN;

const _: () = assert!(
    BLOB_AAD_LEN == 66,
    "the wire format states a 66-byte header"
);
const _: () = assert!(
    sealed_len(0) == 40,
    "a sealed blob is plaintext plus nonce and tag"
);

/// Bytes of a sealed blob whose plaintext is `payload_len` bytes.
#[must_use]
pub const fn sealed_len(payload_len: usize) -> usize {
    BLOB_NONCE_LEN + payload_len + BLOB_TAG_LEN
}

/// Who a blob is sealed for. The key and the associated data are both
/// functions of this value, so a caller cannot expand the key for one
/// header and bind another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobHeader<'a> {
    /// The envelope version byte.
    pub version: u8,
    /// The group's address fingerprint.
    pub address_fingerprint: &'a [u8; ADDRESS_FINGERPRINT_LEN],
    /// The intent this blob belongs to.
    pub intent_hash: &'a [u8; INTENT_HASH_LEN],
    /// The ceremony message type. Inside the payload, and a key field.
    pub message_type: u8,
    /// The sending member's index.
    pub sender_index: u8,
}

impl BlobHeader<'_> {
    /// The key's domain: intent, message type, sender. The message type is
    /// not on the envelope in the clear.
    #[must_use]
    pub fn context(&self) -> BlobContext {
        BlobContext {
            intent_hash: *self.intent_hash,
            message_type: self.message_type,
            sender_index: self.sender_index,
        }
    }

    /// The associated data, which is the envelope's first [`BLOB_AAD_LEN`]
    /// bytes: version, address fingerprint, intent hash, sender index.
    #[must_use]
    pub fn associated_data(&self) -> [u8; BLOB_AAD_LEN] {
        let mut aad = [0u8; BLOB_AAD_LEN];
        aad[0] = self.version;
        aad[FINGERPRINT_AT..INTENT_AT].copy_from_slice(self.address_fingerprint);
        aad[INTENT_AT..SENDER_AT].copy_from_slice(self.intent_hash);
        aad[SENDER_AT] = self.sender_index;
        aad
    }
}

/// The triple the blob key expands for. A payload sealed for one intent,
/// message type or sender does not open as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobContext {
    /// The intent the ceremony is for.
    pub intent_hash: [u8; INTENT_HASH_LEN],
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
    /// The tag does not verify: wrong secret, wrong header, or an edited
    /// ciphertext. One variant for all of them, so the failure is no oracle
    /// for which.
    #[error("the blob does not open under this group's key for this header")]
    Unauthentic,
    /// The AEAD refused to seal (a payload past the cipher's length limit).
    #[error("the blob could not be sealed")]
    Seal,
}

/// Seal `payload` for `header`.
///
/// The plaintext copy lives in a [`Zeroizing`] buffer. Encryption overwrites
/// it, and a refusal drops that buffer wiped; only the ciphertext is returned.
///
/// # Errors
///
/// [`BlobError::Seal`] if the AEAD refuses the payload.
pub fn seal_blob(
    transport_secret: &[u8; 32],
    header: &BlobHeader<'_>,
    payload: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, BlobError> {
    let aad = header.associated_data();
    let key = blob_key(transport_secret, &header.context());
    let mut nonce = [0u8; BLOB_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut body = Zeroizing::new(payload.to_vec());
    let tag = XChaCha20Poly1305::new((&*key).into())
        .encrypt_in_place_detached(&XNonce::from(nonce), &aad, body.as_mut_slice())
        .map_err(|_| BlobError::Seal)?;
    let mut sealed = Vec::with_capacity(sealed_len(body.len()));
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&body);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open a blob [`seal_blob`] made for `header`. The plaintext may carry a
/// member's FROST share or signature material, so it is returned wiped-on-drop.
///
/// # Errors
///
/// [`BlobError::Truncated`] for bytes too short to be a sealed blob;
/// [`BlobError::Unauthentic`] when the tag does not verify.
pub fn open_blob(
    transport_secret: &[u8; 32],
    header: &BlobHeader<'_>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BlobError> {
    if sealed.len() < BLOB_NONCE_LEN + BLOB_TAG_LEN {
        return Err(BlobError::Truncated);
    }
    let (nonce, rest) = sealed.split_at(BLOB_NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - BLOB_TAG_LEN);
    let nonce: [u8; BLOB_NONCE_LEN] = nonce.try_into().expect("split at the nonce length");
    let tag: [u8; BLOB_TAG_LEN] = tag.try_into().expect("split at the tag length");
    let key = blob_key(transport_secret, &header.context());
    let mut payload = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new((&*key).into())
        .decrypt_in_place_detached(
            &XNonce::from(nonce),
            &header.associated_data(),
            payload.as_mut_slice(),
            &Tag::from(tag),
        )
        .map_err(|_| BlobError::Unauthentic)?;
    Ok(payload)
}

/// The blob key for `context`, expanded from the transport secret.
fn blob_key(transport_secret: &[u8; 32], context: &BlobContext) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(
        LABEL_MULTISIG_BLOB_KEY.len() + INTENT_HASH_LEN + MESSAGE_TYPE_LEN + SENDER_INDEX_LEN,
    );
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
    const FINGERPRINT: [u8; ADDRESS_FINGERPRINT_LEN] = [0x22; ADDRESS_FINGERPRINT_LEN];
    const INTENT: [u8; INTENT_HASH_LEN] = [0x11; INTENT_HASH_LEN];

    fn header() -> BlobHeader<'static> {
        BlobHeader {
            version: 1,
            address_fingerprint: &FINGERPRINT,
            intent_hash: &INTENT,
            message_type: 3,
            sender_index: 1,
        }
    }

    fn sealed(payload: &[u8]) -> Vec<u8> {
        seal_blob(&SECRET, &header(), payload, &mut OsRng).unwrap()
    }

    /// The key derivation, pinned: HKDF-SHA-512 with an empty salt over the
    /// transport secret, info = label ‖ intent ‖ type ‖ sender. The vector
    /// was computed with Python's `hmac`/`hashlib`, independently of this
    /// crate's HKDF. The header's associated data is not an input to the key.
    #[test]
    fn the_blob_key_is_pinned() {
        let expected: [u8; 32] = [
            0xf5, 0x07, 0xd7, 0x74, 0xbe, 0xfd, 0x95, 0x43, 0xeb, 0x9f, 0x06, 0xfa, 0x92, 0xc6,
            0x8e, 0x83, 0xb0, 0x73, 0x20, 0x58, 0x83, 0xa3, 0x51, 0xee, 0x8b, 0xfb, 0xe5, 0x8c,
            0xd2, 0x5c, 0xe9, 0xaf,
        ];
        assert!(*blob_key(&SECRET, &header().context()) == expected);
    }

    /// The associated data is the envelope prefix through the sender index,
    /// and the message type is not in it.
    #[test]
    fn the_associated_data_is_the_envelope_prefix() {
        let aad = header().associated_data();
        assert_eq!(aad.len(), BLOB_AAD_LEN);
        assert_eq!(aad[0], 1);
        assert_eq!(&aad[FINGERPRINT_AT..INTENT_AT], &FINGERPRINT);
        assert_eq!(&aad[INTENT_AT..SENDER_AT], &INTENT);
        assert_eq!(aad[SENDER_AT], 1);
        let mut other = header();
        other.message_type = header().message_type.wrapping_add(1);
        assert_eq!(other.associated_data(), aad);
        assert_ne!(other.context(), header().context());
    }

    #[test]
    fn a_sealed_blob_opens_to_its_payload() {
        for payload in [&b""[..], b"x", &[0x55; 4096]] {
            let blob = sealed(payload);
            assert_eq!(blob.len(), sealed_len(payload.len()));
            assert_eq!(
                open_blob(&SECRET, &header(), &blob).unwrap().as_slice(),
                payload
            );
        }
    }

    /// Two seals of one payload under one header differ: the nonce is
    /// random, not a function of anything a restored wallet repeats.
    #[test]
    fn every_seal_draws_a_fresh_nonce() {
        let a = sealed(b"same");
        let b = sealed(b"same");
        assert_ne!(a[..BLOB_NONCE_LEN], b[..BLOB_NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn a_blob_opens_only_for_its_secret_and_header() {
        let blob = sealed(b"payload");
        let other_fingerprint = [0x23; ADDRESS_FINGERPRINT_LEN];
        let other_intent = [0x12; INTENT_HASH_LEN];
        let refused = |header: BlobHeader<'_>| {
            assert_eq!(
                open_blob(&SECRET, &header, &blob).err(),
                Some(BlobError::Unauthentic)
            );
        };
        let mut edited = header();
        edited.version = 2;
        refused(edited);
        edited = header();
        edited.address_fingerprint = &other_fingerprint;
        refused(edited);
        edited = header();
        edited.intent_hash = &other_intent;
        refused(edited);
        edited = header();
        edited.message_type = edited.message_type.wrapping_add(1);
        refused(edited);
        edited = header();
        edited.sender_index = edited.sender_index.wrapping_add(1);
        refused(edited);
        assert_eq!(
            open_blob(&[0x7B; 32], &header(), &blob).err(),
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
                open_blob(&SECRET, &header(), &edited).err(),
                Some(BlobError::Unauthentic),
                "byte {at}"
            );
        }
        assert_eq!(
            open_blob(
                &SECRET,
                &header(),
                &blob[..BLOB_NONCE_LEN + BLOB_TAG_LEN - 1]
            )
            .err(),
            Some(BlobError::Truncated)
        );
    }
}
