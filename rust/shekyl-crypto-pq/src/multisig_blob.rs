// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sealed file an Option E′ ceremony passes between members
//! (`docs/SHEKYL_MULTISIG_WIRE_FORMAT.md` §1, §4; `docs/PQC_MULTISIG.md`
//! §12.3; rulings R-4, R-9, R-10).
//!
//! Every member holds the group transport secret (the member file,
//! `derivation::derive_group_transport_secret`, derived under `salt_for`).
//! One key per group is expanded from it, and every file is sealed under
//! that key with XChaCha20-Poly1305 and a **random** 24-byte nonce:
//!
//! ```text
//! key  = HKDF-SHA-512(ikm = transport_secret, info = LABEL_MULTISIG_BLOB_KEY)
//! aad  = format_version
//! file = format_version(1) ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, aad, plaintext) ‖ tag(16)
//! ```
//!
//! **Nothing but the format version is in the clear** (R-10). A file shows
//! its size and that it is a Shekyl multisig file; which group, which
//! intent, which member and which step are inside the ciphertext, so files
//! carried by email, a messenger or a USB stick (R-9) are not linkable by
//! whoever carries or finds them. The plaintext's layout — header, body,
//! sender signature — is `shekyl-multisig`'s; this module seals and opens
//! bytes.
//!
//! Because nothing names the group, a wallet finds a file's group by **trial
//! decryption**: it opens the file under each of its groups' secrets, and
//! [`BlobError::Unauthentic`] from all of them means the file is for none of
//! them.
//!
//! The nonce is random because a nonce derived from a persisted counter
//! repeats when a wallet is restored from a backup, and a repeated nonce
//! under ChaCha20-Poly1305 leaks the XOR of two plaintexts and the Poly1305
//! key. At 192 bits a random nonce under one key does not repeat for any
//! number of files a group will ever make.
//!
//! Version `1` was the clear-header layout of slice 3 PR-A (fingerprint,
//! intent hash and sender index in the clear, the key per intent, type and
//! sender). Nothing shipped it; a file of that version is refused by name.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroizing;

/// The HKDF info label a group's blob key expands under
/// (`CRYPTO_DOMAIN_REGISTRY.tsv`, mechanism 2). The label is the whole info.
pub const LABEL_MULTISIG_BLOB_KEY: &[u8] = b"shekyl/multisig-blob-key-v1";

/// The format version this module seals, and the only one it opens. It is
/// the file's first byte and the AEAD's associated data.
pub const BLOB_FORMAT_VERSION: u8 = 2;

/// The clear-header layout of slice 3 PR-A. Never shipped; refused by name.
const CLEAR_HEADER_VERSION: u8 = 1;

/// Bytes of the format version at the front of a file.
pub const BLOB_VERSION_LEN: usize = 1;

/// Bytes of the random nonce after the version.
pub const BLOB_NONCE_LEN: usize = 24;

/// Bytes of the Poly1305 tag at the end of a file.
pub const BLOB_TAG_LEN: usize = 16;

/// Bytes of a file around its plaintext: version, nonce and tag.
pub const BLOB_OVERHEAD: usize = BLOB_VERSION_LEN + BLOB_NONCE_LEN + BLOB_TAG_LEN;

const _: () = assert!(
    sealed_len(0) == 41,
    "a file is its plaintext plus version, nonce and tag"
);

/// Bytes of a file whose plaintext is `plaintext_len` bytes.
#[must_use]
pub const fn sealed_len(plaintext_len: usize) -> usize {
    BLOB_OVERHEAD + plaintext_len
}

/// Why a file cannot be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    /// Shorter than a version, a nonce and a tag: not a sealed file.
    #[error("a sealed multisig file is at least {BLOB_OVERHEAD} bytes")]
    Truncated,
    /// Version 1, the clear-header layout. Nothing shipped it.
    #[error("a version-1 multisig file (clear header) is not accepted")]
    ClearHeaderVersion,
    /// A version this build does not know.
    #[error("unknown multisig file version {0}")]
    UnknownVersion(u8),
    /// The tag does not verify: another group's file, a wrong secret, or an
    /// edited file. One variant for all of them, so the failure is no
    /// oracle for which.
    #[error("the file does not open under this group's key")]
    Unauthentic,
    /// The AEAD refused to seal (a plaintext past the cipher's length limit).
    #[error("the file could not be sealed")]
    Seal,
}

/// Seal `plaintext` into a version-[`BLOB_FORMAT_VERSION`] file under the
/// group's key.
///
/// The plaintext copy lives in a [`Zeroizing`] buffer. Encryption overwrites
/// it, and a refusal drops that buffer wiped; only the file is returned.
///
/// # Errors
///
/// [`BlobError::Seal`] if the AEAD refuses the plaintext.
pub fn seal_blob(
    transport_secret: &[u8; 32],
    plaintext: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, BlobError> {
    let aad = [BLOB_FORMAT_VERSION];
    let key = blob_key(transport_secret);
    let mut nonce = [0u8; BLOB_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut body = Zeroizing::new(plaintext.to_vec());
    let tag = XChaCha20Poly1305::new((&*key).into())
        .encrypt_in_place_detached(&XNonce::from(nonce), &aad, body.as_mut_slice())
        .map_err(|_| BlobError::Seal)?;
    let mut file = Vec::with_capacity(sealed_len(body.len()));
    file.push(BLOB_FORMAT_VERSION);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&body);
    file.extend_from_slice(&tag);
    Ok(file)
}

/// Read a file's format version without a key: the length and the version
/// byte, which a trial decryption checks once before it tries any group.
///
/// # Errors
///
/// [`BlobError::Truncated`], [`BlobError::ClearHeaderVersion`] or
/// [`BlobError::UnknownVersion`].
pub fn check_blob_version(file: &[u8]) -> Result<(), BlobError> {
    if file.len() < BLOB_OVERHEAD {
        return Err(BlobError::Truncated);
    }
    match file[0] {
        BLOB_FORMAT_VERSION => Ok(()),
        CLEAR_HEADER_VERSION => Err(BlobError::ClearHeaderVersion),
        other => Err(BlobError::UnknownVersion(other)),
    }
}

/// Open a file [`seal_blob`] made under this group's secret. The plaintext
/// may carry a member's FROST share or signature material, so it is
/// returned wiped-on-drop.
///
/// # Errors
///
/// The refusals of [`check_blob_version`], then
/// [`BlobError::Unauthentic`] when the tag does not verify under this key.
pub fn open_blob(
    transport_secret: &[u8; 32],
    file: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BlobError> {
    check_blob_version(file)?;
    let (aad, rest) = file.split_at(BLOB_VERSION_LEN);
    let (nonce, rest) = rest.split_at(BLOB_NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - BLOB_TAG_LEN);
    let nonce: [u8; BLOB_NONCE_LEN] = nonce.try_into().expect("split at the nonce length");
    let tag: [u8; BLOB_TAG_LEN] = tag.try_into().expect("split at the tag length");
    let key = blob_key(transport_secret);
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new((&*key).into())
        .decrypt_in_place_detached(
            &XNonce::from(nonce),
            aad,
            plaintext.as_mut_slice(),
            &Tag::from(tag),
        )
        .map_err(|_| BlobError::Unauthentic)?;
    Ok(plaintext)
}

/// The group's blob key, expanded from its transport secret.
fn blob_key(transport_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha512>::new(None, transport_secret)
        .expand(LABEL_MULTISIG_BLOB_KEY, key.as_mut())
        .expect("32 bytes is within HKDF-SHA-512's output limit");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const SECRET: [u8; 32] = [0x7A; 32];

    fn sealed(plaintext: &[u8]) -> Vec<u8> {
        seal_blob(&SECRET, plaintext, &mut OsRng).unwrap()
    }

    /// The key derivation, pinned: HKDF-SHA-512 with an empty salt over the
    /// transport secret, info = the label alone. The vector was computed
    /// with Python's `hmac`/`hashlib`, independently of this crate's HKDF.
    #[test]
    fn the_blob_key_is_pinned() {
        let expected: [u8; 32] = [
            0x9a, 0x17, 0x48, 0x9d, 0x48, 0x5f, 0x21, 0xa6, 0x38, 0x33, 0x89, 0x45, 0xec, 0x24,
            0xdf, 0x73, 0xdd, 0x6b, 0x87, 0xce, 0xe3, 0x64, 0x75, 0x59, 0x12, 0xd1, 0x2d, 0xbe,
            0xb3, 0x19, 0x1f, 0x81,
        ];
        assert!(*blob_key(&SECRET) == expected);
    }

    #[test]
    fn a_sealed_file_opens_to_its_plaintext() {
        for plaintext in [&b""[..], b"x", &[0x55; 4096]] {
            let file = sealed(plaintext);
            assert_eq!(file.len(), sealed_len(plaintext.len()));
            assert_eq!(file[0], BLOB_FORMAT_VERSION);
            assert_eq!(open_blob(&SECRET, &file).unwrap().as_slice(), plaintext);
        }
    }

    /// Two seals of one plaintext share nothing after the version: the
    /// nonces differ, and no aligned 8-byte window of the two files is equal
    /// (a chance match of 8 bytes is 2^-64 per window). Not "every byte
    /// differs": two random bytes are equal one time in 256.
    #[test]
    fn every_seal_draws_a_fresh_nonce() {
        let plaintext = [0x33; 512];
        let a = sealed(&plaintext);
        let b = sealed(&plaintext);
        assert_eq!(a[0], b[0]);
        let nonce = BLOB_VERSION_LEN..BLOB_VERSION_LEN + BLOB_NONCE_LEN;
        assert_ne!(a[nonce.clone()], b[nonce]);
        for (wa, wb) in a[BLOB_VERSION_LEN..]
            .chunks_exact(8)
            .zip(b[BLOB_VERSION_LEN..].chunks_exact(8))
        {
            assert_ne!(wa, wb);
        }
    }

    #[test]
    fn a_file_opens_only_under_its_groups_secret() {
        let file = sealed(b"plaintext");
        assert_eq!(
            open_blob(&[0x7B; 32], &file).err(),
            Some(BlobError::Unauthentic)
        );
    }

    #[test]
    fn an_edited_or_short_file_is_refused() {
        let file = sealed(b"plaintext");
        for at in [
            BLOB_VERSION_LEN,
            BLOB_VERSION_LEN + BLOB_NONCE_LEN,
            file.len() - 1,
        ] {
            let mut edited = file.clone();
            edited[at] ^= 1;
            assert_eq!(
                open_blob(&SECRET, &edited).err(),
                Some(BlobError::Unauthentic),
                "byte {at}"
            );
        }
        assert_eq!(
            open_blob(&SECRET, &file[..BLOB_OVERHEAD - 1]).err(),
            Some(BlobError::Truncated)
        );
    }

    /// The version byte is read before any key: version 1 by name, any other
    /// unknown version with its value. A sealed file relabelled as another
    /// version is refused at the byte, not at the tag.
    #[test]
    fn a_version_other_than_two_is_refused_by_name() {
        let mut file = sealed(b"plaintext");
        file[0] = 1;
        assert_eq!(
            open_blob(&SECRET, &file).err(),
            Some(BlobError::ClearHeaderVersion)
        );
        file[0] = 3;
        assert_eq!(
            open_blob(&SECRET, &file).err(),
            Some(BlobError::UnknownVersion(3))
        );
        assert_eq!(check_blob_version(&file), Err(BlobError::UnknownVersion(3)));
    }
}
