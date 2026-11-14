// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The member file: what the dealer gives one member of an Option E′ group
//! (`docs/PQC_MULTISIG.md` §6.6).
//!
//! It holds everything that member needs to receive and to sign:
//!
//! - the group's address payload (its public state and identity);
//! - the member's index;
//! - `b`, the group-plaintext spend scalar every member holds (scan,
//!   balance and key images are local);
//! - the member's share of `y_group` and every member's verification share;
//! - the group hybrid KEM secret (every member holds it; the output's one
//!   `0x06` ciphertext is to it);
//! - the member's own hybrid KEM secret (its per-output signing keys come
//!   from the `0x0D` ciphertext to it);
//! - the group transport secret, which keys the ceremony files (slice 3);
//! - the member's long-term envelope secret, and every member's envelope
//!   public key: a ceremony file's sender signs it with the first, and every
//!   other member checks it with the second (R-6).
//!
//! This module defines the plaintext serialization, versioned. Keeping the
//! file encrypted at rest is the wallet's job (slice 4), as it is for every
//! other key file. Every secret field is `Zeroizing`, and `Debug` prints no
//! secret.
//!
//! Byte validity of the scalars and points (canonical, on the curve) is
//! checked where they are used — the scanner, and the FROST key share
//! (`shekyl_fcmp::frost_sal::threshold_keys`, which also turns the 0-based
//! `member_index` into the 1-based FROST participant) — so this crate does
//! no curve arithmetic, as `shekyl-address` does none.
//!
//! Layout, version 2:
//!
//! ```text
//! magic "SKMF" ‖ version(2) ‖ u32_le(len) ‖ address payload(len) ‖
//! member_index(1) ‖ b(32) ‖ y_share(32) ‖ verification_share × n (32 each) ‖
//! group_kem_secret(HYBRID_KEM_SECRET_LEN) ‖ member_kem_secret(HYBRID_KEM_SECRET_LEN) ‖
//! transport_secret(32) ‖ envelope_secret(ENVELOPE_SECRET_LEN) ‖
//! envelope_public_key × n (HybridPublicKey::CANONICAL_LEN each)
//! ```
//!
//! Version 1 had no envelope keys. Pre-genesis, it is refused, not migrated.

use shekyl_address::multisig_address::{MultisigAddressError, MultisigAddressPayload};
use shekyl_crypto_pq::multisig_envelope::{MultisigEnvelopeSecret, ENVELOPE_SECRET_LEN};
use shekyl_crypto_pq::signature::HybridPublicKey;
use zeroize::Zeroizing;

/// The file's first four bytes.
pub const MEMBER_FILE_MAGIC: [u8; 4] = *b"SKMF";
/// The layout version this module writes and reads.
pub const MEMBER_FILE_VERSION: u8 = 2;
/// X25519 secret scalar length. Pinned, in the test build, to the classical
/// half of the hybrid KEM (`shekyl_crypto_pq::kem::X25519_KEM_CT_LEN`: an
/// X25519 scalar and its Montgomery u-coordinate are the same width).
const X25519_SECRET_LEN: usize = 32;
/// ML-KEM-768 decapsulation key length (FIPS 203). Pinned to
/// `shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN` in the test build.
const ML_KEM_768_DK_LEN: usize = 2400;
/// A hybrid KEM secret: the X25519 scalar, then the ML-KEM-768 decapsulation key.
pub const HYBRID_KEM_SECRET_LEN: usize = X25519_SECRET_LEN + ML_KEM_768_DK_LEN;
/// Bytes of a scalar, a point, or the transport secret.
const FIELD_LEN: usize = 32;

#[cfg(test)]
const _: () = {
    assert!(X25519_SECRET_LEN == shekyl_crypto_pq::kem::X25519_KEM_CT_LEN);
    assert!(ML_KEM_768_DK_LEN == shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN);
};

/// Why a member file cannot be built or read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemberFileError {
    #[error("not a member file (bad magic)")]
    Magic,
    #[error("unsupported member file version {0}")]
    UnsupportedVersion(u8),
    #[error("member file truncated")]
    Truncated,
    #[error("member file has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("address payload: {0}")]
    Address(String),
    #[error("member index {index} is not below the group size {n}")]
    MemberIndex { index: u8, n: u8 },
    #[error("expected {expected} verification shares, got {got}")]
    VerificationShareCount { expected: u8, got: usize },
    #[error("a hybrid KEM secret must be {HYBRID_KEM_SECRET_LEN} bytes, got {0}")]
    KemSecretLength(usize),
    #[error("expected {expected} envelope public keys, got {got}")]
    EnvelopeKeyCount { expected: u8, got: usize },
    #[error("member {member}'s envelope public key is malformed")]
    EnvelopeKey { member: u8 },
    #[error("two members have the same envelope public key")]
    DuplicateEnvelopeKeys,
    #[error("this member's envelope secret does not match its public key in the list")]
    EnvelopeKeyMismatch,
}

impl From<MultisigAddressError> for MemberFileError {
    fn from(err: MultisigAddressError) -> Self {
        Self::Address(err.to_string())
    }
}

/// One member's key file. Built by the dealer ([`MemberFile::new`]) or read
/// back ([`MemberFile::from_bytes`]); both check every length and that the
/// index names a member.
pub struct MemberFile {
    address: MultisigAddressPayload,
    member_index: u8,
    b: Zeroizing<[u8; FIELD_LEN]>,
    y_share: Zeroizing<[u8; FIELD_LEN]>,
    verification_shares: Vec<[u8; FIELD_LEN]>,
    group_kem_secret: Zeroizing<Vec<u8>>,
    member_kem_secret: Zeroizing<Vec<u8>>,
    transport_secret: Zeroizing<[u8; FIELD_LEN]>,
    envelope_secret: MultisigEnvelopeSecret,
    envelope_public_keys: Vec<HybridPublicKey>,
}

impl std::fmt::Debug for MemberFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberFile")
            .field("n_total", &self.address.n_total())
            .field("m_required", &self.address.m_required())
            .field("member_index", &self.member_index)
            .field("secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// The secret material a member file carries, as the dealer hands it over.
pub struct MemberSecrets {
    /// `b`, the group-plaintext spend scalar.
    pub b: Zeroizing<[u8; FIELD_LEN]>,
    /// This member's share of `y_group`.
    pub y_share: Zeroizing<[u8; FIELD_LEN]>,
    /// The group hybrid KEM secret.
    pub group_kem_secret: Zeroizing<Vec<u8>>,
    /// This member's own hybrid KEM secret.
    pub member_kem_secret: Zeroizing<Vec<u8>>,
    /// The group transport secret. The dealer derives it and passes the
    /// bytes in; this file stores them and does not derive them.
    pub transport_secret: Zeroizing<[u8; FIELD_LEN]>,
    /// This member's long-term envelope secret, minted by the dealer
    /// (`shekyl_crypto_pq::multisig_envelope::mint_multisig_envelope_keypair`).
    pub envelope_secret: MultisigEnvelopeSecret,
}

impl MemberFile {
    /// Assemble a member file.
    ///
    /// # Errors
    ///
    /// [`MemberFileError::MemberIndex`] unless `member_index < n`;
    /// [`MemberFileError::VerificationShareCount`] unless there are `n`
    /// verification shares; [`MemberFileError::KemSecretLength`] for a KEM
    /// secret of the wrong length; [`MemberFileError::EnvelopeKeyCount`]
    /// unless there are `n` envelope public keys;
    /// [`MemberFileError::DuplicateEnvelopeKeys`] if two are equal (a file
    /// could not then say which of them sent it); and
    /// [`MemberFileError::EnvelopeKeyMismatch`] unless this member's
    /// envelope secret is the one behind its own public key, as the loader
    /// checks the FROST share against its verification share.
    pub fn new(
        address: MultisigAddressPayload,
        member_index: u8,
        verification_shares: Vec<[u8; FIELD_LEN]>,
        envelope_public_keys: Vec<HybridPublicKey>,
        secrets: MemberSecrets,
    ) -> Result<Self, MemberFileError> {
        let n = address.n_total();
        if member_index >= n {
            return Err(MemberFileError::MemberIndex {
                index: member_index,
                n,
            });
        }
        if verification_shares.len() != usize::from(n) {
            return Err(MemberFileError::VerificationShareCount {
                expected: n,
                got: verification_shares.len(),
            });
        }
        for secret in [&secrets.group_kem_secret, &secrets.member_kem_secret] {
            if secret.len() != HYBRID_KEM_SECRET_LEN {
                return Err(MemberFileError::KemSecretLength(secret.len()));
            }
        }
        if envelope_public_keys.len() != usize::from(n) {
            return Err(MemberFileError::EnvelopeKeyCount {
                expected: n,
                got: envelope_public_keys.len(),
            });
        }
        let mut canonical = Vec::with_capacity(envelope_public_keys.len());
        for (member, key) in (0u8..).zip(&envelope_public_keys) {
            let bytes = key
                .to_canonical_bytes()
                .map_err(|_| MemberFileError::EnvelopeKey { member })?;
            if canonical.contains(&bytes) {
                return Err(MemberFileError::DuplicateEnvelopeKeys);
            }
            canonical.push(bytes);
        }
        let own = secrets
            .envelope_secret
            .public_key()
            .and_then(|key| key.to_canonical_bytes())
            .map_err(|_| MemberFileError::EnvelopeKeyMismatch)?;
        if own != canonical[usize::from(member_index)] {
            return Err(MemberFileError::EnvelopeKeyMismatch);
        }
        Ok(Self {
            address,
            member_index,
            b: secrets.b,
            y_share: secrets.y_share,
            verification_shares,
            group_kem_secret: secrets.group_kem_secret,
            member_kem_secret: secrets.member_kem_secret,
            transport_secret: secrets.transport_secret,
            envelope_secret: secrets.envelope_secret,
            envelope_public_keys,
        })
    }

    /// The group's address payload.
    #[must_use]
    pub fn address(&self) -> &MultisigAddressPayload {
        &self.address
    }

    /// This member's index, `0..n`.
    #[must_use]
    pub const fn member_index(&self) -> u8 {
        self.member_index
    }

    /// `b`.
    #[must_use]
    pub fn b(&self) -> &[u8; FIELD_LEN] {
        &self.b
    }

    /// This member's share of `y_group`.
    #[must_use]
    pub fn y_share(&self) -> &[u8; FIELD_LEN] {
        &self.y_share
    }

    /// Every member's verification share, member order.
    #[must_use]
    pub fn verification_shares(&self) -> &[[u8; FIELD_LEN]] {
        &self.verification_shares
    }

    /// The group hybrid KEM secret (`X25519 ‖ ML-KEM-768 dk`).
    #[must_use]
    pub fn group_kem_secret(&self) -> &[u8] {
        &self.group_kem_secret
    }

    /// This member's own hybrid KEM secret (`X25519 ‖ ML-KEM-768 dk`).
    #[must_use]
    pub fn member_kem_secret(&self) -> &[u8] {
        &self.member_kem_secret
    }

    /// The group transport secret.
    #[must_use]
    pub fn transport_secret(&self) -> &[u8; FIELD_LEN] {
        &self.transport_secret
    }

    /// This member's envelope secret.
    #[must_use]
    pub fn envelope_secret(&self) -> &MultisigEnvelopeSecret {
        &self.envelope_secret
    }

    /// Every member's envelope public key, member order.
    #[must_use]
    pub fn envelope_public_keys(&self) -> &[HybridPublicKey] {
        &self.envelope_public_keys
    }

    /// The version 2 bytes. Secret-bearing, so returned `Zeroizing`.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let address = self.address.to_canonical_bytes();
        let address_len = u32::try_from(address.len()).expect("an address payload is a few KiB");
        let mut out = Zeroizing::new(Vec::with_capacity(
            4 + 1
                + 4
                + address.len()
                + 1
                + FIELD_LEN * (3 + self.verification_shares.len())
                + 2 * HYBRID_KEM_SECRET_LEN
                + ENVELOPE_SECRET_LEN
                + HybridPublicKey::CANONICAL_LEN * self.envelope_public_keys.len(),
        ));
        out.extend_from_slice(&MEMBER_FILE_MAGIC);
        out.push(MEMBER_FILE_VERSION);
        out.extend_from_slice(&address_len.to_le_bytes());
        out.extend_from_slice(&address);
        out.push(self.member_index);
        out.extend_from_slice(self.b.as_ref());
        out.extend_from_slice(self.y_share.as_ref());
        for share in &self.verification_shares {
            out.extend_from_slice(share);
        }
        out.extend_from_slice(&self.group_kem_secret);
        out.extend_from_slice(&self.member_kem_secret);
        out.extend_from_slice(self.transport_secret.as_ref());
        out.extend_from_slice(self.envelope_secret.as_bytes());
        for key in &self.envelope_public_keys {
            out.extend_from_slice(
                &key.to_canonical_bytes()
                    .expect("new() checked every envelope public key encodes"),
            );
        }
        out
    }

    /// Read a version 2 member file.
    ///
    /// # Errors
    ///
    /// A [`MemberFileError`] naming the first defect: magic, version,
    /// truncation, the address payload's own refusal, the index, or trailing
    /// bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemberFileError> {
        let mut r = Reader(bytes);
        if r.take(4)? != MEMBER_FILE_MAGIC {
            return Err(MemberFileError::Magic);
        }
        let version = r.byte()?;
        if version != MEMBER_FILE_VERSION {
            return Err(MemberFileError::UnsupportedVersion(version));
        }
        let address_len: [u8; 4] = r.take(4)?.try_into().expect("four bytes");
        let address_len = usize::try_from(u32::from_le_bytes(address_len))
            .map_err(|_| MemberFileError::Truncated)?;
        let address = MultisigAddressPayload::from_canonical_bytes(r.take(address_len)?)?;
        let member_index = r.byte()?;
        let b = Zeroizing::new(r.field()?);
        let y_share = Zeroizing::new(r.field()?);
        let verification_shares = (0..address.n_total())
            .map(|_| r.field())
            .collect::<Result<Vec<_>, _>>()?;
        let group_kem_secret = Zeroizing::new(r.take(HYBRID_KEM_SECRET_LEN)?.to_vec());
        let member_kem_secret = Zeroizing::new(r.take(HYBRID_KEM_SECRET_LEN)?.to_vec());
        let transport_secret = Zeroizing::new(r.field()?);
        let envelope_secret = MultisigEnvelopeSecret::from_bytes(Zeroizing::new(
            r.take(ENVELOPE_SECRET_LEN)?
                .try_into()
                .expect("ENVELOPE_SECRET_LEN bytes"),
        ));
        let envelope_public_keys = (0..address.n_total())
            .map(|member| {
                HybridPublicKey::from_canonical_bytes(r.take(HybridPublicKey::CANONICAL_LEN)?)
                    .map_err(|_| MemberFileError::EnvelopeKey { member })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !r.0.is_empty() {
            return Err(MemberFileError::TrailingBytes(r.0.len()));
        }
        Self::new(
            address,
            member_index,
            verification_shares,
            envelope_public_keys,
            MemberSecrets {
                b,
                y_share,
                group_kem_secret,
                member_kem_secret,
                transport_secret,
                envelope_secret,
            },
        )
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MemberFileError> {
        if self.0.len() < n {
            return Err(MemberFileError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, MemberFileError> {
        Ok(self.take(1)?[0])
    }

    fn field(&mut self) -> Result<[u8; FIELD_LEN], MemberFileError> {
        Ok(self.take(FIELD_LEN)?.try_into().expect("FIELD_LEN bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use shekyl_address::multisig_address::HYBRID_KEM_PUBKEY_LEN;
    use shekyl_address::Network;
    use shekyl_crypto_pq::multisig_envelope::mint_multisig_envelope_keypair;

    /// Every member's envelope keypair, as the dealer mints them.
    fn envelope_keys(n: u8) -> Vec<(HybridPublicKey, MultisigEnvelopeSecret)> {
        (0..n)
            .map(|_| mint_multisig_envelope_keypair(&mut OsRng).unwrap())
            .collect()
    }

    fn address(n: u8) -> MultisigAddressPayload {
        MultisigAddressPayload::new(
            Network::Testnet,
            n,
            2,
            [0xB1; 32],
            [0x71; 32],
            vec![0x40; HYBRID_KEM_PUBKEY_LEN],
            (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
        )
        .unwrap()
    }

    fn secrets(envelope_secret: MultisigEnvelopeSecret) -> MemberSecrets {
        MemberSecrets {
            b: Zeroizing::new([0x0B; 32]),
            y_share: Zeroizing::new([0x0F; 32]),
            group_kem_secret: Zeroizing::new(vec![0x6A; HYBRID_KEM_SECRET_LEN]),
            member_kem_secret: Zeroizing::new(vec![0x6B; HYBRID_KEM_SECRET_LEN]),
            transport_secret: Zeroizing::new([0x5E; 32]),
            envelope_secret,
        }
    }

    /// Member `index`'s file in a new `n`-member group.
    fn file(n: u8, index: u8) -> MemberFile {
        let mut keys = envelope_keys(n);
        let publics = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let (_, own) = keys.swap_remove(usize::from(index));
        MemberFile::new(
            address(n),
            index,
            (0..n).map(|i| [0x50 + i; 32]).collect(),
            publics,
            secrets(own),
        )
        .unwrap()
    }

    fn canonical(keys: &[HybridPublicKey]) -> Vec<Vec<u8>> {
        keys.iter()
            .map(|k| k.to_canonical_bytes().unwrap())
            .collect()
    }

    #[test]
    fn member_file_round_trips() {
        for (n, index) in [(2u8, 0u8), (3, 2), (5, 4)] {
            let original = file(n, index);
            let bytes = original.to_bytes();
            let read = MemberFile::from_bytes(&bytes).unwrap();
            assert_eq!(read.address(), original.address());
            assert_eq!(read.member_index(), index);
            assert_eq!(read.b(), original.b());
            assert_eq!(read.y_share(), original.y_share());
            assert_eq!(read.verification_shares(), original.verification_shares());
            assert_eq!(read.group_kem_secret(), original.group_kem_secret());
            assert_eq!(read.member_kem_secret(), original.member_kem_secret());
            assert_eq!(read.transport_secret(), original.transport_secret());
            assert_eq!(
                read.envelope_secret().as_bytes(),
                original.envelope_secret().as_bytes()
            );
            assert_eq!(
                canonical(read.envelope_public_keys()),
                canonical(original.envelope_public_keys())
            );
            assert_eq!(*read.to_bytes(), *bytes);
        }
    }

    #[test]
    fn a_damaged_member_file_is_refused_by_name() {
        let bytes = file(3, 1).to_bytes().to_vec();
        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert_eq!(
            MemberFile::from_bytes(&magic).unwrap_err(),
            MemberFileError::Magic
        );
        // Version 1 had no envelope keys: refused, not migrated.
        for v in [1, 3] {
            let mut version = bytes.clone();
            version[4] = v;
            assert_eq!(
                MemberFile::from_bytes(&version).unwrap_err(),
                MemberFileError::UnsupportedVersion(v)
            );
        }
        assert_eq!(
            MemberFile::from_bytes(&bytes[..bytes.len() - 1]).unwrap_err(),
            MemberFileError::Truncated
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            MemberFile::from_bytes(&long).unwrap_err(),
            MemberFileError::TrailingBytes(1)
        );
        let index_at = 4 + 1 + 4 + MultisigAddressPayload::canonical_len_for(3);
        let mut index = bytes.clone();
        index[index_at] = 3;
        assert_eq!(
            MemberFile::from_bytes(&index).unwrap_err(),
            MemberFileError::MemberIndex { index: 3, n: 3 }
        );
        // The last envelope public key with its version byte edited.
        let mut key = bytes.clone();
        let last_key_at = key.len() - HybridPublicKey::CANONICAL_LEN;
        key[last_key_at] ^= 0xFF;
        assert_eq!(
            MemberFile::from_bytes(&key).unwrap_err(),
            MemberFileError::EnvelopeKey { member: 2 }
        );
    }

    /// The dealer's list must hold `n` distinct keys, and the member's own
    /// secret must be the one behind its own slot.
    #[test]
    fn the_envelope_keys_are_checked_on_assembly() {
        let build = |publics: Vec<HybridPublicKey>, own: MultisigEnvelopeSecret| {
            MemberFile::new(
                address(3),
                1,
                (0..3).map(|i| [0x50 + i; 32]).collect(),
                publics,
                secrets(own),
            )
            .err()
        };
        let mut keys = envelope_keys(3);
        let publics: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();

        assert_eq!(
            build(publics[..2].to_vec(), keys.swap_remove(1).1),
            Some(MemberFileError::EnvelopeKeyCount {
                expected: 3,
                got: 2
            })
        );

        let keys = envelope_keys(3);
        let mut repeated: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        repeated[2] = repeated[0].clone();
        let (_, own) = keys.into_iter().nth(1).unwrap();
        assert_eq!(
            build(repeated, own),
            Some(MemberFileError::DuplicateEnvelopeKeys)
        );

        // Member 1's file holding member 0's secret.
        let keys = envelope_keys(3);
        let publics: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let (_, someone_else) = keys.into_iter().next().unwrap();
        assert_eq!(
            build(publics, someone_else),
            Some(MemberFileError::EnvelopeKeyMismatch)
        );
    }

    #[test]
    fn debug_prints_no_secret() {
        let shown = format!("{:?}", file(2, 0));
        assert!(shown.contains("REDACTED"));
        assert!(!shown.contains("11, 11"), "{shown}");
    }
}
