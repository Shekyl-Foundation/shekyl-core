// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Long-term and ephemeral identities for the `hybridXK` handshake.
//!
//! The transcript in the parent module sends these token by token. What
//! lives here is how a key is drawn and how an X25519 agreement refuses a
//! point the peer's key alone determined.

use fips203::ml_kem_768;
use fips203::traits::{KeyGen, SerDes};
use rand_core::{CryptoRngCore, OsRng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::HandshakeError;
use crate::mac1::Mac1Key;
use crate::static_public::StaticPublic;
use crate::{MAC1_LEN, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};

/// A long-term identity: both secret halves, the public bundle, and the
/// bundle's mac1 key, derived once for the daemon's check on every message 1.
///
/// The secrets wipe themselves when this is dropped (`x25519-dalek`'s and
/// `fips203`'s types do it), and nothing here hands them out.
pub struct StaticKeypair {
    pub(super) x25519: StaticSecret,
    pub(super) mlkem_dk: ml_kem_768::DecapsKey,
    pub(super) public: StaticPublic,
    mac1_key: Mac1Key,
}

impl StaticKeypair {
    /// A new identity from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Local`] when the generator fails.
    pub fn generate() -> Result<Self, HandshakeError> {
        Self::generate_from(&mut OsRng)
    }

    /// X25519 first, then ML-KEM: the order a static bundle is sent in.
    ///
    /// The pinned comparison calls this with its seeded generator. Production
    /// calls it with the operating system's generator and takes no other.
    pub(super) fn generate_from(rng: &mut impl CryptoRngCore) -> Result<Self, HandshakeError> {
        let x25519 = draw_x25519(rng)?;
        let (ek, mlkem_dk) =
            ml_kem_768::KG::try_keygen_with_rng(rng).map_err(|_| HandshakeError::Local)?;
        let public = StaticPublic::from_parts(PublicKey::from(&x25519).to_bytes(), ek.into_bytes())
            .map_err(|_| HandshakeError::Local)?;
        Ok(Self {
            x25519,
            mlkem_dk,
            mac1_key: Mac1Key::of(&public),
            public,
        })
    }

    /// The public bundle.
    pub fn public(&self) -> &StaticPublic {
        &self.public
    }

    /// The mac1 a holder of this bundle puts after a Noise message 1 (§4.3).
    ///
    /// The bytes only. The tag that can answer busy borrows the key that
    /// made it, and that key stays on this identity.
    #[must_use]
    pub fn mac1(&self, noise_message1: &[u8]) -> [u8; MAC1_LEN] {
        *self.mac1_key.mac1(noise_message1).as_bytes()
    }

    /// The tag, when `tag` is the mac1 of `noise_message1` under this
    /// identity's bundle. The tag borrows this identity's mac1 key, so a
    /// busy reply answers under the key that proved it.
    pub(super) fn mac1_verifies(
        &self,
        noise_message1: &[u8],
        tag: &[u8],
    ) -> Option<crate::mac1::Mac1Tag<'_>> {
        self.mac1_key.verify(noise_message1, tag)
    }

    /// The busy reply this identity would send for a message 1 whose Noise
    /// bytes are `noise`: its own mac1, then the busy MAC under its own key.
    #[cfg(test)]
    pub(super) fn busy_for(&self, noise: &[u8]) -> [u8; crate::BUSY_LEN] {
        self.mac1_key.mac1(noise).busy()
    }
}

/// The key file's first bytes: what it is, before its version.
pub const KEY_FILE_MAGIC: &[u8] = b"shekyl/rpc-static-key";

/// The key file's version (RT-O34: versioned, and pinned by a known answer).
pub const KEY_FILE_VERSION: u8 = 1;

/// An X25519 secret's length.
const X25519_SECRET_LEN: usize = 32;

/// An ML-KEM-768 decapsulation key's length (FIPS 203: `dk_PKE`, `ek`,
/// `H(ek)`, `z`).
const MLKEM768_DK_LEN: usize = 2400;

/// Where `ek` sits inside an ML-KEM-768 decapsulation key: after `dk_PKE`,
/// 384 bytes for each of its three polynomials.
const MLKEM768_DK_EK_AT: usize = 3 * 384;

/// A key file's length at [`KEY_FILE_VERSION`].
pub const KEY_FILE_LEN: usize = KEY_FILE_MAGIC.len() + 1 + X25519_SECRET_LEN + MLKEM768_DK_LEN;

/// A key file that does not hold a usable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    /// Not a key file: the magic or the length is wrong.
    Format,
    /// A key file of a version this build does not read.
    Version(u8),
    /// The secret halves do not form an identity: the decapsulation key
    /// fails FIPS 203's check, or its public half is not a usable bundle.
    Key,
}

impl core::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format => f.write_str("it is not an RPC channel key file"),
            Self::Version(v) => write!(
                f,
                "it is a version {v} key file, and this build reads version {KEY_FILE_VERSION}"
            ),
            Self::Key => f.write_str("its keys do not form a usable identity"),
        }
    }
}

impl std::error::Error for KeyFileError {}

impl StaticKeypair {
    /// The key file's bytes: [`KEY_FILE_MAGIC`], [`KEY_FILE_VERSION`], the
    /// X25519 secret, then the ML-KEM-768 decapsulation key, which carries
    /// its encapsulation key. The public bundle is derived again on read,
    /// so it cannot disagree with the secrets. Wiped when dropped (rule 35).
    #[must_use]
    pub fn to_key_file(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(KEY_FILE_LEN));
        out.extend_from_slice(KEY_FILE_MAGIC);
        out.push(KEY_FILE_VERSION);
        out.extend_from_slice(Zeroizing::new(self.x25519.to_bytes()).as_slice());
        out.extend_from_slice(Zeroizing::new(self.mlkem_dk.clone().into_bytes()).as_slice());
        out
    }

    /// Read a key file [`Self::to_key_file`] wrote.
    ///
    /// # Errors
    ///
    /// [`KeyFileError`]: not a key file, another version, or keys that do
    /// not form an identity.
    pub fn from_key_file(bytes: &[u8]) -> Result<Self, KeyFileError> {
        let rest = bytes
            .strip_prefix(KEY_FILE_MAGIC)
            .ok_or(KeyFileError::Format)?;
        let (&version, rest) = rest.split_first().ok_or(KeyFileError::Format)?;
        if version != KEY_FILE_VERSION {
            return Err(KeyFileError::Version(version));
        }
        if rest.len() != X25519_SECRET_LEN + MLKEM768_DK_LEN {
            return Err(KeyFileError::Format);
        }
        let (x25519, dk) = rest.split_at(X25519_SECRET_LEN);
        let mut secret = Zeroizing::new([0u8; X25519_SECRET_LEN]);
        secret.copy_from_slice(x25519);
        let x25519 = StaticSecret::from(*secret);
        let mut dk_bytes = Zeroizing::new([0u8; MLKEM768_DK_LEN]);
        dk_bytes.copy_from_slice(dk);
        let mlkem_dk =
            ml_kem_768::DecapsKey::try_from_bytes(*dk_bytes).map_err(|_| KeyFileError::Key)?;
        let mut ek = [0u8; MLKEM768_EK_LEN];
        ek.copy_from_slice(&dk_bytes[MLKEM768_DK_EK_AT..MLKEM768_DK_EK_AT + MLKEM768_EK_LEN]);
        let public = StaticPublic::from_parts(PublicKey::from(&x25519).to_bytes(), ek)
            .map_err(|_| KeyFileError::Key)?;
        Ok(Self {
            x25519,
            mlkem_dk,
            mac1_key: Mac1Key::of(&public),
            public,
        })
    }
}

/// One side's ephemeral pair for one handshake.
pub(super) struct Ephemeral {
    pub(super) x25519: StaticSecret,
    pub(super) mlkem_dk: ml_kem_768::DecapsKey,
    pub(super) x25519_public: [u8; X25519_PUBLIC_LEN],
    pub(super) mlkem_ek: [u8; MLKEM768_EK_LEN],
}

impl Ephemeral {
    /// The X25519 scalar, then ML-KEM's `d` and `z`.
    pub(super) fn generate(rng: &mut impl CryptoRngCore) -> Result<Self, HandshakeError> {
        let x25519 = draw_x25519(rng)?;
        let (ek, mlkem_dk) =
            ml_kem_768::KG::try_keygen_with_rng(rng).map_err(|_| HandshakeError::Local)?;
        Ok(Self {
            x25519_public: PublicKey::from(&x25519).to_bytes(),
            mlkem_ek: ek.into_bytes(),
            x25519,
            mlkem_dk,
        })
    }
}

/// Draw an X25519 scalar.
///
/// The secret and the public key are both [`X25519_PUBLIC_LEN`] bytes.
/// Clamping happens when the scalar is used, as `StaticSecret::from` does,
/// which is what `StaticSecret::random_from_rng` stores after it fills.
/// That fill goes through `fill_bytes` and panics when the generator fails.
/// This returns [`HandshakeError::Local`] instead.
pub(super) fn draw_x25519(rng: &mut impl CryptoRngCore) -> Result<StaticSecret, HandshakeError> {
    let mut bytes = Zeroizing::new([0u8; X25519_PUBLIC_LEN]);
    rng.try_fill_bytes(&mut bytes[..])
        .map_err(|_| HandshakeError::Local)?;
    Ok(StaticSecret::from(*bytes))
}

/// X25519, refusing a result the peer's key alone determined. `None` means
/// the peer sent a low-order point: the result is all zero whatever our
/// secret is, and it is never mixed.
pub(super) fn dh(
    secret: &StaticSecret,
    public: &[u8; X25519_PUBLIC_LEN],
) -> Option<x25519_dalek::SharedSecret> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    shared.was_contributory().then_some(shared)
}
