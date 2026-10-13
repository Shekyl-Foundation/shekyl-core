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
use crate::{static_fingerprint, StaticFingerprint, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};

/// A static public bundle: an X25519 key and an ML-KEM-768 encapsulation
/// key, the latter already checked as FIPS 203 requires.
///
/// The daemon's is what every enrolled client holds. The client's is what
/// the daemon learns in message 3 and looks up.
#[derive(Clone)]
pub struct StaticPublic {
    x25519: [u8; X25519_PUBLIC_LEN],
    mlkem_ek_bytes: [u8; MLKEM768_EK_LEN],
    pub(super) mlkem_ek: ml_kem_768::EncapsKey,
}

/// The two halves did not form a usable bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidStaticPublic;

impl core::fmt::Display for InvalidStaticPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a valid static public bundle")
    }
}

impl std::error::Error for InvalidStaticPublic {}

impl StaticPublic {
    /// Build a bundle from its two halves, checking the encapsulation key.
    ///
    /// # Errors
    ///
    /// When the encapsulation key fails FIPS 203's input check.
    pub fn from_parts(
        x25519: [u8; X25519_PUBLIC_LEN],
        mlkem_ek: [u8; MLKEM768_EK_LEN],
    ) -> Result<Self, InvalidStaticPublic> {
        let parsed =
            ml_kem_768::EncapsKey::try_from_bytes(mlkem_ek).map_err(|_| InvalidStaticPublic)?;
        Ok(Self {
            x25519,
            mlkem_ek_bytes: mlkem_ek,
            mlkem_ek: parsed,
        })
    }

    /// The X25519 half.
    pub fn x25519(&self) -> &[u8; X25519_PUBLIC_LEN] {
        &self.x25519
    }

    /// The ML-KEM-768 half, as it travels.
    pub fn mlkem_ek(&self) -> &[u8; MLKEM768_EK_LEN] {
        &self.mlkem_ek_bytes
    }

    /// The fingerprint an operator compares and an allowlist stores (§5).
    pub fn fingerprint(&self) -> StaticFingerprint {
        static_fingerprint(&self.x25519, &self.mlkem_ek_bytes)
    }
}

/// A long-term identity: both secret halves and the public bundle.
///
/// The secrets wipe themselves when this is dropped (`x25519-dalek`'s and
/// `fips203`'s types do it), and nothing here hands them out.
pub struct StaticKeypair {
    pub(super) x25519: StaticSecret,
    pub(super) mlkem_dk: ml_kem_768::DecapsKey,
    pub(super) public: StaticPublic,
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
            public,
        })
    }

    /// The public bundle.
    pub fn public(&self) -> &StaticPublic {
        &self.public
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
