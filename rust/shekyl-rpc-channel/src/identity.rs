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
