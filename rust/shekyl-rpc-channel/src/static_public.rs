// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A daemon's or a client's static public bundle.
//!
//! This module does not know about mac1. The mac1 key is derived from the
//! bundle in `mac1`, and a bundle that also cached that key would import
//! `mac1` and close the cycle the handshake already has with it. The
//! daemon's [`crate::handshake::StaticKeypair`] holds the derived key.

use fips203::ml_kem_768;
use fips203::traits::SerDes;

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
    /// Parsed. The handshake encapsulates to [`Self::encaps_key`]. The
    /// bytes on the wire are [`Self::mlkem_ek`].
    encaps_key: ml_kem_768::EncapsKey,
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
        let encaps_key =
            ml_kem_768::EncapsKey::try_from_bytes(mlkem_ek).map_err(|_| InvalidStaticPublic)?;
        Ok(Self {
            x25519,
            mlkem_ek_bytes: mlkem_ek,
            encaps_key,
        })
    }

    /// The X25519 half.
    #[must_use]
    pub fn x25519(&self) -> &[u8; X25519_PUBLIC_LEN] {
        &self.x25519
    }

    /// The ML-KEM-768 half, as it travels.
    #[must_use]
    pub fn mlkem_ek(&self) -> &[u8; MLKEM768_EK_LEN] {
        &self.mlkem_ek_bytes
    }

    /// The encapsulation key, already checked by [`Self::from_parts`].
    #[must_use]
    pub(crate) fn encaps_key(&self) -> &ml_kem_768::EncapsKey {
        &self.encaps_key
    }

    /// The fingerprint an operator compares and an allowlist stores (§5).
    #[must_use]
    pub fn fingerprint(&self) -> StaticFingerprint {
        static_fingerprint(&self.x25519, &self.mlkem_ek_bytes)
    }
}
