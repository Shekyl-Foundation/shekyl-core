// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! View pair types for scanning: public spend key + private view key + KEM keys.

use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};

use shekyl_crypto_pq::kem::MlKemDecapsKey;

/// An error while working with a ViewPair.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ViewPairError {
    /// The spend key has torsion and is of questionable spendability.
    #[error("torsioned spend key")]
    TorsionedSpendKey,
    /// ML-KEM-768 decapsulation key bytes failed parse/validation.
    #[error("invalid ML-KEM decapsulation key")]
    InvalidMlKemDecapKey,
}

/// The pair of keys necessary to scan transactions.
///
/// Composed of the public spend key, the private view key, and the hybrid
/// KEM secret keys (X25519 + ML-KEM-768) needed for PQC output recovery.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ViewPair {
    spend: EdwardsPoint,
    pub(crate) view: Zeroizing<Scalar>,
    /// X25519 secret key for ECDH after FA-6 pre-filter match.
    pub(crate) x25519_sk: Zeroizing<[u8; 32]>,
    /// ML-KEM-768 decapsulation key (2400 bytes).
    pub(crate) ml_kem_dk: Zeroizing<Vec<u8>>,
    /// Parsed once at construction for FA-6 universal-decap scan hot path.
    parsed_ml_kem_dk: MlKemDecapsKey,
}

impl PartialEq for ViewPair {
    fn eq(&self, other: &Self) -> bool {
        self.spend == other.spend && *self.view == *other.view
    }
}
impl Eq for ViewPair {}

impl Clone for ViewPair {
    fn clone(&self) -> Self {
        Self {
            spend: self.spend,
            view: self.view.clone(),
            x25519_sk: self.x25519_sk.clone(),
            ml_kem_dk: self.ml_kem_dk.clone(),
            // Re-parse from canonical bytes; `MlKemDecapsKey` is intentionally not `Clone`.
            parsed_ml_kem_dk: MlKemDecapsKey::from_bytes(&self.ml_kem_dk)
                .expect("ml_kem_dk was valid at construction"),
        }
    }
}

impl ViewPair {
    /// Create a new ViewPair with KEM keys for hybrid PQC scanning.
    pub fn new(
        spend: EdwardsPoint,
        view: Zeroizing<Scalar>,
        x25519_sk: Zeroizing<[u8; 32]>,
        ml_kem_dk: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ViewPairError> {
        if !spend.is_torsion_free() {
            Err(ViewPairError::TorsionedSpendKey)?;
        }
        let parsed_ml_kem_dk = MlKemDecapsKey::from_bytes(&ml_kem_dk)
            .map_err(|_| ViewPairError::InvalidMlKemDecapKey)?;
        Ok(ViewPair {
            spend,
            view,
            x25519_sk,
            ml_kem_dk,
            parsed_ml_kem_dk,
        })
    }

    /// The public spend key.
    pub fn spend(&self) -> EdwardsPoint {
        self.spend
    }

    /// The public view key (view_scalar * G).
    pub fn view(&self) -> EdwardsPoint {
        self.view.deref() * ED25519_BASEPOINT_TABLE
    }

    /// The X25519 secret key bytes.
    pub fn x25519_sk(&self) -> &[u8; 32] {
        &self.x25519_sk
    }

    /// The ML-KEM-768 decapsulation key bytes.
    pub fn ml_kem_dk(&self) -> &[u8] {
        &self.ml_kem_dk
    }

    /// Parsed ML-KEM decapsulation key (reuse across outputs in a scan).
    pub(crate) fn parsed_ml_kem_dk(&self) -> &MlKemDecapsKey {
        &self.parsed_ml_kem_dk
    }
}

/// ViewPair variant for guaranteed (burning-bug-immune) scanning.
///
/// Uses a modified shared-key derivation that incorporates input key images,
/// guaranteeing scanned outputs are spendable under cryptographic hardness
/// assumptions.
#[derive(Clone, Zeroize)]
pub struct GuaranteedViewPair(pub(crate) ViewPair);

impl GuaranteedViewPair {
    /// Create a new GuaranteedViewPair.
    pub fn new(
        spend: EdwardsPoint,
        view: Zeroizing<Scalar>,
        x25519_sk: Zeroizing<[u8; 32]>,
        ml_kem_dk: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ViewPairError> {
        ViewPair::new(spend, view, x25519_sk, ml_kem_dk).map(GuaranteedViewPair)
    }

    /// The public spend key.
    pub fn spend(&self) -> EdwardsPoint {
        self.0.spend()
    }

    /// The public view key.
    pub fn view(&self) -> EdwardsPoint {
        self.0.view()
    }
}
