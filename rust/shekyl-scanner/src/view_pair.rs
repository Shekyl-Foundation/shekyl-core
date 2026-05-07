// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! View pair types for scanning: public spend key + private view key + KEM keys.

use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};

use shekyl_crypto_pq::subaddress as crypto_subaddress;

use crate::SubaddressIndex;

/// An error while working with a ViewPair.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ViewPairError {
    /// The spend key has torsion and is of questionable spendability.
    #[error("torsioned spend key")]
    TorsionedSpendKey,
}

/// The pair of keys necessary to scan transactions.
///
/// Composed of the public spend key, the private view key, and the hybrid
/// KEM secret keys (X25519 + ML-KEM-768) needed for PQC output recovery.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewPair {
    spend: EdwardsPoint,
    pub(crate) view: Zeroizing<Scalar>,
    /// X25519 secret key for view-tag pre-filter and KEM decap.
    pub(crate) x25519_sk: Zeroizing<[u8; 32]>,
    /// ML-KEM-768 decapsulation key (2400 bytes).
    pub(crate) ml_kem_dk: Zeroizing<Vec<u8>>,
}

impl PartialEq for ViewPair {
    fn eq(&self, other: &Self) -> bool {
        self.spend == other.spend && *self.view == *other.view
    }
}
impl Eq for ViewPair {}

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
        Ok(ViewPair {
            spend,
            view,
            x25519_sk,
            ml_kem_dk,
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

    /// Public `(spend, view)` point pair for a subaddress.
    ///
    /// Thin call-through to
    /// [`shekyl_crypto_pq::subaddress::subaddress_keys`], the canonical home
    /// for Shekyl's classical Edwards-curve subaddress derivation per
    /// `STAGE_1_PR_3_KEY_ENGINE.md` Commit 4a. The cryptographic spec
    /// (genesis-locked domain tag, scalar/index encoding) lives with the
    /// primitive; this method only adapts the typed [`SubaddressIndex`]
    /// argument to the canonical-bytes shape via
    /// [`SubaddressIndex::to_canonical_bytes`].
    pub(crate) fn subaddress_keys(&self, index: SubaddressIndex) -> (EdwardsPoint, EdwardsPoint) {
        crypto_subaddress::subaddress_keys(&self.view, &self.spend, &index.to_canonical_bytes())
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
