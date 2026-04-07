// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! View pair types for scanning: public spend key + private view key.

use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};

use shekyl_oxide::primitives::keccak256_to_scalar;

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
/// Composed of the public spend key and the private view key.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ViewPair {
    spend: EdwardsPoint,
    pub(crate) view: Zeroizing<Scalar>,
}

impl ViewPair {
    /// Create a new ViewPair.
    pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> Result<Self, ViewPairError> {
        if !spend.is_torsion_free() {
            Err(ViewPairError::TorsionedSpendKey)?;
        }
        Ok(ViewPair { spend, view })
    }

    /// The public spend key.
    pub fn spend(&self) -> EdwardsPoint {
        self.spend
    }

    /// The public view key (view_scalar * G).
    pub fn view(&self) -> EdwardsPoint {
        self.view.deref() * ED25519_BASEPOINT_TABLE
    }

    pub(crate) fn subaddress_derivation(&self, index: SubaddressIndex) -> Scalar {
        keccak256_to_scalar(Zeroizing::new(
            [
                b"SubAddr\0".as_slice(),
                Zeroizing::new(self.view.to_bytes()).as_slice(),
                &index.account().to_le_bytes(),
                &index.address().to_le_bytes(),
            ]
            .concat(),
        ))
    }

    pub(crate) fn subaddress_keys(&self, index: SubaddressIndex) -> (EdwardsPoint, EdwardsPoint) {
        let scalar = self.subaddress_derivation(index);
        let spend = self.spend + (&scalar * ED25519_BASEPOINT_TABLE);
        let view = self.view.deref() * spend;
        (spend, view)
    }
}

/// ViewPair variant for guaranteed (burning-bug-immune) scanning.
///
/// Uses a modified shared-key derivation that incorporates input key images,
/// guaranteeing scanned outputs are spendable under cryptographic hardness
/// assumptions.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct GuaranteedViewPair(pub(crate) ViewPair);

impl GuaranteedViewPair {
    /// Create a new GuaranteedViewPair.
    pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> Result<Self, ViewPairError> {
        ViewPair::new(spend, view).map(GuaranteedViewPair)
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
