// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A new output's commitment mask, as a scalar.
//!
//! The mask `z` of an output's commitment `C = z·G + amount·H` is derived in
//! this crate ([`crate::derivation::derive_output_secrets`], a wide HKDF
//! expansion reduced mod `ℓ`), so it is a scalar from the moment it exists.
//! [`OutputMask`] is that scalar. [`OutputMask::from_derived`] is the one
//! place its bytes are read, and [`OutputMask::opening`] is how every other
//! crate uses it. A reader does not convert the bytes back.

use crate::secret_scalar::canonical_secret_scalar;
use std::fmt;

use curve25519_dalek::Scalar;
use shekyl_curve_primitives::Commitment;
use zeroize::{Zeroize, Zeroizing};

/// A new output's commitment mask `z`, held as the scalar it was derived as.
/// Made by [`Self::from_derived`] from the bytes the derivation wrote
/// ([`crate::output::OutputData::commitment_mask`],
/// [`crate::multisig_output::MultisigOutputData::commitment_mask`]). It wipes
/// on drop and prints nothing.
#[derive(Clone, Zeroize)]
pub struct OutputMask(Zeroizing<Scalar>);

impl OutputMask {
    /// The mask the derivation wrote into `z`.
    ///
    /// Those bytes are a scalar already reduced mod `ℓ`. A non-canonical
    /// encoding is a broken derivation, and this refuses it rather than
    /// reducing it a second time.
    #[must_use]
    pub fn from_derived(z: &[u8; 32]) -> Self {
        Self(canonical_secret_scalar(z).expect("a derived output mask is a canonical scalar"))
    }

    /// The output's commitment opening at `amount`: the mask and the amount
    /// `C = z·G + amount·H` commits to.
    #[must_use]
    pub fn opening(&self, amount: u64) -> Commitment {
        Commitment::new(*self.0, amount)
    }
}

impl fmt::Debug for OutputMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutputMask(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use shekyl_curve_generators::H;

    /// A derived mask is kept exactly: the opening commits to `z·G +
    /// amount·H` for the very scalar the bytes hold.
    #[test]
    fn a_mask_opens_to_the_commitment_its_bytes_make() {
        let z = Scalar::from(0x5eed_u64);
        let mask = OutputMask::from_derived(&z.to_bytes());
        assert_eq!(mask.opening(0).mask, z);
        assert_eq!(
            mask.opening(9).calculate(),
            z * ED25519_BASEPOINT_POINT + Scalar::from(9u64) * *H
        );
    }

    /// The mask prints nothing of itself.
    #[test]
    fn a_mask_never_prints() {
        let mask = OutputMask::from_derived(&Scalar::from(3u64).to_bytes());
        assert_eq!(format!("{mask:?}"), "OutputMask(..)");
    }
}
