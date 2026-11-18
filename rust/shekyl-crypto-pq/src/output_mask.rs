// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A new output's commitment mask, as a scalar.
//!
//! The mask `z` of an output's commitment `C = z·G + amount·H` is derived in
//! this crate ([`crate::derivation::derive_output_secrets`], a wide HKDF
//! expansion reduced mod `ℓ`), so it is a scalar from the moment it exists.
//! A builder that handed it out as 32 bytes made every reader convert it
//! back, and each conversion carried a failure that cannot happen: a mask
//! that is not a canonical scalar. [`OutputMask`] hands out the scalar, so
//! there is no conversion left to fail.

use std::fmt;

use curve25519_dalek::Scalar;
use shekyl_curve_primitives::Commitment;
use zeroize::Zeroizing;

/// A new output's commitment mask `z`, held as the scalar it was derived as.
/// Made only in this crate, from a constructed output
/// ([`crate::output::OutputData::commitment_mask`],
/// [`crate::multisig_output::MultisigOutputData::commitment_mask`]). It wipes
/// on drop and prints nothing.
#[derive(Clone)]
pub struct OutputMask(Zeroizing<Scalar>);

impl OutputMask {
    /// The mask of a constructed output, from the bytes the derivation wrote:
    /// the bytes of a scalar already reduced mod `ℓ`, so the reduction here
    /// leaves it as it is and cannot refuse.
    pub(crate) fn of_derived(z: &[u8; 32]) -> Self {
        Self(Zeroizing::new(Scalar::from_bytes_mod_order(*z)))
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
        let mask = OutputMask::of_derived(&z.to_bytes());
        assert_eq!(mask.opening(0).mask, z);
        assert_eq!(
            mask.opening(9).calculate(),
            z * ED25519_BASEPOINT_POINT + Scalar::from(9u64) * *H
        );
    }

    /// The mask prints nothing of itself.
    #[test]
    fn a_mask_never_prints() {
        let mask = OutputMask::of_derived(&Scalar::from(3u64).to_bytes());
        assert_eq!(format!("{mask:?}"), "OutputMask(..)");
    }
}
