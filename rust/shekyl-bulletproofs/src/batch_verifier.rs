use std_shims::vec::Vec;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::EdwardsPoint,
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};

use shekyl_curve_generators::{BulletproofGenerators, H as SHEKYL_H};

use crate::plus;

#[derive(Default)]
pub(crate) struct InternalBatchVerifier {
    pub(crate) g: Scalar,
    pub(crate) h: Scalar,
    pub(crate) g_bold: Vec<Scalar>,
    pub(crate) h_bold: Vec<Scalar>,
    pub(crate) other: Vec<(Scalar, EdwardsPoint)>,
}

impl InternalBatchVerifier {
    #[must_use]
    fn verify(self, G: EdwardsPoint, H: EdwardsPoint, generators: &BulletproofGenerators) -> bool {
        /*
          Technically, this following line can overflow, and joining these `Vec`s _may_ panic if
          they're individually acceptable lengths yet their sum isn't. This is so negligible, due to
          the amount of memory required, it's dismissed.
        */
        let capacity = 2 + self.g_bold.len() + self.h_bold.len() + self.other.len();
        let mut scalars = Vec::with_capacity(capacity);
        let mut points = Vec::with_capacity(capacity);

        scalars.push(self.g);
        points.push(G);

        scalars.push(self.h);
        points.push(H);

        for (i, g_bold) in self.g_bold.into_iter().enumerate() {
            scalars.push(g_bold);
            points.push(generators.G[i]);
        }

        for (i, h_bold) in self.h_bold.into_iter().enumerate() {
            scalars.push(h_bold);
            points.push(generators.H[i]);
        }

        for (scalar, point) in self.other {
            scalars.push(scalar);
            points.push(point);
        }

        EdwardsPoint::vartime_multiscalar_mul(scalars, points).is_identity()
    }
}

/// A point the verifier does not evaluate, as its terms over the batch's
/// slots: `g` is the coefficient of the batch's `g` point, `g_bold[i]` and
/// `h_bold[i]` of its `i`th bold generators, and `other` carries any point the
/// fixed slots do not hold.
///
/// Adding it into the batch at a weight is the same as pushing
/// `(weight, the evaluated point)`: the batch's single multiscalar
/// multiplication sums to the same group element, so every verdict is
/// unchanged, and a point that shares the batch's generators costs no
/// multiscalar multiplication of its own.
pub(crate) struct BatchTerms {
    pub(crate) g: Scalar,
    pub(crate) g_bold: Vec<Scalar>,
    pub(crate) h_bold: Vec<Scalar>,
    pub(crate) other: Vec<(Scalar, EdwardsPoint)>,
}

impl BatchTerms {
    /// One point, as a single term.
    #[cfg(test)]
    pub(crate) fn point(point: EdwardsPoint) -> Self {
        Self {
            g: Scalar::ZERO,
            g_bold: Vec::new(),
            h_bold: Vec::new(),
            other: vec![(Scalar::ONE, point)],
        }
    }

    /// The longest bold vector these terms address.
    pub(crate) fn bold_len(&self) -> usize {
        self.g_bold.len().max(self.h_bold.len())
    }

    /// Adds `weight` times these terms into `verifier`. Its bold vectors must
    /// already be at least [`Self::bold_len`] long; the caller pads them
    /// first, as every proof's own terms are padded.
    pub(crate) fn add_into(self, weight: Scalar, verifier: &mut InternalBatchVerifier) {
        assert!(
            verifier.g_bold.len() >= self.g_bold.len()
                && verifier.h_bold.len() >= self.h_bold.len(),
            "the batch's bold vectors are padded to the terms' length before they are added"
        );
        verifier.g += weight * self.g;
        for (slot, scalar) in verifier.g_bold.iter_mut().zip(self.g_bold) {
            *slot += weight * scalar;
        }
        for (slot, scalar) in verifier.h_bold.iter_mut().zip(self.h_bold) {
            *slot += weight * scalar;
        }
        for (scalar, point) in self.other {
            verifier.other.push((weight * scalar, point));
        }
    }
}

#[derive(Default)]
pub(crate) struct BulletproofsPlusBatchVerifier(pub(crate) InternalBatchVerifier);
impl BulletproofsPlusBatchVerifier {
    #[must_use]
    pub(crate) fn verify(self) -> bool {
        // Bulletproofs+ is written as per the paper, with G for the value and H for the mask
        // Monero uses H for the value and G for the mask
        self.0
            .verify(*SHEKYL_H, ED25519_BASEPOINT_POINT, &plus::GENERATORS)
    }
}

/// A batch verifier for Bulletproofs(+).
///
/// This uses a fixed layout such that all fixed points only incur a single point scaling,
/// regardless of the amounts of proofs verified. For all variable points (commitments), they're
/// accumulated with the fixed points into a single multiscalar multiplication.
#[derive(Default)]
pub struct BatchVerifier {
    pub(crate) plus: BulletproofsPlusBatchVerifier,
}
impl BatchVerifier {
    /// Create a new batch verifier.
    pub fn new() -> Self {
        Self {
            plus: BulletproofsPlusBatchVerifier(InternalBatchVerifier::default()),
        }
    }

    /// Verify all of the proofs queued within this batch verifier.
    ///
    /// This uses a variable-time multiscalar multiplication internally.
    #[must_use]
    pub fn verify(self) -> bool {
        self.plus.verify()
    }
}
