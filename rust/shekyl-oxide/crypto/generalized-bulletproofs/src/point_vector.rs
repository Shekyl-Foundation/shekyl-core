use core::ops::{Add, Index, IndexMut, Mul, Sub};
use std_shims::vec::Vec;

use zeroize::Zeroize;

use ciphersuite::Ciphersuite;

use crate::{zip_exact, ScalarVector};

/// A point vector struct with the functionality necessary for Bulletproofs.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct PointVector<C: Ciphersuite>(pub(crate) Vec<C::G>);

impl<C: Ciphersuite> Index<usize> for PointVector<C> {
    type Output = C::G;
    fn index(&self, index: usize) -> &C::G {
        &self.0[index]
    }
}

impl<C: Ciphersuite> IndexMut<usize> for PointVector<C> {
    fn index_mut(&mut self, index: usize) -> &mut C::G {
        &mut self.0[index]
    }
}

impl<C: Ciphersuite> Add<C::G> for PointVector<C> {
    type Output = Self;
    fn add(mut self, point: C::G) -> Self::Output {
        for val in &mut self.0 {
            *val += point;
        }
        self
    }
}

impl<C: Ciphersuite> Sub<C::G> for PointVector<C> {
    type Output = Self;
    fn sub(mut self, point: C::G) -> Self::Output {
        for val in &mut self.0 {
            *val -= point;
        }
        self
    }
}

impl<C: Ciphersuite> Mul<C::F> for PointVector<C> {
    type Output = Self;
    fn mul(mut self, scalar: C::F) -> Self::Output {
        for val in &mut self.0 {
            *val *= scalar;
        }
        self
    }
}

impl<C: Ciphersuite> PointVector<C> {
    /// Scales the points in this vector by the corresponding scalars within the scalar vector.
    ///
    /// The vectors must be the same length, in every build ([`zip_exact`]).
    pub(crate) fn mul_vec(mut self, vector: &ScalarVector<C::F>) -> Self {
        zip_exact(&mut self.0, &vector.0, "scaling", |point, scalar| {
            *point *= *scalar
        });
        self
    }

    /// Compute the multi-scalar multiplication of this point vector by the scalar vector.
    ///
    /// The vectors must be the same length.
    #[cfg(test)] // The tests' reference computation
    pub(crate) fn multiexp(&self, vector: &ScalarVector<C::F>) -> C::G
    where
        C::G: subtle::ConditionallySelectable,
    {
        assert_eq!(
            self.len(),
            vector.len(),
            "multiexp of vectors of different lengths"
        );
        let mut res = Vec::with_capacity(self.len());
        for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
            res.push((scalar, point));
        }
        multiexp::multiexp(&res)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Split this point vector into two equally-sized halves.
    ///
    /// The length must be even and non-zero, in every build: an odd length cannot halve, and the
    /// inner-product argument folds the two halves together element by element.
    pub(crate) fn split(mut self) -> (Self, Self) {
        assert!(
            (self.len() != 0) && (self.len() % 2 == 0),
            "splitting a point vector of length {} into halves",
            self.len()
        );
        let r = self.0.split_off(self.len() / 2);
        (self, PointVector(r))
    }
}
