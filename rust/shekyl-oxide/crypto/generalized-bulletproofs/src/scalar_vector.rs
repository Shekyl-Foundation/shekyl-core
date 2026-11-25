use core::ops::{Add, Index, IndexMut, Mul, Sub};
use std_shims::{vec, vec::Vec};

use zeroize::Zeroize;

use ciphersuite::group::ff::PrimeField;

use crate::zip_exact;

/// A scalar vector struct with the functionality necessary for Bulletproofs.
///
/// Every elementwise operation between two vectors requires equal lengths, in every build
/// ([`zip_exact`]); a mismatch panics rather than computing over a truncated vector.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ScalarVector<F: PrimeField>(pub(crate) Vec<F>);

impl<F: PrimeField + Zeroize> Zeroize for ScalarVector<F> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F: PrimeField> Index<usize> for ScalarVector<F> {
    type Output = F;
    fn index(&self, index: usize) -> &F {
        &self.0[index]
    }
}
impl<F: PrimeField> IndexMut<usize> for ScalarVector<F> {
    fn index_mut(&mut self, index: usize) -> &mut F {
        &mut self.0[index]
    }
}

impl<F: PrimeField> Add<F> for ScalarVector<F> {
    type Output = ScalarVector<F>;
    fn add(mut self, scalar: F) -> Self {
        for s in &mut self.0 {
            *s += scalar;
        }
        self
    }
}
impl<F: PrimeField> Sub<F> for ScalarVector<F> {
    type Output = ScalarVector<F>;
    fn sub(mut self, scalar: F) -> Self {
        for s in &mut self.0 {
            *s -= scalar;
        }
        self
    }
}
impl<F: PrimeField> Mul<F> for ScalarVector<F> {
    type Output = ScalarVector<F>;
    fn mul(mut self, scalar: F) -> Self {
        for s in &mut self.0 {
            *s *= scalar;
        }
        self
    }
}

impl<F: PrimeField> Add<&ScalarVector<F>> for ScalarVector<F> {
    type Output = ScalarVector<F>;
    fn add(mut self, other: &ScalarVector<F>) -> Self {
        zip_exact(&mut self.0, &other.0, "addition", |s, o| *s += o);
        self
    }
}
impl<F: PrimeField> Sub<&ScalarVector<F>> for ScalarVector<F> {
    type Output = ScalarVector<F>;
    fn sub(mut self, other: &ScalarVector<F>) -> Self {
        zip_exact(&mut self.0, &other.0, "subtraction", |s, o| *s -= o);
        self
    }
}
impl<F: PrimeField> Mul<&ScalarVector<F>> for ScalarVector<F> {
    type Output = ScalarVector<F>;
    fn mul(mut self, other: &ScalarVector<F>) -> Self {
        zip_exact(&mut self.0, &other.0, "multiplication", |s, o| *s *= o);
        self
    }
}

impl<F: PrimeField> ScalarVector<F> {
    /// Create a new scalar vector, initialized with `len` zero scalars.
    pub(crate) fn new(len: usize) -> Self {
        ScalarVector(vec![F::ZERO; len])
    }

    /// The first `len` powers of `x`, `x^0` through `x^(len - 1)`; empty when `len == 0`.
    pub(crate) fn powers(x: F, len: usize) -> Self {
        ScalarVector(
            core::iter::successors(Some(F::ONE), |power| Some(*power * x))
                .take(len)
                .collect(),
        )
    }

    /// If this scalar vector is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The length of this scalar vector.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The inner, or dot, product of two scalar vectors of the same length.
    ///
    /// A different length is refused in every build: a `zip` would drop the longer vector's tail.
    pub(crate) fn inner_product<'a, V: ExactSizeIterator<Item = &'a F>>(&self, vector: V) -> F {
        assert_eq!(
            self.len(),
            vector.len(),
            "inner product of vectors of different lengths"
        );
        self.inner_product_zero_extended(vector)
    }

    /// The inner, or dot, product where the shorter vector is read as zero past its end.
    ///
    /// For polynomial coefficient vectors whose trailing zero coefficients are not stored, such as a
    /// vector commitment's opening, which holds its values without their zero padding.
    pub(crate) fn inner_product_zero_extended<'a, V: Iterator<Item = &'a F>>(
        &self,
        vector: V,
    ) -> F {
        self.0.iter().zip(vector).map(|(a, b)| *a * b).sum()
    }

    /// Split this scalar vector into two parts.
    ///
    /// `at` represents the index split at, with all elements before `at` being in the first vector
    /// and all elements at and after `at` being in the second vector.
    ///
    /// Panics if `at > self.len()`.
    pub(crate) fn split(mut self, at: usize) -> (Self, Self) {
        let r = self.0.split_off(at);
        (self, ScalarVector(r))
    }
}

impl<F: PrimeField> From<Vec<F>> for ScalarVector<F> {
    fn from(vec: Vec<F>) -> Self {
        Self(vec)
    }
}
