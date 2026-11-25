// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Operand domains. Every input type names the distribution it is drawn
//! from, so a row's domain is read off its type rather than off a comment:
//!
//! - [`Sample`] is the uniform draw over the type's whole domain: every
//!   field element (the near-modulus ones included, through the field's
//!   wide reduction), every byte string (invalid encodings included), every
//!   `U256`.
//! - [`Canonical<F>`] is a `U256` that is the canonical value of a uniformly
//!   random element of `F`: what the field's own arithmetic holds, the input
//!   the two halves of a square see.
//! - [`Shape`] is a structured operand class (sparse, small, dense), for the
//!   rows that ask which operand property moves the time.

use core::marker::PhantomData;

use crypto_bigint::{impl_modulus, modular::constant_mod::Residue, Encoding, U256};
use dalek_ff_group::FieldElement as Field25519;

use crate::field::{decode, FieldUnderTest};
use crate::rng::Rng;

/// The uniform draw over the type's whole domain.
pub trait Sample: Sized {
    fn sample(rng: &mut Rng) -> Self;
}

impl Sample for u8 {
    fn sample(rng: &mut Rng) -> Self {
        rng.byte()
    }
}

/// Unrestricted bytes: for a 32-byte encoding, invalid ones included.
impl<const N: usize> Sample for [u8; N] {
    fn sample(rng: &mut Rng) -> Self {
        rng.bytes()
    }
}

/// Unrestricted: all 256 bits.
impl Sample for U256 {
    fn sample(rng: &mut Rng) -> Self {
        U256::from_le_bytes(rng.bytes())
    }
}

impl<A: Sample, B: Sample> Sample for (A, B) {
    fn sample(rng: &mut Rng) -> Self {
        (A::sample(rng), B::sample(rng))
    }
}

/// Every element of the field, through its wide reduction of 64 bytes (a
/// masked 32-byte encoding would never reach [2^CAPACITY, p)).
impl<F: FieldUnderTest> Sample for F {
    fn sample(rng: &mut Rng) -> Self {
        F::wide_reduce(rng.bytes())
    }
}

impl_modulus!(
    P25519,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

/// crypto-bigint 0.5.5's own modular residue mod 2^255 − 19: the
/// `Residue::pow` BINSEC found branching on a secret exponent.
pub type Residue25519 = Residue<P25519, { U256::LIMBS }>;

/// From an unrestricted `U256`, which the Montgomery conversion reduces.
impl Sample for Residue25519 {
    fn sample(rng: &mut Rng) -> Self {
        Residue25519::new(&U256::sample(rng))
    }
}

/// The canonical value of a uniformly random element of `F`, as a `U256`.
#[derive(Clone, Copy)]
pub struct Canonical<F> {
    pub value: U256,
    field: PhantomData<F>,
}

impl<F: FieldUnderTest> Sample for Canonical<F> {
    fn sample(rng: &mut Rng) -> Self {
        Canonical {
            value: U256::from_le_bytes(F::sample(rng).to_repr()),
            field: PhantomData,
        }
    }
}

/// A structured operand class. Each draws a value below 2^CAPACITY, which
/// both fields decode as itself (canonical by construction).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Low Hamming weight: one random byte at a random position per limb.
    Sparse,
    /// High limbs zero: a random value below 2^64.
    Small,
    /// Every bit below the capacity set: the one value 2^CAPACITY − 1,
    /// whose square has almost no bits set. A single value, so this class
    /// repeats its operand within a batch, as the constant control does.
    Dense,
}

/// Bytes in one 64-bit limb of the field encodings.
const LIMB_BYTES: usize = size_of::<u64>();

impl Shape {
    pub const ALL: [Shape; 3] = [Shape::Sparse, Shape::Small, Shape::Dense];

    pub fn label(self) -> &'static str {
        match self {
            Shape::Sparse => "sparse",
            Shape::Small => "small",
            Shape::Dense => "dense",
        }
    }

    /// A 32-byte little-endian encoding of this shape for `F`.
    pub fn encoding<F: FieldUnderTest>(self, rng: &mut Rng) -> [u8; 32] {
        let mut encoding = [0u8; 32];
        match self {
            Shape::Sparse => {
                for limb in encoding.chunks_mut(LIMB_BYTES) {
                    let position = rng.below(LIMB_BYTES);
                    limb[position] = rng.byte();
                }
            }
            Shape::Small => {
                encoding[..LIMB_BYTES].copy_from_slice(&rng.next_u64().to_le_bytes());
            }
            Shape::Dense => encoding = [u8::MAX; 32],
        }
        below_capacity::<F>(encoding)
    }
}

/// The encoding with every bit at or above `F::CAPACITY` cleared, so it
/// decodes to itself.
fn below_capacity<F: FieldUnderTest>(mut encoding: [u8; 32]) -> [u8; 32] {
    let capacity = F::CAPACITY as usize;
    let byte_bits = u8::BITS as usize;
    for (index, byte) in encoding.iter_mut().enumerate() {
        let low_bit = index * byte_bits;
        if low_bit >= capacity {
            *byte = 0;
        } else if low_bit + byte_bits > capacity {
            *byte &= u8::MAX >> (low_bit + byte_bits - capacity);
        }
    }
    encoding
}

/// A value of an operand shape, in the terms of field `F`: an element of
/// `F` decoded from the shape's encoding, the encoding itself (for the
/// decoding rows), or the encoding as the low half of 64 bytes (for the
/// wide-reduction rows). A row's shaped class is drawn from this, fresh
/// per element; its random class from [`Sample`].
pub trait FromShape<F>: Sized {
    fn from_shape(shape: Shape, rng: &mut Rng) -> Self;
}

impl<F: FieldUnderTest> FromShape<F> for F {
    fn from_shape(shape: Shape, rng: &mut Rng) -> Self {
        decode(shape.encoding::<F>(rng))
    }
}

impl<F: FieldUnderTest> FromShape<F> for [u8; 32] {
    fn from_shape(shape: Shape, rng: &mut Rng) -> Self {
        shape.encoding::<F>(rng)
    }
}

impl<F: FieldUnderTest> FromShape<F> for [u8; 64] {
    fn from_shape(shape: Shape, rng: &mut Rng) -> Self {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&shape.encoding::<F>(rng));
        wide
    }
}

impl<F, A: FromShape<F>, B: FromShape<F>> FromShape<F> for (A, B) {
    fn from_shape(shape: Shape, rng: &mut Rng) -> Self {
        (A::from_shape(shape, rng), B::from_shape(shape, rng))
    }
}

/// A `Field25519` whose Montgomery residue is a sparse value.
///
/// The field stores `x·R mod p`, so [`FromShape`] of [`Shape::Sparse`] is
/// not a sparse residue. This draw is `x = s·R⁻¹ mod p` for a sparse `s`.
pub fn sparse_montgomery_fe25519(rng: &mut Rng) -> Field25519 {
    let residue = U256::from_le_bytes(Shape::Sparse.encoding::<Field25519>(rng));
    let canonical = Residue25519::from_montgomery(residue).retrieve();
    decode(canonical.to_le_bytes())
}

/// A product of two [`sparse_montgomery_fe25519`] draws.
pub fn sparse_montgomery_fe25519_pair(rng: &mut Rng) -> (Field25519, Field25519) {
    (
        sparse_montgomery_fe25519(rng),
        sparse_montgomery_fe25519(rng),
    )
}

/// An ML-KEM-768 ciphertext, the length `fips203` 0.5.0 compares.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;

/// The two operands of that compare.
#[derive(Clone)]
pub struct CtPair {
    left: [u8; ML_KEM_768_CIPHERTEXT_BYTES],
    right: [u8; ML_KEM_768_CIPHERTEXT_BYTES],
}

impl CtPair {
    /// A random string and itself: a ciphertext and its re-encryption.
    pub fn equal(rng: &mut Rng) -> Self {
        let left: [u8; ML_KEM_768_CIPHERTEXT_BYTES] = rng.bytes();
        CtPair { left, right: left }
    }

    /// Two independent strings: an invalid ciphertext and a re-encryption.
    pub fn random(rng: &mut Rng) -> Self {
        CtPair {
            left: rng.bytes(),
            right: rng.bytes(),
        }
    }

    /// A random string and itself with one bit flipped.
    pub fn bitflip(rng: &mut Rng) -> Self {
        let left: [u8; ML_KEM_768_CIPHERTEXT_BYTES] = rng.bytes();
        let mut right = left;
        let bit = rng.below(ML_KEM_768_CIPHERTEXT_BYTES * 8);
        right[bit / 8] ^= 1u8 << (bit % 8);
        CtPair { left, right }
    }

    /// `subtle`'s slice compare, the impl `ct.ct_ne(&*c_prime)` resolves to.
    pub fn ne(pair: &Self) -> u64 {
        use subtle::ConstantTimeEq;
        u64::from(pair.left[..].ct_ne(&pair.right[..]).unwrap_u8())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dalek_ff_group::FieldElement as Field25519;
    use ff::PrimeField;
    use helioselene::HelioseleneField;

    fn every_shape_is_canonical<F: FieldUnderTest>() {
        let mut rng = Rng::from_os();
        for shape in Shape::ALL {
            for _ in 0..256 {
                let encoding = shape.encoding::<F>(&mut rng);
                let decoded = F::from_repr(encoding);
                assert!(bool::from(decoded.is_some()), "{shape:?} not canonical");
                assert_eq!(decoded.unwrap().to_repr(), encoding);
            }
        }
    }

    #[test]
    fn shapes_are_canonical_in_both_fields() {
        every_shape_is_canonical::<Field25519>();
        every_shape_is_canonical::<HelioseleneField>();
    }

    #[test]
    fn dense_is_every_bit_below_the_capacity() {
        let mut rng = Rng::from_os();
        let dense = U256::from_le_bytes(Shape::Dense.encoding::<HelioseleneField>(&mut rng));
        let capacity = HelioseleneField::CAPACITY;
        assert_eq!(dense, U256::MAX.shr_vartime(256 - capacity as usize));
    }

    /// The canonical sampler reaches [2^CAPACITY, p), which a masked
    /// encoding never does: the near-modulus values the fields hold.
    #[test]
    fn canonical_values_reach_above_the_capacity() {
        let mut rng = Rng::from_os();
        let capacity_bound = U256::ONE.shl_vartime(HelioseleneField::CAPACITY as usize);
        let reached = (0..256)
            .any(|_| Canonical::<HelioseleneField>::sample(&mut rng).value >= capacity_bound);
        assert!(reached);
    }

    #[test]
    fn unrestricted_encodings_include_invalid_ones() {
        let mut rng = Rng::from_os();
        let invalid = (0..256).any(|_| {
            let encoding: [u8; 32] = Sample::sample(&mut rng);
            bool::from(HelioseleneField::from_repr(encoding).is_none())
        });
        assert!(invalid);
    }

    /// Re-entering the canonical value into Montgomery form gives back at
    /// most one set byte per limb.
    #[test]
    fn sparse_montgomery_operands_hold_sparse_residues() {
        use crate::classes::{Retention, COMPLETE_OPERAND_MAX};
        let mut rng = Rng::from_os();
        for _ in 0..256 {
            let x = sparse_montgomery_fe25519(&mut rng);
            let canonical = U256::from_le_bytes(x.to_repr());
            let residue = Residue25519::new(&canonical);
            let set_bytes = residue
                .as_montgomery()
                .to_le_bytes()
                .iter()
                .filter(|byte| **byte != 0)
                .count();
            assert!(set_bytes <= 4, "residue has {set_bytes} set bytes");
        }
        let uniform = Field25519::sample(&mut rng);
        let uniform_residue = Residue25519::new(&U256::from_le_bytes(uniform.to_repr()));
        let uniform_set = uniform_residue
            .as_montgomery()
            .to_le_bytes()
            .iter()
            .filter(|byte| **byte != 0)
            .count();
        assert!(
            uniform_set > 4,
            "a uniform residue was sparse ({uniform_set} set bytes)"
        );
        assert!(size_of::<(Field25519, Field25519)>() <= COMPLETE_OPERAND_MAX);
        assert_eq!(
            Retention::for_operand(size_of::<CtPair>()),
            Retention::Windowed
        );
    }

    #[test]
    fn ciphertext_pairs_compare_as_their_distribution_says() {
        let mut rng = Rng::from_os();
        for _ in 0..32 {
            let equal = CtPair::equal(&mut rng);
            assert_eq!(equal.left, equal.right);
            assert_eq!(CtPair::ne(&equal), 0);

            let flipped = CtPair::bitflip(&mut rng);
            let flipped_bits: u32 = flipped
                .left
                .iter()
                .zip(&flipped.right)
                .map(|(left, right)| (left ^ right).count_ones())
                .sum();
            assert_eq!(flipped_bits, 1);
            assert_eq!(CtPair::ne(&flipped), 1);

            assert_eq!(CtPair::ne(&CtPair::random(&mut rng)), 1);
        }
    }
}
