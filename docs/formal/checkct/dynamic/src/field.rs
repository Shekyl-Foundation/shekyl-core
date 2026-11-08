// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two fields under comparison, behind one trait, so every row is
//! written once and run on both: `Field25519` (dalek-ff-group, Montgomery
//! form) and `HelioseleneField` (canonical form). CA-2 is the contrast
//! between them, so the rows must be the same rows.

use core::hint::black_box;

use dalek_ff_group::FieldElement as Field25519;
use ff::{Field, PrimeField};
use helioselene::HelioseleneField;

/// A field the harness times. Every contrast of an operation (null, fixed
/// set, fixed pair, constant, operand shape) runs the same code path, so
/// two rows of one operation differ in their operands only, never in how
/// the operation was compiled into the loop. The `_isolated` operations are
/// the wrapped path; the suite's direct path calls the field's operators.
pub trait FieldUnderTest: PrimeField<Repr = [u8; 32]> {
    /// The row-name prefix (`helio square`, `property: fe25519 square ...`).
    const LABEL: &'static str;

    /// The field's reduction of 64 bytes: a uniformly random element of
    /// the whole field, near-modulus values included.
    fn wide_reduce(bytes: [u8; 64]) -> Self;

    /// Multiplication, behind a non-inlined symbol (see [`op_helio_mul`]).
    fn mul_isolated(a: &Self, b: &Self) -> Self;

    /// Squaring, behind a non-inlined symbol (see [`op_helio_square`]).
    fn square_isolated(a: &Self) -> Self;

    /// Exponentiation by a secret exponent, the field's own constant-time
    /// method.
    fn pow_secret(&self, exponent: &Self) -> Self;
}

impl FieldUnderTest for Field25519 {
    const LABEL: &'static str = "fe25519";
    fn wide_reduce(bytes: [u8; 64]) -> Self {
        Field25519::wide_reduce(bytes)
    }
    fn mul_isolated(a: &Self, b: &Self) -> Self {
        op_fe25519_mul(a, b)
    }
    fn square_isolated(a: &Self) -> Self {
        op_fe25519_square(a)
    }
    fn pow_secret(&self, exponent: &Self) -> Self {
        self.pow(*exponent)
    }
}

impl FieldUnderTest for HelioseleneField {
    const LABEL: &'static str = "helio";
    fn wide_reduce(bytes: [u8; 64]) -> Self {
        HelioseleneField::wide_reduce(bytes)
    }
    fn mul_isolated(a: &Self, b: &Self) -> Self {
        op_helio_mul(a, b)
    }
    fn square_isolated(a: &Self) -> Self {
        op_helio_square(a)
    }
    fn pow_secret(&self, exponent: &Self) -> Self {
        self.pow(*exponent)
    }
}

// Non-inlined wrappers for the operations CA-2 compares, so each field's
// code is one addressable symbol in the binary and the two can be diffed
// (`objdump -d --disassemble=<symbol>`); the call costs the same for every
// class. They are concrete functions, not one generic, because a generic's
// two instances demangle to the same name.

#[inline(never)]
pub fn op_helio_square(a: &HelioseleneField) -> HelioseleneField {
    a.square()
}
#[inline(never)]
pub fn op_fe25519_square(a: &Field25519) -> Field25519 {
    a.square()
}
#[inline(never)]
pub fn op_helio_mul(a: &HelioseleneField, b: &HelioseleneField) -> HelioseleneField {
    *a * *b
}
#[inline(never)]
pub fn op_fe25519_mul(a: &Field25519, b: &Field25519) -> Field25519 {
    *a * *b
}

/// Decode a 32-byte encoding; an invalid one becomes zero through the
/// constant-time `unwrap_or`, so decoding never branches on validity.
pub fn decode<F: FieldUnderTest>(encoding: [u8; 32]) -> F {
    F::from_repr(encoding).unwrap_or(F::ZERO)
}

/// The word an operation's result contributes to the timing loop's sink.
/// The whole result reaches an optimisation barrier before one word is
/// taken from it, so an inlined operation cannot drop the computation of
/// the words nobody reads.
pub fn sink_word<F: PrimeField<Repr = [u8; 32]>>(value: &F) -> u64 {
    let encoding = black_box(value).to_repr();
    u64::from_le_bytes(black_box(encoding)[..size_of::<u64>()].try_into().unwrap())
}
