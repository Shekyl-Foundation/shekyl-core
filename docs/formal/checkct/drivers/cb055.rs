// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// crypto-bigint 0.5.5, the operations dalek-ff-group 0.5.0's FieldElement
// (helioselene::Field25519) is built from, over p = 2^255 - 19 with secret
// operands and the public modulus.
use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use subtle::ConstantTimeLess;
use crypto_bigint::{
    impl_modulus,
    modular::constant_mod::{Residue, ResidueParams},
    NonZero, U256, U512,
};

impl_modulus!(
    P25519,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);
type R = Residue<P25519, { U256::LIMBS }>;
const P: U256 = <P25519 as ResidueParams<{ U256::LIMBS }>>::MODULUS;
const WIDE: U512 = U256::ZERO.concat(&P);

fn secret_u256() -> U256 {
    black_box(PublicRng::new().next_u32());
    let mut b = [0u8; 32];
    PrivateRng::new().fill_bytes(&mut b);
    b[0] &= 0x3f;
    U256::from_be_slice(&b)
}

fn secret_r() -> R {
    R::new(&secret_u256())
}

#[inline(never)]
fn sub_mod(a: &U256, b: &U256) -> U256 {
    a.sub_mod(b, &P)
}
#[checkct]
pub fn cb055_sub_mod_u256() {
    let (a, b) = (secret_u256(), secret_u256());
    black_box(sub_mod(&a, &b));
}

#[inline(never)]
fn add_mod(a: &U256, b: &U256) -> U256 {
    a.add_mod(b, &P)
}
#[checkct]
pub fn cb055_add_mod_u256() {
    let (a, b) = (secret_u256(), secret_u256());
    black_box(add_mod(&a, &b));
}

/// Montgomery form conversion (a Montgomery multiplication by R^2).
#[inline(never)]
fn residue_new(a: &U256) -> R {
    R::new(a)
}
#[checkct]
pub fn cb055_residue_new() {
    black_box(residue_new(&secret_u256()));
}

/// Montgomery reduction out of the form.
#[inline(never)]
fn residue_retrieve(a: &R) -> U256 {
    a.retrieve()
}
#[checkct]
pub fn cb055_residue_retrieve() {
    black_box(residue_retrieve(&secret_r()));
}

#[inline(never)]
fn residue_mul(a: &R, b: &R) -> R {
    a.mul(b)
}
#[checkct]
pub fn cb055_residue_mul() {
    let (a, b) = (secret_r(), secret_r());
    black_box(residue_mul(&a, &b));
}

#[inline(never)]
fn residue_square(a: &R) -> R {
    a.square()
}
#[checkct]
pub fn cb055_residue_square() {
    black_box(residue_square(&secret_r()));
}

#[inline(never)]
fn residue_add(a: &R, b: &R) -> R {
    a.add(b)
}
#[checkct]
pub fn cb055_residue_add() {
    let (a, b) = (secret_r(), secret_r());
    black_box(residue_add(&a, &b));
}

#[inline(never)]
fn residue_sub(a: &R, b: &R) -> R {
    a.sub(b)
}
#[checkct]
pub fn cb055_residue_sub() {
    let (a, b) = (secret_r(), secret_r());
    black_box(residue_sub(&a, &b));
}

#[inline(never)]
fn residue_neg(a: &R) -> R {
    a.neg()
}
#[checkct]
pub fn cb055_residue_neg() {
    black_box(residue_neg(&secret_r()));
}

#[inline(never)]
fn residue_invert(a: &R) -> (R, crypto_bigint::CtChoice) {
    a.invert()
}
#[checkct]
pub fn cb055_residue_invert() {
    black_box(residue_invert(&secret_r()));
}

/// Exponentiation with a secret exponent (dalek-ff-group's own `pow` is a
/// separate entrypoint in the dfg driver).
#[inline(never)]
fn residue_pow(a: &R, e: &U256) -> R {
    a.pow(e)
}
#[checkct]
pub fn cb055_residue_pow_secret_exp() {
    let (a, e) = (secret_r(), secret_u256());
    black_box(residue_pow(&a, &e));
}

/// The wide reduction dalek-ff-group's `reduce` performs: a secret U512
/// remaindered by the public modulus.
#[inline(never)]
fn rem_wide(a: &U512) -> U512 {
    a.rem(&NonZero::new(WIDE).unwrap())
}
#[checkct]
pub fn cb055_rem_u512_public_modulus() {
    let mut b = [0u8; 64];
    black_box(PublicRng::new().next_u32());
    PrivateRng::new().fill_bytes(&mut b);
    black_box(rem_wide(&U512::from_be_slice(&b)));
}

#[inline(never)]
fn ct_lt(a: &U256) -> subtle::Choice {
    a.ct_lt(&P)
}
#[checkct]
pub fn cb055_ct_lt_modulus() {
    let mut b = [0u8; 32];
    black_box(PublicRng::new().next_u32());
    PrivateRng::new().fill_bytes(&mut b);
    black_box(ct_lt(&U256::from_be_slice(&b)));
}


// The workspace unifies zeroize/alloc from dalek-ff-group's curve25519-dalek,
// so this freestanding driver links `alloc` too and must name an allocator.
// Nothing here allocates; a null allocator turns any allocation into a panic.
extern crate alloc;
struct NoAlloc;
unsafe impl core::alloc::GlobalAlloc for NoAlloc {
    unsafe fn alloc(&self, _l: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _p: *mut u8, _l: core::alloc::Layout) {}
}
#[global_allocator]
static GLOBAL: NoAlloc = NoAlloc;
