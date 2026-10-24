// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// dalek-ff-group 0.5.0 FieldElement (helioselene::Field25519), field ops over 2^255-19.
// Inputs are secret canonical encodings (top two bits cleared, so below the
// modulus); from_repr's CtOption is resolved with the constant-time
// `unwrap_or`, and from_repr itself is its own entrypoint, so a leak inside it
// is not attributed to the operation under test.
use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use ff::{Field, PrimeField};
use dalek_ff_group::FieldElement as F;

fn secret_bytes() -> [u8; 32] {
    black_box(PublicRng::new().next_u32());
    let mut b = [0u8; 32];
    PrivateRng::new().fill_bytes(&mut b);
    b[31] &= 0x3f;
    b
}

fn secret_fe() -> F {
    F::from_repr(secret_bytes()).unwrap_or(F::ZERO)
}


#[inline(never)]
fn from_repr(b: [u8; 32]) -> F {
    F::from_repr(b).unwrap_or(F::ZERO)
}
#[checkct]
pub fn dfg_from_repr() {
    black_box(from_repr(secret_bytes()));
}

#[inline(never)]
fn to_repr(a: &F) -> <F as PrimeField>::Repr {
    a.to_repr()
}
#[checkct]
pub fn dfg_to_repr() {
    black_box(to_repr(&secret_fe()));
}

#[inline(never)]
fn add(a: &F, b: &F) -> F {
    *a + *b
}
#[checkct]
pub fn dfg_add() {
    black_box(add(&secret_fe(), &secret_fe()));
}

#[inline(never)]
fn sub(a: &F, b: &F) -> F {
    *a - *b
}
#[checkct]
pub fn dfg_sub() {
    black_box(sub(&secret_fe(), &secret_fe()));
}

#[inline(never)]
fn neg(a: &F) -> F {
    -*a
}
#[checkct]
pub fn dfg_neg() {
    black_box(neg(&secret_fe()));
}

#[inline(never)]
fn mul(a: &F, b: &F) -> F {
    *a * *b
}
#[checkct]
pub fn dfg_mul() {
    black_box(mul(&secret_fe(), &secret_fe()));
}

#[inline(never)]
fn square(a: &F) -> F {
    a.square()
}
#[checkct]
pub fn dfg_square() {
    black_box(square(&secret_fe()));
}

#[inline(never)]
fn invert(a: &F) -> F {
    a.invert().unwrap_or(F::ZERO)
}
#[checkct]
pub fn dfg_invert() {
    black_box(invert(&secret_fe()));
}

#[inline(never)]
fn sqrt(a: &F) -> F {
    a.sqrt().unwrap_or(F::ZERO)
}
#[checkct]
pub fn dfg_sqrt() {
    black_box(sqrt(&secret_fe()));
}

#[inline(never)]
fn is_odd(a: &F) -> u8 {
    a.is_odd().unwrap_u8()
}
#[checkct]
pub fn dfg_is_odd() {
    black_box(is_odd(&secret_fe()));
}

#[inline(never)]
fn pow_secret_exp(a: &F, e: &F) -> F {
    a.pow(*e)
}
#[checkct]
pub fn dfg_pow_secret_exp() {
    black_box(pow_secret_exp(&secret_fe(), &secret_fe()));
}

#[inline(never)]
fn wide_reduce(b: [u8; 64]) -> F {
    F::wide_reduce(b)
}
#[checkct]
pub fn dfg_wide_reduce() {
    black_box(wide_reduce({ let mut w = [0u8; 64]; black_box(PublicRng::new().next_u32()); PrivateRng::new().fill_bytes(&mut w); w }));
}

#[inline(never)]
fn sqrt_ratio_i(u: F, v: F) -> (subtle::Choice, F) {
    F::sqrt_ratio_i(u, v)
}
#[checkct]
pub fn dfg_sqrt_ratio_i() {
    black_box(sqrt_ratio_i(secret_fe(), secret_fe()));
}

// dalek-ff-group 0.5.0 enables curve25519-dalek/alloc, so the freestanding
// driver must link `alloc` and name an allocator. Nothing on these paths
// allocates; a null-returning allocator makes any allocation a panic, which
// ends that path and would show as a leak if it depended on a secret.
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
