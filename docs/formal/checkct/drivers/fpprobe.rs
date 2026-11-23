// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Probe for CA-3 (CRYPTO_AUDIT.md §3.1): can this BINSEC model the SSE2
// double-precision instructions FN-DSA signing executes on secret-derived
// values? One instruction per entrypoint (`mulsd`, `divsd`, `sqrtsd`,
// `cvtsd2si`), each on secret operands, beside a positive control.
// If the control is not insecure, the probe says nothing. If the
// floating-point entrypoints come back `unknown`, BINSEC cannot give a
// verdict on FN-DSA signing on x86_64, whatever driver is written for it.
use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::arch::x86_64::*;
use core::hint::black_box;

/// A secret normal double in [1, 2): exponent fixed, mantissa secret.
fn secret_f64() -> f64 {
    black_box(PublicRng::new().next_u32());
    let mut b = [0u8; 8];
    PrivateRng::new().fill_bytes(&mut b);
    let m = u64::from_le_bytes(b) & 0x000F_FFFF_FFFF_FFFF;
    f64::from_bits(0x3FF0_0000_0000_0000 | m)
}

#[inline(never)]
fn mul(a: f64, b: f64) -> f64 { a * b }
#[checkct]
pub fn fp_mul() { black_box(mul(secret_f64(), secret_f64())); }

#[inline(never)]
fn div(a: f64, b: f64) -> f64 { a / b }
#[checkct]
pub fn fp_div() { black_box(div(secret_f64(), secret_f64())); }

#[inline(never)]
fn sqrt(a: f64) -> f64 {
    unsafe { _mm_cvtsd_f64(_mm_sqrt_pd(_mm_set_sd(a))) }
}
#[checkct]
pub fn fp_sqrt() { black_box(sqrt(secret_f64())); }

#[inline(never)]
fn rint(a: f64) -> i64 {
    unsafe { _mm_cvtsd_si64(_mm_set_sd(a)) }
}
#[checkct]
pub fn fp_rint() { black_box(rint(secret_f64() * 1000.0)); }

#[inline(never)]
fn leaky(secret: u8) -> u32 { if secret & 1 == 1 { black_box(17) } else { black_box(23) } }
#[checkct]
pub fn ctl_positive_leaky_branch() {
    let s = PrivateRng::new().next_u32() as u8;
    black_box(leaky(s));
}
