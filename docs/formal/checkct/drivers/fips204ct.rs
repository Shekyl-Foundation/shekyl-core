// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// CA-3 (CRYPTO_AUDIT.md section 3.2): fips204's coefficient helpers, built with
// overflow checks on, on secret inputs.
//
// The helpers are `pub(crate)`, so setup.sh compiles fips204's own `helpers.rs`
// and `high_low.rs` from a pinned revision into `fips204_src`, with `crate::`
// rewritten to `super::`. The same driver runs on two revisions:
// - `fips204-tag`, the unpatched tag v0.5.0, is the control and must be insecure;
// - `fips204-fix`, the Shekyl fork, must be secure.
//
// Every input is an unrestricted secret `i32`. On the fork these helpers have no
// branch on the value at all, so nothing needs to assume the valid range.
use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;

#[allow(dead_code, unused_imports, clippy::all)]
#[path = "fips204_src/mod.rs"]
mod fips204_src;
use fips204_src::helpers::infinity_norm;
use fips204_src::high_low::{decompose, make_hint};
use fips204_src::types::R;

/// gamma2 for ML-DSA-44, and for ML-DSA-65 and ML-DSA-87: public parameters.
const GAMMA2_44: i32 = (fips204_src::Q - 1) / 88;
const GAMMA2_65: i32 = (fips204_src::Q - 1) / 32;

fn secret_i32() -> i32 {
    black_box(PublicRng::new().next_u32());
    let mut b = [0u8; 4];
    PrivateRng::new().fill_bytes(&mut b);
    i32::from_le_bytes(b)
}

fn secret_poly() -> R {
    black_box(PublicRng::new().next_u32());
    let mut b = [0u8; 1024];
    PrivateRng::new().fill_bytes(&mut b);
    let mut out = [0i32; 256];
    for (coefficient, bytes) in out.iter_mut().zip(b.chunks_exact(4)) {
        *coefficient = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    R(out)
}

#[inline(never)]
fn norm(w: &[R; 1]) -> i32 {
    infinity_norm(w)
}
#[checkct]
pub fn fips204_infinity_norm() {
    black_box(norm(&[secret_poly()]));
}

#[inline(never)]
fn decompose_at(gamma2: i32, r: i32) -> (i32, i32) {
    decompose(gamma2, r)
}
#[checkct]
pub fn fips204_decompose_44() {
    black_box(decompose_at(black_box(GAMMA2_44), secret_i32()));
}
#[checkct]
pub fn fips204_decompose_65() {
    black_box(decompose_at(black_box(GAMMA2_65), secret_i32()));
}

#[inline(never)]
fn hint_at(gamma2: i32, z: i32, r: i32) -> bool {
    make_hint(gamma2, z, r)
}
#[checkct]
pub fn fips204_make_hint_44() {
    black_box(hint_at(black_box(GAMMA2_44), secret_i32(), secret_i32()));
}
#[checkct]
pub fn fips204_make_hint_65() {
    black_box(hint_at(black_box(GAMMA2_65), secret_i32(), secret_i32()));
}
