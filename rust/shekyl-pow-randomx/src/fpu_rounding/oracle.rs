// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Test-only oracles for the rounding blocks: each RandomX
//! floating-point instruction computed at round-to-nearest in plain
//! Rust, then moved by at most one step, decided by the exact sign of
//! the rounding error. Nothing here reaches a shipped binary.
//!
//! - [`Impl::C`]: the error from TwoSum for add and sub, and from an
//!   FMA residual for mul, div and sqrt where the residual is exact
//!   (operand exponents summing to at least
//!   [`FMA_EXACT_MIN_EXP_SUM`]); an exact integer comparison elsewhere.
//! - [`Impl::CInt`]: the integer comparison everywhere: the path a
//!   CPU without FMA would take.
//!
//! The tests run both against the blocks per operation and mode
//! (`fpu_rounding::tests`). The edge cases and why each is right are
//! the decision record's (`docs/design/RANDOMX_ROUNDING_DECISION.md`).
//! The oracles compute in plain Rust, so they must run under the
//! default control word.

use super::NEAREST;
use core::cmp::Ordering;

const DOWN: u32 = 1;
const UP: u32 = 2;
const TOWARD_ZERO: u32 = 3;

/// One RandomX floating-point operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
}

/// The five operations, in [`Op`] order.
pub(crate) const OPS: [Op; 5] = [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::Sqrt];

/// Which oracle computes the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Impl {
    /// FMA residual where exact, integer comparison elsewhere.
    C,
    /// Integer comparison only.
    CInt,
}

#[inline(always)]
fn nearest(op: Op, a: [f64; 2], b: [f64; 2]) -> [f64; 2] {
    match op {
        Op::Add => [a[0] + b[0], a[1] + b[1]],
        Op::Sub => [a[0] - b[0], a[1] - b[1]],
        Op::Mul => [a[0] * b[0], a[1] * b[1]],
        Op::Div => [a[0] / b[0], a[1] / b[1]],
        Op::Sqrt => [a[0].sqrt(), a[1].sqrt()],
    }
}

/// `(m, e)` with `|x| = m * 2^e`, `m < 2^53`, for finite `x`
/// (subnormals included; zero gives `m = 0`).
#[inline(always)]
fn decompose(x: f64) -> (u64, i32) {
    let bits = x.to_bits() & !(1u64 << 63);
    let field = (bits >> 52) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    if field == 0 {
        (frac, -1074)
    } else {
        (frac | (1u64 << 52), field - 1075)
    }
}

/// Exact comparison of `|x * y|` with `|z|`, all finite.
fn cmp_product(x: f64, y: f64, z: f64) -> Ordering {
    let (mx, ex) = decompose(x);
    let (my, ey) = decompose(y);
    let (mz, ez) = decompose(z);
    let p = u128::from(mx) * u128::from(my); // < 2^106
    if p == 0 || mz == 0 {
        return p.cmp(&u128::from(mz));
    }
    // Compare p * 2^(ex+ey) with mz * 2^ez.
    let d = ez - (ex + ey);
    if d >= 0 {
        // p vs mz << d. When mz << d would reach 2^127 it exceeds
        // p < 2^106 without being computed.
        let bits = 64 - mz.leading_zeros().cast_signed(); // mz >= 1
        if bits - 1 + d >= 127 {
            return Ordering::Less;
        }
        p.cmp(&(u128::from(mz) << d))
    } else {
        // p * 2^s vs mz, s = -d > 0. When p << s would reach 2^127 it
        // exceeds mz < 2^53 without being computed.
        let s = -d;
        let bits = 128 - p.leading_zeros().cast_signed(); // p >= 1
        if bits - 1 + s >= 127 {
            return Ordering::Greater;
        }
        (p << s).cmp(&u128::from(mz))
    }
}

/// Move the round-to-nearest result `s` by at most one step, given the
/// sign of `true - s`.
#[inline(always)]
fn adjust(s: f64, true_vs_s: Ordering, mode: u32) -> f64 {
    match (mode, true_vs_s) {
        (DOWN, Ordering::Less) => s.next_down(),
        (UP, Ordering::Greater) => s.next_up(),
        (TOWARD_ZERO, Ordering::Less) if !s.is_sign_negative() => s.next_down(),
        (TOWARD_ZERO, Ordering::Greater) if s.is_sign_negative() => s.next_up(),
        _ => s,
    }
}

/// The directed result when round-to-nearest overflowed to `s = ±inf`
/// from finite operands: the true value is beyond `MAX`.
#[inline(always)]
fn overflow(s: f64, mode: u32) -> f64 {
    let neg = s.is_sign_negative();
    match (mode, neg) {
        (DOWN | TOWARD_ZERO, false) => f64::MAX,
        (UP | TOWARD_ZERO, true) => -f64::MAX,
        _ => s,
    }
}

/// Signed `true - s` from a magnitude comparison of the true result
/// against `s` (both share `s`'s sign when nonzero).
#[inline(always)]
fn signed(mag: Ordering, s: f64) -> Ordering {
    if s.is_sign_negative() {
        mag.reverse()
    } else {
        mag
    }
}

#[inline(always)]
fn finish(s: f64, ord: Ordering, mode: u32) -> f64 {
    adjust(s, ord, mode)
}

#[inline(always)]
fn c_add(a: f64, b: f64, mode: u32) -> f64 {
    let s = a + b;
    if mode == NEAREST {
        return s;
    }
    if !s.is_finite() {
        if a.is_finite() && b.is_finite() {
            return overflow(s, mode);
        }
        return s;
    }
    // TwoSum: err = (a + b) - s exactly.
    let bb = s - a;
    let mut err = (a - (s - bb)) + (b - bb);
    if !err.is_finite() {
        // Spurious intermediate overflow next to MAX: halve (exact for
        // operands this large unless one is tiny, where the large one
        // decides s alone) and take the error's sign from the halves.
        let (ha, hb) = (a * 0.5, b * 0.5);
        let hs = ha + hb;
        let hbb = hs - ha;
        err = (ha - (hs - hbb)) + (hb - hbb);
    }
    if s == 0.0 {
        // Addition never underflows inexactly, so s == 0 is exact. Only
        // the sign is mode-dependent: x + (-x) and (+0) + (-0) are -0
        // when rounding down, +0 otherwise; (-0) + (-0) is -0 always.
        if mode == DOWN && !(a.to_bits() == 0 && b.to_bits() == 0) {
            return -0.0;
        }
        return s;
    }
    finish(s, err.partial_cmp(&0.0).unwrap_or(Ordering::Equal), mode)
}

/// Does `imp` take the FMA residual where it is exact?
#[inline(always)]
fn use_fma(imp: Impl) -> bool {
    imp == Impl::C
}

/// `a * b + c` with one rounding: `f64::mul_add`, the CPU's FMA where
/// it has one and libm's correctly rounded `fma` where not.
#[inline(always)]
fn fma(a: f64, b: f64, c: f64) -> f64 {
    a.mul_add(b, c)
}

/// Unbiased exponent of a finite nonzero normal `x`; `i32::MIN` for
/// zero and subnormals (which send the caller to the integer path).
#[inline(always)]
fn exp_of(x: f64) -> i32 {
    let field = ((x.to_bits() >> 52) & 0x7FF) as i32;
    if field == 0 {
        i32::MIN / 4
    } else {
        field - 1023
    }
}

/// The FMA residual is exact when its granularity, `2^(e1-52+e2-52)`,
/// is at least the smallest subnormal and the operands are normal.
const FMA_EXACT_MIN_EXP_SUM: i32 = -970;

#[inline(always)]
fn c_mul(a: f64, b: f64, mode: u32, imp: Impl) -> f64 {
    let s = a * b;
    if mode == NEAREST {
        return s;
    }
    if !s.is_finite() {
        if a.is_finite() && b.is_finite() {
            return overflow(s, mode);
        }
        return s;
    }
    if a == 0.0 || b == 0.0 {
        return s; // exact; RN's sign is every mode's sign
    }
    let ord = if use_fma(imp) && exp_of(a) + exp_of(b) >= FMA_EXACT_MIN_EXP_SUM {
        fma(a, b, -s).partial_cmp(&0.0).unwrap_or(Ordering::Equal)
    } else {
        signed(cmp_product(a, b, s), s)
    };
    finish(s, ord, mode)
}

#[inline(always)]
fn c_div(a: f64, b: f64, mode: u32, imp: Impl) -> f64 {
    let s = a / b;
    if mode == NEAREST {
        return s;
    }
    if !s.is_finite() {
        if a.is_finite() && b.is_finite() && b != 0.0 {
            return overflow(s, mode);
        }
        return s; // inf operand, division by zero, or NaN: exact or no rounding
    }
    if a == 0.0 || b.is_infinite() {
        return s; // exact zero
    }
    // true = a / b; sign(true - s) = sign(a - s*b) * sign(b).
    let ord = if use_fma(imp)
        && exp_of(s) + exp_of(b) >= FMA_EXACT_MIN_EXP_SUM
        && exp_of(a) >= FMA_EXACT_MIN_EXP_SUM
    {
        let r = fma(-s, b, a);
        let o = r.partial_cmp(&0.0).unwrap_or(Ordering::Equal);
        if b.is_sign_negative() {
            o.reverse()
        } else {
            o
        }
    } else {
        // |true| vs |s|  <=>  |a| vs |s * b|
        if s == 0.0 {
            // underflowed to zero from a nonzero quotient
            signed(Ordering::Greater, s)
        } else {
            signed(cmp_product(s, b, a).reverse(), s)
        }
    };
    finish(s, ord, mode)
}

#[inline(always)]
fn c_sqrt(a: f64, mode: u32, imp: Impl) -> f64 {
    let s = a.sqrt();
    if mode == NEAREST || !s.is_finite() || s == 0.0 {
        return s; // NaN, +inf, and +-0 are exact
    }
    let ord = if use_fma(imp) && 2 * exp_of(s) >= FMA_EXACT_MIN_EXP_SUM {
        fma(-s, s, a).partial_cmp(&0.0).unwrap_or(Ordering::Equal)
    } else {
        // true vs s  <=>  a vs s*s
        cmp_product(s, s, a).reverse()
    };
    finish(s, ord, mode)
}

#[inline(always)]
fn c_op(op: Op, a: [f64; 2], b: [f64; 2], mode: u32, imp: Impl) -> [f64; 2] {
    if mode == NEAREST {
        return nearest(op, a, b);
    }
    let f = |x: f64, y: f64| match op {
        Op::Add => c_add(x, y, mode),
        Op::Sub => c_add(x, -y, mode),
        Op::Mul => c_mul(x, y, mode, imp),
        Op::Div => c_div(x, y, mode, imp),
        Op::Sqrt => c_sqrt(x, mode, imp),
    };
    [f(a[0], b[0]), f(a[1], b[1])]
}

/// One packed RandomX operation under `mode`, by `imp`.
pub(crate) fn op(imp: Impl, op: Op, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
    c_op(op, a, b, mode, imp)
}
