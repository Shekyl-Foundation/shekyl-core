// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PROTOTYPE (not for merge): the two candidate fixes for RandomX's
//! directed rounding, side by side, so they can be measured.
//!
//! RandomX rounds every FP instruction by the mode CFROUND last set
//! (`0` nearest, `1` down, `2` up, `3` toward zero). Today the crate
//! writes that mode into MXCSR / FPCR and runs ordinary Rust FP code
//! under it, which breaks the compiler's assumption that FP code runs
//! at round-to-nearest. Both candidates keep the hardware at nearest
//! everywhere Rust code runs:
//!
//! - `b`: one `asm!` block per instruction that saves the control
//!   register, writes the mode, computes, and restores. Plain Rust while
//!   the mode is nearest.
//! - `c`: compute at round-to-nearest in plain Rust, then move the
//!   result by at most one step, decided by the exact sign of the
//!   rounding error. The error comes from TwoSum for add/sub, and for
//!   mul/div/sqrt from an FMA residual where the CPU has FMA and is in
//!   range, otherwise from an exact integer comparison.
//!
//! Both are selected per call by [`Impl`] so one binary can fuzz them
//! against each other; the VM picks one at compile time.

#![allow(dead_code, unused_imports)]

use core::cmp::Ordering;

/// RandomX rounding modes, the `fprc` encoding.
pub(crate) const NEAREST: u32 = 0;
pub(crate) const DOWN: u32 = 1;
pub(crate) const UP: u32 = 2;
pub(crate) const TOWARD_ZERO: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
}

/// Which candidate computes the op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Impl {
    /// Hardware mode set per instruction in `asm!`.
    B,
    /// Software correction, FMA residual where available.
    C,
    /// Software correction, integer comparison only (the pre-FMA path).
    CInt,
}

// ---------------------------------------------------------------- (b)

#[cfg(target_arch = "x86_64")]
mod hw {
    use core::arch::asm;

    macro_rules! binop {
        ($name:ident, $insn:literal) => {
            #[inline(always)]
            #[allow(unsafe_code)]
            pub(crate) fn $name(mut a0: f64, mut a1: f64, b0: f64, b1: f64, mode: u32) -> (f64, f64) {
                // csr[0] = the caller's MXCSR, csr[1] = it with RC = mode.
                let mut csr = [0u32; 2];
                let rc = (mode & 3) << 13;
                // SAFETY: reads and writes MXCSR and the two-word local
                // `csr`; restores the caller's MXCSR before the block ends.
                unsafe {
                    asm!(
                        "stmxcsr [{csr}]",
                        "mov {t:e}, [{csr}]",
                        "and {t:e}, 0xFFFF9FFF",
                        "or {t:e}, {rc:e}",
                        "mov [{csr} + 4], {t:e}",
                        "ldmxcsr [{csr} + 4]",
                        concat!($insn, " {a0}, {b0}"),
                        concat!($insn, " {a1}, {b1}"),
                        "ldmxcsr [{csr}]",
                        csr = in(reg) csr.as_mut_ptr(),
                        t = out(reg) _,
                        rc = in(reg) rc,
                        a0 = inout(xmm_reg) a0,
                        a1 = inout(xmm_reg) a1,
                        b0 = in(xmm_reg) b0,
                        b1 = in(xmm_reg) b1,
                        options(nostack),
                    );
                }
                (a0, a1)
            }
        };
    }
    binop!(add, "addsd");
    binop!(sub, "subsd");
    binop!(mul, "mulsd");
    binop!(div, "divsd");

    #[inline(always)]
    #[allow(unsafe_code)]
    pub(crate) fn sqrt(mut a0: f64, mut a1: f64, mode: u32) -> (f64, f64) {
        let mut csr = [0u32; 2];
        let rc = (mode & 3) << 13;
        // SAFETY: as in `binop!`.
        unsafe {
            asm!(
                "stmxcsr [{csr}]",
                "mov {t:e}, [{csr}]",
                "and {t:e}, 0xFFFF9FFF",
                "or {t:e}, {rc:e}",
                "mov [{csr} + 4], {t:e}",
                "ldmxcsr [{csr} + 4]",
                "sqrtsd {a0}, {a0}",
                "sqrtsd {a1}, {a1}",
                "ldmxcsr [{csr}]",
                csr = in(reg) csr.as_mut_ptr(),
                t = out(reg) _,
                rc = in(reg) rc,
                a0 = inout(xmm_reg) a0,
                a1 = inout(xmm_reg) a1,
                options(nostack),
            );
        }
        (a0, a1)
    }

    /// The thread's MXCSR control bits (status flags 0..=5 masked
    /// off: ordinary FP code sets them), for the leak test.
    #[allow(unsafe_code)]
    pub(crate) fn control_word() -> u64 {
        let mut csr = 0u32;
        // SAFETY: stores MXCSR into a local.
        unsafe { asm!("stmxcsr [{p}]", p = in(reg) &mut csr, options(nostack)) };
        u64::from(csr & !0x3F)
    }
}

#[cfg(target_arch = "aarch64")]
mod hw {
    use core::arch::asm;

    /// RandomX mode -> FPCR.RMode bits (RN, RP, RM, RZ = 0, 1, 2, 3 in
    /// FPCR; RandomX's 1 = down and 2 = up are swapped).
    #[inline(always)]
    fn rmode(mode: u32) -> u64 {
        let m = u64::from(mode & 3);
        ((m & 1) << 23) | ((m & 2) << 21)
    }

    macro_rules! binop {
        ($name:ident, $insn:literal) => {
            #[inline(always)]
            #[allow(unsafe_code)]
            pub(crate) fn $name(mut a0: f64, mut a1: f64, b0: f64, b1: f64, mode: u32) -> (f64, f64) {
                // SAFETY: reads and writes FPCR only, and restores the
                // caller's FPCR before the block ends.
                unsafe {
                    asm!(
                        "mrs {old}, fpcr",
                        "bic {new}, {old}, #0xC00000",
                        "orr {new}, {new}, {rm}",
                        "msr fpcr, {new}",
                        concat!($insn, " {a0:d}, {a0:d}, {b0:d}"),
                        concat!($insn, " {a1:d}, {a1:d}, {b1:d}"),
                        "msr fpcr, {old}",
                        old = out(reg) _,
                        new = out(reg) _,
                        rm = in(reg) rmode(mode),
                        a0 = inout(vreg) a0,
                        a1 = inout(vreg) a1,
                        b0 = in(vreg) b0,
                        b1 = in(vreg) b1,
                        options(nomem, nostack),
                    );
                }
                (a0, a1)
            }
        };
    }
    binop!(add, "fadd");
    binop!(sub, "fsub");
    binop!(mul, "fmul");
    binop!(div, "fdiv");

    #[inline(always)]
    #[allow(unsafe_code)]
    pub(crate) fn sqrt(mut a0: f64, mut a1: f64, mode: u32) -> (f64, f64) {
        // SAFETY: as in `binop!`.
        unsafe {
            asm!(
                "mrs {old}, fpcr",
                "bic {new}, {old}, #0xC00000",
                "orr {new}, {new}, {rm}",
                "msr fpcr, {new}",
                "fsqrt {a0:d}, {a0:d}",
                "fsqrt {a1:d}, {a1:d}",
                "msr fpcr, {old}",
                old = out(reg) _,
                new = out(reg) _,
                rm = in(reg) rmode(mode),
                a0 = inout(vreg) a0,
                a1 = inout(vreg) a1,
                options(nomem, nostack),
            );
        }
        (a0, a1)
    }

    /// The thread's FPCR, for the leak test.
    #[allow(unsafe_code)]
    pub(crate) fn control_word() -> u64 {
        let v: u64;
        // SAFETY: reads FPCR.
        unsafe { asm!("mrs {v}, fpcr", v = out(reg) v, options(nomem, nostack)) };
        v
    }
}

pub(crate) use hw::control_word;

#[inline(always)]
fn b_op(op: Op, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
    if mode == NEAREST {
        return nearest(op, a, b);
    }
    let (r0, r1) = match op {
        Op::Add => hw::add(a[0], a[1], b[0], b[1], mode),
        Op::Sub => hw::sub(a[0], a[1], b[0], b[1], mode),
        Op::Mul => hw::mul(a[0], a[1], b[0], b[1], mode),
        Op::Div => hw::div(a[0], a[1], b[0], b[1], mode),
        Op::Sqrt => hw::sqrt(a[0], a[1], mode),
    };
    [r0, r1]
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

// ---------------------------------------------------------------- (c)

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
        let bits = 64 - mz.leading_zeros() as i32; // mz >= 1
        if bits - 1 + d >= 127 {
            return Ordering::Less;
        }
        p.cmp(&(u128::from(mz) << d))
    } else {
        // p * 2^s vs mz, s = -d > 0. When p << s would reach 2^127 it
        // exceeds mz < 2^53 without being computed.
        let s = -d;
        let bits = 128 - p.leading_zeros() as i32; // p >= 1
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
        (_, Ordering::Equal) => s,
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
        (DOWN, false) | (TOWARD_ZERO, false) => f64::MAX,
        (UP, true) | (TOWARD_ZERO, true) => -f64::MAX,
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

#[cfg(feature = "proto-fp-census")]
pub mod census {
    use std::cell::RefCell;

    #[derive(Default, Clone, Debug)]
    pub struct Census {
        /// ops[op][mode]
        pub ops: [[u64; 4]; 5],
        pub result_subnormal: u64,
        pub result_zero: u64,
        pub result_inf: u64,
        pub result_nan: u64,
        pub input_subnormal: u64,
        pub input_inf: u64,
        pub c_slow_path: u64,
        pub c_overflow: u64,
        pub c_adjusted: u64,
        /// smallest positive normal-or-not magnitude seen in an E result
        pub min_e_result: f64,
        /// smallest nonzero |F result|
        pub min_f_result: f64,
        pub max_f_result: f64,
        pub max_runs_per_instruction: u64,
        pub max_fdiv_runs_per_e_register: u64,
        pub max_fdiv_instrs_per_e_register: u64,
        pub iterations: u64,
    }

    thread_local! {
        pub static CENSUS: RefCell<Census> = RefCell::new(Census {
            min_e_result: f64::INFINITY,
            min_f_result: f64::INFINITY,
            ..Default::default()
        });
    }

    pub fn take() -> Census {
        CENSUS.with(|c| {
            core::mem::replace(
                &mut *c.borrow_mut(),
                Census { min_e_result: f64::INFINITY, min_f_result: f64::INFINITY, ..Default::default() },
            )
        })
    }

    pub(crate) fn note(op: super::Op, mode: u32, a: [f64; 2], b: [f64; 2], r: [f64; 2]) {
        CENSUS.with(|c| {
            let mut c = c.borrow_mut();
            c.ops[op as usize][mode as usize & 3] += 1;
            let unary = matches!(op, super::Op::Sqrt);
            for i in 0..2 {
                let ins: &[f64] = if unary { &[a[i]] } else { &[a[i], b[i]] };
                for x in ins {
                    if x.is_subnormal() {
                        c.input_subnormal += 1;
                    }
                    if x.is_infinite() {
                        c.input_inf += 1;
                    }
                }
                let x = r[i];
                if x.is_subnormal() {
                    c.result_subnormal += 1;
                }
                if x == 0.0 {
                    c.result_zero += 1;
                }
                if x.is_infinite() {
                    c.result_inf += 1;
                }
                if x.is_nan() {
                    c.result_nan += 1;
                }
                let m = x.abs();
                match op {
                    super::Op::Add | super::Op::Sub => {
                        if m != 0.0 && m < c.min_f_result {
                            c.min_f_result = m;
                        }
                        if m.is_finite() && m > c.max_f_result {
                            c.max_f_result = m;
                        }
                    }
                    _ => {
                        if m < c.min_e_result {
                            c.min_e_result = m;
                        }
                    }
                }
            }
        });
    }

    pub(crate) fn slow() {
        CENSUS.with(|c| c.borrow_mut().c_slow_path += 1);
    }
    pub(crate) fn overflowed() {
        CENSUS.with(|c| c.borrow_mut().c_overflow += 1);
    }
    pub(crate) fn adjusted() {
        CENSUS.with(|c| c.borrow_mut().c_adjusted += 1);
    }
}

macro_rules! note {
    ($f:ident) => {{
        #[cfg(feature = "proto-fp-census")]
        census::$f();
    }};
}

#[inline(always)]
fn finish(s: f64, ord: Ordering, mode: u32) -> f64 {
    let r = adjust(s, ord, mode);
    #[cfg(feature = "proto-fp-census")]
    if r.to_bits() != s.to_bits() {
        census::adjusted();
    }
    r
}

#[inline(always)]
fn c_add(a: f64, b: f64, mode: u32) -> f64 {
    let s = a + b;
    if mode == NEAREST {
        return s;
    }
    if !s.is_finite() {
        if a.is_finite() && b.is_finite() {
            note!(overflowed);
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
        note!(slow);
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

/// FMA available? Cached by std's detection macro on x86_64; baseline
/// on aarch64.
#[inline(always)]
fn have_fma(imp: Impl) -> bool {
    if imp == Impl::CInt {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("fma")
    }
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
fn fma_x86(a: f64, b: f64, c: f64) -> f64 {
    use core::arch::x86_64::*;
    _mm_cvtsd_f64(_mm_fmadd_sd(_mm_set_sd(a), _mm_set_sd(b), _mm_set_sd(c)))
}

/// `a * b + c` with one rounding. Only called when `have_fma`.
#[inline(always)]
#[allow(unsafe_code)]
fn fma(a: f64, b: f64, c: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: called only after `is_x86_feature_detected!("fma")`.
        unsafe { fma_x86(a, b, c) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        a.mul_add(b, c)
    }
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
            note!(overflowed);
            return overflow(s, mode);
        }
        return s;
    }
    if a == 0.0 || b == 0.0 {
        return s; // exact; RN's sign is every mode's sign
    }
    let ord = if have_fma(imp) && exp_of(a) + exp_of(b) >= FMA_EXACT_MIN_EXP_SUM {
        fma(a, b, -s).partial_cmp(&0.0).unwrap_or(Ordering::Equal)
    } else {
        note!(slow);
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
            note!(overflowed);
            return overflow(s, mode);
        }
        return s; // inf operand, division by zero, or NaN: exact or no rounding
    }
    if a == 0.0 || b.is_infinite() {
        return s; // exact zero
    }
    // true = a / b; sign(true - s) = sign(a - s*b) * sign(b).
    let ord = if have_fma(imp)
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
        note!(slow);
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
    let ord = if have_fma(imp) && 2 * exp_of(s) >= FMA_EXACT_MIN_EXP_SUM {
        fma(-s, s, a).partial_cmp(&0.0).unwrap_or(Ordering::Equal)
    } else {
        note!(slow);
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

/// One packed RandomX FP op under `mode`, by `imp`.
#[inline(always)]
pub(crate) fn op(imp: Impl, op: Op, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
    let r = match imp {
        Impl::B => b_op(op, a, b, mode),
        Impl::C | Impl::CInt => c_op(op, a, b, mode, imp),
    };
    #[cfg(feature = "proto-fp-census")]
    census::note(op, mode, a, b, r);
    r
}

/// The implementation the VM uses, chosen at build time.
#[cfg(feature = "proto-rounding-b")]
pub(crate) const VM_IMPL: Impl = Impl::B;
#[cfg(all(feature = "proto-rounding-c", not(feature = "proto-rounding-c-int")))]
pub(crate) const VM_IMPL: Impl = Impl::C;
#[cfg(feature = "proto-rounding-c-int")]
pub(crate) const VM_IMPL: Impl = Impl::CInt;

#[cfg(test)]
mod tests;
