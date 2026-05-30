// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Quarantined RandomX floating-point rounding-mode setter.
//!
//! Phase 2d keeps host FPU state mutation in this module so the
//! implementation PR's grep gate can mechanically audit the unsafe
//! surface. The selected primitive is target-specific per
//! `RANDOMX_V2_PHASE2D_PLAN.md` §3.7 R6-D1: MXCSR on `x86_64`,
//! FPCR on `aarch64`, and compile-time rejection elsewhere.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("shekyl-pow-randomx FPU rounding is implemented only for x86_64 and aarch64");

/// Set the host FPU rounding mode to the RandomX mode `0..=3`.
///
/// RandomX uses the mode encoding from `rx_set_rounding_mode`: `0`
/// nearest, `1` down, `2` up, `3` toward zero. Callers pass only
/// `isrc % 4`; this function masks defensively to keep the hardware
/// write inside the same two-bit encoding.
#[cfg(target_arch = "x86_64")]
#[allow(deprecated, unsafe_code)]
pub(crate) fn set_rounding_mode(mode: u32) {
    const RX_MXCSR_DEFAULT: u32 = 0x9FC0;
    debug_assert!(mode < 4, "RandomX rounding mode must fit in two bits");

    // SAFETY: `_mm_setcsr` writes only the MXCSR control register.
    // The value is the C reference's `rx_mxcsr_default | (mode << 13)`.
    unsafe {
        core::arch::x86_64::_mm_setcsr(RX_MXCSR_DEFAULT | ((mode & 3) << 13));
    }
}

/// Set the host FPU rounding mode to the RandomX mode `0..=3`.
///
/// RandomX uses the mode encoding from `rx_set_rounding_mode`: `0`
/// nearest, `1` down, `2` up, `3` toward zero. AArch64 FPCR encodes
/// the same modes in `RMode` bits 22..=23 as RN/RU/RD/RZ, so modes
/// `1` and `2` are swapped when written to FPCR.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
pub(crate) fn set_rounding_mode(mode: u32) {
    const FPCR_RMODE_MASK: u64 = 0b11 << 22;

    debug_assert!(mode < 4, "RandomX rounding mode must fit in two bits");
    let mode = mode & 3;
    let fpcr_rmode = (u64::from(mode & 1) << 23) | (u64::from(mode & 2) << 21);

    // SAFETY: the two asm blocks read and write only FPCR. The write
    // preserves every FPCR bit except the rounding-mode field.
    unsafe {
        let old: u64;
        core::arch::asm!(
            "mrs {old}, fpcr",
            old = out(reg) old,
            options(nomem, nostack, preserves_flags),
        );
        let new = (old & !FPCR_RMODE_MASK) | fpcr_rmode;
        core::arch::asm!(
            "msr fpcr, {new}",
            new = in(reg) new,
            options(nomem, nostack, preserves_flags),
        );
    }
}
