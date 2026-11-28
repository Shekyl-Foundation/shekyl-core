// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RandomX floating-point rounding, quarantined.
//!
//! RandomX rounds every floating-point instruction by the mode the
//! last CFROUND chose: `0` nearest, `1` down, `2` up, `3` toward zero.
//! The compiler assumes ordinary Rust floating-point code runs under
//! the thread's control word, so the mode never stays in the hardware.
//! Each RandomX floating-point instruction runs in one `asm!` block
//! that
//!
//! 1. writes a fixed control word: the IEEE defaults plus the mode,
//!    with flush-to-zero and denormals-are-zero off and every exception
//!    masked;
//! 2. computes both lanes;
//! 3. writes back the caller's word before the block ends.
//!
//! So results are IEEE 754 on every architecture whatever the caller's
//! word holds, and a hash, or a panic out of one, leaves the caller's
//! control bits as it found them: no block can unwind, and nothing
//! else here writes the register.
//!
//! The caller's word is read once per program run
//! ([`FpEnv::capture`], from `VmState::execute_program`), not per
//! instruction. While the mode is nearest and the caller's word is
//! already the fixed nearest word, an instruction is plain Rust. That
//! fact is fixed for the run, so the VM decides it once per iteration
//! and runs one of two instruction loops (the `PLAIN` parameter of the
//! operations); an instruction tests only its mode.
//!
//! This module is the crate's only reader and writer of MXCSR / FPCR;
//! `scripts/ci/check_randomx_fpu_rounding.sh` holds it to a fixed
//! count of `asm!` blocks.
//!
//! ## What each block promises the compiler
//!
//! - x86_64 arithmetic: `readonly` (the two `ldmxcsr` read the fixed
//!   and the caller's word through their pointers; nothing is written
//!   to memory) and `nostack` (nothing is pushed). Operands are
//!   declared in full: the four lanes as `xmm` registers, two of them
//!   `inout`; no other register is touched.
//! - aarch64 arithmetic: `nomem` (`msr` and the arithmetic read and
//!   write no memory) and `nostack`. Operands as on x86_64, in `v`
//!   registers; the two words arrive in general registers.
//! - Not promised: `pure`, because the arithmetic raises exception
//!   flags (MXCSR's status bits, FPSR), a side effect; and
//!   `preserves_flags`, which on x86 covers MXCSR's exception flags
//!   and on aarch64 FPSR, both of which the arithmetic sets.
//! - The once-per-run read and the test-only write promise nothing.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("shekyl-pow-randomx FPU rounding is implemented only for x86_64 and aarch64");

#[cfg(test)]
pub(crate) mod fp_census;
#[cfg(test)]
pub(crate) mod oracle;
#[cfg(test)]
mod tests;

/// RandomX's round-to-nearest mode: `fprc` when a hash starts.
pub(crate) const NEAREST: u32 = 0;

/// The control register's width: MXCSR is 32 bits, FPCR 64.
#[cfg(target_arch = "x86_64")]
pub(crate) type ControlWord = u32;
/// The control register's width: MXCSR is 32 bits, FPCR 64.
#[cfg(target_arch = "aarch64")]
pub(crate) type ControlWord = u64;

/// MXCSR's status flags (bits 0..=5). Ordinary floating-point code
/// sets them, so comparisons of the caller's word leave them out.
#[cfg(target_arch = "x86_64")]
const STATUS_FLAGS: ControlWord = 0x3F;
/// FPCR holds no status flags (they live in FPSR).
#[cfg(target_arch = "aarch64")]
const STATUS_FLAGS: ControlWord = 0;

/// The fixed control word for RandomX mode `mode`: MXCSR with every
/// exception masked (bits 7..=12), denormals-are-zero (bit 6) and
/// flush-to-zero (bit 15) off, no status flag, and the rounding
/// control (bits 13..=14) set to `mode`, whose encoding RandomX shares
/// with MXCSR.
#[cfg(target_arch = "x86_64")]
const fn fixed_word(mode: u32) -> ControlWord {
    0x1F80 | ((mode & 3) << 13)
}

/// The fixed control word for RandomX mode `mode`: FPCR with every
/// field at its reset value (no exception trapped, flush-to-zero and
/// default-NaN off, the alternate behaviours off) except `RMode`
/// (bits 22..=23). FPCR encodes nearest, up, down, toward zero as
/// 0, 1, 2, 3, so RandomX's 1 (down) and 2 (up) swap.
#[cfg(target_arch = "aarch64")]
const fn fixed_word(mode: u32) -> ControlWord {
    let m = (mode & 3) as u64;
    ((m & 1) << 23) | ((m & 2) << 21)
}

/// The four fixed words, indexed by RandomX mode.
const FIXED_WORDS: [ControlWord; 4] = [fixed_word(0), fixed_word(1), fixed_word(2), fixed_word(3)];

/// The fixed words at an address: `ldmxcsr` takes no register
/// operand, so the x86_64 blocks read the fixed word from memory. One
/// promoted array, so a block's operand is the array's address plus
/// four times the mode, with no pointer to load first (the crate has no
/// `static` items, `check_randomx_crate_invariants.sh`).
#[cfg(target_arch = "x86_64")]
const FIXED_TABLE: &[ControlWord; 4] = &FIXED_WORDS;

/// What a program run needs to compute RandomX floating-point
/// instructions: the caller's word.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FpEnv {
    /// The caller's word, written back at the end of every block.
    caller: ControlWord,
    /// The caller's control bits are the fixed nearest word, so a
    /// nearest-mode instruction can run as plain Rust.
    plain_nearest: bool,
}

impl FpEnv {
    /// The environment of a thread whose word is the IEEE default,
    /// which every supported OS starts threads with. For a
    /// `VmState` that has not run a program yet; every program run
    /// replaces it with [`Self::capture`].
    pub(crate) const DEFAULT: Self = Self {
        caller: FIXED_WORDS[0],
        plain_nearest: true,
    };

    /// Read the calling thread's word.
    pub(crate) fn capture() -> Self {
        let caller = read_word();
        Self {
            caller,
            plain_nearest: caller & !STATUS_FLAGS == FIXED_WORDS[0],
        }
    }

    /// The caller's control bits are the fixed nearest word: the VM
    /// runs its instruction loop with `PLAIN = true`.
    #[inline(always)]
    pub(crate) fn plain_nearest(&self) -> bool {
        self.plain_nearest
    }

    /// Plain Rust for this instruction: nearest mode, in a loop the VM
    /// runs only when [`Self::plain_nearest`] holds. With `PLAIN =
    /// false` every instruction goes through a block.
    #[inline(always)]
    fn plain<const PLAIN: bool>(&self, mode: u32) -> bool {
        debug_assert!(
            !PLAIN || self.plain_nearest,
            "PLAIN loop under a caller whose word is not the fixed nearest word"
        );
        PLAIN && mode == NEAREST
    }

    /// The fixed word for `mode` as the x86_64 blocks take it: a
    /// reference into [`FIXED_TABLE`].
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn fixed_arg(mode: u32) -> &'static ControlWord {
        &FIXED_TABLE[(mode & 3) as usize]
    }

    /// The fixed word for `mode` as the aarch64 blocks take it: in a
    /// register, computed from the mode. A table here costs a load
    /// chain in front of every `msr` once the table's address is
    /// spilled (RANDOMX_ROUNDING_DECISION.md §6).
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn fixed_arg(mode: u32) -> ControlWord {
        fixed_word(mode)
    }

    /// The caller's word as the x86_64 blocks take it: by reference.
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn caller_arg(&self) -> &ControlWord {
        &self.caller
    }

    /// The caller's word as the aarch64 blocks take it: in a register.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn caller_arg(&self) -> ControlWord {
        self.caller
    }

    /// `a + b` per lane, rounded by `mode`.
    #[inline(always)]
    pub(crate) fn add<const PLAIN: bool>(&self, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
        let r = if self.plain::<PLAIN>(mode) {
            [a[0] + b[0], a[1] + b[1]]
        } else {
            hw::add(Self::fixed_arg(mode), self.caller_arg(), a, b)
        };
        #[cfg(test)]
        fp_census::note(fp_census::Op::Add, mode, a, b, r);
        r
    }

    /// `a - b` per lane, rounded by `mode`.
    #[inline(always)]
    pub(crate) fn sub<const PLAIN: bool>(&self, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
        let r = if self.plain::<PLAIN>(mode) {
            [a[0] - b[0], a[1] - b[1]]
        } else {
            hw::sub(Self::fixed_arg(mode), self.caller_arg(), a, b)
        };
        #[cfg(test)]
        fp_census::note(fp_census::Op::Sub, mode, a, b, r);
        r
    }

    /// `a * b` per lane, rounded by `mode`.
    #[inline(always)]
    pub(crate) fn mul<const PLAIN: bool>(&self, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
        let r = if self.plain::<PLAIN>(mode) {
            [a[0] * b[0], a[1] * b[1]]
        } else {
            hw::mul(Self::fixed_arg(mode), self.caller_arg(), a, b)
        };
        #[cfg(test)]
        fp_census::note(fp_census::Op::Mul, mode, a, b, r);
        r
    }

    /// `a / b` per lane, rounded by `mode`.
    #[inline(always)]
    pub(crate) fn div<const PLAIN: bool>(&self, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
        let r = if self.plain::<PLAIN>(mode) {
            [a[0] / b[0], a[1] / b[1]]
        } else {
            hw::div(Self::fixed_arg(mode), self.caller_arg(), a, b)
        };
        #[cfg(test)]
        fp_census::note(fp_census::Op::Div, mode, a, b, r);
        r
    }

    /// `sqrt(a)` per lane, rounded by `mode`.
    #[inline(always)]
    pub(crate) fn sqrt<const PLAIN: bool>(&self, a: [f64; 2], mode: u32) -> [f64; 2] {
        let r = if self.plain::<PLAIN>(mode) {
            [a[0].sqrt(), a[1].sqrt()]
        } else {
            hw::sqrt(Self::fixed_arg(mode), self.caller_arg(), a)
        };
        #[cfg(test)]
        fp_census::note(fp_census::Op::Sqrt, mode, a, a, r);
        r
    }
}

#[cfg(target_arch = "x86_64")]
mod hw {
    use super::ControlWord;
    use core::arch::asm;

    macro_rules! binop {
        ($name:ident, $insn:literal) => {
            #[inline(always)]
            #[allow(unsafe_code)]
            pub(super) fn $name(fixed: &ControlWord, caller: &ControlWord, mut a: [f64; 2], b: [f64; 2]) -> [f64; 2] {
                // SAFETY: the block reads the two words through their
                // pointers and writes MXCSR twice, the second time back
                // to the caller's word; it writes no memory, pushes
                // nothing, and touches no register but the declared
                // `xmm` operands (module doc, "What each block
                // promises the compiler").
                unsafe {
                    asm!(
                        "ldmxcsr [{fixed}]",
                        concat!($insn, " {a0}, {b0}"),
                        concat!($insn, " {a1}, {b1}"),
                        "ldmxcsr [{caller}]",
                        fixed = in(reg) fixed,
                        caller = in(reg) caller,
                        a0 = inout(xmm_reg) a[0],
                        a1 = inout(xmm_reg) a[1],
                        b0 = in(xmm_reg) b[0],
                        b1 = in(xmm_reg) b[1],
                        options(readonly, nostack),
                    );
                }
                a
            }
        };
    }
    binop!(add, "addsd");
    binop!(sub, "subsd");
    binop!(mul, "mulsd");
    binop!(div, "divsd");

    #[inline(always)]
    #[allow(unsafe_code)]
    pub(super) fn sqrt(fixed: &ControlWord, caller: &ControlWord, mut a: [f64; 2]) -> [f64; 2] {
        // SAFETY: as in `binop!`.
        unsafe {
            asm!(
                "ldmxcsr [{fixed}]",
                "sqrtsd {a0}, {a0}",
                "sqrtsd {a1}, {a1}",
                "ldmxcsr [{caller}]",
                fixed = in(reg) fixed,
                caller = in(reg) caller,
                a0 = inout(xmm_reg) a[0],
                a1 = inout(xmm_reg) a[1],
                options(readonly, nostack),
            );
        }
        a
    }

    /// The calling thread's MXCSR.
    #[allow(unsafe_code)]
    pub(super) fn read() -> ControlWord {
        let mut word: ControlWord = 0;
        // SAFETY: `stmxcsr` stores MXCSR into the local `word`; nothing
        // else is read or written.
        unsafe { asm!("stmxcsr [{p}]", p = in(reg) &raw mut word) };
        word
    }

    /// Test-only: set the calling thread's MXCSR, standing in for a
    /// caller that runs with another word.
    #[cfg(test)]
    #[allow(unsafe_code)]
    pub(super) fn write(word: ControlWord) {
        // SAFETY: `ldmxcsr` loads MXCSR from the local `word`. The
        // tests that call it put the default back before they end.
        unsafe { asm!("ldmxcsr [{p}]", p = in(reg) &raw const word) };
    }
}

#[cfg(target_arch = "aarch64")]
mod hw {
    use super::ControlWord;
    use core::arch::asm;

    // A write to FPCR applies to the instructions after it with no
    // barrier, as glibc's `fesetround` relies on.

    macro_rules! binop {
        ($name:ident, $insn:literal) => {
            #[inline(always)]
            #[allow(unsafe_code)]
            pub(super) fn $name(fixed: ControlWord, caller: ControlWord, mut a: [f64; 2], b: [f64; 2]) -> [f64; 2] {
                // SAFETY: the block writes FPCR twice, the second time
                // back to the caller's word; it reads and writes no
                // memory, pushes nothing, and touches no register but
                // the declared operands (module doc, "What each block
                // promises the compiler").
                unsafe {
                    asm!(
                        "msr fpcr, {fixed}",
                        concat!($insn, " {a0:d}, {a0:d}, {b0:d}"),
                        concat!($insn, " {a1:d}, {a1:d}, {b1:d}"),
                        "msr fpcr, {caller}",
                        fixed = in(reg) fixed,
                        caller = in(reg) caller,
                        a0 = inout(vreg) a[0],
                        a1 = inout(vreg) a[1],
                        b0 = in(vreg) b[0],
                        b1 = in(vreg) b[1],
                        options(nomem, nostack),
                    );
                }
                a
            }
        };
    }
    binop!(add, "fadd");
    binop!(sub, "fsub");
    binop!(mul, "fmul");
    binop!(div, "fdiv");

    #[inline(always)]
    #[allow(unsafe_code)]
    pub(super) fn sqrt(fixed: ControlWord, caller: ControlWord, mut a: [f64; 2]) -> [f64; 2] {
        // SAFETY: as in `binop!`.
        unsafe {
            asm!(
                "msr fpcr, {fixed}",
                "fsqrt {a0:d}, {a0:d}",
                "fsqrt {a1:d}, {a1:d}",
                "msr fpcr, {caller}",
                fixed = in(reg) fixed,
                caller = in(reg) caller,
                a0 = inout(vreg) a[0],
                a1 = inout(vreg) a[1],
                options(nomem, nostack),
            );
        }
        a
    }

    /// The calling thread's FPCR.
    #[allow(unsafe_code)]
    pub(super) fn read() -> ControlWord {
        let word: ControlWord;
        // SAFETY: `mrs` copies FPCR into a register; nothing else is
        // read or written.
        unsafe { asm!("mrs {w}, fpcr", w = out(reg) word) };
        word
    }

    /// Test-only: set the calling thread's FPCR, standing in for a
    /// caller that runs with another word.
    #[cfg(test)]
    #[allow(unsafe_code)]
    pub(super) fn write(word: ControlWord) {
        // SAFETY: `msr` writes FPCR. The tests that call it put the
        // default back before they end.
        unsafe { asm!("msr fpcr, {w}", w = in(reg) word) };
    }
}

fn read_word() -> ControlWord {
    hw::read()
}

/// Test-only: the calling thread's control bits (MXCSR without its
/// status flags; FPCR whole).
#[cfg(test)]
pub(crate) fn control_bits() -> ControlWord {
    read_word() & !STATUS_FLAGS
}

/// Test-only: a caller's word with flush-to-zero (and, on x86_64,
/// denormals-are-zero) on, rounding to nearest.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) const FLUSH_TO_ZERO_WORD: ControlWord = FIXED_WORDS[0] | (1 << 15) | (1 << 6);
/// Test-only: a caller's word with flush-to-zero (and, on x86_64,
/// denormals-are-zero) on, rounding to nearest.
#[cfg(all(test, target_arch = "aarch64"))]
pub(crate) const FLUSH_TO_ZERO_WORD: ControlWord = FIXED_WORDS[0] | (1 << 24);

/// Test-only: run `f` with the calling thread's word set to `word`,
/// putting the word found back afterwards, also on unwind.
#[cfg(test)]
pub(crate) fn with_caller_word<R>(word: ControlWord, f: impl FnOnce() -> R) -> R {
    struct Restore(ControlWord);
    impl Drop for Restore {
        fn drop(&mut self) {
            hw::write(self.0);
        }
    }
    let _restore = Restore(read_word());
    hw::write(word);
    f()
}
