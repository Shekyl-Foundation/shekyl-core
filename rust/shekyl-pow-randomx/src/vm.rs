// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RandomX v2 [`VmState`] — the per-hash transient state owned
//! internally by `compute_hash` (the free function landed by commit 6
//! of the same Phase 2c implementation PR).
//!
//! Per
//! [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §2 surface 3 + §3 module layout + §5.1.1 frozen `VmState` field
//! set, this module lands across three Phase 2c implementation-PR
//! commits:
//!
//! - **Commit 4 introduced** (as corrected by the R0-D9 fix-up
//!   immediately on top) the [`VmState`] struct skeleton with the frozen field set
//!   (per §5.1.1 + §5.5 F5 v2-only simplification), the [`F128`] /
//!   [`Instruction`] / [`Program`] type definitions, the
//!   [`PROGRAM_SIZE`] / [`PROGRAM_ITERATIONS`] /
//!   [`RANDOMX_SCRATCHPAD_L3`] spec constants, [`VmState::new`]
//!   (allocation-only constructor), the [`alloc_zeroed_scratchpad`]
//!   carve-out (Phase 2c's second and final `#![deny(unsafe_code)]`
//!   carve-out per §1 covenant 7 + §5.11.2), the scratchpad-
//!   allocation `debug_assert!` per §5.11.2, and the empty [`Drop`]
//!   (review-surface hook per §5.11.4).
//! - **Commit 5 introduced** (per §14 Round 0 R0-D8 Rust-idiomatic
//!   two-method init shape) [`VmState::init_scratchpad`] via
//!   [`crate::aes::fill_aes_1r_x4`], plus [`VmState::init_program`]
//!   (stack-allocate the [`PROGRAM_BUFFER_SIZE`] = 3_200-byte buffer
//!   per spec §4.5's `128 + 8 * RANDOMX_PROGRAM_SIZE` budget, fill
//!   via [`crate::aes::fill_aes_4r_x4`], parse entropy[0..128] into
//!   the register-init field set via
//!   [`get_small_positive_float_bits`] / [`get_float_mask`] /
//!   [`CACHE_LINE_ALIGN_MASK`] / [`DATASET_EXTRA_ITEMS`] /
//!   [`CACHE_LINE_SIZE`], parse instructions[128..3200] into
//!   `self.program.instructions`); plus the IEEE-754 / dataset
//!   constants the helpers consume; plus T3'/T4'/T5' fixture-free
//!   determinism property tests inline per §5.11.1.
//! - **Commit 6 introduced** (per §9 + §5.1.1 + §5.11.1 T6'-T8')
//!   [`compute_hash`] (the `pub` per-hash transform — the crate's
//!   single hash-producing entry point) + [`VmState::execute_program`]
//!   (the spec §4.6 / `vm_interpreted.cpp::execute()` 2048-iteration
//!   loop, single per-iteration body that the stub-NOP
//!   [`dispatch_instruction`] dispatches into per spec §4.6.5) + the
//!   private [`dispatch_instruction`] NOP-body stub (the §5.1
//!   function-body replacement contract Phase 2d fills in per
//!   §5.1.1 frozen surfaces 1–3); plus the supporting helpers
//!   ([`SCRATCHPAD_L3_MASK_64`] + [`DYNAMIC_MANTISSA_MASK`] +
//!   [`RANDOMX_PROGRAM_COUNT`] constants;
//!   [`cvt_packed_int_to_f128`] + [`mask_register_exponent_mantissa`]
//!   pure-function bytecode-machine helpers); plus T6'/T7'/T8'
//!   fixture-free determinism property tests inline per §5.11.1.
//!
//! # `compute_hash` cache-seedhash binding — typed via [`crate::PreparedCache`]
//!
//! Phase 2c shipped [`compute_hash`] with a
//! `(&Cache, &[u8; 32], &[u8])` signature where the seedhash was
//! documentary-only — the per-hash Blake2b chain consumes `H`
//! (data) and not `K` (seedhash; spec §2 / `randomx.cpp::randomx_calculate_hash`
//! lines 392-394 at pin `aaafe71`), so the seedhash parameter
//! existed solely to document the cache-binding contract that
//! "the cache used to compute this hash was derived from this
//! seedhash." The contract was convention-enforced; a caller
//! passing the wrong cache for a given seedhash got a
//! consensus-rejected hash (correct outcome) but no compile-time
//! check (avoidable footgun).
//!
//! Phase 2F §1.1 Round 2 closes the footgun by wrapping the pair
//! in [`crate::PreparedCache`], whose only public construction
//! path is [`crate::PreparedCache::derive(seedhash)`](crate::PreparedCache::derive).
//! [`compute_hash`] now takes `(&PreparedCache, &[u8])`; the
//! cache-seedhash binding is type-enforced at construction rather
//! than convention-enforced at the call site, and the seedhash
//! travels in the bundle for any future body-level cache-binding
//! assertions. The per-hash chain still consumes only `H` (the
//! `data` parameter) — the seedhash's role at this layer remains
//! documentary; only the documentation mechanism changed from
//! "third parameter" to "field on the bundle." See
//! [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
//! §1.1 / §3.1 Round 2 for the substrate-correction trail that
//! produced this disposition.
//!
//! # Threat-model disposition (per §5.11.4)
//!
//! The [`scratchpad`] field is **public-input-only**: every byte is a
//! deterministic function of `(seedhash, block_header)`, both of which
//! are public by construction (block-header field + chain-tip pinned
//! seedhash). No constant-time discipline applies to access patterns
//! over scratchpad memory, and no wipe-on-drop is load-bearing for
//! confidentiality. The empty [`Drop`] impl below exists as a
//! review-surface hook for future field additions that *would* carry
//! secret material (e.g., a hypothetical `ledger_session_secret`
//! field) — landing zeroization inside an already-present [`Drop`]
//! body, not requiring a future contributor to remember to add the
//! impl, is the architectural shape `35-secure-memory.mdc`'s
//! continuous-discipline corollary names.
//!
//! [`scratchpad`]: VmState::scratchpad

use core::mem::MaybeUninit;

/// IEEE-754 binary64 register-pair carrying a single RandomX FP
/// register's two `double` lanes.
///
/// Spec §5.2 defines `f0`..`f3`, `e0`..`e3`, `a0`..`a3` as
/// register pairs holding two `double`s each; the C reference uses
/// SSE2 `__m128d` (`bytecode_machine.hpp:38-44`). The Rust port
/// represents each pair as `[f64; 2]` rather than a SIMD intrinsic
/// type for portability across non-x86 targets (RISC-V `rv64gc` is
/// a supported verifier platform per
/// [`RANDOMX_V2_PLAN.md`](../../../docs/design/RANDOMX_V2_PLAN.md)).
///
/// # Phase 2d shape (R1-D2 minimal newtype)
///
/// Phase 2d promotes the Phase 2c `type F128 = [f64; 2]` alias to a
/// `struct` newtype per
/// [`RANDOMX_V2_PHASE2D_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2D_PLAN.md)
/// §3.2 R1-D2. The inner `[f64; 2]` lane layout is unchanged; FP
/// opcode methods land in the same commit series as their dispatch
/// arms. Integer helpers (`rotr`, `rotl`, `load64`, `store64`) live
/// alongside this type as private `fn` items for bytecode dispatch.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct F128(pub(crate) [f64; 2]);

impl core::ops::Index<usize> for F128 {
    type Output = f64;

    fn index(&self, index: usize) -> &f64 {
        &self.0[index]
    }
}

impl core::ops::IndexMut<usize> for F128 {
    fn index_mut(&mut self, index: usize) -> &mut f64 {
        &mut self.0[index]
    }
}

impl F128 {
    fn add_unrestricted(self, rhs: Self) -> Self {
        Self([self[0] + rhs[0], self[1] + rhs[1]])
    }

    fn sub_unrestricted(self, rhs: Self) -> Self {
        Self([self[0] - rhs[0], self[1] - rhs[1]])
    }

    fn mul_unrestricted(self, rhs: Self) -> Self {
        Self([self[0] * rhs[0], self[1] * rhs[1]])
    }

    fn div_masked(self, rhs: Self) -> Self {
        Self([self[0] / rhs[0], self[1] / rhs[1]])
    }

    fn sqrt_unrestricted(self) -> Self {
        Self([self[0].sqrt(), self[1].sqrt()])
    }

    fn swap_lanes(self) -> Self {
        Self([self[1], self[0]])
    }

    fn xor_with_scale_mask(self) -> Self {
        const FSCAL_MASK: u64 = 0x80F0_0000_0000_0000;
        Self([
            f64::from_bits(self[0].to_bits() ^ FSCAL_MASK),
            f64::from_bits(self[1].to_bits() ^ FSCAL_MASK),
        ])
    }
}

/// Number of [`Instruction`]s in a single RandomX v2 [`Program`].
///
/// `RANDOMX_PROGRAM_SIZE_V2 = 384` per
/// [`external/randomx-v2/src/configuration.h:57`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.5 F5 (v2-only simplification), the Rust port carries no
/// `PROGRAM_SIZE_V1` constant — v2 is structural, not a runtime
/// flag, and the V1 program size (256 instructions) is unreachable.
///
/// # Distinct from [`PROGRAM_ITERATIONS`] (R0-D9 anchor)
///
/// Per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §14 Round 0 R0-D9, `PROGRAM_SIZE` (the per-program instruction
/// count, 384) is structurally distinct from [`PROGRAM_ITERATIONS`]
/// (the per-program outer-loop iteration count, 2048). Each program
/// is executed [`PROGRAM_ITERATIONS`] times, and each iteration
/// dispatches through all [`PROGRAM_SIZE`] instructions in sequence.
/// Conflating the two produces a 5× over-allocation of the
/// [`Program`] buffer (an earlier draft of this constant carried
/// `2048` and was corrected via R0-D9). The two constants are
/// defined together below to make the distinction structurally
/// explicit at every reading.
pub(crate) const PROGRAM_SIZE: usize = 384;

/// Number of times each RandomX v2 [`Program`] is executed per hash.
///
/// `RANDOMX_PROGRAM_ITERATIONS = 2048` per
/// [`external/randomx-v2/src/configuration.h:62`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Consumed by `VmState::run`'s outer iteration
/// loop (commit 6) mirroring
/// [`external/randomx-v2/src/vm_interpreted.cpp:69`](../../../external/randomx-v2/src/vm_interpreted.cpp)'s
/// `for(unsigned ic = 0; ic < RANDOMX_PROGRAM_ITERATIONS; ++ic)`.
///
/// # Distinct from [`PROGRAM_SIZE`] (R0-D9 anchor)
///
/// See [`PROGRAM_SIZE`] rustdoc.
pub(crate) const PROGRAM_ITERATIONS: usize = 2048;

/// RandomX v2 scratchpad size in bytes.
///
/// `RANDOMX_SCRATCHPAD_L3 = 2_097_152` (2 MiB) per
/// [`external/randomx-v2/src/configuration.h:68`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. The C reference asserts the constant is a power
/// of two and is the L3 (largest) of three nested scratchpad sizes
/// (`common.hpp:57`); the Rust port mirrors the power-of-two
/// invariant at compile time (the `const _: () = assert!(…)` block
/// below) and carries only the L3 constant — L1/L2 are derived
/// masks the bytecode dispatch in Phase 2d will compute as
/// `RANDOMX_SCRATCHPAD_L3 / sizeof(int_reg_t) - 1` etc., not as
/// independent constants.
///
/// # Allocation discipline
///
/// The [`VmState::scratchpad`] field is typed
/// `Box<[u8; RANDOMX_SCRATCHPAD_L3]>` — a fixed-size array on the
/// heap. The type-level length pins the invariant: any drift between
/// the allocation site and the consumer is a compile error, not a
/// runtime bug. Allocation goes through [`alloc_zeroed_scratchpad`]
/// (Phase 2c's second and final `#![deny(unsafe_code)]` carve-out
/// per §1 covenant 7); the conversion `Box<[u8]> → Box<[u8; N]>`
/// is the safe `try_into` from `std`, with a `debug_assert!` per
/// §5.11.2 guarding the intermediate slice length.
pub(crate) const RANDOMX_SCRATCHPAD_L3: usize = 2_097_152;

const _: () = assert!(
    RANDOMX_SCRATCHPAD_L3.is_power_of_two(),
    "RANDOMX_SCRATCHPAD_L3 must be a power of two per common.hpp:57 \
     (the bytecode dispatch in Phase 2d derives the L1/L2/L3 masks as \
     RANDOMX_SCRATCHPAD_LN / sizeof(int_reg_t) - 1 for N in 1..=3, \
     which is only correct when the operand is a power of two)"
);

/// Cache-line-aligned scratchpad address mask applied by
/// [`VmState::execute_program`] to `sp_addr0` / `sp_addr1` each
/// iteration before the register-load + F/E-load + scratchpad-store
/// memory accesses.
///
/// `ScratchpadL3Mask64 = (ScratchpadL3 / 8 - 1) * 64` per
/// [`external/randomx-v2/src/common.hpp:164`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`, where `ScratchpadL3 = RANDOMX_SCRATCHPAD_L3 /
/// sizeof(int_reg_t) = RANDOMX_SCRATCHPAD_L3 / 8`. The expression
/// resolves to `RANDOMX_SCRATCHPAD_L3 / 64 - 1` u64-pair cache-lines,
/// multiplied by `64` bytes per cache-line, equaling
/// `RANDOMX_SCRATCHPAD_L3 - 64` (= the byte offset of the last
/// 64-byte cache-line within the 2 MiB scratchpad). The Rust port
/// preserves the C reference's compositional spelling
/// (`/ 64 - 1) * 64` rather than `- 64` directly) for traceability;
/// the `const _: () = assert!(…)` block below double-checks the two
/// equal-value reductions.
///
/// # Address-derivation budget
///
/// At the spec-pinned `RANDOMX_SCRATCHPAD_L3 = 2_097_152`, the mask
/// is `2_097_088`. The per-iteration loop reads from
/// `scratchpad[sp_addr1 + 8 * (i + RegisterCountFlt)]` (max
/// `sp_addr1 + 8 * 7 = sp_addr1 + 56`, last byte at offset
/// `sp_addr1 + 63`) and writes to `scratchpad[sp_addr0 + 16 * i]`
/// (max `sp_addr0 + 16 * 3 = sp_addr0 + 48`, last byte at offset
/// `sp_addr0 + 63`). Mask-bounded by `2_097_088`, the highest byte
/// access is `2_097_088 + 63 = 2_097_151` — exactly the last byte
/// of the 2 MiB scratchpad. The mask is tight: any larger
/// `sp_addr` would index past the buffer.
#[allow(clippy::cast_possible_truncation)]
pub(crate) const SCRATCHPAD_L3_MASK_64: u32 = ((RANDOMX_SCRATCHPAD_L3 / 64 - 1) * 64) as u32;

const _: () = assert!(
    SCRATCHPAD_L3_MASK_64 as usize == RANDOMX_SCRATCHPAD_L3 - 64,
    "SCRATCHPAD_L3_MASK_64 must equal `RANDOMX_SCRATCHPAD_L3 - 64` \
     (the byte offset of the last 64-byte cache-line in the scratchpad); \
     drift here means the C-reference compositional spelling no longer \
     reduces to the simpler equivalent — investigate whether \
     RANDOMX_SCRATCHPAD_L3 has drifted or whether the C reference's \
     formula has changed"
);

const RANDOMX_SCRATCHPAD_L1: usize = 16_384;
const RANDOMX_SCRATCHPAD_L2: usize = 262_144;
const SCRATCHPAD_L1_MASK: u64 = ((RANDOMX_SCRATCHPAD_L1 / 8 - 1) * 8) as u64;
const SCRATCHPAD_L2_MASK: u64 = ((RANDOMX_SCRATCHPAD_L2 / 8 - 1) * 8) as u64;
const SCRATCHPAD_L3_MASK: u64 = ((RANDOMX_SCRATCHPAD_L3 / 8 - 1) * 8) as u64;

const REGISTER_NEEDS_DISPLACEMENT: usize = 5;
const RANDOMX_JUMP_BITS: u32 = 8;
const RANDOMX_JUMP_OFFSET: u32 = 8;
const CONDITION_MASK: u64 = (1u64 << RANDOMX_JUMP_BITS) - 1;

/// Number of program chains executed per [`compute_hash`] invocation.
///
/// `RANDOMX_PROGRAM_COUNT = 8` per
/// [`external/randomx-v2/src/configuration.h:65`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Consumed by [`compute_hash`]'s chain loop:
/// the first `RANDOMX_PROGRAM_COUNT - 1` (= 7) chains follow each
/// `init_program` + `execute_program` with a
/// `Blake2b-512(register_file)` chain step that overwrites
/// `temp_hash`; the eighth chain skips the chain-step Blake2b and
/// instead feeds the final register-file (post-`AesHash1R` overwrite
/// of the `a` registers) to `Blake2b<U32>` for the 32-byte output.
/// Mirrors the loop bound at
/// [`external/randomx-v2/src/randomx.cpp:397-402`](../../../external/randomx-v2/src/randomx.cpp).
pub(crate) const RANDOMX_PROGRAM_COUNT: usize = 8;

/// Output size in bytes of [`compute_hash`]'s final
/// `Blake2b<U32>(register_file)` step.
///
/// `RANDOMX_HASH_SIZE = 32` per
/// [`external/randomx-v2/src/randomx.h:35`](../../../external/randomx-v2/src/randomx.h)
/// at pin `aaafe71`. Encoded in the [`compute_hash`] return type
/// (`[u8; 32]`); this constant exists for documentation cross-reference
/// to the C reference and to anchor any future generic-over-output-
/// size code that wants the named source.
#[allow(dead_code)]
pub(crate) const RANDOMX_HASH_SIZE: usize = 32;

/// Number of 64-bit integer registers in the RandomX register file.
///
/// `RegistersCount = 8` per
/// [`external/randomx-v2/src/common.hpp:165`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Equals the array length of [`VmState::r`].
/// Used by [`VmState::execute_program`]'s register-load loop and by
/// [`compute_hash`]'s register-file Blake2b feed.
pub(crate) const REGISTERS_COUNT: usize = 8;

/// Number of 128-bit floating-point register pairs in the RandomX
/// register file (each register pair carries two `f64` lanes).
///
/// `RegisterCountFlt = RegistersCount / 2 = 4` per
/// [`external/randomx-v2/src/common.hpp:166`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Equals the array length of [`VmState::f`] /
/// [`VmState::e`] / [`VmState::a`]. Used by
/// [`VmState::execute_program`]'s F/E load + AES mix + F store loops
/// and by [`compute_hash`]'s register-file Blake2b feed.
pub(crate) const REGISTER_COUNT_FLT: usize = REGISTERS_COUNT / 2;

/// RandomX dataset base size in bytes.
///
/// `RANDOMX_DATASET_BASE_SIZE = 2_147_483_648` (2 GiB) per
/// [`external/randomx-v2/src/configuration.h:50`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Consumed transitively by [`CACHE_LINE_ALIGN_MASK`]
/// (`(RANDOMX_DATASET_BASE_SIZE - 1) & !(CACHE_LINE_SIZE as u32 - 1)`
/// per `common.hpp:87`). The Rust port never indexes a dataset
/// directly (the verifier uses `Cache::derive_item` to compute dataset
/// items on the fly per Phase 0's "no dataset" decision); this
/// constant exists only to derive [`CACHE_LINE_ALIGN_MASK`] and is
/// not otherwise consumed.
pub(crate) const RANDOMX_DATASET_BASE_SIZE: u32 = 2_147_483_648;

/// RandomX dataset extra size in bytes.
///
/// `RANDOMX_DATASET_EXTRA_SIZE = 33_554_368` per
/// [`external/randomx-v2/src/configuration.h:53`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Consumed transitively by [`DATASET_EXTRA_ITEMS`]
/// (`RANDOMX_DATASET_EXTRA_SIZE / CACHE_LINE_SIZE` per
/// `common.hpp:90`). The Rust port never indexes a dataset directly;
/// this constant exists only to derive [`DATASET_EXTRA_ITEMS`] and is
/// not otherwise consumed.
pub(crate) const RANDOMX_DATASET_EXTRA_SIZE: u32 = 33_554_368;

/// Cache-line size in bytes.
///
/// `CacheLineSize = RANDOMX_DATASET_ITEM_SIZE = 64` per
/// [`external/randomx-v2/src/common.hpp:85`](../../../external/randomx-v2/src/common.hpp)
/// and
/// [`external/randomx-v2/src/randomx.h:36`](../../../external/randomx-v2/src/randomx.h)
/// at pin `aaafe71`. Used by [`VmState::init_program`]'s `mem.ma`
/// alignment + `dataset_offset` multiplier.
pub(crate) const CACHE_LINE_SIZE: u32 = 64;

/// Cache-line alignment mask.
///
/// `CacheLineAlignMask = (RANDOMX_DATASET_BASE_SIZE - 1) & ~(CacheLineSize - 1)`
/// per
/// [`external/randomx-v2/src/common.hpp:87`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Applied to `entropy(8)` during
/// [`VmState::init_program`] to compute `mem.ma` per
/// `virtual_machine.cpp:81`. The mask zeros the low 6 bits (cache-
/// line alignment) within the low 31 bits (`DATASET_BASE_SIZE - 1`);
/// at the spec-pinned values the result is `0x7FFF_FFC0`.
pub(crate) const CACHE_LINE_ALIGN_MASK: u32 =
    (RANDOMX_DATASET_BASE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);

/// Dataset extra items.
///
/// `DatasetExtraItems = RANDOMX_DATASET_EXTRA_SIZE / CACHE_LINE_SIZE`
/// per
/// [`external/randomx-v2/src/common.hpp:90`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Applied to `entropy(13)` during
/// [`VmState::init_program`] to compute `dataset_offset` per
/// `virtual_machine.cpp:91`. At the spec-pinned values the result is
/// `524_287` (= `2^19 - 1`).
pub(crate) const DATASET_EXTRA_ITEMS: u32 = RANDOMX_DATASET_EXTRA_SIZE / CACHE_LINE_SIZE;

/// IEEE-754 binary64 mantissa width in bits.
///
/// `mantissaSize = 52` per
/// [`external/randomx-v2/src/common.hpp:174`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Used by [`get_small_positive_float_bits`] /
/// [`get_static_exponent`] to assemble IEEE-754 binary64 bit patterns
/// from the program-init entropy buffer.
pub(crate) const MANTISSA_SIZE: u32 = 52;

/// IEEE-754 binary64 exponent width in bits.
///
/// `exponentSize = 11` per
/// [`external/randomx-v2/src/common.hpp:175`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Used by [`get_small_positive_float_bits`] to
/// mask the entropy-derived exponent into the binary64 11-bit field.
pub(crate) const EXPONENT_SIZE: u32 = 11;

/// IEEE-754 binary64 mantissa mask.
///
/// `mantissaMask = (1 << mantissaSize) - 1` per
/// [`external/randomx-v2/src/common.hpp:176`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
pub(crate) const MANTISSA_MASK: u64 = (1u64 << MANTISSA_SIZE) - 1;

/// IEEE-754 binary64 exponent mask.
///
/// `exponentMask = (1 << exponentSize) - 1` per
/// [`external/randomx-v2/src/common.hpp:177`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
pub(crate) const EXPONENT_MASK: u64 = (1u64 << EXPONENT_SIZE) - 1;

/// IEEE-754 binary64 exponent bias.
///
/// `exponentBias = 1023` per
/// [`external/randomx-v2/src/common.hpp:178`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
pub(crate) const EXPONENT_BIAS: u64 = 1023;

/// Dynamic-mantissa mask applied by FDIV_M's
/// `maskRegisterExponentMantissa` step and by the per-iteration F/E
/// mix in [`VmState::execute_program`] (the spec §4.6.3 E-register
/// load with the mantissa preserved and the exponent replaced by
/// `e_mask`).
///
/// `dynamicMantissaMask = (1 << (mantissaSize + dynamicExponentBits)) - 1`
/// per
/// [`external/randomx-v2/src/common.hpp:182`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. At the spec-pinned values (`mantissaSize = 52`,
/// `dynamicExponentBits = 4`) the mask is `(1 << 56) - 1 =
/// 0x00FF_FFFF_FFFF_FFFF` — the low 56 bits set, the high 8 bits
/// (the static exponent half) clear.
pub(crate) const DYNAMIC_MANTISSA_MASK: u64 = (1u64 << (MANTISSA_SIZE + DYNAMIC_EXPONENT_BITS)) - 1;

/// Dynamic exponent bit-width for the `e`-register float-mask
/// derivation.
///
/// `dynamicExponentBits = 4` per
/// [`external/randomx-v2/src/common.hpp:179`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Used by [`get_static_exponent`].
pub(crate) const DYNAMIC_EXPONENT_BITS: u32 = 4;

/// Static exponent bit-width consumed from the entropy MSB by
/// [`get_static_exponent`].
///
/// `staticExponentBits = 4` per
/// [`external/randomx-v2/src/common.hpp:180`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
pub(crate) const STATIC_EXPONENT_BITS: u32 = 4;

/// Fixed exponent bits seeded into [`get_static_exponent`]'s output
/// before XOR-ing with the entropy-derived bits.
///
/// `constExponentBits = 0x300` per
/// [`external/randomx-v2/src/common.hpp:181`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
pub(crate) const CONST_EXPONENT_BITS: u64 = 0x300;

/// Size in bytes of the per-program entropy header.
///
/// Per [`spec §4.5`](../../../external/randomx-v2/doc/specs.md) +
/// [`external/randomx-v2/src/program.hpp:66`](../../../external/randomx-v2/src/program.hpp)
/// at pin `aaafe71`, the C reference's `Program::entropyBuffer` is
/// `uint64_t entropyBuffer[16]` — 16 × 8 = 128 bytes. The Rust port
/// reads these 128 bytes from the head of the [`PROGRAM_BUFFER_SIZE`]
/// AES-fill output and parses them into the register-init field set
/// per [`VmState::init_program`].
pub(crate) const ENTROPY_BUFFER_SIZE: usize = 128;

/// Size in bytes of a single parsed [`Instruction`] in the program
/// buffer's instruction tail.
///
/// Per [`spec §5.1`](../../../external/randomx-v2/doc/specs.md) +
/// [`external/randomx-v2/src/instruction.hpp`](../../../external/randomx-v2/src/instruction.hpp)
/// at pin `aaafe71`, every RandomX instruction is exactly 8 bytes
/// on the wire: `opcode | dst | src | mod_ | imm32 (LE)`.
pub(crate) const INSTRUCTION_SIZE: usize = 8;

/// Size in bytes of the [`VmState::init_program`] AES-fill buffer.
///
/// Per [`spec §4.5`](../../../external/randomx-v2/doc/specs.md) the
/// per-program AES-generator emits `128 + 8 * RANDOMX_PROGRAM_SIZE`
/// bytes per program-init call (128-byte entropy header + 384 × 8-byte
/// instructions = 3_200 bytes at `RANDOMX_PROGRAM_SIZE_V2 = 384`).
/// The constant is asserted equal to `ENTROPY_BUFFER_SIZE +
/// PROGRAM_SIZE * INSTRUCTION_SIZE` at compile time below.
pub(crate) const PROGRAM_BUFFER_SIZE: usize = ENTROPY_BUFFER_SIZE + PROGRAM_SIZE * INSTRUCTION_SIZE;

const _: () = assert!(
    PROGRAM_BUFFER_SIZE == 3_200,
    "PROGRAM_BUFFER_SIZE must equal 128 + 8 * 384 = 3_200 per spec \
     section 4.5; if PROGRAM_SIZE drifts away from 384 (per R0-D9), \
     this assertion catches the drift before init_program's stack \
     allocation runs against a wrong size"
);

const _: () = assert!(
    PROGRAM_BUFFER_SIZE.is_multiple_of(64),
    "PROGRAM_BUFFER_SIZE must be a multiple of 64 per the \
     `aes::fill_aes_4r_x4` output-length contract \
     (the AES-4R-x4 generator emits in 64-byte chunks)"
);

/// Decode an entropy-derived `u64` into IEEE-754 binary64 bits for a
/// "small positive float" — used for `a`-register initialization.
///
/// Mirrors `getSmallPositiveFloatBits` at
/// [`external/randomx-v2/src/virtual_machine.cpp:49-56`](../../../external/randomx-v2/src/virtual_machine.cpp)
/// at pin `aaafe71`. Extracts the high 5 bits of `entropy` as the
/// exponent (range `0..=31`), adds [`EXPONENT_BIAS`], masks with
/// [`EXPONENT_MASK`], and ORs the masked exponent (shifted up by
/// [`MANTISSA_SIZE`]) with the low [`MANTISSA_SIZE`] bits of `entropy`
/// as the mantissa. The result is the bit pattern of a positive
/// binary64 value in the range `[2^-1023, 2^-993)`.
///
/// # Determinism / side-channel posture
///
/// Pure function of `entropy`; no allocator calls, no atomic ops, no
/// table lookups. Constant-time across all inputs per the bit-pattern
/// shape of the operations (shifts/ANDs/ORs on `u64`).
pub(crate) fn get_small_positive_float_bits(entropy: u64) -> u64 {
    let exponent = entropy >> 59;
    let mantissa = entropy & MANTISSA_MASK;
    let exponent = exponent + EXPONENT_BIAS;
    let exponent = exponent & EXPONENT_MASK;
    let exponent = exponent << MANTISSA_SIZE;
    exponent | mantissa
}

/// Decode an entropy-derived `u64` into the static-exponent half of
/// an `e_mask` value — used internally by [`get_float_mask`].
///
/// Mirrors `getStaticExponent` at
/// [`external/randomx-v2/src/virtual_machine.cpp:58-63`](../../../external/randomx-v2/src/virtual_machine.cpp)
/// at pin `aaafe71`. Seeds with [`CONST_EXPONENT_BITS`] (`0x300`),
/// ORs in the top [`STATIC_EXPONENT_BITS`] of `entropy` shifted up by
/// [`DYNAMIC_EXPONENT_BITS`], then shifts the whole assembly up by
/// [`MANTISSA_SIZE`] to land in the binary64 exponent field.
///
/// # Determinism / side-channel posture
///
/// See [`get_small_positive_float_bits`].
pub(crate) fn get_static_exponent(entropy: u64) -> u64 {
    let exponent = CONST_EXPONENT_BITS;
    let exponent = exponent | ((entropy >> (64 - STATIC_EXPONENT_BITS)) << DYNAMIC_EXPONENT_BITS);
    exponent << MANTISSA_SIZE
}

/// Decode an entropy-derived `u64` into an `e_mask[i]` value applied
/// by FDIV_M's `maskRegisterExponentMantissa` step.
///
/// Mirrors `getFloatMask` at
/// [`external/randomx-v2/src/virtual_machine.cpp:65-68`](../../../external/randomx-v2/src/virtual_machine.cpp)
/// at pin `aaafe71`. Combines the low 22 bits of `entropy` with the
/// [`get_static_exponent`]-derived static exponent. The result is
/// stored into `VmState::e_mask[0]` / `e_mask[1]` during
/// [`VmState::init_program`] and consumed by FDIV_M in Phase 2d's
/// bytecode dispatch (`bytecode_machine.hpp:272-278`).
///
/// # Determinism / side-channel posture
///
/// See [`get_small_positive_float_bits`].
pub(crate) fn get_float_mask(entropy: u64) -> u64 {
    const MASK_22BIT: u64 = (1u64 << 22) - 1;
    (entropy & MASK_22BIT) | get_static_exponent(entropy)
}

/// Convert an 8-byte little-endian scratchpad slice (two packed
/// 32-bit signed integers) to a [`F128`] (two f64 lanes), per the
/// SSE2 `_mm_cvtepi32_pd` semantics the bytecode machine relies on
/// for the spec §4.6.2 F/E register load.
///
/// Mirrors `rx_cvt_packed_int_vec_f128(const void* addr)` at
/// [`external/randomx-v2/src/intrin_portable.h:163-166`](../../../external/randomx-v2/src/intrin_portable.h)
/// at pin `aaafe71`. The C reference loads 8 bytes via
/// `_mm_loadl_epi64`, then `_mm_cvtepi32_pd` interprets the low 64
/// bits as two packed signed 32-bit integers (little-endian on x86)
/// and converts each to a `double` with full-range sign extension
/// (i32 → f64 is exact: every i32 fits in f64's 53-bit mantissa).
///
/// # Wire-format and consensus posture
///
/// The byte interpretation is consensus-relevant: bytes `0..4` of
/// `addr` are the **first** i32 (lo lane), bytes `4..8` are the
/// **second** i32 (hi lane). The Rust port reads each lane via
/// `i32::from_le_bytes` and converts to `f64` via the lossless
/// `f64::from(i32)` (`From<i32> for f64` is the language's canonical
/// i32→f64 conversion, equivalent to the spec-pinned x86 semantics).
///
/// # Determinism / side-channel posture
///
/// Pure function of the 8 input bytes; no allocator calls, no atomic
/// ops, no table lookups. The `i32 → f64` conversion is a single
/// constant-time operation on every supported target (no branching
/// on the input value, no exception generation since every i32 has
/// an exact f64 representation).
pub(crate) fn cvt_packed_int_to_f128(bytes: &[u8; 8]) -> F128 {
    let lo = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let hi = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    F128([f64::from(lo), f64::from(hi)])
}

/// Apply the FDIV_M-style `maskRegisterExponentMantissa` transform
/// to a [`F128`] register pair.
///
/// Mirrors `maskRegisterExponentMantissa(ProgramConfiguration& config,
/// rx_vec_f128 x)` at
/// [`external/randomx-v2/src/bytecode_machine.hpp:272-278`](../../../external/randomx-v2/src/bytecode_machine.hpp)
/// at pin `aaafe71`. The transform replaces each lane's IEEE-754
/// exponent (the high 8 bits of the static-exponent half) with the
/// corresponding `e_mask[i]` byte pattern while preserving the
/// 56-bit mantissa-plus-dynamic-exponent low bits via
/// [`DYNAMIC_MANTISSA_MASK`]. The C reference uses SSE2
/// `_mm_and_pd` + `_mm_or_pd`; the Rust port operates on the bit
/// pattern directly via `f64::to_bits` / `f64::from_bits` (the
/// IEEE-754 spec defines the bit-level transform unambiguously,
/// and the Rust intrinsics are constant-time on every target).
///
/// # Consumer
///
/// Used by [`VmState::execute_program`]'s spec §4.6.3 E-register
/// load (mirroring `vm_interpreted.cpp:83` at pin `aaafe71`). Once
/// Phase 2d lands real bytecode dispatch, FDIV_M consumes the same
/// helper.
///
/// # Determinism / side-channel posture
///
/// Pure function of `x` + `e_mask`; no allocator calls, no atomic
/// ops, no table lookups. The bit-pattern manipulation is
/// constant-time across all inputs per the shape of the operations
/// (ANDs/ORs on `u64`).
pub(crate) fn mask_register_exponent_mantissa(x: F128, e_mask: [u64; 2]) -> F128 {
    let lo_bits = (x[0].to_bits() & DYNAMIC_MANTISSA_MASK) | e_mask[0];
    let hi_bits = (x[1].to_bits() & DYNAMIC_MANTISSA_MASK) | e_mask[1];
    F128([f64::from_bits(lo_bits), f64::from_bits(hi_bits)])
}

/// Reinterpret a [`F128`] register pair as a 16-byte AES state block
/// (little-endian bit-pattern: lo lane bytes then hi lane bytes).
///
/// Mirrors the C reference's `rx_cast_vec_f2i(nreg.f[i])` at
/// [`external/randomx-v2/src/vm_interpreted.cpp:104-105`](../../../external/randomx-v2/src/vm_interpreted.cpp)
/// at pin `aaafe71`. The C path uses SSE2 `_mm_castpd_si128` which
/// is a zero-cost reinterpret of the 128-bit register's bytes; the
/// Rust port serializes via `f64::to_bits` + `u64::to_le_bytes` to
/// the same byte sequence on little-endian targets (the spec-pinned
/// representation matches the IEEE-754 binary64 little-endian
/// canonical form per spec §5.2). Consumed by the per-iteration F/E
/// AES mix in [`VmState::execute_program`].
///
/// # Determinism / side-channel posture
///
/// Pure function of `f`; no allocator calls, no atomic ops. The
/// `to_bits` / `to_le_bytes` conversions are constant-time on every
/// supported target.
fn f128_to_aes_bytes(f: F128) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&f[0].to_bits().to_le_bytes());
    bytes[8..16].copy_from_slice(&f[1].to_bits().to_le_bytes());
    bytes
}

/// Inverse of [`f128_to_aes_bytes`] — reinterpret a 16-byte AES
/// state block as a [`F128`] register pair.
///
/// Mirrors `rx_cast_vec_i2f(freg[i])` at
/// [`external/randomx-v2/src/vm_interpreted.cpp:115-116`](../../../external/randomx-v2/src/vm_interpreted.cpp)
/// at pin `aaafe71`. The C path uses SSE2 `_mm_castsi128_pd`; the
/// Rust port deserializes via `u64::from_le_bytes` + `f64::from_bits`
/// to the same f64-pair value on little-endian targets.
///
/// # Determinism / side-channel posture
///
/// Pure function of `bytes`; no allocator calls, no atomic ops. The
/// `from_le_bytes` / `from_bits` conversions are constant-time on
/// every supported target.
fn aes_bytes_to_f128(bytes: &[u8; 16]) -> F128 {
    let lo = u64::from_le_bytes(bytes[0..8].try_into().expect("16-byte block split at 8"));
    let hi = u64::from_le_bytes(bytes[8..16].try_into().expect("16-byte block split at 8"));
    F128([f64::from_bits(lo), f64::from_bits(hi)])
}

/// Sign-extend a 32-bit two's-complement immediate to 64 bits.
///
/// Mirrors `signExtend2sCompl` / IMM32 handling in
/// `bytecode_machine.cpp` operand decode at pin `aaafe71`.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
pub(crate) const fn sign_extend_i32_to_i64(x: u32) -> u64 {
    (x as i32 as i64) as u64
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstructionType {
    IAddRs,
    IAddM,
    ISubR,
    ISubM,
    IMulR,
    IMulM,
    IMulhR,
    IMulhM,
    ISMulhR,
    ISMulhM,
    IMulRcp,
    INegR,
    IXorR,
    IXorM,
    IRorR,
    IRolR,
    ISwapR,
    FSwapR,
    FAddR,
    FAddM,
    FSubR,
    FSubM,
    FScalR,
    FMulR,
    FDivM,
    FSqrtR,
    CBranch,
    CfRound,
    IStore,
}

fn decode_instruction_type(opcode: u8) -> InstructionType {
    match opcode {
        0..=15 => InstructionType::IAddRs,
        16..=22 => InstructionType::IAddM,
        23..=38 => InstructionType::ISubR,
        39..=45 => InstructionType::ISubM,
        46..=61 => InstructionType::IMulR,
        62..=65 => InstructionType::IMulM,
        66..=69 => InstructionType::IMulhR,
        70 => InstructionType::IMulhM,
        71..=74 => InstructionType::ISMulhR,
        75 => InstructionType::ISMulhM,
        76..=83 => InstructionType::IMulRcp,
        84..=85 => InstructionType::INegR,
        86..=100 => InstructionType::IXorR,
        101..=105 => InstructionType::IXorM,
        106..=113 => InstructionType::IRorR,
        114..=115 => InstructionType::IRolR,
        116..=119 => InstructionType::ISwapR,
        120..=123 => InstructionType::FSwapR,
        124..=139 => InstructionType::FAddR,
        140..=144 => InstructionType::FAddM,
        145..=160 => InstructionType::FSubR,
        161..=165 => InstructionType::FSubM,
        166..=171 => InstructionType::FScalR,
        172..=203 => InstructionType::FMulR,
        204..=207 => InstructionType::FDivM,
        208..=213 => InstructionType::FSqrtR,
        214..=238 => InstructionType::CBranch,
        239 => InstructionType::CfRound,
        240..=255 => InstructionType::IStore,
    }
}

/// Load a little-endian `u64` from an 8-byte scratchpad slice.
///
/// Mirrors `load64` in `external/randomx-v2/src/blake2/endian.h` at
/// pin `aaafe71` (native little-endian on verifier targets).
pub(crate) fn load64(addr: &[u8]) -> u64 {
    let bytes: [u8; 8] = addr[..8].try_into().expect("load64 requires 8 bytes");
    u64::from_le_bytes(bytes)
}

/// Store a little-endian `u64` into an 8-byte scratchpad slice.
///
/// Mirrors `store64` in `external/randomx-v2/src/blake2/endian.h` at
/// pin `aaafe71`.
pub(crate) fn store64(addr: &mut [u8], value: u64) {
    addr[..8].copy_from_slice(&value.to_le_bytes());
}

/// Rotate `a` right by `b` bits (mod 64).
///
/// Portable definition matching `instructions_portable.cpp:92-94`
/// (`(-b & 63)` shift amount) at pin `aaafe71`.
#[allow(clippy::manual_rotate)]
pub(crate) fn rotr(a: u64, b: u32) -> u64 {
    let b = b & 63;
    if b == 0 {
        return a;
    }
    (a >> b) | (a << (64 - b))
}

/// Rotate `a` left by `b` bits (mod 64).
///
/// Portable definition matching `instructions_portable.cpp:99-101`
/// at pin `aaafe71`.
#[allow(clippy::manual_rotate)]
pub(crate) fn rotl(a: u64, b: u32) -> u64 {
    let b = b & 63;
    if b == 0 {
        return a;
    }
    (a << b) | (a >> (64 - b))
}

fn int_reg(index: u8) -> usize {
    usize::from(index) % REGISTERS_COUNT
}

fn fp_reg(index: u8) -> usize {
    usize::from(index) % REGISTER_COUNT_FLT
}

fn mod_mem(instr: &Instruction) -> bool {
    !instr.mod_.is_multiple_of(4)
}

fn mod_shift(instr: &Instruction) -> u32 {
    u32::from((instr.mod_ >> 2) % 4)
}

fn mod_cond(instr: &Instruction) -> u32 {
    u32::from(instr.mod_ >> 4)
}

fn memory_mask(instr: &Instruction, dst: usize, src: usize) -> u64 {
    if src == dst {
        SCRATCHPAD_L3_MASK
    } else if mod_mem(instr) {
        SCRATCHPAD_L1_MASK
    } else {
        SCRATCHPAD_L2_MASK
    }
}

fn scratchpad_addr(base: u64, imm: u64, mask: u64) -> usize {
    usize::try_from(base.wrapping_add(imm) & mask)
        .expect("RandomX scratchpad masks fit in usize on verifier targets")
}

fn load_scratchpad_u64(state: &VmState, base: u64, imm: u64, mask: u64) -> u64 {
    let off = scratchpad_addr(base, imm, mask);
    load64(&state.scratchpad[off..off + 8])
}

fn load_scratchpad_f128(state: &VmState, base: u64, imm: u64, mask: u64) -> F128 {
    let off = scratchpad_addr(base, imm, mask);
    let bytes: [u8; 8] = state.scratchpad[off..off + 8]
        .try_into()
        .expect("scratchpad mask bounds 8-byte F128 integer load");
    cvt_packed_int_to_f128(&bytes)
}

fn store_scratchpad_u64(state: &mut VmState, base: u64, imm: u64, mask: u64, value: u64) {
    let off = scratchpad_addr(base, imm, mask);
    store64(&mut state.scratchpad[off..off + 8], value);
}

fn is_zero_or_power_of_two(x: u32) -> bool {
    x & x.wrapping_sub(1) == 0
}

/// Execute the v2-only CFROUND body.
///
/// Mirrors `bytecode_machine.hpp:261-266` with the v1 flag branch
/// deleted per `RANDOMX_V2_PHASE2D_PLAN.md` §2 F5. The helper is
/// separated from the dispatch match so commit 2 can pin the
/// rounding-mode side effect before commit 3 lands the frequency
/// decode ladder.
fn execute_cfround(instr: &Instruction, state: &mut VmState) {
    let src = usize::from(instr.src % 8);
    let isrc = rotr(state.r[src], instr.imm32 & 63);

    if (isrc & 60) == 0 {
        let mode = (isrc & 3) as u32;
        crate::fpu_rounding::set_rounding_mode(mode);
        state.fprc = mode;
    }
}

/// A single 8-byte RandomX v2 bytecode instruction.
///
/// Per spec §5.1 and
/// [`external/randomx-v2/src/instruction.hpp`](../../../external/randomx-v2/src/instruction.hpp)
/// at pin `aaafe71`, every RandomX instruction is exactly 8 bytes:
/// one opcode byte, three register/mod bytes, and a 32-bit immediate.
/// The on-disk layout is wire-format-stable (program-init produces
/// these byte-for-byte from the AES-generated entropy buffer per spec
/// §4.5.4); the Rust port carries it as a plain `#[repr(Rust)]`
/// struct because the only construction site is in-memory parse from
/// the entropy buffer (commit 5), not raw-byte transmute.
///
/// # Frozen surface per §5.1.1
///
/// Per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.1 "Frozen surface 2" (and the single-pass dispatch design
/// choice), Phase 2d **cannot** add fields to this struct. Spec
/// §5.1's 8-byte layout is stable; instruction-derived state
/// (resolved register pointers, memMask, shift amount, branch
/// target) is computed per-call inside `dispatch_instruction`'s body
/// (Phase 2d), not stored on [`Instruction`].
///
/// # Field naming
///
/// `mod_` (trailing underscore) avoids the `mod` keyword collision;
/// the C reference uses `mod` directly since C++ has no such
/// reservation.
// `Instruction` fields are written by `init_program` and consumed
// only by `dispatch_instruction`. Under the Phase 2c stub-NOP body,
// `dispatch_instruction` ignores every field; Phase 2d's body
// replacement is the first production reader, so the per-field
// "never read" dead-code lint stays suppressed at the struct level
// until then.
#[allow(dead_code)]
#[derive(Default, Clone, Copy)]
pub(crate) struct Instruction {
    /// Opcode byte; spec §5.1.1 `opcode` field.
    pub(crate) opcode: u8,
    /// Destination register index; spec §5.1.2 `dst` field.
    pub(crate) dst: u8,
    /// Source register index; spec §5.1.3 `src` field.
    pub(crate) src: u8,
    /// Mod byte; spec §5.1.4 `mod` field. Trailing underscore avoids
    /// the Rust `mod` keyword.
    pub(crate) mod_: u8,
    /// 32-bit immediate; spec §5.1.5 `imm32` field.
    pub(crate) imm32: u32,
}

/// A RandomX v2 program — exactly [`PROGRAM_SIZE`] (384)
/// [`Instruction`]s feeding the dispatch loop, executed
/// [`PROGRAM_ITERATIONS`] (2048) times per hash.
///
/// Per
/// [`external/randomx-v2/src/program.hpp:44-68`](../../../external/randomx-v2/src/program.hpp)
/// at pin `aaafe71`, the C reference's `Program` class carries
/// *both* the 128-byte entropy buffer header *and* the 384-instruction
/// `programBuffer`. The Rust port splits these: the entropy-buffer-
/// derived state (`e_mask`, `read_reg`, scratchpad init, register
/// init, etc.) lives in individual [`VmState`] fields, and [`Program`]
/// carries only the parsed instruction sequence. The split is
/// permitted because none of the C reference's `Program::*`
/// accessors are called outside `vm_interpreted.cpp`'s `execute()`
/// loop, and the Rust port collapses that surface into [`VmState`]
/// fields the dispatch loop reads directly.
///
/// # Allocation discipline
///
/// [`VmState::program`] is `Box<Program>` — a single heap allocation
/// of `size_of::<Program>() = PROGRAM_SIZE * size_of::<Instruction>()
/// = 384 * 8 = 3_072` bytes. Construction goes through
/// [`Program::default`] (safe stable Rust via `std::array::from_fn`)
/// then `Box::new`; the 3 KiB stack overhead during construction
/// is amortized to a single move into the [`Box`] and is bounded by
/// the once-per-hash construction cost (`VmState::new` is called
/// from `compute_hash` once per hash, not per dispatch).
pub(crate) struct Program {
    /// The [`PROGRAM_SIZE`] (384) parsed instructions feeding the
    /// spec §4.5.4 dispatch loop. Populated by commit 5's
    /// `VmState::init_program` from the AES-generated entropy
    /// buffer; left zero-initialized by [`Program::default`].
    pub(crate) instructions: [Instruction; PROGRAM_SIZE],
    /// CBRANCH target-next-PC table, derived from the C reference's
    /// `registerUsage` simulation during program compilation.
    pub(crate) cbranch_table: [u16; PROGRAM_SIZE],
}

impl Default for Program {
    /// Zero-initialize all [`PROGRAM_SIZE`] instructions.
    ///
    /// Uses [`core::array::from_fn`] rather than the `[T; N]: Default`
    /// derive because the standard library's `Default` impl for fixed-
    /// size arrays only covers `N <= 32` for general `T: Default`
    /// (the `[T; 0..=32]` impls predate const-generic `Default`).
    /// [`core::array::from_fn`] is stable since 1.63 (well under the
    /// crate's 1.85 MSRV per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §11) and constructs the array element-by-element without
    /// requiring `T: Copy`.
    ///
    /// Construction allocates the 3 KiB array on the stack, which
    /// [`VmState::new`] then moves into a [`Box`] via [`Box::new`].
    /// The stack overhead is acceptable at the once-per-hash
    /// allocation cadence per the same construction-cost rationale
    /// `RANDOMX_V2_PHASE2C_PLAN.md` §8 budgets `compute_hash` against.
    fn default() -> Self {
        Self {
            instructions: core::array::from_fn(|_| Instruction::default()),
            cbranch_table: [u16::MAX; PROGRAM_SIZE],
        }
    }
}

/// Allocate a zeroed `Box<[u8; RANDOMX_SCRATCHPAD_L3]>` for the
/// [`VmState::scratchpad`] buffer.
///
/// # Why this exists
///
/// Phase 2c's second and final `#![deny(unsafe_code)]` carve-out per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §1 covenant 7 + §5.11.2: scratchpad memory is allocated as
/// `Box<[u8; RANDOMX_SCRATCHPAD_L3]>` (fixed at construction; no
/// `Vec`-style growth surface; size pinned in the type) and zero-
/// initialized before commit 5's `VmState::initialize` overwrites it
/// via `aes::fill_aes_1r_x4`. The carve-out is encapsulated in this
/// single helper — one function, one `unsafe` block, no other
/// intrinsic calls or pointer dereferences — so the audit surface is
/// a single grep target and a single review unit, mirroring the
/// first carve-out in `cache.rs::alloc_zeroed_cache_blocks` per the
/// same discipline.
///
/// # Pattern: `Box<[T]> → Box<[T; N]>` via safe `try_into`
///
/// `Box::new_zeroed_slice(N)` produces `Box<[MaybeUninit<T>]>` of
/// length `N` (the type-level length is erased by the slice form).
/// Recovering the fixed-array length goes through the stable
/// `TryFrom<Box<[T]>> for Box<[T; N]>` impl (`Box` impls since
/// Rust 1.43, well under the crate's 1.85 MSRV) — `try_into` is
/// safe and infallible by the `Box::new_zeroed_slice(N)` length
/// contract. The intermediate `debug_assert!` in [`VmState::new`]
/// per §5.11.2 catches drift between the allocator's length argument
/// and [`RANDOMX_SCRATCHPAD_L3`] if either ever changes without
/// updating the other.
#[allow(unsafe_code)]
fn alloc_zeroed_scratchpad() -> Box<[u8]> {
    let uninit: Box<[MaybeUninit<u8>]> = Box::new_zeroed_slice(RANDOMX_SCRATCHPAD_L3);
    // SAFETY:
    // `u8` is a primitive integer type for which the all-zeroes bit pattern
    // is a valid value (every `u8` from 0 to 255 is well-defined; 0 is
    // trivially in-range). `Box::new_zeroed_slice(len)` allocates `len`
    // contiguous `MaybeUninit<u8>` cells and zero-initializes them per its
    // stabilized contract (Rust 1.82+; current MSRV 1.85), so converting
    // `Box<[MaybeUninit<u8>]>` to `Box<[u8]>` via `assume_init` is sound
    // because every byte is a valid `u8` value. The length invariant
    // (`RANDOMX_SCRATCHPAD_L3` cells) is checked at the caller via the
    // `debug_assert_eq!` in [`VmState::new`] per
    // [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    // §5.11.2.
    unsafe { uninit.assume_init() }
}

/// RandomX v2 per-hash transient state — the scratchpad + register
/// file + parsed program + memory-register state owned internally by
/// `compute_hash` for one hash invocation.
///
/// # Visibility (per §5.9)
///
/// [`VmState`] is `pub(crate)` (visible inside `shekyl-pow-randomx`
/// only), never re-exported via `lib.rs`. Per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.4 (R2-D1 visibility-by-purpose), the public surface for RandomX
/// hashing is `Cache::derive` + the eventual `compute_hash` free
/// function — [`VmState`] is an implementation detail of `compute_hash`,
/// never observed by external callers. Keeping it crate-private leaves
/// the Phase 2f `VmState`-pooling decision (and any associated lifetime
/// / borrow / `Send` / `Sync` adjustments) free to internalize without
/// an API-break. The Phase 3a FFI shim consumes `compute_hash` only;
/// it has no [`VmState`] surface at all.
///
/// # Frozen field set (per §5.1.1)
///
/// The field set below is the Phase 2c → Phase 2d hand-off contract.
/// Phase 2d's bytecode dispatch reads `r` / `f` / `e` / `a` / `fprc` /
/// `scratchpad` / `e_mask` directly via
/// `fn dispatch_instruction(instr: &Instruction, state: &mut VmState)`;
/// the per-iteration loop in `VmState::run` (commit 6 + 2d) reads
/// `ma` / `mx` / `read_reg` / `dataset_offset` / `program` / `temp_hash`.
/// Per §5.1.1's reversion clause, the field set is reopenable iff
/// Phase 2d's per-opcode benchmark demonstrates single-pass dispatch
/// fails the ≤3.0× C-reference budget for reasons attributable to
/// per-call decode cost.
///
/// # Threat-model disposition (per §5.11.4)
///
/// See the module-level docstring for the public-input-only
/// disposition that drives the empty [`Drop`] implementation below.
#[allow(dead_code)]
pub(crate) struct VmState {
    /// Integer register file `r[0]`..`r[7]`. Spec §5.2.1 +
    /// `NativeRegisterFile.r[RegistersCount]` at
    /// `bytecode_machine.hpp:38-44`. Read/written by every integer
    /// R-form and M-form opcode + ISTORE + CBRANCH.
    pub(crate) r: [u64; 8],
    /// Floating-point register file `f[0]`..`f[3]` — additive
    /// double-precision pairs. Spec §5.2.2 +
    /// `NativeRegisterFile.f[RegisterCountFlt]`. Read/written by
    /// FADD_R, FADD_M, FSUB_R, FSUB_M, FSCAL_R, FSWAP_R.
    pub(crate) f: [F128; 4],
    /// Floating-point register file `e[0]`..`e[3]` — multiplicative
    /// double-precision pairs (constrained to positive values per
    /// spec §5.2.6 `maskRegisterExponentMantissa`). Spec §5.2.3 +
    /// `NativeRegisterFile.e[RegisterCountFlt]`. Read/written by
    /// FMUL_R, FDIV_M, FSQRT_R.
    pub(crate) e: [F128; 4],
    /// Floating-point register file `a[0]`..`a[3]` — read-only
    /// operands derived from the program-init entropy. Spec §5.2.4 +
    /// `NativeRegisterFile.a[RegisterCountFlt]`. Read-only after
    /// init: never mutated by any bytecode opcode (only consumed as
    /// `fsrc` by FADD_R, FSUB_R, FMUL_R).
    pub(crate) a: [F128; 4],
    /// FPU rounding-mode register. Spec §5.2.5 + `randomx_vm::fprc`
    /// (the field is on `randomx_vm`, not `NativeRegisterFile`, per
    /// the spec's separation of FP state from architectural state).
    /// Read by CFROUND; written by CFROUND. Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.2 F2, Phase 2c's stub-NOP dispatch does not read or write
    /// `fprc`; the actual rounding-mode plumbing lands in 2d.
    pub(crate) fprc: u32,
    /// 2 MiB scratchpad. Spec §5.2.7 + `VmBase::scratchpad`. Backing
    /// storage for all M-form opcodes (IADD_M, ISUB_M, IMUL_M,
    /// IMULH_M, ISMULH_M, IXOR_M, FADD_M, FSUB_M, FDIV_M) and
    /// ISTORE writes, plus the per-iteration F/E AES mix.
    ///
    /// Stored as `Box<[u8; RANDOMX_SCRATCHPAD_L3]>` (fixed-size
    /// array on the heap) so the size is encoded in the type. The
    /// allocation goes through [`alloc_zeroed_scratchpad`]
    /// (Phase 2c's second `unsafe` carve-out) and is checked at
    /// construction via the [`VmState::new`] `debug_assert!` per
    /// §5.11.2.
    pub(crate) scratchpad: Box<[u8; RANDOMX_SCRATCHPAD_L3]>,
    /// `ProgramConfiguration.eMask[2]` — the FDIV_M exponent-mantissa
    /// mask. Spec §5.2.6 + `program.hpp:40`. Read by FDIV_M's
    /// `maskRegisterExponentMantissa` step (`bytecode_machine.hpp:272-278`);
    /// written once during program-init from the entropy buffer
    /// (commit 5). Phase 2c stub-NOP dispatch never reads or writes
    /// it.
    pub(crate) e_mask: [u64; 2],
    /// Memory-address `ma` register. Spec §5.2.8 +
    /// `MemoryRegisters.ma` (`common.hpp:184-187`). Drives the
    /// per-iteration `datasetRead` address. Per §5.5 F5 v2-only
    /// simplification, the C reference's `mp` alias collapses to a
    /// direct `state.ma` access; no `mp` field exists.
    pub(crate) ma: u32,
    /// Memory-address `mx` register. Spec §5.2.8 +
    /// `MemoryRegisters.mx`. Drives the per-iteration `datasetPrefetch`
    /// address; swapped with `ma` at every iteration boundary per
    /// `vm_interpreted.cpp:94`.
    pub(crate) mx: u32,
    /// `ProgramConfiguration.readReg0`..`readReg3` — the register
    /// indices the per-iteration loop reads to derive `sp_addr0` /
    /// `sp_addr1` and the `mp` XOR per `vm_interpreted.cpp:70, 90`.
    /// Written once during program-init (commit 5).
    pub(crate) read_reg: [u32; 4],
    /// `randomx_vm::datasetOffset` — base offset into the cache for
    /// `datasetRead` / `datasetPrefetch`. Set once during program-
    /// init (commit 5).
    pub(crate) dataset_offset: u64,
    /// The [`PROGRAM_SIZE`] (384) parsed [`Instruction`]s feeding
    /// the per-iteration dispatch loop, executed
    /// [`PROGRAM_ITERATIONS`] (2048) times per hash. Heap-allocated
    /// as `Box<Program>` (one allocation of 3 KiB). Populated by
    /// commit 5's `VmState::init_program` from the AES-generated
    /// entropy buffer; left zero-initialized by [`VmState::new`].
    pub(crate) program: Box<Program>,
    /// `randomx_vm::tempHash` — Blake2b intermediate hash buffer
    /// used by program-init (read 1024 bytes of entropy per program
    /// per spec §4.5.3) and the final hash assembly. Set during
    /// `compute_hash` setup, read by program-init and finalize.
    pub(crate) temp_hash: [u64; 8],
    /// Next program counter requested by CBRANCH, or `u16::MAX` when
    /// the current instruction did not branch.
    pub(crate) branch_pc: u16,
    /// Currently executing instruction index, used to index
    /// [`Program::cbranch_table`] from the frozen dispatch signature.
    pub(crate) exec_pc: u16,
}

impl VmState {
    /// Allocate a zero-initialized [`VmState`].
    ///
    /// Commits 5 / 6 transform a freshly-allocated [`VmState`] into a
    /// usable VM by populating it from `(seedhash, data)` via
    /// `VmState::initialize`; this constructor performs only the
    /// allocation, leaving every field in a structurally-valid but
    /// semantically-uninitialized state. The pattern matches
    /// [`crate::Cache::derive`]'s split between
    /// `alloc_zeroed_cache_blocks` (allocation) and `fill_cache`
    /// (initialization) — landing the unsafe allocation carve-out
    /// in its own commit, separately from the initialization logic,
    /// keeps the audit surface tight and the reviewer attention
    /// focused.
    ///
    /// # Allocation breakdown
    ///
    /// - One [`RANDOMX_SCRATCHPAD_L3`]-sized heap allocation
    ///   (2 MiB) for [`scratchpad`], zero-initialized via the
    ///   [`alloc_zeroed_scratchpad`] carve-out.
    /// - One `size_of::<Program>()`-sized heap allocation (3 KiB)
    ///   for [`program`], constructed via [`Program::default`]
    ///   ([`core::array::from_fn`] of [`Instruction::default`]) and
    ///   moved into a [`Box`].
    /// - All other fields are inlined into the [`VmState`] struct
    ///   itself (zero-cost zero-initialization of integer and
    ///   floating-point arrays).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §8 budget, the per-hash *allocation-only* skeleton (the
    /// 2 MiB scratchpad plus the 3 KiB program plus the inline
    /// state) was scoped at ≤100 µs as a separate sub-bench target.
    /// `BENCH_RESULTS.md` records that no allocation-only sub-bench
    /// has landed yet (R0-D12 reconciliation followup); commit 8's
    /// `benches/compute_hash_alloc.rs` measures the **full
    /// `compute_hash` pipeline** under stub-NOP dispatch (median
    /// 296.00 ms on i9-11950H per `BENCH_RESULTS.md`), not the
    /// allocation skeleton in isolation, and is informational
    /// rather than PR-gating. The dominant cost in that
    /// full-pipeline measurement is the per-chain hash-math
    /// pipeline (init_scratchpad / init_program / execute_program
    /// repeated `RANDOMX_PROGRAM_COUNT` times) and the inter-chain
    /// Blake2b-512 overwrites, not the one-shot allocation here.
    /// The §8 ≤100 µs target stays applicable to the allocation
    /// skeleton (an isolated allocation-only bench would land at
    /// well below the threshold on the same machine); reconciling
    /// the §8 budget against the empirical full-pipeline
    /// measurement is the R0-D12 followup, tracked in
    /// `RANDOMX_V2_PHASE2C_PLAN.md` §14.
    ///
    /// # Liveness disposition (commit 6 wired)
    ///
    /// Commit 6's [`compute_hash`] is the production `pub` caller
    /// of [`VmState::new`]; the transitive chain
    /// ([`alloc_zeroed_scratchpad`], [`Program::default`],
    /// [`Instruction::default`], the [`F128`] alias, the
    /// [`PROGRAM_SIZE`] / [`PROGRAM_ITERATIONS`] /
    /// [`RANDOMX_SCRATCHPAD_L3`] constants, the [`VmState`] /
    /// [`Program`] / [`Instruction`] field reads from
    /// [`VmState::execute_program`] and [`compute_hash`]'s
    /// `feed_register_file_to_hasher`) is reached from this entry
    /// point as a live chain. The per-struct `#[allow(dead_code)]`
    /// on [`VmState`] persists because the `fprc` and `temp_hash`
    /// fields remain unread under the Phase 2c stub-NOP dispatch
    /// (`fprc` is wired by Phase 2d's CFROUND handler; `temp_hash`
    /// is a placeholder field whose role [`compute_hash`] satisfies
    /// with a local buffer — see the field's rustdoc for the
    /// Phase 2d / V3.1 followup that re-evaluates the field).
    pub(crate) fn new() -> Self {
        let slice = alloc_zeroed_scratchpad();

        debug_assert_eq!(
            slice.len(),
            RANDOMX_SCRATCHPAD_L3,
            "VmState::new scratchpad-allocation invariant (per RANDOMX_V2_PHASE2C_PLAN.md §5.11.2): \
             `slice.len()` from `alloc_zeroed_scratchpad` must equal `RANDOMX_SCRATCHPAD_L3` \
             ({RANDOMX_SCRATCHPAD_L3} bytes = 2 MiB); got {actual}",
            actual = slice.len(),
        );

        let scratchpad: Box<[u8; RANDOMX_SCRATCHPAD_L3]> = slice
            .try_into()
            .expect("alloc_zeroed_scratchpad returns Box<[u8]> of length RANDOMX_SCRATCHPAD_L3 by construction");

        Self {
            r: [0u64; 8],
            f: [F128::default(); 4],
            e: [F128::default(); 4],
            a: [F128::default(); 4],
            fprc: 0,
            scratchpad,
            e_mask: [0u64; 2],
            ma: 0,
            mx: 0,
            read_reg: [0u32; 4],
            dataset_offset: 0,
            program: Box::new(Program::default()),
            temp_hash: [0u64; 8],
            branch_pc: u16::MAX,
            exec_pc: u16::MAX,
        }
    }

    /// Fill [`scratchpad`] from `seed` via the spec §4.5.2
    /// `fill_aes_1r_x4` generator.
    ///
    /// Mirrors `VmBase<...>::initScratchpad(void* seed)` at
    /// [`external/randomx-v2/src/virtual_machine.cpp`](../../../external/randomx-v2/src/virtual_machine.cpp)
    /// (`fillAes1Rx4<softAes>(seed, ScratchpadSize, scratchpad)`) at
    /// pin `aaafe71`. The seed is mutated in place: after the call
    /// returns, `seed` contains the next 64 bytes of AES-1R-x4 stream
    /// state, which `compute_hash` (commit 6) chains forward as the
    /// seed for the first program-init call.
    ///
    /// # Why the seed is `&mut [u8; 64]` rather than a `VmState` field
    ///
    /// The C reference stores the seed as `VmBase::tempHash[8]`
    /// (`virtual_machine.hpp`) and threads `void*` into the AES
    /// primitive. The Rust port takes the seed as an explicit
    /// `&mut [u8; 64]` parameter per the
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §14 Round 0 R0-D8 results-fidelity-over-shape-fidelity
    /// discipline: the data flow is made explicit at the call site
    /// (the caller manages a local `[u8; 64]` seed buffer; the AES
    /// chain advances visibly across `init_scratchpad` +
    /// `init_program` invocations); no `unsafe` `u64`-to-`u8` cast is
    /// required to bridge the [`crate::aes::fill_aes_1r_x4`] primitive's
    /// `&mut [u8; 64]` state parameter to a hypothetical
    /// `VmState::temp_hash` field; and tests pass seeds directly
    /// without preparing `temp_hash` field state per setup.
    ///
    /// [`scratchpad`]: VmState::scratchpad
    ///
    /// # Production caller
    ///
    /// Same chain-entry pattern as [`VmState::new`] — commit 6's
    /// [`compute_hash`] is the production `pub` caller; the
    /// transitive chain reached from this method
    /// ([`crate::aes::fill_aes_1r_x4`]) is live as of commit 6.
    pub(crate) fn init_scratchpad(&mut self, seed: &mut [u8; 64]) {
        crate::aes::fill_aes_1r_x4(seed, &mut self.scratchpad[..]);
    }

    /// Parse the spec §4.5 per-program entropy header into the
    /// register-init field set + parse the trailing instruction
    /// sequence into [`program`].
    ///
    /// Mirrors the fused effect of `VmBase<...>::generateProgram(seed)`
    /// (at
    /// [`external/randomx-v2/src/virtual_machine.hpp`](../../../external/randomx-v2/src/virtual_machine.hpp))
    /// followed by `randomx_vm::initialize()` (at
    /// [`external/randomx-v2/src/virtual_machine.cpp:72-94`](../../../external/randomx-v2/src/virtual_machine.cpp))
    /// at pin `aaafe71`. The Rust port fuses the C reference's two
    /// methods into one per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §14 Round 0 R0-D8 results-fidelity-over-shape-fidelity
    /// discipline: the [`PROGRAM_BUFFER_SIZE`]-byte AES-fill buffer
    /// is a function-local consumed in the same call that produces
    /// it, so the C class-method shape (one method per logical step
    /// on the same struct) collapses cleanly to a single Rust method
    /// with a stack-local intermediate.
    ///
    /// # Layout of the AES-fill buffer
    ///
    /// `fill_aes_4r_x4(seed, &mut buf)` produces
    /// [`PROGRAM_BUFFER_SIZE`] = 3_200 bytes laid out per
    /// [`spec §4.5`](../../../external/randomx-v2/doc/specs.md):
    ///
    /// - **Bytes `0..ENTROPY_BUFFER_SIZE = 128`** — entropy header
    ///   (16 little-endian `u64`s). Parsed below into `a` / `ma` /
    ///   `mx` / `read_reg` / `dataset_offset` / `e_mask`.
    /// - **Bytes `128..PROGRAM_BUFFER_SIZE = 3_200`** — 384 ×
    ///   `INSTRUCTION_SIZE = 8`-byte instructions. Parsed below into
    ///   `self.program.instructions[0..PROGRAM_SIZE]`.
    ///
    /// Entropy indices 9 and 11 are *read* by the underlying AES
    /// stream (the `u64` decode consumes all 128 bytes regardless of
    /// whether the parsed value is consumed) but their decoded values
    /// are intentionally **unused** per `virtual_machine.cpp:72-94`'s
    /// `initialize` body — only entropy indices 0..=8, 10, 12..=15
    /// are read by the C reference, leaving 9 and 11 as deliberate
    /// gaps in the entropy-consumption schedule. The Rust port
    /// mirrors this exactly: the `entropy[9]` / `entropy[11]` decoded
    /// values are local-only and never assigned to any `VmState`
    /// field.
    ///
    /// # Determinism / side-channel posture
    ///
    /// Pure function of `seed` and `self.scratchpad`'s allocation
    /// (no per-call mutable state outside `self`); `fill_aes_4r_x4`
    /// is deterministic per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T5'. The entropy-parse helpers
    /// ([`get_small_positive_float_bits`] / [`get_float_mask`]) are
    /// constant-time across all entropy inputs per their bit-pattern
    /// shape.
    ///
    /// [`program`]: VmState::program
    ///
    /// Same chain-entry pattern as [`VmState::init_scratchpad`] —
    /// commit 6's [`compute_hash`] is the production `pub` caller.
    pub(crate) fn init_program(&mut self, seed: &[u8; 64]) {
        let mut buf = [0u8; PROGRAM_BUFFER_SIZE];
        crate::aes::fill_aes_4r_x4(seed, &mut buf);

        let entropy: [u64; 16] = core::array::from_fn(|i| {
            let off = i * 8;
            u64::from_le_bytes(
                buf[off..off + 8]
                    .try_into()
                    .expect("ENTROPY_BUFFER_SIZE = 128 fits 16 u64s by construction"),
            )
        });

        for i in 0..4 {
            self.a[i][0] = f64::from_bits(get_small_positive_float_bits(entropy[2 * i]));
            self.a[i][1] = f64::from_bits(get_small_positive_float_bits(entropy[2 * i + 1]));
        }

        // SAFETY (clippy::cast_possible_truncation): the mask
        // `CACHE_LINE_ALIGN_MASK = 0x7FFF_FFC0` zeros bits 32..=63
        // before the cast, so the `as u32` truncation discards only
        // zero bits. Mirrors C `mem.ma = entropy(8) & CacheLineAlignMask;`
        // at `virtual_machine.cpp:81` where the same arithmetic
        // assigns to `uint32_t ma`.
        #[allow(clippy::cast_possible_truncation)]
        let masked_ma = (entropy[8] & u64::from(CACHE_LINE_ALIGN_MASK)) as u32;
        self.ma = masked_ma;

        // SAFETY (clippy::cast_possible_truncation): the spec-pinned
        // truncation is the consensus rule. Mirrors C
        // `mem.mx = entropy(10);` at `virtual_machine.cpp:82` where
        // the `uint64_t` is implicitly truncated by the
        // `uint32_t mx` field type. Preserving the divergence-free
        // mapping requires the same truncation in Rust.
        #[allow(clippy::cast_possible_truncation)]
        let truncated_mx = entropy[10] as u32;
        self.mx = truncated_mx;

        let addr_regs = entropy[12];
        // SAFETY (clippy::cast_possible_truncation): `& 1` /
        // `>> N & 1` masks the operand to {0, 1}, which fits in `u32`
        // trivially. Mirrors C `config.readReg0 = 0 + (addressRegisters & 1);`
        // pattern at `virtual_machine.cpp:84-90`.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.read_reg[0] = (addr_regs & 1) as u32;
            self.read_reg[1] = 2 + ((addr_regs >> 1) & 1) as u32;
            self.read_reg[2] = 4 + ((addr_regs >> 2) & 1) as u32;
            self.read_reg[3] = 6 + ((addr_regs >> 3) & 1) as u32;
        }

        self.dataset_offset =
            (entropy[13] % u64::from(DATASET_EXTRA_ITEMS + 1)) * u64::from(CACHE_LINE_SIZE);

        self.e_mask[0] = get_float_mask(entropy[14]);
        self.e_mask[1] = get_float_mask(entropy[15]);

        for i in 0..PROGRAM_SIZE {
            let off = ENTROPY_BUFFER_SIZE + i * INSTRUCTION_SIZE;
            let bytes = &buf[off..off + INSTRUCTION_SIZE];
            self.program.instructions[i] = Instruction {
                opcode: bytes[0],
                dst: bytes[1],
                src: bytes[2],
                mod_: bytes[3],
                imm32: u32::from_le_bytes(
                    bytes[4..8]
                        .try_into()
                        .expect("INSTRUCTION_SIZE = 8 yields a 4-byte imm32 tail by construction"),
                ),
            };
        }

        let mut register_usage = [-1i32; REGISTERS_COUNT];
        self.program.cbranch_table = [u16::MAX; PROGRAM_SIZE];
        for i in 0..PROGRAM_SIZE {
            let current_index = i32::try_from(i).expect("PROGRAM_SIZE fits in i32");
            let instr = self.program.instructions[i];
            let instr_type = decode_instruction_type(instr.opcode);
            let dst = int_reg(instr.dst);
            let src = int_reg(instr.src);

            match instr_type {
                InstructionType::IAddRs
                | InstructionType::IAddM
                | InstructionType::ISubR
                | InstructionType::ISubM
                | InstructionType::IMulR
                | InstructionType::IMulM
                | InstructionType::IMulhR
                | InstructionType::IMulhM
                | InstructionType::ISMulhR
                | InstructionType::ISMulhM
                | InstructionType::INegR
                | InstructionType::IXorR
                | InstructionType::IXorM
                | InstructionType::IRorR
                | InstructionType::IRolR => {
                    register_usage[dst] = current_index;
                }
                InstructionType::IMulRcp if !is_zero_or_power_of_two(instr.imm32) => {
                    register_usage[dst] = current_index;
                }
                InstructionType::ISwapR if src != dst => {
                    register_usage[dst] = current_index;
                    register_usage[src] = current_index;
                }
                InstructionType::CBranch => {
                    let creg = dst;
                    self.program.cbranch_table[i] =
                        u16::try_from(register_usage[creg] + 1).expect("CBRANCH target fits u16");
                    register_usage.fill(current_index);
                }
                _ => {}
            }
        }
    }

    /// Execute the parsed [`program`] for [`PROGRAM_ITERATIONS`]
    /// iterations against `cache`, mutating the register file and
    /// scratchpad in place per spec §4.6 + `vm_interpreted.cpp::execute()`
    /// at pin `aaafe71`.
    ///
    /// Mirrors `InterpretedVm<...>::execute()` at
    /// [`external/randomx-v2/src/vm_interpreted.cpp:57-138`](../../../external/randomx-v2/src/vm_interpreted.cpp)
    /// fused with the light-VM `datasetRead` override at
    /// [`external/randomx-v2/src/vm_interpreted_light.cpp:41-49`](../../../external/randomx-v2/src/vm_interpreted_light.cpp).
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.4 F4 (Cache::derive absorption / DatasetReader-trait
    /// elimination), the cache is borrowed directly here rather than
    /// through a trait abstraction; `cache.derive_item(item_number)`
    /// substitutes for the C reference's `initDatasetItem(cachePtr,
    /// (uint8_t*)rl, itemNumber)`.
    ///
    /// # v2-only simplification
    ///
    /// Per §5.5 F5 v2-only simplification, the C reference's `mp`
    /// alias collapses to direct `self.ma` access (the v2-branch of
    /// `auto& mp = (flags & V2) ? mem.ma : mem.mx;` at
    /// `vm_interpreted.cpp:89` — under v2 the alias is always
    /// `mem.ma`, so the Rust port skips the alias entirely). The F/E
    /// AES mix below similarly skips the non-v2 fallback
    /// (`nreg.f[i] = rx_xor_vec_f128(nreg.f[i], nreg.e[i])` at
    /// `vm_interpreted.cpp:119-120`), executing only the v2 AES-mix
    /// path. Per `60-no-monero-legacy.mdc`, the v1 paths are deleted
    /// rather than gated behind a runtime check.
    ///
    /// # Light-mode `datasetPrefetch` no-op
    ///
    /// The C reference's `datasetPrefetch(datasetOffset + (mp &
    /// CacheLineAlignMask))` at `vm_interpreted.cpp:92` is
    /// overridden as an empty body by
    /// `InterpretedLightVm::datasetPrefetch` at
    /// `vm_interpreted_light.hpp:55` — light-mode VMs have no
    /// actual dataset memory to prefetch. The Rust port (verifier-
    /// only, light-mode equivalent per
    /// [`RANDOMX_V2_PLAN.md`](../../../docs/design/RANDOMX_V2_PLAN.md)'s
    /// "no dataset" decision) omits the prefetch call entirely.
    ///
    /// # Stub-NOP dispatch (Phase 2c)
    ///
    /// Per §5.1 F1 + §5.1.1, the per-instruction loop dispatches
    /// through [`dispatch_instruction`]'s NOP body — every opcode is
    /// a no-op in 2c. The structural pieces of the iteration loop
    /// (spAddr derivation, register-load from scratchpad, F/E AES
    /// mix, `ma`/`mx` swap, scratchpad store) all run; only the
    /// per-instruction semantics are deferred to 2d.
    ///
    /// # Determinism / side-channel posture
    ///
    /// Pure function of `(self, cache)`. No allocator calls beyond
    /// the local `[F128; 4]` AES-mix buffers; no atomic ops; no
    /// global state. The scratchpad index space (`sp_addr0` /
    /// `sp_addr1` masked by [`SCRATCHPAD_L3_MASK_64`]) is bounded
    /// by construction per the constant's rustdoc — all
    /// `self.scratchpad[off..off + N]` accesses are in-bounds and
    /// non-panicking under the spec-pinned configuration.
    ///
    /// [`program`]: VmState::program
    pub(crate) fn execute_program(&mut self, cache: &crate::Cache) {
        // Per-chain `nreg.r` reset to mirror the C reference's
        // `NativeRegisterFile nreg;` construction at
        // `vm_interpreted.cpp:59`. The C struct declares
        // `int_reg_t r[RegistersCount] = { 0 };` at
        // `bytecode_machine.hpp:40`, so each chain begins with
        // integer registers zeroed regardless of the prior chain's
        // final `nreg.r` (the prior chain's writeback to `reg.r` at
        // `vm_interpreted.cpp:130-131` is consumed by the
        // inter-chain Blake2b at `randomx.cpp` but NOT by the next
        // chain's iteration loop — `nreg.r` is freshly zero-init,
        // not loaded from `reg.r`).
        //
        // Rust's [`VmState`] fuses `reg` and `nreg` into a single
        // `self.r` field for per-`30-cryptography.mdc` secret-
        // locality clarity (one source of truth per register). The
        // chain-boundary semantics that fall out of the C two-struct
        // shape must be re-asserted here at the Rust function entry,
        // or the second-and-subsequent chains' iteration 0 sees
        // non-zero `self.r` carried from the prior chain's writeback
        // and diverges from C byte-for-byte.
        //
        // `self.f` / `self.e` are NOT reset: the C `nreg.f` /
        // `nreg.e` are likewise uninitialized at chain start
        // (`rx_vec_f128 f[RegisterCountFlt]; e[RegisterCountFlt];`
        // at `bytecode_machine.hpp:41-42`), but the iteration loop
        // unconditionally overwrites both (`nreg.f[i] =
        // rx_cvt_packed_int_vec_f128(...)` / `nreg.e[i] =
        // maskRegisterExponentMantissa(...)` at `vm_interpreted.cpp:80-83`)
        // before any read. Iteration 0's overwrite makes the prior
        // chain's carryover unobservable, so the Rust port leaves
        // `self.f` / `self.e` untouched here (matches C's behavior
        // post-iter-0 by construction).
        //
        // `self.a` is set by [`Self::init_program`] (replaces the C
        // `randomx_vm::initialize` writes to `reg.a`); no reset
        // needed at this entry point.
        //
        // T8 spec-vector test (commit 7) is the production caller
        // that surfaces the chain-boundary divergence — single-chain
        // tests (T6 / T7) don't reproduce because `VmState::new`
        // returns `self.r = [0; 8]` already.
        self.r = [0; 8];

        // Spec §4.6.1: initial sp_addr derivation from mem.mx / mem.ma.
        // The two addresses drive the per-iteration scratchpad reads
        // and writes; both reset to 0 at the end of each iteration
        // (so they only carry from-iteration state on iteration 0).
        let mut sp_addr0: u32 = self.mx;
        let mut sp_addr1: u32 = self.ma;

        for _ic in 0..PROGRAM_ITERATIONS {
            let _used = self.execute_iteration(cache, sp_addr0, sp_addr1);
            // Spec §4.6 trailer: sp_addr0/1 reset to 0 between
            // iterations. The C reference re-derives them at the top
            // of each iteration from sp_mix; the reset here ensures
            // the XOR at iteration N+1 starts from 0 ^ sp_mix
            // rather than from the prior iteration's value, matching
            // `vm_interpreted.cpp:126-127`.
            sp_addr0 = 0;
            sp_addr1 = 0;
        }
    }

    /// Run **one** iteration of the spec §4.6 loop body.
    ///
    /// Factored out of [`Self::execute_program`] so the per-iteration
    /// snapshot points needed by the T6 and T7 spec-vector tests
    /// (`tests/vectors/reference/vm/t6_vm_spaddr_4iter.bin`,
    /// `t7_vm_aesmix_4iter.bin`) can capture intermediate state
    /// without duplicating the loop body in test code.
    ///
    /// Returns the spec §4.6.1 *post-mask* `(sp_addr0, sp_addr1)`
    /// pair — the values actually used to index the scratchpad for
    /// this iteration's loads and stores, after the `sp_mix`-driven
    /// derivation and the `SCRATCHPAD_L3_MASK_64` mask. Concretely:
    ///
    /// ```text
    /// sp_mix  = self.r[read_reg[0]] ^ self.r[read_reg[1]]
    /// sp_addr0 = (sp_addr0_in ^ (sp_mix as u32))         & SCRATCHPAD_L3_MASK_64
    /// sp_addr1 = (sp_addr1_in ^ ((sp_mix >> 32) as u32)) & SCRATCHPAD_L3_MASK_64
    /// ```
    ///
    /// `sp_addr0_in` / `sp_addr1_in` are `self.mx` / `self.ma` on
    /// iteration 0 and `0` / `0` on every subsequent iteration; the
    /// reset is the caller's responsibility ([`Self::execute_program`]
    /// performs it). Returning the masked pair (rather than re-deriving
    /// it at the call site) gives the snapshot tests a single
    /// authoritative source for the value.
    ///
    /// This is a `pub(crate)` helper for the T6 / T7 tests; production
    /// callers should use [`Self::execute_program`] instead.
    pub(crate) fn execute_iteration(
        &mut self,
        cache: &crate::Cache,
        sp_addr0_in: u32,
        sp_addr1_in: u32,
    ) -> (u32, u32) {
        // Spec §4.6.1: sp_mix derivation + sp_addr update.
        let rr0 = self.read_reg[0] as usize;
        let rr1 = self.read_reg[1] as usize;
        let sp_mix: u64 = self.r[rr0] ^ self.r[rr1];

        let mut sp_addr0 = sp_addr0_in;
        let mut sp_addr1 = sp_addr1_in;
        // SAFETY (clippy::cast_possible_truncation): `sp_mix as u32`
        // intentionally truncates to the low 32 bits, mirroring C
        // `spAddr0 ^= spMix;` where the uint32_t LHS forces the
        // uint64_t RHS to be implicitly truncated. Same for the
        // `(sp_mix >> 32) as u32` extracting the high 32 bits.
        #[allow(clippy::cast_possible_truncation)]
        {
            sp_addr0 ^= sp_mix as u32;
            sp_addr1 ^= (sp_mix >> 32) as u32;
        }
        sp_addr0 &= SCRATCHPAD_L3_MASK_64;
        sp_addr1 &= SCRATCHPAD_L3_MASK_64;

        // Spec §4.6.2: load r[0..8] from scratchpad at sp_addr0,
        // XOR-ing into the existing register values.
        let sp_addr0_usize = sp_addr0 as usize;
        for i in 0..REGISTERS_COUNT {
            let off = sp_addr0_usize + 8 * i;
            let bytes: [u8; 8] = self.scratchpad[off..off + 8]
                .try_into()
                .expect("SCRATCHPAD_L3_MASK_64 bounds sp_addr0 + 64 within scratchpad");
            self.r[i] ^= u64::from_le_bytes(bytes);
        }

        // Spec §4.6.3: load f[0..4] from scratchpad at sp_addr1
        // (overwriting prior f values).
        let sp_addr1_usize = sp_addr1 as usize;
        for i in 0..REGISTER_COUNT_FLT {
            let off = sp_addr1_usize + 8 * i;
            let bytes: [u8; 8] = self.scratchpad[off..off + 8]
                .try_into()
                .expect("SCRATCHPAD_L3_MASK_64 bounds sp_addr1 + 64 within scratchpad");
            self.f[i] = cvt_packed_int_to_f128(&bytes);
        }

        // Spec §4.6.3: load e[0..4] from scratchpad at sp_addr1 +
        // RegisterCountFlt-pair offset, with maskRegisterExponentMantissa
        // applied to enforce the positive-finite range FDIV_M requires.
        for i in 0..REGISTER_COUNT_FLT {
            let off = sp_addr1_usize + 8 * (REGISTER_COUNT_FLT + i);
            let bytes: [u8; 8] = self.scratchpad[off..off + 8]
                .try_into()
                .expect("SCRATCHPAD_L3_MASK_64 bounds sp_addr1 + 64 within scratchpad");
            let raw = cvt_packed_int_to_f128(&bytes);
            self.e[i] = mask_register_exponent_mantissa(raw, self.e_mask);
        }

        // Spec §4.6.4: dispatch through the 384 parsed instructions.
        // In Phase 2c the body is NOP per §5.1.1 frozen surface 1;
        // Phase 2d replaces dispatch_instruction's body with the
        // 28 opcode-handler dispatch table.
        let mut instr_idx = 0usize;
        while instr_idx < PROGRAM_SIZE {
            self.exec_pc = u16::try_from(instr_idx).expect("PROGRAM_SIZE fits in u16");
            self.branch_pc = u16::MAX;
            let instr = self.program.instructions[instr_idx];
            dispatch_instruction(&instr, self);
            if self.branch_pc == u16::MAX {
                instr_idx += 1;
            } else {
                instr_idx = usize::from(self.branch_pc);
            }
        }
        self.exec_pc = u16::MAX;
        self.branch_pc = u16::MAX;

        // Spec §4.6.5: dataset read prep — capture read_ptr from
        // the pre-mutation `ma`, then XOR-mutate `ma` from
        // r[read_reg[2]] ^ r[read_reg[3]] (v2-only mp aliasing
        // collapsed to direct ma access per §5.5 F5).
        let read_ptr: u64 = self.dataset_offset + u64::from(self.ma & CACHE_LINE_ALIGN_MASK);
        let rr2 = self.read_reg[2] as usize;
        let rr3 = self.read_reg[3] as usize;
        let mp_xor: u64 = self.r[rr2] ^ self.r[rr3];
        // SAFETY (clippy::cast_possible_truncation): mirrors C
        // `mp ^= nreg.r[readReg2] ^ nreg.r[readReg3];` where the
        // uint32_t LHS (mem.ma) truncates the uint64_t RHS.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.ma ^= mp_xor as u32;
        }
        // `datasetPrefetch(datasetOffset + (mp & CacheLineAlignMask))`
        // is a no-op in light mode per
        // `vm_interpreted_light.hpp:55` — the Rust port omits the
        // call entirely (no actual dataset memory to prefetch).

        // Spec §4.6.5: dataset read — XOR a 64-byte dataset item
        // into r[0..8]. Light-mode derives the item on-the-fly via
        // Cache::derive_item; mirrors
        // `vm_interpreted_light.cpp::datasetRead`.
        let item_number = read_ptr / u64::from(CACHE_LINE_SIZE);
        let item = cache.derive_item(item_number);
        for i in 0..REGISTERS_COUNT {
            let off = 8 * i;
            let bytes: [u8; 8] = item[off..off + 8]
                .try_into()
                .expect("Cache::derive_item returns 64 bytes; 8 u64 chunks fit by construction");
            self.r[i] ^= u64::from_le_bytes(bytes);
        }

        // Spec §4.6.5: std::swap(mem.mx, mem.ma).
        core::mem::swap(&mut self.mx, &mut self.ma);

        // Spec §4.6.6: store r[0..8] into scratchpad at sp_addr1.
        for i in 0..REGISTERS_COUNT {
            let off = sp_addr1_usize + 8 * i;
            self.scratchpad[off..off + 8].copy_from_slice(&self.r[i].to_le_bytes());
        }

        // Spec §4.6.7: F/E AES mix (v2 path).
        //
        // Per `vm_interpreted.cpp:99-117`: cast each f/e pair to
        // 16-byte AES state vectors, then for each of 4 e-keys
        // apply AES-encrypt to f[0]/f[2] and AES-decrypt to
        // f[1]/f[3] in lockstep (same e-key per round across all
        // 4 f-vectors). Result: each f[j] is mixed through 4
        // rounds using the 4 e-keys.
        //
        // The C uses `aesenc<softAes>` and `aesdec<softAes>` —
        // `aesenc` = ShiftRows + SubBytes + MixColumns + Xor(key)
        // (which is `crate::aes::cipher_round`); `aesdec` =
        // InvShiftRows + InvSubBytes + InvMixColumns + Xor(key)
        // (which is `crate::aes::equiv_inv_cipher_round`). Audit
        // posture: same AES round primitives the Phase 2b
        // commit-2 spec-vector tests validate via T6/T7 against
        // C-reference output.
        let mut freg: [[u8; 16]; 4] = [
            f128_to_aes_bytes(self.f[0]),
            f128_to_aes_bytes(self.f[1]),
            f128_to_aes_bytes(self.f[2]),
            f128_to_aes_bytes(self.f[3]),
        ];
        let ekey: [[u8; 16]; 4] = [
            f128_to_aes_bytes(self.e[0]),
            f128_to_aes_bytes(self.e[1]),
            f128_to_aes_bytes(self.e[2]),
            f128_to_aes_bytes(self.e[3]),
        ];
        for ek in &ekey {
            crate::aes::cipher_round(&mut freg[0], ek);
            crate::aes::equiv_inv_cipher_round(&mut freg[1], ek);
            crate::aes::cipher_round(&mut freg[2], ek);
            crate::aes::equiv_inv_cipher_round(&mut freg[3], ek);
        }
        for (i, fblock) in freg.iter().enumerate().take(REGISTER_COUNT_FLT) {
            self.f[i] = aes_bytes_to_f128(fblock);
        }

        // Spec §4.6.8: store f[0..4] (16 bytes each) into
        // scratchpad at sp_addr0.
        for i in 0..REGISTER_COUNT_FLT {
            let off = sp_addr0_usize + 16 * i;
            self.scratchpad[off..off + 8].copy_from_slice(&self.f[i][0].to_bits().to_le_bytes());
            self.scratchpad[off + 8..off + 16]
                .copy_from_slice(&self.f[i][1].to_bits().to_le_bytes());
        }

        (sp_addr0, sp_addr1)
    }
}

impl Drop for VmState {
    /// Empty drop — the 2 MiB `scratchpad` buffer is freed by the
    /// default `Box<[u8; RANDOMX_SCRATCHPAD_L3]>` destructor, the
    /// 3 KiB `program` buffer is freed by the default `Box<Program>`
    /// destructor, and every other field is `Copy`/`Default` inline
    /// state that needs no destructor. No zeroization is required
    /// because every field is public-input-only per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.4 (scratchpad, register file, parsed program, memory
    /// registers, temp-hash buffer — all deterministic functions of
    /// the public `seedhash` + `data` inputs).
    ///
    /// # Why the impl exists if it does nothing
    ///
    /// The empty [`Drop`] is the review-surface hook for future field
    /// additions to [`VmState`]: any added field that does carry
    /// secret material (e.g., a hypothetical
    /// `ledger_session_secret: [u8; 32]` in some far-future protocol
    /// extension) lands inside an already-present [`Drop`] body
    /// rather than requiring a future contributor to remember to add
    /// the impl — which is the failure mode that produces the "we
    /// forgot to zeroize" class of bugs
    /// [`35-secure-memory.mdc`](../../../.cursor/rules/35-secure-memory.mdc)
    /// names. Per
    /// [`16-architectural-inheritance.mdc`](../../../.cursor/rules/16-architectural-inheritance.mdc)'s
    /// continuous-discipline corollary, the impl is structurally
    /// cheaper than the dropped-discipline class of bug it preempts.
    /// The same pattern lands on [`crate::Cache`] per
    /// `cache.rs:454-478`.
    fn drop(&mut self) {
        // INTENT: no-op. See impl rustdoc for the public-input-only
        // rationale and the future-field-addition review-surface hook.
    }
}

/// Per-instruction dispatch — the §5.1.1 frozen-surface-1 function-
/// body replacement point for Phase 2c → Phase 2d.
///
/// **Phase 2c body (commit 6, stub): NOP** — every opcode is a no-op.
/// The structural pieces of the interpreter loop
/// ([`VmState::execute_program`]'s spAddr derivation, register-load
/// from scratchpad, F/E AES mix, ma/mx swap, scratchpad store) run
/// per spec §4.6.4-§4.6.8 around this NOP body and exercise the full
/// per-iteration data-flow surface; only the per-instruction
/// semantics (IADD_RS, ISUB_R, IMUL_R, ..., the 28 opcode handlers
/// per `bytecode_machine.hpp` audit at R0-D1) are deferred to Phase
/// 2d's body replacement.
///
/// **Phase 2d body (replaces this body, not the signature):** a
/// table-driven 28-arm dispatch per spec §5.1 (the 29 dispatchable
/// opcodes collapse to 28 handlers because IMUL_RCP dispatches
/// through IMUL_R per `bytecode_machine.cpp:75` — see
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.1.1 R0-D1).
///
/// # Function-body replacement contract (per §5.1.1 frozen surface 1)
///
/// Phase 2d **cannot** change this signature:
///
/// - The two-parameter shape (`&Instruction` + `&mut VmState`) is
///   the surface every opcode handler operates against. Adding
///   parameters (e.g., a `&Cache` for a hypothetical "memory-mode
///   read" opcode) is incorrect against the C reference's
///   `bytecode_machine.hpp:145-270` audit — no per-instruction
///   handler reads the cache. The cache is read once per iteration
///   in [`VmState::execute_program`]'s dataset-read step, not here.
/// - No return value. CBRANCH's PC mutation is via `state.program`
///   per the C reference's `compileInstruction`-driven branch-target
///   resolution.
/// - No lifetime/borrow shape change. [`VmState`] owns its data;
///   the cache borrow is the caller's, not the dispatcher's.
///
/// **Reopening criterion** (per `21-reversion-clause-discipline.mdc`):
/// Phase 2d's per-opcode benchmark may demonstrate the single-pass
/// signature fails the ≤3.0× C-reference perf budget for reasons
/// attributable to per-call decode cost. Iff that evidence surfaces,
/// the signature reopens to the IBC 2-pass form
/// (`fn dispatch_instruction(ibc: &InstructionByteCode, state: &mut
/// VmState)`); the re-evaluation lands as a 2d Round 1 design
/// finding, not implementation-time reactive scope expansion. See
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.1.1 "Reopening criterion (reversion-clause shape)".
///
/// # Determinism / side-channel posture
///
/// Pure NOP function. No-ops on every input. Phase 2d's body
/// inherits the constant-time-or-explicit-rejection discipline per
/// `30-cryptography.mdc` for per-opcode timing equivalence.
fn dispatch_instruction(instr: &Instruction, state: &mut VmState) {
    let dst = int_reg(instr.dst);
    let src = int_reg(instr.src);
    let imm = sign_extend_i32_to_i64(instr.imm32);

    match decode_instruction_type(instr.opcode) {
        InstructionType::IAddRs => {
            let addend = state.r[src].wrapping_shl(mod_shift(instr)).wrapping_add(
                if dst == REGISTER_NEEDS_DISPLACEMENT {
                    imm
                } else {
                    0
                },
            );
            state.r[dst] = state.r[dst].wrapping_add(addend);
        }
        InstructionType::IAddM => {
            let mask = memory_mask(instr, dst, src);
            let base = if src == dst { 0 } else { state.r[src] };
            let value = load_scratchpad_u64(state, base, imm, mask);
            state.r[dst] = state.r[dst].wrapping_add(value);
        }
        InstructionType::ISubR => {
            let value = if src == dst { imm } else { state.r[src] };
            state.r[dst] = state.r[dst].wrapping_sub(value);
        }
        InstructionType::ISubM => {
            let mask = memory_mask(instr, dst, src);
            let base = if src == dst { 0 } else { state.r[src] };
            let value = load_scratchpad_u64(state, base, imm, mask);
            state.r[dst] = state.r[dst].wrapping_sub(value);
        }
        InstructionType::IMulR => {
            let value = if src == dst { imm } else { state.r[src] };
            state.r[dst] = state.r[dst].wrapping_mul(value);
        }
        InstructionType::IMulM => {
            let mask = memory_mask(instr, dst, src);
            let base = if src == dst { 0 } else { state.r[src] };
            let value = load_scratchpad_u64(state, base, imm, mask);
            state.r[dst] = state.r[dst].wrapping_mul(value);
        }
        InstructionType::IMulhR => {
            state.r[dst] = crate::superscalar::mulh(state.r[dst], state.r[src]);
        }
        InstructionType::IMulhM => {
            let mask = memory_mask(instr, dst, src);
            let base = if src == dst { 0 } else { state.r[src] };
            let value = load_scratchpad_u64(state, base, imm, mask);
            state.r[dst] = crate::superscalar::mulh(state.r[dst], value);
        }
        InstructionType::ISMulhR => {
            state.r[dst] = crate::superscalar::smulh_u64(state.r[dst], state.r[src]);
        }
        InstructionType::ISMulhM => {
            let mask = memory_mask(instr, dst, src);
            let base = if src == dst { 0 } else { state.r[src] };
            let value = load_scratchpad_u64(state, base, imm, mask);
            state.r[dst] = crate::superscalar::smulh_u64(state.r[dst], value);
        }
        InstructionType::IMulRcp => {
            if !is_zero_or_power_of_two(instr.imm32) {
                state.r[dst] =
                    state.r[dst].wrapping_mul(crate::superscalar::randomx_reciprocal(instr.imm32));
            }
        }
        InstructionType::INegR => {
            state.r[dst] = (!state.r[dst]).wrapping_add(1);
        }
        InstructionType::IXorR => {
            let value = if src == dst { imm } else { state.r[src] };
            state.r[dst] ^= value;
        }
        InstructionType::IXorM => {
            let mask = memory_mask(instr, dst, src);
            let base = if src == dst { 0 } else { state.r[src] };
            let value = load_scratchpad_u64(state, base, imm, mask);
            state.r[dst] ^= value;
        }
        InstructionType::IRorR => {
            let value = if src == dst {
                u64::from(instr.imm32)
            } else {
                state.r[src]
            };
            state.r[dst] = rotr(state.r[dst], (value & 63) as u32);
        }
        InstructionType::IRolR => {
            let value = if src == dst {
                u64::from(instr.imm32)
            } else {
                state.r[src]
            };
            state.r[dst] = rotl(state.r[dst], (value & 63) as u32);
        }
        InstructionType::ISwapR => {
            if src != dst {
                state.r.swap(dst, src);
            }
        }
        InstructionType::CBranch => {
            let shift = mod_cond(instr) + RANDOMX_JUMP_OFFSET;
            let mut addend = imm | (1u64 << shift);
            if shift > 0 {
                addend &= !(1u64 << (shift - 1));
            }
            state.r[dst] = state.r[dst].wrapping_add(addend);
            if (state.r[dst] & (CONDITION_MASK << shift)) == 0 {
                state.branch_pc = state.program.cbranch_table[usize::from(state.exec_pc)];
            }
        }
        InstructionType::CfRound => execute_cfround(instr, state),
        InstructionType::IStore => {
            let mask = if mod_cond(instr) < 14 {
                if mod_mem(instr) {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                }
            } else {
                SCRATCHPAD_L3_MASK
            };
            store_scratchpad_u64(state, state.r[dst], imm, mask, state.r[src]);
        }
        InstructionType::FSwapR => {
            let dst = int_reg(instr.dst);
            if dst < REGISTER_COUNT_FLT {
                state.f[dst] = state.f[dst].swap_lanes();
            } else {
                let dst = dst - REGISTER_COUNT_FLT;
                state.e[dst] = state.e[dst].swap_lanes();
            }
        }
        InstructionType::FAddR => {
            let dst = fp_reg(instr.dst);
            let src = fp_reg(instr.src);
            state.f[dst] = state.f[dst].add_unrestricted(state.a[src]);
        }
        InstructionType::FAddM => {
            let dst = fp_reg(instr.dst);
            let src = int_reg(instr.src);
            let mask = if mod_mem(instr) {
                SCRATCHPAD_L1_MASK
            } else {
                SCRATCHPAD_L2_MASK
            };
            let value = load_scratchpad_f128(state, state.r[src], imm, mask);
            state.f[dst] = state.f[dst].add_unrestricted(value);
        }
        InstructionType::FSubR => {
            let dst = fp_reg(instr.dst);
            let src = fp_reg(instr.src);
            state.f[dst] = state.f[dst].sub_unrestricted(state.a[src]);
        }
        InstructionType::FSubM => {
            let dst = fp_reg(instr.dst);
            let src = int_reg(instr.src);
            let mask = if mod_mem(instr) {
                SCRATCHPAD_L1_MASK
            } else {
                SCRATCHPAD_L2_MASK
            };
            let value = load_scratchpad_f128(state, state.r[src], imm, mask);
            state.f[dst] = state.f[dst].sub_unrestricted(value);
        }
        InstructionType::FScalR => {
            let dst = fp_reg(instr.dst);
            state.f[dst] = state.f[dst].xor_with_scale_mask();
        }
        InstructionType::FMulR => {
            let dst = fp_reg(instr.dst);
            let src = fp_reg(instr.src);
            state.e[dst] = state.e[dst].mul_unrestricted(state.a[src]);
        }
        InstructionType::FDivM => {
            let dst = fp_reg(instr.dst);
            let src = int_reg(instr.src);
            let mask = if mod_mem(instr) {
                SCRATCHPAD_L1_MASK
            } else {
                SCRATCHPAD_L2_MASK
            };
            let value = load_scratchpad_f128(state, state.r[src], imm, mask);
            let value = mask_register_exponent_mantissa(value, state.e_mask);
            state.e[dst] = state.e[dst].div_masked(value);
        }
        InstructionType::FSqrtR => {
            let dst = fp_reg(instr.dst);
            state.e[dst] = state.e[dst].sqrt_unrestricted();
        }
    }
}

/// Compute the 32-byte RandomX v2 hash of `data` against the
/// [`PreparedCache`](crate::PreparedCache) the caller derived
/// from a [`Seedhash`](crate::Seedhash), per spec §4.1 + spec §4.6 +
/// [`external/randomx-v2/src/randomx.cpp:380-410`](../../../external/randomx-v2/src/randomx.cpp)'s
/// `randomx_calculate_hash` at pin `aaafe71`.
///
/// This is the **single hash-producing entry point** of the
/// `shekyl-pow-randomx` crate — the public surface the
/// [`shekyl-ffi`](../../../rust/shekyl-ffi) FFI shim (Phase 3a) and
/// the daemon's block-validation path consume. No other `pub fn`
/// produces a RandomX hash; no internal API circumvents this
/// function's chain-of-Blake2b + scratchpad + program-iteration
/// composition.
///
/// # Inputs
///
/// - `prepared` — a [`PreparedCache`](crate::PreparedCache) bundle
///   carrying the (crate-private) `Cache` and the
///   [`Seedhash`](crate::Seedhash) it was derived from. Per
///   [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
///   §1.1 Round 2, the bundle replaces the pre-Round-2
///   `(&Cache, &Seedhash)` parameter pair: the cache-seedhash
///   pairing is enforced at construction
///   ([`PreparedCache::derive`](crate::PreparedCache::derive) is
///   the only public path), so wrong-cache-for-seedhash is
///   unrepresentable at the call site. The dataset items
///   `VmState::execute_program` reads each iteration are computed
///   on-the-fly via the inner cache's `derive_item` (accessed
///   through the `pub(crate)` `cache_ref`). The seedhash is
///   **documentary-only** at the per-hash level (the spec's `K`
///   argument is consumed by the cache-derive primitive, not by
///   the hash chain itself); the bundle carries it so the pairing
///   is type-checked, not so the hash body re-reads it.
/// - `data` — the spec §2 `H` argument; arbitrary-length input
///   whose hash this function produces. Internally consumed by the
///   initial `temp_hash = Blake2b-512(data)` step.
///
/// # Output
///
/// A 32-byte `Blake2b<U32>(register_file)` over the final
/// register-file state (after the eighth `init_program` +
/// `execute_program` chain and the `AesHash1R(scratchpad) → a`
/// overwrite).
///
/// # Hash composition (spec §4.1 + §4.6, mirroring C
/// `randomx_calculate_hash`)
///
/// 1. `temp_hash := Blake2b-512(data)` — 64-byte seed for the AES
///    chains. Spec §4.1; C ref `randomx.cpp:392-394`. `seedhash` is
///    NOT mixed into this Blake2b call (see §2's `K`/`H` separation
///    + the module-level rustdoc justification).
/// 2. `VmState::init_scratchpad(&mut temp_hash)` — fill the
///    2 MiB scratchpad via `AesGenerator1R` keyed by `temp_hash`,
///    which mutates `temp_hash` to the post-fill AES state (this
///    mutation chains forward to the first `VmState::init_program`
///    call). Spec §4.2; C ref `virtual_machine.cpp:132-134` +
///    `randomx.cpp:395`.
/// 3. For `chain in 0..RANDOMX_PROGRAM_COUNT - 1` (= 7 chains):
///    - `VmState::init_program(&temp_hash)` — generate the
///      program + initialize register state from `temp_hash`. The
///      Rust port's `fill_aes_4r_x4` does NOT mutate `temp_hash`
///      (the C ref does, but the mutation is immediately
///      overwritten by step 3.3 and never read between, so the Rust
///      port's non-mutating signature is byte-equivalent per
///      §14 R0-D8 results-fidelity discipline). Spec §4.5; C ref
///      `virtual_machine.cpp:137-138` + `:72-94`.
///    - `VmState::execute_program(cache)` — execute the parsed
///      program for `PROGRAM_ITERATIONS` (2048) iterations. Spec
///      §4.6; C ref `vm_interpreted.cpp:57-138`.
///    - `temp_hash := Blake2b-512(register_file)` — overwrite
///      `temp_hash` with the Blake2b of the 256-byte register file.
///      The register-file layout is `r[0..8] (64 bytes) || f[0..4]
///      (64 bytes) || e[0..4] (64 bytes) || a[0..4] (64 bytes)`,
///      with each `u64` little-endian and each `f64` as IEEE-754
///      little-endian bit pattern, matching C's `RegisterFile`
///      struct layout per `common.hpp:190-195`. Spec §4.1.3; C ref
///      `randomx.cpp:399`.
/// 4. The eighth (last) chain:
///    - `VmState::init_program(&temp_hash)`.
///    - `VmState::execute_program(cache)`.
///    - **NO** chain-step Blake2b after this last execute — instead,
///      the finalize step below produces the 32-byte output.
/// 5. **Finalize (spec §4.7; C ref
///    `virtual_machine.cpp:120-123` + `randomx.cpp:402-403`):**
///    - `aes::hash_aes_1r_x4(scratchpad → a)` — hash the entire
///      scratchpad into the 64-byte `a` register array, overwriting
///      the program-init-derived `a` values.
///    - `output := Blake2b<U32>(register_file)` — 32-byte Blake2b
///      over the final register file (with `a` now holding the
///      AesHash1R'd scratchpad digest).
///
/// # Phase 2c stub-NOP dispatch caveat
///
/// Per `dispatch_instruction`'s rustdoc, Phase 2c's bytecode
/// dispatch is NOP — every per-instruction opcode is a no-op. The
/// scratchpad-init, program-init, F/E AES mix, dataset-read, and
/// scratchpad-store steps all execute correctly, but the per-iteration
/// register arithmetic that real RandomX requires (the 28 opcode
/// handlers) is deferred to Phase 2d. As a result, [`compute_hash`]'s
/// Phase 2c output is **not** consensus-equivalent with the C
/// reference RandomX v2 hash — the function is structurally complete
/// (deterministic, type-safe, panic-safe, allocates correctly) but
/// semantically a stub. Spec-vector parity tests (T1–T8 per §5.11.1
/// and §6) land in Phase 2c's commit 7 to fixture the stub's
/// deterministic output; the C-reference-equivalence tests land in
/// Phase 2d's spec-vector update.
///
/// # Determinism / side-channel posture
///
/// Pure function of `(prepared, data)` — equivalently
/// `(cache, seedhash, data)` decomposed inside the bundle. The
/// seedhash is documentary-only for the per-hash chain. No
/// allocator calls outside the per-call `VmState::new` (2 MiB
/// scratchpad + 3 KiB program). No atomic ops, no module-level
/// mutable state, no time-based behavior. Thread-safe by
/// construction: every call allocates its own `VmState`; no shared
/// mutable state between calls.
///
/// Per the §5.11.4 threat-model disposition, every byte of every
/// internal buffer is a deterministic function of `(prepared, data)`,
/// both of which are public by construction (the cache inside
/// `prepared` is derived from a block-header seedhash; data is a
/// block-header hash candidate). No constant-time discipline
/// applies to access patterns; no wipe-on-drop is load-bearing for
/// confidentiality.
///
/// # Performance posture (per §8 budget, R0-D12 reconciliation)
///
/// At the Phase 2c stub-NOP cost, [`compute_hash`] is dominated by
/// the 8 × 2048 iteration loop's per-iteration work: the AES-mix
/// (8 chains × 2048 iterations × 16 AES rounds = ~262_144 AES round
/// operations) + the `Cache::derive_item` calls (one per iteration ×
/// 8 chains × 2048 iterations = ~16_384 SuperscalarHash chains) +
/// the scratchpad I/O + the Blake2b inter-chain hashes. The 2 MiB
/// scratchpad allocation is sub-millisecond on contemporary x86-64
/// and is dominated by the loop body, not the other way around.
///
/// **Empirical baseline (commit 8).** The `compute_hash_alloc::per_call`
/// criterion bench at
/// [`rust/shekyl-pow-randomx/BENCH_RESULTS.md`](../../rust/shekyl-pow-randomx/BENCH_RESULTS.md)
/// measures median **296.00 ms per call** (95% CI [292.81 ms,
/// 299.47 ms]) on an i9-11950H (Debian 13, kernel
/// `6.12.88+deb13-amd64`, N=100). The §8 plan-doc budget (≤100 µs)
/// bound the *allocation portion specifically* — not the full
/// pipeline; the §5.8 plan-doc disposition #1 parenthetical
/// authorized the implementation-PR-time bench-shape decision the
/// commit-8 bench actually implements (end-to-end pipeline, because
/// that matches the bench function call). The reconciliation
/// (re-baseline the budget against empirical hardware-class
/// measurements; add an allocation-only sub-bench; or defer the
/// per-hash latency check to Phase 2g's Rust-vs-C ratio per
/// R3-minor-2's `tests/perf/per_hash_latency.rs` placeholder) is a
/// §13-forward-path question for 2d / 2f / 2g design rounds. The
/// disposition is documented in
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §14 Round 0 R0-D12 with substrate-anchored reopening criteria
/// per `21-reversion-clause-discipline.mdc`.
///
/// **Why the dominant cost is the loop body, not the SS execution.**
/// Stub-NOP `dispatch_instruction` does no per-instruction work, so
/// the per-iteration cost reduces to: SS chain execution (~16 µs
/// per item per `Cache::derive_item`'s commit-3 measured cost) +
/// scratchpad load/store + AES f/e mix + the per-iter Blake2b
/// chaining. Phase 2g's inline-superscalar work is the optimization
/// path that brings this into the per-hash budget Phase 0 §6 names;
/// the Phase 2c shape is functionally correct (T1-T8 byte-identical
/// to the C reference under stub-NOP dispatch) and the Phase 2g
/// shape is production-fast.
pub fn compute_hash(prepared: &crate::PreparedCache, data: &[u8]) -> [u8; 32] {
    let mut state = VmState::new();
    compute_hash_inner(&mut state, prepared, data)
}

/// Inner `compute_hash` body, factored out so the Phase 2F cfg-gated
/// `vm_pool::VmStatePool` path can share the dispatch logic with the
/// production no-pool [`compute_hash`] entry point. The pool module
/// is gated by `#[cfg(any(test, feature = "internal-pool-bench"))]`,
/// so the rustdoc link cannot be hard-coded — production builds
/// (no feature flag) do not compile the module.
///
/// Per `docs/design/RANDOMX_V2_PHASE2F_PLAN.md` §3.3 Round 3, the
/// pool body is implemented behind
/// `#[cfg(any(test, feature = "internal-pool-bench"))]` and the
/// bench harness measures both paths directly. Both paths feed
/// through this inner function so the dispatch loop is a single
/// source of truth — duplicating the body would fork the
/// consensus-relevant code path between two call sites.
///
/// # Pool-reuse safety
///
/// The function takes `&mut VmState` rather than allocating one
/// internally. When called from the pool path, `state` may be a
/// recycled instance whose fields carry residue from a prior call.
/// Every field that is *read* before being written by the dispatch
/// pipeline is re-initialized below or by [`VmState::execute_program`]
/// at chain entry:
///
/// - `r[]` is zero-set by [`VmState::execute_program`] at every
///   chain entry (mirroring the C reference's `NativeRegisterFile`
///   per-chain reconstruction; see that function's rustdoc).
/// - `f[]`, `e[]` are overwritten by iteration 0's `nreg.f[i]` /
///   `nreg.e[i]` writes before any read.
/// - `a[]` is overwritten by [`VmState::init_program`].
/// - `scratchpad` is overwritten byte-for-byte by
///   [`VmState::init_scratchpad`].
/// - `e_mask`, `ma`, `mx`, `read_reg`, `dataset_offset`,
///   `program.instructions`, `program.cbranch_table` are written by
///   [`VmState::init_program`].
/// - `branch_pc` / `exec_pc` are set per-instruction by the
///   iteration loop before being read.
/// - `temp_hash` is unread by the current production path
///   (see the field's rustdoc; `compute_hash` uses a local
///   `temp_hash: [u8; 64]` buffer).
///
/// The only field whose carry-over could be observable is
/// [`VmState::fprc`], the FPU rounding-mode tracker that Phase 2d's
/// CFROUND handler writes. The C reference's `nreg.fprc` resets to
/// 0 at chain entry; the Rust port mirrors that here at function
/// entry for pool-reuse safety. The hardware FPU rounding-mode
/// register is independently reset via
/// [`crate::fpu_rounding::set_rounding_mode`].
pub(crate) fn compute_hash_inner(
    state: &mut VmState,
    prepared: &crate::PreparedCache,
    data: &[u8],
) -> [u8; 32] {
    // The cache-seedhash binding travels in the `PreparedCache`
    // bundle per Phase 2F §1.1 Round 2. The dispatch loop reads
    // the inner `Cache` via `prepared.cache_ref()`; the seedhash
    // is available via `prepared.seedhash()` for any future
    // body-level cache-binding assertions (currently the binding
    // is type-enforced by `PreparedCache::derive`'s pairing of
    // cache + seedhash at construction; a runtime
    // `debug_assert!` would re-derive the cache and defeat its
    // purpose).
    let cache = prepared.cache_ref();

    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Blake2b512, Digest};

    crate::fpu_rounding::set_rounding_mode(0);

    // Pool-reuse safety: reset `fprc` so a recycled `VmState` from
    // [`crate::vm_pool::VmStatePool`] does not carry forward the
    // prior call's CFROUND mode in the in-memory tracker. The
    // hardware FPU register is reset by `set_rounding_mode(0)` above;
    // this line keeps the in-memory shadow consistent. For a
    // freshly-constructed [`VmState`] from [`VmState::new`] the
    // assignment is a no-op (the field already starts at 0).
    state.fprc = 0;

    // Step 1: temp_hash = Blake2b-512(data). Output is 64 bytes,
    // which becomes the seed for `init_scratchpad`.
    let mut temp_hash: [u8; 64] = {
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        let out = hasher.finalize();
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&out);
        buf
    };

    // Step 2: init_scratchpad. This mutates temp_hash to the
    // post-AES-1R-x4 stream state, chaining forward to step 3.
    state.init_scratchpad(&mut temp_hash);

    // Step 3: first `RANDOMX_PROGRAM_COUNT - 1` (= 7) chains.
    // Each chain runs init_program + execute_program, then
    // overwrites temp_hash with Blake2b-512(register_file).
    for _chain in 0..(RANDOMX_PROGRAM_COUNT - 1) {
        state.init_program(&temp_hash);
        state.execute_program(cache);

        let mut hasher = Blake2b512::new();
        feed_register_file_to_hasher(&*state, &mut hasher);
        let out = hasher.finalize();
        temp_hash.copy_from_slice(&out);
    }

    // Step 4: last chain — init + execute, no chain-step Blake2b.
    state.init_program(&temp_hash);
    state.execute_program(cache);

    // Step 5a: AesHash1R the scratchpad into a 64-byte buffer that
    // mirrors the C reference's `&reg.a` post-`hashAes1Rx4` state.
    // Mirrors `hashAes1Rx4<softAes>(scratchpad, ScratchpadSize, &reg.a)`
    // at `virtual_machine.cpp:121`. The Rust port deliberately does
    // NOT round-trip these bytes through `state.a` (which is typed
    // `[F128; 4] = [[f64; 2]; 4]`) before feeding them to the final
    // Blake2b. The C reference treats `reg.a` as a raw 64-byte memory
    // region during the final hash (`blake2b(&reg, sizeof(RegisterFile))`
    // reads it as bytes), whereas a load-store of arbitrary AES output
    // bytes through Rust's `f64` slot risks bit-pattern divergence for
    // pathological NaN encodings the AES output may produce — the
    // hash output is not constrained to valid IEEE-754 representations.
    // Hashing the bytes directly side-steps the round-trip entirely
    // and matches the C ref byte-for-byte regardless of the AES
    // output's interpretation as a float. See `state.a` field rustdoc
    // for the post-`hashAes1Rx4` invariant about its abandoned
    // observable shape.
    let mut a_bytes = [0u8; 64];
    crate::aes::hash_aes_1r_x4(&state.scratchpad[..], &mut a_bytes);

    // Step 5b: Blake2b<U32>(register_file) → 32-byte output.
    // Mirrors `blake2b(out, outSize, &reg, sizeof(RegisterFile), ...)`
    // at `virtual_machine.cpp:122` with outSize = RANDOMX_HASH_SIZE = 32.
    // Feeds r/f/e from state (their bit patterns are the iteration-loop
    // outputs, byte-equivalent to the C ref's `nreg`-to-`reg` writeback)
    // and the raw `a_bytes` for the AES-hashed slot.
    let mut hasher = Blake2b::<U32>::new();
    feed_register_file_to_hasher_with_raw_a(&*state, &a_bytes, &mut hasher);
    let out = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&out);
    crate::fpu_rounding::set_rounding_mode(0);
    output
}

/// Feed the 256-byte register-file (`r[0..8] || f[0..4] || e[0..4] ||
/// a[0..4]`) to a [`Digest`] hasher, matching the C reference's
/// `blake2b(..., &reg, sizeof(RegisterFile), ...)` byte-for-byte.
///
/// The C `RegisterFile` struct layout per
/// [`external/randomx-v2/src/common.hpp:190-195`](../../../external/randomx-v2/src/common.hpp)
/// is `int_reg_t r[8]` (8 × 8 = 64 bytes) followed by `fpu_reg_t
/// f[4]` (4 × 16 = 64 bytes) followed by `fpu_reg_t e[4]` (64 bytes)
/// followed by `fpu_reg_t a[4]` (64 bytes) — total 256 bytes. Each
/// `int_reg_t` is `uint64_t` (little-endian on x86); each
/// `fpu_reg_t` is `struct { double lo; double hi; }` (two IEEE-754
/// binary64 little-endian bit patterns). The Rust port serializes
/// in the same order with `to_le_bytes` / `to_bits().to_le_bytes()`
/// to produce a byte-identical input to Blake2b.
///
/// Used `RANDOMX_PROGRAM_COUNT - 1 = 7` times by [`compute_hash`]'s
/// Step 3 (the per-chain `temp_hash` overwrite loop, Blake2b-512).
/// The final 32-byte output (Step 5b, `Blake2b<U32>`) does **not**
/// use this function — it uses
/// [`feed_register_file_to_hasher_with_raw_a`] instead, which
/// substitutes the raw 64-byte `hashAes1Rx4` output for `state.a`
/// to avoid round-tripping arbitrary AES bytes through `f64`.
/// See that function's rustdoc for the rationale.
///
/// Factored out (rather than inlined into the chain loop) so the 7
/// call sites are guaranteed to feed byte-identical inputs to
/// Blake2b — any drift across the inter-chain `temp_hash`
/// overwrites would be a consensus bug invisible to local unit
/// tests.
///
/// # Determinism / side-channel posture
///
/// Pure function of `state`. Constant-time per the
/// `to_le_bytes` / `to_bits` semantics.
fn feed_register_file_to_hasher<D: blake2::Digest>(state: &VmState, hasher: &mut D) {
    for r_val in &state.r {
        hasher.update(r_val.to_le_bytes());
    }
    for f_pair in &state.f {
        hasher.update(f_pair[0].to_bits().to_le_bytes());
        hasher.update(f_pair[1].to_bits().to_le_bytes());
    }
    for e_pair in &state.e {
        hasher.update(e_pair[0].to_bits().to_le_bytes());
        hasher.update(e_pair[1].to_bits().to_le_bytes());
    }
    for a_pair in &state.a {
        hasher.update(a_pair[0].to_bits().to_le_bytes());
        hasher.update(a_pair[1].to_bits().to_le_bytes());
    }
}

/// Same as [`feed_register_file_to_hasher`] but substitutes the
/// 64-byte raw `a_bytes` slot in place of `state.a`'s `f64`-typed
/// view. Used by [`compute_hash`]'s final step where the AES-hashed
/// scratchpad bytes are NOT guaranteed to be valid IEEE-754
/// representations and must not pass through `f64::from_bits` ->
/// `to_bits` round-trip before hashing.
///
/// The C reference's `getFinalResult` writes the `hashAes1Rx4` output
/// into `&reg.a` (64 bytes raw) and then hashes the whole `RegisterFile`
/// struct via `blake2b(&reg, sizeof(RegisterFile))`, which treats
/// `reg.a` as raw bytes. Mirroring that path requires hashing the
/// raw 64-byte AES output directly rather than reconstructing it
/// from `state.a`'s `f64` array — Rust's `f64::from_bits` and
/// `f64::to_bits` are documented bit-preserving on x86_64, but the
/// `state.a` field is typed `[F128; 4] = [[f64; 2]; 4]`, and arbitrary
/// AES output bytes interpreted as `f64` can land on signaling-NaN
/// bit patterns whose canonical handling is not load-store-safe in
/// all backend code paths. Per `30-cryptography.mdc`'s constant-time
/// and behavior-equivalence discipline, eliminate the round-trip
/// entirely.
///
/// Inputs:
/// * `state` — VM state; only `r`, `f`, `e` are read.
/// * `a_bytes` — 64-byte raw AES-hashed scratchpad slot. Replaces
///   `state.a` in the hash input.
/// * `hasher` — any `Digest` instance.
fn feed_register_file_to_hasher_with_raw_a<D: blake2::Digest>(
    state: &VmState,
    a_bytes: &[u8; 64],
    hasher: &mut D,
) {
    for r_val in &state.r {
        hasher.update(r_val.to_le_bytes());
    }
    for f_pair in &state.f {
        hasher.update(f_pair[0].to_bits().to_le_bytes());
        hasher.update(f_pair[1].to_bits().to_le_bytes());
    }
    for e_pair in &state.e {
        hasher.update(e_pair[0].to_bits().to_le_bytes());
        hasher.update(e_pair[1].to_bits().to_le_bytes());
    }
    hasher.update(a_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; 64] = [0xAB; 64];
    const SEED_B: [u8; 64] = [0xCD; 64];

    /// Byte-equality between two scratchpads.
    fn scratchpads_equal(a: &[u8; RANDOMX_SCRATCHPAD_L3], b: &[u8; RANDOMX_SCRATCHPAD_L3]) -> bool {
        a.as_slice() == b.as_slice()
    }

    /// Field-wise equality between two [`Instruction`]s.
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T5'a: "compared via field-wise equality across
    /// `opcode`, `dst`, `src`, `mod_`, `imm32`". Local-to-tests
    /// helper so [`Instruction`]'s production derive list stays
    /// minimal per R0-D6 (tests-use-the-actual-API discipline; no
    /// production trait additions to ease test ergonomics).
    fn instructions_equal(a: &Instruction, b: &Instruction) -> bool {
        a.opcode == b.opcode
            && a.dst == b.dst
            && a.src == b.src
            && a.mod_ == b.mod_
            && a.imm32 == b.imm32
    }

    /// T3'a determinism property: two `VmState`s each fed the same
    /// seed to `init_scratchpad` produce byte-identical scratchpads
    /// **and** advance the seed to byte-identical post-call states.
    /// Catches hidden state inside `fill_aes_1r_x4`, allocator-
    /// dependent layout, or any per-call mutable state in the AES
    /// path.
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T3'a sub-test 1/2.
    #[test]
    fn t3_prime_init_scratchpad_determinism_same_seed_twice() {
        let mut vm1 = VmState::new();
        let mut vm2 = VmState::new();
        let mut seed1 = SEED_A;
        let mut seed2 = SEED_A;

        vm1.init_scratchpad(&mut seed1);
        vm2.init_scratchpad(&mut seed2);

        assert!(
            scratchpads_equal(&vm1.scratchpad, &vm2.scratchpad),
            "init_scratchpad(SAME_SEED) produced divergent scratchpads",
        );
        assert_eq!(
            seed1, seed2,
            "init_scratchpad(SAME_SEED) advanced the seed divergently \
             (the AES-1R-x4 stream-state write-back is non-deterministic)",
        );
    }

    /// T3'b interleaved-seed determinism property: one `VmState`
    /// run through `init_scratchpad(A)` / `init_scratchpad(B)` /
    /// `init_scratchpad(A)` produces byte-identical scratchpads on
    /// both `A` invocations. Catches cross-call state pollution
    /// (e.g., AES round-key state retention between invocations,
    /// allocator-scratch buffer not reset, etc.).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T3'b sub-test 2/2.
    #[test]
    fn t3_prime_init_scratchpad_determinism_interleaved() {
        let mut vm = VmState::new();

        let mut seed_a1 = SEED_A;
        vm.init_scratchpad(&mut seed_a1);
        let scratchpad_a1: Box<[u8; RANDOMX_SCRATCHPAD_L3]> = vm.scratchpad.clone();

        let mut seed_b = SEED_B;
        vm.init_scratchpad(&mut seed_b);

        let mut seed_a2 = SEED_A;
        vm.init_scratchpad(&mut seed_a2);

        assert!(
            scratchpads_equal(&vm.scratchpad, &scratchpad_a1),
            "init_scratchpad(SEED_A) scratchpad drifted after init_scratchpad(SEED_B)",
        );
        assert_eq!(
            seed_a1, seed_a2,
            "init_scratchpad(SEED_A) seed-advance drifted after init_scratchpad(SEED_B)",
        );
    }

    /// T4'a register-init determinism property: two `VmState`s each
    /// fed the same seed to `init_program` produce byte-identical
    /// register-init field subsets (`a`, `ma`, `mx`, `read_reg`,
    /// `dataset_offset`, `e_mask`). Catches non-determinism in the
    /// entropy-parse path (`get_small_positive_float_bits`,
    /// `get_float_mask`) or in the `[u64; 16]` little-endian decode.
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T4'a.
    #[test]
    fn t4_prime_init_program_register_determinism_same_seed_twice() {
        let mut vm1 = VmState::new();
        let mut vm2 = VmState::new();

        vm1.init_program(&SEED_A);
        vm2.init_program(&SEED_A);

        assert_eq!(
            vm1.a.map(|pair| [pair[0].to_bits(), pair[1].to_bits()]),
            vm2.a.map(|pair| [pair[0].to_bits(), pair[1].to_bits()]),
            "init_program(SAME_SEED) register `a` divergent",
        );
        assert_eq!(
            vm1.ma, vm2.ma,
            "init_program(SAME_SEED) memory register `ma` divergent",
        );
        assert_eq!(
            vm1.mx, vm2.mx,
            "init_program(SAME_SEED) memory register `mx` divergent",
        );
        assert_eq!(
            vm1.read_reg, vm2.read_reg,
            "init_program(SAME_SEED) `read_reg` divergent",
        );
        assert_eq!(
            vm1.dataset_offset, vm2.dataset_offset,
            "init_program(SAME_SEED) `dataset_offset` divergent",
        );
        assert_eq!(
            vm1.e_mask, vm2.e_mask,
            "init_program(SAME_SEED) `e_mask` divergent",
        );
    }

    /// T5'a parsed-instructions determinism property: two `VmState`s
    /// each fed the same seed to `init_program` produce
    /// byte-identical `program.instructions` across all
    /// [`PROGRAM_SIZE`] (384) entries, compared field-wise via
    /// [`instructions_equal`]. Catches non-determinism in
    /// `fill_aes_4r_x4` output or in the per-instruction 8-byte
    /// decode (`opcode` / `dst` / `src` / `mod_` bytes +
    /// little-endian `imm32`).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T5'a.
    #[test]
    fn t5_prime_init_program_instructions_determinism_same_seed_twice() {
        let mut vm1 = VmState::new();
        let mut vm2 = VmState::new();

        vm1.init_program(&SEED_A);
        vm2.init_program(&SEED_A);

        for i in 0..PROGRAM_SIZE {
            assert!(
                instructions_equal(&vm1.program.instructions[i], &vm2.program.instructions[i]),
                "init_program(SAME_SEED) program.instructions[{i}] divergent: \
                 vm1 = (opcode={}, dst={}, src={}, mod_={}, imm32={:#010x}), \
                 vm2 = (opcode={}, dst={}, src={}, mod_={}, imm32={:#010x})",
                vm1.program.instructions[i].opcode,
                vm1.program.instructions[i].dst,
                vm1.program.instructions[i].src,
                vm1.program.instructions[i].mod_,
                vm1.program.instructions[i].imm32,
                vm2.program.instructions[i].opcode,
                vm2.program.instructions[i].dst,
                vm2.program.instructions[i].src,
                vm2.program.instructions[i].mod_,
                vm2.program.instructions[i].imm32,
            );
        }
    }

    /// Helpers' bit-pattern smoke check: `get_small_positive_float_bits`
    /// always produces a positive-finite IEEE-754 binary64 (per the
    /// spec §4.5's "small positive float" guarantee). Constructs the
    /// bit pattern from a known-input entropy and verifies the sign
    /// bit is zero and the exponent field falls in the spec-pinned
    /// range `[exponentBias, exponentBias + 31]`.
    ///
    /// Pins the helper's invariant: divergence from the C reference's
    /// `getSmallPositiveFloatBits` would silently produce non-finite
    /// `a`-register values in 2d's FP dispatch, with no test in 2c
    /// observing the drift under stub-NOP dispatch. T4' / T5' check
    /// determinism; this check pins the *value-range* contract.
    #[test]
    fn get_small_positive_float_bits_produces_positive_finite() {
        for entropy in [0u64, 1, u64::MAX, 0x1234_5678_9ABC_DEF0] {
            let bits = get_small_positive_float_bits(entropy);
            let f = f64::from_bits(bits);
            assert!(
                f.is_finite() && f.is_sign_positive(),
                "get_small_positive_float_bits({entropy:#x}) = {bits:#x} \
                 yielded f64 {f} (not positive-finite)",
            );
            let exponent_field = (bits >> MANTISSA_SIZE) & EXPONENT_MASK;
            assert!(
                (EXPONENT_BIAS..=EXPONENT_BIAS + 31).contains(&exponent_field),
                "get_small_positive_float_bits({entropy:#x}) exponent field {exponent_field} \
                 out of spec-pinned [exponentBias, exponentBias + 31] = [{}, {}]",
                EXPONENT_BIAS,
                EXPONENT_BIAS + 31,
            );
        }
    }

    // -------------------------------------------------------------------
    // T6'/T7'/T8' determinism property tests (per
    // `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.1).
    //
    // [`Cache::derive`] is the dominant cost in these tests (single-thread
    // ~5s on a 2026-era reference machine per commit 2's measurement).
    // The tests share one [`Cache`] instance across all T6'/T7'/T8' calls
    // via a [`std::sync::OnceLock`]; the per-test cost drops to one
    // `execute_program` (light-mode dataset reads dominate at ~5ms per
    // iteration ✕ 2048 ✕ 8 chains = many seconds per `compute_hash`).
    // The plan-doc §8 budget marks this performance as expected for
    // Phase 2c (Phase 2g closes the verifier-perf gap).
    //
    // The shared cache is derived from a fixed test seedhash. The
    // tests are not concerned with consensus-equivalence of the
    // dataset items (Phase 2d spec-vector tests cover that); they
    // are concerned only with determinism (same inputs → same
    // outputs) of the structural execute_program / compute_hash
    // path.
    // -------------------------------------------------------------------

    use std::sync::OnceLock;

    use crate::{PreparedCache, Seedhash};

    /// Test-only fixed seedhash bytes used to derive the shared
    /// [`crate::PreparedCache`] for T6'/T7'/T8'. The value is
    /// arbitrary; what matters is that the same seedhash is
    /// reused across every call so the `OnceLock` initialization
    /// runs exactly once for the whole test run. Wrapped in
    /// [`Seedhash`] inside [`shared_prepared_cache`] per the Phase
    /// 2F §1.1 Round 2 type sweep.
    const TEST_SEEDHASH_BYTES: [u8; 32] = [0x42; 32];

    /// Shared [`PreparedCache`] for T6'/T7'/T8'. The first test
    /// to call [`shared_prepared_cache`] pays the ~5 s
    /// [`crate::PreparedCache::derive`] cost (dominated by the
    /// 256-MiB Argon2d fill); every subsequent caller (across
    /// every test in this module) reuses the same instance. Per
    /// the [`std::sync::OnceLock`] contract, concurrent first-
    /// callers race once and exactly one initialization runs.
    fn shared_prepared_cache() -> &'static PreparedCache {
        static PREPARED: OnceLock<PreparedCache> = OnceLock::new();
        PREPARED.get_or_init(|| PreparedCache::derive(Seedhash::from_bytes(TEST_SEEDHASH_BYTES)))
    }

    /// Test-only fixed program-init seed used by T6'/T7' to populate
    /// `VmState` with reproducible register, ma, mx, read_reg,
    /// dataset_offset, e_mask, and parsed `program.instructions`
    /// state before each `execute_program` call.
    const TEST_PROGRAM_SEED: [u8; 64] = [0xA5; 64];

    /// T6' scratchpad-mix determinism: two [`VmState`]s, each
    /// initialized identically (same `init_scratchpad` + `init_program`
    /// seed, same shared [`crate::Cache`]) and executed via
    /// [`VmState::execute_program`], produce byte-identical
    /// `scratchpad` bytes after execution. Catches non-determinism
    /// in the per-iteration scratchpad-load → dispatch → scratchpad-
    /// store data flow, including non-deterministic sp_addr
    /// derivation, non-deterministic register-load XOR ordering,
    /// non-deterministic dataset-read indexing, or non-deterministic
    /// scratchpad-write ordering.
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T6'.
    #[test]
    fn t6_prime_execute_program_scratchpad_determinism() {
        let cache = shared_prepared_cache().cache_ref();

        let mut vm1 = VmState::new();
        let mut vm2 = VmState::new();

        let mut seed1 = [0x37u8; 64];
        let mut seed2 = [0x37u8; 64];
        vm1.init_scratchpad(&mut seed1);
        vm2.init_scratchpad(&mut seed2);

        vm1.init_program(&TEST_PROGRAM_SEED);
        vm2.init_program(&TEST_PROGRAM_SEED);

        crate::fpu_rounding::set_rounding_mode(0);
        vm1.execute_program(cache);
        crate::fpu_rounding::set_rounding_mode(0);
        vm2.execute_program(cache);

        assert!(
            scratchpads_equal(&vm1.scratchpad, &vm2.scratchpad),
            "execute_program(SAME_INPUTS) produced divergent scratchpad bytes",
        );
    }

    /// T7' F/E AES mix + integer-register determinism: two
    /// [`VmState`]s, each initialized identically and executed via
    /// [`VmState::execute_program`], produce byte-identical `r`, `f`,
    /// `e`, `a`, `ma`, `mx` state after execution. Catches non-
    /// determinism in the F/E AES mix's per-round e-key application
    /// or in the integer-register XOR chain (`r[i] ^=
    /// scratchpad[off..off+8]` and the dataset-item XOR fold).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T7'.
    #[test]
    fn t7_prime_execute_program_register_determinism() {
        let cache = shared_prepared_cache().cache_ref();

        let mut vm1 = VmState::new();
        let mut vm2 = VmState::new();

        let mut seed1 = [0x37u8; 64];
        let mut seed2 = [0x37u8; 64];
        vm1.init_scratchpad(&mut seed1);
        vm2.init_scratchpad(&mut seed2);

        vm1.init_program(&TEST_PROGRAM_SEED);
        vm2.init_program(&TEST_PROGRAM_SEED);

        crate::fpu_rounding::set_rounding_mode(0);
        vm1.execute_program(cache);
        crate::fpu_rounding::set_rounding_mode(0);
        vm2.execute_program(cache);

        assert_eq!(vm1.r, vm2.r, "execute_program(SAME_INPUTS) `r` divergent");
        assert_eq!(
            vm1.f.map(|p| [p[0].to_bits(), p[1].to_bits()]),
            vm2.f.map(|p| [p[0].to_bits(), p[1].to_bits()]),
            "execute_program(SAME_INPUTS) `f` divergent",
        );
        assert_eq!(
            vm1.e.map(|p| [p[0].to_bits(), p[1].to_bits()]),
            vm2.e.map(|p| [p[0].to_bits(), p[1].to_bits()]),
            "execute_program(SAME_INPUTS) `e` divergent",
        );
        assert_eq!(
            vm1.a.map(|p| [p[0].to_bits(), p[1].to_bits()]),
            vm2.a.map(|p| [p[0].to_bits(), p[1].to_bits()]),
            "execute_program(SAME_INPUTS) `a` divergent",
        );
        assert_eq!(
            vm1.ma, vm2.ma,
            "execute_program(SAME_INPUTS) `ma` divergent"
        );
        assert_eq!(
            vm1.mx, vm2.mx,
            "execute_program(SAME_INPUTS) `mx` divergent"
        );
    }

    /// T8'a end-to-end [`compute_hash`] determinism: two
    /// `compute_hash(prepared, data)` calls with identical
    /// inputs produce byte-identical 32-byte outputs. Catches any
    /// non-determinism in the full hash composition (Blake2b chain,
    /// scratchpad init, program init, 8-chain execute loop, finalize
    /// AES-hash + Blake2b).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T8' "single-thread determinism".
    #[test]
    fn t8_prime_compute_hash_determinism_same_inputs_twice() {
        let prepared = shared_prepared_cache();

        let data = b"shekyl-randomx-v2-phase-2c-commit-6-determinism-test";

        let hash1 = compute_hash(prepared, data);
        let hash2 = compute_hash(prepared, data);

        assert_eq!(
            hash1, hash2,
            "compute_hash(SAME_INPUTS) divergent: {hash1:02x?} vs {hash2:02x?}",
        );
    }

    /// T8'b [`compute_hash`] distinguishes inputs that differ in a
    /// single bit. Pins the trivial-collision-resistance contract:
    /// the Phase 2c stub-NOP dispatch must still propagate input
    /// differences through the scratchpad + AES mix + Blake2b chain
    /// to a different final hash, even though the per-instruction
    /// arithmetic is a no-op. Catches a hypothetical degenerate
    /// case where the stub-NOP collapses input variation
    /// (e.g., if `data` were not fed to the Blake2b seed).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T8' "single-bit flip distinguishability".
    #[test]
    fn t8_prime_compute_hash_distinguishes_single_bit_flip() {
        let prepared = shared_prepared_cache();

        let data_a: &[u8] = b"phase-2c-t8b-bitflip-A";
        let data_b: &[u8] = b"phase-2c-t8b-bitflip-B";

        let hash_a = compute_hash(prepared, data_a);
        let hash_b = compute_hash(prepared, data_b);

        assert_ne!(
            hash_a, hash_b,
            "compute_hash(DIFFERENT_DATA) collided: {hash_a:02x?} vs {hash_b:02x?}",
        );
    }

    /// T8'c [`compute_hash`] concurrent determinism: two threads
    /// each computing `compute_hash(prepared, data)` against the
    /// same shared [`crate::PreparedCache`] produce identical
    /// outputs. Catches a hypothetical thread-unsafe data path in
    /// `compute_hash` or `VmState::execute_program` (e.g.,
    /// accidentally-shared mutable state, allocator-dependent
    /// behavior). Per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1 T8' "concurrent determinism" — the same
    /// `PreparedCache` shared between threads is the Phase 3a FFI
    /// deployment
    /// shape, so this property must hold by construction.
    #[test]
    fn t8_prime_compute_hash_concurrent_determinism() {
        let prepared = shared_prepared_cache();

        let data = b"phase-2c-t8c-concurrent-determinism-test-input-bytes";

        let h1 = std::thread::scope(|s| {
            let t = s.spawn(|| compute_hash(prepared, data));
            t.join().expect("compute_hash thread panicked")
        });
        let h2 = std::thread::scope(|s| {
            let t = s.spawn(|| compute_hash(prepared, data));
            t.join().expect("compute_hash thread panicked")
        });
        let h_main = compute_hash(prepared, data);

        assert_eq!(
            h1, h2,
            "compute_hash concurrent: thread1 != thread2 ({h1:02x?} vs {h2:02x?})",
        );
        assert_eq!(
            h1, h_main,
            "compute_hash concurrent: thread1 != main ({h1:02x?} vs {h_main:02x?})",
        );
    }

    /// Helper smoke-check: `cvt_packed_int_to_f128` recovers the
    /// signed 32-bit lanes from a packed 8-byte input as IEEE-754
    /// binary64 floats. Mirrors SSE2 `_mm_cvtepi32_pd` per spec §5.2.
    /// Pins the cast direction (signed, not unsigned) for the
    /// integer → float conversion that the `f`/`e` register loads
    /// depend on per `vm_interpreted.cpp:79-81`.
    #[test]
    fn cvt_packed_int_to_f128_recovers_signed_i32_lanes() {
        let bytes: [u8; 8] = {
            let mut b = [0u8; 8];
            b[0..4].copy_from_slice(&(-1i32).to_le_bytes());
            b[4..8].copy_from_slice(&(42i32).to_le_bytes());
            b
        };
        let f = cvt_packed_int_to_f128(&bytes);
        assert_eq!(
            f[0].to_bits(),
            (-1.0f64).to_bits(),
            "lo lane: signed -1 should round-trip",
        );
        assert_eq!(
            f[1].to_bits(),
            42.0f64.to_bits(),
            "hi lane: signed 42 should round-trip",
        );
    }

    /// Helper smoke-check: `mask_register_exponent_mantissa` clears
    /// the high (sign + exponent) bits of each lane and OR-overlays
    /// the e_mask exponent. Pins the masking semantics
    /// `bytecode_machine.hpp:272-278` requires for FDIV_M's
    /// positive-finite operand contract.
    #[test]
    fn mask_register_exponent_mantissa_preserves_mantissa_and_overlays_emask() {
        const X_LO: u64 = 0xDEAD_BEEF_CAFE_BABE;
        const X_HI: u64 = 0x0123_4567_89AB_CDEF;
        let x = F128([f64::from_bits(X_LO), f64::from_bits(X_HI)]);
        let e_mask: [u64; 2] = [
            0x3FF0_0000_0000_0000, // exponent bias only
            0x4000_0000_0000_0000,
        ];
        let out = mask_register_exponent_mantissa(x, e_mask);
        let expected_lo = (X_LO & DYNAMIC_MANTISSA_MASK) | e_mask[0];
        let expected_hi = (X_HI & DYNAMIC_MANTISSA_MASK) | e_mask[1];
        assert_eq!(
            out[0].to_bits(),
            expected_lo,
            "mask_register_exponent_mantissa lo lane mis-masked",
        );
        assert_eq!(
            out[1].to_bits(),
            expected_hi,
            "mask_register_exponent_mantissa hi lane mis-masked",
        );
    }

    /// Helper round-trip: `f128_to_aes_bytes` and `aes_bytes_to_f128`
    /// are byte-exact inverses. Pins the F/E AES mix's cast surface:
    /// any drift between the two helpers' byte serialization would
    /// silently corrupt the AES mix output.
    #[test]
    fn f128_aes_bytes_round_trip() {
        let originals: [F128; 4] = [
            F128([0.0, -0.0]),
            F128([1.0, f64::from_bits(0xCAFE_BABE_DEAD_BEEF)]),
            F128([f64::INFINITY, f64::NEG_INFINITY]),
            F128([f64::from_bits(0x1234_5678_9ABC_DEF0), f64::EPSILON]),
        ];
        for &f in &originals {
            let bytes = f128_to_aes_bytes(f);
            let back = aes_bytes_to_f128(&bytes);
            assert_eq!(
                back[0].to_bits(),
                f[0].to_bits(),
                "F128 round-trip lo lane drifted: {:#x} -> {:#x}",
                f[0].to_bits(),
                back[0].to_bits(),
            );
            assert_eq!(
                back[1].to_bits(),
                f[1].to_bits(),
                "F128 round-trip hi lane drifted: {:#x} -> {:#x}",
                f[1].to_bits(),
                back[1].to_bits(),
            );
        }
    }

    #[test]
    fn integer_helpers_match_portable_semantics() {
        assert_eq!(sign_extend_i32_to_i64(0x8000_0000), 0xffff_ffff_8000_0000);
        assert_eq!(sign_extend_i32_to_i64(0x7fff_ffff), 0x0000_0000_7fff_ffff);

        let mut buf = [0u8; 8];
        store64(&mut buf, 0x0123_4567_89AB_CDEF);
        assert_eq!(load64(&buf), 0x0123_4567_89AB_CDEF);

        let x = 0x1234_5678_9ABC_DEF0u64;
        assert_eq!(rotr(x, 0), x);
        assert_eq!(rotl(x, 0), x);
        assert_eq!(rotr(x, 4), x.rotate_right(4));
        assert_eq!(rotl(x, 4), x.rotate_left(4));
        assert_eq!(rotr(x, 64), x);
        assert_eq!(rotl(x, 64), x);
    }

    #[test]
    fn cfround_helper_updates_fprc_only_when_unthrottled() {
        let mut state = VmState::new();
        let instr = Instruction {
            opcode: 0,
            dst: 0,
            src: 1,
            mod_: 0,
            imm32: 0,
        };

        state.r[1] = 2;
        state.fprc = 0;
        execute_cfround(&instr, &mut state);
        assert_eq!(state.fprc, 2, "CFROUND should publish isrc % 4");

        state.r[1] = 4;
        state.fprc = 2;
        execute_cfround(&instr, &mut state);
        assert_eq!(
            state.fprc, 2,
            "CFROUND should not update fprc when isrc & 60 is nonzero",
        );

        crate::fpu_rounding::set_rounding_mode(0);
    }

    // -----------------------------------------------------------------
    // T3-T8 spec-vector tests (Phase 2c §5.7 / F7 T3..T8; §9 commit 7).
    //
    // All six vectors were generated by
    // `tests/vectors/reference/_generator/phase2c/gen.cpp` against the
    // v2 RandomX fork at pin
    // `aaafe71322df6602c21a5c72937ac284724ae561` (v2.0.1). The
    // committed `.bin` bytes are bootstrap vectors until Phase 2g
    // lands the live differential harness; see the sibling
    // `.meta.txt` files for per-vector provenance and the Phase 2c
    // generator README for the cross-vector substrate provenance.
    //
    // Inputs shared across T3-T7: `CANONICAL_TEMP_HASH` is the
    // 64-byte Blake2b-512 of the ASCII preimage
    // `"shekyl-randomx-v2-phase2c-canonical-input"` — re-derived
    // here as a pinned constant rather than re-computed at test time
    // so a reviewer can cross-check the bytes against the one-line
    // Python equivalent (`python3 -c "import hashlib; \
    // print(hashlib.blake2b(b'shekyl-randomx-v2-phase2c-canonical-\
    // input', digest_size=64).hexdigest())"`) without running the
    // test suite.
    //
    // Inputs shared across T1/T2/T8: `CANONICAL_SEEDHASH` is the
    // 32-byte sequential 0x01..=0x20. Defined locally in this
    // tests module (duplicated from `cache.rs#mod tests` rather
    // than promoted to a shared test-helper crate — the duplication
    // is two lines per side, and a shared test helper would expand
    // the crate's `[dev-dependencies]` surface for one literal).
    // -----------------------------------------------------------------

    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    /// 32-byte canonical T1/T2/T8 seedhash bytes; mirrors
    /// `cache.rs#mod tests::CANONICAL_SEEDHASH_BYTES` and
    /// `CANONICAL_SEEDHASH` in
    /// `tests/vectors/reference/_generator/phase2c/gen.cpp`.
    /// Wrapped in [`Seedhash`] inside [`canonical_prepared_cache`]
    /// per the Phase 2F §1.1 Round 2 type sweep.
    const CANONICAL_SEEDHASH_BYTES: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    /// 64-byte canonical temp_hash for T3/T4/T5/T6/T7 — equals
    /// `Blake2b-512(b"shekyl-randomx-v2-phase2c-canonical-input")`.
    /// Mirrors `g_canonical_temp_hash` (derived at startup from
    /// `CANONICAL_TEMP_HASH_PREIMAGE`) in
    /// `tests/vectors/reference/_generator/phase2c/gen.cpp`.
    const CANONICAL_TEMP_HASH: [u8; 64] = [
        0xb8, 0x4e, 0xb7, 0x92, 0xf6, 0xcf, 0x73, 0xe0, 0x3a, 0x89, 0x32, 0x0d, 0x42, 0xd6, 0xa4,
        0x50, 0x92, 0xa7, 0x3b, 0x2f, 0xa9, 0xbf, 0x51, 0x9e, 0xad, 0xad, 0x44, 0xe5, 0xe6, 0x27,
        0x92, 0x48, 0x01, 0xc8, 0xce, 0x2e, 0x2f, 0xb2, 0xb1, 0x29, 0x66, 0xff, 0xa0, 0x83, 0xd1,
        0x62, 0x72, 0xbe, 0xa3, 0x45, 0xce, 0x3d, 0xad, 0x43, 0x48, 0x4c, 0x5f, 0xe7, 0x52, 0xde,
        0x77, 0x78, 0xde, 0x78,
    ];

    /// Cross-check: re-derive `CANONICAL_TEMP_HASH` at test time
    /// from its documented preimage and assert byte-equality.
    /// Catches a stale pinned constant if a future contributor
    /// edits one without the other.
    #[test]
    fn canonical_temp_hash_matches_preimage_derivation() {
        let mut hasher = Blake2bVar::new(64).expect("Blake2bVar(64) accepts 64-byte output");
        hasher.update(b"shekyl-randomx-v2-phase2c-canonical-input");
        let mut derived = [0u8; 64];
        hasher
            .finalize_variable(&mut derived)
            .expect("Blake2bVar finalize succeeds for 64-byte buffer");
        assert_eq!(
            derived, CANONICAL_TEMP_HASH,
            "CANONICAL_TEMP_HASH constant diverged from its documented preimage",
        );
    }

    /// Serialize a [`VmState`]'s register file in the 256-byte
    /// canonical layout the C generator emits via
    /// `emit_register_file_snapshot`:
    ///
    /// - `+0`   `r[0..8]`  × u64 LE        (64 B)
    /// - `+64`  `f[0..4]`  × `[lo f64 LE bits, hi f64 LE bits]` (64 B)
    /// - `+128` `e[0..4]`  × `[lo f64 LE bits, hi f64 LE bits]` (64 B)
    /// - `+192` `a[0..4]`  × `[lo f64 LE bits, hi f64 LE bits]` (64 B)
    ///
    /// Total: 256 bytes. Matches the C `RegisterFile` struct's byte
    /// layout (per `common.hpp:190-195`) and the order
    /// [`feed_register_file_to_hasher`] uses to feed the
    /// `compute_hash` chain Blake2b.
    fn register_file_snapshot(state: &VmState) -> [u8; 256] {
        let mut out = [0u8; 256];
        for (i, &v) in state.r.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        for (i, pair) in state.f.iter().enumerate() {
            let off = 64 + i * 16;
            out[off..off + 8].copy_from_slice(&pair[0].to_bits().to_le_bytes());
            out[off + 8..off + 16].copy_from_slice(&pair[1].to_bits().to_le_bytes());
        }
        for (i, pair) in state.e.iter().enumerate() {
            let off = 128 + i * 16;
            out[off..off + 8].copy_from_slice(&pair[0].to_bits().to_le_bytes());
            out[off + 8..off + 16].copy_from_slice(&pair[1].to_bits().to_le_bytes());
        }
        for (i, pair) in state.a.iter().enumerate() {
            let off = 192 + i * 16;
            out[off..off + 8].copy_from_slice(&pair[0].to_bits().to_le_bytes());
            out[off + 8..off + 16].copy_from_slice(&pair[1].to_bits().to_le_bytes());
        }
        out
    }

    /// T3 spec-vector: `VmState::init_scratchpad(&mut CANONICAL_TEMP_HASH)`
    /// produces a 2 MiB scratchpad whose Blake2b-256 matches the v2
    /// RandomX fork's `fillAes1Rx4<softAes>` output byte-for-byte at
    /// pin `aaafe71`.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/vm/t3_vm_scratchpad_init.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T3, §9 commit 7.
    #[test]
    fn t3_vm_scratchpad_init_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t3_vm_scratchpad_init.bin");
        assert_eq!(expected.len(), 32, "t3 .bin size invariant");

        let mut state = VmState::new();
        let mut seed = CANONICAL_TEMP_HASH;
        state.init_scratchpad(&mut seed);

        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) accepts 32-byte output");
        hasher.update(&state.scratchpad[..]);
        let mut actual = [0u8; 32];
        hasher
            .finalize_variable(&mut actual)
            .expect("Blake2bVar finalize succeeds for 32-byte buffer");

        assert_eq!(
            actual,
            <[u8; 32]>::try_from(expected).expect("32-byte vector"),
            "VmState::init_scratchpad scratchpad fingerprint diverged from fork pin aaafe71 reference",
        );
    }

    /// T4 spec-vector: post-`init_program` [`VmState`] register file
    /// snapshot matches the v2 RandomX fork's post-`initialize()`
    /// `NativeRegisterFile` byte-for-byte at pin `aaafe71`.
    ///
    /// Captures the pre-iteration state: `r[8]` / `f[4]` / `e[4]`
    /// are zero (set per-iteration inside `execute_iteration`),
    /// `a[4]` is populated from `getSmallPositiveFloatBits(entropy[0..8])`.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/vm/t4_vm_register_init.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T4, §9 commit 7.
    #[test]
    fn t4_vm_register_init_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t4_vm_register_init.bin");
        assert_eq!(expected.len(), 256, "t4 .bin size invariant");

        let mut state = VmState::new();
        state.init_program(&CANONICAL_TEMP_HASH);

        let actual = register_file_snapshot(&state);

        assert_eq!(
            actual.as_slice(),
            expected,
            "VmState::init_program register-file snapshot diverged from fork pin aaafe71 reference",
        );
    }

    /// T5 spec-vector: post-`init_program` [`VmState::program`]
    /// instruction stream matches the v2 RandomX fork's parsed
    /// [`randomx::Program`] byte-for-byte at pin `aaafe71`, serialized
    /// in the canonical 8-bytes-per-instruction wire format
    /// `(opcode u8, dst u8, src u8, mod u8, imm32 u32 LE)`.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/vm/t5_vm_program_parse.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T5, §9 commit 7.
    #[test]
    fn t5_vm_program_parse_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t5_vm_program_parse.bin");
        assert_eq!(
            expected.len(),
            PROGRAM_SIZE * INSTRUCTION_SIZE,
            "t5 .bin size invariant ({PROGRAM_SIZE} instructions × {INSTRUCTION_SIZE} bytes)",
        );

        let mut state = VmState::new();
        state.init_program(&CANONICAL_TEMP_HASH);

        let mut actual = vec![0u8; PROGRAM_SIZE * INSTRUCTION_SIZE];
        for (i, instr) in state.program.instructions.iter().enumerate() {
            let off = i * INSTRUCTION_SIZE;
            actual[off] = instr.opcode;
            actual[off + 1] = instr.dst;
            actual[off + 2] = instr.src;
            actual[off + 3] = instr.mod_;
            actual[off + 4..off + 8].copy_from_slice(&instr.imm32.to_le_bytes());
        }

        assert_eq!(
            actual.as_slice(),
            expected,
            "VmState::init_program instruction stream diverged from fork pin aaafe71 reference",
        );
    }

    /// [`PreparedCache`] derived under the canonical T6/T7/T8
    /// seedhash (0x01..=0x20). Distinct from the T6'/T7'/T8'
    /// shared `PreparedCache` (0x42..) — those property tests
    /// pay one cache derivation; the spec-vector tests pay a
    /// second, since the canonical inputs differ. Cached via
    /// `OnceLock` so the 8 spec-vector tests that touch the
    /// cache (T6, T7, T8 + helper sub-tests if added) amortize
    /// the ~5 s derivation cost.
    ///
    /// [`PreparedCache`]: crate::PreparedCache
    fn canonical_prepared_cache() -> &'static crate::PreparedCache {
        use std::sync::OnceLock;
        static PREPARED: OnceLock<crate::PreparedCache> = OnceLock::new();
        PREPARED.get_or_init(|| {
            crate::PreparedCache::derive(Seedhash::from_bytes(CANONICAL_SEEDHASH_BYTES))
        })
    }

    /// T6 spec-vector: post-mask `(sp_addr0, sp_addr1)` pairs across
    /// the first 4 iterations of the stub-NOP loop match the v2
    /// RandomX fork's interpreted iteration loop byte-for-byte at
    /// pin `aaafe71`. The C generator's snapshot fires immediately
    /// after the spAddr derivation and masking step, before the
    /// register-load substrate runs; the Rust port's `execute_iteration`
    /// returns the post-mask pair after performing the iteration's
    /// loads — both shapes capture the same `(sp_addr0, sp_addr1)`
    /// values used to index the scratchpad for that iteration.
    ///
    /// The first iteration uses `(self.mx, self.ma)` (set by
    /// `init_program`) as the initial `(sp_addr0_in, sp_addr1_in)`;
    /// every subsequent iteration uses `(0, 0)` (the spec-pinned
    /// per-iteration reset).
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/vm/t6_vm_spaddr_4iter.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T6, §5.6 stub-NOP
    /// dispatch, §9 commit 7.
    #[test]
    #[ignore = "Phase 2c stub-NOP vector; Phase 2d real-dispatch parity is covered by T16"]
    fn t6_vm_spaddr_4iter_matches_fork_reference() {
        const ITER_COUNT: usize = 4;
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t6_vm_spaddr_4iter.bin");
        assert_eq!(
            expected.len(),
            ITER_COUNT * 8,
            "t6 .bin size invariant ({ITER_COUNT} iterations × 8 bytes)",
        );

        let cache = canonical_prepared_cache().cache_ref();
        let mut state = VmState::new();
        state.init_program(&CANONICAL_TEMP_HASH);

        let mut actual = [0u8; ITER_COUNT * 8];
        let mut sp_addr0_in: u32 = state.mx;
        let mut sp_addr1_in: u32 = state.ma;
        for ic in 0..ITER_COUNT {
            let (sp_addr0, sp_addr1) = state.execute_iteration(cache, sp_addr0_in, sp_addr1_in);
            actual[ic * 8..ic * 8 + 4].copy_from_slice(&sp_addr0.to_le_bytes());
            actual[ic * 8 + 4..ic * 8 + 8].copy_from_slice(&sp_addr1.to_le_bytes());
            sp_addr0_in = 0;
            sp_addr1_in = 0;
        }

        assert_eq!(
            actual.as_slice(),
            expected,
            "execute_iteration sp_addr pairs diverged from fork pin aaafe71 reference \
             (each 8-byte chunk = spAddr0 LE u32 + spAddr1 LE u32; iteration 0..{ITER_COUNT} in order)",
        );
    }

    /// T7 spec-vector: post-AES-mix register-file snapshot across
    /// the first 4 iterations of the stub-NOP loop matches the v2
    /// RandomX fork's iteration loop byte-for-byte at pin `aaafe71`.
    /// Each 256-byte snapshot uses the same layout as T4: `r[8]
    /// u64 LE` then `f[4]` / `e[4]` / `a[4]` pairs of f64 LE bits.
    ///
    /// The C generator captures `nreg` at the END of the iteration's
    /// loop body (after the FP register → scratchpad store); the
    /// Rust port's `execute_iteration` mutates `state.{r,f,e}`
    /// in place and returns at the same point — so `register_file_snapshot(&state)`
    /// after each iteration captures the same byte image.
    ///
    /// The `a[4]` portion of every snapshot is identical to T4's
    /// post-`init_program` `a[4]` (the iteration body never writes
    /// to `state.a`); the test does not special-case this — the
    /// byte-equality assertion covers it.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/vm/t7_vm_aesmix_4iter.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T7, §5.6 stub-NOP
    /// dispatch, §9 commit 7.
    #[test]
    #[ignore = "Phase 2c stub-NOP vector; Phase 2d real-dispatch parity is covered by T16"]
    fn t7_vm_aesmix_4iter_matches_fork_reference() {
        const ITER_COUNT: usize = 4;
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t7_vm_aesmix_4iter.bin");
        assert_eq!(
            expected.len(),
            ITER_COUNT * 256,
            "t7 .bin size invariant ({ITER_COUNT} iterations × 256 bytes)",
        );

        let cache = canonical_prepared_cache().cache_ref();
        let mut state = VmState::new();
        state.init_program(&CANONICAL_TEMP_HASH);

        let mut actual = vec![0u8; ITER_COUNT * 256];
        let mut sp_addr0_in: u32 = state.mx;
        let mut sp_addr1_in: u32 = state.ma;
        for ic in 0..ITER_COUNT {
            let _ = state.execute_iteration(cache, sp_addr0_in, sp_addr1_in);
            let snap = register_file_snapshot(&state);
            actual[ic * 256..(ic + 1) * 256].copy_from_slice(&snap);
            sp_addr0_in = 0;
            sp_addr1_in = 0;
        }

        assert_eq!(
            actual.as_slice(),
            expected,
            "execute_iteration register-file snapshots diverged from fork pin aaafe71 reference \
             (each 256-byte chunk = r[8]/f[4]/e[4]/a[4] in T4 layout; iteration 0..{ITER_COUNT} in order)",
        );
    }

    /// 192-byte ASCII canonical T8 data input — mirrors `T8_DATA_INPUT`
    /// in `tests/vectors/reference/_generator/phase2c/gen.cpp`. The
    /// literal's "padding-to-256" / "spans-multiple-blocks" phrasing
    /// is content, not a size promise — the actual length is 192 B,
    /// which still spans multiple 64-B AES-1R-x4 scratchpad seed
    /// blocks.
    const T8_DATA_INPUT: &[u8] = b"phase2c-t8-end-to-end-stub-nop-hash-canonical-data-input-padding-to-256-bytes-so-the-blake2b-input-spans-multiple-blocks-and-the-fillaes1rx4-scratchpad-init-consumes-a-non-trivial-seed.....END";

    /// Cross-check: `T8_DATA_INPUT` is exactly 192 bytes. The literal
    /// is split across multiple `&str` segments in `gen.cpp`; this
    /// assertion locks the concatenated total against accidental
    /// edits on either side.
    #[test]
    fn t8_data_input_is_192_bytes() {
        assert_eq!(
            T8_DATA_INPUT.len(),
            192,
            "T8_DATA_INPUT length diverged from the 192-byte invariant \
             documented in tests/vectors/reference/vm/t8_vm_compute_hash_nop.meta.txt",
        );
    }

    /// T16 spec-vector: end-to-end `compute_hash` output under real
    /// bytecode dispatch matches the v2 RandomX fork's `randomx_calculate_hash`
    /// byte-for-byte at pin `aaafe71`, given the canonical seedhash
    /// and 192-byte data input (see `t8_data_input_is_192_bytes` above
    /// and `tests/vectors/reference/vm/t16_vm_compute_hash_real.meta.txt`).
    ///
    /// This is the single end-to-end attestation: if T3-T7 pass and
    /// If T16 fails, the divergence is in the `compute_hash` orchestration
    /// (program-chaining, RegisterFile re-seeding Blake2b,
    /// `getFinalResult` AES + Blake2b finalize), not in any individual
    /// stage T3-T7 covers.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/vm/t16_vm_compute_hash_real.meta.txt`.
    /// Per RANDOMX_V2_PHASE2D_PLAN.md §6.2 T16 and §8 commit 5b.
    #[test]
    fn t16_vm_compute_hash_real_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t16_vm_compute_hash_real.bin");
        assert_eq!(expected.len(), 32, "t16 .bin size invariant");

        let prepared = canonical_prepared_cache();
        let actual = compute_hash(prepared, T8_DATA_INPUT);

        assert_eq!(
            actual,
            <[u8; 32]>::try_from(expected).expect("32-byte vector"),
            "compute_hash diverged from fork pin aaafe71 reference \
             (prepared = PreparedCache::derive(Seedhash::from_bytes(CANONICAL_SEEDHASH_BYTES)); \
              data = T8_DATA_INPUT)",
        );
    }

    // -----------------------------------------------------------------
    // Phase 2d single-opcode reference vectors (T9-T15).
    //
    // Each probe drives `dispatch_instruction` against a fabricated
    // `Instruction` over a canonical `VmState` register file and
    // scratchpad pattern, and asserts the 256-byte
    // `register_file_snapshot` matches the v2 fork's
    // `executeInstruction` output byte-for-byte. Provenance for each
    // vector is documented inline below and in the sibling
    // `.meta.txt` files under `tests/vectors/reference/vm/`.
    //
    // The canonical fixture matches
    // `tests/vectors/reference/_generator/phase2d/gen.cpp`'s
    // `CANONICAL_*` tables exactly — see the matching constants
    // there for byte-for-byte cross-reference.
    // -----------------------------------------------------------------

    const CANONICAL_R: [u64; 8] = [
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        0x2122_2324_2526_2728,
        0x3132_3334_3536_3738,
        0x4142_4344_4546_4748,
        0x5152_5354_5556_5758,
        0x6162_6364_6566_6768,
        0x7172_7374_7576_7778,
    ];

    const CANONICAL_F_BITS: [[u64; 2]; 4] = [
        [0x3FF0_0000_0000_0000, 0x4000_0000_0000_0000],
        [0xBFF0_0000_0000_0000, 0xC000_0000_0000_0000],
        [0x4008_0000_0000_0000, 0x4010_0000_0000_0000],
        [0xBFE0_0000_0000_0000, 0x3FE8_0000_0000_0000],
    ];

    const CANONICAL_E_BITS: [[u64; 2]; 4] = [
        [0x4030_0000_0000_0000, 0x4034_0000_0000_0000],
        [0x4038_0000_0000_0000, 0x403C_0000_0000_0000],
        [0x4040_0000_0000_0000, 0x4042_0000_0000_0000],
        [0x4044_0000_0000_0000, 0x4046_0000_0000_0000],
    ];

    const CANONICAL_A_BITS: [[u64; 2]; 4] = [
        [0x3FE0_0000_0000_0000, 0x3FE8_0000_0000_0000],
        [0x3FF8_0000_0000_0000, 0x3FFC_0000_0000_0000],
        [0x4002_0000_0000_0000, 0x4006_0000_0000_0000],
        [0x400C_0000_0000_0000, 0x4010_0000_0000_0000],
    ];

    const CANONICAL_E_MASK_PD: [u64; 2] = [0x3FF0_0000_0000_0000, 0x4000_0000_0000_0000];

    /// Materialize a fresh [`VmState`] populated with the Phase 2d
    /// canonical register file + scratchpad fixture. Mirrors
    /// `_generator/phase2d/gen.cpp`'s `init_nreg` / `init_config` /
    /// `init_scratchpad` per-probe. Each probe re-uses this helper so
    /// the harness shape is identical across opcodes.
    fn canonical_phase2d_state() -> VmState {
        let mut state = VmState::new();
        state.r = CANONICAL_R;
        for i in 0..REGISTER_COUNT_FLT {
            state.f[i] = F128([
                f64::from_bits(CANONICAL_F_BITS[i][0]),
                f64::from_bits(CANONICAL_F_BITS[i][1]),
            ]);
            state.e[i] = F128([
                f64::from_bits(CANONICAL_E_BITS[i][0]),
                f64::from_bits(CANONICAL_E_BITS[i][1]),
            ]);
            state.a[i] = F128([
                f64::from_bits(CANONICAL_A_BITS[i][0]),
                f64::from_bits(CANONICAL_A_BITS[i][1]),
            ]);
        }
        state.e_mask = CANONICAL_E_MASK_PD;
        state.read_reg = [0, 1, 2, 3];
        for (i, byte) in state.scratchpad.iter_mut().enumerate() {
            let mixed = i.wrapping_mul(0x9E).wrapping_add(0x37);
            *byte = u8::try_from(mixed & 0xff).expect("masked u8");
        }
        // Pin the FPU rounding mode to RN before each probe so the
        // helper is rounding-mode-clean across tests. Per-probe FP
        // matrix tests overwrite this immediately before dispatch.
        crate::fpu_rounding::set_rounding_mode(0);
        state
    }

    /// Build a fabricated [`Instruction`] for a single Phase 2d probe.
    fn instr(opcode: u8, dst: u8, src: u8, mod_: u8, imm32: u32) -> Instruction {
        Instruction {
            opcode,
            dst,
            src,
            mod_,
            imm32,
        }
    }

    /// Drive `dispatch_instruction` for one probe under MXCSR mode
    /// `fprc` and return the 256-byte post-execution register-file
    /// snapshot. Resets the FPU mode to RN on exit so subsequent
    /// probes start clean.
    fn run_probe(opcode: u8, dst: u8, src: u8, mod_: u8, imm32: u32, fprc: u32) -> [u8; 256] {
        let mut state = canonical_phase2d_state();
        crate::fpu_rounding::set_rounding_mode(fprc);
        let i = instr(opcode, dst, src, mod_, imm32);
        dispatch_instruction(&i, &mut state);
        let snap = register_file_snapshot(&state);
        crate::fpu_rounding::set_rounding_mode(0);
        snap
    }

    /// T9 spec-vector: single-opcode integer dispatch matches the v2
    /// RandomX fork's `executeInstruction` byte-for-byte at pin
    /// `aaafe71` for IADD_RS / IMULH_R / IROR_R / ISTORE.
    ///
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T9.
    #[test]
    fn t9_vm_single_int_smoke_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t9_vm_single_int_smoke.bin");
        assert_eq!(expected.len(), 4 * 256, "t9 .bin size invariant");

        let probes: [(u8, u8, u8, u8, u32); 4] = [
            (0, 2, 3, 0, 0x1234_5678),
            (66, 4, 5, 0, 0),
            (106, 6, 7, 0, 11),
            (240, 0, 1, 0xE0, 0xCAFE_0007),
        ];
        let mut actual = vec![0u8; probes.len() * 256];
        for (i, &(opcode, dst, src, mod_, imm32)) in probes.iter().enumerate() {
            let snap = run_probe(opcode, dst, src, mod_, imm32, 0);
            actual[i * 256..(i + 1) * 256].copy_from_slice(&snap);
        }

        assert_eq!(
            actual.as_slice(),
            expected,
            "T9 integer-smoke dispatch diverged from fork pin aaafe71",
        );
    }

    /// T10 spec-vector: single-opcode FP dispatch under RN matches
    /// the v2 RandomX fork's `executeInstruction` byte-for-byte at
    /// pin `aaafe71` for FADD_R / FMUL_R / FDIV_M / FSQRT_R.
    ///
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T10.
    #[test]
    fn t10_vm_single_fp_smoke_rn_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t10_vm_single_fp_smoke_rn.bin");
        assert_eq!(expected.len(), 4 * 256, "t10 .bin size invariant");

        let probes: [(u8, u8, u8, u8, u32); 4] = [
            (124, 0, 0, 0, 0),
            (172, 1, 2, 0, 0),
            (204, 2, 3, 0, 0x040),
            (208, 3, 0, 0, 0),
        ];
        let mut actual = vec![0u8; probes.len() * 256];
        for (i, &(opcode, dst, src, mod_, imm32)) in probes.iter().enumerate() {
            let snap = run_probe(opcode, dst, src, mod_, imm32, 0);
            actual[i * 256..(i + 1) * 256].copy_from_slice(&snap);
        }

        assert_eq!(
            actual.as_slice(),
            expected,
            "T10 FP-smoke RN dispatch diverged from fork pin aaafe71",
        );
    }

    /// Drive the 9-opcode FP matrix probe under a given MXCSR mode
    /// and return the concatenated 9 × 256 = 2304-byte snapshot.
    fn fp_matrix_actual(fprc: u32) -> Vec<u8> {
        let probes: [(u8, u8, u8, u8, u32); 9] = [
            (120, 1, 0, 0, 0),
            (124, 0, 0, 0, 0),
            (140, 1, 2, 0, 0x040),
            (145, 2, 1, 0, 0),
            (161, 0, 3, 0, 0x080),
            (166, 3, 0, 0, 0),
            (172, 1, 2, 0, 0),
            (204, 2, 3, 0, 0x040),
            (208, 3, 0, 0, 0),
        ];
        let mut out = vec![0u8; probes.len() * 256];
        for (i, &(opcode, dst, src, mod_, imm32)) in probes.iter().enumerate() {
            let snap = run_probe(opcode, dst, src, mod_, imm32, fprc);
            out[i * 256..(i + 1) * 256].copy_from_slice(&snap);
        }
        out
    }

    /// T11 spec-vector: 9-opcode FP matrix under MXCSR mode 0 (RN).
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T11.
    #[test]
    fn t11_vm_fp_matrix_rn_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t11_vm_fp_matrix_rn.bin");
        assert_eq!(expected.len(), 9 * 256, "t11 .bin size invariant");
        let actual = fp_matrix_actual(0);
        assert_eq!(
            actual.as_slice(),
            expected,
            "T11 FP-matrix RN diverged from fork pin aaafe71",
        );
    }

    /// T12 spec-vector: 9-opcode FP matrix under MXCSR mode 1 (RD).
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T12.
    #[test]
    fn t12_vm_fp_matrix_rd_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t12_vm_fp_matrix_rd.bin");
        assert_eq!(expected.len(), 9 * 256, "t12 .bin size invariant");
        let actual = fp_matrix_actual(1);
        assert_eq!(
            actual.as_slice(),
            expected,
            "T12 FP-matrix RD diverged from fork pin aaafe71",
        );
    }

    /// T13 spec-vector: 9-opcode FP matrix under MXCSR mode 2 (RU).
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T13.
    #[test]
    fn t13_vm_fp_matrix_ru_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t13_vm_fp_matrix_ru.bin");
        assert_eq!(expected.len(), 9 * 256, "t13 .bin size invariant");
        let actual = fp_matrix_actual(2);
        assert_eq!(
            actual.as_slice(),
            expected,
            "T13 FP-matrix RU diverged from fork pin aaafe71",
        );
    }

    /// T14 spec-vector: 9-opcode FP matrix under MXCSR mode 3 (RZ).
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T14.
    #[test]
    fn t14_vm_fp_matrix_rz_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t14_vm_fp_matrix_rz.bin");
        assert_eq!(expected.len(), 9 * 256, "t14 .bin size invariant");
        let actual = fp_matrix_actual(3);
        assert_eq!(
            actual.as_slice(),
            expected,
            "T14 FP-matrix RZ diverged from fork pin aaafe71",
        );
    }

    /// T15 spec-vector: CFROUND throttle and unthrottled-mode
    /// behavior matches the v2 RandomX fork's `exe_CFROUND` byte-for
    /// byte at pin `aaafe71`. Three cases per the .meta.txt:
    /// throttled (r[1] = 0x0C, expected mode unchanged), unthrottled
    /// target RN (r[1] = 0x00), unthrottled target RZ (r[1] = 0x03).
    ///
    /// Per `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.2 T15.
    #[test]
    fn t15_vm_cfround_throttle_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/vm/t15_vm_cfround_throttle.bin");
        assert_eq!(expected.len(), 3 * (256 + 4), "t15 .bin size invariant");

        let mut actual = vec![0u8; 3 * (256 + 4)];

        for (case_idx, &src_value) in [0x0Cu64, 0x00, 0x03].iter().enumerate() {
            let mut state = canonical_phase2d_state();
            state.r[1] = src_value;
            crate::fpu_rounding::set_rounding_mode(0);
            let i = instr(239, 0, 1, 0, 0);
            dispatch_instruction(&i, &mut state);
            let snap = register_file_snapshot(&state);
            let mode = state.fprc;
            crate::fpu_rounding::set_rounding_mode(0);

            let off = case_idx * (256 + 4);
            actual[off..off + 256].copy_from_slice(&snap);
            actual[off + 256..off + 260].copy_from_slice(&mode.to_le_bytes());
        }

        assert_eq!(
            actual.as_slice(),
            expected,
            "T15 CFROUND-throttle dispatch diverged from fork pin aaafe71",
        );
    }
}
