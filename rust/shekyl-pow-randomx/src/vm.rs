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
//! - **Commit 4 (as corrected by the R0-D9 fix-up immediately on
//!   top):** [`VmState`] struct skeleton with the frozen field set
//!   (per §5.1.1 + §5.5 F5 v2-only simplification), the [`F128`] /
//!   [`Instruction`] / [`Program`] type definitions, the
//!   [`PROGRAM_SIZE`] / [`PROGRAM_ITERATIONS`] /
//!   [`RANDOMX_SCRATCHPAD_L3`] spec constants, [`VmState::new`]
//!   (allocation-only constructor), the [`alloc_zeroed_scratchpad`]
//!   carve-out (Phase 2c's second and final `#![deny(unsafe_code)]`
//!   carve-out per §1 covenant 7 + §5.11.2), the scratchpad-
//!   allocation `debug_assert!` per §5.11.2, and the empty [`Drop`]
//!   (review-surface hook per §5.11.4).
//! - **Commit 5 (this commit, per §14 Round 0 R0-D8 Rust-idiomatic
//!   two-method init shape):** [`VmState::init_scratchpad`] via
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
//! - **Commit 6 (planned):** `pub fn compute_hash` + the private
//!   `fn dispatch_instruction` NOP-body stub (the §5.1 function-body
//!   replacement contract Phase 2d fills in), plus the F/E AES mix
//!   per-iteration loop and the Blake2b finalize, plus T6'/T7'/T8'
//!   fixture-free determinism property tests inline.
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
/// # Phase 2c shape (F3a deferred newtype)
///
/// Phase 2c introduces `F128` as a `type F128 = [f64; 2];` alias —
/// no `struct` wrapper, no method API, no `Copy`/`Default`/`Debug`
/// derives beyond what the inner array already provides. Per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.3 F3a + §5.1.1 "F128 shorthand discipline", the newtype
/// extraction decision (`struct F128([f64; 2])` with method API,
/// distinct type identity) is deferred to Phase 2d's §3.2
/// design-decision point: 2d Round 1 evaluates the newtype-or-keep
/// against real dispatch surfaces (FADD_R, FSUB_R, FMUL_R, FDIV_M,
/// FSQRT_R, FSCAL_R, FSWAP_R, CFROUND) and decides then. Until
/// then, this alias locks the *element shape* (`[f64; 2]`), not
/// the *type identity*.
#[allow(dead_code)]
pub(crate) type F128 = [f64; 2];

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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) const RANDOMX_SCRATCHPAD_L3: usize = 2_097_152;

const _: () = assert!(
    RANDOMX_SCRATCHPAD_L3.is_power_of_two(),
    "RANDOMX_SCRATCHPAD_L3 must be a power of two per common.hpp:57 \
     (the bytecode dispatch in Phase 2d derives the L1/L2/L3 masks as \
     RANDOMX_SCRATCHPAD_LN / sizeof(int_reg_t) - 1 for N in 1..=3, \
     which is only correct when the operand is a power of two)"
);

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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) const RANDOMX_DATASET_EXTRA_SIZE: u32 = 33_554_368;

/// Cache-line size in bytes.
///
/// `CacheLineSize = RANDOMX_DATASET_ITEM_SIZE = 64` per
/// [`external/randomx-v2/src/common.hpp:85`](../../../external/randomx-v2/src/common.hpp)
/// and
/// [`external/randomx-v2/src/randomx.h:36`](../../../external/randomx-v2/src/randomx.h)
/// at pin `aaafe71`. Used by [`VmState::init_program`]'s `mem.ma`
/// alignment + `dataset_offset` multiplier.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) const DATASET_EXTRA_ITEMS: u32 = RANDOMX_DATASET_EXTRA_SIZE / CACHE_LINE_SIZE;

/// IEEE-754 binary64 mantissa width in bits.
///
/// `mantissaSize = 52` per
/// [`external/randomx-v2/src/common.hpp:174`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Used by [`get_small_positive_float_bits`] /
/// [`get_static_exponent`] to assemble IEEE-754 binary64 bit patterns
/// from the program-init entropy buffer.
#[allow(dead_code)]
pub(crate) const MANTISSA_SIZE: u32 = 52;

/// IEEE-754 binary64 exponent width in bits.
///
/// `exponentSize = 11` per
/// [`external/randomx-v2/src/common.hpp:175`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Used by [`get_small_positive_float_bits`] to
/// mask the entropy-derived exponent into the binary64 11-bit field.
#[allow(dead_code)]
pub(crate) const EXPONENT_SIZE: u32 = 11;

/// IEEE-754 binary64 mantissa mask.
///
/// `mantissaMask = (1 << mantissaSize) - 1` per
/// [`external/randomx-v2/src/common.hpp:176`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
#[allow(dead_code)]
pub(crate) const MANTISSA_MASK: u64 = (1u64 << MANTISSA_SIZE) - 1;

/// IEEE-754 binary64 exponent mask.
///
/// `exponentMask = (1 << exponentSize) - 1` per
/// [`external/randomx-v2/src/common.hpp:177`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
#[allow(dead_code)]
pub(crate) const EXPONENT_MASK: u64 = (1u64 << EXPONENT_SIZE) - 1;

/// IEEE-754 binary64 exponent bias.
///
/// `exponentBias = 1023` per
/// [`external/randomx-v2/src/common.hpp:178`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
#[allow(dead_code)]
pub(crate) const EXPONENT_BIAS: u64 = 1023;

/// Dynamic exponent bit-width for the `e`-register float-mask
/// derivation.
///
/// `dynamicExponentBits = 4` per
/// [`external/randomx-v2/src/common.hpp:179`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. Used by [`get_static_exponent`].
#[allow(dead_code)]
pub(crate) const DYNAMIC_EXPONENT_BITS: u32 = 4;

/// Static exponent bit-width consumed from the entropy MSB by
/// [`get_static_exponent`].
///
/// `staticExponentBits = 4` per
/// [`external/randomx-v2/src/common.hpp:180`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
#[allow(dead_code)]
pub(crate) const STATIC_EXPONENT_BITS: u32 = 4;

/// Fixed exponent bits seeded into [`get_static_exponent`]'s output
/// before XOR-ing with the entropy-derived bits.
///
/// `constExponentBits = 0x300` per
/// [`external/randomx-v2/src/common.hpp:181`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`.
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) const ENTROPY_BUFFER_SIZE: usize = 128;

/// Size in bytes of a single parsed [`Instruction`] in the program
/// buffer's instruction tail.
///
/// Per [`spec §5.1`](../../../external/randomx-v2/doc/specs.md) +
/// [`external/randomx-v2/src/instruction.hpp`](../../../external/randomx-v2/src/instruction.hpp)
/// at pin `aaafe71`, every RandomX instruction is exactly 8 bytes
/// on the wire: `opcode | dst | src | mod_ | imm32 (LE)`.
#[allow(dead_code)]
pub(crate) const INSTRUCTION_SIZE: usize = 8;

/// Size in bytes of the [`VmState::init_program`] AES-fill buffer.
///
/// Per [`spec §4.5`](../../../external/randomx-v2/doc/specs.md) the
/// per-program AES-generator emits `128 + 8 * RANDOMX_PROGRAM_SIZE`
/// bytes per program-init call (128-byte entropy header + 384 × 8-byte
/// instructions = 3_200 bytes at `RANDOMX_PROGRAM_SIZE_V2 = 384`).
/// The constant is asserted equal to `ENTROPY_BUFFER_SIZE +
/// PROGRAM_SIZE * INSTRUCTION_SIZE` at compile time below.
#[allow(dead_code)]
pub(crate) const PROGRAM_BUFFER_SIZE: usize = ENTROPY_BUFFER_SIZE + PROGRAM_SIZE * INSTRUCTION_SIZE;

const _: () = assert!(
    PROGRAM_BUFFER_SIZE == 3_200,
    "PROGRAM_BUFFER_SIZE must equal 128 + 8 * 384 = 3_200 per spec \
     section 4.5; if PROGRAM_SIZE drifts away from 384 (per R0-D9), \
     this assertion catches the drift before init_program's stack \
     allocation runs against a wrong size"
);

const _: () = assert!(
    PROGRAM_BUFFER_SIZE % 64 == 0,
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) fn get_float_mask(entropy: u64) -> u64 {
    const MASK_22BIT: u64 = (1u64 << 22) - 1;
    (entropy & MASK_22BIT) | get_static_exponent(entropy)
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
#[allow(dead_code)]
pub(crate) struct Program {
    /// The [`PROGRAM_SIZE`] (384) parsed instructions feeding the
    /// spec §4.5.4 dispatch loop. Populated by commit 5's
    /// `VmState::init_program` from the AES-generated entropy
    /// buffer; left zero-initialized by [`Program::default`].
    pub(crate) instructions: [Instruction; PROGRAM_SIZE],
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
    /// §8 budget, the per-hash allocation cost (the 2 MiB scratchpad
    /// plus the 3 KiB program plus the inline state) is the
    /// dominant cost of `compute_hash` under stub-NOP dispatch —
    /// commit 8's `benches/compute_hash_alloc.rs` measures it
    /// directly under the ≤100 µs PR-gating threshold.
    ///
    /// # REMOVE WHEN PHASE 2c COMMIT 6 WIRES THIS:
    ///
    /// Until commit 6's `pub fn compute_hash` lands, [`VmState::new`]
    /// has no `pub`-reachable caller. The entire transitive chain
    /// reached from this function ([`alloc_zeroed_scratchpad`],
    /// [`Program::default`], [`Instruction::default`], the
    /// [`F128`] alias, the [`PROGRAM_SIZE`] / [`PROGRAM_ITERATIONS`]
    /// / [`RANDOMX_SCRATCHPAD_L3`] constants, the [`VmState`] /
    /// [`Program`] / [`Instruction`] field reads in [`VmState::drop`]'s
    /// implicit field-drop walk) is dead-code-lint dead in the same
    /// chain. [`PROGRAM_ITERATIONS`] is consumed at commit 6 by
    /// `VmState::run`'s outer loop and at Phase 2d by the bytecode
    /// dispatch's per-iteration index space; until then, the same
    /// chain-entry `#[allow(dead_code)]` covers its read-site
    /// absence.
    ///
    /// A single `#[allow(dead_code)]` at this chain entry-point
    /// suppresses the transitive lint cascade per the standard
    /// `rustc` reachability analysis (mirroring the same discipline
    /// applied to `Cache::derive_item` in commit 3 of this PR per
    /// `cache.rs:402`). Per-struct `#[allow(dead_code)]` on
    /// [`VmState`] / [`Program`] / [`Instruction`] / [`F128`]
    /// covers the field-level "never read" lint that the
    /// reachability propagation does not suppress on its own (the
    /// lint fires for unread fields independent of whether the
    /// enclosing struct is constructed). Commit 6's `compute_hash`
    /// becomes the production `pub` caller, at which point this
    /// `#[allow]` on [`VmState::new`] is removed (the per-struct
    /// `#[allow]`s outlive it because the field reads only begin
    /// when commit 5's [`VmState::initialize`] and commit 6's
    /// dispatch wire them).
    #[allow(dead_code)]
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
            f: [[0.0f64; 2]; 4],
            e: [[0.0f64; 2]; 4],
            a: [[0.0f64; 2]; 4],
            fprc: 0,
            scratchpad,
            e_mask: [0u64; 2],
            ma: 0,
            mx: 0,
            read_reg: [0u32; 4],
            dataset_offset: 0,
            program: Box::new(Program::default()),
            temp_hash: [0u64; 8],
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
    /// # REMOVE WHEN PHASE 2c COMMIT 6 WIRES THIS:
    ///
    /// Same chain-entry pattern as [`VmState::new`] — until commit
    /// 6's `pub fn compute_hash` lands, [`VmState::init_scratchpad`]
    /// has no `pub`-reachable caller. The transitive chain reached
    /// from this method ([`crate::aes::fill_aes_1r_x4`] —
    /// already chain-entry-allowed in `aes.rs` per Phase 2b's
    /// commit-2 dead-code discipline) inherits the suppression via
    /// the standard `rustc` reachability analysis. Commit 6's
    /// `compute_hash` becomes the production `pub` caller, at which
    /// point this `#[allow]` is removed.
    #[allow(dead_code)]
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
    /// # REMOVE WHEN PHASE 2c COMMIT 6 WIRES THIS:
    ///
    /// Same chain-entry pattern as [`VmState::init_scratchpad`].
    #[allow(dead_code)]
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
}
