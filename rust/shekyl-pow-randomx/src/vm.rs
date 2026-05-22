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
//! - **Commit 4 (this commit):** [`VmState`] struct skeleton with the
//!   frozen field set (per §5.1.1 + §5.5 F5 v2-only simplification),
//!   the [`F128`] / [`Instruction`] / [`Program`] type definitions,
//!   the [`PROGRAM_SIZE`] / [`RANDOMX_SCRATCHPAD_L3`] spec constants,
//!   [`VmState::new`] (allocation-only constructor), the
//!   `alloc_zeroed_scratchpad` carve-out (Phase 2c's second and final
//!   `#![deny(unsafe_code)]` carve-out per §1 covenant 7 + §5.11.2),
//!   the scratchpad-allocation `debug_assert!` per §5.11.2, and the
//!   empty [`Drop`] (review-surface hook per §5.11.4). No `compute_hash`,
//!   no `dispatch_instruction`, no register/program init — those land
//!   in commits 5 and 6.
//! - **Commit 5 (planned):** `VmState::initialize` with scratchpad init
//!   via `aes::fill_aes_1r_x4`, register-file init from the entropy
//!   buffer, program parsing via `aes::fill_aes_4r_x4`, plus T3-T5
//!   inline spec-vector tests (per §6 T3-T5 / §14 Round 0 R0-D6).
//! - **Commit 6 (planned):** `pub fn compute_hash` + the private
//!   `fn dispatch_instruction` NOP-body stub (the §5.1 function-body
//!   replacement contract Phase 2d fills in), plus the F/E AES mix
//!   per-iteration loop and the Blake2b finalize, plus T6-T8 inline
//!   spec-vector tests.
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
/// `RANDOMX_PROGRAM_SIZE_V2 = 2048` per
/// [`external/randomx-v2/src/configuration.h:57`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.5 F5 (v2-only simplification), the Rust port carries no
/// `PROGRAM_SIZE_V1` constant — v2 is structural, not a runtime
/// flag, and the V1 program size (256 instructions) is unreachable.
#[allow(dead_code)]
pub(crate) const PROGRAM_SIZE: usize = 2048;

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

/// A RandomX v2 program — exactly [`PROGRAM_SIZE`] (2048)
/// [`Instruction`]s feeding the dispatch loop.
///
/// Per
/// [`external/randomx-v2/src/program.hpp:44-68`](../../../external/randomx-v2/src/program.hpp)
/// at pin `aaafe71`, the C reference's `Program` class carries
/// *both* the 128-byte entropy buffer header *and* the 2048-instruction
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
/// = 2048 * 8 = 16_384` bytes. Construction goes through
/// [`Program::default`] (safe stable Rust via `std::array::from_fn`)
/// then `Box::new`; the 16 KiB stack overhead during construction
/// is amortized to a single move into the [`Box`] and is bounded by
/// the once-per-hash construction cost (`VmState::new` is called
/// from `compute_hash` once per hash, not per dispatch).
#[allow(dead_code)]
pub(crate) struct Program {
    /// The 2048 parsed instructions feeding the spec §4.5.4 dispatch
    /// loop. Populated by commit 5's `VmState::initialize` from the
    /// AES-generated entropy buffer; left zero-initialized by
    /// [`Program::default`].
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
    /// Construction allocates the 16 KiB array on the stack, which
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
    /// The 2048 parsed [`Instruction`]s feeding the dispatch loop.
    /// Heap-allocated as `Box<Program>` (one allocation of 16 KiB).
    /// Populated by commit 5's `VmState::initialize` from the AES-
    /// generated entropy buffer; left zero-initialized by
    /// [`VmState::new`].
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
    /// - One `size_of::<Program>()`-sized heap allocation (16 KiB)
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
    /// plus the 16 KiB program plus the inline state) is the
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
    /// [`F128`] alias, the [`PROGRAM_SIZE`] / [`RANDOMX_SCRATCHPAD_L3`]
    /// constants, the [`VmState`] / [`Program`] / [`Instruction`]
    /// field reads in [`VmState::drop`]'s implicit field-drop walk)
    /// is dead-code-lint dead in the same chain.
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
}

impl Drop for VmState {
    /// Empty drop — the 2 MiB `scratchpad` buffer is freed by the
    /// default `Box<[u8; RANDOMX_SCRATCHPAD_L3]>` destructor, the
    /// 16 KiB `program` buffer is freed by the default `Box<Program>`
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
