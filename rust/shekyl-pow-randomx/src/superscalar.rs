// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SuperscalarHash program generator + executor per
//! [`specs.md`](../../external/randomx-v2/doc/specs.md) §6 and §7.2.
//!
//! `SuperscalarHash` is RandomX's custom diffusion function over 8
//! 64-bit registers. It is consumed by Cache → Dataset construction
//! (Phase 2e); this module provides the two pure functions Cache::derive
//! needs:
//!
//! - [`generate_superscalar`] — generate a [`SuperscalarProgram`] by
//!   simulating an Intel-Ivy-Bridge-style reference CPU and driving
//!   instruction selection / port assignment / operand assignment from
//!   a [`Blake2Generator`].
//! - [`execute_superscalar`] — execute a previously-generated program
//!   over an `[u64; 8]` register file.
//!
//! # Scope at this commit (Phase 2b commit 5)
//!
//! Commit 3 landed the program-generator and executor plus structural
//! smoke tests on a single fixed `(seed, nonce)`. Commit 5 adds the
//! byte-for-byte spec-vector parity tests against `superscalar.cpp`
//! at fork pin `aaafe71`: Layer A program serialization × 3 + Layer B
//! execution × 3 + combined end-to-end attestation, per the F4
//! structured 3-vector decomposition in
//! [`RANDOMX_V2_PHASE2B_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2B_PLAN.md)
//! §5.4.
//!
//! The 7 reference vectors live under
//! [`tests/vectors/reference/superscalar/`] with `.meta.txt`
//! provenance headers; the C++ generator that produced them lives at
//! [`tests/vectors/reference/superscalar/_generator/`] and is
//! reviewer-runnable per its `README.md`. The Rust tests consume the
//! pre-committed `.bin` bytes via `include_bytes!`, so `cargo test`
//! has no dev-dep on the C library (Phase 2g's live differential
//! harness is the separate artifact).
//!
//! **Failure-mode attribution.** The Layer A vectors share the
//! `(seed=empty, nonce=*)` axis (vectors 1+2) and the `(*, nonce=0)`
//! axis (vectors 1+3); a divergence on only vector 2 attributes to
//! Blake2Generator nonce handling, on only vector 3 attributes to
//! seed initialization, on both 2 and 3 attributes to the downstream
//! port-assign / instruction-selection pipeline. Layer B decouples
//! generation parity from execution parity; the combined vector tests
//! the full generate→execute pipeline without intermediate
//! serialization (the spec-attestation reference downstream consumers
//! verify against).
//!
//! [`tests/vectors/reference/superscalar/`]: ../../tests/vectors/reference/superscalar/
//! [`tests/vectors/reference/superscalar/_generator/`]: ../../tests/vectors/reference/superscalar/_generator/
//!
//! # Spec / C reference
//!
//! - **Spec:** [`specs.md`](../../external/randomx-v2/doc/specs.md) §6
//!   (SuperscalarHash, reference CPU, CPU simulation), §7.2
//!   (SuperscalarHash initialization).
//! - **C reference:** `external/randomx-v2/src/superscalar.cpp` (903
//!   lines) and `superscalar_program.hpp` (83 lines).
//! - **Configuration constants:** `RANDOMX_SUPERSCALAR_LATENCY = 170`
//!   per `external/randomx-v2/src/configuration.h:47`;
//!   `SuperscalarMaxSize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2 = 512`
//!   per `common.hpp:84`; `sizeof(Instruction) = 8` per
//!   `instruction.hpp:147` static_assert.
//!
//! # Architecture compliance
//!
//! - Pure function call surface (no module-level mutable state) per
//!   permanent decision #6 (`RANDOMX_V2_PLAN.md`); the
//!   [`Blake2Generator`] passed by `&mut` is the caller's state, not
//!   ours.
//! - `#![deny(unsafe_code)]` survives.
//! - C-side diagnostic fields (`ipc`, `codeSize`, `macroOps`,
//!   `decodeCycles`, `cpuLatency`, `asicLatency`, `mulCount`,
//!   `cpuLatencies[8]`) are deleted from the Rust port per
//!   `15-deletion-and-debt.mdc`: they exist only for the C `print()`
//!   method, which has no Rust equivalent. `addr_reg` is kept because
//!   spec §7.3 step 7 uses it ("Set `cacheIndex` to the value of the
//!   register that has the longest dependency chain"). `asicLatencies`
//!   itself is also dropped — only the index of the maximum is kept
//!   (i.e., `addr_reg`).
//! - The data layout matches `superscalar_program.hpp`'s relevant
//!   fields: a fixed-size array of [`SUPERSCALAR_MAX_SIZE`] (= 512)
//!   instructions plus a `usize` size counter plus a `u8`
//!   address-register index; total = 4096 bytes for instructions
//!   plus ~16 bytes of meta = ~4 KiB per program. Cache::derive in
//!   Phase 2e holds 8 programs simultaneously = ~32 KiB total, well
//!   within default 2 MiB Linux thread stacks (no heap allocation
//!   needed).
//!
//! # Spec-silence audit table
//!
//! Per `RANDOMX_V2_PHASE2B_PLAN.md` §5.5: where [`specs.md`] is silent
//! on fine-grain details that the generator nonetheless must commit to
//! a specific behavior for, the Rust port matches the C reference
//! verbatim. The discipline says "spec wins on disagreement," but
//! spec **silence** means C wins by default; this table records the
//! eight places that happens so the choice is auditable rather than
//! invisible.
//!
//! | # | Spec section silent on | C reference disposition | Rust port disposition |
//! |---|-------------------------|--------------------------|------------------------|
//! | 1 | §6.3 initial `DecoderBuffer` before the first `fetchNext` call | `superscalar.cpp:659` initialises `decodeBuffer = &DecoderBuffer::Default` (a sentinel with `index_ = -1` and `getSize() = 0`); on the first `fetchNext` call with `currentInstruction.type = INVALID`, `mulCount = 0`, `cycle = 0`, the `mulCount < cycle + 1` branch fires unconditionally and returns `decodeBuffer4444`. The Default buffer is never queried for slots. | Same observable behaviour: the Rust generator's `decode_buffer` binding is freshly produced by `DecoderBuffer::fetch_next` inside each outer-loop iteration, so the C sentinel is structurally unnecessary; the first call returns `&DECODE_BUFFER_4444` via the same `mul_count < cycle + 1` test. |
//! | 2 | §6.3.4 `LOOK_FORWARD_CYCLES` constant | `superscalar.cpp:583` defines `LOOK_FORWARD_CYCLES = 4`; if no source/destination register is available at the current cycle, the generator looks up to 4 cycles forward before throwing the instruction away. | Same constant value 4. |
//! | 3 | §6.3.4 `MAX_THROWAWAY_COUNT` constant | `superscalar.cpp:584` defines `MAX_THROWAWAY_COUNT = 256`; after that many throwaways the generator aborts the current decode buffer. | Same constant value 256. |
//! | 4 | §6.3.1 bit selection from `getByte()` for default decoder-group choice | `superscalar.cpp:304` selects `decodeBuffers[gen.getByte() & 3]` (low 2 bits, indexing the 4-entry `decodeBuffers` array). | Same: `decode_buffers[gen.get_byte() & 0b11]`. |
//! | 5 | §6.3.1 bit selection from `getByte()` for IMUL_RCP follow-up (group 0 or 3) | `superscalar.cpp:285` selects `(gen.getByte() & 1) ? decodeBuffer484 : decodeBuffer493` (bit 0). | Same. |
//! | 6 | §6.3.2 3-byte last-slot selection between ISUB_R, IXOR_R, IMULH_R, ISMULH_R | `superscalar.cpp:373` selects `slot_3L[gen.getByte() & 3]` (low 2 bits over the 4-entry `slot_3L` array). | Same: `SLOT_3_LAST[gen.get_byte() & 0b11]`. |
//! | 7 | §6.3.4 IADD_RS exceptional case: only 2 registers available and r5 is one of them | `superscalar.cpp:524-528` sets `src = RegisterNeedsDisplacement (= r5)` unconditionally (so the other register can be destination), bypassing the normal `selectRegister` path. | Same. |
//! | 8 | §6.3.4 `allowChainedMul` trigger semantics | `superscalar.cpp:739` passes `throwAwayCount > 0` as `allowChainedMul`; spec says "set to true if an attempt to find source/destination registers failed". | Same. |
//!
//! **Long-tail acknowledgement.** Whether each row eventually
//! becomes a filed fork-side spec-clarification issue is not under
//! Phase 2b's control and is not load-bearing for Phase 2b's
//! correctness claim — the Rust port's verbatim-port-of-C
//! disposition is the right one for each row regardless of any
//! fork-side resolution status. The audit table is the
//! disposition; per
//! `21-reversion-clause-discipline.mdc`, this disposition reopens
//! only if a substrate change makes per-row issue tracking
//! load-bearing (for example, if the spec is later amended such
//! that a row's C-only behavior becomes spec-required, in which
//! case the row would migrate from "spec-silent, C wins" to "spec-
//! required, verified against spec" and the corresponding parity
//! test would carry the new spec citation).
//!
//! [`specs.md`]: ../../external/randomx-v2/doc/specs.md

use crate::blake2_generator::Blake2Generator;

// -----------------------------------------------------------------------------
// Configuration constants
// -----------------------------------------------------------------------------

/// Target latency for SuperscalarHash, in cycles of the reference CPU.
///
/// Per `external/randomx-v2/src/configuration.h:47` (value `170`,
/// identical in v1 and v2 per `RANDOMX_V2_RUST.md` §1.3).
pub(crate) const RANDOMX_SUPERSCALAR_LATENCY: usize = 170;

/// Maximum number of instructions in a [`SuperscalarProgram`].
///
/// Per `external/randomx-v2/src/common.hpp:84`:
/// `SuperscalarMaxSize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2 = 512`.
pub(crate) const SUPERSCALAR_MAX_SIZE: usize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2;

/// Number of integer registers in the `SuperscalarHash` register
/// file (`r0`-`r7`).
pub(crate) const REGISTERS_COUNT: usize = 8;

/// Register index that cannot be the destination of `IADD_RS`
/// (x86 `r13` register: `lea` with a `disp32` field).
///
/// Per `external/randomx-v2/src/common.hpp:167`.
const REGISTER_NEEDS_DISPLACEMENT: u8 = 5;

/// Per `superscalar.cpp:582`:
/// `CYCLE_MAP_SIZE = RANDOMX_SUPERSCALAR_LATENCY + 4`.
const CYCLE_MAP_SIZE: usize = RANDOMX_SUPERSCALAR_LATENCY + 4;

/// Per `superscalar.cpp:583`. See spec-silence audit row 2.
const LOOK_FORWARD_CYCLES: usize = 4;

/// Per `superscalar.cpp:584`. See spec-silence audit row 3.
const MAX_THROWAWAY_COUNT: usize = 256;

// -----------------------------------------------------------------------------
// Instruction types
// -----------------------------------------------------------------------------

/// `SuperscalarHash` instruction opcode enumeration per
/// [`specs.md`](../../external/randomx-v2/doc/specs.md) §6.1 Table
/// 6.1.1. Values match `superscalar.hpp:38-55`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SuperscalarInstructionType {
    /// `dst = dst - src` (rule: `dst != src`). Macro-op `sub_rr`.
    ISubR = 0,
    /// `dst = dst ^ src` (rule: `dst != src`). Macro-op `xor_rr`.
    IXorR = 1,
    /// `dst = dst + (src << mod.shift)` (rules: `dst != src`,
    /// `dst != r5`). Macro-op `lea_sib`.
    IAddRs = 2,
    /// `dst = dst * src` (rule: `dst != src`). Macro-op `imul_rr`.
    IMulR = 3,
    /// `dst = dst >>> imm32` (rule: `imm32 % 64 != 0`). Macro-op
    /// `ror_ri`.
    IRorC = 4,
    /// `dst = dst + sext(imm32)`, code size 7 bytes. Macro-op
    /// `add_ri`.
    IAddC7 = 5,
    /// `dst = dst ^ sext(imm32)`, code size 7 bytes. Macro-op
    /// `xor_ri`.
    IXorC7 = 6,
    /// `dst = dst + sext(imm32)`, code size 8 bytes (7 + 1-byte nop).
    /// Macro-op `add_ri`.
    IAddC8 = 7,
    /// `dst = dst ^ sext(imm32)`, code size 8 bytes (7 + 1-byte nop).
    /// Macro-op `xor_ri`.
    IXorC8 = 8,
    /// `dst = dst + sext(imm32)`, code size 9 bytes (7 + 2-byte nop).
    /// Macro-op `add_ri`.
    IAddC9 = 9,
    /// `dst = dst ^ sext(imm32)`, code size 9 bytes (7 + 2-byte nop).
    /// Macro-op `xor_ri`.
    IXorC9 = 10,
    /// `dst = (dst * src) >> 64` (unsigned). Macro-ops
    /// `mov_rr, mul_r, mov_rr`.
    IMulhR = 11,
    /// `dst = (dst * src) >> 64` (signed). Macro-ops
    /// `mov_rr, imul_r, mov_rr`.
    ISMulhR = 12,
    /// `dst = (2^x / imm32) * dst` for highest `x` such that
    /// `result < 2^64`. Rule: `imm32 != 0`, `imm32 != 2^N`. Macro-ops
    /// `mov_ri, imul_rr` (with `imul_rr` flagged as dependent on the
    /// preceding `mov_ri`).
    IMulRcp = 13,
}

impl SuperscalarInstructionType {
    /// Convert from a discriminant value, returning [`None`] on
    /// out-of-range. Used by [`execute_superscalar`] to dispatch.
    const fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            0 => Some(Self::ISubR),
            1 => Some(Self::IXorR),
            2 => Some(Self::IAddRs),
            3 => Some(Self::IMulR),
            4 => Some(Self::IRorC),
            5 => Some(Self::IAddC7),
            6 => Some(Self::IXorC7),
            7 => Some(Self::IAddC8),
            8 => Some(Self::IXorC8),
            9 => Some(Self::IAddC9),
            10 => Some(Self::IXorC9),
            11 => Some(Self::IMulhR),
            12 => Some(Self::ISMulhR),
            13 => Some(Self::IMulRcp),
            _ => None,
        }
    }

    fn is_multiplication(self) -> bool {
        matches!(
            self,
            Self::IMulR | Self::IMulhR | Self::ISMulhR | Self::IMulRcp
        )
    }
}

// -----------------------------------------------------------------------------
// SuperscalarProgram instruction (the data-model record)
// -----------------------------------------------------------------------------

/// A single instruction in a [`SuperscalarProgram`].
///
/// Layout matches `external/randomx-v2/src/instruction.hpp:103-107`
/// for the fields the Rust port uses (`opcode`, `dst`, `src`, `mod_`,
/// `imm32`); `sizeof = 8 bytes` per `instruction.hpp:147` static_assert.
///
/// The `mod_` field is a packed bit-field per
/// `instruction.hpp:90-98`:
/// - bits 0-1: `mod_mem` (unused by SuperscalarHash);
/// - bits 2-3: `mod_shift` (used by IADD_RS).
///
/// The Rust port keeps the same packed representation rather than
/// pre-decomposing because the value is fixed at generation time and
/// the C reference's accessor functions are the canonical interface.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SuperscalarInstruction {
    /// [`SuperscalarInstructionType`] discriminant value.
    pub(crate) opcode: u8,
    /// Destination register index (0-7).
    pub(crate) dst: u8,
    /// Source register index (0-7). For register-immediate
    /// instructions where the C generator writes `src = dst`, the
    /// same convention is preserved here so dispatch can treat src
    /// uniformly.
    pub(crate) src: u8,
    /// Packed mod field; only bits 2-3 (shift count for IADD_RS) are
    /// load-bearing for SuperscalarHash.
    pub(crate) mod_: u8,
    /// 32-bit immediate; semantics depend on opcode (rotation count
    /// for IROR_C, sign-extended addend for IADD_C* / XOR_C*,
    /// reciprocal divisor for IMUL_RCP).
    pub(crate) imm32: u32,
}

const _: () = assert!(core::mem::size_of::<SuperscalarInstruction>() == 8);

impl SuperscalarInstruction {
    const ZERO: Self = Self {
        opcode: 0,
        dst: 0,
        src: 0,
        mod_: 0,
        imm32: 0,
    };

    /// Extract the IADD_RS shift count from `mod_` (bits 2-3).
    /// Matches `instruction.hpp:93-95 getModShift`.
    fn mod_shift(self) -> u32 {
        u32::from((self.mod_ >> 2) & 0b11)
    }
}

/// A generated SuperscalarHash program.
///
/// Per design-plan §5.2: fixed-size in-place instruction array (no
/// heap allocation). The `size` field is the number of valid leading
/// entries.
pub(crate) struct SuperscalarProgram {
    instructions: [SuperscalarInstruction; SUPERSCALAR_MAX_SIZE],
    size: usize,
    /// The register with the longest ASIC dependency chain, used by
    /// spec §7.3 step 7 ("Set `cacheIndex` to the value of the
    /// register that has the longest dependency chain in the
    /// SuperscalarHash function executed in step 5").
    address_register: u8,
}

impl SuperscalarProgram {
    /// Construct an empty program (`size = 0`). Used as the starting
    /// state for [`generate_superscalar`] before instructions are
    /// pushed.
    fn new() -> Self {
        Self {
            instructions: [SuperscalarInstruction::ZERO; SUPERSCALAR_MAX_SIZE],
            size: 0,
            address_register: 0,
        }
    }

    /// Number of valid leading instructions.
    ///
    /// # REMOVE WHEN PHASE 2e WIRES THIS:
    ///
    /// `Cache::derive` iterates `0..program.size()` to drive the
    /// dataset construction loop per spec §7.3.
    #[allow(dead_code)]
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// Read-only access to the slice of generated instructions
    /// (length = [`Self::size`]).
    pub(crate) fn instructions(&self) -> &[SuperscalarInstruction] {
        &self.instructions[..self.size]
    }

    /// Address register index (see the struct's `address_register`
    /// field doc).
    ///
    /// # REMOVE WHEN PHASE 2e WIRES THIS:
    ///
    /// `Cache::derive` reads this per spec §7.3 step 7
    /// ("Set `cacheIndex` to the value of the register that has the
    /// longest dependency chain").
    #[allow(dead_code)]
    pub(crate) fn address_register(&self) -> u8 {
        self.address_register
    }
}

// -----------------------------------------------------------------------------
// Reference-CPU model: execution ports and macro-ops
// -----------------------------------------------------------------------------

/// Execution-port bitset per `superscalar.cpp:49-58` and spec
/// §6.2 (3 integer execution ports P0, P1, P5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutionPort(u8);

impl ExecutionPort {
    const NULL: Self = Self(0);
    const P0: Self = Self(1);
    const P1: Self = Self(2);
    const P5: Self = Self(4);
    const P01: Self = Self(Self::P0.0 | Self::P1.0);
    const P05: Self = Self(Self::P0.0 | Self::P5.0);
    const P015: Self = Self(Self::P0.0 | Self::P1.0 | Self::P5.0);

    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Per-cycle per-port busy map. The C reference uses
/// `ExecutionPort::type portBusy[CYCLE_MAP_SIZE][3]` where the
/// per-cycle entry is the *port mask of the uOP that occupied it*
/// (zero = idle); the Rust port uses `bool` (occupied or not) because
/// the mask value is never read back.
type PortBusy = [[bool; 3]; CYCLE_MAP_SIZE];

/// Reference-CPU macro-op record per `superscalar.cpp:63-148`.
///
/// `dependent` is the IMUL_RCP `Imul_rr` flag: when true, the
/// macro-op cannot begin before the cycle at which the preceding
/// macro-op produced its result.
///
/// The C reference's `size` byte-count field (`MacroOp::size_`) is
/// not ported: it exists only to maintain the diagnostic `codeSize`
/// running total in `superscalar.cpp:786,830`, which feeds the
/// per-program `codeSize` field deleted by `RANDOMX_V2_PHASE2B_PLAN.md`
/// §5.2 along with the other diagnostic fields.
#[derive(Clone, Copy, Debug)]
struct MacroOp {
    latency: u8,
    uop1: ExecutionPort,
    uop2: ExecutionPort,
    dependent: bool,
}

impl MacroOp {
    const fn simple(latency: u8, uop: ExecutionPort) -> Self {
        Self {
            latency,
            uop1: uop,
            uop2: ExecutionPort::NULL,
            dependent: false,
        }
    }

    const fn dual(latency: u8, uop1: ExecutionPort, uop2: ExecutionPort) -> Self {
        Self {
            latency,
            uop1,
            uop2,
            dependent: false,
        }
    }

    const fn eliminated() -> Self {
        Self {
            latency: 0,
            uop1: ExecutionPort::NULL,
            uop2: ExecutionPort::NULL,
            dependent: false,
        }
    }

    const fn with_dependent(mut self) -> Self {
        self.dependent = true;
        self
    }

    fn is_simple(self) -> bool {
        self.uop2.is_null()
    }

    fn is_eliminated(self) -> bool {
        self.uop1.is_null()
    }
}

// Macro-op definitions per spec §6.2 Table 6.2.1 / superscalar.cpp:124-148.

/// `add r,r` — latency 1, P015.
const ADD_RR: MacroOp = MacroOp::simple(1, ExecutionPort::P015);
/// `sub r,r` — latency 1, P015.
const SUB_RR: MacroOp = MacroOp::simple(1, ExecutionPort::P015);
/// `xor r,r` — latency 1, P015.
const XOR_RR: MacroOp = MacroOp::simple(1, ExecutionPort::P015);
/// `imul r` — latency 4, P1+P5 (two uOPs).
const IMUL_R_MOP: MacroOp = MacroOp::dual(4, ExecutionPort::P1, ExecutionPort::P5);
/// `mul r` — latency 4, P1+P5 (two uOPs).
const MUL_R_MOP: MacroOp = MacroOp::dual(4, ExecutionPort::P1, ExecutionPort::P5);
/// `mov r,r` — latency 0, eliminated (register renaming).
const MOV_RR: MacroOp = MacroOp::eliminated();
/// `lea r,r+r*s` — latency 1, P01.
const LEA_SIB: MacroOp = MacroOp::simple(1, ExecutionPort::P01);
/// `imul r,r` — latency 3, P1.
const IMUL_RR: MacroOp = MacroOp::simple(3, ExecutionPort::P1);
/// `ror r,i` — latency 1, P05.
const ROR_RI: MacroOp = MacroOp::simple(1, ExecutionPort::P05);
/// `add r,i` — latency 1, P015.
const ADD_RI: MacroOp = MacroOp::simple(1, ExecutionPort::P015);
/// `xor r,i` — latency 1, P015.
const XOR_RI: MacroOp = MacroOp::simple(1, ExecutionPort::P015);
/// `mov rax,i64` — latency 1, P015.
const MOV_RI64: MacroOp = MacroOp::simple(1, ExecutionPort::P015);

/// Per-instruction macro-op sequence (max 3 macro-ops).
///
/// The fixed-size array + length avoids heap allocation; max length
/// is 3 (IMULH_R, ISMULH_R).
#[derive(Clone, Copy, Debug)]
struct MacroOpSequence {
    ops: [MacroOp; 3],
    len: u8,
}

impl MacroOpSequence {
    const fn one(op: MacroOp) -> Self {
        Self {
            ops: [op, ADD_RR, ADD_RR], // padding (ignored)
            len: 1,
        }
    }

    const fn two(op0: MacroOp, op1: MacroOp) -> Self {
        Self {
            ops: [op0, op1, ADD_RR],
            len: 2,
        }
    }

    const fn three(op0: MacroOp, op1: MacroOp, op2: MacroOp) -> Self {
        Self {
            ops: [op0, op1, op2],
            len: 3,
        }
    }

    fn len(&self) -> usize {
        self.len as usize
    }

    fn op(&self, i: usize) -> MacroOp {
        self.ops[i]
    }
}

/// Per-instruction-type info: macro-op sequence + which macro-op
/// index handles src/dst/result responsibilities (see
/// `superscalar.cpp:154-241`).
///
/// The C reference encodes "no operand at this slot" as the sentinel
/// `-1` in a signed `int`; the Rust port uses `Option<u8>` instead
/// per workspace clippy discipline (`cast_sign_loss`,
/// `cast_possible_wrap` denied at workspace level).
#[derive(Clone, Copy, Debug)]
struct InstructionInfo {
    seq: MacroOpSequence,
    /// Index of the macro-op that writes the result, or `None` for
    /// the NOP / "null" instruction.
    result_op: Option<u8>,
    /// Index of the macro-op that selects the destination register,
    /// or `None` (NOP).
    dst_op: Option<u8>,
    /// Index of the macro-op that selects the source register, or
    /// `None` for immediate-only instructions.
    src_op: Option<u8>,
}

impl InstructionInfo {
    const fn single(op: MacroOp, src_op: Option<u8>) -> Self {
        Self {
            seq: MacroOpSequence::one(op),
            result_op: Some(0),
            dst_op: Some(0),
            src_op,
        }
    }

    const fn multi(
        seq: MacroOpSequence,
        result_op: Option<u8>,
        dst_op: Option<u8>,
        src_op: Option<u8>,
    ) -> Self {
        Self {
            seq,
            result_op,
            dst_op,
            src_op,
        }
    }
}

const INFO_ISUB_R: InstructionInfo = InstructionInfo::single(SUB_RR, Some(0));
const INFO_IXOR_R: InstructionInfo = InstructionInfo::single(XOR_RR, Some(0));
const INFO_IADD_RS: InstructionInfo = InstructionInfo::single(LEA_SIB, Some(0));
const INFO_IMUL_R: InstructionInfo = InstructionInfo::single(IMUL_RR, Some(0));
const INFO_IROR_C: InstructionInfo = InstructionInfo::single(ROR_RI, None);
const INFO_IADD_C7: InstructionInfo = InstructionInfo::single(ADD_RI, None);
const INFO_IXOR_C7: InstructionInfo = InstructionInfo::single(XOR_RI, None);
const INFO_IADD_C8: InstructionInfo = InstructionInfo::single(ADD_RI, None);
const INFO_IXOR_C8: InstructionInfo = InstructionInfo::single(XOR_RI, None);
const INFO_IADD_C9: InstructionInfo = InstructionInfo::single(ADD_RI, None);
const INFO_IXOR_C9: InstructionInfo = InstructionInfo::single(XOR_RI, None);
const INFO_IMULH_R: InstructionInfo = InstructionInfo::multi(
    MacroOpSequence::three(MOV_RR, MUL_R_MOP, MOV_RR),
    Some(1),
    Some(0),
    Some(1),
);
const INFO_ISMULH_R: InstructionInfo = InstructionInfo::multi(
    MacroOpSequence::three(MOV_RR, IMUL_R_MOP, MOV_RR),
    Some(1),
    Some(0),
    Some(1),
);
const INFO_IMUL_RCP: InstructionInfo = InstructionInfo::multi(
    MacroOpSequence::two(MOV_RI64, IMUL_RR.with_dependent()),
    Some(1),
    Some(1),
    None,
);
/// NOP / "null" instruction: zero macro-ops, all operand slots
/// `None`.
const INFO_NOP: InstructionInfo = InstructionInfo {
    seq: MacroOpSequence {
        ops: [ADD_RR; 3],
        len: 0,
    },
    result_op: None,
    dst_op: None,
    src_op: None,
};

fn info_for(t: SuperscalarInstructionType) -> &'static InstructionInfo {
    use SuperscalarInstructionType as Sit;
    match t {
        Sit::ISubR => &INFO_ISUB_R,
        Sit::IXorR => &INFO_IXOR_R,
        Sit::IAddRs => &INFO_IADD_RS,
        Sit::IMulR => &INFO_IMUL_R,
        Sit::IRorC => &INFO_IROR_C,
        Sit::IAddC7 => &INFO_IADD_C7,
        Sit::IXorC7 => &INFO_IXOR_C7,
        Sit::IAddC8 => &INFO_IADD_C8,
        Sit::IXorC8 => &INFO_IXOR_C8,
        Sit::IAddC9 => &INFO_IADD_C9,
        Sit::IXorC9 => &INFO_IXOR_C9,
        Sit::IMulhR => &INFO_IMULH_R,
        Sit::ISMulhR => &INFO_ISMULH_R,
        Sit::IMulRcp => &INFO_IMUL_RCP,
    }
}

// -----------------------------------------------------------------------------
// Decoder buffers
// -----------------------------------------------------------------------------

/// One of the six decoder configurations per spec §6.3.1 Table 6.3.1
/// / `superscalar.cpp:246-251`. Each lists slot sizes in bytes that
/// sum to 16.
#[derive(Clone, Copy, Debug)]
struct DecoderBuffer {
    /// Slot byte sizes, padded to 4 entries with trailing zeros.
    counts: [u8; 4],
    /// Number of valid leading entries in `counts`.
    len: u8,
    /// `decode_buffers` index used by the IMUL_R special-case in
    /// [`SuperscalarInstructionState::create_for_slot`]; `None` for
    /// the `Default` sentinel (the C reference uses `-1`).
    index: Option<u8>,
}

const DECODE_BUFFER_484: DecoderBuffer = DecoderBuffer {
    counts: [4, 8, 4, 0],
    len: 3,
    index: Some(0),
};
const DECODE_BUFFER_7333: DecoderBuffer = DecoderBuffer {
    counts: [7, 3, 3, 3],
    len: 4,
    index: Some(1),
};
const DECODE_BUFFER_3733: DecoderBuffer = DecoderBuffer {
    counts: [3, 7, 3, 3],
    len: 4,
    index: Some(2),
};
const DECODE_BUFFER_493: DecoderBuffer = DecoderBuffer {
    counts: [4, 9, 3, 0],
    len: 3,
    index: Some(3),
};
const DECODE_BUFFER_4444: DecoderBuffer = DecoderBuffer {
    counts: [4, 4, 4, 4],
    len: 4,
    index: Some(4),
};
const DECODE_BUFFER_3310: DecoderBuffer = DecoderBuffer {
    counts: [3, 3, 10, 0],
    len: 3,
    index: Some(5),
};

/// Default-pool of 4 decoder buffers, indexed by `getByte() & 3`
/// (per spec-silence audit row 4).
const DECODE_BUFFER_POOL: [&DecoderBuffer; 4] = [
    &DECODE_BUFFER_484,
    &DECODE_BUFFER_7333,
    &DECODE_BUFFER_3733,
    &DECODE_BUFFER_493,
];

impl DecoderBuffer {
    fn count_at(&self, i: usize) -> u8 {
        self.counts[i]
    }

    fn len(&self) -> usize {
        self.len as usize
    }

    /// Select the next decoder buffer based on the previous
    /// instruction type, the current decoding cycle, and the running
    /// multiplication count. Matches `superscalar.cpp:271-289`.
    fn fetch_next(
        instr_type: Option<SuperscalarInstructionType>,
        cycle: usize,
        mul_count: usize,
        gen: &mut Blake2Generator,
    ) -> &'static DecoderBuffer {
        // If the previous instruction was IMULH_R or ISMULH_R the
        // next decode group is 3-3-10.
        if matches!(
            instr_type,
            Some(SuperscalarInstructionType::IMulhR | SuperscalarInstructionType::ISMulhR)
        ) {
            return &DECODE_BUFFER_3310;
        }
        // To saturate the multiplication port, generate a 4-4-4-4
        // configuration if multiplication count is lower than cycle.
        // `cycle < RANDOMX_SUPERSCALAR_LATENCY (170)` and `mul_count`
        // is bounded by the program-size cap (512), so the add cannot
        // overflow `usize`.
        if mul_count < cycle + 1 {
            return &DECODE_BUFFER_4444;
        }
        // If the previous instruction was IMUL_RCP, the next buffer
        // must begin with a 4-byte slot for multiplication.
        if matches!(instr_type, Some(SuperscalarInstructionType::IMulRcp)) {
            return if gen.get_byte() & 1 == 1 {
                &DECODE_BUFFER_484
            } else {
                &DECODE_BUFFER_493
            };
        }
        // Default: random selection from groups 0-3.
        DECODE_BUFFER_POOL[(gen.get_byte() & 0b11) as usize]
    }
}

// -----------------------------------------------------------------------------
// Slot → instruction-type pickers
// -----------------------------------------------------------------------------

const SLOT_3: [SuperscalarInstructionType; 2] = [
    SuperscalarInstructionType::ISubR,
    SuperscalarInstructionType::IXorR,
];

const SLOT_3_LAST: [SuperscalarInstructionType; 4] = [
    SuperscalarInstructionType::ISubR,
    SuperscalarInstructionType::IXorR,
    SuperscalarInstructionType::IMulhR,
    SuperscalarInstructionType::ISMulhR,
];

const SLOT_4: [SuperscalarInstructionType; 2] = [
    SuperscalarInstructionType::IRorC,
    SuperscalarInstructionType::IAddRs,
];

const SLOT_7: [SuperscalarInstructionType; 2] = [
    SuperscalarInstructionType::IXorC7,
    SuperscalarInstructionType::IAddC7,
];

const SLOT_8: [SuperscalarInstructionType; 2] = [
    SuperscalarInstructionType::IXorC8,
    SuperscalarInstructionType::IAddC8,
];

const SLOT_9: [SuperscalarInstructionType; 2] = [
    SuperscalarInstructionType::IXorC9,
    SuperscalarInstructionType::IAddC9,
];

const SLOT_10: SuperscalarInstructionType = SuperscalarInstructionType::IMulRcp;

// -----------------------------------------------------------------------------
// Register-info + register selection
// -----------------------------------------------------------------------------

/// Per-register state tracked by the CPU simulator (cycle at which
/// the register's value will be ready, plus the last-operation
/// "group" and "parameter" used by the operand-assignment rules).
///
/// The C reference's `latency` is `int` and `lastOpPar` is `int`
/// with the sentinel `-1`; the Rust port uses `usize` for the
/// always-non-negative cycle counter and `Option<u32>` for the
/// parameter (which stores either a register index in `0..=7` or a
/// 32-bit immediate from `get_uint32()`).
#[derive(Clone, Copy, Debug)]
struct RegisterInfo {
    latency: usize,
    last_op_group: Option<SuperscalarInstructionType>,
    last_op_par: Option<u32>,
}

impl RegisterInfo {
    const INITIAL: Self = Self {
        latency: 0,
        last_op_group: None,
        last_op_par: None,
    };
}

/// Select one register at random from `available` (which is a
/// monotone-shrinking vec of available register indices). Matches
/// `superscalar.cpp:332-345 selectRegister`.
fn select_register(available: &[u8], gen: &mut Blake2Generator) -> Option<u8> {
    if available.is_empty() {
        return None;
    }
    let index = if available.len() > 1 {
        gen.get_uint32() as usize % available.len()
    } else {
        0
    };
    Some(available[index])
}

// -----------------------------------------------------------------------------
// In-flight instruction state during generation
// -----------------------------------------------------------------------------

/// State carried per in-flight instruction during generation.
/// Mirrors `superscalar.cpp:357-578 SuperscalarInstruction`. The
/// final per-program record is [`SuperscalarInstruction`].
///
/// The C reference uses `int` for `src`/`dst` (with the sentinel
/// `-1` for "unassigned") and `int` for `opGroupPar` (with either
/// `-1`, a register index `0..=7`, or a 32-bit immediate from
/// `getUInt32()` reinterpreted as signed). The Rust port replaces
/// these with `Option<u8>` and `Option<u32>` per workspace clippy
/// discipline.
#[derive(Clone, Copy, Debug)]
struct SuperscalarInstructionState {
    info: &'static InstructionInfo,
    instr_type: Option<SuperscalarInstructionType>,
    src: Option<u8>,
    dst: Option<u8>,
    mod_: u8,
    imm32: u32,
    op_group: Option<SuperscalarInstructionType>,
    op_group_par: Option<u32>,
    can_reuse: bool,
    group_par_is_source: bool,
}

impl SuperscalarInstructionState {
    const NULL: Self = Self {
        info: &INFO_NOP,
        instr_type: None,
        src: None,
        dst: None,
        mod_: 0,
        imm32: 0,
        op_group: None,
        op_group_par: None,
        can_reuse: false,
        group_par_is_source: false,
    };

    /// Per `superscalar.cpp:367-403 createForSlot`. `slot_size` and
    /// `fetch_type` come from the active decoder buffer (the latter
    /// matters only when checking for the 4-4-4-4 buffer where
    /// `fetch_type == Some(4)`); `is_last` is "this is the last slot
    /// in the buffer."
    fn create_for_slot(
        &mut self,
        gen: &mut Blake2Generator,
        slot_size: u8,
        fetch_type: Option<u8>,
        is_last: bool,
    ) {
        let t = match slot_size {
            3 => {
                if is_last {
                    SLOT_3_LAST[(gen.get_byte() & 0b11) as usize]
                } else {
                    SLOT_3[(gen.get_byte() & 0b01) as usize]
                }
            }
            4 => {
                if fetch_type == Some(4) && !is_last {
                    SuperscalarInstructionType::IMulR
                } else {
                    SLOT_4[(gen.get_byte() & 0b01) as usize]
                }
            }
            7 => SLOT_7[(gen.get_byte() & 0b01) as usize],
            8 => SLOT_8[(gen.get_byte() & 0b01) as usize],
            9 => SLOT_9[(gen.get_byte() & 0b01) as usize],
            10 => SLOT_10,
            _ => unreachable!("DecoderBuffer slot sizes are {{3,4,7,8,9,10}}"),
        };
        self.create(t, gen);
    }

    /// Per `superscalar.cpp:405-493 create`. Sets per-type parameters
    /// (`mod_`, `imm32`, `op_group`, `op_group_par`, `can_reuse`,
    /// `group_par_is_source`) and clears `src`/`dst`.
    fn create(&mut self, t: SuperscalarInstructionType, gen: &mut Blake2Generator) {
        use SuperscalarInstructionType as Sit;
        self.info = info_for(t);
        self.instr_type = Some(t);
        self.src = None;
        self.dst = None;
        self.mod_ = 0;
        self.imm32 = 0;
        self.op_group = None;
        self.op_group_par = None;
        self.can_reuse = false;
        self.group_par_is_source = false;

        match t {
            Sit::ISubR => {
                self.op_group = Some(Sit::IAddRs);
                self.group_par_is_source = true;
            }
            Sit::IXorR => {
                self.op_group = Some(Sit::IXorR);
                self.group_par_is_source = true;
            }
            Sit::IAddRs => {
                self.mod_ = gen.get_byte();
                self.op_group = Some(Sit::IAddRs);
                self.group_par_is_source = true;
            }
            Sit::IMulR => {
                self.op_group = Some(Sit::IMulR);
                self.group_par_is_source = true;
            }
            Sit::IRorC => {
                loop {
                    let v = u32::from(gen.get_byte() & 63);
                    if v != 0 {
                        self.imm32 = v;
                        break;
                    }
                }
                self.op_group = Some(Sit::IRorC);
            }
            Sit::IAddC7 | Sit::IAddC8 | Sit::IAddC9 => {
                self.imm32 = gen.get_uint32();
                self.op_group = Some(Sit::IAddC7);
            }
            Sit::IXorC7 | Sit::IXorC8 | Sit::IXorC9 => {
                self.imm32 = gen.get_uint32();
                self.op_group = Some(Sit::IXorC7);
            }
            Sit::IMulhR => {
                self.can_reuse = true;
                self.op_group = Some(Sit::IMulhR);
                self.op_group_par = Some(gen.get_uint32());
            }
            Sit::ISMulhR => {
                self.can_reuse = true;
                self.op_group = Some(Sit::ISMulhR);
                self.op_group_par = Some(gen.get_uint32());
            }
            Sit::IMulRcp => {
                loop {
                    let v = gen.get_uint32();
                    if !is_zero_or_power_of_2(u64::from(v)) {
                        self.imm32 = v;
                        break;
                    }
                }
                self.op_group = Some(Sit::IMulRcp);
            }
        }
    }

    /// Per `superscalar.cpp:495-514 selectDestination`. Returns
    /// whether a destination was selected (and stores it in
    /// `self.dst`).
    fn select_destination(
        &mut self,
        cycle: usize,
        allow_chained_mul: bool,
        registers: &[RegisterInfo; REGISTERS_COUNT],
        gen: &mut Blake2Generator,
    ) -> bool {
        let mut available = [0u8; REGISTERS_COUNT];
        let mut n = 0usize;
        for (i, r) in registers.iter().enumerate() {
            // Destination conditions (see C reference comment block
            // lines 499-508):
            //  * value must be ready at the required cycle
            //  * cannot be the same as the source register unless
            //    can_reuse
            //  * register cannot be multiplied twice in a row unless
            //    allow_chained_mul (and op_group == IMUL_R)
            //  * the last instruction applied to the register or its
            //    source must be different than this instruction
            //  * register r5 cannot be the destination of IADD_RS
            let i_u8 = REG_INDEX_AS_U8[i];
            let cond_ready = r.latency <= cycle;
            // When `src` is `None` (no source register) the
            // distinctness check is vacuous, matching the C
            // semantics where `i != src_` with `src_ = -1` is always
            // true for unsigned `i`.
            let cond_distinct = self.can_reuse || self.src.is_none_or(|s| i_u8 != s);
            let cond_no_chained_mul = allow_chained_mul
                || self.op_group != Some(SuperscalarInstructionType::IMulR)
                || r.last_op_group != Some(SuperscalarInstructionType::IMulR);
            let cond_op_diff =
                r.last_op_group != self.op_group || r.last_op_par != self.op_group_par;
            let cond_not_r5_for_iadd_rs = self.instr_type
                != Some(SuperscalarInstructionType::IAddRs)
                || i_u8 != REGISTER_NEEDS_DISPLACEMENT;
            if cond_ready
                && cond_distinct
                && cond_no_chained_mul
                && cond_op_diff
                && cond_not_r5_for_iadd_rs
            {
                available[n] = i_u8;
                n += 1;
            }
        }
        match select_register(&available[..n], gen) {
            Some(reg) => {
                self.dst = Some(reg);
                true
            }
            None => false,
        }
    }

    /// Per `superscalar.cpp:516-536 selectSource`.
    fn select_source(
        &mut self,
        cycle: usize,
        registers: &[RegisterInfo; REGISTERS_COUNT],
        gen: &mut Blake2Generator,
    ) -> bool {
        let mut available = [0u8; REGISTERS_COUNT];
        let mut n = 0usize;
        for (i, r) in registers.iter().enumerate() {
            if r.latency <= cycle {
                available[n] = REG_INDEX_AS_U8[i];
                n += 1;
            }
        }
        // Spec-silence audit row 7: if there are exactly 2 available
        // registers for IADD_RS and one of them is r5, force r5 as
        // the source so the other can be the destination.
        if n == 2
            && self.instr_type == Some(SuperscalarInstructionType::IAddRs)
            && (available[0] == REGISTER_NEEDS_DISPLACEMENT
                || available[1] == REGISTER_NEEDS_DISPLACEMENT)
        {
            self.src = Some(REGISTER_NEEDS_DISPLACEMENT);
            self.op_group_par = Some(u32::from(REGISTER_NEEDS_DISPLACEMENT));
            return true;
        }
        match select_register(&available[..n], gen) {
            Some(reg) => {
                self.src = Some(reg);
                if self.group_par_is_source {
                    self.op_group_par = Some(u32::from(reg));
                }
                true
            }
            None => false,
        }
    }

    /// Per `superscalar.cpp:359-365 toInstr`. Translate the in-flight
    /// state into the per-program [`SuperscalarInstruction`] record.
    fn into_instruction(self) -> SuperscalarInstruction {
        let t = self
            .instr_type
            .expect("into_instruction called on NULL instruction state");
        let dst = self
            .dst
            .expect("into_instruction called before dst was assigned");
        // `src` falls back to `dst` for instructions with no source
        // register (immediate-only), matching `toInstr`.
        let src = self.src.unwrap_or(dst);
        SuperscalarInstruction {
            opcode: t as u8,
            dst,
            src,
            mod_: self.mod_,
            imm32: self.imm32,
        }
    }
}

/// Precomputed `i as u8` table for `0..REGISTERS_COUNT`. Hoisted to
/// avoid the `cast_possible_truncation` lint at every loop body.
const REG_INDEX_AS_U8: [u8; REGISTERS_COUNT] = [0, 1, 2, 3, 4, 5, 6, 7];

/// `REGISTERS_COUNT` projected into `u8` for bounds checks in tests.
/// Defined as a literal to avoid the workspace-deny
/// `cast_possible_truncation` lint on `REGISTERS_COUNT as u8`. The
/// `const _` assert keeps the two in sync.
const REGISTERS_COUNT_U8: u8 = 8;
const _: () = {
    assert!(REGISTERS_COUNT_U8 as usize == REGISTERS_COUNT);
    assert!(REG_INDEX_AS_U8.len() == REGISTERS_COUNT);
};

const fn is_zero_or_power_of_2(x: u64) -> bool {
    // Per common.hpp:170-172 isZeroOrPowerOf2.
    (x & x.wrapping_sub(1)) == 0
}

// -----------------------------------------------------------------------------
// Port scheduling
// -----------------------------------------------------------------------------

/// Schedule a single uOP on the first available port at or after
/// `cycle`. Matches `superscalar.cpp:587-614 scheduleUop`. Port-check
/// order is P5 → P0 → P1 per spec §6.3.3.
fn schedule_uop(
    uop: ExecutionPort,
    port_busy: &mut PortBusy,
    mut cycle: usize,
    commit: bool,
) -> Option<usize> {
    while cycle < CYCLE_MAP_SIZE {
        if uop.contains(ExecutionPort::P5) && !port_busy[cycle][2] {
            if commit {
                port_busy[cycle][2] = true;
            }
            return Some(cycle);
        }
        if uop.contains(ExecutionPort::P0) && !port_busy[cycle][0] {
            if commit {
                port_busy[cycle][0] = true;
            }
            return Some(cycle);
        }
        if uop.contains(ExecutionPort::P1) && !port_busy[cycle][1] {
            if commit {
                port_busy[cycle][1] = true;
            }
            return Some(cycle);
        }
        cycle += 1;
    }
    None
}

/// Schedule a macro-op (1 or 2 uOPs). Matches
/// `superscalar.cpp:616-651 scheduleMop`.
fn schedule_mop(
    mop: MacroOp,
    port_busy: &mut PortBusy,
    mut cycle: usize,
    dep_cycle: usize,
    commit: bool,
) -> Option<usize> {
    // Explicit dependency chain (IMUL_RCP's Imul_rr).
    if mop.dependent {
        cycle = cycle.max(dep_cycle);
    }
    // Eliminated (move) macro-ops don't need an execution unit.
    if mop.is_eliminated() {
        return Some(cycle);
    }
    if mop.is_simple() {
        return schedule_uop(mop.uop1, port_busy, cycle, commit);
    }
    // Macro-ops with 2 uOPs are scheduled conservatively by requiring
    // both uOPs to execute in the same cycle.
    while cycle < CYCLE_MAP_SIZE {
        let c1 = schedule_uop(mop.uop1, port_busy, cycle, false);
        let c2 = schedule_uop(mop.uop2, port_busy, cycle, false);
        if let (Some(c1), Some(c2)) = (c1, c2) {
            if c1 == c2 {
                if commit {
                    schedule_uop(mop.uop1, port_busy, c1, true);
                    schedule_uop(mop.uop2, port_busy, c2, true);
                }
                return Some(c1);
            }
        }
        cycle += 1;
    }
    None
}

// -----------------------------------------------------------------------------
// Main generator
// -----------------------------------------------------------------------------

/// Generate a [`SuperscalarProgram`] driven by `gen`.
///
/// Per [`specs.md`](../../external/randomx-v2/doc/specs.md) §6 and
/// `superscalar.cpp:653-854 generateSuperscalar`.
///
/// The CPU-simulation loop iterates for at most
/// [`RANDOMX_SUPERSCALAR_LATENCY`] decoding cycles or until execution
/// ports are saturated (whichever comes first), driven by 4 phases
/// per §6.3:
///
/// 1. **Decoding stage:** select the next decoder buffer
///    (`fetch_next`) producing 3-4 macro-op slots summing to 16 bytes.
/// 2. **Instruction selection:** pick an instruction type appropriate
///    for each slot's byte size.
/// 3. **Port assignment:** schedule each macro-op's uOPs on the
///    earliest available execution port (`schedule_mop`).
/// 4. **Operand assignment:** select source and destination registers
///    subject to the §6.3.4 dependency / availability rules.
///
/// The final pass walks the generated instructions to compute ASIC
/// latencies (1 cycle per op, unlimited parallelism) and identifies
/// the register with the longest dependency chain — that register's
/// index is stored as `address_register` and used by §7.3 step 7.
///
/// # REMOVE WHEN PHASE 2e WIRES THIS:
///
/// Phase 2e (`Cache::derive`) is the production caller; 8 programs are
/// generated from a single `Blake2Generator` seeded from key `K` per
/// §7.2 to produce the Dataset.
#[allow(dead_code)]
pub(crate) fn generate_superscalar(gen: &mut Blake2Generator) -> SuperscalarProgram {
    let mut prog = SuperscalarProgram::new();
    let mut port_busy: PortBusy = [[false; 3]; CYCLE_MAP_SIZE];
    let mut registers = [RegisterInfo::INITIAL; REGISTERS_COUNT];

    let mut current = SuperscalarInstructionState::NULL;
    let mut macro_op_index: usize = 0;
    let mut cycle: usize = 0;
    let mut dep_cycle: usize = 0;
    let mut ports_saturated = false;
    let mut program_size: usize = 0;
    let mut mul_count: usize = 0;
    let mut throw_away_count: usize = 0;

    let mut decode_cycle: usize = 0;
    while decode_cycle < RANDOMX_SUPERSCALAR_LATENCY
        && !ports_saturated
        && program_size < SUPERSCALAR_MAX_SIZE
    {
        // Phase 1: select decode configuration.
        let decode_buffer =
            DecoderBuffer::fetch_next(current.instr_type, decode_cycle, mul_count, gen);

        let mut buffer_index = 0;
        while buffer_index < decode_buffer.len() {
            let top_cycle = cycle;

            // If we have issued all macro-ops for the current
            // RandomX instruction, create a new instruction.
            if macro_op_index >= current.info.seq.len() {
                if ports_saturated || program_size >= SUPERSCALAR_MAX_SIZE {
                    break;
                }
                let is_last = decode_buffer.len() == buffer_index + 1;
                current.create_for_slot(
                    gen,
                    decode_buffer.count_at(buffer_index),
                    decode_buffer.index,
                    is_last,
                );
                macro_op_index = 0;
            }

            let mop = current.info.seq.op(macro_op_index);
            let macro_op_index_u8 = u8::try_from(macro_op_index)
                .expect("macro_op_index < seq.len() <= 3 by construction");

            // Earliest cycle this macro-op can be scheduled (dry-run).
            let Some(mut schedule_cycle) =
                schedule_mop(mop, &mut port_busy, cycle, dep_cycle, false)
            else {
                ports_saturated = true;
                break;
            };

            // Source-register selection (if this is the src-bearing
            // macro-op).
            if current.info.src_op == Some(macro_op_index_u8) {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_source(schedule_cycle, &registers, gen)
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.seq.len();
                        continue;
                    }
                    current = SuperscalarInstructionState::NULL;
                    break;
                }
            }

            // Destination-register selection.
            if current.info.dst_op == Some(macro_op_index_u8) {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_destination(
                        schedule_cycle,
                        throw_away_count > 0,
                        &registers,
                        gen,
                    )
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.seq.len();
                        continue;
                    }
                    current = SuperscalarInstructionState::NULL;
                    break;
                }
            }
            throw_away_count = 0;

            // Commit-pass scheduling. The dep_cycle override
            // matches C: `scheduleMop<true>(mop, portBusy,
            // scheduleCycle, scheduleCycle)`.
            let Some(schedule_cycle) =
                schedule_mop(mop, &mut port_busy, schedule_cycle, schedule_cycle, true)
            else {
                ports_saturated = true;
                break;
            };

            dep_cycle = schedule_cycle + usize::from(mop.latency);

            // If this macro-op writes the result, update register
            // info.
            if current.info.result_op == Some(macro_op_index_u8) {
                let dst = usize::from(current.dst.expect("dst assigned before result_op macro-op"));
                registers[dst].latency = dep_cycle;
                registers[dst].last_op_group = current.op_group;
                registers[dst].last_op_par = current.op_group_par;
            }

            buffer_index += 1;
            macro_op_index += 1;

            // Terminating condition.
            if schedule_cycle >= RANDOMX_SUPERSCALAR_LATENCY {
                ports_saturated = true;
            }
            cycle = top_cycle;

            // When all macro-ops of the current instruction have
            // been issued, append the instruction to the program.
            if macro_op_index >= current.info.seq.len() {
                prog.instructions[program_size] = current.into_instruction();
                program_size += 1;
                if current
                    .instr_type
                    .is_some_and(SuperscalarInstructionType::is_multiplication)
                {
                    mul_count += 1;
                }
            }
        }
        cycle += 1;
        decode_cycle += 1;
    }

    // Compute ASIC latencies (1 cycle / op; unlimited parallelism)
    // per superscalar.cpp:810-817. The address register is the one
    // with the highest ASIC latency.
    let mut asic_latencies = [0usize; REGISTERS_COUNT];
    for instr in &prog.instructions[..program_size] {
        let dst = usize::from(instr.dst);
        let src = usize::from(instr.src);
        let lat_dst = asic_latencies[dst] + 1;
        let lat_src = if instr.dst != instr.src {
            asic_latencies[src] + 1
        } else {
            0
        };
        asic_latencies[dst] = lat_dst.max(lat_src);
    }
    let mut asic_latency_max = 0usize;
    let mut address_reg = 0u8;
    for (i, &lat) in asic_latencies.iter().enumerate() {
        if lat > asic_latency_max {
            asic_latency_max = lat;
            address_reg = REG_INDEX_AS_U8[i];
        }
    }

    prog.size = program_size;
    prog.address_register = address_reg;
    prog
}

// -----------------------------------------------------------------------------
// Executor
// -----------------------------------------------------------------------------

/// Execute a generated [`SuperscalarProgram`] over `registers`.
/// Mirrors `superscalar.cpp:856-902 executeSuperscalar`.
///
/// The `reciprocals` parameter from the C reference is omitted in
/// the Rust port: the C signature accepts an optional pre-computed
/// `Vec<uint64_t>` cache, but the cached values are identical to the
/// on-the-fly [`randomx_reciprocal`] computation and the
/// pre-computation is a JIT-side optimization that has no role in
/// the interpreter-only Phase 2 stack.
///
/// # REMOVE WHEN PHASE 2e WIRES THIS:
///
/// Phase 2e (`Cache::derive`) is the production caller per spec
/// §7.3 step 5: `SuperscalarHash[i](r0..r7)` modifies the registers
/// in place.
#[allow(dead_code)]
pub(crate) fn execute_superscalar(
    program: &SuperscalarProgram,
    registers: &mut [u64; REGISTERS_COUNT],
) {
    for instr in program.instructions() {
        let dst = usize::from(instr.dst);
        let src = usize::from(instr.src);
        let t = SuperscalarInstructionType::from_opcode(instr.opcode)
            .expect("opcode in 0..=13 by construction in generate_superscalar");
        use SuperscalarInstructionType as Sit;
        match t {
            Sit::ISubR => registers[dst] = registers[dst].wrapping_sub(registers[src]),
            Sit::IXorR => registers[dst] ^= registers[src],
            Sit::IAddRs => {
                let shift = instr.mod_shift();
                registers[dst] = registers[dst].wrapping_add(registers[src].wrapping_shl(shift));
            }
            Sit::IMulR => registers[dst] = registers[dst].wrapping_mul(registers[src]),
            Sit::IRorC => registers[dst] = registers[dst].rotate_right(instr.imm32 % 64),
            Sit::IAddC7 | Sit::IAddC8 | Sit::IAddC9 => {
                registers[dst] = registers[dst].wrapping_add(sign_extend_2s_compl(instr.imm32));
            }
            Sit::IXorC7 | Sit::IXorC8 | Sit::IXorC9 => {
                registers[dst] ^= sign_extend_2s_compl(instr.imm32);
            }
            Sit::IMulhR => registers[dst] = mulh(registers[dst], registers[src]),
            Sit::ISMulhR => {
                registers[dst] = smulh_u64(registers[dst], registers[src]);
            }
            Sit::IMulRcp => {
                registers[dst] = registers[dst].wrapping_mul(randomx_reciprocal(instr.imm32));
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Helper arithmetic primitives
// -----------------------------------------------------------------------------

/// Sign-extend a 32-bit two's-complement immediate to 64 bits.
/// Matches `intrin_portable.h:42-44 signExtend2sCompl`.
///
/// The casts reinterpret the input as a signed value and propagate
/// the sign bit; both the C reference and the spec language treat
/// IMM32 as a two's-complement signed quantity in this context.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
const fn sign_extend_2s_compl(x: u32) -> u64 {
    (x as i32) as i64 as u64
}

/// High 64 bits of the unsigned 128-bit product of two 64-bit
/// values. Matches `instructions_portable.cpp:64-67 mulh`.
///
/// `u64 -> u128` widening is lossless; the `>>` produces a value in
/// `0..2^64` which casts back to `u64` without truncation. Not
/// `const fn` because `u128::From` is not yet stable as a const
/// trait (rust-lang/rust#143874); call sites are runtime-only.
#[allow(clippy::cast_possible_truncation)]
fn mulh(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) >> 64) as u64
}

/// High 64 bits of the signed 128-bit product of two 64-bit values.
/// Matches `instructions_portable.cpp:71-74 smulh`.
///
/// `i64 -> i128` widening is lossless; the `>>` produces a value
/// representable in `i64`. Not `const fn` for the same reason as
/// [`mulh`].
#[allow(clippy::cast_possible_truncation)]
fn smulh(a: i64, b: i64) -> i64 {
    ((i128::from(a) * i128::from(b)) >> 64) as i64
}

/// `smulh` wrapper that takes/returns `u64`, reinterpreting the
/// inputs and output as two's-complement. Hoisted out of
/// [`execute_superscalar`] so the `#[allow]` for the intentional
/// reinterpretation has the smallest possible scope.
///
/// Matches the C reference's `r[dst] = smulh((int64_t)r[dst],
/// (int64_t)r[src])` pattern from `superscalar.cpp:888`.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn smulh_u64(a: u64, b: u64) -> u64 {
    smulh(a as i64, b as i64) as u64
}

/// `randomx_reciprocal`: compute `2^x / divisor` for the highest `x`
/// such that the result fits in 64 bits. Matches
/// `reciprocal.c:47-64 randomx_reciprocal`.
///
/// Preconditions (per the C `assert`): `divisor != 0`. The
/// SuperscalarHash generator additionally guarantees `divisor` is
/// not a power of 2 (see [`SuperscalarInstructionState::create`]).
fn randomx_reciprocal(divisor: u32) -> u64 {
    debug_assert!(divisor != 0, "randomx_reciprocal divisor must be nonzero");
    let p2_exp63: u64 = 1u64 << 63;
    let divisor_u64 = u64::from(divisor);
    let q = p2_exp63 / divisor_u64;
    let r = p2_exp63 % divisor_u64;
    // `64 - clz(divisor)`: position of the MSB + 1. divisor is
    // nonzero so clz < 64; shift < 64.
    let shift = 64 - divisor_u64.leading_zeros();
    q.wrapping_shl(shift)
        .wrapping_add(r.wrapping_shl(shift) / divisor_u64)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomx_reciprocal_matches_c_test_vectors() {
        // Vectors from external/randomx-v2/src/tests/tests.cpp:117-124.
        assert_eq!(randomx_reciprocal(3), 12_297_829_382_473_034_410);
        assert_eq!(randomx_reciprocal(13), 11_351_842_506_898_185_609);
        assert_eq!(randomx_reciprocal(33), 17_887_751_829_051_686_415);
        assert_eq!(randomx_reciprocal(65537), 18_446_462_603_027_742_720);
        assert_eq!(randomx_reciprocal(15_000_001), 10_316_166_306_300_415_204);
        assert_eq!(
            randomx_reciprocal(3_845_182_035),
            10_302_264_209_224_146_340
        );
        assert_eq!(randomx_reciprocal(0xffff_ffff), 9_223_372_039_002_259_456);
    }

    #[test]
    fn sign_extend_2s_compl_round_trip() {
        assert_eq!(sign_extend_2s_compl(0x0000_0000), 0x0000_0000_0000_0000);
        assert_eq!(sign_extend_2s_compl(0x7fff_ffff), 0x0000_0000_7fff_ffff);
        assert_eq!(sign_extend_2s_compl(0x8000_0000), 0xffff_ffff_8000_0000);
        assert_eq!(sign_extend_2s_compl(0xffff_ffff), 0xffff_ffff_ffff_ffff);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn mulh_and_smulh_agree_with_widening_multiplication() {
        // Cross-check by recomputing via 128-bit widening.
        for &(a, b) in &[(0u64, 0u64), (1, 1), (u64::MAX, u64::MAX), (1 << 63, 2)] {
            assert_eq!(mulh(a, b), ((u128::from(a) * u128::from(b)) >> 64) as u64);
        }
        for &(a, b) in &[(0i64, 0i64), (-1, -1), (i64::MIN, 2), (1 << 62, -2)] {
            assert_eq!(smulh(a, b), ((i128::from(a) * i128::from(b)) >> 64) as i64);
        }
    }

    #[test]
    fn is_zero_or_power_of_2_table() {
        assert!(is_zero_or_power_of_2(0));
        assert!(is_zero_or_power_of_2(1));
        assert!(is_zero_or_power_of_2(2));
        assert!(is_zero_or_power_of_2(4));
        assert!(is_zero_or_power_of_2(1 << 32));
        assert!(is_zero_or_power_of_2(1 << 63));
        assert!(!is_zero_or_power_of_2(3));
        assert!(!is_zero_or_power_of_2(5));
        assert!(!is_zero_or_power_of_2(0xffff_ffff));
    }

    #[test]
    fn generated_program_is_within_size_bounds() {
        let mut gen = Blake2Generator::new(&[], 0);
        let prog = generate_superscalar(&mut gen);
        let n = prog.size();
        // Per superscalar.cpp termination conditions: program never
        // exceeds SUPERSCALAR_MAX_SIZE, and it terminates well before
        // that in practice (port saturation kicks in first). The
        // lower bound is not specified by the spec but a degenerate
        // empty program would indicate a wiring failure; SS-hash
        // programs in practice contain hundreds of instructions.
        assert!(n > 0, "program size must be > 0");
        assert!(
            n <= SUPERSCALAR_MAX_SIZE,
            "program size {n} exceeds SUPERSCALAR_MAX_SIZE = {SUPERSCALAR_MAX_SIZE}",
        );
    }

    #[test]
    fn generated_program_has_valid_register_indices() {
        let mut gen = Blake2Generator::new(b"shekyl-ss-test", 0);
        let prog = generate_superscalar(&mut gen);
        for instr in prog.instructions() {
            assert!(instr.dst < REGISTERS_COUNT_U8);
            assert!(instr.src < REGISTERS_COUNT_U8);
            assert!(instr.opcode < 14);
            // IADD_RS rule: dst != r5.
            if instr.opcode == SuperscalarInstructionType::IAddRs as u8 {
                assert_ne!(
                    instr.dst, REGISTER_NEEDS_DISPLACEMENT,
                    "IADD_RS dst must not be r5",
                );
            }
            // IROR_C rule: imm32 & 63 != 0.
            if instr.opcode == SuperscalarInstructionType::IRorC as u8 {
                assert_ne!(instr.imm32 % 64, 0, "IROR_C rotation count must be nonzero");
            }
            // IMUL_RCP rule: imm32 != 0 and not a power of 2.
            if instr.opcode == SuperscalarInstructionType::IMulRcp as u8 {
                assert_ne!(instr.imm32, 0);
                assert!(!is_zero_or_power_of_2(u64::from(instr.imm32)));
            }
        }
    }

    #[test]
    fn address_register_in_range() {
        let mut gen = Blake2Generator::new(&[0x01], 42);
        let prog = generate_superscalar(&mut gen);
        assert!(prog.address_register() < REGISTERS_COUNT_U8);
    }

    #[test]
    fn execute_then_re_execute_is_deterministic() {
        let mut gen = Blake2Generator::new(b"shekyl-ss-test", 0);
        let prog = generate_superscalar(&mut gen);
        let mut r1 = [0u64, 1, 2, 3, 4, 5, 6, 7];
        let mut r2 = r1;
        execute_superscalar(&prog, &mut r1);
        execute_superscalar(&prog, &mut r2);
        assert_eq!(r1, r2);
    }

    #[test]
    fn execute_diffuses_uniform_input_to_non_uniform_output() {
        let mut gen = Blake2Generator::new(b"shekyl-ss-test", 0);
        let prog = generate_superscalar(&mut gen);
        let mut r = [0x0123_4567_89ab_cdefu64; REGISTERS_COUNT];
        execute_superscalar(&prog, &mut r);
        // After hundreds of mixing instructions, no two registers
        // should be equal.
        for i in 0..REGISTERS_COUNT {
            for j in (i + 1)..REGISTERS_COUNT {
                assert_ne!(r[i], r[j], "registers {i} and {j} collided");
            }
        }
    }

    #[test]
    fn different_seeds_produce_different_programs() {
        let mut g1 = Blake2Generator::new(b"seed-a", 0);
        let mut g2 = Blake2Generator::new(b"seed-b", 0);
        let p1 = generate_superscalar(&mut g1);
        let p2 = generate_superscalar(&mut g2);
        // Programs may match in size by accident but the instruction
        // stream must differ. Compare the first N instructions.
        let n = p1.size().min(p2.size()).min(16);
        assert!(n > 0);
        let diff = (0..n).any(|i| p1.instructions()[i] != p2.instructions()[i]);
        assert!(
            diff,
            "two distinct seeds produced identical instruction prefixes"
        );
    }

    #[test]
    fn different_nonces_produce_different_programs() {
        let mut g1 = Blake2Generator::new(&[], 0);
        let mut g2 = Blake2Generator::new(&[], 1);
        let p1 = generate_superscalar(&mut g1);
        let p2 = generate_superscalar(&mut g2);
        let n = p1.size().min(p2.size()).min(16);
        assert!(n > 0);
        let diff = (0..n).any(|i| p1.instructions()[i] != p2.instructions()[i]);
        assert!(
            diff,
            "two distinct nonces produced identical instruction prefixes"
        );
    }

    // ============================================================
    // Spec-vector parity tests (Phase 2b commit 5)
    // ============================================================
    //
    // Byte-for-byte parity against the v2 RandomX fork's reference
    // (`external/randomx-v2/`, pin `aaafe71`) per
    // `docs/design/RANDOMX_V2_PHASE2B_PLAN.md` §5.4 (F4 structured
    // 3-vector decomposition). The `.bin` reference vectors live
    // under `tests/vectors/reference/superscalar/` and are
    // reproducible via `tests/vectors/reference/superscalar/_generator/`
    // (see that directory's `README.md` for the build / regeneration
    // procedure).
    //
    // The wire format for serialized programs is documented in
    // `_generator/README.md` "Wire format" and is reproduced here in
    // the [`serialize_program`] / [`deserialize_program`] helpers.
    // The format is intentionally fixed-cost-per-instruction (8 bytes,
    // mirroring `SuperscalarInstruction`'s declared layout) so any
    // cross-component disagreement on instruction encoding surfaces
    // as a byte diff at a predictable offset rather than as an opaque
    // hash mismatch.

    /// Fixed Layer B input applied to all three generated programs.
    /// Mirrors `_generator/gen.cpp`'s `r[8] = {0, 1, 2, 3, 4, 5, 6, 7}`
    /// initialization at the `emit_layer_b` call site.
    const LAYER_B_INPUT_R: [u64; REGISTERS_COUNT] = [0, 1, 2, 3, 4, 5, 6, 7];

    /// Wire-format magic for a serialized [`SuperscalarProgram`]. ASCII
    /// "SSP1" pins the format version; any future drift (e.g., metadata
    /// expansion) is caught at the deserializer's assertion site.
    const SSP_MAGIC: &[u8; 4] = b"SSP1";

    /// Serialize a program in the canonical wire format. Used by Layer
    /// A tests to compare against the committed `.bin` bytes.
    fn serialize_program(prog: &SuperscalarProgram) -> Vec<u8> {
        let size = prog.size();
        assert!(size <= SUPERSCALAR_MAX_SIZE);
        let size_u16 = u16::try_from(size).expect("size fits in u16");
        let mut buf = Vec::with_capacity(8 + size * 8);
        buf.extend_from_slice(SSP_MAGIC);
        buf.extend_from_slice(&size_u16.to_le_bytes());
        buf.push(prog.address_register());
        buf.push(0); // reserved
        for instr in prog.instructions() {
            buf.push(instr.opcode);
            buf.push(instr.dst);
            buf.push(instr.src);
            buf.push(instr.mod_);
            buf.extend_from_slice(&instr.imm32.to_le_bytes());
        }
        buf
    }

    /// Parse the canonical wire format into a [`SuperscalarProgram`].
    /// Used by Layer B tests to decouple "did we generate the right
    /// program?" (Layer A) from "did we execute correctly?" (Layer B).
    fn deserialize_program(bytes: &[u8]) -> SuperscalarProgram {
        assert!(bytes.len() >= 8, "wire format header is 8 bytes");
        assert_eq!(&bytes[0..4], SSP_MAGIC, "wire-format magic mismatch");
        let size = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        assert!(
            size <= SUPERSCALAR_MAX_SIZE,
            "size exceeds SUPERSCALAR_MAX_SIZE"
        );
        let addr_reg = bytes[6];
        assert!(
            addr_reg < REGISTERS_COUNT_U8,
            "address register out of range"
        );
        assert_eq!(bytes[7], 0, "reserved byte must be 0x00");
        let body_len = size * 8;
        assert_eq!(
            bytes.len(),
            8 + body_len,
            "wire-format body length mismatch"
        );

        let mut prog = SuperscalarProgram::new();
        prog.size = size;
        prog.address_register = addr_reg;
        for i in 0..size {
            let off = 8 + i * 8;
            prog.instructions[i] = SuperscalarInstruction {
                opcode: bytes[off],
                dst: bytes[off + 1],
                src: bytes[off + 2],
                mod_: bytes[off + 3],
                imm32: u32::from_le_bytes([
                    bytes[off + 4],
                    bytes[off + 5],
                    bytes[off + 6],
                    bytes[off + 7],
                ]),
            };
        }
        prog
    }

    /// Decode a Layer B / combined 64-byte register dump.
    fn decode_register_output(bytes: &[u8]) -> [u64; REGISTERS_COUNT] {
        assert_eq!(bytes.len(), 64, "register output is 8 * u64 LE");
        let mut r = [0u64; REGISTERS_COUNT];
        for (i, slot) in r.iter_mut().enumerate() {
            let off = i * 8;
            *slot = u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]);
        }
        r
    }

    // ---- Layer A: program-serialization parity ----

    #[test]
    fn vector_1_layer_a_baseline_determinism() {
        let expected: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_program_seed_empty_nonce_0.bin"
        );
        let mut gen = Blake2Generator::new(&[], 0);
        let prog = generate_superscalar(&mut gen);
        let actual = serialize_program(&prog);
        assert_eq!(
            actual.as_slice(),
            expected,
            "Layer A baseline (seed=empty, nonce=0) diverges from reference",
        );
    }

    #[test]
    fn vector_2_layer_a_tests_nonce_mixing_only() {
        let expected: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_program_seed_empty_nonce_1.bin"
        );
        let mut gen = Blake2Generator::new(&[], 1);
        let prog = generate_superscalar(&mut gen);
        let actual = serialize_program(&prog);
        assert_eq!(
            actual.as_slice(),
            expected,
            "Layer A nonce-mixing isolation (seed=empty, nonce=1) diverges from reference; \
             if vector 1 also fails, the bug is downstream of RNG; if only this fails, \
             the bug is in Blake2Generator nonce handling",
        );
    }

    #[test]
    fn vector_3_layer_a_tests_seed_derivation_only() {
        let expected: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_program_seed_shekyl_nonce_0.bin"
        );
        let mut gen = Blake2Generator::new(b"shekyl-ss-test", 0);
        let prog = generate_superscalar(&mut gen);
        let actual = serialize_program(&prog);
        assert_eq!(
            actual.as_slice(),
            expected,
            "Layer A seed-derivation isolation (seed=shekyl-ss-test, nonce=0) diverges \
             from reference; if vector 1 also fails, the bug is downstream of RNG; if \
             only this fails, the bug is in Blake2Generator seed initialization",
        );
    }

    // ---- Layer B: execution parity (loads program from Layer A .bin) ----

    #[test]
    fn vector_1_layer_b_execute_baseline() {
        let prog_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_program_seed_empty_nonce_0.bin"
        );
        let expected_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_execute_seed_empty_nonce_0.bin"
        );
        let prog = deserialize_program(prog_bytes);
        let mut r = LAYER_B_INPUT_R;
        execute_superscalar(&prog, &mut r);
        let expected = decode_register_output(expected_bytes);
        assert_eq!(
            r, expected,
            "Layer B execution (vector 1, baseline) diverges from reference",
        );
    }

    #[test]
    fn vector_2_layer_b_execute_nonce_mixing() {
        let prog_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_program_seed_empty_nonce_1.bin"
        );
        let expected_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_execute_seed_empty_nonce_1.bin"
        );
        let prog = deserialize_program(prog_bytes);
        let mut r = LAYER_B_INPUT_R;
        execute_superscalar(&prog, &mut r);
        let expected = decode_register_output(expected_bytes);
        assert_eq!(
            r, expected,
            "Layer B execution (vector 2, nonce-mixing) diverges from reference",
        );
    }

    #[test]
    fn vector_3_layer_b_execute_seed_derivation() {
        let prog_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_program_seed_shekyl_nonce_0.bin"
        );
        let expected_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_execute_seed_shekyl_nonce_0.bin"
        );
        let prog = deserialize_program(prog_bytes);
        let mut r = LAYER_B_INPUT_R;
        execute_superscalar(&prog, &mut r);
        let expected = decode_register_output(expected_bytes);
        assert_eq!(
            r, expected,
            "Layer B execution (vector 3, seed-derivation) diverges from reference",
        );
    }

    // ---- Combined: end-to-end generate→execute pipeline ----

    #[test]
    fn combined_end_to_end_spec_attestation() {
        // Bytes are by construction identical to
        // ss_execute_seed_shekyl_nonce_0.bin (see the .meta.txt
        // headers for the rationale on keeping both files); this
        // test exercises the full generate→execute pipeline without
        // an intermediate wire-format round-trip, mirroring how
        // downstream consumers would actually use SuperscalarHash.
        let expected_bytes: &[u8] = include_bytes!(
            "../tests/vectors/reference/superscalar/ss_combined_seed_shekyl_nonce_0.bin"
        );
        let mut gen = Blake2Generator::new(b"shekyl-ss-test", 0);
        let prog = generate_superscalar(&mut gen);
        let mut r = LAYER_B_INPUT_R;
        execute_superscalar(&prog, &mut r);
        let expected = decode_register_output(expected_bytes);
        assert_eq!(
            r, expected,
            "Combined end-to-end attestation tuple diverges from reference; \
             if the Layer A and Layer B tests above pass, the wire-format \
             round-trip in deserialize_program is masking a bug",
        );
    }
}
