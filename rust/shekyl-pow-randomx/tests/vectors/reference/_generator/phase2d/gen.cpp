// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Phase 2d single-opcode reference-vector generator
// (RANDOMX_V2_PHASE2D_PLAN.md §6.2 / §8 commit 5a).
//
// Drives the pinned v2 fork's
// `randomx::BytecodeMachine::compileInstruction` +
// `randomx::BytecodeMachine::executeInstruction` against a single
// fabricated `randomx::Instruction` per emission, given a fixed
// `NativeRegisterFile` + `ProgramConfiguration` + scratchpad
// pattern. Snapshots the post-execution `NativeRegisterFile` in the
// 256-byte T4 layout so each vector is a stable byte-equality
// fixture against the Rust port's `dispatch_instruction` body.
//
// Build: `make` (see Makefile FORK_OBJS list).

#include <cassert>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "allocator.hpp"
#include "bytecode_machine.hpp"
#include "common.hpp"
#include "configuration.h"
#include "instruction.hpp"
#include "intrin_portable.h"
#include "program.hpp"
#include "randomx.h"

namespace {

// ---------------------------------------------------------------------------
// Little-endian emit helpers (host-endian-independent).
// ---------------------------------------------------------------------------

void emit_bytes(const void* buf, size_t n) {
    std::fwrite(buf, 1, n, stdout);
}

void store_le_u64(uint8_t* dst, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        dst[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void store_le_u32(uint8_t* dst, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        dst[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void store_le_f128(uint8_t* dst, rx_vec_f128 v) {
    alignas(16) double tmp[2];
    rx_store_vec_f128(tmp, v);
    uint64_t lo, hi;
    std::memcpy(&lo, &tmp[0], 8);
    std::memcpy(&hi, &tmp[1], 8);
    store_le_u64(dst, lo);
    store_le_u64(dst + 8, hi);
}

// ---------------------------------------------------------------------------
// Canonical fixtures shared by all Phase 2d single-opcode tests.
//
// `nreg.r[i]` carries a distinct byte in every lane so misordered
// stores surface as snapshot mismatches. The FP lanes are deliberately
// representable normal IEEE 754 doubles in every rounding mode so the
// matrix tests reflect only rounding-mode-induced LSB differences.
// ---------------------------------------------------------------------------

constexpr uint64_t CANONICAL_R[8] = {
    0x0102030405060708ULL, 0x1112131415161718ULL,
    0x2122232425262728ULL, 0x3132333435363738ULL,
    0x4142434445464748ULL, 0x5152535455565758ULL,
    0x6162636465666768ULL, 0x7172737475767778ULL,
};

// Each pair is {low-lane bits, high-lane bits} as IEEE 754 u64.
constexpr uint64_t CANONICAL_F[4][2] = {
    {0x3FF0000000000000ULL, 0x4000000000000000ULL}, // +1.0,  +2.0
    {0xBFF0000000000000ULL, 0xC000000000000000ULL}, // -1.0,  -2.0
    {0x4008000000000000ULL, 0x4010000000000000ULL}, // +3.0,  +4.0
    {0xBFE0000000000000ULL, 0x3FE8000000000000ULL}, // -0.5,  +0.75
};

constexpr uint64_t CANONICAL_E[4][2] = {
    {0x4030000000000000ULL, 0x4034000000000000ULL}, // +16,  +20
    {0x4038000000000000ULL, 0x403C000000000000ULL}, // +24,  +28
    {0x4040000000000000ULL, 0x4042000000000000ULL}, // +32,  +36
    {0x4044000000000000ULL, 0x4046000000000000ULL}, // +40,  +44
};

constexpr uint64_t CANONICAL_A[4][2] = {
    {0x3FE0000000000000ULL, 0x3FE8000000000000ULL}, // +0.5,  +0.75
    {0x3FF8000000000000ULL, 0x3FFC000000000000ULL}, // +1.5,  +1.75
    {0x4002000000000000ULL, 0x4006000000000000ULL}, // +2.25, +2.75
    {0x400C000000000000ULL, 0x4010000000000000ULL}, // +3.5,  +4.0
};

// eMask lanes mirror the per-iteration eMask the C reference would
// compute in `randomx_vm::initialize()`; pinned here to keep FDIV_M
// reproducible.
constexpr uint64_t CANONICAL_E_MASK[2] = {
    0x3FF0000000000000ULL,
    0x4000000000000000ULL,
};

// Deterministic 2 MiB scratchpad pattern. `(i * 0x9E + 0x37) & 0xff`
// covers all 256 byte values, so every memory-form opcode reads stable
// bytes that depend on its `getScratchpadAddress` index.
void init_scratchpad(uint8_t* scratchpad, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        scratchpad[i] = static_cast<uint8_t>((i * 0x9E + 0x37) & 0xff);
    }
}

void init_nreg(randomx::NativeRegisterFile& nreg) {
    for (unsigned i = 0; i < randomx::RegistersCount; ++i) {
        nreg.r[i] = CANONICAL_R[i];
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        // rx_set_vec_f128(hi_bits, lo_bits) -> {lane0=lo, lane1=hi}.
        nreg.f[i] = rx_set_vec_f128(CANONICAL_F[i][1], CANONICAL_F[i][0]);
        nreg.e[i] = rx_set_vec_f128(CANONICAL_E[i][1], CANONICAL_E[i][0]);
        nreg.a[i] = rx_set_vec_f128(CANONICAL_A[i][1], CANONICAL_A[i][0]);
    }
}

void init_config(randomx::ProgramConfiguration& config) {
    std::memset(&config, 0, sizeof config);
    config.eMask[0] = CANONICAL_E_MASK[0];
    config.eMask[1] = CANONICAL_E_MASK[1];
    config.readReg0 = 0;
    config.readReg1 = 1;
    config.readReg2 = 2;
    config.readReg3 = 3;
}

// 256-byte T4-layout register-file snapshot:
//   bytes   0.. 63 : r[0..7] u64 LE
//   bytes  64..127 : f[0..3] [f64; 2] LE
//   bytes 128..191 : e[0..3] [f64; 2] LE
//   bytes 192..255 : a[0..3] [f64; 2] LE
void emit_register_snapshot(const randomx::NativeRegisterFile& nreg) {
    uint8_t buf[256];
    for (unsigned i = 0; i < randomx::RegistersCount; ++i) {
        store_le_u64(buf + i * 8, nreg.r[i]);
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        store_le_f128(buf + 64 + i * 16, nreg.f[i]);
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        store_le_f128(buf + 128 + i * 16, nreg.e[i]);
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        store_le_f128(buf + 192 + i * 16, nreg.a[i]);
    }
    emit_bytes(buf, sizeof buf);
}

// ---------------------------------------------------------------------------
// Single-opcode harness.
//
// Build a single `Instruction`, compile it into an `InstructionByteCode`
// against a freshly initialized `NativeRegisterFile`, execute it with
// the requested FP rounding mode, snapshot, and reset the FPU.
// ---------------------------------------------------------------------------

void execute_one(uint8_t opcode, uint8_t dst, uint8_t src, uint8_t mod, uint32_t imm32,
                 uint32_t fprc, uint8_t* scratchpad) {
    randomx::NativeRegisterFile nreg;
    init_nreg(nreg);

    randomx::ProgramConfiguration config;
    init_config(config);

    randomx::InstructionByteCode ibc;
    std::memset(&ibc, 0, sizeof ibc);

    randomx::Instruction instr;
    instr.opcode = opcode;
    instr.dst = dst;
    instr.src = src;
    instr.setMod(mod);
    instr.setImm32(imm32);

    randomx::BytecodeMachine machine;
    machine.beginCompilation(nreg);
    machine.compileInstruction(instr, 0, ibc);

    rx_set_rounding_mode(fprc & 3);
    int pc = 0;
    randomx::BytecodeMachine::executeInstruction(ibc, pc, scratchpad, config,
                                                 RANDOMX_FLAG_V2);
    rx_reset_float_state();

    emit_register_snapshot(nreg);
}

// ---------------------------------------------------------------------------
// T9 — single-instruction integer smoke (4 × 256 B = 1024 B).
//
// Opcodes (frequency-decoded per common.hpp):
//   IADD_RS  : opcode  0..15
//   IMULH_R  : opcode 66..69
//   IROR_R   : opcode 106..113
//   ISTORE   : opcode 240..255
// ---------------------------------------------------------------------------

void emit_t9(uint8_t* scratchpad) {
    init_scratchpad(scratchpad, randomx::ScratchpadSize);
    execute_one(0,   2, 3, 0,    0x12345678, 0, scratchpad); // IADD_RS
    execute_one(66,  4, 5, 0,    0,          0, scratchpad); // IMULH_R
    execute_one(106, 6, 7, 0,    11,         0, scratchpad); // IROR_R
    init_scratchpad(scratchpad, randomx::ScratchpadSize);
    execute_one(240, 0, 1, 0xE0, 0xCAFE0007, 0, scratchpad); // ISTORE (L3 mask via mod>>4=14)
}

// ---------------------------------------------------------------------------
// T10 — single-instruction FP smoke under RN (4 × 256 B = 1024 B).
//
// Opcodes:
//   FADD_R  : 124..139
//   FMUL_R  : 172..203
//   FDIV_M  : 204..207
//   FSQRT_R : 208..213
// ---------------------------------------------------------------------------

void emit_t10(uint8_t* scratchpad) {
    init_scratchpad(scratchpad, randomx::ScratchpadSize);
    execute_one(124, 0, 0, 0,     0,     0, scratchpad); // FADD_R
    execute_one(172, 1, 2, 0,     0,     0, scratchpad); // FMUL_R
    execute_one(204, 2, 3, 0,     0x040, 0, scratchpad); // FDIV_M
    execute_one(208, 3, 0, 0,     0,     0, scratchpad); // FSQRT_R
}

// ---------------------------------------------------------------------------
// T11-T14 — FP rounding-mode matrix (9 × 256 B = 2304 B per mode).
//
// Each mode applies a fresh canonical register file per opcode, so
// snapshots are independent.
// ---------------------------------------------------------------------------

void emit_fp_matrix(uint32_t fprc, uint8_t* scratchpad) {
    init_scratchpad(scratchpad, randomx::ScratchpadSize);
    execute_one(120, 1, 0, 0,     0,     fprc, scratchpad); // FSWAP_R
    execute_one(124, 0, 0, 0,     0,     fprc, scratchpad); // FADD_R
    execute_one(140, 1, 2, 0,     0x040, fprc, scratchpad); // FADD_M
    execute_one(145, 2, 1, 0,     0,     fprc, scratchpad); // FSUB_R
    execute_one(161, 0, 3, 0,     0x080, fprc, scratchpad); // FSUB_M
    execute_one(166, 3, 0, 0,     0,     fprc, scratchpad); // FSCAL_R
    execute_one(172, 1, 2, 0,     0,     fprc, scratchpad); // FMUL_R
    execute_one(204, 2, 3, 0,     0x040, fprc, scratchpad); // FDIV_M
    execute_one(208, 3, 0, 0,     0,     fprc, scratchpad); // FSQRT_R
}

void emit_t11(uint8_t* scratchpad) { emit_fp_matrix(0, scratchpad); }
void emit_t12(uint8_t* scratchpad) { emit_fp_matrix(1, scratchpad); }
void emit_t13(uint8_t* scratchpad) { emit_fp_matrix(2, scratchpad); }
void emit_t14(uint8_t* scratchpad) { emit_fp_matrix(3, scratchpad); }

// ---------------------------------------------------------------------------
// T15 — CFROUND throttle (3 × (256 + 4) B = 780 B).
//
// Per case:
//   - 256 B post-execution register snapshot (CFROUND must not touch
//     the register file; emitting it pins the invariant).
//   - 4 B LE u32 = `rx_get_rounding_mode()` measured immediately
//     after dispatch.
//
// Cases:
//   1. Throttled: src bits 2..5 nonzero -> mode unchanged from
//      `rx_set_rounding_mode(0)`.
//   2. Unthrottled, target RN (mode 0).
//   3. Unthrottled, target RZ (mode 3).
// ---------------------------------------------------------------------------

void emit_cfround_case(uint8_t src_value, uint8_t imm_rotate, uint8_t* scratchpad) {
    randomx::NativeRegisterFile nreg;
    init_nreg(nreg);
    nreg.r[1] = static_cast<uint64_t>(src_value);

    randomx::ProgramConfiguration config;
    init_config(config);

    randomx::InstructionByteCode ibc;
    std::memset(&ibc, 0, sizeof ibc);

    randomx::Instruction instr;
    instr.opcode = 239; // single opcode in CFROUND range (frequency 1)
    instr.dst = 0;
    instr.src = 1;
    instr.setMod(0);
    instr.setImm32(imm_rotate);

    randomx::BytecodeMachine machine;
    machine.beginCompilation(nreg);
    machine.compileInstruction(instr, 0, ibc);

    rx_set_rounding_mode(0);
    int pc = 0;
    randomx::BytecodeMachine::executeInstruction(ibc, pc, scratchpad, config,
                                                 RANDOMX_FLAG_V2);
    uint32_t observed = rx_get_rounding_mode();
    rx_reset_float_state();

    emit_register_snapshot(nreg);
    uint8_t le[4];
    store_le_u32(le, observed);
    emit_bytes(le, sizeof le);
}

void emit_t15(uint8_t* scratchpad) {
    init_scratchpad(scratchpad, randomx::ScratchpadSize);
    // Throttle path: isrc & 60 nonzero so the dispatch leaves the
    // mode at whatever `rx_set_rounding_mode(0)` set it to.
    emit_cfround_case(0x0C, 0, scratchpad);
    // Unthrottled, target RN.
    emit_cfround_case(0x00, 0, scratchpad);
    // Unthrottled, target RZ (isrc bits 0..1 = 0b11).
    emit_cfround_case(0x03, 0, scratchpad);
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(
            stderr,
            "Usage: %s <mode>\n"
            "Modes: t9 t10 t11 t12 t13 t14 t15\n",
            argv[0]);
        return 2;
    }

    uint8_t* scratchpad =
        (uint8_t*)randomx::AlignedAllocator<randomx::CacheLineSize>::allocMemory(
            randomx::ScratchpadSize);
    if (scratchpad == nullptr) {
        std::fprintf(stderr, "allocMemory(ScratchpadSize) returned NULL\n");
        return 3;
    }

    const std::string mode = argv[1];
    int rc = 0;
    if      (mode == "t9")  emit_t9(scratchpad);
    else if (mode == "t10") emit_t10(scratchpad);
    else if (mode == "t11") emit_t11(scratchpad);
    else if (mode == "t12") emit_t12(scratchpad);
    else if (mode == "t13") emit_t13(scratchpad);
    else if (mode == "t14") emit_t14(scratchpad);
    else if (mode == "t15") emit_t15(scratchpad);
    else { std::fprintf(stderr, "unknown mode: %s\n", mode.c_str()); rc = 2; }

    randomx::AlignedAllocator<randomx::CacheLineSize>::freeMemory(
        scratchpad, randomx::ScratchpadSize);
    return rc;
}
