// SuperscalarHash reference-vector generator (Phase 2b commit 5).
//
// Compiles against the v2 fork's reference at submodule pin `aaafe71`
// (see `../../../../../../../external/randomx-v2`). Produces deterministic
// binary vectors that the Rust port's parity tests consume via
// `include_bytes!`. The wire format is documented in this directory's
// README.md and in the `superscalar_vector_format` module rustdoc on the
// Rust side (`rust/shekyl-pow-randomx/src/superscalar.rs`).
//
// Build: `make` (links `superscalar.cpp`, `blake2_generator.cpp`,
// `blake2/blake2b.c`, `reciprocal.c` from the fork).
//
// Per RANDOMX_V2_PHASE2B_PLAN.md §5.4 (F4 structured 3-vector
// decomposition), the seed/nonce vector tuples are:
//
//   Vector 1: seed=empty, nonce=0  — baseline determinism
//   Vector 2: seed=empty, nonce=1  — Blake2Generator nonce-mixing
//   Vector 3: seed="shekyl-ss-test", nonce=0 — full RNG re-seeding
//
// Layer A vectors emit the serialized SuperscalarProgram; Layer B vectors
// emit the post-execution `r[8]` after threading the fixed input
// `[0, 1, 2, 3, 4, 5, 6, 7]` through each Layer A program. The combined
// vector is the spec-attestation tuple a downstream consumer can verify
// against their own SS-hash implementation.

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "blake2_generator.hpp"
#include "common.hpp"
#include "instruction.hpp"
#include "superscalar.hpp"
#include "superscalar_program.hpp"

namespace {

// `SuperscalarMaxSize` is `3 * RANDOMX_SUPERSCALAR_LATENCY + 2 = 512`
// per `common.hpp:84` with `RANDOMX_SUPERSCALAR_LATENCY = 170`
// (see `configuration.h:47`). The wire format's `size: u16` field is
// well above this bound either way; the static assert guards against
// silent upstream drift that would invalidate the `u16` choice.
static_assert(randomx::SuperscalarMaxSize == 512,
              "SuperscalarMaxSize changed; regenerate vectors and update meta");

// Wire format for a serialized SuperscalarProgram. Documented at the
// directory README.md and in the Rust-side `superscalar_vector_format`
// module rustdoc. Little-endian; 8-byte header + size * 8 bytes per
// instruction. The magic and version pin the format so any future
// drift (e.g. metadata expansion) is caught at the `assert` site,
// not silently misparsed.
constexpr uint8_t MAGIC[4] = {'S', 'S', 'P', '1'};

void emit_le_u16(uint16_t v) {
    uint8_t b[2] = {
        static_cast<uint8_t>(v & 0xff),
        static_cast<uint8_t>((v >> 8) & 0xff),
    };
    std::fwrite(b, 1, sizeof b, stdout);
}

void emit_le_u32(uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>(v & 0xff),
        static_cast<uint8_t>((v >> 8) & 0xff),
        static_cast<uint8_t>((v >> 16) & 0xff),
        static_cast<uint8_t>((v >> 24) & 0xff),
    };
    std::fwrite(b, 1, sizeof b, stdout);
}

void emit_le_u64(uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) {
        b[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
    }
    std::fwrite(b, 1, sizeof b, stdout);
}

// Serialize a SuperscalarProgram in the canonical wire format described in
// the directory README.md. The format is fixed-cost-per-instruction (8
// bytes, mirroring `randomx::Instruction`'s declared layout) so any cross-
// component disagreement on instruction encoding surfaces as a byte diff
// at a predictable offset rather than as an opaque hash mismatch.
void emit_program(randomx::SuperscalarProgram &prog) {
    std::fwrite(MAGIC, 1, sizeof MAGIC, stdout);
    const uint32_t size = prog.getSize();
    if (size > randomx::SuperscalarMaxSize) {
        std::fprintf(stderr,
                     "generated program exceeds SuperscalarMaxSize: %u > %u\n",
                     size, randomx::SuperscalarMaxSize);
        std::exit(3);
    }
    emit_le_u16(static_cast<uint16_t>(size));
    const int addr_reg = prog.getAddressRegister();
    if (addr_reg < 0 || addr_reg >= 8) {
        std::fprintf(stderr, "address register out of range: %d\n", addr_reg);
        std::exit(3);
    }
    const uint8_t addr_reg_byte = static_cast<uint8_t>(addr_reg);
    const uint8_t reserved = 0;
    std::fwrite(&addr_reg_byte, 1, 1, stdout);
    std::fwrite(&reserved, 1, 1, stdout);

    for (uint32_t i = 0; i < size; ++i) {
        randomx::Instruction &instr = prog(i);
        std::fwrite(&instr.opcode, 1, 1, stdout);
        std::fwrite(&instr.dst, 1, 1, stdout);
        std::fwrite(&instr.src, 1, 1, stdout);
        std::fwrite(&instr.mod, 1, 1, stdout);
        emit_le_u32(instr.getImm32());
    }
}

// `(seed, nonce)` pairs per F4. Empty seed (`size=0`) is the baseline; the
// Blake2Generator constructor accepts `nullptr` when `size == 0`.
struct SeedNonce {
    const uint8_t *seed;
    size_t seed_size;
    int nonce;
    const char *label;
};

const SeedNonce VECTOR_1 = {nullptr, 0, 0, "seed=empty,nonce=0"};
const SeedNonce VECTOR_2 = {nullptr, 0, 1, "seed=empty,nonce=1"};
const uint8_t SHEKYL_SEED[] = {'s', 'h', 'e', 'k', 'y', 'l', '-',
                               's', 's', '-', 't', 'e', 's', 't'};
const SeedNonce VECTOR_3 = {SHEKYL_SEED, sizeof SHEKYL_SEED, 0,
                            "seed=shekyl-ss-test,nonce=0"};

randomx::SuperscalarProgram make_program(const SeedNonce &v) {
    randomx::Blake2Generator gen(v.seed, v.seed_size, v.nonce);
    randomx::SuperscalarProgram prog;
    randomx::generateSuperscalar(prog, gen);
    return prog;
}

void emit_layer_a(const SeedNonce &v) {
    auto prog = make_program(v);
    emit_program(prog);
}

void emit_layer_b(const SeedNonce &v) {
    auto prog = make_program(v);
    randomx::int_reg_t r[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    randomx::executeSuperscalar(r, prog);
    for (int i = 0; i < 8; ++i) {
        emit_le_u64(r[i]);
    }
}

// Combined emits exactly Layer B for vector 3 (`seed=shekyl-ss-test,
// nonce=0, input=[0..8]`). The duplication is intentional and documented
// in the .meta.txt: Layer B tests load the serialized program (proving
// generation parity is decoupled from execution parity), while combined
// tests the end-to-end generate→execute pipeline without intermediate
// serialization. A divergence in only one of the two attributes the
// failure to serialization vs. computation.
void emit_combined() { emit_layer_b(VECTOR_3); }

}  // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::fprintf(stderr,
                     "Usage: %s <mode>\n"
                     "Modes: prog_v1, prog_v2, prog_v3,\n"
                     "       exec_v1, exec_v2, exec_v3,\n"
                     "       combined\n",
                     argv[0]);
        return 2;
    }
    const std::string mode = argv[1];
    if (mode == "prog_v1") {
        emit_layer_a(VECTOR_1);
    } else if (mode == "prog_v2") {
        emit_layer_a(VECTOR_2);
    } else if (mode == "prog_v3") {
        emit_layer_a(VECTOR_3);
    } else if (mode == "exec_v1") {
        emit_layer_b(VECTOR_1);
    } else if (mode == "exec_v2") {
        emit_layer_b(VECTOR_2);
    } else if (mode == "exec_v3") {
        emit_layer_b(VECTOR_3);
    } else if (mode == "combined") {
        emit_combined();
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
        return 2;
    }
    return 0;
}
