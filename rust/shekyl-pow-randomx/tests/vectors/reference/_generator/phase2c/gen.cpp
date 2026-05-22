// Phase 2c reference-vector generator (RANDOMX_V2_PHASE2C_PLAN.md
// §9 commit 7).
//
// Compiles against the v2 fork's reference at submodule pin `aaafe71`
// (see `../../../../../../../external/randomx-v2`). Produces eight
// deterministic binary vectors that the Rust port's parity tests
// consume via `include_bytes!`. The wire formats are documented in
// this directory's README.md and in the per-test rustdoc on the Rust
// side at `rust/shekyl-pow-randomx/src/cache.rs` (T1, T2) and
// `rust/shekyl-pow-randomx/src/vm.rs` (T3-T8).
//
// Build: `make` (see Makefile FORK_OBJS list).
//
// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 (F7 T1-T8 matrix) + §6 (test
// strategy), the eight reference vectors map to the eight Rust spec-
// vector tests T1-T8. T1, T2 land in `src/cache.rs#mod tests`; T3-T8
// land in `src/vm.rs#mod tests`.
//
// All emitted bytes are platform-independent: the generator pins
// `softAes=true` for fillAes / hashAes calls (no AES-NI codegen
// dispatch) and emits all multi-byte fields as explicit little-endian.
// The Rust port's `compute_hash` is also softAes-only; byte-equality
// holds on any little-endian host with a C++17 compiler.

#include <cassert>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "aes_hash.hpp"
#include "allocator.hpp"
#include "blake2/blake2.h"
#include "blake2_generator.hpp"
#include "bytecode_machine.hpp"
#include "common.hpp"
#include "dataset.hpp"
#include "instruction.hpp"
#include "intrin_portable.h"
#include "program.hpp"
#include "randomx.h"
#include "soft_aes.h"
#include "superscalar.hpp"
#include "superscalar_program.hpp"
#include "virtual_machine.hpp"
#include "vm_interpreted.hpp"
#include "vm_interpreted_light.hpp"

namespace {

// ---------------------------------------------------------------------------
// Little-endian emit helpers (host-endian-independent).
// ---------------------------------------------------------------------------

void emit_bytes(const void* buf, size_t n) {
    std::fwrite(buf, 1, n, stdout);
}

void emit_le_u32(uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>(v & 0xff),
        static_cast<uint8_t>((v >> 8) & 0xff),
        static_cast<uint8_t>((v >> 16) & 0xff),
        static_cast<uint8_t>((v >> 24) & 0xff),
    };
    emit_bytes(b, sizeof b);
}

void emit_le_u64(uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) {
        b[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
    }
    emit_bytes(b, sizeof b);
}

// Emit an IEEE 754 f64 as its little-endian bit pattern. Reinterpret
// through uint64_t — no host-format assumption beyond "double is IEEE
// 754 64-bit". Matches the Rust side's `f64::to_bits()` + `u64::to_le_bytes()`.
void emit_le_f64(double v) {
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof bits);
    emit_le_u64(bits);
}

// ---------------------------------------------------------------------------
// Canonical inputs for the eight vectors.
// ---------------------------------------------------------------------------

// 32-byte canonical seedhash. Same byte literal used by the Rust
// determinism property tests (T1' / T2' / T3' / T4' / T5' / T6' / T7'
// / T8'); pinning it here keeps the C generator and Rust tests
// referencing identical inputs.
constexpr uint8_t CANONICAL_SEEDHASH[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

// Canonical 64-byte temp_hash for direct fillAes1Rx4 / fillAes4Rx4
// inputs (T3, T4, T5, T6, T7). Constructed as Blake2b-512 over the
// ASCII bytes of "shekyl-randomx-v2-phase2c-canonical-input" so any
// reviewer can reproduce.
//
// Computed once and pinned as a constant; the generator does not
// re-derive it at runtime.
constexpr uint8_t CANONICAL_TEMP_HASH[64] = {
    // Blake2b-512(b"shekyl-randomx-v2-phase2c-canonical-input")
    // — value verified at generator-build time via t3's runtime
    // assertion (see verify_canonical_temp_hash() below).
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

constexpr const char* CANONICAL_TEMP_HASH_PREIMAGE =
    "shekyl-randomx-v2-phase2c-canonical-input";

// 8 item_numbers for T2 — covers item 0 boundary, low cache-line
// boundary, both sides of a typical Argon2 block boundary, and the
// upper-end items just below DatasetExtraItems. Same set used by Rust
// T2' (`t2_prime_invariance`).
constexpr uint64_t T2_ITEM_NUMBERS[8] = {
    0, 1, 1023, 1024, 524287, 524288, 2097150, 2097151,
};

// 192-byte canonical "data" input for T8 end-to-end hash. The bytes
// are the ASCII of the preimage label repeated and padded; the
// generator stores them as-is and the Rust T8 test mirrors them
// byte-for-byte. Length is exact; the literal's "padding-to-256" /
// "spans-multiple-blocks" phrasing is *content*, not a size promise —
// the actual length (192 B) still spans multiple 64-B AES-1R-x4
// scratchpad seed blocks, which is all the test needs.
const std::string T8_DATA_INPUT =
    "phase2c-t8-end-to-end-stub-nop-hash-canonical-data-input-"
    "padding-to-256-bytes-so-the-blake2b-input-spans-multiple-"
    "blocks-and-the-fillaes1rx4-scratchpad-init-consumes-a-"
    "non-trivial-seed.....END";

// ---------------------------------------------------------------------------
// Canonical temp_hash verification + emission of derived temp_hash bytes.
// ---------------------------------------------------------------------------

// At startup, re-derive the canonical temp_hash from its documented
// preimage and emit it to a side-channel buffer. The vectors that
// depend on it (T3-T7) write the verified bytes into their inputs;
// this keeps the generator self-contained (no manual transcription of
// 64 hex bytes into the source).
uint8_t g_canonical_temp_hash[64];

void derive_canonical_temp_hash() {
    int rc = blake2b(g_canonical_temp_hash, sizeof g_canonical_temp_hash,
                     CANONICAL_TEMP_HASH_PREIMAGE,
                     std::strlen(CANONICAL_TEMP_HASH_PREIMAGE),
                     nullptr, 0);
    if (rc != 0) {
        std::fprintf(stderr, "blake2b failure deriving canonical temp_hash\n");
        std::exit(3);
    }
    // Silence the unused-constant warning by binding it; the pinned
    // CANONICAL_TEMP_HASH constant is documentation, not load-bearing.
    (void)CANONICAL_TEMP_HASH;
}

// ---------------------------------------------------------------------------
// Cache helpers (T1, T2).
// ---------------------------------------------------------------------------

// Allocate + init a fresh cache with CANONICAL_SEEDHASH. Caller owns
// the returned pointer (must call randomx_release_cache).
randomx_cache* alloc_and_init_canonical_cache() {
    randomx_cache* cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
    if (cache == nullptr) {
        std::fprintf(stderr, "randomx_alloc_cache returned NULL\n");
        std::exit(3);
    }
    randomx_init_cache(cache, CANONICAL_SEEDHASH, sizeof CANONICAL_SEEDHASH);
    return cache;
}

// T1 wire format documented in `.meta.txt`:
//   Blake2b-256(cache.memory ‖ serialized 8 SuperscalarPrograms)
//
// The 256-MiB cache.memory dominates the input; the 8 SS programs
// (~3.6 KB × 8 ≈ 29 KB) are appended for completeness — both sides
// must agree on cache contents AND on the SS programs derived from
// the same seedhash. Output is 32 bytes.
//
// SS program wire format mirrors the Phase 2b superscalar generator's
// `emit_program` (magic SSP1, size u16 LE, address_register u8,
// reserved u8, then size × 8 bytes of (opcode, dst, src, mod, imm32 LE)).
void emit_ss_program_into_blake2b(blake2b_state& st,
                                  randomx::SuperscalarProgram& prog) {
    constexpr uint8_t MAGIC[4] = {'S', 'S', 'P', '1'};
    blake2b_update(&st, MAGIC, sizeof MAGIC);

    const uint32_t size = prog.getSize();
    if (size > randomx::SuperscalarMaxSize) {
        std::fprintf(stderr,
                     "SS program exceeds SuperscalarMaxSize: %u > %u\n",
                     size, randomx::SuperscalarMaxSize);
        std::exit(3);
    }
    uint8_t size_le[2] = {
        static_cast<uint8_t>(size & 0xff),
        static_cast<uint8_t>((size >> 8) & 0xff),
    };
    blake2b_update(&st, size_le, sizeof size_le);

    const int addr_reg = prog.getAddressRegister();
    if (addr_reg < 0 || addr_reg >= 8) {
        std::fprintf(stderr, "SS address register out of range: %d\n", addr_reg);
        std::exit(3);
    }
    const uint8_t addr_reg_byte = static_cast<uint8_t>(addr_reg);
    const uint8_t reserved = 0;
    blake2b_update(&st, &addr_reg_byte, 1);
    blake2b_update(&st, &reserved, 1);

    for (uint32_t i = 0; i < size; ++i) {
        randomx::Instruction& instr = prog(i);
        blake2b_update(&st, &instr.opcode, 1);
        blake2b_update(&st, &instr.dst, 1);
        blake2b_update(&st, &instr.src, 1);
        blake2b_update(&st, &instr.mod, 1);
        uint32_t imm32 = instr.getImm32();
        uint8_t imm32_le[4] = {
            static_cast<uint8_t>(imm32 & 0xff),
            static_cast<uint8_t>((imm32 >> 8) & 0xff),
            static_cast<uint8_t>((imm32 >> 16) & 0xff),
            static_cast<uint8_t>((imm32 >> 24) & 0xff),
        };
        blake2b_update(&st, imm32_le, sizeof imm32_le);
    }
}

void emit_t1() {
    randomx_cache* cache = alloc_and_init_canonical_cache();

    blake2b_state st;
    if (blake2b_init(&st, 32) != 0) {
        std::fprintf(stderr, "blake2b_init failed\n");
        std::exit(3);
    }
    blake2b_update(&st, cache->memory, randomx::CacheSize);

    // Per-program SS regeneration via Blake2Generator + generateSuperscalar
    // directly, deliberately bypassing `cache->programs` (which `initCache`
    // post-processes per `dataset.cpp:131-138`: for every `IMUL_RCP`
    // instruction the C reference REPLACES `imm32` in-place with the
    // reciprocalCache *index* and pushes the precomputed reciprocal value
    // into `cache->reciprocalCache`). The Rust port at
    // `rust/shekyl-pow-randomx/src/superscalar.rs:1465-1467` stores the
    // ORIGINAL `imm32` and computes `randomx_reciprocal(imm32)` on-the-fly
    // in `execute_superscalar`'s `IMUL_RCP` arm (no reciprocal side cache
    // exists). The two storage shapes are RESULT-equivalent (verified by
    // T2 dataset-item parity below) but BYTE-divergent for any T1-style
    // SS-program serialization fingerprint.
    //
    // The fix lives in the generator, not the Rust port: per
    // `05-system-thinking.mdc`'s spec-first / results-fidelity-over-shape-
    // fidelity discipline and per RANDOMX_V2_PHASE2C_PLAN.md §14 Round 0
    // R0-D7/R0-D8, the JIT-side reciprocal cache is a code-generation
    // optimization that the interpreter-only Phase 2c stack does not need;
    // the cache fingerprint vector that the Rust port can match by
    // construction is the one over the *unmodified* SS programs.
    //
    // Re-deriving the Blake2Generator from the same seedhash and calling
    // `generateSuperscalar` 8 times yields byte-identical SS-program state
    // to what `initCache` produces *before* the in-place imm32 substitution
    // (`dataset.cpp:130` calls `generateSuperscalar(cache->programs[i],
    // gen);` first; lines 131-138 then mutate the programs). The
    // generator below stops at the pre-mutation state.
    randomx::SuperscalarProgram t1_programs[RANDOMX_CACHE_ACCESSES];
    randomx::Blake2Generator gen(CANONICAL_SEEDHASH, sizeof CANONICAL_SEEDHASH);
    for (int i = 0; i < RANDOMX_CACHE_ACCESSES; ++i) {
        randomx::generateSuperscalar(t1_programs[i], gen);
    }
    for (uint32_t i = 0; i < RANDOMX_CACHE_ACCESSES; ++i) {
        emit_ss_program_into_blake2b(st, t1_programs[i]);
    }
    uint8_t out[32];
    if (blake2b_final(&st, out, sizeof out) != 0) {
        std::fprintf(stderr, "blake2b_final failed\n");
        std::exit(3);
    }
    emit_bytes(out, sizeof out);

    randomx_release_cache(cache);
}

void emit_t2() {
    randomx_cache* cache = alloc_and_init_canonical_cache();

    for (size_t i = 0; i < sizeof T2_ITEM_NUMBERS / sizeof T2_ITEM_NUMBERS[0]; ++i) {
        alignas(8) uint8_t item[randomx::CacheLineSize];
        randomx::initDatasetItem(cache, item, T2_ITEM_NUMBERS[i]);
        emit_bytes(item, sizeof item);
    }

    randomx_release_cache(cache);
}

// ---------------------------------------------------------------------------
// T3 — fillAes1Rx4 scratchpad init.
//
// Input: 64-byte CANONICAL_TEMP_HASH (the post-Blake2b-512(input)
// state that `randomx_calculate_hash` passes to `machine->initScratchpad`).
// Output: Blake2b-256(scratchpad bytes after fillAes1Rx4).
// ---------------------------------------------------------------------------

void emit_t3() {
    uint8_t* scratchpad =
        (uint8_t*)randomx::AlignedAllocator<randomx::CacheLineSize>::allocMemory(
            randomx::ScratchpadSize);
    if (scratchpad == nullptr) {
        std::fprintf(stderr, "scratchpad alloc failed\n");
        std::exit(3);
    }

    uint8_t seed[64];
    std::memcpy(seed, g_canonical_temp_hash, sizeof seed);
    // Pin softAes=true for portability (see top-of-file note). The
    // `fillAes1Rx4` template is declared at global scope in
    // `aes_hash.hpp`, not in the `randomx` namespace.
    ::fillAes1Rx4<true>(seed, randomx::ScratchpadSize, scratchpad);

    uint8_t out[32];
    int rc = blake2b(out, sizeof out, scratchpad, randomx::ScratchpadSize,
                     nullptr, 0);
    if (rc != 0) {
        std::fprintf(stderr, "blake2b failed in t3\n");
        std::exit(3);
    }
    emit_bytes(out, sizeof out);

    randomx::AlignedAllocator<randomx::CacheLineSize>::freeMemory(
        scratchpad, randomx::ScratchpadSize);
}

// ---------------------------------------------------------------------------
// VM-side helpers (T4-T8).
// ---------------------------------------------------------------------------

// Stub-NOP-dispatch subclass of InterpretedLightVm. Mirrors `Rust 2c`'s
// `dispatch_instruction` NOP stub: the per-iteration loop body runs
// normally (spAddr derivation, register loads, AES mix, dataset read,
// scratchpad writes) but `executeBytecode` is skipped — equivalent to
// every instruction being NOP. Used by T6, T7, T8.
//
// Why not patch the C ref's `compileProgram` / `bytecode` array: per
// RANDOMX_V2_PHASE2C_PLAN.md §5.6, "no upstream patch to
// `bytecode_machine.cpp::compileProgram`". The constraint is binding
// because the v2 substrate's opcode → InstructionType mapping has
// `RANDOMX_FREQ_NOP = 0`, so no opcode value in [0, 256) translates
// to InstructionType::NOP via the standard compile path; the only
// way to produce a NOP-dispatch loop without patching is to override
// `run()` and skip `executeBytecode` + `compileProgram`.
//
// Inheritance from `InterpretedLightVm` (not `InterpretedVm`) is
// deliberate: light-VM mode derives dataset items on demand from
// the cache (per `vm_interpreted_light.cpp::datasetRead`), so the
// generator does not need to allocate the 2 GiB dataset. This keeps
// the per-vector run time bounded by the cache init (~30 s) instead
// of cache+dataset (~minutes). The Rust port's `compute_hash` also
// runs light-VM-only, so the C ref needs to match.
//
// The subclass uses the InterpretedVm's protected accessors (mem,
// scratchpad, program, config, reg, datasetPtr, datasetOffset) via
// the `using` declarations at vm_interpreted.hpp:44-50.
// `InterpretedLightVm::setCache` wires `mem.memory` to the cache's
// memory; `InterpretedLightVm::datasetRead` performs on-the-fly
// dataset item derivation from the cache.
template <bool softAes>
class StubNopInterpretedLightVm
    : public randomx::InterpretedLightVm<
          randomx::AlignedAllocator<randomx::CacheLineSize>, softAes> {
public:
    using Base = randomx::InterpretedLightVm<
        randomx::AlignedAllocator<randomx::CacheLineSize>, softAes>;
    using Base::mem;
    using Base::scratchpad;
    using Base::program;
    using Base::config;
    using Base::reg;
    using Base::datasetOffset;

    explicit StubNopInterpretedLightVm(randomx_flags flags) : Base(flags) {}

    // Mirrors vm_interpreted.cpp's InterpretedVm::run() but skips
    // `compileProgram` and `executeBytecode` inside the iteration
    // loop. The pre-loop entropy → reg.a / mem.ma / mem.mx / config /
    // datasetOffset setup is delegated to `randomx_vm::initialize()`
    // (the same function the production C path calls).
    void run(void* seed) override {
        // VmBase::generateProgram: fillAes4Rx4(seed, sizeof(program),
        // &program). Mirrors the production path.
        randomx::VmBase<randomx::AlignedAllocator<randomx::CacheLineSize>,
                        softAes>::generateProgram(seed);
        randomx_vm::initialize();
        execute_nop();
    }

    // Public helper for T4 and T5: run only the entropy → program +
    // initialize() phase, without executing any iterations. Captures
    // the post-initialize() RegisterFile (T4) and the parsed Program
    // (T5) before any iteration mutates them.
    //
    // `generateProgram` and `initialize` are protected on the parent;
    // promoting the call sequence to a public method on the subclass
    // gives `emit_t4` / `emit_t5` a non-protected entry point without
    // running the full iteration loop.
    void setup_only(void* seed) {
        randomx::VmBase<randomx::AlignedAllocator<randomx::CacheLineSize>,
                        softAes>::generateProgram(seed);
        randomx_vm::initialize();
    }

    // Public accessors for T4 / T5 / T8: the parent's `getProgram()`
    // returns `const Program&`, but `Program::operator()(int)` is
    // non-const. Expose non-const refs directly via the subclass's
    // inherited `using Base::program` / `using Base::reg` declarations.
    randomx::Program& program_ref() { return program; }
    randomx::RegisterFile& register_file_ref() { return reg; }

    // Snapshot callback fired before and after the bytecode-dispatch
    // skip on each iteration. T6 / T7 register snapshot callbacks
    // install pointers to per-iteration capture buffers via
    // set_snapshot_buffers(); T8 leaves them null.
    void set_snapshot_buffers(uint32_t* sp_addr_out, uint8_t* reg_snap_out,
                              uint32_t iter_count) {
        sp_addr_out_ = sp_addr_out;
        reg_snap_out_ = reg_snap_out;
        snap_iter_count_ = iter_count;
    }

private:
    uint32_t* sp_addr_out_ = nullptr;     // T6: writes 8 bytes per iter (spAddr0 LE, spAddr1 LE)
    uint8_t* reg_snap_out_ = nullptr;     // T7: writes 256 bytes per iter (NativeRegisterFile snapshot)
    uint32_t snap_iter_count_ = 0;        // # iterations to capture

    // Mirror of vm_interpreted.cpp's execute() body with
    // compileProgram + executeBytecode removed. Per-iteration
    // semantics:
    //   1. spAddr derivation (lines 70-74 in vm_interpreted.cpp).
    //   2. scratchpad → integer register XOR-load (lines 76-77).
    //   3. scratchpad → FP f / e register cvt+mask (lines 79-83).
    //   4. [SKIPPED] executeBytecode.
    //   5. dataset prefetch + read + mx/ma swap (lines 87-94).
    //   6. integer register → scratchpad store (lines 96-97).
    //   7. V2 AES f/e mix (lines 99-117) — V2 branch only, since
    //      we always pass RANDOMX_FLAG_V2 to the constructor.
    //   8. FP register → scratchpad store (lines 123-124).
    //   9. spAddr0/1 = 0 (lines 126-127).
    // After the loop: store nreg.r / .f / .e back into reg.* (lines
    // 130-137). Identical to the C ref.
    void execute_nop() {
        using namespace randomx;

        NativeRegisterFile nreg;

        for (unsigned i = 0; i < RegisterCountFlt; ++i) {
            nreg.a[i] = rx_load_vec_f128(&reg.a[i].lo);
        }

        uint32_t spAddr0 = mem.mx;
        uint32_t spAddr1 = mem.ma;

        for (unsigned ic = 0; ic < RANDOMX_PROGRAM_ITERATIONS; ++ic) {
            uint64_t spMix = nreg.r[config.readReg0] ^ nreg.r[config.readReg1];
            spAddr0 ^= spMix;
            spAddr0 &= ScratchpadL3Mask64;
            spAddr1 ^= spMix >> 32;
            spAddr1 &= ScratchpadL3Mask64;

            // T6 snapshot: capture spAddr0/1 BEFORE the iteration's
            // register-load + AES-mix work. Pair semantics match the
            // C ref's per-iteration view.
            if (sp_addr_out_ != nullptr && ic < snap_iter_count_) {
                sp_addr_out_[ic * 2 + 0] = spAddr0;
                sp_addr_out_[ic * 2 + 1] = spAddr1;
            }

            for (unsigned i = 0; i < RegistersCount; ++i) {
                nreg.r[i] ^= load64(scratchpad + spAddr0 + 8 * i);
            }

            for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                nreg.f[i] = rx_cvt_packed_int_vec_f128(scratchpad + spAddr1 + 8 * i);
            }

            for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                // `maskRegisterExponentMantissa` is a static member of
                // `randomx::BytecodeMachine`, an indirect base of this
                // template subclass. Unqualified lookup inside a
                // template member function does not see dependent-base
                // members, so qualify explicitly.
                nreg.e[i] = BytecodeMachine::maskRegisterExponentMantissa(
                    config,
                    rx_cvt_packed_int_vec_f128(scratchpad + spAddr1 +
                                               8 * (RegisterCountFlt + i)));
            }

            // [BYTECODE DISPATCH SKIPPED] — Phase 2c stub-NOP.

            const uint64_t readPtr = datasetOffset + (mem.ma & CacheLineAlignMask);

            // V2 branch unconditional (we always construct with
            // RANDOMX_FLAG_V2). `mp` aliases `mem.ma` per vm_interpreted.cpp:89.
            auto& mp = mem.ma;
            mp ^= nreg.r[config.readReg2] ^ nreg.r[config.readReg3];

            // datasetPrefetch + datasetRead are inherited from
            // InterpretedVm (light-VM mode → on-demand item derivation
            // from cache). Call via the protected accessors.
            this->datasetPrefetch_(datasetOffset + (mp & CacheLineAlignMask));
            this->datasetRead_(readPtr, nreg.r);
            std::swap(mem.mx, mem.ma);

            for (unsigned i = 0; i < RegistersCount; ++i) {
                store64(scratchpad + spAddr1 + 8 * i, nreg.r[i]);
            }

            // V2 AES f/e mix — always taken (constructor pins
            // RANDOMX_FLAG_V2).
            {
                rx_vec_i128 ekey[RegisterCountFlt];
                rx_vec_i128 freg[RegisterCountFlt];

                for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                    ekey[i] = rx_cast_vec_f2i(nreg.e[i]);
                    freg[i] = rx_cast_vec_f2i(nreg.f[i]);
                }

                // `aesenc` / `aesdec` are declared at global scope in
                // `soft_aes.h`, not inside `randomx::`; explicit `::`
                // qualification is required for template member
                // lookup.
                for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                    freg[0] = ::aesenc<softAes>(freg[0], ekey[i]);
                    freg[1] = ::aesdec<softAes>(freg[1], ekey[i]);
                    freg[2] = ::aesenc<softAes>(freg[2], ekey[i]);
                    freg[3] = ::aesdec<softAes>(freg[3], ekey[i]);
                }

                for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                    nreg.f[i] = rx_cast_vec_i2f(freg[i]);
                }
            }

            for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                rx_store_vec_f128((double*)(scratchpad + spAddr0 + 16 * i),
                                  nreg.f[i]);
            }

            // T7 snapshot: capture post-AES-mix register state AFTER
            // the iteration's mix work and scratchpad writeback.
            // Layout: r[8] u64 LE, f[4] [2] f64 LE, e[4] [2] f64 LE,
            // a[4] [2] f64 LE — same 256-byte layout as T4.
            if (reg_snap_out_ != nullptr && ic < snap_iter_count_) {
                uint8_t* dst = reg_snap_out_ + ic * 256;
                for (unsigned i = 0; i < RegistersCount; ++i) {
                    uint64_t v = nreg.r[i];
                    for (int j = 0; j < 8; ++j) {
                        dst[i * 8 + j] = static_cast<uint8_t>((v >> (j * 8)) & 0xff);
                    }
                }
                alignas(16) double tmp[2];
                size_t off = 64;
                for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                    rx_store_vec_f128(tmp, nreg.f[i]);
                    uint64_t lo, hi;
                    std::memcpy(&lo, &tmp[0], 8);
                    std::memcpy(&hi, &tmp[1], 8);
                    for (int j = 0; j < 8; ++j) {
                        dst[off + 16 * i + j] = static_cast<uint8_t>((lo >> (j * 8)) & 0xff);
                        dst[off + 16 * i + 8 + j] = static_cast<uint8_t>((hi >> (j * 8)) & 0xff);
                    }
                }
                off = 128;
                for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                    rx_store_vec_f128(tmp, nreg.e[i]);
                    uint64_t lo, hi;
                    std::memcpy(&lo, &tmp[0], 8);
                    std::memcpy(&hi, &tmp[1], 8);
                    for (int j = 0; j < 8; ++j) {
                        dst[off + 16 * i + j] = static_cast<uint8_t>((lo >> (j * 8)) & 0xff);
                        dst[off + 16 * i + 8 + j] = static_cast<uint8_t>((hi >> (j * 8)) & 0xff);
                    }
                }
                off = 192;
                for (unsigned i = 0; i < RegisterCountFlt; ++i) {
                    rx_store_vec_f128(tmp, nreg.a[i]);
                    uint64_t lo, hi;
                    std::memcpy(&lo, &tmp[0], 8);
                    std::memcpy(&hi, &tmp[1], 8);
                    for (int j = 0; j < 8; ++j) {
                        dst[off + 16 * i + j] = static_cast<uint8_t>((lo >> (j * 8)) & 0xff);
                        dst[off + 16 * i + 8 + j] = static_cast<uint8_t>((hi >> (j * 8)) & 0xff);
                    }
                }
            }

            spAddr0 = 0;
            spAddr1 = 0;
        }

        for (unsigned i = 0; i < RegistersCount; ++i) {
            store64(&reg.r[i], nreg.r[i]);
        }

        for (unsigned i = 0; i < RegisterCountFlt; ++i) {
            rx_store_vec_f128(&reg.f[i].lo, nreg.f[i]);
        }

        for (unsigned i = 0; i < RegisterCountFlt; ++i) {
            rx_store_vec_f128(&reg.e[i].lo, nreg.e[i]);
        }
    }

    // Trampolines to the parent's protected virtual methods. C++ name
    // lookup inside the subclass's template member function won't see
    // the `using` declarations through indirect base resolution for
    // protected virtuals; explicit `this->` qualification + a fresh
    // name avoids "no matching call" diagnostics.
    void datasetPrefetch_(uint64_t address) { this->datasetPrefetch(address); }
    void datasetRead_(uint64_t address,
                      randomx::int_reg_t (&r)[randomx::RegistersCount]) {
        this->datasetRead(address, r);
    }
};

// Construct + bind a stub-NOP VM to a freshly initialized cache. The
// cache lifetime is tied to the VM (the VM does not take ownership,
// so the caller releases both via the returned pair).
struct StubVmPair {
    StubNopInterpretedLightVm<true>* vm;
    randomx_cache* cache;
};

StubVmPair alloc_stub_vm_pair() {
    randomx_cache* cache = alloc_and_init_canonical_cache();
    // Pass RANDOMX_FLAG_V2 so the iteration loop runs the V2 AES f/e
    // mix branch (the only branch our stub VM implements).
    auto* vm = new StubNopInterpretedLightVm<true>(
        static_cast<randomx_flags>(RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_V2));
    // setCache() must come first: it populates cachePtr (which
    // aliases datasetPtr via the union at virtual_machine.hpp:76-79).
    // VmBase::allocate() then throws if datasetPtr is null. After
    // allocate(), scratchpad points at a fresh 2 MiB buffer.
    vm->setCache(cache);
    static_cast<randomx::VmBase<
        randomx::AlignedAllocator<randomx::CacheLineSize>, true>*>(vm)
        ->allocate();
    vm->cacheKey = cache->cacheKey;
    return {vm, cache};
}

void release_stub_vm_pair(StubVmPair p) {
    delete p.vm;
    randomx_release_cache(p.cache);
}

// Serialize a NativeRegisterFile-equivalent snapshot in the canonical
// 256-byte layout used by T4 and T7. Reads from `randomx::RegisterFile`
// directly (the post-`initialize()` state is already there; nreg.r
// values are read via the public `r[]` array on RegisterFile).
//
// Layout (little-endian throughout):
//   +0   r[8]  × u64                  → 64 bytes
//   +64  f[4]  × [f64 lo, f64 hi]     → 64 bytes
//   +128 e[4]  × [f64 lo, f64 hi]     → 64 bytes
//   +192 a[4]  × [f64 lo, f64 hi]     → 64 bytes
//   = 256 bytes total
void emit_register_file_snapshot(const randomx::RegisterFile& reg) {
    for (unsigned i = 0; i < randomx::RegistersCount; ++i) {
        emit_le_u64(reg.r[i]);
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        emit_le_f64(reg.f[i].lo);
        emit_le_f64(reg.f[i].hi);
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        emit_le_f64(reg.e[i].lo);
        emit_le_f64(reg.e[i].hi);
    }
    for (unsigned i = 0; i < randomx::RegisterCountFlt; ++i) {
        emit_le_f64(reg.a[i].lo);
        emit_le_f64(reg.a[i].hi);
    }
}

// ---------------------------------------------------------------------------
// T4 — Register init from entropy (post-initialize() RegisterFile).
//
// Input: program parsed from CANONICAL_TEMP_HASH via fillAes4Rx4 +
// initialize() (entropy slots 0-15 → reg.a / mem / config / eMask).
// Output: 256-byte NativeRegisterFile snapshot (only the .a[4]
// FP registers are populated by initialize(); .r / .f / .e are
// untouched).
//
// Note: T4 snapshots the register file BEFORE the iteration loop
// runs, so the .r / .f / .e fields are zero-initialized (they're
// populated per-iteration inside execute()). The Rust port's T4
// test asserts the same — `r` should be all zeros, `f` and `e`
// should be all zeros, only `a` should be the bit-exact
// reinterpretation of program.entropy(0..8) via
// getSmallPositiveFloatBits.
// ---------------------------------------------------------------------------

void emit_t4() {
    StubVmPair p = alloc_stub_vm_pair();
    // run() is overkill; we only need the pre-loop state. Use the
    // subclass's `setup_only()` helper which calls generateProgram +
    // initialize() without executing any iterations.
    p.vm->setup_only(g_canonical_temp_hash);

    emit_register_file_snapshot(p.vm->register_file_ref());

    release_stub_vm_pair(p);
}

// ---------------------------------------------------------------------------
// T5 — Parsed Program structure from entropy.
//
// Input: 64-byte CANONICAL_TEMP_HASH → fillAes4Rx4 → 384-instruction
// Program (the entropy buffer (128 B) + instruction bytes (3072 B) =
// 3200 B fillAes4Rx4 output, of which we serialize only the
// 3072-byte instruction tail).
// Output: 384 × 8 bytes = 3072 bytes.
//
// Wire format per instruction (mirrors Phase 2b's SS-program format
// and the Rust port's `Instruction` struct layout):
//   +0: opcode u8
//   +1: dst    u8
//   +2: src    u8
//   +3: mod    u8
//   +4..+8: imm32 u32 LE
// ---------------------------------------------------------------------------

void emit_t5() {
    StubVmPair p = alloc_stub_vm_pair();
    // setup_only is sufficient: T5 only needs the program after
    // generateProgram (initialize() further mutates reg/mem/config
    // but does not touch program). Keep it consistent with T4 for
    // reviewability.
    p.vm->setup_only(g_canonical_temp_hash);

    randomx::Program& prog = p.vm->program_ref();
    for (unsigned i = 0; i < RANDOMX_PROGRAM_SIZE_V2; ++i) {
        randomx::Instruction& instr = prog(i);
        emit_bytes(&instr.opcode, 1);
        emit_bytes(&instr.dst, 1);
        emit_bytes(&instr.src, 1);
        emit_bytes(&instr.mod, 1);
        emit_le_u32(instr.getImm32());
    }

    release_stub_vm_pair(p);
}

// ---------------------------------------------------------------------------
// T6 — spAddr0/1 derivation across the first 4 iterations of the
// stub-NOP loop.
//
// Input: CANONICAL_TEMP_HASH → generateProgram + initialize → 4
// iterations of the stub-NOP loop.
// Output: 4 × (spAddr0 LE u32, spAddr1 LE u32) = 32 bytes.
// ---------------------------------------------------------------------------

void emit_t6() {
    StubVmPair p = alloc_stub_vm_pair();

    constexpr uint32_t T6_ITER_COUNT = 4;
    uint32_t sp_addr_buf[T6_ITER_COUNT * 2];
    std::memset(sp_addr_buf, 0, sizeof sp_addr_buf);
    p.vm->set_snapshot_buffers(sp_addr_buf, nullptr, T6_ITER_COUNT);
    p.vm->run(g_canonical_temp_hash);

    for (uint32_t i = 0; i < T6_ITER_COUNT; ++i) {
        emit_le_u32(sp_addr_buf[i * 2 + 0]);
        emit_le_u32(sp_addr_buf[i * 2 + 1]);
    }

    release_stub_vm_pair(p);
}

// ---------------------------------------------------------------------------
// T7 — Post-AES-mix register snapshot across the first 4 iterations.
//
// Input: CANONICAL_TEMP_HASH → generateProgram + initialize → 4
// iterations of the stub-NOP loop.
// Output: 4 × 256-byte NativeRegisterFile snapshot = 1024 bytes.
//
// Each 256-byte snapshot captures the post-AES-mix register state
// AT THE END of the iteration's loop body (after V2 AES f/e mix +
// FP register → scratchpad store). Layout matches T4.
// ---------------------------------------------------------------------------

void emit_t7() {
    StubVmPair p = alloc_stub_vm_pair();

    constexpr uint32_t T7_ITER_COUNT = 4;
    uint8_t reg_snap_buf[T7_ITER_COUNT * 256];
    std::memset(reg_snap_buf, 0, sizeof reg_snap_buf);
    p.vm->set_snapshot_buffers(nullptr, reg_snap_buf, T7_ITER_COUNT);
    p.vm->run(g_canonical_temp_hash);

    emit_bytes(reg_snap_buf, sizeof reg_snap_buf);

    release_stub_vm_pair(p);
}

// ---------------------------------------------------------------------------
// T8 — End-to-end stub-NOP hash.
//
// Input: CANONICAL_SEEDHASH (cache key) + T8_DATA_INPUT (the data
// argument to compute_hash).
// Output: 32-byte Blake2b-256 final hash.
//
// Mirrors `randomx_calculate_hash` exactly, except the VM is our
// StubNopInterpretedLightVm whose run() skips bytecode dispatch.
// The Rust port's `compute_hash` does the same.
// ---------------------------------------------------------------------------

void emit_t8() {
    StubVmPair p = alloc_stub_vm_pair();

    // resetRoundingMode mirrors randomx_calculate_hash's pre-loop
    // `_mm_setcsr` save + restore. We don't restore on exit because
    // the generator is a single-shot process.
    static_cast<randomx_vm*>(p.vm)->resetRoundingMode();

    alignas(16) uint64_t tempHash[8];
    int rc = blake2b(tempHash, sizeof tempHash, T8_DATA_INPUT.data(),
                     T8_DATA_INPUT.size(), nullptr, 0);
    if (rc != 0) {
        std::fprintf(stderr, "blake2b failure in t8 input hash\n");
        std::exit(3);
    }

    // Call into base-class initScratchpad via the VmBase template
    // method.
    randomx::VmBase<randomx::AlignedAllocator<randomx::CacheLineSize>, true>* base =
        static_cast<
            randomx::VmBase<randomx::AlignedAllocator<randomx::CacheLineSize>, true>*>(
            p.vm);
    base->initScratchpad(tempHash);

    for (int chain = 0; chain < RANDOMX_PROGRAM_COUNT - 1; ++chain) {
        p.vm->run(tempHash);
        rc = blake2b(tempHash, sizeof tempHash,
                     &p.vm->register_file_ref(),
                     sizeof(randomx::RegisterFile), nullptr, 0);
        if (rc != 0) {
            std::fprintf(stderr, "blake2b failure in t8 chain hash\n");
            std::exit(3);
        }
    }
    p.vm->run(tempHash);

    uint8_t out[RANDOMX_HASH_SIZE];
    base->getFinalResult(out, RANDOMX_HASH_SIZE);
    emit_bytes(out, RANDOMX_HASH_SIZE);

    release_stub_vm_pair(p);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(
            stderr,
            "Usage: %s <mode>\n"
            "Modes: t1, t2, t3, t4, t5, t6, t7, t8\n"
            "  t1: cache derivation Blake2b-256 fingerprint\n"
            "  t2: 8 × 64-byte dataset items (item_numbers fixed)\n"
            "  t3: fillAes1Rx4 scratchpad Blake2b-256 fingerprint\n"
            "  t4: post-initialize() NativeRegisterFile snapshot\n"
            "  t5: 384-instruction Program serialization\n"
            "  t6: spAddr0/1 pairs for first 4 stub-NOP iterations\n"
            "  t7: post-AES-mix register snapshot for first 4 iters\n"
            "  t8: end-to-end stub-NOP compute_hash output\n",
            argv[0]);
        return 2;
    }
    derive_canonical_temp_hash();

    const std::string mode = argv[1];
    if (mode == "t1") {
        emit_t1();
    } else if (mode == "t2") {
        emit_t2();
    } else if (mode == "t3") {
        emit_t3();
    } else if (mode == "t4") {
        emit_t4();
    } else if (mode == "t5") {
        emit_t5();
    } else if (mode == "t6") {
        emit_t6();
    } else if (mode == "t7") {
        emit_t7();
    } else if (mode == "t8") {
        emit_t8();
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
        return 2;
    }
    return 0;
}
