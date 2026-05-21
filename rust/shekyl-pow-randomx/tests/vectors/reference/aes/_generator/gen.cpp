/*
 * Copyright (c) 2025-2026, The Shekyl Foundation
 *
 * All rights reserved.
 * BSD-3-Clause
 */

/*
 * AES reference-bytes generator for `shekyl-pow-randomx` tests.
 *
 * Compiled against the v2 fork's reference AES implementation at pin
 * `aaafe71` (`external/randomx-v2/src/soft_aes.cpp`,
 * `external/randomx-v2/src/aes_hash.cpp`) to produce derived test
 * vectors that `shekyl-pow-randomx`'s `src/aes.rs` tests assert
 * byte-for-byte against. Per `docs/design/RANDOMX_V2_RUST.md` §3
 * "Spec Is the Source of Truth", `specs.md` is normative and the
 * `soft_aes`/`aes_hash` family is the byte-level cross-check; this
 * generator instantiates the C cross-check.
 *
 * Build: see the sibling Makefile.
 *
 * Usage:
 *   ./gen <mode> > vector.bin
 *
 * Modes (each emits a fixed-size raw byte stream; the .bin file size
 * is the column below, and the Rust test side hard-codes the inputs
 * matching the emitter so that the .bin contains the *outputs* only):
 *
 *   round_enc            48 bytes  3 × 16-byte soft_aesenc outputs
 *   round_dec            48 bytes  3 × 16-byte soft_aesdec outputs
 *   chained_enc         48 bytes  3 successive soft_aesenc states from a
 *                                 single chained run (round-1, round-2,
 *                                 round-3 intermediate states)
 *   chained_dec         48 bytes  3 successive soft_aesdec states from a
 *                                 single chained run
 *   gen_1r_state42_iters4
 *                       320 bytes fillAes1Rx4<true> with state=[0x42;64],
 *                                 iters=4 → output[256] || final_state[64]
 *   gen_4r_state33_iters4
 *                       256 bytes fillAes4Rx4<true> with state=[0x33;64],
 *                                 iters=4 → output[256] (no state writeback
 *                                 per aes_hash.cpp:282)
 *   hash_1r_uniform128
 *                        64 bytes hashAes1Rx4<true>(input=[0x11;128]) → 64
 *   hash_1r_empty
 *                        64 bytes hashAes1Rx4<true>(input=&[], len=0) → 64
 *
 * The byte order on stdout is the raw little-endian-host memory layout
 * of `rx_vec_i128` (a 16-byte aligned 128-bit value); on x86_64 and
 * aarch64 that is the canonical FIPS-197 byte order for state[0..16].
 * Cross-checked against the Rust `[u8; 16]` representation that
 * `aes-0.9.0::Block` aliases via `hybrid_array::Array<u8, U16>`. The
 * Rust test side reads these bytes with `include_bytes!` and compares
 * directly to its in-process `[u8; 16]` / `[u8; 64]` arrays — a
 * regenerator on a big-endian host would need to byteswap before
 * writing, but all maintainer and CI hosts are little-endian.
 *
 * All composite functions are instantiated at `<softAes=true>` so the
 * emitted bytes are SIMD-codegen-independent. `soft_aesenc` /
 * `soft_aesdec` themselves are pure C++ LUT implementations with no
 * conditional codegen.
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "aes_hash.hpp"
#include "intrin_portable.h"
#include "soft_aes.h"

/*
 * The three round-primitive inputs the Rust side mirrors. Picked to
 * cover (a) uniform-byte state + uniform-byte key (the smoke-test
 * input), (b) sequential state + zero key (catches a ShiftRows
 * regression), and (c) sequential state + offset-sequential key
 * (every byte distinct, maximising mix).
 *
 * Each .bin in `round_{enc,dec}` mode is the concatenation of the
 * three 16-byte outputs in this order.
 */
static const uint8_t ROUND_INPUT_STATES[3][16] = {
    /* T1 */
    {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
     0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
    /* T2 */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    /* T3 */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
};
static const uint8_t ROUND_INPUT_KEYS[3][16] = {
    /* T1 */
    {0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
     0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99},
    /* T2 */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* T3 */
    {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
};

/*
 * The chained-round (F6 supplement) input: 3 rounds of the same
 * primitive with a fixed initial state and a fixed key reused across
 * rounds. The shared-key shape is intentional — the F6 attack-vector
 * the test guards against ("equivalent-inverse vs FIPS-197 standard
 * inverse happen to agree on degenerate inputs but diverge by round
 * 2") cares about the cumulative diffusion across rounds, not about
 * per-round key novelty. Reusing one key keeps the test reproducible
 * from a single literal on both the C and Rust sides.
 */
static const uint8_t CHAIN_INPUT_STATE[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t CHAIN_INPUT_KEY[16] = {
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
};

/*
 * Wrappers that hide the rx_vec_i128 round-trip across a 16-byte
 * aligned scratch buffer. The buffer layout (canonical LE on
 * little-endian hosts) is what the .bin files commit to.
 */
static void load_block(rx_vec_i128 *out, const uint8_t bytes[16]) {
    alignas(16) uint8_t aligned[16];
    std::memcpy(aligned, bytes, 16);
    *out = rx_load_vec_i128(reinterpret_cast<const rx_vec_i128 *>(aligned));
}

static void store_block(uint8_t bytes[16], rx_vec_i128 v) {
    alignas(16) uint8_t aligned[16];
    rx_store_vec_i128(reinterpret_cast<rx_vec_i128 *>(aligned), v);
    std::memcpy(bytes, aligned, 16);
}

static int emit_round_enc() {
    uint8_t out[3 * 16];
    for (int i = 0; i < 3; ++i) {
        rx_vec_i128 state, key;
        load_block(&state, ROUND_INPUT_STATES[i]);
        load_block(&key, ROUND_INPUT_KEYS[i]);
        rx_vec_i128 result = soft_aesenc(state, key);
        store_block(&out[i * 16], result);
    }
    return fwrite(out, 1, sizeof(out), stdout) == sizeof(out) ? 0 : 1;
}

static int emit_round_dec() {
    uint8_t out[3 * 16];
    for (int i = 0; i < 3; ++i) {
        rx_vec_i128 state, key;
        load_block(&state, ROUND_INPUT_STATES[i]);
        load_block(&key, ROUND_INPUT_KEYS[i]);
        rx_vec_i128 result = soft_aesdec(state, key);
        store_block(&out[i * 16], result);
    }
    return fwrite(out, 1, sizeof(out), stdout) == sizeof(out) ? 0 : 1;
}

static int emit_chained_enc() {
    rx_vec_i128 state, key;
    load_block(&state, CHAIN_INPUT_STATE);
    load_block(&key, CHAIN_INPUT_KEY);
    uint8_t out[3 * 16];
    for (int round = 0; round < 3; ++round) {
        state = soft_aesenc(state, key);
        store_block(&out[round * 16], state);
    }
    return fwrite(out, 1, sizeof(out), stdout) == sizeof(out) ? 0 : 1;
}

static int emit_chained_dec() {
    rx_vec_i128 state, key;
    load_block(&state, CHAIN_INPUT_STATE);
    load_block(&key, CHAIN_INPUT_KEY);
    uint8_t out[3 * 16];
    for (int round = 0; round < 3; ++round) {
        state = soft_aesdec(state, key);
        store_block(&out[round * 16], state);
    }
    return fwrite(out, 1, sizeof(out), stdout) == sizeof(out) ? 0 : 1;
}

static int emit_gen_1r_state42_iters4() {
    /*
     * fillAes1Rx4 reads from `state` and writes back the post-loop
     * state; `output[256]` is iters=4 worth of PRNG bytes. The
     * committed .bin layout is `output[256] || final_state[64]` so
     * the Rust test can pin both the produced bytes and the
     * mutated-state contract.
     */
    alignas(16) uint8_t state[64];
    std::memset(state, 0x42, sizeof(state));
    alignas(16) uint8_t output[256];
    fillAes1Rx4<true>(state, sizeof(output), output);
    uint8_t combined[256 + 64];
    std::memcpy(combined, output, 256);
    std::memcpy(combined + 256, state, 64);
    return fwrite(combined, 1, sizeof(combined), stdout) == sizeof(combined) ? 0 : 1;
}

static int emit_gen_4r_state33_iters4() {
    /*
     * fillAes4Rx4 does NOT write back state per aes_hash.cpp:282;
     * only the produced output is committed. The Rust signature
     * takes `state: &[u8; 64]` (shared, not mutable), pinning the
     * same property at the type level.
     */
    alignas(16) uint8_t state[64];
    std::memset(state, 0x33, sizeof(state));
    alignas(16) uint8_t output[256];
    fillAes4Rx4<true>(state, sizeof(output), output);
    return fwrite(output, 1, sizeof(output), stdout) == sizeof(output) ? 0 : 1;
}

static int emit_hash_1r_uniform128() {
    alignas(16) uint8_t input[128];
    std::memset(input, 0x11, sizeof(input));
    alignas(16) uint8_t hash[64];
    hashAes1Rx4<true>(input, sizeof(input), hash);
    return fwrite(hash, 1, sizeof(hash), stdout) == sizeof(hash) ? 0 : 1;
}

static int emit_hash_1r_empty() {
    /*
     * Empty input is permitted: the loop body never executes, and
     * the resulting hash is the two-extra-rounds-from-initial-state
     * value. Pin this constant; downstream consumers reproduce it
     * from the published spec constants alone.
     */
    alignas(16) uint8_t hash[64];
    hashAes1Rx4<true>(nullptr, 0, hash);
    return fwrite(hash, 1, sizeof(hash), stdout) == sizeof(hash) ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr,
                "Usage: %s <mode>\n"
                "Modes: round_enc, round_dec, chained_enc, chained_dec,\n"
                "       gen_1r_state42_iters4, gen_4r_state33_iters4,\n"
                "       hash_1r_uniform128, hash_1r_empty\n",
                argv[0]);
        return 2;
    }

    const char *mode = argv[1];
    if (std::strcmp(mode, "round_enc") == 0) return emit_round_enc();
    if (std::strcmp(mode, "round_dec") == 0) return emit_round_dec();
    if (std::strcmp(mode, "chained_enc") == 0) return emit_chained_enc();
    if (std::strcmp(mode, "chained_dec") == 0) return emit_chained_dec();
    if (std::strcmp(mode, "gen_1r_state42_iters4") == 0) return emit_gen_1r_state42_iters4();
    if (std::strcmp(mode, "gen_4r_state33_iters4") == 0) return emit_gen_4r_state33_iters4();
    if (std::strcmp(mode, "hash_1r_uniform128") == 0) return emit_hash_1r_uniform128();
    if (std::strcmp(mode, "hash_1r_empty") == 0) return emit_hash_1r_empty();

    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
}
