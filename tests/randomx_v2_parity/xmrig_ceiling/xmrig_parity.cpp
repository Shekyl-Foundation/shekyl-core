// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// NOTE: this dev-only harness is BUILT against a local XMRig clone (GPLv3, via
// XMRIG_DIR); XMRig is neither vendored nor distributed here. The built binary
// is GPLv3 by linkage and is not distributed. This source, as authored by The
// Shekyl Foundation, is BSD-3-Clause.

// Phase 0 hash-core byte-equality differential: XMRig RandomX-v2 vs Shekyl canonical pins.
//
// Proves that XMRig 6.26.0's RandomX-v2 hash core (selected via the global
// RandomX_ConfigurationMoneroV2 config — XMRig has NO per-VM RANDOMX_FLAG_V2)
// is byte-identical to Shekyl's committed CANONICAL_RANDOM_HASHES, which were
// generated from external/randomx-v2 @ aaafe71 with randomx_create_vm(RANDOMX_FLAG_V2).
//
// MODE MATTERS — the ceiling comparison MUST run full-dataset + JIT. XMRig's v2 is
// NOT mode-invariant: its light/interpreter path is v2-INCOMPLETE (it applies only
// Tweak_V2_PREFETCH; AES/CFROUND/COMMITMENT are JIT-only), and even its light-JIT
// result diverges from its own full-dataset result. Full-dataset (mining) mode is the
// one an adversary uses and the only one that reproduces the canonical hash. Software
// AES throughout — RandomX mandates soft==hard output, matching the fork's soft-AES
// c_oracle canonical. This is a hash-CORRECTNESS test (hardware-independent), not timing.
//
// Modes: <parity_corpus.dat> = full-dataset differential over all 1024 vectors;
//   --rx0 = published rx/0 v1 build-faithfulness anchor (interpreter is fine — v1 has
//           no tweaks); --kat-full = single v2 KAT, full-dataset (== canonical);
//   --kat = single v2 KAT, light-JIT — DEMONSTRATES the v2-incomplete divergence.
//
// Corpus: parity_corpus.dat (magic SKLPRTY1), carrying per-record
// seed[32] / canonical_index / canonical_hash[32] / data_len / data.

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

#include "crypto/randomx/randomx.h"

static uint32_t rd_u32(FILE* f) {
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) { fprintf(stderr, "EOF reading u32\n"); exit(2); }
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void rd_exact(FILE* f, void* p, size_t n) {
    if (fread(p, 1, n, f) != n) { fprintf(stderr, "EOF reading %zu bytes\n", n); exit(2); }
}
static std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 15]); }
    return s;
}

// RandomX buffer sizes (RandomX_ConfigurationMoneroV2): cache = ArgonMemory(262144)*1024,
// scratchpad = RANDOMX_SCRATCHPAD_L3, dataset item = 64 bytes.
static const size_t CACHE_BYTES      = 268435456; // 256 MiB
static const size_t SCRATCHPAD_BYTES = 2097152;   // 2 MiB
static const size_t DATASET_ITEM_BYTES = 64;

// Aligned alloc that aborts on failure — an unchecked posix_memalign would leave the
// pointer indeterminate and feed garbage to RandomX (UB). Dev-only harness, so exit(2)
// (not throw) is the honest, minimal contract.
static void* xalloc(size_t align, size_t size) {
    void* p = nullptr;
    if (posix_memalign(&p, align, size) != 0 || !p) {
        fprintf(stderr, "xalloc: failed to allocate %zu bytes (align %zu)\n", size, align);
        exit(2);
    }
    return p;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <parity_corpus.dat> | --rx0 | --kat-full | --kat\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "--rx0") == 0) {
        // Published RandomX v1 (rx/0) reference vector — proves the build pipeline
        // (argon2 cache, soft-AES, interpreter, blake2) is faithful.
        randomx_apply_config(RandomX_MoneroConfig); // v1 Monero (ProgramSize 256, no v2 tweaks)
        const char* key    = "test key 000";
        const char* input  = "This is a test";
        const char* expect = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f";
        void* cm = xalloc(4096, CACHE_BYTES); void* sp = xalloc(4096, SCRATCHPAD_BYTES);
        randomx_cache* cache = randomx_create_cache(RANDOMX_FLAG_DEFAULT, (uint8_t*)cm);
        if (!cache) { fprintf(stderr, "rx0: create_cache failed\n"); return 2; }
        randomx_init_cache(cache, key, strlen(key));
        randomx_vm* vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, nullptr, (uint8_t*)sp, 0);
        if (!vm) { fprintf(stderr, "rx0: create_vm failed\n"); return 2; }
        uint8_t out[32]; randomx_calculate_hash(vm, input, strlen(input), out);
        std::string got = hex(out, 32);
        printf("RX0  xmrig = %s\n     expect = %s\n%s\n", got.c_str(), expect,
               got == expect ? "RX0 MATCH: build pipeline is faithful (v1 reference vector reproduced)"
                             : "RX0 MISMATCH: the build itself is wrong");
        return got == expect ? 0 : 1;
    }

    if (strcmp(argv[1], "--kat-full") == 0) {
        // Same KAT input, but FULL dataset + JIT (mode-invariance self-check vs --kat light-JIT).
        uint8_t seed[32]; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i + 1);
        const char* blob = "Shekyl RandomX v2 full-dataset parity KAT (Phase 3a, pin aaafe71)";
        randomx_apply_config(RandomX_MoneroConfigV2);
        void* cm = xalloc(4096, CACHE_BYTES); void* sp = xalloc(4096, SCRATCHPAD_BYTES);
        randomx_cache* cache = randomx_create_cache(RANDOMX_FLAG_JIT, (uint8_t*)cm);
        if (!cache) { cache = randomx_create_cache(RANDOMX_FLAG_DEFAULT, (uint8_t*)cm); }
        if (!cache) { fprintf(stderr, "katfull: create_cache failed\n"); return 2; }
        randomx_init_cache(cache, seed, 32);
        unsigned long items = randomx_dataset_item_count();
        void* dsmem = xalloc(4096, (size_t)items * DATASET_ITEM_BYTES);
        randomx_dataset* ds = randomx_create_dataset((uint8_t*)dsmem);
        if (!ds) { fprintf(stderr, "katfull: create_dataset failed\n"); return 2; }
        fprintf(stderr, "initializing full dataset (%lu items, ~%lu MiB)...\n", items, (unsigned long)((size_t)items*64/1048576));
        randomx_init_dataset(ds, cache, 0, items);
        randomx_vm* vm = randomx_create_vm((randomx_flags)(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_JIT), nullptr, ds, (uint8_t*)sp, 0);
        if (!vm) { fprintf(stderr, "katfull: create_vm failed\n"); return 2; }
        uint8_t out[32]; randomx_calculate_hash(vm, blob, strlen(blob), out);
        printf("KATFULL xmrig(full+JIT) = %s\n", hex(out, 32).c_str());
        return 0;
    }

    if (strcmp(argv[1], "--kat") == 0) {
        // LIGHT-JIT path on the frozen KAT — DEMONSTRATES XMRig's v2-incompleteness.
        // Its light-JIT hash is EXPECTED to diverge from the full-dataset canonical
        // (34f8b017…); use --kat-full for the value that actually matches. If this ever
        // stops diverging, XMRig's light path changed and the Phase 0 finding needs review.
        uint8_t seed[32]; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i + 1); // 0x01..0x20
        const char* blob = "Shekyl RandomX v2 full-dataset parity KAT (Phase 3a, pin aaafe71)";
        const char* canonical = "34f8b0179159d837e463c17c8692c106d2d3536f7da325aeefeb3e22a136b651";
        randomx_apply_config(RandomX_MoneroConfigV2);
        void* cm = xalloc(4096, CACHE_BYTES); void* sp = xalloc(4096, SCRATCHPAD_BYTES);
        randomx_cache* cache = randomx_create_cache(RANDOMX_FLAG_DEFAULT, (uint8_t*)cm);
        if (!cache) { fprintf(stderr, "kat: create_cache failed\n"); return 2; }
        randomx_init_cache(cache, seed, 32);
        randomx_vm* vm = randomx_create_vm(RANDOMX_FLAG_JIT, cache, nullptr, (uint8_t*)sp, 0);
        if (!vm) { fprintf(stderr, "kat: create_vm failed\n"); return 2; }
        uint8_t out[32];
        randomx_calculate_hash(vm, blob, strlen(blob), out);
        std::string got = hex(out, 32);
        bool diverges = (got != canonical);
        printf("KAT  xmrig(light-JIT) = %s\n     canonical(full)  = %s\n%s\n", got.c_str(), canonical,
               diverges ? "light-JIT DIVERGES as expected (XMRig light path is v2-incomplete)"
                        : "UNEXPECTED MATCH: XMRig light path no longer diverges — revisit Phase 0 finding");
        return diverges ? 0 : 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("open corpus"); return 2; }

    char magic[8];
    rd_exact(f, magic, 8);
    if (memcmp(magic, "SKLPRTY1", 8) != 0) { fprintf(stderr, "bad magic\n"); return 2; }
    uint32_t seed_count = rd_u32(f);
    uint32_t data_per   = rd_u32(f);
    printf("corpus: %u seedhashes x %u blobs = %u pairs\n", seed_count, data_per, seed_count * data_per);

    // Select RandomX v2 the XMRig way: apply the MoneroV2 global config
    // (ProgramSize=384 + the four v2 tweaks). No per-VM V2 flag exists in XMRig.
    randomx_apply_config(RandomX_MoneroConfigV2);
    printf("applied RandomX_ConfigurationMoneroV2 (ProgramSize=%u)\n", RandomX_CurrentConfig.ProgramSize);

    // FULL-DATASET + JIT: the mode a real adversary mines with. XMRig's v2 is
    // mode-invariant with the fork ONLY in full mode (its light path is v2-incomplete),
    // so the ceiling comparison MUST use full dataset. One 2 GiB dataset, re-init per seedhash.
    void* cache_mem = xalloc(4096, CACHE_BYTES);
    void* scratchpad = xalloc(4096, SCRATCHPAD_BYTES);
    unsigned long items = randomx_dataset_item_count();
    void* ds_mem = xalloc(4096, (size_t)items * DATASET_ITEM_BYTES);
    randomx_dataset* ds = randomx_create_dataset((uint8_t*)ds_mem);
    if (!ds) { fprintf(stderr, "create_dataset failed\n"); return 2; }
    printf("full dataset: %lu items (~%lu MiB); %u seedhashes to init\n",
           items, (unsigned long)((size_t)items * DATASET_ITEM_BYTES / 1048576), seed_count);

    uint64_t total = 0, mism = 0;
    int shown = 0;

    for (uint32_t g = 0; g < seed_count; g++) {
        uint8_t seed[32];
        rd_exact(f, seed, 32);

        randomx_cache* cache = randomx_create_cache(RANDOMX_FLAG_JIT, (uint8_t*)cache_mem);
        if (!cache) cache = randomx_create_cache(RANDOMX_FLAG_DEFAULT, (uint8_t*)cache_mem);
        if (!cache) { fprintf(stderr, "create_cache failed\n"); return 2; }
        randomx_init_cache(cache, seed, 32);
        randomx_init_dataset(ds, cache, 0, items);
        randomx_release_cache(cache);
        randomx_vm* vm = randomx_create_vm((randomx_flags)(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_JIT),
                                           nullptr, ds, (uint8_t*)scratchpad, 0);
        if (!vm) { fprintf(stderr, "create_vm failed\n"); return 2; }

        for (uint32_t j = 0; j < data_per; j++) {
            uint32_t canon_idx = rd_u32(f);
            uint8_t canon[32];
            rd_exact(f, canon, 32);
            uint32_t len = rd_u32(f);
            std::vector<uint8_t> blob(len);
            if (len) rd_exact(f, blob.data(), len);

            uint8_t out[RANDOMX_HASH_SIZE];
            randomx_calculate_hash(vm, blob.data(), len, out);

            total++;
            if (memcmp(out, canon, 32) != 0) {
                mism++;
                if (shown < 8) {
                    printf("MISMATCH idx=%u seedgrp=%u blob=%u len=%u\n  xmrig=%s\n  canon=%s\n",
                           canon_idx, g, j, len, hex(out, 32).c_str(), hex(canon, 32).c_str());
                    shown++;
                }
            }
        }
        randomx_destroy_vm(vm); // cache already released after dataset init
        printf("  seedgroup %u done: %llu checked, %llu mismatch\n",
               g, (unsigned long long)total, (unsigned long long)mism); fflush(stdout);
    }
    randomx_release_dataset(ds);
    fclose(f);

    printf("\n=== RESULT: %llu pairs checked, %llu mismatches ===\n",
           (unsigned long long)total, (unsigned long long)mism);
    if (mism == 0) { printf("PASS: XMRig RandomX-v2 hash core == Shekyl canonical pins (byte-identical)\n"); return 0; }
    printf("FAIL: XMRig diverges from Shekyl canonical on %llu pairs\n", (unsigned long long)mism);
    return 1;
}
