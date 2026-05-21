/*
 * Copyright (c) 2025-2026, The Shekyl Foundation
 *
 * All rights reserved.
 * BSD-3-Clause
 */

/*
 * Argon2d reference-bytes generator for `shekyl-pow-randomx` tests.
 *
 * Compiled against the v2 fork's reference Argon2 implementation at
 * pin `aaafe71` (`external/randomx-v2/src/argon2_*.c`,
 * `blake2/blake2b.c`) to produce derived test vectors that
 * `shekyl-pow-randomx`'s `src/argon2d.rs` tests assert byte-for-byte
 * against. Per `docs/design/RANDOMX_V2_RUST.md` §3 "Spec Is the Source
 * of Truth", `specs.md` is normative and `argon2_ref.c` is the
 * cross-check; this generator instantiates the C cross-check.
 *
 * Build: see the sibling Makefile.
 *
 * Usage:
 *   ./gen raw   <m_cost> <t_cost> <p_cost> <key> > vector.bin
 *   ./gen blake <m_cost> <t_cost> <p_cost> <key> > fingerprint.bin
 *
 * "raw" mode writes all `m_cost` 1 KiB memory blocks to stdout
 * (`m_cost * 1024` bytes total) after the omit-finalizer fill defined
 * in `external/randomx-v2/doc/specs.md` §7.1.
 *
 * "blake" mode writes the 64-byte Blake2b-512 fingerprint of those
 * memory blocks to stdout. Used for the RandomX-full-parameter
 * vector to keep the committed file size manageable (64 bytes rather
 * than 256 MiB).
 *
 * In both modes the salt is hardcoded to `RANDOMX_ARGON_SALT =
 * "RandomX\x03"` per `configuration.md`; only the algorithm
 * parameters and key vary. This matches the production
 * `shekyl-pow-randomx::argon2d::fill_cache` surface, which also fixes
 * the salt.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"
#include "argon2_core.h"
#include "blake2/blake2.h"

/*
 * Argon2 implementation used: the v2 fork's reference (portable)
 * impl in `argon2_ref.c`. Pinning this here (rather than at the SSSE3
 * or AVX2 variants) keeps the produced bytes architecture-independent
 * and reproducible on any platform with a C compiler.
 */
extern void randomx_argon2_fill_segment_ref(const argon2_instance_t *instance,
                                            argon2_position_t position);

/*
 * Hardcoded RandomX Argon2 salt per `configuration.md` Table:
 * RANDOMX_ARGON_SALT = "RandomX\x03". The trailing 0x03 is the v2
 * salt-version byte. 8 bytes total.
 */
static const uint8_t RANDOMX_ARGON_SALT_BYTES[8] = {
    'R', 'a', 'n', 'd', 'o', 'm', 'X', 0x03,
};
#define RANDOMX_ARGON_SALT_LEN 8

#define ARGON_SYNC_POINTS 4 /* Argon2 spec; also `ARGON2_SYNC_POINTS` in core.h */

static int run_argon2_fill(uint32_t m_cost,
                           uint32_t t_cost,
                           uint32_t p_cost,
                           const uint8_t *key,
                           size_t key_len,
                           block **out_memory) {
    *out_memory = NULL;

    block *memory = (block *)calloc((size_t)m_cost, sizeof(block));
    if (!memory) {
        fprintf(stderr, "calloc failed for %u blocks\n", m_cost);
        return 1;
    }

    argon2_context context;
    memset(&context, 0, sizeof(context));
    context.out = NULL;
    context.outlen = 0; /* omit-finalizer per RandomX spec §7.1 */
    context.pwd = (uint8_t *)key;
    context.pwdlen = (uint32_t)key_len;
    context.salt = (uint8_t *)RANDOMX_ARGON_SALT_BYTES;
    context.saltlen = RANDOMX_ARGON_SALT_LEN;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = p_cost;
    context.threads = 1;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = ARGON2_VERSION_NUMBER;

    int rc = randomx_argon2_validate_inputs(&context);
    if (rc != ARGON2_OK) {
        fprintf(stderr, "validate_inputs failed: %d\n", rc);
        free(memory);
        return 1;
    }

    argon2_instance_t instance;
    memset(&instance, 0, sizeof(instance));
    instance.version = context.version;
    instance.memory = memory;
    instance.passes = context.t_cost;
    instance.memory_blocks = m_cost;
    instance.segment_length = m_cost / (p_cost * ARGON_SYNC_POINTS);
    instance.lane_length = instance.segment_length * ARGON_SYNC_POINTS;
    instance.lanes = p_cost;
    instance.threads = 1;
    instance.type = Argon2_d;
    instance.impl = &randomx_argon2_fill_segment_ref;
    instance.context_ptr = &context;

    rc = randomx_argon2_initialize(&instance, &context);
    if (rc != ARGON2_OK) {
        fprintf(stderr, "initialize failed: %d\n", rc);
        free(memory);
        return 1;
    }

    rc = randomx_argon2_fill_memory_blocks(&instance);
    if (rc != ARGON2_OK) {
        fprintf(stderr, "fill_memory_blocks failed: %d\n", rc);
        free(memory);
        return 1;
    }

    *out_memory = memory;
    return 0;
}

static int write_raw(const block *memory, uint32_t m_cost) {
    size_t total_bytes = (size_t)m_cost * sizeof(block);
    size_t written = fwrite(memory, 1, total_bytes, stdout);
    if (written != total_bytes) {
        fprintf(stderr, "fwrite raw: %zu of %zu\n", written, total_bytes);
        return 1;
    }
    return 0;
}

static int write_blake(const block *memory, uint32_t m_cost) {
    uint8_t fingerprint[64];
    size_t total_bytes = (size_t)m_cost * sizeof(block);
    int rc = randomx_blake2b(fingerprint, sizeof(fingerprint),
                             memory, total_bytes, NULL, 0);
    if (rc != 0) {
        fprintf(stderr, "blake2b failed: %d\n", rc);
        return 1;
    }
    size_t written = fwrite(fingerprint, 1, sizeof(fingerprint), stdout);
    if (written != sizeof(fingerprint)) {
        fprintf(stderr, "fwrite blake: %zu of %zu\n", written, sizeof(fingerprint));
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr,
                "Usage: %s {raw|blake} <m_cost> <t_cost> <p_cost> <key>\n",
                argv[0]);
        return 2;
    }

    const char *mode = argv[1];
    uint32_t m_cost = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t t_cost = (uint32_t)strtoul(argv[3], NULL, 10);
    uint32_t p_cost = (uint32_t)strtoul(argv[4], NULL, 10);
    const char *key = argv[5];
    size_t key_len = strlen(key);

    block *memory = NULL;
    int rc = run_argon2_fill(m_cost, t_cost, p_cost,
                             (const uint8_t *)key, key_len, &memory);
    if (rc != 0) {
        return rc;
    }

    if (strcmp(mode, "raw") == 0) {
        rc = write_raw(memory, m_cost);
    } else if (strcmp(mode, "blake") == 0) {
        rc = write_blake(memory, m_cost);
    } else {
        fprintf(stderr, "unknown mode: %s (expected 'raw' or 'blake')\n", mode);
        rc = 2;
    }

    free(memory);
    return rc;
}
