// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// RPC facts shims — the C ABI the natively-served (Rust) daemon RPC methods
// read core state through (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.2, RK-D3).
//
// A shim reads; it decides nothing. Every POD here has a #[repr(C)] twin in
// rust/shekyl-daemon-rpc/src/ffi.rs whose layout is pinned both directions by
// tests/unit_tests/rpc_facts_ffi_roundtrip.cpp. Daemon-only: linked through
// the daemon image (shekyl-ffi + shekyl-daemon-rpc), never libshekyl_ffi.a.

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct core_rpc_handle core_rpc_handle;

enum {
    SHEKYL_RPC_FACTS_OK = 0,
    SHEKYL_RPC_FACTS_ERR_NULL = -1,       // null handle or null out pointer
    SHEKYL_RPC_FACTS_ERR_NOT_READY = -2,  // core not initialized
};

// Chain tip + the one build fact get_version reports (RK-1).
typedef struct shekyl_rpc_chain_tip_facts {
    uint64_t chain_height;      // top block height + 1
    uint8_t  top_hash[32];
    uint64_t target_height;     // raw core target; "0 when synchronized" is the handler's rule
    uint8_t  synchronized;
    uint8_t  release_build;     // SHEKYL_VERSION_IS_RELEASE
    uint8_t  reserved[6];
} shekyl_rpc_chain_tip_facts;

int shekyl_rpc_chain_tip(core_rpc_handle* h, shekyl_rpc_chain_tip_facts* out);

// One row of the hard-fork schedule.
typedef struct shekyl_rpc_hardfork_entry {
    uint8_t  version;
    uint8_t  reserved[7];
    uint64_t height;
} shekyl_rpc_hardfork_entry;

// Fills a C++-owned view of the schedule; release `*out_owner` with
// shekyl_rpc_hardforks_free once the rows have been copied out.
int shekyl_rpc_hardforks(core_rpc_handle* h,
    const shekyl_rpc_hardfork_entry** out, size_t* out_len, void** out_owner);
void shekyl_rpc_hardforks_free(void* owner);

// Layout-twin test hooks (no production callers; see the roundtrip test).
void shekyl_rpc_chain_tip_facts_test_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed);
int shekyl_rpc_chain_tip_facts_test_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed);

#ifdef __cplusplus
} // extern "C"
#endif
