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
    SHEKYL_RPC_FACTS_ERR_INTERNAL = -3,   // a core/P2P read threw; logged, never propagated across the C ABI
    SHEKYL_RPC_FACTS_ERR_INCONSISTENT = -4, // the store reported a height it cannot produce the block for
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

// Block hash at a height, with the tip as of the same read (RK-2), so a
// refusal can name the top height without a second call.
typedef struct shekyl_rpc_block_hash_facts {
    uint8_t  hash[32];
    uint64_t chain_height;   // top block height + 1
    uint8_t  found;          // 0 iff height >= chain_height; hash is then zero. An
                             // in-range height that resolves to nothing is
                             // SHEKYL_RPC_FACTS_ERR_INCONSISTENT, never found == 0.
    uint8_t  reserved[7];
} shekyl_rpc_block_hash_facts;

int shekyl_rpc_block_hash_at(core_rpc_handle* h, uint64_t height,
    shekyl_rpc_block_hash_facts* out);

// Layout-twin test hooks (no production callers; see the roundtrip test).
void shekyl_rpc_chain_tip_facts_test_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed);
int shekyl_rpc_chain_tip_facts_test_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed);
void shekyl_rpc_hardfork_entry_test_fill(shekyl_rpc_hardfork_entry* out, uint64_t seed);
int shekyl_rpc_hardfork_entry_test_check(const shekyl_rpc_hardfork_entry* entry, uint64_t seed);
void shekyl_rpc_block_hash_facts_test_fill(shekyl_rpc_block_hash_facts* out, uint64_t seed);
int shekyl_rpc_block_hash_facts_test_check(const shekyl_rpc_block_hash_facts* facts, uint64_t seed);

#ifdef __cplusplus
} // extern "C"

// The exports' bodies, over the core objects they read. Same shape as
// `daemon_submit::snapshot_facts` (daemon_submit_ffi.h): the extern "C" entry
// point unwraps the handle and delegates here, so the logic — the lock, the
// reads, and the classification — is reachable from a unit test with a
// controlled chain (tests/unit_tests/rpc_facts_shims.cpp) instead of needing
// a core_rpc_server. A facts export shaped as one opaque block would be
// testable only through a live daemon; new exports take this shape.
//
// `shekyl_rpc_chain_tip` is not split this way yet: it reads
// `is_synchronized()` off the p2p payload object, for which this tree has no
// test double, so splitting it would move the untestable dependency rather
// than remove it. It is covered by the live daemon check until a p2p double
// exists (RK-5 builds one for `get_info`, which needs the same object).

namespace cryptonote { class Blockchain; }

namespace daemon_rpc_facts {

int block_hash_at(cryptonote::Blockchain& bc, uint64_t height,
    shekyl_rpc_block_hash_facts* out) noexcept;

} // namespace daemon_rpc_facts

#endif // __cplusplus
