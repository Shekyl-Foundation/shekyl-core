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

// The block-header projection (RK-3): every field of the wire's
// `block_header_response` in raw form — hashes as bytes, the 128-bit
// difficulties as (lo, hi) pairs — leaving hex and the wide-decimal
// rendering to Rust. One call per header, so the block, its weights and its
// difficulties come from one acquisition of the chain lock.
typedef struct shekyl_rpc_block_header_facts {
    uint8_t  hash[32];
    uint8_t  prev_hash[32];
    uint8_t  miner_tx_hash[32];
    uint8_t  curve_tree_root[32];
    uint8_t  attestation_root[32];
    uint8_t  pow_hash[32];        // zero unless pow_hash_filled
    uint64_t height;
    uint64_t depth;               // chain_height - height - 1
    uint64_t chain_height;        // so a refusal can name the top height
    uint64_t timestamp;
    uint64_t difficulty_lo;
    uint64_t difficulty_hi;
    uint64_t cumulative_difficulty_lo;
    uint64_t cumulative_difficulty_hi;
    uint64_t reward;              // sum of the miner tx's outputs
    uint64_t block_weight;
    uint64_t long_term_weight;
    uint64_t num_txes;
    uint32_t nonce;
    uint8_t  major_version;
    uint8_t  minor_version;
    uint8_t  orphan_status;
    uint8_t  pow_hash_filled;
    uint8_t  found;               // 0 iff height >= chain_height (past the tip)
    uint8_t  reserved[7];
} shekyl_rpc_block_header_facts;

// `fill_pow_hash` is the caller's request AND its right to ask (the
// restricted listener never sets it): computing the long hash is the
// expensive part of this call and is skipped unless asked.
int shekyl_rpc_block_header_at(core_rpc_handle* h, uint64_t height,
    uint8_t fill_pow_hash, shekyl_rpc_block_header_facts* out);

// The variable-length half of a block's facts (RK-3b): the three payloads
// whose size the caller cannot know in advance. Allocated by C++, owned by
// the opaque `owner` the export hands back, and released as one unit by
// `shekyl_rpc_block_free` — the `shekyl_rpc_hardforks` shape, which §3.2
// states as the rule for every variable-length payload.
//
// `json` is epee's rendering of the whole block (RK-D11). It crosses as an
// opaque string and Rust passes it through untouched; matching that renderer
// in Rust would mean reimplementing it over the entire transaction structure,
// to match something already queued for deletion.
typedef struct shekyl_rpc_block_payload {
    const uint8_t* blob;      // consensus-encoded block bytes; hex is Rust's job
    size_t         blob_len;
    const char*    json;      // epee's `obj_to_json_str(blk)`, carried verbatim
    size_t         json_len;
    const uint8_t* tx_hashes; // tx_hashes_len * 32 contiguous bytes
    size_t         tx_hashes_len;  // number of hashes, NOT bytes
} shekyl_rpc_block_payload;

// A whole block, by hash or by height (RK-3b).
//
// `block_hash` selects the lookup: 32 bytes to reach a block by hash — which
// may be an alt block, so `out_header->orphan_status` is a real value here
// and not the constant it is for `shekyl_rpc_block_header_at` — or NULL to
// reach the block at `height`.
//
// `out_header->found == 0` means no such block, and `chain_height` is set
// either way: past the tip and an unknown hash are both legitimate query
// outcomes, and the caller knows which it asked for. A block whose coinbase
// is not a single `txin_gen` is `ERR_INCONSISTENT` — that is a broken block,
// not a missing one.
//
// On OK with `found == 1` the payload is set and `*out_owner` must be passed
// to `shekyl_rpc_block_free`; on every other outcome the owner is NULL and
// there is nothing to release.
int shekyl_rpc_block_at(core_rpc_handle* h, const uint8_t* block_hash,
    uint64_t height, uint8_t fill_pow_hash,
    shekyl_rpc_block_header_facts* out_header,
    shekyl_rpc_block_payload* out_payload, void** out_owner);
void shekyl_rpc_block_free(void* owner);

// The global output indices of one transaction (RK-4a). Variable-length, so
// it follows §3.2's rule: C++ allocates, the caller gets (pointer, length,
// opaque owner), and `shekyl_rpc_tx_output_indices_free` releases it.
//
// `found` is 0 when the store has no such transaction — a legitimate query
// outcome, not a fault, and the one the wire reports as a non-OK status. A
// transaction that exists with no outputs recorded yet is `found = 1` with
// `len == 0`, which is a different answer and must stay distinguishable.
int shekyl_rpc_tx_output_indices(core_rpc_handle* h, const uint8_t* txid,
    const uint64_t** out, size_t* out_len, uint8_t* out_found, void** out_owner);
void shekyl_rpc_tx_output_indices_free(void* owner);

// One block of a `/get_blocks_by_height.bin` answer (RK-4b). Every pointer
// borrows memory owned by the opaque owner the export returns.
//
// `txs` is an array of `tx_count` pointers with matching lengths in
// `tx_lens` — the transactions of this block, in block order, as consensus
// blobs. The wire drops each transaction's prunable hash on this endpoint
// (the C++ map serializes a plain blob vector when `pruned` is false), so
// there is nothing else per transaction to carry.
typedef struct shekyl_rpc_block_entry {
    const uint8_t*        block;
    size_t                block_len;
    const uint8_t* const* txs;
    const size_t*         tx_lens;
    size_t                tx_count;
} shekyl_rpc_block_entry;

// Blocks at the given heights, in the order asked (RK-4b).
//
// On OK with `*out_ok == 1` the view holds `heights_len` entries and
// `*out_owner` must be released with `shekyl_rpc_blocks_by_height_free`.
// When a height cannot be read the answer is `*out_ok == 0` with
// `*out_failed_height` naming it — and the blocks gathered *before* it are
// still returned, with an owner to release. The C++ cleared its block list
// once before its loop and returned from the failure without clearing
// again, so `[0, past_tip]` carried block 0 alongside the error; the prefix
// is part of that reply, not debris.
//
// The restricted-listener block cap is NOT applied here: it is handler
// policy, single-sourced in Rust (RK-D6), and this export answers what it
// is asked.
int shekyl_rpc_blocks_by_height(core_rpc_handle* h, const uint64_t* heights,
    size_t heights_len, const shekyl_rpc_block_entry** out, size_t* out_len,
    uint64_t* out_failed_height, uint8_t* out_ok, void** out_owner);
void shekyl_rpc_blocks_by_height_free(void* owner);

// Layout-twin test hooks (no production callers; see the roundtrip test).
void shekyl_rpc_chain_tip_facts_test_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed);
int shekyl_rpc_chain_tip_facts_test_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed);
void shekyl_rpc_hardfork_entry_test_fill(shekyl_rpc_hardfork_entry* out, uint64_t seed);
int shekyl_rpc_hardfork_entry_test_check(const shekyl_rpc_hardfork_entry* entry, uint64_t seed);
void shekyl_rpc_block_hash_facts_test_fill(shekyl_rpc_block_hash_facts* out, uint64_t seed);
int shekyl_rpc_block_hash_facts_test_check(const shekyl_rpc_block_hash_facts* facts, uint64_t seed);
void shekyl_rpc_block_header_facts_test_fill(shekyl_rpc_block_header_facts* out, uint64_t seed);
int shekyl_rpc_block_header_facts_test_check(const shekyl_rpc_block_header_facts* facts, uint64_t seed);

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

#include "crypto/hash.h"

namespace cryptonote { class Blockchain; class core; }

namespace daemon_rpc_facts {

int block_hash_at(cryptonote::Blockchain& bc, uint64_t height,
    shekyl_rpc_block_hash_facts* out) noexcept;

int block_header_at(cryptonote::Blockchain& bc, uint64_t height,
    bool fill_pow_hash, shekyl_rpc_block_header_facts* out) noexcept;

int tx_output_indices(cryptonote::Blockchain& bc, const crypto::hash& txid,
    const uint64_t** out, size_t* out_len, uint8_t* out_found, void** out_owner) noexcept;

int blocks_by_height(cryptonote::Blockchain& bc, const uint64_t* heights, size_t heights_len,
    const shekyl_rpc_block_entry** out, size_t* out_len, uint64_t* out_failed_height,
    uint8_t* out_ok, void** out_owner) noexcept;

int block_at(cryptonote::Blockchain& bc, const crypto::hash* block_hash,
    uint64_t height, bool fill_pow_hash,
    shekyl_rpc_block_header_facts* out_header,
    shekyl_rpc_block_payload* out_payload, void** out_owner) noexcept;

} // namespace daemon_rpc_facts

#endif // __cplusplus
