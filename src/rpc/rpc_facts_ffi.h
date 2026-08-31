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
    SHEKYL_RPC_FACTS_ERR_INCONSISTENT = -4, // the store contradicted itself (logged which read)
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

// One requested transaction's answer (RK-4c). Every pointer borrows memory
// owned by the opaque owner the export returns.
//
// **Indexed by request position**: entry `i` answers txid `i`, and `where`
// says which store held it. The C++ handler instead batched a chain lookup,
// batched a pool lookup for the misses, then re-sorted the two into request
// order — a merge that carried its own failure modes ("tx hash mismatch",
// "internal error - txs is empty") for a reply shape that had none. Answering
// per request slot deletes the merge, and those errors with it.
//
// `pruned` / `prunable` are the consensus encoding split as the store holds
// it; `prunable_len == 0` means the daemon has no prunable half. Which of
// them the wire shows, and in what form, is the handler's `(split, prune,
// decode_as_json)` matrix — the shim reads, it does not decide.
typedef struct shekyl_rpc_tx_entry {
    const uint8_t*  pruned;
    size_t          pruned_len;
    const uint8_t*  prunable;
    size_t          prunable_len;
    // Chain only. A chain transaction always has these: one found without an
    // index record beside it is an inconsistent store, refused rather than
    // reported with an empty list.
    const uint64_t* output_indices;
    size_t          output_indices_len;
    uint64_t        block_height;        // chain only
    uint64_t        block_timestamp;     // chain only
    uint64_t        received_timestamp;  // pool only
    uint8_t         prunable_hash[32];
    uint8_t         where;               // 0 = not found, 1 = chain, 2 = pool
    uint8_t         pruned_flag;         // chain: the store holds no verification data
    uint8_t         double_spend_seen;   // pool only
    uint8_t         relayed;             // pool only
    uint8_t         reserved[4];
} shekyl_rpc_tx_entry;

// Transactions by hash, answered per request slot (RK-4c).
//
// `txids` is `txids_len * 32` bytes. `include_sensitive` is the pool's own
// flag: 0 withholds a transaction that is not `relay_category::broadcasted`,
// which is what a restricted listener must send (§2.2). It is the caller's
// decision, not this shim's.
//
// `out_chain_height` is the tip, read **once** for the whole gather, so every
// entry's confirmations are computed against one height rather than a height
// per transaction that could move between them.
//
// No lock spans the chain and pool reads. The pool takes `m_transactions_lock`
// before `m_blockchain`, so a chain lock held across a pool read would be the
// AB half of an AB-BA deadlock; this matches the C++ handler's granularity and
// the resulting race is the one it already had (§3.2).
int shekyl_rpc_transactions(core_rpc_handle* h, const uint8_t* txids, size_t txids_len,
    uint8_t include_sensitive, const shekyl_rpc_tx_entry** out, size_t* out_len,
    uint64_t* out_chain_height, void** out_owner);
void shekyl_rpc_transactions_free(void* owner);

// epee's JSON rendering of one transaction (RK-D11), which stays in C++ for
// the reason `get_block`'s `json` does: it duplicates the consensus encoding
// the caller already has, and a second renderer would have to agree with this
// one. Takes no handle and no lock — it parses a blob the caller already
// holds — so the *decision* to render stays in the Rust handler and only the
// rendering is here.
int shekyl_rpc_tx_to_json(const uint8_t* blob, size_t blob_len, uint8_t pruned,
    const char** out, size_t* out_len, void** out_owner);
void shekyl_rpc_tx_json_free(void* owner);

// Key images, answered per request slot (RK-4c). `key_images` is `count * 32`
// bytes and `out_status` is a caller-provided array of `count` bytes: 0
// unspent, 1 spent in the chain, 2 spent in the pool. Fixed size, so no owner.
//
// The pool half filters on `relay_category::broadcasted` unconditionally, so a
// transaction that has not been broadcast never answers 2 — that path never
// had the disclosure the pool reads did (§7, 2026-08-26).
int shekyl_rpc_key_images_spent(core_rpc_handle* h, const uint8_t* key_images,
    size_t count, uint8_t* out_status);

// ── RK-5a: the p2p seam ─────────────────────────────────────────────────────
//
// `m_p2p` cannot be doubled, so these exports are the rule's other half: the
// thin `extern "C"` adapter is the *only* thing that touches it, and it does
// nothing but transcribe. Every derived quantity the retired C++ handlers
// computed inline — idle times, live time, KiB/s averages, the state name,
// peer-id and connection-id renderings, the ipv4-only `ip`/`port` strings,
// the block-queue overview — is computed in Rust from the raw fields below,
// where a unit test can reach it without a network.

// Process start plus the global throttle counters.
//
// The one export with no free-function body: five scalars with no
// classification between them. Splitting it would produce a function whose
// test could only restate its own inputs.
typedef struct shekyl_rpc_net_stats_facts {
    uint64_t start_time;         // unix seconds, the core's start
    uint64_t total_packets_in;
    uint64_t total_bytes_in;
    uint64_t total_packets_out;
    uint64_t total_bytes_out;
} shekyl_rpc_net_stats_facts;

int shekyl_rpc_net_stats(core_rpc_handle* h, shekyl_rpc_net_stats_facts* out);

// One live p2p connection, raw.
//
// `started` / `last_recv` / `last_send` are absolute unix seconds and the
// counters are absolute totals: the *elapsed* quantities the wire carries are
// derived in Rust against the single `now` this export reports beside the
// list. The C++ this replaces read the clock **twice** per connection — once
// for the idle times and again for the averages — so a connection could
// report a `live_time` that disagreed with the divisor its own averages used.
// One clock read for the whole snapshot makes that unrepresentable.
typedef struct shekyl_rpc_connection_facts {
    // `network_address::str()` — "host:port" for ipv4, the onion for tor.
    const char*  address;
    size_t       address_len;
    // `network_address::host_str()` — the host alone.
    const char*  host;
    size_t       host_len;
    uint64_t     peer_id;              // rendered as hex by the caller
    uint8_t      connection_id[16];    // raw uuid; hex is the caller's job
    uint64_t     started;              // unix seconds
    uint64_t     last_recv;            // unix seconds; 0 if never
    uint64_t     last_send;            // unix seconds; 0 if never
    uint64_t     recv_count;           // bytes, absolute
    uint64_t     send_count;           // bytes, absolute
    uint64_t     current_speed_down;   // bytes/s, truncated from the double
    uint64_t     current_speed_up;     // bytes/s, truncated from the double
    uint64_t     height;               // the peer's claimed blockchain height
    uint32_t     support_flags;
    uint32_t     pruning_seed;
    uint16_t     port;                 // `network_address::port()`, 0 if none
    uint8_t      state;                // cryptonote_connection_context::state
    uint8_t      address_type;         // epee type id: 1 ipv4, 2 ipv6, 4 tor…
    uint8_t      incoming;
    uint8_t      localhost;
    uint8_t      local_ip;
    uint8_t      reserved[9];
} shekyl_rpc_connection_facts;

// Fills a C++-owned view of the live connections and the instant they were
// read at; release `*out_owner` with `shekyl_rpc_connections_free`.
int shekyl_rpc_connections(core_rpc_handle* h, uint64_t* out_now,
    const shekyl_rpc_connection_facts** out, size_t* out_len, void** out_owner);
void shekyl_rpc_connections_free(void* owner);

// One span in the block-download queue.
//
// `rate` and `speed_fraction` cross as floats and are rounded by the caller.
// The C++ rounded with `(uint32_t)(x + 0.5f)`, which is undefined for a
// negative or out-of-range value; the Rust rounding is total, and the ×100
// that turns `speed_fraction` into the wire's percentage goes with it.
typedef struct shekyl_rpc_sync_span_facts {
    const char*  remote_address;       // `network_address::str()` of the origin
    size_t       remote_address_len;
    uint64_t     start_block_height;
    uint64_t     nblocks;
    uint64_t     size;                 // bytes held for this span
    uint8_t      connection_id[16];    // raw uuid; hex is the caller's job
    float        rate;                 // bytes/s
    float        speed_fraction;       // 0..1; the wire carries 100x this
    // Whether the span's blocks have **arrived**, as opposed to being
    // requested and still outstanding. Exported rather than inferred from
    // `size`: the overview rendering branches on exactly this bit, and
    // "size == 0" is a different question that happens to agree today.
    uint8_t      filled;
    uint8_t      reserved[7];
} shekyl_rpc_sync_span_facts;

// The p2p facts `sync_info` needs that are not connections and not the chain
// tip: the download queue and the stripe the node wants next. Release
// `*out_owner` with `shekyl_rpc_sync_spans_free`.
//
// `next_needed_pruning_stripe` is a **stripe**, not a seed — the wire field
// it feeds is named `next_needed_pruning_seed`, which is an inherited
// misnomer the caller carries deliberately (see the cutover doc's §7).
int shekyl_rpc_sync_spans(core_rpc_handle* h, uint32_t* out_next_needed_pruning_stripe,
    const shekyl_rpc_sync_span_facts** out, size_t* out_len, void** out_owner);
void shekyl_rpc_sync_spans_free(void* owner);

// One peerlist entry, white or gray.
//
// The three address arms differ in what `host` means — the ip string for
// ipv4, `host_str()` for ipv6, the whole `str()` for anything else — so the
// adapter resolves them here, where the epee type dispatch has to live, and
// the caller has no branch left to get wrong.
typedef struct shekyl_rpc_peer_facts {
    const char*  host;
    size_t       host_len;
    uint64_t     id;
    uint64_t     last_seen;
    uint32_t     ip;                   // ipv4 only, host byte order; else 0
    uint32_t     pruning_seed;
    uint16_t     port;                 // 0 for the address arms that carry none
    uint8_t      white;                // 1 = white list, 0 = gray
    // Filled unconditionally, so the `include_blocked` policy is the caller's
    // to apply. The C++ skipped the check when the request asked to include
    // blocked peers; this takes the host-blocked lock once per entry either
    // way, which is the price of moving a request policy out of the facts.
    uint8_t      blocked;
    uint8_t      reserved[4];
} shekyl_rpc_peer_facts;

// `public_only` selects `get_public_peerlist` over `get_peerlist`; it is a
// different p2p call, not a filter, so it cannot move to the caller. Release
// `*out_owner` with `shekyl_rpc_peer_list_free`.
int shekyl_rpc_peer_list(core_rpc_handle* h, uint8_t public_only,
    const shekyl_rpc_peer_facts** out, size_t* out_len, void** out_owner);
void shekyl_rpc_peer_list_free(void* owner);

// ── Constants the console renders with ──────────────────────────────────────
//
// Neither takes a handle, and that is what makes them usable: `shekyld
// <command>` runs this same binary against a *remote* daemon, with no core to
// ask, so anything the renderer needs from C++ configuration has to be
// reachable without one. They cross rather than being restated in Rust
// because a duplicated constant is the drift this cutover deletes rather than
// synchronizes.

// The two peerlist capacities `print_peer_list_stats` reports a fraction of.
void shekyl_rpc_peerlist_limits(uint32_t* out_white, uint32_t* out_gray);

// The stripe label `sync_info` prints beside a span:
// `tools::get_pruning_seed(start_block_height, UINT64_MAX, LOG_STRIPES)`.
// `UINT64_MAX` is the sentinel the console has always passed — it means "not
// in the tip window", so the answer is a pure function of the height. Behind
// it are `make_pruning_seed`'s bit layout and three `cryptonote_config.h`
// constants, none of which gets a second definition.
uint32_t shekyl_rpc_span_pruning_seed(uint64_t start_block_height);

// Layout-twin test hooks (no production callers; see the roundtrip test).
void shekyl_rpc_chain_tip_facts_test_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed);
int shekyl_rpc_chain_tip_facts_test_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed);
void shekyl_rpc_hardfork_entry_test_fill(shekyl_rpc_hardfork_entry* out, uint64_t seed);
int shekyl_rpc_hardfork_entry_test_check(const shekyl_rpc_hardfork_entry* entry, uint64_t seed);
void shekyl_rpc_block_hash_facts_test_fill(shekyl_rpc_block_hash_facts* out, uint64_t seed);
int shekyl_rpc_block_hash_facts_test_check(const shekyl_rpc_block_hash_facts* facts, uint64_t seed);
void shekyl_rpc_net_stats_facts_test_fill(shekyl_rpc_net_stats_facts* out, uint64_t seed);
int shekyl_rpc_net_stats_facts_test_check(const shekyl_rpc_net_stats_facts* facts, uint64_t seed);
// The three RK-5a list PODs carry pointers, which have no seed value to fill
// and compare, so they are pinned by layout instead — see
// `rpc_facts_ffi_roundtrip.cpp`, as `shekyl_rpc_tx_entry` is.
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
// **The seam's rule, settled in RK-5a.** A body takes what a fixture can
// build as objects (`Blockchain&`, the pool) and everything else — the p2p
// reads, the build-time constants — **as scalars the adapter snapshots**.
// This is not a convenience: `m_p2p` is a concrete
// `node_server<t_cryptonote_protocol_handler<cryptonote::core>>`, not an
// interface, so nothing can subclass it, and the one `node_server` harness in
// the tree (tests/unit_tests/node_server.cpp) instantiates the template on
// `test_core` — a different type, not a double for this one. A p2p double
// cannot be built, so the p2p facts arrive as plain integers a test supplies
// and the thin `extern "C"` adapter is the only thing that touches `m_p2p`.
//
// `shekyl_rpc_chain_tip` was the one export with no fixture, written before
// this shape existed; RK-5a retrofitted it, and it is now the smallest
// example of the rule.

#include "crypto/hash.h"

namespace cryptonote { class Blockchain; class core; class tx_memory_pool; }

namespace daemon_rpc_facts {

int chain_tip(cryptonote::Blockchain& bc, uint8_t synchronized,
    uint64_t target_height, shekyl_rpc_chain_tip_facts* out) noexcept;

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

// Declared for the same reason as its five siblings above: the extern "C"
// entry point needs a live `core_rpc_handle`, so the store-fault paths are
// only reachable from a test through the `Blockchain&` form. Free the owner
// with `shekyl_rpc_transactions_free`.
int transactions(cryptonote::Blockchain& bc, cryptonote::tx_memory_pool& pool,
    const uint8_t* txids, size_t txids_len, uint8_t include_sensitive,
    const shekyl_rpc_tx_entry** out, size_t* out_len, uint64_t* out_chain_height,
    void** out_owner) noexcept;

// Same reason: the chain-then-pool status mapping and its slot re-association
// are only reachable from a test through the `Blockchain&` / pool form.
int key_images_spent(cryptonote::Blockchain& bc, cryptonote::tx_memory_pool& pool,
    const uint8_t* key_images, size_t count, uint8_t* out_status) noexcept;

} // namespace daemon_rpc_facts

#endif // __cplusplus
