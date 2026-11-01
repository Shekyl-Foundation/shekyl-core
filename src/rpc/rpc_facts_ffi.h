// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// RPC facts shims — the C ABI the natively-served (Rust) daemon RPC methods
// read core state through (docs/completed/DAEMON_RPC_KV_CUTOVER.md §3.2, RK-D3).
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
    uint64_t target_height;     // raw core target; the handlers do not rewrite it when synchronized
    uint8_t  synchronized;
    uint8_t  release_build;     // shekyl_version::IS_RELEASE, supplied by the Rust node (DC-Q20)
    uint8_t  reserved[6];
} shekyl_rpc_chain_tip_facts;


// Daemon identity: what this process IS, as opposed to what its chain tip
// looks like right now (VC-2). Deliberately its own POD rather than two more
// fields on `shekyl_rpc_chain_tip_facts` (VC-R17): `nettype` and the genesis
// hash are fixed at startup and per network, five of the tip POD's six
// callers want a tip and not identity, and widening the tip would move its
// layout twins, its seeded fill indices and its size pin for every one of
// them. The precedent is the narrow exports below.
//
// The rules digest is NOT here: it is compiled into the Rust image from
// `config/`, so the handler reads its own constant and never asks C++ for it.
typedef struct shekyl_rpc_identity_facts {
    uint8_t  nettype;           // cryptonote::network_type (MAINNET=0 .. FAKECHAIN=3)
    uint8_t  reserved[7];
    uint8_t  genesis_hash[32];  // block 0's id
} shekyl_rpc_identity_facts;


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


// The block-header projection (RK-3): every field of the wire's header in
// raw form — hashes as bytes, the 128-bit difficulties as (lo, hi) pairs —
// leaving hex and the wide-decimal rendering to Rust. The wire type is
// `shekyl_rpc_types::BlockHeader`; the C++ `block_header_response` it was
// first written against is deleted (RK-5b). One call per header, so the block, its weights and its
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
    // 0 means no such block, and only then: by height, `height >=
    // chain_height`; by hash, a hash this chain does not hold. Both are
    // legitimate query outcomes and the caller knows which it asked for.
    // An in-range height the store cannot produce is
    // SHEKYL_RPC_FACTS_ERR_INCONSISTENT, never found == 0 — the same
    // classification `shekyl_rpc_block_hash_at` states, and the one
    // `shekyl_rpc_block_at` states for a broken coinbase.
    uint8_t  found;
    uint8_t  reserved[7];
} shekyl_rpc_block_header_facts;

// The header projection alone, by hash or by height (RK-3; the hash selector
// is RK-5b's).
//
// `block_hash` selects the lookup exactly as `shekyl_rpc_block_at`'s does: 32
// bytes to reach a block by hash — which may be an alt block, so
// `out->orphan_status` is then a real value rather than the constant it is on
// the height path — or NULL to reach the block at `height`.
//
// **Header-only on purpose.** `shekyl_rpc_block_at` answers the same question
// and more, but it allocates its payloads before a caller can decline them,
// so a header-only reader would pay a block-blob copy and an
// `obj_to_json_str` render per block — and that `json` is already queued for
// deletion (see the payload struct below), so reading headers through it
// would add a consumer to a field on its way out. This export also has no
// owner to release, so there is no lifetime for a caller to get wrong.
//
// `fill_pow_hash` is the caller's request AND its right to ask (the
// restricted listener never sets it): computing the long hash is the
// expensive part of this call and is skipped unless asked.

// The variable-length half of a block's facts (RK-3b): the three payloads
// whose size the caller cannot know in advance. Allocated by C++, owned by
// the opaque `owner` the export hands back, and released as one unit by
// `shekyl_rpc_block_free`, which §3.2 states as the rule for every
// variable-length payload.
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
// may be an alt block, so `out_header->orphan_status` is a real value — or
// NULL to reach the block at `height`. `shekyl_rpc_block_header_at` takes the
// same selector and answers the header half of this question without the
// payloads.
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

// The global output indices of one transaction (RK-4a). Variable-length, so
// it follows §3.2's rule: C++ allocates, the caller gets (pointer, length,
// opaque owner), and `shekyl_rpc_tx_output_indices_free` releases it.
//
// `found` is 0 when the store has no such transaction — a legitimate query
// outcome, not a fault, and the one the wire reports as a non-OK status. A
// transaction that exists with no outputs recorded yet is `found = 1` with
// `len == 0`, which is a different answer and must stay distinguishable.

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

// epee's JSON rendering of one transaction (RK-D11), which stays in C++ for
// the reason `get_block`'s `json` does: it duplicates the consensus encoding
// the caller already has, and a second renderer would have to agree with this
// one. Takes no handle and no lock — it parses a blob the caller already
// holds — so the *decision* to render stays in the Rust handler and only the
// rendering is here.

// Key images, answered per request slot (RK-4c). `key_images` is `count * 32`
// bytes and `out_status` is a caller-provided array of `count` bytes: 0
// unspent, 1 spent in the chain, 2 spent in the pool. Fixed size, so no owner.
//
// The pool half filters on `relay_category::broadcasted` unconditionally, so a
// transaction that has not been broadcast never answers 2 — that path never
// had the disclosure the pool reads did (§7, 2026-08-26).

// ── RK-5a: the p2p seam ─────────────────────────────────────────────────────
//
// `m_p2p` cannot be doubled, so these exports are the rule's other half: the
// thin `extern "C"` adapter is the *only* thing that touches it, and it does
// nothing but transcribe. Every derived quantity the retired C++ handlers
// computed inline — idle times, live time, KiB/s averages, the state name,
// peer-id and connection-id renderings, the ipv4-only `ip`/`port` strings —
// is computed in Rust from the raw fields below,
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
// `started` is unix seconds at admission, from the board. `last_recv` and
// `last_send` are unix seconds of the last byte read or written
// (`shekyl_link_unix_ms`, milliseconds, divided by 1000), or 0 when that
// direction has not moved a byte. The stall check uses the monotonic
// stamps, not these. The counters are absolute totals: the *elapsed* quantities the wire carries are
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
    uint8_t      connection_id[16];    // raw uuid; hex is the caller's job
    uint64_t     started;              // unix seconds
    uint64_t     last_recv;            // unix seconds; 0 if never
    uint64_t     last_send;            // unix seconds; 0 if never
    uint64_t     recv_count;           // bytes, absolute
    uint64_t     send_count;           // bytes, absolute
    // Bytes/s, raw. Crossing as `double` rather than a truncated integer for
    // the reason every other derived value in this POD crosses raw: the
    // truncation is a computation, `static_cast<uint64_t>` of a NaN, an
    // infinity, a negative or an out-of-range value is undefined, and these
    // are the outputs of a rate estimator. The caller clamps.
    double       current_speed_down;
    double       current_speed_up;
    uint16_t     port;                 // `network_address::port()`, 0 if none
    uint8_t      address_type;         // epee type id: 1 ipv4, 2 ipv6, 4 tor…
    uint8_t      incoming;
    uint8_t      localhost;
    uint8_t      local_ip;
    /// The board's half only. The peer's claim and what chain sync is
    /// doing with the session are the sync owner's view (CS-5 §7).
    uint8_t      reserved[2];
} shekyl_rpc_connection_facts;

// Fills a C++-owned view of the live connections and the instant they were
// read at; release `*out_owner` with `shekyl_rpc_connections_free`.
int shekyl_rpc_connections(core_rpc_handle* h, uint64_t* out_now,
    const shekyl_rpc_connection_facts** out, size_t* out_len, void** out_owner);
void shekyl_rpc_connections_free(void* owner);

// ── RK-5b: the header remainder's two non-header facts ──────────────────────

// The dynamic base-fee estimate at the tip.
//
// One estimator: the 2021-scaling one. A function of chain state alone
// (FL-R20); the lattice a fee is rounded to is a Rust constant
// (shekyl_economics::FEE_QUANTIZATION_MASK) and does not cross here.
//
// `fees` is one slot per priced tier: [economy, standard, priority].
// `fee_count` reports what was actually written so a change in that
// contract is caught here rather than read as a shorter answer.
typedef struct shekyl_rpc_fee_estimate_facts {
    uint64_t fees[3];
    uint8_t  fee_count;
    uint8_t  reserved[7];
} shekyl_rpc_fee_estimate_facts;


// ── A constant the console renders with ─────────────────────────────────────
//
// It takes no handle, and that is what makes it usable: `shekyld <command>`
// runs this same binary against a *remote* daemon, with no core to ask, so
// anything the renderer needs from C++ configuration has to be reachable
// without one. It crosses rather than being restated in Rust because a
// duplicated constant is the drift this cutover deletes rather than
// synchronizes. (The two peerlist capacities crossed here until the lists
// moved to Rust, 2026-10-13; the console reads `shekyl-peerlist`'s now.)


// ── RK-5c: `get_info` ──────────────────────────────────────────────────────
//
// `get_info` is gathered by part (docs/design/DAEMON_RPC_KV_GET_INFO.md §4.2,
// RK-D24): a part the caller will not be shown is not read. So there is one
// export per unit of disclosure rather than one for the method, and the Rust
// handler calls only those its caller is entitled to.

// Health, identity, chain and the economics operands: read for every caller.
// Every member that comes from the chain store is read under ONE chain lock
// and carries its own tip (RK-D20), so a reply cannot pair one tip's hash with
// another tip's difficulty.
typedef struct shekyl_rpc_info_chain_facts {
    uint64_t chain_height;             // top block height + 1
    uint8_t  top_hash[32];
    uint64_t difficulty_lo;            // next block's difficulty, 128 bits
    uint64_t difficulty_hi;
    uint64_t cumulative_difficulty_lo; // at the tip, 128 bits
    uint64_t cumulative_difficulty_hi;
    uint64_t difficulty_target;        // seconds
    uint64_t total_transactions;       // coinbases included
    uint64_t block_weight_limit;
    uint64_t block_weight_median;
    uint64_t adjusted_time;
    uint64_t already_generated_coins;  // through the tip, atomic units
    uint64_t total_burned;
    uint64_t tx_volume_count_sum;      // the trailing volume window
    uint64_t tx_volume_blocks;
    uint64_t core_target_height;       // 0: the core has no target
    uint8_t  synchronized;             // the protocol's predicate, read once
    uint8_t  busy_syncing;
    uint8_t  offline;
    uint8_t  following_degraded;
    uint8_t  protocol_version;         // shekyl_version::PROTOCOL_VERSION, a Rust constant (DC-Q20)
    uint8_t  reserved[3];
} shekyl_rpc_info_chain_facts;


// The pool's population, as two counts of one pool state.
//
// `*out_broadcast` is the entries this node has broadcast: what every caller
// may be told. With `with_unbroadcast` non-zero, `*out_unbroadcast` is the
// entries it holds and has not yet broadcast, which is host-only data
// (RPC_CHANNEL.md §6.1, RT-O9.3) and is asked for only on behalf of a caller
// who may see it. Both are then counted under one hold of the pool's lock, so
// they describe one pool; a pool whose broadcast set is larger than the whole
// is ERR_INCONSISTENT. With `with_unbroadcast` zero the second count is not
// made and `out_unbroadcast` is not written (it may be null).

// Status facts, read only for a caller who is shown Status. The store's
// on-disk size is NOT here: a restricted reply still carries it, rounded, so
// it has its own read (`shekyl_rpc_info_store_file`).
typedef struct shekyl_rpc_info_status_facts {
    uint64_t start_time;
    uint64_t free_space;                   // of the data directory's volume
    uint64_t alt_blocks_count;
} shekyl_rpc_info_status_facts;

// The build's version string is not a fact this header carries: it is
// `shekyl_version::VERSION_FULL`, a Rust constant the node supplies in its
// identity (DC-Q20).

// Peers facts, read only for a caller who is shown Peers.
typedef struct shekyl_rpc_info_peers_facts {
    uint64_t public_incoming_sockets;
    uint64_t public_outgoing_sockets;
    uint64_t tor_incoming_sockets;
    uint64_t tor_outgoing_sockets;
} shekyl_rpc_info_peers_facts;


// The path of the chain store's data file, written to `path_buf`, not
// NUL-terminated, with its length in `*path_len`.
//
// This crosses instead of a size because the store's own size getter swallows
// the stat error and answers 0 — a zero that means "could not read". The Rust
// side stats the file itself and reports a failure as a fault. It is also the
// half that survives the store cutover: the Rust store names its file the
// same way and the stat does not change. A store that names no file, or a
// path longer than the buffer, is ERR_INTERNAL.

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
