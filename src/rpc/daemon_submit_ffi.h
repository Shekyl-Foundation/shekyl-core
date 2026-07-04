// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// C FFI: the three transaction-submit state shims consumed by the Rust
// admission engine (rust/shekyl-daemon-rpc/src/submit/), per
// docs/design/DAEMON_SUBMIT_VERDICT.md §4. Zero verdict logic lives here:
// the shims fetch facts and execute the attested insert tail; Rust decides.
//
// Compatibility domain (§4.5): shekyl_submit_facts_ffi is SAME-BUILD ABI —
// the Rust and C++ sides ship in one artifact, so the layout is free to
// change between builds and carries no versioning. The layout is pinned by
// compile-time asserts on both sides (static_assert in daemon_submit_ffi.cpp,
// const asserts in shekyl-daemon-rpc's ffi.rs) against the documented
// offsets below, plus the bidirectional runtime round-trip test
// (tests/unit_tests/daemon_submit_ffi_roundtrip.cpp).

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct core_rpc_handle core_rpc_handle;

// Per-key-image conflict descriptor values (§4.1: none | own_txid | other).
enum {
    SHEKYL_SUBMIT_KI_FREE = 0,
    SHEKYL_SUBMIT_KI_OWN_TX = 1,
    SHEKYL_SUBMIT_KI_OTHER = 2,
};

// Return codes shared by the snapshot and commit shims. The commit outcomes
// mirror rust CommitOutcome (§4.2); the snapshot uses OK / INTERNAL_FAULT
// only.
enum {
    SHEKYL_SUBMIT_OK = 0,               // snapshot filled / commit committed
    SHEKYL_SUBMIT_RACED = 1,            // a re-checked premise moved; fresh facts filled
    SHEKYL_SUBMIT_PRUNED_ON_INSERT = 2, // insert tail's prune() evicted the tx (F23)
    SHEKYL_SUBMIT_INTERNAL_FAULT = -1,  // §3.4 loud-failure arm; never a verdict
};

// POD fact snapshot (§4.1) — also the shape of Phase-D fresh facts when the
// commit races. Byte layout (size 80, align 8), asserted on both sides:
//
//   offset  0: in_pool               (u8; txid pool-resident at `all` category — §3.1 F40)
//   offset  1: in_chain              (u8; txid in main chain)
//   offset  2: ref_block_found       (u8; reference hash known ⇒ fields below valid)
//   offset  3: tree_depth            (u8; current curve-tree depth, LMDB convention)
//   offset  4: in_pool_broadcast     (u8; txid pool-resident at `legacy`/broadcast category —
//                                      the foreign-disclosable presence; differs from in_pool
//                                      only for a Dandelion++-embargoed tx, §3.1 identity pin)
//   offset  5: reserved[3]           (zeroed)
//   offset  8: ref_height            (u64; reference block main-chain height)
//   offset 16: root[32]              (curve-tree root at ref_height)
//   offset 48: fee_per_byte          (u64; check_fee's derived floor param)
//   offset 56: fee_quantization_mask (u64; ≥ 1)
//   offset 64: weight_limit          (u64; get_transaction_weight_limit)
//   offset 72: chain_height          (u64; block count, m_db->height())
//
// Key-image conflicts travel beside the struct as a plain uint8_t array
// (one SHEKYL_SUBMIT_KI_* entry per submitted key image, submission order).
typedef struct shekyl_submit_facts_ffi {
    uint8_t in_pool;
    uint8_t in_chain;
    uint8_t ref_block_found;
    uint8_t tree_depth;
    uint8_t in_pool_broadcast;
    uint8_t reserved[3];
    uint64_t ref_height;
    uint8_t root[32];
    uint64_t fee_per_byte;
    uint64_t fee_quantization_mask;
    uint64_t weight_limit;
    uint64_t chain_height;
} shekyl_submit_facts_ffi;

// Shim 1 (§4.1): Phase-B POD fact snapshot under one short pool→blockchain
// lock scope (§4.4 order), reads only.
//
// txid / reference_block: 32 bytes each. key_images: n_key_images × 32
// bytes, flat, submission order. out_ki_conflicts: n_key_images entries.
// Returns SHEKYL_SUBMIT_OK or SHEKYL_SUBMIT_INTERNAL_FAULT (DB exception /
// bad arguments; never a verdict).
int shekyl_submit_snapshot_facts(core_rpc_handle* h,
    const uint8_t* txid,
    const uint8_t* key_images, size_t n_key_images,
    const uint8_t* reference_block,
    shekyl_submit_facts_ffi* out_facts,
    uint8_t* out_ki_conflicts);

// Shim 2 (§4.2): Phase-D check-and-commit under one short pool→blockchain
// lock scope. Recomputes the C++ txid over the blob and release-checks it
// against the engine txid (§3.4; mismatch = INTERNAL_FAULT, never a
// verdict); re-checks every mutable premise (identity, key images,
// hash-anchored reference + age window, root == certificate root, the
// check_fee re-gate against fresh params — F34); on clean, executes the
// attested insert tail (tx_memory_pool::insert_attested_tx) and the
// post-prune membership check (F23).
//
// cert_* carry the VerificationCertificate facts (§3.3). On RACED, the
// fresh facts (same collection as shim 1, same lock scope) are written to
// out_fresh_facts / out_fresh_ki_conflicts (n_key_images entries) and Rust
// classifies, most-terminal-first (§3.1). The blob-derived key-image count
// must equal n_key_images (INTERNAL_FAULT otherwise).
int shekyl_submit_commit_tx(core_rpc_handle* h,
    const uint8_t* blob, size_t blob_len,
    const uint8_t* txid,
    uint64_t tx_weight, uint64_t fee,
    const uint8_t* cert_ref_block, uint64_t cert_ref_height,
    const uint8_t* cert_root,
    shekyl_submit_facts_ffi* out_fresh_facts,
    uint8_t* out_fresh_ki_conflicts, size_t n_key_images);

// Shim 3 (§4.3): post-commit relay nudge — fetch the pool-resident blob by
// txid and enqueue it through the existing
// relay_transactions(relay_method::local) dispatch, the same entry point
// on_send_raw_tx uses, so Dandelion++ embargo arming is inherited, not
// re-implemented (§5.2 item 2). Fire and forget: the nudge is latency; the
// embargo + periodic loop are the guarantee. Returns SHEKYL_SUBMIT_OK /
// SHEKYL_SUBMIT_INTERNAL_FAULT (callers may ignore; a miss means the tx
// raced away post-commit and the periodic loop owns whatever remains).
int shekyl_submit_relay_tx(core_rpc_handle* h, const uint8_t* txid);

// ── §4.5 round-trip test hooks (no production callers) ─────────────────────
//
// Layout probes for the bidirectional FFI struct tests: per-FIELD writes and
// reads, so a field-offset disagreement fails even where a memcpy echo would
// pass. `fill` writes seed-derived values into every field through the C++
// view of the layout; `check` reads every field through the C++ view and
// returns 0 iff each matches the same derivation. The Rust twin does the
// mirror-image derivation through its view.
void shekyl_submit_facts_test_fill(shekyl_submit_facts_ffi* out, uint64_t seed);
int shekyl_submit_facts_test_check(const shekyl_submit_facts_ffi* facts, uint64_t seed);

#ifdef __cplusplus
} // extern "C"

// ── C++-side implementations over the core objects ──────────────────────────
//
// The extern "C" wrappers above only resolve pool/blockchain/protocol from
// the handle and delegate here. Exposed so the latch-based commit
// integration test (§10 item 2) can drive the real shim logic against a
// unit-test pool/blockchain fixture without constructing a core_rpc_server.

namespace cryptonote { class tx_memory_pool; class Blockchain; struct i_cryptonote_protocol; }

namespace daemon_submit {

int snapshot_facts(cryptonote::tx_memory_pool& pool, cryptonote::Blockchain& bc,
    const uint8_t* txid,
    const uint8_t* key_images, size_t n_key_images,
    const uint8_t* reference_block,
    shekyl_submit_facts_ffi* out_facts,
    uint8_t* out_ki_conflicts) noexcept;

int commit_tx(cryptonote::tx_memory_pool& pool, cryptonote::Blockchain& bc,
    const uint8_t* blob, size_t blob_len,
    const uint8_t* txid,
    uint64_t tx_weight, uint64_t fee,
    const uint8_t* cert_ref_block, uint64_t cert_ref_height,
    const uint8_t* cert_root,
    shekyl_submit_facts_ffi* out_fresh_facts,
    uint8_t* out_fresh_ki_conflicts, size_t n_key_images) noexcept;

int relay_tx(cryptonote::tx_memory_pool& pool,
    cryptonote::i_cryptonote_protocol& protocol,
    const uint8_t* txid) noexcept;

} // namespace daemon_submit

#endif // __cplusplus
