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

// The transaction-submit state shims (DAEMON_SUBMIT_VERDICT.md §4): fact
// fetching and the attested insert tail for the Rust admission engine.
// Deliberately verdict-free — every branch here either fills facts, reports
// RACED with fresh facts for Rust to classify, or fails loudly as
// INTERNAL_FAULT (§3.4). No SubmitVerdict is chosen on this side of the
// boundary.

#include "daemon_submit_ffi.h"
#include "core_rpc_ffi_internal.h"
#include "core_rpc_server.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "cryptonote_protocol/enums.h"
#include "misc_log_ex.h"
#include "net/enums.h"
#include "shekyl/shekyl_ffi.h"

#include <boost/uuid/nil_generator.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc.submit"

// ── §4.5 layout pins (mirrored by const asserts in shekyl-daemon-rpc) ──────
static_assert(sizeof(shekyl_submit_facts_ffi) == 96, "SubmitFactsFfi size");
static_assert(alignof(shekyl_submit_facts_ffi) == 8, "SubmitFactsFfi align");
static_assert(offsetof(shekyl_submit_facts_ffi, in_pool) == 0, "in_pool offset");
static_assert(offsetof(shekyl_submit_facts_ffi, in_chain) == 1, "in_chain offset");
static_assert(offsetof(shekyl_submit_facts_ffi, ref_block_found) == 2, "ref_block_found offset");
static_assert(offsetof(shekyl_submit_facts_ffi, tree_depth) == 3, "tree_depth offset");
static_assert(offsetof(shekyl_submit_facts_ffi, in_pool_broadcast) == 4, "in_pool_broadcast offset");
static_assert(offsetof(shekyl_submit_facts_ffi, bond_record_probed) == 5, "bond_record_probed offset");
static_assert(offsetof(shekyl_submit_facts_ffi, bond_record_exists) == 6, "bond_record_exists offset");
static_assert(offsetof(shekyl_submit_facts_ffi, emission_probed) == 7, "emission_probed offset");
static_assert(offsetof(shekyl_submit_facts_ffi, emission_claim_conflict) == 8, "emission_claim_conflict offset");
static_assert(offsetof(shekyl_submit_facts_ffi, reserved) == 9, "reserved offset");
static_assert(offsetof(shekyl_submit_facts_ffi, ref_height) == 16, "ref_height offset");
static_assert(offsetof(shekyl_submit_facts_ffi, root) == 24, "root offset");
static_assert(offsetof(shekyl_submit_facts_ffi, fee_per_byte) == 56, "fee_per_byte offset");
static_assert(offsetof(shekyl_submit_facts_ffi, weight_limit) == 64, "weight_limit offset");
static_assert(offsetof(shekyl_submit_facts_ffi, chain_height) == 72, "chain_height offset");
static_assert(offsetof(shekyl_submit_facts_ffi, in_chain_height) == 80, "in_chain_height offset");
static_assert(offsetof(shekyl_submit_facts_ffi, bond_record_bonded_total) == 88,
  "bond_record_bonded_total offset");


struct shekyl_submit_emission_facts_handle
{
  shekyl_submit_emission_facts_ffi view{};
};

struct shekyl_submit_release_facts_handle
{
  shekyl_submit_release_facts_ffi view{};
};

// ── extern "C" wrappers: resolve core objects from the handle, delegate ────

extern "C" {

// The §8.7.2 emission fact-bundle accessors. (Definitions live in this
// block for explicitness/consistency — the header's extern "C"
// declarations would confer C linkage either way.)
const shekyl_submit_emission_facts_ffi* shekyl_submit_emission_facts_view(
  const shekyl_submit_emission_facts_handle* h)
{
  return h ? &h->view : nullptr;
}

void shekyl_submit_emission_facts_free(shekyl_submit_emission_facts_handle* h)
{
  delete h;
}

const shekyl_submit_release_facts_ffi* shekyl_submit_release_facts_view(
  const shekyl_submit_release_facts_handle* h)
{
  return h ? &h->view : nullptr;
}

void shekyl_submit_release_facts_free(shekyl_submit_release_facts_handle* h)
{
  delete h;
}

int shekyl_submit_snapshot_facts(core_rpc_handle* h,
  const uint8_t* txid,
  const uint8_t* key_images, size_t n_key_images,
  const uint8_t* reference_block,
  const uint8_t* bond_p_canonical_id,
  uint8_t bond_probe_kind,
  const uint8_t* bond_auth_pubkey, size_t bond_auth_pubkey_len,
  uint64_t bond_debit,
  const uint8_t* emission_p_canonical_id,
  const uint64_t* emission_epochs, size_t n_emission_epochs,
  shekyl_submit_emission_facts_handle** out_emission,
  shekyl_submit_release_facts_handle** out_release,
  shekyl_submit_facts_ffi* out_facts,
  uint8_t* out_ki_conflicts)
{
  if (!h || !h->rpc)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  (void)txid;
  (void)key_images;
  (void)n_key_images;
  (void)reference_block;
  (void)bond_p_canonical_id;
  (void)bond_probe_kind;
  (void)bond_auth_pubkey;
  (void)bond_auth_pubkey_len;
  (void)bond_debit;
  (void)emission_p_canonical_id;
  (void)emission_epochs;
  (void)n_emission_epochs;
  (void)out_emission;
  (void)out_release;
  (void)out_facts;
  (void)out_ki_conflicts;
  // Production submit reads the Rust pool. This export is the deleted
  // C++ snapshot.
  return SHEKYL_SUBMIT_INTERNAL_FAULT;
}

int shekyl_submit_commit_tx(core_rpc_handle* h,
  const uint8_t* blob, size_t blob_len,
  const uint8_t* txid,
  uint64_t tx_weight, uint64_t fee,
  const uint8_t* cert_ref_block, uint64_t cert_ref_height,
  const uint8_t* cert_root,
  shekyl_submit_facts_ffi* out_fresh_facts,
  uint8_t* out_fresh_ki_conflicts, size_t n_key_images)
{
  if (!h || !h->rpc)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  (void)blob;
  (void)blob_len;
  (void)txid;
  (void)tx_weight;
  (void)fee;
  (void)cert_ref_block;
  (void)cert_ref_height;
  (void)cert_root;
  (void)out_fresh_facts;
  (void)out_fresh_ki_conflicts;
  (void)n_key_images;
  return SHEKYL_SUBMIT_INTERNAL_FAULT;
}

int shekyl_submit_relay_tx(core_rpc_handle* h, const uint8_t* txid)
{
  if (!h || !h->rpc || !txid)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  return SHEKYL_SUBMIT_INTERNAL_FAULT;
}

// ── §4.5 round-trip test hooks ──────────────────────────────────────────────
//
// Field values are seed-derived with a per-field tweak so an offset swap
// between any two same-width fields fails the check; the Rust twin
// (tests in shekyl-daemon-rpc) uses the identical derivation. Seeds 0 and
// u64::MAX drive the zeroed/max edge shapes.

static uint64_t submit_facts_field_value(uint64_t seed, uint64_t field)
{
  if (seed == 0)
    return 0;
  if (seed == UINT64_MAX)
    return UINT64_MAX;
  // splitmix64 over seed ⊕ field-tweak: cheap, and identical in Rust.
  uint64_t z = seed ^ (0x9E3779B97F4A7C15ULL * (field + 1));
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

void shekyl_submit_facts_test_fill(shekyl_submit_facts_ffi* out, uint64_t seed)
{
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  out->in_pool = static_cast<uint8_t>(submit_facts_field_value(seed, 0));
  out->in_chain = static_cast<uint8_t>(submit_facts_field_value(seed, 1));
  out->ref_block_found = static_cast<uint8_t>(submit_facts_field_value(seed, 2));
  out->tree_depth = static_cast<uint8_t>(submit_facts_field_value(seed, 3));
  out->in_pool_broadcast = static_cast<uint8_t>(submit_facts_field_value(seed, 10));
  out->bond_record_probed = static_cast<uint8_t>(submit_facts_field_value(seed, 12));
  out->bond_record_exists = static_cast<uint8_t>(submit_facts_field_value(seed, 13));
  out->emission_probed = static_cast<uint8_t>(submit_facts_field_value(seed, 14));
  out->emission_claim_conflict = static_cast<uint8_t>(submit_facts_field_value(seed, 15));
  out->ref_height = submit_facts_field_value(seed, 4);
  for (size_t i = 0; i < sizeof(out->root); ++i)
    out->root[i] = static_cast<uint8_t>(submit_facts_field_value(seed, 5) >> ((i % 8) * 8));
  out->fee_per_byte = submit_facts_field_value(seed, 6);
  out->weight_limit = submit_facts_field_value(seed, 8);
  out->chain_height = submit_facts_field_value(seed, 9);
  out->in_chain_height = submit_facts_field_value(seed, 11);
  out->bond_record_bonded_total = submit_facts_field_value(seed, 16);
}

int shekyl_submit_facts_test_check(const shekyl_submit_facts_ffi* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_submit_facts_ffi expected;
  shekyl_submit_facts_test_fill(&expected, seed);
  return memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

} // extern "C"
