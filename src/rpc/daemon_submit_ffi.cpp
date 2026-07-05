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

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/tx_verification_utils.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "misc_log_ex.h"
#include "net/enums.h"

#include <boost/uuid/nil_generator.hpp>

#include <cstddef>
#include <cstring>
#include <mutex>
#include <vector>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc.submit"

// ── §4.5 layout pins (mirrored by const asserts in shekyl-daemon-rpc) ──────
static_assert(sizeof(shekyl_submit_facts_ffi) == 80, "SubmitFactsFfi size");
static_assert(alignof(shekyl_submit_facts_ffi) == 8, "SubmitFactsFfi align");
static_assert(offsetof(shekyl_submit_facts_ffi, in_pool) == 0, "in_pool offset");
static_assert(offsetof(shekyl_submit_facts_ffi, in_chain) == 1, "in_chain offset");
static_assert(offsetof(shekyl_submit_facts_ffi, ref_block_found) == 2, "ref_block_found offset");
static_assert(offsetof(shekyl_submit_facts_ffi, tree_depth) == 3, "tree_depth offset");
static_assert(offsetof(shekyl_submit_facts_ffi, in_pool_broadcast) == 4, "in_pool_broadcast offset");
static_assert(offsetof(shekyl_submit_facts_ffi, reserved) == 5, "reserved offset");
static_assert(offsetof(shekyl_submit_facts_ffi, ref_height) == 8, "ref_height offset");
static_assert(offsetof(shekyl_submit_facts_ffi, root) == 16, "root offset");
static_assert(offsetof(shekyl_submit_facts_ffi, fee_per_byte) == 48, "fee_per_byte offset");
static_assert(offsetof(shekyl_submit_facts_ffi, fee_quantization_mask) == 56, "fee_quantization_mask offset");
static_assert(offsetof(shekyl_submit_facts_ffi, weight_limit) == 64, "weight_limit offset");
static_assert(offsetof(shekyl_submit_facts_ffi, chain_height) == 72, "chain_height offset");

using namespace cryptonote;

namespace {

// Marshalling bound on the flat key-image array: far above any transaction
// the size cap admits, so hitting it means a corrupted length, not a big tx
// (40-ffi-discipline: bounded deserialization at the boundary).
constexpr size_t MAX_SUBMIT_KEY_IMAGES = 4096;

crypto::hash hash_from_bytes(const uint8_t* bytes)
{
  crypto::hash h;
  memcpy(h.data, bytes, sizeof(h.data));
  return h;
}

// Per-key-image conflict descriptor (§4.1: none | own_txid | other),
// derived from the public pool/chain surfaces:
//
// - A chain-level spend is always a *different* settled transaction from
//   the engine's perspective; if the spender were the submitted tx itself,
//   `in_chain` is 1 and identity outranks the descriptor everywhere the
//   engine consults it (Phase-B early return, race-classifier step 1).
// - `tx_memory_pool::have_tx_keyimg_as_spent(ki, txid)` is true iff a
//   different pool tx spends ki (category-blind), or the sole spender is
//   the submitted txid itself *and* it is legacy-visible. The two arms are
//   split on `in_pool_any`: a sole-self spender implies pool residency, so
//   `!in_pool_any` proves the spender is foreign. When `in_pool_any` is
//   true the engine returns AlreadyInPool before consulting descriptors,
//   so the OwnTx label (facts.rs: "paired with in_pool") is exact on every
//   observable path.
// - False with no chain spend is Free: the remaining shape (sole-self
//   spender, not legacy-visible — a local-state embargoed self-tx) also
//   implies `in_pool_any`, and identity again outranks.
uint8_t classify_key_image(tx_memory_pool& pool, Blockchain& bc,
  const crypto::key_image& ki, const crypto::hash& txid, bool in_pool_any)
{
  if (bc.have_tx_keyimg_as_spent(ki))
    return SHEKYL_SUBMIT_KI_OTHER;
  if (pool.have_tx_keyimg_as_spent(ki, txid))
    return in_pool_any ? SHEKYL_SUBMIT_KI_OWN_TX : SHEKYL_SUBMIT_KI_OTHER;
  return SHEKYL_SUBMIT_KI_FREE;
}

// The §4.1 fact collection. Caller holds the §4.4 pool→blockchain lock
// order; everything here is a read.
//
// Two presence facts, and the engine chooses which to disclose by caller
// tier (§3.1 identity-category pin):
//
//   `in_pool` (relay_category::all) is the *internal* truth, wider than the
//   legacy path's `legacy` category (row I4): it must see the daemon's own
//   local-state (Dandelion++ embargo) insertions, or a resubmit-during-
//   embargo — the §5.2 ladder's status-query probe (F31) — would fall
//   through identity, re-verify, and fault at the insert tail instead of
//   returning AlreadyInPool. It is also what the commit re-check keys on to
//   avoid a double-insert.
//
//   `in_pool_broadcast` (relay_category::legacy) is the *foreign-disclosable*
//   truth — presence that carries no embargo secret because the tx has
//   fluffed. The two differ exactly for an embargoed tx. The Rust engine
//   discloses `in_pool` only to the owner (unrestricted endpoint) and
//   `in_pool_broadcast` to a foreign caller (restricted/public endpoint), so
//   `POST /submit_transaction` is not a stem-presence oracle. The legacy
//   `have_tx(_, legacy)` identity check disclosed exactly this narrower fact
//   to foreign callers; an embargoed self-resubmit was caught later and
//   lossily by add_tx's existing-tx arm (`OK + not_relayed`).
void collect_facts_locked(tx_memory_pool& pool, Blockchain& bc,
  const crypto::hash& txid, const std::vector<crypto::key_image>& key_images,
  const crypto::hash& reference_block,
  shekyl_submit_facts_ffi& facts, uint8_t* ki_conflicts)
{
  memset(&facts, 0, sizeof(facts));

  facts.in_pool = pool.have_tx(txid, relay_category::all) ? 1 : 0;
  facts.in_pool_broadcast = pool.have_tx(txid, relay_category::legacy) ? 1 : 0;
  facts.in_chain = bc.have_tx(txid) ? 1 : 0;

  for (size_t i = 0; i < key_images.size(); ++i)
    ki_conflicts[i] = classify_key_image(pool, bc, key_images[i], txid, facts.in_pool != 0);

  // Reference facts iff the hash is on the main chain (F21: hash-anchored;
  // block_exists consults the main-chain table only, so found ⇒ canonical).
  uint64_t ref_height = 0;
  if (bc.get_db().block_exists(reference_block, &ref_height))
  {
    facts.ref_block_found = 1;
    facts.ref_height = ref_height;
    const std::array<uint8_t, 32> root = bc.get_db().get_curve_tree_root_at_height(ref_height);
    memcpy(facts.root, root.data(), sizeof(facts.root));
  }
  facts.tree_depth = bc.get_db().get_curve_tree_depth();

  facts.fee_per_byte = bc.get_current_fee_per_byte();
  facts.fee_quantization_mask = Blockchain::get_fee_quantization_mask();
  facts.weight_limit = get_transaction_weight_limit(bc.get_current_hard_fork_version());
  facts.chain_height = bc.get_current_blockchain_height();
}

// The §3.1 ref-age window over fresh facts — the same comparison shape as
// the consensus check (blockchain.cpp `check_tx_inputs`) and the F22 pool
// sweep, re-run at D because chain height moves during Phase C.
bool ref_age_window_holds(uint64_t chain_height, uint64_t ref_height)
{
  if (chain_height < FCMP_REFERENCE_BLOCK_MIN_AGE ||
      ref_height > chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE)
    return false;
  if (chain_height > FCMP_REFERENCE_BLOCK_MAX_AGE &&
      ref_height < chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE)
    return false;
  return true;
}

} // anonymous namespace

namespace daemon_submit {

int snapshot_facts(tx_memory_pool& pool, Blockchain& bc,
  const uint8_t* txid,
  const uint8_t* key_images, size_t n_key_images,
  const uint8_t* reference_block,
  shekyl_submit_facts_ffi* out_facts,
  uint8_t* out_ki_conflicts) noexcept
{
  try
  {
    if (!txid || !reference_block || !out_facts ||
        (n_key_images > 0 && (!key_images || !out_ki_conflicts)) ||
        n_key_images > MAX_SUBMIT_KEY_IMAGES)
    {
      MERROR("submit snapshot: bad arguments (marshalling fault)");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    const crypto::hash id = hash_from_bytes(txid);
    const crypto::hash ref = hash_from_bytes(reference_block);
    std::vector<crypto::key_image> kis(n_key_images);
    for (size_t i = 0; i < n_key_images; ++i)
      memcpy(kis[i].data, key_images + i * 32, 32);

    // §4.4 lock order: pool → blockchain, one short scope, reads only.
    std::lock_guard<tx_memory_pool> pool_lock(pool);
    std::lock_guard<Blockchain> bc_lock(bc);

    collect_facts_locked(pool, bc, id, kis, ref, *out_facts, out_ki_conflicts);

    if (out_facts->fee_per_byte == 0)
    {
      // Block-reward derivation failed (check_fee's own failure arm) — a
      // daemon-state fault, not a verdict input (§3.4).
      MERROR("submit snapshot: fee-per-byte derivation failed");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }
    return SHEKYL_SUBMIT_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("submit snapshot: exception: " << e.what());
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  }
  catch (...)
  {
    MERROR("submit snapshot: unknown exception");
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  }
}

int commit_tx(tx_memory_pool& pool, Blockchain& bc,
  const uint8_t* blob, size_t blob_len,
  const uint8_t* txid,
  uint64_t tx_weight, uint64_t fee,
  const uint8_t* cert_ref_block, uint64_t cert_ref_height,
  const uint8_t* cert_root,
  shekyl_submit_facts_ffi* out_fresh_facts,
  uint8_t* out_fresh_ki_conflicts, size_t n_key_images) noexcept
{
  try
  {
    if (!blob || blob_len == 0 || !txid || !cert_ref_block || !cert_root ||
        !out_fresh_facts ||
        (n_key_images > 0 && (!out_fresh_ki_conflicts)) ||
        n_key_images > MAX_SUBMIT_KEY_IMAGES)
    {
      MERROR("submit commit: bad arguments (marshalling fault)");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    // §3.4 txid authority: reparse the exact submitted bytes and
    // release-check the C++ hash against the engine hash *first* — nothing
    // else is trustworthy if the two sides disagree about the blob.
    transaction tx;
    if (!parse_and_validate_tx_from_blob(
          blobdata_ref{reinterpret_cast<const char*>(blob), blob_len}, tx))
    {
      MERROR("submit commit: C++ reparse failed on engine-validated bytes");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }
    const crypto::hash id = get_transaction_hash(tx);
    if (id != hash_from_bytes(txid))
    {
      MERROR("submit commit: txid divergence between engine and C++ over the "
        "same blob: engine " << hash_from_bytes(txid) << ", C++ " << id
        << " (daemon defect; see DAEMON_SUBMIT_VERDICT.md §3.4)");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    // §3.4 weight authority: the engine-supplied tx_weight gates check_fee
    // (below) and is persisted into txpool meta, where block-template
    // assembly and pool eviction ordering weigh with the C++ arithmetic. Row
    // I3 pins the Rust weight formula (BP+ clawback) to C++
    // get_transaction_weight only by KAT; re-derive it here over the same
    // reparsed blob and release-check, exactly as the txid check does. A
    // silent low divergence would let an over-weight tx into a block template
    // that every validating node then rejects — a mined-and-orphaned block.
    const uint64_t cpp_weight = get_transaction_weight(tx, blob_len);
    if (cpp_weight != tx_weight)
    {
      MERROR("submit commit: tx weight divergence between engine and C++ over "
        "the same blob: engine " << tx_weight << ", C++ " << cpp_weight
        << " (daemon defect; see DAEMON_SUBMIT_VERDICT.md row I3)");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    // Blob-derived key images, `txin_to_key` in vin order — the same
    // extraction as the engine's ParsedSubmission (phase_a.rs).
    std::vector<crypto::key_image> kis;
    kis.reserve(tx.vin.size());
    for (const auto& in : tx.vin)
      if (std::holds_alternative<txin_to_key>(in))
        kis.push_back(std::get<txin_to_key>(in).k_image);
    if (kis.size() != n_key_images)
    {
      MERROR("submit commit: key-image count mismatch: blob " << kis.size()
        << ", caller " << n_key_images);
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    const crypto::hash cert_ref = hash_from_bytes(cert_ref_block);

    // §4.4 lock order: pool → blockchain, one short scope across the
    // re-check list and the insert tail.
    std::lock_guard<tx_memory_pool> pool_lock(pool);
    std::lock_guard<Blockchain> bc_lock(bc);

    shekyl_submit_facts_ffi fresh;
    collect_facts_locked(pool, bc, id, kis, cert_ref, fresh, out_fresh_ki_conflicts);
    if (fresh.fee_per_byte == 0)
    {
      MERROR("submit commit: fee-per-byte derivation failed");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    // Re-establish the legacy add_tx side effect: an incoming spend that
    // conflicts with a resident pool tx on a key image marks that resident tx
    // `double_spend_seen`, so its owner sees the early warning via pool RPC
    // (tx_pool.cpp add_tx → mark_double_spend). Rust classifies
    // DoubleSpendConflict for the *submitter* from these same fresh facts;
    // this marks the *victim*. KI_OWN_TX is the submitted txid's own image
    // (identity, not a conflict) — only KI_OTHER, a foreign spender, marks.
    // Not a verdict, so it stays C++-side, and it precedes the Raced return so
    // the flag is set whether or not this submit is the one that ultimately
    // relays.
    bool foreign_ki_conflict = false;
    for (size_t i = 0; i < n_key_images; ++i)
      if (out_fresh_ki_conflicts[i] == SHEKYL_SUBMIT_KI_OTHER)
        foreign_ki_conflict = true;
    if (foreign_ki_conflict)
      pool.mark_double_spend(tx);

    // §3.1 Phase-D re-check list. Any moved premise → Raced{fresh}; Rust
    // classifies most-terminal-first. The C++ chooses no verdict.
    bool raced = fresh.in_pool != 0 || fresh.in_chain != 0;
    for (size_t i = 0; !raced && i < n_key_images; ++i)
      raced = out_fresh_ki_conflicts[i] != SHEKYL_SUBMIT_KI_FREE;
    if (!raced)
      raced = fresh.ref_block_found == 0 ||
        fresh.ref_height != cert_ref_height ||
        memcmp(fresh.root, cert_root, sizeof(fresh.root)) != 0 ||
        !ref_age_window_holds(fresh.chain_height, fresh.ref_height);
    if (!raced)
      // F34 fee re-gate against fresh params, mirroring add_tx's
      // gate-before-tail order (tx_pool.cpp) — mechanism reuse; Rust
      // re-runs its own floor arithmetic on the fresh facts (row P2).
      raced = !bc.check_fee(tx_weight, fee);
    if (raced)
    {
      memcpy(out_fresh_facts, &fresh, sizeof(fresh));
      return SHEKYL_SUBMIT_RACED;
    }

    // Clean: the certificate-gated attested insert tail (§3.5/§4.2), then
    // the post-prune membership check (F23).
    bool pruned_on_insert = false;
    if (!pool.insert_attested_tx(tx, id,
          blobdata(reinterpret_cast<const char*>(blob), blob_len),
          tx_weight, fee, cert_ref, cert_ref_height, pruned_on_insert))
    {
      MERROR("submit commit: attested insert tail failed");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }
    return pruned_on_insert ? SHEKYL_SUBMIT_PRUNED_ON_INSERT : SHEKYL_SUBMIT_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("submit commit: exception: " << e.what());
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  }
  catch (...)
  {
    MERROR("submit commit: unknown exception");
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  }
}

int relay_tx(tx_memory_pool& pool, i_cryptonote_protocol& protocol,
  const uint8_t* txid) noexcept
{
  try
  {
    if (!txid)
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    const crypto::hash id = hash_from_bytes(txid);

    // Fetch at `all`: the just-committed tx sits at relay_method::local,
    // invisible to the legacy/broadcasted categories until relayed.
    cryptonote::blobdata txblob;
    if (!pool.get_transaction(id, txblob, relay_category::all))
    {
      // Raced away between commit and nudge — the periodic relay loop owns
      // whatever remains (§4.3 fire-and-forget).
      MDEBUG("submit relay: tx " << id << " no longer pool-resident; skipping nudge");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }

    // The exact dispatch the deleted legacy on_send_raw_tx handler used
    // (§9.3): relay_method::local arms the Dandelion++ embargo machinery.
    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(std::move(txblob));
    protocol.relay_transactions(r, boost::uuids::nil_uuid(),
      epee::net_utils::zone::invalid, relay_method::local);
    return SHEKYL_SUBMIT_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("submit relay: exception: " << e.what());
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  }
  catch (...)
  {
    MERROR("submit relay: unknown exception");
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  }
}

} // namespace daemon_submit

// ── extern "C" wrappers: resolve core objects from the handle, delegate ────

extern "C" {

int shekyl_submit_snapshot_facts(core_rpc_handle* h,
  const uint8_t* txid,
  const uint8_t* key_images, size_t n_key_images,
  const uint8_t* reference_block,
  shekyl_submit_facts_ffi* out_facts,
  uint8_t* out_ki_conflicts)
{
  if (!h || !h->rpc)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  core& c = h->rpc->get_core();
  return daemon_submit::snapshot_facts(c.get_pool(), c.get_blockchain_storage(),
    txid, key_images, n_key_images, reference_block, out_facts, out_ki_conflicts);
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
  core& c = h->rpc->get_core();
  return daemon_submit::commit_tx(c.get_pool(), c.get_blockchain_storage(),
    blob, blob_len, txid, tx_weight, fee, cert_ref_block, cert_ref_height,
    cert_root, out_fresh_facts, out_fresh_ki_conflicts, n_key_images);
}

int shekyl_submit_relay_tx(core_rpc_handle* h, const uint8_t* txid)
{
  if (!h || !h->rpc)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  core& c = h->rpc->get_core();
  i_cryptonote_protocol* protocol = c.get_protocol();
  if (!protocol)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  return daemon_submit::relay_tx(c.get_pool(), *protocol, txid);
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
  out->ref_height = submit_facts_field_value(seed, 4);
  for (size_t i = 0; i < sizeof(out->root); ++i)
    out->root[i] = static_cast<uint8_t>(submit_facts_field_value(seed, 5) >> ((i % 8) * 8));
  out->fee_per_byte = submit_facts_field_value(seed, 6);
  out->fee_quantization_mask = submit_facts_field_value(seed, 7);
  out->weight_limit = submit_facts_field_value(seed, 8);
  out->chain_height = submit_facts_field_value(seed, 9);
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
