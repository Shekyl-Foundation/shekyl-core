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
static_assert(sizeof(shekyl_submit_facts_ffi) == 104, "SubmitFactsFfi size");
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
static_assert(offsetof(shekyl_submit_facts_ffi, fee_quantization_mask) == 64, "fee_quantization_mask offset");
static_assert(offsetof(shekyl_submit_facts_ffi, weight_limit) == 72, "weight_limit offset");
static_assert(offsetof(shekyl_submit_facts_ffi, chain_height) == 80, "chain_height offset");
static_assert(offsetof(shekyl_submit_facts_ffi, in_chain_height) == 88, "in_chain_height offset");
static_assert(offsetof(shekyl_submit_facts_ffi, bond_record_bonded_total) == 96,
  "bond_record_bonded_total offset");

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

// Overlap of the vin's claimed epochs with the record's claimed set — the
// §8.7.2 E6 claim-slot predicate (both sides strictly increasing; a linear
// scan over ≤ MAX_SETTLEMENT_EPOCHS × record set is cheap).
bool emission_epochs_overlap(const uint64_t* vin_epochs, size_t n,
  const std::vector<uint64_t>& claimed)
{
  // `claimed` is the record's claimed_settlement_epochs — persisted
  // strictly increasing (the codec's claimed_epochs_well_formed bound), so
  // the membership test is a binary search: this predicate runs inside the
  // §4.4 short lock scope and the claimed set grows for a persona's whole
  // life. (The verdict-critical dedup re-runs in the Rust claims battery;
  // this is the Phase-B/D race bit.)
  for (size_t i = 0; i < n; ++i)
    if (std::binary_search(claimed.begin(), claimed.end(), vin_epochs[i]))
      return true;
  return false;
}

} // anonymous namespace

// Opaque owner of the §8.7.2 E6/E7 fact buffers: every pointer in `view`
// aliases the vectors held here, so the handle must outlive the Rust copy
// (the shim copies during the snapshot call and frees immediately after).
struct shekyl_submit_emission_facts_handle
{
  // E6 storage.
  std::vector<uint64_t> bond_shard_ids;
  std::vector<uint64_t> bond_claimed_epochs;
  // E7 storage: the snapshots own the row values; the ffi_* vectors alias
  // their bad_intervals_flat (to_ffi_bonds contract), so snapshot order is
  // load-bearing for lifetime.
  std::vector<cryptonote::ArchivalEmissionEpochSnapshot> snaps;
  std::vector<std::vector<shekyl_archival_epoch_close_bond>> ffi_bonds;
  std::vector<std::vector<shekyl_archival_epoch_close_shard>> ffi_shards;
  std::vector<std::vector<shekyl_archival_credit_pair>> ffi_pairs;
  std::vector<shekyl_submit_emission_snapshot_ffi> pod_snaps;
  shekyl_submit_emission_facts_ffi view{};
};

// Opaque owner of the §8.7.1.1 Unbond fact buffers. Same contract as the
// emission handle: every pointer in `view` aliases the vectors held here, the
// shim copies during the snapshot call and frees immediately after.
struct shekyl_submit_unbond_facts_handle
{
  std::vector<uint8_t> bond_spend_pk;
  std::vector<uint64_t> per_shard_last_served;
  shekyl_submit_unbond_facts_ffi view{};
};

namespace {

// §8.7.1.1 Unbond fact-bundle marshal. Runs inside the caller's lock scope,
// beside every other fact, so the record, its last-served slice and the slash
// watermark describe ONE chain state (a record read before a block paired with
// a watermark read after it describes a state the chain never occupied).
//
// The kind->scan decision is Rust's (shekyl_archival_last_served_scan,
// exhaustive on HoldingsKind); this site marshals the discriminant onto the
// matching DB accessor and ECHOES it back, exactly as the block path's Unbond
// arm does. The echo is not redundant: the wrong accessor fails permissively
// (a complete-tree record has no shard list, so the held-shards accessor
// returns nothing, which folds to "never served" and lets the release cooldown
// elapse for a record that has been serving), and Rust pins the echo against
// the record's holdings kind rather than trusting this gather.
//
// Returns false on a marshal fault (unknown holdings kind) -- never a verdict.
bool fill_unbond_facts_locked(Blockchain& bc, const crypto::hash& p_id,
  shekyl_submit_unbond_facts_handle& handle)
{
  shekyl::db::ArchivalBondValue record{};
  const bool present = bc.get_db().get_archival_bond_value(p_id, record);
  handle.view.record_present = present ? 1 : 0;
  // As stored: u64::MAX ("nothing settled yet") stays the sentinel here and is
  // normalised once, Rust-side.
  handle.view.last_settled_slash_epoch = bc.get_db().get_archival_last_slash_epoch();
  if (!present)
    return true;

  uint8_t scan = 0;
  if (shekyl_archival_last_served_scan(record.holdings_kind, &scan)
      != SHEKYL_ARCHIVAL_BOND_POST_OK)
  {
    MERROR("submit snapshot: unbond gather: unknown holdings kind "
      << static_cast<unsigned>(record.holdings_kind));
    return false;
  }
  handle.per_shard_last_served =
    (scan == SHEKYL_ARCHIVAL_LAST_SERVED_SCAN_ALL_SHARDS)
      ? bc.get_db().archival_bond_all_last_served_epochs(p_id)
      : bc.get_db().archival_bond_last_served_epochs(p_id, record.held_shard_ids);
  handle.bond_spend_pk = record.bond_spend_pk;

  shekyl_submit_unbond_record_ffi& out = handle.view.record;
  out.bonded_total_atomic = record.bonded_total_atomic;
  out.bad_interval_count = record.bad_intervals.size();
  out.bond_spend_pk =
    handle.bond_spend_pk.empty() ? nullptr : handle.bond_spend_pk.data();
  out.bond_spend_pk_len = handle.bond_spend_pk.size();
  out.holdings_kind = record.holdings_kind;
  out.last_served_scan = scan;
  out.per_shard_last_served =
    handle.per_shard_last_served.empty() ? nullptr : handle.per_shard_last_served.data();
  out.per_shard_last_served_len = handle.per_shard_last_served.size();
  return true;
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
//   `in_pool_broadcast` (relay_category::broadcasted) is the *foreign-disclosable*
//   truth — presence that carries no embargo secret because the tx has
//   fluffed. The two differ exactly for an embargoed tx. The Rust engine
//   discloses `in_pool` only to the owner (unrestricted endpoint) and
//   `in_pool_broadcast` to a foreign caller (restricted/public endpoint), so
//   `POST /submit_transaction` is not a stem-presence oracle. The inherited
//   `have_tx` identity check disclosed exactly this narrower fact to foreign
//   callers; an embargoed self-resubmit was caught later and lossily by
//   add_tx's existing-tx arm (`OK + not_relayed`). It asked the deleted
//   `relay_category::legacy`, whose extra member (`relay_method::none`) this
//   comment's own justification never covered: a do-not-relay transaction
//   has not fluffed, so its presence is not free of embargo secret.
//   `bond_record_probed`/`bond_record_exists` carry the §8.7.1 BP3 fact —
//   the archival bond record for the bond-post vin's claimed p_canonical_id
//   (the claim is pinned to the pubkey by the Rust verifier's BP2 leg).
//   Probed iff `bond_p_canonical_id` is non-null: the engine passes it for a
//   bond-post submission (snapshot), and the commit re-derives it from the
//   reparsed blob (re-check) so a bond-post block landing during Phase C
//   surfaces as a Raced fresh fact that Rust classifies DoubleSpendConflict.
void collect_facts_locked(tx_memory_pool& pool, Blockchain& bc,
  const crypto::hash& txid, const std::vector<crypto::key_image>& key_images,
  const crypto::hash& reference_block,
  const crypto::hash* bond_p_canonical_id, uint8_t bond_probe_kind,
  const crypto::hash* emission_p_canonical_id,
  const uint64_t* emission_epochs, size_t n_emission_epochs,
  shekyl_submit_facts_ffi& facts, uint8_t* ki_conflicts)
{
  memset(&facts, 0, sizeof(facts));

  if (bond_p_canonical_id)
  {
    std::vector<uint8_t> existing_pubkey;
    facts.bond_record_probed = 1;
    facts.bond_record_exists =
      bc.get_db().get_archival_bond_hybrid_pubkey(*bond_p_canonical_id, existing_pubkey) ? 1 : 0;
    // The debit arm additionally needs the BALANCE, because presence does not
    // move when a persona exits: apply_archival_unbond rewrites the row with
    // bonded_total_atomic == 0 rather than deleting it. Read only for the
    // _UNBOND probe -- the credit arm's question is answered by presence
    // alone, and this is a second, heavier record load.
    if (bond_probe_kind == SHEKYL_SUBMIT_BOND_PROBE_UNBOND && facts.bond_record_exists)
    {
      shekyl::db::ArchivalBondValue record{};
      if (bc.get_db().get_archival_bond_value(*bond_p_canonical_id, record))
        facts.bond_record_bonded_total = record.bonded_total_atomic;
    }
  }

  if (emission_p_canonical_id)
  {
    // §8.7.2 E6 claim-slot predicate, fact-shaped (Rust classifies): the
    // claimant record is gone, or a claimed epoch is already consumed.
    facts.emission_probed = 1;
    shekyl::db::ArchivalBondValue record{};
    const bool present =
      bc.get_db().get_archival_bond_value(*emission_p_canonical_id, record);
    facts.emission_claim_conflict = (!present
      || emission_epochs_overlap(emission_epochs, n_emission_epochs,
           record.claimed_settlement_epochs)) ? 1 : 0;
  }

  facts.in_pool = pool.have_tx(txid, relay_category::all) ? 1 : 0;
  facts.in_pool_broadcast = pool.have_tx(txid, relay_category::broadcasted) ? 1 : 0;
  facts.in_chain = bc.have_tx(txid) ? 1 : 0;
  // F40: the confirming-block height, read under the same lock scope as the
  // membership fact so the pair cannot be racy (§3.1 Phase B). Valid iff
  // in_chain; zeroed (by the memset above) otherwise.
  if (facts.in_chain)
    facts.in_chain_height = bc.get_db().get_tx_block_height(txid);

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
  const uint8_t* bond_p_canonical_id,
  uint8_t bond_probe_kind,
  const uint8_t* emission_p_canonical_id,
  const uint64_t* emission_epochs, size_t n_emission_epochs,
  shekyl_submit_emission_facts_handle** out_emission,
  shekyl_submit_unbond_facts_handle** out_unbond,
  shekyl_submit_facts_ffi* out_facts,
  uint8_t* out_ki_conflicts) noexcept
{
  try
  {
    if (!txid || !reference_block || !out_facts ||
        (n_key_images > 0 && (!key_images || !out_ki_conflicts)) ||
        n_key_images > MAX_SUBMIT_KEY_IMAGES ||
        (emission_p_canonical_id != nullptr &&
          (n_emission_epochs == 0 || !emission_epochs ||
           n_emission_epochs > SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS)) ||
        (bond_p_canonical_id != nullptr &&
          bond_probe_kind != SHEKYL_SUBMIT_BOND_PROBE_JOIN &&
          bond_probe_kind != SHEKYL_SUBMIT_BOND_PROBE_UNBOND) ||
        // An UNBOND probe with nowhere to put the bundle is an incoherent
        // argument set, not a request for a cheaper probe. The debit arm's
        // Phase-C battery cannot run on the presence bit alone -- UB3, UB5,
        // UB7 and UB9 all read the record's CONTENTS -- so dropping the
        // bundle would leave the caller holding a fact set that cannot
        // verify anything, discoverable only later and one layer up.
        //
        // Deliberately NOT the emission arm's rule, which admits a null
        // out_emission: there the POD's claim-conflict bit IS a complete
        // answer for a consumer that only needs the §8.7.2 E6 re-check, and
        // the E7 bundle is an extra. Do not flatten the two.
        (bond_p_canonical_id != nullptr &&
          bond_probe_kind == SHEKYL_SUBMIT_BOND_PROBE_UNBOND &&
          out_unbond == nullptr))
    {
      MERROR("submit snapshot: bad arguments (marshalling fault)");
      return SHEKYL_SUBMIT_INTERNAL_FAULT;
    }
    if (out_emission)
      *out_emission = nullptr;
    if (out_unbond)
      *out_unbond = nullptr;

    const crypto::hash id = hash_from_bytes(txid);
    const crypto::hash ref = hash_from_bytes(reference_block);
    crypto::hash bond_p_id{};
    if (bond_p_canonical_id)
      bond_p_id = hash_from_bytes(bond_p_canonical_id);
    crypto::hash emission_p_id{};
    if (emission_p_canonical_id)
      emission_p_id = hash_from_bytes(emission_p_canonical_id);
    std::vector<crypto::key_image> kis(n_key_images);
    for (size_t i = 0; i < n_key_images; ++i)
      memcpy(kis[i].data, key_images + i * 32, 32);

    // §4.4 lock order: pool → blockchain, one short scope, reads only.
    std::lock_guard<tx_memory_pool> pool_lock(pool);
    std::lock_guard<Blockchain> bc_lock(bc);

    collect_facts_locked(pool, bc, id, kis, ref,
      bond_p_canonical_id ? &bond_p_id : nullptr, bond_probe_kind,
      emission_p_canonical_id ? &emission_p_id : nullptr,
      emission_epochs, n_emission_epochs,
      *out_facts, out_ki_conflicts);

    // §8.7.1.1 Unbond fact-bundle marshal, same lock scope. The POD's
    // bond_record_probed/exists pair is filled for every bond-post probe
    // (it is the kind-agnostic "a record exists for this p_canonical_id"
    // fact); this bundle adds the record's CONTENTS, which only the debit
    // arm needs. Rust pins the two against each other.
    // No `&& out_unbond` here: the argument check above already refused that
    // shape, and repeating it would re-read as "the bundle is optional".
    if (bond_p_canonical_id && bond_probe_kind == SHEKYL_SUBMIT_BOND_PROBE_UNBOND)
    {
      auto handle = std::make_unique<shekyl_submit_unbond_facts_handle>();
      if (!fill_unbond_facts_locked(bc, bond_p_id, *handle))
        return SHEKYL_SUBMIT_INTERNAL_FAULT;
      *out_unbond = handle.release();
    }

    // §8.7.2 E6/E7 fact-bundle marshal, same lock scope: the record's
    // verify operands + one frozen as-of-E snapshot per claimed epoch
    // (the block path's exact gather + to_ffi_* marshal).
    if (emission_p_canonical_id && out_emission)
    {
      auto handle = std::make_unique<shekyl_submit_emission_facts_handle>();
      shekyl::db::ArchivalBondValue record{};
      const bool present = bc.get_db().get_archival_bond_value(emission_p_id, record);
      handle->view.bond_present = present ? 1 : 0;
      if (present)
      {
        handle->bond_shard_ids = record.held_shard_ids;
        handle->bond_claimed_epochs = record.claimed_settlement_epochs;
        handle->view.bond.join_settlement_epoch = record.join_settlement_epoch;
        handle->view.bond.holdings_kind = static_cast<uint8_t>(record.holdings_kind);
        handle->view.bond.shard_ids =
          handle->bond_shard_ids.empty() ? nullptr : handle->bond_shard_ids.data();
        handle->view.bond.shard_ids_len = handle->bond_shard_ids.size();
        handle->view.bond.claimed_epochs =
          handle->bond_claimed_epochs.empty() ? nullptr : handle->bond_claimed_epochs.data();
        handle->view.bond.claimed_epochs_len = handle->bond_claimed_epochs.size();
      }
      handle->snaps.resize(n_emission_epochs);
      handle->ffi_bonds.resize(n_emission_epochs);
      handle->ffi_shards.resize(n_emission_epochs);
      handle->ffi_pairs.resize(n_emission_epochs);
      handle->pod_snaps.resize(n_emission_epochs);
      for (size_t k = 0; k < n_emission_epochs; ++k)
      {
        bc.get_db().gather_archival_emission_epoch_snapshot(
          emission_p_id, emission_epochs[k], handle->snaps[k]);
        const auto& snap = handle->snaps[k];
        handle->ffi_bonds[k] = snap.to_ffi_bonds();
        handle->ffi_shards[k] = snap.to_ffi_shards();
        handle->ffi_pairs[k] = snap.to_ffi_credit_pairs();
        shekyl_submit_emission_snapshot_ffi& pod = handle->pod_snaps[k];
        pod.has_budget_row = snap.has_budget_row ? 1 : 0;
        pod.settlement_epoch = snap.settlement_epoch;
        pod.close_block_height = snap.close_block_height;
        pod.sigma_work_milli = snap.sigma_work_milli;
        pod.budget_atomic = snap.budget_atomic;
        pod.claimant_bond_idx = snap.claimant_bond_idx;
        pod.bonds = handle->ffi_bonds[k].empty() ? nullptr : handle->ffi_bonds[k].data();
        pod.bonds_len = handle->ffi_bonds[k].size();
        pod.shards = handle->ffi_shards[k].empty() ? nullptr : handle->ffi_shards[k].data();
        pod.shards_len = handle->ffi_shards[k].size();
        pod.credit_pairs = handle->ffi_pairs[k].empty() ? nullptr : handle->ffi_pairs[k].data();
        pod.credit_pairs_len = handle->ffi_pairs[k].size();
      }
      handle->view.snapshots =
        handle->pod_snaps.empty() ? nullptr : handle->pod_snaps.data();
      handle->view.snapshots_len = handle->pod_snaps.size();
      *out_emission = handle.release();
    }

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
    // extraction as the engine's ParsedSubmission (phase_a.rs). The
    // bond-post vin's claimed p_canonical_id rides along for the §8.7.1
    // BP3 re-probe (blob-derived, exactly as the snapshot probe was
    // engine-derived from the same bytes).
    std::vector<crypto::key_image> kis;
    kis.reserve(tx.vin.size());
    const crypto::hash* bond_p_id = nullptr;
    // The two arms race on DIFFERENT FACTS, not on one fact in two
    // directions (§8.7.1.1 UB2): JoinMarket races when a record APPEARS
    // during Phase C, while an exit PRESERVES the debited row -- so the debit
    // arm races on the record's BALANCE no longer matching the debit this
    // transaction was verified against. Both discriminants are derived from
    // the reparsed blob, exactly as the probe key is.
    //
    // INVARIANT this loop depends on, enforced two layers away: a submission
    // carries AT MOST ONE bond-post vin. The loop below assigns on every
    // bond-post input, so with two it would describe the LAST; the Rust side
    // reads the FIRST (`ParsedSubmission::bond_post`, a `find_map`). The two
    // sides would then re-check different vins of the same transaction --
    // a consensus divergence, not a cosmetic one. What prevents it is
    // `phase_a.rs`: `SubmitTxKind::BondPost` is classified only on
    // `n_bond_post == 1`, and `shekyl-wire`'s `validate()` forbids mixing a
    // bond-post with an emission vin. Neither guard is visible from here, so
    // any new per-vin bond-post read added to this loop must either preserve
    // "at most one" or stop assuming it. (Same for `bond_p_id` above, whose
    // spelling this one copied.)
    bool bond_is_unbond = false;
    // The debit the transaction was verified against. Phase C required it to
    // equal the record's bonded total, so any drift in that total during
    // Phase C makes these bytes unconnectable.
    uint64_t bond_debit = 0;
    const txin_archival_reward_emission* emission_vin = nullptr;
    for (const auto& in : tx.vin)
    {
      if (std::holds_alternative<txin_to_key>(in))
        kis.push_back(std::get<txin_to_key>(in).k_image);
      else if (std::holds_alternative<txin_archival_bond_post>(in))
      {
        const auto& bond_vin = std::get<txin_archival_bond_post>(in);
        bond_p_id = &bond_vin.p_canonical_id;
        bond_is_unbond = bond_vin.post_kind
          == static_cast<uint8_t>(archival_bond_post_kind::Unbond);
        bond_debit = bond_vin.bond_debit;
      }
      else if (std::holds_alternative<txin_archival_reward_emission>(in))
        emission_vin = &std::get<txin_archival_reward_emission>(in);
    }
    // §8.7.2 E6 re-probe operands, blob-derived exactly as the snapshot's
    // were engine-derived from the same bytes (the BP3 pattern).
    crypto::hash emission_p_id{};
    uint64_t emission_epochs[SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS] = {};
    size_t emission_epochs_len = 0;
    if (emission_vin)
    {
      const uint8_t extract_rc = shekyl_archival_emission_vin_extract(
        emission_vin->canonical_bytes.data(), emission_vin->canonical_bytes.size(),
        reinterpret_cast<uint8_t*>(emission_p_id.data),
        emission_epochs, SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS, &emission_epochs_len);
      if (extract_rc != SHEKYL_EMISSION_VIN_OK || emission_epochs_len == 0)
      {
        // The engine verified these bytes at Phase C; a failed re-extract
        // is an internal inconsistency, never a verdict (§3.4).
        MERROR("submit commit: emission vin re-extract failed on engine-verified bytes");
        return SHEKYL_SUBMIT_INTERNAL_FAULT;
      }
    }
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
    collect_facts_locked(pool, bc, id, kis, cert_ref, bond_p_id,
      bond_is_unbond ? SHEKYL_SUBMIT_BOND_PROBE_UNBOND : SHEKYL_SUBMIT_BOND_PROBE_JOIN,
      emission_vin ? &emission_p_id : nullptr, emission_epochs, emission_epochs_len,
      fresh, out_fresh_ki_conflicts);
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
      // Bond-record re-check, direction chosen by the post kind. §8.7.1 BP3:
      // Phase C verified the record ABSENT for a JoinMarket bond-post, so a
      // record now present means a competing bond-post block landed during C.
      // §8.7.1.1 UB2: an exit does NOT remove the row, so the debit arm
      // cannot mirror that -- it re-checks the balance against the debit
      // Phase C verified, which a competing exit zeroes and a competing
      // credit raises. Either arm means the slot moved — Rust classifies
      // DoubleSpendConflict from these fresh facts; C++ chooses no verdict.
      // §8.7.1 BP3 (credit): a record APPEARING during C consumed the claim
      // slot. §8.7.1.1 UB2 (debit): the record does not disappear on exit --
      // apply_archival_unbond rewrites the row with a zero bonded total -- so
      // the debit arm re-checks the BALANCE it was verified against. Gone, or
      // no longer equal to this transaction's bond_debit, both mean these
      // bytes can no longer connect. Rust classifies; C++ chooses no verdict.
      raced = fresh.bond_record_probed != 0
        && (bond_is_unbond
              ? (fresh.bond_record_exists == 0
                 || fresh.bond_record_bonded_total != bond_debit)
              : fresh.bond_record_exists != 0);
    if (!raced)
      // §8.7.2 E6 re-check: the emission claim slot moved during C (record
      // gone, or a claimed epoch consumed by a competing claim) — Rust
      // classifies DoubleSpendConflict from these fresh facts.
      raced = fresh.emission_probed != 0 && fresh.emission_claim_conflict != 0;
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
    //
    // Q12-D5a once-at-origin: this is the one roll. `true` → `invalid`,
    // which `send_txs` fail-closes onto the anonymity zone. `false` →
    // `public_`, which `send_txs` sends on clearnet *by design* — not as
    // a fallback from an unusable chosen zone. Pool re-relays of `local`
    // keep passing `invalid` and do not come through this function, so
    // they cannot re-roll. A missed nudge is a second chooser (the pool
    // then first-decides always-anon) — D5a in miniature, FOLLOWUPS —
    // not a reason to roll on the pool path.
    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(std::move(txblob));
    protocol.relay_transactions(
      r,
      boost::uuids::nil_uuid(),
      /* One crossing: the roll and its zone mapping both live in Rust
         (rule 40). Byte contract static_asserted in enums.h. */
      static_cast<epee::net_utils::zone>(shekyl_relay_zone_roll_originated_zone()),
      relay_method::local);
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

const shekyl_submit_unbond_facts_ffi* shekyl_submit_unbond_facts_view(
  const shekyl_submit_unbond_facts_handle* h)
{
  return h ? &h->view : nullptr;
}

void shekyl_submit_unbond_facts_free(shekyl_submit_unbond_facts_handle* h)
{
  delete h;
}

int shekyl_submit_snapshot_facts(core_rpc_handle* h,
  const uint8_t* txid,
  const uint8_t* key_images, size_t n_key_images,
  const uint8_t* reference_block,
  const uint8_t* bond_p_canonical_id,
  uint8_t bond_probe_kind,
  const uint8_t* emission_p_canonical_id,
  const uint64_t* emission_epochs, size_t n_emission_epochs,
  shekyl_submit_emission_facts_handle** out_emission,
  shekyl_submit_unbond_facts_handle** out_unbond,
  shekyl_submit_facts_ffi* out_facts,
  uint8_t* out_ki_conflicts)
{
  if (!h || !h->rpc)
    return SHEKYL_SUBMIT_INTERNAL_FAULT;
  core& c = h->rpc->get_core();
  return daemon_submit::snapshot_facts(c.get_pool(), c.get_blockchain_storage(),
    txid, key_images, n_key_images, reference_block, bond_p_canonical_id,
    bond_probe_kind, emission_p_canonical_id, emission_epochs,
    n_emission_epochs, out_emission, out_unbond, out_facts, out_ki_conflicts);
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
  out->bond_record_probed = static_cast<uint8_t>(submit_facts_field_value(seed, 12));
  out->bond_record_exists = static_cast<uint8_t>(submit_facts_field_value(seed, 13));
  out->emission_probed = static_cast<uint8_t>(submit_facts_field_value(seed, 14));
  out->emission_claim_conflict = static_cast<uint8_t>(submit_facts_field_value(seed, 15));
  out->ref_height = submit_facts_field_value(seed, 4);
  for (size_t i = 0; i < sizeof(out->root); ++i)
    out->root[i] = static_cast<uint8_t>(submit_facts_field_value(seed, 5) >> ((i % 8) * 8));
  out->fee_per_byte = submit_facts_field_value(seed, 6);
  out->fee_quantization_mask = submit_facts_field_value(seed, 7);
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
