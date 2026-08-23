// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc_facts_ffi.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include "core_rpc_ffi_internal.h"
#include "core_rpc_server.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "misc_log_ex.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc.facts"

namespace
{
  // Same derivation as the submit twins (daemon_submit_ffi.cpp) so both
  // languages compute identical per-field values from one seed.
  uint64_t field_value(uint64_t seed, uint64_t field)
  {
    if (seed == 0)
      return 0;
    if (seed == UINT64_MAX)
      return UINT64_MAX;
    uint64_t z = seed ^ (0x9E3779B97F4A7C15ULL * (field + 1));
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
}

namespace daemon_rpc_facts {

// Body of `shekyl_rpc_block_hash_at`; see the header for why it is separate.
int block_hash_at(cryptonote::Blockchain& bc, uint64_t height,
  shekyl_rpc_block_hash_facts* out) noexcept
{
  if (!out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  try
  {
    std::memset(out, 0, sizeof(*out));
    // Both reads under ONE acquisition of the blockchain lock.
    // `Blockchain::get_block_id_by_height` takes none and documents that a
    // caller combining it with a height read must — this pair is the example
    // its comment names. A miss there is a *null hash*, not an exception
    // (BLOCK_DNE is swallowed), so the unlocked pair could answer 32 zero
    // bytes as a successful block hash after a reorg.
    //
    // Safe to hold: `m_blockchain_lock` is an `epee::critical_section` over a
    // `boost::recursive_mutex`, so the callees' own acquisitions nest, and
    // this shim takes no other lock, so no ordering cycle exists. The cost is
    // that a read can wait behind a block being connected; that is the right
    // trade for an answer that cannot be a lie.
    const std::lock_guard<cryptonote::Blockchain> guard(bc);
    const uint64_t chain_height = bc.get_current_blockchain_height();
    out->chain_height = chain_height;
    if (height >= chain_height)
      return SHEKYL_RPC_FACTS_OK;  // past the tip: data, not a fault (found == 0)

    const crypto::hash id = bc.get_block_id_by_height(height);
    // An *in-range* height that resolves to nothing means the store reported
    // a height it cannot produce the block for: a data-integrity fault of
    // this daemon, not a fact about the caller's request. Its own code, so it
    // is logged and alertable — reporting the zero hash as an identity would
    // be a lie, and answering "greater than the tip" would be a different lie
    // about a height that is below it.
    if (id == crypto::null_hash)
    {
      MERROR("block hash facts: chain height " << chain_height
        << " but no block at in-range height " << height);
      std::memset(out, 0, sizeof(*out));
      return SHEKYL_RPC_FACTS_ERR_INCONSISTENT;
    }
    std::memcpy(out->hash, id.data, sizeof(out->hash));
    out->found = 1;
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("block hash facts: exception: " << e.what());
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("block hash facts: unknown exception");
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

// Body of `shekyl_rpc_block_header_at`. Carries what the deleted
// `on_get_block_header_by_height` did together with
// `fill_block_header_response` (which the header methods still in C++ keep
// using): one lock, the bound, the block, and every field the wire's header
// carries.
int block_header_at(cryptonote::Blockchain& bc, uint64_t height,
  bool fill_pow_hash, shekyl_rpc_block_header_facts* out) noexcept
{
  if (!out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  try
  {
    std::memset(out, 0, sizeof(*out));
    cryptonote::block blk;
    {
      // One acquisition for the whole projection: the bound, the block, its
      // weights and its difficulties all describe the same chain state (see
      // `block_hash_at` for why the lock is safe to hold here). The long hash
      // is deliberately *outside* this scope — see below.
      const std::lock_guard<cryptonote::Blockchain> guard(bc);
      const uint64_t chain_height = bc.get_current_blockchain_height();
      out->chain_height = chain_height;
      if (height >= chain_height)
        return SHEKYL_RPC_FACTS_OK;  // past the tip: data, not a fault

      const crypto::hash id = bc.get_block_id_by_height(height);
      // Either failure means the store reported a height it cannot produce the
      // block for — the same data-integrity fault `block_hash_at` reports, and
      // the condition the C++ handler answered "can't get block by height" to.
      if (id == crypto::null_hash || !bc.get_block_by_hash(id, blk))
      {
        MERROR("block header facts: chain height " << chain_height
          << " but no block at in-range height " << height);
        std::memset(out, 0, sizeof(*out));
        return SHEKYL_RPC_FACTS_ERR_INCONSISTENT;
      }

      std::memcpy(out->hash, id.data, sizeof(out->hash));
      std::memcpy(out->prev_hash, blk.prev_id.data, sizeof(out->prev_hash));
      const crypto::hash miner_tx_hash = cryptonote::get_transaction_hash(blk.miner_tx);
      std::memcpy(out->miner_tx_hash, miner_tx_hash.data, sizeof(out->miner_tx_hash));
      std::memcpy(out->curve_tree_root, blk.curve_tree_root.data, sizeof(out->curve_tree_root));
      std::memcpy(out->attestation_root, blk.attestation_root.data, sizeof(out->attestation_root));

      out->height = height;
      out->depth = chain_height - height - 1;
      out->timestamp = blk.timestamp;

      const cryptonote::difficulty_type difficulty = bc.block_difficulty(height);
      out->difficulty_lo = (difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
      out->difficulty_hi = ((difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
      const cryptonote::difficulty_type cumulative =
        bc.get_db().get_block_cumulative_difficulty(height);
      out->cumulative_difficulty_lo = (cumulative & 0xffffffffffffffff).convert_to<uint64_t>();
      out->cumulative_difficulty_hi =
        ((cumulative >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();

      // The block's reward is the sum of its coinbase outputs, and
      // `get_outs_money_amount` is this tree's one definition of that sum.
      // NB `core_rpc_server::get_block_reward` is a private third copy of the
      // same loop, and its name collides with the *consensus*
      // `cryptonote::get_block_reward(median_weight, ...)`, which computes the
      // subsidy rather than reading a block. It dies with
      // `fill_block_header_response` in RK-5; nothing new should call it.
      out->reward = cryptonote::get_outs_money_amount(blk.miner_tx);

      out->block_weight = bc.get_db().get_block_weight(height);
      out->long_term_weight = bc.get_db().get_block_long_term_weight(height);
      out->num_txes = blk.tx_hashes.size();
      out->nonce = blk.nonce;
      out->major_version = blk.major_version;
      out->minor_version = blk.minor_version;
      // Reached by height, so never an alt block.
      out->orphan_status = 0;
      out->found = 1;
    }

    // Outside the lock, as the C++ handler had it. The long hash is a pure
    // function of the block and its height, so it needs none of the chain
    // state the projection had to read atomically — and it is by far the
    // expensive part of this call: a block in a different seed epoch makes
    // RandomX rebuild its cache, which would otherwise stall block handling
    // and p2p for as long as that takes.
    if (fill_pow_hash)
    {
      const crypto::hash pow = get_block_longhash(&bc, blk, height, 0);
      std::memcpy(out->pow_hash, pow.data, sizeof(out->pow_hash));
      out->pow_hash_filled = 1;
    }
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("block header facts: exception: " << e.what());
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("block header facts: unknown exception");
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

} // namespace daemon_rpc_facts

extern "C" {

// Every export is an exception barrier: a throw from a core / P2P read is
// logged and becomes SHEKYL_RPC_FACTS_ERR_INTERNAL, never an unwind across
// the C ABI into Rust (which would abort the daemon). Same discipline as
// daemon_submit_ffi.cpp's shims.
int shekyl_rpc_chain_tip(core_rpc_handle* h, shekyl_rpc_chain_tip_facts* out)
{
  if (!h || !h->rpc || !out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  try
  {
    std::memset(out, 0, sizeof(*out));
    cryptonote::core& core = h->rpc->get_core();
    uint64_t top_height = 0;
    crypto::hash top_hash = crypto::null_hash;
    core.get_blockchain_top(top_height, top_hash);
    out->chain_height = top_height + 1;
    std::memcpy(out->top_hash, top_hash.data, sizeof(out->top_hash));
    out->target_height = core.get_target_blockchain_height();
    out->synchronized = h->rpc->get_p2p().get_payload_object().is_synchronized() ? 1 : 0;
    out->release_build = SHEKYL_VERSION_IS_RELEASE ? 1 : 0;
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("chain tip facts: exception: " << e.what());
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("chain tip facts: unknown exception");
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

int shekyl_rpc_hardforks(core_rpc_handle* h,
  const shekyl_rpc_hardfork_entry** out, size_t* out_len, void** out_owner)
{
  if (!h || !h->rpc || !out || !out_len || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  *out_owner = nullptr;
  std::unique_ptr<std::vector<shekyl_rpc_hardfork_entry>> rows;
  try
  {
    rows.reset(new std::vector<shekyl_rpc_hardfork_entry>());
    for (const hardfork_t& hf : h->rpc->get_core().get_blockchain_storage().get_hardforks())
    {
      shekyl_rpc_hardfork_entry e;
      std::memset(&e, 0, sizeof(e));
      e.version = hf.version;
      e.height = hf.height;
      rows->push_back(e);
    }
  }
  catch (const std::exception& e)
  {
    MERROR("hardforks facts: exception: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("hardforks facts: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  *out = rows->empty() ? nullptr : rows->data();
  *out_len = rows->size();
  *out_owner = rows.release();
  return SHEKYL_RPC_FACTS_OK;
}

void shekyl_rpc_hardforks_free(void* owner)
{
  delete static_cast<std::vector<shekyl_rpc_hardfork_entry>*>(owner);
}

int shekyl_rpc_block_hash_at(core_rpc_handle* h, uint64_t height,
  shekyl_rpc_block_hash_facts* out)
{
  if (!h || !h->rpc || !out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  return daemon_rpc_facts::block_hash_at(
    h->rpc->get_core().get_blockchain_storage(), height, out);
}

int shekyl_rpc_block_header_at(core_rpc_handle* h, uint64_t height,
  uint8_t fill_pow_hash, shekyl_rpc_block_header_facts* out)
{
  if (!h || !h->rpc || !out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  return daemon_rpc_facts::block_header_at(
    h->rpc->get_core().get_blockchain_storage(), height, fill_pow_hash != 0, out);
}

void shekyl_rpc_chain_tip_facts_test_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->chain_height = field_value(seed, 0);
  for (size_t i = 0; i < sizeof(out->top_hash); ++i)
    out->top_hash[i] = static_cast<uint8_t>(field_value(seed, 1) >> ((i % 8) * 8));
  out->target_height = field_value(seed, 2);
  out->synchronized = static_cast<uint8_t>(field_value(seed, 3));
  out->release_build = static_cast<uint8_t>(field_value(seed, 4));
}

int shekyl_rpc_chain_tip_facts_test_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_chain_tip_facts expected;
  shekyl_rpc_chain_tip_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_hardfork_entry_test_fill(shekyl_rpc_hardfork_entry* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->version = static_cast<uint8_t>(field_value(seed, 0));
  out->height = field_value(seed, 1);
}

int shekyl_rpc_hardfork_entry_test_check(const shekyl_rpc_hardfork_entry* entry, uint64_t seed)
{
  if (!entry)
    return -1;
  shekyl_rpc_hardfork_entry expected;
  shekyl_rpc_hardfork_entry_test_fill(&expected, seed);
  return std::memcmp(entry, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_block_hash_facts_test_fill(shekyl_rpc_block_hash_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  for (size_t i = 0; i < sizeof(out->hash); ++i)
    out->hash[i] = static_cast<uint8_t>(field_value(seed, 0) >> ((i % 8) * 8));
  out->chain_height = field_value(seed, 1);
  out->found = static_cast<uint8_t>(field_value(seed, 2));
}

int shekyl_rpc_block_hash_facts_test_check(const shekyl_rpc_block_hash_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_block_hash_facts expected;
  shekyl_rpc_block_hash_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_block_header_facts_test_fill(shekyl_rpc_block_header_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  uint8_t* const hashes[] = {out->hash, out->prev_hash, out->miner_tx_hash,
    out->curve_tree_root, out->attestation_root, out->pow_hash};
  for (uint64_t f = 0; f < 6; ++f)
  {
    for (size_t i = 0; i < 32; ++i)
      hashes[f][i] = static_cast<uint8_t>(field_value(seed, f) >> ((i % 8) * 8));
  }
  out->height = field_value(seed, 6);
  out->depth = field_value(seed, 7);
  out->chain_height = field_value(seed, 8);
  out->timestamp = field_value(seed, 9);
  out->difficulty_lo = field_value(seed, 10);
  out->difficulty_hi = field_value(seed, 11);
  out->cumulative_difficulty_lo = field_value(seed, 12);
  out->cumulative_difficulty_hi = field_value(seed, 13);
  out->reward = field_value(seed, 14);
  out->block_weight = field_value(seed, 15);
  out->long_term_weight = field_value(seed, 16);
  out->num_txes = field_value(seed, 17);
  out->nonce = static_cast<uint32_t>(field_value(seed, 18));
  out->major_version = static_cast<uint8_t>(field_value(seed, 19));
  out->minor_version = static_cast<uint8_t>(field_value(seed, 20));
  out->orphan_status = static_cast<uint8_t>(field_value(seed, 21));
  out->pow_hash_filled = static_cast<uint8_t>(field_value(seed, 22));
  out->found = static_cast<uint8_t>(field_value(seed, 23));
}

int shekyl_rpc_block_header_facts_test_check(const shekyl_rpc_block_header_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_block_header_facts expected;
  shekyl_rpc_block_header_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

} // extern "C"
