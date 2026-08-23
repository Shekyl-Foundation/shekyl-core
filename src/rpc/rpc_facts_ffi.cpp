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

} // extern "C"
