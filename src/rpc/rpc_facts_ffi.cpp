// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc_facts_ffi.h"

#include <cstring>
#include <memory>
#include <string>
#include <variant>
#include <mutex>
#include <vector>

#include "core_rpc_ffi_internal.h"
#include "core_rpc_server.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/tx_pool.h"
#include "rpc_tx_json.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_ffi.h"
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
    crypto::hash seed = crypto::null_hash;
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

      // The long hash is computed after this scope, but its RandomX seed is
      // chain state and belongs to *this* snapshot, so it is read here.
      // `get_pending_block_id_by_height` reads the prepare-state members
      // (`m_prepare_height` / `m_prepare_blocks`) with no lock of its own;
      // `prepare_handle_incoming_blocks` writes them holding this lock, so
      // reading them here is both race-free and consistent with the block
      // above. Left to resolve itself inside `get_block_longhash`, the seed
      // would be read after the unlock — pairing this block with a seed from
      // another chain state.
      if (fill_pow_hash)
        seed = bc.get_pending_block_id_by_height(
          shekyl_pow_randomx_v2_seedheight(height));
    }

    // Outside the lock: with the seed passed explicitly, the hash is a pure
    // function of values already copied out, so it needs nothing the lock
    // protects — and it is by far the expensive part of this call. A block in
    // a different seed epoch makes RandomX rebuild its cache, which under the
    // lock would stall block handling and p2p for as long as that takes
    // (seconds, not microseconds: ~1.2 s on a cold genesis block here).
    if (fill_pow_hash)
    {
      const crypto::hash pow = get_block_longhash(&bc, blk, height, &seed);
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

// Owns every variable-length payload of one `block_at` answer, so the caller
// releases them with a single `shekyl_rpc_block_free`. Three separate owners
// would be three chances to leak one. Named (not anonymous) so the C entry
// point's `_free` twin below can name the type it deletes.
struct block_payload_owner
{
  std::string blob;
  std::string json;
  std::vector<uint8_t> tx_hashes;  // n * 32, contiguous
};

// Body of `shekyl_rpc_block_at`. Carries what the deleted `on_get_block` did
// together with `fill_block_header_response`.
int block_at(cryptonote::Blockchain& bc, const crypto::hash* block_hash,
  uint64_t height, bool fill_pow_hash,
  shekyl_rpc_block_header_facts* out_header,
  shekyl_rpc_block_payload* out_payload, void** out_owner) noexcept
{
  if (!out_header || !out_payload || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  std::memset(out_header, 0, sizeof(*out_header));
  std::memset(out_payload, 0, sizeof(*out_payload));
  *out_owner = nullptr;
  try
  {
    cryptonote::block blk;
    crypto::hash seed = crypto::null_hash;
    uint64_t block_height = 0;
    std::unique_ptr<block_payload_owner> owned(new block_payload_owner());
    {
      // One acquisition for the whole projection, as `block_header_at` does.
      // The long hash is computed after it; its seed is read inside.
      const std::lock_guard<cryptonote::Blockchain> guard(bc);
      const uint64_t chain_height = bc.get_current_blockchain_height();
      out_header->chain_height = chain_height;

      crypto::hash id;
      if (block_hash)
      {
        id = *block_hash;
      }
      else
      {
        if (height >= chain_height)
          return SHEKYL_RPC_FACTS_OK;  // past the tip: data, not a fault
        id = bc.get_block_id_by_height(height);
        if (id == crypto::null_hash)
          return SHEKYL_RPC_FACTS_OK;  // in range but absent: still "no block"
      }

      bool orphan = false;
      if (!bc.get_block_by_hash(id, blk, &orphan))
        return SHEKYL_RPC_FACTS_OK;  // no such block; the caller knows how it asked

      // The height comes from the coinbase, not from the lookup, and every
      // height-keyed field below is then read at THAT height — so for an alt
      // block they describe the main-chain block sharing its height. Inherited
      // and preserved (RK-D8); see the §7 entry of 2026-08-23.
      if (blk.miner_tx.vin.size() != 1
        || !std::holds_alternative<cryptonote::txin_gen>(blk.miner_tx.vin.front()))
      {
        MERROR("block facts: coinbase of block " << id << " is not a single txin_gen");
        return SHEKYL_RPC_FACTS_ERR_INCONSISTENT;
      }
      block_height = std::get<cryptonote::txin_gen>(blk.miner_tx.vin.front()).height;
      // The coinbase names its own height, so it can name one this chain has
      // not reached — an alt block extending past the tip is exactly that.
      // Every height-keyed read below would then be out of range, and `depth`
      // would underflow to a value near 2^64 before those reads threw. The
      // C++ computed that underflow too and relied on the DB throwing
      // afterwards; checking here makes the failure named instead of
      // incidental, and the subtraction unable to wrap.
      if (block_height >= chain_height)
      {
        MERROR("block facts: block " << id << " claims coinbase height " << block_height
          << " at chain height " << chain_height << "; no coherent header can be built");
        return SHEKYL_RPC_FACTS_ERR_INTERNAL;
      }

      std::memcpy(out_header->hash, id.data, sizeof(out_header->hash));
      std::memcpy(out_header->prev_hash, blk.prev_id.data, sizeof(out_header->prev_hash));
      const crypto::hash miner_tx_hash = cryptonote::get_transaction_hash(blk.miner_tx);
      std::memcpy(out_header->miner_tx_hash, miner_tx_hash.data,
        sizeof(out_header->miner_tx_hash));
      std::memcpy(out_header->curve_tree_root, blk.curve_tree_root.data,
        sizeof(out_header->curve_tree_root));
      std::memcpy(out_header->attestation_root, blk.attestation_root.data,
        sizeof(out_header->attestation_root));

      out_header->height = block_height;
      out_header->depth = chain_height - block_height - 1;
      out_header->timestamp = blk.timestamp;

      const cryptonote::difficulty_type difficulty = bc.block_difficulty(block_height);
      out_header->difficulty_lo = (difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
      out_header->difficulty_hi = ((difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
      const cryptonote::difficulty_type cumulative =
        bc.get_db().get_block_cumulative_difficulty(block_height);
      out_header->cumulative_difficulty_lo =
        (cumulative & 0xffffffffffffffff).convert_to<uint64_t>();
      out_header->cumulative_difficulty_hi =
        ((cumulative >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();

      out_header->reward = cryptonote::get_outs_money_amount(blk.miner_tx);
      out_header->block_weight = bc.get_db().get_block_weight(block_height);
      out_header->long_term_weight = bc.get_db().get_block_long_term_weight(block_height);
      out_header->num_txes = blk.tx_hashes.size();
      out_header->nonce = blk.nonce;
      out_header->major_version = blk.major_version;
      out_header->minor_version = blk.minor_version;
      out_header->orphan_status = orphan ? 1 : 0;
      out_header->found = 1;

      // The variable payloads are built here too: `json` renders the block
      // that this snapshot describes, so it belongs to the same read.
      owned->blob = cryptonote::t_serializable_object_to_blob(blk);
      owned->json = cryptonote::obj_to_json_str(blk);
      owned->tx_hashes.resize(blk.tx_hashes.size() * sizeof(crypto::hash));
      for (size_t i = 0; i < blk.tx_hashes.size(); ++i)
      {
        std::memcpy(owned->tx_hashes.data() + i * sizeof(crypto::hash),
          blk.tx_hashes[i].data, sizeof(crypto::hash));
      }

      if (fill_pow_hash)
        seed = bc.get_pending_block_id_by_height(
          shekyl_pow_randomx_v2_seedheight(block_height));
    }

    // Outside the lock, with the seed already taken from inside it: see
    // `block_header_at` for why both halves of that sentence matter.
    if (fill_pow_hash)
    {
      const crypto::hash pow = get_block_longhash(&bc, blk, block_height, &seed);
      std::memcpy(out_header->pow_hash, pow.data, sizeof(out_header->pow_hash));
      out_header->pow_hash_filled = 1;
    }

    out_payload->blob = reinterpret_cast<const uint8_t*>(owned->blob.data());
    out_payload->blob_len = owned->blob.size();
    out_payload->json = owned->json.c_str();
    out_payload->json_len = owned->json.size();
    out_payload->tx_hashes = owned->tx_hashes.empty() ? nullptr : owned->tx_hashes.data();
    out_payload->tx_hashes_len = owned->tx_hashes.size() / sizeof(crypto::hash);
    *out_owner = owned.release();
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("block facts: exception: " << e.what());
    std::memset(out_header, 0, sizeof(*out_header));
    std::memset(out_payload, 0, sizeof(*out_payload));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("block facts: unknown exception");
    std::memset(out_header, 0, sizeof(*out_header));
    std::memset(out_payload, 0, sizeof(*out_payload));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

// Body of `shekyl_rpc_tx_output_indices`. One read, so no lock is taken
// here: `Blockchain::get_tx_outputs_gindexs` takes its own, and there is no
// second value that has to agree with it.
int tx_output_indices(cryptonote::Blockchain& bc, const crypto::hash& txid,
  const uint64_t** out, size_t* out_len, uint8_t* out_found, void** out_owner) noexcept
{
  if (out_owner)
    *out_owner = nullptr;
  if (!out || !out_len || !out_found || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  *out_found = 0;
  try
  {
    std::unique_ptr<std::vector<uint64_t>> rows(new std::vector<uint64_t>());
    if (!bc.get_tx_outputs_gindexs(txid, *rows))
      return SHEKYL_RPC_FACTS_OK;  // no such transaction: data, not a fault
    *out = rows->empty() ? nullptr : rows->data();
    *out_len = rows->size();
    *out_found = 1;
    *out_owner = rows.release();
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("tx output indices facts: exception: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("tx output indices facts: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

// Owns every allocation behind one `blocks_by_height` answer. The entry
// views point into these vectors, so they must not reallocate after the
// views are built — hence the two-pass fill: blobs first, pointers second.
struct blocks_owner
{
  std::vector<std::string> blocks;               // one per height
  std::vector<std::vector<std::string>> txs;     // per height, per tx
  std::vector<std::vector<const uint8_t*>> tx_ptrs;
  std::vector<std::vector<size_t>> tx_lens;
  std::vector<shekyl_rpc_block_entry> entries;
};

// Owns every allocation behind one `transactions` answer. Entry views point
// into these vectors, so the fill is two-pass for `blocks_owner`'s reason:
// pointers taken in pass one would dangle when a vector reallocated.
struct transactions_owner
{
  std::vector<std::string> pruned;      // one per request slot; empty when missed
  std::vector<std::string> prunable;
  std::vector<std::vector<uint64_t>> output_indices;
  std::vector<shekyl_rpc_tx_entry> entries;
};

// Body of `shekyl_rpc_transactions`.
//
// Takes the `Blockchain` and the pool separately rather than a `core`, for
// `blocks_by_height`'s reason — a body that required a `core` would only be
// reachable through a live daemon — and because passing the two lock domains
// as two arguments is what makes the rule below visible at the signature.
//
// **Two passes over two stores, and no lock spanning them.** The chain reads
// happen first, then the pool is asked about what the chain did not have.
// `tx_memory_pool` takes `m_transactions_lock` then `m_blockchain`
// (`tx_pool.cpp`), so holding the chain lock across a pool read would be the
// AB half of an AB-BA deadlock against every pool path that already runs BA.
// The blob, height and timestamp of a chain hit are read inside one
// `CRITICAL_REGION_LOCAL(bc)` along with the tip, so they describe one chain
// state and there is no blob-to-height race left to name.
//
// The window that remains is between the two passes: a transaction mined
// *after* the chain pass missed it and *before* the pool is asked has left the
// pool and is not in this reply's chain results, so it comes back as missed
// though the chain now holds it. The C++ handler had the same granularity and
// the same window; it is named here rather than closed by a lock that would
// trade a stale answer for a hung daemon (§3.2).
int transactions(cryptonote::Blockchain& bc, cryptonote::tx_memory_pool& pool,
  const uint8_t* txids, size_t txids_len, uint8_t include_sensitive,
  const shekyl_rpc_tx_entry** out, size_t* out_len, uint64_t* out_chain_height,
  void** out_owner) noexcept
{
  if (out_owner)
    *out_owner = nullptr;
  if (!out || !out_len || !out_chain_height || !out_owner || (!txids && txids_len))
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  *out_chain_height = 0;
  try
  {
    std::vector<crypto::hash> ids(txids_len);
    for (size_t i = 0; i < txids_len; ++i)
      std::memcpy(ids[i].data, txids + i * 32, 32);

    std::unique_ptr<transactions_owner> owned(new transactions_owner());
    owned->pruned.resize(txids_len);
    owned->prunable.resize(txids_len);
    owned->output_indices.resize(txids_len);
    // `vector(n)` value-initializes its elements, which zeroes every scalar
    // and gives the pointer members real null pointers rather than an
    // all-zero byte pattern that is only null by convention. The `memset`
    // this replaces added nothing on top of that and was undefined at
    // `txids_len == 0`, where `data()` may be null and passing null to
    // `memset` is undefined even for a zero count — and an empty
    // `get_transactions` request is valid.
    std::vector<shekyl_rpc_tx_entry> facts(txids_len);

    // ── chain ──────────────────────────────────────────────────────────────
    // The tip is read once, inside the same lock as the per-transaction
    // reads, so `confirmations` is computed by the handler against a height
    // that describes the same chain state the rest of the entry does.
    {
      CRITICAL_REGION_LOCAL(bc);
      *out_chain_height = bc.get_current_blockchain_height();
      for (size_t i = 0; i < txids_len; ++i)
      {
        cryptonote::blobdata pruned_blob;
        if (!bc.get_db().get_pruned_tx_blob(ids[i], pruned_blob))
          continue;
        owned->pruned[i] = std::move(pruned_blob);

        // The prunable HASH is read unconditionally, and the prunable BLOB is
        // optional — that asymmetry is pruning's design, not an oversight.
        // Both `prune_worker` and `prune_tx_data` delete `txs_prunable` (and
        // the worker, `txs_prunable_tip`) and never `txs_prunable_hash`:
        // keeping the hash after dropping the bytes is the entire point of
        // storing it, since it is what still lets a client bind the pruned
        // body to the transaction. Reading the hash only when the blob
        // survived would therefore report an all-zero hash for every
        // transaction on a pruned daemon — the node-local mode this daemon
        // ships post-genesis without coordination (rule 75), so the absence
        // of that mode today is not a reason to encode its absence.
        //
        // A missing hash is an inconsistent store rather than a fact: the
        // write path stores it for every transaction it indexes (the
        // `tx.version > 1` guard there is Monero-era, and Shekyl is
        // v3-from-genesis with no v1 transactions to except — rule 60), and
        // removal takes the hash with the transaction. Fabricating zeros here
        // would hand the caller a valid-looking field for a store that cannot
        // support it.
        crypto::hash ph;
        if (!bc.get_db().get_prunable_tx_hash(ids[i], ph))
        {
          MERROR("shekyl_rpc_transactions: chain holds "
            << epee::string_tools::pod_to_hex(ids[i])
            << " with no prunable hash beside it");
          return SHEKYL_RPC_FACTS_ERR_INCONSISTENT;
        }
        std::memcpy(facts[i].prunable_hash, ph.data, 32);

        cryptonote::blobdata prunable_blob;
        if (bc.get_db().get_prunable_tx_blob(ids[i], prunable_blob))
          owned->prunable[i] = std::move(prunable_blob);

        facts[i].where = 1;
        facts[i].block_height = bc.get_db().get_tx_block_height(ids[i]);
        facts[i].block_timestamp = bc.get_db().get_block_timestamp(facts[i].block_height);
        facts[i].pruned_flag = bc.get_db().tx_has_verification_data(ids[i]) ? 0 : 1;

        // A transaction the chain holds has outputs — a spend with fewer than
        // two is consensus-invalid — so a false here is the index disagreeing
        // with the transaction it was found beside, under this same lock.
        // Reporting that as an empty index list would turn corruption into a
        // successful, inaccurate reply.
        if (!bc.get_tx_outputs_gindexs(ids[i], owned->output_indices[i]))
        {
          MERROR("shekyl_rpc_transactions: chain holds "
            << epee::string_tools::pod_to_hex(ids[i])
            << " with no output-index record beside it");
          return SHEKYL_RPC_FACTS_ERR_INCONSISTENT;
        }
      }
    }

    // ── pool ───────────────────────────────────────────────────────────────
    // Only what the chain did not hold, and only if the caller is entitled to
    // see transactions the node has not broadcast.
    std::vector<crypto::hash> missed;
    std::vector<size_t> missed_slots;
    for (size_t i = 0; i < txids_len; ++i)
      if (facts[i].where == 0)
      {
        missed.push_back(ids[i]);
        missed_slots.push_back(i);
      }
    if (!missed.empty())
    {
      std::vector<std::pair<crypto::hash, cryptonote::tx_memory_pool::tx_details>> found;
      pool.get_transactions_info(missed, found, include_sensitive != 0);
      // One result per input occurrence, so a repeated txid must consume a
      // repeated slot. Searching from zero every time would write the first
      // matching slot twice and leave the second reported missing — a request
      // like [H, H] answering only its first H.
      std::vector<bool> slot_taken(missed.size(), false);
      for (const auto& entry : found)
      {
        // Back to the request slot it came from. The C++ re-sorted a merged
        // list to recover this; here the mapping never left.
        size_t slot = txids_len;
        for (size_t k = 0; k < missed.size(); ++k)
          if (!slot_taken[k] && missed[k] == entry.first)
          {
            slot_taken[k] = true;
            slot = missed_slots[k];
            break;
          }
        if (slot == txids_len)
          continue;
        const cryptonote::tx_memory_pool::tx_details& td = entry.second;
        std::stringstream ss;
        binary_archive<true> ba(ss);
        if (!const_cast<cryptonote::transaction&>(td.tx).serialize_base(ba))
          return SHEKYL_RPC_FACTS_ERR_INTERNAL;
        owned->pruned[slot] = ss.str();
        // The pool stores the whole blob; the prunable half is what follows
        // the base, which is how the C++ handler split it.
        if (td.tx_blob.size() > owned->pruned[slot].size())
          owned->prunable[slot] = td.tx_blob.substr(owned->pruned[slot].size());
        const crypto::hash ph = cryptonote::get_transaction_prunable_hash(td.tx);
        std::memcpy(facts[slot].prunable_hash, ph.data, 32);
        facts[slot].where = 2;
        facts[slot].double_spend_seen = td.double_spend_seen ? 1 : 0;
        facts[slot].relayed = td.relayed ? 1 : 0;
        facts[slot].received_timestamp = td.receive_time;
      }
    }

    // Second pass: the vectors are final, so views into them are stable.
    owned->entries = std::move(facts);
    for (size_t i = 0; i < txids_len; ++i)
    {
      shekyl_rpc_tx_entry& e = owned->entries[i];
      e.pruned = owned->pruned[i].empty()
        ? nullptr : reinterpret_cast<const uint8_t*>(owned->pruned[i].data());
      e.pruned_len = owned->pruned[i].size();
      e.prunable = owned->prunable[i].empty()
        ? nullptr : reinterpret_cast<const uint8_t*>(owned->prunable[i].data());
      e.prunable_len = owned->prunable[i].size();
      e.output_indices = owned->output_indices[i].empty()
        ? nullptr : owned->output_indices[i].data();
      e.output_indices_len = owned->output_indices[i].size();
    }
    *out = owned->entries.empty() ? nullptr : owned->entries.data();
    *out_len = owned->entries.size();
    *out_owner = owned.release();
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("shekyl_rpc_transactions: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("shekyl_rpc_transactions: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

// Body of `shekyl_rpc_key_images_spent`. Chain first, then the pool for the
// ones the chain did not have — the same two questions the C++ handler asked,
// minus its filter/re-index dance, because the answer is written straight into
// the caller's slot.
int key_images_spent(cryptonote::Blockchain& bc, cryptonote::tx_memory_pool& pool,
  const uint8_t* key_images, size_t count, uint8_t* out_status) noexcept
{
  if (!out_status || (!key_images && count))
    return SHEKYL_RPC_FACTS_ERR_NULL;
  try
  {
    std::vector<crypto::key_image> kis(count);
    for (size_t i = 0; i < count; ++i)
      std::memcpy(&kis[i], key_images + i * 32, 32);

    std::vector<bool> spent;
    {
      CRITICAL_REGION_LOCAL(bc);
      spent = bc.have_tx_keyimges_as_spent(epee::span<const crypto::key_image>(kis.data(), kis.size()));
      if (spent.size() != count)
        return SHEKYL_RPC_FACTS_ERR_INTERNAL;
    }
    std::vector<crypto::key_image> unspent;
    std::vector<size_t> unspent_slots;
    for (size_t i = 0; i < count; ++i)
    {
      out_status[i] = spent[i] ? 1 : 0;
      if (!spent[i])
      {
        unspent.push_back(kis[i]);
        unspent_slots.push_back(i);
      }
    }
    if (!unspent.empty())
    {
      std::vector<bool> in_pool;
      // Filters on `relay_category::broadcasted` unconditionally, so a
      // stem-phase transaction's key image does not answer here whoever asks.
      if (!pool.check_for_key_images(unspent, in_pool) || in_pool.size() != unspent.size())
        return SHEKYL_RPC_FACTS_ERR_INTERNAL;
      for (size_t k = 0; k < unspent.size(); ++k)
        if (in_pool[k])
          out_status[unspent_slots[k]] = 2;
    }
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("shekyl_rpc_key_images_spent: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("shekyl_rpc_key_images_spent: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

// Body of `shekyl_rpc_tx_to_json` (RK-D11). No core, no lock: it parses the
// blob the caller passes and renders it the way epee did, which is the only
// part of this that has to stay in C++.
int tx_to_json(const uint8_t* blob, size_t blob_len, uint8_t pruned,
  const char** out, size_t* out_len, void** out_owner) noexcept
{
  if (out_owner)
    *out_owner = nullptr;
  if (!out || !out_len || !out_owner || (!blob && blob_len))
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  try
  {
    const cryptonote::blobdata data(reinterpret_cast<const char*>(blob), blob_len);
    cryptonote::transaction tx;
    std::unique_ptr<std::string> rendered(new std::string());
    if (pruned)
    {
      if (!cryptonote::parse_and_validate_tx_base_from_blob(data, tx))
        return SHEKYL_RPC_FACTS_ERR_INTERNAL;
      cryptonote::pruned_transaction ptx{tx};
      *rendered = cryptonote::obj_to_json_str(ptx);
    }
    else
    {
      if (!cryptonote::parse_and_validate_tx_from_blob(data, tx))
        return SHEKYL_RPC_FACTS_ERR_INTERNAL;
      *rendered = cryptonote::obj_to_json_str(tx);
    }
    *out = rendered->data();
    *out_len = rendered->size();
    *out_owner = rendered.release();
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("shekyl_rpc_tx_to_json: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("shekyl_rpc_tx_to_json: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

// Body of `shekyl_rpc_blocks_by_height`. Carries what the deleted
// `on_get_blocks_by_height` did, minus the restricted cap, which is handler
// policy (RK-D6).
//
// Takes the `Blockchain`, not the `core`, deliberately: everything it needs
// is there, and a body that required a `core` would be reachable only
// through a live daemon — the shim fixture builds a Blockchain and a pool.
// The transaction read stays parse-then-`tx_to_blob`, matching what the C++
// handler did, rather than the stored blob: the two should agree, and
// "should" is not a basis for a byte-preserving migration.
int blocks_by_height(cryptonote::Blockchain& bc, const uint64_t* heights, size_t heights_len,
  const shekyl_rpc_block_entry** out, size_t* out_len, uint64_t* out_failed_height,
  uint8_t* out_ok, void** out_owner) noexcept
{
  if (out_owner)
    *out_owner = nullptr;
  if (!out || !out_len || !out_failed_height || !out_ok || !out_owner
    || (!heights && heights_len))
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  *out_failed_height = 0;
  *out_ok = 0;
  try
  {
    std::unique_ptr<blocks_owner> owned(new blocks_owner());
    owned->blocks.reserve(heights_len);
    owned->txs.reserve(heights_len);
    bool failed = false;
    for (size_t i = 0; i < heights_len; ++i)
    {
      cryptonote::block blk;
      try
      {
        blk = bc.get_db().get_block_from_height(heights[i]);
      }
      catch (...)
      {
        // A height this chain cannot produce is the caller's answer, not a
        // fault: the C++ replied with a status naming the height, and the
        // handler rebuilds that message from `out_failed_height`.
        //
        // The blocks already gathered are kept, because the C++ kept them:
        // it cleared `res.blocks` once before the loop and returned from
        // here without clearing again, so a request like `[0, past_tip]`
        // carried block 0 alongside the error. Dropping the prefix would be
        // a quieter reply and a different one.
        *out_failed_height = heights[i];
        failed = true;
        break;
      }
      owned->blocks.push_back(cryptonote::block_to_blob(blk));
      std::vector<cryptonote::transaction> txs;
      std::vector<crypto::hash> missed;
      bc.get_transactions(blk.tx_hashes, txs, missed);
      std::vector<std::string> blobs;
      blobs.reserve(txs.size());
      for (const cryptonote::transaction& tx : txs)
        blobs.push_back(cryptonote::tx_to_blob(tx));
      owned->txs.push_back(std::move(blobs));
    }

    // Second pass: the vectors above are final, so views into them are
    // stable. Building them in the first pass would dangle on reallocation.
    // Sized by what was actually gathered, which is short of `heights_len`
    // when a height failed and the prefix is being returned with it.
    const size_t gathered = owned->blocks.size();
    owned->tx_ptrs.resize(gathered);
    owned->tx_lens.resize(gathered);
    owned->entries.resize(gathered);
    for (size_t i = 0; i < gathered; ++i)
    {
      const std::vector<std::string>& blobs = owned->txs[i];
      owned->tx_ptrs[i].reserve(blobs.size());
      owned->tx_lens[i].reserve(blobs.size());
      for (const std::string& b : blobs)
      {
        owned->tx_ptrs[i].push_back(reinterpret_cast<const uint8_t*>(b.data()));
        owned->tx_lens[i].push_back(b.size());
      }
      shekyl_rpc_block_entry& e = owned->entries[i];
      e.block = reinterpret_cast<const uint8_t*>(owned->blocks[i].data());
      e.block_len = owned->blocks[i].size();
      e.txs = owned->tx_ptrs[i].empty() ? nullptr : owned->tx_ptrs[i].data();
      e.tx_lens = owned->tx_lens[i].empty() ? nullptr : owned->tx_lens[i].data();
      e.tx_count = blobs.size();
    }

    *out = owned->entries.empty() ? nullptr : owned->entries.data();
    *out_len = owned->entries.size();
    *out_ok = failed ? 0 : 1;
    *out_owner = owned.release();
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("blocks by height facts: exception: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("blocks by height facts: unknown exception");
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
  // Cleared before anything can return. An owner slot is the one out-param
  // whose stale value is dangerous rather than merely wrong: a caller reusing
  // the variable across calls would be left holding — and freeing — the
  // pointer from the previous one. See `shekyl_rpc_block_at`.
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->rpc || !out || !out_len || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
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

int shekyl_rpc_block_at(core_rpc_handle* h, const uint8_t* block_hash,
  uint64_t height, uint8_t fill_pow_hash,
  shekyl_rpc_block_header_facts* out_header,
  shekyl_rpc_block_payload* out_payload, void** out_owner)
{
  // The header promises a null owner on every outcome but a found success,
  // and this is the earliest point that promise can be kept: a null handle
  // returns below, and a caller that reuses the slot across calls would
  // otherwise see the previous call's pointer and free it a second time.
  // The other out-params are left alone — a stale struct after a non-OK
  // return is the ordinary C contract and frees nothing.
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->rpc || !out_header || !out_payload || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  crypto::hash id;
  if (block_hash)
    std::memcpy(id.data, block_hash, sizeof(id.data));
  return daemon_rpc_facts::block_at(h->rpc->get_core().get_blockchain_storage(),
    block_hash ? &id : nullptr, height, fill_pow_hash != 0, out_header, out_payload,
    out_owner);
}

int shekyl_rpc_tx_output_indices(core_rpc_handle* h, const uint8_t* txid,
  const uint64_t** out, size_t* out_len, uint8_t* out_found, void** out_owner)
{
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->rpc || !txid || !out || !out_len || !out_found || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  crypto::hash id;
  std::memcpy(id.data, txid, sizeof(id.data));
  return daemon_rpc_facts::tx_output_indices(
    h->rpc->get_core().get_blockchain_storage(), id, out, out_len, out_found, out_owner);
}

void shekyl_rpc_tx_output_indices_free(void* owner)
{
  delete static_cast<std::vector<uint64_t>*>(owner);
}

int shekyl_rpc_blocks_by_height(core_rpc_handle* h, const uint64_t* heights,
  size_t heights_len, const shekyl_rpc_block_entry** out, size_t* out_len,
  uint64_t* out_failed_height, uint8_t* out_ok, void** out_owner)
{
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->rpc || !out || !out_len || !out_failed_height || !out_ok || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  return daemon_rpc_facts::blocks_by_height(h->rpc->get_core().get_blockchain_storage(),
    heights, heights_len,
    out, out_len, out_failed_height, out_ok, out_owner);
}

int shekyl_rpc_transactions(core_rpc_handle* h, const uint8_t* txids, size_t txids_len,
  uint8_t include_sensitive, const shekyl_rpc_tx_entry** out, size_t* out_len,
  uint64_t* out_chain_height, void** out_owner)
{
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->rpc)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  cryptonote::core& core = h->rpc->get_core();
  return daemon_rpc_facts::transactions(core.get_blockchain_storage(),
    core.get_pool(), txids, txids_len, include_sensitive, out, out_len,
    out_chain_height, out_owner);
}

void shekyl_rpc_transactions_free(void* owner)
{
  delete static_cast<daemon_rpc_facts::transactions_owner*>(owner);
}

int shekyl_rpc_tx_to_json(const uint8_t* blob, size_t blob_len, uint8_t pruned,
  const char** out, size_t* out_len, void** out_owner)
{
  return daemon_rpc_facts::tx_to_json(blob, blob_len, pruned, out, out_len, out_owner);
}

void shekyl_rpc_tx_json_free(void* owner)
{
  delete static_cast<std::string*>(owner);
}

int shekyl_rpc_key_images_spent(core_rpc_handle* h, const uint8_t* key_images,
  size_t count, uint8_t* out_status)
{
  if (!h || !h->rpc)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  cryptonote::core& core = h->rpc->get_core();
  return daemon_rpc_facts::key_images_spent(core.get_blockchain_storage(),
    core.get_pool(), key_images, count, out_status);
}

void shekyl_rpc_blocks_by_height_free(void* owner)
{
  delete static_cast<daemon_rpc_facts::blocks_owner*>(owner);
}

void shekyl_rpc_block_free(void* owner)
{
  delete static_cast<daemon_rpc_facts::block_payload_owner*>(owner);
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
