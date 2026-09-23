// Copyright (c) 2026, The Shekyl Project
// Copyright (c) 2014-2022, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <array>
#include <memory>
#include <random>
#include <fstream>

#include "include_base_utils.h"

#include "console_handler.h"

#include "p2p/net_node.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/miner.h"

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/blockchain.h"
#include "blockchain_db/testdb.h"

#include "chaingen.h"
#include "device/device.hpp"

extern "C" {
#include "crypto/crypto-ops.h"
}
#include "fcmp/ct_ops.h"
#include "fcmp/ct_semantics.h"
#include "memwipe.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_core/tx_pqc_verify.h"
using namespace std;

using namespace epee;
using namespace crypto;
using namespace cryptonote;

namespace
{
  /**
   * Dummy TestDB to store height -> (block, hash) information
   * for the use only in the test_generator::fill_nonce() function,
   * which requires blockchain object to correctly compute PoW on HF12+ blocks
   * as the mining function requires it to obtain a valid seedhash.
   */
  class TestDB: public cryptonote::BaseTestDB
  {
  private:
    struct block_t
    {
      cryptonote::block bl;
      crypto::hash hash;
    };

  public:
    TestDB() { m_open = true; }

    virtual void add_block( const cryptonote::block& blk
        , size_t block_weight
        , uint64_t long_term_block_weight
        , const cryptonote::difficulty_type& cumulative_difficulty
        , const uint64_t& coins_generated
        , uint64_t num_rct_outs
        , const crypto::hash& blk_hash
    ) override
    {
      blocks.push_back({blk, blk_hash});
    }

    virtual uint64_t height() const override { return blocks.empty() ? 0 : blocks.size() - 1; }

    // Required for randomx
    virtual crypto::hash get_block_hash_from_height(const uint64_t &height) const override
    {
      if (height < blocks.size())
      {
        MDEBUG("Get hash for block height: " << height << " hash: " << blocks[height].hash);
        return blocks[height].hash;
      }

      MDEBUG("Get hash for block height: " << height << " zero-hash");
      crypto::hash hash = crypto::null_hash;
      *(uint64_t*)&hash = height;
      return hash;
    }

    virtual crypto::hash top_block_hash(uint64_t *block_height = NULL) const override
    {
      const uint64_t h = height();
      if (block_height != nullptr)
      {
        *block_height = h;
      }

      return get_block_hash_from_height(h);
    }

    virtual cryptonote::block get_top_block() const override
    {
      if (blocks.empty())
      {
        cryptonote::block b;
        return b;
      }

      return blocks[blocks.size()-1].bl;
    }

    virtual void pop_block(cryptonote::block &blk, std::vector<cryptonote::transaction> &txs) override { if (!blocks.empty()) blocks.pop_back(); }
    virtual void set_hard_fork_version(uint64_t height, uint8_t version) override { if (height >= hf.size()) hf.resize(height + 1); hf[height] = version; }
    virtual uint8_t get_hard_fork_version(uint64_t height) const override { if (height >= hf.size()) return 255; return hf[height]; }

    virtual void grow_curve_tree(const std::vector<uint8_t>&, uint64_t) override {}
    virtual void trim_curve_tree(uint64_t) override {}
    virtual uint8_t get_curve_tree_depth() const override { return 0; }
    virtual uint64_t get_curve_tree_leaf_count() const override { return 0; }
    virtual bool get_curve_tree_leaf_by_tree_position(uint64_t, uint8_t*) const override { return false; }
    virtual bool get_curve_tree_leaf_by_output_index(uint64_t, uint8_t*) const override { return false; }

    virtual void store_curve_tree_root_at_height(uint64_t, const std::array<uint8_t, 32>&) override {}
    virtual void remove_curve_tree_root_at_height(uint64_t) override {}
    virtual void store_archival_attestation_witness_at_height(uint64_t, const cryptonote::blobdata&) override {}
    virtual cryptonote::blobdata get_archival_attestation_witness_at_height(uint64_t) const override { return {}; }
    virtual void remove_archival_attestation_witness_at_height(uint64_t) override {}
    virtual void store_archival_alt_attestation_witness(const crypto::hash&, const cryptonote::blobdata&) override {}
    virtual cryptonote::blobdata get_archival_alt_attestation_witness(const crypto::hash&) const override { return {}; }
    virtual void remove_archival_alt_attestation_witness(const crypto::hash&) override {}

    virtual void save_curve_tree_checkpoint(uint64_t) override {}
    virtual bool get_curve_tree_checkpoint(uint64_t, std::vector<uint8_t>&) const override { return false; }
    virtual uint64_t get_latest_curve_tree_checkpoint_height() const override { return 0; }
    virtual void prune_curve_tree_intermediate_layers(uint64_t) override {}

  private:
    std::vector<block_t> blocks;
    std::vector<uint8_t> hf;
  };

}

static std::unique_ptr<cryptonote::Blockchain> init_blockchain(const std::vector<test_event_entry> & events, cryptonote::network_type nettype)
{
  std::unique_ptr<cryptonote::Blockchain> bc;
  v_hardforks_t hardforks;
  cryptonote::test_options test_options_tmp{nullptr, 0};
  const cryptonote::test_options * test_options = &test_options_tmp;
  if (!extract_hard_forks(events, hardforks))
  {
    MDEBUG("Extracting hard-forks from blocks");
    extract_hard_forks_from_blocks(events, hardforks);
  }

  hardforks.push_back(std::make_pair((uint8_t)0, (uint64_t)0));  // terminator
  test_options_tmp.hard_forks = hardforks.data();
  test_options = &test_options_tmp;

  cryptonote::tx_memory_pool txpool(*bc);
  bc.reset(new cryptonote::Blockchain(txpool));

  cryptonote::Blockchain *blockchain = bc.get();
  auto bdb = new TestDB();

  for (const test_event_entry &ev : events)
  {
    if (!std::holds_alternative<block>(ev))
    {
      continue;
    }

    const block *blk = &std::get<block>(ev);
    auto blk_hash = get_block_hash(*blk);
    bdb->add_block(*blk, 1, 1, 1, 0, 0, blk_hash);
  }

  bool r = blockchain->init(bdb, nettype, true, test_options, 2);
  CHECK_AND_ASSERT_THROW_MES(r, "could not init blockchain from events");
  return bc;
}

void test_generator::get_block_chain(std::vector<block_info>& blockchain, const crypto::hash& head, size_t n) const
{
  crypto::hash curr = head;
  while (null_hash != curr && blockchain.size() < n)
  {
    auto it = m_blocks_info.find(curr);
    if (m_blocks_info.end() == it)
    {
      throw std::runtime_error("block hash wasn't found");
    }

    blockchain.push_back(it->second);
    curr = it->second.prev_id;
  }

  std::reverse(blockchain.begin(), blockchain.end());
}

void test_generator::get_last_n_block_weights(std::vector<size_t>& block_weights, const crypto::hash& head, size_t n) const
{
  std::vector<block_info> blockchain;
  get_block_chain(blockchain, head, n);
  for (auto& bi : blockchain)
  {
    block_weights.push_back(bi.block_weight);
  }
}

uint64_t test_generator::get_already_generated_coins(const crypto::hash& blk_id) const
{
  auto it = m_blocks_info.find(blk_id);
  if (it == m_blocks_info.end())
    throw std::runtime_error("block hash wasn't found");

  return it->second.already_generated_coins;
}

uint64_t test_generator::get_already_generated_coins(const cryptonote::block& blk) const
{
  crypto::hash blk_hash;
  get_block_hash(blk, blk_hash);
  return get_already_generated_coins(blk_hash);
}

void test_generator::add_block(const cryptonote::block& blk, size_t txs_weight, std::vector<size_t>& block_weights, uint64_t already_generated_coins, uint64_t block_reward, uint8_t hf_version, const std::vector<cryptonote::transaction>& txs)
{
  const size_t block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  const crypto::hash id = get_block_hash(blk);
  m_blocks_info[id] = block_info(blk.prev_id, already_generated_coins + block_reward, block_weight);
  m_block_txs[id] = block_txs{blk.miner_tx, txs};
}

// ---------------------------------------------------------------------------
// Curve-tree replica: the header-root oracle.
//
// A block's header commits to the curve-tree state at the block's own height
// -- after its parent connected, before its own drain (FCMP_PLUS_PLUS.md §5,
// CEN-I12) -- and the daemon checks that at admission on every nettype
// (CEN-B5). The generator builds blocks before any store exists, so it replays
// its own chain through the Rust CurveTreeClient (shekyl_curve_tree_replica_*),
// whose parity with the daemon's store is KAT-pinned. The replica tracks which
// block hashes it holds at which heights; a fork rolls it back to the common
// prefix, a different genesis recreates it.
// ---------------------------------------------------------------------------
struct curve_tree_replica
{
  ShekylCurveTreeReplica* handle = nullptr;
  std::vector<crypto::hash> chain; // ingested block hashes; index == height

  curve_tree_replica() { reset(); }
  ~curve_tree_replica() { shekyl_curve_tree_replica_free(handle); }
  curve_tree_replica(const curve_tree_replica&) = delete;
  curve_tree_replica& operator=(const curve_tree_replica&) = delete;

  void reset()
  {
    shekyl_curve_tree_replica_free(handle);
    handle = shekyl_curve_tree_replica_new();
    chain.clear();
    CHECK_AND_ASSERT_THROW_MES(handle != nullptr, "curve-tree replica: cannot create the Rust client");
  }
};

namespace
{
  // One transaction's leaf inputs, owned here so the FFI view can point into it.
  struct replica_tx_buffers
  {
    bool is_miner = false;
    bool has_blob = false;
    std::vector<uint8_t> blob;
    std::vector<ShekylCurveTreeReplicaOutput> outputs;
  };

  // Mirrors the daemon's collect_outputs() inputs (blockchain_db.cpp): the
  // 0x07 leaf-entry blob as parsed there, one entry per vout with its outPk
  // commitment when present and its target kind. Maturity, entry slicing and
  // leaf eligibility are the client's to decide, not repeated here.
  replica_tx_buffers to_replica_tx(const cryptonote::transaction& tx, bool is_miner)
  {
    replica_tx_buffers out;
    out.is_miner = is_miner;
    // The replica mirrors the daemon's read: the 0x07 blob as the codec
    // finds it (first 0x07 field), absent when the extra carries none or
    // does not parse -- the replica is an oracle for the *tree*, and what
    // the daemon does with a bad extra is the shape rule's business.
    ShekylOwnedBuffer leaf;
    if (shekyl_tx_extra_field(tx.extra.empty() ? nullptr : tx.extra.data(), tx.extra.size(),
          SHEKYL_TX_EXTRA_TAG_PQC_LEAF_ENTRIES, 0, &leaf.buf) == SHEKYL_TX_EXTRA_OK)
    {
      out.has_blob = true;
      out.blob.assign(leaf.data(), leaf.data() + leaf.size());
    }
    out.outputs.reserve(tx.vout.size());
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      ShekylCurveTreeReplicaOutput o{};
      const auto& target = tx.vout[i].target;
      if (std::holds_alternative<cryptonote::txout_to_tagged_key>(target))
      {
        o.target_kind = 0;
        memcpy(o.output_key, &std::get<cryptonote::txout_to_tagged_key>(target).key, 32);
      }
      else if (std::holds_alternative<cryptonote::txout_to_key>(target))
      {
        o.target_kind = 1;
        memcpy(o.output_key, &std::get<cryptonote::txout_to_key>(target).key, 32);
      }
      else
        o.target_kind = 2;
      if (i < tx.ct_signatures.outPk.size())
      {
        o.has_commitment = 1;
        memcpy(o.commitment, tx.ct_signatures.outPk[i].mask.bytes, 32);
      }
      out.outputs.push_back(o);
    }
    return out;
  }

  void replica_ingest(curve_tree_replica& replica, uint64_t height, const crypto::hash& id, const test_generator::block_txs& bt)
  {
    std::vector<replica_tx_buffers> buffers;
    buffers.reserve(1 + bt.txs.size());
    buffers.push_back(to_replica_tx(bt.miner_tx, true));
    for (const auto& tx : bt.txs)
      buffers.push_back(to_replica_tx(tx, false));
    std::vector<ShekylCurveTreeReplicaTx> views;
    views.reserve(buffers.size());
    for (const auto& b : buffers)
    {
      ShekylCurveTreeReplicaTx v{};
      v.is_miner = b.is_miner ? 1 : 0;
      v.has_leaf_entry_blob = b.has_blob ? 1 : 0;
      v.leaf_entry_blob = b.blob.data();
      v.leaf_entry_blob_len = b.blob.size();
      v.outputs = b.outputs.data();
      v.n_outputs = b.outputs.size();
      views.push_back(v);
    }
    CHECK_AND_ASSERT_THROW_MES(shekyl_curve_tree_replica_ingest_block(replica.handle, height, views.data(), views.size()),
      "curve-tree replica: ingest of block " << id << " at height " << height << " failed (see the replica's log line)");
    replica.chain.push_back(id);
  }
}

void test_generator::fill_curve_tree_root(cryptonote::block& blk)
{
  // Ancestors of blk, genesis first. Every one was recorded by add_block with
  // its transaction bodies.
  std::vector<crypto::hash> ancestors;
  for (crypto::hash cur = blk.prev_id; cur != null_hash; )
  {
    auto it = m_blocks_info.find(cur);
    if (it == m_blocks_info.end())
    {
      // A parent the generator never built (gen_block_invalid_prev_id's
      // deliberate bad prev_id): the daemon rejects the block on prev_id
      // before the root is read, so the header only needs to be well-formed.
      MDEBUG("fill_curve_tree_root: prev_id " << cur << " is not a generated block; header gets the empty-tree root");
      shekyl_curve_tree_selene_hash_init(reinterpret_cast<uint8_t*>(&blk.curve_tree_root));
      return;
    }
    ancestors.push_back(cur);
    cur = it->second.prev_id;
  }
  std::reverse(ancestors.begin(), ancestors.end());

  if (!m_replica)
    m_replica = std::make_shared<curve_tree_replica>();
  curve_tree_replica& replica = *m_replica;

  // Reconcile the replica with this block's ancestry: keep the common prefix,
  // roll back the rest, then ingest what is missing.
  size_t common = 0;
  while (common < ancestors.size() && common < replica.chain.size() && ancestors[common] == replica.chain[common])
    ++common;
  if (common < replica.chain.size())
  {
    if (common == 0)
      replica.reset();
    else
    {
      CHECK_AND_ASSERT_THROW_MES(shekyl_curve_tree_replica_rollback_to_fork(replica.handle, common - 1),
        "curve-tree replica: rollback to height " << (common - 1) << " failed");
      // A rollback onto a prefix that produced no leaf entry reports "nothing
      // ingested" (the client's resume rule); replay from genesis then.
      uint64_t tip = 0;
      if (shekyl_curve_tree_replica_tip_height(replica.handle, &tip) && tip == common - 1)
        replica.chain.resize(common);
      else
        replica.reset();
    }
    common = replica.chain.size();
  }
  for (size_t h = common; h < ancestors.size(); ++h)
  {
    auto bt = m_block_txs.find(ancestors[h]);
    CHECK_AND_ASSERT_THROW_MES(bt != m_block_txs.end(), "curve-tree replica: no recorded transactions for block " << ancestors[h]);
    replica_ingest(replica, h, ancestors[h], bt->second);
  }

  std::array<uint8_t, 32> root{};
  CHECK_AND_ASSERT_THROW_MES(shekyl_curve_tree_replica_next_block_root(replica.handle, root.data()),
    "curve-tree replica: next_block_root failed after " << ancestors.size() << " ancestors");
  memcpy(&blk.curve_tree_root, root.data(), root.size());
}

std::vector<cryptonote::transaction> test_generator::find_txs_in_events(const std::vector<crypto::hash>& tx_hashes) const
{
  std::vector<cryptonote::transaction> found;
  if (tx_hashes.empty())
    return found;
  std::unordered_map<crypto::hash, const cryptonote::transaction*> by_hash;
  if (m_events != nullptr)
  {
    for (const auto& ev : *m_events)
    {
      if (const auto* tx = std::get_if<cryptonote::transaction>(&ev))
        by_hash[get_transaction_hash(*tx)] = tx;
      else if (const auto* txs = std::get_if<std::vector<cryptonote::transaction>>(&ev))
        for (const auto& tx : *txs)
          by_hash[get_transaction_hash(tx)] = &tx;
    }
  }
  for (const auto& h : tx_hashes)
  {
    auto it = by_hash.find(h);
    if (it != by_hash.end())
      found.push_back(*it->second);
    else
      MWARNING("construct_block_manually: no body among the events for tx " << h
        << "; the curve-tree replica omits its outputs, so a header built ten or more blocks later may mismatch");
  }
  return found;
}

bool test_generator::construct_block(cryptonote::block& blk, uint64_t height, const crypto::hash& prev_id,
                                     const cryptonote::account_base& miner_acc, uint64_t timestamp, uint64_t already_generated_coins,
                                     std::vector<size_t>& block_weights, const std::list<cryptonote::transaction>& tx_list,
                                     const std::optional<uint8_t>& hf_ver)
{
  blk.major_version = hf_ver ? *hf_ver : CURRENT_BLOCK_MAJOR_VERSION;
  blk.minor_version = hf_ver ? *hf_ver : CURRENT_BLOCK_MINOR_VERSION;
  blk.timestamp = timestamp;
  blk.prev_id = prev_id;
  fill_curve_tree_root(blk);
  blk.attestation_root = cryptonote::empty_attestation_root();

  blk.tx_hashes.reserve(tx_list.size());
  for (const transaction &tx : tx_list)
  {
    crypto::hash tx_hash;
    get_transaction_hash(tx, tx_hash);
    blk.tx_hashes.push_back(tx_hash);
  }

  uint64_t total_fee = 0;
  size_t txs_weight = 0;
  for (auto& tx : tx_list)
  {
    uint64_t fee = 0;
    bool r = get_tx_fee(tx, fee);
    CHECK_AND_ASSERT_MES(r, false, "wrong transaction passed to construct_block");
    total_fee += fee;
    txs_weight += get_transaction_weight(tx);
  }

  blk.miner_tx = AUTO_VAL_INIT(blk.miner_tx);
  size_t target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  while (true)
  {
    // frozen_segment_count = 0: the generator builds blocks offline and tracks
    // no curve tree, and the shipped genesis-neutral parameterization makes
    // the burn split independent of n (asymptote == floor, bit-identity
    // pinned in shekyl-ffi). A test that configures a non-neutral asymptote
    // must thread the real parent leaf-derived n here or its coinbase will be
    // refused at connect — which is the loud failure we want.
    if (!construct_miner_tx(height, misc_utils::median(block_weights), already_generated_coins, target_block_weight, total_fee, /*frozen_segment_count=*/0, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), /*max_outs=*/1, hf_ver ? *hf_ver : 1,
        /*tx_volume=*/{}, shekyl::supply_facts{already_generated_coins, /*total_burned: the generator tracks no burn fold; see the frozen_segment_count note*/0}, /*genesis_ng_height=*/0))
      return false;

    size_t actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
    if (target_block_weight < actual_block_weight)
    {
      target_block_weight = actual_block_weight;
    }
    else if (actual_block_weight < target_block_weight)
    {
      size_t delta = target_block_weight - actual_block_weight;
      blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
      actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
      if (actual_block_weight == target_block_weight)
      {
        break;
      }
      else
      {
        CHECK_AND_ASSERT_MES(target_block_weight < actual_block_weight, false, "Unexpected block size");
        delta = actual_block_weight - target_block_weight;
        blk.miner_tx.extra.resize(blk.miner_tx.extra.size() - delta);
        actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
        if (actual_block_weight == target_block_weight)
        {
          break;
        }
        else
        {
          CHECK_AND_ASSERT_MES(actual_block_weight < target_block_weight, false, "Unexpected block size");
          blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
          target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
        }
      }
    }
    else
    {
      break;
    }
  }

  //blk.tree_root_hash = get_tx_tree_hash(blk);

  fill_nonce(blk, get_test_difficulty(hf_ver), height);
  // Mirror Blockchain::validate_miner_transaction's base_reward out-param so the
  // harness's already_generated_coins stays byte-identical to the daemon's LMDB
  // accumulation. For h>=1 (fix alpha, :1609) that out-param is the FULL emission
  // subsidy (miner + staker legs); the coinbase carries only the miner leg, so
  // summing get_outs_money_amount would undercount and desync later blocks. The
  // genesis (h==0) takes the daemon's height-0 branch (:1565), which accumulates
  // money_in_use (the coinbase outputs), not the subsidy formula.
  uint64_t accum_reward = 0;
  if (height == 0)
  {
    accum_reward = get_outs_money_amount(blk.miner_tx);
  }
  else
  {
    get_block_reward(misc_utils::median(block_weights), target_block_weight,
                     already_generated_coins, accum_reward,
                     hf_ver ? *hf_ver : 1, /*tx_volume=*/{});
  }
  add_block(blk, txs_weight, block_weights, already_generated_coins, accum_reward, hf_ver ? *hf_ver : 1,
    std::vector<cryptonote::transaction>(tx_list.begin(), tx_list.end()));

  return true;
}

bool test_generator::construct_block(cryptonote::block& blk, const cryptonote::account_base& miner_acc, uint64_t timestamp)
{
  std::vector<size_t> block_weights;
  std::list<cryptonote::transaction> tx_list;
  return construct_block(blk, 0, null_hash, miner_acc, timestamp, 0, block_weights, tx_list);
}

bool test_generator::construct_block(cryptonote::block& blk, const cryptonote::block& blk_prev,
                                     const cryptonote::account_base& miner_acc,
                                     const std::list<cryptonote::transaction>& tx_list/* = std::list<cryptonote::transaction>()*/,
                                     const std::optional<uint8_t>& hf_ver)
{
  uint64_t height = std::get<txin_gen>(blk_prev.miner_tx.vin.front()).height + 1;
  crypto::hash prev_id = get_block_hash(blk_prev);
  // Keep difficulty unchanged
  uint64_t timestamp = blk_prev.timestamp + current_difficulty_window(hf_ver);
  uint64_t already_generated_coins = get_already_generated_coins(prev_id);
  std::vector<size_t> block_weights;
  get_last_n_block_weights(block_weights, prev_id, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

  return construct_block(blk, height, prev_id, miner_acc, timestamp, already_generated_coins, block_weights, tx_list, hf_ver);
}

bool test_generator::construct_block_manually(block& blk, const block& prev_block, const account_base& miner_acc,
                                              int actual_params/* = bf_none*/, uint8_t major_ver/* = 0*/,
                                              uint8_t minor_ver/* = 0*/, uint64_t timestamp/* = 0*/,
                                              const crypto::hash& prev_id/* = crypto::hash()*/, const difficulty_type& diffic/* = 1*/,
                                              const transaction& miner_tx/* = transaction()*/,
                                              const std::vector<crypto::hash>& tx_hashes/* = std::vector<crypto::hash>()*/,
                                              size_t txs_weight/* = 0*/, size_t max_outs/* = 0*/, uint8_t hf_version/* = 1*/,
                                              uint64_t fees/* = 0*/)
{
  blk.major_version = actual_params & bf_major_ver ? major_ver : CURRENT_BLOCK_MAJOR_VERSION;
  blk.minor_version = actual_params & bf_minor_ver ? minor_ver : CURRENT_BLOCK_MINOR_VERSION;
  blk.timestamp     = actual_params & bf_timestamp ? timestamp : prev_block.timestamp + SHEKYL_DAA_TARGET_SECONDS; // Keep difficulty unchanged
  blk.prev_id       = actual_params & bf_prev_id   ? prev_id   : get_block_hash(prev_block);
  fill_curve_tree_root(blk);
  blk.attestation_root = cryptonote::empty_attestation_root();
  blk.tx_hashes     = actual_params & bf_tx_hashes ? tx_hashes : std::vector<crypto::hash>();
  // F-H harness conformance: the consensus coinbase output-count cap is 1, and
  // the harness conforms to consensus rather than the cap inflating for the
  // harness (FOLLOWUPS F-H principle). bf_max_outs still lets a test state a
  // deliberate violation.
  max_outs          = actual_params & bf_max_outs ? max_outs : 1;
  hf_version        = actual_params & bf_hf_version ? hf_version : 1;
  fees              = actual_params & bf_tx_fees ? fees : 0;

  size_t height = get_block_height(prev_block) + 1;
  uint64_t already_generated_coins = get_already_generated_coins(prev_block);
  std::vector<size_t> block_weights;
  get_last_n_block_weights(block_weights, get_block_hash(prev_block), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  if (actual_params & bf_miner_tx)
  {
    blk.miner_tx = miner_tx;
  }
  else
  {
    size_t current_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
    // TODO: This will work, until size of constructed block is less then CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE
    if (!construct_miner_tx(height, misc_utils::median(block_weights), already_generated_coins, current_block_weight, fees, /*frozen_segment_count=*/0, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), max_outs, hf_version,
        /*tx_volume=*/{}, shekyl::supply_facts{already_generated_coins, /*total_burned: the generator tracks no burn fold; see the frozen_segment_count note*/0}, /*genesis_ng_height=*/0))
      return false;
  }

  //blk.tree_root_hash = get_tx_tree_hash(blk);

  difficulty_type a_diffic = actual_params & bf_diffic ? diffic : get_test_difficulty(hf_version);
  fill_nonce(blk, a_diffic, height);

  // construct_block_manually always builds h>=1 (prev_block+1); accumulate the
  // full emission subsidy matching fix alpha (:1609) — coinbase only carries
  // the miner leg so get_outs_money_amount would undercount.
  uint64_t full_base_reward = 0;
  get_block_reward(misc_utils::median(block_weights),
                   txs_weight + get_transaction_weight(blk.miner_tx),
                   already_generated_coins, full_base_reward, hf_version,
                   /*tx_volume=*/{});
  add_block(blk, txs_weight, block_weights, already_generated_coins, full_base_reward, hf_version,
    find_txs_in_events(blk.tx_hashes));

  return true;
}

bool test_generator::construct_block_manually_tx(cryptonote::block& blk, const cryptonote::block& prev_block,
                                                 const cryptonote::account_base& miner_acc,
                                                 const std::vector<crypto::hash>& tx_hashes, size_t txs_weight)
{
  return construct_block_manually(blk, prev_block, miner_acc, bf_tx_hashes, 0, 0, 0, crypto::hash(), 0, transaction(), tx_hashes, txs_weight);
}

void test_generator::fill_nonce(cryptonote::block& blk, const difficulty_type& diffic, uint64_t height)
{
  const cryptonote::Blockchain *blockchain = nullptr;
  std::unique_ptr<cryptonote::Blockchain> bc;

  if (diffic > 1)
  {
    if (m_events == nullptr)
    {
      MDEBUG("events not set, RandomX PoW can fail due to zero seed hash");
    }
    else
    {
      bc = init_blockchain(*m_events, m_nettype);
      blockchain = bc.get();
    }
  }

  blk.nonce = 0;
  while (!miner::find_nonce_for_given_block([blockchain](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, crypto::hash &hash){
    return cryptonote::get_block_longhash(blockchain, b, hash, height, seed_hash);
  }, blk, diffic, height, NULL)) {
    blk.timestamp++;
  }
}

// The coinbase extra through the one writer (shekyl_coinbase_extra), zero
// nonce: [0x01 pubkey, 0x02 nonce(8), 0x06 KEM, 0x07 leaf entries] for
// tx.vout.size() outputs, judged by the coinbase grammar before it is handed
// back. Every block_validation coinbase is built here, so a test that expects
// a block to be refused is refused for the reason it is about, never for a
// scaffold that fell out of the grammar.
static bool write_coinbase_extra(transaction& tx, const crypto::public_key& tx_pub,
                                 const std::vector<uint8_t>& kem_blob, const std::vector<uint8_t>& leaf_blob)
{
  const uint8_t nonce[SHEKYL_COINBASE_NONCE_BYTES] = {0};
  char msg[SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP] = {0};
  ShekylOwnedBuffer extra;
  const int32_t rc = shekyl_coinbase_extra(
    reinterpret_cast<const uint8_t*>(&tx_pub), nonce,
    kem_blob.empty() ? nullptr : kem_blob.data(), kem_blob.size(),
    leaf_blob.empty() ? nullptr : leaf_blob.data(), leaf_blob.size(),
    tx.vout.size(), &extra.buf, msg, sizeof(msg));
  CHECK_AND_ASSERT_MES(rc == SHEKYL_TX_EXTRA_OK, false,
    "coinbase extra refused by the grammar (code " << rc << "): " << msg);
  tx.extra.assign(extra.data(), extra.data() + extra.size());
  return true;
}

bool construct_miner_tx_manually(size_t height, uint64_t already_generated_coins,
                                 const account_public_address& miner_address, transaction& tx, uint64_t fee,
                                 uint8_t hf_version/* = 1*/, keypair* p_txkey/* = 0*/,
                                 size_t median_block_weight/* = 0*/, size_t txs_weight/* = 0*/)
{
  CHECK_AND_ASSERT_MES(miner_address.m_pqc_public_key.size() == SHEKYL_PQC_PUBLIC_KEY_BYTES, false,
    "construct_miner_tx_manually: miner PQC public key size "
    << miner_address.m_pqc_public_key.size() << " != " << SHEKYL_PQC_PUBLIC_KEY_BYTES);

  keypair txkey = keypair::generate(hw::get_device("default"));
  if (p_txkey)
    *p_txkey = txkey;

  const uint8_t* pk_x25519 = miner_address.m_pqc_public_key.data();
  const uint8_t* pk_ml_kem = miner_address.m_pqc_public_key.data() + SHEKYL_X25519_PK_BYTES;
  const size_t pk_ml_kem_len = miner_address.m_pqc_public_key.size() - SHEKYL_X25519_PK_BYTES;

  // The extra is built once, at the end, by the one coinbase writer
  // (shekyl_coinbase_extra, zero nonce): this scaffold produces what the
  // coinbase grammar admits, so a block_validation test that expects
  // acceptance gets it, and one that expects rejection gets it for the
  // reason it is about. (The former weight-padding arm -- 0x00 bytes appended
  // to hit a target block weight -- built a coinbase the grammar forbids;
  // every caller passed txs_weight = 0 and never reached it.)
  CHECK_AND_ASSERT_MES(txs_weight == 0, false,
    "construct_miner_tx_manually: weight padding is not a coinbase the grammar admits");
  {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();
    tx.ct_signatures = {};

    txin_gen in;
    in.height = height;

    uint64_t block_reward;
    if (!get_block_reward(median_block_weight, /*current_block_weight=*/0, already_generated_coins, block_reward, hf_version, /*tx_volume=*/{}))
      return false;

    shekyl::EmissionSplit em_split = shekyl::compute_emission_split(block_reward, height, 0);
    block_reward = em_split.miner_emission;

    shekyl::BurnResult burn = shekyl::compute_fee_burn(fee, shekyl::tx_volume_window{}, shekyl::supply_facts{}, /*frozen_segment_count=*/0);
    block_reward += burn.miner_fee_income;

    std::vector<uint8_t> kem_blob;
    std::vector<uint8_t> leaf_blob;

    tx.ct_signatures.outPk.resize(1);
    tx.ct_signatures.enc_amounts.resize(1);
    tx.ct_signatures.enc_labels.resize(1);

    ShekylOutputData od = shekyl_construct_output(
      reinterpret_cast<const uint8_t*>(&txkey.sec),
      pk_x25519, pk_ml_kem, pk_ml_kem_len,
      reinterpret_cast<const uint8_t*>(&miner_address.m_spend_public_key),
      block_reward, 0);
    CHECK_AND_ASSERT_MES(od.success, false, "shekyl_construct_output failed for manual coinbase");

    crypto::public_key out_key;
    memcpy(out_key.data, od.output_key, 32);
    crypto::view_tag vt;
    vt.data = od.view_tag_prefilter;

    tx_out out;
    cryptonote::set_tx_out(block_reward, out_key, true, vt, out);
    tx.vout.push_back(out);

    memcpy(tx.ct_signatures.outPk[0].mask.bytes, od.commitment, 32);
    memcpy(tx.ct_signatures.enc_amounts[0].data(), od.enc_amount, 8);
    tx.ct_signatures.enc_amounts[0][8] = od.amount_tag;
    memcpy(tx.ct_signatures.enc_labels[0].data(), od.enc_label, 8);
    tx.ct_signatures.enc_labels[0][8] = od.label_tag;

    kem_blob.insert(kem_blob.end(), od.kem_ciphertext_x25519, od.kem_ciphertext_x25519 + 32);
    if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
      kem_blob.insert(kem_blob.end(), od.kem_ciphertext_ml_kem.ptr,
        od.kem_ciphertext_ml_kem.ptr + od.kem_ciphertext_ml_kem.len);
    leaf_blob.insert(leaf_blob.end(), od.pqc_leaf, od.pqc_leaf + SHEKYL_PQC_LEAF_ENTRY_BYTES);

    ShekylOutputData tmp = od;
    shekyl_output_data_free(&tmp);

    if (!write_coinbase_extra(tx, txkey.pub, kem_blob, leaf_blob))
      return false;

    tx.version = 3;
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);
    tx.invalidate_hashes();
  }

  return true;
}

bool append_v3_output_to_miner_tx(transaction& tx, const crypto::secret_key& txkey_sec,
                                  const account_public_address& addr, uint64_t amount)
{
  CHECK_AND_ASSERT_MES(tx.version == 3, false, "append_v3_output_to_miner_tx requires a v3 tx");
  CHECK_AND_ASSERT_MES(addr.m_pqc_public_key.size() == SHEKYL_PQC_PUBLIC_KEY_BYTES, false,
    "append_v3_output: recipient PQC public key size "
    << addr.m_pqc_public_key.size() << " != " << SHEKYL_PQC_PUBLIC_KEY_BYTES);

  const uint8_t* pk_x25519 = addr.m_pqc_public_key.data();
  const uint8_t* pk_ml_kem = addr.m_pqc_public_key.data() + SHEKYL_X25519_PK_BYTES;
  const size_t pk_ml_kem_len = addr.m_pqc_public_key.size() - SHEKYL_X25519_PK_BYTES;
  const size_t out_idx = tx.vout.size();

  ShekylOutputData od = shekyl_construct_output(
    reinterpret_cast<const uint8_t*>(&txkey_sec),
    pk_x25519, pk_ml_kem, pk_ml_kem_len,
    reinterpret_cast<const uint8_t*>(&addr.m_spend_public_key),
    amount, static_cast<uint64_t>(out_idx));
  CHECK_AND_ASSERT_MES(od.success, false, "shekyl_construct_output failed for appended output");

  crypto::public_key out_key;
  memcpy(out_key.data, od.output_key, 32);
  crypto::view_tag vt;
  vt.data = od.view_tag_prefilter;

  tx_out out;
  cryptonote::set_tx_out(amount, out_key, true, vt, out);
  tx.vout.push_back(out);

  ct::ctkey pk_entry;
  memcpy(pk_entry.mask.bytes, od.commitment, 32);
  tx.ct_signatures.outPk.push_back(pk_entry);

  std::array<uint8_t, 9> enc_amt{};
  memcpy(enc_amt.data(), od.enc_amount, 8);
  enc_amt[8] = od.amount_tag;
  tx.ct_signatures.enc_amounts.push_back(enc_amt);

  std::array<uint8_t, 9> enc_label{};
  memcpy(enc_label.data(), od.enc_label, 8);
  enc_label[8] = od.label_tag;
  tx.ct_signatures.enc_labels.push_back(enc_label);

  // Read the coinbase's pubkey, 0x06 and 0x07 back through the codec, extend
  // the two blobs by this output, and rebuild the extra with the one writer.
  crypto::public_key tx_pub;
  CHECK_AND_ASSERT_MES(shekyl_tx_extra_tx_pubkey(tx.extra.data(), tx.extra.size(),
      reinterpret_cast<uint8_t*>(&tx_pub)) == SHEKYL_TX_EXTRA_OK, false,
    "append_v3_output: coinbase extra carries no 0x01 pubkey");
  ShekylOwnedBuffer kem_buf, leaf_buf;
  // A leafless coinbase (no outputs yet) has neither field: ABSENT is the
  // empty blob here, MALFORMED is a real failure.
  const int32_t kem_rc = shekyl_tx_extra_field(tx.extra.data(), tx.extra.size(),
    SHEKYL_TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT, 0, &kem_buf.buf);
  CHECK_AND_ASSERT_MES(kem_rc == SHEKYL_TX_EXTRA_OK || kem_rc == SHEKYL_TX_EXTRA_ABSENT, false,
    "append_v3_output: coinbase extra 0x06 read failed with code " << kem_rc);
  const int32_t leaf_rc = shekyl_tx_extra_field(tx.extra.data(), tx.extra.size(),
    SHEKYL_TX_EXTRA_TAG_PQC_LEAF_ENTRIES, 0, &leaf_buf.buf);
  CHECK_AND_ASSERT_MES(leaf_rc == SHEKYL_TX_EXTRA_OK || leaf_rc == SHEKYL_TX_EXTRA_ABSENT, false,
    "append_v3_output: coinbase extra 0x07 read failed with code " << leaf_rc);

  std::vector<uint8_t> kem_blob(kem_buf.data(), kem_buf.data() + kem_buf.size());
  kem_blob.insert(kem_blob.end(), od.kem_ciphertext_x25519, od.kem_ciphertext_x25519 + 32);
  if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
    kem_blob.insert(kem_blob.end(), od.kem_ciphertext_ml_kem.ptr,
      od.kem_ciphertext_ml_kem.ptr + od.kem_ciphertext_ml_kem.len);
  std::vector<uint8_t> leaf_blob(leaf_buf.data(), leaf_buf.data() + leaf_buf.size());
  leaf_blob.insert(leaf_blob.end(), od.pqc_leaf, od.pqc_leaf + SHEKYL_PQC_LEAF_ENTRY_BYTES);

  ShekylOutputData tmp = od;
  shekyl_output_data_free(&tmp);

  if (!write_coinbase_extra(tx, tx_pub, kem_blob, leaf_blob))
    return false;

  tx.invalidate_hashes();
  return true;
}

bool extract_hard_forks(const std::vector<test_event_entry>& events, v_hardforks_t& hard_forks)
{
  for(auto & ev : events)
  {
    if (std::holds_alternative<event_replay_settings>(ev))
    {
      const auto & rep_settings = std::get<event_replay_settings>(ev);
      if (rep_settings.hard_forks)
      {
        const auto & hf = *rep_settings.hard_forks;
        std::copy(hf.begin(), hf.end(), std::back_inserter(hard_forks));
      }
    }
  }

  return !hard_forks.empty();
}

bool extract_hard_forks_from_blocks(const std::vector<test_event_entry>& events, v_hardforks_t& hard_forks)
{
  int hf = -1;
  int64_t height = 0;

  for(auto & ev : events)
  {
    if (!std::holds_alternative<block>(ev))
    {
      continue;
    }

    const block *blk = &std::get<block>(ev);
    if (blk->major_version != hf)
    {
      hf = blk->major_version;
      hard_forks.push_back(std::make_pair(blk->major_version, (uint64_t)height));
    }

    height += 1;
  }

  return !hard_forks.empty();
}

void get_confirmed_txs(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, map_hash2tx_t& confirmed_txs)
{
  std::unordered_set<crypto::hash> confirmed_hashes;
  for (const block& blk : blockchain)
  {
    for (const crypto::hash& tx_hash : blk.tx_hashes)
    {
      confirmed_hashes.insert(tx_hash);
    }
  }

  for (const auto& tx_pair : mtx)
  {
    if (0 != confirmed_hashes.count(tx_pair.first))
    {
      confirmed_txs.insert(tx_pair);
    }
  }
}

bool trim_block_chain(std::vector<cryptonote::block>& blockchain, const crypto::hash& tail){
  size_t cut = 0;
  bool found = true;

  for(size_t i = 0; i < blockchain.size(); ++i){
    crypto::hash chash = get_block_hash(blockchain[i]);
    if (chash == tail){
      cut = i;
      found = true;
      break;
    }
  }

  if (found && cut > 0){
    blockchain.erase(blockchain.begin(), blockchain.begin() + cut);
  }

  return found;
}

bool trim_block_chain(std::vector<const cryptonote::block*>& blockchain, const crypto::hash& tail){
  size_t cut = 0;
  bool found = true;

  for(size_t i = 0; i < blockchain.size(); ++i){
    crypto::hash chash = get_block_hash(*blockchain[i]);
    if (chash == tail){
      cut = i;
      found = true;
      break;
    }
  }

  if (found && cut > 0){
    blockchain.erase(blockchain.begin(), blockchain.begin() + cut);
  }

  return found;
}

uint64_t num_blocks(const std::vector<test_event_entry>& events)
{
  uint64_t res = 0;
  for (const test_event_entry& ev : events)
  {
    if (std::holds_alternative<block>(ev))
    {
      res += 1;
    }
  }

  return res;
}

cryptonote::block get_head_block(const std::vector<test_event_entry>& events)
{
  for(auto it = events.rbegin(); it != events.rend(); ++it)
  {
    auto &ev = *it;
    if (std::holds_alternative<block>(ev))
    {
      return std::get<block>(ev);
    }
  }

  throw std::runtime_error("No block event");
}

bool find_block_chain(const std::vector<test_event_entry>& events, std::vector<cryptonote::block>& blockchain, map_hash2tx_t& mtx, const crypto::hash& head) {
    std::unordered_map<crypto::hash, const block*> block_index;
    for (const test_event_entry& ev : events)
    {
        if (std::holds_alternative<block>(ev))
        {
            const block* blk = &std::get<block>(ev);
            block_index[get_block_hash(*blk)] = blk;
        }
        else if (std::holds_alternative<transaction>(ev))
        {
            const transaction& tx = std::get<transaction>(ev);
            mtx[get_transaction_hash(tx)] = &tx;
        }
    }

    bool b_success = false;
    crypto::hash id = head;
    for (auto it = block_index.find(id); block_index.end() != it; it = block_index.find(id))
    {
        blockchain.push_back(*it->second);
        id = it->second->prev_id;
        if (null_hash == id)
        {
            b_success = true;
            break;
        }
    }
    reverse(blockchain.begin(), blockchain.end());

    return b_success;
}

bool find_block_chain(const std::vector<test_event_entry>& events, std::vector<const cryptonote::block*>& blockchain, map_hash2tx_t& mtx, const crypto::hash& head) {
    std::unordered_map<crypto::hash, const block*> block_index;
    for (const test_event_entry& ev : events)
    {
        if (std::holds_alternative<block>(ev))
        {
            const block* blk = &std::get<block>(ev);
            block_index[get_block_hash(*blk)] = blk;
        }
        else if (std::holds_alternative<transaction>(ev))
        {
            const transaction& tx = std::get<transaction>(ev);
            mtx[get_transaction_hash(tx)] = &tx;
        }
    }

    bool b_success = false;
    crypto::hash id = head;
    for (auto it = block_index.find(id); block_index.end() != it; it = block_index.find(id))
    {
        blockchain.push_back(it->second);
        id = it->second->prev_id;
        if (null_hash == id)
        {
            b_success = true;
            break;
        }
    }
    reverse(blockchain.begin(), blockchain.end());
    return b_success;
}


void test_chain_unit_base::register_callback(const std::string& cb_name, verify_callback cb)
{
  m_callbacks[cb_name] = cb;
}
bool test_chain_unit_base::verify(const std::string& cb_name, cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  auto cb_it = m_callbacks.find(cb_name);
  if(cb_it == m_callbacks.end())
  {
    LOG_ERROR("Failed to find callback " << cb_name);
    return false;
  }
  return cb_it->second(c, ev_index, events);
}

bool test_chain_unit_base::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  return !cryptonote::block_rejected(bvc);
}

bool test_chain_unit_base::check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool /*tx_added*/, size_t /*event_index*/, const cryptonote::transaction& /*tx*/)
{
  return !tvc.m_verifivation_failed;
}

bool test_chain_unit_base::check_tx_verification_context_array(const std::vector<cryptonote::tx_verification_context>& tvcs, size_t /*tx_added*/, size_t /*event_index*/, const std::vector<cryptonote::transaction>& /*txs*/)
{
  for (const cryptonote::tx_verification_context &tvc: tvcs)
    if (tvc.m_verifivation_failed)
      return false;
  return true;
}
