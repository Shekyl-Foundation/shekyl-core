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
#include "fcmp/rctOps.h"
#include "fcmp/rctSigs.h"
#include "memwipe.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_core/tx_pqc_verify.h"
using namespace std;

using namespace epee;
using namespace crypto;
using namespace cryptonote;

static bool get_output_key_from_target(const txout_target_v &target, crypto::public_key &key)
{
  if (std::holds_alternative<txout_to_key>(target))
    key = std::get<txout_to_key>(target).key;
  else if (std::holds_alternative<txout_to_tagged_key>(target))
    key = std::get<txout_to_tagged_key>(target).key;
  else
    return false;
  return true;
}

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
    virtual std::array<uint8_t, 32> get_curve_tree_root() const override { return {}; }
    virtual uint8_t get_curve_tree_depth() const override { return 0; }
    virtual uint64_t get_curve_tree_leaf_count() const override { return 0; }
    virtual bool get_curve_tree_layer_hash(uint8_t, uint64_t, uint8_t*) const override { return false; }
    virtual bool get_curve_tree_leaf_by_tree_position(uint64_t, uint8_t*) const override { return false; }
    virtual bool get_curve_tree_leaf_by_output_index(uint64_t, uint8_t*) const override { return false; }

    virtual void store_curve_tree_root_at_height(uint64_t, const std::array<uint8_t, 32>&) override {}
    virtual std::array<uint8_t, 32> get_curve_tree_root_at_height(uint64_t) const override { return {}; }
    virtual void remove_curve_tree_root_at_height(uint64_t) override {}

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

  bool r = blockchain->init(bdb, nettype, true, test_options, 2, nullptr);
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

void test_generator::add_block(const cryptonote::block& blk, size_t txs_weight, std::vector<size_t>& block_weights, uint64_t already_generated_coins, uint64_t block_reward, uint8_t hf_version)
{
  const size_t block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  m_blocks_info[get_block_hash(blk)] = block_info(blk.prev_id, already_generated_coins + block_reward, block_weight);
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
  shekyl_curve_tree_selene_hash_init(reinterpret_cast<uint8_t*>(&blk.curve_tree_root));

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
    if (!construct_miner_tx(height, misc_utils::median(block_weights), already_generated_coins, target_block_weight, total_fee, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), 10, hf_ver ? *hf_ver : 1,
        /*tx_volume_avg=*/0, /*circulating_supply=*/already_generated_coins, /*stake_ratio=*/0, /*genesis_ng_height=*/0))
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
  const uint64_t block_reward = get_outs_money_amount(blk.miner_tx) - total_fee;
  add_block(blk, txs_weight, block_weights, already_generated_coins, block_reward, hf_ver ? *hf_ver : 1);

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
  uint64_t timestamp = blk_prev.timestamp + current_difficulty_window(hf_ver); // DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN;
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
  blk.timestamp     = actual_params & bf_timestamp ? timestamp : prev_block.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN; // Keep difficulty unchanged
  blk.prev_id       = actual_params & bf_prev_id   ? prev_id   : get_block_hash(prev_block);
  shekyl_curve_tree_selene_hash_init(reinterpret_cast<uint8_t*>(&blk.curve_tree_root));
  blk.tx_hashes     = actual_params & bf_tx_hashes ? tx_hashes : std::vector<crypto::hash>();
  max_outs          = actual_params & bf_max_outs ? max_outs : 9999;
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
    if (!construct_miner_tx(height, misc_utils::median(block_weights), already_generated_coins, current_block_weight, fees, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), max_outs, hf_version,
        /*tx_volume_avg=*/0, /*circulating_supply=*/already_generated_coins, /*stake_ratio=*/0, /*genesis_ng_height=*/0))
      return false;
  }

  //blk.tree_root_hash = get_tx_tree_hash(blk);

  difficulty_type a_diffic = actual_params & bf_diffic ? diffic : get_test_difficulty(hf_version);
  fill_nonce(blk, a_diffic, height);

  const uint64_t block_reward = get_outs_money_amount(blk.miner_tx) - fees;
  add_block(blk, txs_weight, block_weights, already_generated_coins, block_reward, hf_version);

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

  if (blk.major_version >= RX_BLOCK_VERSION && diffic > 1)
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
  while (!miner::find_nonce_for_given_block([blockchain](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, unsigned int threads, crypto::hash &hash){
    return cryptonote::get_block_longhash(blockchain, b, hash, height, seed_hash, threads);
  }, blk, diffic, height, NULL)) {
    blk.timestamp++;
  }
}

namespace
{
  uint64_t get_inputs_amount(const vector<tx_source_entry> &s)
  {
    uint64_t r = 0;
    for (const tx_source_entry &e : s)
    {
      r += e.amount;
    }

    return r;
  }
}

static bool try_v3_scan_output(const cryptonote::account_base& from, const transaction& tx,
    size_t j, uint64_t& amount_out, rct::key& mask_out,
    crypto::secret_key* ho_out = nullptr)
{
    const auto& keys = from.get_keys();
    if (keys.m_ml_kem_decap_key.empty()) return false;
    if (tx.version < 3) return false;
    if (j >= tx.rct_signatures.outPk.size()) return false;
    if (j >= tx.rct_signatures.enc_amounts.size()) return false;

    std::vector<tx_extra_field> extra_fields;
    if (!parse_tx_extra(tx.extra, extra_fields)) return false;
    tx_extra_pqc_kem_ciphertext kem_ct_field;
    if (!find_tx_extra_field_by_type(extra_fields, kem_ct_field)) return false;

    static constexpr size_t HYBRID_KEM_CT_BYTES = 1120;
    static constexpr size_t X25519_CT_BYTES = 32;
    static constexpr size_t ML_KEM_CT_BYTES = 1088;
    if (kem_ct_field.blob.size() < (j + 1) * HYBRID_KEM_CT_BYTES) return false;

    const uint8_t* ct_ptr = reinterpret_cast<const uint8_t*>(kem_ct_field.blob.data()) + j * HYBRID_KEM_CT_BYTES;
    crypto::public_key output_public_key;
    if (!cryptonote::get_output_public_key(tx.vout[j], output_public_key)) return false;

    auto vt_opt = cryptonote::get_output_view_tag(tx.vout[j]);
    uint8_t view_tag = vt_opt ? vt_opt->data : 0;
    uint8_t amount_tag = tx.rct_signatures.enc_amounts[j][8];

    uint8_t ho_buf[32], y_buf[32], z_buf[32], k_amount_buf[32], recovered_bprime[32];
    uint64_t recovered_amount = 0;
    ShekylBuffer pqc_pk_buf{}, pqc_sk_buf{};
    uint8_t h_pqc_buf[32];

    bool ok = shekyl_scan_output_recover(
        reinterpret_cast<const uint8_t*>(&keys.m_view_secret_key),
        keys.m_ml_kem_decap_key.data(),
        keys.m_ml_kem_decap_key.size(),
        ct_ptr, ct_ptr + X25519_CT_BYTES, ML_KEM_CT_BYTES,
        reinterpret_cast<const uint8_t*>(&output_public_key),
        tx.rct_signatures.outPk[j].mask.bytes,
        tx.rct_signatures.enc_amounts[j].data(),
        amount_tag, view_tag,
        static_cast<uint64_t>(j),
        ho_buf, y_buf, z_buf, k_amount_buf, &recovered_amount,
        recovered_bprime, &pqc_pk_buf, &pqc_sk_buf, h_pqc_buf);

    if (pqc_pk_buf.ptr) shekyl_buffer_free(pqc_pk_buf.ptr, pqc_pk_buf.len);
    if (pqc_sk_buf.ptr) shekyl_buffer_free(pqc_sk_buf.ptr, pqc_sk_buf.len);

    if (!ok) {
        memwipe(ho_buf, 32); memwipe(y_buf, 32);
        memwipe(z_buf, 32); memwipe(k_amount_buf, 32);
        return false;
    }

    if (memcmp(recovered_bprime, &keys.m_account_address.m_spend_public_key, 32) != 0) {
        memwipe(ho_buf, 32); memwipe(y_buf, 32);
        memwipe(z_buf, 32); memwipe(k_amount_buf, 32);
        return false;
    }

    amount_out = recovered_amount;
    memcpy(mask_out.bytes, z_buf, 32);
    if (ho_out)
        memcpy(ho_out->data, ho_buf, 32);
    memwipe(ho_buf, 32); memwipe(y_buf, 32);
    memwipe(z_buf, 32); memwipe(k_amount_buf, 32);
    return true;
}

bool init_output_indices(map_output_idx_t& outs, std::map<uint64_t, std::vector<size_t> >& outs_mine, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, const cryptonote::account_base& from) {

    for (const block& blk : blockchain) {
        vector<const transaction*> vtx;
        vtx.push_back(&blk.miner_tx);

        for (const crypto::hash &h : blk.tx_hashes) {
            const map_hash2tx_t::const_iterator cit = mtx.find(h);
            if (mtx.end() == cit)
                throw std::runtime_error("block contains an unknown tx hash");

            vtx.push_back(cit->second);
        }

        for (size_t i = 0; i < vtx.size(); i++) {
            const transaction &tx = *vtx[i];

            for (size_t j = 0; j < tx.vout.size(); ++j) {
                const tx_out &out = tx.vout[j];

                bool is_miner = (i == 0);
                output_index oi(out.target, out.amount, std::get<txin_gen>(*blk.miner_tx.vin.begin()).height, i, j, &blk, vtx[i]);
                oi.set_rct(tx.version >= 2);
                oi.unlock_time = tx.unlock_time;
                oi.is_coin_base = is_miner;

                if (std::holds_alternative<txout_to_key>(out.target) || std::holds_alternative<txout_to_tagged_key>(out.target)) {
                    uint64_t amount_key = (is_miner && tx.version >= 2) ? 0 : out.amount;
                    outs[amount_key].push_back(oi);
                    size_t tx_global_idx = outs[amount_key].size() - 1;
                    outs[amount_key][tx_global_idx].idx = tx_global_idx;

                    uint64_t recovered_amount = 0;
                    rct::key recovered_mask{};
                    crypto::secret_key recovered_ho{};
                    if (try_v3_scan_output(from, tx, j, recovered_amount, recovered_mask, &recovered_ho))
                    {
                        outs_mine[amount_key].push_back(tx_global_idx);
                        outs[amount_key][tx_global_idx].amount = recovered_amount;
                        outs[amount_key][tx_global_idx].v3_mask = recovered_mask;
                        outs[amount_key][tx_global_idx].v3_ho = recovered_ho;
                        memwipe(recovered_ho.data, sizeof(recovered_ho.data));
                        outs[amount_key][tx_global_idx].v3_recovered = true;
                        LOG_PRINT_L2("v3 output detected: blk_h=" << oi.blk_height
                            << " tx_no=" << i << " out_no=" << j
                            << " amount=" << recovered_amount);
                    }
                }
            }
        }
    }

    return true;
}

static bool compute_v3_key_image(const cryptonote::account_base& from,
    const transaction& tx, size_t out_no, crypto::key_image& img_out)
{
    const auto& keys = from.get_keys();
    if (keys.m_ml_kem_decap_key.empty() || tx.version < 3) return false;
    if (out_no >= tx.rct_signatures.outPk.size()) return false;
    if (out_no >= tx.rct_signatures.enc_amounts.size()) return false;

    std::vector<tx_extra_field> extra_fields;
    if (!parse_tx_extra(tx.extra, extra_fields)) return false;
    tx_extra_pqc_kem_ciphertext kem_ct_field;
    if (!find_tx_extra_field_by_type(extra_fields, kem_ct_field)) return false;

    static constexpr size_t HYBRID_KEM_CT_BYTES = 1120;
    static constexpr size_t X25519_CT_BYTES = 32;
    static constexpr size_t ML_KEM_CT_BYTES = 1088;
    if (kem_ct_field.blob.size() < (out_no + 1) * HYBRID_KEM_CT_BYTES) return false;

    const uint8_t* ct_ptr = reinterpret_cast<const uint8_t*>(kem_ct_field.blob.data()) + out_no * HYBRID_KEM_CT_BYTES;
    crypto::public_key output_public_key;
    if (!cryptonote::get_output_public_key(tx.vout[out_no], output_public_key)) return false;

    auto vt_opt = cryptonote::get_output_view_tag(tx.vout[out_no]);
    uint8_t view_tag = vt_opt ? vt_opt->data : 0;
    uint8_t amount_tag = tx.rct_signatures.enc_amounts[out_no][8];

    uint8_t ho_buf[32], y_buf[32], z_buf[32], k_amount_buf[32], recovered_bprime[32];
    uint64_t recovered_amount = 0;
    ShekylBuffer pqc_pk_buf{}, pqc_sk_buf{};
    uint8_t h_pqc_buf[32];

    bool ok = shekyl_scan_output_recover(
        reinterpret_cast<const uint8_t*>(&keys.m_view_secret_key),
        keys.m_ml_kem_decap_key.data(),
        keys.m_ml_kem_decap_key.size(),
        ct_ptr, ct_ptr + X25519_CT_BYTES, ML_KEM_CT_BYTES,
        reinterpret_cast<const uint8_t*>(&output_public_key),
        tx.rct_signatures.outPk[out_no].mask.bytes,
        tx.rct_signatures.enc_amounts[out_no].data(),
        amount_tag, view_tag,
        static_cast<uint64_t>(out_no),
        ho_buf, y_buf, z_buf, k_amount_buf, &recovered_amount,
        recovered_bprime, &pqc_pk_buf, &pqc_sk_buf, h_pqc_buf);

    if (pqc_pk_buf.ptr) shekyl_buffer_free(pqc_pk_buf.ptr, pqc_pk_buf.len);
    if (pqc_sk_buf.ptr) shekyl_buffer_free(pqc_sk_buf.ptr, pqc_sk_buf.len);

    if (!ok) {
        memwipe(ho_buf, 32); memwipe(y_buf, 32);
        memwipe(z_buf, 32); memwipe(k_amount_buf, 32);
        return false;
    }

    // ki = (ho + b_spend) * Hp(O)
    crypto::secret_key ho;
    memcpy(&ho, ho_buf, 32);
    crypto::secret_key dest_key;
    sc_add(reinterpret_cast<unsigned char*>(&dest_key),
           reinterpret_cast<const unsigned char*>(&ho),
           reinterpret_cast<const unsigned char*>(&keys.m_spend_secret_key));

    crypto::generate_key_image(output_public_key, dest_key, img_out);

    memwipe(&ho, sizeof(ho));
    memwipe(&dest_key, sizeof(dest_key));
    memwipe(ho_buf, 32); memwipe(y_buf, 32);
    memwipe(z_buf, 32); memwipe(k_amount_buf, 32);
    return true;
}

bool init_spent_output_indices(map_output_idx_t& outs, map_output_t& outs_mine, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, const cryptonote::account_base& from) {

    for (const map_output_t::value_type &o : outs_mine) {
        for (size_t i = 0; i < o.second.size(); ++i) {
            output_index &oi = outs[o.first][o.second[i]];

            crypto::key_image img;
            bool got_image = false;

            if (oi.v3_recovered)
            {
                got_image = compute_v3_key_image(from, *oi.p_tx, oi.out_no, img);
            }

            CHECK_AND_ASSERT_MES(got_image, false, "v3 key image derivation failed for output " << oi.out_no);

            for (auto& tx_pair : mtx) {
                const transaction& tx = *tx_pair.second;
                for (const txin_v &in : tx.vin) {
                    if (std::holds_alternative<txin_to_key>(in)) {
                        const txin_to_key &itk = std::get<txin_to_key>(in);
                        if (itk.k_image == img) {
                            oi.spent = true;
                        }
                    }
                }
            }
        }
    }

    return true;
}

bool fill_output_entries(std::vector<output_index>& out_indices, size_t sender_out, size_t nmix, size_t& real_entry_idx, std::vector<tx_source_entry::output_entry>& output_entries)
{
  if (out_indices.size() <= nmix)
    return false;

  bool sender_out_found = false;
  size_t rest = nmix;
  for (size_t i = 0; i < out_indices.size() && (0 < rest || !sender_out_found); ++i)
  {
    const output_index& oi = out_indices[i];
    if (oi.spent)
      continue;

    bool append = false;
    if (i == sender_out)
    {
      append = true;
      sender_out_found = true;
      real_entry_idx = output_entries.size();
    }
    else if (0 < rest)
    {
      --rest;
      append = true;
    }

    if (append)
    {
      rct::key comm = oi.commitment();
      crypto::public_key otk_key;
      CHECK_AND_ASSERT_MES(get_output_key_from_target(oi.out, otk_key), false, "Invalid output target type in fill_output_entries");
      output_entries.push_back(tx_source_entry::output_entry(oi.idx, rct::ctkey({rct::pk2rct(otk_key), comm})));
    }
  }

  return 0 == rest && sender_out_found;
}

bool fill_tx_sources(std::vector<tx_source_entry>& sources, const std::vector<test_event_entry>& events,
                     const block& blk_head, const cryptonote::account_base& from, uint64_t amount, size_t nmix)
{
    map_output_idx_t outs;
    map_output_t outs_mine;

    std::vector<cryptonote::block> blockchain;
    map_hash2tx_t mtx;
    if (!find_block_chain(events, blockchain, mtx, get_block_hash(blk_head)))
        return false;

    if (!init_output_indices(outs, outs_mine, blockchain, mtx, from))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, mtx, from))
        return false;

    uint64_t sources_amount = 0;
    bool sources_found = false;
    for (auto rit = outs_mine.rbegin(); rit != outs_mine.rend(); ++rit)
    {
        const auto& o = *rit;
        for (size_t i = 0; i < o.second.size() && !sources_found; ++i)
        {
            size_t sender_out = o.second[i];
            const output_index& oi = outs[o.first][sender_out];
            if (oi.spent)
                continue;

            cryptonote::tx_source_entry ts;
            ts.real_output_in_tx_index = oi.out_no;
            ts.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx);
            ts.rct = true;

            if (oi.v3_recovered)
            {
                ts.amount = oi.amount;
                ts.mask = oi.v3_mask;
                ts.ho = oi.v3_ho;
                ts.v3_ho_valid = true;
                rct::key C_check = rct::commit(ts.amount, ts.mask);
                if (!rct::equalKeys(C_check, oi.p_tx->rct_signatures.outPk[oi.out_no].mask)) {
                    LOG_ERROR("v3 recovered commitment mismatch for output " << oi.out_no
                        << " amount=" << ts.amount);
                    continue;
                }
            }
            else
            {
                LOG_ERROR("Non-v3 output cannot be recovered (legacy scanning removed)");
                continue;
            }

            size_t realOutput;
            if (!fill_output_entries(outs[o.first], sender_out, nmix, realOutput, ts.outputs))
              continue;

            ts.real_output = realOutput;

            sources.push_back(ts);

            sources_amount += ts.amount;
            sources_found = amount <= sources_amount;
        }

        if (sources_found)
            break;
    }

    return sources_found;
}

bool fill_tx_destination(tx_destination_entry &de, const cryptonote::account_public_address &to, uint64_t amount) {
    de.addr = to;
    de.amount = amount;
    return true;
}

map_txid_output_t::iterator block_tracker::find_out(const crypto::hash &txid, size_t out)
{
  return find_out(std::make_pair(txid, out));
}

map_txid_output_t::iterator block_tracker::find_out(const output_hasher &id)
{
  return m_map_outs.find(id);
}

void block_tracker::process(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx)
{
  std::vector<const cryptonote::block*> blks;
  blks.reserve(blockchain.size());

  for (const block& blk : blockchain) {
    auto hsh = get_block_hash(blk);
    auto it = m_blocks.find(hsh);
    if (it == m_blocks.end()){
      m_blocks[hsh] = blk;
    }

    blks.push_back(&m_blocks[hsh]);
  }

  process(blks, mtx);
}

void block_tracker::process(const std::vector<const cryptonote::block*>& blockchain, const map_hash2tx_t& mtx)
{
  for (const block* blk : blockchain) {
    vector<const transaction*> vtx;
    vtx.push_back(&(blk->miner_tx));

    for (const crypto::hash &h : blk->tx_hashes) {
      const map_hash2tx_t::const_iterator cit = mtx.find(h);
      CHECK_AND_ASSERT_THROW_MES(mtx.end() != cit, "block contains an unknown tx hash");
      vtx.push_back(cit->second);
    }

    for (size_t i = 0; i < vtx.size(); i++) {
      process(blk, vtx[i], i);
    }
  }
}

void block_tracker::process(const block* blk, const transaction * tx, size_t i)
{
  for (size_t j = 0; j < tx->vout.size(); ++j) {
    const tx_out &out = tx->vout[j];

    if (!std::holds_alternative<cryptonote::txout_to_key>(out.target) && !std::holds_alternative<cryptonote::txout_to_tagged_key>(out.target)) {
      continue;
    }

    const uint64_t rct_amount = tx->version >= 2 ? 0 : out.amount;
    const output_hasher hid = std::make_pair(tx->hash, j);
    auto it = find_out(hid);
    if (it != m_map_outs.end()){
      continue;
    }

    output_index oi(out.target, out.amount, std::get<txin_gen>(blk->miner_tx.vin.front()).height, i, j, blk, tx);
    oi.set_rct(tx->version >= 2);
    oi.idx = m_outs[rct_amount].size();
    oi.unlock_time = tx->unlock_time;
    oi.is_coin_base = tx->vin.size() == 1 && std::holds_alternative<cryptonote::txin_gen>(tx->vin.back());

    m_outs[rct_amount].push_back(oi);
    m_map_outs.insert({hid, oi});
  }
}

void block_tracker::global_indices(const cryptonote::transaction *tx, std::vector<uint64_t> &indices)
{
  indices.clear();

  for(size_t j=0; j < tx->vout.size(); ++j){
    auto it = find_out(tx->hash, j);
    if (it != m_map_outs.end()){
      indices.push_back(it->second.idx);
    }
  }
}

void block_tracker::get_fake_outs(size_t num_outs, uint64_t amount, uint64_t global_index, uint64_t cur_height, std::vector<get_outs_entry> &outs){
  auto & vct = m_outs[amount];
  const size_t n_outs = vct.size();
  CHECK_AND_ASSERT_THROW_MES(n_outs > 0, "n_outs is 0");

  std::set<size_t> used;
  std::vector<size_t> choices;
  choices.resize(n_outs);
  for(size_t i=0; i < n_outs; ++i) choices[i] = i;
  shuffle(choices.begin(), choices.end(), std::default_random_engine(crypto::rand<unsigned>()));

  size_t n_iters = 0;
  ssize_t idx = -1;
  outs.reserve(num_outs);
  while(outs.size() < num_outs){
    n_iters += 1;
    idx = (idx + 1) % n_outs;
    size_t oi_idx = choices[(size_t)idx];
    CHECK_AND_ASSERT_THROW_MES((n_iters / n_outs) <= outs.size(), "Fake out pick selection problem");

    auto & oi = vct[oi_idx];
    if (oi.idx == global_index)
      continue;
    crypto::public_key oi_out_key;
    if (!get_output_key_from_target(oi.out, oi_out_key))
      continue;
    if (oi.unlock_time > cur_height)
      continue;
    if (used.find(oi_idx) != used.end())
      continue;

    rct::key comm = oi.commitment();
    auto item = std::make_tuple(oi.idx, oi_out_key, comm);
    outs.push_back(item);
    used.insert(oi_idx);
  }
}

std::string block_tracker::dump_data()
{
  ostringstream ss;
  for (auto &m_out : m_outs)
  {
    auto & vct = m_out.second;
    ss << m_out.first << " => |vector| = " << vct.size() << '\n';

    for (const auto & oi : vct)
    {
      crypto::public_key dump_key{};
      get_output_key_from_target(oi.out, dump_key);

      ss << "    idx: " << oi.idx
      << ", rct: " << oi.rct
      << ", xmr: " << oi.amount
      << ", key: " << dump_keys(dump_key.data)
      << ", msk: " << dump_keys(oi.comm.bytes)
      << ", txid: " << dump_keys(oi.p_tx->hash.data)
      << '\n';
    }
  }

  return ss.str();
}

void block_tracker::dump_data(const std::string & fname)
{
  ofstream myfile;
  myfile.open (fname);
  myfile << dump_data();
  myfile.close();
}

std::string dump_data(const cryptonote::transaction &tx)
{
  ostringstream ss;
  ss << "msg: " << dump_keys(tx.rct_signatures.message.bytes)
     << ", vin: ";

  for(auto & in : tx.vin){
    if (std::holds_alternative<txin_to_key>(in)){
      auto tk = std::get<txin_to_key>(in);
      std::vector<uint64_t> full_off;
      int64_t last = -1;

      ss << " i: " << tk.amount << " [";
      for(auto ix : tk.key_offsets){
        ss << ix << ", ";
        if (last == -1){
          last = ix;
          full_off.push_back(ix);
        } else {
          last += ix;
          full_off.push_back((uint64_t)last);
        }
      }

      ss << "], full: [";
      for(auto ix : full_off){
        ss << ix << ", ";
      }
      ss << "]; ";

    } else if (std::holds_alternative<txin_gen>(in)){
      ss << " h: " << std::get<txin_gen>(in).height << ", ";
    } else {
      ss << " ?, ";
    }
  }

  return ss.str();
}

cryptonote::account_public_address get_address(const var_addr_t& inp)
{
  if (std::holds_alternative<cryptonote::account_public_address>(inp)){
    return std::get<cryptonote::account_public_address>(inp);
  } else if(std::holds_alternative<cryptonote::account_keys>(inp)){
    return std::get<cryptonote::account_keys>(inp).m_account_address;
  } else if (std::holds_alternative<cryptonote::account_base>(inp)){
    return std::get<cryptonote::account_base>(inp).get_keys().m_account_address;
  } else if (std::holds_alternative<cryptonote::tx_destination_entry>(inp)){
    return std::get<cryptonote::tx_destination_entry>(inp).addr;
  } else {
    throw std::runtime_error("Unexpected type");
  }
}

cryptonote::account_public_address get_address(const cryptonote::account_public_address& inp)
{
  return inp;
}

cryptonote::account_public_address get_address(const cryptonote::account_keys& inp)
{
  return inp.m_account_address;
}

cryptonote::account_public_address get_address(const cryptonote::account_base& inp)
{
  return inp.get_keys().m_account_address;
}

cryptonote::account_public_address get_address(const cryptonote::tx_destination_entry& inp)
{
  return inp.addr;
}

uint64_t sum_amount(const std::vector<tx_destination_entry>& destinations)
{
  uint64_t amount = 0;
  for(auto & cur : destinations){
    amount += cur.amount;
  }

  return amount;
}

uint64_t sum_amount(const std::vector<cryptonote::tx_source_entry>& sources)
{
  uint64_t amount = 0;
  for(auto & cur : sources){
    amount += cur.amount;
  }

  return amount;
}

void fill_tx_destinations(const var_addr_t& from, const std::vector<tx_destination_entry>& dests,
                          uint64_t fee,
                          const std::vector<tx_source_entry> &sources,
                          std::vector<tx_destination_entry>& destinations,
                          bool always_change)

{
  destinations.clear();
  uint64_t amount = sum_amount(dests);
  std::copy(dests.begin(), dests.end(), std::back_inserter(destinations));

  tx_destination_entry de_change;
  uint64_t cache_back = get_inputs_amount(sources) - (amount + fee);

  if (cache_back > 0 || always_change) {
    if (!fill_tx_destination(de_change, get_address(from), cache_back <= 0 ? 0 : cache_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }
}

void fill_tx_destinations(const var_addr_t& from, const cryptonote::account_public_address& to,
                          uint64_t amount, uint64_t fee,
                          const std::vector<tx_source_entry> &sources,
                          std::vector<tx_destination_entry>& destinations,
                          std::vector<tx_destination_entry>& destinations_pure,
                          bool always_change)
{
  destinations.clear();

  tx_destination_entry de;
  if (!fill_tx_destination(de, to, amount))
    throw std::runtime_error("couldn't fill transaction destination");
  destinations.push_back(de);
  destinations_pure.push_back(de);

  tx_destination_entry de_change;
  uint64_t cache_back = get_inputs_amount(sources) - (amount + fee);

  if (cache_back > 0 || always_change) {
    if (!fill_tx_destination(de_change, get_address(from), cache_back <= 0 ? 0 : cache_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }
}

void fill_tx_destinations(const var_addr_t& from, const cryptonote::account_public_address& to,
                          uint64_t amount, uint64_t fee,
                          const std::vector<tx_source_entry> &sources,
                          std::vector<tx_destination_entry>& destinations, bool always_change)
{
  std::vector<tx_destination_entry> destinations_pure;
  fill_tx_destinations(from, to, amount, fee, sources, destinations, destinations_pure, always_change);
}

void fill_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_public_address& to,
                                      uint64_t amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry>& sources,
                                      std::vector<tx_destination_entry>& destinations)
{
  sources.clear();
  destinations.clear();

  if (!fill_tx_sources(sources, events, blk_head, from, amount + fee, nmix))
    throw std::runtime_error("couldn't fill transaction sources");

  fill_tx_destinations(from, to, amount, fee, sources, destinations, true);
}

void fill_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_base& to,
                                      uint64_t amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry>& sources,
                                      std::vector<tx_destination_entry>& destinations)
{
  fill_tx_sources_and_destinations(events, blk_head, from, to.get_keys().m_account_address, amount, fee, nmix, sources, destinations);
}

cryptonote::tx_destination_entry build_dst(const var_addr_t& to, bool is_subaddr, uint64_t amount)
{
  tx_destination_entry de;
  de.amount = amount;
  de.addr = get_address(to);
  de.is_subaddress = is_subaddr;
  return de;
}

std::vector<cryptonote::tx_destination_entry> build_dsts(const var_addr_t& to1, bool sub1, uint64_t am1)
{
  std::vector<cryptonote::tx_destination_entry> res;
  res.push_back(build_dst(to1, sub1, am1));
  return res;
}

std::vector<cryptonote::tx_destination_entry> build_dsts(std::initializer_list<dest_wrapper_t> inps)
{
  std::vector<cryptonote::tx_destination_entry> res;
  res.reserve(inps.size());
  for(auto & c : inps){
    res.push_back(build_dst(c.addr, c.is_subaddr, c.amount));
  }
  return res;
}

namespace {
  static void local_derivation_to_scalar(const crypto::key_derivation &d, size_t output_index, crypto::ec_scalar &res)
  {
    #pragma pack(push, 1)
    struct { crypto::key_derivation d; uint8_t vi[8]; } buf;
    #pragma pack(pop)
    buf.d = d;
    size_t idx = output_index, vi_len = 0;
    while (idx >= 0x80) { buf.vi[vi_len++] = (uint8_t)(idx & 0x7f) | 0x80; idx >>= 7; }
    buf.vi[vi_len++] = (uint8_t)idx;
    crypto::hash_to_scalar(&buf, sizeof(crypto::key_derivation) + vi_len, res);
  }

  static bool local_derive_public_key(const crypto::key_derivation &d, size_t output_index,
                                      const crypto::public_key &spend_pub, crypto::public_key &out)
  {
    crypto::ec_scalar hs;
    local_derivation_to_scalar(d, output_index, hs);
    ge_p3 point1;
    ge_scalarmult_base(&point1, reinterpret_cast<const unsigned char*>(&hs));
    ge_p3 point2;
    if (ge_frombytes_vartime(&point2, reinterpret_cast<const unsigned char*>(&spend_pub)) != 0)
      return false;
    ge_cached point2c;
    ge_p3_to_cached(&point2c, &point2);
    ge_p1p1 sum;
    ge_add(&sum, &point1, &point2c);
    ge_p3 result;
    ge_p1p1_to_p3(&result, &sum);
    ge_p3_tobytes(reinterpret_cast<unsigned char*>(&out), &result);
    return true;
  }

  static void local_derive_view_tag(const crypto::key_derivation &d, size_t output_index, crypto::view_tag &vt)
  {
    #pragma pack(push, 1)
    struct { char tag[8]; crypto::key_derivation d; uint8_t vi[8]; } buf;
    #pragma pack(pop)
    memcpy(buf.tag, "view_tag", 8);
    buf.d = d;
    size_t idx = output_index, vi_len = 0;
    while (idx >= 0x80) { buf.vi[vi_len++] = (uint8_t)(idx & 0x7f) | 0x80; idx >>= 7; }
    buf.vi[vi_len++] = (uint8_t)idx;
    crypto::hash h;
    crypto::cn_fast_hash(&buf, sizeof(buf.tag) + sizeof(crypto::key_derivation) + vi_len, h);
    vt.data = h.data[0];
  }
} // anonymous namespace

bool construct_miner_tx_manually(size_t height, uint64_t already_generated_coins,
                                 const account_public_address& miner_address, transaction& tx, uint64_t fee,
                                 uint8_t hf_version/* = 1*/, keypair* p_txkey/* = 0*/)
{
  tx.vin.clear();
  tx.vout.clear();
  tx.extra.clear();
  tx.rct_signatures = {};

  keypair txkey = keypair::generate(hw::get_device("default"));
  add_tx_pub_key_to_extra(tx, txkey.pub);
  if (!sort_tx_extra(tx.extra, tx.extra))
    return false;

  if (p_txkey)
    *p_txkey = txkey;

  txin_gen in;
  in.height = height;

  uint64_t block_reward;
  if (!get_block_reward(0, 0, already_generated_coins, block_reward, hf_version, 0))
    return false;

  shekyl::EmissionSplit em_split = shekyl::compute_emission_split(block_reward, height, 0, hf_version);
  block_reward = em_split.miner_emission;

  shekyl::BurnResult burn = shekyl::compute_fee_burn(fee, 0, 0, 0, hf_version);
  block_reward += burn.miner_fee_income;

  CHECK_AND_ASSERT_MES(miner_address.m_pqc_public_key.size() == SHEKYL_PQC_PUBLIC_KEY_BYTES, false,
    "construct_miner_tx_manually: miner PQC public key size "
    << miner_address.m_pqc_public_key.size() << " != " << SHEKYL_PQC_PUBLIC_KEY_BYTES);

  const uint8_t* pk_x25519 = miner_address.m_pqc_public_key.data();
  const uint8_t* pk_ml_kem = miner_address.m_pqc_public_key.data() + SHEKYL_X25519_PK_BYTES;
  const size_t pk_ml_kem_len = miner_address.m_pqc_public_key.size() - SHEKYL_X25519_PK_BYTES;

  tx_extra_pqc_kem_ciphertext kem_field;
  kem_field.blob.reserve(HYBRID_KEM_CT_BYTES);
  tx_extra_pqc_leaf_hashes leaf_hash_field;
  leaf_hash_field.blob.reserve(PQC_LEAF_HASH_BYTES);

  tx.rct_signatures.outPk.resize(1);
  tx.rct_signatures.enc_amounts.resize(1);

  ShekylOutputData od = shekyl_construct_output(
    reinterpret_cast<const uint8_t*>(&txkey.sec),
    pk_x25519, pk_ml_kem, pk_ml_kem_len,
    reinterpret_cast<const uint8_t*>(&miner_address.m_spend_public_key),
    block_reward, 0);
  CHECK_AND_ASSERT_MES(od.success, false, "shekyl_construct_output failed for manual coinbase");

  crypto::public_key out_key;
  memcpy(out_key.data, od.output_key, 32);
  crypto::view_tag vt;
  vt.data = od.view_tag_x25519;

  tx_out out;
  cryptonote::set_tx_out(block_reward, out_key, true, vt, out);
  tx.vout.push_back(out);

  memcpy(tx.rct_signatures.outPk[0].mask.bytes, od.commitment, 32);
  memcpy(tx.rct_signatures.enc_amounts[0].data(), od.enc_amount, 8);
  tx.rct_signatures.enc_amounts[0][8] = od.amount_tag;

  kem_field.blob.append(reinterpret_cast<const char*>(od.kem_ciphertext_x25519), 32);
  if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
    kem_field.blob.append(
      reinterpret_cast<const char*>(od.kem_ciphertext_ml_kem.ptr),
      od.kem_ciphertext_ml_kem.len);
  leaf_hash_field.blob.append(reinterpret_cast<const char*>(od.h_pqc), PQC_LEAF_HASH_BYTES);

  ShekylOutputData tmp = od;
  shekyl_output_data_free(&tmp);

  {
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    tx_extra_field variant_field = kem_field;
    if (!::do_serialize(oar, variant_field)) return false;
    std::string blob = oss.str();
    tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
  }
  {
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    tx_extra_field variant_field = leaf_hash_field;
    if (!::do_serialize(oar, variant_field)) return false;
    std::string blob = oss.str();
    tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
  }
  if (!sort_tx_extra(tx.extra, tx.extra))
    return false;

  tx.version = 3;
  tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
  tx.vin.push_back(in);
  tx.invalidate_hashes();

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
  vt.data = od.view_tag_x25519;

  tx_out out;
  cryptonote::set_tx_out(amount, out_key, true, vt, out);
  tx.vout.push_back(out);

  rct::ctkey pk_entry;
  memcpy(pk_entry.mask.bytes, od.commitment, 32);
  tx.rct_signatures.outPk.push_back(pk_entry);

  std::array<uint8_t, 9> enc_amt{};
  memcpy(enc_amt.data(), od.enc_amount, 8);
  enc_amt[8] = od.amount_tag;
  tx.rct_signatures.enc_amounts.push_back(enc_amt);

  std::vector<tx_extra_field> extra_fields;
  CHECK_AND_ASSERT_MES(parse_tx_extra(tx.extra, extra_fields), false, "failed to parse tx.extra");

  tx_extra_pqc_kem_ciphertext kem_field;
  find_tx_extra_field_by_type(extra_fields, kem_field);
  kem_field.blob.append(reinterpret_cast<const char*>(od.kem_ciphertext_x25519), 32);
  if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
    kem_field.blob.append(
      reinterpret_cast<const char*>(od.kem_ciphertext_ml_kem.ptr),
      od.kem_ciphertext_ml_kem.len);

  tx_extra_pqc_leaf_hashes leaf_hash_field;
  find_tx_extra_field_by_type(extra_fields, leaf_hash_field);
  leaf_hash_field.blob.append(reinterpret_cast<const char*>(od.h_pqc), PQC_LEAF_HASH_BYTES);

  ShekylOutputData tmp = od;
  shekyl_output_data_free(&tmp);

  tx.extra.clear();
  for (auto& f : extra_fields)
  {
    if (std::holds_alternative<tx_extra_pqc_kem_ciphertext>(f))
      f = kem_field;
    else if (std::holds_alternative<tx_extra_pqc_leaf_hashes>(f))
      f = leaf_hash_field;

    std::ostringstream oss;
    binary_archive<true> oar(oss);
    CHECK_AND_ASSERT_MES(::do_serialize(oar, f), false, "failed to re-serialize extra field");
    std::string blob = oss.str();
    tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
  }
  if (!sort_tx_extra(tx.extra, tx.extra))
    return false;

  tx.invalidate_hashes();
  return true;
}

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const cryptonote::block& blk_head,
                         const cryptonote::account_base& from, const var_addr_t& to, uint64_t amount,
                         uint64_t fee, size_t nmix, bool rct)
{
  vector<tx_source_entry> sources;
  vector<tx_destination_entry> destinations;
  fill_tx_sources_and_destinations(events, blk_head, from, get_address(to), amount, fee, nmix, sources, destinations);

  return construct_tx_rct(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, rct);
}

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const cryptonote::block& blk_head,
                         const cryptonote::account_base& from, std::vector<cryptonote::tx_destination_entry> destinations,
                         uint64_t fee, size_t nmix, bool rct)
{
  vector<tx_source_entry> sources;
  vector<tx_destination_entry> destinations_all;
  uint64_t amount = sum_amount(destinations);

  if (!fill_tx_sources(sources, events, blk_head, from, amount + fee, nmix))
    throw std::runtime_error("couldn't fill transaction sources");

  fill_tx_destinations(from, destinations, fee, sources, destinations_all, false);

  return construct_tx_rct(from.get_keys(), sources, destinations_all, get_address(from), std::vector<uint8_t>(), tx, rct);
}

bool construct_tx_to_key(cryptonote::transaction& tx,
                         const cryptonote::account_base& from, const var_addr_t& to, uint64_t amount,
                         std::vector<cryptonote::tx_source_entry> &sources,
                         uint64_t fee, bool rct)
{
  vector<tx_destination_entry> destinations;
  fill_tx_destinations(from, get_address(to), amount, fee, sources, destinations, rct);
  return construct_tx_rct(from.get_keys(), sources, destinations, get_address(from), std::vector<uint8_t>(), tx, rct);
}

bool construct_tx_to_key(cryptonote::transaction& tx,
                         const cryptonote::account_base& from,
                         const std::vector<cryptonote::tx_destination_entry>& destinations,
                         std::vector<cryptonote::tx_source_entry> &sources,
                         uint64_t fee, bool rct)
{
  vector<tx_destination_entry> all_destinations;
  fill_tx_destinations(from, destinations, fee, sources, all_destinations, rct);
  return construct_tx_rct(from.get_keys(), sources, all_destinations, get_address(from), std::vector<uint8_t>(), tx, rct);
}

bool construct_tx_rct(const cryptonote::account_keys& sender_account_keys, std::vector<cryptonote::tx_source_entry>& sources, const std::vector<cryptonote::tx_destination_entry>& destinations, const std::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, cryptonote::transaction& tx, bool rct, uint8_t hf_version)
{
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0, 0};
  crypto::secret_key tx_key;
  std::vector<tx_destination_entry> destinations_copy = destinations;
  return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, tx_key, rct, true, hf_version);
}

transaction construct_tx_with_fee(std::vector<test_event_entry>& events, const block& blk_head,
                                  const account_base& acc_from, const var_addr_t& to, uint64_t amount, uint64_t fee)
{
  transaction tx;
  construct_tx_to_key(events, tx, blk_head, acc_from, to, amount, fee, 0);
  events.push_back(tx);
  return tx;
}

// Mirrors production collect_outputs() in blockchain_db.cpp: only counts
// outputs with recognized vout types that also have an outPk entry (commitment).
static uint64_t count_eligible_outputs(const cryptonote::transaction& tx, bool is_miner, uint64_t block_height)
{
  uint64_t count = 0;
  for (uint64_t i = 0; i < tx.vout.size(); ++i)
  {
    const auto& vout = tx.vout[i];

    uint64_t maturity;
    if (std::holds_alternative<cryptonote::txout_to_tagged_key>(vout.target))
    {
      maturity = is_miner
          ? block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
          : block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    }
    else if (std::holds_alternative<cryptonote::txout_to_key>(vout.target))
    {
      maturity = is_miner
          ? block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
          : block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    }
    else if (std::holds_alternative<cryptonote::txout_to_staked_key>(vout.target))
    {
      const auto& staked = std::get<cryptonote::txout_to_staked_key>(vout.target);
      uint64_t lock_until = block_height + shekyl_stake_lock_blocks(staked.lock_tier);
      maturity = std::max(lock_until, block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
    }
    else
      continue;

    if (i >= tx.rct_signatures.outPk.size())
      continue;

    (void)maturity;
    ++count;
  }
  return count;
}

static uint64_t compute_leaf_count_at_height(
    cryptonote::core& c, uint64_t target_height)
{
  const auto& bs = c.get_blockchain_storage();
  const auto& db = bs.get_db();
  uint64_t leaf_count = 0;

  for (uint64_t h = 0; h <= target_height; ++h)
  {
    cryptonote::block blk = db.get_block_from_height(h);
    const uint64_t block_height = h + 1;

    // Coinbase: count eligible outputs and check maturity.
    // drain_pending_tree_leaves drains at maturity <= current_height, so
    // the leaf count at height H is outputs with maturity <= H.
    {
      uint64_t coinbase_maturity = block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
      if (coinbase_maturity <= target_height)
        leaf_count += count_eligible_outputs(blk.miner_tx, true, block_height);
    }

    // Non-coinbase tx outputs
    for (const auto& tx_hash : blk.tx_hashes)
    {
      cryptonote::transaction tx;
      if (!db.get_tx(tx_hash, tx))
        continue;

      for (uint64_t i = 0; i < tx.vout.size(); ++i)
      {
        const auto& vout = tx.vout[i];

        uint64_t mat;
        if (std::holds_alternative<cryptonote::txout_to_tagged_key>(vout.target))
          mat = block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
        else if (std::holds_alternative<cryptonote::txout_to_key>(vout.target))
          mat = block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
        else if (std::holds_alternative<cryptonote::txout_to_staked_key>(vout.target))
        {
          const auto& staked = std::get<cryptonote::txout_to_staked_key>(vout.target);
          uint64_t lock_until = block_height + shekyl_stake_lock_blocks(staked.lock_tier);
          mat = std::max(lock_until, block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
        }
        else
          continue;

        if (i >= tx.rct_signatures.outPk.size())
          continue;

        if (mat <= target_height)
          ++leaf_count;
      }
    }
  }
  return leaf_count;
}

static bool assemble_tree_path_for_output(
    const BlockchainDB& db,
    uint64_t output_idx,
    uint64_t ref_leaf_count,
    std::vector<uint8_t>& path_out)
{
  const uint8_t depth = db.get_curve_tree_depth();
  if (ref_leaf_count == 0 || output_idx >= ref_leaf_count || depth == 0)
    return false;

  const uint32_t SELENE_CHUNK = shekyl_curve_tree_selene_chunk_width();
  const uint32_t HELIOS_CHUNK = shekyl_curve_tree_helios_chunk_width();
  static constexpr uint32_t SCALARS_PER_LEAF = 4;

  auto chunk_width = [&](uint8_t layer) -> uint32_t {
    if (layer == 0) return SELENE_CHUNK;
    return (layer % 2 == 0) ? SELENE_CHUNK : HELIOS_CHUNK;
  };

  const uint64_t current_leaf_count = db.get_curve_tree_leaf_count();

  path_out.clear();

  // Layer 0: leaf scalars in the chunk (bounded by ref_leaf_count)
  uint64_t chunk_idx = output_idx / SELENE_CHUNK;
  uint64_t chunk_start = chunk_idx * SELENE_CHUNK;
  uint64_t chunk_end = std::min(chunk_start + static_cast<uint64_t>(SELENE_CHUNK), ref_leaf_count);

  uint16_t leaf_pos = static_cast<uint16_t>(output_idx - chunk_start);
  path_out.push_back(static_cast<uint8_t>(leaf_pos & 0xFF));
  path_out.push_back(static_cast<uint8_t>((leaf_pos >> 8) & 0xFF));

  static constexpr size_t LEAF_BYTES = 128;
  for (uint64_t i = chunk_start; i < chunk_end; ++i)
  {
    uint8_t leaf[LEAF_BYTES];
    if (!db.get_curve_tree_leaf_by_tree_position(i, leaf))
      return false;
    path_out.insert(path_out.end(), leaf, leaf + LEAF_BYTES);
  }

  // Compute node counts at each layer for the ref state, and identify
  // the last chunk at each layer that may need hash correction.
  uint64_t ref_nodes_at_prev_layer = ref_leaf_count;
  uint64_t cur_nodes_at_prev_layer = current_leaf_count;

  uint64_t parent_idx = chunk_idx;
  for (uint8_t layer = 1; layer <= depth; ++layer)
  {
    uint32_t prev_cw = chunk_width(layer - 1);
    uint32_t cw = chunk_width(layer);

    uint64_t ref_chunks_below = (ref_nodes_at_prev_layer + prev_cw - 1) / prev_cw;
    uint64_t cur_chunks_below = (cur_nodes_at_prev_layer + prev_cw - 1) / prev_cw;
    uint64_t last_ref_chunk_below = (ref_chunks_below > 0) ? ref_chunks_below - 1 : 0;

    uint64_t my_chunk_idx = parent_idx / cw;
    uint64_t sib_start = my_chunk_idx * cw;
    uint16_t pos_in_chunk = static_cast<uint16_t>(parent_idx - sib_start);
    path_out.push_back(static_cast<uint8_t>(pos_in_chunk & 0xFF));
    path_out.push_back(static_cast<uint8_t>((pos_in_chunk >> 8) & 0xFF));

    // Read sibling hashes from layer below (layer-1 chunk hashes).
    // Pad to full chunk width with zeros for the prover.
    for (uint32_t c = 0; c < cw; ++c)
    {
      uint64_t sibling_chunk = sib_start + c;
      uint8_t hash[32] = {};

      if (sibling_chunk < ref_chunks_below)
      {
        db.get_curve_tree_layer_hash(layer - 1, sibling_chunk, hash);

        // If this sibling is the boundary chunk that grew since ref_height,
        // trim back to the ref state.
        if (sibling_chunk == last_ref_chunk_below &&
            ref_nodes_at_prev_layer != cur_nodes_at_prev_layer &&
            ref_nodes_at_prev_layer % prev_cw != 0)
        {
          uint64_t ref_in_chunk = ref_nodes_at_prev_layer - sibling_chunk * prev_cw;
          uint64_t cur_in_chunk = std::min(
              cur_nodes_at_prev_layer - sibling_chunk * prev_cw,
              static_cast<uint64_t>(prev_cw));

          if (cur_in_chunk > ref_in_chunk)
          {
            uint64_t scalars_per_entry = (layer == 1) ? SCALARS_PER_LEAF : 1;
            uint64_t trim_offset = ref_in_chunk * scalars_per_entry;
            uint64_t num_extra = cur_in_chunk - ref_in_chunk;
            uint64_t num_extra_scalars = num_extra * scalars_per_entry;

            std::vector<uint8_t> extra_data;
            if (layer == 1)
            {
              for (uint64_t li = sibling_chunk * prev_cw + ref_in_chunk;
                   li < sibling_chunk * prev_cw + cur_in_chunk; ++li)
              {
                uint8_t leaf[LEAF_BYTES];
                if (db.get_curve_tree_leaf_by_tree_position(li, leaf))
                  extra_data.insert(extra_data.end(), leaf, leaf + LEAF_BYTES);
                else
                  extra_data.insert(extra_data.end(), LEAF_BYTES, 0);
              }
            }
            else
            {
              for (uint64_t li = sibling_chunk * prev_cw + ref_in_chunk;
                   li < sibling_chunk * prev_cw + cur_in_chunk; ++li)
              {
                uint8_t h[32] = {};
                db.get_curve_tree_layer_hash(layer - 2, li, h);
                extra_data.insert(extra_data.end(), h, h + 32);
              }
            }

            uint8_t zero_scalar[32] = {};
            uint8_t trimmed[32];
            bool is_selene = (layer - 1) % 2 == 0;
            bool ok;
            if (is_selene)
              ok = shekyl_curve_tree_hash_trim_selene(
                  hash, trim_offset, extra_data.data(),
                  num_extra_scalars, zero_scalar, trimmed);
            else
              ok = shekyl_curve_tree_hash_trim_helios(
                  hash, trim_offset, extra_data.data(),
                  num_extra_scalars, zero_scalar, trimmed);

            if (ok)
              memcpy(hash, trimmed, 32);
          }
        }
      }
      path_out.insert(path_out.end(), hash, hash + 32);
    }

    ref_nodes_at_prev_layer = ref_chunks_below;
    cur_nodes_at_prev_layer = cur_chunks_below;
    parent_idx = my_chunk_idx;
  }

  return !path_out.empty();
}

static bool apply_fcmp_pipeline(
    cryptonote::core& c,
    const cryptonote::account_base& from,
    const std::vector<tx_source_entry>& sources,
    const std::vector<tx_destination_entry>& dests_copy,
    rct::keyV& v3_commitment_masks,
    uint64_t fee,
    const std::vector<test_event_entry>& events,
    const cryptonote::block& blk_head,
    cryptonote::transaction& tx)
{
  // Phase B: build FCMP++ proof
  const auto& bs = c.get_blockchain_storage();
  const auto& db = bs.get_db();
  const size_t num_inputs = tx.vin.size();

  rct::ctkeyV inSk(num_inputs), inPk(num_inputs);
  rct::keyV y_keys(num_inputs);
  std::vector<std::vector<uint8_t>> tree_paths(num_inputs);
  std::vector<std::vector<rct::fcmp_chunk_entry>> leaf_chunk_entries(num_inputs);
  rct::keyV pqc_pk_hashes(num_inputs);

  // Per-input combined_ss (64 bytes) + output_index for shekyl_sign_pqc_auth.
  // ML-DSA secret key never leaves Rust — signing uses the high-level FFI.
  struct pqc_sign_input { uint8_t combined_ss[64]; uint64_t output_index; };
  std::vector<pqc_sign_input> pqc_sign_data(num_inputs);

  std::vector<const tx_source_entry*> matched_sources(num_inputs, nullptr);

  auto wipe_keys = epee::misc_utils::create_scope_leave_handler([&pqc_sign_data]() {
    for (auto& sd : pqc_sign_data)
      memwipe(sd.combined_ss, sizeof(sd.combined_ss));
  });

  crypto::hash reference_block{};
  uint8_t tree_depth = db.get_curve_tree_depth();
  CHECK_AND_ASSERT_MES(tree_depth > 0, false, "construct_fcmp_tx: curve tree depth is 0");

  uint64_t chain_height = c.get_current_blockchain_height();
  CHECK_AND_ASSERT_MES(chain_height > FCMP_REFERENCE_BLOCK_MIN_AGE, false,
    "construct_fcmp_tx: chain not tall enough for FCMP_REFERENCE_BLOCK_MIN_AGE");

  uint64_t ref_height = chain_height - 1 - FCMP_REFERENCE_BLOCK_MIN_AGE;
  reference_block = bs.get_block_id_by_height(ref_height);

  rct::key curve_tree_root;
  {
    auto stored_root = db.get_curve_tree_root_at_height(ref_height);
    memcpy(curve_tree_root.bytes, stored_root.data(), 32);
  }

  const uint64_t ref_leaf_count = compute_leaf_count_at_height(c, ref_height);
  LOG_PRINT_L1("construct_fcmp_tx: ref_height=" << ref_height
    << " ref_leaf_count=" << ref_leaf_count
    << " current_leaf_count=" << db.get_curve_tree_leaf_count()
    << " tree_depth=" << (int)tree_depth
    << " curve_tree_root=" << epee::string_tools::pod_to_hex(curve_tree_root));

  static constexpr size_t HYBRID_KEM_CT_BYTES = 1120;
  static constexpr size_t X25519_CT_BYTES = 32;
  static constexpr size_t ML_KEM_CT_BYTES = 1088;

  // Pre-build blockchain/mtx once for source tx lookup
  std::vector<block> ev_blockchain;
  map_hash2tx_t ev_mtx;
  find_block_chain(events, ev_blockchain, ev_mtx, get_block_hash(blk_head));

  // Build inSk/inPk and tree paths per input using HKDF (scan_output_recover)
  for (size_t i = 0; i < num_inputs; ++i)
  {
    CHECK_AND_ASSERT_MES(std::holds_alternative<txin_to_key>(tx.vin[i]), false,
      "construct_fcmp_tx: unexpected input type");
    const txin_to_key& in = std::get<txin_to_key>(tx.vin[i]);

    // Match vin to source using legacy key image (both sides use the same derivation)
    const tx_source_entry* matched_src = nullptr;
    for (const auto& src : sources)
    {
      crypto::public_key out_key = rct::rct2pk(src.outputs[src.real_output].second.dest);
      crypto::key_image ki;
      CHECK_AND_ASSERT_MES(src.v3_ho_valid, false, "construct_fcmp_tx: source missing v3 ho");
      {
        crypto::secret_key x_secret;
        sc_add(reinterpret_cast<unsigned char*>(&x_secret),
               reinterpret_cast<const unsigned char*>(&src.ho),
               reinterpret_cast<const unsigned char*>(&from.get_keys().m_spend_secret_key));
        crypto::generate_key_image(out_key, x_secret, ki);
        memwipe(&x_secret, sizeof(x_secret));
      }
      if (ki == in.k_image) { matched_src = &src; break; }
    }
    CHECK_AND_ASSERT_MES(matched_src, false, "construct_fcmp_tx: could not match source for vin " << i);
    matched_sources[i] = matched_src;

    // Find source transaction
    transaction src_tx_data;
    {
      bool found = false;
      for (const auto& blk : ev_blockchain)
      {
        crypto::public_key blk_tx_key = get_tx_pub_key_from_extra(blk.miner_tx);
        if (blk_tx_key == matched_src->real_out_tx_key)
        { src_tx_data = blk.miner_tx; found = true; break; }
        for (const auto& [hash, ptx] : ev_mtx)
        {
          crypto::public_key tx_pk = get_tx_pub_key_from_extra(*ptx);
          if (tx_pk == matched_src->real_out_tx_key)
          { src_tx_data = *ptx; found = true; break; }
        }
        if (found) break;
      }
      CHECK_AND_ASSERT_MES(found, false, "construct_fcmp_tx: source tx not found in events for vin " << i);
    }

    size_t output_in_tx = matched_src->real_output_in_tx_index;
    crypto::public_key out_key = rct::rct2pk(matched_src->outputs[matched_src->real_output].second.dest);

    // Recover all per-output secrets via HKDF (KEM decap + HKDF inside Rust)
    std::vector<tx_extra_field> extra_fields;
    parse_tx_extra(src_tx_data.extra, extra_fields);
    tx_extra_pqc_kem_ciphertext kem_ct_field;
    bool has_kem = find_tx_extra_field_by_type(extra_fields, kem_ct_field);
    CHECK_AND_ASSERT_MES(has_kem, false, "construct_fcmp_tx: source tx missing KEM ciphertext for vin " << i);
    CHECK_AND_ASSERT_MES(kem_ct_field.blob.size() >= (output_in_tx + 1) * HYBRID_KEM_CT_BYTES, false,
      "construct_fcmp_tx: KEM ciphertext blob too short for vin " << i);

    const uint8_t* ct_ptr = reinterpret_cast<const uint8_t*>(kem_ct_field.blob.data()) + output_in_tx * HYBRID_KEM_CT_BYTES;
    const auto& sender_keys = from.get_keys();
    CHECK_AND_ASSERT_MES(!sender_keys.m_ml_kem_decap_key.empty(), false,
      "construct_fcmp_tx: sender has no ML-KEM decapsulation key; wallet is "
      "classical-signing-only and cannot construct v3 inputs");

    CHECK_AND_ASSERT_MES(output_in_tx < src_tx_data.rct_signatures.outPk.size(), false,
      "construct_fcmp_tx: outPk index out of range");
    CHECK_AND_ASSERT_MES(output_in_tx < src_tx_data.rct_signatures.enc_amounts.size(), false,
      "construct_fcmp_tx: enc_amounts index out of range");

    auto vt_opt = get_output_view_tag(src_tx_data.vout[output_in_tx]);
    uint8_t view_tag = vt_opt ? vt_opt->data : 0;
    uint8_t amount_tag = src_tx_data.rct_signatures.enc_amounts[output_in_tx][8];

    uint8_t ho_buf[32], y_buf[32], z_buf[32], k_amount_buf[32], recovered_bprime[32];
    uint64_t recovered_amount = 0;
    ShekylBuffer pqc_pk_buf{}, pqc_sk_buf{};
    uint8_t h_pqc_buf[32];

    bool scan_ok = shekyl_scan_output_recover(
        reinterpret_cast<const uint8_t*>(&sender_keys.m_view_secret_key),
        sender_keys.m_ml_kem_decap_key.data(),
        sender_keys.m_ml_kem_decap_key.size(),
        ct_ptr, ct_ptr + X25519_CT_BYTES, ML_KEM_CT_BYTES,
        reinterpret_cast<const uint8_t*>(&out_key),
        src_tx_data.rct_signatures.outPk[output_in_tx].mask.bytes,
        src_tx_data.rct_signatures.enc_amounts[output_in_tx].data(),
        amount_tag, view_tag,
        static_cast<uint64_t>(output_in_tx),
        ho_buf, y_buf, z_buf, k_amount_buf, &recovered_amount,
        recovered_bprime, &pqc_pk_buf, &pqc_sk_buf, h_pqc_buf);
    CHECK_AND_ASSERT_MES(scan_ok, false, "construct_fcmp_tx: scan_output_recover failed for vin " << i);

    LOG_PRINT_L1("construct_fcmp_tx: vin " << i << " recovered amount=" << recovered_amount
      << " output_in_tx=" << output_in_tx);

    CHECK_AND_ASSERT_MES(pqc_pk_buf.ptr && pqc_sk_buf.ptr, false,
      "construct_fcmp_tx: scan_output_recover returned null PQC buffers for vin " << i);
    memcpy(pqc_pk_hashes[i].bytes, h_pqc_buf, 32);
    shekyl_buffer_free(pqc_pk_buf.ptr, pqc_pk_buf.len);
    shekyl_buffer_free(pqc_sk_buf.ptr, pqc_sk_buf.len);

    // Derive combined_ss for PQC signing via shekyl_sign_pqc_auth later.
    // ML-DSA secret key stays inside Rust — never materialized in C++.
    bool decap_ok = shekyl_kem_decapsulate(
        reinterpret_cast<const uint8_t*>(&sender_keys.m_view_secret_key),
        sender_keys.m_ml_kem_decap_key.data(),
        sender_keys.m_ml_kem_decap_key.size(),
        ct_ptr, ct_ptr + X25519_CT_BYTES, ML_KEM_CT_BYTES,
        pqc_sign_data[i].combined_ss);
    CHECK_AND_ASSERT_MES(decap_ok, false, "construct_fcmp_tx: KEM decapsulate failed for vin " << i);
    pqc_sign_data[i].output_index = static_cast<uint64_t>(output_in_tx);

    // Compute HKDF-correct dest key: ho + b_spend
    crypto::secret_key ho_key;
    memcpy(&ho_key, ho_buf, 32);
    crypto::secret_key dest_key;
    sc_add(reinterpret_cast<unsigned char*>(&dest_key),
           reinterpret_cast<const unsigned char*>(&ho_key),
           reinterpret_cast<const unsigned char*>(&from.get_keys().m_spend_secret_key));

    inSk[i].dest = rct::sk2rct(dest_key);
    memcpy(inSk[i].mask.bytes, z_buf, 32);
    inPk[i].dest = rct::pk2rct(out_key);
    inPk[i].mask = matched_src->rct ? matched_src->outputs[matched_src->real_output].second.mask
                                     : rct::zeroCommit(matched_src->amount);
    memcpy(y_keys[i].bytes, y_buf, 32);

    // Replace key image in vin with correct HKDF-derived one: (ho + b_spend) * Hp(O)
    crypto::key_image correct_ki;
    crypto::generate_key_image(out_key, dest_key, correct_ki);
    std::get<txin_to_key>(tx.vin[i]).k_image = correct_ki;

    memwipe(&ho_key, sizeof(ho_key));
    memwipe(&dest_key, sizeof(dest_key));
    memwipe(ho_buf, 32); memwipe(y_buf, 32);
    memwipe(z_buf, 32); memwipe(k_amount_buf, 32);

    // Assemble tree path for this output's global index
    uint64_t global_idx = matched_src->outputs[matched_src->real_output].first;
    LOG_PRINT_L1("construct_fcmp_tx: vin " << i
      << " global_idx=" << global_idx
      << " key_image=" << epee::string_tools::pod_to_hex(std::get<txin_to_key>(tx.vin[i]).k_image)
      << " h_pqc=" << epee::string_tools::pod_to_hex(pqc_pk_hashes[i]));
    CHECK_AND_ASSERT_MES(assemble_tree_path_for_output(db, global_idx, ref_leaf_count, tree_paths[i]), false,
      "construct_fcmp_tx: tree path assembly failed for global_idx " << global_idx);

    // Populate leaf chunk entries (Ed25519 points for every output in the same chunk)
    {
      const uint32_t SELENE_CHUNK = shekyl_curve_tree_selene_chunk_width();
      uint64_t chunk_start = (global_idx / SELENE_CHUNK) * SELENE_CHUNK;
      uint64_t chunk_end = std::min(chunk_start + static_cast<uint64_t>(SELENE_CHUNK), ref_leaf_count);

      for (uint64_t oi = chunk_start; oi < chunk_end; ++oi)
      {
        output_data_t od = db.get_output_key(0, oi, true);
        tx_out_index txi = db.get_output_tx_and_index(0, oi);
        transaction src_tx_for_chunk;
        CHECK_AND_ASSERT_MES(db.get_tx(txi.first, src_tx_for_chunk), false,
          "construct_fcmp_tx: cannot fetch tx for output " << oi);

        rct::fcmp_chunk_entry entry{};
        memcpy(entry.output_key.bytes, &od.pubkey, 32);

        ge_p3 hp;
        rct::hash_to_p3(hp, entry.output_key);
        ge_p3_tobytes(reinterpret_cast<unsigned char*>(entry.key_image_gen.bytes), &hp);

        entry.commitment = od.commitment;

        std::vector<tx_extra_field> chunk_extra_fields;
        parse_tx_extra(src_tx_for_chunk.extra, chunk_extra_fields);
        tx_extra_pqc_leaf_hashes chunk_lh;
        if (find_tx_extra_field_by_type(chunk_extra_fields, chunk_lh) &&
            chunk_lh.blob.size() >= (txi.second + 1) * PQC_LEAF_HASH_BYTES)
        {
          memcpy(entry.h_pqc.bytes, chunk_lh.blob.data() + txi.second * PQC_LEAF_HASH_BYTES, 32);
        }

        leaf_chunk_entries[i].push_back(entry);
      }
    }
  }

  // Key images were replaced with HKDF-correct values; invalidate cached hashes.
  tx.invalidate_hashes();

  // Gather output data for genRctFcmpPlusPlus
  std::vector<rct::xmr_amount> inamounts, outamounts;
  rct::keyV destinations_rct;
  for (size_t i = 0; i < num_inputs; ++i)
  {
    CHECK_AND_ASSERT_MES(matched_sources[i], false, "construct_fcmp_tx: missing matched source for vin " << i);
    inamounts.push_back(matched_sources[i]->amount);
  }
  for (const auto& out : tx.vout)
  {
    crypto::public_key out_pk;
    CHECK_AND_ASSERT_MES(get_output_public_key(out, out_pk), false, "Cannot extract output public key");
    destinations_rct.push_back(rct::pk2rct(out_pk));
  }

  // dests_copy reflects the shuffled order matching tx.vout after
  // construct_tx_and_get_tx_key. Use it for real output amounts (tx.vout
  // amounts are zeroed by RCT encoding) and for correct amount_key derivation.
  CHECK_AND_ASSERT_MES(dests_copy.size() == tx.vout.size(), false,
    "construct_fcmp_tx: dests_copy size mismatch with tx.vout");
  for (size_t i = 0; i < dests_copy.size(); ++i)
    outamounts.push_back(dests_copy[i].amount);

  CHECK_AND_ASSERT_MES(v3_commitment_masks.size() == destinations_rct.size(), false,
    "construct_fcmp_tx: v3_commitment_masks size mismatch — construction did not produce HKDF masks");
  auto saved_enc_amounts = tx.rct_signatures.enc_amounts;

  {
    uint64_t sum_in = 0, sum_out = 0;
    for (auto a : inamounts) sum_in += a;
    for (auto a : outamounts) sum_out += a;
    LOG_PRINT_L2("construct_fcmp_tx: sum_in=" << sum_in << " sum_out=" << sum_out
      << " fee=" << fee << " balance=" << (sum_in == sum_out + fee ? "OK" : "MISMATCH"));
  }

  crypto::hash tx_prefix_hash;
  get_transaction_prefix_hash(tx, tx_prefix_hash);

  rct::rctSig rv = rct::genRctFcmpPlusPlus(
    rct::hash2rct(tx_prefix_hash),
    inSk, inPk,
    destinations_rct, inamounts, outamounts,
    v3_commitment_masks, saved_enc_amounts,
    y_keys,
    fee, reference_block, curve_tree_root, tree_depth,
    tree_paths, leaf_chunk_entries, pqc_pk_hashes,
    hw::get_device("default"));
  tx.rct_signatures = rv;
  for (auto& m : v3_commitment_masks) memwipe(m.bytes, 32);

  // Phase C: PQC auth — two-phase: derive all public keys first so
  // get_transaction_signed_payload sees complete all_pqc_key_hashes,
  // then sign each input.
  tx.pqc_auths.resize(num_inputs);
  for (size_t i = 0; i < num_inputs; ++i)
  {
    tx.pqc_auths[i].auth_version = 1;
    tx.pqc_auths[i].scheme_id = 1;
    tx.pqc_auths[i].flags = 0;

    ShekylBuffer pk_buf = shekyl_derive_pqc_public_key(
        pqc_sign_data[i].combined_ss, pqc_sign_data[i].output_index);
    CHECK_AND_ASSERT_MES(pk_buf.ptr && pk_buf.len > 0, false,
      "construct_fcmp_tx: shekyl_derive_pqc_public_key failed for input " << i);
    tx.pqc_auths[i].hybrid_public_key.assign(pk_buf.ptr, pk_buf.ptr + pk_buf.len);
    shekyl_buffer_free(pk_buf.ptr, pk_buf.len);
  }

  for (size_t i = 0; i < num_inputs; ++i)
  {
    std::string payload_blob;
    CHECK_AND_ASSERT_MES(get_transaction_signed_payload(tx, i, payload_blob), false,
      "construct_fcmp_tx: get_transaction_signed_payload failed for input " << i);
    crypto::hash payload_hash;
    get_blob_hash(payload_blob, payload_hash);

    ShekylPqcAuthResult auth = shekyl_sign_pqc_auth(
      pqc_sign_data[i].combined_ss, pqc_sign_data[i].output_index,
      reinterpret_cast<const uint8_t*>(payload_hash.data), sizeof(payload_hash.data));
    CHECK_AND_ASSERT_MES(auth.success, false,
      "construct_fcmp_tx: shekyl_sign_pqc_auth failed for input " << i);

    tx.pqc_auths[i].hybrid_signature.assign(auth.signature.ptr,
      auth.signature.ptr + auth.signature.len);
    shekyl_pqc_auth_result_free(&auth);
  }

  tx.invalidate_hashes();
  return true;
}

bool construct_fcmp_tx(
    cryptonote::core& c,
    const cryptonote::account_base& from,
    const cryptonote::account_public_address& to,
    uint64_t amount,
    uint64_t fee,
    const std::vector<test_event_entry>& events,
    const cryptonote::block& blk_head,
    cryptonote::transaction& tx)
{
  vector<tx_source_entry> sources;
  vector<tx_destination_entry> destinations;
  fill_tx_sources_and_destinations(events, blk_head, from, to, amount, fee, 0, sources, destinations);

  if (sources.empty())
  {
    LOG_ERROR("construct_fcmp_tx: no sources found");
    return false;
  }

  crypto::secret_key tx_key;
  rct::keyV v3_commitment_masks;
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[from.get_keys().m_account_address.m_spend_public_key] = {0, 0};
  std::vector<tx_destination_entry> dests_copy = destinations;

  bool r = construct_tx_and_get_tx_key(
    from.get_keys(), subaddresses, sources, dests_copy,
    from.get_keys().m_account_address, std::vector<uint8_t>(),
    tx, tx_key, true, true, 1, &v3_commitment_masks);
  CHECK_AND_ASSERT_MES(r, false, "construct_fcmp_tx: construct_tx_and_get_tx_key failed");

  return apply_fcmp_pipeline(c, from, sources, dests_copy, v3_commitment_masks,
                             fee, events, blk_head, tx);
}

bool construct_fcmp_staked_tx(
    cryptonote::core& c,
    const cryptonote::account_base& from,
    const cryptonote::account_base& to,
    uint64_t amount,
    uint64_t fee,
    uint8_t tier,
    const std::vector<test_event_entry>& events,
    const cryptonote::block& blk_head,
    cryptonote::transaction& tx)
{
  std::vector<tx_source_entry> sources;
  if (!fill_tx_sources(sources, events, blk_head, from, amount + fee, 0))
  {
    LOG_ERROR("construct_fcmp_staked_tx: no sources found");
    return false;
  }

  std::vector<tx_destination_entry> destinations;
  tx_destination_entry staking_dest;
  staking_dest.amount = amount;
  staking_dest.addr = to.get_keys().m_account_address;
  staking_dest.is_subaddress = false;
  staking_dest.is_staking = true;
  staking_dest.stake_tier = tier;
  destinations.push_back(staking_dest);

  uint64_t sources_amount = 0;
  for (const auto& s : sources) sources_amount += s.amount;
  if (sources_amount > amount + fee)
  {
    tx_destination_entry change;
    change.amount = sources_amount - amount - fee;
    change.addr = from.get_keys().m_account_address;
    change.is_subaddress = false;
    destinations.push_back(change);
  }

  crypto::secret_key tx_key;
  rct::keyV v3_commitment_masks;
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[from.get_keys().m_account_address.m_spend_public_key] = {0, 0};
  std::vector<tx_destination_entry> dests_copy = destinations;

  bool r = construct_tx_and_get_tx_key(
    from.get_keys(), subaddresses, sources, dests_copy,
    from.get_keys().m_account_address, std::vector<uint8_t>(),
    tx, tx_key, true, true, 1, &v3_commitment_masks);
  CHECK_AND_ASSERT_MES(r, false, "construct_fcmp_staked_tx: construct_tx_and_get_tx_key failed");

  return apply_fcmp_pipeline(c, from, sources, dests_copy, v3_commitment_masks,
                             fee, events, blk_head, tx);
}

uint64_t get_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx) {
    uint64_t res = 0;
    std::map<uint64_t, std::vector<output_index> > outs;
    std::map<uint64_t, std::vector<size_t> > outs_mine;

    map_hash2tx_t confirmed_txs;
    get_confirmed_txs(blockchain, mtx, confirmed_txs);

    if (!init_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    for (const map_output_t::value_type &o : outs_mine) {
        for (size_t i = 0; i < o.second.size(); ++i) {
            if (outs[o.first][o.second[i]].spent)
                continue;

            res += outs[o.first][o.second[i]].amount;
        }
    }

    return res;
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
  return !bvc.m_verifivation_failed;
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
