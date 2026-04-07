// Copyright (c) 2026, The Shekyl Project
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

// LMDB tx-data pruning tests intentionally do not link tests/core_tests/chaingen.cpp into
// unit_tests (avoids duplicate object code / linker unwind issues on e.g. macOS CI).

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>

#include "misc_language.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/hardfork.h"

using namespace cryptonote;

namespace {

struct TempLMDB {
  boost::filesystem::path tmpdir;
  BlockchainLMDB db;

  TempLMDB()
  {
    tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(tmpdir);
    db.open(tmpdir.string());
  }

  ~TempLMDB()
  {
    try {
      db.close();
      boost::filesystem::remove_all(tmpdir);
    } catch (...) {}
  }
};

void fill_test_nonce(block& blk, const difficulty_type& diffic, uint64_t height)
{
  const Blockchain* blockchain = nullptr;
  blk.nonce = 0;
  while (!miner::find_nonce_for_given_block(
      [blockchain](const block& b, uint64_t h, const crypto::hash* seed_hash, unsigned int threads, crypto::hash& hash) {
        return get_block_longhash(blockchain, b, hash, h, seed_hash, threads);
      },
      blk,
      diffic,
      height,
      NULL))
  {
    ++blk.timestamp;
  }
}

// Miner-only block (no tx_list), same structure as test_generator::construct_block without
// registering blocks in a test_generator.
bool construct_miner_only_block(
    block& blk,
    uint64_t height,
    const crypto::hash& prev_id,
    uint64_t timestamp,
    uint64_t already_generated_coins,
    account_base& miner_acc,
    std::vector<size_t>& block_weights,
    uint8_t hf_version)
{
  blk.major_version = hf_version;
  blk.minor_version = hf_version;
  blk.timestamp = timestamp;
  blk.prev_id = prev_id;
  blk.curve_tree_root = crypto::null_hash;
  blk.tx_hashes.clear();

  const uint64_t total_fee = 0;
  const size_t txs_weight = 0;

  blk.miner_tx = transaction{};
  size_t target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  while (true)
  {
    if (!construct_miner_tx(height,
            epee::misc_utils::median(block_weights),
            already_generated_coins,
            target_block_weight,
            total_fee,
            miner_acc.get_keys().m_account_address,
            blk.miner_tx,
            blobdata(),
            10,
            hf_version,
            /*tx_volume_avg=*/0,
            /*circulating_supply=*/already_generated_coins,
            /*stake_ratio=*/0,
            /*genesis_ng_height=*/0))
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
        break;
      delta = actual_block_weight - target_block_weight;
      blk.miner_tx.extra.resize(blk.miner_tx.extra.size() - delta);
      actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
      if (actual_block_weight == target_block_weight)
        break;
      blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
      target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
    }
    else
    {
      break;
    }
  }

  const difficulty_type diffic = (hf_version <= 1) ? difficulty_type(1) : difficulty_type(2);
  fill_test_nonce(blk, diffic, height);
  block_weights.push_back(txs_weight + get_transaction_weight(blk.miner_tx));
  return true;
}

bool build_two_miner_only_blocks(account_base& miner, block& b0, block& b1)
{
  std::vector<size_t> block_weights;
  if (!construct_miner_only_block(b0, 0, crypto::null_hash, 1500000000, 0, miner, block_weights, 1))
    return false;
  const uint64_t after0 = get_outs_money_amount(b0.miner_tx);
  return construct_miner_only_block(b1, 1, get_block_hash(b0), 1500000001, after0, miner, block_weights, 1);
}

} // namespace

TEST(tx_data_pruning_lmdb, empty_chain_prune_is_noop)
{
  TempLMDB env;
  BlockchainDB& db = env.db;
  ASSERT_EQ(db.height(), 0u);
  ASSERT_TRUE(db.prune_tx_data(1));
  ASSERT_EQ(db.get_last_pruned_tx_data_height(), 0u);
}

TEST(tx_data_pruning_lmdb, prune_clears_verification_data_and_is_idempotent)
{
  account_base miner;
  miner.generate();
  block b0{}, b1{};
  ASSERT_TRUE(build_two_miner_only_blocks(miner, b0, b1));

  TempLMDB env;
  BlockchainDB& db = env.db;
  HardFork hf(db, 1, 0);
  hf.init();
  db.set_hard_fork(&hf);

  const size_t w0 = get_transaction_weight(b0.miner_tx);
  const size_t w1 = get_transaction_weight(b1.miner_tx);
  const difficulty_type cum0 = 1;
  const difficulty_type cum1 = 2;
  const uint64_t coins0 = get_outs_money_amount(b0.miner_tx);
  const uint64_t coins1 = coins0 + get_outs_money_amount(b1.miner_tx);

  {
    db_wtxn_guard w(&db);
    db.add_block(std::make_pair(b0, block_to_blob(b0)), w0, w0, cum0, coins0, {});
    db.add_block(std::make_pair(b1, block_to_blob(b1)), w1, w1, cum1, coins1, {});
  }

  ASSERT_EQ(db.height(), 2u);

  const crypto::hash miner_txh = get_transaction_hash(db.get_block_from_height(0).miner_tx);
  ASSERT_TRUE(db.tx_has_verification_data(miner_txh));

  ASSERT_TRUE(db.prune_tx_data(1));
  ASSERT_FALSE(db.tx_has_verification_data(miner_txh));
  ASSERT_EQ(db.get_last_pruned_tx_data_height(), 0u);

  ASSERT_TRUE(db.prune_tx_data(1));
  ASSERT_FALSE(db.tx_has_verification_data(miner_txh));
  ASSERT_EQ(db.get_last_pruned_tx_data_height(), 0u);
}
