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

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>

#include "../core_tests/chaingen.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
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

bool build_two_block_chain(test_generator& gen, account_base& miner, block& b0, block& b1)
{
  if (!gen.construct_block(b0, miner, 1500000000))
    return false;
  return gen.construct_block(b1, b0, miner, std::list<transaction>{}, std::nullopt);
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

TEST(tx_data_pruning_lmdb, prune_removes_verification_blobs_and_is_idempotent)
{
  test_generator gen;
  account_base miner;
  miner.generate();
  block b0{}, b1{};
  ASSERT_TRUE(build_two_block_chain(gen, miner, b0, b1));

  TempLMDB env;
  BlockchainDB& db = env.db;
  HardFork hf(db, 1, 0);
  hf.init();
  db.set_hard_fork(&hf);

  const size_t w0 = get_transaction_weight(b0.miner_tx);
  const size_t w1 = get_transaction_weight(b1.miner_tx);
  const difficulty_type cum0 = 1;
  const difficulty_type cum1 = 2;
  const uint64_t coins0 = gen.get_already_generated_coins(b0);
  const uint64_t coins1 = gen.get_already_generated_coins(b1);

  {
    db_wtxn_guard w(&db);
    db.add_block(std::make_pair(b0, block_to_blob(b0)), w0, w0, cum0, coins0, {});
    db.add_block(std::make_pair(b1, block_to_blob(b1)), w1, w1, cum1, coins1, {});
  }

  ASSERT_EQ(db.height(), 2u);

  const crypto::hash miner_txh = get_transaction_hash(db.get_block_from_height(0).miner_tx);
  cryptonote::blobdata prunable_before;
  ASSERT_TRUE(db.get_prunable_tx_blob(miner_txh, prunable_before));
  ASSERT_FALSE(prunable_before.empty());
  ASSERT_TRUE(db.tx_has_verification_data(miner_txh));

  ASSERT_TRUE(db.prune_tx_data(1));
  ASSERT_FALSE(db.tx_has_verification_data(miner_txh));
  cryptonote::blobdata prunable_after;
  ASSERT_FALSE(db.get_prunable_tx_blob(miner_txh, prunable_after));
  ASSERT_EQ(db.get_last_pruned_tx_data_height(), 0u);

  ASSERT_TRUE(db.prune_tx_data(1));
  ASSERT_FALSE(db.tx_has_verification_data(miner_txh));
  ASSERT_EQ(db.get_last_pruned_tx_data_height(), 0u);
}

TEST(tx_data_pruning_lmdb, pop_block_fails_when_tip_has_pruned_tx_data)
{
  test_generator gen;
  account_base miner;
  miner.generate();
  block b0{}, b1{};
  ASSERT_TRUE(build_two_block_chain(gen, miner, b0, b1));

  TempLMDB env;
  BlockchainDB& db = env.db;
  HardFork hf(db, 1, 0);
  hf.init();
  db.set_hard_fork(&hf);

  const size_t w0 = get_transaction_weight(b0.miner_tx);
  const size_t w1 = get_transaction_weight(b1.miner_tx);
  const difficulty_type cum0 = 1;
  const difficulty_type cum1 = 2;
  const uint64_t coins0 = gen.get_already_generated_coins(b0);
  const uint64_t coins1 = gen.get_already_generated_coins(b1);

  {
    db_wtxn_guard w(&db);
    db.add_block(std::make_pair(b0, block_to_blob(b0)), w0, w0, cum0, coins0, {});
    db.add_block(std::make_pair(b1, block_to_blob(b1)), w1, w1, cum1, coins1, {});
  }

  ASSERT_TRUE(db.prune_tx_data(1));

  block popped{};
  std::vector<transaction> popped_txs;
  ASSERT_NO_THROW(db.pop_block(popped, popped_txs));
  ASSERT_EQ(db.height(), 1u);

  ASSERT_THROW(db.pop_block(popped, popped_txs), DB_ERROR);
}
