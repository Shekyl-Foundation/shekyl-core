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

#include <array>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <cstdio>
#include <iostream>
#include <chrono>
#include <thread>

#include "gtest/gtest.h"

#include "string_tools.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

#define ASSERT_HASH_EQ(a,b) ASSERT_EQ(pod_to_hex(a), pod_to_hex(b))

namespace {  // anonymous namespace

const std::vector<difficulty_type> t_diffs =
  {
    4003674
  , 4051757
  };

const std::vector<uint64_t> t_coins =
  {
    1952630229575370
  , 1970220553446486
  };

// if the return type (blobdata for now) of block_to_blob ever changes
// from std::string, this might break.
bool compare_blocks(const block& a, const block& b)
{
  auto hash_a = pod_to_hex(get_block_hash(a));
  auto hash_b = pod_to_hex(get_block_hash(b));

  return hash_a == hash_b;
}

/*
void print_block(const block& blk, const std::string& prefix = "")
{
  std::cerr << prefix << ": " << std::endl
            << "\thash - " << pod_to_hex(get_block_hash(blk)) << std::endl
            << "\tparent - " << pod_to_hex(blk.prev_id) << std::endl
            << "\ttimestamp - " << blk.timestamp << std::endl
  ;
}

// if the return type (blobdata for now) of tx_to_blob ever changes
// from std::string, this might break.
bool compare_txs(const transaction& a, const transaction& b)
{
  auto ab = tx_to_blob(a);
  auto bb = tx_to_blob(b);

  return ab == bb;
}
*/

template <typename T>
class BlockchainDBTest : public testing::Test
{
protected:
  BlockchainDBTest() : m_db(new T()), m_hardfork(*m_db, 1, 0)
  {
    account_base miner_acc;
    miner_acc.generate();

    auto make_block = [&](const crypto::hash& prev_id) -> std::pair<block, blobdata> {
      block bl;
      bl.major_version = 1;
      bl.minor_version = 0;
      bl.timestamp = 1500000000;
      bl.prev_id = prev_id;
      bl.nonce = 12345;
      bl.curve_tree_root = crypto::null_hash;
      if (!construct_miner_tx(0, 0, 0, 500, 0, miner_acc.get_keys().m_account_address, bl.miner_tx))
        throw std::runtime_error("BlockchainDBTest: construct_miner_tx failed");
      bl.miner_tx.invalidate_hashes();
      blobdata bd;
      if (!block_to_blob(bl, bd))
        throw std::runtime_error("BlockchainDBTest: block_to_blob failed");
      return std::make_pair(bl, bd);
    };

    m_blocks.push_back(make_block(crypto::null_hash));
    const crypto::hash h0 = get_block_hash(m_blocks[0].first);
    m_blocks.push_back(make_block(h0));

    m_block_weights[0] = m_blocks[0].second.size();
    m_block_weights[1] = m_blocks[1].second.size();

    m_txs.resize(2);
  }

  ~BlockchainDBTest() {
    delete m_db;
    remove_files();
  }

  BlockchainDB* m_db;
  HardFork m_hardfork;
  std::string m_prefix;
  std::vector<std::pair<block, blobdata>> m_blocks;
  std::array<size_t, 2> m_block_weights{};
  std::vector<std::vector<std::pair<transaction, blobdata>>> m_txs;
  std::vector<std::string> m_filenames;

  void init_hard_fork()
  {
    m_hardfork.init();
    m_db->set_hard_fork(&m_hardfork);
  }

  void get_filenames()
  {
    m_filenames = m_db->get_filenames();
    for (auto& f : m_filenames)
    {
      std::cerr << "File created by test: " << f << std::endl;
    }
  }

  void remove_files()
  {
    // remove each file the db created, making sure it starts with fname.
    for (auto& f : m_filenames)
    {
      if (boost::starts_with(f, m_prefix))
      {
        boost::filesystem::remove(f);
      }
      else
      {
        std::cerr << "File created by test not to be removed (for safety): " << f << std::endl;
      }
    }

    // remove directory if it still exists
    boost::filesystem::remove_all(m_prefix);
  }

  void set_prefix(const std::string& prefix)
  {
    m_prefix = prefix;
  }
};

using testing::Types;

typedef Types<BlockchainLMDB> implementations;

TYPED_TEST_CASE(BlockchainDBTest, implementations);

TYPED_TEST(BlockchainDBTest, OpenAndClose)
{
  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();

  // make sure open when already open DOES throw
  ASSERT_THROW(this->m_db->open(dirPath), DB_OPEN_FAILURE);

  ASSERT_NO_THROW(this->m_db->close());
}

TYPED_TEST(BlockchainDBTest, AddBlock)
{

  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();
  this->init_hard_fork();

  db_wtxn_guard guard(this->m_db);

  // adding a block with no parent in the blockchain should throw.
  // note: this shouldn't be possible, but is a good (and cheap) failsafe.
  //
  // TODO: need at least one more block to make this reasonable, as the
  // BlockchainDB implementation should not check for parent if
  // no blocks have been added yet (because genesis has no parent).
  //ASSERT_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]), BLOCK_PARENT_DNE);

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[0], this->m_block_weights[0], this->m_block_weights[0], t_diffs[0], t_coins[0], this->m_txs[0]));
  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[1], this->m_block_weights[1], this->m_block_weights[1], t_diffs[1], t_coins[1], this->m_txs[1]));

  block b;
  ASSERT_TRUE(this->m_db->block_exists(get_block_hash(this->m_blocks[0].first)));
  ASSERT_NO_THROW(b = this->m_db->get_block(get_block_hash(this->m_blocks[0].first)));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

  ASSERT_NO_THROW(b = this->m_db->get_block_from_height(0));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

  // assert that we can't add the same block twice
  ASSERT_THROW(this->m_db->add_block(this->m_blocks[0], this->m_block_weights[0], this->m_block_weights[0], t_diffs[0], t_coins[0], this->m_txs[0]), TX_EXISTS);

  for (auto& h : this->m_blocks[0].first.tx_hashes)
  {
    transaction tx;
    ASSERT_TRUE(this->m_db->tx_exists(h));
    ASSERT_NO_THROW(tx = this->m_db->get_tx(h));

    ASSERT_HASH_EQ(h, get_transaction_hash(tx));
  }
}

TYPED_TEST(BlockchainDBTest, RetrieveBlockData)
{
  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();
  this->init_hard_fork();

  db_wtxn_guard guard(this->m_db);

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[0], this->m_block_weights[0], this->m_block_weights[0],  t_diffs[0], t_coins[0], this->m_txs[0]));

  ASSERT_EQ(this->m_block_weights[0], this->m_db->get_block_weight(0));
  ASSERT_EQ(t_diffs[0], this->m_db->get_block_cumulative_difficulty(0));
  ASSERT_EQ(t_diffs[0], this->m_db->get_block_difficulty(0));
  ASSERT_EQ(t_coins[0], this->m_db->get_block_already_generated_coins(0));

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[1], this->m_block_weights[1], this->m_block_weights[1], t_diffs[1], t_coins[1], this->m_txs[1]));
  ASSERT_EQ(t_diffs[1] - t_diffs[0], this->m_db->get_block_difficulty(1));

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), this->m_db->get_block_hash_from_height(0));

  std::vector<block> blks;
  ASSERT_NO_THROW(blks = this->m_db->get_blocks_range(0, 1));
  ASSERT_EQ(2, blks.size());
  
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), get_block_hash(blks[0]));
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1].first), get_block_hash(blks[1]));

  std::vector<crypto::hash> hashes;
  ASSERT_NO_THROW(hashes = this->m_db->get_hashes_range(0, 1));
  ASSERT_EQ(2, hashes.size());

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), hashes[0]);
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1].first), hashes[1]);
}

}  // anonymous namespace
