// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// A real-nettype (TESTNET) Blockchain over a temporary LMDB at fixed
// difficulty 1: the production template, connect and prevalidation paths with
// no FAKECHAIN branch taken. Lifted from curve_tree_header_root_check.cpp
// (where its rationale lives) so every consensus check that must hold on a
// real nettype can drive it. Blockchain::init takes NO test_options (they
// would force FAKECHAIN); fixed_difficulty is an independent parameter.

#pragma once

#include <boost/filesystem.hpp>
#include <stdexcept>
#include <string>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"

namespace shekyl_test_fixtures
{
using namespace cryptonote;

struct TestnetChain
{
  boost::filesystem::path tmpdir;
  tx_memory_pool txpool;
  Blockchain bc;
  account_base miner;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
  TestnetChain(): txpool(bc), bc(txpool)
  {
    tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(tmpdir);
    try
    {
      BlockchainLMDB* db = new BlockchainLMDB();
      db->open(tmpdir.string());
      // TESTNET, offline, NO test_options (they would force FAKECHAIN), fixed
      // difficulty 1. Blockchain takes ownership of the DB.
      if (!bc.init(db, TESTNET, true, nullptr, 1))
        throw std::runtime_error("Blockchain::init failed on TESTNET over LMDB");
      miner.generate(crypto::secret_key{}, false, false, TESTNET);
    }
    catch (...)
    {
      // ~TestnetChain never runs for an object whose constructor threw, so the
      // temp directory would outlive the test run — one per failure, under the
      // system temp dir, invisible until something fills. Remove it here and
      // re-throw the original failure. The DB handle is deliberately not
      // deleted on this path: Blockchain::init may already have taken it, and
      // bc's destructor runs (it is a constructed member) into deinit, which
      // calls m_db->close() — so freeing the handle here would be a
      // use-after-free at that close, to reclaim one object in a test that is
      // failing anyway.
      boost::system::error_code ec;
      boost::filesystem::remove_all(tmpdir, ec);
      throw;
    }
  }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

  ~TestnetChain()
  {
    bc.deinit();
    boost::system::error_code ec;
    boost::filesystem::remove_all(tmpdir, ec);
  }

  // The production template: fills the header root from the current tree
  // root. At difficulty 1 the first nonce satisfies check_hash, so no search.
  bool make_template(block& b)
  {
    b = block{};
    difficulty_type diff = 0;
    uint64_t height = 0, reward = 0, seed_height = 0;
    crypto::hash seed_hash = crypto::null_hash;
    if (!bc.create_block_template(b, miner.get_keys().m_account_address, diff, height,
          reward, blobdata(), seed_height, seed_hash))
      return false;
    b.nonce = 0;
    return true;
  }

  // The production connect path. It writes inside a caller-held LMDB write
  // transaction, as core::handle_incoming_block and Blockchain::init's
  // genesis add both do.
  bool submit(const block& b, block_verification_context& bvc)
  {
    bvc = block_verification_context{};
    db_wtxn_guard wtxn(&bc.get_db());
    return bc.add_new_block(b, bvc);
  }

  bool mine_next(block_verification_context& bvc)
  {
    block b;
    return make_template(b) && submit(b, bvc);
  }
};

} // namespace shekyl_test_fixtures
