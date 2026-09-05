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

// CEN-B5 regression: the header's curve_tree_root must equal the root the
// block was built on -- the tree state at the block's own height, after its
// parent connected and before its own drain (CEN-I12, census section 7 #16).
//
// Why this runs on TESTNET and not FAKECHAIN: the defect it guards was hidden
// by a nettype-gated skip of the very check under test (rule 71). Every other
// Blockchain-level test and every `--regtest` daemon run as FAKECHAIN, where
// the check never executed, so this fixture was the first to exercise it. The
// skip is gone (the same PR retired it; the test generator now computes real
// roots), so FAKECHAIN fixtures exercise the check too -- this one stays the
// non-FAKECHAIN witness that a real-nettype chain, template to connect,
// crosses the first maturity boundary. With the nettype branches gone from the
// consensus path a TESTNET chain exercising the check is evidence about
// MAINNET's check -- that is rule 71's payoff, and it is why this test must
// not be moved onto MAINNET nor dismissed as testnet-only.
//
// Why fixed difficulty 1 is not a weakening: difficulty 1 is the locus where
// CEN-D2's fail-open sentinel was found and fixed (PR #604), whose own
// regressions run at difficulty 1 for that reason; this fixture inherits that
// proof. `fixed_difficulty` is an independent Blockchain::init parameter,
// uncoupled from `test_options` (which would force FAKECHAIN) and from nettype.
//
// Cost: sixty-one RandomX light-cache hashes plus one cache derivation. It
// runs in the always-on suite by design; a guard against a mainnet halt that
// is opted out of is no guard.

#include "gtest/gtest.h"

#include <array>
#include <boost/filesystem.hpp>
#include <cstring>
#include <stdexcept>
#include <string>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"

using namespace cryptonote;

namespace
{

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
    BlockchainLMDB* db = new BlockchainLMDB();
    db->open(tmpdir.string());
    // TESTNET, offline, NO test_options (they would force FAKECHAIN), fixed
    // difficulty 1. Blockchain takes ownership of the DB.
    if (!bc.init(db, TESTNET, true, nullptr, 1))
      throw std::runtime_error("Blockchain::init failed on TESTNET over LMDB");
    miner.generate(crypto::secret_key{}, false, false, TESTNET);
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

  // One block through the production template and connect paths. The
  // template fills the header root from the current tree root; at difficulty
  // 1 the first nonce satisfies check_hash, so no search is needed.
  bool mine_next(block_verification_context& bvc)
  {
    block b{};
    difficulty_type diff = 0;
    uint64_t height = 0, reward = 0, seed_height = 0;
    crypto::hash seed_hash = crypto::null_hash;
    if (!bc.create_block_template(b, miner.get_keys().m_account_address, diff, height,
          reward, blobdata(), seed_height, seed_hash))
      return false;
    b.nonce = 0;
    bvc = block_verification_context{};
    // The connect path writes inside a caller-held LMDB write transaction, as
    // core::handle_incoming_block and Blockchain::init's genesis add both do.
    db_wtxn_guard wtxn(&bc.get_db());
    return bc.add_new_block(b, bvc);
  }
};

} // namespace

TEST(curve_tree_header_root_check, testnet_chain_connects_through_the_first_maturing_block)
{
  TestnetChain chain;
  const BlockchainDB& db = chain.bc.get_db();
  ASSERT_EQ(chain.bc.get_current_blockchain_height(), 1u) << "genesis only";
  ASSERT_EQ(db.get_curve_tree_leaf_count(), 0u);

  // The genesis coinbase outputs carry stored maturity (0 + 1) + 60 and drain
  // when the block at index 60 connects (current_height 61): the first block
  // whose add moves the tree, and therefore the first block where a check
  // comparing the header against the POST-add root can disagree with a
  // header the template filled from the PRE-add root.
  const uint64_t first_maturing_block = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  block_verification_context bvc{};
  for (uint64_t h = 1; h < first_maturing_block; ++h)
  {
    ASSERT_TRUE(chain.mine_next(bvc)) << "block " << h << " rejected";
    ASSERT_FALSE(bvc.m_verifivation_failed) << "block " << h;
  }
  ASSERT_EQ(chain.bc.get_current_blockchain_height(), first_maturing_block);
  ASSERT_EQ(db.get_curve_tree_leaf_count(), 0u) << "nothing matures before block 60";

  // The block under test. Its header was filled from the root at chain height
  // 60 (the state after block 59 connected). A conformant check accepts it.
  ASSERT_TRUE(chain.mine_next(bvc))
    << "block " << first_maturing_block << " rejected: the header-root check "
       "compared the post-drain root against a header filled from the pre-drain root";
  ASSERT_FALSE(bvc.m_verifivation_failed);
  ASSERT_EQ(chain.bc.get_current_blockchain_height(), first_maturing_block + 1);
  EXPECT_GT(db.get_curve_tree_leaf_count(), 0u) << "the genesis coinbase drained at block 60";

  // Both witnesses name the state at chain height 60: the header of block 60
  // equals the per-height record under key 60.
  const block b60 = db.get_block_from_height(first_maturing_block);
  const std::array<uint8_t, 32> record = db.get_curve_tree_root_at_height(first_maturing_block);
  EXPECT_EQ(0, memcmp(&b60.curve_tree_root, record.data(), record.size()))
    << "header witness and per-height record disagree at height 60";

  // The chain keeps going past the boundary.
  ASSERT_TRUE(chain.mine_next(bvc)) << "block after the boundary rejected";
  ASSERT_EQ(chain.bc.get_current_blockchain_height(), first_maturing_block + 2);
}
