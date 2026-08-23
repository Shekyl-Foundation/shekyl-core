// Copyright (c) 2026, The Shekyl Foundation
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

// The RK-2 facts shim's real logic, against a controlled chain
// (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.2).
//
// `shekyl_rpc_block_hash_at` unwraps a handle and delegates to
// `daemon_rpc_facts::block_hash_at(Blockchain&, ...)`, the same split
// `daemon_submit_ffi` uses, so the part with the decisions — the bound, the
// hash lookup, the `found` mapping and the inconsistent-store branch — is
// driven here against a real `Blockchain` over a test DB, rather than only
// through a live daemon. The layout twins live in
// rpc_facts_ffi_roundtrip.cpp; they check the struct, not the behaviour.

#include <gtest/gtest.h>

#include <cstring>
#include <limits>

#include "blockchain_db/testdb.h"
#include "cryptonote_core/blockchain.h"
// cryptonote_core.h defines cryptonote::test_options (blockchain.h only
// forward-declares it), needed by init_blockchain's fakechain options.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "rpc/rpc_facts_ffi.h"

using namespace cryptonote;

namespace
{
  // A block hash that is a function of its height, so a test can tell "the
  // hash of the block you asked for" from "some hash".
  crypto::hash hash_at(uint64_t height)
  {
    crypto::hash h = crypto::null_hash;
    for (size_t i = 0; i < 8; ++i)
      h.data[i] = static_cast<char>((height >> (i * 8)) & 0xff);
    h.data[8] = 0x5a; // never all-zero, so it cannot be confused with null_hash
    return h;
  }

  // Chain of `m_height` blocks. `m_missing` (when set) is an in-range height
  // the store cannot produce a block for — what an unwound or degraded chain
  // looks like from `Blockchain::get_block_id_by_height`, which swallows
  // BLOCK_DNE and answers a null hash.
  class FactsTestDB : public BaseTestDB
  {
  public:
    explicit FactsTestDB(uint64_t height) : m_height(height) { m_open = true; }

    void set_missing(uint64_t height) { m_missing = height; }

    uint64_t height() const override { return m_height; }

    crypto::hash get_block_hash_from_height(const uint64_t& height) const override
    {
      if (height >= m_height || height == m_missing)
        throw BLOCK_DNE("no block at that height");
      return hash_at(height);
    }

    crypto::hash top_block_hash(uint64_t* block_height = nullptr) const override
    {
      const uint64_t top = m_height ? m_height - 1 : 0;
      if (block_height)
        *block_height = top;
      return m_height ? hash_at(top) : crypto::null_hash;
    }

    bool block_exists(const crypto::hash& h, uint64_t* height) const override
    {
      for (uint64_t i = 0; i < m_height; ++i)
      {
        if (hash_at(i) == h)
        {
          if (height)
            *height = i;
          return true;
        }
      }
      return false;
    }

  private:
    uint64_t m_height;
    uint64_t m_missing = std::numeric_limits<uint64_t>::max();
  };

  // Blockchain and its pool refer to each other; construct in this order, as
  // daemon_submit_shims.cpp does.
  struct BlockchainAndPool
  {
    tx_memory_pool txpool;
    Blockchain bc;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
    BlockchainAndPool() : txpool(bc), bc(txpool) {}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
  };

  bool init_blockchain(Blockchain& bc, BlockchainDB* db)
  {
    const std::pair<uint8_t, uint64_t> hard_forks[] = {
      std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
      std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
    };
    const cryptonote::test_options test_options = {hard_forks, 5000};
    return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 1, nullptr);
  }

  constexpr uint64_t CHAIN_HEIGHT = 7;

  bool is_zeroed(const shekyl_rpc_block_hash_facts& facts)
  {
    for (const uint8_t byte : facts.hash)
    {
      if (byte)
        return false;
    }
    return true;
  }
}

// Every in-range height answers with *that* height's hash — not the tip's,
// not a constant — and reports the chain height alongside it.
TEST(rpc_facts_shims, in_range_heights_answer_their_own_block)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  for (uint64_t h = 0; h < CHAIN_HEIGHT; ++h)
  {
    shekyl_rpc_block_hash_facts facts{};
    ASSERT_EQ(SHEKYL_RPC_FACTS_OK, daemon_rpc_facts::block_hash_at(bap.bc, h, &facts))
      << "height " << h;
    EXPECT_EQ(1, facts.found) << "height " << h;
    EXPECT_EQ(CHAIN_HEIGHT, facts.chain_height);
    const crypto::hash expected = hash_at(h);
    EXPECT_EQ(0, std::memcmp(facts.hash, expected.data, sizeof(facts.hash))) << "height " << h;
  }
}

// The bound is `height < chain_height`: the tip's own height is one past the
// last block and is refused, which is what makes the wire's "greater than
// current top block height" message true.
TEST(rpc_facts_shims, tip_height_and_beyond_are_absent_not_found)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  for (const uint64_t h : {CHAIN_HEIGHT, CHAIN_HEIGHT + 1, CHAIN_HEIGHT + 1000})
  {
    shekyl_rpc_block_hash_facts facts{};
    ASSERT_EQ(SHEKYL_RPC_FACTS_OK, daemon_rpc_facts::block_hash_at(bap.bc, h, &facts))
      << "height " << h;
    EXPECT_EQ(0, facts.found) << "height " << h;
    EXPECT_EQ(CHAIN_HEIGHT, facts.chain_height) << "height " << h;
    EXPECT_TRUE(is_zeroed(facts)) << "an absent block carries no hash";
  }
}

// A store that reports a height it cannot produce the block for is a fault of
// this daemon, not an answer about the request: it must not come back as
// `found == 0` (which the handler would render as "greater than the tip" for
// a height that is below it) and must not come back as a zero hash.
TEST(rpc_facts_shims, in_range_height_the_store_cannot_produce_is_inconsistent)
{
  BlockchainAndPool bap;
  auto* db = new FactsTestDB(CHAIN_HEIGHT);
  db->set_missing(3);
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  shekyl_rpc_block_hash_facts facts{};
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_INCONSISTENT,
    daemon_rpc_facts::block_hash_at(bap.bc, 3, &facts));
  EXPECT_EQ(0, facts.found);
  EXPECT_TRUE(is_zeroed(facts));

  // Its neighbours still answer: the fault is about one height, not the chain.
  shekyl_rpc_block_hash_facts ok{};
  EXPECT_EQ(SHEKYL_RPC_FACTS_OK, daemon_rpc_facts::block_hash_at(bap.bc, 2, &ok));
  EXPECT_EQ(1, ok.found);
}

TEST(rpc_facts_shims, null_out_pointer_refuses)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL, daemon_rpc_facts::block_hash_at(bap.bc, 0, nullptr));
}
