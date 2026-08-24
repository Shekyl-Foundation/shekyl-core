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
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
// cryptonote_core.h defines cryptonote::test_options (blockchain.h only
// forward-declares it), needed by init_blockchain's fakechain options.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/tx_pool.h"
#include "rpc/rpc_facts_ffi.h"
#include "shekyl/shekyl_ffi.h"

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

  // The block this fake chain holds at `height`: every field the header
  // projection reads, derived from the height so the test can predict it.
  cryptonote::block block_at(uint64_t height)
  {
    cryptonote::block blk{};
    blk.major_version = 1;
    blk.minor_version = 2;
    blk.timestamp = 1500000000 + height;
    blk.prev_id = height ? hash_at(height - 1) : crypto::null_hash;
    blk.nonce = static_cast<uint32_t>(height * 7 + 1);
    blk.curve_tree_root = hash_at(height + 1000);
    blk.attestation_root = hash_at(height + 2000);

    cryptonote::transaction miner_tx{};
    miner_tx.version = 1;
    miner_tx.unlock_time = height + 60;
    cryptonote::txin_gen gen{};
    gen.height = height;
    miner_tx.vin.push_back(gen);
    cryptonote::tx_out out{};
    out.amount = 600000000000 + height;
    miner_tx.vout.push_back(out);
    blk.miner_tx = std::move(miner_tx);

    // Two transactions, so `num_txes` is not trivially zero.
    blk.tx_hashes.push_back(hash_at(height + 3000));
    blk.tx_hashes.push_back(hash_at(height + 4000));
    return blk;
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

    // An in-range block whose coinbase is not a single `txin_gen` — the
    // shape `block_at` refuses as a broken block rather than a missing one.
    void set_bad_coinbase(uint64_t height) { m_bad_coinbase = height; }

    // A block off the main chain, reached only by hash. `Blockchain::
    // get_block_by_hash` falls through to `get_alt_block` when the main-chain
    // lookup throws BLOCK_DNE, and sets `orphan` when it hits.
    void set_alt_block(const cryptonote::block& blk) { m_alt = blk; m_has_alt = true; }
    crypto::hash alt_hash() const { return cryptonote::get_block_hash(m_alt); }

    bool get_alt_block(const crypto::hash& blkid, cryptonote::alt_block_data_t* data,
      cryptonote::blobdata* blob) override
    {
      if (!m_has_alt || blkid != cryptonote::get_block_hash(m_alt))
        return false;
      if (data)
        *data = cryptonote::alt_block_data_t{};
      if (blob)
        *blob = cryptonote::t_serializable_object_to_blob(m_alt);
      return true;
    }

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

    // `Blockchain::get_block_by_hash` reaches the store through
    // `BlockchainDB::get_block` -> `get_block_blob`.
    cryptonote::blobdata get_block_blob(const crypto::hash& h) const override
    {
      for (uint64_t i = 0; i < m_height; ++i)
      {
        if (i != m_missing && hash_at(i) == h)
        {
          cryptonote::block blk = block_at(i);
          if (i == m_bad_coinbase)
            blk.miner_tx.vin.clear();
          return cryptonote::t_serializable_object_to_blob(blk);
        }
      }
      throw BLOCK_DNE("no block with that hash");
    }

    size_t get_block_weight(const uint64_t& height) const override { return 1000 + height; }
    uint64_t get_block_long_term_weight(const uint64_t& height) const override
    {
      return 2000 + height;
    }
    // A difficulty above 2^64, so the projection's 128-bit split is exercised
    // through the real path rather than only in the Rust unit test.
    cryptonote::difficulty_type get_block_difficulty(const uint64_t& height) const override
    {
      cryptonote::difficulty_type d = 1;
      d <<= 70;
      return d + height;
    }
    cryptonote::difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const override
    {
      cryptonote::difficulty_type d = 1;
      d <<= 71;
      return d + height;
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
    uint64_t m_bad_coinbase = std::numeric_limits<uint64_t>::max();
    cryptonote::block m_alt{};
    bool m_has_alt = false;
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

// The header projection carries what the block and the store say, at the
// height asked for — the fields the wire's `block_header_response` renders.
TEST(rpc_facts_shims, header_projection_reads_the_block_at_that_height)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  const uint64_t height = 4;
  shekyl_rpc_block_header_facts f{};
  ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_header_at(bap.bc, height, /*fill_pow_hash=*/false, &f));

  const cryptonote::block expected = block_at(height);
  EXPECT_EQ(1, f.found);
  EXPECT_EQ(height, f.height);
  EXPECT_EQ(CHAIN_HEIGHT, f.chain_height);
  EXPECT_EQ(CHAIN_HEIGHT - height - 1, f.depth);
  EXPECT_EQ(expected.timestamp, f.timestamp);
  EXPECT_EQ(expected.nonce, f.nonce);
  EXPECT_EQ(expected.major_version, f.major_version);
  EXPECT_EQ(expected.minor_version, f.minor_version);
  EXPECT_EQ(expected.tx_hashes.size(), f.num_txes);
  EXPECT_EQ(0, f.orphan_status);
  EXPECT_EQ(expected.miner_tx.vout[0].amount, f.reward);
  EXPECT_EQ(1000u + height, f.block_weight);
  EXPECT_EQ(2000u + height, f.long_term_weight);

  // The 128-bit values arrive split, not truncated.
  EXPECT_EQ(height, f.difficulty_lo);
  EXPECT_EQ(64u, f.difficulty_hi);          // 2^70 >> 64
  EXPECT_EQ(height, f.cumulative_difficulty_lo);
  EXPECT_EQ(128u, f.cumulative_difficulty_hi); // 2^71 >> 64

  const crypto::hash id = hash_at(height);
  EXPECT_EQ(0, std::memcmp(f.hash, id.data, sizeof(f.hash)));
  EXPECT_EQ(0, std::memcmp(f.prev_hash, expected.prev_id.data, sizeof(f.prev_hash)));
  const crypto::hash miner = cryptonote::get_transaction_hash(expected.miner_tx);
  EXPECT_EQ(0, std::memcmp(f.miner_tx_hash, miner.data, sizeof(f.miner_tx_hash)));
  EXPECT_EQ(0, std::memcmp(f.curve_tree_root, expected.curve_tree_root.data,
    sizeof(f.curve_tree_root)));
  EXPECT_EQ(0, std::memcmp(f.attestation_root, expected.attestation_root.data,
    sizeof(f.attestation_root)));

  // Not asked for, so not computed and not reported.
  EXPECT_EQ(0, f.pow_hash_filled);
  shekyl_rpc_block_hash_facts zero{};
  EXPECT_EQ(0, std::memcmp(f.pow_hash, zero.hash, sizeof(f.pow_hash)));
}

// The only automated exercise of the real `fill_pow_hash` branch: the Rust
// tests stop at `FakeFacts`, so without this nothing in CI ever calls
// `get_block_longhash` through this export at all.
//
// It pins WHICH seed the projection uses — the block id at
// `shekyl_pow_randomx_v2_seedheight(height)` — by recomputing the hash from
// that seed explicitly and requiring the same answer. Changing the seed
// height, or sourcing the seed from somewhere else, turns this red.
//
// What it deliberately does NOT claim: that the seed is read *inside* the
// projection's lock. Single-threaded, an implicit seed resolved after the
// unlock yields the identical value, so no assertion here can separate the
// two. That property is structural — it is why the seed is read in the
// locked scope and passed explicitly — and the comment at the call site is
// its record.
TEST(rpc_facts_shims, header_pow_hash_is_computed_from_the_seed_at_its_seed_height)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  const uint64_t height = 4;
  shekyl_rpc_block_header_facts f{};
  ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_header_at(bap.bc, height, /*fill_pow_hash=*/true, &f));

  ASSERT_EQ(1, f.found);
  EXPECT_EQ(1, f.pow_hash_filled);
  const shekyl_rpc_block_header_facts zero{};
  EXPECT_NE(0, std::memcmp(f.pow_hash, zero.pow_hash, sizeof(f.pow_hash)))
    << "a filled pow hash is not 32 zero bytes";

  // The same block, hashed against the seed this height is supposed to use.
  const crypto::hash seed =
    bap.bc.get_pending_block_id_by_height(shekyl_pow_randomx_v2_seedheight(height));
  const cryptonote::block blk = block_at(height);
  const crypto::hash expected = get_block_longhash(&bap.bc, blk, height, &seed);
  EXPECT_EQ(0, std::memcmp(f.pow_hash, expected.data, sizeof(f.pow_hash)))
    << "the projection hashed against a different seed than the one at its seed height";

  // Every other field still describes the same block, so asking for the pow
  // hash does not disturb the projection.
  EXPECT_EQ(height, f.height);
  EXPECT_EQ(CHAIN_HEIGHT, f.chain_height);
  const crypto::hash id = hash_at(height);
  EXPECT_EQ(0, std::memcmp(f.hash, id.data, sizeof(f.hash)));
}

TEST(rpc_facts_shims, header_past_the_tip_is_absent_and_names_the_chain_height)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  for (const uint64_t h : {CHAIN_HEIGHT, CHAIN_HEIGHT + 500})
  {
    shekyl_rpc_block_header_facts f{};
    ASSERT_EQ(SHEKYL_RPC_FACTS_OK, daemon_rpc_facts::block_header_at(bap.bc, h, false, &f))
      << "height " << h;
    EXPECT_EQ(0, f.found) << "height " << h;
    EXPECT_EQ(CHAIN_HEIGHT, f.chain_height) << "height " << h;
  }
}

TEST(rpc_facts_shims, header_for_an_unproducible_in_range_block_is_inconsistent)
{
  BlockchainAndPool bap;
  auto* db = new FactsTestDB(CHAIN_HEIGHT);
  db->set_missing(3);
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  shekyl_rpc_block_header_facts f{};
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_INCONSISTENT,
    daemon_rpc_facts::block_header_at(bap.bc, 3, false, &f));
  EXPECT_EQ(0, f.found);

  shekyl_rpc_block_header_facts ok{};
  EXPECT_EQ(SHEKYL_RPC_FACTS_OK, daemon_rpc_facts::block_header_at(bap.bc, 2, false, &ok));
  EXPECT_EQ(1, ok.found);
}

TEST(rpc_facts_shims, null_out_pointer_refuses)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL, daemon_rpc_facts::block_hash_at(bap.bc, 0, nullptr));
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    daemon_rpc_facts::block_header_at(bap.bc, 0, false, nullptr));
}

// ── RK-3b: whole blocks ─────────────────────────────────────────────────────
//
// `block_at` is the first export with variable-length payloads, so these
// tests drive the real allocate/release pair rather than a stand-in: every
// success path below ends in `shekyl_rpc_block_free`, and the refusal paths
// assert the owner was never handed out.

namespace
{
  // Releases a `block_at` payload however the test leaves, so a failed
  // EXPECT cannot turn into a leak that only shows up under a sanitizer.
  struct BlockOwner
  {
    void* owner = nullptr;
    ~BlockOwner() { shekyl_rpc_block_free(owner); }
  };
}

TEST(rpc_facts_shims, block_by_height_carries_the_header_and_its_payloads)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  const uint64_t height = 4;
  shekyl_rpc_block_header_facts h{};
  shekyl_rpc_block_payload p{};
  BlockOwner owned;
  ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_at(bap.bc, /*block_hash=*/nullptr, height,
      /*fill_pow_hash=*/false, &h, &p, &owned.owner));

  const cryptonote::block expected = block_at(height);
  ASSERT_EQ(1, h.found);
  ASSERT_NE(nullptr, owned.owner) << "a found block must hand back its payload owner";
  EXPECT_EQ(height, h.height);
  EXPECT_EQ(CHAIN_HEIGHT, h.chain_height);
  EXPECT_EQ(0, h.orphan_status) << "reached by height: main chain";
  EXPECT_EQ(expected.miner_tx.vout[0].amount, h.reward);

  // The blob is the consensus encoding, and round-trips back to the block.
  ASSERT_NE(nullptr, p.blob);
  const cryptonote::blobdata blob(reinterpret_cast<const char*>(p.blob), p.blob_len);
  EXPECT_EQ(cryptonote::t_serializable_object_to_blob(expected), blob);
  cryptonote::block parsed;
  ASSERT_TRUE(cryptonote::parse_and_validate_block_from_blob(blob, parsed));
  EXPECT_EQ(cryptonote::get_block_hash(expected), cryptonote::get_block_hash(parsed));

  // The json is epee's rendering, carried whole (RK-D11) — not parsed here,
  // because nothing in the daemon parses it either.
  ASSERT_NE(nullptr, p.json);
  EXPECT_EQ(cryptonote::obj_to_json_str(const_cast<cryptonote::block&>(expected)), 
    std::string(p.json, p.json_len));
  EXPECT_EQ(std::strlen(p.json), p.json_len) << "json_len must match the NUL-terminated string";

  // The tx hashes arrive contiguous, count first.
  ASSERT_EQ(expected.tx_hashes.size(), p.tx_hashes_len);
  ASSERT_NE(nullptr, p.tx_hashes);
  for (size_t i = 0; i < p.tx_hashes_len; ++i)
  {
    EXPECT_EQ(0, std::memcmp(p.tx_hashes + i * sizeof(crypto::hash),
      expected.tx_hashes[i].data, sizeof(crypto::hash))) << "tx hash " << i;
  }
}

TEST(rpc_facts_shims, block_by_hash_answers_the_same_block)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));

  const uint64_t height = 3;
  const crypto::hash id = hash_at(height);
  shekyl_rpc_block_header_facts by_hash{};
  shekyl_rpc_block_payload ph{};
  BlockOwner owned_hash;
  ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_at(bap.bc, &id, /*height=*/0, false, &by_hash, &ph,
      &owned_hash.owner));

  shekyl_rpc_block_header_facts by_height{};
  shekyl_rpc_block_payload pn{};
  BlockOwner owned_height;
  ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_at(bap.bc, nullptr, height, false, &by_height, &pn,
      &owned_height.owner));

  ASSERT_EQ(1, by_hash.found);
  // The `height` argument is ignored when a hash is given — 0 above would
  // otherwise have fetched the genesis block.
  EXPECT_EQ(height, by_hash.height);
  EXPECT_EQ(0, std::memcmp(&by_hash, &by_height, sizeof(by_hash)))
    << "the lookup mode must not change a single field of the header";
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(ph.blob), ph.blob_len),
    std::string(reinterpret_cast<const char*>(pn.blob), pn.blob_len));
}

TEST(rpc_facts_shims, block_off_the_main_chain_is_flagged_orphan)
{
  BlockchainAndPool bap;
  FactsTestDB* db = new FactsTestDB(CHAIN_HEIGHT);
  // An alt block at a height the main chain also has: this is the inherited
  // quirk (§7, 2026-08-23) — the height comes from the coinbase, and the
  // height-keyed fields below are then read for the MAIN-chain block there.
  cryptonote::block alt = block_at(2);
  alt.nonce = 999999;                     // a different block at the same height
  alt.timestamp = 1600000000;
  db->set_alt_block(alt);
  const crypto::hash alt_id = db->alt_hash();
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  shekyl_rpc_block_header_facts h{};
  shekyl_rpc_block_payload p{};
  BlockOwner owned;
  ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_at(bap.bc, &alt_id, 0, false, &h, &p, &owned.owner));

  ASSERT_EQ(1, h.found);
  EXPECT_EQ(1, h.orphan_status) << "an alt block must not report as main chain";
  EXPECT_EQ(0, std::memcmp(h.hash, alt_id.data, sizeof(h.hash)));
  EXPECT_EQ(2u, h.height) << "the height is the coinbase's, not the lookup's";
  EXPECT_EQ(alt.timestamp, h.timestamp) << "the header describes the ALT block";
  // ...but these come from the main-chain block at that height. Preserved
  // deliberately; if RK-W ever fixes it, this expectation is what changes.
  EXPECT_EQ(1000u + 2u, h.block_weight) << "main-chain weight at the alt block's height";
  EXPECT_EQ(2000u + 2u, h.long_term_weight);
}

// An alt chain ahead of ours: the block exists, but the height its coinbase
// names is one this chain has not reached. `depth` would underflow to a value
// near 2^64 and every height-keyed read would be out of range. The C++
// computed that subtraction too and relied on the DB throwing afterwards.
TEST(rpc_facts_shims, block_claiming_a_height_beyond_the_tip_is_refused)
{
  BlockchainAndPool bap;
  FactsTestDB* db = new FactsTestDB(CHAIN_HEIGHT);
  cryptonote::block ahead = block_at(2);
  ahead.nonce = 4242;
  // The coinbase names its own height, and this one is past our tip.
  ahead.miner_tx.vin.clear();
  cryptonote::txin_gen gen{};
  gen.height = CHAIN_HEIGHT + 5;
  ahead.miner_tx.vin.push_back(gen);
  db->set_alt_block(ahead);
  const crypto::hash id = db->alt_hash();
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  shekyl_rpc_block_header_facts h{};
  shekyl_rpc_block_payload p{};
  void* owner = nullptr;
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_INTERNAL,
    daemon_rpc_facts::block_at(bap.bc, &id, 0, false, &h, &p, &owner));
  EXPECT_EQ(nullptr, owner) << "a refusal hands back nothing to free";
  // Deleting the guard turns this red: `depth` would come back near 2^64.
  EXPECT_EQ(0u, h.depth);
  EXPECT_EQ(0, h.found);
}

TEST(rpc_facts_shims, block_absent_by_either_lookup_is_data_not_a_fault)
{
  BlockchainAndPool bap;
  FactsTestDB* db = new FactsTestDB(CHAIN_HEIGHT);
  db->set_missing(2);
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  const crypto::hash unknown = hash_at(9999);
  struct { const crypto::hash* hash; uint64_t height; const char* what; } cases[] = {
    {nullptr, CHAIN_HEIGHT,     "past the tip"},
    {nullptr, CHAIN_HEIGHT + 5, "well past the tip"},
    {nullptr, 2,                "in range, but the store cannot produce it"},
    {&unknown, 0,               "a hash the chain does not have"},
  };
  for (const auto& c : cases)
  {
    shekyl_rpc_block_header_facts h{};
    shekyl_rpc_block_payload p{};
    void* owner = reinterpret_cast<void*>(0x1);  // must be cleared, not left
    ASSERT_EQ(SHEKYL_RPC_FACTS_OK,
      daemon_rpc_facts::block_at(bap.bc, c.hash, c.height, false, &h, &p, &owner))
      << c.what;
    EXPECT_EQ(0, h.found) << c.what;
    EXPECT_EQ(CHAIN_HEIGHT, h.chain_height) << c.what << ": the bound is still reported";
    EXPECT_EQ(nullptr, owner) << c.what << ": nothing was allocated, nothing to free";
    EXPECT_EQ(nullptr, p.blob) << c.what;
    EXPECT_EQ(0u, p.tx_hashes_len) << c.what;
  }
}

TEST(rpc_facts_shims, block_with_a_malformed_coinbase_is_inconsistent)
{
  BlockchainAndPool bap;
  FactsTestDB* db = new FactsTestDB(CHAIN_HEIGHT);
  db->set_bad_coinbase(3);
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  shekyl_rpc_block_header_facts h{};
  shekyl_rpc_block_payload p{};
  void* owner = nullptr;
  // A block that exists but whose coinbase carries no `txin_gen` is broken,
  // not missing — the height it reports would otherwise be unreadable.
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_INCONSISTENT,
    daemon_rpc_facts::block_at(bap.bc, nullptr, 3, false, &h, &p, &owner));
  EXPECT_EQ(nullptr, owner);

  // Its neighbours are unaffected.
  BlockOwner good;
  EXPECT_EQ(SHEKYL_RPC_FACTS_OK,
    daemon_rpc_facts::block_at(bap.bc, nullptr, 2, false, &h, &p, &good.owner));
  EXPECT_EQ(1, h.found);
}

// The `extern "C"` entry points, not the bodies the other tests drive. A null
// handle returns before any core object is touched, which is the one path
// where the owner slot could keep a value from a previous call — and a caller
// that frees what it sees there frees it twice.
TEST(rpc_facts_shims, a_refused_export_never_leaves_a_stale_owner)
{
  void* const stale = reinterpret_cast<void*>(0xdeadbeef);
  shekyl_rpc_block_header_facts h{};
  shekyl_rpc_block_payload p{};

  void* owner = stale;
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    shekyl_rpc_block_at(nullptr, nullptr, 0, 0, &h, &p, &owner));
  EXPECT_EQ(nullptr, owner) << "block_at left the caller a pointer to free twice";

  const shekyl_rpc_hardfork_entry* rows = nullptr;
  size_t len = 0;
  owner = stale;
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    shekyl_rpc_hardforks(nullptr, &rows, &len, &owner));
  EXPECT_EQ(nullptr, owner) << "hardforks left the caller a pointer to free twice";

  // A null owner slot is still refused rather than dereferenced.
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    shekyl_rpc_block_at(nullptr, nullptr, 0, 0, &h, &p, nullptr));
}

TEST(rpc_facts_shims, block_null_out_pointers_refuse)
{
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, new FactsTestDB(CHAIN_HEIGHT)));
  shekyl_rpc_block_header_facts h{};
  shekyl_rpc_block_payload p{};
  void* owner = nullptr;
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    daemon_rpc_facts::block_at(bap.bc, nullptr, 0, false, nullptr, &p, &owner));
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    daemon_rpc_facts::block_at(bap.bc, nullptr, 0, false, &h, nullptr, &owner));
  EXPECT_EQ(SHEKYL_RPC_FACTS_ERR_NULL,
    daemon_rpc_facts::block_at(bap.bc, nullptr, 0, false, &h, &p, nullptr));
  // Freeing nothing is a no-op, as the header promises.
  shekyl_rpc_block_free(nullptr);
}
