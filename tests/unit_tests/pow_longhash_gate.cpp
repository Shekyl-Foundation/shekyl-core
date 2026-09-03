// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// CEN-D2 fix coverage (docs/design/CONSENSUS_STORE_RECONCILIATION.md §5.4.1):
// a longhash the verifier could not compute must reject at EVERY difficulty.
// The 0xff sentinel is a belt, not the gate — at difficulty 1 every hash
// passes check_hash, so the verifier's returned bool is the gate. These tests
// pin the verdict contracts at the seams take-able in a unit test:
//   - get_block_longhash (bool overload): false + belt on schema failure;
//   - get_altblock_longhash: same contract, now routed through the one
//     IPowSchema dispatch point;
//   - block_longhash_worker: an uncomputed hash never enters the precompute
//     table (a table hit is trusted by the consumer without re-checking).
//
// COVERAGE BOUNDARY (rule 50 — record the ground): the two validation call
// sites in handle_block_to_main_chain / handle_alternative_block consume
// these bools; exercising them end-to-end needs a connectable block and is
// the same harness family as the CEN-M8 wiring regression in FOLLOWUPS. The
// worker test covers one of the three consumer sites for real; the other two
// rest on the code walk recorded in the register.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <cstring>
#include <unordered_map>

#include "blockchain_db/testdb.h"
#include "crypto/pow_registry.h"
#include "crypto/pow_schema.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
// cryptonote_core.h defines cryptonote::test_options (blockchain.h only
// forward-declares it), needed by init_blockchain's fakechain options.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/tx_pool.h"

using namespace cryptonote;

namespace
{

class FailingPowSchema final : public IPowSchema
{
public:
  bool hash(const void*, size_t, uint64_t, const crypto::hash*, unsigned,
    crypto::hash&) const override
  {
    return false; // the verifier-failure arm under test
  }
  const char* name() const override { return "FailingTestSchema"; }
};

// Control schema: proves the override seam engages (a test must be able to
// observe its own setup) and pins the success path through the same seams.
class ConstPowSchema final : public IPowSchema
{
public:
  bool hash(const void*, size_t, uint64_t, const crypto::hash*, unsigned,
    crypto::hash& out) const override
  {
    memset(out.data, 0x42, sizeof(out.data));
    return true;
  }
  const char* name() const override { return "ConstTestSchema"; }
};

struct SchemaOverrideGuard
{
  explicit SchemaOverrideGuard(const IPowSchema* s)
  {
    set_pow_schema_override_for_tests(s);
  }
  ~SchemaOverrideGuard() { set_pow_schema_override_for_tests(nullptr); }
};

class PowGateTestDB : public BaseTestDB
{
public:
  PowGateTestDB() { m_open = true; }
  virtual uint64_t height() const override { return 10; }
  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const override
  {
    crypto::hash h = crypto::null_hash;
    const uint64_t tagged = height + 1;
    memcpy(h.data, &tagged, sizeof(tagged));
    return h;
  }
};

struct BlockchainAndPool
{
  cryptonote::tx_memory_pool txpool;
  cryptonote::Blockchain bc;
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
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 1);
}

bool is_belt_sentinel(const crypto::hash& h)
{
  for (size_t i = 0; i < sizeof(h.data); ++i)
    if (static_cast<unsigned char>(h.data[i]) != 0xff)
      return false;
  return true;
}

} // namespace

TEST(pow_longhash_gate, bool_overload_reports_failure_and_seeds_belt)
{
  FailingPowSchema failing;
  SchemaOverrideGuard guard(&failing);

  block blk{};
  blk.major_version = 1;
  crypto::hash res = crypto::null_hash;
  EXPECT_FALSE(get_block_longhash(nullptr, blk, res, 1, nullptr, 0))
    << "verifier failure must surface through the bool";
  EXPECT_TRUE(is_belt_sentinel(res))
    << "the 0xff belt must still be written for bool-ignoring callers";
}

TEST(pow_longhash_gate, altblock_longhash_reports_failure_and_seeds_belt)
{
  FailingPowSchema failing;
  SchemaOverrideGuard guard(&failing);

  block blk{};
  blk.major_version = 1;
  crypto::hash seed{};
  memset(seed.data, 0xAB, sizeof(seed.data));
  crypto::hash res = crypto::null_hash;
  EXPECT_FALSE(get_altblock_longhash(blk, res, seed))
    << "alt-path verifier failure must surface through the bool";
  EXPECT_TRUE(is_belt_sentinel(res));
}

TEST(pow_longhash_gate, seam_engages_and_success_path_passes_through)
{
  ConstPowSchema constant;
  SchemaOverrideGuard guard(&constant);

  block blk{};
  blk.major_version = 1;
  crypto::hash res = crypto::null_hash;
  ASSERT_TRUE(get_block_longhash(nullptr, blk, res, 1, nullptr, 0));
  for (size_t i = 0; i < sizeof(res.data); ++i)
    ASSERT_EQ(0x42, static_cast<unsigned char>(res.data[i]));

  crypto::hash seed{};
  crypto::hash res2 = crypto::null_hash;
  ASSERT_TRUE(get_altblock_longhash(blk, res2, seed));
  for (size_t i = 0; i < sizeof(res2.data); ++i)
    ASSERT_EQ(0x42, static_cast<unsigned char>(res2.data[i]))
      << "alt-path hash byte " << i << " not written through";
}

// The one consumer site reachable in a unit test: the precompute worker. Its
// map is trusted by handle_block_to_main_chain without re-checking, so an
// uncomputed hash entering it would resurrect the fail-open one layer up.
TEST(pow_longhash_gate, worker_never_caches_uncomputed_hash)
{
  FailingPowSchema failing;
  SchemaOverrideGuard guard(&failing);

  PowGateTestDB* db = new PowGateTestDB();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  block blk{};
  blk.major_version = 1;
  std::unordered_map<crypto::hash, crypto::hash> map;
  bap.bc.block_longhash_worker(1, epee::span<const block>(&blk, 1), map);
  EXPECT_TRUE(map.empty())
    << "an uncomputed (sentinel) hash entered the precompute table";
}

TEST(pow_longhash_gate, worker_caches_computed_hash)
{
  ConstPowSchema constant;
  SchemaOverrideGuard guard(&constant);

  PowGateTestDB* db = new PowGateTestDB();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  block blk{};
  blk.major_version = 1;
  std::unordered_map<crypto::hash, crypto::hash> map;
  bap.bc.block_longhash_worker(1, epee::span<const block>(&blk, 1), map);
  ASSERT_EQ(1u, map.size());
  ASSERT_EQ(0x42, static_cast<unsigned char>(map.begin()->second.data[0]));
}
