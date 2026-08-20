// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// KAT B5 — fee-bearing coinbase foreclosure (ARCHIVAL_BUDGET_SCHEDULE.md §7,
// §2.2's coinbase-foreclosure pin). The budget redirect is supply-safe only
// because the staker halves never enter the coinbase: validate_miner_transaction
// rejects any coinbase that is not exactly miner_emission + miner_fee_income.
// The standing economics_c2a_prime tests run fee-free blocks, so the fee-side
// half (staker_pool_amount excluded from a fee-bearing block's coinbase) was
// pinned only at the helper level; this KAT drives the production decision
// with fee > 0.
//
// Connect-path form deferral: the chaingen harness cannot construct valid
// fee-paying FCMP++ transactions (chaingen_main.cpp, tests removed
// 2026-05-05), so the fee-bearing *block* vehicle defers with that harness
// gap; the *decision* this KAT arms is the same :1611/:1616 exact-equality
// check the connect path calls with the block's fee_summary.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <cstring>
#include <memory>

#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "shekyl/economics.h"

using namespace cryptonote;

namespace {

// Reports open for Blockchain::init and a busy prior block so
// get_tx_volume_avg(1) is above SHEKYL_TX_VOLUME_BASELINE — with an empty
// chain the burn percentage is zero and the fee split degenerates to
// miner-takes-all, which would leave the fee-side foreclosure untested.
class B5TestDB: public BaseTestDB
{
public:
  static constexpr size_t kTxPerBlock = 100;

  B5TestDB() { m_open = true; }

  cryptonote::block get_block_from_height(const uint64_t&) const override
  {
    cryptonote::block b{};
    b.tx_hashes.resize(kTxPerBlock);
    return b;
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
  BlockchainAndPool(): txpool(bc), bc(txpool) {}
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
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 0, nullptr);
}

// Synthetic block carrying only what validate_miner_transaction reads:
// txin_gen height and the coinbase vout amounts.
block make_block_with_coinbase(uint64_t height, uint64_t coinbase_amount)
{
  block b{};
  txin_gen gen{};
  gen.height = height;
  b.miner_tx.vin.push_back(gen);

  tx_out vout{};
  vout.amount = coinbase_amount;
  txout_to_tagged_key tagged{};
  memset(&tagged.key, 0xAA, sizeof(tagged.key));
  tagged.view_tag.data = 0;
  vout.target = tagged;
  b.miner_tx.vout.push_back(vout);
  return b;
}

// ~1% of MONEY_SUPPLY: the burn percentage scales with
// circulating/total (SCALE 10^6 fixed point), so the circulating supply
// must clear MONEY_SUPPLY/SCALE or the ratio floors to zero and the fee
// split degenerates to miner-takes-all.
constexpr uint64_t kAlreadyGenerated = UINT64_C(42949672960000000);
constexpr uint64_t kBlockHeight = 1;
constexpr uint64_t kFee = UINT64_C(1000000000);
constexpr uint8_t kHfVersion = 1;

struct B5Operands
{
  uint64_t base_reward;
  shekyl::EmissionSplit split;
  shekyl::BurnResult burn;
};

// Recompose the expected coinbase through the same single-evaluator helpers
// the production check calls (compute_emission_split / compute_fee_burn wrap
// the Rust FFI) — the KAT arms the exact-equality *decision*, not a second
// evaluation of the formula.
B5Operands expected_operands(const Blockchain& bc)
{
  B5Operands ops{};
  const uint64_t median = bc.get_current_cumulative_block_weight_median();
  // Same DB-derived operand the production check reads (B5TestDB's busy
  // prior block makes it exceed the burn baseline).
  const uint64_t tx_volume_avg = bc.get_tx_volume_avg(kBlockHeight);
  EXPECT_GT(tx_volume_avg, 0u);
  EXPECT_TRUE(get_block_reward(median, 0, kAlreadyGenerated, ops.base_reward,
    kHfVersion, tx_volume_avg));
  ops.split = shekyl::compute_emission_split(ops.base_reward, kBlockHeight,
    /*genesis_ng_height=*/0);
  // n = 0 is the same parent-state operand the production check reads:
  // B5TestDB's curve tree is empty, so parent_frozen_segment_count yields 0.
  ops.burn = shekyl::compute_fee_burn(kFee, tx_volume_avg,
    kAlreadyGenerated, /*frozen_segment_count=*/0);
  return ops;
}

} // namespace

TEST(economics_b5_fee_coinbase, fee_bearing_exact_coinbase_accepts)
{
  auto db = std::make_unique<B5TestDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));

  const B5Operands ops = expected_operands(bap.bc);
  // The fee legs must be genuinely fee-bearing for the KAT to close the
  // fee-side gap: nonzero miner income, nonzero staker pool (so the
  // overclaim rejections below reject real amounts), income strictly
  // below the raw fee (the burn/pool carve-out is real).
  ASSERT_GT(ops.burn.miner_fee_income, 0u);
  ASSERT_GT(ops.burn.staker_pool_amount, 0u);
  ASSERT_LT(ops.burn.miner_fee_income, kFee);
  ASSERT_GT(ops.split.staker_emission, 0u);

  const block b = make_block_with_coinbase(kBlockHeight,
    ops.split.miner_emission + ops.burn.miner_fee_income);
  uint64_t base_reward_out = 0;
  EXPECT_TRUE(bap.bc.validate_miner_transaction(b, /*cumulative_block_weight=*/0,
    kFee, base_reward_out, kAlreadyGenerated, kHfVersion, /*frozen_segment_count=*/0));
  // Fix α regression guard: the out-param stays the FULL subsidy (miner +
  // staker emission) so the connect path accumulates the full amount into
  // already_generated_coins.
  EXPECT_EQ(base_reward_out, ops.base_reward);
}

TEST(economics_b5_fee_coinbase, coinbase_claiming_staker_pool_rejects)
{
  auto db = std::make_unique<B5TestDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));

  const B5Operands ops = expected_operands(bap.bc);
  ASSERT_GT(ops.burn.staker_pool_amount, 0u);

  const block b = make_block_with_coinbase(kBlockHeight,
    ops.split.miner_emission + ops.burn.miner_fee_income + ops.burn.staker_pool_amount);
  uint64_t base_reward_out = 0;
  EXPECT_FALSE(bap.bc.validate_miner_transaction(b, 0, kFee, base_reward_out,
    kAlreadyGenerated, kHfVersion, /*frozen_segment_count=*/0));
}

TEST(economics_b5_fee_coinbase, coinbase_claiming_staker_emission_rejects)
{
  auto db = std::make_unique<B5TestDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));

  const B5Operands ops = expected_operands(bap.bc);
  ASSERT_GT(ops.split.staker_emission, 0u);

  const block b = make_block_with_coinbase(kBlockHeight,
    ops.split.miner_emission + ops.split.staker_emission + ops.burn.miner_fee_income);
  uint64_t base_reward_out = 0;
  EXPECT_FALSE(bap.bc.validate_miner_transaction(b, 0, kFee, base_reward_out,
    kAlreadyGenerated, kHfVersion, /*frozen_segment_count=*/0));
}

TEST(economics_b5_fee_coinbase, fee_underclaim_rejects_exactness)
{
  // The check is exact equality, not ≤: a coinbase leaving fee income
  // unclaimed also rejects (:1616's != branch), so "exactly" in §2.2's pin
  // is two-sided.
  auto db = std::make_unique<B5TestDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));

  const B5Operands ops = expected_operands(bap.bc);
  const block b = make_block_with_coinbase(kBlockHeight, ops.split.miner_emission);
  uint64_t base_reward_out = 0;
  EXPECT_FALSE(bap.bc.validate_miner_transaction(b, 0, kFee, base_reward_out,
    kAlreadyGenerated, kHfVersion, /*frozen_segment_count=*/0));
}
