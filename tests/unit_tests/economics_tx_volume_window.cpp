// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// FL-R24 (FEE_LADDER_DERIVATION.md §11.7, PR A) — the transaction-volume
// operand crosses the FFI as the exact window `(tx_count_sum, blocks)` and
// C++ never divides it. These tests pin the C++ half of that contract:
//
//   1. `Blockchain::get_tx_volume_window` returns the SUM and the window
//      length, not their quotient — on a chain whose per-block counts do
//      not average to a whole number, the quotient is exactly the value
//      the old `get_tx_volume_avg` would have truncated to.
//   2. The 6-arg `get_block_reward` shim hands that pair to Rust intact:
//      the reward at the exact window differs from the reward at the
//      floored mean, and equals the direct FFI call with the same pair.
//      The literals are the ones pinned Rust-side in
//      `shekyl-economics/src/emission.rs`
//      (`fl_r24_exact_window_mean_moves_the_reward_off_the_truncated_value`),
//      so a shim that quietly re-divided would fail here and nowhere else.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <memory>

#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "shekyl/shekyl_ffi.h"
#include "shekyl/tx_volume_window.h"

using namespace cryptonote;

namespace {

// Block h carries 40 transactions on even heights and 41 on odd ones, so
// every even-length window has a mean of exactly 40.5 — a value the old
// integer operand could not represent (it floored to 40, which is also
// the 0.8 release rail).
class AlternatingVolumeDB: public BaseTestDB
{
public:
  AlternatingVolumeDB() { m_open = true; }

  cryptonote::block get_block_from_height(const uint64_t& h) const override
  {
    cryptonote::block b{};
    b.tx_hashes.resize(40 + (h % 2));
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
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 0);
}

} // namespace

TEST(economics_tx_volume_window, returns_the_sum_and_the_length_not_their_quotient)
{
  auto db = std::make_unique<AlternatingVolumeDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));

  // Height 0: nothing below it.
  const shekyl::tx_volume_window at_genesis = bap.bc.get_tx_volume_window(0);
  EXPECT_EQ(at_genesis.tx_count_sum, 0u);
  EXPECT_EQ(at_genesis.blocks, 0u);

  // Inside the first window the length is the height itself, and the sum
  // is over blocks [0, height): 40 + 41 + 40 + 41 + 40 = 202 for five.
  const shekyl::tx_volume_window early = bap.bc.get_tx_volume_window(5);
  EXPECT_EQ(early.tx_count_sum, 202u);
  EXPECT_EQ(early.blocks, 5u);

  // A full window: 720 blocks, 360 even + 360 odd = 40 * 720 + 360.
  const uint64_t h = SHEKYL_TX_VOLUME_WINDOW + 10;
  const shekyl::tx_volume_window full = bap.bc.get_tx_volume_window(h);
  EXPECT_EQ(full.blocks, static_cast<uint64_t>(SHEKYL_TX_VOLUME_WINDOW));
  EXPECT_EQ(full.tx_count_sum, 40u * SHEKYL_TX_VOLUME_WINDOW + SHEKYL_TX_VOLUME_WINDOW / 2);
  // The value the retired `get_tx_volume_avg` would have returned here —
  // named so the diff shows what was being thrown away.
  EXPECT_EQ(full.tx_count_sum / full.blocks, 40u);
  EXPECT_NE(full.tx_count_sum, full.blocks * (full.tx_count_sum / full.blocks));
}

TEST(economics_tx_volume_window, shim_hands_the_exact_pair_to_rust_undivided)
{
  // Same chain state as the Rust KAT: mid-curve, weight below the zone.
  const uint64_t ag = SHEKYL_EMISSION_CURVE_ASYMPTOTE / 2;
  const uint8_t version = 1;
  const shekyl::tx_volume_window exact{40u * 720 + 360, 720};
  const shekyl::tx_volume_window floored{40, 1};

  uint64_t reward_exact = 0;
  uint64_t reward_floored = 0;
  ASSERT_TRUE(cryptonote::get_block_reward(0, 1, ag, reward_exact, version, exact));
  ASSERT_TRUE(cryptonote::get_block_reward(0, 1, ag, reward_floored, version, floored));

  // new (exact, M_r = 0.81) / old (floored, M_r = 0.80 = the lower rail).
  EXPECT_EQ(reward_exact, UINT64_C(829440000000));
  EXPECT_EQ(reward_floored, UINT64_C(819200000000));
  EXPECT_NE(reward_exact, reward_floored);

  // And the shim agrees with the direct FFI call on the same pair.
  uint64_t direct = 0;
  uint64_t limit = 0;
  ASSERT_EQ(SHEKYL_BLOCK_REWARD_OK,
            shekyl_block_reward(0, 1, ag, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
                                exact.tx_count_sum, exact.blocks, &direct, &limit));
  EXPECT_EQ(reward_exact, direct);
}
