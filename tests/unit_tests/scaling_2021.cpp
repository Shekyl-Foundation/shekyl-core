// Copyright (c) 2019-2022, The Monero Project
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

// Shekyl fee scaling tests.  All hard-fork features are active from genesis
// (HF1).  Under FL-R20 the served floor is
//   F(h) = max(1, R * C(h) * 3000 / M(h)^2)
// with C raw (no snap, no band) and Monero's 0.95 DELETED — it and the 2%
// admission buffer were the same fudge for the same gap, which FL-R23 closes
// structurally.  The arithmetic lives in shekyl-economics (rule 20); these
// tests pin the daemon's marshalling and the FL-R6 identity.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_db/testdb.h"
#include "shekyl/economics_params_generated.h"

namespace
{

class TestDB: public cryptonote::BaseTestDB
{
public:
  TestDB() { m_open = true; }
};

// A chain whose LONG-TERM median clears the penalty-free zone.
//
// It exists because the plain `TestDB` cannot observe FL-R20's un-gracing of
// `Mlw`. That fixture reports one block, so the long-term median is `max(128,
// Zm)` = Zm — pinned at the floor, where inserting `grace_blocks` zeroes moves
// nothing. A test written over it passes identically before and after the
// change, which is worse than no test: it reads as coverage.
//
// With every long-term weight at 2 * Zm the median sits above the floor, zeroes
// inserted by the old graced shape pull it DOWN, and the served ladder moves —
// so `grace_blocks_do_not_move_the_served_ladder` below can actually fail.
class HighLongTermMedianTestDB: public cryptonote::BaseTestDB
{
public:
  static constexpr uint64_t BLOCKS = 5000;
  static constexpr uint64_t WEIGHT = 2 * CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  HighLongTermMedianTestDB() { m_open = true; }

  virtual uint64_t height() const override { return BLOCKS; }
  virtual size_t get_block_weight(const uint64_t &) const override { return WEIGHT; }
  virtual uint64_t get_block_long_term_weight(const uint64_t &) const override { return WEIGHT; }
  virtual std::vector<uint64_t> get_block_weights(uint64_t, size_t count) const override {
    return std::vector<uint64_t>(count, WEIGHT);
  }
  virtual std::vector<uint64_t> get_long_term_block_weights(uint64_t, size_t count) const override {
    return std::vector<uint64_t>(count, WEIGHT);
  }
  virtual crypto::hash get_block_hash_from_height(const uint64_t &height) const override {
    crypto::hash hash = crypto::null_hash;
    *(uint64_t*)&hash = height;
    return hash;
  }
  virtual crypto::hash top_block_hash(uint64_t *block_height = NULL) const override {
    crypto::hash top = crypto::null_hash;
    *(uint64_t*)&top = BLOCKS - 1;
    if (block_height)
      *block_height = BLOCKS - 1;
    return top;
  }
};

}

// A chain whose long-term weights, per-block transaction counts and supply
// all VARY by height, with a height the test can advance.
//
// It exists for warm_ring_equals_cold_reconstruction. On a fixture whose
// per-height quantities are constant, the warm push and the cold rebuild
// agree trivially — every F(h) is the same number — and the test asserts
// nothing about the reconstruction. Here M, C and R each move with h, so the
// two paths can only agree if the cold path reconstructs each height's
// operands exactly.
class VaryingChainTestDB: public cryptonote::BaseTestDB
{
public:
  explicit VaryingChainTestDB(uint64_t height) : m_height(height) { m_open = true; }
  void set_height(uint64_t h) { m_height = h; }

  // Above the penalty-free floor everywhere, and not monotone, so the
  // stepped median genuinely moves as the window slides.
  static uint64_t lt_weight(uint64_t h) { return 2 * CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 + (h * 7919) % 100000; }
  // Mean ~49.5/block — AT the volume baseline, so M_r sits between its rails
  // and C actually responds to the window. The first version used h % 13
  // (mean ~6), which pinned M_r at the 0.8 rail at every height: C was then
  // a constant, and a bite that fed every height the TIP's window passed —
  // the C axis was invisible. See the C-axis subject assertion in the test.
  static size_t tx_count(uint64_t h) { return static_cast<size_t>(h % 100); }
  // The volume window the daemon would count at height h: sum over [h-720, h).
  static uint64_t window_sum(uint64_t h) {
    const uint64_t start = h > SHEKYL_TX_VOLUME_WINDOW ? h - SHEKYL_TX_VOLUME_WINDOW : 0;
    uint64_t sum = 0;
    for (uint64_t x = start; x < h; ++x) sum += tx_count(x);
    return sum;
  }

  virtual uint64_t height() const override { return m_height; }
  virtual size_t get_block_weight(const uint64_t &h) const override { return lt_weight(h); }
  virtual uint64_t get_block_long_term_weight(const uint64_t &h) const override { return lt_weight(h); }
  virtual std::vector<uint64_t> get_block_weights(uint64_t start, size_t count) const override {
    std::vector<uint64_t> v; v.reserve(count);
    for (uint64_t h = start; h < start + count && h < m_height; ++h) v.push_back(lt_weight(h));
    return v;
  }
  virtual std::vector<uint64_t> get_long_term_block_weights(uint64_t start, size_t count) const override {
    std::vector<uint64_t> v; v.reserve(count);
    for (uint64_t h = start; h < start + count && h < m_height; ++h) v.push_back(lt_weight(h));
    return v;
  }
  virtual cryptonote::block get_block_from_height(const uint64_t &h) const override {
    cryptonote::block b;
    b.tx_hashes.resize(tx_count(h), crypto::null_hash);
    return b;
  }
  virtual uint64_t get_block_already_generated_coins(const uint64_t &h) const override {
    return 10000000000ull + h * 1000000ull;
  }
  virtual crypto::hash get_block_hash_from_height(const uint64_t &h) const override {
    crypto::hash hash = crypto::null_hash;
    *(uint64_t*)&hash = h;
    return hash;
  }
  virtual crypto::hash top_block_hash(uint64_t *block_height = NULL) const override {
    crypto::hash top = crypto::null_hash;
    *(uint64_t*)&top = m_height - 1;
    if (block_height)
      *block_height = m_height - 1;
    return top;
  }

private:
  uint64_t m_height;
};

#define PREFIX_WINDOW(hf_version,window) \
  std::unique_ptr<cryptonote::Blockchain> bc; \
  cryptonote::tx_memory_pool txpool(*bc); \
  bc.reset(new cryptonote::Blockchain(txpool)); \
  struct get_test_options { \
    const std::pair<uint8_t, uint64_t> hard_forks[3]; \
    const cryptonote::test_options test_options = { \
      hard_forks, \
      window, \
    }; \
    get_test_options(): hard_forks{std::make_pair(1, (uint64_t)0), std::make_pair((uint8_t)hf_version, (uint64_t)1), std::make_pair((uint8_t)0, (uint64_t)0)} {} \
  } opts; \
  cryptonote::Blockchain *blockchain = bc.get(); \
  bool r = blockchain->init(new TestDB(), cryptonote::FAKECHAIN, true, &opts.test_options, 0); \
  ASSERT_TRUE(r)

#define PREFIX(hf_version) PREFIX_WINDOW(hf_version, TEST_LONG_TERM_BLOCK_WEIGHT_WINDOW)

#define PREFIX_WINDOW_DBPTR(hf_version,window,dbptr) \
  std::unique_ptr<cryptonote::Blockchain> bc; \
  cryptonote::tx_memory_pool txpool(*bc); \
  bc.reset(new cryptonote::Blockchain(txpool)); \
  struct get_test_options_dbptr { \
    const std::pair<uint8_t, uint64_t> hard_forks[3]; \
    const cryptonote::test_options test_options = { \
      hard_forks, \
      window, \
    }; \
    get_test_options_dbptr(): hard_forks{std::make_pair(1, (uint64_t)0), std::make_pair((uint8_t)hf_version, (uint64_t)1), std::make_pair((uint8_t)0, (uint64_t)0)} {} \
  } opts; \
  cryptonote::Blockchain *blockchain = bc.get(); \
  bool r = blockchain->init(dbptr, cryptonote::FAKECHAIN, true, &opts.test_options, 0); \
  ASSERT_TRUE(r)

#define PREFIX_WINDOW_DB(hf_version,window,dbtype) \
  std::unique_ptr<cryptonote::Blockchain> bc; \
  cryptonote::tx_memory_pool txpool(*bc); \
  bc.reset(new cryptonote::Blockchain(txpool)); \
  struct get_test_options_db { \
    const std::pair<uint8_t, uint64_t> hard_forks[3]; \
    const cryptonote::test_options test_options = { \
      hard_forks, \
      window, \
    }; \
    get_test_options_db(): hard_forks{std::make_pair(1, (uint64_t)0), std::make_pair((uint8_t)hf_version, (uint64_t)1), std::make_pair((uint8_t)0, (uint64_t)0)} {} \
  } opts; \
  cryptonote::Blockchain *blockchain = bc.get(); \
  bool r = blockchain->init(new dbtype(), cryptonote::FAKECHAIN, true, &opts.test_options, 0); \
  ASSERT_TRUE(r)

// `fee_2021_scaling.relay_fee` and the whole of `tests/unit_tests/fee.cpp`
// are DELETED, not ported. Both exercised `Blockchain::get_dynamic_base_fee`,
// whose entire body was the inherited `0.95 * R * w_ref / M^2`; FL-R20 deletes
// the 0.95 and moves the arithmetic to its Rust owner (rule 20), so the
// function no longer exists to call. Re-pointing the assertions at the FFI
// would have kept a C++ copy of a Rust contract in the tree — and a KAT whose
// expected values were read off the new code rather than re-derived is the
// classic test that passes for the wrong reason after a formula change.
//
// The 18-row grid is re-derived from FL-R20 and lives with the formula, in
// `shekyl-economics` `fee.rs` (`relay_floor_matches_the_migrated_heritage_grid`),
// with every old value beside its new one. Only six rows move: truncation
// already absorbed the 5% everywhere else.
TEST(fee_2021_scaling, wallet_fee_estimate)
{
  PREFIX_WINDOW(HF_VERSION_2021_SCALING, CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE);
  std::vector<uint64_t> fees;

  // FL round §5.2 shape (FL-R17 signed): three tiers, Fh main arm
  // UNCONDITIONAL. C = SCALE is the neutral correction.
  //
  // Values moved with FL-R20/FL-R21: round_money_up_2 is off the served path,
  // so each rung is the arithmetic's own answer rather than that answer
  // rounded up to two significant digits, and standard is 4x economy exactly.

  // 10 SKL reward, Mnw=Mlw=ZONE_V5
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 300000, 300000, SHEKYL_FIXED_POINT_SCALE, fees);
  ASSERT_EQ(fees.size(), 3);
  ASSERT_EQ(fees[0], 333u);
  ASSERT_EQ(fees[1], 1332u);
  ASSERT_EQ(fees[2], 66666u);

  // 10 SKL reward, large Mnw. The heritage 22000 came from the surge
  // discount; the unconditional main arm prices full expansion here too
  // (FL-C2(b) — the one derived defect in the inherited shape).
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 15000000, 300000, SHEKYL_FIXED_POINT_SCALE, fees);
  ASSERT_EQ(fees.size(), 3);
  ASSERT_EQ(fees[0], 333u);
  ASSERT_EQ(fees[1], 1332u);
  ASSERT_EQ(fees[2], 66666u);

  // 10 SKL reward, Mnw=Mlw=1500000
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 1500000, 1500000, SHEKYL_FIXED_POINT_SCALE, fees);
  ASSERT_EQ(fees.size(), 3);
  ASSERT_EQ(fees[0], 13u);
  ASSERT_EQ(fees[1], 52u);
  ASSERT_EQ(fees[2], 13333u);

  // C = 2 (one congestion step): every rung doubles EXACTLY, now that
  // round_money_up_2 is off the served path (FL-R21). Under the rounding the
  // C = 1 row was [340, 1400, 67000] and this one [670, 2700, 140000] — not
  // quite double, because each rung was rounded up independently.
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 300000, 300000, 2 * SHEKYL_FIXED_POINT_SCALE, fees);
  ASSERT_EQ(fees.size(), 3);
  ASSERT_EQ(fees[0], 666u);
  ASSERT_EQ(fees[1], 2664u);
  ASSERT_EQ(fees[2], 133333u);
}

TEST(fee_2021_scaling, state_computed_estimate_holds_the_acceptance_identity)
{
  // The 2-arg wrapper — the path wallets actually reach — computes C from
  // chain state. The 5-arg pins above bypass that, so this is the wrapper's
  // own pin.
  //
  // THE ASSERTION IS NOW EQUALITY, and the upgrade is the substance of
  // FL-R20/FL-R21. It used to be `>=`, guaranteed by a
  // `fees[0] = max(fees[0], get_current_fee_per_byte())` clamp, and the old
  // note here recorded that the clamp's ACTIVATION was untested because the
  // two pricing functions "take DIFFERENT medians, so divergence is possible
  // by construction". That is no longer true and is why the clamp is gone:
  // both paths now divide by one M (the un-graced long-term effective median)
  // and multiply by one C, through one Rust entry point. `>=` was satisfiable
  // by over-quoting any amount; `==` is not, so this test now fails if the two
  // ever part company instead of silently tolerating it.
  //
  // Falsifier, restated for the new shape: anything that gives the estimate
  // and the relay floor different operands — re-introducing the grace
  // lookahead on Mlw, a second C derivation, a rounding step on one side —
  // breaks this, which is the intent.
  PREFIX_WINDOW(HF_VERSION_2021_SCALING, CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE);
  std::vector<uint64_t> fees;
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, fees);
  ASSERT_EQ(fees.size(), 3);
  ASSERT_LE(fees[0], fees[1]);
  ASSERT_LE(fees[1], fees[2]);
  // FL-R6's identity: the served economy rung IS the relay floor.
  ASSERT_EQ(fees[0], bc->get_current_fee_per_byte());
  // And standard is exactly 4F, with no rounding step between them.
  ASSERT_EQ(fees[1], 4 * fees[0]);
}

// FL-R20's un-gracing of `Mlw`, tested where it can actually fail.
//
// The inherited estimate copied the long-term rolling median and inserted
// `grace_blocks` zeroes, pulling M down and the quoted fee UP — a deliberate
// over-quote so a wallet's quote survived the next few blocks. FL-R23 does that
// job exactly rather than probabilistically, so the lookahead is deleted and the
// served ladder must not depend on `grace_blocks` at all.
//
// WHY THE WINDOW IS SHRUNK, which is a finding and not a convenience. At the
// production window the lookahead was ALREADY almost inert: `grace_blocks` is
// capped at CRYPTONOTE_REWARD_BLOCKS_WINDOW = 100 and the long-term window is
// CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE = 100 000, so the zeroes move the
// median by at most 100 ranks in 100 000 — and on any locally flat stretch of the
// weight distribution, by nothing whatever. Two bites confirmed it: restoring the
// graced shape verbatim left both a floor-pinned fixture and a 5 000-block
// high-median fixture bit-for-bit unchanged. So a test of this property written
// at production constants CANNOT FAIL, and would have been a green that
// establishes nothing.
//
// Setting the long-term window to the grace cap makes the zeroes saturate it, so
// the graced and un-graced medians genuinely differ and the assertion below has
// teeth. What it pins is the MECHANISM — the served ladder is a function of chain
// state and not of a caller-supplied lookahead — which is the property FL-R20
// actually rules on; the production-scale magnitude of the thing being deleted is
// the paragraph above, not this test's subject.
//
// SUBJECT ASSERTION FIRST (rule 47), because the floor makes this easy to get
// wrong: where the long-term median sits at the penalty-free zone, inserting
// zeroes changes nothing no matter how many, since `Mlw` is floored there. The
// fixture is checked for a median above the floor before anything is asserted.
TEST(fee_2021_scaling, grace_blocks_do_not_move_the_served_ladder)
{
  PREFIX_WINDOW_DB(HF_VERSION_2021_SCALING, CRYPTONOTE_REWARD_BLOCKS_WINDOW, HighLongTermMedianTestDB);

  uint64_t long_term_effective_median = 0;
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit(&long_term_effective_median));
  ASSERT_GT(long_term_effective_median, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
      << "fixture median is at the floor, where grace is inert for reasons "
         "unrelated to this change — the assertions below would prove nothing";

  std::vector<uint64_t> no_grace, max_grace;
  bc->get_dynamic_base_fee_estimate_2021_scaling(0, no_grace);
  bc->get_dynamic_base_fee_estimate_2021_scaling(CRYPTONOTE_REWARD_BLOCKS_WINDOW, max_grace);
  ASSERT_EQ(no_grace.size(), 3);
  ASSERT_EQ(no_grace, max_grace)
      << "grace_blocks still moves the served ladder; FL-R20 deletes the lookahead";

  // And FL-R6's identity holds on this fixture too, not only on the empty one.
  ASSERT_EQ(no_grace[0], bc->get_current_fee_per_byte());
}

// The FL-R23 ring's two paths agree — the gate that turns "a warm node and a
// restarted node admit the same transaction" from a claim into a check.
//
// Warm: init at height S (a cold rebuild), then advance the chain G + 1 times
// so that EVERY entry now in the ring arrived by an O(1) push from the live
// m_long_term_effective_median_block_weight and the memoized volume window.
// Cold: rebuild from chain history at the same tip — prefix-sum windows and a
// stepped rolling median. If the cold path reconstructs any height's M, C or
// R differently from what the live path computed when that height was the
// tip, the two rings differ and this fails.
//
// Subject assertions first (rule 47): the ring is full and consecutive, and
// the floors are NOT all equal — on a flat fixture equality is vacuous.
TEST(fee_2021_scaling, warm_ring_equals_cold_reconstruction)
{
  const uint64_t start = 800; // > SHEKYL_TX_VOLUME_WINDOW + G, so every window is full
  const uint64_t G = SHEKYL_RELAY_FLOOR_LOOKBACK;
  VaryingChainTestDB* db = new VaryingChainTestDB(start);
  PREFIX_WINDOW_DBPTR(HF_VERSION_2021_SCALING, CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE, db);

  for (uint64_t i = 1; i <= G + 1; ++i)
  {
    db->set_height(start + i);
    ASSERT_TRUE(bc->update_next_cumulative_weight_limit());
  }
  const uint64_t tip = start + G + 1;
  const auto warm = bc->relay_floor_ring();

  ASSERT_EQ(warm.size(), G + 1) << "the ring must hold exactly G + 1 entries after G + 1 pushes";
  for (size_t k = 0; k < warm.size(); ++k)
    ASSERT_EQ(warm[k].first, tip - G + k) << "ring heights must be consecutive and end at the tip";
  uint64_t lo = warm.front().second, hi = lo;
  for (const auto& e : warm) { lo = std::min(lo, e.second); hi = std::max(hi, e.second); }
  ASSERT_LT(lo, hi) << "fixture produced a flat ring; equality below would prove nothing";
  // The C AXIS, separately: the volume window must differ across the ring's
  // heights, or the cold path could feed every height the tip's window and
  // still agree. A flat-floor check cannot see this — M alone can make the
  // floors vary while C is rail-pinned and constant, which is exactly what
  // happened with the first fixture.
  ASSERT_NE(VaryingChainTestDB::window_sum(tip - G), VaryingChainTestDB::window_sum(tip))
      << "fixture's volume window is flat across the ring; the C axis would be untested";

  bc->rebuild_relay_floor_ring(tip);
  const auto cold = bc->relay_floor_ring();
  ASSERT_EQ(warm, cold) << "cold reconstruction disagrees with the warm push at the same tip";

  // And the served floor IS the ring's top — the identity every consumer
  // of get_current_fee_per_byte now rests on.
  ASSERT_EQ(cold.back().second, bc->get_current_fee_per_byte());
}

// A pop moves the tip BACKWARDS, and the ring must not carry entries from the
// future it no longer has. Continuity fails, the ring rebuilds, and the result
// is what a node that never saw those blocks would hold.
TEST(fee_2021_scaling, ring_rebuilds_when_the_tip_moves_backwards)
{
  const uint64_t G = SHEKYL_RELAY_FLOOR_LOOKBACK;
  VaryingChainTestDB* db = new VaryingChainTestDB(806);
  PREFIX_WINDOW_DBPTR(HF_VERSION_2021_SCALING, CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE, db);
  const auto at_806 = bc->relay_floor_ring();
  ASSERT_EQ(at_806.back().first, 806u);

  db->set_height(803);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());
  const auto at_803 = bc->relay_floor_ring();
  ASSERT_EQ(at_803.size(), G + 1);
  ASSERT_EQ(at_803.back().first, 803u) << "the ring must follow the tip backwards";
  for (const auto& e : at_803)
    ASSERT_LE(e.first, 803u) << "no entry may come from a height the chain no longer has";
  // The overlapping heights are the same numbers either way — reconstruction
  // is a function of chain state, not of the path taken to reach it.
  for (const auto& e : at_803)
    for (const auto& f : at_806)
      if (e.first == f.first)
        ASSERT_EQ(e.second, f.second) << "height " << e.first << " priced differently after a pop";
}

TEST(fee_2021_scaling, rounding)
{
  ASSERT_EQ(cryptonote::round_money_up("27810", 3), "27900.000000000");
  ASSERT_EQ(cryptonote::round_money_up("37.94", 3), "38.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.5555", 3), "0.556000000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 3), "0.002350000");

  ASSERT_EQ(cryptonote::round_money_up("27810", 2), "28000.000000000");
  ASSERT_EQ(cryptonote::round_money_up("37.94", 2), "38.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.5555", 2), "0.560000000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 2), "0.002400000");

  ASSERT_EQ(cryptonote::round_money_up("0", 8), "0.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.0", 8), "0.000000000");
  ASSERT_EQ(cryptonote::round_money_up("50.0", 8), "50.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 8), "0.002342000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 1), "0.003000000");
  ASSERT_EQ(cryptonote::round_money_up("12345", 8), "12345.000000000");
  ASSERT_EQ(cryptonote::round_money_up("45678", 1), "50000.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.234", 1), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.000001", 4), "1.001000000");
  ASSERT_EQ(cryptonote::round_money_up("1.002001", 4), "1.003000000");

  ASSERT_EQ(cryptonote::round_money_up("1.999999", 1), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 2), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 3), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 4), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 5), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 6), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 7), "1.999999000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 8), "1.999999000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 9), "1.999999000");

  ASSERT_EQ(cryptonote::round_money_up("2.000001", 1), "3.000000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 2), "2.100000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 3), "2.010000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 4), "2.001000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 5), "2.000100000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 6), "2.000010000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 7), "2.000001000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 8), "2.000001000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 9), "2.000001000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 4000), "2.000001000");

  ASSERT_EQ(cryptonote::round_money_up("999", 2), "1000.000000000");

  ASSERT_THROW(cryptonote::round_money_up("1.23", 0), std::runtime_error);
  // Shekyl 9dp max: UINT64_MAX / 10^9 = 18446744073.709551615
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 1), std::runtime_error);
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 2), std::runtime_error);
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 12), std::runtime_error);
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 19), std::runtime_error);
}
