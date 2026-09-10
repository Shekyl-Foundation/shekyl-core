// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// @file
/// @brief Block-ingest ABI: header constants pinned to the Rust type.
///
/// Pins the hand-written `SHEKYL_BLOCK_INGEST_*` constants by searching
/// the byte domain rather than restating a discriminant. P2P may not
/// drop on `is_rejected`; drop is `shekyl_drop_verdict_severs`.

#include "gtest/gtest.h"

#include <cstdint>
#include <vector>

#include "cryptonote_basic/block_ingest.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
  std::vector<uint8_t> all_bytes()
  {
    std::vector<uint8_t> bytes;
    bytes.reserve(256);
    for (int b = 0; b <= 0xff; ++b)
      bytes.push_back(static_cast<uint8_t>(b));
    return bytes;
  }
}

TEST(peer_policy_block_ingest, exactly_two_bytes_are_rejections_and_one_is_bad_pow)
{
  std::vector<uint8_t> rejected;
  std::vector<uint8_t> bad_pow;
  for (const uint8_t byte : all_bytes())
  {
    if (shekyl_block_ingest_is_rejected(byte))
      rejected.push_back(byte);
    if (shekyl_block_ingest_is_bad_pow(byte))
      bad_pow.push_back(byte);
  }

  ASSERT_EQ(2u, rejected.size());
  EXPECT_EQ(SHEKYL_BLOCK_INGEST_REJECTED, rejected[0]);
  EXPECT_EQ(SHEKYL_BLOCK_INGEST_REJECTED_BAD_POW, rejected[1]);
  ASSERT_EQ(1u, bad_pow.size());
  EXPECT_EQ(SHEKYL_BLOCK_INGEST_REJECTED_BAD_POW, bad_pow.front());
  EXPECT_TRUE(shekyl_block_ingest_is_rejected(bad_pow.front()));
}

TEST(peer_policy_block_ingest, missing_txs_is_not_a_rejection)
{
  EXPECT_TRUE(shekyl_block_ingest_missing_txs(SHEKYL_BLOCK_INGEST_MISSING_TXS));
  EXPECT_FALSE(shekyl_block_ingest_is_rejected(SHEKYL_BLOCK_INGEST_MISSING_TXS));
}

TEST(peer_policy_block_ingest, a_value_initialised_block_context_is_unclassified)
{
  cryptonote::block_verification_context bvc{};
  EXPECT_EQ(SHEKYL_BLOCK_INGEST_UNCLASSIFIED, bvc.m_outcome);
  EXPECT_FALSE(cryptonote::block_rejected(bvc));
  EXPECT_FALSE(cryptonote::block_added(bvc));
  EXPECT_FALSE(shekyl_drop_verdict_severs(bvc.m_drop_verdict));
}

TEST(peer_policy_block_ingest, reject_block_form_records_rejected_and_does_not_by_itself_prove_a_drop)
{
  cryptonote::block_verification_context bvc{};
  EXPECT_FALSE(cryptonote::reject_block_form(bvc));
  EXPECT_TRUE(cryptonote::block_rejected(bvc));
  EXPECT_TRUE(shekyl_drop_verdict_severs(bvc.m_drop_verdict));
}

TEST(peer_policy_block_ingest, reject_block_internal_does_not_sever)
{
  cryptonote::block_verification_context bvc{};
  EXPECT_FALSE(cryptonote::reject_block_internal(bvc));
  EXPECT_TRUE(cryptonote::block_rejected(bvc));
  EXPECT_FALSE(shekyl_drop_verdict_severs(bvc.m_drop_verdict));
}

TEST(peer_policy_block_ingest, first_writer_wins_and_a_later_added_cannot_clear_a_rejection)
{
  cryptonote::block_verification_context bvc{};
  cryptonote::reject_block_form(bvc);
  cryptonote::record_block_ingest(bvc, SHEKYL_BLOCK_INGEST_ADDED);
  EXPECT_TRUE(cryptonote::block_rejected(bvc));
  EXPECT_FALSE(cryptonote::block_added(bvc));
}

TEST(peer_policy_block_ingest, the_both_false_arms_are_not_rejections)
{
  const uint8_t keep[] = {
    SHEKYL_BLOCK_INGEST_DEGRADED_KEEP,
    SHEKYL_BLOCK_INGEST_ALT_STORED,
    SHEKYL_BLOCK_INGEST_ORPHANED,
    SHEKYL_BLOCK_INGEST_ALREADY_EXISTS,
  };
  for (const uint8_t arm : keep)
  {
    EXPECT_FALSE(shekyl_block_ingest_is_rejected(arm));
    EXPECT_FALSE(shekyl_block_ingest_is_added(arm));
  }
}

TEST(peer_policy_block_ingest, announce_action_predicates_are_exclusive_over_the_byte_domain)
{
  for (const uint8_t byte : all_bytes())
  {
    const int hits =
        (shekyl_block_announce_re_request_txs(byte) ? 1 : 0)
        + (shekyl_block_announce_drop(byte) ? 1 : 0)
        + (shekyl_block_announce_our_failure(byte) ? 1 : 0)
        + (shekyl_block_announce_relay(byte) ? 1 : 0)
        + (shekyl_block_announce_request_history(byte) ? 1 : 0);
    EXPECT_LE(hits, 1) << "byte " << static_cast<int>(byte);
    if (shekyl_block_announce_heavier_score(byte))
      EXPECT_TRUE(shekyl_block_announce_drop(byte));
  }
}

TEST(peer_policy_block_ingest, announce_missing_txs_wins_over_a_severing_drop)
{
  cryptonote::block_verification_context bvc{};
  cryptonote::record_block_ingest(bvc, SHEKYL_BLOCK_INGEST_MISSING_TXS);
  shekyl_drop_verdict_classify(&bvc.m_drop_verdict, SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM);
  const uint8_t action = cryptonote::block_announce_action(bvc, false);
  EXPECT_TRUE(cryptonote::block_announce_re_request_txs(action));
  EXPECT_FALSE(cryptonote::block_announce_drop(action));
}

TEST(peer_policy_block_ingest, sync_a_form_rejection_severs_and_an_orphan_does_not)
{
  cryptonote::block_verification_context rejected{};
  EXPECT_FALSE(cryptonote::reject_block_form(rejected));
  EXPECT_TRUE(cryptonote::block_sync_drop(cryptonote::block_sync_action(rejected)));

  cryptonote::block_verification_context orphaned{};
  cryptonote::record_block_ingest(orphaned, SHEKYL_BLOCK_INGEST_ORPHANED);
  const uint8_t action = cryptonote::block_sync_action(orphaned);
  EXPECT_TRUE(cryptonote::block_sync_orphan_resync(action));
  EXPECT_FALSE(cryptonote::block_sync_drop(action));
}
