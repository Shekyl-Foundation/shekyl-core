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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "chaingen.h"
#include "block_validation.h"

using namespace epee;
#include "crypto/pow_registry.h"
#include "crypto/pow_schema.h"

using namespace cryptonote;

// The inherited Monero-era `lift_up_difficulty` helper (which exercised
// the deleted CryptoNote DAA against `DIFFICULTY_TARGET_V1`) was removed
// in Phase 4 of the LWMA-1 migration along with `gen_block_invalid_nonce`
// and `gen_block_invalid_binary_format` — both tests' generators
// depended on the helper. See `docs/completed/DAA_LWMA1.md` §9.1 / drift F3
// in `docs/completed/DAA_LWMA1_PHASE4_PREFLIGHT.md` §3, and rule
// `60-no-monero-legacy.mdc`.

#define BLOCK_VALIDATION_INIT_GENERATE()                                                \
  GENERATE_ACCOUNT(miner_account);                                                      \
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, 1338224400);

//----------------------------------------------------------------------------------------------------------------------
// Tests

bool gen_block_big_major_version::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_major_ver, 255);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_big_minor_version::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_minor_ver, 0, 255);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_below_median_in_bootstrap::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, SHEKYL_DAA_MTP_WINDOW - 2);

  // C2-R3-Q2: the chain holds SHEKYL_DAA_MTP_WINDOW - 1 blocks, one short of
  // a full window; the window is right-padded with the genesis timestamp and
  // the median check runs anyway. A timestamp an hour before genesis sits
  // below any element of that window and must be rejected. (The inherited
  // carve-out accepted it — this generator replaced gen_block_ts_not_checked,
  // which asserted exactly that acceptance.)
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_timestamp, 0, 0, blk_0.timestamp - 60 * 60);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_in_past::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, SHEKYL_DAA_MTP_WINDOW - 1);

  // Pick a timestamp strictly below the median of the MTP window. For
  // the post-LWMA-1 window size 11, the median is at index 5 (0-based);
  // `MTP/2 - 1 == 4` is one position below the median. For the legacy
  // window size 60 the same expression picked index 29, one position
  // below the upper-median candidate (indices 29/30 in a 60-window).
  // The intent is identical in both regimes: a timestamp that, when
  // promoted to the head of the window, sits strictly below the
  // median and therefore must be rejected by the MTP rule.
  uint64_t ts_below_median = std::get<block>(events[SHEKYL_DAA_MTP_WINDOW / 2 - 1]).timestamp;
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_timestamp, 0, 0, ts_below_median);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_at_genesis_in_deep_bootstrap::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, 3);

  // Window at h = 4: the four real timestamps [g, g+T, g+2T, g+3T] plus
  // seven genesis pads -> sorted index 5 IS the genesis timestamp, so a
  // candidate equal to it violates the strict boundary. If the padding
  // value is a stale init-time genesis (timestamp 0 on fakechain) the
  // median collapses to 0 and this candidate is wrongly accepted.
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_timestamp, 0, 0, blk_0.timestamp);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_at_median::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, SHEKYL_DAA_MTP_WINDOW - 1);

  // C2-R3-Q1: the strict boundary itself. REWIND timestamps ascend by T per
  // block, so chain order equals sorted order and the window's sorted
  // index-5 element is events[SHEKYL_DAA_MTP_WINDOW / 2]'s timestamp — the
  // exact median. Equality must be rejected (`>` , not `>=`).
  uint64_t ts_at_median = std::get<block>(events[SHEKYL_DAA_MTP_WINDOW / 2]).timestamp;
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_timestamp, 0, 0, ts_at_median);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_in_future::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_timestamp, 0, 0, time(NULL) + 60*60 + SHEKYL_DAA_FTL_SECONDS);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_alt_ts_above_ftl::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner_account);
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner_account);

  // C2-R3-Q3: this candidate forks from blk_1 while the main tip is blk_2,
  // so it takes handle_alternative_block; its timestamp is beyond
  // local_clock + FTL and must be refused at admission rather than parked
  // in the alt store until promotion re-checks it.
  block blk_alt;
  generator.construct_block_manually(blk_alt, blk_1, miner_account, test_generator::bf_timestamp, 0, 0, time(NULL) + 60*60 + SHEKYL_DAA_FTL_SECONDS);
  events.push_back(blk_alt);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_alt_ts_window_truncation::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  // Main chain: SHEKYL_DAA_MTP_WINDOW + 2 blocks past genesis, so its
  // cumulative difficulty (fixed at 1 per block) strictly exceeds anything
  // the shorter alt fork below can accumulate — no reorg, the candidate
  // stays on the alternative path.
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, SHEKYL_DAA_MTP_WINDOW + 2);

  // Alt fork at genesis: SHEKYL_DAA_MTP_WINDOW + 1 blocks (one longer than
  // the MTP window), timestamps ascending by T per block.
  cryptonote::block alt_prev = blk_0;
  for (size_t i = 0; i < SHEKYL_DAA_MTP_WINDOW + 1; ++i)
  {
    cryptonote::block blk_a;
    generator.construct_block(blk_a, alt_prev, miner_account);
    events.push_back(blk_a);
    alt_prev = blk_a;
  }

  // With T = 120 the 12 alt timestamps are genesis + 120..1440. The
  // inherited code medianed the WHOLE alt chain — epee's even-window arm
  // averages the two middle elements: (g+720 + g+840)/2 = g+780. The ruled
  // window is the newest 11 (g+240..g+1440), sorted index 5 = g+840. A
  // candidate at g+800 is strictly above the inherited median (accepted
  // before this round) and at-or-below the ruled one (rejected after) —
  // it isolates the window-selection axis from the boundary axis.
  block blk_bad;
  generator.construct_block_manually(blk_bad, alt_prev, miner_account, test_generator::bf_timestamp, 0, 0, blk_0.timestamp + 800);
  events.push_back(blk_bad);

  DO_CALLBACK(events, "check_alt_stored_top_unmoved");

  return true;
}

bool gen_block_alt_ts_window_truncation::check_alt_stored_top_unmoved(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_alt_ts_window_truncation::check_alt_stored_top_unmoved");

  // The well-formed alt blocks really entered the alt store — proving the
  // candidate was evaluated on the alternative path rather than refused
  // earlier — and neither the candidate nor the fork moved the main tip.
  CHECK_EQ(SHEKYL_DAA_MTP_WINDOW + 1, c.get_alternative_blocks_count());
  CHECK_EQ(SHEKYL_DAA_MTP_WINDOW + 3, c.get_current_blockchain_height());

  return true;
}

bool gen_block_invalid_prev_id::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  crypto::hash prev_id = get_block_hash(blk_0);
  reinterpret_cast<char &>(prev_id) ^= 1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_prev_id, 0, 0, 0, prev_id);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_invalid_prev_id::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (1 == event_idx)
    return bvc.m_marked_as_orphaned && !bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
  else
    return !bvc.m_marked_as_orphaned && bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}

bool gen_block_invalid_attestation_root::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  // ARCHIVAL_CREDIT_WIRE.md §3: null_hash is the banned dual-empty; slice-1
  // consensus accepts only empty_attestation_root() until the cutover.
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account);
  blk_1.attestation_root = crypto::null_hash;
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_no_miner_tx::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  transaction miner_tx;
  miner_tx.set_null();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_low::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  --miner_tx.unlock_time;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_high::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  ++miner_tx.unlock_time;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_timestamp_in_past::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.unlock_time = blk_0.timestamp - 10 * 60;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_timestamp_in_future::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.unlock_time = blk_0.timestamp + 3 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW * SHEKYL_DAA_TARGET_SECONDS;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_height_is_low::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  std::get<txin_gen>(miner_tx.vin[0]).height--;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_height_is_high::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  std::get<txin_gen>(miner_tx.vin[0]).height++;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_2_tx_gen_in::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);

  txin_gen in;
  in.height = get_block_height(blk_0) + 1;
  miner_tx.vin.push_back(in);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_2_in::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS(events, blk_0r, blk_0, miner_account);

  txin_to_key fake_spend;
  fake_spend.amount = 0;
  fake_spend.key_offsets.push_back(0);
  crypto::generate_random_bytes_thread_safe(32, reinterpret_cast<uint8_t*>(&fake_spend.k_image));

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vin.push_back(fake_spend);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_with_txin_to_key::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  txin_to_key fake_spend;
  fake_spend.amount = 0;
  fake_spend.key_offsets.push_back(0);
  crypto::generate_random_bytes_thread_safe(32, reinterpret_cast<uint8_t*>(&fake_spend.k_image));

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vin[0] = fake_spend;
  miner_tx.pqc_auths.resize(1);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_is_small::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vout[0].amount /= 2;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_is_big::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vout[0].amount *= 2;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_no_out::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vout.clear();
  miner_tx.ct_signatures.outPk.clear();
  miner_tx.ct_signatures.enc_amounts.clear();
  miner_tx.ct_signatures.enc_labels.clear();
  miner_tx.extra.clear();
  miner_tx.invalidate_hashes();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_out_to_alice::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  GENERATE_ACCOUNT(alice);

  keypair txkey;
  MAKE_MINER_TX_AND_KEY_MANUALLY(miner_tx, blk_0, &txkey);

  uint64_t alice_amount = miner_tx.vout[0].amount / 2;
  miner_tx.vout[0].amount -= alice_amount;

  if (!append_v3_output_to_miner_tx(miner_tx, txkey.sec, alice.get_keys().m_account_address, alice_amount))
    return false;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  // F-H: a two-output coinbase must be refused (output-count cap = 1); this
  // test asserted acceptance until the cap landed -- see the header comment.
  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_has_invalid_tx::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  std::vector<crypto::hash> tx_hashes;
  tx_hashes.push_back(crypto::hash());

  block blk_1;
  generator.construct_block_manually_tx(blk_1, blk_0, miner_account, tx_hashes, 0);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_is_too_big::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  static const size_t tx_out_count = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1 / 2;
  uint64_t amount = get_outs_money_amount(miner_tx);
  uint64_t portion = amount / tx_out_count;
  uint64_t remainder = amount % tx_out_count;
  txout_target_v target = miner_tx.vout[0].target;
  miner_tx.vout.clear();
  miner_tx.ct_signatures.outPk.clear();
  miner_tx.ct_signatures.enc_amounts.clear();
  miner_tx.ct_signatures.enc_labels.clear();
  for (size_t i = 0; i < tx_out_count; ++i)
  {
    tx_out o;
    o.amount = portion;
    o.target = target;
    miner_tx.vout.push_back(o);
    miner_tx.ct_signatures.outPk.push_back({});
    miner_tx.ct_signatures.enc_amounts.push_back({});
    miner_tx.ct_signatures.enc_labels.push_back({});
  }
  if (0 < remainder)
  {
    tx_out o;
    o.amount = remainder;
    o.target = target;
    miner_tx.vout.push_back(o);
    miner_tx.ct_signatures.outPk.push_back({});
    miner_tx.ct_signatures.enc_amounts.push_back({});
    miner_tx.ct_signatures.enc_labels.push_back({});
  }

  block blk_1;
  if (!generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx))
    return false;

  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_late_v1_coinbase_tx::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver,
      1, 1);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_low_coinbase::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  std::vector<size_t> block_weights;
  generator.construct_block(blk_1, cryptonote::get_block_height(blk_0) + 1, cryptonote::get_block_hash(blk_0),
    miner_account, blk_0.timestamp + SHEKYL_DAA_TARGET_SECONDS, COIN + generator.get_already_generated_coins(cryptonote::get_block_hash(blk_0)),
    block_weights, {}, HF_VERSION_EXACT_COINBASE);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_has_no_view_tag_before_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  bool use_view_tags = false;

  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);

  crypto::public_key output_public_key;
  crypto::view_tag view_tag;
  cryptonote::get_output_public_key(miner_tx.vout[0], output_public_key);

  cryptonote::set_tx_out(miner_tx.vout[0].amount, output_public_key, use_view_tags, view_tag, miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(!cryptonote::get_output_view_tag(miner_tx.vout[0]), false, "output should not have a view tag");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  // Shekyl starts at HF1 where view tags are mandatory — block without view tags is rejected
  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  bool use_view_tags = false;

  BLOCK_VALIDATION_INIT_GENERATE();

  keypair txkey;
  MAKE_MINER_TX_AND_KEY_AT_HF_MANUALLY(miner_tx, blk_0, HF_VERSION_VIEW_TAGS+1, &txkey);

  crypto::public_key output_public_key;
  crypto::view_tag view_tag;
  cryptonote::get_output_public_key(miner_tx.vout[0], output_public_key);

  // remove the view tag that is currently set on the miner tx output at this point
  cryptonote::set_tx_out(miner_tx.vout[0].amount, output_public_key, use_view_tags, view_tag, miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(!cryptonote::get_output_view_tag(miner_tx.vout[0]), false, "output should not have a view tag");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_miner_tx,
      HF_VERSION_VIEW_TAGS+1, HF_VERSION_VIEW_TAGS+1, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_has_view_tag_before_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);

  CHECK_AND_ASSERT_MES(cryptonote::get_output_view_tag(miner_tx.vout[0]), false,
    "v3 miner tx output should have a view tag (HKDF-derived)");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  // Shekyl: view tags are mandatory from HF1 (genesis), so this is accepted
  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_miner_tx_out_has_view_tag_from_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_AND_KEY_AT_HF_MANUALLY(miner_tx, blk_0, HF_VERSION_VIEW_TAGS, nullptr);

  CHECK_AND_ASSERT_MES(cryptonote::get_output_view_tag(miner_tx.vout[0]), false,
    "v3 miner tx output should have a view tag (HKDF-derived)");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_miner_tx,
      HF_VERSION_VIEW_TAGS, HF_VERSION_VIEW_TAGS, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}


//----------------------------------------------------------------------------------------------------------------------
// CEN-D2: the PoW-verdict consumers (see block_validation.h for the contract)

namespace
{
// Twin of the unit-test double in pow_longhash_gate.cpp -- deliberately
// duplicated rather than shared: it is five lines of test scaffolding in a
// different binary, and any IPowSchema change breaks both loudly at compile
// time, so there is nothing here that can silently drift.
class FailingPowSchema final : public IPowSchema
{
public:
  bool hash(const void*, size_t, uint64_t, const crypto::hash*, unsigned,
    crypto::hash&) const override
  {
    return false;
  }
  const char* name() const override { return "FailingCoreTestSchema"; }
};

const FailingPowSchema g_failing_pow_schema{};
} // namespace

gen_block_pow_verifier_failure_base::gen_block_pow_verifier_failure_base(
  size_t invalid_block_idx, uint64_t expected_height)
  : m_invalid_block_idx(invalid_block_idx)
  , m_expected_height(expected_height)
{
  REGISTER_CALLBACK("install_failing_pow_schema",
    gen_block_pow_verifier_failure_base::install_failing_pow_schema);
  REGISTER_CALLBACK("check_rejected_unproven",
    gen_block_pow_verifier_failure_base::check_rejected_unproven);
}

gen_block_pow_verifier_failure_base::~gen_block_pow_verifier_failure_base()
{
  // Belt: an assertion failure between install and check must not leave the
  // override installed for whatever test runs next in this binary.
  set_pow_schema_override_for_tests(nullptr);
}

bool gen_block_pow_verifier_failure_base::install_failing_pow_schema(
  cryptonote::core& /*c*/, size_t /*ev_index*/,
  const std::vector<test_event_entry>& /*events*/)
{
  set_pow_schema_override_for_tests(&g_failing_pow_schema);
  return true;
}

bool gen_block_pow_verifier_failure_base::check_rejected_unproven(
  cryptonote::core& c, size_t /*ev_index*/,
  const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_pow_verifier_failure_base::check_rejected_unproven");
  set_pow_schema_override_for_tests(nullptr);

  // The bvc assertions only run if the candidate actually reached them; a
  // harness change that stopped submitting it would otherwise pass here
  // vacuously.
  CHECK_TEST_CONDITION(m_saw_expected_rejection);
  CHECK_EQ(m_expected_height, c.get_current_blockchain_height());
  CHECK_EQ(0, c.get_pool_transactions_count());
  return true;
}

bool gen_block_pow_verifier_failure_base::check_block_verification_context(
  const cryptonote::block_verification_context& bvc, size_t event_idx,
  const cryptonote::block& /*blk*/)
{
  if (event_idx != m_invalid_block_idx)
    return !bvc.m_verifivation_failed;

  // Rejected, and rejected as UNPROVEN: m_bad_pow would attribute a local
  // verifier failure to the sender.
  m_saw_expected_rejection = bvc.m_verifivation_failed && !bvc.m_bad_pow;
  return m_saw_expected_rejection;
}

bool gen_block_pow_verifier_failure_main::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  DO_CALLBACK(events, "install_failing_pow_schema");

  // A normal, fully valid block: mined against the real schema at generation
  // time, so the verifier failure at submission is its only defect.
  MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner_account);

  DO_CALLBACK(events, "check_rejected_unproven");

  return true;
}

bool gen_block_pow_verifier_failure_alt::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner_account);
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner_account);

  DO_CALLBACK(events, "install_failing_pow_schema");

  // Forks from blk_1 while the tip is blk_2, so it takes
  // handle_alternative_block. Mined to a second account so it differs from
  // blk_2 by its miner tx alone -- same height, same parent, valid
  // timestamp: the verifier failure is the only thing that can reject it.
  GENERATE_ACCOUNT(alt_miner_account);
  block blk_alt;
  generator.construct_block_manually(blk_alt, blk_1, alt_miner_account, test_generator::bf_none);
  events.push_back(blk_alt);

  DO_CALLBACK(events, "check_rejected_unproven");

  return true;
}
