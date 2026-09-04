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

#pragma once 
#include "chaingen.h"

template<size_t invalid_block_idx = 0>
class gen_block_verification_base : public test_chain_unit_base
{
public:
  gen_block_verification_base()
  {
    REGISTER_CALLBACK("check_block_purged", gen_block_verification_base<invalid_block_idx>::check_block_purged);
  }

  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
  {
    if (invalid_block_idx == event_idx)
      return bvc.m_verifivation_failed;
    else
      return !bvc.m_verifivation_failed;
  }

  bool check_block_purged(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_block_verification_base::check_block_purged");

    CHECK_TEST_CONDITION(invalid_block_idx < ev_index);
    CHECK_EQ(0, c.get_pool_transactions_count());
    CHECK_EQ(invalid_block_idx, c.get_current_blockchain_height());

    return true;
  }
};

template<size_t expected_blockchain_height>
struct gen_block_accepted_base : public test_chain_unit_base
{
  gen_block_accepted_base()
  {
    REGISTER_CALLBACK("check_block_accepted", gen_block_accepted_base::check_block_accepted);
  }

  bool check_block_accepted(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_block_accepted_base::check_block_accepted");

    CHECK_EQ(0, c.get_pool_transactions_count());
    CHECK_EQ(expected_blockchain_height, c.get_current_blockchain_height());

    return true;
  }
};

// CEN-D2 (PR #604): the two PoW-verdict CONSUMERS reject a block whose
// longhash the verifier could not compute. The unit tests in
// pow_longhash_gate.cpp pin what get_block_longhash / get_altblock_longhash
// *report*; these pin that handle_block_to_main_chain and
// handle_alternative_block *act* on that report — reverting either consumer
// to ignore the bool leaves every unit test green.
//
// Fidelity to the defect: the harness runs at the test difficulty (1), which
// is exactly where the 0xff belt fails open — check_hash(0xff…, 1) passes —
// so a consumer that trusts the sentinel instead of the verdict accepts the
// block and the test fails. The failing schema is installed by a replay
// callback, so block GENERATION (which mines a real nonce) is unaffected;
// only the submission under test sees the failing verifier.
//
// The rejection must also be attribution-correct: m_verifivation_failed
// without m_bad_pow. A local verifier failure is not evidence against the
// block — it is unproven, not disproven — and m_bad_pow drives peer
// punishment.
class gen_block_pow_verifier_failure_base : public test_chain_unit_base
{
public:
  gen_block_pow_verifier_failure_base(size_t invalid_block_idx, uint64_t expected_height);
  ~gen_block_pow_verifier_failure_base();

  bool install_failing_pow_schema(cryptonote::core& c, size_t ev_index,
    const std::vector<test_event_entry>& events);
  bool check_rejected_unproven(cryptonote::core& c, size_t ev_index,
    const std::vector<test_event_entry>& events);
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc,
    size_t event_idx, const cryptonote::block& blk);

private:
  const size_t m_invalid_block_idx;
  const uint64_t m_expected_height;
  bool m_saw_expected_rejection = false;
};

// Event layout: 0 genesis, 1 install-callback, 2 the candidate (rejected),
// 3 the check/restore callback. Height must still be 1 (genesis only).
struct gen_block_pow_verifier_failure_main : public gen_block_pow_verifier_failure_base
{
  gen_block_pow_verifier_failure_main() : gen_block_pow_verifier_failure_base(2, 1) {}
  bool generate(std::vector<test_event_entry>& events) const;
};

// Event layout: 0 genesis, 1-2 main blocks, 3 install-callback, 4 the alt
// candidate forked at blk_1 (rejected), 5 the check/restore callback. The
// alt candidate is a normal block mined to a second account, so it differs
// from blk_2 by its miner tx alone -- the ONLY reason it can be rejected is
// the verifier failure. Main height must still be 3.
struct gen_block_pow_verifier_failure_alt : public gen_block_pow_verifier_failure_base
{
  gen_block_pow_verifier_failure_alt() : gen_block_pow_verifier_failure_base(4, 3) {}
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_big_major_version : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_big_minor_version : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// C2-R3-Q2 (CONSENSUS_C2_R3_TIMESTAMPS.md §5): there is no bootstrap
// carve-out — below SHEKYL_DAA_MTP_WINDOW blocks of history the window is
// right-padded with the genesis timestamp and the median check runs from
// block 1. Replaces gen_block_ts_not_checked, which asserted the deleted
// carve-out (any timestamp accepted below 11 blocks of history).
struct gen_block_ts_below_median_in_bootstrap : public gen_block_verification_base<SHEKYL_DAA_MTP_WINDOW - 1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_ts_in_past : public gen_block_verification_base<SHEKYL_DAA_MTP_WINDOW>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// C2-R3-Q2 + the genesis-timestamp cache: the padding value must be the
// CHAIN's genesis timestamp, not whatever block 0 the store held at
// Blockchain::init. Core-test replay installs its own genesis via
// reset_and_set_genesis_block, so a padding value cached only at init pads
// deep-bootstrap windows with the superseded genesis (timestamp 0),
// dragging the median low enough to accept a candidate the ruled rule
// rejects. At h = 4 (three rewound blocks + genesis) correct padding makes
// the median the genesis timestamp itself, so a candidate EQUAL to it must
// be rejected under the strict boundary; stale-0 padding yields median 0
// and accepts it.
struct gen_block_ts_at_genesis_in_deep_bootstrap : public gen_block_verification_base<4>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// C2-R3-Q1 (CONSENSUS_C2_R3_TIMESTAMPS.md §4): the MTP boundary is strict —
// a timestamp EQUAL to the median of the previous 11 is rejected.
struct gen_block_ts_at_median : public gen_block_verification_base<SHEKYL_DAA_MTP_WINDOW>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_ts_in_future : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// C2-R3-Q3 (CONSENSUS_C2_R3_TIMESTAMPS.md §6): FTL applies at alt ADMISSION,
// not only at promotion. Event layout: 0 genesis, 1–2 main blocks, 3 the
// future-dated alt candidate (so invalid_block_idx == final main height == 3
// and the inherited purged callback's height assert holds).
struct gen_block_alt_ts_above_ftl : public gen_block_verification_base<3>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// C2-R3-Q1 sub-a (CONSENSUS_C2_R3_TIMESTAMPS.md §4.2a): the alt-path MTP
// window is the NEWEST 11 timestamps, not the whole alt chain (whose even
// lengths the inherited epee median silently averaged). Event layout:
// 0 genesis, 1..MTP+2 main blocks (main must out-weigh the alt fork or the
// alt chain reorgs into main and the candidate never takes the alt path),
// then MTP+1 alt blocks forked at genesis, then the candidate at index
// 2*MTP + 4. The candidate timestamp sits strictly above the whole-window
// (averaged) median but below the newest-11 median, isolating the
// window-selection axis. The purged callback's height assert cannot hold
// here (alt events inflate indices past the main height), so this test
// asserts through the per-event bvc check plus its own callback.
struct gen_block_alt_ts_window_truncation : public gen_block_verification_base<2 * SHEKYL_DAA_MTP_WINDOW + 4>
{
  gen_block_alt_ts_window_truncation()
  {
    REGISTER_CALLBACK("check_alt_stored_top_unmoved", gen_block_alt_ts_window_truncation::check_alt_stored_top_unmoved);
  }
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_alt_stored_top_unmoved(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_block_invalid_prev_id : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
};

struct gen_block_no_miner_tx : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_invalid_attestation_root : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_low : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_high : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_timestamp_in_past : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_timestamp_in_future : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_height_is_low : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_height_is_high : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_2_tx_gen_in : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_2_in : public gen_block_verification_base<CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + 1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_with_txin_to_key : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_is_small : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_is_big : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_no_out : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// Inverted by F-H (consensus coinbase output-count cap = 1): inherited Monero
// behavior let a miner pay an arbitrary extra address in the coinbase, and this
// test asserted that ACCEPTANCE. The second output is now exactly the
// unpriced-burden state the cap makes unrepresentable, so the same
// construction pins the REJECTION.
struct gen_block_miner_tx_has_out_to_alice : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_has_invalid_tx : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_is_too_big : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_late_v1_coinbase_tx : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_late_v1_coinbase_tx> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(1, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_low_coinbase : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_low_coinbase> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_EXACT_COINBASE, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_miner_tx_out_has_no_view_tag_before_hf_view_tags : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_VIEW_TAGS+1, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_miner_tx_out_has_view_tag_before_hf_view_tags : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_has_view_tag_from_hf_view_tags : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_miner_tx_out_has_view_tag_from_hf_view_tags> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_VIEW_TAGS, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};
