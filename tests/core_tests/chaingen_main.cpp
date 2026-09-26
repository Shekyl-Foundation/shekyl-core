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
#include "chaingen_tests_list.h"
#include "common/util.h"
#include "common/command_line.h"

#include <boost/regex.hpp>

namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string> arg_test_data_path              = {"test_data_path", "", ""};
  const command_line::arg_descriptor<bool>        arg_generate_and_play_test_data = {"generate_and_play_test_data", ""};
  const command_line::arg_descriptor<std::string> arg_filter                      = { "filter", "Regular expression filter for which tests to run" };
  const command_line::arg_descriptor<bool>        arg_list_tests                  = {"list_tests", ""};
}

int main(int argc, char* argv[])
{
  TRY_ENTRY();
  tools::on_startup();
  epee::string_tools::set_module_name_and_folder(argv[0]);

  //set up logging options
  mlog_configure(mlog_get_default_log_path("core_tests.log"), true);
  mlog_set_log_level(2);
  
  po::options_description desc_options("Allowed options");
  command_line::add_arg(desc_options, command_line::arg_help);
  command_line::add_arg(desc_options, arg_test_data_path);
  command_line::add_arg(desc_options, arg_generate_and_play_test_data);
  command_line::add_arg(desc_options, arg_filter);
  command_line::add_arg(desc_options, arg_list_tests);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << desc_options << std::endl;
    return 0;
  }

  const std::string filter = tools::glob_to_regex(command_line::get_arg(vm, arg_filter));
  boost::smatch match;

  size_t tests_count = 0;
  std::vector<std::string> failed_tests;
  std::string tests_folder = command_line::get_arg(vm, arg_test_data_path);
  bool list_tests = false;
  if (command_line::get_arg(vm, arg_generate_and_play_test_data) || (list_tests = command_line::get_arg(vm, arg_list_tests)))
  {
    // chaingen builds blocks and coinbases only. Its user-transaction
    // builder (construct_tx_rct over the C++ construct_tx*) went dark on
    // 2026-05-05 when the transaction format moved to FCMP++/PQC and the
    // C++ builder was never taught it — a capability gap, not a handoff —
    // and every test that needed one was disabled then. Builder and tests
    // were deleted together with the C++ tx_extra codec; the per-test record
    // of what each exercised and where the case lives now is
    // TX_EXTRA_RUST_CUTOVER.md §9.1. A validating Rust-built spend exists and
    // is gated per PR (regtest_e2e e2e_fcmp_spend_accepted_by_daemon); a
    // chain containing one that then reorgs does not — FOLLOWUPS
    // "user-transaction chain cases", owner E2's corpus.
    GENERATE_AND_PLAY(one_block);
    GENERATE_AND_PLAY(economics_c2a_prime_layer3_pop_replay);
    GENERATE_AND_PLAY(archival_budget_conservation_boundary);
    // Block verification tests
    GENERATE_AND_PLAY(gen_block_big_major_version);
    GENERATE_AND_PLAY(gen_block_big_minor_version);
    GENERATE_AND_PLAY(gen_block_ts_below_median_in_bootstrap);
    GENERATE_AND_PLAY(gen_block_ts_at_genesis_in_deep_bootstrap);
    GENERATE_AND_PLAY(gen_block_ts_in_past);
    GENERATE_AND_PLAY(gen_block_ts_at_median);
    GENERATE_AND_PLAY(gen_block_alt_ts_above_ftl);
    GENERATE_AND_PLAY(gen_block_pow_verifier_failure_main);
    GENERATE_AND_PLAY(gen_block_pow_verifier_failure_alt);
    GENERATE_AND_PLAY(gen_block_alt_ts_window_truncation);
    GENERATE_AND_PLAY(gen_reorg_watermark_refused_switch);
    GENERATE_AND_PLAY(gen_checkpoint_conflict_rollback);
    GENERATE_AND_PLAY(gen_block_ts_in_future);
    GENERATE_AND_PLAY(gen_block_invalid_prev_id);
    GENERATE_AND_PLAY(gen_block_already_known_is_already_exists);
    GENERATE_AND_PLAY(gen_block_already_known_in_alt_store_is_already_exists);
    GENERATE_AND_PLAY(gen_block_invalid_attestation_root);
    GENERATE_AND_PLAY(gen_block_no_miner_tx);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_low);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_high);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_timestamp_in_past);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_timestamp_in_future);
    GENERATE_AND_PLAY(gen_block_height_is_low);
    GENERATE_AND_PLAY(gen_block_height_is_high);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_2_tx_gen_in);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_2_in);
    GENERATE_AND_PLAY(gen_block_miner_tx_with_txin_to_key);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_is_small);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_is_big);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_no_out);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_out_to_alice);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_has_no_view_tag_before_hf_view_tags);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_has_view_tag_before_hf_view_tags);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_has_view_tag_from_hf_view_tags);
    GENERATE_AND_PLAY(gen_block_missing_tx);
    GENERATE_AND_PLAY(gen_block_is_too_big);
    // Disabled: no "late v1 coinbase" era in Shekyl (1 = 1 = genesis)
    // GENERATE_AND_PLAY(gen_block_late_v1_coinbase_tx);

    // Transaction verification, FCMP++ transaction and staking tests were
    // removed 2026-05-05 (gen_tx_*, gen_fcmp_*, gen_staking_*/gen_claim_*/
    // gen_stake_*, txpool_*), and the last user-transaction tests
    // (gen_simple_chain_*, gen_chain_switch_1, gen_uint_overflow_*,
    // gen_block_reward, gen_bpp_*) on 2026-09-23 — see the note above the
    // enabled list. Monero-era v2 mixin/dust, RCT, Borromean and old BP
    // tests are gone: Shekyl enforces v3 with PQC auth for every
    // non-coinbase transaction from genesis.

    GENERATE_AND_PLAY(gen_block_low_coinbase);

    el::Level level = (failed_tests.empty() ? el::Level::Info : el::Level::Error);
    if (!list_tests)
    {
      MLOG(level, "\nREPORT:");
      MLOG(level, "  Test run: " << tests_count);
      MLOG(level, "  Failures: " << failed_tests.size());
    }
    if (!failed_tests.empty())
    {
      MLOG(level, "FAILED TESTS:");
      for (auto test_name : failed_tests)
      {
        MLOG(level, "  " << test_name);
      }
    }
  }
  else
  {
    MERROR("Wrong arguments");
    return 2;
  }

  return failed_tests.empty() ? 0 : 1;

  CATCH_ENTRY_L0("main", 1);
}
