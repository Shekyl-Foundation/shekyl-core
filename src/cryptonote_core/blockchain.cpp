// Copyright (c) 2025-2026, The Shekyl Foundation
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

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <limits>
#include <sstream>
#include <unordered_set>
#include <boost/asio/dispatch.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/format.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "tx_pool.h"
#include "tx_pqc_verify.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "serialization/binary_archive.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/events.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "hardforks/hardforks.h"
#include "shekyl/economics.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "int-util.h"
#include "common/threadpool.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "cryptonote_core.h"
#include "difficulty_engine_error.h"
#include "fcmp/ct_semantics.h"
#include "shekyl/shekyl_ffi.h"
#include "common/perf_timer.h"
#include "common/notify.h"
#include "common/varint.h"
#include "common/pruning.h"
#include "time_helper.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "blockchain"

#define FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE (100*1024*1024) // 100 MB

using namespace crypto;

//#include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;
using epee::string_tools::pod_to_hex;
extern "C" void slow_hash_allocate_state();
extern "C" void slow_hash_free_state();

DISABLE_VS_WARNINGS(4267)

#define MERROR_VER(x) MCERROR("verify", x)

// used to overestimate the block reward when estimating a per kB to use
#define BLOCK_REWARD_OVERESTIMATE (10 * 1000000000000)

namespace
{
  // LWMA-1 bridge — Phase 4 commit 3 of the DAA cutover.
  //
  // Converts the daemon's canonical inputs (oldest-first `uint64_t`
  // timestamps + `boost::multiprecision::uint128_t` cumulative
  // difficulties) into the FFI's `shekyl_u128` (lo/hi `uint64_t` pair)
  // surface, dispatches to `shekyl_difficulty_lwma1_next`, decomposes
  // the result, and throws `cryptonote::difficulty_computation_error`
  // on any non-zero return code.
  //
  // `chain_height` semantics match the spec
  // (docs/completed/DAA_LWMA1.md §5.3): the height of the chain tip (the
  // most recent block already on chain). The FFI's genesis short-circuit
  // fires when `chain_height < SHEKYL_DAA_WINDOW_N`, returning
  // `SHEKYL_DAA_GENESIS_DIFFICULTY` without inspecting the input
  // slices. When `chain_height >= SHEKYL_DAA_WINDOW_N`, the slices MUST
  // contain exactly `SHEKYL_DAA_WINDOW_N + 1` entries (consensus
  // invariant; see §5.3 step 1's boundary).
  //
  // Allocation note: this helper builds a `std::vector<shekyl_u128>`
  // (≈1.5 KiB at N=90) per call. Timestamps are also copied to a
  // contiguous `std::vector<uint64_t>` so that the FFI raw pointer is
  // valid regardless of whether the caller passes a `std::vector` or a
  // `std::deque` (the member-variable caches use `std::deque` for O(1)
  // pop_front). Both allocations are part of the same V3.1+ future
  // optimization scope documented in FOLLOWUPS.md.
  template <typename Timestamps, typename Difficulties>
  cryptonote::difficulty_type lwma1_next_difficulty(
      uint64_t chain_height,
      const Timestamps& timestamps,
      const Difficulties& cumulative_difficulties)
  {
    if (timestamps.size() != cumulative_difficulties.size())
    {
      throw cryptonote::difficulty_computation_error(
          SHEKYL_DIFFICULTY_ERR_INVALID_COUNT);
    }

    // Defense-in-depth: enforce the FFI contract at the C++ bridge
    // boundary rather than relying solely on Rust to surface a count
    // violation. The FFI contract (`shekyl/shekyl_ffi.h`) requires that
    // when `chain_height >= SHEKYL_DAA_WINDOW_N` the caller passes
    // exactly `SHEKYL_DAA_WINDOW_N + 1` window entries; under- or
    // over-populated windows in that range are a consensus-invariant
    // violation. Catching it here gives a clearer stack and avoids
    // wasting an FFI roundtrip; the Rust side still validates the
    // same invariant as belt-and-braces.
    if (chain_height >= SHEKYL_DAA_WINDOW_N &&
        timestamps.size() != SHEKYL_DAA_WINDOW_N + 1)
    {
      throw cryptonote::difficulty_computation_error(
          SHEKYL_DIFFICULTY_ERR_INVALID_COUNT);
    }

    // Per the FFI contract (shekyl/shekyl_ffi.h): when chain_height < N
    // pass count == 0; when chain_height >= N pass count == N + 1.
    // Normalize here so the C++ call sites can carry their natural
    // window state without each having to special-case the genesis
    // range.
    const bool genesis_range = chain_height < SHEKYL_DAA_WINDOW_N;
    std::vector<shekyl_u128> cum_u128;
    std::vector<uint64_t> ts_vec;
    if (!genesis_range)
    {
      cum_u128.reserve(cumulative_difficulties.size());
      const cryptonote::difficulty_type u64_mask =
          cryptonote::difficulty_type(std::numeric_limits<uint64_t>::max());
      for (const cryptonote::difficulty_type& v : cumulative_difficulties)
      {
        shekyl_u128 entry{};
        entry.lo = static_cast<uint64_t>((v & u64_mask)
            .convert_to<std::uint64_t>());
        entry.hi = static_cast<uint64_t>((v >> 64)
            .convert_to<std::uint64_t>());
        cum_u128.push_back(entry);
      }
      // Copy timestamps to a contiguous buffer so we can pass a raw
      // pointer regardless of whether `Timestamps` is std::vector or
      // std::deque (std::deque does not guarantee contiguous storage).
      ts_vec.reserve(timestamps.size());
      ts_vec.assign(timestamps.begin(), timestamps.end());
    }

    const uint64_t* ts_ptr = genesis_range || ts_vec.empty()
        ? nullptr : ts_vec.data();
    const shekyl_u128* cd_ptr = genesis_range || cum_u128.empty()
        ? nullptr : cum_u128.data();
    const size_t count = genesis_range ? 0u : cum_u128.size();

    shekyl_u128 result{};
    const int32_t rc = shekyl_difficulty_lwma1_next(
        ts_ptr,
        cd_ptr,
        count,
        chain_height,
        &result);
    if (rc != SHEKYL_DIFFICULTY_OK)
    {
      throw cryptonote::difficulty_computation_error(rc);
    }

    return (cryptonote::difficulty_type(result.hi) << 64)
         | cryptonote::difficulty_type(result.lo);
  }
} // anonymous namespace

//------------------------------------------------------------------
Blockchain::Blockchain(tx_memory_pool& tx_pool) :
  m_db(), m_tx_pool(tx_pool), m_hardfork(NULL), m_timestamps_and_difficulties_height(0), m_reset_timestamps_and_difficulties_height(true), m_current_block_cumul_weight_limit(0), m_current_block_cumul_weight_median(0),
  m_max_prepare_blocks_threads(4), m_db_sync_on_blocks(true), m_db_sync_threshold(1), m_db_sync_mode(db_async), m_db_default_sync(false), m_show_time_stats(false), m_sync_counter(0), m_bytes_to_sync(0), m_cancel(false),
  m_long_term_block_weights_window(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE),
  m_long_term_effective_median_block_weight(0),
  m_long_term_block_weights_cache_tip_hash(crypto::null_hash),
  m_long_term_block_weights_cache_rolling_median(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE),
  m_difficulty_for_next_block_top_hash(crypto::null_hash),
  m_difficulty_for_next_block(1),
  m_btc_valid(false),
  m_genesis_timestamp(0),
  m_batch_success(true),
  m_prepare_height(0)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
}
//------------------------------------------------------------------
Blockchain::~Blockchain()
{
  try { deinit(); }
  catch (const std::exception &e) { /* ignore */ }
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash &id) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image &key_im) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return  m_db->has_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template <class visitor_t>
bool Blockchain::scan_outputkeys_for_indexes(size_t tx_version, const txin_to_key& tx_in_to_key, visitor_t &vis, const crypto::hash &tx_prefix_hash, uint64_t* pmax_related_block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND: Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // verify that the input has key offsets (that it exists properly, really)
  if(!tx_in_to_key.key_offsets.size())
    return false;

  // cryptonote_format_utils uses relative offsets for indexing to the global
  // outputs list.  that is to say that absolute offset #2 is absolute offset
  // #1 plus relative offset #2.
  // TODO: Investigate if this is necessary / why this is done.
  std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);
  std::vector<output_data_t> outputs;

  bool found = false;
  auto it = m_scan_table.find(tx_prefix_hash);
  if (it != m_scan_table.end())
  {
    auto its = it->second.find(tx_in_to_key.k_image);
    if (its != it->second.end())
    {
      outputs = its->second;
      found = true;
    }
  }

  if (!found)
  {
    try
    {
      m_db->get_output_key(epee::span<const uint64_t>(&tx_in_to_key.amount, 1), absolute_offsets, outputs, true);
      if (absolute_offsets.size() != outputs.size())
      {
        MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
        return false;
      }
    }
    catch (...)
    {
      MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
      return false;
    }
  }
  else
  {
    // check for partial results and add the rest if needed;
    if (outputs.size() < absolute_offsets.size() && outputs.size() > 0)
    {
      MDEBUG("Additional outputs needed: " << absolute_offsets.size() - outputs.size());
      std::vector < uint64_t > add_offsets;
      std::vector<output_data_t> add_outputs;
      add_outputs.reserve(absolute_offsets.size() - outputs.size());
      for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
        add_offsets.push_back(absolute_offsets[i]);
      try
      {
        m_db->get_output_key(epee::span<const uint64_t>(&tx_in_to_key.amount, 1), add_offsets, add_outputs, true);
        if (add_offsets.size() != add_outputs.size())
        {
          MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
        return false;
      }
      outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
    }
  }

  size_t count = 0;
  for (const uint64_t& i : absolute_offsets)
  {
    try
    {
      output_data_t output_index;
      try
      {
        // get tx hash and output index for output
        if (count < outputs.size())
          output_index = outputs.at(count);
        else
          output_index = m_db->get_output_key(tx_in_to_key.amount, i);

        // call to the passed boost visitor to grab the public key for the output
        if (!vis.handle_output(output_index.unlock_time, output_index.pubkey, output_index.commitment))
        {
          MERROR_VER("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount << ", absolute_offset = " << i);
        return false;
      }

      // if on last output and pmax_related_block_height not null pointer
      if(++count == absolute_offsets.size() && pmax_related_block_height)
      {
        // set *pmax_related_block_height to tx block height for this output
        auto h = output_index.height;
        if(*pmax_related_block_height < h)
        {
          *pmax_related_block_height = h;
        }
      }

    }
    catch (const OUTPUT_DNE& e)
    {
      MERROR_VER("Output does not exist: " << e.what());
      return false;
    }
    catch (const TX_DNE& e)
    {
      MERROR_VER("Transaction does not exist: " << e.what());
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(BlockchainDB* db, const network_type nettype, bool offline, const cryptonote::test_options *test_options, difficulty_type fixed_difficulty)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  CHECK_AND_ASSERT_MES(nettype != FAKECHAIN || test_options, false, "fake chain network type used without options");

  CRITICAL_REGION_LOCAL(m_tx_pool);
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if (db == nullptr)
  {
    LOG_ERROR("Attempted to init Blockchain with null DB");
    return false;
  }
  if (!db->is_open())
  {
    LOG_ERROR("Attempted to init Blockchain with unopened DB");
    delete db;
    return false;
  }

  m_db = db;

  m_nettype = test_options != NULL ? FAKECHAIN : nettype;
  m_offline = offline;
  m_fixed_difficulty = fixed_difficulty;

  if (shekyl_archival_settlement_epoch_override_present())
  {
    // Same shape as the SEEDHASH_EPOCH_* gate below: the settlement-epoch
    // schedule is consensus (epoch close boundaries, serve-credit epochs,
    // bond join epochs, emission claim windows all derive from it), and
    // SHEKYL_SETTLEMENT_EPOCH_BLOCKS is the fakechain-only lever that
    // makes epoch-close e2e coverage affordable. A node inheriting it
    // from a leaked environment would close epochs at wrong heights and
    // fork every public peer — refuse on the lever's PRESENCE, before
    // any question of its validity.
    //
    // This gate runs BEFORE anything touches the DB: arming must precede
    // the process's first epoch arithmetic, and on a fresh datadir the
    // genesis add below reaches it (add_block →
    // process_archival_epoch_close_at_height) — arming after that latches
    // the genesis schedule first and the arm refuses as ArmedTooLate
    // (caught live by the PR-4c emission e2e's first daemon spawn).
    if (m_nettype != FAKECHAIN)
    {
      MERROR("SHEKYL_SETTLEMENT_EPOCH_BLOCKS override active on a public network: the settlement-epoch schedule is consensus-critical and the override is a fakechain-only (regtest) lever; refusing to start. Unset SHEKYL_SETTLEMENT_EPOCH_BLOCKS to run this node.");
      return false;
    }
    // FAKECHAIN: arm the override. An unarmed process ignores the lever
    // wholesale, so this is the single gate a regtest schedule passes
    // through — and an invalid value refuses loudly here instead of
    // silently running the genesis schedule until the harness times out.
    const uint8_t arm_rc = shekyl_archival_settlement_epoch_arm_regtest();
    if (arm_rc != SHEKYL_ARCHIVAL_SEB_ARM_OK)
    {
      // The two refusals have different remedies, so they get different
      // messages: a bad value is the operator's to fix, while a late arm
      // means this gate ran after something already latched the schedule —
      // a daemon-side initialization-order defect the operator cannot fix
      // by editing the variable.
      const char *raw = getenv("SHEKYL_SETTLEMENT_EPOCH_BLOCKS");
      if (arm_rc == SHEKYL_ARCHIVAL_SEB_ARM_ERR_TOO_LATE)
        MERROR("SHEKYL_SETTLEMENT_EPOCH_BLOCKS=" << (raw ? raw : "?") << " could not be armed: the settlement-epoch schedule had already latched before this gate ran. The value is fine; this is an initialization-order defect in the daemon (arming must precede every epoch-arithmetic call, including the genesis add). Refusing to start — please report it.");
      else
        MERROR("SHEKYL_SETTLEMENT_EPOCH_BLOCKS=" << (raw ? raw : "?") << " is not a valid override: expected an integer between 2 and the genesis settlement-epoch length; refusing to start. Fix the value or unset the variable.");
      return false;
    }
    MWARNING("SHEKYL_SETTLEMENT_EPOCH_BLOCKS override active on fakechain: settlement epochs are " << shekyl_archival_settlement_epoch_blocks() << " blocks instead of the genesis-pinned schedule — epoch closes, serve-credit windows, and emission claims computed under this schedule are valid only among fakechain nodes running the same override");
  }

  if (m_hardfork == nullptr)
  {
    if (m_nettype ==  FAKECHAIN || m_nettype == STAGENET)
      m_hardfork = new HardFork(*db, 1, 0);
    else if (m_nettype == TESTNET)
      m_hardfork = new HardFork(*db, 1, testnet_hard_fork_version_1_till);
    else
      m_hardfork = new HardFork(*db, 1, mainnet_hard_fork_version_1_till);
  }
  if (m_nettype == FAKECHAIN)
  {
    for (size_t n = 0; test_options->hard_forks[n].first; ++n)
      m_hardfork->add_fork(test_options->hard_forks[n].first, test_options->hard_forks[n].second, 0, n + 1);
  }
  else if (m_nettype == TESTNET)
  {
    for (size_t n = 0; n < num_testnet_hard_forks; ++n)
      m_hardfork->add_fork(testnet_hard_forks[n].version, testnet_hard_forks[n].height, testnet_hard_forks[n].threshold, testnet_hard_forks[n].time);
  }
  else if (m_nettype == STAGENET)
  {
    for (size_t n = 0; n < num_stagenet_hard_forks; ++n)
      m_hardfork->add_fork(stagenet_hard_forks[n].version, stagenet_hard_forks[n].height, stagenet_hard_forks[n].threshold, stagenet_hard_forks[n].time);
  }
  else
  {
    for (size_t n = 0; n < num_mainnet_hard_forks; ++n)
      m_hardfork->add_fork(mainnet_hard_forks[n].version, mainnet_hard_forks[n].height, mainnet_hard_forks[n].threshold, mainnet_hard_forks[n].time);
  }
  m_hardfork->init();

  m_db->set_hard_fork(m_hardfork);

  // if the blockchain is new, add the genesis block
  // this feels kinda kludgy to do it this way, but can be looked at later.
  // TODO: add function to create and store genesis block,
  //       taking testnet into account
  if(!m_db->height())
  {
    MINFO("Blockchain not loaded, generating genesis block.");
    block bl;
    block_verification_context bvc = {};
    generate_genesis_block(bl, get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);
    db_wtxn_guard wtxn_guard(m_db);
    add_new_block(bl, bvc);
    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
  }
  // TODO: if blockchain load successful, verify blockchain against both
  //       hard-coded and runtime-loaded (and enforced) checkpoints.
  else
  {
  }

  if (m_nettype != FAKECHAIN)
  {
    // ensure we fixup anything we found and fix in the future
    m_db->fixup();
  }

  db_rtxn_guard rtxn_guard(m_db);

  // Block 0 exists from here on (added above when the store was empty) and
  // is immutable, so its timestamp — the C2-R3 genesis padding value — is
  // cached once for the timestamp-rule shim.
  m_genesis_timestamp = m_db->get_block_timestamp(0);

  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1397818133...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1397818133;

  // create general purpose async service queue

  m_async_work_idle = std::make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(m_async_service.get_executor());
  // we only need 1
  m_async_pool.create_thread(boost::bind(&boost::asio::io_context::run, &m_async_service));

  MINFO("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_difficulty_for_next_block());

  rtxn_guard.stop();

  uint64_t num_popped_blocks = 0;
  while (!m_db->is_read_only())
  {
    uint64_t top_height;
    const crypto::hash top_id = m_db->top_block_hash(&top_height);
    const block top_block = m_db->get_top_block();
    const uint8_t ideal_hf_version = get_ideal_hard_fork_version(top_height);
    if (ideal_hf_version <= 1 || ideal_hf_version == top_block.major_version)
    {
      if (num_popped_blocks > 0)
        MGINFO("Initial popping done, top block: " << top_id << ", top height: " << top_height << ", block version: " << (uint64_t)top_block.major_version);
      break;
    }
    else
    {
      if (num_popped_blocks == 0)
        MGINFO("Current top block " << top_id << " at height " << top_height << " has version " << (uint64_t)top_block.major_version << " which disagrees with the ideal version " << (uint64_t)ideal_hf_version);
      if (num_popped_blocks % 100 == 0)
        MGINFO("Popping blocks... " << top_height);
      ++num_popped_blocks;
      block popped_block;
      std::vector<transaction> popped_txs;
      try
      {
        m_db->pop_block(popped_block, popped_txs);
      }
      // anything that could cause this to throw is likely catastrophic,
      // so we re-throw
      catch (const std::exception& e)
      {
        MERROR("Error popping block from blockchain: " << e.what());
        throw;
      }
      catch (...)
      {
        MERROR("Error popping block from blockchain, throwing!");
        throw;
      }
    }
  }
  if (num_popped_blocks > 0)
  {
    m_timestamps_and_difficulties_height = 0;
    m_reset_timestamps_and_difficulties_height = true;
    m_hardfork->reorganize_from_chain_height(get_current_blockchain_height());
    uint64_t top_block_height;
    crypto::hash top_block_hash = get_tail_id(top_block_height);
    m_tx_pool.on_blockchain_dec(top_block_height, top_block_hash);
  }

  if (test_options && test_options->long_term_block_weight_window)
  {
    m_long_term_block_weights_window = test_options->long_term_block_weight_window;
    m_long_term_block_weights_cache_rolling_median = epee::misc_utils::rolling_median_t<uint64_t>(m_long_term_block_weights_window);
  }

  {
    db_txn_guard txn_guard(m_db, m_db->is_read_only());
    if (!update_next_cumulative_weight_limit())
      return false;
  }

  {
    if (shekyl_pow_randomx_v2_seed_epoch_overridden())
    {
      // The seed-epoch schedule is consensus; SEEDHASH_EPOCH_* is a
      // fakechain-only lever (regtest daemons and test fixtures both run
      // nettype FAKECHAIN). Fail closed on every public network, not just
      // mainnet: a node that inherits the lever from a leaked environment
      // (shared systemd template, container base layer) computes wrong
      // seedheights and silently rejects every block its peers accept —
      // and on testnet/stagenet that forks the genesis-rehearsal
      // infrastructure exactly when it matters most. The lever's
      // legitimate use, fast epochs for local development, is what
      // FAKECHAIN exists for.
      if (m_nettype != FAKECHAIN)
      {
        MERROR("SEEDHASH_EPOCH_* override active on a public network: the RandomX seed-epoch schedule is consensus-critical and the override is a fakechain-only (regtest) lever; refusing to start. Unset SEEDHASH_EPOCH_BLOCKS / SEEDHASH_EPOCH_LAG to run this node.");
        return false;
      }
      MWARNING("SEEDHASH_EPOCH_* override active on fakechain: the RandomX seed-epoch schedule differs from mainnet defaults — blocks produced under this schedule validate only among fakechain nodes running the same override, and captured vectors will not match mainnet seedheights");
    }
    if (m_nettype == FAKECHAIN)
    {
      // Datadir schedule pin: persisted epoch-derived state (bond join
      // epochs, serve-credit bits) is only meaningful under the schedule it
      // was written with, so a fakechain datadir records its schedule at
      // first init and refuses to reopen under a different one — the
      // silent-mis-epoch reopen (built under =50, reopened unset, or vice
      // versa) becomes a loud startup refusal with the remedy named.
      const uint64_t effective = shekyl_archival_settlement_epoch_blocks();
      const uint64_t pinned = m_db->get_settlement_epoch_blocks_pin();
      if (pinned == 0)
      {
        // A read-only open writes no epoch-derived rows either, so an
        // unpinned datadir stays unpinned rather than crashing on the put.
        if (!m_db->is_read_only())
          m_db->set_settlement_epoch_blocks_pin(effective);
      }
      else if (pinned != effective)
      {
        MERROR("this fakechain data directory was built with settlement epochs of " << pinned << " blocks but the effective schedule is " << effective << ": persisted join epochs and serve-credit windows would be silently mislabeled; refusing to start. Set SHEKYL_SETTLEMENT_EPOCH_BLOCKS=" << pinned << " to reopen it, or use a fresh --data-dir.");
        return false;
      }
    }
    const crypto::hash seedhash = get_block_id_by_height(shekyl_pow_randomx_v2_seedheight(m_db->height()));
    if (seedhash != crypto::null_hash)
      shekyl_pow_randomx_v2_set_canonical(reinterpret_cast<const uint8_t (*)[32]>(seedhash.data));
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::init(BlockchainDB* db, HardFork*& hf, const network_type nettype, bool offline)
{
  if (hf != nullptr)
    m_hardfork = hf;
  bool res = init(db, nettype, offline, NULL);
  if (hf == nullptr)
    hf = m_hardfork;
  return res;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // lock because the rpc_thread command handler also calls this
  CRITICAL_REGION_LOCAL(m_db->m_synchronization_lock);

  TIME_MEASURE_START(save);
  // TODO: make sure sync(if this throws that it is not simply ignored higher
  // up the call stack
  try
  {
    m_db->sync();
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Error syncing blockchain db: ") + e.what() + "-- shutting down now to prevent issues!");
    throw;
  }
  catch (...)
  {
    MERROR("There was an issue storing the blockchain, shutting down now to prevent issues!");
    throw;
  }

  TIME_MEASURE_FINISH(save);
  if(m_show_time_stats)
    MINFO("Blockchain stored OK, took: " << save << " ms");
  return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  MTRACE("Stopping blockchain read/write activity");

 // stop async service
  m_async_work_idle.reset();
  m_async_pool.join_all();
  m_async_service.stop();

  // as this should be called if handling a SIGSEGV, need to check
  // if m_db is a NULL pointer (and thus may have caused the illegal
  // memory operation), otherwise we may cause a loop.
  try
  {
    if (m_db)
    {
      m_db->close();
      MTRACE("Local blockchain read/write activity stopped successfully");
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Error closing blockchain db: ") + e.what());
  }
  catch (...)
  {
    LOG_ERROR("There was an issue closing/storing the blockchain, shutting down now to prevent issues!");
  }

  delete m_hardfork;
  m_hardfork = NULL;
  delete m_db;
  m_db = NULL;
  return true;
}
//------------------------------------------------------------------
// This function removes blocks from the top of blockchain.
// It starts a batch and calls private method pop_block_from_blockchain().
bool Blockchain::pop_blocks(uint64_t nblocks)
{
  uint64_t i = 0;
  CRITICAL_REGION_LOCAL(m_tx_pool);
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  bool stop_batch = m_db->batch_start();

  try
  {
    const uint64_t blockchain_height = m_db->height();
    if (blockchain_height > 0)
      nblocks = std::min(nblocks, blockchain_height - 1);
    // C2-R1b F-1: refuse the whole request up front rather than popping
    // part-way to a wall -- the operator asked for a rollback the retention
    // design cannot honor. Same predicate as the pop_block belt.
    {
      const uint64_t target_tip = blockchain_height > nblocks ? blockchain_height - 1 - nblocks : 0;
      if (!m_db->pop_target_allowed(target_tip))
      {
        MERROR("REFUSED pop_blocks(" << nblocks << "): target height " << target_tip
          << " is below the prune watermark floor (epoch "
          << m_db->get_archival_prune_watermark_epoch()
          << ") -- rows a revert needs are already pruned; remedy: resync this node");
        if (stop_batch)
          m_db->batch_abort();
        return false;
      }
    }
    while (i < nblocks && !m_cancel.load())
    {
      pop_block_from_blockchain();
      ++i;
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Error when popping blocks after processing " << i << " blocks: " << e.what());
    if (stop_batch)
      m_db->batch_abort();
    return false;
  }

  CHECK_AND_ASSERT_THROW_MES(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");

  if (stop_batch)
    m_db->batch_stop();

  {
    const crypto::hash seedhash = get_block_id_by_height(shekyl_pow_randomx_v2_seedheight(m_db->height()));
    // Mirror the init() guard: get_block_id_by_height() returns null_hash for a
    // nonexistent height, and an unwound/degraded chain can hit that here.
    // Pinning the all-zero seedhash would derive and stick a 256 MiB canonical
    // cache for a garbage epoch. Skip set_canonical on a null seedhash.
    if (seedhash != crypto::null_hash)
      shekyl_pow_randomx_v2_set_canonical(reinterpret_cast<const uint8_t (*)[32]>(seedhash.data));
  }
  return true;
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  block popped_block;
  std::vector<transaction> popped_txs;

  CHECK_AND_ASSERT_THROW_MES(m_db->height() > 1, "Cannot pop the genesis block");

  const uint8_t previous_hf_version = get_current_hard_fork_version();
  try
  {
    m_db->pop_block(popped_block, popped_txs);
  }
  // anything that could cause this to throw is likely catastrophic,
  // so we re-throw
  catch (const std::exception& e)
  {
    LOG_ERROR("Error popping block from blockchain: " << e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Error popping block from blockchain, throwing!");
    throw;
  }

  // make sure the hard fork object updates its current version
  m_hardfork->on_block_popped(1);

  // return transactions from popped block to the tx_pool
  size_t pruned = 0;
  for (transaction& tx : popped_txs)
  {
    if (tx.pruned)
    {
      ++pruned;
      continue;
    }
    if (!is_coinbase(tx))
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);

      // FIXME: HardFork
      // Besides the below, popping a block should also remove the last entry
      // in hf_versions.
      uint8_t version = get_ideal_hard_fork_version(m_db->height());

      // We assume that if they were in a block, the transactions are already known to the network
      // as a whole. However, if we had mined that block, that might not be always true. Unlikely
      // though, and always relaying these again might cause a spike of traffic as many nodes
      // re-relay all the transactions in a popped block when a reorg happens. You might notice that
      // we also set the "nic_verified_hf_version" paramater. Since we know we took this transaction
      // from the mempool earlier in this function call, when the mempool has the same current fork
      // version, we can return it without re-verifying the consensus rules on it.
      const bool r = m_tx_pool.add_tx(tx, tvc, relay_method::block, true, version, /*origin=*/epee::net_utils::zone::invalid, version);
      if (!r)
      {
        LOG_ERROR("Error returning transaction to tx_pool");
      }
    }
  }
  if (pruned)
    MWARNING(pruned << " pruned txes could not be added back to the txpool");

  m_blocks_longhash_table.clear();
  m_scan_table.clear();

  uint64_t top_block_height;
  crypto::hash top_block_hash = get_tail_id(top_block_height);
  m_tx_pool.on_blockchain_dec(top_block_height, top_block_hash);
  invalidate_block_template_cache();

  const uint8_t new_hf_version = get_current_hard_fork_version();
  if (new_hf_version != previous_hf_version)
  {
    MINFO("Validating txpool for v" << (unsigned)new_hf_version);
    m_tx_pool.validate(new_hf_version);
  }

  {
    db_wtxn_guard wtxn_guard(m_db);
    const uint64_t popped_height = m_db->height();
    const uint64_t destroyed = m_db->get_block_burn(popped_height);
    if (destroyed > 0)
    {
      uint64_t total_burned = m_db->get_total_burned();
      total_burned = (destroyed <= total_burned) ? total_burned - destroyed : 0;
      m_db->set_total_burned(total_burned);
    }
    m_db->remove_block_burn(popped_height);
    // The accrual-row removal (the pop side of the §2.2 staker-inflow
    // write) lives in BlockchainDB::pop_block, mirroring the
    // connect-side write that add_block performs before the epoch-close
    // hook (F-B1a) — both sides of that row are DB-layer and share the
    // pop's wtxn.
  }

  return popped_block;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;
  invalidate_block_template_cache();
  m_db->reset();
  m_db->drop_alt_blocks();
  m_hardfork->init();

  db_wtxn_guard wtxn_guard(m_db);
  block_verification_context bvc = {};
  add_new_block(b, bvc);
  if (!update_next_cumulative_weight_limit())
    return false;
  if (bvc.m_added_to_main_chain && !bvc.m_verifivation_failed)
  {
    // This is the second of the two places block 0 can be (re)installed
    // (Blockchain::init is the first): refresh the cached C2-R3 padding
    // value from the store, or short-window validation keeps padding
    // with the SUPERSEDED genesis timestamp — observed as
    // gen_block_ts_at_genesis_in_deep_bootstrap accepting a candidate
    // the ruled rule rejects (fakechain replay installs its own genesis
    // through this path).
    m_genesis_timestamp = m_db->get_block_timestamp(0);
    return true;
  }
  return false;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id(uint64_t& height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->top_block_hash(&height);
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
/*TODO: this function was...poorly written.  As such, I'm not entirely
 *      certain on what it was supposed to be doing.  Need to look into this,
 *      but it doesn't seem terribly important just yet.
 *
 * puts into list <ids> a list of hashes representing certain blocks
 * from the blockchain in reverse chronological order
 *
 * the blocks chosen, at the time of this writing, are:
 *   the most recent 11
 *   powers of 2 less recent from there, so 13, 17, 25, etc...
 *
 */
bool Blockchain::get_short_chain_history(std::list<crypto::hash>& ids, uint64_t& current_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t i = 0;
  uint64_t current_multiplier = 1;
  uint64_t sz = current_height = m_db->height();

  if(!sz)
    return true;

  db_rtxn_guard rtxn_guard(m_db);
  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < sz)
  {
    ids.push_back(m_db->get_block_hash_from_height(sz - current_back_offset));

    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_multiplier *= 2;
      current_back_offset += current_multiplier;
    }
    ++i;
  }

  if (!genesis_included)
  {
    ids.push_back(m_db->get_block_hash_from_height(0));
  }

  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_hash_from_height(height);
  }
  catch (const BLOCK_DNE& e)
  {
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by height"));
    throw;
  }
  return null_hash;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_pending_block_id_by_height(uint64_t height) const
{
  if (m_prepare_height && height >= m_prepare_height && height - m_prepare_height < m_prepare_nblocks)
    return (*m_prepare_blocks)[height - m_prepare_height].hash;
  return get_block_id_by_height(height);
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(h);
    if (orphan)
      *orphan = false;
    return true;
  }
  // try to find block in alternative chain
  catch (const BLOCK_DNE& e)
  {
    alt_block_data_t data;
    cryptonote::blobdata blob;
    if (m_db->get_alt_block(h, &data, &blob))
    {
      if (!cryptonote::parse_and_validate_block_from_blob(blob, blk))
      {
        MERROR("Found block " << h << " in alt chain, but failed to parse it");
        throw std::runtime_error("Found block in alt chain, but failed to parse it");
      }
      if (orphan)
        *orphan = true;
      return true;
    }
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by hash"));
    throw;
  }

  return false;
}
//------------------------------------------------------------------
// LWMA-1 next-difficulty (per docs/completed/DAA_LWMA1.md §5.3). Aggregates
// timestamps and cumulative_difficulties for the last
// `SHEKYL_DAA_WINDOW_N + 1` blocks (or zero entries when the chain has
// fewer than `SHEKYL_DAA_WINDOW_N` blocks — the FFI genesis short-circuit
// returns SHEKYL_DAA_GENESIS_DIFFICULTY in that case). Throws
// difficulty_computation_error on consensus-invariant violations
// surfaced by the Rust algorithm; the daemon treats those as fatal.
difficulty_type Blockchain::get_difficulty_for_next_block()
{
  if (m_fixed_difficulty)
  {
    return m_db->height() ? m_fixed_difficulty : 1;
  }

  LOG_PRINT_L3("Blockchain::" << __func__);

  crypto::hash top_hash = get_tail_id();
  {
    CRITICAL_REGION_LOCAL(m_difficulty_lock);
    // we can call this without the blockchain lock, it might just give us
    // something a bit out of date, but that's fine since anything which
    // requires the blockchain lock will have acquired it in the first place,
    // and it will be unlocked only when called from the getinfo RPC
    if (top_hash == m_difficulty_for_next_block_top_hash)
      return m_difficulty_for_next_block;
  }

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  std::deque<uint64_t> timestamps;
  std::deque<difficulty_type> difficulties;
  uint64_t height;
  top_hash = get_tail_id(height); // get it again now that we have the lock
  ++height; // top block height to blockchain height

  // LWMA-1 window: exactly N+1 entries when the chain is past the
  // genesis short-circuit, zero entries otherwise. The FFI's
  // chain_height parameter is the height of the chain tip, i.e.,
  // `height - 1` in this file's convention.
  constexpr uint64_t lwma1_window_size = SHEKYL_DAA_WINDOW_N + 1;
  const uint64_t chain_height = height - 1;

  // ND: Speedup
  // Keep the LWMA-1 window cached on the Blockchain object so the
  // next call only needs a 1-block roll-forward rather than re-fetching
  // all N+1 entries from LMDB.
  //
  // Cache-state invariant: the cache is either empty (the genesis-range
  // else-branch below clears it) or fully populated (the chain_height
  // >= SHEKYL_DAA_WINDOW_N else-if branch fills it with exactly N+1
  // entries). The fast roll-forward branch's `m_timestamps.size() >=
  // lwma1_window_size` guard then ensures we never enter roll-forward
  // against a partially-populated cache; the transition from genesis-
  // range (empty cache) to fully-populated happens via the full-refetch
  // branch, never directly via roll-forward.
  if (m_reset_timestamps_and_difficulties_height)
    m_timestamps_and_difficulties_height = 0;
  if (m_timestamps_and_difficulties_height != 0 && ((height - m_timestamps_and_difficulties_height) == 1) && m_timestamps.size() >= lwma1_window_size)
  {
    uint64_t index = height - 1;
    m_timestamps.push_back(m_db->get_block_timestamp(index));
    m_difficulties.push_back(m_db->get_block_cumulative_difficulty(index));

    while (m_timestamps.size() > lwma1_window_size)
      m_timestamps.pop_front();
    while (m_difficulties.size() > lwma1_window_size)
      m_difficulties.pop_front();

    m_timestamps_and_difficulties_height = height;
    timestamps = m_timestamps;
    difficulties = m_difficulties;
  }
  else if (chain_height >= SHEKYL_DAA_WINDOW_N)
  {
    // Window fully populated: fetch exactly N+1 entries ending at
    // chain tip (heights chain_height - N .. chain_height inclusive).
    const uint64_t window_start = chain_height + 1 - lwma1_window_size;
    for (uint64_t h = window_start; h <= chain_height; ++h)
    {
      timestamps.push_back(m_db->get_block_timestamp(h));
      difficulties.push_back(m_db->get_block_cumulative_difficulty(h));
    }
    m_timestamps_and_difficulties_height = height;
    m_timestamps = timestamps;
    m_difficulties = difficulties;
  }
  else
  {
    // Genesis short-circuit: chain has fewer than N blocks, so the
    // FFI ignores the slices and returns SHEKYL_DAA_GENESIS_DIFFICULTY.
    // Clear the cache so the next call re-evaluates.
    m_timestamps_and_difficulties_height = 0;
    m_timestamps.clear();
    m_difficulties.clear();
  }
  difficulty_type diff = lwma1_next_difficulty(chain_height, timestamps, difficulties);

  CRITICAL_REGION_LOCAL1(m_difficulty_lock);
  m_difficulty_for_next_block_top_hash = top_hash;
  m_difficulty_for_next_block = diff;
  return diff;
}
//------------------------------------------------------------------
std::vector<time_t> Blockchain::get_last_block_timestamps(unsigned int blocks) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t height = m_db->height();
  if (blocks > height)
    blocks = height;
  std::vector<time_t> timestamps(blocks);
  while (blocks--)
    timestamps[blocks] = m_db->get_block_timestamp(height - blocks - 1);
  return timestamps;
}
//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(std::list<detached_block>& original_chain, uint64_t rollback_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // fail if rollback_height passed is too high
  if (rollback_height > m_db->height())
  {
    return true;
  }

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  // remove blocks from blockchain until we get back to where we should be.
  // These are the alt blocks a failed switch had partially promoted; they are
  // still in the alt-block table, which owns their attestation witnesses, so the
  // pop needs to preserve nothing. The blocks we re-add below are a different set
  // — the ones the switch demoted — and each carries its own witness here.
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain();
  }
  CHECK_AND_ASSERT_THROW_MES(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");

  // make sure the hard fork object updates its current version
  m_hardfork->reorganize_from_chain_height(rollback_height);

  //return back original chain
  for (auto& entry : original_chain)
  {
    block_verification_context bvc = {};
    const crypto::hash restore_id = get_block_hash(entry.bl);
    block_connect_supplement connect{};
    // Re-supply the credit-wire witness this block held before the switch demoted
    // it (captured at pop; ARCHIVAL_CREDIT_WIRE.md §3, credit-wire CW-2), so the
    // restored block gets its height-keyed row back.
    connect.attestation_witness = entry.attestation_witness;
    bool r = handle_block_to_main_chain(entry.bl, restore_id, bvc, connect);
    CHECK_AND_ASSERT_MES(r && bvc.m_added_to_main_chain, false, "PANIC! failed to add (again) block while chain switching during the rollback!");
  }

  m_hardfork->reorganize_from_chain_height(rollback_height);

  MINFO("Rollback to height " << rollback_height << " was successful.");
  if (!original_chain.empty())
  {
    MINFO("Restoration to previous blockchain successful as well.");
  }
  return true;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(std::list<block_extended_info>& alt_chain, bool discard_disconnected_chain)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  // if empty alt chain passed (not sure how that could happen), return false
  CHECK_AND_ASSERT_MES(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  // verify that main chain has front of alt chain's parent block
  if (!m_db->block_exists(alt_chain.front().bl.prev_id))
  {
    LOG_ERROR("Attempting to move to an alternate chain, but it doesn't appear to connect to the main chain!");
    return false;
  }

  // C2-R1b F-1(a): the prune-watermark pre-check lives in the ONE caller
  // (handle_alternative_block's switch arm), because a refusal there is a
  // LOCAL retention limitation, not a switch failure -- it must not travel
  // this function's false return, which the caller maps to
  // m_verifivation_failed and the P2P paths punish. The pop_block belt
  // still backstops any path that reaches a below-floor pop unchecked.

  // pop blocks from the blockchain until the top block is the parent of the front
  // block of the alt chain. Each demoted block's credit-wire attestation witness
  // is read off its height row before the pop deletes it (ARCHIVAL_CREDIT_WIRE.md
  // §3, credit-wire CW-2) and travels with the block: to handle_alternative_block
  // below when the old chain is kept as alternates, or to
  // rollback_blockchain_switching if a promote fails. Discarded blocks simply drop
  // theirs — nothing was written anywhere for the retention prune to miss.
  std::list<detached_block> disconnected_chain;
  while (m_db->top_block_hash() != alt_chain.front().bl.prev_id)
  {
    detached_block demoted;
    demoted.attestation_witness = m_db->get_archival_attestation_witness_at_height(
      archival_attestation_witness_key(m_db->height() - 1));
    demoted.bl = pop_block_from_blockchain();
    disconnected_chain.push_front(std::move(demoted));
  }
  CHECK_AND_ASSERT_THROW_MES(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");

  auto split_height = m_db->height();

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    const auto &bei = *alt_ch_iter;
    block_verification_context bvc = {};

    // Promote: the witness lives in the hash-keyed table, put there beside the
    // alt block when it was added. Read it and pass through connect so add_block
    // re-writes the height-keyed row. The hash-keyed row stays until the alt block
    // itself is removed below — a switch that fails partway needs it to still be
    // there for the blocks this loop already promoted.
    const crypto::hash promoted_id = get_block_hash(bei.bl);
    block_connect_supplement promoted{};
    promoted.attestation_witness = m_db->get_archival_alt_attestation_witness(promoted_id);
    bool r = handle_block_to_main_chain(bei.bl, promoted_id, bvc, promoted);

    // if adding block to main chain failed, rollback to previous state and
    // return false
    if(!r || !bvc.m_added_to_main_chain)
    {
      MERROR("Failed to switch to alternative blockchain");

      // rollback_blockchain_switching should be moved to two different
      // functions: rollback and apply_chain, but for now we pretend it is
      // just the latter (because the rollback was done above).
      rollback_blockchain_switching(disconnected_chain, split_height);

      const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
      m_db->remove_alt_block(blkid);
      alt_ch_iter++;

      for(auto alt_ch_to_orph_iter = alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end(); )
      {
        const auto &bei = *alt_ch_to_orph_iter++;
        const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
        m_db->remove_alt_block(blkid);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  const size_t discarded_blocks = disconnected_chain.size();
  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain. Each block hands its captured
    // credit-wire witness to handle_alternative_block, which stores it beside the
    // alt block that now owns it.
    for (auto& old_ch_ent : disconnected_chain)
    {
      block_verification_context bvc = {};
      block_connect_supplement connect{};
      connect.attestation_witness = old_ch_ent.attestation_witness;
      const crypto::hash old_id = get_block_hash(old_ch_ent.bl);
      bool r = handle_alternative_block(old_ch_ent.bl, old_id, bvc, connect);
      if(!r)
      {
        MERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  }

  //removing alt_chain entries from alternative chains container
  for (const auto &bei: alt_chain)
  {
    m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));
  }

  m_hardfork->reorganize_from_chain_height(split_height);

  std::shared_ptr<tools::Notify> reorg_notify = m_reorg_notify;
  if (reorg_notify)
    reorg_notify->notify("%s", std::to_string(split_height).c_str(), "%h", std::to_string(m_db->height()).c_str(),
        "%n", std::to_string(m_db->height() - split_height).c_str(), "%d", std::to_string(discarded_blocks).c_str(), NULL);

  const uint64_t new_height = m_db->height();
  const crypto::hash seedhash = get_block_id_by_height(shekyl_pow_randomx_v2_seedheight(new_height));

  crypto::hash prev_id;
  if (!get_block_hash(alt_chain.back().bl, prev_id))
    MERROR("Failed to get block hash of an alternative chain's tip");
  else
    // The LEDGER's cumulative supply, not the alt block's bookkeeping copy.
    // bei.already_generated_coins is advanced by get_outs_money_amount (see the
    // note at the alt-chain accumulation site), which differs from the ledger by
    // miner_fee_income - staker_emission per block. That approximation is
    // harmless inside alt bookkeeping — nothing validates against it — but this
    // send is the reorg's LAST WORD to miners, and it was overwriting the correct
    // notifications that each promoted block just issued from
    // handle_block_to_main_chain. A miner templating on a wrong cumulative supply
    // computes a wrong subsidy and builds a block consensus then rejects.
    //
    // Safe to read unguarded: the promotion loop above committed at least one
    // block (switch_to_alternative_blockchain asserts a non-empty alt_chain), so
    // new_height >= 1. This is the same quantity the main-chain send passes —
    // add_block stores the post-advance total for the block it returns the height
    // for, so get_block_already_generated_coins(new_height - 1) IS that value.
    send_miner_notifications(new_height, seedhash, prev_id,
                             m_db->get_block_already_generated_coins(new_height - 1));

  for (const auto& notifier : m_block_notifiers)
  {
    std::size_t notify_height = split_height;
    for (const auto& bei: alt_chain)
    {
      notifier(notify_height, {std::addressof(bei.bl), 1});
      ++notify_height;
    }
  }

  shekyl_pow_randomx_v2_set_canonical(reinterpret_cast<const uint8_t (*)[32]>(seedhash.data));

  MGINFO_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height());
  return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
difficulty_type Blockchain::get_next_difficulty_for_alternative_chain(const std::list<block_extended_info>& alt_chain, block_extended_info& bei) const
{
  if (m_fixed_difficulty)
  {
    return m_db->height() ? m_fixed_difficulty : 1;
  }

  LOG_PRINT_L3("Blockchain::" << __func__);

  // Precondition: alt-chain candidates are added at height >= 1.
  // bei.height == 0 would mean "alternative genesis", which is
  // structurally impossible — genesis is fixed per `60-no-monero-legacy.mdc`,
  // and `handle_alternative_block` sets `bei.height = prev_data.height + 1`
  // before calling here. A silent ternary fallback would mask the
  // precondition violation; per `00-mission.mdc`, fail loudly instead.
  // Matches the in-function sentinel-return pattern at the alt_chain.size()
  // bound check below (false → difficulty 0 via implicit uint128_t conversion).
  CHECK_AND_ASSERT_MES(bei.height > 0, false,
      "get_next_difficulty_for_alternative_chain called with bei.height=0; "
      "alt-chain candidates must have height >= 1 (genesis is fixed).");

  // LWMA-1 next-difficulty for the alt-chain candidate `bei`. The
  // window contains the last N+1 blocks of the alt chain ending at
  // bei.height - 1 (the parent of `bei` on the alt chain). The alt
  // chain is conceptually `main_chain[0..first_alt_height) ++ alt_chain`.
  //
  // When bei.height <= N (i.e., chain_height < N), the FFI's genesis
  // short-circuit fires and the window contents are ignored. Above
  // that threshold the window MUST be exactly N+1 entries.
  constexpr uint64_t lwma1_window_size = SHEKYL_DAA_WINDOW_N + 1;
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;
  timestamps.reserve(lwma1_window_size);
  cumulative_difficulties.reserve(lwma1_window_size);

  // chain_height for the FFI call: the parent of `bei` on the alt
  // chain. bei.height >= 1 is guaranteed by the precondition assert
  // above, so `bei.height - 1` is well-defined.
  const uint64_t chain_height = bei.height - 1;

  // C2-R1b-Q1b / CEN-D5: the window SELECTION -- which main-chain range
  // and how many newest alt entries -- is the rule, and it lives in
  // shekyl-difficulty::alt_window_plan behind the FFI (both regimes: the
  // short-alt stitch and the alt-covers-the-window tail). This site
  // performs the fetches the plan names; a plan refusal (height-0
  // candidate, discontiguous ancestry) fails closed into the difficulty-0
  // sentinel that CEN-D6's zero guard rejects.
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);

    uint64_t plan_main_start = 0, plan_main_stop = 0, plan_alt_take = 0;
    const uint64_t first_alt_height = alt_chain.size() ? alt_chain.front().height : 0;
    const int32_t plan_rc = shekyl_difficulty_alt_window_plan(
        bei.height, alt_chain.size(), first_alt_height,
        &plan_main_start, &plan_main_stop, &plan_alt_take);
    CHECK_AND_ASSERT_MES(plan_rc == SHEKYL_DIFFICULTY_OK, false,
        "alt-window plan refused (rc " << plan_rc << ") for candidate height " << bei.height
        << ", alt length " << alt_chain.size() << ", first alt height " << first_alt_height);

    for (uint64_t h = plan_main_start; h < plan_main_stop; ++h)
    {
      timestamps.push_back(m_db->get_block_timestamp(h));
      cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(h));
    }

    // Newest `plan_alt_take` alt entries, oldest-first so the assembled
    // window ends at the candidate's parent.
    uint64_t skip = alt_chain.size() - plan_alt_take;
    for (const auto &alt_bei : alt_chain)
    {
      if (skip > 0) { --skip; continue; }
      timestamps.push_back(alt_bei.bl.timestamp);
      cumulative_difficulties.push_back(alt_bei.cumulative_difficulty);
    }

    CHECK_AND_ASSERT_MES(timestamps.size() == cumulative_difficulties.size()
        && timestamps.size() == std::min<uint64_t>(lwma1_window_size, bei.height), false,
        "assembled alt window size " << timestamps.size() << " violates the plan invariant for height " << bei.height);
  }

  return lwma1_next_difficulty(chain_height, timestamps, cumulative_difficulties);
}
//------------------------------------------------------------------
static bool check_commitment_mask_valid(const transaction& tx);
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
//   valid output types
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height, uint8_t hf_version)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  CHECK_AND_ASSERT_MES(std::holds_alternative<txin_gen>(b.miner_tx.vin[0]), false, "coinbase transaction in the block has the wrong type");
  CHECK_AND_ASSERT_MES(b.miner_tx.version >= 3, false, "Invalid coinbase transaction version: " << b.miner_tx.version << " (minimum: 3)");
  CHECK_AND_ASSERT_MES(b.miner_tx.ct_signatures.type == ct::CTTypeNull, false, "FCMP++ signatures not allowed in coinbase transactions");

  // F-H: consensus coinbase output-count cap (FOLLOWUPS "GENESIS-FREEZE: cap
  // the coinbase output count"; ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md
  // §12.3). Coinbase outputs are curve-tree leaves that count toward
  // frozen_segment_count yet pay no fee, so an uncapped foreign coinbase is an
  // unpriced burden channel -- the W9 fee-path burden-coupling defense has a
  // second face without this. The cap is EXACTLY 1: the honest template has
  // only ever built one output (create_block_template max_outs = 1), the
  // staker pool accrues off-coinbase, and a uniform coinbase is
  // privacy-consistent. Genesis is exempt -- its hardcoded coinbase is
  // accepted as configured, the same carve-out as
  // validate_miner_transaction's height-0 return. The exemption is
  // LOAD-BEARING TODAY, not defensive: testnet's shipped GENESIS_TX already
  // carries 5 outputs (verified at the blob -- vout count 0x05), so without
  // height == 0 testnet fails to validate its own genesis and the chain does
  // not start. The final genesis is multi-output on every nettype; the
  // current mainnet/stagenet 1-output blobs are pre-genesis placeholders.
  // The exemption cannot be spoofed: the height operand deciding
  // genesis-or-not is CALLER-derived from chain position (main path passes
  // blockchain_height, alt path passes bei.height) -- it is not derived from
  // the block's claimed txin_gen height. That claimed height IS read just
  // below, but as a second guard rather than an input: it must EQUAL the
  // caller's height or the block is rejected there, so a mined block claiming
  // to be genesis both faces the cap here (caller height != 0) and fails the
  // height match below. Rule-21 reopen (sole trigger): a consensus consumer
  // that structurally requires a multi-output coinbase in MINED blocks, as
  // its own design round.
  CHECK_AND_ASSERT_MES(height == 0 || b.miner_tx.vout.size() == 1, false,
    "coinbase transaction has " << b.miner_tx.vout.size()
    << " outputs; consensus requires exactly 1 (F-H output-count cap)");

  if(std::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    MWARNING("The miner transaction in block has invalid height: " << std::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  MDEBUG("Miner tx hash: " << get_transaction_hash(b.miner_tx));
  CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, false, "coinbase transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

  //check outs overflow
  if(!check_outs_overflow(b.miner_tx))
  {
    MERROR("miner transaction has money overflow in block " << get_block_hash(b));
    return false;
  }

  CHECK_AND_ASSERT_MES(check_output_types(b.miner_tx, hf_version), false, "miner transaction has invalid output type(s) in block " << get_block_hash(b));
  // CEN-I19: the coinbase carries its outputs' 0x06 / 0x07 fields like every
  // other transaction (construct_miner_tx emits both); the shape rule runs
  // here because the coinbase never passes core::check_tx_semantic.
  {
    std::string why;
    CHECK_AND_ASSERT_MES(check_tx_extra_pqc_field_shape(b.miner_tx, why), false,
      "miner transaction: " << why << " (block " << get_block_hash(b) << ")");
  }

  // §2.3 output-point rule for coinbase output keys: pool txs get this via
  // core::check_tx_semantic -> check_outs_valid; the miner tx never passes
  // through that path, so the gate is applied here.
  CHECK_AND_ASSERT_MES(check_outs_valid(b.miner_tx), false, "miner transaction has invalid output public key(s) in block " << get_block_hash(b));

  if (!check_commitment_mask_valid(b.miner_tx))
  {
    MERROR("Coinbase transaction has invalid output commitment mask in block " << get_block_hash(b));
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// D2 escalation operand read-point (ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md
// §6.2): n = frozen_segment_count at PARENT-block state, derived from the
// curve-tree leaf count. add_block advances the chain height and grows the
// tree in the same write txn, and pop_block trims both in the same write txn
// (see the pop invariant comment in blockchain_db.cpp), so
// m_db->height() == block_height is EQUIVALENT to "the tree has not yet grown
// for this block" — the leaf count read below is the parent's, by
// construction, on every surviving path (the prev_block template path that
// could not satisfy this was deleted; see create_block_template).
//
// The check is load-bearing at CONNECT: handle_block_to_main_chain computes n
// before validate_miner_transaction and m_db->add_block, and a refactor that
// moves the read past add_block (the M3-1 cached-counter drift class) must
// stop the node here, not skew the split. The teeth depend on the OPERAND,
// not just the call site: block_height must be a height captured BEFORE
// add_block (connect passes its blockchain_height snapshot). "Simplifying"
// the call to parent_frozen_segment_count(m_db->height()) makes the check a
// permanent tautology — it still looks correct and still passes every test,
// while the reordering it exists to catch becomes undetectable. Do not pass a
// fresh m_db->height() at a load-bearing site. At TEMPLATE build it is a tripwire
// only — create_block_template sets height = m_db->height() itself, so the
// guarantee there comes from using the same expression, not from this check;
// its value is refusing any future reintroduction of a non-tip parent, which
// is exactly how the deleted prev_block path would have violated it.
uint64_t Blockchain::parent_frozen_segment_count(uint64_t block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  const uint64_t db_height = m_db->height();
  CHECK_AND_ASSERT_THROW_MES(db_height == block_height,
    "escalation operand read-point violated: template and connect must read "
    "n = frozen_segment_count at the same parent state, but m_db->height() ("
    << db_height << ") != block_height (" << block_height
    << ") — the curve tree has already grown past this block's parent");
  return shekyl_archival_frozen_segment_count(m_db->get_curve_tree_leaf_count());
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(const block& b, size_t cumulative_block_weight, uint64_t fee, uint64_t& base_reward, uint64_t already_generated_coins, uint8_t version, uint64_t frozen_segment_count)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  const uint64_t block_height = std::get<txin_gen>(b.miner_tx.vin[0]).height;
  uint64_t money_in_use = 0;
  for (auto& o: b.miner_tx.vout)
    money_in_use += o.amount;

  if (block_height == 0)
  {
    // Genesis emission is hardcoded via GENESIS_TX and may not match the live
    // runtime reward function after economics tuning. Validate structure in
    // prevalidate_miner_transaction and accept the configured amount here.
    base_reward = money_in_use;
    return true;
  }

  if (version == 3) {
    for (auto &o: b.miner_tx.vout) {
      if (!is_valid_decomposed_amount(o.amount)) {
        MERROR_VER("miner tx output " << print_money(o.amount) << " is not a valid decomposed amount");
        return false;
      }
    }
  }

  uint64_t median_weight = m_current_block_cumul_weight_median;
  const uint64_t tx_volume_avg = get_tx_volume_avg(block_height);
  const uint64_t circulating_supply = already_generated_coins;

  if (!get_block_reward(median_weight, cumulative_block_weight, already_generated_coins, base_reward, version, tx_volume_avg))
  {
    MERROR_VER("block weight " << cumulative_block_weight << " is bigger than allowed for this blockchain");
    return false;
  }

  // Component 4: split emission between miner and staker pool.
  const uint64_t genesis_ng_height = get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG);
  shekyl::EmissionSplit em_split = shekyl::compute_emission_split(base_reward, block_height, genesis_ng_height);
  uint64_t miner_base_reward = em_split.miner_emission;

  // Component 2: fee burn split — miner only receives miner_fee_income.
  // frozen_segment_count is the caller's parent-state read (the asserting
  // read-point above); the escalated share cannot reach miner_fee_income
  // (§12.11.1 Leg 1), so this stays the security-budget-preserving split.
  shekyl::BurnResult burn = shekyl::compute_fee_burn(fee, tx_volume_avg, circulating_supply, frozen_segment_count);
  uint64_t effective_fee = burn.miner_fee_income;

  if(miner_base_reward + effective_fee < money_in_use)
  {
    MERROR_VER("coinbase transaction spend too much money (" << print_money(money_in_use) << "). Block reward is " << print_money(miner_base_reward + effective_fee) << "(" << print_money(miner_base_reward) << "+" << print_money(effective_fee) << "), cumulative_block_weight " << cumulative_block_weight);
    return false;
  }
  if(miner_base_reward + effective_fee != money_in_use)
  {
    MDEBUG("coinbase transaction doesn't use full amount of block reward:  spent: " << money_in_use << ",  block reward " << miner_base_reward + effective_fee << "(" << miner_base_reward << "+" << effective_fee << ")");
    return false;
  }
  // base_reward out-param stays full post-get_block_reward subsidy for :4946 (fix α).
  return true;
}
//------------------------------------------------------------------
// get the block weights of the last <count> blocks, and return by reference <sz>.
void Blockchain::get_last_n_blocks_weights(std::vector<uint64_t>& weights, size_t count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto h = m_db->height();

  // this function is meaningless for an empty blockchain...granted it should never be empty
  if(h == 0)
    return;

  // add weight of last <count> blocks to vector <weights> (or less, if blockchain size < count)
  size_t start_offset = h - std::min<size_t>(h, count);
  weights = m_db->get_block_weights(start_offset, count);
}
//------------------------------------------------------------------
uint64_t Blockchain::get_long_term_block_weight_median(uint64_t start_height, size_t count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  PERF_TIMER(get_long_term_block_weights);

  CHECK_AND_ASSERT_THROW_MES(count > 0, "count == 0");

  bool cached = false;
  uint64_t blockchain_height = m_db->height();
  uint64_t tip_height = start_height + count - 1;
  crypto::hash tip_hash = crypto::null_hash;
  if (tip_height < blockchain_height && count == (size_t)m_long_term_block_weights_cache_rolling_median.size())
  {
    tip_hash = m_db->get_block_hash_from_height(tip_height);
    cached = tip_hash == m_long_term_block_weights_cache_tip_hash;
  }

  if (cached)
  {
    MTRACE("requesting " << count << " from " << start_height << ", cached");
    return m_long_term_block_weights_cache_rolling_median.median();
  }

  // in the vast majority of uncached cases, most is still cached,
  // as we just move the window one block up:
  if (tip_height > 0 && count == (size_t)m_long_term_block_weights_cache_rolling_median.size() && tip_height < blockchain_height)
  {
    crypto::hash old_tip_hash = m_db->get_block_hash_from_height(tip_height - 1);
    if (old_tip_hash == m_long_term_block_weights_cache_tip_hash)
    {
      MTRACE("requesting " << count << " from " << start_height << ", incremental");
      m_long_term_block_weights_cache_tip_hash = tip_hash;
      m_long_term_block_weights_cache_rolling_median.insert(m_db->get_block_long_term_weight(tip_height));
      return m_long_term_block_weights_cache_rolling_median.median();
    }
  }

  MTRACE("requesting " << count << " from " << start_height << ", uncached");
  std::vector<uint64_t> weights = m_db->get_long_term_block_weights(start_height, count);
  m_long_term_block_weights_cache_tip_hash = tip_hash;
  m_long_term_block_weights_cache_rolling_median.clear();
  for (uint64_t w: weights)
    m_long_term_block_weights_cache_rolling_median.insert(w);
  return m_long_term_block_weights_cache_rolling_median.median();
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_block_weight_limit() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_weight_limit;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_block_weight_median() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_weight_median;
}
//------------------------------------------------------------------
//TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
//
// FIXME: this codebase references #if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
// in a lot of places.  That flag is not referenced in any of the code
// nor any of the makefiles, howeve.  Need to look into whether or not it's
// necessary at all.
bool Blockchain::create_block_template(block& b, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t median_weight;
  uint64_t already_generated_coins;
  uint64_t pool_cookie;

  seed_hash = crypto::null_hash;

  m_tx_pool.lock();
  const auto unlock_guard = epee::misc_utils::create_scope_leave_handler([&]() { m_tx_pool.unlock(); });
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if (m_btc_valid) {
    // The pool cookie is atomic. The lack of locking is OK, as if it changes
    // just as we compare it, we'll just use a slightly old template, but
    // this would be the case anyway if we'd lock, and the change happened
    // just after the block template was created
    if (miner_address == m_btc_address && m_btc_nonce == ex_nonce
      && m_btc_pool_cookie == m_tx_pool.cookie() && m_btc.prev_id == get_tail_id()) {
      const uint64_t now = time(NULL);
      if (m_btc.timestamp < now)
        m_btc.timestamp = now;
      // C2-R3: a cached template must satisfy the same rule as a fresh
      // one. The raise-to-now above keeps the timestamp strictly above
      // the (tip-unchanged, so identical) window median as the clock
      // advances; what it cannot repair is a BACKWARD clock step, which
      // can leave the cached timestamp beyond the current FTL deadline.
      // Revalidate through the rule owner rather than hand-rolling a
      // second copy of the bound here; on failure, drop the cache and
      // rebuild below — the fresh path's own edge refusal then decides
      // loudly. (This replaces the inherited raise-only path, whose
      // "ensures it can't get below the median" comment DAA_LWMA1.md
      // §5.5 had flagged as doc-vs-code drift.)
      uint64_t cached_median_ts;
      if (check_block_timestamp(m_btc, cached_median_ts))
      {
        MDEBUG("Using cached template");
        b = m_btc;
        diffic = m_btc_difficulty;
        height = m_btc_height;
        expected_reward = m_btc_expected_reward;
        seed_height = m_btc_seed_height;
        seed_hash = m_btc_seed_hash;
        return true;
      }
      MDEBUG("Cached template's timestamp no longer satisfies the C2-R3 rule (backward clock step?); rebuilding");
      invalidate_block_template_cache();
    }
    else
    {
      MDEBUG("Not using cached template: address " << (miner_address == m_btc_address) << ", nonce " << (m_btc_nonce == ex_nonce) << ", cookie " << (m_btc_pool_cookie == m_tx_pool.cookie()));
      invalidate_block_template_cache();
    }
  }

  // DRS/Stage-3a: the from_block (prev_block) template path was DELETED.
  // It built on a caller-specified parent, which could be an alt-chain block,
  // so m_db->height() != height there -- and there is no height-indexed curve
  // leaf count, so that path had no way to read its own parent's
  // frozen_segment_count for the D2 escalation. Templates now always extend the
  // tip, which makes m_db->height() == height an assertable precondition on
  // every surviving path. The RPC refuses prev_block loudly rather than
  // silently building on the tip. Reopen: see docs/FOLLOWUPS.md.
    height = m_db->height();
    b.major_version = m_hardfork->get_current_version();
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = get_tail_id();
    median_weight = m_current_block_cumul_weight_limit / 2;
    diffic = get_difficulty_for_next_block();
    already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
    seed_height = shekyl_pow_randomx_v2_seedheight(height);
    seed_hash = get_block_id_by_height(seed_height);
  b.timestamp = time(NULL);

  // Jagerman MTP patch (DAA_LWMA1.md §5.5): never issue a template the node
  // itself would reject. The floor is median + 1 — the smallest
  // consensus-valid value under the strict MTP boundary (C2-R3-Q1 sub-b;
  // a template AT the median is self-rejecting under `>`); median_ts is
  // set by the callee on every arm, including an FTL failure.
  uint64_t median_ts;
  if (!check_block_timestamp(b, median_ts))
  {
    b.timestamp = median_ts + 1;
    // The floor does NOT license an invalid template. When the window
    // median sits at or beyond the local FTL deadline, the constraint
    // set {ts : ts > median AND ts <= now + FTL} is EMPTY (median + 1
    // busts FTL; a maximal median even wraps the +1), so revalidate the
    // bump and refuse template creation honestly rather than hand the
    // miner a template this node would reject. Under a non-decreasing
    // local clock the state is at most one second wide (every stored
    // timestamp passed FTL against the clock at its own admission, so
    // the median can reach now + FTL only in the admission second) and
    // self-heals on the next tick. A BACKWARD clock step of D seconds
    // can hold median > now + FTL for up to D seconds — the refusal
    // then persists until the clock re-passes median - FTL, which is
    // still the correct behavior (a rolled-back clock minting blocks at
    // its own FTL edge would mint peer-rejected blocks); the operator
    // NTP-hygiene obligation is DAA_LWMA1.md §5.5's. Callers already
    // handle false from this function and retry.
    if (!check_block_timestamp(b, median_ts))
    {
      MERROR("create_block_template: no timestamp currently satisfies the C2-R3 rule (window median at or beyond the local FTL deadline); retry shortly - if this persists, verify the system clock (NTP), it may have stepped backward");
      return false;
    }
  }

  CHECK_AND_ASSERT_MES(diffic, false, "difficulty overhead.");

  size_t txs_weight;
  uint64_t fee;
  if (!m_tx_pool.fill_block_template(b, median_weight, already_generated_coins, height, txs_weight, fee, expected_reward, b.major_version))
  {
    return false;
  }
  pool_cookie = m_tx_pool.cookie();
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  size_t real_txs_weight = 0;
  uint64_t real_fee = 0;
  for(crypto::hash &cur_hash: b.tx_hashes)
  {
    auto cur_res = m_tx_pool.m_transactions.find(cur_hash);
    if (cur_res == m_tx_pool.m_transactions.end())
    {
      LOG_ERROR("Creating block template: error: transaction not found");
      continue;
    }
    tx_memory_pool::tx_details &cur_tx = cur_res->second;
    real_txs_weight += cur_tx.weight;
    real_fee += cur_tx.fee;
    if (cur_tx.weight != get_transaction_weight(cur_tx.tx))
    {
      LOG_ERROR("Creating block template: error: invalid transaction weight");
    }
    if (cur_tx.tx.version < 3)
    {
      LOG_ERROR("Creating block template: error: tx version < 3 is not supported on Shekyl");
      continue;
    }
    if (cur_tx.fee != cur_tx.tx.ct_signatures.txnFee)
    {
      LOG_ERROR("Creating block template: error: invalid fee");
    }
  }
  if (txs_weight != real_txs_weight)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated transaction weight");
  }
  if (fee != real_fee)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated fee");
  }
  MDEBUG("Creating block template: height " << height <<
      ", median weight " << median_weight <<
      ", already generated coins " << already_generated_coins <<
      ", transaction weight " << txs_weight <<
      ", fee " << fee);
#endif

  /*
   two-phase miner transaction generation: we don't know exact block weight until we prepare block, but we don't know reward until we know
   block weight, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block weight
   */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob weight
  uint8_t hf_version = b.major_version;
  size_t max_outs = 1;
  const uint64_t tx_volume_avg = get_tx_volume_avg(height);
  const uint64_t circulating_supply = already_generated_coins;
  const uint64_t genesis_ng_height = get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG);
  // D2 escalation operand, computed ONCE and passed to BOTH construct_miner_tx
  // calls: the retry below re-prices the coinbase after the weight changes, and
  // a second read there could price against a different n than the first pass
  // (criterion #1 — template and connect must agree by construction).
  const uint64_t frozen_segment_count = parent_frozen_segment_count(height);
  bool r = construct_miner_tx(height, median_weight, already_generated_coins, txs_weight, fee, frozen_segment_count, miner_address, b.miner_tx, ex_nonce, max_outs, hf_version, tx_volume_avg, circulating_supply, genesis_ng_height);
  CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, first chance");
  size_t cumulative_weight = txs_weight + get_transaction_weight(b.miner_tx);
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  MDEBUG("Creating block template: miner tx weight " << get_transaction_weight(b.miner_tx) <<
      ", cumulative weight " << cumulative_weight);
#endif
  for (size_t try_count = 0; try_count != 10; ++try_count)
  {
    r = construct_miner_tx(height, median_weight, already_generated_coins, cumulative_weight, fee, frozen_segment_count, miner_address, b.miner_tx, ex_nonce, max_outs, hf_version, tx_volume_avg, circulating_supply, genesis_ng_height);

    CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, second chance");
    size_t coinbase_weight = get_transaction_weight(b.miner_tx);
    if (coinbase_weight > cumulative_weight - txs_weight)
    {
      cumulative_weight = txs_weight + coinbase_weight;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
          ", cumulative weight " << cumulative_weight << " is greater than before");
#endif
      continue;
    }

    if (coinbase_weight < cumulative_weight - txs_weight)
    {
      size_t delta = cumulative_weight - txs_weight - coinbase_weight;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
          ", cumulative weight " << txs_weight + coinbase_weight <<
          " is less than before, adding " << delta << " zero bytes");
#endif
      b.miner_tx.extra.insert(b.miner_tx.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
      {
        CHECK_AND_ASSERT_MES(cumulative_weight + 1 == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " + 1 is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));
        b.miner_tx.extra.resize(b.miner_tx.extra.size() - 1);
        if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
        {
          //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_weight
          MDEBUG("Miner tx creation has no luck with delta_extra size = " << delta << " and " << delta - 1);
          cumulative_weight += delta - 1;
          continue;
        }
        MDEBUG("Setting extra for block: " << b.miner_tx.extra.size() << ", try_count=" << try_count);
      }
    }
    CHECK_AND_ASSERT_MES(cumulative_weight == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
        ", cumulative weight " << cumulative_weight << " is now good");
#endif

    {
      const auto root_bytes = m_db->get_curve_tree_root();
      static_assert(sizeof(b.curve_tree_root) == root_bytes.size());
      std::memcpy(&b.curve_tree_root, root_bytes.data(), root_bytes.size());
    }
    // Empty-set attestation root until the next slice computes from pass records.
    // Explicit (not only the constructor default) so a reused template never
    // retains a stale value (ARCHIVAL_CREDIT_WIRE.md §3).
    b.attestation_root = empty_attestation_root();

    // Always cacheable now: every template extends the tip (from_block deleted).
    cache_block_template(b, miner_address, ex_nonce, diffic, height, expected_reward, seed_height, seed_hash, pool_cookie);
    return true;
  }
  LOG_ERROR("Failed to create_block_template with " << 10 << " tries");
  return false;
}
//------------------------------------------------------------------
bool Blockchain::get_miner_data(uint8_t& major_version, uint64_t& height, crypto::hash& prev_id, crypto::hash& seed_hash, difficulty_type& difficulty, uint64_t& median_weight, uint64_t& already_generated_coins, std::vector<tx_block_template_backlog_entry>& tx_backlog)
{
  prev_id = m_db->top_block_hash(&height);
  ++height;

  major_version = m_hardfork->get_ideal_version(height);

  seed_hash = get_block_id_by_height(shekyl_pow_randomx_v2_seedheight(height));

  difficulty = get_difficulty_for_next_block();
  median_weight = m_current_block_cumul_weight_median;
  already_generated_coins = m_db->get_block_already_generated_coins(height - 1);

  m_tx_pool.get_block_template_backlog(tx_backlog);

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_tx_volume_avg(uint64_t height) const
{
  if (height == 0)
    return 0;

  const uint64_t start_height = height > SHEKYL_TX_VOLUME_WINDOW ? height - SHEKYL_TX_VOLUME_WINDOW : 0;
  const uint64_t blocks = height - start_height;
  if (blocks == 0)
    return 0;

  uint64_t tx_count_sum = 0;
  for (uint64_t h = start_height; h < height; ++h)
  {
    const block blk = m_db->get_block_from_height(h);
    tx_count_sum += blk.tx_hashes.size();
  }

  return tx_count_sum / blocks;
}
//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for SHEKYL_DAA_MTP_WINDOW.
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  if(timestamps.size() >= SHEKYL_DAA_MTP_WINDOW)
    return true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t need_elements = SHEKYL_DAA_MTP_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  timestamps.reserve(timestamps.size() + start_top_height - stop_offset);
  while (start_top_height != stop_offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(start_top_height));
    --start_top_height;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::build_alt_chain(const crypto::hash &prev_id, std::list<block_extended_info>& alt_chain, std::vector<uint64_t> &timestamps, block_verification_context& bvc) const
{
    //build alternative subchain, front -> mainchain, back -> alternative head
    cryptonote::alt_block_data_t data;
    cryptonote::blobdata blob;
    bool found = m_db->get_alt_block(prev_id, &data, &blob);
    timestamps.clear();
    while(found)
    {
      block_extended_info bei;
      CHECK_AND_ASSERT_MES(cryptonote::parse_and_validate_block_from_blob(blob, bei.bl), false, "Failed to parse alt block");
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cumulative_difficulty = data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      timestamps.push_back(bei.bl.timestamp);
      alt_chain.push_front(std::move(bei));
      found = m_db->get_alt_block(bei.bl.prev_id, &data, &blob);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(!alt_chain.empty())
    {
      // make sure alt chain doesn't somehow start past the end of the main chain
      CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front().height, false, "main blockchain wrong height");

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db->block_exists(alt_chain.front().bl.prev_id))
      {
        MERROR("alternate chain does not appear to connect to main chain...");
        return false;
      }

      // make sure block connects correctly to the main chain
      auto h = m_db->get_block_hash_from_height(alt_chain.front().height - 1);
      CHECK_AND_ASSERT_MES(h == alt_chain.front().bl.prev_id, false, "alternative chain has wrong connection to main chain");
      complete_timestamps_vector(m_db->get_block_height(alt_chain.front().bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      bool parent_in_main = m_db->block_exists(prev_id);
      CHECK_AND_ASSERT_MES(parent_in_main, false, "internal error: broken imperative condition: parent_in_main");

      complete_timestamps_vector(m_db->get_block_height(prev_id), timestamps);
    }

    return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(const block& b, const crypto::hash& id,
  block_verification_context& bvc, block_connect_supplement& connect)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  pool_supplement& extra_block_txs = connect.pool;
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;
  uint64_t block_height = get_block_height(b);
  if(0 == block_height)
  {
    MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative), but miner tx says height is 0.");
    bvc.m_verifivation_failed = true;
    return false;
  }
  // this basically says if the blockchain is smaller than the first
  // checkpoint then alternate blocks are allowed.  Alternatively, if the
  // last checkpoint *before* the end of the current chain is also before
  // the block to be added, then this is fine.
  if (!m_checkpoints.is_alternative_block_allowed(get_current_blockchain_height(), block_height))
  {
    MERROR_VER("Block with id: " << id << std::endl << " can't be accepted for alternative chain, block height: " << block_height << std::endl << " blockchain height: " << get_current_blockchain_height());
    bvc.m_verifivation_failed = true;
    return false;
  }

  // this is a cheap test
  const uint8_t hf_version = m_hardfork->get_ideal_version(block_height);
  if (!m_hardfork->check_for_height(b, block_height))
  {
    LOG_PRINT_L1("Block with id: " << id << std::endl << "has old version for height " << block_height);
    bvc.m_verifivation_failed = true;
    return false;
  }

  // the credit-wire attestation verify (ARCHIVAL_CREDIT_WIRE.md §3-§4). Cheap pre-cutover (empty
  // witness -> empty-set root recompute); post-cutover it does up to one hybrid-signature verify per
  // pass record, so the signature leg must sit behind PoW before population turns on (Phase-5
  // ordering constraint, see FOLLOWUPS). verify_block_attestation logs the specific verdict code.
  if (!verify_block_attestation(b, connect.attestation_witness))
  {
    bvc.m_verifivation_failed = true;
    return false;
  }

  //block is not related with head of main chain
  //first of all - look in alternative chains container
  alt_block_data_t prev_data;
  bool parent_in_alt = m_db->get_alt_block(b.prev_id, &prev_data, NULL);
  bool parent_in_main = m_db->block_exists(b.prev_id);
  if (parent_in_alt || parent_in_main)
  {
    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(b.prev_id, alt_chain, timestamps, bvc))
      return false;

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    const uint64_t prev_height = alt_chain.size() ? prev_data.height : m_db->get_block_height(b.prev_id);
    bei.height = prev_height + 1;
    // NOT the same quantity the main-chain path accumulates, despite sharing the
    // clamp with it. The main chain advances by the full emission subsidy
    // (validate_miner_transaction's base_reward — fix alpha, :1788); this
    // advances by what the coinbase PAYS, which carries the miner leg plus
    // miner_fee_income and omits the staker leg entirely. Per block the two
    // differ by (miner_fee_income - staker_emission): an undercount on fee-poor
    // blocks, an overcount when fees exceed the staker leg.
    // tests/core_tests/chaingen.cpp:459 documents the same asymmetry, and
    // recomputes the full reward for exactly this reason.
    //
    // It is an approximation BY CONSTRUCTION, not an oversight: the correct
    // value is what the ledger would hold if this chain were promoted, and
    // obtaining it requires the reward validation the alt path deliberately
    // defers (alt blocks get prevalidate_miner_transaction only) plus an
    // alt-chain weight median that does not exist — get_last_n_blocks_weights
    // reads the MAIN chain. Recomputing with main-chain medians would fabricate
    // a plausible-looking wrong number, which is worse than an honest one.
    //
    // Nothing reads it that can be harmed: no consensus decision consults it,
    // and promotion does not carry it into the ledger — handle_block_to_main_chain
    // re-reads already_generated_coins from the DB and only the attestation
    // witness is passed through. Its one external consumer, the post-reorg miner
    // notification, now reads the DB instead (see switch_to_alternative_blockchain).
    // Tracked in docs/FOLLOWUPS.md ("Alt-chain supply accumulation").
    uint64_t block_reward = get_outs_money_amount(b.miner_tx);
    const uint64_t prev_generated_coins = alt_chain.size() ? prev_data.already_generated_coins : m_db->get_block_already_generated_coins(prev_height);
    bei.already_generated_coins = shekyl_advance_already_generated(prev_generated_coins, block_reward);

    // C2-R3-Q1 sub-a: the ruled window is the 11 timestamps immediately
    // preceding the candidate. build_alt_chain + complete_timestamps_vector
    // hand back the full newest-first history (the whole alt chain, plus a
    // main-chain top-up only when the alt part is short), so keep the
    // newest 11 — the rule function refuses a wider window rather than
    // medianing it the way the inherited code did.
    if (timestamps.size() > SHEKYL_DAA_MTP_WINDOW)
      timestamps.resize(SHEKYL_DAA_MTP_WINDOW);

    // verify the block's timestamp: strictly above the window median and
    // within the future-time limit — FTL applies at alt ADMISSION, not
    // only at promotion (C2-R3-Q3)
    if(!check_block_timestamp(timestamps, b))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, has invalid timestamp: " << b.timestamp);
      bvc.m_verifivation_failed = true;
      return false;
    }

    bool is_a_checkpoint;
    if(!m_checkpoints.check_block(bei.height, id, is_a_checkpoint))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Check the block's hash against the difficulty target for its alt chain
    difficulty_type current_diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
    CHECK_AND_ASSERT_MES(current_diff, false, "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!");
    crypto::hash proof_of_work;
    memset(proof_of_work.data, 0xff, sizeof(proof_of_work.data));
    {
      crypto::hash seedhash = null_hash;
      uint64_t seedheight = shekyl_pow_randomx_v2_seedheight(bei.height);
      // seedblock is on the alt chain somewhere
      if (alt_chain.size() && alt_chain.front().height <= seedheight)
      {
        for (auto it=alt_chain.begin(); it != alt_chain.end(); it++)
        {
          if (it->height == seedheight+1)
          {
            seedhash = it->bl.prev_id;
            break;
          }
        }
      } else
      {
        seedhash = get_block_id_by_height(seedheight);
      }
      if (!get_altblock_longhash(bei.bl, proof_of_work, seedhash))
      {
        // CEN-D2, alt path: verifier failure rejects at every difficulty
        // (the sentinel alone passes check_hash at difficulty 1). Local
        // failure, not evidence against the block -- no m_bad_pow.
        MERROR_VER("PoW verifier failure (RandomX FFI) for alt block " << id
          << " -- block rejected unverified");
        bvc.m_verifivation_failed = true;
        return false;
      }
    }
    if(!check_hash(proof_of_work, current_diff))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, does not have enough proof of work: " << proof_of_work << std::endl << " expected difficulty: " << current_diff);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height, hf_version))
    {
      MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) has incorrect miner transaction.");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME:
    // this brings up an interesting point: consider allowing to get block
    // difficulty both by height OR by hash, not just height.
    difficulty_type main_chain_cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->height() - 1);
    if (alt_chain.size())
    {
      bei.cumulative_difficulty = prev_data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + prev_data.cumulative_difficulty_low;
    }
    else
    {
      // passed-in block's previous block's cumulative difficulty, found on the main chain
      bei.cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    }
    bei.cumulative_difficulty += current_diff;

    // Now that we have the PoW verification out of the way, verify all pool supplement txs
    tx_verification_context tvc{};
    if (!ver_non_input_consensus(extra_block_txs, tvc, hf_version))
    {
      MERROR_VER("Transaction pool supplement verification failure for alt block " << id);
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Add pool supplement txs to the main mempool with relay_method::block
    CRITICAL_REGION_LOCAL(m_tx_pool);
    for (auto& extra_block_tx : extra_block_txs.txs_by_txid)
    {
      const crypto::hash& txid = extra_block_tx.first;
      transaction& tx = extra_block_tx.second.first;
      const blobdata &tx_blob = extra_block_tx.second.second;

      tx_verification_context tvc{};
      if ((!m_tx_pool.have_tx(txid, relay_category::broadcasted) &&
          !m_db->tx_exists(txid) &&
          !m_tx_pool.add_tx(tx, tvc, relay_method::block, /*relayed=*/true, hf_version, /*origin=*/epee::net_utils::zone::invalid, hf_version))
          || tvc.m_verifivation_failed)
      {
        MERROR_VER("Transaction " << txid <<
          " in pool supplement failed to enter main pool for alt block " << id);
        bvc.m_verifivation_failed = true;
        return false;
      }

      // If new incoming tx in alt block passed verification and entered the pool, notify subscribers
      if (tvc.m_added_to_pool)
      {
        txpool_event evt{};
        evt.tx = tx;
        evt.hash = txid;
        evt.blob_size = tx_blob.size();
        evt.weight = get_transaction_weight(tx);
        evt.res = true;
        notify_txpool_event({std::move(evt)});
      }
    }
    extra_block_txs.txs_by_txid.clear();
    extra_block_txs.nic_verified_hf_version = 0;

    bei.block_cumulative_weight = cryptonote::get_transaction_weight(b.miner_tx);
    for (const crypto::hash &txid: b.tx_hashes)
    {
      cryptonote::tx_memory_pool::tx_details td;
      cryptonote::blobdata blob;
      if (m_tx_pool.have_tx(txid, relay_category::broadcasted))
      {
        if (m_tx_pool.get_transaction_info(txid, td, true/*include_sensitive_data*/))
        {
          bei.block_cumulative_weight += td.weight;
        }
        else
        {
          MERROR_VER("Transaction is in the txpool, but metadata not found");
          bvc.m_verifivation_failed = true;
          return false;
        }
      }
      else if (m_db->get_pruned_tx_blob(txid, blob))
      {
        cryptonote::transaction tx;
        if (!cryptonote::parse_and_validate_tx_base_from_blob(blob, tx))
        {
          MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) refers to unparsable transaction hash " << txid << ".");
          bvc.m_verifivation_failed = true;
          return false;
        }
        bei.block_cumulative_weight += cryptonote::get_pruned_transaction_weight(tx);
      }
      else
      {
        // we can't determine the block weight, set it to 0 and break out of the loop
        bei.block_cumulative_weight = 0;
        break;
      }
    }

    // add block to alternate blocks storage,
    // as well as the current "alt chain" container
    CHECK_AND_ASSERT_MES(!m_db->get_alt_block(id, NULL, NULL), false, "insertion of new alternative block returned as it already exists");
    cryptonote::alt_block_data_t data;
    data.height = bei.height;
    data.cumulative_weight = bei.block_cumulative_weight;
    data.cumulative_difficulty_low = (bei.cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    data.cumulative_difficulty_high = ((bei.cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    data.already_generated_coins = bei.already_generated_coins;
    m_db->add_alt_block(id, data, cryptonote::block_to_blob(bei.bl));
    // Store this alt block's credit-wire attestation witness (if any) keyed by block hash, so it
    // survives a later reorg-connect back to the main chain (ARCHIVAL_CREDIT_WIRE.md §3,
    // credit-wire CW-2). This is the ONLY writer of that table: the witness arrives here either
    // from the p2p transport (a fresh alt block) or from switch_to_alternative_blockchain (a block
    // demoted off main, which read it before the pop). Empty stores no row. Lifetime is the alt
    // block's — remove_alt_block / drop_alt_blocks / reset() are the only removers — so a row can
    // neither outlive its block nor be orphaned by a pop that never comes back.
    if (!connect.attestation_witness.empty())
      m_db->store_archival_alt_attestation_witness(id, connect.attestation_witness);
    alt_chain.push_back(bei);

    // FIXME: is it even possible for a checkpoint to show up not on the main chain?
    // C2-R1b-Q1a/Q1b: the fork-choice rule has ONE implementation --
    // shekyl-difficulty's fork_choice behind the FFI (strictly greater
    // switches, equality keeps, a checkpoint match forces). This site
    // marshals the two cumulative difficulties and consumes the verdict;
    // the DISCARD flag stays C++ orchestration keyed on the checkpoint
    // arm (a checkpoint-forced switch can promote a LIGHTER chain, and
    // re-admitting the heavier demoted chain would immediately switch
    // back -- the discard is the flip-flop terminator, round doc §4b).
    const cryptonote::difficulty_type fc_u64_mask =
        cryptonote::difficulty_type(std::numeric_limits<uint64_t>::max());
    shekyl_u128 fc_current{}, fc_alternative{};
    fc_current.lo = (main_chain_cumulative_difficulty & fc_u64_mask).convert_to<std::uint64_t>();
    fc_current.hi = (main_chain_cumulative_difficulty >> 64).convert_to<std::uint64_t>();
    fc_alternative.lo = (bei.cumulative_difficulty & fc_u64_mask).convert_to<std::uint64_t>();
    fc_alternative.hi = (bei.cumulative_difficulty >> 64).convert_to<std::uint64_t>();
    int32_t fc_verdict = SHEKYL_FORK_CHOICE_KEEP_CURRENT;
    if (shekyl_difficulty_fork_choice(fc_current, fc_alternative,
          is_a_checkpoint ? 1 : 0, &fc_verdict) != SHEKYL_DIFFICULTY_OK)
    {
      // Fail closed: an FFI failure must never silently keep OR switch.
      MERROR("fork-choice FFI failure for alt block " << id);
      bvc.m_verifivation_failed = true;
      return false;
    }
    if (fc_verdict == SHEKYL_FORK_CHOICE_SWITCH)
    {
      // C2-R1b F-1(a): pre-check the whole rollback against the prune
      // watermark BEFORE the switch mutates anything -- a mid-pop refusal
      // would force a pointless restore cycle. Same single predicate as the
      // pop_block belt, never a re-spelling. A refusal is a LOCAL retention
      // limitation, not block invalidity: the block above was already
      // stored as an alternative, so keep it, leave bvc clean, and return
      // success -- setting m_verifivation_failed here would make both P2P
      // receive paths drop and score every honest peer advertising the
      // heavier chain, isolating the degraded node onto its own fork. The
      // node is a live participant knowingly NOT following the heaviest
      // chain it has seen: flag it sticky (process-lifetime, re-armed on
      // every re-attempt), log loudly each time, and surface it on
      // get_info -- a silent healthy-looking continue would be exactly the
      // split the ruling forbids. (The parent-existence guard mirrors the
      // switch function's own first check; if the parent is somehow gone,
      // fall through and let that guard fail the switch as before.)
      if (m_db->block_exists(alt_chain.front().bl.prev_id))
      {
        const uint64_t fork_parent_height = m_db->get_block_height(alt_chain.front().bl.prev_id);
        if (!m_db->pop_target_allowed(fork_parent_height))
        {
          m_following_degraded.store(true, std::memory_order_relaxed);
          MERROR("REFUSED chain switch at the prune watermark: the alternative chain forks at height "
            << fork_parent_height << ", below the floor of epoch "
            << m_db->get_archival_prune_watermark_epoch()
            << " -- this node cannot safely revert that deep (rows already pruned)."
            << " Continuing DEGRADED on the current chain; the block is kept as an"
            << " alternative and its peer is not penalized; get_info reports"
            << " following_degraded=true; remedy: resync this node");
          return true;
        }
      }
      //do reorganize!
      MGINFO_GREEN("###### REORGANIZE on height: " << alt_chain.front().height << " of " << m_db->height() - 1
        << (is_a_checkpoint ? " (checkpoint-forced)" : "")
        << ": alt cum_difficulty " << bei.cumulative_difficulty
        << " vs main " << main_chain_cumulative_difficulty
        << ", alt tip height " << bei.height
        << ", alternative blockchain size: " << alt_chain.size());

      bool r = switch_to_alternative_blockchain(alt_chain, is_a_checkpoint);
      if (r)
        bvc.m_added_to_main_chain = true;
      else
        bvc.m_verifivation_failed = true;
      return r;
    }
    else
    {
      MGINFO_BLUE("----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height << std::endl << "id:\t" << id << std::endl << "PoW:\t" << proof_of_work << std::endl << "difficulty:\t" << current_diff);
      return true;
    }
  }
  else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    MERROR_VER("Block recognized as orphaned and rejected, id = " << id << ", height " << block_height
        << ", parent in alt " << parent_in_alt << ", parent in main " << parent_in_main
        << " (parent " << b.prev_id << ", current top " << get_tail_id() << ", chain height " << get_current_blockchain_height() << ")");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks, std::vector<cryptonote::blobdata>& txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;

  if (!get_blocks(start_offset, count, blocks))
  {
    return false;
  }

  for(const auto& blk : blocks)
  {
    std::vector<crypto::hash> missed_ids;
    get_transactions_blobs(blk.second.tx_hashes, txs, missed_ids);
    CHECK_AND_ASSERT_MES(!missed_ids.size(), false, "has missed transactions in own block in main blockchain");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  const uint64_t height = m_db->height();
  if(start_offset >= height)
    return false;

  blocks.reserve(blocks.size() + height - start_offset);
  for(size_t i = start_offset; i < start_offset + count && i < height;i++)
  {
    blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(i), block()));
    if (!parse_and_validate_block_from_blob(blocks.back().first, blocks.back().second))
    {
      LOG_ERROR("Invalid block");
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
//
//FIXME: This function appears to want to return false if any transactions
//       that belong with blocks are missing, but not if blocks themselves
//       are missing.
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  db_rtxn_guard rtxn_guard (m_db);
  rsp.current_blockchain_height = get_current_blockchain_height();
  std::vector<std::pair<cryptonote::blobdata,block>> blocks;
  get_blocks(arg.blocks, blocks, rsp.missed_ids);

  for (size_t i = 0; i < blocks.size(); ++i)
  {
    auto& bl = blocks[i];
    std::vector<crypto::hash> missed_tx_ids;

    rsp.blocks.push_back(block_complete_entry());
    block_complete_entry& e = rsp.blocks.back();

    // FIXME: s/rsp.missed_ids/missed_tx_id/ ?  Seems like rsp.missed_ids
    //        is for missed blocks, not missed transactions as well.
    e.pruned = arg.prune;
    get_transactions_blobs(bl.second.tx_hashes, e.txs, missed_tx_ids, arg.prune);
    if (missed_tx_ids.size() != 0)
    {
      // do not display an error if the peer asked for an unpruned block which we are not meant to have
      if (tools::has_unpruned_block(get_block_height(bl.second), get_current_blockchain_height(), get_blockchain_pruning_seed()))
      {
        LOG_ERROR("Error retrieving blocks, missed " << missed_tx_ids.size()
            << " transactions for block with hash: " << get_block_hash(bl.second)
            << std::endl
        );
      }

      // append missed transaction hashes to response missed_ids field,
      // as done below if any standalone transactions were requested
      // and missed.
      rsp.missed_ids.insert(rsp.missed_ids.end(), missed_tx_ids.begin(), missed_tx_ids.end());
      return false;
    }

    //pack block
    e.block = std::move(bl.first);
    e.block_weight = 0;
    if (arg.prune && m_db->block_exists(arg.blocks[i]))
      e.block_weight = m_db->get_block_weight(m_db->get_block_height(arg.blocks[i]));

    // Attach-if-present: empty for pruned / interim / all-miss — omitted on the wire by
    // KV_SERIALIZE_OPT. Whether a syncing node may accept a witness-pruned block is a Phase 2
    // admission decision, not here.
    e.attestation_witness = get_block_attestation_witness(bl.second);
  }

  return true;
}
//------------------------------------------------------------------
blobdata Blockchain::get_block_attestation_witness(const block& b) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // Key through the helper so the height+1 convention cannot drift from add_block
  // (ARCHIVAL_CREDIT_WIRE.md §3, credit-wire CW-2). get_block_height reads the
  // coinbase, so this costs no extra DB lookup at the serving sites.
  return m_db->get_archival_attestation_witness_at_height(
    archival_attestation_witness_key(get_block_height(b)));
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::vector<block>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref *blob) {
    if (!blob)
    {
      MERROR("No blob, but blobs were requested");
      return false;
    }
    cryptonote::block bl;
    if (cryptonote::parse_and_validate_block_from_blob(*blob, bl))
      blocks.push_back(std::move(bl));
    else
      MERROR("Failed to parse block from blob");
    return true;
  }, true);
  return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->get_alt_block_count();
}
crypto::public_key Blockchain::get_output_key(uint64_t amount, uint64_t global_index) const
{
  output_data_t data = m_db->get_output_key(amount, global_index);
  return data.pubkey;
}

//------------------------------------------------------------------
void Blockchain::get_output_key_mask_unlocked(const uint64_t& amount, const uint64_t& index, crypto::public_key& key, ct::key& mask, bool& unlocked) const
{
  const auto o_data = m_db->get_output_key(amount, index);
  key = o_data.pubkey;
  mask = o_data.commitment;
  tx_out_index toi = m_db->get_output_tx_and_index(amount, index);
  const uint8_t hf_version = m_hardfork->get_current_version();
  unlocked = is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first), hf_version);
}
//------------------------------------------------------------------
bool Blockchain::get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const
{
  // rct outputs don't exist before v4
  if (amount == 0 && m_nettype != network_type::FAKECHAIN)
    start_height = m_hardfork->get_earliest_ideal_height_for_version(HF_VERSION_DYNAMIC_FEE);
  else
    start_height = 0;
  base = 0;

  if (to_height > 0 && to_height < from_height)
    return false;

  if (from_height > start_height)
    start_height = from_height;

  distribution.clear();
  uint64_t db_height = m_db->height();
  if (db_height == 0)
    return false;
  if (start_height >= db_height || to_height >= db_height)
    return false;
  if (amount == 0)
  {
    std::vector<uint64_t> heights;
    heights.reserve(to_height + 1 - start_height);
    const uint64_t real_start_height = start_height > 0 ? start_height-1 : start_height;
    for (uint64_t h = real_start_height; h <= to_height; ++h)
      heights.push_back(h);
    distribution = m_db->get_block_cumulative_rct_outputs(heights);
    if (start_height > 0)
    {
      base = distribution[0];
      distribution.erase(distribution.begin());
    }
    return true;
  }
  else
  {
    return m_db->get_output_distribution(amount, start_height, to_height, distribution, base);
  }
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // make sure the request includes at least the genesis block, otherwise
  // how can we expect to sync from the client that the block list came from?
  if(qblock_ids.empty())
  {
    MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << qblock_ids.size() << ", dropping connection");
    return false;
  }

  db_rtxn_guard rtxn_guard(m_db);
  // make sure that the last block in the request's block list matches
  // the genesis block
  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(qblock_ids.back() != gen_hash)
  {
    MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch: " << std::endl << "id: " << qblock_ids.back() << ", " << std::endl << "expected: " << gen_hash << "," << std::endl << " dropping connection");
    return false;
  }

  // Find the first block the foreign chain has that we also have.
  // Assume qblock_ids is in reverse-chronological order.
  auto bl_it = qblock_ids.begin();
  uint64_t split_height = 0;
  for(; bl_it != qblock_ids.end(); bl_it++)
  {
    try
    {
      if (m_db->block_exists(*bl_it, &split_height))
        break;
    }
    catch (const std::exception& e)
    {
      MWARNING("Non-critical error trying to find block by hash in BlockchainDB, hash: " << *bl_it);
      return false;
    }
  }

  // this should be impossible, as we checked that we share the genesis block,
  // but just in case...
  if(bl_it == qblock_ids.end())
  {
    MERROR("Internal error handling connection, can't find split point");
    return false;
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
  starter_offset = split_height;
  return true;
}
//------------------------------------------------------------------
difficulty_type Blockchain::block_difficulty(uint64_t i) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    MERROR("Attempted to get block difficulty for height above blockchain height");
  }
  return 0;
}
//------------------------------------------------------------------
template<typename T> void reserve_container(std::vector<T> &v, size_t N) { v.reserve(N); }
template<typename T> void reserve_container(std::list<T> &v, size_t N) { }
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no blocks missed
template<class t_ids_container, class t_blocks_container, class t_missed_container>
bool Blockchain::get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  reserve_container(blocks, block_ids.size());
  for (const auto& block_hash : block_ids)
  {
    try
    {
      uint64_t height = 0;
      if (m_db->block_exists(block_hash, &height))
      {
        blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(height), block()));
        if (!parse_and_validate_block_from_blob(blocks.back().first, blocks.back().second))
        {
          LOG_ERROR("Invalid block: " << block_hash);
          blocks.pop_back();
          missed_bs.push_back(block_hash);
        }
      }
      else
        missed_bs.push_back(block_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, cryptonote::blobdata &tx, bool pruned)
{
  if (pruned)
  {
    if (!db->get_pruned_tx_blob(tx_hash, tx))
    {
      MDEBUG("Pruned transaction blob not found for " << tx_hash);
      return false;
    }
  }
  else
  {
    if (!db->get_tx_blob(tx_hash, tx))
    {
      MDEBUG("Transaction blob not found for " << tx_hash);
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, tx_blob_entry &tx, bool pruned)
{
  if (!fill(db, tx_hash, tx.blob, pruned))
    return false;
  if (pruned)
  {
    if (is_v1_tx(tx.blob))
    {
      // v1 txes aren't pruned, so fetch the whole thing
      cryptonote::blobdata prunable_blob;
      if (!db->get_prunable_tx_blob(tx_hash, prunable_blob))
      {
        MDEBUG("Prunable transaction blob not found for " << tx_hash);
        return false;
      }
      tx.blob.append(prunable_blob);
      tx.prunable_hash = crypto::null_hash;
    }
    else
    {
      if (!db->get_prunable_tx_hash(tx_hash, tx.prunable_hash))
      {
        MDEBUG("Prunable transaction data hash not found for " << tx_hash);
        return false;
      }
    }
  }
  return true;
}
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no transactions missed
bool Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::blobdata tx;
      if (fill(m_db, tx_hash, tx, pruned))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<tx_blob_entry>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      tx_blob_entry tx;
      if (fill(m_db, tx_hash, tx, pruned))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_transactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs, bool pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  reserve_container(txs, txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::blobdata tx;
      bool res = pruned ? m_db->get_pruned_tx_blob(tx_hash, tx) : m_db->get_tx_blob(tx_hash, tx);
      if (res)
      {
        txs.push_back(transaction());
        res = pruned ? parse_and_validate_tx_base_from_blob(tx, txs.back()) : parse_and_validate_tx_from_blob(tx, txs.back());
        if (!res)
        {
          LOG_ERROR("Invalid transaction");
          return false;
        }
      }
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, std::vector<crypto::hash>& hashes, std::vector<uint64_t>* weights, uint64_t& start_height, uint64_t& current_height, bool clip_pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if we can't find the split point, return false
  if(!find_blockchain_supplement(qblock_ids, start_height))
  {
    return false;
  }

  db_rtxn_guard rtxn_guard(m_db);
  current_height = get_current_blockchain_height();
  uint64_t stop_height = current_height;
  if (clip_pruned)
  {
    const uint32_t pruning_seed = get_blockchain_pruning_seed();
    if (start_height < tools::get_next_unpruned_block_height(start_height, current_height, pruning_seed))
    {
      MDEBUG("We only have a pruned version of the common ancestor");
      return false;
    }
    stop_height = tools::get_next_pruned_block_height(start_height, current_height, pruning_seed);
  }
  size_t count = 0;
  const size_t reserve = std::min((size_t)(stop_height - start_height), (size_t)BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT);
  hashes.reserve(reserve);
  if (weights)
    weights->reserve(reserve);
  for(size_t i = start_height; i < stop_height && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT; i++, count++)
  {
    hashes.push_back(m_db->get_block_hash_from_height(i));
    if (weights)
      weights->push_back(m_db->get_block_weight(i));
  }

  return true;
}

bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, bool clip_pruned, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  bool result = find_blockchain_supplement(qblock_ids, resp.m_block_ids, &resp.m_block_weights, resp.start_height, resp.total_height, clip_pruned);
  if (result)
  {
    cryptonote::difficulty_type wide_cumulative_difficulty = m_db->get_block_cumulative_difficulty(resp.total_height - 1);
    resp.cumulative_difficulty = (wide_cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    resp.cumulative_difficulty_top64 = ((wide_cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  return result;
}
//------------------------------------------------------------------
//FIXME: change argument to std::vector, low priority
// find split point between ours and foreign blockchain (or start at
// blockchain height <req_start_block>), and return up to max_count FULL
// blocks by reference.
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid by tx returned status existed");
  MINFO("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
void Blockchain::flush_invalid_blocks()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_invalid_blocks.clear();
}
//------------------------------------------------------------------
bool Blockchain::have_block_unlocked(const crypto::hash& id, int *where) const
{
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  LOG_PRINT_L3("Blockchain::" << __func__);

  if(m_db->block_exists(id))
  {
    LOG_PRINT_L2("block " << id << " found in main chain");
    if (where) *where = HAVE_BLOCK_MAIN_CHAIN;
    return true;
  }

  if(m_db->get_alt_block(id, NULL, NULL))
  {
    LOG_PRINT_L2("block " << id << " found in alternative chains");
    if (where) *where = HAVE_BLOCK_ALT_CHAIN;
    return true;
  }

  if(m_invalid_blocks.count(id))
  {
    LOG_PRINT_L2("block " << id << " found in m_invalid_blocks");
    if (where) *where = HAVE_BLOCK_INVALID;
    return true;
  }

  return false;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id, int *where) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return have_block_unlocked(id, where);
}
//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc)
{
    LOG_PRINT_L3("Blockchain::" << __func__);
    crypto::hash id = get_block_hash(bl);
    block_connect_supplement connect{};
    return handle_block_to_main_chain(bl, id, bvc, connect);
}
//------------------------------------------------------------------
size_t Blockchain::get_total_transactions() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(const transaction& tx, key_images_container& keys_this_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  struct add_transaction_input_visitor
  {
    key_images_container& m_spent_keys;
    BlockchainDB* m_db;
    add_transaction_input_visitor(key_images_container& spent_keys, BlockchainDB* db) :
      m_spent_keys(spent_keys), m_db(db)
    {
    }
    bool operator()(const txin_to_key& in) const
    {
      const crypto::key_image& ki = in.k_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

    bool operator()(const txin_gen& tx) const
    {
      return true;
    }
    bool operator()(const txin_to_script& tx) const
    {
      return false;
    }
    bool operator()(const txin_to_scripthash& tx) const
    {
      return false;
    }
    bool operator()(const txin_archival_serve_credit_response& in) const
    {
      (void)in;
      return true;
    }
    bool operator()(const txin_archival_bond_post& in) const
    {
      (void)in;
      return true;
    }
    bool operator()(const txin_archival_reward_emission& in) const
    {
      // No key image: emission dedup is claimed_settlement_epochs (WS-2 journaled
      // check-and-set) + the block-level (P,E) pass, not this container.
      (void)in;
      return true;
    }
  };

  for (const txin_v& in : tx.vin)
  {
    if(!std::visit(add_transaction_input_visitor(keys_this_block, m_db), in))
    {
      LOG_ERROR("Double spend detected!");
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  indexs = m_db->get_tx_amount_output_indices(tx_index, n_txes);
  CHECK_AND_ASSERT_MES(n_txes == indexs.size(), false, "Wrong indexs size");

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  std::vector<std::vector<uint64_t>> indices = m_db->get_tx_amount_output_indices(tx_index, 1);
  CHECK_AND_ASSERT_MES(indices.size() == 1, false, "Wrong indices size");
  indexs = indices.front();
  return true;
}
//------------------------------------------------------------------
//FIXME: it seems this function is meant to be merely a wrapper around
//       another function of the same name, this one adding one bit of
//       functionality.  Should probably move anything more than that
//       (getting the hash of the block at height max_used_block_id)
//       to the other function to keep everything in one place.
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(transaction& tx, uint64_t& max_used_block_height, crypto::hash& max_used_block_id, tx_verification_context &tvc, bool kept_by_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  TIME_MEASURE_START(a);
  bool res = check_tx_inputs(tx, tvc, &max_used_block_height);
  TIME_MEASURE_FINISH(a);
  if(m_show_time_stats)
  {
    MINFO("HASH: " <<  get_transaction_hash(tx) << " I/O: " << tx.vin.size() << "/" << tx.vout.size() << " H: " << max_used_block_height << " ms: " << a + m_fake_scan_time << " B: " << get_object_blobsize(tx) << " W: " << get_transaction_weight(tx));
  }
  if (!res)
    return false;

  CHECK_AND_ASSERT_MES(max_used_block_height < m_db->height(), false,  "internal error: max used block index=" << max_used_block_height << " is not less then blockchain size = " << m_db->height());
  max_used_block_id = m_db->get_block_hash_from_height(max_used_block_height);
  return true;
}
//------------------------------------------------------------------
// Validate outPk commitment masks per the GENESIS_TX_WIRE_FORMAT.md §2.3
// output-point rule — a thin marshaling shim over shekyl_check_commitment_masks
// (single home: shekyl-ct-balance). The Rust side enforces:
//
// Structural (every mask): canonical, prime-order (torsion-free) encoding —
// the same strictness the FCMP++ leaf builder applies, so no accepted mask is
// silently skipped from the curve tree. LOAD-BEARING DOWNSTREAM (CEN-L11):
// blockchain_db.cpp's leaf collector now THROWS on a construct_leaf failure
// rather than dropping the output, on the strength of this gate and
// check_outs_valid; weakening either surfaces as an abort at block connect. For non-coinbase this is redundant
// with shekyl_verify_ct_balance's point gate; for coinbase (CTTypeNull, no
// balance equation) this is the sole gate.
//
// Trivial forms (every mask): identity (mask=0, amount=0) and G (mask=1,
// amount=0) — defense-in-depth against construction bugs.
//
// Coinbase fingerprint: C != zeroCommit(public_amount) = G + amount*H, the
// trivially-computable commitment that would leak the confidential-coinbase
// amount to any observer.
static bool check_commitment_mask_valid(const transaction& tx)
{
  const auto& rv = tx.ct_signatures;

  // Every tx shape carries exactly one outPk commitment per vout (0 == 0 for
  // the no-output serve-credit shape). The wire serializer already pins this
  // (serialize_ctsig_base sizes outPk to vout.size(), ct_types.h) and
  // check_tx_semantic re-checks it for pool txs — but this gate must be
  // locally sound rather than lean on a distant invariant, or an empty outPk
  // beside a non-empty vout would skate through the empty fast-path below
  // with no mask ever checked.
  if (rv.outPk.size() != tx.vout.size())
  {
    MERROR("outPk count " << rv.outPk.size() << " != vout count " << tx.vout.size()
      << ", tx " << get_transaction_hash(tx));
    return false;
  }
  if (rv.outPk.empty())
    return true;

  static_assert(sizeof(ct::key) == 32, "ct::key must be 32 bytes");
  std::vector<uint8_t> masks_flat;
  masks_flat.reserve(rv.outPk.size() * sizeof(ct::key));
  for (const auto& pk : rv.outPk)
    masks_flat.insert(masks_flat.end(), pk.mask.bytes, pk.mask.bytes + sizeof(ct::key));

  std::vector<uint64_t> coinbase_amounts;
  if (rv.type == ct::CTTypeNull)
  {
    coinbase_amounts.reserve(tx.vout.size());
    for (const auto& o : tx.vout)
      coinbase_amounts.push_back(o.amount);
  }

  const uint8_t rc = shekyl_check_commitment_masks(
    masks_flat.data(), rv.outPk.size(),
    coinbase_amounts.empty() ? nullptr : coinbase_amounts.data(),
    coinbase_amounts.size());
  switch (rc)
  {
    case SHEKYL_OUTPUT_POINTS_OK:
      return true;
    case SHEKYL_OUTPUT_POINTS_ERR_INVALID_MASK:
      MERROR("An output commitment mask is not a canonical prime-order point, tx "
        << get_transaction_hash(tx));
      return false;
    case SHEKYL_OUTPUT_POINTS_ERR_TRIVIAL_MASK:
      MERROR("An output commitment mask uses a trivial amount-leaking form "
        "(identity, G, or coinbase zeroCommit), tx " << get_transaction_hash(tx));
      return false;
    default:
      MERROR("shekyl_check_commitment_masks failed with rc=" << unsigned(rc)
        << ", tx " << get_transaction_hash(tx));
      return false;
  }
}
//------------------------------------------------------------------
bool Blockchain::check_tx_outputs(const transaction& tx, tx_verification_context &tvc, std::uint8_t hf_version)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  if (tx.version < 3)
  {
    MERROR_VER("Transaction version " << tx.version << " is not supported (minimum: 3)");
    tvc.m_invalid_output = true;
    return false;
  }

  // All v3+ outputs must have 0 amount (amounts are encrypted in RingCT) —
  // except the archival emission tx's reward vouts, which are loud by design
  // (REWARD_EMISSION_VIN_PLAN.md §4: plaintext reward amounts are the
  // priority-1 inflation-audit surface). Their sum is bound three ways: the
  // CT balance equation (verCtSemanticsEmission), the Rust arithmetic
  // cross-check (check_tx_inputs' vout_reward_sum operand), and P's Q1
  // field-7 signed commit set.
  // Skip the ban ONLY for a well-formed emission tx (the SAME classification
  // check_tx_inputs uses — not a bare emission-vin count, which would also
  // exempt a malformed tx pairing an emission vin with a bond-post or extra
  // special vin and leak the zero-amount enforcement to a distant FCMP assert).
  if (classify_archival_tx(tx.vin).kind != archival_tx_kind::emission)
  {
    for (auto &o: tx.vout) {
      if (o.amount != 0) {
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  if (tx.ct_signatures.type != ct::CTTypeNull &&
      tx.ct_signatures.type != ct::CTTypeFcmpPlusPlusPqc)
  {
    MERROR_VER("Disallowed rct type " << (unsigned)tx.ct_signatures.type);
    tvc.m_invalid_output = true;
    return false;
  }

  if (tx.unlock_time >= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL)
  {
    MERROR_VER("Transaction uses timestamp-based unlock_time (" << tx.unlock_time
               << " >= sentinel " << CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL << ")");
    tvc.m_invalid_output = true;
    return false;
  }

  // require view tags on outputs
  if (!check_output_types(tx, hf_version))
  {
    tvc.m_invalid_output = true;
    return false;
  }

  // Commitment mask validation: reject trivial masks (mask=0 or mask=1).
  // Non-coinbase path. Coinbase is validated in prevalidate_miner_transaction.
  if (!check_commitment_mask_valid(tx))
  {
    MERROR_VER("Output commitment mask validation failed");
    tvc.m_invalid_output = true;
    return false;
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  for (const txin_v& in: tx.vin)
  {
    if (std::holds_alternative<txin_to_key>(in))
    {
      if (have_tx_keyimg_as_spent(std::get<txin_to_key>(in).k_image))
        return true;
    }
  }
  return false;
}
//------------------------------------------------------------------
std::vector<bool> Blockchain::have_tx_keyimges_as_spent(const epee::span<const crypto::key_image> key_imgs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->has_key_images(key_imgs);
}
//------------------------------------------------------------------
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc, uint64_t* pmax_used_block_height, bool skip_fcmp_verify) const
{
  PERF_TIMER(check_tx_inputs);
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t sig_index = 0;
  if(pmax_used_block_height)
    *pmax_used_block_height = 0;

  crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  const uint8_t hf_version = m_hardfork->get_current_version();
  const bool is_fcmp_pp = ct::is_ct_fcmp_pp_pqc(tx.ct_signatures.type);

  // Shared archival-tx taxonomy (classify_archival_tx, cryptonote_basic.h):
  // one special vin with key-imaged spends as the only permitted co-residents
  // (the Q11 mixing rule — REWARD_EMISSION_E3_GATING_ROUND.md §2.2; arity 1 per
  // Q3 §2.1); any other combination is `none` and falls through to the regular
  // FCMP++ path, whose txin_to_key assertion rejects it. Single-sourced with
  // check_tx_outputs and ver_non_input_consensus so all three agree on the kind.
  const archival_tx_classification archival_class = classify_archival_tx(tx.vin);
  const bool is_archival_serve_credit_only = (archival_class.kind == archival_tx_kind::serve_credit_only);
  const bool is_archival_bond_post_tx = (archival_class.kind == archival_tx_kind::bond_post);
  const bool is_archival_emission_tx = (archival_class.kind == archival_tx_kind::emission);
  const size_t archival_bond_post_index = archival_class.special_index;
  const size_t archival_emission_index = archival_class.special_index;

  if (tx.version >= 2 && !is_archival_serve_credit_only)
  {
    if (tx.vout.size() < 2)
    {
      MERROR_VER("Tx " << get_transaction_hash(tx) << " has fewer than two outputs");
      tvc.m_too_few_outputs = true;
      return false;
    }
  }

  if (m_nettype != network_type::FAKECHAIN)
  {
    if (!is_fcmp_pp)
    {
      MERROR_VER("Tx " << get_transaction_hash(tx) << " must use CTTypeFcmpPlusPlusPqc; CTTypeNull is only allowed for coinbase");
      tvc.m_verifivation_failed = true;
      return false;
    }

    if (tx.vin.size() > FCMP_MAX_INPUTS_PER_TX)
    {
      MERROR_VER("FCMP++ tx " << get_transaction_hash(tx) << " has " << tx.vin.size()
        << " inputs, max is " << FCMP_MAX_INPUTS_PER_TX);
      tvc.m_verifivation_failed = true;
      return false;
    }

    const size_t max_tx_version = 3;
    if (tx.version > max_tx_version)
    {
      MERROR_VER("transaction version " << (unsigned)tx.version << " is higher than max accepted version " << max_tx_version);
      tvc.m_verifivation_failed = true;
      return false;
    }
    const size_t min_tx_version = 3;
    if (tx.version < min_tx_version)
    {
      MERROR_VER("transaction version " << (unsigned)tx.version << " is lower than min accepted version " << min_tx_version);
      tvc.m_verifivation_failed = true;
      return false;
    }
  }

  // sorted ins
  {
    const crypto::key_image *last_key_image = NULL;
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      const txin_v &txin = tx.vin[n];
      const crypto::key_image* ki = nullptr;
      if (std::holds_alternative<txin_to_key>(txin))
        ki = &std::get<txin_to_key>(txin).k_image;

      if (ki)
      {
        if (last_key_image && memcmp(ki, last_key_image, sizeof(*last_key_image)) >= 0)
        {
          MERROR_VER("transaction has unsorted inputs");
          tvc.m_verifivation_failed = true;
          return false;
        }
        last_key_image = ki;
      }
    }
  }

  std::vector<std::vector<ct::ctkey>> pubkeys(tx.vin.size());

  // Block connect passes nullptr; steer to stack storage so FCMP++ paths can
  // always update max reference height without a null check at each write site.
  uint64_t max_used_block_height = 0;
  if (!pmax_used_block_height)
    pmax_used_block_height = &max_used_block_height;

  if (is_archival_serve_credit_only)
  {
    // Serve-credit responses: non-spending archival vins; hybrid signature
    // lives on the vin (gate-2 §5).
  }
  else if (is_archival_bond_post_tx)
  {
    for (const auto& txin : tx.vin)
    {
      if (!std::holds_alternative<txin_to_key>(txin))
        continue;
      const txin_to_key& in_to_key = std::get<txin_to_key>(txin);
      if (!in_to_key.key_offsets.empty())
      {
        MERROR_VER("Archival bond-post spend input has non-empty key_offsets");
        tvc.m_verifivation_failed = true;
        return false;
      }
      if (have_tx_keyimg_as_spent(in_to_key.k_image))
      {
        MERROR_VER("Archival bond-post key image already spent");
        tvc.m_double_spend = true;
        return false;
      }
    }
  }
  else if (is_archival_emission_tx)
  {
    // Fee inputs (>= 0 permitted, Q11): same key-imaged txin_to_key pre-gates
    // as bond-post funding inputs. The emission vin itself carries no key
    // image — its anti-replay is the per-epoch dedup (WS-2).
    for (const auto& txin : tx.vin)
    {
      if (!std::holds_alternative<txin_to_key>(txin))
        continue;
      const txin_to_key& in_to_key = std::get<txin_to_key>(txin);
      if (!in_to_key.key_offsets.empty())
      {
        MERROR_VER("Archival emission fee input has non-empty key_offsets");
        tvc.m_verifivation_failed = true;
        return false;
      }
      if (have_tx_keyimg_as_spent(in_to_key.k_image))
      {
        MERROR_VER("Archival emission fee-input key image already spent");
        tvc.m_double_spend = true;
        return false;
      }
    }
  }
  else if (is_fcmp_pp)
  {
    // ─── FCMP++ per-input validation ────────────────────────────────────
    for (const auto& txin : tx.vin)
    {
      CHECK_AND_ASSERT_MES(std::holds_alternative<txin_to_key>(txin), false,
        "FCMP++ tx inputs must be txin_to_key at Blockchain::check_tx_inputs");
      const txin_to_key& in_to_key = std::get<txin_to_key>(txin);

      if (!in_to_key.key_offsets.empty())
      {
        MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
          << " has non-empty key_offsets on input with k_image " << in_to_key.k_image);
        tvc.m_verifivation_failed = true;
        return false;
      }

      if (have_tx_keyimg_as_spent(in_to_key.k_image))
      {
        MERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(in_to_key.k_image));
        tvc.m_double_spend = true;
        return false;
      }
    }
  }
  else
  {
    MERROR_VER("Non-FCMP++ transaction rejected: ring-based inputs are not supported from genesis");
    tvc.m_verifivation_failed = true;
    return false;
  }

  {
    const ct::CtSig &rv = tx.ct_signatures;
    switch (rv.type)
    {
    case ct::CTTypeNull: {
      MERROR_VER("CTTypeNull is not allowed for non-coinbase transactions");
      tvc.m_verifivation_failed = true;
      return false;
    }
    case ct::CTTypeFcmpPlusPlusPqc:
    {
      const uint64_t chain_height = m_db->height();
      const size_t num_inputs = tx.vin.size();

      if (!is_archival_serve_credit_only && tx.pqc_auths.size() != num_inputs)
      {
        MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
          << " pqc_auths count " << tx.pqc_auths.size()
          << " does not match input count " << num_inputs);
        tvc.m_verifivation_failed = true;
        return false;
      }

      if (!is_archival_serve_credit_only && !is_archival_bond_post_tx
        && !is_archival_emission_tx
        && rv.p.pseudoOuts.size() != num_inputs)
      {
        MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
          << " pseudoOuts count " << rv.p.pseudoOuts.size()
          << " does not match input count " << num_inputs);
        tvc.m_verifivation_failed = true;
        return false;
      }

      if (is_archival_serve_credit_only)
      {
        if (!tx.pqc_auths.empty())
        {
          MERROR_VER("Archival serve-credit tx " << get_transaction_hash(tx)
            << " must not carry pqc_auths (signature is on the vin)");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (!tx.vout.empty() || rv.txnFee != 0)
        {
          MERROR_VER("Archival serve-credit tx " << get_transaction_hash(tx)
            << " must have no outputs and zero fee");
          tvc.m_verifivation_failed = true;
          tvc.m_invalid_output = true;
          return false;
        }
        if (!rv.outPk.empty() || !rv.p.bulletproofs_plus.empty()
          || !rv.p.pseudoOuts.empty())
        {
          MERROR_VER("Archival serve-credit tx " << get_transaction_hash(tx)
            << " must not carry RCT output material");
          tvc.m_verifivation_failed = true;
          tvc.m_invalid_output = true;
          return false;
        }
        if (!rv.p.fcmp_pp_proof.empty())
        {
          MERROR_VER("Archival serve-credit tx " << get_transaction_hash(tx)
            << " must not carry an FCMP++ membership proof");
          tvc.m_verifivation_failed = true;
          return false;
        }
        // PC-D3: `block_hash(h-1)` for the slot this tx is being validated FOR.
        //
        // `chain_height` already means "the height the next block will occupy"
        // on both paths, so the parent is at `chain_height - 1`. Derived from
        // that variable rather than from a second `height()` read: the two
        // would then be independent reads that a connect could separate,
        // leaving a height and a hash describing different slots. This way
        // they are one slot by construction.
        //
        // On the block path this IS the validated block's `prev_id`, and as a
        // CHECKED invariant rather than an ambient one --
        // `handle_block_to_main_chain` refuses `bl.prev_id != top_hash`
        // before any tx here runs. It is read from the chain rather
        // than taken from `bl` because this function has no block, and
        // reading it here keeps the pool path -- which has no block at all --
        // on an identical derivation.
        //
        // On the pool path it is the current tip, which makes a pooled
        // serve-credit record NEXT-BLOCK-ONLY: once another block connects,
        // the record's derivation is bound to a hash that is no longer the
        // tip's and it can never be admitted. That is PC-D2 working -- a
        // response is valid in exactly one block -- not a defect. The pool is
        // transport, not a claim about which block the record belongs to
        // (ARCHIVAL_PER_CHALLENGE_RECORD.md §5.3).
        //
        // Read inside this branch, not beside `chain_height` above: only
        // serve-credit txs need it, and the outer scope is every FCMP++ tx.
        // The zero-height arm cannot be reached by a serve-credit tx, but
        // yields the all-zero hash the FFI refuses rather than a wrapped
        // height -- `top_block_hash(&h)` would have underflowed its out-param
        // to UINT64_MAX here.
        const crypto::hash slot_prev_block_hash = chain_height
          ? m_db->get_block_hash_from_height(chain_height - 1)
          : crypto::null_hash;

        // RF-D1: one pruned pass record per serve-credit vin, in vin order.
        // Every vin is a serve-credit in this shape, so index i pairs them.
        const auto& pruned_records = tx.ct_signatures.p.serve_credit_pruned;
        if (pruned_records.size() != num_inputs)
        {
          MERROR_VER("Archival serve-credit: " << pruned_records.size()
            << " pruned records for " << num_inputs << " vins");
          tvc.m_verifivation_failed = true;
          return false;
        }
        for (size_t i = 0; i < num_inputs; ++i)
        {
          const txin_archival_serve_credit_response& resp =
            std::get<txin_archival_serve_credit_response>(tx.vin[i]);
          if (!check_archival_serve_credit_input(resp, pruned_records[i], chain_height,
                slot_prev_block_hash))
          {
            MERROR_VER("Archival serve-credit validation failed for input " << i);
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
      }
      else if (is_archival_bond_post_tx)
      {
        const txin_archival_bond_post& bond =
          std::get<txin_archival_bond_post>(tx.vin[archival_bond_post_index]);
        // The auth-key selection (gate-4 §3.5 step 5 — identity key on
        // credit, the record's committed bond_spend_pk on debit) lives inside
        // check_archival_bond_post_input, which has the record access; the
        // bond input's pqc auth key is passed in for that pinning. The
        // signature over the whole-tx payload is verified against the same
        // key by verify_transaction_pqc_auth.
        if (!check_archival_bond_post_input(bond,
              tx.pqc_auths[archival_bond_post_index].hybrid_public_key, chain_height))
        {
          MERROR_VER("Archival bond-post validation failed");
          tvc.m_verifivation_failed = true;
          return false;
        }

        std::vector<size_t> spend_indices;
        spend_indices.reserve(tx.vin.size());
        for (size_t i = 0; i < tx.vin.size(); ++i)
        {
          if (std::holds_alternative<txin_to_key>(tx.vin[i]))
            spend_indices.push_back(i);
        }
        // The funding-input floor is decided HERE, in C++, and it is the last
        // copy of a rule Rust already owns: `bond_post_funding_floor_met`
        // (`shekyl-archival-retention::bond_post`), which the wallet-side
        // producer calls so the two sides state one rule. Marshaling
        // `spend_indices.size()` to that predicate — the standing
        // decision-placement pin, as `shekyl_archival_bond_post_block_unique`
        // below — is what deletes this copy; do not repair a divergence by
        // editing the condition here.
        if (spend_indices.empty())
        {
          MERROR_VER("Archival bond-post tx requires at least one txin_to_key funding input");
          tvc.m_verifivation_failed = true;
          return false;
        }

        const size_t num_spend = spend_indices.size();
        if (rv.p.pseudoOuts.size() != num_spend)
        {
          MERROR_VER("Archival bond-post tx pseudoOuts count " << rv.p.pseudoOuts.size()
            << " does not match spend input count " << num_spend);
          tvc.m_verifivation_failed = true;
          return false;
        }

        uint64_t ref_height = 0;
        if (!m_db->block_exists(rv.referenceBlock, &ref_height))
        {
          MERROR_VER("Archival bond-post tx referenceBlock not found");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (chain_height < FCMP_REFERENCE_BLOCK_MIN_AGE ||
            ref_height > chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE)
        {
          MERROR_VER("Archival bond-post tx referenceBlock too recent");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (chain_height > FCMP_REFERENCE_BLOCK_MAX_AGE &&
            ref_height < chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE)
        {
          MERROR_VER("Archival bond-post tx referenceBlock too old");
          tvc.m_verifivation_failed = true;
          return false;
        }
        *pmax_used_block_height = ref_height;

        std::array<uint8_t, 32> tree_root = m_db->get_curve_tree_root_at_height(ref_height);
        const uint8_t current_depth = m_db->get_curve_tree_depth();
        if (rv.p.curve_trees_tree_depth == 0 || rv.p.curve_trees_tree_depth > current_depth)
        {
          MERROR_VER("Archival bond-post tx curve_trees_tree_depth out of range");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (rv.p.fcmp_pp_proof.empty())
        {
          MERROR_VER("Archival bond-post tx has empty FCMP++ proof");
          tvc.m_verifivation_failed = true;
          return false;
        }

        std::vector<uint8_t> key_images_flat(num_spend * 32);
        std::vector<uint8_t> pseudo_outs_flat(num_spend * 32);
        std::vector<uint8_t> pqc_hashes_flat(num_spend * 32);
        for (size_t j = 0; j < num_spend; ++j)
        {
          const size_t i = spend_indices[j];
          const txin_to_key& in_to_key = std::get<txin_to_key>(tx.vin[i]);
          memcpy(key_images_flat.data() + j * 32, &in_to_key.k_image, 32);
          memcpy(pseudo_outs_flat.data() + j * 32, rv.p.pseudoOuts[j].bytes, 32);
          const auto& hpk = tx.pqc_auths[i].hybrid_public_key;
          if (!shekyl_fcmp_pqc_leaf_hash(hpk.data(), hpk.size(), pqc_hashes_flat.data() + j * 32))
          {
            MERROR_VER("Archival bond-post tx pqc leaf hash failed for spend input " << i);
            tvc.m_verifivation_failed = true;
            return false;
          }
        }

        if (!skip_fcmp_verify)
        {
          const uint8_t fcmp_layers = static_cast<uint8_t>(rv.p.curve_trees_tree_depth + 1);
          const uint8_t fcmp_result = shekyl_fcmp_verify(
            rv.p.fcmp_pp_proof.data(),
            rv.p.fcmp_pp_proof.size(),
            key_images_flat.data(),
            num_spend,
            pseudo_outs_flat.data(),
            num_spend,
            pqc_hashes_flat.data(),
            num_spend,
            tree_root.data(),
            fcmp_layers,
            reinterpret_cast<const uint8_t*>(tx_prefix_hash.data));
          if (fcmp_result != 0)
          {
            MERROR_VER("Archival bond-post FCMP++ proof verification failed (code "
              << (int)fcmp_result << ")");
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
      }
      else if (is_archival_emission_tx)
      {
        // ── C-1 emission dispatch (REWARD_EMISSION_E3_GATING_ROUND.md §9.5
        // item 5). LIVE from genesis: the item-4 whitelist flip landed in
        // this cut (check_inputs_types_supported now accepts a single emission
        // vin — cryptonote_format_utils.cpp) and archival emission is a
        // genesis fact, so a well-formed txin_archival_reward_emission
        // reaches full verify+connect here. This branch mints coins on
        // acceptance — treat every check below as load-bearing consensus.
        const txin_archival_reward_emission& emission =
          std::get<txin_archival_reward_emission>(tx.vin[archival_emission_index]);

        // Pre-parse the opaque blob (the Rust codec is its only parser;
        // C++ reads nothing past the tag byte): claimant id + claimed epochs.
        crypto::hash p_canonical_id{};
        uint64_t vin_epochs[SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS] = {};
        size_t vin_epochs_len = 0;
        const uint8_t extract_rc = shekyl_archival_emission_vin_extract(
          emission.canonical_bytes.data(), emission.canonical_bytes.size(),
          reinterpret_cast<uint8_t*>(p_canonical_id.data),
          vin_epochs, SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS, &vin_epochs_len);
        if (extract_rc != SHEKYL_EMISSION_VIN_OK || vin_epochs_len == 0)
        {
          MERROR_VER("Archival emission vin parse failed (code " << (int)extract_rc << ")");
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Tx-level PQC slot binding: the emission slot's hybrid key must
        // derive the vin's P_canonical_id, so the tx-wide hybrid signature
        // over this slot (tx_pqc_verify.cpp) is P's — mirroring bond-post's
        // pubkey-equality pin with the id as the comparable (the vin's
        // P_pubkey stays inside the opaque blob).
        const auto& emission_auth = tx.pqc_auths[archival_emission_index];
        crypto::hash auth_p_id{};
        if (!shekyl_archival_p_canonical_id_from_pubkey(
              emission_auth.hybrid_public_key.data(),
              emission_auth.hybrid_public_key.size(),
              reinterpret_cast<uint8_t*>(auth_p_id.data))
            || auth_p_id != p_canonical_id)
        {
          MERROR_VER("Archival emission pqc_auths[" << archival_emission_index
            << "] hybrid pubkey does not derive the vin's P_canonical_id");
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Fee-spend subset (Q11: >= 0 txin_to_key co-residents; with none,
        // the fee is paid out of the mint and the balance closes in the
        // emission RCT semantics — block 4).
        std::vector<size_t> spend_indices;
        spend_indices.reserve(tx.vin.size());
        for (size_t i = 0; i < tx.vin.size(); ++i)
        {
          if (std::holds_alternative<txin_to_key>(tx.vin[i]))
            spend_indices.push_back(i);
        }
        const size_t num_spend = spend_indices.size();
        if (rv.p.pseudoOuts.size() != num_spend)
        {
          MERROR_VER("Archival emission tx pseudoOuts count " << rv.p.pseudoOuts.size()
            << " does not match fee-input count " << num_spend);
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Reference block + curve-tree context (bond-post idiom). Required
        // even with zero fee inputs: the vin's membership-only backing proof
        // verifies against this root.
        uint64_t ref_height = 0;
        if (!m_db->block_exists(rv.referenceBlock, &ref_height))
        {
          MERROR_VER("Archival emission tx referenceBlock not found");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (chain_height < FCMP_REFERENCE_BLOCK_MIN_AGE ||
            ref_height > chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE)
        {
          MERROR_VER("Archival emission tx referenceBlock too recent");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (chain_height > FCMP_REFERENCE_BLOCK_MAX_AGE &&
            ref_height < chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE)
        {
          MERROR_VER("Archival emission tx referenceBlock too old");
          tvc.m_verifivation_failed = true;
          return false;
        }
        *pmax_used_block_height = ref_height;

        std::array<uint8_t, 32> tree_root = m_db->get_curve_tree_root_at_height(ref_height);
        const uint8_t current_depth = m_db->get_curve_tree_depth();
        if (rv.p.curve_trees_tree_depth == 0 || rv.p.curve_trees_tree_depth > current_depth)
        {
          MERROR_VER("Archival emission tx curve_trees_tree_depth out of range");
          tvc.m_verifivation_failed = true;
          return false;
        }
        // One tx-declared depth for both proofs, in upstream layers units
        // (LMDB depth + 1): the backing proof's wire tree_depth must equal
        // this (verify_membership_only pins equality), and the fee-input
        // FCMP++ proof below takes the same value.
        const uint8_t fcmp_layers = static_cast<uint8_t>(rv.p.curve_trees_tree_depth + 1);

        // Signable hash (F-C1c): the prefix hash of the tx with the emission
        // vin removed wholesale. The vin cannot be covered by the hash its
        // own auths and backing proof sign (circularity); every property the
        // exclusion could lose is re-bound explicitly by the Q1 auth message
        // (vin fields 1–6) and the reward commit set (field 7), and the
        // tx-level hybrid auth (tx_pqc_verify.cpp) covers the complete
        // prefix including the assembled vin.
        crypto::hash signable_tx_hash;
        {
          transaction_prefix pruned = static_cast<const transaction_prefix&>(tx);
          pruned.vin.erase(pruned.vin.begin() + archival_emission_index);
          signable_tx_hash = get_transaction_prefix_hash(pruned);
        }

        // Claimant's pre-block bond record (the WS-2 read side's operand).
        shekyl::db::ArchivalBondValue bond;
        const bool bond_present = m_db->get_archival_bond_value(p_canonical_id, bond);

        // As-of-E snapshots, one per claimed epoch in claim order. An absent
        // frozen budget row means the epoch never closed (or was pruned) —
        // a gather failure, rejected here rather than marshaled.
        std::vector<ArchivalEmissionEpochSnapshot> snaps(vin_epochs_len);
        std::vector<std::vector<shekyl_archival_epoch_close_bond>> ffi_bonds(vin_epochs_len);
        std::vector<std::vector<shekyl_archival_epoch_close_shard>> ffi_shards(vin_epochs_len);
        std::vector<std::vector<shekyl_archival_credit_pair>> ffi_pairs(vin_epochs_len);
        std::vector<shekyl_archival_emission_epoch_snapshot> ffi_snaps(vin_epochs_len);
        for (size_t k = 0; k < vin_epochs_len; ++k)
        {
          m_db->gather_archival_emission_epoch_snapshot(p_canonical_id, vin_epochs[k], snaps[k]);
          if (!snaps[k].has_budget_row)
          {
            MERROR_VER("Archival emission claimed epoch " << vin_epochs[k]
              << " has no frozen budget row (epoch not closed, or pruned)");
            tvc.m_verifivation_failed = true;
            return false;
          }
          ffi_bonds[k] = snaps[k].to_ffi_bonds();
          ffi_shards[k] = snaps[k].to_ffi_shards();
          ffi_pairs[k] = snaps[k].to_ffi_credit_pairs();
          shekyl_archival_emission_epoch_snapshot s{};
          s.settlement_epoch = snaps[k].settlement_epoch;
          s.close_block_height = snaps[k].close_block_height;
          s.sigma_work_milli = snaps[k].sigma_work_milli;
          s.budget_atomic = snaps[k].budget_atomic;
          s.bonds_ptr = ffi_bonds[k].empty() ? nullptr : ffi_bonds[k].data();
          s.bonds_len = ffi_bonds[k].size();
          s.shards_ptr = ffi_shards[k].empty() ? nullptr : ffi_shards[k].data();
          s.shards_len = ffi_shards[k].size();
          s.credit_pairs_ptr = ffi_pairs[k].empty() ? nullptr : ffi_pairs[k].data();
          s.credit_pairs_len = ffi_pairs[k].size();
          s.claimant_bond_idx = snaps[k].claimant_bond_idx;
          ffi_snaps[k] = s;
        }

        // Ordered reward vout commit set (§8.0.2 field 7): the vouts carrying
        // loud (non-zero plaintext) amounts, in vout order. Zero-amount vouts
        // are ordinary confidential outputs (change) and join neither the
        // commit set nor the sum.
        if (rv.outPk.size() != tx.vout.size())
        {
          MERROR_VER("Archival emission tx outPk count " << rv.outPk.size()
            << " does not match vout count " << tx.vout.size());
          tvc.m_verifivation_failed = true;
          return false;
        }
        std::vector<uint8_t> commits_flat;
        commits_flat.reserve(tx.vout.size() * 72);
        std::vector<uint64_t> reward_amounts;
        reward_amounts.reserve(tx.vout.size());
        size_t reward_commit_count = 0;
        for (size_t i = 0; i < tx.vout.size(); ++i)
        {
          const uint64_t amount = tx.vout[i].amount;
          if (amount == 0)
            continue;
          reward_amounts.push_back(amount);
          crypto::public_key one_time_key;
          if (!get_output_public_key(tx.vout[i], one_time_key))
          {
            MERROR_VER("Archival emission reward vout " << i << " has no output public key");
            tvc.m_verifivation_failed = true;
            return false;
          }
          const size_t off = commits_flat.size();
          commits_flat.resize(off + 72);
          memcpy(commits_flat.data() + off, rv.outPk[i].mask.bytes, 32);
          for (size_t b = 0; b < 8; ++b)
            commits_flat[off + 32 + b] = static_cast<uint8_t>((amount >> (8 * b)) & 0xff);
          memcpy(commits_flat.data() + off + 40, &one_time_key, 32);
          ++reward_commit_count;
        }
        // Amount arithmetic in Rust (rule 20): the reward total is the
        // inflation-audit operand, checked-summed once and single-sourced with
        // the CT-balance shape check (tx_verification_utils.cpp).
        uint64_t vout_reward_sum = 0;
        if (shekyl_checked_sum_amounts(
              reward_amounts.empty() ? nullptr : reward_amounts.data(),
              reward_amounts.size(), &vout_reward_sum) != 0)
        {
          MERROR_VER("Archival emission reward vout sum overflows");
          tvc.m_verifivation_failed = true;
          return false;
        }

        // The coarse verify crossing: §7.1 claims 1–5, membership-only
        // backing 6, hybrid auth gate 8 — one FFI call, verdict + operands
        // for the connect arm (block 5).
        uint64_t total_reward = 0;
        uint64_t epochs_to_commit[SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS] = {};
        size_t epochs_to_commit_len = 0;
        const uint8_t verify_rc = shekyl_emission_vin_verify(
          emission.canonical_bytes.data(), emission.canonical_bytes.size(),
          chain_height,
          vout_reward_sum,
          bond_present ? 1 : 0,
          bond.join_settlement_epoch,
          bond.holdings_kind,
          bond.held_shard_ids.empty() ? nullptr : bond.held_shard_ids.data(),
          bond.held_shard_ids.size(),
          bond.claimed_settlement_epochs.empty()
            ? nullptr : bond.claimed_settlement_epochs.data(),
          bond.claimed_settlement_epochs.size(),
          ffi_snaps.data(), ffi_snaps.size(),
          tree_root.data(),
          fcmp_layers,
          reinterpret_cast<const uint8_t*>(signable_tx_hash.data),
          commits_flat.empty() ? nullptr : commits_flat.data(),
          reward_commit_count,
          &total_reward,
          epochs_to_commit, SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS, &epochs_to_commit_len);
        if (verify_rc != SHEKYL_EMISSION_VIN_OK)
        {
          MERROR_VER("Archival emission vin verification failed (code "
            << (int)verify_rc << ")");
          tvc.m_verifivation_failed = true;
          return false;
        }
        MDEBUG("Archival emission vin verified: total_reward=" << total_reward
          << " epochs_to_commit=" << epochs_to_commit_len);

        // §7.1 step 7: fee-input FCMP++ membership/balance over the
        // txin_to_key subset — identical to bond-post funding inputs. With
        // zero fee inputs the prunable proof must be absent (the backing
        // proof lives inside the vin, not here).
        if (num_spend == 0)
        {
          if (!rv.p.fcmp_pp_proof.empty())
          {
            MERROR_VER("Archival emission tx with no fee inputs must not carry an FCMP++ proof");
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
        else
        {
          if (rv.p.fcmp_pp_proof.empty())
          {
            MERROR_VER("Archival emission tx has fee inputs but an empty FCMP++ proof");
            tvc.m_verifivation_failed = true;
            return false;
          }

          std::vector<uint8_t> key_images_flat(num_spend * 32);
          std::vector<uint8_t> pseudo_outs_flat(num_spend * 32);
          std::vector<uint8_t> pqc_hashes_flat(num_spend * 32);
          for (size_t j = 0; j < num_spend; ++j)
          {
            const size_t i = spend_indices[j];
            const txin_to_key& in_to_key = std::get<txin_to_key>(tx.vin[i]);
            memcpy(key_images_flat.data() + j * 32, &in_to_key.k_image, 32);
            memcpy(pseudo_outs_flat.data() + j * 32, rv.p.pseudoOuts[j].bytes, 32);
            const auto& hpk = tx.pqc_auths[i].hybrid_public_key;
            if (!shekyl_fcmp_pqc_leaf_hash(hpk.data(), hpk.size(), pqc_hashes_flat.data() + j * 32))
            {
              MERROR_VER("Archival emission tx pqc leaf hash failed for fee input " << i);
              tvc.m_verifivation_failed = true;
              return false;
            }
          }

          if (!skip_fcmp_verify)
          {
            const uint8_t fcmp_result = shekyl_fcmp_verify(
              rv.p.fcmp_pp_proof.data(),
              rv.p.fcmp_pp_proof.size(),
              key_images_flat.data(),
              num_spend,
              pseudo_outs_flat.data(),
              num_spend,
              pqc_hashes_flat.data(),
              num_spend,
              tree_root.data(),
              fcmp_layers,
              reinterpret_cast<const uint8_t*>(tx_prefix_hash.data));
            if (fcmp_result != 0)
            {
              MERROR_VER("Archival emission fee-input FCMP++ proof verification failed (code "
                << (int)fcmp_result << ")");
              tvc.m_verifivation_failed = true;
              return false;
            }
          }
        }
      }
      else
      {
        // ── Regular FCMP++ spend path ─────────────────────────────────

        // Step 1: referenceBlock age validation
        uint64_t ref_height = 0;
        if (!m_db->block_exists(rv.referenceBlock, &ref_height))
        {
          MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
            << " referenceBlock " << rv.referenceBlock << " not found in chain");
          tvc.m_verifivation_failed = true;
          return false;
        }

        if (chain_height < FCMP_REFERENCE_BLOCK_MIN_AGE ||
            ref_height > chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE)
        {
          MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
            << " referenceBlock at height " << ref_height
            << " is too recent (min age " << FCMP_REFERENCE_BLOCK_MIN_AGE
            << ", chain height " << chain_height << ")");
          tvc.m_verifivation_failed = true;
          return false;
        }

        if (chain_height > FCMP_REFERENCE_BLOCK_MAX_AGE &&
            ref_height < chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE)
        {
          MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
            << " referenceBlock at height " << ref_height
            << " is too old (max age " << FCMP_REFERENCE_BLOCK_MAX_AGE
            << ", chain height " << chain_height << ")");
          tvc.m_verifivation_failed = true;
          return false;
        }

        *pmax_used_block_height = ref_height;

        // Step 2: the membership anchor is the curve-tree state at chain height
        // ref_height -- after the reference block's parent connected, before its
        // own drain (CEN-I12). The verifier reads its own per-height record of
        // that state, never the block header: the header is the block's
        // attestation of the same value, bound to the record by the CEN-B5
        // admission check, and a verifier that trusted it would be trusting the
        // block it is validating.
        std::array<uint8_t, 32> tree_root = m_db->get_curve_tree_root_at_height(ref_height);

        MDEBUG("FCMP++ verify: ref_height=" << ref_height
          << " tree_root=" << epee::string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tree_root.data()), 32))
          << " tx_depth=" << (int)rv.p.curve_trees_tree_depth
          << " proof_len=" << rv.p.fcmp_pp_proof.size()
          << " num_inputs=" << num_inputs
          << " tx_prefix_hash=" << epee::string_tools::pod_to_hex(tx_prefix_hash));

        // Step 3: Validate curve_trees_tree_depth
        const uint8_t current_depth = m_db->get_curve_tree_depth();
        if (rv.p.curve_trees_tree_depth == 0 || rv.p.curve_trees_tree_depth > current_depth)
        {
          MERROR_VER("FCMP++ tx " << get_transaction_hash(tx)
            << " curve_trees_tree_depth " << (int)rv.p.curve_trees_tree_depth
            << " out of range (current depth " << (int)current_depth << ")");
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Step 4: FCMP++ proof verification
        if (rv.p.fcmp_pp_proof.empty())
        {
          MERROR_VER("FCMP++ tx " << get_transaction_hash(tx) << " has empty proof");
          tvc.m_verifivation_failed = true;
          return false;
        }

        std::vector<uint8_t> key_images_flat(num_inputs * 32);
        for (size_t i = 0; i < num_inputs; ++i)
        {
          const txin_to_key& in_to_key = std::get<txin_to_key>(tx.vin[i]);
          memcpy(key_images_flat.data() + i * 32, &in_to_key.k_image, 32);
        }

        std::vector<uint8_t> pseudo_outs_flat(num_inputs * 32);
        for (size_t i = 0; i < num_inputs; ++i)
          memcpy(pseudo_outs_flat.data() + i * 32, rv.p.pseudoOuts[i].bytes, 32);

        std::vector<uint8_t> pqc_hashes_flat(num_inputs * 32);
        for (size_t i = 0; i < num_inputs; ++i)
        {
          const auto& hpk = tx.pqc_auths[i].hybrid_public_key;
          if (!shekyl_fcmp_pqc_leaf_hash(hpk.data(), hpk.size(), pqc_hashes_flat.data() + i * 32))
          {
            MERROR_VER("FCMP++ tx " << get_transaction_hash(tx) << " pqc leaf hash failed for input " << i);
            tvc.m_verifivation_failed = true;
            return false;
          }
        }

        for (size_t dbg_i = 0; dbg_i < num_inputs; ++dbg_i)
        {
          MDEBUG("FCMP++ verify input " << dbg_i
            << " ki=" << epee::string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(key_images_flat.data() + dbg_i * 32), 32))
            << " pseudo_out=" << epee::string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(pseudo_outs_flat.data() + dbg_i * 32), 32))
            << " pqc_hash=" << epee::string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(pqc_hashes_flat.data() + dbg_i * 32), 32)));
        }

        if (skip_fcmp_verify)
        {
          MDEBUG("FCMP++ proof verification skipped (cache hit) for tx " << get_transaction_hash(tx));
        }
        else
        {
          // Convert LMDB depth to upstream layers count (depth + 1).
          const uint8_t fcmp_layers = static_cast<uint8_t>(rv.p.curve_trees_tree_depth + 1);
          const uint8_t fcmp_result = shekyl_fcmp_verify(
            rv.p.fcmp_pp_proof.data(),
            rv.p.fcmp_pp_proof.size(),
            key_images_flat.data(),
            num_inputs,
            pseudo_outs_flat.data(),
            num_inputs,
            pqc_hashes_flat.data(),
            num_inputs,
            tree_root.data(),
            fcmp_layers,
            reinterpret_cast<const uint8_t*>(tx_prefix_hash.data)
          );

          if (fcmp_result != 0)
          {
            MERROR_VER("FCMP++ proof verification failed for tx " << get_transaction_hash(tx)
                       << " (error code " << (int)fcmp_result << ")");
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
      }

      break;
    }
    default:
      MERROR_VER("Unsupported ct type: " << rv.type);
      return false;
    }
  }

  // v3 PQC hybrid signature verification (per-input hybrid Ed25519+ML-DSA,
  // or M-of-N multisig, over each input's signing-payload hash).
  //
  // MSW-6 (PQC_MULTISIG.md §16.3): the former tx-wide scheme_id agreement was
  // withdrawn. Its *stated* purpose — a cross-input scheme-downgrade defense —
  // was vacuous: `expected_scheme` was derived from `tx.pqc_auths[0]` itself
  // (self-referential), and per-output scheme binding is the leaf hash
  // `h_pqc = H(hybrid_public_key)` (see :3769, `shekyl_fcmp_pqc_leaf_hash`),
  // not this check. Its *effect* was to make a tx that spends a solo (scheme 1)
  // output and a multisig (scheme 2) output together unrepresentable — under
  // FCMP++ separate txs are unlinkable, so co-spending is the only proof of
  // common control across key models. That belongs in the wallet, not consensus,
  // on no externality: the two outputs are one-time keys and the FCMP++ proof
  // ranges over the whole tree, so no other party's anonymity set shrinks
  // (unlike a small ring poisoning others' decoys — the reason ring size *is*
  // consensus). Shekyl already permits exactly this opt-in class (a scheme_id=2
  // spend marks the spender, a disclosed opt-in cost), so refusing an opt-in
  // cross-model link at consensus would be incoherent. It is a wallet
  // coin-selection invariant — a BLOCKING E′/MS-5 ship gate (see §16.3), not a
  // consensus mechanism. (NOT TM-1, whose disposition rests on the linkage being
  // impossible to mechanize; here the mechanism existed and worked.)
  // Each input is still validated per-input (scheme ∈ {1,2}, key-blob length,
  // signature); only the cross-input agreement is dropped.
  if (tx.version >= 3 && !tx.vin.empty() && !std::holds_alternative<txin_gen>(tx.vin[0])
      && !is_archival_serve_credit_only)
  {
    if (!verify_transaction_pqc_auth(tx))
    {
      MERROR_VER("Failed to verify PQC hybrid signature on v3 transaction");
      tvc.m_verifivation_failed = true;
      return false;
    }
  }

  return true;
}

//------------------------------------------------------------------
uint64_t Blockchain::get_dynamic_base_fee(uint64_t block_reward, size_t median_block_weight, uint8_t version)
{
  const uint64_t min_block_weight = get_min_block_weight(version);
  if (median_block_weight < min_block_weight)
    median_block_weight = min_block_weight;
  uint64_t hi, lo;

  // min_fee_per_byte = round_up( 0.95 * block_reward * ref_weight / (fee_median^2) )
  // fee_median (a.k.a. median_block_weight) equals effective long term median
  lo = mul128(block_reward, DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT, &hi);
  div128_64(hi, lo, median_block_weight, &hi, &lo, NULL, NULL);
  div128_64(hi, lo, median_block_weight, &hi, &lo, NULL, NULL);
  assert(hi == 0);
  lo -= lo / 20;
  return lo == 0 ? 1 : lo;
}

//------------------------------------------------------------------
uint64_t Blockchain::get_current_fee_per_byte() const
{
  const uint8_t version = get_current_hard_fork_version();

  uint64_t base_reward = 0;
  uint64_t median = m_current_block_cumul_weight_limit / 2;
  const uint64_t blockchain_height = m_db->height();
  uint64_t already_generated_coins = blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
  if (!get_block_reward(median, 1, already_generated_coins, base_reward, version))
    return 0;

  // get_dynamic_base_fee never returns 0, so 0 is unambiguously the
  // block-reward-failure arm above.
  return get_dynamic_base_fee(base_reward, std::min<uint64_t>(median, m_long_term_effective_median_block_weight), version);
}
//------------------------------------------------------------------
bool Blockchain::check_fee(size_t tx_weight, uint64_t fee) const
{
  const uint64_t fee_per_byte = get_current_fee_per_byte();
  if (fee_per_byte == 0)
    return false;
  MDEBUG("Using " << print_money(fee_per_byte) << "/byte fee");
  uint64_t needed_fee = tx_weight * fee_per_byte;
  const uint64_t mask = get_fee_quantization_mask();
  needed_fee = (needed_fee + mask - 1) / mask * mask;

  if (fee < needed_fee - needed_fee / 50) // keep a little 2% buffer on acceptance - no integer overflow
  {
    MERROR_VER("transaction fee is not enough: " << print_money(fee) << ", minimum fee: " << print_money(needed_fee));
    return false;
  }
  return true;
}

//------------------------------------------------------------------
void Blockchain::get_dynamic_base_fee_estimate_2021_scaling(uint64_t grace_blocks, uint64_t base_reward, uint64_t Mnw, uint64_t Mlw, std::vector<uint64_t> &fees) const
{
  // variable names and calculations as per https://github.com/ArticMine/Monero-Documents/blob/master/MoneroScaling2021-02.pdf
  // from (earlier than) this fork, the base fee is per byte
  const uint64_t Mfw = std::min(Mnw, Mlw);

  // 3 kB divided by something ? It's going to be either 0 or *very* quantized, so fold it into integer steps below
  //const uint64_t Brlw = DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / Mfw;

  // constant.... equal to 0, unless floating point, so fold it into integer steps below
  //const uint64_t Br = DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5

  //const uint64_t Fl = base_reward * Brlw / Mfw; fold Brlw from above
  const uint64_t Fl = base_reward * /*Brlw*/ DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (Mfw * Mfw);

  // fold Fl into this for better precision (and to match the test cases in the PDF)
  // const uint64_t Fn = 4 * Fl;
  const uint64_t Fn = 4 * base_reward * /*Brlw*/ DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (Mfw * Mfw);

  // const uint64_t Fm = 16 * base_reward * Br / Mfw; fold Br from above
  const uint64_t Fm = 16 * base_reward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * Mfw);

  // const uint64_t Fp = 2 * base_reward / Mnw;

  // fold Br from above, move 4Fm in the max to decrease quantization effect
  //const uint64_t Fh = 4 * Fm * std::max<uint64_t>(1, Mfw / (32 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT * Mnw / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5));
  const uint64_t Fh = std::max<uint64_t>(4 * Fm, 4 * Fm * Mfw / (32 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT * Mnw / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5));

  fees.resize(4);
  fees[0] = cryptonote::round_money_up(Fl, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  fees[1] = cryptonote::round_money_up(Fn, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  fees[2] = cryptonote::round_money_up(Fm, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  fees[3] = cryptonote::round_money_up(Fh, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
}

void Blockchain::get_dynamic_base_fee_estimate_2021_scaling(uint64_t grace_blocks, std::vector<uint64_t> &fees) const
{
  const uint8_t version = get_current_hard_fork_version();
  const uint64_t db_height = m_db->height();

  CHECK_AND_ASSERT_THROW_MES(grace_blocks <= CRYPTONOTE_REWARD_BLOCKS_WINDOW, "Grace blocks invalid In 2021 fee scaling estimate.");

  // we want Mlw = median of max((min(Mbw, 1.7 * Ml), Zm), Ml / 1.7)
  // Mbw: block weight for the last 99990 blocks, 0 for the next 10
  // Ml: penalty free zone (dynamic), aka long_term_median, aka median of max((min(Mb, 1.7 * Ml), Zm), Ml / 1.7)
  // Zm: 300000 (minimum penalty free zone)
  //
  // So we copy the current rolling median state, add 10 (grace_blocks) zeroes to it, and get back Mlw

  epee::misc_utils::rolling_median_t<uint64_t> rm = m_long_term_block_weights_cache_rolling_median;
  for (size_t i = 0; i < grace_blocks; ++i)
    rm.insert(0);
  const uint64_t Mlw_penalty_free_zone_for_wallet = std::max<uint64_t>(rm.median(), CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5);

  // Msw: median over [100 - grace blocks] past + [grace blocks] future blocks
  std::vector<uint64_t> weights;
  get_last_n_blocks_weights(weights, 100 - grace_blocks);
  weights.reserve(100);
  for (size_t i = 0; i < grace_blocks; ++i)
    weights.push_back(0);
  const uint64_t Msw_effective_short_term_median = std::max(epee::misc_utils::median(weights), Mlw_penalty_free_zone_for_wallet);

  const uint64_t Mnw = std::min(Msw_effective_short_term_median, 50 * Mlw_penalty_free_zone_for_wallet);

  uint64_t already_generated_coins = db_height ? m_db->get_block_already_generated_coins(db_height - 1) : 0;
  uint64_t base_reward;
  if (!get_block_reward(m_current_block_cumul_weight_limit / 2, 1, already_generated_coins, base_reward, version))
  {
    MERROR("Failed to determine block reward, using placeholder " << print_money(BLOCK_REWARD_OVERESTIMATE) << " as a high bound");
    base_reward = BLOCK_REWARD_OVERESTIMATE;
  }

  get_dynamic_base_fee_estimate_2021_scaling(grace_blocks, base_reward, Mnw, Mlw_penalty_free_zone_for_wallet, fees);
}

//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(uint64_t unlock_time, uint8_t hf_version) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    // ND: Instead of calling get_current_blockchain_height(), call m_db->height()
    //    directly as get_current_blockchain_height() locks the recursive mutex.
    if(m_db->height()-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }
  else
  {
    //interpret as time
    const uint64_t current_time = get_adjusted_time(m_db->height());
    if(current_time + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.  It also checks the ring
// signature for each input.
bool Blockchain::check_tx_input(size_t tx_version, const txin_to_key& txin, const crypto::hash& tx_prefix_hash, const std::vector<crypto::signature>& sig, const ct::CtSig &ct_signatures, std::vector<ct::ctkey> &output_keys, uint64_t* pmax_related_block_height, uint8_t hf_version) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND:
  // 1. Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<ct::ctkey >& m_output_keys;
    const Blockchain& m_bch;
    const uint8_t hf_version;
    outputs_visitor(std::vector<ct::ctkey>& output_keys, const Blockchain& bch, uint8_t hf_version) :
      m_output_keys(output_keys), m_bch(bch), hf_version(hf_version)
    {
    }
    bool handle_output(uint64_t unlock_time, const crypto::public_key &pubkey, const ct::key &commitment)
    {
      //check tx unlock time
      if (!m_bch.is_tx_spendtime_unlocked(unlock_time, hf_version))
      {
        MERROR_VER("One of outputs for one of inputs has wrong tx.unlock_time = " << unlock_time);
        return false;
      }

      // The original code includes a check for the output corresponding to this input
      // to be a txout_to_key. This is removed, as the database does not store this info.
      // Only txout_to_key (and since HF_VERSION_VIEW_TAGS, txout_to_tagged_key)
      // outputs are stored in the DB in the first place, done in Blockchain*::add_output.
      // Additional type checks on outputs were also added via cryptonote::check_output_types
      // and cryptonote::get_output_public_key (see Blockchain::check_tx_outputs).

      m_output_keys.push_back(ct::ctkey({ct::pk2rct(pubkey), commitment}));
      return true;
    }
  };

  output_keys.clear();

  // collect output keys
  outputs_visitor vi(output_keys, *this, hf_version);
  if (!scan_outputkeys_for_indexes(tx_version, txin, vi, tx_prefix_hash, pmax_related_block_height))
  {
    MERROR_VER("Failed to get output keys for tx with amount = " << print_money(txin.amount) << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  if(txin.key_offsets.size() != output_keys.size())
  {
    MERROR_VER("Output keys for tx with amount = " << txin.amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }
  if (tx_version == 1) {
    CHECK_AND_ASSERT_MES(sig.size() == output_keys.size(), false, "internal error: tx signatures count=" << sig.size() << " mismatch with outputs keys count for inputs=" << output_keys.size());
  }
  // ct_signatures will be expanded after this
  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::compute_fcmp_verification_hash(const transaction& tx)
{
  const ct::CtSig &rv = tx.ct_signatures;
  if (rv.type != ct::CTTypeFcmpPlusPlusPqc)
    return crypto::null_hash;

  // Mempool verification-cache id: binds proof bytes to the anchored snapshot
  // (via referenceBlock hash, which determines curve_tree_root in consensus)
  // and to all input key images. Same logical intent as H(proof || tree_root || KIs).
  std::vector<uint8_t> buf;
  buf.reserve(rv.p.fcmp_pp_proof.size() + 32 + tx.vin.size() * 32);

  buf.insert(buf.end(), rv.p.fcmp_pp_proof.begin(), rv.p.fcmp_pp_proof.end());

  static_assert(sizeof(rv.referenceBlock) == 32);
  buf.insert(buf.end(),
    reinterpret_cast<const uint8_t*>(&rv.referenceBlock),
    reinterpret_cast<const uint8_t*>(&rv.referenceBlock) + 32);

  for (const auto& txin : tx.vin)
  {
    if (!std::holds_alternative<txin_to_key>(txin))
      return crypto::null_hash;
    const auto& ki = std::get<txin_to_key>(txin).k_image;
    buf.insert(buf.end(),
      reinterpret_cast<const uint8_t*>(&ki),
      reinterpret_cast<const uint8_t*>(&ki) + 32);
  }

  crypto::hash result;
  crypto::cn_fast_hash(buf.data(), buf.size(), result);
  return result;
}
//------------------------------------------------------------------
namespace
{
const char* archival_bond_post_verify_err_string(uint8_t code)
{
  switch (code)
  {
  case SHEKYL_ARCHIVAL_BOND_POST_OK:
    return "ok";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR:
    return "null shard id pointer";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND:
    return "post_kind not JoinMarket";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY:
    return "ShardSetCompact requires shards";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS:
    return "CompleteTree must not carry shard ids";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO:
    return "JoinMarket bond_debit must be zero";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS:
    return "bond_credit and bond_debit both non-zero";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_ZERO:
    return "bond_floor is zero";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH:
    return "bonded_total/bond_credit must equal bond_floor";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS:
    return "bond record already exists";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND:
    return "invalid holdings_kind";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_UNBOND:
    return "post_kind not Unbond";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING:
    return "Unbond requires an existing bond record";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_NOTHING_TO_UNBOND:
    return "record bonded_total is zero";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_CREDIT:
    return "Unbond bond_credit must be zero";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_FLOOR_MISMATCH:
    return "post-connect bonded_total must equal bond_floor(holdings)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_UNBOND:
    return "Unbond is a full exit: post-connect bonded_total must be zero";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL:
    return "bond_debit must equal the record's current bonded_total";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED:
    return "release cooldown has not elapsed";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW:
    return "marshaled array length overflow";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_HOLDINGS_NOT_EMPTY:
    return "full exit must end at empty holdings";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_INTERVAL_LOG_FULL:
    return "record interval log is full";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING:
    return "slash scheduler has not settled every epoch through the last-served anchor";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING:
    return "bond_spend_pk violates the JoinMarket coupling (missing/non-canonical on "
      "JoinMarket, or present on another kind)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE:
    return "post_kind is not HoldingsUpdate";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ON_COMPLETE_TREE:
    return "HoldingsUpdate on a CompleteTree record (no shard set to change)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_POST_NOT_COMPACT:
    return "HoldingsUpdate post holdings are not ShardSetCompact";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_TERMS:
    return "HoldingsUpdate-add terms are not exactly +FLOOR credit / no debit";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_GOOD_STANDING:
    return "HoldingsUpdate-add on a record not good_through the current epoch";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_ADD:
    return "HoldingsUpdate-add is not exactly one added shard";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_FLOOR_MISMATCH:
    return "HoldingsUpdate-add post bonded_total != bond_floor(post) / current + FLOOR";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_TERMS:
    return "HoldingsUpdate-drop terms are not exactly -FLOOR debit / no credit";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_DROP:
    return "HoldingsUpdate-drop must remove exactly one shard, and it must be the "
      "shard whose per-shard facts were marshaled";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_LAST_SHARD:
    return "HoldingsUpdate-drop would empty the shard set (a full exit is Unbond)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_FLOOR_MISMATCH:
    return "HoldingsUpdate-drop post bonded_total != bond_floor(post) / current - FLOOR";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_WITHIN_HORIZON:
    return "HoldingsUpdate-drop before the shard's retention-commitment horizon elapsed";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REBOND:
    return "post_kind is not Rebond";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_ON_COMPLETE_TREE:
    return "Rebond on a CompleteTree record (demotion flips the kind; unrepresentable)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_NOT_COMPACT:
    return "Rebond post-holdings are not ShardSetCompact";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SLASHED:
    return "Rebond requires an open bad interval (the record is not slashed)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_MULTIPLE_OPEN:
    return "record carries multiple open bad intervals (coalescing invariant broken)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_LOG_HEADROOM:
    return "record interval log lacks Rebond headroom (must leave a slot for the next "
      "slash and the Unbond clean close)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_TERMS:
    return "Rebond terms mismatch (debit nonzero, or credit != bond_floor(post) - "
      "record bonded_total, or post bonded_total != bond_floor(post))";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SUPERSET:
    return "Rebond post-holdings are not a duplicate-free superset of the record's "
      "current holdings (shedding goes through HoldingsUpdate-drop)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_OVERSIZE_RETIRED:
    return "retired Rebond oversize code (45) — never returned; oversize is now "
      "unrepresentable in the vin's ShardSet holdings";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_RECORD_FLOOR:
    return "record bonded_total != bond_floor(record holdings) (floor-drifted record)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED:
    return "vin holdings shard count exceeds the wire codec bound";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD:
    return "vin holdings carry a duplicate shard id (a set on the wire)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED:
    return "HoldingsUpdate requires a Bonded record (an Exited or slash-emptied "
      "record re-enters via JoinMarket/Rebond)";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_NO_RECORD_KEY:
    return "bond record commits no bond_spend_pk; it authorizes no debit";
  case SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_KEY_MISMATCH:
    return "pqc auth key is not the record's committed bond_spend_pk";
  default:
    return "unknown bond-post verify code";
  }
}

// GF-1 debit authorization (gate-4 §3.5 step 5) — the SHARED debit authorizer,
// single-sourced for every bond_debit > 0 arm (Unbond, HoldingsUpdate-drop; a
// future debit kind rides the same call): the pqc auth key must equal the
// record's COMMITTED bond_spend_pk — never the identity key P_pubkey
// (identity-only invariant, gate-6 §9.6). The signature itself is verified
// over the whole-tx payload by verify_transaction_pqc_auth against
// pqc_auths[idx].hybrid_public_key; pinning that key here is the authorization
// choice. A record with no committed key (pre-GF-1 shape) authorizes nothing —
// fail closed, not identity fallback. Callers gate on have_record (a missing
// record falls through to the semantic verify's RECORD_MISSING) and run this
// BEFORE any per-shard cursor scans or FFI verify: it is a two-vector compare,
// so an unauthorized attempt is rejected before it can cost LMDB seeks.
// Debit authorization for the value-out bond-post arms. The predicate itself
// is Rust (`shekyl-archival-retention::debit_auth_pin`); this site marshals and
// logs. It used to be implemented here, which made it a second copy of the one
// check that has no recovery -- a compromised serving host holds the identity
// hybrid key, so an identity-authorized debit is a collateral drain. The Rust
// submit battery calls the same function natively (DAEMON_SUBMIT_VERDICT.md
// 8.7.1.1 row UB3), so the two verifying paths share it rather than tracking
// each other.
bool archival_debit_auth_pin(const shekyl::db::ArchivalBondValue& record,
  const std::vector<uint8_t>& auth_pubkey, const char* arm)
{
  const uint8_t rc = shekyl_archival_debit_auth_pin(
    record.bond_spend_pk.empty() ? nullptr : record.bond_spend_pk.data(),
    record.bond_spend_pk.size(),
    auth_pubkey.empty() ? nullptr : auth_pubkey.data(),
    auth_pubkey.size());
  if (rc == SHEKYL_ARCHIVAL_BOND_POST_OK)
    return true;
  // Two arms, deliberately distinct in the log: "this record authorizes
  // nothing" and "wrong key against a record that does" have different
  // operator remedies.
  if (rc == SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_NO_RECORD_KEY)
  {
    MERROR_VER("Archival " << arm << " rejected: record commits no bond_spend_pk; "
      "a debit cannot be authorized (and the identity key never authorizes "
      "a value-out)");
  }
  else if (rc == SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_KEY_MISMATCH)
  {
    MERROR_VER("Archival " << arm << " rejected: pqc auth key does not match the "
      "record's committed bond_spend_pk (identity-key or foreign-key debit "
      "authorization is forbidden)");
  }
  else
  {
    MERROR_VER("Archival " << arm << " rejected: debit-auth pin marshal fault (code "
      << static_cast<unsigned>(rc) << ")");
  }
  return false;
}

// Shared record-fact marshal for the record-mutating bond-post verify arms
// (HoldingsUpdate, Rebond): load the bond record, belt the v6 index-parallel
// coupling, and flatten the interval log into the FFI's (start, end_exclusive)
// pair layout. Returns false — rejecting the tx — on the desync belt.
// Single-sourced so the arms verify against identically-gathered record facts;
// a marshal fix cannot land on one bond-post kind and leave another verifying
// against differently-shaped facts for the same chain state.
bool archival_marshal_record_facts(BlockchainDB* db, const crypto::hash& p_id,
  const char* arm, shekyl::db::ArchivalBondValue& record, bool& have_record,
  std::vector<uint64_t>& intervals_flat)
{
  have_record = db->get_archival_bond_value(p_id, record);
  if (have_record && record.held_shard_ids.size() != record.shard_add_epochs.size())
  {
    MERROR_VER("Archival " << arm << " rejected: record shard id / add-epoch "
      "length desync");
    return false;
  }
  intervals_flat.clear();
  intervals_flat.reserve(record.bad_intervals.size() * 2);
  for (const auto& iv : record.bad_intervals)
  {
    intervals_flat.push_back(iv.start_epoch);
    intervals_flat.push_back(iv.end_exclusive);
  }
  return true;
}
} // namespace

bool Blockchain::check_archival_bond_post_input(const txin_archival_bond_post& bond,
  const std::vector<uint8_t>& auth_pubkey, uint64_t chain_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  if (bond.hybrid_public_key.size() != config::PQC_HYBRID_SINGLE_KEY_LEN)
  {
    MERROR_VER("Archival bond-post hybrid pubkey length not canonical");
    return false;
  }

  crypto::hash recomputed{};
  if (!shekyl_archival_p_canonical_id_from_pubkey(
        bond.hybrid_public_key.data(), bond.hybrid_public_key.size(),
        reinterpret_cast<uint8_t*>(recomputed.data)))
  {
    MERROR_VER("Archival bond-post P_canonical_id recomputation failed");
    return false;
  }
  if (bond.p_canonical_id != recomputed)
  {
    MERROR_VER("Archival bond-post p_canonical_id hint mismatch");
    return false;
  }

  const uint64_t* shard_ptr = bond.holdings.shard_ids.empty()
    ? nullptr
    : bond.holdings.shard_ids.data();

  if (bond.post_kind == static_cast<uint8_t>(archival_bond_post_kind::Unbond))
  {
    // §9.11 coupling belt for non-parse callers (every codec refuses this at
    // parse; the credit path's twin belt sits below): only JoinMarket carries
    // the debit authorizer — an Unbond debit authorizes against the record's
    // COMMITTED copy, never a key the vin brings along.
    if (!bond.bond_spend_pk.empty())
    {
      MERROR_VER("Archival Unbond rejected: vin carries a bond_spend_pk "
        "(JoinMarket-coupled field)");
      return false;
    }

    shekyl::db::ArchivalBondValue record{};
    const bool have_record = m_db->get_archival_bond_value(bond.p_canonical_id, record);

    // GF-1 debit authorization — the shared pin (archival_debit_auth_pin
    // above), run before the cooldown-anchor gathering + semantic verify.
    if (have_record && !archival_debit_auth_pin(record, auth_pubkey, "Unbond"))
      return false;

    // Unbond semantic verify (gate-4 §3.5 debit path): marshal the record
    // facts + the P2B-8 Q1/Q2 cooldown anchors (one reverse-cursor seek per
    // held shard; never-served shards omitted) + the slash scheduler's
    // settled watermark. The kind→scan decision is Rust
    // (`shekyl_archival_last_served_scan`, exhaustive on HoldingsKind). This
    // site only marshals the discriminant onto the matching DB accessor. The
    // fold and every verdict stay Rust-side.
    std::vector<uint64_t> last_served;
    if (have_record)
    {
      uint8_t scan = 0;
      if (shekyl_archival_last_served_scan(record.holdings_kind, &scan)
          != SHEKYL_ARCHIVAL_BOND_POST_OK)
        return false;
      last_served = (scan == SHEKYL_ARCHIVAL_LAST_SERVED_SCAN_ALL_SHARDS)
        ? m_db->archival_bond_all_last_served_epochs(bond.p_canonical_id)
        : m_db->archival_bond_last_served_epochs(bond.p_canonical_id,
            record.held_shard_ids);
    }
    const uint64_t last_settled_slash_epoch = m_db->get_archival_last_slash_epoch();
    const uint64_t current_epoch = shekyl_archival_settlement_epoch_at_height(chain_height);
    const uint8_t verify_rc = shekyl_archival_verify_unbond_bond_post(
      bond.post_kind,
      static_cast<uint8_t>(bond.holdings.kind),
      shard_ptr,
      bond.holdings.shard_ids.size(),
      nullptr, // bond_spend_pk: empty on Unbond (§9.11; the belt above enforces it)
      0,
      bond.bonded_total_atomic,
      bond.bond_credit,
      bond.bond_debit,
      have_record ? 1 : 0,
      record.bonded_total_atomic,
      record.bad_intervals.size(),
      last_served.empty() ? nullptr : last_served.data(),
      last_served.size(),
      last_settled_slash_epoch,
      current_epoch);
    if (verify_rc != SHEKYL_ARCHIVAL_BOND_POST_OK)
    {
      MERROR_VER("Archival Unbond verify failed (code " << static_cast<unsigned>(verify_rc)
        << "): " << archival_bond_post_verify_err_string(verify_rc));
      return false;
    }
    return true;
  }

  if (bond.post_kind == static_cast<uint8_t>(archival_bond_post_kind::HoldingsUpdate))
  {
    // §9.11 coupling belt: a HoldingsUpdate never carries the vin-borne debit
    // authorizer — the add is a credit (identity-key auth) and the drop's debit
    // authorizes against the record's COMMITTED bond_spend_pk (GF-1 selector),
    // never a key the vin brings along.
    if (!bond.bond_spend_pk.empty())
    {
      MERROR_VER("Archival HoldingsUpdate rejected: vin carries a bond_spend_pk "
        "(JoinMarket-coupled field)");
      return false;
    }

    shekyl::db::ArchivalBondValue record{};
    bool have_record = false;
    std::vector<uint64_t> bad_flat;
    if (!archival_marshal_record_facts(m_db, bond.p_canonical_id, "HoldingsUpdate",
        record, have_record, bad_flat))
      return false;
    const uint64_t current_epoch = shekyl_archival_settlement_epoch_at_height(chain_height);
    const uint64_t* record_shard_ptr = record.held_shard_ids.empty()
      ? nullptr : record.held_shard_ids.data();

    // Direction (verify-pinned §3.2): bond_debit == 0 is the add (credit) arm;
    // a positive debit is the drop (grace-tail) arm. Each arm's own term check
    // is authoritative — this only selects which fact set to marshal.
    if (bond.bond_debit == 0)
    {
      // ADD (credit path): the record's current holdings + the good_through
      // inputs (join epoch + the flattened bad intervals). Auth is the
      // IDENTITY key.
      const uint8_t hu_rc = shekyl_archival_verify_holdings_update_add(
        bond.post_kind,
        static_cast<uint8_t>(bond.holdings.kind),
        shard_ptr,
        bond.holdings.shard_ids.size(),
        nullptr, // bond_spend_pk: empty on HoldingsUpdate (belt above)
        0,
        bond.bonded_total_atomic,
        bond.bond_credit,
        bond.bond_debit,
        have_record ? 1 : 0,
        record.bonded_total_atomic,
        static_cast<uint8_t>(record.holdings_kind),
        record_shard_ptr,
        record.held_shard_ids.size(),
        record.join_settlement_epoch,
        bad_flat.empty() ? nullptr : bad_flat.data(),
        record.bad_intervals.size(),
        current_epoch);
      if (hu_rc != SHEKYL_ARCHIVAL_BOND_POST_OK)
      {
        MERROR_VER("Archival HoldingsUpdate-add verify failed (code "
          << static_cast<unsigned>(hu_rc) << "): "
          << archival_bond_post_verify_err_string(hu_rc));
        return false;
      }
      if (auth_pubkey != bond.hybrid_public_key)
      {
        MERROR_VER("Archival HoldingsUpdate-add rejected: credit-path pqc auth key "
          "does not match the identity key P_pubkey");
        return false;
      }
      return true;
    }

    // DROP (grace-tail debit path). GF-1 debit authorization — the shared pin
    // (archival_debit_auth_pin above), the Unbond arm's twin.
    if (have_record && !archival_debit_auth_pin(record, auth_pubkey, "HoldingsUpdate-drop"))
      return false;

    // Identify the dropped shard by set-difference (record CURRENT \ vin POST)
    // and read its per-shard facts. The Rust verify recomputes the diff and
    // cross-checks dropped_shard_id, so a non-single diff is rejected there
    // regardless of what we pass; we gather real facts only when exactly one
    // shard was removed (the happy path), else pass zeroed facts.
    uint64_t dropped_shard_id = 0;
    uint64_t dropped_add_epoch = 0;
    uint64_t dropped_freeze_height = 0;
    uint64_t dropped_last_served = std::numeric_limits<uint64_t>::max();
    if (have_record)
    {
      // Index the POST holdings once (O(1) membership) so identifying the
      // record-minus-post shard stays O(n) rather than a nested scan at the
      // 4096 holdings cap.
      const std::unordered_set<uint64_t> post_shards(
        bond.holdings.shard_ids.begin(), bond.holdings.shard_ids.end());
      std::vector<size_t> removed_idx;
      for (size_t i = 0; i < record.held_shard_ids.size(); ++i)
      {
        if (post_shards.find(record.held_shard_ids[i]) == post_shards.end())
          removed_idx.push_back(i);
      }
      if (removed_idx.size() == 1)
      {
        const size_t i = removed_idx[0];
        dropped_shard_id = record.held_shard_ids[i];
        dropped_add_epoch = record.shard_add_epochs[i];
        // The ADD verify deliberately does NOT require a frozen segment
        // (bond_post.rs: adding an unfrozen shard is self-harm, not an
        // attack), so a held shard may legitimately have no freeze row yet.
        // Fail closed by leaving the freeze height at 0 — the genesis-band
        // "oldest" sentinel, i.e. the longest (hardest-to-drop) horizon. The
        // Rust age computation (ShardAgeAtAdd::from_add) pins the adjacent
        // corner to the same extreme: a segment that froze AT or AFTER
        // H_close(add_epoch) also gets the longest horizon, so an
        // added-before-freeze shard cannot recycle its FLOOR early no matter
        // when the freeze lands relative to the drop attempt.
        uint64_t freeze = 0;
        if (m_db->archival_shard_freeze_height(dropped_shard_id, freeze))
          dropped_freeze_height = freeze;
        const std::vector<uint64_t> served =
          m_db->archival_bond_last_served_epochs(bond.p_canonical_id, {dropped_shard_id});
        if (!served.empty())
          dropped_last_served = served.front();
      }
    }
    const uint64_t last_settled_slash_epoch = m_db->get_archival_last_slash_epoch();
    const uint8_t hu_rc = shekyl_archival_verify_holdings_update_drop(
      bond.post_kind,
      static_cast<uint8_t>(bond.holdings.kind),
      shard_ptr,
      bond.holdings.shard_ids.size(),
      nullptr, // bond_spend_pk: empty on HoldingsUpdate (belt above)
      0,
      bond.bonded_total_atomic,
      bond.bond_credit,
      bond.bond_debit,
      have_record ? 1 : 0,
      record.bonded_total_atomic,
      static_cast<uint8_t>(record.holdings_kind),
      record_shard_ptr,
      record.held_shard_ids.size(),
      dropped_shard_id,
      dropped_add_epoch,
      dropped_freeze_height,
      dropped_last_served,
      last_settled_slash_epoch,
      current_epoch);
    if (hu_rc != SHEKYL_ARCHIVAL_BOND_POST_OK)
    {
      MERROR_VER("Archival HoldingsUpdate-drop verify failed (code "
        << static_cast<unsigned>(hu_rc) << "): "
        << archival_bond_post_verify_err_string(hu_rc));
      return false;
    }
    return true;
  }

  if (bond.post_kind == static_cast<uint8_t>(archival_bond_post_kind::Rebond))
  {
    // §9.11 coupling belt: Rebond never carries the vin-borne debit authorizer
    // — it is a credit (identity-key auth, P2B-9 Pin 4) and the record keeps
    // its join-time committed bond_spend_pk for future debits.
    if (!bond.bond_spend_pk.empty())
    {
      MERROR_VER("Archival Rebond rejected: vin carries a bond_spend_pk "
        "(JoinMarket-coupled field)");
      return false;
    }

    // Rebond semantic verify (gate-4 §3.4; P2B-9 reinstatement): marshal the
    // record's current holdings + the full interval log as flattened
    // (start, end_exclusive) pairs — the open-interval precondition, the Pin-5
    // single-open check, and the Pin-6 headroom bound all read it Rust-side.
    // No epoch operand: the precondition is interval-shaped, not epoch-shaped.
    shekyl::db::ArchivalBondValue record{};
    bool have_record = false;
    std::vector<uint64_t> intervals_flat;
    if (!archival_marshal_record_facts(m_db, bond.p_canonical_id, "Rebond",
        record, have_record, intervals_flat))
      return false;
    const uint8_t rb_rc = shekyl_archival_verify_rebond_bond_post(
      bond.post_kind,
      static_cast<uint8_t>(bond.holdings.kind),
      shard_ptr,
      bond.holdings.shard_ids.size(),
      nullptr, // bond_spend_pk: empty on Rebond (belt above)
      0,
      bond.bonded_total_atomic,
      bond.bond_credit,
      bond.bond_debit,
      have_record ? 1 : 0,
      record.bonded_total_atomic,
      static_cast<uint8_t>(record.holdings_kind),
      record.held_shard_ids.empty() ? nullptr : record.held_shard_ids.data(),
      record.held_shard_ids.size(),
      intervals_flat.empty() ? nullptr : intervals_flat.data(),
      record.bad_intervals.size());
    if (rb_rc != SHEKYL_ARCHIVAL_BOND_POST_OK)
    {
      MERROR_VER("Archival Rebond verify failed (code "
        << static_cast<unsigned>(rb_rc) << "): "
        << archival_bond_post_verify_err_string(rb_rc));
      return false;
    }
    // Credit-path authorization (P2B-9 Pin 4, the GF-1 selector): the identity
    // key — a Rebond proves control of P_canonical_id; the funded value (if
    // any) arrives via self-authorizing txin_to_key inputs.
    if (auth_pubkey != bond.hybrid_public_key)
    {
      MERROR_VER("Archival Rebond rejected: credit-path pqc auth key does not "
        "match the identity key P_pubkey");
      return false;
    }
    return true;
  }

  // §9.11 belt for non-parse callers, the Unbond arm's twin (the serializer
  // enforces this at parse, and the FFI vin marshaler below re-refuses the
  // coupling): JoinMarket must commit a canonical-length bond_spend_pk for
  // the record — it never authorizes the credit itself; the identity-key pin
  // below does — and every other kind on this arm (Rebond and HoldingsUpdate
  // dispatch above; anything else is verify-rejected downstream) must not
  // carry one.
  if (bond.post_kind == static_cast<uint8_t>(archival_bond_post_kind::JoinMarket))
  {
    if (bond.bond_spend_pk.size() != config::PQC_HYBRID_SINGLE_KEY_LEN)
    {
      MERROR_VER("Archival JoinMarket rejected: bond_spend_pk missing or not canonical");
      return false;
    }
  }
  else if (!bond.bond_spend_pk.empty())
  {
    MERROR_VER("Archival bond-post rejected: vin carries a bond_spend_pk "
      "(JoinMarket-coupled field)");
    return false;
  }

  std::vector<uint8_t> existing_pubkey;
  const bool record_exists = m_db->get_archival_bond_hybrid_pubkey(bond.p_canonical_id, existing_pubkey);
  const uint8_t verify_rc = shekyl_archival_verify_join_market_bond_post(
    bond.post_kind,
    static_cast<uint8_t>(bond.holdings.kind),
    shard_ptr,
    bond.holdings.shard_ids.size(),
    bond.bond_spend_pk.data(),
    bond.bond_spend_pk.size(),
    bond.bonded_total_atomic,
    bond.bond_credit,
    bond.bond_debit,
    record_exists ? 1 : 0);
  if (verify_rc != SHEKYL_ARCHIVAL_BOND_POST_OK)
  {
    MERROR_VER("Archival bond-post verify failed (code " << static_cast<unsigned>(verify_rc)
      << "): " << archival_bond_post_verify_err_string(verify_rc));
    return false;
  }

  // D3/R3 admission viability (JoinMarket only — rebond/HU-add are monotone
  // in credited work; HU-drop is left ungated so we do not trap exit-ward
  // capital). Predicate + epoch key + age live in Rust; C++ only marshals
  // LMDB rows. parent_height = chain_height - 1 (tip would self-score).
  // Full rationale: shekyl-archival-retention::admission.
  {
    const uint64_t parent_height = chain_height ? chain_height - 1 : 0;
    std::vector<uint64_t> adm_r_market;
    std::vector<uint64_t> adm_freeze_heights;
    // uint8_t, not bool: std::vector<bool> is a bitset specialization with no
    // contiguous bool* to hand across the ABI. Rust reads each byte as != 0.
    std::vector<uint8_t> adm_has_segment;
    if (bond.holdings.kind != archival_holdings_kind::CompleteTree)
    {
      const uint64_t settled_epoch =
        shekyl_archival_last_settled_epoch_as_of_parent(parent_height);
      adm_r_market.reserve(bond.holdings.shard_ids.size());
      adm_freeze_heights.reserve(bond.holdings.shard_ids.size());
      adm_has_segment.reserve(bond.holdings.shard_ids.size());
      for (const uint64_t shard_id : bond.holdings.shard_ids)
      {
        adm_r_market.push_back(m_db->get_archival_r_market(shard_id, settled_epoch));
        // The RETURN VALUE is the presence bit and must be marshaled: a shard
        // with no frozen segment scores age 0 in the reward path, and
        // freeze_height 0 is a legitimate genesis-band value, so presence
        // cannot be recovered from the height. Dropping this bit would score
        // an unfrozen shard at MAXIMUM age (age_epochs == chain_epochs) where
        // the reward path scores zero, over-scoring the holding.
        uint64_t freeze = 0;
        const bool has_segment = m_db->archival_shard_freeze_height(shard_id, freeze);
        adm_freeze_heights.push_back(freeze);
        adm_has_segment.push_back(has_segment ? 1u : 0u);
      }
    }
    const uint8_t adm_rc = shekyl_archival_check_bond_admission(
      static_cast<uint8_t>(bond.holdings.kind),
      bond.holdings.shard_ids.size(),
      adm_r_market.empty() ? nullptr : adm_r_market.data(),
      adm_r_market.size(),
      adm_freeze_heights.empty() ? nullptr : adm_freeze_heights.data(),
      adm_freeze_heights.size(),
      adm_has_segment.empty() ? nullptr : adm_has_segment.data(),
      adm_has_segment.size(),
      parent_height);
    if (adm_rc != SHEKYL_ARCHIVAL_ADMISSION_OK)
    {
      MERROR_VER("Archival JoinMarket rejected: "
        << shekyl_archival_admission_err_string(adm_rc)
        << " (admission code " << static_cast<unsigned>(adm_rc) << ")");
      return false;
    }
  }

  // Credit-path authorization (gate-4 §3.5 step 5, the debit selection's
  // twin): bond_debit == 0 paths authorize with the IDENTITY key P_pubkey.
  if (auth_pubkey != bond.hybrid_public_key)
  {
    MERROR_VER("Archival bond-post rejected: credit-path pqc auth key does not "
      "match the identity key P_pubkey");
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// FAKECHAIN-only regtest shim; contract, coverage boundary, and the
// non-pop-symmetry caveat are documented at the declaration
// (blockchain.h). Fail-closed here as well as at the RPC gate: this is a
// consensus-state write, and the core boundary must not trust the RPC
// layer to have checked the nettype.
bool Blockchain::regtest_inject_archival_serve_credit(const crypto::hash& p_canonical_id,
  uint64_t shard_id, uint64_t settlement_epoch)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if (m_nettype != FAKECHAIN)
  {
    MERROR("regtest_inject_archival_serve_credit called off fakechain; refusing");
    return false;
  }
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  // PC-D4: attribute the injected row to the tip's INDEX, read here under the
  // same lock as the write. A tip snapshot taken by the caller (the RPC
  // handler ran get_current_blockchain_height() before this lock) can go
  // stale against a concurrent mine/pop; deriving it inside the critical
  // section makes the attribution race-free by construction, and removing
  // the parameter means no caller can reintroduce the stale copy.
  // m_db->height() is the block COUNT, so the tip's index is one below it —
  // the same count-versus-index distinction the pop path got wrong.
  const uint64_t chain_height = m_db->height();
  if (chain_height == 0)
  {
    MERROR("regtest_inject_archival_serve_credit refusing: chain has no tip to attribute the row to");
    return false;
  }
  const uint64_t block_height = chain_height - 1;
  db_wtxn_guard wtxn_guard(m_db);
  m_db->set_archival_serve_credit_bit(p_canonical_id, shard_id, settlement_epoch, block_height);
  MWARNING("Injected archival serve-credit bit (regtest Gate-6 stand-in): P="
    << p_canonical_id << " shard=" << shard_id << " E=" << settlement_epoch
    << " height=" << block_height
    << " — bit is not block-owned; pops below this height strand it");
  return true;
}
//------------------------------------------------------------------
// AUDITED DECISION (ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md, D-SC-B wide /
// D-SC-A dedup): this gate's ordered predicate sequence is mirrored in Rust
// (shekyl-archival-retention::serve_credit_decisions) and pinned by the
// standing equivalence KAT (serve_credit_equivalence_kat_v1.json; Rust leg
// serve_credit_equivalence_kat.rs, C++ leg archival_serve_credit_equivalence.cpp).
// Reordering predicates, adding one, or changing a reject condition requires
// re-authoring the fixture's expected-reason column and updating the mirror
// in the same change.
bool Blockchain::check_archival_serve_credit_input(const txin_archival_serve_credit_response& resp,
  const std::vector<uint8_t>& pruned_record, uint64_t current_height,
  const crypto::hash& prev_block_hash) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // RF-D1 / rule 40: the vin is an opaque blob. The three fields this function
  // indexes by come through the Rust codec; every structural bound on the
  // record (branch-layer counts and widths, leg lengths) is the Rust parser's
  // and is enforced inside the FFI verify below. Nothing here reads inside the
  // bytes.
  crypto::hash sc_p_id{};
  uint64_t sc_shard_id = 0;
  uint64_t sc_settlement_epoch = 0;
  if (!get_archival_serve_credit_key(resp, sc_p_id, sc_shard_id, sc_settlement_epoch))
  {
    MERROR_VER("Archival serve-credit vin did not parse");
    return false;
  }
  if (pruned_record.empty() || pruned_record.size() > ct::CtSigPrunable::SERVE_CREDIT_PRUNED_MAX_BYTES)
  {
    MERROR_VER("Archival serve-credit pruned record size out of bounds");
    return false;
  }

  // PC-D4/PC-D7: PAIR-EPOCH-wide, deliberately, and this is the one place the
  // widened key could have silently changed consensus.
  //
  // The exact-get `has_archival_serve_credit_bit(P, s, E, h)` would be
  // VACUOUS here: `h` is the block under validation, which is not in the DB
  // yet, so no row can match and every duplicate would be admitted. That is
  // the correct END state -- up to CHALLENGES_PER_PAIR_PER_EPOCH rows across
  // distinct blocks -- but only once the derived-assignment issuer bounds how
  // many blocks may challenge a pair. That issuer is NOT wired:
  // `assign_epoch` exists in Rust with no FFI export and no consensus caller,
  // and the live mechanism is still the one-challenge-per-pair-epoch beacon.
  // Relaxing to the exact-get now would leave the pass count bounded by
  // nothing at all.
  //
  // So this stays the pair-epoch bound the beacon mechanism already implies,
  // and consensus behaviour is byte-identical to before the key widened.
  //
  // REOPEN (rule 21): when the assignment cutover lands, this relaxes to
  // "reject unless this block's assignment names this pair" -- which is the
  // count bound and the anti-adaptive-selection check in one, and is what
  // PC-D7's surviving half asks for.
  if (m_db->archival_serve_credit_pass_count(sc_p_id, sc_shard_id, sc_settlement_epoch) > 0)
  {
    MERROR_VER("Duplicate archival serve-credit for (P, shard, E)");
    return false;
  }

  std::vector<uint8_t> bond_pubkey;
  if (!m_db->get_archival_bond_hybrid_pubkey(sc_p_id, bond_pubkey))
  {
    MERROR_VER("Archival serve-credit rejected: bond record substrate not available for P_id");
    return false;
  }

  const uint64_t join_epoch = m_db->archival_bond_join_epoch(sc_p_id);
  if (!shekyl_archival_serve_credit_epoch_ok(sc_settlement_epoch, join_epoch))
  {
    MERROR_VER("Archival serve-credit settlement epoch " << sc_settlement_epoch
      << " before E_first (join_settlement_epoch+1) for join_settlement_epoch "
      << join_epoch);
    return false;
  }

  if (!m_db->archival_bond_good_through(sc_p_id, sc_settlement_epoch))
  {
    MERROR_VER("Archival serve-credit rejected: P not good_through at epoch "
      << sc_settlement_epoch);
    return false;
  }

  const uint64_t h_open = shekyl_archival_epoch_open_height(sc_settlement_epoch);
  const uint64_t h_close = shekyl_archival_epoch_close_height(sc_settlement_epoch);
  const uint64_t h_seal = shekyl_archival_challenge_seal_height(h_open);
  if (current_height > h_close)
  {
    MERROR_VER("Archival serve-credit past credit deadline H_close=" << h_close);
    return false;
  }

  // block_hash(H_seal) must be committed to derive the H_fire beacon. The
  // seal-on-chain predicate is Rust-authoritative (challenge_seal_on_chain):
  // called here and mirrored by shekyl-archival-retention::serve_credit_decisions
  // from that one source, so the boundary never drifts. Rejecting a future-epoch
  // (attacker-chosen settlement_epoch) input by predicate keeps the seal read
  // below from throwing BLOCK_DNE on it; the slash-eligibility consumer
  // (db_lmdb.cpp) applies the same boundary against its connected block height.
  if (!shekyl_archival_challenge_seal_on_chain(h_open, current_height))
  {
    MERROR_VER("Archival serve-credit: seal block " << h_seal
      << " at or beyond chain height " << current_height << " (not yet committed)");
    return false;
  }

  crypto::hash seal_hash{};
  try
  {
    seal_hash = m_db->get_block_hash_from_height(h_seal);
  }
  catch (const std::exception& e)
  {
    // Post-guard, h_seal is a committed height, so this can only be a genuine DB
    // read failure (corruption/IO), never BLOCK_DNE. Rejecting keeps this twin
    // symmetric with the slash consumer; whether a corrupt read should instead
    // halt is a separate consensus-policy question, decided for both together.
    MERROR_VER("Archival serve-credit: cannot load seal block hash at height " << h_seal
      << ": " << e.what());
    return false;
  }

  // Derived identically to the slash-eligibility consumer (db_lmdb.cpp,
  // archival_baseline_observed_at_epoch) from the same deterministic inputs, so
  // the two consumers of "held at fire height" agree on which height that is
  // (WS-1 h_fire symmetry). H_fire is in (0, H_close] for every well-formed
  // epoch, so no range check is applied here — see challenge_fire_height's
  // reopen criterion (a Round-2 re-pin that admits H_close <= H_seal restores
  // the check at both consumers).
  const uint64_t h_fire = shekyl_archival_challenge_fire_height(
    h_open, h_close, reinterpret_cast<const uint8_t*>(seal_hash.data),
    reinterpret_cast<const uint8_t*>(sc_p_id.data),
    sc_shard_id, sc_settlement_epoch);

  if (!m_db->archival_bond_holds_shard(sc_p_id, sc_shard_id, h_fire))
  {
    MERROR_VER("Archival serve-credit: shard " << sc_shard_id
      << " not in bond holdings at H_fire=" << h_fire);
    return false;
  }

  crypto::hash registry_rk{};
  uint64_t segment_leaf_count = 0;
  if (!m_db->get_archival_shard_segment_at_height(sc_shard_id, h_fire, registry_rk, segment_leaf_count))
  {
    MERROR_VER("Archival serve-credit: shard registry substrate not available at H_fire="
      << h_fire);
    return false;
  }

  // Challenge-path leaf chunk (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §6.2): the
  // leaf-layer scalars are read straight from the consensus curve-tree leaf
  // table. A frozen segment's leaves are immutable on the branch (freezing is
  // a first-crossing rule over the append-only leaf count), so the live rows
  // ARE the as-of-H_fire chunk; no snapshot table exists. Chunk-bounds
  // arithmetic lives in Rust only (same one-site family as the freeze rule).
  // RF-D6: the challenged index is DERIVED, never read off the vin.
  // PC-D3: bound to the block this record rides in, so each of a pair-epoch's
  // challenges samples an independently drawn leaf (independent, not
  // guaranteed-distinct: draws can collide mod the leaf count). An all-zero
  // `prev_block_hash` is refused by the FFI rather than derived against.
  uint32_t leaf_index = 0;
  const uint8_t leaf_index_rc = shekyl_archival_challenge_leaf_index(
    reinterpret_cast<const uint8_t*>(sc_p_id.data), sc_shard_id, sc_settlement_epoch,
    reinterpret_cast<const uint8_t*>(prev_block_hash.data),
    segment_leaf_count, &leaf_index);
  if (leaf_index_rc != SHEKYL_ARCHIVAL_VERIFY_OK)
  {
    MERROR_VER("Archival serve-credit: leaf index derivation refused (code "
      << (int)leaf_index_rc << ")");
    return false;
  }
  uint64_t chunk_first_leaf = 0;
  uint64_t chunk_leaf_count = 0;
  if (!shekyl_archival_challenge_leaf_chunk_bounds(sc_shard_id, leaf_index,
        &chunk_first_leaf, &chunk_leaf_count))
  {
    MERROR_VER("Archival serve-credit: challenged leaf index out of segment range");
    return false;
  }
  // Leaf byte-width is the shared shekyl::db::kLeafSize (4 Selene scalars × 32B);
  // no local re-declaration to drift against the DB's leaf-record contract. The
  // buffer is left uninitialised — the chunk read overwrites every byte or fails
  // wholesale (no partial-fill path reaches the FFI verifier).
  const size_t leaf_layer_scalars_len = chunk_leaf_count * shekyl::db::kLeafSize;
  std::unique_ptr<uint8_t[]> leaf_layer_scalars(new uint8_t[leaf_layer_scalars_len]);
  // One cursor scan over the contiguous chunk positions (a single B-tree
  // traversal), not one root-to-leaf lookup per leaf. Every chunk of a frozen
  // segment is full (segment bases are chunk-aligned; freezing requires the
  // whole segment present), so a short/missing chunk is registry/tree
  // disagreement, not a benign partial chunk.
  if (!m_db->get_curve_tree_leaf_chunk(chunk_first_leaf, chunk_leaf_count, leaf_layer_scalars.get()))
  {
    MERROR_VER("Archival serve-credit: leaf chunk read failed at tree position "
      << chunk_first_leaf << " (frozen-segment registry disagrees with curve tree)");
    return false;
  }

  // The FFI takes the kept half AFTER its tag byte (the serializer guard
  // already pinned the tag) and this vin's pruned record alongside.
  shekyl_archival_verify_ctx ctx{};
  ctx.current_height = current_height;
  ctx.settlement_epoch = sc_settlement_epoch;
  memcpy(ctx.block_hash_at_seal, seal_hash.data, 32);
  // NOT seal_hash: different block, different derivation (PC-D3).
  memcpy(ctx.prev_block_hash, prev_block_hash.data, 32);
  memcpy(ctx.registry_segment_subroot_rk, registry_rk.data, 32);
  ctx.segment_leaf_count = segment_leaf_count;
  ctx.pqc_pubkey_ptr = bond_pubkey.data();
  ctx.pqc_pubkey_len = bond_pubkey.size();
  ctx.leaf_layer_scalars_ptr = leaf_layer_scalars.get();
  ctx.leaf_layer_scalars_len = leaf_layer_scalars_len;

  const uint8_t verify_rc = shekyl_archival_verify_serve_credit_vin(
    resp.canonical_bytes.data(), resp.canonical_bytes.size(),
    pruned_record.data(), pruned_record.size(), &ctx);
  if (verify_rc != SHEKYL_ARCHIVAL_VERIFY_OK)
  {
    MERROR_VER("Archival serve-credit FFI verify failed (code " << (int)verify_rc << ")");
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// only works on the main chain
uint64_t Blockchain::get_adjusted_time(uint64_t height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // if not enough blocks, no proper median yet, return current time
  if(height < SHEKYL_DAA_MTP_WINDOW)
  {
      return static_cast<uint64_t>(time(NULL));
  }
  std::vector<uint64_t> timestamps;

  // need most recent SHEKYL_DAA_MTP_WINDOW blocks, get index of first of those
  size_t offset = height - SHEKYL_DAA_MTP_WINDOW;
  timestamps.reserve(height - offset);
  for(;offset < height; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }
  uint64_t median_ts = epee::misc_utils::median(timestamps);

  // project the median to match approximately when the block being validated will appear
  // the median is calculated from a chunk of past blocks, so we use +1 to offset onto the current block
  median_ts += (SHEKYL_DAA_MTP_WINDOW + 1) * SHEKYL_DAA_TARGET_SECONDS / 2;

  // project the current block's time based on the previous block's time
  // we don't use the current block's time directly to mitigate timestamp manipulation
  uint64_t adjusted_current_block_ts = timestamps.back() + SHEKYL_DAA_TARGET_SECONDS;

  // return minimum of ~current block time and adjusted median time
  // we do this since it's better to report a time in the past than a time in the future
  return (adjusted_current_block_ts < median_ts ? adjusted_current_block_ts : median_ts);
}
//------------------------------------------------------------------
bool Blockchain::check_block_timestamp(const std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // Marshaling shim (rule 20) over the ONE implementation of the C2-R3
  // block-timestamp rule: shekyl-difficulty's check_timestamp_rule,
  // exported as shekyl_difficulty_check_timestamp_rule beside the LWMA-1
  // difficulty entry point this validator already consumes. This side
  // only assembles the window, reads the clock, and logs the verdict —
  // it decides nothing (the crossing was re-ratified 2026-09-01 after
  // the round's original C++ owner was ruled a rule-20 violation; see
  // CONSENSUS_C2_R3_TIMESTAMPS.md §7's execution record).
  //
  // The padding value is passed unconditionally (cached at init; block 0
  // is immutable) so the pad-or-not decision lives wholly in the rule
  // owner — this side carries no copy of the short-window threshold.
  const int32_t verdict = shekyl_difficulty_check_timestamp_rule(
      b.timestamp, timestamps.data(), timestamps.size(), m_genesis_timestamp,
      (uint64_t)time(NULL), &median_ts);
  switch (verdict)
  {
    case SHEKYL_TIMESTAMP_RULE_OK:
      return true;
    case SHEKYL_TIMESTAMP_RULE_ABOVE_FTL:
      MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", more than " << SHEKYL_DAA_FTL_SECONDS << "s ahead of local time (LWMA-1 future-time limit)");
      return false;
    case SHEKYL_TIMESTAMP_RULE_NOT_ABOVE_MEDIAN:
      MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", not strictly above the median of the previous " << SHEKYL_DAA_MTP_WINDOW << " blocks, " << median_ts);
      return false;
    case SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE:
      // The newest-11 selection is order-dependent and therefore the
      // caller's job (C2-R3-Q1 sub-a); the rule refuses a wider window
      // rather than silently medianing it.
      MERROR_VER("Timestamp window construction bug for block with id: " << get_block_hash(b) << " (window wider than " << SHEKYL_DAA_MTP_WINDOW << ")");
      return false;
    default:
      MERROR_VER("Timestamp rule FFI misuse (code " << verdict << ") for block with id: " << get_block_hash(b));
      return false;
  }
}
//------------------------------------------------------------------
bool Blockchain::check_block_timestamp(const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // The window is the up-to-11 newest main-chain timestamps. Fewer than 11
  // exist only below SHEKYL_DAA_MTP_WINDOW blocks of history, where the
  // rule's genesis padding takes over — the median check runs from block 1;
  // the inherited bootstrap carve-out is deleted (C2-R3-Q2).
  const uint64_t h = m_db->height();

  // h == 0 is exactly one caller: Blockchain::init adding the locally
  // constructed genesis block to an empty store. The C2-R3 rule governs
  // blocks with predecessors (heights >= 1); block 0 is pinned by the
  // compiled genesis identity, and a peer-supplied "genesis" never reaches
  // here (handle_alternative_block rejects block_height == 0, and every
  // other main-path add has h >= 1). Not a carve-out: there is no window
  // to check, not a window we decline to check.
  if (h == 0)
  {
    median_ts = 0;
    return true;
  }

  std::vector<uint64_t> timestamps;
  uint64_t offset = h > SHEKYL_DAA_MTP_WINDOW ? h - SHEKYL_DAA_MTP_WINDOW : 0;
  timestamps.reserve(h - offset);
  for (; offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b, median_ts);
}
//------------------------------------------------------------------
bool Blockchain::verify_block_attestation(const block& b, const blobdata& witness)
{
  // ARCHIVAL_CREDIT_WIRE.md §3-§4: recompute-and-compare the block's attestation_root and verify
  // every pass record's P-countersignature. ALL logic is in Rust (shekyl_archival_verify_attestation);
  // this only marshals -- reads the header blob from the coinbase tx_extra, names the pass p_ids
  // (step 1), reads each bond's hybrid pubkey from LMDB by those keys, reads the coinbase output key,
  // hands the raw bytes across, and obeys the verdict. It parses nothing structural and decides
  // nothing (rule 20). Pre-cutover no block carries pass records, so on every VALID block (empty
  // witness, well-formed coinbase) this matches the interim's attestation_root ==
  // empty_attestation_root(); it is strictly stricter only on three pinned shapes (unsolicited
  // witness bytes, an unreadable coinbase vout[0] that prevalidate_miner_transaction rejects anyway,
  // and a coinbase tx_extra that fails to parse), so no valid block's verdict changes except the
  // deliberate unparseable-extra tightening pinned in unreadable_headers_is_headers_unreadable.
  const crypto::hash id = get_block_hash(b);

  // 1. Header blob from the coinbase tx_extra. parse_archival_attestation_from_extra returns false
  //    ONLY on a tx_extra parse failure (a parsed extra with no attestation tag is true with an
  //    empty blob -- the committed empty set). Unreadable is NOT empty: attestation-shaped bytes
  //    could ride an unparseable extra outside the attestation_root commitment, and the settlement
  //    scan later reads these same coinbase bytes, so flag it and let Rust return
  //    ERR_HEADERS_UNREADABLE -- a loud reject, never a silent empty.
  std::string headers;
  const bool headers_readable = parse_archival_attestation_from_extra(b.miner_tx.extra, headers);

  // 2. Step 1 (readable headers only -- unreadable headers name nothing): name the distinct pass
  //    p_ids so we know which bonds to read. Zero authority -- step 2 re-derives the authoritative
  //    set and rejects any coverage mismatch (ERR_PUBKEY_SET_MISMATCH).
  uint8_t pass_ids[config::ARCHIVAL_MAX_ATTESTATION_RECORDS][32];
  size_t pass_id_count = 0;
  if (headers_readable)
  {
    const uint8_t step1 = shekyl_archival_attestation_pass_p_ids(
      headers.empty() ? nullptr : reinterpret_cast<const uint8_t*>(headers.data()), headers.size(),
      pass_ids, config::ARCHIVAL_MAX_ATTESTATION_RECORDS, &pass_id_count);
    if (step1 != SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK)
    {
      MERROR_VER("Block with id: " << id << " has malformed attestation headers (step-1 verdict "
        << (unsigned)step1 << ")");
      return false;
    }
  }

  // 3. Read each distinct bond's hybrid pubkey. Fill ALL pubkey buffers first, THEN build the pairs
  //    array -- taking .data() while the vector still grows would dangle earlier pointers on realloc.
  //    A missing bond leaves the buffer empty (pubkey_len == 0), which Rust reads as the bond-absent
  //    marker (ERR_BOND_ABSENT for that pass), never a bad-signature verdict.
  std::vector<std::vector<uint8_t>> pubkeys(pass_id_count);
  for (size_t i = 0; i < pass_id_count; ++i)
  {
    crypto::hash p_id;
    std::memcpy(p_id.data, pass_ids[i], 32);
    m_db->get_archival_bond_hybrid_pubkey(p_id, pubkeys[i]);
  }
  std::vector<shekyl_archival_pid_pubkey> pairs(pass_id_count);
  for (size_t i = 0; i < pass_id_count; ++i)
  {
    std::memcpy(pairs[i].p_id, pass_ids[i], 32);
    pairs[i].pubkey_ptr = pubkeys[i].empty() ? nullptr : pubkeys[i].data();
    pairs[i].pubkey_len = pubkeys[i].size();
  }

  // 4. Assemble the ctx. cb_out_key is the coinbase vout[0] output key the nonce binds (consensus
  //    rule); a block with no coinbase output or a non-key output is unreadable -- flag it so Rust
  //    returns ERR_CBKEY_UNREADABLE rather than verifying against garbage.
  shekyl_archival_attestation_verify_ctx ctx{};
  std::memcpy(ctx.attestation_root, b.attestation_root.data, 32);
  crypto::public_key cb_out_key;
  if (!b.miner_tx.vout.empty() && get_output_public_key(b.miner_tx.vout[0], cb_out_key))
  {
    std::memcpy(ctx.cb_out_key, cb_out_key.data, 32);
    ctx.cb_out_key_readable = 1;
  }
  // prev_block_hash: the nonce's anchor term, replacing the producer's revealed randomness `r`
  // (RF-D3). It must be the VALIDATED predecessor -- on the main-chain path `bl.prev_id` is checked
  // against `top_hash` before this runs; on the alt-chain path it is the fork point the alt chain is
  // built on. An unvalidated header field would be producer-chosen, which is exactly the property
  // `r` was deleted for having. Rust refuses all-zeros (ERR_PREVHASH_UNPOPULATED) rather than
  // verifying every countersignature against H(0..0), so a forgotten field is loud, not silent --
  // deliberately with no `_readable` flag, since a verifier holding a block has parsed its header
  // and that arm could never legitimately fire.
  std::memcpy(ctx.prev_block_hash, b.prev_id.data, 32);
  ctx.headers_readable = headers_readable ? 1 : 0;
  ctx.headers_ptr = headers.empty() ? nullptr : reinterpret_cast<const uint8_t*>(headers.data());
  ctx.headers_len = headers.size();
  ctx.pairs_ptr = pairs.empty() ? nullptr : pairs.data();
  ctx.pairs_len = pairs.size();

  // 5. Step 2: the atomic verify. Any non-OK is a block-validity failure.
  const uint8_t verdict = shekyl_archival_verify_attestation(
    witness.empty() ? nullptr : reinterpret_cast<const uint8_t*>(witness.data()), witness.size(), &ctx);
  if (verdict != SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK)
  {
    MERROR_VER("Block with id: " << id << " failed attestation verify (verdict "
      << (unsigned)verdict << ")");
    return false;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::flush_txes_from_pool(const std::vector<crypto::hash> &txids)
{
  CRITICAL_REGION_LOCAL(m_tx_pool);

  bool res = true;
  for (const auto &txid: txids)
  {
    cryptonote::transaction tx;
    cryptonote::blobdata txblob;
    size_t tx_weight;
    uint64_t fee;
    bool relayed, do_not_relay, double_spend_seen, pruned;
    bool fcmp_cached_unused; // removal path; the cache verdict is not consumed
    MINFO("Removing txid " << txid << " from the pool");
    if(m_tx_pool.have_tx(txid, relay_category::all) && !m_tx_pool.take_tx(txid, tx, txblob, tx_weight, fee, relayed, do_not_relay, double_spend_seen, pruned, fcmp_cached_unused))
    {
      MERROR("Failed to remove txid " << txid << " from the pool");
      res = false;
    }
  }
  return res;
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(const block& bl, const crypto::hash& id,
  block_verification_context& bvc, block_connect_supplement& connect)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  pool_supplement& extra_block_txs = connect.pool;

  TIME_MEASURE_START(block_processing_time);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  static bool seen_future_version = false;

  db_rtxn_guard rtxn_guard(m_db);
  uint64_t blockchain_height;
  const crypto::hash top_hash = get_tail_id(blockchain_height);
  ++blockchain_height; // block height to chain height
  if(bl.prev_id != top_hash)
  {
    MERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
    bvc.m_verifivation_failed = true;
leave:
    return false;
  }

  // warn users if they're running an old version
  if (!seen_future_version && bl.major_version > m_hardfork->get_ideal_version())
  {
    seen_future_version = true;
    const el::Level level = el::Level::Warning;
    MCLOG_RED(level, "global", "**********************************************************************");
    MCLOG_RED(level, "global", "A block was seen on the network with a version higher than the last");
    MCLOG_RED(level, "global", "known one. This may be an old version of the daemon, and a software");
    MCLOG_RED(level, "global", "update may be required to sync further. Try running: update check");
    MCLOG_RED(level, "global", "**********************************************************************");
  }

  // this is a cheap test
  const uint8_t hf_version = get_current_hard_fork_version();
  if (!m_hardfork->check(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has old version: " << (unsigned)bl.major_version << std::endl << "current: " << (unsigned)hf_version);
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  // the credit-wire attestation verify (ARCHIVAL_CREDIT_WIRE.md §3-§4). Cheap pre-cutover (empty
  // witness -> empty-set root recompute); post-cutover it does up to one hybrid-signature verify per
  // pass record, so the signature leg must sit behind PoW before population turns on (Phase-5
  // ordering constraint, see FOLLOWUPS). verify_block_attestation logs the specific verdict code.
  if (!verify_block_attestation(bl, connect.attestation_witness))
  {
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t1);
  TIME_MEASURE_START(t2);

  // C2-R3 timestamp rule: strictly above the median of the previous 11
  // (genesis-padded) and within the future-time limit.
  if(!check_block_timestamp(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t2);
  //check proof of work
  TIME_MEASURE_START(target_calculating_time);

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_difficulty_for_next_block can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  difficulty_type current_diffic = get_difficulty_for_next_block();
  CHECK_AND_ASSERT_MES(current_diffic, false, "!!!!!!!!! difficulty overhead !!!!!!!!!");

  TIME_MEASURE_FINISH(target_calculating_time);

  TIME_MEASURE_START(longhash_calculating_time);

  crypto::hash proof_of_work;
  memset(proof_of_work.data, 0xff, sizeof(proof_of_work.data));

  // Formerly the code below contained an if loop with the following condition
  // !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
  // however, this caused the daemon to not bother checking PoW for blocks
  // before checkpoints, which is very dangerous behaviour. We moved the PoW
  // validation out of the next chunk of code to make sure that we correctly
  // check PoW now.
  // FIXME: height parameter is not used...should it be used or should it not
  // be a parameter?
  // validate proof_of_work versus difficulty target
  bool precomputed = false;
  {
    auto it = m_blocks_longhash_table.find(id);
    if (it != m_blocks_longhash_table.end())
    {
      precomputed = true;
      proof_of_work = it->second;
    }
    else if (!get_block_longhash(this, bl, proof_of_work, blockchain_height, nullptr, 0))
    {
      // CEN-D2: a longhash the verifier could not compute must reject the
      // block at EVERY difficulty — the 0xff sentinel alone passes
      // check_hash at difficulty 1. This is a local verifier failure, not
      // evidence against the block, so m_bad_pow is deliberately NOT set
      // (same class as the checkpoint-validation arm below: the block is
      // unproven, not disproven).
      MERROR_VER("PoW verifier failure (RandomX FFI) for block " << id
        << " at height " << blockchain_height << " -- block rejected unverified");
      bvc.m_verifivation_failed = true;
      goto leave;
    }

    // validate proof_of_work versus difficulty target
    if(!check_hash(proof_of_work, current_diffic))
    {
      MERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << proof_of_work << " at height " << blockchain_height << ", unexpected difficulty: " << current_diffic);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      goto leave;
    }
  }

  // If we're at a checkpoint, ensure that our hardcoded checkpoint hash
  // is correct.
  if(m_checkpoints.is_in_checkpoint_zone(blockchain_height))
  {
    if(!m_checkpoints.check_block(blockchain_height, id))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  TIME_MEASURE_FINISH(longhash_calculating_time);
  if (precomputed)
    longhash_calculating_time += m_fake_pow_calc_time;

  TIME_MEASURE_START(t3);

  // CEN-B5: the header's curve_tree_root commits to the tree state AT this
  // block's height -- the state after its parent connected and before this
  // block's own drain (the template fills it from get_curve_tree_root() at
  // that same point; the per-height record stores the same value under key
  // blockchain_height at connect). The prev_id check above guarantees the tip
  // is this block's parent, so the current tip root IS that state. Compare
  // here, at admission, before add_block runs the drain: a mismatch is a
  // rejected block, never a connected-then-popped one. (Comparing after
  // add_block read the post-drain root and rejected every block that matures
  // leaves -- the first one at height CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
  // where the genesis coinbase matures, on every real nettype;
  // tests/unit_tests/curve_tree_header_root_check.cpp.)
  //
  // Runs on every nettype, FAKECHAIN included (rule 71). The test generator
  // computes real roots through the Rust curve-tree client
  // (shekyl_curve_tree_replica_*), so a generated header that disagrees with
  // this store is a real disagreement between the two implementations, and
  // this is where it is caught.
  {
    const auto tip_root = m_db->get_curve_tree_root();
    crypto::hash expected_root;
    static_assert(sizeof(expected_root) == tip_root.size());
    std::memcpy(&expected_root, tip_root.data(), tip_root.size());
    if (bl.curve_tree_root != expected_root)
    {
      MERROR_VER("Block with id: " << id << " curve_tree_root mismatch at height " << blockchain_height
        << ": header " << bl.curve_tree_root << ", chain tip " << expected_root);
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, blockchain_height, hf_version))
  {
    MERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  // verify all non-input consensus rules for txs inside the pool supplement
  {
    tx_verification_context tvc{};
    // If fail non-input consensus rule checking...
    if (!ver_non_input_consensus(extra_block_txs, tvc, hf_version))
    {
      MERROR_VER("Pool supplement provided for block with id: " << id << " failed to pass validation");
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  size_t coinbase_weight = get_transaction_weight(bl.miner_tx);
  size_t cumulative_block_weight = coinbase_weight;

  std::vector<std::pair<transaction, blobdata>> txs;
  //                          txid     weight mempool?
  std::vector<std::tuple<crypto::hash, size_t, bool>> txs_meta;

  // Notification data for pool listeners for txs which skipped the mempool
  std::vector<txpool_event> txpool_events;

  // this lambda returns relevant txs back to the mempool
  auto return_txs_to_pool = [this, &txs, &txs_meta, &hf_version]()
  {
    if (txs_meta.size() != txs.size())
    {
      MERROR("BUG: txs_meta and txs not matching size!!!");
      return;
    }

    for (size_t i = 0; i < txs.size(); ++i)
    {
      // if this transaction wasn't ever in the pool, don't return it back to the pool
      const bool found_in_pool = std::get<2>(txs_meta[i]);
      if (!found_in_pool)
        continue;

      transaction &tx = txs[i].first;
      const crypto::hash &txid = std::get<0>(txs_meta[i]);
      const blobdata &tx_blob = txs[i].second;
      const size_t tx_weight = std::get<1>(txs_meta[i]);

      // We assume that if they were in a block, the transactions are already known to the network
      // as a whole. However, if we had mined that block, that might not be always true. Unlikely
      // though, and always relaying these again might cause a spike of traffic as many nodes
      // re-relay all the transactions in a popped block when a reorg happens. You might notice that
      // we also set the "nic_verified_hf_version" paramater. Since we know we took this transaction
      // from the mempool earlier in this function call, when the mempool has the same current fork
      // version, we can return it without re-verifying the consensus rules on it.
      cryptonote::tx_verification_context tvc{};
      if (!m_tx_pool.add_tx(tx, txid, tx_blob, tx_weight, tvc, relay_method::block, true,
          hf_version, /*origin=*/epee::net_utils::zone::invalid, hf_version))
        MERROR("Failed to return taken transaction with hash: " << txid << " to tx_pool");
    }
  };

  key_images_container keys;

  uint64_t fee_summary = 0;
  uint64_t t_checktx = 0;
  uint64_t t_exists = 0;
  uint64_t t_pool = 0;
  uint64_t t_dblspnd = 0;
  uint64_t n_pruned = 0;
  TIME_MEASURE_FINISH(t3);

// XXX old code adds miner tx here

  // Iterate over the block's transaction hashes, grabbing each
  // from the tx_pool (or from extra_block_txs) and validating them.  Each is then added
  // to txs.  Keys spent in each are added to <keys> by the double spend check.
  txs.reserve(bl.tx_hashes.size());
  txs_meta.reserve(bl.tx_hashes.size());
  txpool_events.reserve(bl.tx_hashes.size());
  for (const crypto::hash& tx_id : bl.tx_hashes)
  {
    TIME_MEASURE_START(aa);

// XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_id))
    {
      MERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }

    TIME_MEASURE_FINISH(aa);
    t_exists += aa;
    TIME_MEASURE_START(bb);

    // get transaction with hash <tx_id> from m_tx_pool or extra_block_txs
    // tx info we want:
    //   * tx as `cryptonote::transaction`
    //   * blob
    //   * weight
    //   * fee
    //   * is pruned?
    txs.emplace_back();
    transaction &tx = txs.back().first;
    blobdata &txblob = txs.back().second;
    size_t tx_weight{};
    uint64_t fee{};
    bool pruned{};

    /* 
     * Try pulling transaction data from the mempool proper first. If that fails, then try pulling
     * from the block supplement. We add txs pulled from the block to the txpool events for future
     * notifications, since if the tx skipped the mempool, then listeners have not yet received a
     * notification for this tx.
     */
    bool _unused1, _unused2, _unused3;
    bool fcmp_verification_cached = false;
    const bool found_tx_in_pool{
        m_tx_pool.take_tx(tx_id, tx, txblob, tx_weight, fee,
          _unused1, _unused2, _unused3, pruned, fcmp_verification_cached,
          /*suppress_missing_msgs=*/true)
      };
    bool find_tx_failure{!found_tx_in_pool};
    if (!found_tx_in_pool) // if not in mempool:
    {
      const auto extra_txs_it{extra_block_txs.txs_by_txid.find(tx_id)};
      if (extra_txs_it != extra_block_txs.txs_by_txid.end()) // if in block supplement:
      {
        tx = std::move(extra_txs_it->second.first);
        txblob = std::move(extra_txs_it->second.second);
        tx_weight = tx.pruned ? get_pruned_transaction_weight(tx) : get_transaction_weight(tx, txblob.size());
        fee = get_tx_fee(tx);
        pruned = tx.pruned;
        extra_block_txs.txs_by_txid.erase(extra_txs_it);
        txpool_events.emplace_back(txpool_event{tx, tx_id, txblob.size(), tx_weight, true});
        find_tx_failure = false;
      }
    }

    // @TODO: We should move this section (checking if the daemon has all txs from the block) to
    // right after the PoW check. Since it's now expected the node will sometimes not have all txs
    // in its pool at this point nor the txs included as fluffy txs (and will need to re-request
    // missing fluffy txs), then the node will sometimes waste cycles doing verification for some
    // txs twice.
    if (find_tx_failure) // did not find txid in mempool or provided extra block txs
    {
      const bool fully_supplemented_block = extra_block_txs.txs_by_txid.size() >= bl.tx_hashes.size();
      if (fully_supplemented_block)
        MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_id);
      else
        LOG_PRINT_L2("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_id);
      txs.pop_back(); // We push to the back preemptively. On fail, we need txs & txs_meta to match size
      bvc.m_verifivation_failed = true;
      bvc.m_missing_txs = true;
      return_txs_to_pool();
      return false;
    }
    if (pruned)
      ++n_pruned;

    TIME_MEASURE_FINISH(bb);
    t_pool += bb;
    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs_meta.emplace_back(tx_id, tx_weight, found_tx_in_pool);
    TIME_MEASURE_START(dd);

    // FIXME: the storage should not be responsible for validation.
    //        If it does any, it is merely a sanity check.
    //        Validation is the purview of the Blockchain class
    //        - TW
    //
    // ND: this is not needed, db->add_block() checks for duplicate k_images and fails accordingly.
    // if (!check_for_double_spend(tx, keys))
    // {
    //     LOG_PRINT_L0("Double spend detected in transaction (id: " << tx_id);
    //     bvc.m_verifivation_failed = true;
    //     break;
    // }

    TIME_MEASURE_FINISH(dd);
    t_dblspnd += dd;
    TIME_MEASURE_START(cc);

    {
      // The skip must be HASH-GATED, never presence-gated (CEN-M8): take_tx
      // reports whether the pool's verification cache affirmatively covers
      // these bytes (fcmp_verified set AND the recorded hash matching the
      // proof/referenceBlock/key images just parsed). Mere pool presence is
      // not enough — add_tx's kept_by_block tolerance inserts txs whose input
      // check FAILED with fcmp_verified = 0, and such a tx must pay full
      // verification here before it may connect.
      //
      // The skip itself stays LOAD-BEARING FOR THE EMBARGO, not only for
      // throughput: `hop` is defined (DAEMON_RELAY_PRIVACY.md §71) as
      // receive-to-forward including verification, and only the
      // POOL-ADMISSION path pays it. An admission-verified tx keeps its skip
      // (add_tx's success arm records flag + hash on the same derivation), so
      // `hop` still measures what the embargo priced; only a never-verified
      // tx loses a skip it should never have had. Removing the skip outright
      // would change what `hop` measures -- re-derive the embargo (§72.1)
      // before doing that. When the skip holds, all structural checks
      // (referenceBlock, depth, key images, PQC auth) still run.
      const bool can_skip_fcmp = found_tx_in_pool && fcmp_verification_cached;

      tx_verification_context tvc;
      if(!check_tx_inputs(tx, tvc, nullptr, can_skip_fcmp))
      {
        MERROR_VER("Block with id: " << id  << " has at least one transaction (id: " << tx_id << ") with wrong inputs.");

        add_block_as_invalid(bl, id);
        MERROR_VER("Block with id " << id << " added as invalid because of wrong inputs in transactions");
        bvc.m_verifivation_failed = true;
        return_txs_to_pool();
        return false;
      }
    }

    TIME_MEASURE_FINISH(cc);
    t_checktx += cc;
    fee_summary += fee;
    cumulative_block_weight += tx_weight;
  }

  // A pruned block has no weight source (the per-block-checkpoint weight
  // table was the only substitute; deleted, C2-R1a): reject.
  if (n_pruned > 0)
  {
    MERROR("Block at " << blockchain_height << " is pruned, but we do not have a weight for it");
    goto leave;
  }

  // Per-tx serve-credit idempotency checks run against pre-block DB state; reject
  // duplicate (P, shard, E) credits across multiple txs in the same block.
  //
  // AUDITED DECISION (ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md, D-SC-C):
  // mirrored in Rust (serve_credit_decisions::serve_credit_block_unique) and
  // transcribed verbatim in archival_serve_credit_equivalence.cpp. The key is
  // ArchivalPairEpochKey — the same big-endian encoding, unchanged by PC-D4 —
  // do not change it independently of the mirror, the transcription, and the
  // fixture's key pins. (SCE-1 unified post-equivalence; the LMDB comparator
  // setup forbids native-endian composite keys.)
  //
  // PC-D4 widened the LEDGER key and deliberately did NOT widen this one. The
  // natural inference — "the key grew, so this should too" — is wrong: within
  // ONE block every record shares the block, so the block component is
  // common-mode here and adds no discrimination. Two records for the same pair
  // in one block collide at the same (P, s, E, h) ledger key regardless, which
  // leaves the (P, s, E) check the correct within-block enforcer rather than a
  // leftover. The bytes must not move; the equivalence fixture's key pin is
  // what says so.
  {
    std::unordered_set<std::string> block_serve_credits;
    block_serve_credits.reserve(txs.size());
    for (const auto& tx_pair : txs)
    {
      for (const auto& vin : tx_pair.first.vin)
      {
        if (!std::holds_alternative<txin_archival_serve_credit_response>(vin))
          continue;
        const auto& resp = std::get<txin_archival_serve_credit_response>(vin);
        crypto::hash sc_p_id{}; uint64_t sc_shard = 0, sc_epoch = 0;
        if (!get_archival_serve_credit_key(resp, sc_p_id, sc_shard, sc_epoch))
        {
          MERROR_VER("Archival serve-credit vin unparseable in block");
          return false;
        }
        const shekyl::db::ArchivalPairEpochKey credit_key(
          reinterpret_cast<const uint8_t*>(sc_p_id.data), sc_shard, sc_epoch);
        std::string key(reinterpret_cast<const char*>(credit_key.bytes().data()),
          credit_key.bytes().size());
        if (!block_serve_credits.insert(std::move(key)).second)
        {
          MERROR_VER("Block " << id << " has duplicate archival serve-credit (P, shard, E)");
          bvc.m_verifivation_failed = true;
          return_txs_to_pool();
          return false;
        }
      }
    }
  }

  // Block-level emission (P,E) uniqueness pass (E3 gating round §6.2 layer 2)
  // and bond-post per-P uniqueness pass (gate-4 §3.5), collected in ONE vin
  // traversal (block verification is the sync/relay hot path; each pass's
  // verdict stays separate and Rust-side).
  //
  // Per-tx verify runs against pre-block DB state (the Q7 frozen-snapshot
  // purity property), so two txs in this block claiming the same (P, E) — or
  // posting the same P's bond twice (JoinMarket+JoinMarket double-credit,
  // Unbond+Unbond double-debit, mixed kinds) — each pass verify
  // independently; these passes are the layer that rejects the block. The
  // §4.5 conservation audit is NOT a backstop (a double-credit doubles both
  // sides consistently). C++ only marshals pairs/ids; the duplicate verdicts
  // are Rust's (decision-placement pin, §9.5 item 6).
  //
  // Deliberately NOT rejected here (ratified 2026-07-12): a serve-credit
  // response and an Unbond for the same P in one block — benign under the
  // settled release semantics (bond_post.rs::bond_post_block_unique docs):
  // served epochs are bit-immune, the re-armed span is the exit-forgiven
  // tail, and rejecting would cost an honest exiting P its final earned
  // credit for zero closed exposure.
  {
    std::vector<uint8_t> emission_claim_pairs;
    std::vector<uint8_t> bond_post_ids;
    for (const auto& tx_pair : txs)
    {
      const transaction& btx = tx_pair.first;
      for (size_t vin_idx = 0; vin_idx < btx.vin.size(); ++vin_idx)
      {
        const auto& vin = btx.vin[vin_idx];
        if (std::holds_alternative<txin_archival_bond_post>(vin))
        {
          const auto& bond = std::get<txin_archival_bond_post>(vin);
          const size_t off = bond_post_ids.size();
          bond_post_ids.resize(off + 32);
          memcpy(bond_post_ids.data() + off, bond.p_canonical_id.data, 32);
          continue;
        }
        if (!std::holds_alternative<txin_archival_reward_emission>(vin))
          continue;
        const auto& emission = std::get<txin_archival_reward_emission>(vin);
        crypto::hash p_canonical_id{};
        uint64_t vin_epochs[SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS] = {};
        size_t vin_epochs_len = 0;
        const uint8_t extract_rc = shekyl_archival_emission_vin_extract(
          emission.canonical_bytes.data(), emission.canonical_bytes.size(),
          reinterpret_cast<uint8_t*>(p_canonical_id.data),
          vin_epochs, SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS, &vin_epochs_len);
        if (extract_rc != SHEKYL_EMISSION_VIN_OK || vin_epochs_len == 0)
        {
          // check_tx_inputs already parsed this blob unconditionally; a
          // failure here is an internal inconsistency between two parses of
          // the same bytes — fail closed.
          MERROR_VER("Block " << id << " has an unparseable archival emission vin");
          bvc.m_verifivation_failed = true;
          return_txs_to_pool();
          return false;
        }
        for (size_t e = 0; e < vin_epochs_len; ++e)
        {
          const size_t off = emission_claim_pairs.size();
          emission_claim_pairs.resize(off + 40);
          memcpy(emission_claim_pairs.data() + off, p_canonical_id.data, 32);
          // The FFI contract is `p_canonical_id[32] || epoch_le[8]` — the Rust
          // side parses the epoch with u64::from_le_bytes. Emit little-endian
          // explicitly (identity on LE hosts, byteswap on BE) so the bytes
          // honor that contract on any target, not just the equality the
          // current distinctness fold happens to rely on.
          const uint64_t epoch_le = SWAP64LE(vin_epochs[e]);
          memcpy(emission_claim_pairs.data() + off + 32, &epoch_le, 8);
        }
      }
    }
    const size_t num_pairs = emission_claim_pairs.size() / 40;
    if (num_pairs > 0
        && shekyl_emission_block_claims_unique(emission_claim_pairs.data(), num_pairs) != 1)
    {
      MERROR_VER("Block " << id << " has duplicate archival emission (P, E) claims");
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }
    const size_t num_ids = bond_post_ids.size() / 32;
    if (num_ids > 0
        && shekyl_archival_bond_post_block_unique(bond_post_ids.data(), num_ids) != 1)
    {
      MERROR_VER("Block " << id << " has multiple archival bond posts for one P");
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }
  }

  TIME_MEASURE_START(vmt);
  uint64_t base_reward = 0;
  uint64_t already_generated_coins = blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
  // D2 escalation operand, read ONCE at parent state (the helper throws if the
  // tree has already grown for this block) and shared by the money check below
  // and the staker-inflow accrual — the same single-read discipline as
  // base_reward (F-B1c): verify's operand IS the accrual's operand.
  const uint64_t frozen_segment_count = parent_frozen_segment_count(blockchain_height);
  if(!validate_miner_transaction(bl, cumulative_block_weight, fee_summary, base_reward, already_generated_coins, m_hardfork->get_current_version(), frozen_segment_count))
  {
    MERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return_txs_to_pool();
    return false;
  }

  TIME_MEASURE_FINISH(vmt);

  // Staker-inflow accrual (ARCHIVAL_BUDGET_SCHEDULE.md §2.2): one per-height
  // write of the block's staker inflow into the `archival_budget_accrual`
  // row the epoch close freezes into budget(E). Unconditional for every
  // non-genesis block: archival emission is a genesis fact — the block
  // version floor is 1, so the claim-era "burn the inflow pre-activation"
  // leg that used to gate this write on HF_VERSION_ARCHIVAL_EMISSION was
  // unreachable-by-construction and has been deleted along with the
  // constant (rule 60; git history has the shape). The burn amount below
  // carries ONLY the fee-burn's destroyed share.
  //
  // Computed HERE, before m_db->add_block, for two load-bearing reasons:
  //  - Version operand (F-B1b): the operand is bl.major_version — the block's
  //    OWN declared version, consensus-bound by m_hardfork->check(bl) above
  //    (do_check: bl.major_version == the voted current version) before this
  //    point is reachable. Explicit per-block anchoring per §2.2: no
  //    dependence on where get_current_version() sits relative to add_block
  //    (post-add it has advanced to the NEXT block's voted version — the
  //    original F-B1b bug; pre-add it happens to equal bl.major_version, but
  //    only via the height+1 advance convention this operand choice retires).
  //    NOT get_ideal_version(height): that is the static-table lookup and
  //    ignores the vote threshold, so it can disagree with the version the
  //    block was validated as. Do NOT reintroduce a get_block_reward call or
  //    a second version read in this block — verify's base_reward and
  //    bl.major_version ARE the operands (tripwire-guarded:
  //    scripts/ci/check_archival_reward_gates.sh).
  //  - Write ordering (F-B1a): the accrual amount rides into add_block and is
  //    written before the epoch-close hook fires, so the close of epoch E
  //    sees its final block's row in the [E·SEB, (E+1)·SEB) range-sum.
  //
  // Both halves of the inflow use verify's exact operands (F-B1c):
  //  - Emission leg (c2, disposition (a) — permanent per the §9.9 sim
  //    closure): the split operand is base_reward — the SAME modulated
  //    (weight-penalized, release-scaled) quantity
  //    validate_miner_transaction just validated the coinbase's subsidy
  //    component against and that already_generated_coins advances by
  //    below. Emission conservation is then by construction:
  //    miner_emission + staker_emission = base_reward, exactly the
  //    ledger advance — every newly created coin is either in the
  //    coinbase's subsidy component or in the accrual row, never both,
  //    never neither. Fees are pre-existing coins conserved by
  //    compute_fee_burn's separate partition (miner_fee_income →
  //    coinbase, staker_pool_amount → accrual row, actually_destroyed →
  //    burn row), so the general per-block identity is
  //    coinbase + accrual row + burn row = base_reward + total_fees
  //    (fee-free it reduces to ledger advance = coinbase + accrual,
  //    the conservation KAT's asserted form). The pre-fix shape
  //    (5-arg get_block_reward, unmodulated) over-sized the staker leg
  //    whenever the release multiplier or weight penalty fired — an
  //    inflation surface, since the accrued leg is re-mintable through
  //    emission claims (coins the ledger never counted as emitted).
  //  - Fee leg (c1): the same prev-cumulative supply and tx_volume_avg
  //    validate_miner_transaction used — a zero volume operand zeroes
  //    burn_pct, which silently zeroed the fee-pool half of the inflow
  //    (accrued nowhere, burn-recorded nowhere).
  //
  // Genesis (blockchain_height == 0) has no staker leg: its emission is the
  // hardcoded GENESIS_TX amount, validate_miner_transaction returns it whole
  // as base_reward, and the genesis coinbase pays ALL of it — splitting here
  // would accrue a share of coins the coinbase already fully paid.
  uint64_t archival_budget_accrual = 0;
  uint64_t block_burn_amount = 0;
  if (blockchain_height > 0)
  {
    const uint64_t genesis_ng_height = m_hardfork->get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG);

    const shekyl::EmissionSplit em_split = shekyl::compute_emission_split(
        base_reward, blockchain_height, genesis_ng_height);

    const shekyl::BurnResult burn = shekyl::compute_fee_burn(
        fee_summary, get_tx_volume_avg(blockchain_height), already_generated_coins,
        frozen_segment_count);

    archival_budget_accrual = em_split.staker_emission + burn.staker_pool_amount;
    block_burn_amount = burn.actually_destroyed;
  }

  size_t block_weight;
  difficulty_type cumulative_difficulty;

  // populate various metadata about the block to be stored alongside it.
  block_weight = cumulative_block_weight;
  cumulative_difficulty = current_diffic;
  // In the "tail" state when the minimum subsidy (implemented in get_block_reward) is in effect, the number of
  // coins will eventually exceed MONEY_SUPPLY and overflow a uint64. To prevent overflow, cap already_generated_coins
  // at MONEY_SUPPLY. already_generated_coins is only used to compute the block subsidy and MONEY_SUPPLY yields a
  // subsidy of 0 under the base formula and therefore the minimum subsidy >0 in the tail state.
  //
  // The clamp itself is Rust-side (shekyl_advance_already_generated). It was
  // written out here AND in the alt-chain path above; two hand-written copies
  // of a consensus clamp are a drift pair, so both now call the one entry
  // point (the division-one-site discipline consensus_constants.json records
  // for segment_leaf_count).
  already_generated_coins = shekyl_advance_already_generated(already_generated_coins, base_reward);
  if(blockchain_height)
    cumulative_difficulty += m_db->get_block_cumulative_difficulty(blockchain_height - 1);

  TIME_MEASURE_FINISH(block_processing_time);
  if(precomputed)
    block_processing_time += m_fake_pow_calc_time;

  rtxn_guard.stop();
  TIME_MEASURE_START(addblock);
  uint64_t new_height = 0;
  if (!bvc.m_verifivation_failed)
  {
    try
    {
      uint64_t long_term_block_weight = get_next_long_term_block_weight(block_weight);
      cryptonote::blobdata bd = cryptonote::block_to_blob(bl);
      // Attestation witness (ARCHIVAL_CREDIT_WIRE.md §3): supplied via
      // block_connect_supplement (p2p transport, verifying import, reorg
      // re-supply). Empty on local mine and until the Phase 2/3 template writer
      // populates it. Empty stores no height-keyed row.
      new_height = m_db->add_block(std::make_pair(std::move(bl), std::move(bd)), block_weight, long_term_block_weight, cumulative_difficulty, already_generated_coins, archival_budget_accrual, connect.attestation_witness, txs);
    }
    catch (const KEY_IMAGE_EXISTS& e)
    {
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }
  }
  else
  {
    LOG_ERROR("Blocks that failed verification should not reach here");
  }

  TIME_MEASURE_FINISH(addblock);

  // do this after updating the hard fork state since the weight limit may change due to fork
  if (!update_next_cumulative_weight_limit())
  {
    MERROR("Failed to update next cumulative weight limit");
    pop_block_from_blockchain();
    return false;
  }

  if (new_height > 0 && block_burn_amount > 0)
  {
    // Per-height burn record for the fee-burn's destroyed share — the sole
    // persisted per-block bookkeeping this path needs, so
    // pop_block_from_blockchain can roll total_burned back. The amount was
    // computed pre-add alongside the accrual (see the staker-inflow accrual
    // block above). Only written when nonzero: get_block_burn returns 0 for
    // an absent height, so a zero row would carry no information (and pop's
    // remove_block_burn tolerates the missing key).
    m_db->add_block_burn(blockchain_height, block_burn_amount);
    uint64_t total_burned = m_db->get_total_burned();
    total_burned += block_burn_amount;
    m_db->set_total_burned(total_burned);
  }

  MINFO("+++++ BLOCK SUCCESSFULLY ADDED" << std::endl << "id:\t" << id << std::endl << "PoW:\t" << proof_of_work << std::endl << "HEIGHT " << new_height-1 << ", difficulty:\t" << current_diffic << std::endl << "block reward: " << print_money(fee_summary + base_reward) << "(" << print_money(base_reward) << " + " << print_money(fee_summary) << "), coinbase_weight: " << coinbase_weight << ", cumulative weight: " << cumulative_block_weight << ", " << block_processing_time << "(" << target_calculating_time << "/" << longhash_calculating_time << ")ms");
  if(m_show_time_stats)
  {
    MINFO("Height: " << new_height << " coinbase weight: " << coinbase_weight << " cumm: "
        << cumulative_block_weight << " p/t: " << block_processing_time << " ("
        << target_calculating_time << "/" << longhash_calculating_time << "/"
        << t1 << "/" << t2 << "/" << t3 << "/" << t_exists << "/" << t_pool
        << "/" << t_checktx << "/" << t_dblspnd << "/" << vmt << "/" << addblock << ")ms");
  }

  bvc.m_added_to_main_chain = true;
  ++m_sync_counter;

  // appears to be a NOP *and* is called elsewhere.  wat?
  m_tx_pool.on_blockchain_inc(new_height, id);
  get_difficulty_for_next_block(); // just to cache it
  invalidate_block_template_cache();

  const uint8_t new_hf_version = get_current_hard_fork_version();
  if (new_hf_version != hf_version)
  {
    // the genesis block is added before everything's setup, and the txpool is empty
    // when we start from scratch, so we skip this
    const bool is_genesis_block = new_height == 1;
    if (!is_genesis_block)
    {
      MGINFO("Validating txpool for v" << (unsigned)new_hf_version);
      m_tx_pool.validate(new_hf_version);
    }
  }

  const crypto::hash seedhash = get_block_id_by_height(shekyl_pow_randomx_v2_seedheight(new_height));

  // Make sure that txpool notifications happen BEFORE block and miner data notifications
  notify_txpool_event(std::move(txpool_events));

  // send miner notifications to switch as soon as possible
  send_miner_notifications(new_height, seedhash, id, already_generated_coins);

  // then send block notifications
  for (const auto& notifier: m_block_notifiers)
    notifier(new_height - 1, {std::addressof(bl), 1});

  shekyl_pow_randomx_v2_set_canonical(reinterpret_cast<const uint8_t (*)[32]>(seedhash.data));

  return true;
}
//------------------------------------------------------------------
bool Blockchain::prune_blockchain(uint32_t pruning_seed)
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  if (!m_db->prune_blockchain(pruning_seed))
    return false;
  // The confirmed prune is complete only with the output-metadata pass:
  // stripe pruning alone leaves the txs_pqc_auths/txs_prunable rows that
  // update_blockchain_pruning would otherwise free up to five hours later,
  // and the console tells the operator to compact once this call returns.
  return m_db->prune_tx_data(CRYPTONOTE_TX_PRUNE_DEPTH);
}
//------------------------------------------------------------------
bool Blockchain::update_blockchain_pruning()
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  if (!m_db->update_pruning())
    return false;
  if (m_db->get_blockchain_pruning_seed() && !m_db->prune_tx_data(CRYPTONOTE_TX_PRUNE_DEPTH))
    return false;
  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_blockchain_pruning()
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->check_pruning();
}
//------------------------------------------------------------------
// returns min(Mb, 1.7*Ml) as per https://github.com/ArticMine/Monero-Documents/blob/master/MoneroScaling2021-02.pdf from HF_VERSION_LONG_TERM_BLOCK_WEIGHT
uint64_t Blockchain::get_next_long_term_block_weight(uint64_t block_weight) const
{
  PERF_TIMER(get_next_long_term_block_weight);

  const uint64_t db_height = m_db->height();
  const uint64_t nblocks = std::min<uint64_t>(m_long_term_block_weights_window, db_height);

  uint64_t long_term_median = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  if (nblocks > 0)
    long_term_median = get_long_term_block_weight_median(db_height - nblocks, nblocks);
  uint64_t long_term_effective_median_block_weight = std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

  // long_term_block_weight = block_weight bounded to range [long-term-median/1.7, long-term-median*1.7]
  block_weight = std::max<uint64_t>(block_weight, long_term_effective_median_block_weight * 10 / 17);
  uint64_t short_term_constraint = long_term_effective_median_block_weight + long_term_effective_median_block_weight * 7 / 10;
  uint64_t long_term_block_weight = std::min<uint64_t>(block_weight, short_term_constraint);

  return long_term_block_weight;
}
//------------------------------------------------------------------
bool Blockchain::update_next_cumulative_weight_limit(uint64_t *long_term_effective_median_block_weight)
{
  PERF_TIMER(update_next_cumulative_weight_limit);

  LOG_PRINT_L3("Blockchain::" << __func__);

  // when we reach this, the last hf version is not yet written to the db
  const uint64_t db_height = m_db->height();
  const uint8_t hf_version = get_current_hard_fork_version();
  uint64_t full_reward_zone = get_min_block_weight(hf_version);

  {
    const uint64_t nblocks = std::min<uint64_t>(m_long_term_block_weights_window, db_height);
    const uint64_t long_term_median = nblocks > 0
      ? get_long_term_block_weight_median(db_height - nblocks, nblocks)
      : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

    m_long_term_effective_median_block_weight = std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

    std::vector<uint64_t> weights;
    get_last_n_blocks_weights(weights, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

    uint64_t short_term_median = epee::misc_utils::median(weights);
    // effective median = short_term_median bounded to range [long_term_median, 50*long_term_median],
    // but it can't be smaller than the minimum penalty free zone (a.k.a. 'full reward zone')
    uint64_t effective_median_block_weight = std::min<uint64_t>(std::max<uint64_t>(m_long_term_effective_median_block_weight, short_term_median), CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * m_long_term_effective_median_block_weight);

    m_current_block_cumul_weight_median = effective_median_block_weight;
  }

  if (m_current_block_cumul_weight_median <= full_reward_zone)
    m_current_block_cumul_weight_median = full_reward_zone;

  m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2;

  if (long_term_effective_median_block_weight)
    *long_term_effective_median_block_weight = m_long_term_effective_median_block_weight;

  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl_, block_verification_context& bvc)
{
  // Witness-less entry: only genesis and (pre-cutover) locally-mined empty-root blocks reach here;
  // p2p and reorg blocks carry their attestation witness through the 3-arg overload. A non-empty
  // attestation_root at this entry means a caller dropped the witness -- the miner-local
  // handle_block_found path (cryptonote_core.cpp) is the known one, and it MUST be rewired to the
  // 3-arg add_new_block before the credit-wire cutover activates population (FOLLOWUPS.md /
  // ARCHIVAL_CREDIT_WIRE.md §3). Until then this guard turns that drop into an immediate, un-missable
  // failure instead of a silent MALFORMED_WITNESS self-reject inside verify_block_attestation. Safe
  // as a hard guard: the witness-less entry is local-only, never reachable from untrusted p2p input.
  CHECK_AND_ASSERT_MES(bl_.attestation_root == empty_attestation_root(), false,
    "add_new_block: witness-less entry reached with a non-empty attestation_root; the caller must "
    "plumb the block's attestation witness through the 3-arg add_new_block (credit-wire cutover wiring)");
  block_connect_supplement connect{};
  return add_new_block(bl_, bvc, connect);
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl, block_verification_context& bvc,
  block_connect_supplement& connect)
{
  try
  {

  LOG_PRINT_L3("Blockchain::" << __func__);
  crypto::hash id = get_block_hash(bl);
  CRITICAL_REGION_LOCAL(m_tx_pool);//to avoid deadlock lets lock tx_pool for whole add/reorganize process
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);
  db_rtxn_guard rtxn_guard(m_db);
  if(have_block(id))
  {
    LOG_PRINT_L3("block with id = " << id << " already exists");
    bvc.m_already_exists = true;
    return false;
  }

  //check that block refers to chain tail
  if(!(bl.prev_id == get_tail_id()))
  {
    //chain switching or wrong block
    bvc.m_added_to_main_chain = false;
    rtxn_guard.stop();
    return handle_alternative_block(bl, id, bvc, connect);
    //never relay alternative blocks
  }

  rtxn_guard.stop();
  return handle_block_to_main_chain(bl, id, bvc, connect);

  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Exception at [add_new_block], what=" << e.what());
    bvc.m_verifivation_failed = true;
    return false;
  }
}
//------------------------------------------------------------------
//TODO: Refactor, consider returning a failure height and letting
//      caller decide course of action.
bool Blockchain::check_against_checkpoints(const checkpoints& points)
{
  const auto& pts = points.get_points();
  bool stop_batch;
  bool ok = true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  stop_batch = m_db->batch_start();
  const uint64_t blockchain_height = m_db->height();
  for (const auto& pt : pts)
  {
    // if the checkpoint is for a block we don't have yet, move on
    if (pt.first >= blockchain_height)
    {
      continue;
    }

    if (!points.check_block(pt.first, m_db->get_block_hash_from_height(pt.first)))
    {
      if (pt.first == 0)
      {
        // A conflict AT genesis has no rollback remedy: genesis cannot be
        // popped, and "rolling back" to a chain whose height-0 block still
        // mismatches would report the conflict resolved while fixing
        // nothing (the reports-success shape, fourth instance). This node
        // is on the wrong network or the file is wrong; fail-stop.
        MERROR("Checkpoint at height 0 (expected " << pt.second
          << ", chain has " << m_db->get_block_hash_from_height(0)
          << ") conflicts with this chain's GENESIS -- no rollback can"
          << " resolve it; remedy: fix the checkpoints file or resync on"
          << " the right network");
        ok = false;
        continue;
      }
      // Roll back to a couple of blocks before the checkpoint, floored at
      // DB height 1: genesis cannot be popped
      // (pop_block_from_blockchain throws at height() == 1), so a target
      // of 0 -- the inherited `pt.first - 2` wrap's saturated form at a
      // height-1/2 checkpoint -- aborted mid-rollback on the genesis
      // guard instead of completing (review round 4; the wrap itself was
      // C2-R1b-Q2b's third reports-success-while-doing-nothing instance).
      const uint64_t rollback_target = pt.first >= 3 ? pt.first - 2 : 1;
      // C2-R1b F-1(b): if the rollback itself would cross the prune
      // watermark, there is no remedy this daemon can apply -- it must not
      // keep running in contradiction with a checkpoint it accepted. Same
      // predicate as the pop_block belt; the false return fail-stops via
      // core::update_checkpoints -> graceful_exit.
      //
      // Height-vs-index: `rollback_target` is a DB HEIGHT (the rollback
      // loop stops when height() == rollback_target), while the predicate
      // takes the resulting tip's block INDEX = rollback_target - 1.
      // Passing the height verbatim let the boundary case slip past this
      // pre-check into the belt's exception instead of the documented
      // fail-stop (review round 2).
      const uint64_t rollback_tip_index = rollback_target >= 1 ? rollback_target - 1 : 0;
      if (!m_db->pop_target_allowed(rollback_tip_index))
      {
        MERROR("Checkpoint at height " << pt.first << " (expected " << pt.second
          << ", chain has " << m_db->get_block_hash_from_height(pt.first)
          << ") conflicts with the local chain, and the rollback target "
          << rollback_target << " is below the prune watermark floor (epoch "
          << m_db->get_archival_prune_watermark_epoch()
          << ") -- cannot roll back that deep; remedy: resync this node");
        ok = false;
        continue;
      }
      LOG_ERROR("Local blockchain failed to pass a checkpoint, rolling back! (checkpoint height " << pt.first
        << ", expected " << pt.second
        << ", chain has " << m_db->get_block_hash_from_height(pt.first)
        << ", rollback target " << rollback_target << ")");
      std::list<detached_block> empty;
      rollback_blockchain_switching(empty, rollback_target);
      // The points map is height-ordered, so every later checkpoint now
      // sits at or above the new tip -- but the loop's have-this-block
      // test reads the PRE-rollback height, so continuing would call
      // get_block_hash_from_height above the tip and throw (review
      // round 4). Those checkpoints are re-checked as the chain regrows.
      break;
    }
  }
  if (stop_batch)
    m_db->batch_stop();
  return ok;
}
//------------------------------------------------------------------
// returns false if any of the checkpoints loading returns false.
// That should happen only if a checkpoint is added that conflicts
// with an existing checkpoint.
bool Blockchain::update_checkpoints(const std::string& file_path)
{
  if (!m_checkpoints.load_checkpoints_from_json(file_path))
  {
      return false;
  }

  if (!check_against_checkpoints(m_checkpoints))
  {
    // F-1(b): a conflict the rollback could not apply -- the caller
    // (core::update_checkpoints) fail-stops rather than letting the daemon
    // run in contradiction with a checkpoint it accepted. The file is the
    // one operator input; name it.
    MERROR("Checkpoint conflict from '" << file_path << "' could not be resolved; refusing to continue");
    return false;
  }

  return true;
}
//------------------------------------------------------------------
void Blockchain::block_longhash_worker(uint64_t height, const epee::span<const block> &blocks, std::unordered_map<crypto::hash, crypto::hash> &map) const
{
  TIME_MEASURE_START(t);
  slow_hash_allocate_state();

  for (const auto & block : blocks)
  {
    if (m_cancel)
       break;
    crypto::hash id = get_block_hash(block);
    crypto::hash pow;
    if (!get_block_longhash(this, block, pow, height++, nullptr, 0))
    {
      // CEN-D2: an uncomputed hash must never enter the precompute table --
      // the consumer trusts table hits without re-checking. Skipping the
      // insert makes the validation site recompute and hit its own
      // verifier-failure rejection.
      MERROR("PoW verifier failure (RandomX FFI) in longhash worker for block "
        << id << " -- leaving hash uncached");
      continue;
    }
    map.emplace(id, pow);
  }

  slow_hash_free_state();
  TIME_MEASURE_FINISH(t);
}

//------------------------------------------------------------------
bool Blockchain::cleanup_handle_incoming_blocks(bool force_sync)
{
  bool success = false;

  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_BEGIN(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  try
  {
    if (m_batch_success)
    {
      m_db->batch_stop();
      if (m_reset_timestamps_and_difficulties_height)
      {
        m_timestamps_and_difficulties_height = 0;
        m_reset_timestamps_and_difficulties_height = false;
      }
    }
    else
      m_db->batch_abort();
    success = true;
  }
  catch (const std::exception &e)
  {
    MERROR("Exception in cleanup_handle_incoming_blocks: " << e.what());
  }

  if (success && m_sync_counter > 0)
  {
    if (force_sync)
    {
      if(m_db_sync_mode != db_nosync)
        store_blockchain();
      m_sync_counter = 0;
    }
    else if (m_db_sync_threshold && ((m_db_sync_on_blocks && m_sync_counter >= m_db_sync_threshold) || (!m_db_sync_on_blocks && m_bytes_to_sync >= m_db_sync_threshold)))
    {
      MDEBUG("Sync threshold met, syncing");
      if(m_db_sync_mode == db_async)
      {
        m_sync_counter = 0;
        m_bytes_to_sync = 0;
        boost::asio::dispatch(m_async_service, boost::bind(&Blockchain::store_blockchain, this));
      }
      else if(m_db_sync_mode == db_sync)
      {
        store_blockchain();
      }
      else // db_nosync
      {
        // DO NOTHING, not required to call sync.
      }
    }
  }

  TIME_MEASURE_FINISH(t1);
  m_blocks_longhash_table.clear();
  m_scan_table.clear();

  CRITICAL_REGION_END();
  m_tx_pool.unlock();

  update_blockchain_pruning();

  return success;
}

//------------------------------------------------------------------
void Blockchain::output_scan_worker(const uint64_t amount, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs) const
{
  try
  {
    m_db->get_output_key(epee::span<const uint64_t>(&amount, 1), offsets, outputs, true);
  }
  catch (const std::exception& e)
  {
    MERROR_VER("EXCEPTION: " << e.what());
  }
  catch (...)
  {

  }
}

//------------------------------------------------------------------
// ND: Speedups:
// 1. Thread long_hash computations if possible (m_max_prepare_blocks_threads = nthreads, default = 4)
// 2. Group all amounts (from txs) and related absolute offsets and form a table of tx_prefix_hash
//    vs [k_image, output_keys] (m_scan_table). This is faster because it takes advantage of bulk queries
//    and is threaded if possible. The table (m_scan_table) will be used later when querying output
//    keys.
bool Blockchain::prepare_handle_incoming_blocks(const std::vector<block_complete_entry> &blocks_entry, std::vector<block> &blocks)
{
  MTRACE("Blockchain::" << __func__);
  TIME_MEASURE_START(prepare);
  bool stop_batch;
  uint64_t bytes = 0;
  size_t total_txs = 0;
  blocks.clear();

  // Order of locking must be:
  //  m_incoming_tx_lock (optional)
  //  m_tx_pool lock
  //  blockchain lock
  //
  //  Something which takes the blockchain lock may never take the txpool lock
  //  if it has not provably taken the txpool lock earlier
  //
  //  The txpool lock is now taken in prepare_handle_incoming_blocks
  //  and released in cleanup_handle_incoming_blocks. This avoids issues
  //  when something uses the pool, which now uses the blockchain and
  //  needs a batch, since a batch could otherwise be active while the
  //  txpool and blockchain locks were not held

  m_tx_pool.lock();
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if(blocks_entry.size() == 0)
    return false;

  for (const auto &entry : blocks_entry)
  {
    bytes += entry.block.size();
    for (const auto &tx_blob : entry.txs)
    {
      bytes += tx_blob.blob.size();
    }
    // Count the credit-wire attestation witness here too: it rides the batch write into the
    // prunable side table and sits in m_block_queue RAM, so both m_bytes_to_sync (the byte-based
    // DB-sync trigger) and batch_start's bound must include it — matching the span accounting in
    // the NOTIFY_RESPONSE_GET_OBJECTS handler. Omitting it lets a witness-carrying span exceed the
    // memory bound the batch believes it is under.
    bytes += entry.attestation_witness.size();
    total_txs += entry.txs.size();
  }
  m_bytes_to_sync += bytes;
  while (!(stop_batch = m_db->batch_start(blocks_entry.size(), bytes))) {
    m_blockchain_lock.unlock();
    m_tx_pool.unlock();
    epee::misc_utils::sleep_no_w(1000);
    m_tx_pool.lock();
    m_blockchain_lock.lock();
  }
  m_batch_success = true;

  const uint64_t height = m_db->height();

  bool blocks_exist = false;
  tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
  unsigned threads = tpool.get_max_concurrency();
  blocks.resize(blocks_entry.size());

  if (1)
  {
    // limit threads, default limit = 4
    if(threads > m_max_prepare_blocks_threads)
      threads = m_max_prepare_blocks_threads;

    unsigned int batches = blocks_entry.size() / threads;
    unsigned int extra = blocks_entry.size() % threads;
    MDEBUG("block_batches: " << batches);
    std::vector<std::unordered_map<crypto::hash, crypto::hash>> maps(threads);
    auto it = blocks_entry.begin();
    unsigned blockidx = 0;

    const crypto::hash tophash = m_db->top_block_hash();
    for (unsigned i = 0; i < threads; i++)
    {
      for (unsigned int j = 0; j < batches; j++, ++blockidx)
      {
        block &block = blocks[blockidx];
        crypto::hash block_hash;

        if (!parse_and_validate_block_from_blob(it->block, block, block_hash))
          return false;

        // check first block and skip all blocks if its not chained properly
        if (blockidx == 0)
        {
          if (block.prev_id != tophash)
          {
            MDEBUG("Skipping prepare blocks. New blocks don't belong to chain.");
            blocks.clear();
            return true;
          }
        }
        if (have_block(block_hash))
          blocks_exist = true;

        std::advance(it, 1);
      }
    }

    for (unsigned i = 0; i < extra && !blocks_exist; i++, blockidx++)
    {
      block &block = blocks[blockidx];
      crypto::hash block_hash;

      if (!parse_and_validate_block_from_blob(it->block, block, block_hash))
        return false;

      if (have_block(block_hash))
        blocks_exist = true;

      std::advance(it, 1);
    }

    if (!blocks_exist)
    {
      m_blocks_longhash_table.clear();
      uint64_t thread_height = height;
      tools::threadpool::waiter waiter(tpool);
      m_prepare_height = height;
      m_prepare_nblocks = blocks_entry.size();
      m_prepare_blocks = &blocks;
      for (unsigned int i = 0; i < threads; i++)
      {
        unsigned nblocks = batches;
        if (i < extra)
          ++nblocks;
        if (nblocks == 0)
          break;
        tpool.submit(&waiter, boost::bind(&Blockchain::block_longhash_worker, this, thread_height, epee::span<const block>(&blocks[thread_height - height], nblocks), std::ref(maps[i])), true);
        thread_height += nblocks;
      }

      if (!waiter.wait())
        return false;
      m_prepare_height = 0;

      if (m_cancel)
         return false;

      for (const auto & map : maps)
      {
        m_blocks_longhash_table.insert(map.begin(), map.end());
      }
    }
  }

  if (m_cancel)
    return false;

  if (blocks_exist)
  {
    MDEBUG("Skipping remainder of prepare blocks. Blocks exist.");
    return true;
  }

  m_fake_scan_time = 0;
  m_fake_pow_calc_time = 0;

  m_scan_table.clear();

  TIME_MEASURE_FINISH(prepare);
  m_fake_pow_calc_time = prepare / blocks_entry.size();

  if (blocks_entry.size() > 1 && threads > 1 && m_show_time_stats)
    MDEBUG("Prepare blocks took: " << prepare << " ms");

  TIME_MEASURE_START(scantable);

  // [input] stores all unique amounts found
  std::vector < uint64_t > amounts;
  // [input] stores all absolute_offsets for each amount
  std::map<uint64_t, std::vector<uint64_t>> offset_map;
  // [output] stores all output_data_t for each absolute_offset
  std::map<uint64_t, std::vector<output_data_t>> tx_map;
  std::vector<std::pair<cryptonote::transaction, crypto::hash>> txes(total_txs);

#define SCAN_TABLE_QUIT(m) \
        do { \
            MERROR_VER(m) ;\
            m_scan_table.clear(); \
            return false; \
        } while(0); \

  // generate sorted tables for all amounts and absolute offsets
  size_t tx_index = 0, block_index = 0;
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (const auto &tx_blob : entry.txs)
    {
      if (tx_index >= txes.size())
        SCAN_TABLE_QUIT("tx_index is out of sync");
      transaction &tx = txes[tx_index].first;
      crypto::hash &tx_prefix_hash = txes[tx_index].second;
      ++tx_index;

      if (!parse_and_validate_tx_base_from_blob(tx_blob.blob, tx))
        SCAN_TABLE_QUIT("Could not parse tx from incoming blocks.");
      cryptonote::get_transaction_prefix_hash(tx, tx_prefix_hash);

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its != m_scan_table.end())
        SCAN_TABLE_QUIT("Duplicate tx found from incoming blocks.");

      m_scan_table.emplace(tx_prefix_hash, std::unordered_map<crypto::key_image, std::vector<output_data_t>>());
      its = m_scan_table.find(tx_prefix_hash);
      assert(its != m_scan_table.end());

      // get all amounts from tx.vin(s). Archival vins (bond-post,
      // serve-credit, reward-emission) carry no key image and no amount —
      // skip them, matching every other vin walk on the block path (an
      // unguarded std::get here threw bad_variant_access on the first
      // mined bond-post, surfaced by the PR-4b e2e).
      for (const auto &txin : tx.vin)
      {
        if (!std::holds_alternative<txin_to_key>(txin))
          continue;
        const txin_to_key &in_to_key = std::get<txin_to_key>(txin);

        // check for duplicate
        auto it = its->second.find(in_to_key.k_image);
        if (it != its->second.end())
          SCAN_TABLE_QUIT("Duplicate key_image found from incoming blocks.");

        amounts.push_back(in_to_key.amount);
      }

      // sort and remove duplicate amounts from amounts list
      std::sort(amounts.begin(), amounts.end());
      auto last = std::unique(amounts.begin(), amounts.end());
      amounts.erase(last, amounts.end());

      // add amount to the offset_map and tx_map
      for (const uint64_t &amount : amounts)
      {
        if (offset_map.find(amount) == offset_map.end())
          offset_map.emplace(amount, std::vector<uint64_t>());

        if (tx_map.find(amount) == tx_map.end())
          tx_map.emplace(amount, std::vector<output_data_t>());
      }

      // add new absolute_offsets to offset_map (same archival-vin skip as
      // the amounts walk above)
      for (const auto &txin : tx.vin)
      {
        if (!std::holds_alternative<txin_to_key>(txin))
          continue;
        const txin_to_key &in_to_key = std::get<txin_to_key>(txin);
        // no need to check for duplicate here.
        auto absolute_offsets = relative_output_offsets_to_absolute(in_to_key.key_offsets);
        for (const auto & offset : absolute_offsets)
          offset_map[in_to_key.amount].push_back(offset);

      }
    }
    ++block_index;
  }

  // sort and remove duplicate absolute_offsets in offset_map
  for (auto &offsets : offset_map)
  {
    std::sort(offsets.second.begin(), offsets.second.end());
    auto last = std::unique(offsets.second.begin(), offsets.second.end());
    offsets.second.erase(last, offsets.second.end());
  }

  // gather all the output keys
  threads = tpool.get_max_concurrency();
  if (!m_db->can_thread_bulk_indices())
    threads = 1;

  if (threads > 1 && amounts.size() > 1)
  {
    tools::threadpool::waiter waiter(tpool);

    for (size_t i = 0; i < amounts.size(); i++)
    {
      uint64_t amount = amounts[i];
      tpool.submit(&waiter, boost::bind(&Blockchain::output_scan_worker, this, amount, std::cref(offset_map[amount]), std::ref(tx_map[amount])), true);
    }
    if (!waiter.wait())
      return false;
  }
  else
  {
    for (size_t i = 0; i < amounts.size(); i++)
    {
      uint64_t amount = amounts[i];
      output_scan_worker(amount, offset_map[amount], tx_map[amount]);
    }
  }

  // now generate a table for each tx_prefix and k_image hashes
  tx_index = 0;
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (size_t i = 0; i < entry.txs.size(); ++i)
    {
      if (tx_index >= txes.size())
        SCAN_TABLE_QUIT("tx_index is out of sync");
      const transaction &tx = txes[tx_index].first;
      const crypto::hash &tx_prefix_hash = txes[tx_index].second;
      ++tx_index;

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its == m_scan_table.end())
        SCAN_TABLE_QUIT("Tx not found on scan table from incoming blocks.");

      // Same archival-vin skip as the collection walks above.
      for (const auto &txin : tx.vin)
      {
        if (!std::holds_alternative<txin_to_key>(txin))
          continue;
        const txin_to_key &in_to_key = std::get<txin_to_key>(txin);
        auto needed_offsets = relative_output_offsets_to_absolute(in_to_key.key_offsets);

        std::vector<output_data_t> outputs;
        for (const uint64_t & offset_needed : needed_offsets)
        {
          size_t pos = 0;
          bool found = false;

          for (const uint64_t &offset_found : offset_map[in_to_key.amount])
          {
            if (offset_needed == offset_found)
            {
              found = true;
              break;
            }

            ++pos;
          }

          if (found && pos < tx_map[in_to_key.amount].size())
            outputs.push_back(tx_map[in_to_key.amount].at(pos));
          else
            break;
        }

        its->second.emplace(in_to_key.k_image, outputs);
      }
    }
  }

  TIME_MEASURE_FINISH(scantable);
  if (total_txs > 0)
  {
    m_fake_scan_time = scantable / total_txs;
    if(m_show_time_stats)
      MDEBUG("Prepare scantable took: " << scantable << " ms");
  }

  return true;
}

void Blockchain::prepare_handle_incoming_block_no_preprocess(const size_t block_byte_estimate)
{
  // acquire locks
  m_tx_pool.lock();
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  // increment sync byte counter to trigger sync against database backing store
  // later in cleanup_handle_incoming_blocks()
  m_bytes_to_sync += block_byte_estimate;

  // spin until we start a batch
  while (!m_db->batch_start(1, block_byte_estimate)) {
    m_blockchain_lock.unlock();
    m_tx_pool.unlock();
    epee::misc_utils::sleep_no_w(1000);
    m_tx_pool.lock();
    m_blockchain_lock.lock();
  }
  m_batch_success = true;
}

void Blockchain::add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata &blob, const txpool_tx_meta_t &meta)
{
  m_db->add_txpool_tx(txid, blob, meta);
}

void Blockchain::update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta)
{
  m_db->update_txpool_tx(txid, meta);
}

void Blockchain::remove_txpool_tx(const crypto::hash &txid)
{
  m_db->remove_txpool_tx(txid);
}

uint64_t Blockchain::get_txpool_tx_count(bool include_sensitive) const
{
  return m_db->get_txpool_tx_count(include_sensitive ? relay_category::all : relay_category::broadcasted);
}

bool Blockchain::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const
{
  return m_db->get_txpool_tx_meta(txid, meta);
}

bool Blockchain::get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, bd, tx_category);
}

cryptonote::blobdata Blockchain::get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, tx_category);
}

bool Blockchain::for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f, bool include_blob, relay_category tx_category) const
{
  return m_db->for_all_txpool_txes(f, include_blob, tx_category);
}

bool Blockchain::txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category)
{
  return m_db->txpool_tx_matches_category(tx_hash, category);
}

void Blockchain::set_user_options(uint64_t maxthreads, bool sync_on_blocks, uint64_t sync_threshold, blockchain_db_sync_mode sync_mode)
{
  if (sync_mode == db_defaultsync)
  {
    m_db_default_sync = true;
    sync_mode = db_async;
  }
  m_db_sync_mode = sync_mode;
  m_db_sync_on_blocks = sync_on_blocks;
  m_db_sync_threshold = sync_threshold;
  m_max_prepare_blocks_threads = maxthreads;
}

void Blockchain::set_txpool_notify(TxpoolNotifyCallback&& notify)
{
  std::lock_guard<decltype(m_txpool_notifier_mutex)> lg(m_txpool_notifier_mutex);
  m_txpool_notifier = notify;
}

void Blockchain::add_block_notify(BlockNotifyCallback&& notify)
{
  if (notify)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);
    m_block_notifiers.push_back(std::move(notify));
  }
}

void Blockchain::add_miner_notify(MinerNotifyCallback&& notify)
{
  if (notify)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);
    m_miner_notifiers.push_back(std::move(notify));
  }
}

void Blockchain::notify_txpool_event(std::vector<txpool_event>&& event) const
{
  std::lock_guard<decltype(m_txpool_notifier_mutex)> lg(m_txpool_notifier_mutex);
  if (m_txpool_notifier)
  {
    try
    {
      m_txpool_notifier(std::move(event));
    }
    catch (const std::exception &e)
    {
      MDEBUG("During Blockchain::notify_txpool_event(), ignored exception: " << e.what());
    }
  }
}

void Blockchain::safesyncmode(const bool onoff)
{
  /* all of this is no-op'd if the user set a specific
   * --db-sync-mode at startup.
   */
  if (m_db_default_sync)
  {
    m_db->safesyncmode(onoff);
    m_db_sync_mode = onoff ? db_nosync : db_async;
  }
}

HardFork::State Blockchain::get_hard_fork_state() const
{
  return m_hardfork->get_state();
}

bool Blockchain::get_hard_fork_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  return m_hardfork->get_voting_info(version, window, votes, threshold, earliest_height, voting);
}

uint64_t Blockchain::get_difficulty_target() const
{
  return SHEKYL_DAA_TARGET_SECONDS;
}

std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> Blockchain:: get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const
{
  return m_db->get_output_histogram(amounts, unlocked, recent_cutoff, min_count);
}

std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> Blockchain::get_alternative_chains() const
{
  std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> chains;

  blocks_ext_by_hash alt_blocks;
  alt_blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&alt_blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref *blob) {
    if (!blob)
    {
      MERROR("No blob, but blobs were requested");
      return false;
    }
    cryptonote::block bl;
    block_extended_info bei;
    if (cryptonote::parse_and_validate_block_from_blob(*blob, bei.bl))
    {
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cumulative_difficulty = data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      alt_blocks.insert(std::make_pair(cryptonote::get_block_hash(bei.bl), std::move(bei)));
    }
    else
      MERROR("Failed to parse block from blob");
    return true;
  }, true);

  for (const auto &i: alt_blocks)
  {
    const crypto::hash top = cryptonote::get_block_hash(i.second.bl);
    bool found = false;
    for (const auto &j: alt_blocks)
    {
      if (j.second.bl.prev_id == top)
      {
        found = true;
        break;
      }
    }
    if (!found)
    {
      std::vector<crypto::hash> chain;
      auto h = i.second.bl.prev_id;
      chain.push_back(top);
      blocks_ext_by_hash::const_iterator prev;
      while ((prev = alt_blocks.find(h)) != alt_blocks.end())
      {
        chain.push_back(h);
        h = prev->second.bl.prev_id;
      }
      chains.push_back(std::make_pair(i.second, chain));
    }
  }
  return chains;
}

void Blockchain::cancel()
{
  m_cancel = true;
}

void Blockchain::lock()
{
  m_blockchain_lock.lock();
}

void Blockchain::unlock()
{
  m_blockchain_lock.unlock();
}

bool Blockchain::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const
{
  return m_db->for_all_key_images(f);
}

bool Blockchain::for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const block&)> f) const
{
  return m_db->for_blocks_range(h1, h2, f);
}

bool Blockchain::for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f, bool pruned) const
{
  return m_db->for_all_transactions(f, pruned);
}

bool Blockchain::for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const
{
  return m_db->for_all_outputs(f);
}

bool Blockchain::for_all_outputs(uint64_t amount, std::function<bool(uint64_t height)> f) const
{
  return m_db->for_all_outputs(amount, f);
}

void Blockchain::invalidate_block_template_cache()
{
  MDEBUG("Invalidating block template cache");
  m_btc_valid = false;
}

void Blockchain::cache_block_template(const block &b, const cryptonote::account_public_address &address, const blobdata &nonce, const difficulty_type &diff, uint64_t height, uint64_t expected_reward, uint64_t seed_height, const crypto::hash &seed_hash, uint64_t pool_cookie)
{
  MDEBUG("Setting block template cache");
  m_btc = b;
  m_btc_address = address;
  m_btc_nonce = nonce;
  m_btc_difficulty = diff;
  m_btc_height = height;
  m_btc_expected_reward = expected_reward;
  m_btc_seed_hash = seed_hash;
  m_btc_seed_height = seed_height;
  m_btc_pool_cookie = pool_cookie;
  m_btc_valid = true;
}

void Blockchain::send_miner_notifications(uint64_t height, const crypto::hash &seed_hash, const crypto::hash &prev_id, uint64_t already_generated_coins)
{
  if (m_miner_notifiers.empty())
    return;

  const uint8_t major_version = m_hardfork->get_ideal_version(height);
  const difficulty_type diff = get_difficulty_for_next_block();
  const uint64_t median_weight = m_current_block_cumul_weight_median;

  std::vector<tx_block_template_backlog_entry> tx_backlog;
  m_tx_pool.get_block_template_backlog(tx_backlog);

  for (const auto& notifier : m_miner_notifiers)
  {
    notifier(major_version, height, prev_id, seed_hash, diff, median_weight, already_generated_coins, tx_backlog);
  }
}

namespace cryptonote {
template bool Blockchain::get_transactions(const std::vector<crypto::hash>&, std::vector<transaction>&, std::vector<crypto::hash>&, bool) const;
}
