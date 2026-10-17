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

#include <sstream>
#include <numeric>
#include "misc_language.h"
#include "syncobj.h"
#include "cryptonote_basic_impl.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/util.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "miner"

#define AUTODETECT_WINDOW 10 // seconds
#define AUTODETECT_GAIN_THRESHOLD 1.02f  // 2%

using namespace epee;

#include "miner.h"
#include "crypto/hash.h"
#include "cryptonote_basic/block_ingest.h"

namespace cryptonote
{

  namespace
  {
  }


  miner::miner(i_miner_handler* phandler, const get_block_hash_t &gbh):m_stop(1),
    m_template{},
    m_template_no(0),
    m_diffic(0),
    m_thread_index(0),
    m_phandler(phandler),
    m_gbh(gbh),
    m_height(0),
    m_threads_active(0),
    m_pausers_count(0),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_total_hashes(0),
    m_do_print_hashrate(false),
    m_do_mining(false),
    m_current_hash_rate(0),
    m_block_reward(0)
  {
    m_attrs.set_stack_size(THREAD_STACK_SIZE);
  }
  //-----------------------------------------------------------------------------------------------------
  miner::~miner()
  {
    try { stop(); }
    catch (...) { /* ignore */ }
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const block& bl, const difficulty_type& di, uint64_t height, uint64_t block_reward)
  {
    CRITICAL_REGION_LOCAL(m_template_lock);
    m_template = bl;
    m_diffic = di;
    m_height = height;
    m_block_reward = block_reward;
    ++m_template_no;
    m_starter_nonce = crypto::rand<uint32_t>();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update()
  {
    if(!is_mining())
      return true;

    return request_block_template();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template()
  {
    block bl;
    difficulty_type di = AUTO_VAL_INIT(di);
    uint64_t height = AUTO_VAL_INIT(height);
    uint64_t expected_reward; //only used for RPC calls - could possibly be useful here too?

    uint64_t seed_height;
    crypto::hash seed_hash;
    // The built-in miner varies only the header nonce; the coinbase nonce is
    // the daemon's zero fill. (The --extra-messages-file rotation that once
    // fed it is gone: arbitrary miner-chosen bytes with no mining purpose.)
    if(!m_phandler->get_block_template(bl, m_mine_address, di, height, expected_reward, blobdata(), seed_height, seed_hash))
    {
      LOG_ERROR("Failed to get_block_template(), stopping mining");
      return false;
    }
    set_block_template(bl, di, height, expected_reward);
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_idle()
  {
    m_update_block_template_interval.do_call([&](){
      if(is_mining())request_block_template();
      return true;
    });

    m_update_merge_hr_interval.do_call([&](){
      merge_hr();
      return true;
    });

    m_autodetect_interval.do_call([&](){
      update_autodetection();
      return true;
    });

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::do_print_hashrate(bool do_hr)
  {
    m_do_print_hashrate = do_hr;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::merge_hr()
  {
    if(m_last_hr_merge_time && is_mining())
    {
      m_current_hash_rate = m_hashes * 1000 / ((misc_utils::get_tick_count() - m_last_hr_merge_time + 1));
      CRITICAL_REGION_LOCAL(m_last_hash_rates_lock);
      m_last_hash_rates.push_back(m_current_hash_rate);
      if(m_last_hash_rates.size() > 19)
        m_last_hash_rates.pop_front();
      if(m_do_print_hashrate)
      {
        uint64_t total_hr = std::accumulate(m_last_hash_rates.begin(), m_last_hash_rates.end(), 0);
        float hr = static_cast<float>(total_hr)/static_cast<float>(m_last_hash_rates.size());
        const auto flags = std::cout.flags();
        const auto precision = std::cout.precision();
        std::cout << "hashrate: " << std::setprecision(4) << std::fixed << hr << std::setiosflags(flags) << std::setprecision(precision) << ENDL;
      }
    }
    m_last_hr_merge_time = misc_utils::get_tick_count();
    m_hashes = 0;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::update_autodetection()
  {
    if (m_threads_autodetect.empty())
      return;

    uint64_t now = epee::misc_utils::get_ns_count();
    uint64_t dt = now - m_threads_autodetect.back().first;
    if (dt < AUTODETECT_WINDOW * 1000000000ull)
      return;

    // work out how many more hashes we got
    m_threads_autodetect.back().first = dt;
    uint64_t dh = m_total_hashes - m_threads_autodetect.back().second;
    m_threads_autodetect.back().second = dh;
    float hs = dh / (dt / (float)1000000000);
    MGINFO("Mining autodetection: " << m_threads_autodetect.size() << " threads: " << hs << " H/s");

    // when we don't increase by at least 2%, stop, otherwise check next
    // if N and N+1 have mostly the same hash rate, we want to "lighter" one
    bool found = false;
    if (m_threads_autodetect.size() > 1)
    {
      int previdx = m_threads_autodetect.size() - 2;
      float previous_hs = m_threads_autodetect[previdx].second / (m_threads_autodetect[previdx].first / (float)1000000000);
      if (previous_hs > 0 && hs / previous_hs < AUTODETECT_GAIN_THRESHOLD)
      {
        m_threads_total = m_threads_autodetect.size() - 1;
        m_threads_autodetect.clear();
        MGINFO("Optimal number of threads seems to be " << m_threads_total);
        found = true;
      }
    }

    if (!found)
    {
      // setup one more thread
      m_threads_autodetect.push_back({now, m_total_hashes});
      m_threads_total = m_threads_autodetect.size();
    }

    // restart all threads
    {
      CRITICAL_REGION_LOCAL(m_threads_lock);
      m_stop = true;
      while (m_threads_active > 0)
        misc_utils::sleep_no_w(100);
      m_threads.clear();
    }
    m_stop = false;
    m_thread_index = 0;
    for(size_t i = 0; i != m_threads_total; i++)
      m_threads.push_back(boost::thread(m_attrs, boost::bind(&miner::worker_thread, this)));
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::init(const ShekylDaemonSnapshot& snapshot, network_type /*nettype*/)
  {
    // The two mining rows (DAEMON_CONFIG_CUTOVER.md §2.9). The address was
    // decoded when the configuration was built and checked against the
    // network there. This assembles the account key from those bytes and
    // does not parse the text. A failure is that decode and this assembler
    // disagreeing. The thread count is passed through: 0 is auto, and
    // miner::start chooses the count.
    if (snapshot.mine_address != nullptr)
    {
      const ShekylMineAddress& mined = *snapshot.mine_address;
      address_parse_info info;
      const char* text = mined.text != nullptr ? mined.text : "";
      if (mined.text == nullptr
          || !cryptonote::account_public_address_from_decoded(
               info, mined.spend, mined.view, mined.ml_kem, mined.ml_kem_len))
      {
        LOG_ERROR("The mining address " << text
            << " decoded when the configuration was built, and the daemon's address assembler disagreed; starting daemon canceled");
        return false;
      }
      m_mine_address = info.address;
      m_mine_address_str = text;
      m_threads_total = snapshot.mine_threads;
      m_do_mining = true;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::is_mining() const
  {
    return !m_stop;
  }
  //-----------------------------------------------------------------------------------------------------
  const account_public_address& miner::get_mining_address() const
  {
    return m_mine_address;
  }
  //-----------------------------------------------------------------------------------------------------
  const std::string& miner::get_mining_address_str() const
  {
    return m_mine_address_str;
  }
  //-----------------------------------------------------------------------------------------------------
  uint32_t miner::get_threads_count() const {
    return m_threads_total;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::start(const account_public_address& adr, const std::string& adr_str, size_t threads_count)
  {
    m_block_reward = 0;
    m_mine_address = adr;
    m_mine_address_str = adr_str;
    m_threads_total = static_cast<uint32_t>(threads_count);
    if (threads_count == 0)
    {
      m_threads_autodetect.clear();
      m_threads_autodetect.push_back({epee::misc_utils::get_ns_count(), m_total_hashes});
      m_threads_total = 1;
    }
    m_starter_nonce = crypto::rand<uint32_t>();
    CRITICAL_REGION_LOCAL(m_threads_lock);
    if(is_mining())
    {
      LOG_ERROR("Starting miner but it's already started");
      return false;
    }

    if(!m_threads.empty())
    {
      LOG_ERROR("Unable to start miner because there are active mining threads");
      return false;
    }

    request_block_template();//lets update block template

    m_stop = false;
    m_thread_index = 0;
    
    for(size_t i = 0; i != m_threads_total; i++)
    {
      m_threads.push_back(boost::thread(m_attrs, boost::bind(&miner::worker_thread, this)));
    }

    if (threads_count == 0)
      MINFO("Mining has started, autodetecting optimal number of threads, good luck!" );
    else
      MINFO("Mining has started with " << threads_count << " threads, good luck!" );

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_speed() const
  {
    if(is_mining()) {
      return m_current_hash_rate;
    }
    else {
      return 0;
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::send_stop_signal()
  {
    m_stop = true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::stop()
  {
    MTRACE("Miner has received stop signal");

    CRITICAL_REGION_LOCAL(m_threads_lock);
    bool mining = !m_threads.empty();
    if (!mining)
    {
      MTRACE("Not mining - nothing to stop" );
      return true;
    }

    send_stop_signal();

    while (m_threads_active > 0)
      misc_utils::sleep_no_w(100);

    MINFO("Mining has been stopped, " << m_threads.size() << " finished" );
    m_threads.clear();
    m_threads_autodetect.clear();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::find_nonce_for_given_block(const get_block_hash_t &gbh, block& bl, const difficulty_type& diffic, uint64_t height, const crypto::hash *seed_hash)
  {
    for(; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++)
    {
      crypto::hash h;
      gbh(bl, height, seed_hash, h);

      if(check_hash(h, diffic))
      {
        bl.invalidate_hashes();
        return true;
      }
    }
    bl.invalidate_hashes();
    return false;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::on_synchronized()
  {
    if(m_do_mining)
    {
      start(m_mine_address, m_mine_address_str, m_threads_total);
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::pause()
  {
    CRITICAL_REGION_LOCAL(m_miners_count_lock);
    MDEBUG("miner::pause: " << m_pausers_count << " -> " << (m_pausers_count + 1));
    ++m_pausers_count;
    if(m_pausers_count == 1 && is_mining())
      MDEBUG("MINING PAUSED");
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::resume()
  {
    CRITICAL_REGION_LOCAL(m_miners_count_lock);
    MDEBUG("miner::resume: " << m_pausers_count << " -> " << (m_pausers_count - 1));
    --m_pausers_count;
    if(m_pausers_count < 0)
    {
      m_pausers_count = 0;
      MERROR("Unexpected miner::resume() called");
    }
    if(!m_pausers_count && is_mining())
      MDEBUG("MINING RESUMED");
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::worker_thread()
  {
    const uint32_t th_local_index = m_thread_index++; // atomically increment, getting value before increment

    MLOG_SET_THREAD_NAME(std::string("[miner ") + std::to_string(th_local_index) + "]");
    MGINFO("Miner thread was started ["<< th_local_index << "]");
    uint32_t nonce = m_starter_nonce + th_local_index;
    uint64_t height = 0;
    difficulty_type local_diff = 0;
    uint32_t local_template_ver = 0;
    block b;
    ++m_threads_active;
    while(!m_stop)
    {
      if(m_pausers_count)//anti split workaround
      {
        misc_utils::sleep_no_w(100);
        continue;
      }

      if(local_template_ver != m_template_no)
      {
        CRITICAL_REGION_BEGIN(m_template_lock);
        b = m_template;
        local_diff = m_diffic;
        height = m_height;
        CRITICAL_REGION_END();
        local_template_ver = m_template_no;
        nonce = m_starter_nonce + th_local_index;
      }

      if(!local_template_ver)//no any set_block_template call
      {
        LOG_PRINT_L2("Block template not set yet");
        epee::misc_utils::sleep_no_w(1000);
        continue;
      }

      b.nonce = nonce;
      crypto::hash h;

      m_gbh(b, height, NULL, h);

      if(check_hash(h, local_diff))
      {
        //we lucky!
        MGINFO_GREEN("Found block " << get_block_hash(b) << " at height " << height << " for difficulty: " << local_diff);
        cryptonote::block_verification_context bvc;
        m_phandler->handle_block_found(b, bvc);
      }
      nonce+=m_threads_total;
      ++m_hashes;
      ++m_total_hashes;
    }
    MGINFO("Miner thread stopped ["<< th_local_index << "]");
    --m_threads_active;
    return true;
  }
}
