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

#include <cassert>
#include <limits>

#include "cryptonote_basic/cryptonote_basic.h"
#include "blockchain_db/blockchain_db.h"
#include "hardfork.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "hardfork"

using namespace cryptonote;

HardFork::HardFork(cryptonote::BlockchainDB &db, uint8_t original_version, time_t forked_time, time_t update_time):
  db(db),
  forked_time(forked_time),
  update_time(update_time),
  original_version(original_version)
{
}

bool HardFork::add_fork(uint8_t version, uint64_t height, time_t time)
{
  CRITICAL_REGION_LOCAL(lock);

  if (version == 0)
    return false;
  if (!heights.empty()) {
    if (version <= heights.back().version)
      return false;
    if (height <= heights.back().height)
      return false;
    if (time <= heights.back().time)
      return false;
  }
  heights.push_back(hardfork_t(version, height, time));
  return true;
}

void HardFork::init()
{
  CRITICAL_REGION_LOCAL(lock);

  if (heights.empty())
    heights.push_back(hardfork_t(original_version, 0, 0));
}

uint8_t HardFork::version_at_height(uint64_t height) const
{
  for (size_t n = heights.size(); n-- > 1; ) {
    if (height >= heights[n].height)
      return heights[n].version;
  }
  return original_version;
}

bool HardFork::accepts_header(uint8_t major_version, uint8_t minor_version, uint64_t height) const
{
  // CEN-B1: the major version is the one the height schedule names.
  if (major_version != version_at_height(height))
    return false;
  // CEN-B2: the minor version is reserved. It is not a vote.
  if (minor_version != CURRENT_BLOCK_MINOR_VERSION)
    return false;
  return true;
}

bool HardFork::check(const cryptonote::block &block) const
{
  CRITICAL_REGION_LOCAL(lock);
  return accepts_header(block.major_version, block.minor_version, db.height());
}

bool HardFork::check_for_height(const cryptonote::block &block, uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  return accepts_header(block.major_version, block.minor_version, height);
}

bool HardFork::add(const cryptonote::block &block, uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);
  if (!accepts_header(block.major_version, block.minor_version, height))
    return false;

  db.set_hard_fork_version(height, version_at_height(height));
  return true;
}

HardFork::State HardFork::get_state(time_t t) const
{
  CRITICAL_REGION_LOCAL(lock);

  // no hard forks setup yet
  if (heights.size() <= 1)
    return Ready;

  time_t t_last_fork = heights.back().time;
  if (t >= t_last_fork + forked_time)
    return LikelyForked;
  if (t >= t_last_fork + update_time)
    return UpdateNeeded;
  return Ready;
}

HardFork::State HardFork::get_state() const
{
  return get_state(time(NULL));
}

uint8_t HardFork::get(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  if (height > db.height()) {
    assert(false);
    return 255;
  }
  if (height == db.height())
    return version_at_height(height);
  return db.get_hard_fork_version(height);
}

uint8_t HardFork::get_ideal_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  if (heights.empty())
    return original_version;
  return heights.back().version;
}

uint8_t HardFork::get_ideal_version(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  return version_at_height(height);
}

uint64_t HardFork::get_earliest_ideal_height_for_version(uint8_t version) const
{
  uint64_t height = std::numeric_limits<uint64_t>::max();
  for (auto i = heights.rbegin(); i != heights.rend(); ++i) {
    if (i->version >= version) {
      height = i->height;
    } else {
      break;
    }
  }
  return height;
}

uint8_t HardFork::get_next_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  uint64_t height = db.height();
  for (auto i = heights.rbegin(); i != heights.rend(); ++i) {
    if (height >= i->height) {
      return (i == heights.rbegin() ? i : (i - 1))->version;
    }
  }
  return original_version;
}

uint8_t HardFork::get_current_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  return version_at_height(db.height());
}

bool HardFork::get_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  CRITICAL_REGION_LOCAL(lock);

  const uint8_t current_version = version_at_height(db.height());
  const bool enabled = current_version >= version;
  window = 0;
  votes = 0;
  threshold = 0;
  earliest_height = get_earliest_ideal_height_for_version(version);
  voting = heights.empty() ? original_version : heights.back().version;
  return enabled;
}
