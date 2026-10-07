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

#pragma once

#include <vector>

#include "syncobj.h"
#include "hardforks/hardforks.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{
  class BlockchainDB;

  /**
   * Height schedule for the block major version.
   *
   * A header is admitted when its major version is the version this height
   * names (CEN-B1) and its minor version is the reserved constant (CEN-B2).
   * The minor byte is not a vote. There is no window and no threshold.
   * `get_state` is an operator hint from the last scheduled fork's timestamp,
   * not a consensus input.
   *
   * The class and the table itself are removed in the PR named in
   * `docs/FOLLOWUPS.md` ("Delete the hard-fork mechanism").
   */
  class HardFork
  {
  public:
    typedef enum {
      LikelyForked,
      UpdateNeeded,
      Ready,
    } State;

    static const time_t DEFAULT_FORKED_TIME = 31557600; // a year in seconds
    static const time_t DEFAULT_UPDATE_TIME = 31557600 / 2;

    /**
     * @param original_version the version a height takes when no later table row covers it
     * @param forked_time seconds after the last scheduled fork before `get_state` reports LikelyForked
     * @param update_time seconds after the last scheduled fork before `get_state` reports UpdateNeeded
     */
    HardFork(cryptonote::BlockchainDB &db, uint8_t original_version = 1, time_t forked_time = DEFAULT_FORKED_TIME, time_t update_time = DEFAULT_UPDATE_TIME);

    /**
     * @brief append one scheduled version
     *
     * Rows must arrive in increasing version, height and time.
     * Version 0 is refused. Returns false on a refusal, true when the row is stored.
     */
    bool add_fork(uint8_t version, uint64_t height, time_t time);

    /**
     * @brief finish registration
     *
     * An empty table receives one placeholder row at `original_version`.
     * The version at a height is computed from the table, so nothing is read
     * back from the chain.
     */
    void init();

    /**
     * @brief CEN-B1 and CEN-B2 at the chain height
     *
     * Called before the block is stored, when `db.height()` is the block's height.
     */
    bool check(const cryptonote::block &block) const;

    /**
     * @brief CEN-B1 and CEN-B2 at an explicit height
     *
     * The alternative-chain path validates a block that is not the chain tip.
     */
    bool check_for_height(const cryptonote::block &block, uint64_t height) const;

    /**
     * @brief record the scheduled version at `height` when the header is admitted
     *
     * `height` is the block's own height. The store calls this after the block
     * is written, so `db.height()` may already be one past `height`.
     * Returns false when the header is not admitted. The version recorded is
     * the schedule's, which the predicate has just required the major byte to equal.
     */
    bool add(const cryptonote::block &block, uint64_t height);

    /**
     * @brief operator hint from the last scheduled fork's timestamp
     */
    State get_state(time_t t) const;
    State get_state() const;

    /**
     * @brief version recorded for a stored height, or the schedule at the chain height
     *
     * `height == db.height()` has no stored row yet and answers
     * `version_at_height`. A height above the chain is a caller bug and returns 255.
     */
    uint8_t get(uint64_t height) const;

    /**
     * @brief the newest scheduled version
     */
    uint8_t get_ideal_version() const;

    /**
     * @brief the version the schedule names at `height`
     */
    uint8_t get_ideal_version(uint64_t height) const;

    /**
     * @brief the next scheduled version at the chain height, or the current one when none follows
     */
    uint8_t get_next_version() const;

    /**
     * @brief the version the schedule names at the chain height
     *
     * This is the version the next block must carry.
     */
    uint8_t get_current_version() const;

    /**
     * @brief earliest height at which `version` is scheduled, or the uint64 maximum when it never is
     */
    uint64_t get_earliest_ideal_height_for_version(uint8_t version) const;

    /**
     * @brief schedule facts for the hard_fork_info projection
     *
     * There is no vote. `window`, `votes` and `threshold` are written as 0.
     * Returns whether the schedule at the chain height has reached `version`.
     * `voting` is the newest scheduled version. `earliest_height` is
     * `get_earliest_ideal_height_for_version`.
     */
    bool get_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const;

    const std::vector<hardfork_t>& get_hardforks() const { return heights; }

  private:
    /**
     * @brief version named at `height`
     *
     * The caller holds `lock`. Index 0 is not consulted: the walk starts at
     * the last row and stops before the first, and a height that matches no
     * later row takes `original_version`. A one-row table therefore names
     * `original_version` at every height. Shipped networks set both to 1.
     */
    uint8_t version_at_height(uint64_t height) const;

    /**
     * @brief CEN-B1 and CEN-B2
     *
     * The caller holds `lock`.
     */
    bool accepts_header(uint8_t major_version, uint8_t minor_version, uint64_t height) const;

    BlockchainDB &db;

    time_t forked_time;
    time_t update_time;
    uint8_t original_version;

    std::vector<hardfork_t> heights;

    mutable epee::critical_section lock;
  };

}  // namespace cryptonote
