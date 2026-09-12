// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "shekyl/relay_floor_ring.h"

#include <algorithm>
#include <vector>

#include "include_base_utils.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "common/perf_timer.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "rolling_median.h"
#include "shekyl/shekyl_ffi.h"
#include "shekyl/tx_volume_window.h"
#include "warnings.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "blockchain"

#define MERROR_VER(x) MCERROR("verify", x)

namespace shekyl {

bool RelayFloorRing::continues_at(uint64_t next_height) const
{
  CRITICAL_REGION_LOCAL(m_lock);
  return !m_entries.empty() && m_entries.back().height + 1 == next_height;
}

bool RelayFloorRing::floor_if_at(uint64_t height, uint64_t &floor) const
{
  CRITICAL_REGION_LOCAL(m_lock);
  if (m_entries.empty() || m_entries.back().height != height)
    return false;
  floor = m_entries.back().floor;
  return true;
}

void RelayFloorRing::reset(std::deque<RelayFloorEntry> entries)
{
  CRITICAL_REGION_LOCAL(m_lock);
  m_entries.swap(entries);
}

void RelayFloorRing::push(uint64_t height, uint64_t floor, size_t window)
{
  CRITICAL_REGION_LOCAL(m_lock);
  m_entries.push_back({height, floor});
  while (m_entries.size() > window)
    m_entries.pop_front();
}

bool RelayFloorRing::copy_floors_at(uint64_t tip, uint64_t *out, size_t cap, size_t &n) const
{
  CRITICAL_REGION_LOCAL(m_lock);
  if (m_entries.empty() || m_entries.back().height != tip || m_entries.size() > cap)
    return false;
  n = m_entries.size();
  size_t i = 0;
  for (const auto &e : m_entries)
    out[i++] = e.floor;
  return true;
}

std::vector<std::pair<uint64_t, uint64_t>> RelayFloorRing::snapshot() const
{
  CRITICAL_REGION_LOCAL(m_lock);
  std::vector<std::pair<uint64_t, uint64_t>> out;
  out.reserve(m_entries.size());
  for (const auto &e : m_entries)
    out.emplace_back(e.height, e.floor);
  return out;
}

} // namespace shekyl

namespace cryptonote {

uint64_t Blockchain::fee_correction_at(uint64_t db_height, uint64_t already_generated_coins) const
{
  return fee_correction_from(db_height, already_generated_coins, get_tx_volume_window(db_height));
}

uint64_t Blockchain::fee_correction_from(uint64_t height, uint64_t already_generated_coins,
    const shekyl::tx_volume_window& tx_volume) const
{
  const uint64_t genesis_ng_height = get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG);
  const uint64_t sigma = shekyl_calc_emission_share(
      height,
      genesis_ng_height,
      SHEKYL_STAKER_EMISSION_SHARE,
      SHEKYL_STAKER_EMISSION_DECAY,
      SHEKYL_BLOCKS_PER_YEAR);
  const uint64_t burn_pct = shekyl_calc_burn_pct(
      tx_volume.tx_count_sum,
      tx_volume.blocks,
      SHEKYL_TX_VOLUME_BASELINE,
      already_generated_coins,
      SHEKYL_EMISSION_CURVE_ASYMPTOTE,
      SHEKYL_BURN_BASE_RATE,
      SHEKYL_BURN_CAP);
  return shekyl_fee_correction(tx_volume.tx_count_sum, tx_volume.blocks, sigma, burn_pct);
}

bool Blockchain::relay_floor_at(uint64_t height, uint64_t long_term_median,
    uint64_t already_generated_coins, const shekyl::tx_volume_window& tx_volume,
    uint64_t& floor) const
{
  // M_r-neutral reward: M_r lives inside C. Weight-1 makes the penalty inert,
  // so R depends on already_generated_coins alone.
  uint64_t base_reward = 0;
  if (!get_block_reward(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, 1, already_generated_coins, base_reward,
      get_current_hard_fork_version()))
    return false;

  const uint64_t c = fee_correction_from(height, already_generated_coins, tx_volume);
  const int32_t rc = shekyl_relay_fee_floor(
      base_reward,
      long_term_median,
      CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
      DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT,
      c,
      &floor);
  CHECK_AND_ASSERT_THROW_MES(rc == 0,
      "shekyl_relay_fee_floor failed: rc=" << rc << " ("
      << (rc == -1 ? "null out-pointer"
                   : rc == -2 ? "scalars outside the floor's arithmetic domain"
                              : "unknown status")
      << "), height=" << height << " base_reward=" << base_reward
      << " M=" << long_term_median << " C=" << c);
  return true;
}

void Blockchain::rebuild_relay_floor_ring(uint64_t tip_height)
{
  PERF_TIMER(rebuild_relay_floor_ring);
  const uint64_t G = shekyl_relay_floor_lookback();
  const uint64_t W = SHEKYL_TX_VOLUME_WINDOW;
  CHECK_AND_ASSERT_THROW_MES(G + 1 <= shekyl::RelayFloorRing::kCapacity,
      "shekyl_relay_floor_lookback()+1 exceeds RelayFloorRing::kCapacity");

  std::deque<shekyl::RelayFloorEntry> ring;
  if (tip_height > 0)
  {
    const uint64_t oldest = tip_height > G ? tip_height - G : 0;

    const uint64_t scan_start = oldest > W ? oldest - W : 0;
    std::vector<uint64_t> prefix(static_cast<size_t>(tip_height - scan_start) + 1, 0);
    for (uint64_t h = scan_start; h < tip_height; ++h)
      prefix[h - scan_start + 1] = prefix[h - scan_start] + m_db->get_block_from_height(h).tx_hashes.size();
    const auto window_at = [&](uint64_t h) {
      const uint64_t start = h > W ? h - W : 0;
      shekyl::tx_volume_window w;
      w.blocks = h - start;
      w.tx_count_sum = prefix[h - scan_start] - prefix[start - scan_start];
      return w;
    };

    const uint64_t N = m_long_term_block_weights_window;
    epee::misc_utils::rolling_median_t<uint64_t> rm(static_cast<size_t>(N));
    const uint64_t seed_blocks = std::min<uint64_t>(N, oldest);
    if (seed_blocks > 0)
      for (const uint64_t w : m_db->get_long_term_block_weights(oldest - seed_blocks, static_cast<size_t>(seed_blocks)))
        rm.insert(w);

    for (uint64_t h = oldest; h <= tip_height; ++h)
    {
      if (h > oldest)
        rm.insert(m_db->get_block_long_term_weight(h - 1));
      const uint64_t long_term_median = rm.size() > 0
        ? std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, rm.median())
        : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
      const uint64_t already_generated_coins = h ? m_db->get_block_already_generated_coins(h - 1) : 0;

      uint64_t floor = 0;
      if (relay_floor_at(h, long_term_median, already_generated_coins, window_at(h), floor))
        ring.push_back({h, floor});
      else
        MERROR("relay floor ring: no block reward at height " << h << "; omitted from the window");
    }
  }

  m_relay_floor_ring.reset(std::move(ring));
}

void Blockchain::advance_relay_floor_ring(uint64_t tip_height)
{
  if (!m_relay_floor_ring.continues_at(tip_height))
  {
    rebuild_relay_floor_ring(tip_height);
    return;
  }

  const uint64_t already_generated_coins = tip_height ? m_db->get_block_already_generated_coins(tip_height - 1) : 0;
  uint64_t floor = 0;
  if (!relay_floor_at(tip_height, m_long_term_effective_median_block_weight, already_generated_coins,
      get_tx_volume_window(tip_height), floor))
  {
    MERROR("relay floor ring: no block reward at tip " << tip_height << "; ring not advanced");
    return;
  }

  m_relay_floor_ring.push(tip_height, floor, static_cast<size_t>(shekyl_relay_floor_lookback()) + 1);
}

std::vector<std::pair<uint64_t, uint64_t>> Blockchain::relay_floor_ring() const
{
  return m_relay_floor_ring.snapshot();
}

uint64_t Blockchain::get_current_fee_per_byte() const
{
  const uint64_t tip_height = m_db->height();
  uint64_t cached = 0;
  if (m_relay_floor_ring.floor_if_at(tip_height, cached))
    return cached;

  const uint64_t already_generated_coins = tip_height ? m_db->get_block_already_generated_coins(tip_height - 1) : 0;
  uint64_t floor = 0;
  if (!relay_floor_at(tip_height, m_long_term_effective_median_block_weight, already_generated_coins,
      get_tx_volume_window(tip_height), floor))
    return 0;
  return floor;
}

bool Blockchain::check_fee(size_t tx_weight, uint64_t fee) const
{
  const uint64_t tip_height = m_db->height();
  uint64_t floors[shekyl::RelayFloorRing::kCapacity];
  size_t n = 0;
  if (!m_relay_floor_ring.copy_floors_at(tip_height, floors, shekyl::RelayFloorRing::kCapacity, n))
  {
    MERROR("relay floor ring is not at the tip (" << tip_height << "); refusing admission");
    return false;
  }

  const int32_t rc = shekyl_relay_floor_admits(
      fee,
      tx_weight,
      get_fee_quantization_mask(),
      floors,
      n,
      shekyl_relay_admission_slack_bp());
  if (rc < 0)
  {
    MERROR("shekyl_relay_floor_admits rejected its arguments (rc=" << rc << ")");
    return false;
  }
  if (rc == 0)
  {
    MERROR_VER("transaction fee is not enough: " << print_money(fee) << ", floor window min "
        << print_money(*std::min_element(floors, floors + n)) << "/byte over " << tx_weight << " bytes");
    return false;
  }
  return true;
}

} // namespace cryptonote
