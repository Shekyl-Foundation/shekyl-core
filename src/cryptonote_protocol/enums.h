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

#pragma once

#include <cstdint>

#include "net/enums.h"

namespace cryptonote
{
  //! Methods tracking how a tx was received and relayed
  enum class relay_method : std::uint8_t
  {
    none = 0, //!< Received via RPC with `do_not_relay` set
    local,    //!< Received via RPC; trying to send over i2p/tor, etc.
    forward,  //!< Received over i2p/tor; timer delayed before ipv4/6 public broadcast
    stem,     //!< Received/send over network using Dandelion++ stem
    fluff,    //!< Received/sent over network using Dandelion++ fluff
    block     //!< Received in block, takes precedence over others
  };

  /*! \brief Pre-fluff relay methods for R-1 (stem / forward / local).

      Fluff is the deliberate exit from the anonymity zone: once a transaction
      fluffs it must leave, or coherence would strand it in the anonymity
      subgraph (§59.1). Extracted so the production branch and its unit
      witness share one predicate — the suite cannot drive a full
      `handle_notify_new_transactions` arrival on a non-public context yet
      (FOLLOWUPS / §89.7), but it can pin this gate. */
  constexpr bool is_pre_fluff_relay(const relay_method method) noexcept
  {
    return method == relay_method::stem
        || method == relay_method::forward
        || method == relay_method::local;
  }

  /*! \brief R-1 coherence: keep a still-stemming transaction on its arrival
      anonymity zone (no re-roll).

      True only when the method is pre-fluff **and** the arrival zone is a real
      anonymity network. Clearnet never coheres to itself via this path; invalid
      origin never coheres; fluff never coheres (liveness exit). The caller still
      checks that the zone is present in the local zone map before sending. */
  constexpr bool r1_coherence_keeps_origin(
    const relay_method tx_relay,
    const epee::net_utils::zone origin) noexcept
  {
    return is_pre_fluff_relay(tx_relay)
        && origin != epee::net_utils::zone::public_
        && origin != epee::net_utils::zone::invalid;
  }
}
