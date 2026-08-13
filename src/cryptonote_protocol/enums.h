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
    stem,     //!< Received/send over network using Dandelion++ stem
    fluff,    //!< Received/sent over network using Dandelion++ fluff
    block     //!< Received in block, takes precedence over others
  };

  /* `forward` was here, between `local` and `stem`, and Q12-U2 deleted it.
     It meant "arrived over i2p/tor; hold on a timer, then broadcast to
     clearnet" — that is, PROVENANCE used as a routing input, and it threw away
     which anonymity network the transaction came from in the process. Q12-D3
     rules provenance is not a routing input, so the class had nothing left to
     express: an arrival is stemmed whatever transport carried it, and the fact
     of where it came from is recorded in `txpool_tx_meta_t::origin_zone`
     (Q12-U1) where a fact belongs. Folding the fact into the decision is what
     made the zone unrecoverable.

     The enum's numeric values are NOT persisted and NOT on the wire — the
     txpool encodes the method as independent bits and no RPC or levin surface
     exposes the integer — so removing a middle value renumbers nothing that
     outlives the process. The ordering the values DO carry is
     `upgrade_relay_method`'s monotonicity, whose `static_assert`s moved with
     the deletion. */

  /*! \brief Pre-fluff relay methods for R-1 (stem / local).

      Fluff is the deliberate exit from the anonymity zone: once a transaction
      fluffs it must leave, or coherence would strand it in the anonymity
      subgraph (§59.1). Extracted so the production branch and its unit
      witness share one predicate — the suite cannot drive a full
      `handle_notify_new_transactions` arrival on a non-public context yet
      (FOLLOWUPS / §89.7), but it can pin this gate. */
  constexpr bool is_pre_fluff_relay(const relay_method method) noexcept
  {
    return method == relay_method::stem
        || method == relay_method::local;
  }

  /*! \brief Originated traffic on an anonymity zone keeps its `local` txpool
      record, whatever the transport did with it.

      §30.5 forbids the backstop falling out to the public zone: re-broadcasting
      our own transaction from the origin's own IP is the first-spy case this
      arc exists to prevent. `local` is the class that prevents it —
      `relay_txpool_transactions` routes `local` to `private_req` at
      `zone::invalid`, which `select_anonymity(require_usable=false)` resolves
      back to the anonymity zone and never to clearnet, so originated traffic
      fails closed (§59.7). Every other class routes to `public_req`.

      This matters because `upgrade_relay_method` is monotone: one record of
      `stem` or `fluff` moves the entry out of `local` permanently, and the next
      pool re-relay puts the user's own transaction on the clear internet.

      Relayed traffic is excluded deliberately, not by oversight. It records
      `stem` so the per-zone embargo is drawn (§89.2), and clearnet was always
      that traffic's home — the roll is eligibility, not a drop commitment
      (§59.7). Clearnet origins are excluded too: `local` on the public zone has
      always recorded `stem`, and its home *is* clearnet. */
  constexpr bool originated_stays_in_zone(
    const relay_method tx_relay,
    const epee::net_utils::zone nzone) noexcept
  {
    return tx_relay == relay_method::local
        && nzone != epee::net_utils::zone::public_
        && nzone != epee::net_utils::zone::invalid;
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

  /*! \brief Where `node_server::send_txs` should place a transaction under
      Q12-D5a once-at-origin.

      Production and the unit table call this. Deleting `keep_arrival` here
      is the edit that reds the coherence witness — not a copy of the
      branch in `net_node.inl`. */
  enum class zone_route : std::uint8_t
  {
    keep_arrival,          //!< still-stemming on a real anonymity origin
    anonymity_fail_closed, //!< originated chose anon, or local re-relay backstop
    public_clearnet        //!< clearnet inherit, fluff exit, or originated chose clearnet
  };

  constexpr zone_route once_at_origin_route(
    const relay_method tx_relay,
    const epee::net_utils::zone origin) noexcept
  {
    if (r1_coherence_keeps_origin(tx_relay, origin))
      return zone_route::keep_arrival;
    if (origin == epee::net_utils::zone::invalid && is_pre_fluff_relay(tx_relay))
      return zone_route::anonymity_fail_closed;
    return zone_route::public_clearnet;
  }

  /*! \brief Map the origination roll onto the zone argument `send_txs` reads.

      `true` (take anonymity) → `invalid`, which `once_at_origin_route` treats
      as fail-closed. `false` (clearnet **by design**) → `public_`.

      These two must stay distinguishable from "chose anon, zone unusable":
      that path never produces a `public_` origin argument, it sends nothing.
      Pool re-relays of `local` keep passing `invalid` and do **not** re-roll
      — they share this mapping's fail-closed arm, which is why the roll
      lives at first origination (`daemon_submit::relay_tx`) rather than on
      every `source.is_nil()` call into `send_txs`. */
  constexpr epee::net_utils::zone originated_zone_from_anonymity_roll(
    const bool take_anonymity) noexcept
  {
    return take_anonymity
      ? epee::net_utils::zone::invalid
      : epee::net_utils::zone::public_;
  }
}
