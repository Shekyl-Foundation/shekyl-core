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
#include "shekyl/shekyl_ffi.h"

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

  /* The once-at-origin decision family below FORWARDS to Rust
     (`shekyl-relay::zone_route`, rule 20): the semantics live beside every
     sibling relay decision and their governing parameter, and the tables that
     pin them run in that crate's own test suite. C++ keeps two things — the
     `zone_route` compile-time token (the seam guard `send_txs` requires), and
     these byte-contract asserts. Each side pins its OWN enums to the shared
     documented literals at compile time (Rust's pins are `const` asserts in
     `zone_route.rs`) -- neither compiler can observe the other, so the pair
     of pins is what makes a renumbering a compile error on the side that
     renumbered. The runtime witness that both pins describe the same wire is
     the `levin.cpp` gtest table, which crosses the real FFI. */
  static_assert(unsigned(relay_method::none) == 0 && unsigned(relay_method::local) == 1
             && unsigned(relay_method::stem) == 2 && unsigned(relay_method::fluff) == 3
             && unsigned(relay_method::block) == 4,
    "relay_method bytes are the FFI contract with shekyl-relay::zone_route");
  static_assert(unsigned(epee::net_utils::zone::invalid) == 0
             && unsigned(epee::net_utils::zone::public_) == 1
             && unsigned(epee::net_utils::zone::i2p) == 2
             && unsigned(epee::net_utils::zone::tor) == 3,
    "zone bytes are the FFI contract with shekyl-relay::zone_route");

  /*! \brief Pre-fluff relay methods for R-1 (stem / local).

      Fluff is the deliberate exit from the anonymity zone: once a transaction
      fluffs it must leave, or coherence would strand it in the anonymity
      subgraph (§59.1). Extracted so the production branch and its unit
      witness share one predicate — the suite cannot drive a full
      `handle_notify_new_transactions` arrival on a non-public context yet
      (FOLLOWUPS / §89.7), but it can pin this gate. */
  inline bool is_pre_fluff_relay(const relay_method method) noexcept
  {
    return shekyl_relay_zone_is_pre_fluff_relay(static_cast<std::uint8_t>(method));
  }

  /*! \brief Originated traffic on an anonymity zone keeps its `local` txpool
      record, whatever the transport did with it.

      §30.5 forbids the backstop falling out to the public zone: re-broadcasting
      our own transaction from the origin's own IP is the first-spy case this
      arc exists to prevent. `local` is the class that prevents it —
      `relay_txpool_transactions` routes `local` to `private_req` at
      `zone::invalid`, which `once_at_origin_route` maps to
      `anonymity_fail_closed` — take the zone, send nothing if unusable.
      Every other class routes to `public_req`.

      This matters because `upgrade_relay_method` is monotone: one record of
      `stem` or `fluff` moves the entry out of `local` permanently, and the next
      pool re-relay puts the user's own transaction on the clear internet.

      Relayed traffic is excluded deliberately, not by oversight. It records
      `stem` so the per-zone embargo is drawn (§89.2), and clearnet was always
      that traffic's home — the roll is eligibility, not a drop commitment
      (§59.7). Clearnet origins are excluded too: `local` on the public zone has
      always recorded `stem`, and its home *is* clearnet. */
  inline bool originated_stays_in_zone(
    const relay_method tx_relay,
    const epee::net_utils::zone nzone) noexcept
  {
    return shekyl_relay_zone_originated_stays_in_zone(
      static_cast<std::uint8_t>(tx_relay), static_cast<std::uint8_t>(nzone));
  }

  /*! \brief R-1 coherence: keep a still-stemming transaction on its arrival
      anonymity zone (no re-roll).

      True only when the method is pre-fluff **and** the arrival zone is a real
      anonymity network. Clearnet never coheres to itself via this path; invalid
      origin never coheres; fluff never coheres (liveness exit). The caller still
      checks that the zone is present in the local zone map before sending. */
  inline bool r1_coherence_keeps_origin(
    const relay_method tx_relay,
    const epee::net_utils::zone origin) noexcept
  {
    return shekyl_relay_zone_r1_coherence_keeps_origin(
      static_cast<std::uint8_t>(tx_relay), static_cast<std::uint8_t>(origin));
  }

  /*! \brief Where `node_server::send_txs` should place a transaction under
      Q12-D5a once-at-origin.

      A token only `once_at_origin_route` can construct. `send_txs` requires
      one to select a zone, so a caller that bypasses the helper is a
      compile error — same device as `f` refusing a timing parameter
      (`DAEMON_RELAY_PRIVACY.md` §77.4) and the depth table refusing an
      unpopulated tier (§83.3). Sharing the helper with the unit table is
      necessary and not sufficient; this is the liveness half the table
      cannot supply.

      What edit reds the table: return `decision::public_clearnet` from
      the `keep_arrival` arm. What edit fails to compile: constructing a
      `zone_route` anywhere except `once_at_origin_route`, or calling
      `send_txs` without one. */
  class zone_route
  {
  public:
    enum class decision : std::uint8_t
    {
      keep_arrival,          //!< still-stemming on a real anonymity origin
      anonymity_fail_closed, //!< originated chose anon, or local re-relay backstop
      public_clearnet        //!< clearnet inherit, fluff exit, or originated chose clearnet
    };

    constexpr decision get() const noexcept { return k_; }

    constexpr bool operator==(zone_route const& o) const noexcept { return k_ == o.k_; }
    constexpr bool operator!=(zone_route const& o) const noexcept { return k_ != o.k_; }

  private:
    decision k_;
    explicit constexpr zone_route(decision k) noexcept : k_(k) {}
    friend zone_route once_at_origin_route(
      const relay_method, const epee::net_utils::zone) noexcept;
  };

  inline zone_route once_at_origin_route(
    const relay_method tx_relay,
    const epee::net_utils::zone origin) noexcept
  {
    static_assert(unsigned(zone_route::decision::keep_arrival) == 0
               && unsigned(zone_route::decision::anonymity_fail_closed) == 1
               && unsigned(zone_route::decision::public_clearnet) == 2,
      "decision bytes are the FFI contract with shekyl-relay::zone_route");
    switch (shekyl_relay_zone_once_at_origin_route(
      static_cast<std::uint8_t>(tx_relay), static_cast<std::uint8_t>(origin)))
    {
      case 0: return zone_route(zone_route::decision::keep_arrival);
      case 2: return zone_route(zone_route::decision::public_clearnet);
      /* 1, and defensively anything else: fail closed — send nothing is the
         one default that cannot leak (§30.5). */
      default: return zone_route(zone_route::decision::anonymity_fail_closed);
    }
  }

}
