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
    local,    //!< Received via RPC; trying to send over Tor, etc.
    stem,     //!< Received/send over network using Dandelion++ stem
    fluff,    //!< Received/sent over network using Dandelion++ fluff
    block     //!< Received in block, takes precedence over others
  };

  /* `forward` was here, between `local` and `stem`, and Q12-U2 deleted it.
     It meant "arrived over Tor; hold on a timer, then broadcast to
     clearnet" — that is, PROVENANCE used as a routing input, and it threw away
     which anonymity network the transaction came from in the process. Q12-D3
     rules provenance is not a routing input, so the class had nothing left to
     express: an arrival is stemmed whatever transport carried it. The arrival
     zone is not stored on the pool record.

     The enum's numeric values are NOT persisted and NOT on the wire — the
     txpool encodes the method as independent bits and no RPC or levin surface
     exposes the integer — so removing a middle value renumbers nothing that
     outlives the process. The ordering the values DO carry is
     `upgrade_relay_method`'s monotonicity, whose `static_assert`s moved with
     the deletion. */

  /* Relay-method bytes are the FFI contract with `shekyl-relay::zone`
     (`origin_keeps_local_record` and the `RelayMethod` pins beside it).
     NetZone bytes below are the contract with `shekyl_types::relay::NetZone`.
     Neither compiler observes the other, so each side pins its own literals.
     The runtime witness is the relay-zone FFI test that crosses
     `shekyl_relay_zone_origin_keeps_local_record`. */
  static_assert(unsigned(relay_method::none) == 0 && unsigned(relay_method::local) == 1
             && unsigned(relay_method::stem) == 2 && unsigned(relay_method::fluff) == 3
             && unsigned(relay_method::block) == 4,
    "relay_method bytes are the FFI contract with shekyl-relay::zone");
  /* Bytes of `shekyl_types::relay::NetZone`. Not connector ids: clearnet's
     connector is 0, and this public byte is 1. Tor stays 3. Discriminant 2
     is not a value. */
  inline constexpr std::uint8_t netzone_invalid = 0;
  inline constexpr std::uint8_t netzone_public = 1;
  inline constexpr std::uint8_t netzone_tor = 3;
  static_assert(netzone_invalid == 0 && netzone_public == 1 && netzone_tor == 3,
    "netzone bytes are the FFI contract with shekyl_types::relay::NetZone");

  inline const char* netzone_name(std::uint8_t zone) noexcept
  {
    switch (zone)
    {
    case netzone_public: return "public";
    case netzone_tor: return "tor";
    default: return "invalid";
    }
  }

  /*! A local origin keeps its pool record when hop 0 is restricted.

      Hop 0 is the relay's construction bit: some configured connector hides
      this node's address, so the first hop draws only from those edges.
      `upgrade_relay_method` is monotone. One record of `stem` or `fluff`
      moves the entry out of `local` permanently, and the next pool re-relay
      puts the origin's own transaction on a clear edge.

      Every other method records the method the relay used. An unknown method
      byte is false: this does not invent a `local` claim. */
  inline bool origin_keeps_local_record(
    const relay_method tx_relay,
    const bool hop0_restricted) noexcept
  {
    return shekyl_relay_zone_origin_keeps_local_record(
      static_cast<std::uint8_t>(tx_relay), hop0_restricted);
  }

}
