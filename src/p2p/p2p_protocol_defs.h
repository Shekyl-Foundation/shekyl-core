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

#pragma once

#include <array>
#include <iomanip>
#include <boost/uuid/uuid.hpp>
#include <boost/serialization/version.hpp>
#include "serialization/keyvalue_serialization.h"
#include "net/net_utils_base.h"
#include "net/tor_address.h" // needed for serialization
#include "net/i2p_address.h" // needed for serialization
#include "misc_language.h"
#include "string_tools.h"
#include "time_helper.h"
#include "serialization/serialization.h"
#include "cryptonote_config.h"

namespace nodetool
{
  typedef boost::uuids::uuid uuid;

  // A peerlist entry carries no identifier (PWD-I1 amendment): a stored id
  // was a durable identifier keyed to an address — the shape the design
  // forbids — and it was self-asserted, so it identified nothing anyway.
  // The address IS the entry: a hypothesis about where a peer can be dialed.
  template<typename AddressType>
  struct peerlist_entry_base
  {
    AddressType adr;
    int64_t last_seen;
    uint32_t pruning_seed;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(adr)
      KV_SERIALIZE_OPT(last_seen, (int64_t)0)
      KV_SERIALIZE_OPT(pruning_seed, (uint32_t)0)
    END_KV_SERIALIZE_MAP()

    BEGIN_SERIALIZE()
      FIELD(adr)
      VARINT_FIELD(last_seen)
      VARINT_FIELD(pruning_seed)
    END_SERIALIZE()
  };
  typedef peerlist_entry_base<epee::net_utils::network_address> peerlist_entry;

  // `anchor_peerlist_entry` was deleted with the anchor mechanism. Its only
  // job was crossing the restart boundary -- see net_peerlist.h `init()`.

  inline 
  std::string print_peerlist_to_string(const std::vector<peerlist_entry>& pl)
  {
    time_t now_time = 0;
    time(&now_time);
    std::stringstream ss;
    ss << std::setfill ('0') << std::setw (8) << std::hex << std::noshowbase;
    for(const peerlist_entry& pe: pl)
    {
      ss << pe.adr.str()
        << " \tpruning seed " << pe.pruning_seed
        << " \tlast_seen: " << (pe.last_seen == 0 ? std::string("never") : epee::misc_utils::get_time_interval_string(now_time - pe.last_seen))
        << std::endl;
    }
    return ss.str();
  }


  struct network_config
  {
    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(max_out_connection_count)
      KV_SERIALIZE(max_in_connection_count)
      KV_SERIALIZE(handshake_interval)
      KV_SERIALIZE(packet_max_size)
      KV_SERIALIZE(config_id)
    END_KV_SERIALIZE_MAP()

    std::chrono::milliseconds ping_connection_timeout;
    uint32_t max_out_connection_count;
    uint32_t max_in_connection_count;
    uint32_t connection_timeout;
    uint32_t handshake_interval;
    uint32_t packet_max_size;
    uint32_t config_id;
    uint32_t send_peerlist_sz;
  };

  /*! What a node announces about itself at handshake.

    There is deliberately no node identifier here. `peer_id` (deleted per
    the PWD-I1 amendment, `SHEKYL_P2P_PROTOCOL.md`) was self-asserted and
    free to mint, so it asserted nothing about WHO a peer is — and on an
    anonymity zone any distinct announced value is an eclipse-completion
    oracle: the dialer announces it to every acceptor it dials, so an
    attacker learns at handshake time how many of a victim's outbound slots
    it holds. What a handshake can honestly establish is that THERE IS A
    PEER AT THIS ADDRESS.

    `address` is that announcement — a hypothesis about WHERE this node can
    be dialed, never a claim about WHO is there:
    - public zone: a port-only advert (host zeroed). The receiver never
      reads the advertised host half; it combines the advertised port with
      the host it OBSERVED on the socket — an announcement proves nothing,
      a dial proves reachability. The derived entry lands in gray and earns
      white only by being dialed (PWD-I2).
    - anonymity zones, serving: the zone's own self-address
      (`zone.m_our_address`), dialable — the only verification an overlay
      address admits.
    - dialer-only / hidden: the zone's unknown-address sentinel, recorded
      nowhere (undialable). The address's type tag reveals only the zone,
      which the acceptor already knows from its own listener. */
  struct basic_node_data
  {
    uuid network_id;
    epee::net_utils::network_address address;
    uint32_t support_flags;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB(network_id)
      KV_SERIALIZE(address)
      KV_SERIALIZE_OPT(support_flags, (uint32_t)0)
    END_KV_SERIALIZE_MAP()
  };


#define P2P_COMMANDS_POOL_BASE 1000

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  template<class t_playload_type>
	struct COMMAND_HANDSHAKE_T
	{
		const static int ID = P2P_COMMANDS_POOL_BASE + 1;

    struct request_t
    {
      basic_node_data node_data;
      t_playload_type payload_data;
      // Self-detection nonce (SHEKYL_P2P_PROTOCOL.md, PWD-T1's token carried
      // interim on this request until the Noise handshake lands): 32 bytes
      // of CSPRNG output, in the clear — its only job is to be recognised
      // by the node that emitted it. Inserted into the dialing zone's
      // in-flight set immediately before this request is written; an
      // arriving handshake carrying a nonce this node recently emitted IS
      // this node. Windows are per zone; comparison is within-zone only —
      // a global window would let a peer dialed on one zone replay the
      // nonce into another zone's listener and use the drop as a
      // cross-zone correlation oracle.
      std::array<uint8_t, 32> nonce;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(node_data)
        KV_SERIALIZE(payload_data)
        KV_SERIALIZE_VAL_POD_AS_BLOB(nonce)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      basic_node_data node_data;
      t_playload_type payload_data;
      std::vector<peerlist_entry> local_peerlist_new;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(node_data)
        KV_SERIALIZE(payload_data)
        KV_SERIALIZE(local_peerlist_new)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  template<class t_playload_type>
  struct COMMAND_TIMED_SYNC_T
  {
    const static int ID = P2P_COMMANDS_POOL_BASE + 2;

    struct request_t
    {
      t_playload_type payload_data;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payload_data)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      t_playload_type payload_data;
      std::vector<peerlist_entry> local_peerlist_new;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payload_data)
        KV_SERIALIZE(local_peerlist_new)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // COMMAND_PING (1003) is deleted (PWD-B10 / PWC-B1): the back-ping was
  // its only user, and the back-ping's only job was gating whitelist
  // promotion of an inbound peer, which the earned-trust model forbids —
  // an inbound advert lands in gray, and an ordinary outbound dial
  // establishes for free what the ping spent a connection to learn.
  // The command id is retired, never reused.

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct COMMAND_REQUEST_SUPPORT_FLAGS
  {
    const static int ID = P2P_COMMANDS_POOL_BASE + 7;

    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()    
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint32_t support_flags;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(support_flags)
      END_KV_SERIALIZE_MAP()    
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
}
