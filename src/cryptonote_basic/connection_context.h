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
// Parts of this file are originally copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net

// TODO(shekyl-v4): Migrate boost::posix_time::ptime fields to
// std::chrono::system_clock::time_point. This struct crosses P2P protocol
// boundaries; change must be coordinated with block_queue and net_node.
#pragma once
#include <unordered_set>
#include <atomic>
#include <algorithm>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <optional>
#include <cstdint>
#include <limits>
#include "net/net_utils_base.h"
#include "crypto/hash.h"

namespace cryptonote
{
  struct cryptonote_connection_context: public epee::net_utils::connection_context_base
  {
    cryptonote_connection_context()
      : cryptonote_connection_context(boost::uuids::uuid(), epee::net_utils::network_address(), false)
    {}

    // SSL is refused. The base is handed a constant false; the seam has
    // no SSL state to pass.
    cryptonote_connection_context(boost::uuids::uuid connection_id,
        const epee::net_utils::network_address& remote_address, bool is_income)
      : epee::net_utils::connection_context_base(connection_id, remote_address, is_income, false),
        m_state(state_before_handshake), m_remote_blockchain_height(0),
        m_remote_height_source(remote_height_source::none), m_last_response_height(0),
        m_expected_heights_start(0), m_last_request_time(boost::date_time::not_a_date_time), m_callback_request_count(0),
        m_last_known_hash(crypto::null_hash), m_score(0),
        m_expect_response(0), m_expect_height(0), m_num_requested(0)
    {}

    enum state
    {
      state_before_handshake = 0, //default state
      state_synchronizing,
      state_standby,
      state_normal
    };

    /*
      This class was originally from the EPEE module. It is identical in function to std::atomic<uint32_t> except
      that it has copy-construction and copy-assignment defined, which means that earliers devs didn't have to write
      custom copy-contructors and copy-assingment operators for the outer class, cryptonote_connection_context.
      cryptonote_connection_context should probably be refactored because it is both trying to be POD-like while
      also (very loosely) controlling access to its atomic members.
    */
    class copyable_atomic: public std::atomic<uint32_t>
    {
    public:
      copyable_atomic()
      {};
      copyable_atomic(uint32_t value)
      { store(value); }
      copyable_atomic(const copyable_atomic& a):std::atomic<uint32_t>(a.load())
      {}
      copyable_atomic& operator= (const copyable_atomic& a)
      {
        store(a.load());
        return *this;
      }
      uint32_t operator++()
      {
        return std::atomic<uint32_t>::operator++();
      }
      uint32_t operator++(int fake)
      {
        return std::atomic<uint32_t>::operator++(fake);
      }
    };

    static constexpr int handshake_command() noexcept { return 1001; }
    bool session_established() const noexcept { return m_state != state_before_handshake; }

    //! \return Payload cap for this `(command, flags)` pair, or `nullopt`
    //! if the header is unrecognised at ingress (PWD-B3a). `nullopt` is
    //! connection-fatal even for a zero-length payload — returning cap 0
    //! would admit empty unknown commands. On reject, `reject_rc` (when
    //! non-null) receives the `shekyl_levin_ingress_admit` code (`-8`
    //! unknown flags, `-9` unknown dispatch command).
    static std::optional<size_t> get_max_bytes(uint32_t command, uint32_t flags, int32_t* reject_rc = nullptr) noexcept;

    //! Use this instead of `m_state = state_normal`.
    void set_state_normal();

    std::optional<crypto::hash> get_expected_hash(uint64_t height) const;

    //! Which message last wrote `m_remote_blockchain_height`.
    //! Relay eligibility does not read this field. A reader of a
    //! failed send, and the sync span, still do.
    enum class remote_height_source : std::uint8_t
    {
      none,
      handshake,
      timed_sync,
      get_objects,
      chain_entry,
      accepted_block
    };

    state m_state;
    std::vector<std::pair<crypto::hash, uint64_t>> m_needed_objects;
    std::vector<crypto::hash> m_expected_heights;
    std::unordered_set<crypto::hash> m_requested_objects;
    uint64_t m_remote_blockchain_height;
    remote_height_source m_remote_height_source;
    uint64_t m_last_response_height;
    uint64_t m_expected_heights_start;
    boost::posix_time::ptime m_last_request_time;
    copyable_atomic m_callback_request_count; //in debug purpose: problem with double callback rise
    crypto::hash m_last_known_hash;
    int32_t m_score;
    int m_expect_response;
    uint64_t m_expect_height;
    size_t m_num_requested;
    copyable_atomic m_idle_peer_notification{0};
  };

  inline const char* remote_height_source_name(cryptonote_connection_context::remote_height_source source)
  {
    switch (source)
    {
    case cryptonote_connection_context::remote_height_source::handshake:
      return "handshake";
    case cryptonote_connection_context::remote_height_source::timed_sync:
      return "timed_sync";
    case cryptonote_connection_context::remote_height_source::get_objects:
      return "get_objects";
    case cryptonote_connection_context::remote_height_source::chain_entry:
      return "chain_entry";
    case cryptonote_connection_context::remote_height_source::accepted_block:
      return "accepted_block";
    case cryptonote_connection_context::remote_height_source::none:
      return "none";
    }
    return "unknown";
  }

  inline void note_remote_height(cryptonote_connection_context& context, std::uint64_t height,
      cryptonote_connection_context::remote_height_source source)
  {
    context.m_remote_blockchain_height = height;
    context.m_remote_height_source = source;
  }

  //! Chain length of a block whose coinbase height is `coinbase_height`.
  //! The recorded field, the handshake write, and `get_current_blockchain_height`
  //! are that length. A coinbase height of 84 is chain length 85.
  inline std::uint64_t chain_length_of_accepted_block(std::uint64_t coinbase_height)
  {
    if (coinbase_height == std::numeric_limits<std::uint64_t>::max())
      return coinbase_height;
    return coinbase_height + 1;
  }

  //! Raise the recorded chain length. A delivered block never lowers it.
  //! A later handshake or timed sync may still replace the value with a claim.
  inline void raise_remote_height(cryptonote_connection_context& context, std::uint64_t chain_length)
  {
    if (chain_length <= context.m_remote_blockchain_height)
      return;
    note_remote_height(context, chain_length,
        cryptonote_connection_context::remote_height_source::accepted_block);
  }

  inline std::string get_protocol_state_string(cryptonote_connection_context::state s)
  {
    switch (s)
    {
    case cryptonote_connection_context::state_before_handshake:
      return "before_handshake";
    case cryptonote_connection_context::state_synchronizing:
      return "synchronizing";
    case cryptonote_connection_context::state_standby:
      return "standby";
    case cryptonote_connection_context::state_normal:
      return "normal";
    default:
      return "unknown";
    }    
  }

  inline char get_protocol_state_char(cryptonote_connection_context::state s)
  {
    switch (s)
    {
    case cryptonote_connection_context::state_before_handshake:
      return 'h';
    case cryptonote_connection_context::state_synchronizing:
      return 's';
    case cryptonote_connection_context::state_standby:
      return 'w';
    case cryptonote_connection_context::state_normal:
      return 'n';
    default:
      return 'u';
    }
  }

}
