// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connection on the seam.
//!
//! The executor owns the strand for the life of the connection, and it owns
//! this link. The link owns the handler until the destroy post drops it.
//! That post runs on the strand and is not the last owner of the link: it
//! drops the handler only. The executor drops the link after the post has
//! finished. A walker that got `add_ref` true still holds a count, so the
//! destroy post has not run.

#pragma once

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/uuid/nil_generator.hpp>

#include "net/i2p_address.h"
#include "net/levin_protocol_handler_async.h"
#include "net/tor_address.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl
{
  inline epee::net_utils::network_address seam_network_address(const shekyl_seam_observed& obs)
  {
    using epee::net_utils::ipv4_network_address;
    using epee::net_utils::ipv6_network_address;
    using epee::net_utils::network_address;
    if (obs.zone_only != 0 && obs.address_type == SHEKYL_ADDR_TOR)
      return network_address{net::tor_address::unknown()};
    if (obs.zone_only != 0 && obs.address_type == SHEKYL_ADDR_I2P)
      return network_address{net::i2p_address::unknown()};
    if (obs.address_type == SHEKYL_ADDR_IPV4 && obs.len == 4)
    {
      // The four octets in memory, which is what `in_addr.s_addr` holds.
      std::uint32_t ip = 0;
      std::memcpy(&ip, obs.bytes, 4);
      return network_address{ipv4_network_address(ip, obs.port)};
    }
    if (obs.address_type == SHEKYL_ADDR_IPV6 && obs.len == 16)
    {
      boost::asio::ip::address_v6::bytes_type bytes{};
      std::memcpy(bytes.data(), obs.bytes, 16);
      return network_address{ipv6_network_address(boost::asio::ip::address_v6(bytes), obs.port)};
    }
    if (obs.address_type == SHEKYL_ADDR_TOR && obs.len > 0 && obs.len <= SHEKYL_SEAM_HOST_MAX)
    {
      const std::string host(reinterpret_cast<const char*>(obs.bytes), obs.len);
      auto made = net::tor_address::make(host, obs.port);
      if (made.has_value())
        return network_address{*made};
    }
    if (obs.address_type == SHEKYL_ADDR_I2P && obs.len > 0 && obs.len <= SHEKYL_SEAM_HOST_MAX)
    {
      const std::string host(reinterpret_cast<const char*>(obs.bytes), obs.len);
      auto made = net::i2p_address::make(host);
      if (made.has_value())
        return network_address{*made};
    }
    return network_address{};
  }

  /// The Levin handler for one `SocketId`.
  ///
  /// The closing bit and the call count share one atomic word. `add_ref`
  /// fails when the bit is set. `begin_closed` sets the bit and sees the
  /// count at that instant. Destruction is posted only when that count is
  /// zero, or when `release` takes it to zero afterwards.
  template <class t_context, class t_handler, class t_config>
  class seam_link final : public epee::net_utils::i_service_endpoint
  {
  public:
    static constexpr std::uint32_t kClosing = 0x80000000u;
    static constexpr std::uint32_t kCount = 0x7fffffffu;

    seam_link(boost::asio::io_context& io, boost::asio::io_context::strand& strand, t_config& config,
        std::uint64_t id, const shekyl_seam_observed& observed)
      : m_io(io),
        m_strand(strand),
        m_context(boost::uuids::nil_uuid(), seam_network_address(observed),
            observed.direction == SHEKYL_DIRECTION_INBOUND, false),
        m_id(id)
    {
      m_handler = std::make_unique<t_handler>(this, config, m_context);
    }

    const t_context& context() const { return m_context; }

    bool arm()
    {
      return m_handler && m_handler->after_init_connection();
    }

    bool take_bytes(const std::uint8_t* bytes, std::size_t len)
    {
      return m_handler && m_handler->handle_recv(bytes, len);
    }

    /// `closed` on the strand. Sets the closing bit, cancels invokes, and
    /// posts destruction when the count it observed was zero.
    void begin_closed()
    {
      const std::uint32_t prev = mark_closing();
      if ((prev & kClosing) != 0)
        return;
      if (m_handler)
        m_handler->release_protocol();
      if ((prev & kCount) == 0)
        post_destroy();
    }

    bool destroyed() const { return m_destroyed.load(std::memory_order_acquire); }

    bool do_send(epee::byte_slice message) override
    {
      return shekyl_seam_send(m_id, message.data(), message.size()) != 0;
    }

    bool close() override
    {
      shekyl_seam_close(m_id);
      return true;
    }

    bool send_done() override { return true; }

    bool call_run_once_service_io() override { return false; }

    bool request_callback() override
    {
      boost::asio::post(m_strand, [this] {
        if (m_handler)
          m_handler->handle_qued_callback();
      });
      return true;
    }

    boost::asio::io_context& get_io_context() override { return m_io; }

    bool add_ref() override
    {
      std::uint32_t cur = m_word.load(std::memory_order_acquire);
      for (;;)
      {
        if ((cur & kClosing) != 0 || (cur & kCount) == kCount)
          return false;
        if (m_word.compare_exchange_weak(cur, cur + 1, std::memory_order_acq_rel, std::memory_order_acquire))
          return true;
      }
    }

    bool release() override
    {
      std::uint32_t cur = m_word.load(std::memory_order_acquire);
      for (;;)
      {
        const std::uint32_t count = cur & kCount;
        if (count == 0)
        {
          // A release with no outstanding add_ref is a mismatched pair.
          assert(false && "seam_link::release without a matching add_ref");
          return false;
        }
        const std::uint32_t next = (cur & kClosing) | (count - 1);
        if (m_word.compare_exchange_weak(cur, next, std::memory_order_acq_rel, std::memory_order_acquire))
        {
          if ((next & kClosing) != 0 && (next & kCount) == 0)
            post_destroy();
          return true;
        }
      }
    }

  private:
    std::uint32_t mark_closing()
    {
      std::uint32_t cur = m_word.load(std::memory_order_acquire);
      for (;;)
      {
        if ((cur & kClosing) != 0)
          return cur;
        if (m_word.compare_exchange_weak(cur, cur | kClosing, std::memory_order_acq_rel, std::memory_order_acquire))
          return cur;
      }
    }

    void post_destroy()
    {
      if (m_destroy_posted.exchange(true, std::memory_order_acq_rel))
        return;
      boost::asio::post(m_strand, [this] {
        m_handler.reset();
        m_destroyed.store(true, std::memory_order_release);
      });
    }

    boost::asio::io_context& m_io;
    boost::asio::io_context::strand& m_strand;
    t_context m_context;
    std::unique_ptr<t_handler> m_handler;
    std::uint64_t m_id;
    std::atomic<std::uint32_t> m_word{0};
    std::atomic<bool> m_destroy_posted{false};
    std::atomic<bool> m_destroyed{false};
  };
}
