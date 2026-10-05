// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connection on the seam.
//!
//! This file is interim translation. The Rust types and the FFI are the
//! contract: the typed address, the observed endpoint, and the D12 cause.
//! The conversions here serve the code above the seam until LV-3 replaces
//! it. They do not shape a Rust type.
//!
//! The executor owns the strand for the life of the connection, and it owns
//! this link. The link owns the handler until the destroy post drops it.
//! That post runs on the strand, drops the handler, tells Rust to reap the
//! row, then asks the owner to drop its `shared_ptr`. The post holds its
//! own `shared_ptr`, so the erase does not free the link while the post
//! is still on the stack.

#pragma once

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "misc_log_ex.h"
#include "net/levin_protocol_handler_async.h"
#include "net/tor_address.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl
{
  inline const char* seam_close_name(std::uint8_t kind)
  {
    switch (kind)
    {
      case SHEKYL_CLOSE_PREFIX_MISMATCH: return "PrefixMismatch";
      case SHEKYL_CLOSE_TRANSPORT_HANDSHAKE_FAILED: return "TransportHandshakeFailed";
      case SHEKYL_CLOSE_TRANSPORT_TIMEOUT: return "TransportTimeout";
      case SHEKYL_CLOSE_ADMISSION_REFUSED: return "AdmissionRefused";
      case SHEKYL_CLOSE_INBOUND_NOT_ACCEPTED: return "InboundNotAccepted";
      case SHEKYL_CLOSE_DIAL_FAILED: return "DialFailed";
      case SHEKYL_CLOSE_PROXY_REFUSED: return "ProxyRefused";
      case SHEKYL_CLOSE_LEVIN_HANDSHAKE_TIMEOUT: return "LevinHandshakeTimeout";
      case SHEKYL_CLOSE_LEVIN_HANDSHAKE_REJECTED: return "LevinHandshakeRejected";
      case SHEKYL_CLOSE_PEER_CLOSED: return "PeerClosed";
      case SHEKYL_CLOSE_RECORD_REJECTED: return "RecordRejected";
      case SHEKYL_CLOSE_SESSION_REFUSED: return "SessionRefused";
      case SHEKYL_CLOSE_IO_ERROR: return "IoError";
      case SHEKYL_CLOSE_SEND_QUEUE_FULL: return "SendQueueFull";
      case SHEKYL_CLOSE_LOCAL_CLOSE: return "LocalClose";
      default: return kind == 0 ? "none" : "unknown";
    }
  }

  /// Registry key for `socket_id`. Zero is not an id, so the result is
  /// never the nil UUID. Two socket ids never share a key.
  inline boost::uuids::uuid seam_connection_id(std::uint64_t socket_id)
  {
    boost::uuids::uuid id{};
    static_assert(sizeof(socket_id) == 8, "socket id is 8 bytes");
    std::memcpy(id.data + 8, &socket_id, sizeof(socket_id));
    return id;
  }

  inline epee::net_utils::network_address seam_network_address(const shekyl_seam_observed& obs)
  {
    using epee::net_utils::ipv4_network_address;
    using epee::net_utils::ipv6_network_address;
    using epee::net_utils::network_address;
    if (obs.zone_only != 0 && obs.address_type == SHEKYL_ADDR_TOR)
      return network_address{net::tor_address::unknown()};
    if (obs.address_type == SHEKYL_ADDR_IPV4 && obs.len == 4)
    {
      // The FFI carries an IPv4 address as its four octets, in network order.
      // `s_addr` is those octets in memory. `memcpy` is that copy on either
      // endian.
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
    return network_address{};
  }

  /// The Levin handler for one `SocketId`.
  ///
  /// The closing bit and the call count share one atomic word. `add_ref`
  /// fails when the bit is set. `begin_closed` sets the bit and sees the
  /// count at that instant. Destruction is posted only when that count is
  /// zero, or when `release` takes it to zero afterwards.
  template <class t_context, class t_handler, class t_config>
  class seam_link final : public epee::net_utils::i_service_endpoint,
                          public std::enable_shared_from_this<seam_link<t_context, t_handler, t_config>>
  {
  public:
    static constexpr std::uint32_t kClosing = 0x80000000u;
    static constexpr std::uint32_t kCount = 0x7fffffffu;

    using retire_fn = std::function<void(std::uint64_t)>;

    static std::shared_ptr<seam_link> create(boost::asio::io_context& io,
        boost::asio::io_context::strand& strand, t_config& config, std::uint64_t id,
        const shekyl_seam_observed& observed, retire_fn retire)
    {
      auto link = std::shared_ptr<seam_link>(new seam_link(io, strand, config, id, observed, std::move(retire)));
      link->m_self = link;
      return link;
    }

    const t_context& context() const { return m_context; }

    bool arm()
    {
      return m_handler && m_handler->after_init_connection();
    }

    bool take_bytes(const std::uint8_t* bytes, std::size_t len)
    {
      if (len != 0)
        m_context.m_last_recv = time(nullptr);
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
      int found = 0;
      std::uint8_t cause = 0;
      const int accepted = shekyl_seam_send_report(
          m_id, message.data(), message.size(), &found, &cause);
      if (accepted != 0 && message.size() != 0)
        m_context.m_last_send = time(nullptr);
      if (accepted == 0)
      {
        MINFO("seam send refused conn " << m_context.m_connection_id
            << " seam_id " << m_id
            << " connector " << (epee::net_utils::connector_from_byte(m_context.m_connector)
                 ? epee::net_utils::connector_id_to_string(*epee::net_utils::connector_from_byte(m_context.m_connector))
                 : "unnamed")
            << " direction " << (m_context.m_is_income ? "in" : "out")
            << " registry " << (found != 0 ? "yes" : "no")
            << " seam " << accepted
            << " cause " << seam_close_name(cause));
      }
      return accepted != 0;
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
      // The queued callback runs on the strand. The count keeps
      // `begin_closed` from destroying the handler first. The
      // `shared_ptr` keeps the allocation alive until the callback returns.
      if (!add_ref())
        return false;
      auto self = m_self.lock();
      if (!self)
      {
        release();
        return false;
      }
      boost::asio::post(m_strand, [self] {
        if (self->m_handler)
          self->m_handler->handle_qued_callback();
        self->release();
      });
      return true;
    }

    boost::asio::io_context& get_io_context() override { return m_io; }

    /// The connection strand. An invoke-timeout completion posts here
    /// before it reads the context.
    void post(std::function<void()> fn) override
    {
      boost::asio::post(m_strand, std::move(fn));
    }

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
    seam_link(boost::asio::io_context& io, boost::asio::io_context::strand& strand, t_config& config,
        std::uint64_t id, const shekyl_seam_observed& observed, retire_fn retire)
      : m_io(io),
        m_strand(strand),
        m_context(seam_connection_id(id), seam_network_address(observed),
            observed.direction == SHEKYL_DIRECTION_INBOUND, observed.connector),
        m_id(id),
        m_retire(std::move(retire))
    {
      m_handler = std::make_unique<t_handler>(this, config, m_context);
    }

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
      auto self = m_self.lock();
      if (!self)
        return;
      boost::asio::post(m_strand, [self] {
        self->m_handler.reset();
        self->m_destroyed.store(true, std::memory_order_release);
        shekyl_seam_reap(self->m_id);
        if (self->m_retire)
          self->m_retire(self->m_id);
      });
    }

    boost::asio::io_context& m_io;
    boost::asio::io_context::strand& m_strand;
    t_context m_context;
    std::unique_ptr<t_handler> m_handler;
    std::uint64_t m_id;
    retire_fn m_retire;
    std::weak_ptr<seam_link> m_self;
    std::atomic<std::uint32_t> m_word{0};
    std::atomic<bool> m_destroy_posted{false};
    std::atomic<bool> m_destroyed{false};
  };
}
