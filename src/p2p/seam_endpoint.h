// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connection on the seam.
//!
//! The strand runs `established`, every `deliver`, and `closed`.
//! Destruction is a later post on that strand, once the outer-call count
//! is zero. Nothing here waits for that count.

#pragma once

#include <atomic>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include "net/levin_protocol_handler_async.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl
{
  /// The Levin handler for one `SocketId`.
  ///
  /// `t_handler` is `epee::levin::async_protocol_handler<t_context>`.
  /// The link outlives the handler. The destroy post drops the handler
  /// on the strand and leaves the link in place so the strand callback
  /// can finish.
  template <class t_context, class t_handler, class t_config>
  class seam_link final : public epee::net_utils::i_service_endpoint
  {
  public:
    seam_link(boost::asio::io_context& io, boost::asio::io_context::strand& strand, t_config& config, std::uint64_t id)
      : m_io(io),
        m_strand(strand),
        m_id(id)
    {
      m_handler = std::make_unique<t_handler>(this, config, m_context);
    }

    bool arm()
    {
      return m_handler && m_handler->after_init_connection();
    }

    bool take_bytes(const std::uint8_t* bytes, std::size_t len)
    {
      return m_handler && m_handler->handle_recv(bytes, len);
    }

    /// `closed` on the strand. Invokes already queued are cancelled
    /// inline. Destruction is posted when the call count is zero.
    void begin_closed()
    {
      m_closing.store(true);
      if (m_handler)
        m_handler->release_protocol();
      if (m_calls.load() == 0)
        post_destroy();
    }

    bool destroyed() const { return m_destroyed.load(); }

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
      if (m_closing.load())
        return false;
      m_calls.fetch_add(1);
      return true;
    }

    bool release() override
    {
      if (m_calls.fetch_sub(1) == 1 && m_closing.load())
        post_destroy();
      return true;
    }

  private:
    void post_destroy()
    {
      if (m_destroy_posted.exchange(true))
        return;
      boost::asio::post(m_strand, [this] {
        m_handler.reset();
        m_destroyed.store(true);
      });
    }

    boost::asio::io_context& m_io;
    boost::asio::io_context::strand& m_strand;
    t_context m_context{};
    std::unique_ptr<t_handler> m_handler;
    std::uint64_t m_id;
    std::atomic<int> m_calls{0};
    std::atomic<bool> m_closing{false};
    std::atomic<bool> m_destroy_posted{false};
    std::atomic<bool> m_destroyed{false};
  };
}
