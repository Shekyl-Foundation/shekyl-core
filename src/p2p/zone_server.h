// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One zone's server.
//!
//! It holds the Levin registry, the socketless executor, the bound ports,
//! and `open`. It does not wrap an epee TCP server, and it does not
//! grow methods that existed only so epee could be configured.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>

#include "misc_log_ex.h"
#include "net/levin_protocol_handler_async.h"
#include "net/net_utils_base.h"
#include "net/tor_address.h"
#include "p2p/seam_endpoint.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl
{

class zone_binding
{
public:
  virtual ~zone_binding() = default;
  virtual void enqueue(std::uint64_t id, std::uint32_t kind, shekyl_seam_observed observed, bool have_observed, std::vector<std::uint8_t> bytes) = 0;
};

namespace detail
{
  struct zone_slots
  {
    std::mutex mu;
    zone_binding* clearnet = nullptr;
    zone_binding* tor = nullptr;
    bool seam_bound = false;
  };

  inline zone_slots& slots()
  {
    static zone_slots slots;
    return slots;
  }

  inline void zone_post(void*, std::uint64_t id, std::uint32_t kind, const shekyl_seam_observed* observed,
      const std::uint8_t* bytes, std::size_t len, const shekyl_close_cause* cause)
  {
    if (kind == SHEKYL_SEAM_CLOSED)
    {
      if (cause != nullptr)
        MINFO("seam close id " << id << " cause " << seam_close_name(cause->kind)
            << " reply " << cause->reply_code);
      else
        MINFO("seam close id " << id << " cause missing");
    }
    // Hold the slot lock through enqueue. The binding pointer is raw, and
    // unregister runs on another thread; enqueue only posts to the strand.
    std::lock_guard<std::mutex> lock(slots().mu);
    zone_binding* target = nullptr;
    if (observed != nullptr && observed->connector == SHEKYL_CONNECTOR_TOR)
      target = slots().tor;
    else
      target = slots().clearnet;
    if (target == nullptr)
      return;
    std::vector<std::uint8_t> copy;
    if (bytes != nullptr && len != 0)
      copy.assign(bytes, bytes + len);
    shekyl_seam_observed stored{};
    const bool have = observed != nullptr;
    if (have)
      stored = *observed;
    target->enqueue(id, kind, stored, have, std::move(copy));
  }

  inline bool ensure_seam(const shekyl_inbound_ceiling& ceiling)
  {
    std::lock_guard<std::mutex> lock(slots().mu);
    if (slots().seam_bound)
    {
      shekyl_seam_set_ceiling(&ceiling);
      return true;
    }
    static int ctx = 1;
    if (shekyl_seam_bind(&ctx, &zone_post, &ceiling) != 0)
      return false;
    slots().seam_bound = true;
    return true;
  }

  inline void register_binding(std::uint32_t connector, zone_binding* binding)
  {
    std::lock_guard<std::mutex> lock(slots().mu);
    if (connector == SHEKYL_CONNECTOR_TOR)
      slots().tor = binding;
    else
      slots().clearnet = binding;
  }

  inline void unregister_binding(zone_binding* binding)
  {
    std::lock_guard<std::mutex> lock(slots().mu);
    if (slots().clearnet == binding)
      slots().clearnet = nullptr;
    if (slots().tor == binding)
      slots().tor = nullptr;
  }

  inline bool address_from(const epee::net_utils::network_address& addr, shekyl_seam_address& out)
  {
    out = {};
    if (addr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
    {
      const auto& ipv4 = addr.as<epee::net_utils::ipv4_network_address>();
      out.connector = SHEKYL_CONNECTOR_CLEARNET;
      out.address_type = SHEKYL_ADDR_IPV4;
      out.port = ipv4.port();
      out.len = 4;
      const std::uint32_t ip = ipv4.ip();
      std::memcpy(out.bytes, &ip, 4);
      return true;
    }
    if (addr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
    {
      const auto& ipv6 = addr.as<epee::net_utils::ipv6_network_address>();
      out.connector = SHEKYL_CONNECTOR_CLEARNET;
      out.address_type = SHEKYL_ADDR_IPV6;
      out.port = ipv6.port();
      out.len = 16;
      const auto bytes = ipv6.ip().to_bytes();
      std::memcpy(out.bytes, bytes.data(), 16);
      return true;
    }
    if (addr.get_type_id() == net::tor_address::get_type_id())
    {
      const auto& tor = addr.as<net::tor_address>();
      const std::string host = tor.host_str();
      if (host.empty() || host.size() > SHEKYL_SEAM_HOST_MAX)
        return false;
      out.connector = SHEKYL_CONNECTOR_TOR;
      out.address_type = SHEKYL_ADDR_TOR;
      out.port = tor.port();
      out.len = static_cast<std::uint16_t>(host.size());
      std::memcpy(out.bytes, host.data(), host.size());
      return true;
    }
    return false;
  }

  /// A canonical decimal in `0..=65535`. `"0"` is the ephemeral request.
  /// Empty, trailing junk, and a leading zero are not a port.
  inline std::optional<std::uint16_t> port_of(const std::string& text)
  {
    if (text.empty() || text.size() > 5)
      return std::nullopt;
    if (text.size() > 1 && text[0] == '0')
      return std::nullopt;
    unsigned long value = 0;
    for (unsigned char ch : text)
    {
      if (ch < '0' || ch > '9')
        return std::nullopt;
      value = value * 10ul + static_cast<unsigned long>(ch - '0');
      if (value > 65535ul)
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
  }
}

template <class t_protocol_handler>
class zone_server final : public zone_binding
{
public:
  using config_type = typename t_protocol_handler::config_type;
  using connection_context = typename t_protocol_handler::connection_context;
  using link_type = seam_link<connection_context, t_protocol_handler, config_type>;

  zone_server()
    : m_owned(std::make_shared<boost::asio::io_context>()),
      m_io(m_owned.get()),
      m_owns_io(true),
      m_config(std::make_shared<config_type>()),
      m_stopped(std::make_shared<std::atomic<bool>>(false)),
      m_prefix("P2P")
  {}

  explicit zone_server(boost::asio::io_context& shared)
    : m_io(&shared),
      m_owns_io(false),
      m_config(std::make_shared<config_type>()),
      m_stopped(std::make_shared<std::atomic<bool>>(false)),
      m_prefix("P2P")
  {}

  zone_server(const zone_server&) = delete;
  zone_server& operator=(const zone_server&) = delete;

  ~zone_server() override
  {
    detail::unregister_binding(this);
  }

  config_type& get_config_object() { return *m_config; }
  std::shared_ptr<config_type> get_config_shared() { return m_config; }
  boost::asio::io_context& get_io_context() { return *m_io; }

  bool is_stop_signal_sent() const noexcept { return m_stopped->load(std::memory_order_acquire); }

  void send_stop_signal()
  {
    m_stopped->store(true, std::memory_order_release);
    m_io->stop();
  }

  void set_threads_prefix(const std::string& prefix) { m_prefix = prefix; }

  int get_binded_port() const { return m_port; }
  int get_binded_port_ipv6() const { return m_port_v6; }

  template <class Handler>
  bool add_idle_handler(Handler callback, std::chrono::milliseconds timeout)
  {
    auto held = std::make_shared<idle_handler<Handler>>(*m_io, std::move(callback), timeout, m_stopped);
    arm_idle(held);
    return true;
  }

  /// The floor is one worker besides the lane `idle_worker` blocks on.
  /// A count below that floor is refused by the ledger and this returns
  /// false. The worker count is unmeasured; the run record replaces it.
  bool run(std::size_t workers, const boost::thread::attributes& attrs)
  {
    if (!m_owns_io)
      return false;
    std::uint64_t handle = 0;
    if (shekyl_executor_record(m_prefix.c_str(), 1, workers, &handle) == 0)
      return false;
    m_executor = handle;
    for (std::size_t i = 1; i < workers; ++i)
      m_threads.emplace_back(attrs, [this] { m_io->run(); });
    m_io->run();
    for (auto& thread : m_threads)
    {
      if (thread.joinable())
        thread.join();
    }
    return true;
  }

  bool deinit_server()
  {
    detail::unregister_binding(this);
    if (!m_owns_io)
      return true;
    send_stop_signal();
    for (auto& thread : m_threads)
    {
      if (thread.joinable())
        thread.join();
    }
    {
      std::lock_guard<std::mutex> lock(m_mu);
      m_links.clear();
      m_strands.clear();
    }
    if (m_executor != 0)
    {
      shekyl_executor_release(m_executor);
      m_executor = 0;
    }
    shekyl_zone_shutdown();
    return true;
  }

  bool listen_clearnet(const std::string& ip, const std::string& port, const std::string& ipv6, const std::string& port_v6,
      bool use_ipv6, const boost::asio::ip::tcp::endpoint* proxy, bool encrypt, const std::uint8_t* network_id, const shekyl_inbound_ceiling& ceiling,
      const shekyl_zone_params& spans)
  {
    const auto parsed_port = detail::port_of(port);
    if (!parsed_port)
      return false;
    std::uint16_t parsed_v6 = 0;
    if (use_ipv6)
    {
      const auto v6 = detail::port_of(port_v6);
      if (!v6)
        return false;
      parsed_v6 = *v6;
    }
    if (!detail::ensure_seam(ceiling))
      return false;
    detail::register_binding(SHEKYL_CONNECTOR_CLEARNET, this);
    shekyl_zone_params params = spans;
    params.network_id = network_id;
    int bound = -1;
    int bound_v6 = -1;
    const std::string proxy_host = proxy != nullptr ? proxy->address().to_string() : std::string();
    const int rc = shekyl_zone_listen_clearnet(
        ip.c_str(), *parsed_port,
        use_ipv6 ? ipv6.c_str() : nullptr, parsed_v6, use_ipv6 ? 1 : 0,
        proxy != nullptr ? proxy_host.c_str() : nullptr, proxy != nullptr ? proxy->port() : 0,
        encrypt ? 1 : 0, &params, &ceiling, &bound, &bound_v6);
    if (rc != 0)
      return false;
    m_port = bound;
    m_port_v6 = bound_v6;
    return true;
  }

  bool listen_tor(const boost::asio::ip::tcp::endpoint& socks, const std::string& extra_ip, const std::string& extra_port, bool have_extra,
      const std::uint8_t* network_id, const shekyl_inbound_ceiling& ceiling, const shekyl_zone_params& spans)
  {
    std::uint16_t parsed_extra = 0;
    if (have_extra)
    {
      const auto extra = detail::port_of(extra_port);
      if (!extra)
        return false;
      parsed_extra = *extra;
    }
    if (!detail::ensure_seam(ceiling))
      return false;
    detail::register_binding(SHEKYL_CONNECTOR_TOR, this);
    shekyl_zone_params params = spans;
    params.network_id = network_id;
    const std::string socks_host = socks.address().to_string();
    int bound = -1;
    const int rc = shekyl_zone_listen_tor(
        socks_host.c_str(), socks.port(),
        have_extra ? extra_ip.c_str() : nullptr, parsed_extra,
        &params, &ceiling, &bound);
    if (rc != 0)
      return false;
    m_port = bound;
    return true;
  }

  /// An outbound-only tor zone (`--tx-proxy tor,...` with no
  /// `--anonymous-inbound`). It listens on nothing, but its dialed
  /// connections still post to a tor binding, and its dials need the SOCKS
  /// address in the host. Without this call both were missing and every
  /// Tor dial was `DialFailed` before the network.
  bool dial_through_tor(const boost::asio::ip::tcp::endpoint& socks, const std::uint8_t* network_id,
      const shekyl_inbound_ceiling& ceiling, const shekyl_zone_params& spans)
  {
    if (!detail::ensure_seam(ceiling))
      return false;
    detail::register_binding(SHEKYL_CONNECTOR_TOR, this);
    shekyl_zone_params params = spans;
    params.network_id = network_id;
    const std::string socks_host = socks.address().to_string();
    return shekyl_zone_set_tor_proxy(socks_host.c_str(), socks.port(), &params, &ceiling) == 0;
  }

  /// 0 when `out` is the opened context. Otherwise the seam cause.
  /// An address this process cannot encode, and a dial the link map does
  /// not hold, are `LocalClose`: this node stopped, the address did not fail.
  std::uint8_t open(const epee::net_utils::network_address& address, connection_context& out)
  {
    shekyl_seam_address ffi{};
    if (!detail::address_from(address, ffi))
      return SHEKYL_CLOSE_LOCAL_CLOSE;
    const shekyl_seam_open_result result = shekyl_seam_open(&ffi, 0);
    if (result.id == 0)
    {
      const std::uint8_t cause = result.cause_kind == 0
          ? static_cast<std::uint8_t>(SHEKYL_CLOSE_DIAL_FAILED)
          : result.cause_kind;
      MINFO("seam open refused cause " << seam_close_name(cause)
          << " reply " << result.reply_code);
      return cause;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    const auto found = m_links.find(result.id);
    if (found == m_links.end())
      return SHEKYL_CLOSE_LOCAL_CLOSE;
    out = found->second->context();
    return 0;
  }

  void enqueue(std::uint64_t id, std::uint32_t kind, shekyl_seam_observed observed, bool have_observed, std::vector<std::uint8_t> bytes) override
  {
    auto strand = strand_for(id);
    boost::asio::post(*strand, [this, id, kind, observed, have_observed, bytes = std::move(bytes)] {
      on_strand(id, kind, observed, have_observed, bytes);
    });
  }

private:
  struct idle_base : std::enable_shared_from_this<idle_base>
  {
    boost::asio::steady_timer timer;
    std::chrono::milliseconds period;
    std::shared_ptr<std::atomic<bool>> stopped;
    idle_base(boost::asio::io_context& io, std::chrono::milliseconds every, std::shared_ptr<std::atomic<bool>> stop)
      : timer(io), period(every), stopped(std::move(stop))
    {}
    virtual ~idle_base() = default;
    virtual bool call() = 0;
  };

  template <class Handler>
  struct idle_handler final : idle_base
  {
    Handler handler;
    idle_handler(boost::asio::io_context& io, Handler callback, std::chrono::milliseconds every, std::shared_ptr<std::atomic<bool>> stop)
      : idle_base(io, every, std::move(stop)), handler(std::move(callback))
    {}
    bool call() override { return handler(); }
  };

  void arm_idle(const std::shared_ptr<idle_base>& held)
  {
    held->timer.expires_after(held->period);
    held->timer.async_wait([this, held](const boost::system::error_code& error) {
      if (error || held->stopped->load(std::memory_order_acquire))
        return;
      if (!held->call())
        return;
      arm_idle(held);
    });
  }

  std::shared_ptr<boost::asio::io_context::strand> strand_for(std::uint64_t id)
  {
    std::lock_guard<std::mutex> lock(m_mu);
    auto found = m_strands.find(id);
    if (found == m_strands.end())
      found = m_strands.emplace(id, std::make_shared<boost::asio::io_context::strand>(*m_io)).first;
    return found->second;
  }

  void on_strand(std::uint64_t id, std::uint32_t kind, const shekyl_seam_observed& observed, bool have_observed, const std::vector<std::uint8_t>& bytes)
  {
    std::shared_ptr<link_type> link;
    {
      std::lock_guard<std::mutex> lock(m_mu);
      if (kind == SHEKYL_SEAM_ESTABLISHED && have_observed)
      {
        if (m_links.find(id) == m_links.end())
        {
          auto created = link_type::create(*m_io, *m_strands.at(id), *m_config, id, observed, [this](std::uint64_t retired) {
            std::lock_guard<std::mutex> retire_lock(m_mu);
            m_links.erase(retired);
            m_strands.erase(retired);
          });
          m_links.emplace(id, created);
          link = std::move(created);
        }
      }
      else
      {
        auto found = m_links.find(id);
        if (found != m_links.end())
          link = found->second;
      }
    }
    if (kind == SHEKYL_SEAM_ESTABLISHED && link)
      shekyl_seam_handler_armed(id, link->arm() ? 1 : 0);
    else if (kind == SHEKYL_SEAM_DELIVER && link)
    {
      const bool accepted = link->take_bytes(bytes.data(), bytes.size());
      shekyl_seam_delivery_finished(id, accepted ? 1 : 0);
    }
    else if (kind == SHEKYL_SEAM_CLOSED && link)
    {
      shekyl_seam_handler_gone(id);
      link->begin_closed();
    }
  }

  std::shared_ptr<boost::asio::io_context> m_owned;
  boost::asio::io_context* m_io;
  bool m_owns_io;
  std::shared_ptr<config_type> m_config;
  std::shared_ptr<std::atomic<bool>> m_stopped;
  std::string m_prefix;
  int m_port = -1;
  int m_port_v6 = -1;
  std::uint64_t m_executor = 0;
  std::vector<boost::thread> m_threads;
  std::mutex m_mu;
  std::map<std::uint64_t, std::shared_ptr<boost::asio::io_context::strand>> m_strands;
  std::map<std::uint64_t, std::shared_ptr<link_type>> m_links;
};

} // namespace shekyl
