// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/thread/thread.hpp>

#include "gtest/gtest.h"

#include "net/levin_base.h"
#include "p2p/seam_board.h"
#include "p2p/seam_endpoint.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
  struct context : public epee::net_utils::connection_context_base
  {
    using connection_context_base::connection_context_base;
    context(boost::uuids::uuid connection_id, const epee::net_utils::network_address& remote_address, bool is_income)
      : connection_context_base(connection_id, remote_address, is_income, false)
    {}
    static constexpr int handshake_command() noexcept { return 1001; }
    static constexpr bool session_established() noexcept { return false; }
    std::optional<std::size_t> get_max_bytes(std::uint32_t, std::uint32_t, std::int32_t* = nullptr) const
    {
      return LEVIN_DEFAULT_MAX_PACKET_SIZE;
    }
  };

  using config_t = epee::levin::async_protocol_handler_config<context>;
  using handler_t = epee::levin::async_protocol_handler<context>;
  using link_t = shekyl::seam_link<context, handler_t, config_t>;

  struct commands : public epee::levin::levin_commands_handler<context>
  {
    int invoke(int, const epee::span<const std::uint8_t>, epee::byte_stream&, context&) override { return LEVIN_OK; }
    int notify(int, const epee::span<const std::uint8_t>, context&) override { return LEVIN_OK; }
  };

  struct pool
  {
    // `config` and the strands outlive the links: a handler destructor
    // calls back into the config, and the link holds the strand by reference.
    boost::asio::io_context io;
    std::mutex mu;
    config_t config;
    std::map<std::uint64_t, std::shared_ptr<boost::asio::io_context::strand>> strands;
    std::vector<std::uint32_t> order;
    std::map<std::uint64_t, shekyl_close_cause> causes;
    std::map<std::uint64_t, std::shared_ptr<link_t>> links;

    std::shared_ptr<boost::asio::io_context::strand> strand_for(std::uint64_t id)
    {
      std::lock_guard<std::mutex> lock(mu);
      auto found = strands.find(id);
      if (found == strands.end())
        found = strands.emplace(id, std::make_shared<boost::asio::io_context::strand>(io)).first;
      return found->second;
    }
  };
}

TEST(seam_endpoint, add_ref_fails_once_closed_and_does_not_use_a_destroyed_handler)
{
  commands cmds;
  pool ex;
  ex.config.set_handler(&cmds, nullptr);
  boost::asio::io_context::strand strand(ex.io);
  shekyl_seam_observed obs{};
  obs.connector = SHEKYL_CONNECTOR_CLEARNET;
  obs.direction = SHEKYL_DIRECTION_INBOUND;
  obs.address_type = SHEKYL_ADDR_IPV4;
  obs.port = 18080;
  obs.len = 4;
  obs.bytes[0] = 203;
  obs.bytes[3] = 10;
  auto link = link_t::create(ex.io, strand, ex.config, 7, obs, {});
  ASSERT_TRUE(link->arm());
  auto* raw = link.get();

  std::atomic<int> failures{0};
  std::atomic<bool> run{true};
  boost::thread_group walkers;
  for (int i = 0; i < 4; ++i)
  {
    walkers.create_thread([raw, &failures, &run] {
      while (run.load(std::memory_order_acquire))
      {
        if (!raw->add_ref())
          return;
        if (raw->destroyed())
          failures.fetch_add(1, std::memory_order_relaxed);
        raw->release();
      }
    });
  }

  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work(ex.io.get_executor());
  boost::thread runner([&ex] { ex.io.run(); });
  boost::asio::post(strand, [raw] { raw->begin_closed(); });

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!raw->destroyed() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  run.store(false, std::memory_order_release);
  walkers.join_all();
  ex.io.stop();
  runner.join();

  EXPECT_TRUE(raw->destroyed());
  EXPECT_EQ(failures.load(), 0);
  EXPECT_FALSE(raw->add_ref());
}
