// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include <chrono>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/thread/thread.hpp>

#include "gtest/gtest.h"

#include "net/levin_base.h"
#include "p2p/seam_endpoint.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
  struct context : public epee::net_utils::connection_context_base
  {
    static constexpr int handshake_command() noexcept { return 1001; }
    static constexpr bool session_established() noexcept { return false; }
    std::optional<std::size_t> get_max_bytes(std::uint32_t, std::uint32_t, std::int32_t* = nullptr) const
    {
      return LEVIN_DEFAULT_MAX_PACKET_SIZE;
    }
  };

  using config_t = epee::levin::async_protocol_handler_config<context>;
  using handler_t = epee::levin::async_protocol_handler<context>;

  struct commands : public epee::levin::levin_commands_handler<context>
  {
    int invoke(int, const epee::span<const std::uint8_t>, epee::byte_stream&, context&) override { return LEVIN_OK; }
    int notify(int, const epee::span<const std::uint8_t>, context&) override { return LEVIN_OK; }
  };

  struct pool
  {
    boost::asio::io_context io;
    std::mutex mu;
    std::map<std::uint64_t, std::shared_ptr<boost::asio::io_context::strand>> strands;
    std::map<std::uint64_t, std::unique_ptr<shekyl::seam_link<context, handler_t, config_t>>> links;
    std::vector<std::uint32_t> order;
    config_t config;

    std::shared_ptr<boost::asio::io_context::strand> strand_for(std::uint64_t id)
    {
      std::lock_guard<std::mutex> lock(mu);
      auto found = strands.find(id);
      if (found == strands.end())
        found = strands.emplace(id, std::make_shared<boost::asio::io_context::strand>(io)).first;
      return found->second;
    }
  };

  void on_strand(pool* ex, std::uint64_t id, std::uint32_t kind, std::vector<std::uint8_t> bytes)
  {
    shekyl::seam_link<context, handler_t, config_t>* link = nullptr;
    {
      std::lock_guard<std::mutex> lock(ex->mu);
      ex->order.push_back(kind);
      if (kind == SHEKYL_SEAM_ESTABLISHED)
      {
        auto created = std::make_unique<shekyl::seam_link<context, handler_t, config_t>>(
            ex->io, *ex->strands.at(id), ex->config, id);
        link = created.get();
        ex->links.emplace(id, std::move(created));
      }
      else
      {
        auto found = ex->links.find(id);
        if (found != ex->links.end())
          link = found->second.get();
      }
    }

    if (kind == SHEKYL_SEAM_ESTABLISHED && link != nullptr && link->arm())
      shekyl_seam_handler_ready(id);
    else if (kind == SHEKYL_SEAM_DELIVER && link != nullptr)
    {
      const bool accepted = link->take_bytes(bytes.data(), bytes.size());
      shekyl_seam_deliver_result(id, bytes.data(), bytes.size(), accepted ? 1 : 0);
    }
    else if (kind == SHEKYL_SEAM_CLOSED && link != nullptr)
    {
      shekyl_seam_handler_gone(id);
      link->begin_closed();
    }
  }

  void post_to_strand(void* ctx, std::uint64_t id, std::uint32_t kind, const std::uint8_t* bytes, std::size_t len, const shekyl_close_cause*)
  {
    auto* ex = static_cast<pool*>(ctx);
    std::vector<std::uint8_t> copy;
    if (bytes != nullptr && len != 0)
      copy.assign(bytes, bytes + len);
    auto strand = ex->strand_for(id);
    boost::asio::post(*strand, [ex, id, kind, copy] { on_strand(ex, id, kind, copy); });
  }
}

TEST(seam_endpoint, the_executor_refuses_one_below_the_floor)
{
  std::uint64_t handle = 1;
  EXPECT_EQ(shekyl_executor_record("p2p-exec", 1, 1, &handle), 0);
}

TEST(seam_endpoint, connect_from_the_executor_completes_at_the_floor)
{
  std::uint64_t handle = 0;
  ASSERT_EQ(shekyl_executor_record("p2p-exec", 1, 2, &handle), 1);

  pool ex;
  commands cmds;
  ex.config.set_handler(&cmds, nullptr);
  shekyl_seam_bind(&ex, &post_to_strand);

  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work(ex.io.get_executor());
  boost::thread_group threads;
  threads.create_thread([&ex] { ex.io.run(); });
  threads.create_thread([&ex] { ex.io.run(); });

  std::promise<int> done;
  auto waited = done.get_future();
  boost::asio::post(ex.io, [&done] {
    const std::uint64_t id = shekyl_seam_open_outbound(0xCB00710A);
    done.set_value(id == 0 ? -1 : shekyl_seam_await_handler(id));
  });

  ASSERT_EQ(waited.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  EXPECT_EQ(waited.get(), 0);

  ex.io.stop();
  threads.join_all();
  shekyl_seam_bind(nullptr, nullptr);
  shekyl_executor_release(handle);
}

TEST(seam_endpoint, a_delivery_posted_before_closed_is_parsed)
{
  pool ex;
  commands cmds;
  ex.config.set_handler(&cmds, nullptr);
  shekyl_seam_bind(&ex, &post_to_strand);

  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work(ex.io.get_executor());
  boost::thread runner([&ex] { ex.io.run(); });

  const std::uint64_t id = shekyl_seam_open_outbound(0xCB00710A);
  ASSERT_NE(id, 0u);
  ASSERT_EQ(shekyl_seam_await_handler(id), 0);

  const std::uint8_t bytes[] = {'h', 'e', 'l', 'l', 'o'};
  ASSERT_EQ(shekyl_seam_deliver(id, bytes, sizeof(bytes)), 0);
  shekyl_seam_close(id);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (std::chrono::steady_clock::now() < deadline)
  {
    std::lock_guard<std::mutex> lock(ex.mu);
    if (ex.order.size() >= 3)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ex.io.stop();
  runner.join();

  ASSERT_GE(ex.order.size(), 3u);
  EXPECT_EQ(ex.order[0], SHEKYL_SEAM_ESTABLISHED);
  EXPECT_EQ(ex.order[1], SHEKYL_SEAM_DELIVER);
  EXPECT_EQ(ex.order[2], SHEKYL_SEAM_CLOSED);

  shekyl_close_cause cause{};
  EXPECT_EQ(shekyl_seam_cause(id, &cause), 1);
  EXPECT_EQ(cause.kind, SHEKYL_CLOSE_LOCAL_CLOSE);
  shekyl_seam_bind(nullptr, nullptr);
}
