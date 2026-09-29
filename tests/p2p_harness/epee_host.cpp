// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// epee-host SEED TRANSCRIPT
//
// One connection on boosted_tcp_server. The transcript text is version 1
// in docs/design/P2P_DIFFERENTIAL_HARNESS.md. Seed 1's handshake fields
// are that document's in-process legs. This binary does not read the
// Rust encoder.

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "misc_log_ex.h"
#include "net/abstract_tcp_server2.h"
#include "net/levin_protocol_handler_async.h"
#include "p2p/p2p_protocol_defs.h"
#include "storages/levin_abstract_invoke2.h"

namespace {

constexpr uint64_t kSeed1 = 1;
constexpr auto kWait = std::chrono::seconds(3);

struct record {
  std::mutex mu;
  std::condition_variable cv;
  std::vector<uint8_t> delivered;
  std::vector<uint8_t> sent;
  bool invoke_done = false;
  bool closed = false;
  bool established = false;
};

record g_record;

struct harness_context : epee::net_utils::connection_context_base {
  static std::optional<size_t> get_max_bytes(uint32_t, uint32_t, int32_t* = nullptr) noexcept {
    return size_t{4 * 1024 * 1024};
  }
  static constexpr int handshake_command() noexcept { return 1001; }
  static constexpr bool session_established() noexcept { return false; }
};

struct tap : epee::net_utils::i_service_endpoint {
  epee::net_utils::i_service_endpoint* real;
  explicit tap(epee::net_utils::i_service_endpoint* real) : real(real) {}

  bool do_send(epee::byte_slice message) override {
    if (!message.empty() && message.data() != nullptr) {
      std::lock_guard<std::mutex> lock(g_record.mu);
      g_record.sent.insert(g_record.sent.end(), message.data(), message.data() + message.size());
    }
    return real->do_send(std::move(message));
  }
  bool close() override { return real->close(); }
  bool send_done() override { return real->send_done(); }
  bool call_run_once_service_io() override { return real->call_run_once_service_io(); }
  bool request_callback() override { return real->request_callback(); }
  boost::asio::io_context& get_io_context() override { return real->get_io_context(); }
  bool add_ref() override { return real->add_ref(); }
  bool release() override { return real->release(); }
};

struct recording_handler {
  using connection_context = harness_context;
  using config_type = epee::levin::async_protocol_handler_config<connection_context>;

  tap endpoint;
  epee::levin::async_protocol_handler<connection_context> inner;

  recording_handler(epee::net_utils::i_service_endpoint* ep, config_type& config, connection_context& ctx)
      : endpoint(ep), inner(&endpoint, config, ctx) {}

  bool handle_recv(const void* ptr, size_t cb) {
    if (ptr != nullptr && cb != 0) {
      std::lock_guard<std::mutex> lock(g_record.mu);
      auto* bytes = static_cast<const uint8_t*>(ptr);
      g_record.delivered.insert(g_record.delivered.end(), bytes, bytes + cb);
    }
    const bool ok = inner.handle_recv(ptr, cb);
    std::lock_guard<std::mutex> lock(g_record.mu);
    if (!g_record.invoke_done && (!g_record.sent.empty() || !ok)) {
      g_record.invoke_done = true;
      g_record.cv.notify_all();
    }
    return ok;
  }

  void after_init_connection() { inner.after_init_connection(); }
  void handle_qued_callback() { inner.handle_qued_callback(); }
  bool release_protocol() { return inner.release_protocol(); }
};

using handshake = nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>;

nodetool::basic_node_data seed1_node() {
  nodetool::basic_node_data node{};
  for (auto& byte : node.network_id)
    byte = 0x11;
  node.address = epee::net_utils::network_address(epee::net_utils::ipv4_network_address(0, 18080));
  node.support_flags = 0;
  return node;
}

cryptonote::CORE_SYNC_DATA seed1_sync() {
  cryptonote::CORE_SYNC_DATA sync{};
  sync.current_height = 1;
  sync.cumulative_difficulty = 2;
  sync.cumulative_difficulty_top64 = 0;
  std::memset(sync.top_id.data, 0xab, sizeof sync.top_id.data);
  sync.top_version = 0;
  return sync;
}

struct commands : epee::levin::levin_commands_handler<harness_context> {
  int invoke(int command, const epee::span<const uint8_t> in_buff, epee::byte_stream& buff_out, harness_context&) override {
    const bool handshake_invoke = command == handshake::ID;
    handshake::request req;
    epee::serialization::portable_storage in_ps;
    const bool loaded = handshake_invoke && in_ps.load_from_binary(in_buff, &default_levin_limits) && req.load(in_ps);
    if (loaded) {
      handshake::response rsp;
      rsp.node_data = seed1_node();
      rsp.payload_data = seed1_sync();
      epee::serialization::portable_storage out_ps;
      rsp.store(out_ps);
      if (!out_ps.store_to_binary(buff_out))
        return LEVIN_ERROR_FORMAT;
    }
    {
      std::lock_guard<std::mutex> lock(g_record.mu);
      g_record.established = loaded;
    }
    return loaded ? LEVIN_OK : LEVIN_ERROR_FORMAT;
  }

  int notify(int, const epee::span<const uint8_t>, harness_context&) override { return LEVIN_ERROR_FORMAT; }

  void on_connection_close(harness_context&) override {
    std::lock_guard<std::mutex> lock(g_record.mu);
    g_record.closed = true;
    g_record.cv.notify_all();
  }

  static void destroy(epee::levin::levin_commands_handler<harness_context>* ptr) { delete ptr; }
};

std::string hex(const std::vector<uint8_t>& bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kDigits[bytes[i] >> 4];
    out[i * 2 + 1] = kDigits[bytes[i] & 0x0f];
  }
  return out;
}

const char* end_word() {
  if (g_record.established)
    return "established";
  if (g_record.closed && g_record.sent.empty())
    return "closed";
  return "refused";
}

bool write_transcript(const std::string& path, uint64_t seed) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out)
    return false;
  out << "shekyl-p2p-transcript 1\n"
      << "seed " << seed << "\n"
      << "role host\n"
      << "sent " << hex(g_record.sent) << "\n"
      << "recv " << hex(g_record.delivered) << "\n"
      << "end " << end_word() << "\n";
  return static_cast<bool>(out);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "epee-host SEED TRANSCRIPT\n";
    return 1;
  }
  char* end = nullptr;
  const unsigned long long seed = std::strtoull(argv[1], &end, 10);
  if (end == argv[1] || *end != '\0') {
    std::cerr << "seed\n";
    return 1;
  }
  if (seed != kSeed1) {
    std::cerr << "no script for seed " << seed << "\n";
    return 1;
  }

  mlog_configure("", true);

  using server_t = epee::net_utils::boosted_tcp_server<recording_handler>;
  server_t server(epee::net_utils::e_connection_type_P2P);
  if (!server.init_server(0, "127.0.0.1", 0, "", false, true, epee::net_utils::ssl_support_t::e_ssl_support_disabled)) {
    std::cerr << "epee host failed to bind\n";
    return 1;
  }
  server.get_config_shared()->set_handler(new commands, &commands::destroy);
  if (!server.run_server(2, false)) {
    std::cerr << "epee host failed to start\n";
    return 1;
  }

  std::cout << "127.0.0.1:" << server.get_binded_port() << std::endl;

  {
    std::unique_lock<std::mutex> lock(g_record.mu);
    if (!g_record.cv.wait_for(lock, kWait, [] { return g_record.invoke_done || g_record.closed; })) {
      std::cerr << "epee host timed out\n";
      server.send_stop_signal();
      server.timed_wait_server_stop(5 * 1000);
      return 1;
    }
    if (g_record.established)
      g_record.cv.wait_for(lock, kWait, [] { return g_record.closed; });
  }

  const bool wrote = write_transcript(argv[2], seed);
  server.send_stop_signal();
  server.timed_wait_server_stop(5 * 1000);
  server.deinit_server();
  if (!wrote) {
    std::cerr << "epee host failed to write the transcript\n";
    return 1;
  }
  return 0;
}
