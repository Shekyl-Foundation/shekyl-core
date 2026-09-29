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
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

extern "C" int32_t shekyl_levin_ingress_admit(uint32_t command, uint32_t flags, uint64_t* out_cap);

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "misc_log_ex.h"
#include "net/abstract_tcp_server2.h"
#include "net/levin_protocol_handler_async.h"
#include "p2p/p2p_protocol_defs.h"
#include "storages/levin_abstract_invoke2.h"

namespace {

constexpr uint64_t kSeedBackpressure = 40;
constexpr uint64_t kSeedConcurrent = 20;
constexpr uint64_t kSeedSendOver = 32;
constexpr auto kPause = std::chrono::milliseconds(400);
constexpr std::size_t kSendCap = 64 * 1024;

bool known_seed(uint64_t seed) {
  switch (seed) {
    case 1:
    case 2:
    case 3:
    case 10:
    case 11:
    case 20:
    case 30:
    case 31:
    case 32:
    case 40:
      return true;
    default:
      return seed >= 100 && seed < 116;
  }
}

std::chrono::seconds wait_for(uint64_t seed) {
  if (seed == 11 || seed == 40)
    return std::chrono::seconds(20);
  return std::chrono::seconds(8);
}

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
uint64_t g_seed = 0;
bool g_paused = false;
bool g_followed = false;
bool g_over_sent = false;

struct harness_context : epee::net_utils::connection_context_base {
  bool established_session = false;

  std::optional<size_t> get_max_bytes(uint32_t command, uint32_t flags, int32_t* rc) const noexcept {
    uint64_t cap = 0;
    const int32_t code = shekyl_levin_ingress_admit(command, flags, &cap);
    if (rc)
      *rc = code;
    if (code != 0)
      return std::nullopt;
    return static_cast<size_t>(cap);
  }
  static constexpr int handshake_command() noexcept { return 1001; }
  bool session_established() const noexcept { return established_session; }
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

epee::byte_slice relay_notify() {
  epee::levin::message_writer writer;
  const char payload[] = {'r', 'e', 'l', 'a', 'y'};
  writer.buffer.write(payload, sizeof payload);
  return writer.finalize_notify(1002);
}

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
    if (g_seed == kSeedConcurrent && !g_followed) {
      bool established = false;
      {
        std::lock_guard<std::mutex> lock(g_record.mu);
        established = g_record.established;
      }
      if (established) {
        g_followed = true;
        endpoint.do_send(relay_notify());
      }
    }
    if (g_seed == kSeedSendOver && !g_over_sent) {
      bool established = false;
      {
        std::lock_guard<std::mutex> lock(g_record.mu);
        established = g_record.established;
      }
      if (established) {
        g_over_sent = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::vector<uint8_t> over(kSendCap + 1, 0);
        endpoint.do_send(epee::byte_slice{std::move(over)});
      }
    }
    if (g_seed == kSeedBackpressure && !g_paused) {
      bool established = false;
      {
        std::lock_guard<std::mutex> lock(g_record.mu);
        established = g_record.established;
      }
      if (established) {
        g_paused = true;
        std::this_thread::sleep_for(kPause);
      }
    }
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
  int invoke(int command, const epee::span<const uint8_t> in_buff, epee::byte_stream& buff_out, harness_context& ctx) override {
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
    if (loaded)
      ctx.established_session = true;
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

void write_events(std::ostream& out) {
  std::size_t off = 0;
  bool first = true;
  while (off + 29 <= g_record.delivered.size()) {
    uint64_t payload = 0;
    std::memcpy(&payload, g_record.delivered.data() + off + 8, sizeof payload);
    const std::size_t total = 29 + static_cast<std::size_t>(payload);
    if (off + total > g_record.delivered.size())
      break;
    std::vector<uint8_t> message(g_record.delivered.begin() + static_cast<std::ptrdiff_t>(off),
                                 g_record.delivered.begin() + static_cast<std::ptrdiff_t>(off + total));
    out << "event read " << hex(message) << "\n";
    if (first) {
      out << "event wrote " << hex(g_record.sent) << "\n";
      out << "event stalled\n";
      out << "event resumed\n";
      first = false;
    }
    off += total;
  }
}

bool write_transcript(const std::string& path, uint64_t seed) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out)
    return false;
  const char* version = seed == kSeedBackpressure ? "shekyl-p2p-transcript 2" : "shekyl-p2p-transcript 1";
  out << version << "\n"
      << "seed " << seed << "\n"
      << "role host\n"
      << "sent " << hex(g_record.sent) << "\n"
      << "recv " << hex(g_record.delivered) << "\n"
      << "end " << end_word() << "\n";
  if (seed == kSeedBackpressure)
    write_events(out);
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
  if (!known_seed(seed)) {
    std::cerr << "no script for seed " << seed << "\n";
    return 1;
  }
  g_seed = seed;

  mlog_configure("", true);

  // A P2P connection enables epee's rate limiter. Unset, its target is
  // 16 KiB/s, which is not a Levin rule. The harness raises it so the
  // comparison is the bytes. The seam has no such limiter.
  using connection_t = epee::net_utils::connection<recording_handler>;
  connection_t::set_rate_up_limit(std::numeric_limits<int64_t>::max());
  connection_t::set_rate_down_limit(std::numeric_limits<int64_t>::max());

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
    const auto wait = wait_for(seed);
    if (!g_record.cv.wait_for(lock, wait, [] { return g_record.invoke_done || g_record.closed; })) {
      std::cerr << "epee host timed out\n";
      server.send_stop_signal();
      server.timed_wait_server_stop(5 * 1000);
      return 1;
    }
    if (g_record.established || g_record.invoke_done)
      g_record.cv.wait_for(lock, wait_for(seed), [] { return g_record.closed; });
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
