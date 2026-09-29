// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// epee-host SEED TRANSCRIPT [--after none|follow|send-over|pause]
//                          [--wait-ms N] [--pause-ms N] [--settle-ms N]
//                          [--over-bytes N]
//
// Recording server for boosted_tcp_server. The seed is a label on the
// transcript. Host behaviour after the first invoke is `--after`; the
// Rust driver owns the seed table and the durations. Handshake encode
// and decode stay here: that is the epee reference the harness diffs.

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "misc_log_ex.h"
#include "net/abstract_tcp_server2.h"
#include "net/levin_base.h"
#include "net/levin_protocol_handler_async.h"
#include "p2p/p2p_protocol_defs.h"
#include "shekyl/shekyl_ffi.h"
#include "storages/levin_abstract_invoke2.h"

namespace {

enum class after_handshake { none, follow, send_over, pause };

using handshake = nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>;
using timed_sync = nodetool::COMMAND_TIMED_SYNC_T<cryptonote::CORE_SYNC_DATA>;

constexpr std::chrono::milliseconds kDefaultWait{8000};
constexpr uint32_t kServerStopMs = 5000;
constexpr uint16_t kAdvertisedPort = 18080;
constexpr uint8_t kNetworkIdByte = 0x11;
constexpr uint8_t kTopIdByte = 0xab;

struct host_plan {
  uint64_t seed = 0;
  std::string transcript;
  after_handshake after = after_handshake::none;
  std::chrono::milliseconds wait{kDefaultWait};
  std::chrono::milliseconds pause{0};
  std::chrono::milliseconds settle{0};
  std::size_t over_bytes = 0;
};

struct record {
  std::mutex mu;
  std::condition_variable cv;
  std::vector<uint8_t> delivered;
  std::vector<uint8_t> sent;
  bool invoke_done = false;
  bool closed = false;
  bool established = false;
  bool after_done = false;
};

record g_record;
host_plan g_plan;

after_handshake parse_after(const std::string& text) {
  if (text == "none")
    return after_handshake::none;
  if (text == "follow")
    return after_handshake::follow;
  if (text == "send-over")
    return after_handshake::send_over;
  if (text == "pause")
    return after_handshake::pause;
  throw std::runtime_error("unknown after " + text);
}

unsigned long parse_ulong(const char* text, const char* name) {
  char* end = nullptr;
  const unsigned long value = std::strtoul(text, &end, 10);
  if (end == text || *end != '\0')
    throw std::runtime_error(std::string(name) + " is not an integer");
  return value;
}

host_plan parse_args(int argc, char** argv) {
  if (argc < 3)
    throw std::runtime_error(
        "epee-host SEED TRANSCRIPT [--after none|follow|send-over|pause] "
        "[--wait-ms N] [--pause-ms N] [--settle-ms N] [--over-bytes N]");
  host_plan plan;
  char* end = nullptr;
  plan.seed = std::strtoull(argv[1], &end, 10);
  if (end == argv[1] || *end != '\0')
    throw std::runtime_error("seed");
  plan.transcript = argv[2];
  for (int i = 3; i < argc; ++i) {
    const std::string flag = argv[i];
    auto need = [&](const char* name) -> const char* {
      if (i + 1 >= argc)
        throw std::runtime_error(std::string("missing ") + name);
      return argv[++i];
    };
    if (flag == "--after")
      plan.after = parse_after(need("after"));
    else if (flag == "--wait-ms")
      plan.wait = std::chrono::milliseconds(parse_ulong(need("wait-ms"), "wait-ms"));
    else if (flag == "--pause-ms")
      plan.pause = std::chrono::milliseconds(parse_ulong(need("pause-ms"), "pause-ms"));
    else if (flag == "--settle-ms")
      plan.settle = std::chrono::milliseconds(parse_ulong(need("settle-ms"), "settle-ms"));
    else if (flag == "--over-bytes")
      plan.over_bytes = static_cast<std::size_t>(parse_ulong(need("over-bytes"), "over-bytes"));
    else
      throw std::runtime_error("unknown flag " + flag);
  }
  if (plan.after == after_handshake::pause && plan.pause.count() <= 0)
    throw std::runtime_error("pause requires --pause-ms");
  if (plan.after == after_handshake::send_over && plan.over_bytes == 0)
    throw std::runtime_error("send-over requires --over-bytes");
  return plan;
}

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
  static constexpr int handshake_command() noexcept { return handshake::ID; }
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
  return writer.finalize_notify(static_cast<uint32_t>(timed_sync::ID));
}

void apply_after(tap& endpoint) {
  {
    std::lock_guard<std::mutex> lock(g_record.mu);
    if (g_record.after_done || !g_record.established)
      return;
    g_record.after_done = true;
  }
  switch (g_plan.after) {
    case after_handshake::follow:
      endpoint.do_send(relay_notify());
      break;
    case after_handshake::send_over: {
      std::this_thread::sleep_for(g_plan.settle);
      std::vector<uint8_t> over(g_plan.over_bytes, 0);
      endpoint.do_send(epee::byte_slice{std::move(over)});
      break;
    }
    case after_handshake::pause:
      std::this_thread::sleep_for(g_plan.pause);
      break;
    case after_handshake::none:
      break;
  }
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
    apply_after(endpoint);
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

nodetool::basic_node_data seed1_node() {
  nodetool::basic_node_data node{};
  for (auto& byte : node.network_id)
    byte = kNetworkIdByte;
  node.address = epee::net_utils::network_address(epee::net_utils::ipv4_network_address(0, kAdvertisedPort));
  node.support_flags = 0;
  return node;
}

cryptonote::CORE_SYNC_DATA seed1_sync() {
  cryptonote::CORE_SYNC_DATA sync{};
  sync.current_height = 1;
  sync.cumulative_difficulty = 2;
  sync.cumulative_difficulty_top64 = 0;
  std::memset(sync.top_id.data, kTopIdByte, sizeof sync.top_id.data);
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
      ctx.established_session = true;
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

void write_events(std::ostream& out) {
  std::size_t off = 0;
  bool first = true;
  while (off + sizeof(epee::levin::bucket_head2) <= g_record.delivered.size()) {
    epee::levin::bucket_head2 head{};
    std::memcpy(&head, g_record.delivered.data() + off, sizeof head);
    const std::size_t total = sizeof(head) + static_cast<std::size_t>(head.m_cb);
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

bool write_transcript(const std::string& path) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out)
    return false;
  const bool version2 = g_plan.after == after_handshake::pause;
  out << (version2 ? "shekyl-p2p-transcript 2" : "shekyl-p2p-transcript 1") << "\n"
      << "seed " << g_plan.seed << "\n"
      << "role host\n"
      << "sent " << hex(g_record.sent) << "\n"
      << "recv " << hex(g_record.delivered) << "\n"
      << "end " << end_word() << "\n";
  if (version2)
    write_events(out);
  return static_cast<bool>(out);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    g_plan = parse_args(argc, argv);
  } catch (const std::exception& err) {
    std::cerr << err.what() << "\n";
    return 1;
  }

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
    if (!g_record.cv.wait_for(lock, g_plan.wait, [] { return g_record.invoke_done || g_record.closed; })) {
      std::cerr << "epee host timed out\n";
      server.send_stop_signal();
      server.timed_wait_server_stop(kServerStopMs);
      return 1;
    }
    if (g_record.established || g_record.invoke_done)
      g_record.cv.wait_for(lock, g_plan.wait, [] { return g_record.closed; });
  }

  const bool wrote = write_transcript(g_plan.transcript);
  server.send_stop_signal();
  server.timed_wait_server_stop(kServerStopMs);
  server.deinit_server();
  if (!wrote) {
    std::cerr << "epee host failed to write the transcript\n";
    return 1;
  }
  return 0;
}
