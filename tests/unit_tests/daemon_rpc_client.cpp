// Copyright (c) 2026, The Shekyl Foundation
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

// The `shekyld <command>` control client (src/daemon/rpc_client.h) over the
// real Rust transport export, against a one-shot HTTP acceptor on loopback.
// The property under test is the failure signal: `failed()` is what the
// process exit status is derived from, so it must be set on every failure
// shape the client can see and stay clear on a good answer.

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <string>
#include <thread>
#include <vector>

#include "daemon/rpc_client.h"

namespace
{
  // Accept `bodies.size()` connections; each is answered as a 200 JSON
  // response from the next body, then closed. First request is captured.
  class n_shot_http_server
  {
  public:
    explicit n_shot_http_server(std::vector<std::string> bodies)
      : m_bodies(std::move(bodies))
      , m_acceptor(m_io, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0))
      , m_thread([this] { serve(); })
    {}

    explicit n_shot_http_server(std::string body)
      : n_shot_http_server(std::vector<std::string>{std::move(body)})
    {}

    ~n_shot_http_server() { m_thread.join(); }

    uint16_t port() const { return m_acceptor.local_endpoint().port(); }
    const std::string& request() const { return m_request; }

  private:
    void serve()
    {
      for (const auto& body : m_bodies)
      {
        boost::asio::ip::tcp::socket socket(m_io);
        m_acceptor.accept(socket);
        boost::asio::streambuf buf;
        boost::system::error_code ec;
        boost::asio::read_until(socket, buf, "\r\n\r\n", ec);
        std::string head{boost::asio::buffers_begin(buf.data()), boost::asio::buffers_end(buf.data())};
        if (m_request.empty())
          m_request = head;
        const std::string response =
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        boost::asio::write(socket, boost::asio::buffer(response), ec);
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      }
    }

    std::vector<std::string> m_bodies;
    boost::asio::io_context m_io;
    boost::asio::ip::tcp::acceptor m_acceptor;
    std::string m_request;
    std::thread m_thread;
  };

  // Port 1 on loopback is connection-refused without a bind-then-drop race
  // (an ephemeral bind released on return can be reallocated under parallel
  // tests and produce a false pass or hang).
  constexpr uint16_t REFUSED_PORT = 1;
  constexpr uint32_t LOOPBACK = 0x0100007f; // 127.0.0.1 in epee's int32 form
}

TEST(daemon_rpc_client, good_answer_leaves_failed_clear)
{
  n_shot_http_server server(R"({"status":"OK","height":42})");
  tools::t_rpc_client client(LOOPBACK, server.port());
  cryptonote::COMMAND_RPC_GET_HEIGHT::request req{};
  cryptonote::COMMAND_RPC_GET_HEIGHT::response res{};
  ASSERT_TRUE(client.rpc_request(req, res, "/get_height", "fail"));
  EXPECT_EQ(res.height, 42u);
  EXPECT_FALSE(client.failed());
  EXPECT_EQ(server.request().rfind("POST /get_height HTTP/1.1", 0), 0u) << server.request();
}

TEST(daemon_rpc_client, refused_connection_sets_failed)
{
  tools::t_rpc_client client(LOOPBACK, REFUSED_PORT);
  EXPECT_FALSE(client.check_connection());
  EXPECT_TRUE(client.failed());
}

TEST(daemon_rpc_client, non_ok_status_sets_failed)
{
  n_shot_http_server server(R"({"status":"BUSY","height":0})");
  tools::t_rpc_client client(LOOPBACK, server.port());
  cryptonote::COMMAND_RPC_GET_HEIGHT::request req{};
  cryptonote::COMMAND_RPC_GET_HEIGHT::response res{};
  EXPECT_FALSE(client.rpc_request(req, res, "/get_height", "fail"));
  EXPECT_TRUE(client.failed());
}

TEST(daemon_rpc_client, json_rpc_error_member_sets_failed)
{
  n_shot_http_server server(R"({"jsonrpc":"2.0","id":"0","error":{"code":-32601,"message":"Method not found"}})");
  tools::t_rpc_client client(LOOPBACK, server.port());
  cryptonote::COMMAND_RPC_GET_VERSION::request req{};
  cryptonote::COMMAND_RPC_GET_VERSION::response res{};
  EXPECT_FALSE(client.basic_json_rpc_request(req, res, "get_version"));
  EXPECT_TRUE(client.failed());
  EXPECT_EQ(server.request().rfind("POST /json_rpc HTTP/1.1", 0), 0u) << server.request();
}

TEST(daemon_rpc_client, failure_is_sticky_across_a_later_success)
{
  // The exit status reflects the whole command, not the last request it
  // happened to make: a command that failed one request and then succeeded
  // at another must still report failure. Same client, two answers.
  n_shot_http_server server({
    std::string(R"({"status":"BUSY","height":0})"),
    std::string(R"({"status":"OK","height":1})"),
  });
  tools::t_rpc_client client(LOOPBACK, server.port());
  cryptonote::COMMAND_RPC_GET_HEIGHT::request req{};
  cryptonote::COMMAND_RPC_GET_HEIGHT::response res{};
  EXPECT_FALSE(client.rpc_request(req, res, "/get_height", "fail"));
  EXPECT_TRUE(client.failed());
  EXPECT_TRUE(client.rpc_request(req, res, "/get_height", "fail"));
  EXPECT_EQ(res.height, 1u);
  EXPECT_TRUE(client.failed());
}
