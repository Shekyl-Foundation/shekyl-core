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

#pragma once

// The `shekyld <command>` control client: `shekyld status`, `shekyld exit`, …
// run as a second process and reach the running daemon over its plaintext
// loopback RPC. The transport is the Rust `shekyl_daemon_ctl_post` export
// (shekyl-daemon-rpc/src/ctl_client.rs, over shekyl-rpc-transport); this
// header owns only the request/response structs and their epee JSON framing,
// which Phase 2 of docs/DAEMON_RPC_RUST.md retires in turn.

#include <chrono>
#include <cstdint>
#include <string>

#include "common/scoped_message_writer.h"
#include "net/jsonrpc_structs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "shekyl/shekyl_ffi.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"

namespace tools
{
  class t_rpc_client final
  {
  private:
    std::string m_address; // host:port of the daemon's RPC listener

    static constexpr std::chrono::seconds TIMEOUT()
    {
      return std::chrono::minutes(3) + std::chrono::seconds(30);
    }

    // One POST over the Rust transport. On success `body` holds the response
    // body; on failure `reason` names what went wrong and `body` is untouched.
    bool post(const std::string& route, const std::string& payload, std::string& body, std::string& reason) const
    {
      uint8_t* out_ptr = nullptr;
      size_t out_len = 0;
      const int32_t rc = shekyl_daemon_ctl_post(
        m_address.c_str(),
        route.c_str(),
        reinterpret_cast<const uint8_t*>(payload.data()),
        payload.size(),
        static_cast<uint64_t>(TIMEOUT().count()),
        &out_ptr,
        &out_len);
      std::string out(reinterpret_cast<const char*>(out_ptr), out_ptr ? out_len : 0);
      shekyl_daemon_ctl_free(out_ptr, out_len);
      if (rc == SHEKYL_DAEMON_CTL_OK)
      {
        body = std::move(out);
        return true;
      }
      reason = out.empty() ? ("control client error " + std::to_string(rc)) : std::move(out);
      return false;
    }

    template <typename T_req, typename T_res>
    bool invoke_json(const std::string& route, T_req& req, T_res& res, std::string& reason) const
    {
      std::string payload;
      if (!epee::serialization::store_t_to_json(req, payload))
      {
        reason = "failed to serialize request";
        return false;
      }
      std::string body;
      if (!post(route, payload, body, reason))
        return false;
      if (!epee::serialization::load_t_from_json(res, body))
      {
        reason = "malformed response body";
        return false;
      }
      return true;
    }

    // JSON-RPC 2.0 envelope over `/json_rpc`. A daemon-side `error` member is
    // reported through `reason`; `res` is filled only on success.
    template <typename T_req, typename T_res>
    bool invoke_json_rpc(const std::string& method_name, T_req& req, T_res& res, std::string& reason) const
    {
      epee::json_rpc::request<T_req> envelope{};
      envelope.jsonrpc = "2.0";
      envelope.id = std::string("0");
      envelope.method = method_name;
      envelope.params = req;
      epee::json_rpc::response<T_res, epee::json_rpc::error> reply{};
      if (!invoke_json("/json_rpc", envelope, reply, reason))
        return false;
      if (reply.error.code != 0 || !reply.error.message.empty())
      {
        reason = reply.error.message.empty()
          ? ("error " + std::to_string(reply.error.code))
          : reply.error.message;
        return false;
      }
      res = reply.result;
      return true;
    }

  public:
    t_rpc_client(uint32_t ip, uint16_t port)
      : m_address(epee::string_tools::get_ip_string_from_int32(ip) + ":" + std::to_string(port))
    {}

    template <typename T_req, typename T_res>
    bool basic_json_rpc_request(T_req& req, T_res& res, std::string const& method_name)
    {
      std::string reason;
      if (!invoke_json_rpc(method_name, req, res, reason))
      {
        fail_msg_writer() << "Daemon request failed (" << m_address << "): " << reason;
        return false;
      }
      return true;
    }

    template <typename T_req, typename T_res>
    bool json_rpc_request(T_req& req, T_res& res, std::string const& method_name, std::string const& fail_msg)
    {
      std::string reason;
      if (!invoke_json_rpc(method_name, req, res, reason))
      {
        fail_msg_writer() << fail_msg << " -- json_rpc_request: " << reason;
        return false;
      }
      if (res.status != CORE_RPC_STATUS_OK) // TODO - handle CORE_RPC_STATUS_BUSY ?
      {
        fail_msg_writer() << fail_msg << " -- json_rpc_request: " << res.status;
        return false;
      }
      return true;
    }

    template <typename T_req, typename T_res>
    bool rpc_request(T_req& req, T_res& res, std::string const& relative_url, std::string const& fail_msg)
    {
      std::string reason;
      if (!invoke_json(relative_url, req, res, reason))
      {
        fail_msg_writer() << fail_msg << " -- rpc_request: " << reason;
        return false;
      }
      if (res.status != CORE_RPC_STATUS_OK) // TODO - handle CORE_RPC_STATUS_BUSY ?
      {
        fail_msg_writer() << fail_msg << " -- rpc_request: " << res.status;
        return false;
      }
      return true;
    }

    // Liveness: a `/get_height` round trip that the transport completes. The
    // reply's content is not consulted — any answer means a daemon is there.
    bool check_connection()
    {
      cryptonote::COMMAND_RPC_GET_HEIGHT::request req{};
      cryptonote::COMMAND_RPC_GET_HEIGHT::response res{};
      std::string reason;
      return invoke_json("/get_height", req, res, reason);
    }
  };
}
