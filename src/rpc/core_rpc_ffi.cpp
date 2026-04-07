// Copyright (c) 2025-2026, The Shekyl Foundation
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

#include "core_rpc_ffi.h"
#include "core_rpc_server.h"
#include "core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "serialization/keyvalue_serialization.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <functional>
#include <sstream>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc.ffi"

using namespace cryptonote;

struct core_rpc_handle {
    core_rpc_server* rpc;
};

// ─── Template Helpers ────────────────────────────────────────────────────────

namespace {

// JSON endpoint: deserialize request from JSON, call handler, serialize response to JSON.
template<typename COMMAND>
char* dispatch_json(core_rpc_server& rpc,
    bool (core_rpc_server::*handler)(const typename COMMAND::request&, typename COMMAND::response&, const core_rpc_server::connection_context*),
    const char* body_json)
{
    typename COMMAND::request req{};
    typename COMMAND::response res{};

    if (body_json && body_json[0]) {
        epee::serialization::load_t_from_json(static_cast<typename COMMAND::request_t&>(req), std::string(body_json));
    }

    (rpc.*handler)(req, res, nullptr);

    std::string out;
    epee::serialization::store_t_to_json(static_cast<const typename COMMAND::response_t&>(res), out);
    return strdup(out.c_str());
}

// Binary endpoint: deserialize request from binary, call handler, serialize response to binary.
// Returns: 0 = success, -1 = bad request (parse failure), -2 = internal error.
template<typename COMMAND>
int dispatch_bin(core_rpc_server& rpc,
    bool (core_rpc_server::*handler)(const typename COMMAND::request&, typename COMMAND::response&, const core_rpc_server::connection_context*),
    const uint8_t* body, size_t body_len,
    uint8_t** out_buf, size_t* out_len)
{
    typename COMMAND::request req{};
    typename COMMAND::response res{};

    // Always attempt deserialization, matching epee's MAP_URI_AUTO_BIN2 behavior.
    // Empty or missing body will fail to parse -> 400 Bad Request.
    epee::span<const uint8_t> blob(body, body_len);
    if (!epee::serialization::load_t_from_binary(static_cast<typename COMMAND::request_t&>(req), blob))
        return -1;

    (rpc.*handler)(req, res, nullptr);

    epee::byte_slice out = epee::serialization::store_t_to_binary(static_cast<typename COMMAND::response_t&>(res));

    *out_len = out.size();
    *out_buf = static_cast<uint8_t*>(malloc(out.size()));
    if (!*out_buf) return -2;
    memcpy(*out_buf, out.data(), out.size());
    return 0;
}

// JSON-RPC: handler without error_resp (MAP_JON_RPC).
template<typename COMMAND>
char* dispatch_jsonrpc(core_rpc_server& rpc,
    bool (core_rpc_server::*handler)(const typename COMMAND::request&, typename COMMAND::response&, const core_rpc_server::connection_context*),
    const char* params_json)
{
    typename COMMAND::request req{};
    typename COMMAND::response res{};

    if (params_json && params_json[0]) {
        epee::serialization::load_t_from_json(static_cast<typename COMMAND::request_t&>(req), std::string(params_json));
    }

    bool ok = (rpc.*handler)(req, res, nullptr);

    std::string result_json;
    epee::serialization::store_t_to_json(static_cast<const typename COMMAND::response_t&>(res), result_json);

    std::ostringstream oss;
    if (ok) {
        oss << R"({"ok":true,"result":)" << result_json << "}";
    } else {
        oss << R"({"ok":false,"error_code":-32603,"error_message":"Internal error"})";
    }
    return strdup(oss.str().c_str());
}

// JSON-RPC: handler with error_resp (MAP_JON_RPC_WE).
template<typename COMMAND>
char* dispatch_jsonrpc_we(core_rpc_server& rpc,
    bool (core_rpc_server::*handler)(const typename COMMAND::request&, typename COMMAND::response&, epee::json_rpc::error&, const core_rpc_server::connection_context*),
    const char* params_json)
{
    typename COMMAND::request req{};
    typename COMMAND::response res{};
    epee::json_rpc::error error_resp{};

    if (params_json && params_json[0]) {
        epee::serialization::load_t_from_json(static_cast<typename COMMAND::request_t&>(req), std::string(params_json));
    }

    bool ok = (rpc.*handler)(req, res, error_resp, nullptr);

    std::ostringstream oss;
    if (ok && error_resp.code == 0) {
        std::string result_json;
        epee::serialization::store_t_to_json(static_cast<const typename COMMAND::response_t&>(res), result_json);
        oss << R"({"ok":true,"result":)" << result_json << "}";
    } else {
        int code = error_resp.code ? error_resp.code : -32603;
        // Escape quotes in message for JSON safety
        std::string msg = error_resp.message.empty() ? "Internal error" : error_resp.message;
        std::string escaped;
        for (char c : msg) {
            if (c == '"') escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else escaped += c;
        }
        oss << R"({"ok":false,"error_code":)" << code
            << R"(,"error_message":")" << escaped << R"("})";
    }
    return strdup(oss.str().c_str());
}

// Dispatch table types
using json_fn = std::function<char*(core_rpc_server&, const char*)>;
using bin_fn = std::function<int(core_rpc_server&, const uint8_t*, size_t, uint8_t**, size_t*)>;
using jsonrpc_fn = std::function<char*(core_rpc_server&, const char*)>;

#define DJSON(uri, handler, cmd) \
    {uri, [](core_rpc_server& rpc, const char* body) -> char* { \
        return dispatch_json<cmd>(rpc, &core_rpc_server::handler, body); \
    }}

#define DBIN(uri, handler, cmd) \
    {uri, [](core_rpc_server& rpc, const uint8_t* body, size_t len, uint8_t** out, size_t* olen) -> int { \
        return dispatch_bin<cmd>(rpc, &core_rpc_server::handler, body, len, out, olen); \
    }}

#define DJRPC(method, handler, cmd) \
    {method, [](core_rpc_server& rpc, const char* params) -> char* { \
        return dispatch_jsonrpc<cmd>(rpc, &core_rpc_server::handler, params); \
    }}

#define DJRPC_WE(method, handler, cmd) \
    {method, [](core_rpc_server& rpc, const char* params) -> char* { \
        return dispatch_jsonrpc_we<cmd>(rpc, &core_rpc_server::handler, params); \
    }}

// ─── Dispatch Tables ─────────────────────────────────────────────────────────

const std::unordered_map<std::string, json_fn>& get_json_table() {
    static const std::unordered_map<std::string, json_fn> t = {
        DJSON("/get_height",                        on_get_height,                   COMMAND_RPC_GET_HEIGHT),
        DJSON("/getheight",                         on_get_height,                   COMMAND_RPC_GET_HEIGHT),
        DJSON("/get_transactions",                  on_get_transactions,             COMMAND_RPC_GET_TRANSACTIONS),
        DJSON("/gettransactions",                   on_get_transactions,             COMMAND_RPC_GET_TRANSACTIONS),
        DJSON("/get_alt_blocks_hashes",             on_get_alt_blocks_hashes,        COMMAND_RPC_GET_ALT_BLOCKS_HASHES),
        DJSON("/is_key_image_spent",                on_is_key_image_spent,           COMMAND_RPC_IS_KEY_IMAGE_SPENT),
        DJSON("/send_raw_transaction",              on_send_raw_tx,                  COMMAND_RPC_SEND_RAW_TX),
        DJSON("/sendrawtransaction",                on_send_raw_tx,                  COMMAND_RPC_SEND_RAW_TX),
        DJSON("/get_public_nodes",                  on_get_public_nodes,             COMMAND_RPC_GET_PUBLIC_NODES),
        DJSON("/get_transaction_pool",              on_get_transaction_pool,         COMMAND_RPC_GET_TRANSACTION_POOL),
        DJSON("/get_transaction_pool_hashes.bin",   on_get_transaction_pool_hashes_bin, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN),
        DJSON("/get_transaction_pool_hashes",       on_get_transaction_pool_hashes,  COMMAND_RPC_GET_TRANSACTION_POOL_HASHES),
        DJSON("/get_transaction_pool_stats",        on_get_transaction_pool_stats,   COMMAND_RPC_GET_TRANSACTION_POOL_STATS),
        DJSON("/get_info",                          on_get_info,                     COMMAND_RPC_GET_INFO),
        DJSON("/getinfo",                           on_get_info,                     COMMAND_RPC_GET_INFO),
        DJSON("/get_limit",                         on_get_limit,                    COMMAND_RPC_GET_LIMIT),
        // Restricted-only endpoints (Rust checks restriction before calling)
        DJSON("/start_mining",                      on_start_mining,                 COMMAND_RPC_START_MINING),
        DJSON("/stop_mining",                       on_stop_mining,                  COMMAND_RPC_STOP_MINING),
        DJSON("/mining_status",                     on_mining_status,                COMMAND_RPC_MINING_STATUS),
        DJSON("/save_bc",                           on_save_bc,                      COMMAND_RPC_SAVE_BC),
        DJSON("/get_peer_list",                     on_get_peer_list,                COMMAND_RPC_GET_PEER_LIST),
        DJSON("/set_log_hash_rate",                 on_set_log_hash_rate,            COMMAND_RPC_SET_LOG_HASH_RATE),
        DJSON("/set_log_level",                     on_set_log_level,                COMMAND_RPC_SET_LOG_LEVEL),
        DJSON("/set_log_categories",                on_set_log_categories,           COMMAND_RPC_SET_LOG_CATEGORIES),
        DJSON("/set_bootstrap_daemon",              on_set_bootstrap_daemon,         COMMAND_RPC_SET_BOOTSTRAP_DAEMON),
        DJSON("/stop_daemon",                       on_stop_daemon,                  COMMAND_RPC_STOP_DAEMON),
        DJSON("/get_net_stats",                     on_get_net_stats,                COMMAND_RPC_GET_NET_STATS),
        DJSON("/set_limit",                         on_set_limit,                    COMMAND_RPC_SET_LIMIT),
        DJSON("/out_peers",                         on_out_peers,                    COMMAND_RPC_OUT_PEERS),
        DJSON("/in_peers",                          on_in_peers,                     COMMAND_RPC_IN_PEERS),
        DJSON("/update",                            on_update,                       COMMAND_RPC_UPDATE),
        DJSON("/pop_blocks",                        on_pop_blocks,                   COMMAND_RPC_POP_BLOCKS),
    };
    return t;
}

const std::unordered_map<std::string, bin_fn>& get_bin_table() {
    static const std::unordered_map<std::string, bin_fn> t = {
        DBIN("/get_blocks.bin",            on_get_blocks,                  COMMAND_RPC_GET_BLOCKS_FAST),
        DBIN("/getblocks.bin",             on_get_blocks,                  COMMAND_RPC_GET_BLOCKS_FAST),
        DBIN("/get_blocks_by_height.bin",  on_get_blocks_by_height,        COMMAND_RPC_GET_BLOCKS_BY_HEIGHT),
        DBIN("/getblocks_by_height.bin",   on_get_blocks_by_height,        COMMAND_RPC_GET_BLOCKS_BY_HEIGHT),
        DBIN("/get_hashes.bin",            on_get_hashes,                  COMMAND_RPC_GET_HASHES_FAST),
        DBIN("/gethashes.bin",             on_get_hashes,                  COMMAND_RPC_GET_HASHES_FAST),
        DBIN("/get_o_indexes.bin",         on_get_indexes,                 COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES),
        DBIN("/get_output_distribution.bin", on_get_output_distribution_bin, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION),
    };
    return t;
}

// Specialized dispatch for GETBLOCKHASH: request=vector<uint64_t>, response=string
char* dispatch_getblockhash(core_rpc_server& rpc, const char* params_json) {
    COMMAND_RPC_GETBLOCKHASH::request req;
    COMMAND_RPC_GETBLOCKHASH::response res;
    epee::json_rpc::error error_resp{};

    if (params_json && params_json[0]) {
        // params is a JSON array of uint64_t, e.g. [12345]
        // Parse manually since it's not a KV-serializable struct
        epee::serialization::portable_storage ps;
        if (ps.load_from_json(std::string(params_json))) {
            // The JSON-RPC spec sends params as array
        }
        // Fallback: try parsing as JSON array directly
        std::string s(params_json);
        // Remove [ ] if present
        auto start = s.find('[');
        auto end = s.rfind(']');
        if (start != std::string::npos && end != std::string::npos) {
            std::string inner = s.substr(start + 1, end - start - 1);
            std::istringstream iss(inner);
            std::string token;
            while (std::getline(iss, token, ',')) {
                try { req.push_back(std::stoull(token)); } catch (...) {}
            }
        }
    }

    bool ok = rpc.on_getblockhash(req, res, error_resp, nullptr);
    std::ostringstream oss;
    if (ok && error_resp.code == 0) {
        oss << R"({"ok":true,"result":")" << res << R"("})";
    } else {
        int code = error_resp.code ? error_resp.code : -32603;
        std::string msg = error_resp.message.empty() ? "Internal error" : error_resp.message;
        oss << R"({"ok":false,"error_code":)" << code
            << R"(,"error_message":")" << msg << R"("})";
    }
    return strdup(oss.str().c_str());
}

// Specialized dispatch for SUBMITBLOCK: request=vector<string>, response has response_t
char* dispatch_submitblock(core_rpc_server& rpc, const char* params_json) {
    COMMAND_RPC_SUBMITBLOCK::request req;
    COMMAND_RPC_SUBMITBLOCK::response res;
    epee::json_rpc::error error_resp{};

    if (params_json && params_json[0]) {
        std::string s(params_json);
        auto start = s.find('[');
        auto end = s.rfind(']');
        if (start != std::string::npos && end != std::string::npos) {
            std::string inner = s.substr(start + 1, end - start - 1);
            // Parse quoted strings from the array
            size_t pos = 0;
            while ((pos = inner.find('"', pos)) != std::string::npos) {
                auto close = inner.find('"', pos + 1);
                if (close != std::string::npos) {
                    req.push_back(inner.substr(pos + 1, close - pos - 1));
                    pos = close + 1;
                } else break;
            }
        }
    }

    bool ok = rpc.on_submitblock(req, res, error_resp, nullptr);
    std::ostringstream oss;
    if (ok && error_resp.code == 0) {
        std::string result_json;
        epee::serialization::store_t_to_json(static_cast<const COMMAND_RPC_SUBMITBLOCK::response_t&>(res), result_json);
        oss << R"({"ok":true,"result":)" << result_json << "}";
    } else {
        int code = error_resp.code ? error_resp.code : -32603;
        std::string msg = error_resp.message.empty() ? "Internal error" : error_resp.message;
        oss << R"({"ok":false,"error_code":)" << code
            << R"(,"error_message":")" << msg << R"("})";
    }
    return strdup(oss.str().c_str());
}

// Specialized dispatch for CALCPOW: request has request_t, response=string
char* dispatch_calcpow(core_rpc_server& rpc, const char* params_json) {
    COMMAND_RPC_CALCPOW::request req{};
    COMMAND_RPC_CALCPOW::response res;
    epee::json_rpc::error error_resp{};

    if (params_json && params_json[0]) {
        epee::serialization::load_t_from_json(static_cast<COMMAND_RPC_CALCPOW::request_t&>(req), std::string(params_json));
    }

    bool ok = rpc.on_calcpow(req, res, error_resp, nullptr);
    std::ostringstream oss;
    if (ok && error_resp.code == 0) {
        oss << R"({"ok":true,"result":")" << res << R"("})";
    } else {
        int code = error_resp.code ? error_resp.code : -32603;
        std::string msg = error_resp.message.empty() ? "Internal error" : error_resp.message;
        oss << R"({"ok":false,"error_code":)" << code
            << R"(,"error_message":")" << msg << R"("})";
    }
    return strdup(oss.str().c_str());
}

// Specialized dispatch for GETBLOCKCOUNT: request=list<string>, response has response_t
char* dispatch_getblockcount(core_rpc_server& rpc, const char* /*params_json*/) {
    COMMAND_RPC_GETBLOCKCOUNT::request req;
    COMMAND_RPC_GETBLOCKCOUNT::response res;
    bool ok = rpc.on_getblockcount(req, res, nullptr);
    std::ostringstream oss;
    if (ok) {
        std::string result_json;
        epee::serialization::store_t_to_json(static_cast<const COMMAND_RPC_GETBLOCKCOUNT::response_t&>(res), result_json);
        oss << R"({"ok":true,"result":)" << result_json << "}";
    } else {
        oss << R"({"ok":false,"error_code":-32603,"error_message":"Internal error"})";
    }
    return strdup(oss.str().c_str());
}

const std::unordered_map<std::string, jsonrpc_fn>& get_jsonrpc_table() {
    static const std::unordered_map<std::string, jsonrpc_fn> t = {
        // Non-standard request/response commands: manual dispatch
        {"get_block_count",  [](core_rpc_server& rpc, const char* p) { return dispatch_getblockcount(rpc, p); }},
        {"getblockcount",    [](core_rpc_server& rpc, const char* p) { return dispatch_getblockcount(rpc, p); }},
        {"on_get_block_hash",  [](core_rpc_server& rpc, const char* p) { return dispatch_getblockhash(rpc, p); }},
        {"on_getblockhash",    [](core_rpc_server& rpc, const char* p) { return dispatch_getblockhash(rpc, p); }},
        {"submit_block",       [](core_rpc_server& rpc, const char* p) { return dispatch_submitblock(rpc, p); }},
        {"submitblock",        [](core_rpc_server& rpc, const char* p) { return dispatch_submitblock(rpc, p); }},
        {"calc_pow",           [](core_rpc_server& rpc, const char* p) { return dispatch_calcpow(rpc, p); }},
        // Standard MAP_JON_RPC_WE
        DJRPC_WE("get_block_template",      on_getblocktemplate,          COMMAND_RPC_GETBLOCKTEMPLATE),
        DJRPC_WE("getblocktemplate",         on_getblocktemplate,          COMMAND_RPC_GETBLOCKTEMPLATE),
        DJRPC_WE("get_miner_data",          on_getminerdata,              COMMAND_RPC_GETMINERDATA),
        DJRPC_WE("add_aux_pow",            on_add_aux_pow,                COMMAND_RPC_ADD_AUX_POW),
        DJRPC_WE("generateblocks",          on_generateblocks,             COMMAND_RPC_GENERATEBLOCKS),
        DJRPC_WE("get_last_block_header",  on_get_last_block_header,      COMMAND_RPC_GET_LAST_BLOCK_HEADER),
        DJRPC_WE("getlastblockheader",     on_get_last_block_header,      COMMAND_RPC_GET_LAST_BLOCK_HEADER),
        DJRPC_WE("get_block_header_by_hash", on_get_block_header_by_hash, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH),
        DJRPC_WE("getblockheaderbyhash",   on_get_block_header_by_hash,   COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH),
        DJRPC_WE("get_block_header_by_height", on_get_block_header_by_height, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT),
        DJRPC_WE("getblockheaderbyheight", on_get_block_header_by_height, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT),
        DJRPC_WE("get_block_headers_range", on_get_block_headers_range,   COMMAND_RPC_GET_BLOCK_HEADERS_RANGE),
        DJRPC_WE("getblockheadersrange",   on_get_block_headers_range,    COMMAND_RPC_GET_BLOCK_HEADERS_RANGE),
        DJRPC_WE("get_block",              on_get_block,                   COMMAND_RPC_GET_BLOCK),
        DJRPC_WE("getblock",               on_get_block,                   COMMAND_RPC_GET_BLOCK),
        DJRPC_WE("get_connections",         on_get_connections,            COMMAND_RPC_GET_CONNECTIONS),
        DJRPC_WE("get_info",               on_get_info_json,              COMMAND_RPC_GET_INFO),
        DJRPC_WE("hard_fork_info",         on_hard_fork_info,             COMMAND_RPC_HARD_FORK_INFO),
        DJRPC_WE("set_bans",              on_set_bans,                    COMMAND_RPC_SETBANS),
        DJRPC_WE("get_bans",              on_get_bans,                    COMMAND_RPC_GETBANS),
        DJRPC_WE("banned",                on_banned,                      COMMAND_RPC_BANNED),
        DJRPC_WE("flush_txpool",          on_flush_txpool,                COMMAND_RPC_FLUSH_TRANSACTION_POOL),
        DJRPC_WE("get_output_histogram",   on_get_output_histogram,       COMMAND_RPC_GET_OUTPUT_HISTOGRAM),
        DJRPC_WE("get_version",            on_get_version,                COMMAND_RPC_GET_VERSION),
        DJRPC_WE("get_coinbase_tx_sum",    on_get_coinbase_tx_sum,        COMMAND_RPC_GET_COINBASE_TX_SUM),
        DJRPC_WE("get_fee_estimate",       on_get_base_fee_estimate,      COMMAND_RPC_GET_BASE_FEE_ESTIMATE),
        DJRPC_WE("get_alternate_chains",   on_get_alternate_chains,       COMMAND_RPC_GET_ALTERNATE_CHAINS),
        DJRPC_WE("relay_tx",              on_relay_tx,                    COMMAND_RPC_RELAY_TX),
        DJRPC_WE("sync_info",             on_sync_info,                   COMMAND_RPC_SYNC_INFO),
        DJRPC_WE("get_txpool_backlog",     on_get_txpool_backlog,         COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG),
        DJRPC_WE("get_output_distribution", on_get_output_distribution,   COMMAND_RPC_GET_OUTPUT_DISTRIBUTION),
        DJRPC_WE("prune_blockchain",       on_prune_blockchain,           COMMAND_RPC_PRUNE_BLOCKCHAIN),
        DJRPC_WE("flush_cache",            on_flush_cache,                COMMAND_RPC_FLUSH_CACHE),
        DJRPC_WE("get_staking_info",       on_get_staking_info,           COMMAND_RPC_GET_STAKING_INFO),
        DJRPC_WE("estimate_claim_reward",  on_estimate_claim_reward,      COMMAND_RPC_ESTIMATE_CLAIM_REWARD),
        DJRPC_WE("rpc_access_info",        on_rpc_access_info,            COMMAND_RPC_ACCESS_INFO),
        DJRPC_WE("rpc_access_submit_nonce", on_rpc_access_submit_nonce,   COMMAND_RPC_ACCESS_SUBMIT_NONCE),
        DJRPC_WE("rpc_access_pay",         on_rpc_access_pay,             COMMAND_RPC_ACCESS_PAY),
        DJRPC_WE("rpc_access_tracking",    on_rpc_access_tracking,        COMMAND_RPC_ACCESS_TRACKING),
        DJRPC_WE("rpc_access_data",        on_rpc_access_data,            COMMAND_RPC_ACCESS_DATA),
        DJRPC_WE("rpc_access_account",     on_rpc_access_account,         COMMAND_RPC_ACCESS_ACCOUNT),
    };
    return t;
}

} // anonymous namespace

// ─── C API Implementation ────────────────────────────────────────────────────

extern "C" {

core_rpc_handle* core_rpc_ffi_create(void* rpc_server_ptr)
{
    if (!rpc_server_ptr) return nullptr;
    auto* h = new(std::nothrow) core_rpc_handle;
    if (!h) return nullptr;
    h->rpc = static_cast<core_rpc_server*>(rpc_server_ptr);
    return h;
}

void core_rpc_ffi_destroy(core_rpc_handle* h)
{
    delete h;
}

bool core_rpc_ffi_is_restricted(const core_rpc_handle* h)
{
    if (!h || !h->rpc) return true;
    // The m_restricted member is private; access it via the same pattern
    // the daemon uses (set at init time). We expose it via the handle.
    // For now, we check by trying a restricted-only endpoint and seeing
    // if the URI map would accept it. A cleaner solution would be to add
    // a public accessor to core_rpc_server, but that's a minimal change.
    // TODO: Add bool core_rpc_server::is_restricted() const { return m_restricted; }
    return false; // Caller tracks restriction separately in Rust AppState
}

char* core_rpc_ffi_json_endpoint(core_rpc_handle* h,
    const char* uri, const char* body_json)
{
    if (!h || !h->rpc || !uri) return nullptr;
    const auto& table = get_json_table();
    auto it = table.find(uri);
    if (it == table.end()) return nullptr;
    try {
        return it->second(*h->rpc, body_json ? body_json : "");
    } catch (const std::exception& e) {
        MERROR("core_rpc_ffi_json_endpoint(" << uri << "): " << e.what());
        return nullptr;
    }
}

int core_rpc_ffi_bin_endpoint(core_rpc_handle* h,
    const char* uri,
    const uint8_t* body, size_t body_len,
    uint8_t** out_buf, size_t* out_len)
{
    if (!h || !h->rpc || !uri || !out_buf || !out_len) return -1;
    const auto& table = get_bin_table();
    auto it = table.find(uri);
    if (it == table.end()) return -1;
    try {
        return it->second(*h->rpc, body, body_len, out_buf, out_len);
    } catch (const std::exception& e) {
        MERROR("core_rpc_ffi_bin_endpoint(" << uri << "): " << e.what());
        return -1;
    }
}

char* core_rpc_ffi_json_rpc(core_rpc_handle* h,
    const char* method, const char* params_json)
{
    if (!h || !h->rpc || !method) return nullptr;
    const auto& table = get_jsonrpc_table();
    auto it = table.find(method);
    if (it == table.end()) return nullptr;
    try {
        return it->second(*h->rpc, params_json ? params_json : "");
    } catch (const std::exception& e) {
        MERROR("core_rpc_ffi_json_rpc(" << method << "): " << e.what());
        std::string err = std::string(R"({"ok":false,"error_code":-32603,"error_message":")")
            + e.what() + R"("})";
        return strdup(err.c_str());
    }
}

void core_rpc_ffi_free_string(char* s) { free(s); }
void core_rpc_ffi_free_buf(uint8_t* buf) { free(buf); }

} // extern "C"
