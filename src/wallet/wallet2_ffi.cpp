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

#include "wallet2_ffi.h"
#include "wallet2.h"
#include "wallet_rpc_server_error_codes.h"
#include "wallet_rpc_server_commands_defs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "mnemonics/electrum-words.h"
#include "string_tools.h"
#include "hex.h"
#include "fee_priority.h"
#include "version.h"
#include "common/util.h"
#include "serialization/binary_archive.h"
#include <boost/archive/portable_binary_iarchive.hpp>
#include "span.h"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include <cstring>
#include <string>
#include <vector>
#include <filesystem>
#include <sstream>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.ffi"

namespace rj = rapidjson;

struct wallet2_handle {
    std::unique_ptr<tools::wallet2> wallet;
    std::string wallet_dir;
    int last_error_code = 0;
    std::string last_error_msg;

    void clear_error() {
        last_error_code = 0;
        last_error_msg.clear();
    }

    void set_error(int code, const std::string& msg) {
        last_error_code = code;
        last_error_msg = msg;
    }

    void set_error_from_exception(const std::exception& e, int default_code) {
        try { throw; }
        catch (const tools::error::no_connection_to_daemon& ex) {
            set_error(WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION, ex.what());
        }
        catch (const tools::error::daemon_busy& ex) {
            set_error(WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY, ex.what());
        }
        catch (const tools::error::zero_amount& ex) {
            set_error(WALLET_RPC_ERROR_CODE_ZERO_AMOUNT, ex.what());
        }
        catch (const tools::error::zero_destination& ex) {
            set_error(WALLET_RPC_ERROR_CODE_ZERO_DESTINATION, ex.what());
        }
        catch (const tools::error::not_enough_money& ex) {
            set_error(WALLET_RPC_ERROR_CODE_NOT_ENOUGH_MONEY, ex.what());
        }
        catch (const tools::error::not_enough_unlocked_money& ex) {
            set_error(WALLET_RPC_ERROR_CODE_NOT_ENOUGH_UNLOCKED_MONEY, ex.what());
        }
        catch (const tools::error::tx_not_possible& ex) {
            set_error(WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE, ex.what());
        }
        catch (const tools::error::not_enough_outs_to_mix& ex) {
            set_error(WALLET_RPC_ERROR_CODE_NOT_ENOUGH_OUTS_TO_MIX, ex.what());
        }
        catch (const tools::error::file_exists& ex) {
            set_error(WALLET_RPC_ERROR_CODE_WALLET_ALREADY_EXISTS, ex.what());
        }
        catch (const tools::error::invalid_password& ex) {
            set_error(WALLET_RPC_ERROR_CODE_INVALID_PASSWORD, ex.what());
        }
        catch (const std::exception& ex) {
            set_error(default_code, ex.what());
        }
    }
};

static char* strdup_alloc(const std::string& s)
{
    char* p = static_cast<char*>(malloc(s.size() + 1));
    if (p) {
        memcpy(p, s.data(), s.size());
        p[s.size()] = '\0';
    }
    return p;
}

static char* json_to_string(const rj::Document& doc)
{
    rj::StringBuffer buf;
    rj::Writer<rj::StringBuffer> writer(buf);
    doc.Accept(writer);
    return strdup_alloc(buf.GetString());
}

static cryptonote::network_type nettype_from_u8(uint8_t n)
{
    switch (n) {
        case 1: return cryptonote::TESTNET;
        case 2: return cryptonote::STAGENET;
        default: return cryptonote::MAINNET;
    }
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

wallet2_handle* wallet2_ffi_create(uint8_t nettype)
{
    auto* h = new(std::nothrow) wallet2_handle();
    if (!h) return nullptr;
    h->wallet = std::make_unique<tools::wallet2>(nettype_from_u8(nettype), 1, true);
    return h;
}

void wallet2_ffi_destroy(wallet2_handle* w)
{
    if (!w) return;
    if (w->wallet) {
        try { w->wallet->store(); } catch (...) {}
        try { w->wallet->deinit(); } catch (...) {}
    }
    delete w;
}

int wallet2_ffi_init(wallet2_handle* w,
                     const char* daemon_address,
                     const char* daemon_username,
                     const char* daemon_password,
                     bool trusted_daemon)
{
    if (!w || !w->wallet) return WALLET_RPC_ERROR_CODE_NOT_OPEN;
    w->clear_error();

    try {
        std::optional<epee::net_utils::http::login> login;
        if (daemon_username && daemon_username[0] != '\0') {
            login.emplace(std::string(daemon_username),
                          std::string(daemon_password ? daemon_password : ""));
        }
        if (!w->wallet->init(daemon_address ? daemon_address : "", login)) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to initialize wallet daemon connection");
            return w->last_error_code;
        }
        w->wallet->set_trusted_daemon(trusted_daemon);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    return 0;
}

int wallet2_ffi_refresh(wallet2_handle* w)
{
    if (!w || !w->wallet) return WALLET_RPC_ERROR_CODE_NOT_OPEN;
    w->clear_error();

    try {
        w->wallet->refresh(w->wallet->is_trusted_daemon());
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    return 0;
}

int wallet2_ffi_store(wallet2_handle* w)
{
    if (!w || !w->wallet) return WALLET_RPC_ERROR_CODE_NOT_OPEN;
    w->clear_error();

    try {
        w->wallet->store();
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    return 0;
}

// ── Error state ──────────────────────────────────────────────────────────────

int wallet2_ffi_last_error_code(const wallet2_handle* w)
{
    return w ? w->last_error_code : 0;
}

const char* wallet2_ffi_last_error_msg(const wallet2_handle* w)
{
    return w ? w->last_error_msg.c_str() : "";
}

void wallet2_ffi_free_string(char* str)
{
    free(str);
}

// ── Wallet file operations ───────────────────────────────────────────────────

void wallet2_ffi_set_wallet_dir(wallet2_handle* w, const char* dir)
{
    if (!w) return;
    w->wallet_dir = dir ? dir : "";
}

static bool validate_filename(const char* filename, wallet2_handle* w)
{
    if (!filename || filename[0] == '\0') {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Empty filename");
        return false;
    }
    if (strchr(filename, '/') != nullptr
#ifdef _WIN32
        || strchr(filename, '\\') != nullptr
        || strchr(filename, ':') != nullptr
#endif
    ) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Invalid filename");
        return false;
    }
    return true;
}

int wallet2_ffi_create_wallet(wallet2_handle* w,
                              const char* filename,
                              const char* password,
                              const char* language)
{
    if (!w) return WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    w->clear_error();

    if (w->wallet_dir.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_WALLET_DIR, "No wallet dir configured");
        return w->last_error_code;
    }
    if (!validate_filename(filename, w))
        return w->last_error_code;
    if (!language || !crypto::ElectrumWords::is_valid_language(language)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                     std::string("Unknown language: ") + (language ? language : ""));
        return w->last_error_code;
    }

    std::string wallet_file = w->wallet_dir + "/" + filename;

    try {
        auto wal = std::make_unique<tools::wallet2>(w->wallet->nettype(), 1, true);
        wal->set_seed_language(language);

        cryptonote::COMMAND_RPC_GET_HEIGHT::request hreq;
        cryptonote::COMMAND_RPC_GET_HEIGHT::response hres;
        hres.height = 0;
        bool r = wal->invoke_http_json("/getheight", hreq, hres);
        if (r)
            wal->set_refresh_from_block_height(hres.height);

        crypto::secret_key dummy_key;
        wal->generate(wallet_file, password ? password : "", dummy_key, false, false);

        if (w->wallet) {
            try { w->wallet->store(); } catch (...) {}
        }
        w->wallet = std::move(wal);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    return 0;
}

int wallet2_ffi_open_wallet(wallet2_handle* w,
                            const char* filename,
                            const char* password)
{
    if (!w) return WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    w->clear_error();

    if (w->wallet_dir.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_WALLET_DIR, "No wallet dir configured");
        return w->last_error_code;
    }
    if (!validate_filename(filename, w))
        return w->last_error_code;

    std::string wallet_file = w->wallet_dir + "/" + filename;

    try {
        auto wal = std::make_unique<tools::wallet2>(w->wallet->nettype(), 1, true);
        wal->load(wallet_file, password ? password : "");

        if (w->wallet) {
            try { w->wallet->store(); } catch (...) {}
        }
        w->wallet = std::move(wal);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    return 0;
}

int wallet2_ffi_close_wallet(wallet2_handle* w, bool autosave)
{
    if (!w || !w->wallet) return WALLET_RPC_ERROR_CODE_NOT_OPEN;
    w->clear_error();

    try {
        if (autosave)
            w->wallet->store();
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    w->wallet.reset();
    w->wallet = std::make_unique<tools::wallet2>(cryptonote::MAINNET, 1, true);
    return 0;
}

char* wallet2_ffi_restore_deterministic_wallet(wallet2_handle* w,
                                               const char* filename,
                                               const char* seed,
                                               const char* password,
                                               const char* language,
                                               uint64_t restore_height,
                                               const char* seed_offset)
{
    if (!w) return nullptr;
    w->clear_error();

    if (w->wallet_dir.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_WALLET_DIR, "No wallet dir configured");
        return nullptr;
    }
    if (!seed || seed[0] == '\0') {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Seed is required");
        return nullptr;
    }
    if (!validate_filename(filename, w))
        return nullptr;

    std::string wallet_file = w->wallet_dir + "/" + filename;

    try {
        std::error_code ignored_ec;
        if (std::filesystem::exists(wallet_file, ignored_ec)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WALLET_ALREADY_EXISTS, "Wallet already exists");
            return nullptr;
        }
    } catch (...) {}

    crypto::secret_key recovery_key;
    std::string old_language;
    if (!crypto::ElectrumWords::words_to_bytes(seed, recovery_key, old_language)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Electrum-style word list failed verification");
        return nullptr;
    }

    try {
        auto wal = std::make_unique<tools::wallet2>(w->wallet->nettype(), 1, true);

        epee::wipeable_string seed_pass;
        if (seed_offset && seed_offset[0] != '\0')
            seed_pass = seed_offset;

        if (language && language[0] != '\0')
            wal->set_seed_language(language);
        else if (!old_language.empty())
            wal->set_seed_language(old_language);
        else
            wal->set_seed_language("English");

        wal->set_refresh_from_block_height(restore_height);
        wal->generate(wallet_file, password ? password : "", recovery_key, true, false, "");

        if (w->wallet) {
            try { w->wallet->store(); } catch (...) {}
        }
        w->wallet = std::move(wal);

        std::string address = w->wallet->get_account().get_public_address_str(w->wallet->nettype());

        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();
        doc.AddMember("address", rj::Value(address.c_str(), alloc), alloc);
        doc.AddMember("seed", rj::Value(seed, alloc), alloc);
        doc.AddMember("info", "Wallet has been restored successfully.", alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

char* wallet2_ffi_generate_from_keys(wallet2_handle* w,
                                     const char* filename,
                                     const char* address,
                                     const char* spendkey,
                                     const char* viewkey,
                                     const char* password,
                                     const char* language,
                                     uint64_t restore_height)
{
    if (!w) return nullptr;
    w->clear_error();

    if (w->wallet_dir.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_WALLET_DIR, "No wallet dir configured");
        return nullptr;
    }
    if (!viewkey || viewkey[0] == '\0') {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "viewkey is required");
        return nullptr;
    }
    if (!address || address[0] == '\0') {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "address is required");
        return nullptr;
    }
    if (!validate_filename(filename, w))
        return nullptr;

    std::string wallet_file = w->wallet_dir + "/" + filename;

    try {
        std::error_code ignored_ec;
        if (std::filesystem::exists(wallet_file, ignored_ec)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WALLET_ALREADY_EXISTS, "Wallet already exists");
            return nullptr;
        }
    } catch (...) {}

    try {
        auto wal = std::make_unique<tools::wallet2>(w->wallet->nettype(), 1, true);

        cryptonote::address_parse_info info;
        if (!get_account_address_from_str(info, wal->nettype(), address)) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to parse public address");
            return nullptr;
        }

        epee::wipeable_string viewkey_str = viewkey;
        crypto::secret_key vk;
        if (!viewkey_str.hex_to_pod(unwrap(unwrap(vk)))) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to parse view key");
            return nullptr;
        }

        std::string info_msg;
        if (spendkey && spendkey[0] != '\0') {
            epee::wipeable_string spendkey_str = spendkey;
            crypto::secret_key sk;
            if (!spendkey_str.hex_to_pod(unwrap(unwrap(sk)))) {
                w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to parse spend key");
                return nullptr;
            }
            wal->generate(wallet_file, password ? password : "", info.address, sk, vk, false);
            info_msg = "Wallet has been generated successfully.";
        } else {
            wal->generate(wallet_file, password ? password : "", info.address, vk, false);
            info_msg = "Watch-only wallet has been generated successfully.";
        }

        if (language && language[0] != '\0') {
            if (!crypto::ElectrumWords::is_valid_language(language)) {
                w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Invalid seed language");
                return nullptr;
            }
            wal->set_seed_language(language);
        }

        wal->set_refresh_from_block_height(restore_height);
        wal->rewrite(wallet_file, password ? password : "");

        if (w->wallet) {
            try { w->wallet->store(); } catch (...) {}
        }
        w->wallet = std::move(wal);

        std::string result_address = w->wallet->get_account().get_public_address_str(w->wallet->nettype());

        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();
        doc.AddMember("address", rj::Value(result_address.c_str(), alloc), alloc);
        doc.AddMember("info", rj::Value(info_msg.c_str(), alloc), alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

// ── Queries ──────────────────────────────────────────────────────────────────

char* wallet2_ffi_get_balance(wallet2_handle* w, uint32_t account_index)
{
    if (!w || !w->wallet) {
        if (w) w->set_error(WALLET_RPC_ERROR_CODE_NOT_OPEN, "No wallet file");
        return nullptr;
    }
    w->clear_error();

    try {
        uint64_t blocks_to_unlock = 0, time_to_unlock = 0;
        uint64_t balance = w->wallet->balance(account_index, false);
        uint64_t unlocked = w->wallet->unlocked_balance(account_index, false, &blocks_to_unlock, &time_to_unlock);

        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();
        doc.AddMember("balance", balance, alloc);
        doc.AddMember("unlocked_balance", unlocked, alloc);
        doc.AddMember("blocks_to_unlock", blocks_to_unlock, alloc);
        doc.AddMember("time_to_unlock", time_to_unlock, alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

char* wallet2_ffi_get_address(wallet2_handle* w, uint32_t account_index)
{
    if (!w || !w->wallet) {
        if (w) w->set_error(WALLET_RPC_ERROR_CODE_NOT_OPEN, "No wallet file");
        return nullptr;
    }
    w->clear_error();

    try {
        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();

        std::string main_address = w->wallet->get_subaddress_as_str({account_index, 0});
        doc.AddMember("address", rj::Value(main_address.c_str(), alloc), alloc);

        rj::Value addresses(rj::kArrayType);
        tools::wallet2::transfer_container transfers;
        w->wallet->get_transfers(transfers);

        for (uint32_t i = 0; i < w->wallet->get_num_subaddresses(account_index); ++i) {
            rj::Value addr_obj(rj::kObjectType);
            std::string addr = w->wallet->get_subaddress_as_str({account_index, i});
            std::string label = w->wallet->get_subaddress_label({account_index, i});

            bool used = std::any_of(transfers.begin(), transfers.end(),
                [account_index, i](const tools::wallet2::transfer_details& td) {
                    return td.m_subaddr_index.major == account_index &&
                           td.m_subaddr_index.minor == i;
                });

            addr_obj.AddMember("address", rj::Value(addr.c_str(), alloc), alloc);
            addr_obj.AddMember("label", rj::Value(label.c_str(), alloc), alloc);
            addr_obj.AddMember("address_index", i, alloc);
            addr_obj.AddMember("used", used, alloc);
            addresses.PushBack(addr_obj, alloc);
        }

        doc.AddMember("addresses", addresses, alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

char* wallet2_ffi_query_key(wallet2_handle* w, const char* key_type)
{
    if (!w || !w->wallet) {
        if (w) w->set_error(WALLET_RPC_ERROR_CODE_NOT_OPEN, "No wallet file");
        return nullptr;
    }
    w->clear_error();

    if (!key_type) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "key_type is required");
        return nullptr;
    }

    try {
        std::string key_value;

        if (strcmp(key_type, "mnemonic") == 0) {
            if (w->wallet->watch_only()) {
                w->set_error(WALLET_RPC_ERROR_CODE_WATCH_ONLY, "Watch-only wallet cannot retrieve seed");
                return nullptr;
            }
            if (!w->wallet->is_deterministic()) {
                w->set_error(WALLET_RPC_ERROR_CODE_NON_DETERMINISTIC, "Non-deterministic wallet cannot display seed");
                return nullptr;
            }
            epee::wipeable_string seed;
            if (!w->wallet->get_seed(seed)) {
                w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to get seed");
                return nullptr;
            }
            key_value = std::string(seed.data(), seed.size());
        } else if (strcmp(key_type, "view_key") == 0) {
            epee::wipeable_string key = epee::to_hex::wipeable_string(
                w->wallet->get_account().get_keys().m_view_secret_key);
            key_value = std::string(key.data(), key.size());
        } else if (strcmp(key_type, "spend_key") == 0) {
            if (w->wallet->watch_only()) {
                w->set_error(WALLET_RPC_ERROR_CODE_WATCH_ONLY, "Watch-only wallet cannot retrieve spend key");
                return nullptr;
            }
            epee::wipeable_string key = epee::to_hex::wipeable_string(
                w->wallet->get_account().get_keys().m_spend_secret_key);
            key_value = std::string(key.data(), key.size());
        } else {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                         std::string("Unknown key_type: ") + key_type);
            return nullptr;
        }

        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();
        doc.AddMember("key", rj::Value(key_value.c_str(), alloc), alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

uint32_t wallet2_ffi_get_version(void)
{
    return WALLET_RPC_VERSION;
}

// ── Transfers ────────────────────────────────────────────────────────────────

char* wallet2_ffi_transfer(wallet2_handle* w,
                           const char* destinations_json,
                           uint32_t priority,
                           uint32_t account_index,
                           uint32_t ring_size)
{
    if (!w || !w->wallet) {
        if (w) w->set_error(WALLET_RPC_ERROR_CODE_NOT_OPEN, "No wallet file");
        return nullptr;
    }
    w->clear_error();

    if (!tools::fee_priority_utilities::is_valid(priority)) {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_FEE_PRIORITY, "Invalid priority (0-4)");
        return nullptr;
    }

    rj::Document dests_doc;
    if (dests_doc.Parse(destinations_json).HasParseError() || !dests_doc.IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Invalid destinations JSON");
        return nullptr;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    for (rj::SizeType i = 0; i < dests_doc.Size(); ++i) {
        const auto& d = dests_doc[i];
        if (!d.HasMember("address") || !d.HasMember("amount")) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Each destination must have address and amount");
            return nullptr;
        }
        cryptonote::address_parse_info info;
        if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(), d["address"].GetString())) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS,
                         std::string("Invalid address: ") + d["address"].GetString());
            return nullptr;
        }
        dsts.emplace_back(d["amount"].GetUint64(), info.address, info.is_subaddress);
    }

    if (dsts.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_ZERO_DESTINATION, "No destinations");
        return nullptr;
    }

    try {
        uint64_t mixin = w->wallet->adjust_mixin(ring_size > 0 ? ring_size - 1 : 0);
        const tools::fee_priority fp = w->wallet->adjust_priority(tools::fee_priority_utilities::from_integral(priority));
        std::set<uint32_t> subaddr_indices;
        std::vector<tools::wallet2::pending_tx> ptx_vector =
            w->wallet->create_transactions_2(dsts, mixin, fp, extra, account_index, subaddr_indices);

        if (ptx_vector.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE, "No transaction created");
            return nullptr;
        }
        if (ptx_vector.size() != 1) {
            w->set_error(WALLET_RPC_ERROR_CODE_TX_TOO_LARGE, "Transaction too large, use transfer_split");
            return nullptr;
        }

        w->wallet->commit_tx(ptx_vector);
        auto& ptx = ptx_vector[0];

        std::string tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
        uint64_t fee = ptx.fee;
        uint64_t amount = 0;
        for (const auto& d : ptx.dests)
            amount += d.amount;

        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();
        doc.AddMember("tx_hash", rj::Value(tx_hash.c_str(), alloc), alloc);
        doc.AddMember("fee", fee, alloc);
        doc.AddMember("amount", amount, alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
        return nullptr;
    }
}

static void add_transfer_entry(rj::Value& arr, rj::Document::AllocatorType& alloc,
                                const std::string& txid, const std::string& type,
                                uint64_t amount, uint64_t fee, uint64_t height,
                                uint64_t timestamp, uint64_t confirmations,
                                uint64_t unlock_time, bool locked)
{
    rj::Value obj(rj::kObjectType);
    obj.AddMember("txid", rj::Value(txid.c_str(), alloc), alloc);
    obj.AddMember("type", rj::Value(type.c_str(), alloc), alloc);
    obj.AddMember("amount", amount, alloc);
    obj.AddMember("fee", fee, alloc);
    obj.AddMember("height", height, alloc);
    obj.AddMember("timestamp", timestamp, alloc);
    obj.AddMember("confirmations", confirmations, alloc);
    obj.AddMember("unlock_time", unlock_time, alloc);
    obj.AddMember("locked", locked, alloc);
    arr.PushBack(obj, alloc);
}

char* wallet2_ffi_get_transfers(wallet2_handle* w,
                                bool in, bool out, bool pending,
                                bool failed, bool pool,
                                uint32_t account_index)
{
    if (!w || !w->wallet) {
        if (w) w->set_error(WALLET_RPC_ERROR_CODE_NOT_OPEN, "No wallet file");
        return nullptr;
    }
    w->clear_error();

    try {
        uint64_t bc_height = w->wallet->get_blockchain_current_height();

        rj::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();

        rj::Value in_arr(rj::kArrayType);
        rj::Value out_arr(rj::kArrayType);
        rj::Value pending_arr(rj::kArrayType);
        rj::Value failed_arr(rj::kArrayType);
        rj::Value pool_arr(rj::kArrayType);

        if (in) {
            std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
            w->wallet->get_payments(payments, 0, CRYPTONOTE_MAX_BLOCK_NUMBER, account_index);
            for (const auto& p : payments) {
                const auto& pd = p.second;
                std::string txid = epee::string_tools::pod_to_hex(pd.m_tx_hash);
                bool locked = !w->wallet->is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
                uint64_t confs = (pd.m_block_height < bc_height) ? (bc_height - pd.m_block_height) : 0;
                std::string type = pd.m_coinbase ? "block" : "in";
                add_transfer_entry(in_arr, alloc, txid, type,
                    pd.m_amount, pd.m_fee, pd.m_block_height,
                    pd.m_timestamp, confs, pd.m_unlock_time, locked);
            }
        }

        if (out) {
            std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> payments;
            w->wallet->get_payments_out(payments, 0, CRYPTONOTE_MAX_BLOCK_NUMBER, account_index);
            for (const auto& p : payments) {
                const auto& pd = p.second;
                std::string txid = epee::string_tools::pod_to_hex(p.first);
                bool locked = !w->wallet->is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
                uint64_t confs = (pd.m_block_height < bc_height) ? (bc_height - pd.m_block_height) : 0;
                uint64_t fee = pd.m_amount_in - pd.m_amount_out;
                uint64_t change = (pd.m_change == (uint64_t)-1) ? 0 : pd.m_change;
                uint64_t amount = pd.m_amount_in - change - fee;
                add_transfer_entry(out_arr, alloc, txid, "out",
                    amount, fee, pd.m_block_height,
                    pd.m_timestamp, confs, pd.m_unlock_time, locked);
            }
        }

        if (pending || failed) {
            std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> upayments;
            w->wallet->get_unconfirmed_payments_out(upayments, account_index);
            for (const auto& p : upayments) {
                const auto& pd = p.second;
                bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
                if (!((!is_failed && pending) || (is_failed && failed)))
                    continue;
                std::string txid = epee::string_tools::pod_to_hex(p.first);
                uint64_t fee = pd.m_amount_in - pd.m_amount_out;
                uint64_t amount = pd.m_amount_in - pd.m_change - fee;
                std::string type = is_failed ? "failed" : "pending";
                add_transfer_entry(is_failed ? failed_arr : pending_arr, alloc,
                    txid, type, amount, fee, 0,
                    pd.m_timestamp, 0, pd.m_tx.unlock_time, true);
            }
        }

        if (pool) {
            std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_txs;
            w->wallet->update_pool_state(process_txs);
            if (!process_txs.empty())
                w->wallet->process_pool_state(process_txs);

            std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> ppayments;
            w->wallet->get_unconfirmed_payments(ppayments, account_index);
            for (const auto& p : ppayments) {
                const auto& pd = p.second.m_pd;
                std::string txid = epee::string_tools::pod_to_hex(pd.m_tx_hash);
                add_transfer_entry(pool_arr, alloc, txid, "pool",
                    pd.m_amount, pd.m_fee, 0,
                    pd.m_timestamp, 0, pd.m_unlock_time, true);
            }
        }

        doc.AddMember("in", in_arr, alloc);
        doc.AddMember("out", out_arr, alloc);
        doc.AddMember("pending", pending_arr, alloc);
        doc.AddMember("failed", failed_arr, alloc);
        doc.AddMember("pool", pool_arr, alloc);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

// ── Control ──────────────────────────────────────────────────────────────────

int wallet2_ffi_stop(wallet2_handle* w)
{
    if (!w || !w->wallet) return WALLET_RPC_ERROR_CODE_NOT_OPEN;
    w->clear_error();

    try {
        w->wallet->store();
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return w->last_error_code;
    }
    return 0;
}

bool wallet2_ffi_is_open(const wallet2_handle* w)
{
    return w && w->wallet && !w->wallet->get_wallet_file().empty();
}

uint64_t wallet2_ffi_get_height(const wallet2_handle* w)
{
    if (!w || !w->wallet) return 0;
    return w->wallet->get_blockchain_current_height();
}

// ── Generic JSON-RPC dispatcher ──────────────────────────────────────────────

static rj::Value json_val_str(const std::string& s, rj::Document::AllocatorType& a) {
    return rj::Value(s.c_str(), a);
}

static uint32_t json_u32(const rj::Value& v, const char* key, uint32_t def = 0) {
    if (v.HasMember(key) && v[key].IsUint()) return v[key].GetUint();
    return def;
}
static uint64_t json_u64(const rj::Value& v, const char* key, uint64_t def = 0) {
    if (v.HasMember(key) && v[key].IsUint64()) return v[key].GetUint64();
    return def;
}
static bool json_bool(const rj::Value& v, const char* key, bool def = false) {
    if (v.HasMember(key) && v[key].IsBool()) return v[key].GetBool();
    return def;
}
static std::string json_str(const rj::Value& v, const char* key, const char* def = "") {
    if (v.HasMember(key) && v[key].IsString()) return v[key].GetString();
    return def;
}

static char* dispatch_get_height(wallet2_handle* w, const rj::Value&) {
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("height", w->wallet->get_blockchain_current_height(), a);
    return json_to_string(doc);
}

static char* dispatch_get_accounts(wallet2_handle* w, const rj::Value& p) {
    std::string tag = json_str(p, "tag");
    bool strict = json_bool(p, "strict_balances");

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();

    uint64_t total_balance = 0, total_unlocked = 0;
    rj::Value accounts(rj::kArrayType);

    for (uint32_t i = 0; i < w->wallet->get_num_subaddress_accounts(); ++i) {
        auto account_tags = w->wallet->get_account_tags();
        std::string account_tag;
        if (i < account_tags.second.size()) account_tag = account_tags.second[i];
        if (!tag.empty() && account_tag != tag) continue;

        uint64_t bal = w->wallet->balance(i, strict);
        uint64_t ubal = w->wallet->unlocked_balance(i, strict);
        total_balance += bal;
        total_unlocked += ubal;

        rj::Value obj(rj::kObjectType);
        obj.AddMember("account_index", i, a);
        obj.AddMember("base_address", json_val_str(w->wallet->get_subaddress_as_str({i, 0}), a), a);
        obj.AddMember("balance", bal, a);
        obj.AddMember("unlocked_balance", ubal, a);
        obj.AddMember("label", json_val_str(w->wallet->get_subaddress_label({i, 0}), a), a);
        obj.AddMember("tag", json_val_str(account_tag, a), a);
        accounts.PushBack(obj, a);
    }

    doc.AddMember("total_balance", total_balance, a);
    doc.AddMember("total_unlocked_balance", total_unlocked, a);
    doc.AddMember("subaddress_accounts", accounts, a);
    return json_to_string(doc);
}

static char* dispatch_create_account(wallet2_handle* w, const rj::Value& p) {
    std::string label = json_str(p, "label");
    w->wallet->add_subaddress_account(label);
    uint32_t idx = w->wallet->get_num_subaddress_accounts() - 1;
    std::string addr = w->wallet->get_subaddress_as_str({idx, 0});

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("account_index", idx, a);
    doc.AddMember("address", json_val_str(addr, a), a);
    return json_to_string(doc);
}

static char* dispatch_label_account(wallet2_handle* w, const rj::Value& p) {
    uint32_t idx = json_u32(p, "account_index");
    std::string label = json_str(p, "label");
    w->wallet->set_subaddress_label({idx, 0}, label);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_create_address(wallet2_handle* w, const rj::Value& p) {
    uint32_t acct = json_u32(p, "account_index");
    uint32_t count = json_u32(p, "count", 1);
    std::string label = json_str(p, "label");

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value addresses(rj::kArrayType);
    rj::Value indices(rj::kArrayType);
    std::string first_addr;
    uint32_t first_idx = 0;

    for (uint32_t i = 0; i < count; ++i) {
        w->wallet->add_subaddress(acct, label);
        uint32_t new_idx = w->wallet->get_num_subaddresses(acct) - 1;
        std::string addr = w->wallet->get_subaddress_as_str({acct, new_idx});
        if (i == 0) { first_addr = addr; first_idx = new_idx; }
        addresses.PushBack(json_val_str(addr, a), a);
        indices.PushBack(new_idx, a);
    }

    doc.AddMember("address", json_val_str(first_addr, a), a);
    doc.AddMember("address_index", first_idx, a);
    doc.AddMember("addresses", addresses, a);
    doc.AddMember("address_indices", indices, a);
    return json_to_string(doc);
}

static char* dispatch_label_address(wallet2_handle* w, const rj::Value& p) {
    std::string label = json_str(p, "label");
    uint32_t major = 0, minor = 0;
    if (p.HasMember("index") && p["index"].IsObject()) {
        major = json_u32(p["index"], "major");
        minor = json_u32(p["index"], "minor");
    }
    w->wallet->set_subaddress_label({major, minor}, label);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_get_account_tags(wallet2_handle* w, const rj::Value&) {
    auto tags_pair = w->wallet->get_account_tags();
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value tags(rj::kArrayType);
    for (const auto& t : tags_pair.first) {
        rj::Value obj(rj::kObjectType);
        obj.AddMember("tag", json_val_str(t.first, a), a);
        obj.AddMember("label", json_val_str(t.second, a), a);
        rj::Value accts(rj::kArrayType);
        for (uint32_t i = 0; i < tags_pair.second.size(); ++i) {
            if (tags_pair.second[i] == t.first)
                accts.PushBack(i, a);
        }
        obj.AddMember("accounts", accts, a);
        tags.PushBack(obj, a);
    }
    doc.AddMember("account_tags", tags, a);
    return json_to_string(doc);
}

static char* dispatch_tag_accounts(wallet2_handle* w, const rj::Value& p) {
    std::string tag = json_str(p, "tag");
    std::set<uint32_t> accounts;
    if (p.HasMember("accounts") && p["accounts"].IsArray()) {
        for (auto& v : p["accounts"].GetArray()) {
            if (v.IsUint()) accounts.insert(v.GetUint());
        }
    }
    w->wallet->set_account_tag(accounts, tag);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_untag_accounts(wallet2_handle* w, const rj::Value& p) {
    std::set<uint32_t> accounts;
    if (p.HasMember("accounts") && p["accounts"].IsArray()) {
        for (auto& v : p["accounts"].GetArray()) {
            if (v.IsUint()) accounts.insert(v.GetUint());
        }
    }
    w->wallet->set_account_tag(accounts, "");
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_set_account_tag_description(wallet2_handle* w, const rj::Value& p) {
    w->wallet->set_account_tag_description(json_str(p, "tag"), json_str(p, "description"));
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_store(wallet2_handle* w, const rj::Value&) {
    w->wallet->store();
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_get_languages(wallet2_handle*, const rj::Value&) {
    std::vector<std::string> languages;
    std::vector<std::string> languages_local;
    crypto::ElectrumWords::get_language_list(languages);
    crypto::ElectrumWords::get_language_list(languages_local, true);

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value langs(rj::kArrayType);
    rj::Value langs_local(rj::kArrayType);
    for (const auto& l : languages) langs.PushBack(json_val_str(l, a), a);
    for (const auto& l : languages_local) langs_local.PushBack(json_val_str(l, a), a);
    doc.AddMember("languages", langs, a);
    doc.AddMember("languages_local", langs_local, a);
    return json_to_string(doc);
}

static char* dispatch_change_wallet_password(wallet2_handle* w, const rj::Value& p) {
    std::string old_pw = json_str(p, "old_password");
    std::string new_pw = json_str(p, "new_password");
    if (!w->wallet->verify_password(old_pw)) {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_PASSWORD, "Invalid original password");
        return nullptr;
    }
    w->wallet->change_password(w->wallet->get_wallet_file(), old_pw, new_pw);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_refresh(wallet2_handle* w, const rj::Value& p) {
    uint64_t start_height = json_u64(p, "start_height");
    uint64_t blocks_fetched = 0;
    bool received_money = false;
    w->wallet->refresh(w->wallet->is_trusted_daemon(), start_height, blocks_fetched, received_money);
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("blocks_fetched", blocks_fetched, a);
    doc.AddMember("received_money", received_money, a);
    return json_to_string(doc);
}

static char* dispatch_rescan_blockchain(wallet2_handle* w, const rj::Value& p) {
    bool hard = json_bool(p, "hard");
    w->wallet->rescan_blockchain(hard);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_rescan_spent(wallet2_handle* w, const rj::Value&) {
    w->wallet->rescan_spent();
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_set_tx_notes(wallet2_handle* w, const rj::Value& p) {
    if (!p.HasMember("txids") || !p["txids"].IsArray() || !p.HasMember("notes") || !p["notes"].IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "txids and notes arrays required");
        return nullptr;
    }
    auto& txids = p["txids"];
    auto& notes = p["notes"];
    if (txids.Size() != notes.Size()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "txids and notes must be same length");
        return nullptr;
    }
    for (rj::SizeType i = 0; i < txids.Size(); ++i) {
        crypto::hash txid;
        if (!epee::string_tools::hex_to_pod(txids[i].GetString(), txid)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "Invalid txid");
            return nullptr;
        }
        w->wallet->set_tx_note(txid, notes[i].GetString());
    }
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_get_tx_notes(wallet2_handle* w, const rj::Value& p) {
    if (!p.HasMember("txids") || !p["txids"].IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "txids array required");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value notes_arr(rj::kArrayType);
    for (auto& v : p["txids"].GetArray()) {
        crypto::hash txid;
        if (!epee::string_tools::hex_to_pod(v.GetString(), txid)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "Invalid txid");
            return nullptr;
        }
        notes_arr.PushBack(json_val_str(w->wallet->get_tx_note(txid), a), a);
    }
    doc.AddMember("notes", notes_arr, a);
    return json_to_string(doc);
}

static char* dispatch_set_attribute(wallet2_handle* w, const rj::Value& p) {
    w->wallet->set_attribute(json_str(p, "key"), json_str(p, "value"));
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_get_attribute(wallet2_handle* w, const rj::Value& p) {
    std::string val;
    if (!w->wallet->get_attribute(json_str(p, "key"), val)) {
        w->set_error(WALLET_RPC_ERROR_CODE_ATTRIBUTE_NOT_FOUND, "Attribute not found");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("value", json_val_str(val, a), a);
    return json_to_string(doc);
}

static char* dispatch_freeze(wallet2_handle* w, const rj::Value& p) {
    std::string ki_str = json_str(p, "key_image");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(ki_str, ki)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE, "Invalid key image");
        return nullptr;
    }
    w->wallet->freeze(ki);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_thaw(wallet2_handle* w, const rj::Value& p) {
    std::string ki_str = json_str(p, "key_image");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(ki_str, ki)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE, "Invalid key image");
        return nullptr;
    }
    w->wallet->thaw(ki);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_frozen(wallet2_handle* w, const rj::Value& p) {
    std::string ki_str = json_str(p, "key_image");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(ki_str, ki)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE, "Invalid key image");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("frozen", w->wallet->frozen(ki), a);
    return json_to_string(doc);
}

static char* dispatch_validate_address(wallet2_handle* w, const rj::Value& p) {
    std::string address = json_str(p, "address");
    bool any_net = json_bool(p, "any_net_type");

    cryptonote::address_parse_info info;
    cryptonote::network_type net = w->wallet ? w->wallet->nettype() : cryptonote::MAINNET;
    bool valid = false;

    if (any_net) {
        for (auto nt : {cryptonote::MAINNET, cryptonote::TESTNET, cryptonote::STAGENET}) {
            if (get_account_address_from_str(info, nt, address)) {
                valid = true;
                net = nt;
                break;
            }
        }
    } else {
        valid = get_account_address_from_str(info, net, address);
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("valid", valid, a);
    doc.AddMember("integrated", valid && info.has_payment_id, a);
    doc.AddMember("subaddress", valid && info.is_subaddress, a);
    const char* nt_str = "mainnet";
    if (net == cryptonote::TESTNET) nt_str = "testnet";
    else if (net == cryptonote::STAGENET) nt_str = "stagenet";
    doc.AddMember("nettype", rj::Value(nt_str, a), a);
    doc.AddMember("openalias_address", "", a);
    return json_to_string(doc);
}

static char* dispatch_get_tx_key(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "Invalid txid");
        return nullptr;
    }
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    if (!w->wallet->get_tx_key(txid, tx_key, additional_tx_keys)) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_TXKEY, "No tx secret key found for txid");
        return nullptr;
    }
    epee::wipeable_string ws;
    ws += epee::to_hex::wipeable_string(tx_key);
    for (const auto& k : additional_tx_keys)
        ws += epee::to_hex::wipeable_string(k);
    std::string key_str(ws.data(), ws.size());

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("tx_key", json_val_str(key_str, a), a);
    return json_to_string(doc);
}

static char* dispatch_get_transfer_by_txid(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    uint32_t account_index = json_u32(p, "account_index");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "Invalid txid");
        return nullptr;
    }

    uint64_t bc_height = w->wallet->get_blockchain_current_height();

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value transfers(rj::kArrayType);

    // Incoming
    std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
    w->wallet->get_payments(payments, 0, CRYPTONOTE_MAX_BLOCK_NUMBER, account_index);
    for (const auto& pp : payments) {
        if (pp.second.m_tx_hash == txid) {
            const auto& pd = pp.second;
            rj::Value obj(rj::kObjectType);
            obj.AddMember("txid", json_val_str(epee::string_tools::pod_to_hex(pd.m_tx_hash), a), a);
            obj.AddMember("type", json_val_str(pd.m_coinbase ? "block" : "in", a), a);
            obj.AddMember("amount", pd.m_amount, a);
            obj.AddMember("fee", pd.m_fee, a);
            obj.AddMember("height", pd.m_block_height, a);
            obj.AddMember("timestamp", pd.m_timestamp, a);
            uint64_t confs = (pd.m_block_height < bc_height) ? (bc_height - pd.m_block_height) : 0;
            obj.AddMember("confirmations", confs, a);
            transfers.PushBack(obj, a);
        }
    }

    // Outgoing
    std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> out_payments;
    w->wallet->get_payments_out(out_payments, 0, CRYPTONOTE_MAX_BLOCK_NUMBER, account_index);
    for (const auto& pp : out_payments) {
        if (pp.first == txid) {
            const auto& pd = pp.second;
            rj::Value obj(rj::kObjectType);
            obj.AddMember("txid", json_val_str(epee::string_tools::pod_to_hex(pp.first), a), a);
            obj.AddMember("type", "out", a);
            uint64_t fee = pd.m_amount_in - pd.m_amount_out;
            uint64_t change = (pd.m_change == (uint64_t)-1) ? 0 : pd.m_change;
            obj.AddMember("amount", pd.m_amount_in - change - fee, a);
            obj.AddMember("fee", fee, a);
            obj.AddMember("height", pd.m_block_height, a);
            obj.AddMember("timestamp", pd.m_timestamp, a);
            uint64_t confs = (pd.m_block_height < bc_height) ? (bc_height - pd.m_block_height) : 0;
            obj.AddMember("confirmations", confs, a);
            transfers.PushBack(obj, a);
        }
    }

    if (transfers.Empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "Transaction not found");
        return nullptr;
    }
    doc.AddMember("transfer", transfers[0], a);
    doc.AddMember("transfers", transfers, a);
    return json_to_string(doc);
}

static char* dispatch_export_key_images(wallet2_handle* w, const rj::Value& p) {
    bool all = json_bool(p, "all");
    auto kis = w->wallet->export_key_images(all);

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value arr(rj::kArrayType);
    for (const auto& ki : kis.second) {
        rj::Value obj(rj::kObjectType);
        obj.AddMember("key_image", json_val_str(epee::string_tools::pod_to_hex(ki.first), a), a);
        obj.AddMember("signature", json_val_str(epee::string_tools::pod_to_hex(ki.second), a), a);
        arr.PushBack(obj, a);
    }
    doc.AddMember("offset", static_cast<uint64_t>(kis.first), a);
    doc.AddMember("signed_key_images", arr, a);
    return json_to_string(doc);
}

static char* dispatch_export_outputs(wallet2_handle* w, const rj::Value& p) {
    bool all = json_bool(p, "all");
    uint32_t start = json_u32(p, "start");
    uint32_t count = json_u32(p, "count");
    std::string hex = epee::string_tools::buff_to_hex_nodelimer(
        w->wallet->export_outputs_to_str(all, start, count));

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("outputs_data_hex", json_val_str(hex, a), a);
    return json_to_string(doc);
}

static char* dispatch_import_outputs(wallet2_handle* w, const rj::Value& p) {
    std::string hex = json_str(p, "outputs_data_hex");
    std::string data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(hex, data)) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_HEX, "Failed to parse hex");
        return nullptr;
    }
    size_t n = w->wallet->import_outputs_from_str(data);
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("num_imported", (uint64_t)n, a);
    return json_to_string(doc);
}

static char* dispatch_get_payments(wallet2_handle* w, const rj::Value& p) {
    std::string pid_str = json_str(p, "payment_id");
    cryptonote::blobdata pid_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(pid_str, pid_blob)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID, "Payment ID has invalid format");
        return nullptr;
    }

    crypto::hash payment_id;
    if (pid_blob.size() == sizeof(crypto::hash)) {
        payment_id = *reinterpret_cast<const crypto::hash*>(pid_blob.data());
    } else if (pid_blob.size() == sizeof(crypto::hash8)) {
        crypto::hash8 pid8 = *reinterpret_cast<const crypto::hash8*>(pid_blob.data());
        memcpy(payment_id.data, pid8.data, 8);
        memset(payment_id.data + 8, 0, 24);
    } else {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID, "Payment ID has invalid size: " + pid_str);
        return nullptr;
    }

    std::list<tools::wallet2::payment_details> payment_list;
    w->wallet->get_payments(payment_id, payment_list);

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value arr(rj::kArrayType);
    for (const auto& pd : payment_list) {
        rj::Value obj(rj::kObjectType);
        obj.AddMember("payment_id", json_val_str(pid_str, a), a);
        obj.AddMember("tx_hash", json_val_str(epee::string_tools::pod_to_hex(pd.m_tx_hash), a), a);
        obj.AddMember("amount", pd.m_amount, a);
        obj.AddMember("block_height", pd.m_block_height, a);
        obj.AddMember("unlock_time", pd.m_unlock_time, a);
        obj.AddMember("locked", !w->wallet->is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height), a);
        rj::Value idx(rj::kObjectType);
        idx.AddMember("major", pd.m_subaddr_index.major, a);
        idx.AddMember("minor", pd.m_subaddr_index.minor, a);
        obj.AddMember("subaddr_index", idx, a);
        obj.AddMember("address", json_val_str(w->wallet->get_subaddress_as_str(pd.m_subaddr_index), a), a);
        arr.PushBack(obj, a);
    }
    doc.AddMember("payments", arr, a);
    return json_to_string(doc);
}

static char* dispatch_get_bulk_payments(wallet2_handle* w, const rj::Value& p) {
    uint64_t min_height = json_u64(p, "min_block_height");

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value arr(rj::kArrayType);

    bool has_ids = p.HasMember("payment_ids") && p["payment_ids"].IsArray() && p["payment_ids"].Size() > 0;

    if (!has_ids) {
        std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payment_list;
        w->wallet->get_payments(payment_list, min_height);
        for (const auto& pp : payment_list) {
            rj::Value obj(rj::kObjectType);
            obj.AddMember("payment_id", json_val_str(epee::string_tools::pod_to_hex(pp.first), a), a);
            obj.AddMember("tx_hash", json_val_str(epee::string_tools::pod_to_hex(pp.second.m_tx_hash), a), a);
            obj.AddMember("amount", pp.second.m_amount, a);
            obj.AddMember("block_height", pp.second.m_block_height, a);
            obj.AddMember("unlock_time", pp.second.m_unlock_time, a);
            obj.AddMember("locked", !w->wallet->is_transfer_unlocked(pp.second.m_unlock_time, pp.second.m_block_height), a);
            rj::Value idx(rj::kObjectType);
            idx.AddMember("major", pp.second.m_subaddr_index.major, a);
            idx.AddMember("minor", pp.second.m_subaddr_index.minor, a);
            obj.AddMember("subaddr_index", idx, a);
            obj.AddMember("address", json_val_str(w->wallet->get_subaddress_as_str(pp.second.m_subaddr_index), a), a);
            arr.PushBack(obj, a);
        }
    } else {
        for (auto& v : p["payment_ids"].GetArray()) {
            std::string pid_str = v.GetString();
            crypto::hash payment_id;
            crypto::hash8 payment_id8;
            bool r;
            if (pid_str.size() == 2 * sizeof(crypto::hash)) {
                r = epee::string_tools::hex_to_pod(pid_str, payment_id);
            } else if (pid_str.size() == 2 * sizeof(crypto::hash8)) {
                r = epee::string_tools::hex_to_pod(pid_str, payment_id8);
                if (r) {
                    memcpy(payment_id.data, payment_id8.data, 8);
                    memset(payment_id.data + 8, 0, 24);
                }
            } else {
                w->set_error(WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID, "Payment ID has invalid size: " + pid_str);
                return nullptr;
            }
            if (!r) {
                w->set_error(WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID, "Payment ID has invalid format: " + pid_str);
                return nullptr;
            }

            std::list<tools::wallet2::payment_details> payment_list;
            w->wallet->get_payments(payment_id, payment_list, min_height);
            for (const auto& pd : payment_list) {
                rj::Value obj(rj::kObjectType);
                obj.AddMember("payment_id", json_val_str(pid_str, a), a);
                obj.AddMember("tx_hash", json_val_str(epee::string_tools::pod_to_hex(pd.m_tx_hash), a), a);
                obj.AddMember("amount", pd.m_amount, a);
                obj.AddMember("block_height", pd.m_block_height, a);
                obj.AddMember("unlock_time", pd.m_unlock_time, a);
                obj.AddMember("locked", !w->wallet->is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height), a);
                rj::Value idx(rj::kObjectType);
                idx.AddMember("major", pd.m_subaddr_index.major, a);
                idx.AddMember("minor", pd.m_subaddr_index.minor, a);
                obj.AddMember("subaddr_index", idx, a);
                obj.AddMember("address", json_val_str(w->wallet->get_subaddress_as_str(pd.m_subaddr_index), a), a);
                arr.PushBack(obj, a);
            }
        }
    }

    doc.AddMember("payments", arr, a);
    return json_to_string(doc);
}

static char* dispatch_import_key_images(wallet2_handle* w, const rj::Value& p) {
    if (!p.HasMember("signed_key_images") || !p["signed_key_images"].IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "signed_key_images array required");
        return nullptr;
    }
    const auto& ski_arr = p["signed_key_images"];
    std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
    ski.resize(ski_arr.Size());
    for (rj::SizeType n = 0; n < ski_arr.Size(); ++n) {
        const auto& item = ski_arr[n];
        std::string ki_hex = item.HasMember("key_image") && item["key_image"].IsString() ? item["key_image"].GetString() : "";
        std::string sig_hex = item.HasMember("signature") && item["signature"].IsString() ? item["signature"].GetString() : "";
        if (!epee::string_tools::hex_to_pod(ki_hex, ski[n].first)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE, "Failed to parse key image");
            return nullptr;
        }
        if (!epee::string_tools::hex_to_pod(sig_hex, ski[n].second)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_SIGNATURE, "Failed to parse signature");
            return nullptr;
        }
    }

    uint64_t spent = 0, unspent = 0;
    size_t offset = static_cast<size_t>(json_u64(p, "offset"));
    uint64_t height = w->wallet->import_key_images(ski, offset, spent, unspent);

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("height", height, a);
    doc.AddMember("spent", spent, a);
    doc.AddMember("unspent", unspent, a);
    return json_to_string(doc);
}

static char* dispatch_make_integrated_address(wallet2_handle* w, const rj::Value& p) {
    std::string pid_str = json_str(p, "payment_id");
    std::string std_addr = json_str(p, "standard_address");

    crypto::hash8 payment_id;
    if (pid_str.empty()) {
        payment_id = crypto::rand<crypto::hash8>();
    } else {
        if (!tools::wallet2::parse_short_payment_id(pid_str, payment_id)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID, "Invalid payment ID");
            return nullptr;
        }
    }

    std::string integrated_address;
    if (std_addr.empty()) {
        integrated_address = w->wallet->get_integrated_address_as_str(payment_id);
    } else {
        cryptonote::address_parse_info info;
        if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(), std_addr)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
            return nullptr;
        }
        if (info.is_subaddress) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Subaddress shouldn't be used");
            return nullptr;
        }
        if (info.has_payment_id) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Already integrated address");
            return nullptr;
        }
        integrated_address = cryptonote::get_account_integrated_address_as_str(
            w->wallet->nettype(), info.address, payment_id);
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("integrated_address", json_val_str(integrated_address, a), a);
    doc.AddMember("payment_id", json_val_str(epee::string_tools::pod_to_hex(payment_id), a), a);
    return json_to_string(doc);
}

static char* dispatch_split_integrated_address(wallet2_handle* w, const rj::Value& p) {
    std::string addr_str = json_str(p, "integrated_address");
    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(), addr_str)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }
    if (!info.has_payment_id) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Address is not an integrated address");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("standard_address", json_val_str(
        cryptonote::get_account_address_as_str(w->wallet->nettype(), info.is_subaddress, info.address), a), a);
    doc.AddMember("payment_id", json_val_str(epee::string_tools::pod_to_hex(info.payment_id), a), a);
    doc.AddMember("is_subaddress", info.is_subaddress, a);
    return json_to_string(doc);
}

static char* dispatch_make_uri(wallet2_handle* w, const rj::Value& p) {
    std::string address = json_str(p, "address");
    std::string payment_id = json_str(p, "payment_id");
    uint64_t amount = json_u64(p, "amount");
    std::string tx_description = json_str(p, "tx_description");
    std::string recipient_name = json_str(p, "recipient_name");

    std::string error;
    std::string uri = w->wallet->make_uri(address, payment_id, amount, tx_description, recipient_name, error);
    if (uri.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_URI, "Cannot make URI from supplied parameters: " + error);
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("uri", json_val_str(uri, a), a);
    return json_to_string(doc);
}

static char* dispatch_parse_uri(wallet2_handle* w, const rj::Value& p) {
    std::string uri_str = json_str(p, "uri");
    std::string address, payment_id, tx_description, recipient_name;
    uint64_t amount = 0;
    std::vector<std::string> unknown_parameters;
    std::string error;

    if (!w->wallet->parse_uri(uri_str, address, payment_id, amount, tx_description, recipient_name, unknown_parameters, error)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_URI, "Error parsing URI: " + error);
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value uri_obj(rj::kObjectType);
    uri_obj.AddMember("address", json_val_str(address, a), a);
    uri_obj.AddMember("payment_id", json_val_str(payment_id, a), a);
    uri_obj.AddMember("amount", amount, a);
    uri_obj.AddMember("tx_description", json_val_str(tx_description, a), a);
    uri_obj.AddMember("recipient_name", json_val_str(recipient_name, a), a);
    doc.AddMember("uri", uri_obj, a);
    rj::Value unk(rj::kArrayType);
    for (const auto& s : unknown_parameters)
        unk.PushBack(json_val_str(s, a), a);
    doc.AddMember("unknown_parameters", unk, a);
    return json_to_string(doc);
}

static char* dispatch_get_address_book(wallet2_handle* w, const rj::Value& p) {
    const auto ab = w->wallet->get_address_book();

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value arr(rj::kArrayType);

    bool has_entries = p.HasMember("entries") && p["entries"].IsArray() && p["entries"].Size() > 0;
    if (!has_entries) {
        uint64_t idx = 0;
        for (const auto& entry : ab) {
            rj::Value obj(rj::kObjectType);
            obj.AddMember("index", idx, a);
            std::string address;
            if (entry.m_has_payment_id)
                address = cryptonote::get_account_integrated_address_as_str(w->wallet->nettype(), entry.m_address, entry.m_payment_id);
            else
                address = cryptonote::get_account_address_as_str(w->wallet->nettype(), entry.m_is_subaddress, entry.m_address);
            obj.AddMember("address", json_val_str(address, a), a);
            obj.AddMember("description", json_val_str(entry.m_description, a), a);
            arr.PushBack(obj, a);
            ++idx;
        }
    } else {
        for (auto& v : p["entries"].GetArray()) {
            uint64_t idx = v.IsUint64() ? v.GetUint64() : 0;
            if (idx >= ab.size()) {
                w->set_error(WALLET_RPC_ERROR_CODE_WRONG_INDEX, "Index out of range: " + std::to_string(idx));
                return nullptr;
            }
            const auto& entry = ab[idx];
            rj::Value obj(rj::kObjectType);
            obj.AddMember("index", idx, a);
            std::string address;
            if (entry.m_has_payment_id)
                address = cryptonote::get_account_integrated_address_as_str(w->wallet->nettype(), entry.m_address, entry.m_payment_id);
            else
                address = cryptonote::get_account_address_as_str(w->wallet->nettype(), entry.m_is_subaddress, entry.m_address);
            obj.AddMember("address", json_val_str(address, a), a);
            obj.AddMember("description", json_val_str(entry.m_description, a), a);
            arr.PushBack(obj, a);
        }
    }

    doc.AddMember("entries", arr, a);
    return json_to_string(doc);
}

static char* dispatch_add_address_book(wallet2_handle* w, const rj::Value& p) {
    std::string addr_str = json_str(p, "address");
    std::string description = json_str(p, "description");

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(), addr_str)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: " + addr_str);
        return nullptr;
    }
    if (!w->wallet->add_address_book_row(info.address, info.has_payment_id ? &info.payment_id : nullptr, description, info.is_subaddress)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to add address book entry");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("index", static_cast<uint64_t>(w->wallet->get_address_book().size() - 1), a);
    return json_to_string(doc);
}

static char* dispatch_edit_address_book(wallet2_handle* w, const rj::Value& p) {
    uint64_t index = json_u64(p, "index");
    const auto ab = w->wallet->get_address_book();
    if (index >= ab.size()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_INDEX, "Index out of range: " + std::to_string(index));
        return nullptr;
    }

    tools::wallet2::address_book_row entry = ab[index];
    bool set_address = json_bool(p, "set_address");
    bool set_description = json_bool(p, "set_description");

    if (set_address) {
        std::string addr_str = json_str(p, "address");
        cryptonote::address_parse_info info;
        if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(), addr_str)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: " + addr_str);
            return nullptr;
        }
        entry.m_address = info.address;
        entry.m_is_subaddress = info.is_subaddress;
        if (info.has_payment_id) {
            entry.m_payment_id = info.payment_id;
            entry.m_has_payment_id = true;
        }
    }

    if (set_description)
        entry.m_description = json_str(p, "description");

    if (!w->wallet->set_address_book_row(index, entry.m_address,
            set_address && entry.m_has_payment_id ? &entry.m_payment_id : nullptr,
            entry.m_description, entry.m_is_subaddress)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to edit address book entry");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_delete_address_book(wallet2_handle* w, const rj::Value& p) {
    uint64_t index = json_u64(p, "index");
    const auto ab = w->wallet->get_address_book();
    if (index >= ab.size()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_INDEX, "Index out of range: " + std::to_string(index));
        return nullptr;
    }
    if (!w->wallet->delete_address_book_row(index)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to delete address book entry");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

// ── Proofs ────────────────────────────────────────────────────────────────────

static char* dispatch_check_tx_key(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "TX ID has invalid format");
        return nullptr;
    }

    epee::wipeable_string tx_key_str = json_str(p, "tx_key");
    if (tx_key_str.size() < 64 || tx_key_str.size() % 64) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY, "Tx key has invalid format");
        return nullptr;
    }
    const char *data = tx_key_str.data();
    crypto::secret_key tx_key;
    if (!epee::wipeable_string(data, 64).hex_to_pod(unwrap(unwrap(tx_key)))) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY, "Tx key has invalid format");
        return nullptr;
    }
    size_t offset = 64;
    std::vector<crypto::secret_key> additional_tx_keys;
    while (offset < tx_key_str.size()) {
        additional_tx_keys.resize(additional_tx_keys.size() + 1);
        if (!epee::wipeable_string(data + offset, 64).hex_to_pod(unwrap(unwrap(additional_tx_keys.back())))) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY, "Tx key has invalid format");
            return nullptr;
        }
        offset += 64;
    }

    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, w->wallet->nettype(), json_str(p, "address"))) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }

    try {
        uint64_t received = 0;
        bool in_pool = false;
        uint64_t confirmations = 0;
        w->wallet->check_tx_key(txid, tx_key, additional_tx_keys, info.address, received, in_pool, confirmations);

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("received", received, a);
        doc.AddMember("in_pool", in_pool, a);
        doc.AddMember("confirmations", confirmations, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

static char* dispatch_get_tx_proof(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "TX ID has invalid format");
        return nullptr;
    }

    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, w->wallet->nettype(), json_str(p, "address"))) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }

    try {
        std::string signature = w->wallet->get_tx_proof(txid, info.address, info.is_subaddress, json_str(p, "message"));
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("signature", json_val_str(signature, a), a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

static char* dispatch_check_tx_proof(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "TX ID has invalid format");
        return nullptr;
    }

    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, w->wallet->nettype(), json_str(p, "address"))) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }

    try {
        uint64_t received = 0;
        bool in_pool = false;
        uint64_t confirmations = 0;
        bool good = w->wallet->check_tx_proof(txid, info.address, info.is_subaddress,
            json_str(p, "message"), json_str(p, "signature"), received, in_pool, confirmations);

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("good", good, a);
        doc.AddMember("received", received, a);
        doc.AddMember("in_pool", in_pool, a);
        doc.AddMember("confirmations", confirmations, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

static char* dispatch_get_spend_proof(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "TX ID has invalid format");
        return nullptr;
    }

    try {
        std::string signature = w->wallet->get_spend_proof(txid, json_str(p, "message"));
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("signature", json_val_str(signature, a), a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

static char* dispatch_check_spend_proof(wallet2_handle* w, const rj::Value& p) {
    std::string txid_str = json_str(p, "txid");
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(txid_str, txid)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "TX ID has invalid format");
        return nullptr;
    }

    try {
        bool good = w->wallet->check_spend_proof(txid, json_str(p, "message"), json_str(p, "signature"));
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("good", good, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

static char* dispatch_get_reserve_proof(wallet2_handle* w, const rj::Value& p) {
    bool all = json_bool(p, "all");
    std::optional<std::pair<uint32_t, uint64_t>> account_minreserve;
    if (!all) {
        uint32_t account_index = json_u32(p, "account_index");
        if (account_index >= w->wallet->get_num_subaddress_accounts()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Account index is out of bound");
            return nullptr;
        }
        account_minreserve = std::make_pair(account_index, json_u64(p, "amount"));
    }

    try {
        std::string signature = w->wallet->get_reserve_proof(account_minreserve, json_str(p, "message"));
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("signature", json_val_str(signature, a), a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

static char* dispatch_check_reserve_proof(wallet2_handle* w, const rj::Value& p) {
    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, w->wallet->nettype(), json_str(p, "address"))) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }
    if (info.is_subaddress) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Address must not be a subaddress");
        return nullptr;
    }

    try {
        uint64_t total = 0, spent = 0;
        bool good = w->wallet->check_reserve_proof(info.address, json_str(p, "message"),
            json_str(p, "signature"), total, spent);

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("good", good, a);
        doc.AddMember("total", total, a);
        doc.AddMember("spent", spent, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
}

// ── Mining & Daemon ──────────────────────────────────────────────────────────

static char* dispatch_start_mining(wallet2_handle* w, const rj::Value& p) {
    if (!w->wallet->is_trusted_daemon()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "This command requires a trusted daemon.");
        return nullptr;
    }

    uint64_t threads_count = json_u64(p, "threads_count", 1);
    size_t max_threads = (std::max)(tools::get_max_concurrency(), static_cast<unsigned>(2));
    if (threads_count < 1 || max_threads < threads_count) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "The specified number of threads is inappropriate.");
        return nullptr;
    }

    cryptonote::COMMAND_RPC_START_MINING::request daemon_req = AUTO_VAL_INIT(daemon_req);
    daemon_req.miner_address = w->wallet->get_account().get_public_address_str(w->wallet->nettype());
    daemon_req.threads_count = threads_count;
    daemon_req.do_background_mining = json_bool(p, "do_background_mining");
    daemon_req.ignore_battery = json_bool(p, "ignore_battery");

    cryptonote::COMMAND_RPC_START_MINING::response daemon_res;
    bool r = w->wallet->invoke_http_json("/start_mining", daemon_req, daemon_res);
    if (!r || daemon_res.status != CORE_RPC_STATUS_OK) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Couldn't start mining due to unknown error.");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_stop_mining(wallet2_handle* w, const rj::Value&) {
    cryptonote::COMMAND_RPC_STOP_MINING::request daemon_req;
    cryptonote::COMMAND_RPC_STOP_MINING::response daemon_res;
    bool r = w->wallet->invoke_http_json("/stop_mining", daemon_req, daemon_res);
    if (!r || daemon_res.status != CORE_RPC_STATUS_OK) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Couldn't stop mining due to unknown error.");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_set_daemon(wallet2_handle* w, const rj::Value& p) {
    std::string address = json_str(p, "address");
    bool trusted = json_bool(p, "trusted");
    std::string proxy = json_str(p, "proxy");

    if (w->wallet->has_proxy_option() && !proxy.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_PROXY_ALREADY_DEFINED,
            "It is not possible to set daemon specific proxy when --proxy is defined.");
        return nullptr;
    }

    std::vector<std::vector<uint8_t>> ssl_allowed_fingerprints;
    if (p.HasMember("ssl_allowed_fingerprints") && p["ssl_allowed_fingerprints"].IsArray()) {
        for (auto& v : p["ssl_allowed_fingerprints"].GetArray()) {
            if (!v.IsString()) continue;
            std::string fp = v.GetString();
            ssl_allowed_fingerprints.push_back({});
            auto& vec = ssl_allowed_fingerprints.back();
            for (auto c : fp) vec.push_back(c);
        }
    }

    std::string ssl_ca_file = json_str(p, "ssl_ca_file");
    bool ssl_allow_any_cert = json_bool(p, "ssl_allow_any_cert");
    std::string ssl_support_str = json_str(p, "ssl_support", "autodetect");

    epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_enabled;
    if (ssl_allow_any_cert)
        ssl_options.verification = epee::net_utils::ssl_verification_t::none;
    else if (!ssl_allowed_fingerprints.empty() || !ssl_ca_file.empty())
        ssl_options = epee::net_utils::ssl_options_t{std::move(ssl_allowed_fingerprints), std::move(ssl_ca_file)};

    if (!epee::net_utils::ssl_support_from_string(ssl_options.support, ssl_support_str)) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION, "Invalid ssl support mode");
        return nullptr;
    }

    ssl_options.auth = epee::net_utils::ssl_authentication_t{
        json_str(p, "ssl_private_key_path"), json_str(p, "ssl_certificate_path")
    };

    const bool verification_required =
        ssl_options.verification != epee::net_utils::ssl_verification_t::none &&
        ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_enabled;
    if (verification_required && !ssl_options.has_strong_verification(boost::string_ref{})) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION,
            "SSL is enabled but no user certificate or fingerprints were provided");
        return nullptr;
    }

    std::optional<epee::net_utils::http::login> daemon_login{};
    std::string username = json_str(p, "username");
    std::string password = json_str(p, "password");
    if (!username.empty() || !password.empty())
        daemon_login.emplace(username, password);

    if (!w->wallet->set_daemon(address, daemon_login, trusted, std::move(ssl_options), proxy)) {
        w->set_error(WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION, "Unable to set daemon");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_set_log_level(wallet2_handle* w, const rj::Value& p) {
    uint32_t level = json_u32(p, "level");
    if (level > 4) {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_LOG_LEVEL, "Error: log level not valid");
        return nullptr;
    }
    mlog_set_log_level(level);
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_set_log_categories(wallet2_handle*, const rj::Value& p) {
    std::string categories = json_str(p, "categories");
    mlog_set_log(categories.c_str());
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("categories", json_val_str(mlog_get_categories(), a), a);
    return json_to_string(doc);
}

static char* dispatch_scan_tx(wallet2_handle* w, const rj::Value& p) {
    if (!p.HasMember("txids") || !p["txids"].IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "txids array required");
        return nullptr;
    }

    std::unordered_set<crypto::hash> txids;
    for (auto& v : p["txids"].GetArray()) {
        if (!v.IsString()) continue;
        cryptonote::blobdata txid_blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(v.GetString(), txid_blob) ||
            txid_blob.size() != sizeof(crypto::hash)) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_TXID, "TX ID has invalid format");
            return nullptr;
        }
        txids.insert(*reinterpret_cast<const crypto::hash*>(txid_blob.data()));
    }

    try {
        w->wallet->scan_tx(txids);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

// ── Staking ──────────────────────────────────────────────────────────────────

static char* dispatch_stake(wallet2_handle* w, const rj::Value& p) {
    try {
        uint32_t tier = json_u32(p, "tier");
        uint64_t amount = json_u64(p, "amount");
        uint32_t priority = json_u32(p, "priority");
        uint32_t account_index = json_u32(p, "account_index");

        auto ptx_vector = w->wallet->create_staking_transaction(
            tier, amount, tools::fee_priority_utilities::from_integral(priority), account_index, {});
        if (ptx_vector.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "No transaction was created");
            return nullptr;
        }
        auto& ptx = ptx_vector.front();
        w->wallet->commit_tx(ptx);

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("tx_hash", json_val_str(
            epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)), a), a);
        doc.AddMember("fee", ptx.fee, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

static char* dispatch_unstake(wallet2_handle* w, const rj::Value& p) {
    try {
        auto matured = w->wallet->get_matured_staked_outputs();
        if (matured.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "No matured staked outputs available for unstaking");
            return nullptr;
        }
        uint32_t priority = json_u32(p, "priority");
        auto ptx_vector = w->wallet->create_unstake_transaction(
            matured, tools::fee_priority_utilities::from_integral(priority));
        if (ptx_vector.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "No transaction was created");
            return nullptr;
        }

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        rj::Value tx_hash_list(rj::kArrayType);
        uint64_t total_amount = 0;
        for (auto& ptx : ptx_vector) {
            w->wallet->commit_tx(ptx);
            tx_hash_list.PushBack(json_val_str(
                epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)), a), a);
            for (const auto& o : ptx.tx.vout)
                total_amount += o.amount;
        }

        doc.AddMember("tx_hash_list", tx_hash_list, a);
        doc.AddMember("amount", total_amount, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

static char* dispatch_get_staked_outputs(wallet2_handle* w, const rj::Value&) {
    try {
        const uint64_t current_height = w->wallet->get_blockchain_current_height();
        uint64_t total_staked = 0;

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        rj::Value outputs(rj::kArrayType);

        for (size_t i = 0; i < w->wallet->get_num_transfer_details(); ++i) {
            const auto& td = w->wallet->get_transfer_details(i);
            if (td.m_staked && !td.m_spent && !td.m_frozen) {
                rj::Value entry(rj::kObjectType);
                entry.AddMember("amount", td.m_amount, a);
                entry.AddMember("tier", td.m_stake_tier, a);
                entry.AddMember("lock_until", td.m_stake_lock_until, a);
                entry.AddMember("matured", td.m_stake_lock_until <= current_height, a);
                entry.AddMember("global_index", td.m_global_output_index, a);
                outputs.PushBack(entry, a);
                total_staked += td.m_amount;
            }
        }

        doc.AddMember("outputs", outputs, a);
        doc.AddMember("total_staked", total_staked, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

static char* dispatch_get_staked_balance(wallet2_handle* w, const rj::Value&) {
    try {
        const uint64_t height = w->wallet->get_blockchain_current_height();

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("staked_balance", w->wallet->get_staked_balance(height), a);
        doc.AddMember("locked_count", (uint64_t)w->wallet->get_locked_staked_outputs().size(), a);
        doc.AddMember("matured_count", (uint64_t)w->wallet->get_matured_staked_outputs().size(), a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

static char* dispatch_claim_rewards(wallet2_handle* w, const rj::Value&) {
    try {
        auto claimable = w->wallet->get_claimable_staked_outputs();
        if (claimable.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "No claimable staked outputs");
            return nullptr;
        }
        auto ptx_vector = w->wallet->create_claim_transaction(claimable);
        if (ptx_vector.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "No claim transaction was created");
            return nullptr;
        }

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        uint64_t total = 0;
        std::string last_hash;
        for (auto& ptx : ptx_vector) {
            w->wallet->commit_tx(ptx);
            last_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
            for (const auto& o : ptx.tx.vout)
                total += o.amount;
        }

        doc.AddMember("tx_hash", json_val_str(last_hash, a), a);
        doc.AddMember("amount", total, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}

// ── Background Sync ──────────────────────────────────────────────────────────

static char* dispatch_setup_background_sync(wallet2_handle* w, const rj::Value& p) {
    try {
        std::string sync_type_str = json_str(p, "background_sync_type", "off");
        const tools::wallet2::BackgroundSyncType sync_type =
            tools::wallet2::background_sync_type_from_str(sync_type_str);

        std::optional<epee::wipeable_string> bg_cache_password = std::nullopt;
        if (sync_type == tools::wallet2::BackgroundSyncCustomPassword)
            bg_cache_password = epee::wipeable_string(json_str(p, "background_cache_password"));

        w->wallet->setup_background_sync(sync_type, json_str(p, "wallet_password"), bg_cache_password);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_start_background_sync(wallet2_handle* w, const rj::Value&) {
    try {
        w->wallet->start_background_sync();
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_stop_background_sync(wallet2_handle* w, const rj::Value& p) {
    try {
        w->wallet->stop_background_sync(json_str(p, "wallet_password"), crypto::null_skey);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, e.what());
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}



// ── Transfer dispatch helpers ────────────────────────────────────────────────

static std::string ptx_to_hex_string(const tools::wallet2::pending_tx& ptx)
{
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    try {
        if (!::serialization::serialize(ar, const_cast<tools::wallet2::pending_tx&>(ptx)))
            return "";
    } catch (...) {
        return "";
    }
    return epee::string_tools::buff_to_hex_nodelimer(oss.str());
}

static bool fill_split_response(
    wallet2_handle* w,
    std::vector<tools::wallet2::pending_tx>& ptx_vector,
    bool get_tx_keys, bool do_not_relay, bool get_tx_hex, bool get_tx_metadata,
    rj::Document& doc)
{
    auto& a = doc.GetAllocator();

    if (w->wallet->watch_only()) {
        std::string us_set = epee::string_tools::buff_to_hex_nodelimer(
            w->wallet->dump_tx_to_str(ptx_vector));
        if (us_set.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                "Failed to save unsigned tx set after creation");
            return false;
        }
        doc.AddMember("unsigned_txset", json_val_str(us_set, a), a);
    } else {
        doc.AddMember("unsigned_txset", "", a);
        if (!do_not_relay)
            w->wallet->commit_tx(ptx_vector);
    }

    rj::Value tx_hash_list(rj::kArrayType);
    rj::Value tx_key_list(rj::kArrayType);
    rj::Value amount_list(rj::kArrayType);
    rj::Value fee_list(rj::kArrayType);
    rj::Value weight_list(rj::kArrayType);
    rj::Value tx_blob_list(rj::kArrayType);
    rj::Value tx_metadata_list(rj::kArrayType);
    rj::Value spent_key_images_list(rj::kArrayType);

    for (auto& ptx : ptx_vector) {
        tx_hash_list.PushBack(json_val_str(
            epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)), a), a);

        if (get_tx_keys) {
            epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
            for (const auto& k : ptx.additional_tx_keys)
                s += epee::to_hex::wipeable_string(k);
            tx_key_list.PushBack(json_val_str(std::string(s.data(), s.size()), a), a);
        }

        uint64_t amount = 0;
        for (const auto& d : ptx.dests) amount += d.amount;
        amount_list.PushBack(amount, a);
        fee_list.PushBack(ptx.fee, a);
        weight_list.PushBack(cryptonote::get_transaction_weight(ptx.tx), a);

        if (get_tx_hex)
            tx_blob_list.PushBack(json_val_str(
                epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(ptx.tx)), a), a);

        if (get_tx_metadata)
            tx_metadata_list.PushBack(json_val_str(ptx_to_hex_string(ptx), a), a);

        rj::Value ki_arr(rj::kArrayType);
        for (const auto& vin : ptx.tx.vin) {
            if (std::holds_alternative<cryptonote::txin_to_key>(vin)) {
                const auto& in = std::get<cryptonote::txin_to_key>(vin);
                ki_arr.PushBack(json_val_str(
                    epee::string_tools::pod_to_hex(in.k_image), a), a);
            }
        }
        spent_key_images_list.PushBack(ki_arr, a);
    }

    doc.AddMember("tx_hash_list", tx_hash_list, a);
    if (get_tx_keys) doc.AddMember("tx_key_list", tx_key_list, a);
    doc.AddMember("amount_list", amount_list, a);
    doc.AddMember("fee_list", fee_list, a);
    doc.AddMember("weight_list", weight_list, a);
    if (get_tx_hex) doc.AddMember("tx_blob_list", tx_blob_list, a);
    if (get_tx_metadata) doc.AddMember("tx_metadata_list", tx_metadata_list, a);
    doc.AddMember("spent_key_images_list", spent_key_images_list, a);
    return true;
}

static bool parse_destinations(wallet2_handle* w, const rj::Value& p,
    std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra)
{
    if (!p.HasMember("destinations") || !p["destinations"].IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "destinations required");
        return false;
    }
    const auto& darr = p["destinations"];
    for (rj::SizeType i = 0; i < darr.Size(); ++i) {
        const auto& d = darr[i];
        if (!d.HasMember("address") || !d.HasMember("amount")) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                "Each destination must have address and amount");
            return false;
        }
        cryptonote::address_parse_info info;
        if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(),
                d["address"].GetString())) {
            w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS,
                std::string("Invalid address: ") + d["address"].GetString());
            return false;
        }
        dsts.emplace_back(d["amount"].GetUint64(), info.address, info.is_subaddress);
    }
    if (dsts.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_ZERO_DESTINATION, "No destinations");
        return false;
    }
    return true;
}

static std::set<uint32_t> parse_subaddr_indices(const rj::Value& p)
{
    std::set<uint32_t> indices;
    if (p.HasMember("subaddr_indices") && p["subaddr_indices"].IsArray()) {
        const auto& arr = p["subaddr_indices"];
        for (rj::SizeType i = 0; i < arr.Size(); ++i) {
            if (arr[i].IsUint())
                indices.insert(arr[i].GetUint());
        }
    }
    return indices;
}

static bool parse_single_address(wallet2_handle* w, const rj::Value& p,
    cryptonote::address_parse_info& info)
{
    std::string addr = json_str(p, "address");
    if (addr.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "address is required");
        return false;
    }
    if (!cryptonote::get_account_address_from_str(info, w->wallet->nettype(), addr)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS,
            std::string("Invalid address: ") + addr);
        return false;
    }
    return true;
}

// ── Transfer dispatch functions ─────────────────────────────────────────────

static char* dispatch_transfer_split(wallet2_handle* w, const rj::Value& p) {
    if (json_u64(p, "unlock_time") != 0) {
        w->set_error(WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME,
            "Transaction cannot have non-zero unlock time");
        return nullptr;
    }
    uint32_t priority = json_u32(p, "priority");
    if (!tools::fee_priority_utilities::is_valid(priority)) {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_FEE_PRIORITY,
            "Invalid priority value. Must be between 0 and 4.");
        return nullptr;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;
    if (!parse_destinations(w, p, dsts, extra))
        return nullptr;

    try {
        uint64_t ring_size = json_u64(p, "ring_size");
        uint64_t mixin = w->wallet->adjust_mixin(ring_size > 0 ? ring_size - 1 : 0);
        const tools::fee_priority fp = w->wallet->adjust_priority(
            tools::fee_priority_utilities::from_integral(priority));
        uint32_t account_index = json_u32(p, "account_index");
        std::set<uint32_t> subaddr_indices = parse_subaddr_indices(p);

        std::vector<tools::wallet2::pending_tx> ptx_vector =
            w->wallet->create_transactions_2(dsts, mixin, fp, extra,
                account_index, subaddr_indices);

        if (ptx_vector.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE, "No transaction created");
            return nullptr;
        }

        bool get_tx_keys = json_bool(p, "get_tx_keys");
        bool do_not_relay = json_bool(p, "do_not_relay");
        bool get_tx_hex = json_bool(p, "get_tx_hex");
        bool get_tx_metadata = json_bool(p, "get_tx_metadata");

        rj::Document doc;
        doc.SetObject();
        if (!fill_split_response(w, ptx_vector, get_tx_keys, do_not_relay,
                get_tx_hex, get_tx_metadata, doc))
            return nullptr;
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
        return nullptr;
    }
}

static char* dispatch_sign_transfer(wallet2_handle* w, const rj::Value& p) {
    if (w->wallet->watch_only()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WATCH_ONLY,
            "command not supported by watch-only wallet");
        return nullptr;
    }
    std::string hex_str = json_str(p, "unsigned_txset");
    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(hex_str, blob)) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_HEX, "Failed to parse hex.");
        return nullptr;
    }

    tools::wallet2::unsigned_tx_set exported_txs;
    if (!w->wallet->parse_unsigned_tx_from_str(blob, exported_txs)) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
            "cannot load unsigned_txset");
        return nullptr;
    }

    std::vector<tools::wallet2::pending_tx> ptxs;
    try {
        tools::wallet2::signed_tx_set signed_txs;
        std::string ciphertext = w->wallet->sign_tx_dump_to_str(exported_txs, ptxs, signed_txs);
        if (ciphertext.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_SIGN_UNSIGNED,
                "Failed to sign unsigned tx");
            return nullptr;
        }

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();

        doc.AddMember("signed_txset", json_val_str(
            epee::string_tools::buff_to_hex_nodelimer(ciphertext), a), a);

        rj::Value tx_hash_list(rj::kArrayType);
        rj::Value tx_key_list(rj::kArrayType);
        rj::Value tx_raw_list(rj::kArrayType);

        bool get_tx_keys = json_bool(p, "get_tx_keys");
        bool export_raw = json_bool(p, "export_raw");

        for (auto& ptx : ptxs) {
            tx_hash_list.PushBack(json_val_str(
                epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)), a), a);
            if (get_tx_keys) {
                epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
                for (const auto& k : ptx.additional_tx_keys)
                    s += epee::to_hex::wipeable_string(k);
                tx_key_list.PushBack(json_val_str(std::string(s.data(), s.size()), a), a);
            }
            if (export_raw) {
                tx_raw_list.PushBack(json_val_str(
                    epee::string_tools::buff_to_hex_nodelimer(
                        cryptonote::tx_to_blob(ptx.tx)), a), a);
            }
        }

        doc.AddMember("tx_hash_list", tx_hash_list, a);
        if (get_tx_keys) doc.AddMember("tx_key_list", tx_key_list, a);
        if (export_raw) doc.AddMember("tx_raw_list", tx_raw_list, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_SIGN_UNSIGNED,
            std::string("Failed to sign unsigned tx: ") + e.what());
        return nullptr;
    }
}

static char* dispatch_describe_transfer(wallet2_handle* w, const rj::Value& p) {
    if (w->wallet->watch_only()) {
        w->set_error(WALLET_RPC_ERROR_CODE_WATCH_ONLY,
            "command not supported by watch-only wallet");
        return nullptr;
    }

    std::string unsigned_hex = json_str(p, "unsigned_txset");

    if (unsigned_hex.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "no txset provided");
        return nullptr;
    }

    std::vector<tools::wallet2::tx_construction_data> tx_constructions;

    try {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_hex, blob)) {
            w->set_error(WALLET_RPC_ERROR_CODE_BAD_HEX, "Failed to parse hex.");
            return nullptr;
        }
        tools::wallet2::unsigned_tx_set exported_txs;
        if (!w->wallet->parse_unsigned_tx_from_str(blob, exported_txs)) {
            w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
                "cannot load unsigned_txset");
            return nullptr;
        }
        tx_constructions = exported_txs.txes;
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
            std::string("failed to parse unsigned transfers: ") + e.what());
        return nullptr;
    }

    try {
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();

        rj::Value desc_arr(rj::kArrayType);
        uint64_t summary_amount_in = 0, summary_amount_out = 0;
        uint64_t summary_change_amount = 0, summary_fee = 0;
        std::string summary_change_address;

        std::unordered_map<cryptonote::account_public_address,
            std::pair<std::string, uint64_t>> all_dests;
        int first_known_non_zero_change_index = -1;

        for (size_t n = 0; n < tx_constructions.size(); ++n) {
            const auto& cd = tx_constructions[n];
            rj::Value desc(rj::kObjectType);

            std::unordered_map<cryptonote::account_public_address,
                std::pair<std::string, uint64_t>> tx_dests;

            uint64_t amount_in = 0, amount_out = 0, change_amount = 0;
            uint32_t ring_size = std::numeric_limits<uint32_t>::max();

            std::vector<cryptonote::tx_extra_field> tx_extra_fields;
            std::string payment_id_str;
            bool has_encrypted_pid = false;
            crypto::hash8 payment_id8 = crypto::null_hash8;
            if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields)) {
                cryptonote::tx_extra_nonce extra_nonce;
                if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce)) {
                    crypto::hash payment_id;
                    if (cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(
                            extra_nonce.nonce, payment_id8)) {
                        if (payment_id8 != crypto::null_hash8) {
                            payment_id_str = epee::string_tools::pod_to_hex(payment_id8);
                            has_encrypted_pid = true;
                        }
                    } else if (cryptonote::get_payment_id_from_tx_extra_nonce(
                            extra_nonce.nonce, payment_id)) {
                        payment_id_str = epee::string_tools::pod_to_hex(payment_id);
                    }
                }
            }

            for (size_t s = 0; s < cd.sources.size(); ++s) {
                amount_in += cd.sources[s].amount;
                size_t rs = cd.sources[s].outputs.size();
                if (rs < ring_size) ring_size = static_cast<uint32_t>(rs);
            }

            for (size_t d = 0; d < cd.splitted_dsts.size(); ++d) {
                const auto& entry = cd.splitted_dsts[d];
                std::string address = cryptonote::get_account_address_as_str(
                    w->wallet->nettype(), entry.is_subaddress, entry.addr);
                if (has_encrypted_pid && !entry.is_subaddress && address != entry.original)
                    address = cryptonote::get_account_integrated_address_as_str(
                        w->wallet->nettype(), entry.addr, payment_id8);
                auto it = tx_dests.find(entry.addr);
                if (it == tx_dests.end())
                    tx_dests.insert(std::make_pair(entry.addr,
                        std::make_pair(address, entry.amount)));
                else
                    it->second.second += entry.amount;
                amount_out += entry.amount;
            }

            uint32_t dummy_outputs = 0;
            if (cd.change_dts.amount > 0) {
                auto it = tx_dests.find(cd.change_dts.addr);
                if (it == tx_dests.end()) {
                    w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
                        "Claimed change does not go to a paid address");
                    return nullptr;
                }
                if (it->second.second < cd.change_dts.amount) {
                    w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
                        "Claimed change is larger than payment to the change address");
                    return nullptr;
                }
                if (first_known_non_zero_change_index == -1)
                    first_known_non_zero_change_index = static_cast<int>(n);
                const auto& cdn = tx_constructions[first_known_non_zero_change_index];
                if (cd.change_dts.addr != cdn.change_dts.addr) {
                    w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
                        "Change goes to more than one address");
                    return nullptr;
                }
                change_amount = cd.change_dts.amount;
                it->second.second -= cd.change_dts.amount;
                if (it->second.second == 0)
                    tx_dests.erase(cd.change_dts.addr);
            }

            rj::Value recipients(rj::kArrayType);
            for (auto& i : tx_dests) {
                if (i.second.second > 0) {
                    rj::Value r(rj::kObjectType);
                    r.AddMember("address", json_val_str(i.second.first, a), a);
                    r.AddMember("amount", i.second.second, a);
                    recipients.PushBack(r, a);
                    auto it_all = all_dests.find(i.first);
                    if (it_all == all_dests.end())
                        all_dests.insert(std::make_pair(i.first, i.second));
                    else
                        it_all->second.second += i.second.second;
                } else {
                    ++dummy_outputs;
                }
            }

            std::string change_address;
            if (change_amount > 0) {
                const auto& cd0 = tx_constructions[0];
                change_address = cryptonote::get_account_address_as_str(
                    w->wallet->nettype(), cd0.subaddr_account > 0, cd0.change_dts.addr);
                if (summary_change_address.empty())
                    summary_change_address = change_address;
            }

            uint64_t fee = amount_in - amount_out;

            desc.AddMember("amount_in", amount_in, a);
            desc.AddMember("amount_out", amount_out, a);
            desc.AddMember("ring_size", ring_size, a);
            desc.AddMember("unlock_time", cd.unlock_time, a);
            desc.AddMember("recipients", recipients, a);
            desc.AddMember("payment_id", json_val_str(payment_id_str, a), a);
            desc.AddMember("change_amount", change_amount, a);
            desc.AddMember("change_address", json_val_str(change_address, a), a);
            desc.AddMember("fee", fee, a);
            desc.AddMember("dummy_outputs", dummy_outputs, a);
            desc.AddMember("extra", json_val_str(
                epee::to_hex::string({cd.extra.data(), cd.extra.size()}), a), a);
            desc_arr.PushBack(desc, a);

            summary_amount_in += amount_in;
            summary_amount_out += amount_out;
            summary_change_amount += change_amount;
            summary_fee += fee;
        }

        rj::Value summary(rj::kObjectType);
        summary.AddMember("amount_in", summary_amount_in, a);
        summary.AddMember("amount_out", summary_amount_out, a);
        summary.AddMember("change_amount", summary_change_amount, a);
        summary.AddMember("change_address", json_val_str(summary_change_address, a), a);
        summary.AddMember("fee", summary_fee, a);

        rj::Value summary_recipients(rj::kArrayType);
        for (auto& i : all_dests) {
            rj::Value r(rj::kObjectType);
            r.AddMember("address", json_val_str(i.second.first, a), a);
            r.AddMember("amount", i.second.second, a);
            summary_recipients.PushBack(r, a);
        }
        summary.AddMember("recipients", summary_recipients, a);

        doc.AddMember("summary", summary, a);
        doc.AddMember("desc", desc_arr, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA,
            "failed to parse unsigned transfers");
        return nullptr;
    }
}

static char* dispatch_submit_transfer(wallet2_handle* w, const rj::Value& p) {
    std::string hex_str = json_str(p, "tx_data_hex");
    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(hex_str, blob)) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_HEX, "Failed to parse hex.");
        return nullptr;
    }

    std::vector<tools::wallet2::pending_tx> ptx_vector;
    try {
        bool r = w->wallet->parse_tx_from_str(blob, ptx_vector, NULL);
        if (!r) {
            w->set_error(WALLET_RPC_ERROR_CODE_BAD_SIGNED_TX_DATA,
                "Failed to parse signed tx data.");
            return nullptr;
        }
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_SIGNED_TX_DATA,
            std::string("Failed to parse signed tx: ") + e.what());
        return nullptr;
    }

    try {
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        rj::Value tx_hash_list(rj::kArrayType);

        for (auto& ptx : ptx_vector) {
            w->wallet->commit_tx(ptx);
            tx_hash_list.PushBack(json_val_str(
                epee::string_tools::pod_to_hex(
                    cryptonote::get_transaction_hash(ptx.tx)), a), a);
        }

        doc.AddMember("tx_hash_list", tx_hash_list, a);
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_SIGNED_SUBMISSION,
            std::string("Failed to submit signed tx: ") + e.what());
        return nullptr;
    }
}

static char* dispatch_sweep_dust(wallet2_handle* w, const rj::Value&) {
    w->set_error(WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR,
        "Sweep dust is not supported: Shekyl has no pre-RCT unmixable outputs.");
    return nullptr;
}

static char* dispatch_sweep_all(wallet2_handle* w, const rj::Value& p) {
    if (json_u64(p, "unlock_time") != 0) {
        w->set_error(WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME,
            "Transaction cannot have non-zero unlock time");
        return nullptr;
    }
    uint32_t priority = json_u32(p, "priority");
    if (!tools::fee_priority_utilities::is_valid(priority)) {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_FEE_PRIORITY,
            "Invalid priority value. Must be between 0 and 4.");
        return nullptr;
    }

    cryptonote::address_parse_info info;
    if (!parse_single_address(w, p, info))
        return nullptr;

    uint64_t outputs = json_u64(p, "outputs", 1);
    if (outputs < 1) {
        w->set_error(WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE,
            "Amount of outputs should be greater than 0.");
        return nullptr;
    }

    uint32_t account_index = json_u32(p, "account_index");
    std::set<uint32_t> subaddr_indices = parse_subaddr_indices(p);
    if (json_bool(p, "subaddr_indices_all")) {
        subaddr_indices.clear();
        for (uint32_t i = 0; i < w->wallet->get_num_subaddresses(account_index); ++i)
            subaddr_indices.insert(i);
    }

    try {
        uint64_t ring_size = json_u64(p, "ring_size");
        uint64_t mixin = w->wallet->adjust_mixin(ring_size > 0 ? ring_size - 1 : 0);
        const tools::fee_priority fp = w->wallet->adjust_priority(
            tools::fee_priority_utilities::from_integral(priority));
        uint64_t below_amount = json_u64(p, "below_amount");
        std::vector<uint8_t> extra;

        std::vector<tools::wallet2::pending_tx> ptx_vector =
            w->wallet->create_transactions_all(below_amount, info.address,
                info.is_subaddress, outputs, mixin, fp, extra,
                account_index, subaddr_indices);

        bool get_tx_keys = json_bool(p, "get_tx_keys");
        bool do_not_relay = json_bool(p, "do_not_relay");
        bool get_tx_hex = json_bool(p, "get_tx_hex");
        bool get_tx_metadata = json_bool(p, "get_tx_metadata");

        rj::Document doc;
        doc.SetObject();
        if (!fill_split_response(w, ptx_vector, get_tx_keys, do_not_relay,
                get_tx_hex, get_tx_metadata, doc))
            return nullptr;
        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
        return nullptr;
    }
}

static char* dispatch_sweep_single(wallet2_handle* w, const rj::Value& p) {
    if (json_u64(p, "unlock_time") != 0) {
        w->set_error(WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME,
            "Transaction cannot have non-zero unlock time");
        return nullptr;
    }
    uint32_t priority = json_u32(p, "priority");
    if (!tools::fee_priority_utilities::is_valid(priority)) {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_FEE_PRIORITY,
            "Invalid priority value. Must be between 0 and 4.");
        return nullptr;
    }

    uint64_t outputs = json_u64(p, "outputs", 1);
    if (outputs < 1) {
        w->set_error(WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE,
            "Amount of outputs should be greater than 0.");
        return nullptr;
    }

    cryptonote::address_parse_info info;
    if (!parse_single_address(w, p, info))
        return nullptr;

    crypto::key_image ki;
    std::string ki_str = json_str(p, "key_image");
    if (!epee::string_tools::hex_to_pod(ki_str, ki)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE, "failed to parse key image");
        return nullptr;
    }

    try {
        uint64_t ring_size = json_u64(p, "ring_size");
        uint64_t mixin = w->wallet->adjust_mixin(ring_size > 0 ? ring_size - 1 : 0);
        const tools::fee_priority fp = w->wallet->adjust_priority(
            tools::fee_priority_utilities::from_integral(priority));
        std::vector<uint8_t> extra;

        std::vector<tools::wallet2::pending_tx> ptx_vector =
            w->wallet->create_transactions_single(ki, info.address,
                info.is_subaddress, outputs, mixin, fp, extra);

        if (ptx_vector.empty()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "No outputs found");
            return nullptr;
        }
        if (ptx_vector.size() > 1) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                "Multiple transactions are created, which is not supposed to happen");
            return nullptr;
        }
        if (ptx_vector[0].selected_transfers.size() > 1) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                "The transaction uses multiple inputs, which is not supposed to happen");
            return nullptr;
        }

        bool get_tx_key = json_bool(p, "get_tx_key");
        bool do_not_relay = json_bool(p, "do_not_relay");
        bool get_tx_hex = json_bool(p, "get_tx_hex");
        bool get_tx_metadata = json_bool(p, "get_tx_metadata");

        auto& ptx = ptx_vector[0];

        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();

        if (w->wallet->watch_only()) {
            std::string us_set = epee::string_tools::buff_to_hex_nodelimer(
                w->wallet->dump_tx_to_str(ptx_vector));
            if (us_set.empty()) {
                w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR,
                    "Failed to save unsigned tx set after creation");
                return nullptr;
            }
            doc.AddMember("unsigned_txset", json_val_str(us_set, a), a);
        } else {
            doc.AddMember("unsigned_txset", "", a);
            if (!do_not_relay)
                w->wallet->commit_tx(ptx_vector);
        }

        doc.AddMember("tx_hash", json_val_str(
            epee::string_tools::pod_to_hex(
                cryptonote::get_transaction_hash(ptx.tx)), a), a);

        if (get_tx_key) {
            epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
            for (const auto& k : ptx.additional_tx_keys)
                s += epee::to_hex::wipeable_string(k);
            doc.AddMember("tx_key", json_val_str(
                std::string(s.data(), s.size()), a), a);
        }

        uint64_t amount = 0;
        for (const auto& d : ptx.dests) amount += d.amount;
        doc.AddMember("amount", amount, a);
        doc.AddMember("fee", ptx.fee, a);
        doc.AddMember("weight", cryptonote::get_transaction_weight(ptx.tx), a);

        if (get_tx_hex)
            doc.AddMember("tx_blob", json_val_str(
                epee::string_tools::buff_to_hex_nodelimer(
                    cryptonote::tx_to_blob(ptx.tx)), a), a);

        if (get_tx_metadata)
            doc.AddMember("tx_metadata", json_val_str(ptx_to_hex_string(ptx), a), a);

        rj::Value ki_arr(rj::kArrayType);
        for (const auto& vin : ptx.tx.vin) {
            if (std::holds_alternative<cryptonote::txin_to_key>(vin)) {
                const auto& in = std::get<cryptonote::txin_to_key>(vin);
                ki_arr.PushBack(json_val_str(
                    epee::string_tools::pod_to_hex(in.k_image), a), a);
            }
        }
        doc.AddMember("spent_key_images", ki_arr, a);

        return json_to_string(doc);
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
        return nullptr;
    }
}

static char* dispatch_relay_tx(wallet2_handle* w, const rj::Value& p) {
    std::string hex_str = json_str(p, "hex");
    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(hex_str, blob)) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_HEX, "Failed to parse hex.");
        return nullptr;
    }

    bool loaded = false;
    tools::wallet2::pending_tx ptx;

    try {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
        if (::serialization::serialize(ar, ptx))
            loaded = true;
    } catch (...) {}

    if (!loaded) {
        try {
            std::istringstream iss(blob);
            boost::archive::portable_binary_iarchive ar(iss);
            ar >> ptx;
            loaded = true;
        } catch (...) {}
    }

    if (!loaded) {
        w->set_error(WALLET_RPC_ERROR_CODE_BAD_TX_METADATA, "Failed to parse tx metadata.");
        return nullptr;
    }

    try {
        w->wallet->commit_tx(ptx);
    } catch (const std::exception& e) {
        w->set_error(WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR, "Failed to commit tx.");
        return nullptr;
    }

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("tx_hash", json_val_str(
        epee::string_tools::pod_to_hex(
            cryptonote::get_transaction_hash(ptx.tx)), a), a);
    return json_to_string(doc);
}

static char* dispatch_get_default_fee_priority(wallet2_handle* w, const rj::Value&) {
    const tools::fee_priority priority = w->wallet->adjust_priority(tools::fee_priority::Default);
    if (priority == tools::fee_priority::Default) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to get adjusted fee priority");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("priority", tools::fee_priority_utilities::as_integral(priority), a);
    return json_to_string(doc);
}

static char* dispatch_auto_refresh(wallet2_handle*, const rj::Value&) {
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_incoming_transfers(wallet2_handle* w, const rj::Value& p) {
    std::string type = json_str(p, "transfer_type", "all");
    uint32_t account_index = json_u32(p, "account_index");

    tools::wallet2::transfer_container transfers;
    w->wallet->get_transfers(transfers);

    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value arr(rj::kArrayType);

    for (const auto& td : transfers) {
        if (td.m_subaddr_index.major != account_index) continue;
        bool available = !td.m_spent;
        if (type == "available" && !available) continue;
        if (type == "unavailable" && available) continue;

        rj::Value obj(rj::kObjectType);
        obj.AddMember("amount", td.amount(), a);
        obj.AddMember("spent", td.m_spent, a);
        obj.AddMember("global_index", td.m_global_output_index, a);
        obj.AddMember("tx_hash", json_val_str(epee::string_tools::pod_to_hex(td.m_txid), a), a);
        obj.AddMember("subaddr_index", rj::Value(rj::kObjectType)
            .AddMember("major", td.m_subaddr_index.major, a)
            .AddMember("minor", td.m_subaddr_index.minor, a), a);
        obj.AddMember("key_image", json_val_str(
            td.m_key_image_known ? epee::string_tools::pod_to_hex(td.m_key_image) : "", a), a);
        obj.AddMember("block_height", td.m_block_height, a);
        obj.AddMember("frozen", td.m_frozen, a);
        obj.AddMember("unlocked", w->wallet->is_transfer_unlocked(td), a);
        arr.PushBack(obj, a);
    }

    doc.AddMember("transfers", arr, a);
    return json_to_string(doc);
}

static char* dispatch_get_address_index(wallet2_handle* w, const rj::Value& p) {
    std::string address = json_str(p, "address");
    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, w->wallet->nettype(), address)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }
    auto idx = w->wallet->get_subaddress_index(info.address);
    if (!idx) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Address not found in wallet");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    rj::Value index_obj(rj::kObjectType);
    index_obj.AddMember("major", idx->major, a);
    index_obj.AddMember("minor", idx->minor, a);
    doc.AddMember("index", index_obj, a);
    return json_to_string(doc);
}

static char* dispatch_set_subaddress_lookahead(wallet2_handle* w, const rj::Value& p) {
    w->wallet->set_subaddress_lookahead(json_u32(p, "major_idx"), json_u32(p, "minor_idx"));
    rj::Document doc;
    doc.SetObject();
    return json_to_string(doc);
}

static char* dispatch_sign(wallet2_handle* w, const rj::Value& p) {
    std::string data = json_str(p, "data");
    std::string sig_type_str = json_str(p, "signature_type");
    uint32_t acct = json_u32(p, "account_index");
    uint32_t addr = json_u32(p, "address_index");

    tools::wallet2::message_signature_type_t sig_type = tools::wallet2::sign_with_spend_key;
    if (sig_type_str == "view")
        sig_type = tools::wallet2::sign_with_view_key;
    else if (!sig_type_str.empty() && sig_type_str != "spend") {
        w->set_error(WALLET_RPC_ERROR_CODE_INVALID_SIGNATURE_TYPE, "Invalid signature type requested");
        return nullptr;
    }
    std::string sig = w->wallet->sign(data, sig_type, cryptonote::subaddress_index{acct, addr});
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("signature", json_val_str(sig, a), a);
    return json_to_string(doc);
}

static char* dispatch_verify(wallet2_handle* w, const rj::Value& p) {
    std::string data = json_str(p, "data");
    std::string address = json_str(p, "address");
    std::string signature = json_str(p, "signature");

    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, w->wallet->nettype(), address)) {
        w->set_error(WALLET_RPC_ERROR_CODE_WRONG_ADDRESS, "Invalid address");
        return nullptr;
    }

    auto result = w->wallet->verify(data, info.address, signature);
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("good", result.valid, a);
    return json_to_string(doc);
}

static char* dispatch_estimate_tx_size_and_weight(wallet2_handle* w, const rj::Value& p) {
    uint32_t n_inputs = json_u32(p, "n_inputs");
    uint32_t n_outputs = json_u32(p, "n_outputs");
    uint32_t ring_size = json_u32(p, "ring_size");
    bool rct = json_bool(p, "rct", true);
    auto sw = w->wallet->estimate_tx_size_and_weight(rct, n_inputs, ring_size, n_outputs, 0);
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("size", (uint64_t)sw.first, a);
    doc.AddMember("weight", (uint64_t)sw.second, a);
    return json_to_string(doc);
}

static char* dispatch_create_pqc_multisig_group(wallet2_handle* w, const rj::Value& p) {
    uint32_t n_total = json_u32(p, "n_total");
    uint32_t m_required = json_u32(p, "m_required");
    if (n_total == 0 || m_required == 0 || m_required > n_total) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Invalid n_total/m_required");
        return nullptr;
    }
    if (!p.HasMember("participant_keys") || !p["participant_keys"].IsArray()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "participant_keys array required");
        return nullptr;
    }
    std::vector<std::vector<uint8_t>> keys_vec;
    for (auto& v : p["participant_keys"].GetArray()) {
        if (!v.IsString()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "participant_keys must be hex strings");
            return nullptr;
        }
        std::string bin;
        if (!epee::string_tools::parse_hexstr_to_binbuff(v.GetString(), bin)) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Invalid hex in participant_keys");
            return nullptr;
        }
        keys_vec.emplace_back(bin.begin(), bin.end());
    }
    if (!w->wallet->create_pqc_multisig_group(static_cast<uint8_t>(n_total), static_cast<uint8_t>(m_required), keys_vec)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to create PQC multisig group");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("group_id", json_val_str(epee::string_tools::pod_to_hex(w->wallet->pqc_multisig_group_id()), a), a);
    doc.AddMember("n_total", (uint32_t)w->wallet->pqc_multisig_n(), a);
    doc.AddMember("m_required", (uint32_t)w->wallet->pqc_multisig_m(), a);
    return json_to_string(doc);
}

static char* dispatch_get_pqc_multisig_info(wallet2_handle* w, const rj::Value&) {
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    bool is_ms = w->wallet->is_pqc_multisig();
    doc.AddMember("is_multisig", is_ms, a);
    doc.AddMember("n_total", (uint32_t)w->wallet->pqc_multisig_n(), a);
    doc.AddMember("m_required", (uint32_t)w->wallet->pqc_multisig_m(), a);
    doc.AddMember("group_id", json_val_str(epee::string_tools::pod_to_hex(w->wallet->pqc_multisig_group_id()), a), a);
    return json_to_string(doc);
}

static char* dispatch_sign_multisig_partial(wallet2_handle* w, const rj::Value& p) {
    std::string signing_request = json_str(p, "signing_request");
    if (signing_request.empty()) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "signing_request is required");
        return nullptr;
    }
    std::string response;
    if (!w->wallet->sign_multisig_partial(signing_request, response)) {
        w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Failed to produce partial signature");
        return nullptr;
    }
    rj::Document doc;
    doc.SetObject();
    auto& a = doc.GetAllocator();
    doc.AddMember("signature_response", json_val_str(response, a), a);
    return json_to_string(doc);
}

static char* dispatch_import_multisig_signatures(wallet2_handle* w, const rj::Value&) {
    w->set_error(-32601, "Not yet available via RPC -- use GUI workflow");
    return nullptr;
}

char* wallet2_ffi_json_rpc(wallet2_handle* w, const char* method, const char* params_json)
{
    if (!w) return nullptr;
    w->clear_error();

    rj::Document params;
    if (params_json && params_json[0] != '\0') {
        if (params.Parse(params_json).HasParseError()) {
            w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "Invalid JSON params");
            return nullptr;
        }
    } else {
        params.SetObject();
    }

    if (!method || method[0] == '\0') {
        w->set_error(-32600, "Method name required");
        return nullptr;
    }

    // Methods that don't require a wallet
    std::string m(method);
    if (m == "get_version") {
        rj::Document doc;
        doc.SetObject();
        auto& a = doc.GetAllocator();
        doc.AddMember("version", (uint32_t)WALLET_RPC_VERSION, a);
        return json_to_string(doc);
    }
    if (m == "get_languages") return dispatch_get_languages(w, params);

    // Methods that require a wallet
    if (!w->wallet) {
        w->set_error(WALLET_RPC_ERROR_CODE_NOT_OPEN, "No wallet file");
        return nullptr;
    }

    try {
        // Wallet file operations (use existing individual functions internally)
        if (m == "create_wallet") {
            int rc = wallet2_ffi_create_wallet(w,
                json_str(params, "filename").c_str(),
                json_str(params, "password").c_str(),
                json_str(params, "language", "English").c_str());
            if (rc != 0) return nullptr;
            rj::Document doc; doc.SetObject(); return json_to_string(doc);
        }
        if (m == "open_wallet") {
            int rc = wallet2_ffi_open_wallet(w,
                json_str(params, "filename").c_str(),
                json_str(params, "password").c_str());
            if (rc != 0) return nullptr;
            rj::Document doc; doc.SetObject(); return json_to_string(doc);
        }
        if (m == "close_wallet") {
            int rc = wallet2_ffi_close_wallet(w, json_bool(params, "autosave_current", true));
            if (rc != 0) return nullptr;
            rj::Document doc; doc.SetObject(); return json_to_string(doc);
        }
        if (m == "restore_deterministic_wallet") {
            return wallet2_ffi_restore_deterministic_wallet(w,
                json_str(params, "filename").c_str(),
                json_str(params, "seed").c_str(),
                json_str(params, "password").c_str(),
                json_str(params, "language", "English").c_str(),
                json_u64(params, "restore_height"),
                json_str(params, "seed_offset").c_str());
        }
        if (m == "generate_from_keys") {
            return wallet2_ffi_generate_from_keys(w,
                json_str(params, "filename").c_str(),
                json_str(params, "address").c_str(),
                json_str(params, "spendkey").c_str(),
                json_str(params, "viewkey").c_str(),
                json_str(params, "password").c_str(),
                json_str(params, "language").c_str(),
                json_u64(params, "restore_height"));
        }

        // Queries
        if (m == "get_balance" || m == "getbalance")
            return wallet2_ffi_get_balance(w, json_u32(params, "account_index"));
        if (m == "get_address" || m == "getaddress")
            return wallet2_ffi_get_address(w, json_u32(params, "account_index"));
        if (m == "query_key")
            return wallet2_ffi_query_key(w, json_str(params, "key_type").c_str());
        if (m == "get_height" || m == "getheight")
            return dispatch_get_height(w, params);

        // Transfer
        if (m == "transfer") {
            rj::StringBuffer buf;
            rj::Writer<rj::StringBuffer> writer(buf);
            if (params.HasMember("destinations") && params["destinations"].IsArray()) {
                params["destinations"].Accept(writer);
            } else {
                w->set_error(WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR, "destinations required");
                return nullptr;
            }
            return wallet2_ffi_transfer(w, buf.GetString(),
                json_u32(params, "priority"),
                json_u32(params, "account_index"),
                json_u32(params, "ring_size"));
        }
        if (m == "transfer_split") return dispatch_transfer_split(w, params);
        if (m == "sign_transfer") return dispatch_sign_transfer(w, params);
        if (m == "describe_transfer") return dispatch_describe_transfer(w, params);
        if (m == "submit_transfer") return dispatch_submit_transfer(w, params);
        if (m == "sweep_dust" || m == "sweep_unmixable") return dispatch_sweep_dust(w, params);
        if (m == "sweep_all") return dispatch_sweep_all(w, params);
        if (m == "sweep_single") return dispatch_sweep_single(w, params);
        if (m == "relay_tx") return dispatch_relay_tx(w, params);
        if (m == "get_transfers")
            return wallet2_ffi_get_transfers(w,
                json_bool(params, "in"), json_bool(params, "out"),
                json_bool(params, "pending"), json_bool(params, "failed"),
                json_bool(params, "pool"), json_u32(params, "account_index"));
        if (m == "get_transfer_by_txid") return dispatch_get_transfer_by_txid(w, params);
        if (m == "stop_wallet") {
            int rc = wallet2_ffi_stop(w);
            if (rc != 0) return nullptr;
            rj::Document doc; doc.SetObject(); return json_to_string(doc);
        }

        // Accounts/subaddresses
        if (m == "get_accounts") return dispatch_get_accounts(w, params);
        if (m == "create_account") return dispatch_create_account(w, params);
        if (m == "label_account") return dispatch_label_account(w, params);
        if (m == "create_address") return dispatch_create_address(w, params);
        if (m == "label_address") return dispatch_label_address(w, params);
        if (m == "get_address_index") return dispatch_get_address_index(w, params);
        if (m == "set_subaddress_lookahead") return dispatch_set_subaddress_lookahead(w, params);
        if (m == "get_account_tags") return dispatch_get_account_tags(w, params);
        if (m == "tag_accounts") return dispatch_tag_accounts(w, params);
        if (m == "untag_accounts") return dispatch_untag_accounts(w, params);
        if (m == "set_account_tag_description") return dispatch_set_account_tag_description(w, params);

        // Wallet management
        if (m == "store") return dispatch_store(w, params);
        if (m == "change_wallet_password") return dispatch_change_wallet_password(w, params);
        if (m == "refresh") return dispatch_refresh(w, params);
        if (m == "auto_refresh") return dispatch_auto_refresh(w, params);
        if (m == "rescan_blockchain") return dispatch_rescan_blockchain(w, params);
        if (m == "rescan_spent") return dispatch_rescan_spent(w, params);
        if (m == "set_tx_notes") return dispatch_set_tx_notes(w, params);
        if (m == "get_tx_notes") return dispatch_get_tx_notes(w, params);
        if (m == "set_attribute") return dispatch_set_attribute(w, params);
        if (m == "get_attribute") return dispatch_get_attribute(w, params);
        if (m == "validate_address") return dispatch_validate_address(w, params);
        if (m == "estimate_tx_size_and_weight") return dispatch_estimate_tx_size_and_weight(w, params);
        if (m == "get_default_fee_priority") return dispatch_get_default_fee_priority(w, params);

        // Keys/proofs
        if (m == "get_tx_key") return dispatch_get_tx_key(w, params);
        if (m == "sign") return dispatch_sign(w, params);
        if (m == "verify") return dispatch_verify(w, params);

        // Proofs
        if (m == "check_tx_key") return dispatch_check_tx_key(w, params);
        if (m == "get_tx_proof") return dispatch_get_tx_proof(w, params);
        if (m == "check_tx_proof") return dispatch_check_tx_proof(w, params);
        if (m == "get_spend_proof") return dispatch_get_spend_proof(w, params);
        if (m == "check_spend_proof") return dispatch_check_spend_proof(w, params);
        if (m == "get_reserve_proof") return dispatch_get_reserve_proof(w, params);
        if (m == "check_reserve_proof") return dispatch_check_reserve_proof(w, params);

        // Freeze/thaw
        if (m == "freeze") return dispatch_freeze(w, params);
        if (m == "thaw") return dispatch_thaw(w, params);
        if (m == "frozen") return dispatch_frozen(w, params);

        // Transfer history
        if (m == "incoming_transfers") return dispatch_incoming_transfers(w, params);

        // Export/import
        if (m == "export_outputs") return dispatch_export_outputs(w, params);
        if (m == "import_outputs") return dispatch_import_outputs(w, params);
        if (m == "export_key_images") return dispatch_export_key_images(w, params);
        if (m == "import_key_images") return dispatch_import_key_images(w, params);

        // Payments
        if (m == "get_payments") return dispatch_get_payments(w, params);
        if (m == "get_bulk_payments") return dispatch_get_bulk_payments(w, params);

        // Address utils
        if (m == "make_integrated_address") return dispatch_make_integrated_address(w, params);
        if (m == "split_integrated_address") return dispatch_split_integrated_address(w, params);

        // URI
        if (m == "make_uri") return dispatch_make_uri(w, params);
        if (m == "parse_uri") return dispatch_parse_uri(w, params);

        // Address book
        if (m == "get_address_book") return dispatch_get_address_book(w, params);
        if (m == "add_address_book") return dispatch_add_address_book(w, params);
        if (m == "edit_address_book") return dispatch_edit_address_book(w, params);
        if (m == "delete_address_book") return dispatch_delete_address_book(w, params);

        // Mining/Daemon
        if (m == "start_mining") return dispatch_start_mining(w, params);
        if (m == "stop_mining") return dispatch_stop_mining(w, params);
        if (m == "set_daemon") return dispatch_set_daemon(w, params);
        if (m == "set_log_level") return dispatch_set_log_level(w, params);
        if (m == "set_log_categories") return dispatch_set_log_categories(w, params);
        if (m == "scan_tx") return dispatch_scan_tx(w, params);

        // Staking
        if (m == "stake") return dispatch_stake(w, params);
        if (m == "unstake") return dispatch_unstake(w, params);
        if (m == "get_staked_outputs") return dispatch_get_staked_outputs(w, params);
        if (m == "get_staked_balance") return dispatch_get_staked_balance(w, params);
        if (m == "claim_rewards") return dispatch_claim_rewards(w, params);

        // Background sync
        if (m == "setup_background_sync") return dispatch_setup_background_sync(w, params);
        if (m == "start_background_sync") return dispatch_start_background_sync(w, params);
        if (m == "stop_background_sync") return dispatch_stop_background_sync(w, params);

        // PQC Multisig
        if (m == "create_pqc_multisig_group") return dispatch_create_pqc_multisig_group(w, params);
        if (m == "get_pqc_multisig_info") return dispatch_get_pqc_multisig_info(w, params);
        if (m == "sign_multisig_partial") return dispatch_sign_multisig_partial(w, params);
        if (m == "import_multisig_signatures") return dispatch_import_multisig_signatures(w, params);

        // Not yet implemented methods return a structured error
        w->set_error(-32601, "Method not implemented: " + m);
        return nullptr;
    } catch (const std::exception& e) {
        w->set_error_from_exception(e, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return nullptr;
    }
}
