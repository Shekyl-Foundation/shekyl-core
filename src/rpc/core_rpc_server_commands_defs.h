// Copyright (c) 2014-2022, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "string_tools.h"

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/difficulty.h"
#include "crypto/hash.h"
#include "rpc/rpc_handler.h"
#include "common/varint.h"
#include "common/perf_timer.h"

namespace
{
  template<typename T>
  std::string compress_integer_array(const std::vector<T> &v)
  {
    std::string s;
    s.resize(v.size() * (sizeof(T) * 8 / 7 + 1));
    char *ptr = (char*)s.data();
    for (const T &t: v)
      tools::write_varint(ptr, t);
    s.resize(ptr - s.data());
    return s;
  }

  template<typename T>
  std::vector<T> decompress_integer_array(const std::string &s)
  {
    std::vector<T> v;
    v.reserve(s.size());
    int read = 0;
    const std::string::const_iterator end = s.end();
    for (std::string::const_iterator i = s.begin(); i != end; std::advance(i, read))
    {
      T t;
      read = tools::read_varint(std::string::const_iterator(i), s.end(), t);
      CHECK_AND_ASSERT_THROW_MES(read > 0 && read <= 256, "Error decompressing data");
      v.push_back(t);
    }
    return v;
  }
}

namespace cryptonote
{
  //-----------------------------------------------
#define CORE_RPC_STATUS_OK   "OK"
#define CORE_RPC_STATUS_BUSY   "BUSY"
#define CORE_RPC_STATUS_NOT_MINING "NOT MINING"

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures CORE_RPC_VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given daemon without having to know in
// advance which version they will stop working with
// Don't go over 32767 for any of these
// CORE_RPC_VERSION lives in rust/shekyl-rpc-types/src/chain.rs since RK-1:
// get_version, the only thing that *emits* it, is served natively. (No number
// here on purpose: a prose copy of a moving constant only goes stale. This one
// had — it said 3.25 through two bumps. Both branches in flight deleted it
// independently, which is the tell.)

  struct rpc_request_base
  {
    BEGIN_KV_SERIALIZE_MAP()
    END_KV_SERIALIZE_MAP()
  };

  struct rpc_response_base
  {
    std::string status;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(status)
    END_KV_SERIALIZE_MAP()
  };



    struct COMMAND_RPC_GET_ALT_BLOCKS_HASHES
    {
        struct request_t: public rpc_request_base
        {
            BEGIN_KV_SERIALIZE_MAP()
                KV_SERIALIZE_PARENT(rpc_request_base)
            END_KV_SERIALIZE_MAP()
        };
        typedef epee::misc_utils::struct_init<request_t> request;

        struct response_t: public rpc_response_base
        {
            std::vector<std::string> blks_hashes;

            BEGIN_KV_SERIALIZE_MAP()
                KV_SERIALIZE_PARENT(rpc_response_base)
                KV_SERIALIZE(blks_hashes)
            END_KV_SERIALIZE_MAP()
        };
        typedef epee::misc_utils::struct_init<response_t> response;
    };

  //-----------------------------------------------

  //-----------------------------------------------

  //-----------------------------------------------
  //-----------------------------------------------
  // Epee marshaling mirror of the typed submit contract
  // (docs/design/DAEMON_SUBMIT_VERDICT.md §2.4; authoritative Rust
  // definition in rust/shekyl-rpc-types). Transport-only per rule 20:
  // consumed by the legacy C++ wallet's commit_tx and the trezor test
  // mock daemon; the production route is served by the Rust admission
  // engine (rust/shekyl-daemon-rpc). Deliberately no rpc_request_base /
  // rpc_response_base parent — the wire carries exactly the §2 fields.
  struct COMMAND_RPC_SUBMIT_TRANSACTION
  {
    struct request_t
    {
      std::string tx_blob; // hex-encoded raw tx bytes

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_blob)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      // Serde tag: "accepted" | "already_in_pool" | "already_in_chain"
      // | "rejected". The contract is closed: the legacy wallet treats a
      // tag it cannot name as a protocol error, not a rejection (see
      // wallet2::commit_tx). The Rust client's typed Err arm is the real
      // skew rule.
      std::string verdict;
      // Present iff verdict == "rejected" (§2.1 RejectCause, snake_case).
      std::string cause;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(verdict)
        KV_SERIALIZE_OPT(cause, std::string())
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  //-----------------------------------------------
  struct COMMAND_RPC_START_MINING
  {
    struct request_t: public rpc_request_base
    {
      std::string miner_address;
      uint64_t    threads_count;
      bool        do_background_mining;
      bool        ignore_battery;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(miner_address)
        KV_SERIALIZE(threads_count)
        KV_SERIALIZE(do_background_mining)        
        KV_SERIALIZE(ignore_battery)        
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  //-----------------------------------------------
  struct COMMAND_RPC_GET_INFO
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      uint64_t height;
      uint64_t target_height;
      uint64_t difficulty;
      std::string wide_difficulty;
      uint64_t difficulty_top64;
      uint64_t target;
      uint64_t tx_count;
      uint64_t tx_pool_size;
      uint64_t alt_blocks_count;
      uint64_t outgoing_connections_count;
      uint64_t incoming_connections_count;
      uint64_t rpc_connections_count;
      uint64_t white_peerlist_size;
      uint64_t grey_peerlist_size;
      bool mainnet;
      bool testnet;
      bool stagenet;
      std::string nettype;
      std::string top_block_hash;
      uint64_t cumulative_difficulty;
      std::string wide_cumulative_difficulty;
      uint64_t cumulative_difficulty_top64;
      uint64_t block_size_limit;
      uint64_t block_weight_limit;
      uint64_t block_size_median;
      uint64_t block_weight_median;
      uint64_t adjusted_time;
      uint64_t start_time;
      uint64_t free_space;
      bool offline;
      uint64_t database_size;
      bool busy_syncing;
      std::string version;
      uint32_t protocol_version;
      bool synchronized;
      bool following_degraded;
      bool restricted;

      // Shekyl NG four-component economics fields
      uint64_t release_multiplier;
      uint64_t burn_pct;
      uint64_t total_burned;
      uint64_t staker_emission_share_effective;
      std::string emission_era;
      uint64_t tx_prune_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(height)
        KV_SERIALIZE(target_height)
        KV_SERIALIZE(difficulty)
        KV_SERIALIZE(wide_difficulty)
        KV_SERIALIZE(difficulty_top64)
        KV_SERIALIZE(target)
        KV_SERIALIZE(tx_count)
        KV_SERIALIZE(tx_pool_size)
        KV_SERIALIZE(alt_blocks_count)
        KV_SERIALIZE(outgoing_connections_count)
        KV_SERIALIZE(incoming_connections_count)
        KV_SERIALIZE(rpc_connections_count)
        KV_SERIALIZE(white_peerlist_size)
        KV_SERIALIZE(grey_peerlist_size)
        KV_SERIALIZE(mainnet)
        KV_SERIALIZE(testnet)
        KV_SERIALIZE(stagenet)
        KV_SERIALIZE(nettype)
        KV_SERIALIZE(top_block_hash)
        KV_SERIALIZE(cumulative_difficulty)
        KV_SERIALIZE(wide_cumulative_difficulty)
        KV_SERIALIZE(cumulative_difficulty_top64)
        KV_SERIALIZE(block_size_limit)
        KV_SERIALIZE_OPT(block_weight_limit, (uint64_t)0)
        KV_SERIALIZE(block_size_median)
        KV_SERIALIZE_OPT(block_weight_median, (uint64_t)0)
        KV_SERIALIZE(adjusted_time)
        KV_SERIALIZE(start_time)
        KV_SERIALIZE(free_space)
        KV_SERIALIZE(offline)
        KV_SERIALIZE(database_size)
        KV_SERIALIZE(busy_syncing)
        KV_SERIALIZE(version)
        KV_SERIALIZE(protocol_version)
        KV_SERIALIZE(synchronized)
        KV_SERIALIZE(following_degraded)
        KV_SERIALIZE(restricted)
        KV_SERIALIZE(release_multiplier)
        KV_SERIALIZE(burn_pct)
        KV_SERIALIZE(total_burned)
        KV_SERIALIZE(staker_emission_share_effective)
        KV_SERIALIZE(emission_era)
        KV_SERIALIZE_OPT(tx_prune_height, (uint64_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

    
  //-----------------------------------------------

  //-----------------------------------------------
  struct COMMAND_RPC_STOP_MINING
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;


    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  //-----------------------------------------------
  struct COMMAND_RPC_MINING_STATUS
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;


    struct response_t: public rpc_response_base
    {
      bool active;
      uint64_t speed;
      uint32_t threads_count;
      std::string address;
      std::string pow_algorithm;
      bool is_background_mining_enabled;
      uint8_t bg_idle_threshold;
      uint8_t bg_min_idle_seconds;
      bool bg_ignore_battery;
      uint8_t bg_target;
      uint32_t block_target;
      uint64_t block_reward;
      uint64_t difficulty;
      std::string wide_difficulty;
      uint64_t difficulty_top64;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(active)
        KV_SERIALIZE(speed)
        KV_SERIALIZE(threads_count)
        KV_SERIALIZE(address)
        KV_SERIALIZE(pow_algorithm)
        KV_SERIALIZE(is_background_mining_enabled)
        KV_SERIALIZE(bg_idle_threshold)
        KV_SERIALIZE(bg_min_idle_seconds)
        KV_SERIALIZE(bg_ignore_battery)
        KV_SERIALIZE(bg_target)
        KV_SERIALIZE(block_target)
        KV_SERIALIZE(block_reward)
        KV_SERIALIZE(difficulty)
        KV_SERIALIZE(wide_difficulty)
        KV_SERIALIZE(difficulty_top64)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  //-----------------------------------------------
  struct COMMAND_RPC_SAVE_BC
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;


    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  
  //



  struct COMMAND_RPC_GETBLOCKTEMPLATE
  {
    struct request_t: public rpc_request_base
    {
      uint64_t reserve_size;       //max 255 bytes
      std::string wallet_address;
      std::string prev_block;
      std::string extra_nonce;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(reserve_size)
        KV_SERIALIZE(wallet_address)
        KV_SERIALIZE(prev_block)
        KV_SERIALIZE(extra_nonce)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      uint64_t difficulty;
      std::string wide_difficulty;
      uint64_t difficulty_top64;
      uint64_t height;
      uint64_t reserved_offset;
      uint64_t expected_reward;
      std::string prev_hash;
      uint64_t seed_height;
      std::string seed_hash;
      std::string next_seed_hash;
      blobdata blocktemplate_blob;
      blobdata blockhashing_blob;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(difficulty)
        KV_SERIALIZE(wide_difficulty)
        KV_SERIALIZE(difficulty_top64)
        KV_SERIALIZE(height)
        KV_SERIALIZE(reserved_offset)
        KV_SERIALIZE(expected_reward)
        KV_SERIALIZE(prev_hash)
        KV_SERIALIZE(seed_height)
        KV_SERIALIZE(blocktemplate_blob)
        KV_SERIALIZE(blockhashing_blob)
        KV_SERIALIZE(seed_hash)
        KV_SERIALIZE(next_seed_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GETMINERDATA
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      uint8_t major_version;
      uint64_t height;
      std::string prev_id;
      std::string seed_hash;
      std::string difficulty;
      uint64_t median_weight;
      uint64_t already_generated_coins;

      struct tx_backlog_entry
      {
        std::string id;
        uint64_t weight;
        uint64_t fee;

        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(id)
          KV_SERIALIZE(weight)
          KV_SERIALIZE(fee)
        END_KV_SERIALIZE_MAP()
      };

      std::vector<tx_backlog_entry> tx_backlog;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(major_version)
        KV_SERIALIZE(height)
        KV_SERIALIZE(prev_id)
        KV_SERIALIZE(seed_hash)
        KV_SERIALIZE(difficulty)
        KV_SERIALIZE(median_weight)
        KV_SERIALIZE(already_generated_coins)
        KV_SERIALIZE(tx_backlog)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CALCPOW
  {
    struct request_t: public rpc_request_base
    {
      uint8_t major_version;
      uint64_t height;
      blobdata block_blob;
      std::string seed_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(major_version)
        KV_SERIALIZE(height)
        KV_SERIALIZE(block_blob)
        KV_SERIALIZE(seed_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    typedef std::string response;
  };

  struct COMMAND_RPC_ADD_AUX_POW
  {
    struct aux_pow_t
    {
      std::string id;
      std::string hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(id)
        KV_SERIALIZE(hash)
      END_KV_SERIALIZE_MAP()
    };

    struct request_t: public rpc_request_base
    {
      blobdata blocktemplate_blob;
      std::vector<aux_pow_t> aux_pow;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(blocktemplate_blob)
        KV_SERIALIZE(aux_pow)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      blobdata blocktemplate_blob;
      blobdata blockhashing_blob;
      std::string merkle_root;
      uint32_t merkle_tree_depth;
      std::vector<aux_pow_t> aux_pow;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(blocktemplate_blob)
        KV_SERIALIZE(blockhashing_blob)
        KV_SERIALIZE(merkle_root)
        KV_SERIALIZE(merkle_tree_depth)
        KV_SERIALIZE(aux_pow)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SUBMITBLOCK
  {
    typedef std::vector<std::string> request;
    
    struct response_t: public rpc_response_base
    {
      std::string block_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(block_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GENERATEBLOCKS
  {
    struct request_t: public rpc_request_base
    {
      uint64_t amount_of_blocks;
      std::string wallet_address;
      std::string prev_block;
      uint32_t starting_nonce;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(amount_of_blocks)
        KV_SERIALIZE(wallet_address)
        KV_SERIALIZE(prev_block)
        KV_SERIALIZE_OPT(starting_nonce, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    
    struct response_t: public rpc_response_base
    {
      uint64_t height;
      std::vector<std::string> blocks;
      
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(height)
        KV_SERIALIZE(blocks)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // FAKECHAIN-only: inject an archival serve-credit bit through the
  // production setter (Gate-6 accrual-path regtest stand-in; contract and
  // pop-range caveat at Blockchain::regtest_inject_archival_serve_credit).
  struct COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT
  {
    struct request_t: public rpc_request_base
    {
      std::string p_canonical_id;  // hex hash
      uint64_t shard_id;
      uint64_t settlement_epoch;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(p_canonical_id)
        KV_SERIALIZE(shard_id)
        KV_SERIALIZE(settlement_epoch)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  




  struct COMMAND_RPC_SET_LOG_HASH_RATE
  {
    struct request_t: public rpc_request_base
    {
      bool visible;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(visible)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_LOG_LEVEL
  {
    struct request_t: public rpc_request_base
    {
      int8_t level;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(level)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_LOG_CATEGORIES
  {
    struct request_t: public rpc_request_base
    {
      std::string categories;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(categories)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::string categories;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(categories)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct tx_info
  {
    std::string id_hash;
    std::string tx_json; // TODO - expose this data directly
    uint64_t blob_size;
    uint64_t weight;
    uint64_t fee;
    std::string max_used_block_id_hash;
    uint64_t max_used_block_height;
    bool kept_by_block;
    uint64_t last_failed_height;
    std::string last_failed_id_hash;
    uint64_t receive_time;
    bool relayed;
    uint64_t last_relayed_time;
    bool do_not_relay;
    bool double_spend_seen;
    std::string tx_blob;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(id_hash)
      KV_SERIALIZE(tx_json)
      KV_SERIALIZE(blob_size)
      KV_SERIALIZE_OPT(weight, (uint64_t)0)
      KV_SERIALIZE(fee)
      KV_SERIALIZE(max_used_block_id_hash)
      KV_SERIALIZE(max_used_block_height)
      KV_SERIALIZE(kept_by_block)
      KV_SERIALIZE(last_failed_height)
      KV_SERIALIZE(last_failed_id_hash)
      KV_SERIALIZE(receive_time)
      KV_SERIALIZE(relayed)
      KV_SERIALIZE(last_relayed_time)
      KV_SERIALIZE(do_not_relay)
      KV_SERIALIZE(double_spend_seen)
      KV_SERIALIZE(tx_blob)
    END_KV_SERIALIZE_MAP()
  };

  struct spent_key_image_info
  {
    std::string id_hash;
    std::vector<std::string> txs_hashes;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(id_hash)
      KV_SERIALIZE(txs_hashes)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_GET_TRANSACTION_POOL
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::vector<tx_info> transactions;
      std::vector<spent_key_image_info> spent_key_images;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(transactions)
        KV_SERIALIZE(spent_key_images)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  struct COMMAND_RPC_GET_TRANSACTION_POOL_HASHES
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::vector<std::string> tx_hashes;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(tx_hashes)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct tx_backlog_entry
  {
    uint64_t weight;
    uint64_t fee;
    uint64_t time_in_pool;
  };

  struct COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::vector<tx_backlog_entry> backlog;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(backlog)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct txpool_histo
  {
    uint32_t txs;
    uint64_t bytes;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(txs)
      KV_SERIALIZE(bytes)
    END_KV_SERIALIZE_MAP()
  };

  struct txpool_stats
  {
    uint64_t bytes_total;
    uint32_t bytes_min;
    uint32_t bytes_max;
    uint32_t bytes_med;
    uint64_t fee_total;
    uint64_t oldest;
    uint32_t txs_total;
    uint32_t num_failing;
    uint32_t num_10m;
    uint32_t num_not_relayed;
    uint64_t histo_98pc;
    std::vector<txpool_histo> histo;
    uint32_t num_double_spends;

    txpool_stats(): bytes_total(0), bytes_min(0), bytes_max(0), bytes_med(0), fee_total(0), oldest(0), txs_total(0), num_failing(0), num_10m(0), num_not_relayed(0), histo_98pc(0), num_double_spends(0) {}

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(bytes_total)
      KV_SERIALIZE(bytes_min)
      KV_SERIALIZE(bytes_max)
      KV_SERIALIZE(bytes_med)
      KV_SERIALIZE(fee_total)
      KV_SERIALIZE(oldest)
      KV_SERIALIZE(txs_total)
      KV_SERIALIZE(num_failing)
      KV_SERIALIZE(num_10m)
      KV_SERIALIZE(num_not_relayed)
      KV_SERIALIZE(histo_98pc)
      KV_SERIALIZE(histo)
      KV_SERIALIZE(num_double_spends)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_GET_TRANSACTION_POOL_STATS
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      txpool_stats pool_stats;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(pool_stats)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };



  struct COMMAND_RPC_STOP_DAEMON
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  
  
  struct COMMAND_RPC_GET_LIMIT
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    
    struct response_t: public rpc_response_base
    {
      uint64_t limit_up;
      uint64_t limit_down;
      
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(limit_up)
        KV_SERIALIZE(limit_down)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  
  struct COMMAND_RPC_SET_LIMIT
  {
    struct request_t: public rpc_request_base
    {
      int64_t limit_down;  // all limits (for get and set) are kB/s
      int64_t limit_up;
      
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(limit_down)
        KV_SERIALIZE(limit_up)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    
    struct response_t: public rpc_response_base
    {
      int64_t limit_up;
      int64_t limit_down;
      
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(limit_up)
        KV_SERIALIZE(limit_down)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  
  struct COMMAND_RPC_OUT_PEERS
  {
    struct request_t: public rpc_request_base
    {
      bool set;
      uint32_t out_peers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE_OPT(set, true)
        KV_SERIALIZE(out_peers)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    
    struct response_t: public rpc_response_base
    {
      uint32_t out_peers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(out_peers)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_IN_PEERS
  {
    struct request_t: public rpc_request_base
    {
      bool set;
      uint32_t in_peers;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE_OPT(set, true)
        KV_SERIALIZE(in_peers)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      uint32_t in_peers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(in_peers)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
    

  struct COMMAND_RPC_GETBANS
  {
    struct ban
    {
      std::string host;
      uint32_t ip;
      uint32_t seconds;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(host)
        KV_SERIALIZE(ip)
        KV_SERIALIZE(seconds)
      END_KV_SERIALIZE_MAP()
    };

    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::vector<ban> bans;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(bans)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SETBANS
  {
    struct ban
    {
      std::string host;
      uint32_t ip;
      bool ban;
      uint32_t seconds;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(host)
        KV_SERIALIZE(ip)
        KV_SERIALIZE(ban)
        KV_SERIALIZE(seconds)
      END_KV_SERIALIZE_MAP()
    };

    struct request_t: public rpc_request_base
    {
      std::vector<ban> bans;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(bans)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_BANNED
  {
    struct request_t
    {
      std::string address;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string status;
      bool banned;
      uint32_t seconds;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(status)
        KV_SERIALIZE(banned)
        KV_SERIALIZE(seconds)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_FLUSH_TRANSACTION_POOL
  {
    struct request_t: public rpc_request_base
    {
      std::vector<std::string> txids;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(txids)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_OUTPUT_HISTOGRAM
  {
    struct request_t: public rpc_request_base
    {
      std::vector<uint64_t> amounts;
      uint64_t min_count;
      uint64_t max_count;
      bool unlocked;
      uint64_t recent_cutoff;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base);
        KV_SERIALIZE(amounts);
        KV_SERIALIZE(min_count);
        KV_SERIALIZE(max_count);
        KV_SERIALIZE(unlocked);
        KV_SERIALIZE(recent_cutoff);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct entry
    {
      uint64_t amount;
      uint64_t total_instances;
      uint64_t unlocked_instances;
      uint64_t recent_instances;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(amount);
        KV_SERIALIZE(total_instances);
        KV_SERIALIZE(unlocked_instances);
        KV_SERIALIZE(recent_instances);
      END_KV_SERIALIZE_MAP()

      entry(uint64_t amount, uint64_t total_instances, uint64_t unlocked_instances, uint64_t recent_instances):
          amount(amount), total_instances(total_instances), unlocked_instances(unlocked_instances), recent_instances(recent_instances) {}
      entry() {}
    };

    struct response_t: public rpc_response_base
    {
      std::vector<entry> histogram;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(histogram)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_COINBASE_TX_SUM
  {
    struct request_t: public rpc_request_base
    {
      uint64_t height;
      uint64_t count;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base);
        KV_SERIALIZE(height);
        KV_SERIALIZE(count);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      uint64_t emission_amount;
      std::string wide_emission_amount;
      uint64_t emission_amount_top64;
      uint64_t fee_amount;
      std::string wide_fee_amount;
      uint64_t fee_amount_top64;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(emission_amount)
        KV_SERIALIZE(wide_emission_amount)
        KV_SERIALIZE(emission_amount_top64)
        KV_SERIALIZE(fee_amount)
        KV_SERIALIZE(wide_fee_amount)
        KV_SERIALIZE(fee_amount_top64)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  struct COMMAND_RPC_GET_ALTERNATE_CHAINS
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct chain_info
    {
      std::string block_hash;
      uint64_t height;
      uint64_t length;
      uint64_t difficulty;
      std::string wide_difficulty;
      uint64_t difficulty_top64;
      std::vector<std::string> block_hashes;
      std::string main_chain_parent_block;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(block_hash)
        KV_SERIALIZE(height)
        KV_SERIALIZE(length)
        KV_SERIALIZE(difficulty)
        KV_SERIALIZE(wide_difficulty)
        KV_SERIALIZE(difficulty_top64)
        KV_SERIALIZE(block_hashes)
        KV_SERIALIZE(main_chain_parent_block)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t: public rpc_response_base
    {
      std::vector<chain_info> chains;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(chains)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_RELAY_TX
  {
    struct request_t: public rpc_request_base
    {
      std::vector<std::string> txids;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(txids)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };



  struct COMMAND_RPC_POP_BLOCKS
  {
    struct request_t: public rpc_request_base
    {
      uint64_t nblocks;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(nblocks)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      uint64_t height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PRUNE_BLOCKCHAIN
  {
    struct request_t: public rpc_request_base
    {
      bool check;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE_OPT(check, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      bool pruned;
      uint32_t pruning_seed;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(pruned)
        KV_SERIALIZE(pruning_seed)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_FLUSH_CACHE
  {
    struct request_t: public rpc_request_base
    {
      bool bad_blocks;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE_OPT(bad_blocks, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_CURVE_TREE_PATH
  {
    struct request_t: public rpc_request_base
    {
      std::vector<uint64_t> output_indices;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(output_indices)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct path_entry
    {
      uint64_t output_index;
      uint8_t  tree_depth;
      std::string path_blob;          // hex-encoded Merkle path (leaf scalars + branch hashes)
      std::string chunk_outputs_blob; // hex-encoded Ed25519 output data for each leaf in the chunk:
                                      // per entry: [O:32][I:32][C:32][h_pqc:32] = 128 bytes

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(output_index)
        KV_SERIALIZE(tree_depth)
        KV_SERIALIZE(path_blob)
        KV_SERIALIZE(chunk_outputs_blob)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t: public rpc_response_base
    {
      std::string reference_block;
      std::string curve_tree_root;
      uint64_t    reference_height;
      uint8_t     tree_depth;
      uint64_t    leaf_count;
      std::vector<path_entry> paths;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(reference_block)
        KV_SERIALIZE(curve_tree_root)
        KV_SERIALIZE(reference_height)
        KV_SERIALIZE(tree_depth)
        KV_SERIALIZE(leaf_count)
        KV_SERIALIZE(paths)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_CURVE_TREE_INFO
  {
    struct request_t: public rpc_request_base
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::string root;
      uint8_t     depth;
      uint64_t    leaf_count;
      uint64_t    height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(root)
        KV_SERIALIZE(depth)
        KV_SERIALIZE(leaf_count)
        KV_SERIALIZE(height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT
  {
    struct request_t: public rpc_request_base
    {
      uint64_t block_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(block_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t: public rpc_response_base
    {
      std::string root;
      uint8_t     depth;
      uint64_t    leaf_count;
      uint64_t    block_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(root)
        KV_SERIALIZE(depth)
        KV_SERIALIZE(leaf_count)
        KV_SERIALIZE(block_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  /// Emission claim-source query (`EMISSION_CLAIM_BUILDER.md` §7): the
  /// claimant's bond-record claim context plus one as-of-`E` epoch snapshot
  /// for **every** epoch in the claim window `[claim_window_floor(settled),
  /// settled − 1]`, unconditionally — the request cannot encode an epoch
  /// selection and the handler branches on nothing claimable-set-derived
  /// (§7.2 transport cause-blindness). The per-epoch payload mirrors
  /// `ArchivalEmissionEpochSnapshot` (blockchain_db.h) field-for-field and is
  /// filled by the single landed gather,
  /// `gather_archival_emission_epoch_snapshot` — never a second gather path
  /// (§7.1, the daemon face of CB-1(b)'s single-evaluator invariant).
  ///
  /// Deliberately NOT carried (§7.3, each exclusion load-bearing):
  /// consensus constants (`settlement_epoch_blocks` / `age_weight_milli` /
  /// curve params — the wallet builds `EpochCloseInputs` from its own
  /// compiled constants, no second source), close-only operands
  /// (CB-5-structural: carrying them would make a cause-distinguishing
  /// wallet branch representable; the retired M1 gate's operands were the
  /// original entry in this class),
  /// per-epoch holdings (WS-1: the work channel carries no holdings), and
  /// tree/membership paths (existing spend-path machinery's concern).
  struct COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE
  {
    struct request_t: public rpc_request_base
    {
      /// 32-byte `P_canonical_id`, hex. The ONLY request field (§7.2): no
      /// epoch selector, no range, no claimable-subset encoding.
      std::string p_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_request_base)
        KV_SERIALIZE(p_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    /// Mirrors `ArchivalEmissionEpochSnapshot::BondRow`.
    struct bond_row_t
    {
      uint64_t join_settlement_epoch;
      bool is_foundation_complete_tree;
      /// Flattened (start_epoch, end_exclusive) pairs, as landed.
      std::vector<uint64_t> bad_intervals_flat;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(join_settlement_epoch)
        KV_SERIALIZE(is_foundation_complete_tree)
        KV_SERIALIZE(bad_intervals_flat)
      END_KV_SERIALIZE_MAP()
    };

    /// Mirrors `ArchivalEmissionEpochSnapshot::ShardRow`.
    struct shard_row_t
    {
      uint64_t shard_id;
      uint64_t freeze_height;
      bool has_segment;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(shard_id)
        KV_SERIALIZE(freeze_height)
        KV_SERIALIZE(has_segment)
      END_KV_SERIALIZE_MAP()
    };

    /// Mirrors `ArchivalEmissionEpochSnapshot::CreditPair`.
    struct credit_pair_t
    {
      uint64_t bond_idx;
      uint64_t shard_idx;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(bond_idx)
        KV_SERIALIZE(shard_idx)
      END_KV_SERIALIZE_MAP()
    };

    /// One as-of-`E` snapshot; mirrors `ArchivalEmissionEpochSnapshot`
    /// field-for-field (§7.3 part B — no field added, none dropped).
    struct epoch_snapshot_t
    {
      uint64_t settlement_epoch;
      /// The close-**processing** height `(E+1)·SEB` — sourced from
      /// `shekyl_archival_epoch_close_processing_height`, NEVER the
      /// lookalike `shekyl_archival_epoch_close_height` (= `(E+1)·SEB − 1`,
      /// the epoch's last block). Carries the landed struct's hazard pin
      /// verbatim (§7.3).
      uint64_t close_block_height;
      /// Persisted finalized `Σwork(E)` milli — the stored denominator,
      /// never a recompute (the M1 gate outcome reaches the wallet only
      /// through this value, same as verify).
      uint64_t sigma_work_milli;
      /// Frozen close-row `budget(E)`; meaningful only when `has_budget_row`.
      uint64_t budget_atomic;
      /// Absent close row ⇒ the wallet treats `E` as unclaimable (mirrors
      /// the verify shim's reject); present-and-zero is rejected downstream
      /// by wire positivity.
      bool has_budget_row;
      std::vector<bond_row_t> bonds;
      std::vector<shard_row_t> shards;
      std::vector<credit_pair_t> credit_pairs;
      /// Claimant P's index into `bonds`; `UINT64_MAX` sentinel (= the
      /// landed struct's `SIZE_MAX`) when P has no serve-credit row in `E`
      /// → `Option<usize>::None` at the Rust decode, exactly as the verify
      /// shim decodes it.
      uint64_t claimant_bond_idx;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(settlement_epoch)
        KV_SERIALIZE(close_block_height)
        KV_SERIALIZE(sigma_work_milli)
        KV_SERIALIZE(budget_atomic)
        KV_SERIALIZE(has_budget_row)
        KV_SERIALIZE(bonds)
        KV_SERIALIZE(shards)
        KV_SERIALIZE(credit_pairs)
        KV_SERIALIZE(claimant_bond_idx)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t: public rpc_response_base
    {
      // ── Part A: claim context (§7.3) ─────────────────────────────────
      /// Tip block count at gather time; the wallet's staleness check
      /// operand (§2 step 3 same-tip rule), not a computation operand.
      uint64_t chain_height;
      /// `shekyl_archival_settlement_epoch_at_height` over `chain_height`
      /// (the next block's height — the same operand class the connect
      /// path's `apply_archival_emission_claim` uses for the earliest
      /// block that can include the claim). Never a second derivation.
      uint64_t current_settled_epoch;
      /// `archival_bond_record` row existence for `p_id`. Absent ⇒ the
      /// wallet refuses idle (`NoClaimableEpochs`), not an RPC error.
      bool has_bond_record;
      /// Bond-record fields (meaningful only when `has_bond_record`):
      uint64_t join_settlement_epoch;
      /// `HoldingsDescriptor` wire form: kind 0 = compact shard set,
      /// 1 = foundation-complete tree.
      uint8_t holdings_kind;
      std::vector<uint64_t> held_shard_ids;
      /// Strictly increasing; mirrors
      /// `ClaimantBondRecord::claimed_settlement_epochs`.
      std::vector<uint64_t> claimed_settlement_epochs;
      // ── Part A, exit operands (the `Unbond` preconditions) ───────────
      /// The record's current bonded balance. `verify_unbond_bond_post`
      /// checks it first (`RecordMissing` / `NothingToUnbond`) and requires
      /// the vin's `bond_debit` to equal it exactly, so a producer cannot
      /// even name a full exit without this value.
      uint64_t bonded_total_atomic;
      /// The record's interval-log length — `verify_unbond_bond_post`'s
      /// `record_bad_interval_count` operand, the sixth and last of its
      /// record facts.
      ///
      /// A plain count, with no presence flag, because unlike the two anchors
      /// below it has no absent state: a record with no bad intervals has a
      /// log of length 0, which is a value rather than a silence. The hazard
      /// is the same one the flags exist for, though, and lands on the
      /// decoder instead: 0 is the *permissive* reading (`0 <
      /// MAX_BOND_BAD_INTERVALS` passes), so an absent field must be a decode
      /// error wallet-side rather than a default.
      ///
      /// Bounded by the codec's `kMaxBadIntervals`, so it always fits.
      uint64_t bad_interval_count;
      /// The whole-record release-cooldown anchor, folded daemon-side by
      /// `shekyl_archival_whole_record_last_served` — the same fold consensus
      /// applies. Never re-derived by the wallet, for the same reason
      /// `close_block_height` is not.
      ///
      /// **The flag is a safety boundary, not a convenience.** Both consumers
      /// of the anchor (`release_cooldown_elapsed`, `slashes_settled_through`)
      /// treat an ABSENT anchor as permissive — correct at the daemon, where
      /// absence can only mean "nothing has ever served". A reader that
      /// inferred absence from a missing or zeroed field would put "the value
      /// did not arrive" into that same permissive branch and report an
      /// irreversible exit as ready on a fact it never received. Reported, so
      /// the two are different values rather than the same silence. Epoch 0
      /// is a real settlement epoch; only this flag separates the cases.
      bool has_last_served_epoch;
      /// Meaningful only when `has_last_served_epoch`.
      uint64_t last_served_epoch;
      /// The slash scheduler's monotone watermark. The storage sentinel
      /// (`u64::MAX` = nothing settled yet) is resolved daemon-side into this
      /// flag rather than shipped raw, so no consumer has to know it.
      ///
      /// Note the deliberate asymmetry with the anchor above: on THIS operand
      /// absence is already fail-closed at consensus
      /// (`slashes_settled_through` returns false when the watermark is absent
      /// but an anchor exists), which is why a single shared "absent" encoding
      /// for both operands would be wrong for one of them by construction.
      bool has_last_settled_slash_epoch;
      /// Meaningful only when `has_last_settled_slash_epoch`.
      uint64_t last_settled_slash_epoch;
      // ── Part B: per-epoch snapshots, full window unconditionally ─────
      std::vector<epoch_snapshot_t> epochs;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_PARENT(rpc_response_base)
        KV_SERIALIZE(chain_height)
        KV_SERIALIZE(current_settled_epoch)
        KV_SERIALIZE(has_bond_record)
        KV_SERIALIZE(join_settlement_epoch)
        KV_SERIALIZE(holdings_kind)
        KV_SERIALIZE(held_shard_ids)
        KV_SERIALIZE(claimed_settlement_epochs)
        KV_SERIALIZE(bonded_total_atomic)
        KV_SERIALIZE(bad_interval_count)
        KV_SERIALIZE(has_last_served_epoch)
        KV_SERIALIZE(last_served_epoch)
        KV_SERIALIZE(has_last_settled_slash_epoch)
        KV_SERIALIZE(last_settled_slash_epoch)
        KV_SERIALIZE(epochs)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

}
