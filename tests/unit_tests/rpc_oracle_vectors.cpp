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


// RK-4c oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what epee emits for `/get_transactions` and `/is_key_image_spent`
// before their handlers and COMMAND_RPC_GET_TRANSACTIONS /
// COMMAND_RPC_IS_KEY_IMAGE_SPENT are deleted.
//
// The hazard this capture exists for is `entry`'s KV map, which is not a
// fixed field list. It branches:
//
//   if (!this_ref.in_pool)  ->  block_height, confirmations,
//                               block_timestamp, output_indices
//   else                    ->  relayed, received_timestamp
//
// so the emitted field SET depends on a value in the same object. A Rust
// mirror that models the union as one flat struct with optional members can
// still round-trip every vector while emitting a shape the daemon never
// does — both groups at once, or the pool group on a mined transaction.
// Only vectors that pin BOTH shapes, in the same document, say which
// members travel together. `chain_and_pool` is that document: one entry of
// each, so the two field sets appear side by side and a mirror that merges
// them cannot match.
//
// The rest is omission behaviour, which the struct declaration hides:
//
//   pruned          OPT false          -> omitted unless the tx is pruned
//   prune, split    OPT false (request)-> omitted at their defaults
//   every sequence  empty              -> omitted, not `[]` — txs,
//                                         missed_tx, txs_as_hex,
//                                         txs_as_json, output_indices,
//                                         spent_status
//
// `as_hex` / `pruned_as_hex` / `prunable_as_hex` / `as_json` are plain
// KV_SERIALIZE, so they are emitted even when empty. Which of them the
// handler fills is the (split, prune, decode_as_json) matrix, and that is
// content, not shape: `split_form` and `decoded` pin the two the wallet
// actually receives.
//
// `txs_as_hex` / `txs_as_json` are captured as they stand. They are deleted
// later in this slice (rule 60 — the handler fills them "in case an old
// wallet asks" and the old wallet is gone), and the deletion gets its own
// `_v2` vector beside these rather than an edit to them: a vector is the
// oracle's memory, and a wire change is a decision with a version bump.
//
// Deleted with the structs it captures, later in this slice.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
  void pin(const char* name, const std::string& json)
  {
    const std::string path = std::string(RPC_ORACLE_VECTOR_DIR) + "/" + name;
    if (std::getenv("SHEKYL_WRITE_RPC_VECTORS"))
    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.good()) << "cannot write " << path;
      out << json;
      return;
    }
    std::ifstream in(path, std::ios::binary);
    ASSERT_TRUE(in.good()) << "missing oracle vector " << path
      << " (run with SHEKYL_WRITE_RPC_VECTORS=1 to capture)";
    std::stringstream buf;
    buf << in.rdbuf();
    EXPECT_EQ(buf.str(), json) << "oracle vector " << name << " drifted from epee's output";
  }

  // A hash that is a function of its tag, so every hash field in the vector
  // is visibly distinct and a transposed field shows up. Same generator as
  // the Rust parity test's.
  crypto::hash tagged_hash(uint8_t tag)
  {
    crypto::hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i)
      h.data[i] = static_cast<char>((i * 7 + tag) & 0xff);
    return h;
  }

  std::string tagged_hex(uint8_t tag)
  {
    return epee::string_tools::pod_to_hex(tagged_hash(tag));
  }

  template <class T>
  std::string emit(T& obj)
  {
    std::string json;
    EXPECT_TRUE(epee::serialization::store_t_to_json(obj, json));
    return json;
  }
}

// ─── /get_transactions ───────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_transactions_request_v1)
{
  // Every request member set away from its default, so nothing is omitted.
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req{};
  req.txs_hashes = {tagged_hex(1), tagged_hex(2)};
  req.decode_as_json = true;
  req.prune = true;
  req.split = true;
  pin("get_transactions_request_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_transactions_request_defaults_v1)
{
  // `prune` and `split` are OPT at false and vanish; `decode_as_json` is a
  // plain member and stays. The pair is what says which is which.
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req{};
  req.txs_hashes = {tagged_hex(3)};
  pin("get_transactions_request_defaults_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_transactions_chain_and_pool_v1)
{
  // The vector this capture exists for: a mined transaction and a pool one
  // in the same response, so the two disjoint field sets of `entry` appear
  // in one document.
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res{};
  res.txs.resize(2);

  // Mined: the !in_pool arm. block_height / confirmations / block_timestamp
  // / output_indices travel; relayed and received_timestamp do not, and the
  // values set here prove it — they are non-zero and must not appear.
  auto &mined = res.txs[0];
  mined.tx_hash = tagged_hex(11);
  mined.as_hex = "0011223344";
  mined.prunable_hash = tagged_hex(12);
  mined.in_pool = false;
  mined.double_spend_seen = false;
  mined.block_height = 1234567;
  mined.confirmations = 89;
  mined.block_timestamp = 1750000000;
  mined.output_indices = {7, 8, 4294967296ull};
  mined.relayed = true;             // must NOT reach the wire
  mined.received_timestamp = 999;   // must NOT reach the wire

  // Pooled: the in_pool arm, and the mirror image — the four chain members
  // are set and must not appear.
  auto &pooled = res.txs[1];
  pooled.tx_hash = tagged_hex(21);
  pooled.as_hex = "aabbcc";
  pooled.prunable_hash = tagged_hex(22);
  pooled.in_pool = true;
  pooled.double_spend_seen = true;
  pooled.relayed = true;
  pooled.received_timestamp = 1750000123;
  pooled.block_height = 4242;       // must NOT reach the wire
  pooled.confirmations = 42;        // must NOT reach the wire
  pooled.block_timestamp = 4242;    // must NOT reach the wire
  pooled.output_indices = {1, 2};   // must NOT reach the wire

  res.txs_as_hex = {mined.as_hex, pooled.as_hex};
  res.status = CORE_RPC_STATUS_OK;
  pin("get_transactions_chain_and_pool_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_transactions_split_form_v1)
{
  // What a `split` or `prune` request gets back: as_hex stays empty and the
  // two halves carry the transaction. `pruned` is OPT and set here, so this
  // is also the vector that shows it present.
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res{};
  res.txs.resize(1);
  auto &e = res.txs[0];
  e.tx_hash = tagged_hex(31);
  e.pruned_as_hex = "0102030405";
  e.prunable_as_hex = "0607";
  e.prunable_hash = tagged_hex(32);
  e.pruned = true;
  e.in_pool = false;
  e.double_spend_seen = false;
  e.block_height = 100;
  e.confirmations = 1;
  e.block_timestamp = 1750000001;
  // output_indices left empty: an empty sequence inside the !in_pool arm,
  // which is dropped like every other empty sequence.
  res.txs_as_hex = {""};
  res.status = CORE_RPC_STATUS_OK;
  pin("get_transactions_split_form_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_transactions_decoded_v1)
{
  // decode_as_json=true fills as_json with an epee rendering of the
  // transaction (RK-D11 keeps that rendering; see §5). The pin here is that
  // the envelope carries the string unaltered, so a fixed stand-in says
  // everything the envelope has to say about it.
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res{};
  res.txs.resize(1);
  auto &e = res.txs[0];
  e.tx_hash = tagged_hex(41);
  e.as_hex = "00";
  e.as_json = "{\"version\": 2, \"unlock_time\": 0}";
  e.prunable_hash = tagged_hex(42);
  e.in_pool = false;
  e.double_spend_seen = false;
  e.block_height = 7;
  e.confirmations = 3;
  e.block_timestamp = 1750000007;
  e.output_indices = {0};
  res.txs_as_hex = {e.as_hex};
  res.txs_as_json = {e.as_json};
  res.status = CORE_RPC_STATUS_OK;
  pin("get_transactions_decoded_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_transactions_missed_v1)
{
  // Nothing found: `missed_tx` carries the hashes and `txs` — an empty
  // sequence — is omitted rather than emitted as `[]`.
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res{};
  res.missed_tx = {tagged_hex(51), tagged_hex(52)};
  res.status = CORE_RPC_STATUS_OK;
  pin("get_transactions_missed_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_transactions_refusal_v1)
{
  // A refusal is a 200 with `status` carrying the reason and every sequence
  // empty, so the whole body is one member. This is the shape the restricted
  // cap would have produced had it ever fired (§7, 2026-08-26).
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res{};
  res.status = "Too many transactions requested in restricted mode";
  pin("get_transactions_refusal_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response_t&>(res)));
}

// ─── /is_key_image_spent ─────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, is_key_image_spent_request_v1)
{
  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::request req{};
  req.key_images = {tagged_hex(61), tagged_hex(62), tagged_hex(63)};
  pin("is_key_image_spent_request_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::request_t&>(req)));
}

TEST(rpc_oracle_vectors, is_key_image_spent_v1)
{
  // All three STATUS values in one response, in the order the request asked
  // — the reply is positional and carries no key image back, so position is
  // the only thing tying an answer to its question.
  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response res{};
  res.spent_status = {
    cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT,
    cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN,
    cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL,
  };
  res.status = CORE_RPC_STATUS_OK;
  pin("is_key_image_spent_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response_t&>(res)));
}

TEST(rpc_oracle_vectors, is_key_image_spent_empty_v1)
{
  // An empty query: `spent_status` is dropped, not `[]`.
  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response res{};
  res.status = CORE_RPC_STATUS_OK;
  pin("is_key_image_spent_empty_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response_t&>(res)));
}
