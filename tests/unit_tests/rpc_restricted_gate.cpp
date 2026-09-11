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


// The origin context the C++ dispatch bridge hands every bridged handler
// (docs/design/DAEMON_RPC_KV_CUTOVER.md §7, 2026-08-26).
//
// Until that date `dispatch_json` / `dispatch_jsonrpc` / `dispatch_jsonrpc_we`
// passed `nullptr`, so `restricted = m_restricted && ctx` was false on every
// JSON route no matter how the listener was configured. That did not merely
// disable request caps: the pool reads compute
// `allow_sensitive = !request_has_rpc_origin || !restricted`, which was
// likewise always true, and `allow_sensitive` decides whether a transaction
// that is not `relay_category::broadcasted` — a stem-phase or locally
// submitted one — is disclosed at all. A restricted, public listener was
// answering with them.
//
// What is here is what only C++ can see: the shared context must not be a
// bannable host, and the relay-category filter the sensitive flag selects
// between must exclude every pre-broadcast state.
//
// What is NOT here, deliberately, is "the dispatchers pass the context". A
// unit test of the helper cannot observe its call sites, so such a test stays
// green through exactly the regression it advertises. That assertion lives on
// the production path instead, in Rust:
// `restricted_listener_applies_request_caps_through_the_ffi_bridge`
// (rust/shekyl-engine-core/src/engine/regtest_e2e.rs) spawns a daemon with
// both listeners and puts a real over-cap request to each.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"
#include "cryptonote_protocol/enums.h"
#include "rpc/core_rpc_server.h"

// The shared origin context must not be a bannable host.
//
// `add_host_fail` scores `ctx->m_remote_address` and blocks the host past a
// threshold. The bridge hands every caller the *same* context, so if its
// address were blockable, unrelated callers would accumulate a single ban
// score against one empty address and eventually ban it. Leaving the address
// default-constructed is what prevents that, and this asserts the epee
// property that makes it work.
//
// The other half of the contract — that the dispatchers actually pass this
// context, so `m_restricted && ctx` means `m_restricted` — is deliberately
// NOT tested here. A unit test of the helper cannot see its call sites:
// reverting any dispatcher to `nullptr` would leave such a test green, which
// makes it decorative on exactly the boundary it claims to guard. That guard
// is `restricted_listener_applies_request_caps_through_the_ffi_bridge` in
// rust/shekyl-engine-core/src/engine/regtest_e2e.rs, which puts a real
// over-cap request to a real `--restricted-rpc` listener and goes red when a
// dispatcher stops passing the origin.
TEST(rpc_restricted_gate, the_shared_origin_is_not_a_bannable_host)
{
  const cryptonote::core_rpc_server::connection_context ctx{};
  EXPECT_FALSE(ctx.m_remote_address.is_blockable())
    << "a default-constructed address must not be blockable, or every bridged "
       "request would score RPC ban points against one shared empty address";
}

// ─── What the flag actually gates ────────────────────────────────────────────
//
// That the dispatchers hand handlers a context at all is asserted on the
// production path, in the Rust e2e named above — not here. What follows is the
// other half: what having that context changes for disclosure, which is the
// reason the fix matters:
//
//   allow_sensitive  ->  relay_category::all vs ::broadcasted   (tx_pool.cpp)
//   category         ->  `if (!meta.matches(category)) continue` (db_lmdb.cpp)
//
// so the flag does not trim fields off a transaction — it decides whether the
// transaction is enumerated at all. These run against a real BlockchainLMDB,
// not a test double, because the filter lives in the DB's own iteration and a
// double that reimplemented it would be testing itself.

namespace
{
  struct TempLMDB
  {
    boost::filesystem::path tmpdir;
    cryptonote::BlockchainLMDB db;

    TempLMDB()
    {
      tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
      boost::filesystem::create_directories(tmpdir);
      db.open(tmpdir.string());
    }
    ~TempLMDB()
    {
      try { db.close(); boost::filesystem::remove_all(tmpdir); } catch (...) {}
    }
  };

  crypto::hash tagged(uint8_t tag)
  {
    crypto::hash h = crypto::null_hash;
    // Unsigned view, for the reason the oracle emitter's generator carries:
    // `data` is `char[]` and the parameter admits 0..255. Today's callers pass
    // 1..3, so the conversion is well-defined by accident of the call sites
    // rather than by the code — which is exactly the kind of safety that
    // stops holding when someone adds a fourth transaction.
    *reinterpret_cast<unsigned char*>(h.data) = tag;
    return h;
  }

  // One pool record in a given relay state.
  void put(cryptonote::BlockchainDB& db, const crypto::hash& id, cryptonote::relay_method m)
  {
    cryptonote::txpool_tx_meta_t meta{};
    meta.set_relay_method(m);
    const std::string blob(32, '\0');
    db.add_txpool_tx(id, cryptonote::blobdata_ref{blob.data(), blob.size()}, meta);
  }

  std::vector<crypto::hash> enumerate(cryptonote::BlockchainDB& db, cryptonote::relay_category c)
  {
    std::vector<crypto::hash> out;
    db.for_all_txpool_txes([&out](const crypto::hash& id, const cryptonote::txpool_tx_meta_t&,
        const cryptonote::blobdata_ref*) { out.push_back(id); return true; }, false, c);
    return out;
  }
}

// The measurement the finding is about. A stem transaction and a locally
// submitted one are in the pool beside a fluffed one. Asking with
// `allow_sensitive` true — which is what a restricted listener got for every
// bridged request until this commit — enumerates all three. Asking with it
// false, which is what a restricted listener gets now, enumerates only the
// one the network already has.
TEST(rpc_restricted_disclosure, the_sensitive_scope_is_the_not_yet_broadcast_set)
{
  using cryptonote::relay_method;
  using cryptonote::relay_category;

  // No HardFork is registered: this test never adds a block, and the txpool
  // tables do not consult one. The block-adding tests nearby need it; copying
  // it here would also outlive-invert it, since a HardFork declared after the
  // DB is destroyed before the close that holds its pointer.
  TempLMDB env;

  const crypto::hash fluffed = tagged(1);
  const crypto::hash stemming = tagged(2);
  const crypto::hash local = tagged(3);
  {
    cryptonote::db_wtxn_guard w(&env.db);
    put(env.db, fluffed, relay_method::fluff);
    put(env.db, stemming, relay_method::stem);
    put(env.db, local, relay_method::local);
  }

  const auto sensitive = enumerate(env.db, relay_category::all);
  const auto public_only = enumerate(env.db, relay_category::broadcasted);

  EXPECT_EQ(3u, sensitive.size())
    << "allow_sensitive=true enumerates the whole pool — this is what a "
       "restricted listener was being served";
  ASSERT_EQ(1u, public_only.size())
    << "allow_sensitive=false must enumerate only what the network already has";
  EXPECT_EQ(fluffed, public_only.front())
    << "the one transaction a public caller may learn of is the fluffed one";

  // The count is the same gate, and `get_info` reports it as `tx_pool_size`.
  // One of the three is broadcast, so a restricted caller sees exactly that
  // one — the *size* of the stem/local set is itself a signal, and it is now
  // subtracted rather than published.
  EXPECT_EQ(1u, env.db.get_txpool_tx_count(relay_category::broadcasted))
    << "a restricted caller's pool count must include only broadcast "
       "transactions";
  EXPECT_EQ(3u, env.db.get_txpool_tx_count(relay_category::all));
}

// The set difference, at the predicate both the pool and the DB delegate to.
// `none` is included for completeness: it is *not* excluded from
// `relay_category::all`, so it would leak like the others — but it is
// unreachable in Shekyl (its only writer, tx_pool.cpp, is a transient
// initializer that `upgrade_relay_method` raises on the same path, and no RPC
// accepts `do_not_relay`; the meta field's only writer hardcodes 0).
TEST(rpc_restricted_disclosure, broadcasted_excludes_every_pre_broadcast_state)
{
  using cryptonote::relay_method;
  using cryptonote::relay_category;

  for (const relay_method m : {relay_method::none, relay_method::local, relay_method::stem})
  {
    EXPECT_FALSE(cryptonote::matches_category(m, relay_category::broadcasted))
      << "relay method " << unsigned(static_cast<uint8_t>(m))
      << " has not been broadcast and must be outside the public scope";
    EXPECT_TRUE(cryptonote::matches_category(m, relay_category::all))
      << "…and inside the sensitive one, which is what makes the flag a "
         "disclosure decision rather than a field trim";
  }
  for (const relay_method m : {relay_method::block, relay_method::fluff})
  {
    EXPECT_TRUE(cryptonote::matches_category(m, relay_category::broadcasted))
      << "the network already has this one";
  }
}
