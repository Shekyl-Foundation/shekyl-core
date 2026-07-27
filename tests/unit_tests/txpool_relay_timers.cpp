// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// RP-4 (docs/design/DAEMON_RELAY_PRIVACY.md §17.1): the embargo and
// MIN_RELAY_TIME are disjoint timers, and that must stay true.
//
// get_relayable_transactions dispatches on relay *method*: stem/forward are
// gated solely by `last_relayed_time > now` — which for a stemmed tx IS its
// embargo deadline — while get_relay_delay/MIN_RELAY_TIME gates only
// local/fluff/block. That disjointness is why lengthening the embargo from the
// inherited 39s to the derived 144s cannot race the re-broadcast interval, even
// though the origin-alone black-hole recovery p90 (~331s) now exceeds
// MIN_RELAY_TIME (300s).
//
// Armed here rather than left as prose because a future edit that folded stem
// into the get_relay_delay branch would reintroduce the race silently: the
// daemon would still relay, just at the wrong time, and no existing test looks.
// The discriminating case is a stem tx whose embargo has *just* expired — the
// two branches disagree there, so it fails loudly if they are ever merged.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <cstring>
#include <ctime>
#include <unordered_map>

#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
// cryptonote_core.h defines cryptonote::test_options (blockchain.h only
// forward-declares it), needed by init_blockchain's fakechain options.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"

using namespace cryptonote;

namespace
{

// Minimal in-memory txpool-backed TestDB for relay-timer probes.
class RelayTimerTestDB : public BaseTestDB
{
public:
  explicit RelayTimerTestDB(uint64_t height) : m_height(height) { m_open = true; }

  crypto::hash block_id_at(uint64_t height) const
  {
    crypto::hash h = crypto::null_hash;
    const uint64_t tagged_height = height + 1;
    memcpy(h.data, &tagged_height, sizeof(tagged_height));
    return h;
  }

  virtual uint64_t height() const override { return m_height; }
  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const override
  {
    return block_id_at(height);
  }
  virtual crypto::hash top_block_hash(uint64_t* block_height = NULL) const override
  {
    if (block_height)
      *block_height = m_height ? m_height - 1 : 0;
    return m_height ? block_id_at(m_height - 1) : crypto::null_hash;
  }

  virtual void add_txpool_tx(const crypto::hash& txid, const cryptonote::blobdata_ref& blob,
    const cryptonote::txpool_tx_meta_t& meta) override
  {
    m_txpool[txid] = {meta, cryptonote::blobdata(blob.data(), blob.size())};
  }
  virtual void update_txpool_tx(const crypto::hash& txid, const cryptonote::txpool_tx_meta_t& meta) override
  {
    const auto it = m_txpool.find(txid);
    if (it != m_txpool.end())
      it->second.meta = meta;
  }
  virtual void remove_txpool_tx(const crypto::hash& txid) override { m_txpool.erase(txid); }
  virtual uint64_t get_txpool_tx_count(relay_category = relay_category::broadcasted) const override
  {
    return m_txpool.size();
  }
  virtual bool txpool_has_tx(const crypto::hash& txid, relay_category) const override
  {
    return m_txpool.count(txid) != 0;
  }
  virtual bool get_txpool_tx_meta(const crypto::hash& txid, cryptonote::txpool_tx_meta_t& meta) const override
  {
    const auto it = m_txpool.find(txid);
    if (it == m_txpool.end())
      return false;
    meta = it->second.meta;
    return true;
  }
  virtual bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata& bd, relay_category) const override
  {
    const auto it = m_txpool.find(txid);
    if (it == m_txpool.end())
      return false;
    bd = it->second.blob;
    return true;
  }
  virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid, relay_category) const override
  {
    return m_txpool.at(txid).blob;
  }
  virtual bool for_all_txpool_txes(
    std::function<bool(const crypto::hash&, const cryptonote::txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f,
    bool include_blob = false, relay_category = relay_category::broadcasted) const override
  {
    for (const auto& entry : m_txpool)
    {
      cryptonote::blobdata_ref ref{entry.second.blob.data(), entry.second.blob.size()};
      if (!f(entry.first, entry.second.meta, include_blob ? &ref : nullptr))
        return false;
    }
    return true;
  }

private:
  struct pool_entry
  {
    cryptonote::txpool_tx_meta_t meta;
    cryptonote::blobdata blob;
  };

  uint64_t m_height;
  std::unordered_map<crypto::hash, pool_entry> m_txpool;
};

struct BlockchainAndPool
{
  cryptonote::tx_memory_pool txpool;
  cryptonote::Blockchain bc;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
  BlockchainAndPool() : txpool(bc), bc(txpool) {}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
};

bool init_blockchain(Blockchain& bc, BlockchainDB* db)
{
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 1, nullptr);
}

crypto::hash make_txid(uint8_t fill)
{
  crypto::hash h;
  memset(h.data, fill, sizeof(h.data));
  return h;
}

cryptonote::blobdata make_minimal_tx_blob()
{
  cryptonote::transaction tx{};
  tx.version = 1;
  tx.unlock_time = 0;
  return cryptonote::tx_to_blob(tx);
}

txpool_tx_meta_t make_meta(uint64_t weight, time_t receive_time)
{
  txpool_tx_meta_t meta{};
  meta.weight = weight;
  meta.fee = 1000;
  meta.receive_time = receive_time;
  meta.set_relay_method(relay_method::fluff);
  return meta;
}

// A pool holding one tx with the given relay method and timers.
struct RelayTimerFixture
{
  BlockchainAndPool bap;
  RelayTimerTestDB* db;
  crypto::hash txid;
  cryptonote::blobdata blob;

  RelayTimerFixture() : db(new RelayTimerTestDB(300)), txid(make_txid(0x77)),
                        blob(make_minimal_tx_blob()) {}

  bool init() { return init_blockchain(bap.bc, db); }

  void put(relay_method method, time_t receive_time, time_t last_relayed_time)
  {
    txpool_tx_meta_t meta = make_meta(100, receive_time);
    meta.set_relay_method(method);
    meta.last_relayed_time = last_relayed_time;
    meta.relayed = true;
    db->add_txpool_tx(txid, {blob.data(), blob.size()}, meta);
  }

  bool relayable()
  {
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> txs;
    bap.txpool.get_relayable_transactions(txs);
    for (const auto& t : txs)
      if (std::get<0>(t) == txid)
        return true;
    return false;
  }
};

} // namespace

TEST(txpool_relay_timers, stem_is_gated_by_its_embargo_not_min_relay_time)
{
  const time_t now = time(nullptr);
  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // The discriminating case: a stem tx whose embargo expired a moment ago. The
  // embargo says "relay now"; MIN_RELAY_TIME (300s since it was set) says
  // "wait". Only the embargo may govern a stem tx, so it must be relayable.
  fx.put(relay_method::stem, now - 10, now - 1);
  EXPECT_TRUE(fx.relayable())
    << "an expired embargo must release the tx immediately; if MIN_RELAY_TIME "
       "gated stem txs this would wait ~300s and the sec 17.1 reconciliation "
       "would be broken";
}

TEST(txpool_relay_timers, stem_under_embargo_is_held_however_old_the_tx_is)
{
  const time_t now = time(nullptr);
  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // Received long ago (well past MIN_RELAY_TIME) but the embargo deadline is
  // still in the future: age must not release it. The deadline is the gate.
  fx.put(relay_method::stem, now - 100000, now + 3600);
  EXPECT_FALSE(fx.relayable())
    << "a stem tx must stay held until its embargo deadline passes";
}

TEST(txpool_relay_timers, fluff_still_obeys_min_relay_time)
{
  const time_t now = time(nullptr);
  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // The other half of the disjointness: a just-relayed fluff tx is held by
  // get_relay_delay/MIN_RELAY_TIME, which the embargo change must not disturb.
  fx.put(relay_method::fluff, now, now);
  EXPECT_FALSE(fx.relayable())
    << "a fluff tx relayed just now must wait out MIN_RELAY_TIME";
}
