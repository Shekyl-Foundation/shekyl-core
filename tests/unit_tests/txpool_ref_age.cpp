// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// F22 defect-fix coverage (docs/design/DAEMON_SUBMIT_VERDICT.md §6, §10 item 5):
//   leg 1 — remove_stuck_transactions evicts pool txs whose FCMP++ reference
//           aged past FCMP_REFERENCE_BLOCK_MAX_AGE (defect 0.8).

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
#include "cryptonote_core/tx_pool.h"

using namespace cryptonote;

namespace
{

// In-memory txpool-backed TestDB with a settable chain height.
class RefAgeTestDB : public BaseTestDB
{
public:
  explicit RefAgeTestDB(uint64_t height) : m_height(height) { m_open = true; }

  void set_chain_height(uint64_t height) { m_height = height; }

  crypto::hash block_id_at(uint64_t height) const
  {
    crypto::hash h = crypto::null_hash;
    const uint64_t tagged_height = height + 1; // +1 keeps height 0 distinct from null_hash
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
  // Circular reference: txpool and bc hold references to each other.
  // bc is not dereferenced during txpool construction.
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
  // fixed_difficulty=1 keeps init off the real difficulty algorithm, which
  // would read block data this DB does not fabricate.
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 1, nullptr);
}

crypto::hash make_txid(uint8_t fill)
{
  crypto::hash h;
  memset(h.data, fill, sizeof(h.data));
  return h;
}

// Minimal parseable blob for sweep-path txs: the eviction body only parses
// the prefix (to release key images), so an empty-vin v1 tx suffices and
// keeps remove_transaction_keyimages a no-op.
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

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// F22 leg 1: ref-age eviction in remove_stuck_transactions
// ─────────────────────────────────────────────────────────────────────────

TEST(txpool_ref_age, sweep_evicts_stale_reference)
{
  const uint64_t chain_height = 300;
  ASSERT_GT(chain_height, (uint64_t)FCMP_REFERENCE_BLOCK_MAX_AGE);

  auto db = new RefAgeTestDB(chain_height);
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  const cryptonote::blobdata blob = make_minimal_tx_blob();
  const time_t now = time(nullptr);

  // Stale: reference strictly below the consensus window floor.
  const crypto::hash stale_txid = make_txid(0x11);
  txpool_tx_meta_t stale_meta = make_meta(100, now);
  stale_meta.max_used_block_height = chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE - 1;
  db->add_txpool_tx(stale_txid, {blob.data(), blob.size()}, stale_meta);

  // Boundary: reference exactly at the window floor — consensus still
  // accepts it (blockchain.cpp: rejection requires ref < height - max_age),
  // so the sweep must keep it.
  const crypto::hash edge_txid = make_txid(0x22);
  txpool_tx_meta_t edge_meta = make_meta(100, now);
  edge_meta.max_used_block_height = chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE;
  db->add_txpool_tx(edge_txid, {blob.data(), blob.size()}, edge_meta);

  bap.txpool.m_txpool_weight = 200;
  ASSERT_TRUE(bap.txpool.remove_stuck_transactions());

  EXPECT_FALSE(db->txpool_has_tx(stale_txid, relay_category::all))
    << "stale-reference tx must be evicted by the sweep";
  EXPECT_TRUE(db->txpool_has_tx(edge_txid, relay_category::all))
    << "reference at the exact window floor is still minable and must stay";
  EXPECT_EQ(bap.txpool.m_txpool_weight, 100u);

  // The tx did not time out; it must not enter the resubmit-gate shortcut set.
  EXPECT_EQ(bap.txpool.m_timed_out_transactions.count(stale_txid), 0u)
    << "ref-age eviction must not be recorded as a timeout";
}

TEST(txpool_ref_age, sweep_spares_kept_by_block_and_zero_reference)
{
  const uint64_t chain_height = 300;
  auto db = new RefAgeTestDB(chain_height);
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  const cryptonote::blobdata blob = make_minimal_tx_blob();
  const time_t now = time(nullptr);

  // kept_by_block entries survive reorgs by design; a chain pop can bring
  // their reference back inside the window, so the ref sweep leaves them.
  const crypto::hash kept_txid = make_txid(0x33);
  txpool_tx_meta_t kept_meta = make_meta(100, now);
  kept_meta.kept_by_block = 1;
  kept_meta.max_used_block_height = chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE - 50;
  db->add_txpool_tx(kept_txid, {blob.data(), blob.size()}, kept_meta);

  // Height 0 is the no-reference sentinel (serve-credit-only txs and
  // kept_by_block entries stored on a failed input check).
  const crypto::hash zero_txid = make_txid(0x44);
  txpool_tx_meta_t zero_meta = make_meta(100, now);
  zero_meta.max_used_block_height = 0;
  db->add_txpool_tx(zero_txid, {blob.data(), blob.size()}, zero_meta);

  bap.txpool.m_txpool_weight = 200;
  ASSERT_TRUE(bap.txpool.remove_stuck_transactions());

  EXPECT_TRUE(db->txpool_has_tx(kept_txid, relay_category::all));
  EXPECT_TRUE(db->txpool_has_tx(zero_txid, relay_category::all));
  EXPECT_EQ(bap.txpool.m_txpool_weight, 200u);
}

TEST(txpool_ref_age, sweep_receive_time_eviction_still_marks_timeout)
{
  // Control: the pre-existing receive-time sweep is untouched — it still
  // evicts and still records the timeout for the resubmit gate.
  const uint64_t chain_height = 300;
  auto db = new RefAgeTestDB(chain_height);
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db));

  const cryptonote::blobdata blob = make_minimal_tx_blob();
  const time_t now = time(nullptr);

  const crypto::hash old_txid = make_txid(0x55);
  txpool_tx_meta_t old_meta = make_meta(100, now - CRYPTONOTE_MEMPOOL_TX_LIVETIME - 3600);
  old_meta.max_used_block_height = chain_height - 10; // reference is fresh; age is not
  db->add_txpool_tx(old_txid, {blob.data(), blob.size()}, old_meta);

  bap.txpool.m_txpool_weight = 100;
  ASSERT_TRUE(bap.txpool.remove_stuck_transactions());

  EXPECT_FALSE(db->txpool_has_tx(old_txid, relay_category::all));
  EXPECT_EQ(bap.txpool.m_timed_out_transactions.count(old_txid), 1u);
}
