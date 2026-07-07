// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// F22 defect-fix coverage (docs/design/DAEMON_SUBMIT_VERDICT.md §6, §10 item 5):
//   leg 1 — remove_stuck_transactions evicts pool txs whose FCMP++ reference
//           aged past FCMP_REFERENCE_BLOCK_MAX_AGE (defect 0.8);
//   leg 2 — is_transaction_ready_to_go re-checks the ref-age window and
//           reference-block canonicality before honoring the fcmp_verified
//           cache seed (defect 0.9).

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

// In-memory txpool-backed TestDB with a settable chain height and a fork
// nonce that lets a test simulate a reorg: block ids are a pure function of
// (height, fork_nonce), so bumping the nonce changes every historical id the
// way a reorg past that height would.
class RefAgeTestDB : public BaseTestDB
{
public:
  explicit RefAgeTestDB(uint64_t height) : m_height(height) { m_open = true; }

  void set_chain_height(uint64_t height) { m_height = height; }
  void set_fork_nonce(uint64_t nonce) { m_fork_nonce = nonce; }

  crypto::hash block_id_at(uint64_t height) const
  {
    crypto::hash h = crypto::null_hash;
    const uint64_t tagged_height = height + 1; // +1 keeps height 0 distinct from null_hash
    memcpy(h.data, &tagged_height, sizeof(tagged_height));
    memcpy(h.data + sizeof(tagged_height), &m_fork_nonce, sizeof(m_fork_nonce));
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
  uint64_t m_fork_nonce = 0;
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

// Structurally parseable FCMP++ tx: survives parse_and_validate_tx_from_blob
// (serializer + expand_transaction_1) without any cryptographic validity —
// the leg-2 guard only needs compute_fcmp_verification_hash to bind
// proof ‖ referenceBlock ‖ key-images on the parsed tx.
cryptonote::transaction make_fcmp_shape_tx()
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;

  cryptonote::txin_to_key txin{};
  txin.amount = 0;
  memset(&txin.k_image, 0xBB, sizeof(txin.k_image));
  tx.vin.push_back(txin); // key_offsets stay empty: FCMP++ txs carry no ring members

  cryptonote::tx_out txout{};
  txout.amount = 0;
  cryptonote::txout_to_tagged_key tagged{};
  memset(&tagged.key, 0xCC, sizeof(tagged.key));
  tagged.view_tag.data = 0;
  txout.target = tagged;
  tx.vout.push_back(txout);

  rct::rctSig& rv = tx.rct_signatures;
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xAD, sizeof(rv.referenceBlock));
  rv.outPk.resize(1);
  // The commitment mask must be a decodable curve point:
  // parse_and_validate_tx_from_blob's expand step computes mask * INV_EIGHT
  // (expand_transaction_1), which throws on garbage bytes. The Ed25519
  // basepoint's compressed encoding (0x58 then 0x66×31) is the cheapest
  // valid point that needs no rctOps call.
  memset(rv.outPk[0].mask.bytes, 0x66, sizeof(rv.outPk[0].mask.bytes));
  rv.outPk[0].mask.bytes[0] = 0x58;
  rv.enc_amounts.resize(1);
  rv.enc_amounts[0].fill(0x42);
  rv.enc_labels.resize(1);
  rv.enc_labels[0].fill(0x43);

  rct::BulletproofPlus bpp{};
  bpp.L.resize(6); // L.size()==6 → max_amounts 2^0 = 1 ≥ the single output
  bpp.R.resize(6);
  rv.p.bulletproofs_plus.push_back(bpp);
  rv.p.curve_trees_tree_depth = 20;
  rv.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04, 0x05};
  rv.p.pseudoOuts.resize(1);

  cryptonote::pqc_authentication auth{};
  auth.auth_version = 1;
  auth.scheme_id = 0;
  auth.flags = 0;
  tx.pqc_auths.push_back(auth);

  return tx;
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
  // No eviction memory exists post-D3 (DAEMON_SUBMIT_VERDICT.md §9.1): a
  // resubmit of the evicted bytes re-enters full admission and is rejected
  // by check_tx_inputs on the aged reference, not by a recorded shortcut.
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

TEST(txpool_ref_age, sweep_receive_time_eviction_still_evicts)
{
  // Control: the pre-existing receive-time sweep is untouched — it still
  // evicts on age. Post-D3 there is no timeout memory: a resubmit of the
  // evicted bytes re-enters full admission (DAEMON_SUBMIT_VERDICT.md §9.1).
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
}

// ─────────────────────────────────────────────────────────────────────────
// F22 leg 2: template-time ref-age + canonicality re-check before the
// fcmp_verified cache seed
// ─────────────────────────────────────────────────────────────────────────

namespace
{

struct Leg2Fixture
{
  static constexpr uint64_t chain_height = 300;

  RefAgeTestDB* db;
  BlockchainAndPool bap;
  cryptonote::transaction shape_tx;
  cryptonote::blobdata blob;
  crypto::hash txid;
  txpool_tx_meta_t meta;

  Leg2Fixture()
  {
    db = new RefAgeTestDB(chain_height);
    EXPECT_TRUE(init_blockchain(bap.bc, db));

    shape_tx = make_fcmp_shape_tx();
    blob = cryptonote::tx_to_blob(shape_tx);

    // The blob must survive the template path's full parse; a failure here
    // is a fixture bug, not a product bug.
    cryptonote::transaction reparsed;
    EXPECT_TRUE(cryptonote::parse_and_validate_tx_from_blob(blob, reparsed));

    txid = make_txid(0x66);
    meta = make_meta(blob.size(), time(nullptr));
    meta.fcmp_verified = 1;
    meta.fcmp_verification_hash = Blockchain::compute_fcmp_verification_hash(shape_tx);
    EXPECT_NE(meta.fcmp_verification_hash, crypto::null_hash);
  }

  // With the seed honored, the pool-level cache short-circuits
  // check_tx_inputs and the tx reads ready. With the seed refused, the full
  // Blockchain::check_tx_inputs runs and fails on this DB (the reference
  // block does not exist), so the tx reads not-ready. The verdict is
  // therefore a direct observation of the guard.
  bool run_readiness()
  {
    cryptonote::transaction tx_out;
    return bap.txpool.is_transaction_ready_to_go(meta, txid, blob, tx_out);
  }
};

} // namespace

TEST(txpool_ref_age, template_seed_honored_for_valid_canonical_reference)
{
  Leg2Fixture fx;
  const uint64_t ref_height = Leg2Fixture::chain_height - 50;
  fx.meta.max_used_block_height = ref_height;
  fx.meta.max_used_block_id = fx.db->block_id_at(ref_height);

  EXPECT_TRUE(fx.run_readiness());
  const auto it = fx.bap.txpool.m_input_cache.find(fx.txid);
  ASSERT_NE(it, fx.bap.txpool.m_input_cache.end());
  EXPECT_TRUE(std::get<0>(it->second)) << "guard must seed a positive cache entry";
}

TEST(txpool_ref_age, template_seed_refused_for_stale_reference)
{
  Leg2Fixture fx;
  const uint64_t ref_height =
    Leg2Fixture::chain_height - FCMP_REFERENCE_BLOCK_MAX_AGE - 1;
  fx.meta.max_used_block_height = ref_height;
  fx.meta.max_used_block_id = fx.db->block_id_at(ref_height);

  EXPECT_FALSE(fx.run_readiness())
    << "stale-reference tx must not be pulled into a block template";
  const auto it = fx.bap.txpool.m_input_cache.find(fx.txid);
  ASSERT_NE(it, fx.bap.txpool.m_input_cache.end());
  EXPECT_FALSE(std::get<0>(it->second))
    << "the full re-check must negative-cache, not seed success";
}

TEST(txpool_ref_age, template_seed_refused_for_noncanonical_reference)
{
  // Simulated reorg: the reference height is inside the window, but the
  // block at that height is no longer the block the proof anchored.
  Leg2Fixture fx;
  const uint64_t ref_height = Leg2Fixture::chain_height - 50;
  fx.meta.max_used_block_height = ref_height;
  fx.meta.max_used_block_id = fx.db->block_id_at(ref_height);
  fx.db->set_fork_nonce(1); // every historical block id changes

  EXPECT_FALSE(fx.run_readiness())
    << "a reorged-out reference must not ride the verification cache into a template";
  const auto it = fx.bap.txpool.m_input_cache.find(fx.txid);
  ASSERT_NE(it, fx.bap.txpool.m_input_cache.end());
  EXPECT_FALSE(std::get<0>(it->second));
}

TEST(txpool_ref_age, template_seed_refused_for_too_recent_reference)
{
  // A chain pop can leave a pooled reference above the min-age ceiling (or
  // above the top entirely); the guard must refuse the seed without an
  // out-of-range block-id lookup.
  Leg2Fixture fx;
  const uint64_t ref_height = Leg2Fixture::chain_height - 1;
  ASSERT_GT(ref_height, Leg2Fixture::chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE);
  fx.meta.max_used_block_height = ref_height;
  fx.meta.max_used_block_id = fx.db->block_id_at(ref_height);

  EXPECT_FALSE(fx.run_readiness());
  const auto it = fx.bap.txpool.m_input_cache.find(fx.txid);
  ASSERT_NE(it, fx.bap.txpool.m_input_cache.end());
  EXPECT_FALSE(std::get<0>(it->second));
}
