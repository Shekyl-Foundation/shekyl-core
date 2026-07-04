// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Integration coverage for the transaction-submit state shims
// (src/rpc/daemon_submit_ffi.cpp) against a real tx_memory_pool/Blockchain
// pair, per docs/design/DAEMON_SUBMIT_VERDICT.md:
//   §10 item 2 — the C++ latch-based race leg: a competing spend lands
//                between Phase-B snapshot and Phase-D commit on real locks,
//                and the commit reports RACED with fresh facts (Rust
//                classifies; no verdict is chosen here);
//   §10 item 4 — embargo arming: an engine-committed tx upgraded to
//                dandelionpp_stem carries a *future* last_relayed_time, and
//                forcing expiry routes it into the periodic relay loop's
//                output (pool-level, no networking);
//   plus the shim contracts: F40 pool-visibility at `all` category, the
//   §3.4 txid release-check, the F34 fee re-gate, the F23 post-prune
//   membership check, and shim 3's fetch-at-`all` relay nudge.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <cstring>
#include <ctime>
#include <future>
#include <thread>
#include <unordered_map>
#include <vector>

#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
// cryptonote_core.h defines cryptonote::test_options (blockchain.h only
// forward-declares it), needed by init_blockchain's fakechain options.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "rpc/daemon_submit_ffi.h"
#include "span.h"

using namespace cryptonote;

namespace
{

// In-memory txpool-backed TestDB with a settable chain height and a fork
// nonce (same shape as txpool_ref_age.cpp's DB), extended with the lookups
// the fact-collection shim needs: hash-anchored block_exists (F21) and a
// deterministic curve-tree root per (height, fork_nonce). Bumping the fork
// nonce changes every historical block id and root the way a reorg past
// that height would.
class SubmitTestDB : public BaseTestDB
{
public:
  explicit SubmitTestDB(uint64_t height) : m_height(height) { m_open = true; }

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

  std::array<uint8_t, 32> root_at(uint64_t height) const
  {
    const crypto::hash id = block_id_at(height);
    std::array<uint8_t, 32> root{};
    memcpy(root.data(), id.data, sizeof(id.data));
    root[31] = 0x7E; // roots are not block ids
    return root;
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

  // Inverse of block_id_at: a hash exists iff it decodes to a height below
  // the current one under the current fork nonce — a reorg (nonce bump)
  // makes every previously-issued id unknown, exactly the F21 semantics
  // (main-chain table lookup; found ⇒ canonical).
  virtual bool block_exists(const crypto::hash& h, uint64_t* height) const override
  {
    uint64_t tagged_height = 0, nonce = 0;
    memcpy(&tagged_height, h.data, sizeof(tagged_height));
    memcpy(&nonce, h.data + sizeof(tagged_height), sizeof(nonce));
    for (size_t i = 2 * sizeof(uint64_t); i < sizeof(h.data); ++i)
      if (h.data[i])
        return false;
    if (tagged_height == 0 || nonce != m_fork_nonce || tagged_height - 1 >= m_height)
      return false;
    if (height)
      *height = tagged_height - 1;
    return true;
  }

  virtual uint8_t get_curve_tree_depth() const override { return 20; }
  virtual std::array<uint8_t, 32> get_curve_tree_root_at_height(uint64_t height) const override
  {
    return root_at(height);
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
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 1, nullptr);
}

// Structurally parseable FCMP++ tx (same shape as txpool_ref_age.cpp's).
// `variant` perturbs the key image and output key so multiple distinct
// txs — including a competing spend sharing the base variant's key image —
// can coexist in one fixture.
cryptonote::transaction make_fcmp_shape_tx(uint8_t variant, uint8_t ki_variant)
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;

  cryptonote::txin_to_key txin{};
  txin.amount = 0;
  memset(&txin.k_image, 0xB0 + ki_variant, sizeof(txin.k_image));
  tx.vin.push_back(txin); // key_offsets stay empty: FCMP++ txs carry no ring members

  cryptonote::tx_out txout{};
  txout.amount = 0;
  cryptonote::txout_to_tagged_key tagged{};
  memset(&tagged.key, 0xC0 + variant, sizeof(tagged.key));
  tagged.view_tag.data = 0;
  txout.target = tagged;
  tx.vout.push_back(txout);

  rct::rctSig& rv = tx.rct_signatures;
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xAD, sizeof(rv.referenceBlock));
  rv.outPk.resize(1);
  // The commitment mask must be a decodable curve point (see
  // txpool_ref_age.cpp): Ed25519 basepoint compressed encoding.
  memset(rv.outPk[0].mask.bytes, 0x66, sizeof(rv.outPk[0].mask.bytes));
  rv.outPk[0].mask.bytes[0] = 0x58;
  rv.enc_amounts.resize(1);
  rv.enc_amounts[0].fill(0x42);
  rv.enc_labels.resize(1);
  rv.enc_labels[0].fill(0x43);

  rct::BulletproofPlus bpp{};
  bpp.L.resize(6);
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

struct SubmitTx
{
  cryptonote::transaction tx;
  cryptonote::blobdata blob;
  crypto::hash txid;
  uint64_t weight = 0;
  uint64_t fee = 0;
};

// Records shim 3's dispatch instead of touching a network.
struct RecordingProtocol final : cryptonote::i_cryptonote_protocol
{
  size_t calls = 0;
  std::vector<cryptonote::blobdata> txs;
  epee::net_utils::zone zone = epee::net_utils::zone::public_;
  cryptonote::relay_method method = cryptonote::relay_method::none;

  bool is_synchronized() const override { return true; }
  bool relay_block(NOTIFY_NEW_FLUFFY_BLOCK::request&, cryptonote_connection_context&) override
  {
    return true;
  }
  bool relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& arg, const boost::uuids::uuid&,
    epee::net_utils::zone z, cryptonote::relay_method m) override
  {
    ++calls;
    txs.assign(arg.txs.begin(), arg.txs.end());
    zone = z;
    method = m;
    return true;
  }
};

struct ShimFixture
{
  static constexpr uint64_t chain_height = 300;
  static constexpr uint64_t ref_height = chain_height - 50;

  SubmitTestDB* db;
  BlockchainAndPool bap;
  crypto::hash cert_ref;
  std::array<uint8_t, 32> cert_root;

  ShimFixture()
  {
    db = new SubmitTestDB(chain_height);
    EXPECT_TRUE(init_blockchain(bap.bc, db));
    EXPECT_GT(bap.bc.get_current_fee_per_byte(), 0u) << "fixture fee derivation broken";
    cert_ref = db->block_id_at(ref_height);
    cert_root = db->root_at(ref_height);
  }

  // fee_scale ≥ 1 clears the floor (with check_fee's 2% buffer); the F34
  // test passes an absolute fee instead.
  SubmitTx make_tx(uint8_t variant, uint8_t ki_variant, uint64_t fee_scale = 2)
  {
    SubmitTx s;
    s.tx = make_fcmp_shape_tx(variant, ki_variant);
    s.blob = cryptonote::tx_to_blob(s.tx);
    EXPECT_FALSE(s.blob.empty());
    s.txid = cryptonote::get_transaction_hash(s.tx);
    s.weight = s.blob.size();
    const uint64_t fee_per_byte = bap.bc.get_current_fee_per_byte();
    const uint64_t mask = Blockchain::get_fee_quantization_mask();
    const uint64_t needed = (s.weight * fee_per_byte + mask - 1) / mask * mask;
    s.fee = needed * fee_scale;
    EXPECT_TRUE(bap.bc.check_fee(s.weight, s.fee));
    return s;
  }

  int snapshot(const SubmitTx& s, shekyl_submit_facts_ffi& facts, uint8_t& ki_conflict)
  {
    const crypto::key_image& ki = std::get<txin_to_key>(s.tx.vin[0]).k_image;
    return daemon_submit::snapshot_facts(bap.txpool, bap.bc,
      reinterpret_cast<const uint8_t*>(s.txid.data),
      reinterpret_cast<const uint8_t*>(ki.data), 1,
      reinterpret_cast<const uint8_t*>(cert_ref.data),
      &facts, &ki_conflict);
  }

  int commit(const SubmitTx& s, shekyl_submit_facts_ffi& fresh, uint8_t& fresh_ki,
    const uint8_t* root_override = nullptr, const uint8_t* txid_override = nullptr,
    uint64_t fee_override = 0)
  {
    return daemon_submit::commit_tx(bap.txpool, bap.bc,
      reinterpret_cast<const uint8_t*>(s.blob.data()), s.blob.size(),
      txid_override ? txid_override : reinterpret_cast<const uint8_t*>(s.txid.data),
      s.weight, fee_override ? fee_override : s.fee,
      reinterpret_cast<const uint8_t*>(cert_ref.data), ref_height,
      root_override ? root_override : cert_root.data(),
      &fresh, &fresh_ki, 1);
  }
};

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// Shim 1: Phase-B fact snapshot
// ─────────────────────────────────────────────────────────────────────────

TEST(daemon_submit_shims, snapshot_fills_facts_for_clean_state)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi facts;
  uint8_t ki_conflict = 0xFF;
  ASSERT_EQ(fx.snapshot(s, facts, ki_conflict), SHEKYL_SUBMIT_OK);

  EXPECT_EQ(facts.in_pool, 0);
  EXPECT_EQ(facts.in_chain, 0);
  EXPECT_EQ(ki_conflict, SHEKYL_SUBMIT_KI_FREE);
  EXPECT_EQ(facts.ref_block_found, 1);
  EXPECT_EQ(facts.ref_height, ShimFixture::ref_height);
  EXPECT_EQ(0, memcmp(facts.root, fx.cert_root.data(), sizeof(facts.root)));
  EXPECT_EQ(facts.tree_depth, 20);
  EXPECT_GT(facts.fee_per_byte, 0u);
  EXPECT_GE(facts.fee_quantization_mask, 1u);
  EXPECT_GT(facts.weight_limit, 0u);
  EXPECT_EQ(facts.chain_height, ShimFixture::chain_height);
}

TEST(daemon_submit_shims, snapshot_unknown_reference_reports_not_found)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);
  fx.cert_ref = crypto::null_hash; // decodes to tagged_height 0 → unknown

  shekyl_submit_facts_ffi facts;
  uint8_t ki_conflict = 0;
  ASSERT_EQ(fx.snapshot(s, facts, ki_conflict), SHEKYL_SUBMIT_OK);
  EXPECT_EQ(facts.ref_block_found, 0);
}

TEST(daemon_submit_shims, snapshot_null_args_are_internal_fault)
{
  ShimFixture fx;
  shekyl_submit_facts_ffi facts;
  uint8_t ki_conflict = 0;
  EXPECT_EQ(daemon_submit::snapshot_facts(fx.bap.txpool, fx.bap.bc,
      nullptr, nullptr, 0, nullptr, &facts, &ki_conflict),
    SHEKYL_SUBMIT_INTERNAL_FAULT);
}

// F40 regression pin: a just-committed tx sits at relay_method::local
// (Dandelion++ embargo state, invisible to the `legacy` category). The
// presence fact queries at `all`, so the §5.3 status-query probe sees it.
TEST(daemon_submit_shims, snapshot_sees_embargoed_local_tx_in_pool)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  txpool_tx_meta_t meta;
  ASSERT_TRUE(fx.db->get_txpool_tx_meta(s.txid, meta));
  ASSERT_EQ(meta.get_relay_method(), relay_method::local);
  ASSERT_FALSE(meta.matches(relay_category::legacy))
    << "fixture must exercise the embargoed (legacy-invisible) state";

  shekyl_submit_facts_ffi facts;
  uint8_t ki_conflict = 0;
  ASSERT_EQ(fx.snapshot(s, facts, ki_conflict), SHEKYL_SUBMIT_OK);
  EXPECT_EQ(facts.in_pool, 1)
    << "presence fact must see local-state txs (relay_category::all, F40)";
}

// ─────────────────────────────────────────────────────────────────────────
// Shim 2: Phase-D check-and-commit
// ─────────────────────────────────────────────────────────────────────────

TEST(daemon_submit_shims, clean_commit_inserts_attested_pool_entry)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  ASSERT_TRUE(fx.db->txpool_has_tx(s.txid, relay_category::all));
  txpool_tx_meta_t meta;
  ASSERT_TRUE(fx.db->get_txpool_tx_meta(s.txid, meta));
  EXPECT_EQ(meta.get_relay_method(), relay_method::local);
  EXPECT_EQ(meta.weight, s.weight);
  EXPECT_EQ(meta.fee, s.fee);
  EXPECT_EQ(meta.max_used_block_height, ShimFixture::ref_height);
  EXPECT_EQ(meta.max_used_block_id, fx.cert_ref);
  EXPECT_EQ(meta.fcmp_verified, 1) << "attested insert must seed the verification cache";
  EXPECT_NE(meta.fcmp_verification_hash, crypto::null_hash);
  EXPECT_EQ(meta.last_relayed_time, std::numeric_limits<decltype(meta.last_relayed_time)>::max())
    << "committed tx must be immediately eligible for the relay nudge (§5.2 item 1)";
  EXPECT_EQ(meta.kept_by_block, 0);
  EXPECT_EQ(meta.do_not_relay, 0);
  EXPECT_EQ(fx.bap.txpool.get_txpool_weight(), s.weight);
}

TEST(daemon_submit_shims, commit_txid_divergence_is_internal_fault)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  crypto::hash wrong;
  memset(wrong.data, 0x99, sizeof(wrong.data));
  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  EXPECT_EQ(fx.commit(s, fresh, fresh_ki, nullptr,
      reinterpret_cast<const uint8_t*>(wrong.data)),
    SHEKYL_SUBMIT_INTERNAL_FAULT)
    << "§3.4 release-check: txid divergence is a daemon defect, never a verdict";
  EXPECT_FALSE(fx.db->txpool_has_tx(s.txid, relay_category::all));
}

TEST(daemon_submit_shims, commit_key_image_count_mismatch_is_internal_fault)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_kis[2] = {0, 0};
  EXPECT_EQ(daemon_submit::commit_tx(fx.bap.txpool, fx.bap.bc,
      reinterpret_cast<const uint8_t*>(s.blob.data()), s.blob.size(),
      reinterpret_cast<const uint8_t*>(s.txid.data),
      s.weight, s.fee,
      reinterpret_cast<const uint8_t*>(fx.cert_ref.data), ShimFixture::ref_height,
      fx.cert_root.data(), &fresh, fresh_kis, 2),
    SHEKYL_SUBMIT_INTERNAL_FAULT);
}

// §10 item 2, C++ latch leg: the deterministic interleaving the Rust race
// suite mocks, driven here through the real shims on real locks. The
// submitter thread snapshots clean facts, then parks on a latch while a
// competitor thread commits a different tx spending the same key image;
// the submitter's Phase-D commit must observe the moved premise and return
// RACED with fresh facts — classification stays on the Rust side.
TEST(daemon_submit_shims, latch_race_competing_spend_returns_raced_with_fresh_facts)
{
  ShimFixture fx;
  SubmitTx mine = fx.make_tx(0, 0);
  SubmitTx competitor = fx.make_tx(1, 0); // different tx, same key image

  ASSERT_NE(mine.txid, competitor.txid);

  std::promise<void> snapshot_taken;
  std::promise<void> competitor_committed;

  std::thread competitor_thread([&] {
    snapshot_taken.get_future().wait();
    shekyl_submit_facts_ffi fresh;
    uint8_t fresh_ki = 0;
    EXPECT_EQ(fx.commit(competitor, fresh, fresh_ki), SHEKYL_SUBMIT_OK);
    competitor_committed.set_value();
  });

  // Phase B: clean snapshot.
  shekyl_submit_facts_ffi facts;
  uint8_t ki_conflict = 0xFF;
  ASSERT_EQ(fx.snapshot(mine, facts, ki_conflict), SHEKYL_SUBMIT_OK);
  EXPECT_EQ(facts.in_pool, 0);
  EXPECT_EQ(ki_conflict, SHEKYL_SUBMIT_KI_FREE);

  // "Phase C": the competing spend lands while verification would run.
  snapshot_taken.set_value();
  competitor_committed.get_future().wait();

  // Phase D: the moved premise is observed under the commit lock scope.
  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0xFF;
  EXPECT_EQ(fx.commit(mine, fresh, fresh_ki), SHEKYL_SUBMIT_RACED);
  EXPECT_EQ(fresh.in_pool, 0) << "the competitor is a different txid";
  EXPECT_EQ(fresh.in_chain, 0);
  EXPECT_EQ(fresh_ki, SHEKYL_SUBMIT_KI_OTHER)
    << "fresh facts must carry the foreign key-image conflict for Rust to classify";
  EXPECT_FALSE(fx.db->txpool_has_tx(mine.txid, relay_category::all))
    << "a raced commit must not insert";
  EXPECT_TRUE(fx.db->txpool_has_tx(competitor.txid, relay_category::all));

  competitor_thread.join();
}

TEST(daemon_submit_shims, identity_race_reports_fresh_in_pool)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  // The same tx offered again: identity moved (in_pool), commit reports
  // RACED and Rust classifies AlreadyInPool.
  shekyl_submit_facts_ffi fresh2;
  uint8_t fresh_ki2 = 0;
  EXPECT_EQ(fx.commit(s, fresh2, fresh_ki2), SHEKYL_SUBMIT_RACED);
  EXPECT_EQ(fresh2.in_pool, 1);
}

TEST(daemon_submit_shims, reorg_race_reports_reference_gone)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  fx.db->set_fork_nonce(1); // reorg during Phase C: every historical id changes

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  EXPECT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_RACED);
  EXPECT_EQ(fresh.ref_block_found, 0);
  EXPECT_FALSE(fx.db->txpool_has_tx(s.txid, relay_category::all));
}

TEST(daemon_submit_shims, root_mismatch_against_certificate_reports_raced)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  std::array<uint8_t, 32> stale_root{};
  stale_root.fill(0x5A); // certificate anchored a root the chain no longer has

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  EXPECT_EQ(fx.commit(s, fresh, fresh_ki, stale_root.data()), SHEKYL_SUBMIT_RACED);
  EXPECT_EQ(fresh.ref_block_found, 1);
  EXPECT_EQ(0, memcmp(fresh.root, fx.cert_root.data(), sizeof(fresh.root)))
    << "fresh facts carry the chain's root, not the certificate's";
}

TEST(daemon_submit_shims, reference_aged_out_during_verification_reports_raced)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  // Chain advances past the max-age window while Phase C runs.
  fx.db->set_chain_height(ShimFixture::ref_height + FCMP_REFERENCE_BLOCK_MAX_AGE + 1);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  EXPECT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_RACED);
  EXPECT_EQ(fresh.ref_block_found, 1);
  EXPECT_EQ(fresh.chain_height, ShimFixture::ref_height + FCMP_REFERENCE_BLOCK_MAX_AGE + 1);
}

TEST(daemon_submit_shims, reference_too_recent_after_pop_reports_raced)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  // A chain pop during Phase C leaves the reference above the min-age
  // ceiling.
  fx.db->set_chain_height(ShimFixture::ref_height + FCMP_REFERENCE_BLOCK_MIN_AGE - 1);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  EXPECT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_RACED);
}

// F34: the fee floor moves during Phase C with the pool not full — the
// commit's check_fee re-gate against fresh params catches what the
// post-prune check cannot. Simulated by a fee below the (unchanged) floor,
// which is exactly what a floor-rise looks like to the re-gate.
TEST(daemon_submit_shims, fee_regate_below_fresh_floor_reports_raced)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  EXPECT_EQ(fx.commit(s, fresh, fresh_ki, nullptr, nullptr, /*fee_override=*/1),
    SHEKYL_SUBMIT_RACED);
  EXPECT_GT(fresh.fee_per_byte, 0u)
    << "fresh facts must carry the floor params for Rust's FeeTooLow arithmetic";
  EXPECT_FALSE(fx.db->txpool_has_tx(s.txid, relay_category::all));
}

// F23 / defect 0.7: the insert tail's prune() can evict the tx it just
// inserted; the membership re-check under the same lock scope reports it.
TEST(daemon_submit_shims, insert_evicted_by_prune_reports_pruned_on_insert)
{
  ShimFixture fx;
  SubmitTx filler = fx.make_tx(0, 0, /*fee_scale=*/20); // best fee/byte, never pruned
  SubmitTx target = fx.make_tx(1, 1, /*fee_scale=*/2);  // worst fee/byte, first out

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(filler, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  // Pool budget only fits the filler; the target's own insert overflows it.
  fx.bap.txpool.set_txpool_max_weight(filler.weight);

  EXPECT_EQ(fx.commit(target, fresh, fresh_ki), SHEKYL_SUBMIT_PRUNED_ON_INSERT);
  EXPECT_FALSE(fx.db->txpool_has_tx(target.txid, relay_category::all))
    << "the prune evicted the just-inserted tx; Accepted would be a lie";
  EXPECT_TRUE(fx.db->txpool_has_tx(filler.txid, relay_category::all));
}

// §10 item 2's regression pin: the legacy add_tx path's foreign-key-image
// behavior (`tvc.m_double_spend`), captured before PR-5 deletes the legacy
// RPC route. The pin outlives the deletion — the P2P ingestion path keeps
// add_tx (§9.4) — and documents the exact behavior the engine's
// DoubleSpendConflict classification replaces on the wallet-facing side.
TEST(daemon_submit_shims, legacy_add_tx_double_spend_pin)
{
  ShimFixture fx;
  SubmitTx competitor = fx.make_tx(1, 0);
  SubmitTx mine = fx.make_tx(0, 0); // different tx, same key image

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(competitor, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  tx_verification_context tvc{};
  // version == nic_verified_hf_version skips ver_non_input_consensus (the
  // shape tx carries no real proofs); the double-spend gate sits before
  // check_tx_inputs, so the reject under test fires first.
  EXPECT_FALSE(fx.bap.txpool.add_tx(mine.tx, tvc, relay_method::local,
    /*relayed=*/false, /*version=*/1, /*nic_verified_hf_version=*/1));
  EXPECT_TRUE(tvc.m_verifivation_failed);
  EXPECT_TRUE(tvc.m_double_spend)
    << "legacy path pins the foreign-key-image conflict on tvc.m_double_spend";
  EXPECT_FALSE(fx.db->txpool_has_tx(mine.txid, relay_category::all));
}

// ─────────────────────────────────────────────────────────────────────────
// §10 item 4: Dandelion++ embargo arming, pool-level
// ─────────────────────────────────────────────────────────────────────────

TEST(daemon_submit_shims, embargo_arms_future_deadline_and_expiry_routes_to_relay_loop)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  // Public-zone stem dispatch calls on_transactions_relayed(stem) before
  // the send (levin_notify.cpp:562); pool-level that is set_relayed(stem).
  const time_t before = time(nullptr);
  std::vector<bool> just_broadcasted;
  fx.bap.txpool.set_relayed(epee::span<const crypto::hash>(&s.txid, 1),
    relay_method::stem, just_broadcasted);

  ASSERT_EQ(just_broadcasted.size(), 1u);
  EXPECT_FALSE(just_broadcasted[0]) << "stem arming is not a broadcast";

  txpool_tx_meta_t meta;
  ASSERT_TRUE(fx.db->get_txpool_tx_meta(s.txid, meta));
  EXPECT_EQ(meta.get_relay_method(), relay_method::stem);
  EXPECT_EQ(meta.dandelionpp_stem, 1);
  EXPECT_GT(meta.last_relayed_time, static_cast<uint64_t>(before) - 1)
    << "the embargo deadline is a future last_relayed_time, not a past-relay stamp";

  // Force embargo expiry: the periodic loop must now offer the tx (the
  // core dispatch switch routes stem entries into the public fluff
  // request — cryptonote_core.cpp relay_txpool_transactions). Stamp a
  // realistically-expired embargo — received 100s ago, ~39s deadline
  // passed 61s ago — because get_relay_delay's backoff is keyed to
  // (deadline - receive_time) and rounds to zero if the deadline is
  // stamped before receipt.
  meta.receive_time = before - 100;
  meta.last_relayed_time = static_cast<uint64_t>(before) - 61;
  fx.db->update_txpool_tx(s.txid, meta);
  fx.bap.txpool.m_next_check = 0;

  std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> relayable;
  ASSERT_TRUE(fx.bap.txpool.get_relayable_transactions(relayable));
  ASSERT_EQ(relayable.size(), 1u);
  EXPECT_EQ(std::get<0>(relayable[0]), s.txid);
  EXPECT_EQ(std::get<1>(relayable[0]), s.blob);
  EXPECT_EQ(std::get<2>(relayable[0]), relay_method::stem)
    << "an expired stem entry rides the fluff request (origin-fluff path)";

  // The loop re-arms the deadline on each attempt.
  ASSERT_TRUE(fx.db->get_txpool_tx_meta(s.txid, meta));
  EXPECT_GT(meta.last_relayed_time, static_cast<uint64_t>(before))
    << "expired stem entries are re-armed, not left permanently eligible";
}

// ─────────────────────────────────────────────────────────────────────────
// Shim 3: relay nudge
// ─────────────────────────────────────────────────────────────────────────

TEST(daemon_submit_shims, relay_nudge_dispatches_local_pool_blob)
{
  ShimFixture fx;
  SubmitTx s = fx.make_tx(0, 0);

  shekyl_submit_facts_ffi fresh;
  uint8_t fresh_ki = 0;
  ASSERT_EQ(fx.commit(s, fresh, fresh_ki), SHEKYL_SUBMIT_OK);

  RecordingProtocol protocol;
  EXPECT_EQ(daemon_submit::relay_tx(fx.bap.txpool, protocol,
      reinterpret_cast<const uint8_t*>(s.txid.data)),
    SHEKYL_SUBMIT_OK);

  ASSERT_EQ(protocol.calls, 1u);
  ASSERT_EQ(protocol.txs.size(), 1u);
  EXPECT_EQ(protocol.txs[0], s.blob)
    << "the nudge must fetch the local-state blob (relay_category::all)";
  EXPECT_EQ(protocol.method, relay_method::local)
    << "local dispatch is the entry point that arms the D++ embargo";
  EXPECT_EQ(protocol.zone, epee::net_utils::zone::invalid);
}

TEST(daemon_submit_shims, relay_nudge_on_absent_tx_is_a_skipped_fault_without_dispatch)
{
  ShimFixture fx;
  crypto::hash absent;
  memset(absent.data, 0x77, sizeof(absent.data));

  RecordingProtocol protocol;
  EXPECT_EQ(daemon_submit::relay_tx(fx.bap.txpool, protocol,
      reinterpret_cast<const uint8_t*>(absent.data)),
    SHEKYL_SUBMIT_INTERNAL_FAULT)
    << "raced-away post-commit: the periodic loop owns whatever remains (§4.3)";
  EXPECT_EQ(protocol.calls, 0u);
}
