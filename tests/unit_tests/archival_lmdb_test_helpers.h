// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Shared archival-LMDB test scaffolding: the temp-dir LMDB batch lifecycle
// and the emission-snapshot KAT chain shape. Single-sourced so the substrate
// KATs (archival_substrate_lmdb.cpp) and the claim-source RPC tests
// (archival_claim_source_rpc.cpp) drive the exact same fixture and cannot
// drift when the KAT arithmetic changes.

#pragma once

#include "cryptonote_basic/cryptonote_format_utils.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <vector>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/shekyl_types.h"
#include "shekyl/shekyl_ffi.h"

namespace archival_test {

// PC-D4: serve-credit rows are keyed by the block they rode in. These
// substrate tests are about the pair-epoch dimensions -- prefix scans, epoch
// ordering, the prune -- and not about which block issued a challenge, so they
// seed every row at one representative height. Each row stays unique per
// (P, shard, E) exactly as it was before the key widened, which is what keeps
// their assertions unchanged.
//
// A test that IS about the block dimension must use distinct heights and say
// so; sharing this constant there would silently collapse the rows it needs.
inline constexpr uint64_t kServeCreditTestBlockHeight = 1000;

/// Temp-dir LMDB with the batch write lifecycle open, templated so tests can
/// substitute a BlockchainLMDB subclass (e.g. a fake-tip height override).
template <typename DBT>
struct TempArchivalLMDB
{
  boost::filesystem::path tmpdir;
  DBT db;

  TempArchivalLMDB()
  {
    tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(tmpdir);
    db.open(tmpdir.string());
    db.set_batch_transactions(true);
    db.batch_start();
  }

  ~TempArchivalLMDB()
  {
    try {
      db.batch_stop();
      db.close();
      boost::filesystem::remove_all(tmpdir);
    } catch (...) {}
  }
};

using TempLMDB = TempArchivalLMDB<cryptonote::BlockchainLMDB>;

/// Append `count` minimal miner-only blocks (heights `height()` upward).
/// Each block carries a unique coinbase (txin_gen height) and no outputs, so
/// the curve-tree path is a no-op and the per-block cost is a handful of LMDB
/// puts — cheap enough to reach archival epoch heights (SEB = 10 000) in a
/// unit test. add_block runs the production connect hooks, including
/// process_archival_slash_at_height, which is the point: the slash KAT below
/// exercises the scheduler at its production call site, not via a test shim.
/// `accrual_per_block` rides into add_block as the redirected staker inflow
/// (F-B1a): the DB layer writes the accrual row before the epoch-close hook,
/// so the epoch-boundary KAT below can assert the close sums it.
inline void append_minimal_blocks(cryptonote::BlockchainDB& db, uint64_t count, uint64_t accrual_per_block = 0)
{
  crypto::hash prev = db.height() == 0
    ? crypto::null_hash : db.get_block_hash_from_height(db.height() - 1);
  for (uint64_t i = 0; i < count; ++i)
  {
    const uint64_t height = db.height();
    cryptonote::block blk{};
    blk.major_version = 1;
    blk.minor_version = 1;
    blk.timestamp = 1500000000 + height;
    blk.prev_id = prev;
    blk.curve_tree_root = crypto::null_hash;
    blk.nonce = 0;

    cryptonote::transaction miner_tx{};
    miner_tx.version = 1;
    miner_tx.unlock_time = height + 60;
    cryptonote::txin_gen gen{};
    gen.height = height;
    miner_tx.vin.push_back(gen);
    blk.miner_tx = std::move(miner_tx);

    db.add_block(std::make_pair(blk, cryptonote::block_to_blob(blk)), 100, 100,
      height + 1, 0, accrual_per_block, {}, {});
    prev = cryptonote::get_block_hash(blk);
  }
}

// Connect one block at the current tip carrying `txs` through the real
// add_block path (miner_tx + prev/height scaffolding that every bond-post /
// emission connect KAT below otherwise open-codes identically). Returns the
// connect height. Caller batch_stop/batch_start around it as needed.
inline uint64_t connect_block_with_txs(cryptonote::BlockchainDB& db, const std::vector<cryptonote::transaction>& txs,
  const cryptonote::blobdata& attestation_witness = {})
{
  const uint64_t connect_height = db.height();
  cryptonote::block blk{};
  blk.major_version = 1;
  blk.minor_version = 1;
  blk.timestamp = 1500000000 + connect_height;
  // Guard the genesis case like append_minimal_blocks: height 0 has no
  // predecessor to hash (connect_height - 1 would underflow).
  blk.prev_id = connect_height == 0
    ? crypto::null_hash : db.get_block_hash_from_height(connect_height - 1);
  blk.curve_tree_root = crypto::null_hash;
  blk.nonce = 0;
  cryptonote::transaction miner_tx{};
  miner_tx.version = 1;
  miner_tx.unlock_time = connect_height + 60;
  cryptonote::txin_gen gen{};
  gen.height = connect_height;
  miner_tx.vin.push_back(gen);
  blk.miner_tx = std::move(miner_tx);

  std::vector<std::pair<cryptonote::transaction, cryptonote::blobdata>> tx_blobs;
  tx_blobs.reserve(txs.size());
  for (const cryptonote::transaction& tx : txs)
  {
    blk.tx_hashes.push_back(cryptonote::get_transaction_hash(tx));
    tx_blobs.emplace_back(tx, cryptonote::tx_to_blob(tx));
  }

  db.add_block(std::make_pair(blk, cryptonote::block_to_blob(blk)), 100, 100,
    connect_height + 1, 0, 0, attestation_witness, tx_blobs);
  return connect_height;
}


inline crypto::hash make_hash(uint8_t fill)
{
  crypto::hash h{};
  memset(h.data, fill, sizeof(h.data));
  return h;
}

/// The emission-snapshot KAT chain shape (PF-8 arithmetic: work_p1 = 1250,
/// work_p2 = 2250, both curve-identity, sigma = 3500): p1 bonded holding
/// {7}, p2 bonded holding {7, 9}, p_no_credit bonded but never credited,
/// shard-7 segment plus the credit-less 1234, three credit bits in epoch 3,
/// closed at height 40000 with the close committed (batch cycled).
struct EmissionSnapshotKat
{
  static constexpr uint64_t kSeb = 10000;
  static constexpr uint64_t kSettlementEpoch = 3;
  static constexpr uint64_t kCloseHeight = (kSettlementEpoch + 1) * kSeb;
  static constexpr uint64_t kJoinEpoch = kSettlementEpoch - 1;

  crypto::hash p1 = make_hash(0x51);
  crypto::hash p2 = make_hash(0x52);
  crypto::hash p_no_credit = make_hash(0x53);
  std::vector<uint8_t> pubkey = {0x01};

  /// Seed the shape and run the epoch close, then commit it (batch cycle) so
  /// post-seed reads and writes ride a fresh write txn.
  void seed(cryptonote::BlockchainDB& db) const
  {
    db.put_archival_bond_record(p1, pubkey, {}, kJoinEpoch,
      2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
      shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
    db.put_archival_bond_record(p2, pubkey, {}, kJoinEpoch,
      2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
      shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7, 9}, {});
    // Bonded but never credited in E: claimant_bond_idx must come back as
    // the no-credit sentinel, zero work by construction.
    db.put_archival_bond_record(p_no_credit, pubkey, {}, kJoinEpoch,
      2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
      shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});

    db.put_archival_shard_segment(7, 100, make_hash(0x60), 26000);
    db.put_archival_shard_segment(1234, 100, make_hash(0x66), 26000);

    db.set_archival_serve_credit_bit(p1, 7, kSettlementEpoch, kServeCreditTestBlockHeight);
    db.set_archival_serve_credit_bit(p2, 7, kSettlementEpoch, kServeCreditTestBlockHeight);
    db.set_archival_serve_credit_bit(p2, 9, kSettlementEpoch, kServeCreditTestBlockHeight);

    db.process_archival_epoch_close_at_height(kCloseHeight);
    db.batch_stop();
    db.batch_start();
  }
};

}  // namespace archival_test
