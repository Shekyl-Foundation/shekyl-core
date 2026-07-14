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

#include <boost/filesystem.hpp>
#include <cstring>
#include <vector>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/shekyl_types.h"
#include "shekyl/shekyl_ffi.h"

namespace archival_test {

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

    db.set_archival_serve_credit_bit(p1, 7, kSettlementEpoch);
    db.set_archival_serve_credit_bit(p2, 7, kSettlementEpoch);
    db.set_archival_serve_credit_bit(p2, 9, kSettlementEpoch);

    db.process_archival_epoch_close_at_height(kCloseHeight);
    db.batch_stop();
    db.batch_start();
  }
};

}  // namespace archival_test
