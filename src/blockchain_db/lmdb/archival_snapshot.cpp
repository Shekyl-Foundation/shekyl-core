// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// DRS-E4 archival snapshot walker (`DRS_E4_ARCHIVAL_WRITER.md` §3.8.1,
// ARW-25). The C++ reading of the archival state the digest excludes
// (`LMDB_WRITE_ATOMICITY_AUDIT.md` §7.1.1), handed to Rust as DECODED FIELDS:
// this file opens one cursor per archival family, decodes each key from its
// big-endian layout and each value through the codec that wrote it, and calls
// the matching `shekyl_e2_archival_snapshot_push_*`. The row encodings, the
// family order, the `r = 0` projection and the duplicate/singleton refusals
// are Rust's (ARW-Q10 (a)); nothing here writes a byte of the record.
//
// The one arithmetic performed is the open epoch's accruing total — the LMDB
// keeps `archival_budget_accrual[h]` per height and the redb store one
// accumulator row — summed with the same checked addition the C++ close
// uses. Rule 20 holds this file to a marshal: if it grows a second sum, stop.
//
// HARVEST SHIM: deleted with the exporter and the daemon (E2 §1.3).

#include "db_lmdb.h"

#include "blockchain_db/shekyl_types.h"
#include "shekyl/shekyl_ffi.h"

#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace cryptonote {

namespace {

// Frees an unconsumed builder on every exit that is not the return.
struct SnapshotBuilder
{
  ShekylE2ArchivalSnapshot* handle;
  explicit SnapshotBuilder(ShekylE2ArchivalSnapshot* h) : handle(h) {}
  ~SnapshotBuilder() { shekyl_e2_archival_snapshot_free(handle); }
  ShekylE2ArchivalSnapshot* release() noexcept
  {
    ShekylE2ArchivalSnapshot* h = handle;
    handle = nullptr;
    return h;
  }
};

struct Cursor
{
  MDB_cursor* cur = nullptr;
  Cursor(MDB_txn* txn, MDB_dbi dbi, const char* family)
  {
    const int rc = mdb_cursor_open(txn, dbi, &cur);
    if (rc)
      throw DB_ERROR((std::string("archival_snapshot_rows: open ") + family + " cursor: "
        + mdb_strerror(rc)).c_str());
  }
  ~Cursor() { if (cur) mdb_cursor_close(cur); }
};

void require(int32_t rc, const char* family)
{
  if (rc != SHEKYL_E2_TRACE_OK)
    throw DB_ERROR((std::string("archival_snapshot_rows: the snapshot refused an ") + family
      + " row (rc " + std::to_string(rc) + ")").c_str());
}

void require_key(const MDB_val& k, size_t expected, const char* family)
{
  if (k.mv_size != expected)
    throw DB_ERROR((std::string("archival_snapshot_rows: ") + family + " key is "
      + std::to_string(k.mv_size) + " bytes, expected " + std::to_string(expected)).c_str());
}

uint64_t be64_value(const MDB_val& v, const char* family)
{
  if (v.mv_size != 8)
    throw DB_ERROR((std::string("archival_snapshot_rows: ") + family + " value is "
      + std::to_string(v.mv_size) + " bytes, expected 8").c_str());
  return shekyl::db::load_be64(static_cast<const uint8_t*>(v.mv_data));
}

const uint8_t* bytes(const MDB_val& v) { return static_cast<const uint8_t*>(v.mv_data); }

// Walk every row of `dbi`, in key order, through `row(key, value)`.
template <typename F>
void for_each(MDB_txn* txn, MDB_dbi dbi, const char* family, F row)
{
  Cursor c(txn, dbi, family);
  MDB_val k, v;
  int rc = mdb_cursor_get(c.cur, &k, &v, MDB_FIRST);
  while (rc == 0)
  {
    row(k, v);
    rc = mdb_cursor_get(c.cur, &k, &v, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND)
    throw DB_ERROR((std::string("archival_snapshot_rows: walk ") + family + ": "
      + mdb_strerror(rc)).c_str());
}

} // namespace

ShekylE2ArchivalSnapshot* BlockchainLMDB::archival_snapshot_rows() const
{
  // No check_open() here: it is an inline defined only in db_lmdb.cpp (the
  // digest walker's note). height() checks it, and runs first.
  //
  // One LMDB snapshot for all ten families, nested inside the caller's read
  // transaction (the exporter's db_rtxn_guard) or the batch write
  // transaction (the unit fixture) when one is open — the same pattern as
  // logical_state_digest_v0, so the two encodings of one checkpoint are read
  // from one state.
  MDB_txn* txn = nullptr;
  mdb_txn_cursors* cursors = nullptr;
  const bool mine_rtxn = block_rtxn_start(&txn, &cursors);
  struct rtxn_stop {
    const BlockchainLMDB* db;
    bool mine;
    ~rtxn_stop() { if (mine) db->block_rtxn_stop(); }
  } const snapshot{this, mine_rtxn};

  const uint64_t n_blocks = height();

  SnapshotBuilder out(shekyl_e2_archival_snapshot_new());
  if (!out.handle)
    throw DB_ERROR("archival_snapshot_rows: the Rust builder could not be allocated");

  // bond: P_id[32] -> ArchivalBondValue (v7).
  for_each(txn, m_archival_bond, "archival_bond", [&](const MDB_val& k, const MDB_val& v) {
    require_key(k, shekyl::db::kArchivalBondKeySize, "archival_bond");
    shekyl::db::ArchivalBondValue bond{};
    if (!shekyl::db::ArchivalBondValue::decode(v.mv_data, v.mv_size, bond))
      throw DB_ERROR("archival_snapshot_rows: archival_bond value does not decode");
    if (bond.held_shard_ids.size() != bond.shard_add_epochs.size())
      throw DB_ERROR("archival_snapshot_rows: archival_bond holdings arrays differ in length");
    // The interval log flattened to (start, end_exclusive) pairs.
    std::vector<uint64_t> intervals;
    intervals.reserve(bond.bad_intervals.size() * 2);
    for (const auto& iv : bond.bad_intervals)
    {
      intervals.push_back(iv.start_epoch);
      intervals.push_back(iv.end_exclusive);
    }
    require(shekyl_e2_archival_snapshot_push_bond(
      out.handle,
      bytes(k),
      bond.hybrid_pubkey.data(), bond.hybrid_pubkey.size(),
      bond.bond_spend_pk.data(), bond.bond_spend_pk.size(),
      bond.endpoint.data(),
      bond.join_settlement_epoch,
      bond.bonded_total_atomic,
      bond.holdings_kind,
      bond.held_shard_ids.data(), bond.shard_add_epochs.data(), bond.held_shard_ids.size(),
      intervals.data(), bond.bad_intervals.size(),
      bond.claimed_settlement_epochs.data(), bond.claimed_settlement_epochs.size(),
      bond.first_paying_emission_height), "archival_bond");
  });

  // serve_credit: P_id[32] || BE(shard) || BE(E) || BE(height) -> 0x01.
  for_each(txn, m_archival_serve_credit, "archival_serve_credit",
    [&](const MDB_val& k, const MDB_val&) {
      require_key(k, shekyl::db::kArchivalServeCreditKeySize, "archival_serve_credit");
      const uint8_t* key = bytes(k);
      require(shekyl_e2_archival_snapshot_push_serve_credit(
        out.handle, key,
        shekyl::db::load_be64(key + 32),
        shekyl::db::load_be64(key + 40),
        shekyl::db::load_be64(key + 48)), "archival_serve_credit");
    });

  // r_market: BE(shard) || BE(E) -> BE(count). Zero rows are handed over;
  // the projection to absence is Rust's (§3.6).
  for_each(txn, m_archival_r_market, "archival_r_market",
    [&](const MDB_val& k, const MDB_val& v) {
      require_key(k, shekyl::db::kArchivalRMarketKeySize, "archival_r_market");
      const uint8_t* key = bytes(k);
      require(shekyl_e2_archival_snapshot_push_r_market(
        out.handle,
        shekyl::db::load_be64(key),
        shekyl::db::load_be64(key + 8),
        be64_value(v, "archival_r_market")), "archival_r_market");
    });

  // sigma_work: BE(E) -> BE(sigma_milli).
  for_each(txn, m_archival_sigma_work, "archival_sigma_work",
    [&](const MDB_val& k, const MDB_val& v) {
      require_key(k, shekyl::db::kArchivalSigmaWorkKeySize, "archival_sigma_work");
      require(shekyl_e2_archival_snapshot_push_sigma_work(
        out.handle, shekyl::db::load_be64(bytes(k)),
        be64_value(v, "archival_sigma_work")), "archival_sigma_work");
    });

  // budget: BE(E) -> BE(budget), the frozen row the close writes.
  for_each(txn, m_archival_budget, "archival_budget",
    [&](const MDB_val& k, const MDB_val& v) {
      require_key(k, shekyl::db::kArchivalBudgetKeySize, "archival_budget");
      require(shekyl_e2_archival_snapshot_push_budget(
        out.handle, shekyl::db::load_be64(bytes(k)),
        be64_value(v, "archival_budget")), "archival_budget");
    });

  // attestation_witness: native u64 height (MDB_INTEGERKEY) -> blob. An
  // empty blob is the row's absence on both sides.
  for_each(txn, m_archival_attestation_witness, "archival_attestation_witness",
    [&](const MDB_val& k, const MDB_val& v) {
      require_key(k, sizeof(uint64_t), "archival_attestation_witness");
      uint64_t h = 0;
      std::memcpy(&h, k.mv_data, sizeof(h));
      if (v.mv_size == 0)
        return;
      require(shekyl_e2_archival_snapshot_push_attestation_witness(
        out.handle, h, bytes(v), v.mv_size), "archival_attestation_witness");
    });

  // slash_log: BE(height) || BE32(seq) -> ArchivalSlashRevertValue (v3). The
  // epoch-marker row (seq 0xFFFFFFFF) is pop-revert bookkeeping, not a
  // slash; it is skipped here and refused by Rust if handed over.
  for_each(txn, m_archival_slash_log, "archival_slash_log",
    [&](const MDB_val& k, const MDB_val& v) {
      require_key(k, shekyl::db::kArchivalSlashLogKeySize, "archival_slash_log");
      const uint8_t* key = bytes(k);
      const uint64_t h = shekyl::db::load_be64(key);
      const uint32_t seq = shekyl::db::load_be32(key + 8);
      if (seq == shekyl::db::kArchivalSlashLogEpochMarkerSeq)
        return;
      shekyl::db::ArchivalSlashRevertValue entry{};
      if (!shekyl::db::ArchivalSlashRevertValue::decode(v.mv_data, v.mv_size, entry))
        throw DB_ERROR("archival_snapshot_rows: archival_slash_log value does not decode");
      if (entry.is_epoch_marker())
        throw DB_ERROR("archival_snapshot_rows: archival_slash_log carries a marker-shaped "
          "entry under a non-marker seq");
      require(shekyl_e2_archival_snapshot_push_slash_log(
        out.handle, h, seq, entry.p_id, entry.shard_id, entry.settlement_epoch,
        entry.holdings_pre_kind, entry.slashed_shard_add_epoch), "archival_slash_log");
    });

  // slash_applied: P_id[32] || BE(shard) || BE(E) -> present.
  for_each(txn, m_archival_slash_applied, "archival_slash_applied",
    [&](const MDB_val& k, const MDB_val&) {
      require_key(k, shekyl::db::kArchivalPairEpochKeySize, "archival_slash_applied");
      const uint8_t* key = bytes(k);
      require(shekyl_e2_archival_snapshot_push_slash_applied(
        out.handle, key,
        shekyl::db::load_be64(key + 32),
        shekyl::db::load_be64(key + 40)), "archival_slash_applied");
    });

  // budget_accruing: the redb writer upserts `archival_budget_accruing[E]`
  // on every connect inside E and removes it in the connect that closes E
  // (archival_write.rs phase 9a, SI-23). So the row is present iff the tip
  // did not close its epoch, and its value is the checked sum of the
  // per-height accrual rows over [E·SEB, tip] — the C++ writes no row for a
  // zero inflow, so the sum of none is a row of zero, not an absence.
  if (n_blocks > 0)
  {
    const uint64_t tip = n_blocks - 1;
    const uint64_t seb = shekyl_archival_settlement_epoch_blocks();
    const bool tip_closes = (tip + 1) % seb == 0;
    if (!tip_closes)
    {
      const uint64_t epoch = tip / seb;
      const uint64_t open = epoch * seb;
      uint64_t total = 0;
      {
        Cursor c(txn, m_archival_budget_accrual, "archival_budget_accrual");
        shekyl::db::ArchivalBudgetAccrualKey from(open);
        MDB_val k = from.as_mdb_val();
        MDB_val v;
        int rc = mdb_cursor_get(c.cur, &k, &v, MDB_SET_RANGE);
        while (rc == 0)
        {
          require_key(k, shekyl::db::kArchivalBudgetAccrualKeySize, "archival_budget_accrual");
          const uint64_t h = shekyl::db::load_be64(bytes(k));
          if (h > tip)
            break;
          const uint64_t inflow = be64_value(v, "archival_budget_accrual");
          if (inflow > std::numeric_limits<uint64_t>::max() - total)
            throw DB_ERROR("archival_snapshot_rows: the open epoch's accrual sum overflows u64");
          total += inflow;
          rc = mdb_cursor_get(c.cur, &k, &v, MDB_NEXT);
        }
        if (rc != 0 && rc != MDB_NOTFOUND)
          throw DB_ERROR((std::string("archival_snapshot_rows: walk archival_budget_accrual: ")
            + mdb_strerror(rc)).c_str());
      }
      require(shekyl_e2_archival_snapshot_set_budget_accruing(out.handle, epoch, total),
        "archival_budget_accruing");
    }
  }

  // last_slash_epoch: the m_properties watermark; unset reads as UINT64_MAX
  // and is the row's absence.
  {
    const uint64_t watermark = get_archival_last_slash_epoch();
    if (watermark != std::numeric_limits<uint64_t>::max())
      require(shekyl_e2_archival_snapshot_set_last_slash_epoch(out.handle, watermark),
        "archival_last_slash_epoch");
  }

  return out.release();
}

} // namespace cryptonote
