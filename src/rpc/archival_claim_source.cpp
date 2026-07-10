// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc/archival_claim_source.h"

#include <cstdint>

#include "blockchain_db/blockchain_db.h"
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{
namespace rpc
{

void fill_archival_emission_claim_source(const BlockchainDB& db,
    const crypto::hash& p_id,
    COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::response& res)
{
  using cmd = COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE;

  // `db.height()` is the block count = the next block's height — the
  // earliest height a claim assembled from this response can be included
  // at, so the settled-epoch operand matches the one the connect path
  // (`apply_archival_emission_claim`) will use at that earliest inclusion.
  // Same helper consensus uses; never a second derivation (§7.3 part A).
  const uint64_t chain_height = db.height();
  res.chain_height = chain_height;
  res.current_settled_epoch = shekyl_archival_settlement_epoch_at_height(chain_height);

  shekyl::db::ArchivalBondValue bond{};
  res.has_bond_record = db.get_archival_bond_value(p_id, bond);
  res.join_settlement_epoch = 0;
  res.holdings_kind = 0;
  res.held_shard_ids.clear();
  res.claimed_settlement_epochs.clear();
  if (res.has_bond_record)
  {
    res.join_settlement_epoch = bond.join_settlement_epoch;
    res.holdings_kind = bond.holdings_kind;
    res.held_shard_ids = bond.held_shard_ids;
    res.claimed_settlement_epochs = bond.claimed_settlement_epochs;
  }

  // Full window, unconditionally (§7.2): the low end resolves through the
  // one landed `claim_window_floor` definition (via its FFI delegate), the
  // high end is the `E < settled` rejection predicate's bound. No epoch is
  // filtered on claimability, bond state, or row presence — absent close
  // rows ride out as `has_budget_row = false` and the wallet treats them
  // as unclaimable, mirroring the verify shim's reject.
  const uint64_t settled = res.current_settled_epoch;
  const uint64_t floor = shekyl_archival_claim_window_floor(settled);
  res.epochs.clear();
  for (uint64_t epoch = floor; epoch < settled; ++epoch)
  {
    ArchivalEmissionEpochSnapshot snap;
    db.gather_archival_emission_epoch_snapshot(p_id, epoch, snap);

    cmd::epoch_snapshot_t out{};
    out.settlement_epoch = snap.settlement_epoch;
    out.close_block_height = snap.close_block_height;
    out.sigma_work_milli = snap.sigma_work_milli;
    out.budget_atomic = snap.budget_atomic;
    out.has_budget_row = snap.has_budget_row;
    out.bonds.reserve(snap.bonds.size());
    for (const auto& b : snap.bonds)
    {
      cmd::bond_row_t row{};
      row.join_settlement_epoch = b.join_settlement_epoch;
      row.is_foundation_complete_tree = b.is_foundation_complete_tree;
      row.bad_intervals_flat = b.bad_intervals_flat;
      out.bonds.push_back(std::move(row));
    }
    out.shards.reserve(snap.shards.size());
    for (const auto& s : snap.shards)
    {
      cmd::shard_row_t row{};
      row.shard_id = s.shard_id;
      row.freeze_height = s.freeze_height;
      row.has_segment = s.has_segment;
      out.shards.push_back(row);
    }
    out.credit_pairs.reserve(snap.credit_pairs.size());
    for (const auto& p : snap.credit_pairs)
    {
      cmd::credit_pair_t row{};
      row.bond_idx = static_cast<uint64_t>(p.bond_idx);
      row.shard_idx = static_cast<uint64_t>(p.shard_idx);
      out.credit_pairs.push_back(row);
    }
    // SIZE_MAX (landed sentinel) → UINT64_MAX on the wire → Option::None
    // at the Rust decode, exactly as the verify shim decodes it.
    out.claimant_bond_idx = snap.claimant_bond_idx == SIZE_MAX
        ? UINT64_MAX
        : static_cast<uint64_t>(snap.claimant_bond_idx);
    res.epochs.push_back(std::move(out));
  }
}

}  // namespace rpc
}  // namespace cryptonote
