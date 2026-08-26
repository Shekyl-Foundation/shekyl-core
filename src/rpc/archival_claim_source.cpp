// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc/archival_claim_source.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

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

  // Bond-less part A stays zeroed by the fresh-response contract (see the
  // header doc): both transports dispatch value-initialized (struct_init)
  // responses, so no per-field reset ladder exists to fall out of sync with
  // the response struct.
  shekyl::db::ArchivalBondValue bond{};
  res.has_bond_record = db.get_archival_bond_value(p_id, bond);
  if (res.has_bond_record)
  {
    res.join_settlement_epoch = bond.join_settlement_epoch;
    res.holdings_kind = bond.holdings_kind;
    res.held_shard_ids = bond.held_shard_ids;
    res.claimed_settlement_epochs = bond.claimed_settlement_epochs;
    res.bonded_total_atomic = bond.bonded_total_atomic;

    // The `Unbond` cooldown anchor, gathered EXACTLY as the Unbond verify arm
    // gathers it -- `blockchain.cpp`'s `shekyl_archival_verify_unbond_bond_post`
    // call site, which carries the twin of this comment. THE TWO GATHERS MUST
    // MOVE TOGETHER: this one only tells the wallet whether an exit can verify,
    // so if they diverge the wallet reports readiness the chain then refuses --
    // or, worse, reports "never served" for a record kind the verify arm knows
    // has served, which is the permissive branch of both cooldown predicates.
    // Nothing but these two comments couples them; a new record kind added to
    // one is a silent divergence in the other (gate-4 §3.5): the record's held shards for
    // a compact set, the all-shards P-prefix scan for a complete-tree record
    // (which stores no shard list, so folding its empty list would report
    // "never served" for a record that has). Never-served shards are omitted
    // by both accessors, so an empty result is the legitimate
    // "record exists, nothing served yet" case.
    //
    // The fold to the whole-record anchor stays Rust-side, through the same
    // function consensus uses. A C++ max() here would be a second derivation of
    // a consensus operand and could drift from the verifier that decides the
    // tx — the failure `close_block_height` is already shaped to prevent.
    const std::vector<uint64_t> last_served = bond.is_complete_tree()
      ? db.archival_bond_all_last_served_epochs(p_id)
      : db.archival_bond_last_served_epochs(p_id, bond.held_shard_ids);
    uint8_t anchor_present = 0;
    uint64_t anchor_epoch = 0;
    // A non-OK return is a marshaling bug on THIS side (null pointer with a
    // positive length, or a length past the slice-soundness bound), never a
    // property of the record — so there is no anchor to report and no honest
    // way to describe this record's exit state.
    //
    // Throwing is the fail-closed choice, and the alternative is worse than it
    // looks: leaving the fields at their value-initialized defaults reports
    // `has_last_served_epoch = false`, which the wallet decodes as
    // `NeverServed` — the PERMISSIVE branch of both cooldown predicates. A
    // record that has served would then read as ready to exit, on an operand
    // this function failed to compute. (An earlier revision of this comment
    // called that default "the fail-closed reading". It is the opposite, and
    // the mistake is worth leaving recorded: on this operand, absence means
    // permissive.)
    //
    // The handler wraps this call in try/catch and answers a non-OK status,
    // which the wallet's decoder rejects before reading any payload field — so
    // an internal error cannot decode as a claim about the record.
    const uint8_t fold_rc = shekyl_archival_whole_record_last_served(
      last_served.empty() ? nullptr : last_served.data(),
      last_served.size(),
      &anchor_present,
      &anchor_epoch);
    if (fold_rc != SHEKYL_ARCHIVAL_BOND_POST_OK)
      throw std::runtime_error(
        "whole-record last-served fold failed (rc=" + std::to_string(fold_rc) + ")");
    res.has_last_served_epoch = anchor_present != 0;
    res.last_served_epoch = anchor_epoch;

    // The scheduler's watermark, with the storage sentinel resolved here so no
    // consumer has to carry it. Unlike the anchor above, absence on THIS
    // operand is fail-closed at consensus (`slashes_settled_through`), so the
    // two flags are not interchangeable.
    const uint64_t slash_watermark = db.get_archival_last_slash_epoch();
    res.has_last_settled_slash_epoch = slash_watermark != UINT64_MAX;
    if (res.has_last_settled_slash_epoch)
      res.last_settled_slash_epoch = slash_watermark;
  }

  // Full window, unconditionally (§7.2): the low end resolves through the
  // one landed `claim_window_floor` definition (via its FFI delegate), the
  // high end is the `E < settled` rejection predicate's bound. No epoch is
  // filtered on claimability, bond state, or row presence — absent close
  // rows ride out as `has_budget_row = false` and the wallet treats them
  // as unclaimable, mirroring the verify shim's reject. The windowed gather
  // collects every epoch's rows in ONE serve-credit table pass — the
  // per-request work bound for this unauthenticated RPC.
  const uint64_t settled = res.current_settled_epoch;
  const uint64_t floor = shekyl_archival_claim_window_floor(settled);
  std::vector<ArchivalEmissionEpochSnapshot> snaps;
  db.gather_archival_emission_window_snapshots(p_id, floor, settled, snaps);
  res.epochs.reserve(snaps.size());
  for (const ArchivalEmissionEpochSnapshot& snap : snaps)
  {
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
