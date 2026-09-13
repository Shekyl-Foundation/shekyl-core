// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Curve-tree membership-path assembly for the FCMP++ prover, read from the
// consensus store. Pure over `BlockchainDB`: no core, no RPC, so the
// fail-closed contract is unit-testable against a stub store.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"

namespace cryptonote
{

/// The two byte strings `get_curve_tree_path` returns per output.
struct curve_tree_path_bytes
{
  /// `[leaf_pos u16 LE][leaf 128 B]*` for the layer-0 chunk, then per layer
  /// `1..depth`: `[pos_in_parent u16 LE][sibling hash 32 B]*chunk_width`.
  /// Sibling slots at or beyond the reference tree's node count are zero (the
  /// prover's padding); a boundary chunk that grew after the reference height
  /// is trimmed back to its reference-state hash.
  std::vector<uint8_t> path;
  /// Per leaf in the layer-0 chunk: `O(32) ‖ I(32) ‖ C(32) ‖ h_pqc(32)`.
  std::vector<uint8_t> chunk_outputs;
};

/// Assemble the membership path for the leaf at tree position `output_idx`
/// against the tree as it stood with `ref_leaf_count` leaves, reading a store
/// that currently holds `tip_leaf_count` leaves.
///
/// Precondition (caller-checked): `output_idx < ref_leaf_count <= tip_leaf_count`
/// and the tree is non-empty.
///
/// Fails closed (PDM-Q-F9): every store read this needs — a leaf, a layer hash,
/// or the boundary-chunk trim — either succeeds or the call returns `false`
/// with `error` naming the position. Nothing is ever substituted: a zero leaf or
/// an untrimmed hash yields a wrong-but-well-formed sibling, and the client's
/// verification against `R_k` then fails with nothing pointing at the store.
bool assemble_curve_tree_path(
    const BlockchainDB& db,
    uint64_t output_idx,
    uint64_t ref_leaf_count,
    uint64_t tip_leaf_count,
    curve_tree_path_bytes& out,
    std::string& error);

} // namespace cryptonote
