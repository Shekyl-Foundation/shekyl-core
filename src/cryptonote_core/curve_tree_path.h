// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// C++ store-callback shim over `shekyl_assemble_curve_tree_path`. The
// membership-path byte layout, boundary-chunk trim, and fail-closed
// contract live in `shekyl-fcmp::rpc_path`.

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
  std::vector<uint8_t> path;
  /// Per leaf in the layer-0 chunk: `O(32) ‖ I(32) ‖ C(32) ‖ CM.x(32)` (the
  /// leaf's 4th scalar: the x-coordinate of its PQC leaf commitment, PL-D3).
  std::vector<uint8_t> chunk_outputs;
};

/// Assemble the membership path for the leaf at tree position `output_idx`
/// against the tree as it stood with `ref_leaf_count` leaves, reading a store
/// that currently holds `tip_leaf_count` leaves.
///
/// `depth` is the caller's snapshot — the same value published as
/// `tree_depth`. The assembler does not re-read depth from the store.
///
/// Precondition (caller-checked): `output_idx < ref_leaf_count <= tip_leaf_count`
/// and the tree is non-empty.
///
/// Fails closed (PDM-Q-F9): every store read — a leaf, a layer hash, an
/// output key, or the boundary-chunk trim — either succeeds or the call
/// returns `false` with `error` naming the position.
bool assemble_curve_tree_path(
    const BlockchainDB& db,
    uint64_t output_idx,
    uint64_t ref_leaf_count,
    uint64_t tip_leaf_count,
    uint8_t depth,
    curve_tree_path_bytes& out,
    std::string& error);

} // namespace cryptonote
