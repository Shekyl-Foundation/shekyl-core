// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#include "curve_tree_path.h"

#include <algorithm>
#include <cstring>

#include "crypto/crypto-ops.h"
#include "fcmp/ct_ops.h"
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{

namespace
{
  constexpr size_t LEAF_BYTES = 128;
  constexpr uint32_t SCALARS_PER_LEAF = 4;

  void push_u16_le(std::vector<uint8_t>& v, uint16_t x)
  {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
  }

  bool read_leaf(const BlockchainDB& db, uint64_t pos, uint8_t* leaf, std::string& error)
  {
    if (db.get_curve_tree_leaf_by_tree_position(pos, leaf))
      return true;
    error = "Failed to read leaf at tree position " + std::to_string(pos);
    return false;
  }

  bool read_layer_hash(const BlockchainDB& db, uint8_t layer, uint64_t chunk, uint8_t* hash, std::string& error)
  {
    if (db.get_curve_tree_layer_hash(layer, chunk, hash))
      return true;
    error = "Internal error: missing layer hash at layer " + std::to_string(layer)
      + " chunk " + std::to_string(chunk);
    return false;
  }
}

bool assemble_curve_tree_path(
    const BlockchainDB& db,
    uint64_t output_idx,
    uint64_t ref_leaf_count,
    uint64_t tip_leaf_count,
    curve_tree_path_bytes& out,
    std::string& error)
{
  const uint8_t depth = db.get_curve_tree_depth();
  const uint32_t selene_cw = shekyl_curve_tree_selene_chunk_width();
  const uint32_t helios_cw = shekyl_curve_tree_helios_chunk_width();
  const auto chunk_width = [&](uint8_t layer) -> uint32_t {
    if (layer == 0) return selene_cw;
    return (layer % 2 == 0) ? selene_cw : helios_cw;
  };

  out.path.clear();
  out.chunk_outputs.clear();

  // Layer 0: the leaf chunk, bounded by the reference leaf count.
  const uint64_t chunk_idx = output_idx / selene_cw;
  const uint64_t chunk_start = chunk_idx * selene_cw;
  const uint64_t chunk_end = std::min(chunk_start + static_cast<uint64_t>(selene_cw), ref_leaf_count);

  push_u16_le(out.path, static_cast<uint16_t>(output_idx - chunk_start));

  for (uint64_t i = chunk_start; i < chunk_end; ++i)
  {
    uint8_t leaf[LEAF_BYTES];
    if (!read_leaf(db, i, leaf, error))
      return false;
    out.path.insert(out.path.end(), leaf, leaf + LEAF_BYTES);

    const output_data_t od = db.get_output_key(0, i);
    out.chunk_outputs.insert(out.chunk_outputs.end(),
        reinterpret_cast<const uint8_t*>(od.pubkey.data),
        reinterpret_cast<const uint8_t*>(od.pubkey.data) + 32);

    ge_p3 hp;
    ct::key od_rct;
    memcpy(od_rct.bytes, od.pubkey.data, 32);
    ct::hash_to_p3(hp, od_rct);
    uint8_t ki_gen[32];
    ge_p3_tobytes(ki_gen, &hp);
    out.chunk_outputs.insert(out.chunk_outputs.end(), ki_gen, ki_gen + 32);

    out.chunk_outputs.insert(out.chunk_outputs.end(),
        reinterpret_cast<const uint8_t*>(od.commitment.bytes),
        reinterpret_cast<const uint8_t*>(od.commitment.bytes) + 32);

    out.chunk_outputs.insert(out.chunk_outputs.end(), leaf + 96, leaf + LEAF_BYTES);
  }

  // Layers 1..depth: sibling hashes, with boundary-chunk trimming. The loop
  // emits exactly `depth` branch layers, the count the wallet's path parser
  // and the FCMP++ signer expect.
  uint64_t ref_nodes_at_prev_layer = ref_leaf_count;
  uint64_t cur_nodes_at_prev_layer = tip_leaf_count;
  uint64_t child_chunk = chunk_idx;

  for (uint8_t layer = 1; layer <= depth; ++layer)
  {
    const uint32_t prev_cw = chunk_width(layer - 1);
    const uint32_t cw = chunk_width(layer);

    const uint64_t ref_chunks_below = (ref_nodes_at_prev_layer + prev_cw - 1) / prev_cw;
    const uint64_t cur_chunks_below = (cur_nodes_at_prev_layer + prev_cw - 1) / prev_cw;
    const uint64_t last_ref_chunk_below = (ref_chunks_below > 0) ? ref_chunks_below - 1 : 0;

    const uint64_t parent_chunk = child_chunk / cw;
    const uint64_t sib_start = parent_chunk * cw;
    push_u16_le(out.path, static_cast<uint16_t>(child_chunk - sib_start));

    for (uint32_t c = 0; c < cw; ++c)
    {
      const uint64_t sibling_chunk = sib_start + c;
      uint8_t hash[32] = {};

      if (sibling_chunk < ref_chunks_below)
      {
        if (!read_layer_hash(db, layer - 1, sibling_chunk, hash, error))
          return false;

        // The boundary chunk grew after the reference height: trim it back to
        // the hash it had with only the reference-state entries.
        if (sibling_chunk == last_ref_chunk_below &&
            ref_nodes_at_prev_layer != cur_nodes_at_prev_layer &&
            ref_nodes_at_prev_layer % prev_cw != 0)
        {
          const uint64_t ref_in_chunk = ref_nodes_at_prev_layer - sibling_chunk * prev_cw;
          const uint64_t cur_in_chunk = std::min(
              cur_nodes_at_prev_layer - sibling_chunk * prev_cw,
              static_cast<uint64_t>(prev_cw));

          if (cur_in_chunk > ref_in_chunk)
          {
            const uint64_t scalars_per_entry = (layer == 1) ? SCALARS_PER_LEAF : 1;
            const uint64_t trim_offset = ref_in_chunk * scalars_per_entry;
            const uint64_t num_extra_scalars = (cur_in_chunk - ref_in_chunk) * scalars_per_entry;

            std::vector<uint8_t> extra_data;
            for (uint64_t li = sibling_chunk * prev_cw + ref_in_chunk;
                 li < sibling_chunk * prev_cw + cur_in_chunk; ++li)
            {
              if (layer == 1)
              {
                uint8_t lf[LEAF_BYTES];
                if (!read_leaf(db, li, lf, error))
                  return false;
                extra_data.insert(extra_data.end(), lf, lf + LEAF_BYTES);
              }
              else
              {
                uint8_t h[32] = {};
                if (!read_layer_hash(db, layer - 2, li, h, error))
                  return false;
                extra_data.insert(extra_data.end(), h, h + 32);
              }
            }

            const uint8_t zero_scalar[32] = {};
            uint8_t trimmed[32];
            const bool is_selene = (layer - 1) % 2 == 0;
            const bool ok = is_selene
              ? shekyl_curve_tree_hash_trim_selene(hash, trim_offset, extra_data.data(),
                                                   num_extra_scalars, zero_scalar, trimmed)
              : shekyl_curve_tree_hash_trim_helios(hash, trim_offset, extra_data.data(),
                                                   num_extra_scalars, zero_scalar, trimmed);
            if (!ok)
            {
              // Same class as a missing read: the untrimmed hash is a valid
              // point that is simply not this chunk's reference-state hash.
              error = "Internal error: boundary-chunk trim failed at layer "
                + std::to_string(layer - 1) + " chunk " + std::to_string(sibling_chunk);
              return false;
            }
            memcpy(hash, trimmed, 32);
          }
        }
      }
      out.path.insert(out.path.end(), hash, hash + 32);
    }

    ref_nodes_at_prev_layer = ref_chunks_below;
    cur_nodes_at_prev_layer = cur_chunks_below;
    child_chunk = parent_chunk;
  }

  return true;
}

} // namespace cryptonote
