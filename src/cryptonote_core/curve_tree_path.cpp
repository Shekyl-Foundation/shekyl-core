// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#include "curve_tree_path.h"

#include <cstring>
#include <exception>

#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{

namespace
{
  struct StoreCtx
  {
    const BlockchainDB* db;
  };

  bool read_leaf(void* ctx, uint64_t pos, uint8_t leaf_out[128])
  {
    return static_cast<StoreCtx*>(ctx)->db->get_curve_tree_leaf_by_tree_position(pos, leaf_out);
  }

  bool read_layer_hash(void* ctx, uint8_t layer, uint64_t chunk, uint8_t hash_out[32])
  {
    return static_cast<StoreCtx*>(ctx)->db->get_curve_tree_layer_hash(layer, chunk, hash_out);
  }

  bool read_output_oc(void* ctx, uint64_t pos, uint8_t o_out[32], uint8_t c_out[32])
  {
    try
    {
      const output_data_t od = static_cast<StoreCtx*>(ctx)->db->get_output_key(0, pos);
      std::memcpy(o_out, od.pubkey.data, 32);
      std::memcpy(c_out, od.commitment.bytes, 32);
      return true;
    }
    catch (const std::exception&)
    {
      return false;
    }
  }

  void take_buffer(ShekylBuffer buf, std::vector<uint8_t>& dest)
  {
    dest.clear();
    if (buf.ptr && buf.len)
      dest.assign(buf.ptr, buf.ptr + buf.len);
    shekyl_buffer_free(buf.ptr, buf.len);
  }

  void take_error(ShekylBuffer buf, std::string& dest)
  {
    dest.clear();
    if (buf.ptr && buf.len)
      dest.assign(reinterpret_cast<const char*>(buf.ptr), buf.len);
    shekyl_buffer_free(buf.ptr, buf.len);
  }
}

bool assemble_curve_tree_path(
    const BlockchainDB& db,
    uint64_t output_idx,
    uint64_t ref_leaf_count,
    uint64_t tip_leaf_count,
    uint8_t depth,
    curve_tree_path_bytes& out,
    std::string& error)
{
  StoreCtx ctx{&db};
  ShekylBuffer path_buf{};
  ShekylBuffer chunk_buf{};
  ShekylBuffer err_buf{};
  const bool ok = shekyl_assemble_curve_tree_path(
      output_idx,
      ref_leaf_count,
      tip_leaf_count,
      depth,
      &ctx,
      read_leaf,
      read_layer_hash,
      read_output_oc,
      &path_buf,
      &chunk_buf,
      &err_buf);
  if (ok)
  {
    take_buffer(path_buf, out.path);
    take_buffer(chunk_buf, out.chunk_outputs);
    shekyl_buffer_free(err_buf.ptr, err_buf.len);
    error.clear();
    return true;
  }
  take_error(err_buf, error);
  shekyl_buffer_free(path_buf.ptr, path_buf.len);
  shekyl_buffer_free(chunk_buf.ptr, chunk_buf.len);
  if (error.empty())
    error = "curve-tree path assembly failed";
  return false;
}

} // namespace cryptonote
