// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/hash.h"

namespace cryptonote
{

/// Fill `out` with `len` connecting-chain hashes for heights `[first, first+len)`.
///
/// `alt_hashes` is consecutive starting at `alt_from`. Empty means no alt chain:
/// every height is read from `main_hash`. Otherwise height `h >= alt_from` is
/// `alt_hashes[h - alt_from]` and heights below the fork come from `main_hash`.
/// `main_hash(height, out)` returns false if that main-chain height is missing.
template <typename MainHash>
bool fill_connecting_anchor_hashes(
    uint64_t first,
    size_t len,
    uint64_t alt_from,
    const std::vector<crypto::hash>& alt_hashes,
    MainHash main_hash,
    std::vector<crypto::hash>& out)
{
  out.clear();
  out.reserve(len);
  for (size_t i = 0; i < len; ++i)
  {
    const uint64_t height = first + i;
    crypto::hash h{};
    if (!alt_hashes.empty() && height >= alt_from)
    {
      const uint64_t idx = height - alt_from;
      if (idx >= alt_hashes.size())
        return false;
      h = alt_hashes[static_cast<size_t>(idx)];
    }
    else if (!main_hash(height, h))
    {
      return false;
    }
    out.push_back(h);
  }
  return true;
}

} // namespace cryptonote
