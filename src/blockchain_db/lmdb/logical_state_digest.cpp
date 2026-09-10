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

#include "db_lmdb.h"

#include "shekyl/shekyl_ffi.h"

#include <cstring>
#include <limits>
#include <vector>

namespace cryptonote {

std::array<uint8_t, 32> BlockchainLMDB::logical_state_digest_v0() const
{
  // Do not call check_open() here: it is an inline defined only in
  // db_lmdb.cpp, so a second TU cannot link it. height() / the other
  // reads below all check_open themselves.
  const uint64_t n_blocks = height();
  if (n_blocks > std::numeric_limits<size_t>::max() / 32)
    throw DB_ERROR("logical_state_digest_v0: block count overflows size_t");

  std::vector<uint8_t> block_hashes(static_cast<size_t>(n_blocks) * 32);
  for (uint64_t h = 0; h < n_blocks; ++h)
  {
    const crypto::hash id = get_block_hash_from_height(h);
    std::memcpy(block_hashes.data() + static_cast<size_t>(h) * 32, &id, 32);
  }

  std::vector<uint8_t> spent_keys;
  uint64_t n_spent = 0;
  for_all_key_images([&](const crypto::key_image& ki) {
    const size_t off = spent_keys.size();
    spent_keys.resize(off + 32);
    std::memcpy(spent_keys.data() + off, &ki, 32);
    ++n_spent;
    return true;
  });

  const std::array<uint8_t, 32> curve_root = get_curve_tree_root();
  std::array<uint8_t, 32> out{};
  const int32_t rc = shekyl_logical_state_digest_v0(
      n_blocks == 0 ? nullptr : block_hashes.data(),
      n_blocks,
      n_spent == 0 ? nullptr : spent_keys.data(),
      n_spent,
      curve_root.data(),
      out.data());
  if (rc != SHEKYL_CHAIN_DIGEST_V0_OK)
    throw DB_ERROR("shekyl_logical_state_digest_v0 failed");
  return out;
}

void BlockchainLMDB::digest_v0_add_spent_key(const crypto::key_image& k_image)
{
  add_spent_key(k_image);
}

void BlockchainLMDB::digest_v0_remove_spent_key(const crypto::key_image& k_image)
{
  remove_spent_key(k_image);
}

} // namespace cryptonote
