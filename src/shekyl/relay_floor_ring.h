// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
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

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

#include "syncobj.h"

namespace shekyl {

struct RelayFloorEntry
{
  uint64_t height;
  uint64_t floor;
};

// (height, F) ring for the last G+1 tips. C++ is a cache over the Rust
// floor/admit owner; G comes from shekyl_relay_floor_lookback().
class RelayFloorRing
{
public:
  // Stack capacity: must be >= G+1. G is Rust-owned and read at runtime.
  static constexpr size_t kCapacity = 8;

  bool continues_at(uint64_t next_height) const;

  // One lock: height check and floor load are one snapshot. False if empty
  // or the ring is not at `height` (caller then computes live).
  bool floor_if_at(uint64_t height, uint64_t &floor) const;

  void reset(std::deque<RelayFloorEntry> entries);
  void push(uint64_t height, uint64_t floor, size_t window);

  // Copy floors oldest-first if the ring is at `tip`. False if empty or stale.
  bool copy_floors_at(uint64_t tip, uint64_t *out, size_t cap, size_t &n) const;

  std::vector<std::pair<uint64_t, uint64_t>> snapshot() const;

private:
  mutable epee::critical_section m_lock;
  std::deque<RelayFloorEntry> m_entries;
};

} // namespace shekyl
