// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "int-util.h"
#include "crypto/hash.h"
#include "difficulty.h"
#include "shekyl/shekyl_ffi.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

  // PoW-target predicate. Thin wrapper over the Rust
  // `shekyl_difficulty_check_hash` (the `shekyl-difficulty` crate's
  // unified `check_hash`). The inherited `check_hash_64` / `check_hash_128`
  // fast/slow split was deleted in the Rust port: it was a pure speed
  // optimization that produced the identical boolean on both paths,
  // proven over the differential corpus in
  // `rust/shekyl-difficulty/tests/check_hash_vectors.rs`. Passes iff the
  // 32-byte hash, read as a 256-bit little-endian integer, satisfies
  // `hash * difficulty < 2^256`.
  //
  // The 128-bit difficulty is decomposed into two u64 halves at this
  // call site (never reinterpret-cast from boost::uint128_t) per the
  // `struct shekyl_u128` ABI in `shekyl/shekyl_ffi.h`.
  bool check_hash(const crypto::hash &hash, difficulty_type difficulty) {
    // Low-64 mask as (2^64 - 1). Deliberately not
    // std::numeric_limits<uint64_t>::max(): on MSVC <windows.h> defines a
    // function-like max() macro that mis-expands the no-arg call (the
    // inherited _64/_128 code guarded the same hazard with `#undef max`);
    // the literal mask avoids the collision with no preprocessor hack.
    const difficulty_type u64_mask = (difficulty_type(1) << 64) - 1;
    shekyl_u128 d{};
    d.lo = (difficulty & u64_mask).convert_to<uint64_t>();
    d.hi = ((difficulty >> 64) & u64_mask).convert_to<uint64_t>();

    bool pass = false;
    const int32_t rc = shekyl_difficulty_check_hash(
        reinterpret_cast<const uint8_t (*)[32]>(&hash),
        d,
        &pass);
    if (rc != SHEKYL_DIFFICULTY_OK)
    {
      // The only failure mode is a null pointer; both arguments here are
      // addresses of stack/reference objects and can never be null. A
      // non-zero return is therefore a contract violation, not a runtime
      // condition — fail closed (reject the PoW) rather than accept on a
      // path that should be unreachable.
      assert(rc == SHEKYL_DIFFICULTY_OK);
      return false;
    }
    return pass;
  }

  std::string hex(difficulty_type v)
  {
    static const char chars[] = "0123456789abcdef";
    std::string s;
    while (v > 0)
    {
      s.push_back(chars[(v & 0xf).convert_to<unsigned>()]);
      v >>= 4;
    }
    if (s.empty())
      s += "0";
    std::reverse(s.begin(), s.end());
    return "0x" + s;
  }

}
