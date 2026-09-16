// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "crypto/pow_randomx.h"

#include <atomic>
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{

namespace
{
// Atomic because hash_pow_randomx is read from the longhash precompute
// worker threads (blockchain.cpp's tpool.submit), so a seam that is only
// safe as long as nobody writes it while they run is correct by argument
// rather than by construction.
//
// Release/acquire, not relaxed: the store must PUBLISH the function
// pointer. A worker that observed the new pointer without an acquire
// would have no happens-before edge to that function's construction.
std::atomic<pow_hash_fn> s_pow_hash_override_for_tests{nullptr};

bool hash_pow_randomx_ffi(const void* blob, size_t len, const crypto::hash& seed_hash, crypto::hash& out)
{
  return shekyl_pow_randomx_v2_hash(
           reinterpret_cast<const uint8_t (*)[32]>(seed_hash.data),
           static_cast<const uint8_t*>(blob),
           len,
           reinterpret_cast<uint8_t (*)[32]>(out.data)) == SHEKYL_POW_RANDOMX_V2_OK;
}
} // namespace

void set_pow_hash_override_for_tests(pow_hash_fn fn)
{
  s_pow_hash_override_for_tests.store(fn, std::memory_order_release);
}

bool hash_pow_randomx(const void* blob, size_t len, const crypto::hash& seed_hash, crypto::hash& out)
{
  const pow_hash_fn override_fn =
    s_pow_hash_override_for_tests.load(std::memory_order_acquire);
  if (override_fn)
    return override_fn(blob, len, seed_hash, out);
  return hash_pow_randomx_ffi(blob, len, seed_hash, out);
}

} // namespace cryptonote
