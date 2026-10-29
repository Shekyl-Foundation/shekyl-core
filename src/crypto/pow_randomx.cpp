// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "crypto/pow_randomx.h"

#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{

namespace
{

bool hash_pow_randomx_ffi(const void* blob, size_t len, const crypto::hash& seed_hash, crypto::hash& out)
{
  return shekyl_pow_randomx_v2_hash(
           reinterpret_cast<const uint8_t (*)[32]>(seed_hash.data),
           static_cast<const uint8_t*>(blob),
           len,
           reinterpret_cast<uint8_t (*)[32]>(out.data)) == SHEKYL_POW_RANDOMX_V2_OK;
}
} // namespace

bool hash_pow_randomx(const void* blob, size_t len, const crypto::hash& seed_hash, crypto::hash& out)
{
  return hash_pow_randomx_ffi(blob, len, seed_hash, out);
}

} // namespace cryptonote
