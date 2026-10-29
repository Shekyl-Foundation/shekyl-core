// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include <cstddef>
#include "crypto/hash.h"

namespace cryptonote
{

// Sole production PoW hash: RandomX v2 via the Rust verifier FFI.
// Returns false if the verifier cannot compute (FFI error); callers must
// treat the bool as the gate (CEN-D2).
bool hash_pow_randomx(const void* blob, size_t len, const crypto::hash& seed_hash, crypto::hash& out);

} // namespace cryptonote
