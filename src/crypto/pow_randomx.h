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

using pow_hash_fn = bool (*)(const void* blob, size_t len, const crypto::hash& seed_hash, crypto::hash& out);

// TEST SEAM — production code must never call this, enforced by
// scripts/ci/check_pow_test_seam.sh (which also fails if this symbol is
// renamed or if no test uses it). Installs a replacement that
// hash_pow_randomx calls instead of the RandomX FFI so unit tests can
// exercise the verifier-failure arms (CEN-D2: a longhash the verifier
// could not compute must reject the block at every difficulty, including
// 1, where the 0xff sentinel passes check_hash). Pass nullptr to restore
// the real hash. The installed function must outlive every call that can
// reach hash_pow_randomx, and it must be immutable and callable from
// several threads at once: the longhash precompute worker runs the
// dispatch on a threadpool.
void set_pow_hash_override_for_tests(pow_hash_fn fn);

} // namespace cryptonote
