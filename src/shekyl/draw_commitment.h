// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include <cstdint>

#include "shekyl/shekyl_ffi.h"

namespace shekyl
{

// A block's coinbase 0x0C field: the producer's commitment to its witness
// key and draw seed (ARCHIVAL_SERVE_CREDIT_SPEC.md 4.2). C++ carries it and
// never reads it. Rust draws the secrets, commits and keeps them
// (shekyl_archival_draw_commitment); the grammar that requires the field
// and the writer that places it are Rust's too (shekyl_coinbase_extra).
//
// Every 32-byte value is a commitment, the genesis block's all-zero one
// included. None means "absent": do not compare one against zero, and do
// not default-construct one to stand for a missing value. A struct rather
// than a bare array so a call site cannot pass a hash or a key where the
// commitment goes.
struct draw_commitment
{
  uint8_t bytes[SHEKYL_DRAW_COMMITMENT_BYTES];
};

} // namespace shekyl
