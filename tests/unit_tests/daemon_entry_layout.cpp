// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The layout of `ShekylDaemonEntry`, including `is_release` (FLIP-Q3).
// The Rust twin is `rust/shekyl-daemon/src/entry.rs`. The numbers are the
// 64-bit ABI `main()` fills.

#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>

#include "shekyl/shekyl_ffi.h"

TEST(daemon_entry_layout, is_release_sits_beside_the_version_string)
{
  static_assert(alignof(ShekylDaemonEntry) == 8, "entry alignment");
  static_assert(sizeof(ShekylDaemonEntry) == 40, "entry size");
  static_assert(offsetof(ShekylDaemonEntry, release_name) == 0, "release_name");
  static_assert(offsetof(ShekylDaemonEntry, version_full) == 8, "version_full");
  static_assert(offsetof(ShekylDaemonEntry, is_release) == 16, "is_release");
  static_assert(offsetof(ShekylDaemonEntry, protocol_version) == 20, "protocol_version");
  static_assert(offsetof(ShekylDaemonEntry, run) == 24, "run");
  static_assert(offsetof(ShekylDaemonEntry, stop) == 32, "stop");
  static_assert(sizeof(bool) == 1, "is_release is one byte");
}
