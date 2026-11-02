// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Cross-language drift sentinel for the RandomX seed-epoch schedule.
//
// The schedule lives in Rust (shekyl_pow_randomx::seed_epoch, exported
// via shekyl-ffi). The schedule itself is pinned here at mainnet
// defaults (KAT values mirrored from the Rust seed_epoch unit tests — a
// divergence means the FFI wiring or the schedule changed). The C++
// block-sync batch this file also held to one seed epoch went with the
// handler's sync half (CS-5): the Rust owner proves each header under
// its own earned seed.
//
// Note: these assertions hold under the default environment. The
// SEEDHASH_EPOCH_* regtest override changes the effective schedule by
// design; the sentinel below guards the guard (skip, don't fail, when
// the lever is deliberately engaged).

#include "gtest/gtest.h"

#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

TEST(seed_epoch, mainnet_schedule_pinned_values)
{
  if (shekyl_pow_randomx_v2_seed_epoch_overridden())
    GTEST_SKIP() << "SEEDHASH_EPOCH_* override active; KAT pins apply to defaults";
  EXPECT_EQ(shekyl_pow_randomx_v2_seedheight(0), 0u);
  EXPECT_EQ(shekyl_pow_randomx_v2_seedheight(2112), 0u);
  EXPECT_EQ(shekyl_pow_randomx_v2_seedheight(2113), 2048u);
  EXPECT_EQ(shekyl_pow_randomx_v2_seedheight(4160), 2048u);
  EXPECT_EQ(shekyl_pow_randomx_v2_seedheight(4161), 4096u);
  EXPECT_EQ(shekyl_pow_randomx_v2_next_seedheight(2100), 2048u);
}
