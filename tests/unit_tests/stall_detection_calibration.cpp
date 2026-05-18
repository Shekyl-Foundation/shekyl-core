// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Stall-detection calibration regression test.
//
// The daemon's `core::check_block_rate()` (src/cryptonote_core/cryptonote_core.cpp:1809)
// runs a Poisson tail test against the last 150 block timestamps. Its
// calibration depends on two T-derived constants:
//
//   threshold       = 1 / (864000 / DIFFICULTY_TARGET_V2)
//                   = 1 / 7200   (one false positive per 10 days)
//   expected_counts = { window_s / DIFFICULTY_TARGET_V2 for each window }
//                   = { 45, 30, 15, 10, 5 }   (5400s, 3600s, 1800s, 1200s, 600s)
//
// Both calibrations assume DIFFICULTY_TARGET_V2 (and its post-commit-6
// successor SHEKYL_DAA_TARGET_SECONDS) equals 120 seconds. Phase 4 commit
// 6 rewires the consumer call sites; this test pins the calibration
// values so a future change to the constant trips a build/test failure
// rather than silently scaling the false-positive rate.
//
// The probability1 / probability functions in cryptonote_core.cpp are
// file-static and not externally callable. This test reproduces them
// locally (the Poisson math is well-known; the test asserts that the
// production code's pinned calibration produces sensible values against
// a reference implementation, not that the C++ implementation itself is
// correct — the existing daemon-integration tests cover the runtime
// path).
//
// See docs/design/DAA_LWMA1_PHASE4_PREFLIGHT.md §7.

#include "gtest/gtest.h"

#include <array>
#include <cmath>

#include "cryptonote_config.h"  // SHEKYL_DAA_TARGET_SECONDS via
                                //   shekyl/consensus_constants_generated.h

namespace
{

// Post-cutover invariant (commit 7 deleted `DIFFICULTY_TARGET_V2`; the
// transitional bridge static_assert is gone with it).
static_assert(SHEKYL_DAA_TARGET_SECONDS == 120,
    "Stall-detection calibration: the 1/7200 false-positive threshold "
    "and the {45, 30, 15, 10, 5} expected-block counts assume the "
    "120-second block target.");

// Local reference implementation of the daemon's static helpers, used to
// sanity-check the canonical Poisson values. Matches the algorithm in
// src/cryptonote_core/cryptonote_core.cpp:1777-1806 exactly.
double ref_factorial(unsigned int n)
{
  if (n <= 1)
    return 1.0;
  double f = n;
  while (n-- > 1)
    f *= n;
  return f;
}

double ref_probability1(unsigned int blocks, unsigned int expected)
{
  return std::pow(static_cast<double>(expected), static_cast<double>(blocks))
       / (ref_factorial(blocks) * std::exp(static_cast<double>(expected)));
}

double ref_probability(unsigned int blocks, unsigned int expected)
{
  double p = 0.0;
  if (blocks <= expected)
  {
    for (unsigned int b = 0; b <= blocks; ++b)
      p += ref_probability1(b, expected);
  }
  else
  {
    for (unsigned int b = blocks; b <= expected * 3; ++b)
      p += ref_probability1(b, expected);
  }
  return p;
}

} // namespace

TEST(stall_detection_calibration, threshold_value_pinned)
{
  // The threshold is 1 / (864000 / 120) = 1/7200 ≈ 1.388e-4.
  // 864000 seconds = 10 days, so the false-positive rate is one per
  // 10 days under correct Poisson block arrivals.
  constexpr double threshold =
      1.0 / (864000.0 / static_cast<double>(SHEKYL_DAA_TARGET_SECONDS));

  EXPECT_DOUBLE_EQ(threshold, 1.0 / 7200.0);
}

TEST(stall_detection_calibration, expected_block_counts_pinned)
{
  // The stall-detection code at cryptonote_core.cpp:1823 checks five
  // time windows; the expected block count for each is window / T. These
  // are the Poisson means of the underlying tail tests.
  constexpr std::array<unsigned int, 5> windows = { 5400, 3600, 1800, 1200, 600 };
  constexpr std::array<unsigned int, 5> expected = { 45, 30, 15, 10, 5 };

  for (size_t n = 0; n < windows.size(); ++n)
  {
    EXPECT_EQ(windows[n] / SHEKYL_DAA_TARGET_SECONDS, expected[n])
        << "Stall-detection window " << n << " (" << windows[n]
        << "s): expected " << expected[n] << " blocks at the 120s target.";
  }
}

TEST(stall_detection_calibration, poisson_reference_canonical_values)
{
  // Sanity-check the Poisson reference implementation against
  // canonical values. If these drift, the production probability()
  // function's calibration interpretation has drifted too.

  // P[X = 0 | λ = 5] = e^-5 ≈ 0.00674.
  EXPECT_NEAR(ref_probability1(0, 5), std::exp(-5.0), 1e-12);

  // CDF at the mean: P[X ≤ 5 | λ = 5] ≈ 0.6160.
  EXPECT_NEAR(ref_probability(5, 5), 0.61596, 1e-4);

  // Lower-tail at zero blocks for the larger windows (full stall):
  // well below the 1/7200 threshold.
  EXPECT_LT(ref_probability(0, 45), 1.0 / 7200.0);
  EXPECT_LT(ref_probability(0, 10), 1.0 / 7200.0);
}

TEST(stall_detection_calibration, stall_threshold_boundary_pinned)
{
  // The calibration's intended boundary: zero blocks in the four longer
  // windows (1200s, 1800s, 3600s, 5400s) must trip the threshold; zero
  // blocks in the 600s window must NOT trip it. The 600s window
  // tolerates noise because the false-positive rate is dominated by
  // short-term natural variance. This is the design point that
  // calibrates the "one false positive per 10 days" rate; if the target
  // T changes without re-deriving the windows, the boundary shifts.
  constexpr double threshold = 1.0 / 7200.0;

  // The four windows that MUST fire on zero blocks under correct
  // calibration:
  for (unsigned int window_s : { 1200u, 1800u, 3600u, 5400u })
  {
    const unsigned int expected = window_s / SHEKYL_DAA_TARGET_SECONDS;
    const double p_zero_blocks = ref_probability(0, expected);
    EXPECT_LT(p_zero_blocks, threshold)
        << "Window " << window_s << "s (λ=" << expected
        << "): zero blocks must trip the stall threshold; "
        << "p(0," << expected << ") = " << p_zero_blocks
        << ", threshold = " << threshold;
  }

  // The 600s window does NOT fire on zero blocks at the current
  // calibration (e^-5 ≈ 6.74e-3 > 1/7200 ≈ 1.39e-4). Pinning this
  // property guards against accidentally lowering T (which would
  // increase λ for the 600s window and push it below the threshold,
  // shifting the false-positive rate).
  const unsigned int expected_600s = 600 / SHEKYL_DAA_TARGET_SECONDS;
  const double p_zero_blocks_600s = ref_probability(0, expected_600s);
  EXPECT_GT(p_zero_blocks_600s, threshold)
      << "Window 600s (λ=" << expected_600s
      << "): zero blocks must NOT trip the stall threshold at the "
         "current calibration; p(0," << expected_600s
      << ") = " << p_zero_blocks_600s
      << ", threshold = " << threshold;
}
