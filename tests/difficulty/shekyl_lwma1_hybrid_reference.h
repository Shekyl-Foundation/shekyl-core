// SPDX-License-Identifier: BSD-3-Clause AND MIT
//
// Shekyl LWMA-1 with running-max + signed-solvetime + symmetric ±6*T
// clamp step 2/3 — the C++ form of docs/design/DAA_LWMA1.md §5.3
// step 2/3. Canonical LWMA-1 portions (genesis short-circuit, step 5
// minimum-L floor, step 6 avg_D, step 7 overflow guard + 99/200 bias,
// step 8 rounding) are byte-identical to canonical zawy12 LWMA-1
// (MIT-licensed) at the pinned revision (see
// tests/difficulty/zawy12_lwma1_reference.h); step 2 (running-max +
// signed-solvetime) and step 3 (symmetric ±6*T clamp) are the Shekyl
// refinement implementing the algorithm-internal fix zawy12 describes
// in https://github.com/zawy12/difficulty-algorithms/issues/24 item 14
// (September 2018 selfish-mine attack class).
//
// Vendored from the executable form recorded in
// docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md
// (SHA-256: f16f62695ae74b2ca47d15227b79035cdc349609d9fc73db2b7a3c57c0dfcc4a,
//  captured 2026-05-18T05:25:21Z). The body below is byte-identical
// to the C++ fenced block at lines 72-160 of that file, modulo
// line-ending normalization.
//
// Canonical LWMA-1 portions copyright (c) 2017-2018 Zawy et al.
// (MIT License); step 2/3 refinement copyright (c) 2026 The Shekyl
// Foundation (BSD-3-Clause).
//
// This file is consumed by tests/difficulty/lwma1_cross_check.cpp as
// the byte-equality reference for the §8.1 out-of-sequence vectors
// (vectors 6 and 7 of docs/design/DAA_LWMA1.md §8.1) where canonical
// LWMA-1 and Shekyl's refinement diverge. For monotonic vectors
// (1-5), the canonical reference in zawy12_lwma1_reference.h is also
// byte-equal to this one; the harness checks both for completeness.
//
// Compiler requirement: this header uses GCC/Clang `__int128` /
// `unsigned __int128` for 128-bit intermediate arithmetic, matching
// the convention in `src/cryptonote_basic/difficulty.cpp` (where the
// extension is guarded behind `__x86_64__` with a portable 64-bit
// fallback) and `tests/unit_tests/staking.cpp` (where the extension
// is used unguarded in test-only code). MSVC does not support
// `__int128`; the parent CMakeLists (`tests/difficulty/CMakeLists.txt`)
// gates the `lwma1-cross-check` target behind `if(NOT MSVC)` so MSVC
// builds skip this harness cleanly rather than failing to compile.
// Coverage of the underlying Rust algorithm on MSVC builds comes
// from `cargo test -p shekyl-difficulty`, which is platform-
// independent.

#pragma once

#include <cassert>
#include <cstdint>
#include <algorithm>
#include <vector>

namespace shekyl_test::shekyl_hybrid {

// Shekyl uses uint64_t for difficulty_type at the C++ FFI boundary;
// the Rust side computes in u128 and the FFI shim decomposes into
// ShekylU128 per DAA_LWMA1.md §6.1. The Phase 2 cross-check harness
// uses uint64_t here for byte-equality comparison.
using difficulty_type = uint64_t;

difficulty_type LWMA1_running_max_symmetric_clamp_(
    std::vector<uint64_t> timestamps,
    std::vector<uint64_t> cumulative_difficulties,
    uint64_t T, uint64_t N, uint64_t height,
    uint64_t FORK_HEIGHT, uint64_t difficulty_guess) {

    assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N + 1);

    // Step 1 — Genesis short-circuit (canonical line 90, unchanged).
    if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return difficulty_guess; }
    assert(timestamps.size() == N + 1);

    // Steps 2 + 3 — Shekyl-modified.
    //   Step 2 (running-max + signed solvetime): replaces canonical's
    //     scalar previous_timestamp with prev_max; updates prev_max via
    //     running max AFTER computing each solvetime so the -T anchor
    //     contributes to iter 1's solvetime exactly as in canonical.
    //   Step 3 (symmetric ±6*T clamp): replaces canonical's one-sided
    //     min(6*T, solvetime) clamp.
    __int128 L_signed = 0;
    int64_t prev_max = (int64_t)timestamps[0] - (int64_t)T;
    for (uint64_t i = 1; i <= N; ++i) {
        // Compute solvetime FIRST using current prev_max — preserves -T anchor on iter 1.
        __int128 solvetime = (__int128)timestamps[i] - (__int128)prev_max;
        // Symmetric clamp: [-6*T, +6*T].
        const __int128 lo = -(__int128)6 * (__int128)T;
        const __int128 hi =  (__int128)6 * (__int128)T;
        if (solvetime < lo) solvetime = lo;
        if (solvetime > hi) solvetime = hi;
        // Weighted sum, signed accumulation (L may be temporarily negative).
        L_signed += (__int128)i * solvetime;
        // THEN update prev_max via running max for next iteration.
        prev_max = std::max(prev_max, (int64_t)timestamps[i]);
    }

    // Step 5 — minimum-L floor (canonical line 103, unchanged).
    const __int128 L_min = (__int128)N * (__int128)N * (__int128)T / 20;
    if (L_signed < L_min) { L_signed = L_min; }
    // L is now a positive i128 (>= L_min > 0); cast to u128 for unsigned arithmetic.
    unsigned __int128 L = (unsigned __int128)L_signed;

    // Step 6 — avg_D (canonical line 104, unchanged).
    difficulty_type avg_D = (cumulative_difficulties[N] - cumulative_difficulties[0]) / N;

    // Step 7 — overflow guard + bias factor 99/200 (canonical lines 107-110, unchanged).
    difficulty_type next_D;
    unsigned __int128 N_factor = (unsigned __int128)N * (unsigned __int128)(N + 1);
    if (avg_D > 2000000ULL * N * N * T) {
        next_D = (uint64_t)(((unsigned __int128)avg_D / (200ULL * L)) * (N_factor * T * 99ULL));
    } else {
        next_D = (uint64_t)(((unsigned __int128)avg_D * N_factor * T * 99ULL) / (200ULL * L));
    }

    // Step 8 — optional rounding (canonical lines 113-117, unchanged).
    uint64_t r = 1000000000ULL;
    while (r > 1) {
        if (next_D > r * 100ULL) {
            next_D = ((next_D + r / 2ULL) / r) * r;
            break;
        } else {
            r /= 10ULL;
        }
    }
    return next_D;
}

} // namespace shekyl_test::shekyl_hybrid
