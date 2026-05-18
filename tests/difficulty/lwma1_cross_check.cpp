// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// @file lwma1_cross_check.cpp
/// @brief Cross-language byte-equality harness for the LWMA-1 difficulty
///        algorithm.
///
/// Iterates the §8.1 test corpus of `docs/design/DAA_LWMA1.md` and asserts
/// the documented cross-implementation relations between:
///
///  - The canonical zawy12 LWMA-1 reference (MIT-licensed, vendored as
///    `tests/difficulty/zawy12_lwma1_reference.h` against the byte-offset
///    anchor in `docs/design/refs/zawy12_issue_3_lwma1.anchors.json`).
///  - The Shekyl hybrid reference (BSD-3-Clause + MIT, vendored as
///    `tests/difficulty/shekyl_lwma1_hybrid_reference.h` from the
///    executable form in
///    `docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md`).
///  - The Rust production implementation via `libshekyl_ffi.a`'s
///    `shekyl_difficulty_lwma1_next` C-ABI export
///    (`rust/shekyl-ffi/src/difficulty_ffi.rs`, wrapping
///    `rust/shekyl-difficulty/src/lwma1.rs`).
///
/// Per-vector expectations follow `docs/design/DAA_LWMA1.md` §3 and §8.1:
///
///  - Monotonic-timestamp vectors (1-5): canonical ≡ hybrid ≡ Rust
///    (byte-equal).
///  - Out-of-sequence vectors (6, 7): hybrid ≡ Rust, BOTH STRICTLY
///    DIFFER from canonical. The divergence is the load-bearing security
///    property per `DAA_LWMA1.md` §5.3 step 2 (zawy12 issue #24 item
///    14, September 2018 selfish-mine attack class).
///
/// Failure aborts the test. Per `DAA_LWMA1_PLAN.md` Phase 2 the gate is
/// 100 % passing across the §8.1 corpus before the C++ cutover (Phase 3,
/// renumbered from the original Phase 4 per the Phase 2/3 absorption).

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "shekyl/shekyl_ffi.h"
#include "shekyl/consensus_constants_generated.h"

#include "zawy12_lwma1_reference.h"
#include "shekyl_lwma1_hybrid_reference.h"

namespace {

// §8.1 corpus parameters. `B` and `AVG_D` mirror the Phase 1 Rust
// integration-test corpus (`rust/shekyl-difficulty/tests/spec_vectors.rs`)
// so the two sides exercise identical input vectors.
constexpr uint64_t B = 1'700'000'000ULL;
constexpr uint64_t AVG_D = 1'000'000ULL;
constexpr uint64_t T = SHEKYL_DAA_TARGET_SECONDS;
constexpr uint64_t N = SHEKYL_DAA_WINDOW_N;
constexpr uint64_t FORK_HEIGHT = 0;
constexpr uint64_t DIFFICULTY_GUESS = SHEKYL_DAA_GENESIS_DIFFICULTY;

// `cumulative_difficulties[i] = i * AVG_D` for i in 0..=N (length N+1).
std::vector<uint64_t> cd_window_u64() {
    std::vector<uint64_t> cd(N + 1);
    for (uint64_t i = 0; i <= N; ++i) {
        cd[i] = i * AVG_D;
    }
    return cd;
}

std::vector<shekyl_u128> cd_window_u128() {
    std::vector<shekyl_u128> cd(N + 1);
    for (uint64_t i = 0; i <= N; ++i) {
        cd[i] = shekyl_u128{ /*lo=*/ i * AVG_D, /*hi=*/ 0 };
    }
    return cd;
}

// Helper: call the Rust FFI and return the result as uint64_t after
// asserting hi == 0 (every §8.1 vector's output fits in u64; a non-zero
// hi half would be a hard failure independent of value equality).
uint64_t call_rust(const std::vector<uint64_t>& ts) {
    const auto cd_u128 = cd_window_u128();
    shekyl_u128 out{0, 0};
    const int32_t rc = shekyl_difficulty_lwma1_next(
        ts.data(),
        cd_u128.data(),
        ts.size(),
        /*chain_height=*/ N,
        &out);
    if (rc != SHEKYL_DIFFICULTY_OK) {
        std::fprintf(stderr,
            "FATAL: shekyl_difficulty_lwma1_next returned %d for input "
            "of size %llu\n",
            rc, static_cast<unsigned long long>(ts.size()));
        std::exit(2);
    }
    if (out.hi != 0) {
        std::fprintf(stderr,
            "FATAL: Rust returned out.hi = 0x%llx for input of size %llu; "
            "no §8.1 vector should overflow u64\n",
            static_cast<unsigned long long>(out.hi),
            static_cast<unsigned long long>(ts.size()));
        std::exit(2);
    }
    return out.lo;
}

uint64_t call_canonical(const std::vector<uint64_t>& ts) {
    return shekyl_test::zawy12_canonical::LWMA1_(
        ts, cd_window_u64(), T, N, /*height=*/ N, FORK_HEIGHT, DIFFICULTY_GUESS);
}

uint64_t call_hybrid(const std::vector<uint64_t>& ts) {
    return shekyl_test::shekyl_hybrid::LWMA1_running_max_symmetric_clamp_(
        ts, cd_window_u64(), T, N, /*height=*/ N, FORK_HEIGHT, DIFFICULTY_GUESS);
}

// Failure counter — we report all mismatches before aborting so a
// reviewer sees the full damage in one run rather than fixing them
// one at a time.
int g_failures = 0;

void expect_eq_u64(const char* label,
                   uint64_t actual,
                   uint64_t expected,
                   const char* vector_name) {
    if (actual == expected) {
        std::printf("  ok  %-20s %s = %llu\n",
            vector_name, label, static_cast<unsigned long long>(actual));
    } else {
        std::printf("  FAIL %-20s %s = %llu, expected %llu\n",
            vector_name, label,
            static_cast<unsigned long long>(actual),
            static_cast<unsigned long long>(expected));
        ++g_failures;
    }
}

void expect_ne_u64(const char* label,
                   uint64_t actual,
                   uint64_t forbidden,
                   const char* vector_name) {
    if (actual != forbidden) {
        std::printf("  ok  %-20s %s = %llu (≠ %llu, divergence as designed)\n",
            vector_name, label,
            static_cast<unsigned long long>(actual),
            static_cast<unsigned long long>(forbidden));
    } else {
        std::printf("  FAIL %-20s %s = %llu, expected ≠ %llu\n",
            vector_name, label,
            static_cast<unsigned long long>(actual),
            static_cast<unsigned long long>(forbidden));
        ++g_failures;
    }
}

// Monotonic vector: canonical ≡ hybrid ≡ Rust (all three must agree).
void check_monotonic_vector(const char* name,
                            const std::vector<uint64_t>& ts,
                            uint64_t expected_next_d) {
    std::printf("Vector %s (monotonic, three-way agreement):\n", name);
    const uint64_t canonical = call_canonical(ts);
    const uint64_t hybrid = call_hybrid(ts);
    const uint64_t rust = call_rust(ts);
    expect_eq_u64("canonical", canonical, expected_next_d, name);
    expect_eq_u64("hybrid   ", hybrid, expected_next_d, name);
    expect_eq_u64("rust     ", rust, expected_next_d, name);
    expect_eq_u64("rust == canonical", rust, canonical, name);
    expect_eq_u64("rust == hybrid   ", rust, hybrid, name);
}

// Out-of-sequence vector: hybrid ≡ Rust, both differ from canonical
// (the load-bearing security divergence).
void check_oos_vector(const char* name,
                      const std::vector<uint64_t>& ts,
                      uint64_t expected_shekyl,
                      uint64_t expected_canonical) {
    std::printf("Vector %s (out-of-sequence, security divergence):\n", name);
    const uint64_t canonical = call_canonical(ts);
    const uint64_t hybrid = call_hybrid(ts);
    const uint64_t rust = call_rust(ts);
    expect_eq_u64("canonical", canonical, expected_canonical, name);
    expect_eq_u64("hybrid   ", hybrid, expected_shekyl, name);
    expect_eq_u64("rust     ", rust, expected_shekyl, name);
    expect_eq_u64("rust == hybrid", rust, hybrid, name);
    expect_ne_u64("rust != canonical", rust, canonical, name);
}

} // namespace

int main() {
    std::printf("LWMA-1 cross-check harness — DAA_LWMA1.md §8.1 corpus\n");
    std::printf("  T = %llu, N = %llu, FORK_HEIGHT = %llu, "
                "DIFFICULTY_GUESS = %llu\n",
        static_cast<unsigned long long>(T),
        static_cast<unsigned long long>(N),
        static_cast<unsigned long long>(FORK_HEIGHT),
        static_cast<unsigned long long>(DIFFICULTY_GUESS));
    std::printf("\n");

    // (1) Perfectly stable hashrate.
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i * T;
        check_monotonic_vector("1-stable", ts, 990'000);
    }

    // (2) Sudden 2x hashrate increase.
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i * (T / 2);
        check_monotonic_vector("2-2x-up", ts, 1'980'000);
    }

    // (3) Sudden 2x hashrate decrease.
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i * (2 * T);
        check_monotonic_vector("3-2x-down", ts, 495'000);
    }

    // (4) Solvetime clamp engagement (still monotonic).
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i * T;
        ts[N] = ts[N - 1] + 100 * T;
        check_monotonic_vector("4-clamp", ts, 892'000);
    }

    // (5) Minimum-L floor engagement.
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i;
        check_monotonic_vector("5-L-floor", ts, 10'000'000);
    }

    // (6) Out-of-sequence single back-step.
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i * T;
        ts[N] = B + (N - 2) * T;
        check_oos_vector("6-oos-back-step",
            ts,
            /*expected_shekyl=*/    1'040'000,
            /*expected_canonical=*/ 1'010'000);
    }

    // (7) Selfish-mine attack regression (zawy12 issue #24 item 14).
    {
        std::vector<uint64_t> ts(N + 1);
        for (uint64_t i = 0; i <= N; ++i) ts[i] = B + i * T;
        ts[N - 1] = B + (N - 2) * T + 1000 * T;
        ts[N]     = B + (N - 2) * T + T;
        check_oos_vector("7-selfish-mine",
            ts,
            /*expected_shekyl=*/    1'040'000,
            /*expected_canonical=*/ 911'000);
    }

    std::printf("\n");
    if (g_failures == 0) {
        std::printf("All §8.1 cross-check assertions passed.\n");
        return 0;
    } else {
        std::fprintf(stderr,
            "FAIL: %d §8.1 cross-check assertion(s) failed; see stdout above.\n",
            g_failures);
        return 1;
    }
}
