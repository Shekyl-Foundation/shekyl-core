# Shekyl LWMA-1 with running-max + signed-solvetime + symmetric ±6*T clamp

**Status:** derived reference file (not a canonical pin). The canonical pin
is [`zawy12_issue_3_lwma1.md`](./zawy12_issue_3_lwma1.md) in this directory.

**Purpose.** This file is the executable C++ form of the
[`../DAA_LWMA1.md`](../DAA_LWMA1.md) §5.3 step 2/3 specification — canonical
zawy12 LWMA-1 (Issue #3, `LWMA1_()`) with the running-max + signed-solvetime
trick from LWMA-3 inlaid at step 2 and the symmetric `±6*T` clamp at step 3.
The `previous_timestamp` scalar of canonical LWMA-1 is replaced by `prev_max`,
which is updated as `max(prev_max, timestamps[i])` *after* the solvetime is
computed. On monotonic inputs the two forms produce byte-identical output
(empirically verified — see `shekyl_lwma1_running_max_symmetric_clamp` Phase 0
pre-flight harness output: stable §8.1 vector yields `990_000` under both
canonical and corrected forms). On out-of-sequence inputs the running-max
form is the closing remediation for
[zawy12 issue #24 item 14](./zawy12_issue_24_history.md) (September 2018
selfish-mine attack class). The `-T` anchor for iteration 1 is preserved
exactly as in canonical (the empirical divergence on out-of-sequence inputs
is the security property, not an iter-1 mismatch).

**Naming.** The filename reflects Shekyl's specific design — running-max +
signed-solvetime + symmetric clamp — rather than a literal extraction from
canonical zawy12 LWMA-3. Canonical LWMA-3 in
[`zawy12_issue_3_lwma1.md`](./zawy12_issue_3_lwma1.md) lines 360–370 of the
pinned `.body` implements running-max equivalence via
`previous_timestamp = this_timestamp` after a `previous_timestamp+1` floor,
but does **not** allow signed solvetimes or symmetric clamping; those are
the Shekyl-specific refinements of the algorithm-internal fix zawy12
describes in
[issue #24 item 14](./zawy12_issue_24_history.md) ("a different method is
used in LWMA-3 and LWMA-4 so developers do not need to do work outside the
algorithm").

**Empirical equivalence on monotonic inputs (Phase 0 pre-flight).** Compiled
and run alongside the canonical Issue #3 `LWMA1_()` reference on
`N = 90`, `T = 120`, `timestamps[i] = 1_700_000_000 + i*T`,
`cumulative_difficulties[i] = i * 1_000_000`, `height = N+1`,
`FORK_HEIGHT = 0`, `difficulty_guess = 100`:

- Canonical `LWMA1_()` output: `990_000`
- Shekyl corrected output: `990_000`
- Byte-identical: **yes**

Same vector with `timestamps[2] = timestamps[1] - 5*T` (out-of-sequence
attack):

- Canonical `LWMA1_()` output: `990_000` (attacker's negative-solvetime
  injection neutralized to `+1` via `previous_timestamp+1` floor; no
  penalty applied)
- Shekyl corrected output: `992_000` (attacker's negative-solvetime
  injection contributes `-5*T * 2` to `L`; the resulting smaller `L`
  produces a higher `next_D`, denying the attacker's attempt to lower
  difficulty)

Both algorithms agree on monotonic inputs; Shekyl's algorithm penalizes
out-of-sequence timestamps with a higher difficulty (security property).

**Phase 2 cross-check harness usage.** The Phase 2 cross-check harness
compares Rust output against this C++ reference's output:

- For inputs in the strictly-monotonic test corpus, Phase 2 expects
  byte-equality against either canonical `LWMA1_()` or this reference
  (they agree).
- For inputs in the out-of-sequence corpus (the §8.1 selfish-mine
  regression vectors), Phase 2 expects byte-equality against this
  reference only (canonical and Shekyl diverge; the §8.1 expected
  output comes from this reference).

## C++ reference

```cpp
// LWMA-1 with running-max + signed-solvetime + symmetric-clamp step 2/3.
// Copyright (c) 2017-2018 Zawy, MIT License (canonical LWMA-1 portions).
// Copyright (c) 2026 Shekyl Foundation, MIT License (step 2/3 derivation).
// Canonical LWMA-1 pin:
//   https://github.com/zawy12/difficulty-algorithms/issues/3
// Selfish-mine attack motivation:
//   https://github.com/zawy12/difficulty-algorithms/issues/24 (item 14)

#include <cassert>
#include <cstdint>
#include <vector>
#include <algorithm>

// Shekyl uses uint64_t for difficulty_type at the C++ FFI boundary; the
// Rust side computes in u128 and passes the low 64 bits at the FFI seam
// per DAA_LWMA1.md §6.1. The Phase 2 cross-check harness uses uint64_t
// here for byte-equality comparison with the canonical reference.
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
```

## Pre-flight verification source

The above C++ has been compiled and run alongside canonical `LWMA1_()` from
the pinned [`zawy12_issue_3_lwma1.md`](./zawy12_issue_3_lwma1.md) at Phase 0
close; the harness produced the empirical results recorded above. The
harness source is reproduced in
[`../DAA_LWMA1_PLAN.md`](../DAA_LWMA1_PLAN.md) Phase 1 pre-flight
verification section so the result is reproducible by any reviewer.
