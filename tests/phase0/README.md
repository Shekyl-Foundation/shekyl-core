# LWMA-1 Phase 0 pre-flight harness

This directory contains the Phase 0 pre-flight C++ harnesses
referenced by [`docs/design/DAA_LWMA1.md`](../../docs/design/DAA_LWMA1.md)
§5.3 step 7 and §8.1. These harnesses are not built by the
production `make`/`cmake` invocation; they are standalone
single-file C++17 programs that compile with `g++` directly and
produce the empirical reference values pinned in §8.1.

The harnesses were last run at Phase 0 close (2026-05-18 UTC) and
Round 13 (2026-05-18 UTC) — see the design doc §5.3 step 7 and
§8.1 for the inputs and expected outputs.

## Files

- **`preflight.cpp`** — canonical zawy12 `LWMA1_()` against the
  §8.1 perfectly-stable-hashrate vector. Confirms canonical
  output is `990_000` on `avg_D = 1_000_000` per §5.3 step 7's
  stochastic-vs-deterministic clarification. Includes the
  canonical rounding step per §5.3 step 9.
- **`preflight_corrected.cpp`** — canonical `LWMA1_()` and
  Shekyl's running-max + signed-solvetime + symmetric-clamp
  variant against (a) the same stable vector and (b) an
  out-of-sequence regression vector
  (`timestamps[2] = timestamps[1] - 5*T`). Confirms
  byte-equivalence on monotonic input and divergence (`990_000`
  vs `992_000`) on the regression vector.
- **`preflight_outofseq.cpp`** — both algorithms against the
  seven §8.1 vectors (stable, 2× up, 2× down, clamp engagement,
  minimum-L floor, single back-step, selfish-mine attack)
  base-anchored on `B = 1_700_000_000`. Produces the empirical
  values §8.1 pins as expected outputs.

## Build and run

Each harness is single-file C++17 with no dependencies:

```bash
g++ -std=c++17 -O2 preflight.cpp -o preflight && ./preflight
g++ -std=c++17 -O2 preflight_corrected.cpp -o preflight_corrected && ./preflight_corrected
g++ -std=c++17 -O2 preflight_outofseq.cpp -o preflight_outofseq && ./preflight_outofseq
```

Expected outputs land in
[`docs/design/DAA_LWMA1.md`](../../docs/design/DAA_LWMA1.md) §5.3
step 7 and §8.1; any divergence is a Phase 0 reversion-clause
trigger per `DAA_LWMA1.md` §10 and must surface on `dev` before
Phase 1 implementation continues.

## Licensing

The harnesses transcribe the canonical zawy12 `LWMA1_()` C++
function from
[`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3),
pinned via
[`docs/design/refs/zawy12_issue_3_lwma1.md`](../../docs/design/refs/zawy12_issue_3_lwma1.md).
The canonical function is published under the
[MIT License](https://github.com/zawy12/difficulty-algorithms/blob/master/LICENSE);
the harness file headers carry the SPDX-License-Identifier and
the upstream attribution per the same `25-rust-architecture.mdc`
discipline that `docs/design/DAA_LWMA1_PLAN.md` Phase 2 applies
to the eventual `tests/difficulty/zawy12_lwma1_reference.h`
vendored header.

The Shekyl variant (`LWMA1_shekyl_corrected`) is Shekyl
Foundation original, BSD-3-Clause, transcribed from the textual
specification in `DAA_LWMA1.md` §5.3.
