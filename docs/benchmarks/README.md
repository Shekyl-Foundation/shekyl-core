# docs/benchmarks

Benchmark manifests and captured baselines for the wallet-rewire
hardening pass (see [`docs/MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md)).

## Layout

```text
docs/benchmarks/
├── README.md                           (this file)
├── wallet2_baseline_v0.manifest.md     C++ baseline: operation lists + fixture shapes
├── wallet2_baseline_v0.json            C++ baseline: frozen numbers (captured post-PR)
└── (commit 3.2 adds the Rust-side artifacts)
    wallet_state_baseline_v0.manifest.md
    wallet_state_baseline_v0.json
    wallet_state_baseline_v0.iai.snapshot
```

The **manifest** files are prose specifications: every operation a
benchmark exercises, every I/O boundary, every validation check. They
are load-bearing against the apples-to-oranges failure mode (a 2×
wall-clock difference that reflects different work, not a regression).
See `docs/MID_REWIRE_HARDENING.md` §4.3.

The **JSON baseline** files carry the frozen numbers captured on a
reference machine, plus a toolchain + host CPU manifest so future PR
diffs are comparing like against like. These are rolling baselines;
they advance on every merge to `dev` via the bench-baseline branch
workflow (commit 3.3 wires this).

## Capturing the C++ baseline

On a reference machine (consistent toolchain, no background workload,
CPU frequency scaling pinned to a stable setting):

```bash
./scripts/bench/capture_cpp_baseline.sh
```

This script:

1. Configures a release build with `BUILD_SHEKYL_WALLET_BENCH=ON`.
2. Builds the `shekyl-wallet-bench` target only (does not rebuild the
   whole tree).
3. Runs the binary with `--benchmark_format=json`,
   `--benchmark_repetitions=5`, `--benchmark_report_aggregates_only=false`
   so every repetition + aggregates are preserved.
4. Captures `uname -a`, compiler version, CPU model, and the git
   commit of the tree under test.
5. Emits `docs/benchmarks/wallet2_baseline_v0.json` as a single
   self-contained artifact.

Commit the resulting JSON as a follow-up to the commit that ships the
harness. The harness commit intentionally does **not** carry numbers
captured on an arbitrary machine — the reference machine is part of
the measurement.

## Baseline-update policy

The `bench-baseline` branch workflow (commit 3.3) advances the
baseline automatically when a merge to `dev` produces new numbers.
Two exceptions require a human in the loop:

- **Crypto benchmark drift.** Any change ≥ ±5% in a `crypto_bench_*`
  line is inquiry-worthy (constant-time property defense). The merge
  commit must include a one-line rationale before the baseline absorbs
  the change.
- **Manifest drift.** Any change to what a benchmark measures — new
  operation in the hot loop, changed fixture shape, different
  counter — requires both the `.manifest.md` update and a schema
  version bump on the `.json` baseline.

## Cross-references

- `docs/MID_REWIRE_HARDENING.md` §3.1 — scope, commit boundary,
  exit criteria.
- `docs/MID_REWIRE_HARDENING.md` §3.3 — CI integration, threshold
  table, rolling baseline rules.
- `docs/MID_REWIRE_HARDENING.md` §4.3 — apples-to-oranges manifest
  discipline.
- `tests/wallet_bench/README.md` — local build + run instructions.
