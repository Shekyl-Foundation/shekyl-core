# docs/benchmarks

Benchmark manifests and captured baselines for the wallet-rewire
hardening pass (see [`docs/MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md)).

## Layout

```text
docs/benchmarks/
├── README.md                           (this file)
├── wallet2_baseline_v0.manifest.md     C++ baseline: operation lists + fixture shapes
├── wallet2_baseline_v0.json            C++ baseline: frozen numbers (captured post-PR)
├── shekyl_rust_v0.manifest.md          Rust baseline: operation lists + fixture shapes
├── shekyl_rust_v0.json                 Rust baseline: frozen numbers (criterion + iai)
└── shekyl_rust_v0.iai.snapshot         Rust baseline: raw iai-callgrind stdout
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

## Capturing the Rust baseline

On the same class of reference machine, additionally requires
`valgrind` and `iai-callgrind-runner` on `PATH`
(`cargo install iai-callgrind-runner`):

```bash
./scripts/bench/capture_rust_baseline.sh
```

This script:

1. Wipes `rust/target/criterion` so the envelope reflects this run
   only.
2. Runs each of the five criterion harnesses
   (`shekyl-wallet-state::{ledger, balance}`,
   `shekyl-wallet-file::open`, `shekyl-scanner::scan_block`,
   `shekyl-tx-builder::transfer_e2e`) with `--noplot`.
3. Runs each of the five iai-callgrind sibling harnesses, teeing
   the stdout to the snapshot file as sections are produced so a
   mid-run failure still leaves a useful artifact on disk.
4. Captures `uname -srvmo`, CPU model, rustc + cargo version,
   valgrind version, iai-callgrind-runner version, git-rev +
   dirty-status.
5. Parses the iai-callgrind stdout into structured metrics
   (`instructions`, `l1_hits`, `ll_hits`, `ram_hits`,
   `total_read+write`, `estimated_cycles`) and glues the criterion
   estimates from `target/criterion/**/new/estimates.json` onto the
   same envelope under `schema_version: "shekyl_rust_v0"`.
6. Atomically writes `docs/benchmarks/shekyl_rust_v0.json` and
   `docs/benchmarks/shekyl_rust_v0.iai.snapshot`.

The same "do not commit laptop-captured baselines" discipline as the
C++ script applies — the reference machine is part of the
measurement.

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

- `docs/MID_REWIRE_HARDENING.md` §3.1 — C++ scope, commit boundary,
  exit criteria.
- `docs/MID_REWIRE_HARDENING.md` §3.2 — Rust scope, tool split
  (criterion + iai-callgrind), naming conventions, exit criteria.
- `docs/MID_REWIRE_HARDENING.md` §3.3 — CI integration, threshold
  table, rolling baseline rules.
- `docs/MID_REWIRE_HARDENING.md` §4.3 — apples-to-oranges manifest
  discipline.
- `tests/wallet_bench/README.md` — C++ local build + run instructions.
- `docs/benchmarks/shekyl_rust_v0.manifest.md` — Rust per-bench
  manifest (operation lists, fixture shapes, known gaps).
