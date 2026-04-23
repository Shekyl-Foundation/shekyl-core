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

### Provisional laptop baseline

Until a reference machine is provisioned, the committed
`shekyl_rust_v0.json` + `shekyl_rust_v0.iai.snapshot` are a **laptop
capture** (`captured_on.cpu_model` + `captured_on.kernel` in the
envelope name the exact host). Treat the iai-callgrind instruction
counts as stable across runs on that host (the determinism criterion
from §3.2 is met) and therefore useful as a slowdown detector for
re-captures on the same host. Do **not** treat the criterion
wall-clock numbers as ground truth — they will drift with CPU
frequency scaling and background load, and the reference-machine
re-capture will replace them. The envelope is schema-stable across
the swap.

When the reference machine lands, the re-capture overwrites both
files in a single commit and the provisional-baseline note in this
section is removed. Until then, the C++ script's stricter "do not
commit laptop-captured baselines" discipline is relaxed for
`shekyl_rust_v0` only.

## CI integration

The `ci/benchmarks` workflow
([`.github/workflows/benchmarks.yml`](../../.github/workflows/benchmarks.yml))
is the per-PR gate, wired in commit 3 of the hardening pass.

### Per-PR gate

On a pull request targeting `dev` that touches any benched crate,
`scripts/bench/**`, or the workflow itself:

1. A fresh `ubuntu-latest` runner captures the full
   `shekyl_rust_v0.json` envelope against the PR head via
   `scripts/bench/capture_rust_baseline.sh` (~8-10 min).
2. The runner fetches `bench-baseline/baseline.json` and runs
   [`scripts/bench/compare.py`](../../scripts/bench/compare.py),
   which diffs the PR's iai-callgrind `instructions` column against
   the baseline and routes each entry through the threshold table
   below.
3. [`scripts/bench/post_comment.py`](../../scripts/bench/post_comment.py)
   upserts a PR comment — marker-keyed to
   `<!-- shekyl-benchmarks-comment -->` so re-runs replace the prior
   comment rather than stacking — with per-bench verdicts, deltas,
   criterion wall-clock numbers for context, and provenance.
4. On any `fail`, the workflow fails the job (blocking merge) and a
   second job re-runs the criterion sibling of the tripped bench
   under `samply record` and uploads the resulting `profile.json`
   as the `samply-profile-<PR>` artifact.

### Threshold routing

| Benchmark class     | Warn      | Fail       | Direction         |
|---------------------|-----------|------------|-------------------|
| `crypto_bench_*`    | ±5%       | ±15%       | **bidirectional** |
| `hot_path_bench_*`  | +5%       | +15%       | slowdown-only     |

- `crypto_bench_*` is bidirectional because a large speed-up on a
  constant-time path is just as suspicious as a slow-down: it
  usually indicates a rejection-loop shortcut, a dropped-round
  fast-path, or a KDF parameter drop. Any `crypto_bench_*` change
  ≥ ±5% requires a one-line rationale on the merge commit before
  the baseline absorbs it.
- `hot_path_bench_*` is slowdown-only because faster postcard
  serde, balance compute, or scanner bookkeeping is unambiguously
  better; speed-ups refresh the baseline without commentary.
- An iai-callgrind entry **missing** from the PR's envelope is
  treated as `fail` (a deleted bench is the most dangerous
  regression — a "regression" that no longer exists to be caught).
- An entry present in the PR but not the baseline is
  informational; the first merge to `dev` seeds it into the
  rolling baseline.

Criterion wall-clock numbers are rendered in the PR comment as an
informational table (median_ns delta, no gate). They drift with
runner load and frequency scaling. The Tier-2 upgrade that makes
criterion gate-worthy (dedicated runner + pinned CPU + warm-up
discipline) is tracked in
[`docs/MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §6.1.

### Rolling baseline (bench-baseline branch)

The authoritative CI baseline lives on an **orphan
`bench-baseline` branch**, never merged into `dev` or `main`, with
a single `baseline.json` at its tip (plus a
`baseline.iai.snapshot` and a `README.md` explaining the branch's
purpose). It is the only place in the repository where captured
numbers live that the gate reads.

- Updated by the `update-baseline` job of the workflow on every
  push to `dev` that touches a benched path. A bot-authored commit
  replaces the tip with the fresh capture.
- If the branch does not exist (first-time bootstrap), the gate
  posts a `bootstrap-pending` comment on the PR and passes. The
  first subsequent push to `dev` that the workflow sees creates
  the branch.
- `docs/benchmarks/shekyl_rust_v0.json` and
  `shekyl_rust_v0.iai.snapshot` in `dev` are **human-readable
  snapshots**, not the gate's source of truth. They are updated by
  hand on schema bumps and reference-machine swaps; the gate
  ignores them.

### When a gate trips

A failing PR comment lists every bench that crossed the fail line,
sorted largest delta first. Next steps:

1. Open the linked `samply-profile-<PR>` artifact in
   [`profiler.firefox.com`](https://profiler.firefox.com) for the
   flamegraph.
2. Cross-reference the failing bench's entry in
   [`shekyl_rust_v0.manifest.md`](shekyl_rust_v0.manifest.md) —
   the manifest names every operation in the hot loop, so a
   regression can usually be localized to one operation by
   elimination.
3. If the regression is intentional (deliberate algorithm change,
   security-motivated slowdown), state it in the PR description
   and land a follow-up commit to the bench itself (fixture change
   or manifest §6.x "known gap" entry) **in the same PR**. Ad-hoc
   override of the gate is not supported by design.
4. For a `crypto_bench_*` speed-up that is real and intentional,
   the merge commit body must spell out why — see "Baseline-update
   policy" below.

## Baseline-update policy

The `bench-baseline` branch workflow advances the baseline
automatically when a push to `dev` produces new numbers (see
"Rolling baseline" above). Two exceptions require a human in the
loop:

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
