# docs/benchmarks

Benchmark manifests and captured baselines for the wallet-rewire
hardening pass (see [`docs/MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md)).

## Layout

```text
docs/benchmarks/
├── README.md                           (this file)
├── wallet2_baseline_v0.manifest.md     C++ baseline: RETIRED (frozen history)
├── shekyl_rust_v0.manifest.md          Rust baseline: operation lists + fixture shapes
├── shekyl_rust_v0.json                 Rust baseline: frozen numbers (criterion + iai)
├── shekyl_rust_v0.iai.snapshot         Rust baseline: raw iai-callgrind stdout
├── drs_bench_ibd_<engine>_h<H>_<arch>_<ts>.json
                                        DRS-BENCH: consensus-store IBD artifacts
└── measurement_ledger.toml             which constant rests on which capture, and which path set it budgets
```

(The tree above names the baseline set; ad-hoc Pi-4 captures,
`reference-captures/`, and
[`D5_TOR_STEM_RUNBOOK.md`](D5_TOR_STEM_RUNBOOK.md) also live here.
The runbook is the command sequence; it is not a completed capture.)

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

## The C++ baseline is retired

The C++ harness (`tests/wallet_bench/`) and its capture script were
deleted with the `wallet2` layer in the Phase-5 cutover: the harness
existed to measure the C++ baseline the Rust stack was replacing, and
that comparison ends when the thing being compared against is gone.

`wallet2_baseline_v0.manifest.md` is **kept as frozen history** — the
Rust manifest cross-references it for operation lists and for the
rationale behind the `SkipWithError`-gated and Rust-only benchmarks.
Nothing regenerates it; treat every number and status in it as a
statement about the tree as it stood before the cutover.

Rust baselines continue to roll forward as below.

## Capturing the Rust baseline

On the same class of reference machine, additionally requires
`valgrind` (headers as well as the binary — `ledger_iai` enables
gungraun `client_requests`) and `gungraun-runner` on `PATH`
(`cargo install gungraun-runner --version '=0.19.3' --locked`):

```bash
./scripts/bench/capture_rust_baseline.sh
```

This script:

1. Wipes `rust/target/criterion` so the envelope reflects this run
   only.
2. Runs each of the five criterion harnesses
   (`shekyl-engine-state::{ledger, balance}`,
   `shekyl-engine-file::open`, `shekyl-scanner::scan_block`,
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

On a pull request targeting `dev` that touches anything under `rust/`,
`scripts/bench/**`, or the workflow itself (the whole workspace, because a
bench's cost depends on crates other than its own):

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
  push to `dev` that touches the same paths the per-PR gate triggers on. A bot-authored commit
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

## DRS-BENCH consensus-store artifacts

`drs_bench_ibd_*.json` are produced by `scripts/bench/drs_bench.py measure` and
consumed by `drs_bench.py check`, which routes two of them through the IBD floor
frozen in `docs/design/DAEMON_REDB_STORE.md` §1.3. The gate itself —
schema, refusals, comparator, redb-engine probe — lives in
`scripts/bench/drs_artifact.py`. They are **not** part of the
`shekyl_rust_v0` envelope and are not read by `compare.py`: that script is
iai-callgrind only by construction, and its
`<crate>/<bench_target>/<group>/<function>` ids cannot name a two-daemon C++ IBD
run.

Unlike the rolling Rust baselines, these do **not** advance on merge. Each is a
dated record of one run on one machine, kept because §1.3's absolute "N hours"
was deferred until a first LMDB baseline landed in-tree.

**They are conditions-first, by refusal.** `measure` will not emit, and `check`
will not compare, an artifact missing any of: DRS-D9 durability (with the argv
that imposed it), CPU / RAM / disk class / **filesystem type**, the height
actually reached, which verification the fixture exercised, and the peer count.
`check` additionally refuses two artifacts that disagree about any of those —
§1.3's floor is a ratio on one machine with one binary, engine being the only
difference, so a ratio across differing conditions measures the difference and
not the engine.

Two refusals are worth knowing before you run it:

- **A store on `tmpfs` or `ramfs` is refused, before any daemon starts.** fsync
  there has no backing store to flush, so `--db-sync-mode=safe` is
  indistinguishable from `MDB_NOSYNC` and the result is a RAM-disk number
  wearing a strict-durability label. The harness's own first artifact was
  exactly that, from a scratch directory that happened to be a large tmpfs.
- **`disk_class` must be `hdd` or `ssd_or_nvme`.** "unknown" is refused: §1.3
  asks for the disk type, and a required field satisfiable by a placeholder is a
  requirement that cannot fail.

Chain generation dominates the cost at the reference height, so the seed chain
is cached and topped up via `--seed-dir` rather than regenerated. Only the
subject is wiped per run — it is the thing being measured, and an IBD that
starts from a partial chain is a different experiment.

`scripts/bench/test_drs_bench.py` is the selftest; it and `drs_bench.py
blockers` run in `docs-gates.yml`.

## Measurement ledger

[`measurement_ledger.toml`](measurement_ledger.toml) holds one row per
constant whose value is justified by a measured cost or latency: where the
constant is defined, which tracked benchmark measures it, and the capture
and revision it was taken at
([`BENCHMARK_ALIGNMENT.md`](../design/BENCHMARK_ALIGNMENT.md) `BA-Q23`).
The code a constant budgets is a `[[path_set]]`. Constants that share
one cost name the same path set, and a commit to that code is acknowledged
once. `scripts/ci/check_measurement_ledger.py` reads the ledger in
`docs-gates.yml`. For each measured constant it asks whether any commit
touching the path set is still unaccounted for at the constant's review
point.

Each constant states one of three things, and the check fails when the
statement disagrees with git in either direction:

| Status | Means | Fails when |
| --- | --- | --- |
| `current` | Every commit touching the path set is in the history of the review point: the capture, or a `cleared` note on that path set | A commit to the path set is in neither; the failure names it |
| `stale` | Something is newer; the constant names the commit and the carrier of the re-measurement, and its path set lists in `stale_through` every later commit to those paths it has heard | Nothing is newer; or the named commit did not touch the paths; or a commit to the paths is in none of the `stale_through` histories |
| `unmeasured` | No capture is in the tree; the constant names what will measure it | It claims a capture, or names no carrier |

A green run means the ledger tells the truth. It does not mean every capture
is fresh: the stale constants are printed on every run, and each is a
re-measurement somebody owes.

**When your PR fails it.** You changed a path a constant budgets. Edit that
path set in the same PR. One acknowledgment covers every constant that
names the path set.

If every constant on the path set is `current`, one of three:

- Land a newer capture on the constant you re-measured and set `capture`
  and `capture_rev` to it.
- Add a `cleared` note on the path set:
  `{ through = "<commit>", reason = "..." }`. It says every commit to the
  paths in that commit's history is cost-neutral, and why. The reason is
  reviewed with the diff. `cleared` is read only by a current constant.
  A path set whose constants are stale or unmeasured leaves the key off.
- Set the constant `status = "stale"`, `stale_since` to the commit,
  `carrier` to the benchmark run that will re-measure it, and start the
  path set's `stale_through` with that commit.

If a constant on the path set is already `stale`, add a `stale_through`
entry on the path set:
`{ through = "<your commit>", note = "what this does to the cost" }`. A
stale constant asks every change to its paths for a sentence, so a second
regression on an already-stale path is recorded. The capture is owed when
the re-measurement lands. A `cleared` note is not consulted while the
constant is stale.

**Only a newer capture retires a stale constant.** The constant keeps its
name, and the capture's revision contains the commit that made it stale.
The check reads the ledger at `HEAD^1`. In CI that parent is the base
branch, so the pull request as a whole is what is checked. On a local
branch that parent is the previous commit only.

**When you change `rust/rust-toolchain.toml`,** add a `[[toolchain]]` entry
naming your commit and what it does to measured cost. One entry covers the
whole ledger. It is owed while any constant is current across the change.
The comparison base is the capture's review point. A compiler bump after
the capture is owed on its own; clearing the path set's code commits
leaves the toolchain question open.
A toolchain entry's `commit` is the commit that touched the pin. A
path-set entry's `through` is a commit whose history the path set has
heard.

Entries name commits, and they are a set: name your own commit and leave
the others in place. If two PRs append to the same path set, git will ask
you to keep both lines.

**When you add a constant that rests on a measurement,** add its row. When
its cost is one an existing path set already names, point the row at that
path set. A new cost gets a new path set. A constant with a number behind
it and no row is the gap this file closes.

The check needs full history. A shallow clone whose cut lies inside a
constant's range is refused with exit 2.

What it does not see: a path set lists source paths, so a dependency
upgrade in `Cargo.lock`, or a change in a crate the path set does not
list, moves no constant. The paths are a reviewed judgement about where
the cost lives.

It depends on merge commits. Every entry is a commit id that stays in the
branch's history. A squash-merge or a rebase-and-merge mints new ids and
orphans the entries. The check then fails, and the repair is a fresh
acknowledgment of the new ids.

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
