# CI Timing Baseline

Wall-clock timings for the [`ci/gh-actions/cli`][workflow] workflow's
per-job runtimes on the `Shekyl-Foundation/shekyl-core` repository's
`dev` branch. Each row records a job-level metric on a specific dev
tip; rows are grouped by the change that motivated the capture, with
explicit "before" / "after" labels so deltas are auditable.

This document exists because the `chore/ci-cache-tightening` PR
(2026-05-02) needed a published anchor for the cache-effectiveness
claim; subsequent caching changes (APT cache for the C++ build matrix,
ccache scope review, etc.) should append rows here rather than
re-deriving "what was the baseline?" from `gh run` logs.

## Methodology

Timings are extracted from the GitHub Actions API via
`gh api repos/Shekyl-Foundation/shekyl-core/actions/jobs/<JOB_ID>` for
per-step durations, and `gh run view <RUN_ID> --json jobs` for
job-level wall clock. All numbers are from CI runs (no local
extrapolation), which means each row is reproducible by re-querying
the same `RUN_ID`.

Each capture identifies:

- **dev tip**: the commit SHA the run was triggered from.
- **GHA run id**: the unique workflow-run identifier under
  `ci/gh-actions/cli`.
- **Toolchain**: the runner's `rustc --version` (relevant for
  cache-key fingerprinting).
- **Job**: the GHA job name as it appears in `gh run view`.
- **Wall clock**: `completedAt - startedAt` of the job, in `MmSSs`.

The metric being recorded is **wall-clock per job**. Cache hit/miss
breakdown and per-step durations live as anecdotes in the
"observations" sub-sections — those are not promoted to rows because
they're not stable enough across runs to compare against (e.g., a
cache hit on one run that misses on the next produces noisy step
times even when nothing about the workflow itself changed).

## Captures

### `chore/ci-cache-tightening` baseline

Captured against the post-rand-bump dev tip, which is the first dev
tip after the `chore/workspace-fmt-clippy-baseline` and
`fix/clippy-1-95-vendored-bulletproofs` and `deps/bump-rand-to-0.8.6`
interim PRs all landed.

#### Before — `actions/cache@v5` (existing strategy)

| Metric | Value |
| --- | --- |
| dev tip | `1155c1abe` |
| GHA run id | `25263753443` |
| Toolchain | `rustc 1.95.0 (59807616e 2026-04-14)` |
| Cache action | `actions/cache@v5` |
| Cache key | `rust-${{ hashFiles('rust/Cargo.lock') }}` |
| Cache paths | `~/.cargo/registry`, `~/.cargo/git`, `rust/target` |

| Job | Wall clock |
| --- | --- |
| `Rust: audit, test, determinism` | 48m 22s |
| `Arch Linux` | 19m 44s |
| `Ubuntu 24.04` | 17m 24s |
| `Windows (MSVC, daemon+wallet+wallet-rpc)` | 17m 11s |
| `Ubuntu 22.04` | 16m 23s |
| `Windows (MSYS2)` | 10m 29s |
| `macOS (brew)` | 5m 18s |
| `source archive` | 0m 53s |
| `Lint: no debug macros in production Rust` | 0m 06s |

##### Observations on the Rust job (the caching target)

Per-step breakdown (top 6 by wall clock) of
`Rust: audit, test, determinism` on `1155c1abe`:

| Step | Wall clock | Cache-relevant |
| --- | --- | --- |
| `cargo test (all workspace crates)` | 28m 26s | Yes — `target/` hot/cold dominates |
| `Post Run actions/cache@v5` (cache UPLOAD) | 8m 44s | Yes — pure waste; smarter cache strategy avoids this |
| `Gate 1: proptest (--release for speed)` | 4m 00s | Partial — release artifacts in `target/release` |
| `install cargo-audit` | 2m 34s | Yes — runs every job (no `~/.cargo/bin` caching) |
| `cargo clippy -D warnings (workspace, all targets)` | 1m 16s | Yes — cache-effective |
| `Run actions/cache@v5` (restore) | 1m 10s | Reasonable; baseline of the restore op |

The 8m 44s post-run cache UPLOAD is the most actionable waste: it
happens on every run regardless of whether the cache key changes,
because `actions/cache@v5` re-uploads the full path set (8.6 GB
target/) when the cache key differs from what was restored.
`Swatinem/rust-cache@v2` writes deltas only.

The 2m 34s `install cargo-audit` step also runs every job because
the previous strategy did not cache `~/.cargo/bin/`. Swatinem caches
this by default; combined with the `--locked`-driven idempotent
re-install, the step becomes a few-second metadata check on cache
hits.

Comparison data point: the immediately preceding dev tip (`514015c7c`,
the post-fix dev tip before the rand-bump's Cargo.lock change)
recorded the same Rust job at **37m 36s** rather than 48m 22s. The
~10m delta between those two adjacent runs is dominated by the
Cargo.lock-driven cache key change forcing a partial recompile, which
illustrates a separate property of the existing cache: it has cliff
behaviour on lockfile changes.

#### After — `Swatinem/rust-cache@v2`

Captured on the `chore/ci-cache-tightening` branch. Two captures were
recorded: a cold-cache run (the first run after the cache action was
swapped, where the new cache layout is being populated for the first
time) and a hot-cache rerun (re-execution of the Rust job on the same
commit, where the cache populated by the cold run is restored).
Run-to-run variance on `cargo test` is non-trivial on dev (the
baseline section above records 37m 36s on `514015c7c` and 48m 22s on
`1155c1abe`, an 11-minute swing on adjacent commits), so the rows
below distinguish "structural" savings (consistent across runs;
attributable to the cache strategy) from total wall-clock (noisy;
dominated by `cargo test` variance).

| Metric | Value |
| --- | --- |
| branch tip | `911989b24` (post-cold-run rerun was on the same SHA) |
| GHA run id | `25265761303` |
| Toolchain | `rustc 1.95.0 (59807616e 2026-04-14)` |
| Cache action | `Swatinem/rust-cache@v2` |
| Cache key | action-managed: rustc version + Cargo.lock hash + job id |
| Cache paths | action-managed: `~/.cargo/{registry,git,bin}` + `rust/target` |

| Job | Cold (first run) | Hot (rerun) | Δ vs. before |
| --- | --- | --- | --- |
| `Rust: audit, test, determinism` | 37m 24s | 35m 57s | cold −10m 58s, hot −12m 25s |

##### Per-step breakdown — Rust job (the caching target)

Step durations from the `Swatinem/rust-cache@v2` runs alongside the
`actions/cache@v5` baseline. Cells where Swatinem has a structural
effect are annotated; rows that are dominated by inherent step cost or
run-to-run variance are marked _noise_.

| Step | Before (cold) | Cold (Swatinem) | Hot (Swatinem) | Notes |
| --- | --- | --- | --- | --- |
| Run cache restore | 1m 10s | 1s | 24s | hot does real cache restore (`~/.cargo/{registry,git,bin}` + `target/`); cold is a no-op miss |
| `install cargo-audit` | 2m 34s | 2m 38s | **0s** | Swatinem caches `~/.cargo/bin/`; hot is no-op; cold matches before |
| `cargo audit` | 4s | 4s | 4s | _noise_ |
| `cargo fmt --check` | 1s | 1s | 1s | _noise_ |
| `cargo clippy -D warnings` | 1m 16s | 1m 19s | 33s | hot benefits from cached `target/` |
| `build shekyl-fcmp` | ~30s | 29s | 22s | hot benefits from cached `target/` |
| `cargo test (all workspace)` | 28m 26s | 24m 20s | 27m 16s | dominated by run-to-run variance, not cache |
| `Gate 1: proptest --release` | 4m 00s | 4m 29s | 3m 58s | _noise_ |
| `Bech32m address tests` | 37s | 37s | 25s | _noise_ |
| `determinism check` | 51s | 51s | 24s | hot benefits from cached `target/` |
| **Post Run cache upload** | **8m 44s** | **1m 30s** | **0s** | **structural win** — incremental writes vs. full target/ upload; no-op when cache is unchanged |

##### Structural savings (consistent across runs)

The wins below are reproducible per run regardless of `cargo test`
variance:

- **Post-run cache upload**: 8m 44s → 1m 30s (cold) → 0s (hot).
  Consistent **−7m 14s on cold**, **−8m 44s on hot**. Compounds across
  every CI run going forward.
- **`install cargo-audit`**: 2m 34s → 0s on hot-cache hits.
  Consistent **−2m 34s** per hot-cache run. Re-pays itself within ~3
  reruns of the same commit.
- **No `target/` invalidation on toolchain bumps with stale binaries.**
  Swatinem's cache key includes `rustc --version`, so the
  1.94.0 → 1.95.0 bump that motivated `fix/clippy-1-95-vendored-bulletproofs`
  would have been correctly invalidated rather than silently restoring
  a 1.94-built `target/`. (Historical fix; not measurable as a delta,
  but a real correctness win.)

##### Variance accounting

`cargo test` swung from 24m 20s (cold) to 27m 16s (hot) on the same
SHA. The hot rerun reused all build artifacts (3 of 4 build-adjacent
steps got faster), so the +2m 56s on the test step is not cache-
related — it is runner CPU contention or test scheduling variance.
This matches the dev-tip variance noted in "Before" (37m 36s vs
48m 22s on adjacent commits, an 11-minute swing). Headline
wall-clock comparisons should be read with this variance band in
mind.

The cargo test step is also still subject to the **lockfile cliff**:
when `Cargo.lock` changes (e.g., `deps/bump-rand-to-0.8.6`), the
Swatinem cache key changes and the workspace recompiles from scratch.
Swatinem's `target/` partitioning prunes stale crates more
aggressively than `actions/cache@v5` did, but does not eliminate the
cliff. That is a separate problem (incremental rebuilds across
lockfile changes is a `cargo` limitation, not a cache one) and is
explicitly out of scope.

##### Out of scope for this PR (deferred to follow-up `chore/ci-cache-...`)

The user-authorized scope of `chore/ci-cache-tightening` is
intentionally tight (see `Question caching_pr_scope: tight_then_iterate`,
2026-05-02). The following caching opportunities are deferred to a
follow-up PR after the `Swatinem/rust-cache@v2` deltas are observed:

- **APT package caching** for the `rust-audit-and-test` container's
  `apt -y install build-essential git curl pkg-config libssl-dev` step
  (~17s). Minor.
- **Rust caching extension to the C++ build matrix.** The
  `Ubuntu 22.04`, `Ubuntu 24.04`, and `Arch Linux` jobs build the
  Rust workspace as part of their C++ build but do not currently use
  Rust caching. They have ccache for C++ but cold Rust target/ on
  every run. Extending Swatinem to those jobs is a >1 commit change
  (each job is 16–20 min wall clock) and benefits from
  baseline-then-after methodology per matrix entry.
- **ccache effectiveness audit** on the C++ matrix — ccache is wired
  in and uses `actions/cache@v5` for its store, but we have not
  measured cache-hit rate. This is a medium investigation, not a
  workflow-edit PR.
- **`cargo install cargo-audit` replaced by `cargo-binstall`**. Not
  caching-related per se, but would shave 2m 34s on cold-cache runs.
  Independent improvement; orthogonal to the cache strategy.

[workflow]: ../.github/workflows/build.yml
