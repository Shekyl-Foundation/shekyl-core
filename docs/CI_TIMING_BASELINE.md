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

> _Captured by appending a row to this section once the
> `chore/ci-cache-tightening` PR's first CI run lands. Same
> methodology, same job set, same toolchain. Updated in the same PR
> as the workflow change, so the diff is auditable as a single
> reviewable unit._

| Metric | Value |
| --- | --- |
| dev tip | _pending CI run on `chore/ci-cache-tightening`_ |
| GHA run id | _pending_ |
| Toolchain | _pending_ |
| Cache action | `Swatinem/rust-cache@v2` |
| Cache key | _action-managed: rustc version + Cargo.lock hash + job id_ |
| Cache paths | _action-managed: `~/.cargo/{registry,git,bin}` + `rust/target`_ |

| Job | Wall clock | Δ vs. before |
| --- | --- | --- |
| `Rust: audit, test, determinism` | _pending_ | _pending_ |

The expected delta is dominated by:

- **No more 8m 44s cache upload on identical-payload re-runs.**
  Swatinem skips cache writes when the cache slot is already up to
  date, and writes only deltas otherwise.
- **No more 2m 34s `cargo install cargo-audit`** on cache hits.
- **Smarter `target/` partition.** Swatinem keeps a per-workspace
  partitioned cache and prunes stale crates between runs, reducing
  the false-hit rate on the cargo test recompile.

The `cargo test` step (28m 26s baseline) is dominated by
recompilation when the cache misses on Cargo.lock changes. Swatinem's
key strategy (rustc version explicit, Cargo.lock implicit) doesn't
fundamentally change this; the lockfile cliff is a separate problem
that is intentionally not addressed in this PR. See "out of scope"
below.

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
