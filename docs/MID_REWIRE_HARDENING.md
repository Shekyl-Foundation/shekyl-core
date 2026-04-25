# Mid-Rewire Hardening Plan — wallet2 → Rust Migration

**Status:** design spec. No normative code reference yet; this document
is the contract that the eight commits below implement.
**Scope:** a bounded instrumentation and mechanical-check pass executed
mid-migration, between the Rust-side FFI surface (commits 2a…2k.4,
landed) and the C++ consumer rewire (commits 2k.5a onward, deferred).
**Related specs:**
[WALLET_FILE_FORMAT_V1.md](./WALLET_FILE_FORMAT_V1.md) ·
[WALLET_PREFS.md](./WALLET_PREFS.md) ·
[WALLET_STATE_MIGRATION.md](./WALLET_STATE_MIGRATION.md) ·
[POST_QUANTUM_CRYPTOGRAPHY.md](./POST_QUANTUM_CRYPTOGRAPHY.md).
**Related rules:**
[05-system-thinking.mdc](../.cursor/rules/05-system-thinking.mdc) ·
[15-deletion-and-debt.mdc](../.cursor/rules/15-deletion-and-debt.mdc) ·
[30-cryptography.mdc](../.cursor/rules/30-cryptography.mdc) ·
[35-secure-memory.mdc](../.cursor/rules/35-secure-memory.mdc) ·
[40-ffi-discipline.mdc](../.cursor/rules/40-ffi-discipline.mdc) ·
[45-rust-lint-checks.mdc](../.cursor/rules/45-rust-lint-checks.mdc) ·
[50-testing.mdc](../.cursor/rules/50-testing.mdc) ·
[75-system-autonomy.mdc](../.cursor/rules/75-system-autonomy.mdc).

## 1. Motivation

The wallet2 → Rust migration is at the structural midpoint. The
Rust-side pieces are in: `shekyl-wallet-state`, `shekyl-wallet-file`,
`shekyl-wallet-prefs`, and the `shekyl-ffi` consumer surface
(`shekyl_wallet_{create,open,save_state,rotate_password,prefs_*,
export_ledger_postcard,get_metadata,free}`). The C++ consumer —
`wallet2.cpp` — has not been rewired yet: the old `keys_file_data` /
`cache_file_data` monolithic path is still live, no `ShekylWallet*`
handle exists in C++, and `wallet2_ffi_refresh` is an undefined symbol
carried as known-broken-linkage until 2k.5b / 2l closes it.

This is the worst moment to pause indefinitely. It is also a window
that will never exist again: the C++ baseline performance numbers are
recoverable only while the C++ paths exist, and the ability to run
both paths against the same inputs (output-equivalence A/B, timing
delta) exists only during the 2k.5b → 2l dual-stack window. After 2m
deletes the C++ side, neither measurement is reconstructible.

Three specific risks motivate a short, bounded hardening pass before
the C++ rewire resumes:

1. **FFI cost is unknown.** Balance compute over 1000 outputs, cold
   wallet-open over a 100k-output cache, scanner block ingest — these
   are operations that happen on every wallet interaction. The
   per-call FFI overhead is probably cheap (~50–100 ns), but the
   call count is enormous, and a 10% regression per call multiplied by
   that call count is user-visible latency. We have no baseline to
   catch this.
2. **`block_version` discipline is cultural, not mechanical.**
   [`42-serialization-policy.mdc`](../.cursor/rules/42-serialization-policy.mdc)
   (landing with this pass) mandates bumping `block_version` in the
   same commit as any add/remove/rename/reorder of a block field.
   Nothing in the toolchain enforces this today. Postcard will
   silently round-trip a drifted struct against a stale version byte
   because the version is just another field.
3. **The dual-stack window is short.** 2k.5b starts the moment
   wallet2.cpp gains a `ShekylWallet*`; 2m-cache closes the window by
   deleting the C++ side entirely. Everything that must be measured
   or A/B-compared while both paths are live has to be instrumented
   structurally, not as an afterthought.

This document pins the response.

## 2. The pass, at a glance

Eight commits, grouped by function. Commits 1–3 are the benchmark
infrastructure (measurement, harness, CI gate). Commits 4–6 are
mechanical invariants (version snapshot, secret-wipe grep, cross-block
consistency). Commits 7–8 are attack-surface hardening (capability
corpus, fuzz).

| #   | Slug                                     | Group          | Pre-2m-hard-dep | Cuttable? |
|-----|------------------------------------------|----------------|-----------------|-----------|
| 1   | `bench(wallet2)`                         | Measurement    | **yes**         | no        |
| 2   | `bench(wallet-state)`                    | Harness        | no              | no        |
| 3   | `ci(benchmarks)`                         | Gate           | no              | no        |
| 4   | `feat(wallet-state-schema)`              | Invariants     | no              | no        |
| 5   | `ci(wallet-state)`                       | Invariants     | no              | **yes**   |
| 6   | `feat(wallet-state): check_invariants`   | Invariants     | no              | no        |
| 7   | `test(wallet-file): adversarial corpus`  | Attack surface | no              | **yes**   |
| 8   | `test(wallet-state): fuzz harness`       | Attack surface | no              | **yes**   |

"Pre-2m-hard-dep" means the commit must land before 2m-cache deletes
the C++ code path, because its deliverable cannot be reconstructed
after that point. Only commit 1 has a hard deadline in this sense;
the others can in principle slip past 2m, though there is no reason
to.

"Cuttable" names the commits we would drop first if the pass grows
beyond available time. Commit 5 (Zeroizing grep) is cheap and
high-leverage but its loss is tolerable if type discipline holds.
Commits 7 and 8 are test-only surfaces; their loss increases residual
risk but does not block correctness. Commits 1–4 and 6 are
load-bearing and not cuttable.

Cumulative estimated size: ~2000 lines, of which ~40% is benchmark
harness + CI config and ~20% is manual `postcard::Schema` impls for
non-derivable types.

## 3. Commit scopes

### 3.1 `bench(wallet2)`: C++ baseline capture

**Scope.** A Google Benchmark harness exercising the hot paths that
are hermetically testable against the existing wallet2 code, while
it still exists. Pure measurement — no wallet2 code modified, no
new runtime dependencies in the wallet2 build, no CI integration
yet.

**Hot paths measured.** Three of the Five ship with C++ baselines
this commit. The remaining two are Rust-only in commit 3.2; the
rationale is documented below and called out in §4.3.

| Bench                                     | What it measures                                                     | Why                                    | C++               | Rust (3.2)     |
|-------------------------------------------|----------------------------------------------------------------------|----------------------------------------|-------------------|----------------|
| `open_cold`                               | Argon2id + keys parse + cache deserialize, from cold cache           | The wait the user actually sees        | **no (blocked)**  | yes            |
| `balance_compute_N` (N=100, 1000, 10000)  | Sum-unspent over N transfers                                         | O(n) vs O(n²) drift, FFI batching cost | yes               | yes            |
| `cache_serialize_roundtrip_N` (N=1k, 10k) | Boost serialize + deserialize of a representative cache blob         | Format-layer regression canary         | **no (blocked)**  | yes (postcard) |
| `scan_block_K` (K=0, 5, 50)               | Scanner processes a synthetic block with K owned outputs             | Scanner hot path; FFI marshal cost     | **no**            | yes            |
| `transfer_e2e_1in_2out`                   | One full transfer including FCMP++ proof + PQC sign                  | Crypto-path regression canary          | **no**            | yes            |

**Why `open_cold` and `cache_serialize_roundtrip_N` are blocked on this
tree.** Both paths require a freshly generated wallet to round-trip
through `wallet2::generate` → `wallet2::store_to` → `wallet2::load`.
On the current tree that round-trip is broken: `load_keys_buf` raises
`tools::error::wallet_files_doesnt_correspond` because the final
`hwdev.verify_keys(spend_secret, spend_public)` returns false against
what `generate` just persisted. The regression is reproduced one-for-one
by the already-failing unit test
`wallet_storage.store_to_mem2file` in
`tests/unit_tests/wallet_storage.cpp` (the sibling tests
`change_password_*` were already guarded with `GTEST_SKIP` referencing
the same missing-fixture dance). Root-causing the regression is
precisely the work scope of hardening-pass commits `2l` (cache rewire)
and `2m-keys` / `2m-cache` (keys + cache deletion). Shoving a fix in
here would collide with that scope and violate the "clear separations"
invariant the hardening pass is built on. The benches are therefore
scaffolded in full — fixture builders, `wallet_accessor_test` hooks,
Google Benchmark registration, manifest entries — and gated with
`state.SkipWithError(...)` carrying a message that names the blocking
issue and points at the un-skip commit. When `2l` / `2m` land, removing
the `SkipWithError` call and flipping this table row from
`**no (blocked)**` to `yes` is a one-line change.

**Why `scan_block_K` and `transfer_e2e_1in_2out` are Rust-only.**
Both depend on daemon-sourced state that wallet2 has no hermetic
provisioning path for:

- **`scan_block_K`**: wallet2's scanner consumes blocks from
  `get_blocks.bin` RPC responses including tx-pubkey-bearing
  outputs; synthesizing ECDH-addressable outputs against a
  specific wallet view key requires ~300–500 lines of chaingen-
  derived fixture code (mutually referencing `src/cryptonote_core`),
  all of which gets deleted in 2m-cache.
- **`transfer_e2e_1in_2out`**: `transfer_selected_rct` requires
  `m_fcmp_precomputed_paths` populated from an RPC `get_tree_paths`
  response (128-byte leaf entries, interior nodes, commitments,
  key-image generators, PQC-key hashes). Populating it hermetically
  means reimplementing the daemon's FCMP++ tree builder in the
  test harness — cryptographically load-bearing, ~500–1000 lines,
  and the resulting benchmark would exercise our reimplementation's
  idea of a valid tree driving the real proof generator rather than
  the real daemon → wallet2 path. That is a proxy measurement,
  not a real one.

These paths are hermetically benchmarkable in the Rust stack
because the Rust stack was designed to be. The C++ gap is a
consequence of the architectural debt we are removing, not a gap
in the plan. §4.3's apples-to-oranges manifest discipline carries
the asymmetry honestly; the 2m-cache PR compares against the
captured C++ baseline only for the three benchmarks where both
sides exist.

**Deliverable artifacts.**

- `tests/wallet_bench/CMakeLists.txt` — `shekyl-wallet-bench`
  target, behind `BUILD_SHEKYL_WALLET_BENCH` option (OFF by default),
  FetchContent of Google Benchmark v1.9.1 mirroring the existing
  GoogleTest pattern in `tests/CMakeLists.txt`.
- `tests/wallet_bench/bench_wallet2.cpp` — Google Benchmark harness
  producing JSON output with median, p95, mean, and cost-per-unit
  (per-output, per-transfer) where meaningful.
- `tests/wallet_bench/bench_fixtures.{h,cpp}` — seeded fixture
  builders: synthetic transfer_details (for balance_compute_N),
  wallet on-disk fixture (for open_cold), representative cache
  blob (for cache_serialize_roundtrip_N). `wallet_accessor_test`
  reused for friend access to `m_transfers`.
- `tests/wallet_bench/README.md` — build + run instructions,
  documented gaps for scan_block and transfer_e2e.
- `docs/benchmarks/wallet2_baseline_v0.manifest.md` — prose
  description of what each C++ benchmark actually measures: every
  step of the operation, every I/O boundary, every validation check.
  **Load-bearing against the apples-to-oranges failure mode** (see
  §4.3).
- `docs/benchmarks/wallet2_baseline_v0.json` — frozen baseline,
  captured on a reference machine by the commit author and
  committed as a follow-up to this PR (see `capture_cpp_baseline.sh`);
  carries a schema version and the exact toolchain + host CPU
  manifest that produced it.
- `scripts/bench/capture_cpp_baseline.sh` — wrapper that builds
  the target, runs the harness with the right flags
  (`--benchmark_format=json`, repetitions, min-time), captures
  toolchain + host CPU metadata, emits `wallet2_baseline_v0.json`.
- `docs/benchmarks/README.md` — capture procedure, baseline
  update policy, cross-reference to §3.3's rolling-baseline rules.

**Implementation notes.**

- Google Benchmark (`benchmark/benchmark.h`) chosen because it is the
  C++ counterpart to criterion, produces JSON in a schema close
  enough to criterion's for trivial normalization.
- Fixtures generated by a seeded `std::mt19937_64` with a pinned
  seed (`0xBEEFF00DCAFEBABE`); wallet files for `open_cold`
  generated in-harness each run (fast enough that a cached fixture
  adds fragility without saving time).
- Google Benchmark is linked only when `BUILD_SHEKYL_WALLET_BENCH=ON`,
  which defaults OFF. The benchmark harness is opt-in because the
  FetchContent step pulls in its own googletest and is a cold-build
  cost that normal contributors should not pay.
- `wallet_accessor_test` is reused verbatim as the friend-class hook
  for populating `m_transfers`. No new friend classes; no wallet2.h
  changes.

**Dependencies.** None. Can land standalone.

**Exit criteria.** `cmake -DBUILD_SHEKYL_WALLET_BENCH=ON` configures
without error; `make shekyl-wallet-bench` builds the target; running
the built binary with `--benchmark_format=console` produces output
for the three benchmark families; `scripts/bench/capture_cpp_baseline.sh`
exits 0 and produces a valid-schema JSON. The baseline JSON is
captured by the commit author on their reference machine and
committed as a follow-up; this commit ships the harness, not the
numbers.

### 3.2 `bench(wallet-state)`: Rust benchmark harness

**Scope.** criterion + iai-callgrind benchmarks against the new
Rust stack, mirroring the Five from commit 1. No CI integration yet
— the harness is locally runnable via `cargo criterion` and
`cargo bench --bench <name>` (iai-callgrind targets).

**Tool split.**

- **iai-callgrind** for all five, instruction-count + cache-miss
  metrics. Deterministic (±0 variance); runs on any CI runner without
  noise concerns. This is the Tier 1 metric, the one the CI gate
  in commit 3 will enforce against.
- **criterion** for all five, wall-clock metrics. Non-deterministic
  on shared runners; intended for local human use and for future
  Tier 2 CI enforcement on a dedicated runner (not in this pass; see
  §6).

**Deliverable artifacts.**

- `rust/shekyl-wallet-state/benches/ledger.rs` — postcard round-trip.
- `rust/shekyl-wallet-state/benches/balance.rs` — balance compute.
- `rust/shekyl-wallet-file/benches/open.rs` — cold open.
- `rust/shekyl-scanner/benches/scan_block.rs` — scan-block.
- `rust/shekyl-tx-builder/benches/transfer_e2e.rs` — transfer E2E.
- `scripts/bench/capture_rust_baseline.sh` — convenience runner
  (sibling of `capture_cpp_baseline.sh`; shell + python3 rather than
  an `xtask` binary, matching the commit-1 shape) that invokes all
  five criterion + all five iai-callgrind benches and emits a single
  JSON envelope (`schema_version: "shekyl_rust_v0"`, toolchain + host
  CPU + git-rev manifest, per-bench criterion estimates + parsed
  iai-callgrind metrics) alongside a raw `shekyl_rust_v0.iai.snapshot`
  text artifact for human review.
- `docs/benchmarks/shekyl_rust_v0.json` — initial snapshot, captured
  at this commit, becomes the rolling baseline in commit 3.
- `docs/benchmarks/shekyl_rust_v0.manifest.md` — Rust-side
  counterpart to the C++ manifest. Lists every step of each
  benchmark; explicitly enumerates work the Rust path does that the
  C++ path did not (e.g., `WalletLedger::check_invariants()` from
  commit 6), so a delta against the C++ baseline can be interpreted.

**Benchmark naming convention (enforced by commit 3).**

- `crypto_bench_*` — bidirectional thresholds. A speedup is as
  suspicious as a slowdown (constant-time property drift). Applies to
  anything exercising curve25519, FCMP++, ML-KEM-768, Argon2id,
  ChaCha20-Poly1305, or the BIP-39 seed derivation.
- `hot_path_bench_*` — slowdown-only thresholds. Speedups are
  unambiguously good. Applies to postcard serde, metadata parse,
  FFI marshal, scanner non-crypto bookkeeping.
- A benchmark that exercises both (e.g., `transfer_e2e` includes
  both FCMP++ proving and non-crypto bookkeeping) is named
  `crypto_bench_*` — the stricter policy wins when the categories
  overlap.

**Dependencies.** None on 3.1; the two harnesses can be developed in
parallel. Commit ordering is 3.1 → 3.2 only because the C++ baseline
capture has the hard pre-2m deadline.

**Exit criteria.** All five benchmarks runnable locally; iai-callgrind
produces stable output (two runs back-to-back agree to the
instruction); Rust-side manifest exists and is honest about
cross-stack differences.

### 3.3 `ci(benchmarks)`: CI integration with bidirectional thresholds

**Scope.** GitHub Actions workflow that runs the iai-callgrind
benchmarks on every pull request, compares against a rolling
baseline, posts a PR comment with deltas, and captures a profile on
any fail-level regression.

**Architecture.**

- **Baseline storage.** A dedicated `bench-baseline` branch holding a
  single `baseline.json` at its tip. Never merged into `dev` or
  `main`. Updated by a post-merge workflow on `dev` that runs the
  benches, diffs, and writes the new numbers as a single commit
  authored by the CI bot. Never updated from a PR directly.
- **Per-PR workflow.** Checks out the PR, checks out
  `bench-baseline`, runs the bench harness against both the PR and
  the baseline commit (not just the PR's numbers), computes deltas,
  routes through the threshold table below.
- **Threshold routing.**

  | Benchmark class     | Warn threshold | Fail threshold | Direction             |
  |---------------------|----------------|----------------|-----------------------|
  | `crypto_bench_*`    | ±5%            | ±15%           | **bidirectional**     |
  | `hot_path_bench_*`  | +5%            | +15%           | slowdown-only         |

  Warn posts a comment, does not block. Fail posts a comment AND
  blocks merge via a required status check. Both percentages are
  relative to the rolling baseline; both are round-numbered and
  documented so there is no dispute about where the lines are.
- **Profile-on-fail.** When any benchmark trips the fail threshold,
  the workflow re-runs that benchmark under `samply
  --output profile.json` (userland profiler, no
  `perf_event_paranoid` dance required) and uploads the profile as
  a PR artifact. The PR comment includes a link.
- **Comment content.**
  - Before/after numbers for every benchmark (median, p95, mean for
    criterion; instructions for iai-callgrind).
  - The threshold that was tripped, if any.
  - The last five commits touching files on the benchmarked code
    path (a reviewer grep hint).
  - Link to the samply profile artifact for any fail.

**Deliverable artifacts.**

- `.github/workflows/benchmarks.yml` — the per-PR gate + the
  post-merge `update-baseline` job + the on-fail samply profile
  job.
- `scripts/bench/compare.py` — ingests two `shekyl_rust_v0`
  envelopes (baseline vs PR), routes each iai-callgrind entry
  through the `crypto_bench_*` / `hot_path_bench_*` threshold
  table, emits a structured
  `shekyl_rust_v0_compare_v1` report on stdout, and exits 1 if any
  entry fails so the workflow step fails the PR gate.
- `scripts/bench/post_comment.py` — ingests a
  `shekyl_rust_v0_compare_v1` report and renders it as a Markdown
  PR comment, upserted by marker
  (`<!-- shekyl-benchmarks-comment -->`) so re-runs replace the
  previous comment instead of stacking.
- `docs/benchmarks/README.md` — "CI integration", "Threshold
  routing", "Rolling baseline", and "When a gate trips" sections.

**Implementation notes.**

- Tier 1 only in this commit. The iai-callgrind deterministic metric
  is what the gate enforces. criterion wall-clock numbers are emitted
  as informational rows in the PR comment but **do not trip
  thresholds**; documented as such in the README.
- C++ Google Benchmark is **not** wired to the gate in this commit.
  Of the five hot paths, only `BM_balance_compute` ships live on
  the C++ side (per §3.1), and it is a wall-clock metric — which
  places it in the same Tier-2 bucket as criterion. A follow-up
  commit will add a C++ informational row to the PR comment once
  the Tier-2 runner lands.
- Dedicated-runner upgrade (Tier 2, criterion wall-clock + C++
  Google Benchmark wall-clock enforced) is deferred. See §6 for
  the upgrade path and its deadline.
- The per-PR gate does **not** re-run the bench on the baseline
  commit to pair with the PR run. §3.3's original framing called
  for this, but iai-callgrind's instruction count is
  machine-independent for deterministic code (Valgrind's VEX IR,
  not native CPU cycles) — two successive `ubuntu-latest` runs
  on the same source produce identical `instructions` columns. The
  rolling baseline stored on `bench-baseline` is therefore trusted
  directly, saving ~8 minutes of CI time per PR. If cross-runner
  drift shows up in practice, promoting the gate to a paired
  re-run is a single-job workflow change.
- Self-hosted runner security: not a concern for this pass because
  we are on GitHub-hosted ubuntu-latest throughout. Becomes a
  concern when Tier 2 lands; mitigation spelled out in §6.

**Dependencies.** Requires 3.1 and 3.2.

**Exit criteria.** A PR intentionally regressing a benchmark triggers
the expected warn / fail comment; a PR leaving the benchmarks
unchanged produces a comment with the expected deltas near zero;
baseline-update-on-merge workflow has run successfully at least once
(a no-op dev merge is sufficient).

### 3.3.1 Mid-rewire warning window (2k.c) — CLOSED 2026-04-25

**Status.** **CLOSED** as of 2026-04-25. Sentinel
`docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active` deleted in PR 0.1
of the
[shekyl-v3-wallet-rust-rewrite plan](../../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md).
The original closure trigger was the 2m-cache commit; that commit is
no longer scheduled because 2l/2m/2n were absorbed into the Rust
rewrite (which deletes `wallet2.cpp` wholesale at Phase 5 instead of
incrementally rewiring it). The window's exit criterion is therefore
"the file scheduled to be benched against has been declared dead and
the bench gate's reference baseline must rotate against the new
steady state (post-2k.c, pre-rewrite)" rather than "2m-cache lands."

The baseline rotation is **a remaining manual step** belonging to
this PR's reviewer / merger:

1. After PR 0.1 merges to `dev`, manually trigger
   `workflow_dispatch` of `ci/benchmarks` on `dev`.
2. The `update-baseline` job captures a fresh `baseline.json` into
   `bench-baseline` from the post-2k.c steady-state code.
3. Verify the next PR sees the rotated baseline (delta ≈ 0 against
   itself).

If the rotation is not performed, the first post-window PR will diff
against the pre-rewire baseline and likely trip — that is the
expected fail-loud-on-skipped-rotation behavior, not a broken gate.

The text below documents the window as it operated; retained for
historical reference only. **Do not re-open the window** without a
plan addendum (see "extending the window past 2m-cache without a
plan addendum" guidance below — same rule applies to re-opening).

Sentinel (deleted):
`docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active` (no longer
exists; `git log -- docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active`
recovers the file's body).

**Problem this subsection exists to solve.** §3.3's fail threshold
(±15% for `crypto_bench_*`, +15% for `hot_path_bench_*`) is calibrated
against the pre-rewire baseline captured in commit 1 of this pass
(`docs/benchmarks/shekyl_rust_v0.json`). That baseline is recoverable
*only while the C++ paths exist*, and the gate is calibrated for the
*post-rewire* end state — not the dual-stack middle.

During the rewire window (2k.a → 2l → 2m-keys → 2m-cache), the live
code does *both things briefly*: it loads via the new SHKW1 FFI, it
also still has the legacy `keys_file_data` / `cache_file_data` JSON
and boost-serialize paths linked in for watch-only companion and
background-sync survivors, and commits land incrementally rather than
atomically. The transitional state is structurally:

- **slower than the baseline** on any bench that touches the dual
  path (each wallet-open runs an envelope decrypt + payload parse +
  FFI extract + m_account populate, where the pre-2k baseline ran
  only one JSON parse + populate),
- **faster than the final end state** on any bench whose legacy code
  path is still warm in icache / already mapped (the JIT warmup and
  the already-paged-in object files are free wins that 2m-keys
  deletes),
- **non-monotonic across the window** — 2k.a, 2k.b, and 2l each shift
  the mix of dual-path-resident vs. post-rewire code, so the numbers
  don't trend cleanly in either direction.

Gating against the pre-rewire baseline at the strict threshold during
this window forces one of three bad outcomes:

1. **Gate-disable** — someone switches `-failures-only` off on every
   PR to get merge-ready, and the canary goes dark permanently.
2. **Threshold relaxation** — we raise the ±15% to ±30% "temporarily"
   and never lower it back.
3. **Feature branch divergence** — contributors rebase only rarely
   because every rebase re-trips the gate, and the rewire stalls.

All three defeat the point of having a canary at all. The mid-rewire
warning window is the "track everything, don't block merges" middle
position that preserves the signal without the three bad outcomes.

**Mechanism.**

- A sentinel file at
  [`docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active`](./benchmarks/MID_REWIRE_WARNING_WINDOW.active)
  toggles the window. Presence = window open.
- [`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml)
  `fail job on threshold trip` step greps for the sentinel. If
  present, the would-be `::error::` annotation is downgraded to a
  `::warning::` and the job exits 0. The `compare`, `post PR comment`,
  and `profile-on-fail` jobs run exactly as before — only the terminal
  merge-block step is softened. Reviewers still see the full delta
  table, the samply profile artifact, and every informational row in
  the PR comment.
- The workflow's `pull_request`/`push` `paths:` filters include the
  sentinel file, so toggling it (opening or closing the window) itself
  triggers the bench job. This means the first PR after the window
  closes re-establishes the gate immediately, and the first commit
  after the window opens re-captures a mid-rewire number into the
  rolling baseline.

**Why sentinel-in-tree, not a workflow-level boolean.**

| Option                                  | Grep-able | Toggle trail        | Branch-specific | Auto-fails-open |
|-----------------------------------------|-----------|---------------------|-----------------|-----------------|
| **Sentinel file** (this design)         | Yes       | git commit message  | Yes             | Yes             |
| Workflow `env:` boolean                 | Yes       | git commit message  | Per-workflow    | No              |
| Actions secret / workflow_dispatch flag | No        | Actions audit log   | Repo-wide       | No              |
| Branch-name prefix match                | Yes (-ish)| Branch rename       | Yes             | No              |

The sentinel-in-tree option is the only one that (a) participates in
a `git grep MID_REWIRE_WARNING_WINDOW` search, (b) has its open and
close events authored as proper commits with messages, and (c)
auto-restores the gate on deletion. See the header of the sentinel
file itself for the branch-vs-workflow-vs-secret tradeoff discussion.

**Window opening.** The window opens in 2k.c, the same commit that
introduces the sentinel file. 2k.c is also the commit that adds this
subsection and updates `benchmarks.yml` to consult the sentinel.
Before 2k.c landed, the dual-stack was *live* for the feat branch but
the gate was *still strict* — which caused the structural noise the
window exists to absorb.

**Closing the window.** Delete the sentinel file in the 2m-cache
commit. That commit also:

1. Deletes the last dual-stack paths
   (`wallet2::keys_file_data`, `wallet2::cache_file_data`,
   boost-serialize cache blocks, inline atomic-write) — after this
   commit, all wallet I/O goes through `shekyl_wallet_*` FFI.
2. Triggers a one-shot manual `workflow_dispatch` of
   `ci/benchmarks` on `dev` so the `update-baseline` job captures a
   post-rewire `baseline.json` into `bench-baseline`. Until this
   rotation runs, the first post-window PR would diff against a
   pre-rewire baseline and likely trip; the rotation short-circuits
   that false positive.
3. (Optional.) Reviews the delta between pre-rewire
   (`docs/benchmarks/shekyl_rust_v0.json`, commit 1) and the new
   post-rewire baseline, records the delta as a commit message
   bullet in the 2m-cache commit or an immediate follow-up
   so future archaeology has the "expected structural shift"
   number logged.

**Expected signals while the window is OPEN.**

- `compare` reports — wallet-open-cold should drift slower by some
  double-digit percent during 2k.a → 2l (envelope decrypt + payload
  parse + FFI extract + m_account populate on every open), then
  re-center once 2m-keys deletes the legacy JSON parse. Balance
  compute should stay roughly flat (the 1000-output loop is not on
  the rewire path). `BM_balance_compute` / staking selection are
  unchanged — they run entirely in the post-2a `shekyl-wallet-state`
  crate.
- PR comment deltas are **informational only during the window**.
  Reviewers should still eyeball them — anything that regresses a
  benchmark the rewire doesn't touch is a real regression, just not
  a merge-blocking one in this mode.
- The samply profile artifact is still produced on any trip. It is
  the diagnostic path for investigating a regression that was
  surfaced-but-not-blocked; attach it to any follow-up issue filed
  against a window-period PR.

**Policy.** During the window:

- *Do* review every benchmark comment before merging.
- *Do* file a follow-up issue for any regression the PR author
  considers out-of-scope (with the samply profile artifact attached)
  rather than ignoring it.
- *Don't* merge a regression that looks like it targets a
  non-rewire code path without at least discussing it in PR review.
  The window waives the automated gate, not the human review.
- *Don't* extend the window past 2m-cache without a plan addendum.
  An open-ended warning window is a dead canary.

### 3.4 `feat(wallet-state-schema)`: postcard-schema snapshot + CI diff

**Status.** Landed. Pointer in §7 below.

**Scope.** Convert the `block_version` discipline from cultural
invariant (currently pinned only in
[`42-serialization-policy.mdc`](../.cursor/rules/42-serialization-policy.mdc))
to mechanical check.

**Approach.** Use `postcard::experimental::schema::Schema` (aka
`postcard-schema`) to produce a `NamedType` tree for each of the
four ledger blocks (`LedgerBlock`, `BookkeepingBlock`, `TxMetaBlock`,
`SyncStateBlock`) plus the aggregator `WalletLedger`. Serialize the
tree as pretty JSON; commit the JSON as a snapshot. CI job diffs the
snapshot on every PR; any change requires a `block_version` (or
`WALLET_LEDGER_VERSION`) bump in the same commit.

**Why postcard-schema and not schemars / typetag.** Postcard is the
on-disk wire format; postcard-schema's `NamedType` is the canonical
representation of the postcard wire layout. schemars targets JSON
Schema and canonicalizes things postcard does not; typetag is for
trait-object serialization and solves a different problem.

**Deliverable artifacts.**

- `rust/shekyl-wallet-state/schemas/ledger_block.snap`,
  `bookkeeping_block.snap`, `tx_meta_block.snap`,
  `sync_state_block.snap`, `wallet_ledger.snap`. Pretty JSON, stable
  ordering, committed to the repo.
- `rust/shekyl-wallet-state/src/schema_snapshot.rs` — a test module
  containing a single test per block that writes the live schema to
  the corresponding `.snap` file **if `UPDATE_SNAPSHOTS=1` is set**,
  and otherwise asserts byte-equality with the committed `.snap`.
  Pattern mirrors `insta`'s review workflow without the dependency.
- `.github/workflows/schema-snapshot.yml` — CI job that runs the
  tests with no env var (so they assert), and separately checks that
  every commit diffing any `.snap` file also modifies the
  corresponding version constant (parseable grep, documented in the
  workflow).

**`postcard::Schema` derive coverage.**

- Primitives (`u8`, `u64`, `[u8; N]`, `Vec<u8>`, `Option<T>`,
  `String`) have derives upstream. Free.
- Fields using `#[serde(with = "…")]` helpers (seen on
  `TransferDetails.*` and `TxSecretKey.0`) cannot be introspected by
  the `postcard_schema::Schema` derive, because the derive reads the
  declared Rust type, not the serde-helper-rewritten wire type.
  Resolved with the **mirror-struct** pattern: declare a compile-only
  `…Schema` shadow struct whose fields use wire-native types
  (`Vec<u8>` for length-prefixed byte sequences, `Option<Vec<u8>>` for
  optional byte sequences), derive `Schema` on the shadow, and lift
  `NamedType.ty` into a manual `impl Schema` on the domain type under
  its real `&'static str` name. Wire-identical, local to the crate, no
  upstream patch required. `Vec<u8>` and `serde_bytes::ByteBuf` are
  both length-prefixed on the postcard wire; we use `Vec<u8>` in
  mirror structs because `ByteBuf` does **not** carry an upstream
  `Schema` impl and `Vec<u8>` does.
- `Zeroizing<T>` delegates to `T`'s schema via a manual impl
  (`Zeroizing<T>` is wire-identical to `T`). This preserves the
  "Zeroizing does not change the wire" property, which is exactly
  the property that motivates the separate secret-wipe grep in
  commit 3.5.
- Third-party types without upstream `Schema` impls
  (`curve25519_dalek::EdwardsPoint`, FCMP++ proof types,
  ML-KEM-768 ciphertexts where applicable) are reached through the
  same mirror-struct pattern at the leaf that uses them (today:
  `TransferDetailsSchema`). As new leaves grow, each one is a few
  lines at the site that already owns the serde helpers.
- Missing impls surface as compile errors, not silent holes. This
  is why `postcard::Schema` is safe to rely on as the enforcement
  mechanism.

**Implementation notes.**

- Snapshot format is pretty JSON, not postcard bytes — the snapshot
  is a human-readable representation of the schema tree, not a wire
  sample.
- JSON is emitted via the indirection
  `NamedType → OwnedNamedType → serde_json::to_string_pretty`.
  `NamedType` holds `&'static` references that `serde_json` cannot
  roundtrip through; `OwnedNamedType` owns its children and
  serializes cleanly. A trailing newline is appended to match the
  repo's `.gitattributes` convention.
- Schema stability across `postcard` minor versions is an upstream
  guarantee; we pin `postcard-schema = "0.2"` in the wallet-state
  `Cargo.toml` with a caret that matches the schema version used to
  generate the baseline, and bump deliberately.

**Dependencies.** None on 3.1–3.3. Can land in parallel with 3.2.

**Exit criteria.** Each of the five snapshot files exists; the
snapshot-assertion test passes on a clean checkout; a deliberate
field rename in a block produces a failing test with a diff pointing
at the changed node; the CI workflow fails on a PR that edits a
`.snap` file without touching the corresponding version constant.
All four conditions met at landing: `rust/shekyl-wallet-state/schemas/`
holds the five files; `cargo test -p shekyl-wallet-state schema_snapshot`
is green; a scratch `#[serde(rename = "restore_height")]` on
`SyncStateBlock::restore_from_height` produced the expected unified
diff (`- "name": "restore_from_height"` / `+ "name": "restore_height"`);
and the workflow's `grep -E '^[-+]pub const <NAME>\s*:'` dry-run matches
a `1 → 2` bump while rejecting source edits that leave the declaration
line untouched.

### 3.5 `ci(wallet-state)`: Zeroizing-field grep + allowlist

**Status.** Landed. Pointer in §7 below.

**Scope.** Last-line-of-defense check that secret-bearing fields in
`shekyl-wallet-state` are wrapped in `Zeroizing<...>` or a typed
secret wrapper. Mechanical, opt-out via allowlist.

**Approach.** ripgrep-based CI job. Scans
`rust/shekyl-wallet-state/src/**/*.rs` for `[u8; N]`, `[u8; _]`, and
`Vec<u8>` field declarations. Each hit must be either wrapped in
`Zeroizing<...>` / `SecretKey<...>` / a typed wrapper over one, or
present in a frozen allowlist file.

**Deliverable artifacts.**

- `rust/shekyl-wallet-state/.zeroize-allowlist` — newline-separated
  list of `path:field_name` entries that are deliberately not
  `Zeroizing` (public keys, addresses, commitments, hashes).
  Reviewer-facing; every entry has a comment explaining why the
  field is public-bytes.
- `scripts/ci/check_zeroize.sh` — ripgrep invocation + allowlist
  diff. ~40 lines of shell + ripgrep. Exits non-zero on any hit
  that isn't wrapped and isn't allowlisted.
- `.github/workflows/zeroize-check.yml` — wire the script into CI.

**Policy.**

- Adding a new `[u8; N]` or `Vec<u8>` field that is a secret:
  wrap it in `Zeroizing`. No allowlist entry needed. PR passes.
- Adding a new `[u8; N]` or `Vec<u8>` field that is public:
  add to allowlist with a comment. PR passes.
- Adding a field without wrapping and without allowlist entry:
  PR fails with a message naming the offending field and linking
  this document.
- Removing a field from the allowlist without removing the
  field: PR fails (the check sees the hit again).

**Why this is a separate check from 3.4.** The schema snapshot
catches wire-format changes. Unwrapping a `Zeroizing<[u8; 32]>` to
`[u8; 32]` is **not** a wire-format change — the on-disk bytes are
identical. It is a runtime secret-wipe break, which the snapshot
cannot see. This is the gap the grep closes.

**Cuttable?** Yes, if the pass grows beyond available time. The
cost of cutting it is that the scrubbed-arr-class bug (the one
Phase 6 manually audited for) reappears the next time a developer
refactors a block struct and unwraps a `Zeroizing` to simplify a
match arm. Given the cost of the check (~40 lines, zero runtime
cost), cutting it is hard to justify.

**Dependencies.** None.

**Exit criteria.** Script passes on clean `dev`; a deliberate
`Zeroizing` unwrap in a test branch produces a failing CI run with
the expected error message. Both met at landing: the script exits 0
against the current tree ("33 candidate field(s) scanned, all wrapped
or allowlisted"), and the three failure modes were verified locally
— (a) adding an unwrapped `scratch_field: [u8; 32]` produces `FATAL:
unwrapped byte-shaped field(s) without allowlist entry`, (b) adding a
stale allowlist line produces `FATAL: stale allowlist entry — field
no longer exists`, (c) unwrapping `Option<Zeroizing<[u8; 32]>>` →
`Option<[u8; 32]>` produces the "missing allowlist entry" failure on
the now-unwrapped field. Initial allowlist encodes 27 deliberate
public-bytes entries across six files with per-entry rationale.

### 3.6 `feat(wallet-state): WalletLedger::check_invariants()`

**Status: Landed.** Module
[`rust/shekyl-wallet-state/src/invariants.rs`](../rust/shekyl-wallet-state/src/invariants.rs)
owns the closed set of five cross-block invariants, each with a
stable machine-readable name constant
(`INV_TIP_NOT_BELOW_TRANSFER`, `INV_TX_KEYS_NO_ORPHANS`,
`INV_SUBADDRESS_REGISTRY_DENSE`, `INV_REORG_TRAIL_MONOTONIC`,
`INV_SPENT_STATE_CONSISTENT`). `WalletLedgerError::InvariantFailed
{ invariant: &'static str, detail: String }` is the new error
variant; `WalletLedger::check_invariants` runs on the load path
(inside `from_postcard_bytes`, after the version gates) and
`WalletLedger::preflight_save` runs on the save path (called from
`shekyl_wallet_file::handle::WalletHandle::save_state` before the
Argon2id-backed seal). Two of the plan's rows below are adjusted to
match actual block shapes, as the plan explicitly sanctioned:
there is no `BookkeepingBlock::spent_images` set (spend state lives
on `TransferDetails`) and no `TxMetaBlock::entries[*].transfer_index`
(the tx-meta block keys by tx-hash, so the cross-check is
"tx-hash exists in a live reference" rather than a transfer-index
dereference). Reorg-trail shape likewise lives on `LedgerBlock`
rather than `SyncStateBlock`, so I-4's wording is "monotonic and
bounded by the tip" rather than "greater than transfer heights".

**Scope.** Aggregator-level invariants that cannot be enforced by any
single block's schema or version alone. Called once in
`WalletLedger::from_postcard_bytes` after successful decode plus
version gates, and once in every `save_state` path before atomic write.

**Invariants (as landed).**

| #   | Stable name                          | Check                                                                                                                                                                                               | Why it matters                                                               |
|-----|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| I-1 | `tip-height-not-below-transfer`      | `ledger.tip.synced_height >= max(ledger.transfers[*].block_height)` (the scan pointer lives on `LedgerBlock`, not `SyncStateBlock`)                                                                 | Scanner height must not regress below observed outputs                       |
| I-2 | `tx-keys-no-orphans`                 | Every tx-hash key in `tx_meta.tx_keys` must appear in `ledger.transfers[*].tx_hash`, `tx_meta.scanned_pool_txs`, or `sync_state.pending_tx_hashes` (tx-meta is keyed by tx-hash, not transfer index) | No orphan per-tx secret keys                                                 |
| I-3 | `subaddress-registry-dense`          | For every major account `m` present in `bookkeeping.subaddress_registry`, the minor set is contiguous between its observed min and max (no holes)                                                   | Holes mean the design invariant "subaddresses are not deleted" was violated  |
| I-4 | `reorg-trail-monotonic`              | `ledger.reorg_blocks.blocks` is strictly ascending by height, no duplicate heights, and the tail height is ≤ `ledger.tip.synced_height` (reorg trail lives on `LedgerBlock`)                        | Reorg window cannot run past the tip nor be internally inconsistent          |
| I-5 | `spent-state-consistent`             | Per transfer: `spent ⇔ spent_height.is_some() ∧ key_image.is_some()`; `!spent ⇒ spent_height.is_none()`; no two transfers share the same `Some(key_image)`                                          | Cross-transfer spent-state consistency without a separate `spent_images` set |

I-2 and I-5 differ in shape from the plan's initial wording because
the actual blocks keep per-txid secrets in `TxMetaBlock::tx_keys`
(keyed by tx-hash, no `transfer_index`) and track spend state on
`TransferDetails` directly (no `BookkeepingBlock::spent_images`
set). The machine-readable names above are stable and outlive any
future shape refactor.

**Failure mode.**

- **Load path** (`deserialize_postcard`): returns
  `WalletFileError::InvariantFailed { invariant: &'static str,
  detail: String }`. The `invariant` field is a stable machine-
  readable name (e.g., `"sync-height-not-below-transfer"`) so a
  support engineer reading a log knows *which* invariant broke, not
  just "file is corrupt."
- **Save path** (`save_state`): `debug_assert!` in debug builds;
  returns the same typed error in release. A broken invariant on
  the write path is a logic bug, not file corruption; the assertion
  is the appropriate tool, but we still don't panic in release
  because panicking during a save is worse than refusing the save.

**Cost.** All five invariants are O(n) in the number of transfers,
single-pass, no allocation beyond a `HashSet<KeyImage>` for I-5.
For a 10k-transfer wallet that is low microseconds — well under
the Argon2id cost of the open path. Not a `crypto_bench_*` concern;
does not trip the commit-3 thresholds.

**Deliverable artifacts.**

- `rust/shekyl-wallet-state/src/invariants.rs` — the five checks.
- `rust/shekyl-wallet-state/src/error.rs` (or equivalent) — new
  variant `InvariantFailed { invariant: &'static str, detail: String }`.
- `rust/shekyl-wallet-state/src/ledger.rs` — call sites.
- Tests: one per invariant, each constructing a minimal
  invariant-violating `WalletLedger` and asserting the expected
  `InvariantFailed` with the expected `invariant` string.

**Dependencies.** None on earlier hardening commits. Benefits from
3.4 landing first (if a future invariant violation is also a schema
drift, we want the schema check to fire first with a clearer
message) but does not require it.

**Exit criteria.** All five invariants pass on a clean
`WalletLedger::default()` and on a representative 10k-transfer
fixture; each of five negative tests produces the expected error;
benchmark 3.2's `ledger_postcard_roundtrip_10k` shows `check_invariants`
in the profile but under 100 µs for that size.

**Verification (at landing).** 16 unit tests in `invariants::tests`
cover: one positive case on `WalletLedger::empty()`, one positive
case on a populated 3-transfer / 3-block reorg-trail ledger, and at
least one negative case per invariant plus alternate reference paths
for I-2 (pending-tx-hash and scanned-pool references both satisfy the
check). The pre-existing 96-test `shekyl-wallet-state` suite and
51-test `shekyl-wallet-file` suite both remain green; clippy is
clean with `-D warnings`; fmt is clean. The release-build preflight
path is exercised by a `#[cfg(not(debug_assertions))]`-gated
assertion in `preflight_save_returns_typed_error_without_panicking`
so the same test drives both profiles.

### 3.7 `test(wallet-file): adversarial corpus`

**Status: Landed.** New
[`rust/shekyl-wallet-file/tests/adversarial_corpus.rs`](../rust/shekyl-wallet-file/tests/adversarial_corpus.rs)
drives 16 programmatic attack shapes through the orchestrator's
`WalletFileHandle::open` entry point. Each test assembles its
adversarial input in-process from a real `WalletFileHandle::create`
call followed by narrow byte surgery (on ciphertext-protected regions
via the public
[`shekyl_crypto_pq::wallet_envelope::seal_state_file`](../rust/shekyl-crypto-pq/src/wallet_envelope.rs)
helper), so the corpus stays green across future format-field
renames and AEAD-parameter changes without needing a
deterministic-seal escape hatch in the crypto crate. Per-attack
narrative and reproduction notes live under
[`rust/shekyl-wallet-file/tests/fixtures/adversarial/`](../rust/shekyl-wallet-file/tests/fixtures/adversarial/)
(README + one `.md` per row). The code-posture rule called for
below now lives in
[`docs/WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) §2.5
("Capability decode posture"). Deviations from the planned attack
matrix, with rationale:

- **A (capability-byte flip on an existing sealed file)** is
  subsumed into `keys_file_region1_bit_flip_is_refused`, which flips
  an arbitrary byte inside region 1 ciphertext. The capability byte
  is part of region 1's AAD+plaintext and the AEAD cannot
  distinguish which byte was flipped, so a dedicated row would
  assert the same refusal (`InvalidPasswordOrCorrupt`) as the
  general region-1 bit-flip row. One test, not two.
- **B and C (capability-shape mismatches)** are refused by the
  existing
  [`WalletEnvelopeError::CapContentLenMismatch { mode, len }`](../rust/shekyl-crypto-pq/src/wallet_envelope.rs)
  variant. The plan's proposed
  `WalletFileError::CapabilityPayloadMismatch` was dropped on
  review — `validate_cap_content` already enforces the entire
  intended `(mode, cap_content_len)` shape, and adding a second
  variant would duplicate the gate. The wiring test
  `capability_payload_mismatch_is_covered_by_envelope_tests`
  asserts the envelope-layer refusal flows through
  `WalletFileError::Envelope` unchanged. `WALLET_FILE_FORMAT_V1.md`
  §2.5 writes up the posture; a dedicated fixture row
  (`16-capability-payload-mismatch.md`) documents why there is no
  second variant.
- **F / G (header-length lies)** collapse into the SWSP
  `body_len` row (`swsp_body_len_mismatch_is_refused`). The
  hardening-pass wallet format does not carry a top-level
  `metadata_len + ledger_len` header — region 2 is a single
  length-prefixed SWSP frame, so the failure mode the plan
  described surfaces as `PayloadError::BodyLenMismatch`, not a new
  `TruncatedRegion2` variant. Same refusal semantics, one typed
  error instead of two.
- **Deliberate refusal collapse.** A single-bit flip inside region
  2 ciphertext currently surfaces as `StateSeedBlockMismatch`
  rather than `InvalidPasswordOrCorrupt` because the opener
  cannot distinguish a ciphertext mutation from a
  `seed_block_tag` mismatch without running the full region-2
  verification twice against two different AADs. The test
  `state_file_region2_bit_flip_is_refused` locks this mapping in
  and the rationale is documented in `07-state-region2-bit-flip.md`
  so any future variant split is caught in review.

All other planned rows (D / E / H / I and the new invariant-gate
attack from commit 6) land with the expected typed refusals. The
16 corpus tests pass; the rest of the `shekyl-wallet-file` suite
remains green; clippy is clean with `-D warnings`; fmt is clean.

**Scope.** A corpus of hand-crafted malformed wallet files exercising
specific attack shapes, each expected to produce a typed error and
not a panic, not a silent fallback, not an incomplete parse.

**Attack matrix.** Each row is one or more corpus fixtures plus the
asserted error.

| Attack                                                     | Fixture shape                                                                                                               | Expected error                                                                    |
|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| A. Flipped capability byte on existing sealed file         | Modify one byte in the capability field of a real sealed file                                                               | `WalletFileError::AuthenticationFailed` (AEAD tag fails)                          |
| B. Capability = FULL with VIEW_ONLY payload shape          | Well-sealed fresh file, AEAD tag valid, declared FULL, CapabilityContent region shaped for VIEW_ONLY                        | `WalletFileError::CapabilityPayloadMismatch`                                      |
| C. Capability = VIEW_ONLY with trailing bytes in payload   | Well-sealed fresh file, declared VIEW_ONLY, CapabilityContent region contains extra bytes past the expected VIEW_ONLY shape | `WalletFileError::CapabilityPayloadMismatch` (strict, not lenient)                |
| D. Wrong magic                                             | First 8 bytes not `SHEKYLWT`                                                                                                | `WalletFileError::UnknownFormat`                                                  |
| E. `format_version` = 0xFF                                 | Magic OK, version byte invalid                                                                                              | `WalletFileError::UnknownFormat` or `VersionNotSupported`                         |
| F. `metadata_len + ledger_len > file_size`                 | Header claims more region-2 bytes than the file contains                                                                    | `WalletFileError::TruncatedRegion2`                                               |
| G. `metadata_len + ledger_len < file_size`                 | Header claims fewer region-2 bytes than the file contains (trailing garbage)                                                | Same error; strict, trailing bytes are never ignored                              |
| H. `payload_version` = 0xFF on SWSP frame                  | Framing magic OK, payload version invalid                                                                                   | `WalletFileError::PayloadVersionUnsupported`                                      |
| I. `block_version` fuzzed per block                        | Each of the four blocks with a mutated version byte                                                                         | `WalletFileError::BlockVersionUnsupported { block: &'static str }`                |

**Attack B is the one requiring a structural code change.** The
capability-decode path must:

1. Read `capability: Capability` first, before decrypting or parsing
   the capability-content region.
2. Dispatch to exactly one of `decode_full`, `decode_view_only`,
   `decode_hardware_offload`, each of which knows its expected shape.
3. Any length mismatch, field-presence mismatch, or trailing-bytes
   condition in the dispatched decoder returns
   `CapabilityPayloadMismatch`, **not** a fallback to a different
   capability decoder.

A code-posture rule to this effect lands in
`docs/WALLET_FILE_FORMAT_V1.md` as a new §capability-decode
subsection, authored in this commit.

**Attack C note on memory-wipe discipline.** The wire-level attack
is covered by the strict-trailing-bytes check. The deeper concern
(a load-path memory-wipe bug where secrets in trailing bytes linger
in decrypted form) is not directly testable from a corpus fixture —
it is a code-correctness property about what happens with the bytes
after parse. The enforceable proxy is the strict parse; the
residual risk is addressed by code review discipline captured in
the new §capability-decode subsection. Honestly named in this
commit, not papered over.

**Deliverable artifacts.**

- `rust/shekyl-wallet-file/tests/fixtures/adversarial/` — binary
  corpus files, one per attack row. Accompanying `.md` files
  describe how each was constructed (reproducibility).
- `rust/shekyl-wallet-file/tests/adversarial_corpus.rs` — one test
  per corpus entry, asserting the exact typed error.
- New `WalletFileError::CapabilityPayloadMismatch` variant (if not
  already present).
- `docs/WALLET_FILE_FORMAT_V1.md §capability-decode` — the code-
  posture rule.

**Cuttable?** Yes. The corpus is high-leverage but the deadline is
not 2m — it is "before the audit," which is further out. If the
pass grows, this commit can slip one PR without changing the
mechanical-check story.

**Dependencies.** None on 3.1–3.6. Pairs naturally with 3.4 (a
schema-drift regression and an adversarial fixture for the same
field both fail CI, which is the design).

**Exit criteria.** Every attack row has a corpus fixture and a
passing test; the code-posture rule is merged into
`WALLET_FILE_FORMAT_V1.md`; a review comment is left on any
decoder that uses `read_to_end`, `take_while`, or similar unbounded
patterns in the capability-decode path.

### 3.8 `test(wallet-state): fuzz harness`

**Status: Landed.** Two harnesses exercising
[`WalletLedger::from_postcard_bytes`](../rust/shekyl-wallet-state/src/wallet_ledger.rs)
(the canonical name for what the plan called
`deserialize_postcard`). The stable-Rust proptest harness at
[`rust/shekyl-wallet-state/tests/fuzz_region2.rs`](../rust/shekyl-wallet-state/tests/fuzz_region2.rs)
runs on every PR via `cargo test -p shekyl-wallet-state`; the
cargo-fuzz harness at
[`rust/shekyl-wallet-state/fuzz/`](../rust/shekyl-wallet-state/fuzz/)
ships as a checked-in local-only tool excluded from the workspace
(see the new `exclude = ["shekyl-wallet-state/fuzz"]` entry in
[`rust/Cargo.toml`](../rust/Cargo.toml)). The proptest harness
runs five strategies at 128 cases each (640 cases total —
comfortably inside the plan's ~500-iteration budget): point
mutation of a valid empty bundle, truncation, random byte
insertion, random byte deletion, and entirely-random bytes.
Wall-clock on the author's machine is ≈0.06 s per run, three
orders of magnitude under the 30 s-per-PR exit criterion. The
single invariant asserted across all five is
**panic-freedom**: every byte input must terminate in `Ok` or in
one of the four enumerated `WalletLedgerError` variants, never a
panic or abort. The error-classification match in
`assert_typed_or_ok` is deliberately exhaustive (distinct
classification tags per arm) so that adding a new
`WalletLedgerError` variant without updating the fuzz harness is
a compile-time error — the harness stays in lockstep with the
error taxonomy mechanically, not culturally. The cargo-fuzz
harness is minimal by design (a single `fuzz_target!` wrapping
`let _ = WalletLedger::from_postcard_bytes(data)`) because the
interesting content is libFuzzer's corpus evolution, not the
wrapper; keeping it trivial prevents the harness from masking a
parser regression by panicking itself. Its `README.md`
documents the `cargo +nightly fuzz run region2_parser`
invocation, the two-condition graduation plan (nightly
stabilisation OR mainnet-freeze proximity), and why nightly is
not in CI today. Verified locally: all 96 existing
`shekyl-wallet-state` unit tests remain green; the new 5-test
proptest harness passes in 0.06 s wall-clock; `cargo check
--workspace --tests` on stable ignores the fuzz crate entirely
(the `exclude` entry works); clippy is clean with `-D warnings`;
fmt is clean. Not verified from this host (no nightly toolchain
installed): `cargo +nightly fuzz build region2_parser` — the
harness is structurally identical to the cargo-fuzz template and
will be exercised on an author's local nightly install before
any parser-level change lands.

**Scope.** Two harnesses exercising the region-2 payload parser
(`WalletLedger::from_postcard_bytes`, listed as
`WalletLedger::deserialize_postcard` in the original plan; the
canonical name landed differently in commit 2n) with randomized
input.

**Tooling.**

- **proptest** (stable Rust) — runs on every PR in CI. Seeded from
  the real payload KATs. Strategy: start from a valid payload,
  mutate 1–3 bytes at random, assert the parser either decodes
  successfully or returns a typed error (no panics, no aborts).
  ~500 iterations per PR; cheap.
- **cargo-fuzz** (nightly Rust, not CI-integrated) — checked-in
  harness at `rust/shekyl-wallet-state/fuzz/fuzz_targets/
  region2_parser.rs`, runnable locally with
  `cargo +nightly fuzz run region2_parser`. Documented in
  `rust/shekyl-wallet-state/fuzz/README.md` as a local-only tool
  until mainnet-freeze, at which point it graduates to a nightly
  sidecar job. No CI integration in this pass.

**Why not cargo-fuzz in CI now.** Nightly Rust is not in the current
CI toolchain; adding it for fuzz alone is a non-zero operational
cost (nightly installs, cache pollution, toolchain version drift).
proptest on stable catches the bulk of regressions at essentially
zero operational cost; cargo-fuzz adds depth we want *eventually*
but don't need before mainnet-freeze.

**Cuttable?** Yes. The proptest harness is the higher-leverage half
and can land on its own; cargo-fuzz can be deferred entirely until
pre-freeze. If the pass must be cut, keep proptest, drop cargo-fuzz.

**Deliverable artifacts.**

- `rust/shekyl-wallet-state/tests/fuzz_region2.rs` — proptest
  harness.
- `rust/shekyl-wallet-state/fuzz/` — cargo-fuzz harness
  (workspace-excluded, local-only).

**Dependencies.** Benefits from 3.6 landing first so that
`check_invariants` is in the parse path and the fuzzer exercises
it; not strictly required.

**Exit criteria.** proptest harness runs in <30 s per PR and has
produced zero false failures across 10 consecutive CI runs; a
deliberately broken parser produces a proptest failure with a
shrunk counterexample; cargo-fuzz harness builds under
`cargo +nightly fuzz build` on the author's local machine.

## 4. Cross-cutting policy

### 4.1 Benchmark threshold routing

The threshold table in §3.3 is the complete policy. Two additional
notes:

- **Rolling baseline, not fixed.** The `bench-baseline` branch
  advances on every merge to `dev`. Improvements are absorbed; we
  don't fight the baseline. A crypto benchmark improving by 20% is
  an inquiry — a `crypto_bench_*` warn/fail — and must be
  investigated before the baseline absorbs the improvement. The
  investigation outcome (constant-time proof preserved, improvement
  is legitimate algorithmic work) is captured in the merge commit
  message.
- **The first baseline is commit 3.1's output**, not commit 3.2's.
  The rolling baseline is *relative*, so what matters is consistency
  between the PR's numbers and the baseline's numbers — both run
  against the Rust stack. The C++ baseline from 3.1 is used for a
  separate artifact: the "have we regressed against the code we
  replaced" comparison, surfaced in the 2m PR (commit 2m-cache),
  *not* in every PR.

### 4.2 Dual-path output-equivalence (2k.5b requirement, captured here)

Commits 2k.5b through 2l-exclusive run with both the C++ and Rust
load paths live. Each 2k.5b / 2l commit MUST include a test that:

1. Loads the same wallet file through both paths.
2. Asserts output-equivalence at a defined abstraction level —
   balance per account, transfer list sorted by (block_height,
   tx_hash), key-image set, sync height. **Not byte-level**; the
   Rust and C++ paths produce different internal representations.
3. Records the wall-clock delta between the two paths into a
   per-commit CSV file under `docs/benchmarks/dual_path/`, one row
   per commit.

This code is deleted in 2m-cache (same PR, rule-93 style). The
requirement is structural — encoded in the commit-message template
for 2k.5b / 2l, not left to reviewer discretion. See
[15-deletion-and-debt.mdc](../.cursor/rules/15-deletion-and-debt.mdc).

### 4.3 Apples-to-oranges manifest discipline

The C++ and Rust benchmarks measure different code stacks even when
they measure the same user-visible operation. `open_cold` in C++
runs `keys_file_data` JSON parse + boost deserialize + epee header
decode. `open_cold` in Rust runs postcard deserialize + AEAD open +
SWSP framing + `check_invariants`. A 2× Rust wall-clock is not
automatically a regression — Rust may be doing work C++ omitted.

Every benchmark has two artifacts:

1. The JSON number (machine-readable, what the CI compares).
2. The manifest line (prose, human-readable, what the operation
   actually does).

The bench-comparison script (§3.3) emits both in the PR comment.
The manifest line for each side is carried verbatim from the
relevant `.manifest.md`; any change to the manifest requires the
same review as changing the benchmark itself.

This is the specific defense against both failure modes:

- **False-positive regression.** "Rust is 40% slower" interpreted
  against "but Rust runs `check_invariants` that C++ didn't" is a
  non-regression.
- **False-negative speedup.** "Rust is 20% faster" interpreted
  against "Rust skips the validation step C++ did" is a silent
  correctness regression hiding as a performance win.

**Benchmarks Rust-only by necessity.** Two of the Five
(`scan_block_K`, `transfer_e2e_1in_2out`) ship only in the Rust
harness because wallet2 has no hermetic provisioning for the
daemon-sourced state they require (see §3.1 for the specifics).
The manifest marks these explicitly `RUST_ONLY: no pre-deletion
C++ baseline, see §3.1 rationale`. For these two benchmarks, the
bench-comparison script in §3.3 does not attempt a C++ delta; the
PR comment prints Rust-only numbers alongside a one-line reminder
that no comparison exists. Regression detection across the rewire
for these paths relies on the Rust rolling baseline (§3.3) plus
human sanity-check on order of magnitude, not on a pre-deletion
comparator. This is an acknowledged gap, not a defect.

### 4.4 Zeroizing allowlist maintenance

The allowlist in 3.5 is load-bearing for the grep's correctness.
Stale allowlist entries (field removed from struct but still in
allowlist) are detected by the ripgrep diff: if the allowlist
contains `path/to/file.rs:removed_field` and that field is no
longer in the source, the check fails with "stale allowlist entry."
This is the counterpart to the "missing allowlist entry" failure
and keeps the file honest.

## 5. Sequencing

```text
[commits 1..3]   benchmark infrastructure
[commits 4..6]   mechanical invariants
[commits 7..8]   attack-surface hardening
        │
        ▼
2k.5a   wallet2 consumes SafetyOverrides (CLI only, no ShekylWallet* yet)
        │
        ▼
2k.5b ─ 2l       wallet2 keys/state/prefs rewire
                 dual-path output-equivalence active per §4.2
                 PR comments carry crypto/hot-path threshold deltas per §3.3
                 postcard-schema snapshot CI active per §3.4
                 Zeroizing grep CI active per §3.5
                 check_invariants running on every load per §3.6
                 adversarial corpus in test suite per §3.7
                 proptest fuzz in CI per §3.8
        │
        ▼
2m-keys           delete C++ keys path + boost serialize for keys
2m-cache          delete C++ cache path + dual-path code + wallet2_ffi_refresh
                   C++ baseline 2× gate enforced here (not on every PR)
        │
        ▼
2n                docs + CHANGELOG + remove transitional alias
                  freeze manifest hash extended to cover all three version counters
```

Commits 1–8 land in the numbered order above **with one exception**:
commit 1 can be reordered earlier if wallet2 is not otherwise
touched and the C++ bench harness is ready sooner. Commits 4 and 5
can swap. Commits 7 and 8 can swap. The benchmark pipeline (1–3)
is a dependency chain and stays ordered.

## 6. Deferred work (post-hardening-pass, pre-freeze)

Captured here explicitly so these are not forgotten and are not
subject to rediscovery.

### 6.1 Tier 2 benchmarks (dedicated runner + criterion wall-clock)

Upgrades §3.3 from Tier 1 (iai-callgrind instruction count only) to
Tier 2 (criterion wall-clock as a gated metric on a dedicated
runner). Triggered when: (a) we have reason to believe a regression
exists that is cache-behavior-sensitive and not instruction-count-
visible, or (b) we are within three months of mainnet freeze and
want wall-clock enforcement as part of the audit trail.

Cost: ~$30/mo cloud dedicated runner, or zero on self-hosted.
Self-hosted requires `require_approval_for_first_time_contributors`
plus a `benchmark-ok` PR label gated on maintainer review.

### 6.2 `#[derive(VersionedBlock)]` proc-macro

Replaces the manual `VERSION: u8` constant + snapshot check with a
compile-time cross-check: deriving `VersionedBlock` generates the
snapshot *and* emits a `const_assert!(VERSION matches schema hash)`.
Defers until post-audit because the proc-macro carries compile-time
cost and lock-in that the snapshot approach does not.

### 6.3 `scanned_pool_txs` bounded growth

Flagged as a follow-up since the V3 scanner design landed. The
`BTreeSet` grows monotonically; wallet-open latency for a long-lived
wallet drifts upward over time. Must land before mainnet freeze
because the on-disk size becomes part of the payload-framing KAT
corpus the moment KATs lock. Not in this pass because the bounded
set's invariants are non-trivial (which eviction policy, how does
reorg handling interact with eviction) and deserve their own
design doc.

### 6.4 ADDRESS_DERIVATION_MANIFEST_HASH extension

Freeze-manifest currently hashes the address-derivation KAT
corpus. Extension: hash the tuple `(format_version, {block_versions},
payload_version)` alongside it. Any drift in any counter fails the
freeze CI. Lands with the freeze commit, not in this pass.

### 6.5 Cargo-fuzz CI integration

Graduates §3.8's cargo-fuzz harness from "local-only" to "nightly
sidecar CI job." Triggered pre-freeze once the payload framing is
KAT-locked.

## 7. Reference implementation pointers

Populated as commits land. Empty until commit 1 merges.

- `bench(wallet2)` — commit 1 — §3.1 — [hash TBD]
- `bench(wallet-state)` — commit 2 — §3.2 — [hash TBD]
- `ci(benchmarks)` — commit 3 — §3.3 — [hash TBD]
- `feat(wallet-state-schema)` — commit 4 — §3.4 — [hash TBD]
- `ci(wallet-state)` — commit 5 — §3.5 — [hash TBD]
- `feat(wallet-state): check_invariants` — commit 6 — §3.6 — [hash TBD]
- `test(wallet-file): adversarial corpus` — commit 7 — §3.7 — [hash TBD]
- `test(wallet-state): fuzz harness` — commit 8 — §3.8 — [hash TBD]

Each sub-commit must cite the section of this document it
implements. Reviewers should reject sub-commits that deviate from
the categorization without a corresponding amendment here.
