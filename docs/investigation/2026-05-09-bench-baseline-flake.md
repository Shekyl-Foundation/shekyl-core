# Bench-baseline `instructions=0` flake — investigation (2026-05-09)

> **Update (2026-06-25) — gungraun did NOT fix the flake; automated the
> documented "rerun" remediation instead.** The capture still flakes to
> `instructions=0` under the latest gungraun (`0.19.2`, the newest published
> version — there is nothing to bump to), confirming the §3.3 cause remains
> unknown and the migration's flake-mitigation was, as flagged, speculative.
> Reconfirmed the bench is healthy: `engine_trait_bench_key_merge_projection`
> measures ~5.16M instructions locally and on a fresh CI runner; the zero is
> purely a capture-layer anomaly. Since the flake correlates with the
> runner-VM state at job start — a same-VM retry (the per-bench retry budget)
> does not clear it, only a *fresh* runner does — the `ci/benchmarks` workflow
> now automates the doc's own "rerun the workflow" remediation: a bounded
> `rerun-on-flake` job re-runs the failed capture on a fresh runner
> (`gh run rerun --failed`), gated on the producer guard's `*.flake.json`
> signature and bounded by `github.run_attempt < 3` (≤2 auto-reruns). A
> *persistent* zero (a genuine empty measured region) flakes on every fresh
> runner, exhausts the budget, and still hard-fails — the guard's
> never-persist-a-zero guarantee is unchanged, and no measurement is ever
> fabricated or carried forward.

<!-- -->

> **Update (2026-06-16) — migration landed as gungraun 0.19.x.** The May
> investigation's recommended disposition (§4.1 Option A) was executed at the
> time on `chore/investigate-bench-baseline-flake-2026-05-09` against gungraun
> **0.18.2**, but that branch was archived (`archive/chore-investigate-bench-
> baseline-flake-2026-05-09-2026-05-25`) **without merging to `dev`** — so `dev`
> stayed on `iai-callgrind 0.16.1` and the capture-time `instructions=0` guard
> kept hard-failing per-PR `capture-pr` jobs (observed recurring 3× in 6h on an
> open PR). The migration is now being re-landed fresh off current `dev` on
> `chore/bench-gungraun-migration`, targeting the **latest stable gungraun
> `0.19.2`** (0.19.0 bumped the harness MSRV to Rust 1.85.1 / edition 2024,
> satisfied by our 1.94 toolchain; gungraun is a dev-dependency only, so it does
> not raise any production crate's MSRV). Verified locally: all bench targets
> compile under 0.19.2 and `gungraun-runner 0.19.2` runs them under Valgrind
> producing real, non-zero instruction counts. §4 / §5 below are preserved as
> the original 2026-05-09 analysis; read this banner for what actually shipped.
> The flake-fix remains **speculative** (§3.3 cause unknown) — the trajectory /
> debt argument (§4) is what justifies the upgrade regardless.

**Status:** **cause unknown.** Initial smoking-gun hypothesis (iai-
callgrind issue #19) was withdrawn after source verification — see
§3 for the retraction. Eliminations in §2 stand. Disposition in §4
recommends a gungraun 0.17.x / 0.18.x upgrade on debt-reduction
grounds with speculative incidental flake-mitigation; the upgrade
is **not** a targeted fix because there is no confirmed target.

**Branch:** `chore/investigate-bench-baseline-flake-2026-05-09`.

**Companion landed work:** PR #35
(`chore/compare-baseline-zero` → `dev`) — the gate-unblocker that routes
`(baseline=0, pr>0)` capture anomalies into a distinct `baseline_zero`
informational bucket so PR #34 (and any future PR landing during a
flake window) doesn't false-fail. This document covers the *cause*
side; PR #35 covered the *symptom* side.

## 1. The failure shape

### 1.1 Observed on PR #34

PR #34's `ci/benchmarks` job reported six `+inf% FAIL` rows for
`hot_path_bench_ledger_postcard_*` entries:

| Bench | Baseline | PR head |
|---|---:|---:|
| `serialize/with_setup_0` (100 transfers)   | `0` | `4,453,844` |
| `serialize/with_setup_1` (1k transfers)    | `0` | `44,641,084` |
| `serialize/with_setup_2` (10k transfers)   | `0` | `447,090,124` |
| `deserialize/with_setup_0` (100 transfers) | `0` | (real number) |
| `deserialize/with_setup_1` (1k transfers)  | `0` | (real number) |
| `deserialize/with_setup_2` (10k transfers) | `0` | (real number) |

The PR-side numbers were stable and matched the prior nine baselines.
The baseline side was zero. Division-by-zero in `compare.py` produced
`+inf%`, which rendered as `FAIL` and tripped the gate.

### 1.2 What the bench-baseline branch actually contained

`bench-baseline`'s `baseline.iai.snapshot` for the bad refresh
(commit `2ba9a5e6f`, refresh from `dev` tip `647f82d59`) carried for
each of the six entries:

```
ledger_iai::ledger::hot_path_bench_ledger_postcard_serialize with_setup_0:build_ledger(100)
  Instructions:                           0|4447771              (-100.000%) [---inf---]
```

iai-callgrind format is `<this run>|<saved baseline>`, so:
- This run's measurement: `0` instructions.
- Saved baseline (from prior capture): `4,447,771` instructions.
- Reported delta: `-100%` (collapse to zero).

**The `0` was the measurement, not a parsing artifact.** The snapshot
file's text faithfully recorded what iai-callgrind reported for that
run.

### 1.3 What iai-callgrind itself thought happened

Embedded in the snapshot file at the top of the run summary:

```
6 without regressions; 0 regressed; 6 benchmarks finished in 69.0922s
```

iai-callgrind reported the run as **clean** — six benches ran, none
regressed, the run completed in normal wall-clock time. From iai-
callgrind's perspective, nothing went wrong. It just happened to
record zero instructions for those six entries.

## 2. What was ruled out

The investigation walked the candidate space from cheapest-to-falsify
to most-expensive. Each section below names a candidate and its
disposition.

### 2.1 Runner-image / toolchain drift — RULED OUT

The two baselines bracketing the transition record byte-identical
provenance in `captured_on`:

| Field | Last good (`b08bf914e`, refresh from `82397c50f0`) | First bad (`2ba9a5e6f`, refresh from `647f82d59`) |
|---|---|---|
| `cpu_model` | `Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz` | (identical) |
| `kernel` | `Linux 6.17.0-1010-azure` | (identical) |
| `rustc_version` | `rustc 1.95.0 (59807616e 2026-04-14)` | (identical) |
| `cargo_version` | `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` | (identical) |
| `valgrind_version` | `valgrind-3.22.0` | (identical) |
| `iai_callgrind_runner_version` | `v0.16.1` | (identical) |

No version drift. No runner-image change. Same CI workflow, same
hosted-runner family.

### 2.2 Code change in the bench's exercised path — RULED OUT

The diff between `82397c50f0` (last good) and `647f82d59` (first bad)
touches:

- `docs/CHANGELOG.md`
- `docs/FOLLOWUPS.md`
- `docs/design/STAGE_1_PR_3_KEY_ENGINE.md`
- `rust/shekyl-crypto-pq/src/account.rs`
- `rust/shekyl-crypto-pq/src/keys.rs`
- `rust/shekyl-engine-core/src/engine/local_keys.rs` (1 line)
- `rust/shekyl-engine-core/src/engine/refresh.rs` (1 line)
- `rust/shekyl-ffi/src/account_ffi.rs`

None of `shekyl-engine-state`'s files were touched. The bench file
`rust/shekyl-engine-state/benches/ledger_iai.rs` is bit-identical
across the transition. The `WalletLedger` and `TransferDetails` types
the bench exercises are bit-identical. The `to_postcard_bytes()` /
`from_postcard_bytes()` functions are bit-identical. The bench
literally measured the same code on both runs.

### 2.3 Cache-key drift — RULED OUT

The benchmark workflow's cache key is
`bench-rust-${{ runner.os }}-${{ hashFiles('rust/Cargo.lock') }}`.

`Cargo.lock` is unchanged between `82397c50f0` and `647f82d59`. Both
runs hit the same cache key, restored the same `~/.cargo/registry`
and `rust/target` artifacts, and rebuilt incrementally from there.
Cache-hit pattern was identical.

### 2.4 Wall-clock execution variance — RULED OUT

Per the bad-run CI logs, the six benches' progression timestamps
(start of bench → start of next bench) were:

| Transition | Good run (3:46:0X) | Bad run (4:05:5X) |
|---|---|---|
| serialize/0 → serialize/1 | 0.5s | 0.5s |
| serialize/1 → serialize/2 | 3.1s | 3.0s |
| serialize/2 → deserialize/0 | 28.1s | 27.8s |
| deserialize/0 → deserialize/1 | 0.6s | 0.6s |
| deserialize/1 → deserialize/2 | 3.7s | 3.6s |

**Wall-clock execution times match within 100ms.** Callgrind ran for
the right amount of wall-clock time on both runs. The instrumentation
machinery executed; the recorded instruction count on the bad run was
zero anyway.

### 2.5 What this leaves

The ruled-out classes above eliminate every candidate that reduces
to "the run executed differently." Both runs executed the same code
on the same hardware with the same tools for the same wall-clock
time. The only remaining surface is **iai-callgrind's measurement
layer reporting different numbers for runs that produced the same
behavior.**

## 3. Hypotheses considered, including one withdrawn

### 3.1 Withdrawn: iai-callgrind issue #19 (linker ICF + per-symbol toggles)

The first hypothesis pursued: upstream issue
https://github.com/iai-callgrind/iai-callgrind/issues/19 —
*"Library benchmark functions with equal bodies produce event counts
of zero."* The issue describes linker identical-code-folding (ICF)
collapsing wrapper functions to a single address, causing Callgrind's
per-symbol toggle markers to miss the folded-away functions and
report zero counts.

**Verification at source:**

- Issue #19 was fixed upstream in **iai-callgrind 0.7.0**
  (released 2023-09-21), per the project's CHANGELOG. The fix
  predates our 0.16.1 by nine minor versions. If the issue's
  mechanism applied unchanged to our pin, the flake would not be
  novel.
- Our `iai-callgrind-macros = 0.6.1` source contains zero
  `#[export_name]` usages. The 0.7.0 fix's described shape was
  "annotate bench functions with `#[export_name]` and use a
  wildcard `--toggle-collect`," so the 0.6.1 macros crate ships a
  *different* mitigation. Inspection shows each `#[library_benchmark]`
  emits a per-bench `mod __iai_callgrind_wrapper_mod { pub fn
  wrapper() { ... } }` whose `wrapper` symbol's full path is
  unique by virtue of the enclosing module's name (one
  `__iai_callgrind_wrapper_mod` per emitted bench-target site).
  Symbol paths are structurally distinct, not name-colliding —
  ICF on identical bodies is the variable iai-callgrind's design
  prevents at the symbol level, not the body level.
- **Empirical refutation:** nine prior baselines on this exact
  macro pattern (same `#[benches::with_setup]` shape, same
  ledger benches) produced correct, stable measurements
  (~4.4M / 44M / 444M instructions per the entry tier). If
  issue-#19's mechanism still applied to our pin, all ten
  baselines would exhibit the symptom, not one.

The hypothesis is withdrawn. iai-callgrind 0.16.1's macro design
does not exhibit the issue-#19 failure mode under our bench shape.
This was a wrong recommendation by `17-dependency-discipline.mdc`'s
standard ("when any of those claims is wrong, the recommendation
is wrong"); the retraction is recorded here rather than buried.

### 3.2 Specific concerns checked at user request

A user-driven follow-up asked whether the diff between
`82397c50f06e` and `647f82d59` introduces threading, memory-
management primitives, miswrapped types, or data-shape changes
that could plausibly affect the measurement. The diff in question
is the AllKeysBlob zeroize realignment (PR #33; 10 commits;
touches 8 files).

| Concern | Finding |
|---|---|
| New threading / `Send`/`Sync` / `Mutex` / `Arc` / `RwLock` / `spawn` | None. Diff is structural; no concurrency primitives added. |
| New `unsafe` blocks | None added. Existing unsafe paths unchanged. |
| New `mem::transmute` / `mem::forget` / `Box::from_raw` / raw pointer manipulation | None added. |
| Miswrapped primitive | `MlKem768DecapKey` is `#[repr(transparent)]` over the same `[u8; ML_KEM_768_DK_LEN]` it replaces. Layout-identical. The wrapper adds type-system protection without changing memory representation. |
| Data-shape change reaching the bench's exercised path | None. `TransferDetails` field set is unchanged across the diff; `WalletLedger` structure unchanged. The bench synthesizes transfers with `combined_shared_secret`/`ho`/`y`/`z`/`k_amount` set to `None`, so the PQC-secret-bearing fields aren't exercised. AllKeysBlob does not appear in `TransferDetails`, `WalletLedger`, the bench file's imports, or `shekyl-engine-state`'s re-exports. |
| New `Drop` glue in the bench binary | AllKeysBlob's hand-written `Drop` was replaced by `derive(ZeroizeOnDrop)`, but AllKeysBlob isn't pulled into the bench's link graph. The bench binary doesn't carry AllKeysBlob's Drop glue. |
| C++ in the bench's link image | None. Pure Rust path: curve25519-dalek, zeroize, postcard, serde. The C++ pipeline doesn't reach this bench. |

**Indirect effect that survives the survey**: shekyl-engine-state
re-compiles transitively when shekyl-crypto-pq's `rmeta` hash
changes. The bench binary gets re-emitted with potentially
different symbol layout, inlining decisions, and linker ICF
outcomes. This is mechanically plausible but unprovable from the
artifacts available, and the selectivity argument below
constrains it sharply.

**Selectivity**: in the bad-baseline run, `ledger_iai`'s 6 entries
recorded zero while `balance_iai`'s 3 entries (same run, same
workspace, same `with_setup` macro pattern, same `TransferDetails`
input type) recorded real numbers. Each `benches/*.rs` compiles
to its own binary (Cargo's bench-target convention), so cross-
target ICF cannot fold a balance_iai wrapper with a ledger_iai
wrapper. Within `ledger_iai` itself, the two wrapper functions
(serialize and deserialize) have structurally different bodies
(different parameter types, different return types, different
methods called on the bench input) — not ICF-foldable in normal
operation. Whatever the cause is, it's confined to one bench-
target binary's instrumentation in one specific run.

### 3.3 What's left as candidate

Eliminations in §2 leave the residue: the measurement layer
(iai-callgrind / Valgrind / Callgrind / runner host) returned
`0 instructions` for six bench entries whose source code, build
inputs, runtime environment, and wall-clock execution profile were
indistinguishable from the prior nine successful captures.

Candidates that remain alive and unverified:

1. **Transient Valgrind/Callgrind nondeterminism** on a specific
   GitHub-hosted runner instance — shared infrastructure can
   exhibit subtle timing-dependent or scheduling-dependent
   measurement variance.
2. **iai-callgrind cached state** in `target/iai/<crate>/...` —
   the workflow's cache restores this directory across runs.
   Whether some interaction between cached state from a prior
   run's binary and the current run's binary can produce zero
   counts isn't verified at source.
3. **Symbol-layout drift on cache-hit incremental rebuilds** — in
   theory, partial cache hits could produce binaries with subtly
   different symbol orderings than full rebuilds, even with
   `Cargo.lock` unchanged. Whether the drift can defeat
   iai-callgrind's toggle scheme isn't verified.
4. **A latent bug in iai-callgrind 0.16.1** that doesn't have a
   filed issue — open/closed-issue search of the upstream repo
   for "zero count" / "instructions zero" / similar terms turned
   up only #19 (covered above) and #364 (about
   `--collect-systime`, which we don't use).

None of (1)–(4) is proven. The investigation didn't bisect deeper
because root-cause attribution on a flake we can't reproduce on
demand has diminishing returns; the disposition (§4) doesn't
require knowing the cause.

### 3.4 Project-trajectory context (still load-bearing for §4)

Independent of the issue-#19 retraction, the upstream project
trajectory is:

- The crate renamed from `iai-callgrind` to `gungraun` in 0.17.0
  (2025-09-22). The old name is retained on crates.io but no
  longer the supported track.
- 0.17.1 reworked the wrapper module's internal structure (PR
  #525) to support nested benchmark file structures.
- 0.18.0 (2026-04-09) added parallel execution, in-memory tmpfs
  storage for new Valgrind data, and processing-while-next-runs
  pipelining.
- 0.18.1 (2026-04-10) fixed a thread-pool slowdown affecting
  multiple benchmark groups (issue #588).
- 0.18.2 (2026-04-30) is a cosmetic split of `valgrind-requests`
  with no API change.

**Our workspace pins `iai-callgrind = "0.16"` across five crates.**
0.16.1 is on the legacy track and no longer receives backports.
Whether the flake we observed is fixed in 0.18.2 cannot be claimed
without evidence — it might be, by virtue of the cumulative
internal reworks; or it might not be, if the cause is actually
runner-host-side or Callgrind-side. The upgrade is justified on
trajectory grounds; flake mitigation, if any, is incidental.

## 4. Disposition options

The disposition is now framed by §3.4's project-trajectory point,
not by the (withdrawn) issue-#19 attribution. The upgrade is
justified independently of root-cause attribution.

### 4.1 Option A: Upgrade to gungraun 0.18.x (recommended on trajectory grounds)

**What it takes:**

- `Cargo.toml` changes in five crates (`shekyl-engine-core`,
  `shekyl-engine-state`, `shekyl-engine-file`, `shekyl-scanner`,
  `shekyl-tx-builder`): replace `iai-callgrind = "0.16"` with
  `gungraun = "0.18"`.
- Bench-target source changes: rename `use iai_callgrind::*` to
  `use gungraun::*` in every bench file (and any explicit module
  paths).
- CI workflow change in `.github/workflows/benchmarks.yml`: replace
  `cargo install iai-callgrind-runner` with the gungraun-runner
  install path the upstream migration guide documents (the
  binstall recipe is `cargo binstall gungraun-runner@0.18.1`).
- `scripts/bench/capture_rust_baseline.sh`: update the runner
  binary check (`iai-callgrind-runner --version` →
  `gungraun-runner --version`) and the snapshot parser if
  upstream changed any output strings (per the migration guide,
  the summary line changed from `Iai-Callgrind result: Ok, ...`
  to `Gungraun result: Ok, ...`; environment variable prefix
  changed from `IAI_CALLGRIND_*` to `GUNGRAUN_*`).
- `bench-baseline` branch: the saved snapshot will need to be
  regenerated under gungraun. The simplest disposition is to
  delete the current `bench-baseline` and let the post-merge
  `update-baseline` job re-capture on the next dev push.

**What it gains:**

- Tracks the supported upstream — gungraun is the current main
  line, `iai-callgrind` 0.16.x is on legacy.
- Picks up cumulative reworks across 0.17.0 → 0.18.2: better DHAT
  support, stabilized metrics, parallel execution, in-memory
  tmpfs for new Valgrind data, thread-pool fix from issue #588.
- **Speculative incidental:** if the 2026-05-09 flake's cause was
  in the area gungraun reworked (wrapper module structure, output
  storage, valgrind data handling, thread pool), the upgrade
  fixes it. If the cause was elsewhere (runner-host transient,
  Callgrind-side measurement variance), it doesn't. This
  document does not claim to know which.

**What it costs:**

- 5 Cargo.toml edits + N bench-file import edits (probably ~20
  lines net) + one CI workflow edit + capture-script edit +
  `bench-baseline` snapshot regeneration.
- Risk: bench harness only. No production code touches gungraun.
- API breakage exposure: the migration guide names an explicit
  short check-list; main breakage classes are import path,
  environment-variable prefix, and post-rename binary install.
  No structural rework of bench files is required.

**Why it's the recommended path:**

- Per `15-deletion-and-debt.mdc`, depending on a renamed-and-no-
  longer-the-main-line crate for CI-gating measurement is debt
  that compounds. The upgrade is one bounded PR; the legacy
  pin's deferred cost grows with each subsequent PR's bench-gate
  exposure.
- Per `17-dependency-discipline.mdc`, the dependency-addition /
  -bump cost is justified by reuse across five crates (high
  fan-out) plus the supported-upstream property.
- The upgrade is the right move regardless of whether it
  incidentally fixes the flake — `baseline_zero` already absorbs
  the symptom, so the upgrade isn't gating anything urgent.

### 4.2 Option B: Stay on 0.16.x and accept periodic flakes (not recommended)

**What it takes:** nothing on the crate side. PR #35's
`baseline_zero` bucket already absorbs the symptom and surfaces it
informationally.

**What it costs:** every dev push that triggers a baseline refresh
is a coin-flip on whether the next round of PRs sees clean baseline
data or the anomaly. Each flake has to be either: (a) waited out
until the next dev push refreshes, or (b) accommodated by reading
around the baseline_zero rows during review. Compounding cost
across the project's lifetime is unbounded; a one-time upgrade is
cheaper.

**Why it's not recommended:** trades a one-time bounded migration
cost for a recurring unbounded review cost, against a measurement
layer the project chose for determinism. The argument applies
even if the gungraun upgrade doesn't fix the flake — the
trajectory-grounded reason stands independently.

### 4.3 Option C: Bisect the runner-side cause on 0.16.1

**What it would look like:** instrument the runner host or local
reproduction to capture the exact iai-callgrind state across
cache hit / cache miss / fresh-build patterns; identify the
specific input that flips zero-counts on; report upstream against
the unmaintained 0.16.x line.

**Why it's not the right use of time:** the cause may be
runner-host-side (which the upstream crate cannot fix even if it
wanted to) and the upstream is no longer maintaining 0.16.x.
Combining the two: the detective work pays back in understanding,
not in landing a fix that helps anyone. Better spent on the
migration.

## 5. Recommendation (executed)

**Option A (gungraun 0.18.x upgrade)** has been executed on this
branch per the user's "doc + fix on this branch" direction. The
upgrade landed as two commits on top of the three documentation
commits:

- `bench: migrate from iai-callgrind 0.16 to gungraun 0.18` —
  five `Cargo.toml` edits and seven bench-file import edits;
  `cargo update --dry-run` resolves cleanly to gungraun v0.18.2
  (lib + macros + runner all on 0.18.2 / 0.8.0); `cargo bench
  --no-run` succeeds for all seven `_iai` bench targets.
- `ci(bench): wire workflow + capture script to gungraun-runner`
  — both `cargo install iai-callgrind-runner` invocations in
  `benchmarks.yml` switched to `cargo install gungraun-runner
  --version '^0.18' --locked`; `scripts/bench/capture_rust_baseline.sh`
  preflight + version-detection + python-heredoc updated; the
  JSON envelope's `captured_on` block emitted both the legacy
  `iai_callgrind_runner_version` field and the new
  `gungraun_runner_version` field for one release cycle of
  consumer-side compatibility. (The 2026-06-16 re-land — the PR that
  actually merges, per the banner above — drops the dual-field for a
  single `gungraun_runner_version` key: nothing consumes the
  runner-version field, so no alias period was warranted. See §6.3.)

The macro API surface (`library_benchmark`, `library_benchmark_group`,
`main`, `benches::with_setup`, `black_box`) was source-compatible —
no bench-file structural changes were needed. Bench-target
filenames retain the `_iai` suffix as a stable identifier so the
manifest, `compare.py` class routing, and bench-baseline snapshot
keys all continue to resolve.

The upgrade was executed on trajectory grounds (legacy version,
supported upstream renamed), not on flake-fix grounds — the
latter remains speculative until a post-merge baseline refresh
either clears the anomaly or persists it. Until that data lands,
PR #35's `baseline_zero` bucket holds the gate open without
compromising the signal — the anomaly remains visible to
reviewers via its own labeled section, but doesn't false-fail
unrelated PRs.

## 6. Open follow-ups

### 6.1 `bench-baseline` regeneration (post-merge)

The current `bench-baseline` branch carries snapshots produced by
iai-callgrind 0.16.1. After this branch merges to dev, the next
push to dev will trigger the `ci/benchmarks` workflow's
`update-baseline` job, which will:

1. Run `scripts/bench/capture_rust_baseline.sh` under the new
   gungraun-runner.
2. Push the resulting `baseline.json` + `baseline.iai.snapshot` to
   the `bench-baseline` branch.

The workflow already handles both the "branch exists" and "branch
doesn't exist" cases (the orphan-seed path is in
`benchmarks.yml::push updated baseline to bench-baseline branch`).
Two viable dispositions:

- **Disposition 1 — let it overwrite (default).** Do nothing; the
  next dev push overwrites the bench-baseline tip with a fresh
  gungraun snapshot. The 0.16.x-captured prior tip becomes
  unreachable from the branch ref but is still in the reflog and
  can be recovered if needed. This is the simpler path and the one
  the workflow naturally drives.

- **Disposition 2 — explicit reset (cleaner audit trail).**
  Manually push an annotated tag at the current bench-baseline tip
  (`archive/bench-baseline-2026-05-09-pre-gungraun`) before merge,
  then delete the branch and let the post-merge `update-baseline`
  re-seed the orphan branch fresh. This is per `06-branching.mdc`
  rule 5 ("never delete a branch without explicit confirmation
  from the user, ideally after tagging the HEAD as
  `archive/<branch-name>-<date>`"), so it requires user
  authorization. It produces a cleaner audit trail at the cost of
  one extra step.

Disposition 1 is the default for this branch's merge unless the
user prefers Disposition 2 explicitly.

### 6.2 What the next baseline tells us

- If the next gungraun-captured baseline still produces
  `instructions=0` for some entries, this document's §3.3
  candidate list re-opens with fresh evidence: the cause survives
  the upgrade, narrowing the candidate space toward
  runner-host-side or Callgrind-side rather than the wrapper-
  module / data-storage / thread-pool reworks landed in 0.17 → 0.18.
- If the next gungraun-captured baseline is clean and stays clean
  across multiple refreshes, the project-trajectory move was the
  right call regardless of whether we ever pin down which
  specific gungraun rework was load-bearing for our case.
- If the next gungraun-captured baseline is clean for ~3–5
  refreshes and then a flake reappears, the `baseline_zero` bucket
  will catch it informationally; PR #35's machinery is the long-
  term safety net even if the flake persists post-upgrade.

### 6.3 Runner-version field rename (no alias — resolved)

The 0.18 attempt planned a one-release-cycle dual-field alias
(`iai_callgrind_runner_version` + `gungraun_runner_version`) to spare
any external consumer of `bench-baseline/baseline.json` keyed on the
legacy field. The 2026-06-16 re-land dropped that: the capture script's
JSON envelope emits **only** `gungraun_runner_version`. The
`captured_on.*_runner_version` field is provenance metadata that nothing
reads — `compare.py` keys on the top-level `iai_callgrind` *section*
(retained as a stable schema key, the only legacy name kept), not on the
runner-version field — so a clean rename was preferable to carrying alias
debt. No cleanup follow-up remains.

## 7. Citations

- iai-callgrind issue #19: *"Library benchmark functions with
  equal bodies produce event counts of zero"* (fixed in 0.7.0,
  verified retracted as smoking-gun for our 0.16.1 in §3.1) —
  https://github.com/iai-callgrind/iai-callgrind/issues/19
- iai-callgrind 0.7.0 changelog entry referencing the #19 fix:
  the upstream CHANGELOG dates this release 2023-09-21.
- gungraun 0.17.0 release notes (rename announcement): refer to
  the release page for `gungraun/gungraun`.
- gungraun 0.17.1 PR #525: *"Nested benchmark file structures
  were restricted by the internal usages of `#[export_name]`."*
- gungraun 0.18.0 / 0.18.1 / 0.18.2 changelog: parallel
  execution, tmpfs valgrind data, thread-pool fix (#588), and
  the cosmetic `valgrind-requests` extraction.
- gungraun migration check-list:
  https://gungraun.github.io/gungraun/latest/html/migration/iai-callgrind-to-gungraun.html
- Bad-run workflow: GitHub Actions run `25591054624` on commit
  `647f82d5945f269245da09b3d53abcddfebb1784`.
- Last good baseline: `bench-baseline` branch commit
  `b08bf914e`, captured from `82397c50f06e392be9282d57443a7ec3aee8ead3`.
- First bad baseline: `bench-baseline` branch commit
  `2ba9a5e6f`, captured from
  `647f82d5945f269245da09b3d53abcddfebb1784`.
