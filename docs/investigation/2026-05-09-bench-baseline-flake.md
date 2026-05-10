# Bench-baseline `instructions=0` flake — investigation (2026-05-09)

**Status:** root cause identified (high confidence); fix path proposed but
not yet executed.

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

## 3. The smoking gun

### 3.1 iai-callgrind issue #19

Upstream issue:
https://github.com/iai-callgrind/iai-callgrind/issues/19 —
*"Library benchmark functions with equal bodies produce event counts
of zero."*

The issue describes:
- Multiple library benchmark functions whose generated wrapper
  bodies are syntactically identical (or near-identical after
  monomorphization).
- The Rust compiler's / linker's **identical code folding (ICF)**
  pass collapses the wrappers into a single emitted function.
- iai-callgrind sets up Callgrind's `--toggle-collect=<symbol>`
  marker per bench function. When the wrapper symbols have been
  folded together at link time, the toggle for the folded-away
  symbols never matches an instruction range in the binary.
- Callgrind reports `0` instructions for the entries whose toggles
  didn't match. The run "succeeds" — Callgrind has no way to know
  the user expected a non-zero count.

### 3.2 Why our benches are vulnerable

The `with_setup` macro pattern in
`rust/shekyl-engine-state/benches/ledger_iai.rs`:

```rust
#[library_benchmark]
#[benches::with_setup(args = [100, 1_000, 10_000], setup = build_ledger)]
fn hot_path_bench_ledger_postcard_serialize(ledger: WalletLedger) -> Vec<u8> {
    black_box(ledger.to_postcard_bytes().expect("serialize"))
}
```

The `with_setup` macro generates three near-identical wrappers (one
per `args` value) — same instruction sequence, just different setup
args fed in. **All three wrappers' bodies are eligible for ICF.**

Same shape for `_deserialize`. Six wrappers total in this bench
target; each is a small `black_box(call(arg))` body whose post-
monomorphization machine code is similar enough that the linker
*can* fold them.

### 3.3 Why ICF kicks in some runs and not others

This is the part the investigation can't pin down without deeper
instrumentation. ICF is a deterministic linker pass given identical
inputs, so a candidate worth flagging is **non-determinism in the
inputs** — namely, the `target/` cache restored on a given run.
Possibilities:

- The cache restored a partial `target/release/deps/` from one of
  many slightly-different prior runs. Subsequent incremental
  compilation produced a binary whose ICF pattern matched the
  cached intermediates, and on the bad run the resulting layout
  collapsed all six wrapper symbols into one address range.
- Some build invocation took a code path that emitted slightly
  different debug info / symbol names, causing the linker to fold
  differently.
- A timing-dependent build cache ordering produced a different
  symbol layout.

The investigation did not bisect this further because the upstream
fix exists and is the correct disposition (see §4); pinpointing the
exact ICF trigger on a flaky runner is detective work whose payoff
is "we now understand a bug in software we will be replacing."

### 3.4 The upstream fix

iai-callgrind issue #19 was resolved by switching the toggle target
from per-function symbols (which ICF can fold) to a wildcard prefix
matching `iai_callgrind::bench::*`. This makes Callgrind's toggle
match against any function whose name carries the prefix, regardless
of how many of those functions the linker folded — the collected
range covers the union, and per-bench attribution comes from the
runner's parsing of the post-collection cost graph rather than from
the toggle layer.

The project also renamed: `iai-callgrind` → `gungraun`, with the
rename and an internal restructuring landing in 0.17.0
(2025-09-22). 0.17.1 (PR #525) further reworked the export-name
internals to support nested benchmark file structures, replacing
the original `#[export_name]`-based fix with an improved structure.
Latest stable: 0.17.2 (2026-02-10).

**Our workspace pins `iai-callgrind = "0.16"` across five crates.**
`0.16.1` predates both the issue-#19 fix and the gungraun rename.

## 4. Disposition options

### 4.1 Option A: Upgrade to gungraun 0.17.x (recommended)

**What it takes:**

- `Cargo.toml` changes in five crates (`shekyl-engine-core`,
  `shekyl-engine-state`, `shekyl-engine-file`, `shekyl-scanner`,
  `shekyl-tx-builder`): replace `iai-callgrind = "0.16"` with
  `gungraun = "0.17"`.
- Bench-target source changes: rename `use iai_callgrind::*` to
  `use gungraun::*` in every bench file (and any explicit module
  paths).
- CI workflow change in `.github/workflows/benchmarks.yml`: replace
  `cargo install iai-callgrind-runner` with
  `cargo binstall gungraun-runner@0.17` (or the install pattern
  upstream documents).
- `bench-baseline` branch: the saved snapshot will need to be
  regenerated under gungraun (the snapshot format may have changed
  across the rename). The simplest disposition is to delete the
  current `bench-baseline` and let the post-merge `update-baseline`
  job re-capture from scratch on the next dev push.

**What it gains:**

- Eliminates the issue-#19 flake permanently.
- Picks up the 0.17.x improvements: better DHAT support, stabilized
  metrics, more precise entry-point control.
- Tracks supported upstream — `iai-callgrind` 0.16.x is unmaintained
  by definition, and depending on an unmaintained crate for
  CI-gating measurement is design debt that compounds.

**What it costs:**

- 5 Cargo.toml edits + N bench-file import edits (probably ~20
  lines net) + one CI workflow edit + `bench-baseline` snapshot
  regeneration.
- The work is isolated to the bench harness and CI; no production
  code touches gungraun. Risk profile: low.

**Why it's the recommended path:**

- The current state is "we are running CI gating on top of a known-
  buggy measurement crate that produces silent zero-readings under
  conditions we cannot reproduce on demand." That is not a stable
  base for a release-gating signal.
- Per `15-deletion-and-debt.mdc`, debt that compounds (every PR's
  bench gate is exposed to the flake) is more expensive than work
  bounded by scope. The upgrade is bounded; the flake is unbounded.
- Per `91-documentation-after-plans.mdc`, the upgrade plan has a
  clear shape: bench harness, CI workflow, baseline regeneration.
  All three are scope-able in a single PR.

### 4.2 Option B: Stay on 0.16.x and accept periodic flakes (not recommended)

**What it takes:** nothing on the crate side. PR #35's
`baseline_zero` bucket already absorbs the symptom and surfaces it
informationally.

**What it costs:** every dev push that triggers a baseline refresh
is a coin-flip on whether the next round of PRs sees clean baseline
data or the anomaly. Each flake has to be either: (a) waited out
until the next dev push refreshes, or (b) accommodated by reading
around the baseline_zero rows during review. The cumulative review
friction across the project's lifetime is unbounded.

**Why it's not recommended:** trades a one-time bounded fix cost
for a recurring unbounded review cost, against a measurement layer
the project chose for determinism. Determinism with periodic
silent-zero is not determinism.

### 4.3 Option C: Investigate the ICF trigger further on 0.16.1

**What it would look like:** instrument the build to capture the
exact symbol layout produced under each cache-restore pattern;
construct a minimal repro that flips ICF on/off; report upstream
to iai-callgrind's archived 0.16.x.

**Why it's not the right use of time:** the upstream project
renamed and reworked the area in question; submitting to the
unmaintained 0.16.x line gets nothing landed. The detective work
is interesting but the payoff is purely educational.

## 5. Recommendation

Land **Option A (gungraun 0.17.x upgrade)** as a separate, scoped
PR off `dev` after PR #35 and PR #34 merge. PR shape:

- Title: `chore(bench): upgrade iai-callgrind 0.16 → gungraun 0.17`.
- Branch: `chore/bench-gungraun-upgrade` (or similar).
- Scope: the five Cargo.toml edits, bench-file import changes, CI
  workflow update, and `bench-baseline` regeneration.
- Pre-flight: skim `gungraun` 0.17.0 / 0.17.1 changelogs for any
  API-breaking changes that affect the `library_benchmark`
  attribute or `with_setup` patterns; if any, factor them into the
  PR's scope.

Until that lands, PR #35's `baseline_zero` bucket holds the gate
open without compromising the signal — the anomaly remains visible
to reviewers via its own labeled section, but doesn't false-fail
unrelated PRs.

## 6. Open follow-ups

- `chore/bench-gungraun-upgrade` — execute Option A. Trigger:
  after PR #35 merges to `dev`. Ownership: this branch's continuation
  or a separate PR.
- `bench-baseline` regeneration approach — coordinate with whoever
  drives the `update-baseline` job to ensure the baseline branch
  doesn't carry stale 0.16.x snapshot format after the upgrade.
- Optional: upstream a writeup of the ICF-on-cache-restore trigger
  to gungraun's issue tracker (community-good-citizen, not
  load-bearing for Shekyl).

## 7. Citations

- iai-callgrind issue #19: *"Library benchmark functions with
  equal bodies produce event counts of zero"* —
  https://github.com/iai-callgrind/iai-callgrind/issues/19
- gungraun 0.17.0 release notes (rename announcement): refer to
  the release page for `gungraun/gungraun`.
- gungraun 0.17.1 PR #525: *"Nested benchmark file structures
  were restricted by the internal usages of `#[export_name]`."*
- Bad-run workflow: GitHub Actions run `25591054624` on commit
  `647f82d5945f269245da09b3d53abcddfebb1784`.
- Last good baseline: `bench-baseline` branch commit
  `b08bf914e`, captured from `82397c50f06e392be9282d57443a7ec3aee8ead3`.
- First bad baseline: `bench-baseline` branch commit
  `2ba9a5e6f`, captured from
  `647f82d5945f269245da09b3d53abcddfebb1784`.
