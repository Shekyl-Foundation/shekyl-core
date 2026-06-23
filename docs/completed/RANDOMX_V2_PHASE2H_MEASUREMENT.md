---
name: RandomX v2 Phase 2h measurement methodology
overview: "Pass-3 (substrate-derived constant validation) measurement methodology and committed-result substrate for RANDOMX_V2_PHASE2H_PLAN.md Round 3 close artifact 1. Defines the per-recipe latency measurement on GitHub-hosted runners (ubuntu-latest) that produces RUNNER_NOISE_MARGIN, the Claim 2 per-class threshold, and the per-recipe sample budget. Per M1 the methodology and results are committed substrate — divergence of measured-on-runner from committed-here is a substrate finding routed back to Round 3 absorption."
isProject: false
---

# RandomX v2 — Phase 2h measurement methodology

## 1. Purpose

Phase 2h Round 3 (pre-implementation round) §11 entry names three
measurement-dependent constants whose values are deferred to the
implementation-PR's first commit per M1's canonical-output-substrate
discipline:

- `RUNNER_NOISE_MARGIN` — GitHub-hosted runner variance margin
  applied to Claim 1's per-recipe max-ratio hard gate (R1-D5
  close).
- `CLAIM_2_THRESHOLD` — per-class systematic-regression threshold
  for Claim 2's tracking signal (R1-D5 close; provisional `1.5×
  corpus_median`).
- `SAMPLE_BUDGET_PER_RECIPE` — number of timing samples drawn per
  recipe per side (Rust + C) for the per-PR cadence (R1-D6 close;
  provisional `100`).

The measurement that produces these constants is itself
load-bearing substrate per the
[`M1 committed-canonical-outputs discipline`](./RANDOMX_V2_PHASE2H_PLAN.md):
the methodology defines what is measured, on what substrate,
under what acceptance rules; the results pin the substrate-derived
values; divergence of any future measurement from the committed
values is a substrate finding.

This document is the **methodology side** of the M1 pairing.
The **results side** lives at the same commit in
[`rust/shekyl-randomx-differential/src/adversarial_canonical_outputs.rs`](../../rust/shekyl-randomx-differential/src/adversarial_canonical_outputs.rs)
as the `RUNNER_NOISE_MARGIN`, `CLAIM_2_THRESHOLD`, and
`SAMPLE_BUDGET_PER_RECIPE` `pub const` items with their rationale
rustdoc citing back here.

## 2. Substrate calibration

### 2.1 Runner class

**Pre-genesis pin: GitHub-hosted `ubuntu-latest` runner class.**
Per Phase 2h Round 1 R1-D7 close, the per-PR cadence runs on
GitHub-hosted runners; self-hosted runners are explicitly deferred.
This methodology calibrates against the `ubuntu-latest` runner
class only; self-hosted runners are out of scope until R1-D7's
reversion-clause-discipline reopening criteria fire.

The `ubuntu-latest` runner class is GitHub's standard hosted-Linux
runner. As of 2026-05-26 the spec is **4 vCPUs, 16 GB RAM, x86_64**;
the underlying hypervisor and CPU family vary by allocation pool.
Variance across allocations is the dominant source of measurement
noise that `RUNNER_NOISE_MARGIN` absorbs.

### 2.2 Runner-class variance characterization

`RUNNER_NOISE_MARGIN` is calibrated against the empirical distribution
of per-recipe latency-ratio measurements (Rust median / C median)
across **N ≥ 5 independent CI runs of the same recipe set on
`ubuntu-latest`**. The margin is set to:

```text
RUNNER_NOISE_MARGIN = max(observed runner-class variance σ) × 3
```

The `× 3` factor is the standard "3-sigma" headroom for a Gaussian
runner-class distribution (covers ≥99.7% of allocations). If the
observed distribution is non-Gaussian (long-tail; bimodal across
allocator pools), the margin is set to the 99.7th-percentile of the
observed distribution and a substrate-finding note is queued for
rule-26 amendment.

Per `21-reversion-clause-discipline.mdc`, the `× 3` factor's
reopening criteria:

- Observed runner-class variance distribution becomes non-Gaussian
  (criterion: 2+ measurement runs show the 99.7th-percentile differing
  from `μ + 3σ` by more than 10%); migrate to percentile-based margin.
- Self-hosted runners come online (R1-D7 reopening clause); recalibrate
  per runner class.

### 2.3 Provisional values at C1 (this commit)

Three values land at C1 as **provisional** (measurement-derived values
replace them at the next implementation-PR commit after CI runs the
bench harness):

| Constant | Provisional value | Anchor for provisional choice |
| --- | --- | --- |
| `RUNNER_NOISE_MARGIN` | `0.20` (20%) | Conservative pre-measurement estimate for GitHub-hosted runner-class variance based on industry baselines for shared hypervisor allocation. Per `17-dependency-discipline.mdc`-style discipline: estimated, not measured; refinement under measurement is the M1 expected case. |
| `CLAIM_2_THRESHOLD` | `1.5` (×) | Direct quote from R1-D5 close framing (per-class median ratio `>1.5× corpus_median` is the systematic-regression signal). Pre-measurement value pin; replaced by measurement if the initial recipe set shows a per-class distribution that warrants tighter or looser pinning. |
| `SAMPLE_BUDGET_PER_RECIPE` | `100` | Direct quote from R1-D6 close framing. Per-recipe per-side sample budget; bounded above by R1-D6's 10-minute per-PR cadence (Pass 4 estimate: 25 recipes × 200 samples × ~100ms = ~8.5 minutes). Pre-measurement value pin; replaced by measurement if the actual per-sample latency on `ubuntu-latest` runners differs from the ~100ms estimate. |

## 3. Measurement procedure

### 3.1 Bench harness invocation

The measurement is produced by the
[`mode_adversarial_ratio::run`](../../rust/shekyl-randomx-differential/src/mode_adversarial_ratio.rs)
orchestrator (the R1-D5 close measurement mode that replaced the
historical `mode_worst_case` deferred stub) and is exercised at
the test layer by the
[`worst_case_ratio`](../../rust/shekyl-randomx-differential/tests/worst_case_ratio.rs)
T6 integration test. The "per-recipe latency" measurement and
T6 share an implementation rather than living as separate
integration tests; the early-plan `tests/per_recipe_latency.rs`
shape consolidated into T6 during R1-D5 close because the
ratio's per-recipe sampling and the latency's per-recipe
sampling consume the same evaluator output.

Invocation (release-mode, `RANDOMX_V2_INSTALL_DIR` set per the
harness build contract; see
[`randomx-v2-adversarial-ratio.yml`](../../.github/workflows/randomx-v2-adversarial-ratio.yml)
for the CI invocation shape):

```bash
RANDOMX_V2_INSTALL_DIR=<install-prefix> \
  cargo test --release --locked \
    --package shekyl-randomx-differential \
    --test worst_case_ratio \
    -- --ignored --nocapture
```

The test is `#[ignore]`-gated at the source level so it does not
run on default `cargo test` invocations (per Phase 2g §5.3 / §9
test-cadence discipline). Per R1-D6 close Reframe 2 + R1-D7
Sub-A close, T6 runs at the `workflow_dispatch` cadence
(pre-genesis) and at the release-gate cadence (post-genesis) via
the dedicated `randomx-v2-adversarial-ratio.yml` workflow rather
than the per-PR `randomx-v2-differential.yml` workflow — the
~100-samples-per-recipe-per-side budget is too expensive for
per-PR cadence even at C4 starter-corpus scale.

### 3.2 What gets measured

For each recipe in the corpus, the harness performs:

1. Derive the cache from the recipe's base seedhash via the C
   reference's `randomx_alloc_cache + randomx_init_cache +
   randomx_get_cache_memory` path (R1-D2's C-side-symmetry
   close).
2. Apply the recipe's modifications to the cache bytes per the
   recipe evaluator (R1-D3's first-class interpreter; landed
   at C3 of the implementation plan).
3. Run `SAMPLE_BUDGET_PER_RECIPE` Rust-side `compute_hash`
   timing samples; record median.
4. Run `SAMPLE_BUDGET_PER_RECIPE` C-side
   `randomx_calculate_hash` timing samples; record median.
5. Compute `per_recipe_ratio = rust_median / c_median`.

The corpus median across all per-recipe ratios is then computed for
Claim 2's per-class systematic-regression check.

### 3.3 Acceptance rules

**Claim 1 (per-recipe max-ratio hard gate):** for every recipe, the
per-recipe ratio must satisfy:

```text
per_recipe_ratio ≤ 5.0 - RUNNER_NOISE_MARGIN
```

A single retry on borderline failure (recipe within 1% of the gate)
absorbs single-allocation noise per R1-D5's single-retry-noise-filter
close. A second failure after retry is a hard gate violation; the CI
job fails with an actionable failure-output JSON record per R1-D6.

**Claim 2 (no per-class systematic regression — tracking signal):**
for every recipe class (Category 1 audit-anchored, Category 3
boundary-value), the per-class median ratio must satisfy:

```text
per_class_median_ratio ≤ CLAIM_2_THRESHOLD × corpus_median_ratio
```

Claim 2 is a regression-tracking signal, not a hard gate per R1-D5;
violation routes to a CI-warning + nightly investigation, not an
immediate PR-blocking failure (the per-PR cadence catches systematic
regression as it accumulates rather than blocking on a single
recipe's class shifting).

## 4. Result-substrate commit shape (M1 pairing)

Per M1, the measurement methodology + results live as committed
substrate. Each measurement run produces:

1. **The three constants** committed to
   `adversarial_canonical_outputs.rs` as `pub const RUNNER_NOISE_MARGIN: f64`,
   `pub const CLAIM_2_THRESHOLD: f64`, `pub const SAMPLE_BUDGET_PER_RECIPE: usize`.
2. **The methodology** committed to this file (substrate-anchored
   description of *how* the values were derived).
3. **The measurement-run metadata** committed to
   `adversarial_canonical_outputs.rs` as `pub const MEASUREMENT_RUNNER_CLASS:
   &str`, `pub const MEASUREMENT_RUN_COUNT: usize`,
   `pub const MEASUREMENT_OBSERVED_VARIANCE: f64` — substrate
   for future audits to verify the committed constants against the
   recorded measurement basis.

The per-recipe latency integration test (`tests/per_recipe_latency.rs`)
asserts measured-on-this-runner values are within
`RUNNER_NOISE_MARGIN` of the committed values; divergence is a
substrate finding per R3's "substrate-finding-class outcome promotes
rule-26 amendment trigger from queued to fire" close criterion.

## 5. Reopening criteria

Per `21-reversion-clause-discipline.mdc`, the measurement-methodology
reopens for re-derivation if any of:

- **R1**: GitHub-hosted runner-class spec changes (e.g., vCPU count
  bump, RAM bump, x86_64 → ARM cutover). Trigger: GitHub publishes
  a substrate-change announcement for `ubuntu-latest`; re-measure
  and re-pin.
- **R2**: Recipe corpus size grows past R1-D6's smoke-subset
  transition trigger (~40 recipes at the current per-recipe runtime).
  Trigger: corpus reaches ~40 recipes; the cadence-corpus alignment
  per R1-D6 may require re-measuring SAMPLE_BUDGET_PER_RECIPE under
  the smoke-subset's reduced sample budget.
- **R3**: Self-hosted runner class comes online (R1-D7 reversion).
  Trigger: self-hosted runner CI job lands; measure separately on
  the new runner class; commit per-runner-class constants.
- **R4**: Pass-3 measurement on first implementation-PR CI run
  diverges from the provisional values committed at C1 by more than
  `RUNNER_NOISE_MARGIN`. Trigger: substrate finding; refine constants
  via amendment commit; pre-implementation-discipline-class trigger
  fires per R3 §11 close.

Each reopening re-runs the §3 measurement procedure and re-commits
the M1 substrate pair (methodology + results).

## 6. Related substrate

- **Phase 2h Round 1 close**: R1-D5 (Claim 1 / Claim 2 framing),
  R1-D6 (sample-budget framing), R1-D7 (runner-class + workflow
  placement).
- **Phase 2h Round 3 close**:
  [`RANDOMX_V2_PHASE2H_PLAN.md`](./RANDOMX_V2_PHASE2H_PLAN.md) §11
  "Round 3 — pre-implementation round" — names this measurement
  as the first round-close artifact.
- **Phase 2g §4.6 M1** committed-canonical-outputs discipline:
  [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md) §4.6.
- **Rule references**:
  [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
  (reopening-criteria discipline);
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
  (pre-implementation round + rule-26 amendment-trigger);
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
  (substrate-anchored-evidence discipline).
