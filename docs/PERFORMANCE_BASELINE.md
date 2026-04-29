# Performance baseline

This document holds the empirical performance baseline for the Stage 1
trait-boundaries migration ([`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3 *interior-mutability measurement gate*).

The §3.3 gate is **binding before Stage 1 PRs land**: this document
must be populated with measured baseline numbers and post-interior-lock
numbers before any Stage 1 trait-implementation PR opens. Reviewers
cite this document during PR review per §3.3.1's threshold-of-concern
discipline (>10% requires PR-description justification; >25% requires
optimization before merge).

This file is a template stub at Round 4b. The first Stage 1 PR fills
in the baseline numbers and the post-interior-lock numbers as part of
the PR's review surface.

## Methodology

Benchmarks are `criterion`-driven and live under
`rust/shekyl-engine-core/benches/` (path stub; the actual harness
lands in the first Stage 1 PR alongside the baseline numbers).

Each benchmark measures a single trait-method invocation under a
controlled scenario (no daemon RPC; no filesystem I/O; mocked
inputs sized to typical wallet workloads). The full set of
hot-path benchmarks per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3 is enumerated below; the Stage 1 PR may add additional hot
paths if reviewer judgment identifies them.

### Hot paths under measurement

| Trait | Method | Why hot | Baseline scenario |
|---|---|---|---|
| `KeyEngine` | `account_public_address` | Read on every UI render of the address bar; called repeatedly by send-flow address validation | Pre-derived address; single read |
| `LedgerEngine` | `balance` | Read on every UI render of the balance display; called repeatedly during send-flow input validation | 10 000-entry transfer history |
| `LedgerEngine` | `synced_height` | Read on refresh-progress polling; called every refresh-cycle iteration | (no preconditions) |
| `EconomicsEngine` | `current_emission` | Read during fee computation in send-flow (per output, per build retry); read during refresh-result aggregation | Height parameter only |
| `EconomicsEngine` | `parameters_snapshot` | Read for the V3.x adaptive-burn observation surface; called whenever observation state is queried | (no preconditions) |

## Baseline (current `dev` monolithic Engine, outer `RwLock` only)

**Status: TO BE MEASURED.** First Stage 1 PR populates these
numbers.

Baseline measurement protocol per
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3.1 (Round 4b — Item 14 baseline definition):

- Baseline = current `dev`-branch monolithic `Engine` performance
  (outer `RwLock` only, no interior locks) measured at the time of
  baseline-document creation.
- Baseline numbers are committed to this document with the commit
  SHA of `dev` at measurement time.
- If `dev` performance shifts substantively between baseline
  measurement and Stage 1 PR review (e.g., due to unrelated
  optimizations or regressions), the baseline is re-measured against
  the new `dev` and percentage deltas are recomputed.

| Hot path | Mean (ns) | p99 (ns) | Sample size | Notes |
|---|---|---|---|---|
| `KeyEngine::account_public_address` | TBD | TBD | TBD | (pending Stage 1 PR) |
| `LedgerEngine::balance` | TBD | TBD | TBD | |
| `LedgerEngine::synced_height` | TBD | TBD | TBD | |
| `EconomicsEngine::current_emission` | TBD | TBD | TBD | |
| `EconomicsEngine::parameters_snapshot` | TBD | TBD | TBD | |

`dev`-branch SHA at baseline measurement: `TBD`

## Post-interior-lock measurements

**Status: TO BE MEASURED.** First Stage 1 PR populates these numbers.

Post-interior-lock numbers reflect the same hot paths under the
Stage 1 trait-extracted implementations (per-trait interior locks,
outer `Arc<RwLock<Engine>>` still in place; per
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3.1 *Stage 1 outer-lock sequential consistency*).

| Hot path | Mean (ns) | p99 (ns) | Sample size | Δ vs baseline (mean) | Δ vs baseline (p99) |
|---|---|---|---|---|---|
| `KeyEngine::account_public_address` | TBD | TBD | TBD | TBD% | TBD% |
| `LedgerEngine::balance` | TBD | TBD | TBD | TBD% | TBD% |
| `LedgerEngine::synced_height` | TBD | TBD | TBD | TBD% | TBD% |
| `EconomicsEngine::current_emission` | TBD | TBD | TBD | TBD% | TBD% |
| `EconomicsEngine::parameters_snapshot` | TBD | TBD | TBD | TBD% | TBD% |

Stage 1 PR commit / branch at measurement: `TBD`

## Threshold-of-concern disposition per
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3

For each hot path, the percentage delta against baseline (mean) is
the canonical signal. The p99 column is an additional check for
worst-case regression that the mean might hide.

- **Δ ≤ 10%**: cost is acceptable. No further action; PR proceeds
  to merge once other review concerns are addressed.
- **10% < Δ ≤ 25%**: cost is acceptable but requires explicit
  justification. The PR description names the source of the
  overhead (e.g., specific lock acquisition adding observed
  contention) and either argues that it's intrinsic to Stage 1's
  interior-mutability shape and will disappear at Stage 4 (when
  the outer `RwLock` retires per Path B), or names a specific
  Stage 1 optimization that's deferred to a follow-up PR.
- **Δ > 25%**: cost is not acceptable as-is. The PR is sent back
  for optimization before merge. Candidate optimizations per
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3.5: narrowing critical sections; substituting
  `parking_lot::RwLock` for `std::sync::RwLock`; moving
  cached read-only values to `Arc`-published snapshots that
  bypass the lock entirely.

## Reviewer responsibility

Per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3.1 (Round 4b — Item 14):

- The Stage 1 PR reviewer confirms the baseline document's commit
  SHA matches a recent `dev` tip (within ~30 days), or triggers
  re-measurement.
- The reviewer is the named owner of this check; the PR author is
  not expected to re-measure unprompted.
- If the baseline document has not been populated at all (still
  shows `TBD` placeholders in the relevant tables), the PR is not
  reviewable — measurement is the gate, not optional metadata.

## Cross-references

- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3 — interior-mutability measurement gate (governs this document).
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3.1 — Stage 1 outer-lock sequential consistency (the implementation surface measured against).
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md) §10.2.1 — Stage 1 baseline measurement deferred entry (this document is the deliverable).
- [`FOLLOWUPS.md`](FOLLOWUPS.md) §"V3.0" — performance baseline FOLLOWUPS row (close-condition: this document populated and Stage 1 PR review consumes it).
