# Staking-sim economics verdict — banded PL repair (PR 0)

**Date:** 2026-06-09  
**Verdict:** `hold` — banded float `Curve` preserves iteration-1 attractor / margin findings; reopen bands only on integer sweep failure (PR 1.5).

## What changed

Replaced flat `min(work, cap)` with banded piecewise-linear `Curve` (`rust/shekyl-staking-sim/src/curve.rs`), matching `reward_arithmetic` shape.

## Sweep status

Full curated sweep set runs via `shekyl-staking-sim` (default `--curve-impl=float`). Integer path: `--curve-impl=integer` imports `shekyl-archival-retention::reward_arithmetic`.

## Disposition

- **Attractor / Gini / margin-robustness:** conclusions stable under banded float (repair complete vs invalid `min(work,cap)` object).
- **Integer canonical path:** thin reconciliation KAT passes (`ε_curve ≤ 0.002`); full integer sweep comparison is PR 1.5 gate.
- **Reopen criteria:** integer sweep flips attractor rank, margin-robustness boolean, or Gini Δ beyond pinned ε in `ARCHIVAL_REWARD_ARITHMETIC.md`.
