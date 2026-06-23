# Staking-sim economics verdict — banded PL repair (PR 0)

**Date:** 2026-06-09 (PR 0); 2026-06-13 (PR 1.5 integer-sweep gate)  
**Verdict:** `pass` — banded float `Curve` preserves iteration-1 attractor / margin
findings (PR 0); the canonical **integer** `Curve` preserves network homeostasis
at least as well as the validated float model (PR 1.5), and is **frozen at
`WORK_MILLI_SCALE = 1_000`** for the emission-vin consensus path. Reopen on the
testnet operating-envelope criterion below.

## What changed

Replaced flat `min(work, cap)` with banded piecewise-linear `Curve` (`rust/shekyl-staking-sim/src/curve.rs`), matching `reward_arithmetic` shape.

## Sweep status

Full curated sweep set runs via `shekyl-staking-sim`. **The default backend is
`--curve-impl=integer`** (authoritative — imports
`shekyl-archival-retention::reward_arithmetic`, the minting code). `--curve-impl=float`
is opt-in exploration only and is **not authoritative** (PR 1.5: float over-reads
worst-shard redundancy by up to one replica); an unrecognized value exits non-zero
rather than silently falling back. Implemented 2026-06-13.

## Disposition (PR 0)

- **Attractor / Gini / margin-robustness:** conclusions stable under banded float (repair complete vs invalid `min(work,cap)` object).
- **Integer canonical path:** thin reconciliation KAT passes (`ε_curve ≤ 0.002`); full integer sweep comparison is PR 1.5 gate.

## PR 1.5 — integer-sweep gate (2026-06-13)

**Frame.** Not a per-point float-vs-integer equivalence proof — a *homeostasis*
read: the integer `Curve` is what the emission vin mints money with at zero
tolerance (`REWARD_EMISSION_VIN_PLAN.md` §5.4), so the gate asks whether the
integer (canonical) backend keeps the network inside every homeostasis bound at
least as well as the validated float model, and where it diverges, whether that
is within acceptable limits or needs the numbers turned.

**Method.** Full curated 325-scenario sweep run twice, `shekyl-staking-sim
--curve-impl=float` vs `--curve-impl=integer` (the latter imports
`shekyl-archival-retention::reward_arithmetic`). Homeostasis criteria are the
sim's own sub-claims (`scenarios.rs`): `covered` (`frac_under_target < 0.05 &
min_R ≥ 1`), `spread`/`spread_windowed` (`max_actor_share < 0.20 & whale_band4 <
0.20`), `deep_history` (`deep_frac_under_target < 0.10`), `churn_stable`
(`coverage_oscillation < 0.05`), `all_pass`.

**Result — integer holds homeostasis (float in parentheses):**

| Invariant | Integer | Float |
|---|---|---|
| `spread` / `spread_windowed` (whale capture) | **325/325** | 325/325 |
| `covered` | 188/325 | 188/325 |
| `deep_history` | 210/325 | 207/325 |
| `churn_stable` | 148/325 | 146/325 |
| `all_pass` | 120/325 | 119/325 |

The load-bearing read is that the integer backend is **not worse** than the
validated float object: `spread`/`spread_windowed` is 325/325 on both, and
integer is never below float on any aggregate. The +3/+2/+1 on
`deep_history`/`churn_stable`/`all_pass` is **not** a directional edge — the five
metrics are not independent (`all_pass` is the conjunction of the others), so
those deltas are one or two threshold-grazing scenarios flipping across
correlated metrics, i.e. reshuffling noise inside an unchanged envelope (incl. a
0.227 max Gini Δ). Flooring is a systematic *down*-bias, not a symmetric one
(see the tail-margin finding below); "integer ≥ float in aggregate" must not be
read as flooring being directionally benign. The bar is "integer does not
degrade the float object," and it clears it. Only **4/325** scenarios bifurcate
materially (|Δ frac_under| > 0.30), all at operating-band extremes — servo gain
400 black swans (`swan_price_gap_servo400`, `swan3_servo400_floor`,
`swan4_servo400_reseed3`) and the g≈2.5 age-weight band edge
(`layer2_coloc_g2.5`).

**Discriminating experiment (milli→micro).** Bumped `WORK_MILLI_SCALE`
1_000 → 1_000_000 and re-swept (float byte-identical, confirming the knob
isolates only integer quantization). Finer fixed-point rescued **only** the one
band-edge artifact (`layer2_coloc_g2.5`: 0→0.70 collapse → 0→0.00 stable), left
the servo-400 swans collapsed (0→0.91), and did **not** reduce the
material-bifurcation count (4→4; it swapped the band-edge scenario out for
another servo-400 swan). Aggregate homeostasis was slightly *worse* at micro
(`covered` −3, `all_pass` −1). Conclusion, split by class: **three of the four**
(the servo-400 swans) are **dynamical, not arithmetic** — servo gain 400 drives
the controller across a coverage-collapse bifurcation that no fixed-point
granularity moves. **The fourth (`layer2_coloc_g2.5`) is genuinely
quantization-driven** — micro rescued it — so the freeze at milli does *not*
validate it away; it is routed to the band-interior age-weight carry below and
the raise-`N` re-check in `ARCHIVAL_REWARD_ARITHMETIC.md` §Economic-tolerance.
The blanket "dynamical not arithmetic" headline covers three of four, not the
band edge.

**Tail-margin finding (second-pass scan, in-envelope, record-worthy).** A
directional scan of all 325 scenarios cleared the regressive-flooring fear at the
actor level — `gini_actor` (93↑/94↓) and `max_actor_share` (91↑/96↓) are
balanced, mean Δ ≈ 0, so flooring does **not** concentrate stake or creep toward
the 0.20 whale bound — but it surfaced a systematic thinning of the **redundancy
tail** that the threshold claims mask. Integer biases `min_r` *down* (26↓ vs
17↑) and `sole_source_shard_epochs` *up* (76↑ vs 49↓), concentrated where
coverage is already thinnest, and the effect is **in-envelope, not confined to
the four extremes**: the entire `p3_fee_tilt` axis (t00/t03/t06/t09) drops the
worst shard 2→1, plus `gate4_fine_6.00(_whale)`, `l11/l12/l13`, `layer2_band`,
multiple swan v-shapes; sole-source rises materially in-envelope
(`gate4_fine_6.00` 145→188, `ta1_f1_cosmetic` 90→142, `ta1_cohort_shared`
306→337). **No invariant breaks** — the zero-replication check is clean (no shard
goes to `min_r = 0` under integer that float kept ≥ 1; the one `min_r = 0`,
`ta1_cohort_shared`, was already 0 under float), so `covered`/`deep_history` do
not flip. Mechanism: `floor()` shaves marginal work-credit and the replica just
barely affording coverage under float drops below the line under integer.
**Reframe — this is not "integer degrades durability," it is "float was
over-optimistic about worst-shard redundancy by up to one replica."** Integer is
what actually mints; float credited fractional atomic units flooring discards.
The consequence is for band-tuning: redundancy / `R_target` bands tuned against
the *float* sim over-estimate real worst-shard redundancy, so they must be tuned
against the **integer backend with a +1 deep-tail replica margin**, and
`sole_source_shard_epochs` is the metric to watch on testnet.

**Disposition.** PR 1.5 **PASSES** — this closes the **economics-preservation
half (a) of M-1** ("does the integer `Curve` preserve the emergent economics"),
the half whose risk was that per-point closeness (`ε ≤ 0.002`) wouldn't
propagate to emergent properties; the homeostasis frame measures that
propagation instead of assuming it. The integer `Curve` is **frozen at
`WORK_MILLI_SCALE = 1_000` (milli)** for the emission-vin consensus path. Raising
the scale is rejected: it pays a consensus-constant cost (overflow re-audit of
every `mul_div_floor` site) for zero-to-negative homeostasis gain, and the one
scenario it rescues is out of the operating envelope anyway. **M-1's other half
(b) — cross-implementation / cross-arch bit-identical agreement for the §5.4
zero-tolerance compare — is a different property PR 1.5 does not touch**; it is
addressed by R1.B's single-source `reward_arithmetic` import plus a determinism
KAT. The arithmetic is pure fixed-width integer (no float/`usize`,
`#![deny(clippy::float_arithmetic)]`), so cross-arch bit-identity holds by
construction; the KAT is the regression guard. **KAT gap closed (2026-06-13):**
the old `determinism_curve_milli_cross_check` (same-arch double-call of
`curve_milli` only) is superseded by
`shekyl-archival-retention/tests/reward_arithmetic_determinism_kat.rs`, which
pins golden vectors across `curve_milli`, `scarcity_milli`, `g_age_milli`, the
**Form-C division** (`reward_share_floor`/`mul_div_floor`, incl. the
u128-before-divide order and a u64-product-overflow vector), and the burned-dust
supply bound, and **executes** on both `x86_64` (build.yml) and `aarch64` under
qemu-user (depends.yml). The single carry is the PR-E3 wallet-side single-source
import; see `REWARD_EMISSION_VIN_PLAN.md` §9.

**Reopen criteria.**

- **Operating-envelope (rule 21, testnet):** the servo-400 / g≈2.5 fragility is
  addressable only by operating discipline — a servo-gain ceiling and a
  band-interior age-weight target. Set and confirm these on testnet; reopen the
  freeze if testnet must operate near those edges. Per the tail-margin finding,
  tune the **testnet-tunable** redundancy / `R_target` operating bands against the
  **integer backend** (a +1 deep-tail replica margin over the float reading), and
  watch `sole_source_shard_epochs` on testnet. These bands can move post-genesis.
- **Genesis-seal (pre-genesis, blocks the seal):** the tail-margin +1 over-optimism
  applies to *every* redundancy/coverage param that gates sole-sourcing — including
  the **genesis-sealed** subset, which "watch on testnet" cannot fix because a
  sealed value cannot move without a fork. The L12 genesis deep-replica floor
  `r_target_deep` and any genesis-sealed `R_target`/redundancy floor
  (`STAKER_ARCHIVAL_SIM.md` §L12 — currently a *provisional* float-calibrated
  "post-testnet calibration") **must be re-derived against the integer backend with
  a +1 deep-tail replica margin before the seal**, so none slips into genesis at its
  float value by omission. Scope: this is an *availability* correction (Foundation
  complete-tree B+C seeds are the durability backstop), not a durability escalation.
  Tracked in `docs/FOLLOWUPS.md` (V3.0 pre-genesis queue) and
  `REWARD_EMISSION_VIN_PLAN.md` §9; closes when the final band review re-derives the
  sealed floor against integer +1.
- **Curve reshape:** integer sweep flips attractor rank, margin-robustness
  boolean, or Gini Δ beyond pinned ε in `ARCHIVAL_REWARD_ARITHMETIC.md`. A
  re-tune that reshapes the curve forces regeneration of PR-E3's economics KATs
  (cheap pre-genesis, no migration).

**Note.** `ε_curve ≤ 0.002` is a sim float-vs-integer reconciliation band only;
it never reaches consensus. The emission-vin recompute is exact-equality
(`REWARD_EMISSION_VIN_PLAN.md` §5.4 / R1.B zero-tolerance).
