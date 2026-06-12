# Archival reward arithmetic — integer substrate

**Status:** Provisional pins (stressnet reopening clause).  
**Upstream:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §4, [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3–§5.

## Crate surface

| Component | Location | Role |
|-----------|----------|------|
| `reward_arithmetic` | `rust/shekyl-archival-retention/src/reward_arithmetic.rs` | Integer `Curve`, `g(age)`, scarcity, `Σwork` helpers — **no `f64`** (`#![deny(clippy::float_arithmetic)]`) |
| `consensus_state` | `rust/shekyl-archival-retention/src/consensus_state.rs` | Pure `R_market` / `good_through` / `shard_age` / epoch-timing replay + `epoch_close_compute` (whole-epoch aggregation) |
| FFI | `shekyl_archival_epoch_close_compute` (+ `good_through`, `epoch_close_due`, `prune_below_epoch` helpers) | C++ epoch-close sweep: gather rows → one coarse compute call → store results |

**Boundary (PR 123):** all consensus arithmetic — market membership, scarcity,
curve, shard age, `R_market` / `Σwork` aggregation — lives in
`shekyl-archival-retention` and crosses the FFI as a single
`shekyl_archival_epoch_close_compute` call. The C++ LMDB layer
(`process_archival_epoch_close_at_height`) is a storage adapter: it reads
serve-credit / bond / segment rows, marshals them, and persists the returned
`R_market` and `Σwork` values. Fine-grained arithmetic FFI exports
(`curve_milli`, `scarcity_milli`, `max_claim_age_w`, `settlement_epoch_blocks`)
were deleted with their C++ callers; per `25-rust-architecture.mdc` coarse
FFI discipline, no per-row arithmetic crosses the boundary.

Constants are emitted from `config/consensus_constants.json` via `shekyl-archival-retention/build.rs`:

- `archival_reward_plateau_value_milli` (8000)
- `archival_reward_plateau_work_milli` (16000)
- `archival_reward_age_weight_milli` (2000 — sealed target `g* ≈ 2`, band `[1500, 2500]`; see §Shard age)
- `max_claim_age_w` (26)

## Economic tolerance (pinned ε)

Integer path is **canonical** for minting. Float sim (`shekyl-staking-sim`) is exploration / cross-check.
Degenerate caps (`cap ≤ 0`, non-finite) credit **zero** on both backends, matching
`curve_milli`'s zero-plateau guard — a missing cap is a degenerate curve, not uncapped pass-through.

| Metric | Tolerance | Test |
|--------|-----------|------|
| Per-work `Curve` float vs integer | `|Δ| ≤ 0.002` credited work units | `reconciliation_curve_float_vs_integer` |
| Plateau value | exact milli match | `reconciliation_plateau_cross_check` |
| Gini / attractor rank (full sweeps) | `ε_gini` TBD in PR 1.5 sweep report | `--curve-impl=integer` vs float |

If a **conclusion flips** under integer at the chosen Q-format, raise `N` (milli scale) before freezing format — do not ship divergent economics.

## Slash-enablement gate

**No production reliance on post-slash `R_market` / `Σwork` until partial per-shard slash writes `bad_interval` (F3).**  
`apply_archival_slash_one` partial path now appends `[E, ∞)` intervals; KAT row `p_id_hex: 03` in `consensus_state_kat_v1.json` exercises exclusion.

## Mint gate

No emission vin may credit outputs under provisional bands until final band review lands. CI: `scripts/ci/check_archival_reward_gates.sh` (grep for live mint paths).

## KATs

- `tests/fixtures/consensus_state_kat_v1.json` — `R_market`, `Σwork`, curve cases, partial-slash row
- `tests/fixtures/gate4_lifecycle_kat_v1.json` — phase-2 `emission` section
- Determinism: `determinism_curve_milli_cross_check` (x86 + GHA `aarch64-linux-gnu` cross-test)

## Shard age

`consensus_state::shard_age_milli(close_height, freeze_height, settlement_epoch_blocks)`
derives age from the `archival_shard_segment` `freeze_height` and
`SETTLEMENT_EPOCH_BLOCKS`, and feeds `g(age)` inside `epoch_close_compute`. C++ passes
`freeze_height` through; it does not compute age.

**Normalization (pinned 2026-06-11, Layer-2 band run).** Age is a **relative depth
fraction**, not a raw epoch count:

```text
age_epochs   = floor((close_height − freeze_height) / SETTLEMENT_EPOCH_BLOCKS)
chain_epochs = floor(close_height / SETTLEMENT_EPOCH_BLOCKS)
age_milli    = floor(age_epochs · 1000 / chain_epochs)        ∈ [0, 1000]
```

`g(age) = 1 + age_weight · age` therefore spans exactly `[1, 1 + age_weight]` for the
life of the chain: the chain-genesis band carries a constant `(1 + age_weight)×` premium
over hot, and the premium *ratio* never drifts. This is the scale-free shape the Layer-2
margin-robustness band run validated
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*Layer-2 margin-robustness band —
results*) — the sim's `g = 1 + w·age` runs on age normalized to `[0, 1]`, and the sealed
operating band `w ∈ [1.5, 2.5]` (target `≈ 2`) is in those units. The prior raw-epoch
form made `g` grow without bound (`g ≈ 700·w` for a 10-year shard at
`SEB = 10 000`), concentrating `Σwork` onto oldest-band holders over mission
timeframes — a shape no sim run ever validated and exactly the whale-capture surface
Layer 2 gates. Mapping: `archival_reward_age_weight_milli = 2000` ⇔ sealed target
`g* ≈ 2`; the calibration-band freedom is `[1500, 2500]` (per the sealed band), value
retunable on stressnet evidence within the band without re-running the design round.

Edge semantics: zero before the segment freezes past the close height, zero before the
first settlement epoch completes (`chain_epochs = 0` — everything is hot at genesis),
and `age_epochs ≤ chain_epochs` by construction so the fraction never exceeds 1000.
