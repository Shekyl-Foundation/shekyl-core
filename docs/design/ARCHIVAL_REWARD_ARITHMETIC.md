# Archival reward arithmetic — integer substrate

**Status:** Provisional pins (stressnet reopening clause).  
**Upstream:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §4, [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3–§5.

## Crate surface

| Component | Location | Role |
|-----------|----------|------|
| `reward_arithmetic` | `rust/shekyl-archival-retention/src/reward_arithmetic.rs` | Integer `Curve`, `g(age)`, scarcity, `Σwork` helpers — **no `f64`** (`#![deny(clippy::float_arithmetic)]`) |
| `consensus_state` | `rust/shekyl-archival-retention/src/consensus_state.rs` | Pure `R_market` / `good_through` replay for KATs |
| FFI | `shekyl_archival_curve_milli`, `shekyl_archival_scarcity_milli` | C++ epoch-close sweep |

Constants are emitted from `config/consensus_constants.json` via `shekyl-archival-retention/build.rs`:

- `archival_reward_plateau_value_milli` (8000)
- `archival_reward_plateau_work_milli` (16000)
- `archival_reward_age_weight_milli` (1000)
- `max_claim_age_w` (26)

## Economic tolerance (pinned ε)

Integer path is **canonical** for minting. Float sim (`shekyl-staking-sim`) is exploration / cross-check.

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

`archival_shard_age_milli(shard, close_height)` derives age from `freeze_height` in `archival_shard_segment` and `SETTLEMENT_EPOCH_BLOCKS`. Inputs `g(age)` at epoch close.
