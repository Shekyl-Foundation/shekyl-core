# F-D2 drain-send subsystem — pre-flight audit trail

Sibling audit trail for `ARCHIVAL_DRAIN_SEND_FD2.md`, per
`26-sub-pr-design-discipline.mdc` §"Pre-flight pass" (the pass is
labeled **Round 0**; findings carry stable **R0-D#** IDs that must not
be renamed).

**Scope of this pass.** The **core-side** substrate DS-PR-1 and DS-PR-2
build on/against — the landed `shekyl-core` surface enumerated in the
plan doc §2.1–§2.3. The GUI-side substrate (plan doc §2.3 GUI bullets,
§2.4) lives in the separate `shekyl-gui-wallet` repo, feeds DS-PR-3/4/5,
and is gated on the native-wallet buildout (plan doc §4); it was
re-verified in design review round 2 but is **not** re-run here — each
GUI sub-PR carries its own pre-flight at open (A5 forward-action, R0-D3).

**Pin.** `shekyl-core` `dev`-merged worktree at `28870bd61`
(feature branch `feat/fd2-drain-send-scope`), 2026-07-19.

**Timing.** Run early, at maintainer direction, ahead of design-round
closure (the plan doc's §5 and DS-PR-1 cell name the pre-flight as owed
"at DS-PR-1 open"). Substrate re-check and artifact execution target
**landed code**, not the design text, so they are robust to any
remaining design-text revisions in review. A thin re-confirmation at
DS-PR-1 open (post-#342-merge) remains the standing requirement; this
pass discharges the heavy lifting (every §2 core citation verified;
every prescribed core artifact run).

---

## Round 0 — pre-flight pass (core-side)

### 1. Substrate re-check

Re-read each core-side disposition's cited source line at the pin
(rule 26 A2 audit-against-actual-code; B6 numeric/source-line variant).

| Plan-doc cite | Claim | Verified at pin | Result |
|---------------|-------|-----------------|--------|
| `drain_orchestrator.rs:80` | `struct DrainPlan` | `:80` | ✓ exact |
| `drain_orchestrator.rs:177` | maturity `spendable_height <= reference_height` | `:177` | ✓ exact |
| `drain_orchestrator.rs:218` | `pub fn drain_balance` | `:218` | ✓ exact |
| `drain_orchestrator.rs:243` | `pub fn plan_drain` | `:243` | ✓ exact |
| §2.1 | planner fee-agnostic (no fee operand in the three stages) | zero `\bfee\b` matches in `drain_orchestrator.rs` | ✓ confirmed |
| `drain_amount.rs` / `drain_select.rs` | `fd1_arm_*` self-grep guards live | `drain_amount.rs:106`, `drain_select.rs:167` | ✓ present |
| `claim_orchestrator.rs:6–63` | six-step pipeline; `PersonaIsolatedTransport` only; `CurveTreeHandle::assemble_tx`; `StakeEngine` actor signing | module doc + `:86`/`:302` | ✓ confirmed |
| `claim_dispatch.rs` | CB-3 seam; persist-before-dispatch; `reserved_gindexes` union | `:32`/`:216`/`:335` | ✓ confirmed |
| `payload.rs:126` | `PScanStatePostcard = 0x02` | `:126` | ✓ exact |
| `handle.rs:594–650` | pscan seal/open (distinct payload kind) | `save_pscan_state:600`, `open_pscan_state:626` | ✓ within range |
| `start.rs:520` | `Engine::start_pscan_if_staker` | `:520` | ✓ exact |
| `start.rs:504` | docstring "the open path found `staking_enabled`" | `:504` | ✓ exact |
| `lifecycle.rs:441–463` | tenant calls unconditionally at open, parks handle | fn `:451`, call `:453` | ✓ within range |
| `handlers.rs:48` | wallet-rpc `"stake"` route | **actual `:51`** (`"stake" => lifecycle::stake(...)`) | ✗ **drift — R0-D1** |
| `bond_orchestrator.rs:537` | `Engine::first_stake` | `:537` | ✓ exact |
| `stake_persist.rs:150` | `staking_enabled = true` (setter terminus) | `:150` | ✓ exact |
| `tx_fee_model.rs` | `predict_weight`/`fee_from_weight`/`converge_fee` (weight-only fee) | `:196`/`:330`/`:336` | ✓ confirmed |

**R0-D1 (B6 — source-line drift).** §2.3 cited the wallet-rpc `"stake"`
route at `handlers.rs:48`; the actual dispatch is `handlers.rs:51`
(`"stake" => lifecycle::stake(tenants, params).await`, routing to
`Engine::first_stake` via `lifecycle::stake`). Attributable to `dev`
merge line-shift. **Disposition:** plan-doc errata applied 2026-07-19
(§2.3 now cites `:51`, via `lifecycle::stake`); the chain terminus
(`first_stake:537` → `stake_persist:150`) was independently verified
exact, so the disposition it supports (production `staking_enabled`
setter exists) is unaffected. Every other core-side cite verified exact
or in-range.

**R0-D2 (A2 — dispositions hold).** No falsified-justification: every
DS-PR-1/DS-PR-2 core disposition is supported by the code at its cited
line. The planner is genuinely fee-agnostic (grep-clean of `fee`), the
`fd1_arm_*` guard template is live, the claim path's transport pin /
single-snapshot assemble / actor-held signing / persist-before-dispatch
are all present, and the P-scan persistence + staker-gate lifecycle
precedent is intact.

### 2. Artifact execution

Ran the behavioral artifacts the plan leans on (rule 26 B9 frame).

| Suite | Filter | Result |
|-------|--------|--------|
| `shekyl-engine-core` | `drain_ fd1_arm predict_weight converge_fee fee_from_weight start_pscan_if_staker` | **18 passed, 0 failed** |
| `shekyl-engine-file` | `pscan` | **5 passed, 0 failed** (+1 doctest) |

Notable coverage confirmed green: `fd1_arm_amount_stage_reads_scalar_not_vector`,
`fd1_arm_select_stage_names_no_lineage_type` (F-D1 self-grep guards);
`drain_balance_sums_only_mature_outputs`, `plan_drain_selects_largest_first_and_returns_change`,
`plan_drain_rejects_target_over_spendable_scalar`, `immature_outputs_are_not_selected`
(planner maturity + largest-first + refusal); `predict_weight_matches_wire_weight`,
`converge_fee_is_stable_within_two_passes` (weight-only fee, T-DS-1 impl leg);
`start_pscan_if_staker_is_none_for_a_non_staker` (staker-gate lifecycle);
`kat_pscan_state_kind_byte_is_byte_stable`, `pscan_state_seals_and_opens_round_trip`,
`pscan_loader_refuses_a_swapped_principal_state_file` (P-scan persistence + isolation).

**R0-D3 (B9 frame — no measurement-gated budget).** This subsystem
carries **no bench-gated threshold**: the plan-doc prescribes no
runtime/allocation budget, and the artifacts above are behavioral
guards, not measurements reconciled against a numeric gate. B9's
estimate-vs-empirical failure mode (`compute_hash_alloc` 296 ms vs
100 µs label) therefore does not apply here — recorded explicitly so a
later reader does not look for a missing `BENCH_RESULTS.md`. All
behavioral artifacts pass at the pin.

### 3. Scope boundary (carry)

**R0-D3-B (A5 — GUI-side pre-flight carried).** The GUI-side substrate
(plan §2.3 GUI bullets, §2.4 — `EngineSession`, engine-backend default,
`activate_staker`, `wrap_and_start_pscan`) lives in `shekyl-gui-wallet`
and feeds DS-PR-3/4/5. Re-verified in design review round 2; **not**
re-run in this core-side pass. Each GUI sub-PR runs its own pre-flight
at open, against the gui-wallet pin at that time, and DS-PR-3 is
additionally gated on the native-wallet buildout (plan §4). Close each
carry when the target sub-PR lands.

---

## Disposition summary

| ID | Class | Finding | Disposition |
|----|-------|---------|-------------|
| R0-D1 | B6 source-line | `handlers.rs:48` → actual `:51` | Errata applied to plan §2.3; chain terminus independently verified |
| R0-D2 | A2 substrate | All core dispositions hold at pin | Discharged — no falsified justification |
| R0-D3 | B9 frame | No measurement-gated budget; behavioral artifacts all green (24) | Discharged — N/A recorded |
| R0-D3-B | A5 forward | GUI-side pre-flight (DS-PR-3/4/5) | Carried to each GUI sub-PR's open |

**Core-side pre-flight (DS-PR-1/DS-PR-2): discharged at `28870bd61`,
2026-07-19.** One errata (R0-D1), no design-invalidating finding, all
core artifacts green. GUI-side pre-flight carried (R0-D3-B). Thin
re-confirmation at DS-PR-1 open (post-#342-merge) remains the standing
rule-26 requirement.
