# Stage 1 PR 7 — `EconomicsEngine` extraction — design

**Status.** **Round 0 closed (2026-05-27);** feedback folded same day. Round 1
open — load-bearing
question reframed to `ChainEconomicsSource` + shared primitives; **F4 grep
closed** (see §3.5). Planning doc branch:
`feat/stage-1-pr7-economics-engine-design` → PR to `dev`. Opened from `dev`
tip `2cf4cbfde` (post–PR #82 `PersistenceEngine` design merge). This document
follows [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and cites
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
explicitly.

**Round 0 reopen criterion (trait identity / scope guard) is NOT triggered** —
the four-method consume-not-subsume shape was settled in the PR-construct economics
round (2026-05-08) and §2.7 is that decision crystallized. Round 0 feedback
corrects **substrate, framing, inventory, lens citations, and test posture**
only.

**Stage 1 is not complete after this PR.** PR 6 (`PersistenceEngine`
implementation) may still be in flight on `dev`; PR 7 is the **remaining
required trait surface** for the seven-trait Stage 1 inventory. Update
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §1 status
banner and [`FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 closeout inventory only after
**both** PR 6 implementation and PR 7 implementation land. Do not link to
`STAGE_1_COMPLETION_AUDIT.md` — that doc is not yet in the tree (per FOLLOWUPS).

**Branch (design).** `feat/stage-1-pr7-economics-engine-design` off `dev` at
`2cf4cbfde` — **doc-only** revisions until Round 3 closes and Phase 0 amends
§2.7 if Round 2 close-out confirms no surface amendment. Implementation branch
`feat/stage-1-pr7-economics-engine` cuts the post–Phase-0 `dev` tip per PR 2 /
PR 4 / PR 5 precedent.

**Cross-references.**

- **Spec (binding).**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.7 (`EconomicsEngine` trait surface + scope guard), §2.8 (spawn graph —
  Group A leaf), §3 (composition — `E` slot, `LocalEconomics`), §4
  (idempotency / sync reads), §7 (invariants — `Result` ceremony), §8.1
  (off critical path; may interleave with PR 6), §8.2 (amendment co-landing),
  §8.3 (lens table — `EconomicsEngine` **bounded**).
- **Economic rationale (consumed, not re-derived).**
  [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) (CALIBRATION gate),
  [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md)
  (wallet vs consensus boundary).
- **Provenance (Round 0 substrate).**
  - **2026-05-08 — economics trait shape.** Supertrait composition
    (`EconomicsEngine: EconomicsParameters + StakeState + …`) **rejected** for
    consume-not-subsume: `StakeEngine` (Phase 2b) and `ArchivalEngine` (V3.x)
    *consume* `EconomicsEngine`. `pool_weighted_total` is the **canonical
    denominator** for future `StakeEngine::projected_yield`. The rejected branch
    carried `unimplemented!()` stubs; PR 7 flips away from that trajectory.
  - **2026-04-08 — stake-claim timing.** Consensus recomputes accrual/burn
    independently. Wrong wallet-side derivation → **failed-send / wrong-display**,
    not theft. Anchors `burn_fraction` threat narrowing (§3.2).
- **Per-PR template / process.**
  [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md),
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
- **Prior PRs (shape precedent).**
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md),
  [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](STAGE_1_PR_6_PERSISTENCE_ENGINE.md).
- **Performance gates.**
  [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) — deferred benches
  `engine_trait_bench_economics_current_emission`,
  `engine_trait_bench_economics_parameters_snapshot`.
- **Test vectors (real-path).**
  [`docs/economics_sim_results.json`](../economics_sim_results.json),
  `docs/test_vectors/PQC_TEST_VECTOR_*.json` (pattern precedent — recorded real
  outputs, not synthesized expectations).

Subsequent revisions land each design round **inline** per template §2 and PR 5 /
PR 6 precedent.

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this PR touches it |
|----------|-------------------------|
| **1 — Security** | **Primary.** Centralizes canonical economic derivations so Bug 2 / 7 / 13 class cannot recur. Does **not** add wallet-side consensus enforcement (§2.7). |
| **2 — Privacy** | Indirect only: economics methods return public parameters and aggregates. |
| **3 — System longevity** | **Primary.** `E` slot + trait surface before Phase 2b / V3.x consumers; V3.x adaptive-burn state stays inside implementor without surface churn (§3.6). |

**Preserve by name (§2.7 scope guard):** canonical derivation only; not
enforcement, not network observability, not economic-rationale documentation;
not collapsed into `StakeEngine` / `ArchivalEngine`.

### §1.1 Calibration vs structural boundary

Reconciles *"adjusted as we learn on testnet"* with *"design decisions are made to
last"*: a hard line between **mechanism (structural, locked)** and **calibration
(pre-genesis tunable, genesis selection)**.

| Structural — change here is a planning failure | Calibration — change here is genesis selection, not a fork |
|---|---|
| §2.7 trait surface (four methods) | `burn_base_rate` response curve + burn coefficients |
| `ChainEconomicsSource` injection seam (§3.9) | `release_multiplier` baseline + `RELEASE_MIN`/`MAX` clamps |
| 0h primitive *location* (`base_block_reward(already_generated)`) | `staker_pool_share` / `staker_emission_share` + decay |
| JSON-authority / `EconomicParams` loading pattern | `FINAL_SUBSIDY` floor |
| `as_of` / param-epoch discriminator | specific *values* behind all of the above |
| u128 lo/hi reconstruction; conservation invariant | (ESF = 22 already resolved — locked) |

**Discipline:** everything tunable lives behind `config/economics_params.json` /
`EconomicParams`. Recalibration is config regen — never surface or code-shape
change. The wargame makes the surface absorb foreseeable calibration (chiefly
release-multiplier / activity inputs) **without wiring them now**.

**Marked in doc and code (implementation PR):**

- **Code.** Module-level `CALIBRATION-PENDING` on `shekyl-economics` constants
  block and `LocalEconomics`: surface stable; values subject to pre-genesis
  testnet recalibration. `as_of` / param-epoch carries a **calibration-generation
  tag** (triple duty: V3.x adaptive-burn staleness, cache-poisoning detection,
  calibration traceability).
- **Docs.** CALIBRATION gate in this doc,
  [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md),
  [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md).
- **Milestone.** **CALIBRATION** is distinct from stressnet (Phase 7.7). Stressnet
  = load survival; calibration = coefficient correctness. Different exit criteria.
- **KATs.** *Generation-invariant* tests (engine-vs-sim differential on shared 0h
  primitive — survives every recalibration) vs *calibration-tagged value vectors*
  (specific emission/burn at heights — expected to churn each generation).

**Three timeframes:**

| Timeframe | Addresses | Does not address |
|-----------|-----------|------------------|
| **Now (V3.0)** | Trait + `LocalEconomics` + `ChainEconomicsSource` + real-path tests + `E` slot | Phase 2b stake FSM; V3.x adaptive-burn `Mutex` in implementor |
| **Mining era end** | Math via `shekyl-economics` + JSON authority | Fee-market UX |
| **V4 lattice** | No trait-surface effect | PQC orthogonal |

---

## §2 Scope

### §2.1 In-scope

1. **`EconomicsEngine` trait** — `engine/traits/economics.rs` + `traits/mod.rs`
   re-export (`pub(crate)`).
2. **`LocalEconomics` implementor** — `engine/local_economics.rs`; thin wrapper
   over `shekyl-economics` + **`ChainEconomicsSource`** (§3.9).
3. **`ChainEconomicsSource` seam** — narrow implementor-side trait: exactly two
   reads — `already_generated_coins()` and `active_weighted_stake()`. One
   production adapter over **recorded real chain-mirror state** (regtest/testnet
   accrual table + real `already_generated` values). **No** `LedgerEngine`
   amendment (§8.2 co-land avoided); **no** type-erased closures.
4. **Supporting types** — `EconomicsError`, `EconomicsParametersSnapshot`
   (incl. `as_of` / calibration-generation tag), `ActivityMetric`.
5. **`Engine` parameterization** — `E: EconomicsEngine = LocalEconomics`;
   field `economics: E`. Incremental order: `E` after `L` (§3.10).
6. **Workspace wiring** — `shekyl-economics` dep on `shekyl-engine-core`.
7. **0h primitive** — `base_block_reward(already_generated_coins: u64) -> u64`
   in `shekyl-economics`; shared with `shekyl-economics-sim` and FFI. Emission is
   path-dependent ([`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) — honest input.
8. **Real-path tests** — `LocalEconomics` over production `ChainEconomicsSource`
   + recorded fixtures (`economics_sim_results.json` spirit; regtest accrual
   tables). **Headline:** engine-vs-sim **differential** — both call 0h; any
   inequality is Bug-2-class drift. **No mock** in the loop.
9. **Performance gates** — both deferred economics benches + baseline rows.
10. **Docs** — this design doc, `CHANGELOG.md`, trait rustdoc, calibration
    banners in economic docs.

### §2.2 Out-of-scope

| Item | Where |
|------|--------|
| `MockEconomics` / §6.1 Mock-X pattern | **Removed** — contradicts project real-path testing value and 2026-05-08 stub-avoidance trajectory |
| `PersistenceEngine` implementation | PR 6 |
| `KeyEngine` on `Engine<S, …>` | FOLLOWUPS |
| Full `<S, K, L, E, D, F, R, P>` reorder | Deferred with `K` |
| `StakeEngine` / `ArchivalEngine` | Phase 2b / V3.x |
| Wallet-side consensus enforcement | `shekyl-consensus` |
| V3.x observer-feed / activity-push surface | No named V3.0 consumer — narrow seam only |
| Inventing `already_generated_coins` mirror in engine | **F4 grep: not mirrored today** (§3.5) — use interpretation **(A)** |
| `Mutex<AdaptiveBurnState>` | V3.x Component 3 |
| Stage 4 `EconomicsActor` | §2.8.3 |
| Orchestrator consumers of economics at V3.0 | §3 — no `Engine<S>` callers yet |
| C++ wallet economics | Deletion / separate migration |

---

## §3 Pre-flight discipline checklist

**Audit pin:** `dev` at `2cf4cbfde`; **F4 grep** re-run on design branch 2026-05-27.

### §3.1 Engine identification (template §3.1)

- [x] **§2.7 binding** — four sync `&self` methods; `Into<EconomicsError>`.
- [x] **§1.5** — additive 7th trait; Stage 4 leaf actor.
- [x] **Surface amend vs preserve** — **Preserves** four-method shape. Phase 0
  amendment **unlikely** for `ChainEconomicsSource` / `as_of` (implementor-side);
  confirm at Round 2 segment **2g** (R7).

### §3.2 Plan-altitude principles

| Principle | Applicability |
|-----------|----------------|
| **4 — architectural-integrity-now** | Build mechanism in force now; values marked `CALIBRATION-PENDING`. |
| **5 — closure-rule** | Round 0 feedback folded; Round 1 open. |
| **6 — wider-substrate audit** | After Round 2 **2g** (§6). |
| **7 — threat-model anchors** | **Corrected** — daemon trust is present on chain-derived inputs, bounded by consensus recompute and absent V3.0 consumers (§3.3.5). |
| **8 — priority-hierarchy** | `CALIBRATION-PENDING` real body ≠ deferred body. Stubbing = priority-1 failure; calibration-marking ≠ stubbing. |

### §3.3 Per-engine-PR disciplines — five-category lens review (PR 5 lineage)

#### Category 1 — Design lenses (§8.3.1)

**Lens 1 — Actor-mesh.** Three-condition test:

1. Trait mediates state-mutation across actors? **No** — four `&self` sync reads.
2. Cross-actor liveness/quiescence dependency? **No.**
3. Stage 4 actor non-trivial? **No** — `EconomicsActor` is spawn-graph leaf.

→ **Bounded; synchronous framing correct.** V3.x implementor gains
`Mutex<AdaptiveBurnState>`, but the lens tests *trait-surface* cross-actor
mutation, not implementor state — same boundary as §3.6 reversion clause.

**Lens 2 — State-as-collection-membership.** Lens 1 bounded → **N/A.**
**Sharpening:** per-record lifecycle (`accruing` → `frozen` → `consumed`) lives
in future `StakeEngine` / consensus, not `EconomicsEngine`. `pool_weighted_total`
is read-only aggregate over that collection — reinforces narrow
`ChainEconomicsSource` read, not ownership. Wallet-local
`shekyl-staking::Registry::total_weighted_stake` is wrong source (Bug 2).

**Lens 3 — Recursive trust boundary.** No diagnostic stream at V3.0 → **N/A.**
**Sharpening (load-bearing without stream):**

- *Temporal projection* → `as_of` / param-epoch. Caching `parameters_snapshot`
  crosses a time boundary; staleness must be detectable. Stale/replayed
  `already_generated` from daemon is the same axis.
- *Field projection* → `ActivityMetric` crosses orchestrator/daemon trust
  boundary.

#### Category 2 — Anti-pattern citations (§8.3.2)

| Anti-pattern | PR 7 posture |
|--------------|--------------|
| **Cost-benefit-defer-to-later** | Reject deferring `E` slot, scattered `calc_burn_pct`, and **stub bodies**. `CALIBRATION-PENDING` complete implementation ≠ deferred implementation. |
| **Pre-provision-for-flexibility** | Do **not** build V3.x observer-feed / wide activity-push now. Build **narrow** `ChainEconomicsSource` only. `as_of` **passes** — named V3.x consumer + named failure mode (caller cache / staleness). |
| **User-protection-defaults** | No soft-deprecate of direct economics calls at orchestrator. |
| **Audits-are-clean-so-compress** | Pre-flight still load-bearing. |

#### §3.3.3–§3.3.5 (closure, process, threat-model)

- **§8.3.3** — Round N closure + §9 banners.
- **§8.3.4** — §7.X synthesis banner if Round 2 amends commits.
- **§8.3.5 — threat-model anchors (corrected).** Daemon trust is **present but
  bounded** on chain-derived inputs (`ActivityMetric`, `already_generated_coins`,
  `active_weighted_stake`):

  - Lying daemon → skewed `burn_fraction`. **Bounded:** consensus recomputes
    burn, rejects divergence → failed-send, not theft (2026-04-08).
  - Stale/wrong `already_generated` or weighted total → wrong
    `current_emission` / `pool_weighted_total`. **Bounded at V3.0:** no consumer
    acts on output; tx-gating values recomputed by consensus.

  **Residual:** future consumers acting on `EconomicsEngine` output without
  consensus backstop must validate chain-source inputs through a consistent,
  height-bound ledger snapshot — not a racy direct DB peek. HW-wallet anchor N/A.

### §3.4 Architectural-inheritance audit

| Substrate | Disposition |
|-----------|-------------|
| `shekyl-economics` + sim | Factor **0h** `base_block_reward(already_generated)` into crate; sim calls shared API — no third curve copy. |
| `shekyl-engine-core` | No economics dep; stake paths use `StakerPoolState` accrual mirror for **estimation**, not canonical `EconomicsEngine`. |
| Bug 2 / 7 / 13 | Preventive — `pool_weighted_total` is single canonical denominator. |

### §3.5 Current-substrate inventory + F4 grep (C-3)

| Location | What exists | PR 7 disposition |
|----------|-------------|------------------|
| `engine/traits/mod.rs` | No `economics.rs` | Create |
| `Engine<…>` | `S, D, L, R, P` — no `E` | Add `E`, `economics` field |
| `shekyl-engine-core` / `shekyl-engine-state` | **No `already_generated_coins` mirror** (F4 grep 2026-05-27) | **`current_emission` interpretation (A)** — neutral-curve projection: iterate from genesis / fixture-supplied path; **do not invent mirror in PR 7** |
| `StakerPoolState` / `AccrualRecord.total_weighted_stake` | Chain-reported accrual mirror | **`active_weighted_stake()`** via `ChainEconomicsSource` production adapter |
| `shekyl-staking::Registry::total_weighted_stake` | Wallet-local | **Not** canonical pool total — Bug 2 risk |
| C++ `blockchain_db` | `get_block_already_generated_coins` | Consensus truth; not wallet-engine mirror today |
| `shekyl-economics-sim` | Per-block loop with `already_generated` | Consumer of shared 0h; differential test anchor |
| `docs/economics_sim_results.json` | Recorded sim output | Calibration-tagged vectors; not generation-invariant |

**F4 grep command (audit pin):**

```bash
rg 'already_generated' rust/shekyl-engine-core rust/shekyl-engine-state
# → no matches (2026-05-27)
```

**`current_emission` contract pin (Round 0 feedback):** returns **base block
subsidy only** (`base_block_reward(already_generated)` after `>> ESF` and
`FINAL_SUBSIDY` floor). Signature has no activity argument → **release-multiplier
modulation is not `current_emission`**; document in trait rustdoc so the name is
not read as effective reward. Release path is consumer / future-method territory.

### §3.6 Reversion clauses

| Disposition | Rejection (now) | Reopen when |
|-------------|-----------------|-------------|
| Adaptive-burn on trait surface | No mutable economics methods at V3.0 | V3.x Component 3 + §2.7 discipline test |
| Consensus enforcement on trait | Wallet cannot enforce | Never — chain is truth |
| Stub canonical methods | Hides missing port | Multi-quarter only — else blocked |
| Wide observer-feed seam | No V3.0 consumer | Named V3.x consumer + discipline test |
| `MockEconomics` | **Rejected** — real-path only | N/A |

### §3.7 Branch posture

Design branch `feat/stage-1-pr7-economics-engine-design`; coordinate `Engine<…>`
with PR 6 `F` slot (§5.4).

### §3.8 Performance gates

| Bench | Notes |
|-------|-------|
| `engine_trait_bench_economics_current_emission` | Fixture uses real `ChainEconomicsSource` + representative `already_generated` path; if **(A)** projection, workload may be O(height)-ish — capture at authoring |
| `engine_trait_bench_economics_parameters_snapshot` | Likely trivial pure-read at V3.0; confirm at authoring |

### §3.9 Implementor shape — `ChainEconomicsSource`

```rust
// Illustrative — binding form pinned at Round 1/2; not final API names.

pub trait ChainEconomicsSource: Send + Sync {
    /// Coins minted strictly before the chain tip the wallet treats as current.
    /// Interpretation (A) at V3.0 if no mirror: supplied by fixture / projection.
    fn already_generated_coins(&self) -> u64;

    /// Canonical pool denominator — chain-mirror aggregate, not wallet registry.
    fn active_weighted_stake(&self) -> u128;
}
```

- **Exactly one production implementor** — adapter over `StakerPoolState` /
  latest accrual record (snapshot-bound read contract in Round 2).
- **`LocalEconomics<S: ChainEconomicsSource>`** holds `params: EconomicParams`
  + `chain: S`.
- **Tests** construct `LocalEconomics::new(params, RecordedChainFixture::…)` —
  same spirit as `PQC_TEST_VECTOR_*.json`.

### §3.10 Engine parameterization

- `E: EconomicsEngine = LocalEconomics` + `economics: E`.
- Insert `E` after `L`: `Engine<S, D, L, E, R, P>` or with PR 6's `F` at end.
- Full spec reorder deferred.

---

## §4 Round 1 — Load-bearing question (OPEN)

> **Round 1 status:** OPEN. **F4 closed** — interpretation **(A)** for
> `current_emission` unless a separate initiative mirrors `already_generated` into
> engine (out of PR 7 scope).

### §4.1–§4.3

See §1, §2, §3.

### §4.4 Phase 0 candidates (pre-enumeration)

| ID | Binding form | Module | Notes |
|----|--------------|--------|-------|
| **0a** | `trait EconomicsEngine` | `traits/economics.rs` | §2.7 verbatim |
| **0b** | `LocalEconomics<S: ChainEconomicsSource>` | `local_economics.rs` | |
| **0b′** | `trait ChainEconomicsSource` | `chain_economics_source.rs` | Two reads only |
| **0c** | `EconomicsError` | `engine/error.rs` | |
| **0d** | `EconomicsParametersSnapshot` + `as_of` | economics types | Calibration-generation tag |
| **0e** | `ActivityMetric` | same | Field-projected daemon/orchestrator input |
| **0f** | `Engine<…, E>` + `economics: E` | `mod.rs`, lifecycle, … | |
| **0g** | `RecordedChainFixture` + production `ChainMirrorSource` | `test_support` / `local_economics.rs` | **Replaces MockEconomics** — real recorded chain state |
| **0h** | `base_block_reward(already_generated_coins: u64) -> u64` | `shekyl-economics` | Single source for engine, FFI, sim |
| **0i** | Engine-vs-sim differential test | `shekyl-engine-core` tests | Generation-invariant; no mock |

### §4.5 Load-bearing question (reframed)

**How does `LocalEconomics` over a narrow `ChainEconomicsSource` feed
`shekyl-economics` primitives for both `pool_weighted_total` and
`current_emission` without (i) a third emission-curve copy, (ii) wallet-registry
math (Bug 2), or (iii) per-entity state on `EconomicsEngine`?**

#### §4.5.1 Candidate shapes

| Shape | Summary | Disposition |
|-------|---------|-------------|
| **(1)** | Type-erased `Arc<dyn Fn() -> …>` injection | **Reject** — hidden coordination; prefer named seam |
| **(2)** | `Arc<L: LedgerEngine>` + new ledger accessor | **Reject** — §8.2 co-land; couples traits |
| **(2′)** | **`ChainEconomicsSource`** — two named reads; production adapter + `RecordedChainFixture` | **Accepted (Round 0)** — Round 1 confirms, does not relitigate |
| **(3)** | Amend trait signatures for caller-supplied totals | **Reject** — §2.7 pinned |
| **(4)** | `todo!()` / defer bodies | **Reject** — priority-1 failure |
| **(5)** | `MockEconomics` | **Reject** — struck (C-1) |

**Emission (paired, C-4):** `base_block_reward(already_generated)` in
`shekyl-economics`. At V3.0 without mirror, source supplies projected
`already_generated` along the height path (**(A)**). `current_emission(height)`
maps height → coins-already-generated along the projection, then 0h. **Base subsidy
only** — not release-multiplier-effective reward.

#### §4.5.2 Implications for prior PRs

| PR | Impact |
|----|--------|
| PR 2 | **No** `LedgerEngine` amendment if **(2′)** holds |
| PR 5 | Future `FeeEstimator` → `burn_fraction` — out of PR 7 |
| PR 6 | `Engine<…>` merge coordination |

#### §4.5.3 Criteria rationale (draft)

1. Single canonical source per derived value (0h + chain reads).
2. Spec surface stability V3.0 → Stage 4.
3. JSON authority for params; `CALIBRATION-PENDING` on values.
4. `parameters_snapshot` + `as_of` — no silent cross-generation cache.
5. Differential test catches drift between engine and sim on shared primitive.
6. Daemon-trust bounded — documented in rustdoc / tests.

#### §4.5.4 R-residuals

| ID | Topic | Segment |
|----|-------|---------|
| **R1** | `burn_fraction` return unit + overflow KAT | 2a |
| **R2** | `EconomicsParametersSnapshot` + `as_of` layout | 2a |
| **R3** | `active_weighted_stake` snapshot-bound read contract | 2b |
| **R4** | Folds into C-3 — **(A)** projection details + bench workload | 2b |
| **R5** | Differential test + fixture format | 2c |
| **R6** | Consumer wiring boundary | 2d |
| **R7** | Phase 0 §2.7 amendment necessity | 2g |

#### §4.5.5 Round 1 disposition

**Open** for R1–R7 wargaming only. **Closed at Round 0 (do not reopen):** trait
identity; MockEconomics struck; lens dispositions; **(2′)** seam; 0h shape;
F4 → interpretation **(A)**.

---

## §5 Round 1 readiness (feedback closure)

**Do not reopen in Round 1:**

- Trait identity / consume-not-subsume — 2026-05-08.
- `MockEconomics` — removed; real-path + differential (C-1).
- Lens 1 bounded; Lens 2/3 N/A with sharpenings recorded.
- 0h = `base_block_reward(already_generated)`.
- Implementor seam = **(2′)** `ChainEconomicsSource`.

**Still open for Round 1 closure:**

- **R1** — `burn_fraction` return semantics + overflow.
- **R2** — snapshot layout incl. `as_of`.
- **R3** — read consistency (snapshot-bound).
- **R4** — **(A)** projection mechanics + bench implications.
- **R7** — likely no §2.7 amendment.

---

## §6 Round 2 — Segment placeholders

| Segment | Scope |
|---------|--------|
| **2a** | R1 + R2 |
| **2b** | R3 + R4 — chain source + **(A)** emission projection |
| **2c** | R5 — differential test + `RecordedChainFixture` format |
| **2d** | R6 — consumer wiring boundary |
| **2g** | Close-out — §4, §6, Round 3 gate |
| **2i** | Wider-substrate audit (fee staleness, snapshot cache, gas-style activity) |

### §5.4 PR 6 / PR 7 merge

Coordinate `Engine<…>` type-parameter edit when both land.

---

## §6 Pre-Round-3 wider-substrate audit (PLACEHOLDER)

Runs after **2g**, before §7.X. Yield: G1–Gn in segment **2i**.

---

## §7 Round 3 — §7.X commit decomposition (PLACEHOLDER)

**Deviation:** No diagnostic enum; no secondary traits; no `MockEconomics`; no
`FaultInjecting` at V3.0.

| Commit | Scope |
|--------|--------|
| **C0** | Phase 0 spec amendment if **2g** requires |
| **C1** | `EconomicsError`, `ActivityMetric`, `EconomicsParametersSnapshot` + `as_of` |
| **C2** | `shekyl-economics`: `base_block_reward(already_generated)` + unit tests; sim rewired |
| **C2b** | `ChainEconomicsSource` + production adapter |
| **C3** | `EconomicsEngine` + `LocalEconomics` impl; `CALIBRATION-PENDING` doc comments |
| **C4** | Real-path tests: generation-invariant engine-vs-sim differential + calibration-tagged vectors |
| **C5** | `Engine` `E` slot + `economics` field |
| **C6** | Benches + `PERFORMANCE_BASELINE.md` |
| **C7** | Docs: CHANGELOG, rustdoc, design doc Phase 1 landed; calibration banners |

### §7.1 Stage 1 closeout

After **PR 6 + PR 7** implementation merge — not either alone.

---

## §8 Discipline-citation matrix (seed)

| # | Discipline | Failure mode foreclosed |
|---|------------|-------------------------|
| 1 | Canonical derivation + 0h single source | Bug 2/7 drift between engine/sim/FFI |
| 2 | Narrow `ChainEconomicsSource` | Wide observer-feed pre-provision |
| 3 | Real-path fixtures | Mock-driven false confidence |
| 4 | Calibration vs structural split | "Adjust on testnet" → accidental fork |
| 5 | `as_of` temporal projection | Silent snapshot cache poison |
| 6 | Daemon trust documented | False "N/A adversary" claim |
| 7 | Scope guard §2.7 | Wallet enforcement illusion |

---

## §9 Banner discipline

| Event | Banner |
|-------|--------|
| Round 0 close | `Round 0 closed 2026-05-27; pre-flight + substrate inventory.` |
| **Round 0 feedback folded** | `Round 0 feedback folded 2026-05-27; lens citations refreshed to PR-5 five-category form; MockEconomics struck (real-path testing); load-bearing question reframed to ChainEconomicsSource (2′) + shekyl-economics primitives; calibration-vs-structural boundary added; F4 grep closed — already_generated not mirrored in engine (interpretation A for current_emission). Reopen Round 0 only if trait identity / scope guard challenged.` |
| Round 1 close | *(pending)* |

---

## Appendix A — Spec trait surface (reference)

See [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7.

**Implementer note:** `current_emission` at V3.0 = **base subsidy** from
`base_block_reward(already_generated)`, not release-multiplier-effective reward.

---

## Appendix B — PR 6 linkage

Unchanged — both PRs required for Stage 1 trait inventory; coordinate `Engine<…>`.

---

## Appendix C — Round 0 feedback index (C-1–C-7)

| ID | Correction |
|----|------------|
| **C-1** | Strike `MockEconomics`; real-path + differential |
| **C-2** | Reframe §4.5.1; add **(2′)** |
| **C-3** | F4 grep; **(A)** vs **(B)** for `current_emission` |
| **C-4** | 0h keyed on `already_generated`; base subsidy semantics |
| **C-5** | Calibration boundary + KAT split + CALIBRATION milestone |
| **C-6** | Five-category lens review (§3.3) |
| **C-7** | Provenance cross-refs (2026-05-08, 2026-04-08) |

---

*Template:* [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md).
*Spec:* [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7+.
*Process:* [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
*Calibration:* [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md),
[`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md).
