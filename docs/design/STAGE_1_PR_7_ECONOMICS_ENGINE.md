# Stage 1 PR 7 — `EconomicsEngine` extraction — design

**Status.** **Round 0 closed (2026-05-27).** **Round 1 closed (2026-05-27)** —
segments 2a–2d and 2g disposed; 2b drafted earlier same day. Round **2** open
(2i wider-substrate audit after 2g close-out in Round 2 segment plan). Planning
doc branch:
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
    not theft. Anchors `burn_amount` threat narrowing (§3.2).
- **Per-PR template / process.**
  [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md),
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
- **Prior PRs (shape precedent).**
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md),
  [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](STAGE_1_PR_6_PERSISTENCE_ENGINE.md).
- **Performance gates.**
  [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) — deferred benches
  `engine_trait_bench_economics_base_emission_at`,
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
3. **`ChainEconomicsSource` seam** — narrow implementor-side trait: **one read**
   at V3.0 — `active_weighted_stake()` only. Production adapter over chain-mirror
   accrual state. `already_generated_coins()` is **not** on the source at V3.0
   (interpretation **(A)** — projection is crate-side; §5.2). **No**
   `LedgerEngine` amendment; **no** type-erased closures.
4. **Supporting types** — `EconomicsError`, `ActivityMetric` (§5.3 R1),
   `EconomicsParametersSnapshot` + `CalibrationStamp` (§5.3 R2 rulebook).
5. **`Engine` parameterization** — `E: EconomicsEngine = LocalEconomics`;
   field `economics: E`. Incremental order: `E` after `L` (§3.10).
6. **Workspace wiring** — `shekyl-economics` dep on `shekyl-engine-core`.
7. **0h + projection primitives** — in `shekyl-economics`, shared with sim and FFI:
   `base_block_reward(already_generated_coins, params)` (0h) and
   `projected_already_generated(height, params)` (interpretation **(A)** neutral
   trajectory). `base_emission_at(height)` composes both. Path-dependent emission
   per [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md).
8. **§2.7 naming amendment (C0)** — `current_emission` → `base_emission_at`;
   `burn_fraction` → `burn_amount` (absolute atomic units). Co-land
   [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7.
9. **Real-path tests** — `LocalEconomics` over production `ChainEconomicsSource`
   + recorded fixtures (`economics_sim_results.json` spirit; regtest accrual
   tables). **Headline:** engine-vs-sim **differential** — both call 0h; any
   inequality is Bug-2-class drift. **No mock** in the loop.
10. **Performance gates** — both deferred economics benches + baseline rows.
11. **Docs** — this design doc, `CHANGELOG.md`, trait rustdoc, calibration
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
- [x] **Surface amend vs preserve** — **Preserves** four-method shape; **C0**
  naming-only §2.7 amendment locked (§5.1). `ChainEconomicsSource` / `as_of` are
  implementor-side. At **2g**, confirm no *other* §2.7 change beyond C0 (R7).

### §3.2 Plan-altitude principles

| Principle | Applicability |
|-----------|----------------|
| **4 — architectural-integrity-now** | Build mechanism in force now; values marked `CALIBRATION-PENDING`. |
| **5 — closure-rule** | Round 0 closed; **Round 1 closed** (2026-05-27). |
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
  bounded** on chain-derived inputs (`ActivityMetric`, `active_weighted_stake`;
  `base_emission_at` is **not** chain-sourced at V3.0 — §5.2 B.1):

  - Lying daemon → skewed `burn_amount`. **Bounded:** consensus recomputes
    burn, rejects divergence → failed-send, not theft (2026-04-08).
  - Stale/wrong `active_weighted_stake` → wrong `pool_weighted_total`.
    **Bounded at V3.0:** no consumer acts on output; tx-gating values recomputed
    by consensus.

  **Residual:** future consumers acting on `EconomicsEngine` output without
  consensus backstop must validate chain-source inputs through a consistent,
  height-bound ledger snapshot — not a racy direct DB peek. HW-wallet anchor N/A.

### §3.4 Architectural-inheritance audit

| Substrate | Disposition |
|-----------|-------------|
| `shekyl-economics` + sim | **0h** `base_block_reward` + **`projected_already_generated`** in crate; sim calls 0h with its per-block `ag`; no third curve copy. |
| `shekyl-engine-core` | No economics dep; stake paths use `StakerPoolState` accrual mirror for **estimation**, not canonical `EconomicsEngine`. |
| Bug 2 / 7 / 13 | Preventive — `pool_weighted_total` is single canonical denominator. |

### §3.5 Current-substrate inventory + F4 grep (C-3)

| Location | What exists | PR 7 disposition |
|----------|-------------|------------------|
| `engine/traits/mod.rs` | No `economics.rs` | Create |
| `Engine<…>` | `S, D, L, R, P` — no `E` | Add `E`, `economics` field |
| `shekyl-engine-core` / `shekyl-engine-state` | **No `already_generated_coins` mirror** (F4 grep 2026-05-27) | **`base_emission_at` interpretation (A)** — `projected_already_generated` in `shekyl-economics`; **does not read** `ChainEconomicsSource`; **do not invent mirror in PR 7** |
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

**`base_emission_at` contract pin (Round 1 segment 2b):** returns **base block
subsidy only** on the **neutral trajectory** at `height`:
`base_block_reward(projected_already_generated(height, params), params)`.
Not effective reward (no activity input); not realized emission (actual path
uses realized multipliers). Name + rustdoc carry the neutral-vs-realized caveat
(§5.2 B.4). Under **(A)**, `Err` is overflow-only (B.7).

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
| `engine_trait_bench_economics_base_emission_at` | **(A)** workload: naive `projected_already_generated(height)` — **O(height)** from genesis; bench at representative height; FOLLOWUPS checkpoint table if hot consumer lands (§5.2 B.6) |
| `engine_trait_bench_economics_parameters_snapshot` | Likely trivial pure-read at V3.0; confirm at authoring |

### §3.9 Implementor shape — `ChainEconomicsSource`

```rust
// Illustrative — binding form pinned at Round 1 segment 2b.

pub trait ChainEconomicsSource: Send + Sync {
    /// Canonical pool denominator — chain-mirror aggregate, not wallet registry.
    fn active_weighted_stake(&self) -> u128;
}
```

- **V3.0: one method only.** `already_generated_coins()` cut — no V3.0 caller
  under **(A)**; wrong shape for both (A) and future (B) (§5.2 B.3). Re-add
  `already_generated_coins(&self, height) -> Result<u64, _>` when mirror + realized
  consumer exist (gated initiative).
- **Exactly one production implementor** — adapter over `StakerPoolState` /
  latest accrual record (snapshot-bound read contract — R3, segment 2b).
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

> **Round 1 status:** **CLOSED (2026-05-27).** Dispositions in §5.3–§5.6. Round 2
> opens on the segment plan in §6 (2i after Round 2 close-out).

### §4.1–§4.3

See §1, §2, §3.

### §4.4 Phase 0 candidates (pre-enumeration)

| ID | Binding form | Module | Notes |
|----|--------------|--------|-------|
| **0a** | `trait EconomicsEngine` | `traits/economics.rs` | §2.7 **signatures + rustdoc** verbatim — **not** Appendix A (signature-only) |
| **0b** | `LocalEconomics<S: ChainEconomicsSource>` | `local_economics.rs` | |
| **0b′** | `trait ChainEconomicsSource` | `chain_economics_source.rs` | **One read** at V3.0 (`active_weighted_stake`) |
| **0h′** | `projected_already_generated(height, params) -> u64` | `shekyl-economics` | Neutral-trajectory **(A)**; pairs with 0h |
| **0c** | `EconomicsError` | `engine/error.rs` | |
| **0d** | `EconomicsParametersSnapshot` + `CalibrationStamp` | economics types | Rulebook constants + `as_of` — §5.3 R2 |
| **0e** | `ActivityMetric` | economics types | Raw integer observables — §5.3 R1 |
| **0j** | `RecordedChainFixture` JSON schema | `docs/test_vectors/economics/` | §5.4 R5 — sim-recorded, two arrays |
| **0f** | `Engine<…, E>` + `economics: E` | `mod.rs`, lifecycle, … | |
| **0g** | `RecordedChainFixture` + production `ChainMirrorSource` | `test_support` / `local_economics.rs` | **Replaces MockEconomics** — real recorded chain state |
| **0h** | `base_block_reward(already_generated_coins: u64) -> u64` | `shekyl-economics` | Single source for engine, FFI, sim |
| **0i** | Engine-vs-sim differential test | `shekyl-engine-core` tests | Generation-invariant; no mock |

### §4.5 Load-bearing question (reframed)

**How does `LocalEconomics` feed `shekyl-economics` primitives for
`pool_weighted_total` (chain read) and `base_emission_at` (pure projection)
without (i) a third emission-curve copy, (ii) wallet-registry math (Bug 2), or
(iii) per-entity state on `EconomicsEngine`?**

#### §4.5.1 Candidate shapes

| Shape | Summary | Disposition |
|-------|---------|-------------|
| **(1)** | Type-erased `Arc<dyn Fn() -> …>` injection | **Reject** — hidden coordination; prefer named seam |
| **(2)** | `Arc<L: LedgerEngine>` + new ledger accessor | **Reject** — §8.2 co-land; couples traits |
| **(2′)** | **`ChainEconomicsSource`** — one V3.0 read (`active_weighted_stake`); production adapter + `RecordedChainFixture` | **Accepted** — Round 1 segment 2b shrinks from two reads |
| **(3)** | Amend trait signatures for caller-supplied totals | **Reject** — §2.7 pinned |
| **(4)** | `todo!()` / defer bodies | **Reject** — priority-1 failure |
| **(5)** | `MockEconomics` | **Reject** — struck (C-1) |

**Emission (segment 2b, §5.2):** Projection lives in **`shekyl-economics`**, not
the source adapter. `base_emission_at(height)` =
`base_block_reward(projected_already_generated(height, &p), &p)`. Reads **nothing**
from `ChainEconomicsSource`. **Base subsidy on neutral trajectory only** — not
effective or realized reward (rustdoc per §5.2 B.4).

#### §4.5.2 Implications for prior PRs

| PR | Impact |
|----|--------|
| PR 2 | **No** `LedgerEngine` amendment if **(2′)** holds |
| PR 5 | Future `FeeEstimator` → `burn_amount` — out of PR 7 |
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
| **R1** | **Disposed §5.3** — `ActivityMetric` raw integer observables; `calc_burn_pct` owns ratios | 2a |
| **R2** | **Disposed §5.3** — rulebook snapshot + `as_of`; not dashboard | 2a |
| **R3** | **Disposed §5.2 B.8** — 0-semantics + read contract (wording in §2.7) | 2b |
| **R4** | **Disposed §5.2** — projection in crate; one read; bench O(height) | 2b |
| **R5** | **Disposed §5.4** — `RecordedChainFixture` two-array schema | 2c |
| **R6** | **Disposed §5.5** — V3.0 zero consumer call sites | 2d |
| **R7** | **Confirmed §5.6** — C0-only §2.7 surface change | 2g |

#### §4.5.5 Round 1 disposition

**Closed (2026-05-27).** All R-residuals disposed; fence in §5.7. Round 2
segment placeholders remain in §6.

---

## §5 Round 1 — Segment 2b and naming amendment (2026-05-27)

Consolidated Round 1 input. Round 0 stays closed — trait identity and scope
guard unchanged.

### §5.1 Phase 0 naming amendment (C0) — locked

Single §2.7 amendment (co-land §8.2). No implementation consumers yet — cheapest
rename moment.

| Old | New | Rationale |
|-----|-----|-----------|
| `current_emission` | `base_emission_at` | `current` incoherent with `height` arg; `base` = no release multiplier; `_at` = height-keyed |
| `burn_fraction` | `burn_amount` | Returns absolute atomic units to burn, not a ratio |

`pool_weighted_total` and `parameters_snapshot` unchanged. Identifier sweep:
`engine_trait_bench_economics_base_emission_at`, `PERFORMANCE_BASELINE.md`,
§4.4, Appendix A, §3.5 pin. **R7 flipped:** C0 **is** a §2.7 amendment.

### §5.2 Segment 2b — `base_emission_at` under interpretation **(A)** (R4)

F4 closed: no `already_generated_coins` mirror in engine Rust. V3.0 uses **(A)**.

**B.1 — `base_emission_at` reads nothing from `ChainEconomicsSource`.** Under
**(A)**, neutral trajectory (`release_multiplier = 1`) makes `already_generated` at
height `h` a pure function of `(height, params)` — **computed, not read**.

**B.2 — Projection in `shekyl-economics`.** Not in the source adapter (would be
a third curve copy / Bug-2 drift). Add alongside 0h:

```rust
fn base_block_reward(already_generated_coins: u64, params: &EconomicParams) -> u64;
fn projected_already_generated(height: u64, params: &EconomicParams) -> u64;
```

Composition: `base_emission_at(h)` =
`base_block_reward(projected_already_generated(h, &p), &p)`. Pure free function —
memoization/checkpoint table is a non-breaking add later.

**B.3 — Source shrinks to one method.** Cut `already_generated_coins()` — no V3.0
caller; wrong shape for (A) and (B). Future (B): add
`already_generated_coins(&self, height) -> Result<u64, _>` when mirror + realized
consumer exist.

**B.4 — Semantics.** Neutral-trajectory base subsidy at `height`; not effective or
realized emission. Residual caveat in trait rustdoc (ESF-22 milestones; forward-ref
`realized_emission_at` if (B) lands).

**B.5 — Two distinct tests.**

| Test class | What it exercises | Churn |
|------------|-------------------|-------|
| Generation-invariant differential (0i) | `base_block_reward(ag)` engine vs sim for **identical** `ag` from fixtures | Survives recalibration |
| Calibration-tagged vectors | `base_emission_at(height)` at known neutral milestones | Per calibration generation |

Fixture supplies recorded real `ag` for differential only — **not** the projection.

**B.6 — Bench.** Naive O(height) `projected_already_generated`; bench and capture.
FOLLOWUPS checkpoint table if hot consumer lands — do not build now.

**B.7 — `Result` under (A).** Overflow-only `Err` (defensive KAT; no inherited
`div128_64` omission). Unsynced-height `Err` deferred to (B).

**B.8 — R3 / `pool_weighted_total` zero-semantics (segment 2b).** Three of four
methods carry forward-compat caveats in §2.7 rustdoc; `pool_weighted_total` was the
gap. Pinned in binding spec (not reopening `-> u128`):

1. **`0` is valid** — no active stake at the mirrored height; consensus burns
   the pool contribution ([`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md)
   §"Empty-staker-set behavior").
2. **Denominator guard** — `StakeEngine::projected_yield` (May-8 reason this
   method exists) must not divide blindly; `0` is live divide-by-zero.
3. **`0` overloaded** — legitimate empty pool vs unsynced/stale mirror both
   surface as `0`; infallible return cannot signal "unknown" (Round 0
   infallibility-collapse note, now in rustdoc). Consumers that must distinguish
   check sync state separately.

**R3 read contract (normative; wording polish open):** `active_weighted_stake()`
reads through the engine's consistent ledger view at a height-bound snapshot —
not a racy direct DB peek outside that view. `pop_block` / accrual-mirror
atomicity covers the reorg boundary (implementation detail at C2b). Return
feeds `pool_weighted_total()` verbatim (single aggregation path). Zero-semantics
for the public method: §2.7 `pool_weighted_total` rustdoc above.

**B.9 — Implementer guard (0a vs Appendix A).** Candidate **0a** is §2.7
**verbatim including all doc comments.** Appendix A is signature-only reference;
`traits/economics.rs` must copy rustdoc from
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7, not
from Appendix A — otherwise neutral-vs-realized, no-cache, and zero-denominator
caveats evaporate at the copy step.

### §5.3 Round 1 segment 2a — R1 + R2 (2026-05-27)

**Coherence (R1 + R2).** Chain-derived observables cross the boundary in
`ActivityMetric` (R1); constants live in `EconomicParams` / the snapshot (R2);
`burn_amount` combines them inside `shekyl-economics` via `self.params`. The
snapshot is the same constants exposed for display — one source, no duplication.

#### R1 — `ActivityMetric` + caller-trust

Burn formula ([`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) Component 2):

```text
burn_pct = min(BURN_CAP,
    BURN_BASE_RATE · √(tx_volume/tx_baseline)
                   · (circulating_supply/total_supply)
                   · (1 + stake_ratio)),
stake_ratio = total_staked / circulating_supply
```

**Disposition:** raw integer observables on the struct; all ratio/burn math stays in
`shekyl-economics` (see §5.8 — burn is already single-source Rust; wallet must
not hand-roll `stake_ratio`).

```rust
pub struct ActivityMetric {
    /// Rolling 720-block window aggregate (daemon-reported).
    pub tx_volume: u64,
    /// `already_generated − destroyed` (chain-derived).
    pub circulating_supply: u64,
    /// Principal-pool total staked amount (chain-mirror; not wallet registry).
    pub total_staked: u128,
}
```

- **Not pre-computed ratios** — orchestrator must not pass `volume_ratio` /
  `supply_ratio` / `stake_ratio`; that relocates derivation → Bug 2 class.
- **`stake_ratio` formation is single-source today:** consensus
  `Blockchain::get_stake_ratio` aggregates `txout_to_staked_key` state, then calls
  `shekyl_calc_stake_ratio(total_staked, circulating_supply)` (Rust FFI —
  `rust/shekyl-ffi/src/lib.rs`). Wallet `ActivityMetric` must use the **same**
  primitive: move ratio arithmetic into `shekyl-economics` (e.g.
  `calc_stake_ratio(total_staked, circulating_supply)`) and have both
  `calc_burn_pct_from_activity(...)` and the FFI call it. **Do not** divide in
  `LocalEconomics` or C++.
- **`circulating_supply` quantity:** consensus passes `already_generated_coins`
  as circulating supply at the burn site (`blockchain.cpp` ~2023). `ActivityMetric.circulating_supply`
  must be that same quantity (typically `already_generated − destroyed` when the
  wallet has both; document in rustdoc).
- **Canonical burn entry point (implementation PR):** add an outer
  `calc_burn_pct_from_activity` / `burned_amount_from_activity` that (1) forms
  `stake_ratio` via the shared ratio helper, (2) calls the existing
  `calc_burn_pct(..., stake_ratio, ...)` core. The precomputed-`stake_ratio`
  signature remains for C++ `compute_fee_burn` but is **not** a second formation
  site — C++ must keep passing a ratio already produced by
  `shekyl_calc_stake_ratio`, not a locally computed division.
- **Integers only** — fixed-point math per [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md)
  (no float across FFI/trait; divergent rounding fails consensus).

**Caller-trust rustdoc (field-projection lens):** all three fields are
daemon-reported / orchestrator-assembled. State explicitly: advisory inputs;
`burn_amount` is a wallet-side estimate; consensus recomputes burn and rejects
divergence → failed-send / wrong-display, not theft (2026-04-08). Must not claim
authoritative burn.

**Locked:** `burn_amount` name; absolute atomic-unit return; overflow KAT.

#### R2 — `EconomicsParametersSnapshot` (rulebook, not dashboard)

`parameters_snapshot()` is infallible, no-arg, no chain read.

**Disposition: rulebook.** Snapshot = `EconomicParams` constants + `as_of` tag.
**Not** time-varying derived state (`release_multiplier`, live `burn_pct`,
effective emission share, annualized yield). Those compose from the other three
methods + chain inputs.

```rust
pub struct EconomicsParametersSnapshot {
    pub emission_speed_factor: u8,          // 22 (locked)
    pub money_supply_atomic: u64,           // 2^32 · 10^9
    pub final_subsidy_per_minute: u64,      // 0h floor — see calibration note below
    pub tx_volume_baseline: u64,
    pub release_min_milli: u32,             // e.g. 800 → 0.800×
    pub release_max_milli: u32,             // e.g. 1300 → 1.300×
    pub burn_base_rate_bp: u16,
    pub burn_cap_bp: u16,
    pub staker_fee_pool_share_bp: u16,
    pub staker_emission_share_bp: u16,      // BASE share — not decayed effective
    pub staker_emission_decay_milli: u16,
    pub tiers: TierTable,                   // read from `shekyl-staking::tiers` — not redefined
    pub as_of: CalibrationStamp,            // calibration-generation + optional param-epoch
}
```

- **Base values, not decayed.** Effective `staker_emission_share` is height-varying
  even at V3.0; snapshot carries base + decay rate; consumer applies decay.
- **Tiers by reference** — single source `shekyl-staking::tiers`; no duplicated
  lock-block pairs in economics types.
- **Integers** — basis points / milli-units; same no-float discipline as R1.
- **No-cache** — already in §2.7 rustdoc; `as_of` detects stale calibration generation.

**Dashboard alternative (rejected for this method):** a one-shot "current economic
state" readout (live burn %, release multiplier, yield) is a **composed UX view**
from `base_emission_at` + `burn_amount` + `pool_weighted_total` + chain inputs —
not this infallible constants method.

**`FINAL_SUBSIDY` doc conflict (reconcile before recording value vectors).**
[`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) §2 still cites historical Monero
`FINAL_SUBSIDY_PER_MINUTE = 3 × 10¹¹` (inherited baseline); the resolved Shekyl
tables (§§533–541 / 594–617 area) pin **300_000_000** atomic units from
`economics_params.json`. **Authoritative for PR 7:** JSON + snapshot field
`final_subsidy_per_minute` = **300_000_000**; historical §2 line is Monero
reference only. Implementation PR updates §2 prose or adds an explicit
disambiguation cross-ref when KATs/fixtures are recorded.

### §5.4 Round 1 segment 2c — R5 `RecordedChainFixture` (2026-05-27)

Two-test split (§5.2 B.5): one fixture file, **two arrays**, recorded from real
`shekyl-economics-sim` output (no hand-authored expectations, no mock).

```jsonc
{
  "calibration_generation": 7,
  "params_digest": "blake2b:…",
  "scenario": "baseline_steady_state",
  "records": [
    {
      "height": 1234,
      "already_generated_coins": 987654321,
      "base_block_reward": 4521,
      "release_multiplier_milli": 1000,
      "tx_volume": 48,
      "circulating_supply": 987654321,
      "total_staked": 12345678,
      "burn_pct_bp": 4283,
      "total_weighted_stake_lo": 18000000,
      "total_weighted_stake_hi": 0,
      "staker_emission": 678,
      "staker_fee_pool": 211,
      "actually_destroyed": 633
    }
  ],
  "neutral_milestones": [
    {
      "height": 5788000,
      "base_emission_at_neutral": 2110,
      "note": "≈50% emitted, ~yr 11 (ESF-22 milestone)"
    }
  ]
}
```

| Decision | Rationale |
|----------|-----------|
| Sim-recorded `records` | Generation-invariant differential: engine `base_block_reward(ag)` must equal sim for **identical** recorded `ag` |
| Separate `neutral_milestones` | `base_emission_at` uses neutral projection (multiplier = 1); must not assert against realized-ag rows |
| `params_digest` + `calibration_generation` | Fixture staleness guard — mismatch rejects run instead of silent pass |
| `total_weighted_stake` as lo/hi | Exercises u128 reconstruction (LMDB/FFI boundary) |
| Integers only | bp / milli in expectations — no float |
| **Staking state live** | If any `records[]` row has `total_staked > 0`, the recording run must use **non-stub** `get_stake_ratio` / real stake aggregation. `params_digest` alone does not catch `(1 + stake_ratio)` collapsed to `1` because consensus still returns ratio `0` while sim models staking. Fixture metadata: `staking_state: "live" \| "stub"`; reject generation when `total_staked > 0` and `staking_state != "live"`. |

Land under `docs/test_vectors/economics/` (exact path at C4); regen when
`economics_params.json` or sim scenario changes.

### §5.5 Round 1 segment 2d — R6 consumer boundary (2026-05-27)

At **V3.0**, **no** `Engine<…>` method calls any `EconomicsEngine` method. PR 7
lands the trait, `LocalEconomics`, the one-read `ChainEconomicsSource`, and the
`E` slot with **zero orchestrator call sites**. Methods are **reachable and tested**
(`RecordedChainFixture` + engine-vs-sim differential) only — not production-called.

**Named follow-ups (not built in PR 7):**

| Consumer | Seam |
|----------|------|
| Fee path / `PendingTxEngine` | `burn_amount` |
| Phase 2b `StakeEngine` | `pool_weighted_total`, `base_emission_at` |
| Display / governance | `parameters_snapshot` |

Pre-provision-for-flexibility at consumer altitude: surface pre-wired for Phase 2b;
no V3.0 consumer exists. Boundary = **reachable + tested, not yet called**.

### §5.6 Round 1 segment 2g — R7 C0-only confirmation (2026-05-27)

**Confirmed:** the only §2.7 **surface** changes in PR 7 are **C0**:

1. `current_emission` → `base_emission_at`; `burn_fraction` → `burn_amount`
   (absolute-amount return pin).
2. Rustdoc clarifications in spec: `base_emission_at` neutral-vs-realized +
   overflow-only `Err` under **(A)**; `pool_weighted_total` 0-semantics;
   `parameters_snapshot` no-cache.

No method added, removed, or re-signatured. **R1/R2 field layouts do not force a
further §2.7 amendment** — `ActivityMetric` and `EconomicsParametersSnapshot` were
already named in §2.7 signatures; layouts are implementor-side (0d/0e, C1). **C0
remains the sole §2.7 amendment.**

### §5.7 Closed / open fence (Round 1)

**Closed — do not reopen:**

- §5.4 fence items (trait identity through R4).
- R1 `ActivityMetric` layout + caller-trust.
- R2 rulebook snapshot + `as_of`.
- R3 read contract + `pool_weighted_total` 0-semantics.
- R5 fixture schema (two-array, sim-recorded).
- R6 zero V3.0 consumer call sites.
- R7 C0-only.

**Round 2 (not Round 1):** segment **2i** wider-substrate audit (§5.8 pins); Round 2
close-out §4/§6 refresh; Round 3 §7.X.

### §5.8 Round 2 substrate pins — economics surface asymmetry (2026-05-27)

Post–Round 1 evidence from `blockchain.cpp`, `economics.h`, `cryptonote_basic_impl.cpp`,
and FFI inventory. **Does not reopen §D-fenced decisions** (R1 raw observables, R2
rulebook snapshot, dashboard rejection). Converts implementation heads-up into
binding pins for C2/C4 and segment **2i**.

#### Three-layer model (mining vs staking vs wallet engine)

| Layer | Authoritative today | PR 7 role |
|-------|-------------------|-----------|
| **Mining output** | **Base subsidy → Rust canonical in PR 7** (`base_block_reward` + FFI; C++ `get_block_reward` cutover). PoW/hash + block template orchestration remain C++ until later migrations | Wallet `base_emission_at` uses same 0h as consensus after cutover |
| **Staking consensus** | C++ orchestration + LMDB (`check_stake_claim_input`, accrual/pool/watermarks, stake-ratio cache) over **Rust FFI math** | `pool_weighted_total` reads **accrual mirror** (`StakerPoolState` / `staker_accrual_record` lo/hi) — **not** `StakeRegistry` / `distribute_staker_rewards` (wallet/sim only) |
| **Economics formulas (non-base)** | Rust canonical; C++ thin wrappers (`compute_fee_burn`, `compute_emission_split`) | `EconomicsEngine` = wallet consumer of same Rust primitives FFI already uses |

#### Burn / emission-share / release — single-source Rust (concern closed)

- `shekyl::compute_fee_burn` → `shekyl_calc_burn_pct` + `shekyl_compute_burn_split`
  (`shekyl-economics/src/burn.rs`). No independent C++ burn formula.
- Burn is **wired** on block connect (`blockchain.cpp` ~5015–5060) but
  `compute_fee_burn` **short-circuits** when `hf_version < HF_VERSION_SHEKYL_NG`
  (present-but-dormant pre-NG; live from genesis on V3 NG chain).
- PR 7 `burn_amount` calls the same primitive stack; R1 anti–Bug-2 value is
  enforcing **one ratio-formation helper** for the `stake_ratio` *input* to that
  stack (§5.3), not inventing parallel burn math.

#### `stake_ratio` — single-source (concern closed)

- `Blockchain::get_stake_ratio` returns `shekyl_calc_stake_ratio(total_staked,
  circulating_supply)` after C++ aggregation — **not** a second division
  implementation.
- Wallet must route `ActivityMetric.total_staked` + `circulating_supply` through
  the same helper (relocate FFI body into `shekyl-economics` per §5.3).

#### Base emission (0h) — genuine asymmetry; must-build cross-check

| Formula | Canonical location | FFI seam? |
|---------|-------------------|-----------|
| DAA (LWMA-1) | Rust `shekyl-difficulty` | Yes — cross-checked (`tests/difficulty/lwma1_cross_check.cpp`) |
| Burn / emission-share / release | Rust `shekyl-economics` | Yes — C++ orchestrates |
| **Base CryptoNote subsidy** | **C++ only** today (`get_block_reward` in `cryptonote_basic_impl.cpp`); **no FFI seam yet** | **After C2c:** thin wrapper like `compute_fee_burn` — `get_block_reward` → `shekyl_base_block_reward` (+ release-multiplier FFI) |

**Target end-state (C2c, reviewable pattern).** After cutover, `get_block_reward`
is structurally identical to `shekyl::compute_fee_burn` / `compute_emission_split`
in [`economics.h`](../../src/shekyl/economics.h): C++ gathers inputs, calls Rust
FFI, returns the result. The duplicated `(MONEY_SUPPLY − ag) >> ESF` body in
`cryptonote_basic_impl.cpp` is deleted only after KAT legs pass (H1).

`already_generated` accumulation also runs C++-side (`blockchain.cpp` — accept
path, fee estimate, `bei.already_generated_coins` at ~2293, **pop_block**
reversal). Per-block subsidy rounding differences **compound** across height;
single-block KAT grids are necessary but not sufficient (H2).

**Test trap:** engine-vs-sim differential (both Rust) proves **Rust self-consistency
only** — not consensus correctness vs C++, and not accumulation over a chain.

**Disposition (ratified 2026-05-27):** **Migration path; C++ cutover in V3.0**
(same PR 7 implementation). Wallet-only re-expression is rejected. See
[`FOLLOWUPS.md`](../FOLLOWUPS.md).

#### Cutover execution hazards (H1–H3) — merge-time, not review-time

Wargame of executing the ratified disposition. **Does not reopen the fork.**

**H1 — C2a′ must have two legs; C++ alone is not an oracle.**

Asserting `base_block_reward(...) == get_block_reward(...)` only proves the Rust
port reproduces C++. If `get_block_reward` carries a latent bug (e.g. `div128_64`
overflow-guard shape in the weight-penalty path), the KAT certifies reproducing
the bug; C2c deletes the C++ original; the bug becomes canonical with its only
witness gone.

**C2a′ requires two independent assertions before C2c deletes C++:**

| Leg | Assertion | Oracle |
|-----|-----------|--------|
| **A** | `base_block_reward(...) == get_block_reward(...)` | Legacy C++ (extract witness **before** deletion) |
| **B** | `base_block_reward(...) == spec_oracle(...)` | Independent of C++: hand-derived grid from `(MONEY_SUPPLY − ag) >> ESF` + `FINAL_SUBSIDY` floor per `economics_params.json`, **and/or** `shekyl-economics-sim` value vectors (spec-driven emission, not `get_block_reward`) |

If leg A and leg B disagree, that is a **consensus bug found pre-cutover** — the
point of doing this pre-genesis. "Rust == C++" and "Rust == spec" are different
claims; require **both** before deleting C++.

**H2 — C2c blast radius is every consensus site that reads block subsidy, including accumulation.**

C2c is not "rewire one function." `blockchain.cpp` consumes base reward at
least:

| Site | Role |
|------|------|
| `validate_miner_transaction` (~1583) | Accept path — coinbase vs expected subsidy |
| Fee-estimate path (~3987) | Template / expectation |
| `bei.already_generated_coins` (~2293) | Running `already_generated` accumulator |
| **pop_block** reversal | Uses the same accumulation arithmetic — must stay atomic with connect |

A one-atomic-unit per-block delta on any height moves **all** sites in lockstep.
C2a′ grid must include:

- Single-block tuples `(median_weight, block_weight, already_generated, version[, tx_volume_avg])`.
- **Multi-block accumulation:** replay N blocks (e.g. 1000-height sequence),
  compare `already_generated` trajectory Rust-vs-C++ (or vs spec oracle) — a
  single-block grid can pass while accumulation silently drifts into a chain split.

**H3 — "C2a′ gates C2c" needs teeth, not an honor-system comment.**

Within one PR, C2a′ and C2c land on `dev` together unless structurally enforced.
**Required discipline:**

1. **Separate commits** in order: C2 → **C2a′** (both KAT legs green) → **C2c** (FFI + rewire + C++ body deletion).
2. **C2c commit message** cites the **C2a′ commit hash** as precondition (same pattern as merge-commit release boundaries).
3. **CI:** cross-check test target is a **required check** on the PR; C2c commit must not appear on the branch until C2a′ is an ancestor (enforce via commit order + reviewer map, not a comment in FOLLOWUPS).

Soft "gates" on a consensus-formula swap is genuinely dangerous; treat H3 as
load-bearing for implementation PR review.

#### Segment 2i carry list (wider-substrate audit)

| ID | Finding | Disposition |
|----|---------|-------------|
| **G1** | Cross-language single formation for `stake_ratio` + burn ActivityMetric entry shape | §5.3 + C1/C3 implementation |
| **G2** | 0h dual-leg KAT (H1) + multi-block accumulation (H2) + commit-ordered cutover (H3) | C2a′ → C2c; see hazards above |
| **G3** | R5 fixture: when `total_staked > 0`, `stake_ratio` / burn fields must come from a run where `add_staked_outputs` populated the cache — **not** the stubbed-zero `get_stake_ratio` path | §5.4 `staking_state: live`; 2i verifies fixture metadata matches evidence from `blockchain.cpp` stake scan |
| **G4** | Fee/burn input staleness at send time (`ActivityMetric` vs block-connect snapshot) | 2i audit (unchanged) |
| **G5** | `parameters_snapshot` cache poison | 2i audit (unchanged) |

---

## §6 Round 2 — Segment placeholders

Round 1 segments **2a–2d** and **2g** are **closed** (§5.3–§5.6). Round 2
work is close-out + wider-substrate audit.

| Segment | Scope | Status |
|---------|-------|--------|
| **2g** | Close-out — refresh §4/§6 binding matrix; Round 3 readiness gate | **Open** |
| **2i** | Wider-substrate audit — §5.8 G1–G5; fee staleness; snapshot cache | **Open** (G1–G3 pre-pinned) |

### §6.1 PR 6 / PR 7 merge

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
| **C0** | Phase 0 §2.7 naming amendment (`base_emission_at`, `burn_amount`) + doc co-land |
| **C1** | `EconomicsError`, `ActivityMetric` (§5.3 R1), `EconomicsParametersSnapshot` + `CalibrationStamp` (§5.3 R2) |
| **C2** | `shekyl-economics`: `base_block_reward` + `projected_already_generated` + `calc_stake_ratio` + `calc_burn_pct_from_activity`; sim rewired to 0h |
| **C2a′** | Dual-leg KAT (H1): leg A Rust==C++ `get_block_reward`; leg B Rust==spec/sim oracle; **multi-block** `already_generated` accumulation grid (H2). Dedicated commit; CI required check |
| **C2c** | `shekyl_base_block_reward` FFI; rewire **all** `get_block_reward` consumers + accumulation sites (H2); target = `economics.h` thin-wrapper shape; delete C++ formula only after C2a′ hash cited in message (H3) |
| **C2b** | `ChainEconomicsSource` + production adapter |
| **C3** | `EconomicsEngine` + `LocalEconomics` impl; `CALIBRATION-PENDING` doc comments |
| **C4** | `RecordedChainFixture` (§5.4) + engine-vs-sim differential (supplementary only); consensus 0h gate is **C2a′** dual-leg + accumulation (H1–H2), not C4 |
| **C5** | `Engine` `E` slot + `economics` field |
| **C6** | Benches + `PERFORMANCE_BASELINE.md` |
| **C7** | Docs: CHANGELOG, rustdoc, design doc Phase 1 landed; calibration banners |

### §7.1 Stage 1 closeout

After **PR 6 + PR 7** implementation merge — not either alone.

---

## §8 Discipline-citation matrix (seed)

| # | Discipline | Failure mode foreclosed |
|---|------------|-------------------------|
| 1 | Canonical derivation; 0h + Rust-vs-C++ KAT | Bug 2/7; false confidence from Rust-only differential |
| 1b | `calc_stake_ratio` single helper (wallet + FFI) | Cross-language stake_ratio divergence |
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
| **Round 1 segment 2b drafted** | `Round 1 segment 2b drafted 2026-05-27; §2.7 naming amendment locked (current_emission→base_emission_at, burn_fraction→burn_amount, C0); base_emission_at = pure shekyl-economics projection under (A), reads nothing from ChainEconomicsSource; source shrunk to one read (active_weighted_stake).` |
| **Round 1 closed** | `Round 1 closed 2026-05-27; segments 2a/2c/2d/2g disposed. ActivityMetric = raw integer observables (calc_burn_pct owns ratios). Snapshot = rulebook constants + as_of (not dashboard). RecordedChainFixture = sim-recorded, params-digest-pinned, two-array (differential vs neutral milestones). No V3.0 consumer call sites. §2.7 surface changes are C0-only.` |
| **Round 2 substrate pins** | `§5.8 2026-05-27: migration ratified V3.0; H1 dual-leg KAT, H2 multi-block accumulation + full blast radius, H3 commit-ordered cutover; G3 add_staked_outputs vs stub.` |

---

## Appendix A — Spec trait surface (reference)

**Signature-only.** Full contract (rustdoc) lives in
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7. When
implementing **0a** (`traits/economics.rs`), copy **signatures and doc comments
from §2.7**, not from this appendix — see §5.2 B.9.

```rust
pub trait EconomicsEngine {
    type Error: Into<EconomicsError>;

    fn base_emission_at(&self, height: u64) -> Result<u64, Self::Error>;
    fn burn_amount(
        &self,
        fee: u64,
        activity: ActivityMetric,
    ) -> Result<u64, Self::Error>;
    fn pool_weighted_total(&self) -> u128;
    fn parameters_snapshot(&self) -> EconomicsParametersSnapshot;
}
```

Signatures above match §2.7 (verified Round 1 segment 2b). Shorthand only —
`base_emission_at` / `burn_amount` / `pool_weighted_total` caveats are not
duplicated here.

---

## Appendix B — PR 6 linkage

Unchanged — both PRs required for Stage 1 trait inventory; coordinate `Engine<…>`.

---

## Appendix C — Round 0 feedback index (C-1–C-7)

| ID | Correction |
|----|------------|
| **C-1** | Strike `MockEconomics`; real-path + differential |
| **C-2** | Reframe §4.5.1; add **(2′)** |
| **C-3** | F4 grep; **(A)** for `base_emission_at` |
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
