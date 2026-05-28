# Stage 1 PR 7 — `EconomicsEngine` extraction — design

**Status.** **Round 0 closed (2026-05-27).** Round 1 **in progress** — segment
**2b drafted** (2026-05-27): §2.7 naming amendment locked (C0);
`base_emission_at` = pure `shekyl-economics` projection under interpretation
**(A)**; `ChainEconomicsSource` shrunk to **one read**. Segments **2a**, **2c**,
**2d**, **2g** pending. Planning doc branch:
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
4. **Supporting types** — `EconomicsError`, `EconomicsParametersSnapshot`
   (incl. `as_of` / calibration-generation tag), `ActivityMetric`.
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
| **5 — closure-rule** | Round 0 closed; Round 1 segment 2b drafted. |
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

> **Round 1 status:** IN PROGRESS — segment **2b drafted**. **F4 closed** →
> interpretation **(A)** for `base_emission_at`. **C0 naming locked** (§5.1).

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
| **0d** | `EconomicsParametersSnapshot` + `as_of` | economics types | Calibration-generation tag |
| **0e** | `ActivityMetric` | same | Field-projected daemon/orchestrator input |
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
| **R1** | `burn_amount` name + unit **locked**; overflow KAT **locked**. **Open:** `ActivityMetric` layout + caller-trust doc | 2a |
| **R2** | `EconomicsParametersSnapshot` + `as_of`. **Open:** which `EconomicParams` fields surface | 2a |
| **R3** | `active_weighted_stake` snapshot-bound read + `pool_weighted_total` **0-semantics** (§2.7 rustdoc pinned). **Open:** snapshot/reorg wording polish only | 2b |
| **R4** | **Specified §5.2** — projection in crate; source one read; bench O(height); overflow-only `Err` under **(A)** | 2b — **closed pending drafting** |
| **R5** | Two-test split (§5.2 B.5). **Open:** `RecordedChainFixture` format | 2c |
| **R6** | No V3.0 `Engine` callers; fee-path wiring **follow-up, not built**. **Open:** boundary statement | 2d |
| **R7** | **Flipped** — C0 naming amendment required; confirm no *other* §2.7 change at 2g | 2g |

#### §4.5.5 Round 1 disposition

**Open** for segments 2a, 2c, 2d, 2g. **Closed (do not reopen):** items in §5.4.

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

### §5.3 R-residuals (remaining segments)

See §4.5.4 — R4 closed pending inline drafting; R1/R2/R3/R5/R6 open.

### §5.4 Closed / open fence

**Closed — do not reopen in Round 1:**

- Trait identity / consume-not-subsume (2026-05-08).
- `MockEconomics` struck (C-1).
- Lens 1 bounded; Lens 2/3 N/A with sharpenings.
- 0h + `projected_already_generated`.
- **(2′)** `ChainEconomicsSource` — **one read** at V3.0.
- F4 → **(A)** for `base_emission_at`.
- **Method names: `base_emission_at`, `burn_amount`.**
- R4 disposition (§5.2).

**Open for segment wargaming:** `ActivityMetric` layout (R1); snapshot field layout
(R2); R3 snapshot/reorg **wording polish** only (0-semantics pinned §5.2 B.8);
fixture format (R5); consumer-boundary statement (R6); 2g confirm no other §2.7
change (R7).

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
| **C0** | Phase 0 §2.7 naming amendment (`base_emission_at`, `burn_amount`) + doc co-land |
| **C1** | `EconomicsError`, `ActivityMetric`, `EconomicsParametersSnapshot` + `as_of` |
| **C2** | `shekyl-economics`: `base_block_reward` + `projected_already_generated` + unit tests; sim rewired to 0h |
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
| **Round 1 segment 2b drafted** | `Round 1 segment 2b drafted 2026-05-27; §2.7 naming amendment locked (current_emission→base_emission_at, burn_fraction→burn_amount, C0); base_emission_at = pure shekyl-economics projection under (A), reads nothing from ChainEconomicsSource; source shrunk to one read (active_weighted_stake).` |
| Round 1 close | *(pending — after 2a, 2c, 2d, 2g)* |

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
