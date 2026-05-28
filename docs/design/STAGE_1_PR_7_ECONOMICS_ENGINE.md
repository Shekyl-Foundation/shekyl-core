# Stage 1 PR 7 — `EconomicsEngine` extraction — design

**Status.** **Round 0 closed (2026-05-27).** **Round 1 closed (2026-05-27).**
**Round 2 closed (2026-05-28)** — close-out §6.2 + segment **2i** (G4/G5). **Round 3
open** — §7.X commit decomposition binding; Phase 0 / implementation PRs may cut
after §2.7 C0 co-lands on `dev`. Planning doc branch:
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
**both** PR 6 implementation and **all three PR 7 implementation PRs** (7-base,
7-cutover, 7-trait — §7.0) land. Do not link to
`STAGE_1_COMPLETION_AUDIT.md` — that doc is not yet in the tree (per FOLLOWUPS).

**Branch (design).** `feat/stage-1-pr7-economics-engine-design` off `dev` at
`2cf4cbfde` — design branch remains authoritative for §7.X until **Round 3 closes**
(all three implementation PRs + PR 6 on `dev`). **Implementation PRs authorized**
(§7.0): `feat/stage-1-pr7-economics-base` → then `feat/stage-1-pr7-economics-cutover`
and `feat/stage-1-pr7-economics-engine` as siblings off post–7-base `dev`. Phase 0
**C0** may co-land with first implementation branch.

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
12. **Implementation PR split (§6.2 item 1, §7.0)** — **7-base** (C2 + C2a′ +
    fix **α**), **7-cutover** (C2c), **7-trait** (C0, C1, C2b–C7); cutover and
    trait are siblings off 7-base.

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
  implementor-side. Round 2 close-out confirmed: no §2.7 change beyond C0 (R7).

### §3.2 Plan-altitude principles

| Principle | Applicability |
|-----------|----------------|
| **4 — architectural-integrity-now** | Build mechanism in force now; values marked `CALIBRATION-PENDING`. |
| **5 — closure-rule** | Round 0 closed; Round 1 closed; **Round 2 closed** (2026-05-28); **Round 3 open**. |
| **6 — wider-substrate audit** | Segment **2i** closed §6.3 (2026-05-28). |
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

## §4 Round 1 — Load-bearing question (CLOSED)

> **Round 1 status:** **CLOSED (2026-05-27).** Dispositions in §5.3–§5.6.
> **Round 2 closed (2026-05-28).** **Round 3 open** — §7.X binding.

### §4.1–§4.3

See §1, §2, §3.

### §4.4 Phase 0 binding matrix (closed Round 2 — 2026-05-28)

Cross-ref §7.0 / §7.1 for implementation commit placement. All IDs bound.

| ID | Binding form | Module / PR | Notes |
|----|--------------|-------------|-------|
| **C0** | §2.7 rename co-land | `V3_ENGINE_TRAIT_BOUNDARIES.md` + **7-trait** | `base_emission_at`, `burn_amount` — §5.1 |
| **0a** | `trait EconomicsEngine` | `traits/economics.rs` — **7-trait** C3 | §2.7 **signatures + rustdoc** verbatim — **not** Appendix A (§5.2 B.9) |
| **0b** | `LocalEconomics<S: ChainEconomicsSource>` | `local_economics.rs` — **7-trait** C3 | |
| **0b′** / **C2b** | `trait ChainEconomicsSource` + adapter | `chain_economics_source.rs` — **7-trait** C2b | **One read** at V3.0 (`active_weighted_stake`); R3 read contract §5.2 B.8 |
| **0c** / **C1** | `EconomicsError` + `ActivityInvariantViolation` | `engine/error.rs` — **7-trait** C1 | |
| **0d** / **C1** | `EconomicsParametersSnapshot` + `CalibrationStamp` | economics types — **7-trait** C1 | `generation`, `params_digest` (custom LE digest — §6.3 G5) |
| **0e** / **C1** | `ActivityMetric` + `::new` | `shekyl-economics` — **7-trait** C1 | `as_of_height`; §6.3 G4 |
| **0f** / **C5** | `Engine<…, E>` + `economics: E` | `mod.rs`, lifecycle — **7-trait** C5 | Coordinate PR 6 §6.1 |
| **0g** / **C4** | `RecordedChainFixture` + `ChainMirrorSource` | `test_support` — **7-trait** C4 | **Replaces MockEconomics**; `staking_state: live` when `total_staked > 0` (G3) |
| **0h** / **C2** | `base_block_reward(already_generated_coins: u64) -> u64` | `shekyl-economics` — **7-base** C2 | Single source for engine, FFI, sim |
| **0h′** / **C2** | `projected_already_generated(height, params) -> u64` | `shekyl-economics` — **7-base** C2 | Neutral **(A)**; pairs with 0h |
| **0i** / **C4** | Engine-vs-sim differential test | `shekyl-engine-core` tests — **7-trait** C4 | Supplementary; **0h gate = C2a′** (H1–H2), not C4 |
| **0j** / **C4** | `RecordedChainFixture` JSON schema | `docs/test_vectors/economics/` — **7-trait** C4 | §5.4 R5 — sim-recorded, two arrays |
| **C2a′** | Dual-leg + accumulation harness + fix **α** | C++ `blockchain.cpp` + tests — **7-base** | A/B-accum == **`Q4_spec`**; `:1608–1609` delete — §5.8 |
| **C2c** | FFI + `get_block_reward` rewire + ESF delete | C++ + `shekyl-ffi` — **7-cutover** | Post–7-base only (H3); H2 blast radius in §6.2 item 1 |
| **C6** | Benches + baseline | **7-trait** | `PERFORMANCE_BASELINE.md` |
| **C7** | Docs closeout | **7-trait** | CHANGELOG, rustdoc, G4/G5 pins |

**Orphan check:** all Phase 0 IDs **0a–0j** mapped. §2.1 scope bullets 1–12 align
with rows above. **C2** does not appear on 7-cutover or 7-trait-only branches except
as **7-base** ancestor dependency.

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

**R3 read contract (normative; polish closed Round 2 — 2026-05-28):** `active_weighted_stake()`
reads through the engine's consistent ledger view at a height-bound snapshot —
not a racy direct DB peek outside that view. `pop_block` / accrual-mirror
atomicity covers the reorg boundary (implementation detail at C2b). Return
feeds `pool_weighted_total()` verbatim (single aggregation path). Zero-semantics
for the public method: §2.7 `pool_weighted_total` rustdoc above. Copy into
§2.7-facing prose at C0/C2b if not already verbatim.

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
    /// Prev-block `already_generated` at `as_of_height` (consensus burn site quantity).
    pub circulating_supply: u64,
    /// Principal-pool total staked amount (chain-mirror; not wallet registry).
    pub total_staked: u128,
    /// Height all four fields were sampled for (0 = genesis).
    pub as_of_height: u64,
}
```

**2i additive amendment (G4, §6.3):** fourth raw field + validated constructor —
does **not** reopen the raw-observables / no-precomputed-ratios pin.

- **Single constructor** — `ActivityMetric::new(tx_volume, circulating_supply,
  total_staked, as_of_height) -> Result<Self, ActivityInvariantViolation>` in
  `shekyl-economics`. Validates structural invariants (cap, can't-stake-more-than-
  exists, height sanity). **No** `#[cfg(test)]` bypass — tests use the same `new()`
  with `RecordedChainFixture` / JSON vectors ("real path, real fixture").
- **Coherence contract** — all four fields must reflect **one chain state** at
  `as_of_height`. Enforced by the **producer** (one LMDB read txn or one daemon
  atomic endpoint), documented in rustdoc; not re-checkable inside `burn_amount`
  without chain access. See §6.3 G4 + FOLLOWUPS (wallet producer actor; conditional
  daemon endpoint).
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
- **`circulating_supply` quantity:** consensus passes **`already_generated` at
  height−1** at the burn site (`validate_miner_transaction`, same as `/get_info`
  today). **Not** `already_generated − total_burned` unless a future consensus
  amendment changes the burn site — do not "fix" wallet to a different quantity
  without that amendment.
- **Genesis edge (`as_of_height = 0`):** when `circulating_supply = 0`,
  `calc_burn_pct` treats `stake_ratio = 0` (vacuous denominator) → `burn_amount`
  returns 0. One-line guard in `calc_burn_pct` (C3), not a trait `Err`.
- **Canonical burn entry point (implementation PR):** add an outer
  `calc_burn_pct_from_activity` / `burned_amount_from_activity` that (1) forms
  `stake_ratio` via the shared ratio helper, (2) calls the existing
  `calc_burn_pct(..., stake_ratio, ...)` core. The precomputed-`stake_ratio`
  signature remains for C++ `compute_fee_burn` but is **not** a second formation
  site — C++ must keep passing a ratio already produced by
  `shekyl_calc_stake_ratio`, not a locally computed division.
- **Integers only** — fixed-point math per [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md)
  (no float across FFI/trait; divergent rounding fails consensus).

**Caller-trust rustdoc (field-projection lens):** all fields are wallet-actor-
assembled from an atomic upstream read. State explicitly: advisory inputs;
`burn_amount(fee, activity)` returns the burn consensus **would compute at
`activity.as_of_height`**; on-chain burn at block-connect may differ if the block
lands at a different height — **consumer** decides whether staleness is
acceptable (no tolerance/range in the trait — pre-provision-for-flexibility).
At V3.0 the only named future consumer is display (`PendingTxEngine` fee path
is a FOLLOWUPS seam, not a live caller). Failure mode is **wrong display**, not
failed send, theft, or user consensus risk: consensus recomputes burn at accept;
miner coinbase must match or the **block** is invalid. Must not claim
authoritative on-chain burn.

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
    pub as_of: CalibrationStamp,            // staleness detection — §6.3 G5
}

pub struct CalibrationStamp {
    /// Monotonic calibration generation (pre-genesis recalibration; V3.x adaptive-burn epoch).
    pub generation: u32,
    /// Blake2b-256 of canonical-serialized resolved `EconomicParams` (not raw JSON bytes).
    pub params_digest: [u8; 32],
}
```

**2i additive amendment (G5, §6.3):** `CalibrationStamp` gains structured
`generation` + `params_digest` — replaces Round 1 "optional param-epoch" placeholder;
does **not** reopen §2.7 (implementor-side 0d layout).

- **Base values, not decayed.** Effective `staker_emission_share` is height-varying
  even at V3.0; snapshot carries base + decay rate; consumer applies decay.
- **Tiers by reference** — single source `shekyl-staking::tiers`; no duplicated
  lock-block pairs in economics types.
- **Integers** — basis points / milli-units; same no-float discipline as R1.
- **No-cache** — already in §2.7 rustdoc; `as_of` lets consumers detect stale copies.
- **`params_digest` encoding (pinned):** Blake2b-256 over **custom canonical byte
  layout** of the resolved `EconomicParams` struct — little-endian, fixed-width fields
  in documented order (`shekyl-economics` module rustdoc + `build.rs` helper). **Not**
  raw `economics_params.json` bytes (JSON formatting drift). **Not bincode** — rejected
  2026-05-28: library-version and cross-toolchain serialization drift (MSVC vs GCC;
  prior platform drift incidents) at a calibration-critical surface; matches
  consensus-constants hand-canonicalization pattern.
- **Independent from G4 at V3.0:** `generation` is a configuration epoch index, not a
  chain height. No `generation_active_at(height)` at V3.0; rustdoc notes V3.x adaptive
  burn may bind calibration to heights (FOLLOWUPS). `ActivityMetric.as_of_height` and
  `CalibrationStamp.generation` are formally independent staleness surfaces.

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

**G4 pin (§6.3):** any future `burn_amount` consumer must consult
`activity.as_of_height` and apply its own staleness policy; the method does not
gate on freshness.

**G5 pin (§6.3):** any future `parameters_snapshot` consumer must compare
`as_of.generation` and `as_of.params_digest` before trusting a cached copy; the
method does not gate on freshness.

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
- R1 `ActivityMetric` layout + caller-trust (+ **2i G4 additive:** `as_of_height`, `::new`, `ActivityInvariantViolation`).
- R2 rulebook snapshot + structured `CalibrationStamp` (`generation`, `params_digest`).
- R3 read contract + `pool_weighted_total` 0-semantics.
- R5 fixture schema (two-array, sim-recorded).
- R6 zero V3.0 consumer call sites.
- R7 C0-only.

**Round 2 (not Round 1):** segment **2i** wider-substrate audit (§5.8 pins) — **closed**
§6.3. Round 2 close-out §4/§6 — **closed**. Round **3** §7.X — **open**.

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

**Disposition (ratified 2026-05-27):** **Migration path; C++ cutover in V3.0.**
Wallet-only re-expression is rejected. See [`FOLLOWUPS.md`](../FOLLOWUPS.md).

**Implementation PR scope (amended Round 2 close-out §6.2 item 1, 2026-05-28):**
cutover lands in V3.0; **three implementation PRs** off a shared keystone
(7-base → 7-cutover ∥ 7-trait). The migration *decision* is unchanged; the
*packaging* splits at the C2/C2c seam, not at "consensus vs trait."

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

C2c is not "rewire one function." Production `cryptonote::get_block_reward`
call sites are enumerated in §6.2 (7-cutover PR map). **Accumulation is a
separate derived quantity** — see **C2a′ grid spec** below; it is **not**
`base_block_reward(ag)` chained naively.

| Concern | Verified locus | Role |
|---------|----------------|------|
| Accept / coinbase bound | `validate_miner_transaction` (`blockchain.cpp:1583`) | Validates **Q3** locally; out-param = **`Q_full_emission`** after fix **α** (today overwritten to **`Q_miner_base`**) |
| Fee gates / estimates | `check_fee` (:3987), `get_dynamic_base_fee_estimate_2021_scaling` (:4071) | **Q_subsidy** (4-arg) |
| Staker accrual inflow | `handle_block_to_main_chain` (:5021) | **Q2** → pool only — **unchanged** by fix **α** |
| LMDB `already_generated_coins` | `handle_block_to_main_chain` (:4946) | **`Q4_spec`** after fix **α**; today **`Q4_cpp`** via site **1** overwrite bug |
| Alt metadata (provisional) | `handle_alternative_block` (:2291–2293) | **Throwaway** `get_outs_money_amount(miner_tx)` — not promoted path |
| Reorg | `switch_to_alternative_blockchain` + `pop_block_from_blockchain` (:799–824) | Pop + replay through main connect |

A one-atomic-unit per-block delta on **Q_chain_ag** moves accept, fee, and subsidy
input in lockstep. C2a′ must exercise **per-quantity** single-block grids **and**
**Q_chain_ag** multi-block + pop-replay grids (not subsidy-only chaining).

**H3 — "C2a′ gates C2c" needs teeth, not an honor-system comment.**

**Preferred enforcement (§6.2 item 1 — three-PR split):** **7-cutover branches off
7-base.** C2a′ is an ancestor of C2c by branch topology — the KAT-before-cutover
invariant is structural, not reviewer-map discipline alone.

**Fallback (bundled single PR):** separate commits in order C2 → C2a′ → C2c; C2c
message cites C2a′ hash; CI cross-check is a required check on the PR.

1. **Separate commits** in order: C2 → **C2a′** (both KAT legs green) → **C2c** (FFI + rewire + C++ body deletion) — required in bundled mode; in split mode C2a′ lives only on **7-base**, C2c only on **7-cutover**.
2. **C2c commit message** cites the **C2a′ commit hash** (or **7-base merge commit**
   on `dev`) as precondition.
3. **CI:** dual-leg + accumulation cross-check is a **required check** on **7-base**
   before **7-cutover** merges; cutover PR must not target `dev` until **7-base** is
   merged.

Soft "gates" on a consensus-formula swap is genuinely dangerous; treat H3 as
load-bearing for implementation PR review.

#### C2a′ grid spec — three-quantity KAT matrix (amended 2026-05-28, disposition pinned)

**Substrate (code-verified, 2026-05-28).**

| Locus | What happens |
|-------|----------------|
| `:1583–1609` | Site **1**: `get_block_reward` → full **`base_reward`**; validates coinbase against **`miner_base_reward`** + fees; **overwrites out-param** with `miner_base_reward` ("for caller tracking") |
| `:4927–4946` | **Only** `validate_miner_transaction` caller: reads out-param at `:4946` as **`already_generated += base_reward`** |
| `:5021–5052` | Site **4**: separate 4-arg `get_block_reward` → pool — **does not write `already_generated`** |
| Claim connect | `blockchain_db.cpp:220–226`: pool decremented; claim outputs minted — **no `already_generated` update** |

**Root cause (not missing site-4 increment):** the under-count is the **`:1608–1609` overwrite**
that renames the out-param from full block subsidy to miner share. `:4946` reads
`base_reward` expecting block emission (the natural meaning of the name); the overwrite
hands it **`Q_miner_base`**. Site **4** was never a second accumulation writer — the bug
is upstream in site **1**.

**`validate_miner_transaction` out-param consumers (7-base entry check, settled):**

```text
rg 'validate_miner_transaction\(' src/
→ blockchain.cpp:4927 only (production)
→ out-param used at :4946 only
```

Site **4** does not consume the out-param (recomputes `full_block_emission`). Fee paths,
pop, and alt metadata do not call site **1**. The "for caller tracking" overwrite targets
**:4946** exclusively; removing it is unconditionally correct for that caller. Miner-share
needs inside site **1** stay on local **`miner_base_reward`**.

**Site 4 verification (settled):** staker inflow → **`staker_pool_balance`** only — unchanged
by the pinned fix.

##### Accumulation disposition (spec-fixed — not an open Reading 1 vs 2 gate)

[`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) Component 4 is explicit: **no new coins
created**; staker share is redirected **from** `block_emission`; **total emission per
block is unchanged**; the `2^32` ceiling is unaffected. The interdependency diagram is
`block_emission → STAKER_EMISSION_SHARE + MINER_EMISSION (remainder)`.

**Reading 1 (miner-only `already_generated`, staker mint "additional") is ruled out.**
If `already_generated` tracked miner share only while staker coins were real minted
supply, total issuance would outrun the ESF curve input, the cap would break, and the
spec's "total emission unchanged" property would be violated.

**Reading 2 (spec disposition):** `already_generated` must track **full block emission**
(`Q_full_emission` / post-release effective reward) for ESF / cap integrity. Component 4
redistributes **within** that total; it does not create a second issuance axis.

Running C++ under-counts because site **1** overwrites the out-param before `:4946` reads
it — not because site **4** fails to compensate.

##### Pinned fix — option α (7-base, before 7-cutover)

**Do:** Remove the **`base_reward = miner_base_reward`** overwrite at
`validate_miner_transaction` `:1608–1609`. Leave the out-param as full post-`get_block_reward`
subsidy ( **`Q_full_emission`** at connect weights). `:4946` then accumulates spec-correct
emission in **one** LMDB write path. Site **4** unchanged on `already_generated`.

**Coinbase bound check (verified 2026-05-28):** validation at `:1598–1606` compares
`money_in_use` against **`miner_base_reward + effective_fee`** (local variables), **not**
the out-param. The overwrite at `:1609` serves **`:4946` only** — removing it does **not**
widen the accept bound or let a miner claim the staker share. Implementer scope: **delete
the overwrite line**; no bound retarget required.

**Do not (option β — rejected):** Add **`Q_staker_emission`** to `already_generated` at
site **4** to compensate for the overwrite. Correct if arithmetic is perfect, but:

1. **Two writers per block** — read-modify-write on `already_generated` across two connect
   sites inside one block txn instead of one authoritative increment.
2. **Pop/reorg mental model** — row-pop still works, but reversal tracks a two-site sequence
   rather than a single `:4946` write.
3. **Cap invariant demoted** — full-emission accounting becomes a **runtime sum across sites**
   instead of a **structural property of one accumulation site**.

Pre-genesis structural fix beats compensating patch. Same rationale as single-site-of-truth
elsewhere (HandleTable disposition).

**Cap-integrity invariant (defense-in-depth after fix α):**

```text
Δ_main_to_ag + Δ_accrual_to_ag == Q_full_emission     // post-fix: Δ_accrual_to_ag == 0
```

Under fix α, **`Δ_accrual_to_ag = 0`** structurally — site **4** stays pool-only. Layer 2
still asserts the invariant on connect replay so a future regression reintroducing a
second writer or re-overwriting the out-param fails CI without relying on B-accum alone.

**7-base obligation:** Land fix **α**; A-accum and B-accum **converge** on **`Q4_spec`**;
cap invariant green; then 7-cutover.

##### Derived quantities (name → definition)

| ID | Symbol | Definition |
|----|--------|------------|
| **Q0** | `Q_subsidy` | Return value of `cryptonote::get_block_reward(...)` for the call's arity/weights (4-arg = no release multiplier; 5-arg = release applied) |
| **Q1** | `Q_miner_base` | `shekyl::compute_emission_split(Q_subsidy, height, …).miner_emission` |
| **Q1s** | `Q_staker_emission` | `emission_split(Q_subsidy, height, …).staker_emission` (= `Q_full_emission − Q_miner_base` when split inputs match) |
| **Q2** | `Q_full_emission` | Full block emission for height *h*: `Q_subsidy` at site-4 weights `(0, 0, prev_ag, 4-arg)` — equals pre-split block reward for cap / ESF stepping |
| **Q3** | `Q_miner_coinbase` | `Q_miner_base + burn.miner_fee_income` (coinbase template / accept bound) |
| **Q4_spec** | `Q_chain_ag` (spec) | **`prev_ag + Q_full_emission`** per block (capped at `MONEY_SUPPLY`) — ESF / sim / post-fix LMDB |
| **Q4_cpp** | `Q_chain_ag` (broken C++) | **`prev_ag + Q_miner_base`** at `:4946` today — **overwrite bug**; leg A pre-fix reproduction only |

**Cap-integrity invariant** — see fix **α** above (defense-in-depth; structurally
`Δ_accrual_to_ag = 0` after fix).

**Sim oracle (leg B):** `shekyl-economics-sim` (`engine.rs:166`) steps **`effective_reward`**
(full pre-split emission) — aligns with **`Q4_spec`**, not **`Q4_cpp`**, on unfixed C++.

**Alt-chain metadata (`blockchain.cpp:2291–2293`):** provisional
`get_outs_money_amount(miner_tx)` — **not** promotion path. C2a′ **must not** assert alt == main.

##### Per-site target quantity (C2c must not conflate)

| Site | Target quantity | C2c note |
|------|-----------------|----------|
| **1** `validate_miner_transaction` | Validates **Q3** (local `miner_base_reward`); out-param to `:4946` = **`Q_full_emission`** (fix **α**: no overwrite) | Remove `:1608–1609` overwrite |
| **2** `check_fee` | **Q_subsidy** (4-arg) | Fee math input |
| **3** `get_dynamic_base_fee_estimate_*` | **Q_subsidy** (4-arg) | Fee estimate tiers |
| **4** post-`add_block` staker accrual | **Q2** → pool inflow only | **Unchanged** on `already_generated` |
| **5** `construct_miner_tx` | **Q_subsidy** → **Q3** | Template coinbase |
| **6–7** `fill_block_template` | **Q_subsidy** (+ fees) | Pool optimization |
| **Accum** `:4946` | **`Q4_spec`** after fix **α** | Single accumulation site |

Uniform `shekyl_base_block_reward` substitution at every site **without** this map
is a consensus conflation hazard.

##### C2a′ test matrix (7-base, CI required)

**Layer 1 — Single-block, per-quantity (legs A + B on each Q*)**

Grid tuples: `(median_weight, block_weight, already_generated, version[, tx_volume_avg])`.

| Quantity | Leg A | Leg B |
|----------|-------|-------|
| **Q_subsidy** | Rust compose == C++ | Rust == spec/hand grid (ESF + penalty + release if 5-arg) |
| **Q_miner_base** / **Q_staker_emission** | Rust compose == C++ split | Spec split of **Q_subsidy** |
| **Q_full_emission** | Site-4 call shape == C++ | Same |
| **Q_miner_coinbase** | Template/validate == C++ | Spec compose (split + burn miner leg) |

**Layer 2 — Multi-block accumulation (legs A + B + cap invariant)**

Two composed trajectories for N blocks (≥1000-height sequence recommended):

**A-accum (C++ reproduction — miner-only loop, matches LMDB today):**

```text
ag := genesis_fixture
for each block h:
  prev := ag
  Q_sub  := get_block_reward(..., prev, ...)          // connect weights/volume
  Q_min  := emission_split(Q_sub, h).miner
  ag     := min(MONEY_SUPPLY, prev + Q_min)             // :4946 shape → Q4_cpp
```

**B-accum (spec / sim oracle — full emission):**

```text
ag := genesis_fixture
for each block h:
  prev := ag
  Q_full := Q_full_emission(prev, h)                    // match site-4 / sim stepping
  ag     := min(MONEY_SUPPLY, prev + Q_full)            // Q4_spec
```

**Per-block cap invariant (same scenario):**

```text
assert Δ_main_to_ag + Δ_accrual_to_ag == Q_full_emission
```

using live C++ increments from connect replay (expected **fail** until 7-base fix).

| Leg | Assertion |
|-----|-----------|
| **A-accum** | A-loop == `get_block_already_generated_coins(h)` after connect-path replay |
| **B-accum** | B-loop == `shekyl-economics-sim` macro `already_generated` stepping (`engine.rs:166`) |
| **Cap invariant** | Two-site / full-emission sum == **Q_full_emission**; **must pass on fixed chain** |
| **A vs B** | **Equal after fix α.** Pre-fix: A = **`Q4_cpp`**, B = **`Q4_spec`** — expected divergence blocks cutover |

**Do not** silence A vs B by modeling miner-only in the B oracle (mirror phantom-pass).
**Do not** implement option β to make B pass while leaving the overwrite in place.

**Layer 3 — Pop-replay (reorg coupling)**

After N-block main-chain build capturing `already_generated` at tip:

1. `pop_block` K times.
2. Replay K blocks through `handle_block_to_main_chain`.
3. Assert `get_block_already_generated_coins` **byte-identical** to pre-pop tip.

Uses post-fix **α** semantics (`:4946` = full emission; site **4** pool-only).

##### C2a′ commit deliverables (7-base)

- [ ] **`validate_miner_transaction` caller grep** — single consumer `:4946` (pinned above)
- [ ] **Fix α:** remove `:1608–1609` overwrite; `:4946` accumulates full `base_reward`
- [ ] Layer 1 per-quantity; Layer 2 A-accum + B-accum + cap invariant; Layer 3 pop-replay
- [ ] CI **required workflow** landed (§7.4 E1) — skeleton on `dev`; layer jobs green when harness registers
- [ ] A-accum == B-accum == **`Q4_spec`** before 7-cutover merges

##### C2a′ amendment record

- **2026-05-28a:** Post-split `:4946` only; guard raw-subsidy phantom-pass.
- **2026-05-28b:** Spec pins Reading 2; **`Q4_spec` vs `Q4_cpp`**; site **4** pool-only;
  B-accum enforces spec/sim.
- **2026-05-28c:** Root cause = site **1** overwrite `:1608–1609`; caller grep settled;
  **fix α pinned** (un-overwrite; single-site `:4946`); option β rejected; cap invariant
  = defense-in-depth.

#### Segment 2i carry list (wider-substrate audit)

| ID | Finding | Disposition |
|----|---------|-------------|
| **G1** | Cross-language single formation for `stake_ratio` + burn ActivityMetric entry shape | §5.3 + C1/C3 implementation |
| **G2** | 0h dual-leg KAT (H1) + multi-block accumulation (H2) + cutover gated on KAT (H3) | **7-base** (C2+C2a′) → **7-cutover** (C2c); **7-trait** off 7-base only — §6.2 item 1 |
| **G3** | R5 fixture: when `total_staked > 0`, `stake_ratio` / burn fields must come from a run where `add_staked_outputs` populated the cache — **not** the stubbed-zero `get_stake_ratio` path | §5.4 `staking_state: live`; 2i verifies fixture metadata matches evidence from `blockchain.cpp` stake scan |
| **G4** | Fee/burn input staleness at send time | **Converged §6.3** — display-only advisory; `as_of_height` + coherent bundle; `ActivityMetric::new` |
| **G5** | `parameters_snapshot` cache poison | **Converged §6.3** — display-only; `CalibrationStamp { generation, params_digest }` |

---

## §6 Round 2 — Segment placeholders (CLOSED 2026-05-28)

Round 1 segments **2a–2d** and **2g** are **closed** (§5.3–§5.6). Round 2
close-out + **2i** audit **closed** — Round **3** open (§7).

| Segment | Scope | Status |
|---------|-------|--------|
| **2g** | Close-out — §6.2 checklist; refresh §4 binding matrix + §7.X scope; Round 3 readiness gate | **Closed** (2026-05-28) |
| **2i** | Wider-substrate audit — §5.8 G1–G5; fee staleness; snapshot cache | **Closed** (§6.3 — G4/G5 converged 2026-05-28) |

> **Segment ID note.** Round 1 segment **2g** (§5.6, R7 C0-only) is **closed**.
> Round 2 segment **2g** (this table) is **close-out bookkeeping** — same label,
> different round. In prose, prefer "Round 2 close-out (§6.2)" vs "Round 1
> segment 2g (R7)" when ambiguity matters.

### §6.2 Round 2 close-out checklist (segment 2g — closed 2026-05-28)

Per [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §5.3 closure
criteria and PR 5 segment-2g precedent. **No new Round 1 dispositions** — reconcile
what moved in Round 1 (C0, C2a′/C2c, H1–H3, §5.8 pins) against §4/§7.X and
confirm Round 3 may open.

#### Item 1 — Implementation PR scope: cut at the C2/C2c seam (disposition recorded)

G2 ratified base-emission migration in V3.0 (§5.8). C2a′ and C2c enlarge scope
beyond the wallet trait. **Decide before §7.X is treated as binding** what
"PR 7" denotes for review, audit, and merge sequencing.

**Three layers (fault line is not "consensus vs trait"):**

| Layer | Commits | Role | Depends on |
|-------|---------|------|------------|
| **Keystone (7-base)** | **C2 + C2a′** (+ **fix α** in C++) | Canonical Rust `base_block_reward`; dual-leg /
  multi-block harness (H1–H2); **`already_generated` accumulation correction**
  (`:1608–1609` un-overwrite — small consensus semantics fix, not FFI cutover) | — |
| **Consensus cutover (7-cutover)** | **C2c** | FFI + rewire all `get_block_reward` consumers +
  delete duplicated C++ ESF body (H2 blast radius) | Keystone green (C2a′ incl. fix α) |
| **Wallet trait (7-trait)** | **C0, C1, C2b, C3, C4, C5, C6, C7** | §2.7 surface +
  `LocalEconomics` + fixtures + `E` slot | **C2 in crate only** — blind to C2c |

**Load-bearing dependency pin:** C3 `LocalEconomics` calls `shekyl-economics`
directly — needs **C2**, not **C2c**. **Do not place C2 inside the cutover PR**
or the trait serializes behind the consensus audit for no technical reason.

| Option | Shape | For | Against |
|--------|-------|-----|---------|
| **A — Bundled** | One implementation PR; commit order C2 → C2a′ → C2c → … | Minimal moving parts; G2 migration unchanged in one merge | Trait merge blocked on cutover audit; H3 = honor-system + reviewer map; mixed audit profile |
| **B — Three-PR split (ratified)** | **7-base:** C2+C2a′ → `dev`. **7-cutover:** C2c off 7-base. **7-trait:** C0…C7 off 7-base; **no** dependency on 7-cutover | H3 hard by branch topology; isolated external-audit unit (7-cutover); independent rollback; trait not blocked on cutover | Three PRs to land (solo maintainer: parallelism benefit ≈ 0 — gate + audit + rollback isolation still load-bearing) |
| **C — Two-PR "consensus first"** | 7a = C2+C2a′+C2c; 7b = trait off 7a | Isolates cutover vs trait labels | **Wrong seam:** bundles keystone with cutover; 7b needs C2 only but waits on cutover audit — same coupling as A, relabeled |
| **D — Trait before cutover** | Trait + C2 without C2c; cutover follow-up | Unblocks trait early | **Rejected:** C++/Rust 0h asymmetry on chain — violates G2 migration; reopen only via explicit G2 amendment |

**Decision record (Round 2 close-out §6.2 item 1 — 2026-05-28):**

- [x] **Chosen option:** **B — three-PR split** (keystone → cutover ∥ trait)
- [x] **Branches:** `feat/stage-1-pr7-economics-base` (7-base) →
  `feat/stage-1-pr7-economics-cutover` (7-cutover) and
  `feat/stage-1-pr7-economics-engine` (7-trait), both off post–7-base `dev`
- [x] **Merge order:** 7-base → then **7-cutover and 7-trait in either order**
  (siblings; no inter-PR dependency)
- [x] **§7.0** table added; §5.8 G2 row + H3 enforcement updated
- [x] **7-cutover PR description:** reviewer-map + rollback procedure below (H2
  sites verified in tree at `dev` tip via `rg`, 2026-05-28)

**7-base scope summary (amended 2026-05-28c — labeling refresh, not re-architecture):**

Round 2 item 1 framed **7-base** as keystone + proof harness and **7-cutover** as the
first **consensus-rule** touch (FFI swap + C++ ESF deletion). **Fix α** narrows that
split without moving the C2/C2c seam:

| What | Where | Notes |
|------|-------|-------|
| Rust canonical 0h + sim | **7-base** C2 | No chain behavior change |
| Dual-leg / accumulation KAT | **7-base** C2a′ | Harness on `dev` |
| **`already_generated` semantics** | **7-base** fix **α** | One-line C++ delete at `:1608–1609`; changes **stored `ag` trajectory** — small consensus footprint, **not** the FFI/formula cutover |
| FFI + `get_block_reward` rewire + ESF body delete | **7-cutover** C2c | Unchanged blast radius |

**Why fix α cannot wait for 7-cutover:** C2a′'s **A-accum == B-accum == `Q4_spec`**
gate is a **7-base** required check. Without fix **α** in C++, that gate stays red
until cutover — defeating the foundation-PR pattern (trait and cutover both branch off
a proven keystone). Fix lands in **7-base** alongside the harness that enforces it.

**Testnet:** pre-genesis posture — no live state to preserve; any testnet syncs from
genesis post-fix **α** (no in-band migration).

**Implementer scope for fix α:** delete `:1608–1609` overwrite only; coinbase bound
already uses `miner_base_reward` locally (`:1598–1606` verified).

#### PR 7-cutover — draft description (`feat/stage-1-pr7-economics-cutover`)

Use as the GitHub PR body when opening **7-cutover** off post–**7-base** `dev`.

---

## Summary

Consensus cutover (Stage 1 PR 7 **C2c**): replace the C++-native base block
subsidy formula in `cryptonote::get_block_reward` with the canonical Rust
primitive landed in **7-base** (C2 + C2a′), rewire every production caller,
and delete the duplicated ESF body only after **7-base** is merged and the
dual-leg KAT is green on `dev`.

**Prerequisite:** **7-base** merged to `dev` (C2 + C2a′ required check). This PR
must branch from that merge commit; C2a′ is an ancestor by branch topology (H3).

**Out of scope:** wallet `EconomicsEngine` trait (7-trait), Phase 0 §2.7
amendment, new economics parameters.

## `07-consensus-atomic-cutovers.mdc` disposition

| Criterion | Met? | Note |
|-----------|------|------|
| 1 — Consensus-rule boundary | **Yes** | Block subsidy bytes at accept, template, fee-check, and staker-accrual paths must agree chain-wide. |
| 2 — Indivisible under flag decomposition | **Yes** | No flag stages “old subsidy on chain / new subsidy in wallet”; cutover is all-or-nothing once C++ body is deleted. |
| 3 — Surface enumerated below | **Yes** | Grep-verified production call sites + accumulation coupling (this PR). |
| 4 — Rollback procedure below | **Yes** | |

Split packaging (7-base → 7-cutover ∥ 7-trait) is per
[`STAGE_1_PR_7_ECONOMICS_ENGINE.md`](STAGE_1_PR_7_ECONOMICS_ENGINE.md) §6.2
item 1; this PR is the isolated consensus artifact for external review.

## H2 — Production `cryptonote::get_block_reward` call sites (verified)

Enumeration command (must be re-run at PR open; paste output into PR if diff
from below):

```bash
rg -n 'get_block_reward\(' \
  src/cryptonote_basic/cryptonote_basic_impl.cpp \
  src/cryptonote_core/blockchain.cpp \
  src/cryptonote_core/cryptonote_tx_utils.cpp \
  src/cryptonote_core/tx_pool.cpp
```

| # | File | Line | Function / path | Overload | Target quantity | Role |
|---|------|------|-----------------|----------|-----------------|------|
| **D** | `src/cryptonote_basic/cryptonote_basic_impl.cpp` | 77–122 | `cryptonote::get_block_reward` (4-arg) | def | **Q_subsidy** core | **Delete target:** ESF + penalty → Rust FFI |
| **D′** | `src/cryptonote_basic/cryptonote_basic_impl.cpp` | 124–141 | `cryptonote::get_block_reward` (5-arg) | def | **Q_subsidy** (+ release) | Release wrapper (existing FFI) |
| 1 | `src/cryptonote_core/blockchain.cpp` | 1583 | `Blockchain::validate_miner_transaction` | 5-arg | Out-param **`Q_full_emission`** (fix **α**); validates **Q3** locally | Remove `:1608–1609` overwrite |
| 2 | `src/cryptonote_core/blockchain.cpp` | 3987 | `Blockchain::check_fee` | 4-arg | **Q_subsidy** | Mempool min-fee |
| 3 | `src/cryptonote_core/blockchain.cpp` | 4071 | `Blockchain::get_dynamic_base_fee_estimate_2021_scaling` | 4-arg | **Q_subsidy** | Fee estimate RPC |
| 4 | `src/cryptonote_core/blockchain.cpp` | 5021 | `handle_block_to_main_chain` (post-`add_block`) | 4-arg | **Q2** → pool only | Unchanged by fix **α** |
| 5 | `src/cryptonote_core/cryptonote_tx_utils.cpp` | 100 | `construct_miner_tx` | 5-arg | **Q_subsidy** → **Q3** | Template coinbase |
| 6 | `src/cryptonote_core/tx_pool.cpp` | 1630 | `tx_memory_pool::fill_block_template` | 5-arg | **Q_subsidy** (+ fees) | Empty baseline |
| 7 | `src/cryptonote_core/tx_pool.cpp` | 1684 | `tx_memory_pool::fill_block_template` | 5-arg | **Q_subsidy** (+ fees) | Per-tx optimization |
| **Acc** | `src/cryptonote_core/blockchain.cpp` | 4946 | `handle_block_to_main_chain` | — | **`Q4_spec`** after fix **α** | Single LMDB increment site |

Quantity definitions: §5.8 C2a′ grid spec (`Q0`–`Q4`).

**Public API (unchanged signatures):** `src/cryptonote_basic/cryptonote_basic_impl.h` lines 66–67.

### Explicitly out of H2 blast radius (grep false positives)

| Symbol | Location | Why excluded |
|--------|----------|--------------|
| `core_rpc_server::get_block_reward(const block&)` | `src/rpc/core_rpc_server.cpp:2317` | Sums `miner_tx.vout` amounts — **not** `cryptonote::get_block_reward` |
| `miner::get_block_reward()` | `src/cryptonote_basic/miner.h:91` | Cached template field accessor |
| `lMiner.get_block_reward()` | `src/rpc/core_rpc_server.cpp:1465` | Miner object accessor |

Tests under `tests/` that call `cryptonote::get_block_reward` directly remain
regression witnesses; update only if FFI changes observable behavior (expected:
unchanged vs C2a′ grid).

## H2 — `already_generated_coins` accumulation coupling (verified)

See §5.8 **C2a′ grid spec** for normative tests. Summary:

| Site | File:line | Mechanism |
|------|-----------|-----------|
| **A** | `blockchain.cpp:4927–4946` | **`ag` += out-param from site **1** — full emission after fix **α**; miner-only today (overwrite bug) |
| **B** | `blockchain.cpp:5021–5052` | Site **4**: pool only — **unchanged** by fix **α** |
| **C** | `blockchain.cpp:799–824` | Pop reverses staker accrual keyed to site **4** |
| **D** | `switch_to_alternative_blockchain` | Pop + replay → re-exercises **A** |
| **E** | `blockchain_db/*` | Pop drops top block; prev height **`ag`** authoritative |

**Spec disposition (pinned):** `already_generated` must track **full block emission**
(`Q4_spec`). **Fix α (pinned):** remove site **1** overwrite `:1608–1609`; `:4946`
single-site increment; site **4** unchanged. **7-base** before **7-cutover**.

**C2a′ (7-base):** Layer 2 A-accum + B-accum converge after fix **α**; cap invariant
defense-in-depth; Layer 3 pop-replay.

## Implementation scope (C2c commits)

1. Add FFI + `economics.h` wrappers so **`get_block_reward` preserves per-site target
   quantities** (§5.8 quantity map) — not a uniform `shekyl_base_block_reward` drop-in.
2. Add thin wrapper(s) in `src/shekyl/economics.h` (same pattern as
   `compute_fee_burn` / `compute_emission_split`).
3. Rewire **D/D′** so the ESF duplicate in `cryptonote_basic_impl.cpp` is
   **deleted**; all behavior flows through Rust canonical from **7-base**.
4. Touch sites **1–7** only if needed for includes/types — **no logic drift**.
5. PR description cites **7-base merge commit** (and C2a′ commit hash therein).

## H3 gate

- [ ] **7-base** is merged to `dev` before this branch is opened.
- [ ] CI: C2a′ dual-leg + multi-block accumulation targets are **required checks**
  on **7-base** and remain green on `dev` when this PR merges.
- [ ] This PR does not land until C2a′ is an **ancestor** (branch topology).

## Reviewer map

| Subsection | Review priority | Files |
|------------|-----------------|-------|
| **Consensus-affecting** | **Primary** | `cryptonote_basic_impl.cpp` (D/D′ deletion), `economics.h`, `shekyl_ffi.*`, any change at blockchain.cpp **1,2,3,4**, `cryptonote_tx_utils.cpp` **5**, `tx_pool.cpp` **6,7** |
| **Mechanical** | Secondary | Include wiring, `CMakeLists.txt` / crate linkage if touched |
| **Tests** | Verify unchanged vs C2a′ | `tests/unit_tests/block_reward.cpp`, `tests/unit_tests/mining_parity.cpp` — run, don't rewrite expectations without substrate finding |

## Rollback procedure

If consensus divergence is observed post-merge (subsidy mismatch, fee gate
false rejects, accumulation drift, reorg failure):

1. **Revert the 7-cutover merge commit on `dev`** (restores C++ `get_block_reward`
   body and pre-cutover call graph). **Do not revert 7-base** unless the Rust
   primitive itself is wrong (separate bisect).
2. **Minimal file rollback** (if revert is conflicted): restore these paths from
   parent of the 7-cutover merge:
   - `src/cryptonote_basic/cryptonote_basic_impl.cpp` (full `get_block_reward`
     implementations)
   - `src/shekyl/economics.h` (remove `shekyl_base_block_reward` wrapper if added)
   - `rust/shekyl-ffi/src/lib.rs` + `src/shekyl/shekyl_ffi.h` (remove new FFI
     exports)
   - Any `blockchain.cpp` / `tx_pool.cpp` / `cryptonote_tx_utils.cpp` hunks that
     changed behavior (expected: none beyond impl delegation)
3. **Verify rollback:** run C2a′ cross-check targets (still on `dev` from
   **7-base**) — leg A must pass again against restored C++.
4. **Chain recovery:** operators on a divergent tip must re-sync; no in-band
   migration (pre-genesis posture).

**7-trait rollback is independent** — reverting this PR does not revert wallet
trait work on a sibling branch.

## Test plan

- [ ] C2a′ required CI green on `dev` from **7-base** (pre-merge gate for 7-cutover)
- [ ] Layer 1: per-quantity KAT (Q_subsidy … Q_miner_coinbase), legs A + B
- [ ] Fix **α** (`:1608–1609` un-overwrite) + Layer 2 A/B-accum converge + cap invariant
- [ ] Layer 3: pop-replay grid (K-block pop + replay, `already_generated` identical)
- [ ] `tests/unit_tests/block_reward`, `tests/unit_tests/mining_parity`
- [ ] `tests/core_tests/block_reward` (accumulation / construct_miner_tx paths)
- [ ] Manual: mine block on regtest/stagenet — coinbase accepts, fee estimate
  RPC sane, `pop_block` + reorg path (staker accrual reversal at
  `blockchain.cpp:799–824`) without pool/burn corruption

## Design reference

- [`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](STAGE_1_PR_7_ECONOMICS_ENGINE.md) §5.8 (H1–H3), §6.2 item 1, §7.0
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) — base emission migration item

---


**Bundled-A remains defensible** for minimal pre-genesis moving parts if threat
profile shifts — but **C must stay rejected** (asymmetry window), and **wrong-seam
two-PR (old "consensus first") stays rejected** regardless.

#### Item 2 — §4 Phase 0 binding matrix refresh

Reconcile §4.4 against Round 1 + §5.8. Confirm every Phase 0 row is
**binding-form-pinned** (type + module + notes). Additions since pre-enumeration:

| ID | Round 1 / §5.8 delta | Binding pin status |
|----|----------------------|-------------------|
| **C0** | §2.7 rename (`base_emission_at`, `burn_amount`) | Locked §5.1 — Phase 0 co-land |
| **C2a′** | §5.8 C2a′ grid spec: C2 + harness + fix **α**; A/B-accum **`Q4_spec`** | §5.8 — **7-base** |
| **C2c** | FFI + full blast radius (H2 sites) + C++ deletion post–7-base (H3) | §5.8 — **7-cutover** only |
| **0h / 0h′** | Pair locked §5.2 B.2 | Unchanged |
| **G3** | Fixture `staking_state: live` when `total_staked > 0` | §5.4 — metadata pin |

- [x] §4.4 table updated with C2a′/C2c as implementation commits (cross-ref §7.X)
- [x] No orphan Phase 0 IDs (0a–0j) without module path
- [x] §2 scope bullets (§2.1) still match §4.4 — no drift (bullet 12 added for PR split)

#### Item 3 — Inside-the-fence polish (non-blocking, land in 2g if cheap)

Closed Round 1 dispositions; doc-only:

- [x] **R3 read contract** (§5.2 B.8): normative; polish closed — copy at C0/C2b if needed
- [x] **R2 `CalibrationStamp` / `as_of` field shape:** pinned §5.3 + §6.3 G5 —
  `generation: u32`, `params_digest: [u8; 32]`; custom fixed-width LE digest; no §2.7 amendment

#### Item 4 — §7.X commit decomposition vs item 1

- [x] §7.0 three-PR table reflects item 1 (7-base / 7-cutover / 7-trait)
- [x] Per-PR commit lists match §7.0; no C2 on 7-cutover or 7-trait-only branches
- [x] C4 remains **supplementary**; consensus 0h gate = **7-base** C2a′ only (§5.8)

#### Item 5 — §6 review checklist (implementation PR gate)

Filled at Round 2 close-out; verified at each implementation PR merge.

| Check | Enumeration source | Gate |
|-------|-------------------|------|
| Binding-check matrix | §4.4 + `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.7 verbatim copy (B.9) | **7-trait** C0 opens; C3 closes trait surface |
| Test-substrate preservation | `RecordedChainFixture` schema §5.4; C2a′ legs A/B; no `MockEconomics` | **7-base** C2a′ required CI; **7-trait** C4 differential |
| Call-site sweep | R6 zero V3.0 `Engine` consumers; C2c `get_block_reward` grep (H2) | **7-trait** grep before merge; **7-cutover** H2 table in §6.2 |
| Performance gates | `PERFORMANCE_BASELINE.md` deferred benches; Stage 0 harness names §3.8 | **7-trait** C6 |
| PR 6 coordination | `Engine<…>` `E`/`F` slot merge §6.1 | **7-trait** C5 + PR 6 landing order |

- [x] Checklist enumerated (§6.2 item 5 — Round 2 close-out)

#### Item 6 — Round 3 readiness gate

All must be true before §7.X is **closed** and Phase 1 branch cuts:

- [x] Item 1 scope decision recorded (three-PR split, §6.2 item 1)
- [x] §4 Phase 0 binding matrix refreshed (item 2)
- [x] Round 2 segment **2i** closed — G4/G5 converged; G1–G3 carry-only confirmed, not reopened
- [x] §2.7 surface still **C0-only** (R7) — G4/G5 are implementor-side layout only
- [x] §9 banner: Round 2 close-out + 2i disposition lines added
- [x] FOLLOWUPS amended for item 1 split + G4 downstream (`ActivityMetric` producer; conditional daemon RPC) — not for G1–G3 reopen

**Round 3 opened:** 2026-05-28. §7.X binding; Phase 0 C0 may co-land with first implementation branch.

### §6.1 PR 6 / PR 7 merge

**Coordination shape (pinned Round 3 entry — 2026-05-28):** PR 6 is
`PersistenceEngine` (**`F` slot**), not `PendingTxEngine` (`P` landed PR 5). PR 6
and **7-trait** have **no runtime dependency** at V3.0 (R6: zero `Engine` economics
callers; PR 6 does not touch `EconomicsEngine`). They **merge in parallel** off
post–7-base `dev`.

**Pre-agreed landing signature:** `Engine<S, D, L, E, R, P, F>` with defaults
`E: EconomicsEngine = LocalEconomics`, `F: PersistenceEngine = WalletFile`. PR 7
**C5** inserts **`E`** after **`L`**; PR 6 **C4** appends **`F`** after **`P`**. The
second PR to merge resolves a mechanical `engine/mod.rs` conflict only — neither
waits on the other's trait behavior. If both PRs are open simultaneously, rebase
the later merge onto the earlier and preserve the full six-parameter shape above.

---

## §6.3 Round 2 segment 2i — wider-substrate audit (2026-05-28)

**Status:** **Closed** 2026-05-28 — G4 and G5 converged; G1–G3 carry-only (no reopen).

### Pre-pinned carry confirmation (G1–G3)

| ID | 2i question | Disposition |
|----|-------------|-------------|
| **G1** | Cross-language single formation for `stake_ratio` + burn inputs | **Carry** — §5.3 R1 + C1/C3; `calc_stake_ratio` / `calc_burn_pct_from_activity` in `shekyl-economics`; C++ passes FFI-formed ratio only |
| **G2** | Cutover discipline | **Carry** — §5.8 H1–H3 + §6.2 three-PR split + fix **α** |
| **G3** | Fixture `staking_state: live` when `total_staked > 0` | **Carry** — §5.4; 2i confirms metadata contract only |

No substrate finding reopens G1–G3.

---

### G4 — `ActivityMetric` staleness vs consensus burn snapshot (CONVERGED)

#### Audit question

When a wallet calls `burn_amount(fee, activity)` at send time, can `ActivityMetric`
fields be **stale vs the block-connect snapshot** consensus uses? What is the bounded
failure mode, and what caller obligation must rustdoc pin?

#### Evidence trace (consensus — verified 2026-05-28)

**Authoritative fee-burn path for coinbase acceptance** — `validate_miner_transaction`
(`blockchain.cpp:1578–1596`):

| Input | Source at height *h* |
|-------|----------------------|
| `tx_volume` | `get_tx_volume_avg(h)` — mean tx count over **`SHEKYL_TX_VOLUME_WINDOW`** (720) blocks `[h−720, h)` |
| `circulating_supply` | `already_generated_coins` passed in (= prev-block LMDB `ag`, not `ag − total_burned`) |
| `stake_ratio` | `get_stake_ratio(h)` — incremental stake scan + `shekyl_calc_stake_ratio` |
| `total_fees` | Block's summed tx fees (`fee_summary`) |

**Secondary connect burn** — site **4** staker accrual (`blockchain.cpp:5027–5028`):

```cpp
compute_fee_burn(fee_summary, 0, prev_already_generated, stake_ratio_at_height, …)
//                              ^ tx_volume forced to 0
```

Site **4** is **not** the wallet `burn_amount` oracle. With `tx_volume = 0`,
`calc_burn_pct` → 0 → fee pool from burn is zero; staker inflow at site **4** is
dominated by **emission split**, not fee-burn pool. Wallet fee estimates must
trace **`validate_miner_transaction`**, not site **4**.

**Daemon `/get_info` today** (`core_rpc_server.cpp:585–592`) mirrors the **validate**
shape (not site **4**): `get_tx_volume_avg(height)`, `already_generated` at
`height−1`, `get_stake_ratio(height)`, `shekyl_calc_burn_pct(...)`.

**Wallet path today:** no `EconomicsEngine` / `burn_amount` production caller (§5.5
R6). GUI reads `burn_pct` from `/get_info` for display only (`shekyl-gui-wallet`
`daemon_rpc.rs`).

#### Staleness axes (load-bearing)

| Axis | Mechanism | Effect on `burn_amount` |
|------|-----------|-------------------------|
| **Height skew** | Wallet reads tip *H*; tx mines at *H+k* | `tx_volume_avg`, `stake_ratio`, `circulating_supply` all height-indexed — each block advance can change burn_pct |
| **Sync lag** | Orchestrator uses cached daemon snapshot while chain moves | Same as height skew; unbounded if refresh never happens |
| **Window roll** | 720-block `tx_volume` window drops old blocks each height | Slow drift; step change when window boundary crosses |
| **Post–fix-α `ag` step** | Full-emission `ag` increments faster than pre-fix | `circulating_supply / total_supply` term moves; wallet must use current prev-`ag` |
| **Mempool / fee** | Wallet estimates burn on proposed fee; consensus uses actual included fee | Fee input is intentional user choice — not staleness; burn scales linearly in fee |

**Not a theft surface:** consensus recomputes burn independently at accept
(`STAKER_REWARD_DISBURSEMENT.md`, §5.3 R1).

**Threat-model pivot (2026-05-28 design comments):** the 2026-04-08 anchor
("wrong daemon → failed send or wrong display") is **too strong for G4**. Stale
wallet `ActivityMetric` → **inaccurate advisory display only** at V3.0. The
user's tx does not fail on burn miscalculation; the miner's block fails if
coinbase split is wrong. G4 pins the **contract for the eventual display/UI
consumer**, not send gating.

#### Converged disposition (G4 — Round 1 convergence, 2026-05-28)

**Accept T0/T1 drift** under explicit height binding and consumer-side staleness
policy. **Do not** add tolerance/range to `burn_amount` (trait stays a point
estimate). **Do not** add consensus-side wallet ActivityMetric validation at V3.0.

**Structural pins for C1 / C3 / rustdoc (7-trait):**

1. **`ActivityMetric` + `as_of_height: u64`** — fourth raw integer (R1 preserved);
   R7 remains C0-only (implementor-side layout). `as_of_height` visible to
   consumers — no hiding for shoulder-surfing (activity disclosure dominates).
2. **`ActivityMetric::new(...) -> Result<Self, ActivityInvariantViolation>`** —
   in `shekyl-economics`; validates **internal-consistency** invariants only:
   `circulating_supply ≤ MONEY_SUPPLY`, `total_staked ≤ circulating_supply`,
   height sanity. **Coherence** ("these four values are one chain view at
   `as_of_height`") is a **constructor-caller obligation** documented in rustdoc:
   production from non-atomic reads of separate sources violates the contract.
   **No** `#[cfg(test)]` backdoor constructor.
3. **`EconomicsError::ActivityInvariantViolation`** — implementor-side discriminator
   for which invariant failed.
4. **`burn_amount` rustdoc** — returns burn consensus would compute at
   `activity.as_of_height`; actual on-chain burn at block-connect may differ;
   consumer applies staleness policy. Oracle path = **`validate_miner_transaction`
   input shape** (`tx_volume_avg`, prev-`ag`, `stake_ratio` at target height),
   **not** site **4** (`tx_volume = 0`).
5. **`circulating_supply` quantity** — prev-block **`already_generated`** at
   `as_of_height` (same as `/get_info` today). Not net-of-burn unless consensus
   amends.
6. **`tx_volume` window** — rustdoc cites **`SHEKYL_TX_VOLUME_WINDOW = 720`** and
   mean-over-window semantics matching `get_tx_volume_avg`.
7. **Genesis guard** — `as_of_height = 0`, `circulating_supply = 0` →
   `stake_ratio = 0` in `calc_burn_pct` → `burn_amount` = 0 (C3 one-liner, not
   `Err` for valid genesis input).
8. **Errors at two altitudes** — structural impossibilities → `Err` from `new()`;
   lying-but-invariant-passing daemon input → display-only wrong estimate
   (threat model absorbs explicitly). Snapshot incoherence from three sequential
   RPCs must not reach `new()` — producer uses atomic upstream read.
9. **No `RecordedActivityFixture` type** — tests use `Vec<ActivityMetric>` JSON +
   expected burn outputs; same type as production debug logs.
10. **Bundle architecture** — wallet actor produces `ActivityMetric`;
    `EconomicsEngine` trusts by type (no re-validation). Upstream = local LMDB
    mirror (one read txn) **or** daemon atomic endpoint (not three RPCs). Which
    upstream is post–PR-7 actor-mesh work; both paths satisfy the trait surface.

**FOLLOWUPS (downstream of PR 7 — see `docs/FOLLOWUPS.md`):**

| Entry | Scope |
|-------|--------|
| **Wallet `ActivityMetric` producer actor** | Stage 4 actor mesh: designated chain-mirror owner performs single-transaction read, validates, constructs bundle. **Unconditional** (post-V3.0). |
| **Daemon atomic activity snapshot RPC** | If producer upstream is daemon RPC: one endpoint returning all four fields in one LMDB read txn (`get_activity_at_height` or equivalent). Three separate RPCs **not** equivalent. **Conditional** — moot if upstream is local mirror only. |

**Reopen clause:** Re-evaluate if (a) a V3.0 production caller caches
`ActivityMetric` across an await without height check, or (b) consensus burn inputs
change (e.g. circulating definition moves to net-of-burn) — requires §2.7 amendment +
G4 re-audit.

---

### G5 — `parameters_snapshot` cache poison (CONVERGED)

#### Audit question

Can a caller cache `parameters_snapshot()` across calibration regen or param-epoch
change and **silently use poisoned constants** despite `as_of`?

#### Evidence trace (verified 2026-05-28)

| Fact | Source |
|------|--------|
| **V3.0 production consumers** | **Zero** (§5.5 R6) — trait + tests only; narrower than G4 (no fee-construction consumer named) |
| **Constants source** | `config/economics_params.json` → compile-time: C++ via
  `cmake/generate_economics_params.py`; Rust via `shekyl-economics/build.rs`
  (`EconomicParams::default()` from generated constants) |
| **Runtime regen** | Changing JSON requires **rebuild** (both languages). No in-process
  hot reload at V3.0 |
| **§2.7 contract** | `parameters_snapshot` rustdoc: **do not cache beyond immediate
  use**; capture at start of logical operation if needed (`V3_ENGINE_TRAIT_BOUNDARIES.md`
  §2.7) |
| **`LocalEconomics` V3.0 shape** | Stateless pure wrappers — no mutable param cache
  (§2.7 Stage 1 note) |
| **Fixture staleness guard** | `RecordedChainFixture.params_digest` + `calibration_generation`
  (§5.4) — same lineage as snapshot `CalibrationStamp` |

#### Threat-model pivot (2026-05-28 design comments)

Snapshot contents are **constants** (ESF, money supply, burn coefficients, tiers).
At V3.0 they do not change within a deployed binary. A cached snapshot is stale only
relative to a **later calibration generation not yet deployed**, or at V3.x when
adaptive burn moves coefficients.

**Consequence envelope:** same as G4 — **display-only advisory**. Cached snapshot →
wallet shows wrong parameters or estimates burn against stale coefficients. Consensus
is authoritative; no theft, no failed send. Bound is **tighter than G4** because no
fee-construction consumer exists or is named at V3.0.

**Load-bearing question:** not "what damage does poisoned cache do" (wrong display,
bounded) — but **what makes poisoning detectable** for the consumer that would care?

#### Converged disposition (G5 — Round 1 convergence, 2026-05-28)

**Accept caller-cache violation** at V3.0 under existing §2.7 no-cache discipline +
structured `CalibrationStamp`. Consumer applies own staleness policy; trait does not
gate on freshness.

**`CalibrationStamp` detection surface (mandatory, C1 / 0d):**

| Field | Type | Answers |
|-------|------|---------|
| `generation` | `u32` | "Is this snapshot from the current calibration epoch?" Cheap compare; human-readable logging ("estimate from generation 7; current is 8"). |
| `params_digest` | `[u8; 32]` | "Is this snapshot bit-exact identical to current?" Blake2b-256 of **custom canonical `EconomicParams` bytes** (fixed-width LE field order in module rustdoc — not JSON, not bincode). Catches generation increment with no param change; catches silent serialization drift. |

**Consumer comparison rule (rustdoc):** stale if `generation` differs (likely real
change); suspicious if `generation` matches but `params_digest` differs (build-system
bug at V3.0, not an attack vector).

**Pre-provision-for-flexibility:** both fields pass the bar — named consumers and
named failure modes (`generation` → display epoch label / silent-stale-coefficient-display;
`params_digest` → config-pipeline integrity / JSON-authority drift not caught by
consensus static_asserts).

**7-trait obligation (implementor-side, R7 C0-only):**

1. **`parameters_snapshot()`** returns `EconomicsParametersSnapshot { ..., as_of:
   CalibrationStamp }` with both fields always populated from current build-time
   loader (`EconomicParams::default()` or equivalent).
2. **`LocalEconomics::parameters_snapshot`** — build fresh **on every call**; **no**
   instance-level snapshot cache at V3.0.
3. **C7 rustdoc** — repeat §2.7 no-cache rule; cite G5; consumer must compare
   `as_of` before trusting a cached copy.
4. **Display-only paths** (GUI `/get_info` economics fields) — out of trait scope.

**Rejected at V3.0:** `Arc<EconomicsParametersSnapshot>` actor mailbox (Stage 4);
process-wide singleton cache; refresh heuristic without `as_of` check; tolerance/range
on trait surface.

**Cross-reference with G4:** at V3.0, `CalibrationStamp.generation` and
`ActivityMetric.as_of_height` are **formally independent** (configuration epoch vs
chain height). V3.x adaptive burn may introduce height-bound calibration epochs
(`generation_active_at(height)`) — **rustdoc note only at V3.0**; no structural
coupling between the two staleness surfaces in PR 7.

**Reopen clause:** Mandatory structural mitigation when **first production caller**
caches snapshot beyond a single logical operation **or** V3.x adaptive-burn adds mutable
state to `LocalEconomics` — then require explicit `as_of` comparison or engine-held
generation counter (design round, not drive-by cache).

**Encoding format (pinned 2026-05-28):** custom documented fixed-width little-endian
field order in `shekyl-economics` — same discipline as consensus-constants
hand-canonicalization. **Bincode rejected:** strict cross-platform stability required;
bincode couples digest to library version and risks MSVC/GCC/toolchain serialization
drift. C1 implements + documents byte layout; C4 fixtures call the same helper.

---

### G4 / G5 threat-model through-line (2i closer)

| | **G4 `ActivityMetric`** | **G5 `ParametersSnapshot`** |
|--|-------------------------|------------------------------|
| **Threat envelope** | Display-only advisory; consensus authoritative | Display-only advisory; constants don't gate anything at V3.0 |
| **Staleness detection** | `as_of_height: u64` (mandatory) | `CalibrationStamp { generation, params_digest }` (mandatory) |
| **Validation altitude** | Internal-invariant in `new()` + producer-coherence | Build-time generation tag; runtime digest = defense-in-depth |
| **Consumer obligation** | Apply own staleness policy (display gate, warn, refuse) | Apply own staleness policy (typically: refresh if `generation` differs) |
| **Caller bypass** | `new()` always validates; no `#[cfg(test)]` backdoor | `parameters_snapshot()` always returns current; stamp always populated |

---

### 2i close checklist

- [x] G4 disposition converged (§6.3 — 2026-05-28 design comments integrated)
- [x] G5 disposition converged (§6.3 — 2026-05-28 design comments integrated)
- [x] G1–G3 carry-only confirmed (no edits)
- [x] §6.2 item 6 + §9 banner updated on close
- [x] C1/C3/C7 rustdoc hooks reflected in §7.1 commit text (CalibrationStamp fields; G4/G5 rustdoc pins)

**Segment 2i → Closed.** Round 3 opened 2026-05-28 (§6.2 item 6).

---

## §7 Round 3 — §7.X commit decomposition (OPEN 2026-05-28)

**Status:** binding for Phase 0 + three implementation PRs. Round 3 closes when all
three PRs merge to `dev` and §7.2 Stage 1 closeout criteria met (with PR 6).

**Deviation (unchanged):** No diagnostic enum; no secondary traits; no
`MockEconomics`; no `FaultInjecting` at V3.0.

### §7.0 Implementation PR split (§6.2 item 1 — ratified 2026-05-28)

| PR | Branch (conventional) | Commits | Merge prerequisite |
|----|----------------------|---------|-------------------|
| **7-base** | `feat/stage-1-pr7-economics-base` | **C2**, **C2a′** (incl. fix **α** `:1608–1609`) | Post–Phase-0 `dev` |
| **7-cutover** | `feat/stage-1-pr7-economics-cutover` | **C2c** | **7-base** on `dev` (C2a′ ancestor) |
| **7-trait** | `feat/stage-1-pr7-economics-engine` | **C0**, **C1**, **C2b**, **C3**, **C4**, **C5**, **C6**, **C7** | **7-base** on `dev` — **not** 7-cutover |

**7-cutover** and **7-trait** are **siblings** after 7-base; merge order between
them is unconstrained. Stage 1 economics closeout (§7.1) requires **all three**
on `dev`. External cryptographer review targets **7-cutover** as the isolated
consensus-subsidy artifact.

**Bundled fallback (option A):** single branch carries all commits below in H3
order — use only if item 1 disposition is explicitly reopened.

### §7.1 Commit inventory (by ID)

| Commit | Scope |
|--------|--------|
| **C0** | Phase 0 §2.7 naming amendment (`base_emission_at`, `burn_amount`) + doc co-land |
| **C1** | `EconomicsError` (+ `ActivityInvariantViolation`), `ActivityMetric` + `::new` (§5.3 R1, §6.3 G4), `EconomicsParametersSnapshot` + `CalibrationStamp { generation, params_digest }` (§5.3 R2, §6.3 G5); **`EconomicParams` canonical digest** — custom fixed-width LE byte layout in `build.rs` + module rustdoc (bincode rejected §5.3 R2 / §6.3 G5) |
| **C2** | `shekyl-economics`: `base_block_reward` + `projected_already_generated` + `calc_stake_ratio` + `calc_burn_pct_from_activity`; extend `build.rs` / `EconomicParams` with ESF + `final_subsidy_per_minute` (§7.4 E3); sim rewired to 0h |
| **C2a′** | **§5.8 C2a′ grid spec:** harness (Layer 1–3); **fix α** (`:1608–1609` delete); A/B-accum converge on **`Q4_spec`**; cap invariant; **required CI workflow** (§7.4 E1) | **7-base** |
| **C2c** | `shekyl_base_block_reward` FFI; rewire **all** `get_block_reward` consumers + accumulation sites (H2); target = `economics.h` thin-wrapper shape; delete C++ formula only after C2a′ on `dev` (H3) |
| **C2b** | `ChainEconomicsSource` + production adapter |
| **C3** | `EconomicsEngine` + `LocalEconomics` impl; `CALIBRATION-PENDING` doc comments |
| **C4** | `RecordedChainFixture` (§5.4) + engine-vs-sim differential (supplementary only); **`params_digest` uses same canonical encoder as C1**; consensus 0h gate is **C2a′** dual-leg + accumulation (H1–H2), not C4 |
| **C5** | `Engine` `E` slot + `economics` field |
| **C6** | Benches + `PERFORMANCE_BASELINE.md` |
| **C7** | Docs: CHANGELOG, rustdoc, design doc Phase 1 landed; calibration banners |

#### Implementation pins (C1)

| Pin | Disposition | Commit |
|-----|-------------|--------|
| **`params_digest` canonical encoding** | Custom fixed-width little-endian field order; documented byte layout in `shekyl-economics` rustdoc; single `build.rs` helper shared with C4 fixtures. **Bincode rejected** (2026-05-28): cross-platform / cross-toolchain drift risk at calibration surface. | **C1** (+ **C4** consumer) |

### §7.2 Per-PR commit assignment (§6.2 item 4 — verified)

| PR | Commits on branch only | Must not include |
|----|------------------------|------------------|
| **7-base** | **C2**, **C2a′** (incl. fix **α**) | C2c, C0–C1, C2b, C3–C7 |
| **7-cutover** | **C2c** | C2 (except as merged ancestor on `dev`), trait commits |
| **7-trait** | **C0**, **C1**, **C2b**, **C3**, **C4**, **C5**, **C6**, **C7** | C2c; C2 lands only via **7-base** on `dev` |

**Consensus 0h gate:** **7-base** C2a′ (H1–H2). **C4** differential is supplementary only.

### §7.3 Stage 1 closeout

After **PR 6** and **all three PR 7 implementation PRs** (7-base, 7-cutover,
7-trait) merge — not any single PR alone. **Round 3 design closes** when this
criterion is met and §6.2 item 5 review gate is green on each PR.

**PR 6 coordination:** parallel with **7-trait**; no wait on `EconomicsEngine`
consumption (§6.1). Stage 1 closeout requires both **`E`** (7-trait C5) and **`F`**
(PR 6 C4) on `Engine<…>` — order of merge between those two PRs is unconstrained
beyond the pre-agreed signature in §6.1.

### §7.4 Round 3 entry items (surfaced at Round 2→3 boundary)

Not Round 2 misses — absorb in first implementation branches so discovery does not
wait for code review.

#### E1 — H3 CI teeth (7-base first deliverable)

§5.8 H1–H3 pin dual-leg + accumulation KATs and branch-topology gating.
**Workflow landed (skeleton):** `.github/workflows/economics-c2a-prime.yml`
(`ci/economics-c2a-prime`) + `scripts/ci/run_economics_c2a_prime.sh`. One **build**
job uploads `unit_tests` + `core_tests` artifacts; three **layer** jobs run tests
in parallel (no triple redundant builds). `concurrency` cancels superseded runs;
failure logs upload as artifacts.

| Job | Subcommand | Passes today? |
|-----|------------|---------------|
| `Economics C2a′ preflight (oracle constants)` | `preflight` | **Yes** — JSON + scoped literal grep (`rg` required) |
| `Economics C2a′ build (unit_tests + core_tests)` | (artifact producer) | **Yes** — when economics paths trigger workflow |
| `Economics C2a′ Layer 1/2/3` | `layer1`–`layer3` | **No** — awaits harness in 7-base |

Layer jobs **fail with a pinpoint message** until gtest/core_tests/Rust harness
cases register under the naming contract in the runner script header. That is
intentional H3 teeth — not a workflow bug.

**After 7-base merges:** mark all four jobs **required** on `dev` in branch
protection (alongside `ci/consensus-invariants` and `ci/gh-actions/cli`) before
**7-cutover** merges.

**7-cutover PR** additionally cites **7-base merge commit** (C2a′ ancestor) in body;
branch topology remains primary enforcement.

#### E2 — PR 6 / 7-trait `Engine` slot coordination

See §6.1 — **parallel merge**, pre-agreed `Engine<S, D, L, E, R, P, F>`. No
V3.0 caller coupling; conflict surface is `engine/mod.rs` signature + field list only.

#### E3 — `FINAL_SUBSIDY` oracle source (grep before C2a′)

**Authoritative:** `config/economics_params.json` → `final_subsidy_per_minute =
300_000_000` → C++ `FINAL_SUBSIDY_PER_MINUTE` via `cmake/generate_economics_params.py`;
C++ tests use the generated `#define`.

**Not authoritative for leg B:** `DESIGN_CONCEPTS.md` §2 still cites historical
Monero `3 × 10¹¹` — documentation only (§5.3 R2 reconciliation).

**Stale-literal regex (preflight self-check):** Monero scale 3×10¹¹ = twelve digits
after the leading 3. Preflight runs an embedded probe set before the source grep:

| Probe input | Expected |
|-------------|----------|
| `300_000_000_000` | match (Monero underscore form) |
| `300000000000` | match (Monero bare integer) |
| `3 * 10^11` | match (prose form) |
| `300000000` | **no match** (Shekyl authoritative JSON value) |
| `30000000000` | **no match** (3×10¹⁰ near-miss / typo class) |

**Build artifact layout (layer jobs):** tarball is `build/` minus object/archive
artifacts; must include `unit_tests`, `core_tests`, and shared libs under
`build/src/**` (binaries link with absolute RPATH). `tests/data/` is **not** in the
tarball — repo checkout supplies it (`DEFAULT_DATA_DIR` / `--data-dir`).
`create_test_disks.sh` runs per layer-3 job (runtime loop state, not packaged).

**Sim (leg B oracle):** `shekyl-economics-sim` uses `300_000_000` in
`SimParams::default()` but **`sim_defaults_match_canonical_economics_config`** asserts
equality with `economics_params.json` — no stale `3×10¹¹` in sim/test paths (grep
2026-05-28).

**C2 / C2a′ implementer guard:** leg B and `base_block_reward` must read
`final_subsidy_per_minute` / ESF from **generated params** (`build.rs` /
`EconomicParams` — extend in **C2**; not yet in `shekyl-economics` `EconomicParams`
today). Do not copy from DESIGN_CONCEPTS or hardcode Monero-era literals in KAT
grids.

### §7.5 Mission review — decisions and flags (00-mission hierarchy)

Evaluated at Round 3 open. **Priority 1 (security / consensus)** items first.

| Item | Mission tier | Disposition | Decision needed? |
|------|--------------|-------------|------------------|
| **Fix α (`ag` semantics)** | P1 — consensus | Pinned 7-base; small footprint, load-bearing for C2a′ gate | **No** — landed in design |
| **H3 without CI** | P1 — consensus integrity | E1 — 7-base ships required workflow | **No** — implement |
| **C2a′ leg B oracle constants** | P1 — false confidence / phantom-pass | E3 — JSON/generated only | **No** — implement; extend `build.rs` in C2 |
| **`Engine<E,F>` merge** | P3 — system longevity (Stage 1 inventory) | §6.1 parallel + pre-agreed signature | **No** — pinned |
| **G4/G5 display-only staleness** | P2/P3 — no user fund loss at V3.0 | Converged §6.3; consumer-side policy | **No** |
| **ActivityMetric daemon atomic RPC** | P2 — coherent display | FOLLOWUPS conditional | **No** at V3.0 |
| **`params_digest` encoding** | P1 — calibration drift | Custom LE layout pinned | **No** |
| **V3.x `Mutex<AdaptiveBurnState>` on `LocalEconomics`** | P1 deferred | G5 reopen clause when first mutable caller | **No** at V3.0 |
| **§2.7 vs G4:** `PendingTxEngine` burn consumer | Spec drift risk | §2.7 still names future fee-path consumer; R6 + G4 pin **display-only** at V3.0 — no send gating | **Optional doc pin:** amend §2.7 rustdoc at C0 to match G4 display-only envelope (no trait change) |

**No blocking decisions remain** for Round 3 branch cuts. **One optional polish:** C0
§2.7 rustdoc alignment with G4 display-only `burn_amount` threat envelope (spec text
still reads like wallet enforcement in places — implementation rustdoc must follow
G4 regardless).

**Structural payoff (user note):** 7-base first → 7-cutover ∥ 7-trait as siblings
makes H3 **branch-ancestry hard**; trait work does not serialize behind cutover
external audit. That is the intended return on the foundation split.

---

## §8 Discipline-citation matrix (seed)

| # | Discipline | Failure mode foreclosed |
|---|------------|-------------------------|
| 1 | Canonical derivation; 0h + Rust-vs-C++ KAT | Bug 2/7; false confidence from Rust-only differential |
| 1b | `calc_stake_ratio` single helper (wallet + FFI) | Cross-language stake_ratio divergence |
| 2 | Narrow `ChainEconomicsSource` | Wide observer-feed pre-provision |
| 3 | Real-path fixtures | Mock-driven false confidence |
| 4 | Calibration vs structural split | "Adjust on testnet" → accidental fork |
| 5 | `as_of` / `CalibrationStamp` temporal projection | Silent snapshot cache poison (G5) |
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
| **Round 2 close-out item 1** | `§6.2 2026-05-28: three-PR split — 7-base (C2+C2a′) → 7-cutover (C2c) ∥ 7-trait (C0–C7 off base only); H3 hard via branch topology; wrong-seam two-PR and trait-before-cutover rejected.` |
| **C2a′ grid amended** | `§5.8 2026-05-28c: root cause site 1 overwrite :1608–1609; fix α pinned; option β rejected; caller grep = :4946 only.` |
| **7-base scope amended** | `§6.2 2026-05-28c: 7-base = C2 + C2a′ harness + fix α (small ag semantics); cutover = FFI/ESF delete only; bound check verified on miner_base_reward.` |
| **2i closed** | `§6.3 2026-05-28: segment 2i closed. G4: display-only advisory; ActivityMetric.as_of_height + ::new; coherent bundle. G5: display-only; CalibrationStamp { generation: u32, params_digest: [u8;32] }; custom fixed-width LE digest (bincode rejected); independent from as_of_height at V3.0. G1–G3 carry-only.` |
| **Round 2 closed** | `Round 2 closed 2026-05-28; §6.2 close-out complete — §4.4 binding matrix, §7.2 per-PR commits, implementation review gate §6.2 item 5; segment 2g + 2i closed.` |
| **Round 3 open** | `Round 3 open 2026-05-28; §7.X binding — 7-base (C2+C2a′+fix α) → 7-cutover (C2c) ∥ 7-trait (C0–C7); Phase 0 C0 may co-land; Round 3 closes when all three implementation PRs + PR 6 land on dev.` |
| **Round 3 entry items** | `§7.4 E1: ci/economics-c2a-prime workflow + run_economics_c2a_prime.sh (preflight green; layer jobs await harness). E2: Engine<S,D,L,E,R,P,F> parallel PR6/7-trait. E3: leg-B oracle from economics_params.json only.` |

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

Both PRs required for Stage 1 trait inventory. **Parallel merge** at V3.0 — see
§6.1 / §7.4 E2. Pre-agreed landing:
`Engine<S, D, L, E, R, P, F>` (`E` = PR 7 C5, `F` = PR 6 C4). Neither PR waits
on the other's trait methods; Stage 1 closeout requires both slots on `dev`.

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
