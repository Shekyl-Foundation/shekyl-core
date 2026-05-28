# Stage 1 PR 7 — `EconomicsEngine` extraction — design

**Status.** **Round 0 closed (2026-05-27).** Round 1 open — load-bearing
question and candidate shapes in §5. Planning doc branch:
`feat/stage-1-pr7-economics-engine-design` → PR to `dev`. Opened from `dev`
tip `2cf4cbfde` (post–PR #82 `PersistenceEngine` design merge). This document
follows [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and cites
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
explicitly.

**Stage 1 is not complete after this PR.** PR 6 (`PersistenceEngine`
implementation) may still be in flight on `dev`; PR 7 is the **remaining
required trait surface** for the seven-trait Stage 1 inventory. Update
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §1 status
banner and [`FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 closeout inventory only after
**both** PR 6 implementation and PR 7 implementation land. Do not link to
`STAGE_1_COMPLETION_AUDIT.md` — that doc is not yet in the tree (per FOLLOWUPS).

**Branch (design).** `feat/stage-1-pr7-economics-engine-design` off `dev` at
`2cf4cbfde` — **doc-only** revisions until Round 3 closes and Phase 0 amends
§2.7 if Round 1–2 surface pins require it. Implementation branch
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
  [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md),
  [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md).
- **Per-PR template / process.**
  [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md),
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
- **Prior PRs (shape precedent).**
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md) (lean trait
  extraction),
  [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](STAGE_1_PR_6_PERSISTENCE_ENGINE.md)
  (§7.X commit decomposition; PR 6/7 interleave note).
- **Performance gates.**
  [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) — deferred benches
  `engine_trait_bench_economics_current_emission`,
  `engine_trait_bench_economics_parameters_snapshot`.
- **Downstream consumers (out of PR 7 scope).** Phase 2b `StakeEngine`, V3.x
  `ArchivalEngine` — consume `EconomicsEngine`; do not collapse into PR 7.

Subsequent revisions land each design round **inline** per template §2 and PR 5 /
PR 6 precedent.

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this PR touches it |
|----------|-------------------------|
| **1 — Security** | **Primary.** Centralizes canonical economic derivations so Bug 2 / 7 / 13 class (same conceptual value computed differently at scattered sites) cannot recur in wallet Rust. Does **not** add wallet-side consensus enforcement (§2.7 consensus-as-truth pin). |
| **2 — Privacy** | Indirect only: economics methods return public parameters and aggregates, not per-output secrets. |
| **3 — System longevity** | **Primary.** Fixes the `E` type-parameter slot and trait surface before Phase 2b `StakeEngine` / V3.x `ArchivalEngine`; adaptive-burn statefulness at V3.x must not force Stage 1 surface churn (reversion clause §3.6). |

**Preserve by name (§2.7 scope guard):**

- `EconomicsEngine` is **wallet-side canonical derivation**, not consensus
  enforcement, not network observability, not economic-rationale documentation.
- Do **not** collapse into `StakeEngine` / `ArchivalEngine` (consumers, not
  sub-traits).
- Do **not** move consensus rule enforcement into wallet economics code.

**Three timeframes:**

| Timeframe | Addresses | Does not address |
|-----------|-----------|------------------|
| **Now (V3.0)** | Four-method sync trait; `LocalEconomics` stateless wrapper; `E` on `Engine`; benches + FOLLOWUPS bench slots | Phase 2b stake FSM; V3.x adaptive-burn `Mutex` state inside implementor |
| **Mining era end** | Emission / burn math uses `shekyl-economics` + JSON authority (`config/economics_params.json`) — same discipline as consensus constants | Fee-market UX; governance votes |
| **V4 lattice** | No effect on trait surface | PQC is orthogonal to economics derivation |

---

## §2 Scope

### §2.1 In-scope

1. **`EconomicsEngine` trait** — `engine/traits/economics.rs` + `traits/mod.rs`
   re-export (`pub(crate)` per §2 preamble).
2. **`LocalEconomics` implementor** — new in `shekyl-engine-core` (e.g.
   `engine/local_economics.rs`), thin wrapper over `shekyl-economics` + any
   chain-state readers Round 1 pins (§5).
3. **Supporting types** — `EconomicsError`, `EconomicsParametersSnapshot`,
   `ActivityMetric` per §2.7 / §4 Round 4a pins (types do not exist in Rust
   yet — Round 0 inventory §3.5).
4. **`Engine` parameterization** — introduce `E: EconomicsEngine =
   LocalEconomics`; field `economics: E` per §3 composition. Incremental
   parameter order toward spec §3 (§5.2) — **not** full `<S, K, L, E, D, F, R,
   P>` reorder in this PR (deferred with `K` per PR 6 Appendix C).
5. **Workspace wiring** — add `shekyl-economics` dependency to
   `shekyl-engine-core` (`17-dependency-discipline.mdc` verification at
   implementation pre-flight).
6. **Performance gates** — `engine_trait_bench_economics_current_emission` and
   `engine_trait_bench_economics_parameters_snapshot` (+ iai pair if ledger
   benches precedent applies); populate
   [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) at introducing merge
   SHA.
7. **`MockEconomics`** — per §6.1 surviving Mock-X commitment (constants-
   driven test double for future `StakeEngine` precursor tests).
8. **Tests** — trait contract tests on `LocalEconomics`; property tests against
   `shekyl-economics` unit tests / FFI KATs where applicable.
9. **Docs** — this design doc, `CHANGELOG.md`, trait rustdoc, §2.7 cross-refs
   if Phase 0 amends land.

### §2.2 Out-of-scope

| Item | Where |
|------|--------|
| `PersistenceEngine` implementation | PR 6 (`feat/stage-1-pr6-persistence-engine`) |
| `KeyEngine` on `Engine<S, …>` | FOLLOWUPS V3.0 inventory |
| Full `Engine<S, K, L, E, D, F, R, P>` reorder | Chore when `K` + persistence land; PR 7 inserts `E` only |
| `StakeEngine` / `ArchivalEngine` | Phase 2b / V3.x additive traits |
| Wallet-side consensus enforcement of staking/archival rules | `shekyl-consensus` / chain |
| `Mutex<AdaptiveBurnState>` / observation window | V3.x Component 3 — surface unchanged; implementor gains state |
| Stage 4 `EconomicsActor` / spawn timeouts | §2.8.3 |
| Diagnostic stream / `FaultInjecting` wrapper | Lens 3 N/A — no diagnostic seam at V3.0 |
| Orchestrator call sites that *consume* economics for fees / burns at V3.0 | §3: `E` is consumed trait with **no** `Engine<S>` method callers at V3.0; wiring `PendingTxEngine` / refresh to `burn_fraction` is a **follow-up** once product path needs it (named in Round 2 — do not silently expand PR 7) |
| C++ wallet economics paths | Deletion targets per `20-rust-vs-cpp-policy.mdc`; separate from this PR unless audit finds a live Rust migration site |

---

## §3 Pre-flight discipline checklist

**Audit pin:** `dev` at `2cf4cbfde` (2026-05-27).

This section pays the **citation cost** for
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §3 and
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §8.3.

### §3.1 Engine identification (template §3.1)

- [x] **§2.7 binding.**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7 —
  four sync methods; `type Error: Into<EconomicsError>`; `&self` only.
- [x] **§1.5 three-condition test.** Distinct Stage 4 state ownership (V3.x
  adaptive-burn observation); distinct failure domain (`RuntimeFailure` at
  Stage 4); cross-cutting canonical-derivation concern consumed by multiple
  future traits. **Additive trait** at Round 3 — not a refinement of an existing
  Stage 1 PR surface.
- [x] **Surface amend vs preserve.** **Preserves** §2.7 four-method shape.
  Phase 0 amendment **only if** Round 1 pins require spec-visible type layouts
  (`ActivityMetric`, `EconomicsParametersSnapshot` fields) not yet enumerated in
  §2.7 prose — amendment co-lands per §8.2.

### §3.2 Plan-altitude principles (template §3.2 — `WALLET_REWRITE_PLAN.md`)

| Principle | Applicability |
|-----------|----------------|
| **4 — architectural-integrity-now** | **Always applies.** Land `LocalEconomics` + `shekyl-economics` wrapper now; do not defer `E` slot to Phase 2b. Rules: [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc), [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc). |
| **5 — closure-rule + audit trail** | **Always applies.** Round 0 closes pre-flight; Round 1–3 follow template. Reopen criterion in status banner. |
| **6 — wider-substrate audit** | **Applies** after Round 2 close-out (segment placeholder §6). |
| **7 — threat-model anchors** | **Applies with narrowing.** Adversary-controlled daemon is **N/A** for pure derivation (inputs are height / fee / activity metric supplied by orchestrator). Wargaming focuses on **wrong derivation** (constant drift, overflow, divergent pool-total sources) and **caller snapshot caching** violating §2.7 `parameters_snapshot` contract. HW-wallet anchor N/A. |
| **8 — priority-hierarchy** | **Applies** if Round 1 weighs "defer `pool_weighted_total` body" vs integrity-now. Default: structural extraction now; stubbing canonical methods is a **priority-1 failure** unless spec-amended with named reopening criteria. |

### §3.3 Per-engine-PR disciplines (template §3.3 — §8.3)

#### §3.3.1 Design lenses (§8.3.1)

| Lens | Decision | Reasoning |
|------|----------|-----------|
| **1 — Actor-mesh** | **Bounded — synchronous framing correct** | Per §8.3.1 table: (2) fails — no cross-actor liveness/quiescence dependency on trait surface. V3.0 methods are sync pure reads. Stage 4 actor is leaf in spawn graph §2.8.3. |
| **2 — State-as-collection-membership** | **No** | Lens 1 not fully applicable. |
| **3 — Recursive trust boundary** | **No** | No diagnostic-stream seam. |

#### §3.3.2 Anti-pattern citations (§8.3.2)

| Anti-pattern | PR 7 posture |
|--------------|--------------|
| Cost-benefit-defer-to-later | Round 1 default rejects deferring `E` slot or leaving scattered `shekyl-economics` calls outside trait |
| User-protection-defaults-in-user-absent-contexts | No soft deprecation of direct `calc_burn_pct` at orchestrator — delete/re-home call sites in scope table when they exist |
| Audits-are-clean-so-compress | Pre-flight inventory is confirmation-shaped but still load-bearing (trait was never extracted) |

#### §3.3.3–§3.3.5

- **§8.3.3 closure-rule:** Round N closure pins + named reopen criteria (§9 banner discipline).
- **§8.3.4 process:** §7.X synthesis banner if Round 2 segments amend commit bodies.
- **§8.3.5 threat-model anchors:** Wrong-derivation / snapshot-cache wargaming in Round 1 §5.3 criterion 5.

### §3.4 Architectural-inheritance audit projection (template §3.4)

| Substrate | Disposition |
|-----------|-------------|
| Monero `wallet2` economics | **Not inherited.** C++ paths use daemon-reported rewards (`m_last_block_reward`, etc.) — out of PR 7 Rust surface. |
| `shekyl-economics` + `shekyl-economics-sim` | **Load-bearing.** Canonical math lives here; sim duplicates emission curve for Monte Carlo — PR 7 should **factor shared emission-at-height** into `shekyl-economics` rather than duplicating a third copy in `engine-core`. |
| `shekyl-ffi` `shekyl_calc_burn_pct` / emission FFI | **Reference for KAT alignment** — trait impl must match FFI + crate tests. |
| `shekyl-engine-core` today | **No `shekyl-economics` dependency** — economics not wired in orchestrator (Round 0 confirmation). Stake reward **estimation** uses `LedgerIndexes` / `StakerPoolState` accrual records (`claim_builder.rs`, `tests.rs`) — **chain-mirrored state**, not `EconomicsEngine` derivation. |
| Bug 2 / 7 / 13 class | **Preventive migration** — trait exists before Phase 2b multiplies consumer sites. |

**Projection:** **Substantive extraction, bounded call-site count** — confirmation-shaped for trait declaration, **discovery-shaped** for `current_emission` Rust port and `pool_weighted_total` chain-state injection (§5 load-bearing question).

### §3.5 Current-substrate inventory (template §8.1 — Round 3 pre-flight seed)

Recorded at audit pin `2cf4cbfde` for implementers and Round 1.

| Location | What exists today | PR 7 disposition |
|----------|-------------------|------------------|
| `engine/traits/mod.rs` | Lists `EconomicsEngine` in module docs; **no** `economics.rs` | **Create** trait module |
| `engine/mod.rs` `Engine<…>` | `Engine<S, D, L, R, P>` — **no** `E`, **no** `economics` field | **C6:** add `E`, field `economics` |
| `engine/traits/*.rs` | `daemon`, `key`, `ledger`, `pending_tx`, `refresh` only | Add `economics` |
| `shekyl-engine-core/Cargo.toml` | **No** `shekyl-economics` dependency | Add workspace dep |
| `shekyl-economics` | `calc_burn_pct`, `compute_burn_split`, `calc_release_multiplier`, `calc_effective_emission_share`, `split_block_emission`, `EconomicParams` | **Consume** from `LocalEconomics` |
| `shekyl-economics-sim` | Full block loop with `base_reward = (remaining >> esf)` emission curve | **Factor** emission-at-height into `shekyl-economics` (shared with sim) — Round 1 shape |
| `engine-core` `build.rs` | `consensus_constants_generated.rs` — FCMP reference ages only | Emission may need `economics_params.json` / consensus JSON keys — verify at pre-flight (B6) |
| `engine-state` `StakerPoolState` / `AccrualRecord.total_weighted_stake` | Chain-reported accrual mirror | **Candidate input** for `pool_weighted_total` canonical read (§5) |
| `shekyl-staking` `Registry::total_weighted_stake` | Wallet-local stake registry math | **Not** canonical pool total unless Round 1 proves equivalence — risk of Bug 2 recurrence |
| `shekyl-ffi` | Burn + emission share FFI | Contract tests / KAT alignment |
| `engine/test_support.rs` | Comment: `ROLE_ECONOMICS` planned | Land `MockEconomics` |
| `PERFORMANCE_BASELINE.md` | Economics benches **deferred** | Close FOLLOWUPS item at PR 7 merge |
| Orchestrator fee/burn paths | **No** `calc_burn` in `engine-core` grep | Trait extraction precedes consumer wiring; document in §2.2 |

### §3.6 Reversion clauses (template + §21)

| Disposition | Rejection (now) | Reopen when | Re-evaluation shape |
|-------------|-----------------|-------------|---------------------|
| Adaptive-burn state on trait surface | No `observe_activity` / mutable economics methods at V3.0 | V3.x Component 3 design lands with named consumer + §2.7 discipline-test pass | Phase 2b / V3.x design round; §8.2 amendment if surface changes |
| Extend `EconomicsEngine` into consensus enforcement | Scope guard §2.7 | Never for wallet — chain is truth | N/A — priority-hierarchy rejection |
| Stub `current_emission` / `pool_weighted_total` with `todo!()` | Hides missing canonical port | **Rejected** — use reversion on deferral only if implementation proves multi-quarter | Round 1 must dispose; else PR blocked |
| `MockEconomics` | N/A — **accepted** per §6.1 | Remove when contract-fidelity `FaultInjecting<LocalEconomics>` suffices for all tests | Follow PR 3/4 retirement pattern |

### §3.7 Branch posture (template §3.5)

- [x] Cite [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2.
  Design branch `feat/stage-1-pr7-economics-engine-design`; implementation
  `feat/stage-1-pr7-economics-engine` lands on `dev` within ≤5 days / ≤10
  commits after Round 3 closes.
- [x] **Interleave with PR 6.** §8.1 allows parallel landing; **both PRs touch
  `Engine` type parameters** — coordinate merge order or stack PR 7 on post–PR
  6 `dev` tip to avoid `Engine<…>` conflict (open question §5.4).

### §3.8 Performance gate obligations (Round 0 pin)

Per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3 /
§10.2.1 and [`FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 performance item:

| Bench | Introduced in | Workload class (pre-pin) | Baseline record |
|-------|---------------|-------------------------|-----------------|
| `engine_trait_bench_economics_current_emission` | PR 7 C7 (tentative) | State-dependent compute — `height` argument; fixture holds `LocalEconomics` + representative `already_generated` / params | `PERFORMANCE_BASELINE.md` §Bench + cumulative-delta row at merge SHA |
| `engine_trait_bench_economics_parameters_snapshot` | PR 7 C7 | Likely trivial pure-read at V3.0 (constants snapshot); **confirm at bench authoring** per §4.4 checklist item 5 | Same |

**Procedure:** Match
[`engine_trait_bench_ledger_synced_height`](../rust/shekyl-engine-core/benches/engine_trait_bench_ledger_synced_height.rs)
pattern — criterion + iai-callgrind pair, shared `benches/common/engine_fixture.rs`
extension or sibling `economics_fixture.rs`, `compare.py` threshold class
`engine_trait_bench_*`.

**Gate:** PR 7 does not open for review until both bench sections are populated
and CI workflow captures N=3 medians (or documents workflow_dispatch deferral
with same precedent as PR 3 closeout, if applicable).

### §3.9 Implementor shape (Round 0 disposition)

| Option | Disposition |
|--------|-------------|
| **`LocalEconomics` in `shekyl-engine-core`** | **Selected** per §3.1 table — Stage 1 type adjacent to other `Local*` engines. |
| **Wrapper over `shekyl-economics` only** | **Selected** — no economics logic duplicated in `engine-core` except chain-state injection adapters Round 1 pins. |
| **Separate `shekyl-engine-economics` crate** | **Rejected** — one-site consumer; violates `17-dependency-discipline` cost/benefit for V3.0. |
| **Error mapping** | `EconomicsError` in `engine/error.rs` per §4; `type Error: Into<EconomicsError>` on trait; `RuntimeFailure` variant Stage 4-only at V3.0. |

### §3.10 Engine parameterization (Round 0 disposition)

- **Introduce `E: EconomicsEngine = LocalEconomics` in PR 7** — yes. Spec §3
  requires slot pre-wired before Phase 2b.
- **Field name:** `economics: E` (spec §3 composition).
- **Parameter order (incremental):** Insert `E` **immediately after `L`**:
  - If PR 6 not landed:
    `Engine<S, D, L, E, R, P, …>`.
  - If PR 6 landed first:
    `Engine<S, D, L, E, R, P, F, …>`.
  - Full spec order `<S, K, L, E, D, F, R, P>` remains **deferred** (PR 6
    Appendix C; same for `K`).
- **Stage 2 actors:** Do not introduce `EngineConfig` / actor handles in PR 7.

---

## §4 Round 1 — Load-bearing question (OPEN)

> **Round 1 status:** OPEN — disposition lands in §5 after candidate
> wargaming. Reopen Round 0 only if substrate audit pin drifts.

### §4.1 Mission posture (Round 1)

See §1. Round 1 adds: the extraction must deliver **one canonical Rust home**
for (a) emission-at-height, (b) burn-fraction-from-fee+activity, (c)
pool-weighted-total, (d) parameter snapshot — without importing per-stake or
per-shard state onto the trait.

### §4.2 Scope pointer

§2.1 / §2.2.

### §4.3 Pre-flight pointer

§3 — Round 0 complete.

### §4.4 Phase 0 candidates (pre-enumeration)

| ID | Binding form | Module (tentative) | Notes |
|----|--------------|-------------------|-------|
| **0a** | `pub(crate) trait EconomicsEngine` | `engine/traits/economics.rs` | §2.7 signatures verbatim |
| **0b** | `pub struct LocalEconomics<…>` | `engine/local_economics.rs` | Round 1 chooses state injection shape |
| **0c** | `pub enum EconomicsError` | `engine/error.rs` | §4 Round 4a pin |
| **0d** | `pub struct EconomicsParametersSnapshot` | `engine/economics_types.rs` or `local_economics.rs` | Field layout Round 1 |
| **0e** | `pub struct ActivityMetric` | same | Burn inputs — align `calc_burn_pct` |
| **0f** | `Engine<…, E: EconomicsEngine = LocalEconomics>` + `economics: E` | `engine/mod.rs`, `lifecycle.rs`, `merge.rs`, … | C6 sweep |
| **0g** | `MockEconomics` | `engine/test_support.rs` | §6.1 |
| **0h** | `block_emission_at_height(height) -> u64` (name TBD) | `shekyl-economics` | Factor from sim — **new** API |

### §4.5 Load-bearing question

**How does stateless `LocalEconomics` implement `pool_weighted_total(&self) ->
u128` and `current_emission(&self, height) -> Result<u64, …>` as the single
canonical wallet derivation paths without (i) duplicating `shekyl-economics-sim`
emission logic, (ii) reintroducing scattered stake-registry math (Bug 2 class),
or (iii) violating §2.7 “no per-entity state on `EconomicsEngine`”?**

#### §4.5.0 Actor-mesh framing

**Not applied** (lens bounded). Synchronous canonical-derivation framing;
rich semantics live in `shekyl-economics` + chain-state injection, not a
diagnostic stream.

#### §4.5.1 Candidate shapes (Round 1 — for wargaming)

| Shape | Summary | Meets §2.7? |
|-------|---------|-------------|
| **(1) Pure constants** | `LocalEconomics` holds only `EconomicParams`; `pool_weighted_total` reads latest accrual from **injected** `Arc<dyn Fn() -> u128 + Send + Sync>` wired at `Engine::open` from `ledger` indexes | Yes — injection is orchestrator wiring, not per-stake trait state |
| **(2) Ledger snapshot reader** | `LocalEconomics` holds `Arc<L>` where `L: LedgerEngine` + **new** `LedgerEngine` accessor for staker-pool aggregate (§8.2 amendment) | Yes if accessor returns public aggregate only |
| **(3) Caller-supplied pool total** | Amend trait: `pool_weighted_total(&self, pool: PoolSnapshot)` | **No** — violates pinned §2.7 signature; reject unless spec round reopens |
| **(4) Defer bodies** | `todo!()` until StakeEngine | **Reject** — cost-benefit-defer anti-pattern |

**Emission sub-question (paired):** Port CryptoNote-style `base_reward(height,
already_generated)` into `shekyl-economics` (shape **0h**), shared with
`shekyl-economics-sim`, with parameters from `economics_params.json` /
`EconomicParams`. `current_emission` wraps release multiplier when orchestrator
supplies tx-volume context — or documents tx-volume **default** at V3.0 for
pure height query (Round 1 must pin).

#### §4.5.2 Implications for prior PRs

| PR | Impact |
|----|--------|
| PR 2 `LedgerEngine` | Shape (2) may need **read-only** staker-pool aggregate accessor — §8.2 co-land if added |
| PR 5 `PendingTxEngine` | Future `FeeEstimator` may call `burn_fraction` — **out of PR 7**; trait must exist |
| PR 6 `PersistenceEngine` | `Engine<…>` type-param merge coordination only |

#### §4.5.3 Criteria rationale (draft — finalize at Round 1 closure)

1. **Single canonical source** — one implementation path per derived value.
2. **Spec surface stability** — no signature changes V3.0 → Stage 4.
3. **`shekyl-economics` authority** — parameters from generated constants, not
   hardcoded in engine-core.
4. **V3.x-ready** — `parameters_snapshot` contract forbids silent caching; doc
   + tests.
5. **Adversarial wrong-derivation** — constant drift / u128 overflow / divergent
   pool sources caught by tests + KATs.

#### §4.5.4 R-residuals (named — Round 2 segments)

| ID | Topic | Round 2 segment (planned) |
|----|-------|---------------------------|
| **R1** | `ActivityMetric` field layout vs `calc_burn_pct` inputs | 2a |
| **R2** | `EconomicsParametersSnapshot` fields vs `EconomicParams` + display needs | 2a |
| **R3** | `pool_weighted_total` chain-state injection shape | 2b |
| **R4** | `current_emission` tx-volume / release-multiplier inputs at V3.0 | 2b |
| **R5** | `MockEconomics` contract fidelity vs `LocalEconomics` | 2c |
| **R6** | Consumer wiring scope boundary (`PendingTxEngine` / fee path) | 2d |
| **R7** | Phase 0 spec amendment necessity | 2g close-out |

#### §4.5.5 Round 1 disposition

**Pending** Round 1 wargaming. Provisional lean: **shape (1) or (2)** for
`pool_weighted_total`; **0h port** for `current_emission`; reject (3) and (4).

**Reopen criterion:** Round 2 surfaces a need for trait signature change or
consensus-enforcement method → explicit Round 1 reopen per principle 5.

---

## §5 Round 2 — Segment placeholders

> Segments land after Round 1 closure. Names follow PR 5 / PR 6 precedent.

| Segment | Scope (planned) |
|---------|-----------------|
| **2a** | R1 + R2 — `ActivityMetric`, `EconomicsParametersSnapshot` binding pins |
| **2b** | R3 + R4 — pool total + emission derivation dispositions |
| **2c** | R5 — `MockEconomics` + §6.1 contract fidelity |
| **2d** | R6 — consumer wiring: V3.0 trait-only vs minimal `Engine` helper |
| **2g** | Close-out — §4 Phase 0 final, §6 review checklist, Round 3 readiness |
| **2h** | *(reserve)* — post-close substrate refinement |
| **2i** | Wider-substrate audit (§6) — Bitcoin/Ethereum/Monero fee-policy drift lessons |

### §5.4 PR 6 / PR 7 merge coordination (Round 0 → Round 2)

If both implementation branches touch `engine/mod.rs`:

1. Land PR 6 `F` slot first **or**
2. Single integration branch merging design-disposition order from §8.1
   (interleave allowed) with **one** `Engine` type-parameter edit.

**Do not** mark Stage 1 complete after only one of the two.

---

## §6 Pre-Round-3 wider-substrate audit (PLACEHOLDER)

Per template §6 — runs after Round 2 segment **2g** closes, before Round 3 §7.X
drafting.

**Audit question:**

> What have other wallet ecosystems taught us about deployment failure modes
> that this PR's substrate hasn't named?

**Seed sources for PR 7 domain:**

- Bitcoin: fee-estimator divergence, cached feerate staleness.
- Ethereum: gas-estimation adversarial inputs (parallel to `burn_fraction`
  activity metric trust).
- Monero: wallet/display emission mismatch (historical — Shekyl deletes Monero
  paths; lesson is **single derivation** still applies).
- Shekyl: `parameters_snapshot` caller caching breaking V3.x adaptive burn
  (forward-compat discipline §2.7).

**Yield placeholder:** G1–Gn table — disposition in Round 2 segment **2i**.

---

## §7 Round 3 — §7.X commit decomposition (PLACEHOLDER)

> **Implementer note:** Bodies below are Round 0 placeholders. Round 2
> segments and Round 3 closure refine within-commit scope. Sub-commit α/β/γ
> only if C2 warrants split (likely minimal for economics).

**Deviation from template eight-commit default:** No diagnostic enum (skip C3),
no secondary traits (skip C4), no `FaultInjecting` at V3.0 (skip C7 unless
Round 2 reopens). Tentative **seven commits** C0–C6 + C7 docs/benches.

| Commit | Scope | Notes |
|--------|-------|-------|
| **C0** | Phase 0 spec amendment (if Round 1–2 require §2.7 type pins) | Doc-only |
| **C1** | `EconomicsError`, `ActivityMetric`, `EconomicsParametersSnapshot` | `engine/error.rs` + types module |
| **C2** | `shekyl-economics`: shared `emission_at_height` (0h) + tests; sim uses shared API | May be separate commit **C2ε** if scope boundary needs split |
| **C3** | `EconomicsEngine` trait + `LocalEconomics` impl | Function-body replacement per `26-sub-pr-design-discipline` A1 |
| **C4** | `MockEconomics` + trait unit tests | §6.1 |
| **C5** | `Engine` `E` parameter + `economics` field; lifecycle/merge wiring (construct `LocalEconomics`) | Coordinate with PR 6 `F` |
| **C6** | Benches + `PERFORMANCE_BASELINE.md` population | FOLLOWUPS partial close |
| **C7** | Docs: CHANGELOG, rustdoc, design doc status → Phase 1 landed | |

### §7.1 Stage 1 closeout dependency (PR 6 + PR 7)

| Milestone | Action |
|-----------|--------|
| PR 6 implementation merged | `PersistenceEngine` + `F` slot on `dev` |
| PR 7 implementation merged | `EconomicsEngine` + `E` slot on `dev` |
| **Then** | Update §1 banner in `V3_ENGINE_TRAIT_BOUNDARIES.md`, FOLLOWUPS V3.0 inventory, optionally add `STAGE_1_COMPLETION_AUDIT.md` |

**Do not** assert Stage 1 complete in PR 7 PR description alone.

---

## §8 Discipline-citation matrix (PLACEHOLDER)

Round 2 segment **2i** / Round 3 produces §8.3.3-equivalent matrix (6–8 rows).
Round 0 seed rows:

| # | Discipline | Failure mode foreclosed | Substrate (planned) |
|---|------------|-------------------------|---------------------|
| 1 | Canonical-derivation surface | Bug 2/7 scattered pool/emission math | §2.7 trait + `LocalEconomics` |
| 2 | Scope guard §2.7 | Wallet “consensus enforcement” illusion | §1 + §2.2 |
| 3 | `parameters_snapshot` forward-compat | V3.x caller cache breakage | §2.7 docstring + tests |
| 4 | `Result` ceremony | Stage 4 signature break | §2.7 + `EconomicsError` |
| 5 | `shekyl-economics` authority | Constant drift vs JSON | `17-dependency-discipline` |
| 6 | Performance baseline | Unbounded trait dispatch regression | §3.8 benches |

---

## §9 Banner discipline (template §9)

| Event | Banner text (to apply on closure) |
|-------|-----------------------------------|
| Round 0 close | `Round 0 closed 2026-05-27; pre-flight + substrate inventory; reopen: trait identity / scope guard challenged.` |
| Round 1 close | *(pending)* |
| Round 2 close | *(pending)* |
| Round 3 close | *(pending)* |

---

## Appendix A — Spec trait surface (reference)

From [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7
(abridged):

```rust
pub trait EconomicsEngine {
    type Error: Into<EconomicsError>;

    fn current_emission(&self, height: u64) -> Result<u64, Self::Error>;
    fn burn_fraction(
        &self,
        fee: u64,
        activity: ActivityMetric,
    ) -> Result<u64, Self::Error>;
    fn pool_weighted_total(&self) -> u128;
    fn parameters_snapshot(&self) -> EconomicsParametersSnapshot;
}
```

---

## Appendix B — Linkage to PR 6

| Topic | PR 6 | PR 7 |
|-------|------|------|
| Stage 1 trait remaining | `PersistenceEngine` impl | `EconomicsEngine` impl |
| `Engine` type params | Adds `F` (end of list per PR 6 design) | Adds `E` after `L` |
| Closeout gate | Both required | Both required |
| Critical path | Off critical path | Off critical path |

---

## Appendix C — Open questions blocking Round 1 closure

1. **`pool_weighted_total` injection** — shape (1) closure vs (2) ledger accessor
   vs spec amendment (reject (3)).
2. **`current_emission` semantics** — height-only base reward vs includes
   release multiplier; where does tx-volume for release come from at V3.0?
3. **`ActivityMetric` definition** — map 1:1 to `calc_burn_pct(tx_volume, …)`
   inputs; document caller trust model (orchestrator-supplied activity).
4. **PR 6 / PR 7 merge order** on `Engine<…>` when both implementation branches
   are active.
5. **Phase 0 amendment** — are `EconomicsParametersSnapshot` / `ActivityMetric`
   field layouts spec-visible enough to require §2.7 doc amendment in C0?

---

*Template:* [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md).
*Spec:* [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7,
§2.8, §3, §4, §6.1, §7, §8.1–§8.3.
*Process:* [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
*Economic context:* [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md),
[`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md).
