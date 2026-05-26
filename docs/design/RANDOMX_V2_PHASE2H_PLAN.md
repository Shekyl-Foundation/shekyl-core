---
name: RandomX v2 Phase 2h plan
overview: "Post-2g adversarial-corpus methodology + implementation. Closes the Phase 2g R7 deferrals — RANDOMX_V2_PHASE2G_PLAN.md §3.19 R7-D1/R7-D2/R7-D3/R7-D4/R7-D5 — that reopened R1-D5 (adversarial seedhash corpus), R1-D6 (u128 / __int128_t edge-case data corpus), and R1-D8 (worst-case timing) under two independent substrate findings against R1-D5's V1-shaped class-heaviness grinding methodology (verifier-accessor gap + statistical-infeasibility gap; per-class σ-gaps from 6.8σ (CACHE_MISS) to ~125σ (CFROUND) against V2's PROGRAM_SIZE = 384). Restores the §2.5 corpus-coverage-as-leg-3-completeness audit-posture claim to full strength before genesis cut. Verifier surface is frozen (Phase 2F R3 + Phase 2g R5-D1); harness layering is frozen (Phase 2g Round 2 T2 four-crate split); 2h is harness-side work bounded by §1 substrate. Round 0 enumerates decision points (D-A through D-H, plus optional D-I rule-26 amendment) without closing them; Round 1 closes architecture; Round 2 closes threat model; pre-implementation round verifies surfaces / dependencies / corpus-size budget; implementation PR lands the methodology, accessor (if any), grinding tool (if any), corpus contents, mode_worst_case reactivation, T2/T6 reactivation, and the §2.5 leg-3 framing restoration. V3.0 pre-genesis queue target per docs/FOLLOWUPS.md; escalates ahead of V3.0 only if a Phase-2 audit finding surfaces a rare-path divergence the random + canonical corpora missed (per 16-architectural-inheritance.mdc priority-1 security override)."
todos:
  - id: phase2h-round-0
    content: "Round 0 scaffold: front-matter + §0 framing + §1 frozen substrate (six items with cite paths) + §2 forward-actions absorbed (R7-D1..R7-D5 specifications, FOLLOWUPS V3.0 scope items 1–6, rule-26 surface-enumeration-pass + substrate-derived constant validation pass) + §3 R1-D1..R1-D8 decision points (open; not closed at Round 0) + §11 Round 0 history row. §4–§10 reserved as placeholders for Round 1+ substantive content. Land on chore/randomx-v2-phase2h-plan as one design-phase commit per 06-branching.mdc rule 2."
    status: in_progress
  - id: phase2h-round-1
    content: "Round 1 architecture close: close R1-D1 (V2-substrate-anchored adversarial-corpus methodology) + R1-D2 (verifier-side or C-shim accessor) + R1-D3 (grinding/construction tool location and shape) + R1-D4 (on-disk corpus format) + R1-D5 (mode_worst_case implementation surface + ≤5.0× ratio substrate-anchored realism check) + R1-D6 (T2/T6 reactivation cadence) + R1-D7 (CI cadence + workflow placement) + R1-D8 (statistical-realism acceptance criterion replacing R1-D5's V1-shaped thresholds; load-bearing per §3.19 R7-D1). Each close carries explicit reopen-criteria per 21-reversion-clause-discipline.mdc. Open R1-D9 only if substrate surfaces it (rule-26 amendment shape)."
    status: pending
  - id: phase2h-round-2
    content: "Round 2 threat-model close: §4 passive + active surfaces under the new corpus methodology. Adversarial corpus changes both surfaces (per Phase 2g §4.4/§4.5/§4.6 precedent: T-A1 silent-disposition-degradation now applies to the adversarial corpus's tamper detection, T-A2 corpus-tamper applies to the adversarial entries, M1 canonical-output property extends to the adversarial canonical hashes). Confirm §35-secure-memory.mdc / §36-secret-locality.mdc remain N/A per Phase 2c §5.11.4 (cache memory public-input-only; the 2h work does not introduce secret-bearing intermediate state)."
    status: pending
  - id: phase2h-pre-implementation
    content: "Pre-implementation round (mandatory per 26-sub-pr-design-discipline.mdc + the R5-D1 R4-blind-spot finding queued for rule-26 amendment; second instance of the discipline after Phase 2g, promoting it to amendment-ready status): surface-enumeration pass against the actual verifier source (confirm any chosen accessor's surface matches §1 frozen items; no production surface grows; test-internals feature gate's discipline is preserved); dependency-discipline pass per 17-dependency-discipline.mdc (any methodology-required crate — cargo-fuzz / bolero / proptest / honggfuzz / arbitrary — verified at source for workspace state, API existence, property existence, feature-flag plumbing); substrate-derived constant validation pass per §3.19 R7-D5 (any numeric threshold the methodology cites — percentile cutoffs, candidate counts, σ values, ratio bounds — verified against V2 substrate's reachability calculus); corpus-size budget verification against runner class (per-PR vs. nightly vs. release-gate sizing fits within existing CI runtime budgets per Phase 2g §9.3 precedent)."
    status: pending
  - id: phase2h-implementation
    content: "Implementation PR on feat/randomx-v2-phase2h-impl off dev: methodology landing, accessor (if any) under the existing `test-internals` feature gate (R5-D1 carve-out shape; sole consumer is shekyl-randomx-differential), grinding/construction tool (if any), adversarial corpus contents, mode_worst_case reactivation in src/main.rs (replaces the §3.19 R7-D4 diagnostic-only branch at the existing CLI dispatch point), §6 T2 + T6 reactivation, §9 CI cadence wiring, canonical-output pinning for adversarial entries per §3.18 R6 cluster discipline, plan-doc closure (§5/§6/§8 substantive content at implementation time per Phase 2g precedent), §2.5 leg-3 framing restoration. Bounded by 06-branching.mdc rule 2 (≤10 commits / ≤5 working days); 07-consensus-atomic-cutovers.mdc explicitly NOT invoked (2h is harness-side, no consensus-rule boundary)."
    status: pending
  - id: phase2h-docs-close
    content: "Per 91-documentation-after-plans.mdc: docs/CHANGELOG.md entry (V3.0 pre-genesis queue closure), parent RANDOMX_V2_PLAN.md status note refresh (Track A Phase 2 status as of close; phase2h-* todo entry closed), this plan-doc's §11 Round history rows for every round landed, docs/FOLLOWUPS.md V3.0 'Post-2g adversarial-corpus methodology + implementation' entry closed by replacement (item's reopening criterion is 'the post-2g round completes and lands the adversarial corpus, at which point R7-D1 closes by replacement' — same close shape as 2h's implementation PR lands)."
    status: pending
isProject: false
---

# RandomX v2 — Track A Phase 2h plan

## Front-matter

| Field | Value |
|-------|-------|
| Status | Active plan document; Round 0 scaffold + Round 1 architecture close landed on `chore/randomx-v2-phase2h-plan`; Round 2 (threat model) and pre-implementation round pending |
| Parent plan | [`docs/design/RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) — Track A Phase 2 status note (2026-05-25; line 304); parent plan-doc's `todos:` list does not yet carry a `phase2h-*` entry — this plan-doc's closure adds one |
| Sibling plans | [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md) §3.19 R7-D1/R7-D2/R7-D3/R7-D4/R7-D5 (the routing decision); §3 R1-D5 / R1-D6 / R1-D8 close annotations (reopened banners); §2.5 Round 7 amplification (corpus-coverage-as-leg-3-completeness restoration target); §6 T2 / T6 (deferred tests this round reactivates); §5.1.11 (deferred `mode_worst_case`); §3.17 R5-D1 (`test-internals` feature-gate carve-out precedent); §3.18 R6 cluster (canonical-output pinning discipline) |
| Base commit (`dev` tip at scaffold) | `33d22a83b44918da7efcab2e3dcc8f543c9495fa` — "Merge pull request #75 from Shekyl-Foundation/feat/randomx-v2-phase2g-impl" (2026-05-25) |
| Fork pin | `external/randomx-v2` at `aaafe71` (v2.0.1); unchanged by 2h per §1 substrate (2h is harness-side; no fork bump) |
| Design-phase branch | `chore/randomx-v2-phase2h-plan` (single short-lived branch off `dev` carrying Round 0 scaffold + Round 1 architecture close + Round 2 threat-model close + pre-implementation round; consolidated single-branch flow chosen at Round 1 open per [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2's ≤5-working-day / ≤10-commit budget. Phase 2g used a scaffold-then-feat-branch split; 2h's smaller scope makes single-branch consolidation defensible. Per-round commits stay mechanically separable via commit-message discipline per [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc).) |
| Implementation branch | `feat/randomx-v2-phase2h-impl` (separate implementation branch for the post-design-close work per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc) rounds discipline; the design/implementation split is preserved even with the design-phase consolidation, because the implementation PR carries production-code changes that warrant the standard fresh-branch review boundary) |
| Round 0 scope envelope | Substrate capture only: lock the 2c/2d/2f/2g-frozen surfaces against which 2h operates; enumerate R1-D1..R1-D8 decision points without closing them; absorb the §3.19 R7-D1..R7-D5 specifications and the FOLLOWUPS V3.0 scope items; name the rule-26 surface-enumeration-pass and substrate-derived constant validation pass forward-actions as pre-implementation-round obligations. No production Rust code; no harness binary changes; no `mode_worst_case` reactivation; no CI workflow changes; no FOLLOWUPS reflow; no `adversarial_corpus.rs` body change. |
| Out of scope (forward-deferred) | (a) **`compute_hash` divergence from C reference at large data sizes** — separate FOLLOWUPS V3.0 entry with its own trigger ([`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) lines 50–82); 2h consumes the harness as-is. 2h benefits if the divergence lands first; if not, 2h proceeds independently against the random + canonical-output corpora plus the new adversarial corpus. (b) **V4 lattice-cryptography corpus** — V4 substrate is not stable per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) three-timeframe discipline; reopening criterion is NIST lattice-cryptography standardization, not 2h. (c) **Re-litigation of Phase 2g R7-D1/R7-D2/R7-D3/R7-D4/R7-D5 closures** — those dispositions are "deferred to the post-2g round"; 2h is the round, not a re-opening of the deferral. (d) **Phase 2F R3-frozen verifier public surface reshape** — `Seedhash`, `PreparedCache`, `compute_hash`, `CacheStore` are frozen; 2h may add a second `test-internals`-gated accessor under the R5-D1 discipline but does not alter the production surface. (e) **Per-PR per-hash latency CI gate (≤3.0× ratio)** — activates at Phase 3a per [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §6; 2h's `mode_worst_case` lands the release-gate worst-case ratio measurement, not the per-PR latency gate. (f) **Full 600k-block initial-sync wall-time test** — release-gate suite per parent plan §6; orthogonal to 2h. |

## 0. Why this document exists (Round 0)

Round 0 captures **the inherited substrate**: what the merged 2c / 2d / 2f
/ 2g code already pins so 2h cannot quietly change it, what the §3.19 R7
deferrals routed forward to this round, and what shape the Round 1
decisions need to take when they land. Round 0 does **not** close
decisions — that is Round 1's job. The scaffold's purpose, per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
is to give a reviewer reading any future Round-N round a single
substrate-anchored document to check the round's claims against, rather
than re-derive the carry-forwards from `RANDOMX_V2_PHASE2G_PLAN.md`'s
§3.19 + §3 + §2.5 + §6 + §5.1.11 + §3.17 sections, the FOLLOWUPS V3.0
entry, and the four frozen substrate code files each time.

Per [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc)
"specification first, code second," Round 0 is the design-doc-first
step before Round 1's option-set evaluation. Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
"reject-now-with-named-reopening-criteria," every decision Round 1
closes carries an explicit reopen-criterion clause; Round 0 pre-shapes
the §3 R1-D* entries to make that discipline mechanical rather than
ad-hoc at Round 1 close.

### Routing rationale (why 2h is the right venue)

Phase 2g [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md) §3.19
R7-D1 + R7-D2 reopen R1-D5 (adversarial seedhash corpus) and R1-D6
(u128 / `__int128_t` edge-case data corpus) under two independent
substrate findings against R1-D5's V1-shaped class-heaviness grinding
methodology:

1. **Verifier-accessor gap.** R1-D5's grinding methodology requires
   per-program opcode-class tallying to evaluate the ≥40% per-class /
   ≥60% combined acceptance criteria; the verifier's program-decode
   infrastructure (`InstructionType` + `decode_instruction_type`) is
   `pub(crate)`. Carrying this through the R5-D1 `test-internals`
   precedent (sketched as
   `compute_hash_opcode_streams_for_testing(prepared, data) ->
   [[u8; PROGRAM_SIZE]; RANDOMX_PROGRAM_COUNT]`) costs a second
   feature-gated `pub` surface on `shekyl-pow-randomx` plus a
   duplicated `compute_hash_inner` body whose drift is anchored only
   by a cross-check `#[test]`.
2. **Statistical-infeasibility gap.** R1-D5's ≥40% / ≥60% acceptance
   criteria were calibrated against V1's `PROGRAM_SIZE = 256`. Under
   V2's `PROGRAM_SIZE = 384`, the per-class opcode-class distribution
   against `configuration.h:88–125` `RANDOMX_FREQ_*` substrate
   produces per-class σ-gaps of 6.8σ (`CACHE_MISS`) up to ≈125σ
   (`CFROUND`); fewer than 10⁻⁸ threshold-meeting candidates expected
   within any realistic compute budget (4 h × ~5 candidates per
   second × 16 threads × 8 programs ≈ 9.2 M program samples). The
   grinding tool against R1-D5's literal criteria produces
   best-of-N candidates that aren't actually adversarial — the
   §4 T-A1 silent-disposition-degradation failure mode.

Per R7-D4, the disposition routes adversarial-corpus methodology
design + implementation to "the post-2g design round." **Phase 2h
is that round.** §3.19 R7-D5 additionally queues "substrate-derived
constant validation pass" as a fourth pre-implementation discipline
class for [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
amendment, alongside R5-D1's surface-enumeration pass, R5-D2's
cross-invariant impact analysis, and R6-D2's methodology-vs-surface-contract
reconciliation. The 2h pre-implementation round is the second instance
of the discipline, promoting it to rule-26 amendment-ready status
(see §3 R1-D9 optional decision).

### Audit-posture restoration (why this lands pre-genesis)

The audit-posture framing for 2h comes from
[`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md) §2.5
(three-leg audit posture). 2g ships with **common-path leg-3
coverage** (random corpus per R1-D4 + canonical outputs per §3.18
R6 cluster + cache-equivalence precondition per R1-D14). **Rare-path
leg-3 coverage** — the adversarial seedhash + u128 edge-case
contributions originally scoped for R1-D5 / R1-D6 — was deferred
under R7-D1 / R7-D2. Per §2.5's R7-D3 amplification, the deferred
gap is carried in the interim by legs 1 (spec-faithful implementation
discipline) and 2 (C-reference audit), plus the canonical-output
third-leg-property (M1) which catches divergences against the
committed-canonical seedhash set.

Per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
priority-1 security commitment and the "cost-benefit-defer-to-later
anti-pattern" naming, the deferral has a named reopening criterion:
**land the post-2g methodology + corpus pre-genesis** so the
"Shekyl's verifier is canonical RandomX v2" claim presents full
audit-posture evidence at genesis cut. The V3.x platform is the
fallback target only if substrate cost is genuinely prohibitive
(multi-quarter scope; cross-component coordination breaking the
discipline budget); the 2h scope is bounded by §1 substrate and
should converge within the V3.0 pre-genesis window.

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) priority
hierarchy: adversarial-corpus catch capacity is a priority-1
(security) property; statistical realism of the methodology's
acceptance criteria is itself a priority-1 substrate property.
Closing 2h without a V2-substrate-anchored statistical-realism
criterion (R1-D5's V1-shaped thresholds are unreachable per R7-D1)
is the same failure mode 2h exists to correct.

### Round-count expectation

**2h's Round 1 is expected to converge in ≤2 rounds.** The
substrate-anchored rationale: 2h introduces no new verifier-side
architectural changes — the type-system surface (`Seedhash` newtype,
`PreparedCache` bundle, `compute_hash` signature, `CacheStore` API,
cfg-gated `VmStatePool`) was closed by Phase 2F Rounds 2 and 3 and
is frozen per §1, and the four-crate layering (Phase 2g Round 2 T2)
puts 2h entirely in the harness-side actor. The substantive Round 1
decisions are methodology shape (R1-D1), accessor surface (R1-D2),
grinding/construction tool (R1-D3), corpus on-disk format (R1-D4),
`mode_worst_case` implementation (R1-D5), test reactivation cadence
(R1-D6), CI cadence + workflow placement (R1-D7), and the
statistical-realism acceptance criterion (R1-D8). All eight are
bounded by the §1 substrate — none require reopening a frozen surface.

**Round 2** closes the threat model (§4) against the Round-1
substrate per Phase 2g's Round-2 → Round-3 precedent. The
adversarial corpus changes both the passive surface (T-A1
silent-disposition-degradation now applies to the adversarial
corpus's tamper detection; T-A2 corpus-tamper applies to the
adversarial entries) and the active surface (the §3.18 R6 cluster
canonical-output property extends to the adversarial canonical
hashes).

**Pre-implementation round** is mandatory per the queued rule-26
amendment (R7-D5 + the R5-D1 R4-blind-spot finding). The round
performs five passes: (1) surface enumeration against the actual
verifier source (no production surface grows); (2) dependency
discipline per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
on any methodology-required crate (`cargo-fuzz` / `bolero` /
`proptest` / `honggfuzz` / `arbitrary` etc. — read the actual
`Cargo.toml`s under `~/.cargo/registry/src/`, do not rely on
training-data recall); (3) substrate-derived constant validation
per R7-D5 (verify every numeric threshold the methodology cites
is reachable against V2 substrate); (4) corpus-size budget
verification against runner class; (5) **methodology-vs-substrate
consistency check** — verify the chosen methodology's operational
substrate exists and behaves as the methodology assumes. Concrete
shape per methodology: for tail-percentile grinding, confirm the
chosen percentile is reachable in the chosen budget against the
actual V2 opcode-frequency distribution (`RANDOMX_FREQ_*` table
in `randomx-v2-sys`'s vendored `configuration.h`, read at source);
for coverage-guided fuzzing, confirm the coverage metric (line,
branch, edge) is actually reported by the chosen fuzzer against
the verifier's instruction code (read the fuzzer's docs at source,
do not assume); for spec-derived rare-path enumeration, confirm
the spec actually documents the rare paths the methodology depends
on (read the spec at source, do not assume rare-path enumeration
exists). Pass 5 is structurally adjacent to Pass 3 — Pass 3
validates numeric constants against substrate, Pass 5 validates
methodology operational substrate against assumptions — but is
the discipline that would have caught the original R1-D5 failure
mode if applied at original methodology-selection time. Round 1
or the pre-implementation round determines whether Pass 5 is a
distinct discipline class (a fifth) or a refinement of Pass 3
(a sub-pass) for the rule-26 amendment queue per R1-D9.

Calibration precedent. Phase 2g closed in 8 substrate-anchored
rounds (Round 0 scaffold + Rounds 1–7 covering architecture,
threat model, R4 implementation-correctness, R5–R6
substrate-completeness, R7 reopening). 2h's reduced scope — single
deferred sub-cluster against frozen verifier and harness surfaces —
maps to roughly half that cadence: **3 substantive close-rounds
(Round 1 architecture + Round 2 threat-model + pre-implementation),
plus Round 0 scaffold**, matching the 5-day / 10-commit budget per
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2.

This is a calibration expectation, not a hard ceiling. If Round 1's
adversarial pass surfaces a substrate finding that warrants a
Round 2 architectural reframe (e.g., a methodology disposition that
requires a verifier-side surface beyond R5-D1's `test-internals`
discipline), the round-count budget reopens substrate-anchored per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
The expectation calibrates reviewers' attention budget, not the
rigor of any individual round.

## 1. Frozen substrate (do not reopen in 2h)

The following are pinned by upstream rounds and the merged 2c / 2d
/ 2f / 2g code. Reopening any of them moves 2h's scope outside its
named brief. Each item is cited with file path + line number; the
"why frozen" column captures the round that closed it and the
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
disposition.

### 1.1 Verifier-crate public API (Phase 2F R3 + Phase 2g R5-D1)

`shekyl-pow-randomx`'s public surface is frozen at the four
re-exports plus the existing `test-internals`-gated accessor:

| Surface | Path:line | Frozen by |
|---|---|---|
| `pub use cache_store::CacheStore;` | [`rust/shekyl-pow-randomx/src/lib.rs:189`](../../rust/shekyl-pow-randomx/src/lib.rs) | Phase 2F §3.1 Round 2 |
| `pub use prepared_cache::PreparedCache;` | [`rust/shekyl-pow-randomx/src/lib.rs:190`](../../rust/shekyl-pow-randomx/src/lib.rs) | Phase 2F §1.1 Round 2 |
| `pub use seedhash::Seedhash;` | [`rust/shekyl-pow-randomx/src/lib.rs:191`](../../rust/shekyl-pow-randomx/src/lib.rs) | Phase 2F §1.1 Round 2 |
| `pub use vm::compute_hash;` | [`rust/shekyl-pow-randomx/src/lib.rs:192`](../../rust/shekyl-pow-randomx/src/lib.rs) | Phase 2F §1.1 Round 2 (signature: `(&PreparedCache, &[u8])`) |
| `#[cfg(feature = "test-internals")] pub use vm::{compute_hash_opcode_streams_for_testing, PROGRAM_SIZE, RANDOMX_PROGRAM_COUNT};` | [`rust/shekyl-pow-randomx/src/lib.rs:204-205`](../../rust/shekyl-pow-randomx/src/lib.rs) | Phase 2g R7-D1 forward-action landed alongside R5-D1's `cache_block_bytes_for_testing` |

2h MAY add a second (or third) `test-internals`-gated accessor if
R1-D2 closes on a methodology that needs it; the surface shape is
bound by R5-D1's discipline (named feature, sole consumer is the
harness crate, plan-doc amendment-grade rationale). 2h may NOT
alter the four production re-exports or relax the
[`#![deny(unsafe_code)]`](../../rust/shekyl-pow-randomx/src/lib.rs)
/ [`#![deny(missing_docs)]`](../../rust/shekyl-pow-randomx/src/lib.rs)
crate-level lints at
[`rust/shekyl-pow-randomx/src/lib.rs:166-167`](../../rust/shekyl-pow-randomx/src/lib.rs).

### 1.2 Four-crate layering (Phase 2g Round 2 T2)

The actor-paradigm split established by Phase 2g §"Layer-separation
discipline (Round 2 observation)" is frozen:

1. **`shekyl-pow-randomx`** (verifier; pure transforms; public
   surface frozen per §1.1).
2. **`CacheStore`** (state-holder; lives inside the verifier crate;
   capacity-2 sticky-canonical store at
   [`rust/shekyl-pow-randomx/src/cache_store.rs`](../../rust/shekyl-pow-randomx/src/cache_store.rs)).
3. **`randomx-v2-sys`** (C-bindings boundary; sole consumer of the
   v2 fork's C ABI; Pattern-C-exempt per Phase 2g R1-D13).
4. **`shekyl-randomx-differential`** (harness orchestrator; long-running
   orchestration actor; mode-dispatch state +
   per-mode actor state).

2h is **harness-side work only**. No verifier-side architectural
changes, no new C-ABI surface, no movement of `CacheStore`
ownership. New 2h-side code lands under
[`rust/shekyl-randomx-differential/`](../../rust/shekyl-randomx-differential/);
verifier-side additions are limited to the `test-internals`-gated
accessor (if R1-D2 closes on that shape) at
[`rust/shekyl-pow-randomx/src/vm.rs`](../../rust/shekyl-pow-randomx/src/vm.rs)
under the existing feature gate.

### 1.3 Harness mode-dispatch surface (Phase 2g §3.15)

The four-mode dispatch surface is frozen:

| Mode | `--mode=` value | Current state | Cite |
|---|---|---|---|
| Correctness | `correctness` | Implemented; per-PR cadence | [`rust/shekyl-randomx-differential/src/main.rs:99,117,457-478`](../../rust/shekyl-randomx-differential/src/main.rs) |
| Latency | `latency` | Implemented; nightly cadence | [`rust/shekyl-randomx-differential/src/main.rs:106,119,479-491`](../../rust/shekyl-randomx-differential/src/main.rs) |
| Concurrent | `concurrent` | Implemented; per-PR cadence | [`rust/shekyl-randomx-differential/src/main.rs:109,120,511-523`](../../rust/shekyl-randomx-differential/src/main.rs) |
| Worst-case | `worst-case` | **Deferred per §3.19 R7-D4**; CLI surface emits an attributable diagnostic citing this plan-doc | [`rust/shekyl-randomx-differential/src/main.rs:102,118,492-510`](../../rust/shekyl-randomx-differential/src/main.rs) |

2h reactivates `mode_worst_case` (per R1-D5 close) by replacing
the diagnostic-only branch at
[`rust/shekyl-randomx-differential/src/main.rs:492-510`](../../rust/shekyl-randomx-differential/src/main.rs)
with the mode-module call — same dispatch shape as the three
implemented modes. The dispatch surface itself (the `Mode` enum +
`parse` + `as_str` + `dispatch` function) is **not reshaped** by
2h; any addition would be a §5.7 contract reshape that requires its
own plan-doc round per the closure rule in Phase 2g §3.15.

### 1.4 R1-D14 cache-equivalence precondition (Phase 2g §5.1.7)

The R1-D14 precondition — SHA-256 fingerprint compare via
`cache_block_bytes_for_testing` before per-input byte equality — is
frozen:

| Surface | Path:line |
|---|---|
| `Cache::block_bytes_le` (pub(crate) iterator helper; `cfg(feature = "test-internals")`) | [`rust/shekyl-pow-randomx/src/cache.rs:549-558`](../../rust/shekyl-pow-randomx/src/cache.rs) |
| `PreparedCache::cache_block_bytes_for_testing` (pub iterator; `cfg(feature = "test-internals")`) | [`rust/shekyl-pow-randomx/src/prepared_cache.rs:184-187`](../../rust/shekyl-pow-randomx/src/prepared_cache.rs) |
| `CANONICAL_CACHE_SHAS` (committed per-seedhash SHA-256 over the 256-MiB cache memory) | [`rust/shekyl-randomx-differential/src/canonical_outputs.rs:32-35`](../../rust/shekyl-randomx-differential/src/canonical_outputs.rs) |

2h's adversarial corpus runs the precondition before per-input byte
equality, **same as the random corpus** — no precondition reshape.
If the adversarial corpus introduces new seedhashes (R1-D1 + R1-D4
close), the corresponding `CANONICAL_CACHE_SHAS` entries are
generated by the same `gen-canonical-outputs` pipeline (per
[`rust/shekyl-randomx-differential/src/canonical_outputs.rs:46-65`](../../rust/shekyl-randomx-differential/src/canonical_outputs.rs))
against the same workspace-pinned fork SHA.

### 1.5 The `test-internals` feature-gate carve-out shape (Phase 2g R5-D1)

The `test-internals` feature is the **only** mechanism by which
test-only surfaces appear on `shekyl-pow-randomx`. R5-D1's
discipline:

- **Named feature.** `test-internals` is the named feature; no
  other feature unlocks any test-only surface.
- **Sole consumer.** `shekyl-randomx-differential`'s `Cargo.toml`
  is the only place the feature is enabled outside the verifier
  crate's own `#[cfg(test)]` blocks. The feature is **not**
  enabled in production builds of any downstream consumer.
- **Plan-doc amendment-grade discipline.** Each new
  `cfg(feature = "test-internals")` item requires a plan-doc
  amendment naming the consumer + the purpose, matching how
  `cache_block_bytes_for_testing` landed via Phase 2g R5-D1 and
  how `compute_hash_opcode_streams_for_testing` /
  `PROGRAM_SIZE` / `RANDOMX_PROGRAM_COUNT` landed via Phase 2g
  R7-D1's forward-action.

Per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
the carve-out is a load-bearing discipline that 2h does not relax.
If R1-D2 closes on "the methodology needs a new accessor," the
accessor lands under the same gate with the same R5-D1
discipline — not under a new feature flag, not as a `#[doc(hidden)]
pub`, not as `pub(crate)` with a downstream `use crate::vm::…`
indirection.

### 1.6 Canonical-output pinning discipline (Phase 2g §3.18 R6 cluster + §4.6 M1)

The harness's third-leg property (M1) — `rust == canonical && c ==
canonical` — is anchored by committed canonical outputs against the
workspace-pinned fork SHA:

| Surface | Path:line | Discipline |
|---|---|---|
| `CANONICAL_RANDOM_HASHES` (flat array indexed by corpus position) | [`rust/shekyl-randomx-differential/src/canonical_outputs.rs:25-31`](../../rust/shekyl-randomx-differential/src/canonical_outputs.rs) | §3.18 R6-D4 substrate-correction |
| `gen-canonical-outputs` binary (`src/bin/gen_canonical_outputs.rs`) | [`rust/shekyl-randomx-differential/src/bin/gen_canonical_outputs.rs`](../../rust/shekyl-randomx-differential/src/bin/gen_canonical_outputs.rs) | §5.2.6 + R4-D7 |
| Adversarial corpus's `ADVERSARIAL_CORPUS_SHA256` tamper-detection pin | [`rust/shekyl-randomx-differential/src/adversarial_corpus.rs`](../../rust/shekyl-randomx-differential/src/adversarial_corpus.rs) (currently empty-scaffold per §3.19 R7-D4) | Phase 2g T10 (`adversarial_corpus_hash_pin`) |

2h's adversarial corpus follows the same canonical-pinning shape:

1. The methodology produces an adversarial `(seedhash, data)` corpus
   (R1-D1 + R1-D4 close).
2. `gen-canonical-outputs` is re-run against the C reference at the
   workspace-pinned fork SHA `aaafe71`, producing the adversarial
   canonical hashes alongside the existing
   `CANONICAL_RANDOM_HASHES`.
3. The new canonical hashes commit alongside the corpus contents in
   the implementation PR.
4. Regeneration after any future substrate change (corpus
   re-grinding, fork pin bump, methodology refinement) is a
   **separate PR** with audit-against-actual-code verification, per
   §3.18 R6 cluster's regeneration discipline.

2h does **not** introduce a new canonical-output mechanism — it
extends the existing flat-array shape with adversarial-corpus
entries.

### 1.7 Negative space (2h does NOT do these things)

Per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
"user-protection defaults in user-absent contexts" and
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)'s
pre-genesis discount, the following are explicitly out of scope —
each named so a Round-N round or pre-implementation reviewer
cannot quietly reabsorb the scope:

- **Do not investigate or fix the `compute_hash` divergence at
  large data sizes** ([`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)
  lines 50–82). Separate FOLLOWUPS V3.0 entry with its own
  trigger; 2h consumes the harness as-is.
- **Do not expand to V4 lattice-cryptography corpus**. V4
  substrate is not stable; reopening criterion is NIST
  lattice-cryptography standardization, not 2h.
- **Do not relax `35-secure-memory.mdc` / `36-secret-locality.mdc`
  N/A status** per Phase 2c §5.11.4 (cache memory public-input-only).
  2h does not introduce secret-bearing intermediate state; §4
  Round-2 close confirms this explicitly.
- **Do not encode pre-genesis Monero shape in the corpus**
  ([`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc)).
  No v1 opcodes, no v1 PoW test vectors, no `if (version < N)` /
  `if (hf_version < N)` branches in the methodology or grinding
  tool.
- **Do not ship without a substrate-anchored statistical-realism
  acceptance criterion** (R1-D8). R1-D5's V1-shaped thresholds
  are unreachable per R7-D1; closing 2h without a V2 substitute
  is the same failure 2h exists to correct.
- **Do not roll out a new dependency without source-verification**
  per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc).
  If methodology choice requires e.g. `cargo-fuzz`, the
  pre-implementation round reads its actual `Cargo.toml` under
  `~/.cargo/registry/src/` and verifies API existence + property
  existence + feature-flag plumbing before any addition lands.
- **Do not invoke `07-consensus-atomic-cutovers.mdc`**. 2h is
  harness-side; criterion 1 (consensus-rule boundary) is not met;
  the standard
  [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) ≤10-commit
  / ≤5-working-day budget applies.
- **Do not reopen the §1.1 + §1.5 verifier-surface freeze to
  accommodate R1-D1 option (g)** (constructed opcode streams at
  fixed density). Option (g) is enumerated in §3 R1-D1 for
  option-set completeness so the rejection is auditable against
  the named substrate rather than re-derived at Round 1; both
  sub-paths of (g) (pipeline reversal; post-program-generation
  `data` field) either reverse the AES4R-derived program-
  generation pipeline or test the verifier against inputs
  production never produces, which contradicts §0's audit-posture
  framing of real production behavior and the §1.1 + §1.5
  verifier-crate production surface freeze. Round 1 closes (g)
  by citing this §1.7 bullet plus §1.1 + §1.5; no re-litigation
  required.

## 2. Forward-actions absorbed from prior phases

This section consolidates the forward-actions Phase 2g routed to
this round, the FOLLOWUPS V3.0 scope items, and the queued rule-26
amendments. Each item is named with its origin cite so a future
round's reviewer can trace the carry-forward without re-deriving it.

**2g→2h carry-forward inventory** (at-a-glance auditability of
the substrate-mapping per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
"Continuous discipline as inheritance prevention"):

| 2g deferral | 2h scope absorption | Status |
|---|---|---|
| R7-D1 adversarial-corpus methodology | §2.1 + §3 R1-D1 + R1-D8 | Open at Round 1 |
| R7-D2 u128 edge-case corpus | §2.2 + §3 R1-D1 by structural analogy | Open at Round 1 |
| R7-D3 §2.5 leg-3 framing restoration | §2.3 + §1.5 substrate freeze on `test-internals` | Pending Round-1 close; plan-doc edit lands at 2h impl PR close |
| R7-D4 surface-contract scope re-additions | §2.4 + §3 R1-D2 / R1-D3 / R1-D5 / R1-D6 | Open at Round 1 |
| R7-D5 substrate-derived constant validation | §2.5 + pre-implementation round Pass 4 | Discipline-amendment queued; R1-D9 disposition |
| FOLLOWUPS V3.0 scope items 1–6 | §2.6 (absorbed by §2.1–§2.4 mapping) | Closes by replacement at 2h impl PR close |

### 2.1 §3.19 R7-D1 — Adversarial-corpus methodology design + implementation

**Origin:** [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md)
§3.19 R7-D1 (lines 4600–4728).

**Specification:**

1. **V2-substrate-anchored methodology.** R1-D5's class-heaviness
   framing is V1-shaped (calibrated against `PROGRAM_SIZE = 256`);
   a V2 framing is required. Candidate shapes named for Round 1
   consideration: tail-percentile grinding (top 99.99th percentile
   of class-X density across a fixed candidate budget; reachable
   by construction); hybrid synthetic + grinded; spec-derived
   rare-path enumeration. Round 1 closes one of these or names a
   new shape with substrate evidence.
2. **Verifier-side or C-shim accessor** for the chosen methodology.
   The R7-D1 sketch (`compute_hash_opcode_streams_for_testing`
   under `cfg(feature = "test-internals")`) is **one** shape; the
   round re-derives the accessor under the new methodology's
   constraints, which may differ. Per §1.1 + §1.5, any accessor
   lands under the existing `test-internals` feature gate.
3. **Grinding tool** (if the chosen methodology grinds).
4. **Adversarial corpus contents** grinded against V2 substrate.
5. **§6 T2 (`adversarial_corpus_byte_equality`) reactivation** in
   the harness's test plan.
6. **§5.1.11 `mode_worst_case` reactivation** at the harness
   binary (replacing the §3.19 R7-D4 diagnostic-only branch).

### 2.2 §3.19 R7-D2 — R1-D6 u128 edge-case corpus (structural analogy)

**Origin:** [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md)
§3.19 R7-D2 (lines 4730–4769).

**Specification:** R1-D6's u128 / `__int128_t` edge-case data
corpus is folded into the same post-2g design round as R1-D5 by
structural analogy (same program-generation pipeline, same V2
substrate). The four `*_DATA` arrays in
[`rust/shekyl-randomx-differential/src/adversarial_corpus.rs`](../../rust/shekyl-randomx-differential/src/adversarial_corpus.rs)
(`DIV_BY_ZERO_DATA`, `SIGNED_DIV_OVERFLOW_DATA`,
`SHIFT_BY_WIDTH_DATA`, `U128_TRUNC_HIGH_DATA`) remain empty until
2h closes the methodology (R1-D1) + corpus shape (R1-D4); the
methodology Round 1 chooses for R1-D5 may absorb R1-D6 (e.g., if
spec-derived rare-path enumeration covers both classes) or treat
them as parallel sub-problems.

### 2.3 §3.19 R7-D3 — §2.5 leg-3 framing restoration

**Origin:** [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md)
§3.19 R7-D3 (lines 4771–4806) + §2.5 Round 7 amplification.

**Specification:** 2g ships with common-path leg-3 coverage; 2h
restores the rare-path leg-3 coverage so the §2.5
corpus-coverage-as-leg-3-completeness pin returns to full strength.
The restoration is a §2.5 plan-doc edit performed at 2h
implementation-PR close (per the
[`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc)
final-task discipline); 2h does not amend §2.5 ahead of the
corpus landing.

### 2.4 §3.19 R7-D4 — Surface-contract scope re-additions

**Origin:** [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md)
§3.19 R7-D4 (lines 4808–4869).

**Specification:** 2g retracted §5.1.6, §5.1.11, §5.1.19, §5.2.7,
§5.3.4, T2, T6 additions; 2h reactivates the relevant subset
(scope determined by R1-D1 + R1-D2 + R1-D3 close):

- **§5.1.6 (`adversarial_corpus.rs`)** — body lands at 2h
  implementation; module-doc-comment refreshed to cite this
  plan-doc instead of the §3.19 R7-D4 empty-scaffold disposition.
- **§5.1.11 (`mode_worst_case`)** — module lands at 2h
  implementation; CLI dispatch arm replaces the
  [`rust/shekyl-randomx-differential/src/main.rs:492-510`](../../rust/shekyl-randomx-differential/src/main.rs)
  diagnostic-only branch.
- **§5.1.19 (grinding-tool surface)** — lands only if R1-D3
  closes on "grinding tool" (alternatives: spec-derived static
  corpus has no tool; property-based testing uses an existing
  framework's harness; coverage-guided fuzzing uses
  `cargo-fuzz`'s tool directly).
- **§5.2.7 (`src/bin/grind_adversarial_corpus.rs`)** — lands only
  if R1-D3 closes on the bin-target shape (alternatives per the
  same R1-D3 close).
- **§5.3.4 (verifier `test-internals` opcode-stream accessor)** —
  lands only if R1-D2 closes on the accessor-needing methodology
  (alternatives: black-box `compute_hash` output-only methodology
  needs no accessor; C-shim instrumentation lives in the C
  reference, not the Rust verifier).

### 2.5 §3.19 R7-D5 — Substrate-derived constant validation pass (rule-26 queue)

**Origin:** [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md)
§3.19 R7-D5 (lines 4871–4903).

**Specification:** R7-D5 named "substrate-derived constant
validation pass" as the **fourth** pre-implementation discipline
class for [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
amendment, alongside R5-D1's surface-enumeration pass (the
R4-blind-spot finding), R5-D2's cross-invariant impact analysis,
R6-D2's methodology-vs-surface-contract reconciliation, and (per
the accumulated queue) R6-D3 / R6-D4. The accumulated queue spans
five discipline classes surfaced across three substrate-completeness
rounds (R5, R6, R7); the rule-26 amendment after 2h closes records
all five.

**2h's role.** 2h is the **second instance** of the discipline
(after Phase 2g). Per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
"Distributed application" and "Compounding payoff" properties,
the second instance promotes the discipline to rule-26
amendment-ready status. R1-D9 (open if Round 1 surfaces it; see
§3) names the disposition: land the rule-26 amendment alongside
the implementation PR (small, single-purpose), or formally cite
2h's pre-implementation round as the precedent the amendment
captures and defer the rule edit to a separate chore-PR.

The 2h pre-implementation round runs all five passes (the fifth
is a 2h-introduced refinement; see below for its candidate
disposition under R1-D9):

1. **Surface-enumeration pass** (R5-D1 carry-forward). Confirm any
   chosen accessor's surface matches §1.1 + §1.5 — `test-internals`
   feature gate, sole consumer is the harness crate, no production
   surface grows.
2. **Cross-invariant impact analysis** (R5-D2 carry-forward).
   Confirm the methodology, accessor, grinding tool, and corpus
   contents do not interact with the §1.2 four-crate layering, the
   §1.6 canonical-output pinning, or the §1.4 R1-D14 precondition
   in ways the Round 1 / Round 2 substrate did not account for.
3. **Methodology-vs-surface-contract reconciliation** (R6-D2
   carry-forward). Confirm R1-D2's accessor shape and R1-D3's
   grinding-tool surface are reconciled with the §5 implementation
   hand-off contract (per Round-1's eventual §5 substance).
4. **Substrate-derived constant validation pass** (R7-D5; this
   plan-doc's first explicit instance). Confirm every numeric
   threshold cited by R1-D1 (percentile cutoffs, candidate counts,
   σ values, ratio bounds, runtime budgets) is reachable against
   the V2 substrate's distribution. The pass shape: enumerate the
   substrate inputs the threshold depends on (program size, opcode
   frequency distribution, expected mean + variance under the
   substrate), compute the reachability calculus, confirm the
   threshold is achievable within the substrate's named budget.
5. **Methodology-vs-substrate consistency check** (2h-introduced;
   candidate fifth discipline class). Confirm the chosen
   methodology's *operational* substrate exists and behaves as the
   methodology assumes, distinct from Pass 4's *numeric* substrate
   validation. For tail-percentile grinding: confirm the chosen
   percentile is reachable in the chosen budget against the actual
   V2 opcode-frequency distribution (`RANDOMX_FREQ_*` table in
   `randomx-v2-sys`'s vendored `configuration.h`, read at source).
   For coverage-guided fuzzing: confirm the coverage metric (line /
   branch / edge) is actually reported by the chosen fuzzer against
   the verifier's instruction code (read the fuzzer's docs at
   source). For spec-derived rare-path enumeration: confirm the
   spec actually documents the rare paths the methodology depends
   on (read the spec at source). Pass 5 is the discipline that
   would have caught the original R1-D5 failure mode at original
   methodology-selection time; whether it counts as a distinct
   fifth discipline class or a refinement of Pass 4 is a
   substrate question Round 1 / pre-implementation closes per R1-D9.

### 2.6 FOLLOWUPS V3.0 scope items 1–6

**Origin:** [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) lines 84–158
("Post-2g adversarial-corpus methodology + implementation").

The FOLLOWUPS entry's scope items are absorbed by §2.1 + §2.2 +
§2.3 + §2.4 above. The entry's **closure shape** is "the post-2g
round completes and lands the adversarial corpus, at which point
R7-D1 closes by replacement" — same close shape as 2h's
implementation PR lands. The FOLLOWUPS entry closes by replacement
at 2h close per [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc).

The entry's **escalation reopening criterion** (per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
priority-1 security override): a Phase-2 audit finding that
surfaces a rare-path divergence at genesis the random +
canonical-output corpus missed forces 2h ahead of its V3.0 target
version. If invoked, 2h does not stall on Round-2 / Round-N
substantive-content thoroughness — Round 1 closes against the
minimum-substrate-anchored methodology and the implementation
ships against an explicit "audit-trigger expedited" disposition;
the §2.5 leg-3 framing restoration follows in the post-audit
hardening cycle.

## 3. Round 1 decision points (open; not closed at Round 0)

Round 0 enumerates the decision points; Round 1 closes them. Each
entry below names the option set, the substrate-anchored criteria
Round 1 uses to choose, the Round-0 default-expectation sketch
(the reviewer's null-hypothesis disposition before substrate
evidence shifts it), and the reopen-criterion sketch per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).

**Closing any of these at Round 0 collapses the substrate-anchored
review the multi-round discipline exists to deliver.** Round 1+
performs the closure with full Round-1 substrate context.

**Procedural sequencing for Round 1: close R1-D8 first.** R1-D8
(statistical-realism acceptance criterion) is enumerated eighth
in this list for thematic ordering — methodology / accessor /
tooling / format / mode / tests / CI / criterion — but is
*structurally* the load-bearing decision per §3.19 R7-D1. R1-D1
through R1-D7 each evaluate against a "statistical realism"
criterion that R1-D8 defines; closing R1-D1's methodology before
R1-D8's acceptance criterion reproduces the same failure mode
R7-D1 surfaced (a methodology shape chosen against thresholds
that turn out to be unreachable on V2 substrate). Round 1
therefore works R1-D8 first; R1-D1's option evaluation explicitly
cites R1-D8's chosen acceptance criterion when weighing each
option's statistical-realism property; R1-D2 through R1-D7 fall
out of the R1-D8 + R1-D1 close in the order their dependencies
allow. The R1-D8-first sequencing is a Round 1 procedural anchor
(not a Round 0 closure of R1-D8) — Round 1's substrate-anchored
review still closes R1-D8 against its option set, but does so
before R1-D1 rather than after.

### R1-D1 — V2-substrate-anchored adversarial-corpus methodology

**Option set (named for Round 1; not closed):**

- **(a) Tail-percentile grinding.** Define "adversarial" as the
  top 99.99th percentile (or analogous reachable threshold) of
  class-X density across a fixed candidate budget, rather than
  against a fixed absolute threshold. Reachable by construction —
  the budget produces the percentile by definition. Named in
  §3.19 R7-D1's resolution sketch.
- **(b) Hybrid synthetic + grinded construction.** Grind for
  class density at reachable thresholds, then post-process by
  direct opcode synthesis where the spec-derivability property
  is preservable. Named in §3.19 R7-D1's resolution sketch.
- **(c) Spec-derived rare-path enumeration.** Extract the spec's
  documented rare paths (if any) as the adversarial corpus's
  anchor set, with grinding only for class-density supplements.
  Named in §3.19 R7-D1's resolution sketch.
- **(d) Coverage-guided fuzzing.** Use `cargo-fuzz` / `bolero` /
  `honggfuzz` against `compute_hash` (Rust + C side) as black
  boxes; the fuzzer's coverage metric drives corpus selection.
  Open per Round 0 — not named in §3.19 R7-D1 but in the
  candidate set per the prompt.
- **(e) Property-based testing.** Use `proptest` / `quickcheck`
  with custom shrinkers + generators that target opcode-class
  density or u128 edge cases. Open per Round 0.
- **(f) Mutation-derived corpora.** Cross-pollinate from
  `cargo-mutants` (already weekly in
  [`.github/workflows/randomx-v2-differential.yml`](../../.github/workflows/randomx-v2-differential.yml)
  per Phase 2g) — derive adversarial inputs by feeding mutated
  intermediate state through the harness. Open per Round 0.
- **(g) Constructed opcode streams at fixed density.** Bypass
  grinding entirely; *construct* opcode byte streams that hit
  each opcode class at fixed density. Requires reversing the
  program-generation pipeline to find seedhashes whose generated
  programs match the constructed streams (or accepting that the
  corpus's `data` field is post-program-generation, which changes
  the verifier surface). **Option (g) is enumerated for option-set
  completeness but is closed by §1.7 + §1.1 + §1.5 frozen
  substrate** — both sub-paths (pipeline reversal; post-program-
  generation `data`) reopen the verifier-crate production surface
  freeze (§1.1) or bypass AES4R-derived program generation, which
  tests the verifier against inputs production never produces and
  contradicts §0's audit-posture framing of real production
  behavior. Included so Round 1's rejection is auditable against
  the named substrate rather than re-derived; Round 1 closes (g)
  by citing §1.7 + §1.1 + §1.5 rather than re-litigating the
  rejection.

**Criteria (substrate-anchored):**

1. **Statistical realism (load-bearing per R7-D1).** The chosen
   methodology must surface a corpus that is **reachable in a
   named compute budget** with substrate evidence. R7-D1's σ-gap
   analysis (per-class σ-gaps from 6.8σ to ~125σ against V1-shaped
   thresholds) is the substrate; the methodology either (i) makes
   the thresholds reachable (tail-percentile grinding), (ii)
   avoids needing class-density thresholds (spec-derived;
   coverage-guided), or (iii) names a substrate-anchored substitute
   criterion (R1-D8).
2. **Verifier surface impact.** Methodology choice constrains
   R1-D2 (accessor). Black-box methodologies (coverage-guided
   fuzzing, property-based testing against `compute_hash` output
   alone) need no new accessor; class-density-aware methodologies
   need either the R7-D1 `test-internals` opcode-stream accessor
   or an equivalent C-shim instrumentation.
3. **Audit-posture restoration completeness** (per §2.3 R7-D3 +
   §2.5). The methodology's coverage must materially address
   rare-path leg-3 coverage. "Methodology shipped" is not
   sufficient if its catch capacity does not exceed what the
   common-path random corpus already delivers.
4. **Dependency cost** per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc).
   Methodologies that add a new workspace dependency
   (`cargo-fuzz`, `bolero`, `proptest`, `arbitrary`, etc.)
   require pre-implementation source-verification; reuse of
   existing workspace dependencies preferred where capability
   is equivalent.
5. **Post-genesis maintenance cost.** Per
   [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc),
   the methodology lives forever once the corpus commits;
   methodologies whose regeneration cost grows superlinearly
   with V2-substrate changes (fork pin bumps, opcode-frequency
   amendments at future hard forks) are downweighted.

**Round-0 default-expectation sketch:** R1-D1 closes on (a)
tail-percentile grinding **or** (c) spec-derived rare-path
enumeration, with (a) more likely on
[`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc)
specification-first grounds (the methodology is reviewable as a
percentile-cutoff specification rather than as a corpus dump).
Coverage-guided fuzzing (d) is a strong alternative if Round 1
surfaces that the V2 substrate makes class-density-aware grinding
infeasible at any threshold; in that case fuzzing's coverage
metric is the substrate-anchored substitute for class density.

**Reopen-criterion sketch:** Reopen R1-D1 if (i) the
pre-implementation substrate-derived constant validation pass
(per §2.5 R7-D5) surfaces that the chosen methodology's numeric
thresholds are not reachable against V2 substrate (the same
failure shape that reopened R1-D5); (ii) a Phase-2 audit finding
surfaces a rare-path divergence at genesis the chosen methodology
does not catch; (iii) the post-2h round-trip discovers that the
methodology's class taxonomy does not match the V2 opcode
distribution's natural clustering (substrate-revealed taxonomy
mismatch). Re-evaluation shape: Round 2 of the implementation PR
if the finding surfaces during implementation; a new design round
on the same plan-doc if the finding surfaces post-implementation.

### R1-D2 — Verifier-side or C-shim accessor for the methodology

**Option set:**

- **(a) `compute_hash_opcode_streams_for_testing` under `cfg(feature = "test-internals")`.**
  Default sketch per §3.19 R7-D1; surface already partially
  staged at [`rust/shekyl-pow-randomx/src/lib.rs:204-205`](../../rust/shekyl-pow-randomx/src/lib.rs)
  (the `PROGRAM_SIZE` + `RANDOMX_PROGRAM_COUNT` promotions
  landed alongside R5-D1; the `compute_hash_opcode_streams_for_testing`
  re-export name is currently referenced in `lib.rs` but the
  underlying `vm.rs` function may or may not yet have a body —
  Round 1 verifies at source).
- **(b) Black-box shape that needs no new accessor.** R1-D1
  closes on a methodology operating against `compute_hash`
  output alone (coverage-guided fuzzing or property-based
  testing against the hash); no verifier-side surface grows.
- **(c) C-shim-only accessor.** Instrument the C reference (via
  the existing `randomx-v2-sys` crate's bindings expansion or a
  new `extern "C"` declaration) rather than the Rust verifier.
  Trade-off: keeps the Rust verifier's `test-internals` surface
  minimal; requires the methodology to operate on the C side
  (which is acceptable because the C reference's behavior is the
  audit anchor per §2.5 leg 2).
- **(d) Callback hook.** A test-time injection point where the
  harness supplies a closure that is invoked after each
  `init_program`. Defers the accessor's data shape to the
  caller; verifier surface is a function-typed `pub` item
  under `test-internals`.

**Criteria:**

1. **§1.1 + §1.5 frozen substrate compatibility.** Any
   verifier-side accessor lands under the `test-internals` gate
   with R5-D1 discipline; no production surface grows.
2. **Methodology coupling** per R1-D1's close. Methodologies
   needing opcode-stream visibility require (a) or (c) or (d);
   black-box methodologies are compatible with (b).
3. **Drift anchoring.** Option (a)'s duplicated
   `compute_hash_inner` body needs a cross-check `#[test]`
   asserting hash equality between the test-internals path and
   production hash; the drift surface is the audit-attention
   cost.
4. **Pre-flight surface-enumeration pass discipline** per
   §2.5 R7-D5 / R5-D1. The pre-implementation round confirms
   the accessor's actual signature against the verifier source
   before any implementation lands.

**Round-0 default-expectation sketch:** R1-D2 closes on (a) if
R1-D1 closes on (a) or (b) or (g); on (b) if R1-D1 closes on (d)
or (e); on (c) if R1-D1 closes on a methodology whose accessor
needs are C-reference-anchored (e.g., spec-derived rare-path
enumeration where the spec's "rare path" is defined against the
C reference's behavior).

**Reopen-criterion sketch:** Reopen R1-D2 if (i) R1-D1's
methodology shape changes (mechanical reopening); (ii) the
pre-implementation surface-enumeration pass surfaces that the
verifier source does not support the chosen accessor's signature
without a deeper reshape than the `test-internals` gate's
discipline allows; (iii) a Phase-2 audit finding requires the
methodology to inspect intermediate state the chosen accessor
does not expose.

### R1-D3 — Grinding/construction tool location and shape

**Option set:**

- **(a) `rust/shekyl-randomx-differential/src/bin/grind_adversarial_corpus.rs`.**
  Default per FOLLOWUPS V3.0 entry scope item 3. Bin-target
  alongside the existing `gen_canonical_outputs.rs`; consumes
  the same `randomx-v2-sys` + `shekyl-pow-randomx` (with
  `test-internals`) substrate.
- **(b) `[lib]` target consumed by `gen_canonical_outputs.rs`-style tooling.**
  Module under
  [`rust/shekyl-randomx-differential/src/`](../../rust/shekyl-randomx-differential/src/)
  with no bin entry point; orchestration happens from the
  existing bin or from a test target.
- **(c) Standalone crate.** New workspace member alongside
  `shekyl-randomx-differential`. Higher cost per
  [`25-rust-architecture.mdc`](../../.cursor/rules/25-rust-architecture.mdc).
- **(d) Integration test.** Lives under
  [`rust/shekyl-randomx-differential/tests/`](../../rust/shekyl-randomx-differential/tests/);
  runs at `cargo test` time; no separate binary.
- **(e) No tool.** R1-D1 closes on a methodology whose corpus is
  spec-derived static enumeration with no grinding step (e.g.,
  rare-path enumeration extracted by hand from the spec, with
  Round 1 + Round 2 review supplying the substrate-anchored
  audit).

**Criteria:**

1. **Methodology coupling** per R1-D1's close. Grinding-heavy
   methodologies need (a) or (b); spec-derived methodologies are
   compatible with (e); property-based testing fits (d).
2. **Reproducibility discipline** per §1.6. The tool's
   regeneration shape mirrors the `gen-canonical-outputs`
   regeneration discipline: invoked via a documented command
   line, reviewed at output time, committed as bytes (not
   regenerated in CI).
3. **CI cost.** A bin-target grinding tool that runs in CI per-PR
   needs a runtime budget compatible with Phase 2g §9.3's
   cadence-slot constraints.
4. **Pattern-C exemption.** §1.2's four-crate layering puts any
   new C-ABI surface in `randomx-v2-sys`; (c) standalone-crate
   shape inherits this constraint.

**Round-0 default-expectation sketch:** R1-D3 closes on (a) per
the FOLLOWUPS V3.0 default sketch, **or** on (e) if R1-D1 closes
on spec-derived rare-path enumeration. (b) is the conservative
fallback if Round 1 surfaces that the bin-target's runtime budget
is incompatible with any cadence slot.

**Reopen-criterion sketch:** Reopen R1-D3 if (i) the
pre-implementation corpus-size budget verification surfaces that
the tool's runtime exceeds the chosen CI cadence slot (R1-D7);
(ii) R1-D1's methodology changes shape; (iii) a future hard-fork
amendment to V2's opcode-frequency distribution requires the tool
to be re-run, and the regeneration discipline surfaces that the
tool's encapsulation is the wrong shape for the regeneration
workflow.

### R1-D4 — Adversarial corpus on-disk format

**Option set:**

- **(a) Hex bytes committed in `adversarial_corpus.rs`.**
  Default per FOLLOWUPS V3.0 entry scope item 4. Single Rust
  source file; per-class arrays; classification tag embedded as
  the array name (e.g., `CFROUND_SEEDHASHES`) per the historical
  R1-D5 framing at
  [`rust/shekyl-randomx-differential/src/adversarial_corpus.rs:91-99`](../../rust/shekyl-randomx-differential/src/adversarial_corpus.rs).
- **(b) Structured format.** One entry per `(seedhash, data)`
  pair with classification tag, optional comment, optional
  provenance metadata. Single Rust file or a separate fixture
  file (binary or JSON or hex with a delimiter).
- **(c) Separate files per class.** One `.rs` file or fixture
  file per class; reduces the per-file diff size at the cost of
  multiple files to keep in sync.
- **(d) Binary fixture file.** `.bin` blob under
  [`rust/shekyl-randomx-differential/tests/fixtures/`](../../rust/shekyl-randomx-differential/tests/)
  or analogous; loaded at runtime; not reviewable as text.

**Criteria:**

1. **Review surface.** The corpus's bytes are the audit
   evidence; the format must be reviewable as text per
   [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc)
   scope discipline. (d) is downweighted for this reason.
2. **R1-D1 methodology coupling.** Spec-derived methodologies
   benefit from per-entry comments (provenance) → (b) preferred;
   grinded methodologies' provenance is "the grinding tool
   produced these bytes from seed X" → (a) is sufficient.
3. **Tamper-detection compatibility** with §1.6's
   `ADVERSARIAL_CORPUS_SHA256` pin. Any format change must
   preserve a stable canonical hashing shape; (b) and (c)
   require explicit serialization order to keep the SHA-256
   stable.
4. **R1-D6 (u128 edge-case) integration.** The four `*_DATA`
   arrays in the existing scaffold are structurally similar to
   the five `*_SEEDHASHES` arrays; format choice should not
   bifurcate the two halves of the corpus unnecessarily.

**Round-0 default-expectation sketch:** R1-D4 closes on (a)
unchanged from the existing scaffold, with class taxonomy
refresh per R1-D1's V2-substrate-anchored methodology — i.e.,
the per-class array structure stays the same, but the array
names and per-class membership criteria change. (b) is the
likely close if R1-D1 closes on spec-derived rare-path
enumeration (where per-entry provenance is reviewer-facing).

**Reopen-criterion sketch:** Reopen R1-D4 if (i) the
implementation PR's diff size for the corpus file exceeds the
≤10-commit / ≤5-working-day budget per
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2
(forces (c) splits-per-class); (ii) R1-D1's methodology
introduces a new classification dimension the chosen format
cannot represent without ambiguity; (iii) post-2h corpus
regeneration encounters review-bandwidth limits the chosen
format does not amortize.

### R1-D5 — `mode_worst_case` implementation surface (reactivates §5.1.11)

**Option set:**

- **(a) Rust/C ratio over the adversarial corpus.** The obvious
  shape per the FOLLOWUPS V3.0 entry scope item 5. For each
  `(seedhash, data)` in the adversarial corpus, time both
  paths and report the ratio. Release-gate cadence; ≤5.0×
  numeric bound (per Phase 2g R1-D8 close, deferred per §3.19
  R7-D4).
- **(b) Adversarial corpus per-hash latency only (no C-ratio).**
  Mode reports Rust per-hash latency over the adversarial
  corpus; the worst-case-ness lives in the corpus's adversarial
  shape, not in the C comparison. Lower implementation cost;
  loses the "ratio drift over time" failure detection.
- **(c) Combined (a) + (b) in one mode.** Mode reports both Rust
  per-hash latency and Rust/C ratio. Higher reporting volume;
  higher CI runtime.
- **(d) Worst-case ratio over random corpus tail.** Mode runs
  the existing `corpus_random` at increased size, reports the
  Nth-percentile (e.g., p99.9) ratio. Bypasses the adversarial
  corpus entirely; restores the random-corpus-only shape Phase
  2g shipped with, augmented by a percentile-aware report.

**Criteria:**

1. **R1-D1 methodology coupling.** If R1-D1 closes on a
   methodology that produces an adversarial corpus, (a) or (c)
   is natural. If R1-D1 closes on coverage-guided fuzzing or
   property-based testing (no static corpus), (d) is the
   closure.
2. **CI cadence compatibility** per R1-D7 close. Release-gate
   cadence is the default per Phase 2g §9.3 + R1-D8 historical
   close.
3. **Substrate-anchored numeric realism check** for the ≤5.0×
   ratio bound. The R1-D8 historical close did not establish
   the ≤5.0× bound's V2-substrate reachability; Round 1
   verifies the bound's substrate-anchored realism per §2.5
   R7-D5 (the substrate-derived constant validation pass).
4. **Failure-output integration** per Phase 2g §5.1.14's
   structured-JSON failure schema (M4). The worst-case mode's
   failure output extends the existing schema; no new schema
   surface.

**Round-0 default-expectation sketch:** R1-D5 closes on (a) per
the FOLLOWUPS V3.0 default sketch, with the ≤5.0× ratio bound
substrate-validated at R1-D8. If R1-D8 surfaces that ≤5.0× is
unreachable against the adversarial corpus's actual ratio
distribution, R1-D5 reopens to (c) (report-both) with the bound
amended.

**Reopen-criterion sketch:** Reopen R1-D5 if (i) R1-D8's
substrate-derived constant validation pass surfaces that ≤5.0×
is unreachable or trivially-reachable against V2 substrate; (ii)
R1-D1's methodology produces a corpus structurally incompatible
with worst-case ratio measurement (e.g., property-based testing
where each test run produces a fresh corpus); (iii) the
pre-implementation runtime-budget verification surfaces that
release-gate cadence is incompatible with the corpus size R1-D4
produces.

### R1-D6 — Test reactivation cadence (T2 + T6)

**Option set:**

- **(a) T2 per-PR, T6 release-gate.** Default per the prompt's
  framing: T2 (`adversarial_corpus_byte_equality`) is plausibly
  per-PR if the corpus fits the per-PR runtime budget; T6
  (`worst_case_ratio`) stays release-gate per Phase 2g §9.3.
- **(b) T2 nightly, T6 release-gate.** Conservative cadence if
  the corpus's per-PR runtime budget is exceeded.
- **(c) T2 release-gate, T6 release-gate.** Most conservative;
  T2 catches divergences only at release-gate cadence,
  matching the worst-case-ratio cadence.
- **(d) T2 per-PR with corpus subsetting.** Run a deterministic
  subset of the adversarial corpus per-PR (the `random_corpus`
  pattern from Phase 2g §6.1 — per-PR sizing 16×8 subsets the
  nightly 32×32 sizing); full corpus runs nightly + release-gate.

**Criteria:**

1. **R1-D4 corpus size + R1-D1 methodology runtime.** Per-PR
   cadence requires the corpus runtime + harness overhead fits
   within the existing CI per-PR runtime budget; the Phase 2g
   per-PR random-corpus run takes single-digit minutes against
   16×8 sizing.
2. **R1-D5 worst-case mode cadence coupling.** T6's cadence
   matches `mode_worst_case`'s cadence per R1-D5 close.
3. **Catch-cadence vs. runtime tradeoff.** Per-PR cadence
   maximizes catch capacity but raises the per-PR runtime; the
   pre-implementation budget verification (§2.5 R7-D5) closes
   the tradeoff against the actual corpus size.

**Round-0 default-expectation sketch:** R1-D6 closes on (a) if
the corpus fits per-PR; on (d) with corpus subsetting if the
full corpus is per-PR-infeasible. Phase 2g §9.3 + §6.1's
random-corpus subsetting precedent is the substrate.

**Reopen-criterion sketch:** Reopen R1-D6 if (i) the
pre-implementation budget verification surfaces that the chosen
cadence is per-PR-infeasible (cadence demotion); (ii) a
post-implementation Phase-2 audit surfaces that the cadence
missed a divergence per-PR cadence would have caught (cadence
promotion); (iii) the corpus subsetting in (d) introduces a
deterministic-subset selection bias that the methodology's
catch-capacity calculus did not account for.

### R1-D7 — CI cadence + workflow placement

**Option set:**

- **(a) Per-PR + nightly + release-gate (full triad).** Match
  Phase 2g's three-tier cadence. T2 + T6 entries inserted into
  existing slots in [`.github/workflows/randomx-v2-differential.yml`](../../.github/workflows/randomx-v2-differential.yml).
- **(b) Nightly + release-gate only.** No per-PR adversarial
  coverage; the per-PR slot stays at Phase 2g's random-corpus
  shape.
- **(c) Release-gate only.** Most conservative; both T2 and T6
  run at release-gate.
- **(d) New workflow file.** Separate adversarial-corpus
  workflow; orthogonal CI surface. Higher review cost; cleaner
  separation.

**Criteria:**

1. **R1-D6 cadence close.** Workflow placement follows R1-D6's
   T2/T6 cadence.
2. **`continue-on-error` discipline** per Phase 2g `randomx-v2-differential.yml`'s
   current shape (runtime modes are `continue-on-error: true`
   until the V3.0 `compute_hash` divergence is fixed). 2h
   inherits this discipline; new adversarial coverage may
   need the same gating until the divergence lands.
3. **Workflow file proliferation cost.** New workflow files
   add review surface; reuse of the existing file is preferred
   per [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc).

**Round-0 default-expectation sketch:** R1-D7 closes on (a) per
Phase 2g precedent; T2 + T6 entries added to the existing
workflow file's existing cadence slots.

**Reopen-criterion sketch:** Reopen R1-D7 if (i) the
pre-implementation runtime-budget verification surfaces that
the cadence is incompatible with existing slot budgets; (ii)
the `continue-on-error` discipline forces a cadence demotion
until the V3.0 `compute_hash` divergence lands; (iii) a
post-implementation maintenance event (CI-runner cost shift,
GitHub Actions usage cap, etc.) requires workflow reshape.

### R1-D8 — Statistical-realism acceptance criterion (load-bearing per §3.19 R7-D1)

**Option set:**

- **(a) V2-substrate-anchored percentile criterion.** Define
  acceptance as "the corpus's class-X density distribution
  achieves the top P-th percentile of the random-grinding
  distribution at budget B." Substrate-anchored; reachable by
  construction at the chosen budget.
- **(b) V2-substrate-anchored absolute criterion.** Replace
  R1-D5's V1-shaped ≥40% / ≥60% thresholds with V2-substrate-anchored
  absolute counts derived from the V2 opcode frequency
  distribution. Reachable subject to substrate calculation.
- **(c) Spec-derived criterion.** Acceptance is "every spec-named
  rare path is exercised by at least one corpus entry";
  no statistical thresholds.
- **(d) Coverage-guided criterion.** Acceptance is "the corpus
  achieves coverage threshold T against the verifier crate per
  `cargo-tarpaulin` / `llvm-cov` instrumentation."
- **(e) Property-based criterion.** Acceptance is "the corpus
  passes property assertions P₁..Pₙ that encode the
  spec-derived rare-path properties as testable predicates."

**Criteria:**

1. **R1-D1 methodology coupling.** Each option pairs naturally
   with a subset of R1-D1's options: (a)/(b) with grinding;
   (c) with spec-derived enumeration; (d) with coverage-guided
   fuzzing; (e) with property-based testing.
2. **Substrate-anchored reachability.** Per §3.19 R7-D5's
   substrate-derived constant validation pass, every numeric
   threshold the criterion cites is verified against the V2
   substrate's reachability calculus.
3. **Audit reviewability.** The criterion is a reviewable
   substrate claim; "the corpus is adversarial because X" must
   be a one-paragraph specification a reviewer can verify
   without re-running the grinding tool.
4. **Load-bearing per R7-D1.** Closing 2h without R1-D8 is the
   same failure 2h exists to correct.

**Round-0 default-expectation sketch:** R1-D8 closes on (a) or
(b) per R1-D1's grinding-class default; on (c) if R1-D1 closes on
spec-derived rare-path enumeration. The exact percentile or
absolute count is the pre-implementation substrate-derived
constant validation pass's deliverable, not Round 1's.

**Reopen-criterion sketch:** Reopen R1-D8 if (i) the
pre-implementation substrate-derived constant validation pass
surfaces the chosen threshold is unreachable (mechanical
reopening per the same shape that produced R7-D1); (ii) R1-D1's
methodology changes shape (mechanical reopening); (iii) a
post-implementation audit surfaces that the chosen criterion
admits a corpus that is not materially adversarial (the §4 T-A1
silent-disposition-degradation failure mode).

### R1-D9 (open if Round 1 surfaces it) — Rule-26 amendment shape

**Option set:**

- **(a) Land the rule-26 amendment alongside the implementation PR.**
  Small, single-purpose chore-PR-shaped edit to
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
  recording all five queued discipline classes (surface
  enumeration, cross-invariant impact analysis, methodology-vs-
  surface-contract reconciliation, substrate-derived constant
  validation, plus the R6-D3/R6-D4 carry-forwards if any). The
  edit lands in the implementation PR's final commit per
  [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc).
- **(b) Land the rule-26 amendment in a separate chore-PR after 2h impl close.**
  Cite 2h's pre-implementation round as the second instance
  in the rule's "Where the pattern appears" enumeration;
  the chore-PR's scope is the rule edit only.
- **(c) Cite 2h as precedent; defer the rule edit further.**
  Both Phase 2g and 2h cite the discipline classes as forward
  actions in their respective plan-docs; the rule itself isn't
  amended until a third instance materializes. Lower scope cost
  per PR; higher carry-cost across plan-docs.

**Criteria:**

1. **Discipline-application cadence** per
   [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
   "Continuous discipline as inheritance prevention" — the
   discipline's payoff compounds with each PR's small
   application; relaxing the rule-amendment cadence is the
   "audits-are-clean-so-compress" anti-pattern.
2. **PR scope discipline** per
   [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc) +
   [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc).
   Folding the rule edit into the implementation PR (option (a))
   risks scope expansion; the separate chore-PR (option (b))
   is the canonical "while we're here is the enemy" disposition.

**Round-0 default-expectation sketch:** R1-D9 closes on (b) — the
implementation PR carries the methodology + accessor + corpus +
mode reactivation + test reactivation + CI cadence + canonical
pinning + §2.5 leg-3 restoration + plan-doc closure; the rule-26
amendment is a separate single-purpose chore-PR that cites 2h's
pre-implementation round as the second instance promoting the
discipline.

**Opening criterion (mechanical):** R1-D9 opens at Round 1 if
**either** (a) **a third confirmed instance of substrate-derived
constant gaps surfaces during 2h's pre-implementation round** —
R5-D1 was the first instance, R7-D5 named the discipline class,
2h's pre-implementation pass would be the third instance and the
pattern is triple-confirmed (the rule-26 amendment is still
warranted at two instances per prior conversation, but a third
makes the amendment urgent rather than queued); **or** (b) **a
new pre-implementation discipline class emerges during 2h that
doesn't fit the existing four/five categories** (surface
enumeration / cross-invariant impact analysis / methodology-vs-
surface-contract reconciliation / substrate-derived constant
validation / methodology-vs-substrate consistency — see §2.5 +
§0). A new class is a substrate-amendment trigger that the
rule-26 amendment must cover, and waiting for a separate chore-PR
risks the class being forgotten between 2h and the amendment PR.
Otherwise R1-D9 defers to a forward-action for a future
discipline-promotion PR; the queue stays as-is and the default
disposition is (b) (separate chore-PR after 2h close).

**Reopen-criterion sketch:** Reopen R1-D9 after Round 1 closure
if Round 2 / pre-implementation rounds surface either trigger
(a) or (b) above retroactively — the opening criterion is
mechanical at Round 1 but the substrate evidence may arrive
later (substrate-derived constant gaps surface during the
pre-implementation pass; new discipline class surfaces during
the implementation PR's surface-enumeration audit). Re-evaluation
shape: amend R1-D9's closure in §11's round-history table and
land the rule-26 amendment in the implementation PR's final
commit or as a follow-on chore-PR per the trigger's timing.

## 4. Threat model

**Reserved for Round-2 close.** Per Phase 2g §4.4 / §4.5 / §4.6
precedent, Round 2 closes the passive + active threat surfaces
under the new corpus methodology. Round-0 expectations (named
here so Round 2's framing is anchored, not closed):

- **Passive surface.** T-A1 (silent-disposition-degradation;
  per Phase 2g §4.4) extends to the adversarial corpus's
  tamper-detection — the corpus's `ADVERSARIAL_CORPUS_SHA256`
  pin per §1.6 catches tamper across this round's ship; the
  T10 (`adversarial_corpus_hash_pin`) test reactivates at
  implementation alongside T2 + T6.
- **Active surface.** T-A2 (corpus-tamper) extends to the
  adversarial entries; the §3.18 R6 cluster M1 canonical-output
  property (`rust == canonical && c == canonical`) extends to
  the adversarial canonical hashes (per §1.6 close).
- **§35-secure-memory.mdc / §36-secret-locality.mdc N/A
  confirmation.** Round 2 confirms 2h does not introduce
  secret-bearing intermediate state per Phase 2c §5.11.4
  (cache memory public-input-only). The methodology, accessor,
  grinding tool, and corpus contents are all public-input
  derivations; no secret material flows through 2h's
  substrate.

Round 2 closes against Round-1 substrate (R1-D1 through R1-D8
closes). The passive + active threat surfaces reshape as
R1-D1's methodology choice constrains the corpus's tamper
surface and the accessor's leak surface.

## 5. Implementation hand-off contract

**Reserved for Round-1 / Round-2 initial substance.** Per Phase
2g §5 precedent, this section pins per-file deliverables,
function signatures, error taxonomy, and pre-implementation gate
items. Round-1 substantive content arrives once R1-D1 through
R1-D8 close.

Round-0 pre-bindings (anchored, not closed):

- **§5.1.6 `adversarial_corpus.rs`** — body refresh per R1-D1 +
  R1-D4 close; module-doc-comment refreshed to cite this
  plan-doc rather than the §3.19 R7-D4 empty-scaffold disposition.
- **§5.1.11 `mode_worst_case`** — module lands per R1-D5 close;
  CLI dispatch arm replaces
  [`rust/shekyl-randomx-differential/src/main.rs:492-510`](../../rust/shekyl-randomx-differential/src/main.rs).
- **§5.1.19 grinding-tool surface** — lands only if R1-D3
  closes on the bin-target shape.
- **§5.2.7 `src/bin/grind_adversarial_corpus.rs`** — lands only
  if R1-D3 closes on the bin-target shape.
- **§5.3.4 verifier `test-internals` accessor (if any)** — lands
  only if R1-D2 closes on the accessor-needing methodology.

## 6. Test plan

**Reserved for Round-1 initial substance.** Round-0 pre-bindings:

- **T2 (`adversarial_corpus_byte_equality`)** — reactivates per
  R1-D6 close.
- **T6 (`worst_case_ratio`)** — reactivates per R1-D6 close.
- **T10 (`adversarial_corpus_hash_pin`)** — reactivates per
  §1.6 + R1-D4 close (corpus tamper-detection over the
  populated arrays, replacing the §3.19 R7-D4 empty-scaffold
  pin).
- **New T# rows** — R1-D1's methodology may add new test rows
  for methodology-specific assertions (e.g., property-based
  invariants if R1-D1 closes on (e); coverage-threshold
  assertions if R1-D1 closes on (d)). Named at Round 1 close;
  Round 2 reviews against the threat surface.

## 7. Generator / fixtures plan

**Reserved for Round-1 initial substance.** Corpus-generation
pipeline placeholder. Round-0 pre-bindings:

- **`gen-canonical-outputs` extension** — per §1.6 close, the
  adversarial corpus's canonical hashes are produced by the
  same `gen-canonical-outputs` binary's regeneration discipline,
  extending `CANONICAL_RANDOM_HASHES` with the adversarial
  entries (or co-resident `CANONICAL_ADVERSARIAL_HASHES` array
  if Round 1 surfaces a structural reason to split).
- **Grinding tool (if any) per R1-D3 close** — invocation shape,
  output format, runtime budget per §2.5 R7-D5 substrate-derived
  constant validation pass.
- **Regeneration discipline** — separate PR with
  audit-against-actual-code verification per §1.6 + §3.18 R6
  cluster.

## 8. Commit table

**Reserved for Round-N close** within the
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule-2
≤10-commit / ≤5-working-day budget. Per §1.7,
[`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
is **not invoked** — 2h is harness-side; criterion 1 (consensus-rule
boundary) is not met.

Round-0 commit-budget expectation (named for Round-N anchoring,
not closed): one commit per substantive deliverable
(methodology + accessor; grinding tool (if any); corpus
contents; `mode_worst_case` reactivation; T2/T6 reactivation;
CI cadence; canonical pinning; §2.5 leg-3 restoration; plan-doc
closure). Total ≤10 commits; aggregate ≤5 working days.

## 9. CI gates

**Reserved for Round-1 initial substance.** Round-0 pre-bindings:

- **2h adds:** T2 + T6 entries per R1-D6 + R1-D7 close; per the
  Phase 2g §9.3 precedent's `continue-on-error` discipline
  until the V3.0 `compute_hash` divergence lands.
- **2h inherits unchanged:** the structural-validate per-PR
  merge-blocking job; the cargo-mutants weekly job; the
  `randomx-v2-differential.yml` workflow's existing structural
  layout.

## 10. Forward path

**Reserved for Round-N close.** Round-0 pre-bindings:

- **Hand-off to Phase 3a.** Per-PR per-hash latency CI gate
  (≤3.0× ratio) activates at Phase 3a when the FFI shim makes
  regressions reachable; 2h's `mode_worst_case` per R1-D5 close
  is consumed at Phase 3a's release-gate suite.
- **Release-gate suite.** `mode_worst_case` runs at release-gate
  cadence per R1-D5 + R1-D7 close.
- **Rule-26 amendment.** Lands per R1-D9 close (likely separate
  chore-PR per the Round-0 default-expectation sketch).
- **§2.5 leg-3 framing restoration.** Plan-doc edit at 2h
  implementation-PR close per
  [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc).
- **FOLLOWUPS V3.0 entry closure.** "Post-2g adversarial-corpus
  methodology + implementation" closes by replacement at 2h
  close per
  [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)
  "FOLLOWUPS.md is not a graveyard."

## 11. Round history

### Round 0 — scaffold (this PR)

**Scope.** Substrate capture only. Front-matter, §0 framing,
§1 frozen substrate (six items with cite paths covering the
Phase 2F R3, Phase 2g R5-D1, Phase 2g R6, and Phase 2g R7
landings), §2 forward-actions absorbed (§3.19 R7-D1 / R7-D2 /
R7-D3 / R7-D4 / R7-D5 specifications, FOLLOWUPS V3.0 scope
items 1–6, and the rule-26 surface-enumeration-pass and
substrate-derived constant validation pass forward-actions),
§3 R1-D1..R1-D8 decision points enumerated with option sets,
criteria, Round-0 default-expectation sketches, and
reopen-criterion sketches per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc),
plus optional R1-D9 (rule-26 amendment shape), §4–§10
placeholders reserved for Round-N substantive content, and §11
Round 0 history row.

**What this round pins.**

- The six frozen substrate items in §1 (verifier surface,
  four-crate layering, mode-dispatch surface, R1-D14
  precondition, `test-internals` carve-out, canonical-output
  pinning) — each with file:line cite paths verified against
  `dev` tip `33d22a83b`.
- The negative space in §1.7 — `compute_hash` divergence
  out-of-scope, V4 out-of-scope, R7 re-litigation out-of-scope,
  R3-frozen verifier surface out-of-scope, per-PR per-hash
  latency CI gate out-of-scope (Phase 3a), 600k-block
  initial-sync wall-time out-of-scope (release-gate suite),
  [`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
  not invoked.
- The forward-actions absorbed from prior phases in §2 — the
  R7-D1..R7-D5 specifications + FOLLOWUPS V3.0 scope items +
  the four carry-forward pre-implementation discipline classes
  (surface enumeration, cross-invariant impact analysis,
  methodology-vs-surface-contract reconciliation,
  substrate-derived constant validation) + the 2h-introduced
  candidate fifth class (methodology-vs-substrate consistency
  check; distinct-class-vs-Pass-4-refinement disposition closes
  per R1-D9).
- The R1-D1..R1-D8 decision-point enumeration in §3 (option
  sets, criteria, Round-0 default-expectation sketches,
  reopen-criterion sketches), plus the optional R1-D9 for
  rule-26 amendment shape.
- The pre-implementation round's mandatory shape per §2.5 and
  the Round-count expectation in §0 — surface enumeration,
  dependency discipline, substrate-derived constant validation,
  corpus-size budget verification, and methodology-vs-substrate
  consistency check (five passes total).

**What this round defers.**

- All R1-D1..R1-D8 closures (Round 1's deliverable).
- The §4 threat model substantive content (Round 2's
  deliverable).
- The §5 implementation hand-off contract substantive content
  (Round 1+ deliverable, with Round-1 initial substance at the
  pre-implementation round + Round-2 threat-model integration).
- The §6 test plan, §7 generator/fixtures plan, §8 commit
  table, §9 CI gates, §10 forward path substantive content
  (Round 1+ deliverables per Phase 2g precedent).
- The §11 Round-1..Round-N history rows (filled as each round
  lands).
- Any code surface — Round 0 references no new code; the
  plan-doc work is markdown-only per the Round-0 scope
  envelope.
