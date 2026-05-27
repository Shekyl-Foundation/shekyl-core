# Stage 1 per-engine PR template — design round structure

**Status.** Standalone template doc. Codifies the design-round structure
that Stage 1 PRs 3, 4, and 5 converged on. Inheritance-by-citation
substrate for PR 6+ Stage 1 trait-extraction work, for Phase 2b's
`StakeEngine` additive trait PR, and for the multi-round design-PR
shape that WALLET_REWRITE_PLAN.md Phases 1–4 will adopt where their
surface admits it.

**Provenance.**
[`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§8.3 (cross-PR discipline inheritance) is the spec-level substrate;
[`docs/WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) operating
principles 4–8 are the plan-altitude substrate; this template is the
**operational manifest** that connects the two and makes
inheritance-by-citation grep-able from a single doc.

**Reading discipline.** This template is not normative ceremony. It is
the *checklist-form distillation* of disciplines that emerged from
adversarial review across three per-engine PRs. Skipping a section is
allowed when its applicability test fails — but the non-applicability
itself must be cited explicitly per §8.3's continuous-discipline
corollary ("citation is the inheritance vehicle").

---

## 1. Purpose

Three goals:

1. **Reduce re-derivation cost.** Each per-engine PR design round
   absorbed ~2 segments of cost re-deriving disciplines that prior PRs
   had already established. The template makes the disciplines
   grep-able from one location; per-engine PRs pay the citation cost
   (one paragraph at design-rounds open) rather than the re-derivation
   cost.
2. **Make inheritance auditable.** Phase 9 audit and post-V3.0
   reviewers asking "why does this PR's substrate have shape X?"
   trace the answer through the template's citations to §8.3 and the
   originating per-engine PR. The audit trail is grep-able from any
   per-engine PR back to the discipline's worked example.
3. **Foreclose silent omission.** Disciplines that are not cited at
   pre-flight are not inherited. The template's pre-flight section
   makes "which disciplines apply" an explicit per-PR question;
   silent omission ("the PR doesn't mention X") becomes "the PR
   explicitly declined to cite X with named non-applicability
   reasoning" or "the PR cited X and inherited the substrate."

## 2. How to use

Copy this template's section structure as the skeleton for a new
per-engine PR design doc
(`docs/design/STAGE_1_PR_N_<ENGINE>_ENGINE.md`). Execute the rounds in
order. Cite this template (and §8.3 / principles 4–8) at the design
doc's pre-flight section. Subsequent rounds extend the design doc
inline per the PR 3 / PR 4 / PR 5 precedent.

**The template is structural, not content.** The design doc's
substantive content (load-bearing question; candidate shapes; criteria
rationale; R-residual dispositions) is per-engine; the template
governs **how the substantive content is organized and closed**, not
what it is.

---

## 3. Pre-flight checklist (before Round 1 opens)

The pre-flight section is the **citation-paying point** for the
inheritance vehicle. Execute every step; cite each result inline at
the design doc's pre-flight section.

### 3.1 Engine identification

- [ ] Cite the
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.X subsection binding this engine's trait surface.
- [ ] Confirm trait existence per §1.5 three-condition test (distinct
  state ownership at Stage 4; distinct failure-isolation domain;
  cross-cutting concern OR isolatable subsystem with explicit
  lifecycle). For *additive* trait proposals (Phase 2b `StakeEngine`
  precedent), confirm all three conditions; for *refinement* PRs on
  existing traits, cite the prior PR's §1.5 row.
- [ ] Cite the engine's §2.X surface methods; confirm whether this PR
  amends the surface (triggers §8.2 amendment co-landing rule) or
  preserves it.

### 3.2 Plan-altitude principles citation (WALLET_REWRITE_PLAN.md)

For each of operating principles 4–8, cite applicability with
reasoning:

- [ ] **Principle 4 (architectural-integrity-now at all altitudes):**
  always applies. Names which `.mdc` rules govern this PR's
  disposition decisions
  (typically `16-architectural-inheritance.mdc` +
  `21-reversion-clause-discipline.mdc`).
- [ ] **Principle 5 (closure-rule discipline + audit-trail
  substrate):** always applies. Names the Round-N closure structure
  this PR will use.
- [ ] **Principle 6 (pre-execution wider-substrate audit):** applies
  if the PR has multi-round design structure. Names whether the audit
  segment will land standalone or fold into an existing segment.
- [ ] **Principle 7 (threat-model anchors are structural):** always
  applies. Names how adversary-controlled-daemon and HW-wallet-as-core
  anchor this PR's wargaming surface.
- [ ] **Principle 8 (priority-hierarchy ordering, not magnitude):**
  applies if the PR has feature-decision surface. Names the priority
  classes the PR's trade-offs touch.

PRs whose surface doesn't admit a given principle name the
non-applicability explicitly rather than skipping the citation.

### 3.3 Per-engine-PR disciplines citation (§8.3)

For each of §8.3.1 through §8.3.5, cite applicability:

- [ ] **§8.3.1 design lenses.** Test each lens's applicability
  conditions:
  - **Actor-mesh framing (lens 1):** does trait surface mediate
    state-mutation across actors? does adversarial review surface
    cross-actor liveness/quiescence dependency? is Stage 4 actor-
    migration target non-trivial? Three-yes → lens applies; bounded
    or no → synchronous framing correct.
  - **State-as-collection-membership (lens 2):** applies only when
    lens 1 applies AND the engine has discrete per-record lifecycle
    stages.
  - **Recursive trust boundary (lens 3):** applies if the engine
    has a diagnostic-stream seam. Three projection axes (field,
    temporal, distributional) bind to cross-trust-boundary
    consumers.
- [ ] **§8.3.2 anti-pattern citations.** Cite the worked-example PR/
  segment for each applicable anti-pattern; commit to running the
  anti-pattern check at the corresponding altitude during Round 1 /
  Round 2 / R-residual dispositions.
- [ ] **§8.3.3 closure-rule operational discipline.** Always applies;
  cite the Round-N closure structure (segment-naming; wider-substrate
  audit obligation; discipline-citation matrix obligation).
- [ ] **§8.3.4 per-PR process discipline.** Always applies; cite
  §7.X synthesis-banner obligation (if multi-segment substrate);
  α/β/γ sub-commit decomposition discipline; workspace-state
  dependency-verification discipline.
- [ ] **§8.3.5 threat-model anchors.** Always applies; cite
  adversary-controlled-daemon + HW-wallet-as-core as load-bearing
  criteria in the PR's wargaming surface.

### 3.4 Architectural-inheritance audit projection

- [ ] Cite the engine's Monero-inherited substrate (if any). Per
  `.cursor/rules/60-no-monero-legacy.mdc`, name what survives from
  the Monero codebase and what gets rewritten.
- [ ] Project the audit result: *confirmation* (no significant
  inheritance) or *substantive migration* (e.g., PR 3's
  `transfer_details`-equivalent migration). If substantive, scope
  the migration as a separate PR per the M3-tail precedent.

### 3.5 Branch posture

- [ ] Cite `.cursor/rules/06-branching.mdc` rule 2 (short-lived
  branches; ≤5 days, ≤10 commits). Design rounds happen on a
  separate design branch
  (`feat/stage-1-prN-<engine>-engine-design`); implementation cuts
  from `dev` after Round 3 closes.

---

## 4. Round 1 — Load-bearing question

Round 1 identifies and disposes the engine's **load-bearing
structural question** — the question whose answer determines the
engine's shape across the V3.0/V3.1/V3.2/V3.x lifecycle.

### 4.1 Standard section structure

Mirror the PR 5 §1–§5 structure:

- **§1 Mission posture.** Cite `00-mission.mdc` priority hierarchy
  (principle 8); name which priorities this engine touches.
- **§2 Scope (in/out).** What this PR delivers; what this PR
  explicitly defers; cross-references to other engines' domains.
- **§3 Pre-flight discipline.** §3.1 (trait-vs-threat-model);
  §3.2 (architectural-inheritance audit per §3.4 above).
- **§4 Phase 0 candidates.** Pre-enumeration of binding-form pins.
  Each Phase 0a, 0b, ..., 0X candidate names the type-signature
  shape, the module location, and the consumer set.
- **§5 Load-bearing question.** The substantive Round 1 work:
  - §5.0 actor-mesh framing **if lens applies per §3.3**; cite
    PR 4 / PR 5 instance precedents.
  - §5.1 the question.
  - §5.2 implications for prior PRs (Round 3 dependency resolution
    if any).
  - §5.3 criteria rationale (criteria 1–5 standard pattern;
    criterion 5 is adversarial-daemon resistance per principle 7).
  - §5.4 R-residuals (some dissolved by §5.0 lens application; rest
    deferred to Round 2 segments with named dispositions).
  - §5.5 Round 1 disposition.

### 4.2 Closure criteria

- [ ] Wargaming surface known at Round 1 closure time is genuinely
  exhausted (principle 5).
- [ ] Lens-applicability test recorded (yes / bounded / no with
  reasoning).
- [ ] R-residuals named with disposition-pointers to Round 2
  segments.
- [ ] Reopen criterion named explicitly: new shapes surfacing in
  Round 2 reopen Round 1 explicitly, not as quiet revisions.
- [ ] §7 discipline budget pin: subsequent rounds land inline; design
  branch holds doc-only revisions until Phase 0 amends the spec.

---

## 5. Round 2 — Segment-decomposed R-residual disposition + Phase 0 enumeration

Round 2 disposes the R-residuals named at Round 1 closure across
**named segments** (2a, 2b, 2c, ...). Each segment is one cohesive
substrate-residual closure that lands as one commit on the design
branch.

### 5.1 Segment-naming discipline

- Segments are sequential (2a → 2b → 2c → ...).
- Each segment's scope is *single-coherent* — one R-residual closure,
  or one cross-cutting discipline refinement paired with related
  R-residual closures.
- Segments close in order; later segments cite earlier segment
  closures rather than re-arguing.
- Segment 2(final) is the **close-out segment**: §4 Phase 0
  binding-form finalization + §6 review checklist + Round 3
  readiness gate.

### 5.2 Standard segment types

The PR 5 segments are the canonical type catalog. New segment types
extend the catalog per the discipline-extension pattern (§8.3.6
scope-guard extension).

- **Audit-readiness segment** (PR 5 segment 2a precedent):
  strengthens criterion-5 adversarial-daemon defense against
  steelman attacks. Lands early in Round 2 per audit-blocking
  sequencing.
- **Anti-pattern reframe segments** (PR 5 2b precedent): residual
  dispositions caught as cost-benefit-defer-to-later at residual
  altitude per principle 4.
- **Closure-rule + lens-applicability segments** (PR 5 2c
  precedent): project-wide discipline refinements paired with
  multiple R-residual named-with-disposition closures.
- **Co-disposition segments** (PR 5 2d precedent): two R-residuals
  closed together when their substrate intersects (e.g., R2 +
  R12 in PR 5).
- **Composition-pattern segments** (PR 5 2e precedent): R-residuals
  closed as consumer-actor composition with V3.0 deliverable
  pre-pins for V3.x emitters.
- **State-machine substrate segments** (PR 5 2f precedent):
  per-error-class disposition tables; ownership-boundary framing;
  enum surface pins.
- **Close-out segments** (PR 5 2g precedent): §4 / §6 finalization
  + Round 3 readiness gate.
- **Reopen segments** (PR 5 2h, 2i precedent): explicit Round-2-
  reopen for substrate residuals surfaced post-close-out per
  principle 5 ("closure pins what was known at closure time").

### 5.3 Closure criteria

- [ ] All R-residuals from Round 1 disposed with named dispositions.
- [ ] §4 Phase 0 binding-form enumeration finalized (all Phase 0a..0X
  pins binding-form-pinned with type signatures + module locations).
- [ ] §6 review checklist filled (binding-check matrix; test-substrate
  preservation; call-site sweep audit).
- [ ] Pre-Round-3 wider-substrate audit segment readied (next
  section).

---

## 6. Pre-Round-3 wider-substrate audit (REQUIRED segment)

Per WALLET_REWRITE_PLAN.md principle 6 and §8.3.3 discipline 2, every
per-engine PR runs a wider-substrate audit **after Round 2 close-out
and before Round 3 drafts**. The audit lands as a named segment
(typically 2(close-out+1); PR 5 precedent: segment 2i landed after
segment 2g/2h).

### 6.1 The audit question

> What have other wallet ecosystems / cryptocurrency projects taught
> us about deployment failure modes that this PR's substrate hasn't
> named?

The yield is **distinct from R-residual sweep**:

- R-residual sweep enumerates what the PR's own design rounds
  surfaced.
- Wider-substrate audit enumerates what *deployed-system failure
  histories* have surfaced that the PR's design rounds didn't ask
  about.

Typical yield: 3–8 items (PR 5 segment 2i: G1–G8, 8 items).

### 6.2 Audit checklist (canonical sources)

Run the audit against each relevant source for the engine's domain:

- **Bitcoin / UTXO chains.** Mempool eviction without daemon
  notification; replace-by-fee / child-pays-for-parent; mempool-
  min-fee policy; long-range reorgs of confirmed txs; dust-attack
  reactions; coin-selection privacy.
- **Ethereum / account-model chains.** Gas estimation under
  adversarial input; MEV / frontrunning; stuck-tx-recovery patterns;
  nonce-management serialization.
- **Monero** (legacy substrate Shekyl forks from). Reorg recovery
  for outputs; subaddress reuse fingerprinting; decoy selection
  privacy under FCMP++; ring signature legacy (now removed in
  Shekyl); coinbase output unlock period.
- **Lightning network / off-chain.** HTLC timeouts; channel
  commitments; watchtower needs; out-of-band signing flows.
- **Universal patterns.** Tx batching / coalescing; confirmation
  tracking handoffs (PendingTx → RefreshEngine); HW-wallet signing
  latency under actor mailbox; wallet-locked-during-in-flight;
  restart-amnesia composition with in-flight; cross-wallet output
  locks (multi-device); cancel-build during long construction;
  fee-fingerprinting on submission.

The list is not exhaustive; new sources extend the audit checklist
when their substrate matters to the engine's domain.

### 6.3 Per-finding disposition options

For each finding, name disposition:

- **V3.0 substrate.** Required to land in this PR (variant pre-pin
  for V3.x consumer-actor; trait method addition; enum reshape).
  Per architectural-integrity-now (principle 4), V3.x consumer-actor
  PRs do not get to revise V3.0 surfaces.
- **V3.x FOLLOWUPS.** Deferred with named V3.x trigger (consumer-
  actor introduction; cryptographic-substrate maturity; operational
  telemetry). FOLLOWUPS entry includes the trigger and the seam-
  design implications.
- **Priority-hierarchy rejection** (per principle 8). Named with two
  substrate-anchored reopening criteria minimum.
- **Out-of-scope for this engine.** Belongs to a different engine's
  domain; forward-reference to that engine's eventual PR via a
  forward-template entry in the relevant FOLLOWUPS section.

### 6.4 Audit closure criteria

- [ ] Every finding has explicit disposition recorded.
- [ ] V3.0 substrate items landed in §4 Phase 0 enumeration
  (binding-form pins) and §5.X disposition prose.
- [ ] V3.x FOLLOWUPS entries created with named triggers.
- [ ] Priority-hierarchy rejections recorded with named reopening
  criteria.
- [ ] Discipline-citation matrix produced (next section).

---

## 7. Discipline-citation matrix (§5.6.X-equivalent)

Per §8.3.3 discipline 3, every per-engine PR produces a matrix
recording **what the PR is getting right by construction** versus the
failure modes other cryptocurrency wallets have absorbed.

### 7.1 Matrix structure

| # | Discipline | Failure mode foreclosed | Substrate / closure |
|---|------------|--------------------------|---------------------|
| 1 | (named discipline) | (deployed-system failure pattern this discipline forecloses) | (segment / closure / §-reference where the discipline landed) |
| ... | ... | ... | ... |

Six-to-eight items typical. PR 5 §5.6.9 is the canonical example.

### 7.2 Matrix scope

The matrix records:

- Disciplines specific to this engine's substrate.
- Disciplines inherited from prior PRs that this engine reinforces.
- Disciplines that emerged during this PR's design rounds that
  extend §8.3.

Entries cite the segment / closure that landed the substrate; the
matrix is the answer to "why this substrate shape over the
obvious-from-other-coins shape?" — the question Phase 9 audit
reviewers will ask first.

### 7.3 Matrix as inheritance vehicle

New disciplines that emerge from this PR extend §8.3 via the
Round-6-style amendment vehicle that §8.3 itself landed under. The
matrix is the local record; §8.3 is the cross-PR inheritance index.

---

## 8. Round 3 — Commit decomposition + §7.X Phase 1 commit list

Round 3 produces the Phase 1 implementation commit list. Structure
follows the PR 1 / PR 2 / PR 3 / PR 4 / PR 5 precedent.

### 8.1 Pre-flight: existing substrate inventory

Before drafting the commit list:

- [ ] Name what exists in the current codebase (types, functions,
  tests) that this PR extracts / augments / replaces.
- [ ] Name what each commit alters with line-range citations.
- [ ] Reviewers cross-reference this inventory when auditing each
  commit's diff scope.

### 8.2 Standard eight-commit shape

The standard ordering (load-bearing):

| Commit | Scope | Sub-decomposition |
|---|---|---|
| **C0** | Phase 0 spec amendment (doc-only) | None |
| **C1** | Foundational types (e.g., `SnapshotId` opaque type) | None |
| **C2** | Error / discriminant enums + struct augmentation | α (errors); β (discriminants); γ (struct fields / config types) |
| **C3** | Diagnostic enum + emission infrastructure | None (emission sites land in C5) |
| **C4** | Secondary trait surfaces + default impls | α / β / γ per secondary trait (e.g., Signer / OutputSelector / FeeEstimator in PR 5) |
| **C5** | Primary trait declaration + aggregate (extraction) | α (trait + skeleton); β (bodies + tests) |
| **C6** | Engine parameterization + orchestration-layer dispatch migration | None |
| **C7** | FaultInjecting wrapper + property tests + per-error-class coverage | None |
| **C8** | Docs propagation + CHANGELOG | None |

Variations from the eight-commit shape are admitted when the engine's
substrate genuinely warrants them; the deviation is recorded in §7.X's
opening prose with named rationale.

### 8.3 Sub-commit decomposition discipline (§8.3.4)

Within-commit content sorts into sub-commits by **type-of-change**,
not by **bytes-of-diff** or **files-touched**:

- C2α — error enums; C2β — discriminant enums + projection enums;
  C2γ — struct augmentation + config types.
- C4α — trait 1 + default impl; C4β — trait 2 + default impl;
  C4γ — trait 3 + default impl.
- C5α — trait declaration + skeleton stub; C5β — extracted bodies +
  augmentation + tests.

Sub-commits are revertible independently for bisection isolation per
`.cursor/rules/90-commits.mdc` bisection discipline.

### 8.4 §7.X synthesis-banner (§8.3.4 discipline 1)

**Required if the PR has multi-segment substrate with deltas landing
in segments after Round-3-original drafting** (PR 5 segment-2h/2i
precedent). The banner opens §7.X and points implementers at the
within-commit deltas:

> **Implementer note (segment-N synthesis).** The C0–C8 commit
> bodies below preserve the Round-3-original substrate per closure-
> rule discipline. Before executing each commit, apply the within-
> commit deltas recorded in §5.X.Y (segment N refinements). Commits
> affected: C0, C2α, ..., C8. The deltas are authoritative; the §7.X
> bodies below are audit-trail substrate that the deltas refine.

The banner is doc-only; the deltas remain authoritative; the commit
bodies retain their closure-rule-correct Round-N-original substrate.

### 8.5 Closure criteria

- [ ] Eight-commit ordering load-bearing (each commit's preconditions
  are the cumulative state of prior commits).
- [ ] Every Phase 0a..0X binding-form mapped to a specific commit.
- [ ] Every §6 review-checklist item mapped to a specific commit's
  test deliverable.
- [ ] Existing pre-PR substrate inventoried with diff scope.
- [ ] §7.X synthesis-banner present if applicable.

---

## 9. Banner discipline

Each round closure produces a banner amendment at the design doc's
status section.

### 9.1 Banner-amendment shape

- **Round-N closure pin.** "Round N closed YYYY-MM-DD; [substrate
  scope]; reopen criterion: [named criterion]."
- **Round-N reopen** (when applicable). "Round N reopen-and-close
  YYYY-MM-DD for [substrate refinement] per closure-rule discipline
  per principle 5."
- **Round 3 readiness gate.** Round 2 close-out criteria all met
  before Round 3 drafts.

### 9.2 Reopen vs advance discipline (principle 5)

Critical distinction:

- **Round-N reopen** — substrate residuals surfaced after Round-N
  closure but before Round-(N+1). The banner names the reopen
  explicitly; the substrate refinement lands as a named segment of
  Round N, not as quiet revision.
- **Round-(N+1) advance** — substrate that genuinely belongs to the
  next round's scope (e.g., Round 3 commit decomposition advancing
  from Round 2 segment-decomposed R-residual closure).

The distinction is grep-able from the banner's verb choice ("Round 2
reopen-and-close" vs "Round 3 closed"); reviewers and audit auditors
trace provenance through the banner sequence.

---

## 10. Implementation execution

Once Round 3 closes and §7.X commit decomposition is finalized:

1. Cut the implementation branch from post-Round-3 `dev` tip per
   `.cursor/rules/06-branching.mdc`.
2. Execute C0–C8 in order. Each commit gates on CI green +
   `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`
   + `cargo doc --no-deps` clean.
3. C8 lands locally with a passing CI run before the PR opens
   against `dev`.
4. Cross-cutting amendments to
   [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
   §2.X follow §8.2's amendment co-landing rule (trait amendment
   commit + consumer commit + PR description bullet).
5. Substrate-level disciplines that emerged during the PR (extending
   §8.3) are recorded as a follow-up §8.3 amendment per the Round-6-
   style amendment vehicle.

---

## 11. When this template doesn't apply

The template assumes per-engine trait-extraction PRs with multi-round
design structure. PRs that don't fit:

- **Mechanical PRs.** Renames; dependency bumps; C++ deletion per
  WALLET_REWRITE_PLAN.md Phase 5 single-commit discipline. Template
  doesn't apply.
- **Bookkeeping PRs.** PR 0.1 (decision-log creation); PR 0.2 (file
  rename) precedents. Template doesn't apply.
- **Bug-fix PRs.** Bug-fix is incremental work; template doesn't
  apply. If the bug-fix touches a trait surface, §8.2's amendment
  co-landing rule governs the trait-surface change.
- **Pre-flight Phase 0 sub-amendment PRs** (PR 22 / PR 23 / PR 25
  precedent from PR 2's lifecycle). These are doc-only spec
  amendments threaded through a parent PR's lifecycle; the parent
  PR follows the template; the sub-amendments don't.

For [WALLET_REWRITE_PLAN.md](WALLET_REWRITE_PLAN.md) Phases 1–6:

| Phase | Template applies? | Notes |
|---|---|---|
| Phase 0 (bookkeeping) | No | Mechanical sub-PRs; template doesn't apply |
| Phase 1 (wallet domain model) | Yes | Multi-round design substrate likely |
| Phase 2 (core operations) | Yes, per-domain | Each domain sub-PR may have multi-round design |
| Phase 3 (`shekyl-cli` binary) | Partial | Applies to UX-decision-heavy sub-PRs; not to thin-wrapper sub-PRs |
| Phase 4 (`shekyl-wallet-rpc` binary) | Yes | RPC surface admits multi-round design |
| Phase 5 (C++ deletion) | No | Single-commit mechanical per WALLET_REWRITE_PLAN.md principle 3 |
| Phase 6 (tests and docs) | Partial | Applies only to PRs introducing new test-discipline shapes |

PRs whose surface doesn't admit the template's structure cite the
non-applicability with reasoning in the PR description; the citation
itself is the discipline (per §8.3 continuous-discipline corollary).

---

## 12. Template-evolution discipline

This template is **not pinned**. New per-engine PRs that surface
disciplines extending §8.3 or operating principles 4–8 amend this
template via the same Round-6-style amendment vehicle that landed
those substrates. Amendment shape:

1. The originating per-engine PR's design doc records the new
   discipline in its §5.6.X discipline-citation matrix.
2. A follow-up doc-only PR amends §8.3 (cross-PR inheritance index)
   with the new discipline's worked-example citation.
3. The same follow-up PR amends this template's relevant section
   (typically §3 pre-flight or §5 segment types or §8 commit shape)
   to make the new discipline grep-able from the template.
4. Operating principles 4–8 in
   [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) grow only when
   the new discipline applies at *plan altitude* (governs how the
   wallet rewrite executes across phases, not just per-engine PRs).

The three-doc structure (template + §8.3 + plan principles) is the
inheritance vehicle; the citation cost at per-PR pre-flight is what
makes the inheritance compound.

---

**End of template.**
