# Engine Trait-Surface Conformance Lenses (Stage 1)

This document codifies the **seven conformance lenses** that every
Stage 1 engine trait surface in `shekyl-engine-core` is reviewed
against. The lenses were extracted by reading the two reference
surfaces — [`LedgerEngine`](../rust/shekyl-engine-core/src/engine/traits/ledger.rs)
and [`DaemonEngine`](../rust/shekyl-engine-core/src/engine/traits/daemon.rs) —
and naming the documentation-as-contract dimensions they satisfy. The
dimensions previously lived implicitly in the reference code and in
scattered spec sections (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §1.4,
§1.5, §1.6); this doc is the single enumerated checklist so a future
contributor or auditor can evaluate a trait surface against named
criteria rather than aesthetic judgment.

> **Why this exists.** Per `.cursor/rules/05-system-thinking.mdc`
> ("specification first") and `.cursor/rules/16-architectural-inheritance.mdc`
> ("what does this deliver against the threat model?"), a trait
> surface's rustdoc *is* its contract. For the secret-touching and
> side-effecting engines (`KeyEngine`, `PersistenceEngine`,
> `PendingTxEngine`), an undocumented panic/cancellation/idempotency
> property is a property an auditor cannot see — the behavior may be
> correct while the contract is illegible. The lenses make the
> contract legible and reviewable.

---

## 0. Terminology: conformance lenses vs. design lenses

Shekyl already uses the word **"lens"** for a *different* concept.
`docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §8.3.1 defines three **design
lenses** (lens 1 — actor-mesh framing; lens 2 —
state-as-collection-membership; lens 3 — recursive trust boundary).
Those govern a trait's **shape** (whether a method is sync or async,
how lifecycle state is represented) and apply only to engines whose
structure satisfies named applicability conditions.

The **conformance lenses** in this document are distinct: they govern
a trait's **documentation surface** (what the rustdoc must state so the
contract is legible), and — with the applicability carve-outs noted
per lens — apply to *every* engine trait. To keep the two from
colliding in casual reference, conformance lenses are abbreviated
**CL-1 … CL-7**; the §8.3.1 design lenses keep their "lens 1/2/3"
naming.

| | Design lenses (§8.3.1) | Conformance lenses (this doc) |
|---|---|---|
| Governs | trait **shape** | trait **documentation/contract** |
| Numbered | lens 1–3 | CL-1 … CL-7 |
| Applies to | engines whose structure admits the lens | every trait (with per-lens carve-outs) |
| Tested at | Round 1 pre-flight (per-PR template §3.3) | Round 1 pre-flight (per-PR template §3.6) |

---

## 1. The seven conformance lenses

Each lens names **what it checks**, **where the contract lives**, the
**reference exemplar** in landed code, the **pass criterion**, and the
**applicability carve-out** (when a trait may legitimately not satisfy
the lens, the absence must be *documented*, never silent — per the
deliberate-absence discipline in §3.2).

### CL-1 — Ownership boundary

- **Checks:** the module-level `//!` doc cites the contract section it
  implements (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.x) and states
  what the actor **owns** vs. what is **deliberately off-trait** and
  why.
- **Lives in:** the trait file's module-level rustdoc.
- **Reference exemplar:** `ledger.rs` module doc — cites §2.2, states
  it owns the confirmed-chain ledger, and explains why the
  ledger *mutation* (`apply_scan_result`) and `transfers()` are
  deliberately off-trait (secret-locality + the `view_secret`
  ownership argument).
- **Pass criterion:** a reader can determine, from the module doc
  alone, the trait's §-anchored charter and the rationale for every
  capability that a naïve reader might expect on the trait but that
  lives elsewhere.

### CL-2 — Supertrait bounds

- **Checks:** an explicit `# Supertrait bounds` section justifying
  `Send + Sync + 'static` (and any additional supertrait, e.g.
  `Rpc`), and stating whether the trait is `Clone` **with the
  reason**.
- **Lives in:** the trait-item rustdoc (`# Supertrait bounds`).
- **Reference exemplars:**
  - `LedgerEngine` — **not** `Clone` (wraps `RwLock`/`ActorRef`,
    shared by `Arc`; implementors clone the `Arc` wrapper, not the
    trait object).
  - `DaemonEngine` — `Rpc + Clone + Send + Sync + 'static` (the
    daemon handle is shared **by clone** with the spawned producer
    task).
  - `PendingTxEngine` — **not** `Clone` (implementors hold
    `Arc<S: Signer>` spend material; a forced `Clone` would
    re-introduce the secret-duplication hazard per the
    architectural-inheritance discipline).
- **Pass criterion:** the bound list is present, each bound has a
  one-line justification tied to the Stage 4 actor wrap, and the
  `Clone`/not-`Clone` disposition is stated with its reason (not left
  for the reader to infer).
- **Why it is load-bearing:** listing `Send + Sync + 'static`
  explicitly catches the common failure mode where a trait that
  "happens to be `Send + Sync` today" gains a non-`Send` field before
  the Stage 4 actor wrap forces the issue.

### CL-3 — Error landing pad

- **Checks:** the trait declares `type Error: Into<…>` as the named
  forward-compatibility hook **even when no method surfaces it yet**,
  *or* documents a deliberate absence with rationale.
- **Lives in:** the associated-type rustdoc (or a documented-absence
  note in the trait/module doc).
- **Reference exemplars:**
  - `LedgerEngine` — declares `type Error: Into<LedgerError>` with a
    `# type Error` section stating no Stage 1 method surfaces it; it
    is the named landing pad for future additive variants per §8.2.
  - `PendingTxEngine` — **deliberate absence**, documented: no
    associated `Error`; the four methods return concrete error
    vocabularies (`SendError` / `SubmitError` / `PendingTxError`)
    because collapsing four distinct domains into one associated type
    would force consumers to discriminate by variant rather than by
    type.
- **Pass criterion:** either the landing pad is present and documented,
  or its absence is explained. Silent absence fails the lens.

### CL-4 — Per-method C/I/P triad

- **Checks:** every method carries `# Cancellation` (naming its
  class a/b/c per §4), `# Idempotency` (yes / conditionally / no, with
  the condition named for "conditionally"), and `# Panics` (including
  the lock-poisoning behavior, or an explicit "Never panics" note where
  the absence would otherwise be ambiguous).
- **Lives in:** each method's rustdoc. This lens **is** the
  `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §1.6 documentation discipline,
  enumerated here as one of the seven.
- **Reference exemplars:**
  - `LedgerEngine::synced_height` — class **a**, idempotent, panics on
    `RwLock` poisoning (sync-infallible return by design per §2.2's
    Round-3 disposition).
  - `DaemonEngine::submit_transaction` — class **b** (network
    side-effect; drop-after-dispatch does not un-send), conditionally
    idempotent (daemon dedupes by hash → `AlreadyKnown`), never
    panics.
- **Pass criterion:** all three subsections present on every method.
  The `# Panics` text states **what the implementor actually does** —
  a method that *maps* lock poisoning to a domain error must say so,
  not claim a panic it does not raise. (This precision is the lens's
  load-bearing edge: `PendingTxEngine`'s mutators map `Mutex`
  poisoning to `SendError`/`SubmitError`, while `outstanding` panics
  on it — the contract must distinguish the two.)
- **Applicability nuance:** a trait whose cancellation discipline is
  genuinely **cross-method** (e.g. `RefreshEngine`'s five-checkpoint
  cancellation) may document `# Cancellation` once at the trait level
  and cross-reference it from the method, rather than duplicating it
  per method. This is conformant, not a gap — do **not** "fix" it into
  per-method duplication.

### CL-5 — Stage-4 swap-in invariance

- **Checks:** a `# Stage-4 swap-in` note stating that method
  signatures do **not** change when the Stage 1 `Local*` implementor
  becomes `ActorRef<*Actor>` at Stage 4; callers binding against the
  trait get the swap-in for free.
- **Lives in:** the module-level or trait-item rustdoc.
- **Reference exemplars:** `LedgerEngine` (`LocalLedger` →
  `ActorRef<LedgerActor>`) and `DaemonEngine` (`DaemonClient` →
  `ActorRef<DaemonActor>`) both carry the note.
- **Pass criterion:** the invariance is stated explicitly, so a Stage 4
  cutover that would change a signature is caught against a written
  contract rather than discovered late.

### CL-6 — Justified `#[allow(dead_code)]`

- **Checks:** every `#[allow(dead_code)]` (and sibling allows on the
  trait surface) carries an inline reason of the form
  `// <PR/phase>: <caller> lands in <commit/phase>`, naming when the
  suppression stops being load-bearing — **never bare**.
- **Lives in:** the attribute's trailing line comment.
- **Reference exemplar:** `LedgerEngine`'s methods —
  `#[allow(dead_code)] // Stage 1 PR 2: production call sites migrate in commit 5.`
- **Pass criterion:** no bare `#[allow(dead_code)]` on the trait
  surface; each names its deletion/relaxation trigger per
  `.cursor/rules/15-deletion-and-debt.mdc` (an allow without a named
  trigger is debt that compounds). A single collective comment above a
  block of attributes is **below bar** — each attribute carries its
  own reason.

### CL-7 — Forward-compat on public value/error types

- **Checks:** public value types (structs/enums) and error types that
  cross the trait surface are forward-compatible per §8.2 — value
  structs/enums carry `#[non_exhaustive]` with a `# #[non_exhaustive]`
  rustdoc section citing the anticipated extension; error types
  intended to stay payload-free carry the **unit-variant-only** pin.
- **Lives in:** the value/error type's attribute + rustdoc.
- **Reference exemplars:**
  - `DaemonEngine`'s `FeeEstimates` (struct) and `TxSubmitOutcome`
    (enum) — both `#[non_exhaustive]` with a `# #[non_exhaustive]`
    section explaining the Phase 2a additive growth they anticipate.
  - `RefreshEngine` — the **unit-variant-only** error pin: trait
    implementors MUST NOT add fielded variants carrying
    caller-attacker payloads (raw daemon `String`s, secret pointers);
    per-event detail flows through the `DiagnosticSink`, not the
    terminal error.
- **Pass criterion:** every trait-owned public value/error type either
  carries the appropriate forward-compat attribute **with a documented
  rationale**, or documents why it is exempt (e.g. it re-exports a
  pre-existing aggregate defined outside the trait file, as
  `LedgerEngine::balance` does with `shekyl_scanner::BalanceSummary`).
- **Why this is the "seventh" lens.** The conformance scorecard's "+"
  annotations — `DaemonEngine (+#[non_exhaustive] value types)` and
  `RefreshEngine (+unit-variant pin)` — are this lens. It is easy to
  miss when enumerating the contract dimensions from method rustdoc
  alone (the first six all surface on the trait/method docs; this one
  surfaces on the *value types* the trait returns), which is exactly
  why it earns an explicit name.

---

## 2. Conformance scorecard (current `dev` state)

State as of the post-PR7 `dev` HEAD. ✓ = at or above bar; ◑ = partial;
✗ = below bar; n/a = lens does not apply (documented exemption);
— = not yet audited (folded into the relevant remediation).

| Trait | CL-1 owns | CL-2 bounds | CL-3 err pad | CL-4 C/I/P | CL-5 swap-in | CL-6 dead_code | CL-7 fwd-compat | Verdict |
|---|---|---|---|---|---|---|---|---|
| `LedgerEngine` | ✓ | ✓ | ✓ | ✓ 3/3 | ✓ | ✓ | n/a¹ | **reference** |
| `DaemonEngine` | ✓ | ✓ | ✓ | ✓ 2/2 | ✓ | ✓ | ✓ | **conformant / exceeds** |
| `RefreshEngine` | ✓ | ✓ | ✓ | ✓ (trait-level 5-checkpoint + per-method I/P) | ✓ | ✓ | ✓ (unit-variant pin) | **conformant / exceeds** |
| `PendingTxEngine` | ✓ | ✓ | ✓ (documented absence) | ◑ 1/5² | ✓ | ✓ | —³ | **partial** |
| `PersistenceEngine` | ✗⁴ | ✗ | ✓ | ✗ 0/6 | ◑ | ◑⁵ | —³ | **laggard** |
| `KeyEngine` | ✓ | ✓ | ✓ | ◑ 4/4 C/I, 0 Panics | ✓ | ✓ | — | **in-flight⁶** |
| `EconomicsEngine` | — | — | — | — | — | — | — | **not yet extracted⁷** |

1. `LedgerEngine` returns pre-existing aggregates (`BalanceSummary`,
   `LedgerSnapshot`, `u64`) rather than trait-owned value types, so
   CL-7's `#[non_exhaustive]` requirement does not apply; the exemption
   is documented per the CL-7 pass criterion.
2. Only `outstanding` carries `# Cancellation` + `# Idempotency`;
   `build` / `submit` / `discard` / `signal_mempool_evicted` carry
   `# Errors` but no C/I/P. The coverage is *inverted from the threat
   model* — the safe sync read is documented while the side-effecting
   async mutators are not. Note the `# Panics` precision requirement:
   the mutators map `Mutex` poisoning to a domain error; only
   `outstanding` panics on poisoning.
3. CL-7 for `PendingTxEngine` / `PersistenceEngine` covers error/value
   types defined off the trait file (`engine/error.rs`,
   `engine/pending.rs`); the audit is folded into the F1/F2 remediation
   rather than asserted here.
4. No `# Supertrait bounds` section and no Stage-4 swap-in note;
   ownership boundary is partial (body docs without the §-anchored
   owns/off-trait framing).
5. `base_path` / `network` / `capability` share one collective reason
   comment above the block rather than a per-attribute inline reason
   (below the CL-6 bar); `save_prefs` has no rustdoc at all.
6. `KeyEngine` is declared (`traits/mod.rs`) but **not re-exported**,
   pending its M3c+ consumers. Its four methods carry C/I but no
   `# Panics` (the implementor `LocalKeys` panics on `RwLock`
   poisoning in `derive_subaddress` and `try_claim_output`). Per the
   "do it now, don't backfill" posture (§3.1), land the `# Panics`
   sections with the methods rather than reconstructing them later.
7. The `EconomicsEngine` *trait surface* is not yet a file under
   `traits/` on `dev`. PR7 landed the C2c `get_block_reward` consensus
   cutover (C++ ESF → Rust FFI), not the trait extraction. Audit
   `EconomicsEngine` against CL-1…CL-7 when its surface lands per
   §1.5 / §2.7.

**Disposition.** `Daemon` / `Refresh` are at or above the
`LedgerEngine` bar — no action. `PersistenceEngine` (laggard) and
`PendingTxEngine` (partial, inverted) are the two that need
remediation; `KeyEngine` lands its `# Panics` sections in-flight. The
remediation is documentation-only and is tracked separately (it does
not change behavior, signatures, or `#[allow]` scope).

---

## 3. Applying the lenses

### 3.1 Posture: do it now, don't backfill

A trait surface lands with the full seven-lens conformance from the
first commit that introduces it, not as a later documentation pass.
Per `.cursor/rules/16-architectural-inheritance.mdc`'s
cost-benefit-defer-to-later anti-pattern, the cost of writing the
contract grows with each call site that lands against an
under-documented method; the cheapest time to state the contract is
when the method is written, before any caller depends on it. A trait
that is mid-extraction (e.g. `KeyEngine`) carries the triad on each
method as the method lands, rather than accumulating documentation
debt a later pass must reconstruct from the implementor.

### 3.2 Deliberate absence is documented, never silent

Several lenses admit a legitimate "does not apply" — `PendingTxEngine`
has no associated `Error` (CL-3); `LedgerEngine` returns pre-existing
aggregates (CL-7); `RefreshEngine`'s cancellation is cross-method
(CL-4). In every case the absence is **documented with its rationale**.
A silently-absent lens is indistinguishable from an overlooked one and
fails review. This mirrors the scope-guard meta-pattern in
`docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §1.5: explicit "no, here's why"
closes the question; silent omission invites a future contributor to
re-open it.

### 3.3 Per-PR pre-flight

For a per-trait extraction PR, Round 1 pre-flight tests the trait
surface against CL-1 … CL-7 (per the per-PR template's §3.6) and
records the result per lens (✓ / documented-exemption /
deferred-with-pointer). This is the conformance-lens sibling of the
template's §3.3 design-lens applicability test. The two are
independent: a trait may decline a design lens (synchronous framing is
correct) while still satisfying all seven conformance lenses.

---

## 4. Maintenance (reversion-clause discipline)

Per `.cursor/rules/21-reversion-clause-discipline.mdc`, the set of
seven lenses is **fixed by the current substrate**, with named
criteria for changing it:

- **Adding an eighth lens** requires a new documentation-as-contract
  dimension that the landed reference surfaces (`LedgerEngine` /
  `DaemonEngine`) already satisfy implicitly but that is not captured
  by CL-1 … CL-7 — i.e. the same way CL-7 was promoted from the
  scorecard's "+" annotations. A proposed lens that the reference
  surfaces do *not* already satisfy is a *design* change to the
  documentation discipline, not a conformance lens, and goes through
  `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §1.6 amendment instead.
- **Removing a lens** requires that the property it guards has been
  absorbed by a stronger mechanism (e.g. a lint that mechanically
  enforces it), at which point the lens becomes redundant rather than
  load-bearing. Until then, "the audits keep coming back clean" is
  **not** grounds to relax the check — the audits come back clean
  *because* the discipline is applied (per the
  `16-architectural-inheritance.mdc` audits-are-clean-so-compress
  anti-pattern).

The conformance scorecard (§2) is re-audited when a trait surface
changes (a new method, a new value type, a Stage 4 cutover) — not on a
fixed cadence.

---

## 5. Cross-references

- **`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`** — the engine-trait spec.
  §1.4 (method shape), §1.5 (trait existence), §1.6 (documentation
  discipline = CL-4), §8.2 (additive-variant forward-compat = CL-7),
  §8.3.1 (the *design* lenses — distinct from these conformance
  lenses, see §0).
- **`docs/design/STAGE_1_PER_PR_TEMPLATE.md`** — §3.6 pre-flight
  checklist hooks the conformance lenses into per-trait PR design
  rounds.
- **`.cursor/rules/05-system-thinking.mdc`** — specification-first /
  documentation-as-contract.
- **`.cursor/rules/15-deletion-and-debt.mdc`** — the
  named-trigger requirement behind CL-6.
- **`.cursor/rules/16-architectural-inheritance.mdc`** — the
  do-it-now posture (§3.1) and the audits-are-clean-so-compress
  anti-pattern (§4).
- **`.cursor/rules/21-reversion-clause-discipline.mdc`** — the
  add/remove-a-lens discipline (§4).
- **`.cursor/rules/35-secure-memory.mdc`** /
  **`.cursor/rules/30-cryptography.mdc`** — why the C/I/P triad
  (CL-4) on secret-touching methods is auditor-facing and
  load-bearing.
