# Bond-PR 2c-2b — JoinMarket archival bond request path (plan + scoping pre-flight)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
— this is the full plan doc nested under §3.5 of that arc. "Bond-PR 2x" is the
bond-construction chain (disambiguated from engine-layer "Phase 2x" per the arc
§0).
**Branch:** `feat/archival-bond-request` (off `dev`, after Bond-PR 2c-2a landed
inert — `06-branching.mdc` land-inert-then-branch; 2c-2a substrate is present on
`dev`: `rust/shekyl-engine-core/src/engine/stake_engine.rs`,
`…/stake_persist.rs`).
**Parent design:** `ARCHIVAL_BOND_CONSTRUCTION.md` §10 / §10.1 / §10.2, §11.1 Q3;
`ARCHIVAL_TIMING_CONSTANTS.md` §7; `ARCHIVAL_FIREWALL_GATE6.md` §9.6 / §10.9.
**Process rule:** `26-sub-pr-design-discipline.mdc` (opt-in; cited here per its
Scope clause — this is a multi-round per-trait PR on the gate-6 firewall request
surface with an RNG self-cert).
**Status:** **OPEN — scoping pre-flight (this document).** Design rounds 1–6 and
the impl-time pre-flight pass have not run.

---

## 0. Framing and the "Round 0" naming reconciliation

This document is the **opening scoping pre-flight**: scope enumeration plus the
`16-architectural-inheritance.mdc` pre-flight check on the request path
(rule 16 §"Discovery cadence" / §"Operational implication for forward
extractions" — "PR pre-flight checklists should include [the threat-model
delivery] question explicitly"). It precedes the adversarial design rounds.

**Naming caution (so the audit trail does not collide).** `26-sub-pr-design-
discipline.mdc` reserves **"Round 0" / `R0-D#`** for the *impl-time* pre-flight
pass that runs **after design closure, before production code** ("Round 0 in
plan-doc naming only, meaning impl-time pre-flight after design closure, not the
round before Round 1" — rule 26 lines 11–14, §"Pre-flight pass"). The pass the
user named "2c-2b Round 0 pre-flight" is the **rule-16 scoping check that opens
the rounds**, a different pass from the rule-26 `R0-D#` one. To keep the stable
`R0-D#` anchors uncontaminated:

- This opening pass records findings as **`SP-#`** (scoping pre-flight).
- The rule-26 impl-time pre-flight pass (§4) keeps **`R0-D#`** for after design
  closure.

The two are complementary exactly as rule 26 frames them: the scoping check
defends against scope drift and inherited-architecture contradiction *before*
the rounds; the impl-time `R0-D#` pass defends against design decisions
falsified by substrate or by running produced artifacts *after* closure.

---

## 1. Scope enumeration (SP-1)

Enumerated against the two canonical scope anchors — `ARCHIVAL_BOND_
CONSTRUCTION.md` §10 (the PR-2 bullet list, lines 450–465) and `docs/FOLLOWUPS.md`
the 2c-2b forward-action block (lines 913–919) — and reconciled with the
substrate 2c-2a actually landed. Every "consumes" row names the producer left
inert by 2c-2a.

### 1.1 In scope

| # | Scope item | Source anchor | Consumes / produces (substrate at pin) |
| --- | --- | --- | --- |
| S1 | **Parallel StakeEngine JoinMarket bond request type** — a typed-separate request to the StakeEngine actor, *not* a `TxRequest` variant, so bond construction never threads the `LedgerEngine` transfer pipeline (cross-assignment unrepresentable). | §11.1 Q3 (CLOSED, lines 766–780); §9.6/§10.1 | New message on `StakeEngine` alongside `MintPersonaHandle` / `ActivatePersona` (`stake_engine.rs:488,521`). Consumes `PersonaHandle` (`stake_engine.rs:241`). Drives `build_join_market_vin` (`shekyl-archival-bond-builder/src/lib.rs:109`). |
| S2 | **`sign_bond(ticket: PersistedBondTicket, …)`** — the consumer half of the persist-before-use typestate; sign-before-persist is uncallable (no ticket to pass). | §10.2 typed contract #1 (lines 567–582); `stake_persist.rs:25–27,70` | Consumes `PersistedBondTicket` **by value** (`stake_persist.rs:70`, `!Clone`). Producer `Engine::persist_bond_record` (`stake_persist.rs:125`) is already landed + tested, inert. |
| S3 | **Funding-selection *design* (design-now / wire-later)** — settle the two-regime split: cold-start = principal-funded, ≥ 1-SEB-spaced + standoff-decorrelated; steady-state = `P`-local fund-from-earnings ramp (≥ 2 settlement epochs). **The genesis-adjacent firewall *logic* lands now; neither real funding source is wired** (principal-output access and `P`-scanning both deferred — SP-2.d / SP-2.e). Selection logic is **fixture-validated** over Bond-PR 2c-1's `funded_ledger_and_tree`, not real sources. | §10 (lines 454–456); `ARCHIVAL_TIMING_CONSTANTS.md` §7 (lines 253, 256) | `verify_credit_funding` (`builder/src/lib.rs:173`) is the amount-level invariant the selection must satisfy. Consumes economics SEB/epoch constants (B6, §4). |
| S4 | **Two typed timing seams** — `NetworkGap(BlockSpan)` (`draw_entry_gap(window=600)`) vs `EconomicSpacing(SebSpan)` (≥ 1 SEB / ramp); cross-apply is a **compile error**. Entry seam only; exit seam deferred to the unbond slice. | §10 (line 457–462); FOLLOWUPS (lines 914–917) | **New types — none exist yet** (verified: no `NetworkGap`/`EconomicSpacing`/`BlockSpan`/`SebSpan` in tree). `BlockSpan` likely rests on `shekyl-types::BlockCount` (`shekyl-types/src/lib.rs:181–247`, Instant/Duration algebra); `SebSpan` has no home (rule-18 placement). |
| S5 | **Live RNG degeneracy check (float-free, fail-loud)** — the cheap integer-only guard, distinct from the statistical self-cert. | §10 (lines 457–462); FOLLOWUPS (line 917–918) | Runs against `draw_entry_gap` output (`shekyl-standoff/src/draw.rs:57`). Negative-control shapes already exist: `draw_entry_gap_double_jitter_trap` (`conformance.rs:135`), `correlated_walk` (`conformance.rs:208`). |
| S6 | **`certify_draw` self-cert against the shipping wallet's CSPRNG (gated)** — proves the *shipping wallet's RNG* produces conformant draws, not merely the reference. | §10 (lines 457–462) | `certify_draw` (`conformance.rs:377`) over a `GapRng` (`draw.rs:13`) adapter on `rand_core::OsRng` (the shipping CSPRNG — `shekyl-tx-builder/src/sign.rs:17`, `engine/sign_bridge.rs:14`). |
| S7 | **Request-path composition KAT + own-surface negatives.** Accept: mint handle → `persist_bond_record` → `sign_bond` → `build_join_market_vin` → verify, over 2c-1's `funded_ledger_and_tree` fixture. **Not** a new prover round-trip (closed by Bond-PR 2a #156 / 2c-1 #158 — arc §5; the prove-half tampering negatives — wrong `bond_credit`, tampered commitment/preimage, replay — live in 2a). 2c-2b's **new** failure surfaces, all uncovered upstream, must be asserted here: **(a)** funding violating `verify_credit_funding` is rejected; **(b)** the RNG degeneracy guard **fires** on a degenerate draw (assert it bites, via the `double_jitter_trap` / `correlated_walk` controls, not just that the shapes exist); **(c)** `trybuild` **compile-fail** tests proving the unrepresentability claims — `sign_bond` without a `PersistedBondTicket`, a `PersonaHandle` for an unheld slot — do not compile. Real-tree verify half stays `#[ignore]`/CT-5-gated. | arc §5; §11.1 Q4 (lines 782–789); FOLLOWUPS (lines 918–924); §4 typed contracts | Builder dev-deps `shekyl-archival-retention` verify path (`builder/Cargo.toml` `[dev-dependencies]` — currently empty, to wire). `trybuild` dev-dep to add. |

### 1.2 Explicitly out of scope (carried to PR 2d, `A5` forward-action)

| Out | Why deferred | Forward anchor |
| --- | --- | --- |
| Broadcast / re-anchor wiring | Activates the CT-5d persona-pin (re-sign on fee/change drift). 2c-2b lands **no submission** — §10.2 CT-5d note (lines 650–667): "2c-2 lands no submission, so this does not execute yet." | FOLLOWUPS lines 954–955; `CT5D_REANCHOR.md` |
| `arti-client` `P`-isolated outbound transport | §11.1 Q3's residual: shared connection links `P` to principal at the network layer "regardless of the request enum" (lines 682–694). The request type isolates *construction*; transport isolation is a separate security-critical pre-flight. | FOLLOWUPS lines 925–928 |
| **`P`-scan layer** (the `P.view_sk` sweep; SP-2.e) | Not 2c-2b-sized — it is the scan-layer firewall (StakeEngine owns `P.view_sk`). The capability exists (`archival_p.rs:332`) but no pipeline is built. **One sweep, two readers**: steady-state funding-output discovery **and** the reconcile below. | **Bond-PR 2d-1** (arc §2 / §3.6) |
| 2d full-scan reconciliation of `bonded_slots` / `p_slot` | Chicken-and-egg: the reconcile needs personas derived first (scan posted + `consumer_held`), so it is post-derive — **it sits on top of the 2d-1 `P`-scan above** (cannot reconcile bonds it has not scanned for). `bonded_slots` stays a reconcilable hint; **no second `STAKING_BLOCK_VERSION` bump** (`stake_engine.rs:166–168`). | **Bond-PR 2d-2** (depends on 2d-1); FOLLOWUPS lines 945–953 (rule-21 reopen) |
| Exit timing seam (unbond) | S4 ships the **entry** seam only. | §10 (line 457–462) |
| Intra-call parallel keygen across the `k`-bounded union | Perf follow-up, not correctness — derivation cost relocated to `assemble()` (`lifecycle.rs:867–873`). | §10.2 perf note (lines 669–680) |

### 1.3 Scope-boundary disposition (`A4` reversion clause)

No scope is **moved** between sub-PRs here; 2c-2b consumes exactly the inert
surface 2c-2a produced, and defers exactly the 2d-anchored items the FOLLOWUPS
block already names. The boundary is **named-reasoning-stable**, not inertia:
the in/out split is forced by (a) the firewall (S1, transport-out), (b) the
persist-before-use typestate (S2), and (c) the derive-first chicken-and-egg
(2d reconcile-out). Reopening triggers are the per-item anchors in §1.2.

### 1.4 Land-inert posture (the same pattern as 2b / 2c-2a — phantom-accrual guard)

**2c-2b lands inert: the request path is wired and KAT-exercised, but NOT
user-invocable until 2d completes broadcast + transport + reconciliation.** This
is the same posture Bond-PR 2b and 2c-2a used (arc §3.2 / §3.4), and here it is
load-bearing, not stylistic. S2 persists a `bonded_slots` entry **before** sign,
at build time (persist-before-use, correct); but 2c-2b lands **no broadcast**, so
any bond it builds is `consumer_held` **forever-until-2d**. If the request path
were user-invocable, those entries would be real **phantoms** — persisted, never
broadcastable, **growing the derive-forward set on every flagged-staker open**
until 2d's reconciliation/GC exists (`stake_engine.rs:166–168`,
`spawn_stake_engine_if_staker` `lifecycle.rs:879`) — and a construct-but-can't-
broadcast bond is a half-working feature besides. Pinning inert is the explicit
reading of §10.2's "2c-2 lands no submission" and **closes the 2c-2b→2d
phantom-accrual window** by construction. The milestone KAT drives the path; no
production caller does.

---

## 2. Architectural-inheritance check on the request path (SP-2, rule 16)

The load-bearing question (rule 16 §"Discovery cadence"): **"what does the
request path deliver against the threat model, and does the existing data flow
support that delivery?"** — not "is it internally consistent?"

**Density expectation (rule 16 §"Density expectations").** The request path is
the **gate-6 firewall surface** — the StakeEngine actor *is* the firewall
realized as actor isolation (`stake_engine.rs:10–14`, §10.1 lines 467–473).
Cryptographic/secret-owning surfaces "carry the highest concentration" of
architectural-inheritance findings, so this check is weighted **heavy**, not
skimmed. Per rule 16 §"Operational implication", the *expected* outcome on a
designed-for-Shekyl surface is **confirmation** (minimal migration); the check's
value is "catching the cases where the expectation breaks" — and the
"audits-are-clean-so-compress" anti-pattern (rule 16 lines 252–265) forbids
relaxing it because 2c-2a's surface looked clean.

### 2.1 What the request path must deliver

The firewall property (§9.6, realized §10.1): **StakeEngine is the sole owner of
`P`'s secret material, structurally disjoint from the `LedgerEngine` transfer
pipeline, never cross-assigned.** The request path is where a JoinMarket bond is
*requested and serviced*, so it is precisely the surface where that disjointness
is either preserved or broken.

### 2.2 Findings

**SP-2.a — CONFIRMATION (migration-by-construction already chosen).** The
inherited wallet2/CryptoNote architecture routes *all* spends through one
transfer pipeline (`TxRequest` → `LedgerEngine`). Carrying that forward as a
bond `TxRequest` variant would thread bond construction through `LedgerEngine`
and **cross-assign** `P` material into the principal's pipeline — the exact
inherited-data-flow contradiction rule 16 governs. §11.1 Q3 already migrates it:
a **typed-separate request to a separate actor makes cross-assignment
unrepresentable** (lines 766–780). 2c-2b must **realize** that disposition (S1),
not re-litigate it. *Verdict: the inherited architecture is migrated by
construction; the check confirms 2c-2b must add the parallel request type and
must NOT add a `TxRequest` variant.* Watch item for the rounds: ensure the new
request handler does not *reuse* `LedgerEngine` output selection over principal
outputs as a shortcut (that would re-introduce the cross-assignment the type
separation removes).

**SP-2.b — CARRIED CONTRADICTION (transport; explicitly to 2d, not accepted).**
The inherited broadcast / `get_fee_estimates` path uses the **principal's**
`DaemonEngine` connection. A shared connection "links `P` to the principal at
the network layer regardless of the request enum" (§11.1 Q3, lines 771–776) —
the §10.9 correlation the firewall exists to prevent. This is a *live*
inherited-architecture contradiction. Rule 16 requires it be **documented with
its disposition**, not silently inherited: the disposition is **migrate, in
2d** (`P`-isolated outbound `DaemonEngine`, §1.2). 2c-2b must therefore **not
wire broadcast at all** (S-out), so it cannot accidentally ship the shared-
transport flow. *Verdict: contradiction real, disposition = carry-to-2d with the
structural guard that 2c-2b lands no submission path.*

**SP-2.c — CONFIRMATION (RNG: inherited ad-hoc jitter would be wrong-for-
Shekyl).** Inherited code reaches for `OsRng` directly at call sites
(`sign.rs:17`, `sign_bridge.rs:14`). For the entry-seam timing draw, any
inherited `next_u64() % window` style jitter would carry **modulo bias**, and
"the bias would be privacy-load-bearing" (`draw.rs:1–7`). The migration is
already designed: the bond timing draw must route through the conformance-correct
`draw_entry_gap` (unbiased integer rejection sampling, float-free, cross-arch
bit-identical — `draw.rs:24–61`). *Verdict: confirmation — S4/S5/S6 must consume
`shekyl-standoff`, never an ad-hoc draw; the check forbids any inherited jitter
shortcut.*

**SP-2.d — CORRECTION (funding is two regimes; the firewall *decorrelates*
principal funding, it does not forbid it).** This finding's first draft asserted
funding must come from **`P`-local value, never principal outputs**. That is
**wrong at cold-start** and papers over the most acute principal↔`P` seam in the
whole design. A brand-new staker's **first** bond has **no `P`-earnings** to draw
on; `bond_floor` has nowhere else to come from, so the first bond **must** be
principal-funded. The firewall cannot forbid that — it **decorrelates** it, and
the §7 **≥ 1 settlement-epoch spacing** (S3) is *precisely that decorrelation
guard* (a SEB spacing is only meaningful if there is a principal→`P` funding link
to space). The corrected disposition splits funding into two regimes, each with
its own mechanism, to settle in Round 1:

- **Cold-start = principal-funded, ≥ 1-SEB-spaced + standoff-decorrelated.** This
  **does** touch principal-output selection; the SEB spacing (economic layer) +
  the standoff `draw_entry_gap` (timing layer) are the firewall guards that make
  it safe, not a prohibition. SP-2.d's clean "never principal" was true only for
  steady-state.
- **Steady-state = `P`-local earnings (fund-from-earnings ramp, ≥ 2 settlement
  epochs).** Presupposes a `P`-output set (SP-2.e).

*Verdict: correction, not confirmation — the §11.1 dispositions did not close
this; it is the Round-1 anchor question, sharper than "where does the `P`-funding
set come from." Taking the original SP-2.d literally either makes the first bond
**unfundable** or hides the seam that most needs the spacing discipline.*

**SP-2.e — MISSING DEPENDENCY (the `P`-output set does not exist yet; KAT must
use synthetic `P`-outputs).** S3's steady-state selection and the fund-from-
earnings ramp both presuppose a **`P`-local output set** (`P`'s reward UTXOs) and
≥ 2 settlement epochs of `P`-earnings history. That set exists only if there is
**`P`-output scanning** — `P`'s `view_sk` swept over the chain, the StakeEngine
scan-layer firewall (StakeEngine owns `P.view_sk`, disjoint from LedgerEngine,
the `combined_ss` recovery of §10.1). Substrate check at pin: `ArchivalPKeys`
**carries `view_sk`** (`shekyl-crypto-pq/src/archival_p.rs:332`) — the capability
— but **no `P`-scan pipeline is implemented**: the StakeEngine actor has only
mint/activate/active messages (`stake_engine.rs`), no `view_sk` sweep, no
`combined_ss` recovery, no `P`-earnings set anywhere in engine code. §10.1
describes the pipeline as *design*, not built. **Disposition:** 2c-2b's milestone
KAT runs over a **synthetic `P`-output set** (the same honesty posture as the
synthetic tree, arc §5 / §8), with real `P`-scanning **deferred to Bond-PR 2d-1,
the `P`-scan layer** (arc §2 / §3.6) — *not* a loose parallel to 2d but the
**foundation 2d-2's reconciliation also sits on** (one `P.view_sk` sweep, two
readers: this funding discovery and the reconcile). **Consequence — bounds
SP-2.d:** with no
`P`-output set, every bond 2c-2b can build is **effectively cold-start**, so
steady-state funding is **untestable except synthetically** this PR. Name the
split in Round 1: synthetic-`P`-outputs-for-the-KAT vs `P`-scanning-in-scope (it
is not 2c-2b-sized — it is the scan-layer firewall).

### 2.3 Verdict

The request-path architectural-inheritance check is **two confirmations
(SP-2.a, SP-2.c), one designed-out contradiction carried to 2d (SP-2.b), one
correction (SP-2.d), and one missing dependency (SP-2.e)**. The two clean
confirmations are consistent with rule 16's "PR 4 onward audits are increasingly
confirmations" — but the expectation **broke at the funding seam**, which is
exactly the value of weighting the firewall surface heavy rather than coasting on
2c-2a's clean surface (the "audits-are-clean-so-compress" anti-pattern this check
refused). SP-2.d corrected a finding that, taken literally, made the **first bond
unfundable**; SP-2.e surfaced that the steady-state funding source (`P`-scanning)
**is not built**, bounding what 2c-2b can test to synthetic `P`-outputs. The one
live contradiction (shared transport, SP-2.b) is structurally fenced by 2c-2b
shipping **no broadcast path** (§1.4 land-inert). The transport contradiction
(network layer) and the economic-correlation guard (SEB spacing, SP-2.d) are
**complements** — `draw_entry_gap` decorrelates *when* `P` acts, the SEB spacing
decorrelates the *funding link*, the isolated transport (2d) decorrelates *over
what link*. Net: the genesis-adjacent **firewall logic** (the funding-regime
design) must be right in 2c-2b; the **wiring** of both real sources is deferred.

---

## 3. Design-round scaffold (rounds 1–6, agenda only — adversarial)

Per the user's framing and rule 26 §"Part A" / `A3` (threat-model addenda is a
*late*-round discipline, R3–R4). Seeded questions, not closures:

1. **Round 1 (anchor) — the funding-regime design (design-now / wire-later).**
   The headline. Settle the **two-regime split** (SP-2.d): cold-start =
   principal-funded, ≥ 1-SEB-spaced + standoff-decorrelated; steady-state =
   `P`-local fund-from-earnings. Make the **design-now / wire-later** boundary
   explicit: the firewall *logic* (which regime, which guard, the SEB-spacing as
   the principal↔`P` decorrelation) is genesis-adjacent and must be right **now**;
   the two real sources are **deferred** — principal-output access (cold-start)
   and `P`-scanning (steady-state, SP-2.e). Name the KAT posture:
   **synthetic-`P`-outputs over 2c-1's `funded_ledger_and_tree`** vs
   `P`-scanning-in-scope (the latter is the scan-layer firewall, not 2c-2b-sized).
   Also: the `StakeEngine` bond-request message signature (mirrors
   `MintPersonaHandle` / `ActivatePersona`) and how `sign_bond` composes the
   `PersonaHandle` + `PersistedBondTicket`. *(Finding 5 — handle use-after-wipe —
   **retracted**: 2c-2a already ships the operation-scoped handle **and** the
   generation-counter invalidation, §3.4 / §4 of the arc; the composition just
   inherits that guarantee, it is not an open question.)*
2. **Round 2 — timing-seam types + which event each gates.** `NetworkGap(BlockSpan)`
   vs `EconomicSpacing(SebSpan)` as two newtypes with no cross-apply path
   (cross-apply = compile error). `BlockSpan` on `BlockCount`? `SebSpan` home
   (`shekyl-economics` vs `shekyl-units`). The types prevent *confusing* the two;
   the round must also **pin which governs which event** (finding 6) so the
   funding+timing composition is unambiguous: **`EconomicSpacing` gates the
   principal-funding-spend → bond-post interval** (the cold-start seam from
   Round 1); **`NetworkGap` gates the prep-spend / announce / bond-post events**
   (the standoff `draw_entry_gap(600)` window).
3. **Round 3 — RNG seams.** Live degeneracy guard (fail-loud) vs gated
   `certify_draw`; the `GapRng`-over-`OsRng` adapter; when each runs (per-draw
   vs per-session). Negative controls (`double_jitter_trap`, `correlated_walk`)
   prove the guard **bites** (assert it fires — S7(b)), not merely that the shapes
   exist.
4. **Round 4 — threat-model addenda (`A3`).** Named attacker objectives against
   the request path: cross-assignment via the new request, transport correlation
   (confirm 2c-2b ships none), economic correlation of funding, RNG degeneracy
   slipping past the live guard, persist-before-use bypass.
5. **Round 5 — audit-against-actual-code (`A2`) + show-your-work.** Every plan
   row re-pinned to `path:N–M` at the round-5 commit.
6. **Round 6 — closure + forward-action propagation (`A5`).** Confirm every
   carried item (2d transport, 2d reconcile, exit seam) has a target anchor.

---

## 4. Impl-time pre-flight pass (rule-26 Round 0 / `R0-D#`) — reserved, agenda

Runs **after** round 6 closes, **before** production commits (rule 26 §"Pre-
flight pass"). Two halves, agenda noted now so the rounds produce the artifacts
it will check:

- **Substrate re-check.** Re-read every disposition's cited substrate at the
  impl pin (the `stake_engine.rs` / `stake_persist.rs` / `draw.rs` /
  `conformance.rs` lines this doc cites; the §10.2 typed contracts).
- **Artifact execution + numeric reconciliation (`B6`/`B9`).** Open numeric
  claims to verify against substrate/measurement at that pass:
  - **`B6`: the 600-block entry-gap window has no named constant** — it lives
    only as test literals (`golden_vector.rs:19` `GOLDEN_WINDOW = 600`,
    `conformance_grading.rs` `window = 600u64`). 2c-2b must introduce a named
    wallet-default constant and reconcile it against the golden vector.
  - **`B6`: settlement-epoch / SEB / ramp constants** (`≥ 1` SEB spacing, `≥ 2`
    settlement epochs ramp — `ARCHIVAL_TIMING_CONSTANTS.md` §7 lines 253, 256)
    resolve through `config/consensus_constants.json` (§6.3); pin their values
    at the source line, not from the table prose.
  - **`B9`: `certify_draw` sample size `n`** vs CI wall-clock — pick `n` from the
    tolerance math (`conformance.rs:300–310`, `8/sqrt(n)`), measured, not
    estimated.

---

## Process notes

- **Branch / push.** `feat/archival-bond-request` is local only. Per
  `06-branching.mdc`, each push is separately authorized — no push without an
  explicit ask.
- **Gates before any "done" claim** (`45`/`50`): `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`; plus
  the persisted-schema snapshot (`42`) — **2c-2b should not bump
  `STAKING_BLOCK_VERSION`** (the format froze in 2c-2a; the `bonded_slots` hint
  semantics were chosen so 2d's GC needs no second bump — `stake_engine.rs:166–
  168`, FOLLOWUPS lines 949–951).
- **No C++.** Entire unit is Rust, advancing the FFI boundary inward
  (`20`/`25`); staking stays inside the Rust domain (no `SETTINGS_BLOCK_VERSION`
  perturbation — §10.2 store decision, lines 606–620).
