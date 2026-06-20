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
**Status:** **OPEN — scoping pre-flight closed; design rounds 1–6 closed; the
rule-26 impl-time pre-flight (`R0-D1`–`R0-D4`, §4.1) closed (2026-06-19). All
design + reconciliation gates met; remaining before merge is the rule-45/50
workspace gate sweep + the substrate re-check, then PR.**

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
| S1 | **Parallel StakeEngine JoinMarket bond request type** — a typed-separate request to the StakeEngine actor, *not* a `TxRequest` variant, so bond construction never threads the `LedgerEngine` transfer pipeline (cross-assignment unrepresentable). | §11.1 Q3 (CLOSED, lines 766–780); §9.6/§10.1 | `SignBond` message on `StakeEngine` (`stake_engine.rs:662`, landed) alongside `MintPersonaHandle` / `ActivatePersona` (`stake_engine.rs:539,572`). Consumes `PersonaHandle` (`stake_engine.rs:247`). Drives `build_join_market_vin` (`shekyl-archival-bond-builder/src/lib.rs:109`). *(Round-5 re-pin §3.5(b)/(c).)* |
| S2 | **`sign_bond(ticket: PersistedBondTicket, …)`** — the consumer half of the persist-before-use typestate; sign-before-persist is uncallable (no ticket to pass). | §10.2 typed contract #1 (lines 567–582); `stake_persist.rs:22–27,70` | Consumes `PersistedBondTicket` **by value** (`stake_persist.rs:70`, `!Clone`) via `SignBond.ticket` (`stake_engine.rs:662`). Producer `Engine::persist_bond_record` (`stake_persist.rs:138`) landed + tested. *(Round-5 re-pin §3.5(b).)* |
| S3 | **Funding-selection *design* (design-now / wire-later)** — settle the two-regime split: cold-start = principal-funded, ≥ 1-SEB-spaced + standoff-decorrelated; steady-state = `P`-local fund-from-earnings ramp (≥ 2 settlement epochs). **The genesis-adjacent firewall *logic* lands now; neither real funding source is wired** (principal-output access and `P`-scanning both deferred — SP-2.d / SP-2.e). Selection logic is **fixture-validated** over Bond-PR 2c-1's `funded_ledger_and_tree`, not real sources. | §10 (lines 454–456); `ARCHIVAL_TIMING_CONSTANTS.md` §7 (lines 253, 256) | `verify_credit_funding` (`builder/src/lib.rs:173`) is the amount-level invariant the selection must satisfy. Consumes economics SEB/epoch constants (B6, §4). |
| S4 | **Two typed timing seams** — `NetworkGap(BlockSpan)` (`draw_entry_gap(window=600)`) vs `EconomicSpacing(SebSpan)` (≥ 1 SEB / ramp); cross-apply is a **compile error**. Entry seam only; exit seam deferred to the unbond slice. | §10 (line 457–462); FOLLOWUPS (lines 914–917) | **Landed** in `stake_timing.rs`: `BlockSpan:81`, `SebSpan:98`, `NetworkGap:111`, `EconomicSpacing:137`, `DEFAULT_ENTRY_GAP:152` (typed `NetworkGap`; renamed from `…_WINDOW` to avoid collision with raw `shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW`, PR #163 re-review), `MIN_COLD_START_SPACING:166`; accessors `BlockSpan::as_u64:86` / `NetworkGap::as_blocks:118`. All are crate-local `pub(crate)` `u64` newtypes — `BlockSpan` is **standalone, not** built on `shekyl-types::BlockCount` (Round 2 §3.2; rule-18 promote-on-second-consumer). *(Round-5 §3.5(c)/(d).)* |
| S5 | **Live RNG degeneracy check (float-free, fail-loud)** — the cheap integer-only guard, distinct from the statistical self-cert. | §10 (lines 457–462); FOLLOWUPS (line 917–918) | Runs against `draw_entry_gap` output (`shekyl-standoff/src/draw.rs:57`). Negative-control shapes already exist: `draw_entry_gap_double_jitter_trap` (`conformance.rs:135`), `correlated_walk` (`conformance.rs:208`). |
| S6 | **`certify_draw` self-cert against the shipping wallet's CSPRNG (gated)** — proves the *shipping wallet's RNG* produces conformant draws, not merely the reference. | §10 (lines 457–462) | `certify_draw` (`conformance.rs:377`) over a `GapRng` (`draw.rs:13`) adapter on `rand_core::OsRng` (the shipping CSPRNG — `shekyl-tx-builder/src/sign.rs:17`, `engine/sign_bridge.rs:14`). |
| S7 | **Request-path composition KAT + own-surface negatives.** Accept: mint handle → `persist_bond_record` → `sign_bond` → `build_join_market_vin` → verify, over 2c-1's `funded_ledger_and_tree` fixture. **Not** a new prover round-trip (closed by Bond-PR 2a #156 / 2c-1 #158 — arc §5; the prove-half tampering negatives — wrong `bond_credit`, tampered commitment/preimage, replay — live in 2a). 2c-2b's **new** failure surfaces, all uncovered upstream, must be asserted here: **(a)** funding violating `verify_credit_funding` is rejected; **(b)** the RNG degeneracy guard **fires** on a degenerate draw (assert it bites, via the `double_jitter_trap` / `correlated_walk` controls, not just that the shapes exist); **(c)** ~~`trybuild` **compile-fail** tests~~ **→ RETIRED, replaced by an in-crate `!Clone` guard (§4.1 `R0-D1`)**: the tokens are `pub(crate)` with module-private fields, so `trybuild` (external crate) cannot reach them without re-exposing firewall internals; the unrepresentability is type-system-enforced unconditionally, and the `!Clone` half is pinned by an always-on `const _` guard verified to bite. Real-tree verify half stays `#[ignore]`/CT-5-gated. | arc §5; §11.1 Q4 (lines 782–789); FOLLOWUPS (lines 918–924); §4.1 `R0-D1`; §4 typed contracts | Builder dev-deps `shekyl-archival-retention` verify path. No `trybuild` dep (retired). |

### 1.2 Explicitly out of scope (carried to PR 2d, `A5` forward-action)

| Out | Why deferred | Forward anchor |
| --- | --- | --- |
| Broadcast / re-anchor wiring | Activates the CT-5d persona-pin (re-sign on fee/change drift). 2c-2b lands **no submission** — §10.2 CT-5d note (lines 650–667): "2c-2 lands no submission, so this does not execute yet." | FOLLOWUPS lines 954–955; `CT5D_REANCHOR.md` |
| `arti-client` `P`-isolated outbound transport | §11.1 Q3's residual: shared connection links `P` to principal at the network layer "regardless of the request enum" (lines 682–694). The request type isolates *construction*; transport isolation is a separate security-critical pre-flight. | FOLLOWUPS lines 925–928 |
| **`P`-scan layer** (the `P.view_sk` sweep; SP-2.e) | Not 2c-2b-sized — it is the scan-layer firewall (StakeEngine owns `P.view_sk`). The capability exists (`archival_p.rs:332`) but no pipeline is built. **One sweep, two readers**: steady-state funding-output discovery **and** the reconcile below. | **Bond-PR 2d-1** (arc §2 / §3.6) |
| 2d full-scan reconciliation of `bonded_slots` / `p_slot` | Chicken-and-egg: the reconcile needs personas derived first (scan posted + `consumer_held`), so it is post-derive — **it sits on top of the 2d-1 `P`-scan above** (cannot reconcile bonds it has not scanned for). `bonded_slots` stays a reconcilable hint; **no second `STAKING_BLOCK_VERSION` bump** (`stake_engine.rs:173`). | **Bond-PR 2d-2** (depends on 2d-1); FOLLOWUPS lines 945–953 (rule-21 reopen) |
| Exit timing seam (unbond) | S4 ships the **entry** seam only. | §10 (line 457–462) |
| Intra-call parallel keygen across the `k`-bounded union | Perf follow-up, not correctness — derivation cost relocated to `assemble()` (`lifecycle.rs:689`; derive-forward loop `:909`). | §10.2 perf note (lines 669–680) |

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
until 2d's reconciliation/GC exists (`stake_engine.rs:173`,
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

- **Cold-start = principal-seeded, amount-decoupled, ≥ 1-SEB-spaced +
  standoff-decorrelated.** The SEB spacing + standoff `draw_entry_gap` decorrelate
  **when** `P` acts — but **timing decorrelation is not enough**: spacing does
  nothing for **amount** or **membership-set**, and a principal spend of a
  `bond_floor`-shaped amount at a distinctive moment **fingerprints the link on
  the amount** regardless of how well-spaced it is. The fix is to **amount-decouple
  the cold-start**: the principal makes a **generic** transfer to `P` (an
  unremarkable amount), `P` **holds** it, and posts the bond **later, from its own
  holdings** — so the bond's `bond_floor`-shaped spend originates from a `P` UTXO,
  **not** from a principal spend shaped like `bond_floor`. That converts one
  linkable event ("principal spends bond-shaped amount → `P` posts", linkable on
  amount **and** timing) into **two unremarkable events**. Cold-start therefore
  carries **three** guards — amount-decoupling, SEB spacing, standoff timing — not
  just the SEB spacing. **Feasibility note (interacts with SP-2.e):** the
  cold-start funding output is a **self-payment** — the wallet owns both the
  principal and `P`, so it **knows** the seeding UTXO without scanning. So
  amount-decoupling is implementable in 2c-2b **even with `P`-scanning deferred**;
  it is *third-party* `P`-earnings (steady-state) that need the 2d-1 scan, not the
  principal's own seed. (SP-2.d's clean "never principal" was wrong; the corrected
  shape is "principal **seeds** at cold-start, amount-decoupled and decorrelated.")
- **Steady-state = `P`-local earnings (fund-from-earnings ramp, ≥ 2 settlement
  epochs).** Presupposes a *third-party*-populated `P`-output set → the 2d-1
  `P`-scan (SP-2.e).
- **Sim obligation (Round 4 / `STAKER_ARCHIVAL_SIM`).** Model the cold-start
  funding event against **amount and membership-set adversaries**, not only
  timing — it is the single most correlatable event in `P`'s life, so all three
  dimensions belong in the adversary model.

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
3. **Round 3 — RNG seams (output *and* source).** Live degeneracy guard
   (fail-loud) vs gated `certify_draw`; the `GapRng`-over-`OsRng` adapter; when
   each runs (per-draw vs per-session). Negative controls (`double_jitter_trap`,
   `correlated_walk`) prove the guard **bites** (assert it fires — S7(b)), not
   merely that the shapes exist. **Source failure, not only statistical
   degeneracy:** the degeneracy guard checks the draw's *distribution*, but
   `OsRng` can *fail* (early boot, seccomp blocking the syscall, exhausted
   entropy). Use the **fallible** path (`try_fill_bytes`), treat a source error as
   **fail-loud-refuse** at the same altitude as the degeneracy guard, and — the
   part that actually bites — **audit that there is no silent fallback RNG**
   anywhere in the draw path: the catastrophic case is not the source erroring, it
   is a **fallback to a weaker source** on that error.
4. **Round 4 — threat-model addenda (`A3`).** Named attacker objectives against
   the request path: cross-assignment via the new request, transport correlation
   (confirm 2c-2b ships none), economic correlation of funding, RNG degeneracy
   slipping past the live guard, persist-before-use bypass.
5. **Round 5 — audit-against-actual-code (`A2`) + show-your-work.** Every plan
   row re-pinned to `path:N–M` at the round-5 commit.
6. **Round 6 — closure + forward-action propagation (`A5`).** Confirm every
   carried item (2d transport, 2d reconcile, exit seam) has a target anchor.

### 3.1 Round 1 findings — CLOSED (2026-06-19)

**Funding-regime design (SP-2.d, design-now / wire-later) — SETTLED.**

The regime selector is typed; neither real source is wired in 2c-2b.

- **Cold-start** (principal-seeded): principal makes a generic transfer to `P`
  (amount-decoupled), `P` holds, `P` posts from its own UTXO.
  `EconomicSpacing(SebSpan(≥ 1))` gates the principal→`P` transfer →
  bond-post interval (the cold-start decorrelation guard).
  `NetworkGap(BlockSpan(600))` gates the standoff draw inside the
  bond-post event. **Real source deferred:** actual principal-output
  selection is wire-later.
- **Steady-state** (`P`-local fund-from-earnings): requires the `P`-scan
  pipeline (Bond-PR 2d-1). **Real source deferred** (SP-2.e).
- Both regimes: the bond-post funding UTXO originates from a
  `P`-held output; `verify_credit_funding` is the amount invariant
  regardless of regime.
- **KAT posture:** synthetic `P`-holdings over `funded_ledger_and_tree`;
  regime selector exercised with fixtures only, no real source wired.

**`SignBond` message signature — SETTLED.**

```rust
pub(crate) struct SignBond {
    pub handle: PersonaHandle,        // validates slot is held + generation current
    pub ticket: PersistedBondTicket,  // validates persist happened before sign
    pub holdings: HoldingsDescriptor, // for bond_floor computation
    pub tx_prefix_hash: [u8; 32],     // binds signature to this transaction
}

impl Message<SignBond> for StakeEngine {
    type Reply = Result<JoinMarketVin, StakeEngineError>;
    // handler: validate_handle → slot-cross-check → source-preflight →
    //          entry-gap draw + degeneracy guard → build_join_market_vin
}
```

New `StakeEngineError` variants: `RngSourceFailed`, `RngDegeneracy`,
`SlotMismatch { handle_slot, ticket_slot }`, `BondBuild(BondBuildError)`.

`SignBond` does **not** advance the rotation generation — signing does not
rotate the active slot or wipe any persona.

Caller workflow (two handle mints — handles are single-use, per §10.2 #2):

1. `mint_handle(slot)` + `activate_persona(handle1)` → sets active slot.
2. `Engine::persist_bond_record(slot)` → `PersistedBondTicket` (durable).
3. `mint_handle(slot)` + `sign_bond(handle2, ticket, holdings, hash)` → `JoinMarketVin`.

**Finding 5 retraction — CONFIRMED.**
`PersonaHandle` use-after-wipe is unexpressible in the 2c-2a substrate:
rotation advances `generation` → `StaleHandle` on stale handle; wiped
persona removed from `held` → membership check fails. 2c-2b inherits
this guarantee without additional machinery.

---

### 3.2 Round 2 findings — CLOSED (2026-06-19)

**Timing-seam type homes — SETTLED.**

- `BlockSpan(u64)` — lives in `shekyl-engine-core::engine::stake_timing`
  (sole consumer in scope; promotion to `shekyl-types` is a reversion-clause
  item for when a second consumer emerges).
- `SebSpan(u64)` — lives in `shekyl-engine-core::engine::stake_timing`
  for the same reason.
- `NetworkGap(BlockSpan)` and `EconomicSpacing(SebSpan)` — role-wrapper
  newtypes in `stake_timing`; cross-apply is a compile error (distinct inner
  types).
- `DEFAULT_ENTRY_GAP: NetworkGap` (named `…_WINDOW` at design time; renamed in
  PR #163 re-review to avoid colliding with the raw standoff const) —
  named constant, closes B6 (no unnamed 600 literal in callers).
- `MIN_COLD_START_SPACING: EconomicSpacing = EconomicSpacing(SebSpan(1))` —
  names the cold-start guard value; real ledger-elapsed check is wire-later.

**Which seam each gates (finding 6 close-out) — SETTLED.**

- `NetworkGap` gates: `draw_entry_gap` standoff window (block-level timing
  for the prep-spend / announce / bond-post sequence inside the `SignBond`
  handler).
- `EconomicSpacing` gates: principal→`P` seed transfer → bond-post interval
  (cold-start decorrelation; elapse ≥ 1 SEB between events). Design-now as
  the named constant; real elapsed check deferred to cold-start wiring.

New `shekyl-engine-core` production deps required: `shekyl-standoff`
(for `GapRng` + `draw_entry_gap`) and `shekyl-archival-bond-builder` (for
`build_join_market_vin` inside `SignBond` handler — promotes from dev-dep).

---

### 3.3 Round 3 findings — CLOSED (2026-06-19)

**RNG seams — SETTLED.**

*Source failure (fail-loud, no silent fallback):*
`OsRng::try_fill_bytes` preflights the entropy source before drawing.
A source error maps to `StakeEngineError::RngSourceFailed` (terminal for
the request). No silent fallback to a weaker source anywhere in the draw
path — the catastrophic failure is a weaker-source *silent* fallback, not
the source erroring (a panic or error is loud). The TOC-TOU between
preflight and draw is accepted: a source that is alive at preflight and
then dies mid-draw triggers the actor's fail-stop (panic = loud). The
`GapRng::next_u64` trait is infallible by design; introducing source
failure into it would require changing `shekyl-standoff`'s API — deferred
per the reversion clause if a specific need emerges.

*Per-draw degeneracy guard (float-free, fail-loud — S5):*
After the entry-gap draw, one probe draw is taken from the same RNG adapter.
If `spread_draw == spread_probe`, the guard fires `StakeEngineError::RngDegeneracy`.
This catches the double-jitter-trap degenerate pattern with probability
≈ 1 per 601 for a correct CSPRNG (acceptable false-positive rate; a bond
retry is cheap). The guard is extracted into a tested helper
`draw_entry_gap_guarded(window, rng)` so the degeneracy logic is unit-tested
with injectable degenerate RNGs (conformance-gated, not injected into the
live actor).

*Session-level self-cert (S6 — `certify_draw`, gated):*
`certify_draw` over `GapRng`-adapted `OsRng` runs at session start, gated
(not per-draw). Catches the correlated-walk pattern that per-draw
comparison cannot detect (requires lag-1 autocorrelation over ≥ n draws,
float-bearing — `conformance` feature, not shipped into production builds).

*Adapter — `OsRngGapAdapter`:*
A private struct in `stake_engine.rs` implementing `GapRng` via
`OsRng::next_u64()`. Single-method, no state. Tests use conformance-module
degenerate-RNG fixtures via the `draw_entry_gap_guarded` helper directly.

---

### 3.4 Round 4 findings — CLOSED (2026-06-19)

**JoinMarket funding-time mixing — verified at source (R0-D# substrate check).**

Verified `shekyl-archival-bond-builder/src/lib.rs` and
`ARCHIVAL_BOND_CONSTRUCTION.md` §5 / §7:

- `build_join_market_vin` produces a **pure credit path**:
  `bonded_total_atomic == bond_credit == bond_floor(holdings)`, `bond_debit == 0`.
- **No mixing occurs at funding time.** JoinMarket is the bond-post type, not a
  collaborative mixing pool: the `bond_credit` value rides the **cleartext
  output side** as an `OutputTerm`. Amount concealment occurs only inside the
  RCT commitment structure (FCMP++ pseudoOuts) at transaction-build time.
- The "join" in JoinMarket names the archival market entry, not amount-joint
  obfuscation across stakers' funding inputs.

**Consequence for S3: self-cover IS the primary mechanism (not a fallback).**

JoinMarket does not provide any funding-time amount mixing across stakers, so
there is nothing structural to route the cold-start principal→`P` funding
transfer through. Self-cover is therefore the primary — and only — protocol-
layer amount decorrelation mechanism at the cold-start funding step.

**Cold-start cover architecture — SETTLED (SP-2.d close-out).**

Design: principal sends `bond_floor + cover`, P stakes the floor
(`bond_credit`), holds the cover as working capital. The change-to-P output
carries the cover amount; `verify_credit_funding`'s `output_total` parameter
naturally includes it (no change to the check).

Properties of this design:

1. **Net principal→P flow is never a clean bond value.** Observer sees
   `bond_floor + cover`, not `bond_floor`. Amount correlation from a known-
   principal spend to the bond post requires guessing the cover amount.
2. **No refund stream.** Refunding the cover produces a distinct outbound
   transfer from P that can be envelope-correlated against the bond-post
   inbound. Cover-stays-with-P eliminates that correlation surface.
3. **Cover seeds P's fund-from-earnings pool.** The cover amount becomes P's
   working capital — the same pool steady-state funding draws on. For a
   committed staker, "over-fund at bootstrap, excess becomes stake capital" is
   strictly better than "over-fund, then leak it back in pieces."
4. **Cover recommendation lives in GUI/CLI.** The engine accepts `CoverAmount`
   as an input; the recommended random value is computed and presented by the
   front-end (not by the engine). The engine imposes no floor (zero cover is
   valid; it is the opt-in stake-only path, see below).

**Opt-in cover recovery — explicit privacy cost, independently timed.**

If a staker wants to recover the cover later ("stake-once-and-recover"), this
is a legitimate need but must be opt-in and explicitly disclosed:

- **Disclosed privacy cost.** Recovery re-creates the principal→P link: any
  outbound P→principal transfer is combinable with the original inbound
  principal→P to reconstruct the net flow, confirming the linkage an observer
  might have suspected. The GUI/CLI must warn the user at opt-in time.
- **Independently timed.** The recovery transfer must not be tied to the bond
  lifecycle (not at bond-post, not at unbond); it must be a separate,
  independently-timed generic transfer to minimize temporal correlation.
- **Not the default.** The default path (cover-stays-with-P) never produces a
  recovery transfer. Opt-in cover recovery is a named, separately gated
  operation; it does not share code paths with the bond request or unbond.

**`CoverAmount` — design-now type, wire-2d.**

A typed `CoverAmount(AtomicUnits)` is defined in `stake_timing.rs` as the
design-now provision (the inner value is the canonical `shekyl_units::AtomicUnits`
money newtype, not a bare `u64` — unit-safe and composable with the funding
path; settled in the PR #163 re-review). The type gates the bond-request
orchestration layer (2d), not `SignBond` (the bond VIN carries `bond_floor`
only; cover is a P-change output in the surrounding transaction).
`CoverAmount::ZERO` (= `AtomicUnits::ZERO`) is the stake-only constant for
callers that do not cover.

---

### 3.5 Round 5 findings — audit-against-actual-code (`A2`) — CLOSED (2026-06-19)

The code now exists (`feat/archival-bond-request` at `783d77db9`). This round
re-pins every plan-row citation to the round-5 substrate and records the
deltas. **Method:** `grep -nE` each cited symbol at HEAD, compared to the
design-time pin. No claim is restated from memory.

**(a) Cross-crate pins — UNCHANGED.** 2c-2b touched only `shekyl-engine-core`,
so every citation into `shekyl-archival-bond-builder`, `shekyl-standoff`, and
`shekyl-archival-retention` holds at its design-time line:

| Symbol | Pin | Status |
| --- | --- | --- |
| `build_join_market_vin` | `builder/src/lib.rs:109` | ✓ unchanged |
| `verify_credit_funding` | `builder/src/lib.rs:173` | ✓ unchanged |
| `JoinMarketVin` | `builder/src/lib.rs:68` | ✓ unchanged |
| `draw_entry_gap` | `shekyl-standoff/src/draw.rs:57` | ✓ unchanged |
| `GapRng` | `shekyl-standoff/src/draw.rs:13` | ✓ unchanged |
| `draw_entry_gap_double_jitter_trap` | `conformance.rs:135` | ✓ unchanged |
| `correlated_walk` | `conformance.rs:208` | ✓ unchanged |
| `certify_draw` | `conformance.rs:377` | ✓ unchanged |
| tolerance math `8/sqrt(n)` | `conformance.rs:301–309` | ✓ (plan said 300–310) |
| `OsRng` (tx-builder) | `shekyl-tx-builder/src/sign.rs:17` | ✓ unchanged |
| `OsRng` (sign_bridge) | `engine/sign_bridge.rs:14` | ✓ unchanged |
| `HoldingsDescriptor` / `HoldingsKind` | `retention/src/bond_wire.rs:64,48` | ✓ (precise pin) |

**(b) Engine-core pins — SHIFTED by 2c-2b insertions.** Re-pinned to HEAD:

| Symbol | Design-time pin (2c-2a) | Round-5 pin |
| --- | --- | --- |
| `PersonaHandle` | `stake_engine.rs:241` | `stake_engine.rs:247` |
| `MintPersonaHandle` | `stake_engine.rs:488` | `stake_engine.rs:539` |
| `ActivatePersona` | `stake_engine.rs:521` | `stake_engine.rs:572` |
| `bonded_slots` reconcilable-hint note | `stake_engine.rs:173` | `stake_engine.rs:173,393` |
| `PersistedBondTicket` typestate doc | `stake_persist.rs:25–27` | `stake_persist.rs:22–27` |
| `PersistedBondTicket` struct | `stake_persist.rs:70` | `stake_persist.rs:70` (✓) |
| `Engine::persist_bond_record` | `stake_persist.rs:125` | `stake_persist.rs:138` |
| `assemble()` derive-forward loop (perf note) | `lifecycle.rs:867–873` | `lifecycle.rs:689` (fn), `:909` (derive loop) |

**(c) New code created by 2c-2b — plan rows that said "none exist yet / to
wire" now have substrate.** Pin them here so the doc is no longer forward-
looking on these:

| Symbol | Round-5 pin |
| --- | --- |
| `SignBond` message | `stake_engine.rs:662` |
| `StakeEngineHandle::sign_bond` | `stake_engine.rs:905` |
| `draw_entry_gap_guarded` helper | `stake_engine.rs:783` |
| `OsRngGapAdapter` | `stake_engine.rs:750` |
| `PersistedBondTicket::__test_only_forge` (cfg(test)) | `stake_persist.rs:94` |
| `BlockSpan` (+ `as_u64:86`) | `stake_timing.rs:81` |
| `SebSpan` | `stake_timing.rs:98` |
| `NetworkGap` (+ `as_blocks:118`) | `stake_timing.rs:111` |
| `EconomicSpacing` | `stake_timing.rs:137` |
| `DEFAULT_ENTRY_GAP` (B6 close; renamed in PR #163 re-review) | `stake_timing.rs:152` |
| `MIN_COLD_START_SPACING` | `stake_timing.rs:166` |
| `CoverAmount(AtomicUnits)` / `CoverAmount::ZERO` | `stake_timing.rs:66,71` |

**(d) Design-time speculation RETIRED.** S4's row reads "*`BlockSpan` likely
rests on `shekyl-types::BlockCount` (`shekyl-types/src/lib.rs:181–247`)*." This
was a placement guess that **Round 2 already overruled**: `BlockSpan` ships as a
standalone `pub(crate) struct BlockSpan(pub u64)` (`stake_timing.rs:72`), not
built on `BlockCount`. `BlockCount` does exist (macro-generated in
`shekyl-types`, the relative-block-span `Duration`-analogue — `lib.rs:31`), but
`BlockSpan` does not depend on it; the rule-18 placement settled at "crate-local
newtype, promote on a second consumer" (§3.2). The S4 cell is corrected below.

**(e) Outcome.** No claim in §§1–3 is falsified by the substrate. The only
correction is the retired S4 placement speculation (d); everything else is a
pure line-number shift from inserting ~530 lines of new code into
`stake_engine.rs` / `stake_persist.rs` / `stake_timing.rs`. The §1.1 scope
table and the §"Process notes" pins are updated in place to the round-5 lines.

---

### 3.6 Round 6 findings — closure + forward-action propagation (`A5`) — CLOSED (2026-06-19)

Confirms every carried item has a live target anchor, and propagates the
forward actions that **implementation created** (not visible at design time)
into `docs/FOLLOWUPS.md`.

**(a) §1.2 carried items — every one resolves to a live anchor (verified at
`docs/FOLLOWUPS.md` HEAD).**

| Carried item | Anchor | Verified |
| --- | --- | --- |
| Broadcast / re-anchor wiring | FOLLOWUPS §"StakeEngine Model D wiring" → "Broadcast / re-anchor wiring activates the CT-5d persona-pin"; `CT5D_REANCHOR.md` | ✓ present |
| `arti-client` `P`-isolated transport | FOLLOWUPS "PR 2d" `arti-client` security-critical pre-flight | ✓ present |
| `P`-scan layer (SP-2.e) | Bond-PR 2d-1 (arc §2 / §3.6); `archival_p.rs:332` capability | ✓ present |
| 2d full-scan reconciliation | FOLLOWUPS "2d full-scan reconciliation of `bonded_slots` / `p_slot`" (rule-21 reopen) | ✓ present |
| Exit timing seam (unbond) | §10 (line 457–462); unbond slice | ✓ named |
| Intra-call parallel keygen (perf) | FOLLOWUPS "Intra-call parallel persona derivation (perf)"; §10.2 perf note | ✓ present |

**(b) Implementation-created forward actions — NEWLY propagated to FOLLOWUPS.**
These were not design-time deferrals; they emerged when 2c-2b code landed and
chose design-now / wire-later boundaries. A new FOLLOWUPS top-level bullet,
"Archival bond request path — deferred items (PR 2c-2b, landed inert
2026-06-19)," now anchors all four:

| New forward action | Why deferred | Target |
| --- | --- | --- |
| **S6 `certify_draw` session self-cert wiring** | Live degeneracy guard ships; the stronger session-level statistical check needs a session-start lifecycle hook the actor does not have yet (`TODO(S6)` ×2 in `stake_engine.rs`). | V3.0 (RNG gate, not consensus-frozen) |
| **S7(c) `trybuild` compile-fail tests** | Unrepresentability asserted today by `!Clone`/by-value types + runtime negatives; compile-fail proofs need the `trybuild` dev-dep. | 2c-2b merge (test-completeness, not a forward PR) |
| **`CoverAmount` bond-tx orchestration** | Type ships inert; the `bond_floor + cover` send + `P`-change threading lands with 2d bond-transaction assembly. | V3.0 (cold-start decorrelation, genesis-adjacent) |
| **Opt-in cover recovery (GUI/CLI)** | Stake-once-and-recover re-creates the principal↔`P` link; must be a separately-gated, independently-timed, disclosed GUI/CLI op, never the default. | V3.x (post-launch UX) |

**(c) Roadmap-bullet correction.** The pre-implementation FOLLOWUPS roadmap
listed `certify_draw` self-cert and the full KAT as landing *in* 2c-2b. That
phrasing is corrected: 2c-2b settles their **design** and defers the **wiring**
(certify_draw session hook) / **completeness** (trybuild). The amendment points
forward to the new deferred-items bullet so the audit trail is single-sourced.

**(d) Outcome.** No carried item is anchorless; no implementation-created
deferral is untracked. The scope boundary is closed: 2c-2b consumes exactly the
2c-2a inert surface and defers exactly the 2d-anchored items plus the four newly-
propagated wire-later actions. Rounds 1–6 are closed; the only remaining gate is
the rule-26 impl-time pre-flight (`R0-D#`, §4 below) before production-merge.

---

## 4. Impl-time pre-flight pass (`R0-D#`)

Runs **after** round 6 closes, **before** production commits (rule 26 §"Pre-
flight pass"). Two halves, agenda noted now so the rounds produce the artifacts
it will check:

- **Substrate re-check.** Re-read every disposition's cited substrate at the
  impl pin (the `stake_engine.rs` / `stake_persist.rs` / `draw.rs` /
  `conformance.rs` lines this doc cites; the §10.2 typed contracts).
- **Artifact execution + numeric reconciliation (`B6`/`B9`) — CLOSED.** All
  three numeric claims are now reconciled against substrate/measurement (see
  §4.1 findings):
  - **`B6` entry-gap window → `R0-D2` (single-sourced).** The 600 literal,
    formerly triplicated, now resolves through `shekyl-standoff`'s
    `pub const DEFAULT_ENTRY_GAP_WINDOW = 600`; the golden vector and the wallet
    both reference it, and a drift fails `golden_vector_is_bit_identical`.
  - **`B6` SEB/ramp constants → `R0-D3` (reconciled).** `MIN_COLD_START_SPACING`
    (1 SEB) = "≥ 1 settlement epoch"; SEB length `settlement_epoch_blocks = 10000`
    is consensus (`config/consensus_constants.json:19`); ramp deferred (SP-2.e).
  - **`B9` `certify_draw` sample size → `R0-D4` (pinned + measured).** `n =
    200_000`, `tolerance ≈ 0.0179`, wall-clock **~14–15 ms** (debug, incl.
    startup); production call site rides the deferred S6 hook.

### 4.1 Closed findings

**`R0-D1` — S7(c) `trybuild` compile-fail tests RETIRED; replaced by an
in-crate `!Clone` guard (2026-06-19).** *Substrate falsifies the design.*

The plan (§1.1 S7, S7(c)) specced `trybuild` compile-fail tests proving the
unrepresentability claims (`sign_bond` without a `PersistedBondTicket`; a
`PersonaHandle` for an unheld slot). The substrate makes this **the wrong
tool**:

- `SignBond`, `PersonaHandle`, `PersistedBondTicket`, and the whole
  `stake_engine` / `stake_persist` surface are `pub(crate)`
  (`engine/mod.rs:234,239`); the capability tokens' identifying fields are
  **module-private** (`PersonaHandle.{p_slot,generation}` `stake_engine.rs:248–249`;
  `PersistedBondTicket.p_slot` `stake_persist.rs:74`).
- `trybuild` compiles each case as an **external** crate (verified against the
  one workspace precedent, `shekyl-logging/tests/trybuild.rs`, which tests only
  the `pub` API). An external crate cannot **name** these `pub(crate)` types
  without a re-export — and a re-export would re-expose the firewall internals
  S1/S2 exist to encapsulate. A test that needs to weaken the property it
  asserts is no test.

**Resolution.** The unrepresentability is already enforced unconditionally by
the type system — module-private fields (no constructor outside the defining
module) + `!Clone` + by-value consumption in `sign_bond`
(`stake_engine.rs:907–908`). That is stronger than any external snapshot (holds
for *all* code, not one example). The `!Clone` half — the only half a careless
edit could silently weaken via `#[derive(Clone)]` — is now pinned by an
**always-on, zero-cost, dependency-free** compile-time guard
(`stake_engine.rs`, the `const _: fn()` block after `PersonaHandle`; the inlined
equivalent of `static_assertions::assert_not_impl_all!`). Verified to bite:
deriving `Clone` on either token makes the guard's `AmbiguousIfImpl` resolution
ambiguous (`E0283`) and fails the build. The runtime negatives (slot-mismatch,
degeneracy-guard-fires) remain the coverage for the cross-check and RNG surfaces.

**Reversion clause (rule 21).** Reopen the `trybuild` path **iff** these tokens
ever become `pub` for an independent reason (then an external crate can name
them without a bespoke re-export, and `trybuild` snapshots become free). No such
need is known.

**`R0-D2` — B6a: the 600-block entry-gap window is now single-sourced
(2026-06-19).** *Numeric reconciliation + drift-guard.*

At design time the `600` window was three independent literals
(`golden_vector.rs:19`, `conformance_grading.rs:175,237`, and the new
`stake_timing::DEFAULT_ENTRY_GAP`, named `…_WINDOW` then). They agreed at `600`,
but nothing
*enforced* the agreement: the golden vector guards the draw **algorithm**, not
the wallet-window-vs-certified-window gap — a change to `stake_timing`'s literal
would not have failed any test. Per `shekyl-standoff`'s own single-source
doctrine ("the simulator, the published conformance vector, and the wallet all
import the same `draw_entry_gap`"), the **value** is now single-sourced too:

- `shekyl-standoff` exports `pub const DEFAULT_ENTRY_GAP_WINDOW: u64 = 600`
  (`src/draw.rs`), re-exported at the crate face (`src/lib.rs`).
- `golden_vector.rs` sources `GOLDEN_WINDOW` from the const (not a literal).
- `stake_timing::DEFAULT_ENTRY_GAP: NetworkGap` wraps the shared const:
  `NetworkGap(BlockSpan(shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW))` (the typed
  wrapper was renamed off `…_WINDOW` in the PR #163 re-review so it cannot be
  confused with the raw scheme const it wraps).

**Verified to bite cross-crate:** flipping the const to `601` re-draws and fails
`golden_vector_is_bit_identical`. Value unchanged (`600`) → frozen vector stays
bit-identical; `cargo test -p shekyl-engine-core` (318) + `-p shekyl-standoff`
green; fmt + clippy clean. The Round-2 placement (the typed `NetworkGap` lives
in `stake_timing`) is preserved — only the raw `u64` moved to the scheme's home.

**`R0-D3` — B6b: cold-start SEB spacing reconciled (2026-06-19).** *Unit
reconciliation.* `MIN_COLD_START_SPACING = EconomicSpacing(SebSpan(1))` matches
`ARCHIVAL_TIMING_CONSTANTS.md` §7 "Min spacing join-Market ↔ principal spend:
≥ 1 settlement epoch" (gate-6 R4). The split is now explicit in the const's doc:
the **count** (1 SEB) is wallet policy; the SEB **length**
(`settlement_epoch_blocks = 10000`) is consensus
(`config/consensus_constants.json:19`). The `SebSpan → blocks` elapsed check
(`1 × settlement_epoch_blocks`) is wire-later with the cold-start funding source
(SP-2.d, deferred). The steady-state ramp (`≥ 2 settlement epochs`,
`ARCHIVAL_TIMING_CONSTANTS.md` §7) is steady-state-deferred (SP-2.e) — no 2c-2b
constant needed.

**`R0-D4` — B9: `certify_draw` sample size pinned + measured (2026-06-19).**
*Measured, not estimated.* The reference sample is `n = 200_000`
(`conformance_grading.rs:175`), giving `tolerance(200_000) = 8/√200000 ≈ 0.0179`
(`conformance.rs:301–309`) — generous enough a correct CSPRNG never false-fails,
tight enough gross bias (`≳ 0.1`) fails. **Wall-clock measured** (not estimated):
`self_cert_passes_reference_rng` (the n=200k `certify_draw` call) runs in
**~14–15 ms** in a debug build *including process startup* — i.e. the draw+grade
itself is sub-15 ms, negligible for a session-start gated check (release is
faster). The `n` choice is therefore settled and shown cheap; only the
**production call site** is deferred (it rides the deferred S6 session-start
hook — see FOLLOWUPS "S6 — `certify_draw` session self-cert wiring"). No
CI-wall-clock concern blocks that wiring.

---

## Process notes

- **Branch / push.** `feat/archival-bond-request` is local only. Per
  `06-branching.mdc`, each push is separately authorized — no push without an
  explicit ask.
- **Gates before any "done" claim** (`45`/`50`): `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`; plus
  the persisted-schema snapshot (`42`) — **2c-2b should not bump
  `STAKING_BLOCK_VERSION`** (the format froze in 2c-2a; the `bonded_slots` hint
  semantics were chosen so 2d's GC needs no second bump — `stake_engine.rs:173`,
  FOLLOWUPS lines 949–951).
- **No C++.** Entire unit is Rust, advancing the FFI boundary inward
  (`20`/`25`); staking stays inside the Rust domain (no `SETTINGS_BLOCK_VERSION`
  perturbation — §10.2 store decision, lines 606–620).
