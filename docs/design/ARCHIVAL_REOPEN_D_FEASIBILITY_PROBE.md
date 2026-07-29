# Reopen-(d) feasibility probe — does any `(grace, m, n)` serve both masters?

**Status:** Round 0 — reviewed at source 2026-07-28; review findings PD-1
(i.i.d. direction) and PD-2 (marginal-map rule) folded, PD-3 ruled (predicate
parameterization inverted to production-side). Second-pass review same day:
PD-F-1 folded (band grounding = named measurable anchors, not a direction
argument), PD-3-1 folded (the delegate is load-bearing — the
`shekyl_archival_failure_window_slashable` FFI export binds its signature).
Dispositions PD-A…PD-F await ratification.
**Spawned:** 2026-07-28, from the Stage-3 close-out ordering
(`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.6 coordination paragraph).
**Family:** `PD-*` (probe design questions `PD-A`…`PD-F`; Round-0 review
findings `PD-1`…`PD-3`; registered in `IMPLEMENTATION_INDEX.md` at birth per
rule 94).

---

## 0. Charter — the near-circularity this breaks

The joint grace + `m`/`n` round needs Round-2 stressnet data to **pin**, but its
**feasibility** question may not. A5 already gives the deterrence threshold
(`q* ≈ 0.098–0.278`, §12.6); the Round-1 pin already gives the honest bound
(transient false-slash ≈ 0.002, `ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1).
What is missing is only the honest transient-`q` behaviour under a tightened
grace — and that gap can be **parameterized instead of awaited**.

Run the feasibility question in sim first and one of two things is learned
cheaply:

- **Comfortably feasible** → reopen (d) resolves to grace-tightening, PoRep
  substrate is **not** a testnet prerequisite, and the stressnet just picks the
  point inside a pre-computed admissible region.
- **Infeasible or marginal** → **PoRep promotes before testnet is built** —
  learned exactly when it is cheap to act on, rather than discovered from first
  stressnet data with no substrate in place.

This matters because reopen (d)'s fork is **not symmetric**: grace-tightening is
a testnet dial; PoRep is architecture. The decision is upstream of testnet in a
way the FOLLOWUPS entry's "Target: V3.0" does not convey.

**Non-goals, stated as hard scope:**

1. **Nothing pins.** `grace`, `m`, `n` all remain provisional. The amended
   handoff (§12.6's corrected crossover surface) still precedes any actual
   `(m, n)` pinning, whenever the joint round runs.
2. **The grace→`q` mapping is out of scope.** How a given response deadline
   maps to a realized failure rate — for either population — is the
   stressnet's measurement. The probe treats the proxy's `q_p` as forced to the
   deterrence threshold by assumption of a sufficiently tight grace, and asks
   only whether the honest side survives that same tightening under an
   assumed coupling (§2).
3. **Not a re-litigation of A5.** The crossover machinery, its corrections
   (shipped-predicate hazard, absorbing-Markov aggregation, per-shard scope),
   and the W10 FAIL verdict are inputs, untouched.

## 1. A-priori commitments — stated before any sweep runs

Committed here, before the arm exists, so the verdict cannot be graded against
a bar chosen after the numbers are seen (the GF-7 ceremony discipline, applied
at probe scale):

- **Honest bound:** transient false-slash ≤ **0.002**, *inherited* from the
  Round-1 pin's tuned value — the probe sets no new bar. Measured in the same
  form the pin measured it: against the L16 outage model, not a bare i.i.d.
  per-epoch coin (see PD-A).
- **Deterrence threshold:** both `q*` ends are map layers — **0.278**
  (bond-exposure-only) and **0.098** (post-D2 forgone-reward folded in). The
  headline feasibility verdict reads at the **0.278 end** (conservative: if
  the honest side survives a grace tight enough to force the *larger* `q`,
  feasibility is robust; feasibility only at the 0.098 end is reported as
  **marginal**, not feasible).
- **Output form:** a **conditional map, never a collapsed verdict**. The
  admissible region is reported *as a function of the honest-`q` assumption* —
  "feasible for honest-`q` below X" — so the stressnet measurement lands into
  a pre-computed map rather than triggering a re-run, and a near-boundary
  measurement already knows which side it is on. (The A1 conditionality
  shape: state the assumption the verdict rests on; do not embed it.)
- **Sweep bounds:** `n ≤ 25` (structural ceiling — the window may not
  out-reach serve-credit retention: `n + SLASH_SETTLEMENT_TIP_LAG_EPOCHS ≤
  MAX_CLAIM_AGE_W + 1` with lag 2 at the genesis schedule,
  `failure_window.rs`), `1 ≤ m ≤ n`, grid anchored at the Round-1 `(11, 13)`.
- **The marginal-map rule** (Round-0 review PD-2 — committed here because
  non-empty-but-tiny is the *likely-contested* case, and leaving it open would
  let the verdict be adjudicated after the numbers are seen — the exact thing
  this section exists to prevent). The verdict is **three-valued**, judged
  against the plausible-`ρ` band, which is itself committed at
  disposition-ratification time, *before any sweep executes* (PD-F):
  - **Feasible** — the admissible region reaches into the band.
  - **Marginal** — the region is non-empty but lies entirely below the band
    (e.g. "feasible only for honest-`q` below 10⁻⁴"). **Marginal carries the
    same action as infeasible**: PoRep-substrate readiness promotes pending
    the stressnet. The recorded difference: a stressnet measurement landing
    inside the region rescues grace-tightening; the substrate work done
    meanwhile is the hedge, not waste.
  - **Infeasible** — empty region: the PoRep-promotion finding outright.

## 2. The feasibility formulation

One grace window tightens for everyone. It raises the proxy's per-fetch
failure rate `q_p` (the deterrence lever) **and** the honest holder's
per-baseline miss rate `q_h` (the false-slash cost) together. The load-bearing
unknown is therefore not either rate alone but their **coupling** at a shared
grace: `ρ = q_h / q_p`. Honest holders serve locally; proxies fetch remotely
inside the deadline — so `ρ < 1` strongly, and *how strongly* is exactly what
the stressnet will measure.

For each `(m, n)` in the grid the probe computes two curves from machinery
that already exists:

- `q_h_max(m, n)` — the largest honest failure rate whose false-slash
  probability stays ≤ 0.002 (the Round-1 harness's measure, swept over the
  honest-`q` family of PD-A);
- `q*(m, n)` — the deterrence crossover, from A5's corrected
  absorbing-Markov machinery, at both exposure ends.

The map is then one surface per exposure end:

> **`ρ_max(m, n) = q_h_max(m, n) / q*(m, n)`** — the pair `(grace, m, n)` is
> admissible iff the measured honest-to-proxy coupling satisfies
> `ρ ≤ ρ_max(m, n)`.

Feasibility verdict semantics: the region `{(m, n) : ρ_max(m, n) ≥ ρ_plaus}`
for a stated plausible-`ρ` band is the deliverable. An empty region at every
plausible `ρ` — even at the 0.098 end — is the PoRep-promotion finding.

## 3. Design questions (Round 0 — dispositions recommended, not ratified)

- **PD-A — the honest-`q` family.** The Round-1 false-slash 0.002 was computed
  under **L16** (exponential outages, mean down ≈ 2 epochs) where misses are
  *correlated* — an outage spans consecutive baselines — not i.i.d. A
  tightened grace adds a second, independent miss mode: even an up-and-serving
  holder can miss a tight deadline. *Recommended:* honest misses = L16 outage
  process **∨** i.i.d. deadline-miss overlay at rate `q_h`; the map's axis is
  the overlay rate. Report the pure-i.i.d. variant alongside as the
  **zero-correlation floor — a LOWER bound on false-slash, never a
  conservative layer** (Round-0 review PD-1, direction corrected): at `m`
  near `n` with small marginal rate, reaching `m` misses under i.i.d. costs
  ~`q_h^m` — astronomically improbable — while a single L16 outage spanning
  `m` baselines does it outright. **Correlation is what makes the slash
  reachable at all**; that is why Round-1 computed under L16 rather than a
  bare coin. The i.i.d. layer's job is to expose how much of the false-slash
  risk clustering drives, and a reader must not mistake it for an upper
  bound.
- **PD-B — verdict end.** Ratify the §1 commitment (headline at 0.278,
  0.098 reported as the marginal layer) or invert. *Recommended:* as stated.
- **PD-C — grid.** `m ∈ [2, n]`, `n ∈ [m, 25]`, full integer grid (≤ ~300
  cells; each cell is a DP over ≤ 2²⁴ states — bound the state count before
  building, and coarsen the grid only if the exact DP is genuinely
  prohibitive, with the coarsening disclosed per no-silent-caps).
- **PD-D — the parameterized window predicate.** The A5 DP builds its
  absorption table by *calling* production `failure_window_slashable`, which is
  fixed at the shipped `(11, 13)`. The sweep needs the predicate over variable
  `(m, n)`. **RULED (Round-0 review PD-3, inverting the original
  recommendation): parameterize production rather than re-express it.** The
  originally recommended twin-plus-parity-gate proved the twin agrees with
  production at `(11, 13)` and nothing else — while the sweep lives entirely
  at other `(m, n)`, unverified *by construction*; a weaker guarantee than
  the `dp_one_step_hazard` idiom it cited, where two constructions checked
  each other across the whole domain. The stronger shape is the one this
  project just ratified for the escalation — **shape frozen, numerics as
  data**: one predicate body taking `FailureWindowParams { m, n }`, the
  config-generated values as the production instance, and the current
  `failure_window_slashable` signature retained as a one-line
  production-instance delegate (**verified feasible at source, with one
  correction from the second-pass review, PD-3-1**: the predicate is a plain
  function whose only `(m, n)` dependence is two const reads — but it is
  *not* FFI-free: `shekyl-ffi/src/archival_ffi.rs` imports it and wraps it as
  the `shekyl_archival_failure_window_slashable` C export. Zero caller ripple
  holds *because the delegate preserves the signature that export binds* —
  which makes the delegate **load-bearing, not a convenience shim**. Its
  defeat condition, named so it cannot be met by accident: a later
  "simplification" that deletes the delegate and updates Rust call sites
  ripples straight into the C++ ABI surface. The delegate's doc comment must
  say so — the `blockchain_height`-snapshot-clause class: a guard whose
  defeat is invisible unless written down). Parity becomes structural,
  and dep-don't-mirror holds across the whole grid instead of at one cell.
  The shape invariants (`m ≥ 1`, `n ≥ m`) and the `n ≤ 25` retention-ceiling
  coupling move into a validated `FailureWindowParams` constructor
  (fail-closed, the `EscalationParams::try_new` shape), so a sweep cell
  cannot silently exceed what consensus structure permits. *Named fallback,
  only if implementation surfaces a constraint invisible from here:* the
  twin plus single-point parity gate, with the residual stated in the report
  — "the sweep's results away from `(11, 13)` rest on the parameterization,
  verified at one point only."
- **PD-E — `φ`-endogeneity.** A5 evaluated at `φ ≈ 0`, the proxy-favouring
  binding case, and needed no `φ`-sweep for its verdict. The probe inherits
  the same argument unchanged (`q` rising in `φ` only helps deterrence).
  *Recommended:* scalar at `φ ≈ 0`, one sentence of justification carried in
  the report.
- **PD-F — the plausible-`ρ` band** (added with the §1 marginal rule, which
  reads against it). The band is an **a-priori input, not a sweep output**:
  it must be stated, grounded, and ratified with the other dispositions,
  before any sweep executes. **The grounding obligation is to cite the
  measurable anchors on both sides, not to argue the separation's direction**
  (Round-0 second-pass review PD-F-1): *local < remote* is true at every
  deadline and therefore informative at none — the band requires the
  **magnitude** of the separation, which is what places `ρ` at 10⁻¹ versus
  10⁻⁴ and decides marginal-versus-comfortable. Left qualitative, an
  "order-of-magnitude argument" has enough latitude to set the band where the
  verdict lands well — the second-order form of the bar-after-numbers problem
  §1 forbids. The anchors are available and cheap: A5 already grounded the
  challenge response at ≈ 3 KB (128-B leaf + the shallow segment co-path,
  §12.6), so the honest side is a **local read plus path construction over a
  few KB** and the proxy side is **the same payload across a network
  round-trip** — both with citable latency distributions. The ratification
  record names those distributions and derives the band from their
  separation. No number is proposed here: proposing one without the named
  anchors would be inventing the bar this round's discipline forbids.

## 4. Deliverables

1. **The arm** — `shekyl-economics-sim` (sibling of `proxy.rs`; deps
   `FAILURE_WINDOW_M/N` for the anchor cell and the §1 bounds as named
   constants). Report rendering follows the sim-report idiom in `main.rs`
   (debug-macro CI gate applies).
2. **The map** — `ρ_max(m, n)` surfaces at both exposure ends + the admissible
   region per plausible-`ρ` band, rendered in the report and recorded in this
   doc's close-out section.
3. **The verdict paragraph** — conditional form only, naming which side of the
   map the plausible-`ρ` band falls on, and the explicit PoRep-promotion
   statement if the region is empty.
4. **Handoff addendum** — the map appended to the §12.6 crossover surface as
   joint-round input; the joint round's pin authority is unchanged.

## 5. Relation to the Round-2 stressnet

The stressnet measures `ρ` (equivalently `q_h` at the candidate grace) and the
grace→`q_p` response — the two quantities this probe deliberately does not
model. With the map in hand, that measurement is a **lookup, not a trigger for
re-analysis**: the §3.2 four-criteria `m` gate
(`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`) gains the probe's admissible region as
a fifth constraint arriving pre-computed. If the measured `ρ` lands outside
every admissible cell, the PoRep branch was already promoted by this probe's
verdict — months earlier than the stressnet could have said so.
