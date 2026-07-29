# Reopen-(d) feasibility probe — does any `(grace, m, n)` serve both masters?

**Status:** Round 0 — design questions open, a-priori commitments stated.
**Spawned:** 2026-07-28, from the Stage-3 close-out ordering
(`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.6 coordination paragraph).
**Family:** `PD-*` (probe design questions `PD-A`…`PD-E`; registered in
`IMPLEMENTATION_INDEX.md` at birth per rule 94).

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
  the overlay rate. Report the pure-i.i.d. variant alongside as a sensitivity
  layer (it is the pessimistic-correlation extreme for m-of-n windows).
- **PD-B — verdict end.** Ratify the §1 commitment (headline at 0.278,
  0.098 reported as the marginal layer) or invert. *Recommended:* as stated.
- **PD-C — grid.** `m ∈ [2, n]`, `n ∈ [m, 25]`, full integer grid (≤ ~300
  cells; each cell is a DP over ≤ 2²⁴ states — bound the state count before
  building, and coarsen the grid only if the exact DP is genuinely
  prohibitive, with the coarsening disclosed per no-silent-caps).
- **PD-D — the parameterized window predicate.** The A5 DP builds its
  absorption table by *calling* production `failure_window_slashable`, which is
  fixed at the shipped `(11, 13)`. The sweep needs the predicate over variable
  `(m, n)`. *Recommended:* a parameterized re-expression **plus a hoist-parity
  gate** — at `(11, 13)` the parameterized table must equal the
  production-predicate table bit-for-bit (the `dp_one_step_hazard` idiom:
  two constructions guarding each other). Dep-don't-mirror is preserved at the
  one point where production has an opinion; everywhere else there is no
  production behaviour to mirror.
- **PD-E — `φ`-endogeneity.** A5 evaluated at `φ ≈ 0`, the proxy-favouring
  binding case, and needed no `φ`-sweep for its verdict. The probe inherits
  the same argument unchanged (`q` rising in `φ` only helps deterrence).
  *Recommended:* scalar at `φ ≈ 0`, one sentence of justification carried in
  the report.

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
