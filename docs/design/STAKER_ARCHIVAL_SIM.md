# Staker-archival simulation — design spec

**Status: reviewed and blessed to build (2026-06-05). Iteration 1 (coverage
dynamics) specified in full with the review's four conditions absorbed into scope
(actor-level spread metric; coarse bond sweep; age-weighted scarcity incl. `g=1`;
whale-under-bond; competitive-share servo incentive); later iterations mapped, not
yet specified. Spec-first per `05-system-thinking.mdc`; a sim that re-prices *what
staking is* is a planning activity per `20-rust-vs-cpp-policy.mdc`, not "while we're
here." Build: new `shekyl-staking-sim` crate (decision below).**

This is the gate-7 instrument for the pay-for-service / firewalled-pseudonym
rebasing. The model it simulates is canonical in
[`../V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Pay-for-service rebasing and
the firewalled-pseudonym identity model*; the finding-side summary and gate-list are
in [`PHASE_2B_STAKE_LIFECYCLE.md`](./PHASE_2B_STAKE_LIFECYCLE.md) §7.5.3. This doc
does **not** restate the model — it specifies how to *test* it.

## Why a sim, and why coverage first

The rebasing makes a falsifiable claim: a reward built from **per-shard `1/R`
scarcity pricing + a per-staker banded plateau-cap + per-shard retention bonds**
produces the coverage property archival exists to deliver —

> **every shard covered enough, spread across many holders, none holding
> everything, and the deep-history shards (the ones that mattered) actually held.**

If the incentive structure does not produce that, nothing downstream matters: the
bond-rate window (gate 4), the Σwork servo (gate 1), the locked-supply re-pricing
(gate 7) are all parameter-tuning *on top of* a coverage model that has to work
first. So **iteration 1 isolates coverage** and treats every other gate's
parameters as fixed inputs, not free variables. The other gates layer on once the
coverage thesis survives or is corrected.

This sim answers economic/behavioral questions only. It is **not** a soundness
instrument: retention-proof unforgeability (gate 2 / the loud 8c), the
per-`(P,shard)`-nullifier counting primitive (gate 3), and the `P` backing/firewall
crypto (gate 6) are out of scope here and are settled by a soundness pass, not by
simulation.

## Iteration 1 — coverage dynamics

### The question, operationalized

The coverage thesis is four sub-claims, each with a metric and a falsification
condition. The sim passes iteration 1 only if all four hold across the swept
regimes; any failure is a finding that feeds back into the model (the keystone is
explicitly allowed to be wrong here — that is what the sim is for).

| Sub-claim | Metric | Fails if |
|---|---|---|
| **Covered enough** | min over shards of replication count `R(shard)`, and the fraction of shards with `R < R_target(age)` | a non-trivial fraction of shards sit below `R_target(age)` at steady state |
| **Spread (no whale)** | Gini / top-1% share of *shards-held* **across actors** (ground-truth actor↔pseudonym map); max single-actor shard fraction | one (or a few) **actors** accumulate an outsized share despite the cap + bond |
| **Deep history held** | replication `R` restricted to deep-history (high-`age`, rarely-queried) shards, vs `R_target(age)` | deep-history shards are systematically under-`R` relative to their (higher) target |
| **Churn-stable** | shard abandonment rate; coverage variance over time | coverage oscillates / shards repeatedly drop below `R_target(age)` (see myopia caveat in *Success / failure*) |

**The spread metric is actor-level, and this is the sim's whole reason to exist on
this axis.** The firewall makes pseudonyms unlinkable, so a Sybil whale *is* many
pseudonyms; a Gini computed over pseudonyms reads a whale as a crowd of small
holders — egalitarian, passing, exactly wrong, blinding the very sub-claim built to
catch the whale. On the live chain you *cannot* observe actor concentration (that is
the privacy guarantee working as designed), so the **only** place the bond's
actor-level deterrence can ever be measured is the sim, where the actor↔pseudonym
map is a model input held as ground truth. The sub-claim's pass/fail is therefore
**actor-level**; a secondary pseudonym-level line is reported as "what an on-chain
observer would (mis)conclude," not as the pass criterion.

`R_target(age)` is a model input (the protocol's intended replication floor for
durability), not an output — and it is **age-dependent**: higher for deep history,
because deep state is *irreplaceable* (lose every copy and it is gone forever),
while hot/recent state is widely held anyway. Iteration 1 reports coverage
*relative to* this stated age-dependent target; it does not invent the target.
Age-dependent target and age-weighted scarcity (below) are the same coupling seen
from both ends.

### Model

**Discrete-time, agent-based, single-region (no network topology in iteration 1).**

- **Shards.** A fixed universe of `N_shard` shards, each with an `age` (hot-set →
  deep-history) and a `query_rate` that decays with age. `age`/`query_rate` are the
  axis along which "deep history is rarely queried but must be retained" lives.
- **Time.** `T` epochs. Each epoch: challenges are issued (retention is proven or
  not), rewards are computed and paid, agents reconsider their shard portfolios
  (acquire / hold / drop).
- **Agents (pseudonyms `P`) and actors.** A population of pseudonyms with
  heterogeneous endowments — **storage capacity** (how many shards they *can* hold)
  and **capital** (how much per-shard bond they *can* post) — each owned by an
  **actor** via a ground-truth actor↔pseudonym map the sim controls as a model
  input. The three archetypes the keystone must survive: storage-rich/capital-poor,
  capital-rich/storage-poor, and the **Sybil whale** (one actor, many `P`s, shared
  endowment). The whale is in iteration 1 as a *coverage* perturbation — **but only
  carrying the bond cost.** A whale tested with free splitting trivially dominates
  and fails the spread sub-claim, but that failure is an artifact of removing the
  defense (the per-shard bond *is* the G-E Sybil deterrent), not a finding about the
  design. So the whale is bonded, which is what pulls a coarse bond sweep into
  iteration 1 (below).
- **Reward (the model under test).** Per the canonical doc, with two refinements the
  equilibrium analysis forces into iteration 1:
  - `work_P = Σ_shards scarcity(shard) · proven_retention(P, shard)`, where
    **`scarcity(shard) ∝ (1/R(shard)) · g(age)`** — age-weighted, not pure `1/R`.
    `g(age)` is a **swept model parameter from the start**, *not* a "maybe discover"
    correctable finding: `g(age)=1` is a baseline point included specifically to
    *confirm* the predicted pure-`1/R` deep-history failure (validating the sim
    against the analysis), and `g(age)>1` curves are swept to find the premium that
    clears deep coverage. Age is a **public shard property**, so age-weighting is the
    privacy-clean replacement for the killed tier weighting — it carries no oracle.
  - `reward_P = Curve(work_P)` with `Curve` a piecewise-linear banded plateau-cap
    (decreasing marginal rates → flat top).
  - The **Σwork servo is a competitive-share game, not a fixed normalizer.**
    `reward_P = budget · work_P / Σwork` makes each agent's reward its *share* of a
    fixed budget, so adding work **dilutes everyone (including yourself)** — a
    **third dilution channel** beyond the `1/R` self-dilution and the concave cap.
    Agents must maximize the *share* reward, not a fixed rate-per-work. The
    atomistic approximation (a single agent ignores its own negligible effect on
    `Σwork`) is fine, but the share shape is constitutive of acquisition behavior and
    is where rent-dissipation and reward-compression-with-population-thickness live —
    exactly what the population sweep must see. (The servo's *supply-safety under
    growth* — `Σreward ≤ budget` as population grows — remains gate 1; only its
    incentive shape is exercised here.)
- **Per-shard retention bond (in iteration 1, coarsely swept).** Holding a
  deep-history shard requires posting a bond `bond(shard)`; dropping it inside the
  retention window slashes the bond. The bond cannot be a clean iteration-2 deferral
  because it is the whale deterrent (above) *and* because the keystone-threatening
  "empty window" finding the spec advertises is **structurally undetectable at a
  single fixed rate** — one point cannot establish an empty window. So iteration 1
  runs a **coarse 3-point bond sweep (low / mid / high)**, which both gives the whale
  its deterrent and lets the empty-window result surface cheaply, pre-build. **Fine
  calibration stays gate 4.**
- **Agent behavior.** Share-reward-maximizing under storage and capital budgets:
  each epoch an agent estimates the marginal *share* reward per additional shard
  (falling through three channels — acquiring a shard raises its `R` and dilutes its
  own `(1/R)·g(age)` payout; the per-staker curve is concave-to-cap; and adding work
  dilutes the `Σwork` denominator), nets it against the bond cost (capital budget)
  and storage cost, and acquires/drops accordingly. **Myopic best-response** in
  iteration 1; learning agents are a conditional escalation (see *Success /
  failure*).

### What is held fixed (deferred-gate inputs)

Iteration 1 must not silently turn deferred-gate parameters into free knobs. The
boundary is redrawn from the first draft: the bond, age-weighting, and the
whale are **entangled** — they jointly *are* the deep-history and spread questions,
so they are **in** iteration 1; the genuinely-separable gates are out. What is in:
`{coarse 3-point bond sweep, age-weighted scarcity incl. g=1, whale-under-bond,
actor-level spread metric}`. What is cleanly deferred (none of these touch the
coverage equilibrium):

- **fine bond calibration** — gate 4 (iteration 1 runs only the coarse low/mid/high
  sweep, enough to give the whale a deterrent and to make an empty-window result
  detectable; the precise window is gate 4).
- **Σwork supply-safety under growth** — gate 1 (`Σreward ≤ budget` as population
  grows). The servo's *incentive shape* (competitive share) is in iteration 1; its
  *supply-safety* is not.
- **foundation floor / bootstrap** — iteration 1 runs at steady state (foundation
  absent or a fixed background coverage); the handoff dynamics are gate 5.
- **locked-supply re-pricing** — macro, not modeled here (gate 7 / the macro sim).
- **privacy firewall + all soundness** — out of scope (a soundness/hygiene property,
  not economic; analyzed, not simulated).

### Sweeps (iteration 1)

The coverage thesis must hold across regimes, not at one lucky point:

- **Coarse bond rate (low / mid / high).** The 3-point sweep that gives the whale
  its deterrent and makes the "empty window" keystone-threat detectable (one point
  cannot). Fine calibration is gate 4.
- **Age-weight `g(age)`.** Swept from `g(age)=1` (baseline, expected to *confirm*
  pure-`1/R` deep-history failure — sim-validates the equilibrium analysis) through
  `g(age)>1` curves to find the premium that clears deep coverage. Coupled to
  `R_target(age)`.
- **Population thickness.** Thin → thick staker populations (the thin regime is
  where coverage is most fragile and where the foundation floor exists for a
  reason — iteration 1 reports where thin-population coverage breaks *without* the
  floor, which sizes the floor for gate 5). Under the competitive-share servo this
  is also where reward-compression-with-thickness shows up.
- **Endowment mix + whale.** Fraction storage-rich vs capital-rich; presence/absence
  and size of a Sybil whale — **whale always under the bond cost** (a free-splitting
  whale is a strawman that fails by having its defense removed).
- **Curve shape.** Number of bands and the cap height (plateau position) — the
  near-term pin from the canonical doc; iteration 1 is where "where does the cap go"
  gets evidence.
- **Shard-age distribution.** Hot-heavy vs deep-history-heavy universes, to stress
  the deep-history sub-claim specifically.

### Outputs

Machine-readable JSON to stdout, human summary to stderr — same convention as
`shekyl-economics-sim` (`main.rs`). Per-sweep: the four coverage metrics at steady
state + their time series, so a reviewer sees both the endpoint and the path
(churn-stability is a path property).

### Success / failure / finding

- **Pass:** all four sub-claims hold across the swept regimes at some `(bond, g(age),
  cap)` combination in the coarse grid. The coverage model is blessed; iterations 2+
  calibrate the deferred gates on top of it.
- **Correctable finding:** a sub-claim fails in a specific regime in a way a model
  change addresses (e.g. whale dominance at low bond → the bond floor is higher than
  assumed; deep-history clears only at a `g(age)` so steep it over-rewards deep →
  the age curve needs reshaping). Recorded, fed back, re-run. (Note: bare
  deep-history-under-`R` at `g(age)=1` is *expected*, not a finding — it validates
  the analysis; the informative result is which `g(age)>1` clears it.)
- **Keystone-threatening finding:** coverage fails *because* `(1/R)·g(age)` + cap +
  bonds are structurally insufficient — e.g. across the whole coarse bond sweep,
  **no** bond rate covers deep history (under `R_target(age)`) without excluding
  storage-rich agents: the bond high enough to deter the whale and guarantee deep
  retention is also high enough to price out capital-poor archivers, so gate 4's
  window is **empty**. The 3-point sweep is what makes this detectable in iteration 1
  (a single rate cannot establish emptiness). This sends the design back to the
  drawing board, and surfacing it cheaply, pre-build, is the entire point.

**Myopia pre-commitment (churn-stability only).** Myopic best-response is the
iteration-1 agent model, but a **churn-stability failure under myopic agents must be
re-tested under anticipatory / learning agents before it is recorded as a
keystone-threatening finding** — oscillation around the `1/R`-and-servo equilibrium
is the canonical myopia artifact (agents over-react to last epoch's prices and
thrash). The other three sub-claims (covered, spread, deep-history) are
steady-state properties and are myopia-safe; only churn-stability carries this
caveat.

## Later iterations (mapped, not specified)

Each layers onto iteration 1's coverage model; each has the gate it discharges and
the metric it needs. Specified when iteration 1 closes.

- **Iteration 2 — fine bond-rate window (gate 4).** *Fine* sweep of `bond rate`
  within the coarse band iteration 1 leaves open; find the precise sub-band that is
  simultaneously Sybil-deterring, deep-history-guaranteeing, and not
  storage-rich-excluding. (Iteration 1's coarse 3-point sweep already establishes
  whether the window is plausibly non-empty; iteration 2 sharpens it.)
- **Iteration 3 — Σwork servo supply-safety (gate 1).** Grow the population under
  the servo; confirm `Σreward ≤ budget` and characterize per-staker reward
  compression as population grows. (This and gate 7 may run in the macro
  `shekyl-economics-sim` rather than the agent sim — build decision below.)
- **Iteration 4 — bootstrap handoff (gate 5).** Foundation floor overlapping a
  growing staker population, shedding as coverage is *demonstrated*; confirm no
  zero-coverage instant; confirm the flat per-bonded-shard subsidy is coverage-
  sufficient and privacy-clean.
- **Iteration 5 — locked-supply re-pricing (gate 7, the foundational macro gate).**
  Does locked supply collapse toward `eligibility_min × population` once principal
  stops multiplying reward, and what does that do to the V3 economy assumptions?
  Macro; couples to `shekyl-economics-sim`.

## Build decision — confirmed: separate `shekyl-staking-sim` crate

A **new crate `shekyl-staking-sim`** (agent-based) for iterations 1, 2, 4; macro
numbers wired from `shekyl-economics-sim` for iterations 3, 5. Epoch-granular agent
dynamics and year-granular macro supply are different instruments, and the
**actor-level ground-truth bookkeeping** the spread metric requires is exactly the
kind of state that would warp the macro sim if bolted on. Extending
`shekyl-economics-sim` is rejected on `15-deletion-and-debt.mdc`'s "two instruments,
two scopes" reading.

## Resolved — review sign-off (four conditions)

The four open questions are resolved *yes-directionally, each with one condition*
that is now folded into the iteration-1 scope above:

1. **`R_target` is a stated constant — but `R_target(age)`.** Not a sim output; an
   age-dependent durability floor, higher for irreplaceable deep history (lose every
   copy → gone forever; hot state is widely held anyway). Couples to age-weighted
   scarcity and sharpens the deep-history bar.
2. **Whale in iteration 1 — yes, but only carrying the bond cost.** The bond is the
   G-E Sybil deterrent; a free-splitting whale is a strawman. This pulls the coarse
   bond sweep into iteration 1, which is also what makes the empty-window
   keystone-threat detectable.
3. **Myopic best-response — yes as first cut, with the churn pre-commitment.** A
   churn-stability failure under myopic agents is re-tested under
   anticipatory/learning agents before being recorded as a keystone finding (the
   other three sub-claims are steady-state and myopia-safe).
4. **Single-region — yes, and the reason is load-bearing.** Acceptable *because the
   reward is retention-based, not retrieval-based*, so latency-routing affects only
   the query secondary-market and never the acquisition incentive. **This
   affirmation is contingent on retention-not-retrieval holding**: if any retrieval
   term ever enters the reward, single-region becomes wrong and network topology has
   to come in.
