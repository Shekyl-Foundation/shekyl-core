# Staker-archival simulation — design spec

**Status: iteration 2 BUILT and RUN — duration (L9) + co-location pair sweep (L8)
(2026-06-06).** Crate `rust/shekyl-staking-sim`; first-build findings in §*Iteration 1 —
results (first build)*, robustness-sweep refinements in §*Iteration 1b — robustness sweeps
and residual-by-age*, the flat-vs-age-scaled-bond fork in §*Iteration 1c — the
flat-vs-age-scaled-bond fork (L4)*, the bond-duration + co-location work in §*Iteration 2
— bond duration (L9) and co-location (L8)*, and the forward worklist in §*Adjustment
ledger* at the end of this doc.

**Iteration-2 headline.** (i) The seating metric is now the **L8 min-form** —
`Σ_actor min(⌊capital/bond⌋, ⌊storage/shard_size⌋) / Σ_deep R_target` — which catches the
co-location starvation the aggregate ratio missed: `bscale_s0` reads `0.86 < 1` (was
aggregate `3.24`) matching `deep_und 0.75`. (ii) The **(bond × shard-size) pair sweep**
confirms L8's joint claim — neither leg moves coverage alone (low bond + big shard, or
small shard + high bond, each still starve), only the *pair* clears deep, exactly when the
min-form crosses 1. (iii) **Age-scaled bond *duration* (L9) is RESOLVED — adopt it.** A
thin/surplus pair sweep separates the two halves the thin regime confounds: oldest-band
churn *persists at surplus* (`oChrn 0.251` at flat duration with deep fully covered — so
the churn is structural, not a knife-edge artifact → duration is *necessary*), and
age-scaled duration damps it (`0.251 → 0.084`) while anticipation costs *zero* coverage at
surplus (`deep_und 0` on every anticipatory row → the thin-regime collapse was a pure
margin artifact → the cost is *gentle*). Outcome: flat magnitude **plus** age-scaled
duration; the L4 reversion trigger (oldest-band churn) fires even at surplus, so duration
is in, and gate-4's duration axis is pre-settled to a level-tuning question. The 1c result, **L4 resolved**: keep flat bond *magnitude*
(durability survival arithmetic — redundancy dominates per-holder reliability, so the
irreplaceable tail wants the *most distinct holders* → the *most accessible* bond, never
scaled up; age-scaling magnitude flips the binding constraint from the tractable `dS/dN`
to an intractable tail-concentration). The commitment-horizon job goes to **age-scaled
bond *duration*** (new axis L9) — three orthogonal knobs: `g` locates the residual, flat
magnitude owns redundancy/`dS/dN`, duration owns the commitment horizon. New gate-inputs:
the **co-location finding (L8)** (`dS/dN≥1` is necessary-not-sufficient — deep needs
storage and bond-capital co-located) and the **magnitude/duration model split (L9)** that
must land before the gate-4 fine sweep. Headline: the sim reproduces the predicted `g=1` deep-history starvation
(validating it against the equilibrium analysis), `g(age)` clears deep monotonically,
and the high-bond empty-window threat surfaces under the coarse 3-point sweep exactly
as designed. The 1b sweeps then establish *which findings are structural vs.
margin-artifacts*: the `deep_und=1.000` corner is a thin-supply artifact (dissolves to
`0.317` then `0.000` as provisioning rises at `g=1`), the empty-window is a precise
aggregate-slot condition (`Σ⌊capital/bond⌋ < Σ_deep R_target`), and the residual-by-age
crux *moves with `g`* (oldest tail at `g≈1`; shoulder at moderate `g`; hot at high `g`).
Specification (below) reviewed and blessed to build with the review's
four conditions absorbed into scope (actor-level spread metric; coarse bond sweep;
age-weighted scarcity incl. `g=1`; whale-under-bond; competitive-share servo
incentive); later iterations mapped, not yet specified. Spec-first per
`05-system-thinking.mdc`; a sim that re-prices *what staking is* is a planning
activity per `20-rust-vs-cpp-policy.mdc`, not "while we're here."**

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

## Iteration 1 — results (first build)

**Status: built and run (2026-06-05).** Crate: `rust/shekyl-staking-sim`
(agent-based, deterministic, no new dependencies — inline splitmix64 PRNG,
`serde_json` for output). Run `cargo run -p shekyl-staking-sim` — JSON results to
stdout, the summary table + threshold legend to stderr. The curated sweep set
(baseline + one-axis sweeps over bond, `g(age)`, population, endowment mix, curve
cap, age distribution, plus the whale×bond cross) is in `src/scenarios.rs`. Verdict
thresholds are stated in code and reported alongside raw metrics so a reviewer can
re-judge: `covered = frac_under<0.05 & min_R≥1`; `spread = gini_actor<0.6 &
max_actor_share<0.20` (actor-level); `deep = deep_frac_under<0.10`;
`churn_stable = churn<0.05`.

### What the first build establishes

1. **The sim is validated against the equilibrium analysis (the headline).** At
   `g(age)=1` (pure `1/R`, no age premium) deep history *completely* starves —
   `deep_frac_under = 1.000`, every deep shard below its `R_target(age)` — while hot
   coverage is fine. This is the spec's predicted bond-asymmetry failure reproduced
   exactly: a deep shard carries a bond a hot shard does not, so at equal `R` it is
   strictly less attractive, agents fill hot and starve deep. The model reproducing
   the *predicted* failure is what licenses trusting its other outputs.

2. **`g(age)` clears deep, monotonically.** `deep_frac_under` falls
   `1.000 → 0.125 → 0.100 → 0.075 → 0.067` as `g(age)` (the slope in
   `g = 1 + age_weight·age`) climbs through `{0, 2, 3, 4, 5}`. The clearing premium
   exists; deep coverage passes its bar by `age_weight ≈ 4`. Age is a public shard
   property, so this is the privacy-clean replacement for the killed tier weighting,
   confirmed to do the job it was introduced for.

3. **But `g(age)` *reallocates* coverage hot→deep; it does not manufacture it.** At
   the margin-calibrated baseline, raising `g` improves deep coverage and *worsens*
   overall coverage in lockstep (`frac_under` rises `0.062 → 0.150` as `g` climbs
   past 2), because scarce storage shifted to deep is robbed from hot. **No single
   `g` clears both `covered` and `deep` at marginal storage.** Total coverage is a
   storage-*supply* question (population thickness / the foundation floor, gate 5),
   not a `g(age)` question — `g(age)` only fixes the deep-vs-hot allocation. This is
   a genuine finding, not an artifact to tune away: it sharpens what the age premium
   is *for*.

4. **The window is non-empty when supply is adequate.** `pop_thick` (200 actors,
   mid bond, `g=2`) passes all four sub-claims — the existence result complementing
   (3): given enough aggregate storage, the `(bond=mid, g=2)` config clears
   coverage, spread, deep, and churn together.

5. **The empty-window keystone-threat is real at high bond — and the coarse 3-point
   sweep is what makes it visible.** `bond_high` (rate 8) collapses deep coverage
   (`deep_frac_under = 0.875`) with no whale present: the bond high enough to deter a
   whale also prices capital-poor archivers out of deep retention. A single fixed
   bond rate could never have shown this; the low/mid/high sweep is doing exactly the
   job the spec advertised for it. Pinning whether the window is merely *narrow* or
   genuinely *empty* is gate 4 (fine bond sweep).

6. **High bond centralizes deep history in the capital-rich.** `bond_high_whale`
   recovers deep coverage (`0.875 → 0.292`) precisely because the whale is the only
   actor who can afford the deep bonds — i.e. a high bond buys Sybil-deterrence at the
   cost of concentrating deep retention in whale hands. This is a real tension for
   gate-4 calibration that the analysis had not surfaced.

7. **The actor-level spread metric earns its place.** Under the bond, the whale is
   contained at the actor level (`max_actor_share ≈ 0.11 < 0.20`), while the
   pseudonym-level Gini reads systematically *more* egalitarian (`≈ 0.19`) — the
   on-chain observer under-counts the whale exactly as the spec warned. The pass/fail
   is taken from the actor-level metric the live chain cannot see; the sim is the only
   place this is measurable.

8. **Thin population is fragile; churn is a non-issue under myopia.** `pop_thin`
   (25 actors) fails coverage outright (`frac_under = 1.000`) — the regime the
   foundation floor exists to backstop (gate 5; the sim sizes where coverage breaks
   without the floor). Churn is *zero* at steady state across every scenario: the
   myopic Gauss–Seidel best-response reaches a fixed point in ~2 epochs and stays, so
   `churn_stable` passes on its own terms and the learning-agent re-test
   pre-commitment is **not** triggered.

### Model-fidelity caveats (what iteration 1 does and does not earn)

- **Calibration sits the baseline at the coverage margin deliberately.** Storage is
  ~18 % above the bare full-coverage requirement and capital is ample at mid bond,
  so storage binds and the `g(age)`/bond tensions are exercised. An over-provisioned
  baseline covers everything trivially and tests nothing; the calibration is a
  modeling decision, not a result, and is documented in `baseline()`.
- **Fast convergence means the equilibrium, not the path, is the story.** ~2-epoch
  convergence makes iteration 1 effectively a one-shot equilibrium solver. This is
  appropriate for the steady-state sub-claims; any future term that introduces
  genuine dynamics (learning agents, stochastic challenges) would re-open the path as
  a question.
- **Self-replication is assumed irrational and not modeled.** Per the model
  docstring, an actor holding a shard twice doubles its storage cost and lowers its
  own `1/R` reward, so `R` (distinct actors) equals distinct-pseudonym `R`. A
  soundness pass — not this sim — owns whether the per-`(P,shard)`-nullifier counting
  actually forecloses self-replication (gate 3).
- **Thresholds are strict and stated.** `covered<0.05` is a demanding bar for a
  myopic sim at marginal storage; the borderline `covered` failures (e.g. `0.062` at
  `g=2`) are reported with raw metrics so the bar can be re-judged rather than being
  silently load-bearing.

### What feeds forward

- **Gate 4 (fine bond window):** iteration 1 brackets the live tension — mid bond
  leaves deep coverage to `g(age)`; high bond collapses it (capital-poor exclusion)
  and centralizes it (whale dependence). The fine sweep pins whether a rate exists
  that is simultaneously Sybil-deterring and not deep-coverage-collapsing.
- **Gate 5 (bootstrap floor):** `pop_thin` failing outright sizes the floor — total
  coverage is supply-bound, and `g(age)` cannot substitute for thin population.
- **`g(age)` near-term pin:** the clearing premium lives near `age_weight ≈ 3–4` at
  this baseline, but it trades against hot coverage; the right value is coupled to
  aggregate supply, so it is pinned *with* the floor, not independently.

## Iteration 1b — robustness sweeps and residual-by-age

**Status: run (2026-06-05), same crate.** Added in response to the review's
neutralizer ("a single calibrated point is a single regime; report each finding as
*holds across [range]*, not *at the point*"). New instruments: a **provisioning sweep**
(`storage_scale ∈ {0.7,1.0,1.3,1.6,2.0}`), a **`g=1`×provisioning cross** (to test
whether the `deep_und=1.000` corner is structural or thin-supply), **per-age-band
metrics** (5 bands: mean-R, residual `frac_under`, actor-Gini, whale-share each), and a
**durability-seating readout** (`dS/dN = Σ⌊capital/bond⌋ / Σ_deep R_target`, the binding
empty-window ratio; plus the looser distinct-actor `seating_feasible`). Epochs trimmed
40 (convergence is ~2 epochs; the cut is runtime-only, verified non-substantive).

### What the sweeps establish

1. **The `deep_und=1.000` corner is a thin-supply artifact, not structural — exactly as
   predicted.** The `g=1`×provisioning cross dissolves the corner monotonically:
   `deep_und = 1.000 → 0.317 → 0.000 → 0.000` as `storage_scale` climbs
   `1.0 → 1.3 → 1.6 → 2.0` at `g=1`. With adequate supply and no premium, hot/mid
   saturate (band mean-R reaches ~8) and deep gets partially then fully held even at
   `g=1`. **What is structural** (survives the whole sweep) is the *direction*: without a
   premium, deep is the last class covered; the *quantitative* total starvation is
   specific to the thin baseline. The review's prediction is confirmed in the sim it
   pointed at.

2. **The residual-by-age crux *moves with `g`* — sharper than the oldest-tail
   prediction.** Per-band `frac_under` shows the under-covered shards are not random
   scatter, and *where* they sit depends on the premium:
   - **`g=1` (no premium):** residual is the deep half — bands `0.6–0.8` and `0.8–1.0`
     both 100 % under; the **oldest tail starves worst**. Confirms the prediction *in the
     no-premium regime*. The cleanest instance is `g1_p13` (adequate supply, `g=1`):
     residual is *exactly* the oldest band (`0.8–1.0` at 0.776 under, every younger band
     0.000) — when supply is sufficient but no premium exists, the last-and-only thing to
     starve is the oldest tail.
   - **`g=2` (clearing premium):** the oldest band becomes the **best**-covered deep band
     (mean-R 6.0, 0 % under) and the residual **migrates to the shoulder** — band
     `0.4–0.6` straddling the deep threshold, 32.6 % under. The premium over-protects the
     extreme and leaves the boundary-of-deep as the tight point.
   - **`g≥4`:** the oldest is **wastefully over**-covered (mean-R 6.6–6.7 > target 6)
     while **hot** starves (band `0.0–0.2` up to 70 % under). The premium over-rewards age
     past the point of durability need and robs recency.

   So "the single tightest point" is regime-dependent: oldest tail at `g≈1`, shoulder
   at moderate `g`, hot at high `g`. A total-residual-minimizing `g` (≈2–3 here) parks
   the residual at the shoulder. The oldest-tail crux is the *no-premium* crux; the
   premium converts it into a shoulder crux.

3. **The empty-window is an aggregate-slot condition, not a distinct-actor one.**
   `bond_high` fails with `dS/dN = 0.97` (`Σ⌊capital/bond⌋ = 620 < Σ_deep R_target = 638`)
   while `seating_feasible = true` (`affording_actors = 80 ≥ R_target_deepest = 6`). The
   distinct-actor condition (#4's literal "seat `R_target(deep)` affording actors per
   shard") is **slack** for any populous network — there are always ≥ `R_target` capital-
   rich actors. The condition that actually binds is the **aggregate bond-budget**: each
   actor can bond only `⌊capital/bond⌋` deep shards, and the network fails deep when the
   summed budget drops below the summed deep need. Gate 4's empty-window test is
   therefore `dS/dN ≥ 1` (capital axis), *separately* from the storage axis.

4. **Capital and storage are orthogonal binding axes.** `dS/dN` cleanly separates the
   two empty-window causes: `bond_high` fails with `dS/dN = 0.97` (capital/bond-bound;
   storage is fine), while `pop_thin` fails with `dS/dN = 1.21` (capital is fine;
   storage/provisioning-bound). A coverage failure is one, the other, or both — and the
   metric now says which. Gate 4 owns the capital axis (`dS/dN`); gate 5 owns the storage
   axis (provisioning floor).

5. **Baseline findings hold across the provisioning range (de-artifacted).** The
   provisioning sweep at `g=2` reproduces the supply story structurally: `prov_p07`
   (under-provisioned) starves (`frac_under 0.821`, residual at oldest); `prov_p10`
   = baseline (`0.062`); `prov_p13`+ pass cleanly. The `g(age)`-reallocates-not-
   manufactures finding (#3 first build) is confirmed structural — it appears wherever
   storage binds (`p07`, `p10`) and resolves with supply (`p13`+), not only at the
   calibrated point.

### 1b model-fidelity caveats

- **Bonds are modeled flat across deep shards, not age-scaled.** The review's framing
  assumed an age-scaled bond ("highest bond at oldest"). Under a *flat* deep bond the
  affording-actor scarcity (mechanism a) never concentrates at the oldest tail — the
  aggregate-slot condition (mechanism b) binds uniformly. An **age-scaled bond** would
  concentrate mechanism-(a) scarcity at the oldest shards (highest bond → fewest
  affording actors there), potentially making the distinct-actor condition bind exactly
  at the tail. Whether the bond is flat-on-deep or age-scaled is a **gate-4 design
  choice** the sim has now framed; iteration 1 tests the flat case.
- **The whale's deep concentration is visible but bounded in current scenarios.**
  `bond_high_whale` recovers deep (`0.875 → 0.292`) with the whale at oldest-band share
  `wB4 ≈ 0.12` — real centralization, but the single whale is not yet large enough to be
  the *sole* deep holder. A gate-4 stress (whale sized to the only-affording-actor regime
  under an age-scaled bond) is the sharpened durability test #4 points at.

## Iteration 1c — the flat-vs-age-scaled-bond fork (L4)

**Status: run (2026-06-05), same crate.** Closes the L4 fork the 1b sweeps opened.
Added a **mean-preserving age-tilted bond** (`model::bond_age`): for deep shards,
`bond_rate · (1 + scale·(age − deep_mid))` with `deep_mid = (deep_threshold+1)/2`, so
the *average* deep bond is held at `bond_rate` while demand tilts toward older shards
as `scale` rises (`scale = 0` is the flat iteration-1 bond). Mean-preservation is what
makes flat vs. tilted comparable at equal aggregate capital demand — isolating the L4
question (does tilting concentrate scarcity on the oldest tail?) from a mere total-cost
increase. The agent budget became `Σ bond(age) ≤ capital` (capital-sum, replacing the
flat count cap). The sweep runs in a deliberately constructed **capital-poor-archiver**
regime (storage-rich actors carry capital 8, not the baseline's 20) because the tilt
mechanism is invisible when every actor's capital dwarfs every per-shard bond.

### What the fork establishes

1. **Naive (fixed-base) age-scaling is strictly coverage-regressive.** Holding
   `bond_rate` fixed and adding an age term raises total deep demand, so capital
   coverage falls `dS/dN = 1.03 → 0.59 → 0.31` across `scale {0,1,3}` and deep fully
   starves. Any age-scaling must be mean-preserving (lower the base) even to be
   comparable — itself a caution against the naive form.

2. **Mean-preserving age-tilt is a weak, non-monotonic lever — because it fights the
   reward premium it is supposed to complement.** Oldest-band residual moves
   `0.71 → 0.78 → 0.69` and oldest-band actor-Gini `0.542 → 0.562 → 0.573` across
   `scale {0,1,3}` — a mild upward concentration push, not a sharp tail break. Two
   reasons: (a) the distinct-actor *afford-one* count stays at 80 (the tilt changes
   *how many* oldest shards a capital-poor archiver holds, not *whether* it can hold
   one — so the distinct-actor empty-window never trips); (b) — **the general
   mechanism** — the age-tilt on bond *magnitude* and the age premium on *reward*
   (`g·scarcity`) pull coverage in **exactly opposite directions**: the premium pulls
   *toward* the oldest, the magnitude-tilt pushes *away* from it, so they cancel. This
   is not a property of the particular tilt shape — *any* age-scaling of bond magnitude
   fights the reward premium already doing the age work, so it can only ever be a
   wash-or-worse. Flat magnitude is therefore not merely the empirical winner; it is the
   only magnitude shape that does not sabotage the lever (`g`) that actually relocates
   coverage.

3. **The dominant deep-coverage lever in the capital-poor regime is a capital-rich
   actor, not the bond shape.** With a whale present, `deep_und` collapses
   `0.75 → 0.058` and the oldest bands fully cover at *every* scale — but the whale then
   holds 16–19 % of each deep band. The durability concentration to watch is the
   capital-rich actor's deep share, and it is essentially independent of the bond's
   age-shape.

4. **Aggregate `dS/dN ≥ 1` is necessary but not sufficient — the co-location finding,
   now folded into the metric (L8).** `bscale_s0` (flat bond) has *aggregate* capital
   coverage `3.24` — ample — yet `deep_und = 0.75`. Deep needs both storage *and*
   bond-capital on the **same** actor; when capital sits with storage-poor capital-rich
   actors and storage sits with bond-constrained capital-poor archivers, deep falls in
   the co-location gap (the whale, ample on both axes, is what closes it). The
   **corrected min-form** metric counts each actor's *smaller* leg —
   `Σ_actor min(⌊capital/bond⌋, ⌊storage/shard_size⌋) / Σ_deep R_target` — and reads
   `0.86 < 1` for `bscale_s0`, predicting the `0.75` starvation that the aggregate `3.24`
   masked. This is the metric the sim now reports as the `dS/dN` column; the aggregate is
   retained only as a secondary line. (It also *unifies* L3's two binding axes: the
   `min(capital-leg, storage-leg)` form collapses the separate capital and storage
   conditions into one co-located number.)

**Disposition (L4): flat bond *magnitude*.** The sim evidence above (weak, mildly
regressive tilt that fights the premium) is corroborating; the *decisive* argument is
durability survival arithmetic. For irreplaceable data, redundancy dominates per-holder
reliability — `N=3, p=0.99 → ~1−10⁻⁶` vs `N=20, p=0.9 → ~1−10⁻²⁰` — so the number of
*distinct holders* swamps per-holder commitment for "does the data survive at all,"
which is the only question that matters for irreplaceable state. The oldest shards
therefore want the **most distinct holders → the most accessible (flat/low) bond**, and
age-scaling magnitude does the precise opposite: it raises the bond exactly where the
widest pool is needed, **flipping the binding constraint** from the tractable
aggregate-slot `dS/dN` (distinct-actor slack, 80 ≥ 6) to the intractable
tail-distinct-actor concentration. The same evidence that produced the clean `dS/dN`
durability condition (L2) is thus itself the argument for keeping magnitude flat.

**Three orthogonal knobs (the L4 synthesis).** The instinct to "age-scale the bond" was
the tier-replacement's legitimate commitment-horizon job reasserting itself — but it
belongs in *duration*, not *magnitude*, where magnitude collides with redundancy. The
clean separation:

| Knob | Job | Constraint it owns |
|------|-----|--------------------|
| `g(age)` (age-weighted **reward**) | attracts coverage onto old shards; **locates the residual** (seat it on the shoulder, L1) | coverage-vs-`R_target(age)` match |
| bond **magnitude** (flat) | sets affordability → distinct-holder count → **redundancy** | aggregate-slot `dS/dN ≥ 1` (L2) |
| bond **duration** (age-scaled) | sets the **commitment horizon** (tier's old job); damps tail churn | churn-stability / willingness ceiling (L9) |

Reward attracts; flat magnitude keeps-accessible; age-scaled duration commits — three
jobs on three knobs, no collisions. The L4 mistake to avoid is folding
commitment-horizon into magnitude, where it fights redundancy.

**The L4 reversion trigger (made measurable).** Flat-magnitude-no-duration is *complete*
unless a specific signal fires: a **churn-stability failure on the oldest band
specifically** — coverage present but oscillating, holders cycling off the irreplaceable
shards (the `oChrn` metric on the deepest band). If the oldest-band churn sub-claim holds,
flat magnitude without any duration term is the final shape and L9 stays parked. If it
*fails on the tail*, that — and only that — is when age-scaled **duration** (never
magnitude) earns its complexity. Iteration 2 exercises exactly this and **discharges
the clause with evidence**: the trigger fires not only thin (`oChrn 0.215`) but *at
surplus* (`oChrn 0.251`, deep fully covered), so the churn is structural and flat-no-duration
is incomplete; age-scaled duration damps it (`→ 0.084`) and, in the surplus regime,
anticipation costs zero coverage — so duration is **adopted**, not parked (see §*L9
resolver*). Magnitude stays flat regardless; duration is the separate knob that carries the
commitment horizon.

**The genuinely new gate-inputs:** the **co-location finding (L8)** — deep durability
needs actors rich on storage *and* bond-capital jointly (or a foundation/whale
backstop) — and the **duration axis (L9)**, which requires a model refinement
(separating bond magnitude from duration, with churn dynamics to make duration
load-bearing) **before** the gate-4 fine sweep. Gate 4 then sweeps two bond axes, not
one.

### 1c model-fidelity caveats

- **The capital-poor-archiver regime is a constructed scenario, not the baseline.** It
  exists to make the tilt mechanism observable; its specific magnitudes (capital 8,
  `frac_storage_rich 0.6`) are illustrative, not calibrated. The structural takeaways
  (tilt is weak; co-location binds) are what carry forward, not the numbers.
- **The per-band `affording` metric measures afford-*one*, not budget capacity.** It
  stays at the full actor count here because the binding effect is on *how many* oldest
  shards an actor bonds (budget exhaustion), which surfaces in coverage/Gini, not in the
  afford-one count. A budget-capacity per-band metric is a candidate 1d refinement if
  the distinct-actor tail mechanism ever needs sharper resolution.

## Iteration 2 — bond duration (L9) and co-location (L8)

Iteration 2 lands the model refinement L4/L8/L9 demanded before the gate-4 fine sweep:
**bond magnitude and duration are separated**, the world **ages dynamically** so duration
has churn to act on, and the seating metric is the **co-located min-form**.

### Model refinement

- **Magnitude vs duration.** `bond_age(age)` (flat by L4) sets the slashable *amount*;
  the new `bond_duration(age) = base·(1 + dur_age_scale·age)` sets the *commitment
  horizon* (in epochs). Magnitude gates affordability (hard — distinct-holder count →
  redundancy); duration is an opportunity-cost on *willingness* (soft — same capital
  committed longer), so it never shrinks the affording pool.
- **Dynamic frontier-window world.** Shards age each epoch; the oldest recycle (a fresh
  frontier shard replaces a retired one), creating the churn duration must damp. A
  per-`(actor, shard)` **lock** counts down the retention commitment: a deep shard under
  an unexpired lock cannot be dropped (force-kept), and fresh deep acquisitions arm a lock
  of length `bond_duration(age)`. The `oChrn` metric reports holding-flips in the deepest
  band per epoch.
- **Lock anticipation.** Forward-looking agents add a willingness penalty to a *fresh*
  deep acquisition proportional to the lock they would incur (`anticipation · duration ·
  storage_unit_cost`) — the "willingness ceiling." Myopic agents (`anticipation = 0`)
  ignore the future lock.
- **Storage leg / granularity.** `deep_shard_size` is the storage a deep shard occupies
  (default `1.0` = iteration-1 behavior). It is the L8 storage leg and gate-5's
  granularity lever; smaller deep shards clear more actors' storage leg.

### L8 — the co-location min-form and the joint lever

The seating metric is now `colocated_coverage = Σ_actor min(⌊capital/bond⌋,
⌊storage/shard_size⌋) / Σ_deep R_target` (reported as the `dS/dN` column). Validation:
`bscale_s0` reads **0.86 < 1**, matching `deep_und 0.75`, where the aggregate ratio (3.24)
gave a false pass.

The **(bond × shard-size) pair sweep** (stark split-endowment regime, where co-location is
scarce) confirms neither leg moves the co-located pool alone — lowering the bond recruits
the storage-rich (raises their capital leg), shrinking the shard recruits the capital-rich
(raises their storage leg) — and deep durability needs the *joint* count. Cells are
`colocated dS/dN / deep_und`:

| flat bond ↓ \ shard size → | `1.0` | `0.5` | `0.25` |
|---|---|---|---|
| **2.0** | 0.38 / **1.00** | 0.55 / **1.00** | 0.91 / 0.47 |
| **1.0** | 0.57 / **1.00** | 0.75 / **1.00** | 1.11 / **0.00** |
| **0.5** | 0.97 / 0.65 | 1.15 / **0.00** | 1.50 / **0.00** |

The lowest bond at full shard size (0.97 / 0.65) and the smallest shard at high bond
(0.91 / 0.47) each still starve; only the *pair* clears deep to zero, and clearing
coincides with the min-form crossing 1. This is the empirical statement of L8: **gates 4
and 5 are re-entangled** — the binding quantity is the count of co-located non-whale
actors per deep shard, a joint function of bond (gate-4's capital leg) and shard size
(gate-5's storage leg), so the gates cannot close independently. The two levers to grow
the co-located pool — **low-flat bond** (recruits the storage-rich) and **finer deep-shard
granularity** (recruits the capital-rich) — must be tuned together. (The stark archetypes
are a stress test; in the real design every archiver is co-located *by construction*, so
the real form of L8 is **ratio-matching**: the deep shard's storage:bond requirement ratio
must sit inside the population's storage:capital endowment-ratio distribution, or
ratio-mismatched actors seat deep inefficiently.)

### L9 — bond duration

Sweeping `dur_age_scale ∈ {0, 2, 4}` in the dynamic world:

| scenario | agents | `oChrn` (oldest-band churn) | `oldU` (oldest residual) | `deep_und` |
|---|---|---|---|---|
| `dur_s0` | myopic | 0.215 | 0.000 | 0.125 |
| `dur_s2` | myopic | 0.123 | 0.041 | 0.205 |
| `dur_s4` | myopic | 0.108 | 0.000 | 0.188 |
| `dur_s0_antic` | anticipatory (0.25) | 0.072 | 0.980 | 0.991 |
| `dur_s2_antic` | anticipatory (0.25) | 0.006 | 1.000 | 0.955 |
| `dur_s4_antic` | anticipatory (0.25) | 0.005 | 0.980 | 0.955 |

- **Myopic: duration damps tail churn without suppressing participation.** Age-scaling the
  duration roughly halves oldest-band churn (`0.215 → 0.108`) while the oldest residual
  stays ≈0 — exactly the commitment-horizon job, with no affordability cost (the affording
  pool is unchanged, as designed).
- **Anticipatory (thin regime): the result is *confounded*, not concludable.** With even
  modest anticipation (0.25), forward-looking agents collapse deep acquisition
  (`oldU ≈ 0.98`). But at thin margin (deep `R ≈ R_target`, marginal deep net ≈ 0) the
  *same* near-zero-net condition produces *both* the churn duration would fix (holders flip
  easily) *and* the steep ceiling (any anticipated lock flips them negative). So the thin
  sweep **cannot distinguish "duration is unnecessary" from "duration is merely
  unaffordable"** — at this margin they are the same amplification seen from two sides. The
  thin regime is therefore not a parkable gate-4 unknown; it says nothing. The **surplus
  regime below** is the only place the two halves come apart.

### L9 resolver — necessity and cost separated (surplus regime)

The surplus sweep (`surp_*`: `g = 4`, `budget = 300`, `storage_scale = 1.6`) changes the
holder *distribution* — generous reward + strong deep premium + ample storage seat many
*inframarginal* deep holders carrying a buffer (deep is fully covered, `deep_und = 0`, on
every row, so the regime is genuinely surplus, not merely well-provisioned).

| scenario | agents | `oChrn` (oldest-band churn) | `oldU` | `deep_und` |
|---|---|---|---|---|
| `surp_s0` | myopic | 0.251 | 0.000 | 0.000 |
| `surp_s2` | myopic | 0.110 | 0.000 | 0.000 |
| `surp_s4` | myopic | 0.084 | 0.000 | 0.000 |
| `surp_s0_antic` | anticipatory (0.25) | 0.137 | 0.000 | 0.000 |
| `surp_s2_antic` | anticipatory (0.25) | 0.045 | 0.000 | 0.000 |
| `surp_s4_antic` | anticipatory (0.25) | 0.010 | 0.000 | 0.000 |

The two halves now separate cleanly, and they land on **outcome 2** (of the three the
resolver was set up to distinguish):

- **Necessity — churn *persists* at surplus.** Flat-duration `surp_s0` churns `oChrn = 0.251`
  — *higher* than the thin `dur_s0` (0.215), with coverage complete throughout. The oldest
  tail oscillates even when holders carry a buffer, so the churn is **structural to the
  frontier-window dynamics, not a knife-edge artifact**. Outcome 1 (churn dissolves with
  surplus → duration retires) is ruled out: duration has a real job.
- **Duration damps it, coverage intact.** `surp_s0 → s2 → s4` = `0.251 → 0.110 → 0.084`
  (≈3×), with `deep_und = 0` the whole way — the tail-churn tool works in the regime that
  matters.
- **Cost — gentle, not a cliff.** The thin-regime collapse was a **pure margin artifact**:
  at surplus, anticipation costs *zero* coverage (`deep_und = 0.000`, `oldU = 0.000` on
  every `_antic` row) and in fact *further* reduces churn (`surp_s0` 0.251 → 0.137;
  `surp_s4` 0.084 → 0.010), because forward-looking holders who do acquire commit more
  stably. The willingness ceiling is affordable precisely where deep coverage has a buffer.
- **Internal validation of "surplus."** If holders were knife-edge, anticipation would
  collapse them as in the thin regime; it does not (`deep_und` stays 0). The buffer is
  real, which is what licenses reading the necessity and cost answers as separated.

**Resolution (L9): adopt age-scaled bond *duration* as the oldest-tail churn tool.** Churn
persists with surplus (necessity established) and its participation cost is gentle in the
well-provisioned regime (cost established). The L4 reversion trigger — oldest-band churn —
*fires even at surplus*, so flat-magnitude-**no-duration** is not the final shape; flat
magnitude **plus** age-scaled duration is. Gate 4's duration axis is thereby pre-settled:
it tunes the horizon level, not the in-or-out question. (Outcome 3 — churn persists with a
steep cost even at surplus, which would have pointed at a foundation permafloor instead of
a market mechanism — is *not* what the evidence shows; the market duration mechanism
suffices.)

### Iteration-2 caveats

- The split-endowment pair-sweep regime is a stress construction (co-location made scarce
  on purpose); the structural takeaways (joint lever; min-form tracks the crossing) carry
  forward, not the specific cell magnitudes.
- The dynamic world's recycling and lock dynamics are a minimal churn model, sufficient to
  give duration a job and to expose the willingness ceiling; richer arrival/exit processes
  are a later refinement if the gate-4 duration sweep needs them.
- The surplus regime (`surp_*`) is a constructed *thick* counterpart to the thin `dur_*`
  sweep — its specific levers (`g = 4`, `budget = 300`, `storage_scale = 1.6`) are chosen
  to seat inframarginal deep holders, not calibrated to a target chain state. What carries
  forward is the *separation* it produces (churn persists at surplus; anticipation costs no
  coverage there), not the magnitudes. The thin/surplus pair spans gate-4 (duration) ×
  gate-5 (thickness) — the same joint shape the L8 re-entanglement established.
- `deep_shard_size = 1.0` keeps every prior (iteration-1) scenario byte-identical; only the
  pair sweep varies it.

## Adjustment ledger — forward inputs to gates 4 and 5

Running record of model-surfaced design questions and the candidate adjustments they
imply, so the eventual gate-4/gate-5 work starts from the sim's evidence rather than a
blank page. Each item names the **evidence** (sim finding), the **disposition**
(decided / open), and the **reversion criterion** per `21-reversion-clause-discipline.mdc`
where a decision is provisional.

| # | Question (gate) | Evidence | Candidate adjustment / disposition |
|---|---|---|---|
| L1 | **`g(age)` value** (gate 4 / near-term pin) | `g` doesn't just clear deep — it **relocates the crux**: the unavoidable finite-provisioning residual sits on the **oldest tail at `g=1`**, the **shoulder at `g≈2`**, and **inverts (oldest over-covered, hot starving) at `g≥4`**. The shoulder (youngest deep shards, just aged out of hot, still partly replicated, *least* irreplaceable) is strictly less harmful than the tail (oldest, most irreplaceable, no recency backstop). | **Decided (target restated), leaning `g≈2`.** The goal is **not** "eliminate the residual" (impossible under reallocation at finite provisioning) but **"seat the residual on the least-critical band"** — i.e. choose `g` so coverage matches `R_target(age)`: highest-`R_target` oldest shards best-covered, shortfall on the shoulder. `g≈2` is that regime, not a lucky midpoint. `g` is genesis-fixed: pin for the *thick steady state*. Reopen if the thick-state sweep moves the shoulder-seating `g`. |
| L2 | **Bond upper bound** (gate 4) | `bond_high` (rate 8) → min-form `dS/dN=0.83` → deep starves; the binding condition is the **co-located min-form** `Σ min(⌊capital/bond⌋, ⌊storage/shard_size⌋) ≥ Σ_deep R_target` (L8), **not** distinct-actor count (slack at 80≥6). | **Decided (constraint form):** gate-4's upper bound is a **durability** constraint stated as min-form `dS/dN ≥ 1` over the expected *joint* storage×capital distribution — not a fairness limit. Fine sweep pins the rate that is simultaneously Sybil-deterring and min-form `dS/dN ≥ 1`. |
| L3 | **Empty-window definition** (gate 4) | The L8 min-form **unifies** what looked like two axes: `min(capital-leg, storage-leg)` is a single co-located number that binds on whichever leg is scarcer. `bond_high` binds on capital (min-form `0.83`); `pop_thin` binds on storage (min-form `0.39`). | **Decided (definition):** the window is empty iff *no* bond rate satisfies min-form `dS/dN ≥ 1` **and** Sybil-deterrence simultaneously. The capital and storage axes are not separate tests — they are the two legs of the one min-form, and gate 5's provisioning sets the storage leg (L8 re-entangles gates 4 and 5). |
| L4 | **Flat vs age-scaled bond *magnitude*** (gate 4) | Sim evidence: the mean-preserving tilt is a weak, mildly regressive lever that fights the premium (1c). The **decisive** argument is durability survival arithmetic: for irreplaceable data redundancy dominates per-holder reliability — `N=3,p=0.99 → ~1−10⁻⁶` vs `N=20,p=0.9 → ~1−10⁻²⁰`; the number of *distinct holders* swamps per-holder commitment for "does the data survive at all." So the oldest shards want the **most distinct holders → the most accessible (flat/low) bond**, never scaled up. Age-scaling magnitude raises the bond exactly where the widest pool is needed, and **flips the binding constraint** from the tractable aggregate-slot `dS/dN` (distinct-actor slack 80≥6) to the intractable **tail-distinct-actor** concentration (#4 aimed at the worst place). | **Resolved: flat magnitude.** The same evidence that gave the clean `dS/dN` condition (L2) *is* the argument for flat — age-scaling trades a tractable capacity constraint for an intractable tail-concentration one. Attraction onto old shards lives on the **reward** (`g·scarcity`, L1): reward attracts, flat bond keeps-accessible, no collision. The commitment-horizon instinct behind "age-scale it" is real but belongs in **duration, not magnitude** (L9). **Reversion:** reopen only if a gate-4 requirement needs stronger slashable commitment on the oldest *that duration (L9) cannot carry*. |
| L8 | **co-location: the min-form seating metric** (gate 4↔5 re-entanglement) | `bscale_s0` (flat) has *aggregate* `dS/dN=3.24` yet `deep_und=0.75`: capital sits with storage-poor capital-rich actors and storage with bond-constrained capital-poor archivers, so deep — needing *both* on the *same* actor — falls in the gap. The **min-form** `Σ min(⌊capital/bond⌋, ⌊storage/shard_size⌋)/Σ_deep R_target` reads **0.86<1**, predicting the starvation the aggregate masked. The **(bond × shard-size) pair sweep** confirms the joint lever: low-bond-alone (0.97/0.65) and small-shard-alone (0.91/0.47) each starve; the *pair* clears deep to 0, coinciding with the min-form crossing 1. | **Decided (metric swapped + gates re-entangled):** the seating metric is now the co-located min-form (implemented; the reported `dS/dN`). Gates 4 and 5 **cannot close independently** — the binding quantity is the count of co-located non-whale actors per deep shard, a joint function of bond (gate-4 capital leg) and shard size (gate-5 storage leg). Two levers grow the pool, tuned **together**: **low-flat bond** (recruits storage-rich) + **finer deep-shard granularity** (recruits capital-rich). Real-design form: **ratio-matching** (deep shard's storage:bond ratio inside the population's storage:capital distribution). |
| L5 | **Oldest-tail provision** (gate 4 + gate 5 jointly) | At `g=1` the residual is *exactly* the oldest tail (`g1_p13`); under a premium the oldest is over-covered. The tail is the crux only absent a premium. | **Open.** Candidates: (a) the age premium itself already covers the tail (sim supports this at `g≥2`), so possibly *no extra* tail mechanism is needed if `g` is set right; (b) permanent foundation floor on the tail as belt-and-suspenders; (c) joint foundation+staker `R_target` for the tail. Decide whether (a) suffices or (b)/(c) is required for irreplaceability margin. |
| L6 | **Foundation floor sizing** (gate 5) | `pop_thin` fails outright (`frac_under 1.000`, storage-bound, `dS/dN` fine); total coverage is supply-bound; a deep-prioritizing `g` leaves a *hot* shortfall during thin periods (`g≥4` band `0.0–0.2` up to 70 % under). | **Decided (sizing input):** the floor must cover (i) the absolute coverage gap when population is thin, **and** (ii) the *hot* class specifically when a deep-prioritizing `g` de-prioritizes it during the thin handoff window. Gate 5 sizes both. |
| L7 | **`g`-for-steady-state** (gate 4↔5 coupling) | `g` trades hot↔deep; the foundation floor absorbs whichever class `g` de-prioritizes in thin periods. | **Decided (method):** choose `g` for the thick steady state to **seat the residual on the shoulder** (L1 — coverage matched to `R_target(age)`); let gate-5's floor backstop the thin-period de-prioritized class. `g` and the floor are pinned *together*, not independently. |
| L9 | **Age-scaled bond *duration*** (gate 4, second axis) | The commitment-horizon job the tier system did belongs in the bond's **duration**, not magnitude (opportunity-cost on *willingness*, not an affordability gate). The **thin** dynamic sweep confounds the question: at near-zero deep margin the *same* condition produces both the churn (holders flip) and the steep ceiling (anticipation flips them negative), so it cannot tell "unnecessary" from "unaffordable." The **surplus** sweep (`surp_*`: `g=4`, `budget=300`, `storage_scale=1.6`; deep fully covered, holders inframarginal) separates them: oldest-band churn **persists** (`oChrn 0.251` at flat duration, *higher* than thin — structural, not knife-edge) and duration damps it (`0.251 → 0.084`); anticipation costs **zero** coverage at surplus (`deep_und 0`, `oldU 0` on every `_antic` row) and further lowers churn (`0.251 → 0.137`). | **RESOLVED: adopt age-scaled duration (outcome 2).** Necessity established (churn persists at surplus) and cost is gentle (the thin-regime collapse was a margin artifact). Final bond shape: **flat magnitude + age-scaled duration**. The L4 reversion trigger (oldest-band churn) *fires even at surplus*, so flat-no-duration is not the final shape. Gate 4's duration axis is pre-settled to **level tuning** (which horizon), not in/out. Outcome 3 (steep cost even at surplus → foundation permafloor) is *not* observed; the market mechanism suffices. |

### Robustness-sweep verdicts (which findings are structural)

- **Structural (survive the provisioning/endowment sweeps):** deep starves without a
  premium (direction); `g(age)` reallocates rather than manufactures coverage; total
  coverage is supply-bound; the empty-window is the **co-located min-form**
  `Σ min(⌊capital/bond⌋, ⌊storage/shard_size⌋) ≥ Σ_deep R_target` (L8) — which unifies the
  capital and storage axes into one binding number and catches the co-location starvation
  the aggregate ratio misses (and which the (bond × shard-size) pair sweep confirms is a
  *joint* lever); actor-level spread contains the whale the pseudonym metric hides; the
  age-tilted bond is a weak, mildly regressive lever that fights the `g(age)` premium
  (L4 → flat-on-deep default); age-scaled bond *duration* damps oldest-band churn under
  myopic agents without an affordability cost (L9).
- **Margin-artifacts (regime-specific, do not generalize):** the `deep_und=1.000`
  *magnitude* (a thin-supply corner that dissolves with provisioning); the specific
  residual-minimizing `g` value (baseline-supply-dependent); the exact `frac_under`
  borderline failures (`0.062` at strict `<0.05`).
