# Staker-archival simulation — design spec

**Status: iteration 3 (L10 + hardening, L11, L12, L13) BUILT and RUN — backfill-lag model
reopens L9 and hardening leans the pin toward age-scaled-constant; L11 derives the lean
equilibrium as an emergent attractor; L12 shows the genesis cold-start reaches that attractor
and the population-decaying foundation floor covers the transient; L13 shows the fee-era
shrinking subsidy thins the attractor (oldest tail first), the price-coupling death spiral is
*dampable* by an adaptive reward-share servo conditional on an adequate fee-market ceiling, and
the foundation floor re-engages as the market thins (2026-06-06).**
Crate `rust/shekyl-staking-sim`; first-build findings in §*Iteration 1 — results (first
build)*, robustness-sweep refinements in §*Iteration 1b — robustness sweeps and
residual-by-age*, the flat-vs-age-scaled-bond fork in §*Iteration 1c — the
flat-vs-age-scaled-bond fork (L4)*, the bond-duration + co-location work in §*Iteration 2
— bond duration (L9) and co-location (L8)*, the backfill-lag work in §*L10 — the
backfill-lag model*, and the forward worklist in §*Adjustment ledger* at the end of this doc.

**Iteration-3 headline (L10).** The backfill-lag model — deep-shard **fetch latency**
(committed-but-not-serving while fetching; drops instant), **decoupled** from the economic
game (game on committed replication = iteration-2-stable; retrieval coverage on seated
replication) — supplies the one thing the capacity-bound model structurally lacked: a
**timing-bound** coverage channel. With it, **both inputs to the iteration-2 "defer flat"
decision (below) reverse.** (1) The L9 *benefit*, previously "inferred and unmodeled," is now
modeled and **net-positive**: serving-coverage oscillation appears with latency (serving `oUmx`
0→0.46→0.71→1.0 across `L0..L4`), and age-scaled duration damps it while *also* improving mean
serving deep coverage at every latency (`L1` 0.263→0.222) and even at capacity binds (`lagbind`
churn 0.942→0.865) — it never worsened serving coverage. (2) The L9 *cost* (`bind_*`
"demonstrated reallocation hit") was a **final-epoch snapshot artifact**: on the windowed mean
(the steady-state read every other metric uses) it is within noise — `a10` 0.178→0.178
(*identical*), `a12`/`stor` slightly positive, `a08` +0.013 (not the "7×" the final-epoch
0.025→0.176 implied). With the benefit demonstrated net-positive and the cost dissolved, the
**sharpened L9 reversion criterion is MET → the disposition is reopened** (per
`21-reversion-clause-discipline.mdc`). The honest residue: L10 fixes the benefit's **sign**
(positive), not its **magnitude** — `fetch_latency_per_unit` is the post-testnet measurement —
so the remaining decision is the **genesis-pin shape** (flat-constant / age-scaled-constant /
duration-servo) under sign-known/magnitude-unknown, a priority-3 + `75-system-autonomy` human
call surfaced to the maintainer, **not** flipped unilaterally. **Hardening (§*L10 hardening*)**
then upgraded that basis: the benefit's sign is **robust across the survivable-latency band**
`L1–L4` (and honestly washes out at `L6`, where nothing helps); it **saturates in the duration
level** (`dur_age_scale` 4 ≡ 8 — so a genesis *constant* is calibration-insensitive, removing
the servo's affirmative case); the cost stays **dissolved across a widened bind grid** (`a06–a14`,
Δ within ±0.015 mixed-sign on the windowed mean); and the **bandwidth-bound regime** that most
resembles the real transport is the clearest win (improves even committed coverage 0.106→0.069).
On that basis the call **leans age-scaled-constant at a safe-side scale**, still a human
disposition. See §*L10 — the backfill-lag model* and §*L10 hardening*.

**Iteration-3 headline (L11).** Endogenous participation removes the last *asserted* input:
the lean operating point was previously a fixed population with a tuned `budget`. L11 makes
entry/exit a function of realized risk-adjusted yield (`apr = (reward − flow_cost) /
committed_bond`) vs. a per-actor reservation ρ, over a pool of *potential* archivers
(trickle-entry + hysteretic realized-yield-exit; fully gated, every pre-L11 scenario
byte-identical). The lean equilibrium then **emerges with three model-backed properties**:
(1) it is an **attractor** — cold-start-from-empty and trim-from-oversubscribed converge to
the same ~79-archiver, deep-covered point; (2) reservation is a **smooth monotone lever**
with a coverage knee (interior-feasible at ρ≈0.02); (3) **budget transfers to coverage
*through participation*** — `budget → APR → marginal entry → archiver count → coverage`, no
asserted population in the loop. Participation churn at the lean margin is **benign for
coverage** (`oUmx=0`, the L9 benign-rotation shape), and the lean-vs-robust spread tradeoff
is now emergent rather than tuned. The honest residue: L11 fixes the equilibrium's *shape*
(attractor, monotone transfer, sorting), not the live operating ρ a real market sits at
(post-testnet). It **unlocks L12/L13** as perturbations of this attractor (bootstrap = the
cold-start fill trajectory; fee-era = budget-shrink thinning; ρ is the home for L13's
price-feedback term). See §*L11 — endogenous participation*.

**Iteration-3 headline (L12).** Bootstrapping composes the L11 attractor with a
**growing frontier window** (genesis hot core + per-epoch block growth, so deep history
accrues *from zero*) and a **population-decaying foundation floor** (separately funded,
invisible to the reward servo; fully gated, legacy byte-identical). The model confirms the
ledger disposition with six findings: (1) the cold start **reaches the L11 attractor**
(steady ~76 archivers, deep covered) — bootstrap is the *transient approach*, not a new
equilibrium; (2) the bare transient deep gap is **total** (`bDU=1.0`) — a *timing* hole
(deep history forms ~10 epochs before archivers can seat it), not an economic failure; (3)
a genesis floor of `r_target_deep` replicas collapses that gap to `0.019` **with steady
archiver count unchanged** — it backstops retrieval without crowding out entry because it
is not in the reward `R`/`Σwork`; (4) the floor's decay schedule is a fine lever with a
wide safe band (aggressive withdrawal leaves only a ~2% hand-off residual); (5) the
APR-inversion **overshoot is real but modest** (peak 83–97 vs steady 76–78, worse on
*slow* growth) and the shed is **coverage-neutral** (`oUmx=0` — benign rotation, the
L9/L11 shape); (6) the bootstrap stress is the **growth/entry race** (block production vs.
capital-arrival rate), not the economics. Disposition: pin genesis constants for the thick
steady state, let the population-decaying floor cover the transient — and that floor's
*bootstrap* role is now its primary one (reframing L5/L6). Residue: the real growth rate,
genesis floor size, and safe decay schedule are post-testnet calibrations of an
already-understood curve. See §*L12 — bootstrapping / cold-start*.

**Iteration-3 headline (L13).** The fee-era end-state is the L11 attractor under a *shrinking*
purse (block subsidy → fees / bounded terminal subsidy; fully gated, legacy byte-identical).
Five findings: (1) a decaying subsidy **thins the attractor monotonically** along the L11
transfer curve in reverse, with a coverage knee at a terminal subsidy of ~80–100 (`bondA` 81→67
→54 as the floor drops 100→80→60); (2) the **oldest tail goes under first** — at the knee the
oldest band oscillates under (`oUmx 0.163`) while mid-deep still holds (`cDeepU 0.057`),
confirming the irreplaceable band is the most exposed; (3) the **price-coupling death spiral is
real** — a coverage shortfall lifting effective reservation (lost trust ⇒ expected
depreciation) deepens the collapse (`bondA` 39→17 vs the same floor without coupling); (4) the
**adaptive reward-share servo damps it** (burn.rs template: `bondA` 17→62, deep shortfall
1.0→0.21, by drawing fees up to ~116) — so the loop is **dampable, not an automatic priority-1
failure** — *conditional* on (a) the servo keying off a **sticky/smoothed** trust signal (a
servo reacting to the raw shortfall oscillates and underperforms a constant purse) and (b) an
**adequate fee-market ceiling**: below ~115 the servo saturates at the ceiling and coverage
stays gone — a **graceful loud failure** (fees cannot fund the deep history); (5) the L12
**foundation floor re-engages automatically** as the market thins (its population decay run in
reverse: `bDUf 0.425` vs bare `1.0`), the one non-market capacity source load-bearing at *both*
ends. Disposition: the durability requirement is the **adaptive servo + a backstop** (adequate
terminal-subsidy/fee ceiling, or the foundation floor); with them the spiral is bounded, without
them it runs. Residue: the live fee-market ceiling, the coupling strength, and the trust horizon
are post-testnet empirics of an already-understood control loop. See §*L13 — fee-era end-state*.

**Iteration-2 headline.** *(Superseded on the L9 disposition by the iteration-3 headline above;
retained for the audit trail of how "defer flat" was reached.)* (i) The seating metric is now the **L8 min-form** —
`Σ_actor min(⌊capital/bond⌋, ⌊storage/shard_size⌋) / Σ_deep R_target` — which catches the
co-location starvation the aggregate ratio missed: `bscale_s0` reads `0.86 < 1` (was
aggregate `3.24`) matching `deep_und 0.75`. (ii) The **(bond × shard-size) pair sweep**
confirms L8's joint claim — neither leg moves coverage alone (low bond + big shard, or
small shard + high bond, each still starve), only the *pair* clears deep, exactly when the
min-form crosses 1. (iii) **Age-scaled bond *duration* (L9): DEFER — default to flat
duration.** The lean test downgraded both halves of the surplus reading as regime artifacts.
*Necessity*: `oChrn` is the *abandonment rate*, not the coverage-oscillation metric the churn
sub-claim names; at the lean operating point flat duration shows `oUmx = 0` (no coverage
oscillation — the surplus `oChrn 0.251` was benign rotation the buffer backfilled), so the
benefit is **inferred and unmodeled** (the model is capacity- not timing-bound and cannot yet
represent the backfill-lag oscillation duration would fix). *Cost*: the one oscillating regime
is a **capacity bind** where age-scaled duration makes `deep_und` *worse*, and the `bind_*`
confirmation sweep banks this as a robust **lock-in reallocation cost** — age-scaling lifts the
oldest band by starving mid-deep (a redistribution signature: oldest `frac_under` ↓, mid-deep
↑), coverage-negative at every bind (0.025→0.176, 0.351→0.377, 0.57→0.623), saturating at the
first increment (`s2 = s4`). It is the **#3 finding compounded**: `g` already reallocates
oldest-ward, and age-scaled duration double-counts that pull, so stacked they over-concentrate
on the very oldest at a bind. **Demonstrated cost against unmodeled benefit is not insurance —
it is an unpriceable bet**, so the conservative genesis shape is **flat magnitude + flat
duration** (`g` does deep-prioritization with a single lever). Genesis-pin ordering reinforces
the defer: age-scaling can only be validated by a backfill-lag model needing post-testnet fetch
latencies, but the constant must be pinned pre-genesis — flat-constant is the pin with nothing
to walk back. Reversion (sharpened): reopen iff a backfill-lag model shows the stability benefit
**net of** the lean-margin reallocation cost is positive. The banked surplus facts (anticipation
sign-flip, outcome 3 ruled out) stay valid as surplus facts but don't reach the operating point. The 1c result, **L4 resolved**: keep flat bond *magnitude*
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
| bond **duration** (flat at genesis) | sets the **commitment horizon** (tier's old job) | churn-stability / willingness ceiling (L9) |

Reward attracts; flat magnitude keeps-accessible; flat duration commits without redistributing.
The L4 mistake to avoid is folding commitment-horizon into magnitude, where it fights
redundancy. **Caveat (L9 update):** the commitment-horizon job is real, but *age-scaling* the
duration is **deferred** — the lean test showed it is a second oldest-ward redistribution lever
that double-counts `g` and is coverage-negative at a capacity bind, with its stability benefit
unmodeled. A *flat* (non-zero) commitment horizon carries the willingness/commitment job at
genesis without the reallocation cost; age-scaling reopens only on a net-positive backfill-lag
finding (see §*L9 resolver — the lock-in reallocation cost*).

**The L4 reversion trigger (made measurable).** Flat-magnitude-no-duration is *complete*
unless a specific signal fires: a **churn-stability failure on the oldest band
specifically** — coverage present but oscillating, holders cycling off the irreplaceable
shards (the `oChrn` metric on the deepest band). If the oldest-band churn sub-claim holds,
flat magnitude without any duration term is the final shape and L9 stays parked. If it
*fails on the tail*, that — and only that — is when age-scaled **duration** (never
magnitude) earns its complexity. The trigger is the churn sub-claim's *fail metric*:
**coverage oscillation** (oldest-band `frac_under` dipping `> 0`), with abandonment
(`oChrn`) as the *diagnostic*, not the trigger. Iteration 2 exercises this and finds the
trigger **does not fire at the operating point**: abandonment persists thin (`oChrn 0.215`),
lean (0.17–0.40), and surplus (`oChrn 0.251`), but it is **benign rotation** — coverage never
drops (`deep_und 0`, and at the lean equilibrium `oUmx = 0` under flat duration). The one
regime with `oUmx > 0` is a *capacity bind* (`lean_osc_a10`, `deep_und 0.35`) that age-scaled
duration does **not** damp — and the `bind_*` sweep shows age-scaling there is *coverage-
negative* (a lock-in reallocation cost, the #3 redistribution shape compounded). So the L4
reversion trigger is **not** discharged: the benefit it would license is inferred-and-unmodeled
while the age-scaling cost is demonstrated. **The conservative genesis shape is flat magnitude +
flat duration** — `g` carries deep-prioritization with a single oldest-ward lever; age-scaled
duration would stack a second one. The clause stays open under the *sharpened* reversion
criterion (a backfill-lag model showing the stability benefit **net of** the lean-margin
reallocation cost is positive; see §*L9 resolver — the lock-in reallocation cost*). Magnitude
stays flat; duration stays flat at genesis, age-scaling deferred to a fork-worthy upgrade if
earned on net.

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

The surplus sweep settles the **cost** half cleanly, but — crucially — it **cannot settle
the necessity half**, and the distinction turns on *which metric* `oChrn` is:

- **`oChrn` is the abandonment rate, not the coverage-oscillation metric.** It measures
  holding-*flips* per held-epoch in the deepest band (`flips ÷ mean held`). The churn
  sub-claim's *failure condition*, by its own definition, is **coverage oscillation**
  (oldest-band `frac_under` dipping `> 0` — a shard repeatedly dropping below `R_target`);
  abandonment is the *diagnostic*, not the fail metric. `oChrn = 0.251` with `deep_und =
  0.000` is exactly consistent with **benign rotation**: holders turn over at 25%, but
  coverage never drops because at surplus a replacement is always standing by. Abandonment
  is not coverage-instability when the frontier backfills instantly.
- **Cost — gentle, not a cliff (this half is solid).** The thin-regime collapse was a
  **pure margin artifact**. At surplus, anticipation costs *zero* coverage (`deep_und =
  0.000`, `oldU = 0.000` on every `_antic` row) and *further* reduces abandonment (`surp_s0`
  0.251 → 0.137; `surp_s4` 0.084 → 0.010). The **anticipation sign-flip** — anticipation
  collapses deep when thin but *helps* it at surplus (0.137 < 0.251, 0.010 < 0.084) — is a
  self-check that can't be a tuning artifact: it is the buffer becoming real, anticipating
  holders self-selecting into shards they will keep rather than fleeing a knife-edge.
  **Outcome 3 (steep cost even at surplus → foundation permafloor) is ruled out**, and the
  market mechanism suffices on cost.
- **Why surplus cannot answer necessity.** The surplus regime, *by construction*,
  over-provisions — its slack is itself a coverage-stability mechanism. Coverage holds at
  surplus *because* of the buffer, which masks whatever duration is or isn't contributing.
  Duration is tested in the one regime where it isn't needed for stability. The
  decision-relevant comparison — does coverage *oscillate* at the operating point under flat
  duration, and does age-scaled duration damp it? — lives at the **lean equilibrium** the
  zero-profit entry condition actually drives toward (`R ≈ R_target`, no buffer), which the
  surplus sweep brackets from above and the thin sweep brackets from below without landing
  on.

### L9 resolver — the lean-equilibrium oscillation test (necessity, directly)

The lean equilibrium is the chain's real operating point: agents enter until the marginal
deep holder breaks even, so `R` settles toward *just-covering* (`R ≈ R_target`, no buffer).
There, abandonment turns into a coverage gap only if it actually does — a holder drops and
no replacement is standing by, so the oldest band's `frac_under` blips `> 0` and recovers.
The probe (`lean_probe_*`, `lean_osc_*`) tunes provisioning to put the *oldest band itself*
at `R ≈ R_target` (`mean_r ≈ 6`, the band's target), then reads **`oUmx`** — the max
oldest-band `frac_under` over the window, i.e. the coverage-oscillation metric the sub-claim
names — flat (`s0`) vs age-scaled (`s4`) duration.

| scenario | oldest `mean_r` / `r_tgt` | `deep_und` | **`oUmx`** (oscillation) | `oUvar` | `oChrn` (abandon.) |
|---|---|---|---|---|---|
| `dur_s0` (g2, budget 100) | 5.80 / 6 | 0.125 | **0.000** | 0 | 0.215 |
| `lean_probe_p090` | 6.33 / 6 | 0.116 | **0.000** | 0 | 0.169 |
| `lean_probe_p100/115/130` | 6.94–8.65 / 6 | 0.000 | **0.000** | 0 | 0.19–0.21 |
| `lean_osc_a05_s0` (lean, slow churn, flat) | 6.55 / 6 | 0.000 | **0.000** | 0 | 0.177 |
| `lean_osc_a05_s4` (lean, slow churn, age-scaled) | 6.55 / 6 | 0.018 | **0.000** | 0 | 0.100 |
| `lean_osc_a10_s0` (capacity bind, flat) | 6.41 / 6 | 0.351 | **0.184** | 0.0016 | 0.313 |
| `lean_osc_a10_s4` (capacity bind, age-scaled) | 6.45 / 6 | 0.377 | **0.184** | 0.0016 | 0.172 |
| `lean_osc_a20_s0/s4` (fast churn) | 7.00 / 6 | 0.000 | **0.000** | 0 | 0.397 |

The test lands on the user's **second informative outcome**: at the lean equilibrium, flat
duration shows **no coverage oscillation**, so necessity is **not** directly confirmed.

- **No oscillation at the lean equilibrium under flat duration.** Across two lean points
  flanking the target — `dur_s0` (oldest `mean_r = 5.80`, *below* target) and `lean_osc_a05`
  (`6.55`, just above) — and the just-covering `lean_probe` points, `oUmx = 0` and `oUvar =
  0` under flat duration. The oldest band, buffer removed, **never dips below `R_target`**;
  the full-re-optimization frontier backfills any drop within the epoch. The abandonment
  (`oChrn` 0.17–0.40) is **benign rotation** all the way down. The surplus `0.251` was
  benign rotation, confirmed.
- **The one regime that oscillates is a capacity bind duration does *not* fix.** `oUmx > 0`
  appears only at `lean_osc_a10` (`oUmx = 0.184`) — but that is **persistent under-coverage**
  (`deep_und = 0.35`, co-located `dS/dN = 1.00`, the seating constraint binding), not lean
  churn oscillation. Age-scaled duration there gives an **identical `oUmx = 0.184` and a
  *worse* `deep_und` (0.377)**: locking holders in place reduces reallocation flexibility
  and mildly aggravates the shortfall. Duration is the wrong tool for a capacity gap, and
  this is direct evidence *against* the "duration stabilizes coverage" mechanism in the only
  regime where coverage is unstable.
- **Modeling bound on the negative result.** `run_epoch` re-optimizes every actor each epoch
  (honoring locks), so backfill is same-epoch and coverage is **capacity-determined, not
  timing-determined**. The model therefore *cannot* exhibit drop-without-standing-replacement
  oscillation unless capacity binds — at which point it shows as persistent under-coverage
  (the `a10` row), not oscillation. A richer arrival/exit process with backfill *lag* is the
  refinement that could surface lean oscillation if it exists; until then, the negative
  result is "no oscillation in a model without backfill friction," which is suggestive, not
  conclusive — hence necessity **inferred**, not refuted.

### L9 resolver — the lock-in reallocation *cost* (the same downgrade necessity got)

The lean-oscillation test that downgraded necessity carries a **cost** signal that the
surplus "gentle" reading masked exactly the way it masked benign rotation — so the cost
gets the same downgrade. The `a10` row is the tell: flat `deep_und = 0.351`, age-scaled
`0.377` (*worse*), and the pairing with the band detail is a **redistribution signature, not
noise** — under age-scaling the oldest band lifts (`mean_r` 6.41→6.45, `frac_under`
0.041→0.020) while the adjacent mid-deep `[0.6–0.8]` starves (`frac_under` 0.346→0.410).
Age-scaled duration *locks holders onto the oldest shards* (the knob working as designed),
but at a capacity bind those locked actors cannot redeploy to mid-deep, which has no slack
to backfill. That is a **lock-in opportunity cost that bites exactly at the operating
regime**; surplus called it "gentle" only because the slack absorbed it.

The confirmation sweep (`bind_*`: lean base, capacity bound three independent ways — aging
`0.08`/`0.10`/`0.12` and a storage-tightened `ss = 0.85`; graded duration `s0/s2/s4`)
banks the **direction** as robust and bind-generic:

| bind | flat `s0` `deep_und` | age-scaled `s2`=`s4` `deep_und` | which band starves under age-scaling |
|---|---|---|---|
| `a08` (mild) | 0.025 | **0.176** (7×) | shallowest-deep `[0.4–0.6]` (0.049→0.344); oldest protected |
| `a10` (bind) | 0.351 | **0.377** | mid-deep `[0.6–0.8]` (0.346→0.410); oldest protected (→0.020) |
| `stor` (storage) | 0.570 | **0.623** | broad — bind so tight even oldest can't be protected (0.449→0.490) |
| `a12` / no bind | 0.000 | 0.000 | none — slack absorbs the lock-in (the surplus reading) |

> **CORRECTION (iteration 3, L10).** This table reads `deep_und` at the **final epoch**. On
> the **windowed mean** (the steady-state read used everywhere else), the cost dissolves —
> `a10` is 0.178→0.178 (identical), `a08` is 0.016→0.029 (+0.013, not 7×), `a12`/`stor`
> slightly positive. The "coverage-negative at every bind" reading below is a final-epoch
> artifact; see the L10 subsection. The mechanism (oldest-ward pull within deep) is real but
> does not produce a net aggregate coverage loss at steady state.

- **Coverage-negative at every bind, never positive.** Wherever capacity binds, age-scaled
  duration worsens aggregate deep coverage (or leaves it equal); it never improves it. The
  starving band tracks where the slack is (shallowest-deep, mid-deep, or broad), but the
  direction is invariant: coverage is pulled **oldest-ward within deep** and the aggregate
  drops. The magnitude is *not* uniformly small — `a08` is a 7× worsening (0.025→0.176).
- **The cost saturates at the first increment.** `s2 = s4` at every bind: even modest
  age-scaling incurs the full reallocation hit. There is no "gentle low-scale" setting that
  buys the lock-in without the cost.
- **It is the #3 finding's shape, compounded.** Reward-`g` reallocates hot→deep without
  manufacturing coverage; age-scaled duration reallocates *within-deep, oldest-ward*, also
  without manufacturing coverage. Both are oldest-ward distribution levers; only **capacity
  (L8)** creates coverage. Stacked, they apply oldest-ward pressure *twice* — at a bind you
  over-concentrate on the very oldest at the expense of hot *and* mid-deep. `a10`/`a08` are
  that double-count showing up. Age-scaled duration is therefore not an independent benefit;
  it **double-counts a reallocation `g` already buys**.

**Resolution (L9): default to FLAT duration; defer age-scaling under a net-benefit reversion
clause. Both halves of the surplus reading were regime artifacts.** The lean test resolved
more than necessity:

- **Cost: demonstrated at the operating regime** (a reallocation hit, bind-generic,
  saturating at `s2`, can be large, compounding with `g` per #3). The surplus "gentle" was
  slack-masking.
- **Benefit (necessity): inferred and unmodeled** (no lean oscillation observed under flat;
  the model is capacity- not timing-bound, so the benefit a backfill-lag model might show is
  not yet representable).
- **Demonstrated cost against unmodeled benefit is not insurance — it is an unpriceable
  bet.** So the conservative genesis shape is **flat magnitude + flat duration**: `g` does
  the deep-prioritization with a *single* oldest-ward lever, flat duration adds no second
  redistribution lever and no reallocation cost.
- **Reversion criterion (`21-reversion-clause-discipline.mdc`), sharpened.** Age-scaling is
  deferred, reopened iff **a backfill-lag churn model shows the timing-stability benefit
  *net of* the lean-margin reallocation cost is positive** (not merely "`oUmx > 0` under flat
  damped by age-scaled" — the damping must beat the demonstrated mid-deep cost on the
  aggregate). The cost *magnitude* across binds is banked as direction-confirmed; a wider
  bind grid would refine the number but cannot flip the sign.
- **Genesis-pin ordering makes the defer cleaner, not harder.** Duration (and its level, if a
  genesis constant) is consensus-visible → pinned pre-genesis. But the backfill-lag model
  that could earn age-scaling needs **real fetch latencies** (deep-shard size over the actual
  anonymizing transport) — a *post-testnet* measurement, not a pre-genesis number. You cannot
  validate age-scaling before you must pin it. **Flat-constant duration is the pin that is
  safe under that ordering**: no demonstrated cost, no reliance on an unproven benefit,
  nothing to walk back. Preserving the age-scaling *option* without a fork would mean a
  duration **servo** with a genesis-set range — buying the option at the price of a new
  governance/manipulation surface, which on current evidence (cost shown, benefit not) is not
  worth it. Pin flat; if a backfill-lag model later earns age-scaling on net, that is a
  fork-worthy upgrade with evidence behind it.

The surplus facts banked earlier stay valid *as surplus facts* — the anticipation sign-flip
proves the buffer is real, outcome 3 is ruled out — they simply do not reach the lean
operating point that governs the pin. The unification: **capacity creates coverage (L8); the
age-scaling levers (`g`, duration) only redistribute it (#3, L9); flat duration is declining
to stack a second redistribution lever on a system that already has one.**

> **UPDATE (iteration 3, L10) — both legs of the "defer flat" decision reversed; the
> reversion criterion is MET.** The backfill-lag model (below) does two things the
> "defer flat" disposition assumed could not be done. (1) It **models the benefit** that
> was "inferred and unmodeled," and the benefit is real and net-positive. (2) It forced a
> re-read of the `bind_*` "demonstrated cost," which turns out to be a **final-epoch
> snapshot artifact** — on the windowed mean (the same steady-state read every other metric
> uses) the cost is within noise (`a10` 0.178→0.178 *identical*; `a12`/`stor` slightly
> *positive*; `a08` +0.013, not the "7×" the final-epoch 0.025→0.176 suggested). With the
> cost dissolved and the benefit demonstrated net-positive at the operating margin, the
> sharpened reversion criterion ("backfill-lag model shows the timing-stability benefit net
> of the lean-margin reallocation cost is positive") is **satisfied**. The disposition is
> **reopened**; see the L10 subsection for the evidence and the remaining (magnitude /
> genesis-pin-shape) decision, which is a human call per `21-reversion-clause-discipline.mdc`.

### L10 — the backfill-lag model: the benefit, modeled (and the `bind_*` cost reconsidered)

The L9 disposition turned on a benefit that was *unmodeled* (the iteration-2 model is
capacity-bound — same-epoch full re-optimization — so it cannot represent a drop that opens
a coverage gap before a replacement is serving) weighed against a cost that was *measured*
(`bind_*`). L10 supplies the missing model and, in doing so, overturns both inputs.

**The model change (spec).** A freshly-acquired deep shard is *committed* (consumes storage,
posts the bond, earns reward — you are paid to **store**, verified by challenge, L14) but is
**not yet serving**: it takes `round(deep_shard_size · fetch_latency_per_unit)` epochs to
seat (`shard size ÷ anonymizing-transport throughput`, the post-testnet measurement). Drops
are instant. Crucially, the lag is **decoupled from the economic game**: the game runs on
*committed* replication (`World::replication`, unchanged — iteration-2 stable), and only the
*retrieval-coverage metric* runs on *seated* replication (`World::serving_replication`). The
first cut that fed seating back into reward death-spiraled the deep game (agents drop-and-
refetch at the hot→deep bond boundary, never seat, band `[0.6–0.8]` → `mean_r 0`); decoupling
isolates the actual L9 question — *does lagged retrieval coverage oscillate, and does
age-scaled duration damp it net of the lock-in cost* — from an unrelated incentive pathology.

**Finding 1 — the timing-bound channel is real (the capacity-bound model could not show it).**
At the covered lean point (`lag_*`, slow churn, committed `deep_und = 0` throughout), serving
coverage degrades as latency rises and oscillation appears where there was none:

| latency | flat `s0` serving `deep_und` (mean) | `s0` serving `oUmx` | age-scaled `s4` serving `deep_und` | `s4` serving `oUmx` | oldest churn `s0`→`s4` |
|---|---|---|---|---|---|
| `L0` (instant) | 0.003 | 0.00 | 0.011 | 0.00 | 0.171 → 0.090 |
| `L1` | 0.263 | 0.458 | **0.222** | **0.179** | 0.171 → 0.090 |
| `L2` | 0.580 | 0.708 | **0.465** | **0.500** | 0.171 → 0.090 |
| `L4` | 0.915 | 1.000 | **0.839** | **0.875** | 0.171 → 0.090 |

Age-scaled duration reduces oldest churn (0.171→0.090 robustly), and through it **damps the
serving-coverage oscillation** (`oUmx` lower at every latency) **and improves mean serving
deep coverage** (`deep_und` lower at every latency). This is the benefit the prior iteration
could only infer.

**Finding 2 — the benefit is net-positive even at a capacity bind.** The `lag_*` point has no
bind, so age-scaling there pays no reallocation cost. The honest net test adds latency `L2`
*on top of* the `bind_*` capacity binds (`lagbind_*`):

| bind + `L2` | flat `s0` committed `deep_und` | `s4` committed `deep_und` | flat `s0` serving `deep_und` | `s4` serving `deep_und` | oldest churn `s0`→`s4` |
|---|---|---|---|---|---|
| churn (`aging 0.10`) | 0.192 | 0.092 | 0.942 | **0.865** | 0.329 → 0.167 |
| storage (`ss 0.85`) | 0.367 | 0.317 | 0.988 | **0.974** | 0.263 → 0.179 |

Serving coverage is **better under age-scaling at the bind too** (`oUmx` is saturated at 1.0
in these harsh binds, so the oscillation benefit is masked there, but the mean-coverage net is
positive). Age-scaling never worsened serving coverage in any L10 regime.

**Finding 3 — the `bind_*` "demonstrated cost" was a final-epoch artifact.** The reconciliation
that Finding 2 forced: `lagbind` committed `deep_und` improves under age-scaling
(churn 0.192→0.092), the *opposite* of the `bind_*` table above (`a10` 0.351→0.377). Fetch
latency does not touch the committed game (confirmed: `lag_L0..L4` all committed `deep_und = 0`),
so the difference is the read. The `bind_*` cost was measured on the **final epoch**; on the
**windowed mean** (`bind_*` runs 80 epochs / 20-epoch window — the same steady-state read style
`oUmx` uses, now banked as the `cDeepU` column so the snapshot trap cannot recur):

| bind | flat `s0` **final** | `s4` **final** | flat `s0` **mean(20)** | `s4` **mean(20)** |
|---|---|---|---|---|
| `a08` | 0.025 | 0.176 ("7×") | 0.016 | 0.029 (+0.013) |
| `a10` | 0.351 | 0.377 | 0.178 | **0.178 (identical)** |
| `a12` | 0.000 | 0.000 | 0.025 | 0.023 (better) |
| `stor` | 0.570 | 0.623 | 0.359 | 0.344 (better) |

The "coverage-negative at every bind" claim does **not survive the windowed mean**. The
reallocation cost is within noise (±0.013, mixed sign), not the robust large effect the
final-epoch snapshots implied. The mechanism (age-scaling pulls coverage oldest-ward within
deep) is real, but it does **not** produce a net aggregate coverage loss at steady state.

**Reversion-clause evaluation (`21-reversion-clause-discipline.mdc`).** The sharpened
criterion was: *reopen iff a backfill-lag model shows the timing-stability benefit net of the
lean-margin reallocation cost is positive.* L10 is that model, and it shows: (a) the benefit
exists and is net-positive on serving coverage across all regimes including binds; (b) the
"lean-margin reallocation cost" it was to be netted against is a final-epoch artifact that the
proper windowed read dissolves. **The criterion is met → the disposition is reopened.**

**What is NOT yet resolved (the honest residue).** L10 establishes the **sign** of the benefit
(positive), not its **magnitude at the real operating point**, because `fetch_latency_per_unit`
is the post-testnet measurement that does not exist pre-genesis — the same ordering tension the
"defer flat" resolution named, now cutting the other way. The remaining decision is therefore
not "cost vs. no-benefit" (resolved: no robust cost, real benefit) but **the genesis-pin
shape** under sign-known / magnitude-unknown:

- **Flat-constant** — forgoes a demonstrated-net-positive mechanism; safe but leaves coverage
  stability on the table if real latencies are non-trivial (the `L1`+ rows say they bite).
- **Age-scaled-constant (a chosen `dur_age_scale`)** — captures the benefit; bets on an
  uncalibrated magnitude for the *level*, though the *sign* is now model-backed.
- **Duration servo (genesis-set range, post-testnet tune)** — preserves the option without a
  fork; costs a governance/manipulation surface (`75-system-autonomy.mdc` caveat).

This is a priority-3 (longevity) / `75-system-autonomy` judgment call, not a priority-1/2
safety question, and it is a human disposition call per the rule. The flip from "defer flat"
is **not** taken unilaterally: the evidence is recorded, the criterion is marked met, and the
pin-shape decision is surfaced to the maintainer.

### L10 hardening — sign robustness, level saturation, cost dissolved across the envelope

The reopen above rests on a benefit whose **sign** is known and **magnitude** is not. Before
taking the pin-shape question to a decision, the residue was hardened along the axes the
decision actually turns on: *is the sign robust across the plausible operating envelope, or an
artifact of two chosen points?* and *how sensitive is the benefit to getting the duration
**level** right?* (the latter is the literal constant-vs-servo question). The instrument was
also fixed at the source — committed deep-coverage is now banked as a **windowed mean**
(`cDeepU`), so the final-epoch snapshot that produced the retracted "7×" cost cannot be read by
accident again.

**H1 — the benefit is robust across the survivable-latency band, and honestly washes out beyond
it.** Densifying the latency grid to `L ∈ {0,1,2,3,4,6}` epochs maps the benefit *curve*, not
two endpoints (serving deep_und, flat `s0` vs age-scaled `s4`):

| latency | `s0` serving deep_und | `s4` serving deep_und | benefit (`s0−s4`) | `s0` sOUmx | `s4` sOUmx |
|---|---|---|---|---|---|
| `L1` | 0.263 | 0.222 | **+0.041** | 0.458 | 0.179 |
| `L2` | 0.580 | 0.465 | **+0.115** | 0.708 | 0.500 |
| `L3` | 0.804 | 0.684 | **+0.120** | 0.975 | 0.717 |
| `L4` | 0.915 | 0.839 | **+0.076** | 1.000 | 0.875 |
| `L6` | 0.983 | 0.991 | −0.008 | 1.000 | 1.000 |

The benefit is positive and material across `L1–L4` (peaking ~`L2–L3` at +0.12), then **vanishes
at `L6`** where both arms saturate near-total under-coverage. This is the honest sharpening the
two-point table hid: age-scaled duration helps in the regime where fetch latency is *survivable*;
in the regime where backfill cannot keep pace at all (`L6`), holding fewer-but-standing replicas
no longer rescues coverage — nothing does. The sign is robust where it matters and the maintainer
is told exactly where it stops mattering.

**H2 — the benefit *saturates* in the duration level (the pivotal constant-vs-servo input).**
At fixed `L2`, sweeping `bond_dur_age_scale ∈ {0,1,2,4,8}`:

| `dur_age_scale` | oldest churn | serving deep_und | sOUmx | committed `cDeepU` |
|---|---|---|---|---|
| 0 (flat) | 0.171 | 0.580 | 0.708 | 0.003 |
| 1 | 0.157 | 0.560 | 0.762 | 0.006 |
| 2 | 0.113 | 0.507 | 0.510 | 0.008 |
| 4 | 0.090 | **0.465** | 0.500 | 0.011 |
| 8 | 0.090 | **0.465** | 0.500 | 0.011 |

Serving coverage improves monotonically `0→4` and then **lands on a flat plateau** (`d4 ≡ d8`
to three decimals — the locks already saturate against the recycle horizon, so more scaling does
nothing). The committed cost rises gently (0.003→0.011) and plateaus at the same point. (One wrinkle:
sOUmx ticks *up* at `d1` — 0.762 vs flat 0.708 — before falling, a small low-scale non-monotonicity,
but it is dominated by `d2`+.) **Decision-relevant consequence:** because the benefit sits on a broad
plateau, a genesis *constant* anywhere in a wide band (scale ≳ 2) captures essentially all of it —
the pin does **not** need post-testnet precision. That removes the main affirmative case for the
**servo** (there is no fine level to tune toward), and correspondingly strengthens **age-scaled-constant
at a safe-side scale** as the shape that captures the benefit without buying a governance/manipulation
surface (`75-system-autonomy.mdc`).

**H3 — the bandwidth-bound regime is the clearest win.** At `L2` with fresh fetches throttled to
one per epoch (`lag_rate1`, `acq_rate = 1` — backfill cannot keep pace with churn), age-scaling
improves *every* axis, including the **committed** game it leaves untouched everywhere else:

| | committed `cDeepU` | serving deep_und | sOUmx | oldest churn |
|---|---|---|---|---|
| flat `s0` | 0.106 | 0.624 | 0.745 | 0.148 |
| age-scaled `s4` | **0.069** | **0.540** | **0.696** | 0.108 |

When refill is rate-limited, holding-not-dropping is strictly better and duration is exactly the
lever that enforces it — so the benefit appears even on committed coverage (0.106→0.069), not only
on the serving view. This is the regime the real anonymizing transport (slow deep fetch) most
resembles.

**H4 — the dissolved cost stays dissolved across a widened bind grid.** Re-reading the
reallocation cost on the banked **committed windowed mean** (`cDeepU`) across `a06–a14` + the
storage bind (not the three original points):

| bind | `cDeepU` flat `s0` | `cDeepU` `s4` | Δ (`s4−s0`) | final-epoch snapshot `s0`→`s4` (the artifact) |
|---|---|---|---|---|
| `a06` | 0.072 | 0.064 | −0.008 (better) | 0.019 → 0.058 |
| `a08` | 0.016 | 0.029 | +0.013 (worse) | 0.025 → 0.176 |
| `a10` | 0.178 | 0.178 | 0.000 | 0.351 → 0.377 |
| `a12` | 0.025 | 0.023 | −0.002 (better) | 0.000 → 0.000 |
| `a14` | 0.093 | 0.093 | 0.000 | 0.000 → 0.000 |
| `stor` | 0.359 | 0.344 | −0.015 (better) | 0.570 → 0.623 |

The windowed-mean cost delta is mixed-sign within ±0.015 (mean ≈ −0.002) across the whole grid —
the single positive (`a08`, +0.013) is the lone outlier, and every other bind is neutral or
*better* under age-scaling. Meanwhile the final-epoch snapshots still show the misleading
oldest-ward pattern (`a06` 0.019→0.058, `a08` 0.025→0.176), now demonstrably the artifact and not
the steady state. Finding 3 holds and strengthens; there is no robust committed reallocation cost
to net against the benefit.

**Hardened residue.** The pin-shape question is now better-posed than "sign known, magnitude
unknown": the **sign is robust across the survivable-latency band** (H1), the benefit
**saturates in the level so the pin is calibration-insensitive** (H2), the **cost is dissolved
across the bind envelope** (H4), and the bandwidth-bound regime that most resembles the real
transport is the **clearest win** (H3). The honest limits that remain: the absolute *magnitude*
at the real operating point still needs `fetch_latency_per_unit` (post-testnet), and the benefit
*does* wash out at extreme latency (`L6`). On this hardened basis the maintainer call leans
**age-scaled-constant at a safe-side scale** (H2 removes the servo's affirmative case), but the
flip remains a priority-3 / `75-system-autonomy` human disposition, not an automatic one.

**Out of scope for L10 (deferred to L15).** Correlated *actor* exit (a cohort of archivers going
offline together) is a distinct oscillation source, but age-scaled duration is a per-actor
*shard-drop* deterrent, not an uptime guarantee — an offline actor's locks are moot. Modeling
correlated exit therefore tests retrieval/uptime realism, not the duration lever, and belongs to
L15 (retrieval / correlated-failure realism), not here.

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

## Forward modeling — iteration-3 scope and the staking-regime far ends

The model so far answers a *steady-state coverage* question: given a populated archiver
population best-responding to a reward servo, where does coverage sit by age band, and what
do the bond/`g`/duration levers do to it. That frame has now paid out (L1–L9). The questions
it **cannot** answer — and which govern whether the mechanism survives contact with a real
chain — fall in two groups: **missing model elements** and **the two far ends of the regime**.

### Missing model elements (what iteration 3 needs)

1. **Backfill lag / arrival-exit dynamics (the L9 reversion hinge).** `run_epoch` re-optimizes
   every actor each epoch, so backfill is same-epoch and the model is **capacity-bound, not
   timing-bound** — it structurally cannot exhibit the drop-without-standing-replacement
   oscillation that age-scaled duration would fix. To price the L9 *benefit* (and thus
   discharge or close its reversion clause) the model needs **rate-limited acquisition** (an
   actor seats only so many shards per epoch, bounded by bandwidth), **real fetch latency**
   for deep shards (shard size ÷ anonymizing-transport throughput — a *post-testnet*
   measurement), and **staggered arrival/exit** rather than synchronous re-optimization. This
   is the single most decision-relevant gap: it is the only thing that can move L9 off "flat
   duration, age-scaling deferred."
2. **Endogenous participation / the economic layer.** `budget` is exogenous and "work" is
   abstract; the *lean equilibrium* (entry until the marginal archiver breaks even) is
   **asserted, not derived**. Iteration 3 should make entry/exit a function of risk-adjusted
   yield — archival APR (token-denominated reward ÷ bonded capital) vs. the bond's opportunity
   cost vs. price expectations — so the operating point *emerges* instead of being tuned. This
   is also the hook for the fee-era transition (below).
3. **The proof-of-archival mechanism (the actual Sybil/free-rider gate).** Reward is for
   *provable* archival work, but the model rewards declared holdings. The free-rider — claim
   reward without storing, or store-but-refuse-to-serve — is gated by the **challenge/audit
   model** (how often holders are challenged to prove possession, the cost of faking, the
   penalty), which is entirely unmodeled and is where the real Sybil economics live. The bond
   is the *capital* cost; the challenge cadence is the *operational* cost.
4. **Retrieval / demand side.** Coverage (R replicas *exist*) is necessary but the point is
   **retrieval within latency** given holder uptime and the anonymizing read path. Per-holder
   availability/uptime (distinct from the hold/drop decision), and the read-path latency, set
   the *real* `R_target` (replicas needed to hit a retrieval-availability target). Without
   this, `R_target` is a stipulated constant rather than a derived one.
5. **Correlated failure (the L4 survival arithmetic's hidden assumption).** The "redundancy
   dominates per-holder reliability" argument (`N=3,p=.99` vs `N=20,p=.9`) assumes
   **independent** failure. Correlated loss (shared datacenter, jurisdiction seizure, common
   software bug) breaks it. `R_target` and the spread metric should carry a **diversity axis**
   (jurisdiction/ASN/implementation), not just actor-count Gini — privacy-compatible diversity
   measurement is itself a research question (mission priority 2).
6. **Bond lifecycle.** Slashing conditions (a failed challenge?), graceful-exit return,
   partial slashing, and the capital-lockup opportunity cost over the duration are abstracted
   to a flat seating cost. The duration knob's *real* cost/benefit lives here.
7. **Unbounded deep-history growth.** Deep shards accumulate forever; total archival storage
   demand grows with chain age while the paid population may not. This is a long-horizon
   sustainability term, not a steady-state one (next subsection).

### The two far ends of the staking regime

The steady-state frame brackets the regime; the ends are where it breaks. Both are
**mission-priority-3 (outlast-the-team) timeframes** and neither is in the current model.

**Far end A — bootstrapping (genesis → thick): the cold-start.** At genesis there is almost
no deep history, so the deep/oldest bands are empty and `R_target(age)` for deep is trivially
met — the archival incentive has little to *do* early, yet the chain's promise (deep history
retrievable for decades) depends on archivers being present *as* deep history accrues. Three
coupled problems:
- **Chicken-and-egg with an APR inversion.** With reward ∝ `budget·work/Σwork`, few early
  archivers split the budget → **high early APR** (good for buy-in), which then *dilutes* as
  the population thickens. The risk is **overshoot**: high APR pulls in entrants who exit when
  APR normalizes, manufacturing exactly the early churn the system can least afford (deep
  history is youngest and thinnest then). Modeling this needs the endogenous-participation
  layer (#2) plus a *growing* frontier window (the current model recycles a fixed-size
  window; bootstrap grows it from zero).
- **The foundation floor is a *bootstrap* mechanism, not just a thin-period backstop.** L5/L6
  framed the floor as covering thin-period gaps; bootstrapping reframes it as the **genesis
  coverage guarantee that decays as the staker population thickens** — foundation runs
  archival nodes to hold the line until the market can, then backs off on a planned schedule
  (population- or chain-age-indexed). This wants its own decay-curve design.
- **Pinning under no-data (the L9 ordering, generalized).** We just argued duration must be
  pinned pre-genesis without the data to validate age-scaling. *Every* genesis-fixed parameter
  (`g`, bond rate, `R_target`, budget share) has this shape: the correct value depends on a
  thick steady state we cannot observe pre-genesis. The discipline (L1/L7): **pin for the
  thick steady state, accept the bootstrap transient is suboptimal, and let the foundation
  floor cover the transient** — rather than pinning for the bootstrap and being wrong forever.

**Far end B — the fee-era end-state (mining-era end, ~30 yr): the thin-and-declining tail.**
As block subsidy → 0 (per `00-mission.mdc` timeframe 2), the archival budget must come from
**fees or a bounded terminal subsidy**. If the budget shrinks, the lean equilibrium thins —
fewer archivers break even — and coverage drifts toward or below `R_target`, with the
**oldest tail most exposed** (most data, least recent fee activity to pay for it), exactly
the irreplaceable band. Two failure modes to model:
- **Demand outgrowing paid capacity.** Deep history grows linearly with chain age; if archival
  demand outgrows the fee-funded population, the system must adaptively raise the archival
  reward share (per `75-system-autonomy.mdc`, the `burn.rs` adaptive model is the template),
  not rely on manual intervention. Whether the fee market *can* fund archival of an
  ever-growing deep history is the core sustainability question.
- **Token-price death-spiral coupling.** Token-denominated reward falls with price → archivers
  exit → coverage/retrievability falls → trust falls → price falls. The adaptive budget-share
  mechanism must *damp* this loop; an undamped coupling is a priority-1 (security/durability)
  failure. This needs the economic layer (#2) with a price/feedback term.

The unifying note: iteration 1–2 established that **capacity creates coverage and the
age-scaling levers only redistribute it**. The far ends are both **capacity** questions —
bootstrap is "capacity not yet present," fee-era is "capacity no longer paid for" — which is
why the foundation floor (the one non-market capacity source) is load-bearing at *both* ends
and why getting its sizing/decay right (L5/L6) is the highest-leverage open item.

### L11 — endogenous participation: the lean equilibrium *derived*, not asserted

Every prior iteration **asserted** the lean operating point: the population was fixed at
`n_actors` and `budget` was tuned so coverage landed near `R_target`. That makes "the
system sits at the lean equilibrium" an input, not a result. L11 removes the assertion —
the population becomes a **pool of potential archivers**, and entry/exit is governed by
**realized risk-adjusted yield vs. a per-actor reservation**, so the operating point
*emerges*.

**Specification.** Each actor `a` carries a `reservation` ρ_a — its opportunity cost per
epoch for capital deployed into bonds. Each epoch:

- **Entry (trickle):** up to `entry_per_epoch` inactive actors are admitted (capital
  arrives at a finite rate, not instantaneously). Admitted actors best-respond and bond
  this epoch.
- **Yield:** after the reward servo runs, actor `a`'s realized
  `apr_a = (reward_a − flow_cost_a) / committed_bond_capital_a`, where `reward_a` is its
  `Σwork`-servo share (`reward.rs`), `flow_cost_a` is per-epoch storage + bond-carry +
  pseudonym-split cost, and the denominator is the capital actually staked into deep-shard
  bonds (undeployed capital is free to pursue the alternative, so it is *not* charged).
- **Exit (hysteretic):** `a` accrues a strike if `apr_a < ρ_a` **or** it deployed no bond
  (came to stake, couldn't — idle capital leaves). After `patience` consecutive strikes it
  exits and drops its holdings. Hysteresis damps thrash, mirroring the shard game's async
  damping.

The dynamic is **trickle-entry + realized-yield-exit**: as the population grows the `Σwork`
servo dilutes the share price, realized `apr` falls, and exit balances entry — the
population converges to the **marginal-archiver-breaks-even** point *without expectations*.
Coverage at that emergent point is then **read, not tuned**. The participation layer is
fully gated (`endogenous=false` ⇒ fixed all-active population, every pre-L11 scenario
byte-identical: non-endogenous scenarios consume zero extra RNG and skip every entry/exit
call).

**Calibration (the pool must have slack).** The first cut used a pool barely above the
coverage floor (~90 co-located archivers for Σ slot-demand ≈ 1080 at ~16 storage/actor) and
produced a **cliff**: ρ=0 gave full coverage, *any* ρ>0 pruned the population below the
floor and deep coverage collapsed to `deep_und=1.0` — an interior-but-infeasible
equilibrium. Widening the pool to 240 (≈150 actors of headroom above the floor) turns the
cliff into a **gradient**: the servo settles at a breakeven population that, for a band of
reservations, lands *above* the floor. The interior-feasible operating point is ρ≈0.02
(bonded-archiver count ≈79, deep covered).

**Finding 1 — the operating point is an attractor.** Booting from near-empty
(`l11_fill`, `init_active_frac=0`, bootstrap-like) and from over-subscribed
(`l11_trim`, `init_active_frac=1`) converge to the **same** steady state — bondA 79.4 vs.
78.6, deep_und 0.002 vs. 0.005. Initialization-independent: the entry/exit dynamic has a
genuine attractor, not an artifact of where the population started. This is the property
that licenses calling the emergent point an *equilibrium* rather than a starting guess.

**Finding 2 — reservation is a smooth monotone participation lever with a coverage knee.**
Sweeping ρ (homogeneous) gives a clean gradient in the emergent bonded-archiver count and a
sharp coverage knee where the breakeven population crosses the floor:

| ρ | bondA (emergent) | deep_und | read |
|---|---|---|---|
| 0.00 | 143 | 0.000 | over-provisioned (no opportunity cost ⇒ everyone bonds) |
| 0.01 | 101 | 0.000 | over-provisioned |
| 0.02 | 79 | 0.002 | **interior + feasible** (the lean equilibrium, *derived*) |
| 0.03 | 65 | 0.392 | knee (breakeven dips below the coverage floor) |
| 0.05 | 50 | 1.000 | broken |
| 0.10 | 32 | 1.000 | broken |

The lean equilibrium that iteration 1–2 *asserted* now **falls out** of the reservation
mechanism at ρ≈0.02 — `R ≈ R_target` is the emergent outcome of entry-until-breakeven, not
a tuned `budget`.

**Finding 3 — budget transfers to coverage *through participation*.** Holding ρ at the
interior 0.02 and sweeping `budget` (the reward purse), coverage is bought monotonically by
**recruiting archivers**, not by a retuned population:

| budget | bondA (emergent) | deep_und | read |
|---|---|---|---|
| 50 | 43 | 1.000 | under-funded — breakeven pop below the floor |
| 100 | 79 | 0.002 | funded — clears the floor |
| 200 | 154 | 0.000 | over-funded — clears comfortably, spread PASS too |

This is the L11 headline transfer function: **`budget → APR → marginal entry → archiver
count → coverage`**, all emergent. The gate-5 lever (how big the archival purse is) maps to
deep coverage *via the participation servo*, with no asserted population in the loop.

**Finding 4 — heterogeneous reservations sort.** With ρ drawn uniform on [0, 0.05],
the emergent active set is the **low-ρ tail** of the pool (bondA 70, deep_und 0.192) —
landing between the homogeneous ρ=0.02 and ρ=0.03 points (its mean ρ=0.025), exactly the
sorting a real alternative-yield spread produces: cheap-capital archivers stay, expensive-
capital probes leave.

**Relation to prior iterations.** The **participation churn** at lean points (chrn
sub-claim fails: the marginal archiver flickers in/out at the breakeven margin) is **benign
for coverage** — `oUmx=0` at ρ=0.02, so the oldest band never opens a gap even while the
participant set churns. This is the *same shape* as the L9 finding that abandonment is
benign rotation when `oUmx=0`: churn in *who* archives is harmless as long as coverage is
backfilled. The spread sub-claim also fails at the lean point (fewer archivers ⇒ more
concentrated; gini 0.71 at ρ=0.02 vs. 0.46 at budget 200) — the classic lean-vs-robust
tradeoff, now **emergent** rather than asserted: a thinner purse buys exactly-enough but
concentrated coverage; a fatter purse buys spread.

**Residue / what this unlocks.** L11 supplies the economic layer the two far ends
(L12 bootstrap, L13 fee-era) were missing. The attractor + transfer function mean those can
now be modeled as *perturbations of an emergent equilibrium* rather than re-assertions:
bootstrap is "the pool fills from zero up the attractor" (the `l11_fill` trajectory is
literally the cold-start), and the fee-era is "the budget shrinks and the attractor thins,
exposing the oldest tail." The reservation ρ is the natural home for L13's price/feedback
term (token-price death-spiral coupling = ρ rising as the token-denominated alternative
yield rises). The honest residue: ρ and `budget` are still genesis/economic inputs whose
*real* values are post-testnet measurements — L11 derives the *shape* of the equilibrium
(attractor, monotone transfer, sorting), not the operating ρ a live market will sit at.

### L12 — bootstrapping / cold-start: the transient approach to the attractor

L11 settled the *steady-state* operating point as an attractor. L12 asks how the system
**reaches** it from genesis, where deep history is ~empty and accrues over time while the
archiver population grows into it — the cold-start the chain "can least afford" because
the youngest deep history is also the thinnest. Three mechanisms compose, all already in
the model: L11 endogenous entry from an empty start (`init_active_frac=0`), L9/L10 dynamic
aging (deep history *forms* as hot shards age past the threshold), and a new
**growing-window** primitive — the chain starts as a small genesis core of hot shards and
appends new shards as it produces blocks (`World::append_shard`), so deep history grows
*from zero* rather than being present at `t=0` (the steady-state model recycles a
full-size window in place). A **foundation floor** is added as a separately-funded deep
backstop that decays with the bonded-archiver population
(`participation::foundation_floor`). The bootstrap/floor paths are fully gated
(`bootstrap=false`, `floor_replicas=0` ⇒ every prior scenario byte-identical: the floor
computation is read-only and consumes no RNG).

**Finding 1 — the cold start reaches the L11 attractor.** From zero archivers and empty
deep history, the endogenous market converges to the *same* lean equilibrium L11 derived:
steady `bondA≈76`, deep covered (`deep_und≈0.000`, windowed `cDeepU≈0.001`). Bootstrap is
not a separate equilibrium — it is the **transient approach** to the L11 attractor, which
is exactly the prediction L11's residue made (the `l11_fill` trajectory is the cold-start;
L12 adds the *growing deep demand* on top and the convergence survives).

**Finding 2 — the bare transient deep gap is total, and it is a timing hole, not an
economic one.** Without a floor, the worst deep retrieval gap is **`bDU=1.000`** (every
deep shard under-target at some early epoch): deep history forms ~10 epochs into the run
(first cohort crosses `age≥0.5` at `epoch_aging=0.05`) but no archiver has yet entered
*and* seated a deep holding, so deep retrieval is momentarily zero. This is the
irreducible cold-start hole — the incentive is working (entry is underway) but acquisition
+ seating lags the demand that aging manufactures.

**Finding 3 — the foundation floor covers the transient cleanly, without crowding out
entry.** A genesis floor of `r_target_deep` replicas decaying to zero as the
bonded-archiver population reaches ~steady size collapses the worst gap from `1.000` to
**`0.019`** (`l12_boot_floor`), and the steady `bondA` is **unchanged** (76 with or without
the floor). The floor is **invisible to the reward servo by construction** — foundation
replicas are not counted in the staker reward `R`/`Σwork`, so they add retrieval coverage
*without* lowering the `1/R` reward that pulls archivers in. The floor backstops
availability while the market builds and withdraws as it thickens — exactly the L5/L6 floor
reframed as a *bootstrap* guarantee, now sim-confirmed to not suppress the very entry the
bootstrap needs.

**Finding 4 — the floor's decay schedule is a fine lever with a wide safe margin.** The
early transient (population near zero) is covered by *every* schedule because the floor is
near-full there regardless of decay speed; the schedule only governs a small
*late*-transient residual:

| floor decay_pop | floored worst gap `bDUf` | read |
|---|---|---|
| 40 (fast withdraw) | 0.019 | residual ~2% of deep shards at the steady-state edge |
| 80 (mid) | 0.019 | same — floor already ≈0 by the residual epoch |
| 160 (slow withdraw) | 0.000 | floor lingers, covers the edge dip too |

So even aggressive withdrawal (foundation backs off once the market is half-built) leaves
only a ~2% residual at the hand-off edge; a gentle schedule closes it entirely at the cost
of the foundation working longer. The decay schedule is the lever trading
**bootstrap-risk against foundation-burden**, and the safe band is wide.

**Finding 5 — overshoot is real but modest, and it is a growth/entry race.** The
APR-inversion the ledger warned of *does* appear: high early APR (few archivers split the
budget) pulls in a transient over-population. Peak `bonded_active` runs **83–97** vs. the
steady **76–78** — an overshoot of ~9–25%. It is worse when the chain grows *slowly*: slow
block production prolongs the few-shards/high-price phase, pulling more entrants in before
`Σwork` dilutes them out:

| shard growth/epoch | bare worst gap `bDU` | peak `bondA` | steady `bondA` | overshoot |
|---|---|---|---|---|
| 3 (slow) | 0.009 | 97 | 77.6 | +19 (~25%) — entry keeps up with trickling demand, *over*-enters on prolonged high APR |
| 6 (mid) | 1.000 | 83 | 76.0 | +7 (~9%) |
| 12 (fast) | 1.000 | 82 | 75.7 | +6 (~8%) — demand outruns bounded entry, gap total, less time at high APR |

Crucially, the shed back to steady is **gentle**: `deep_und` steady ≈0.001 and `oUmx=0`
throughout, so the overshoot-and-shed does **not** open a coverage gap — it is benign
rotation in *who* archives, the same shape as the L9 abandonment finding and the L11
participation churn. The "early churn the system can least afford" is bounded and
coverage-neutral; the foundation floor (and the still-ample committed coverage) backstops
the youngest deep band through the shed.

**Finding 6 — the bootstrap stress is the growth/entry mismatch, not the economics.** Fast
chain growth (12 shards/epoch) against bandwidth-limited entry (6/epoch) is what produces
the total bare gap; slow growth lets entry keep pace (gap `0.009`). Either way the steady
state is the same attractor and the floor covers the transient. So the cold-start design
question is *not* "will the market find the equilibrium" (it does) but "how fast does deep
demand accrue relative to how fast capital can arrive and seat" — and the foundation floor
is the instrument that makes that race safe regardless of its outcome.

**Disposition (shape derived).** The L12 ledger disposition is confirmed by the model: pin
all genesis constants for the *thick steady state* (L1/L7), accept the bootstrap transient
is suboptimal, and let the **population-decaying foundation floor** cover it. The floor is
load-bearing *most* at genesis (Finding 2/3), withdraws adaptively as the market thickens
(Finding 4, per `75-system-autonomy.mdc`: population-indexed, no manual reset), and does
not crowd out entry (Finding 3). Overshoot is bounded and coverage-neutral (Finding 5).

**Residue / what is post-testnet.** L12 fixes the *shape* (the cold start reaches the
attractor; the bare gap is a timing hole; the floor covers it without crowding out entry;
overshoot is bounded and benign). It does **not** fix the live magnitudes: the real
chain-growth rate (block production vs. the rate staking capital actually arrives), the
genesis floor size, and the safe decay schedule are post-testnet calibrations of an
already-understood curve — the same sign-known/magnitude-unknown posture as L9/L10. The
floor's genesis size and decay schedule are gate-5 foundation parameters, pinnable for the
thick-state hand-off and re-tunable as the foundation observes the real entry rate.

### L13 — fee-era end-state: the attractor under a shrinking purse

L11 derived the lean equilibrium as an attractor at a *fixed* purse; L12 showed the genesis
cold-start reaches it. L13 takes the other temporal end (`00-mission.mdc` timeframe 2, ~30 yr):
as block subsidy → 0 the archival purse comes from **fees or a bounded terminal subsidy**, so
the purse **shrinks**. The questions, all perturbations of the L11 attractor: does a shrinking
purse thin the equilibrium, and is the **oldest (irreplaceable) tail** the most exposed? Is the
**token-price death-spiral** (`coverage ↓ → trust ↓ → price ↓ → token-denominated yield ↓ →
exit ↑ → coverage ↓`) damped or undamped? Can an **adaptive reward-share servo**
(`75-system-autonomy.mdc`, the `burn.rs` template) damp it, and where does the fee market's
finite capacity turn damping into failure?

**Model (three composed mechanisms, all gated behind `fee_era`; every pre-L13 scenario
byte-identical).**
- **Shrinking subsidy.** The base purse decays geometrically toward a **bounded terminal
  subsidy** `budget_floor` each epoch (`base ← floor + (base − floor)·(1 − budget_decay)`). The
  run starts well-funded (`budget=200`, above the L11 ~budget-100 knee) so the decay sweeps the
  population *down* through the L11 budget→coverage transfer curve.
- **Price-coupling / death spiral.** The staking yield and the bond capital are both
  token-denominated, so a *static* token price cancels in the `apr` ratio; what does not cancel
  is **expected depreciation**. A deep retrieval shortfall (lost trust) raises every active
  actor's *effective* reservation by `price_coupling · signal` (`process_exits`'
  `reservation_add`), so a coverage failure makes staking look worse against the outside option
  and forces more exit — closing the loop. The `signal` is an **EMA** of the serving deep
  shortfall (λ=0.25, ~4-epoch trust horizon): trust is *sticky*, and this stickiness is
  load-bearing (below).
- **Adaptive reward-share servo.** When `adaptive_share` is on, the effective purse is raised
  above the decayed base in proportion to the shortfall, `budget_eff = base·(1 + share_gain·
  signal)`, **bounded by `budget_ceiling`** — the most fees *can* fund. This is the
  autonomy-rule mechanism: fees flow to archival automatically when coverage slips, no manual
  reset. The L12 **foundation floor** is reused unchanged as the non-market backstop.

New observables: `feB` (the realized purse, windowed mean — how far the subsidy decayed and how
much the servo topped up; `≈budget_ceiling` ⇒ fees saturated) and `fDUpk` (worst *serving* deep
gap over the run's second half — the thinned end-state; sustained-high ⇒ death-spiral /
unsustainable). The L11/L12 `bondA`, `cDeepU`, `oUmx`, and `bDUf` carry the rest.

**Findings.**

1. **A shrinking subsidy thins the attractor monotonically** — the L11 transfer curve run in
   reverse. Terminal subsidy `100 / 80 / 60 / 40 / 20 → bondA 81 / 67 / 54 / 39 / 21`, with a
   **coverage knee at ~80–100**: at floor 100 deep is fully covered (`cDeepU 0`), at floor 60 it
   has collapsed (`cDeepU 0.99`). The minimum viable terminal subsidy is a model output, not an
   assertion: ~budget-80 sustains the ~67-archiver set that covers deep.
2. **The oldest tail goes under first.** At the knee (floor 80) the oldest band oscillates under
   (`oUmx 0.163`, `sOUmx 0.163`) while mid-deep still holds (`cDeepU 0.057`) — the irreplaceable
   band (most data, least fresh fee activity to pay for it) is the most exposed exactly as the
   far-end-B analysis predicted. Below the knee the collapse is total across deep (the L11
   interior-feasibility cliff), so the oldest-first gradient is visible *at* the knee, which is
   the operating margin that matters.
3. **The price-coupling death spiral is real.** With coupling on at an unsustainable floor (40)
   and no servo, `bondA` falls to **17** vs **39** at the same floor without coupling — the
   depreciation premium amplifies the thinning into a deeper collapse. Undamped, this is the
   priority-1 durability failure the ledger flagged.
4. **The adaptive servo damps it — conditionally.** Same coupling + the servo with an adequate
   ceiling recovers `bondA` **17 → 62** and cuts the deep shortfall **`cDeepU` 1.0 → 0.21**, by
   drawing the purse up to **~116** (`feB`). So the loop is **dampable — not an automatic
   priority-1 failure**. Two conditions are load-bearing:
   - **Sticky trust signal.** The servo (and the coupling) must key off the *smoothed* shortfall.
     A servo reacting to the *instantaneous* shortfall relaxes the moment coverage is briefly met;
     with rate-limited entry and hysteretic exit the population then bleeds back down and the
     system oscillates, underperforming a *constant* purse of the same average size. The EMA holds
     the response across the few epochs entry needs to rebuild. (This is itself a finding: a naive
     reactive servo is destabilizing; the autonomy mechanism must integrate/smooth.)
   - **Adequate fee-market ceiling.** The servo can only draw what fees provide. Sweeping the
     ceiling: at **70 and 110** the servo **saturates at the ceiling** (`feB = 70.0 / 110.0`
     exactly) and coverage stays gone (`cDeepU 1.0`) — a **graceful loud failure** (the metric
     pins at the ceiling and the gap stays open: detectable, not silent); at **200** the servo
     draws only the ~116 it needs and damps. The binding ceiling under this coupling is ~115
     (above the no-coupling sustainable ~100, because the premium shifts the knee up).
5. **The foundation floor re-engages automatically as the market thins.** The L12 floor is
   `floor0·max(0, 1 − pop/decay_pop)` — in bootstrap `pop` rises and the floor withdraws; in the
   fee-era `pop` thins and the **floor re-engages with no new mechanism**. At the unsustainable
   floor (40) with the foundation floor on and no servo, the bare deep gap is total (`bDU 1.0`)
   but the **floored** gap is `bDUf 0.425` — the foundation backstops ~57% of the deep tail's
   retrieval as the paid market collapses, and (as in L12) it is invisible to the reward servo so
   it does not crowd out what market remains. The one non-market capacity source is load-bearing
   at **both** temporal ends, confirming the iteration-3 unifying note (capacity creates
   coverage; bootstrap is "capacity not yet present," fee-era is "capacity no longer paid for").

**Disposition (shape derived).** The fee-era death spiral is **not** an undamped priority-1
failure *provided* the system ships the damping apparatus: (a) an adaptive reward-share servo
keyed to a **smoothed** trust/coverage signal (a reactive servo oscillates and is worse than
nothing), (b) a fee-market / terminal-subsidy ceiling **above** the coupling-shifted sustainable
purse (below it the failure is graceful and loud but is still a failure), and (c) the foundation
floor as the non-market backstop that re-engages automatically when the market thins. With the
apparatus the loop is bounded; without any of it the coupling runs. This is a concrete gate-5
economics requirement, not a tuning preference.

**Residue / what is post-testnet.** L13 fixes the *shape* (thinning is monotone along the known
transfer curve; oldest-first exposure; the spiral is real and dampable; the servo must be
smoothed; the ceiling sets a graceful-failure threshold; the floor re-engages). It does **not**
fix the live magnitudes: the real fee-market ceiling (how much fee revenue a mature Shekyl
actually directs to archival), the coupling strength (how sharply trust/price tracks coverage),
the bounded terminal-subsidy level, and the trust horizon (the EMA λ) are post-testnet /
economic-layer empirics of an already-understood control loop — the same sign-known /
magnitude-unknown posture as L9/L10/L12. The adaptive-share servo's gain and ceiling are gate-5
parameters; the terminal subsidy floor is a `00-mission.mdc`-timeframe-2 consensus constant
whose *minimum* is now bounded below by the ~budget-80 knee (in model units).

### Transport coupling — the `L2–L6` band is the operating regime, not a stress corner

A forward note connecting the latency axis to the (deferred) transport choice; the full
analysis lives in [`../ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Transport for the
staker-archival path*. No transport work is scheduled — this records why the sim's latency
sweeps are already pointed at the right regime.

The firewalled-pseudonym requirement forces the **heavy archival fetch path onto an
onion-service-to-Tor-client rendezvous** (the pseudonym `P`'s location must not link to the
principal, so the serving path cannot fall back to clearnet the way Monero's public chain
sync does). Rendezvous is the slowest configuration Tor has. The consequence for this sim:

- **`fetch_latency_per_unit` is not a free stress parameter — it is the onion-rendezvous
  latency by construction.** The `L2–L6` band the L10 sweeps treated as "survivable-to-
  extreme" is the *operating* band, and the post-testnet "real fetch latency" unknown
  (flagged in §*L10*) is just *where on that band* the live transport sits, measured against
  Monero's documented heavy-over-Tor bandwidth cost.
- **The model has already designed around it:** age-scaled duration is win-or-harmless
  across `L2–L6` (L10 H1/H4), and the foundation floor backstops the `L6` ceiling where
  backfill cannot keep pace regardless of incentive. So the worst-case transport is a
  *known, bounded, already-modeled* constraint, not a discovery waiting to happen.
- **The one transport parameter that feeds this sim** is whether the heavy path stays
  pure-rendezvous (worst-case L-regime, maximal firewall) or admits a bandwidth-buying
  relaxation that does *not* link `P`. That choice is the lever that moves where Shekyl lands
  on the `L2–L6` curve; everything else in transport selection is downstream of it and does
  not change the sim. See ledger item L16.

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
| L9 | **Age-scaled bond *duration*** (gate 4, second axis) | The commitment-horizon job the tier system did belongs in the bond's **duration**, not magnitude — but *age-scaling* it is a second oldest-ward redistribution lever, and the lean test downgrades **both** halves of the surplus reading as regime artifacts. **Necessity (benefit): inferred, unmodeled.** `oChrn` is the *abandonment rate*, not the coverage-oscillation metric the churn sub-claim names; at the lean operating point flat duration shows `oUmx 0` (no oscillation — the surplus `oChrn 0.251` was benign rotation the buffer backfilled). The model is capacity- not timing-bound (same-epoch backfill), so the benefit a backfill-lag model might show is not yet representable. **Cost: demonstrated at the operating regime.** The one oscillating regime is a *capacity bind* where age-scaling makes `deep_und` *worse*; the `bind_*` sweep banks this as a robust **lock-in reallocation cost** — age-scaling lifts the oldest band by starving mid-deep (redistribution signature: oldest `frac_under` ↓, mid-deep ↑), coverage-negative at every bind (`a08` 0.025→0.176 [7×], `a10` 0.351→0.377, `stor` 0.57→0.623), saturating at the first increment (`s2`=`s4`). It is the **#3 finding compounded**: `g` already reallocates oldest-ward; age-scaled duration double-counts it, so stacked they over-concentrate the very oldest at a bind. | **DEFER age-scaling — default to FLAT duration (cost demonstrated, benefit unmodeled).** Final genesis bond shape: **flat magnitude + flat (non-zero) duration** — `g` carries deep-prioritization with a *single* oldest-ward lever; flat duration carries the commitment horizon with no reallocation cost. *Demonstrated cost against unmodeled benefit is not insurance — it is an unpriceable bet*, so age-scaling is not adopted now. **Genesis-pin ordering reinforces:** the constant is consensus-visible (pinned pre-genesis), but age-scaling can only be validated by a backfill-lag model needing **post-testnet fetch latencies** — you cannot validate before you must pin, and flat-constant has nothing to walk back. A duration *servo* (genesis range, post-testnet tunable) would preserve the option but adds a governance/manipulation surface not worth it on current evidence. **Reversion (sharpened):** reopen iff a backfill-lag churn model shows the timing-stability benefit **net of** the lean-margin reallocation cost is positive (the damping must beat the demonstrated mid-deep aggregate cost) — a fork-worthy upgrade if earned. The L4 reversion trigger (oldest-band coverage oscillation) is **not discharged** and stays open under this clause. Banked surplus facts (anticipation sign-flip, outcome 3 ruled out) remain valid as surplus facts but don't reach the operating point. **UPDATE (L10): this disposition is REOPENED.** The backfill-lag model both (a) models the benefit (net-positive — serving `oUmx` damped, serving `deep_und` improved across regimes incl. binds) and (b) shows the "demonstrated cost" was a **final-epoch artifact** (windowed mean: `a10` 0.178→0.178 identical). The sharpened reversion criterion is **met**; the remaining call is the genesis-pin *shape* (magnitude is post-testnet), surfaced to the maintainer per L10. |
| L10 | **Backfill-lag / timing-bound dynamics** (gate 4; the L9 hinge) | Deep-shard **fetch latency** added (committed-but-not-serving for `round(deep_shard_size · fetch_latency_per_unit)` epochs; drops instant), **decoupled** from the game (game on committed replication = iteration-2-stable; retrieval coverage on seated replication). The timing-bound channel the capacity-bound model could not show now appears: serving `oUmx` rises 0→0.46→0.71→1.0 with latency `L0..L4`. Age-scaled duration **damps it net-positive** — lower oldest churn (0.171→0.090), lower serving `oUmx` *and* lower serving `deep_und` at every latency (`L1` 0.263→0.222; `L2` 0.580→0.465), and lower serving `deep_und` even at capacity binds (`lagbind` churn 0.942→0.865, stor 0.988→0.974). **It also forced the `bind_*` cost re-read:** that cost was a **final-epoch artifact** — on the windowed mean it is within noise (`a10` 0.178→0.178 identical, `a12`/`stor` slightly positive, `a08` +0.013 not 7×). | **RESOLVED — reversion criterion MET; L9 disposition reopened.** The sharpened L9 clause (benefit net of the lean-margin reallocation cost positive) is satisfied: benefit demonstrated net-positive across all regimes incl. binds, and the cost it was netted against dissolves on the proper windowed read. **Residue (honest):** L10 establishes the benefit's **sign** (positive), not its **magnitude** at the real operating point — `fetch_latency_per_unit` is the post-testnet measurement. So the open decision is no longer "cost vs. no-benefit" but the **genesis-pin shape** (flat-constant / age-scaled-constant / duration-servo) under sign-known/magnitude-unknown — a priority-3 + `75-system-autonomy` human call, surfaced to the maintainer, **not** flipped unilaterally. **HARDENED (§*L10 hardening*):** denser latency grid `L1–L6` shows the benefit is robust across the survivable band and honestly **washes out at `L6`** (both arms saturate; nothing helps when backfill can't keep pace); the `dur_age_scale` sweep shows the benefit **saturates** (scale 4 ≡ 8 — a genesis *constant* is calibration-insensitive, which removes the servo's affirmative case); the widened bind grid (`a06–a14`) keeps the committed cost **dissolved** (Δ within ±0.015, mixed sign, on the now-banked `cDeepU` windowed-mean column); the **bandwidth-bound** regime (`acq_rate=1`) is the clearest win (improves even committed coverage 0.106→0.069). Net: the call **leans age-scaled-constant at a safe-side scale**, still a human disposition. Correlated *actor* exit is scoped to L15 (duration is a shard-drop deterrent, not an uptime guarantee). |
| L11 | **Endogenous participation / lean equilibrium derivation** (gate 5 / economics) | The lean operating point was *asserted* (fixed pop + tuned `budget`). L11 makes entry/exit a function of realized `apr = (reward − flow_cost)/committed_bond` vs. per-actor reservation ρ (trickle-entry + hysteretic realized-yield-exit; pool of potential archivers; fully gated, legacy byte-identical). The lean equilibrium now **emerges**: (1) it is an **attractor** — fill-from-empty (`l11_fill`, bondA 79.4) and trim-from-full (`l11_trim`, 78.6) converge to the same point, deep covered; (2) reservation is a **smooth monotone lever** with a coverage knee (ρ 0.01/0.02/0.03 → bondA 101/79/65, deep_und 0/0.002/0.392 — the interior-feasible lean point is ρ≈0.02); (3) **budget transfers to coverage *through participation*** (budget 50/100/200 → bondA 43/79/154, deep_und 1.0/0.002/0 — emergent, no asserted pop); (4) **heterogeneous ρ sorts** (the low-ρ tail self-selects). Calibration note: the pool must exceed the coverage floor with slack or the equilibrium is interior-but-infeasible (a cliff); pool 240 vs. floor ~90 gives the gradient. | **RESOLVED (shape derived) — iteration 3.** The lean equilibrium is no longer asserted: it is the attractor of entry-until-breakeven, and `budget → APR → marginal entry → archiver count → coverage` is the emergent transfer function. Participation churn at the lean margin is **benign for coverage** (`oUmx=0` — same shape as L9 benign rotation); the spread/lean tradeoff is now emergent (thin purse ⇒ exact-but-concentrated, fat purse ⇒ spread). **Residue:** ρ and `budget` real values are post-testnet/market — L11 fixes the equilibrium's *shape* (attractor, monotone transfer, sorting), not the live operating ρ. **Unlocks L12/L13** as perturbations of this attractor (bootstrap = `l11_fill` cold-start trajectory; fee-era = budget-shrink thinning; ρ is the natural home for L13's price-feedback term). |
| L12 | **Bootstrapping / cold-start** (gate 5; genesis transient) | Growing frontier window (genesis hot core + per-epoch block growth via `World::append_shard`, deep history accrues *from zero*) + L11 endogenous entry from empty + a population-decaying foundation floor (`participation::foundation_floor`, invisible to the reward servo); fully gated, legacy byte-identical. Findings: (1) the cold start **reaches the L11 attractor** (steady `bondA≈76`, deep covered) — bootstrap is the *transient approach*, not a separate equilibrium; (2) the bare transient deep gap is **total** (`bDU=1.0`) — a *timing* hole (deep forms ~10 epochs before archivers seat it), not an economic one; (3) a `r_target_deep` floor decaying to ~steady pop collapses it to `bDUf=0.019` with **steady `bondA` unchanged** (no crowd-out — floor not in `R`/`Σwork`); (4) decay schedule is a fine lever (`decay_pop` 40/80/160 → floored gap 0.019/0.019/0.000 — wide safe band); (5) **overshoot is real but modest and is a growth/entry race** (peak `bondA` 83–97 vs steady 76–78; worse on *slow* growth — prolonged high-APR phase), and the shed is **coverage-neutral** (`oUmx=0`, `deep_und` steady ≈0.001 — benign rotation, L9/L11 shape); (6) the stress is the growth/entry mismatch (fast growth 12/epoch > entry 6 ⇒ total gap; slow 3 ⇒ gap 0.009), not the economics. | **RESOLVED (shape derived) — iteration 3.** Disposition confirmed: pin genesis constants for the **thick steady state** (L1/L7); the **population-decaying foundation floor** covers the transient (load-bearing *most* at genesis, withdraws adaptively per `75-system-autonomy.mdc`, does not crowd out entry). Overshoot bounded + coverage-neutral. **Reframes L5/L6:** the floor's bootstrap role is now the primary one; gate-5 sizes the genesis floor + decay schedule. **Residue:** real chain-growth rate, genesis floor size, and safe decay schedule are post-testnet calibrations of an already-understood curve (sign-known/magnitude-unknown, as L9/L10). **Unlocks L13** (fee-era = the budget-shrink mirror of this budget-transfer; the floor's decay reverses into a re-engagement as the market thins). |
| L13 | **Fee-era end-state / sustainability** (mission timeframe 2; ~30 yr) | As subsidy → 0 the archival budget must come from fees/terminal subsidy; a shrinking budget thins the lean equilibrium and the oldest (irreplaceable) tail is most exposed. Deep history grows unboundedly while the paid population may not; token-price ↓ → reward ↓ → exit ↓ → coverage ↓ is a candidate death spiral. | **RESOLVED (shape derived) — iteration 3.** Modeled the shrinking purse + price-coupling + adaptive reward-share servo + foundation-floor backstop (gated, legacy byte-identical). Findings: decay thins the attractor along the L11 transfer curve in reverse (coverage knee at terminal subsidy ~80–100); the **oldest tail goes under first** (`oUmx 0.163` at the knee vs `cDeepU 0.057`); the price-coupling spiral is **real** (`bondA` 39→17) but **dampable** by the burn.rs-style servo (`bondA` 17→62, shortfall 1.0→0.21) **conditional** on (a) a *smoothed* trust signal (a reactive servo oscillates) and (b) an adequate fee-market ceiling (below it the servo saturates → graceful loud failure); the L12 floor **re-engages automatically** as the market thins (`bDUf 0.425` vs bare `1.0`). The loop is **not** an undamped priority-1 failure provided the damping apparatus ships; without it, it runs. Residue: live ceiling, coupling strength, terminal-subsidy level, trust horizon are post-testnet empirics. See §*L13 — fee-era end-state*. |
| L14 | **Proof-of-archival / free-rider gate** (gate 4 / consensus) | Reward is for *provable* work but the model rewards declared holdings; the free-rider (claim without storing, or store-but-refuse-to-serve) is gated by the unmodeled challenge/audit cadence, not the bond. | **Open — gate 7 / consensus design.** The bond is the capital cost; the challenge frequency + fake-cost + penalty are the operational Sybil/free-rider economics. Model challenge cadence vs. faking cost; couple to retrieval (L15). |
| L15 | **Retrieval / correlated-failure realism** (gate 4–5) | Coverage (replicas exist) ≠ retrieval (fetch within latency at target availability); the L4 survival arithmetic assumes *independent* holder failure. | **Open — iteration 3+.** Add per-holder uptime + read-path latency to derive `R_target` from a retrieval-availability target (rather than stipulating it); add a privacy-compatible **diversity axis** (jurisdiction/ASN/implementation) to the spread metric so correlated loss is visible (mission priority 2 tension: diversity measurement must not leak). |
| L16 | **Transport selection / latency-regime coupling** (gate 6 / networking; the L10 latency axis seen from the transport side) | The firewalled-pseudonym requirement forces the **heavy archival fetch onto onion-service↔Tor-client rendezvous** (slowest Tor config; `P`'s location must not link to the principal, so no clearnet fallback). This makes the L10 `L2–L6` sweep the **operating regime by construction**, and `fetch_latency_per_unit` the onion-rendezvous latency — the post-testnet "real fetch latency" unknown is just *where on the band* the live transport sits. TCP-sync and Tor reinforce (Tor is TCP-only; the inherited Levin/TCP stack drops in); the commitment is coupled (UDP/QUIC sync would reopen it). Tor is primary on maturity + TCP + persistent-reachable-service + longevity; I2P is a defensible secondary; Lokinet (Oxen-tied, UDP) and Nym (mixnet, latency-disqualifying for heavy fetch) are out. The **Arti in-process onion-service** option (Rust-canonical) is claimed viable on the 2.x LTS line — *to verify per `17-dependency-discipline.mdc`*. Full analysis: [`../ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Transport for the staker-archival path*. | **Open — forward consideration, NOT scheduled.** Captured so the eventual transport PR starts from a stated position. The model is **already designed around the worst case** (duration win-or-harmless `L2–L6` per L10 H1/H4; foundation floor backstops the `L6` ceiling), so transport latency is a *bounded, modeled* constraint, not a discovery. **The one transport input that feeds the sim:** whether the heavy path stays pure-rendezvous (worst-case L-regime) or admits a bandwidth-buying relaxation that does **not** link `P` — the lever that sets where Shekyl lands on the `L2–L6` curve. Forks deferred to the transport PR: (1) embed Arti vs. external Tor daemon; (2) keep the I2P secondary door open architecturally (reversion-clause shape); (3) a dedicated privacy threat pass on the rendezvous-forced heavy path (Monero does not lean on that config — no inheritance-by-assumption). |

### Robustness-sweep verdicts (which findings are structural)

- **Structural (survive the provisioning/endowment sweeps):** deep starves without a
  premium (direction); `g(age)` reallocates rather than manufactures coverage; total
  coverage is supply-bound; the empty-window is the **co-located min-form**
  `Σ min(⌊capital/bond⌋, ⌊storage/shard_size⌋) ≥ Σ_deep R_target` (L8) — which unifies the
  capital and storage axes into one binding number and catches the co-location starvation
  the aggregate ratio misses (and which the (bond × shard-size) pair sweep confirms is a
  *joint* lever); actor-level spread contains the whale the pseudonym metric hides; the
  age-tilted bond is a weak, mildly regressive lever that fights the `g(age)` premium
  (L4 → flat-on-deep default); and the **redistribution unification (#3):** the magnitude
  age-tilt and the `g(age)` premium only *redistribute* coverage oldest-ward — they never
  manufacture it; only **capacity (L8)** does. *Age-scaled bond **duration**, by contrast, is no
  longer in this "redistribution-only" set:* the iteration-2 reading that called it coverage-negative
  at every capacity bind was a **final-epoch-snapshot artifact** that L10 retracted (windowed-mean
  `cDeepU` across the `a06–a14`+`stor` grid: Δ within ±0.015, mixed sign — no robust cost), and the
  L10 backfill-lag model showed duration carries a real **timing-stability benefit** (damps serving
  `oUmx`, improves serving `deep_und` across `L1–L4`, and improves even *committed* coverage in the
  bandwidth-bound regime). So duration is not a second redistribution lever stacked on `g`; it
  addresses a distinct (timing) failure mode `g` does not touch. Net: **L9 is reopened (leaning
  age-scaled-constant)**; the residue is the genesis-pin *shape* under a known-positive sign with a
  post-testnet magnitude, not a demonstrated cost.
- **Margin-artifacts (regime-specific, do not generalize):** the `deep_und=1.000`
  *magnitude* (a thin-supply corner that dissolves with provisioning); the specific
  residual-minimizing `g` value (baseline-supply-dependent); the exact `frac_under`
  borderline failures (`0.062` at strict `<0.05`).
