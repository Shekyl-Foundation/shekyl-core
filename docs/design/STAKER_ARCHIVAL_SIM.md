# Staker-archival simulation — design spec

**Status: iteration 3 (L10 + hardening, L11, L12, L13) BUILT and RUN — backfill-lag model
reopens L9 and hardening leans the pin toward age-scaled-constant; L11 derives the lean
equilibrium as an emergent attractor; L12 shows the genesis cold-start reaches that attractor
and the population-decaying foundation floor covers the transient; L13 shows the fee-era
shrinking subsidy thins the attractor (oldest tail first), the price-coupling death spiral is
*dampable* by an adaptive reward-share servo conditional on an adequate fee-market ceiling, and
the foundation floor re-engages as the market thins; the P1/P2 hardening confirms the L11 lever
survives co-location (graded, not a cliff, but with a narrower feasible band) and that the L13
spiral has a second, level-driven leg (a falling token price collapses coverage via fiat flow
cost with no trust-loss trigger); L15 shows **coverage ≠ retrieval** — a fully-covered deep set
fails its retrieval SLA when holders cluster into too few failure domains, so **diversity, not
replica count, is the binding retrieval constraint** and `R_target` is derivable from the SLA
`(u, A*)` rather than stipulated; L14 shows **read-credited proof-of-archival confines
oversight to the cold tail** — crediting real reads cuts challenge traffic ~65% with ~98% of
the residual on deep shards, the slash (not the cadence) is the primary deterrent, and demand
self-polices popular history; P3 **band-resolves the irreplaceable tail** — the fee-era floored
residual concentrates in the oldest band (`boOld 0.612 > bDUf 0.425`) while the *bootstrap*
residual does **not** (it lands on the freshly-deepened, most-re-derivable band, `boOld≈0`), and
a mean-preserving **age-stratified floor** cuts the oldest-band gap ~80% (`0.612→0.125`) at equal
total foundation cost — so age-stratification is a **fee-era lever**, not a bootstrap one; L16
couples the L10 onion-rendezvous latency band to L15 by depressing effective per-holder uptime
`u` (`u_eff = u_base/(1+k·L)`), so a **fully-covered** deep set (`deep_und=0`, `R≈6`) fails its
retrieval SLA from transport alone at `L≥1` (`rUDp` 0→1.0 across `L0..L6`) while derived
`R_target` climbs 3→7 — duration backstop and replica floor do not repair depressed `u`
(2026-06-06); **T-A1/T-A2 F1 instrument built; v2 metrics re-pointed (2026-06-07) — F1
final accept still blocked on cohort channel, not timeline rotation.**
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
On that basis the call **leans age-scaled-constant at a safe-side scale**.
**DECIDED (maintainer, 2026-06-11): age-scaled-constant**, pinned provisionally at the
sim-exercised plateau arm (`BOND_DURATION_BASE_EPOCHS = 4`, `BOND_DURATION_AGE_SCALE = 4`;
[`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1). See §*L10 — the
backfill-lag model* and §*L10 hardening* for the evidence and the reversion clause.

**Iteration-3 headline (L11).** Endogenous participation removes the last *asserted* input:
the lean operating point was previously a fixed population with a tuned `budget`. L11 makes
entry/exit a function of realized risk-adjusted yield (`apr = (reward − flow_cost) /
committed_bond`) vs. a per-actor reservation ρ, over a pool of *potential* archivers
(trickle-entry + hysteretic realized-yield-exit; fully gated, every pre-L11 scenario
byte-identical). The lean equilibrium then **emerges with three model-backed properties**:
(1) it is an **attractor** — cold-start-from-empty and trim-from-oversubscribed converge to
the same ~79-archiver, deep-covered point (post-Curve-repair substrate: ~113 — the
attractor property is unchanged, the count moved; §*Layer-2 results* Finding 0); (2) reservation is a **smooth monotone lever**
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
already-understood curve. **Genesis-seal carry (tail-margin finding,
`ARCHIVAL_SIM_ECONOMICS_VERDICT.md`):** the `r_target_deep` genesis floor is
sealed at genesis, so its post-testnet calibration must be re-derived against the
**integer** backend with a **+1 deep-tail replica margin** — the float sim
over-reads worst-shard redundancy by up to one replica, and a sealed floor cannot
be corrected post-genesis without a fork (tracked: `docs/FOLLOWUPS.md` V3.0
pre-genesis queue). See §*L12 — bootstrapping / cold-start*.

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

**Iteration-3 hardening (P1, P2) — the two places a derived result still rested on a modeling
choice.** Both probe banked iteration-3 results; both are now anchored (gated, legacy
byte-identical). **P1 (L8×L11 entanglement):** the L11 "smooth lever" was shown on an
*all-seatable* pool (baseline archetypes each seat ~10 deep shards, total seating ~2400 ≫ the
~720 deep floor), so co-location never bound. Re-running the ρ gradient against a
**co-location-binding** endowment (polarized archetypes seating ~3–4 deep each, seating ~840,
`dS/dN` 1.31 vs loose 3.76) shows the gradient **survives but compresses**: deep coverage falls
*graded*, not as a 0→1 cliff (deep_und 0/0/0.067/0.192/1.0 across ρ 0.005/0.01/0.015/0.02/0.03),
the **feasible ρ band narrows** (clean coverage only ρ≤0.01 vs ≤0.02 loose) and the **headroom
thins** (feasibility needs ~88% of the pool active, `bondA` 210/240, vs ~42% loose). The
knife-edge the probe feared does **not** appear — but the equilibrium is **more fragile**
(self-correcting within a *tighter* ρ window), and the **oldest band fails first** (`sOUmx 0.408`
at ρ=0.015 while aggregate deep_und is only 0.067 — P3 corroborated). Budget still buys coverage
but is **capped by the co-location ceiling** (`b200`≡`b400`: once the whole seatable pool is in,
more purse manufactures nothing — only capacity does, per L8). So the lever is real; its
*robustness margin* is co-location-dependent and must be sized against the co-located seating, not
the raw pool. **P2 (flow-cost denomination):** `flow_cost` is **token-denominated** in the model
(every term in the APR shares the `budget` unit), so the price-cancellation that made "only
expected depreciation bites" was a modeling artifact, not an economic fact. Adding a
**fiat-denominated** flow cost (`apr = R/B − F/(B·p)`) confirms the death spiral has a **second,
level-driven leg**: a price falling to 0.25 *with `price_coupling = 0` (no trust-loss trigger)*
collapses deep coverage outright (`deep_und 1.0`, `bondA` 81→28) — the level channel ignites the
loop with no expectation feedback at all. And it is the **more dangerous leg**: the
token-denominated servo damps it only *partially* even at a ceiling of 400 (2× the original
purse: `deep_und 1.0→0.607`, `bondA 28→56`), because it must over-pay the entire fiat drag in
tokens. So the L13 disposition is **sharpened, not overturned**: the spiral is dampable, but the
damping condition against the level leg is much stronger than against the expectation leg — which
**reinforces P4** (a token-denominated backstop is a weak lever against a low-price, fiat-cost
collapse; the terminal subsidy must carry real margin). See the L11/L13 ledger rows.

**Iteration-3 hardening (P3) — age-stratify the irreplaceable tail (gated, legacy
byte-identical).** P3 asked whether the "deep" band is the right granularity for the
*irreplaceable* tail, since the oldest shards fail first at both temporal ends. Two parts. **(a)
Band-resolve the residual.** A new oldest-band-resolved floored gap (`boOld`, the peak floored
deep gap restricted to age ≥ 0.8) separates the irreplaceable tail from aggregate deep. The
fee-era floored residual **is** oldest-concentrated (`l13_floor`: `boOld 0.612 > bDUf 0.425`) —
confirming L13#2's oscillation is the *least-replaceable* band thinning under the re-engaging
floor. But the **bootstrap** residual is **not**: at genesis the oldest shards are the genesis
core (covered earliest and longest), so the L12 hand-off slice (`bDUf 0.019`) lands on the
**freshly-deepened** band (`boOld≈0`) — the *most* re-derivable history, not the least. This
**refutes** the probe's worry that the 0.019 might be slow permanent loss of the irreplaceable
tail; the irreplaceable-tail exposure is a **fee-era**, not a bootstrap, phenomenon. **(b) The
age-stratified floor.** `foundation_floor_aged` applies a **mean-preserving** oldest-ward tilt to
the floor (factor `1 + tilt·(2x−1)` over the deep range, `x=0` at the deep threshold, `x=1` at
the oldest) — the same age-tilt shape `R_target(age)` already uses, at **equal total foundation
cost**. Swept on the realistic re-engagement floor (`floor_replicas = 6`), the tilt collapses the
oldest-band gap from `0.612` (tilt 0) to `0.391` (tilt 0.6) to **`0.125`** (tilt 0.9, an ~80%
cut), at the cost of the aggregate gap rising modestly (`0.425→0.467`) as the freshly-deepened,
re-derivable band under-floors. That trade — **protect the irreplaceable, let the re-derivable
ride the market** — is the P3 disposition. The bootstrap sweep leaves `boOld` at `≈0` across all
tilts, confirming the lever belongs at the fee-era end. Residue: the live tilt magnitude is a
post-testnet calibration; the *shape* (age-stratified floor + terminal subsidy, mirroring
`R_target(age)`) is the genesis decision, and it composes with **P4** (the trustless terminal
subsidy carries the same age-tilt). See the L13/P3 ledger row.

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
instrument: retention-proof unforgeability (gate 2 / the loud 8c), the archival read
contract (gate 3 dissolved — derived `R_market`, no `ν`; see
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)), and the `P`
backing/firewall crypto (gate 6) are out of scope here and are settled by a soundness
pass, not by simulation.

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
| **Churn-stable** | coverage oscillation: `max(oUmx, serving_oUmx)` over the steady-state window (`churn_window`) | shards repeatedly drop below `R_target(age)` in the oldest band (participation abandonment `churn` is reported but **not** the pass metric — see F2 bank below) |

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
  - `work_P = Σ_shards scarcity(shard) · serve_credit_bit(P, shard)`, where
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

- **Iteration 2 — fine bond-rate window (gate 4).** **Built and run (2026-06-07).**
  Fine sweep `gate4_fine_*` at the L11 lean equilibrium; sim pin `bond_rate* = 0.75`.
  See §*Gate 4 iteration-2 — fine bond-rate window*.
- **Iteration 3 — Σwork servo supply-safety (gate 1).** Grow the population under
  the servo; confirm `Σreward ≤ budget` and characterize per-staker reward
  compression as population grows. (This and gate 7 may run in the macro
  `shekyl-economics-sim` rather than the agent sim — build decision below.)
- **Iteration 4 — bootstrap handoff (gate 5).** Foundation floor overlapping a
  growing staker population, shedding as coverage is *demonstrated*; confirm no
  zero-coverage instant; confirm the flat per-bonded-shard subsidy is coverage-
  sufficient and privacy-clean.
- **Iteration 5 — locked-supply re-pricing (gate 7, the foundational macro gate).**
  **Couples to transfer-shaped admission (§2.4 close-condition iii):** if admission
  principal goes soft or away, **bond-locked supply is the sole sink** — re-price
  `stake_ratio` / circulating-supply assumptions in macro sim at the **same severity**
  as per-reward proof aggregate (close-condition ii). Does locked supply collapse
  toward `bond_rate × shards × population` once principal lock no longer contributes?
  Macro; couples to `shekyl-economics-sim`. **Scoped 2026-06-11 — see
  §*Iteration-5 scope* below.**

### Iteration-5 scope — gate-7 locked-supply re-pricing (scoped 2026-06-11; built and run same day — results in §*Gate 7 iteration-5 — results*)

**Decision it informs (the only output that matters):** §2.4 close-condition (iii) — is
admission principal **load-bearing for locked supply** (pin `ADMISSION_MIN_ATOMIC` as a
consensus constant, emission verify keeps the `admission_proof` branch per emission §7.2/§7.4)
or is the bond the sufficient sole sink (**bonds-only**: delete the branch and the constant's
consensus role; `MIN` survives only as gate-6 funding-hygiene policy)? Per emission §10.2 the
verification path *branches* on this — the decision is structural, not a tuning knob.

**Instrument:** macro `shekyl-economics-sim` (per the build decision below: iterations 3/5 run
macro, not agent-based). The build work is one structural change plus scenarios:

1. **Replace the asserted `stake_ratio` input** (`SimParams.stake.get_stake_ratio`, an
   exogenous closure) **with a derived archival-lock model**:
   `locked(t) = bonded(t) [+ admission(t)]` where
   `bonded(t) = bond_floor × Σ_P |holdings_P(t)|` — driven by deterministic shard-count
   growth (chain history per block; the L12 frontier-growth shape) times an `N_P` population
   path taken from the **L11 lean-equilibrium attractor** outputs (`bondA` trajectories:
   fill, trim, and fee-era-thinned arms), **not** a free parameter.
2. **Two admission arms** per scenario: **(A) bonds-only** — admission contributes 0 at
   steady state (ordinary transfer spendable post-first-emission, emission §159);
   **(B) hard lock** — `+ MIN × N_P(t)` with `MIN` swept over a small grid (order-of
   magnitude around `ARCHIVAL_BOND_FLOOR`).
3. **Scenario grid:** the existing emission-schedule scenarios × {A, B×MIN-grid} ×
   `N_P` envelope {lean ≈ bondA 79, thick ≈ 154, fee-era-thin ≈ 17–62 (L13 servo band)}.

**Pinned build constraint — circulating-supply definition (2026-06-11).** The sim's
modeling loop (`engine.rs`) computes `circulating = already_generated − total_burned`;
the **consensus burn-site quantity** is prev-block `already_generated` alone (the input
`validate_miner_transaction` actually feeds `calc_burn_pct`; see
`shekyl-economics-sim::record` §5.3-R1 note and `STAGE_1_PR_7_ECONOMICS_ENGINE.md`
§5.3/§608–612 — the C4 recorder already records the consensus quantity for exactly this
reason). The gate-7 wiring must follow the recorder, not the modeling loop: the derived
`stake_ratio` fed to `calc_burn_pct` denominates against **consensus circulating**
(`ag_start`), while emitted-minus-burned remains a reporting-only gauge. Otherwise the
re-priced burn trajectory diverges from what consensus will compute and the close
criteria read a sim artifact instead of the chain's arithmetic.

**Inputs — all already pinned (which is why this is buildable now):** `bond_rate* = 0.75`
(iteration-2 fine sweep); `ARCHIVAL_BOND_FLOOR` (gate-4 §8.1); `W = 26`, `SEB = 10_000`
(timing cluster — claim cadence bounds in-flight unclaimed value, a second-order term the
model may carry or note as noise); shard growth = block growth (deterministic). The A4
duration pin is **not** an input: duration moves churn, not the locked *amount*.

**Outputs (metrics the close criteria read):** locked-supply trajectory (absolute and % of
circulating) over the ~30-yr mining-era horizon (timeframe 2); Δ vs. the current asserted
`stake_ratio` scenarios on the three published macro gauges — `staker_yield`, burn servo
behavior, release factor; the collapse check (does arm A's locked supply degenerate to
`bond_rate × shards × N_P` and is that level macro-material?); arm-B sensitivity (the
smallest `MIN` whose trajectory differs measurably from arm A).

**Close criteria (named in advance, per `21-reversion-clause-discipline.mdc`):**

- **(iii) closes bonds-only** iff arm A keeps all three macro gauges within the tolerance
  bands the existing economics scenarios already treat as healthy, across the full `N_P`
  envelope — i.e. admission lock is demonstrably **not** load-bearing for supply.
- **(iii) closes hard-lock** iff arm A breaches a gauge band that some arm-B `MIN` restores;
  pin `ADMISSION_MIN_ATOMIC` at the smallest such `MIN` (least capital-exclusion per
  priority-2-adjacent admission-cost concerns in gate-6 §2.5).
- **Indeterminate** (gauges insensitive to both arms at every `N_P`) resolves **bonds-only**
  — an admission lock that does no measurable macro work is pure optionality debt and the
  smaller consensus surface wins.

**Severity:** same as close-condition (ii), per `PHASE_2B_STAKE_LIFECYCLE.md` §2.4 — gate 7
is not optional resilience; Stage 3 emission code stays gated on it.

**Deliverables:** `gate7_*` scenarios in `shekyl-economics-sim` (gated; legacy scenarios
byte-identical per the iteration-3 discipline); a §*Gate 7 iteration-5* findings section in
this doc + a gate-7 ledger row; dispositions recorded in emission §10.2 (branch kept or
deleted), `PHASE_2B_STAKE_LIFECYCLE.md` §2.4 (iii) + §6 admission row, and gate-6 §2.5
(bond-funding obligation references the surviving arm).

### Gate 7 iteration-5 — results (2026-06-11)

**Instrument as built.** `ArchivalLockModel` in `shekyl-economics-sim::engine`, gated via
`ScenarioConfig.archival_lock` (`None` on every legacy scenario — the default eight-scenario
output was verified **byte-identical** by diffing the old-binary and new-binary JSON). The
model's constants are **compile-tied to the consensus pins** (crate dependency on
`shekyl-archival-retention`: `ARCHIVAL_BOND_FLOOR_ATOMIC`, `SETTLEMENT_EPOCH_BLOCKS`) rather
than re-asserted locally. Per the pinned build constraint above, the derived `stake_ratio`
and the burn input both denominate against **consensus circulating** (prev-block
`already_generated`), composed through the shared `calc_stake_ratio` +
`calc_burn_pct_from_activity` helpers — the same composition the C4 recorder and the engine
use. Eleven scenarios run via `--gate7`: arm A across the `N_P` envelope
{lean 79 / R = 6, thick 154 / R = 6, fee-era-thin 40 / R = 4} plus a 10×-denser
shard-geometry sensitivity arm (geometry is not yet consensus-pinned); arm B `MIN` grid
{1×, 100×, 10 000×} the bond floor at lean; a volume-stress pair (20 %/yr growth) for arm A
and the largest arm-B `MIN`; and two asserted-schedule comparators on the same 30-year
horizon.

**Locked-supply trajectory (the collapse check: confirmed, and the level is
macro-immaterial).** Arm A's locked supply degenerates exactly to
`bond_floor × R × shards(t)` as predicted: **117 coins** at year 0 → **3 546 coins** at year
29 against ~4.18 B circulating (`lock/circ` 2.3 × 10⁻⁷ → 8.5 × 10⁻⁷). The 10×-denser
geometry arm reaches 35 474 coins (8.5 × 10⁻⁶). The largest arm-B `MIN` (10 000× floor =
7 500 coins × `N_P` = 79) reaches **593 k coins ≈ 1.4 × 10⁻⁴** of circulating. Every arm is
three-plus orders of magnitude below the ~10⁻³ band where the burn servo's `stake_factor`
would begin to register at `SCALE` resolution.

**Gauge reads (all three insensitive to both arms at every `N_P`).**

| arm | burn % (yr 0 / 9 / 29) | release | net infl % (yr 9 / 29) | burned 30 yr (coins) |
|---|---|---|---|---|
| A lean / thick (R = 6) | 5.89 / 35.72 / 48.84 | 1.000 | 5.63 / 0.31 | 10 941 937 |
| A thin (R = 4, N_P = 40) | identical | identical | identical | identical |
| A lean, 10× dense shards | identical | identical | identical | +41 (+4 × 10⁻⁴ %) |
| B 1× / 100× MIN | identical | identical | identical | identical |
| B 10 000× MIN | identical | identical | identical | +2 023 (+0.0185 %) |
| A lean, growth | 5.89 / 89.98 / 90.00 (cap) | 1.300 | 4.69 / −0.74 | 496.6 M |
| B 10 000×, growth | identical at cap | identical | identical | +3 082 (+6 × 10⁻⁴ %) |
| comparator (asserted 5→35 %) | 6.18 / 42.83 / 65.71 | 1.000 | 5.63 / 0.30 | 14 086 259 |

The burn trajectory is identical to the cent across every arm-A and arm-B variant; the
release factor is volume-driven only (1.000 / 1.300) and never moves; net inflation is
identical. Under volume stress both arms clamp at the 90 % burn cap — indistinguishable.
The `staker_yield` gauge reads ~7 000 %/yr at lean because the income side
(`staker_pool_share` × burn + emission share) is unchanged while the capital base collapsed
~five orders of magnitude; that is a reward-arithmetic observation (income *distribution*
is governed by gate-5 serve-credit weighting, not by this gauge), not a stability breach.

**The re-pricing itself (Δ vs. the asserted comparator).** The legacy 5 %→35 % schedules
overstated burn through `calc_burn_pct`'s `(1 + stake_ratio)` factor: comparator total
burned 14.09 M coins vs. arm A 10.94 M (**−22.3 %**); final-year burn 65.71 % vs. 48.84 %.
The servo remains healthy without the stake term — `burn_base_rate` + √volume +
supply-ratio drive it to 48.8 % at steady state and to the cap under load, identically in
both arms. Corollary recorded to `docs/FOLLOWUPS.md`: the `(1 + stake_ratio)` term in
`calc_burn_pct` is **effectively inert in V3** (derived ratios 10⁻⁷–10⁻⁴ ≪ `SCALE`); it was
designed for the retired tier-staking model, and whether it stays (inert but harmless) or
goes (smaller consensus surface) is a consensus-parameter question for its own review, not
gate 7.

**Close-criteria application (named in advance, applied mechanically).** The gauges are
insensitive to both arms at every `N_P` — the **indeterminate branch** of the §scope close
criteria, which **resolves bonds-only**: an admission lock that does no measurable macro
work is pure optionality debt, and the smaller consensus surface wins. (The first branch
reads the same way — arm A stays within every band the legacy scenarios treat as healthy —
so both applicable readings converge on bonds-only.)

**Disposition — gate 7 closes; §2.4 close-condition (iii) resolves bonds-only.**
Admission principal is demonstrably **not** load-bearing for locked supply: emission verify
drops the `admission_proof` branch (emission §10.2), `ADMISSION_MIN_ATOMIC` loses its
consensus role, and gate-6 §2.5 subsequently pinned **no wallet-policy minimum either**
(no funding minimum at any layer; shape/timing hygiene only). The
cross-doc spec edits (emission §10.2 + `admission_proof`/§7.4 deletion,
`PHASE_2B_STAKE_LIFECYCLE.md` §2.4 (iii) + staking-form admission row, gate-6 §2.5
sole-owner note, `V3_STAKER_ARCHIVAL.md` admission bullet) **landed 2026-06-11 on
maintainer sign-off** of this disposition, per `05-system-thinking.mdc` (the criteria
were named in advance; the structural edit got a human eye before the branch was deleted).

**Coupling exported to the `R_market` weighting record (W10).** Bonds-only sharpens
what the no-minimum world costs: with no admission minimum at any layer (this close +
gate-6 §2.5), a market identity costs `bond_floor × R × shards ≈ 0.75` coins at one
shard. That is correct for *pricing work* — but it makes any **bond-membership
weighting** of `R_market` manipulable at ~0.75/pseudonym. The consensus pin
(`ARCHIVAL_CONSENSUS_STATE.md` §3.3: `R_market(s,E)` = plain count over the public
**serve-credit ledger**) is therefore **load-bearing against Sybil inflation of the
scarcity signal, with this close as a named input**: serve-credit bits cost real
service per pseudonym; bond membership post-close costs 0.75 coins. Any future
proposal to re-weight `R_market` onto bond membership must treat this gate-7 close as
a blocking input, not background.

**Reversion clause (per `21-reversion-clause-discipline.mdc`):** reopen gate 7 iff (a)
`ARCHIVAL_BOND_FLOOR` or the shard geometry is re-pinned upward by ≥ 3 orders of magnitude
combined (the level at which `lock/circ` enters the ≥ 10⁻³ band where the gauges begin to
move), or (b) a V3.x consensus change introduces a new archival-side lock class this model
does not carry. Re-evaluation shape: re-run the `--gate7` set against the new pins and
re-apply the same named close criteria; no new design round needed unless a gauge moves.
(A re-weighting of `R_market` away from serve-credit is *not* a gate-7 reopen — it is a
consensus §3.3 change that must cite the coupling paragraph above.)

## Close-condition (ii) — per-reward proof aggregate (2026-06-11)

PHASE_2B §2.4 close-condition (ii): is the per-reward backing-proof aggregate at target
`N_P` × settlement-epoch cadence compatible with block space? Unlike gate 7 this has no
feedback dynamics — every term is a pinned constant or a sim-banked envelope value — so
the instrument is a worked byte sweep, mechanically checkable, not a dynamic run.

**Inputs (all pinned or banked):** `SETTLEMENT_EPOCH_BLOCKS = 10_000`,
`MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` (emission §3); `daa_target_seconds = 120`
(`config/consensus_constants.json`) → epoch ≈ 13.9 days, ≈ 262 800 blocks/yr; shard
geometry `shards(t) = height / 10_000` with `R = 6` (G7 model); `N_P` envelope
{thin 40 (R = 4), lean 79, thick 154} (L11/L13); penalty-free block zone 300 000 B
(`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`).

**Per-emission vin terms (emission §5.3/§10.1; doc-estimated sizes, sources named):**

| Term | Size | Source |
|---|---|---|
| `P_pubkey` (hybrid canonical: Ed25519 32 + ML-DSA-65 pk 1 952) | ≈ 2.0 kB | FIPS 204 / `shekyl-crypto-pq` |
| `holdings` (ShardSetCompact, 8 B/shard × portfolio) | 0.2–0.6 kB | gate-4 §encoding |
| `settlement_epochs` (8 B × \|E\|) | 8–120 B | emission §5.3 |
| `work_claim` (\|E\| × portfolio × 13 B; `ShardWorkEntry` = id 8 + bit 1 + milli 4) | see sweep | emission §5.4 |
| `backing` (`MembershipOnlyBacking`, 1-input FCMP++ order) | ≈ 2.5 kB | `FCMP_PLUS_PLUS.md` §proof-size |
| `pqc_auth` ×2 inputs (Ed25519 64 + ML-DSA-65 sig 3 309) | ≈ 6.8 kB | FIPS 204 |
| fee input (FCMP++ marginal) + 2 vouts (KEM blob 1 120 ea + BP+ + ecdh/outPk) | ≈ 5.5 kB | `FCMP_PLUS_PLUS.md` §4 |

Typical single-epoch emission tx ≈ **17–19 kB**, dominated by constant-size crypto
(hybrid keys/sigs + FCMP++), **not** by the work claim. Per-archiver portfolio
`R × shards(t) / N_P` at year 30 (shards ≈ 788): lean ≈ 60 entries → work claim
**780 B/epoch** — under 5 % of the tx. Round to **20 kB** for margin.

**The sweep (aggregate per settlement epoch = `N_P` × 20 kB, amortized over 10 000 blocks):**

| Arm | Aggregate / epoch | Amortized / block | % of 300 kB zone |
|---|---|---|---|
| thin (`N_P` = 40) | 0.8 MB | 80 B | 0.027 % |
| lean (`N_P` = 79) | 1.6 MB | 160 B | 0.053 % |
| thick (`N_P` = 154) | 3.1 MB | 310 B | 0.103 % |

**Bound checks beyond the mean:**

- **Single-tx max** (15-epoch batch × year-30 lean portfolio): work claim
  60 × 13 × 15 ≈ 11.7 kB + constant crypto ≈ **29 kB** — ~5× under a
  half-penalty-zone tx ceiling (~150 kB).
- **Boundary burst** (every archiver claims in the first blocks after the epoch
  closes, zero spreading): thick = 3.1 MB ÷ 300 kB/block ≈ **11 blocks (~22 min)**
  to drain at penalty-free throughput alone; gate-6 jitter policy spreads it further
  as a privacy side effect.
- **Verifier cost:** `N_P` membership-only FCMP++ verifications per 10 000 blocks —
  one to two orders below ordinary-transfer load at any plausible tx volume.
- **Growth dependence:** only `work_claim` grows with chain age (linear in
  `shards/N_P`); at year 100 (~2 600 shards, lean portfolio ≈ 197) it is still
  ≈ 2.6 kB/epoch against ≈ 15 kB constant crypto. The aggregate scales with `N_P`,
  not chain age — and `N_P` is economically self-limiting (L11 attractor).

**Disposition — close-condition (ii) CLOSES.** The per-reward proof aggregate is
**≤ 0.11 % of penalty-free block space amortized across the entire `N_P` envelope**,
with bounded single-tx size, a self-draining boundary burst, and no compounding growth
term. Even a uniform 2× error on every doc-estimated size leaves the aggregate ≤ 0.21 %.
No emission-wire change is needed; `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` and
`SETTLEMENT_EPOCH_BLOCKS = 10_000` are confirmed as pinned.

**Honest caveat:** `MembershipOnlyBacking` is a not-yet-built sibling of
`FcmpPlusPlus::verify`; its size is assumed at 1-input `FcmpPlusPlus` order (it proves
strictly less — membership without key-image emission). The 2× margin read covers it.

**Reversion clause (rule 21):** reopen (ii) iff (a) the built `FcmpMembershipOnly`
proof exceeds 3× the 1-input `FcmpPlusPlus` estimate, (b) the `N_P` envelope re-pins
above ~1 500 (the level at which thick-arm amortized load crosses 1 % of the zone),
(c) `SETTLEMENT_EPOCH_BLOCKS` is re-pinned below 1 000, or (d) **the operating
envelope extends below `N_P` ≈ 25–30** (the thin direction, W9: the sweep ran
`N_P` {40, 79, 154}, but the L13 servo band floor is 17 and the L17 swan troughs
reach ~9 — per-archiver portfolio scales as `R·shards(t)/N_P`, so at `N_P` = 17,
year-30, the work claim is ~3.6 kB/epoch and a 15-epoch-batch single tx ≈ 70 kB —
under the 300 kB zone but ~23 % of one block, *and growing with chain age*; the
guard against thin populations is a **per-emission claim cap forcing batch
splitting**, which trades one oversized tx for several bounded ones).
Re-evaluation shape: re-run this sweep with measured sizes at the envelope edge —
a table update, not a design round, unless a bound check fails; if (d) fires, the
update pins the claim cap as a consensus constant.

## Layer-2 margin-robustness band — scope (scoped 2026-06-11)

**Decision it informs:** the genesis seal of `g(age)` (L1) and the standing of the
`bond_rate* = 0.75` pin's spread margin (L2). The emission leg's Layer-2 keystone row
(`REWARD_EMISSION_LEG.md` §1.2 #4) names the risk: the pin rows pass `sprdW` at
`giniW ≈ 0.593–0.599` against the hard 0.6 threshold — a single-point graze. The
reframe (2026-06-07) demands **margin robustness across the `g` operating band with
the whale trend bounded throughout**, not a point pass.

### Problem definition — what the 0.6 gate protects, and why the margin is narrow

Before sweeping, decompose the grazing reading. The `sprdW` verdict carries two
thresholds protecting two different properties:

1. **Whale capture** (the threat the actor-level metric was built for): one actor —
   via unlinkable pseudonyms — accumulating a durability-critical share of shards,
   especially irreplaceable deep history. Direct gauges: `max_actor_share` (< 0.20),
   per-band `whale_share` (`wB4`), per-band distinct-actor counts.
2. **Population-wide concentration**: the shards-held distribution across *all*
   actors. Gauge: `gini_actor` (< 0.6), windowed (`giniW`).

At the pin these tell **opposite stories**. The whale gauges have wide margins:
`max_actor_share ≈ 0.011` (18× under the 0.20 bar); oldest-band whale share
`wB4 ≈ 0.12`. The gini grazes — and the decomposition shows the whale contributes
almost none of it: lean-no-whale `giniW ≈ 0.593` vs whale-present `≈ 0.594`
(+0.001); the polarized-endowment coloc row reads 0.599 (+0.006 from endowment
shape).

**The ~0.59 baseline is the lean L11 attractor's intrinsic inequality**, produced by
three structural causes, none of which is whale capture:

- **Entry-until-breakeven leans the population.** The attractor stops recruiting
  exactly when the marginal archiver earns ρ — so the steady state holds a few
  large incumbent portfolios plus a tail of small marginal ones. Leanness *is*
  concentration: L11 measured `gini 0.71` at the lean point vs `0.46` at
  budget 200 (bond_rate 2.0 rows; the transfer re-confirms at 0.75 in this sweep).
- **`g(age)` compounds incumbency.** The age premium pays deep portfolios more
  per shard, and deep shards demand bond capital — so capital-rich incumbents
  systematically hold the higher-value books. Raising `g` (the band under test)
  should *worsen* the gini trend while *improving* deep seating: L1's entanglement.
- **Windowing counts the churn flicker.** Participation churn ≈ 0.17 at the pin is
  benign rotation (F2 bank), but mid-flicker actors hold near-zero shards while
  sampled, inflating the windowed mean (the "whale window worsens under windowing"
  note is this artifact class).

The narrow margin is therefore a **proxy-metric graze, not a measured approach to
the protected property** — pending the band sweep confirming the decomposition holds
across the operating band, which is exactly what this scope tests.

### Instrument

`shekyl-staking-sim` (agent-based; all knobs and gauges exist: `age_weight`,
`bond_rate`, `budget`, `giniW`, `max_actor_share_window`, per-band `gini_actor` /
`whale_share` / affording-actor counts). New axis `--axis=layer2_band`; existing
scenarios byte-identical per the iteration-3 discipline.

1. **`g` band sweep at the pin:** `age_weight ∈ {1.5, 2.0, 2.5, 3.0, 3.5, 4.0}` ×
   `bond_rate = 0.75` × the three pin rows (lean L11 fill ρ=0.02; whale cross;
   coloc polarized ρ=0.015). Per cell: `giniW`, `max_actor_share` peak, `wB4`,
   per-band distinct-actor counts, `deep_und`, min-form `dS/dN`, `oUmx`, churn.
2. **Budget cross at the pin (the second lever, L2 "Active" item):**
   `budget ∈ {100, 130, 160, 200}` × `g = 2.0` × lean + whale rows at
   `bond_rate = 0.75` — quantifies the spread-purchased-through-participation
   transfer (`budget → bondA → giniW`) at the pinned bond, replacing the
   non-comparable `l11_bud_*` rows (bond_rate 2.0). This prices the gate-1/7
   emission lever as a spread instrument: if the seal ever needs margin, the purse
   is the named knob that buys it without touching consensus shape.
3. **Decomposition check per cell:** report lean-no-whale vs whale-present `giniW`
   delta and the correlation of `giniW` movement with `bondA` (population leanness)
   vs `wB4` (whale concentration). This is the evidence that either confirms or
   refutes the problem definition above.

### Close criteria (named in advance, rule 21)

- **Seal as-is** iff across the full `g` band: `giniW < 0.6`, whale gauges flat
  (`max_actor_share` peak < 0.05, `wB4` < 0.2, distinct-actor counts ≥
  `R_target(band)`), and coverage/seating hold (`deep_und < 0.10`, `dS/dN ≥ 1`,
  `oUmx < 0.05`). Comfortable margin = the band never enters [0.59, 0.6) for more
  than one grid point.
- **Re-anchor the gate** iff the proxy grazes or crosses 0.6 somewhere in the band
  **but** the decomposition shows the movement is leanness-attributed (giniW tracks
  `bondA`, whale gauges stay flat with the margins above). Disposition: the seal
  gates on the **direct protected-property gauges** (whale share, per-band
  distinct-actor counts); `gini_actor` is demoted to a reported trend gauge with the
  decomposition recorded. This is a metric re-derivation against the threat model —
  not a threshold relaxation; the whale-capture bar does not move.
- **Pull the Curve reserve** iff any **direct** whale gauge trends toward its bar
  anywhere in the band, or coverage and spread cannot hold simultaneously at any
  `g`. The population-gated declining-tail `Curve` (V3 reserve) caps the per-shard
  premium at high age, flattening incumbent advantage — the named pocket-widener.
  The budget lever (item 2) is the second reserve: recruit spread via the purse.

**Severity:** genesis-seal gate for `g` and the final Layer-2 economics item.
Stage 3 emission code does **not** gate on this (its gates are schema
implementation + gate-6 soundness), but the genesis constants table does.

**Deliverables:** `layer2_band_*` scenarios in `shekyl-staking-sim`; a findings
section in this doc + L1/L2 ledger updates (seal, re-anchor, or reserve pull);
disposition recorded in `REWARD_EMISSION_LEG.md` §1.2 #4 and the Layer-2 row of
§1.1; `ARCHIVAL_TIMING_CONSTANTS.md` gains the sealed `g` if the seal lands.

## Layer-2 margin-robustness band — results (2026-06-11)

**Instrument as built.** `layer2_band_*` / `layer2_bud_*` / `layer2_colocbud_*`
scenarios in `shekyl-staking-sim` (axes `layer2_band{,_whale,_coloc}`,
`layer2_budget{,_whale}`, `layer2_colocbud`); 29 scenarios total; existing axes
untouched. The `g = 2.0` rows are config-identical (same fixed seed) to
`gate4_fine_0.75{,_whale}` / `gate4_coloc_0.75` — the in-table cross-check. Run:
`cargo run -p shekyl-staking-sim --release -- --axis=layer2`.

**Finding 0 — substrate drift: the 2026-06-07 pin readings are superseded.** The
cross-check rows do *not* reproduce the iteration-2 recorded values (`giniW
0.593/0.594/0.599`, all pass, `bondA ≈ 79`). Today they read `0.598 / 0.595 /
0.614`, with the **coloc pin row failing** `sprdW` and `churn_stable`
(`oUmx 0.245`), at `bondA ≈ 113`. Cause: the **banded PL Curve repair**
(`4071ec032`, 2026-06-10, ARCHIVAL_CONSENSUS_STATE PR 0) replaced the hard
reward cap with the banded plateau `Curve(work)` (slopes `[1.0, 0.5, 0.25, 0]`),
changing marginal credit and therefore the L11 equilibrium: the population
thickened (`bondA` 79 → ~113), the windowed gini moved ~+0.005–0.015, and the
polarized-endowment world developed mid-band coverage oscillation. This is the
Layer-2 reframe's warning made empirical: a single-point pass recorded against a
moving substrate is not a seal. The gate-4 `bond_rate* = 0.75` pin itself is
unaffected (see Finding 4).

**Finding 1 — the decomposition is confirmed decisively; the gini is a leanness
gauge, not a whale gauge.** Across the entire `g` band and the entire budget
cross, the direct whale gauges never move:

| g | lean `giniW` | whale `giniW` | Δ(whale−lean) | `mxSW` | `wB4` | lean `bondA` |
|---:|---|---|---|---|---|---|
| 1.5 | 0.588 | 0.588 | +0.000 | 0.014 | 0.00 | 116.3 |
| 2.0 | 0.598 | 0.595 | −0.003 | 0.014–0.018 | 0.00 | 113.5 |
| 2.5 | 0.598 | 0.601 | +0.003 | 0.014 | 0.00 | 113.8 |
| 3.0 | 0.606 | 0.609 | +0.003 | 0.013 | 0.00 | 111.2 |
| 3.5 | 0.610 | 0.612 | +0.002 | 0.013 | 0.00 | 109.9 |
| 4.0 | 0.634 | 0.637 | +0.003 | 0.014 | 0.00 | 102.5 |

The whale's windowed share peak stays at **0.013–0.018 against the 0.20 bar
(≥ 11× margin) at every point**; its oldest-band share is 0.00 throughout; adding
the whale moves `giniW` by ≤ 0.003 (sign-indefinite — noise). Meanwhile `giniW`
co-moves with `bondA` in **both directions**: `g` 1.5→4.0 thins `bondA` 116→102
and lifts `giniW` 0.588→0.634; budget 100→200 thickens `bondA` 113→226 and drops
`giniW` 0.598→0.217. The grazing metric is measuring population leanness — the
attractor's deliberate operating point — not actor capture.

**Finding 2 — the budget cross is the spread lever, with steep gain.** At
`g = 2`, `bond_rate = 0.75` (lean + whale arms):

| budget | `bondA` | `giniW` | `mxSW` |
|---:|---|---|---|
| 100 | 113.5 | 0.598 | 0.018 |
| 130 | 150.4 | 0.475 | 0.010 |
| 160 | 183.2 | 0.363 | 0.008 |
| 200 | 226.0 | 0.217 | 0.006 |

+30 % purse converts the 0.002-margin graze into a 0.125 margin. The transfer is
monotone, whale-arm-identical, and confirms the L11 `budget → bondA → spread`
function at the pinned bond (the old `l11_bud_*` rows at `bond_rate = 2.0` are
retired as non-comparable).

**Finding 3 — the band's real upper bound is coverage oscillation in the
polarized world, and the purse cures the shoulder but not the tail.** At
budget 100 the coloc rows oscillate (`oUmx` 0.245 / 0.347 / 0.612 / 1.000 at `g`
2.0 / 2.5 / 3.0 / 3.5; `g` 3.0 also fails coverage outright at `frac_und 0.167`);
only `g = 1.5` passes everything at the bare-lean purse. At budget 130 the
shoulder heals completely — coloc `g` 2.0 / 2.5 pass **all** gates (`giniW 0.477`,
`oUmx = 0`) — but `g = 3.0` still fails hard (`frac_und 0.225`, `oUmx 1.0`):
above the shoulder the age premium starves hot coverage in ratio-mismatched
populations regardless of purse. Note the live design carries the L13 adaptive
servo (`budget_eff = base·(1 + gain·shortfall)`), which responds to exactly this
oscillation signal; the b100 rows are servo-less by construction, so the
purse-restores-stability finding is the servo's static image.

**Close-criteria application (named in the scope):**

- **Seal as-is** — fails: `giniW` crosses 0.6 inside the band (whale arm from
  `g = 2.5`) and the coloc rows oscillate at the bare-lean purse.
- **Re-anchor the gate** — **selected.** The decomposition evidence is exactly
  the re-anchor trigger: proxy grazes/crosses while every direct
  protected-property gauge holds flat with ≥ 11× margin and the gini movement is
  leanness-attributed in both sweep directions. Disposition: the **genesis spread
  seal gates on the direct whale gauges** — windowed `max_actor_share < 0.20`,
  per-band whale share bounded (`wB4`), per-band distinct-actor counts ≥
  `R_target(band)` — and `gini_actor` is **demoted to a reported trend gauge**
  (decomposition recorded here; the whale-capture bar moves nowhere).
- **Curve reserve** — not triggered: no direct whale gauge trends toward its bar
  anywhere in the band or the budget cross. The declining-tail `Curve` stays a
  V3 reserve.

**Finding 4 — implication for the gate-4 bond pin (note, not a reopen).** The
iteration-2 upper bound at `bond_rate = 1.00` was a `gini_actor` fail (0.61) —
under the re-anchored gauges that fail class is leanness, not capture (`mxSW` at
1.00 today: 0.014, flat). The L2 reversion clause names "the spread threshold …
shifts the triple intersection" as a reopen trigger; the re-anchor is such a
shift, but nothing pushes toward a higher bond — `0.75` passes every gauge,
maximizes Sybil headroom within the live band, and the atomic constant is
already pinned. **Disposition: bond pin stands; the upper-bound rationale is
re-annotated (leanness-gini, not whale spread) without moving the value.**

**`g` seal disposition.** The operating band under the current substrate is
**`g ∈ [1.5, 2.5]`** — `g = 1.5` passes everything at the bare-lean purse;
`g ∈ {2.0, 2.5}` passes everything with ~30 % purse headroom (which the L13
servo provides adaptively); `g ≥ 3.0` fails polarized-world coverage at any
purse and is **out**. The genesis target stays **`g ≈ 2`** (deep-allocation
insurance at endogenous-population thickness costs nothing while the servo
holds the purse above bare-lean), with `g = 1.5` recorded as the fallback if
calibration finds the purse pinned at the bare-lean point.

**Finding 5 — `g` units gap blocks the constant mapping. CLOSED same day.**
The sealed band is in **sim units**: `g = 1 + age_weight · age` with age
**normalized to [0, 1]** (fraction of chain depth). The consensus form
(`g_age_milli` in `shekyl-archival-retention/src/reward_arithmetic.rs`) took
**raw epoch counts** from `shard_age_milli` — unbounded, so consensus `g` grew
linearly with shard age forever (`≈ 700·w` at 10 years), a different functional
shape from the one this run sealed and a mission-timeframe oldest-band
concentration surface. **Resolution (2026-06-11, same day):** normalization
pinned as relative depth — `age_milli = floor(age_epochs · 1000 /
chain_epochs)` — in `ARCHIVAL_REWARD_ARITHMETIC.md` §Shard age;
`shard_age_milli` reimplemented (signature unchanged);
`archival_reward_age_weight_milli = 2000` maps the sealed target `g* ≈ 2` with
calibration band `[1500, 2500]`; the epoch-close KAT vector re-derived by hand
(`Σwork` 3500 → 2590).

**Instrument note — gate re-anchor implemented (2026-06-11, same day).** The
sim's `spread`/`sprdW` verdicts now gate on the direct whale gauges
(`max_actor_share < 0.20`; oldest-band whale share `wB4 < 0.20`; the per-band
distinct-actor-seating term rides on the coverage claims since `R` counts
distinct actors), with `gini_actor`/`giniW` printed as trend gauges only.
Verdict columns in tables recorded *before* this date were produced under the
old gini-gated `sprdW`; the raw gauge columns are unchanged and re-judgeable.
Re-run under the new gate: every lean/whale band row passes `sprdW` across
`g ∈ [1.5, 4.0]` (mxSW 0.013–0.018, wB4 = 0), and the bare-lean coloc fails at
`g ∈ {2.0, 2.5, 3.0, 3.5}` are now attributed to `churn_stable`/coverage —
matching the Finding-3 oscillation reading, not spread. (The coloc `g = 4.0`
row prints ALL-pass under the new gate; its `churn ≈ 0.01` is the frozen
lock-in artifact, and the band's `g ≥ 3.0` exclusion stands on the `g = 3.0`
coverage fail and `g = 3.5` oscillation.)

**Reversion clause (rule 21).** Reopen the Layer-2 seal iff (a) any direct whale
gauge (`mxSW`, `wB4`, per-band distinct-actor count) trends past half its bar in
a future substrate re-read, (b) a reward-curve or participation-model change of
the Curve-repair class lands (Finding-0 precedent: re-run `--axis=layer2` and
re-read this table — a table update, not a design round, unless a direct gauge
fails), or (c) calibration pins the live purse at or below the bare-lean point
while `g ≥ 2` (then the `g = 1.5` fallback activates or the L13 servo gain is
re-examined). Re-evaluation shape: re-run the band axes against the changed
substrate and update this section; design round only on a direct-gauge fail.

## L17 — black-swan / acute-shock layer (2026-06-11)

**Why.** The L13/P2 sustainability layers stress *gradual* declines — geometric
subsidy taper, geometric price decay. Historical crises are step events. This
layer fires one-epoch discontinuities at a settled, healthy network and reads
the damage and the recovery, closing the "feasible scenarios, outliers, black
swans" due-diligence gap.

**Research grounding — observed crash patterns and the channel each maps to:**

| Historical pattern | What happened | Sim channel |
|---|---|---|
| March 2020 (COVID) | BTC −50 % in 2 days, V-shaped recovery within months | `shock_price_mult` + `shock_price_relax` (gap-down that heals) |
| FTX, Nov 2022 | Contagion price leg **plus** custody collapse — a cohort of participants (exchange-held stakes, exchange-run nodes) vanished overnight | `shock_price_mult` (permanent) + `shock_exit_frac` |
| LUNA/UST, May 2022 | Compound event: price, panic, forced exits, and a live trust→exit feedback | all channels + `price_coupling` (the L13 expectation leg) |
| 2008 (flight to liquidity) | Outside yields / liquidity preference spike; risk capital's opportunity cost jumps as a *factor*, then subsides — or persists (rates-era regime change) | `shock_rho_mult` + `shock_rho_relax` |
| **Filecoin, 2022→2024** | **The closest analog of this exact system**: FIL price fell, fiat opex vs token rewards turned negative, providers terminated sectors to recover pledged collateral — active SPs 4 100 → ~1 900, raw capacity 17 → 4.2 EiB (Messari, State of Filecoin Q3'22→Q4'24) | the P2 fiat flow-cost leg (`flow_cost_fiat`) under a permanent `shock_price_mult` |

**Instrument.** Gated `shock_*` knobs in `SimConfig` (`shock_at = 0` ⇒ inert;
every prior scenario byte-identical — cross-checked: `gate4_fine_0.75` and the
`layer2_band` rows reproduce their banked values to the digit). At the shock
epoch: the token price gaps by `shock_price_mult` (bites via the P2 fiat
flow-cost leg), every reservation steps by `shock_rho_mult` (relaxing back at
`shock_rho_relax`), and `shock_exit_frac` of the active set is deactivated by
deterministic stride (samples all endowment classes; no RNG perturbation;
exiters drop holdings and rejoin the entry pool at the rate-limited
`entry_per_epoch`). Reads: `shkP` (post-shock worst serving deep gap),
`shkRec` (epochs the deep tail stayed over the 0.10 bar; −1 = not recovered by
run end), `shkBA` (post-shock bonded-archiver trough). World: the pinned
genesis economics (`bond 0.75`, `g 2.0`, ρ = 0.02, budget 100 — bare-lean),
mature and healthy at t = 0; shock at epoch 120 of 240. Run:
`cargo run -p shekyl-staking-sim --release -- --axis=swan`.

**swan-2 instrument extensions (W1–W3 wargame response, same day).** The swan-1
verdicts measured *metric* recovery under the most benign correlation structure
(stride) at the healthy attractor only. Three extensions convert the
assumed-away tails into measured ones:

- **Extinction accounting (W1).** Substrate answer first: re-acquisition in
  this model is **sourceless** — the best-response simply sets
  `holdings[a][s] = true` with no surviving-source check, so backfill succeeds
  unconditionally and `shkRec` measures recovery of a *metric*, not of *data*.
  New read: a deep shard whose serving holder set empties *after having been
  seated at depth* is a **data-extinction event** (corrected swan-4: a
  **foundation-as-sole-source transition** — the retention guarantee makes
  it an availability state, not loss; the columns stand as measurements)
  (sticky per slot until the
  frontier recycles it; scanned at the shock instant, after each epoch, and
  after voluntary exits — the death-spiral channel's orphanings land in
  `process_exits` and would otherwise be re-covered invisibly one epoch
  later). `extT` = run-wide events, `shkExt` = post-shock events. The scan
  counts **market copies only**: the swan worlds run with no foundation floor,
  so `shkExt` is the no-floor worst case, and a complete floor over the band
  converts each event into an availability window instead of a loss.
- **Domain-correlated exit (W2).** `shock_exit_domains = n`: every active
  actor in failure domain 0 under the L15 bucketing (`a % n == 0`) exits at
  the shock — one custody/operator domain vanishes whole, the FTX class as it
  actually happened. Stride is kept as the benign-correlation baseline.
- **Aftershock + timing (W3).** `aftershock_at` re-fires every configured
  shock leg against the survivors (the 2022 LUNA→3AC→FTX sequence shape);
  `swan2_knee_cascade` fires a 30 % cascade at the **L13 knee** (terminal
  floor 80, purse ≈ 86 at the shock — the decayed low-margin state) instead
  of the healthy attractor; `swan2_cascade_rho` compounds the 50 % exit with
  a ρ ×2 panic so entry is suppressed exactly when the rebuild needs it.

**swan-3 instrument extensions (W12–W15 wargame response, same day).** swan-2
sized the gate-5 floor-completeness export *by inference*: the swan worlds are
**bare-lean** (`floor_replicas = 0` everywhere), the export's band scope
("oldest stratum") was an assumption, and the benign domain results ran with
**no placement-side diversity floor in the model at all** (the L15 domain
machinery is scoring-only; nothing constrains a shard's holders to span
domains). Three extensions convert the inferences into measurements:

- **Per-band extinction read (W12).** `extB` bins each shock extinction by the
  shard's age band *at extinction time* (the five normalized-age bands;
  b5 = oldest). Scopes the completeness requirement to the band set that
  actually extinguishes instead of the assumed one.
- **Floored extinction read + floor-on closure arms (W13).** `shkExF` counts a
  deep-seated shard data-dead only when its market holder set **and**
  `foundation_floor_aged` at its age are *simultaneously* zero — the floor is
  the non-market source of last resort, so a market wipe-out with the floor
  engaged is under-replication, not loss. The read also catches the **hand-off
  race**: if the floor withdraws (population recovery decays it) before the
  market re-seats a still-empty slot, the slot is counted then. Closure arms
  re-run the two extinguishing price rows with the re-engagement floor on
  (`6 = r_target_deep`, `decay_pop 100` ≈ the attractor population — ≈0
  pre-shock, re-engaging as the trough thins the market), at tilt 0 and at the
  P3 maximum tilt 0.9. The floored read is conditional on **completeness** —
  the foundation actually holding a copy of everything the formula floors —
  which is exactly the requirement the arm sizes; the model grants instant
  re-engagement, which is only coherent under continuous completeness.
- **Holder-class-correlated exit (W15).** `shock_exit_top_deep`: the active-set
  fraction holding the **most deep shards** exits at once. The `a % n` domain
  bucketing is uncorrelated with portfolio composition *by construction*, so
  the swan-2 domain rows measured benign correlation luck, not a floor working;
  the FTX pattern — custody membership correlated with holder class (the
  marginal deep bonds cluster on cheap custodial operators) — is the honest
  worst case, and this leg is exit maximally correlated with deep holder sets.

**swan-4 — the retention correction (foundation-as-sole-source re-read, same
day).** The swan-1/2/3 extinction framing contradicted the corpus's own
retention pin: genesis foundation seeds hold **complete trees (B + C)
permanently** — `V3_STAKER_ARCHIVAL.md` gate-list item 5 ("permanent
foundation floor, no `decay_pop` withdrawal") and the §*Foundation
complete-tree seeds* authority pin (retention vs internal redundancy vs
serving participation). A market holder-set wipe-out is therefore **never
data loss**: it is a transition to **foundation-as-sole-source**, and the
model's sourceless backfill coincidentally models the real recovery path
(fetch from a public foundation seed) *minus its bandwidth bound*. The
`extT`/`shkExt`/`extB`/`shkExF` columns stand as measurements — re-read as
**availability transitions**, with `shkExF` measuring the *serving-layer*
floor's coverage of those windows. What the framing missed, swan-4 adds:

- **Foundation re-seed bottleneck (`reseed_rate`).** Post-trough, every
  zero-market-holder shard must re-seed from the foundation seeds —
  `N_active = 3` public endpoints, a serialized, bandwidth-bound source
  (contrast L10's market backfill, which parallelizes across holders).
  `reseed_rate = k` caps network-wide fresh fetches of zero-serving-holder
  shards at *k* per epoch (0 = unlimited, legacy byte-identical; 3 ≈ one
  seeding flow per seat, 12 = 4× provisioning sensitivity).
- **Sole-source window read.** `ssSE` = run-wide shard-epochs spent with the
  foundation as a deep shard's only source; `ssMxW` = the longest
  single-shard window; `ssOpn` = windows still open at run end. This is the
  honest verdict shape for the price rows: *"deep retrieval degraded for X
  epochs with the foundation as sole source"* — replacing both the old
  fake-instant recovery and the extinction over-claim.

Two instrument notes. (1) The bound also binds the **boot transient** — these
worlds cold-start their deep seating from the same foundation bandwidth, so
the over-subscription spike never forms (`baPk` 107–109 vs 237 legacy) and the
pre-shock attractor settles from a rate-limited build-up; this is *more*
realistic (the L12 cold start seeds from the foundation), but it means the
rate-limited rows are not byte-identical worlds to their unbounded twins, and
`ssSE` is run-wide (boot-transient windows included). (2) On unbounded rows
`ssSE = 0` by construction — sourceless-instant re-seat closes every window
within its own epoch, which is exactly the artifact the bound removes.

**Results (23 scenarios; swan-1/2 rows re-run under the band + floored +
sole-source reads):**

| scenario | shock | `shkP` | `shkRec` | `shkBA` | `shkExt` | `shkExF` | `extB` (b1…b5) | verdict read |
|---|---|---:|---:|---:|---:|---:|---|---|
| `swan_cascade30` | 30 % of actives gone overnight (stride) | 0.000 | 0 | 75 | 0 | 0 | — | **absorbed** — deep bar never breached |
| `swan_cascade50` | 50 % gone overnight (stride) | 1.000 | 4 | 53 | 0 | 0 | — | breached 4 epochs, full metric **and data** recovery |
| `swan2_domain3` | one of **3 domains** gone (~33 %, index-bucketed) | 0.241 | 1 | 69 | 0 | 0 | — | **absorbed** (1-epoch graze) ‡ |
| `swan2_domain2` | one of **2 domains** gone (~50 %, index-bucketed) | 1.000 | 5 | 53 | **1** | 1 | 0/0/0/1/0 | metric recovers in 5 — **1 deep shard to sole-source** ‡ |
| `swan3_class30` | **top-30 % deep holders** gone (class-correlated) | 0.429 | 1 | 74 | **4** | 4 | 0/0/0/4/0 | 1-epoch graze — **4 deep shards to sole-source** |
| `swan3_class50` | **top-50 % deep holders** gone (class-correlated) | 1.000 | 5 | 53 | **28** | 28 | 0/0/0/17/11 | metric recovers in 5 — **28 deep shards to sole-source** |
| `swan2_aftershock` | 50 % at 120 + 50 % of survivors at 123 | 1.000 | 13 | 37 | **4** | 4 | 0/0/0/4/0 | metric recovers in 13 — **4 deep shards to sole-source** |
| `swan2_cascade_rho` | 50 % exit + ρ ×2 panic (slow subside) | 1.000 | 4 | 53 | 0 | 0 | — | as `cascade50` — entry suppression didn't extend the breach |
| `swan2_knee_cascade` | 30 % cascade **at the L13 knee** (purse ≈ 86) | 0.217 | 2 | 66 | 0 | 0 | — | **absorbed at the low-margin state** |
| `swan_flight` | ρ ×3, subsiding (~14-ep half-life) | 0.000 | 0 | 70 | 0 | 0 | — | **absorbed** |
| `swan_regime` | ρ ×2 **permanent** | 0.000 | 0 | 74 | 0 | 0 | — | leaner attractor (−25 %), coverage holds † |
| `swan_price_vshape` | price ×0.25, V-shaped recovery | 1.000 | 17 | 10 | **37** | 37 | 0/0/0/20/17 | metric fully recovers — **37 deep shards to sole-source in the trough** |
| `swan3_vshape_floor` | same + **re-engagement floor on** (tilt 0) | 1.000 | 17 | 10 | 37 | **0** | 0/0/0/20/17 | every wipe-out covered by the serving floor |
| `swan3_vshape_floor_t9` | same, floor at P3 tilt 0.9 | 1.000 | 17 | 10 | 37 | **0** | 0/0/0/20/17 | tilt redistributes depth, not membership — no leak |
| `swan_price_gap` | price ×0.25 **permanent**, fiat opex | 1.000 | **−1** | 10 | **347** | 347 | 0/0/23/181/143 | **market collapse** — deep set foundation-dependent |
| `swan_price_gap_servo` | + L13 servo, ceiling 130 | 1.000 | **−1** | 12 | **144** | 144 | 0/0/2/81/61 | **market collapse** — +30 % purse ≪ 4× cost shock |
| `swan_price_gap_servo400` | + servo, ceiling 400 | 1.000 | 114 | 9 | **99** | 99 | 0/0/5/64/30 | coverage recovers — **99 deep shards to sole-source meanwhile** |
| `swan3_servo400_floor` | same + **re-engagement floor on** (tilt 0) | 1.000 | 114 | 9 | 99 | **0** | 0/0/5/64/30 | 114-epoch window crossed under serving-floor cover |
| `swan_perfect` | ×0.25 + ρ ×2 + 30 % exit + trust coupling | 1.000 | **−1** | 8 | **649** | 649 | 0/0/59/413/177 | **market collapse** |
| `swan_perfect_servo` | same + servo, ceiling 130 | 1.000 | **−1** | 9 | **265** | 265 | 0/0/31/139/95 | **market collapse** |

**swan-4 re-seed bottleneck arms** (the two recovering price rows, re-seed
bandwidth-bound; `ssSE` = sole-source shard-epochs, `ssMxW` = longest
single-shard window, `ssOpn` = unrecovered at run end):

| scenario | re-seed bound | `shkRec` | `shkExt` | `ssSE` | `ssMxW` | `ssOpn` | verdict read |
|---|---|---:|---:|---:|---:|---:|---|
| `swan4_vshape_reseed3` | 3/epoch (≈ 1 flow per seat) | 17 | 40 | **429** | **10** | 0 | trough costs ~429 shard-epochs of foundation-only retrieval; worst shard 10 epochs; all re-seeded |
| `swan4_vshape_reseed12` | 12/epoch (4× provisioning) | 16 | 10 | 204 | 9 | 0 | provisioning 4× cuts exposure ~2× — backlog drains, demand-bound tail remains |
| `swan4_servo400_reseed3` | 3/epoch, servo ceiling 400 | 113 | 121 | **403** | 9 | 5 | the 114-epoch window is crossed; re-seed keeps pace with the thinned market's demand (5 windows open at the run boundary — final-epoch evictions, re-seat pending) |

(Measurement note: the sole-source tick reads **end-of-epoch** state — a window
opened by an epoch's voluntary exits counts from the epoch it opens. The
pre-correction tick ran before exit processing, systematically undercounting
each exit-opened window by one epoch; the Copilot-review fix on this PR
re-measured these rows.)

† conditioned on the Finding-0 reconciliation — see Finding 7.
‡ floor state pinned (W15): these rows ran with **no diversity floor** — none
exists in the model's placement — so the benign results are luck of the
`a % n` bucketing being uncorrelated with holder sets, not a floor working.
The `swan3_class*` rows are the same magnitudes under honest worst-case
correlation.

(`extT` baseline note: absorbed rows show `extT ≈ 94, shkExt = 0` — those ~94
events all land in the **initialization trim transient** (these worlds boot
over-subscribed at `init_active_frac = 1` and prune ~140 actors toward the
attractor in the first ~20 epochs; real genesis is the L12 bootstrap + floor
path, not a trim). The settled attractor's own extinction rate is **zero per
120 epochs** — `shkExt = 0` on every absorbed row. `swan2_knee_cascade` boots
well-funded and shows `extT = 0`: no trim, no noise.)

**Finding 1 — population shocks are absorbed by construction, now including
the low-margin timing and the compound.** A 30 % overnight exit, a
tripled-then-subsiding opportunity cost, and even a *permanent* doubling of
every actor's reservation never breach the deep-history bar: the per-shard
replication headroom (`R_target_deep`) rides through the transient and the
free-entry attractor (L11) refills the population. The 50 % cascade breaches
for exactly 4 epochs and recovers completely — with **zero market wipe-outs**
under stride sampling. swan-2 hardens the claim on two axes the swan-1 grid skipped:
the same 30 % cascade fired **at the L13 knee** (decayed purse, the low-margin
state where markets actually deliver crises) is absorbed with a 2-epoch graze,
and compounding the 50 % exit with a ρ ×2 entry-suppressing panic does not
extend the breach. The system's resilience to *who-shows-up* shocks is
structural, not tuned.

**Finding 2 — the fatal channel is a permanent price collapse with
fiat-denominated operating costs.** A −75 % permanent gap quadruples real flow
costs (`F/p`), and the network collapses regardless of the +30 % adaptive purse
— consistent with the banked P2 finding (the gradual fall collapses to the same
end state), now confirmed for step ignition. This is precisely the
Filecoin-2022 pattern, observed at production scale in the closest real-world
analog. The compound (LUNA-class) event is dominated by this leg.

**Finding 3 — survivability of the fatal channel scales with fee-market
headroom, and recovery is slow.** With the servo ceiling raised to ≈ the real
cost multiplier (400 ≈ 4×), coverage recovers — but the impaired window is
~114 epochs and the recovered attractor is leaner (`bondA` 58 vs 113). The
mitigation stack named at L13 — adaptive purse (capacity permitting) **plus the
population-decaying foundation floor that re-engages automatically as the
market thins** (`l13_floor`) — is the bridge across that window. The V-shaped
crash needs none of it for the *metric*: 17 epochs impaired, full recovery, no
coverage ratchet. **Caveat (W4): both legs of that stack are pro-cyclical.**
The ceiling is fee-market capacity, and a −75 % price collapse co-occurs with
collapsed transaction demand — the crisis-time ceiling sits *below* the static
one, so "recovers at ceiling ≈ cost multiplier" is the optimistic branch. The
foundation floor is likewise token-treasury-funded: the same event cuts its
fiat purchasing power ~75 % unless treasury policy diversifies (named as a
foundation-operations requirement in `FOLLOWUPS.md` — the floor is
load-bearing at both temporal ends and, per Finding 4, for data survival).
The survivable/fatal boundary therefore sits *lower* than this table reads.

**Finding 4 (swan-2/W1, re-scoped swan-3/W12–W13, corrected swan-4) — metric
recovery ≠ market-source recovery; under the retention guarantee the gap is
an availability window, and its honest size is the re-seed bottleneck.**
The swan-2/-3 rounds framed `shkExt` as data extinction; that framing
contradicted the corpus's retention pin (`V3_STAKER_ARCHIVAL.md`
§*Foundation complete-tree seeds*: every genesis seat holds complete B + C
permanently, no sunset). Corrected reading: the stride cascades and all
absorbed rows recover with **zero** market wipe-outs, while the V-shaped
crash sends **37 deep shards to foundation-as-sole-source** in its 17-epoch
trough and the recovered servo-400 branch **99** across its 114-epoch
window — degraded-retrieval exposure, not loss. The retention guarantee is
what converts the swan-2 export from a *new* gate-5 requirement into
**documentation of an existing guarantee plus its threat model** (the
authority pin, with the single-organization threat model named there:
correlated infra loss, seizure, dissolution over timeframes 2–3).

*Where the wipe-outs land (W12).* The `extB` band read rejects the
oldest-concentration assumption: in every price row **band 4 (mid-deep)
dominates** — vshape 20/17 (b4/b5), servo-400 5/64/30 (b3/b4/b5),
permanent-gap 23/181/143. Trough wipe-out follows *holder economics at
eviction*, not shard age. The read keeps its force under the corrected
framing: any **serving** floor or successor mechanism scoped to the oldest
stratum only would leave the modal exposure band uncovered, and the
completeness question re-activates in full if the no-sunset retention pin
is ever reopened (parked there, per the authority pin's reversion clause).

*Serving-floor sufficiency (W13).* The floor-on arms measure the
**serving layer**: `swan3_vshape_floor` and `swan3_servo400_floor`
reproduce identical market damage (`shkExt` 37/99, same bands) with
**`shkExF` = 0** — the re-engagement floor covers every wipe-out window,
the hand-off race is never lost. Under the corrected framing this is an
availability result (sole-source windows shortened to zero because the
floor *serves*, not merely retains), and it composes with the L13 ~57 %
gap-reduction sizing rather than superseding the retention guarantee.

*The re-seed bottleneck is the honest cost (swan-4).* With re-seed
bandwidth bound at ~1 flow per foundation seat (`reseed_rate = 3`), the
V-shaped trough costs **~429 shard-epochs** of foundation-only deep
retrieval with a worst single-shard window of **10 epochs**, all windows
closed by run end; the servo-400 window costs **403** shard-epochs
(worst 9, five final-epoch windows still open at the run boundary) and
the market re-seats everything else inside its own 113-epoch
recovery. Provisioning 4× (`reseed_rate = 12`) roughly halves the exposure
**and** cuts the wipe-out count (40 → 10): faster re-seeding closes the
window between holder-set thinning and re-seat before further evictions
empty it. The L10 conclusion transfers: recovery is serialized and
latency-bound through the foundation path (~backlog/rate once demand
returns), so foundation seeding bandwidth is an **availability-SLO sizing
input** (the internal maintenance SLO of `V3_STAKER_ARCHIVAL.md`'s
engineering taxonomy — not a user-facing durability term).

*The export carries a recommendation, not just the measurement:*
**provision seeding capacity at the crisis multiple, ~4× steady-state
flow.** The 40 → 10 result is the actionable number — surge seeding
doesn't just shorten windows, it interrupts the trough cascade before it
propagates. And unlike adaptive `m/n` widening, surge seeding is **not
gameable**: it is the foundation's own provisioning decision, not a
consensus rule an adversary can trigger, so the
`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §3.3 static-margin objection to
predictable adaptivity does not apply. Landed in the authority pin's
internal-redundancy requirement (`V3_STAKER_ARCHIVAL.md`), alongside the
**domain-diversity condition**: during a sole-source window the shard's
availability is the foundation's uptime with effective domain count 1 in
the L15 sense unless the `N_active = 3` seats sit in distinct failure
domains — internal redundancy counts toward the diversity floor only if
they do, otherwise the "degraded" verdicts here are degraded further
than the rows imply.

*Closure observation — the scarcity servo and foundation seeding compose
correctly through the sole-source window.* The foundation is not in
`Market`, so a sole-source shard reads `R_market = 0` — maximal scarcity,
maximal `g`-weighted reward for re-acquisition — at exactly the moment
the foundation is the only source of the bytes. The incentive gradient
and the seeding path point the same direction **by construction**: the
reward formula tells every solvent archiver to acquire precisely the
shards the foundation is seeding, and the binding constraint is
`reseed_rate` — which is exactly what the SLO sizes. That is the system
behaving as designed under its worst measured stress, and it is why the
trough self-heals rather than requiring an intervention path: no
emergency mechanism exists here because none is needed, and a future
reviewer finding the sole-source windows should not re-derive this.

**Finding 5 (swan-2/W2, sharpened swan-3/W14–W15) — correlation, not
magnitude, drives the sole-source tail; class correlation is the honest worst
case.** Stride sampling straddles holder sets by construction (per-shard
total wipe-out ≈ 0 — measured: `shkExt = 0` at 50 %); the same 50 % exit
correlated by index-bucketed failure domain (`swan2_domain2`) wipes out 1,
consistent with the independence analytic ((1/2)⁶ ≈ 1.6 % × ~120 deep
≈ 1.9). But the bucketing is itself uncorrelated with *portfolio
composition*, so 1 is the benign end. The class-correlated arms are the
measured worst case: the top-30 % deep holders exiting wipes out **4** (vs 0
for stride-30 and domain-3 at the same magnitude), and the top-50 % **28**
(vs 0 stride / 1 domain-bucketed) — a **28:1 spread at identical magnitude**,
driven entirely by correlation structure. A class-correlated 30 % outranks
every independently-sampled 50 % in the grid, which is what reversion
criterion (c) encodes.

*Aftershock analytic, pinned (W14).* The aftershock pair wipes out 4 —
banked as **within the independence-to-no-reseat envelope**, not as "matches
the analytic": fully independent sequential culls with full reseat give
(1/2)⁶ × ~120 ≈ 1.9; two culls with *no* reseat give (3/4)⁶ × 120 ≈ 21.
Measured 4 sits between, above the independence floor because the 3-epoch gap
allows only partial reseat (entry is rate-limited at 6/epoch) and the second
stride lands on a stride-thinned population — no longer anti-correlated with
the surviving holder sets. Sequenced shocks multiply the tail because the
second wave lands on holder sets already at minimum.

**Finding 6 (W5, named residue; trigger observable pinned swan-3/W17) — the
honest-holding assumption breaks exactly in the fatal channel, and detection
is open, not solved.** Sim agents either hold bytes or don't. The design's own
8c analysis says that under crisis economics (fiat opex > token rewards) the
individually rational strategy is *keep the bond, drop the bytes,
fetch-on-demand from surviving true holders at challenge time* — L16's
rendezvous latency gives only weak timing discrimination. If many archivers
degrade simultaneously, true replication collapses while challenge-pass
coverage stays green, and the gap is revealed only by the next correlated
failure — at which point Findings 4–5 apply to a replica count far below what
`shkBA` implies. No V3.0 mechanism (the L14 read-credited path and any cheap
local-possession bias in the gate-2 challenge shape both raise the cost of
just-in-time fetching at depth and are already queued); named residue with
reversion trigger (e) below.

*What the trigger actually reads (W17).* Fetch-on-demand is designed to be
indistinguishable at the challenge interface — that was the 8c finding — so
the residue's observability must be stated honestly. **Weak observable:**
challenge-response latency distribution shift (a degrader's response carries
one rendezvous fetch; L16 says the discrimination is poor at depth and worse
under crisis network conditions). **Stronger observable:** correlated *load*
on the surviving true holders at challenge anchors — a degrader cannot answer
without sourcing the bytes from someone who has them, so synchronized
challenge epochs produce read-traffic spikes on the shrinking true-holder set
that scale with the degrader population; the source set's bandwidth is the
side channel the degraders cannot hide. Trigger (e) names both: the latency
read is cheap and continuous, the source-load read is the confirmatory one.
A residue with an unmeasurable trigger is an unmonitored residue —
pre-mainnet this is acceptable; the stressnet campaign (see the m/n pin's
crisis-tail criteria) should exercise the source-load observable under
induced degradation before the verdict hardens.

**Finding 7 (W11) — `swan_regime` is conditioned on the Finding-0
reconciliation.** ρ ×2 from 0.02 lands at 0.04 — between the L11 knee (3 %)
and broken (5 %) on the pre-Curve-repair substrate, "leaner but covered" on
the post-repair one. The absorbed/leaner boundary for the ρ axis sits exactly
where `gate4_fine` vs `l11_bud` disagree; the row's verdict inherits the
matured-windowed-Gini reconciliation (Finding 0) and is re-run with it.

**Disposition.** No new mechanism at V3.0, with the claim **re-anchored on
the retention guarantee** (swan-4): durability of deep history is carried by
the foundation's permanent complete-tree retention
(`V3_STAKER_ARCHIVAL.md` authority pin — retention vs internal redundancy vs
serving participation), so **no shock in this grid loses data**; what the
grid measures is availability. Population shocks (stride or index-bucketed
≤ 1/3, single or knee-timed) are absorbed with zero market wipe-outs;
holder-class-correlated and sequenced exits send single-to-double-digit deep
shards to foundation-as-sole-source while the metric recovers (28 at
class-correlated 50 % — the honest worst case); price-collapse troughs send
tens-to-hundreds, spread across the **whole deep set** (mid-deep modal, not
oldest-concentrated), and the bandwidth-bound re-seed arms size the recovery
honestly: hundreds of shard-epochs of foundation-only deep retrieval, worst
single-shard windows under ~10 epochs, fully re-seeded (Finding 4 / swan-4).
The defenses this layer exercises are already in the design (replication
headroom + free entry; the L13 servo + serving-floor re-engagement carry the
price leg to the limit of fee-market capacity), with three exports: **the
retention guarantee + its single-organization threat model documented with
authority** (the swan-2 "completeness requirement" converted to documenting
an existing guarantee — landed in `V3_STAKER_ARCHIVAL.md`), **foundation
re-seed bandwidth named as an availability-SLO sizing input with a
provisioning recommendation — ~4× steady-state flow, the crisis multiple,
plus the `N_active` domain-diversity condition** (Finding 4 / swan-4 —
internal maintenance SLO, not a user promise; surge seeding is the
foundation's own action and not gameable, so the §3.3 static-margin
objection doesn't apply), and **foundation treasury diversification as a
named operations requirement** (Finding 3 caveat). The residual exposure — a permanent large price collapse with fiat
opex exceeding crisis-time fee capacity — remains an economic-viability
bound on the *market layer*: coverage collapses onto the foundation
backstop, loudly, with chain data intact (the L13 "graceful loud failure"
reading, now with its floor named). Honest holding under crisis economics is
a named residue with both its trigger observables pinned (Finding 6).
Timeframes: addresses **now** and **mining-era end** (the fee-era stress is
where the price leg lives); V4 inherits the mechanism unchanged.

**Reversion clause (rule 21).** Reopen this layer iff (a) a substrate change of
the Curve-repair class lands (re-run `--axis=swan`, table update per the
Finding-0 precedent), (b) calibration or testnet telemetry shows the real
fiat-opex share of archiver costs materially exceeds the model's flow-cost
share (the price leg's bite scales with it), (c) a custody-concentration read
shows a plausible single-event **class- or domain-concentrated exit ≥ ~0.3**
— correlation is the binding variable, not magnitude (Finding 5; a
class-correlated 30 % outranks every independently-sampled 50 % in the grid),
(d) the **no-sunset retention pin is reopened** (foundation-independence
becomes a design goal) — the W12/W13 completeness questions re-activate in
full at that design round (parked against the pin in
`V3_STAKER_ARCHIVAL.md`'s authority-pin reversion clause; the per-band and
serving-floor reads here are the instruments that round inherits), or
measured foundation seeding throughput falls materially below the
`reseed_rate ≈ 3` operating point the swan-4 windows were sized at, or (e)
stressnet/testnet telemetry shows challenge-pass coverage diverging from
sampled true-replication audits under economic stress — read as
challenge-latency distribution shift (weak, continuous) and **source-load
spikes on true holders at challenge anchors** (confirmatory; Finding 6/W17)
— the residue turning live. Re-evaluation shape: re-run the axis against the
changed substrate and update this table; design round only if a
previously-absorbed channel turns fatal or the sole-source exposure grows an
order of magnitude.

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
re-judge: `covered = frac_under<0.05 & min_R≥1`; `spread` = final-epoch snapshot;
`sprdW` = windowed steady-state (`mean gini_actor`, `peak max_actor_share` over
`churn_window` — L9 lesson); thresholds `gini<0.6 & max_share<0.20` (actor-level);
`ALL` uses `sprdW`. `deep = deep_frac_under<0.10`;
`churn_stable = max(oUmx, serving_oUmx)<0.05` (coverage oscillation, not abandonment).

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
  soundness pass — not this sim — owns retention-proof and ledger semantics; gate 3
  counting is ledger-derived (no separate ν primitive).
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

### Gate 4 iteration-2 — fine bond-rate window (2026-06-07)

> **Substrate-drift note (2026-06-11):** the numeric readings below predate the
> banded PL Curve repair (`4071ec032`, ARCHIVAL_CONSENSUS_STATE PR 0) and are
> superseded — re-read under the current substrate in §*Layer-2
> margin-robustness band — results* Finding 0 (`bondA` 79 → ~113; coloc pin row
> oscillates at the bare-lean purse). The **pin disposition (`bond_rate* =
> 0.75`) stands** under the re-read (results Finding 4); the selection logic
> below is unchanged.

**Status: built and run.** Scenarios: `gate4_fine_*` (lean L11 fill, ρ=0.02, `g=2`,
flat magnitude), `gate4_fine_*_whale` (Sybil spread cross), `gate4_coloc_*` (P1
polarized endowment, ρ=0.015). Twenty rates from **0.50–7.50** step 0.25 inside the
coarse `(0.5, 8)` band. Run:

```bash
cd rust && cargo run -p shekyl-staking-sim --release -- --axis=gate4_fine \
  > gate4_fine.json 2> gate4_fine_summary.txt
```

**Pass criteria for the sim pin:** at the lean equilibrium, simultaneously (a) min-form
`dS/dN ≥ 1`, (b) `deep_frac_under < 0.10`, (c) `seating_feasible`, (d) with whale present
**actor-level spread** (`gini_actor < 0.6`, `max_actor_share < 0.20`), and (e) co-location-
binding endowment duplicate passes (a)+(b).

**Findings.**

1. **The window is non-empty but narrow and sits below the coarse “mid” (2.0), not at it.**
   Lean deep coverage holds with ample min-form headroom for `bond_rate ∈ [0.50, 2.00]`
   (`dS/dN` 3.76–5.89, `deep_und = 0`). Deep coverage breaks above **2.25** as the
   emergent archiver count thins (`bondA` 79→48).

2. **The binding upper bound is whale spread (actor Gini), not min-form seating.** From
   **1.00** upward, `gate4_fine_*_whale` fails spread (`gini_actor` 0.61–0.82) even while
   min-form stays ≫1 on the no-whale lean runs. At **0.75**, whale spread passes
   (`gini_actor ≈ 0.58`, `max_actor_share ≈ 0.011`); at **1.00** it fails.

3. **Co-location-binding duplicate confirms the low band.** Under polarized endowment
   (P1), `dS/dN ≥ 1` with `deep_und = 0` holds through **2.00**; deep starves from **2.25**
   (`deep_und` 0.08–1.0). The triple intersection (lean + whale spread + coloc) is
   **`{0.50, 0.75}` only**.

4. **Sim pin (dimensionless `bond_rate*`): `0.75`.** Highest rate in the feasible triple
   intersection — maximizes Sybil headroom within the live band. **Not 2.0:** `bond_rate=2.0`
   is `baseline()` default and yields `giniW ≈ 0.71` at budget 100 (`l11_bud_b100` /
   `gate4_fine_2.00`) — a **different bond**, not a conflicting attractor family. At pin
   `0.75`, spread passes with hair margin; atomic mapping lands at **`750_000_000` atomic
   (0.75 SKL)** per `FOUNDATION_GENESIS_IDENTITY_SET.md` §9.3.

5. **Windowed spread (`sprdW`, 2026-06-07).** At `bond_rate* = 0.75`: `gate4_fine_0.75`
   `giniW ≈ 0.593`; whale `≈ 0.594`; coloc `≈ 0.599` — all pass `sprdW`.

6. **`churn_stable` metric bank (F2, 2026-06-07).** The sub-claim names coverage
   oscillation (line 275) but the code had `churn_stable = churn < 0.05` (participation
   abandonment). At pin, `oUmx = 0` and `deep_und = 0` while participation churn ≈ 0.17 —
   benign rotation with backfill slack (L9/L11 bank when `oUmx = 0`). Same artifact class
   as the L9 final-epoch read and bond-0.75 spread graze. **Disposition:** re-pointed to
   `max(oUmx, serving_oUmx) < 0.05`; pin rows (`gate4_fine_0.75`, whale, coloc) pass
   `all_pass`. **Conditionality:** benign rotation only while backfill capacity exists —
   at capacity bind (`lagbind` churn, serving `deep_und` 0.942→0.865) abandonment
   co-occurs with coverage fail. Do not price participation churn down; it is the attractor
   doing its job.

| `bond_rate` | lean `dS/dN` / `deep_und` | whale spread | coloc `dS/dN` / `deep_und` | in band |
|---:|---|---|---|:---:|
| 0.50 | 5.89 / 0.000 | pass | 3.43 / 0.000 | ✓ |
| 0.75 | 5.89 / 0.000 | pass | 2.37 / 0.000 | **pin** |
| 1.00 | 5.53 / 0.000 | **fail** (gini 0.61) | 2.01 / 0.000 | |
| 2.00 | 3.76 / 0.000 | fail | 1.31 / 0.067 | lean only |
| 2.25 | 3.41 / 0.592 | fail | 1.13 / 0.083 | |
| 7.50 | 2.35 / 1.000 | fail | 0.77 / 1.000 | |

**Disposition:** gate-4 iteration-2 **closes the numeric sim pin** at `bond_rate* = 0.75`.
Reopen only if the spread threshold, whale endowment, or mainnet joint storage×capital
calibration shifts the triple intersection.

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

**Disposition (maintainer, 2026-06-11): age-scaled-constant, taken.** The genesis pin is the
sim-exercised plateau arm — `BOND_DURATION_BASE_EPOCHS = 4`, `BOND_DURATION_AGE_SCALE = 4`,
i.e. `bond_duration(age) = 4 · (1 + 4·age)` settlement epochs over normalized shard age
`age ∈ [0,1]` (youngest deep shard ≈ 4 epochs / ~8 weeks; oldest ≈ 20 epochs / ~9 months at
120 s blocks). Why this arm and not another point in the band:

- **Shape:** flat-constant forgoes a demonstrated net-positive mechanism (H1/H3); the servo's
  affirmative case is removed by H2's plateau (no fine level to tune toward) and it buys a
  governance/manipulation surface (`75-system-autonomy.mdc`). Age-scaled-constant is what's left.
- **Scale = 4:** the H2 plateau point (`d4 ≡ d8` to three decimals) — full benefit capture with
  zero marginal cost vs. `d2` beyond a committed-`cDeepU` delta (0.008→0.011) inside noise, and
  clear of the `d1` low-scale sOUmx non-monotonicity. "Safe-side" resolves to the *low edge of
  the saturated plateau*, not below it.
- **Base = 4:** the value the L9/L10 scenario grid actually exercised (`bond_dur_base = 4.0`);
  no sim evidence distinguishes nearby bases, and inventing an unexercised number would decouple
  the pin from its evidence.

**Reversion clause (per `21-reversion-clause-discipline.mdc`):** the *shape* (age-scaled-constant)
reopens only on testnet evidence that measured `fetch_latency_per_unit` places the network outside
the survivable band (`≥ L6`-equivalent, where H1 shows nothing helps) — re-evaluation is a fresh
L10-grid run at measured latency plus a maintainer round. The *numeric pair* (base 4, scale 4) is
**provisional until the testnet backfill-lag measurement** and is re-confirmed or re-pinned at
that point via the `ARCHIVAL_TIMING_CONSTANTS.md` cluster process (sim-backed sweep at measured
`fetch_latency_per_unit`); drift within the H2 plateau band (scale ∈ [2,8]) is a constants-table
amendment, not a design reopen.

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
6. **Bond lifecycle.** Slashing conditions (a failed challenge?), graceful-exit return —
   **spec'd:** [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §4.3 `Unbond` + release
   cooldown vs `W` backlog; sim still unmodeled,
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
(bonded-archiver count ≈79, deep covered). *(Substrate note, 2026-06-11: the banded PL
Curve repair thickened the attractor to ≈113 at the same ρ — counts in this section are
the pre-repair record; the attractor/lever/transfer properties re-confirmed at the new
equilibrium. §Layer-2 results, Finding 0.)*

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

## L14×L15 — proof-of-archival in harmony with retrieval (specification)

*Specification first, code second (`05-system-thinking.mdc`). This section is the design
the L14 (proof-of-archival / free-rider) and L15 (retrieval / correlated-failure) sim
layers implement; the sim mechanics fall out of it, not the reverse.*

**The unifying observation.** Two questions have been treated separately: *is the replica
there?* (L14 — proof-of-archival, the free-rider gate) and *can the data be fetched within
latency?* (L15 — retrieval availability). They are the **same question answered by the same
wire operation**: a successful, content-bound retrieval of shard `S` from holder `H`
*proves* `H` holds `S` and *delivers* `S`. So **real read traffic is the proof of archival,
wherever it exists** — and explicit oversight challenges are needed only where reads do
*not* exist. That set is precisely the **cold deep tail**: the oldest, least-recently-fetched,
most-irreplaceable shards (the same band P3 flags and that L13 finding 2 shows failing first).
The design goal — *minimize non-productive (oversight-only) traffic* — therefore reduces to:
**make the productive read path double as the proof path, and confine explicit challenges to
the unread tail, sampled, aggregated, and credited against real reads.**

**The mechanism, in six parts.**

1. **Retrieval-as-proof (the productive path, zero marginal oversight cost).** Every served
   read is a signed, **content-bound receipt**: `H` returns the requested byte-range *plus*
   a Merkle opening of that range against `S`'s public commitment, so the response cannot be
   produced without the bytes. The receipt `(H, S, height, range)` is the proof-of-service.
   For hot/warm shards (frequently read), natural read traffic produces enough receipts that
   **no separate challenge is ever issued** — oversight cost is zero, paid entirely by
   productive traffic.

2. **Challenge-as-fallback (the oversight path, confined to cold shards).** A shard that
   accrued too few receipts this epoch (the cold tail) is **spot-checked**: a verifier asks
   `H` to open a *random* byte-range of `S` under a per-epoch public beacon seed — a
   proof-of-retrievability (PoR) challenge. This is the **only** non-productive traffic, and
   it exists only for shards real users are not currently reading.

3. **Challenge ≡ retrieval (the L14↔L15 unification).** A challenge is just a retrieval the
   network performs *against itself* for oversight: same wire operation, differing only in
   *who initiates* (a verifier vs. a user) and *whether the payload is consumed*. Therefore
   **the cold-shard challenge cadence (L14) and the retrieval-availability SLA (L15) are one
   knob** — set the challenge rate for a band to the retrieval availability you want to
   *guarantee* for it, and the same read-path latency budget bounds both
   (challengeable-within-latency ⟺ retrievable-within-latency). This is why L14 and L15 are
   specified together: the challenge *is* the availability probe.

4. **Minimizing the oversight traffic (the three reducers).** Non-productive traffic =
   challenges on under-read shards, driven to its floor by: **(a) credit** — a shard a real
   user read this epoch needs no challenge (its receipt already proved it); **(b) sample** —
   challenge a *random subset* of the cold tail per epoch, sized to bound the *expected time
   to detect* a vanished replica below the band's risk tolerance, so the oldest /
   most-irreplaceable band is challenged *more often* (the age-stratification of P3, now on
   the oversight cadence); **(c) aggregate** — one batched Merkle multiproof (or vector-
   commitment opening) covers many shards a holder claims at once, so per-shard oversight
   cost *falls* as a holder's claimed set grows.

5. **Free-rider economics (L14 proper).** Two free-rider variants, both closed: *store-but-
   refuse-to-serve* is defeated **directly** by retrieval-as-proof (no receipts ⇒ no reward);
   *claim-without-storing* is defeated by the **unforgeable content-bound opening** (you
   cannot answer a random-index challenge without the bytes). The **bond** (L2/L8) is the
   *capital* cost that makes Sybil-spraying claims expensive; the **challenge-rate × penalty**
   is the *operational* expected cost that makes faking unprofitable. The sim's L14 question
   is the cadence: find the cold-shard challenge rate `c` at which
   `E[fake payoff] = (1−p_detect)·reward + storage_saved − p_detect·penalty < E[honest]`,
   where `p_detect ≈ c` per epoch (per cold shard) and `penalty` is the slashed bond. Because
   hot shards self-prove from reads, `c` applies *only* to the cold tail, so oversight traffic
   `∝ c · (cold-shard count)` — minimized subject to `E[fake] < 0` **and** the L15 SLA.

6. **Privacy harmony (mission priority 2).** Retrieval-as-proof must prove **supply, never
   demand.** A receipt binds `(pseudonym P, shard S, height)` — that `P` *serves* `S` is
   already public (`P` posted a bond on `S`). It must **not** reveal *who requested* the read:
   the fetcher's query privacy is preserved by the onion path (L16), and the receipt is a
   *holder-side* artifact the requester is unlinkable to. Challenges are issued to a
   *pseudonym*, not a principal. So the oversight traffic is privacy-clean: it measures that
   `P` holds `S`, never that anyone *wants* `S`. The L15 **diversity axis** (jurisdiction /
   ASN / implementation, to make correlated loss visible) is the one place this tension bites
   — diversity must be measured in coarse, privacy-compatible buckets, never per-holder
   geolocation.

**Net design.** *Productive reads are the proof wherever they exist; explicit challenges are
cover traffic confined to the unread cold tail — sampled, aggregated, credited against real
reads, and rate-set by the band's irreplaceability (P3) and its retrieval-availability SLA
(L15).* Non-productive (oversight-only) traffic is thereby reduced to exactly the
least-active, most-irreplaceable shards, at the lowest cadence that keeps faking unprofitable
and the retrieval SLA met. This is the spec the L14/L15 sim layers test: L15 derives
`R_target` from a retrieval-availability target under per-holder uptime *and correlated
failure* (the L4 survival arithmetic assumed independence); L14 finds the challenge cadence
that makes free-riding unprofitable *given* that hot shards self-prove, so the cadence — the
non-productive traffic — lands only on the cold tail.

### L14 — proof-of-archival: oversight traffic collapses onto the cold tail

L14 quantifies the §*L14×L15 specification*'s central lever — **a content-bound retrieval is
a proof of possession** — against the user's question: how does shard-holding validation work
*in harmony with* retrieval so that non-productive (oversight-only) traffic is minimized? The
model (`src/audit.rs`, gated by `audit_model`, legacy byte-identical) is the free-rider's
decision: claim a shard (collect reward) without storing it (save the flow cost `benefit`), at
the risk of being audited and slashed (`penalty`). The free-rider abstains iff the per-epoch
caught-probability `a ≥ a* = benefit/penalty`. Two audit policies reach `a*`:

- **Naive:** challenge *every* shard at rate `a*`, ignoring reads. Oversight traffic `= a*` per
  shard, uniform — the entire chain is policed at the deterrence rate forever.
- **Read-credited:** a real read already audits with probability `p_read(age)` (recency-decaying
  — hot shards read often, the oldest approach a cold floor). An explicit challenge then only
  has to top the total up to `a*`: `c = max(0, (a* − p_read)/(1 − p_read))`. Hot shards with
  `p_read ≥ a*` need **zero** challenge.

All scenarios run on the healthy covered substrate (`l14_*` over the L11 attractor), so the
age distribution spans hot→deep and the read curve sorts oversight by age.

**Finding 1 — read-credit confines oversight to the cold tail.** At `a*=0.1` (`l14_credited`):

| policy | mean per-shard cadence | deep share of oversight | oldest-band cadence |
|---|---|---|---|
| naive (`auN`) | 0.100 | — | 0.100 |
| read-credited (`auC`) | 0.035 | 0.98 (`auDp`) | 0.090 (`auOld`) |

Crediting real reads cuts the mean challenge cadence **~65%**, and **98% of what remains lands
on deep shards** — hot shards are proven for free by their own reads. The non-productive
traffic is reduced to exactly the least-active shards, rising toward the oldest (`auOld 0.090`)
— the same P3 tail that is thinnest in coverage and diversity.

**Finding 2 — the slash is the primary deterrent; challenges are the top-up.** Sweeping the
penalty (`l14_penalty_*`) drops the deterrence threshold `a* = benefit/penalty` and with it the
oversight traffic:

| penalty (slash) | `a*` (`auN`) | credited cadence `auC` | deep share `auDp` |
|---|---|---|---|
| 0.5 | 0.200 | 0.106 | 0.81 |
| 1.0 | 0.100 | 0.035 | 0.98 |
| 2.0 | 0.050 | 0.010 | 1.00 |
| 4.0 | 0.025 | 0.002 | 1.00 |

A credible slash, not a high challenge cadence, is what makes free-riding unprofitable cheaply
— the bond/penalty carries the deterrence and the challenge rate is only the residual top-up.

**Finding 3 — demand self-polices the tail.** Raising the cold-tail read floor toward `a*`
(`l14_read_*`) shrinks the oldest-band cadence to zero: `auOld` 0.090 / 0.090 / 0.053 / 0.000
at a read floor of 0.001 / 0.01 / 0.05 / 0.1. When even the oldest shards are read as often as
`a*`, reads alone deter and explicit challenges vanish entirely. The non-productive traffic is
bounded by *demand* on the cold tail — popular history is self-policing; only the genuinely
unread deep shards ever carry oversight.

**Disposition.** Gate-4's free-rider gate is **retrieval-credited proof-of-retrievability**:
real reads are the proof wherever they occur; explicit challenges are cover traffic confined
to the unread cold tail, sampled/aggregated and rate-set by the band's irreplaceability (P3)
and its retrieval SLA (L15); deterrence is carried by a **credible slash**, with the challenge
cadence only topping the read-audit up to `a*`. **Residue:** the live read-rate distribution,
the real `benefit/penalty` ratio, and the **challenge-faking cost** (whether a free-rider can
fetch-on-demand to answer a challenge it can't otherwise serve — this sets the floor cadence
that a pure read-credit cannot go below) are post-testnet / gate-7 empirics. L14 fixes the
*shape* — oversight ∝ unread-tail, slash-primary, challenge-top-up — not the live cadence.

### L14b — failure-confirmation scheduling (design pin; sim-gated)

**Pin:** [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](../completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md).

After a baseline epoch challenge **miss**, consensus may escalate scrutiny with a **recheck
window** `[start, start+w]` — `start` from the **assumed residual-life** quantile `p`
(false-slash knob), `w` the spread width (gaming / dodge-cost knob). Not a single deterministic
delay: false-slash wants late recheck; gaming wants spread. Nominal `false_slash ≈ 1−p` is
exact only for exponential (memoryless); fat-tailed true outages inflate realized false-slash
when start is sized from the wrong law — Round-1 reports **tail misspecification gap**.

**Enforcement claim:** policy certifies **not-durably-absent**, not a reachability SLA. The
quantitative form is **`P(slash)` vs honest `u`** (u-sweep in report), not a single operating
point at `u_eff ≈ 0.634`. Steady-state `u_eff` does not pin tail shape; stressnet needs the
**outage-duration CDF**.

**Decision gate (ordered):** (1) pin **`b_min`** (gaming floor on baseline + `w`); (2)
**binding check** — analytical `N_market × shards_per_P × rate × vin / SEB` (per-P sim cannot
settle absolute volume); slash-latency likely non-binding under the durability floor; (3) only
if binding: relative `volR` escalate vs sliding-window. If volume and latency do not bind, FSM
is unjustified regardless of adaptivity.

**Round-1 harness (revised).** `rust/shekyl-staking-sim/src/failure_confirmation.rs` — per-`P`
epoch micro-sim; exponential + lognormal tail-misspec scenarios. JSON report: `binding`,
`u_sweep`, `scenarios`. Run:

```bash
cargo run -p shekyl-staking-sim --release -- --failure-confirmation
cargo run -p shekyl-staking-sim --release -- --failure-confirmation --axis=l14b_confirm_tail
```

Scenarios: `l14b_confirm_default`, `l14b_confirm_quantile_*`,
`l14b_confirm_tail_assumed_exp_true_lognormal`, `l14b_confirm_width_*`,
`l14b_confirm_window_*`, `l14b_confirm_gaming_thin`. **Round-1 outcome (pinned):** sliding-window **m-of-n** (`m=11,n=13` provisional at L16
exponential — **Round-2** stressnet CDF gates final `m`). Escalation **rejected** (§5 of pin
doc — audit stratum only): dodge 0/1, `volR≈1.7`, tuned transient fs 0.002 vs 0.025.
`R_market` is **serve-credit-weighted** (consensus §3.3) — slow slash does not pollute
scarcity at E-close; Round-2 must confirm no slot-weighted path. Fat-tail may force higher
`m`; joint feasibility with bond-resolution latency is the Round-2 gate. Report:
`policy_pin`, `sliding_m_sweep`, `dEsc`/`dSl`, `baseline_timing`.

### L15 — retrieval availability: coverage ≠ retrieval, and `R_target` is derivable

L15 is the first layer that scores the property users actually need — *retrieval* (≥1 holder
reachable at a target availability `A*`) — rather than *coverage* (`R ≥ R_target`, replicas
merely exist). The model (`src/retrieval.rs`, gated by `retrieval_model`, legacy
byte-identical) adds two facts the coverage score ignored:

- **Per-holder uptime `u`.** A holder is not always serving (downtime, churn, the slow onion
  path of L16). One replica delivers `u`, not `1`; redundancy is what converts `u` into `A*`.
- **Correlated failure.** The L4 survival arithmetic (`N=3, p=0.99 ⇒ 1−10⁻⁶`) assumed
  *independent* holder failure. Real holders share **failure domains** — jurisdiction, ASN,
  client implementation — and a domain fails as a unit. A shard's effective redundancy is its
  count of **distinct domains** `d`, not its raw replica count `R`. Availability
  `= 1 − (1−u)^d`; extra replicas inside an already-covered domain add nothing.

Both findings run on the **healthy L11 attractor at a low ρ** — a *fully covered* deep set
(`deep_und=0`, `R≈6`) — so what they surface is not a coverage shortfall but a property the
coverage score is blind to.

**Finding 1 — coverage ≠ retrieval; diversity is the binding constraint.** Under independent
failure (`l15_indep`, each holder its own domain ⇒ `d=R`), the covered set clears a three-nines
SLA: `rAvl=1.0`, `rUDp=0`. Bucketing the *same* holders into fewer domains (`l15_corr_*`,
`R` unchanged):

| domains `d` | deep-set mean availability `rAvl` | deep frac under SLA `rUDp` |
|---|---|---|
| 6 | 0.9997 | 0.007 |
| 3 | 0.9967 | 0.202 |
| 2 | 0.9884 | 1.000 |
| 1 | 0.9000 | 1.000 |

The deep set is fully covered at every row (`deep_und=0`); availability collapses purely from
domain clustering. **Diversity (≥3 distinct domains per deep shard at `u=0.9, A*=0.999`), not
replica count, is the binding retrieval constraint** — a covered-but-clustered set is a latent
availability failure that the L1–L13 coverage metric reports as healthy.

**Finding 2 — `R_target` is derivable from the SLA, not stipulated.** Inverting the
availability formula, `R_target = ⌈ln(1−A*)/ln(1−u)⌉` (`l15_uptime_*`, independent domains):

| holder uptime `u` | derived deep `R_target` (`rTgtA`) |
|---|---|
| 0.95 | 2 |
| 0.90 | 3 |
| 0.80 | 5 |
| 0.50 | 10 |

The stipulated `r_target_deep = 6` silently assumes `u ≳ 0.85`. Below that the covered set is
**under-redundant for the SLA even under independent failure** (`u50`: `rUDp=1.0` despite
`R≈6`). So `R_target` should be *read off* the stated SLA `(u, A*)` rather than asserted as a
constant.

**Sim note (soundness pass).** The `A*=0.999` three-nines bar used here is a **stress probe**,
not the ratified service SLA — see §*Soundness pass* step 0. The spec's reward basis is
retention, not instantaneous retrieval (`V3_STAKER_ARCHIVAL.md` §*The reward curve*); L15
findings are **conditional on which SLA is pinned** for each retrieval class.

**Disposition.** Gate-4/5 must (a) state the retrieval SLA `(u, A*)` and derive `R_target`
from it (the L16 onion path depresses `u`, which raises the derived `R_target` — the two
layers compose), and (b) add a **diversity floor co-located with the coverage floor**: a deep
shard needs ≥`d*` distinct domains *and* `R ≥ R_target`, the latter being insufficient alone.
This **reinforces P3** — the oldest band, thinnest in both replica count and (therefore) domain
spread, is the first to fall under the diversity floor, exactly as it is first under the
coverage floor at both temporal ends. **Privacy tension (mission priority 2):** the diversity
axis must be measured in coarse, deterministic buckets (the model's `a % n_domains`), never
per-holder geolocation — a diversity metric that leaks holder location defeats the
firewalled-pseudonym requirement it exists to protect. **Residue:** live `u`, the SLA `A*`, and
the real domain-correlation structure are post-testnet empirics; L15 fixes the *shape*
(coverage≠retrieval, derived-`R_target`, diversity-floor), not the live values. L15 is the
serving/diversity substrate L14's challenge cadence rides on.

### L16 — transport-regime coupling depresses retrieval uptime

L16 closes the iteration-3 arc by wiring the L10 latency axis to L15 through a transport
model (`src/transport.rs`, gated by `transport_model`, legacy byte-identical). The
firewalled-pseudonym requirement forces the heavy archival fetch onto onion rendezvous, so
`fetch_latency_per_unit` is not a free stress knob — it is **where on the `L0–L6` band the
live transport sits** (§*Transport coupling*). L10 scored seating/backfill lag on that band;
L16 scores **retrieval uptime**: a holder that is network-up still delivers fewer successful
serves within an outage window when every read traverses rendezvous hops. Model:
`u_eff = u_base / (1 + k·L)` with representative deep latency
`L = fetch_latency(true, deep_shard_size, fetch_latency_per_unit)`; at `L=0` (hypothetical
clearnet baseline) `u_eff = u_base`.

Scenarios run on the L11 attractor with `retrieval_model` on, independent failure domains
(`retr_n_domains = 0`), `u_base = 0.9`, `k = 0.07`, `A* = 0.999`, and a fully covered deep
set (`deep_und = 0`, `R ≈ 6`) — isolating transport from coverage shortfall and from L15's
correlated-failure bucketing.

**Finding 1 — transport depression alone can break the retrieval SLA on a covered set.** Regime
sweep (`l16_regime_L*`):

| regime `L` | transport `u_eff` (`trU`) | derived `R_target` (`rTgtA`) | deep frac under SLA (`rUDp`) |
|---|---|---|---|
| 0 (baseline) | 0.900 | 3 | 0.000 |
| 1 | 0.841 | 4 | 1.000 |
| 2 | 0.789 | 5 | 1.000 |
| 3 | 0.744 | 6 | 1.000 |
| 4 | 0.703 | 6 | 1.000 |
| 6 (band ceiling) | 0.634 | 7 | 1.000 |

At `L=0` the covered set clears three-nines under independence (`rUDp=0`). Each step up the
onion band depresses `u_eff` monotonically and raises the **derived** `R_target`; from `L≥1`
the stipulated `R≈6` is under-redundant for the SLA **even though `deep_und=0`**. So the
post-testnet "where on the band?" question is load-bearing for retrieval, not only for L10's
seating oscillation — the same rendezvous path that makes deep fetch slow also makes per-holder
uptime the binding input to `R_target`.

**Finding 2 — duration backstop does not repair depressed `u`.** At the band ceiling (`l16_L6_s0`
vs `l16_L6_s4`, age-scaled duration 0 vs 4): identical `trU`, `rTgtA`, `rUDp`. L10's duration
win addresses **seating/backfill timing** on committed replication; it does not raise the
successful-serve rate under onion rendezvous. The two layers are orthogonal.

**Finding 3 — replica floor adds `R`, not `u`.** `l16_L6_floor` (`floor_replicas=6`) matches
`l16_regime_L6` on every retrieval column. The foundation floor is a **capacity** backstop (P4);
it cannot substitute for transport-depressed uptime. At saturation, the SLA can fail with the
floor on — capacity without serve-rate is the P4 / soundness-pass separation made concrete.

**Finding 4 — transport and diversity compose multiplicatively.** `l16_L4_d3` (operating point
`L=4`, `d=3` domains): `rUDp=1.0` vs L15's `l15_corr_d3` at `u=0.9` (`rUDp=0.202`). Transport
depression lowers `u_eff` to 0.703, which both raises `R_target` and steepens the
`1−(1−u)^d` curve — the architecture-tension preview (diversity needed for three-nines, but
location hidden) is **worse** once onion latency is in the SLA denominator.

**Disposition.** Gate 6 / transport work must treat the rendezvous latency as an input to the
retrieval SLA `(u, A*)`, not a separate networking concern: calibrate `L` post-testnet, derive
`R_target` from depressed `u_eff`, and size redundancy against **both** transport and diversity.
The L10 band remains the operating regime by construction; L16 fixes the **coupling shape**
(`u_eff` monotone in `L`, composes with L15), not live `k` or the band position. Residue:
post-testnet measurement of `L`, `k`, and any bandwidth-buying relaxation that does not link
`P` (the lever that moves along the band per §*Transport coupling*).

**Iteration-3 headline (L16).** The onion path depresses retrieval uptime, not just seating lag:
a covered deep set fails its SLA from transport alone above `L=0`, derived `R_target` rises
3→7 across the band, and neither duration backstop nor replica floor repairs depressed `u` —
transport is a first-class retrieval input compositing with L15 diversity.

## T-A1 / T-A2 — F1 re-linkage instrument (PHASE_2B §7.7 gate)

**Status: BUILT, v2 RE-POINTED, RUN (2026-06-07).** Crate module
`rust/shekyl-staking-sim/src/fingerprint.rs`; axes `ta1_f1` and `ta1_cohort`
(`cargo run -p shekyl-staking-sim --release -- --axis=ta1_f1`).

**Metric re-point (v1 → v2).** The v1 instrument scored absolute timeline Hamming
(`mean_pairwise_distance ≥ 0.10`, `lapse_relink ≤ 0.55`). At the lean equilibrium those
thresholds confound **homogeneous serving** (everyone serves every epoch on their seated
shards) with **fingerprinting**. v2 splits two channels:

| Channel | Metric | Meaning | Pass threshold |
|---------|--------|---------|----------------|
| **Timeline (diagnostic)** | `mean_independent_similarity` | `1 − mean_pairwise_distance` between distinct `P` on the same shard | ≥ 0.90 (homogeneous ⇒ non-fingerprint) |
| | `lapse_relink_similarity` | Pre-lapse `P₀` vs post-rotation `P₁` (`1 − Hamming`) | ≤ baseline (no rotation advantage) |
| | `lapse_vs_baseline_advantage` | `baseline − lapse_relink` | > 0 ⇒ rotation *harder* to link than a random other archiver |
| **Cohort (F1 gate)** | `mean_portfolio_cohort_size` | Mean `\|{P' : portfolio(P') = portfolio(P)}\|` over seated deep actor-epochs | ≥ 2.0 |
| | `singleton_portfolio_fraction` | Fraction of seated deep actor-epochs in a size-1 cohort | ≤ 0.10 |
| **E-4 control** | `cosmetic_overlap` | Pre/post overlap when cosmetic relink is forced | ≥ 0.70 (documents failure) |

Portfolio = the set of deep shards an actor is **held + seated** on at settlement close.
Cohort size = count of actors with the **exact same** portfolio that epoch.

**Scenario pin (hygiene default).** `gate4_fine` lean stack (`bond_rate=0.75`, `g=2`, endogenous
L11 at ρ≈0.02, L10 `fetch_latency_per_unit=2`, age-scaled duration 2/2, L16 transport,
`dynamic` frontier churn, 800 sim epochs × 2000 blocks/epoch ⇒ 160 settlement epochs).
Lapse window on actor 0 at settlement epoch 30 for 15 epochs; hygiene row rotates to actor 1
post-lapse (`ta1_rotation_actor`).

**v2 run (2026-06-07) — timeline axis (`ta1_f1`).**

| Scenario | nE | baseline | lapse | advantage | cohort | singleton | F1 |
|----------|-----|----------|-------|-----------|--------|-----------|-----|
| `ta1_f1_hygiene` | 160 | 0.959 | 0.928 | +0.031 | 1.0 | 0.982 | **FAIL** |
| `ta1_f1_no_hygiene` | 160 | 0.998 | 0.000 | +0.998 | 1.1 | 0.948 | FAIL |
| `ta1_f1_cosmetic` | 160 | 0.959 | 0.881 | +0.078 | 1.0 | 0.982 | FAIL |
| `ta1_f1_seb_coarse` (SEB=20_000) | 80 | 0.949 | 0.939 | +0.010 | 1.0 | 0.981 | FAIL |

**v2 run — cohort sweep (`ta1_cohort`).**

| Scenario | cohort | singleton | distinctive ctrl | F1 |
|----------|--------|-----------|-------------------|-----|
| `ta1_cohort_lean` | 1.0 | 0.982 | — | FAIL |
| `ta1_cohort_distinctive` (pin actor 0 → shards `{7,53,211}`) | 1.0 | 0.978 | PASS (singleton ≥ 0.50) | PASS* |
| `ta1_cohort_shared` (pin actors 0–109 → shards `{0..9}`) | **92.6** | **0.075** | — | **PASS** |

\*Distinctive row passes the **negative-control** claim (`distinctive_identifiable`), not the
lean F1 gate (`cohort_adequate`).

**Shared-portfolio positive control (2026-06-07).** Forcing 110 actors onto the identical
10-shard deep set raises mean cohort **1.0 → 92.6** and cuts singleton fraction **0.982 → 0.075**
— the cohort instrument responds correctly. F1 cohort gate **passes** on this row. The forced
homogeneity is **not** an equilibrium outcome: `deep_und` rises to 0.973 and churn spikes
(coverage collateral). **Mechanism:** scarcity pricing rewards under-replicated shards → archivers
diversify into different deep holdings → unique portfolios at lean eq. Coverage and
rotation-anonymity sit at **opposite** portfolio distributions; the attractor sits at the
spread/unique end because the reward pays for it. F1-FAIL-on-cohort is the **privacy shadow of
coverage working correctly**, not a metric bug.

**Headline (revised).** F1 **does not clear** final accept, but **not** because rotation is
futile:

1. **Timeline channel is empty (reassuring).** Independent operators' timelines are ~96%
   identical at lean equilibrium (`baseline 0.959`). Rotation `P₀→P₁` is *less* similar
   (`0.928`) than a random other archiver — timeline similarity has **no discriminating
   power** for re-linkage here. Homogeneous serving is protective, not a fingerprint.
2. **Cohort channel fails (binding).** Mean portfolio cohort size is **1.0** and singleton
   fraction **~98%** — at this equilibrium every seated deep archiver has a **combinatorially
   unique** shard-set portfolio even while retention timelines homogenize. Re-linkage across
   rotation is bounded by portfolio co-holder cohort, and the sim's lean attractor does **not**
   produce large shared portfolios.
3. **SEB is not the F1 lever.** `ta1_f1_seb_coarse` (SEB=20_000) barely moves timeline metrics
   (`advantage +0.010` vs `+0.031`); cohort unchanged. SEB stays emission-cadence / UX only.
4. **Cosmetic E-4** — `ta1_f1_cosmetic` still confirms relink (`overlap 0.957 ≥ 0.70`).
5. **Distinctive negative control is inconclusive** — pinning a rare triple does not raise
   singleton rate above the already-singleton lean baseline (everyone is already singleton).
6. **Shared-portfolio positive control passes** — `ta1_cohort_shared` confirms the cohort
   metric and gate work; lean failure is an **emergent portfolio-diversity** property, not
   instrument mis-pointing.

**Disposition.** Cohort instrumentation **closed**. F1 = gate-3 Form-C holdings publicity
through rotation. Qual firewall wargame **complete** — **conditionally finally accepted**
(T-A3/T-A5/T-A7 pass; T-A4/T-A6 pending pins; Form-C reopen not triggered). See
[`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9 and ledger **T-A1**.

## Soundness pass — ordering, SLA pin, and deferred conditions

The iteration-3 sim validates **retention/durability economics** (L1–L13, shapes settled)
**conditional** on the security and architecture pins below. L14–L16 scored retrieval using a
**provisional CDN-style bar** (`A*=0.999`, low-latency instantaneous availability) as a stress
probe — not because that bar is the service promise. The soundness pass **starts upstream of
L15**: pin what the service owes per retrieval class, then decide whether L15's
diversity-under-privacy tension is a load-bearing wall or an artifact of the wrong SLA.

### Architectural decomposition (L16 orthogonality)

L16's identity checks (`l16_L6_s0` ≡ `l16_L6_s4`; `l16_L6_floor` ≡ `l16_L6`) prove:

- **Coverage** (`deep_und`, `R`, foundation floor) and **retrieval uptime** (`u_eff`, `rUDp`)
  live in **different layers** — coverage can be perfect while retrieval fails totally.
- **No staking-economics lever moves serve-rate under rendezvous** — duration deters voluntary
  drops (L10 seating timing); replica floor adds capacity (P4); neither raises `u_eff`.
- The **instantaneous retrieval SLA is not a staking-economics problem** — it is
  **transport-layer + SLA-definition** work.

| Layer | Scope | Status |
|---|---|---|
| Retention / durability economics | L1–L13 (+ P1–P4) | Shapes settled |
| Retrieval SLA definition | Per-class service promise | **Step 0 — pinned** (`V3_STAKER_ARCHIVAL.md` §*Service promise*) |
| Retrieval under pinned SLA | L15 re-run + L16 transport | Step 1 closed (L15d/L16d); step 2 reduced scope |
| Contained crypto / counting | L14 crediting, archival read contract, firewall | Step 3 — [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) |
| Genesis lifecycle pins | Key rotation, `market_R`/`durability_count`, legal disclosure | **Pre-genesis — see spec §*Service promise*** |

### Step 0 — pin the SLA per retrieval class (before L15)

**Status: pinned** in `docs/V3_STAKER_ARCHIVAL.md` §*Service promise — genesis-pinned
commitments* (2026-06). Summary:

- **User promise:** permanent retention (hard) + best-effort latency (soft, unbounded);
  auditable foundation complete-tree; not CDN availability.
- **Engineering only:** archiver seeding/backfill SLO — not user-facing.
- **Durability anchor:** foundation managed-N complete archive (public number), market
  additive — not market `D*=0.999`.
- **Foundation:** permanent complete-tree seeds; **no decaying L12 floor**; fully
  outside reward formula; genesis-enumerated identity set; **`market_R` ≠
  `durability_count`** enumerated per consumer.
- **Step 1 (L15d/L16d)** validated: historical class passes on covered set; L15 wall
  localizes to seeding/instantaneous path.

**Remaining pre-genesis (lifecycle, not soundness):** counsel review of
`docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`; operational provisioning
of over-enumerated identity set and reserve custody.

**Closed (2026-06):** key rotation → pure over-enumeration (reversion: per-root
subkey only; never cross-authorizing master); foundation bond default → none
(full uniform per-shard only if policy posts bonds).

### Soundness pass ordering

| Step | Work |
|---|---|
| **0** | Pin SLA per retrieval class; justify or retire three-nines-instantaneous globally |
| **1** | Re-run L15/L16 under pinned SLA — durability metrics vs bounded seeding latency |
| **2** | Seeding-path transport relaxation (contained firewall pass) |
| **3** | L14 per-holder crediting; archival read contract (derived `R_market`); firewall crypto |

### Step 1 result — durability SLA rescore (L15d / L16d)

**Instrument.** `durability_model` in `shekyl-staking-sim` scores **permanent retention**
`1 − (1−s)^d` per deep shard, with per-domain **retention survival** `s = 0.999` (bond-backed
loss probability, not momentary serve uptime) and target `D* = 0.999`. Distinct domains `d`
count **committed** holders (`World::replication` — all `holdings`, including in-flight fetches),
not seated replicas; transport does not depress `s`. Columns: `dUDp` (deep frac under `D*`),
`dAvl` (deep-set mean durability), `dTgtR` (derived `R_target` under independence).

**Derived redundancy collapses.** At `(s=0.999, D*=0.999)` independence needs `dTgtR = 1`
(vs `rTgtA = 3` at `(u=0.9, A*=0.999)`). The three-nines *availability* bar implied triple
redundancy at 90 % uptime; the three-nines *durability* bar at 99.9 % per-domain survival
needs only one independent domain when `R ≥ 6` deep replicas are seated.

**L15d diversity — wall shrinks for the historical class.**

| Scenario | Availability (`rUDp`) | Durability (`dUDp`) | Notes |
|---|---|---|---|
| `l15_corr_d3` / `l15d_corr_d3` | 0.202 | **0.000** | Same covered deep set; availability fails, durability passes |
| `l15_corr_d1` / `l15d_corr_d1` | 1.000 | **0.000** | Total availability failure; durability at knife-edge (`dAvl ≈ 0.999`) |
| `l15d_corr_d2` / `d6` | — | 0.000 | All pass at `s=0.999` |
| `l15d_surv_s99` (`d=2`) | — | **0.020** | Binds only when survival drops to 0.99 with ≤2 domains |

**L16d transport orthogonality — confirmed.**

| Scenario | `rUDp` | `trU` | `dUDp` | `dAvl` |
|---|---|---|---|---|
| `l16_regime_L0` / `l16d_regime_L0` | 0.000 | 0.900 | 0.000 | 1.000 |
| `l16_regime_L6` / `l16d_regime_L6` | **1.000** | 0.634 | **0.000** | 1.000 |
| `l16d_vs_avail_L6` (both models) | 1.000 | 0.634 | **0.000** | 1.000 |
| `l16_L4_d3` / `l16d_L4_d3` | 1.000 | 0.703 | **0.000** | 1.000 |

`dUDp` is **flat at 0** across the full `L0–L6` transport band while `rUDp` climbs to 1.0
and `rTgtA` rises 3→7 — the L16 orthogonality decomposition holds under the pinned SLA:
transport depresses **instantaneous availability**, not **bond-backed retention**.

**Disposition.** Step 0's two-class split is **pinned and supported by the rescore** (see
`V3_STAKER_ARCHIVAL.md` §*Service promise*): the L15 diversity-under-privacy tension is a
**load-bearing wall only for the seeding / instantaneous availability class** (steps 2–3), not
for historical/audit durability. The remaining anonymous-layer durability bind is marginal
(`d=1` at `s=0.999`, or `s≤0.99` with ≤2 domains) — the **public promise** rests on the
foundation complete-tree floor, not market `D*`. Seeding-path bounded latency (step 2) is
reduced in scope when archivers fetch from public foundation complete copies.

### Step 3 — L14 read-credit must be per-holder, never shard-global

Retrieval-as-proof (§*L14×L15*) is sound iff credited reads **reduce challenge burden only for
the holder that served them**, and only when the reader verified the response against the leaf
commitment. A dropper serves nothing, earns no credit, faces the full topped-up `a*`. If
`p_read` were a **shard-global** popularity estimate lowering cadence for every holder of that
shard, one holder's fake self-reads would inflate global `p_read` and shield a dropping
co-holder — so the soundness pin is: **per-(holder, shard), reader-verified,
successful-serve-only crediting; never shard-level.**

Secondary composition (lower priority): "high penalty → low `a*` → low oversight traffic" is
bounded above by L11 — penalty couples to the bond, and the bond is the APR denominator. A
privacy-optimal penalty that pushes the bond past the co-location-feasible point buys quiet
challenge-channel privacy at the cost of entry. Soundness pass should check that full-bond
slash at the credible penalty still hits an acceptable `a*` at the L11-feasible bond.

### Step 1 context — L15 diversity under location-hiding (conditional on step 0)

**If step 0 retains instantaneous availability globally**, L15's diversity floor at three-nines
needs ≥3 failure domains — but domains are location/operator/ISP correlation and `P` hides
location. Pick among: (1) correlation-inferred diversity; (2) relaxed instantaneous target;
(3) foundation as perpetual diversity anchor (sharper than P4).

**If step 0 pins durability+eventual for historical/audit reads**, this wall applies only to
the **seeding class** (step 2) and **routing-quality** (secondary market), not the retention
reward basis — durability-diversity replaces availability-diversity for the primary promise.

### P3 disposition — floor-tilt ≠ duration age-scaling

`foundation_floor_aged` (mean-preserving oldest-ward floor tilt) must **not** be filed under
the same "age-scaling" disposition as L9/L10 bond-duration age-scaling. Floor-tilt is a
targeted reallocation of non-market capacity onto the band demonstrably most exposed (`boOld`);
duration-tilt reallocated holding effort with a lean-margin cost that only dissolved on
windowed-mean. Tilting the floor is unambiguously good where tilting duration was ambiguous.

## Adjustment ledger — forward inputs to gates 4 and 5

Running record of model-surfaced design questions and the candidate adjustments they
imply, so the eventual gate-4/gate-5 work starts from the sim's evidence rather than a
blank page. Each item names the **evidence** (sim finding), the **disposition**
(decided / open), and the **reversion criterion** per `21-reversion-clause-discipline.mdc`
where a decision is provisional.

**Genesis staking shape (2026-06).** Leading form is **transfer-shaped admission**
([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4). Round 3–4
ratification requires three sim/design close-conditions at **equal severity**: **(ii)**
per-reward backing-proof aggregate at target `N_P` × settlement-epoch cadence; **(iii)**
admission-principal decision with **gate 7** locked-supply re-pricing when bonds become
the sole sink. Iteration 5 below is the gate-7 instrument. **(ii) CLOSED (2026-06-11):**
worked byte sweep at the pinned cadence (`SETTLEMENT_EPOCH_BLOCKS = 10_000`,
`MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15`) across the `N_P` envelope — aggregate
≤ 0.11 % of penalty-free block space; see §*Close-condition (ii)* and ledger row AGG.

| # | Question (gate) | Evidence | Candidate adjustment / disposition |
|---|---|---|---|
| L1 | **`g(age)` value** (gate 4 / near-term pin) | Shoulder-vs-tail seating (lean `g≈2`). **Layer 2 reframed (2026-06-07)** as a margin-robustness gate; **band run 2026-06-11** (§*Layer-2 margin-robustness band — results*): decomposition confirmed — `giniW` tracks leanness (`bondA`), whale gauges flat (`mxSW` 0.013–0.018 vs 0.20 bar, `wB4 = 0`) across the whole band; spread gate **re-anchored on direct whale gauges**, `gini_actor` demoted to trend. Band upper bound is coloc coverage oscillation, not spread: `g ≥ 3.0` fails at any purse; `g ∈ {2.0, 2.5}` healed by +30 % purse (L13 servo's static image); `g = 1.5` passes bare-lean. | **Sealed (band): `g ∈ [1.5, 2.5]`, genesis target `g ≈ 2`,** fallback `g = 1.5` if calibration pins the purse at bare-lean. Constant home `archival_reward_age_weight_milli` (calibration-tagged). Reversion clause in the results section (substrate re-read on curve/participation-model changes — Finding-0 precedent). |
| L2 | **Bond upper bound + spread margin** (gate 4) | Pin **`bond_rate* = 0.75`** on **endogenous L11** (`gate4_fine_*`, not fixed-pop). **2026-06-07 readings superseded** (banded PL Curve repair `4071ec032` moved the equilibrium: `bondA` 79 → ~113, coloc pin row now oscillates at bare-lean purse — §results Finding 0). Budget cross at the pin (replaces non-comparable `l11_bud_*` rows): budget 100→200 ⇒ `bondA` 113→226, `giniW` 0.598→0.217, whale-arm-identical — the purse is the spread lever. Iteration-2's `bond_rate = 1.00` upper-bound fail re-attributed to leanness-gini under the re-anchored gauges (Finding 4). | **Decided (numeric pin, stands):** `bond_rate* = 0.75`; **`ARCHIVAL_BOND_FLOOR = 750_000_000` atomic** — passes every direct gauge, maximizes Sybil headroom. Upper-bound rationale re-annotated (leanness, not whale spread); no value change. Budget-cross item **closed 2026-06-11** (§results Finding 2). |
| L3 | **Empty-window definition** (gate 4) | The L8 min-form **unifies** what looked like two axes: `min(capital-leg, storage-leg)` is a single co-located number that binds on whichever leg is scarcer. `bond_high` binds on capital (min-form `0.83`); `pop_thin` binds on storage (min-form `0.39`). | **Decided (definition):** the window is empty iff *no* bond rate satisfies min-form `dS/dN ≥ 1` **and** Sybil-deterrence simultaneously. The capital and storage axes are not separate tests — they are the two legs of the one min-form, and gate 5's provisioning sets the storage leg (L8 re-entangles gates 4 and 5). |
| L4 | **Flat vs age-scaled bond *magnitude*** (gate 4) | Sim evidence: the mean-preserving tilt is a weak, mildly regressive lever that fights the premium (1c). The **decisive** argument is durability survival arithmetic: for irreplaceable data redundancy dominates per-holder reliability — `N=3,p=0.99 → ~1−10⁻⁶` vs `N=20,p=0.9 → ~1−10⁻²⁰`; the number of *distinct holders* swamps per-holder commitment for "does the data survive at all." So the oldest shards want the **most distinct holders → the most accessible (flat/low) bond**, never scaled up. Age-scaling magnitude raises the bond exactly where the widest pool is needed, and **flips the binding constraint** from the tractable aggregate-slot `dS/dN` (distinct-actor slack 80≥6) to the intractable **tail-distinct-actor** concentration (#4 aimed at the worst place). | **Resolved: flat magnitude.** The same evidence that gave the clean `dS/dN` condition (L2) *is* the argument for flat — age-scaling trades a tractable capacity constraint for an intractable tail-concentration one. Attraction onto old shards lives on the **reward** (`g·scarcity`, L1): reward attracts, flat bond keeps-accessible, no collision. The commitment-horizon instinct behind "age-scale it" is real but belongs in **duration, not magnitude** (L9). **Reversion:** reopen only if a gate-4 requirement needs stronger slashable commitment on the oldest *that duration (L9) cannot carry*. |
| L8 | **co-location: the min-form seating metric** (gate 4↔5 re-entanglement) | `bscale_s0` (flat) has *aggregate* `dS/dN=3.24` yet `deep_und=0.75`: capital sits with storage-poor capital-rich actors and storage with bond-constrained capital-poor archivers, so deep — needing *both* on the *same* actor — falls in the gap. The **min-form** `Σ min(⌊capital/bond⌋, ⌊storage/shard_size⌋)/Σ_deep R_target` reads **0.86<1**, predicting the starvation the aggregate masked. The **(bond × shard-size) pair sweep** confirms the joint lever: low-bond-alone (0.97/0.65) and small-shard-alone (0.91/0.47) each starve; the *pair* clears deep to 0, coinciding with the min-form crossing 1. | **Decided (metric swapped + gates re-entangled):** the seating metric is now the co-located min-form (implemented; the reported `dS/dN`). Gates 4 and 5 **cannot close independently** — the binding quantity is the count of co-located non-whale actors per deep shard, a joint function of bond (gate-4 capital leg) and shard size (gate-5 storage leg). Two levers grow the pool, tuned **together**: **low-flat bond** (recruits storage-rich) + **finer deep-shard granularity** (recruits capital-rich). Real-design form: **ratio-matching** (deep shard's storage:bond ratio inside the population's storage:capital distribution). |
| L5 | **Oldest-tail provision** (gate 4 + gate 5 jointly) | At `g=1` the residual is *exactly* the oldest tail (`g1_p13`); under a premium the oldest is over-covered. The tail is the crux only absent a premium. | **Open.** Candidates: (a) the age premium itself already covers the tail (sim supports this at `g≥2`), so possibly *no extra* tail mechanism is needed if `g` is set right; (b) permanent foundation floor on the tail as belt-and-suspenders; (c) joint foundation+staker `R_target` for the tail. Decide whether (a) suffices or (b)/(c) is required for irreplaceability margin. |
| L6 | **Foundation floor sizing** (gate 5) | `pop_thin` fails outright (`frac_under 1.000`, storage-bound, `dS/dN` fine); total coverage is supply-bound; a deep-prioritizing `g` leaves a *hot* shortfall during thin periods (`g≥4` band `0.0–0.2` up to 70 % under). | **Decided (sizing input):** the floor must cover (i) the absolute coverage gap when population is thin, **and** (ii) the *hot* class specifically when a deep-prioritizing `g` de-prioritizes it during the thin handoff window. Gate 5 sizes both. |
| L7 | **`g`-for-steady-state** (gate 4↔5 coupling) | `g` trades hot↔deep; the foundation floor absorbs whichever class `g` de-prioritizes in thin periods. | **Decided (method):** choose `g` for the thick steady state to **seat the residual on the shoulder** (L1 — coverage matched to `R_target(age)`); let gate-5's floor backstop the thin-period de-prioritized class. `g` and the floor are pinned *together*, not independently. |
| L9 | **Age-scaled bond *duration*** (gate 4, second axis) | The commitment-horizon job the tier system did belongs in the bond's **duration**, not magnitude — but *age-scaling* it is a second oldest-ward redistribution lever, and the lean test downgrades **both** halves of the surplus reading as regime artifacts. **Necessity (benefit): inferred, unmodeled.** `oChrn` is the *abandonment rate*, not the coverage-oscillation metric the churn sub-claim names; at the lean operating point flat duration shows `oUmx 0` (no oscillation — the surplus `oChrn 0.251` was benign rotation the buffer backfilled). The model is capacity- not timing-bound (same-epoch backfill), so the benefit a backfill-lag model might show is not yet representable. **Cost: demonstrated at the operating regime.** The one oscillating regime is a *capacity bind* where age-scaling makes `deep_und` *worse*; the `bind_*` sweep banks this as a robust **lock-in reallocation cost** — age-scaling lifts the oldest band by starving mid-deep (redistribution signature: oldest `frac_under` ↓, mid-deep ↑), coverage-negative at every bind (`a08` 0.025→0.176 [7×], `a10` 0.351→0.377, `stor` 0.57→0.623), saturating at the first increment (`s2`=`s4`). It is the **#3 finding compounded**: `g` already reallocates oldest-ward; age-scaled duration double-counts it, so stacked they over-concentrate the very oldest at a bind. | **DEFER age-scaling — default to FLAT duration (cost demonstrated, benefit unmodeled).** Final genesis bond shape: **flat magnitude + flat (non-zero) duration** — `g` carries deep-prioritization with a *single* oldest-ward lever; flat duration carries the commitment horizon with no reallocation cost. *Demonstrated cost against unmodeled benefit is not insurance — it is an unpriceable bet*, so age-scaling is not adopted now. **Genesis-pin ordering reinforces:** the constant is consensus-visible (pinned pre-genesis), but age-scaling can only be validated by a backfill-lag model needing **post-testnet fetch latencies** — you cannot validate before you must pin, and flat-constant has nothing to walk back. A duration *servo* (genesis range, post-testnet tunable) would preserve the option but adds a governance/manipulation surface not worth it on current evidence. **Reversion (sharpened):** reopen iff a backfill-lag churn model shows the timing-stability benefit **net of** the lean-margin reallocation cost is positive (the damping must beat the demonstrated mid-deep aggregate cost) — a fork-worthy upgrade if earned. The L4 reversion trigger (oldest-band coverage oscillation) is **not discharged** and stays open under this clause. Banked surplus facts (anticipation sign-flip, outcome 3 ruled out) remain valid as surplus facts but don't reach the operating point. **UPDATE (L10): this disposition is REOPENED.** The backfill-lag model both (a) models the benefit (net-positive — serving `oUmx` damped, serving `deep_und` improved across regimes incl. binds) and (b) shows the "demonstrated cost" was a **final-epoch artifact** (windowed mean: `a10` 0.178→0.178 identical). The sharpened reversion criterion is **met**; the remaining call is the genesis-pin *shape* (magnitude is post-testnet), surfaced to the maintainer per L10. **DECIDED (2026-06-11): age-scaled-constant** — see L10 row and §*L10 hardening* disposition. |
| L10 | **Backfill-lag / timing-bound dynamics** (gate 4; the L9 hinge) | Deep-shard **fetch latency** added (committed-but-not-serving for `round(deep_shard_size · fetch_latency_per_unit)` epochs; drops instant), **decoupled** from the game (game on committed replication = iteration-2-stable; retrieval coverage on seated replication). The timing-bound channel the capacity-bound model could not show now appears: serving `oUmx` rises 0→0.46→0.71→1.0 with latency `L0..L4`. Age-scaled duration **damps it net-positive** — lower oldest churn (0.171→0.090), lower serving `oUmx` *and* lower serving `deep_und` at every latency (`L1` 0.263→0.222; `L2` 0.580→0.465), and lower serving `deep_und` even at capacity binds (`lagbind` churn 0.942→0.865, stor 0.988→0.974). **It also forced the `bind_*` cost re-read:** that cost was a **final-epoch artifact** — on the windowed mean it is within noise (`a10` 0.178→0.178 identical, `a12`/`stor` slightly positive, `a08` +0.013 not 7×). | **RESOLVED — reversion criterion MET; L9 disposition reopened.** The sharpened L9 clause (benefit net of the lean-margin reallocation cost positive) is satisfied: benefit demonstrated net-positive across all regimes incl. binds, and the cost it was netted against dissolves on the proper windowed read. **Residue (honest):** L10 establishes the benefit's **sign** (positive), not its **magnitude** at the real operating point — `fetch_latency_per_unit` is the post-testnet measurement. So the open decision is no longer "cost vs. no-benefit" but the **genesis-pin shape** (flat-constant / age-scaled-constant / duration-servo) under sign-known/magnitude-unknown — a priority-3 + `75-system-autonomy` human call, surfaced to the maintainer, **not** flipped unilaterally. **HARDENED (§*L10 hardening*):** denser latency grid `L1–L6` shows the benefit is robust across the survivable band and honestly **washes out at `L6`** (both arms saturate; nothing helps when backfill can't keep pace); the `dur_age_scale` sweep shows the benefit **saturates** (scale 4 ≡ 8 — a genesis *constant* is calibration-insensitive, which removes the servo's affirmative case); the widened bind grid (`a06–a14`) keeps the committed cost **dissolved** (Δ within ±0.015, mixed sign, on the now-banked `cDeepU` windowed-mean column); the **bandwidth-bound** regime (`acq_rate=1`) is the clearest win (improves even committed coverage 0.106→0.069). Net: the call **leans age-scaled-constant at a safe-side scale**. **DECIDED (maintainer, 2026-06-11): age-scaled-constant**, pinned at the sim-exercised plateau arm (`BOND_DURATION_BASE_EPOCHS = 4`, `BOND_DURATION_AGE_SCALE = 4`; shape pinned, numerics provisional until testnet `fetch_latency_per_unit` — see §*L10 hardening* disposition + reversion clause, [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1, gate-4 §3.4). Correlated *actor* exit is scoped to L15 (duration is a shard-drop deterrent, not an uptime guarantee). |
| L11 | **Endogenous participation / lean equilibrium derivation** (gate 5 / economics) | The lean operating point was *asserted* (fixed pop + tuned `budget`). L11 makes entry/exit a function of realized `apr = (reward − flow_cost)/committed_bond` vs. per-actor reservation ρ (trickle-entry + hysteretic realized-yield-exit; pool of potential archivers; fully gated, legacy byte-identical). The lean equilibrium now **emerges**: (1) it is an **attractor** — fill-from-empty (`l11_fill`, bondA 79.4) and trim-from-full (`l11_trim`, 78.6) converge to the same point, deep covered; (2) reservation is a **smooth monotone lever** with a coverage knee (ρ 0.01/0.02/0.03 → bondA 101/79/65, deep_und 0/0.002/0.392 — the interior-feasible lean point is ρ≈0.02); (3) **budget transfers to coverage *through participation*** (budget 50/100/200 → bondA 43/79/154, deep_und 1.0/0.002/0 — emergent, no asserted pop); (4) **heterogeneous ρ sorts** (the low-ρ tail self-selects). Calibration note: the pool must exceed the coverage floor with slack or the equilibrium is interior-but-infeasible (a cliff); pool 240 vs. floor ~90 gives the gradient. | **RESOLVED (shape derived) — iteration 3.** The lean equilibrium is no longer asserted: it is the attractor of entry-until-breakeven, and `budget → APR → marginal entry → archiver count → coverage` is the emergent transfer function. Participation churn at the lean margin is **benign for coverage** (`oUmx=0` — same shape as L9 benign rotation); the spread/lean tradeoff is now emergent (thin purse ⇒ exact-but-concentrated, fat purse ⇒ spread). **Residue:** ρ and `budget` real values are post-testnet/market — L11 fixes the equilibrium's *shape* (attractor, monotone transfer, sorting), not the live operating ρ. **Unlocks L12/L13** as perturbations of this attractor (bootstrap = `l11_fill` cold-start trajectory; fee-era = budget-shrink thinning; ρ is the natural home for L13's price-feedback term). **HARDENED (P1 — L8×L11):** the banked gradient sat on an *all-seatable* pool (both archetypes seat ~10 deep, total ~2400 ≫ the ~720 floor — co-location never bound). Against a **co-location-binding** endowment (`p1_coloc_*`: polarized archetypes seating ~3–4 deep, `dS/dN 1.31`) the lever **survives but compresses**: deep coverage falls *graded* (`deep_und` 0/0/0.067/0.192/1.0 across ρ 0.005–0.03), **not** a 0→1 cliff — the feared knife-edge does not appear — but the feasible band narrows (clean only ρ≤0.01 vs ≤0.02 loose), headroom thins (feasibility needs ~88% of the pool active vs ~42%), the **oldest band fails first** (`sOUmx 0.408` at ρ=0.015, aggregate only 0.067 — P3), and budget is **capped by the co-location ceiling** (`b200`≡`b400` — only capacity manufactures coverage, per L8). Disposition: the smooth lever holds; its *robustness margin is co-location-dependent* and must be sized against the co-located seating, not the raw pool. |
| L12 | **Bootstrapping / cold-start** (gate 5; genesis transient) | Growing frontier window (genesis hot core + per-epoch block growth via `World::append_shard`, deep history accrues *from zero*) + L11 endogenous entry from empty + a population-decaying foundation floor (`participation::foundation_floor`, invisible to the reward servo); fully gated, legacy byte-identical. Findings: (1) the cold start **reaches the L11 attractor** (steady `bondA≈76`, deep covered) — bootstrap is the *transient approach*, not a separate equilibrium; (2) the bare transient deep gap is **total** (`bDU=1.0`) — a *timing* hole (deep forms ~10 epochs before archivers seat it), not an economic one; (3) a `r_target_deep` floor decaying to ~steady pop collapses it to `bDUf=0.019` with **steady `bondA` unchanged** (no crowd-out — floor not in `R`/`Σwork`); (4) decay schedule is a fine lever (`decay_pop` 40/80/160 → floored gap 0.019/0.019/0.000 — wide safe band); (5) **overshoot is real but modest and is a growth/entry race** (peak `bondA` 83–97 vs steady 76–78; worse on *slow* growth — prolonged high-APR phase), and the shed is **coverage-neutral** (`oUmx=0`, `deep_und` steady ≈0.001 — benign rotation, L9/L11 shape); (6) the stress is the growth/entry mismatch (fast growth 12/epoch > entry 6 ⇒ total gap; slow 3 ⇒ gap 0.009), not the economics. | **RESOLVED (shape derived) — iteration 3.** Disposition confirmed: pin genesis constants for the **thick steady state** (L1/L7); the **population-decaying foundation floor** covers the transient (load-bearing *most* at genesis, withdraws adaptively per `75-system-autonomy.mdc`, does not crowd out entry). Overshoot bounded + coverage-neutral. **Reframes L5/L6:** the floor's bootstrap role is now the primary one; gate-5 sizes the genesis floor + decay schedule. **Residue:** real chain-growth rate, genesis floor size, and safe decay schedule are post-testnet calibrations of an already-understood curve (sign-known/magnitude-unknown, as L9/L10). **Unlocks L13** (fee-era = the budget-shrink mirror of this budget-transfer; the floor's decay reverses into a re-engagement as the market thins). |
| L13 | **Fee-era end-state / sustainability** (mission timeframe 2; ~30 yr) | As subsidy → 0 the archival budget must come from fees/terminal subsidy; a shrinking budget thins the lean equilibrium and the oldest (irreplaceable) tail is most exposed. Deep history grows unboundedly while the paid population may not; token-price ↓ → reward ↓ → exit ↓ → coverage ↓ is a candidate death spiral. | **RESOLVED (shape derived) — iteration 3.** Modeled the shrinking purse + price-coupling + adaptive reward-share servo + foundation-floor backstop (gated, legacy byte-identical). Findings: decay thins the attractor along the L11 transfer curve in reverse (coverage knee at terminal subsidy ~80–100); the **oldest tail goes under first** (`oUmx 0.163` at the knee vs `cDeepU 0.057`); the price-coupling spiral is **real** (`bondA` 39→17) but **dampable** by the burn.rs-style servo (`bondA` 17→62, shortfall 1.0→0.21) **conditional** on (a) a *smoothed* trust signal (a reactive servo oscillates) and (b) an adequate fee-market ceiling (below it the servo saturates → graceful loud failure); the L12 floor **re-engages automatically** as the market thins (`bDUf 0.425` vs bare `1.0`). The loop is **not** an undamped priority-1 failure provided the damping apparatus ships; without it, it runs. Residue: live ceiling, coupling strength, terminal-subsidy level, trust horizon are post-testnet empirics. See §*L13 — fee-era end-state*. **HARDENED (P2 — flow-cost denomination):** `flow_cost` is **token-denominated** in the model (every APR term shares the `budget` unit), so the price-cancellation behind "only expected depreciation bites" was a *modeling artifact*. Adding a **fiat** flow cost (`apr = R/B − F/(B·p)`, `p2_fiat_*`) confirms a **second, level-driven leg**: a price falling to 0.25 *with `price_coupling = 0`* (no trust trigger) collapses deep coverage outright (`deep_und 1.0`, `bondA 81→28`) — the level channel ignites the loop with no expectation feedback. It is the **more dangerous leg**: the token-denominated servo damps it only *partially* even at ceiling 400 (2× the purse: `deep_und 1.0→0.607`), because it must over-pay the fiat drag in tokens. The L13 disposition is **sharpened, not overturned** — dampable, but the level-leg damping condition is far stronger than the expectation-leg one, **reinforcing P4** (a token-denominated backstop is weak against a low-price fiat-cost collapse; the terminal subsidy must carry real margin). **HARDENED (P3 — age-stratify the irreplaceable tail):** a new oldest-band-resolved floored gap (`boOld`, age ≥ 0.8) shows the fee-era residual **is** oldest-concentrated (`l13_floor`: `boOld 0.612 > bDUf 0.425`) — L13#2's oscillation is the *least-replaceable* band thinning — while the **bootstrap** residual is **not** (`l12_boot_floor`: `boOld≈0` vs `bDUf 0.019`; the genesis core is covered earliest, so the hand-off slice lands on the *freshly-deepened, most-re-derivable* band — refuting the worry that 0.019 is irreplaceable loss). The lever is a **mean-preserving age-stratified floor** (`participation::foundation_floor_aged`, factor `1+tilt·(2x−1)` over the deep range, mirroring `R_target(age)`, at equal total cost): swept on the realistic `floor_replicas=6` re-engagement floor (`p3_fee_tilt_*`), tilt 0/0.6/0.9 cuts the oldest-band gap `0.612/0.391/0.125` (**~80%**) while the aggregate rises only `0.425→0.467` (the re-derivable band under-floors) — *protect the irreplaceable, let the re-derivable ride the market*. The bootstrap sweep leaves `boOld≈0` at every tilt, so **age-stratification is a fee-era lever, not a bootstrap one**; it composes with **P4** (the trustless terminal subsidy carries the same age-tilt). |
| L14 | **Proof-of-archival / free-rider gate** (gate 4 / consensus) | Reward is for *provable* work but the model rewards declared holdings; the free-rider (claim without storing, or store-but-refuse-to-serve) is gated by the audit cadence, not the bond. Modeled the deterrence threshold `a* = benefit/penalty` (abstain iff caught-prob·slash ≥ saved flow cost) and the **read-credit**: a content-bound retrieval *is* a proof, so the explicit-challenge rate is only the top-up `max(0, (a*−p_read)/(1−p_read))` the unread tail needs (`src/audit.rs`; gated, legacy byte-identical). | **RESOLVED (shape derived) — iteration 3.** The non-productive (oversight-only) traffic **collapses onto the cold tail**: crediting real reads cuts the mean challenge cadence from the naive `a*=0.1` to `0.035` (**~65%**) with **98% of the residual on deep shards** (`l14_credited`: `auN 0.100 → auC 0.035`, `auDp 0.98`) — hot shards are proven for free by their own reads; only the oldest carry cadence (`auOld 0.090`, P3). Two levers shrink it further: (1) **a credible slash is the primary deterrent** — penalty 0.5/1/2/4 drops `a*` 0.20/0.10/0.05/0.025 and credited cadence 0.106/0.035/0.010/0.002 (`l14_penalty_*`), so the bond/penalty does the deterring and challenges are the top-up, not the reverse; (2) **demand self-polices** — as the cold-tail read floor rises to `a*`, even the oldest self-prove and explicit challenges vanish (`l14_read_*`: `auOld 0.090→0`). **Disposition:** gate-4's free-rider gate is **retrieval-credited PoR** — real reads are the proof wherever they occur; explicit challenges are cover traffic confined to the unread cold tail, sampled/aggregated, rate-set by the band's irreplaceability (P3) and its retrieval SLA (L15); deterrence is carried by a credible slash, with the challenge cadence only topping up the read-audit to `a*`. **Residue:** live read-rate distribution, the real `benefit/penalty` ratio, and the challenge-faking cost (can a free-rider fetch-on-demand to fake a challenge? — sets the floor cadence) are post-testnet/gate-7 empirics. See §*L14 — proof-of-archival* and the §*L14×L15 specification*. |
| L15 | **Retrieval / correlated-failure realism** (gate 4–5) | Coverage (replicas exist) ≠ retrieval (fetch within latency at target availability); the L4 survival arithmetic assumes *independent* holder failure. Modeled per-holder uptime `u` + a coarse failure-domain bucketing (`a % n_domains`); availability `= 1 − (1−u)^d` where `d` is the count of *distinct domains* among a shard's serving holders (`src/retrieval.rs`; gated, legacy byte-identical). | **RESOLVED (shape derived) — iteration 3.** Two results, both on a **fully-covered** deep set (`deep_und=0`, `R≈6`): (1) **coverage ≠ retrieval** — under independent failure (`l15_indep`) the covered set meets a three-nines SLA (`rUDp=0`), but as holders cluster into fewer domains (`l15_corr_d{6,3,2,1}`) realized availability falls `0.9997/0.997/0.988/0.900` and the under-SLA deep fraction climbs `0.007/0.20/1.0/1.0` **with `R` unchanged** — so **diversity (≥3 domains), not replica count, is the binding retrieval constraint**; (2) **`R_target` is derivable, not stipulated** — `⌈ln(1−A*)/ln(1−u)⌉` gives `rTgtA` 2/3/5/10 at `u` 0.95/0.90/0.80/0.50 (`l15_uptime_*`), so the stipulated `r_target_deep=6` silently assumes `u ≳ 0.85`; below that the covered set is under-redundant for the SLA *even under independence* (`u50`: `rUDp=1.0`). **Disposition:** gate-4/5 must (a) state the retrieval SLA `(u, A*)` and *derive* `R_target` from it, and (b) add a **co-located-with-coverage diversity floor** (≥`d*` distinct domains per deep shard) — a covered-but-clustered set is a latent availability failure. **Reinforces P3** (the oldest band, thinnest, is first under the diversity floor) and **L16** (the onion path depresses `u`, raising the derived `R_target`). **Residue:** live `u`, the SLA `A*`, and the real domain-correlation structure are post-testnet empirics; the privacy tension (diversity must be measured in coarse buckets, never per-holder geolocation — mission priority 2) is the gate-4 design constraint. See §*L15 — retrieval availability*. **Substrate for L14** (the challenge cadence rides on this serving/diversity state). |
| L16 | **Transport selection / latency-regime coupling** (gate 6 / networking; the L10 latency axis seen from the transport side) | The firewalled-pseudonym requirement forces the **heavy archival fetch onto onion-service↔Tor-client rendezvous** (slowest Tor config; `P`'s location must not link to the principal, so no clearnet fallback). This makes the L10 `L2–L6` sweep the **operating regime by construction**, and `fetch_latency_per_unit` the onion-rendezvous latency — the post-testnet "real fetch latency" unknown is just *where on the band* the live transport sits. L16 couples that band to L15 via `u_eff = u_base/(1+k·L)` (`src/transport.rs`; gated, legacy byte-identical). TCP-sync and Tor reinforce (Tor is TCP-only; the inherited Levin/TCP stack drops in); the commitment is coupled (UDP/QUIC sync would reopen it). Tor is primary on maturity + TCP + persistent-reachable-service + longevity; I2P is a defensible secondary; Lokinet (Oxen-tied, UDP) and Nym (mixnet, latency-disqualifying for heavy fetch) are out. The **Arti in-process onion-service** option (Rust-canonical) is claimed viable on the 2.x LTS line — *to verify per `17-dependency-discipline.mdc`*. Full analysis: [`../ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Transport for the staker-archival path*. | **RESOLVED (shape derived) — iteration 3.** On a fully covered deep set (`deep_und=0`, `R≈6`), transport depression alone breaks the retrieval SLA from `L≥1` (`l16_regime_*`: `trU` 0.900→0.634, derived `rTgtA` 3→7, `rUDp` 0→1.0 across `L0..L6`); duration backstop does not repair depressed `u` (`l16_L6_s0`≡`s4`); replica floor adds `R` not `u` (`l16_L6_floor`≡`L6` — reinforces P4); transport+diversity compose worse than either (`l16_L4_d3`: `rUDp=1.0` vs `l15_corr_d3` `0.202`). **Disposition:** treat rendezvous latency as an input to the retrieval SLA `(u,A*)`, derive `R_target` from depressed `u_eff`, size against transport **and** diversity. **Residue:** post-testnet `L`, `k`, band position, and any non-linking bandwidth relaxation. Transport PR forks unchanged (Arti embed, I2P door, rendezvous threat pass). See §*L16 — transport-regime coupling* and §*Soundness pass*. |
| L17 | **Black-swan / acute-shock resilience** (gates 5/7; due-diligence close) | L13/P2 stressed *gradual* declines; historical crises are steps (March-2020 gap-down, FTX custody collapse, LUNA compound, 2008 flight-to-liquidity, **Filecoin's fiat-opex provider exodus** — SPs 4 100 → ~1 900 as FIL fell). Gated `shock_*` knobs fire one-epoch discontinuities at the settled pinned-economics attractor; reads `shkP`/`shkRec`/`shkBA` (§*L17*). **swan-2** (W1–W3): extinction accounting (`shkExt` — backfill is *sourceless*), domain-correlated exit, aftershock re-fire, shock-at-knee, cascade × ρ. **swan-3** (W12–W15): per-band extinction read (`extB`), floored extinction read + floor-on closure arms (`shkExF`), holder-class-correlated exit (`shock_exit_top_deep`). **swan-4** (retention correction): foundation-as-sole-source re-read; bandwidth-bound re-seed arms (`reseed_rate`, `ssSE`/`ssMxW`/`ssOpn`). | **RESOLVED (measured, re-anchored on the retention guarantee) — 2026-06-11, swan-2/-3/-4 same day.** **swan-4 correction:** genesis foundation seeds retain complete trees permanently (`V3_STAKER_ARCHIVAL.md` authority pin), so market wipe-outs are **foundation-as-sole-source transitions, not data loss** — no shock in the grid loses data; the grid measures availability. Population shocks **absorbed with zero market wipe-outs**: 30 % exit (stride or index-bucketed, attractor or knee), ρ×3 panic, permanent ρ×2 (conditioned on Finding-0). Correlation drives the tail: at 50 %, stride 0 / index-bucketed-domain 1 / **class-correlated 28** wipe-outs — and class-correlated **30 %** costs 4 (outranks every independent 50 %). Aftershock pair 4, **within the independence-to-no-reseat envelope [1.9, 21]** (W14). Price legs, bare-lean: V-crash 37 to sole-source, recovered servo-400 99, permanent-gap 144–649 (market collapse onto the backstop); **band read (W12): mid-deep modal, NOT oldest-concentrated** (vshape 20/17 b4/b5; servo-400 5/64/30). **Re-seed bottleneck sized (swan-4):** at `reseed_rate = 3` (~1 flow/seat) the V-trough costs **429 sole-source shard-epochs, worst window 10**, servo-400 **403/9** (5 windows open at the run boundary); 4× provisioning halves exposure (429→204) and cuts wipe-outs 40→10 — foundation seeding bandwidth = **availability-SLO sizing input, provisioned at the crisis multiple (~4× steady-state; not gameable — foundation's own action)**, with the `N_active` domain-diversity condition folded into the gate-5 ops requirement. Serving-floor arms (`shkExF = 0`) cover every window incl. the 114-epoch servo-400 crossing. swan-2 domain rows ran with **no placement diversity floor (W15 pinned)** — benign results were bucketing luck. **Exports: retention guarantee + single-org threat model documented with authority** (swan-2 "new requirement" → existing-guarantee documentation); **treasury diversification = named ops requirement** (W4). W12/W13 completeness questions **parked against the no-sunset pin** (reversion (d)). Honest-holding = named residue; trigger observables pinned (W17): challenge-latency shift (weak) + **source-load spikes on true holders at challenge anchors** (confirmatory); detection open, not solved. Reversion re-keyed on **class- or domain-concentrated exit ≥ ~0.3** and on reopening the no-sunset pin. §*L17*. |
| T-A1 | **F1 re-linkage instrument** (PHASE_2B §7.7; gate-3 + rotation) | **CLOSED.** Instrument + qual firewall wargame complete. Scarcity-spread → unique portfolios; primary firewall holds lifetime `T_obs` under wallet defaults. | **Conditionally finally accepted — regime-bounded (swan-2/W7).** Form-C reopen not triggered. The acceptance premise (lean-eq cohort ~79–100) is temporarily invalidated in L17 swan troughs (9–25 bonded — intersection surface maximally cheap); holds at the attractor, not in a crisis trough. [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §7 regime bound + §9; gate-6 sync-exit wargame (W8) is the mitigation question. |
| G7 | **Locked-supply re-pricing / admission principal** (gate 7; PHASE_2B §2.4 close-condition (iii)) | Iteration-5 run (2026-06-11; §*Gate 7 iteration-5 — results*): derived archival lock collapses to `bond_floor × R × shards(t)` — 117 → 3 546 coins over 30 yr, `lock/circ ≤ 8.5×10⁻⁷` (10⁻⁵ even at 10× denser shard geometry; 1.4×10⁻⁴ at arm-B `MIN = 10 000×` floor). All three macro gauges (burn servo, release factor, net inflation) **insensitive to both arms at every `N_P`** — burn identical to the cent; both arms clamp identically at the 90 % cap under load. Δ vs. the asserted comparator: legacy schedules overstated burn −22.3 % via the now-inert `(1 + stake_ratio)` factor (FOLLOWUPS item). | **RESOLVED — bonds-only** per the pre-named indeterminate criterion (admission lock does no measurable macro work; smaller consensus surface wins). Cross-doc spec edits **landed 2026-06-11** (emission §10.2 branch deletion, PHASE_2B §2.4 (iii) + admission row, gate-6 §2.5, V3_STAKER_ARCHIVAL). **Reversion:** reopen iff bond floor / shard geometry re-pin ≥ 3 OOM upward combined, or a new archival lock class lands; re-run `--gate7`, re-apply criteria. |
| AGG | **Per-reward proof aggregate** (PHASE_2B §2.4 close-condition (ii); emission §10.1) | Worked byte sweep (2026-06-11; §*Close-condition (ii)*) — no feedback dynamics, every term pinned or banked. Typical emission tx ≈ 17–19 kB, dominated by constant-size hybrid crypto (ML-DSA-65 sig 3.3 kB ×2, hybrid pk 2 kB, FCMP++ ~2.5 kB), not the work claim (≤ 780 B/epoch at year-30 lean portfolio ≈ 60 shards). Aggregate at 20 kB margin: thin/lean/thick = 80/160/310 B per block amortized = **0.027/0.053/0.103 %** of the 300 kB penalty-free zone. Single-tx max (15-epoch batch) ≈ 29 kB; boundary burst drains in ≈ 11 blocks at thick with zero spreading; only `work_claim` grows with chain age (2.6 kB/epoch at year 100 — still < 15 kB constant term). | **RESOLVED — (ii) closes; wire confirmed as pinned.** ≤ 0.11 % amortized across the envelope (≤ 0.21 % at uniform 2× size error). `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` + `SETTLEMENT_EPOCH_BLOCKS = 10_000` confirmed. Caveat: `FcmpMembershipOnly` size assumed at 1-input `FcmpPlusPlus` order (proves strictly less). **Reversion:** reopen iff built proof > 3× estimate, `N_P` envelope re-pins above ~1 500, epoch re-pins below 1 000 blocks, or **the envelope extends below `N_P` ≈ 25–30** (thin direction, W9 — L13 servo floor 17 / swan troughs ~9; per-archiver claim scales as `1/N_P` and a 15-epoch batch ≈ 70 kB at `N_P`=17 year-30; the guard is a per-emission claim cap forcing batch splitting); re-evaluation = re-run sweep with measured sizes. |

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

### Archival timing cluster pin (2026-06-07)

**Authority:** [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md).

| Constant | Value |
|----------|-------|
| `MAX_CLAIM_AGE_W` (`W`) | **26** settlement epochs (~361 d) |
| `RETENTION_HORIZON_BLOCKS` | **420_000** blocks (~583 d retention floor) |
| `ARCHIVAL_REORG_DEPTH_BLOCKS` | **720** blocks (~24 h processable reorg) |
| `RELEASE_COOLDOWN_EPOCHS` | **2** |
| `CHALLENGE_RESOLUTION_BLOCKS` | **10_000** (one `SEB`; T-A16 margin) |
| `prune_horizon_epochs` | **26** (`= W`) |

**Verification:** `cargo run -p shekyl-staking-sim -- --timing-cluster` — all couplings §2 and
F4 scenarios **PASS** (`rust/shekyl-staking-sim/src/timing_cluster.rs`).

**T-A4:** consensus-leg quantitative pass unblocked; gate-6 Round 3–4 wallet defaults (jitter,
drain spacing) remain open per timing doc §7.
- **Margin-artifacts (regime-specific, do not generalize):** the `deep_und=1.000`
  *magnitude* (a thin-supply corner that dissolves with provisioning); the specific
  residual-minimizing `g` value (baseline-supply-dependent); the exact `frac_under`
  borderline failures (`0.062` at strict `<0.05`).

### Funding-seam entry standoff (Gate 6 §10.12 pass-4; 2026-06-13)

**Authority:** [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §10.12. Closes the §7
"wallet jitter default" open item flagged in the timing-cluster pin above (T-A4).

**Charter (pass-4 organizing principle):** hide **P ↔ principal** (GF-7), *not* **P ↔ its own
rewards** (`P_canonical_id` is a conceded-public earner). The standoff decorrelates `P`'s observable
entry event from the bond-post; the **inversion** (`P` may appear *before* its bond is staked,
feasible because the announce is membership-only backing over principal outputs that exist pre-bond)
removes the adversary's ordering prior. The mitigation touches **no economic quantity** — it is off
the trilemma axis.

**Harness:** `cargo run -p shekyl-staking-sim -- --standoff`
(`rust/shekyl-staking-sim/src/standoff.rs`). Monte-Carlo (200k trials/arm, SplitMix64, reproducible)
over candidate-set size = 1 target + Poisson background funding-shaped decoys.

**Homeostasis is analytical, not re-simmed.** Economic dynamics are epoch-quantized
(`SETTLEMENT_EPOCH_BLOCKS = 10_000` ≈ 13.9 d); the standoff adds at most `window_blocks` of entry
latency = `window/epoch` of one epoch. Re-running the epoch-granularity sweep to resolve a sub-epoch
effect would over-read the model (cf. the float-vs-integer over-read,
[`ARCHIVAL_SIM_ECONOMICS_VERDICT.md`](../completed/ARCHIVAL_SIM_ECONOMICS_VERDICT.md)). **Free ≤ 0.10 epoch
(≈ 1000 blocks ≈ 1.4 d)** — two orders above any obfuscation-useful window.

**Findings:**

1. **Window vs. anonymity set** (background rate `0.02` ≈ 1 funding-spend/1.7 h): candidate-set mean
   `1 → 7 → 13 → 25` across windows `0 → 300 → 600 → 1200` blocks; the **thin-cover tail**
   `P(set ≤ 2)` reaches **0 % at 600 blocks** (~20 h). Homeostasis-free holds through 600
   (`latΕ = 0.06`) and **trips at 1200** (`latΕ = 0.12`).
2. **Anonymity is rate-driven, not width-driven** (the load-bearing finding). At a fixed 300-block
   window, the set is `2.5` (thin 56 %) at rate `0.005` but `16` (thin 0 %) at rate `0.05`. The
   window's value depends entirely on the **background funding-spend rate, which is unmeasured
   pre-testnet** — a swept assumption flagged like `fetch_latency_per_unit` (L10). The recommendation
   is conditional on the measured rate.
3. **The inversion carries the low-activity worst case.** In the thin regime (rate `0.005`, where
   set-enlargement *cannot* lift cover), enabling inversion cuts single-guess link probability
   `0.52 → 0.32` and thin-cover `56 % → 20 %`, and breaks the ordering prior in ~50 % of cases — the
   structural gain width alone can't buy. Inversion should be **on**.
4. **Trigger independence is decisive.** A shared trigger (everyone jittering off a common epoch
   boundary) collapses the candidate set `16 → 1.01` and link `0.067 → 0.997` — a detectable surge
   separable from background traffic, destroying all cover regardless of width. **Uniform-independent
   draws are mandatory.**

**Recommendation:** **window = 600 blocks (~20 h), uniform-independent draw, inversion enabled**
(symmetric ±600 envelope). Rationale: thin-cover → 0 % and set mean ≈ 13 at moderate background
traffic (rate ≥ 0.02), comfortably homeostasis-free (`latΕ = 0.06`), and the inversion both breaks the
ordering prior and covers the low-activity principal that a wider symmetric window cannot. The window
cap is a candidate consensus bound, but as an **anti-griefing ceiling** (max announce↔bond separation,
with announce-before-bond permitted) — *not* a privacy control; the privacy floor is the
uniform-independent draw, which is wallet-only and therefore a **hard conformance requirement with a
published test vector**, not a default (see caveats below). **Testnet must measure the background
funding-spend rate** — at low traffic (rate ≤ 0.005) set≥10 is unbuyable by width under the
homeostasis ceiling, and the inversion (not a wider window) is the lever.

**Conditionality and caveats (review pass, 2026-06-13) — what the numbers mean.**
The window/inversion/draw *shape* is right and the standoff sits off the trilemma axis as claimed,
but four things bound the result; the first two change the meaning, not just the value:

1. **The cap is anti-griefing, not privacy.** A "max announce↔bond ≤ 600" rule is a *liveness
   ceiling* (don't let announced-but-unbonded `P`s linger), not a privacy floor — privacy wants the
   separation large and random. The privacy-load-bearing controls are a **minimum effective spread**
   and the **uniform-independent draw**, and both are **wallet-only and consensus-unenforceable**:
   consensus sees neither the FCMP++-hidden funding source nor the principal's off-chain activity, so
   it cannot police the draw. Finding 4 makes this load-bearing in the worst way — a single popular
   wallet shipping "bond at the next epoch boundary" injects a detectable surge that degrades cover
   for *everyone* drawing in the window, and nothing in consensus can stop it. **Disposition:** the
   draw is a **hard conformance requirement with a published test vector** (reference wallet nails it
   and documents it loudly), not a "wallet-side default." **Open consensus question:** the one lever
   consensus *has* is the bond-post it can see — a per-block bond-post budget that defers excess posts
   would make a shared-trigger spike unconstructible on-chain. It is only a **partial** backstop (it
   smooths the chain event, not the network announce it can't see, so wallet conformance on the
   announce draw stays load-bearing) and it is **not free** (an attacker can saturate the budget to
   delay honest entrants — a liveness-griefing risk traded for the privacy-surge risk). Carried to
   `FOLLOWUPS.md` / Gate 4 timing.
2. **Cover is conditional on §10.9 isolation, multiplicatively.** The harness models background as
   *indistinguishable* funding-shaped decoys — indistinguishability that **§10.9 circuit/key
   isolation is what buys**. Without isolation the principal's activity is attributable directly (the
   target is *named*, not in a crowd) and no window helps. So these numbers are `P(link | isolation
   holds)`; the unconditional `P(link) = P(link|iso)·P(iso) + P(link|¬iso)·P(¬iso)` with
   `P(link|¬iso) ≈ 1`. **The standoff is a multiplier on isolation, never an independent additive
   mitigation.** Corollary: post-isolation the residual channel is concurrent *network* activity, so
   the rate that actually drives cover is the **network-event rate, not the on-chain funding-spend
   rate** swept here (a proxy). The harness is channel-agnostic ("candidate events in a window"), so
   the structure transfers, but **testnet must measure the rate of the actual channel**, or the
   rate-driven finding is calibrated against a proxy.
3. **Cold-start is the structural worst case (named pre-seal residual).** The rate that drives cover
   is lowest at genesis (a cold chain has the thinnest funding/network traffic), and the earliest
   `P`s are the foundational, longest-lived stakers — so the **weakest cover and the longest exposure
   window coincide on the actors who matter most for bootstrap** (tie-in: L12 cold-start). Inversion-on
   is the right call but the thin numbers (link 0.32, thin-cover 20 %) are not strong. The obvious
   remedy — **foundation-injected decoy funding** — is undercut by caveat 4: foundation decoys are
   foundation-*attributable* (keys, patterns, origin), so a sophisticated adversary discounts them and
   early-`P` cover does not actually rise. The honest lean is **document weak early cover as a named
   residual** unless a *non-attributable* decoy source exists (which does not, short of reopening
   confidential staking). Do not let "rate ≥ 0.02" quietly assume a steady-state rate the genesis
   chain will not have.
4. **The set is nominal cover under honest traffic — an upper bound.** Poisson decoys are honest
   background; the RingCT decade's lesson is that nominal anonymity set ≠ effective set against an
   adversary that **observes** (marks which background it can attribute elsewhere) and **injects**
   (announce-then-not-bond seeding, bounded but not foreclosed by the membership-only backing
   requirement). So "set ≈ 13 at rate 0.02" is an **upper bound**; effective adversarial cover is
   lower and unquantified. The testnet target is **S-3's modeled observer**, not a passive rate
   measurement.

**Construction and per-seam geometry (conformance-critical, 2026-06-13).**

- **Draw the gap directly — do *not* independently jitter two event-times around a common anchor.**
  The sim assumes the separation between the two seam events is `s ~ U[0, 600]` with a random order.
  The obvious-but-wrong build picks an intent time `t0` and independently draws an announce offset and
  a bond offset in `[0, 600]`; their *difference* is **triangular, peaked at zero** — the events
  cluster together most of the time, the precise opposite of a standoff, while still satisfying "both
  within 600" and "separation ≤ 600" on paper. This is a **conformance trap**, and it matters
  precisely because the draw is wallet-side and consensus-unenforceable (caveat 1). **Correct shape:**
  at `t0`, flip a fair coin for order, place the first event at `t0`, draw `s ~ U[0, 600]`, place the
  second at `t0 + s`. That yields uniform separation, *free* inversion (the coin), max latency 600,
  and per-`P` independence (`t0` is the principal's private intent). **The published test vector must
  reject the triangular construction** — it asserts on the *distribution* of the realized
  `(spread, order)` over a large sample (uniform spread: **discrete chi-square GoF** against the
  uniform on `[0, 600]` + an excess-mass-near-zero / first-decile detector; balanced,
  per-`P`-independent order), **not** the
  ±600 bound alone (which the trap also passes). Order-balance alone is *not* sufficient — the trap's
  order-coin still looks fair while its spread is zero-peaked, so the spread distribution is the
  load-bearing check. This is executable in the harness as the reference for the vector:
  `draw_entry_gap` / `summarize_gaps` in `standoff.rs`, with `correct_draw_is_well_distributed`
  (the correct draw is flat) and `double_jitter_trap_fails_the_same_check` (the same summary rejects
  the trap) as the validating tests.
  **Single-sourced (2026-06-16):** the executable reference has since moved out of the sim into the
  `shekyl-standoff` crate (float-free `draw::draw_entry_gap` in the default build; the instruments
  named here and below — `summarize_gaps`, `population_bond_time` / `max_bin_share`, `lag1_autocorr`,
  the double-jitter trap — plus the RNG-generic `certify_draw` self-cert harness under the
  `conformance` feature), with the generic goodness-of-fit primitives (`chi_square_uniform`,
  `chi_square_upper_crit`, `Z_ALPHA_1E6`) in `shekyl-stats`. The sim now `impl GapRng for SplitMix64`
  and imports the shared draw + harness; the integer `(spread, order)` golden vector is verified
  bit-identical on the aarch64 CI lane, the float grading x86-only. See `FOLLOWUPS.md` §funding-seam
  carry 2 and `ARCHIVAL_FIREWALL_GATE6.md` §10.12.
- **"Uniform-*independent*" has two independence dimensions a marginal gap test cannot see — both
  must be in the conformance vector.** The uniform/trap checks above nail the *marginal*; they are
  structurally blind to *independence*, and the gap is the wrong input for both failures:
  - **Population anchor-independence (the catastrophic shared-trigger mode, finding 4).** The gap is
    anchor-agnostic — a wallet bonding at "next epoch boundary + uniform gap" draws a *perfect*
    uniform spread (passes every gap test) while every wallet's anchor `t0` snaps to the same
    boundary, so the **absolute bond times** cluster and the candidate set collapses to ~1.01 (worse
    than the triangular trap's merely-bad). The bug is in the anchor, not the gap, so it needs a
    **separate harness on absolute times**: a population of `N` wallets with independent private
    intents, asserting the realized bond times do not cluster, with an **epoch-snapped population as
    the negative**. Landed: `population_bond_time` / `max_bin_share` +
    `population_anchor_independence_disperses_shared_trigger_clusters`.
  - **Serial independence across a `P`'s repeated draws (now load-bearing).** A marginal GoF cannot
    see autocorrelation; a weak PRNG can produce a beautiful uniform marginal with correlated
    successive draws. This was moot when a `P` drew one gap in its life, but **rebond / partial-unbond
    / re-entry at genesis** make a `P` draw several gaps over its lifetime — and a conformant-but-weak
    wallet's correlated successive gaps make those recurring bond ops linkable to each other (exactly
    the recurring-surface exposure). For a *cross-wallet* vector (different implementations, different
    PRNGs — cannot assume SplitMix64), add a **lag-1 autocorrelation / runs probe** on a single
    wallet's gap sequence. Landed: `lag1_autocorr` +
    `serial_independence_reference_passes_correlated_fails`.
- **The grade is a discrete GoF at a strict grading alpha — not continuous KS, not research alpha.**
  Three conformance-gate-specific cautions: (i) the gap is **integer blocks**, so continuous KS is
  mis-calibrated and conservative — use **chi-square against the discrete uniform** (`chi_square_uniform`,
  graded by `chi_square_grades_uniform_at_strict_alpha`); (ii) pick **alpha for a grading gate, not
  research** — a naive `p < 0.05` false-fails ~5 % of correct wallets by sampling chance, so set the
  threshold strict (**~1e-6**, via `chi_square_upper_crit` at `Z_ALPHA_1E6`) where a correct wallet
  essentially never false-fails while the trap (a gross deviation) still fails by orders of magnitude;
  (iii) **"fixed seed" means reference-determinism, not a PRNG mandate** — the seeded SplitMix64
  sequence makes the *reference* reproducible for others to match their statistics against; it must
  not become "all wallets emit this exact sequence" (that grades the implementation, not the
  property, and false-fails a correct wallet with a different CSPRNG). Grade the property
  (uniform-independent) statistically.
- **The 600 is *per seam*; the symmetric ±600 envelope is the entry seam only.** The entry standoff
  (announce↔bond) is order-symmetric and inversion-eligible: ±600 around the bond-post, 1200-block
  adversary search width, 600-block max entry latency (caveat geometry above). The **exit seam**
  (terminal drain, and now the *recurring* partial-unbond `HoldingsUpdate`) is a **separate standoff
  with its own envelope and its own latency budget** — and it differs structurally on two axes:
  (i) it is **one-sided** (no inversion: collateral is not spendable before the **20_000-block
  release cooldown**, so the drain cannot precede the unbond), so a 600-block exit window buys a
  600-block search width, *not* 1200 — the exit seam is inherently weaker cover per unit latency than
  the entry seam; (ii) its latency lands on **funds availability measured from cooldown expiry, not
  from the unbond event**, because the cooldown already pins the earliest spend deterministically — so
  the exit standoff's job is specifically to **break that deterministic fixed-offset tell** (without
  it, the drain fires at exactly cooldown-expiry, trivially linkable to the unbond). Cost: ≤ 600
  blocks *on top of* the 20_000-block cooldown = **0.06 epoch of additional availability latency**,
  free on its own seam. Symmetric entry/exit protection is therefore **two independent 600-block
  draws**, each free on its own seam — but the exit one must be stated explicitly; "±600 envelope"
  describes the entry seam and does not imply the exit.
- **Thin-regime: the cheap lever is gap-shape and inversion, not width.** Width is the *expensive*
  axis (the rate-driven finding: a wider window trips homeostasis above ~1000 blocks and barely moves
  thin-regime cover, which is rate-limited not width-limited). If more cover than rate-at-600 is wanted
  in the thin regime, the free levers are (a) **biasing the gap distribution toward the max** — 600 is
  already homeostasis-free, and positioning the true event far from the bond-post anchor defeats a
  *nearest-spend* proximity heuristic when any background exists (modest, adversary-model-dependent),
  and (b) **leaning on the inversion** (the proven thin-regime lever, finding 3). Neither widens the
  window; both stay off the economic axis.

## L18 — `HoldingsUpdate` release-cooldown freeze (R-3 reconciliation, 2026-06-16)

**Why.** `HoldingsUpdate` (voluntary partial-unbond / rebond) is promoted to genesis
(V3.0). The prior layers modeled mobility as *frictionless* re-allocation: an actor
could shed a deep shard and re-deploy that capital the same epoch. The FSM
([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md), pins P2B-7) does not permit that —
collateral released by a voluntary drop inherits the **Unbond release cooldown** and is
frozen for `RELEASE_COOLDOWN` before it can re-bond. This layer reconciles the sim's
mobility model with that friction and **re-derives whether the genesis redundancy floor
`r_target_deep` must rise to absorb it.** This is the R-3 reconciliation: its value is
faithfulness to the FSM, so the friction is taken from consensus source, not modeled in
the abstract.

**Faithfulness pins (taken from [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) at
source).** Two source-divergences in the first-draft model were corrected before the
sweep was trusted:

1. **The frozen amount is flat `ARCHIVAL_BOND_FLOOR`, not age-scaled.** §8.1:
   `bond_floor(ShardSetCompact(set)) = ARCHIVAL_BOND_FLOOR × |set|` — per-shard capital is
   flat regardless of depth; §4.4 confirms the drop side reduces `bond_floor(holdings)` by
   a flat `ARCHIVAL_BOND_FLOOR`. The escrow therefore freezes a flat amount per dropped
   shard (`World.cooling` pushes `(bond_rate, RELEASE_COOLDOWN)`), **not** `bond_age(s)`.
   The age-scaled-amount draft would have over-stated the deep-shard freeze *exactly where
   the redundancy margin lives* — sealing a higher `r_target_deep` than the real friction
   requires (a permanent entry-barrier / decentralization cost) on an artifact. The
   **"age-stratified by composition, not a re-tuned flat scalar"** conclusion survives, but
   on legs 1+3 only: a *flat* freeze, age-stratified in **incidence** because
   (1) `bond_duration(age)` makes deep capital least mobile to begin with (you can't shed it
   to free budget) and (3) the deep tail is where coverage is thinnest, so a freeze-induced
   delay there does the most harm. Flat freeze, age-stratified harm.
2. **The cooldown anchors at per-shard last-served, not at drop** (§4.4). The sim is
   serve-until-drop (an actor that holds a shard serves it until the epoch it sheds it), so
   `last_served ≈ drop` and the drop-anchor is faithful. Recorded because a hold-but-don't-serve
   model would over-state the freeze on top of any amount error, and the two pessimisms
   compound.

Escrow scope (the three forks, resolved against source): **voluntary drops only** — §4.5
slash moves `bonded → burned` (forfeited, never cooled), and a clean `Unbond` requires the
cooldown to have *already elapsed* (§3.2/§4.3), so the exit→re-entry path is not
re-frozen (`deactivate` clears `cooling`, no double-count). The drop-and-re-add **2× capital
bite** (P2B-7 Pin 3 anti-dodge) is faithful: the per-shard cooldown is keyed on released
collateral, so re-adding the same shard needs fresh capital while the old freezes out.

**Instrument.** `SimConfig.release_cooldown_epochs` (gated: `0` ⇒ inert, every prior
scenario byte-identical — the `c0` arms reproduce the pre-L18 lean/buffered baselines to the
digit). `World.cooling: Vec<Vec<(f64, u32)>>` holds per-actor `(frozen_amount,
epochs_remaining)`; `frozen_capital(a)` is subtracted from spendable budget in
`best_response`, and `advance_epoch` decrements/retires entries. New metrics:
`frozen_capital_frac` (system escrow fraction), the freeze-harm **bracket**
(`freeze_harm_causal` lower bound / `freeze_harm_co` upper bound, see below), and the
lag-immune `oldest_min_committed_r` (worst-epoch committed replication over the oldest
band).

**Sweep.** `--axis=holdingsupdate_cooldown`. Three crossed axes: backfill latency
(`lag0` lag-free = the **primary seal channel** that isolates the freeze; `lag2` =
compounding-stress diagnostic), cooldown (`c0/c1/c2/c4`; **`c2` is genesis
`RELEASE_COOLDOWN`**, `c4` is the cliff probe), and bond-duration composition (`s0` flat
contrast; `s4` age-scaled = the realistic composition). Plus buffered arms
(`hu_buf_b{140,160,180}`) that raise the budget, and lever arms (`hu_lever_aw{3,7,12}`) that
raise the deep-tail reward premium, to test whether any market setting makes the redundancy
margin emergent (findings 4, 6: none does).

**Seal gates (absolute, named in advance per rule 21).** At genesis `c2`, on the primary
`lag0` committed channel: (i) `committed_deep_under < 0.10`; (ii) `sole_source_shard_epochs
= 0`; (iii) **hold-the-floor** `oldest_margin ≥ 0` (the committed oldest-band worst-epoch
min is not eroded below `r_target_deep`). The freeze-harm seal is gated on the
**co-occurrence upper bound** (`freeze_harm_co`) — a seal wants the pessimistic reading.
The cooldown-2-vs-0 delta is the diagnostic for *how load-bearing the prior optimism was*,
not a gate; `sole_source` is gated lag-free because backfill lag alone makes it non-zero
(confounded under `lag2`).

### Results

| arm | frozFrac | freeze_harm_co | committed_deep_under | oldest_min_committed | sole_source |
|---|---|---|---|---|---|
| `lag0_c0_s4` (baseline) | 0.000 | 0.000 | 0.0027 | 6 | 0 |
| `lag0_c1_s4` | 0.024 | 0.028 | 0.0027 | 6 | 0 |
| **`lag0_c2_s0`** (genesis, flat) | 0.077 | 0.063 | 0.0064 | **6** | **0** |
| **`lag0_c2_s4`** (genesis, age-scaled) | 0.054 | 0.099 | 0.0138 | **6** | **0** |
| `lag0_c4_s0` (cliff, flat) | 0.201 | 0.321 | 0.139 | 5 | 0 |
| `lag0_c4_s4` (cliff, age-scaled) | 0.118 | 0.212 | 0.068 | 6 | 0 |

**1. Genesis `c2` passes all three absolute gates on both duration arms; the binding seal
number is the age-scaled `0.0138`.** Both arms clear (`committed_deep_under` an order under
the `0.10` ceiling, `sole_source = 0`, committed oldest-band min at `r_target_deep = 6`,
`oldest_margin = 0`), so the seal is covered either way — but the **faithful figure to seal
against is the age-scaled `0.0138`, not the rosier flat `0.0064`** (see finding 2: gate-4
§3.4 makes `bond_duration(age)` genuinely age-scaled, so `s4` is the shipping composition
and `s0` is the optimistic contrast). The flat-`ARCHIVAL_BOND_FLOOR` freeze is absorbed at
genesis with no floor erosion. **The +1 margin held at the flat floor, exactly as
predicted** — the `bond_age` over-statement was concentrated on the deep band, and removing
it is what lets `c2` pass where the artifact would have tripped it.

**2. Age-scaled is the faithful arm (gate-4 §3.4); the cliff lives in the flat *contrast*
arm.** Gate-4 §3.4 fixes `bond_duration(age) = BOND_DURATION_BASE_EPOCHS · (1 +
BOND_DURATION_AGE_SCALE · age)` — the consensus *form* is genuinely age-scaled, so `s4` is
the shipping composition and `s0` is the optimistic contrast. (The "L9 resolved to flat
default" note elsewhere refers to the *sim's legacy knob default* `bond_dur_age_scale = 0`,
kept so pre-L18 rows stay byte-identical — not a claim that flat duration ships.) The `2→4`
gradient is the bifurcation tell. Flat (`s0`): `committed_deep_under 0.0064 → 0.139`
(**21.6×**, breaches `0.10`) and `oldest_min_committed 6 → 5` — super-linear, fragile.
Age-scaled (`s4`, faithful): `0.0138 → 0.068` (**4.9×**, stays under `0.10`) and the floor
**holds at 6**. Because the faithful arm is the bounded one, **genesis `c2` is not on a
bifurcation edge and "keep cooldown at 2" is reassurance, not a load-bearing operating
constraint.** The servo-400 lesson (gate the realistic arm, confirm it isn't on an edge) is
satisfied.

*The crossover is positive evidence the model captures real dynamics, not a monotone knob-
scaling.* Age-scaled is **worse** at `c2` (`0.0138` vs flat `0.0064` — deep shards are held
longer, so there is *less* mobility to re-cover a thinning shard) and **better** at `c4`
(`0.068` vs flat `0.139` — flat churns more, so it accrues more cooldown exposure under a
long freeze). That duration-shape × cooldown interaction *reversing sign* across the sweep is
the operating-envelope coupling: **the dangerous corner is flat-duration × high-cooldown, and
the genesis config sits in the opposite corner** (age-scaled × cooldown-2).

*Reopen criteria (rule 21):* (a) if `RELEASE_COOLDOWN` rises above `~3` epochs the faithful
arm itself approaches the `0.10` ceiling (`c4_s4 = 0.068`), so the cooldown value is the
load-bearing knob; (b) **if `BOND_DURATION_AGE_SCALE` is sealed at or near `0`** in the
joint cluster pass (gate-4 §3.4 numeric values land there, not here), flat *becomes* the
faithful arm — the cliff moves into the realistic composition and "keep cooldown ≤ 2 **and
do not flatten duration**" becomes a load-bearing operating-envelope constraint, not
reassurance.

**3. "Harmless at `c2`" is a *conjunction* — co-occurrence bounded AND `oldest_min` holds —
not `causal = 0`.** The freeze's harm mode is **structural, not transient**, and the two
detectors are complementary, not redundant:

- *`freeze_harm_causal` (the transient/recovery-lag detector) reads `0` in every epoch of
  every arm* — verified by a global-max probe across the whole sweep, **including
  `lag0_c4_s0` where the floor demonstrably eroded `6 → 5` and co-occurrence hit `0.936`.**
  A causal `0` therefore cannot be read as "the freeze is harmless"; it means the detector's
  firing state (a willing-and-able archiver with frozen-but-recoverable capital, blocked from
  re-covering) is **precluded under cooldown-aware optimization — not a structural
  impossibility.** The `best_response` budgets on `effective_capital = capital − Σ frozen`
  (it *sees* the cooldown), so it never makes the one move that strands an actor — the futile
  *drop-to-reallocate* (drop A to fund B while A's freed collateral is frozen this window). It
  instead points scarce budget at the *thinnest* shards and *holds* them; the shards that stay
  under target are in absolute shortage (nobody can afford them), never frozen-but-idle. **The
  scope of the preclusion is the rational-cooldown-aware regime, not all behavior:** a naive
  operator who drops A intending to immediately rebond into B, not modeling the cooldown,
  discovers A's capital frozen and leaves B under-covered for the 2-epoch window — exactly the
  transient the sim precludes. So the transient is *reachable, just not by an optimizing
  agent*; that residual is routed to operator-education and a wallet-conformance guard (see
  Disposition), and is the mechanism by which the reopen clause's named rebond/unbond churn
  would erode the band — which is why "precluded under optimization" (consistent with a reopen
  path) is the correct framing and "by construction" (which would contradict it) is not.
- *Detector validation owed and delivered (the triangular-trap discipline).* To distinguish
  "`0` because the precluded state never arises" from "`0` because the metric is dead", the
  firing predicate is extracted to `World::freeze_blocks_recoverage` with a positive control
  (`freeze_predicate_fires_when_blocked`) that constructs the willing-and-able-but-frozen
  state and confirms it fires, and negative controls
  (`freeze_predicate_silent_when_any_conjunct_fails`) that falsify each of the four conjuncts.
  The computation is live and selective; the sweep `0` is the precluded state.
- *Consequence for the bracket.* `freeze_harm_co − freeze_harm_causal` is therefore
  **maximally wide in this sweep** (`co − 0`), i.e. maximal entanglement — the causal
  attribution carries **no marginal information** in this model and is *not* a load-bearing
  seal input. The trustworthy reads are the two it brackets: the **co-occurrence upper
  bound** (`freeze_harm_co ≤ 0.099` at genesis — the transient/co-occurring ceiling) and the
  **structural `oldest_min_committed` floor** (holds at `6` at `c2`; the `6 → 5` erosion at
  `c4_s0` that `recovery_lag` is structurally blind to). The freeze's real harm — when it
  appears, at `c4` — is a *floor settling to a lower level*, which only `oldest_min` sees.

So the supported "harmless at `c2`" result is the **conjunction**: `freeze_harm_co` bounded
*and* `oldest_min_committed` holds at `r_target_deep`. Recorded that way — not as `causal = 0`
alone, which carries no information here.

**4. The `+1` redundancy is provisioned, not emergent (the floor re-derivation).** The
buffered arms settle the redundancy-floor question directly: at `c0` the worst-epoch
committed oldest-min is `6 = r_target_deep` at **every** budget (b120/b140/b160/b180) — the
equilibrium never discovers a 7th replica regardless of surplus capital. The literal `+1`
redundancy is therefore a property of **how `r_target_deep` is set** (`= availability_floor
+ 1`), not a buffer the lean equilibrium emergently holds. Combined with finding 1 (the
flat freeze costs `~0` floor erosion at `c2`), the re-derivation conclusion is:
**`r_target_deep` requires no freeze-driven increase. The genesis redundancy floor is
unchanged by `HoldingsUpdate` promotion.** (The noisy `b160_c2`/`b180_c2` rows show the
worst-single-epoch oldest-min flickering to `5` — a fragile tail statistic, *not* a freeze
effect: their robust `committed_deep_under` stays `0.012`–`0.016`. The committed-deep-under
read is the load-bearing durability confirmation; the worst-epoch min is reported with its
noise.)

**Posture (conscious, per rule 21): the `+1` is fully consumed by modeled frictions, with no
emergent slack underneath.** "Buffered arms settle to exactly `r_target_deep`" means the
`+1` seat is entirely absorbed by the known frictions (integer flooring + freeze) — there is
**no self-correcting cushion** below the provisioned floor. The reopen clause is widened
accordingly (see Disposition): it fires on *any* newly-discovered friction that erodes the
deep band, not only on "the freeze pushes under `+1`", because there is nothing beneath to
absorb a new bite. The rebond/unbond recurring surface and the cooldown-anchor edge case are
both live candidates.

**5. Under compounding stress (`lag2`), the committed floor survives; only serving
sole-source rises.** Backfill lag alone makes `sole_source` non-zero at `c0` (`7`–`15`),
confirming the metric is lag-confounded (hence gated lag-free). The freeze compounds the
*serving* read under lag (`c2`: `sole_source 135`–`154`, `serving_deep_under ~0.49`–`0.72`),
but the **committed** reads hold (`oldest_min_committed = 6`, `committed_deep_under ≤
0.014`). The freeze+lag interaction is a transient backfill effect on serving exposure, not
a committed-durability breach — the durable floor is intact even off the primary channel.

**6. No market lever buys emergent slack — a wider band is provisioning-only (`hu_lever_*`).**
Asked whether *any* setting yields emergent margin above `r_target_deep` or lets the system
run mid-band: no. The buffered arms show **budget** alone buys none (idle capital stays idle —
a `(target+1)`-th replica of an at-target deep shard is individually unprofitable). The
`hu_lever_*` arms hold budget at the lean point and raise only the **deep-tail reward
premium** (`age_weight` 3→12): `oldest_min_committed` stays pinned at `6` across the whole
range, and `committed_deep_under` *worsens* slightly at the top (`0.0138 → 0.037` at
`age_weight = 9`, a concentration effect). The `1/R` reward makes the `(target+1)`-th replica
unprofitable **by construction** — anti-over-replication is the intended property (no wasteful
redundancy), so there is no emergent free cushion from any market knob. Running mid-band is a
**priced provisioning decision**, two options: (a) set `r_target_deep = availability_floor +
2` (the market provisions the cushion, paid in entry barrier / launch decentralization); or
(b) lean on the **foundation complete-tree (B+C) backstop**, which sits structurally *below*
the market floor (the foundation is not a `1/R` market actor, so it can hold the deep tail
unconditionally — paid in trust concentration, and self-undercutting against a sophisticated
adversary per the standoff carry 3). The trilemma trade is explicit and neither option is
free; the genesis disposition takes the minimal one (`availability_floor + 1`, no foundation
band-widening) and accepts the no-cushion posture above.

### Disposition

`HoldingsUpdate` is sealable at genesis with `RELEASE_COOLDOWN` at its current value and
**no change to `r_target_deep`**. The flat-`ARCHIVAL_BOND_FLOOR` freeze is the faithful
friction; the redundancy margin is a provisioning property the floor already delivers; the
faithful (age-scaled) composition is not on a cliff edge at `c2` (binding seal number:
`committed_deep_under = 0.0138`). The reconciliation closes the "mobility is frictionless"
optimism in L1–L17: the friction is real, modeled, and absorbed without re-provisioning.

*Standing reopen criteria (rule 21).* Because the `+1` is fully consumed with **no emergent
cushion beneath it** (findings 4, 6), the reopen trigger is **any newly-discovered friction
that erodes the deep band** — not only "the freeze pushes under `+1`". Named live candidates:
(a) a `RELEASE_COOLDOWN` increase past `~3` epochs (the faithful arm approaches the `0.10`
ceiling); (b) `BOND_DURATION_AGE_SCALE` sealed at/near `0` in the joint cluster pass (flat
becomes faithful → the cliff moves into the realistic arm); (c) the rebond/unbond
recurring-surface friction (R-2/R-3) consuming margin; (d) the cooldown last-served-anchor
edge case if actors hold-but-don't-serve before dropping. Any of these re-opens the floor
question via a fresh `--axis=holdingsupdate_cooldown` sweep at the new parameters; on a
failing arm, `r_target_deep + |oldest_margin|` is the actionable reopen floor (no re-run).

*Routed residuals (the honest scope of the causal-`0` preclusion).* The transient gap the
sim shows as `0` is precluded only under cooldown-aware optimization; a naive operator can
still reach it via drop-to-reallocate. This residual lives in **operator behavior and wallet
conformance, not the consensus floor** — the network-floor harm is structural (caught by
`oldest_min`) and bounded, and the naive transient is individual, self-correcting within the
2-epoch cooldown, and not a structural breach. It does *not* move the seal, but given the
no-cushion posture (finding 4) there is no emergent slack to absorb a *wave* of naive
operators stranding capital in a thin-tail epoch, so the two items below earn their place
rather than being optional:

- **Operator-education item (transparency theme).** Document, in operator-facing guidance:
  *do not drop a shard to fund another within the release cooldown.* The freed collateral is
  frozen for the cooldown window, so the new shard is stranded for ~2 epochs — a self-inflicted
  coverage gap, and in the lean regime other actors are too capital-pinned to backfill it
  quickly.
- **Candidate wallet-conformance guard.** The wallet should warn or refuse a `HoldingsUpdate`
  drop whose freed capital the operator is visibly trying to redeploy within the cooldown —
  the same conformance posture as the standoff draw. A drop-to-reallocate the cooldown will
  strand is a UX footgun the wallet can catch at construction time. (Tracked as a wallet-side
  follow-up; not a consensus rule.)

### Faithful-freeze reconciliation (Copilot PR#148 findings #4/#5, 2026-06-16)

The R-3 results above (the `0.0138` binding number, the `c4` cliff, the bracket width) were
produced by a freeze model that was **one epoch too lenient and, worse, let a voluntary drop
recycle its bond *within the same epoch*.** Copilot review of PR #148 surfaced both:

- **The off-by-one (#5).** The release-cooldown escrow was pushed with
  `epochs_remaining = release_cooldown_epochs` *after* `advance_epoch` ran, and
  `advance_epoch` decrements before the next best-response — so an entry intended to freeze
  for `C` epochs was observed frozen for only `C − 1`. The drop epoch itself was never frozen.
- **The same-epoch recycle (#4).** Because the dropped shard's collateral was not charged in
  the drop epoch's budget, `best_response` could **drop A and immediately fund B with A's
  freed bond in the same epoch** — the futile *drop-to-reallocate* move that finding 3's prose
  explicitly claimed a cooldown-aware actor "never makes." The sim's *prose* described the
  intended FSM; the sim's *budget arithmetic* contradicted it. The freeze harm the sweep
  measured was, in large part, the sim charging the network for an irrational move the
  cooldown exists to prevent.

**The fix (faithful freeze).** `best_response` now **pre-charges** the collateral of every
deep shard held at epoch start: that bond seeds `used_bond`, so a same-epoch drop cannot
refund a fresh acquisition. Pre-charge covers the drop epoch; the escrow covers the next
`C − 1`; together they span the full `RELEASE_COOLDOWN_EPOCHS`. With
`release_cooldown_epochs == 0` only locked shards pre-charge, so every `c0` arm stays
byte-identical to the pre-cooldown baselines (verified: 0 numeric diffs).

**The numbers move — and the move *confirms* the section's thesis rather than overturning
it.** Re-running `--axis=holdingsupdate_cooldown` under the faithful model:

| arm | before `cDeepU` | after `cDeepU` | before `harm_co` | after `harm_co` | before `oMin` | after `oMin` | before `churn` | after `churn` |
|---|---|---|---|---|---|---|---|---|
| `lag0_c2_s4` (genesis) | 0.0138 | **0.0000** | 0.099 | **0.000** | 6 | **6** | — | 0.157 |
| `lag0_c2_s0` | 0.0064 | **0.0000** | 0.063 | **0.000** | 6 | **6** | — | 0.160 |
| `lag0_c4_s0` (old "cliff") | 0.139 | **0.0000** | 0.321 | **0.000** | **5** | **6** | 0.37 | 0.157 |
| `lag0_c4_s4` | 0.068 | **0.0000** | 0.212 | **0.000** | 6 | **6** | — | 0.157 |

Three consequences, in order of importance:

1. **The `c4` "cliff" was an artifact of the budget bug, not a real bifurcation.** It was the
   sim accruing cooldown exposure on the spurious same-epoch churn; under a long cooldown the
   bug bit hardest, which *looked* like a super-linear harm gradient. With the recycle closed,
   churn flattens to `~0.157` at *every* cooldown duration (`c1 = c2 = c4`), and the only arm
   with elevated churn is `c0` (`0.239`) — i.e. **the cooldown is coverage-neutral-to-mildly-
   *protective* for rational agents, and its duration is irrelevant in this regime.** This is
   exactly finding 3's rationality-preclusion thesis, now true in the budget arithmetic and not
   only in the prose. `freeze_harm_causal` was already `0` (the transient detector, with its
   positive/negative controls); now `freeze_harm_co` collapses to `0` too, because the
   co-occurring shortage it was counting was the artifact.

2. **Production calibration is unchanged; the seal is strengthened, not weakened.** Both the
   old (artifact) model and the faithful model pass every absolute `c2` gate
   (`committed_deep_under < 0.10`, `sole_source = 0`, `oldest_margin ≥ 0`). No gate flips
   pass→fail; every arm is strictly safer. Therefore **every shipped genesis parameter is
   identical under both models** — `RELEASE_COOLDOWN_EPOCHS = 2`, `r_target_deep =
   availability_floor + 1`, no foundation band-widening, `age_weight = 3`. The faithful model
   passes with larger margin (binding seal number `0.0000`, not `0.0138`) and *widens* the
   known-safe operating envelope (`c4` is now also clean), so reopen criterion (a) — "cooldown
   past `~3` approaches `0.10`" — weakens to reassurance but is **retained conservatively**
   pending the joint cluster pass. The disposition's headline stands: **`HoldingsUpdate` is
   sealable at genesis with no change to `r_target_deep`.** The correction does not
   substantially alter the calibration of the production system; it removes a pessimism that
   was an artifact, not a margin.

3. **Finding 6 is partially superseded — a mid-band lever now exists.** With the spurious
   churn removed, the `age_weight` lever *does* buy emergent slack: at `aw7`/`aw12` the
   committed oldest band reaches a **7th** replica (`oldest_min_committed = 7`, `oldest_margin
   = 1`), where the artifact model kept it pinned at `6`. Genesis (`aw3`) is unchanged
   (`oMin = 6`, `oMrg = 0`), so this moves no shipped number — but it answers the earlier "is
   there a lever to run mid-band?" question in the affirmative under the faithful model:
   raising the deep-tail reward premium to `~7` funds a cushion above `r_target_deep`. This is
   a *new optimization option*, not a calibration change; it is routed to a follow-up
   (`FOLLOWUPS.md`) rather than re-derived here, because it reopens the economics finding 6
   closed and deserves its own pass.

**Why the faithful model is kept, not the conservative artifact.** Overstatement that comes
from a *modeling bug* (the agent making a move the modeled cooldown precludes) is not
legitimate conservatism — it is the sim measuring the wrong thing and gating the seal on
noise. A seal rests on a faithful model. The artifact is documented here (not hidden) so the
audit trail shows the binding number *moved* and *why*, and so the superseded prose above
(the `0.0138` binding figure in finding 1, the `c4` cliff in finding 2, the no-lever claim in
finding 6) is read through this correction.

### Adversarial-dodge arm — the cooldown's bad-actor seal leg (2026-06-16)

The faithful fix above closed a real bug, but it left the seal resting on one leg. Under the
faithful **cooldown-aware rational** agent the cooldown is *inert* — a rational actor never
makes the futile drop-to-reallocate move, so it never populates the escrow, so the sim
provides no evidence for `RELEASE_COOLDOWN_EPOCHS` at all. A reader optimizing parameters
against the faithful-only sim would read `c2 ≡ c0` and conclude the cooldown is dead weight.
That conclusion is wrong, because the cooldown's entire justification (P2B-7 Pin 3) was never
about rational agents — it is the anti-dodge defense against an operator that *wants* to
drop-and-refund to shed an aged retention obligation. The faithful model removes that agent
from the sim, removing the only thing the parameter defends against.

**Instrument.** `AgentParams.dodge_pref` / `SimConfig.dodge_pref` (`agent.rs`, `scenarios.rs`).
`0.0` ⇒ the faithful rational agent (every prior scenario byte-identical — the **good-actor /
lower-bound** leg). `> 0.0` ⇒ a **non-cooldown-aware** operator that over-values acquiring a
*fresh* deep bond by an additive net-value bonus and tries to rotate held deep bonds into
fresh ones every epoch — the **bad-actor / upper-bound** leg. The faithful pre-charge decides
whether the attempt *succeeds*; the dodger does not plan around the cooldown. New scenarios:
`hu_dodge_{nolock,ship}_{lag0,lag2}_{dp0,dp1}_{c0,c2}` — `nolock` disables the L9 retention
locks (cooldown is the *sole* anti-dodge defense), `ship` is the realistic shipping
composition (`bond_dur_age_scale = 4`).

**The premise inverted on the committed channel.** The expectation was: `c0` lets the dodge
succeed (harm rises), `c2` defeats it (harm → 0). The committed channel (the lag-immune one
the gate reads) shows the reverse:

| arm | churn | `cDeepU` | `oMinCmtR` | `frzCo` | `frzCap` |
|---|---|---|---|---|---|
| `nolock_lag0_dp0_c0` (rational) | 0.268 | 0.0009 | 6.0 | 0.000 | −0.000 |
| `nolock_lag0_dp1_c0` (dodge, no cooldown) | **1.364** | 0.0005 | **6.0** | 0.000 | −0.000 |
| `nolock_lag0_dp1_c2` (dodge, cooldown 2) | 0.962 | 0.0103 | **4.0** | 0.0625 | **0.375** |
| `ship_lag0_dp1_c0` (dodge, locks on) | 0.214 | 0.0125 | **7.0** | 0.000 | −0.000 |
| `ship_lag0_dp1_c2` (dodge, locks + cooldown) | 0.256 | 0.0172 | **7.0** | 0.107 | 0.047 |

1. **At `c0` the dodge does not cause committed-coverage harm** — it churns 5× harder
   (`1.364` vs the rational `0.268`) but `oMinCmtR` holds at `6.0`. With instant re-seating
   the drop-and-refund is *churn*, not a coverage gap: the freed bond refunds the rotation the
   same epoch, the seat is never empty on the committed channel.
2. **At `c2` the cooldown is what *causes* the only committed breach in the sweep** —
   `oMinCmtR 6.0 → 4.0` (gate fail) with `frzCap = 0.375` (37 % of capital stranded). The
   pre-charge does exactly what Pin 3 says (it refuses the rotation by freezing the refunded
   bond), but in the lock-off regime the *consequence* of stranding that capital is fewer
   funded deep seats — the breach. **Defeating the dodge by stranding capital costs more
   coverage than the dodge it prevents.**
3. **The coverage defense is the L9 retention lock, not the cooldown.** In every `ship` arm
   the lock forbids the voluntary drop, so `oMinCmtR` holds at `7.0` at *both* `c0` and `c2`;
   the cooldown adds only a bounded `frzCo` (`0.107`) and no breach.

**Corrected mechanism.** Pin 3's anti-dodge property is real — the cooldown makes
drop-and-refund non-free — but its mechanism is a **cost / deterrent**, not a coverage
protector. As a *sole* defense (`nolock`) it backfires; as a *complement* to the retention
lock (`ship`) it is bounded-safe. `freeze_harm_causal` is `0.0` everywhere (even where
`oMinCmtR` erodes), reconfirming the L18 detector split: causal/recovery_lag is the
*transient* detector, `oldest_min_committed` is the *structural* one, and `freeze_harm_co` is
the co-occurrence upper bound that catches the `nolock` breach the causal lower bound cannot.

**The two-leg seal (the seal rests on both).** Sealed against the **`ship` config** — what
actually ships:

- **Good-actor leg** (faithful rational, `dp0`): cooldown inert-to-beneficial (churn
  `0.268 → 0.159`), no harm. **Costless.**
- **Bad-actor leg** (dodger, `dp1`, `ship`): gate holds (`oMinCmtR 7.0 ≥ availability_floor +
  1`), `frzCo` bounded (`0.107`), dodge defeated. **Bounded-safe** — not costless (the
  cooldown does freeze some capital), but no breach.

**Operating-envelope constraint (load-bearing, new).** The cooldown is **not a substitute for
the L9 retention lock** — relied on alone (`nolock`) it produces the sweep's only gate
failure. *Reopen (rule 21):* if `BOND_DURATION_AGE_SCALE`/`BOND_DURATION_BASE` are driven to
zero (retention locks disabled), the cooldown's coverage effect inverts and
`RELEASE_COOLDOWN_EPOCHS` must be re-evaluated — the two parameters are coupled, not
independent.

**The honest scope — every agent in this sim is a financial wizard.** `best_response`
re-optimizes every epoch and chases basis points; every harm characterized across five
independent stress passes (overstated model, faithful model, dodge sweep, lever sweep,
cooldown sweep) *requires* that hyperactivity — the freeze only bites under churn, the dodge
only exists under active rotation, the stranding only under drop-to-reallocate. The real
target user is the opposite: set-up-and-walk-away, i.e. **low churn, the safest corner of
every envelope drawn here** (no freeze population, no dodge, no stranding). The convergent
result of all five passes is a *dependability* finding, not a tuning one: **the system holds
at the existing genesis settings, usually with more margin than the math first suggested,
across a wide range of operator behavior up to and including an aggressive adversarial
optimizer.** Not one parameter moved (`RELEASE_COOLDOWN_EPOCHS = 2`, `r_target_deep =
availability_floor + 1`, `age_weight = 3`, foundation floor unchanged). The settings are
**frozen**; the residual risk lives in operator behavior and the wallet/ops surface, not in
the protocol parameters — and that, not more sweeps, is where the next work belongs.
