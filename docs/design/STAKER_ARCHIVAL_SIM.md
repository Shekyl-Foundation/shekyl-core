# Staker-archival simulation — design spec

**Status: spec-first, pre-code. Iteration 1 (coverage dynamics) specified in full;
later iterations mapped, not yet specified. Reviewed before any code is written,
per `05-system-thinking.mdc` (specification first) and `20-rust-vs-cpp-policy.mdc`
(a sim that re-prices *what staking is* is a planning activity, not "while we're
here").**

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
| **Covered enough** | min over shards of replication count `R(shard)`, and the fraction of shards with `R < R_target` | a non-trivial fraction of shards sit below `R_target` at steady state |
| **Spread (no whale)** | Gini / top-1% share of *shards-held* across pseudonyms; max single-holder shard fraction | one (or a few) holders accumulate an outsized share despite the cap |
| **Deep history held** | replication `R` restricted to deep-history (high-`age`, rarely-queried) shards | deep-history shards are systematically under-`R` relative to hot-set |
| **Churn-stable** | shard abandonment rate; coverage variance over time | coverage oscillates / shards repeatedly drop below `R_target` |

`R_target` is a model input (the protocol's intended replication floor for
durability), not an output — iteration 1 reports coverage *relative to* a stated
target, it does not invent the target.

### Model

**Discrete-time, agent-based, single-region (no network topology in iteration 1).**

- **Shards.** A fixed universe of `N_shard` shards, each with an `age` (hot-set →
  deep-history) and a `query_rate` that decays with age. `age`/`query_rate` are the
  axis along which "deep history is rarely queried but must be retained" lives.
- **Time.** `T` epochs. Each epoch: challenges are issued (retention is proven or
  not), rewards are computed and paid, agents reconsider their shard portfolios
  (acquire / hold / drop).
- **Agents (pseudonyms `P`).** A population with heterogeneous endowments —
  **storage capacity** (how many shards they *can* hold) and **capital** (how much
  per-shard bond they *can* post). The three archetypes the keystone must survive:
  storage-rich/capital-poor, capital-rich/storage-poor, and the **Sybil whale**
  (one actor, many `P`s, shared endowment). Iteration 1 includes the whale as a
  *coverage* perturbation (does splitting let one actor dominate coverage?); its
  *cost* (gate 4/5) is iteration-2.
- **Reward (the model under test).** Per the canonical doc:
  `work_P = Σ_shards scarcity(shard) · proven_retention(P, shard)`, where
  `scarcity(shard) ∝ 1/R(shard)`; `reward_P = Curve(work_P)` with `Curve` a
  piecewise-linear banded plateau-cap (decreasing marginal rates → flat top).
  The **Σwork servo** (`reward_P = budget · work_P / Σwork`) is present as a fixed
  normalizer so per-staker numbers are budget-consistent, but its *supply-safety
  behavior under population growth* is gate 1 (iteration 2), not exercised here.
- **Per-shard retention bond.** Holding a deep-history shard requires posting a
  bond `bond(shard)`; dropping it inside the retention window slashes the bond.
  Bond rate is a **fixed input** in iteration 1 (its *calibration* is gate 4 /
  iteration 2); iteration 1 asks only whether, *at a plausible fixed rate*, the
  bonds + scarcity + cap produce coverage.
- **Agent behavior.** Reward-maximizing under a budget: each epoch an agent
  estimates marginal `reward` per additional shard (falling, because acquiring a
  shard raises its `R` and dilutes its own `1/R` payout, and because the per-staker
  curve is concave-to-cap), nets it against the bond cost and storage cost, and
  acquires/drops accordingly. Myopic best-response in iteration 1; richer learning
  is a later refinement only if myopic gives degenerate dynamics.

### What is held fixed (deferred-gate inputs)

Iteration 1 must not silently turn deferred-gate parameters into free knobs:

- **bond rate** — fixed (gate 4 sweeps it later).
- **Σwork servo / budget** — fixed normalizer (gate 1 stresses it later).
- **foundation floor / bootstrap** — iteration 1 runs at steady state (foundation
  absent or a fixed background coverage); the handoff dynamics are gate 5.
- **locked-supply re-pricing** — macro, not modeled here (gate 7 / the macro sim).
- **privacy firewall** — out of scope (a soundness/hygiene property, not economic).

### Sweeps (iteration 1)

The coverage thesis must hold across regimes, not at one lucky point:

- **Population thickness.** Thin → thick staker populations (the thin regime is
  where coverage is most fragile and where the foundation floor exists for a
  reason — iteration 1 reports where thin-population coverage breaks *without* the
  floor, which sizes the floor for gate 5).
- **Endowment mix.** Fraction storage-rich vs capital-rich; presence/absence and
  size of a Sybil whale.
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

- **Pass:** all four sub-claims hold across the swept regimes at a plausible fixed
  bond rate and cap. The coverage model is blessed; iterations 2+ proceed to
  calibrate the deferred gates on top of it.
- **Correctable finding:** a sub-claim fails in a specific regime in a way a model
  change addresses (e.g. deep-history under-`R` → the scarcity weight needs an
  age term; whale dominance → the cap or bond needs restructuring). Recorded,
  fed back, re-run.
- **Keystone-threatening finding:** coverage fails *because* `1/R` +
  cap + bonds are structurally insufficient (e.g. no fixed bond rate covers deep
  history without excluding storage-rich agents — gate 4's window is empty even
  before iteration 2 sweeps it). This is the result that sends the design back to
  the drawing board, and surfacing it cheaply is the entire point of doing the sim
  before building the subsystem.

## Later iterations (mapped, not specified)

Each layers onto iteration 1's coverage model; each has the gate it discharges and
the metric it needs. Specified when iteration 1 closes.

- **Iteration 2 — bond-rate window (gate 4).** Sweep `bond rate`; find the band
  that is simultaneously Sybil-deterring, deep-history-guaranteeing, and not
  storage-rich-excluding. Output: the window, or the finding that it is empty.
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

## Build decision (not part of this spec — flagged for the post-review PR)

Two viable shapes, decided after this spec is blessed:

1. **New crate `shekyl-staking-sim`** (agent-based) for iterations 1, 2, 4; wire
   macro numbers from `shekyl-economics-sim` for iterations 3, 5. Clean separation:
   the agent sim is a different instrument from the macro emission/burn sim.
2. **Extend `shekyl-economics-sim`** with an agent-based mode. Reuses the JSON/
   scenario harness; risks entangling two instruments with different granularities
   (year-macro vs epoch-agent).

The spec is implementation-agnostic; the recommendation (pending review) is **(1)**
— the macro sim is year-granular aggregate-supply and the coverage sim is
epoch-granular agent-based, and `15-deletion-and-debt.mdc`'s "two instruments,
two scopes" reading favors not overloading the economics sim.

## Open questions for review

1. **`R_target` source.** Is the durability replication floor a stated protocol
   constant (with a documented rationale per `75-system-autonomy.mdc`), or itself a
   sim output to be discovered? Iteration 1 assumes the former.
2. **Whale in iteration 1.** Include the Sybil whale as a coverage perturbation now
   (recommended — it stresses the "spread" sub-claim), or defer it entirely to
   gate-4/iteration-2 where its *cost* lives?
3. **Myopic vs learning agents.** Start myopic best-response (recommended for a
   first coverage read), escalate to learning only if myopic dynamics are
   degenerate?
4. **Single-region.** Iteration 1 omits network topology / latency-routing (the
   secondary market). Confirm that is acceptable for a coverage-incentive read, or
   whether routing materially changes acquisition behavior and must be in from the
   start.
