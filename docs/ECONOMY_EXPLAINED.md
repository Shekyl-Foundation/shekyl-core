# The Shekyl economy, explained

> **Status:** human-friendly explainer, written 2026-06-11. Mechanisms described
> here are structural and designed to last. **Specific coefficient values are
> provisional until the CALIBRATION milestone closes** (see
> `DESIGN_CONCEPTS.md` §CALIBRATION gate) — they live in
> `config/economics_params.json` and may be retuned on testnet evidence.
> Trajectory numbers below come from `shekyl-economics-sim` runs against the
> consensus integer math (gate-7 iteration-5, 2026-06).
>
> Deeper reading: `V3_STAKER_ARCHIVAL.md` (archival economics spec),
> `design/STAKER_ARCHIVAL_SIM.md` (simulation ledger),
> `design/REWARD_EMISSION_LEG.md` (emission mechanics),
> `PUBLIC_NARRATIVE_FAQ.md` (positioning and service promise).

## The big picture

Shekyl has one fixed supply — 4,294,967,296 coins (2³²) — and four interacting
control loops that decide *who* receives newly released coins, *how fast* they
release, and *how many fees get destroyed*. None of the loops needs governance
or manual tuning; each reads an on-chain quantity (transaction volume,
emitted-supply fraction, staked fraction, archival work claims) and adjusts
automatically. The design goals — low burn, fair split between miners and
stakers, strong participation incentives on both sides — fall out of how the
four loops push against each other.

A deliberate structural choice underlies all of it: **Shekyl's proof-of-stake
is not "yield on locked capital." It is payment for archival work**, with a
small accountability bond. That single decision is what makes the
participation loop self-regulating, and it is what the gate-7 locked-supply
simulation confirmed numerically.

## Loop 1 — The emission curve (the PoW backbone)

Every block releases `(remaining_supply >> 21)` atomic units, floored at a
perpetual tail of 0.6 coins/block (0.3 coins/minute × 2-minute blocks). At
genesis that's **2,048 coins per block**; the curve decays smoothly as supply
empties:

| Year | Avg block reward | Supply emitted | Net inflation |
|---|---|---|---|
| 0 | ~1,807 | 11.8% | — |
| 5 | ~966 | 52.9% | 13.5% |
| 10 | ~516 | 74.8% | 4.7% |
| 20 | ~147 | 92.8% | 1.04% |
| 29 | ~48 | 97.7% | 0.31% |

(Sim output against the consensus integer math, not estimates.) By year 30 the
chain is effectively in its fee era, with the 0.6-coin tail preventing the
"zero subsidy" security cliff forever.

## Loop 2 — The release multiplier (demand-responsive pacing)

The curve above isn't applied raw. Each block's reward is scaled by
`clamp(tx_volume / baseline, 0.8, 1.3)`, where the baseline is 50 transactions
averaged over a 720-block (~1 day) window.

**Example:** suppose the base reward at some height is 1,000 coins.

- Quiet chain (20 tx/block avg): multiplier clamps to **0.8** → 800 coins
  released.
- Baseline activity (50 tx): **1.0** → 1,000 coins.
- Busy chain (80 tx): 80/50 = **1.6, clamped to 1.3** → 1,300 coins.

This never creates coins — it only re-times the same fixed supply. When the
economy is hot, coins release faster to meet demand; when it's cold, release
slows and scarcity supports the price. It is the supply-side half of the
regulator.

## Loop 3 — The adaptive burn (demand-responsive fee destruction)

The demand-side half. A fraction of each block's **transaction fees** (never
the subsidy) is burned:

```text
burn_pct = 50% × sqrt(volume/baseline) × (emitted/total_supply)
                × (1 + stake_ratio), capped at 90%
```

Three things keep the burn rate low where it should be low:

1. **It only touches fees.** Block subsidy is never burned, so miner security
   funding is insulated.
2. **The supply-ratio term suppresses it early.** At year 0 only ~12% of
   supply is out, so the effective burn is just **~5.9% of fees**. It rises
   with maturity: ~26% at year 5, ~37% at year 10, ~49% at year 29 — exactly
   when fee destruction starts doing useful deflationary work against a
   nearly-fully-emitted supply.
3. **A quarter of "burned" fees aren't destroyed** — they're redirected to the
   staker pool (`staker_pool_share = 25%`).

**Worked example, year 10** (burn rate 37.4%): a block carries 10 coins of
fees.

- Burned amount: 3.74 coins.
- Of that, 0.94 coins go to the staker pool; **2.80 coins are actually
  destroyed**.
- The miner keeps the unburned 6.26 coins of fees, plus the full ~492-coin
  subsidy share.

Notice the symmetry with Loop 2: high activity simultaneously *releases more
subsidy* (multiplier up) and *destroys more fees* (sqrt-volume term up). The
two act as opposing spring forces around the activity baseline.

One honest caveat: the `(1 + stake_ratio)` term is currently **inert** — the
gate-7 simulation showed bonds-only staking locks so little supply that the
factor never moves off 1.0. A FOLLOWUPS item (target V3.1) re-evaluates it;
today the burn is governed by volume and supply maturity alone.

## Loop 4 — The staker emission share (the PoS bootstrap subsidy)

Each block's emission is split before the miner sees it: a slice goes to the
staker/archival reward pool, starting at **15% and decaying ×0.90 per year**:

| Year | Staker share | Miner keeps (vs. no-share counterfactual) |
|---|---|---|
| 0 | 15.0% | 86.5% |
| 5 | 8.86% | 92.0% |
| 10 | 5.23% | 95.3% |
| 20 | 1.82% | 98.4% |
| 30 | 0.64% | 99.4% |

**Concrete numbers at year 0:** a ~1,807-coin block sends ~244 coins to the
staker pool and ~1,563 to the miner. **At year 10:** ~516 total → ~24 coins to
stakers, ~492 to the miner.

The decay is the fairness mechanism over time: stakers get a meaningful
bootstrap subsidy while the archival network is young and fee income is thin;
miners progressively reclaim nearly the whole subsidy as the staker pool
transitions to its permanent funding source — the 25% fee-burn redirect from
Loop 3. By the fee era, archival is fee-funded and mining keeps both the tail
subsidy and the majority of fees. Neither side's income depends on squeezing
the other.

## What stakers actually do, and why participation self-regulates

A staker bonds **0.75 coins per shard slot** and commits to storing a shard of
chain history (one shard per 10,000-block settlement epoch, ~13.9 days). Each
epoch they prove retention and are paid from the staker pool **proportional to
verified work** — payment for service, not yield on stake.

This is where the most important regulating behavior lives, and it is emergent
rather than tuned. The staking-market simulation (ledger entry L11 in
`design/STAKER_ARCHIVAL_SIM.md`) modeled a pool of potential archivers, each
with a private reservation yield ρ (their opportunity cost of capital and
storage), and let them enter or exit freely. The result is a **transfer
function: budget → APR → marginal entry → archiver count → coverage**:

| Reward budget | Emergent archiver count | Deep-coverage shortfall |
|---|---|---|
| 50 | 43 | 1.000 (underfunded) |
| 100 | 79 | 0.002 (funded) |
| 200 | 154 | 0.000 (overfunded, well-spread) |

And sweeping the opportunity cost at fixed budget:

| ρ (alternative yield) | Archivers | Coverage |
|---|---|---|
| 1% | 101 | full |
| **2%** | **79** | **full (the lean equilibrium)** |
| 3% | 65 | knee — gaps open |
| 5% | 50 | broken |

The equilibrium at ~79 archivers is an **attractor**: boot the system from
zero participants or from oversubscription, and it converges to the same
point, because entry continues exactly until the marginal archiver's pay
equals their reservation yield. If rewards run rich, new archivers join and
dilute per-archiver pay back to breakeven. If rewards run thin, the
highest-opportunity-cost archivers exit first — and the simulations show
coverage degrades *gracefully* (oldest shards thin first, churn backfills, no
death spiral) rather than cliff-collapsing.

So "encourage participation" isn't a fixed APR promise — it's a servo. The
protocol sets the purse (Loops 3+4); the market sets the population.

## Why staking doesn't distort the money supply

Because PoS here is work-priced rather than capital-priced, the capital
actually locked is tiny. The gate-7 simulation traced the real locked-supply
trajectory under the pinned constants: **117 coins locked at year 0, growing
to ~3,546 coins by year 30 — at most 0.000085% of circulating supply.** Every
macro gauge (burn, inflation, miner income, emission pace) was numerically
insensitive to it. That is why there is no admission minimum at any layer: a
Sybil identity is priced by `0.75 × shards` at market join (a year-30 archiver
with a ~60-shard portfolio posts ~45 coins), and no larger lock would do any
economic work.

It also means stakers face nearly zero capital-lockup risk — another
participation incentive: the cost of being an archiver is *storage and
bandwidth*, compensated by the pool, not frozen wealth.

## Putting it together: one block at year 10

- Base curve says ~516 coins; chain is at baseline activity so the release
  multiplier is 1.0 → **516 coins emitted**.
- Split: **~24 coins to the staker pool** (5.23% share), **~492 to the miner**.
- Fees total 10 coins; burn rate is 37.4% → **2.80 coins destroyed**, **0.94
  to the staker pool**, **6.26 to the miner**.
- Miner's block income: ~498 coins. Staker pool inflow: ~25 coins, divided
  among ~79 archivers by verified epoch work — which over an epoch is what
  holds the population at its breakeven attractor.
- Net inflation that year: 4.7% and falling; locked supply: ~1,300 coins out
  of 3.2 billion circulating.

Every number above moves automatically: more usage → faster release, higher
burn, fatter fee flow to both miners and stakers; less usage → slower release,
lighter burn, and the archiver set leans out along its graceful-degradation
path. The only constants a human ever chose are the curve parameters — and
each of those has a sim-banked rationale and a reversion clause.
