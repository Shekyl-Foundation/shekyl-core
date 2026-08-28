# Shekyl Design Concepts

> **Last updated:** 2026-07-19

> **Staking-model correction (2026-07-19).** Earlier revisions of this document
> described a **passive lock-tier PoS** staking model ("lock SHEKYL for a duration
> tier, earn by `staked_amount × duration_multiplier`") that was **retired before
> genesis** with the confidential-staking sweep
> (`docs/completed/LEGACY_CLAIM_ERA_RETIREMENT.md`;
> `rust/shekyl-economics/src/lib.rs`). Genesis staking is **archival
> pay-for-service**: stakers post on-chain bonds, join the archival market, and
> earn reward emission recomputed from **public serve-work** — there is no
> duration tier, no `staked_amount × duration_multiplier` weighting, and no
> claim/unstake wire. Component 3 and the participant lifecycle below have been
> rewritten to the live model. The canonical archival specs are
> [`docs/V3_STAKER_ARCHIVAL.md`](V3_STAKER_ARCHIVAL.md) (mechanism) and
> [`docs/design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md)
> (consensus reward leg). Components 1, 2, and 4 (release multiplier, adaptive
> burn + staker fee pool, decaying staker emission share) are unchanged and live.

## CALIBRATION gate (pre-genesis)

**Mechanism is structural; coefficient values are provisional until the
CALIBRATION milestone closes.**

Structural choices (trait surfaces, injection seams, primitive locations,
JSON-authority loading patterns, conservation invariants) are designed to
last — changing them after genesis is a planning failure. Tunable coefficients
(`burn_base_rate`, release-multiplier clamps, staker-pool shares, `FINAL_SUBSIDY`
floor, and the specific numeric values behind them) live behind
`config/economics_params.json` / `EconomicParams` so recalibration is a config
regen, not a code-shape or hard-fork event.

The **CALIBRATION** milestone (distinct from stressnet / Phase 7.7 load testing)
answers: *are the coefficients economically right on testnet?* Stressnet answers:
*does the stack survive load?* Exit criteria differ.

Implementation and tests for economics surfaces are split per
[`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](completed/STAGE_1_PR_7_ECONOMICS_ENGINE.md):
generation-invariant differential tests (engine vs `shekyl-economics-sim` on the
shared primitive) vs calibration-tagged value vectors (expected to churn each
generation). See that doc for `CALIBRATION-PENDING` code markers and the
`as_of` / param-epoch calibration-generation tag.

---

## Monetary Supply and Denomination Policy (Next Generation Shekyl)

This document proposes a concrete monetary design set for next-generation Shekyl, with rationale grounded in:

- Shekyl current implementation constraints.
- Comparative cryptocurrency monetary models.
- Mechanism-design research on long-run security budgets.
- UX goals for everyday currency use ("no satoshi-like pain").
- A self-regulating economic system with interlocking incentives for miners, stakers, and transactors.

---

## 1) Design Goals

Shekyl monetary policy should satisfy six constraints at once:

1. **Usability-first denomination**
   - Everyday users should rarely handle very long decimals.
   - Wallet defaults should feel natural for normal payment amounts.

2. **Long-run security budget**
   - Consensus participants must retain robust incentives after early issuance declines.
   - Design must avoid a brittle fee-only end state.

3. **Predictability and credibility**
   - Emission schedule should be simple enough to reason about.
   - Monetary policy should not require frequent governance intervention.

4. **Implementation safety**
   - Supply and atomic-unit arithmetic must remain safe under `uint64_t` accounting.
   - No overflow-prone parameter combinations.

5. **Demand-responsive emission**
   - The rate at which coins are released should reflect real network usage.
   - High transaction activity accelerates emission; low activity conserves supply.
   - Total supply remains fixed — only the release timeline is elastic.

6. **Self-regulating economic balance**
   - Miners, stakers, and transactors should form interlocking constituencies with complementary incentives.
   - The system should self-stabilize without manual governance intervention.
   - Staking behavior should implicitly govern deflationary parameters.

---

## 2) Historical Shekyl Baseline and Problem Statement

Historical constants from the original chain configuration:

- `MONEY_SUPPLY = 2^32`
- `COIN = 10^12`
- `CRYPTONOTE_DISPLAY_DECIMAL_POINT = 12`
- `FINAL_SUBSIDY_PER_MINUTE = 3 * 10^11` atomic units (**historical Monero
  reference only** — not Shekyl `economics_params.json`)

### Critical interpretation detail

**Shekyl authoritative floor:** `FINAL_SUBSIDY_PER_MINUTE = 300_000_000` atomic
units (0.3 SHEKYL/min) per the parameter tables below and
`config/economics_params.json`. The `3 × 10¹¹` figure above is inherited Monero
baseline prose; do not use it for fixtures, KATs, or `EconomicsParametersSnapshot`.

In Cryptonote-family code, `MONEY_SUPPLY` is interpreted in **atomic units**, not whole coins. Therefore:

- The **historical** 12-decimal interpretation of those constants yielded
  `2^32 / 10^12 = 0.004294967296` SHEKYL — not economically meaningful, and
  **not** the live genesis supply. Live denomination is 9 decimals
  (`config/economics_params.json`: `"display_decimal_point": 9`,
  `"coin": 1000000000`); see §3.

Reward logic in `src/cryptonote_basic/cryptonote_basic_impl.cpp`:

- `base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor`
- `base_reward` is clamped to a minimum via `FINAL_SUBSIDY_PER_MINUTE`

Given the mismatch above, the original chain effectively entered minimum-subsidy behavior immediately.

For Shekyl NG, constants are generated from `config/economics_params.json` and included via generated headers referenced by `src/cryptonote_config.h`.

Archival economic parameters (staker emission share and its yearly decay, staker
fee-pool share, and the archival reward-budget curve inputs) are read from the same
JSON so wallet and node stay aligned with the economics file. The retired lock-tier
constants (`TIERS`, `MAX_CLAIM_RANGE`, `shekyl_stake_max_claim_range`) belong to the
superseded claim-era staking model and are being removed
(`docs/completed/LEGACY_CLAIM_ERA_RETIREMENT.md`); genesis staking is archival bonds,
which carry no duration tier.

### Technical limit with `uint64_t`

If the target is `2^32` **whole coins**, then with atomic accounting:

- `MONEY_SUPPLY_ATOMIC = 2^32 * 10^decimals`
- Must satisfy `MONEY_SUPPLY_ATOMIC <= 2^64 - 1`

For `2^32` whole supply, the maximum safe decimal precision under `uint64_t` is:

- `decimals <= 9`

So `2^32` whole + 12 decimals is not representable in `uint64_t`.

---

## 3) Core Parameters (Fixed at Genesis)

### Headline constants

| Parameter | Value | Rationale |
|---|---|---|
| Headline supply target | `2^32` whole SHEKYL (4,294,967,296) | Large unit count avoids satoshi-style UX pain |
| Atomic precision | 9 decimals | Maximum safe precision under `uint64_t` with `2^32` supply |
| Atomic unit constant | `COIN = 10^9` | Standard CryptoNote convention |
| Core display precision default | 9 decimals | Matches canonical accounting (`1 SHEKYL = 10^9 atomic`) |
| Website/UI display precision | 6 decimals | Readability layer only; values are still stored/transmitted at 9-decimal fidelity |
| Block time target | 2 minutes | Standard CryptoNote block interval |
| Blocks per year | 262,800 | `(60/2) * 24 * 365` |
| Emission speed factor (base) | 22 | CryptoNote geometric decay — 50% emitted ~year 11, 80% ~year 25 |
| Tail emission | Bounded non-zero floor per block | Ensures perpetual security budget |

### `uint64_t` safety verification

- `MONEY_SUPPLY_ATOMIC = 2^32 * 10^9 = 4,294,967,296,000,000,000`
- `uint64_t max = 18,446,744,073,709,551,615`
- Headroom factor: ~4.3x
- Sufficient for all intermediate arithmetic including reward calculations

---

## 4) The Four-Component Economic System

The Shekyl economic model consists of four interlocking mechanisms operating on a single fixed supply constraint:

### Component 1: Transaction-Responsive Release Rate

Transaction volume controls how quickly the CryptoNote emission curve releases coins from the fixed `2^32` supply. This does NOT create additional coins — it adjusts the timeline of the predetermined emission schedule.

#### Mechanism

The standard CryptoNote block reward formula:

```
base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor
```

Is modified to:

```
effective_reward = base_reward * release_multiplier
```

Where `release_multiplier` is derived from a rolling average of transaction volume over the previous 720 blocks (~1 day):

```
release_multiplier = clamp(
    tx_volume_avg / tx_volume_baseline,
    RELEASE_MIN,       // e.g., 0.8
    RELEASE_MAX        // e.g., 1.3
)
```

#### Key properties

- **Fixed total supply:** Faster release now means smaller rewards later. The `2^32` ceiling is immutable.
- **Self-correcting:** Accelerated emission depletes the remaining supply faster, causing the geometric decay formula to naturally reduce subsequent rewards.
- **Anti-stuffing by design:** A miner who stuffs transactions to inflate the multiplier is "borrowing from the future," not creating money. The cost is real (burned fees); the benefit is a rearranged timeline that favors all miners equally, not just the stuffer.
- **Bootstrap protection:** Low early transaction volume means slow emission, preserving the supply budget for periods of genuine adoption.

### Component 2: Adaptive Fee Burn

A percentage of each transaction fee is permanently destroyed. The burn rate adjusts algorithmically based on three inputs: transaction volume, circulating supply ratio, and stake ratio.

#### Burn formula

```
burn_pct = min(
    BURN_CAP,
    BURN_BASE_RATE
        * sqrt(tx_volume / tx_baseline)
        * (circulating_supply / total_supply)
        * (1 + stake_ratio)
)
```

Where:
- `BURN_BASE_RATE`: Base burn coefficient (e.g., 50%)
- `BURN_CAP`: Maximum burn percentage (e.g., 90%)
- `tx_volume / tx_baseline`: Volume-driven scaling (sublinear via `sqrt`)
- `circulating_supply / total_supply`: Supply-maturity scaling (0.0 to ~1.0)
- `stake_ratio`: Staker-driven governance signal (see Component 3)

#### Fee distribution per block

```
total_fees = sum of all transaction fees in block
burned_amount = total_fees * burn_pct
staker_fee_pool = burned_amount * STAKER_FEE_POOL_SHARE    // 25% of burn → staker fee pool
actually_destroyed = burned_amount - staker_fee_pool        // 75% of burn → permanently destroyed
miner_fee_income = total_fees - burned_amount
```

#### Burn rate behavior across chain lifecycle

| Phase | Circulating % | Typical stake ratio | Typical volume | Approximate burn |
|---|---|---|---|---|
| Early (Founding Era) | 10-30% | 5-15% | Low (0.5x) | 5-12% |
| Growth Era | 30-60% | 15-30% | Medium (1-2x) | 15-35% |
| Maturity | 60-85% | 25-40% | High (2-4x) | 35-65% |
| Late (Tail Era) | 85%+ | 30-45% | Variable | 45-80%+ |

The burn automatically transitions the economy from inflationary growth (gentle early burns) to deflationary maturity (aggressive late burns) without any governance intervention.

### Component 3: Archival Staking (Pay-for-Service) and Implicit Governance

Staking is **pay-for-service archival**, and it is also the sole governance
action. A staker posts an on-chain bond, joins the archival market, and serves
chain data the network needs for FCMP++ proof construction; in return the staker
earns reward emission. There are no votes, proposals, or governance forums — the
protocol reads aggregate staking participation as a confidence signal and adjusts
the burn rate algorithmically. Staking is **not** a passive lock: there is no
duration tier, no `staked_amount × duration_multiplier` weighting, and no
claim/unstake transaction. The mechanism is specified in
[`docs/V3_STAKER_ARCHIVAL.md`](V3_STAKER_ARCHIVAL.md) (design home) and
[`docs/design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) (consensus
reward leg).

#### Why archival is the "useful work"

FCMP++ transaction construction needs the curve-tree state at historical heights,
which requires long-term archival of chain data. Rather than leaving this to
foundation-operated archival nodes (a centralization concern), Shekyl pays stakers
to perform distributed archival. Miners optimize for the current block; transactors
are transient; **stakers are the only actor class with a long-horizon economic stake
in the chain's health**, which is exactly what archival demands. Consensus-securing
work (capital at risk) and useful work (archival service) are decoupled and paid
from related-but-distinct reward streams.

#### Governance signal

```
stake_ratio = total_staked / circulating_supply
```

This ratio feeds directly into the burn formula via the `(1 + stake_ratio)` term.
Higher aggregate archival participation → higher burn rate → stronger deflationary
pressure → value preservation for holders. "Staking behavior implicitly governs
the deflationary parameters" remains true; the underlying action is now archival
market participation rather than a duration lock.

#### Staking mechanics

- **Admission:** An ordinary transfer moves principal to a firewalled pseudonym
  `P`; joining the market posts an on-chain bond record (`txin_archival_bond_post`)
  with the staker's holdings and bond posture. There is **no consensus minimum and
  no separate stake-output type** — admission is transfer-shaped.
- **Service:** The staker archives assigned chain data and answers retention
  challenges under `P`. Bonded reputation plus retention proofs establish that the
  service was actually performed.
- **Liquidity:** Funds at `P` may be spent freely between settlement epochs — the
  bond, not a protocol lock, is the honesty anchor. A misbehaving staker is
  slashable against the bond (gate 4). There is no unstake lock to wait out.
- **Compensation:** Two streams — (1) a share of the fee burn pool (Component 2),
  and (2) a decaying share of block emission (Component 4) — flow into a staker
  reward pool distributed by **verified serve-work** (below).

#### Staker reward distribution (loud, recomputed from public work)

Reward emission is **loud**: the emission transaction carries **public** work and
**public** mint amounts, and every verifier **recomputes** the payout from
consensus archival state plus the reward budget. The prover does not author a
confidential entitlement. Double-claim prevention is per-bond
claimed-settlement-epoch state, not a spend-tree nullifier or stake-keyed tag.

The pool is divided by **capped** serve-work (the anti-concentration "form C"
servo), not by stake size or lock duration:

```
// Combined reward budget for the settlement epoch
budget = fee_staker_pool (Component 2) + emission_staker_pool (Component 4)

// Each staker's work is capped by an anti-whale curve before division,
// so a single large actor's marginal work redistributes via the rate.
capped[a]  = Curve(work_a)          // plateau-capped serve-work
price      = budget / Σ_a capped[a]
reward_a   = price * capped[a]      // = budget · capped_a / Σ capped
```

Capping at the budget layer is deliberately anti-concentration: it widens the
reward spread across many small servers rather than paying a whale linearly for
raw volume. See `REWARD_EMISSION_LEG.md` §4 (form C) and `STAKER_ARCHIVAL_SIM.md`
for the calibration.

#### No consensus minimum

There is no minimum bond enforced at consensus. The yield for a tiny archival
footprint will be negligible, but participation has no protocol gate — the market,
not a threshold, decides viability.

#### Reward reception and privacy

A staker's reward is received as an ordinary transfer back to their principal
address; the emission *amounts* are public (loud), but the link between the
archival pseudonym `P` and the principal is protected by the gate-6 firewall
(HKDF-derived `P`, announce-before-anchor, multi-`P` hygiene). Once a reward output
matures into the curve tree, spending it is indistinguishable from spending any
other output.

#### Multisig for bonded value (operational security)

Long-lived bonded positions represent meaningful value held under a single key
over long horizons. Multisig authorization (`scheme_id = 2`) is the recommended
configuration for archival positions with significant value: a 2-of-3 multisig
ensures no single compromised key can control the bonded output or its rewards.
Multisig outputs use the same `pqc_auth` framework as regular transactions with
the extended signature-list format. See `docs/PQC_MULTISIG.md`.

#### Self-balancing dynamics

- If too many stakers join: reward per staker falls (fixed epoch budget divided
  across more capped-work), and marginal servers exit — restoring equilibrium.
- If too few stakers serve: reward per staker rises, attracting participants and
  restoring archival coverage.
- High stake ratio pushes the burn rate higher, increasing deflationary pressure —
  rewarding participation.
- Low stake ratio reduces burn, preserving miner fee income during downturns —
  protecting chain security when it is most vulnerable.

### Component 4: Staker Emission Share (Bootstrap Subsidy)

Fee-based staker yields are structurally insufficient during the early chain when transaction volume is low. To bootstrap meaningful staker participation, a decaying fraction of block emission is redirected from miners to the staker reward pool. (The pool is then divided among stakers by verified serve-work per Component 3, not by stake size or lock duration.)

#### The problem

Staker yield from fees alone = `(annual_fees × burn_pct × pool_share) ÷ (stake_ratio × circulating)`. At baseline early-chain parameters (50 tx/block, 0.10 SHEKYL fee, 20% burn, 25% pool share, 20% stake ratio), this produces approximately 0.02% annual yield — far below the threshold needed to incentivize staking.

The gap is approximately 50x. No combination of burn rate, pool share, or stake ratio parameters can close it without either destroying the deflationary mechanism or requiring unrealistic transaction volumes.

#### Mechanism

Each block, a fraction of the total emission is directed to the staker reward pool instead of the miner:

```
effective_share = STAKER_EMISSION_SHARE * STAKER_EMISSION_DECAY ^ years_since_genesis
staker_emission = block_emission * effective_share
miner_emission = block_emission - staker_emission
```

The decay is multiplicative per year, causing the emission share to decline exponentially. This creates a bootstrapping subsidy that fades out as the fee economy matures.

#### Key properties

- **No new coins created.** The emission share redirects a portion of each block's reward from the miner to stakers. Total emission per block is unchanged. The `2^32` ceiling is unaffected.
- **Self-retiring.** At 15% initial share with 10%/year decay: year 1 = 15%, year 5 = 8.9%, year 10 = 5.2%, year 20 = 1.8%. The subsidy naturally fades, transitioning staker income to fee-based sources.
- **Modest miner impact.** At peak (year 0), miners receive 85% of emission instead of 100%. By year 10, they receive ~95%, so the long-run effect on mining incentives is small.
- **Bridges the yield gap.** Produces 1.7% staker yield at year 10 under baseline conditions, and 4–6% during years 1–5, making staking genuinely attractive from launch.

#### Staker yield composition over time

| Year | Emission share (effective) | Yield from emission | Yield from fees | Total yield |
|---|---|---|---|---|
| 1 | 13.5% | ~30% | ~0.02% | ~30% |
| 5 | 8.9% | ~6% | ~0.02% | ~6% |
| 10 | 5.2% | ~1.7% | ~0.02% | ~1.7% |
| 15 | 3.1% | ~0.6% | ~0.03% | ~0.6% |
| 20 | 1.8% | ~0.2% | ~0.04% | ~0.2% |

Early yields are high because emission is large and circulating supply is small. As the chain matures, emission shrinks (geometric decay), the emission share shrinks (annual decay), and fee-based income grows (more transactions, higher burn rate). The handoff is gradual and requires no governance action.

---

## 5) The Participant Lifecycle

The economic system creates a natural progression for participants:

### Phase 1: Builder (Miner)

- Earns emission rewards by securing the network with proof-of-work.
- Income is highest in the early chain when the emission curve is steep.
- Motivated by a busy chain: transaction volume accelerates the release rate, increasing block rewards.

### Phase 2: Transition

- Mining hardware ages or the participant wants to move to other projects.
- Accumulated holdings back an archival bond, and the participant stands up an archival node.
- Staking yields become increasingly competitive as the chain matures and the burn pool grows.

### Phase 3: Keeper (Staker / Archival Server)

- The staker posts a bond, serves chain data under a firewalled pseudonym, and earns yield from two sources: emission share (dominant early) and fee burn pool (dominant late).
- The emission share provides attractive yields from day one, rewarding early believers.
- As the chain matures, yield composition shifts from emission-funded to fee-funded — no action required.
- Yield scales with **verified serve-work** (anti-whale capped), not with a duration lock; more useful archival service earns more, up to the concentration cap.
- The act of staking implicitly governs the burn rate — no active decision-making required.
- Principal at the pseudonym stays liquid between settlement epochs; the bond, not a lock, keeps the staker honest. Spending rewards feeds the very system that generates the yield.

### Value flow between participants

```
Block emission
  → Split: miner share (85-98%) + staker emission share (2-15%, decaying)

Transactors pay fees
  → Fees split: miner share + burn
    → Burn split: destroyed (deflation) + staker fee pool (yield)

Combined staker income (emission share + fee pool)
  → Stakers bond holdings and archive the chain (useful work + scarcity)
    → Distributed archival + scarcity support value
      → Value makes mining worthwhile
        → Mining secures transactions
          → Security attracts transactors
            → Transactors generate fees → (cycle repeats)
```

Every participant role strengthens the other two. No role is parasitic. The system does not require perpetual growth to remain stable — it only requires ongoing usage.

---

## 6) Anti-Gaming Analysis

### Transaction stuffing

Under this design, stuffing (creating fake transactions to inflate the volume metric) has fundamentally different economics than in a bonus-emission model:

**Why stuffing is weakened:**

1. **Release rate, not total supply:** Stuffing pulls coins forward from future emission; it does not create new coins. The `2^32` ceiling is immutable.
2. **Fee burn cost is real:** The `burn_pct` of every fake transaction's fee is irrecoverably destroyed. The stuffer cannot recover burned fees even if they mine the block.
3. **Benefits are socialized:** Accelerated emission benefits ALL miners proportionally, but the stuffer alone bears the burn cost.
4. **Self-limiting:** Higher volume increases the burn rate (via `sqrt(tx_volume / baseline)`), making each additional fake transaction more expensive.
5. **Dilution:** Accelerated emission dilutes the stuffer's existing holdings.

**Quantitative example (stuffer with 20% hash power, multiplier bounds 0.8x-1.3x):**

- Extra emission captured by stuffer: ~20% of the acceleration delta
- Burn cost: paid on 100% of fake transaction fees
- Net: marginally profitable in the short term, but "borrowing from the future" — subsequent block rewards are lower for everyone including the stuffer
- With tighter multiplier bounds (0.9x-1.2x), the profitability margin approaches zero

### Mining pool dominance

A large pool that also accumulates a staking position could attempt to extract maximum value from both roles. Mitigations:

- Archival rewards are paid for **verified serve-work capped by an anti-concentration curve** (Component 3, form C): a whale's marginal work redistributes to smaller servers via the price rather than paying out linearly, so buying a dominant reward share is structurally throttled.
- Posting a bond and running archival infrastructure is real capital and operational commitment, not a costless side-position; a slashable bond puts that capital at risk against misbehavior.
- Stake ratio governance is proportional — no outsized influence from single large stakers.
- The system is transparent: stake concentration and archival coverage are publicly visible and monitored as chain health metrics (`gini`/whale gauges in the sim calibration).

### Empty-chain manipulation

An attacker suppressing on-chain volume (e.g., running off-chain payment channels) to slow emission and then re-entering:

- Slow emission during low activity is a *feature*, not a bug — it preserves supply for genuine adoption.
- The attacker cannot capture the preserved emission without eventually generating on-chain transactions, which re-activates the release rate.

---

## 7) Quantitative Denomination Framework

To avoid uncomfortable tiny fractions in user-facing payments, choose decimal precision `d` using:

- `coin_price = market_cap / circulating_supply`
- `d >= ceil(log10(coin_price / min_payment_value))`

Where:

- `min_payment_value` is smallest practical payment denomination in fiat terms (e.g., `$0.01` or `$0.001`).

### Example with `supply = 2^32` whole

Approximate coin price by market cap:

| Market cap | Approx. coin price | Decimals needed for $0.01 |
|---|---|---|
| $1B | ~$0.233 | 2 |
| $100B | ~$23.28 | 4 |
| $1T | ~$232.83 | 5 |

Implication:

- 4-6 decimals already support cent-scale payments over a very wide market-cap range.
- 9 decimals offers ample protocol safety margin without forcing users to see tiny fractions.

---

## 8) Security-Budget Rationale

### Why avoid fee-only end state

Mechanism-design and mining-incentive literature indicates:

- Fee-only regimes can induce unstable strategic behavior. Carlsten et al. (2016) demonstrated that with only transaction fees, high variance in block rewards due to exponential block arrival times makes it attractive to fork "wealthy" blocks, leading to equilibria with undesirable security properties.
- Selfish mining becomes profitable for miners with arbitrarily low hash power in fee-only regimes.
- Transaction-fee mechanism design is non-trivial, especially with active block producers and MEV-like incentives (Roughgarden 2021, Bahrani et al. 2023).

### How Shekyl addresses this

- **Tail emission floor:** Miners always receive a minimum block reward regardless of transaction volume, preventing fee-only instability.
- **Release-rate scaling:** During high-activity periods, miners earn more from accelerated emission — their security contribution is rewarded proportionally to the chain's actual usage.
- **Adaptive burn protection:** During low-activity periods, the burn rate drops, directing more fee revenue to miners and maintaining security incentives when the chain is most vulnerable.
- **CryptoNote precedent:** Tail emission in production CryptoNote chains (e.g. Monero's 0.6 XMR/block since May 2022) has operated successfully for years, validating the approach for Shekyl.

---

## 9) Migration and Compatibility Guidance

If this design is adopted:

1. **Hard-fork activation**
   - Use a single, explicit activation height.

2. **Versioned monetary semantics**
   - For the rebooted chain, apply the new supply/precision semantics from launch.
   - Activate release-rate scaling, burn mechanism, staking, and PQ-enabled transaction rules as part of the rebooted runtime.

3. **Wallet/UI migration**
   - Preserve legacy display compatibility only where historical data or exported reports require it.
   - Introduce user-facing denomination aliases (e.g., milli-SHEKYL) if useful.
   - Implement the chain health dashboard (see Section 10).

4. **RPC and API compatibility**
   - Ensure all amount fields remain atomic-unit based.
   - Add explicit metadata for display precision in docs and client SDKs.
   - Expose new fields: `release_multiplier`, `burn_pct`, `stake_ratio`, `staker_pool_balance`, `staker_emission_share_effective`, `staker_yield_annualized`.
     - **Implemented:** `stake_ratio` and `staker_pool_balance` are wired to live chain state in `/get_info`. The dedicated `/get_staking_info` RPC returns all staking metrics.
   - Document the reboot-only PQ transaction format separately in `docs/POST_QUANTUM_CRYPTOGRAPHY.md`.

5. **Test coverage**
   - Unit tests for reward curve and tail state.
   - Unit tests for burn formula across all lifecycle phases.
   - Unit tests for staker reward distribution (fee pool + emission share).
   - Unit tests for emission share decay schedule accuracy over 30+ years.
   - Property tests for overflow boundaries (`uint64_t` limits), including worst-case bonus emission over a 1000-year horizon.
   - Property tests for intermediate arithmetic overflow in burn and reward calculations.
   - Integration tests for rebooted-chain transaction validation and node/wallet interoperability.
   - Simulation tests for stuffing profitability under various hash power distributions.
   - Unit tests for multisig `pqc_auth` (`scheme_id = 2`) serialization, verification, and rejection of malformed inputs.
   - Integration tests for multisig-backed archival positions: post a bond from a multisig-controlled output, spend/receive rewards with M-of-N authorization, and verify slashing authorization.
   - Size regression tests for multisig transactions across 2-of-3 through 5-of-5 configurations (target `MAX_MULTISIG_PARTICIPANTS = 5`; MSW-1 enforces).

---

## 10) Wallet Gamification and Chain Legibility

The economic system should be visible and comprehensible to participants through the default wallet interface.

### Chain health dashboard

| Element | Description |
|---|---|
| Emission Era | Named phase: Founding, Growth, Maturity, Tail |
| Emission progress | Percentage of total supply released, with era boundaries |
| Current release tempo | Release multiplier (e.g., "1.12x — moderately active chain") |
| Burn rate | Current effective burn percentage |
| Stake ratio gauge | Percentage of circulating supply staked, displayed as a health indicator |
| Total burned counter | Cumulative SHEKYL destroyed, ticking in real-time |
| Staker yield | Annualized yield for archival serve-work, with composition (emission vs fees) |
| Emission share gauge | Current effective staker emission share %, showing decay progress |
| Emission forecast | "At current pace, Maturity Era begins in ~X years" |

### Participant identity

| Role | Description | Wallet indicator |
|---|---|---|
| Builder (Miner) | Active PoW participant, earning emission rewards | Hash rate contribution, blocks found |
| Keeper (Staker) | Bonded holdings serving archival, earning emission share + burn-pool yield | Bonded amount, archival coverage/serve-work, yield earned, yield composition |
| Trader (Transactor) | Active user of the chain for payments | Transaction history, contribution to chain activity |

Users may hold multiple roles simultaneously. The wallet should reflect all active roles without forcing a single identity.

---

## 11) Parameters Requiring Simulation

The following parameters were tuned via simulation sweeps and are now resolved (see Section 13 for final values). Remaining parameters to be set from testnet data:

| Parameter | Status | Notes |
|---|---|---|
| `EMISSION_SPEED_FACTOR` | **Resolved: 22** | Swept 18–24; 22 gives optimal Builder era duration |
| `BURN_BASE_RATE` | **Resolved: 50%** | Swept 25–60%; 50% gives strong deflation with negligible miner impact |
| `STAKER_FEE_POOL_SHARE` | **Resolved: 25%** | Swept 10–40%; 25% balances yield with deflationary burn |
| `STAKER_EMISSION_SHARE` | **Resolved: 15%** | Swept 0–25%; 15% with 10%/yr decay delivers >1% yield through year 10 |
| `STAKER_EMISSION_DECAY` | **Resolved: 0.90/yr** | Tested against 0.80–1.0; 0.90 balances bootstrap with miner recovery |
| `RELEASE_MIN / MAX` | **Resolved: 0.8 / 1.3** | Tight enough to limit stuffing, wide enough for demand response |
| `BURN_CAP` | **Resolved: 90%** | High ceiling for mature chain, rarely reached in practice |
| `tx_baseline` | **Provisional: 50** | Validated by 8-scenario simulation sweep; locked pending testnet confirmation |
| `FINAL_SUBSIDY_PER_MINUTE` | **Provisional: 300,000,000** | 0.3 SHEKYL/min floor; validated by late-tail simulation; locked pending testnet confirmation |
| Archival reward-budget curve (`g` band, form C) | **Sealed: band `[1.5, 2.5]`, target ≈ 2** | Anti-concentration serve-work servo; see `REWARD_EMISSION_LEG.md` §1.2 / `STAKER_ARCHIVAL_SIM.md` |

### Simulation scenarios required

1. **Baseline steady-state:** Constant moderate transaction volume over 10 years.
2. **Boom-bust cycle:** 3x volume for 1 year, then 0.3x for 1 year, repeating.
3. **Sustained growth:** Volume increasing 20% per year for 20 years.
4. **Stuffing attack:** 20% hash power miner generating 5x fake volume for 30 days.
5. **Stake concentration:** Single entity bonding 30% of supply and capturing archival serve-work.
6. **Mass exit event:** 80% of stakers leaving the archival market within one epoch.
7. **Chain bootstrap:** First 2 years from genesis with very low organic transaction volume.
8. **Late-chain tail state:** 95%+ supply emitted, high burn, fee-market-dominated economy.

### Simulation harness

All eight scenarios above are implemented in `rust/shekyl-economics-sim/` and can be re-run with:

```
cargo run --package shekyl-economics-sim > docs/economics_sim_results.json
```

The harness uses the same formulas as the production `shekyl-economics` crate, driven from `config/economics_params.json`. The latest results are archived in `docs/economics_sim_results.json` for reproducibility and CI comparison.

---

## 12) Final Recommendation

Adopt the **Four-Component Model**:

1. **Fixed `2^32` whole SHEKYL supply** with 9-decimal atomic precision.
2. **Transaction-responsive release rate** that accelerates or slows the emission curve based on real network usage, without ever exceeding the fixed supply ceiling.
3. **Adaptive fee burn** driven algorithmically by transaction volume, chain maturity, and aggregate staking behavior — with a portion of the burn funding staker yields.
4. **Decaying staker emission share** that bootstraps meaningful staker yields from launch, funded by redirecting a small, declining fraction of block emission from miners to stakers.
5. **Implicit staker governance** where the act of locking coins is the sole governance input, eliminating the need for voting mechanisms.
6. **Wallet-first presentation** with a gamified dashboard making the economic system legible and engaging.

This design creates a self-regulating economic system where miners, stakers, and transactors form complementary constituencies. The system transitions automatically from inflationary growth to deflationary maturity, maintains perpetual security incentives through tail emission, bootstraps staker participation through a self-retiring emission subsidy, and resists gaming through interlocking negative feedback loops.

---

## 13) Optimal Parameter Set

The following values are derived from simulation sweeps across ESF, burn rate, staker pool share, and emission share configurations, tested against baseline, boom-bust, growth, stuffing, bootstrap, and chain-winter scenarios.

### Emission and supply

| Parameter | Value | Notes |
|---|---|---|
| `TOTAL_SUPPLY` | `2^32` (4,294,967,296) whole SHEKYL | Immutable ceiling |
| `COIN` | `10^9` | 9-decimal atomic precision |
| `DISPLAY_DECIMAL_POINT` | 9 | Core/wallet canonical display; parse/print aligns with `COIN = 10^9` |
| `EMISSION_SPEED_FACTOR` | 22 | 50% emitted ~year 11, 80% ~year 25 |
| `BLOCK_TIME_TARGET` | 120 seconds | Standard CryptoNote 2-minute blocks |
| `FINAL_SUBSIDY_PER_MINUTE` | 300,000,000 (atomic units) | 0.3 SHEKYL/min tail floor; provisional, locked pending testnet |

### Release rate (Component 1)

| Parameter | Value | Notes |
|---|---|---|
| `RELEASE_MULTIPLIER_MIN` | 0.8 | Floor: low activity slows emission by up to 20% |
| `RELEASE_MULTIPLIER_MAX` | 1.3 | Ceiling: high activity accelerates emission by up to 30% |
| `RELEASE_WINDOW_BLOCKS` | 720 | Rolling average window (~1 day at 2-min blocks) |
| `TX_VOLUME_BASELINE` | 50 | ~50 tx/block equivalent; provisional, locked pending testnet |

### Adaptive burn (Component 2)

| Parameter | Value | Notes |
|---|---|---|
| `BURN_BASE_RATE` | 50% | Base burn coefficient before scaling |
| `BURN_CAP` | 90% | Maximum burn under extreme conditions |
| `STAKER_FEE_POOL_SHARE` | 25% | Fraction of calculated burn redirected to staker fee pool |

Effective burn formula:
```
burn_pct = min(BURN_CAP, BURN_BASE_RATE × √(tx_volume / baseline) × (circulating / total_supply) × (1 + stake_ratio))
```

### Staking (Component 3)

| Parameter | Value | Notes |
|---|---|---|
| Consensus minimum bond | None | Any amount eligible; the market decides viability |
| Reward basis | Verified serve-work | Recomputed from public archival state; no duration tier |
| Reward division | Anti-concentration curve (form C), `g` band `[1.5, 2.5]`, target ≈ 2 | Caps whale share; see `REWARD_EMISSION_LEG.md` |
| Principal liquidity | Spendable between settlement epochs | Bond (not a lock) is the honesty anchor; slashable on misbehavior |
| Admission | Transfer-shaped (`txin_archival_bond_post`) | No separate stake-output type, no claim/unstake wire |

### Staker emission share (Component 4)

| Parameter | Value | Notes |
|---|---|---|
| `STAKER_EMISSION_SHARE` | 15% | Initial share of block emission directed to staker pool |
| `STAKER_EMISSION_DECAY` | 0.90 per year (multiplicative) | Share declines ~10%/year |

Effective share schedule:

| Year | Effective share | Miner receives |
|---|---|---|
| 0 | 15.0% | 85.0% |
| 1 | 13.5% | 86.5% |
| 2 | 12.2% | 87.8% |
| 5 | 8.9% | 91.1% |
| 10 | 5.2% | 94.8% |
| 15 | 3.1% | 96.9% |
| 20 | 1.8% | 98.2% |
| 30 | 0.6% | 99.4% |

### Projected outcomes at baseline (50 tx/block, 0.10 SHEKYL fee, 20% stake ratio)

| Metric | Year 1 | Year 5 | Year 10 | Year 20 |
|---|---|---|---|---|
| Supply emitted | ~6% | ~32% | ~50% | ~75% |
| Block reward (total) | ~970 | ~726 | ~531 | ~284 |
| Block reward (miner) | ~825 | ~661 | ~503 | ~278 |
| Effective burn rate | ~4% | ~17% | ~27% | ~40% |
| Staker annual yield | ~33% | ~6.3% | ~1.7% | ~0.2% |
| Miner income as % of no-share baseline | ~85% | ~91% | ~95% | ~98% |
| Net inflation (vs circulating) | ~100%* | ~14% | ~7% | ~2% |

\* Year 1 net inflation is high in percentage terms because the denominator (circulating supply) is very small. In absolute terms, the emission rate is moderate.

### Parameter interdependencies

```
ESF=22 ──────────────────────► Emission curve shape (fixed)
                                    │
RELEASE_MIN/MAX ◄── tx volume ──────┤
                                    │
                                    ▼
                            Block emission per block
                                    │
                    ┌───────────────┤
                    │               │
            STAKER_EMISSION    MINER_EMISSION
            _SHARE × decay     (remainder)
                    │
                    ▼
           Staker emission pool ──► Combined with fee pool
                                         │
                    ┌────────────────────┤
                    │                    │
              Fee burn pool         Miner fee income
                    │
            ┌───────┴───────┐
            │               │
    STAKER_FEE        Actually
    _POOL_SHARE       destroyed
       (25%)            (75%)
            │
            ▼
    Staker fee pool ──► Combined staker reward
                            │
                            ▼
                    Distributed by:
                    Curve(serve_work)  (form C, capped)
```

---

## 14) Research Appendix: Reward-Driven Privacy Enhancement

> **Re-walk note (2026-07-17, per Gate-6 §11.7 method note 5 — inherited
> privacy intuitions re-verify against what FCMP++ actually emits):** this
> appendix predates that discipline and carries ring-decoy-era framing.
> Corrected reading, mechanism by mechanism:
>
> - **The hypothesis's "mixing layer / clean coins" framing is
>   ring-era.** "No spending history" confers an advantage only where an
>   observer can trace spending history — i.e., on a visible spend graph
>   where decoy selection samples outputs. Under FCMP++ every output enters
>   the full-chain anonymity set identically; a fresh coinbase output adds
>   exactly what any other output adds.
> - **Mechanism A's harm model presupposes an observable FCMP++ does not
>   emit.** "Temporal correlation between *block mined at H* and *coinbase
>   output spent at H+N*" requires observing **when a specific output is
>   spent** — an FCMP++ spend never reveals which output it consumes, so
>   N is unobservable and there is nothing to decorrelate. Do not build
>   this.
> - **Mechanism B's observable is real.** Staker claims are P-attributed
>   and carry loud plain amounts on the wire (`REWARD_EMISSION_LEG.md`),
>   so claim frequency/timing is genuinely public; batching addresses an
>   observable that actually exists. This is the only mechanism here with
>   a live substrate.
> - **Mechanism C's gain reduces to "+K outputs in the set."** True but
>   marginal, and its stated benefit ("UTXO set diversity") is the
>   ring-era intuition restated.
>
> The hard-constraints list and the gate below remain sound as written.

### Hypothesis

Block rewards (both PoW and staker emission) create fresh UTXOs with no
spending history. If the reward disbursement path is designed with privacy as
a first-class constraint, these outputs could function as a built-in mixing
layer — every block injects "clean" coins into circulation, increasing the
effective anonymity set for all participants.

### Candidate Mechanisms

#### A. Delayed and Randomized Miner Reward Maturation

Currently, coinbase outputs have a fixed unlock delay. If the unlock time
were drawn from a random distribution (e.g., uniform over a configurable
window), an observer could not predict when a specific miner reward becomes
spendable. This desynchronizes miner-spend timing from block-found timing.

**Privacy gain:** Reduces temporal correlation between "block mined at height
H" and "coinbase output spent at height H+N."

**Risk:** Miners need predictable cash flow. A wide random window hurts
operational planning. Bounded randomness (e.g., base delay +/- 10%) is more
practical.

#### B. Staker Claim Batching and Route Obfuscation

Staker rewards are received via the loud reward-emission leg
(`REWARD_EMISSION_LEG.md`), which carries public amounts and is P-attributed.
If the protocol encouraged (or mandated) reward reception at coarser
settlement-epoch intervals rather than per block, the reception events become
less frequent and less attributable to specific serve periods.

**Privacy gain:** Reduces the number of on-chain events that link a staker
identity to a specific accrual period.

**Risk:** Delayed claiming increases the staker pool balance and creates a
larger target for accounting confusion. Batching must be exact or the pool
will drift.

#### C. Reward Output Shaping

Instead of a single coinbase output per miner, the miner transaction could
split the reward into K outputs of randomized denomination (summing to the
correct total). These outputs enter the UTXO set and are part of the full-chain
anonymity set used by FCMP++ membership proofs.

**Privacy gain:** More coinbase-shaped outputs in the UTXO set increase the
overall UTXO set diversity. With FCMP++, the full UTXO set is the anonymity
set, so additional outputs improve privacy indirectly by increasing set size.

**Risk:** Increases coinbase transaction size and adds consensus complexity.
Anti-sybil enforcement is needed to prevent miners from creating outputs
that only they can distinguish.

### Hard Constraints (Do-Not-Break)

Any reward-privacy mechanism must satisfy all of the following:

1. **No anonymity-set regression.** The change must not reduce the effective
   FCMP++ anonymity set or stealth-address unlinkability for any participant.
2. **No stuffing vector reintroduction.** The mechanism must not create a new
   profitable strategy for inflating transaction volume or manipulating reward
   timing.
3. **No hidden inflation or accounting ambiguity.** Total mined + staker
   rewards must remain exactly verifiable from the chain. No probabilistic
   or approximate accounting.
4. **No key material exposure.** Per the PQC security policy, secret keys
   must never be logged, serialized to plaintext, or exposed in error paths.
5. **No consensus fragility.** Randomized parameters must have deterministic
   seeds derived from block data so all validators produce identical results.

### Adversarial Analysis Summary

| Mechanism | Stuffing risk | Sybil risk | Inflation risk | Complexity |
|---|---|---|---|---|
| Random maturation delay | None (delay only) | None | None | Low |
| Claim batching | None | Low (timing alignment) | None if exact | Medium |
| Reward output shaping | Low (K is bounded) | Medium (distinguishable outputs) | None if sum-checked | High |

### Recommendation

**Random maturation delay** is low-risk and can be evaluated for v3 or early
v4. **Claim batching** is a natural fit for the staker reward redesign
already planned in the v4 privacy phase. **Reward output shaping** requires
significantly more research and should only be considered after lattice-based
further FCMP++ optimizations are available, as the privacy benefit depends
on UTXO set composition.

**Gate:** Promote to protocol proposal only if simulation confirms a
measurable privacy gain (e.g., >20% increase in effective anonymity set size
for typical spend patterns) with zero regression on the hard constraints above.

---

## 15) References

### Protocol and ecosystem docs

- Bitcoin BIP process (BIP-42 context): <https://bips.dev/42>
- Monero technical specs (CryptoNote/Shekyl lineage): <https://docs.getmonero.org/technical-specs/>
- Monero tail emission rationale: <https://web.getmonero.org/resources/moneropedia/tail-emission.html>
- Ethereum EIP-1559 specification: <https://eips.ethereum.org/EIPS/eip-1559>
- Cardano monetary policy: <https://docs.cardano.org/about-cardano/explore-more/monetary-policy>
- Cardano rewards/reserve flow: <https://docs.cardano.org/about-cardano/learn/pledging-rewards>
- Avalanche token model overview: <https://avax.network/about/tokens>
- Dogecoin inflation rationale: <https://dogecoin.com/dogepedia/faq/dogecoin-inflation/>

### Research and mechanism design

- Carlsten et al. "On the Instability of Bitcoin Without the Block Reward" (ACM CCS 2016): <https://dl.acm.org/doi/10.1145/2976749.2978408>
- Carlsten et al. discussion summary: <https://freedom-to-tinker.com/2016/10/21/bitcoin-is-unstable-without-the-block-reward/>
- Roughgarden, "Transaction Fee Mechanism Design" (arXiv 2106.01340): <https://arxiv.org/abs/2106.01340>
- Bahrani, Garimidi, Roughgarden, "Transaction Fee Mechanism Design with Active Block Producers" (arXiv 2307.01686): <https://arxiv.org/abs/2307.01686>

### Elastic supply and adaptive mechanisms

- Ampleforth elastic supply model: <https://www.ampleforth.org/papers/>
- AIER analysis of elastic cryptocurrency supplies: <https://aier.org/article/elastic-cryptocurrency-supplies-a-step-in-the-right-direction/>

### Denomination and unit-bias context

- Example summary on crypto unit bias: <https://www.nofreelunch.co.uk/blog/unit-bias-crypto/>
