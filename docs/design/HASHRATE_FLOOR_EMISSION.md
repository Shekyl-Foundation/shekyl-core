# Round 0: the hashrate floor on emission — 2026-11-19

**Status: PARKED (Rick, 2026-11-19).** Registered so it isn't forgotten. It is taken up only after the existing economics work is finished (EUP-4 prep, EUP-4, and the J, G, F and I rulings). No brief, measurement or model starts from this note until Rick reopens it. Nothing here is built. Ground: `dev` at `59ffce75`, read from a fresh fetch.

**Identifier family:** `HF-`, registered at birth (rule 194) in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2. No `HF-` identifier is minted yet.

## 1. Rick's intent (2026-11-19)

- Early emission shouldn't reward being first. A quiet launch must not hand a few miners a large stake.
- The same rule applies at any time: if hashrate falls under a floor, emission slows with it. That also defeats spike-and-drop.
- It's a last-ditch measure for when the bottom falls out. The hope is that it never triggers after launch.
- No calendar gate and no one-way latch.
- The threshold is a fixed amount of work, so it ages out as hardware improves. That's wanted.
- The threshold is set from testnet mining. The behaviour is modelled before it's ruled.

## 2. The rule

Below a threshold difficulty `D*`, the block reward scales with difficulty:

```text
reward = full_reward × min(1, D / D*)
```

- `D` is the block's own required difficulty, which consensus already has. It comes from LWMA-1 over 90 blocks at a 120 s target (`shekyl-difficulty`, `config/consensus_constants.json`), so it's already a three-hour average.
- Below `D*`, every hash earns the same expected coins: `full_reward / D*`. Being early, or mining while others have left, earns nothing extra.
- At or above `D*` the reward is the full curve's, as today.
- Coins not paid stay in the curve. Production advances `already_generated` by the reward actually paid, so nothing is destroyed and total supply is unchanged.

## 3. What it does and doesn't do

**Does:**

- **Removes the early-miner advantage.** Genesis difficulty is 400, so the first blocks pay almost nothing and the reward rises as miners arrive.
- **Makes spike-and-drop pointless.** A spike earns the same per hash as steady mining, and the reward falls again when the spike leaves.
- **Can't be faked cheaply.** Difficulty rises only with real work. Timestamp games within the 540 s future limit can nudge it, but coins per hash are constant below `D*`, so there's nothing to gain.
- **Gives nobody a reason to keep others out.** Below `D*`, new miners don't dilute existing ones.

**Doesn't:**

- **Stabilise hashrate below the floor.** In ordinary proof of work, when miners leave, the rest earn more per hash. Under this rule they don't. In a price collapse, hashrate is simply "everyone still profitable at the fixed rate", and it falls further than it would today.
- **Protect security in a collapse.** It cuts the security budget at the moment the chain is weakest. Its purpose there is to stop full-rate coins going to a handful of miners, not to defend the chain.

## 4. Variants to model

- **V0, none:** production today. The control.
- **V1, proportional:** the rule in §2.
- **V2, proportional with a floor:** the factor never drops below `f` (candidates 0.1 and 0.25). Below that, ordinary behaviour returns and remaining miners earn more per hash.
- **V3, partial response:** the factor is `(D / D*)^a` with `a` under 1 (candidate 0.5). Leaving miners still raise pay for the rest, but less than today. In integers this needs an exact root; state it or drop the variant.
- **V4, launch-only (for comparison):** V1 with a one-way latch after the first sustained crossing. Rick has set this aside; it's here so the model shows what the latch would have cost or saved.

## 5. Open design questions

1. **What the factor multiplies.** Options:
   - the whole emission (miners' and stakers' shares);
   - the miners' share only.

   Stakers' storage costs don't fall when hashrate does, so the second deserves a look.
2. **The tail.** Does the factor apply to the tail emission? If it does, the long-run security floor can be cut. If it doesn't, the rule fades out by design as the curve flattens.
3. **What else reads the reward.** The fee floor is `R·C·w_ref/M²` and the block-size penalty is a share of the reward. If both read the gated reward, fees and the cost of block growth fall when hashrate falls, which makes spam cheapest when the chain is weakest. Recommended: both read the full curve's reward, and only the payout is gated.
4. **Other networks.** `D*` is data per network (rule 171). Regtest and testnet need a value that leaves their rewards usable, and it must be data, never a branch.
5. **The restated predictability row.** It assumes the release rails. This rule adds a second way emission can slow, with no lower bound in V1. The row needs a line for it.
6. **Its place among the economies.** Hashrate follows price and can't be faked for less than it earns, so this is a demand-linked emission signal that passes the test the transaction count failed. It only works downward. It could be a fourth candidate beside the three on the whole-system page.

## 6. Setting the threshold

- **Measure on testnet:** hashrate per machine for a stated set of reference hardware, and the network hashrate through a public mining period.
- **State the target in plain terms:** full emission once mining is at least as broad as N reference machines. `D*` is then N × the reference rate × 120 s.
- **State how it ages:** with an assumed rate of hardware improvement, the year in which a small number of machines meets `D*`. Rick wants it to fade; the note should say when.
- **Derivation is recorded before the model is graded.** No threshold is picked after seeing its result.

## 7. Adversarial cases

- **Quiet launch:** a handful of machines for the first weeks.
- **A whale at launch:** one operator with most of the hashrate.
- **Spike and leave:** rented hashrate for hours or days, then gone.
- **Timestamp manipulation** within the future limit and the median-time rule, to raise or lower difficulty.
- **A price collapse:** 90 % in a month, and a slow bleed over two years.
- **Withdrawal by a large miner:** does it hurt the others? (Below `D*` it shouldn't: their pay per hash is unchanged.)
- **Selfish mining and block withholding** near the threshold.
- **A 51 % attacker's cost** through each case, against V0.

## 8. What the sim needs

The sim has no price or hashrate today. This needs a small model, kept separate from the fee and block-space folds:

- a price path per scenario (stated, not fitted);
- miners as a cost distribution, so hashrate at any pay per hash is "everyone below that cost";
- a response lag for miners joining and leaving;
- production's own LWMA-1 from `shekyl-difficulty` for difficulty, called and not copied;
- production's emission curve for the full reward.

**Measures:**

- the share of supply paid to the first 1, 7, 30 and 90 days' miners, and how many miners that was;
- hashrate against V0 through each scenario;
- the cost to buy a majority of hashrate for a day, against V0;
- the emission timeline against the full curve;
- the fraction of time the rule binds after year 1.

Predictions are committed before the first run, as for every instrument.

## 9. Sequence

1. Rick rules on this note's shape and the open questions in §5 that he wants settled before modelling.
2. Testnet measurement for §6 (the mining and CI lanes).
3. The model and its runs (the economics-sim lane, after EUP-4 prep).
4. Rick rules on the variant and the threshold, together with J, G, F and I.
5. If adopted: a consensus change after alpha.12, with the reward rule in `shekyl-economics`. A per-network `D*` moves `CONSENSUS_CONSTANTS_DIGEST` (built in `shekyl-rpc-types`); it is not a persisted-schema change.
