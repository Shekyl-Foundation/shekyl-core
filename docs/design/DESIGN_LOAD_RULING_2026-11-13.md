# Design load vs. block weight — ruling and econ-sim question, 2026-11-13

Raised by the CI lane's D2 (#1365, block-template row). Applies to the CI lane, the chain forge lane (Chain P) and the economics sim lane.

## The facts (dev, `config/consensus_constants.json`)
- Penalty-free zone: 300,000. Block limit = 2 × short-term median (100-block window), clamped to [LTEM, S·LTEM] with S = 3. LTEM is floored at the zone, over a 100,000-block window.
- A 2-in/2-out spend weighs 21,184 (the #1365 fixture). The coinbase takes about 1,400 of the block.
- **At genesis:** about **14 spends a block are penalty-free**, which at 120 s blocks is **about 7 a minute, or about 10,000 a day**. The hard limit is about 600,000, or 28 spends, and a block that size burns the whole reward.
- **Cause:** the 300,000 zone comes from Monero, where it was sized for transactions of about 1.5 KB (on the order of 200 per block). Shekyl's post-quantum spends are about 14× heavier, and the zone was never rescaled for that.

## Ruling (Rick, 2026-11-13)
1. **The design load stays at 30 spends a block (2-in/2-out) for now.** It's the steady-state assumption every PB budget is stated against. It is not lowered to fit a genesis fixture.
2. **#1365's template row is accepted at 28**, labelled as the most a genesis-median block holds. It is re-measured at 30 on a forge chain with grown medians.
3. **Chain P (forge, CF-6)** ramps the medians under the real rule, with miners taking the penalty, before its 30-spend segment. The ramp is derived when the plan is built, using the validator's own median functions, not hard-coded.
4. **The block size will be re-derived through the economics sim.** Rick expects somewhere around 90 spends a block. Until the sim produces a number, everything is built at 30. Redoing the PB rows, fixtures, Chain P and the fee derivation when the number changes is an accepted cost of getting it right.
5. **Not before alpha.12.** Changing the number has knock-on effects:
   - the zone is a consensus constant;
   - the fee ladder and fee floor were derived against the current zone;
   - PB-R2 and the other floor-device budgets would move;
   - every fixture and corpus would need re-mining;
   - it is a consensus change under the shard-fill freeze.

   So it is not trivial, and it waits until at least after alpha.12.

## Constraints a ~90-spend zone must be checked against (about 1.9 MB)
- PB-R2: writes of at most 1 GB a day on the floor device. 720 full blocks a day is about 1.4 GB before indexes.
- Chain growth of about 500 GB a year at full blocks: pruning, archival bond and shard economics.
- Per-block FCMP++ verification on the floor device: PB-D1 (adversarial block) and PB-D3 (stress catch-up at 1.5× chain growth).
- Propagation over Tor: a larger block raises the orphan rate and favours well-connected miners.
- Spam pricing: a larger free zone makes junk blocks cheaper, so the fee floor and ladder have to be re-derived.
- Whether S (3) and the long-term window (100,000) still make sense at the new zone.

## Questions for the econ sim
- Is a penalty-free capacity of about 14 spends a block (about 10,000 a day) at launch right for Shekyl? Or should the zone be rescaled for post-quantum transaction weight, for example stated in "reference transactions" rather than bytes?
- Under sustained demand above the zone, do fees ever pay for the penalty, so that miners grow the median? Or does launch-era demand stall in the pool? How long does a ramp from genesis to the design load take under realistic fee behaviour?
- Does the answer change the surge factor S (interim 3) or the long-term window (100,000)?
- Adversarial angle: a larger zone makes spam cheaper (more blocks of junk for free), and a smaller one lets a fee war price out ordinary users. The sim should run both.

The zone and windows are consensus constants frozen at genesis, so this has to be settled before genesis.
