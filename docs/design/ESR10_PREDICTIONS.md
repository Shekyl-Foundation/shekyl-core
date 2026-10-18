# ESR-10 prediction set — fee multiplier and rung mix, on both constant arms

**Status:** OPEN — predictions written 2026-10-17, before the run. Outcomes
land in [`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md)
§5 when ESR-10 runs. Nothing here is a result.

Design-owner predictions for ESR-10 (`ECONOMICS_SIM_PRODUCTION_REBASE.md`, §3 row and the 2026-10-03 amendment), written against `dev@06690efab` before any ESR-10 code exists; corrected 2026-10-17 against `dev@d2ac8b45` (growth conditions on `ρ`, not `C`; see §1). The agent registers them in the rebase doc's §5 **before the first run**, verbatim in substance, and reports outcomes in a following "what the run said" table. Nothing here authorizes a production change; §0 names the two places where ESR-10 needs one.

## 0. What has to be built before anything can be run

1. **A pool that holds more than one fee class.** `BlockSpace` (`block_space.rs`) models identical transactions: one weight, one fee, oldest first, and `admit_up_to` stops at the first refusal. A rung mix needs one waiting queue per rung, offered **by fee rung first, then by age**, which is the daemon's own order (`fill.rs:20`, "by fee, then by receive time"). Walk the classes from Priority down. A refusal inside a class ends that class and every class below it, because the weight is the same and the fee is lower. A tie-break on age inside a class keeps the livetime-expiry model as it is. This is the instrument's change, not production's: `Fill` already takes any order.
2. **The re-derived arm's zone needs a single source of truth for the zone.** The zone has two readers on `dev`:
   - `shekyl_economics::penalty_free_weight` reads `params.full_reward_zone` (`emission.rs:100`);
   - `shekyl_chain_rules::medians_from` floors at the constant `FULL_REWARD_ZONE` (`block_weight.rs:291`).

   They agree only because the two are generated from the same config value. That's a rule-05 defect on the consensus surface whether or not ESR-10 exists: a parameter set that moves one moves half the rule. **Recommendation (Rick's ruling, since it touches `shekyl-chain-rules`):** `medians_from` takes the zone from `EconomicParams`, in its own commit. At shipped parameters the behaviour is identical, which a test pins. The re-derived arm is then expressible through parameters alone, with no declared divergence. Rejected alternative: a sim-local median floor, which would restate a consensus rule in the sim (the thing ESR-8 just finished removing).
3. **The re-derived constants, derived and not typed.**
   - `w_ref′` is the ordinary 1-in/2-out weight from `shekyl-tx-weight` at **genesis tree depth**, because the constant is fixed at genesis.
   - `zone′ = 100 · w_ref′` keeps the inherited ratio of 100 reference transactions to the zone. That ratio is itself inherited and is declared as such; the zone's capacity leg remains its owner's ruling (`FOLLOWUPS.md`).
   - Both are integers in bytes, computed by calling the weight function, with a test that prints them and pins the derivation, not the number (the `bond_duration` precedent).
   - Declare that the ordinary weight grows with depth (the narration shows about 7 % by y20), so `w_ref′` describes the transaction at genesis and is not a running quantity.

## 1. The mechanism the predictions rest on (stated so a miss says which part was wrong)

This is the rebase doc's own reading-pass findings 1 and 2 (`w ≤ 4ρ·w_ref·(m/M)²`, `ρ = (1−σ)/(1−b)`), extended to the other rungs. **Corrected 2026-10-17:** the first draft of this set used `C`, which includes `M_r`. `M_r` scales the penalised emission and the fee alike and cancels (finding 2), so every growth condition below is on `ρ`, and `C` enters only fee *levels*.

Under the reward-aware fill on the gross coinbase, the k-th transaction past the penalty-free weight is admitted iff its fee covers the reward it costs, `R·M_r·[(x_k)² − (x_{k−1})²]`, with `x = W/M − 1`. The ladder's rungs are:

- **Economy** = `F = R·C·w_ref/M²` per byte;
- **Standard** = `4F`;
- **Priority** = `max(2RC/M, 4F)`.

Three consequences follow, each falsifiable:

- **M1: R and `M_r` cancel for Economy and Standard.** Fee and penalty are both proportional to `R·M_r`, and both scale as `1/M²`. Whether a Standard transaction buys one more transaction's room is therefore a condition on `m·ρ` alone. The threshold `θ = w/(4·w_ref)` (1.22 on the doc's figures) is independent of year, reward and median.
- **M2: the ratchet.** Because the condition is scale-invariant in `M`, once `m·ρ ≥ θ` every block takes one transaction past its median. The long-term median follows, and growth continues until demand is carried. Growth is a **switch at a ρ threshold**, not a slope.
- **M3: Priority buys to `M·(1 + ρ)`.** Priority's per-byte fee scales as `1/M` against a marginal penalty of `≈ 2R·x·w/M`, so a Priority transaction is admitted while `x ≤ ρ`, capped at `2M − reserve`. Priority can grow a block only when Priority demand exceeds the penalty-free room.

Operands, from code (`config/economics_params.json`, `fee_correction`, `calc_burn_pct`, `emission_share`):

- `C = (1−σ)·M_r/(1−b)`.
- `σ = 0.15·0.9^t`, starting at block 1.
- `M_r = clamp(V/50, 0.8, 1.3)`.
- `b = 0.5·√(V/50)·s`, clamped at 0.9, where `s` is net supply / curve total.
- `ρ = (1−σ)/(1−b)`; ESR-9's growth-gate table (#1104) measures `ρ = 0.879` and `θ = 1.188` in year 1 on the baseline, and the crossing in year 19 in every constrained scenario except boom-bust (year 17), each growing in its crossing year. That is M1/M2's premise, measured.
- Fee level only: on the inherited arm while 22 of 50 are carried, `M_r = 0.8` and `C₀ ≈ 0.70`; on the re-derived arm, where 50 of 50 are carried, `M_r = 1.0` and `C₀ ≈ 0.87`.

Inherited `θ = w/(4·w_ref)`: 1.188 in year 1, 1.220 from year 2, 1.274 from year 23 (it steps with tree depth). On the re-derived arm `w/w_ref′ = 1`, which puts `θ′ = 0.25`.

**Already visible in the committed fixture, and consistent with M1/M2:** every scenario whose demand exceeds the room (baseline, stuffing, stake, unstaking, sustained growth, high-history) carries about 22 through y15 and switches between y15 and y20, whatever its demand level. One ρ threshold, crossed in the same window, in every scenario.

## 2. Predictions — inherited arm (`w_ref = 3 000`, zone 300 KB)

- **P1. The `×1` all-Standard column equals the default report byte for byte.** This is the registered falsifier, and it covers every scenario and every table.
- **P2. Multiplier sweep `m ∈ {1, 1.25, 1.5, 2, 3}`, all Standard.**
  - Growth onset is the first year with `m·ρ(t) ≥ θ`, and θ is one number for every `m` and every scenario.
  - The run prints `ρ(t_g)` per cell, and P2 holds if those agree to within the one-transaction granularity, `(w/M)²`-sized.
  - `m = 1`: the fixture's y15–y20.
  - `m = 1.25`: earlier, y4–y10.
  - **`m* = θ(y1)/ρ(y1) = 1.188/0.879 ≈ 1.35` (register 1.30–1.40), the operands from ESR-9's growth-gate table (#1104), not from any ESR-10 run:** at and above it, all demand is carried from year 1, within one long-term-median adaptation. No constrained era at all.
  - Read: the constrained era behind reading-pass finding 1 is a knife-edge of `m·ρ₀` against `θ`, not a property of demand.
- **P3. Rung mix 15/80/5, baseline demand 50.**
  - **Blocks do not grow from genesis.** Priority demand (2.5 a block) fits inside the penalty-free room (22), so it displaces Standard instead of adding to it. The block carries 2.5 P + 19.5 S, and **Economy is never carried.** This contradicts the rebase doc's line "A share of Priority transactions … so blocks grow from genesis" (§ reading-pass finding 1); if the run agrees with P3, that sentence is wrong and ESR-9 restates it.
  - **Fee revenue is about 6.6× all-Standard in the constrained era** (125 + 19.5 Standard-units against 22), with Priority 85–90 % of all fees.
  - **The ratchet year moves by at most about one year** relative to P1. Only Standard transactions are marginal past the median, and the extra burn lowers `s`, and so `b` and `ρ`, by a few per cent.
- **P4. After the ratchet on 15/80/5: Economy expires forever.**
  - Once Standard demand (42.5) is carried, the median plateaus near 42.5 transactions' weight. Economy past the median needs `ρ ≥ 4θ ≈ 4.9`, and `ρ`'s reachable maximum is about 2 (`b ≤ 0.5` at baseline volume).
  - So 15 % of demand is never served, in any year, in any scenario whose demand exceeds the room. Blocks plateau about 15 % lighter than the default's.
  - Priority/Standard per byte is `M/(2·w_ref)`: 50× at the zone, about 120–127× at the post-ratchet median. Priority's share of fees reaches about 89 %.
  - Read: on the inherited constants, the Economy rung is non-functional on any loaded chain, which is a rule-82 failure mode and goes to EUP-5. 89 % of the fee budget coming from 5 % of users is a fragility in the fee-era security budget, which also goes to EUP-5.
- **P5. Zero-Priority arm 15/85/0.**
  - Identical to P1 in every cell up to the ratchet year, because the 22 carried are Standard and Economy expires either way.
  - It departs **exactly at the ratchet year** and plateaus at 42.5 carried, with 7.5 Economy expiring a block.
  - Any difference before the ratchet year is a wiring error in §0.1.
- **P6. A1 with the rung mix: onsets move later on every scenario**, because the fee leg is about ×7. The size depends on the fee leg's share of the budget at onset. The run prints the emission/fee leg split at the onset year so the shift is attributed, not inferred. No size is registered.

## 3. Predictions — re-derived arm (`w_ref′`, `zone′ = 100·w_ref′`)

- **R1. Baseline carries 50 of 50 from genesis, with zero expired.** The median stays on the zone′ floor for the whole run (50 transactions are about half of zone′). The same holds for every scenario until its demand exceeds 100 a block.
- **R2. Where demand exceeds the room, blocks track demand immediately.** `θ′ = 0.25 < ρ₀ ≈ 0.87`, so the Standard ratchet runs from the first block that has a queue. There is no constrained era in any scenario, at any `m ≥ 1`. The multiplier sweep is flat in blocks carried and moves only fees.
- **R3. Year-1 Standard fee per transaction ≈ 0.25–0.30× the inherited arm's.** That is `1/k` with `k = w/3000 ≈ 4.5–4.8`, times `M_r` 1.0/0.8 = 1.25 (fee level reads `C`, so `M_r` counts here).
  - Fee revenue a block: about 0.6× the inherited arm's in its constrained years (50/22 transactions × 0.27).
  - **It crosses over once the inherited arm ratchets.** The inherited median then sits at about 730–765 KB, while the re-derived arm sits at zone′, so the re-derived per-transaction fee becomes **1.2–1.45×** the inherited one.
  - Read: cheaper early, dearer late. Which constant set serves the year-1 Standard fee Rick ratifies is itself an EUP-5 input.
- **R4. Emission runs at `M_r = 1.0` from genesis.**
  - The inherited arm's "1.313× higher reward after the constrained decade" does not appear: its reward path is the unconstrained one.
  - At every year after the inherited ratchet, the inherited reward ≈ 1.25–1.35× the re-derived one.
- **R5. Corpus growth.**
  - Closed shards at y10 ≈ the pre-ESR-6 figure, **523 841 ± 5 %**, because that run carried the same 50 a block.
  - final_n at y60 ≈ 1.10–1.15× the inherited arm's 2 717 162: the inherited arm's deficit is about 28 a block for 15–20 years.
- **R6. Rung mix 15/80/5 on the re-derived arm, baseline.**
  - All three rungs are carried, Economy included, because 50 < 100 room.
  - Priority/Standard per byte at zone′ is still 50×. The ratio `M/(2w_ref)` is invariant under the joint re-derivation, so Priority's share of fees is the doc's "about three quarters" (75 %).
  - Economy expires only in scenarios with demand above the room, and only until `ρ ≥ 4θ′ = 1`.
- **R7. A1 on the re-derived arm, baseline.**
  - Burden is about 2.3× higher through y10 and about 1.1× at y60.
  - The emission leg is about 1.25× higher early and about 0.75–0.8× after y20.
  - The fee leg is about 0.6× early and about 1.2–1.45× per transaction late.
  - **Predicted net: onsets earlier by 1–5 years.** This is the weakest prediction here. It assumes the emission leg dominates at onset, and the leg split the run prints (P6) is what decides it. If the fee leg dominates instead, onsets move later, and that tells us something on its own.

## 4. What each outcome would mean

- **P2 holds (one θ):** M1/M2 is the mechanism, so reading-pass finding 1 is a statement about `w/w_ref`, not about demand or reward.
- **θ varies across cells:** something besides `m·ρ` gates growth (the coinbase reserve, the fill's `2M − reserve` bound, or the median window's lag). Find it before EUP-4.
- **P3 or P4 misses (Priority grows blocks at 5 %, or Economy is served on a loaded inherited chain):** the multi-class pool's order is wrong, or Priority's `max(2RC/M, 4F)` isn't what the instrument calls. Check §0.1 first.
- **R1/R2 miss:** the zone′ floor isn't reaching the median (check §0.2). The arm then says nothing until that's fixed.

## 5. Out of scope, stated so nobody reads it in

- No elasticity, no wallet rung escalation, no resubmission: demand is still a schedule.
- No production constant changes. The re-derived arm is declared and stays an arm until the owners rule on `w_ref` and the zone (EUP-2 finding G; FL-R13).
- The single-source change in §0.2 is the only production code ESR-10 asks for, and it goes to Rick.
