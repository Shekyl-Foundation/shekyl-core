# ESR — the economics sims on production code: census and re-base

**Status:** **OPEN — Round 0 (the census) executed 2026-10-02 at
`bb021f254`; implementation opened the same day.** Identifier family
**`ESR-`** (work items), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file
(rule 94 §1). This document owns the re-base of `shekyl-economics-sim`.
Checking `shekyl-staking-sim` against the staking code built so far is a
separate PR against the same census (§6), and the design round the measurements feed is not opened
here (§7).

**One sentence.** The archival economics was measured on a fee the chain
does not charge — a flat `0.1 SKL` per transaction for sixty years, and a
stuffer priced at a `300` atomic/byte constant with no caller — so every
fee-share verdict in
[`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md)
§12.13–§12.14 is a statement about that fee, not about the system.

---

## Reading-pass finding 1: the production default carries 22 of 50 (2026-10-03, ESR-6)

*Relabelled 2026-10-05 (Rick's ruling, [`ECONOMY_UMBRELLA_PLAN.md`](ECONOMY_UMBRELLA_PLAN.md) §3.2).* "The production block-template fill rule" below is the reward-aware fill, which is the design's. The daemon runs Monero's pre-v5 rule until the fill moves to Rust, so this finding is the design's behaviour once the fill lands, not what the daemon does today. The sim's fill also weighs the bodies without the coinbase (1,331 B a block); the figures are re-run when the owner prices the block's weight ([`FOLLOWUPS.md`](../FOLLOWUPS.md)).

**What the run says.** On the baseline schedule, 50 ordinary transactions a
block, at the production Standard rung and under the production
block-template fill rule:

- Blocks carry **22 transactions** for the first eighteen years.
- The median stays within one transaction of the 300 KB zone (314–322 KB).
- About **28 a block go unserved**, roughly 7.4 M a year.
- Blocks grow in year 19, 42.4 a block on average that year. From year 20
  they carry all 50, and the median settles at 732–764 KB.

On the flat control fee blocks carry 20 for the whole 60-year run.

**The mechanism is production code.** The producer lists a transaction only
when it does not lower the gross coinbase (`fill_block_template`, now
`shekyl_block_template::Fill`). Past the median, one more transaction of
weight `w` therefore needs a fee that covers its penalty:
`w ≤ 4ρ·w_ref·(m/M)²` at the Standard rung, with `ρ = (1 − σ)/(1 − b)`. The
fee grows with `w` and the penalty with `w²`. The ladder's reference weight
`w_ref = 3 000` is a quarter to a fifth of a post-quantum ordinary
transaction (12.6–15.3 KB), so the condition fails until `ρ` reaches about 1.2. That
happens in year 19 on this trajectory (`--stage2`, the growth-gate table).

**The demand assumption, named. The sim has no demand response.** Demand is
the scenario's schedule. It is exogenous, the same whatever the fee or the
congestion, with no elasticity, and nothing in it is deterred by price.
Every transaction pays the Standard rung. No wallet escalates to Priority
under congestion: the production wallet has no automatic escalation, and the
tier is the user's choice. A refused transaction waits in the pool, is
offered again to the next block at that block's fee, and is dropped unserved
after `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, three days or 2 160 blocks. It is
never resubmitted.

So "unserved" means **expired for want of block space**, not "deterred by
the fee". 22/50 is a supply-side result: what production's block-space rule
does to an inelastic, all-Standard, non-escalating demand. It is not an
adoption estimate. ESR-1's early-fee number (§5.1) is the usability
question, and nothing in this sim can respond to it.

**What would change it.**

- **The two constants the condition reads.** Both are Monero's, and both
  were sized for a Monero transaction:
  - `w_ref = 3 000` is `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT`. CEN-M3
    finds no examination record of it as a choice.
  - The 300 000-byte zone holds 100 Monero-sized transactions and about
    22 of ours. Its transaction-capacity leg was ratified on a 4–8 KB
    estimate per spend (C2-R2 Q1; CEN-G6b's provenance gap).

  The post-quantum transaction made both wrong by a factor of 4–5. ESR-6's
  fee re-base is the first thing that priced them. Re-deriving them is a
  ruling for their owners (`docs/FOLLOWUPS.md`), not this lane's. Until it
  lands, the sim keeps the inherited values, and ESR-10 runs a second
  declared arm with the pair re-derived.
- A share of Priority transactions (ESR-10's rung mix). Priority pays
  `max(2RC/M, 4F)` per byte, which buys deep into the penalty zone, so blocks
  grow from genesis.
- An elasticity. It would lower demand instead of expiring it.
- A wallet that escalates its rung under congestion.

Each is an input, not a result, and none is modelled.

**What it feeds.**

- **Corpus growth.** The baseline's closed shards at year 10 are 229 864.
- **The purse.** Emission is paced at the release multiplier's 0.8 floor
  for eighteen years, so every later year's reward is higher than on a chain
  that carries its demand. ESR-10's re-derived arm measures by how much.
- **The escalation knee.** Its band's low anchor moved with the corpus
  (`docs/FOLLOWUPS.md`; GF-7's, after ESR-10).
- **Every onset year** (§5.7).

None of these should be quoted without the assumption above beside it.

## Reading-pass finding 2: block growth is gated by the fee correction (2026-10-03, ESR-6)

A Standard-rung transaction buys one more transaction's room past the
median when `w ≤ 4ρ·w_ref·(m/M)²`, with `ρ = (1 − σ)/(1 − b)`. That is the
fee correction `C = (1 − σ)·M_r/(1 − b)` with the release multiplier taken
out: `M_r` scales the reward and the fee alike and cancels. So **the year
the default fee starts growing blocks is set by the staker emission share
`σ` and the burn fraction `b`.** Those are two economic levers, with jobs of
their own: the staker bootstrap leg and the fee burn. Block-size growth is a
third job carried by the same term, and nothing chose it.

Measured on the baseline, production arm, at each year's last block
(`--stage2`, the growth-gate table):

| | Year 1 | Year 10 | Year 18 | Factor, year 1 → 18 |
| --- | ---: | ---: | ---: | ---: |
| `σ` | 0.135 | 0.052 | 0.023 | `1 − σ`: × 1.13 |
| `b` | 0.016 | 0.131 | 0.197 | `1/(1 − b)`: × 1.22 |
| `ρ` | 0.879 | 1.090 | 1.217 | × 1.38 |

The threshold `θ = w/(4·w_ref)` reads the ordinary transaction's weight,
so it steps with the tree's depth: 1.188 in year 1, 1.220 from year 2,
1.274 from year 23. `ρ` crosses it in year 19, and every constrained
scenario grows in the year its `ρ` crosses (year 17 on the boom-bust
cycle, whose booms raise `b` sooner). In the year blocks grow, `ρ` jumps
to 1.415: the carried volume enters the burn. About **three-fifths of the
rise to year 18 is the burn fraction** climbing as the supply is emitted,
and two-fifths is `σ` decaying. At 22 carried a block `b ≈ 0.33·s`,
with `s` the net supply over the asymptote (0.394 at year 10), so `b`
rises only as fast as the curve emits. Any change to the decay schedule,
the burn curve or the `(1 − σ)` correction therefore moves the year blocks
can first grow, and with it the corpus, the purse and the onsets. Under
re-derived `w_ref` and zone (finding 1) the threshold itself moves.

The greenfield economics note this belongs in does not exist yet: the
design round is not opened here (§7). The finding is recorded here so the
note can cite it when that round opens.

## 0. Why this round exists

Production prices a byte as `F = R·C·w_ref/M²`
(`shekyl_economics::relay_fee_floor`): proportional to the block reward
`R`, corrected by `C = (1−σ)·M_r/(1−b)`, inversely quadratic in the
block-weight median `M`.
[`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md) FL-V11 named the
consequence on 2026-09-03: the floor decays **3 413×** from genesis to the
tail (1 707× on the design curve, since 2026-10-04). The archival sim's A1, A4 and onset arms never joined that finding.
They read `fee_per_tx` from the scenario table, and the scenario table
says `100_000_000` atomic in every row.

Two rulings govern the repair.

- **The sim calls production (Rick, 2026-10-02, design-owner lane).** In
  substance: wherever possible a sim runs against the production code —
  its functions, constants and levers — so the sim and what ships cannot
  drift; a divergence is allowed for experimental work or for planning a
  different strategy, and then it is express. §4 is the register of the
  divergences this crate keeps.
- **The sim is the plan (Rick, 2026-10-04).** The cycle: we tweak the sim
  until the economy is what we need it to be, to know and to do; then it is
  implemented in code; then the sim incorporates that code as a check; then
  the cycle repeats. The sim keeps a current snapshot of development,
  aligned to the plan. The first ruling is the check half of that cycle:
  it binds to what has been built. Where a mechanism is still being
  designed — staking, now — the sim leads the code, and a surface the
  daemon does not read yet is not dead (ESR-8, census D4).
- **Order of work (Rick, 2026-10-02).** First the sim is put in order; then
  the current system is measured under its own rules; only then are levers
  designed or moved. So nothing in this round proposes a mechanism. A
  candidate fee policy, bond policy or controller is out of scope by
  ruling, not by omission.

## 1. What the census found

Two read-only passes read every file of both sim crates against the
production owners (§8 gives the method and its limits; Appendix A2 is
the economics sim's rows and where each stands, Appendix B the staking
sim's report). The rows that move a published number, or that block the
baseline the second ruling asks for:

| Finding | Where | Effect | Checked by the lane |
| --- | --- | --- | :-: |
| Honest fee is a scenario constant, `0.1 SKL` flat | `scenarios.rs`, consumed in `engine.rs`, `stage2.rs`, `budget.rs`, `record.rs`, `onset.rs` | Every fee leg; the closed-form horizon `H` | yes |
| Stuffer pays `FEE_PER_BYTE = 300`, a C++ macro with no caller | `calibration.rs` | A4 cost per shard, ROI; A3 claim cost | yes |
| No block-weight median in any fold | `stage2.rs`, `engine.rs`, `budget.rs`, `onset.rs` | The floor's `1/M²`; the penalty; a miner's free capacity | yes |
| No weight penalty in any fold | same | A zero-fee miner stuffer has no cost to model | reported |
| Emission-split epoch `0` where production uses `1` | every arm but the fee-ladder instrument | `σ` one decay step early at exact year-boundary heights | yes |
| Instantaneous transaction volume, not the 720-block window | every fold | Burn and release answer a step schedule in one block | reported |
| Gross circulating supply into the burn | gate-7 path of `engine.rs`; `record.rs` (and its committed fixture) | Gate-7 JSON and the fixture. **Not** the A1 tables: `stage2.rs` nets the burn | yes |
| Gate-7 locked supply closes one shard per `blocks_per_shard`, defaulted to a settlement epoch | `engine.rs` | The "117 coins locked" figure in `ECONOMY_EXPLAINED.md` | yes |
| Stake schedule feeds report columns nothing reads | `engine.rs`, `scenarios.rs`, `record.rs` | Dead surface | reported |

"Checked by the lane" means the row was re-read at source after the pass
reported it; "reported" means it rests on the pass alone until its work
item lands.

The staking sim's census (Appendix B) is a different kind of result. That
crate models three mechanisms production has since retired — a
per-pseudonym reward plateau with pseudonym splitting, in-place holdings
updates, and a Foundation floor that decays to zero — and five consensus
constants were calibrated from its runs, the `0.75 SKL` bond floor among
them at "1 sim capital unit ≡ 1 SKL" against a purse of 100 units per
epoch. §6 carries it.

## 2. Work items

One change to the fold per commit, so that every delta in the published
tables has one cause. Each item names what would show it wrong.

| Item | Change | Falsifier |
| --- | --- | --- |
| **ESR-1** | The ordinary user's fee comes from `shekyl_economics::corrected_fee_ladder` — the Standard rung, the production default — at the block's own `R`, `C` and median. The flat `0.1 SKL` stays as a **named control arm**. | The control arm reproduces every §12.14 A1-T and A1-L cell **exactly**. If it does not, nothing after it is readable. |
| **ESR-2** | The stuffer pays the Economy rung from `relay_fee_floor`; the `FEE_PER_BYTE_ATOMIC` mirror is deleted. The A3 claim cost follows. | A4's cost per shard is no longer depth-flat near `1 SKL`: it tracks `R`. `a_shard_costs_about_one_skl_and_depth_barely_moves_it` must go red before it is rewritten. |
| **ESR-3** | Emission-split epoch closed over inside `shekyl_economics::emission_share` (`EMISSION_SPLIT_EPOCH`). | A fold sampled at an exact year-boundary height moves by one decay step; a mid-year sample does not. |
| **ESR-4** | Transaction volume through `TxVolume::window` over `TX_VOLUME_WINDOW`, as the validator reads it. | A step schedule's burn and release ramp over 720 blocks instead of jumping. |
| **ESR-5** | Net circulating supply (`CirculatingSupply::derive`) in the gate-7 path and the recorder; the fixture is regenerated. | Each regenerated column is justified from the production formula, not from the run that produced it. |
| **ESR-6** | The weight penalty (`paid_block_reward`) and a block-weight median enter the fold. The pure median fold is **exposed from `shekyl-chain-rules`**, not restated — see §3. What a block carries is the producer's fill rule, lifted from `fill_block_template` to `shekyl_block_template::Fill` and called. | With traffic above the penalty-free zone the median rises and the floor falls as `1/M²` — **amended by §5.6 before the run**: on an all-Standard chain, only once one more transaction's fee covers its penalty. |
| **ESR-7** | A miner stuffer: transactions the miner includes in its own blocks. Two arms: the fee floor **unenforced** (the current system — zero fee, bounded only by the penalty) and **enforced** (a declared divergence, §4). | `--stage2` prints a stuffer row at zero fee beside the fee-path one. |
| **ESR-8** | Restated constants become imports, or are declared in §4. The stake schedule, the stake ratio and `ActivityMetric.total_staked` stay (Rick, 2026-10-03): staking is being built now, and the sim is the instrument for designing it. A staking surface the daemon does not read yet is not dead. Rejected: deleting the stake schedule as dead. | The census's restated-constant rows are each closed by an import, a deletion, or a §4 entry; staking surfaces are excepted from deletion. Appendix A2 holds none open. |
| **ESR-9** | Every live passage that quotes a superseded figure or reads as history is replaced by the current one, with the history in git (ruled 2026-10-15). In scope: the documents that quote the old tables (§12.13–§12.14 rows); the FL-E1 note in [`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md) §11.7, re-measured before it is replaced; the staking-sim plan's clause that L11–L19 figures become records-was rows (§6, EUP-3's to restate before it runs); and Appendix A, which Appendix A2's re-census supersedes; and the thin-margin counts that `FEE_LADDER_DERIVATION.md` (the arm table of §10.10) and `FEE_LADDER_ROUND.md` (round 16b) quote from a column the sim no longer prints. Also in scope: the deleted fee-ladder arms (`served_ceil_cq`, and the quantized, hysteresis, rate-limited and grid columns), the FL-R3 and FL-R18 sweep lines `--fee-ladder` no longer prints, and the §4 nearest-pow2 row. | No current-tense sentence quotes a superseded figure, and no live section says records-was. |

The constant-fee closed form for the fee horizon (`onset.rs`, and the two
tests that pin it) describes a fee the chain does not charge. It is
retired with ESR-1 as the §12.14 artifact it is, not adapted: the report
prints it on the control arm only, and its tests run on that arm.

**Landed.** ESR-1, 2026-10-02, in three commits: `cef2c6638` pins the
`--stage2` report before the change; `c78cfd76e` makes the fee an arm of
the run with the control as its only variant (every mode byte-identical);
`9d8a52985` adds the production arm and makes it the default. §5.1 has
the result.

**Landed.** ESR-2, 2026-10-02, at `354bc5d52`. The registered test went
red first: at the production genesis floor a shard cost 211.67 SKL against
its 0.5–2 SKL band. The control arm is byte-identical to its fixture. §5.3
has the result. The C++ macro `FEE_PER_BYTE` the mirror copied had no
caller, and neither had four legacy fee macros beside it (`FEE_PER_KB`,
`FEE_PER_KB_OLD`, `DYNAMIC_FEE_PER_KB_BASE_FEE`,
`DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD`); all five are deleted from
`src/cryptonote_config.h` in this PR, with the C++ tree built after the
deletion.

**Landed.** ESR-3, 2026-10-02, at `08925a981`. Six folds read the
validator's `EMISSION_SPLIT_EPOCH`; the fee-ladder instrument's pinned
copy is discharged. It moved 20 numeric cells of the control report and 33
of the production report, the largest by a relative 1.9 × 10⁻⁵, and no
cell of A1-T or A1-L. The falsifier above ("a mid-year sample does not
move") was wrong in the small — every sample shifts by one block of the
within-year interpolation — and right in what it guarded: nothing a reader
would quote changes. **UPDATE 2026-10-09:** those folds call
`shekyl_economics::emission_share`, which closes over
`EMISSION_SPLIT_EPOCH`. The chain-rules re-export is gone. Height 0 is
share 0, the same answer the daemon gives.

**What the control arm is, from here on.** Up to ESR-2 the control
reproduced the §12.13–§12.14 report exactly, plus 13 added lines; its
fixture at `354bc5d52` is the last one that does. ESR-3 moved 20 of its
cells in the sixth significant digit, and every later fold change (ESR-4
onward) moves it again, because the volume window, the supply operand and
the median are shared by both arms. From ESR-3 the control's job is no
longer to reproduce the old tables. It holds the fee flat while the folds
change, so that a difference between the arms is the fee and nothing
else. A control cell that moves at ESR-4 or later is the fold change
showing on that arm, not a wiring error.

**Added 2026-10-02: ESR-10**, the fee sensitivity the first two items
left out. ESR-1 runs the Standard rung at `×1` only. The multiplier is in
the type and nothing sweeps it, and the rung mix is not modelled at all.
ESR-10 prints A1-T at a swept multiplier and at the defaulted 15/80/5
mix, including a zero-Priority arm. Its falsifier: the `×1` column equals
the default report's.

**Amended 2026-10-03 (design owner, after ESR-6).** ESR-10 runs every rung
mix twice:

- with `w_ref` and the zone as inherited;
- with both re-derived from the post-quantum ordinary weight, as a
  declared arm that states its derivation until the owners' ruling
  replaces it.

The reason is reading-pass finding 1. A Priority share grows blocks from
genesis, and a table that showed only that would credit users paying
several times Standard with what is partly a reference weight wrong by
4–5×. Run on both constants, the ceremony sees which part of block growth
is demand paying up and which part is the constant.

One implementation fact for the re-derived arm:
`shekyl_chain_rules::medians_from` floors the medians at the shipped
`FULL_REWARD_ZONE` constant, not at `EconomicParams::full_reward_zone`.
The arm therefore cannot be expressed through parameters alone, and either
the floor takes its zone from the parameter set or the arm declares the
divergence.

**Where the items land (design owner, 2026-10-02).** ESR-1, ESR-2 and
ESR-3 land in PR #935, which goes to review with them. ESR-4 onward
land in a second PR stacked on #935's branch, so the remaining fold
changes — the volume window, the supply operand, the median and the
miner stuffer — are reviewed apart from the fee arm they build on.

**Landed.** ESR-4, 2026-10-02, in PR #936: `fc7d5a9b2` splits CEN-F20's
window into a span readable without a store (`shekyl_chain_rules::tx_volume_span`),
with `tx_volume_window` unchanged in behaviour; `896d95c33` has the
engine, stage-2 and budget folds read it through `VolumeWindow`. Merged
over the #935 review at `143ca633f`, where it moves the same cells by the
same amounts as before the review. §5.5 has the result.

**Landed.** ESR-6, 2026-10-03, in PR #936, in four commits:

- `422e40954` exposes the validator's median fold (§3).
- `3a79a7d7d` lifts the template fill rule to `shekyl_block_template::Fill`
  and names the pre-penalty emission (`PrePenaltyEmission`).
- `49b313eeb` puts the medians, the penalty and the fill rule in every fold
  and regenerates both fixtures.
- `4a4cbced0` brings the debug test suite from 307 s back to 80 s.

§5.6 registered the prediction before the run (`3a3df4df4`) and §5.7
records it. The reading-pass finding at the head of this document is its
first consequence.

**Landed.** ESR-5, 2026-10-03, at `eb501b15d`, in PR #936. Every fold
derives the circulating supply through `CirculatingSupply::derive`
(`engine::net_supply`). The engine, budget and stage-2 folds price the burn
through `calc_burn_pct_at`. The recorder folds its burn and keeps the
primitive engine-core's differential composes. Two stale statements of the
gross convention are corrected in the same change: `ActivityMetric`'s
field documentation in `shekyl-economics`, and the 2026-06-11 pinned
constraint in [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md). §5.8
registered the prediction (`da1a6b082`) and §5.9 records it.

**Landed.** ESR-7, 2026-10-03, in PR #936.

- `4dcaacfcd` registers the design and the prediction (§5.10).
- `d1021aa55` gives the run's `EconomicParams` one construction
  (`SimParams::economic`), replacing five copies, verified byte-identical on
  the staged tree.
- `28b0006f4` prints the envelope in `--stage2` (`miner_stuffer.rs`).
- The miner columns are one integer packing of the block, and the cost is
  the fall in the miner's payout. §5.12 records that correction. §5.10 and
  §5.11 stay the prediction and the first run.

§5.11 records the first run. ESR-7's falsifier holds: the report prints the
unenforced miner's zero-fee row beside the relay stuffer's.

**Landed.** ESR-9, 2026-10-17, in PR #1104.

- `43a8f104f` prints the growth gate year by year in `--stage2`, on the
  production arm: `σ`, `s`, `b` and `ρ` against `θ = w/(4·w_ref)`. On
  the baseline `ρ` reaches `θ ≈ 1.22` in year 19, and blocks grow that
  year. Reading-pass findings 1 and 2 quote that run.
- The live passages that quoted a superseded figure quote the current
  run. `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13–§12.14 are
  dated runs on the flat fee, with their commits in the headings; neither
  arm of today's run reproduces them, and re-deriving their readings is
  EUP-4's.
- `FEE_LADDER_DERIVATION.md` §11.7 is the dated run at `5574be2ea`. The
  current `--fee-floor` runs FL-E1 on the exact window only: 600 cells,
  4 not converged, worst 87 bp, all at age 12, `ε` = 3, `D` = 400,
  displaced start.
- Appendix A is deleted; Appendix A2 names each row's subject.

The falsifier holds over the documents in scope: no current-tense
sentence quotes a superseded figure, and no live section says
records-was. Appendix C's briefs are kept as sent, and their "already
known" lists describe the tree they were written against.

**Where the fixture tests run (2026-10-10).** The two `--stage2` narration
tests are `#[ignore]`d for cost, and until this date no CI lane ran them: on
PR #1009 both fixtures drifted at `783053554` and were regenerated two
commits later, found by a fresh-clone run and not by CI. The nightly
`economics-sim-ignored` job (`.github/workflows/nightly.yml`) now runs them,
with the secret draw at ESR-11's timing. Nightly runs after merge, so it is not the pre-push gate: a
change to any lever a fold calls still runs
`cargo test --locked --release -p shekyl-economics-sim -- --ignored matches_the_committed_fixture`
from a fresh clone before it is pushed.

## 3. The median is a production change inside a sim PR

`shekyl_chain_rules::rules::block_weight::effective_median_at` needs a
`ChainView`, a store trait the sim has no chain to satisfy. The fold
beneath it is pure. ESR-6 makes the composition public (`medians_from`,
`medians_over`) rather than writing a second one. The selecting routine
stays private. Its even-count rule is `even_pair_median`, and `median`
reads a slice without reordering it.

The test that matters is **not** "the store-backed entry point and the
pure fold agree": the first is implemented on the second, so that test is
green by construction. What can drift is the **window** — which blocks'
weights the sim feeds the fold, against which the validator records. ESR-6
pins the sim's window construction against the validator's on a shared
trace.

What ESR-6 built, and why it is not the plan above. A sixty-year fold
cannot select a 100 000-row median per block, so
`median_window::RollingMedian` keeps the long window as two ordered halves
and hands the middle pair to the validator's own `even_pair_median`;
`medians_from` composes the result exactly as `medians_over` does. Two
tests hold it to production: the rolling median equals `median` over the
explicit window at every step, across capacities that fill, evict and
churn; and the whole of CEN-G6/G6b equals `medians_over` over the same
recorded weights through a stream past the 100 000-block window's first
eviction. The C++ relay-floor ring keeps the same median the same way
(`epee::misc_utils::rolling_median_t`, `relay_floor_ring.cpp`).

The block's weight is what its transactions weigh, and how many it takes
is not the schedule's: it is what the producer's fill rule admits
(`shekyl_block_template::Fill`, §5.6). `block_space::BlockSpace` holds
the medians and the waiting transactions. One cursor,
`chain_cursor::ChainCursor`, steps that space and CEN-F20's volume window
together: the engine, the budget and the stage-2 fold each call it once
per block, and what they accumulate afterwards is their own.
The stage-2 report folds each scenario once, out to at least the onset
horizon, and every arm reads that fold. The burden trajectory and the
clearance arms read the scenario's own years; the onset table, the
envelope and the admission map read the whole horizon. `burden_trajectory`
and `a1_year_aggs` remain the one-scenario fold a caller asks for directly.
The recorder (`record.rs`) steps the cursor too, since ESR-8: its chain
is the folds'. A row is the block the cursor priced. The burn, the
release multiplier and both splits are that block's CEN-F20 window;
`tx_volume` is the count the block listed and is not a volume operand.
The differential replays the window (`volume_tx_count_sum`,
`volume_window_blocks`).

## 4. Declared divergences

Under the first ruling, every place this crate does not call production is
listed here with its reason. A divergence missing from this table is a
defect.

| Divergence | Why it exists | Reported as |
| --- | --- | --- |
| Control arm: flat `0.1 SKL` per transaction | The fee §12.13–§12.14 were measured on. The two arms of one run differ by the fee and nothing else | Named arm, printed beside the production arm |
| Fee multiplier on the Standard rung | What users pay above the default is not knowable before launch | `×1`, the production default, is what runs. The sweep is ESR-10 and is not printed yet |
| Rung mix (economy / standard / priority shares) | Same. At the defaulted 15/80/5 mix ([`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md) §5.5) the 5 % on Priority pay roughly three quarters of all fees at the zone median | Not modelled yet: every ordinary transaction pays Standard. ESR-10 |
| Control arm: admission at a flat 300 atomic/byte | The rate §12.13's stuffer and claim were priced at. Nothing in the chain charges it; the chain's admission rate is the relay floor | Part of the control arm; printed in its stuffer table |
| The admission rate at a shard count (`AdmissionAtShards`) | Arms that sample the chain by shard count alone have no height, and the rate depends on emission, not on traffic. The pairing is fixed as the baseline scenario's: the rate at the year the baseline reaches that count, and its last year's rate beyond | Stated in the stuffer table's footer |
| Admission rate sampled at the year's last block | A stuffer picks its moment, and on the production arm the floor falls through the year | Attacker-favouring; stated at the field |
| A scenario that starts mid-chain starts with an empty volume window and empty median windows | A fold's heights are its own; `genesis_height_offset` scenarios carry no history before their first block, so their medians start at the zone as a genesis chain's do | Stated in `volume_window.rs` and `median_window.rs` |
| A block's weight is its bodies' | The coinbase's few hundred bytes are neither priced nor recorded in the median. The fill rule itself prices bodies only, as the C++ does; the template then prices the whole block | Stated at `BlockSpace` |
| Waiting transactions pay the fee of the block they are offered to | They were built at an earlier block's fee. Every transaction is the same shape, so a refusal of one is a refusal of all, and the pool's order (fee, then age) is age | Stated at `BlockSpace` |
| The pool's livetime is a restated C++ define | `CRYPTONOTE_MEMPOOL_TX_LIVETIME` has no Rust owner until the pool moves (`DRS_E1_SPOOL.md`); the sim's copy is pinned to the header by a test | Stated at its definition |
| Budget disposition (b) is unpenalised | (b) is the unmodulated subsidy, a counterfactual of the release multiplier. The penalty in (a) is bounded by the fees of the transactions that crossed the median, since the fill rule admits no other | Stated in `budget.rs` |
| Every ordinary transaction pays Standard | No wallet escalates its rung under congestion; the user chooses. Blocks past the median are what Priority pays for | ESR-10's rung mix |
| A claim is one ordinary transaction at the admission rate | The claim's own envelope and the wallet's claim hold floor (`EMISSION_CLAIM_FEE_FLOOR`) are not modelled | Stated here |
| Fee paid unrounded | The product is the fixed point of `shekyl_tx_weight::converge_weight_fee` — the wallet's iteration without the lattice. The wallet rounds each fee up to the lattice, `shekyl_economics::FEE_QUANTIZATION_MASK` (1 000 atomic), through `quantized_fee`, the function relay admission runs. The fee-floor instrument in this crate pays unrounded too (FL-R22). At most 1 000 atomic per transaction, below print precision | Stated here. The lattice has its owner, so calling `quantized_fee` closes the row. That changes both narration fixtures in their last printed digits, so it is its own step with its predictions written first |
| Fee floor enforced in consensus | Not the current system: the floor is relay policy (C2-R2 Q9, reopened 2026-10-02) | Second arm of ESR-7 |
| Traffic schedules, opportunity-cost band, SKL price band, storage and Kryder terms, replica target `R = 6` | No production owner exists | Exogenous; each declared at its definition |
| The fee-floor instrument's floor at `SCALE` resolution | FL-E1–E3 measure the floor's per-block slew, which is finer than one atomic unit per byte; the owner rounds to whole units | `fee_floor.rs`; pinned to `relay_fee_floor` and the ladder's `4F` by `the_floor_is_the_owners_at_scale_resolution` |
| The secret draw's reveal lag and dropout (ESR-11) | Who reveals a block's seed, and when, is behaviour production cannot know. ESR-13 runs ESR-11's epoch at `Timing::esr11()` on production's `draw_count`, `draw_horizon` and `select_draw`; ESR-11's own loop was deleted at `f58531716` (§5.22). ESR-11's analytic functions are called: the `(m, n)` re-check, the retry mixture and the clearing figures, the evidence set's shape, and the count rule's callers `count_at` / `capped_at` | `secret_draw.rs`, `secret_draw_production.rs`; `--secret-draw` |
| The secret draw on production's count and selection: producer dropout, filing lag, inclusion latency, loss to a reorg, and each block's seed and hash (ESR-13) | The count, the horizon and the selection are production's and are called. What decides whether a block's bundle is admitted is the behaviour of producers and of the chain, which has no owner to call; the seed and the block hash are the generator's bytes because no block is built. `M` is challenger policy, not consensus | `secret_draw_production.rs`; §5.17 fixes the model before the run |
| The f64 closed forms of the m-of-n rule (`mn_feasibility.rs`, `cartel.rs`, R22) | Production's rule is a predicate over one window, not a probability. The closed forms are the analysis of that predicate and are cross-checked against the predicate-backed kernel by test | Stated at each form |
| Maturity operands (`MATURITY_D = 324_000`, 40 000 projected pairs; D13) | Assumptions about a network that does not exist yet, not values of the chain | Named as assumptions where they are defined |
| Gate-7's locked supply counts one shard per `blocks_per_shard` blocks (`engine.rs`, D1) | The partition is by archival bytes (`shard_of`), and the engine fold carries no byte fold to read it from. The default cadence is one shard per `SETTLEMENT_EPOCH_BLOCKS`; the sim's own stage-2 baseline closes 229,864 shards in ten years, one per eleven blocks, so the default understates the locked supply by a factor near 900. **Not a neutral choice:** a gate-7 figure is a floor on the lock, not an estimate of it | Stated at `ArchivalLockModel::blocks_per_shard`. Moving gate-7 onto the byte fold moves its committed figures and is its own step, with its predictions written first |
| The A3 and A4 base paths score through the plateau curve (`population.rs`, `stranding.rs`, D3) | Credited work is linear in production; the curve is kept there for counterfactuals only. The two base paths predate that and still read `curve_milli` | `distribution.rs` and OQ-4 name themselves counterfactual; `redistribution.rs` is linear. Re-basing A3 and A4 moves both narration fixtures and is its own step, with its predictions written first |
| Demand does not respond to the fee or to congestion | A schedule is a number of transactions per block, the same whatever they cost or however long they wait: no elasticity, no rung escalation, no resubmission after expiry. What the chain fails to carry expires; it is not deterred | Stated at the head of this document beside the result it governs |

## 5. Predictions, written before any run (2026-10-02)

Hand arithmetic from the floor formula, for a transaction of about
17.5 KB. Rough by construction; registered so that the tables are a test
and not a narrative.

**Amended 2026-10-02, still before any run: the shape.** 17.5 KB is the
2-in/2-out spend of
[`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md). The
sim's ordinary transaction is **1-in/2-out** (`burden::normal_tx_shape`),
one authorisation lighter — roughly 12–13 KB. Every per-transaction fee
below, and the 875 KB block figure, are therefore about 30 % too high.
Read the crossover years as about three years earlier (≈ year 30 and
≈ year 10) and the block figure as ≈ 600 KB. The directions and their
order are unchanged, and they are what is registered.

1. **ESR-1, control arm.** Exact reproduction of §12.14. This is the
   wiring's falsifier, not a prediction about the system.
2. **ESR-1, production arm, median at the zone.** The Standard rung is
   above `0.1 SKL` per transaction until about year 33 and below it after.
   Clearance is therefore **better than §12.14 early and worse late**, and
   in the tail era the fee leg is smaller by a factor of a few tens.
3. **ESR-6.** Baseline traffic is about 875 KB per block against a 300 KB
   zone, so the median floats and the floor falls about 8–9×. The
   crossover of prediction 2 moves from about year 33 to about year 13.
4. **ESR-2.** A stuffed shard costs on the order of 200 SKL at genesis and
   a few hundredths of an SKL at the tail, against `0.93 SKL` flat today.
5. **ESR-7.** Unenforced, a miner's marginal cost of stuffing is zero up
   to the median — about 875 KB per block at baseline, not 300 KB.
   Enforced, it is the burn fraction of the floor.

ESR-3 and ESR-6 both move the early years against prediction 2. If the
early columns do not improve at ESR-1's production arm, that is a finding
about ESR-1; if they stop improving after ESR-3 or ESR-6, read that
step's delta alone before judging the prediction.

### 5.1 ESR-1 — what the run said (2026-10-02, at `9d8a52985`)

**Quote the directions from this section, not the levels.** The median
is still held at the penalty-free zone here, so every production figure
below is the fee at its highest, and ESR-6 is predicted to lower it 4–5×
(§5.2). What stands now: the production fee falls with the reward, it
crosses the flat control between year 30 and year 40, and by year 60 it
is 21× below it. The absolute fees, the clearance ratios and the onset
years do not stand until ESR-6 has run.

| Prediction | Outcome |
| --- | --- |
| 1. The control arm reproduces §12.14 exactly | **Held.** `--stage2 --control-flat-fee` against the report captured before the change: 13 lines added, none removed, none changed. The 13 are the arm label, a blank line, and the new fee table (`0.1000` in every cell). |
| 2. Better than §12.14 early, worse late; crossover ≈ year 30 as amended | **Held in direction; the crossover is later than registered.** Mean fee per ordinary transaction on the baseline, SKL, at y10 / 20 / 30 / 40 / 50 / 60: **1.7480 / 0.6421 / 0.1960 / 0.0571 / 0.0164 / 0.0047**, against a flat `0.1`. It crosses `0.1 SKL` between year 30 and year 40, not at year 30. At year 60 it is 21× below the control ("a few tens" was registered). |

What moved in A1-T (flat-25 clearance ratio at 10 %, by decade; onset
year at 10 % for flat / best):

| Scenario | Arm | y10 | y20 | y30 | y40 | y50 | y60 | Onset |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | :-: |
| baseline | control | 38.72 | 2.17 | 0.34 | 0.17 | 0.13 | 0.11 | y24 / y28 |
| baseline | production | 46.55 | 3.81 | 0.54 | 0.10 | 0.02 | 0.01 | y27 / y33 |
| high-history / low-activity | control | 9.84 | 0.60 | 0.03 | 0.02 | 0.01 | 0.01 | y18 / y21 |
| high-history / low-activity | production | 46.67 | 1.27 | 0.03 | 0.00 | 0.00 | 0.00 | y21 / y21 |

Three things the control tables said that the production arm does not:

- **Every scenario has an onset at every rate.** On the control, the best
  band candidate never failed at 2 % in six scenarios and at 5 % in two.
  On the production arm no cell reads "never" (baseline best at 2 %:
  year 44). That is the claim, and no more: the boom/bust schedule's
  onsets are starred, meaning a later year clears again, as on the
  control. The commit message of `9d8a52985` says "no candidate now
  clears to 60 years", which conflates the two; this sentence is the
  corrected one.
- **The fee era has no fee leg to speak of.** On the settled chain, the
  A1-L row "all fees × 100 %" — the miner's whole fee income — carried
  0.88 / 0.36 / 0.18 of the burden at 2 / 5 / 10 % on the control. On the
  production arm it carries 0.03 / 0.01 / 0.01. Only the tail-floor rows
  still read above a tenth.
- **The constant-fee horizon `H` does not exist.** It needs a fee that is
  constant in height; the report prints it for the control arm only.

**A finding for the reading pass, separate from the purse: what an
ordinary user pays in the early years.** Nobody predicted it, because no
run had charged the production fee before. The Standard rung at the zone
median is about **3.3 SKL per ordinary transaction in year 1** and 1.7 at
year 10 (year-1 fees over year-1 transactions, baseline scenario). If
ESR-6 lowers it as §5.2 predicts, year 1 is still around 0.65–0.75 SKL.
These are the years in which adoption is decided, so this is a usability
number before it is an archival one. Its levers are not the archival
purse's either: they are the ladder's own — the rung multiple, the
reference weight `w_ref`, the median clamp. Whether anyone would pay it
is outside the sim; that the chain asks it is not.

**Why a 17× fee moves the year-10 ratio by only 20 %.** The fee leg is
17.2× the control's at year 10 (1.97 M against 0.114 M SKL per year), but
the staker emission leg is 9.05 M on both arms, so emission is 82 % of the
production budget and 99 % of the control's. The budgets stand at 11.02 M
and 9.16 M, a ratio of 1.202, which is the ratio of the two table cells
(46.55 / 38.72). The fee reaches the burden as it should; early clearance
is an emission result on either arm. Emission's share of the production
budget by year: 99.6 % at year 1, 82 % at 10, 49 % at 20, 23 % at 30.

### 5.2 ESR-6, predicted from ESR-1's output (2026-10-02, before ESR-6)

Sharper than prediction 3, which assumed the wrong shape. Baseline traffic
is 50 ordinary transactions per block. At 12.5–13.5 KB each that is a
block of 625–675 KB against a 300 KB zone. If the validator's median
settles at the block weight, the floor falls by `(B / 300 KB)²`, which is
**4.3–5.1×**, at every decade alike, because traffic is constant on the
baseline. The year-10 fee of 1.75 SKL becomes about 0.35–0.40. A result
far from that range says the median feed is wrong before it says anything
about the system.

### 5.3 ESR-2 — what the run said (2026-10-02, at `354bc5d52`)

Median still at the zone, so these are stuffing costs at their highest.

**Prediction 4 held at the early end and was not tested at the late
end.** Cost to stuff one shard along the baseline chain, against a flat
0.93–0.94 SKL on the control:

| Closed shards | 1 | 100,000 | 500,000 | 2.25 M | 10 M |
| --- | ---: | ---: | ---: | ---: | ---: |
| Relay floor, atomic/byte | 55,348 | 52,471 | 28,497 | 684 | 72 |
| Cost per shard, SKL | 171.46 | 163.13 | 88.60 | 2.15 | 0.23 |

"On the order of 200 SKL at genesis" is borne out. "A few hundredths at
the tail" is not reached: the last column is the baseline's year 60,
where the floor is still 72 atomic per byte, not the tail's 20.

The control arm did not move at all: its report is byte-identical to its
fixture.

What else moved on the production arm:

- **A4, stuffing for profit.** Realistic-end ROI is 0.17–0.40 across the
  scenarios and the gate passes; on the control it was 0.81–1.90. In the
  baseline's worst configuration the stuffer pays 15.3 M SKL in fees for
  2.6 M of revenue.
- **A4 is blind where stuffing is cheap.** It samples each scenario inside
  its own horizon (10–20 years for most), where the floor is still high.
  That is the blind spot A1 had before A1-T. It says nothing yet about
  years 40–60, where a shard costs under an SKL.
- **A6.** Stuffing fees at the legal block limit are about 1.25 M SKL per
  epoch at the worst sampled point; the control read 7,174.
- **A3.** A claim costs 0.697 SKL early and 0.0011 late.

The stuffer here pays the relay floor. A miner filling its own block does
not (C2-R2 Q9, reopened); that adversary is ESR-7.

### 5.4 ESR-4, predicted before it is built (2026-10-02)

ESR-4 feeds the burn, the release multiplier and the fee correction `C`
from the validator's 720-block window in place of each block's own
transaction count. Every fold uses that operand, so cells move on both
arms. The prediction is about a **shape**, per arm and per direction,
not about cells:

1. **The shape.** At a traffic step the burn fraction, the release
   multiplier and (on the production arm) `C` move to their new values
   over 720 blocks, not in one block. The window does not include the
   block being priced, and at genesis it is empty.
2. **Where it shows.** Every scenario's traffic steps at year boundaries,
   except the stuffing attack's, which steps at block 21,600. A step
   year's aggregates move by at most about 0.3 % (720 of 262,800 blocks)
   of that step's effect, toward the previous year's traffic. A
   constant-traffic year moves not at all, except year 1, through the
   genesis block alone (an empty window reads as zero volume, which
   clamps the release multiplier to 0.8 for one block).
3. **Both arms, same direction.** The fee arm does not change what the
   window does; on the production arm it also reaches the fee through
   `C`, in the same direction.
4. **No onset year and no verdict changes.** If one does, the cell that
   moved was within about 0.3 % of 1.0 before the change; anything larger
   says the window is wired wrong.

### 5.5 ESR-4 — what the run said (2026-10-02, at `896d95c33`, and again over the review at `143ca633f`)

**All four registered points held.**

1. **Shape.** Two tests pin it: the window equals the transactions of
   the `min(h, 720)` blocks before `h`, against a prefix sum held in
   full; and a step reaches the operand one block later and fully after
   720 blocks.
2. **Where it shows.** Control: 39 cells moved, the largest by 0.12 %.
   Production: 76 cells; the largest real move is 0.38 %, every large
   one in boom/bust, which steps every year. Larger relative figures in
   the diff are two-decimal rounding (0.06 → 0.07).
3. **Both arms, same direction.** Yes; the production arm moves more
   because the window also reaches the fee through `C`.
4. **Onsets.** One moved, on the production arm: boom/bust at 5 %, year
   22 → year 24. That year's clearance was 0.99854 before and 1.00086
   after (a probe, not committed), a cell 0.15 % below 1.0. That is the
   exception the prediction named, not a wiring error. No verdict
   changed.

The 0.38 % is a little above the "about 0.3 %" registered, and it is the
production fee itself that moves most: `C = (1 − σ)·M_r/(1 − b)` takes both
the release multiplier and the burn fraction, so a step reaches the fee
through two windowed operands at once. The control has no `C`.

### 5.6 ESR-6, predicted again before it runs (2026-10-02)

§5.2 assumed the median settles at the block weight, which assumes blocks
carry their demand. What a block carries is the producer's choice, and
production makes it with one comparison (`fill_block_template`, lifted to
`shekyl_block_template::Fill` for this item): a body is listed when it
does not lower the gross coinbase. Past the median a body of weight `w`
costs `paid · w · (2(c − m) + w) / m²` of reward, and a Standard-rung
transaction pays `4F·w` with `F = R·C·w_ref/M²`. A median that sits at a
whole number of transactions therefore grows only when one more
transaction's fee covers its penalty:

> **`w ≤ 4ρ · w_ref · (m/M)²`**, with `ρ = (1 − σ)/(1 − b)`

— independent of the reward level, because the fee and the penalty both
scale with it. Here `m` is the effective median, `M` the long-term one the
fee divides by, `w_ref = 3 000`. Production values on the neutral
baseline trajectory, from the production functions at the zone (not from
a run):

| Year | σ | b | ρ | `w`, bytes | `4ρ·w_ref` |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0.150 | 0.000 | 0.85 | 12 595 | 10 200 |
| 1 | 0.135 | 0.059 | 0.92 | 14 643 | 11 030 |
| 5 | 0.089 | 0.233 | 1.19 | 14 643 | 14 256 |
| 10 | 0.052 | 0.357 | 1.47 | 14 643 | 17 692 |
| 20 | 0.018 | 0.459 | 1.82 | 15 283 | 21 785 |

The ladder's reference weight is a quarter of a post-quantum ordinary
transaction's, and the penalty grows with `w²` while the fee grows with
`w`. On an all-Standard chain the median cannot grow until `ρ` reaches
about 1.22. Registered:

1. **The production arm's blocks do not carry their demand at first.**
   On the baseline (50 per block) they carry 21–24 transactions, the
   median stays within one transaction of the zone, and the rest wait and
   expire after `CRYPTONOTE_MEMPOOL_TX_LIVETIME` (2 160 blocks): roughly
   26–29 transactions a block, about 7 M a year, turned away.
2. **That delays its own end.** The volume window counts carried
   transactions, so the burn fraction is lower than in the table above
   (the `√V` damper, at about 22/50), `ρ` is lower, and growth starts
   later than the year 5–6 the table implies: **between year 8 and
   year 12**. The release multiplier also sits below 1 over the same
   years, so emission is paid more slowly.
3. **Once it starts, it finishes in weeks.** The median climbs about one
   transaction for each half short window (≈ 50 blocks) until the waiting
   transactions are served, then settles at the demand: 50 × 14.6–15.3 KB
   ≈ 730–765 KB. From there the floor is **5.9–6.5×** below its zone
   value. §5.2's 4.3–5.1× used 12.5–13.5 KB weights; the fold's ordinary
   transaction weighs 14.6–15.3 KB at the depths it reaches.
4. **The control arm is held at the zone far longer.** A flat 0.1 SKL
   covers one more transaction's penalty only when the reward is below
   about `0.1 / (w/m)²` ≈ 42 SKL, around **year 28–32**. Until then it
   too carries 21–24 transactions a block.
5. **What A1 does with it.** Early clearance barely moves: emission is
   99.6 % of the year-1 budget, and the release multiplier trims it by at
   most a fifth. After the production arm's growth starts, its fee leg
   falls about sixfold. **Onsets move earlier on the production arm.**

Every ordinary transaction here pays the Standard rung, and users who
choose Priority (`max(2RC/M, 4F)` per byte, enough to buy deep into the
penalty zone) are what grows blocks on a real chain. This prediction is
about the default, not about a chain under congestion with a rung mix;
that is ESR-10's.

### 5.7 ESR-6 — what the run said (2026-10-03, at `49b313eeb`)

| Prediction (§5.6) | Outcome |
| --- | --- |
| 1. Blocks carry 21–24 of 50; the median stays within a transaction of the zone; 26–29 a block expire | **Held.** 22 a block, the long-term median at 314–322 KB, 27.6–28.0 expired a block, through year 10. |
| 2. Growth starts between year 8 and year 12 | **Held.** Year 11: 25.5 a block on average that year, all 50 from year 12. |
| 3. Then the demand is carried, the median settles at 730–765 KB, and the floor is 5.9–6.5× below its zone value | **Held in shape, missed in size.** The median settles at 732 KB, then 764 KB from year 19 as the transaction grows with depth. The fee falls **4.9×**, not 5.9–6.5×. The `(M/300 KB)²` part is 6.49× as registered, but the reward is **1.313× higher at every year after the constrained decade**: the release multiplier held emission at its 0.8 floor while blocks carried 22, leaving more supply to emit later. 6.49 / 1.313 = 4.94. The prediction took the reward trajectory as given. |
| 4. The control is held at the zone until about year 28–32 | **Missed in year, held in mechanism.** Year 38. Same cause: the control's reward is 85 SKL at year 30, not the 48 of the unconstrained trajectory, and it reaches the ≈ 42 SKL a flat 0.1 SKL can cover only in year 37. |
| 5. Early clearance barely moves; onsets move earlier on the production arm | **The first half is wrong, the second held.** The A1 ratio at year 10 (flat-25 at 10 %) doubled on both arms: production 46.55 → 92.01, control 38.72 → 96.80. The budget side moved as registered; the burden side, which the prediction left out, did not stand still: fewer transactions carried is a smaller corpus, 229 864 closed shards at year 10 against 523 841. Production onsets moved earlier: baseline flat-25 at 10 % from year 27 to year 26, best from 33 to 27; at 2 %, 36 → 32 and 44 → 36. |

Not predicted:

- **The control's onsets moved later**, flat-25 at 10 % from year 24 to
  year 29 on the baseline. Its blocks carried 20 a block for 37 years, so
  its corpus is smaller (2.06 M closed shards at year 60 against 3.28 M)
  and its emission is paid later.
- **The late-chain tail is the largest move.** It starts in the tail era,
  where `ρ` is already near 2, so its median grows from the first block:
  200 a block at 2.9 MB. A median ten times the zone divides the floor by
  a hundred, and its fee-era clearance collapses. Production flat-25 at
  10 % now fails from year 4, against year 19; its year-10 ratio is 0.07,
  against 6.78.
- **Year-1 fee.** An ordinary transaction pays 2.36 SKL in year 1, against
  3.26. The median it divides by is within a transaction of the zone, as
  before. Most of the drop is the correction `C = (1 − σ)·M_r/(1 − b)`: the
  volume window now counts 22 transactions, which puts the release
  multiplier at its floor and lowers the burn fraction.

Production fee per ordinary transaction on the baseline, SKL, at y10 / 20 /
30 / 40 / 50 / 60: **1.2691 / 0.1287 / 0.0401 / 0.0117 / 0.0034 / 0.0009**,
against 1.7480 / 0.6421 / 0.1960 / 0.0571 / 0.0164 / 0.0047 at ESR-4.

Cost. The `--stage2` report runs in 289 s on the production arm and 220 s
on the control, against about 150 s before. Getting there took two fixes:
the fill offered one transaction at a time, which is millions of steps a
block on the growth schedule, and the waiting queue was re-summed every
block. Both are fixed in the owner and the sim. The batch offer is held
to the one-at-a-time walk by test.

### 5.8 ESR-5, predicted before it is built (2026-10-03)

**The production definition.** Circulating supply is `coins_generated −
total_burned` at parent state (FL-R16c; CEN-F17). `CirculatingSupply::derive`
is its one owner, and the burn reads it through `calc_burn_pct_at`. Both
validators use it: the C++ hands the pair to Rust (`blockchain.cpp`, "derived
in Rust from this pair"), and the Rust validator derives it in
`rules/miner.rs`.

**Where the sim stands.**

- The stage-2, budget and legacy-engine folds already net the burn, as a
  `u64` subtraction of their own.
- The gate-7 path (`engine.rs`) and the recorder (`record.rs`) use gross
  `already_generated`, citing a "consensus burn-site quantity" pinned to a
  C++ `validate_miner_transaction` that no longer reads it.
- The recorder does not fold the burn at all.

**ESR-5.** Every fold derives the supply through `CirculatingSupply::derive`
and prices the burn through `calc_burn_pct_at`, and the recorder folds what
it destroys. Registered:

1. **The `--stage2` report does not move on either arm, byte for byte.** Its
   folds already pass the same numbers, and gate-7 is not in it. Any moved
   cell means the old subtraction and the owner disagree somewhere, and is a
   finding.
2. **The recorder's vectors move only in their net columns, and only a
   little.** `circulating_supply` falls by the cumulative burn, about 0.1 %
   of supply by year 10. The burn is proportional to the supply ratio, so
   `burn_pct_bp` falls by at most a few basis points, and only in the later
   samples; the genesis row does not move. `staker_fee_pool` and
   `actually_destroyed` follow the burn. Every other column is identical.
   The engine-core differential stays green, because it recomputes the burn
   from the recorded supply.
3. **The gate-7 set's burn fraction falls by the cumulative-burn share of
   supply, below 0.1 % relative.** No verdict moves.

### 5.9 ESR-5 — what the run said (2026-10-03, at `eb501b15d`)

| Prediction (§5.8) | Outcome |
| --- | --- |
| 1. `--stage2` does not move on either arm, byte for byte | **Held.** Both reports are byte-identical to their fixtures, so the three folds' own subtraction and the owner agreed everywhere. |
| 2. The recorder's vectors move only in their net columns, a few basis points late, genesis untouched | **Held in the columns named, missed in the count.** `circulating_supply` is down 0.069 % at year 10. `burn_pct_bp` moves by at most 2 bp in six later rows. `actually_destroyed` and `staker_fee_pool` follow the burn at full precision, so they move in rows whose basis-point value did not. The genesis row is untouched, and engine-core's differential passes on the regenerated vector. But `total_staked` and `total_weighted_stake_lo` move too: they are the supply times the stake ratio, and the prediction overlooked them. |
| 3. The gate-7 burn fraction falls by under 0.1 % relative; no verdict moves | **Missed in size.** The fall is 0.5 % relative (last-year burn 48.47 % → 48.22 %, total burned −0.48 %). Gate-7 runs 30 years on the production fee, and its cumulative burn, about 21 M SKL, is about 0.5 % of supply; the estimate was sized at the recorder's year 10. The gate-7 mode prints no verdicts, so the second half holds only trivially. |

### 5.10 ESR-7, designed and predicted before it is built (2026-10-03)

**The question (design owner, relayed).** The chain does not care which
adversary stuffs; it cares about the cheapest archival byte in each era. So
ESR-7 prints an **envelope**: per-shard cost by era for each attacker, and
the minimum across them, which is the number the burden model consumes. A
51 % miner is out of scope: once the median can be moved, the question is no
longer economic.

**The attackers**, each priced through production functions — the fee
ladder, `PrePenaltyEmission::penalised`, the burn split, and the production
weight and archival predictors over every shape the builder accepts:

1. **Relay stuffer.** Pays the relay path. The pool offers bodies by fee per
   byte (`tx_pool.cpp`, `fee / weight`), so whether he gets in depends on the
   honest traffic.
2. **Miner, floor unenforced (today).** Lists its own zero-fee transactions
   in the blocks it mines (`kept_by_block` exempts them from the relay
   floor). It chooses the cheaper of two legs:
   - **displacement:** listing its bytes in place of honest bodies under the
     median, and forgoing their fee net of the burn;
   - **penalty:** listing them past the median and losing reward.
3. **Miner, floor enforced (after C2-R2 Q9's fix, a declared divergence).**
   As 2, but every transaction pays the floor. The miner recovers its own
   miner leg, so it nets `b·F` per byte. It is reported twice more, as a
   **self-archiver** that also holds its stuffed shards and recovers the
   staker pool's portion: once as one of the ~100 co-holders, and once as
   the whole holder set (Sybil). The lower bound is
   `b·(1 − p·q)·F`, with `p` the pool share of the burn and `q` the
   attacker's share of the pool payout.

**Table.** Columns: each attacker; cells are SKL per shard. For the miners
it adds the shards a hashrate share `h` ∈ {10 %, 33 %} can stuff at that
price within a budget `N` ∈ {one settlement epoch (10 000 blocks), one
year, ten years}. Rows:

- three eras of the baseline (constrained, years 1–11; carried, years
  12–30; tail);
- one demand-below-the-zone row, where free room exists.

The last column is the envelope minimum.

**Where this departs from the relayed recommendation, and why:**

- **The relay stuffer is not shut out in years 1–11.** At the Economy rung
  he waits behind Standard and expires, as the relay said. But he sets his
  own fee. The price of entry is outbidding the marginal honest body,
  about the Standard rate, and each byte he gets in pushes out an honest
  one. In the constrained era he pays about four times the floor ESR-2
  priced him at, so the defence is a price and not a wall.
- **The patient miner's cost does not converge to zero, nor to displaced
  fees alone.** The penalty is quadratic in a block's overshoot past the
  median, `R·X²/m²` for an overshoot `X`, but an overshoot is whole
  transactions. Per shard it is therefore `R·W·x/(α·m²)` at the
  stuffing transaction that minimises `x²/a` (weight `x`, archival `a`,
  `α = a/x`), provided the attacker has `W/a` blocks to spread over. That is
  `x/(α·C·w_ref)` floors per archival byte at `M = m`.
  - With a short budget the overshoot per block grows, and the cost is
    `R·W²/(N_h·α²·m²)` over the `N_h` blocks it mines.
  - Patience buys the floor, not zero.
- **Free room is a property of demand, not of the era.** The baseline's tail
  carries 50 a block at a 764 KB median, with no free room. Room exists
  where demand sits below the zone.

**Registered:**

1. **Constrained era (years 1–11).**
   - The relay stuffer pays about the Standard rate.
   - The unenforced miner's cheapest leg is within a factor of two of it:
     the penalty floor `x/(α·C·w_ref)` and the displacement leg
     `(1 − b)·4` floors are of the same order, both 4–5× the Economy
     floor.
   - The envelope minimum is the miner, at 3–5 floors per byte.
2. **Carried era (years 12–30).**
   - The relay stuffer pays the Economy floor at the margin of the median.
   - The unenforced miner's penalty floor is about 4–5 Economy floors
     (the same `w_ref` mismatch).
   - The envelope minimum is the relay stuffer, at one floor.
   - The enforced miner nets `b·F`, below both, so once the fix lands the
     envelope minimum is the enforced miner.
3. **Free room (demand below the zone).**
   - The unenforced miner stuffs for **zero**.
   - The enforced miner pays `b·F` per byte. At the tail `F` is about
     0.00035 SKL per transaction, so the cost is negligible.
   - **The floor fix does not close this case**: it is right for the
     self-dealing reason, not as an archival-burden defence.
4. **Hashrate share and budget set a rate, not a price.**
   - A shard needs about `W/a` ≈ 250 mined blocks at the floor.
   - A miner at `h` = 10 % mines 1 000 blocks an epoch and 26 280 a year,
     so `h` and `N` leave the per-shard floor alone and cap how many shards
     it can stuff at that price: `N_h·a/W`, about 4 an epoch and 100 a year
     at 10 %.
   - A larger campaign raises the overshoot per block and the price with
     it.
   - The table prints the floor price and the shards a budget buys at it.
5. **Self-archiving.** It lowers the enforced miner by at most the pool
   share of the burn (25 % flat today): `b·(1 − p·q)·F` with `q` = 1, and
   barely at all at `q` = 1/100.

### 5.11 ESR-7 — what the run said (2026-10-03, at `28b0006f4`)

Production arm, SKL per shard. "Floors" are read against the relay
stuffer's outranking rate, `4F + 1` atomic per byte, which is the Standard
rate the honest bodies pay.

| Row | Relay | Miner, unenforced | Miner, enforced | Self, all holders | Today | Fixed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline y5 (constrained, `M` 322 KB) | 374.01 | 325.17, displacement | 337.39 | 334.34 | 325.17 | 337.39 |
| Baseline y20 (carried, 764 KB) | 25.00 | 13.89, displacement | 16.67 | 15.97 | 13.89 | 16.67 |
| Baseline y45 (tail, 764 KB) | 1.221 | 0.615, displacement | 0.766 | 0.728 | 0.615 | 0.766 |
| Low activity y50 (300 KB, 71 KB free) | 0.882 at the floor | **0**, free room | 0.238 | 0.179 | **0** | 0.238 |

| Prediction (§5.10) | Outcome |
| --- | --- |
| 1. Constrained: the relay stuffer pays about Standard; the miner is within 2× of him, at 3–5 floors per byte, and is the envelope minimum | **Held.** The relay stuffer outranks the honest bodies at 120 297 atomic per byte. The miner is at 325 against his 374, about 3.5 floors, through displacement. The penalty leg is not printed separately, so its "same order" half is not graded. |
| 2. Carried: the relay stuffer pays the floor at the margin and is the envelope minimum; once the fix lands the minimum is the enforced miner | **Wrong in its first half, held in its last.** The fill rule refuses the floor rate here too: honest demand fills the median exactly, and a floor-rate body past it does not cover its penalty. The relay stuffer outranks at about 4 floors. The envelope minimum is the **unenforced miner at about 2.2 floors** (13.89 against 25.00), displacing honest fees it would have kept at `(1 − b)`. After the fix the minimum is the whole-set self-archiver (15.97), under the enforced miner (16.67). The registered prediction named the enforced miner and left the pool recovery out of the minimum. Both still pay the displacement, at about 2.5 and 2.7 floors, not `b·F` alone. This failure mode was suspected when building began and recorded then; the fill rule decided it. |
| 3. Free room: the unenforced miner stuffs for zero; the enforced miner pays `b·F`; the fix does not close it | **Held.** Zero today. 0.238 SKL with the floor enforced, 0.27 of the relay stuffer's floor-rate 0.882, which is the burn fraction. The floor fix is right for the self-dealing reason and is not an archival-burden defence. |
| 4. Hashrate and budget set a rate, not a price: about 250 blocks a shard, about 100 shards a year at 10 % | **Held in kind, wrong in size.** The miner's cheapest placement is displacement **in bulk**: clearing a block's honest bodies carries several stuffing transactions. A shard lands in 5–11 blocks, so a 10 % miner can stuff about 2 400–5 300 shards a year at the printed price, not 100. The ~250-block figure belongs to the penalty leg, one transaction a block, and appears where that leg wins: the control arm's tail, 239 blocks a shard. |
| 5. Self-archiving lowers the enforced miner by at most the pool's share of the burn | **Held.** At year 20, 16.67 → 15.97 as the whole holder set (−4 %), and −0.04 % as one of 100. |

**What the envelope says.** On the chain as it stands, the cheapest archival
byte belongs to a miner in every era:

- **free** wherever demand sits below the zone;
- **two to three and a half floors** where blocks run full (3.5 at year 5,
  2.2 at year 20, 2.0 at year 45), by forgoing honest fees rather than
  paying any.

The relay floor never prices the attack. A relay stuffer pays more than a
miner in every row. Enforcing the floor on a block's own bodies raises the
full-block cost by 4–25 % (+3.8 % at year 5, +20 % at year 20, +25 % at year
45) and the free-room cost from zero to `b·F`.
Neither moves the minimum out of the miner's hands. Hashrate is not a
meaningful brake: displacement lands a shard in a handful of the miner's
blocks.

**The control arm** shows the same shape at its own prices. At its tail, a
flat 0.1 SKL fee against a small reward makes the **penalty** leg the
cheaper one: one stuffing transaction a block, 239 blocks a shard. That is
the whole-transaction floor of the design, appearing where it should.

The cells above are that run. §5.12 prices the same rows again, on the
miner's payout and one integer packing. It does not revise these cells.

### 5.12 ESR-7 — the miner's payout, on one packing (2026-10-04)

Two corrections to the envelope in §5.11, both read off the chain rather
than off a second formula.

**The outlay is the miner's.** `Fill::reward` is the gross block reward.
The miner is paid his leg of `split_block_emission`, plus
`miner_fee_income` from the block's one burn split, less the fees on his
own bodies, plus the share of the staker pool those fees funded. The
staker's leg of a penalty is an externality. Charging it to the attacker
priced a loss he does not pay.

**One packing, not three legs.** He may drop whole honest transactions and
list his own, and the final weight has to sit inside the block bound. The
cost of a packing is the fall in that payout. Where the reward is still the
full emission, only the fullest packing of that region is a candidate.
Past it, every count is priced. The placement is what the cheapest packing
did: free room, penalty, displacement, or both a drop and a lower reward
(mixed). The relay stuffer is unchanged: the pool's fee-per-byte path.

A miner column is those terms — whether the relay floor binds, and what
pool share he recovers — on that one search. The production arm and the
flat control both call it, so a comparison is another column, not another
formula. The narration moved only in this section. The A1, A3, and A4
blocks are the fold they were.

Production arm, SKL per shard. Relay figures are the §5.11 ones.

| Row | Relay | Miner, unenforced | Miner, enforced | Self, all holders | Today | Fixed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline y5 (constrained, `M` 322 KB) | 374.01 | 289.30, mixed | 302.05 | 298.88 | 289.30 | 298.88 |
| Baseline y20 (carried, 764 KB) | 25.00 | 12.21, mixed | 15.06 | 14.35 | 12.21 | 14.35 |
| Baseline y45 (tail, 764 KB) | 1.221 | 0.541, mixed | 0.695 | 0.657 | 0.541 | 0.657 |
| Low activity y50 (300 KB, 71 KB free) | 0.882 at the floor | **0**, free room | 0.238 | 0.179 | **0** | 0.179 |

**What changed.** On a full block the cheapest packing is mixed: it drops
honest bodies and it lets the reward fall. The §5.11 displacement cleared
the block (5–11 blocks a shard). Piling that many bodies in pays the
quadratic penalty, and the search will not. A shard of the winning packing
takes 155 blocks at year 5 and 156 at years 20 and 45. A 10 % miner
therefore stuffs about 170 shards a year at the printed price, not the
2 400–5 300 of the bulk clear. The per-shard cost falls with that thinner
packing (325 → 289 at year 5, 13.89 → 12.21 at year 20, 0.615 → 0.541 at
year 45).

The shape of the envelope holds. Today the minimum is the unenforced miner
in every row, free wherever demand sits below the zone. After the floor
binds a block's own bodies, the minimum is the whole-set self-archiver.
One holder in a hundred barely moves the enforced miner (302.05 → 302.02
at year 5). The whole set moves it by the pool share of his own fees
(302.05 → 298.88). The relay stuffer is still the dearest column. The
floor fix still does not close free room: zero today, 0.238 SKL once the
floor is enforced.

**The control arm** keeps the §5.11 shape at lower levels. Years 5 and 20
stay displacement, now at 155 blocks a shard rather than 11, and the
per-shard cost falls (18.59 → 13.57, 15.42 → 11.26). The tail stays the
penalty, one transaction a block, 239 blocks a shard. That row's cost
moves in the fourth decimal (1.466 → 1.464): it was already a single body,
and the correction is the miner's leg of a small penalty. The
whole-transaction floor still appears where the flat fee makes the penalty
the cheaper packing.

### 5.13 The secret draw: the question and the model (ESR-11)

**The question (maintainer's Slice C Round 0 brief, 2026-10-07, §7).** The
serve-credit design replaces the public urn with a secret per-block draw:
the producer of block `h` commits to a seed, draws pairs with replacement
from the epoch's drawable set, and reveals the seed with that block's pass
records within `W₂`. A draw is issued only when its seed is revealed. At
0 %, 10 % and 30 % producer dropout (blocks whose seed is never revealed)
the sim reports:

1. the share of pairs short of 3 issued draws at `h_close(E) + W₂`;
2. the draws per block the count rule produces;
3. `(m, n)` re-checked at the resulting observation rate;
4. the witness's fetch volume per won block;
5. what a NonObservation epoch costs an honest archiver in unpaid service.

**The model.** One settlement epoch, `SETTLEMENT_EPOCH_BLOCKS` blocks, `D`
pairs, `W₂ = CHALLENGE_RESPONSE_BLOCKS`, all read from the production
crate. `--secret-draw` runs it on ESR-13's loop at `Timing::esr11()`
(§5.17, §5.22).

- **Dropout.** Each block is independently unrevealed with probability
  `d ∈ {0, 0.10, 0.30}`. An unrevealed block issues nothing.
- **Reveal lag.** A revealed block's seed lands `ℓ` blocks after it, `ℓ`
  uniform on `0..=W₂`, and its draws are visible from the next block on:
  a seed revealed in a block reaches later blocks only.
- **Selection and count.** Production's: `select_draw` for every draw,
  `draw_count` at `draw_horizon` with its 32-bit carry, through the sim's
  `count_at` / `capped_at`. The shortfall the rule is given is the visible
  shortfall less the draws of blocks whose seed is not yet revealed
  (`SCS-P9`). *Rejected:* counting every draw of the last `W₂` blocks,
  revealed or not, which subtracts draws the visible counts already hold
  and under-asks while reveals land (measured at `6681692ed9`).
- **Not modelled.** The read itself (every revealed draw is issued whether
  or not it passed), carry-over of the previous epoch's last `W₂` blocks,
  producers that reveal selectively, and any correlation between dropout
  and time.

**Scale and seeds.** `D = 324,000` (maturity, row D13's larger figure) and
`D = 4,096` (the genesis set). Eight seeds per cell. Every figure is
printed as mean, minimum and maximum over seeds.

**The bar.** The brief's ruling 6 (PROVISIONAL): at most 3 % of pairs short
of 3 issued at 10 % dropout. Graded at `D = 324,000` on the **maximum**
over seeds, with the number of seeds over 3 % printed beside it. The other
cells have no bar.

**`(m, n)`, how it is re-checked.** The settlement rule selects 3 of a
pair's issued draws and settles Served at 2 or 3 passes, so a missed
observation is "fewer than 2 of 3 independent reads passed":
`q = 3x²(1−x) + x³` with `x` the per-read failure probability the
feasibility module uses (`default_sources()`, `p_attempt = 0.30`, one
attempt). The check prints `q`, the false-slash bound at the production
`(m, n)` over the bond's life per pair (`false_slash_bound`) and for an
archiver at the maximum holdings (`max_holder_exposure`, the axis the
module's budget is set on), and the observation rate `o = 1 − short`. `o`
does not enter the false-slash bound, which is priced at a ceiling of one
observation per epoch. It stretches the time a non-serving pair takes to
reach `m` misses, by `1/o`, and that stretch is printed.

**Fetch volume and unpaid service.** Fetch volume per won block is the
block's draw count times `SHARD_LENGTH`, the partition's shard length; a
closed shard is at most one transaction longer. Unpaid service is the
share of pair-epochs that settle NonObservation, and the issued reads
those pairs answered. It is not converted to currency: the per-pair
reward depends on the emission scenario, and this arm reads none.

### 5.14 The secret draw — what the run says (at `91ff50f41`)

`cargo run --release -p shekyl-economics-sim -- --secret-draw`: six cells
at eight seeds each. Maturity, `D = 324,000`:

| Dropout | Short of 3: mean (min – max) | Seeds over 3 % | Draws per pair, drawn / issued | Draws per block, mean / max | Blocks at the cap, per epoch |
| --- | --- | --- | --- | --- | --- |
| 0 % | 0.46 % (0.43 – 0.47) | 0 | 3.61 / 3.61 | 117.1 / 172 | 0 |
| 10 % | 1.07 % (1.00 – 1.13) | 0 | 3.91 / 3.53 | 126.8 / 208 | 0 |
| 30 % | 3.70 % (3.48 – 3.82) | 8 | 4.78 / 3.37 | 154.8 / 292 | 234 |

The genesis set (`D = 4,096`) reads the same shares to within sampling:
0.45 / 1.08 / 3.69 %.

**The bar holds.** At 10 % dropout the largest short share over eight seeds
is 1.13 %, against 3 %. No seed is over the bar. The cap does not bind at
0 % or 10 %; at 30 % it binds in about 234 blocks an epoch.

**`(m, n)`.** With the 3 counted draws settled at 2 of 3, an honest pair
at the feasibility module's per-read failure of 0.30 misses an observed
epoch with probability `q = 0.216`. At the production `(11, 13)` the
false-slash bound over the bond's life is `2.85 × 10⁻⁴` **per pair**. The
module's provisional `10⁻³` budget is **per archiver**, and its verdict
compares the exposure of an archiver at the maximum holdings
(`max_holder_exposure`, 4,096 shards): that is `0.689`, which **exceeds**
the budget. The two are different measures and the run prints both.
Neither moves with the observation rate, so the secret draw's dropout
does not enter them.

`0.689` is not the probability that such an archiver is slashed. It is
`1 − (1 − p)^4096`, which treats the 4,096 pairs as failing independently.
One persona serves all its shards from one host and one onion service, so
their read failures are strongly correlated. Correlation changes the
shape of the risk more than its size: the chance of at least one false
slash can be lower than the figure, and when false slashes come they come
many at once.

The window does not clear the per-archiver budget under this rule at this
read failure. That is not new with the secret draw: the module's own
report (`--stage2`) already reads the shipped pin as exceeding it, at
`4.13 × 10⁻²` per pair under the rule it models. Two-of-three over three
counted draws lowers the per-pair figure by two orders of magnitude and
does not bring an archiver at the maximum holdings inside the budget. The
`(m, n)` re-pin stays open
([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §3).

The observation rate is 0.995 / 0.989 / 0.963 at 0 / 10 / 30 % dropout,
so a pair that never serves reaches 11 misses in 11.05 / 11.12 / 11.42
epochs against 11.

**Fetch volume per won block.** At the mean count and `SHARD_LENGTH`
(3,000,000 B): 351 / 380 / 465 MB. A producer that wins a block owes about
117 to 155 whole-shard reads inside `W₂`. A producer with a tenth of the
hashrate wins about 50 blocks per `W₂` window, which is about 17.6 GB of
reads per window, or roughly 290 KB/s sustained, at 0 % dropout. That is
the witness's cost, it scales with hashrate share, and nothing in the tree
has measured a producer's reader at that rate.

**Unpaid service.** The share of pair-epochs that settle NonObservation is
the short share above: 0.46 % / 1.07 % / 3.70 %. Those pairs answered
0.008 / 0.019 / 0.063 issued reads per pair on average, and served the
epoch's organic reads besides. Separately, an observed epoch settles
Missed for an honest pair at `q = 0.216` under the 0.30 read failure,
which is a much larger unpaid share than NonObservation and is the 2-of-3
rule's, not the draw's. Neither is converted to currency (§5.13).

**What this run does not say.** The reads are not modelled, so nothing
here measures whether a producer can complete 117 reads per won block.
Dropout is independent per block; a producer that is offline for a
stretch, or one that withholds selectively, is not in the model. The
previous epoch's last `W₂` blocks are not carried in. For the count rule
that is the rule itself: the serve-credit specification stops the
in-flight term at the epoch's open (its count rule), so an epoch's counts
do not depend on the one before. What the run leaves out at the
boundary is the producer's work: reads owed for the previous epoch's
draws overlap the first `W₂` blocks of the next.

The ESR-11 loop's run (2026-10-07), with its predictions and their
grading, is at `6681692ed9`; the model and predictions it ran were fixed
at `ecc39c040e`.

### 5.15 The failure window against retry correlation

§5.14's window check credits one attempt per read, the feasibility
module's calibration (`default_sources()`: `p_attempt = 0.30`,
`attempts = 1`). The module credits one because, on the worst day the W₂
size ladder measured, misses were mostly circuit failures that cluster
inside a window, so a retry there is not an independent draw
(`mn_feasibility.rs`, `MissSources::attempts`).

Under the secret draw the producer spreads its reads across `W₂`, 500
blocks, about 16.7 hours. A retry can come hours after the failed try, on
a fresh circuit. Whether tries that far apart fail together is not
measured. This section does not assume an answer. It prints the window at
each answer.

**Model.** The witness reads a draw up to three times, hours apart. Each
is a whole read by the fetch caller's rule; its stall retries inside one
window are the ones the calibration declines to credit, and they are not
credited here. A share `ρ` of single-try failures is common to
every try of that read, and the rest are independent, so the read fails
with probability `p · (ρ + (1 − ρ) · p²)`. At `ρ = 1` that is `p`, the
calibration. At `ρ = 0` it is `p³`. The settlement rule and `(m, n)` are
unchanged. This was added after §5.14 was read and was not pre-registered;
it has no bar of its own.

| `ρ` | Read failure | Missed observation `q` | False slash, per pair | Per archiver at 4,096 shards | Against `10⁻³` |
| --- | --- | --- | --- | --- | --- |
| 1.00 | 0.3000 | 0.21600 | `2.85 × 10⁻⁴` | `6.89 × 10⁻¹` | exceeds |
| 0.50 | 0.1635 | 0.07146 | `2.01 × 10⁻⁹` | `8.23 × 10⁻⁶` | clears |
| 0.25 | 0.0953 | 0.02549 | `2.61 × 10⁻¹⁴` | `1.07 × 10⁻¹⁰` | clears |
| 0.10 | 0.0543 | 0.00853 | `1.58 × 10⁻¹⁹` | `6.47 × 10⁻¹⁶` | clears |
| 0.05 | 0.0406 | 0.00482 | `3.02 × 10⁻²²` | `1.24 × 10⁻¹⁸` | clears |
| 0.00 | 0.0270 | 0.00215 | `4.14 × 10⁻²⁶` | `1.70 × 10⁻²²` | clears |

**The production `(11, 13)` clears the per-archiver budget when a draw
goes unread after all three tries with probability at most `0.2076`.**
That boundary assumes no model: the window reads only the probability
that a draw goes unread, and a measurement reports it directly.

`ρ` is a parameter of the mixture, not something a run observes. What a
run observes besides the read failure `x` is the first-try failure `p`
and the conditional rate `c = x / p`: of reads whose first try failed,
the share whose two later tries also failed. In the model
`c = ρ + (1 − ρ)·p²`, so independent tries still give `c = p²` (0.09 at
0.30), not zero. At the retained `p = 0.30` the boundary is `c ≤ 0.692`,
which is `ρ ≤ 0.661`. A measured `c` is compared with 0.692, or converted
by `ρ = (c − p²) / (1 − p²)` and compared with 0.661; comparing `c` with
0.661 would refuse cases that clear.

The per-try failure stays at the retained 0.30; the measured single-try
miss is 0.041 on a typical window and 0.20 on the worst day observed, so
the table is conservative in `p`. At a lower measured `p` the boundary on
`x` does not move and the boundary on `c` rises.

**What this does not say.** `ρ` is unmeasured, so the window's verdict is
unchanged: it exceeds the budget at the calibration. The two-point mixture
is the simplest model that has the calibration and independence as its
ends; a failure that persists for some hours and then clears sits between
them and depends on how the tries are spaced, which the model does not
represent. A persona that is down for the whole of `W₂` fails all three
tries at any `ρ`, and that is a miss the window is meant to count.

### 5.16 ESR-12 — settlement timing, posed (2026-10-08). Not run

Posed by the maintainer with the settlement writer's rulings
([`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) §14.5).
Nothing here is modelled yet; this is the question and what a run has to
report. The model, the bar and the predictions are written before the code,
as for ESR-11.

**The question.** Does settling epoch `E` at `h_close(E) + W₂ + 1`, where
it is settled today at `(E+2)·SEB − 1`, change anything that matters?

Settlement needs every reveal for `E` to be in, and that is true at
`h_close(E) + W₂`. The full-epoch delay is inherited from the beacon's
resolution window of one epoch.

**To measure, under both timings:**

- the time from serving to a claimable reward. Under the timing as built
  (`SO-D11`, 2026-10-09) an epoch's `Σwork` is written by its slash pass,
  so epoch `E` is claimable from `(E+2)·SEB`: one epoch after its close,
  where it was claimable the block after. That is the baseline figure the
  earlier timing would be compared against;
- the time to slash for a pair that does not serve;
- the exposure of an honest archiver to a slash during an outage that
  straddles the epoch boundary;
- the interaction with `MAX_CLAIM_AGE_W`, with the grace coupling
  (`SLASH_GRACE_EPOCHS · SEB ≥ W₂`), and with the wallet's claim arithmetic.

**What it can change.** It does not block the settlement writer, which is
built on the current timing. If the run shows a material gain, the result
comes back as a re-pin: slash timing and the grace coupling re-derived. It
does not come back as a move of the pass.

### 5.17 ESR-13, the secret draw on production's count and selection, designed and predicted before it is built (2026-10-12)

**Why a second arm.** ESR-11 (§5.13) ran when the draw had no production
owner. It carries its own count rule in `f64` and its own weighted pick.
Both now have owners in `shekyl-archival-retention`: `draw_count` (integers,
a 32-bit fractional carry), `draw_horizon`, and `select_draw` (rejection
sampling, 16 : 1, capped at 256 attempts). ESR-13 runs the same one-epoch
experiment on those functions, and adds what decides whether a block's
draws are issued at all once the reveal and the pass records travel as one
object. ESR-11 is not changed: its mode, its functions and its tests stay
as they are, and its cells are printed beside this arm's as the `f64`
reference.

**The mechanism modelled.** Block `h` has `count(h)` draws from the epoch's
drawable set. Its producer files one **bundle**: the reveal and every pass
record. The draws of `h` are issued only if the bundle is admitted in a
block `h_incl` with `h < h_incl ≤ h + W₂`. A block whose bundle is never
admitted issues nothing. There is no partial state: a bundle is admitted
whole or not at all, so a lost bundle leaves no draw issued and therefore
no miss.

**The model, fixed here.** One settlement epoch of `SETTLEMENT_EPOCH_BLOCKS`
blocks, `D` pairs, `W₂ = CHALLENGE_RESPONSE_BLOCKS`, read from the
production crate. Heights are epoch-relative.

- **Count.** `count(h)` and the carry are `draw_count(D, u, H, SEB, carry)`
  with `H = draw_horizon(h, SEB, W₂)` and
  `u = max(0, visible shortfall − in flight)`. The carry starts at zero.
- **Visible at `h`.** A pair's visible count at `h` is the number of its
  draws in bundles admitted in blocks below `h`. It is visibly short when
  that is under 3. The visible shortfall is `Σ max(0, 3 − visible)`.
- **In flight at `h`.** The total draw count of the blocks in
  `[max(h − W₂, 0), h − 1]` with no bundle admitted below `h`. This is
  ESR-11's reading A, which the specification states. A block whose bundle
  will never be admitted counts as in flight until it leaves the range,
  because nothing public distinguishes it earlier.
- **Selection.** Each block draws a 32-byte seed and a 32-byte block hash
  from the run's generator. Draw `j` is
  `select_draw(seed, hash, j, D, short)`, where `short(i)` is "pair `i` is
  visibly short at `h`". Every draw of a block reads the same visible
  state. The selection is not approximated.
- **Dropout.** A producer never files, with probability
  `d ∈ {0, 0.10, 0.30}`, independently per block.
- **Filing lag.** A producer that files does so `ℓ` blocks after `h`.
  Honest: `ℓ` uniform on `0..=(W₂ − M)`. Lazy: `ℓ = W₂ − M`, the last block
  its policy allows. `M` is the challenger's margin (PROVISIONAL at 30).
- **Inclusion latency.** A filed bundle is included `λ` blocks later, `λ`
  uniform on `λ_lo..=λ_hi`, default `1..=3`.
  `h_incl = h + max(ℓ + λ, 1)`: a bundle is never included in its own
  block, which matters only when `λ_lo = 0`.
- **Late.** A bundle with `h_incl > h + W₂` is not admitted.
- **Loss to a reorg.** A bundle whose `h_incl` is one of the last `R`
  blocks of its window (`h_incl > h + W₂ − R`, default `R = 3`) is lost
  with probability `p_reorg ∈ {0, 0.01, 0.1}`. A lost bundle is treated as
  never admitted: it is not visible for the blocks before the reorg.
- **Generator.** One generator per run, seeds 1 to 8 as in ESR-11. Each
  block takes its seed, its hash, a dropout roll, a lag roll, a latency
  roll and a loss roll, in that order, whether or not each is used, so two
  cells that differ in one parameter read the same rolls.

**Cells.** At `D = 324,000` and at `D = 4,096`, eight seeds each:

1. *ESR-11's timing* (`M = 0`, `λ = 0`, `p_reorg = 0`, honest lag) at each
   dropout. `h_incl − h` is then uniform on `0..=W₂` with 0 moved to 1,
   which is ESR-11's reveal lag for all but one block in 501. Beside
   ESR-11's own cell this isolates the integer count and the rejection
   sampling from everything else. 3 cells.
2. *The grid*: dropout `{0, 10, 30} %` × `M ∈ {0, 30}` ×
   `p_reorg ∈ {0, 0.01, 0.1}`, honest lag, `λ` on `1..=3`. 18 cells.
3. *Lazy producers*, at 10 % dropout: `M ∈ {0, 3, 30}` ×
   `p_reorg ∈ {0, 0.01, 0.1}`. `M = 3` is not in the brief; it is the
   smallest margin at which a lazy bundle is always in time, and it is the
   only lazy cell where the reorg term can act. 9 cells.

Each cell prints the share of pairs short of 3 issued (mean, minimum and
maximum over seeds), draws per pair drawn and issued, draws per block mean
and maximum, the observation rate, where its blocks' bundles went
(admitted, never filed, late, lost), the mean and largest attempts per
draw, and the draws that reached the 256th attempt. Cells with a
counterpart print ESR-11's `f64` cell at the same `D` and dropout beside
them.

**The integer rule against the `f64` rule, on one trajectory.** Two runs
with different selections differ by sampling, which hides a difference in
the count rule. So each run also feeds every block's
`(D, shortfall, in flight, h)` to ESR-11's `block_target` with its own
`f64` carry, and reports the blocks where the two counts differ and the
difference in total draws.

**The bar.** The same provisional 3 %, graded on the maximum over seeds,
at `D = 324,000`, 10 % dropout, `M = 30`, `p_reorg = 0`, honest lag.

**If the run is too slow.** `select_draw` costs one cSHAKE per attempt and
about 16 attempts per draw once few pairs are short. The plan is the full
set above. If a full-size cell does not run in minutes, the results section
states the measured time and every reduction made. No reduction changes
the selection.

**Predictions.**

(a) *The bar cell.* Mean short share between 0.95 % and 1.25 %, that is
within 0.15 points of ESR-11's 1.10 %. Maximum over seeds at most 1.40 %,
against ESR-11's 1.18 %. No seed over 3 %. Reason: the count rule is
ESR-11's to within `2⁻³²` of a draw per block, the selection has ESR-11's
weights unless a draw reaches the 256th attempt, and the mean delay to
visibility falls only from 250 blocks to about 237.

(a′) *ESR-11's timing.* Mean short share within 0.08 points of ESR-11's
0.46 % and 1.10 % at 0 % and 10 % dropout, and within 0.15 points of its
3.83 % at 30 %. Reason: nothing differs but the two production functions,
and ESR-11's own seeds spread by about that much.

(b) *The `(m, n)` figures do not move.* The missed-observation probability
under 2-of-3 (`q = 0.216` at a read failure of 0.30), the false-slash
bound per pair (`2.85 × 10⁻⁴`), the exposure of an archiver at the maximum
holdings (`0.689`, exceeding the `10⁻³` budget), all six rows of the retry
table, the boundary `x ≤ 0.2076` and the mixture's `ρ ≤ 0.661` are
identical to §5.14 and §5.15 in every cell. Reason: each is a function of
the read failure and the window, and no cell changes either. What does
move is the observation rate `1 − short` and with it the epochs a
non-serving pair takes to reach 11 misses. In the bar cell I expect an
observation rate between 0.9875 and 0.9905 and 11.10 to 11.14 epochs.

(c) *`M`, `p_reorg`, lazy producers.*

- *`M`.* At `M = 0` a filed bundle is late when `ℓ + λ > 500`: 6 of the
  1,503 `(ℓ, λ)` pairs, 0.40 %. At `M = 30` none is. I expect the short
  share at `M = 0` to exceed the one at `M = 30` by between 0 and 0.15
  points at each dropout with `p_reorg = 0`. That is small beside the seed
  spread, and at 0 % dropout the sign may not resolve. Reason: 0.4 % more
  blocks issue nothing, and ESR-11 moved 0.64 points for 10 % more.
- *`p_reorg` at `M = 30`.* No effect at all: every figure is identical
  across the three values, to the last digit. Reason: `h_incl ≤ h + 473`,
  and the reorg term acts only above `h + 497`.
- *`p_reorg` at `M = 0`.* 9 of 1,503 filed bundles (0.60 %) land in the
  last three blocks, so 0.006 % and 0.06 % are lost at 0.01 and 0.1. I
  expect the short share to move by less than 0.05 points from the
  `p_reorg = 0` cell at each dropout, which is inside the seed spread.
- *Lazy, `M = 0`.* Every bundle is late (`ℓ + λ ≥ 501`). Nothing is
  issued, 100 % of pairs are short, at any `p_reorg`. The count sits at
  the cap of 291.6 draws per block for more than half the epoch; I expect
  a mean of 240 to 280 draws per block.
- *Lazy, `M = 30`.* Every filed bundle is admitted, 471 to 473 blocks
  after its block, and `p_reorg` has no effect. The count rule learns of
  each block's draws almost a whole window late, so more top-up draws go
  to pairs that are already covered. I expect a short share between 1.3 %
  and 2.5 % at 10 % dropout: above the bar cell, under the bar.
- *Lazy, `M = 3`.* Every filed bundle lands in the last three blocks. At
  `p_reorg = 0` I expect a short share within 0.15 points of lazy
  `M = 30`. At 0.01, between 0.02 and 0.20 points above that. At 0.1 a
  fifth of blocks issue nothing (dropout and loss together, 19 %), and I
  expect between 2.5 % and 4.5 %. I do not predict which side of 3 % it
  falls.

(d) *The integer rule against the `f64` rule.* On one trajectory the two
total draw counts differ by at most 1 draw per epoch, and the two rules
give a different count in fewer than one block per epoch on average.
Reason: the integer target is the `f64` target floored to `2⁻³²`, so the
running totals are never more than `2.4 × 10⁻⁶` apart by the end of an
epoch, and a block's count differs only when a running total is that close
to an integer. Between the two arms, in ESR-11's timing, mean draws per
block within 1 % of ESR-11's 117.1 / 127.1 / 155.9 at 0 / 10 / 30 %
dropout; in the bar cell within 2 % of 127.1.

(e) *The selection's cost.* Between 3.5 and 7 attempts per draw on average
in the bar cell: one while every pair is short, about 12 once 1 to 3 % are.
Across the whole set at most a few draws reach the 256th attempt; I expect
none or one. Reason: a draw gets there with probability `(15/16)²⁵⁵`,
about `7 × 10⁻⁸`, when no pair is short, and less when some are.

**Not modelled.** As in ESR-11: the read itself, the previous epoch's last
`W₂` blocks, producers that withhold selectively, and any correlation of
dropout with time. Also not modelled here: a bundle that is visible for
some blocks and then reorganised away (it is treated as never admitted), a
reorg that removes the block `h` itself, resubmission of a lost bundle
inside its window, and any link between a producer's lag and its dropout.
`p_reorg` and `R` are parameters; nothing here measures either.

**Divergence.** The count, the horizon and the selection are production's.
Dropout, lag, latency, reorg loss and the per-block seed and hash have no
owner to call; §4 carries the row.

### 5.18 ESR-13 — what the run said (2026-10-12, at `6b5e3169f4`)

`cargo run --release -p shekyl-economics-sim -- --secret-draw-production`.
The whole set of §5.17 ran at full size: 30 cells at `D = 324,000` and 30
at `D = 4,096`, eight seeds each, and ESR-11's six reference cells beside
them. **Nothing was reduced.** No cell was shrunk, no seed dropped, and
the selection is `select_draw` on every draw.

**Time.** 112 s of wall time for the whole set, measured twice (111.7 s
and 112.5 s; the two JSON outputs are byte-identical). A full-size cell
takes 3.2 to 4.0 s with its eight seeds on one thread each, on a 16-core
machine that was carrying other work at a load average of 6 to 8. The set
made 353.8 million draws in 711.1 million `select_draw` attempts.

Maturity, `D = 324,000`. Cells that came out identical across `p_reorg`
are printed once.

| Arm | Dropout | `M` | `p_reorg` | Short of 3: mean (min – max) | Seeds over 3 % | Draws per pair, drawn / issued | Draws per block, mean / max | Blocks at the cap, per epoch | Observation rate | Bundles admitted / never filed / late / lost | Attempts per draw, mean / most |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ESR-11, `f64` | 0 % | – | – | 0.46 % (0.45 – 0.48) | 0 | 3.61 / 3.61 | 117.1 / 172 | 0 | 0.9954 | – | – |
| ESR-11, `f64` | 10 % | – | – | 1.10 % (1.03 – 1.18) | 0 | 3.92 / 3.53 | 127.1 / 208 | 0 | 0.9890 | – | – |
| ESR-11, `f64` | 30 % | – | – | 3.83 % (3.65 – 3.95) | 8 | 4.81 / 3.36 | 155.9 / 292 | 242 | 0.9617 | – | – |
| ESR-11's timing | 0 % | 0 | 0 | 0.46 % (0.43 – 0.47) | 0 | 3.61 / 3.61 | 117.1 / 172 | 0 | 0.9954 | 100.00 / 0.00 / 0.00 / 0.00 % | 2.60 / 173 |
| ESR-11's timing | 10 % | 0 | 0 | 1.07 % (1.00 – 1.13) | 0 | 3.91 / 3.53 | 126.8 / 208 | 0 | 0.9893 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.36 / 150 |
| ESR-11's timing | 30 % | 0 | 0 | 3.70 % (3.48 – 3.82) | 8 | 4.78 / 3.37 | 154.8 / 292 | 234 | 0.9630 | 70.42 / 29.58 / 0.00 / 0.00 % | 1.99 / 148 |
| Bundle, honest lag | 0 % | 0 | 0 | 0.48 % (0.45 – 0.50) | 0 | 3.63 / 3.61 | 117.5 / 172 | 0 | 0.9952 | 99.59 / 0.00 / 0.41 / 0.00 % | 2.59 / 150 |
| Bundle, honest lag | 0 % | 0 | 0.01 | 0.48 % (0.45 – 0.50) | 0 | 3.63 / 3.61 | 117.5 / 172 | 0 | 0.9952 | 99.58 / 0.00 / 0.41 / 0.01 % | 2.59 / 150 |
| Bundle, honest lag | 0 % | 0 | 0.1 | 0.48 % (0.45 – 0.50) | 0 | 3.63 / 3.61 | 117.5 / 172 | 0 | 0.9952 | 99.53 / 0.00 / 0.41 / 0.06 % | 2.59 / 150 |
| Bundle, honest lag | 0 % | 30 | 0, 0.01, 0.1 (identical) | 0.43 % (0.40 – 0.44) | 0 | 3.61 / 3.61 | 117.0 / 172 | 0 | 0.9957 | 100.00 / 0.00 / 0.00 / 0.00 % | 2.62 / 190 |
| Bundle, honest lag | 10 % | 0 | 0 | 1.10 % (1.03 – 1.16) | 0 | 3.93 / 3.53 | 127.2 / 211 | 0 | 0.9890 | 89.80 / 9.83 / 0.36 / 0.00 % | 2.35 / 150 |
| Bundle, honest lag | 10 % | 0 | 0.01 | 1.10 % (1.03 – 1.16) | 0 | 3.93 / 3.53 | 127.2 / 211 | 0 | 0.9890 | 89.80 / 9.83 / 0.36 / 0.00 % | 2.35 / 150 |
| Bundle, honest lag | 10 % | 0 | 0.1 | 1.10 % (1.04 – 1.16) | 0 | 3.93 / 3.53 | 127.2 / 211 | 0 | 0.9890 | 89.75 / 9.83 / 0.36 / 0.05 % | 2.35 / 150 |
| Bundle, honest lag | 10 % | 30 | 0, 0.01, 0.1 (identical) | 1.02 % (0.98 – 1.09) | 0 | 3.91 / 3.53 | 126.6 / 208 | 0 | 0.9898 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.38 / 159 |
| Bundle, honest lag | 30 % | 0 | 0 | 3.76 % (3.54 – 3.90) | 8 | 4.80 / 3.37 | 155.4 / 292 | 246 | 0.9624 | 70.14 / 29.58 / 0.28 / 0.00 % | 1.99 / 148 |
| Bundle, honest lag | 30 % | 0 | 0.01 | 3.76 % (3.54 – 3.91) | 8 | 4.80 / 3.37 | 155.4 / 292 | 246 | 0.9624 | 70.14 / 29.58 / 0.28 / 0.00 % | 1.99 / 148 |
| Bundle, honest lag | 30 % | 0 | 0.1 | 3.77 % (3.55 – 3.91) | 8 | 4.80 / 3.36 | 155.4 / 292 | 249 | 0.9623 | 70.10 / 29.58 / 0.28 / 0.05 % | 1.99 / 103 |
| Bundle, honest lag | 30 % | 30 | 0, 0.01, 0.1 (identical) | 3.62 % (3.45 – 3.78) | 8 | 4.78 / 3.36 | 154.7 / 292 | 228 | 0.9638 | 70.42 / 29.58 / 0.00 / 0.00 % | 2.00 / 134 |
| Bundle, lazy | 10 % | 0 | 0, 0.01, 0.1 (identical) | 100.00 % (100.00 – 100.00) | 8 | 8.06 / 0.00 | 261.2 / 292 | 6218 | 0.0000 | 0.00 / 9.83 / 90.16 / 0.00 % | 1.00 / 1 |
| Bundle, lazy | 10 % | 3 | 0 | 2.34 % (2.27 – 2.40) | 0 | 4.00 / 3.61 | 129.6 / 216 | 0 | 0.9766 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.03 / 100 |
| Bundle, lazy | 10 % | 3 | 0.01 | 2.44 % (2.38 – 2.53) | 0 | 4.03 / 3.60 | 130.7 / 221 | 0 | 0.9756 | 89.27 / 9.83 / 0.00 / 0.90 % | 2.01 / 112 |
| Bundle, lazy | 10 % | 3 | 0.1 | 3.48 % (3.40 – 3.54) | 8 | 4.36 / 3.54 | 141.2 / 271 | 0 | 0.9652 | 81.25 / 9.83 / 0.00 / 8.92 % | 1.91 / 107 |
| Bundle, lazy | 10 % | 30 | 0, 0.01, 0.1 (identical) | 2.17 % (2.11 – 2.24) | 0 | 3.99 / 3.60 | 129.4 / 216 | 0 | 0.9783 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.06 / 111 |

The genesis set, `D = 4,096`:

| Arm | Dropout | `M` | `p_reorg` | Short of 3: mean (min – max) | Seeds over 3 % | Draws per pair, drawn / issued | Draws per block, mean / max | Blocks at the cap, per epoch | Observation rate | Bundles admitted / never filed / late / lost | Attempts per draw, mean / most |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ESR-11, `f64` | 0 % | – | – | 0.49 % (0.44 – 0.61) | 0 | 3.61 / 3.61 | 1.5 / 3 | 0 | 0.9951 | – | – |
| ESR-11, `f64` | 10 % | – | – | 1.18 % (0.93 – 1.39) | 0 | 3.91 / 3.52 | 1.6 / 3 | 0 | 0.9882 | – | – |
| ESR-11, `f64` | 30 % | – | – | 3.75 % (3.49 – 4.13) | 8 | 4.80 / 3.37 | 2.0 / 4 | 256 | 0.9625 | – | – |
| ESR-11's timing | 0 % | 0 | 0 | 0.45 % (0.29 – 0.54) | 0 | 3.61 / 3.61 | 1.5 / 3 | 0 | 0.9955 | 100.00 / 0.00 / 0.00 / 0.00 % | 2.61 / 102 |
| ESR-11's timing | 10 % | 0 | 0 | 1.08 % (0.85 – 1.27) | 0 | 3.91 / 3.53 | 1.6 / 3 | 0 | 0.9892 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.35 / 126 |
| ESR-11's timing | 30 % | 0 | 0 | 3.69 % (3.37 – 4.08) | 8 | 4.78 / 3.37 | 2.0 / 4 | 243 | 0.9631 | 70.42 / 29.58 / 0.00 / 0.00 % | 1.97 / 57 |
| Bundle, honest lag | 0 % | 0 | 0 | 0.43 % (0.32 – 0.54) | 0 | 3.62 / 3.61 | 1.5 / 3 | 0 | 0.9957 | 99.59 / 0.00 / 0.41 / 0.00 % | 2.58 / 105 |
| Bundle, honest lag | 0 % | 0 | 0.01 | 0.44 % (0.32 – 0.54) | 0 | 3.62 / 3.61 | 1.5 / 3 | 0 | 0.9956 | 99.58 / 0.00 / 0.41 / 0.01 % | 2.58 / 105 |
| Bundle, honest lag | 0 % | 0 | 0.1 | 0.48 % (0.27 – 0.63) | 0 | 3.62 / 3.61 | 1.5 / 3 | 0 | 0.9952 | 99.53 / 0.00 / 0.41 / 0.06 % | 2.59 / 126 |
| Bundle, honest lag | 0 % | 30 | 0, 0.01, 0.1 (identical) | 0.43 % (0.24 – 0.54) | 0 | 3.61 / 3.61 | 1.5 / 3 | 0 | 0.9957 | 100.00 / 0.00 / 0.00 / 0.00 % | 2.61 / 126 |
| Bundle, honest lag | 10 % | 0 | 0 | 1.00 % (0.83 – 1.17) | 0 | 3.92 / 3.53 | 1.6 / 3 | 0 | 0.9900 | 89.80 / 9.83 / 0.36 / 0.00 % | 2.34 / 95 |
| Bundle, honest lag | 10 % | 0 | 0.01 | 1.00 % (0.83 – 1.17) | 0 | 3.92 / 3.53 | 1.6 / 3 | 0 | 0.9900 | 89.80 / 9.83 / 0.36 / 0.00 % | 2.34 / 95 |
| Bundle, honest lag | 10 % | 0 | 0.1 | 1.09 % (0.88 – 1.20) | 0 | 3.93 / 3.53 | 1.6 / 3 | 0 | 0.9891 | 89.75 / 9.83 / 0.36 / 0.05 % | 2.34 / 100 |
| Bundle, honest lag | 10 % | 30 | 0, 0.01, 0.1 (identical) | 0.94 % (0.73 – 1.17) | 0 | 3.90 / 3.52 | 1.6 / 3 | 0 | 0.9906 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.38 / 102 |
| Bundle, honest lag | 30 % | 0 | 0 | 3.78 % (3.47 – 4.00) | 8 | 4.80 / 3.37 | 2.0 / 4 | 253 | 0.9622 | 70.14 / 29.58 / 0.28 / 0.00 % | 1.97 / 91 |
| Bundle, honest lag | 30 % | 0 | 0.01 | 3.78 % (3.47 – 4.00) | 8 | 4.80 / 3.37 | 2.0 / 4 | 253 | 0.9622 | 70.14 / 29.58 / 0.28 / 0.00 % | 1.97 / 91 |
| Bundle, honest lag | 30 % | 0 | 0.1 | 3.79 % (3.32 – 4.20) | 8 | 4.80 / 3.37 | 2.0 / 4 | 254 | 0.9621 | 70.10 / 29.58 / 0.28 / 0.05 % | 1.97 / 67 |
| Bundle, honest lag | 30 % | 30 | 0, 0.01, 0.1 (identical) | 3.53 % (3.03 – 3.98) | 8 | 4.77 / 3.36 | 2.0 / 4 | 223 | 0.9647 | 70.42 / 29.58 / 0.00 / 0.00 % | 1.99 / 83 |
| Bundle, lazy | 10 % | 0 | 0, 0.01, 0.1 (identical) | 100.00 % (100.00 – 100.00) | 8 | 8.06 / 0.00 | 3.3 / 4 | 6218 | 0.0000 | 0.00 / 9.83 / 90.16 / 0.00 % | 1.00 / 1 |
| Bundle, lazy | 10 % | 3 | 0 | 2.25 % (1.86 – 2.59) | 0 | 3.99 / 3.60 | 1.6 / 3 | 0 | 0.9775 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.02 / 91 |
| Bundle, lazy | 10 % | 3 | 0.01 | 2.43 % (2.32 – 2.59) | 0 | 4.03 / 3.60 | 1.7 / 3 | 0 | 0.9757 | 89.27 / 9.83 / 0.00 / 0.90 % | 2.00 / 83 |
| Bundle, lazy | 10 % | 3 | 0.1 | 3.50 % (3.27 – 3.71) | 8 | 4.35 / 3.54 | 1.8 / 4 | 0 | 0.9650 | 81.25 / 9.83 / 0.00 / 8.92 % | 1.90 / 63 |
| Bundle, lazy | 10 % | 30 | 0, 0.01, 0.1 (identical) | 2.18 % (1.95 – 2.47) | 0 | 3.99 / 3.60 | 1.6 / 3 | 0 | 0.9782 | 90.16 / 9.83 / 0.00 / 0.00 % | 2.05 / 70 |

**The bar holds.** At 10 % dropout, `M = 30`, `p_reorg = 0`, honest lag,
the largest short share over eight seeds is 1.09 %, against 3 %. No seed
is over.

**Against the predictions.**

- *(a) The bar cell: held.* Mean 1.02 % (predicted 0.95 to 1.25 %),
  maximum 1.09 % (predicted at most 1.40 %), no seed over 3 %.
- *(a′) ESR-11's timing: held.* 0.46 % against ESR-11's 0.46 %, 1.07 %
  against 1.10 %, 3.70 % against 3.83 %: differences of 0.01, 0.04 and
  0.13 points, inside the predicted 0.08, 0.08 and 0.15. The 30 % cell is
  close to its limit, and most of that is not the two functions. This
  arm's eight seeds realise a dropout of 29.58 % (and 9.83 % at the
  nominal 10 %); ESR-11's eight realise about 30.1 % and 10.1 %, read from
  its issued share. Half a point of dropout is worth about 0.07 points of
  short share near 30 %.
- *(b) The `(m, n)` figures do not move: held.* Every cell prints
  `q = 0.2160`, `2.85 × 10⁻⁴` per pair, `0.689` per archiver at the
  maximum holdings (exceeding `10⁻³`), the six retry rows of §5.15 digit
  for digit, the boundary `x ≤ 0.2076` and `ρ ≤ 0.6614`. They are ESR-11's
  own lines: the mode takes them from ESR-11's renderer run on no cells.
  In the bar cell the observation rate is 0.9898 (predicted 0.9875 to
  0.9905) and a non-serving pair reaches 11 misses in 11.11 epochs
  (predicted 11.10 to 11.14).
- *(c) `M`: held.* 0.41 % of blocks are late at `M = 0` and 0 % dropout
  (predicted 0.40 % of filed bundles). The short share at `M = 0` exceeds
  the one at `M = 30` by 0.05, 0.07 and 0.14 points at 0, 10 and 30 %
  dropout (predicted between 0 and 0.15). The sign resolved at every
  dropout, including 0 %.
- *(c) `p_reorg` at `M = 30`: held.* The three cells are identical in
  every field of every seed's run, at both pair counts and for the lazy
  producer as well. (Corrected 2026-10-12: this is a consequence of the
  model's parameters, not a property of the mechanism. See §5.19.)
- *(c) `p_reorg` at `M = 0`: held.* 0.004 to 0.005 % and 0.05 to 0.06 %
  of blocks are lost at 0.01 and 0.1 (predicted 0.006 % and 0.06 % of
  filed bundles). The short share moves by at most 0.01 points (predicted
  under 0.05).
- *(c) Lazy, `M = 0`: held.* Every filed bundle is late, nothing is
  issued, 100 % of pairs are short. 261.2 draws per block on average
  (predicted 240 to 280), with the count at the cap in 6,218 of 10,000
  blocks.
- *(c) Lazy, `M = 30`: held.* 2.17 % short (2.11 – 2.24), predicted 1.3
  to 2.5 %: about twice the bar cell, under the bar. `p_reorg` has no
  effect. (Corrected 2026-10-12: at `R = 3` and a latency of `1..=3`; see
  §5.19.)
- *(c) Lazy, `M = 3`, `p_reorg = 0`: missed, narrowly.* 2.34 %, which is
  0.16 points above lazy `M = 30`; I predicted within 0.15. Twenty-seven
  more blocks of delay cost more than I allowed.
- *(c) Lazy, `M = 3`, `p_reorg = 0.01`: held as written.* 2.44 %, 0.1
  points above the `p_reorg = 0` cell (predicted 0.02 to 0.20 above
  "that", meaning that cell). Against lazy `M = 30` it is 0.27 above.
- *(c) Lazy, `M = 3`, `p_reorg = 0.1`: held.* 3.48 % (3.40 – 3.54),
  predicted 2.5 to 4.5 %. I did not predict the side of 3 %: it is over,
  on all eight seeds.
- *(d) The integer rule against the `f64` rule: held.* On one trajectory
  the two rules gave the same count in every block of every run: no block
  differs and no epoch's total differs, over 480 epochs. Between the arms,
  in ESR-11's timing, mean draws per block are 117.09 / 126.76 / 154.84
  against ESR-11's 117.09 / 127.11 / 155.92: 0.0 %, 0.3 % and 0.7 % lower
  (predicted within 1 %). The bar cell is 126.64, 0.4 % under 127.11
  (predicted within 2 %).
- *(e) The selection's cost: missed on the mean, held on the cap.* 2.38
  attempts per draw in the bar cell; I predicted 3.5 to 7. No draw in the
  set reached the 256th attempt; the most any draw took is 190. I weighted
  the late epoch too heavily. Most draws are made while most pairs are
  still visibly short, where one or two attempts select; the blocks where
  a draw needs twelve are the ones that make only the base rate.

**The integer rule and the `f64` rule are the same rule.** That is the
finding on the difference: there is none to measure at this scale. The
integer target is the `f64` target floored to `2⁻³²`, and over an epoch
that never moved a count. What separates this arm's ESR-11-timing cells
from ESR-11's own is sampling: the realised dropout above, and a
selection that draws different pairs from the same weights. The
rejection sampling reproduces the 16 : 1 weights; the cap that would
bend them was never reached.

**What the bundle adds to the picture.**

- *The margin is worth having, and its size is not critical.* With
  `M = 30` no honest bundle is late and none is exposed to a reorg in the
  last three blocks. (Corrected 2026-10-12: "none is exposed" holds for a
  reorg of depth `R = 3` and a latency of at most 3 blocks, which are this
  model's parameters. A deeper reorg or a longer latency reaches a bundle
  filed with `M = 30`. See §5.19.) With `M = 0`, 0.4 % are late, and the short share
  rises by 0.05 to 0.14 points. That is small against the bar.
- *The reorg term is second-order for an honest producer and first-order
  for a lazy one.* Honest lag with `M = 0` exposes 0.6 % of bundles, and
  even `p_reorg = 0.1` moves nothing visible. A lazy producer at the
  minimal margin exposes every bundle, and `p_reorg = 0.1` takes the short
  share from 2.34 % to 3.48 %, over the bar.
- *Lateness of the information costs more than 10 % dropout does.* Going
  from 0 % to 10 % dropout adds 0.59 points of short share. A
  lazy producer at `M = 30` loses nothing, and still doubles the short
  share (1.02 % to 2.17 %), because the count rule sees each block's
  draws a whole window late and spends top-up draws on pairs already
  covered. It spends 2 % more draws per block doing so (129.4 against
  126.6).
- *A producer that files at the very end of the window, with no margin,
  issues nothing.* That is the model's inclusion latency of at least one
  block, not a property of the chain: the bundle must be in a block by
  `h + W₂`, so it must be filed before then.

**What this run does not say.** As in §5.14, the reads are not modelled,
dropout is independent per block, and the previous epoch's last `W₂`
blocks are not carried in. Further:

- `p_reorg`, `R`, the inclusion latency and the lag distribution are
  parameters. None is measured. The lazy cells are every producer lazy at
  once, which is a bound, not a population.
- A lost bundle is treated as never admitted. A bundle that is visible
  for some blocks and then reorganised away would change the counts those
  blocks' draws were made against; the model has no such state. Nor does
  it model a reorg that removes block `h` itself, or a producer that
  files a lost bundle again inside its window, which would lower every
  loss figure here.
- The eight seeds read the same rolls in every cell, by design: cells
  compare with each other more tightly than with ESR-11 or with the
  nominal dropout. Every cell at 10 % nominal dropout ran at 9.83 %.
  (Corrected 2026-10-12, in the standard terms: the cells are run with
  **common random numbers**. The same eight seeds drive dropout, lag,
  latency and the loss roll in every cell. That is a variance-reduction
  choice, and it makes the differences between cells sharp. Its price is
  that the cells are not independent samples, and all of them share one
  realised dropout: 9.83 % at the nominal 10 %, 29.58 % at the nominal
  30 %.)
- (Added 2026-10-12.) The section budget is not modelled; see §5.19.
- The seed and the block hash are the generator's bytes. Nothing here
  exercises the commitment, the nonce, or a verifier recomputing a draw.
- The attempts per draw are the producer's and the verifier's hashing
  cost per draw (1.9 to 2.6 cSHAKE calls on average, and 1 when every
  pair is short). The run does not
  time a verifier, and a block's verification cost is the count times
  that, not measured here.
- The `(m, n)` verdict is unchanged because nothing in this run can
  change it: the window still exceeds the per-archiver budget at the
  calibration (§5.14, §5.15).

**Existing outputs.** ESR-11's reference rows above are its §5.14
figures, reproduced by calling its `cell`: 0.46 / 1.10 / 3.83 % short,
117.1 / 127.1 / 155.9 draws per block, 242 blocks at the cap at 30 %.

### 5.19 ESR-13 — addendum after review (2026-10-12, at `e3f2b15966`)

The review of the pull request found three defects in the mode. None is in
the model of §5.17, and §5.17 and the tables of §5.18 are left as written.

**The cap column's predicate was approximate. No recorded figure changed.**
The run counted a block as at the cap when its `(count, carry)` equalled
the one an unbounded shortfall gives. That also holds when an uncapped
target lands exactly on the cap (`SEB·u = 8·D·H`), where nothing was held
down. Production now answers the question: `draw_target` in
`shekyl-archival-retention` is the computation `draw_count` already made,
factored out, and it returns `capped` as `D·H + SEB·u > 9·D·H`, strictly.
`draw_count` calls it; its signature, outputs and vectors are unchanged.
The sim asks it and holds no copy of the cap term.

The evidence set was run again at `e3f2b15966`. Every field of every one
of the 480 runs is identical to the recorded run's, the cap count
included: 325,089 capped blocks over the set under both predicates. The
"Blocks at the cap, per epoch" column of §5.18 stands as printed, and now
means "blocks where the cap bound". No block of the set landed exactly on
the cap.

**The cap column's unit (maintainer's review, 2026-10-12).** Three
places carried the count in three units, and only one said which.

| Where | Unit |
| --- | --- |
| §5.14's and §5.18's tables, "Blocks at the cap, per epoch" | blocks in one epoch: the mean over the cell's eight seeds |
| The binary's column, and `blocks_at_cap` on a cell in the JSON | blocks summed over the cell's eight seeds: eight times the tables' figure |
| `blocks_at_cap` on a run in the JSON | blocks in that one epoch |

So the binary prints 1,870 where §5.18 prints 234, and 49,744 where it
prints 6,218. The tables' unit is the one this document uses, and they
stand. The binary's column was labelled `capped`, with the unit only in
the legend; it is now `cap sum`, and the legend gives the division by
eight. The 325,089 above is the cell figure summed over all 60 cells,
that is over 480 epochs: 677 an epoch on average, and 298,464 of it is
the six lazy `M = 0` cells.

**Why `p_reorg` does nothing at `M = 30`, and what the reorg term is not
(maintainer's review, 2026-10-12).** §5.18 reports that the three
`p_reorg` cells at `M = 30` are identical. That is arithmetic on this
model's parameters. The reorg zone is the last `R = 3` blocks of the
window, `h + 498` to `h + 500`. An honest producer with `M = 30` files by
`h + 470`, and the inclusion latency is `1..=3`, so its bundle is in a
block by `h + 473`. The latest inclusion cannot reach the zone. It is not
a property of the mechanism: a reorg deeper than 27 blocks, or a latency
longer than 27, reaches a bundle filed with `M = 30`, and the margin's
size is what stands between them.

The model also loses each exposed bundle independently, with probability
`p_reorg`. A reorg does not behave that way. It removes a run of
consecutive blocks, and every bundle included in that run is lost
together. Loss is correlated across the blocks whose bundles shared the
run, and many producers' draws go at once. This run does not model that,
and its loss figures say nothing about it: the share of pairs left short
by one deep reorg is not the share left short by the same number of
bundles lost one at a time.

**Not modelled: the section budget (maintainer's review, 2026-10-12).** A
block has room for `c · (⌊9·D/SEB⌋ + 1)` draws' worth of bundles, and a
bundle is charged `max(count, 1)`. In the model a filed bundle is
included after its latency whatever else is waiting: inclusion is never
refused for lack of room. So nothing here examines a backlog near the
budget, which is where lazy producers filing together, or a burst after
an outage, would be felt.

**Common random numbers.** §5.18's sentence on the seeds is restated
there in the standard terms.

**Each row's timing.** §5.18's tables do not carry the inclusion latency
or the reorg depth, and the mode's own table printed the defaults in its
header, which ESR-11's-timing rows do not use. For the rows of §5.18:

| Rows | Inclusion latency | `R` |
| --- | --- | --- |
| ESR-11, `f64` | none: the seed lands at its lag | none |
| ESR-11's timing | `0..=0` | 3, never acting (`p_reorg = 0`) |
| Bundle, honest lag and Bundle, lazy, every `M` and `p_reorg` | `1..=3` | 3 |

The mode's table now prints both on every row, beside `M` and `p_reorg`,
and its header states only what holds for every row.

**Sections.** The table's sections were found by removing adjacent
duplicates from the cells' pair counts, which is right only while the
cells arrive grouped. They did in the recorded run, so its output had each
section once. The sections are now an ordered set.

**Time.** The second run took 350 s of wall time against 112 s, on the
same machine at a load average near 30. The two times measure the
machine, not the change.

### 5.20 ESR-14, the sim's integer seams, predicted before the run (2026-10-13)

**Why.** The sim is used two ways (the maintainer, 2026-10-12). In
*design* it models what is not built yet, and that is all sim code.
In *verification* it is a harness around Shekyl code, and what it
computes about the chain must be what the chain computes: production's
integer arithmetic, the same on every platform. DQ-2G
([`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md))
is the rule: floats live in the scenario and report layers; anything
that mirrors a chain computation runs in production's integers; a float
crosses into integers once, at a named input boundary. Production is
clean: `shekyl-economics`, `shekyl-chain-rules` and
`shekyl-archival-retention` have no float outside tests. The violations
are the sim's, found in the review of ESR-8 (#1052). Each is listed with
what the fix is and what would show it wrong. Nothing in production
changes.

| # | Where | What it does today | The fix | Prediction |
| --- | --- | --- | --- | --- |
| 1 | `fee_floor.rs`, `floor_feedback_scenario` | Keeps the volume window as an `f64` running sum of fractional demand and converts it to a milli-sum on each block | Demand is rounded to whole transactions once, at the scenario boundary, and pushed into the fold's `VolumeWindow`, which is read as production's `TxVolume` | Every `--fee-floor` feedback row's operand moves by at most one transaction's rounding per block. The `converged` verdict is unchanged in every row; the amplitude and grace columns are reported as they move. The same pattern in `fee_ladder.rs` was the FL-R18 instrument's; that instrument was deleted in #1087, and PR C (#1096, 2026-10-16) put the ladder's dwell and feedback traces on the fold's `VolumeWindow` too, with `whole_transactions` the one named boundary and both files in the seams gate — discharged |
| 2 | `stage2.rs`, `a3_stranding_report`, the A2 envelope block and `shard_reward_operands` | Divides an atomic budget by `epochs_per_year()`, an `f64` 26.28, and truncates | `budget × SETTLEMENT_EPOCH_BLOCKS / BLOCKS_PER_YEAR` in `u128`. `shard_reward_operands` crosses to SKL once, after. `epochs_per_year()` keeps only report and fiat readers, and says so | Each per-epoch operand moves by at most one atomic unit. Both narration fixtures are byte-identical; nothing is printed at atomic precision |
| 3 | `engine.rs`, `budget.rs`, `stage2.rs`: `initial_emitted_fraction` | An `f64` fraction times the asymptote, truncated | A `u32` in parts per million, `asymptote × ppm / 1 000 000` in `u128`: the declared input boundary, in integers | Byte-identical. The asymptote is `2³²·10⁹`, exact in `f64`, and at the three fractions in use (0, 0.95, 1) the `f64` product already equals the integer one; shown by arithmetic before the change |
| 4 | `scripts/ci/check_sim_integer_seams.py`, in the bundled grep gates | Nothing | A gate that fails on a float-to-integer cast in the fold files (`chain_cursor.rs`, `engine.rs`, `budget.rs`, `stage2.rs`, `record.rs`, `burden.rs`) outside their test modules, with a self-test. Exceptions, if any, are listed by function with a reason | Red on one committed violation, green on its revert; both commits stay in the branch. After the fixes above the exception list is empty |
| 5 | The narration fixture tests | The reason strings say what runs them | One sentence: the fixtures are generated and checked on Linux x86-64, because the scenario layer calls `powf`, `exp` and `ln`, whose last bit can differ between C runtimes | Text only |
| 6 | `burden.rs`, `HonestOutputs` | Accumulates the curve tree's leaf count as an `f64` and truncates on read. The count sets the tree depth, which sets every transaction's weight and fee | A `u64`, and `OUTPUTS_PER_TX_NORMAL` an integer 2 | Byte-identical: integer sums are exact in `f64` far past any fold's size, so the truncated value was already the integer |
| 7 | `secret_draw.rs` (ESR-11) | Its own `f64` count rule and carry, and its own weighted sampler, kept as ESR-13's "`f64` reference" | Deleted. ESR-11 calls `draw_count`, `draw_horizon` and `select_draw`, as #1052 had it before the merge with ESR-13 withdrew it. ESR-13 stops computing and printing the `f64` comparison and the reference rows; its two tests whose subject was that comparison go with it, named in the commit | `--secret-draw-production` is byte-identical except the removed columns and rows: ESR-13's random stream is not touched. `--secret-draw` moves within seed noise, since its draws come from a different stream; the bar holds under both readings and no verdict column moves |

If any verdict moves, the run stops and reports before a fixture is
regenerated. Not in scope: ESR-10, the staking sim, and production code.

**Not decided here.** With both on production's rule, ESR-11's epoch
loop and ESR-13's "ESR-11 timing" arm model the same epoch. Whether
ESR-11's loop is then deleted, with §5.14 as its record, is a question
for the maintainer; this step does not answer it.

### 5.21 ESR-14 — what the run said (2026-10-13, at `5cc8930dec`)

Each item of §5.20 against its prediction. The baselines were captured
from the tree at `05e922c4c4`, before the first code change, on one
binary; the comparisons are byte-for-byte on each arm's JSON and table.

| # | Prediction | Result |
| --- | --- | --- |
| 1 | `converged` unchanged in every feedback row | **Falsified in part.** *Exact arm*, production's reading since FL-R24: 4 of 600 not converged before and after, worst amplitude 88 → 87 bp; no verdict moved. *Integer arm*, the truncating `sum/720` the chain no longer runs: 92 → 116 not converged (36 cells to not-converged, 12 the other way), worst amplitude 194 → 281 bp. The slew and lookback sections are byte-identical; they already used integer windows. Reading: whole-transaction demand feeds the integer arm's one-tick toggles more coarsely. A dated note sits under the FL-E1 record in [`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md) §11.7; its 2026-09-10 figures are not edited. The change stands as specified; the maintainer reads the finding |
| 2 | ≤ 1 atomic unit per operand; fixtures byte-identical | Held. Both narration fixtures, the default, gate-7 and budget arms are byte-identical |
| 3 | Byte-identical | Held |
| 4 | Red on one violation, green on its revert | Held. The bundled grep gates failed on `bbe94ddef6` with the gate's own line after its selftest passed ([run](https://github.com/Shekyl-Foundation/shekyl-core/actions/runs/38407093967/job/115329439231)); `5cc8930dec` reverts it. That head was red on rustfmt too, for the probe's attribute layout. The exception list is empty |
| 5 | Text | Done |
| 6 | Byte-identical | Held |
| 7 | ESR-13 byte-identical bar the removed columns and rows; ESR-11 within seed noise, bar holds, no verdict column moves | Held. ESR-13's JSON is identical to the baseline's once the two removed fields per cell and per run and the reference rows are dropped from it; its table differs by those rows and columns only. ESR-11's figures are below |

**ESR-11 on production's rule and selection, at maturity `D = 324,000`,
eight seeds.** The sim's rule and sampler → `draw_count` with its 32-bit
carry and `select_draw`:

| Reading | Dropout | Short of 3, max over seeds | Seeds over 3 % |
| --- | --- | --- | --- |
| A | 0 % | 0.48 % → 0.48 % | 0 → 0 |
| A | 10 % (the bar) | 1.18 % → 1.13 % | 0 → 0 |
| A | 30 % | 3.95 % → 4.15 % | 8 → 8 |
| B | 0 % | 1.44 % → 1.42 % | 0 → 0 |
| B | 10 % (the bar) | 2.67 % → 2.65 % | 0 → 0 |
| B | 30 % | 6.46 % → 6.58 % | 8 → 8 |

The genesis set (`D = 4,096`) moves the same way. The bar holds under
both readings. The cap column moved more (B, 30 %: 177 → 284 blocks
over eight seeds), because its definition changed with the rule: it was
the sim's `wanted > cap` and is `draw_target`'s own flag, as in ESR-13.
It is a report column.

**Time.** The ESR-11 run takes 361 s where it took one second, since
every draw is a `select_draw`; the ESR-13 run took 615 s against 408 s
for its baseline, both on a machine carrying a concurrent workspace
clippy. The nightly lane's job has three hours.

**Not decided here**, as §5.20 said: ESR-11's epoch loop and ESR-13's
"ESR-11 timing" arm now model one epoch on one rule. Which stays is the
maintainer's.

### 5.22 ESR-11's loop deleted (2026-10-15)

**Why.** Since ESR-14 both `secret_draw.rs` (ESR-11) and
`secret_draw_production.rs` (ESR-13) called production's `draw_count`,
`draw_horizon` and `select_draw`, and ESR-13's `Timing::esr11()`, a
uniform lag over `0..=W₂` with no latency and no loss, is ESR-11's
experiment on ESR-13's loop. Two loops running one experiment drift
apart the next time one is changed. ESR-11's loop is deleted; its
analytic functions and the shared `count_at` / `capped_at` stay.

**The comparison, made before the deletion** at `7f0e77afef` from the
runs captured for §5.21: ESR-11's loop under reading A against ESR-13 at
ESR-11's timing, short of 3 as mean (min–max) and seeds over the bar.

| D | Dropout | ESR-11's loop | ESR-13 at ESR-11's timing |
| --- | --- | --- | --- |
| 4 096 | 0 % | 0.49 % (0.34–0.63), 0 | 0.45 % (0.29–0.54), 0 |
| 4 096 | 10 % | 1.10 % (0.93–1.20), 0 | 1.08 % (0.85–1.27), 0 |
| 4 096 | 30 % | 3.81 % (3.52–4.08), 8 | 3.69 % (3.37–4.08), 8 |
| 324 000 | 0 % | 0.45 % (0.44–0.48), 0 | 0.46 % (0.43–0.47), 0 |
| 324 000 | 10 % | 1.09 % (1.04–1.13), 0 | 1.07 % (1.00–1.13), 0 |
| 324 000 | 30 % | 3.87 % (3.59–4.15), 8 | 3.70 % (3.48–3.82), 8 |

Issued draws per pair and the largest block agree to three figures in
every cell; the verdict is the same in every cell.

**The 30 % gap has a cause, and it is not the reveal timing.** ESR-13 is
lower at 30 % for both `D`, and lower at 10 % for both. The two loops
consume their generator differently per block (ESR-11: a 32-byte seed,
the dropout roll, a lag roll when revealed; ESR-13: a seed and a hash,
then dropout, lag, latency and loss rolls), so the same eight seeds
realise different dropout, and each loop's realisation is shared across
`D`. Replicating the generators: at 30 % ESR-11's seeds leave a mean of
3 025 blocks unrevealed per epoch (30.25 %) and ESR-13's 2 958 (29.58 %);
at 10 %, 995 against 984. A lighter realised dropout in ESR-13, the same
for both `D`, is the pattern in the table. The one timing difference,
that ESR-13 lands a lag-0 reveal in the next block where ESR-11 counted
it in its own, touches 1 block in 501 by one block, and does not show.
ESR-13's form is production's: a seed revealed in a block can reach
later blocks only. §5.14 now reports this loop's run; the deleted loop's
figures are at `6681692ed9`.

**What moved.** `--secret-draw` runs ESR-13's loop at ESR-11's timing on
the evidence set's six `(D, dropout)` cells, through ESR-13's renderer.
The nightly lane's test is
`secret_draw_production::tests::the_esr11_timing_set_runs_and_the_table_renders`
in place of `secret_draw::tests::the_evidence_set_runs_and_the_table_renders`.
ESR-11's loop tests go with their subject: `a_run_is_a_function_of_its_seed`
(ESR-13 has its own); `every_draw_of_a_revealed_block_is_issued_and_none_of_an_unrevealed_one`
(ESR-13: `with_the_margin_and_no_reorg_every_filed_block_s_draws_are_issued`,
`a_lost_bundle_issues_nothing_and_leaves_no_draw_to_miss`,
`a_lazy_producer_with_no_margin_is_always_late`);
`issued_counts_account_for_every_issued_draw` (ESR-13:
`with_the_margin_and_no_reorg_every_filed_block_s_draws_are_issued`);
`no_block_draws_more_than_the_cap_allows` (ESR-13:
`the_count_is_production_s_on_a_hand_checked_sequence`);
`zero_pairs_is_refused` and `more_dropout_leaves_more_pairs_short`, whose
subjects ESR-13 did not test, are added to ESR-13 at ESR-11's timing.

## 6. The staking sim — the plan for staking, checked against what is built (a separate PR)

Under the cycle ruling (§0), staking is being designed now, and the
staking sim is where it is designed. It is not a
re-base onto a finished system. Its next PR is the *check* half of the cycle,
for the pieces that have been implemented and settled:

- the reward arithmetic (`g_age_milli`, `scarcity_micro`,
  `reward_share_floor`);
- the bond floor;
- the challenge count;
- the failure window;
- the release cooldown;
- the settlement epoch;
- the block time.

Appendix B lists every place the sim restates or departs from one of them.
Each row is resolved in one of two ways, and says which:

- **The sim is behind the code.** The sim incorporates the code, and calls
  it.
- **The plan is ahead of the code.** The sim keeps its mechanism as the plan,
  declared, and the code follows. The release cooldown's per-shard versus
  whole-record anchoring (Appendix B, R10) is the first row that has to say
  which.

What has not been built — the purse's shape, the parts of the bond
lifecycle not yet coded, the yield a staker sees — stays the sim's design
surface. The purse stops being an abstract 100 units per epoch: it becomes
the one this sim computes, the economy's plan. Its falsifier is that an
abstract-purse control arm reproduces the existing L11 and L13 pins in
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md).

Two consequences are recorded here so they are not discovered later.

- When that PR lands, each L11–L19 section that reports a run reports
  the new one, and cites the run it replaces by its commit. No test pins
  a population result today; they are pinned in documents only.
- The consensus constants calibrated from those runs — the bond floor, the
  age weight, the bond duration, the failure window, the release cooldown
  — keep their values and lose their derivation until the runs are
  repeated.

It is a separate PR because it is a separate validation surface (rule 19),
and it is carried by the `FOLLOWUPS.md` row *Check `shekyl-staking-sim`
against the staking code built so far*.

## 7. What this round does not decide

The measurements feed one design round that is not opened here. Four open
items sit on the same variable and each currently assumes the others are
sound: the fee-floor basis (FL-R13), the fee-era budget servo
([`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md) §8), the
bond sizing
([`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md)
§12.14 *Ruling*), and the challenge-egress funding finding
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L19i–§L19j). The
reopened consensus-fee-floor question (C2-R2 Q9) joins them. Whether they
are ruled as one round is the design owner's call.

## 8. How the census was produced, and what it is not

Each pass was one read-only agent given a written brief (Appendix C) and
the crate. It read every file it lists as read, compared each constant
and formula against the named production owners, and classified what it
found. It built nothing and ran nothing.

- **It is a reading, not a gate.** Re-issuing a brief reproduces the
  method, not the output byte for byte. A row is closed by the commit that
  fixes it, and that commit re-reads the site.
- **Every row carries its own confidence**: `V` where the pass read both
  the definition and the use, `I` where it inferred. §1 marks which rows
  the lane re-read.
- **Row labels inside the appendices are local to their tables** (`R9`,
  `D2`, `A1`, …). They are not identifiers and collide by spelling with
  registered families and with the sim's arm names. Cite a row as
  "Appendix A2 row R9"; the identifiers of this round are `ESR-`.
- **Line numbers are at each appendix's pin** and will move.
- **Appendix B is the report as returned**, less two lines about the
  reporting environment and one local path, its headings demoted one
  level to sit under the appendix heading. Nothing else is edited, so a
  claim in it is the pass's, not this document's. The economics sim's
  first report as returned is in this document at `486c754e6`;
  Appendix A2 carries each of its rows forward.
- The census did not sweep the design documents that quote sim output;
  ESR-9 did.

---

## Appendix A2 — census of `shekyl-economics-sim`, and where each row stands (re-census at `258b4d851`)

The first census was a read-only pass of 2026-10-02 over `bb021f254`
(§8); its row labels are used here. This re-census, 2026-10-11, read its
items 1–5, R1–R31 and D1–D13 again. Sim paths are relative to
`rust/shekyl-economics-sim/src/`. The first census's other classes —
inputs assumed exogenous, exceptions declared in the code, sweep bands
and correct imports — were not re-read; the first two are declared where
they are defined (§4).

| Status | Rows |
| --- | --- |
| Closed by import or call | The block-weight median every fold lacked (item 4); `SimParams::default`'s eleven literals (R1); `COIN` (R3); `BLOCKS_PER_YEAR` (R4); the swing model's epoch length, reorg depth and penalty-free ceiling (R5–R7); its penalty compensation (R8); the literal split epoch `0` (R9); the per-block reward chain assembled from primitives, now `price_emission` (R10); the instantaneous transaction volume, now the 720-block window (R11); the tail per year (R12); the flat `0.25` staker share (R13); `/ 10_000.0` for `SCALE` (R14); report strings that spelled a constant (R15, R16); the plateau curve value (R17); the age weight (R18); the gather's `n` bound (R19); `λ = 3` (R20); the slash settlement lag (R23); the fee instrument's local `C` and `round_money_up_2` (R24, R25); the release rails (R27); the baseline volume and reference-block age (R28); the reference weight `w_ref` (item 3, `629c49b4a`); the bond-floor test literals (R30's bond half); gross circulating supply into the burn (D2); proof-response widths (D5); the secret draw's count rule (N1); the recorder's block (N2); the stage-2 burn split (N3). Text fixed: stale line citations, the scenario count, the epoch length and a dated test input (D9–D12); a stale dependency comment (N4) |
| Closed by deletion | Five copies of the `SimParams` → `EconomicParams` literal (R2); a mid-year height without the genesis offset (R31); "no Rust owner" for the genesis-epoch height (D8); the public urn's reproduction (R21) and the FL-R18 race with its retired 2 % buffer (D6), instruments of superseded designs; the nearest-pow2 arm (R26); the ArticMine transliteration and its KAT inputs (D7, R30's zone half, `7bcea06e9`) |
| Closed by a §4 row | The stuffer's flat 300 atomic per byte (item 1) and the flat `0.1 SKL` fee (item 2), both the control arm; the fee-floor instrument's floor at `SCALE` resolution (R29); the f64 closed forms of the m-of-n rule (R22); gate-7's one shard per `blocks_per_shard` (D1); the A3 and A4 base paths' plateau curve (D3); the maturity operands (D13) |
| Staking-excepted (ruled 2026-10-03) | The stake schedule and stake ratio (D4) |
| **Open** | none |


### The eleven restated rows open at the re-census

The first two columns are the tree at `258b4d851`. The last says what
ESR-8 did.

| # | What remained | Closes by | In ESR-8 |
| --- | --- | --- | --- |
| R3 | Two test literals, `let coin: u64 = 1_000_000_000` (`fee_ladder.rs:3004`, `:3098`). Every non-test `COIN` derives from `shekyl_units::ATOMIC_UNITS_PER_SKL` | `crate::burden::COIN` | Closed: both tests read `crate::burden::COIN` |
| R10 | No fold restated the three differences the first census listed: the penalty, the net supply and the height-0 share are production's. What remains is that each fold composes the reward chain from production's parts (`split_block_emission`, `compute_burn_split_at`) and none calls `price_emission`, which owns the order they run in | A decision (below) | Closed: the cursor calls `price_emission` and the folds read its `PaidEmission`; the stuffer's payout calls it too. See the note under the direction |
| R13 | `0.25` as the flat staker share in the fee-horizon report (`fee_horizon.rs:151`) and its test (`:203`). The literal moved here from `onset.rs` with the closed form | `escalation::floor_share()` | Closed: the share and its label come from `floor_share()` |
| R15 | Report strings that spell a constant: "0.75" (`stage2.rs:622`, `:1241`; `scenarios.rs:430`, with "75 coins" and "7_500 coins" at `:437`, `:444`), "4096 shards" (`stage2.rs:1508`) | Interpolate `ARCHIVAL_BOND_FLOOR_ATOMIC` and `MAX_HOLDINGS_SHARDS` | Closed: every string interpolates the constant. Both narration fixtures match byte for byte |
| R16 | One table header, "split-loss@4096" (`admission.rs:155`); the value beside it already reads the constant | Interpolate `MAX_HOLDINGS_SHARDS` | Closed |
| R17 | `BandedCurveParams::from_plateau_value(8_000)` (`population.rs:43`) | `shekyl_archival_retention::reward_arithmetic::ARCHIVAL_PROVISIONAL_CURVE` | Closed: `reward_curve()` returns the constant |
| R18 | `AGE_WEIGHT_MILLI = 1_000` (`population.rs:56`); production's is 2 000. Declared inert in its own comment, not in §4 | `ARCHIVAL_REWARD_AGE_WEIGHT_MILLI`, or a §4 row saying why the sim's differs | Closed by import (1 000 → 2 000). No figure moved, which is the inertness its comment claimed |
| R19 | `N_HARD_BOUND = 25` (`mn_feasibility.rs:55`) | A new `pub` export: the bound exists in production only as a const-assert over a private constant (`failure_window.rs`) | Closed: `FAILURE_WINDOW_N_GATHER_BOUND`, a named `pub` constant the assert now reads |
| R21 | The exact-min urn and its even-spread schedule (`challenge_coverage.rs`). **Its production owner no longer exists**: `ChallengeUrn` and `assign_epoch` were deleted when the secret draw replaced the public urn | A decision (below) | Deleted 2026-10-15: the urn it reproduced was superseded by the secret draw and its production code deleted 2026-10-10. The module was last at `4de99d1e1b` |
| R22 | The f64 closed forms of the m-of-n rule (`mn_feasibility.rs`, `cartel.rs:136`). Cross-checked against the predicate-backed kernel by test; no production counterpart to import | A §4 row | Closed by its §4 row |
| R23 | `1.0 + SLASH_GRACE_EPOCHS` (`cartel.rs:249`) | A new `pub` export of `SLASH_SETTLEMENT_TIP_LAG_EPOCHS`, private today | Closed: the constant is `pub` and `cartel.rs` reads it |

### The dead-referent rows

| # | What remained | Closes by | In ESR-8 |
| --- | --- | --- | --- |
| D1 | One shard per `SETTLEMENT_EPOCH_BLOCKS` blocks (`engine.rs:83`), called a model parameter where it is defined | `shekyl_types::archival::shard_of`, or a §4 row | §4 row. The row says the default understates the lock by a factor near 900; moving gate-7 onto the byte fold is a separate step (`FOLLOWUPS.md`) |
| D3 | The A3 and A4 base paths still score through the plateau curve; credited work is linear in production | A §4 row, or the linear owner | §4 row. Re-basing A3 and A4 on linear work is a separate step (`FOLLOWUPS.md`) |
| D5 | Proof-response widths as literals (`proxy.rs:92`) | `shekyl_fcmp::tree` constants, which needs a new dependency | Closed by import: `RESPONSE_BYTES` is built from `shekyl_fcmp::tree`'s widths and `CHALLENGED_LEAF_LEN`, and a const-assert holds it at 6 784 |
| D6 | The retired 2 % relay buffer, as `* 98` and `< 1020` (`fee_ladder.rs:1717`, `:2329`, `:2505`), in a file that also asserts the slack is 0 | `relay_floor_admits` | Deleted 2026-10-15: the race measured admission under FL-R19, which FL-R23 superseded and production runs. The race code was last at `4de99d1e1b` |
| D7 | The ArticMine transliteration (`fee_ladder.rs:198-210`). §4 declares its KAT inputs, not the transliteration | A §4 row | §4 row. The transliteration and its KATs are deleted (`7bcea06e9`) |
| D9–D12 | Stale citations, "8 scenarios" where there are nine, "~35 days" for an epoch, a dated representative run | Text | Text fixed: line numbers into C++ replaced by the function named; the scenario count is read from the run; the always-empty `stuffing_profitable` field is deleted; "one epoch" is "25,000 blocks"; the 2026-07-30 figure is labelled a test input |
| D13 | Maturity operands as literals (`MATURITY_D = 324_000`, 40 000 projected pairs) | A §4 row naming them as assumptions | §4 row |

### Found by this pass, in neither the first census nor §4

| # | What was found | Closes by |
| --- | --- | --- |
| N1 | **The secret draw's count rule is restated.** §4's ESR-11 row says "no production function exists to call". It does now: `shekyl_archival_retention::{draw_horizon, draw_count, select_draw}`. The sim keeps its own `horizon()`, `block_target()` and three constants (`MIN_HORIZON_BLOCKS`, `CATCH_UP_BY_PERMILLE`, `CAP_MULTIPLE`); only `COUNTED_DRAWS` is pinned to its owner. Whether the sim's f64 `block_target` equals production's fixed-point `draw_count` was read, not run | **Closed by ESR-13** (PR #1050, merged while this PR was open): `secret_draw_production.rs` calls all three, and `secret_draw.rs` was kept as it ran, as the `f64` reference, under its §4 row. See below. **Superseded 2026-10-13 by ESR-14** (§5.20 item 7, §5.21): `secret_draw.rs` calls the three too, and the `f64` rule and sampler are gone |
| N2 | **The recorder priced a block the chain does not build.** It paid `effective_emission` on the schedule's whole demand, fifty transactions a block. At the control arm's fee that is 630 to 765 kB against a 300 kB penalty-free zone: over the block-weight limit while the median sits at the zone, so the missing penalty was the smaller half of it. The loop's own comment declared the omission; §4 declared its volume operand only | **Fixed in ESR-8:** the recorder steps the cursor. The burn and the multiplier are that window too: the per-block recomputation §4 had declared is withdrawn. The vectors were regenerated and every column that moved is accounted for below |
| N3 | `stage2.rs` split the fee burn at the flat `staker_pool_share` where the engine and budget folds use `compute_burn_split_at` at `n = 0`. The two are equal at the shipped parameters and nothing failed if they stopped being equal | **Closed:** the stage-2 ledger advances by production's destroyed amount at the fold's closed-shard count, and `the_shipped_split_is_flat_at_every_count` fails when the shipped asymptote leaves the floor |
| N4 | `Cargo.toml` justified the `shekyl-chain-rules` dependency by `EMISSION_SPLIT_EPOCH`, which that crate no longer provides. The dependency is still used, for the medians, the volume span and the reference-block age | **Closed:** the comment says what it is used for |

A fifth observation, not a row: the bound R19 imports is the C++
gather's. `failure_window.rs` holds a second, tighter condition for the
Rust gather (`WINDOW_MIN_OBSERVATION_PER_MILLE`), which at the shipped
values admits no `n` above 13. `mn_feasibility.rs` sweeps `n` to 25
under the name "hard bound". The sweep is unchanged here; which bound
the report should name is a question for the lane that owns the window.

### Direction on the three decisions (received 2026-10-12)

Relayed review direction, matching what this pass recommended. It is
recorded as direction, not as a signed ruling.

1. **R21.** `challenge_coverage.rs` was deleted 2026-10-15, with its
   nightly test; the urn it reproduced is superseded by the secret draw.
2. **R10.** The folds call `price_emission`. Where its signature does
   not fit a fold, that is a finding about `price_emission` and the fix
   is there, not a third copy in the sim. Built; see below.
3. **The secret draw (N1).** Equivalence first: the sim's rule and
   production's run on the same inputs, agreement or the delta recorded,
   and only then the calls switched. Overtaken by ESR-13; see below.

### N1: closed by ESR-13, and what this PR withdrew

> **Superseded 2026-10-13 by ESR-14** (§5.20 item 7, §5.21). What follows
> is the tree at ESR-8's merge. ESR-14 made the withdrawn move again,
> with the rule's callers shared between the two modules: `secret_draw.rs`
> calls `draw_count`, `draw_horizon` and `select_draw`, and ESR-13 no
> longer prints an `f64` reference.

ESR-13 (§5.17 to §5.19, PR #1050) landed on `dev` while this PR was
open. It runs the secret draw on production's `draw_count`,
`draw_horizon` and `select_draw` in a module of its own, and keeps
`secret_draw.rs` unchanged as the `f64` reference it prints beside its
own cells and calls in its tests. That closes N1.

This PR had made the same move inside `secret_draw.rs`: it deleted the
`f64` rule and called the owners there. That change is withdrawn at the
merge with `dev`. ESR-13 needs the module as it ran, and one arm on the
owners is enough. `secret_draw.rs` and `challenge_coverage.rs` were
`dev`'s at that merge, byte for byte.

One result from the withdrawn work stands as corroboration, and its code
is in this branch's history at `2395057f41`. An epoch ran under either
count rule on one random stream, over 120 epochs: set sizes 1, 7, 500,
4 096 and 16 384; dropout 0, 10, 50 and 100 %; both in-flight readings;
three seeds. Drawn, issued, the issued histogram, the largest block and
the unpaid reads were equal in every epoch. ESR-13 measures the same
agreement on its own runs (§5.18).

### R10 as built, and what it found about `price_emission`

`price_emission` fits the folds with no change. The cursor calls it once
the fill has decided what the block lists, at the bodies' weight, and
asserts on every block that the fill's reward and the composition's paid
reward are one number. The folds and the stuffer advance and price from
that paid reward. The fill's copy is read only by the assert.

One misfit was on the sim's side. `price_emission` splits at the shipped
share, decay and year: they are free constants in `shekyl-economics`, not
fields of `EconomicParams`, and the wallet's calibration stamp digests
them beside the parameter set for the same reason. `SimParams` carried
`staker_emission_share` and `staker_emission_decay` as if a run could
vary them; no scenario did, and both fields are removed. The decay lever
in `onset.rs` is a counterfactual on a year's totals and still calls the
share kernel with its own decay. `SimParams::blocks_per_year` stays as
the fold's bookkeeping year and its doc says the share does not follow
it.

Three composing sites remain by design: the budget fold's arm (b), which
is the declared unmodulated counterfactual; the stuffer's tests, whose
written-out arithmetic is the independent side of a comparison; and
`the_shipped_split_is_flat_at_every_count`.

### N2: the recorder's regenerated vectors

`docs/test_vectors/economics/baseline_steady_state.json`, eleven rows.
The metadata and the neutral milestones are unchanged. Every row moved,
and each move follows from one fact: the fill lists 20 to 24 of the 50
transactions offered, because ordinary transactions at the control fee
fill the 300 kB zone at 24 in an empty tree and at 20 in a deep one, and
the fee does not cover the penalty past it.

| Column | Before → after (year 1, last block) | Why |
| --- | --- | --- |
| `tx_volume` | 50 → 21 | It is the listed count now, not the demand |
| `release_multiplier_milli` | 1000 → 800 | `calc_release_multiplier` at 21 against a baseline of 50 is at `release_min` |
| `already_generated_coins` | 2.608e17 → 2.100e17 | The chain released at 0.8 of the curve for a year |
| `base_block_reward` | 9.618e11 → 9.739e11 | The curve at less emitted |
| `circulating_supply`, `total_staked` | follow `already_generated_coins` | Net supply, and a fixed stake ratio of it |
| `burn_pct_bp` | 303 → 158 | `calc_burn_pct_from_activity` at the lower volume and the lower supply |
| `staker_emission` | 1.298e11 → 1.052e11 | The share of a reward paid at 0.8 |
| `staker_fee_pool`, `actually_destroyed` | 3.80e7 → 8.32e6, 1.14e8 → 2.49e7 | 21 fees in place of 50, at the lower burn |

The first row (height 1) keeps its burn at zero and moves only through
block 0, which an empty window prices at `release_min`.

At that regen `shekyl-engine-core`'s differential passed on the new
vectors without a code change: it recomputed `base_block_reward` and
the burn from each row's own operands, which were then the listed count.

A consequence for a reader of the control arm, not a defect: on the
flat fee the baseline never fills past the zone, so it never reaches its
own volume baseline and its release multiplier sits at the floor for
the whole run. The scenario folds have shown this since ESR-6; the
recorder now shows it too.

The same ESR-8 then closed the operand split that regen left in place.
The block was priced at the window, and the row recomputed
`burn_pct_bp` and `release_multiplier_milli` at the listed count as a
one-block volume; §4's row for that split is withdrawn. The row now
stores the window (`volume_tx_count_sum`, `volume_window_blocks`) and
both columns are taken from it. `tx_volume` remains the listed count.
The differential replays `TxVolume::window` of that pair and does not
read `tx_volume`. On the regenerated baseline every sampled window mean
is the listed count — 24 over the one block before height 1, then 21
and 20 over the full 720-block window at the year ends — so
`burn_pct_bp` and `release_multiplier_milli` do not move. The operand
is the window anyway.

## Appendix B — census of `shekyl-staking-sim` (as reported, at `bb021f254`)

Read-only pass, 2026-10-02. Row labels are local to these tables (§8).

The sim calls production in only a handful of places; the population model restates or assumes almost everything else, and three of its core mechanisms model things production has since retired. No file was edited.

Paths: `sim/` = `rust/shekyl-staking-sim/src/`, `prod/` = `rust/shekyl-archival-retention/src/`, `econ/` = `rust/shekyl-economics/src/`, `DOC` = `docs/design/STAKER_ARCHIVAL_SIM.md`. Tags: **V** = verified by reading definition and use; **I** = inferred.

### Confirmation of the four known items

1. **Confirmed.** `sim/model.rs:641` `g_age` (f64) and `sim/reward.rs:67-76` `raw_work` (f64) sit beside the imports at `sim/reward.rs:25`.
2. **Confirmed.** The purse is `budget: 100.0` at `sim/scenarios.rs:2067`; only `sim/budget_throttle.rs:58,69-71` reads `EconomicParams`.
3. **Confirmed.** `REGISTERED_SHARD_TX_COUNT = 200.0` at `sim/model.rs:221`, declared at `:214-220`.
4. **Confirmed.** `storage_unit_cost: 0.03` at `sim/scenarios.rs:2074` and `age_weight: 2.0` at `:2070`. The L19h calibration lives only in the doc (`DOC:4868-4891`), not in code.

### (D) Dead / stale referent

The first three rows are structural: every registered run inherits them from `baseline()`.

| # | Sim site | What it models | Production state | Tag |
|---|---|---|---|---|
| D1 | `sim/reward.rs:121-132` `curve`, `:135-154` `split_decision`, `:184-199`; `sim/curve.rs:9-39`; defaults `cap: 8.0`, `pseudonym_cost: 0.05` at `sim/scenarios.rs:2068-2069`; cap sweep `:2262-2268` | Per-pseudonym banded plateau on work, plus optimal pseudonym splitting | Plateau deleted from the reward path (D3/R2); credited work is linear and membership-gated: `prod/consensus_state.rs:190-210`, `prod/reward_arithmetic.rs:109-110`, `config/consensus_constants.json` `_comment_archival_reward_path`. The sim's `8.0` restates `ARCHIVAL_PROVISIONAL_CURVE` (`prod/reward_arithmetic.rs:120-121`). `curve_milli` is imported but is sim/counterfactual-only in production. `docs/design/ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md:1609-1610` lists `shekyl-staking-sim::reward` among the plateau's consumers; the sim still applies it. DOC never mentions D3/R2 (grep empty). | V |
| D2 | `sim/agent.rs:104-342` (whole portfolio re-chosen in place every epoch); L9 lock `sim/agent.rs:288-295`, `sim/model.rs:670-673`; L18 escrow `sim/model.rs:356-372`, `sim/agent.rs:131-151,333-339`; axis `holdingsupdate_cooldown` `sim/scenarios.rs:3899-4065` | In-place per-shard add/drop (`HoldingsUpdate`) with a per-shard duration lock and per-shard release cooldown | `HoldingsUpdate` rejected 2026-09-20; a bond is fixed at join and holdings change by `Release` + `JoinMarket`: `prod/bond_wire.rs:47-58`, `prod/admission.rs:79-83`. DOC did not record the rejection at this row's pin (grep empty); its §L18 heading carries it since 2026-10-04. | V |
| D3 | `sim/participation.rs:227-233` `foundation_floor`, `:247-263` `foundation_floor_aged`; arms `sim/scenarios.rs:2798-2815,2943-2944,3198-3214,3288-3289,3815-3846` | Foundation floor that decays to zero at `decay_pop` | The sim's own comment at `sim/scenarios.rs:3862-3866` says the ratified design is a permanent complete-tree floor with no `decay_pop` withdrawal. Production: foundation excluded from market, `prod/consensus_state.rs:106-116,699`; single-floor bond `prod/bond_floor.rs:28-30`. | V (sim) / I (ratified design, from the comment) |
| D4 | `sim/audit.rs:22-49`; defaults `sim/scenarios.rs:2161-2166` | L14 read-credited probabilistic audit cadence | Fixed 3 challenges per pair per epoch (`prod/constants.rs:30`), 2-of-3 threshold (`prod/attestation.rs:71`), m-of-n slash (`prod/failure_window.rs:334-337`). No read credit: `DOC:4904`. | V / I (no read credit) |
| D5 | `sim/failure_confirmation.rs:269,789,969` | "Production baseline: `H_fire` beacon" | Fire-beacon shape superseded by derived assignment: `prod/constants.rs:67-78`. | V |
| D6 | `sim/model.rs:221-227,265` | `T = 200` tx-count partition | Retired by SHT-Q2; `shekyl_types::SHARD_LENGTH` at `rust/shekyl-types/src/archival/mod.rs:128`. Declared, so also in (X). | V |
| D7 | `sim/cover.rs` (whole module; `:1574-1600` `cover_dial_span_atomic`) | Count-dependent `span(C)` cover curve | Retired 2026-07-21; production is `COVER_RUNG_ATOMIC` at `rust/shekyl-standoff/src/cover.rs:41`. Declared at `sim/cover.rs:70-79,1630-1636`. | V |
| D8 | `sim/standoff.rs:75-87,132-134,246-250,295-302` | Inversion / order coin (`bond_first`) | No order coin: `rust/shekyl-standoff/src/draw.rs:89-96`. Undeclared in this module. | V |
| D9 | `sim/gf7_timeline.rs:77-93`, `sim/riders.rs:316-322`, `sim/gf7_breakeven.rs:109,245`, `sim/partition_adversary.rs:90-93` | Entry-seam correlator, founder-cover arm | Declared fail-closed / retracted in their own banners. | V (banners only) |
| D10 | `sim/main.rs:30,2028`; `sim/gf7_seal.rs:9`; `sim/partition_adversary.rs:113` | `K_COVER` seal references | `K_COVER` gate retired: `prod/consensus_state.rs:680-684`. | V |
| D11 | `rust/shekyl-staking-sim/Cargo.toml:27` | Comment "(ARCHIVAL_REWARD_GATE_M1.md §4) — delete this feature at the §14.4 seal" above the archival-retention dependency | M1 gate retired (doc now under `docs/completed/`); the dependency carries no feature. | V |

### (R) Restated production constant or formula

| # | Sim site | Name / value | Represents | Production owner | Tag |
|---|---|---|---|---|---|
| R1 | `sim/model.rs:641-643` | `g_age = 1 + w·age` (f64) | Age premium | `g_age_milli`, `prod/reward_arithmetic.rs:50-54` | V |
| R2 | `sim/reward.rs:67-76` | `raw_work = Σ (1/R)·g` (f64, no floor) | Per-actor work | `scarcity_micro` `prod/reward_arithmetic.rs:71-82`; `shard_work_micro` `prod/consensus_state.rs:154-164`; `shard_contribution_micro` `:646-661`; micro accumulation with a single milli floor `:605-626`, `work_milli_from_micro` `prod/reward_arithmetic.rs:94` | V |
| R3 | `sim/reward.rs:194-202` | `price = budget/Σcapped`; `reward = price·capped` | Per-epoch split | `reward_share_floor` `prod/reward_arithmetic.rs:128-133` (floors, dust unminted); `sigma_work_milli` `prod/consensus_state.rs:175-186` | V |
| R4 | `sim/agent.rs:198-201`; `sim/clustering.rs:251-264` | `value = price·(1/r_eff)·g_age` | Marginal value, a second float copy of R1/R2 | same as R1/R2 | V |
| R5 | `sim/reward.rs:177`, `sim/model.rs:548-558` | `r = World::replication()` | Replica count in the reward | `r_market`: `prod/consensus_state.rs:131-148,591-596` (semantics below) | V |
| R6 | `sim/model.rs:670-673` | `bond_duration = round(base·(1+scale·age)).max(1)` (f64) | Retention horizon | `prod/bond_duration.rs:142-153`; relationship declared there at `:51-63` (stale pointers `model.rs:417`, `agent.rs:275-280`). Sim defaults `0.0/0.0` (`sim/scenarios.rs:2088-2089`), `4.0` in `dyn_base` (`:2355`), scale grid {0,2,4,8}; production 4/4. | V |
| R7 | `sim/scenarios.rs:2070`; `sim/clustering.rs:122` | `age_weight: 2.0` | `g` slope | `ARCHIVAL_REWARD_AGE_WEIGHT_MILLI = 2000` (generated, `prod/build.rs:207`), used at `prod/consensus_state.rs:436` | V |
| R8 | `sim/scenarios.rs:2075` (2.0), `:3435,3532,3553,3583,3612,3760` (0.75); `sim/clustering.rs:126` (2.0) | `bond_rate` | Per-shard bond | `ARCHIVAL_BOND_FLOOR_ATOMIC = 750_000_000`, `prod/bond_floor.rs:27-43`. Never imported by the population sim. | V |
| R9 | `sim/main.rs:1887` | `let floor_atomic = 750_000_000u64` | Bond floor literal | same (already imported at `sim/cover.rs:83`) | V |
| R10 | `sim/scenarios.rs:2100` (default 0), grids `:3941,3966,4002,4045`; comments `sim/agent.rs:73`, `sim/scenarios.rs:112,3903` | `release_cooldown_epochs`, "`= 2`" | Cooldown | `RELEASE_COOLDOWN_EPOCHS`, imported only at `sim/timing_cluster.rs:22`. Mechanism differs: production is whole-record, anchored at last-served epoch (`prod/release_cooldown.rs:54-90`); sim is per-shard, anchored at drop. | V |
| R11 | `sim/fingerprint.rs:20`; `sim/scenarios.rs:2177,3446`; `sim/cover.rs:1062-1063` (`600.0/10_000.0`) | `SEB_DEFAULT = 10_000` | Settlement epoch | `SETTLEMENT_EPOCH_BLOCKS` `prod/constants.rs:245`; `DEFAULT_ENTRY_GAP_WINDOW` `rust/shekyl-standoff/src/draw.rs:80`. Both are imported elsewhere in the crate. | V |
| R12 | `sim/timing_cluster.rs:32`; `sim/fingerprint.rs:22` | `BLOCK_TIME_SEC = 120` (twice) | Block time | `daa_target_seconds` (config) → `rust/shekyl-difficulty/src/consts.rs:33` | V |
| R13 | `sim/failure_confirmation.rs:36` | `BLOCK_WEIGHT_LIMIT_BYTES = 300_000` | Block budget | `FULL_REWARD_ZONE` `econ/params.rs:17`. That is the reward zone, not the limit (`econ/emission.rs:265`). | V |
| R14 | `sim/failure_confirmation.rs:668-672` | 1 baseline challenge per pair per epoch | Challenge volume | `CHALLENGES_PER_PAIR_PER_EPOCH = 3`, `prod/constants.rs:30` | V |
| R15 | `sim/failure_confirmation.rs:1087-1088` (m=2, n=5), sweep `:748-749`, `:1127-1136` | Sliding window m-of-n | Slash window | `FAILURE_WINDOW_M/N = 11/13`, `prod/failure_window.rs:334-337`. Imported only in tests (`sim/failure_confirmation.rs:1193`). The policy function `:526-551` is equivalence-tested against production (`:1254`). | V |
| R16 | `sim/fingerprint.rs:145-149` | `serve_credit_bit = deep && held && inflight==0` | Serve credit | `settle_epoch` and `SERVE_THRESHOLD_PASSES = 2`, `prod/attestation.rs:71,192`. **UPDATE 2026-10-08 (`SO-D10e`):** `settle_epoch` is deleted; the fold is `settle_pair` (`prod/settlement_select.rs`) and `SERVE_THRESHOLD_PASSES = 2` is in `rust/shekyl-types/src/archival/settlement.rs` | V |
| R17 | `sim/timing_cluster.rs:33`, `:171` | `JOIN_LAG_BLOCKS = SEB`; `verify_f4_slow_emitter(25, 1)` | Join lag; W−1 | `good_through` `prod/consensus_state.rs:85-102`; `MAX_CLAIM_AGE_W = 26` | V |
| R18 | `sim/budget_throttle.rs:107-111` | `emis_frac` 1.0 / 0.012 | Emission share of the purse | Hand-copied from `shekyl-economics-sim` output; computable from `econ/emission_share.rs:33`, `econ/burn.rs:124` | V (literal) / I (source) |
| R19 | `sim/failure_confirmation.rs:24-27`; `sim/clustering.rs:122-134,156-157,205-206`; `sim/cover.rs:336-337,912-915`; `sim/budget_throttle.rs:115` | L16 constants, baseline constants and endowments, 80/20 operators, `N_P` 17/79/154, knee 80/86 | Intra-sim copies of `baseline()` values and of registered-run outputs | Owner is `sim/scenarios.rs:2051-2197` and the doc tables. `sim/clustering.rs:114-117` claims "single-sourced" but retypes. | V |
| R20 | `sim/model.rs:25-41`, `sim/standoff.rs:176-185`, `sim/clustering.rs:85-97`, `sim/cover.rs:166-179` | Four SplitMix64 copies | PRNG | Intra-crate | V |

### (X) Declared exception

| Sim site | Value | Declared where | Tag |
|---|---|---|---|
| `sim/model.rs:221` | `REGISTERED_SHARD_TX_COUNT = 200.0` | `sim/model.rs:214-220` | V |
| `sim/cover.rs:87` | `ATOMIC_PER_SKL = 1e9` (owner `rust/shekyl-units/src/lib.rs:59-68`) | `sim/cover.rs:85-86` | V |
| `sim/wallclock_leg.rs:69` | `TICK_MS = 60_000` (owner `DEFAULT_PSCAN_CADENCE`, `rust/shekyl-engine-core/src/engine/pscan/start.rs`) | `sim/wallclock_leg.rs:64-68` | V |
| `sim/reward.rs:36-40` | `CurveImpl::Float` (`curve_banded`) | `sim/reward.rs:27-34`; it wrongly calls `Integer` "authoritative" (see D1) | V |
| `sim/model.rs:493-510` | Fixed recycling window, "retire at age 1" | `sim/model.rs:459-463` | V |
| `sim/cover.rs:1574-1600` | Local `k(C)` copy | `sim/cover.rs:1630-1636` | V |

### (A) Assumed exogenous (no production owner)

| # | Sim site | Name / default | Declared? | Tag |
|---|---|---|---|---|
| A1 | `sim/scenarios.rs:2067`; `sim/reward.rs:44-47` | `budget = 100` model units per epoch, constant | Declared as a fixed pool. Not derived from emission and fees. | V |
| A2 | `sim/scenarios.rs:1161-1179`; `:2121-2127`; L13 `:2853-2855` | Fee-era purse: `base ← floor + (base−floor)(1−decay)`; `budget_floor`, `budget_ceiling`, `budget_decay 0.02` | Declared as a stress model. No link to `econ/emission.rs:79` or `econ/emission_share.rs:33,62`. | V |
| A3 | `sim/scenarios.rs:1164-1175` | Adaptive servo `budget_eff = base·(1+gain·signal)`, `share_gain 8.0` | No production owner. The nearest lever, `staker_pool_share_at` (`econ/escalation.rs:283`), keys on closed-shard count and is flat today. `DOC:2773-2780` states the servo as a gate-5 requirement. | V |
| A4 | `sim/scenarios.rs:1634` | Trust EMA `0.75/0.25` | Literal in an expression; rationale in a comment. | V |
| A5 | `sim/scenarios.rs:2074`; `sim/agent.rs:202` | `storage_unit_cost = 0.03` per shard per epoch | Silently pinned in code. `DOC:4865`: "never calibrated against anything". | V |
| A6 | `sim/scenarios.rs:2077`; `sim/agent.rs:202-203`; `sim/participation.rs:88-90` | `bond_carry = 0.03`, flat per deep shard; does not scale with `bond_rate` | Silently pinned. | V |
| A7 | `sim/scenarios.rs:2078`; `sim/model.rs:90-92`; `sim/agent.rs:123-129,249` | `deep_threshold = 0.5`; only deep shards bond | Undeclared divergence: production floor is flat times shard count with no age input (`prod/bond_floor.rs:27-38`). | V |
| A8 | `sim/scenarios.rs:2189-2190`; `sim/model.rs:692-696` | `r_target` 3 hot / 6 deep, linear in age | Stipulated; DOC L15 says so. No production replica target. | V |
| A9 | `sim/scenarios.rs:2110-2111` (0), L11 `:2689-2690` (0.02); `sim/model.rs:311-318` | Reservation yield ρ | Declared exogenous, post-testnet: `DOC:2586-2588`. | V |
| A10 | `sim/scenarios.rs:2670-2671` | `entry_per_epoch = 6`, `participation_patience = 3` | Declared in comments. | V |
| A11 | `sim/scenarios.rs:2055-2066` | World size: 240 shards, 80 actors (240 from L11); endowments 22/20, 10/100; whale 150/600 | Calibrated to sit at the coverage margin, `:2037-2050`. | V |
| A12 | `sim/scenarios.rs:2127,2131-2134,2138-2145` | `price_coupling`, `token_price`, `price_decay`, shock knobs | Declared exogenous (`:1075-1078`). | V |
| A13 | `sim/scenarios.rs:2093-2097`; `sim/model.rs:681-686` | `fetch_latency_per_unit`, `acq_rate`, `reseed_rate` (3 = "N_active seeds", `:3870`) | Declared as a post-testnet measurement. | V |
| A14 | `sim/scenarios.rs:2151-2156,2174-2175`; `sim/transport.rs:28-36` | Uptime 0.9, SLA 0.999, survival 0.999, `transport_u_k 0.07` | Declared. | V |
| A15 | `sim/scenarios.rs:2087` (0), 0.05 in dynamic bases (`:2353`), 0.02 in f34 (`sim/f34_heavy_era.rs:43`) | `epoch_aging` | Sets the window length; no production mapping. | V |
| A16 | `sim/scenarios.rs:1923-1937`; `sim/metrics.rs:16,172-174`; `sim/budget_throttle.rs:75,80`; `sim/f34_heavy_era.rs:39` | Verdict bars 0.05 / 0.20 / 0.10; band grids | Stated. | V |
| A17 | `sim/model.rs:655-659` | `bond_age` tilt (`deep_mid`, `.max(0.05)`) | Declared L4 counter-evidence; default scale 0. | V |
| A18 | `sim/model.rs:405-408,370`; no `capital` mutation anywhere (grep) | Slashing | Comments say exit "forfeits" collateral; the code never reduces capital. Production: `prod/failure_window.rs:362`, `prod/consensus_state.rs:85-102`. | V |
| A19 | `sim/failure_confirmation.rs:29,32-35,39,42,45` | Outage mean 2.0, 2,000 archivers, 6 shards per P, 2,048-byte vin, 0.05, 0.90, 0.99 | Stated as order-of-magnitude. | V |
| A20 | `sim/fingerprint.rs:25-35`; `sim/standoff.rs:106-118`; `sim/riders.rs:44-75`; `sim/partition_adversary.rs:98-122,472-546` | Privacy-harness thresholds and geometries | Stated. | V (consts only) |

### Answers to the specific questions

- **Reward and split.** `reward_a = budget · Curve(raw_a) / Σ Curve(raw)` in f64, with the plateau and pseudonym split active (`sim/reward.rs:176-210`). Production is linear, membership-gated, micro-accumulated, floored once per bond, then `floor(budget·credited/Σ)`.
- **What `r` counts, and lag.** The sim counts bonded (committed) holdings: actor-distinct, in-flight fetches included, no serve-credit gate (`sim/model.rs:543-558`; `sim/reward.rs:60-66`). Production counts served, member pairs as of epoch close.
  - Lag on `r` is zero in the sim: `evaluate` runs after `run_epoch` in the same epoch (`sim/scenarios.rs:1291,1326`). The one-epoch lag is on `price` only (`:1327-1331`, seeded 1.0 at `:999`).
  - There is no membership onset: entrants earn in their entry epoch (`:1282`). Production credits from `join_epoch + 1` (`prod/consensus_state.rs:90`).
  - Foundation is excluded in both.
  - `serving_replication` (`sim/model.rs:568-578`) feeds metrics only.
- **Bond per shard and carry.** Bond is `bond_rate` flat per deep shard: 2.0 at baseline, 0.75 in pinned arms; hot shards carry none. Constraint is `Σ bond ≤ capital` (`sim/agent.rs:249-252`). Carry is a flat 0.03 per deep shard regardless of bond size. Production is 0.75 SKL per shard for every held shard.
- **Unit mapping (I).** `config/consensus_constants.json` `_comment_archival` and `docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md:264-295` set 1 sim capital unit = 1 SKL. The purse is 100 units per epoch, while `DOC:4908` computes production `budget(E)` at 2,413,775 SKL per epoch in year 1. L19h sidesteps this with a dimensionless ratio; nothing else reconciles it.
- **Epoch length.** No fixed mapping. Duration (4) and cooldown (2) are compared to settlement-epoch constants, L19h treats an epoch as 1 SEB (`DOC:4902`), but TA1 sets `blocks_per_sim_epoch = 2000`, i.e. 0.2 SEB (`sim/scenarios.rs:2178,3440-3446`).
- **Shard size / length.** Relative units only (`deep_shard_size 1.0`, `Shard.size`). The crate does not depend on `shekyl-types`, `shekyl-chain-rules` or `shekyl-units`, so `SHARD_LENGTH`, `shard_of` and shard close are unused. `DOC:4903,4909` still size shards as 200 tx.
- **Age units.** Sim age is position in a fixed recycling window. Production is epochs since shard close over chain depth in epochs, in milli (`prod/consensus_state.rs:234-251`); open shards score 0. Both range over [0,1] but with different referents (`DOC:937-950`).
- **Challenge / witness.** See R14-R16 and D4. `p_attempt` is not in this crate; it is at `rust/shekyl-economics-sim/src/mn_feasibility.rs:79,386`.
- **Holdings cap.** None; `storage_capacity` is the only bound. `MAX_HOLDINGS_SHARDS = 4096` (`rust/shekyl-types/src/archival/mod.rs:78`) is never referenced.
- **Admission.** No counterpart to `ADMISSION_MIN_WORK_MILLI` (`prod/admission.rs:97`).
- **Defaults: where set.**
  - The single source is `baseline()` at `sim/scenarios.rs:2051-2197`. There is no `Default` impl and no config file.
  - Per-layer closures: `dyn_base :2350`, `surplus_base :2391`, `lean_base :2450`, `lag_base :2540`, `l11_base :2660`, `l12_base :2760`, `l13_base :2846`, `l11_coloc_base :2963`, `l13_fiat_base :3013`, `l15_base :3068`, `l14_base :3127`, `l16_base :3224`, `l15d_base :3297`, `gate4_fine_base :3384`, `ta1_hygiene_base :3433`, `layer2_base :3530`, `swan_base :3610`.
  - World init: `sim/model.rs:376-395`, `sim/scenarios.rs:680-790`.
  - CLI overrides: only `--curve-impl` and `--axis` (`sim/main.rs:2115-2163`).
  - f34 levers: `sim/f34_heavy_era.rs:63-95`.

### Reverse provenance: production constants calibrated from this sim

- Bond floor 0.75 SKL: `config/consensus_constants.json` `_comment_archival`; `DOC:1904-1911`.
- Age weight 2000, band [1500, 2500]: config comment; `DOC:928-950`.
- Bond duration 4/4: `DOC:63-65`.
- Failure window 11/13: from `--failure-confirmation` (config `_comment_archival_failure_window`).
- Release cooldown 2: L18 seal.
- Production `bond_duration` has no caller in `rust/` or `src/`: only the re-export at `prod/lib.rs:99` and a comment at `src/blockchain_db/shekyl_types.h:1206` (grep). Its parity KAT (`prod/bond_duration.rs:212-226`) re-types the sim's f64 formula.

### (S) Sweeps / grids

- bond_rate {0.5, 2, 8} `:2207`; 20-point fine window `:3404-3407`
- age_weight {0, 2, 3, 4, 5} `:2225`; {1.5…4.0} `:3535`; {3…8} `:3994`; f34 ladder to 8.0 (`sim/f34_heavy_era.rs:351`). These go beyond the config band [1.5, 2.5].
- cap {4, 8, 16} `:2262`
- n_actors {25, 80, 200} `:2240`
- storage_scale `:2281,2299,2420`
- duration scale {0, 2, 4} `:2358`; {0, 1, 2, 4, 8} `:2577`
- latency {0, 1, 2, 3, 4, 6} `:2551,3245`
- ρ `:2701,2977`
- budget {50, 100, 200} `:2725`; {100, 200, 400} `:2994`; {100, 130, 160, 200} `:3560`; {140, 160, 180} `:3965`
- budget_floor {100, 80, 60, 40, 20} `:2867`; ceiling {70, 110, 200} `:2918`
- floor decay {40, 80, 160} `:2809`; tilt {0, 0.3, 0.6, 0.9} `:3193`
- cooldown {0, 1, 2, 4} `:3941`
- composition S {1, 2, 4, 10, 60} `:4078`
- f34 ladders `sim/f34_heavy_era.rs:349-351,434,475-478,507-509`
- seeds `sim/budget_throttle.rs:87-96`
- failure-confirmation `sim/failure_confirmation.rs:797,1102-1151`
- standoff `sim/standoff.rs:372-378`

### (P) Correct production imports, one line per file

- `sim/reward.rs:25` — `curve_milli`, `BandedCurveParams`, `WORK_MILLI_SCALE`. Correct as an import; the mechanism is retired (D1).
- `sim/budget_throttle.rs:58,69-71` — `EconomicParams::default().release_min / SCALE`.
- `sim/timing_cluster.rs:21-30` — `ARCHIVAL_REORG_DEPTH_BLOCKS`, `MAX_CLAIM_AGE_W`, `RELEASE_COOLDOWN_EPOCHS`, `RETENTION_HORIZON_BLOCKS`, `SETTLEMENT_EPOCH_BLOCKS`, `SLASH_GRACE_EPOCHS`, `MAX_SETTLEMENT_EPOCHS_PER_EMISSION`.
- `sim/standoff.rs:102,226,589` — SEB via `timing_cluster`; `GapRng`; `conformance::certify_draw` (test).
- `sim/failure_confirmation.rs:18,1193` — SEB; `failure_window_slashable`, `FAILURE_WINDOW_M/N` (tests only).
- `sim/cover.rs:83` — `ARCHIVAL_BOND_FLOOR_ATOMIC`.
- `sim/gf7_timeline.rs:71-72` — `BroadcastTimelineObserver`, `TimelineEvent`, `bounded_uniform`, `draw_entry_gap`, `DEFAULT_ENTRY_GAP_WINDOW`.
- `sim/partition_adversary.rs:80,115` — `draw_entry_gap`, `DEFAULT_ENTRY_GAP_WINDOW`.
- `sim/wallclock_leg.rs:60` — `bounded_uniform`.
- `sim/main.rs:2360,2392` — test-only curve imports.
- No production imports: `model.rs`, `agent.rs`, `participation.rs`, `metrics.rs`, `scenarios.rs`, `audit.rs`, `retrieval.rs`, `transport.rs`, `fingerprint.rs`, `clustering.rs`, `f34_heavy_era.rs`, `curve.rs`, `riders.rs`, `gf7_breakeven.rs`, `gf7_seal.rs`.

### Pinned tests and registered runs

**Crate tests.** No `#[test]` calls `run_sim`, `evaluate` or `build_scenarios` (grep). No CI job pins sim output; the only workflow touching the crate is `.github/workflows/gf7-no-emit-guard.yml:71-113` (dependency graph). All population-run numbers are pinned in docs only.

**(a) Purse replaced by production emission + fee inflow**

- Tests: none change. `sim/budget_throttle.rs:167-172` panics if `l11_bud_b100` is renamed.
- Every run changes, because `budget` sets `price` against costs fixed in model units (0.03 / 0.03 / 0.05) and ρ times bond. Directly purse-defined:
  - L11: `DOC:2527-2528,2536-2543,2553-2557,2564`
  - L12: `DOC:2609,2615,2625,2638-2642,2656-2660`
  - L13: `DOC:2733-2738,2744,2748-2749,2758-2762,2767`. The decay / floor / ceiling / servo model is the thing being replaced.
  - Layer-2: `DOC:857-864,877-882,891-895`
  - Gate-4 bond window, the evidence for the 0.75 floor: `DOC:1904-1911`
  - L17: `DOC:1117-1148`
  - L18: `DOC:3738-3745` (lean budget 120; buffered 140/160/180)
  - L19 family: `DOC:4187-4199,4454-4463,4590-4596,4681-4694,5006-5010,5154-5160`, plus the calibration `storage_unit_cost = φ·budget_sim/H` at `DOC:4870-4891`
  - `--budget-throttle` (`sim/budget_throttle.rs:107-115`)
- An existing production-sourced `budget(E)` is at `rust/shekyl-economics-sim/src/budget.rs:51-52,139`. Era figures: 2,413,775 / 960,334 / 304,084 / 3,004 SKL per epoch at years 1 / 5 / 10 / 30 (`DOC:4908`).

**(b) Float work replaced by production integer arithmetic**

- Tests that lose their subject if the production path (linear, no plateau) is adopted:
  - `split_raises_credited_work_below_plateau_work` — `sim/reward.rs:217`
  - `degenerate_cap_credits_zero_on_both_backends` — `sim/reward.rs:240`
  - `backends_agree_to_milli_precision` — `sim/reward.rs:262` (tolerates 2e-3 if only precision changes)
  - `reaches_plateau_at_twice_cap_work`, `monotone_increasing` — `sim/curve.rs:46,51`
  - `reconciliation_curve_float_vs_integer` — `sim/main.rs:2358`
  - `reconciliation_plateau_cross_check` — `sim/main.rs:2390`, pins `curve_milli(16_000) == 8_000`
- Tests that change signature or units:
  - `g_age_*` — `sim/main.rs:2219,2225`
  - `bond_duration_*` — `sim/main.rs:2249,2256`, pins `bond_duration(0.5,4.0,0.0) == 4`
  - clustering thresholds — `sim/clustering.rs:859-912` (`mean_r > 1.5`, `< 2.0`)
  - production `bond_duration_matches_sim_f64_over_full_age_sweep` — `prod/bond_duration.rs:212`
- Registered runs: all of the above. Precedent: Finding 0 (`DOC:839-851`) records that the last curve change moved `bondA` 79 to about 113 and broke the gate-4 cross-check rows; reversion clause (b) at `DOC:967-975` already names this trigger. L11/L12/L13 counts are marked pre-repair record at `DOC:2520-2523`. Most exposed: the lean and knee rows, L18 `oldest_min_committed = 6` (`DOC:3740-3745`), L19 SPLIT cells (`DOC:5010,5157,5159`), and the `cap` and `gini_pseudonym` columns.
- Unaffected by either: `--failure-confirmation`, `--timing-cluster`, `--standoff`, `--cover*` and the GF-7 modes (separate harnesses).

### Not checked / uncertain

- Const-swept and import-checked, not line-read: `gf7_timeline.rs` (other than `:76-130,236-300`), `partition_adversary.rs`, `gf7_breakeven.rs`, `gf7_seal.rs`, `wallclock_leg.rs`, `cover.rs:420-1545`, `main.rs:420-2000` (report printers). All other files were read in full.
- D3's "ratified design" rests on the sim's own comment; `docs/V3_STAKER_ARCHIVAL.md` was not opened.
- D4's "no read credit in production" rests on `DOC:4904` and the `prod/constants.rs` docs, not a full read of `challenge_assignment.rs`.
- "`bond_duration` has no production caller" is a grep over `rust/` and `src/`; the FFI was not line-read.
- The unit-mapping mismatch is inferred from documents; the 2.4M SKL figure is the doc's, not recomputed.
- `reseed_rate = 3` and `FOUNDER_COUNT = 5` (`sim/partition_adversary.rs:98`) were not traced to a production owner.
- Sim outputs pinned in other docs (`docs/completed/ARCHIVAL_COVER_DRAW.md`, `ARCHIVAL_TM1_CLUSTERING.md`, `ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`, `ARCHIVAL_SIM_ECONOMICS_VERDICT.md`) were not enumerated.
- Outside scope but seen: `sim/timing_cluster.rs:14-20` notes `SETTLEMENT_EPOCH_BLOCKS` is dual-sourced in production (`prod/constants.rs:245` and the JSON key), and `prod/release_cooldown.rs:6` and `prod/bond_duration.rs:9` still name `HoldingsUpdate`-drop.

---

## Appendix C — the briefs

The two briefs as issued, so the census can be repeated. Re-issuing one
repeats the method; it does not reproduce the report byte for byte (§8).

### C.1 Economics sim

````text
READ-ONLY census task. Do not edit, create, stage or commit any file. Repo: <repository root> (branch dev). Report back in your final message only.

## Goal
The project owner has set a standing rule: simulation crates must CALL the production core code (functions, constants, levers) rather than restate it, so the sim and production cannot drift; any divergence must be express and declared. I need a complete census of where the crate `rust/shekyl-economics-sim` (about 20k lines under src/) currently RESTATES, MIRRORS, HARD-CODES or ASSUMES something that has (or should have) a production owner, versus where it correctly imports production.

## Production owners to compare against
- `rust/shekyl-economics/src/` (emission.rs, emission_share.rs, burn.rs, escalation.rs, release.rs, reward.rs, supply.rs, volume.rs, block_weight.rs, params.rs, fee/relay.rs, fee/ladder.rs, fee/correction.rs) and the generated params from `config/economics_params.json` and `config/consensus_constants.json`.
- `rust/shekyl-archival-retention/src/` (reward_arithmetic.rs, constants.rs, bond_floor.rs, consensus_state.rs, failure_window.rs, etc.).
- `rust/shekyl-chain-rules/src/` (e.g. rules/block_weight.rs `effective_median_at`, closed_shards_before, shard close).
- `rust/shekyl-tx-weight`, `rust/shekyl-types` (SHARD_LENGTH, shard_of), `rust/shekyl-curve-tree`, `rust/shekyl-units`.
- C++ constants in `src/cryptonote_config.h` (legacy; note whether a constant there has any caller under src/).

## Already known — confirm, do not rediscover at length
1. `calibration.rs` `FEE_PER_BYTE_ATOMIC = 300` mirrors the C++ macro `FEE_PER_BYTE`, which has no caller; the production per-byte floor is `shekyl_economics::relay_fee_floor` (F = R*C*w_ref/M^2).
2. Every scenario in `scenarios.rs` pins `fee_per_tx: 100_000_000` (0.1 SKL) flat; consumed at engine.rs (~line 235), stage2.rs (~line 306), onset.rs. Production has a three-rung fee ladder (`corrected_fee_ladder`).
3. `fee_ladder.rs` declares `REF_TX_WEIGHT = 3_000` as a marked exception (no Rust owner).
4. The A1/onset arms carry no block-weight median state.
5. `fee_ladder.rs` and `fee_floor.rs` (the FL instrument) DO import production functions heavily — these are the good precedent.

## What to find (be exhaustive across every file in rust/shekyl-economics-sim/src/)
For each item give: file:line, the name/value, what it represents, the production owner if one exists (file:line), and a classification:
- (R) RESTATED: a production constant or formula re-declared or re-implemented locally (including f64 re-implementations of integer production math, and literals embedded in expressions or struct initialisers, not only `const` items).
- (A) ASSUMED EXOGENOUS: a model input with no production owner (e.g. demand, price, opportunity-cost rate, replica target) — say whether it is declared/documented as exogenous or silently pinned.
- (D) DEAD/STALE REFERENT: mirrors something production no longer uses, or a retired unit (J-segments, leaf counts, T=200 tx-count shards, 10,000-block-epoch-as-shard, etc.).
- (X) DECLARED EXCEPTION: restated but explicitly marked as an exception at its definition.
- (S) SWEEP/GRID: a band of experiment values — list briefly, these are legitimate.
Also list (P) the production imports that are done correctly, briefly, per file (one line each), so the census shows coverage.

Specifically check and report on: the replica target R (e.g. `R_FULL = 6`), the bond floor 0.75 SKL (is it imported from `ARCHIVAL_BOND_FLOOR_ATOMIC`?), `SHARD_BYTES` in burden.rs vs `shekyl_types::SHARD_LENGTH`, blocks-per-year, epoch length, COIN, emission/tail/decay values, burn parameters, staker share values, archival bytes per transaction (e.g. 12,627), transaction weights, storage/Kryder cost terms, opportunity-cost rates, the scenario traffic schedules, and anything the stage2.rs / onset.rs / burden.rs / budget.rs / engine.rs / stranding.rs / swing.rs / proxy.rs / cartel.rs / distribution.rs / redistribution.rs / admission.rs / population.rs / mn_feasibility.rs / challenge_coverage.rs arms compute by a local formula where a production function exists.

Also report: which report outputs and which tests PIN numeric results that depend on items (1) and (2) above (test names and file:line), since those pins will move when the fee is rewired.

## Method cautions
- Read the code; do not infer from names. A grep hit is a lead, not a finding — open the site.
- If a listing is truncated, say so; never conclude "none" from a truncated listing.
- Distinguish "verified by reading the definition and its use" from "inferred".

## Output format
A markdown table per classification (R, A, D, X), then the short (S) and (P) lists, then the pinned-tests list, then a short "not checked / uncertain" list. Keep prose minimal. Every row must carry a file:line.
````

### C.2 Staking sim

````text
READ-ONLY census task. Do not edit, create, stage or commit any file. Repo: <repository root> (branch dev). Report back in your final message only.

## Goal
The project owner has set a standing rule: simulation crates must CALL the production core code (functions, constants, levers) rather than restate it, so the sim and production cannot drift; any divergence must be express and declared. I need a complete census of where the crate `rust/shekyl-staking-sim` (about 21k lines under src/) currently RESTATES, MIRRORS, HARD-CODES or ASSUMES something that has (or should have) a production owner, versus where it correctly imports production. This is the archiver-population sim (entry/exit of archivers, coverage, the L11-L19 ledger in docs/design/STAKER_ARCHIVAL_SIM.md).

## Production owners to compare against
- `rust/shekyl-archival-retention/src/` — especially reward_arithmetic.rs (`g_age_milli`, `scarcity_micro`, `work_milli_from_micro`, `curve_milli`, `BandedCurveParams`, reward share floor), consensus_state.rs (r_market fold, shard_work_micro, shard_contribution_micro), constants.rs, bond_floor.rs, bond_duration.rs, release_cooldown.rs, failure_window.rs, challenge.rs, challenge_assignment.rs, admission.rs.
- `rust/shekyl-economics/src/` (emission, emission_share, burn, escalation, release, fee/*, params) and `config/economics_params.json`, `config/consensus_constants.json`.
- `rust/shekyl-chain-rules`, `rust/shekyl-types` (SHARD_LENGTH, shard_of, shard close), `rust/shekyl-units`, `rust/shekyl-standoff`.

## Already known — confirm, do not rediscover at length
1. `reward.rs` carries a float `g_age` / `raw_work` (f64) beside production `g_age_milli` / `scarcity_micro`; it does import `curve_milli`, `BandedCurveParams`, `WORK_MILLI_SCALE`.
2. The purse is abstract: budgets like 50/100/200 "model units" per epoch, with a decaying base and `budget_floor`, `budget_ceiling` in the fee-era mode — not derived from production emission/fees. Only `budget_throttle.rs` reads `EconomicParams`.
3. `model.rs` (~line 214-226) carries `REGISTERED_SHARD_TX_COUNT = 200.0`, the retired transaction-count partition, kept so registered runs reproduce.
4. `storage_unit_cost` is a calibrated abstract cost (see STAKER_ARCHIVAL_SIM.md L19h); `age_weight` baseline 2.0 is a float lever.

## What to find (be exhaustive across every file in rust/shekyl-staking-sim/src/)
For each item give: file:line, the name/value, what it represents, the production owner if one exists (file:line), and a classification:
- (R) RESTATED: a production constant or formula re-declared or re-implemented locally (including f64 re-implementations of integer production math, and literals embedded in expressions, struct initialisers or Default impls, not only `const` items).
- (A) ASSUMED EXOGENOUS: a model input with no production owner (reservation yield, price coupling, churn, entry rate, bandwidth/egress cost, storage cost, opportunity cost) — say whether it is declared/documented as exogenous or silently pinned.
- (D) DEAD/STALE REFERENT: mirrors something production no longer uses or a retired unit (J-segments, T=200 tx-count shards, epoch-as-shard, K_COVER, order-coin planner, etc.).
- (X) DECLARED EXCEPTION: restated but explicitly marked as an exception at its definition.
- (S) SWEEP/GRID: experiment bands — list briefly.
Also list (P) the production imports done correctly, one line per file.

Specifically check and report on: how the per-epoch reward is computed and split (compare to production `scarcity_micro`, `shard_contribution_micro`, `reward_share_floor`, r_market semantics — does the sim's r count bonded or served pairs, and with what lag?); the bond amount per shard and its carry cost in the agent model (`agent.rs` ~180-196) versus `ARCHIVAL_BOND_FLOOR_ATOMIC`; the replica target R; epoch length; shard size/length; age units; the challenge/witness parameters (reads per pair per epoch, m/n failure window, p_attempt); the foundation floor model; holdings caps (MAX_HOLDINGS_SHARDS); cooldowns and bond durations; and what the default config/World parameters are and where they are set.

Also report: which tests and which registered/pinned runs (named in docs/design/STAKER_ARCHIVAL_SIM.md, e.g. L11, L13, L19) would change if (a) the purse were replaced by production emission+fee inflow and (b) the float work arithmetic were replaced by production integer arithmetic. Give test names and file:line where a numeric result is pinned.

## Method cautions
- Read the code; do not infer from names. A grep hit is a lead, not a finding — open the site.
- If a listing is truncated, say so; never conclude "none" from a truncated listing.
- Distinguish "verified by reading the definition and its use" from "inferred".

## Output format
A markdown table per classification (R, A, D, X), then the short (S) and (P) lists, then the pinned-tests/registered-runs list, then a short "not checked / uncertain" list. Keep prose minimal. Every row must carry a file:line.
````
