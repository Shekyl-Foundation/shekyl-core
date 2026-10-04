# ESR — the economics sims on production code: census and re-base

**Status:** **OPEN — Round 0 (the census) executed 2026-10-02 at
`bb021f254`; implementation opened the same day.** Identifier family
**`ESR-`** (work items), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file
(rule 94 §1). This document owns the re-base of `shekyl-economics-sim`.
The re-base of `shekyl-staking-sim` is a separate PR against the same
census (§6), and the design round the measurements feed is not opened
here (§7).

**One sentence.** The archival economics was measured on a fee the chain
does not charge — a flat `0.1 SKL` per transaction for sixty years, and a
stuffer priced at a `300` atomic/byte constant with no caller — so every
fee-share verdict in
[`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md)
§12.13–§12.14 is a statement about that fee, not about the system.

---

## Reading-pass finding 1: the production default carries 22 of 50 (2026-10-03, ESR-6)

**What the run says.** On the baseline schedule, 50 ordinary transactions a
block, at the production Standard rung and under the production
block-template fill rule:

- Blocks carry **22 transactions** for the first eleven years.
- The median stays within one transaction of the 300 KB zone (314–322 KB).
- About **28 a block go unserved**, roughly 7.4 M a year.
- The median starts to climb in year 11. By year 12 blocks carry all 50, and
  it settles at 732–764 KB.

On the flat control fee the same thing lasts until **year 38**.

**The mechanism is production code.** The producer lists a transaction only
when it does not lower the gross coinbase (`fill_block_template`, now
`shekyl_block_template::Fill`). Past the median, one more transaction of
weight `w` therefore needs a fee that covers its penalty:
`w ≤ 4ρ·w_ref·(m/M)²` at the Standard rung, with `ρ = (1 − σ)/(1 − b)`. The
fee grows with `w` and the penalty with `w²`. The ladder's reference weight
`w_ref = 3 000` is a quarter to a fifth of a post-quantum ordinary
transaction (12.6–15.3 KB), so the condition fails until `ρ` reaches about 1.2. That
happens in year 11 on this trajectory (§5.6–§5.7).

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

- **Corpus growth.** The baseline's closed shards at year 10 are 229 864,
  against 523 841 before.
- **The purse.** Emission is paced at the release multiplier's 0.8 floor
  for eleven years, so the reward is 1.313× higher at every later year.
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

Measured on the ESR-6 baseline, production arm, years 1 → 10:

| | Year 1 | Year 10 | Factor |
| --- | ---: | ---: | ---: |
| `σ` | 0.143 | 0.055 | `1 − σ`: × 1.10 |
| `b` | 0.016 | 0.203 | `1/(1 − b)`: × 1.24 |
| `ρ` | 0.871 | 1.185 | × 1.36 |

`ρ` crosses the threshold `w/(4·w_ref)` = 1.22 in year 11. About
**two-thirds of the rise is the burn fraction** climbing as the supply is
emitted, and one-third is `σ` decaying. Any change to the decay schedule,
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
tail. The archival sim's A1, A4 and onset arms never joined that finding.
They read `fee_per_tx` from the scenario table, and the scenario table
says `100_000_000` atomic in every row.

Two rulings govern the repair.

- **The sim calls production (Rick, 2026-10-02, design-owner lane).** In
  substance: wherever possible a sim runs against the production code —
  its functions, constants and levers — so the sim and what ships cannot
  drift; a divergence is allowed for experimental work or for planning a
  different strategy, and then it is express. §4 is the register of the
  divergences this crate keeps.
- **Order of work (Rick, same day).** First the sim is put in order; then
  the current system is measured under its own rules; only then are levers
  designed or moved. So nothing in this round proposes a mechanism. A
  candidate fee policy, bond policy or controller is out of scope by
  ruling, not by omission.

## 1. What the census found

Two read-only passes read every file of both sim crates against the
production owners (§8 gives the method and its limits; Appendices A and B
are the reports). The rows that move a published number, or that block the
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
| **ESR-3** | Emission-split epoch read from `shekyl_chain_rules::EMISSION_SPLIT_EPOCH`. | A fold sampled at an exact year-boundary height moves by one decay step; a mid-year sample does not. |
| **ESR-4** | Transaction volume through `TxVolume::window` over `TX_VOLUME_WINDOW`, as the validator reads it. | A step schedule's burn and release ramp over 720 blocks instead of jumping. |
| **ESR-5** | Net circulating supply (`CirculatingSupply::derive`) in the gate-7 path and the recorder; the fixture is regenerated. | Each regenerated column is justified from the production formula, not from the run that produced it. |
| **ESR-6** | The weight penalty (`paid_block_reward`) and a block-weight median enter the fold. The pure median fold is **exposed from `shekyl-chain-rules`**, not restated — see §3. What a block carries is the producer's fill rule, lifted from `fill_block_template` to `shekyl_block_template::Fill` and called. | With traffic above the penalty-free zone the median rises and the floor falls as `1/M²` — **amended by §5.6 before the run**: on an all-Standard chain, only once one more transaction's fee covers its penalty. |
| **ESR-7** | A miner stuffer: transactions the miner includes in its own blocks. Two arms: the fee floor **unenforced** (the current system — zero fee, bounded only by the penalty) and **enforced** (a declared divergence, §4). | `--stage2` prints a stuffer row at zero fee beside the fee-path one. |
| **ESR-8** | Restated constants become imports, or are declared in §4. The dead stake schedule is deleted in its own commit (rule 15). | Appendix A's restated-constant rows are each closed by an import, a deletion, or a §4 entry. |
| **ESR-9** | The documents that quote the old tables: §12.13–§12.14 rows become records-was with the new rows beside them. | No current-tense sentence quotes a flat-fee figure. |

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
would quote changes.

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

## 3. The median is a production change inside a sim PR

`shekyl_chain_rules::rules::block_weight::effective_median_at` needs a
`ChainView`, a store trait the sim has no chain to satisfy. The fold
beneath it (`medians_over`, `cxx_median`) is pure and crate-private. ESR-6
makes that fold public rather than writing a second one.

The test that matters is **not** "the store-backed entry point and the
pure fold agree": the first is implemented on the second, so that test is
green by construction. What can drift is the **window** — which blocks'
weights the sim feeds the fold, against which the validator records. ESR-6
pins the sim's window construction against the validator's on a shared
trace.

What ESR-6 built, and why it is not the plan above. A sixty-year fold
cannot select a 100 000-row median per block, so
`median_window::RollingMedian` keeps the long window as two ordered halves
and hands the middle value or pair to the validator's own `cxx_median`;
`medians_from` composes the result exactly as `medians_over` does. Two
tests hold it to production: the rolling median equals `cxx_median` over
the explicit window at every step, across capacities that fill, evict and
churn; and the whole of CEN-G6/G6b equals `medians_over` over the same
recorded weights through a stream past the 100 000-block window's first
eviction. The C++ relay-floor ring keeps the same median the same way
(`epee::misc_utils::rolling_median_t`, `relay_floor_ring.cpp`).

The block's weight is what its transactions weigh, and how many it takes
is not the schedule's: it is what the producer's fill rule admits
(`shekyl_block_template::Fill`, §5.6). One type, `median_window::BlockSpace`,
holds the medians and the waiting transactions for the engine, the budget
and the stage-2 fold alike; `burden_trajectory` reads the stage-2 fold's
aggregates instead of folding the schedule a second time, so the burden
side and the funding side count the same transactions.

## 4. Declared divergences

Under the first ruling, every place this crate does not call production is
listed here with its reason. A divergence missing from this table is a
defect.

| Divergence | Why it exists | Reported as |
| --- | --- | --- |
| Control arm: flat `0.1 SKL` per transaction | Reproduces §12.14, so the old and new tables differ by the fee and nothing else | Named arm, printed beside the production arm |
| Fee multiplier on the Standard rung | What users pay above the default is not knowable before launch | `×1`, the production default, is what runs. The sweep is ESR-10 and is not printed yet |
| Rung mix (economy / standard / priority shares) | Same. At the defaulted 15/80/5 mix ([`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md) §5.5) the 5 % on Priority pay roughly three quarters of all fees at the zone median | Not modelled yet: every ordinary transaction pays Standard. ESR-10 |
| Control arm: admission at a flat 300 atomic/byte | The rate §12.13's stuffer and claim were priced at. Nothing in the chain charges it; the chain's admission rate is the relay floor | Part of the control arm; printed in its stuffer table |
| The admission rate at a shard count (`AdmissionAtShards`) | Arms that sample the chain by shard count alone have no height, and the rate depends on emission, not on traffic. The pairing is fixed as the baseline scenario's: the rate at the year the baseline reaches that count, and its last year's rate beyond | Stated in the stuffer table's footer |
| Admission rate sampled at the year's last block | A stuffer picks its moment, and on the production arm the floor falls through the year | Attacker-favouring; stated at the field |
| The recorder's volume operand stays per-block | `record.rs` writes test vectors for the engine-core differential, which recomputes from a recorded per-block volume. That is the vectors' contract, not a model of the chain; the three model folds read the validator's window (ESR-4) | Stated at the recorder |
| A scenario that starts mid-chain starts with an empty volume window and empty median windows | A fold's heights are its own; `genesis_height_offset` scenarios carry no history before their first block, so their medians start at the zone as a genesis chain's do | Stated in `volume_window.rs` and `median_window.rs` |
| A block's weight is its bodies' | The coinbase's few hundred bytes are neither priced nor recorded in the median. The fill rule itself prices bodies only, as the C++ does; the template then prices the whole block | Stated at `BlockSpace` |
| Waiting transactions pay the fee of the block they are offered to | They were built at an earlier block's fee. Every transaction is the same shape, so a refusal of one is a refusal of all, and the pool's order (fee, then age) is age | Stated at `BlockSpace` |
| The pool's livetime is a restated C++ define | `CRYPTONOTE_MEMPOOL_TX_LIVETIME` has no Rust owner until the pool moves (`DRS_E1_SPOOL.md`); the sim's copy is pinned to the header by a test | Stated at its definition |
| Budget disposition (b) is unpenalised | (b) is the unmodulated subsidy, a counterfactual of the release multiplier. The penalty in (a) is bounded by the fees of the transactions that crossed the median, since the fill rule admits no other | Stated in `budget.rs` |
| Every ordinary transaction pays Standard | No wallet escalates its rung under congestion; the user chooses. Blocks past the median are what Priority pays for | ESR-10's rung mix |
| A claim is one ordinary transaction at the admission rate | The claim's own envelope and the wallet's claim hold floor (`EMISSION_CLAIM_FEE_FLOOR`) are not modelled. Carried from the pre-ESR report unchanged | Appendix A, class A, row A9 |
| Fee paid unrounded | The product is the fixed point of `shekyl_tx_weight::converge_weight_fee` — the wallet's iteration without the mask. The wallet then rounds each fee up to the daemon's quantization mask (1 000 atomic). The mask has no Rust owner — it is a C++ static — and the fee-floor instrument in this crate already pays unrounded (FL-R22). At most 1 000 atomic per transaction, below print precision | Stated here; closes when the mask gains a Rust owner |
| `REF_TX_WEIGHT = 3_000` | The ladder's reference weight is a C++ macro with no single Rust owner. The crate's one existing declared copy (`fee_ladder.rs`) is reused, not duplicated | Declared at its definition |
| Fee floor enforced in consensus | Not the current system: the floor is relay policy (C2-R2 Q9, reopened 2026-10-02) | Second arm of ESR-7 |
| Traffic schedules, opportunity-cost band, SKL price band, storage and Kryder terms, replica target `R = 6` | No production owner exists | Exogenous; each already declared at its definition (Appendix A, class A) |
| Demand does not respond to the fee or to congestion | A schedule is a number of transactions per block, the same whatever they cost or however long they wait: no elasticity, no rung escalation, no resubmission after expiry. What the chain fails to carry expires; it is not deterred | Stated at the head of this document beside the result it governs |

## 5. Predictions, written before any run (2026-10-02)

Hand arithmetic from the floor formula, for a transaction of about
17.5 KB. Rough by construction; registered so that the tables are a test
and not a narrative.

**Amended 2026-10-02, still before any run: the shape.** 17.5 KB is the
2-in/2-out spend of
[`ARCHIVAL_SHARD_T_DERIVATION.md`](ARCHIVAL_SHARD_T_DERIVATION.md). The
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

## 6. The staking sim — a separate PR

Appendix B is the work list. It is a re-base, not a wiring change: the
reward path, the bond lifecycle and the unit system all move onto
production code, and the purse stops being an abstract 100 units per
epoch. Its falsifier is that an abstract-purse control arm reproduces the
existing L11 and L13 pins in
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md).

Two consequences are recorded here so they are not discovered later.

- Every L11–L19 figure becomes a records-was row when that PR lands. No
  test pins a population result today; they are pinned in documents only.
- The consensus constants calibrated from those runs — the bond floor, the
  age weight, the bond duration, the failure window, the release cooldown
  — keep their values and lose their derivation until the runs are
  repeated.

It is a separate PR because it is a separate validation surface (rule 19),
and it is carried by the `FOLLOWUPS.md` row *Re-base `shekyl-staking-sim`
on production code*.

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
  "Appendix A row R9"; the identifiers of this round are `ESR-`.
- **Line numbers are at the pin** (`bb021f254`) and will move.
- **The appendices are the reports as returned**, less two lines about
  the reporting environment and one local path; report headings are
  demoted one level to sit under the appendix headings. Nothing else is
  edited, so a claim in an appendix is the pass's, not this document's.
- The census did not sweep the design documents that quote sim output;
  ESR-9 owes that sweep.

---

## Appendix A — census of `shekyl-economics-sim` (as reported, at `bb021f254`)

Read-only pass, 2026-10-02. Row labels are local to these tables (§8).
Sim paths are relative to `rust/shekyl-economics-sim/src/`; production
paths to `rust/`. Status column: **V** = definition and use both read;
**I** = inferred.

Scope: `dev` @ `bb021f254`, 23 files under `rust/shekyl-economics-sim/src/`, **15,255 lines** (not ~20k), every file read in full. Nothing was edited, built or run. Sim paths below are relative to that `src/`; production paths are relative to `rust/`.

Status column: **V** = definition and use both read; **I** = inferred.


### Known items (confirmed)

1. `calibration.rs:53` `FEE_PER_BYTE_ATOMIC = 300`, consumed at `:126`, `:135`. The macro is at `src/cryptonote_config.h:78` (the sim comment cites `:66`). A word-match grep over `src/` and `tests/` finds only the `#define`, so it has no caller. V.
2. `fee_per_tx: 100_000_000` appears at `scenarios.rs:31,55,76,102,121,154,193,220,268,342,389`, `budget_scenarios.rs:23,40,69,92,116,143`, and the test config at `engine.rs:386`. Consumers: `engine.rs:235`, `stage2.rs:306`, `budget.rs:245`, `record.rs:229`, `onset.rs:581` (closed form), `onset.rs:881,917` (tests). V.
3. `fee_ladder.rs:62` `REF_TX_WEIGHT = 3_000` is still a valid exception. The macro is at `cryptonote_config.h:81` (comment cites `:70`); C++ callers are `relay_floor_ring.cpp:151` and `blockchain.cpp:4303`. Rust has only a private copy at `shekyl-engine-core/src/engine/fee_policy.rs:62`. V.
4. No block-weight median state in `stage2.rs:251-343`, `engine.rs:155-338`, `budget.rs:139-326` (declared at `budget.rs:44-48`) or `onset.rs`. A6 assumes the saturated ceiling (`swing.rs:117,150-152`). The FL instruments take the median as a swept constant (`fee_ladder.rs:2292`, `fee_floor.rs:289,473`). Owners: `shekyl-chain-rules/src/rules/block_weight.rs:237`, `shekyl-economics/src/block_weight.rs:41,52`. V.
5. `fee_ladder.rs` and `fee_floor.rs` import heavily, but still carry three undeclared local copies (R24–R26) and one retired rule (D6).

### (R) Restated

| # | Site | What | Production owner | St. |
|---|---|---|---|---|
| R1 | `engine.rs:134-148` | 11 `SimParams::default` literals: asymptote, speed factor 22, final subsidy 300_000_000, `blocks_per_year` 262_800, baseline 50, release 800_000/1_300_000, burn 500_000/900_000, staker emission share 150_000, decay 900_000. Only `staker_pool_share` (`:146`) is imported. Guarded by a JSON-parity test (`engine.rs:423`). | `EconomicParams::default()` `shekyl-economics/src/params.rs:245-271`; `STAKER_EMISSION_SHARE` `:108`, `STAKER_EMISSION_DECAY` `:113`, `BLOCKS_PER_YEAR` `:118` | V |
| R2 | `engine.rs:156-170`, `stage2.rs:252-266`, `stage2.rs:1598-1612`, `budget.rs:140-154`, `record.rs:150-164` | Five copies of the `SimParams` → `EconomicParams` struct literal | `EconomicParams::default()` | V |
| R3 | `burden.rs:38` (u64); `engine.rs:153`, `stage2.rs:52`, `onset.rs:87`, `budget.rs:62` (f64); `swing.rs:101,217` (`/ 1.0e9`); `fee_ladder.rs:3031,3123` (tests) | `COIN = 1_000_000_000` | `shekyl_units::ATOMIC_UNITS_PER_SKL` (`shekyl-units/build.rs:70`, from JSON `coin`). The sim has no `shekyl-units` dep. | V |
| R4 | `proxy.rs:48` | `BLOCKS_PER_YEAR = 262_800`, feeding `epochs_per_year()` (`:52`) used at `stage2.rs:1311,1459,1586`, `redistribution.rs:100`, `cartel.rs:449,654`. Bypasses `SimParams.blocks_per_year`. | `params.rs:118` | V |
| R5 | `swing.rs:50` | `EPOCH_BLOCKS = 10_000` | `SETTLEMENT_EPOCH_BLOCKS` `shekyl-archival-retention/src/constants.rs:245` (imported by five other sim files) | V |
| R6 | `swing.rs:54` | `REORG_DEPTH_BLOCKS = 720` | `ARCHIVAL_REORG_DEPTH_BLOCKS` (`shekyl-archival-retention/build.rs:210`, re-exported `lib.rs:102`); `D_MAX` `shekyl-chain-rules/src/reorg.rs:70` | V |
| R7 | `swing.rs:41,47` | Penalty-free ceiling = zone × S; max = × 2 | `effective_median` `block_weight.rs:41`; `block_weight_limit` `emission.rs:265` | V |
| R8 | `swing.rs:86-102` | Penalty compensation hard-codes "reward at B = 2M is zero" while the doc says "measured from the production penalty formula". Nothing is called. | `block_reward_with_penalty` `emission.rs:243`, `paid_block_reward` `:175` | V (no call) |
| R9 | `engine.rs:226`, `stage2.rs:290`, `budget.rs:223,355`, `onset.rs:219`, `record.rs:204` | Literal epoch `0` passed to `calc_effective_emission_share`. `fee_ladder.rs:76-86` documents this exact defect and uses 1. | `compute_emission_split` `emission_share.rs:33`; `EMISSION_SPLIT_EPOCH = 1` `shekyl-chain-rules/src/rules/miner.rs:128` | V |
| R10 | `engine.rs:214-269`, `stage2.rs:279-323`, `budget.rs:204-262`, `record.rs:176-256` | Per-block reward chain assembled from primitives. Differences from production: no height-0 whole-to-miner arm; no weight penalty; circulating via `saturating_sub` on u64-truncated casts (`engine.rs:196`, `stage2.rs:297`, `budget.rs:235`). | `price_emission` `reward.rs:163`; `compute_fee_burn` `burn.rs:170`; `CirculatingSupply::derive` `supply.rs:81` | V |
| R11 | `engine.rs:215,221,242,249`; `stage2.rs:286,299`; `budget.rs:211,218,237`; `onset.rs:447`; `record.rs:192,199,224` | `TxVolume::per_block(instantaneous)`; step schedules respond in one block. Undeclared. | `TxVolume::window(sum, 720)` `volume.rs:58`, `TX_VOLUME_WINDOW` `params.rs:65` | V |
| R12 | `onset.rs:754-757` | Tail per year uses `final_subsidy_per_minute * 2` (literal 2 minutes) | `tail_subsidy_per_block` `emission.rs:49` | V |
| R13 | `onset.rs:620`; tests `:886,919` | Literal `0.25` staker share | `staker_pool_share` (sim already has `escalation.rs:50 floor_share()`) | V |
| R14 | `stage2.rs:476,669,1069`; `swing.rs:136` | `/ 10_000.0` for SCALE → percent (`onset.rs:137` derives it) | `SCALE` | V |
| R15 | `stage2.rs:499,1095`, `onset.rs:744`, `scenarios.rs:436,443,450`; `stage2.rs:1276`; `stage2.rs:1360` | Report strings hard-code "0.75", "MAX_CLAIM_AGE_W=26", "4096 shards" | `ARCHIVAL_BOND_FLOOR_ATOMIC`, `MAX_CLAIM_AGE_W`, `MAX_HOLDINGS_SHARDS` | V |
| R16 | `admission.rs:155,170` | Literal `4_096` | `MAX_HOLDINGS_SHARDS` `shekyl-types/src/archival/mod.rs:78` (already imported at `admission.rs:34`) | V |
| R17 | `population.rs:42-44` | `BandedCurveParams::from_plateau_value(8_000)` | `ARCHIVAL_PROVISIONAL_CURVE` `reward_arithmetic.rs:120` | V |
| R18 | `population.rs:56` | `AGE_WEIGHT_MILLI = 1_000`; production is 2000. Declared inert at `AGE_MILLI = 0` (`:53-55`). | `ARCHIVAL_REWARD_AGE_WEIGHT_MILLI` (`shekyl-archival-retention/build.rs:207`) | V |
| R19 | `mn_feasibility.rs:53` | `N_HARD_BOUND = 25` | Derived privately as `MAX_CLAIM_AGE_W − LAG + 1` (`failure_window.rs:176-183`); no pub owner | V |
| R20 | `mn_feasibility.rs:370`; `challenge_coverage.rs:227-230,290,302` | λ = 3 as literal | `CHALLENGES_PER_PAIR_PER_EPOCH` `constants.rs:30` (`proxy.rs:41` imports it) | V |
| R21 | `challenge_coverage.rs:72-124,147-204` | Exact-min urn and the even-spread schedule (`:163`) re-implemented with a local SplitMix64 | `ChallengeUrn::new` `challenge_assignment.rs:172`, `assign_epoch` `:303`. The band variant has no owner. | V (equivalence I) |
| R22 | `mn_feasibility.rs:204-267`; `cartel.rs:135-137` | f64 closed forms of the m-of-n rule: naive binomial P(≥ m of n) used as a union bound, `(m−1)/n`, `(n−m+1)/n`. Cross-checked against the predicate-backed kernel by test `mn_feasibility.rs:978`. | `failure_window_slashable` `failure_window.rs:362` | V |
| R23 | `cartel.rs:249` | `1.0 + SLASH_GRACE_EPOCHS` | `SLASH_SETTLEMENT_TIP_LAG_EPOCHS` `failure_window.rs:176` (private) | V |
| R24 | `fee_ladder.rs:163-193` | `C = (1−σ)·M_r/(1−b)` composed locally (`:186`). Not among the file's declared exceptions (`:29-35`). | `fee_correction` `fee/correction.rs:49` (also clamps σ and b) | V |
| R25 | `fee_ladder.rs:230-243` (used `:257-263,1912,1923`) | Local `round_money_up_2`. The owner's doc (`ladder.rs:14-18`) says the FL instrument imports it; the import list (`:45-52`) does not. | `round_money_up_2` `fee/ladder.rs:20` | V |
| R26 | `fee_ladder.rs:349-355,396-450` | `quantize_c_pow2` Ceiling arm and `pow2_le`. No cross-pin against the owner. | `quantize_pow2_ceil` `fee/correction.rs:83` | V |
| R27 | `fee_ladder.rs:2155-2156` | Reachability `×8/10`, `×13/10` restates the release rails | `params.release_min/max` | V |
| R28 | `fee_ladder.rs:1996`; `:110` | `per_block(100)` for "double baseline"; `RACE_LAGS` 100 equals `fcmp_reference_block_max_age` | `tx_volume_baseline`; `consensus_constants.json` | V |
| R29 | `fee_floor.rs:380` | Standard rung `4 * f` | `corrected_fee_ladder` `fee/ladder.rs:72` | V |
| R30 | `fee_ladder.rs:3035,3039,3068`; `engine.rs:349-371,410`; `cartel.rs:974` | Test literals: zone 300_000; bond 750_000_000 / 0.75 / 445.5 | `FULL_REWARD_ZONE`, `ARCHIVAL_BOND_FLOOR_ATOMIC` | V |
| R31 | `onset.rs:216` | Mid-year height omits `genesis_height_offset` (`stage2.rs:280` includes it). Harmless today: only offset-0 scenarios reach it (`onset.rs:669-672`). | — | V |

### (A) Assumed exogenous

| # | Site | What | Declared? | St. |
|---|---|---|---|---|
| A1 | `burden.rs:125` `REPLICAS_PER_SHARD = 6` (used `burden.rs:142`, `stage2.rs:411,470,918`, `onset.rs:439,477,708`); `scenarios.rs:311-312` `R_FULL = 6`, `R_THIN = 4`; `population.rs:65`, `redistribution.rs:45`, `distribution.rs:189,279` | Replica target R. No production owner found by grep of `rust/` outside the sim crates. Two separate consts hold the same 6. | Declared (`burden.rs:121-124`; `stage2.rs:441-443` calls it "a leaf-era replication constant carried as an input") | V; absence I |
| A2 | `scenarios.rs:299,304-306` | Gate-7 horizon 30 y; N_P 79 / 154 / 40 | Declared (staking-sim L11/L13) | V |
| A3 | `burden.rs:132`; binding member at `stage2.rs:532`, `onset.rs:99`. Duplicates: `stage2.rs:790` `A4_OPP_RATE`, `stage2.rs:1793-1795`, `onset.rs:886` | Opportunity-cost band 2 / 5 / 10 % | Declared, including in report text (`stage2.rs:573-575`) | V |
| A4 | `burden.rs:119`; mid pick at `stage2.rs:463,1625-1626`, `onset.rs:315,344,512`; duplicate literal `redistribution.rs:178` | SKL/fiat band 0.01 / 0.10 / 1.00 | Declared | V |
| A5 | `burden.rs:111,177-183`; `proxy.rs:96` (duplicate of `burden.rs:111`), `:102`, `:110` | Storage 1e-11 $/B/yr, Kryder 0 / 10 / 25 %, fetch and cloud bands | Declared | V |
| A6 | `scenarios.rs:27-29,44-52,68-73,89-97,115-117,134-136,169-179,205-215,233,252-263,322-332,373-381`; `budget_scenarios.rs:22,39,59-68,84-91,108-115,132-142` | All traffic schedules: multipliers on the production baseline, or absolute counts (scenario 8, `fee_era`, scenario 9). `scenarios.rs:91` uses 21_600 blocks for 30 days. | Declared as scenarios | V |
| A7 | `scenarios.rs:221-225`; `budget_scenarios.rs:144-150` | "95 % emitted at ~year 30" asserted as a start state. `projected_already_generated` (`emission.rs:193`) could derive it. | Comment only | V |
| A8 | `burden.rs:67,72-74` | Honest tx shape 1-in/2-out | Declared | V |
| A9 | `stage2.rs:1269-1272`; `stranding.rs:162-171,215` | Claim cost is one normal tx at 300 atomic/byte. The wallet's claim hold floor is not modelled. | Silent. Owner candidate: `EMISSION_CLAIM_FEE_FLOOR` = 3.6 SKL, `fee/ladder.rs:38` | I |
| A10 | `stranding.rs:48-52`; `population.rs:51,63-68`; `redistribution.rs:43-48`; `stage2.rs:784,1256,1590`; `distribution.rs:51` | Archiver population classes, replica tail, scarcity bands, holdings sizes, age 0 | Declared, except the bare `20_000` at `stage2.rs:1590` | V |
| A11 | `proxy.rs:474`; `mn_feasibility.rs:57`; literal 131 in tests `proxy.rs:825-1018`, `mn_feasibility.rs:1065-1067` | 131-epoch reward horizon, reused as "bond life". Production `bond_duration` (`bond_duration.rs:142`) is not consulted. | Silently pinned | I (owner mapping) |
| A12 | `mn_feasibility.rs:370-375,386-388`; `challenge_coverage.rs:223-225` | False-slash target 1e-3, free-ride 0.80, 40,000 pairs, `p_attempt` 0.30, pair counts 4,096 / 324,000. `k_cap` is 6 in one arm and 30 in the other. | Declared provisional; the `k_cap` disagreement is silent | V |
| A13 | `calibration.rs:57-61` | Rucknium March-2024 anchors | Declared | V |
| A14 | `stage2.rs:57,817,1613`; `record.rs:263`; `admission.rs:46`; `fee_ladder.rs:123` | Ramp years 2, response lag 2, reward at asymptote/2, milestone height 5_788_000, safety multiple 2, gap placeholder 5 | Mostly declared | V |
| A15 | `fee_ladder.rs:1708,2574-2581`; `fee_floor.rs:408` | Demand elasticity model, tier-usage shares | Declared (registered grid) | V |

### (D) Dead or stale referent

| # | Site | What | Production today | St. |
|---|---|---|---|---|
| D1 | `engine.rs:93-99`; `scenarios.rs:397,406-468` (`seb`; `seb/10` at `:429`) | Gate-7 locked supply counts one shard per 10,000-block epoch. Acknowledged as a "model parameter" at `engine.rs:69-77`. Using the sim's own figure (`escalation.rs:69`: n = 523,841 at 10 y), that is about one shard per 5 blocks, roughly 2000× denser. | `shard_of` `shekyl-types/src/archival/mod.rs:134`, wrapped by the sim's `burden.rs:203` | V; magnitude I |
| D2 | `engine.rs:197-206,241-246`; `record.rs:140-144,182-188` | Gross circulating (`already_generated` alone), commented "matching `validate_miner_transaction`". The recorder tracks no burn at all. | Net: `CirculatingSupply::derive` `supply.rs:81`; callers `shekyl-block-template/src/lib.rs:510`, `shekyl-ffi/src/economics_ffi.rs:233` | V |
| D3 | `population.rs:42-44,97-125,166-178` (A4, via `stage2.rs:875,1020`); `stranding.rs:173,185-189` (A3, via `stage2.rs:1318-1333`) | A3 and A4 base paths score through the plateau `curve_milli`. `distribution.rs` and OQ-4 (`stage2.rs:1376`) are explicit counterfactuals; `redistribution.rs:21-26` is already linear. | Credited work is linear: `consensus_state.rs:204`; the curve is "sim/counterfactual only" (`reward_arithmetic.rs:108-120`) | V |
| D4 | `engine.rs:43-45,201-212,278-291`; `scenarios.rs:4-19` and per-scenario stake closures; `record.rs:189,212-216,238-249` | Stake schedule and stake ratio. They now feed only reported yield and ratio, plus fixture columns nobody reads. | Burn no longer consumes stake ratio (`params.rs:313-318`); `economics_differential.rs:73-80` marks the weighted-stake columns unconsumed | V |
| D5 | `proxy.rs:91`; A5 table `proxy.rs:480-561` | Leaf-plus-segment opening payload with widths 4·38, 18, 38 as literals. Called "the retained pre-pruning artifact" at `proxy.rs:132`. | Width owners: `shekyl-fcmp/src/tree.rs:46,50,53,650` | V |
| D6 | `fee_ladder.rs:1514,1738-1748`; `:2356,2532` | Rejection race applies the 2 % buffer (`×100 < ×98`) and a 1020 thin-margin threshold. The same file removed the cushion at `:592-600`. | `RELAY_ADMISSION_SLACK_BP = 0` `fee/relay.rs:25`; lookback-min `relay_floor_admits` `:79` is not called | V |
| D7 | `fee_ladder.rs:211-223`; mode `:749,1454`; pin `:3030` | Pre-FL-R20 four-rung ladder; declared a historical baseline (`:281-285`). | The C++ function is now at `blockchain.cpp:4297` with a different signature | V |
| D8 | `fee_ladder.rs:76-86` | "No Rust owner exists" for the genesis-epoch height | `EMISSION_SPLIT_EPOCH` `miner.rs:128` (pub) | V |
| D9 | `calibration.rs:50`; `fee_ladder.rs:58,201,206,572`; `fee_floor.rs:29` | Stale line cites into `cryptonote_config.h` (`:66`→`:78`, `:70`→`:81`) and `blockchain.cpp` | — | V for the header; I for `blockchain.cpp` |
| D10 | `main.rs:147`; `Cargo.toml` description; `engine.rs:36,335` | "All 8 scenarios" (there are 9, `scenarios.rs:275-287`); `stuffing_profitable` is always `None` | — | V |
| D11 | `scenarios.rs:132,143-144` | "One epoch (~35 days)" = 25,000 blocks | Settlement epoch is 10,000 blocks | V; provenance I |
| D12 | `cartel.rs:830,881-890` | Test literals 2.4 and 2.4156 SKL/shard/epoch from a "representative run (2026-07-30)", before the byte-keyed re-derivation | — | I |
| D13 | `challenge_coverage.rs:26-27,224`; `mn_feasibility.rs:64,375` | Pair-count projections (324,000; 40,000). The design doc (`docs/design/ARCHIVAL_CHALLENGE_MECHANISM.md:1738`) calls 324k "a snapshot, not a ceiling"; the sim's own n × R at 10 y is about 3.1 M. | — | I |

### (X) Declared exceptions

| # | Site | What | Marking and standing | St. |
|---|---|---|---|---|
| X1 | `fee_ladder.rs:62` | `REF_TX_WEIGHT = 3_000` | Declared; still no Rust owner | V |
| X2 | `fee_ladder.rs:86` | `GENESIS_NG_HEIGHT = 1` | Declared; its premise is now false (D8) | V |
| X3 | `fee_ladder.rs:211` | ArticMine transliteration | Declared as the round's subject | V |
| X4 | `fee_ladder.rs:383` | `D8_MARGIN_MILLI = 30` | Declared; the owner's margin is private (`correction.rs:123`); behaviour-pinned by test `:2978` | V |
| X5 | `fee_ladder.rs:116` | `BLOCKS_PER_DAY = 720` | Rationale at `:112-115`; numerically equal to `TX_VOLUME_WINDOW` | V |
| X6 | `fee_floor.rs:154-157` | `floor_rate`, a SCALE-unit copy of the relay floor | Declared (`:45-59`). The cross-check against `relay_fee_floor` it says it owes is absent: the file has no tests. | V |
| X7 | `stage2.rs:244-246` | `year_share_atomic`, a u128 widening of `mul_scale` | Declared; pinned by test `stage2.rs:1757` | V |
| X8 | `stranding.rs:71-77` | Pre-D1 scoring, re-expressing a deleted production function | Declared (`:24-29`) | V |
| X9 | `escalation.rs:86` | Knee as archival length, 6.75 TB | Pinned against a W re-pin by test `:231` | V |

### (S) Sweep and grid bands

- **Escalation:** `escalation.rs:57` asymptote band; `:80` `KNEE_BAND = [500_000, 2_250_000, 10_000_000]`. The band exists under that name and matches the JSON comment. Test `escalation.rs:253` pins `shekyl_escalation_knee_n` to `KNEE_BAND[1]`, so production config is pinned to a sim constant, not the reverse.
- **Stage 2:** `stage2.rs:61,768,772,780,1256,1387`.
- **Onset:** `onset.rs:93,96,106,112`.
- **Archival arms:** `distribution.rs:189`; `cartel.rs:98,101,107-116,478,670`; `mn_feasibility.rs:60-64`; `challenge_coverage.rs:41`; `proxy.rs:102,696`.
- **Fee instruments:** `fee_floor.rs:87,91,96,122,203-214,459,473-476`; `fee_ladder.rs:95,110,1242-1255,2134-2136,2245-2281,2292-2299,2333,2399-2431`.

### (P) Correct production imports, per file

- **`admission.rs:33-35`** — `scarcity_micro`, `work_milli_from_micro`, `MAX_HOLDINGS_SHARDS`, `WORK_MICRO_PER_MILLI`.
- **`budget.rs:51-58`** — `SETTLEMENT_EPOCH_BLOCKS`; `base_block_reward`, `effective_emission`, `calc_release_multiplier`, `calc_burn_pct`, `compute_burn_split_at`, `calc_effective_emission_share`, `split_block_emission`.
- **`budget_scenarios.rs`** — none directly; uses `SimParams.tx_volume_baseline`.
- **`burden.rs:31-33`** — `ARCHIVAL_BOND_FLOOR_ATOMIC`, `predict_archival_len`, `shard_of`, `SHARD_LENGTH`.
- **`calibration.rs:42-46`** — `outputs_per_node`, `predict_weight`, `predict_archival_len`, `MAX_OUTPUTS`, `MAX_TREE_DEPTH`, `SHARD_LENGTH`; test `:513` uses `FULL_REWARD_ZONE` and `BLOCK_WEIGHT_SURGE_FACTOR`.
- **`cartel.rs:81-85`** — `bond_floor_of`, `reinstate_connect`, `BadInterval`, `FAILURE_WINDOW_M/N`, `MAX_HOLDINGS_SHARDS`, `SLASH_GRACE_EPOCHS`.
- **`challenge_coverage.rs:36`** — `SETTLEMENT_EPOCH_BLOCKS`.
- **`distribution.rs:43`** — `curve_milli`, `scarcity_micro`, `work_milli_from_micro`.
- **`engine.rs:2-7,146,166-169`** — the burn, emission and release functions, `calc_stake_ratio`; `staker_pool_share`, DAA target and escalation fields from `EconomicParams::default()`.
- **`escalation.rs:35-38,237`** — `staker_pool_share_at`, `EscalationParams`, `SCALE`, floor from the shipped config, `SHARD_LENGTH`. Nothing computes a ramp locally.
- **`fee_floor.rs:65-69`** — `TX_VOLUME_WINDOW`, `base_block_reward`, `BLOCKS_PER_YEAR`, `RELAY_ADMISSION_SLACK_BP`, `RELAY_FLOOR_LOOKBACK`.
- **`fee_ladder.rs:44-56`** — `corrected_fee_ladder`, `relay_fee_floor`, `hysteresis_step/fold/settled`, `paid_block_reward`, `effective_emission`, `projected_already_generated`, `tail_subsidy_per_block`, `emission_speed_factor`, `STAKER_EMISSION_SHARE/DECAY`, `BLOCKS_PER_YEAR`, `FULL_REWARD_ZONE`.
- **`main.rs`** — none.
- **`mn_feasibility.rs:46-48`** — `FAILURE_WINDOW_M/N`, `MAX_HOLDINGS_SHARDS`, `SETTLEMENT_EPOCH_BLOCKS`.
- **`onset.rs:69-72,584,746`** — `ARCHIVAL_BOND_FLOOR_ATOMIC`, `calc_burn_pct`, `calc_effective_emission_share`, `SHARD_LENGTH`.
- **`population.rs:34-36`** — `curve_milli`, `scarcity_micro`, `work_milli_from_micro`.
- **`proxy.rs:39-43`** — `failure_window_slashable`, `BaselineObservation`, `CHALLENGES_PER_PAIR_PER_EPOCH`, `FAILURE_WINDOW_M/N`, `MAX_HOLDINGS_SHARDS`, `SETTLEMENT_EPOCH_BLOCKS`, bond floor.
- **`record.rs:40-45,281`** — `base_block_reward`, `base_emission_at`, `calc_burn_pct_from_activity`, `compute_burn_split_at`, `params_digest`, `CALIBRATION_GENERATION`.
- **`redistribution.rs:33`** — `reward_share_floor`, bond floor.
- **`scenarios.rs:2`** — bond floor (`:356,398`), `SETTLEMENT_EPOCH_BLOCKS` (`:397`).
- **`stage2.rs:23-29,47-49,507`** — emission and burn functions, `reward_share_floor`, bond floor, `MAX_HOLDINGS_SHARDS`, `SHARD_LENGTH`.
- **`stranding.rs:37-40`** — `g_age_milli`, `scarcity_micro`, `work_milli_from_micro`, `reward_share_floor`, `MAX_CLAIM_AGE_W`, `MAX_HOLDINGS_SHARDS`.
- **`swing.rs:29,36,38`** — `SHARD_LENGTH`, `FULL_REWARD_ZONE`, `blocks_to_surge_saturation`, `BLOCK_WEIGHT_SURGE_FACTOR`.

### Answers to the specific checks

| Item | Finding |
|---|---|
| Replica target R | A1: exogenous, declared, held in two consts. |
| Bond floor 0.75 | Imported from `ARCHIVAL_BOND_FLOOR_ATOMIC` wherever it is computed: `burden.rs:142`, `scenarios.rs:356,398`, `stage2.rs:904`, `onset.rs:437,476`, `proxy.rs:468`, `redistribution.rs:102`, `cartel.rs:234`. Literals survive only in report strings (R15) and tests (R30). |
| `SHARD_BYTES` | `burden.rs:60` is `SHARD_LENGTH.to_raw() as f64`: imported, pinned at `burden.rs:253`. Integer paths use `SHARD_LENGTH` directly. |
| Blocks per year | Restated at R1 and R4. `fee_ladder.rs` and `fee_floor.rs` import it. |
| Epoch length | Imported in five files; restated at `swing.rs:50` (R5) and in `mn_feasibility.rs` test literals `:1052,1081,1098`. |
| COIN | R3. |
| Emission, tail, decay | Values restated (R1); functions called. Tail restated at `onset.rs:755` (R12). Split epoch wrong (R9). |
| Burn | Values restated (R1); `calc_burn_pct` called. The supply operand is gross in two places (D2). |
| Staker share | Pool share imported; emission share and decay restated (R1); literal 0.25 (R13). |
| Archival bytes per tx | No `12,627` literal anywhere in the crate. `burden.rs:82-85` calls `predict_archival_len` at the modelled tree depth. |
| Tx weights | `predict_weight` at `calibration.rs:125`, shapes searched (`:162-201`). No local byte model. |
| Storage / Kryder, opportunity cost, traffic | A5, A3, A6. |

### Tests and outputs that pin results depending on items 1 and 2

**Item 1 (`FEE_PER_BYTE_ATOMIC`)**
- `calibration.rs:556` `a_shard_costs_about_one_skl_and_depth_barely_moves_it` pins an absolute band of 0.5–2 SKL per shard and ≤ 5 % depth drift. It will move.
- `calibration.rs:385` `stuffer_shape_is_max_inputs_min_outputs`, `calibration.rs:508` `max_archival_per_block_is_a_search_not_the_cost_shape` and `swing.rs:229` `flood_ceiling_is_finite_and_nearly_depth_flat` depend on the fee only through the fee varint in the weight. Weak.
- `calibration.rs:435`, `:469`, `:534` are identities over `tx_fee_atomic`. They survive a value change but need rework if the fee becomes state-dependent.
- `stranding.rs:279,309,325` use hand-typed claim costs (0.01 and 0.005 SKL). They will not move, but lose their anchor.
- Report outputs: stuffer table `stage2.rs:702-761`; A4 cost, ROI and verdict `stage2.rs:901,1079,1157-1249`; A3 claim cost `stage2.rs:1269-1286,1316`; OQ-4 `stage2.rs:1417`; A6 fee term `swing.rs:215`.

**Item 2 (`fee_per_tx`)**
- `onset.rs:827` `growth_schedule_year_fees_exceed_u64_so_the_aggregate_is_u128` asserts a magnitude and is the most likely to go red. The production floor scales with the base reward (333 atomic/byte at 10 SKL, about 20 at the 0.6 SKL tail), so a late-era fee per tx is orders of magnitude below 0.1 SKL. This is arithmetic from constants, not a run.
- `onset.rs:872` `fee_horizon_closed_form_matches_the_fold_on_the_baseline` and `onset.rs:903` `burn_horizon_rises_with_sqrt_traffic_until_the_cap` rest on the constant-fee closed form (`onset.rs:428-440`) and literals 0.25 / 0.10.
- `record.rs:330` `committed_fixture_matches_recorder` pins `staker_fee_pool` and `actually_destroyed` in `docs/test_vectors/economics/baseline_steady_state.json` (11 rows). Regenerate via `record.rs:318`.
  - This is the only pin on those columns. The engine-core differential (`shekyl-engine-core/src/engine/economics_differential.rs:46-90`) drops them, and `staker_emission`, through serde.
  - That differential takes `circulating_supply` as an input (`:149-162`), so it cannot see D2 or R9 either.
  - `CALIBRATION_GENERATION` is written into the fixture (`record.rs:281`) and asserted engine-side, so a generation bump moves both.
- `stage2.rs:1743` `a1_aggs_positive_and_emission_decays` needs fee > 0.
- `stage2.rs:1785`, `:1818`, `onset.rs:772`, `:809` are ordinal or equalities between sim paths. They survive.
- `cartel.rs:880` `reinstate_breakeven_pins_at_representative_reward` hard-codes its reward input. It will not move; its "representative" label goes stale (D12).
- `engine.rs:394` carries the literal (`:386`), but its asserted values are fee-independent.
- Not fee-dependent: `stage2.rs:1703`, `escalation.rs:253`, `onset.rs:793`.
- Report outputs:
  - Default and `--gate7` JSON: burned, yield, circulating, inflation.
  - `--fb1c-c2`: fee leg, budgets, uplift.
  - `--stage2`: A1 `stage2.rs:493-633`; onset and levers `onset.rs:481-750`, including the closed-form horizon `:581-637`; A3 budget; A2 pool `stage2.rs:1585-1592`; A4 Δpool `:869-873`; A5/TJ operands `:1458-1480`; the JSON payload `:1642-1648`.
  - `--fee-ladder`, `--fee-floor` and `--challenge-coverage` read neither item.
- `docs/economics_sim_results.json` holds fee-dependent totals, but it is a stale stderr capture (cargo lines, "Running scenario"). No test or workflow reference was found.

### Not checked / uncertain

- `tests/unit_tests/scaling_2021.cpp` contents against the pins at `fee_ladder.rs:3034-3046` (file exists; cases not compared).
- Whether the Rust weight penalty returns exactly zero at B = 2M (the value R8 asserts).
- Equivalence of the sim urn (R21) and production `ChallengeUrn`: both read, neither run.
- Whether `bond_duration` is the right owner for "bond life" (A11), and whether the wallet claim floor is the right owner for A9.
- R-target absence is grep-based over `rust/`; design docs were not searched for a ratified value.
- Design-doc figures quoted from sim runs (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13–§12.14) were not swept.
- `shekyl-staking-sim` was not censused.
- Owners for R3, R9 and D5 live in `shekyl-units`, `shekyl-chain-rules` and `shekyl-fcmp`, none of which the sim depends on today.
- Grid literals in `fee_ladder.rs` and `fee_floor.rs` are summarised under (S), not itemised line by line.

---

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
| D2 | `sim/agent.rs:104-342` (whole portfolio re-chosen in place every epoch); L9 lock `sim/agent.rs:288-295`, `sim/model.rs:670-673`; L18 escrow `sim/model.rs:356-372`, `sim/agent.rs:131-151,333-339`; axis `holdingsupdate_cooldown` `sim/scenarios.rs:3899-4065` | In-place per-shard add/drop (`HoldingsUpdate`) with a per-shard duration lock and per-shard release cooldown | `HoldingsUpdate` rejected 2026-09-20; a bond is fixed at join and holdings change by `Release` + `JoinMarket`: `prod/bond_wire.rs:47-58`, `prod/admission.rs:79-83`. DOC does not record the rejection (grep empty). | V |
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
| R16 | `sim/fingerprint.rs:145-149` | `serve_credit_bit = deep && held && inflight==0` | Serve credit | `settle_epoch` and `SERVE_THRESHOLD_PASSES = 2`, `prod/attestation.rs:71,192` | V |
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
