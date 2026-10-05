# EUP — one economy, assessed whole

**Status:** **OPEN — opened 2026-10-04.** Identifier family **`EUP-`**
(the program's steps, §5), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file
(rule 94 §1). This document owns the order in which the economy is realigned,
measured and decided. It does not own any single mechanism; each row of §2
names its owner.

**Why it exists (Rick, 2026-10-04).** "Without a consolidated, umbrella plan
to ensure the elements of the economy interact predictably, we run the risk of
a patch economy, which is one of the worst things for a coin." The design has
moved since April in necessary directions, one mechanism at a time: the fee
ladder, the burn, the archival good, staking. Each change was right for its
own mechanism. Nothing has yet checked that, together, they still deliver what
April set out to deliver.

**How the economy is built (Rick, 2026-10-04): the sim is the plan.** We tweak
the sim until the economy is what we need it to be, to know and to do; then it
is implemented in code; then the sim incorporates that code as a check; then
the cycle repeats. Where a mechanism is settled, the sim calls the code. Where
it is still being designed (staking, now), the sim leads the code, and a
surface the daemon does not read yet is not dead.

---

## 1. The program

Ordered, because each step's numbers are inputs to the next.

| Step | What | Owner | State |
| --- | --- | --- | --- |
| **EUP-1** | The emission speed factor per block, as designed (A below), fixed in the code on `dev`. This document and the `DESIGN_CONCEPTS.md` drift corrections (B, C, E) land beside it. | #951 (`fix/esf-per-block`); #948 | landed |
| **EUP-2** | The economics sim realigned to the code: #936 landed on `dev` first, and the ESF fix (#951) merged over it, carrying the per-block factor into the sim and regenerating its fixtures on the design curve; ESR-8 (restated constants → imports); ESR-10 (fee multiplier and rung mix, each run on `w_ref` and the zone as they are **and** re-derived from the post-quantum ordinary weight). | [`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md) | ESR-1…ESR-7 landed (#935, #936); ESR-8 in progress |
| **EUP-3** | Staking coupled in: the purse the economics sim computes feeds the population model; L19i's challenge egress in the same model; the bond at the shipped floor. The staking sim is checked against what has been built, and leads what has not. | `shekyl-staking-sim`; the staking-sim row in `FOLLOWUPS.md` (reworded on PR #936 to *Check `shekyl-staking-sim` against the staking code built so far*) | not started |
| **EUP-4** | The full per-year set, run on the design curve, every scenario, both fee arms, the ESR-7 envelope. **This is the assessment baseline.** §4's criteria are graded against it, and they are written before it runs. | this document | waits on EUP-1…EUP-3 |
| **EUP-5** | The decisions, with numbers: D (the floor in consensus, holistically), F (the escalation and its GF-7 asymptote), G (zone and `w_ref` derivations, FL-R13), H (challenge doctrine against the budget), I (bond sizing, first-time sim), and the stress test of the 720-block window's length. | each row's owner (§3) | waits on EUP-4 |

**No production-arm table is run until the ESF fix and #936 are both on
`dev`** (design-owner lane, 2026-10-04): every number in ESR-1…ESR-7 was
computed on the Monero curve, and a table run before then would be a third
curve's worth of numbers. From that point EUP-2's registered runs (ESR-10's
tables and the realigned fixtures) run on the design curve; the full
assessment set, graded against §4, is EUP-4's.

**Whether we are "not terribly far off"** is held until EUP-4. The emission
speed factor is the input under every other number, and it could move that
judgement either way.

---

## 2. The mechanisms, and how they couple

Column one is the design as designed, read from `dev` at `684673611` by the
design-owner lane (2026-10-04); doc-versus-ruling and doc-versus-code
disagreements are recorded as drift (§3), not verdicts. *Measured* is filled
only where an ESR table has measured the mechanism, with the commit the number
came from. **Every measured figure is on the ESF-21 curve** (§3 A): read it
for direction, not level, until EUP-4.

| # | Mechanism | Job | Ruled / specified | Couples to (→ feeds, ← fed by) | Measured (ESR, on PR #936) |
| --- | --- | --- | --- | --- | --- |
| 1 | Emission curve | PoW security budget; predictable, no governance. ESF 22 per block | `DESIGN_CONCEPTS.md` §3, §13; FL-R12′ | → miner pay, staker share (11), fee floor (5), every onset | Code ran 21 per block (A) |
| 2 | Perpetual tail | Avoid the fee-only end state; 0.3 SKL/min | FL-R12′ | → security budget | — |
| 3 | Release multiplier | Demand-paced emission, 0.8–1.3× over a 720-block window | Component 1; FL-R24 (operand) | ← volume; → emission (1), correction C (6) | ESR-4 (`896d95c33`): step response over 720 blocks; ESR-6 (`49b313eeb`): pinned at 0.8 while blocks carry 22 of 50 |
| 4 | Block-weight governance | Penalty past the median; 300 KB zone; 2× limit; penalty applied last | FL-R12′ (order); zone value punted (G) | ← weights; → floor (5), fill rule, paid reward | ESR-6: blocks carry 22 of 50 for eleven years (finding 1) |
| 5 | Fee ladder | Price block space: Economy `F = R·C·w_ref/M²`, Standard 4F, Priority `max(2RC/M, 4F)` | `FEE_LADDER_DERIVATION.md` §5, §8; FL-R13 open | ← reward, C, median, `w_ref` | ESR-1 (`9d8a52985`): Standard ≈ 3.3 SKL/tx in year 1; ESR-6: year 1 2.36, falls 4.9× once the median grows |
| 6 | Fee correction C | Keep the miner's margin whole: `(1 − σ)·M_r/(1 − b)` | FL-R20/21 | ← σ (11), burn (8), M_r (3); → floor (5), **block growth** | ESR-6 finding 2: the year blocks first grow is set by `(1 − σ)/(1 − b)` — two-thirds burn, one-third σ |
| 7 | Floor enforcement | Relay policy; block-carried transactions bypass it | FL-V2; **Q9 reopened as a bug, 2026-10-02** | → stuffing cost | ESR-7 (`28b0006f4`): cheapest archival byte is a miner's in every era |
| 8 | Adaptive burn | `50 % × √(V/50) × net supply ratio`, cap 90 % | Component 2; F-D; FL-R16c | ← volume, net supply; → split (9), C (6) | ESR-5 (`eb501b15d`): net supply through its owner, report byte-identical |
| 9 | Burn split | 25 % of burn → staker pool, 75 % destroyed | Component 2 | → budget (12) | — |
| 10 | Escalation | Lift the staker share with the corpus; banded-PL in closed shards | `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §6, §12; GF-7 | ← closed shards; → split (9) | Ships flat at genesis (F); knee band's low anchor moved by finding 1 |
| 11 | Staker emission share | Bootstrap subsidy, 15 %, ×0.90/yr | Component 4 | ← emission; → budget (12), C (6) | — |
| 12 | Archival budget | Emission leg + fee leg; unclaimed after 26 epochs is never created | `ARCHIVAL_BUDGET_SCHEDULE.md` §4 | ← (9), (11); → reward division (13) | — |
| 13 | Reward division | Pay-for-service by capped serve-work | `REWARD_EMISSION_LEG.md` §4 | ← budget, work; → archiver income | — |
| 14 | The archival good | Prunable bodies + `pqc_auths`, for rescan, audit, dispute | `V3_STAKER_ARCHIVAL.md`; PDM-Q6, PDM-Q2 | → burden | ESR-6: corpus at year 10 is 229 864 closed shards, against 523 841 before |
| 15 | Bond | Honesty anchor, slashable; 0.75 SKL per shard | Component 3; magnitude underived (I) | → locked capital, the binding burden (F-G) | — |
| 16 | Challenge | Exhaustive, 3 per pair per epoch, whole-shard read | `ARCHIVAL_CHALLENGE_MECHANISM.md`; SF-D1 | → archiver egress cost | Not yet in the economics sim (H) |
| 17 | Coverage | Market-set by budget → APR → entry | L11 | ← budget; → availability | — |
| 18 | Total staked | An observable; under bonds-only, the bonded principal | F-D deleted the burn consumer | (was) → burn | Retained (ruled 2026-10-03; staking is being built) |
| 19 | Supply accounting | Net circulating = generated − burned | FL-R16 family | → burn, ratios | ESR-5 |

**The couplings already found**, because these are what a patch economy
breaks:

- **Everything rides the curve.** `F ∝ R`, so every fee, every stuffing
  cost, every onset year and the year-11 capacity unlock move with the emission
  speed factor (A).
- **Block growth rides the staker share and the burn** (ESR-6 finding 2). A
  change to the decay schedule, the burn curve or C moves the year the default
  fee can first grow blocks, and with it the corpus, the purse and the onsets.
- **Two inherited constants gate capacity.** `w_ref = 3 000` and the
  300 000-byte zone were sized for a Monero transaction, a quarter to a fifth of
  ours (ESR-6 finding 1; G).
- **Capacity sets the corpus, and the corpus sets the knee.** The escalation's
  knee band was derived from a baseline that carries its demand, which the
  chain does not (F).
- **Floor enforcement does not set the cheapest byte.** A miner displacing
  honest fees is cheaper than any relay stuffer, and the free-room case stays
  free or `b·F` with the floor enforced (ESR-7; D).
- **The challenge doctrine's egress is a cost the budget has not been shown to
  carry** (L19i; H).

---

## 3. What the read found, and how it is disposed

Each row is the design-owner lane's finding (2026-10-04) with **Rick's
disposition verbatim**.

| | Finding | Rick's disposition | Action | Step |
| --- | --- | --- | --- | --- |
| **A** | The design's curve is ESF 22 per block (50 % ~year 11, 80 % ~year 25; year-1 reward ~970). The code applies Monero's per-minute convention, 22 − (2 − 1) = 21 per block: 50 % at ~5.5 years, 2 048 SKL at genesis. Witnessed by the design's year-1 reward row as well as its sentence; the recorder's "ESF-22 milestone" at 5 788 000 blocks is a third figure (ESF 23). | "The code should match the sim, as that is the design - It's entirely likely that the implementation is still in Monero, that happens alot, especially with the old cpp." | The ESF PR: the factor becomes per block; the conversion and its unread C++ macro are deleted; KATs re-minted from the closed form on both sides; digests re-pinned; the captured chains re-captured. | EUP-1 |
| **B** | `DESIGN_CONCEPTS.md` still carries the stake-ratio governance signal F-D deleted. | "Great finding, that should be fixed immediately because it is likely to send both humans and agents down the wrong path early." | Corrected in this PR. | EUP-1 |
| **C** | Component 3's rationale ("FCMP++ needs historical tree state") contradicts its design home: the good is prunable bodies for rescan, audit and dispute. | "This has recently evolved during implementation, and this is one place where the landed code is ahead of the design documents … We need to, but we also need to make sure that we aren't unbalancing the whole cart, as it were." | Corrected in this PR; the balance question is EUP-4's. | EUP-1, EUP-4 |
| **D** | The anti-stuffing argument assumes a consensus floor; a miner's own transactions bypass it. | "Yes, this is one of the things we need from the sim, and then decide how it should be implemented holistically." | ESR-7 measured it; noted at the argument in this PR; decided at EUP-5 with the floor-basis question. | EUP-5 |
| **E** | The yield and outcome tables were computed at a flat 0.10 SKL fee and the deleted stake-ratio concept. | "And they should be fixed, based on taking current implementation into the sim. This staking section is where we are ahead, and same problem - how is what we have implemented going to affect the system as a whole." | Marked records-was in this PR; recomputed from the sim at EUP-4. | EUP-1, EUP-4 |
| **F** | The escalation is described as live and ships flat; the knee was derived from a trajectory the chain does not carry. | "This is a deviation that was recently coded in, and we have to re-evaluate this when we have the sim aligned - then we will probably have to make some design decisions." | Held: the knee test bounds, not pins (2026-10-03); FOLLOWUPS row owned by the GF-7 ceremony. | EUP-5 |
| **G** | The 300 KB zone and `w_ref = 3 000` were never derived for Shekyl; FL-R13 (floor basis) is open on the same surface. | "Yes, and that punt needs to have some derivation behind it - which is why we stopped to run the sim under the new/current paradigm." | ESR-10's second arm; FOLLOWUPS rows (zone capacity leg; `w_ref`). | EUP-2, EUP-5 |
| **H** | The challenge doctrine's egress (~80× storage, L19i) breaches the budget in calibrated cells; the two were ruled in different rounds. | "Yes, they need to be reconciled." | Egress into the population model. | EUP-3, EUP-5 |
| **I** | The bond's magnitude has no derivation; F-G found it the binding burden. | "Yes, which is why we need to re-sim it. Or sim it the first time, since it was not part of the original design, or at least not part of the design that was fully assessed." | First-time sim of the bond. | EUP-3, EUP-5 |
| **J** | Design goal 5 and the release multiplier are intact. | "Yes, I think the 720-block operand has been tested in a number of ways (check this) and is actually more derived than it looks. However, I think we are still calling it provisional because it has NOT been stress tested." | Checked: FL-R24 ruled the operand's *form* (the exact SMA) from FL-E1–E3; window-length arms were run in round 2b and recorded "not selected, not read for selection". The form is derived, the length is provisional, and no stress test of the length has run. ESR-4 put the window into the fold, so step response, boom/bust and a stuffer working the window's edge are now runnable. | EUP-5 |

**One conflict, resolved by the later ruling.** The relayed program lists
"dead schedule" under ESR-8. Rick ruled on 2026-10-03 that the stake schedule
stays — staking is being built, and the sim leads it — and that ruling governs.
"`total_staked` as bonded principal" is read as giving the field its meaning,
not as deleting it.

### 3.1 Inherited operands: a search pattern, and its first walk (2026-10-04)

A, G and the fee floor's basis are one pattern, not three findings. Each is
a Monero constant or convention that was correct at Monero's state — a
tail-era reward, a 3 KB transaction, a per-minute factor — and went wrong
here because Shekyl's state differs. The code was faithful and so were the
documents, which is why no review tripped; the numbers appeared only when
the sim charged what the chain charges.

**The pattern.** Any inherited formula that takes the block reward, a
transaction's or coinbase's weight, or the block time as an operand was
derived at Monero's value of that operand, and is re-derived at ours or
named as not. The census found the restated constants; this is the layer
below, constants that are faithful and whose derivation assumed another
chain. Two of the three operands differ sharply: the reward (0.6 XMR at
Monero's tail; 1,024 SKL at genesis, falling 1,707× to 0.6) and the weight
(an ordinary transaction is 12.6–15.3 KB against a 3 KB reference). The
third does not: both chains run 120-second blocks, so a count of blocks is
the same duration here, and what remains of that class is a per-minute
convention (A).

**The walk.** Each row is answered from its record, read at source at
`e9b41e3115`. "Derived" means a ruling on record used Shekyl's operand.

| Constant | Operand | Answer | Record, and where it goes |
| --- | --- | --- | --- |
| Emission speed factor | Block time, via the per-minute convention | **Was not; fixed** | A; #951 |
| Fee floor's basis, `F = R·C·w_ref/M²` | Reward | **Not derived.** Reward-proportional, so highest at genesis and decaying 1,707× | FL-V11; FL-R13 open; EUP-5 G |
| `w_ref` = 3,000 | Transaction weight | **Not derived.** No examination record as a choice | CEN-M3; `FOLLOWUPS.md`; EUP-5 G |
| Zone, 300,000 B | Transaction weight (capacity leg); verification time (cost leg) | **Split.** The cost leg is measured on the device floor. The capacity leg was ratified on an estimate of 4–8 KB a spend; measured, 13.6 KB, so about 22 spends | C2-R2 Q1; `FOLLOWUPS.md`; EUP-5 G |
| Coinbase reserve, 600 B | Coinbase weight | **Not derived, and ratified on a statement that is false.** C2-R2 Q7 records that a Shekyl coinbase "serializes well under 600 bytes". The minimal one, a single output with no attestation, weighs 1,331 B, of which 1,232 B is `extra` (measured: `shekyl-block-template`, the genesis-era template's `miner_transaction.weight()`) | **New.** `FOLLOWUPS.md`; rule it with the zone |
| Transaction weight cap, 149,400 = zone/2 − reserve | The two rows above | **Formula derived; its stated guarantee does not hold.** Two maximal transactions and a coinbase are 300,131 B, over the zone | C2-R2 Q7; rides the two rows above |
| Tail, 0.6 per block | Reward against supply | **Not derived.** The same 0.6 as Monero's, on an asymptote of 2³² SKL: 157,680 SKL a year is 0.0037 % of it, where Monero's is about 0.86 % of its supply. FL-R12′ ruled the tail perpetual; no record sizes it | FL-V11 ("inherited-unexamined"); §4 goal 2 grades the security budget it leaves; EUP-5 |
| Input cap, 8 | Verifier time per input | **Not derived.** Carried as inherited and unjustified | CEN-I4; `FOLLOWUPS.md` |
| Coinbase unlock, 60 blocks | Block time | **Not re-derived**; the operand is unchanged | CEN-F6, `pinned-not-re-derived` |
| Long-term clamp 1.7×, 100,000-block window | Block time; growth rate | **Derived.** Traced on Shekyl's machinery, two-regime rationale countersigned, checked against the retention horizon | C2-R2 Q2 |
| Surge factor and the 100-block window | Verification time of a surge block | **Derived.** The inherited ×50 was re-derived from the device floor's verification time; the config carries 4 | C2-R2 Q3; GAP-7 |
| Quadratic penalty and the 2× limit | Reward and weight, both as ratios | **Derived.** Scale-free in both operands; shape examined | C2-R2 Q4 |
| Serialized-size cap, 1,000,000 B | Transaction weight | **Derived** as a parse bound: the weight cap binds first, and it admits 22 inputs of the measured shape | C2-R2 Q6; CEN-I4's measurement |
| Pool lifetime, 3 days; pool cap, 648 MB | Block time; the zone | **Derived**, against the FCMP++ reference-age window. The cap is "3 days at the zone" and moves with it | C2-R2 Q11 |
| `tx_extra` relay cap, 24,576 B | Transaction weight | **Derived**; Shekyl's own value | C2-R2 Q10 |
| Fee correction `C` and the three rungs | Shekyl's `σ`, `M_r`, `b` | **Derived**, given the floor they multiply | FL-R11, FL-R17, FL-R20 |

**What the walk adds.** One row is new: the coinbase reserve. The fill
admits bodies up to `2·median − 600`, so a block filled to that bound
carries a coinbase 731 B past the limit it was reserved for; that is
arithmetic from the measured weight, not yet a test. Changing the reserve
moves the transaction weight cap, which is consensus (CEN-H3), so it is a
ruling and travels with the zone's. One row sharpens an old name: the tail's
size has never been examined against Shekyl's supply. The rest were already
on record, and the block-weight governors (the clamps, the surge factor, the
penalty) come out derived: C2-R2 did that work.

**Not walked.** The difficulty algorithm's constants (`daa_*`), the staking
and archival constants and the FCMP++ reference ages are Shekyl's own, with
their own rounds. Peer-to-peer timeouts and sync batch sizes read none of
the three operands.

---

## 4. The assessment set, written before EUP-4 runs

Graded at EUP-4 against the design curve, both fee arms, every scenario. A
criterion with an April number takes it; a criterion April did not set is
**PROPOSED** and needs Rick's ratification before EUP-4 runs — setting a
threshold after seeing the numbers is the failure this section exists to
prevent.

| Design goal (`DESIGN_CONCEPTS.md` §1) | Measured as | April's figure | Criterion |
| --- | --- | --- | --- |
| 2. Long-run security budget | Miner income (reward + kept fees) per block, by year; the tail era's share that is fee | Miner income ≥ 85 % of no-share in year 1, 95 % by year 10 | Holds on the baseline and the boom/bust schedule. **PROPOSED:** no year in which the tail-era miner income falls below the tail subsidy alone |
| 3. Predictability | Emitted fraction by year; release multiplier's range | 50 % ~year 11, 80 % ~year 25 | The owner's curve test pins April's figures on the neutral trajectory. **PROPOSED:** within ±1 year of them on every scenario |
| 5. Demand-responsive emission | Release multiplier and burn under step, boom/bust and stuffing schedules; the 720 window's step response | M_r in [0.8, 1.3] | **PROPOSED:** a stuffer working the window's edge cannot hold M_r above 1.0 for longer than the window at a cost below the ESR-7 envelope |
| 6. Self-regulating balance | Staker yield; A1 clearance; onset year; coverage | Staker yield 4–6 % years 1–5, ~1.7 % at year 10 | **PROPOSED:** yields within a factor of two of April's in years 1–10; A1 flat-25 clearance ≥ 1 through year 20 at 10 % on the baseline |
| Capacity (no April row) | Transactions carried per block against demand; years to carry the baseline's 50 | — (April assumed blocks carry demand) | **PROPOSED:** the default rung carries the baseline's demand from genesis, or the deviation is a ruled choice |
| Usability (no April row) | Standard-rung fee for an ordinary transaction, by year | — | **PROPOSED:** a year-1 figure Rick sets before EUP-4 |
| Stuffing (§6) | The ESR-7 envelope minimum, in floors per byte, by era | "Marginally profitable short-term" | **PROPOSED:** the cheapest archival byte is no cheaper than the relay floor in any era, after D is decided |

Goals 1 (denomination) and 4 (`uint64_t` safety) are code properties, held by
their own tests, and are not graded here.

### 4.1 The horizon, and one reading registered before the tables run (2026-10-04)

**What the first run on the design curve showed.** Merging the ESF fix over
the realigned sim (#936) failed three tests that each used "year 60" to mean
"the fee era". On the design curve it is not: the neutral trajectory reaches
the tail near year 119, and the control arm's fold near year 132 (the release
multiplier's floor slows it); at year 60 the curve still mints ≈ 23.9
SKL/block. Two of the tests state tail-era facts and now start in the tail era
and assert it (`onset::tests::assert_tail_era`). The third is the escalation
knee's band, whose high fell to 2,079,614 against a shipped knee of 2,250,000;
the knee is held, not re-pinned (`docs/FOLLOWUPS.md`).

**Horizon — PROPOSED, a decision about the assessment.** The structural
questions (onset, fee era, tail) are tail-era questions, and a 60-year run no
longer sees them. The structural arms run to about 135 years; the remaining
arms stay at 60. Measured cost on the control arm: the baseline to 135 years
is 64 s. The growth schedule is not affordable that far as the fill stands —
63 years is 337 s and 66 years exceeds 500 s — because
`Fill::admit_up_to` batches only the penalty-free part of a block and walks
the penalty zone one body at a time. Long growth arms wait on that zone being
closed in form, held to the single-offer walk as the free part is.

Scenario 9 (high history, low activity) is the first of the structural arms.
It was built to be the fee-era case, and its 60 years no longer reach that
era. Asked whether its horizon should follow the tail out, Rick's initial
assessment (2026-10-04) is "yes it should, since that is it's actual
purpose". The horizon moves with EUP-4's run set, not before: it changes
every scenario-9 figure and the knee band's high.

**Registered reading: the capacity cap spans most or all of the horizon on
the production arm.** The design-owner lane's argument: the fill condition
`w ≤ 4ρ·w_ref·(m/M)²` has no reward in it, because `R` cancels between a
ladder fee and the penalty; the crossover moves only with `ρ = (1−σ)/(1−b)`,
which grows as `σ` decays and the burn's supply ratio rises, and the supply
ratio rises half as fast at 22 per block. One observation agrees: the band's
low anchor, the production-arm baseline's closed shards at year 10, is
229,864 on both curves. One does not bear on it: the control arm sitting at
20 of 50 transactions a block through year 60 (and carrying 50 from between
years 61 and 65) is the flat fee, which does not scale with `R`, so there the
reward does not cancel. If the reading holds when the production tables run,
G (`w_ref` and the zone) is the first decision of EUP-5 rather than one of
six: the purse, the knee, the onset and the stuffer's cost are not readable
on a chain capped at the zone.

---

## 5. What this document does not do

It proposes no mechanism. Each EUP-5 decision is made by its owner, with
EUP-4's numbers. It does not replace
[`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md),
which owns EUP-2, or `STAKER_ARCHIVAL_SIM.md`, which owns the staking runs.
