# FL — Fee Ladder Derivation from Shekyl Miner Economics

> **STATUS: DESIGN ROUND IN PROGRESS — NOTHING HERE IS RATIFIED.**
> The §8 ratification table is unsigned. No constant in this document is
> consensus or policy until §8 is signed and the change lands through its own
> implementation PR(s). The RK-5 RPC migration lane is explicitly out of
> scope: every wire-shaped consequence in §7 carries a named trigger and is a
> proposal, not a change.

Identifier family: `FL-*` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) at birth, rule 94).
Convention, because the family token is one case-flip from a rung symbol:
rung symbols always appear backticked as `Fl` / `Fn` / `Fm` / `Fh`; family
tokens are always `FL-` followed by a digit or section letter.

Branch: `design/fee-ladder-derivation` (worktree, off `dev`). All `file:line`
anchors are at `dev` = 6d2f49a5c unless stated.

---

## §0 The question and its jurisdiction

`Blockchain::get_dynamic_base_fee_estimate_2021_scaling`
(`src/cryptonote_core/blockchain.cpp:4475-4508`) serves a four-rung fee
ladder (`Fl`/`Fn`/`Fm`/`Fh`) transliterated from ArticMine's Monero 2021
scaling paper, cited by URL at `blockchain.cpp:4477`. The rungs are
block-expansion price points: each is (approximately) the per-byte fee at
which expanding the block past the effective median by a given factor is
paid for. Nobody has ruled that this is Shekyl's ladder. Rule 16 §Scope puts
inherited code squarely in jurisdiction; this round derives the ladder from
Shekyl's own miner economics or retires the question with a derivation
showing the inherited one is right.

The three Shekyl mechanisms absent from the ArticMine calibration:

1. **Release multiplier** — consensus reward is scaled by
   `M_r = clamp(tx_volume_avg / 50, 0.8, 1.3)`
   (`rust/shekyl-economics/src/release.rs:7-8`,
   `config/economics_params.json`).
2. **Fee burn** — the miner receives `(1 − b)` of total fees,
   `b = min(0.9, 0.5·sqrt(v/50)·circulating/total)`
   (`rust/shekyl-economics/src/burn.rs`).
3. **Emission split** — the miner receives `(1 − σ(t))` of the (penalized,
   modulated) block emission, `σ(0) = 0.15` decaying `×0.9` per year
   (`rust/shekyl-economics/src/emission_share.rs`,
   `src/shekyl/economics.h:95-116`).

### §0.1 Census collision and sequencing hold (coordination, 2026-09-03)

The consensus census's queued **C2-R2 batch** (`CONSENSUS_RULE_CENSUS.md`
§10 R2: CEN-G6, G6b, F14b, H1, H3, M3, M4, M10) owns rows that are this
round's subject, flagged by the umbrella lane at round start:

- **CEN-M3** (census :532) *is* the FL-V2/FL-C6 relay floor — classed
  `examined-disposition` on the submit path only; the 0.95 factor,
  quantization mask, reference weight, and 2% buffer "have no examination
  record as choices."
- **CEN-F14b** (census :359) is the penalty curve — classed `KAT-port`,
  explicitly **not** `ratified`; the census independently found that Survey
  A's claimed "A3 fee round" has **no locatable record**. The census and
  this round agree on the record: the transliteration is unruled.
- **CEN-G6b** (census :378) carries the fossil flag: the 300 000-byte
  reward-zone value's arbitration was punted *"to the economics doc"*
  (`GENESIS_TX_WIRE_FORMAT.md` :806–811) and never landed. **This document
  is the economics derivation that punt was waiting for**; §8 states
  explicitly which part of the punt it discharges and which it does not
  (the 1.7×/×50 clamps are consumed as boundary here, not derived — see
  §1.8 and §9).

**Sequencing is Rick's decision, put to him by the umbrella lane:** either
`FL-*` is registered as the substance of C2-R2 (and §8's signatures
disposition those census rows), or FL runs separately and R2's fee rows are
dispositioned by pointing at FL's ruling. This round therefore **holds at
the design-doc stage**: §8 stays unsigned, and no CEN-M3 / CEN-F14b /
CEN-G6b-shaped question is *ruled* here before the sequencing answer.
Derivation, findings, and the unsigned table proceed — they are inputs to
whichever sequencing wins, not rulings.

## §1 Pre-registered decision criteria (rule 11)

**Registered before any model output exists.** The instrument (§1.9) had not
been written when this section was committed; commit history is the
register.

**Taint disclosure (rule 11 discipline, disclosed rather than laundered):**
before this registration, the round performed the mandated verifications
V1–V3 (§2) and, in the course of verifying premise (4) of the brief,
derived the *correction-factor form* `C = (1−σ)·M_r/(1−b)` and evaluated it
at its clamp corners by hand (~0.68 young-quiet to ~13 congested-mature).
That quantifies a premise the brief already asserted directionally. What the
criteria below govern — rung **count**, **spacing**, **dwell**, **usage
share**, state-computed vs static, and the relay-floor disposition — had not
been measured or computed when this section was committed, and the criteria
do not encode a preferred outcome of those measurements.

Priority order throughout: **privacy > security > correctness > performance
> features**. Where an economic criterion and a privacy criterion conflict,
the conflict is surfaced in §5/§8 as its own row; it is not resolved
silently in either direction.

### §1.1 FL-C1 — Continuous-schedule precommitment (privacy)

A fee schedule in which wallets compute arbitrary-precision fees (every fee
value a near-unique fingerprint, every wallet's selection algorithm a
software fingerprint) is **rejected up front** on the privacy hierarchy,
*unless* no discrete ladder of ≤ 5 rungs can satisfy FL-C2–FL-C5. If that
exception fires, this round does not adopt a continuous schedule; it
presents the conflict unresolved to ratification.

Clarification registered now so it cannot be gerrymandered later:
**daemon-computed, state-dependent rung values are not "continuous."** All
wallets querying at the same height receive identical values; the
fingerprint axes are rung-index choice and value dwell time, governed by
FL-C4.

### §1.2 FL-C2 — Coverage

Characterize each rung by the average-cost expansion it funds:
`x(f) = f·M/R_eff` where `R_eff` is the miner-effective reward and `M` the
effective median (§3). The ladder must provide:

- **(a)** a floor rung usable as the everyday minimum: it funds at least the
  single-reference-transaction expansion `x = w_ref/M` and satisfies FL-C6
  (relay-floor consistency) in every reachable state;
- **(b)** a top rung funding `x ≥ 1.0` (expansion to the 2×median hard cap)
  in every reachable state with `v ≥ 2×baseline` (the congested states where
  full expansion is what the buyer needs), and `x ≥ 0.5` everywhere else.

### §1.3 FL-C3 — Spacing / overpayment bound

Rungs are geometric (uniform adjacent ratio `r` in log space, to within
fee rounding), with `r ≤ 10`. Rationale: a user whose need sits just above
rung `i` pays rung `i+1`, overpaying by at most `r`; an order of magnitude
is the registered ceiling on forced overpayment. If covering FL-C2's range
within 5 rungs forces `r > 10` in some reachable state, that is a criterion
conflict for §8, not a rounding to the nearest convenient answer.

### §1.4 FL-C4 — Anonymity set: dwell, usage share, count

The anonymity set of a fee value is evaluated over
`(rung index, weight bucket, height window)` — not over absolute value —
under the registered traffic model (§1.8).

- **(a) Dwell.** A posted rung value's set is the transactions emitted while
  that exact value persists on the wire. Requirement: **median posted-value
  dwell ≥ 240 blocks (8 h at 120 s blocks) per rung** in every stationary
  scenario of §1.8, and ≥ 60 blocks during the registered ramp scenario. If
  a state-computed ladder (FL-C5) violates this, the state-dependent factor
  is quantized (registered remedy: powers of 2, i.e. `C` snapped to
  `2^round(log2 C)`) before entering the formula, and dwell is re-measured.
  If it still fails, the failure is surfaced in §8.
- **(b) Usage-share floor.** Any rung with predicted usage share < 5% under
  §1.8 must be **deleted or explicitly ruled an emergency lane** whose users
  accept being marked (a §8 row either way). A rung nobody uses is pure
  fingerprint surface; a rung 1% of users use marks that 1%.
- **(c) Count.** Rung count = the number demanded by FL-C2 coverage at
  FL-C3 spacing, minus rungs failing (b); every rung beyond that count is
  paid for in anonymity set and buys nothing. Hard cap: 5.

### §1.5 FL-C5 — State-computed vs static values

Let `C(state) = (1−σ)·M_r/(1−b)` be the correction factor (§3 derives it
from source; its *form* is taint-disclosed above). Over the reachable state
grid (§1.8): if `max C / min C > r` (the adopted adjacent-rung ratio), the
rung values **must be daemon-computed from state at estimate time** — a
static rescaled ladder would be wrong by more than one whole rung somewhere.
A static ladder (possibly a one-time recalibration multiplier) is adopted
only if `max C / min C ≤ r`.

### §1.6 FL-C6 — Relay-floor consistency

`Blockchain::check_fee` (`blockchain.cpp:4456`) enforces a relay floor
computed by an independent path (§2 V2). Requirement: in every reachable
grid state, the served floor rung must pass `check_fee` (including its 2%
buffer). If the derivation produces a floor rung below the relay floor
anywhere, §8 must choose on the record between (i) clamping the served
floor rung up to the relay floor and (ii) re-deriving the relay floor from
the same corrected base in the same cutover. Neither is adopted silently.

### §1.7 FL-C7 — Feedback convergence

The fee influences volume; volume drives `b` and `M_r`; both drive the fee.
Registered demand model: `v_demand = v_0 · (f/f_0)^(−ε)`, elasticity
`ε ∈ {0, 0.5, 1, 2, 3}`. The instrument iterates the per-height map (720-
block trailing `tx_volume_avg`, per-block update, fee rounding applied). Adoption
requires: convergence to a fixed point, or limit cycles with amplitude ≤ one
fee-rounding step, across the interior grid. At the clamp rails, algebraic
boundedness suffices (both `M_r` and `b` saturate, making `C` locally
constant). Registered remedy if a divergent interior region exists:
hysteresis/smoothing on `C`, then re-test; if still divergent, surface in
§8 — do not ship a smoothed number whose stability is unproven.

### §1.8 Registered state grid, traffic model, and scenarios

- **State grid:** `v ∈ {0, 5, 50 (=baseline), 100, 200, 500}` tx/block;
  supply ratio `circulating/total ∈ {0.1, 0.5, 0.9}`; chain age (for `σ`)
  `∈ {0, 1, 4, 12, 30}` years; medians `M ∈ {Zm=300000, 3·Zm, 10·Zm, 50·Zm}`
  bytes with `Mnw = Mlw` except a registered spot-check of `Mnw = 50·Mlw`;
  reward regime: pre-tail per the emission curve at the given supply ratio,
  plus the tail (`final_subsidy_per_minute = 0.3 SKL/min`).
- **Consistency constraint:** supply ratio and chain age are coupled through
  the emission curve (τ ≈ 8 years); grid points violating the coupling by
  more than the release/burn modulation can move it are marked unreachable
  and excluded — with the exclusion listed, not silent.
- **Traffic model (tier usage):** floor 50% / middle 40% / top 10% of
  transactions, with sensitivity re-runs at (70/25/5) and (33/33/33). For a
  ladder with a different rung count the shares collapse proportionally
  (registered rule: adjacent shares merge when a rung is removed).
- **Dwell scenarios:** stationary Poisson per-block tx counts at each grid
  `v`; ramp `v: 50 → 200` linearly over 720 blocks; supply ratio and `σ`
  quasi-static (their per-day drift is orders slower than volume's, which
  the instrument must confirm, not assume).
- **Degenerate cases (FL-C8, must be pinned, not sampled by accident):**
  `b` at its 0.9 cap; `M_r` at both rails; tail-emission reward; and the
  supply-headroom clamp `shekyl_cap_reward_to_remaining_supply`
  (`cryptonote_basic_impl.cpp:169-173`) binding — when the cap binds,
  marginal penalty is absorbed by the clamp and expansion is locally free;
  the round must state whether that state is reachable and what the estimate
  does there.

### §1.9 Registered instrument

A module in `rust/shekyl-economics-sim` (extending the existing sim per the
drift-pair ban) that calls the **canonical** `shekyl-economics` functions —
`calc_burn_pct`, `calc_release_multiplier`, `calc_effective_emission_share`,
and the KAT-pinned penalty via the crate's block-reward entry point — and
reimplements none of them. Hand arithmetic in this document is illustration;
the tables in §4 come from the instrument.

### §1.10 Decision table (registered)

| Result | Selection |
| --- | --- |
| FL-C2 coverage at FL-C3 spacing needs 2 rungs, all pass FL-C4(b) | 2 rungs |
| needs 3 | 3 rungs |
| needs 4 | 4 rungs |
| needs 5 | 5 rungs |
| cannot be done in ≤ 5 rungs at `r ≤ 10` | FL-C1 exception: present continuous-vs-discrete conflict unresolved |
| `max C / min C > r` | values are state-computed (FL-C5) |
| dwell < threshold after quantization remedy | surface in §8 |
| any rung usage < 5% | delete or rule emergency-lane, own §8 row |

---

## §2 Verification findings (pre-model; each anchored)

### FL-V1 — Validation uses the modulated reward; the estimate does not — premise (2) STANDS

- Block validation (`validate_miner_transaction`,
  `blockchain.cpp:1789`) calls the **six-argument** `get_block_reward` with
  `tx_volume_avg`; the overload (`cryptonote_basic_impl.cpp:148-172`)
  applies `shekyl_calc_release_multiplier` + `shekyl_apply_release_multiplier`
  to the already-penalized reward, then the supply-headroom cap.
- Both fee-estimate paths call the **five-argument** (unmodulated) overload:
  `blockchain.cpp:4448` (`get_current_fee_per_byte`) and
  `blockchain.cpp:4541` (`get_dynamic_base_fee_estimate_2021_scaling`).
- Additionally — a factor the brief did not list — the miner does not
  receive the whole modulated reward: `compute_emission_split`
  (`blockchain.cpp:1795-1798`, `src/shekyl/economics.h:95-116`) diverts
  `σ(t)` (15% at genesis, ×0.9/year) to the staker pool, and the split
  operand is the modulated reward (per the F-B1c block comment at
  `blockchain.cpp:6349-6365`), so the miner bears exactly `(1−σ)` of any
  penalty. The estimate knows nothing of this either.

### FL-V2 — The relay floor is an independent code path sharing the base formula; and it is relay-only, not block validity

- `check_fee` (`blockchain.cpp:4456-4471`) prices from
  `get_current_fee_per_byte` → `get_dynamic_base_fee`
  (`blockchain.cpp:4422-4437`): `0.95 · R · w_ref / median²` — algebraically
  ~0.95 · `Fl` but computed separately, with a *different median operand*
  (`min(weight_limit/2, long-term effective median)` vs the ladder's
  `Mfw = min(Mnw, Mlw)`), then a further 2% acceptance buffer.
- Callers: pool admission `tx_pool.cpp:250` — where the `kept_by_block ||`
  disjunct proves transactions arriving *in blocks* bypass the check — and
  the daemon submit re-gate `src/rpc/daemon_submit_ffi.cpp:823`. **The fee
  floor is relay/admission policy, not block validity.** Changing the ladder
  is therefore not a chain-splitting consensus change; but a floor/ladder
  divergence fragments mempools and dead-letters wallets (FL-V5), so the
  cutover is coordinated even though it is not rule-07 atomic.

### FL-V3 — Rung consumers: three of four rungs reachable; two unreconciled mappings; one dead fallback ladder

- `shekyl-engine-core` maps economy=`fees[0]`, standard=`fees[1]`,
  priority=`fees[3]`, deliberately skipping index 2
  (`rust/shekyl-engine-core/src/engine/fee_policy.rs:429-433`).
- `shekyl-rpc-client` carries the wallet2-transliterated mapping
  (`rust/shekyl-rpc-client/src/lib.rs:454-465`): `fee_priority ≥ 4 → 3`,
  else `priority−1`, so **index 2 is reachable only via
  `FeePriority::Elevated` (=3)** — which has **zero production callers**:
  none in the workspace, and the out-of-workspace GUI consumer uses only
  `FeePriority::Standard`
  (`shekyl-gui-wallet/src-tauri/src/engine_session.rs:707,771`). `Fm` is
  wire-served and dead.
- The `fees:None` fallback ladder `[1, 5, 25, 1000]`
  (`lib.rs:471-486`) services a daemon shape that cannot occur on this
  chain (`HF_VERSION_2021_SCALING = 1` from genesis; the daemon always
  populates `fees`). Dead code, rule-60 class; disposition row in §8.
- The two mappings have **not** been unified since the brief was written.

### FL-V4 — `FrozenSegmentCount` drops out of the miner's calculus (a brief-listed state variable collapses)

`staker_pool_share` (and its D2 escalation input `FrozenSegmentCount`)
splits the **burned** amount between destruction and the staker pool;
`miner_fee_income = total_fees − burned_amount` in either case
(`rust/shekyl-economics/src/burn.rs:110-124`). The miner's marginal fee
income depends on `b` only. The D2 escalation cannot move any rung.

### FL-V5 — The relay-floor collision (consequence of V1 + V2, direction that bites)

On a young, quiet chain: `σ = 0.15`, `M_r = 0.8` (floor), `b ≈ 0` ⇒
`C = 0.85 × 0.8 = 0.68`. A corrected floor rung `0.68·Fl` sits **below**
the relay floor `≈ 0.95·Fl × 0.98 ≈ 0.93·Fl`: every corrected-economy
transaction would bounce at `tx_pool.cpp:250` and
`daemon_submit_ffi.cpp:823`. Any ruling that lowers `fees[0]` must resolve
FL-C6 explicitly. (Bound is hand-derived; the instrument re-derives it.)

### FL-V6 — Scaling-test pins are hypothetical-state, not genesis-state

`tests/unit_tests/scaling_2021.cpp:88-119` pins the ladder at a
**10 SKL reward** across three median states (340/1400/5400/67000 at
`Mnw=Mlw=Zm`; 22000 top with `Mnw=15,000,000`; 13/53/1100/14000 at
`Mnw=Mlw=1,500,000`). Genesis conditions are ~2048 SKL reward at `M=Zm`,
whose daemon-rounded `Fh` = 14,000,000 is the KAT-pinned wallet cap
(`fee_policy.rs:23-27`). The two "14000"-shaped numbers are different
states; citations must not conflate them.

---

### FL-V7 — User-facing docs promise perpetual tail emission; the consensus arithmetic ends it (escalated finding, minted 2026-09-03 at steering review)

The §4.6 exhaustion pin refutes a headline monetary-policy claim made to
users, three times:

- `docs/ECONOMY_EXPLAINED.md:35-36` — "floored at a **perpetual** tail of
  0.6 coins/block"; `:49-50` — "the 0.6-coin tail preventing the 'zero
  subsidy' security cliff **forever**."
- `docs/DESIGN_CONCEPTS.md:162` — "Ensures **perpetual** security budget";
  `:667` — "maintains **perpetual** security incentives through tail
  emission."

What consensus does (verified §4.6, independently re-derived at steering):
the supply-headroom cap (`cryptonote_basic_impl.cpp:169-173`,
`shekyl_cap_reward_to_remaining_supply` — added *deliberately*, with a
comment fixing the underflow that used to disable it) zeroes the
validation reward once `already_generated_coins` reaches `money_supply`.
Tail-era headroom is exactly `tail·2^esf`, so the tail lasts exactly
`2^21 = 2 097 152` blocks (~8 years) and then emission is zero, permanently.
"Perpetual tail" and "hard supply cap" are mutually exclusive commitments;
the code chose the cap, the explainers promise the tail —
`ECONOMY_EXPLAINED.md` states the `>> 21` decay, the cap, *and* the
"forever" claim in the same section. The cited precedent does not
transfer: Monero's tail is perpetual because Monero's supply is uncapped
(`DESIGN_CONCEPTS.md:544`).

**Not fixed in this round, with the blocker named (rule 22):** the fix
direction is a monetary-policy ratification, not a text edit — either the
docs change to "a tail era of exactly 2²¹ blocks, then the fee era," or
the cap semantics change to make the tail perpetual. Editing the docs
first would presume the answer to a genesis-freeze-sensitive question.
Decision row FL-R12; distinct from FL-D1 (which is the *design gap* —
what governs block size once the reward is zero — and stands regardless
of which way FL-R12 goes, though a perpetual-tail ruling would shrink
it). Class note for the program: this is the negative-space failure from
a third direction — a claim nowhere checked against the thing it
describes, found only because a derivation round happened to compute the
quantity the prose asserts.

## §3 The model

**Which reward the derivation prices against — stated because every number
below depends on it:** the **validation path** — the quantities consensus
actually pays the miner — not the estimate path. The estimate path is
FL-V1's defect; an instrument that derived against it would iterate its own
subject and come out self-consistent with the broken input. The
estimate/validation gap is therefore a measured *output* below, never an
assumption.

### §3.1 The miner's marginal calculus (each term anchored)

A miner deciding whether to include `w` extra bytes beyond the effective
median `M` at fee rate `f`, at expansion `x = (B−M)/M ∈ (0, 1]`:

- **Marginal gain:** `(1−b)·f·w`. The burn split is applied to the block's
  total fees at validation (`blockchain.cpp:1806-1808` →
  `compute_fee_burn`; `rust/shekyl-economics/src/burn.rs:110-124`); `b`
  depends on `tx_volume_avg` and supply ratio, not on the block's own
  contents, so the burn is linear in the marginal fee.
- **Marginal cost:** the penalty is applied to the base subsidy `R`
  (KAT-pinned quadratic, `emission.rs:142-190`: reward
  `= R·(1−x²)`), then the release multiplier scales the penalized value
  (`cryptonote_basic_impl.cpp:150-160`), then the supply cap, then the
  emission split takes `σ` off the top (`blockchain.cpp:1795-1798`). Away
  from the supply cap, the miner's marginal cost of expansion is
  `(1−σ)·M_r · dP`, with `dP/dbytes = 2Rx/M` (marginal) and the average
  cost over the whole expansion `Rx/M`.

Break-even (marginal): `(1−b)·f ≥ (1−σ)·M_r·2Rx/M`, i.e.

```text
f(x) = C · 2Rx/M        with C = (1−σ)·M_r/(1−b)
```

The inherited ladder computes `f` from `R` alone (`C ≡ 1` assumed). Since
every rung formula is linear in the reward, the corrected ladder is exactly
the inherited ladder times `C` — equivalently, the ArticMine formula run on
the miner-effective reward `(1−σ)·M_r·R` and divided by `(1−b)`.

### §3.2 What each inherited rung turns out to *be* (derived, not asserted)

Running the algebra through the folded integer expressions at
`blockchain.cpp:4488-4501` (instrument-verified against the C++ KATs,
`fee_ladder.rs` tests):

- **`Fl` = `R·w_ref/M²`** is the fee at which a single reference-weight
  transaction added to an exactly-median block pays its own penalty
  (`f·w = R·(w/M)²` at `w = w_ref`). A *self-funding admission* rung.
- **`Fn` = `4·Fl`** covers marginal expansion to `x = 2·w_ref/M` (average
  cost to `4·w_ref/M`). Both scale as **1/M²**.
- **`Fm` = `16·R·w_ref/(Zm·M)`** covers a **constant** expansion fraction —
  average cost to `x = 16·w_ref/Zm =` **16%** at every median. Scales as
  **1/M**.
- **`Fh`'s main arm ≡ `2R/M` exactly** (the folded `12.5·Fm` when
  `Mnw = Mfw`): the *marginal* cost of the very last byte before the
  2×median hard cap — i.e. full-expansion pricing with no approximation.
  The surge arm (`4·Fm`, active when the short-term median runs far above
  the long-term) covers marginal expansion only to `x = 32%`.

So the inherited ladder is **two families**: admission rungs (`Fl`, `Fn`,
∝ 1/M²) and expansion rungs (`Fm`, `Fh`, ∝ 1/M, constant-`x`). The gap
between the families grows linearly with the median — that is structure,
not accident, and §5 uses it.

### §3.3 State inputs — all daemon-local

`C` needs `tx_volume_avg` (already computed for validation at
`blockchain.cpp:1786`, definition at 2170), `already_generated_coins`, and
the height (for `σ`). The estimate paths already read the first two's
siblings. **Re-deriving rung values adds zero wire fields, zero new state,
and zero client changes.** Only rung *count* touches the wire (§7).

## §4 Instrument results

Instrument: `shekyl-economics-sim --fee-ladder` (`src/fee_ladder.rs`),
calling only canonical `shekyl-economics` functions for economics
quantities; its "current-ladder" comparison column is pinned against the
C++ oracle by four KATs (the three `scaling_2021.cpp` `wallet_fee_estimate`
triples, the `relay_fee` set, and the genesis-condition
`Fh = 14,000,000` the wallet cap is derived from). Full JSON is
reproducible from the module; headline numbers:

### §4.1 The correction surface (FL-C5 input)

`C` over the reachable §1.8 grid spans **[0.680, 12.92] — a 19× range**.
(The JSON's `c_reachable_min` prints 0.692: the age-0 grid *ratios* {0.1,
0.5, 0.9} are all unreachable — genesis sits at ratio ≈ 0 and enters the
measurement through the §4.2 rung tables, whose genesis-quiet row is the
0.680 endpoint.)
Extremes: genesis-quiet (`σ=0.15, M_r=0.8, b≈0`) → 0.680; old chain at 90%
supply ratio under congestion (`M_r=1.3, b=0.90, σ≈0.006`) → 12.92. Both
`M_r` and `b` saturate at their rails, so `C` is *constant* in the deep
extremes — the clamps bound the surface and kill its gradient exactly where
feedback pressure is highest.

**FL-C5 verdict: 19× ≫ any admissible rung ratio ⇒ rung values MUST be
state-computed daemon-side.** A static rescale is wrong by more than a
whole rung somewhere reachable.

### §4.2 Corrected vs current rung tables (extract)

| State | `C` | current (rounded) | corrected | floor-accept | floor bounce? |
| --- | --- | --- | --- | --- | --- |
| genesis-quiet (`v=0`) | 0.680 | 69 000 / 280 000 / 1 100 000 / 14 000 000 | 47 000 / 190 000 / 750 000 / 9 300 000 | 63 556 | **yes** |
| genesis-baseline (`v=50`) | 0.850 | same | 59 000 / 240 000 / 930 000 / 12 000 000 | 63 556 | **yes** |
| young-congested (1 y, `v=200`) | 1.275 | 61 000 / 250 000 / 970 000 / 13 000 000 | 77 000 / 310 000 / 1 300 000 / 16 000 000 | 56 071 | no |
| mature-quiet (12 y, `v=5`) | 0.874 | 16 000 / 61 000 / 250 000 / 3 100 000 | 14 000 / 54 000 / 220 000 / 2 700 000 | 14 129 | **yes** |
| mature-congested (12 y, `v=200`, `M=3·Zm`) | 5.60 | 1 700 / 6 800 / 81 000 / 1 100 000 | 9 500 / 38 000 / 460 000 / 5 700 000 | 1 570 | no |
| old-congested-wide (30 y, `v=500`, `M=10·Zm`) | 12.92 | 15 / 63 / 2 600 / 32 000 | 200 / 820 / 33 000 / 420 000 | 15 | no |

(These tables measure the *mispricing* and therefore apply raw `C`; the
values a §5.2 daemon would actually serve apply the quantized `C_q` and
differ by up to one pow2 step.)

Two regimes, both mispriced today, in opposite directions:

- **Quiet chain: the current ladder overprices ~1.2–1.5×** — and the honest
  corrected floor lands **below the relay floor** (FL-V5 confirmed in three
  of six states, mature-quiet included, not just young-chain). FL-C6
  disposition required (§5.4).
- **Congested mature chain: the current ladder underprices 5.6–12.9×.**
  A user paying today's top rung offers a rational miner as little as 8% of
  the actual cost of the expansion it is supposed to buy. This is the
  regime the ladder exists for, and it is where the transliteration is most
  wrong — the brief's premise (4), now measured.

### §4.3 Spacing and coverage of the inherited ladder (FL-C2/C3 input)

Average-cost `x` per rung and adjacent fee ratios (instrument `x_ladder`):

| `M` | `x(Fl)` | `x(Fn)` | `x(Fm)` | `x(Fh)` | ratios `Fn/Fl, Fm/Fn, Fh/Fm` |
| --- | --- | --- | --- | --- | --- |
| `Zm` | 1.0% | 4.0% | 16% | 200% | 4.0, 4.0, **12.5** |
| `3·Zm` | 0.33% | 1.3% | 16% | 200% | 4.0, **12.0**, 12.5 |
| `10·Zm` | 0.10% | 0.40% | 16% | 200% | 4.0, **40**, 12.5 |
| `50·Zm` | 0.02% | 0.08% | 16% | 200% | 4.0, **200**, 12.5 |
| surge (`Mnw=50·Mlw`) | 1.0% | 4.0% | 16% | **64%** | 4.0, 4.0, 4.0 |

- The inherited ladder **already violates FL-C3 everywhere**: the `Fm→Fh`
  gap is 12.5× at every median, and the inter-family `Fn→Fm` gap grows
  linearly with `M` (200× at 15 MB medians). Uniform-geometric spacing was
  never a property of this ladder.
- Mechanical FL-C2+C3 coverage arithmetic: floor-to-top span is 100× at
  `M=Zm` (needs ≥ 3 rungs at `r ≤ 10`), 10 000× at `50·Zm` (needs 5). So a
  strict reading of C2+C3 wants **4–5 rungs at large medians**, while FL-C4b
  (below) supports **3**. This is the round's registered conflict; §5.3
  resolves it on the record.
- **FL-C2(b) gap found:** in the surge state the top rung covers marginal
  expansion only to `x = 32%` — under exactly the short-term congestion
  spike where full expansion is the product being sold. The main arm is
  exact (`2R/M`); the surge discount is the defect. §5.2 removes it.

### §4.4 Dwell (FL-C4a)

Median blocks a posted rung value persists (20 000-block runs, Poisson
traffic, 720-block window; "current" is the churn baseline with medians and
reward held quasi-static, so it isolates the *marginal* churn `C` adds):

| Scenario | current | corrected, raw `C` | corrected, `C` quantized pow2 |
| --- | --- | --- | --- |
| stationary `v=5` | no change | no change | no change |
| stationary `v=50` | no change | **4–6 blocks, 252 distinct values** | no change (1 value) |
| stationary `v=200` | no change | **3 blocks, 356 distinct** | no change (1 value) |
| ramp `v: 50→200` | no change | 3–17 blocks | **2 values, one step** |

**Raw `C` fails FL-C4a catastrophically** — per-value anonymity cohorts of
3–6 blocks (~150–300 txs at baseline volume vs ~500 000 for a month-stable
value). **Pow2 quantization passes every scenario.** Two snap rules were
measured: the *registered* round-to-nearest (§1.4a) passes with one 2×
step on the 4× ramp; the *adopted* ceiling variant (`2^ceil(log2 C)`,
§5.2 — a post-registration refinement selected by the already-registered
FL-C2(b), because round-to-nearest under-funds the top rung's marginal
pricing by up to √2) passes with **zero** steps on the same ramp. The
register itself is not rewritten; this paragraph is the disclosure.
FL-C4a verdict: `C` enters the formula only as `C_q`. Residual risk: a
state sitting exactly on a pow2 boundary could flicker at 2× amplitude —
the registered scenarios did not exhibit it, and §7 carries a hysteresis
construction requirement with the dwell gate as its acceptance test.

### §4.5 Feedback (FL-C7)

Deterministic fee↔volume iteration (demand `v = v0·(f/f_ref)^(−ε)`,
`ε ∈ {0…3}`, starts at baseline and at 8× baseline): **converged to a fixed
point in every cell** — tail shows exactly one fee value, volume returned to
its demand-curve fixed point even from the 8× start. The 720-block window
plus fee rounding plus the rail clamps damp the loop; no hysteresis was
needed in the interior. (The instrument answers *stability*, not
equilibrium location — the demand model's fixed point is at baseline by
construction.) FL-C7: **pass**.

### §4.6 Degenerate pins (FL-C8)

- `b` cap and `M_r` rails confirmed on-grid (0.9 at `(v=500, ratio=0.9)`;
  0.8 at `v=0`; 1.3 by `v=100`).
- **Tail era:** entry headroom `tail·2^esf` = 1 258 291 200 000 000 atomic;
  the tail lasts exactly **2 097 152 blocks (~8 years)**, then the supply
  cap zeroes the *validation* reward permanently — Shekyl's mining era
  ends by construction.
- **At exhaustion, FL-V1's divergence reaches its terminal form:** the
  5-arg estimate path (no supply cap) still believes `R = 600 000 000` and
  serves the ladder **[20, 80, 320, 4000]**, while validation pays **0**
  and the true ladder is **[0, 0, 0, 0]**; the relay floor collapses to its
  hardcoded 1 atomic/byte. With `R = 0` the weight penalty prices nothing:
  expansion to the 2×median cap is free every block, and block-size
  governance rests on the 1.7×/window long-term clamp plus a 1-atomic
  floor. **Post-mining-era block-size governance has no economic mechanism
  at all.** Out of this round's scope to fix; deferred with reopen criteria
  (§9, FL-D1) — but the corrected estimate at least stops quoting fees from
  a reward that no longer exists. This pin also refutes the user-facing
  "perpetual tail" claims — escalated separately as **FL-V7** with its own
  decision row (FL-R12), because a false monetary-policy promise and a
  missing governance mechanism need different owners and different urgency.

## §5 The rung ruling (proposed, unsigned) and the anonymity analysis

### §5.1 Criteria disposition

| Criterion | Verdict | Where |
| --- | --- | --- |
| FL-C1 continuous | **rejected** — never triggered: discrete ladders satisfy the registered set; the exception clause stays unfired | §4.3 |
| FL-C2 coverage | met by floor + `2R/M` top; **surge arm fails C2(b)** → fixed in §5.2 | §4.3 |
| FL-C3 spacing ≤ 10× | **conflict with C4b** — registered outcome, resolved on the record in §5.3 | §4.3 |
| FL-C4a dwell | raw `C` fails; **pow2-quantized `C_q` passes all scenarios** → adopted | §4.4 |
| FL-C4b usage floor | `Fm` at **0% measured production usage** (FL-V3) → **delete** (emergency-lane branch examined and rejected: an emergency lane nobody was using marks the first user who ever touches it) | §5.3 |
| FL-C4c count | **3** | §5.3 |
| FL-C5 static vs state | **state-computed** (19× ≫ r) | §4.1 |
| FL-C6 relay floor | **clamp** (option i), floor re-derivation deferred to CEN-M3's round | §5.4 |
| FL-C7 feedback | pass, no smoothing needed beyond `C_q` | §4.5 |
| FL-C8 degenerates | pinned; exhaustion-era governance deferred FL-D1 | §4.6 |

### §5.2 The proposed ladder

Three rungs, values computed by the daemon at estimate time from state it
already holds, with `C_q = 2^ceil(log2((1−σ)·M_r/(1−b)))` (ceiling, not
the registered round-to-nearest — the §4.4 disclosure: ceiling never
under-funds marginal pricing, overprices ≤ 2× which is inside FL-C3, and
re-passed the full dwell gate):

```text
fees[0]  economy   = max( round_up2( C_q · R·w_ref/Mfw² ),  relay_floor )
fees[1]  standard  =      round_up2( C_q · 4·R·w_ref/Mfw² )
fees[2]  priority  =      round_up2( C_q · 2·R/Mfw )
```

`relay_floor` is the **unbuffered** `check_fee` operand (`0.95·R·w_ref/M²`,
the `blockchain.h:682` seam) — clamping to the post-2%-buffer acceptance
edge would spend the entire buffer that exists to absorb estimate→admission
state drift.

- `R` = the 5-arg base subsidy (unmodulated) — `C_q` carries the modulation;
  `Mfw = min(Mnw, Mlw)` and the grace-block median machinery are unchanged.
- **economy** keeps `Fl`'s derived meaning (single-reference-tx
  self-funding admission), clamped per §5.4.
- **standard** keeps `Fn = 4·Fl` (admission family; the 4× spacing to
  economy is constant at every median).
- **priority** is the inherited `Fh` **main arm made unconditional** —
  exact marginal-cost pricing of expansion to the 2×median cap, with the
  surge discount removed (fixes the FL-C2(b) gap: full expansion is now
  funded in every state, surge included).
- `Fm` is **deleted** (FL-C4b: zero production consumers — FL-V3).

If the honest-outcome clause of the brief is asked of this: the inherited
ladder was **approximately right in structure** (two families, both
derivable from Shekyl's own penalty function — and the `Fh` main arm turns
out to be *exact*), **wrong in values across the whole state space**
(0.68×–12.9×), **wrong in one arm** (surge), and **one rung heavy**. That
conclusion is now derived rather than inherited.

### §5.3 The registered conflict, resolved on the record (FL-C3 vs FL-C4b)

The economics arithmetic (C2+C3, §4.3) wants 4–5 rungs at large medians;
the anonymity criterion supports 3 and zeroes one existing rung. The two
disagree; per §1 the resolution is argued, not smoothed:

**Resolution: privacy wins; 3 rungs; the C3 uniform-spacing premise is
named as misfitting a two-family ladder.**

1. Privacy is lexicographically prior. A rung's cost is paid by *every*
   transaction in the anonymity set it splits, forever; the overpayment C3
   bounds is paid only by a user whose need falls between rungs, once,
   voluntarily, and capped: a user needing `Fm`'s 16% who now pays the
   `2R/M` top overpays **12.5×** — exactly the `Fh/Fm` gap the inherited
   ladder already carries at every median (§4.3), and constant across
   medians because both rungs are 1/M-family. Deleting `Fm` does not
   *create* a C3 violation; it inherits the 12.5× one the ladder always
   had, confines its marginal cost to needs in the 16%-neighborhood, and
   those needs are borne today by **zero measured users** (FL-V3). Needs
   *between* the standard rung's `x` and 16% cross the inter-family seam
   and overpay up to `M/(2·w_ref)` — with or without `Fm`; the deletion
   does not change that side.
2. The rungs C3 would insert have no users to protect: the traffic model
   assigns them < 5%, and the one intermediate rung that existed measured
   **0%** in production for its entire life (FL-V3). C4b would delete them
   right back.
3. The scary C3 numbers (`Fn→Fm` = 200×) are *inter-family* gaps: they
   compare an admission price to an expansion price, which diverge as 1/M²
   vs 1/M by construction (§3.2). Uniform-geometric spacing across that
   seam is not achievable with any finite rung count — the criterion's
   premise (one geometric family) does not describe this object. The
   *intra-family* spacings of the proposed ladder are 4× (admission,
   within C3's bound) and 12.5× worst-case overpayment on the expansion
   side — the inherited `Fh/Fm` gap, above C3's bound and resolved for
   privacy per point 1.
4. The losing branch, recorded: 4 rungs re-spaced uniform-geometric
   (`r = 5.85` over 1%–200% at `Zm`) satisfies C3 at minimum zone only,
   re-breaks at 10·Zm (`r = 12.6`), and staffs its extra rung with nobody —
   inheriting exactly the dead-`Fm` position this round is deleting.

### §5.4 Relay-floor disposition (FL-C6)

Adopted (proposal): **clamp** — `fees[0] = max(corrected economy,
unbuffered relay floor)`, the floor read from the same seam `check_fee`
prices from (`blockchain.h:682`), *not* the post-2%-buffer acceptance
edge: serving the edge would spend the whole buffer that exists to absorb
estimate→admission state drift. Rationale: the clamp is correct
*unconditionally* — whatever
the floor is ruled to be later, serving an estimate below it dead-letters
wallets (FL-V5, three of six states). Re-deriving the floor itself (scaling
`get_dynamic_base_fee` by `C_q`, principled endpoint) **is CEN-M3's row**
and is held for the §0.1 sequencing decision; deferral FL-D2 carries the
reopen criteria. Until then the floor stays a lower bound the estimate
respects, and the quiet-chain overpricing that survives the clamp is
bounded by the measured 1.5× worst case.

## §6 Wargame

| # | Adversary / actor | Move | Outcome under current ladder | Outcome under proposed ladder | Defence / residual |
| --- | --- | --- | --- | --- | --- |
| W1 | Miner who ignores the ladder and mines only the penalty-free zone | Refuses all expansion regardless of fees | Individually rational whenever `C > 1` (fees at the served ladder genuinely don't cover cost — measured 5.6–12.9× short in congestion): congestion persists *because* the ladder lies | Forgoes real profit: corrected rungs actually clear the miner's cost, so a refusing miner cedes fee income to competitors; expansion market functions | The ladder is an offer curve; no defence needed beyond pricing it honestly |
| W2 | User pays the top rung, gets no expansion | Buys priority during mature-chain congestion | **Real and measured**: top rung offers as little as 8% of the miner's cost; rational miners take queue-jumping money and never expand; the product sold does not exist | Top rung = exact marginal cost of full expansion in every state incl. surge (§5.2); a rational miner expands | Residual: collusive non-expansion cartel is a mining-cartel question (out of scope, unchanged by this round) |
| W3 | Fee-fingerprint adversary (links txs / identifies wallet software by fee values) | Reads the public fee field | 4 static-formula values; but any wallet deviating from daemon values is marked (unchanged) | 3 values; `C_q` is a deterministic function of public chain state, so all conforming wallets at a height agree; measured dwell with `C_q`: no value change over 20 000 blocks stationary, one step per 4× volume ramp — sets of ~10⁵ txs/rung-value vs ~150–300 for raw `C` | Raw `C` was the hazard and is rejected by FL-C4a; custom-fee users remain self-marked (pre-existing, out of scope) |
| W4 | `tx_volume` manipulator (moves `b` and `M_r`) | Self-trades to raise `tx_volume_avg` | Same lever exists and *worsens* mispricing (raises `M_r` 1.3× while ladder ignores it) | Manipulation is at least priced consistently: raising `v` raises `C_q` for everyone including the adversary; pow2 plateaus mean small manipulations usually move nothing | Cost: burn share of every spam fee is destroyed; young chain (`b≈0`) self-mining spam is near-free — but that is the release-multiplier's own emission surface (economics lane, unchanged by this round); the ladder correction adds no new profit path for it |
| W5 | Exhaustion-era spammer (post-mining-era, `R = 0`) | Expands every block to the 2× cap for free | Estimate quotes fees from a reward that no longer exists ([20,80,320,4000] vs true [0,0,0,0]); penalty prices nothing; growth governed only by the 1.7×/window clamp and a 1-atomic floor | Corrected estimate at least reports the truth (zero); the governance gap itself remains | **Open hazard, deferred FL-D1** — post-mining-era block-size governance has no economic mechanism; reopen criteria §9 |
| W6 | Quiet-chain wallet (honest) | Pays served economy rung | Overpays ~1.2–1.5×, or — if the ladder were naively corrected without FL-C6 — bounces off the relay floor entirely (three of six states) | Clamp guarantees relayability; overpayment bounded at measured 1.5× worst case until CEN-M3 re-derives the floor | FL-D2 |

## §7 What changes downstream (proposals with triggers — RK-5 lane untouched)

| Surface | Change | Wire? | Trigger |
| --- | --- | --- | --- |
| `get_dynamic_base_fee_estimate_2021_scaling` (daemon) | compute `C_q` from `tx_volume_avg`/`ag`/height (all already daemon-local), scale rungs, drop `Fm`, make the `Fh` main arm unconditional, clamp `fees[0]` | **No** (values only) | §8 signature; independent of RK-5 |
| `fees` vector length 4 → 3 | wire shape change; both client mappings touch it | **Yes** | **post-RK-5 cutover completion only.** Bridge option if value-correction ships first: keep 4 slots with `fees[2] = fees[1]` (dead index served the *standard* value — its only reachable callers are wallet2-transliterated `Elevated`, keeping them inside the largest set) |
| `CORE_RPC_VERSION` | minor bump with the vector change | Yes | with the row above |
| `shekyl-engine-core` `fee_policy.rs` mapping | 0/1/3 → 0/1/2 | No | with the vector change |
| `shekyl-rpc-client` | unify to the engine mapping; **delete** the dead `[1, 5, 25, 1000]` fallback ladder (`lib.rs:471-486`, impossible daemon shape, rule 60) | No | fallback deletion any time; mapping with the vector change |
| `fee_policy.rs` absolute cap | `Fh` moves ⇒ the KAT-pinned 14 000 000 genesis-condition cap is re-derived as the swept maximum of the **served** (`C_q`) top rung over the reachable young-chain grid; §4.2's raw-`C` young-congested 16 000 000 is a lower-bound anchor only; exact value pinned by KAT in the implementing PR | No | with the daemon value change |
| `check_fee` / `get_dynamic_base_fee` | **unchanged** this round (clamp absorbs the collision); re-derivation is CEN-M3's | — | FL-D2 |
| Hysteresis construction requirement | implementation must not flicker at a pow2 boundary: enter a new `C_q` step only when `C` crosses the boundary by a margin; the §4.4 dwell scenarios are the acceptance gate | No | implementing PR |

## §8 Ratification table — **UNSIGNED**; census-sequencing hold per §0.1

Rows marked ⚖ are CEN-R2-shaped and are *proposals held* for the
sequencing decision; nothing in this table is ruled by this document.

| # | Decision | Proposed disposition | Census hold |
| --- | --- | --- | --- |
| FL-R1 | The ladder derives from the validation-path miner economics (`C = (1−σ)·M_r/(1−b)`), not the 5-arg estimate reward | adopt | ⚖ (F14b-adjacent) |
| FL-R2 | Rung values are state-computed daemon-side each estimate | adopt | |
| FL-R3 | `C` enters only pow2-quantized (`C_q`), hysteresis-guarded | adopt | |
| FL-R4 | Rung count = 3; `Fm` deleted; FL-C3-vs-C4b conflict resolved for privacy per §5.3 | adopt | |
| FL-R5 | Top rung = `C_q·2R/Mfw` unconditional (surge discount removed) | adopt | |
| FL-R6 | `fees[0]` clamped to the unbuffered relay floor (`blockchain.h:682` seam) | adopt | ⚖ CEN-M3 |
| FL-R7 | Wire shape (vector 3), `CORE_RPC_VERSION`, both client mappings | adopt **post-RK-5**; bridge = duplicate `fees[2]=fees[1]` | |
| FL-R8 | Dead rpc-client fallback ladder deleted | adopt | |
| FL-R9 | Wallet absolute cap re-derived as the swept maximum of the *served* (`C_q`) top rung over the reachable young-chain grid, pinned by KAT in the implementing PR (§4.2's raw-`C` 16 000 000 is a lower-bound anchor, not the value) | adopt | |
| FL-R10 | FL-V1 recorded as a standing defect independent of this ladder (estimate/validation reward divergence, terminal form §4.6) | record | ⚖ (F14b evidence) |
| FL-R11 | The G6b fossil-flag punt is discharged **for the fee constants only**: this round derives the ladder *given* the 300 000-byte zone; the zone value itself and the 1.7×/×50 clamps remain underived | record | ⚖ CEN-G6b |
| FL-R12 | **Perpetual tail vs supply cap (FL-V7)**: rule which commitment is intended — (a) docs corrected to the ~8-year tail era the code implements, or (b) cap semantics changed to deliver the promised perpetual tail. Genesis-freeze-sensitive; the losing text (four instances across `ECONOMY_EXPLAINED.md` / `DESIGN_CONCEPTS.md`, enumerated in FL-V7) is fixed by whichever side wins, in that PR | **decision required — neither presumed** | escalated via steering 2026-09-03 |

Signature line (empty by design): ________________

## §9 Deferrals — each with rule-21 reopen criteria

| # | Deferred | Named blocker | Reopen when |
| --- | --- | --- | --- |
| FL-D1 | Post-mining-era block-size governance (`R = 0` ⇒ penalty prices nothing; §4.6) | Bigger than the fee surface: needs the end-of-mining-era economics round the mission hierarchy already names as an evaluation horizon | (a) any round touches tail-era or post-exhaustion economics, or (b) the V4 lattice-only transition round opens, whichever first — the ladder holder then owes this row an answer |
| FL-D2 | Relay-floor re-derivation (scale `get_dynamic_base_fee` by `C_q`) | CEN-M3 is a queued census-R2 row; ruling it here would create the double-ratification §0.1 forbids | the §0.1 sequencing decision lands; or CEN-M3's round opens; or the clamp is observed binding in > 50% of mainnet estimate calls over a 30-day window (evidence the floor, not the ladder, is setting prices) |
| FL-D3 | A fourth tier, if UX ever wants one | No engine tier addresses one (FL-V3: `Elevated` has zero production callers); a rung without users is fingerprint surface | an engine/GUI round proposes a user-facing tier with a predicted ≥ 5% usage share under FL-C4b's test |
| FL-D4 | Zone value (300 000) and the 1.7×/×50 clamps | CEN-G6b/G6 own them; this round consumed them as boundary (§1.8) | census-R2 runs; FL-R11 records the partial discharge so R2 inherits a smaller question |

---

*Round instrument: `rust/shekyl-economics-sim/src/fee_ladder.rs`
(`--fee-ladder`). Pre-registration commit precedes the instrument in this
branch's history — that ordering is the rule-11 register, stated here so a
later reader sees method, not accident.*
