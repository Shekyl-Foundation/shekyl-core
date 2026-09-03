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

## §3 Model (placeholder — filled by the instrument after §1 was committed)

## §4 Derivation and results (placeholder)

## §5 Rung ruling and anonymity analysis (placeholder)

## §6 Wargame (placeholder)

## §7 Downstream changes (placeholder)

## §8 Ratification table (placeholder, will be unsigned)

## §9 Deferrals and rule-21 reopen criteria (placeholder)
