# FL — Fee Ladder Derivation from Shekyl Miner Economics

**Status:** OPEN — round RULED, implementation in flight. §8 now carries
**FL-R12′ and FL-R17 SIGNED and FL-R14 RULED** (in-channel, provenance
per-row); the remaining rows hold their marked states, and rows marked
BUILT refer to the round-9 implementation branches
(`feat/fee-ladder-impl-1`/`-impl-2`), which follow this document's merge
as their own PRs — **no consensus behavior changes in this PR**. The RK-5
RPC migration lane is explicitly out of scope: every wire-shaped
consequence in §7 carries a named trigger and is a proposal, not a
change.

Identifier family: `FL-*` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) at birth, rule 94).
Convention, because the family token is one case-flip from a rung symbol:
rung symbols always appear backticked as `Fl` / `Fn` / `Fm` / `Fh`; family
tokens are always `FL-` followed by a digit or section letter.

Branch: `design/fee-ladder-derivation` (worktree, off `dev`). `file:line`
anchors in §1–§9 are at `dev` = 6d2f49a5c unless stated; FL-V8…FL-V11
(minted at review round 2) are anchored at the merge with `dev` =
a566a466. Round-state record: [`FEE_LADDER_ROUND.md`](FEE_LADDER_ROUND.md).

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

**Sequencing was Rick's decision, put to him by the umbrella lane:** either
`FL-*` is registered as the substance of C2-R2 (and §8's signatures
disposition those census rows), or FL runs separately and R2's fee rows are
dispositioned by pointing at FL's ruling. Until that answer the round
**held at the design-doc stage** — §8 unsigned, no CEN-M3 / CEN-F14b /
CEN-G6b-shaped question ruled here — with derivation, findings, and the
then-unsigned table proceeding as inputs to whichever sequencing won, not
rulings. The ruling below ended that hold.

**Sequencing ruled at review round 2 (maintainer, 2026-09-03): census-R2
is deferred, not silently.** FL-V8/FL-V9 are consensus-surface,
genesis-frozen, and pre-genesis-cheap; they jump the R2 queue. Rule-21
reopen criterion for the R2 deferral, as ruled: **R2 resumes when (a) the
emission terminal-state ruling (FL-R12′) is signed in §8, and (b)
`projected_already_generated` has a red test at the exhaustion
boundary.** Conjunct (b) is discharged as of review round 2 and, since
review round 3, literally: `terminal_reward_legs_agree` lives in
`shekyl-economics`' `emission.rs` tests and asserts the projection leg —
`projected_already_generated` by name — against validation past the
exhaustion height (FL-V10). Conjunct (a) — the FL-R12′ signature — was
**OPEN from review round 4** (an earlier revision recorded it as ruled on
a steering relay that round could not verify; the signature then waited
on the F-1 pre-/post-multiplier amendment) **until review round 8, when
FL-R12′ was SIGNED with the amendment adopted** (§8, provenance per-row).
**Both conjuncts are therefore SATISFIED and census-R2 is unblocked** per
its own criterion; the resumption routes through the consensus lane
(C2-R0 phase 2, which edits `CONSENSUS_RULE_CENSUS.md` §10), and
`FEE_LADDER_ROUND.md`'s pending list records the satisfaction. The red
oracle asserts the *amended* contract (paid reward = `TAIL`,
rail-independent, asserted against the shipped composition) and stays
red on this branch; it is graduated green through the one owner on
`feat/fee-ladder-impl-1`.

## §1 Pre-registered decision criteria (the brief's pre-registration mandate)

**Registered before any model output exists.** The instrument (§1.9) had not
been written when this section was committed; commit history is the
register.

**Taint disclosure (pre-registration discipline, disclosed rather than laundered).** (The round brief cites this mandate as "rule 11"; no `.cursor/rules/11-*` exists — the binding source is the brief's own Standing-discipline section, and this doc cites it as such.)
Before this registration, the round performed the mandated verifications
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

**Post-registration correction (PR #614 review; the registered line above
is kept, not rewritten — the register is committed history):** the line
inverts the repository's canonical hierarchy.
[`00-mission`](../../.cursor/rules/00-mission.mdc) makes **security &
quantum resilience the precondition** and privacy second ("privacy is the
product"), and declares that ordering the single source of truth; where
this document and the rule disagree, the rule wins. Audit of every place
the registered order was invoked — §1.1 FL-C1 (continuous schedules
rejected on privacy), §1.11 FL-C9 (the anchored-reduction criterion), and
§5.3's "privacy is lexicographically prior" resolution (rung count,
re-applied at FL-R17) — shows each adjudicated conflict was
**privacy-vs-economics**, a pair 00-mission resolves the same way this
round did (privacy is the product; ladder economics is not a security
precondition). No disposition in this document resolved a
privacy-vs-security conflict, so none is contaminated by the inversion;
any future round that meets that pair takes 00-mission's order.

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
  (`cryptonote_basic_impl.cpp:168`) binding — when the cap binds,
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

### §1.11 FL-C9 — fee signal bits (POST-REGISTRATION: minted at maintainer direction, review round 5, after measurement began)

Birth stamp carried per the ceil-quantization precedent — and stated as
a **class distinction, not just a timestamp**: what pre-registration buys
is that a criterion could not have been fitted to a result. **C1–C8 were
fixed before any result existed; C9 was minted post-registration, on a
measurement** — it exists because review round 5 found the register's
privacy criteria stopped one rung early, and its weight is assessed
accordingly (the number is real and plainly bears on the decision; the
criterion could not have predicted it). Definition — **re-labeled at review round 6, at the maintainer's own
correction, to the honest attack model**: FL-C9 is the **anchored-attack
candidate-set reduction**, not "signal bits as if the chain leaked
identity." FCMP++ puts no linkage primitive on the wire (no addresses,
no ring members; key images reveal only double-spends) — nothing
on-chain says two transactions share an author; *that is the design
working*. The attack that exists: acquire an anchor **off-chain**
(a merchant paid at time T, a KYC'd exchange withdrawal, a
Dandelion++/Tor timing observation, a compromised submission path), take
the height window around T, and filter by every public field. The fee
rung's contribution is a multiplier of ≈ `1/usage_share(rung)` on that
one transaction's candidate set, **applied once per anchored
transaction** — this folds back into FL-C4's registered framing (the set
over `(rung, weight bucket, height window)`), which was the right one
all along. Conditioned on the registered §4.4 dwell measurements (the
stale-quote term is ≈ 0 under ceiling-`C_q`). Measured in §4.7; consumed
by FL-R17.

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
users, four times:

- `docs/ECONOMY_EXPLAINED.md:35-36` — "floored at a **perpetual** tail of
  0.6 coins/block"; `:49-50` — "the 0.6-coin tail preventing the 'zero
  subsidy' security cliff **forever**."
- `docs/DESIGN_CONCEPTS.md:162` — "Ensures **perpetual** security budget";
  `:667` — "maintains **perpetual** security incentives through tail
  emission."

**Restated at review round 2 (maintainer ruling, 2026-09-03).** An
earlier draft led with the doc-vs-doc contradiction (`:18` fixed supply
vs `:35` "perpetual") and demoted the code to "supplying only the date" —
optimizing for a finding undisputable-by-disputing-the-instrument. That
was the wrong objective function: a doc-vs-doc contradiction is a prose
bug, and the demotion buried the code defect where the real severity
lives. Correct statement:

- **`:35`'s formula description is implemented faithfully** —
  `(remaining_supply >> 21)` floored at 0.6/block *is*
  `base_block_reward` (`emission.rs:52-67`); only the word "perpetual"
  overreaches. `:18`'s fixed supply is faithful too.
- **The refuted line is `:49-50`** — "the 0.6-coin tail preventing the
  'zero subsidy' security cliff **forever**." The instrument of
  refutation is the code itself, **FL-V8 below**: the validation path
  composes the tail floor with a supply cap that zeroes the reward at
  exhaustion, so the cliff arrives at ≈ block 19 158 412 (~year 73) —
  exactly where the doc promises it cannot.
- The tail-era length is an **identity, not a measurement**: the tail
  engages when `remaining < tail·2^esf`, so `remaining/tail = 2^esf =
  2²¹` blocks exactly. (Tail entry ≈ block 17 061 260, ~year 65; the
  ±1 against any independently quoted height is a fencepost convention,
  not a disagreement.)
- The cited precedent does not transfer: Monero's tail is perpetual
  because Monero's supply cap is unreachable
  (`DESIGN_CONCEPTS.md:544`).

**Not fixed in this round, with the blocker named (rule 22):** the fix
direction is a monetary-policy ratification, not a text edit — and FL-V8
shows the code itself has not taken one side. Decision row FL-R12′;
distinct from FL-D1 (the *design gap* — what governs block size once the
reward is zero — which stands regardless of the ruling, though a
perpetual-tail ruling would shrink it). Class note for the program: the
negative-space failure from a third direction — a claim nowhere checked
against the thing it describes, found only because a derivation round
happened to compute the quantity the prose asserts.

### FL-V8 — The two supply clamps encode opposite terminal policies, and both are live (review round 2; anchors at a566a466)

The FFI calls them twins (`rust/shekyl-ffi/src/legacy_core.rs:585`, "the
emission-side twin of `shekyl_advance_already_generated`"). They are not
twins:

- **`blockchain.cpp:6420`** advances the supply accumulator through
  `shekyl_advance_already_generated`, saturating at `money_supply`. The
  rationale directly above it (`:6410-6413`) is inherited Monero prose
  verbatim: *"MONEY_SUPPLY yields a subsidy of 0 under the base formula
  and therefore the minimum subsidy >0 in the tail state"* — i.e. **pay
  the tail forever**. Precision matters for whoever fixes this: the
  comment's *local* claim about the base formula is **true** (at
  `A = S`, `base_block_reward` returns the tail); what is false is the
  policy conclusion, because the comment predates the capped composition
  below. In Monero the premise holds because `MONEY_SUPPLY = 2⁶⁴−1` is
  unreachable; here it is reached at ≈ block 19 158 412. Rule 16: the
  inherited rationale is still sitting in the comment.
- **`cryptonote_basic_impl.cpp:168`** clips the validation reward through
  `shekyl_cap_reward_to_remaining_supply` to `money_supply −
  already_generated` — **pay nothing** once the accumulator saturates.

One component says tail-forever, the other says cap-to-zero, and both
ship on the consensus surface. The earlier FL-V7 draft's "the code took
the cap side" was wrong as stated: the *validation composition*
behaviorally ends at zero, but the codebase as a whole has not taken one
side — which is exactly why FL-R12 was malformed as originally posed.

### FL-V9 — The supply cap is gated on an unrelated feature flag (review round 2)

`cryptonote_basic_impl.cpp:153` wraps **both** the release multiplier and
the supply cap in `if (SHEKYL_TX_VOLUME_BASELINE > 0)`. Setting the
demand-pacing baseline to 0 silently flips terminal emission policy from
cap-to-zero back to tail-forever. A genesis-frozen supply rule must not
be reachable through a pacing parameter — this is the
silent-security-downgrade class, and it also couples FL-R12′'s answer to
a knob that has nothing to do with it. **No behavior edit in this round**
(deliberately: the branch's charter is design-doc-only, and making the
cap unconditional would entrench one side of FL-R12′ before signature);
the unconditional-cap fix ships with whichever FL-R12′ implementation
wins.

### FL-V10 — The canonical crate cannot see the terminal defect, and one test pins it green (review round 2)

- `projected_already_generated` returns `Ok(money_supply)` on saturation
  (`emission.rs:80-82`), so `base_emission_at` at any height beyond
  exhaustion returns the tail cleanly — the projection leg reports a
  clean perpetual tail forever. `base_block_reward` errors only *past*
  the cap (`:56-58`), never at it. No canonical-crate path composes the
  cap into a height-indexed emission answer, so no test built on the
  crate can reach the failure (rule 47: there was no edit that makes it
  go red).
- Worse, `emission.rs`' `base_block_reward_tail_floor` test sets
  `near_max = money_supply − 2 097 153` and asserts the reward is
  600 000 000 — **a block paying ≈ 286× the entire remaining supply,
  pinned green as intended behavior**. The function's arithmetic is
  correct for what it computes (the pre-cap floor); the test's *name and
  role* present it as terminal behavior with no companion asserting the
  capped composition. Wrong-oracle exhibit; left untouched this round.
- The missing companion now exists as this round's **red test**:
  `terminal_reward_legs_agree`, homed at review round 3 directly in
  `shekyl-economics`' `emission.rs` test module — beside the wrong-oracle
  exhibit, where a retiring design-round instrument cannot take it along
  (`#[ignore]`d with the reason naming FL-R12′). It asserts the estimate
  leg and the validation leg agree at the first diverging block
  (`remaining < tail`) and at exhaustion, **and** asserts the projection
  leg (`projected_already_generated` → reward, the function the census-R2
  reopen criterion names) agrees with validation past the exhaustion
  height. It is red today under *either* reading of the terminal policy —
  the invariant "descriptions of one chain agree" presumes neither — and
  greens (then un-ignores) with whichever FL-R12′ implementation is
  signed. Observed red at both probes: estimate 600 000 000 vs validation
  599 999 999 at the first diverging block, and the projection leg would
  fail at tail-vs-0 past exhaustion. This discharges the test conjunct of
  the census-R2 reopen criterion (§0.1), now literally: the named
  function is called by the red test.

### FL-V11 — The ladder's anti-spam floor decays 3 413× across the emission curve; the round measured it and failed to name it (review round 2)

`Fl = R·w_ref/Mfw²` is linear in the reward. At `Mfw = Zm`: genesis
`Fl = 68 266` atomic/byte; tail-era `Fl = 20` atomic/byte — a **3 413×
decay** (and 0 after exhaustion on the capped leg). Monero's equivalent
span (35.18 → 0.6 XMR) is ~59×: the 2³² cap plus ESF-21 plus the
inherited-unexamined 0.6 tail produced a floor dynamic range ~58× wider
than the one ArticMine's constants (`w_ref = 3000`, `Zm = 300 000`) were
tuned for — on a chain where stakers are paid to store whatever the
floor admits, and where the burn loop is downstream of fee level.

Two things stated on the record:

1. **The instrument printed this number and the round failed to name the
   finding** — `[20, 80, 320, 4000]` sits in §4.6's degenerate pins; the
   3 413× ratio was never computed from it. A measured value is not a
   finding until it is named against the thing it breaks.
2. **§5.2's proposed ladder does not resolve it.** The correction keeps
   `Fl ∝ R` by construction, and `C_q`'s 19× range cannot offset a
   3 413× reward decay: the corrected tail-era floor is ~20·`C_q`
   against a genesis ~46 000–68 000. The open question — whether the
   anti-spam floor should be reward-proportional *at all*, versus an
   absolute constant or a fee-era recalibration — is **new derivation
   scope** requiring its own pre-registered criteria (repeating this
   round's pre-registration discipline, not skipping it). Decision row FL-R13;
   deferral FL-D5. Per the maintainer's review: **if FL-R12′ lands on
   the cap side, the fee floor is the sole long-run security budget and
   this is genesis-blocking, not a calibration question.**

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
(Since review round 3 the instrument folds the projected-trajectory states
themselves into the reachable extremes — the age-0 grid *ratios* {0.1, 0.5,
0.9} are all unreachable, and genesis-quiet at projected ratio ≈ 0 is the
0.680 endpoint — so the JSON's `c_reachable_min` now prints 0.680
directly.)
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
differ by up to one pow2 step. The instrument's `served_ceil_cq` column
carries them — measured highlights, review round 3: in every quiet state
with `C ∈ (0.5, 1]` the ceiling rule gives `C_q = 1`, so the **served
ladder equals today's ladder exactly** — genesis-quiet, genesis-baseline
and mature-quiet all serve `[69 000/16 000, …]` unchanged, meaning launch
continuity is built in and the ladder only moves once `C` leaves `(0.5, 2]`.
Under congestion the served values are the corrected ones rounded up one
pow2 step: young-congested serves `[130 000, 490 000, 2 000 000,
25 000 000]`, mature-congested `[14 000, 54 000, 650 000, 8 100 000]`,
old-congested-wide `[240, 1 100, 41 000, 510 000]`.)

Two regimes, both mispriced today, in opposite directions:

- **Quiet chain: the current ladder overprices ~1.2–1.5×** — and the honest
  corrected floor lands **below the relay floor** (FL-V5 confirmed in three
  of six states, mature-quiet included, not just young-chain). FL-C6
  disposition required (§5.4). Measured refinement (review round 3): the
  bounce is a **raw-`C` phenomenon** — under the adopted ceiling rule every
  reachable quiet state snaps to `C_q = 1` (reachable `C_min = 0.68 >
  0.5`), so the *served* floor never drops below today's and clears
  `check_fee` everywhere on the grid. The §5.4 clamp is therefore a belt
  for states outside the measured envelope, not a live fix.
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

**Metrics (corrected at review round 3):** *median dwell* (blocks a posted
value persists, whole trace), *distinct posted values* (true set
cardinality — the wire alphabet), *value changes* (churn; an earlier
revision published the churn count under the name "distinct values",
overstating the alphabet ~84×), and for the ramp, *minimum dwell of runs
starting inside the ramp window* — the statistic the ramp criterion
actually gates on, because the whole-trace median is dominated by the
stationary tail and structurally cannot fail for ≤ 2 posted values.
20 000-block runs, Poisson traffic over the full §1.8 stationary grid
(`v ∈ {0, 5, 50, 100, 200, 500}` and `M = 10·Zm`), 720-block window,
**swept at round 11 over every registered age at its projected (coupled)
supply state** — `{0, 1, 4, 12, 30}` years; earlier revisions measured
the single age-4 state, and age moves `C` relative to every pow2
boundary (200 runs total); "current" is the churn baseline (medians and
reward quasi-static per scenario), so the table isolates the marginal
churn `C` adds. **Both pow2 snap rules and the §7 hysteresis
construction are modes of the shipped instrument**, so the
register-vs-adopted comparison is reproducible from the branch (table:
the age-4 extract; cross-age results below it):

| Scenario | current | corrected, raw `C` | quantized, nearest (§1.4a registered) | quantized, ceiling (§5.2 adopted) |
| --- | --- | --- | --- | --- |
| stationary `v=50` | no change | **median 4–6 blocks; 251 changes over a 2–3-value alphabet** | no change | no change |
| stationary `v=100` | no change | economy rung churns (median 4); others stable | no change | no change |
| stationary `v=200` | no change | **median 3 blocks; 355 changes, 2-value alphabet** | no change | no change |
| stationary `v ∈ {0, 5, 500}`, `v=50@10·Zm` | no change | no change (rounding plateaus) | no change | no change |
| ramp `v: 50→200` | no change | median 3–17 blocks; min in-ramp run **10 blocks** | one step; min in-ramp run 19 717 | **zero steps** (value held through the whole ramp — vacuous pass, reported as such) |

**Raw `C` fails FL-C4a catastrophically at every age**, and the honest
statistic sharpens the failure mode: the wire alphabet stays tiny (2–3
values) while the *value flickers* every 3–6 blocks — so the fingerprint
is not "which rare value" but "which side of a flicker", cohorts of
~150–300 txs vs ~10⁶ for a stable value. **Both quantized rules and the
hysteresis mode pass the ≥ 240-block gate in every scenario at every
age.** Cross-age honesty on the ramp claim (round 11): the ceiling
rule's "zero steps through the whole 4× ramp" holds at ages ≤ 4; at ages
12 and 30 the same ramp legitimately crosses 2–3 pow2 boundaries (`C` is
larger there and the boundaries sit closer together along `v`), with
minimum in-ramp dwell **644 blocks (age 12)** and **274 blocks
(age 30)** — above the 240-block gate, and worst-case ramp cohorts of
~1.4–5.5 × 10⁴ txs/value (274 blocks at 50–200 tx/block), two orders
above raw-`C`'s 150–300 though below the stationary ~10⁶. The *adopted*
ceiling variant (`2^ceil(log2 C)` — a post-registration refinement
selected by the already-registered FL-C2(b), because round-to-nearest
under-funds the top rung's marginal pricing by up to √2) still rides the
young-age ramps with zero steps where the registered nearest rule steps
once. The §1.4a register itself is not rewritten; this paragraph is the
disclosure. FL-C4a verdict: `C` enters the formula only as `C_q`
(ceiling, behind the §7 hysteresis). Residual risk, re-measured at
round 11: a state sitting exactly on a pow2 boundary **does** flicker at
2× amplitude on the un-hysteretic map — the swept interior exhibits it
(18 feedback cells, §4.5) — and the §7 hysteresis construction closes
it, measured, which promotes that requirement from belt to load-bearing.

### §4.5 Feedback (FL-C7) — measured on the SERVED map (re-run at round 3; swept over the reachable interior at round 11)

An earlier revision measured this criterion on the raw-`C` ladder with the
demand fixed point pinned at baseline — a map the §5.2 proposal does not
serve, anchored where the quantization discontinuity cannot bite (review
finding). Re-measured: deterministic fee↔volume iteration
(`v = D·(f/f_D)^(−ε)`, `ε ∈ {0…3}`), on the raw-`C` map, the served
ceiling-`C_q` map — whose pow2 step is exactly the limit-cycle mechanism
FL-C7 exists to exclude — and (round 11) the **§7 hysteresis
construction** over that map; swept over the reachable §1.8 interior:
every registered age at its projected (coupled) supply, all four
medians, `D ∈ {50, 100, v*, 400}` with the pow2-boundary scale `v*`
**computed per state** (59 / 55 / 221 / 60 / 52 at ages 0/1/4/12/30 —
round 3's fixed `D = 230` was read off the age-4 curve and sat
off-boundary at every other state), each cell run from the fixed point
and from a displaced (up to 8×) start. 2 400 cells.

**The interior sweep found the limit cycle the round-3 grid missed**
(the single-state run had honestly reported "all 80 cells converge" —
of a grid whose one boundary probe was off-boundary): at each state's
true boundary demand the **un-hysteretic** ceiling map 2-cycles — 18
cells, fee amplitude a full `C_q` step (e.g. 37 000 ↔ 74 000 at age 4,
`M = 3·Zm`): `v_avg` oscillates one tx/block around the boundary and
`C_q` flips between adjacent powers. **That fails FL-C7's adoption bar
as registered** (convergence, or cycles ≤ one fee-rounding step). The
§1.7 registered remedy — hysteresis on `C`, then re-test — was applied:
under the §7 construction (3% band around the previous step; the
implementing branch's `fee_correction_quantized`, transliterated into
the instrument as a declared exception until that branch merges) **all
800 hysteresis cells converge to a single tail fee value**, and every
hysteresis dwell run passes the §4.4 gate (min in-ramp 274 blocks).
Raw-`C` cycles at ≤ one rounding step in 49 cells — within C7's letter,
and raw is already rejected by FL-C4a.

FL-C7: **pass — on the CONSTRUCTED map, and only there.** The §7
hysteresis requirement is thereby **load-bearing, not belt**: the
boundary states round 3 guessed "the grid may not represent" are on the
reachable interior, the un-constructed map fails there, and the built
mechanism is what closes it. (The instrument answers *stability*, not
equilibrium location — each cell's fixed point is at its own `D` by
construction.)

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
  at all.** *(Measured against pre-implementation code; FL-R12′ SIGNED at
  round 8 and FL-D1 closed — the authorized implementation retires this
  state: the reward floor is permanent and these exhaustion rows are the
  defect record the implementing KATs close.)* The corrected estimate at
  least stops quoting fees from a reward that no longer exists. This pin
  also refutes the user-facing
  "perpetual tail" claims — escalated separately as **FL-V7** with its own
  decision row (FL-R12′), because a false monetary-policy promise and a
  missing governance mechanism need different owners and different urgency.

### §4.7 Anchored candidate-set reduction (FL-C9; measured at round 5, re-labeled at round 6)

Instrument section `fee_signal_bits` (analytic, reproducible from the
registered traffic model). The measured numbers survived the round-6
re-label unchanged — surprisal is `log2` of the reduction factor — but
their *meaning* is corrected: these are per-anchored-transaction
candidate-set divisors, not identity bits the chain leaks.

| Traffic model | per-rung reduction (eco/std/pri) | surprisal (bits) | `H(rung)` bits/tx | single state-computed rate |
| --- | --- | --- | --- | --- |
| registered 50/40/10 | ×2.0 / ×2.5 / **×10** | 1.00 / 1.32 / 3.32 | 1.361 | **×1.0** |
| sensitivity 70/25/5 | ×1.4 / ×4.0 / **×20** | 0.51 / 2.00 / 4.32 | 1.076 | ×1.0 |
| sensitivity 33/33/33 | ~×3 each | ~1.59 each | 1.585 | ×1.0 |
| **defaulted 15/80/5** (operative post-FL-R17: standard ships as default, §5.5) | ×6.7 / **×1.25** / **×20** | 2.74 / 0.32 / 4.32 | 0.884 | ×1.0 |

Readings, as corrected at round 6:

- **The reduction is real, bounded, and minority-borne.** An anchored
  observer divides the height window's candidate set by ≈ the inverse
  usage share of the transaction's rung — once, for that transaction. At
  5% priority usage that is ~20× against the standard-tier set in the
  same window. It is not a behavior the user can opt out of by
  randomizing: a priority transaction sits in the priority bucket
  regardless of why it is there. A uniform rate makes every
  transaction's candidate set the full window (×1).
- ~~A habitual priority payer is a linkable pseudonym in fee-space~~ —
  **struck at round 6 (maintainer's own correction)**: cross-transaction
  linkage requires an adversary who *already holds* a set of the user's
  transactions from an external source, at which point fee habit is a
  weak confirmation signal on a much stronger leak (and if they hold the
  submission path, fee is irrelevant). Without the anchor, "all priority
  fees" is a **partition, not a cluster**. Tier choice uncorrelated with
  identity carries zero cross-transaction information even with an
  anchor set. The earlier ×0.1ⁿ set-measure compounding is withdrawn
  with this strike.
- The inherited 4-rung and proposed 3-rung ladders measure identically
  (`Fm` carries 0% — latent surface, not entropy).
- The information-theoretic floor below ×1 is **confidential fees**
  (commit the fee, prove `fee − floor ≥ 0`) — out of scope: an FCMP++
  transaction-format surface, recorded as the endpoint and not designed.

## §5 The rung ruling (FL-R17 SIGNED at review round 7) and the anonymity analysis

### §5.1 Criteria disposition

| Criterion | Verdict | Where |
| --- | --- | --- |
| FL-C1 continuous | **rejected** — never triggered: discrete ladders satisfy the registered set; the exception clause stays unfired | §4.3 |
| FL-C2 coverage | met by floor + `2R/M` top; **surge arm fails C2(b)** → fixed in §5.2 | §4.3 |
| FL-C3 spacing ≤ 10× | **conflict with C4b** — registered outcome, resolved on the record in §5.3 | §4.3 |
| FL-C4a dwell | raw `C` fails; **pow2-quantized `C_q` behind the §7 hysteresis passes the 240-block gate in every scenario at every registered age** → adopted (round 11: old-age ramps legitimately step 2–3×, min in-ramp dwell 274 ≥ 240) | §4.4 |
| FL-C4b usage floor | `Fm` at **0% measured production usage** (FL-V3) → **delete** (emergency-lane branch examined and rejected: an emergency lane nobody was using marks the first user who ever touches it) | §5.3 |
| FL-C4c count | **3** | §5.3 |
| FL-C5 static vs state | **state-computed** (19× ≫ r) | §4.1 |
| FL-C6 relay floor | **clamp** (option i), floor re-derivation deferred to CEN-M3's round | §5.4 |
| FL-C7 feedback | **pass on the CONSTRUCTED map only** (round 11): the un-hysteretic `C_q` map 2-cycles at 18 reachable boundary cells at full-step amplitude — the §1.7 remedy applied; the §7 hysteresis (load-bearing) converges all 800 cells | §4.5 |
| FL-C8 degenerates | pinned (incl. the tail-reward penalty via the KAT-pinned entry point, round 11); exhaustion-era governance was deferred as FL-D1 and **CLOSED AS ANSWERED at round 8** (perpetual tail; penalty after the floor) | §4.6, §9 |
| FL-C9 anchored candidate-set reduction (post-registration, round 5; re-labeled round 6) | measured: minority-rung reduction ×10–×20 once per anchored tx; single state-computed rate ×1.0 — **rung-count ruling REOPENED as FL-R17** | §4.7, W7-revised |

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

*Operand resolution (round 8, amendment ADOPTED):* `R` above is the
M_r-neutral total operand `max(curve(remaining), TAIL)` and `C_q` the
whole-scalar `2^ceil(log2((1−σ)·M_r/(1−b)))` — the round's adopted design
unchanged, on an operand immune to the exhaustion `[0, 0, 0]` defect. The
drafted split (raw `M_r` in the operand) was measured and rejected on the
§4.4 dwell gate; the instrument's `C` surface therefore remains the
operative one. Where the tail floor binds, the scalar still carries `M_r`
while the payer's floor does not — a bounded ≤1.3×/0.8× mispricing inside
the ≤2× quantization step whose **direction is made safe by
construction**: the served economy rung is clamped at the very value
`check_fee` prices from, so a conforming wallet's quote can only err
toward acceptance, never dead-letter (the round-8 rider, satisfied as an
identity).

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

*(Superseded-in-part at review round 5: the resolution below is the
historical record of what the round believed at round 2 and why. The same
principle it applies — privacy is lexicographically prior — applied one
rung further was FL-R17's question — **answered at round 7: FL-R17
signed (a), three tiers**, on the anchored-reduction numbers and the
RingCT-baseline comparison.)*

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
`get_dynamic_base_fee` by `C_q`, principled endpoint) **is CEN-M3's row**,
owed to the resumed census round now that census-R2 is unblocked (§0.1);
deferral FL-D2 carries the routing. Until then the floor stays a lower bound the estimate
respects, and the quiet-chain overpricing that survives the clamp is
bounded by the measured 1.5× worst case. Measured status (review round 3):
with the adopted ceiling `C_q` the clamp is **never live on the reachable
grid** (`C_min = 0.68 → C_q = 1` ⇒ served floor ≥ today's floor ≥
`check_fee`); it is retained as an unconditional belt — one `max()` whose
cost is nil and whose absence would silently dead-letter wallets if a
future parameter change pushes reachable `C` below 0.5.

### §5.5 Tier contracts and the default (adopted with FL-R17's signature, round 7)

- **Economy — the admission rung** (`max(C_q·R·w_ref/Mfw², relay floor)`,
  `Fl`'s derived meaning): the price of being relayable and self-funding
  at an exactly-median block. Buys essentially no expansion (marginal
  coverage `w_ref/2M`); under congestion it waits for slack. For
  deferrable payments; the relay-floor clamp means it can never
  dead-letter.
- **Standard — the sustained-growth rung, and the DEFAULT**
  (`C_q·4·R·w_ref/Mfw²`): funds marginal expansion to `x = 2·w_ref/M` —
  the pace at which default traffic can grow the median indefinitely.
  Being in the 1/M² family, the growth it funds tapers naturally as the
  median rises: default traffic cannot runaway-expand the chain
  (rule-75 self-regulation without a knob). Default on three grounds:
  failure-mode UX (rule 82 — the default must not stall exactly when
  the network is busy, which economy-as-default would), bounded cost
  (4× the admission floor at every median), and shipped behavior (the
  GUI already passes `FeePriority::Standard`). *The privacy argument
  for the default choice was explicitly DISCOUNTED by the maintainer at
  signature* ("no privacy argument for the default case") — recorded so
  the default is not later defended on a ground its signer rejected.
- **Priority — the guaranteed-inclusion rung** (`C_q·2R/Mfw`,
  unconditional main arm): exact marginal-cost pricing of expansion to
  the 2×median cap — next-block inclusion from a rational miner in any
  state, surge included. Disclosed cost: the §4.7 anchored divisor
  (~×20 at the defaulted share), borne by self-selected users (C4b's
  accepted premise), and still larger than the RingCT ring-16 baseline
  for any anchor looser than ~13 minutes at baseline volume (FL-R17).

The default choice sets the realized shares C9 is computed over, so the
**defaulted 15/80/5 model (economy/standard/priority) is the operative row** of §4.7's table; the
registered 50/40/10 remains the pre-signature reference.

## §6 Wargame

| # | Adversary / actor | Move | Outcome under current ladder | Outcome under proposed ladder | Defence / residual |
| --- | --- | --- | --- | --- | --- |
| W1 | Miner who ignores the ladder and mines only the penalty-free zone | Refuses all expansion regardless of fees | Individually rational whenever `C > 1` (fees at the served ladder genuinely don't cover cost — measured 5.6–12.9× short in congestion): congestion persists *because* the ladder lies | Forgoes real profit: corrected rungs actually clear the miner's cost, so a refusing miner cedes fee income to competitors; expansion market functions | The ladder is an offer curve; no defence needed beyond pricing it honestly |
| W2 | User pays the top rung, gets no expansion | Buys priority during mature-chain congestion | **Real and measured**: top rung offers as little as 8% of the miner's cost; rational miners take queue-jumping money and never expand; the product sold does not exist | Top rung = exact marginal cost of full expansion in every state incl. surge (§5.2); a rational miner expands | Residual: collusive non-expansion cartel is a mining-cartel question (out of scope, unchanged by this round) |
| W3 | Fee-fingerprint adversary (links txs / identifies wallet software by fee values) | Reads the public fee field | 4 static-formula values; but any wallet deviating from daemon values is marked (unchanged) | 3 values; `C_q` is a deterministic function of public chain state, so all conforming wallets at a height agree; measured dwell with the served (hysteresis-constructed) `C_q`, swept over every registered age at round 11: no value change in any stationary scenario; the 4× ramp holds one value at ages ≤ 4 and legitimately steps 2–3× at ages 12/30 with min in-ramp dwell ≥ 274 blocks (gate: 240) — cohorts ~10⁶ txs/rung-value stationary, worst-case ~1.4–5.5 × 10⁴ inside an old-age ramp window, vs ~150–300 for raw `C`, whose alphabet is only 2–3 values but flickers every 3–6 blocks | Raw `C` was the hazard and is rejected by FL-C4a; custom-fee users remain self-marked (pre-existing, out of scope) |
| W4 | `tx_volume` manipulator (moves `b` and `M_r`) | Self-trades to raise `tx_volume_avg` | Same lever exists and *worsens* mispricing (raises `M_r` 1.3× while ladder ignores it) | Manipulation is at least priced consistently: raising `v` raises `C_q` for everyone including the adversary; pow2 plateaus mean small manipulations usually move nothing | Cost: burn share of every spam fee is destroyed; young chain (`b≈0`) self-mining spam is near-free — but that is the release-multiplier's own emission surface (economics lane, unchanged by this round); the ladder correction adds no new profit path for it |
| W5 | Exhaustion-era spammer (post-mining-era, `R = 0`) | Expands every block to the 2× cap for free | Estimate quotes fees from a reward that no longer exists ([20,80,320,4000] vs true [0,0,0,0]); penalty prices nothing; growth governed only by the 1.7×/window clamp and a 1-atomic floor | RESOLVED at round 8: FL-R12′'s signed composition (`paid = max(M_r·curve, TAIL)·penalty(x)`) keeps the penalty biting at the tail permanently — expansion to the cap costs the full `TAIL` at `x = 1` | ~~FL-D1~~ closed as answered (§9) |
| W6 | Quiet-chain wallet (honest) | Pays served economy rung | Overpays ~1.2–1.5×, or — if the ladder were naively corrected without FL-C6 — bounces off the relay floor entirely (three of six states) | Clamp guarantees relayability; overpayment bounded at measured 1.5× worst case until CEN-M3 re-derives the floor | FL-D2 |
| W7 | Fee-tier count vs **single-tier** — **CLOSED ON THE MERITS at review round 7, rationale REPLACED at the maintainer's direction**: the round-2 argument ("a single price cannot do both jobs") defeated only the *static* single rate and is retired — a future reviewer would notice; the round-5 state-computed candidate was evaluated and rejected at FL-R17 | Observer holds an off-chain anchor and filters the height window by public fields (§1.11's corrected model) | **The durable rationale:** under FCMP++ the fee field **partitions the global set but cannot link** — no on-chain primitive relates two transactions, so the per-transaction cost is bounded by the inverse usage share (×1.25 default / ×6.7 / ×20 at the operative shares, applied once per anchored transaction) and nothing amplifies it across a history | Selectable urgency is a widely used feature whose removal would buy a small constant factor | **A bounded, non-amplifiable per-transaction cost is what a proportionality judgment handles, not what the lexicographic priority order was written for** (maintainer, round 7). Reopeners live on FL-R17: FL-C4b's registered < 5% mechanism, and any change introducing an on-chain linkage primitive |
| W8 | Miner fee-rank ordering leak (minted at review round 5; **exists TODAY under any multi-rate ladder, independent of FL-R17's outcome**) | Fee-sorted inclusion order: block position reveals fee rank, so miners publish a partial ordering of user urgency every block | Standing finding against the current and proposed ladders alike | The sharper half is what becomes **possible**, not what stops leaking: under a ladder a miner has a *legitimate* reason to order by fee, so inclusion order cannot be constrained without breaking the fee market — under a single rate there is none, which turns deterministic/hash-ordered inclusion from an unenforceable exhortation ("miners should not discriminate") into a **checkable rule** a node can verify. This argument survives a dispute about the bit-count. Rule-71-adjacent surface, not a freebie | Disposition: FL-R17 signed (a), so the checkable-rule opportunity is not taken — the leak STANDS under three tiers as **FL-D7** (deferral with reopeners) |

## §7 What changes downstream (proposals with triggers — RK-5 lane untouched)

| Surface | Change | Wire? | Trigger |
| --- | --- | --- | --- |
| `get_dynamic_base_fee_estimate_2021_scaling` (daemon) | compute `C_q` from `tx_volume_avg`/`ag`/height (all already daemon-local), scale rungs, drop `Fm`, make the `Fh` main arm unconditional, clamp `fees[0]` | **No** (values only) | §8 signature; independent of RK-5 |
| `fees` vector length 4 → 3 | wire shape change; both client mappings touch it | **Yes** | **post-RK-5 cutover completion only.** Bridge option if value-correction ships first: keep 4 slots with `fees[2] = fees[1]` (dead index served the *standard* value — its only reachable callers are wallet2-transliterated `Elevated`, keeping them inside the largest set) |
| `CORE_RPC_VERSION` | minor bump with the vector change | Yes | with the row above |
| `shekyl-engine-core` `fee_policy.rs` mapping | 0/1/3 → 0/1/2 | No | with the vector change |
| `shekyl-rpc-client` | unify to the engine mapping; **delete** the dead `[1, 5, 25, 1000]` fallback ladder (`lib.rs:471-486`, impossible daemon shape, rule 60) | No | fallback deletion any time; mapping with the vector change |
| `fee_policy.rs` absolute cap | `Fh` moves ⇒ the KAT-pinned 14 000 000 genesis-condition cap is re-derived as the swept maximum of the **served** (`C_q`) top rung over the reachable young-chain grid — measured: young-congested serves 25 000 000; the genesis-congested bound is 28 000 000 (`C_q = 2` reachable at genesis for `v ≥ 65`, i.e. 2× the 13 653 333 unrounded genesis `Fh`, daemon-rounded); exact value pinned by KAT in the implementing PR | No | with the daemon value change |
| `check_fee` / `get_dynamic_base_fee` | **unchanged** this round (clamp absorbs the collision); re-derivation is CEN-M3's | — | FL-D2 |
| Hysteresis construction requirement | implementation must not flicker at a pow2 boundary: enter a new `C_q` step only when `C` crosses the boundary by a margin. **Measured at round 11 (§4.5): LOAD-BEARING, not belt** — the un-hysteretic served map 2-cycles at 18 reachable boundary cells (full `C_q`-step amplitude, failing FL-C7's bar); the constructed map converges in all 800 cells. The mechanism is the implementing branch's `fee_correction_quantized` (3% band around the previous step); the §4.4 ramp runs and the §4.5 boundary cells are the acceptance gate | No | implementing PR (built on `feat/fee-ladder-impl-1`; the instrument's transliterated copy retires at that merge) |
| Wallet/CLI tier-picker disclosure (rule-81 obligation **created by FL-R17's signature**, flagged at steering) | Three tiers put a privacy cost behind a user-facing choice (×1.25 default / ×6.7 / ×20 operative divisors, §4.7) — a user selecting "priority" cannot be expected to price a candidate-set divisor, so the surface must disclose the trade in terms a non-protocol user can act on, or the choice is uninformed by construction. Copy is owned by the wallet/GUI lane (rules 80/81/82), **not this round** — handed off via the round record; the engine mapping change is the natural carrier | No | with the engine tier-mapping change; owner: wallet/GUI surfaces |

## §8 Ratification table — FL-R12′/FL-R17 SIGNED, FL-R14 RULED (per-row provenance); census overlap per §0.1

Rows marked ⚖ are census-R2 overlap, routed to the resumed census round
(§0.1: both resume conjuncts are satisfied). They are not unsigned
proposals held for an open sequencing call.
Rows marked **BUILT** refer to the round-9 implementation branches
(`feat/fee-ladder-impl-1`, then the rename in `-impl-2`), which follow
this document's merge as their own PRs — this design PR contains no
consensus behavior change.

Maintainer endorsement recorded at round 7: the remaining three-tier
mechanics — the `C_q` correction, `Fm`'s deletion, the `Fh` main arm made
unconditional, and `fees[0]` clamped to the unbuffered relay floor —
"already read as sound." Recorded as endorsement; the formal signatures
ride each row.

| # | Decision | Proposed disposition | Census hold |
| --- | --- | --- | --- |
| FL-R1 | The ladder derives from the validation-path miner economics. **Operand per the ADOPTED round-8 amendment (whole-scalar form)**: the estimate prices against the M_r-neutral total operand `max(curve(remaining), TAIL)` with the WHOLE volume-dependent scalar quantized — `C_q = Q_ceil((1−σ)·M_r/(1−b))`, unchanged from the round's adopted design. The drafted split (`R_eff` carrying raw `M_r`, only `C′` snapped) was measured and REJECTED: `Q(C′)·M_r ≠ Q(C′·M_r)` — identical in algebra, not in quantization — and it re-created the FL-C4a dwell failure (4-block cohorts at baseline), flipped the FL-C6 clamp live at genesis-quiet, and broke launch continuity at quiet-mature. **BUILT** | adopt — **built** | ⚖ (F14b-adjacent) |
| FL-R2 | Rung values are state-computed daemon-side each estimate | adopt | |
| FL-R3 | The correction enters only pow2-quantized (ceiling) and hysteresis-guarded; per the adopted round-8 amendment the quantized quantity is the WHOLE scalar `C = (1−σ)·M_r/(1−b)` — exactly the round's measured design. Hysteresis implemented Rust-side (`fee_correction_quantized`, 3% band, previous-`C_q` memory daemon-side). **BUILT** | adopt — **built** | |
| FL-R4 | Rung count = 3; `Fm` deleted; FL-C3-vs-C4b conflict resolved for privacy per §5.3 | ~~adopt~~ ~~CONTESTED round 5~~ **RESOLVED: confirmed by FL-R17's signature (three tiers), round 7** | reopened round 5; resolved round 7 |
| FL-R5 | Top rung = `C_q·2·R/Mfw` unconditional (surge discount removed; operand per the adopted amendment). **BUILT** (`corrected_fee_ladder`; heritage surge case 22 000 → 67 000, pinned) | adopt — **built** | |
| FL-R6 | `fees[0]` clamped to the unbuffered relay floor (`blockchain.h:682` seam) | adopt | ⚖ CEN-M3 |
| FL-R7 | Wire shape (vector 3), `CORE_RPC_VERSION`, both client mappings | adopt **post-RK-5**; bridge = duplicate `fees[2]=fees[1]` | |
| FL-R8 | Dead rpc-client fallback ladder deleted | adopt | |
| FL-R9 | Wallet absolute cap re-derived as the swept maximum of the *served* (`C_q`) top rung over the reachable young-chain grid — instrument anchors: 25 000 000 measured at young-congested, 28 000 000 genesis-congested bound — pinned by KAT in the implementing PR | adopt | |
| FL-R10 | FL-V1 recorded as a standing defect independent of this ladder (estimate/validation reward divergence, terminal form §4.6) | record | ⚖ (F14b evidence) |
| FL-R11 | The G6b fossil-flag punt is discharged **for the fee constants only**: this round derives the ladder *given* the 300 000-byte zone; the zone value itself and the 1.7×/×50 clamps remain underived | record | ⚖ CEN-G6b |
| FL-R12′ | **Terminal emission-state ruling — SIGNED at review round 8 (maintainer, in-channel, with the composition given verbatim).** Direction: perpetual tail (accepted round 4; the round-4 dormancy rationale stands). **Signed composition: `paid = max(M_r·curve(remaining), TAIL) · penalty(x)`** — `remaining` floored at zero (non-saturating accumulator; reuses the cap function's own saturating-sub lesson), `cap_reward_to_remaining_supply` retired, one owner, no flag path (discharges FL-V9). The three operators, each placed on the record: **(1) Floor on the paid emission, not the base** — the release multiplier exists to pace a *finite remaining* toward demand; under a perpetual tail there is nothing to defer, so `M_r` at the tail would only make the perpetual inflation rate wobble with activity, and wobble the wrong way for a security floor (paying least when fees are lowest); `max(M_r·curve, TAIL)` gives it no object. **(2) Penalty AFTER the floor** — the operator the F-1 draft was silent on, and the one that decides whether block-size governance survives the ruling: floor-last (`max(M_r·curve·(1−x²), TAIL)`) would kill the penalty at the tail *permanently* (W5 realized, forever, since no post-tail era exists); the signed order keeps expansion costing the full `TAIL` at `x = 1`. **Ordering rule, generalized: floors belong to emission; penalties apply to the paid quantity.** (3) The floor is on the **pre-split total**, not the miner's share (`σ(t)` ≈ 0.1% by year 65 — immaterial to the number, material to which quantity 0.6 describes). **Ladder operand consequence:** the estimate prices against `R_eff = max(M_r·curve, TAIL)` and the correction drops `M_r` (`C′ = (1−σ)/(1−b)`) so multiplier and floor are not double-counted — algebraically identical to the prior `C·R` wherever the floor does not bind, and it kills the `[0,0,0]`-ladder-at-exhaustion defect (the V1 class re-created by the unamended draft). FL-R1/R3/R5 operands updated; oracle re-oriented (FL-V10). FL-D1 **closed as answered** — the ruling abolishes the era D1 deferred to, and the signed order penalizes the tail like any other reward. **Build authorization: YES from the maintainer, upon this record.** **ROUND-8 AMENDMENT (estimate side) ADOPTED in the maintainer's words**: the signature governs the payer, not the row consuming the operand; quantize the whole volume-dependent scalar; "bounded cost against structural regression is the right selector, and it isn't close." Rider satisfied by construction (§5.2). **BUILT on `feat/fee-ladder-impl-1`** (the round-9 atomic bundle, a follow-up PR to this document — none of it is in this PR): one owner `paid_block_reward` (Rust) + marshal-only C++, no flag path, cap retired, accumulator through the asymptote, FL-R14 build assertion, FL-R16a error arm removed (estimator + relay dead-letters closed), FL-R16b/c, FL-R15 rename executed, oracle graduated green | **SIGNED — composition as above; BUILT** | signed in-channel at review round 8 |
| FL-R13 | **Fee-floor basis (FL-V11)**: whether the anti-spam floor stays reward-proportional (`Fl ∝ R`, decaying 3 413× to the permanent tail floor of 20·`C_q` atomic/byte) or moves to an absolute/recalibrated basis. New derivation scope with its own pre-registered criteria — not resolved by §5.2, which inherits the decay by construction. **FL-R12′ SIGNED at round 8 retires the genesis-blocking escalation**: the reward-proportional floor now has a permanent nonzero terminal value instead of reaching 0, so this is a calibration round (is 20·`C_q`/byte the right permanent floor for a chain whose stakers store what it admits?), not a security-budget-existence question | **decision required — own round, criteria first; non-blocking (gate satisfied by the FL-R12′ signature; reverts to genesis-blocking if the direction reverses to the cap)** | minted at review round 2; recalibrated at review round 4 |
| FL-R14 | **Persisted accumulator width — RULED (b) by the maintainer at review round 4, in-channel: keep `u64` persisted.** Rationale as ruled: the binding bound is not the LMDB column but the genesis-frozen **64-bit range-proof width** (`shekyl-bulletproofs` `prove_plus`, commitments in `[0, 2⁶⁴)`) — a `u128` accumulator cannot help a chain whose outputs cannot provably exceed 2⁶⁴ atomic; it would be a check that can't be the first to fail. Build obligation: encode the ≈ 89 750-year bound as a **build-time assertion** over `(tail × blocks_per_year)` with the range-proof width named as the reason, so a re-parameterization (bigger tail, fewer decimals) fails loudly. Documented failure mode the assertion guards: accumulator wrap **un-saturating `remaining`** (wrapped small `ag` → huge `remaining` → curve reward resumes) | **RULED (b)** | ruled in-channel at review round 4 |
| FL-R15 | **Rename sweep (FL-R12′ implementation obligation):** `money_supply` → asymptote-class name reaches `config/economics_params.json`, the codegen, engine-core consumers, the census rows, and every doc naming it — each hit classified asserts-is / records-was / describes-a-closed-hazard before editing (census + CHANGELOG hits are legitimately records-was). **Method note (reusable):** a name sweep finds `MONEY_SUPPLY`; only a *jobs enumeration* — emission input, burn-ratio denominator, activity invariant, headroom operand — reveals that two of the four jobs are **assertions that the cap holds**; that enumeration is what surfaced FL-R16, and it is the instrument, not the name list | **record — binds the implementing PR** | minted at the FL-R12′ direction; guard dispositions re-minted FL-R16a/b/c at review round 4 |
| FL-R16 | **REJECTED AS WRITTEN at review round 4 and re-minted below.** The original row's headline claims did not survive source: `economics_differential.rs:145` is `#[cfg(test)]` fixture replay (`engine/mod.rs:288-289`), not a live consumer; `ActivityMetric::new` has **zero production constructors** on `dev`; the consensus burn path (`blockchain.cpp:1804` → `compute_fee_burn` → `calc_burn_pct`) never touches it, so "taking the burn's activity input down" was false; and the date conflated tail *onset* (~yr 65) with *exhaustion* (~yr 73) — `circulating > asymptote` first occurs at exhaustion. Kept as the record of the defect: three relayed claims entered a §8 row unverified | **superseded by FL-R16a/b/c** | rejected at review round 4 |
| FL-R16a | **Past-asymptote error arm (BUILD-BLOCKING):** `base_block_reward`'s `AlreadyGeneratedExceedsSupply` (`emission.rs:61`) is unreachable-by-design today and load-bearing wrong under the accepted direction. Consequences if the ruled accumulator ships with the arm intact, both at exhaustion ≈ yr 73: (i) the 5-arg estimate path (`blockchain.cpp:4541-4544`) errors → falls to the 10 000-SKL `BLOCK_REWARD_OVERESTIMATE` placeholder → `fee_policy.rs` refuses that snapshot **by design** → **no wallet can quote a fee**; (ii) `get_current_fee_per_byte` (`:4448-4453`) returns its failure-arm 0 → `check_fee` rejects everything → **the mempool refuses every transaction** (`kept_by_block` excepted). Removal ships with the FL-R12′ implementation | **decision folded into the FL-R12′ build** | minted at review round 4 |
| FL-R16b | **`ActivityMetric::new` cap guard (`activity.rs:124`): non-blocking API cleanup.** False under the accepted direction, but fixture-test-only today — remove with the rename sweep, not on the build's critical path | **record** | minted at review round 4 |
| FL-R16c | **Burn-ratio semantics past the asymptote:** `calc_burn_pct`'s `supply_ratio` (`burn.rs:76-78`) is unsaturated — exceeds 1.0 after exhaustion, drifting the burn toward `burn_cap` (≈ 0.0037%/yr issuance scale, negligible but unnamed). Disposition: saturate at `SCALE`, one line. And the sweep must not walk past the pre-existing definitional bug: `circulating_supply = already_generated_coins` (`blockchain.cpp:1787`, `:2074`) is **gross emission ignoring burn** | **record — binds the implementing PR** | minted at review round 4 |
| FL-R17 | **Rung count — SIGNED (a): THREE TIERS. Maintainer, in-channel, review round 7** ("sign it as three tier"). Rationale as signed: (i) **no privacy argument applies to the default case** — the default bucket is the majority set and its users bear no meaningful reduction (defaulted model: the standard bucket at ×1.25, §4.7); (ii) **the non-default case does not significantly degrade privacy** — a smaller set is still, arguably, much *larger* than Monero RingCT's ring-16, the de facto standard. (iii) The ruling's interpretive frame, in the maintainer's words: the privacy cost of a tier is *a bounded per-transaction candidate-set reduction for anchored attacks, with no linkage primitive to amplify it under FCMP++ — the kind of cost a proportionality judgment handles, not the kind the priority order was written for*. This frame *reconciles* rather than contradicts the stake-quorum rejection (the hierarchy's canonical privacy-wins ruling): there the cost was **structural and unbounded** — a per-persona uptime log growing without ceiling — so the lexicographic ordering applied; here it is **bounded, once per anchored transaction**, so proportionality applies. Same hierarchy, two instruments, selected by whether the cost is bounded — read together, the two rulings are one position. The round's supporting arithmetic for (ii): a priority transaction's anchored candidate set is `W/20` for an anchor window of `W` transactions, above ring-16 for any anchor looser than `W = 320` txs — at baseline volume, any anchor wider than ≈ 6.4 blocks (~13 minutes); tighter time-windows come with higher volume, which scales the set back up. Tier contracts and the default are §5.5. **Candidate (b) REJECTED; rule-21 reopeners as set by the maintainer at round 7, superseding the round's drafted three:** (r1) **FL-C4b's already-registered mechanism** — any rung whose measured mainnet usage share falls below 5% over a window is deleted or explicitly ruled an emergency lane; it needs no new row, and it is what retires priority if "many people use it" proves wrong; (r2) **any transaction-format or spend-proof change that introduces an on-chain way to relate two transactions** — the no-linkage-primitive premise is what makes the cost bounded, so its loss reopens the fee-tier disposition itself. *Method note (steering, round 7): r2 is anchored to the premise the argument rests on, not to a magnitude the argument produced — a threshold reopener invites argument about whether the number was crossed; a premise reopener either holds or does not, checkable by reading the format. Tie reopeners to assumptions, not magnitudes.* The median-dynamics gate lapses for this decision; W8 re-homed to FL-D7 | **SIGNED (a) — three tiers** | signed in-channel at review round 7 |

Signatures are recorded per-row with their provenance (in-channel, review
rounds 4–8); this line remains for any wholesale countersign the
maintainer chooses to add: ________________

## §9 Deferrals — each with rule-21 reopen criteria

| # | Deferred | Named blocker | Reopen when |
| --- | --- | --- | --- |
| FL-D1 | ~~Post-mining-era block-size governance~~ **CLOSED AS ANSWERED at round 8**: FL-R12′'s signed composition abolishes the `R = 0` era this row deferred to, and places the penalty AFTER the floor — the tail is penalized like any other reward, so the governance lever never dies. (Had the penalty composed before the floor, this row would have been *undeferrable*: the failure state would arrive at tail onset and never leave.) | *Historical (pre-signature) reopeners, retained as record:* (a) any round touches tail-era economics, or (b) the V4 lattice-only transition round opens | Closed — residue is the FL-R13 calibration of a permanent ~20·`C_q`/byte floor, not a governance vacuum |
| FL-D2 | Relay-floor re-derivation (scale `get_dynamic_base_fee` by `C_q`) | CEN-M3 is a queued census-R2 row; ruling it here would create the double-ratification §0.1 forbids | *First criterion FIRED (the §0.1 sequencing landed at round 2; both resume conjuncts satisfied at round 8):* the item is routed, not reopened here — it lands in CEN-M3's resumed round. Early trigger unchanged: the clamp observed binding in > 50% of mainnet estimate calls over a 30-day window (evidence the floor, not the ladder, is setting prices) |
| FL-D3 | A fourth tier, if UX ever wants one | No engine tier addresses one (FL-V3: `Elevated` has zero production callers); a rung without users is fingerprint surface | an engine/GUI round proposes a user-facing tier with a predicted ≥ 5% usage share under FL-C4b's test |
| FL-D4 | Zone value (300 000) and the 1.7×/×50 clamps | CEN-G6b/G6 own them; this round consumed them as boundary (§1.8) | census-R2 may resume (both §0.1 conjuncts satisfied: FL-R12′ signed, red-test discharged); FL-R11 records the partial discharge so R2 inherits a smaller question |
| FL-D5 | Fee-floor basis derivation (FL-V11 / FL-R13) — whether `Fl ∝ R` survives a 3 413× reward decay as the anti-spam floor, on a chain where stakers store what the floor admits | Its own pre-registered round: criteria must be committed before the floor model is chosen | Open on its own merits (FL-R12′ signature satisfied): the floor's long-run role is the *permanent tail-era floor* and the genesis-blocking escalation is retired; the round opens as FL-R13's calibration |
| FL-D6 | Fee-variance smoothing pool (declined as a floor at the FL-R12′ direction; may still earn a place as *smoothing*, never as the security floor) | Post-genesis per the accepted direction — no pre-genesis blocker exists once the tail is the floor | Design reopens **before tail onset** (by height ≈ 60·`BLOCKS_PER_YEAR`, five years ahead of the ≈ year-65 tail entry), or **early** if over any rolling 90-day mainnet window the 10th-percentile day's miner fee income falls below 25% of the window median (the dormancy signal the declined pool was meant to paper over) |
| FL-D7 | W8: miner fee-rank ordering leak — block position reveals fee rank under any multi-rate ladder, and FL-R17's three-tier signature keeps it live | Under a ladder a miner has a *legitimate* reason to order by fee, so inclusion order cannot be made a checkable rule without breaking the fee market — the constraint W8 identified is only available under uniform rates | (a) any FL-R17 reopener fires (single-rate reconsidered ⇒ the checkable rule becomes available); (b) the relay/P2P-3 round takes inclusion-ordering scope and finds a ladder-compatible mitigation (e.g. intra-block shuffle of same-rate transactions, which three tiers still permit within each tier) |

---

*Round instrument: `rust/shekyl-economics-sim/src/fee_ladder.rs`
(`--fee-ladder`). Pre-registration commit precedes the instrument in this
branch's history — that ordering is the pre-registration register, stated here so a
later reader sees method, not accident.*
