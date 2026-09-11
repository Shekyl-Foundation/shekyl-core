# FL — Fee Ladder Derivation from Shekyl Miner Economics

**Status:** OPEN — **round 19 (§11) OPEN, 2026-09-10: the relay floor follows raw `C` (FL-R20), the quantizers and §10 go (FL-R21), the wallet pays the served rung exactly (FL-R22), admission is lookback-min over `G` = 5 blocks (FL-R23; `G` re-derived per node at review A-1, 2026-09-10), SMA resolution decided on FL-E3 (FL-R24); confirmation run pre-registered §11.5, implementation spec §11.6 **SIGNED OFF by the maintainer in-channel 2026-09-11** — PR A (FL-R24, the consensus operand) is MERGED to `dev`; **PR B (relay policy) and PR C (the FL-R21 deletion sweep) are cleared to implement.** §8 now carries
**FL-R12′ and FL-R17 SIGNED and FL-R14 RULED** (in-channel, provenance
per-row); the remaining rows hold their marked states. Rows marked BUILT
refer to the round-9 implementation, which **merged as PR #640**
(`fb06e1d2b`, from `feat/fee-ladder-impl-1`), and the follow-up
mechanical sweep — FL-R15's rename and FL-R16b's guard removal —
**merged as PR #654**; both branches are deleted and archive-tagged.
What keeps this document OPEN is round 19 (§11) and the residue queued in
[`FOLLOWUPS.md`](../FOLLOWUPS.md), each row pointing at the §-row that
carries its blocker. **FL-R3 is CLOSED premise-refuted** (FL-R21): the
pow2 snap its band smoothed is deleted, so nothing is restored, and §10
is closed as record (archive tag
`archive/fl-r3-time-grid-2026-09-11`).
The RK-5
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

*Round-19 note (2026-09-10, §11.2 FL-R22):* an overrule of this criterion
was issued and then had its premise withdrawn in the same day. The
maintainer's reading — a fresh per-transaction draw from a distribution
every client shares links nothing; a per-wallet constant is the
fingerprint — is correct and is recorded verbatim at §11.2(a). The draw
was withdrawn as an *insurance* instrument (§11.2(b)), not on this
criterion, and the shape that landed (wallet pays exactly the served
rung, FL-R22/FL-R23) satisfies FL-C1 as written. The criterion stands;
its "arbitrary-precision, wallet-selected" target never included a
daemon-served value paid exactly.

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
**Post-registration note (rounds 14–15): (a)'s STATED RATIONALE is
refuted, and the replacement rationale is thinner than round 14 first
claimed.** §4.5b establishes that a
posted fee value's cohort is not the anonymity quantity this criterion
assumed: construction time is already public at finer resolution via
`reference_block`, and `C_q` is deterministic from public state, so the
fee is redundant with the block carrying it. **The dwell figure is
therefore NOT protecting the cohort of a conforming transaction.** Round 14 proposed *stale-quote self-marking* as the
replacement subject. **Round 15 retracts that too**: `check_fee` is a
floor, not an equality (§4.5b), so a stale quote that still clears the
floor is accepted and invisible, and a fee differing from its including
block's rate is the ordinary case rather than a mark. The only real
observable is **implementation divergence** — a fee outside the small
set of `C_q` values spanning the construction window — and dwell's
relationship to it **points the wrong way**: fewer rate changes mean
fewer occasions on which a divergent implementation can betray itself.
That is a benefit to a broken wallet, and only derivatively to its
users; a privacy system should fix divergent implementations, not
lengthen the interval that hides them.

**So FL-C4a is NOT retained as an anonymity criterion.** What survives
is non-anonymity and should be named as such: served-value churn is a
**quantization-quality and user-predictability** property — a fee quote
that changes every 3–6 blocks is a bad quote, independent of who is
watching. Every decision the criterion drove still stands on that
ground (raw `C` fails it hardest; quantization passes), which is why
nothing downstream moves — but the criterion should no longer be cited
as protecting a transaction's cohort, and any future round that leans
on it for anonymity is leaning on a refuted premise. The registered
text above is not rewritten (it is committed history); this note is the
disclosure. **The tautology hazard that would have arisen under
FL-R18 (c) does not arise under (a)**, since no mechanism enforces the
property — but the concern is kept on record: had (c) shipped, this
gate would have displayed green forever, and any future proposal to
*enforce* dwell inherits the obligation to replace this subject with a
check on the mechanism (restart-inclusive floor application).

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

> **DISCHARGED at #640 (§4.6).** The divergence this section records is
> closed: with FL-R12′ in the tree both sides agree at exhaustion. What
> follows is the evidence the ruling was made on, in the tense it was
> found in — it cites `shekyl_apply_release_multiplier` and the
> supply-headroom cap, both of which #640 deleted. Read it as the record,
> not as a description of the current call graph.

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
boundary (**440 runs at time-grid round 2** — eleven modes × eight scenarios × five ages, 360 of them quantized, read off the run's own `dwell grid = N runs` line; **this figure has now gone stale three times for the same reason** — 200 until the rate-limited mode joined at round 13, 240 until §10's grid arms joined at round 18, 320 until round 2 added the `P` = 720 pair and the warm arm — each time because a count derived from a mode list is invalidated by every addition to that list. It is re-derived from the run, never by arithmetic on the previous number, and round 2b will move it again); **at round 12 the traces EVOLVE chain state per block**
(`already_generated` advances by the shipped paid emission; height, σ,
supply and reward all drift — §1.8's quasi-static claim is confirmed by
measurement, not assumed); "current" is the churn baseline, so the table
isolates the marginal churn `C` adds on top of the shared reward-decay
drift. **Both pow2 snap rules and the §7 hysteresis
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
~150–300 txs vs ~10⁶ for a stable value. Under the evolved traces
(round 12) a slow secular value change is NORMAL — reward decay crosses
a 2-significant-digit rounding step roughly once per 10–20 k blocks at
genesis, and every mode including "current" shares it — so the gate is
dwell, not zero-change. **The adopted ceiling rule and the §7 hysteresis
mode pass the ≥ 240-block gate in every scenario at every age** (minimum
median dwell 464 / 446 blocks, minimum in-ramp run 274 at the age-30
ramp; worst-case cohorts ~1.4–5.5 × 10⁴ txs/value there, two orders
above raw-`C`'s 150–300 though below the quiet-state ~10⁶). **The
registered round-to-nearest rule FAILS its stationary gate outright at
age 12** (median dwell 2–3 blocks at `v ≥ 200`): drift parks raw `C`
at the √2 midpoint and the nearest snap flips per-block — a failure
the frozen-state traces could not see, and a second, independent
ground for the already-adopted ceiling (the first was FL-C2(b)
marginal-pricing under-funding; the §1.4a register itself is not
rewritten — this paragraph is the disclosure). The same state's ramp
scenario passes the ramp's own registered bar (min in-ramp run 1 457 ≥
60; the round-12 gate correction measures each scenario kind against
ITS registered statistic) while flickering identically in its
stationary tail — the stationary rows carry the verdict. FL-C4a verdict:
`C` enters the formula only as `C_q` (ceiling; the §7 hysteresis was
behind it when this verdict was taken and is no longer on the served
path — FL-R3. The verdict does not turn on the band: the ceiling clears
the dwell gate with it or without it, 446 and 464 blocks). Residual,
re-measured on the evolved traces: boundary-
parked states still 2-cycle on the un-hysteretic map, and at the
high-elasticity corner a residual oscillation SURVIVES the hysteresis
band — measured, bounded, and surfaced as **FL-R18** (§4.5, §8), not
smoothed over. **Round 14 re-reads this section's own premise:** the
cohort arithmetic above assumes the fee is the only time signal, and it
is not — `reference_block` is public and finer-grained (§4.5b) — so the
residual is accepted as bounded and the criterion is re-grounded — at
round 15, on quantization quality and predictability rather than on any
anonymity property at all (§1.4 note). The dwell numbers stand; what
changes is what they are evidence FOR.

### §4.5 Feedback (FL-C7) — measured on the SERVED map (re-run at round 3; swept over the reachable interior at round 11)

> **Which map is "served", and a temporary gap.** This section is written
> about the pow2 ceiling *behind the §7 hysteresis band*, and round 17
> RULED that this is the map the daemon serves (**FL-R3**, §8). The
> measurements below are the design's and stand as ratified.
>
> The shipped daemon does not yet meet them: #640 review cycle 5 found
> the band unreachable on the served path — `blockchain.cpp` passes
> `prev_cq = 0` — and restoring it needs a grid-anchored previous value,
> which is a design change coming back as its own round. So until that
> lands, the daemon serves the un-hysteretic ceiling: dwell is
> unaffected (464-block minimum median against the banded 446, bar 240)
> and the rejection race moves three cells, but the FL-C7 residual is
> 1 161 worst tail transitions rather than 24. Read "the served map"
> below as the RULED map; FL-R3 carries the gap and its two binding
> constraints.

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
true boundary demand the **un-hysteretic** ceiling map 2-cycles at a
full `C_q` step (e.g. 37 000 ↔ 74 000 at age 4, `M = 3·Zm`): `v_avg`
oscillates one tx/block around the boundary and `C_q` flips between
adjacent powers. **That fails FL-C7's adoption bar as registered**
(convergence, or cycles ≤ one fee-rounding step). The §1.7 registered
remedy — hysteresis on `C`, then re-test — was applied (the §7
construction: 3% band around the previous step; the implementing
branch's `fee_correction_quantized`, transliterated into the instrument
as a declared exception until that branch merges), and on the
frozen-state traces it converged every cell.

**Round 12 made the traces drift-honest** (state evolves per block —
§1.8's "confirm, not assume") and split the outcomes with a transition
counter (one tail transition = a secular boundary crossing, the system
tracking real state change; ≥ 2 = oscillation):

- **230 cells: secular single crossings** — σ-decay pushes `C` across a boundary once; the served value
  steps once and holds. Pass.
- **Plain ceiling: 20 oscillating cells** at full `C_q` amplitude,
  worst 1 177 transitions in the 3 000-block tail — the round-11
  failure, worse under drift.
- **Hysteresis: 14 oscillating cells remain** — all at the
  boundary-parked baseline demand (`D = 50`), elasticity ≥ 2 (and ≥ 1
  at age 30, `M = 3·Zm`): 7–24 transitions, amplitude one `C_q` step,
  worst inter-flip dwell ≈ 125 blocks (under the 240-block anonymity
  gate). Mechanism: the band absorbs boundary NOISE (it damps 1 177 →
  24 transitions) but not gain-≥2 demand feedback — a fee step moves
  volume ~4–8×, which moves `C` ~20%, far outside any 3% band.
- Raw-`C` oscillates BEYOND one rounding step in 28 cells under the
  registered bar (round 12 correction: the earlier 1.9× screen tested
  `C_q` flips, not the bar) — raw fails C7's letter as well as C4a.
  Under-one-step drift fills most of its remaining cells.

FL-C7: **pass on the CONSTRUCTED map for every state except the
boundary-parked high-elasticity corner, which was SURFACED as FL-R18
(§8) per §1.7's own chain** — "if still divergent, surface in §8; do
not ship a smoothed number whose stability is unproven." The §7
hysteresis requirement remains **load-bearing** (necessary: without it
the map fails broadly) but is measured as **not sufficient at that
corner**. **This is precisely the sentence FL-R3 now cashes out:** the
requirement is load-bearing on FL-C7 and the daemon does not meet it,
because the served path has no deterministic previous value to band
against. **FL-R18 accepts that residual as bounded (round 14)**,
after the mechanism proposed to close it was measured and rejected on
its own terms (§4.5a) and the harm it was to prevent was refuted
(§4.5b). The deadband/limit-cycle asymmetry still holds — a deadband
cannot suppress a gain-≥2 feedback cycle — which is why no wider band
is adopted either. Note for anyone
re-reading `D = 50` as an odd corner: it is the volume at which
`M_r = 1.0` by construction (`ratio = v/tx_volume_baseline`,
baseline 50), i.e. the neutral point the release curve is calibrated
around — a quiet mature chain sits at or near it, which is why the
corner was not accepted as bounded. (The instrument answers *stability*, not equilibrium
location — each cell's fixed point is at its own `D` by construction.)

### §4.5a FL-R18's `N`, measured (round 13)

The ruling requires `N` to come from the trace set. Candidates are the
figures the register already contains — the ramp bar (60), the
stationary dwell gate (240), the volume window (720) — plus midpoints.
Swept over the same reachable interior, counting cells that oscillate
beyond the registered one-rounding-step bar:

| `N` (blocks) | oscillating cells | worst tail transitions |
| --- | --- | --- |
| (band only, no floor) | 14 | 24 |
| 60 | 18 | 19 |
| 120 | 36 | 16 |
| 240 | 56 | 14 |
| 480 | 71 | 8 |
| 720 | 102 | 5 |

**Read the two columns against each other — they move in opposite
directions, and that is the finding.** The residual cycle's period is
**125–429 blocks** (measured), so `N = 60` cannot bind on it at all and
changes nothing. Above that the floor binds and the flip RATE falls as
designed (24 → 14 → 5 transitions), but the cell COUNT rises, because a
dwell floor is a DELAY in a feedback loop and delay is destabilising:
holding the served value stale lets demand wander further before the
fee corrects, which pushes previously-converging cells into the same
slow cycle. One representative cell (age 30, `M = 3·Zm`, ε = 3,
`D = 50`), band-only → `N = 240` → `N = 500`:

| | transitions | fee range | `v_avg` range |
| --- | --- | --- | --- |
| band only | 24 | 1 400 ↔ 2 800 | 49–53 |
| `N = 240` | 8 | 1 400 ↔ 2 800 | 43–53 |
| `N = 500` | 6 | 1 400 ↔ 2 800 | 24–53 |

Frequency improves, **amplitude does not** (one `C_q` step throughout),
and the volume excursion widens monotonically.

*(Round 14: (c) is WITHDRAWN and no `N` ships — this section is kept
because it is the reproducible evidence for why, and because the
delay-destabilises result outlives the disposition. Read below as "the
best `N` available, and still not good enough.")*

**Best candidate `N` = 240 blocks**, i.e. the FL-C4a stationary gate itself:
the property the gate used to *check* becomes the property the
mechanism *enforces*, which is the whole ground of the (c) ruling. At
240 the representative cell's inter-flip dwell moves from ≈ 125 blocks
(under the gate) to ≈ 375 (over it), and every open-loop dwell scenario
still passes its registered gate (min median 342, min in-ramp 274).

**What (c) does NOT do, stated plainly rather than smoothed:** it does
not close FL-C7. The residual cells still cycle at one `C_q` step of
amplitude, which exceeds C7's "≤ one fee-rounding step", and at
`N = 240` MORE cells exhibit that slow cycle (56) than exhibited the
fast one (14). The trade (c) actually makes is **fast
anonymity-harmful oscillation → slow anonymity-safe oscillation, at
the cost of breadth and of a wider volume excursion.** That is a good
trade on the ruling's own reasoning — dwell is the anonymity property
and it is now structural — but it is a *different* outcome from "the
14 cells close", which is what the ruling's instruction anticipated.
**Recorded for the countersignature: this trade is a fact the ruling
was made without, and if it changes the answer the row reopens.**

### §4.5b The rejection race, measured (round 14) — and the anonymity premise, refuted

FL-R18 was surfaced on an anonymity premise: that a fee value flipping
faster than 240 blocks shrinks the cohort a transaction hides in. **That
premise was examined at source and does not hold.** Two legs, both
verified in this tree rather than argued:

1. **Construction time is already public, at finer resolution than the
   fee.** A transaction carries `reference_block: [u8; 32]` **in the
   clear** on the wire (`shekyl-wire` `transaction.rs`, written
   unconditionally), and the daemon's acceptance window is
   `FCMP_REFERENCE_BLOCK_MIN_AGE = 5` to `MAX_AGE = 100`
   (`shekyl-daemon-rpc`). An observer maps hash → height for free, so
   build time is exposed to within that window — against a fee flip
   whose resolution is 125–429 blocks. **The fee's timing signal is
   dominated, not merely weakened.** The cohort arithmetic in §4.4
   inverts with it: that section's "~10⁶ txs per stable fee value"
   assumes the fee is the ONLY time signal, and the reference-block
   cohort (one block's transactions, or a few thousand across the
   admissible window) is *smaller*.
2. **The fee is redundant with the block that carries it.** `C_q` is a
   deterministic function of public chain state, so every conforming
   wallet at a height computes the same value — a fact this document
   already asserted in its own W3 wargame row while §4.4 built a gate on
   its opposite. An observer reading a transaction in a block derives
   the schedule's rate from the block itself; the fee field partitions
   transactions exactly the way the blocks already partition them.
   **Redundant data leaks nothing.**

**The residual, corrected at round 15 — and the first statement of it
was wrong.** Round 14 wrote that a transaction whose fee "does not match
the schedule" self-marks, naming staleness as the cause. That does not
distinguish anything, because **`check_fee` is a FLOOR, not an
equality**: `if (fee < needed_fee - needed_fee/50) reject`
(`blockchain.cpp`). A fee differing from the rate of the block that
includes it is the ORDINARY case — every transaction that waits across
a rate change lands that way and is accepted, as does anyone who
deliberately overpays. Stale wallet and honest-but-delayed wallet are
indistinguishable, and neither is marked.

**What can actually be compared is the fee against the transaction's own
`reference_block`** — both travel in the clear, and `C_q` at a height is
public and deterministic. But the comparison is not equality either, and
the reason is structural: a conforming wallet fetches its estimate from
`get_dynamic_base_fee_estimate`, which computes at the **tip**
(`m_db->height()`), while it anchors at `tip − REF_ANCHOR_AGE` with
`REF_ANCHOR_AGE = FCMP_REFERENCE_BLOCK_MIN_AGE + 1 = 6`. **Fee and
reference height are six blocks apart by construction**, so requiring
`fee == C_q(reference_height)` would mark conforming wallets — precisely
those built in the six blocks after a rate change.

The honest observable is therefore set membership: is the fee in
`{ C_q(h) : h across the plausible construction window }`? Because the
served value changes rarely, that set holds one or two values. **A
wallet posting a value outside it has revealed an IMPLEMENTATION
DIVERGENCE — it computes the ladder differently — not staleness**, since
a stale wallet whose quote still matches some height in the window is
invisible, and one whose quote is older than any change is caught only
if a change happened at all. **The residual is implementation
divergence, and it is small.**

**What survives the refutation** is not anonymity but two plain harms:
the quote-then-broadcast **rejection race**, and user-facing
unpredictability. The race is the one with teeth, so it was measured.

**Measurement.** Along every trace, the SERVED economy rung — the
ladder's floor rung clamped up to the relay floor at quote time (§5.2) —
is compared against the floor at admission `L` blocks later, applying
`check_fee`'s 2% buffer. Lags are stated: **1** (built and broadcast
inside a block), **3** ≈ 6 min (FCMP++ proving at the rule-76 device
floor, human confirmation, Dandelion++ stem embargo), **25** ≈ 50 min (a
signing session left open), and **100** — the protocol's own ceiling,
`FCMP_REFERENCE_BLOCK_MAX_AGE`, past which no conforming transaction can
be submitted at all.

**Refusals: 0 of 72 000 000 quotes, at every lag, across the swept
interior and at the oscillating cells alike — and that zero proves
nothing.** It is structural: these traces hold the median fixed, and
with a fixed median the relay floor is monotonically NON-INCREASING
(reward decay only shrinks `R`), while the clamp puts every quote at or
above the floor it was issued against. A refusal was impossible by
construction, so the count is an artifact of the model, not evidence
about the chain.

**What actually governs the race is the MARGIN a quote carries over its
floor**, and that is measurable here. A quote survives a median
contraction of factor `f` exactly when `f² ≤ (served/floor)·(100/98)`:

| served map | median margin | 5th pct | cells < 2% headroom | contraction survived at worst |
| --- | --- | --- | --- | --- |
| **ceiling `C_q`, no band — THE SERVED MAP** | **2.10×** | **1.00×** | **25 / 800** | **1.010×** |
| ceiling + §7 band (NOT served — see FL-R3) | 2.10× | 1.00× | 22 / 800 | 1.010× |
| raw `C` (rejected) | 1.29× | 1.00× | 165 / 800 | 1.010× |
| + dwell floor `N = 240` (withdrawn) | — | — | 27 / 800 | 1.010× |
| + dwell floor `N = 720` (withdrawn) | — | — | 39 / 800 | 1.010× |

*(Re-measured against the SHIPPED owner at the implementing PR, #640.
The instrument had been scaling already-truncated rungs while
`corrected_fee_ladder` divides once with `C_q` in the numerator, so
these figures previously described an arithmetic nothing serves — 51 /
49 / 181 / 52 / 64. The instrument now calls the owner, so that drift
cannot recur; every conclusion below is unchanged and the exposure is
smaller.)*

So in **3.1% of served-map states (25 of 800) the clamp is live with
under 2% headroom**, and there a median contraction of just **1%**
inside the quote window refuses the transaction. The thin states are not
spread across the grid: **23 of the 25 sit at the widest median (50·Zm)
and 16 at the oldest age**, the degenerate regime where the ladder rung and the
floor both collapse toward the 1-atomic minimum and the 5% gap between
them vanishes into integer truncation. **This also corrects §5.4's "the
clamp is never live on the reachable grid":** measured on the
drift-honest interior it is live in that regime.

**The finding that decides FL-R18: the race is DISPOSITION-INDEPENDENT**,
and the measurement says so directly. Every quantized served map lands
in the same narrow band — **25 thin cells without the §7 band, which is
what the daemon serves**, 22 with it (so the band is neutral on the
race, marginally favourable, and its removal from the served path costs
three cells), and
27 / 33 / 39 with a dwell floor of `N` = 240 / 480 / 720. The exposure
does not track the disposition; it tracks the degenerate large-median
regime that every map shares. A dwell floor makes it modestly worse
rather than better, so the race gives **no reason to prefer (c) over
(a)** — it argues weakly the other way — and it does not hold FL-R18
open.
It is a real exposure in its own right and was minted as **FL-R19**
rather than buried inside a row it does not belong to — **ruled (b) at
round 16**: clamp with a fixed margin above the unbuffered floor. Its
threat is a **liveness** one with **no adversary**: the short-term
median contracts between construction and broadcast, the floor rises
above the quoted fee, and the relay refuses. Three conjuncts must hold
— the gap spans at least one block (the median cannot move inside a
block interval), the short-term median is the binding term (the quiet
chain), and the state is thin-margin — and the consequence is a
refused broadcast recoverable by re-quoting: no fund loss, no
disclosure.

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
  defect record the implementing KATs close. At the time of measurement
  the corrected estimate at least stopped quoting fees from a reward that
  no longer existed, and this pin is what refuted the user-facing
  "perpetual tail" claims — escalated separately as **FL-V7** with its own
  decision row (FL-R12′), because a false monetary-policy promise and a
  missing governance mechanism needed different owners and different
  urgency.)*

  **DISCHARGED at the implementing PR (#640).** With FL-R12′ in the tree
  the instrument reports `val_reward_at_exhaustion = 600 000 000`, equal
  to the estimate side: FL-V1's terminal divergence is CLOSED, and every
  sentence above — the `[0, 0, 0, 0]` ladder, the collapsed relay floor,
  the reward that "no longer exists", the refuted tail promise — is the
  historical defect record, not current behaviour. It is kept because it
  is the evidence the ruling was made on.

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
| FL-C4a dwell | raw `C` fails; **the adopted ceiling passes the 240-block gate in every scenario at every registered age on drift-honest traces, with or without the §7 band** (round 12 behind the band: min median 446, min in-ramp 274; #640 un-banded — which is what the daemon now serves, FL-R3: min median **464**, so this criterion is insensitive to the band's removal; secular reward-decay steps ~1 per 10–20 k blocks are shared by every mode incl. current). **The registered nearest rule FAILS at age 12 under drift** (median 2–3 blocks — per-block flicker at the √2 midpoint), a second independent ground for the ceiling. **Rounds 14–15: the criterion's anonymity rationale is REFUTED and NOT replaced by another anonymity one** — a conforming transaction's fee is redundant with the block carrying it, construction time is already public via `reference_block`, and round 14's fallback (stale-quote self-marking) was itself retracted at round 15 because `check_fee` is a floor, not an equality. What survives is **quantization quality and user predictability**, on which every decision this criterion drove still holds (§1.4 note, §4.5b) | §4.4, §4.5b |
| FL-C4b usage floor | `Fm` at **0% measured production usage** (FL-V3) → **delete** (emergency-lane branch examined and rejected: an emergency lane nobody was using marks the first user who ever touches it) | §5.3 |
| FL-C4c count | **3** | §5.3 |
| FL-C5 static vs state | **state-computed** (19× ≫ r) | §4.1 |
| FL-C6 relay floor | **clamp** (option i), floor re-derivation deferred to CEN-M3's round | §5.4 |
| FL-C7 feedback | **pass on the CONSTRUCTED map except one corner, which FL-R18 ACCEPTS AS BOUNDED** (measured round 12 on drift-honest traces; premise refuted and re-dispositioned round 14): un-hysteretic map oscillates at 20 cells (worst 1 177 transitions on the round-12 instrument; 1 161 re-measured at #640 against the shipped owner); the §7 hysteresis (load-bearing, necessary) damps to 14 residual oscillating cells at the boundary-parked high-elasticity corner (`D = 50` — the release curve's own neutral point, not an odd corner; ε ≥ 2; one `C_q`-step amplitude, worst inter-flip dwell ≈ 125 blocks). Per §1.7's chain the residual went to §8 rather than into a smoothed number, and §8 disposes it: the assumed anonymity harm was examined and **refuted** (§4.5b), and the mechanism briefly ruled to close it was measured to make the loop *worse* (§4.5a). The residual is a slow, one-`C_q`-step cycle at the baseline attractor, on record rather than papered over. **NOT reopened — the figures here stand as ratified.** #640 review cycle 5 removed the band from the SERVED path and round 17 ruled it restored (FL-R3), so the banded figures in this row remain the design's and the criterion's disposition is unchanged. What is temporarily true of the shipped daemon is the un-hysteretic arm — worst tail transitions 1 161 rather than 24 — and that is an implementation gap with a named owner, not a re-disposition of FL-C7 | §4.5, §4.5a, §4.5b, §8 FL-R18, §8 FL-R3 |
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

**This clamp is LOAD-BEARING, and round 14 measured how thin its
margin is.** It is what makes the acceptance direction an identity at
quote time, and §4.5b shows it is **live in 3.1% of served-map states**,
concentrated in the widest-median regime — not "never live on the
reachable grid" as §5.4 recorded from the round-3 single-state grid. In
those states the served rung sits AT the floor with ~1% of headroom, so a 1% contraction of the median between
quote and broadcast refuses the transaction (**FL-R19**). **FL-R19
rules (b): the clamp gains a fixed margin above the unbuffered floor**,
sized per the criterion pre-registered in that row — and the margin
**must be a fixed deterministic multiplier, never randomized and never
per-wallet**, because a quote that stops being derivable from public
chain state manufactures precisely the fingerprint FL-R18 established
does not otherwise exist. Two further consequences for anyone editing
this seam: the clamp may not be "simplified out" as a redundant belt —
it is the acceptance identity itself — and any future proposal that
holds a served value stale (a minimum-dwell floor, a cache, a batched
estimate) must re-measure that margin first, because staleness spends
exactly the headroom this measurement shows is already thin.

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
| W3 | Fee-fingerprint adversary (links txs / identifies wallet software by fee values) — **round 14: this row's own determinism observation is what refutes §4.4's cohort premise (§4.5b). Round 15 narrows the residual further: `check_fee` is a floor, so a mismatched fee is ordinary and unmarked; the only real observable is a fee outside the `C_q` set spanning the construction window, i.e. IMPLEMENTATION DIVERGENCE** | Reads the public fee field | 4 static-formula values; but any wallet deviating from daemon values is marked (unchanged) | 3 values; `C_q` is a deterministic function of public chain state, so all conforming wallets at a height agree; measured dwell on drift-honest traces (round 12 behind the band; #640 for the un-banded map the daemon actually serves, FL-R3): stationary scenarios post at most the shared secular reward-decay step (~1 per 10–20 k blocks, common to every mode incl. today's ladder); minimum median dwell **464 blocks served** (446 banded), min in-ramp 274 (gate: 240) — the band's removal does not weaken this row — cohorts ~10⁶ txs/rung-value in quiet states, worst-case ~1.4–5.5 × 10⁴ inside an old-age ramp window, vs ~150–300 for raw `C`, whose alphabet is only 2–3 values but flickers every 3–6 blocks | Raw `C` was the hazard and is rejected by FL-C4a; custom-fee users remain self-marked (pre-existing, out of scope) |
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
| `fee_policy.rs` absolute cap | **DONE at #640, and NOT as this row instructed — do not pin a swept maximum here.** The row's plan was to re-derive the cap as the swept maximum of the served top rung over the reachable young-chain grid (young-congested 25 000 000; genesis-congested 28 000 000). That framing was measured and found wrong in the expensive direction: it locates the peak at genesis, where the operand reward peaks, missing that `C_q` GROWS with age while `R` decays slowly, so the product peaks in the interior — the 28 000 000 bound sits BELOW honest daemon quotes from ≈ year 3 and would refuse correct snapshots. The cap shipped as a **structural bound** (220 000 000, every factor at its own extreme) with the sweep kept only as a floor under its adequacy. See FL-R9 | No | **cleared at #640** |
| `check_fee` / `get_dynamic_base_fee` | **unchanged** this round (clamp absorbs the collision); re-derivation is CEN-M3's | — | FL-D2 |
| Hysteresis construction requirement | implementation must not flicker at a pow2 boundary: enter a new `C_q` step only when `C` crosses the boundary by a margin. **Measured (rounds 11–12): LOAD-BEARING and NOT SUFFICIENT alone** — without it the map oscillates broadly (20 cells, worst 1 177 transitions on drift-honest traces at round 12; 1 161 re-measured at #640 against the shipped owner — and since #640 that un-banded map is the one SERVED, FL-R3); with the 3% band the residual is 14 boundary-parked high-elasticity cells (7–24 transitions, one `C_q` step), which **FL-R18 accepts as bounded at round 14**: the band stays as built (it is what damps boundary noise ~50×), and **nothing is composed on top of it** — the minimum-dwell floor briefly ruled at round 13 is withdrawn on two independent grounds: the anonymity harm it was to prevent does not exist (§4.5b), and it was measured to destabilise the loop it was meant to calm (§4.5a). The mechanism therefore remains exactly the implementing branch's `fee_correction_quantized` as already built — **no rework** *(Implementation note added after this row was written: #640 review cycle 5 took the band OFF the served path. Round 17 ruled it back ON — FL-R3 — so "no rework" still holds for the MECHANISM, which is unchanged and stays; what is owed is the served-path restoration under FL-R3's two constraints, on the time-grid branch. The measurements in this row are of the banded map and stand.)* | No | implementing PR (built on `feat/fee-ladder-impl-1`; the instrument's transliterated copy retires at that merge) |
| Wallet/CLI tier-picker disclosure (rule-81 obligation **created by FL-R17's signature**, flagged at steering) | Three tiers put a privacy cost behind a user-facing choice (×1.25 default / ×6.7 / ×20 operative divisors, §4.7) — a user selecting "priority" cannot be expected to price a candidate-set divisor, so the surface must disclose the trade in terms a non-protocol user can act on, or the choice is uninformed by construction. Copy is owned by the wallet/GUI lane (rules 80/81/82), **not this round** — handed off via the round record; the engine mapping change is the natural carrier | No | with the engine tier-mapping change; owner: wallet/GUI surfaces |

## §8 Ratification table — FL-R12′/FL-R17 SIGNED, FL-R14 RULED (per-row provenance); census overlap per §0.1

Rows marked ⚖ are census-R2 overlap, routed to the resumed census round
(§0.1: both resume conjuncts are satisfied). They are not unsigned
proposals held for an open sequencing call.
Rows marked **BUILT** refer to the round-9 implementation, which merged
as PR #640 (`fb06e1d2b`, from `feat/fee-ladder-impl-1`); the FL-R15
rename and FL-R16b guard removal follow on `feat/fee-ladder-impl-2`.

Maintainer endorsement recorded at round 7: the remaining three-tier
mechanics — the `C_q` correction, `Fm`'s deletion, the `Fh` main arm made
unconditional, and `fees[0]` clamped to the unbuffered relay floor —
"already read as sound." Recorded as endorsement; the formal signatures
ride each row.

| # | Decision | Proposed disposition | Census hold |
| --- | --- | --- | --- |
| FL-R1 | The ladder derives from the validation-path miner economics. **Operand per the ADOPTED round-8 amendment (whole-scalar form)**: the estimate prices against the M_r-neutral total operand `max(curve(remaining), TAIL)` with the WHOLE volume-dependent scalar quantized — `C_q = Q_ceil((1−σ)·M_r/(1−b))`, unchanged from the round's adopted design. The drafted split (`R_eff` carrying raw `M_r`, only `C′` snapped) was measured and REJECTED: `Q(C′)·M_r ≠ Q(C′·M_r)` — identical in algebra, not in quantization — and it re-created the FL-C4a dwell failure (4-block cohorts at baseline), flipped the FL-C6 clamp live at genesis-quiet, and broke launch continuity at quiet-mature. **BUILT** | adopt — **built** | ⚖ (F14b-adjacent) |
| FL-R2 | Rung values are state-computed daemon-side each estimate | adopt | |
| FL-R3 | The correction enters only pow2-quantized (ceiling) and hysteresis-guarded; per the adopted round-8 amendment the quantized quantity is the WHOLE scalar `C = (1−σ)·M_r/(1−b)` — exactly the round's measured design. Hysteresis implemented Rust-side (`fee_correction_quantized`, 3% band). **RULED at review round 17: the hysteresis STAYS, and FL-R3 closes by RESTORING it to the production path** — not by persisting `C_q` as chain state, and not by retiring the band. *(Maintainer, in-channel and relayed 2026-09-07. A relayed ruling, not an in-tree signature — no approving review or maintainer commit carries it — and this row says so rather than letting a relay read as a signature.)* **The ground, as ruled, and it is the banded map's own figures:** the worst inter-flip dwell is ≈ 125 blocks, which at this tree's 120 s target (`BLOCKS_PER_YEAR` = 262 800) is **4.2 hours**, so a 2× move roughly every four hours in a minority of states, and a **4.0 %** chance that a re-quote changes across a ten-minute window. Against the baseline users actually live with — Bitcoin and Ethereum estimates can move several-fold *within one block* under congestion, which is why those wallets present low/medium/high and the number is understood to be soft — that is stabler, and it sits below the threshold at which anyone forms an expectation there is something to violate. So "barely moves" is accurate, the residual needs no mechanism, and the disposition is to serve the band rather than to argue the band away. **TWO BINDING CONSTRAINTS ON THE RESTORATION, both from findings already on this record:** **(1) the band must remain a PURE FUNCTION OF CHAIN STATE.** Whatever unblocks the production caller may not introduce per-node held state. Derivability is the property FL-R18 closed on and the whole reason a conforming wallet's fee leaks nothing; a restoration that quietly acquires state does not restore this row, it repeals FL-R18. Named here so the fix cannot acquire state while nobody is watching. **(2) SINGLE OWNER.** The band's arithmetic lives in one place and the instrument transliterates nothing — this cycle's own finding, where the sim's copied band had silently lost the owner's `MIN_REPRESENTABLE_C` floor, so a measurement was being taken on a mechanism that was not the shipped one. It binds whatever caller gets wired up. **WHERE THAT LEAVES THE WORK, stated against constraint (1) rather than around it: the blocker IS that the band needs history.** `C_q(h) = f(C(h), C_q(h−1))` is a recurrence, and the two attempts that failed each failed on this: a daemon-local remembered value made the served rate track the process's query history, and the previous block's UNSEEDED snap is a one-step approximation, not the recurrence, and inverts the result. By the ruling's own terms that puts the restoration on the **time-grid** branch — a band whose "previous" is taken from a grid-aligned anchor rather than from unbounded history (a fold over a fixed window from a grid height, or a seed at an epoch boundary), which is a pure function of chain state and bounded to evaluate, at the cost of extra evaluations per query. **That is a design change, so it comes back as a round; it is not smuggled in as an implementation detail here.** **Until it lands the daemon serves the un-banded ceiling. That is a temporary implementation state, NOT a design regression:** FL-C7's ratified figures are the banded ones and stand as ratified, the FL-C4a dwell gate is insensitive to the band either way (446 banded, 464 un-banded, bar 240), and §4.5b's rejection-race exposure moves by three cells (22 → 25). **ROUND OPENED 2026-09-08 — see §10**, which carries the pre-registered criteria (C10-1…C10-5), the candidate shapes, and the cost table. Two things §10 settles that this row could not: the fold's FIRST step is the ruled-out unseeded snap, confined to one block per grid cell, which puts a lower bound on `P` independent of cost; and the naive fold is DISQUALIFYING on cost (`D × 720` full block parses under the blockchain lock, since `get_tx_volume_avg`'s memo holds one entry), so the restoration rides a single-scan shape or is **BLOCKED on the storage-lane cheap per-block tx count** — named per rule 22 rather than implied. | **RULED — hysteresis STAYS; ceiling served today, band restoration owed as the time-grid round (OPEN, §10)** **UPDATE 2026-09-10 (§11):** **CLOSED — premise refuted.** The snap was kept for FL-C4a after FL-C4a was withdrawn as an anonymity criterion (§11.1 item 2); the band smoothed the snap; §10 restored the band. All three deleted by FL-R21. Not superseded: the ground disappeared. | adopt — **built; served-path restoration owed, constraints (1) and (2) binding; round open** | ruled in-channel at review round 17; round opened 2026-09-08 |
| FL-R4 | Rung count = 3; `Fm` deleted; FL-C3-vs-C4b conflict resolved for privacy per §5.3 | ~~adopt~~ ~~CONTESTED round 5~~ **RESOLVED: confirmed by FL-R17's signature (three tiers), round 7** | reopened round 5; resolved round 7 |
| FL-R5 | Top rung = `C_q·2·R/Mfw` unconditional (surge discount removed; operand per the adopted amendment). **BUILT** (`corrected_fee_ladder`; heritage surge case 22 000 → 67 000, pinned) | adopt — **built** | |
| FL-R6 | `fees[0]` clamped to the unbuffered relay floor (`blockchain.h:682` seam) | adopt **UPDATE 2026-09-10 (§11):** **identity under FL-R20** — the economy rung *is* the relay floor; the clamp at `blockchain.cpp:4643` is deleted, not preserved. | ⚖ CEN-M3 |
| FL-R7 | Wire shape (vector 3), `CORE_RPC_VERSION`, both client mappings | adopt **post-RK-5**; bridge = duplicate `fees[2]=fees[1]` | |
| FL-R8 | Dead rpc-client fallback ladder deleted | adopt | |
| FL-R9 | Wallet absolute cap. **Re-derived AGAIN in the implementing PR (#640), because the young-chain framing below was wrong in the expensive direction:** it located the era maximum at genesis, where the operand reward peaks, missing that `C_q` GROWS with age (σ decays, burn rises) while `R` decays slowly — so the product peaks in the interior. The swept peak is **91 000 000 at ≈ year 7 on the NEUTRAL accumulation, and 98 000 000 at ≈ year 8 once the release rails are swept as accumulation extremes** — a chain dormant at `M_r = 0.8` and then busy carries more `remaining`, hence a larger `R`, at the same height. **Neither figure is the reachable maximum, and this row must not be read as naming one:** arbitrary volume paths are uncountable, so the sweep bounds the cap's adequacy from below rather than proving its tightness. (An earlier revision of this row called the 91 000 000 neutral walk "the reachable maximum" — the same overclaim, one level down, that the structural bound exists to avoid.) The 28 000 000 genesis-congested bound this row originally adopted sat **below honest daemon quotes from ≈ year 3**, i.e. it would have refused correct snapshots. The cap is now a **structural bound** with every factor at its own extreme (σ ⇒ 0, `M_r` = release_max, `b` = burn_cap ⇒ `C_q` ≤ 16; `R` ≤ `base_block_reward(0)`; `Mfw` ≥ `Zm`) = **220 000 000**, deliberately loose against the reachable peak because refusing an honest quote dead-letters the wallet while a loose cap only weakens a sanity check. Original framing, retained as the record of the error: *swept maximum of the served top rung over the reachable young-chain grid — anchors 25 000 000 young-congested, 28 000 000 genesis-congested* | adopt — **re-derived as a bound at #640** | |
| FL-R10 | FL-V1 recorded as a defect independent of this ladder (estimate/validation reward divergence, terminal form §4.6). **No longer standing: DISCHARGED at #640** — with FL-R12′ in the tree both sides agree at exhaustion (`val_reward_at_exhaustion = 600 000 000`), so §4.6's record is the historical evidence, not current behaviour | record — **closed at #640** | ⚖ (F14b evidence) |
| FL-R11 | The G6b fossil-flag punt is discharged **for the fee constants only**: this round derives the ladder *given* the 300 000-byte zone; the zone value itself and the 1.7×/×50 clamps remain underived | record | ⚖ CEN-G6b |
| FL-R12′ | **Terminal emission-state ruling — SIGNED at review round 8 (maintainer, in-channel, with the composition given verbatim).** Direction: perpetual tail (accepted round 4; the round-4 dormancy rationale stands). **Signed composition: `paid = max(M_r·curve(remaining), TAIL) · penalty(x)`** — `remaining` floored at zero (non-saturating accumulator; reuses the cap function's own saturating-sub lesson), `cap_reward_to_remaining_supply` retired, one owner, no flag path (discharges FL-V9). The three operators, each placed on the record: **(1) Floor on the paid emission, not the base** — the release multiplier exists to pace a *finite remaining* toward demand; under a perpetual tail there is nothing to defer, so `M_r` at the tail would only make the perpetual inflation rate wobble with activity, and wobble the wrong way for a security floor (paying least when fees are lowest); `max(M_r·curve, TAIL)` gives it no object. **(2) Penalty AFTER the floor** — the operator the F-1 draft was silent on, and the one that decides whether block-size governance survives the ruling: floor-last (`max(M_r·curve·(1−x²), TAIL)`) would kill the penalty at the tail *permanently* (W5 realized, forever, since no post-tail era exists); the signed order keeps expansion costing the full `TAIL` at `x = 1`. **Ordering rule, generalized: floors belong to emission; penalties apply to the paid quantity.** (3) The floor is on the **pre-split total**, not the miner's share (`σ(t)` ≈ 0.1% by year 65 — immaterial to the number, material to which quantity 0.6 describes). **Ladder operand consequence:** the estimate prices against `R_eff = max(M_r·curve, TAIL)` and the correction drops `M_r` (`C′ = (1−σ)/(1−b)`) so multiplier and floor are not double-counted — algebraically identical to the prior `C·R` wherever the floor does not bind, and it kills the `[0,0,0]`-ladder-at-exhaustion defect (the V1 class re-created by the unamended draft). FL-R1/R3/R5 operands updated; oracle re-oriented (FL-V10). FL-D1 **closed as answered** — the ruling abolishes the era D1 deferred to, and the signed order penalizes the tail like any other reward. **Build authorization: YES from the maintainer, upon this record.** **ROUND-8 AMENDMENT (estimate side) ADOPTED in the maintainer's words**: the signature governs the payer, not the row consuming the operand; quantize the whole volume-dependent scalar; "bounded cost against structural regression is the right selector, and it isn't close." Rider satisfied by construction (§5.2). **BUILT on `feat/fee-ladder-impl-1`** (the round-9 atomic bundle, a follow-up PR to this document — none of it is in this PR): one owner `paid_block_reward` (Rust) + marshal-only C++, no flag path, cap retired, accumulator through the asymptote, FL-R14 build assertion, FL-R16a error arm removed (estimator + relay dead-letters closed), FL-R16c, oracle graduated green — **FL-R15 (rename) and FL-R16b (the `ActivityMetric` cap guard) are NOT in this bundle**, both riding the follow-up mechanical rename PR, FL-R16b by its own ratified row | **SIGNED — composition as above; BUILT** | signed in-channel at review round 8 |
| FL-R13 | **Fee-floor basis (FL-V11)**: whether the anti-spam floor stays reward-proportional (`Fl ∝ R`, decaying 3 413× to the permanent tail floor of 20·`C_q` atomic/byte) or moves to an absolute/recalibrated basis. New derivation scope with its own pre-registered criteria — not resolved by §5.2, which inherits the decay by construction. **FL-R12′ SIGNED at round 8 retires the genesis-blocking escalation**: the reward-proportional floor now has a permanent nonzero terminal value instead of reaching 0, so this is a calibration round (is 20·`C_q`/byte the right permanent floor for a chain whose stakers store what it admits?), not a security-budget-existence question | **decision required — own round, criteria first; non-blocking (gate satisfied by the FL-R12′ signature; reverts to genesis-blocking if the direction reverses to the cap)** | minted at review round 2; recalibrated at review round 4 |
| FL-R14 | **Persisted accumulator width — RULED (b) by the maintainer at review round 4, in-channel: keep `u64` persisted.** Rationale as ruled: the binding bound is not the LMDB column but the genesis-frozen **64-bit range-proof width** (`shekyl-bulletproofs` `prove_plus`, commitments in `[0, 2⁶⁴)`) — a `u128` accumulator cannot help a chain whose outputs cannot provably exceed 2⁶⁴ atomic; it would be a check that can't be the first to fail. Build obligation: encode the ≈ 89 750-year bound as a **build-time assertion** over `(tail × blocks_per_year)` with the range-proof width named as the reason, so a re-parameterization (bigger tail, fewer decimals) fails loudly. Documented failure mode the assertion guards: accumulator wrap **un-saturating `remaining`** (wrapped small `ag` → huge `remaining` → curve reward resumes) | **RULED (b)** | ruled in-channel at review round 4 |
| FL-R15 | **Rename sweep (FL-R12′ implementation obligation):** `money_supply` → asymptote-class name reaches `config/economics_params.json`, the codegen, engine-core consumers, the census rows, and every doc naming it — each hit classified asserts-is / records-was / describes-a-closed-hazard before editing (census + CHANGELOG hits are legitimately records-was). **Method note (reusable):** a name sweep finds `MONEY_SUPPLY`; only a *jobs enumeration* — emission input, burn-ratio denominator, activity invariant, headroom operand — reveals that two of the four jobs are **assertions that the cap holds**; that enumeration is what surfaced FL-R16, and it is the instrument, not the name list **BUILT on `feat/fee-ladder-impl-2`:** the JSON key, both codegen paths, the Rust field/const surface (incl. the engine snapshot's `emission_curve_asymptote_atomic`) and the C++ macro (`SHEKYL_EMISSION_CURVE_ASYMPTOTE`, rule 93 prefix). Behaviour unchanged, and observed so rather than asserted — the parameter digest hashes values at fixed byte offsets, not field names, so its tests passed unre-pinned, and `--fee-ladder`/`--stage2` are byte-identical across the rename. Docs classified as prescribed; the one hit deliberately left alone is `blockchain.cpp`'s quotation of the inherited Monero rationale, where the old name is *quoted text* rather than a reference | **record — BUILT** | minted at the FL-R12′ direction; guard dispositions re-minted FL-R16a/b/c at review round 4; built at impl-2 **Digest sequencing, corrected against what happened (`CLIENT_VERSION_CONSTANTS_VALIDATION.md` §3.12 (ii)):** that note predicted "VC-1 widens first, this rename re-pins". **The order flipped** — the rename landed on `dev` while VC-1 sat unmerged, so VC-1's own merge is what re-pins, and the pinned literal now lives in `rust/shekyl-rpc-types/build.rs` (moved there by VC-R5 so the failure can print the computed value). Expected red, not a broken build. **And the two digests over this file disagree about this rename, both correctly:** the parameter digest hashes values at fixed byte offsets and is name-blind, so it passed unre-pinned; `CONSENSUS_CONSTANTS_DIGEST` canonicalises `key value` pairs and is name-sensitive, so it moves. A key is part of the binding for an identity check (every generator reads it by name), and is not part of it for a fixture-lineage check. Two instruments, two jobs, one file. |
| FL-R16 | **REJECTED AS WRITTEN at review round 4 and re-minted below.** The original row's headline claims did not survive source: `economics_differential.rs:145` is `#[cfg(test)]` fixture replay (`engine/mod.rs:288-289`), not a live consumer; `ActivityMetric::new` has **zero production constructors** on `dev`; the consensus burn path (`blockchain.cpp:1804` → `compute_fee_burn` → `calc_burn_pct`) never touches it, so "taking the burn's activity input down" was false; and the date conflated tail *onset* (~yr 65) with *exhaustion* (~yr 73) — `circulating > asymptote` first occurs at exhaustion. Kept as the record of the defect: three relayed claims entered a §8 row unverified | **superseded by FL-R16a/b/c** | rejected at review round 4 |
| FL-R16a | **Past-asymptote error arm (BUILD-BLOCKING):** `base_block_reward`'s `AlreadyGeneratedExceedsSupply` (`emission.rs:61`) is unreachable-by-design today and load-bearing wrong under the accepted direction. Consequences if the ruled accumulator ships with the arm intact, both at exhaustion ≈ yr 73: (i) the 5-arg estimate path (`blockchain.cpp:4541-4544`) errors → falls to the 10 000-SKL `BLOCK_REWARD_OVERESTIMATE` placeholder → `fee_policy.rs` refuses that snapshot **by design** → **no wallet can quote a fee**; (ii) `get_current_fee_per_byte` (`:4448-4453`) returns its failure-arm 0 → `check_fee` rejects everything → **the mempool refuses every transaction** (`kept_by_block` excepted). Removal ships with the FL-R12′ implementation | **decision folded into the FL-R12′ build** | minted at review round 4 |
| FL-R16b | **`ActivityMetric::new` cap guard (`activity.rs:124`): non-blocking API cleanup.** False under the accepted direction, but fixture-test-only today — remove with the rename sweep, not on the build's critical path. **BUILT on `feat/fee-ladder-impl-2`:** the check and its `CirculatingExceedsSupply` discriminator are gone, and the test flipped to assert *acceptance* past the asymptote (observed red against the guard first) so the new semantics are asserted rather than merely un-asserted. `EMISSION_CURVE_ASYMPTOTE`'s docstring lost the rationale that cited this guard; the constant's surviving bound-assertion is FL-R14's build check on the u64 headroom *above* the asymptote — the opposite direction | **record — BUILT** | minted at review round 4; built at impl-2 |
| FL-R16c | **Burn-ratio semantics past the asymptote:** `calc_burn_pct`'s `supply_ratio` (`burn.rs:76-78`) is unsaturated — exceeds 1.0 after exhaustion, drifting the burn toward `burn_cap` (≈ 0.0037%/yr issuance scale, negligible but unnamed). Disposition: saturate at `SCALE`, one line. And the sweep must not walk past the pre-existing definitional bug: `circulating_supply = already_generated_coins` (`blockchain.cpp:1787`, `:2074`) is **gross emission ignoring burn** | **record — binds the implementing PR** | minted at review round 4 |
| FL-R17 | **Rung count — SIGNED (a): THREE TIERS. Maintainer, in-channel, review round 7** ("sign it as three tier"). Rationale as signed: (i) **no privacy argument applies to the default case** — the default bucket is the majority set and its users bear no meaningful reduction (defaulted model: the standard bucket at ×1.25, §4.7); (ii) **the non-default case does not significantly degrade privacy** — a smaller set is still, arguably, much *larger* than Monero RingCT's ring-16, the de facto standard. (iii) The ruling's interpretive frame, in the maintainer's words: the privacy cost of a tier is *a bounded per-transaction candidate-set reduction for anchored attacks, with no linkage primitive to amplify it under FCMP++ — the kind of cost a proportionality judgment handles, not the kind the priority order was written for*. This frame *reconciles* rather than contradicts the stake-quorum rejection (the hierarchy's canonical privacy-wins ruling): there the cost was **structural and unbounded** — a per-persona uptime log growing without ceiling — so the lexicographic ordering applied; here it is **bounded, once per anchored transaction**, so proportionality applies. Same hierarchy, two instruments, selected by whether the cost is bounded — read together, the two rulings are one position. The round's supporting arithmetic for (ii): a priority transaction's anchored candidate set is `W/20` for an anchor window of `W` transactions, above ring-16 for any anchor looser than `W = 320` txs — at baseline volume, any anchor wider than ≈ 6.4 blocks (~13 minutes); tighter time-windows come with higher volume, which scales the set back up. Tier contracts and the default are §5.5. **Candidate (b) REJECTED; rule-21 reopeners as set by the maintainer at round 7, superseding the round's drafted three:** (r1) **FL-C4b's already-registered mechanism** — any rung whose measured mainnet usage share falls below 5% over a window is deleted or explicitly ruled an emergency lane; it needs no new row, and it is what retires priority if "many people use it" proves wrong; (r2) **any transaction-format or spend-proof change that introduces an on-chain way to relate two transactions** — the no-linkage-primitive premise is what makes the cost bounded, so its loss reopens the fee-tier disposition itself. *Method note (steering, round 7): r2 is anchored to the premise the argument rests on, not to a magnitude the argument produced — a threshold reopener invites argument about whether the number was crossed; a premise reopener either holds or does not, checkable by reading the format. Tie reopeners to assumptions, not magnitudes.* The median-dynamics gate lapses for this decision; W8 re-homed to FL-D7 | **SIGNED (a) — three tiers** | signed in-channel at review round 7 |
| FL-R18 | **The anonymity premise this row rests on was examined and found EMPTY. There is no harm here for a mechanism to fix, and (a) — accept as bounded — is what remains, not an option chosen over others on cost.** *(Provenance, stated precisely per round 4's standing rule for this table: **COUNTERSIGNED on (a) in-channel and relayed** through the umbrella lane, 2026-09-06. That is a relayed countersignature, not an in-tree one — no approving review or maintainer commit carries it — and the row says so rather than letting a relay read as a signature.)* **The premise:** a served fee flipping faster than 240 blocks was assumed to shrink the cohort a transaction hides in — the ground on which this row was surfaced (round 12) and briefly ruled (c), a minimum-dwell floor (round 13). **The refutation, both legs verified in this tree (§4.5b):** (1) `reference_block` travels **in the clear** on the wire with an admissible age of 5–100 blocks, exposing construction time far more finely than a 125–429-block fee flip — and making the reference-block cohort *smaller* than the fee cohort §4.4 set out to protect; (2) `C_q` is a deterministic function of public chain state, so every conforming wallet at a height posts the same rate and the fee is **redundant with the block that carries it** — a fact this document already asserted in its own W3 row while §4.4 built a gate on its opposite. **Redundant data leaks nothing, so there is nothing to protect and nothing to fix.** The maintainer's own statement of the finding, which is the row: *`C_q` is deterministic from public chain state, so every conforming wallet in a window computes the same value and an observer derives it from the block regardless; the fee is redundant with what the block already discloses.* **What survives is not anonymity:** the quote-then-broadcast rejection race (measured, §4.5b — and **disposition-independent**: every quantized served map lands within 22–39 thin-margin cells of 800, the §7 band being neutral and a dwell floor modestly worse; minted as **FL-R19**), and plain user-facing unpredictability. **Consequently the mechanisms are moot, not out-competed:** (b) a wider band, (c) the dwell floor, and (d) FL-D6 smoothing were each proposed to close a harm that does not exist. **(c) additionally fails on its own terms**, and that measurement stands whatever the premise did: no candidate `N` closes the cells, because a dwell floor is a DELAY in a feedback loop and delay destabilises — flip rate falls while oscillating-cell count RISES 14 → 101 (§4.5a). **Nothing ships and no rework reaches the bundle**; `fee_correction_quantized` is unchanged. *(Post-countersignature implementation note: the crate function is indeed unchanged, and #640 review cycle 5 removed the band from the SERVED path. Round 17 RULED that the band stays and is restored — see FL-R3 — so this clause stands as written about the mechanism, and the served-path gap is an implementation item with a named owner, not a reopening of this row.)* **Kept, because they are findings independent of the disposition:** FL-C4a's re-grounding — itself corrected at round 15, and now **not an anonymity criterion at all** (§1.4 note) — and the estimate clamp's measured role (§5.2). **How this happened, on the record rather than smoothed:** four layers of threat model were built on the premise without anyone asking what the leak was | **(a) COUNTERSIGNED — the premise is refuted, so nothing remains to mechanise (relayed countersignature; see provenance)** | surfaced round 12; ruled (c) round 13; premise refuted round 14; residual corrected round 15 |
| FL-R19 | **Quote-to-broadcast rejection race — RULED (b): clamp the served economy rung with a fixed margin above the unbuffered relay floor.** *(Countersigned in-channel and relayed 2026-09-06; a relayed countersignature, not an in-tree one.)* **The threat, stated properly — ADVERSARY: NONE.** This is a **liveness** failure, not a disclosure: nothing leaks, nobody is watching. *Event:* the short-term median contracts between construction and broadcast, raising the relay floor above the already-quoted fee, and the relay refuses the transaction. **Three conjuncts must all hold:** (i) the construction-to-broadcast gap spans **at least one block** — the median cannot move inside a block interval; (ii) the **short-term median is the binding term** (below the long-term effective median), i.e. the quiet-chain case; and (iii) the state sits in the thin-margin band — **25 of 800 swept served-map cells**, concentrated at the widest median and oldest age (§4.5b; the ruling quoted 22, the banded map, before #640 removed the band from the served path — 154 before the round-16 instrument correction and 49 before #640 re-measured against the shipped owner). *Consequence:* a refused broadcast, recoverable by re-quoting — **no fund loss, no disclosure.** **Why (b) and not the others:** **(d) re-quote at broadcast is REFUTED, not merely unchosen** — `rv.txnFee` is an **operand of `shekyl_verify_ct_balance`** (`src/fcmp/ct_semantics.cpp`, both the standard site and the bond-post variant), so the fee closes the commitment sum and re-quoting means **re-constructing and re-signing**. For a hot interactive wallet that is a no-op dressed as a fix (construction and broadcast are seconds apart and the median cannot move in that window); for the flows that ARE exposed — offline signing, hardware confirmation, batched or scheduled sends — re-signing at broadcast is precisely the expensive round trip the failure would have cost anyway. **It helps the population that does not need it and cannot help the one that does.** **(c) re-deriving the relay floor with the ladder stays open, but NOT HERE**: legitimate to want at the cutover (CEN-M3 / FL-D2), and it must not be justified by this race. **(a) accept** is what (b) improves on at negligible cost. **BINDING IMPLEMENTATION CONSTRAINT, not advice: the margin MUST be a fixed deterministic multiplier — never randomized, never per-wallet.** A per-wallet or randomized margin makes the quote no longer derivable from chain state and manufactures exactly the fingerprint FL-R18 established does not otherwise exist. **Why it is cheap:** it binds only where the clamp binds, so the **775 of 800 cells above the thin band pay nothing** (the ruling quoted ~646 at 1.29×, derived from figures that have since been re-measured three times; against the shipped owner and the shipped no-band served map the median margin is 2.10× and 25 cells are thin); the overpay is bounded and small in absolute terms on a low-fee chain; and determinism is preserved by the constraint above. **SIZING — the acceptance criterion is PRE-REGISTERED here, before the numbers exist: choose the margin to cover the plausible median contraction over the p95 construction-to-broadcast gap for the OFFLINE-SIGNING flow.** And the instrument is named, including what it is NOT: the refusal RATE cannot size this — these traces are structurally blind to it and that blindness is the finding, not a zero (§4.5b). The quantity that can see it is the **construction-to-broadcast gap distribution across real wallet flows**, which is wallet instrumentation rather than chain simulation and therefore **not this lane's measurement to take**. If that distribution turns out sub-block for essentially every flow, **the margin may be nominal** | **RULED (b) — margin fixed and deterministic; sizing criterion pre-registered, gap distribution owed by the wallet lane** **UPDATE 2026-09-10 (§11):** **RE-RULED — superseded by FL-R23.** Sizing premise void: there is no offline signing (decision log 2026-09-07); the gap is one hot session, 0–2 blocks; no distribution is owed and no margin is paid. The liveness threat model stands and is restated at §11.1 item 8. | minted round 14; ruled round 16 |
| FL-R20 | **The relay floor tracks `C`: `F(h) = R·C(h)·w_ref/M²`, raw, one formula for every regime (`C < 1` lowers it), 720-block SMA operand, 0.95 deleted.** Still relay policy; `kept_by_block` exempt; Q9 (no consensus fee floor) untouched. §11.2 | **RULED in-channel 2026-09-09/10** | none — FL-D2's CEN-M3 routing discharged (§11.2 FL-R21) |
| FL-R21 | **Quantizers deleted:** `quantize_pow2_ceil`, `fee_correction_quantized`, hysteresis step/fold/settled, `MIN_REPRESENTABLE_C`, the `fees[0]` clamp, `round_money_up_2` on the served path, the §10 instrument. FL-R3 CLOSED premise-refuted; FL-R6 identity; FL-D2 CLOSED; FL-D6/D8 moot; FL-R3-STORE demoted; §10 closed as record. §11.2 | **RULED in-channel 2026-09-09** ("What are we making this so complicated for?") | none |
| FL-R22 | **Wallet pays exactly the served rung — no pad, fixed or drawn.** Path recorded: random pad proposed (FL-C1 overrule quoted) → withdrawn on the failure-mode analysis ("The safety argument won me over"; FL-C1 stands, premise refuted) → fixed pad → superseded by FL-R23. Temporal link of a deterministic fee accepted as inherent ("ALWAYS going to have a temporal link"). §11.2 | **RULED in-channel 2026-09-10** | none |
| FL-R23 | **Lookback-min admission:** `fee ≥ mask_round_up(weight · min{F(h′−k) : 0 ≤ k ≤ G})`, `G` = 5 (hot-session gap 0–2 + network height spread 2 + 1 slack; the identity is per receiving node — review A-1 2026-09-10 corrected the first draft's `G` = 3). A quote at `F(h)` inside the gap is admitted by identity; the 2 % buffer and 0.95 deleted (weight model is byte-exact, §11.1 item 9). Cost = grace = worst `G`-block rise (FL-E3). Predicate lands in Rust behind FFI (rule 20). §11.2 | **RULED in-channel 2026-09-10** ("I agree with the math"); **spec amended at review 2026-09-10 (A-1 `G` = 5 per-node; A-2 weight-gate property test + `RELAY_ADMISSION_SLACK_BP` = 0 pin; A-3 reopening clause: reopens if any per-block-response operand enters `F`)** | none — relay policy |
| FL-R24 | **SMA resolution for the floor operand:** (i) integer `tx_count_sum/720` as shipped — the 1/V tick is a grace cost under FL-R23, a quote-quality question only; (ii) exact `(tx_count_sum, baseline·720)` via the scale-invariant ratio functions — floor-only breaks FL-V1 by ≤ one tick; reward-and-floor is a consensus change to `M_r`'s operand (own row, rule 07). Decision rule pre-registered §11.5 FL-E3. §11.2 | **RULED in-channel 2026-09-10 ("accepted/agree"): (ii) exact SMA for reward AND floor** — the FL-E3 rule fired (integer tick 307 bp at age 30, §11.7) | **consensus row** (change to `M_r`'s operand resolution; pre-genesis; opened by the implementing PR, rule 07 evaluated there) |

Signatures are recorded per-row with their provenance (in-channel, review
rounds 4–8); this line remains for any wholesale countersign the
maintainer chooses to add: ________________

## §9 Deferrals — each with rule-21 reopen criteria

| # | Deferred | Named blocker | Reopen when |
| --- | --- | --- | --- |
| FL-D1 | ~~Post-mining-era block-size governance~~ **CLOSED AS ANSWERED at round 8**: FL-R12′'s signed composition abolishes the `R = 0` era this row deferred to, and places the penalty AFTER the floor — the tail is penalized like any other reward, so the governance lever never dies. (Had the penalty composed before the floor, this row would have been *undeferrable*: the failure state would arrive at tail onset and never leave.) | *Historical (pre-signature) reopeners, retained as record:* (a) any round touches tail-era economics, or (b) the V4 lattice-only transition round opens | Closed — residue is the FL-R13 calibration of a permanent ~20·`C_q`/byte floor, not a governance vacuum |
| FL-D2 | Relay-floor re-derivation (scale `get_dynamic_base_fee` by `C_q`) | CEN-M3 is a queued census-R2 row; ruling it here would create the double-ratification §0.1 forbids **UPDATE 2026-09-10 (§11):** **CLOSED** — FL-R20 is the re-derivation (`F = R·C·w_ref/M²`); the CEN-M3 routing is discharged and the census row's formula text is carried by the implementing PR (§11.6). | *First criterion FIRED (the §0.1 sequencing landed at round 2; both resume conjuncts satisfied at round 8):* the item is routed, not reopened here — it lands in CEN-M3's resumed round. Early trigger unchanged: the clamp observed binding in > 50% of mainnet estimate calls over a 30-day window (evidence the floor, not the ladder, is setting prices) |
| FL-D3 | A fourth tier, if UX ever wants one | No engine tier addresses one (FL-V3: `Elevated` has zero production callers); a rung without users is fingerprint surface | an engine/GUI round proposes a user-facing tier with a predicted ≥ 5% usage share under FL-C4b's test |
| FL-D4 | Zone value (300 000) and the 1.7×/×50 clamps | CEN-G6b/G6 own them; this round consumed them as boundary (§1.8) | census-R2 may resume (both §0.1 conjuncts satisfied: FL-R12′ signed, red-test discharged); FL-R11 records the partial discharge so R2 inherits a smaller question |
| FL-D5 | Fee-floor basis derivation (FL-V11 / FL-R13) — whether `Fl ∝ R` survives a 3 413× reward decay as the anti-spam floor, on a chain where stakers store what the floor admits | Its own pre-registered round: criteria must be committed before the floor model is chosen | Open on its own merits (FL-R12′ signature satisfied): the floor's long-run role is the *permanent tail-era floor* and the genesis-blocking escalation is retired; the round opens as FL-R13's calibration |
| FL-D6 | Fee-variance smoothing pool (declined as a floor at the FL-R12′ direction; may still earn a place as *smoothing*, never as the security floor) | Post-genesis per the accepted direction — no pre-genesis blocker exists once the tail is the floor **UPDATE 2026-09-10 (§11):** **moot** — nothing to smooth once the snap is gone (FL-R21); the tail-onset reopen no longer has a subject. | Design reopens **before tail onset** (by height ≈ 60·`BLOCKS_PER_YEAR`, five years ahead of the ≈ year-65 tail entry), or **early** if over any rolling 90-day mainnet window the 10th-percentile day's miner fee income falls below 25% of the window median (the dormancy signal the declined pool was meant to paper over) |
| FL-D7 | W8: miner fee-rank ordering leak — block position reveals fee rank under any multi-rate ladder, and FL-R17's three-tier signature keeps it live | Under a ladder a miner has a *legitimate* reason to order by fee, so inclusion order cannot be made a checkable rule without breaking the fee market — the constraint W8 identified is only available under uniform rates | (a) any FL-R17 reopener fires (single-rate reconsidered ⇒ the checkable rule becomes available); (b) the relay/P2P-3 round takes inclusion-ordering scope and finds a ladder-compatible mitigation (e.g. intra-block shuffle of same-rate transactions, which three tiers still permit within each tier) |
| FL-D8 | **Boundary-cell OCCUPANCY: what fraction of chain TIME is spent in the cells where `C` sits near a pow2 boundary.** A measurement deferral, not a design one — nothing is being postponed except taking a number. Every disposition that has turned on flicker argued it from **cell count** — how many of the 800 swept cells oscillate — and cell count is a property of the SWEEP GRID, not of the chain: it says how much of the parameter space flickers, never how often anyone is standing there. Three dispositions have now rested on that unknown (FL-C4a's dwell gate, FL-C7's residual, FL-R18's acceptance of it as bounded) and FL-R3's restoration is the fourth. The quantity is occupancy-weighted flicker: over drift-honest traces, the fraction of blocks whose `C` lies within the band region, and the flip rate weighted by it **MEASURED at round 18 (§10.10), and it selected `P`**: over the dwell ensemble, boundary occupancy reaches **741‰**, mean residence per visit **up to 637 blocks**, max residence **13 597 blocks**. C10-4's rule — `P` must exceed expected residence — therefore rejects `P` = 60 and 240 and selects **720**, independently the natural ceiling since the fold cannot outrun the 720-block average feeding it. No candidate spans the worst single visit (≈ 19 days at 120 s); that residual is the `1/P` first-step effect §10.2 prices, recorded not left to be discovered. **This closes D8 as an owed measurement.** | Not owed by any current disposition. FL-R3 is ruled on the band's own record and does not wait for this; the round-16/17 figures were sufficient for every decision taken. It is registered because the unknown has been load-bearing four times and the argument gets re-run from scratch each time **UPDATE 2026-09-10 (§11):** **moot** — no pow2 boundary cells exist to occupy (FL-R21). Round 2b took the number anyway (`/tmp/fl_r3_round2b.summary`); it is a measurement of a deleted mechanism. | **Due the next time a disposition turns on flicker** — any reopening of FL-C4a, FL-C7, FL-R18 or FL-R3, or any proposal to change the quantization rule, the band margin, or the served map. The point of the row is that the fifth occasion reaches for a number instead of an argument. Instrument: the existing drift-honest traces already evolve the state needed; this is an added statistic, not a new model |

---

*Round instrument: `rust/shekyl-economics-sim/src/fee_ladder.rs`
(`--fee-ladder`). Pre-registration commit precedes the instrument in this
branch's history — that ordering is the pre-registration register, stated here so a
later reader sees method, not accident.*

---

## §10 FL-R3 restoration — the time-grid round (CLOSED as record — superseded by §11)

**Status:** CLOSED as record, 2026-09-10 — superseded by §11: the snap this round's band smoothed is deleted (FL-R21), so there is nothing left to restore. Rounds 1, 2 and 2b ran to completion and their figures stand as measurements of a road not taken (§11.3); no §10 identifier (C10-*, R2-E*, R18-M*) is worked further. §10.15 is not written — round 2b's selection was made moot before its results were read (`/tmp/fl_r3_round2b.*`, 2026-09-09). Text below is the round as it stood.

*Original status:* OPEN. Opened 2026-09-08 against `dev` `c1709cf2f`; round 2
opened 2026-09-09 (§10.12). This round
exists because FL-R3 was RULED at review round 17 — the hysteresis band
**stays** and FL-R3 closes by **restoring it to the served path** — and
the ruling put the restoration on the time-grid branch rather than
leaving it to the implementing PR. Rule 26
(`26-sub-pr-design-discipline`) is cited: the surface is
consensus-adjacent, crosses the FFI, and is designed before it is cut.

### §10.0 Jurisdiction — what this round may and may not decide

**May not.** The band stays (ruled). `C_q` is not persisted as chain
state (ruled). The two binding constraints are inputs, not questions:
the band remains a **pure function of chain state**, and it keeps a
**single owner**. A proposal that acquires per-node state does not
restore FL-R3, it repeals FL-R18 — the row says so and this round
inherits that.

**May.** The *shape* of the previous value: grid period, fold depth,
evaluation cost, reorg behaviour, and where the fold lives across the
FFI. These are the four questions `blockchain.cpp` already names at the
call site, and they are this round's agenda.

### §10.1 Pre-registered decision criteria

**Registered before the instrument's grid arm exists**, per the same
mandate §1 carried. The pre-registration commit precedes the instrument
commit in this branch's history; that ordering is the register.

- **C10-1 — restoration is measured against FL-C7's ratified banded
  figures, not against "better than today".** Restored means the served
  map's worst boundary-cell transition count returns to the banded order
  (ratified: worst 24, 14 boundary-parked cells) rather than the served
  un-banded 1 161. A result between the two is a partial restoration and
  is reported as one, with the number, not rounded up to success.
- **C10-2 — dwell must not regress.** The FL-C4a dwell gate (bar 240;
  banded 446, un-banded 464) is insensitive to the band either way. A
  grid that *lowers* dwell below the bar fails regardless of what it does
  for boundary flicker.
- **C10-3 — a per-query cost budget is a gate, and it is measured on the
  COLD path.** The restoration must not make a fee quote cost more block
  parses than the un-banded path does today (one `get_tx_volume_avg`).
  **The budget is met by the cold, from-`h₀` computation alone; no memo
  may be counted toward it** — see §10.6 for why counting one would
  reintroduce exactly the property round 17 rejected. This is what makes
  the single-scan shape mandatory rather than merely preferable. Any
  shape exceeding the budget on the cold path is BLOCKED on the
  storage-lane per-block tx count (§10.4), and the FL-R3 row must name
  that blocker rather than implying it (rule 22).
- **C10-4 — the grid period `P` is selected from measurement, not
  taste.** `P` is chosen from the §10.4 cost table together with FL-D8's
  boundary-cell occupancy. Neither alone is sufficient: cost bounds `P`
  from below, occupancy says whether the residual `P` leaves is worth
  paying for.
- **C10-5 — pre-registered reading of the grid-only arm (§10.3 C).** If
  grid-only matches the banded map on C10-1 within one transition, the
  finding is *the grid subsumes the band's boundary job* and it goes to
  the maintainer as a question, because the band staying is ruled and
  this round may not retire it. If grid-only does not match, the finding
  is *the band is doing work the grid cannot do* and the fold (§10.3 B)
  is the shape. Both readings are written here before either is
  observed — the failure mode this guards is that both arguments drift
  toward the decision already taken.

### §10.2 The recurrence, and why both earlier attempts failed on it

`C_q(h) = f(C(h), C_q(h−1))` is a recurrence, and that is the whole
difficulty. Two attempts are on the record, each archived rather than
merely described:

- **Daemon-local remembered value.** `blockchain.h` carried
  `mutable uint64_t m_fee_correction_cq{0}`, threaded as `prev_cq`. It
  makes the served rate track *the process's query history*: two nodes at
  the same tip serve different quotes depending on what they were asked
  before. Archived at tag
  `archive/fee-ladder-r12-impl-rejected-2026-09-08`, which exists so this
  round does not rebuild it.
- **Previous block's unseeded snap.** A one-step approximation rather
  than the recurrence, and it inverts the result.

**The second failure has a consequence this round must carry.** A fold
that starts at a grid anchor `h₀` with no history takes its first step
from `snap(h₀)` — which *is* the unseeded one-step shape. The grid does
not eliminate that flaw; it **confines it to the first block of each
grid cell**. So the flaw's weight falls as `1/P`, which is a lower bound
on `P` independent of cost, and is the reason the "seed at `h₀`, single
step straight to `h`" shape is **not** a candidate below: it skips
`h₀+1 … h−1` and is the rejected shape with a longer lever.

### §10.3 Candidate shapes

**(B) Fold over a fixed window from the grid anchor — the ruling's named
shape.** `h₀ = h − (h mod P)`; `C_q(h₀) = snap(C(h₀))`; then iterate
`hysteresis_step` over `h₀+1 … h`. Pure function of `(chain state, h)`,
bounded by `P` evaluations. This is the shape to beat.

**(C) Grid-only, as INSTRUMENTATION.** Evaluate the snap at `h₀` and
serve it for the whole cell — the quote changes at most once per `P`
blocks, so a grid alone produces dwell `≥ P` without any band. This is
**not proposed**; the band staying is ruled. It is built as a sim arm so
the measurement exists, because the question "does a time grid already
do the band's boundary job" will otherwise be argued rather than
answered, and C10-5 pre-registers how each outcome reads.

### §10.4 Cost — the crux, and where the round is blocked

`get_tx_volume_avg(h)` walks `SHEKYL_TX_VOLUME_WINDOW` = 720 blocks and
**parses each full block blob** to read `tx_hashes.size()`. It is
memoized, but on a **single entry** keyed `(top_hash, height)`. A fold
evaluating `D` distinct heights therefore thrashes that memo.

| shape | block parses per quote | note |
|---|---|---|
| today (un-banded) | 720, memoized to ~0 on repeat | the budget C10-3 protects |
| naive fold, depth `D` | `D × 720` | memo thrashes; at `D` = 60 that is 43 200 parses **under the blockchain lock** |
| single-scan fold | `D + 720` | the `D` windows overlap; their union is one contiguous range |
| storage-lane per-block count | ≈ 0 parses | the structural fix |

**The naive column is disqualifying, and it is why this is a round and
not a patch.** The single-scan column is the interesting one: consecutive
heights share 719 of their 720 blocks, so the union of all `D` windows is
the contiguous range `(h₀ − 720, h]` — scanned **once**, with the rolling
means and the fold computed from one pass. That requires a different
shape at the boundary than "call the FFI per height" (§10.7).

**Two substrate facts checked rather than assumed.**
`get_block_already_generated_coins(height)` is a per-block LMDB field,
not a walk, so the other per-height input to `C` does not enter the cost
table. And the FFI already carries an array-marshal shape to inherit
(`shekyl_tree_hash(const uint8_t* ptr, size_t count, uint8_t* out)`),
so §10.7's single call mints no new boundary convention and inherits
that shape's rule-40 discipline.

**Named blocker, per rule 22.** If the single-scan shape cannot meet
C10-3's budget, FL-R3's restoration is BLOCKED on the storage-lane cheap
per-block tx count already queued in FOLLOWUPS — which this round would
promote from a nicety to FL-R3's critical path. That dependency is to be
stated in the FL-R3 row, with the measurement that decided it.

### §10.5 The grid period `P`

Candidates, with the reason each is on the list:

| `P` | wall time at 120 s | provenance | first-look objection |
|---|---|---|---|
| 720 | 24 h | `SHEKYL_TX_VOLUME_WINDOW` — the correction's own averaging window | fold depth up to 720; quote frozen up to a day |
| 60 | 2 h | ≈ the measured worst inter-flip dwell (≈ 125 blocks ≈ 4.2 h) | none yet — nearest to the dynamics being damped |
| 10 000 | ≈ 13.9 days | `settlement_epoch_blocks`, an existing consensus constant | **reject**: a fee quote frozen for two weeks is not a fee quote; reusing a constant whose job is settlement, not pricing, is coupling by coincidence |

Reusing an existing constant is attractive — it mints nothing and
inherits a ratified value — but only where the two jobs share a cadence.
Settlement and fee pricing do not, and the table records that rejection
so it is not re-proposed. `P` is selected per C10-4.

### §10.6 Purity: a memo is not held state, and the line is already drawn

The distinction this round leans on is **already in the tree**, at the
function whose cost created the problem. `get_tx_volume_avg`'s memo is
keyed `(top_hash, height)` and its comment states the reasoning: that
makes it *"a memoization of a pure function of chain state and NOT
daemon-local held state — every node at the same tip returns the same
value, and a reorg changes the top hash so the entry simply misses."*

The fold may be memoized the same way — keyed on chain state, verified
against a cold from-`h₀` path that is defined without it. The rejected
`m_fee_correction_cq` was keyed on *nothing*: there was no cold path it
approximated.

**But a memo cannot be counted toward C10-3's budget, and an earlier
draft of this section was wrong to imply it could.** The tempting shape —
advance the fold incrementally as blocks arrive — needs the fold state at
`h−1` under the previous tip, which the node only holds if it was
*queried* at `h−1`. Restart, a gap between queries, or a reorg all miss,
and the miss recomputes from `h₀`. So the amortized cost is **a property
of the query pattern, not of chain state** — which is the very axis the
ruling rejected `m_fee_correction_cq` on. A design whose cost argument
rests on that amortization has smuggled the rejected property back in
through the performance argument instead of the correctness one, where it
is harder to see.

Hence: the memo may save recomputation, never the cold path's cost, and
**C10-3 is measured cold**. The purity distinction survives; the cost
argument has to stand on the single-scan shape by itself.

### §10.7 Single owner across the FFI

Constraint (2) is not satisfiable by discipline alone here. If C++
iterates and calls the FFI once per step, **C++ owns the fold** — the
recurrence structure, its bounds, and its boundary behaviour would live
on the C++ side and the Rust owner would hold only one step. That is the
FL-R12′ shape inverted.

So: **Rust folds, C++ marshals.** One call carrying the bounded
per-height inputs, matching #640's marshal-only shape, under rule 40 (no
panic across the ABI; length-checked, total at the boundary). The
instrument's grid arm calls the **same** fold function — which makes
constraint (2) true by construction rather than by review, and is the
direct lesson of the drifted transliterated band that lost
`MIN_REPRESENTABLE_C`.

### §10.8 Reorg behaviour

A reorg shallower than `h − h₀` changes intermediate blocks and therefore
changes `C_q`. **That is correct, not a defect**: the value is a pure
function of chain state, so a different chain is entitled to a different
quote, and the memo misses because `top_hash` changed. Recorded because
"the quote moved after a reorg" will otherwise be read as instability.

### §10.9 What the instrument must produce

- The grid arm (B) and the grid-only arm (C), both calling the one owner.
- Per `P` candidate: worst boundary-cell transition count and parked-cell
  count (against C10-1), dwell (against C10-2), and evaluation depth
  distribution (against C10-3).
- **FL-D8 folds into this round's instrument, and its definition is
  pre-registered here** — otherwise the instrument returns a number and
  the round decides afterwards what it meant, which is the one criterion
  that picks `P`. D8 measures, over **the same drift-honest trace
  ensemble the round already sweeps** (the dwell grid's runs and the
  feedback grid's cells, unchanged so the figures compose with FL-C7's):

  - **"near a boundary" = the band's own flicker zone.** A height is near
    iff its raw `C` lies within `HYSTERESIS_MARGIN_MILLI` (3%) of a pow2
    boundary. The band exists to damp exactly that zone, so the band's
    own margin is the non-arbitrary definition of it.
  - **Two statistics, because the round's question is a comparison of
    two:** *occupancy* — the fraction of block-heights whose `C` is near —
    and *expected residence per visit* — how many consecutive blocks a
    visit lasts. Occupancy is the "how much chain time" half; residence
    is what says whether a grid of period `P` would span a typical visit
    or chop it.
  - **Reading, pre-registered:** `P` must exceed the expected residence,
    or the grid re-samples inside a single visit and the boundary
    behaviour survives the grid. Occupancy then says how much of the
    chain's life that case governs — i.e. whether the residual is worth
    the cold-path cost C10-3 budgets.

### §10.10 Round-1 instrument results

**Run at the branch tip; arms measured on the SAME feedback grid as
FL-C7 and FL-R18**, with both reference arms swept alongside so every
comparison below is within one measurement rather than against a figure
from another.

| arm | oscillating cells | worst tail transitions | thin-margin cells |
|---|---|---|---|
| `corrected-quantized-pow2-ceil` — **served today** | 20 | **1 161** | 25 |
| `...-ceil-hysteresis` — **the RULED banded map** | **14** | **24** | 22 |
| `grid-fold-p60` | 20 | 45 | 25 |
| `grid-fold-p240` | 20 | **24** | 25 |
| `grid-fold-p720` | 20 | **24** | 25 |
| `grid-only-p60` | 29 | 23 | 26 |
| `grid-only-p240` | 82 | 9 | 39 |
| `grid-only-p720` | 114 | 5 | 42 |

**C10-1 — PARTIAL restoration, reported as one.** `grid-fold` at
`P ≥ 240` reaches **worst = 24**, exactly the banded figure: the
oscillation's *amplitude* is fully restored from the served 1 161. But
**oscillating cells stay at 20 — the un-banded count — against the
band's 14.** Six cells oscillate under the fold that the band keeps
quiet, and the mechanism is legible: the band's memory is unbounded,
while the fold's resets at every anchor, so a cell whose quiet depends on
history older than its current cell loses it. C10-1 pre-committed to
reporting a between-result as partial with the number rather than
rounding it up, and this is that case.

**C10-2 — dwell does not regress.** 320 runs, 240 of them quantized, and
**exactly one** fails the registered gate — the same single failure the
sweep carried before the grid arms joined it. No grid arm fails.

**C10-3 — NOT MET on the cold path, by 1.33×.** *[**Corrected at round 2,
§10.12.1:** the depth below was read from the dwell grid, which ran only
the `P` = 240 arms; at the `P` = 720 that C10-4 selects the depth is 720
and the single-scan cost 1 440 — **2.0×**, not 1.33×. The disposition
(BLOCKED) is unchanged; the magnitude was wrong.]* Observed max fold depth
is **240** (= `P`, as `h mod P` predicts). Cold cost:

| | block parses per cold quote |
|---|---|
| today, one `get_tx_volume_avg` | 720 |
| naive fold, `D` = 240 | **172 800** — disqualifying, as pre-registered |
| single-scan fold | **960** |

960 against a 720 budget is **1.33×**, so the single-scan shape does not
meet C10-3 unaided. §10.4 pre-registered exactly this branch, so the
consequence is already ruled rather than argued now: **FL-R3's
restoration is BLOCKED on the storage-lane cheap per-block tx count**,
which takes both the 720 and the 960 to ≈ 0 and makes the fold free. That
item is hereby on FL-R3's critical path, not a queued nicety. The
alternative — accepting 1.33× on the cold path — is a maintainer call,
not this round's to make, and it is stated as such rather than assumed
either way. *[Round 2: the figure the maintainer is asked to accept or
refuse is 2.0×, per the correction above; the call itself is restated
with its options at §10.12.5.]*

**C10-4 — `P` = 720, and FL-D8 is what says so.** Measured over the
dwell ensemble: boundary occupancy reaches **741‰** (in the worst states
three blocks in four sit in the band's flicker zone), **mean residence
per visit up to 637 blocks**, and **max residence 13 597 blocks**.
C10-4's pre-registered rule is that `P` must *exceed* expected residence:

- `P` = 60 — fails (60 < 637), and it is the arm that measured worse;
- `P` = 240 — fails (240 < 637), despite scoring identically to 720 on
  the boundary axis;
- `P` = 720 — **passes** (720 > 637), and it is independently the natural
  ceiling: the fold cannot usefully outrun the 720-block average feeding
  it.

**No candidate spans the worst single visit** (13 597 blocks ≈ 19 days at
120 s). That is a bounded residual, not a blocker — a visit longer than
`P` is re-anchored mid-visit, which is the `1/P` first-step effect §10.2
already prices — but it is recorded rather than left for someone to
discover.

**The methodologically important result: `P` = 60's failure was predicted
twice, before it was run.** §10.2 derived it analytically (the unseeded
first step's weight falls as `1/P`, so small `P` re-seeds the flaw too
often) and C10-4 derived it from residence (`P` must exceed 637). Two
independent pre-registered lines named the same failing candidate, and
the instrument returned worst = 45 against 24 for the larger periods.
That is the pre-registration doing its job: the prediction was falsifiable
and was not adjusted after the fact.

**C10-5 — the grid does NOT subsume the band; the fold is the shape.**
`grid-only` trades amplitude for breadth in a way the band does not:
worst transitions fall (23 → 9 → 5) while oscillating cells climb
sharply (29 → 82 → 114). At `P` = 720 its signature — 114 cells, worst 5
— is within noise of FL-R18's rate-limited `n` = 720 row (102 cells,
worst 5), i.e. **grid-only reproduces the minimum-dwell floor's
signature, the mechanism round 14 WITHDREW** on measured grounds. So
C10-5's second branch is the one that fired: the band is doing work a
grid alone cannot do. **No question goes to the maintainer here** — the
arm was built so this would be answered rather than argued, and it
answered against itself.

### §10.11 Two instrument defects found by this round

**(1) The dwell gate was selecting its own subject from a display
string.** It filtered rows on `mode.contains("quantized")`. Two arms
serve a pow2-snapped map without that word in their label —
`served-rate-limited-n*`, which joined the dwell sweep at round 13, and
§10's `grid-*` arms — so **both were skipped by the gate entirely**, and
a new arm would keep being skipped without anything saying so. Replaced
with a structural `LadderMode::serves_quantized_map()`. Bringing the
previously-ungated arms under the gate revealed **no new failures** (still
exactly one), so nothing ratified moves on the substance — but the gate
now covers what it claims to.

**(2) §4's dwell-grid figure is re-derived: 240 → 320 runs.** Eight modes
× eight scenarios × five ages = 320, of which 240 are quantized (six of
the eight modes), against the previously recorded 240 total / 120
quantized. **This is the second time this figure has gone stale for the
same reason:** §4 already records that it "read 200 until the
rate-limited mode joined the dwell sweep at round 13 and the count was
not re-derived". A register figure derived from a mode list is invalidated
by every addition to that list, so it is corrected here **from the run**
rather than by arithmetic on the old number.

### §10.12 Round 2 (opened 2026-09-09): the cost figure at the selected `P`; the blocker specified; C10-1's residual put to measurement

Round 1 closed with C10-3 failed and FL-R3 blocked, and left three things
undone that a round can do without the maintainer: it measured the cost at
a `P` it did not select, it named the blocker without specifying what would
discharge it, and it explained C10-1's six lost cells by a mechanism it did
not test. Round 2 does those three. **Everything in §10.12.1–§10.12.4 is
written before the round-2 instrument is run**; the commit ordering on
`design/fl-r3-time-grid` is the register, as it was for round 1. Results go
in §10.13.

#### §10.12.1 Finding: the C10-3 figure was measured at the wrong `P`

§10.10 reads the cold cost off "observed max fold depth **240**". That
number is true and is the wrong one. The dwell grid — the only sweep that
reports `grid_max_fold_depth` — ran the grid arms **at `P` = 240 only**
(`fee_ladder.rs`, the dwell mode list), and the cost summary printed depth
for the two labels `grid-fold-p240` / `grid-only-p240` and no others. C10-4
then selected **`P` = 720** on the feedback grid, where depth is not
measured. The fold depth is `h mod P` + 1 (anchor inclusive), so at the
selected period it reaches **720**, and §10.4's single-scan formula gives
`D + 720` = **1 440** block parses per cold quote — **2.0×** the budget,
not 1.33×. The 1.33× recorded in §10.10, in round 18's record, and in both
FOLLOWUPS rows is the `P` = 240 arm's cost attributed to the `P` = 720
selection.

**Nothing ratified moves on the disposition** — C10-3 fails either way and
§10.4 pre-registered the consequence — but the *magnitude* is what the
maintainer was asked to accept or refuse, and it was understated by a
third. C10-2 has the same gap: "no grid arm fails the dwell gate" was
measured on the `P` = 240 arms, so dwell at the selected `P` is unverified.

**This is the third instance in one round of the same defect class.**
§10.11(1) was a gate selecting its subject from a display string;
§10.11(2) was a figure derived from a mode list that died on every
addition to the list. The cost line did both: a hard-coded label list,
naming an arm the selection had already moved past. The fix is
structural, not a corrected constant — the dwell grid runs every grid arm
at the selected `P`, and the cost line iterates over the arms actually run.

**Pre-registered expectation (R2-E1).** The re-run reports
`grid_max_fold_depth` = 720 for `grid-fold-p720` on the dwell grid. If it
reports anything else, the `h mod P` model in §10.2 is wrong and the cost
table is re-derived from what is observed, not from the formula.

#### §10.12.2 The blocker, specified — RECORD-AND-SPECIFY, not fix-in-C++

Round 1 named the blocker ("the storage-lane cheap per-block tx count") and
stopped. A named blocker with no specification is one the storage lane can
build wrong, or not at all, without anyone noticing — rule 22's "falsify
by" is unanswerable when nobody has written down what "it landed" means.
This section writes it down.

**The substrate has moved under the blocker since it was queued.**
`DAEMON_REDB_STORE.md`'s 2026-09-01 countermand rules the inherited C++
"not a base": genesis is redb-only, DRS-C ships no C++ refactor PRs, and
DRS-P0c's FIX-IN-CPP-FIRST default is **inverted to RECORD-AND-SPECIFY**.
So the shape this item was queued in — an LMDB field the C++
`BlockchainLMDB` writes — is the shape the countermand retires. The item
is a **requirement on `shekyl-chain-store`'s S-CHAIN-R surface**, and FL-R3
owes the store lane the requirement, not a patch.

**Requirement FL-R3-STORE (for `shekyl-chain-store`, S-CHAIN-R).**

- **What.** An O(1) per-height read `cumulative_tx_count(h)` =
  `Σ_{i ≤ h} |tx_hashes(i)|` — the count of **non-coinbase** transactions
  through height `h`, which is exactly the summand `get_tx_volume_avg`
  walks today (`blk.tx_hashes.size()`, `blockchain.cpp:2117`). Then
  `tx_volume_avg(h)` for any `h` is two reads:
  `(cum(h−1) − cum(start−1)) / (h − start)` with
  `start = h > W ? h − W : 0`, `W` = `SHEKYL_TX_VOLUME_WINDOW`, and the
  `h` = 0 / `cum(−1)` = 0 edges as the walk defines them
  (`blockchain.cpp:2055–2061`).
- **Layout precedent, not invention.** `mdb_block_info_4.bi_cum_rct` is a
  cumulative-at-write, differenced-at-read per-block counter
  (`db_lmdb.cpp`, `bi.bi_cum_rct = num_rct_outs; bi.bi_cum_rct +=
  bi_prev->bi_cum_rct`), pop-symmetric for free because the row goes with
  the block. The redb block row carries the same field in the same
  discipline. Eight bytes per block.
- **Consensus bit-identity gate (rule 47).** `get_tx_volume_avg` is not a
  fee-estimate convenience: it feeds `get_block_reward` inside
  `validate_miner_transaction` (`blockchain.cpp:1669`), i.e. **block
  validity**. A store read that disagrees with the walk by one at one
  height is a consensus split. The gate the store PR must carry: on a
  regtest chain containing empty blocks, a pop, and a reorg,
  `cum(h) − cum(h−1) == |tx_hashes(h)|` at every height **and** the
  derived `tx_volume_avg(h)` equals the blob walk's at every height. A
  gate that checks only the tip is not this gate.
- **Falsifier for the FL-R3 blocker (rule 22).** *Blocked on the store
  providing O(1) `cumulative_tx_count(h)` — falsify by
  `rg cumulative_tx_count rust/shekyl-chain-store` returning the read and
  its bit-identity gate.* Until that grep returns, the blocker holds; when
  it does, FL-R3's fold costs `2(D + 1)` field reads and **zero** blob
  parses at any `D`, and C10-3 is met with room to spare.

**The LMDB alternative, recorded so it is not re-derived.** Under the
countermand the default is *not* to add `bi_cum_tx_count` to
`mdb_block_info` (a `VERSION 12 → 13` bump, delete-and-resync,
`LMDB_SCHEMA.md` +8 B at offset 96). It is ~40 lines of C++ against a store
that does not reach genesis, so it is fix-in-C++ against DRS-P0c's
inversion. It is recorded here as the alternative the maintainer may
choose **if a banded quote on the current C++ daemon is wanted before the
Rust store lands** — e.g. for a testnet cycle — with its cost stated: the
field dies at redb genesis and the C++ PR must carry the same bit-identity
gate. It is a maintainer call (§10.12.5), not this round's.

#### §10.12.3 C10-1's residual — a mechanism claimed, so a mechanism tested

Round 1 explained the six cells the fold loses to the band as "the band's
memory is unbounded, the fold's resets at every anchor". That is a
mechanism, and rule 16's corollary says a mechanism asserted from the
design is a hypothesis until it is read at the implementation. Read at the
instrument, it sharpens into a **testable** claim with a consequence for
what C10-1 was asking:

**Claim.** In a cell where raw `C` sits inside the band's flicker zone for
the whole 3 000-block tail, the reference banded map's served value was
fixed by history *before* the tail — ultimately by the trace's initial
condition — and never moves. The fold re-anchors every `P` blocks with an
unseeded `snap(C(h₀))`, which lands on one side of the boundary or the
other according to where `C(h₀)` happens to sit, and the band then holds
that value for the cell. So in those six cells the fold's transitions
occur **only at anchor heights** — at most `⌈3 000 / 720⌉` = 5 in the
tail — and **no fold depth removes them**: a deeper fold moves the anchor,
it does not remove the anchor.

**Consequence if the claim holds.** The reference's 14 is not a quieter
mechanism than the fold's 20. It is the *same* mechanism plus infinite
memory of an arbitrary start — memory FL-R18 forbids a real node from
holding. Then **20 is the oscillating-cell count for any realisation of
the band that is a pure function of chain state**, and C10-1's target of
14 was unreachable by construction, not missed. The honest re-reading of
C10-1 is: *amplitude* restored (worst 24 = 24) and the residual bounded by
the §10.2 `1/P` first-step effect, already priced. That re-reading is
**not adopted here** — a round may not move its own pre-registered
target after seeing the result. It goes to the maintainer (§10.12.5) with
the measurement that supports or refutes it.

**Measurement, pre-registered.**

- **(a) Per-cell diff, fold vs reference.** For each grid-fold arm on the
  feedback grid: the cells oscillating under the fold and *not* under the
  reference (predicted: six for `P` ≥ 240), each cell's tail transitions
  (predicted: ≤ 5 at `P` = 720), and how many of those transitions fall at
  a height `≡ 0 (mod P)` (predicted: **all of them**). Also the reverse
  set — cells quiet under the fold but oscillating under the reference
  (predicted: none; a non-empty reverse set means the fold *damps* what
  the band does not, which would be its own finding).
- **(b) A deeper-fold arm, `grid-fold-p720-w1`.** Anchor one full cell
  earlier: `h₀ = h − (h mod P) − P`, depth ∈ [720, 1 440). **Prediction:
  oscillating cells stay at 20.** If they fall toward 14, the claim is
  false — the band's memory horizon is finite in practice and fold depth
  *is* a lever — and the round tables a depth-versus-cost trade instead of
  the re-reading above. This arm is instrumentation for the mechanism
  question only: its cold cost without FL-R3-STORE is ≥ 2 160 parses and
  it is not a candidate shape.

Both readings are written before the run. **R2-E2:** (a) all extra-cell
transitions at anchors, each ≤ 5, reverse set empty. **R2-E3:** (b) leaves
the count at 20. **R2-E4 (C10-2 at the selected `P`):** the dwell grid at
`P` = 720 adds no gate failure beyond the one pre-existing.

#### §10.12.4 The fold's owner and the FFI shape, pinned

§10.7 stated the principle — Rust folds, C++ marshals — and left the
signature to the implementing PR. A principle without a signature gets
implemented per-step "just for now". Pinned:

**Owner, landing on this branch.** `shekyl-economics::fee::hysteresis_fold`
— the §7 recurrence from an unseeded anchor over a slice of raw `C`,
returning `None` for an empty slice (there is no "no history" `C_q`; `0`
is what `fee_correction_quantized` *takes* as no-history, never what it
returns). The instrument's `GridCq` calls it, retiring the fold loop the
instrument carried itself — the same drift hazard that discharged declared
exception #3, closed the same way. A KAT pins `hysteresis_fold(&[c]) ==
hysteresis_step(c, 0)`: a fold of one is today's served value, so at every
anchor height the restored path and the interim path agree by
construction. This lands now because §10.7 requires the instrument to call
the owner and round 2's measurement must be of that owner; the grid period
and anchor rule do **not** land now — `P` is selected, not signed, and a
constant for an unsigned value is pre-provisioning (rule 21).

**FFI, for the implementing PR (after C10-4's `P` is signed and
FL-R3-STORE lands or the alternative is chosen):**

```c
/* h0 = h − (h mod P); P is owned in Rust with the fold. */
uint64_t shekyl_fee_grid_anchor(uint64_t height);

/* Fold the §7 band from the grid anchor to `anchor_height + count − 1`.
 * Per-height inputs, oldest first, both arrays `count` long:
 *   tx_volume_avg[i]     = Blockchain::get_tx_volume_avg(anchor + i)
 *   already_generated[i] = already_generated_coins at anchor + i
 * Rust derives σ, b, M_r and C per height from the shipped
 * EconomicParams (EconomicParams::default(), the build-generated set —
 * exactly as shekyl_fee_correction_quantized already sources it in
 * legacy_core.rs) and folds via hysteresis_fold.
 * Returns 0 and writes *out_cq; −1 on a null pointer; −2 when count == 0
 * or count > P (a fold longer than one cell is not this function).
 * count == 1 returns shekyl_fee_correction_quantized(…, prev_cq = 0)
 * for the anchor height — the identity the KAT pins. No panic across
 * the ABI (rule 40): every derivation clamps as fee_correction_quantized
 * does today, and hysteresis_step is total. */
int shekyl_fee_correction_grid_fold(uint64_t anchor_height,
                                    const uint64_t* tx_volume_avg,
                                    const uint64_t* already_generated,
                                    size_t count,
                                    uint64_t genesis_ng_height,
                                    uint64_t* out_cq);
```

C++ at `blockchain.cpp:4612–4631` becomes: anchor from the FFI, two array
reads over `[h₀, h]`, one call — and `prev_cq = 0` leaves the call site.
The array-marshal shape is `shekyl_tree_hash`'s (§10.4). Memoisation of
the fold, if any, is keyed `(top_hash, h)` exactly like `get_tx_volume_avg`'s
(§10.6) and counts for nothing in C10-3.

**Implementing-PR pre-flight (rule 26), written now so it is not
reconstructed then.** (i) Re-verify the call-site lines and the store
surface at PR open — both are cited by line here and lines move. (ii) Gates:
the anchor-identity KAT above; a pinned trace vector on which the FFI fold
equals the instrument's `grid-fold-p720` arm block-for-block (the
instrument and the daemon are then measuring one mechanism, which is what
constraint (2) means); the `count > P` refusal; FL-R3-STORE's bit-identity
gate if the store PR has not carried it. (iii) Scope: the fold, its two
exports, the C++ marshal, and the deletion of the `prev_cq = 0` literal.
Nothing else rides — §10.11's instrument fixes are already on this branch.

#### §10.12.5 What closes round 18, and who decides it

Round 2 leaves the round OPEN on three maintainer calls, each of which the
round has now measured or specified but may not make:

- **R18-M1 — sign `P` = 720** (C10-4's selection; the residence rule and
  the window ceiling agree). Signing it is what lets the anchor rule and
  `P` land in the owner.
- **R18-M2 — C10-1's reading.** If §10.13 confirms R2-E2 and R2-E3, the
  round asks the maintainer to close C10-1 as *amplitude restored, residual
  bounded by `1/P`, the 14-cell target unreachable by any chain-state
  realisation*. If either expectation fails, the round tables a
  depth-versus-cost trade instead and asks nothing yet.
- **R18-M3 — the blocker's disposition.** Default: RECORD-AND-SPECIFY —
  FL-R3-STORE goes to the store lane and FL-R3's wiring waits on its
  falsifier. Alternatives, both stated with cost: the LMDB
  `bi_cum_tx_count` field (§10.12.2; dies at redb genesis) or accepting
  **2.0×** cold on the interim C++ path (1 440 blob parses per cold quote
  under the blockchain lock, memoised to ~0 on repeat — against a budget
  C10-3 pre-registered and this round cannot relax).

With M1–M3 ruled the round closes; the implementing PR follows §10.12.4's
pre-flight. *(Round 2b, §10.14, adds R18-M4 — jurisdiction on a non-band
window filter, asked only if one measures dominant — and R18-M5 — the
human-time floor/ceiling and the `W`/`K` choice. It also puts a fourth
shape, the settled-anchor band, beside the fold; M1's `P` and M2's
reading are then taken on whichever shape §10.15 selects.)*

### §10.13 Round-2 instrument results — the fold arms

Run of the §10.12 instrument at `b8c2e270c`, 36 min on the contended box;
written after §10.14 was committed, so the round-2b pre-registration below
cannot have been shaped by these numbers. Scored against §10.12.3's
expectations as stated:

| expectation | stated | measured | verdict |
|---|---|---|---|
| **R2-E1** fold depth at `P` = 720 | 720; single-scan cold 1 440 | `grid-fold-p720` max depth **720**, `single_scan_cold_parses` **1 440**; warm arm depth 1 440 → 2 160 | **holds** — C10-3 is **2.0×**, §10.12.1's correction confirmed on the run |
| **R2-E2** the six extra cells' transitions all sit at anchors | off-anchor = 0 | `grid-fold-p720`: 6 extra cells, worst 4 transitions, **12 off-anchor**; `P` = 240: 18; `P` = 60: 16 | **FAILS** — see below |
| **R2-E3** the warm arm recovers none of the six | recovered = 0 | `grid-fold-p720-w1`: 6 extra, **0 recovered**, off-anchor 7 | **holds** — a deeper fold does not buy the cells back |
| **R2-E4** no new dwell failure | 1 pre-existing | 440 runs, 360 quantized, **1 fails** — the same row as the baseline | **holds** |

Also reproduced unchanged: banded reference 14 / 24; served ceiling 20 /
1 161; every fold arm at `P` ≥ 240 at 20 / 24; grid-only at 114 / 5 at
`P` = 720 (C10-5's reading stands); FL-D8 741‰ / 637 / 13 597.

**What R2-E2's failure means, stated without rescuing it.** §10.12.3(a)
predicted that the fold's six extra cells were *anchor-flip* cells, and
pre-registered the signature: their transitions would sit **at** grid
anchors. They do not — twelve of them at `P` = 720 fall inside periods.
The mechanism claim is therefore **not confirmed by the signature it
named**. What the run does show is consistent with a *reset* rather than a
*flip*: at each anchor the fold restarts from the unseeded snap, which can
land the band in the other state from the one the unbounded band holds;
the transition then happens mid-period, when `C` next crosses the margin
from that wrong state. That reading is offered as a hypothesis with its
own falsifier — **a band anchored where its state is history-free
(§10.14.2) should lose none of the six** — and it is exactly what round
2b's `grid-band-*` arms test. R2-E3 holding alongside R2-E2 failing is the
useful combination: depth is not the lever, the anchor is.

**Consequences for the maintainer calls.** R18-M2's requested reading ("14
unreachable by any chain-state realisation") is **withdrawn as
premature** — §10.14.2 names a chain-state realisation that may reach it,
and the round should not ask for a closure the next arm might refute.
R18-M1 and R18-M3 are unchanged: the fold at `P` = 720 costs 2.0× cold and
the block stands.

### §10.14 Round 2b (pre-registered 2026-09-09): the band over the grid *sequence*; window filters; the stability criterion in human time

Three maintainer proposals arrived in-channel on 2026-09-09 while §10.12's
run was in flight. Each is pre-registered here **before its arm exists**;
the commit ordering is the register, as at rounds 1 and 2. Nothing in
§10.12 is withdrawn: its fold arms are still measured and recorded at
§10.13, because the comparison the new arms have to win is against the
fold's *measured* figures, not its predicted ones.

#### §10.14.1 Jurisdiction, checked before anything is built

- **The settled-anchor grid band (§10.14.2) is inside §10.0.** It *is*
  the §7 band — the same `hysteresis_step`, the same 3 % margin, the same
  owner — applied to the sequence of grid samples rather than the sequence
  of blocks. "The previous value" becomes *the band's state at the previous
  grid sample*, reconstructed from chain state. That is the question §10.0
  says this round may decide.
- **The window filters (§10.14.3) are NOT the band.** Median and peak-hold
  replace the amplitude margin with a time release. §10.0 rules that the
  band stays. So both window arms are **INSTRUMENTATION under a
  pre-registered reading, exactly as C10-5 treated grid-only**: if a
  window arm dominates every band arm on the registered criteria, the
  finding goes to the maintainer as **R18-M4 — widen the round's
  jurisdiction to a non-band filter**, with the measured dominance as the
  rule-21 reopening criterion for "the band stays". It does not close
  FL-R3 by itself, however well it measures. If no window arm dominates,
  the reading is *the band's amplitude margin does work a time release
  does not*, and the band arms are the shape.

#### §10.14.2 Shape (D): the band over the grid sequence, anchored at the last settled sample

**Construction.** Sample at grid heights `g_k = k·P`. `C_k = C(g_k)` is a
pure function of chain state at `g_k` (at `P` = 720 each sample's volume
window `[g_k − 720, g_k)` is disjoint from the next). Run the band over
the *sequence*: `S_k = hysteresis_step(C_k, S_{k−1})`. Serve `S_⌊h/P⌋`
for every `h` in the period.

**The settled-state property, verified against the owner's arithmetic
rather than asserted.** `hysteresis_step(c, prev)` holds `prev ≠ ⌈c⌉₂`
only when `c ∈ [ (prev/2)(1−m), prev(1+m) ]`. With `cq = ⌈c⌉₂`, so
`c ∈ (cq/2, cq]`: `prev = 2cq` can be held only if `c ≥ (1−m)·cq`;
`prev = cq/2` only if `c ≤ (1+m)·cq/2`; no other power of two intersects
`(cq/2, cq]` at all. So when `c` lies **more than the margin from every
pow2 boundary** — call the sample *settled* — `hysteresis_step(c, prev) =
cq` for **every** `prev`, and the band's state at that sample is
`⌈C_k⌉₂` regardless of history. Consequently, for the most recent
settled index `j ≤ k`:

```text
S_k  =  hysteresis_fold(C_j, C_{j+1}, …, C_k)        (exact, not approximate)
```

The anchor is not a fixed depth and not an epoch: it is *wherever the band
was last unambiguous*. The owner gains one predicate,
`hysteresis_settled(c) = step(c, 2cq) == cq ∧ step(c, cq/2) == cq`,
defined **through** `hysteresis_step` so the two cannot drift, and one
property test that IS the theorem: for any sequence and any settled `j`,
`hysteresis_fold(seq) == hysteresis_fold(seq[j..])`.

**Scan bound `K`.** Look back at most `K` samples for a settled one; if
none, anchor at `k − K` with the unseeded snap. That fallback is where the
§10.2 first-step defect now lives — at weight *P(residence in the margin
> K·P)* instead of once per cell. FL-D8 measured max residence 13 597
blocks (≈ 19 periods at `P` = 720), so `K` = 32 covers the observed worst
with margin; `K` ∈ {8, 16, 32} are swept and the unbounded arm (`kfull`)
is run as the exact-recurrence reference.

**Properties pre-registered, each with its falsifier.**

- *Pure function of chain state.* No held value; a restarted node and a
  long-running node agree at every height. (By construction; the
  instrument's arm holds only the sample sequence, which stands in for
  chain state exactly as `GridCq.span` does.)
- *Transitions ≤ grid-only, per cell, over the whole trace* — **the
  monotonicity invariant.** Proof sketch: a band transition at `k` either
  coincides with a snap transition at `k` (band in sync at `k−1`), or ends
  a desync run that *began* at a snap transition the band did not follow;
  the map from band transitions to snap transitions is injective. It is
  **exact for the unbounded arm** and can be broken only by the bounded
  arm's fallback anchor. The instrument counts violations per arm;
  **expected 0 at `K` = 32, possibly > 0 at `K` = 8** (5 760 blocks <
  the 13 597 observed). A violation on `kfull` means the arm is not a
  hysteresis and the run is void.
- *Long memory at low cost.* One period is one step, so the cells C10-1
  lost to the fold's per-cell reset are reachable. **Expectation R2-E5:
  `grid-band-p720-k32` oscillating cells ≤ 14 (the banded figure), worst
  transitions ≤ 24.** If it lands between 14 and the fold's 20, that is
  the finding and it is reported at its number.
- *Reorg.* Each `C_k` memoises on `(hash_at_g_k, g_k)` — chain-state
  keyed, §10.6's legitimate kind; a reorg below `g_k` invalidates that
  sample and nothing older, and the served value does not move under any
  reorg inside the current period.
- *The FL-R18 corner.* Gain-≥2 feedback swings `C` by ≈ 20 %, which
  clears a 3 % band, so those cells still flip — **once per period**, on
  the grid's cadence, not every ≈ 125 blocks. That residual is bounded by
  `P` and is what §10.14.4's criteria price in days.

**The honest cost line — three columns, and the arm may not be ranked on
the one that flatters it.**

| column | settled-anchor band | fold (§10.3 B, P = 720) | window-W (§10.14.3) |
|---|---|---|---|
| cold, no memo (C10-3 as registered) | `(scan+1) × 720`: mean measured; worst `(K+1) × 720` = 23 760 at `K` = 32 | 1 440 (§10.12.1) | `W × 720` |
| chain-state memo (§10.6's legitimate kind; **not adopted by the register**) | 720 per **period** — one new sample; the cold figure is a once-per-restart backfill | 720 per **block** — one new height per block | 720 per period |
| FL-R3-STORE (§10.12.2) | `scan+1` O(1) reads | 720 reads | `W` reads |

The cold worst case is disqualifying under C10-3 *as written*; the memo
column is where the shape wins, and the register has not adopted that
column (§10.6 explains why it may not be counted toward the budget). Both
facts go to R18-M3 together. The instrument measures `scan` (mean, max,
fallback count) so the first column is a number, not a formula.

#### §10.14.3 Window filters over the grid sequence — INSTRUMENTATION

Served value at `h` is a function of the last `W` grid samples' snaps,
`W` ∈ {3, 5, 9}, `P` = 720. Fixed cost `W × 720` cold; no anchor, no
seed, no scan bound. Two statistics, and the difference between them is
the whole question:

- **Median-W.** A temporal filter: suppresses excursions shorter than
  `W/2` periods, adds `W/2` periods of lag to a real move. **Pre-registered
  expectation R2-E6: it does NOT handle the regime FL-D8 says we live
  in.** A `C` parked at a boundary alternating `a, b, a, b` across samples
  has a median that phase-locks to the alternation for every odd `W`, so
  the served value flips every period — grid-only's behaviour. Median is
  expected to measure at or near grid-only on C10-1.
- **Peak-hold-W.** `max` over the window of snapped values: upward moves
  served immediately, downward moves held `W` periods — one-directional
  hysteresis with a time release instead of an amplitude margin. Handles
  parking (`a, b, a, b` serves `b`). Its price is a **conservative bias**:
  over-quoting for up to `W` periods after `C` genuinely falls. On a
  ceiling-snapped fee that is the safe direction for the rejection race
  (§4.5b) and a cost in the user's fee, so the instrument measures it —
  **over-quote time share**: blocks where the served `C_q` exceeds the
  un-banded ceiling's, per thousand, on the dwell ensemble.
- *Monotonicity.* Both are transition-removing filters over the same
  sequence; the invariant of §10.14.2 is measured for them too, and a
  violation means the arm is not what it claims.

**What none of them does, stated so the record cannot be read otherwise.**
A gain-≥2 fee↔volume loop with a period of delay is still a loop. A filter
**lengthens the period** of that oscillation (from ≈ 2 periods toward
≈ `W` periods); it does not remove it. Only lowering the loop gain removes
it, and the gain lives in `M_r` inside the served operand. Every arm's
result on the feedback corner is a period, not a cure.

#### §10.14.4 The stability criterion restated in the user's units — C10-6, C10-7, C10-8

What a user cannot tolerate is not change but **change faster than their
planning horizon**: a quote that differs from the one ten minutes ago is a
seizure; one that differs from last week's is weather. A dwell floor in
blocks was a proxy for that. The criteria below are the thing itself, and
all three are direct statistics on the traces already swept. Numbers are
in **blocks and days** (120 s target: 720 blocks = 1 day).

- **C10-6 — minimum period of any sustained oscillation in the served
  value.** For each cell FL-C7 scores as oscillating, the cycle period is
  `2 × mean inter-transition gap` over the tail; the arm's figure is the
  **minimum over cells** (its worst state). FL-R18's accepted residual is
  the baseline: ≈ 125-block inter-flip dwell, ≈ 4.2 h. The floor is the
  maintainer's (R18-M5); the arm reports blocks and days.
- **C10-7 — probability that the served value moves inside the
  construction-to-broadcast gap.** Over the whole trace, the fraction of
  blocks `h` such that a transition occurs in `(h, h+g]`, with `g` = 5
  blocks (ten minutes) — the window FL-R18's 4.0 % was quoted on. **`g` is
  a placeholder for FL-R19's gap distribution, which the wallet lane owes;
  it is named as one.** *(§11.1 item 5, 2026-09-10: the premise is void — there is no offline signing; the gap is one hot session, 0–2 blocks, and no distribution is owed.)* Reported as worst cell and as the mean over the
  dwell ensemble (chain time, so occupancy-weighted). Expectation R2-E7:
  the banded reference reproduces ≈ 4 % in its worst cell; grid-sequence
  arms at `P` = 720 land near `≤ 5/720 ≈ 0.7 %` per transition-period, and
  peak-hold-8-class arms an order lower.
- **C10-8 — lag on a secular crossing, in blocks and days.** On the ramp
  scenario, the offset of the arm's first served change from the un-banded
  ceiling's. This is the *price* of `W` and of `P`, in the same units as
  C10-6 so both sides of the trade are visible at once.

**Occupancy-weighted flip rate — the number FL-D8 still owed.** FL-D8's row
named "the flip rate weighted by occupancy" and round 1 measured occupancy
and residence but not the rate. Per arm: `Σ standard-rung changes / Σ
blocks` over the dwell ensemble, per 10 000 blocks. Time-weighted by
construction, which is what the cell-count figures were not.

**What this reclassifies, contingent on measurement.** "Accepted as
bounded" was the honest label for a 125-block flicker nobody could fix.
Under a grid-sequence mechanism the residual's period is a **designed
quantity** — `P` for the band, ≈ `W·P` for peak-hold — so the FL-R18 row
could say *the corner oscillates on an ≈ N-day cycle by construction*
rather than *we could not stop it*. The trade is not free: larger `W`
lengthens both the cycle and the lag on real moves. Both are now in days,
so it is a choice a person can make on the record — **R18-M5 — set the
C10-6 floor and C10-7 ceiling, and choose `W` / `K` against C10-8's lag.**

#### §10.14.5 Instrument additions, enumerated before they are written

- Owner (`shekyl-economics`): `hysteresis_settled(c) -> bool`; property
  test *fold from any settled index equals the full fold*; property test
  *band transitions ≤ snap transitions over the sequence*.
- Arms: `grid-band-p{P}-k{K}` for `P` ∈ {60, 240, 720}, `K` ∈ {8, 16, 32,
  full}; `grid-median-p720-w{W}` and `grid-peak-p720-w{W}` for `W` ∈ {3,
  5, 9}. Feedback sweep: all of them beside §10.12's arms. Dwell grid:
  `grid-band-p720-k32`, `grid-median-p720-w3`, `grid-peak-p720-w3`,
  `grid-peak-p720-w9`.
- Per cell: full-trace transitions (for the invariant), tail
  inter-transition gap (min, mean), change-within-`g` share, scan depth
  (max, mean, fallbacks). Per dwell trace: first-change offset (C10-8),
  over-/under-ceiling time share, standard-rung changes (flip rate).
- Per arm in the summary: C10-6/7/8 figures in blocks and days, invariant
  violations, the cost triple from measured depth, flips per 10 000
  blocks, over-quote share.

**Amendments made while building the instrument, before it ran** (each is
a measurement choice the results depend on, so it is registered here
rather than discovered in §10.15):

- *C10-6 is read on the late half of the trace (15 000 blocks), not the
  3 000-block tail.* A peak-hold cycle at `W` = 9, `P` = 720 is ≈ 7 200
  blocks; the tail cannot hold one, so a tail-only reading would report
  the longest-cycle arms as *not oscillating* — flattering exactly the
  arms whose cycle length is the question. `is_oscillating` (the C10-1
  owner) is unchanged so round 1's counts stay comparable;
  `is_sustained_late` applies FL-C7's same two-changes-plus-amplitude bar
  over the late half for C10-6 only.
- *The monotonicity invariant is measured on whole-trace transitions*,
  for the same reason: the tail is shorter than two grid cycles.
- *Cost formulas differ by arm kind and are stated as such*: block-fold
  arms `720 + depth` (one overlapping scan, §10.12.1); sequence arms
  `depth × 720` (disjoint windows); memo column as parses **per day**
  (720 blocks) so arms with different `P` compare — `720 × (720/P)` for
  sequence arms, `720 × 720` for every per-block arm.
- *C10-8's over-quote share* is measured against the un-banded ceiling of
  the **same** raw `C` at each block, per dwell trace; the lag is the
  arm's first served change minus the ceiling arm's on the same ramp
  trace, reported as the maximum over ramp traces.
- *`grid-band` runs at `P` ∈ {60, 240, 720}* — the full sweep as asked —
  even though at `P` = 60 twelve consecutive samples share one volume
  window and the cost columns are least favourable; the number is
  reported rather than the arm being excluded on the argument.

#### §10.14.6 Maintainer rulings received before the run (2026-09-09), and the selection rule they fix

Three rulings arrived in-channel after §10.14.1–5 were committed and
before any round-2b arm ran. Each is recorded here so the selection at
§10.15 is made by a rule that predates its numbers.

- **R18-M4 — RULED in advance, conditionally.** *"Peak-hold is eligible,
  if it is proven best."* The window arms are no longer instrumentation
  only: a window arm that wins under the rule below is adopted, and §10.0's
  "the band stays" is thereby amended by the maintainer for this round. If
  no window arm wins, §10.0 stands as written.
- **R18-M5 — values accepted as proposed.** C10-7 ceiling **0.5 %** (an
  order below FL-R18's accepted 4 %); C10-6 floor **2 days** (strictly
  longer than one period at `P` = 720, so the grid alone cannot clear it).
- **R18-M3 — deferred to the results, with a stated preference for the
  memo column.** What that column proves and does not is set out below;
  the round reports both columns regardless.
- **What "best" means, in the maintainer's words:** *"the smoothest, with
  the least required input, and preferably without memory."* Mapped to the
  registered statistics: *smoothest* = fewest served-value changes per unit
  chain time (the occupancy-weighted flip rate) and the longest C10-6
  period; *least input* = fewest tunables the mechanism needs beyond `P`
  (grid-only 0, peak-hold / median 1 (`W`), settled-anchor band 1 (`K`) plus
  the already-ruled margin); *without memory* = a pure function of chain
  state — every grid-sequence arm satisfies this by construction, and a
  chain-state-keyed memo is a cache of that function, not memory (it can be
  dropped at any height and recomputed identically, which is the property
  the rejected `m_fee_correction_cq` lacked).

**Selection rule (fixed before the run).**

1. *Eligible* = zero monotonicity-invariant violations, C10-7 worst-cell
   ≤ 0.5 %, C10-6 minimum sustained period ≥ 2 days, and **worst-direction
   secular lag (C10-8) ≤ 7 days**. The lag cap is the one number added
   here rather than ruled: without it "smoothest" is won by `W → ∞` — a
   constant fee is infinitely smooth and tracks nothing — so a cap is what
   makes the criterion a criterion. Seven days is the horizon the
   maintainer discussion itself used ("a fee that takes a week to come
   down"); it may be re-ruled, but only before §10.15 is written.
2. Among eligible arms, **lowest flip rate** wins; ties (within 10 %) go to
   the **longer C10-6 period**; remaining ties to the **fewest inputs**.
3. C10-8's lag and the over-quote share are reported beside the winner as
   its price, in days and per-mille; they do not re-rank within the cap.
4. Two outcomes stated in advance: **peak-hold clears and is adopted** at
   the smallest `W` that wins, or **peak-hold is ineligible (lag) and the
   settled-anchor band is adopted** with `K` set from FL-D8's residence.
   A third — nothing clears — sends the round to the operand axis below.

**The `W` sweep is widened to {3, 4, 5, 8, 9, 16}** for peak-hold (the
maintainer discussion proposed {4, 8, 16}; §10.14.3's {3, 5, 9} stays so
the two sets are one run). Median stays at odd {3, 5, 9}. **A downward
ramp (`ramp-v200-to-v50`) is added to the dwell scenarios**: the grid had
one ramp, one direction, and peak-hold's lag is asymmetric by
construction — measured on the rising side alone it ties the band, so a
selection made there would be made on the flattering half.

**What judging C10-3 on the memo column proves, in plain terms.** The cold
column bounds the cost of *one quote on a node that has nothing cached* —
after a restart, or the first query after a reorg past the samples: it is
a per-request latency figure, and on the interim C++ path it is paid under
the blockchain lock. The memo column bounds the cost *per unit of chain
time* once the node is warm: one volume window per period, for every
grid-sequence arm alike, however many quotes arrive. Adopting the memo
column therefore proves **amortised affordability** — the mechanism's
running cost is set by the chain, not by the query rate — and it changes
nothing about correctness or purity, because the cache is keyed by block
hash and can be discarded freely. What it does **not** prove is that the
first quote after a restart is fast: that quote pays the cold figure once
(`W × 720` or `(K+1) × 720` parses), and the register would then owe a
separate **restart-latency bound at the rule-76 device floor** — either
measured on a Pi 4, or made moot by FL-R3-STORE, whose O(1) row read
collapses both columns. Recommended shape if the column moves: C10-3 judged
on the memo column *and* a named cold-restart budget carried as owed, not
a silent relaxation.

**Out of scope, named:** the operand question — whether `M_r` sits inside
the served value, the only lever that lowers the gain-≥2 loop's *gain*
rather than lengthening its period. It **opens** if no arm clears rule 1;
otherwise it is a refinement for a later round and this one does not grow
to include it.

Round 2b's results go in §10.15.

### §10.16 Closure

Closed as record 2026-09-10 by §11 (FL-R21). Round 2b completed (`/tmp/fl_r3_round2b.summary`: settled-anchor band and window arms reported; not selected, not read for selection). The one round-2b figure that carried forward is not about any arm: the 27 oscillating raw-`C` feedback cells are all adjacent-integer SMA toggles (§11.1 item 6), which is the finding that sized FL-R24.

## §11 The floor follows `C` — round 19 (OPEN; pre-registered 2026-09-10)

**Status:** OPEN. Rulings received in-channel 2026-09-09 → 2026-09-10 and
recorded here per row (§11.2); the confirmation run FL-E1…FL-E3 is
pre-registered at §11.5 and its results are recorded at §11.7 (FL-E1…FL-E3 run 2026-09-10; FL-R24 RULED: exact SMA for reward and floor, a consensus row); the implementation
spec is §11.6, **signed off in-channel 2026-09-11** (PR A merged; PR B and
PR C cleared). **This round supersedes §10**,
which closes as record at §10.16 — not because its measurements were wrong
but because the thing it was restoring turned out to rest on a premise
refuted two rounds before §10 opened (§11.1 item 2).

### §11.0 How the round opened

Round 2b of §10 was running when the maintainer asked what all the
machinery was for:

> the ladder is a base cost (economy covers only the cost, standard
> provides incentive to miners, priority pays miners well) and ANY value
> BETWEEN tiers simply falls to the lower tier. Economy is the floor, and
> we could probably put a reasonable ceiling on priority. The wallet
> estimates, the daemon confirms that the value fits into the tier, and
> viola. What are we making this so complicated for?

The honest answer, once the acceptance path was read rather than
remembered, was that the ladder already *was* banded pricing (three rungs
at 1 : 4 : 200), and that the pow2 snap on `C` was a **third** quantizer
layered on it — the only one with 2× steps, added for a criterion the
round had since refuted — and that §7's band and all of §10 existed to
smooth the steps that quantizer introduced. Delete the quantizer and the
round collapses. The rest of the day's exchange re-derived the floor,
struck a stale premise from FL-R19, considered and withdrew two pad
designs, and landed on an admission rule that needs no pad at all. Every
turn is recorded below, including the two that were reversed, because a
record that shows only the survivor cannot tell a reconsidered conclusion
from one whose ground disappeared (rule 16, "refuted, not superseded").

### §11.1 Findings, verified at source (rule 16 corollary)

Each of these was read at the implementation during the exchange; none is
taken from another document's prose.

1. **Acceptance is `C`-free.** `Blockchain::check_fee`
   (`src/cryptonote_core/blockchain.cpp:4476–4491`) admits
   `fee ≥ needed − needed/50` with `needed` rounded up to the quantization
   mask, against `get_current_fee_per_byte()` (`:4453`) — the inherited
   `0.95·R·w_ref/M²`, no `C` anywhere in it. `C` enters only the *served*
   quote, `fees[]` at `:4628`, and the economy rung is clamped up to that
   `C`-free floor at `:4643`. The quote tracks demand; the admission floor
   does not; that gap is real and is what FL-R20 closes.
2. **The snap survived its premise.** §1.4's registration names the pow2
   snap as FL-C4a's remedy (dwell for anonymity); §1.4's own post-round-15
   note records that FL-C4a **is not retained as an anonymity criterion**
   and that the survivor is "quantization-quality and user-predictability".
   §4.5 records that the pow2 step "is exactly the limit-cycle mechanism"
   FL-C7 exists to exclude. So: the snap was kept for a reason that had
   been withdrawn; §7's hysteresis band was built to damp the oscillation
   the snap causes; §10 was opened to restore the band to the served path
   at a cost the register could not afford (§10.12.1, 2.0× the cold
   budget). Three layers over a refuted premise. Rule 16's comment
   anti-pattern, at the scale of a design round.
3. **"Must not track demand" was scoping, not a ruling.** The comment at
   `blockchain.cpp:4461–4467` was written by an agent bounding a PR; the
   only ruling in the area is Q9
   ([`CONSENSUS_C2_R2_WEIGHT_FEES.md`](../completed/CONSENSUS_C2_R2_WEIGHT_FEES.md)
   §Q9, RULED 2026-09-06): **no consensus fee floor**. A relay floor that
   follows `C` is still relay policy; Q9 is untouched.
4. **`tx_volume_avg` is a consensus operand.** `validate_miner_transaction`
   feeds it to `get_block_reward` (`blockchain.cpp:1669`; the miner tx at
   `:1956`); `get_tx_volume_avg` (`:2053`) is memoized per tip since #640.
   A differently weighted average (LWMA) for the floor is therefore either
   a consensus change to the reward or a second operand that breaks
   FL-V1's identity between what the miner is paid and what the floor
   prices. **LWMA is closed; the SMA is the operand.** (Maintainer:
   "LWMA was a fun idea, but not even really necessary, so let's close
   that for now.")
5. **There is no offline signing.** Cold signing is NEVER
   ([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) 2026-09-07,
   overturning the 2026-04-25 entry; `export_unsigned` / `submit_signed`
   are REJECTED in [`wallet_rpc.yaml`](../api/wallet_rpc.yaml)). FL-R19's
   sizing criterion — a margin covering an offline-signing flow — was
   written against an architecture that no longer exists (rule 16's
   "comment that outlived its architecture", in a ruling). The
   construction-to-broadcast gap is **one hot session: 0–2 blocks.**
6. **The SMA is integer-truncated.** `get_tx_volume_avg` returns
   `tx_count_sum / blocks` (`blockchain.cpp:2115`), whole transactions per
   block. That is a hidden quantizer on `C`: one tick is `1/V` of `M_r` —
   **2 % at the baseline, 2.5 % at the low rail (`V` = 40)** — and it can
   fire in a single block. Every one of the 27 raw-`C` cells round 2b's
   feedback grid listed as oscillating has `v_tail = [n, n+1]` and a fee
   swing of one `round_money_up_2` step: they are this tick, rendered
   through finding 7, not a property of the map. Round 1's "raw `C` fails
   dwell hardest" was the tick.
7. **`round_money_up_2` is a fee-uniformity quantizer of the same refuted
   class.** Two significant digits is a step of 1–10 % depending on the
   leading digit (inherited `CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES`).
   Harmless on a quote that a buffer then forgives; unacceptable inside an
   admission floor, where a 10 % step in one block would refuse every
   transaction quoted the block before. It leaves the served path
   (§11.2 FL-R21); it has no wallet consumer (`rg round_money_up_2` →
   `shekyl-economics`, the instrument).
8. **Admission runs once.** `kept_by_block || check_fee` at
   `tx_pool.cpp:251`; a pooled transaction is never re-checked against a
   risen floor; eviction is by size pressure and age. A floor that rises
   between quote and broadcast produces a **bounce** — rejected at
   submission, re-quoted, resent — never a stuck transaction and never
   funds at risk. This is what any margin is insuring, and it bounds how
   much insurance is worth buying.
9. **The 2 % buffer covers no weight mismatch.** `predict_weight` is a
   byte-for-byte mirror of `Transaction::write`
   (`rust/shekyl-tx-weight/src/lib.rs:247`) and
   `transfer_pending_tx_tests.rs:1053` asserts it equals the built
   transaction's canonical `weight()`. The buffer and Monero's 0.95 were
   both papering over the quote-to-admission gap and nothing else.

### §11.2 Rulings

Maintainer rulings, in-channel, recorded verbatim where quoted. Row
identifiers continue §8's FL-R series (registered at birth, rule 94).

**FL-R20 — The relay floor tracks `C`.** `F(h) = R(h)·C(h)·w_ref/M(h)²`
with `C` **raw** — no snap, no band, no rounding — and **one formula for
every regime**: `C < 1` (quiet chain, `M_r` at its low rail) lowers the
floor below the inherited value exactly as `C > 1` raises it; there is no
`max(F, F_inherited)`. Monero's 0.95 is deleted: it and the 2 % buffer
were the same fudge for the same gap, and FL-R23 closes the gap
structurally. Operand: the 720-block SMA (finding 4). Still relay policy;
`kept_by_block` exempt; Q9 untouched. The V1 identity holds by
construction: economy·(1−b) = R·M_r·(1−σ)·w_ref/M² — the miner nets the
subsidy-scaled floor regardless of burn.

**FL-R21 — The quantizers go.** `quantize_pow2_ceil`,
`fee_correction_quantized`, `hysteresis_step` / `hysteresis_fold` /
`hysteresis_settled`, `MIN_REPRESENTABLE_C` (a pow2-floor artefact; raw
`C ≥ (1−σ)·0.8 ≈ 0.68` needs no floor), the `fees[0]` clamp at `:4643`,
`round_money_up_2` on the served path, and the whole §10 grid / fold /
band / window instrument are deletion targets. Consequences on §8 rows:
**FL-R3 CLOSED, premise refuted** (§11.1 item 2 — not superseded: the
ground disappeared); **FL-R6 becomes an identity** (the economy rung *is*
the floor; a clamp of a value to itself is deleted, not kept); **FL-D2
CLOSED** (the floor scaled by `C` is the re-derivation FL-D2 asked for;
its CEN-M3 routing is discharged — the census row's formula text is
carried by the implementing PR); **FL-D6 and FL-D8 moot** (no snap, no
boundary cells, nothing to smooth); **FL-R3-STORE demoted** from an FL
blocker to the storage-lane performance item it was before round 18
promoted it — FL-R23's cold cost is one 725-block scan (§11.6), inside the
720 budget to within the lookback depth. *(This row was ruled 2026-09-09 when `G` = 3 made the scan 723; `G` was re-derived to 5 at review A-1 the
next day, so the figure is restated here at the settled `G` rather than
left disagreeing with §11.6.)*

**FL-R22 — The wallet pays exactly the served rung.** No pad, fixed or
drawn. The day's path to this ruling, in order, because each step was
argued and two were reversed:

- *(a) A per-transaction random pad* `u ~ U[0.5 %, 2.5 %]` was proposed
  when the floor first moved into the loop, on the argument that a
  deterministic fee on a continuously drifting floor dates the quote to
  its block, while a fresh draw from a distribution every client shares
  links nothing. The maintainer's ruling on FL-C1 at that point, verbatim:
  > FL-C1 overruled as a misunderstanding of what a fingerprint is, how
  > transactions work, and basically the entire premise. HOW does a random
  > number link to anyone if EVERYONE is generating a random number of the
  > same magnitude?
  The answer to the question is: it does not — a fresh draw from a common
  distribution carries no information about who drew it; a *per-wallet
  constant* offset is the fingerprint, and a per-transaction draw is
  noise. That part stands. What did not stand was the draw as an
  **insurance instrument**, which is the next step.
- *(b) The draw was withdrawn on the failure-mode analysis*, not on
  privacy. Given finding 8 (a risen floor is a bounce, not a loss), a pad
  whose size is randomized after the fact under-insures by design — every
  draw below the worst rise is a purchased chance of the exact failure the
  pad exists to prevent; the resulting failure is *intermittent*, which is
  the most expensive failure class to own ("it works most of the time"
  reads as flaky software and is misattributed for months), where a fixed
  pad fails all-or-nothing, one cause, self-correcting on the next quote;
  and identical transactions paying different fees for the same service
  is the definition of uneven — it also manufactures a fee rank among
  economy transactions that FL-D7 says block position can reveal. The
  maintainer: "The safety argument won me over." **FL-C1 is therefore NOT
  overruled**: a fixed additive margin identical for every client was never
  the arbitrary-precision fee FL-C1 forbids, and the overrule's premise
  (that the pad had to be random to avoid a fingerprint) was itself
  withdrawn. Recorded as a refuted premise, not a reversal of the
  maintainer's reading of what a fingerprint is, which was correct.
- *(c) A fixed pad sized from the spam-onset trace* was the disposition
  for one exchange, then superseded by FL-R23, which removes the need for
  any pad: if the daemon admits against the lowest floor a quote inside
  the gap could have been taken at, a quote at exactly `F(h)` is admitted
  by identity, and the wallet's overhead is zero. A pad sized from a
  simulation is a constant pinned forever against dynamics that may
  differ; the lookback is exact whatever the dynamics (rule 75: no
  tunable where an identity is available).
- *Temporal linkability, accepted as inherent.* A deterministic fee on a
  drifting floor does date the quote to within the gap. The maintainer's
  disposition: "the transaction is going into the chain within a small
  number of blocks from when it is estimated, so it's ALWAYS going to have
  a temporal link." The mempool timestamp already places construction
  within the same window; the fee adds nothing an observer lacked. Not a
  cost of FL-R22; a property of broadcasting.

**FL-R23 — Lookback-min admission.** A transaction is admitted at height
`h′` iff

```text
fee ≥ mask_round_up( weight · min{ F(h′−k) : 0 ≤ k ≤ G } ),   G = 5
```

where `h′` is **the receiving node's tip** — the predicate is evaluated
per node, and the identity it delivers is per node: a quote taken at `h`
and paid at exactly `F(h)` is admitted **by identity at every node whose
tip lies in `[h, h+G]`**. That is the honest form of the claim; the
2026-09-10 text said "impossible, not merely rare" without saying at which
node, and review A-1 (2026-09-10) caught it. So `G` is derived from three
terms, none of them a trace: the hot-session gap (0–2 blocks, finding 5)
**+ the network height spread at relay time** (peers a transaction reaches
may be ahead of the quoting node's tip by the blocks that arrived during
propagation; two inside one propagation interval is uncommon under
Poisson block times but not rare over millions of transactions — 2) **+
one block of slack** = 5. The first draft's `G` = 3 covered the gap and
left one block for the spread; a peer two blocks ahead would have
evaluated `[h+1, h+4]`, excluded `h`, and refused — a partial relay
partition, harder to diagnose than a bounce. The symmetric case, a peer
*behind* the quoting node on a *falling* floor, is not covered by the
predicate and does not need to be: the quoting node's own daemon is at
`h` and admits; a lagging peer refuses transiently, catches up within its
lag, and receives the transaction in a block under `kept_by_block`. What
`G` = 5 costs against 3 is priced by FL-E4 (§11.5), and the run gave it a
closed form (§11.7): **worst-case grace ≈ `G` × the one-block slew of
`F`** — 479 / 639 / 807 bp at `G` = 3 / 4 / 5 is ~160 bp per block against
FL-E2's measured 160, because after a step the 720-block SMA is a linear
ramp and `min` sits `G` blocks back down it. Each extra block of `G` costs
one block of slew in the worst case and nothing in expectation (mean 3–6
bp at every `G`), so the trade is a formula, not a table; and it is the
same quantity FL-E2 measures, not an independent one.

**Why `min` is safe here, registered so it stays safe (review A-3).** A
minimum over a window is adversary-favourable by construction: any
transient dip in `F`, from any cause, becomes the admission threshold for
`G` blocks. It is safe *because every operand of `F` is slow* — a
720-block SMA (`C`), a 100-block weight median (`M`), a reward that decays
by `2⁻²¹` per block (`R`) — so no single block can produce a dip worth
exploiting; the worst one-block fall in the run is 3.5 % on a 10× volume
collapse (§11.7). That is a property of the operands, not of `min` —
and it is why the mean stays at 3–6 bp while the worst case is `G` × slew:
a fast operand would move both together, so the clause below fires on
evidence, not on someone noticing. The integer tick is the contrast case:
its grace is 307 bp at every `G`, flat, because a quantizer's step has
nothing for a wider window to average out (FL-R24's one-line case).
**Reopening clause (rule 21, FL-R17 shape): FL-R23 reopens if any operand
with a per-block response enters `F`** — a fast term added to the floor
would be amplified by the window for `G` blocks, and this sentence is
here so whoever adds it finds out why. The 2 % buffer (`needed/50`) and the 0.95 are
deleted — they insured the same gap probabilistically and finding 9 shows
they insured nothing else. What the lookback *costs* is grace: admission
may sit below the current floor by `F(h′)/min_k F(h′−k) − 1`, which is the
floor's worst rise over `G` blocks and is what FL-E3 measures. Every node
derives the `G+1` floors from the chain, so the rule is deterministic and
remains relay policy. The predicate is new logic and lands in Rust behind
an FFI entry point per rule 20; the C++ marshals `G+1` floors and the
fee. Rejected alternative: `fee ≥ F(h′)/(1+s_max)` with `s_max` a measured
slew bound — same effect, but a constant from a simulation where an
identity was available; rejected on the same ground as (c).

**FL-R24 — SMA resolution: OPEN, decided on this round's evidence.** Two
branches. *(i) Integer* (shipped; `tx_count_sum / 720`): the tick of
finding 6 is a **grace cost** under FL-R23, never a bounce; its remaining
effect is on the *quote*, which toggles by one tick under Poisson noise
around a stationary volume — a quote-quality question, not a safety one.
*(ii) Exact* (`tx_count_sum` against `baseline·720`; the ratio functions
`calc_release_multiplier` / `calc_burn_pct` take `(volume, baseline)` and
are scale-invariant, so no new economics code): removes the tick entirely.
Applied to the floor alone it introduces a second operand and breaks the
FL-V1 identity by up to one tick; applied to the reward as well it is a
**consensus change** to `M_r`'s operand — pre-genesis, its own row, and a
rule-07 evaluation (a constant-like change to a consensus operand; likely
indivisible). Pre-registered decision rule at §11.5 FL-E3/FL-R24.

**FL-R19 — RE-RULED, superseded by FL-R23.** The 2026-09-06 (b) ruling
("fixed deterministic margin above the unbuffered floor; sizing criterion
pre-registered; gap distribution owed by the wallet lane") rested on
finding 5's void premise and is discharged: the gap is one hot session,
the wallet lane owes no distribution, and no margin is sized because
none is paid. The row's threat model (liveness, adversary none) was
correct and is what finding 8 restates.

### §11.3 Roads not taken

Kept as record so they are not re-derived (rule 21 — each names its
reopening condition):

| Road | Why not | Reopens if |
| --- | --- | --- |
| LWMA-weighted floor operand | `tx_volume_avg` is consensus (finding 4); a relay-only LWMA is a second operand and breaks FL-V1 | the reward's operand itself changes weighting, by its own consensus round |
| Per-transaction random pad `u ~ U[0.5 %, 2.5 %]` | insurance by lottery under-insures by design; intermittent failure class; uneven by definition; manufactures FL-D7 rank | never as insurance; only if a *privacy* need for fee dispersion is demonstrated that the temporal-link disposition above does not already answer |
| Fixed pad `p` sized from the spam-onset trace | a simulation constant pinned forever where an identity (FL-R23) exists | FL-R23 proves unimplementable at the admission site — falsify by the implementing PR |
| Slew-bound admission `F(h′)/(1+s_max)` | same as the fixed pad, daemon-side | same |
| §10 grid / fold / settled-anchor band / median / peak-hold arms | smoothed a quantizer that is deleted | a quantizer is reintroduced on the served path (rule 21 says name it: none is contemplated) |
| `fees[0] = max(fees[0], relay floor)` | identity under FL-R20 | never — a clamp to self is not a mechanism |

### §11.4 Criteria under the round-19 shape

| Criterion | Disposition | Note |
| --- | --- | --- |
| FL-C1 continuous-schedule precommitment | **met — satisfied, not merely un-overruled** | daemon-computed rung values identical for all wallets at a height (§1.1's own clarification); no wallet-side arithmetic beyond `rate × weight`; `round_money_up_2` leaves the served path but `get_fee_quantization_mask` survives at admission, so paid fees still sit on a lattice — "arbitrary-precision fees" was never on the table; the overrule of §11.2(a) recorded as premise-refuted |
| FL-C2 coverage | **met exactly** | economy = floor by identity |
| FL-C3 fee rounding | **re-based** | `round_money_up_2` leaves the served path (finding 7); the mask remains the only rounding |
| FL-C4a dwell | **re-grounded** on quote quality, not anonymity (§1.4 note) | FL-R24's remaining question |
| FL-C4b/c | unchanged | three tiers, FL-R17 |
| FL-C5 | **met** | ladder multiples 1 : 4 : `2M/w_ref` unchanged |
| FL-C6 relay-floor coherence | **met by construction** | closes FL-D2 |
| FL-C7 feedback stability | **must be re-run** with the floor in the loop | FL-E1 |
| FL-C8 tail degenerate | unchanged | §4.6 pins hold; `C` raw at the tail is the same `C` |
| FL-C9 anchored-attack reduction | **re-argued**: no snap means no boundary cells to straddle; the fee signal is `C` itself, which every observer already computes from the chain | no new bits |

### §11.5 Pre-registered confirmation run — FL-E1…FL-E3

Instrument: `shekyl-economics-sim --fee-floor`
(`rust/shekyl-economics-sim/src/fee_floor.rs`), committed **before** this
run per rule 26. It measures raw `C` along Poisson-driven traces
(stationary at `V` ∈ {40, 50, 500}; 720-block ramps 50↔500; and
**instantaneous steps** 40→500, 50→500, 500→50 — the worst case a linear
ramp cannot show) and FL-C7's loop through the FL-R20 served map, each
under **both** SMA resolutions of FL-R24, across the §1.8 age grid. Fee
ratios are computed on `F × SCALE` so integer atomic/byte granularity
cannot masquerade as slew. Grace is `F(t)/min_{k≤G} F(t−k) − 1` in basis
points. As the record of the road not taken, each slew cell also reports
how many quotes a fixed pad of 50 / 100 / 200 / 300 bp would have bounced
against the inherited 2 % buffer.

Expectations, stated before running:

- **FL-E1 (FL-C7 with the floor in the loop).** 1 200 cells. *Exact arm:*
  every cell converges — tail amplitude of the paid fee ≤ 50 bp; the
  fixed-point argument of §4.5 does not depend on rounding. *Integer arm:*
  the only non-converged cells are single-tick toggles (amplitude ≈ one
  tick, 100–250 bp, `v_tail = [n, n+1]`) — the round-2b signature
  reproduced through the new map. Any cell with amplitude > one tick on
  either arm **falsifies** the claim that raw `C` in the loop is stable
  and reopens §4.5.
- **FL-E2 (per-block slew).** Worst single-block rise of `F`: *exact* ≤
  ~160 bp (the 40→500 step: `460/720` tx/block on `V` = 40 in the `M_r`
  regime), ≤ 100 bp on 720-block ramps, ≤ ~30 bp stationary; *integer* ≤
  one tick plus the burn term — ~250–300 bp at `V` = 40. A rise above
  these on the exact arm means the slew bound is wrong and FL-R23's `G`
  must be re-derived, not the pad re-sized.
- **FL-E3 (lookback grace; FL-R24 evidence).** `grace_bp_max`: *exact* ≤
  ~480 bp in the 40→500 step, ≤ ~300 in 50→500, ≤ ~100 stationary;
  *integer* stationary = one tick (200–250 bp). `grace_bp_mean` in
  stationary cells: exact < 20 bp, integer < 30 bp (a tick every ~80
  blocks over a 3-block lookback). **Pre-registered FL-R24 decision
  rule:** if the integer arm's stationary grace_max ≤ 300 bp and grace_mean
  ≤ 30 bp, the tick is an acceptable grace cost and FL-R24 is decided on
  **quote quality alone** — reported as `c_changes` in stationary cells
  (integer arm) and left to the maintainer as a UX call with the
  consensus cost of branch (ii) stated; if either bound is exceeded,
  branch (ii) is recommended and its consensus row opens. Pad comparison
  column: the 50 bp pad is expected to bounce in the integer arm's `V` =
  40 cells and in every step cell on both arms; 300 bp in none but the
  40→500 step — recorded to show what FL-R23 replaced, not to size it.

No selection is made from this run: FL-R23 is an identity and sizes
nothing. The run confirms the loop, prices the grace, and produces the
FL-R24 evidence.

**FL-E4 — the `G` sweep (added 2026-09-10 after review A-1, before its
run).** Grace re-measured at `G` ∈ {3, 4, 5} on every slew and feedback
cell, both arms. Expectation, stated against the review's own guess so the
curve can rule: the review expected "roughly the same worst case" because
the step is instantaneous; I expect the opposite for the *maximum* — after
an instantaneous step the SMA ramps **linearly for 720 blocks**, so the
worst rise over `G` blocks scales with `G`: exact arm ≈ `G × 160` bp at
age 0 (3 → 479 measured; 5 → ~800), ≈ `G × 225` at age 30 (3 → 679; 5 →
~1 130); integer arm one tick higher. The *mean* is where the review is
right: 0–6 bp at `G` = 3, expected ≤ 10 bp at `G` = 5, because rises are
rare and the window only widens the few blocks they touch. Decision rule:
`G` = 5 is adopted **as derived** (gap + spread + slack) unless the sweep
shows `grace_bp_mean` > 20 bp in any stationary cell or a worst case that
does not scale as stated — either would mean the operands are faster than
§11.2's safety argument assumes, and FL-R23's reopening clause fires
rather than `G` being tuned down.

### §11.6 Implementation scope — **SIGNED OFF 2026-09-11**

**Provenance:** signed off by the maintainer in-channel on 2026-09-11
("the spec is signed off on"), recorded as an in-channel sign-off — the
provenance class this lane already consumes (FL-R12′, FL-R21) — and
**not** as an in-tree signature: no approving review or maintainer commit
carries it, and this line says so rather than letting a relay read as
one. PR A landed under it; **PR B and PR C are cleared to implement.**

Three PRs, in this order, so a reviewer never meets a consensus
predicate and a repo-wide deletion in one diff (review 2026-09-10):

- **PR A — consensus operand (FL-R24). LANDED on
  `feat/fl-r24-exact-volume-operand` 2026-09-10.** The operand crosses the
  FFI as the exact window `(tx_count_sum, blocks)` and is divided once,
  Rust-side, against the baseline: `shekyl_economics::TxVolume`
  (`volume.rs`; `window(sum, blocks)` is the chain form, `per_block(mean)`
  the whole-mean form every pre-existing KAT already used) feeds
  `calc_release_multiplier`, `calc_burn_pct`, `paid_block_reward` and
  `fee_correction_quantized`; the four FFI exports take
  `(tx_count_sum, window_blocks)`; C++ marshals `shekyl::tx_volume_window`
  and **never divides** — `Blockchain::get_tx_volume_avg` is renamed
  `get_tx_volume_window` because it now returns a sum and a length, not a
  mean, and #640's memo (`m_tx_volume_window_*`, same `(tip, height)` key)
  moves with it. The `G+1` floor ring PR B adds sits beside that memo.
  Every pre-existing reward KAT is unchanged — each feeds a whole-number
  mean, on which floored and exact agree — so two discriminating KATs were
  added with both values in the diff (`emission.rs`
  `fl_r24_exact_window_mean_moves_the_reward_off_the_truncated_value`,
  `burn.rs` `…_moves_the_burn_off_…`, and the C++
  `economics_tx_volume_window` pair): mid-curve, a 720-block window of
  29 160 transactions (mean 40.5, `M_r` = 0.81) pays 829 440 000 000
  where the floored operand (40, `M_r` = 0.80 — the lower rail) paid
  819 200 000 000; at 35 640 (49.5 vs 49) 1 013 760 000 000 vs
  1 003 520 000 000; `burn_pct` 225 000 vs 223 606 and 248 746 vs
  247 487. **Rule 07, evaluated:** (1) *consensus-rule boundary* — the
  operand feeds `M_r` and `b`, so the paid reward and the burn split
  differ between a floored and an exact node on any block whose window
  mean is fractional, and each rejects the other's coinbase; (2)
  *indivisible under flag decomposition* — a "flag off" node computes
  the floored reward and a "flag on" node the exact one for the same
  block, so every intermediate is a split, not a staging; there is no
  consensus-safe PR A/B/C sequence for a change to an operand's
  resolution; (3) *surface enumerated in advance* — the touched set is
  the `git grep -n 'tx_volume_avg\|get_tx_volume_avg'` hit list at
  `bc1808227` (`blockchain.{h,cpp}`, `tx_pool.cpp`, `core_rpc_server.cpp`,
  `cryptonote_basic_impl.{h,cpp}`, `cryptonote_tx_utils.{h,cpp}`,
  `economics.h`, `shekyl_ffi.h`; Rust `release.rs`, `burn.rs`,
  `emission.rs`, `fee.rs`, `activity.rs`, `legacy_core.rs`; the sim and
  engine-core operand sites; the C++ tests), pasted into the PR
  description and closed to zero; (4) *disposition and rollback* — in
  the PR description: reviewer map (consensus-affecting: `volume.rs`,
  `release.rs`, `burn.rs`, `emission.rs`, the `get_tx_volume_window`
  body; mechanical: every marshal rename and KAT wrap; deletions: none)
  and a rollback that restores `/ blocks` at the scan and re-forms the
  scalar at the four FFI exports. Lands first so PR B is read against a
  settled operand.
- **PR B — relay policy (FL-R20, FL-R22, FL-R23)** — items 1–4 below,
  in that order: the weight-gate property test (item 3) lands before the
  zero-slack deletion it justifies. Relay policy and wallet-side only.
  *(Items were numbered 1, 2, 4, 3 when the weight gate was inserted at
  review A-2; renumbered to reading order here — the numeric order used
  to contradict the ordering the items themselves require. Order and
  numbering only; no item's content changed.)*
- **PR C — the FL-R21 deletion sweep** (economics, FFI, instrument).

*Daemon (`blockchain.cpp`, `tx_pool.cpp`), Rust-forward per rule 20:*

1. `get_current_fee_per_byte(h)` → `F(h) = R·C(h)·w_ref/M²` via a raw
   `shekyl_fee_correction` FFI export (replacing
   `shekyl_fee_correction_quantized`); 0.95 deleted; `max(1)` kept.
2. `check_fee` → the FL-R23 predicate in a Rust entry point
   (`shekyl_relay_floor_admits(fee, weight, mask, floors[G+1])`); C++
   marshals a `(height, F)` ring of depth `G+1` maintained beside the
   `tx_volume_avg` memo under the same lock and rebuilt on tip change /
   reorg by one scan of `720 + G` blocks (the overlapping-window cost
   §10.12.1 derived — 725 parses at `G` = 5, at the 720 budget).
   `needed/50` deleted — but **the slack is a named parameter, not an
   absence**: the predicate takes `slack_bp`, pinned by a single constant
   `RELAY_ADMISSION_SLACK_BP = 0` with a KAT asserting it is zero and a
   doc comment naming the gate below as the reason it may be. If the
   weight gate ever fails on a live shape, re-introducing a buffer is one
   constant and one KAT, not a design round (review A-2).
   `kept_by_block` exempt, unchanged.
3. **Weight gate (review A-2, same PR as the deletion, and landing BEFORE it):**
   finding 9 rests on one equality assertion
   (`transfer_pending_tx_tests.rs:1053`). With zero slack a one-byte
   prediction error on any untested shape is a hard bounce that FL-R23
   cannot cover (it is not temporal). The deletion is justified by a
   **property test over the shape space** — every `n_in` in
   `1..=MAX_INPUTS`, every `n_out` in `1..=MAX_OUTPUTS` (so both sides of
   every power-of-two clawback boundary), tree depths across the KAT
   grid, fee varint lengths across their boundaries — asserting
   `predict_weight(n_in, n_out, depth, fee) == Transaction::weight()` of
   the transaction the builder produces, exactly. The gate asserts its own
   subject (rule 47): it fails if the shape enumeration is empty.
4. Estimate path: `fees[0] = F` (no clamp, no `round_money_up_2`),
   `fees[1] = 4F`, `fees[2] = 2RC/M`; the wire shape (FL-R7) is unchanged.

*Economics (`rust/shekyl-economics/src/fee.rs`):* export raw
`fee_correction`; delete `quantize_pow2_ceil`, `fee_correction_quantized`,
`hysteresis_*`, `MIN_REPRESENTABLE_C`, `round_money_up_2` (no consumer
after item 3); `corrected_fee_ladder` takes raw `C`, drops the rounding;
KAT pins for `F(h)` at the §4.6 degenerates and the §1.8 grid.

*Wallet (`shekyl-engine-core` fee path):* verify nothing adds a margin —
`fee = mask_round_up(rate × weight)` is already the shape
(`tx_fee_model.rs`); no change expected. `fee_policy.rs`'s absolute cap
unchanged.

*Instrument:* `fee_ladder.rs` loses the §10 arms, `RateLimited`,
`Quantized*`, hysteresis; `fee_floor.rs`'s `floor_rate` is replaced by a
call to the economics owner when it lands.

*Documents (rule 91 sweep, implementing PR):* CEN-M3's formula text in
[`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md); `CHANGELOG`
(relay admission behaviour is user-visible); `IMPLEMENTATION_INDEX.md`
rows; FOLLOWUPS rows for FL-R3 / FL-R3-STORE.

### §11.7 Results (run 2026-09-10 at `5574be2ea`; `/tmp/fl_r3_floor.{json,summary}`)

40 slew cells (5 ages × 8 traces) × 2 arms; 600 feedback cells × 2 arms.
Ten seconds.

**FL-E2 — per-block slew.** At age 0 the prediction lands on the number:
exact-arm one-block rise on the 40→500 step **160 bp** (predicted ~160),
ramps ≤ 33, stationary ≤ 13; integer-arm tick at `V` = 50 **209 bp**.
Two things the pre-registration got wrong, recorded rather than
re-fitted: *(i)* at `V` = 40 the integer tick is invisible in the `M_r`
term because 39 and 40 both clamp to the 0.8 rail — the tick appears at
`V` = 50, not at the rail (stationary-`V`40 rise 1 bp, `V`50 209 bp);
*(ii)* the bound omitted the burn term. `C = (1−σ)·M_r/(1−b)` and
`b/(1−b)` grows with `supply/asymptote`, so the same volume tick moves
`C` more as the chain ages: integer tick at `V` = 50 is 209 bp at age 0
and **307 bp at age 30**; exact one-block step rise is 160 at age 0 and
**225 at age 30**. The slew bound is `ΔC/C ≈ ΔM_r/M_r + Δb/(1−b)`, not
`ΔM_r/M_r` alone. §11.5's consequence clause ("`G` must be re-derived")
was mis-stated and is withdrawn: `G` is defined by the gap (0–2 blocks +
1), not by the slew; the slew prices the **grace**, and a larger slew is a
larger grace, not a different `G`.

**FL-E3 — lookback grace.** `grace_bp_max` (worst case any admitted
transaction sits below the current floor, for at most `G` blocks after a
rise): exact arm 479 at age 0 → **679 at age 30** on the 40→500 step;
≤ 32 stationary at every age. Integer arm: 501 → **706**, and its
stationary `V`50 grace is the tick itself (209 → 307). `grace_bp_mean` is
**0–6 bp in every cell of both arms**: in expectation the lookback gives
miners nothing; in the worst block after a 10× instantaneous step it
gives ≤ 7 % for three blocks. **Zero bounces under FL-R23 by identity.**
The road-not-taken column shows why: a 50 bp fixed pad bounces **281 of
19 997** quotes in the integer arm's *stationary* `V`50 cell at age 30
(1.4 %, in a chain doing nothing), and **even a 300 bp pad bounces 23–36**
quotes per 20 000 in every step cell on both arms. No fixed pad covers
the step; the lookback covers it exactly and charges nothing on average.

**FL-E1 — FL-C7 with the floor in the loop.** *Exact arm:* 596/600
converge inside the 50 bp bar at 30 000 blocks; the 4 misses are one cell
shape — age 30, ε = 3, `D` = 100, start displaced 8× — at 77 bp, changing
every block. Re-run at 120 000 blocks (diagnostic only, not committed):
**600/600, worst 34 bp** — a slow transient from the 8× displacement at
the most elastic ε, not a cycle. The map's fixed point is stable under raw
`C` in the loop, as §4.5 argued and round 2b's raw-`C` "oscillations" did
not contradict. *Integer arm:* 108/600 outside the bar at 30 000 blocks,
**152/600 at 120 000** (longer tails catch more toggles), amplitudes 62 →
**312 bp** — persistent limit cycles of ≤ ~1.5 ticks at the cell's `V`,
every one of them the truncation, none of them the map. The tick is not a
transient; it is a quantizer doing what quantizers do in a loop.

**FL-R24 — the pre-registered rule fires; RULED 2026-09-10: exact SMA, reward and floor together ("accepted/agree").** Integer stationary
`grace_bp_max` = 307 > 300 at age 30 (`grace_bp_mean` = 4, inside its
bound). By the rule as written, branch (ii) is recommended. The
recommendation on the evidence, not just the rule: the integer SMA is a
quantizer on a **consensus operand** — the block reward's `M_r` toggles by
2–3 % between adjacent blocks under Poisson noise today, independently of
anything this round did — and the exact ratio removes it from both the
reward and the floor with no new arithmetic (`calc_release_multiplier` /
`calc_burn_pct` already take `(volume, baseline)`). Floor-only exactness
(branch (ii) without the reward) is rejected here: it makes the miner's
`M_r` and the floor's `C` disagree by up to a tick and breaks the FL-V1
identity for a saving of nothing. **Recommended: exact SMA for the
operand, reward and floor together — a pre-genesis consensus row, opened
by the implementing PR, rule 07 evaluated there** (a change to a
consensus operand's resolution; a flag has no meaning, so the four
criteria are expected to hold). Until that row lands the integer arm is
what ships, and under FL-R23 it is safe — its tick costs miners ≤ 3 % for
≤ 3 blocks after a toggle and bounces nobody. The maintainer's call.

**FL-E4 — the `G` sweep (run 2026-09-10 at `3f3d3e9ac`;
`/tmp/fl_r3_floor_e4.{json,summary}`).** As pre-registered, against the
review's guess: the **worst case scales linearly with `G`** because the
SMA ramps for 720 blocks after a step — exact arm on the 40→500 step
479 → 639 → **807 bp** at age 0 (predicted ~800), 679 → 916 → **1 153**
at age 30 (predicted ~1 130); integer arm 706 → 1 067 → 1 407. The
**mean does not move**: worst stationary `grace_bp_mean` 4 → 4 → 5 bp
(exact), 4 → 5 → 6 (integer); mean of means over all 40 cells 1 → 2 → 3.
The integer tick's grace is flat in `G` (307 at all three): a tick is one
block up then level, so a wider window sees the same tick. Feedback grid
worst grace 399 → 526 → 650 (exact). **Decision rule: neither trigger
fires** (no stationary mean near 20 bp; the worst case scales exactly as
stated, so the operands are as slow as §11.2's safety argument assumes).
**`G` = 5 stands as derived.** What it buys against 3 is the partial
relay partition of review A-1 gone; what it costs is a worst case of
~8 % / ~11.5 % (age 0 / 30) below the current floor for at most five
blocks after a 10× instantaneous step, and 3 bp in expectation.

**Disposition of the round.** FL-R20…FL-R23 confirmed as ruled, FL-R23
at `G` = 5 with the A-1/A-2/A-3 amendments; FL-R24
RULED (ii)-with-reward; §11.6 goes to spec review
unchanged except that `check_fee`'s Rust predicate takes the `G+1` floors
as computed, whichever operand resolution is ruled.
