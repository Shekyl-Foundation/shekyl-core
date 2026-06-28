# TM-1 / A0 — Shard-portfolio linkage across sequential persona rotation

**Status:** **ANALYZED — accepted + disclosed (2026-06-28).** TM-1 (are an operator's
`P`-personas unlinkable *from each other*?) reduces, against the actual design, to
the shard-portfolio correlate across **sequential** rotation. The dispersive-default
shard-selection built this round reduces the binding at a modest, capacity-bounded
haircut; the residual is the **temporal** intersection channel, which is T-A1 / TM-2
(already instrumented in `fingerprint.rs`), not a new problem.
**Scope:** the principal ↔ `P` firewall (gate-6), Attack **A0** / finding **TM-1** in
[`ARCHIVAL_FIREWALL_THREATS.md`](ARCHIVAL_FIREWALL_THREATS.md) §4.
**Method:** the §7 silent-compliance audit + an endogenous-equilibrium simulation in
`rust/shekyl-staking-sim` (`--clustering`) — the analogue of the cover's
`--cover-targeting` (measure, do not reason).
**Parent designs:** `ARCHIVAL_FIREWALL_THREATS.md`, `ARCHIVAL_COVER_DRAW.md`,
`F1_TA3_TA7_LIFETIME_WINDOW.md` (the temporal channel + the regime bound),
`STAKER_ARCHIVAL_SIM.md` (the economic substrate the equilibrium is validated against).
**Process rule:** `26-sub-pr-design-discipline.mdc`; `21-reversion-clause-discipline.mdc`.

---

## 0. The retraction (ground the design before the rigor)

An earlier draft of this round modelled an operator **splitting capacity across K
*simultaneous* personas** to hide scale, and built a sibling-clustering matcher and a
"split cardinality" open problem on it. **That premise is a phantom and is retracted.**
The staking design rotates personas **sequentially** — `stake_engine` (atomic rotation)
is explicit: *"there is never a window with two active personas"*; a bonded retired
persona stays resident only so unbonding/claiming remains reachable (the `W`-tail),
never as a second active persona. The design does not run simultaneous personas, so the
sibling channel does not exist.

The economics confirm it independently: the `1/R` scarcity reward makes simultaneous
personas self-defeating. Two personas on the **same** shard raise `R` and split one
reward while paying double storage/serving work — diminishing pay for double cost. Two
personas on **different** shards are simply a bigger operator doing proportionally more
work (storage, serving, challenges, retrieval) for proportional pay — pure coverage, no
exploit, no double-pay. So the only "downside" of running simultaneous personas is
self-correlation — a self-inflicted privacy choice. **Disposition: a one-line wallet
disclosure** (don't run simultaneous personas to hide scale — it is self-defeating and
the design's sequential rotation is what you want), **not a mechanism and not a round.**
(For the record, so the retraction is not mistaken for sloppy work: the matcher was built
and gate-clean, and its AUC / ablation / heterogeneity findings were *internally valid* —
they simply measured the self-correlation of a behavior the design forecloses. Sound
analysis, wrong question — which is the whole lesson.)

The methodological lesson, named: the discipline that served this work — *believe the
surprising number, verify at source* — will happily analyze a channel rigorously whether
or not the design has it. The fix is to ask *"does the design actually do this?"* **before**
the rigor, not after. The substrate had already answered (sequential rotation) when the
matcher was built on simultaneous personas; the answer just wasn't applied.

---

## 1. What TM-1 actually is

With the sibling channel gone, the real, design-relevant correlate is the **F1
portfolio-bound linkage across sequential rotation**: when an operator rotates from
retired persona A to fresh persona B, B's public shard set
(`bond_wire::HoldingsDescriptor::shard_ids`) is on-chain. At the lean equilibrium
portfolios are ~unique (`F1`/T-A1), so a B that re-takes A's set re-links the succession
on the portfolio alone — rotation without a storage change does not decorrelate. The
**unifying invariant**: each persona's portfolio must be statistically indistinguishable
from an independent operator's — neither rotation-persistent (T-A1) nor (in a design that
had it, which this one does not) sibling-correlated.

---

## 2. Three findings on the value structure (the dichotomy is dead three ways)

The dispersive default's cost was hypothesized as either a *virtuous cycle* (scarcity
flattens with adoption → haircut → 0) or a *capacity-bound floor*. Both are wrong, three
independent and source-grounded ways:

| # | Finding | Mechanism (verified) |
| --- | --- | --- |
| **F-1** | **No per-shard serving cost exists.** | Consensus scarcity is `1/R · g(age)` with no intrinsic-difficulty term (`reward_arithmetic::scarcity_milli`; `Shard` carries only `age`). The only supply constraint is *aggregate operator capacity*. A `phi` sensitivity arm injects one: `phi·age` with **φ ≳ 0.30** re-steepens the in-tier attractor (haircut crosses the floor; deep `R` falls) — the rule-21 reopen number if the protocol ever tiers shards by difficulty. |
| **F-2** | **An intrinsic `g(age)` age-premium floor dispersion cannot flatten.** | `value = (1/R)·g(age)`; only `1/R` is demand-driven. Dispersing *across value tiers* (into the hot tail) charges the unflattenable `g(age)` premium — which is why the faithful dispersive default must stay **in-tier** (mimic a deep-concentrated independent operator), spreading only *which* deep shards. |
| **F-3** | **The haircut is higher at the capacity-rich attractor than the trough.** | Capacity-rich → cheap shards get covered, so the deep premium stands out as a steep relative gradient → dispersing costs more; starved → uniformly scarce (flat gradient) → less to give up. So the shard-haircut is *lowest* where the anonymity set is *thinnest* — a different axis from `F1`'s regime bound, but worth recording. |

---

## 3. The disposition — dispersive default + honest degradation

The faithful (in-tier) dispersive default — on rotation, B re-selects a value-rank-
stratified set **within the deep tier**, disjoint from A's retired set — decorrelates the
shard portfolio across the succession at a **modest, capacity-bounded haircut**
(`shekyl-staking-sim --clustering`, α = adoption fraction):

| regime | α=1 haircut (cross-tier) | α=1 haircut (in-tier, faithful) | deep redundancy |
| --- | --- | --- | --- |
| **lean attractor** (~80 bonded) | 0.471 | **0.099** | 5.9 |
| **trough** (~20 bonded) | 0.364 | **~0.00** | 1.6 |

Two load-bearing reads:

- **In-tier is near-free and removes the vicious cycle.** Deep `R` is preserved (~6 vs
  cross-tier collapsing to 5.0) because in-tier dispersion does not abandon the deep top —
  so the cross-tier anti-virtuous result (haircut rising 0.18 → 0.47 with α) was a
  modelling artifact (the `g(age)` premium + deep abandonment), confirmed in-evidence
  (deep `R` falls 6.1 → 5.0, deep value rises 0.41 → 0.58 as α → 1 in cross-tier; flat in
  in-tier). The faithful haircut is ~0.10 at the attractor, ~0 at a moderate trough.
- **The honest-degradation predictor is the deep-tier redundancy.** Dispersion needs
  slack to rotate a fresh persona onto a different deep set; the binding quantity is
  **mean served-deep `R`** (not the pool size, which stays ≈ deep ÷ op-deep ≈ 6 in both
  regimes and does not predict the failure). Redundancy is ~6 at the attractor and ~1.6
  at a 20-operator trough — both have room. It approaches **1** (no slack) only in a
  *deep crisis trough* (the smallest bonded populations, below ~15), where within-tier
  dispersion runs out **regardless of α**.

**Net:** TM-1's shard channel is **accepted + disclosed**. The dispersive default reduces
the F1 portfolio-bound binding at a near-free, capacity-bounded cost; below the redundancy
floor it is unavailable and the wallet must say so. The residual cross-persona linkage that
remains is the **temporal intersection** (an adversary clustering the rotation succession
over a lifetime) — that is **T-A1 / TM-2**, already instrumented in `fingerprint.rs`, not a
new problem and not a 2d-2 cardinality hand-off (there is none).

---

## 4. Correlate dispositions (the §7 silent-compliance audit)

Every correlate shared across an operator's sequential personas, each given exactly one of
**enforced-invariant / loud-default / disclosed-cost** — never silent compliance.

| Correlate | Disposition | Basis |
| --- | --- | --- |
| **Key independence** | **Enforced invariant** (closed) | Per-persona keys are HKDF-PRF-independent (`shekyl-archival-retention` `archival_p`); not an attack surface. |
| **Shard portfolio across rotation** | **Loud default** (dispersive default) **+ disclosed network-size limit** | §3: in-tier dispersion → ~0.10 haircut where deep redundancy > ~1.5; unavailable in a deep crisis trough (disclose). |
| **Simultaneous personas** | **Disclosed cost** (one-liner) | §0: the design is sequential; running simultaneous only self-correlates and is economically self-defeating. No mechanism. |
| **`W`-tail retirement shape** | **Enforced invariant** (anchor-free sliding cutover) | DQ8 terminal predicate; the residual post-DQ8 claim tail is closed by the anchor-free sliding-cutover retirement shape. Sequential rotation's tail. |
| **Funding source / cadence** | **Routed to TM-2** | Funding-event independence over time. |
| **Claim rhythm / earnings scale** | **Routed to TM-4** | The earnings-scale fingerprint — named, **unmeasured**; a bounded one-time measurement (dense distribution ⇒ large set for typical operators; potentially distinctive for outliers/whales). |

---

## 5. Wallet disclosure (per `80`/`81`/`82`)

> **Archival pseudonym hygiene.** Your stored shards are public on chain. The wallet
> changes *which* shards a fresh rotation serves so your archival identities don't look
> related by what they store — automatic, and near-free in a healthy network. In a very
> small or shrinking network it has no room to disperse, and the wallet says so rather than
> failing silently. Do **not** run several archival identities *at the same time* to hide
> your size — it doesn't help (it only links them to each other) and it costs you double
> work; the design's one-at-a-time rotation is what protects you.

---

## 6. Residuals and reopen criteria (`21-reversion-clause-discipline`)

- **Per-shard serving cost (F-1).** The verdict rests on the *absence* of a per-shard cost.
  Reopen if the protocol ever tiers shards by size/difficulty; the `phi` arm gives the
  number — a cost term `phi·age` with **φ ≳ 0.30** re-floors the in-tier attractor.
- **Honest-degradation threshold.** The redundancy → 1 floor (dispersion unavailable) is
  approached only in a deep crisis trough (< ~15 bonded). Reopen the wallet copy if the
  realized minimum bonded population sits below that floor at genesis economics.
- **Earnings-scale fingerprint (TM-4).** Named, unmeasured; the dispersive default's value-
  matching reintroduces a scale signal. Measure once (the cover's method) to bound whether
  it is negligible (typical) or an outlier risk (whales) — a bounded check, not a round.

---

## 7. Reproduce

```bash
cd rust
cargo run -p shekyl-staking-sim -- --clustering   # §2/§3: findings + within-tier comparison + room
cargo test -p shekyl-staking-sim clustering        # positive control + in-tier/room controls
```

Harness: `rust/shekyl-staking-sim/src/clustering.rs` (deterministic SplitMix64 seeding).

## Revision history

- **2026-06-27:** Created (cross-persona clustering, disperse + disclose; with a
  simultaneous-persona sibling matcher).
- **2026-06-28:** **Retracted the simultaneous-persona premise** (the design is sequential —
  `stake_engine` "never two active personas") and the sibling-clustering matcher / cardinality
  hand-off built on it. Reframed to the real, sequential-rotation shard-portfolio correlate:
  dispersive default + honest-degradation disclosure; residual is the temporal channel
  (T-A1 / TM-2). Shrank the doc to what the design actually poses.
