# TM-1 / A0 — Cross-persona clustering (the Stage-1 enabler), measured

**Status:** **ANALYZED — verdict in evidence (2026-06-27).** The firewall's Stage-1
enabler (are an operator's `P`-personas unlinkable *from each other*?) is closed
with a measured verdict: **disperse + disclose.** Shard-portfolio dispersion
decorrelates the shard channel, but the binding clustering signal was never the
shards — it is the **split partition** (how many simultaneous siblings, and when
they appear). Onset co-timing is a user-controllable lever; **split cardinality is
a structural C0 observable** that no behavioral heterogeneity masks, and it is the
named open problem handed to 2d-2.
**Scope:** the principal ↔ `P` firewall (gate-6), Attack **A0** / finding **TM-1**
in [`ARCHIVAL_FIREWALL_THREATS.md`](ARCHIVAL_FIREWALL_THREATS.md) §4; the
**sibling** channel (simultaneous multi-`P`), distinct from the **temporal**
channel (one persona across rotation, [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md)).
**Method:** the §7 silent-compliance audit + an endogenous-equilibrium simulation
and a C0 sibling-clustering matcher, both in `rust/shekyl-staking-sim`
(`--clustering`, `--matcher`) — the analogue of the cover's `--cover-targeting`
(measure, do not reason).
**Parent designs:** `ARCHIVAL_FIREWALL_THREATS.md` (A0/TM-1 catalog + §7 lens),
`ARCHIVAL_COVER_DRAW.md` (the simulate-don't-reason precedent),
`F1_TA3_TA7_LIFETIME_WINDOW.md` (the temporal channel + the regime bound),
`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` (DQ8 `W`-tail), `STAKER_ARCHIVAL_SIM.md`
(the economic substrate the equilibrium is validated against).
**Process rule:** `26-sub-pr-design-discipline.mdc` (firewall-load-bearing);
`21-reversion-clause-discipline.mdc` (the reopen criteria below).

---

## 0. The inversion (lead finding)

C-5 set out to solve **shard-portfolio clustering**: an operator with fixed capital
spreads its personas over a correlated shard set, and that overlap clusters them.
A whole mechanism followed — the wallet dispersive-default, the within-tier draw,
the value-approximating disjoint set, the haircut curve. All of it was real work on
the shard channel.

**The shard channel was never the binding signal.** With the sibling personas'
shard portfolios *fully decorrelated* (the dispersive default applied, in-tier, at
the capacity-rich attractor), a C0 chain-observer that scores persona pairs for
"same operator?" gets:

- **portfolio (which-shards) features: AUC 0.567** — barely above its measured null
  of 0.488. The shard channel is essentially noise.
- **partition (size + onset) features: AUC 0.969** — near-ceiling. The partition is
  essentially everything.

(Null = AUC under shuffled operator labels, same group-size multiset, random
membership; it sits at 0.485–0.516 across every scenario, so every figure here is
read against a *measured* baseline, not an assumed 0.5.)

That inversion is the finding. The dispersive default is necessary — you had to
decorrelate the shards to *prove* they were not the signal; an un-dispersed run
leaves portfolio AUC high and confounds the ablation — but C-5's deliverable was
never the value-matcher. It is the statement that **an operator's sibling personas
are linked by the structure of the split, not the content of the portfolios**, and
that hiding the split is a different, still-undesigned problem.

---

## 1. The unifying invariant (the north star)

> Each persona's portfolio must be statistically indistinguishable from an
> **independent** operator's — neither sibling-correlated (TM-1, this round) nor
> rotation-persistent (T-A1, `F1_TA3_TA7_LIFETIME_WINDOW.md`).

The two firewall channels are one property with two failure directions. T-A1
already conceded the temporal direction (portfolios are ~unique, so rotation
re-links unless storage changes — the conceded honest residual). TM-1 measures the
sibling direction. The invariant is what unifies them: uniqueness per se is not the
enemy; **correlation** (with siblings) and **persistence** (across rotation) are.
The matcher operationalizes the sibling half — "indistinguishable from independent"
becomes "pairwise discrimination AUC at the measured null."

---

## 2. Method — simulate, don't reason; believe the surprising number

The round ran as an endogenous-equilibrium simulation (`shekyl-staking-sim`,
reusing the validated `STAKER_ARCHIVAL_SIM.md` substrate — `g(age) = 1 + 2·age`,
scarcity `1/R·g(age)`, the {storage-rich 22/20, capital-rich 10/100} archetypes,
the L9/L18 retention friction) plus a C0 matcher. The discipline that produced the
verdict is worth recording because the answer changed three times under it:

1. **A positive control before any downstream number** (the CT-5 lesson). The
   equilibrium is asserted to reproduce the capacity-regime signature of `F1`:
   redundant deep coverage at the lean attractor (`R ≈ 3.7`), the coverage edge at
   the swan-2 trough (`R ≈ 1.0`). (The *relative* curve-steepness ratio actually
   inverts — recorded as a finding, not encoded as the control.)
2. **The surprising result gets believed before the convenient fix.** The first
   disperse model came out *anti-virtuous*; the immediate instinct was a model
   change that would restore the hoped-for result. Instead the mechanism was
   **verified in the existing data** (deep `R` falls −19% and deep value rises +61%
   as adoption rises — the predicted signature of "dispersion abandons the deep
   top"), and only then was the model corrected, as a *swept comparison arm* that
   keeps the anti-virtuous baseline side by side rather than deleting it.
3. **Every verdict-carrying number gets its own mechanism check.** The matcher's
   load-bearing result (cardinality re-inflation under heterogeneous K) is confirmed
   to *track the mechanism across seeds* (§5 Check A), not to be a single-seed
   artifact; the modelling-dependent number (onset co-timing) is conceded against
   the headline and tested for killability (§5 Check B).

The simulation is a focused harness, not `run_sim`; its only load-bearing claim is
that it reproduces the known attractor/trough result (the positive control), so
every verdict is a **ratio** (haircut fraction, AUC-at-null) where the arbitrary
absolute scale cancels.

---

## 3. The three dichotomy-killing findings

The round opened on a dichotomy: the dispersive default's cost is either a
*virtuous cycle* (demand-driven scarcity flattens as adoption rises → haircut → 0)
or a *capacity-bound floor* (supply-constrained shards keep the haircut up in the
trough). **Both halves are wrong**, in three independent, source-grounded ways:

| # | Finding | Mechanism (verified) |
| --- | --- | --- |
| **F-1** | **No per-shard serving cost exists.** | Consensus scarcity is `1/R · g(age)` with no intrinsic-difficulty term (`reward_arithmetic.rs::scarcity_milli`; `Shard` carries only `age`). So the "supply-constrained shard" the cost-floor half assumed is **absent** — the only supply constraint is *aggregate operator capacity*, not per-shard difficulty. (A `phi·age` sensitivity arm injects one: a per-shard cost ≥ ~0.5 re-steepens the attractor, so the rule-21 reopen number is *named with magnitude* — see §9.) |
| **F-2** | **An intrinsic `g(age)` age-premium floor dispersion cannot touch.** | Value `= (1/R)·g(age)`: only the `1/R` part is demand-driven and flattenable; `g(age)=1+2·age` is a fixed shard property. A persona that disperses *across value tiers* (into the hot tail) charges the unflattenable age-premium — which is why the faithful dispersive default must stay **in-tier** (mimic a deep-concentrated independent operator), spreading only *which* deep shards. The clean virtuous hypothesis dies on this regardless of capacity. |
| **F-3** | **The haircut is HIGHER at the capacity-rich attractor than the trough** — the reverse of the hypothesized capacity floor. | Capacity-rich → the cheap shards get covered, so the deep premium stands out as a *steep relative gradient* → dispersing (giving up the top) costs more (~0.57 cross-tier / ~0.15 in-tier). Starved → everything is uniformly scarce (flat relative gradient) → less to give up (~0.07–0.25). **And the cost structure compounds the wrong way:** dispersing is *cheapest exactly where the anonymity set is thinnest* (the trough), so the regime where privacy is most needed is the one where the shard-haircut is lowest but the *partition* exposure is highest. |

F-3 is the non-obvious one. It does not contradict `F1`'s regime bound (small
*anonymity set* in the trough) — it is a different axis (cost-of-dispersing) — but
it inverts the headline the round started with ("near-free at the attractor,
disclosed price in the trough"): the real cost structure is the opposite.

---

## 4. The dispersive-default verdict (the shard channel)

The faithful (in-tier) dispersive default — each persona re-selects a value-rank-
stratified set *within* the deep tier an independent operator occupies, disjoint
from its siblings and its prior self — **decorrelates the shard channel** at a
modest, bounded cost:

| regime | α=1 haircut (cross-tier) | α=1 haircut (in-tier, faithful) | deep redundancy | within-tier room |
| --- | --- | --- | --- | --- |
| **lean attractor** | 0.567 | **0.156** | 3.55 | available |
| **swan-2 trough** | 0.239 | 0.108 | 1.02 | **runs out** |

Two results, both load-bearing for the disclosure:

- **In-tier removes most of the cross-tier cost and the vicious cycle.** Deep `R`
  is preserved (~3.5 vs collapsing to 2.99) because in-tier dispersion does not
  abandon the deep top. So the cross-tier anti-virtuous result was substantially a
  *modelling artifact* (the `g(age)` premium + deep abandonment). The faithful
  haircut is ~0.15, roughly flat in α — a **modest fixed cost, not a virtuous
  cycle and not a vicious one**.
- **Dispersion is only *available* where coverage has redundancy.** The honest-
  degradation predictor is the **deep-tier redundancy** (mean served-deep `R`), not
  the pool size (deep-shards ÷ operator-deep stays ≈12 in both regimes and does not
  predict the failure). When redundancy → 1 (the trough, the small-network case),
  there is no slack to rotate a persona onto a fresh deep shard without a reward
  hit, so **within-tier dispersion runs out regardless of α**. The trough's *low*
  in-tier haircut (0.108) is "nothing moved," not decorrelation.

So the shard-channel disposition is a **loud default with a disclosed network-size
limit**: disperse where redundancy > 1; below it, tell the user decorrelation is
unavailable at this network size (§7).

---

## 5. The matcher — the partition is the binding signal

A C0 chain observer (public `shard_ids`, persona sizes, bond-post onset heights —
no principal knowledge) scores every persona pair for "same operator?" and is read
as discrimination AUC against the shuffled-label null. Aimed at the **lean
attractor, α=1, in-tier** — the regime where §4 showed the portfolios actually
separate, so "does the *partition* still leak despite decorrelation?" is the real
question. The deliverable is three conditionals, not one number.

**(1) Ablation — partition vs shards.** Portfolio (which-shards) AUC **0.567** vs
null 0.488; partition (size+onset) AUC **0.969**. The shards are noise; the
partition is the signal. (A smarter shard-adversary could only *raise* portfolio
AUC, but partition is already near-ceiling — so the verdict is robust to the matcher
features being crude; 0.567 is the favorable-to-dispersion read.)

**(2) Null — the metric is unbiased.** Shuffled-label AUC 0.485–0.516 across every
scenario. "Above baseline" is genuine, not an assumed chance line.

**(3) Heterogeneity — structural, not blur-able.** The partition decomposes into
two sub-channels with *different* mitigations:

| scenario | portf | partition | **size** | **onset** | full | null |
| --- | --- | --- | --- | --- | --- | --- |
| regular (equal, co-onset, uniform-K) | 0.567 | 0.969 | 0.759 | 0.990 | 0.842 | 0.488 |
| varied size (uniform-K) | 0.564 | 0.845 | **0.586** | 0.991 | 0.747 | 0.496 |
| staggered onset (w=96) | 0.572 | 0.905 | 0.794 | 0.788 | 0.812 | 0.515 |
| **full-range stagger (w=240)** | 0.527 | 0.814 | 0.792 | **0.612** | 0.727 | 0.512 |
| heterogeneous K | 0.650 | 0.997 | **0.898** | 0.991 | 0.880 | 0.507 |
| varied+stagger+hetK (full blur) | 0.559 | 0.917 | 0.845 | 0.802 | 0.786 | 0.516 |

- **Onset (co-timing) is a user-controllable lever.** It is dominant (0.990) but
  partly a modelling choice (siblings made near-perfectly co-onset). **Check B**
  (full-range stagger) drops it 0.990 → **0.612** — most of the way to null,
  confirming **stagger-by-default is a real wallet hygiene lever**. A small residual
  (+0.10) survives wallet-local staggering; full elimination needs a population-wide
  origin, not the operator's own base height.
- **Size (cardinality) is the structural irreducible core.** It is killed *only* by
  varied sizes *under uniform K* (0.586) — but real populations have heterogeneous K
  (some operators run 1 persona, some run 5), and **Check A** confirms heterogeneous
  K *re-inflates* it to 0.898 and that this **tracks the mechanism across seeds**:

  | high-K fraction | 0.10 | 0.20 | 0.35 | 0.50 | 0.75 |
  | --- | --- | --- | --- | --- | --- |
  | size-AUC (6 seeds) | 0.903 | 0.893 | 0.853 | 0.822 | 0.773 |
  | ±std | 0.007 | 0.006 | 0.004 | 0.010 | 0.005 |

  Size-AUC **falls as the high-K fraction rises** — exactly the predicted mechanism
  (more K=1 background → a K=5 operator's equal-small siblings are *more* distinctive,
  not less) — with tiny seed variance (not an artifact), and it **never approaches
  null** (0.77–0.90 across the entire K-mix). The cardinality of a simultaneous-
  persona split is a structural C0 observable that behavioral heterogeneity does not
  mask.

**Net:** the partition leaks. Onset → behavioral (a lever the user controls).
Cardinality → structural (no lever; disclose). Even the full blur leaves AUC
0.79 — well above null.

---

## 6. Correlate-by-correlate dispositions (the §7 silent-compliance audit)

Every correlate shared across an operator's personas, each given exactly one of
**enforced-invariant / loud-default / disclosed-cost** — never silent compliance
(the strictly-dominated option).

| Correlate | Channel | Disposition | Basis |
| --- | --- | --- | --- |
| **Key independence** | crypto | **Enforced invariant** (closed) | Per-persona keys are HKDF-PRF-independent (`shekyl-archival-retention/src/archival_p.rs`); not an attack surface. |
| **Shard portfolio** (which shards) | C-2/C-5 shard channel | **Loud default** (dispersive default) **+ disclosed network-size limit** | §4: in-tier dispersion drives portfolio AUC to ≈ null at ~0.15 haircut where deep redundancy > 1; below redundancy 1 it is unavailable (disclose). |
| **Persona onset** (co-timing of siblings) | partition sub-channel | **Loud default** (stagger onset by default) | §5 Check B: full-range stagger drops onset AUC 0.99 → 0.61; jitter it the way the standoff jitters entry timing. |
| **Split cardinality** (how many siblings) | partition sub-channel | **Disclosed cost** + **named open problem (2d-2)** | §5 Check A: structural across the K-mix (0.77–0.90), not blur-able; no behavioral lever. §8. |
| **Funding source / cadence** | C-3 | **Routed to TM-2** | Funding-event independence over time; TM-2's territory (`ARCHIVAL_FIREWALL_THREATS.md` A1/TM-2). |
| **Claim rhythm / temporal exclusivity** | C-4 | **Routed to TM-4** | Earnings-scale fingerprint; TM-4 (`ARCHIVAL_FIREWALL_THREATS.md` A3/TM-4). |
| **`W`-tail retirement shape** | C-1 | **Enforced invariant** (anchor-free sliding cutover) + secondary | DQ8's terminal predicate; the residual post-DQ8 claim tail is closed by the anchor-free sliding-cutover retirement shape. Contributing, not binding (the matcher shows cardinality/onset dominate). |

No row is left to silent user compliance.

---

## 7. The honest-degradation disclosure (per `80`/`81`/`82`)

The disclosure must say two true things — no protocol jargon (`81`), the failure
mode as first-class scope (`82`):

1. **Shard hygiene is automatic, with a network-size limit.** The wallet disperses
   your archival holdings for you so your archival identities don't look related by
   *what* they store. This works while the network is large enough; in a small or
   shrinking network it has **no room to disperse**, and the wallet says so plainly
   rather than silently failing — the trigger is the deep-tier redundancy crossing
   1 (the swan-2 trough), an enforced loud state, not a silent one.
2. **Running several archival identities at once is only partly hideable.** The
   wallet **staggers when your identities come online** by default (a lever it
   controls), but **how many you run at once is visible** and cannot be fully
   hidden by the wallet. If you run multiple archival identities simultaneously,
   that count is a public correlate. (Draft wallet copy: *"Your archival identities
   are kept from looking related by what they store and when they appear. The
   number you run at the same time is visible on chain; for the strongest privacy,
   keep simultaneous identities few, or run them one at a time."*)

This is **disperse + disclose**, not "rotate-with-varied-timing-and-you're-fine":
the cardinality residual is real and named, and the user is told once, at the
moment of the choice, what running many simultaneous personas costs.

---

## 8. The named open problem for 2d-2 (precisely scoped)

Hiding the partition is **not** "hide the partition" (vague). It is two observables
with different tractability:

- **Co-timing → a cadence problem 2d-2 already owns.** When an operator's siblings
  appear and fund is the same family as the standoff entry-gap and the anchor-free
  draws; stagger persona onset/funding across a wide window as a wallet default.
  Inherited, solvable with existing machinery.
- **Cardinality → structural, genuinely new.** *The number of simultaneous personas
  an operator runs is a structural C0 observable that behavioral heterogeneity does
  not mask* (§5 Check A, in evidence). It is structural **specifically because the
  operator cannot make it unobservable by behaving differently**: you cannot jitter
  "how many," and varying the siblings' sizes does not mask it (it re-inflates under
  realistic heterogeneous K). Behavioral levers — the only ones a wallet owns — are
  exhausted. So 2d-2 inherits a **two-lever structural design space**, named here
  (even where one is likely rejected) so the round opens on the *shape* of the
  problem, not a blank page:

  - **Lever A — standardize or cap simultaneous personas per funding lineage.**
    Removes the cardinality *variance* the matcher keys on (if every operator
    presents the same count, count carries no operator signal). **Cost:** a
    flexibility / consensus-rule cost (it constrains how an operator may structure
    its archival operation, and it is a genesis-frozen parameter); the standardized
    count must be chosen against the same regime bound this round surfaced (a count
    that is fine at the lean attractor may be coercive in the trough).
  - **Lever B — make persona instantiation itself unobservable.** Would hide the
    count at the source rather than flatten it. **Cost:** likely *impossible against
    C0* — bond posts are public by construction (`bond_wire` is cleartext), so a pure
    chain observer counts an operator's simultaneous bonds directly; this lever can
    at best be partial and probably reduces to Lever A plus network-layer hygiene.

Both belong to 2d-2 (the network/broadcast firewall) where instantiation/funding
cadence lives — not to the shard channel this round closed. This is the difference
between handing 2d-2 a cadence problem it can already solve and a structural problem
that needs new mechanism: the cardinality question is the latter, **scoped with a
measured floor 2d-2 must beat** (AUC 0.77–0.90 at the null) and a named candidate
lever pair (A viable-but-costly, B likely-foreclosed-against-C0).

---

## 9. Residuals and reopen criteria (`21-reversion-clause-discipline`)

- **Per-shard serving cost (F-1 reopen).** The verdict rests on the *absence* of a
  per-shard cost. The `phi` sensitivity arm gives the reopen number: a per-shard
  cost term whose magnitude steepens the attractor (`phi·age` with `phi ≳ 0.5`
  materially re-floors the in-tier haircut and pulls deep `R` from 3.5 → 2.2). **If
  the protocol ever tiers shards by size/difficulty** (a plausible future), C-5
  reopens, and this arm says at what cost magnitude the attractor flips
  virtuous → floored.
- **Onset residual — population-wide-origin stagger (rule-21, numeric trigger).**
  Wallet-local full-range staggering drives onset AUC from 0.99 to **~0.61** — most
  of the way down, but a residual **+0.10 above the 0.51 null** survives because a
  sibling staggers against the *operator's own* base height, not a shared chain
  origin. **Rejected now:** the population-wide-origin stagger arm is not built,
  because the cardinality core is structural regardless (§8), so driving onset to
  null sharpens only the *disclosure*, not the verdict. **Reopen when (the number,
  not a vibe):** 2d-2's cardinality mitigation lands and its combined-partition
  residual target cannot be met with onset stuck at the ~0.61 wallet-local floor —
  i.e. onset becomes the *binding* term in the combined residual rather than a
  sharpening one. **Re-evaluation:** add the population-wide-origin stagger arm to
  `--matcher`; if it drives onset to the null, onset moves from disclosed-residual
  to enforced-default and the combined-residual claim is available; if it does not,
  onset stays disclosed and 2d-2's target must be met on cardinality alone. Without
  this trigger the residual is a TODO that rots; with it, it is a decision.
- **Matcher feature ceiling.** Portfolio AUC 0.567 is "near null *with these
  features*"; a richer shard-adversary is the floor, not the ceiling. This does not
  move the verdict (partition is already near-ceiling, so a better adversary raises
  both and the *binding* channel is unchanged) but is recorded so the shard-channel
  "decorrelated" claim is read as "decorrelated against a C0 centroid/coherence
  adversary," reopen-able if a stronger shard feature beats the partition.
- **Cardinality mechanism.** Not a residual — confirmed across the K-mix and seeds
  (§5 Check A). The structural claim is the bulletproof core of the verdict.

---

## 10. Reproduce

```bash
cd rust
cargo run -p shekyl-staking-sim -- --clustering   # §3/§4: 3 findings + within-tier comparison + room
cargo run -p shekyl-staking-sim -- --matcher       # §5: ablation + null + heterogeneity + Checks A/B
cargo test -p shekyl-staking-sim clustering         # positive control + matcher validity controls
```

The harness lives in `rust/shekyl-staking-sim/src/clustering.rs` (deterministic
SplitMix64 seeding; results are git-diffable across runs, like `cover.rs`).

## Revision history

- **2026-06-27:** Created. The inversion (shard channel is not the binding signal);
  the three dichotomy-killing findings (no per-shard cost, `g(age)` floor,
  attractor-costlier-than-trough); the disperse-default verdict + within-tier-room
  threshold; the matcher (partition is the signal; cardinality structural via Check
  A, onset a user lever via Check B); correlate dispositions; the honest-degradation
  disclosure; the precisely-scoped 2d-2 cardinality open problem.
