# Archival Cover-Amount Draw — entropy scoping (genesis-adjacent)

**Status:** SCOPING (2026-06-20, review-revised). Design-questions enumerated;
not yet decided.

> **Correction (2026-07-01) — `C_min` pinned post-sim; the "pending the 2d-1 ramp" language
> below is superseded.** `C_min` was scoped here (pre-sim) as a runway floor whose *final value
> awaited the 2d-1 earnings-ramp sizing*. The sim ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md))
> is the definitive authority and took a different direction — it does **not** track a runway
> `C_min`. Disposition: **`C_min = 1 rung = 0.75 SKL`** (`= ARCHIVAL_BOND_FLOOR`, gate-4-pinned and
> fixed — §2.3), sim-supported (the `--cover` harness shows even `k = 0` / the `cover == 0` opt-out
> still gets same-rung cover ≈ 1.9). The "pending the 2d-1 ramp for its final value" phrases below
> (§2.2 / §7.4 / §8) are **retired**; `COVER_RUNWAY_FLOOR_ATOMIC` is not provisional.

Off-wire, scanner-independent, un-vendor-independent —
parallelizable now (no open upstream decision: the bond-standardization is
**decided in shape**, flat `floor × shards`, pinned rung — §2.3). **But off-wire
is *not* re-tunable (§2.5):** the anonymity-uniformity requirement genesis-freezes
the **whole** distribution — **shape *and* bounds**. So the next step is a genesis
pin of **shape together with bounds sized against pessimistic inputs**; post-testnet
**confirms** adequacy, it cannot **fix** a mis-pinned bound — **not**
shape-now/bounds-later. **§7 is the analytical cut** at the bound: the lattice dial
derived (`k = W/floor`), the regressive capital tax surfaced, and the `--cover`
harness **built and run** (`shekyl-staking-sim --cover`). Two headline findings:
(§7.4) the cover decoy pool is **bounded by `N_P` and saturates**, so the dial
sizes the *mean* and the worst-case **tail** is a firewall-composition property;
and (§7.5) economic participation makes `C_max` a **two-sided interior optimum**
(too-large prices low rungs out — humped, not monotone), realized optimum
`k ≈ 8–12 (~6–9 SKL)` — **not** the "err-large, go big" the earlier draft assumed
(retired in §2.5). **Resolved (§7.6/§7.7, `--cover-fn`):** a frozen scalar is
**not** the object — `k*` slides 6 → 20 across the input corners (driven by the
softest, least-observable input, affordability), so the best single `k` holds only
77% of peak at its worst corner. The genesis object is a **public, height-conditioned
distribution** (pin a *function*, not a constant): it dominates the best frozen
scalar on realized set (up to ~2.6× at the dense end) and its one theoretical leak
(height-conditioning) is **~0%** at the realistic population drift (timing window ≪
population epoch). **But freezing a function *relocates* the genesis risk (§7.8):** it
inherits a **manipulation** surface a constant never had, so `f` must read a **slow,
reorg-final, canonical** aggregate (proposal: the settlement-epoch-boundary live-bond
count, `SETTLEMENT_EPOCH_BLOCKS`, read below `ARCHIVAL_REORG_DEPTH_BLOCKS`) — not a tip
snapshot — and its **bootstrap boundary** must be pinned deliberately. The statistic
`f` trusts is now the whole ballgame. **Resolved (§7.9, `--cover-targeting`):** the
statistic is the **bond count** (global) driving a **uniform `D`** — a histogram's
per-rung response *is* a rung-local targeting surface (it halves a chosen victim at
`m = 5` vs count's `> 8`, surgically vs broadly), so count-uniform is pinned (the
dispersion scalar is a *deferrable* capital-efficiency refinement, not a genesis
requirement — measured). **Grounding correction (§7.9):** the statistic must be the
**standing-bond *stock*** read at the last-closed epoch boundary (final-by-construction);
`EpochCloseInputs.bonds` is the *serving* set, not the stock, and the standing aggregate
is audit-only today — so a canonical stock read is itself a spec item, not a ready field.
**Parent design:** `ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §3.4 (cover-stays-with-P,
SETTLED) + §SP-2.d; `GENESIS_TX_WIRE_FORMAT.md` §2.0 (the security-crux flag);
`ARCHIVAL_FIREWALL_GATE6.md` §10.12 (the funding seam); `STAKER_ARCHIVAL_SIM.md`
(the shard-count / bond-standardization population — the input C1 inherits).
Mechanism sibling: `shekyl-standoff` (the entry-gap timing draw).
**Process rule:** `26-sub-pr-design-discipline.mdc` (genesis-adjacent privacy
surface; lightweight — the *architecture* is settled, this pins one draw).

---

## 0. Why this exists, and why now

2c-2b settled the cover **architecture** (cover-stays-with-`P`, §3.4): the
principal sends `bond_floor + cover` to `P`; `P` stakes the floor (public
`bond_credit == bond_floor` on the bond-post) and keeps the `cover` as a
confidential change-to-`P` output. What it did **not** settle is the **cover
amount itself** — the distribution it's drawn from. `GENESIS_TX_WIRE_FORMAT.md`
§2.0 flags this as the security crux: *the cover defense reduces entirely to the
entropy of the cover draw.*

It is **genesis-adjacent** (must be pinned before 2d's bond-tx assembly lands —
2C2B forward-action) and **off-wire** (cover is an ordinary confidential CT
output, no wire field), so it is **independent of the shekyl-oxide un-vendor and
the scanner** — parallel to the wire-format port.

---

## 1. Threat model — the link the cover defeats (and what it does *not*)

**Not** the on-chain amount (the principal→`P` transfer is confidential CT — the
on-chain value is already hidden). The cover defends against an observer who
learns the principal's spend amount **out-of-band** (`A` — an exchange
withdrawal, KYC'd desk, partially-deanonymized wallet) and tries to link that
principal to a stake position. `bond_floor` is **public** (cleartext on the
bond-post, `bond_credit == bond_floor(holdings)`, `==` not `≥`), keyed to `P`.

- **Without cover:** principal sends exactly `bond_floor`; the observer matches
  `A == bond_floor` → links principal → `P`.
- **With cover:** principal sends `A = bond_floor + cover`; the observer must
  decide, per public bond, whether `A − bond_floor` is a plausible cover.

**Three corrections to a naive "count of consistent bonds" (the metric, §C1):**

1. **Joint amount × timing, not amount-marginal.** The observer who knows `A`
   knows *when* the withdrawal happened, and the bond posts a bounded interval
   later — `≥ 1 SEB` spacing plus the `shekyl-standoff` entry-gap window
   (`DEFAULT_ENTRY_GAP_WINDOW = 600`). So the real candidate set is the
   **intersection** of amount-consistent bonds **and** bonds posted inside that
   timing window — far smaller than the amount-marginal set. **Consequence:** the
   entry-gap standoff width is an *input* to the cover metric; a tight standoff
   forces wider cover and vice versa, so **the entry-gap draw and the cover draw
   must be sized jointly**, not independently.
2. **Posterior-weighted, not a raw count.** §C5/DQ5 pins the distribution
   *publicly*, so a distribution-aware attacker knows the cover pdf and weights
   each candidate by it. The metric must be an **effective anonymity set**
   (posterior-weighted — an inverse-participation-ratio over the attacker's
   likelihood), not a membership count. *(This is what makes uniform the **answer**
   to DQ1, not just a preference — §4.)*
3. **Scope: the cover protects the naive direct-funder only.** The attack needs
   `A == bond_floor + cover` — i.e. the principal funds `P` *directly* from the
   identifiable withdrawal with **no intermediate handling**. Any consolidation,
   intermediate hop, or independent spacing on the principal side breaks that
   equality *orthogonally to the cover*. So the cover is the decorrelation for the
   **direct funder**; a sophisticated funder gets upstream protection the cover
   doesn't supply. C1 sizes entropy for the **worst-case direct path** — the cover
   is one defense in the firewall, not the whole of it.

So the defense's strength = the **effective, timing-intersected anonymity set**
the cover distribution induces over the live-bond population. That population is a
**discrete lattice**, not a smooth spread — §2.3.

---

## 2. The tensions to resolve (the heart of the scope)

### 2.1 Entropy vs working-capital predictability (GENESIS §2.0)

`P` holds the cover as working capital (seeds the fund-from-earnings pool, §3.4
item 3). An amount chosen for *operational utility* (round, fee-sized, correlated
with `P`'s activity) is **predictable** — what the defense can't tolerate.
*Resolution to ratify (DQ4):* the cover is an **entropy draw, privacy-primary**;
the working-capital use is a **downstream consequence** of whatever was drawn,
never a constraint that narrows it (mirrors cover-stays-with-`P`). **But** the
working-capital role sets a *floor* with privacy meaning, not an upper constraint
— §2.2 / C3.

### 2.2 The lower bound is a runway floor, not a dust floor

If the entropy draw comes in **small**, `P` depletes the working capital and must
**re-fund from the principal** — which is *another cold-start link*, the exact
event the cover exists to prevent. So `C_min` is not economic dust; it is **the
capital below which `P` re-links too soon**. It must guarantee enough
working-capital runway (until earnings carry, or until a separately-decorrelated
top-up) that the draw does not induce premature re-funding — and it therefore
**interacts with the steady-state fund-from-earnings ramp (2d-1)**. A strictly
positive `C_min` also reserves `cover == 0` cleanly for the named opt-out (no tail
draw overlaps it — DQ6).

### 2.3 The distribution can't be pinned independently of `bond_floor` structure

`bond_floor = ARCHIVAL_BOND_FLOOR_ATOMIC (750_000_000) × shard_count`
(`bond_floor.rs:19-28`) — a **discrete, shard-quantized lattice** with rungs at
multiples of the per-shard floor, **not** a continuous spread. This makes the
cover's anonymity contribution a **step function of `C_max`**:

- `C_max < floor` ⇒ the cover only mixes you among **same-shard-count** stakers
  and **leaks your shard count** (hence approximate bond size — `A` localizes to
  one lattice rung).
- To blur across `k` rungs you need `C_max ≥ k × floor` — i.e. **capital
  proportional to how many rungs you want to hide across**.

So DQ2's "entropy ↔ capital" dial has *specific structure* — it steps at
multiples of `floor`. **C1's population analysis must run over the discrete
lattice and the actual shard-count distribution, not a smooth spread.**

**Status of that input (checked `STAKER_ARCHIVAL_SIM.md`, 2026-06-20):** the
needed pieces are **decided in *shape*, not open** — not a blocked decision:

- **Lattice rung is pinned.** Bond magnitude is **flat, `floor × shards`**
  ("L4 resolved: keep flat bond magnitude", `:218`; `bonded = bond_floor ×
  Σ|holdings|`, `:493`), with `ARCHIVAL_BOND_FLOOR_ATOMIC = 750_000_000` gate-4
  pinned. So the rung size is fixed.
- **Distribution shape is characterized**, not chosen ad-hoc: heterogeneous
  archetypes (capacity/capital-bounded, `min(⌊capital/bond⌋, ⌊storage/shard⌋)`),
  a banded plateau-cap anti-whale (`:252/:339`), `N_P` envelope {lean 79 / thick
  154 / fee-era 17–62}.
- **But the distribution's *magnitudes* are post-testnet** — the sim repeatedly
  pins shape now and calibrates magnitude later ("post-testnet calibrations of an
  already-understood curve", `:52/:83/:105/:187`).

**Consequence:** C1 is **not** blocked on an open decision — it *inherits* the
sim's already-shaped lattice population (the rung is pinned, the shard-count
*shape* is characterized). What it does **not** do is "pin shape now, calibrate
the magnitude later": the bounds are frozen too — see §2.5. Post-testnet
population data is the **same class** as every other staking magnitude only for
*confirming* a conservative genesis bound was adequate; it cannot be the thing
that *sizes* the bound, because by then the bound is unmovable. The sizing
criterion is therefore **not** "dominate the realistic spread" (there is no
realistic spread pre-genesis) but **"clear the target effective anonymity set
under the *pessimistic* per-rung populations the `N_P` envelope allows"** — the
**thin** end {17–62}, not the fat end {154}.

### 2.4 Per-wallet uniformity — necessary but **unenforceable** (state it plainly)

Like the entry-gap window, the cover **distribution must be identical across
wallets** — if wallet A draws `~U[0,X]` and B draws `~lognormal`, the
*distribution choice* fingerprints the software and the distribution-aware
attacker (§1.2) flags off-pdf covers as hand-picked: a distinguishable class. So
it is a single pinned, single-sourced policy.

**But because the cover is off-wire, this invariant is *not enforceable*** — the
engine accepting a `CoverAmount` cannot verify it was drawn from the pinned
distribution; a non-conforming wallet or a user override silently draws
otherwise. So uniformity is a **soft, conformance-dependent guarantee**, not a
consensus rule (unlike the on-wire `enc_label` invariant). That is exactly *why*
the single-source / golden-vector / conformance harness matters: it makes the
**reference wallet** conform and makes the pinned draw the **only low-friction
path** — it cannot make *all* wallets conform. The defense is "pinned draw is the
default + override is a **disclosed privacy cost**," not enforcement. A front-end
override therefore joins the disclosed-opt-out family with `cover == 0` and
stake-once-recover (§3.2).

### 2.5 The whole distribution is genesis-frozen — off-wire is *not* re-tunable

The anti-fingerprint requirement (§2.4) has a consequence sharper than "pin a
constant": it freezes the **entire** distribution — **shape *and* both bounds** —
at genesis, on anti-fingerprint grounds rather than consensus ones. "Off-wire"
buys freedom from the **wire format**, **not** freedom to **re-tune**.

**A boundary move is inferable even off-wire.** The attacker's test is
`candidate_cover(bond) = A − bond_floor(bond) ∈ [C_min, C_max]?`. If any boundary
moves at a known height `H`:

- **widen `C_max`** ⇒ a bond whose candidate cover lands in the newly-opened band
  is unambiguously **post-`H`** — its set collapses to post-`H` bonds in that band;
- **narrow `C_max`** ⇒ flags the old wide bonds;
- **raise `C_min`** ⇒ flags everything below the new floor.

There is **no clean migration**: a past bond carries its old-regime cover forever
and cannot re-draw. So the cover distribution is effectively **genesis-frozen**.

**The decision rule — *not* "err large"; an interior optimum (corrected by §7.5).**
An earlier framing here said over-provision, on the reasoning that too-small
`C_max` is an un-fixable privacy failure while too-large merely **fails safe** at a
capital cost. The first half holds: a **too-small** `C_max` spans too few rungs and
**cannot be widened**. The second half does **not** — the participation analysis
(§7.5) shows a **too-large** `C_max` does *not* fail safe: its regressive capital
tax prices the low-rung stakers out into the `cover == 0` opt-out, and because the
rung is **public** that opt-out is inferable, so an over-large bound **shrinks** the
realized anonymity set rather than holding it. The "fails safe" reasoning rested on
anonymity being **monotone** in the dial — bigger range, bigger set — which is true
only for the honest-uniform population, the very assumption participation falsifies.
The set as a function of `k` is **humped, not monotone**.

And the high side is a *genuine* failure, not mere foregone anonymity, because
opt-out is **affordability-driven, not anonymity-rational**. If stakers opted out by
reasoning "paying makes me *more* distinctive here," the realized set would floor at
the same-rung baseline (`≈ 1.9`) — nobody pays to be more exposed. But a staker
**cannot** reason that way: they observe neither `N_P` nor the realized rung density,
so they pay whatever the pinned recommendation says if they can afford it. At high
`k` the affordable-but-unlucky payer pays into a pool most of the population has
abandoned *for affordability*, lands in a sparse payer set, and can end up **below
the same-rung baseline** — *worse than posting no cover* — without ever being able to
see it coming. So **both** directions are un-fixable failures (you can neither widen
nor narrow post-freeze), and the genesis pin must hit an **interior optimum** — which
*raises* the bar on the pre-freeze analysis rather than letting "just go big" stand
in for it. `C_min` (the runway floor, §2.2) is the one bound that is still
one-sided-conservative — pinned against **pessimistic slow early yield** (under-funding
re-links, and it can't be raised later) — but `C_max` is a two-sided pin.

**Net (the correction to "shape-now/calibrate-later"):** the genesis pin is
**shape + conservative bounds together**. Post-testnet population data
*confirms* a conservative bound was adequate; it cannot *fix* one that wasn't.

---

## 3. Scope

### 3.1 In scope

| # | Item |
| --- | --- |
| C1 | **The metric (§1).** A **joint amount × timing, posterior-weighted effective anonymity set** (IPR over the attacker's likelihood) over the **discrete `bond_floor` lattice** and shard-count distribution (the latter *inherited* from the sim, §2.3 — not a co-pin). Target = the cover analogue of `window = 600`, sized for the worst-case direct funder (§1.3), **jointly with the entry-gap standoff** (§1.1), and **under the *pessimistic* per-rung populations** (thin `N_P` end, §2.5) since the bound ships genesis-frozen blind to the real population. |
| C2 | **Distribution shape (DQ1).** Pinned shape; uniform is the expected *result* of the posterior-weighting argument (§4), not a guess. |
| C3 | **Bounds (DQ2) — genesis-frozen, sized against pessimistic inputs (§2.5/§7.5).** `C_min` = **working-capital runway** floor (§2.2; references 2d-1 ramp), strictly positive, one-sided-conservative against pessimistic slow yield. `C_max` = the **lattice dial** (§2.3), `k × floor` to blur `k` rungs — **not** "as large as possible": §7.5 makes it a **two-sided interior optimum** (too-small under-blurs, too-large prices low rungs out), sized at the realized optimum under the pessimistic corner. Both single-sourced beside `DEFAULT_ENTRY_GAP_WINDOW` and **pinned at genesis** (not post-testnet). |
| C4 | **Mechanism (DQ3).** A `shekyl-standoff` **value draw** (float-free, single-sourced, conformance-graded) reusing `GapRng` + `bounded_uniform`, extending the crate from "entry-standoff timing draw" → "funding-seam decorrelation draws: timing **and** amount." Golden vector + gated conformance grade. |
| C5 | **Uniformity binding (DQ5) — as a *soft* rule (§2.4).** Single pinned distribution; reference wallet conforms; override is a disclosed cost, **not** enforced. Stated like the `enc_label` caveat, with its enforceability limit explicit. |
| C6 | **`CoverAmount` follow-through.** `CoverAmount(AtomicUnits)` exists inert (`stake_timing.rs`); the draw produces it. Orchestration (the send + `P`-change threading) stays 2d; the **draw** is pinned here. |

### 3.2 Out of scope

| Out | Why |
| --- | --- |
| The 2d bond-tx assembly (`bond_floor + cover` send, `P`-change threading) | Needs the broadcast/tx path (2d); the **draw** is the prerequisite, the *spend* is 2d. |
| Any wire/consensus change | Cover is an ordinary confidential CT output; the chain never sees or verifies it. |
| Upstream principal-side decorrelation (consolidation / intermediate hops) | Orthogonal protection for the sophisticated funder (§1.3); the cover targets the direct path. |
| Opt-in cover **recovery**; front-end **override**; `cover == 0` | The **disclosed-opt-out family** (§2.4): each removes the *opter's own* protection, none creates an on-chain class (off-wire) — V3.x GUI/CLI surface, named with disclosed cost. |
| Steady-state fund-from-earnings sizing | The cover *seeds* the pool; how it's spent is 2d-1. (`C_min` references the ramp — §2.2 — but doesn't own it.) |

---

## 4. Design questions

- **DQ1 — distribution shape → uniform is the *result*.** Against a
  distribution-aware attacker (§1.2) the metric is posterior-weighted, so any
  non-uniform shape (lognormal, floor-relative) hands the attacker **posterior
  concentration on the true bond**. Uniform is the **max-entropy choice that
  denies concentration** — optimal, not merely preferred. Floor-relative
  additionally **leaks shard count** (the scaling is the size signal), rejected on
  the same ground `==` (not `≥`) was chosen for the floor. *Decision: uniform over
  the pinned `[C_min, C_max]`, confirmed by C1's analysis over the lattice.*
- **DQ2 — bounds (genesis-frozen, §2.5/§7.5).** `C_min` = working-capital runway
  (§2.2). `C_max` = lattice dial (§2.3). Both **ship at genesis** (not
  post-testnet), because the pin is un-revisable (moving a boundary splits the
  cohort). `C_min` is one-sided-conservative (slow-yield). `C_max` is **two-sided**:
  too-small under-blurs (un-widenable), too-large prices low rungs out (§7.5 —
  un-narrowable), so it pins at the **realized interior optimum** sized against the
  pessimistic corner. Post-testnet *confirms* adequacy, it cannot *fix*.
- **DQ3 — mechanism home.** Extend `shekyl-standoff` (re-scope its crate doc to
  "funding-seam decorrelation draws: timing + amount") with `draw_cover_amount`
  beside `draw_entry_gap`, sharing `GapRng` / `bounded_uniform` / golden-vector —
  the cover is the amount-axis of the seam the crate already owns on the
  timing-axis. *Lean: extend, not a sibling.*
- **DQ4 — entropy-primary (ratify).** The cover is a privacy draw `P` *then* uses
  as capital, not a utility-sized amount (§2.1). If overturned, the defense
  weakens and C1's target must absorb the reduced entropy — surface explicitly.
- **DQ5 — uniformity as a *soft* invariant (§2.4).** Binding on the reference
  wallet; unenforceable on the wire; override is a disclosed cost. State the
  enforceability limit, don't imply consensus enforcement.
- **DQ6 — `cover == 0` resolves cleanly.** Because the cover is off-wire there is
  **no chain signal** separating a zero-cover bond from a covered one — so
  zero-cover creates **no attacker-visible class**. It only removes the *opter's
  own* protection (their `A == bond_floor` exactly); it does **not** pollute
  covered users' anonymity sets. So `cover == 0` is a **self-contained, named
  opt-out** with a disclosed cost. A strictly-positive `C_min` (C3) keeps every
  real draw off zero, reserving the value unambiguously for that opt-out.

---

## 5. Sequencing & dependencies

- **No open upstream decision (§2.3):** the bond-standardization is decided in
  *shape* (flat `floor × shards`, pinned rung; `STAKER_ARCHIVAL_SIM.md`). C1
  *inherits* it — not a co-pin.
- **The genesis pin is shape + bounds *together* (§2.5/§7.5):** off-wire is
  **not** re-tunable — moving any boundary later splits the anonymity cohort and
  past bonds can't re-draw, so the bounds are genesis-frozen. `C_max` is a
  **two-sided interior optimum** (too-small un-widenable; too-large prices low
  rungs out, §7.5, un-narrowable), sized against the **pessimistic** corner —
  *not* "err-large, go big." Post-testnet **confirms** adequacy; it cannot **fix**.
  This is the correction to "shape-now/bounds-later."
- **The integrated joint × participation pass is a pre-genesis blocker (§7.6):**
  amount-marginal (§7.4), timing intersection (§7.4 finding 3), and participation
  (§7.5) move the pin in conflicting directions and must be sized **together**
  before the freeze — not a testnet follow-on.
- **Prerequisite for:** 2d bond-tx assembly (the `bond_floor + cover` send).
- **`C_min` references** the steady-state fund-from-earnings ramp (2d-1) — runway
  must outlast cold-start until earnings carry.
- **Independent of:** the shekyl-oxide un-vendor (off-wire) and the scanner — the
  **shape + pessimistic-input bounds genesis pin** (C2/C3/C4/C5) can be done now;
  nothing waits on the consensus path. Post-testnet only *confirms* the bounds.
- **Owns no wire/consensus bytes** — does not gate or touch the genesis freeze.
- **The substantive work is the sim/analysis pass** (C1), the way the entry-gap
  window was set by analysis — distinct from wiring the draw. **Done (first cut):
  §7** — the `--cover` harness is built and run; §7.4–§7.6 have the measured dial,
  the bounded-pool saturation finding, and the participation correction (realized
  optimum `k ≈ 8–12`, not the amount-marginal `k = 21` floor). Open: the integrated
  pre-freeze pass, per-rung density (testnet-confirm), and `C_min` (2d-1 ramp).

## 6. Gates (when it lands)

`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; production draw
**float-free** (like `draw_entry_gap`); golden-vector KAT; conformance grade gated
behind the `conformance` feature (distribution graded by margin, not asserted
bit-identical — the entry-gap posture). No `STAKING_BLOCK_VERSION` / wire-format
bump (off-wire).

---

## 7. C1 first cut — sizing `C_max` / `C_min` (pessimistic-input, interior optimum)

First analytical pass (the §5 "substantive sim/analysis pass"). It pins the
**structure** of the bound and a **conservative genesis bracket**; it lands on a
`--cover` harness arm as the step that replaces the bracket with measured
numbers — the analogue of how `window = 600` was set by `--standoff`
(`STAKER_ARCHIVAL_SIM.md:3471` Monte-Carlo, not a guess).

### 7.1 The lattice dial, derived (`C_max − C_min = k · floor` blurs `k` rungs)

The rung spacing is the per-shard floor: `floor = ARCHIVAL_BOND_FLOOR_ATOMIC =
750_000_000 atomic = 0.75 SKL` (`consensus_constants.rs:17`,
`ATOMIC_UNITS_PER_SKL = 1e9`). A staker on rung `s` posts public `bond_floor =
floor · s` (`s = Σ|holdings|`, the shard count). The attacker, knowing `A =
floor · s_P + cover`, tests each public bond `Q`:

```text
Q candidate  ⟺  A − floor · s_Q ∈ [C_min, C_max]
             ⟺  floor·(s_P − s_Q) + cover ∈ [C_min, C_max]
```

For the realized `cover`, the candidate rungs form a **contiguous window of `k`
rungs straddling `s_P`**, where `k = ⌊(C_max − C_min) / floor⌋`: the consistency
condition pins `s_Q` to a real interval of length `k` (in rung units), which
contains `k` integer rungs almost always — `k + 1` only when `cover` lands exactly
on a floor multiple (measure-zero for a continuous, atomic-grained cover). The
split slides with the draw: a high `cover` (near `C_max`) must be matched by a
*higher* rung, so the window opens mostly **above** `s_P`; a low `cover` opens it
below. So the width `W = C_max − C_min`, in units of `floor`, **is** the number of
rungs the cover blurs across — the §2.3 lattice dial, now exact: `k = W / floor`.

The **effective** anonymity set is not the rung *count* but the
**posterior-weighted count of *stakers* on those rungs** (the §1.2 IPR). Uniform
`cover` (DQ1) makes the likelihood flat across the window, so the effective set
≈ `Σ` stakers occupying the window's rungs — uniform is exactly the shape that
denies the attacker concentration on `s_P`.

### 7.2 The binding case is the sparse thin regime

The sim reports per-staker **mean** portfolio, not a per-rung histogram: thin
`N_P = 17` ⇒ ≈ 9 shards/staker; lean ≈ 60; (`STAKER_ARCHIVAL_SIM.md:676,720`).
So under the **thin** `N_P` end (§2.5's pessimistic populations) the rung density
is **below one staker per rung** — ~17 stakers spread over a band roughly
`[1, ~2·mean]`. Consequence: clearing a target effective set is a problem of
**accumulating count across rungs**, not landing on a populated one. But the pool
the cover accumulates from is **bounded by `N_P`** — unlike `--standoff`'s
unbounded background traffic — so it **saturates**, and the thin-cover tail does
*not* simply close the way the standoff's did (§7.4 measures this). The mean-set
shape still tracks the standoff (`1 → 7 → 13 → 25` there, `:3484`), with `k` rungs
on the x-axis instead of timing blocks.

### 7.3 The capital tax is regressive (a finding to surface)

`C_max = k · floor` is a **fixed SKL cover** independent of `s`. As a fraction of
the staker's own bond (`floor · s`) it is `k / s` — **larger for small `s`**. A
rung-9 staker spanning `k = 12` locks `9 SKL` cover on a `6.75 SKL` bond
(`1.3×`); a rung-60 staker spanning the same 12 rungs locks `9 SKL` on `45 SKL`
(`0.2×`). So the §2.5 permanent capital tax **falls hardest on the smallest
stakers** — precisely the thin-runway cold-start funders the cover most protects.
This bounds err-large from running away: over-provisioning `C_max` is not free
insurance, it is a regressive lock that can itself thin the small-staker
population the metric depends on. The harness must report the tax curve
alongside the anonymity curve and pick the knee, not the ceiling.

### 7.4 What the harness measured (built: `shekyl-staking-sim --cover`)

The `--cover` arm (`cover.rs`) runs the metric over the lattice — 200k trials,
SplitMix64, four arms (dial / `N_P` scenario / density bracket / timing
intersection) + a saturation-knee recommendation. The dial sweep at the
pessimistic corner (thin `N_P = 17`, dispersed, amount-marginal):

| `k` | `C_max − C_min` | mean set | thin-tail `P(set ≤ 2)` | worst tax |
| --- | --- | --- | --- | --- |
| 0 | 0 | 1.9 | 0.75 | 0× |
| 8 | 6 SKL | 6.7 | 0.136 | 8× |
| 16 | 12 SKL | 9.8 | 0.068 | 16× |
| 24 | 18 SKL | 11.7 | 0.045 | 24× |
| 32 | 24 SKL | 12.9 | 0.034 | 32× |

Three findings change the §7.1 picture:

1. **The decoy pool is bounded by `N_P` and saturates.** Unlike `--standoff`'s
   unbounded Poisson background, the cover's candidates come from the `≤ N_P` live
   stakers, so the **mean** set climbs toward `N_P` and plateaus (ceiling 17) but
   the **thin-cover tail does not close** at any viable `k` (still `0.034` at
   `k = 32`). The tail floor is set by **edge-of-lattice stakers no window can
   surround** — a **firewall-composition** property, **not** a cover-sizing knob.
   The two seams that cover it are the **`N_P`-independent** ones: **network
   isolation** (denies the correlation channel entirely — population-independent)
   and the **direct-funder-only scope** (§1.3 — any intermediate handling voids
   the amount attack regardless of set size). **Timing is *not* one of them** —
   finding 3 shows timing intersects-and-*shrinks* the amount-set over the same
   `N_P`; it fights the tail, it does not rescue it. So the dial is sized to the
   **mean**, and the residual tail is handed to network-isolation + funder-scope.
2. **Per-rung density dominates, and it's unmeasured.** Clustered vs dispersed at
   `k = 16`: thin-tail `2.1%` vs `6.8%`, mean `13.8` vs `9.8`. The *spread* of
   shard counts (not the mean the sim pins) is the load-bearing input — swept, not
   measured, the cover analogue of `--standoff`'s rate. Err-large sizes against
   **dispersed**, which **already includes the isolated-outlier** shape (a lone
   staker on a sparse high rung has set `≈ 1` at any `k`) — that *is* the
   irreducible tail. The bond **plateau-cap** anti-whale likely bunches the *top*
   rungs at the cap band (built-in same-rung cover the cover-draw can't supply),
   which would give a clean structural division — **cap → top, cover → middle,
   network + funder-scope → thin bottom** (DQ: confirm the cap bunches the top).
3. **The timing intersection is costly — the joint set saturates *low*.** The
   saturation-knee scan (smallest `k` past which a rung of cover buys `< 0.15`
   set/rung): amount-marginal `rt = 1.0` knees at `k = 28` (set `14.2`); but the
   **joint** corner saturates far lower — `rt = 0.5` knees at `k = 16` (set
   **`7.6`**), `rt = 0.2` at `k = 4` (set **`3.6`**). The two seams fight the same
   `N_P`, so they **must be sized jointly** — and the joint corner, not the
   amount-marginal, is the genesis-pin input.

**The "pin" is a FLOOR, not a number — §7.5 and the joint pass move it.** The
amount-marginal saturation knee (`k = 28`, `21 SKL`) is computed blind to *two*
forces that both bind harder: the joint timing intersection (finding 3 — set
saturates at `7.6` not `14`), and **economic participation (§7.5)**, which prices
low rungs out and pushes the realized optimum **down to `k ≈ 8–12` (`6–9 SKL`)**.
So `k = 21–28` is a first-cut **floor on the blur**, not the pin; the genesis pin
is the realized optimum of the integrated joint × participation pass (§7.6), which
the freeze forbids approximating. `C_min` stays the runway floor (§2.2), `≥ 1 rung
(0.75 SKL)`, reserving `cover == 0` for the DQ6 opt-out — which the harness shows
still gets **same-rung cover** (`k = 0` set `≈ 1.9`, not 1: same-`bond_floor`
stakers are indistinguishable). **`C_min = 1 rung` is the pinned value** (sim-definitive; top Correction).

### 7.5 Economic participation — the honest tail is worse than the uniform one

§7.4's sets assume **uniform cover over an honest population**. But the §7.3
regressive tax does not fail randomly — it fails **by rung**, and modelling that
(the `--cover` participation arm) turns the honest tail into the realized one.

Cover-stays-with-`P` means the principal must fund `bond + cover` at the seam. A
staker posts cover only if the dial's max draw `C_max = k · floor` is at most
`β ×` their own bond — i.e. rung `s ≥ k / β`. Capital-constrained low-rung stakers
fall below that and take the `cover == 0` opt-out. Two things then bite that the
honest model misses, and they **interlock**:

- the opted-out stakers **leave the low-rung cover pool**, shrinking everyone's
  set down there; and
- the rung is **public** on the bond-post, so the attacker raises the `cover == 0`
  prior on exactly the low rungs, reads `A ≈ bond_floor`, and matches — the forced
  opt-out is **inferable from a public field**.

The measured cost (thin/dispersed, `β` = willingness-to-pay as a multiple of bond):

| `k` | `C_max` | opt-out (`β = 1`) | opt-out (`β = 2`) | realized payer set (`β = 2`) |
| --- | --- | --- | --- | --- |
| 8 | 6 SKL | 56% | 30% | 4.98 |
| 12 | 9 SKL | 73% | 45% | **5.12** |
| 16 | 12 SKL | 83% | 56% | 4.85 |
| 21 | 15.75 SKL | 90% | 69% | 4.11 |
| 32 | 24 SKL | 97% | 83% | 3.01 |

Two consequences:

1. **The realized optimum is interior and *low*.** The payer set **peaks at
   `k ≈ 12` and falls as `k` grows** — past the peak, widening the dial prices out
   more low rungs than the wider window gathers. So the realized-set-maximising
   dial is `k ≈ 8–12` (`6–9 SKL`), **well below** §7.4's amount-marginal `k = 21`.
   Participation pulls the pin **down**, joint-timing pushes it up, and at the thin
   corner **participation dominates**. This **bounds err-large on *both* sides**
   (refining §2.5): too-small under-blurs, too-large prices-out — so the freeze
   must hit an **interior optimum**, raising (not lowering) the bar on getting the
   integrated pass right *before* the freeze.
2. **The cover is a mid-to-high-rung defense.** Even at the optimum the realized
   payer set is only `~3–5` in the pessimistic corner, and the rung-1 population is
   **structurally priced out** — its anonymity comes from network-isolation +
   funder-scope, not the cover. And the regressivity is **non-negotiable**: a flat
   cover range is uniform-but-regressive, a stake-proportional one is
   progressive-but-magnitude-leaking (the rejected floor-relative DQ1) — you cannot
   tune it out without breaking the uniformity invariant (§2.4).

(`β` and the discount-opted-out-decoys rule are themselves modelling assumptions,
swept like density; testnet measures the real funding-budget distribution.)

### 7.6 The question has moved: is the peak robust enough to freeze a scalar?

A two-sided interior optimum (§2.5) frozen as a blind scalar relocates the
load-bearing question. It is no longer *"where is `k*`"* but **how stable is `k*`,
and how broad is the plateau around it, across the pessimistic ranges of every
input** — density, `timing_retain`, and now affordability (`β`). A broad
flat-topped hump is safe to freeze: a range of `k` sit near peak and a mis-pin
costs little either way. A sharp peak whose location slides with the inputs is
fragile both ways and un-fixable both ways. So the harness's next job is **not** to
locate `k*` more precisely — it is to **characterize the hump's shape and the
sensitivity of `k*` to the pessimistic-input corners**, and report whether a single
frozen `k` stays within (say) **90% of peak across all of them**. If it does, freeze
the centre of that robust band. If `k*` swings across the corners, the honest
finding is **"no blind scalar pin is safe"** — surface that, don't paper it over
with a point estimate.

**Measured — the scalar is fragile (`shekyl-staking-sim --cover-fn`, arm A).** The
full sweep of the realized payer set (timing × participation together) over the
thin corner across **18 input corners** (density × `timing_retain` × `β`) puts
`k*` at:

| input | `k*` range |
| --- | --- |
| `β = 1` (tight affordability) | 6 |
| `β = 2` | 10–12 |
| `β = 4` (loose) | 16–20 |

`k*` **slides 6 → 20 (a 14-rung spread)**, driven mostly by affordability — the
softest input. The best single frozen `k` (the worst-corner-maximising `k = 8`)
holds only **77% of its corners' peaks at the worst corner — *outside* the 90%
bar**. So the earlier two-point read was optimistic: across the full corner set
**no blind scalar pin is safe**. That is the §7.6 result, and it is what makes §7.7
the live path rather than a hedge.

**Affordability is the softest input yet sets the right wall** — spare capital
beyond the bond is the least observable thing in the model, and it is exactly what
moves `k*` from 6 to 20. A frozen scalar is hostage to a quantity no one can
measure pre-genesis.

**So a scalar pin is *not* recommended.** The integrated pass confirms a scalar
can't be frozen within the robust band; the pre-genesis work moves to §7.7 (pin a
function). `C_min` (runway floor) and the density confirm still apply to whatever
object ships.

### 7.7 The structural escape — pin a function, not a constant (feasibility: PASSES)

The only escape from the blind-scalar bind is to stop pinning a constant and pin a
**function**: a deterministic, **public-bond-population-conditioned** distribution,
where every wallet computes the same recommended cover from the same public chain
state at the draw height `H`. It **adapts to the realized density** — sizing to the
local `k*` — so it never freezes a fragile peak.

**Measured (arm B/C). The function dominates the best frozen scalar, and its one
theoretical leak is negligible.**

- **Dominance (arm B).** Across a sparse→dense sweep the adaptive dial (each
  density's own `k*`) **matches or beats** the best frozen scalar (`k = 8`) at
  *every* level, and the gap is the set the frozen scalar leaves on the table —
  largest where it under-serves the dense end: realized payer set **14.6 (adaptive)
  vs 5.7 (frozen)** at the thick corner, `7.9 vs 3.4` at lean. One scalar cannot
  serve both ends; the function gets both.
- **No net leak (arm C).** The one real concern — a height-aware attacker
  sub-localising when `D` drifts across a timing window — is bounded by the
  **timescale separation**: the entry-gap window (~600 blk) is ≪ the
  population-change epoch (~10 000 blk), so per-window drift ≈ **1.06**, at which
  the leak proxy is **0.0%**. Even a 1.5× shock strips < 5%. Height-conditioning
  reveals nothing the attacker (who already holds the public population) didn't
  have, and the realized draw stays hidden.

**It preserves DQ5 uniformity in the sense that matters.** All wallets drawing at
height `H` agree on the distribution, so it adds **no fingerprint beyond the bond
height `H`** — which is already public on-chain. The "frozen" object becomes the
deterministic mapping `population(H) → D`, a consensus-uniform *algorithm*, not a
magic number guessed blind.

**The single deciding question (the feasibility analysis):** does conditioning on
per-height public population ever **net-leak** to a height-aware attacker more than
it helps the staker, given both condition on the *same* public data? First-order
intuition is **no net leak** — the attacker already has the population, `D` is a
public function of it, and the realized draw stays hidden — but that is the analysis
that decides it, and it is the one thing that could **dissolve the freeze entirely**
rather than manage it. Two caveats to carry into that analysis:

- **Affordability still isn't observable.** The function conditions on public
  population, not the staker's private spare capital, so the affordability opt-out
  does not vanish. But the adaptive `D` *reduces the pressure*: it narrows exactly
  where wide cover would over-tax (sparse periods), so it stops manufacturing the
  high-`k` opt-out collapse the frozen scalar risks.
- **It is a freeze of a function, not freedom from freezing.** The response curve
  `population(H) → D` is itself genesis-frozen (all wallets, all time, must agree),
  so its *parameters* still need pinning — but pinning a conservative *response*
  (e.g. "target set, capped at saturation, floored at runway") is far more robust
  than pinning a *point*, because it responds to the population instead of guessing
  it.

**Verdict.** Feasibility **passes**: the scalar is fragile (§7.6) and the function
both dominates it and doesn't net-leak. So the genesis object is the **response
curve `f: population → D`**, not a frozen `k`. The conservative response is target
effective set, **capped at the saturation knee** (never over-tax into the §7.5
opt-out) and **floored at `C_min`**; its *parameters* are what get pinned and
golden-vectored (C4), far more robust than a point because they respond to the
population instead of guessing it. Off-wire, parallel to the consensus path.

**But freezing a function does not remove the genesis risk — it *relocates* it, into
a class the scalar was immune to. That relocation is §7.8, and it is now the
load-bearing decision.**

### 7.8 The statistic is the ballgame — `f` must read a slow, final, canonical aggregate

A constant is **inert and un-manipulable**. A function that reads public chain state
inherits a failure class the scalar had no surface for: an attacker who can move the
input can move everyone's cover. The frozen object is the curve, but the load-bearing
choice inside it is **which statistic the curve reads — and the naive instantaneous
`population(H)` tip snapshot is the dangerous reading.**

**The pin: `f` reads a *slow, reorg-final, long-window* population aggregate at a
*canonical* reference height — not a tip snapshot.** One choice closes three distinct
threats, and the **same `600 ≪ 10_000` timescale separation** that bought the §7.7
no-net-leak result powers all three:

1. **Manipulation / grinding — the class a constant can't have.** If `f` narrows `D`
   when the observable population looks sparse, an attacker can *make* it look sparse:
   withhold or withdraw their own bonds to dip the live-bond count — **targeted**
   (timed at a victim's draw → victim draws narrow cover → their `A` matches) or
   **chronic** (suppress the statistic so everyone's cover stays narrow). An
   instantaneous count is cheap to move (one block); a trailing ~epoch aggregate is
   **expensive** — the attacker must suppress bonds across the *whole window*,
   forgoing real staking yield the entire time, and visibly. So the timescale
   separation buys **manipulation-resistance too — but only if `f` reads the window
   aggregate, not the tip.** The design metric is the statistic's **manipulation
   cost** ≈ forgone yield × window × the attacker's share of the stat; maximise it
   with a long window and an aggregation no single actor dominates.
2. **Draw-vs-post desync.** The staker draws cover at construction height; the bond
   posts a few blocks later. A tip-read that moved in between leaves the cover **off
   the post-height distribution** — and an off-distribution cover is a *distinguishable*
   cover, the exact fingerprint the whole mechanism exists to kill. A slow aggregate
   barely moves over a few blocks.
3. **Reorg desync.** A tip-read can reorg out from under a completed draw — same
   off-distribution result. Read the statistic **below the reorg horizon**
   (`ARCHIVAL_REORG_DEPTH_BLOCKS = 720`) so the input is final before any wallet
   conditions on it.

**Concrete canonical reference (proposal).** Key the statistic to the **most-recent
settlement-epoch boundary** (`SETTLEMENT_EPOCH_BLOCKS = 10_000`) — already a
consensus-tracked canonical boundary (`is_multiple_of(SETTLEMENT_EPOCH_BLOCKS)`,
`consensus_state.rs`). It is **slow** (changes only at epoch boundaries), **final**
(the boundary is far past the 720 horizon for all but the first 720 blocks of an
epoch), and **canonical** (every wallet derives the same epoch index from the height),
so draw and post — a few blocks apart — read the **identical** value almost always.
This folds slow + final + canonical into one existing constant.

**The bootstrap boundary must be pinned deliberately, not extrapolated.** At genesis
the live-bond count is ≈ 0, and "narrow-for-sparse" then hands the **earliest** stakers
the **narrowest** cover — at exactly the moment the anonymity set is smallest and the
cold-start principal→`P` link is most exposed. That is a guaranteed-to-occur state with
a real population, **not** a tail to wave at the other seams by default. So `f`'s
bootstrap behaviour is a deliberate decision: it may be right to **concede the earliest
stakers to network-isolation + funder-scope** (the firewall carries the thin regime,
consistent with §7.4/§7.5), but make that call **explicitly** rather than inherit it
from how the curve happens to extrapolate toward zero. Same care at the **top**: the
saturation-knee cap is **self-referential** — it is computed from the very statistic
`f` reads — so it must stay sane and manipulation-robust as that input moves, under the
same slow-aggregate discipline.

**Smooth and monotone, no cliffs (precautionary).** A step at some population threshold
is the continuous-space analogue of the cohort split — it sorts bonds into a
below-threshold and an above-threshold cover-regime, for no reason. A smooth monotone
response keeps every bond on a continuum where the per-bond conditioning stays the
lockstep no-net-leak §7.7 measured.

**Net.** The conditioning approach holds and the function genuinely dominates — but the
win moved the risk from *"what value do I freeze"* to *"what input does the frozen
function trust,"* and that input is now the whole ballgame. The next pass specifies `f`
around the **slow / final / canonical** statistic (the epoch-boundary aggregate) and
the **deliberately-pinned bootstrap boundary**; those are the new un-takebackable
choices, and the manipulation surface is the one a constant never had.

### 7.9 The statistic, grounded in landed code + the targeting measurement

Re-grounding §7.8 on `dev` lands the abstract statistic on concrete consensus code,
and settles its one open DQ (count vs histogram) by measurement.

**The statistic must be a *stock*, and that needs care — corrected at source.** `f`'s
whole manipulation/finality argument rests on the input being the **standing live-bond
population** (a stock: slow, expensive to suppress across a full epoch), not a flow
(per-epoch deltas) or a serving subset. Checking `consensus_state` at source:
`EpochCloseInputs.bonds: &[EpochCloseBond]` is **not** the standing stock — its gather
contract is "one entry per distinct `P_id` *holding at least one serve-credit row* for
the epoch," and idle-bonded `P`s "may be omitted." So it is the **serving/credited
set**, which both **drops posted-but-idle bonds** (wrong population — the cover mixes
over *all* posted bonds) and measures manipulation against serving-churn, not standing
stock. The true standing stock *is* expressible — `conservation::ConservationSnapshot`
carries `total_bonded_atomic` and `per_p_bonded` (count = `per_p_bonded.len()`) — but
that module is flagged **"Audit/KAT only … a full `Σ_P` scan is O(`N_P`); live
enforcement would need incremental maintenance"**. So there is **no ready-made,
live-maintained standing-bond-count** to read; the earlier "the source already exists in
`EpochCloseInputs.bonds`" claim was wrong.

**Consequence:** `f` needs a **canonical, deterministic standing-bond-count read at the
last-closed epoch boundary**, defined as part of this spec — either a canonical
epoch-boundary `Σ_P` gather (acceptable: epoch close is already a heavy consensus
compute, and it runs once per 10 000 blocks) or a maintained standing-count aggregate.
It must **not** read the serving-set close payload directly. Given a stock source, the
two §7.8 finality properties still come free — keyed to the most-recently-*closed*
epoch the value is ≥ `SETTLEMENT_EPOCH_BLOCKS` (10 000) blocks deep (far below any
`NetworkSafetyConstants::max_reorg_depth`; the `720` cited earlier is sim-local, not a
canonical prod const) so it is **final by construction** and **fixed for the whole
current epoch** (draw and post read the identical value) — and the Arm-D manipulation
numbers (measured against honest *standing* occupancy) are the right ones. Manipulation,
the stock source, and the bootstrap boundary are what remain.

**Count vs histogram — settled by `--cover-targeting`, not argument.** The histogram's
only value over the count is a **per-rung** response (narrow where your local rung is
sparse, wide where dense) — and that per-rung response **is** the rung-local targeting
surface: an attacker who withdraws bonds *at a victim's rung* makes `f` see "sparse
here" and narrows that victim's cover toward `A == bond_floor`. Richness and
forgeability are the same property. The arm models a rung-local suppression adversary
and measures the gap (thin `N_P` corner, moderate/targetable victim):

| attacker bonds `m` | count victim set | histogram victim set |
| --- | --- | --- |
| 0 | 10.5 | 10.4 |
| 5 | 8.6 | **5.2** |
| 8 | 7.0 | 4.3 |

**Bonds to halve a chosen victim's set: histogram = 5, count = > 8** — and the
histogram attack is **surgical** (only the chosen victim), while count's same mass only
moves the **global** width: it narrows *everyone* (broad, epoch-long, visible) and never
halves a single chosen victim within `m ≤ 8`. The local signal (~6.6) is small enough
that the attacker's bonds dominate it; the global count (17) dilutes the same mass.
**The per-rung targeting gain is material ⇒ count-uniform is the pin.**

**Decision.** The statistic is the **bond count** (global), driving a **uniform `D`**.
This makes the targetable design *unrepresentable* (the make-bad-states-unrepresentable
move), keeps the one live threat — manipulation — broad, expensive, and visible, and is
one consistent rule with the bootstrap boundary (low count → narrow → concede to the
`N_P`-independent seams). A per-rung histogram is **rejected**.

**The dispersion scalar buys capital, not anonymity — measured (`--cover-dispersion`).**
The candidate enrichment is a **coarse global dispersion scalar** — the occupancy
inverse-participation-ratio `(Σ n_r)² / Σ n_r²` (`1` = fully clustered → `N_P` = fully
dispersed), global so it keeps the targeting-resistance. The arm tested whether count
*alone* under-serves the dispersed bracket (§7.4's load-bearing input). It does — at the
thin corner the dispersed victim's set is `4.3` vs clustered `7.0` under count-only (a
real ~40% gap). But the scalar closes that gap (`2.7 → 1.4`) **almost entirely by
narrowing the over-served clustered side** (`7.0 → 5.7`, capital saved), **not** by
lifting the dispersed side (`4.3 → 4.4`, +0.1): the dispersed thin population is
**saturation-limited** (§7.4) — widening can't gather neighbours that aren't there. So
the scalar's real value is **capital efficiency** (right-size dense periods, less §7.5
over-tax), **not** anonymity for the under-served tier, which is conceded to the
`N_P`-independent seams anyway (the three-tier framing). **Verdict: count-only is
sufficient for the *anonymity* goal; the dispersion scalar is a *deferrable*
capital-efficiency refinement (IPR, global), not a genesis requirement** — and its
**reopen trigger is *economic*, not anonymity** (the arm measured that it doesn't move
the anonymity floor): file it as *"deferred for capital efficiency; reopens if
post-testnet the realized capital lock-up at the chosen `D` prices out more of the
population than projected (the §7.5 opt-out / participation pressure); gated on the
Arm-D targeting check when it returns."* That keeps it from being re-proposed for the
wrong reason (anonymity, which it doesn't help) and ensures the targeting check rides
along with it.

**The response-curve spec (next), with four constraints pinned *deliberately* — not
left to fall out of the curve's math, because each is genesis-frozen and un-revisable:**

- **Statistic source (the §7.9 grounding gap):** define the canonical standing-bond-count
  read at the last-closed epoch boundary (a `Σ_P` gather, or a maintained aggregate) —
  the stock, **not** the serving-set close payload.
- **Same population as the anonymity set — the metric's hinge.** The count `f` reads must
  be the count of bonds the attacker can enumerate as candidates: **every active posted
  bond with an observable `bond_floor`**. Checked at source: a bond-post aggregates a
  `P`'s full `holdings` into **one** `bond_floor`, and `HoldingsUpdate`/`Rebond` mutate
  that single bond — so **per-`P` == per-bond == per-observable-`bond_floor`** (no
  persona-deflation; `per_p_bonded`'s per-`P_id` keying is the right per-bond unit). The
  population matches at both edges: the *serving* set was too few (dropped idle bonds, the
  §7.9 correction); the standing set is not too many either — an announced-but-not-posted
  `P` has no `bond_floor` (not a candidate, not bonded), and last-closed-epoch finality
  excludes any pending/un-final bond. The one-active-bond-per-`P_id` invariant is now
  **verified at source as three sub-checks** (not inferred from the record shape): it is
  **consensus-enforced** — the daemon rejects a second `JoinMarket` for a bonded `P` via
  the `RecordExists` rule (`bond_post.rs:73`, called from `blockchain.cpp:4673`), not a
  wallet convention; there is **no transient double** across the unbond/rebond seam
  (single record per `P_id`, `Rebond` mutates, `Unbond` atomically zeros, invariant
  `bonded_total_atomic ∈ {0, bond_floor}`); and the rule and `per_p_bonded` key on the
  **same** `p_canonical_id` granularity (`p_slot` rotation mints a *new* retired-old
  `P_id`, so rotated personas are distinct candidates, correctly counted apart). **One
  precision the check surfaced:** `Unbond` leaves the record present with
  `bonded_total_atomic = 0`, so the count is of **active** bonds (`bonded > 0` — the only
  ones with an observable `bond_floor`); the `Σ_P` gather **must filter out zeroed-retired
  records**, or the denominator inflates with `P`s the attacker can't match. With that
  filter, the count read is **bedrock**.
- **Bootstrap boundary as a *stated clause*, not an extrapolation.** At epochs 0–1 the
  last-closed count ≈ 0; a smooth low-count→narrow curve would hand the earliest stakers
  the **narrowest** cover at the moment the live set is smallest and the cold-start link
  most exposed. Pin it as an explicit clause — *"below `count = C_boot`, `D` is [floor /
  the other seams carry it]"* — conceding the bootstrap cohort to network-isolation +
  funder-scope (consistent with how `f` treats every sparse state), a decision on the
  record. Genesis-frozen, so the clause is itself un-revisable.
- **The saturation-knee cap is self-referential — pin it in lockstep.** The cap is
  computed from the *same* count `f` reads, so it must stay monotone and sane as count
  moves under a suppression attempt, or the manipulation surface closed on the width
  re-opens on the cap. State the cap as a function of the **same slow standing-stock
  aggregate**, not a separately-sourced number, so the whole curve moves in lockstep with
  one final, expensive-to-move input.
- **Smooth and monotone is a *hard constraint* on `D(count)`, not a preference.** Any step
  is the continuous analogue of the cohort split — it sorts bonds into below-step and
  above-step cover-regimes at a public, frozen count threshold (a fingerprint,
  un-revisable). Monotone-and-smooth keeps every bond on one continuum.

And `draw_cover_amount` in `shekyl-standoff` (C4, the `draw_entry_gap` sibling) emitting
the inert `CoverAmount` at `stake_timing.rs`.

**Dispersion scalar — deferred, *with* its Arm-D check.** If the scalar is ever added
(post-testnet, for capital efficiency), it must first clear the **same Arm-D bar the
histogram failed**: confirm a global IPR/occupied-rungs measure feeding a uniform `D`
**cannot** be sculpted rung-locally (it almost certainly can't — moving a whole-population
dispersion measure takes far more bond mass than moving one rung's local signal — but it
is a one-arm check, not an assumption). Since count-only ships at genesis, this check is
deferred with the scalar; if it doesn't clear cheaply, drop it and stay count-only.

---

## 8. The `D(count)` response curve — spec

The four frozen constraints (§7.9) pinned in **dependency order**, so each constrains the
next rather than being implied by the curve's math: the **count read** is bedrock; the
**saturation-knee cap** and the **`C_min` floor** define the envelope; the **smooth
monotone shape** fills it; the **bootstrap clause** is the named exception at the
`count ≈ 0` edge. All five are genesis-frozen and un-revisable.

Notation: `floor = ARCHIVAL_BOND_FLOOR_ATOMIC = 0.75 SKL` (rung spacing). The wallet draws
`cover ~ U[C_min, C_min + k(C)·floor]`, i.e. a uniform draw whose **width is `k(C)` rungs**;
`C` is the count read. `draw_cover_amount` (C4) emits this in `shekyl-standoff`,
float-free with a golden-vector and a conformance grade, like `draw_entry_gap`.

### 8.1 The count read `C` (bedrock — §7.9, verified)

`C` = the count of **active** archival bonds (`bonded_total_atomic > 0`) at the
**most-recently-closed settlement epoch boundary**, keyed per `p_canonical_id` (= per
observable `bond_floor` = the attacker's candidate pool, §7.9). Sourced by a canonical
`Σ_P` gather at epoch close (filtering zeroed-retired records), **not** the serving-set
close payload. Final-by-construction (≥ `SETTLEMENT_EPOCH_BLOCKS` deep) and fixed for the
current epoch. Everything below is a function of **this one** slow, expensive-to-move input.

### 8.2 The saturation-knee cap `K_sat(C)` (self-referential lockstep)

The dial is capped at the **saturation knee for the realized count** — the `k` past which a
rung of cover buys less than the marginal-return cutoff (`--cover` arm). `K_sat` is a
function of the **same `C`**, monotone non-decreasing: more candidates ⇒ a wider blur can
still gather set; fewer ⇒ the knee falls. Stating the cap as `K_sat(C)` (not a
separately-sourced constant) is the **lockstep** that keeps the §7.8 manipulation surface
closed: an attacker suppressing `C` moves the width *and* the cap together, against the
same epoch-scoped, expensive-to-move quantity — there is no second input to sculpt.

### 8.3 The `C_min` floor (runway)

`C_min` is the **working-capital runway floor** (§2.2): strictly positive, `≥ 1 rung
(0.75 SKL)`, so even the narrowest draw funds non-trivial runway and `cover == 0` stays
reserved for the DQ6 opt-out. Sized against **pessimistic slow early yield** (under-funding
re-links `P` too soon); pinned at **1 rung** (sim-definitive; top Correction). It is the lower edge of
every draw, independent of `C` — the envelope's floor.

### 8.4 The shape `k(C)` — smooth, monotone, *decaying to zero in the low tail* (hard constraint)

Across the populated range `k(C)` rises **smoothly and monotonically** from `0` toward
`K_sat(C)` as `C` grows: more live bonds ⇒ wider blur, up to the knee. **No steps** — a
step at any count threshold is the continuous analogue of the cohort split (§7.8), sorting
bonds into below-/above-threshold cover-regimes at a public frozen threshold (a fingerprint,
un-revisable). The `k(C)` magnitudes inherit the `--cover` / `--cover-fn` analysis under the
**pessimistic** corner, pinned conservatively at genesis (per §2.5 the bound can't be
re-tuned later); a future `f` may *confirm* but not *fix* them.

**The low tail must *decay* to zero, not *clamp* to it.** Because `K_sat(C) → 0` in the low
tail (§8.5), `k(C)` reaches zero there as the limit of the ramp — there is no separate
bootstrap threshold to be continuous *at*. But the functional form (§8.8) must realise this as
a **decay**: a ramp that is smooth in the body and then *clamps* to `0` at the bottom
re-introduces a **slope discontinuity** (a kink) at the clamp count — softer than a value-step,
but still a curvature feature at a public frozen count, the same fingerprint genre one order
down. The form must **approach** zero (`k` *and* `dk/dC → 0` into the tail) so the bootstrap
behaviour is the natural limit of the curve, not a clamp on it.

### 8.5 "Bootstrap" is the `k = 0` tail of `K_sat`, not a separate threshold (`C_boot` *dissolved*)

The continuous resolution doesn't *pin* `C_boot` — it **dissolves** it. Earlier this section
treated `C_boot` as a frozen policy threshold (the count below which the cover "gives up").
The magnitude pass (§8.7) shows that was a conflation of two different things: the
**`K_sat → 0` boundary** (`C ≈ 13–15`) is where the curve's *own math* stops offering cover —
below it `k = 0` is **not a concession or an override, it is simply what the saturation
structure yields**; whereas the **floor's-worth point** (`C = 25`) is where cover stops being
*worth much*, a descriptive statement and **not a boundary at all**. The old "derive `C_boot`
from where cover buys < a floor's worth" would have *manufactured* a discontinuity to express
something the curve already expresses continuously by ramping toward zero.

So there is **one envelope, `K_sat(C)`** — `0` below `C ≈ 13–15`, ramping under the §8.7 cap
above — and **"bootstrap" is the name for its low `k = 0` tail**, not a separate regime, clause,
or pinned constant. This is strictly better: **one fewer frozen scalar**, and the one removed is
the policy threshold that was most exposed to being wrong with no recourse (a genesis-once value
post-testnet couldn't confirm). The §2.5 *confirm-not-fix* discipline applies to `K_sat` and
`C_min`; there is no third magnitude here. `C = 25` is retained only as the descriptive
*"cover-becomes-substantial"* marker.

**Record discipline:** state this as the single envelope, or a future reader who sees a `C_boot`
constant *and* a bootstrap clause re-introduces the step we removed. There is no `C_boot`
constant; there is `K_sat(C)` and its low tail.

### 8.6 Out of scope here (downstream)

The `draw_cover_amount` wiring (C4) and the `CoverAmount` orchestration (the
`bond_floor + cover` send, `P`-change threading) remain 2d. The dispersion scalar stays
deferred (§7.9, capital-efficiency, economic reopen trigger). This section pins the **frozen
shape of `f`**; the magnitude pins (`K_sat` curve, `C_min`, `C_boot`) are the conservative
genesis numbers the `--cover` analysis sets under the pessimistic corner (§8.7).

### 8.7 Measured magnitudes (`--cover-magnitudes`, joint corner)

The pass runs the **joint** corner (dispersed, `timing_retain = 0.5`, `β = 2`, thin per-staker
mean), `C` on the x-axis — *not* the amount-marginal set, which overstates. Per count: the
saturation knee `K_sat(C)`, its cover span, the achievable joint set, the `k = 0` baseline,
and the robust **plateau width** (dial rungs within 90% of peak):

| `C` | `K_sat` | cover span | set@knee | baseline | gain | plateau (rungs) |
| --- | --- | --- | --- | --- | --- | --- |
| ≤ 12 | 0 | 0 | ≈ baseline | 1.0–1.3 | 0 | 14–34 |
| 15 | 4 | 3.0 SKL | 2.27 | 1.41 | 0.86 | 14 |
| 17 | 6 | 4.5 SKL | 2.79 | 1.47 | 1.31 | 14 |
| 25 | 8 | 6.0 SKL | 3.99 | 1.71 | 2.28 | 12 |
| 40 | 8 | 6.0 SKL | 5.84 | 2.16 | 3.68 | 10 |
| 79 | 10 | 7.5 SKL | 11.1 | 3.29 | 7.81 | 10 |
| 154 | 10 | 7.5 SKL | 20.6 | 5.51 | 15.1 | 10 |

Three reads:

- **`K_sat(C)` ramps and caps low.** It activates at `C ≈ 13–15` and caps at **`k = 10`
  (7.5 SKL)** even at thick — the joint corner saturates low (consistent with §7.4). The
  `K_sat(C)` curve is the **cap envelope**; the frozen `k(C)` is a smooth ramp *under* it.
- **The pins are robust, not sharp.** Plateau widths are **10–16+ rungs** near-peak, so a
  band around each `K_sat` stays near-peak — safe to freeze conservatively (a narrow plateau
  would have been the signal to widen, per the magnitude-pass rule; none is).
- **No `C_boot` pin — the tail dissolves it (§8.5).** `K_sat(C)` is already `0` below
  `C ≈ 13–15`, so the bootstrap concession is the curve's own `k = 0` tail, not a separate
  threshold. The "buys ≥ floor's worth" point (`C = 25`, where `K_sat = 8`) is a *descriptive*
  marker only — conceding out to it would re-introduce a `0 → 8` step. **First-cut genesis
  pins:** just `K_sat(C)` per the table (a smooth monotone ramp under it, decaying to `0` in
  the tail, capping at `k = 10 / 7.5 SKL`); `C_min = 1 rung`, pinned (top Correction). Two frozen
  magnitudes, not three. Conservative-frozen per §2.5 (confirm-not-fix for `K_sat`).

### 8.8 The `k(C)` functional form — float-free cubic smoothstep (`--cover-dial`, ref C4 ports)

Two genesis-frozen constraints decide the form, not just "smooth and monotone":

- **Decay, not clamp (§8.4).** A ramp that is smooth in the body but *clamps* to `0` at the
  bottom leaves a **slope kink** at the clamp count — a softer fingerprint, but the same genre.
  The form must approach zero with `k` *and* `dk/dC → 0` into the tail.
- **Exactly float-free.** C4 (`draw_cover_amount`) is the consumer and the production draw is
  float-free by doctrine (the standoff's integer rule). Two wallets computing even slightly
  different `k` from the same `C` draw from **different distributions** — the cross-wallet
  uniformity break that *is* the fingerprint the mechanism closes. So the form must be
  **bit-identically evaluable in integer arithmetic**, golden-vector-pinnable — which rules out
  anything transcendental and points at a fixed-point polynomial.

Both are met by a **cubic smoothstep** `s(t) = t²(3 − 2t)`, whose `s'(0) = s'(1) = 0` gives zero
slope at *both* ends (decays into the tail *and* joins the cap with no kink), and which is a
finite integer expression. The output is the cover **span** `C_max − C_min` in atomic units (the
draw is then `bounded_uniform` over `[C_min, C_min + span]`, the standoff's integer draw):

```text
COVER_TAIL_COUNT      = 13            # K_sat→0 tail (the dissolved C_boot)
COVER_RAMP_END_COUNT  = 79            # ramp reaches the cap
COVER_SPAN_CAP_ATOMIC = 7_500_000_000 # 7.5 SKL = k=10 × 0.75 (§8.7 knee)

span(C) = 0                                   for C ≤ 13
        = CAP                                 for C ≥ 79
        = CAP · num²·(3·den − 2·num) / den³   otherwise, num = C−13, den = 66
```

`num²·(3·den − 2·num) ≤ den³`, so `span ≤ CAP` and it is monotone in `num`; the intermediate
`CAP · num²·(…) ≤ CAP · den³ ≈ 2.16e15 < u64::MAX`, so it never overflows. Sampled
(`--cover-dial`): `C=14 → 0.005 SKL` (gentle decay, no jump), `25 → 0.65`, `46 → 3.75`,
`60 → 5.99`, `79 → 7.50` (cap). Golden vector pinned (`cover_dial_span_golden_vector`); tests
assert monotone-and-capped and the second-difference sign (convex into the tail = decay, concave
into the cap = no kink). **C4 landed:** `draw_cover_amount(count, c_min, rng)` +
`cover_dial_span_atomic` in `shekyl-standoff::cover` (`cover ~ U[C_min, C_min + span(C)]`
via the shared `bounded_uniform`). The three implementation checks are its acceptance tests,
not open decisions: **variable-span uniformity** (`bounded_uniform` is exact rejection for
any bound, golden-vectored at tail/mid/cap spans), **tail smoothness** (`span = 0 ⇒
cover = C_min` exactly, the continuous `span→0` limit; the first non-zero span ~5.1M atomic
is no near-constant), and **`C_min` single-sourced** (`COVER_RUNWAY_FLOOR_ATOMIC`, provisional
`C_min = 1 rung`, pinned; the cover golden vector is frozen against it). The
`shekyl-staking-sim` copy is independently golden-vectored to the same values, so the two
can't silently diverge.
