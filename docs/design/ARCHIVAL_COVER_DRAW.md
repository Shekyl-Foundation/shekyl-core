# Archival Cover-Amount Draw — entropy scoping (genesis-adjacent)

**Status:** SCOPING (2026-06-20, review-revised). Design-questions enumerated;
not yet decided. Off-wire, scanner-independent, un-vendor-independent —
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
(too-large prices low rungs out), realized optimum `k ≈ 8–12 (~6–9 SKL)` — **not**
the "err-large, go big" the earlier draft assumed (corrected in §2.5).
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
realized anonymity set rather than holding it. So **both** directions are
un-fixable failures (you can neither widen nor narrow post-freeze), and the genesis
pin must hit an **interior optimum** — which *raises* the bar on the pre-freeze
analysis rather than letting "just go big" stand in for it. `C_min` (the runway
floor, §2.2) is the one bound that is still one-sided-conservative — pinned against
**pessimistic slow early yield** (under-funding re-links, and it can't be raised
later) — but `C_max` is a two-sided pin.

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

For the realized `cover`, the candidate rungs form a **contiguous window of
`k + 1` rungs straddling `s_P`**, where `k = ⌊(C_max − C_min) / floor⌋` and the
split (how many below `s_P` vs above) slides with the realized draw. So the
width `W = C_max − C_min`, in units of `floor`, **is** the number of rungs the
cover blurs across — the §2.3 lattice dial, now exact: `k = W / floor`.

The **effective** anonymity set is not `k + 1` rungs but the
**posterior-weighted count of *stakers* on those rungs** (the §1.2 IPR). Uniform
`cover` (DQ1) makes the likelihood flat across the window, so the effective set
≈ `Σ` stakers occupying the `k + 1` rungs — uniform is exactly the shape that
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
stakers are indistinguishable). Pending the 2d-1 ramp for its final value.

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

### 7.6 What must precede the freeze, and what may follow it

**Pre-genesis blockers** (the freeze makes a partial-model pin un-revisable, §2.5):

- **The integrated joint × participation pass.** §7.4 (amount-marginal) and §7.5
  (participation) and finding 3 (timing) each move the pin materially and in
  conflicting directions; the genesis `k` is the realized optimum of all three
  **together**, under pessimistic inputs (thin `N_P`, dispersed density, low
  `timing_retain`, tight `β`). This couples the `--cover` and `--standoff` decoy
  models end-to-end — it is **not** a testnet-deferred follow-on (the earlier
  filing was wrong): pin it conservatively pre-freeze or it cannot be pinned.

**May follow (confirm-only, can't move an un-widenable bound):**

- **Per-rung density** (clustered ↔ dispersed) — the dominant lever; testnet
  measures the seating archetype's realized spread, but the bound ships sized
  against **dispersed** and testnet only *confirms*.
- **`C_min`** — needs the 2d-1 earnings-ramp numbers to size the runway floor.

C3 ships from the integrated pass's conservative interior optimum; testnet
**confirms** adequacy (§2.5). The wiring (C4 — `draw_cover_amount` in
`shekyl-standoff`) is mechanical once `k` and `C_min` are fixed.
