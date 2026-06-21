# Archival Cover-Amount Draw — entropy scoping (genesis-adjacent)

**Status:** SCOPING (2026-06-20, review-revised). Design-questions enumerated;
not yet decided. Off-wire, scanner-independent, un-vendor-independent —
parallelizable now. The bond-standardization input is **decided in shape**
(flat `floor × shards`, pinned rung) so C1's *shape* is pinnable now; only C1's
**magnitudes inherit the staking economics' post-testnet calibration** (§2.3) —
not a blocked decision.
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

**Consequence (refines "co-pin first"):** C1 is **not** blocked on an open
decision — it *inherits* the sim's already-shaped lattice population, and its
**numbers (the C1 target, `C_max` in rungs) inherit the staking economics'
post-testnet calibration**, the same class as every other staking magnitude. So
the cover follows the sim's **own** genesis-pin pattern: **pin the *shape* now**
(uniform draw, the rung-stepped `C_max` structure) **with a conservative genesis
constant, calibrate the exact magnitude post-testnet** against the same population
the sim does. **One sharper-than-wallet-policy twist (§2.4):** because the cover
must be *uniform across wallets* for the anonymity set, `C_max` is **not** freely
re-tunable post-genesis the way an off-wire wallet constant normally is — moving
it splits the anonymity set into old-`C_max` and new-`C_max` cohorts. So `C_max`
wants a genesis-pin-grade conservative value (over-provision the rung span), not a
"tune it on testnet" knob — a tension to flag for the genesis-pin pass.

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

---

## 3. Scope

### 3.1 In scope

| # | Item |
| --- | --- |
| C1 | **The metric (§1).** A **joint amount × timing, posterior-weighted effective anonymity set** (IPR over the attacker's likelihood) computed over the **discrete `bond_floor` lattice** and the actual shard-count distribution. **Inherits** the bond-standardization / shard-count decision (§2.3) — co-pin first. Target value = the cover analogue of `window = 600`, sized for the worst-case direct funder (§1.3) and **jointly with the entry-gap standoff** (§1.1). |
| C2 | **Distribution shape (DQ1).** Pinned shape; uniform is the expected *result* of the posterior-weighting argument (§4), not a guess. |
| C3 | **Bounds (DQ2).** `C_min` = **working-capital runway** floor (§2.2; references 2d-1 ramp), strictly positive. `C_max` = the **lattice dial** (§2.3): steps at `floor` multiples; `≥ k × floor` to blur `k` shard-count rungs. Both single-sourced beside `DEFAULT_ENTRY_GAP_WINDOW`. |
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
- **DQ2 — bounds.** `C_min` = working-capital runway (§2.2). `C_max` = lattice
  dial (§2.3), set by how many shard-count rungs the anonymity target (C1) must
  blur, against acceptable `P` capital lockup. Both **fall out of C1**, which
  needs the §2.3 co-pin first.
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

- **Inherit, don't block (refined §2.3):** the bond-standardization is decided in
  *shape* (flat `floor × shards`, pinned rung; `STAKER_ARCHIVAL_SIM.md`). C1's
  *shape* (uniform draw, rung-stepped `C_max`) is **pinnable now**; only its
  *magnitudes* inherit the sim's **post-testnet** calibration — so pin shape now,
  calibrate magnitude against the same population the sim does. **`C_max` is *not*
  freely re-tunable post-genesis** (anonymity-set uniformity, §2.4) — it wants a
  conservative genesis-pin value, not a testnet knob.
- **Size jointly with the entry-gap standoff (§1.1):** the standoff width is an
  input to the cover metric; the two draws share the funding seam and trade off.
- **Prerequisite for:** 2d bond-tx assembly (the `bond_floor + cover` send).
- **`C_min` references** the steady-state fund-from-earnings ramp (2d-1) — runway
  must outlast cold-start until earnings carry.
- **Independent of:** the shekyl-oxide un-vendor (off-wire) and the scanner — the
  *mechanism* (C4) and *uniformity rule* (C5) can be drafted now; the *numbers*
  (C1/DQ1/DQ2) wait on the co-pin.
- **Owns no wire/consensus bytes** — does not gate or touch the genesis freeze.
- **The substantive work is the sim/analysis pass** (C1), the way the entry-gap
  window was set by analysis — distinct from wiring the draw.

## 6. Gates (when it lands)

`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; production draw
**float-free** (like `draw_entry_gap`); golden-vector KAT; conformance grade gated
behind the `conformance` feature (distribution graded by margin, not asserted
bit-identical — the entry-gap posture). No `STAKING_BLOCK_VERSION` / wire-format
bump (off-wire).
