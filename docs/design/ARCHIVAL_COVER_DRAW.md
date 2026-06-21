# Archival Cover-Amount Draw — entropy scoping (genesis-adjacent)

**Status:** SCOPING (2026-06-20). Design-questions enumerated; not yet decided.
Off-wire, scanner-independent, un-vendor-independent — parallelizable now.
**Parent design:** `ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §3.4 (cover-stays-with-P,
SETTLED) + §SP-2.d; `GENESIS_TX_WIRE_FORMAT.md` §2.0 (the security-crux flag);
`ARCHIVAL_FIREWALL_GATE6.md` §10.12 (the funding seam). Mechanism sibling:
`shekyl-standoff` (the entry-gap timing draw).
**Process rule:** `26-sub-pr-design-discipline.mdc` (genesis-adjacent privacy
surface; lightweight — the *architecture* is settled, this pins one draw).

---

## 0. Why this exists, and why now

2c-2b settled the cover **architecture** (cover-stays-with-`P`, §3.4): the
principal sends `bond_floor + cover` to `P`; `P` stakes the floor (public
`bond_credit == bond_floor` on the bond-post) and keeps the `cover` as a
confidential change-to-`P` output. What it did **not** settle is the **cover
amount itself** — the distribution it's drawn from. `GENESIS_TX_WIRE_FORMAT.md`
§2.0 flags this as the security crux:

> the cover defense reduces entirely to the **entropy of the cover draw** … an
> amount chosen for operational utility pulls toward predictability … while the
> correlation defense wants high entropy. The `shekyl-standoff` entry-draw exists
> to arbitrate exactly this.

It is **genesis-adjacent** (must be pinned before 2d's bond-tx assembly lands —
2C2B forward-action) and it is the one bond/cover piece that is **off-wire**
(cover is an ordinary confidential CT output, no wire field) and therefore
**independent of the shekyl-oxide un-vendor and the scanner** — so it can be done
in parallel while the wire-format port proceeds.

---

## 1. Threat model — the link the cover defeats

**Not** the on-chain amount (the principal→`P` transfer is confidential CT — the
on-chain value is already hidden). The cover defends against an observer who
learns the principal's spend amount **out-of-band** (the principal is a known
entity — exchange withdrawal, KYC'd desk, partially-deanonymized wallet) and
tries to link that principal to a specific stake position.

- **`bond_floor` is public.** It rides the bond-post cleartext
  (`bond_credit == bond_floor(holdings)`, `==` not `≥`), so the observer knows it
  for every bond, keyed to the persona `P`.
- **Without cover:** the principal sends exactly `bond_floor`. An observer with
  the out-of-band amount `A` matches `A == bond_floor` → links principal → `P`.
- **With cover:** the principal sends `A = bond_floor + cover`. The observer
  computes a candidate `cover = A − bond_floor` for each public bond and asks "is
  this a plausible cover?" The link survives only if the true `(bond, cover)`
  pair stands out from coincidental matches across the chain.

So the defense's strength = **how many `(public bond_floor, plausible cover)`
pairs are consistent with a given known `A`** — i.e. the anonymity set the cover
distribution induces over the population of live bonds. Low cover entropy ⇒ a
near-unique match ⇒ the link holds. This is the quantity to pin.

---

## 2. The two tensions to resolve (the heart of the scope)

1. **Entropy vs working-capital predictability (GENESIS §2.0).** `P` holds the
   cover as working capital (it seeds the fund-from-earnings pool, §3.4 #3). An
   amount chosen for *operational utility* (round, sized to expected fees,
   correlated with `P`'s activity) is **predictable** — exactly what the defense
   can't tolerate. *Proposed resolution to ratify:* the cover is an **entropy
   draw, privacy-primary**; the working-capital use is a **downstream
   consequence** of whatever was drawn, never a constraint that narrows it
   (mirrors the cover-stays-with-`P` decision — don't optimize the cover for
   utility at privacy's expense). DQ4 makes this binding or overturns it.

2. **Per-wallet uniformity (the entry-gap lesson).** Like the entry-gap window
   (single-sourced `DEFAULT_ENTRY_GAP_WINDOW`, golden-vector-pinned), the cover
   **distribution must be the same across all wallets**. If wallet A draws cover
   `~U[0,X]` and wallet B draws `~lognormal`, the *distribution choice itself*
   fingerprints the wallet/software and shrinks the anonymity set — a
   mission-priority-1 leak, the same class the cover exists to close. So the
   distribution is a **pinned, single-sourced wallet policy**, not a per-wallet
   knob — even though the GUI/CLI presents the *value* (2c-2b §3.4 #4, the engine
   accepts `CoverAmount`, the front-end computes the recommended draw **from the
   pinned distribution**).

---

## 3. Scope

### 3.1 In scope

| # | Item |
| --- | --- |
| C1 | **Threat-model quantification (§1).** Define the anonymity-set metric: given the live-bond `bond_floor` population and an out-of-band `A`, the count of consistent `(bond, cover)` pairs. Target value (the cover analogue of `window = 600`). |
| C2 | **Distribution shape (DQ1).** What the cover is drawn from — additive uniform `U[0, C_max]`, multiplicative/log over a range, or floor-relative (`cover ~ f(bond_floor)`). Must dominate the realistic spread of `bond_floor` values so a known `A` doesn't localize. |
| C3 | **Bounds (DQ2).** `C_min` / `C_max` (genesis-adjacent constants, single-sourced beside `DEFAULT_ENTRY_GAP_WINDOW`). Lower bound: dust / economic-noise floor. Upper bound: the capital `P` must actually lock up (the cost of the entropy). |
| C4 | **Mechanism (DQ3).** A `shekyl-standoff` **value draw** (float-free, single-sourced, conformance-graded) reusing `GapRng` + `bounded_uniform`, extending the crate's scope from "entry-standoff timing draw" to "funding-seam decorrelation draws: timing **and** amount." Golden vector + (gated) conformance grade, the same discipline as the entry-gap. |
| C5 | **Uniformity binding (DQ5).** Single pinned distribution; the GUI/CLI computes the recommended value **from it**, the engine only accepts the `CoverAmount`. Stated as a normative anti-fingerprint rule (like the `enc_label` invariant). |
| C6 | **Wire `CoverAmount` type follow-through.** `CoverAmount(AtomicUnits)` exists inert (`stake_timing.rs`); the draw produces it. (Orchestration — the `bond_floor + cover` send + `P`-change threading — stays 2d, but the **draw** is pinned here.) |

### 3.2 Out of scope

| Out | Why |
| --- | --- |
| The 2d bond-tx assembly (`bond_floor + cover` send, `P`-change output threading) | Needs the broadcast/transaction path (2d); the **draw** is the genesis-adjacent prerequisite, the *spend* is 2d. |
| Any wire/consensus change | Cover is an ordinary confidential CT output; the chain never sees or verifies it. No wire surface, no consensus rule. |
| Opt-in cover **recovery** (stake-once-and-recover) | Separate, V3.x, GUI/CLI, independently-timed (2c-2b §3.4). |
| Steady-state fund-from-earnings sizing | The cover *seeds* the pool; how the pool is *spent* is the `P`-scan / 2d-1 funding work. |

---

## 4. Design questions

- **DQ1 — distribution shape.** Additive `U[0, C_max]` vs multiplicative/log vs
  floor-relative. The constraint: a known `A = bond_floor + cover` must not
  localize `bond_floor` better than the target anonymity set (C1). Floor-relative
  (`cover` scaled to `bond_floor`) better matches the population spread but
  **leaks holdings magnitude** if the scaling is observable — likely rejected on
  the same grounds `==` (not `≥`) was chosen for the floor. *Lean: additive
  uniform over a range that dominates the realistic `bond_floor` spread* — pending
  C1's population analysis.
- **DQ2 — bounds `C_min`/`C_max`.** Pinned constants (single-sourced). `C_max` is
  the entropy↔capital trade dial (bigger = more anonymity, more locked capital).
  Needs the C1 population analysis + an economic read on acceptable `P` lockup.
- **DQ3 — mechanism home.** Extend `shekyl-standoff` (re-scope its crate doc to
  "funding-seam decorrelation draws: timing + amount") with a `draw_cover_amount`
  beside `draw_entry_gap`, sharing `GapRng`/`bounded_uniform`/golden-vector
  discipline — **vs** a sibling crate. *Lean: extend `shekyl-standoff`* — same
  single-source "what we validated is what ships" property, same conformance
  harness; the cover draw is the amount-axis of the very seam the crate already
  owns.
- **DQ4 — entropy-primary vs utility-constrained.** Ratify §2 tension #1: the
  cover is a privacy draw whose value `P` *then* uses as capital, **not** a
  utility-sized amount. If overturned (utility constrains the draw), C1's target
  must absorb the reduced entropy — and the defense weakens accordingly; surface
  that explicitly.
- **DQ5 — uniformity as a normative rule.** State "all wallets draw cover from
  the single pinned distribution" as a binding anti-fingerprint invariant (§2
  tension #2), the cover analogue of the `enc_label` indistinguishability rule.
- **DQ6 — `cover == 0` (stake-only) interaction.** `CoverAmount::ZERO` is the
  opt-in stake-only path (disclosed privacy cost, 2c-2b §3.4 #4). Does a
  population where *some* wallets draw `0` and others draw from the distribution
  create a distinguishable class? (Likely: zero-cover bonds are the
  exact-`bond_floor` match the cover exists to prevent — so `0` is a *named
  opt-out with a disclosed cost*, not part of the anonymity set. Confirm.)

---

## 5. Sequencing & dependencies

- **Prerequisite for:** 2d bond-tx assembly (the `bond_floor + cover` send). Must
  pin the draw before that lands (2C2B forward-action, "genesis-adjacent").
- **Independent of:** the shekyl-oxide un-vendor (off-wire) and the scanner (no
  scan path) — runnable in parallel with the wire-format port.
- **Owns no wire/consensus bytes** — so it does **not** gate or touch the genesis
  freeze; it's a wallet-policy draw, pinned for cross-wallet uniformity.
- **Likely needs a sim/analysis pass** for C1/DQ1/DQ2 (the population anonymity
  metric), the same way the entry-gap window was set by analysis — that's the
  substantive work, distinct from wiring the draw.

## 6. Gates (when it lands)

`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; the draw is
float-free (the production path, like `draw_entry_gap`); golden-vector KAT for
the draw; conformance grade gated behind the `conformance` feature (the cover
draw's distribution graded, not asserted bit-identical — same posture as the
entry-gap grade). No `STAKING_BLOCK_VERSION` / wire-format bump (off-wire).
