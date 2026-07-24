# Archival work-precision fix + shard-indexed staker escalation

Status: **design, Stage-0 round open** (spec-first per `05-system-thinking`,
`26-sub-pr-design-discipline`; the M1 precedent — consensus-rule changes get
their own design doc and review round). Grounded at `dev@3883c7947`
(2026-07-24); every source claim below is verified at that commit.
Scope owner: economics + archival-retention (consensus arithmetic).

This doc is the record of one design round covering **two consensus-arithmetic
defects** on genesis-frozen surface and their interaction. The arithmetic
changes land into [`ARCHIVAL_REWARD_ARITHMETIC.md`](ARCHIVAL_REWARD_ARITHMETIC.md)
and [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md) at
implementation; this doc owns the round.

---

## 0. Why this is genesis-critical and time-boxed

Both defects sit on **genesis-frozen wire/consensus arithmetic** with **no
version negotiation path** (the emission work-claim carries no version field;
verification is integer-exact, zero-tolerance — `emission_wire.rs:76`,
`emission_verify.rs:575`). Pre-genesis there is no installed base, so **no fork
surface** — but every change here is *free now, impossible after genesis*.

Both defects are also **latent at genesis and bite at scale**: they only appear
once the archival network succeeds and shards become widely replicated. That is
the worst latency profile — invisible in early testing, structural at maturity —
which is exactly why they must be settled pre-freeze rather than discovered
after.

---

## 1. The two defects

### D1 — aggregate truncation in `work_P` (correctness; urgent)

`as_of_e_served_work` (`consensus_state.rs:468–476`) accumulates each shard's
contribution into `work_by_bond` via `shard_contribution_milli`
(`:493`) → `shard_work_milli` (`:160`) → `scarcity_milli`
(`reward_arithmetic.rs:63`) → `mul_div_floor` (`:119`). Each per-shard term is
`floor(g(age) / r_market)` in **milli**, **floored before summation**:

```text
work_P = Σ_s  floor( g(age_s) / r_market_s )        // truncate-then-sum
```

`g(age) = 1 + age_weight · age`, with `age_milli ∈ [0, 1000]` by construction
(`shard_age_milli`, `:229–246`) and `age_weight_milli = 2000`
(`consensus_constants.json:36`, band `[1500, 2500]`), so `g ∈ [1000, 3000]`
today. Therefore any shard with `r_market > g` contributes **exactly 0**.

**Consequence.** An archiver whose shards each exceed the co-holder cliff scores
`work_P = 0` — no reward, permanently — regardless of how much correctly-served
data they hold. Worst *representable* case (see F-A): **4,096 shards ≈ 13.6 GB**
of served data, every challenge passed, `work_P = 0`. The cliff sits at
`r_market > g`: **1,000 for a fresh shard, up to 3,000 at max age.**

This is truncate-then-sum error. Under a single floor over the (precision-bounded)
sum, 4,096 shards at `r ≈ 2,000` yield `4,096 × 0.5 = 2,048` milli, not 0.

### D2 — `staker_pool_share` is a frozen scalar against a growing burden

The fee-era staker income leg **exists and is wired** (verified — not sim-only):

```cpp
// blockchain.cpp:6081
archival_budget_accrual = em_split.staker_emission + burn.staker_pool_amount;
```

`budget(E)` has two legs — the decaying emission share and the fee-burn share.
The fee leg is `compute_burn_split(...).staker_pool_amount` (`burn.rs:107`),
`staker_pool_share = 250_000` fixed-point = **25% of burn**
(`economics_params.json:14`). That 25% is **genesis-frozen** while the archival
*workload* grows with chain size (see §2). The mechanism that funds archival
work does not index to the load it funds.

`budget(E)` is a **minting entitlement, not held coin**: the B1 conservation
invariant keeps the accrual and burn tables disjoint, and budget unclaimed past
`MAX_CLAIM_AGE_W = 26` epochs is *"supply never created"*
(`ARCHIVAL_BUDGET_SCHEDULE.md` §4, ratified). So diverting burn → stakers
converts *unconditional destruction* into a *work-gated mint authorization* that
reverts to deflation by default if the work is not claimed.

### The interaction (why one round, not two)

D1 and D2 are coupled through **budget stranding**. A zero-work archiver (D1)
has nothing claimable → their slice of any diverted budget goes unclaimed →
never mints. Raising the staker share (D2) while a cohort sits at structural zero
(D1) would enlarge a pool that partly evaporates. `ARCHIVAL_BUDGET_SCHEDULE.md`
§4's own rule-21 reopen names exactly this: *"systematic budget stranding that
changes the archival-incentive calculus."* The two must be reasoned together.

---

## 2. Why the burden grows — the shard model (verified)

- **A shard is 25,992 outputs, not transactions.** `SEGMENT_LEAF_COUNT = 25 992`
  (`consensus_constants.json:38`; the level-2 subtree, `38·18·38`), and a leaf is
  one output tuple (128 bytes/output; `MERKLE_TREE.md`, the
  every-on-chain-output-is-a-leaf invariant). So shards accrue with **output
  volume** (≈ 2–3× tx count), not time — the busier the chain, the faster they
  freeze.
- **Shards are permanent and monotone in the canonical chain.** A frozen
  sub-root `R_k` is permanent the moment the subtree completes (MMR property of
  append-only `hash_grow`); ids are dense from 0; there is no retirement or
  pruning of a frozen segment (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §1.1). The
  daemon *"retains every leaf forever"* (§2.5) — the archival layer is exactly
  what a pruning node discards.
- **Pop-symmetric on reorg.** `frozen_segment_count` is monotone on the
  canonical chain but the pop hook (§4.2) deletes segment rows above the
  post-trim count. Any operand keyed on it inherits this and must read through
  the frontier-check, never a cached counter (M1 §11.8 M3-1 named the cached
  counter as a drift adversary).

The burden (shards) and the funding source (fees → burn; `burn_pct` itself rises
with `√(volume/baseline)` and `circulating/total_supply`) are driven by the
**same variable — activity**. That is why a shard-indexed staker share is
self-indexing rather than a constant bolted onto a growing cost.

---

## 3. Findings (this round), with dispositions

Ⓥ = verified at `dev@3883c7947`.

### F-A — the worst case is 4,096 shards, not 5,000 (Ⓥ; corrected)

`MAX_HOLDINGS_SHARDS = 4096` (`bond_wire.rs:33`) caps the holdings descriptor
**and** the per-epoch claim entries (write-side rejection,
`emission_wire.rs:457`). Worst representable case per bond: **4,096 shards ≈
13.6 GB → work 0.** This also corrects the anti-tail arithmetic: under a
`max(1, ·)` tail, one bond caps at 4,096 milli → `curve_milli(4096) = 4,048`
against plateau value 8,000, so the full-plateau-via-common-shards sybil path
needs **≥ 4 bonds**, not one. The anti-tail argument survives (per-persona bonds
make multi-bond fan-out the system's own admission path), but the doc carries the
corrected numbers.

### F-B — the exact-sum form is not implementable; micro is (analysis)

`floor(Σ g_s/r_s)` over heterogeneous denominators cannot be done in bounded
integer arithmetic without rational accumulation. Any real implementation picks
a **fixed intermediate precision** and floors per-shard at that precision. The
proposal is that idea instantiated at 10⁻⁶: `scarcity_micro` per shard, one floor
back to milli at the aggregate. Residual error: `< 1` micro/shard, `≤ 4,096`
micro `≈ 4.1` milli/bond worst case — **0.026% of `plateau_work_milli`**.
Harvesting it adversarially requires controlling `r_market` across thousands of
shards to net ~4 milli; no economics there (wargame W2).

### F-C — micro fits `u32`; nano is brittle; F-E8 does not reopen (Ⓥ arithmetic)

Per-entry micro max `= 1000·g ≤ 1000·(1000 + 2500) = 3.5×10⁶` at the
calibration-band ceiling — `u32` with ~1,200× headroom. Nano would fit `u32`
(3.5×10⁹ < 4.29×10⁹) but at 19% headroom against a band explicitly
provisional-re-pin-at-testnet — brittle, **rejected**. Aggregate `4,096 ×
3.5×10⁶ ≈ 1.43×10¹⁰` needs `u64`; `work_by_bond` is already `Vec<u64>`. **F-E8
(u128 width audit) does not reopen** — `WORK_MILLI_SCALE` is untouched and the
new intermediates stay inside existing `u64/u128` domains — and the doc states
this explicitly rather than assuming it.

### F-D — the dormant `stake_factor` lever; pull to Stage 0; **DELETE** (Ⓥ)

`calc_burn_pct` carries `stake_factor = 1 + stake_ratio` (`burn.rs:69`), and
`stake_ratio` is hard-pinned to `0` at all three production call sites
(`blockchain.cpp:1666`, `:1975`, `:6079`). The `:1663` comment points the feed at
"C-1", but C-1 (#277) landed without it. The live disposition
(`FOLLOWUPS.md:5255`): gate-7 iteration-5 showed the shipped bonds-only lock
holds `stake_ratio` at `10⁻⁷–10⁻⁴` of `SCALE` — **structurally inert** — and the
factor *"was designed for the retired tier-staking model"*; keep-vs-delete
deferred to V3.1, reopen at `> 10⁻³·SCALE`.

**Disposition: DELETE, in Stage 0.** The FOLLOWUPS item's own words — *"This is
consensus burn math; it needs its own review… not a ride-along edit"* — and D2 is
that review, pre-genesis, on that exact math, so the V3.1 target is superseded.
The reason is stronger than "inert": the two knobs are conflated.

- `stake_factor` (in `calc_burn_pct`) is a **burn-rate** lever — deflate more
  when more is staked.
- `staker_pool_share` (in `compute_burn_split`) is a **reward-share** lever.

Leaving `stake_factor` live would stack a **second** stake-responsive multiplier
on `staker_pool_amount`, keyed on the *wrong axis*: `stake_ratio` is
**participation** (capital locked), the manipulable-ish family D2 explicitly
rejected in favour of shard-count as a **chain-state fact**. And it is dead by
design — nothing under bonds-only can lift `stake_ratio` to relevance; it was
built for a staking model that no longer exists. Deleting a `×1` term is
**numerically inert at genesis** (`stake_ratio = 0 ⇒ factor = 1`), removes a
fossil with a stale C-1 pointer, and leaves one clean decomposition: **burn rate
= activity × supply; staker share = archival work** (rule 15, rule 05). The
`:1663` stale comment is fixed in Stage 1's diff.

### F-E — preserve the single-source property; bump the auth-msg separator (Ⓥ)

The single-source property is the load-bearing safety feature
(`consensus_state.rs:392` — the numerator is the denominator's term by
definition; `:485` — verify's recompute cannot drift from close). The micro
change must preserve it **structurally**: `shard_contribution` returns micro; the
floor-to-milli lives in **exactly one** function consumed by both epoch close and
the verify body; and the verify's aggregate compare runs in **micro-space before
that floor** — otherwise the per-entry compare (micro) and total compare (milli)
sit on different scales and `WorkTotalMismatch` silently weakens (wargame W3).

The auth-msg digest binds the work-claim bytes (field 6), so the format change
regenerates `kat_emission_auth_msg` and raises a rule-30 question.
**Disposition: bump `shekyl/archival-emission-auth-*-v1 → -v2`.** No ambiguity
*attack* exists (the zero-tolerance recompute rejects milli-valued entries under
micro rules), but the digested layout's **semantics** changed (milli → micro);
domain separators exist to make "same bytes, different meaning" non-colliding
*structurally* rather than by an argument a future reader must reconstruct. Cheap
pre-genesis, belt to the recompute's suspenders (wargame W4).

---

## 4. Answered questions (this round)

1. **Wire call:** widen `scarcity_milli` → **`scarcity_micro` (`u32`)** per
   entry; keep **both** compares (per-entry and aggregate). Do **not** drop to
   aggregate-only: the per-entry compare is precisely what stops "a wrong
   per-shard split hiding behind a correct total" (`emission_verify.rs:560`). Byte
   cost: ~1–2 bytes/entry of varint growth, `≤ 8 KiB` on a maximal claim. Rename
   the field to the consumer's meaning.
2. **Sequence:** design-doc first, **no parallel production code**. The "obvious
   shape" moved twice this round (exact-sum → micro; 5,000 → 4,096) and produced
   two genuinely open design decisions (`-v2` bump, floor-site placement). The one
   thing that may move now: the **red property test** (§7), test-only, asserting
   only the fix-shape-agnostic property.
3. **Blast radius:** genesis-freeze-class, slightly wider than first stated. Add
   to the surface list: the auth-msg binding (`-v2`), the FFI epoch-close
   signature if the contribution type crosses the boundary in micro
   (`archival_ffi.rs:20`), and the explicit F-E8 non-reopen statement.

---

## 5. Staged plan

The sequence is **forced**, not convenience: D1 corrupts the exact denominator
(`Σwork`) the D2 sim measures against. Simulating D2 on a broken work model
measures the wrong thing — this is evidence validity.

- **Stage 0 — this design round.** Both defects, the interaction, the
  dispositions above. Output: this doc, reviewed.
- **Stage 1 — the precision fix (D1).** `scarcity_micro (u32)`; single floor-site
  shared by close + verify; aggregate compare in micro-space; the `-v2`
  separator bump; delete `stake_factor` (F-D); fix the `:1663` comment.
  Surfaces: `reward_arithmetic.rs`, `consensus_state.rs`, `emission_wire.rs`
  (field + varint codec), `emission_verify.rs` (both compares),
  `shekyl-ffi/archival_ffi.rs` epoch-close, C++ callers if the FFI signature
  moves; auth-msg binding. Fixture regen (expected to dominate the diff):
  `emission_verify_kat`, `emission_connect_kat`, `consensus_state_kat`,
  `kat_emission_auth_msg`, `EMISSION_KAT_SHAPE`; rule-42 snapshot check.
  Acceptance gate: the §7 red test un-ignores and passes.
- **Stage 2 — the sim arm (needs Stage 1).** `shekyl-economics-sim` budget arm:
  sweep shard-count trajectories against both decay curves (emission `>>21`,
  staker share `×0.9/yr`) and answer whether a 25%-floor + shard-indexed lift
  clears the archival burden in the fee era, or whether burn runs out first.
  **Extend scope to the distributional shift (W6):** the D1 fix moves ex-zero
  archivers into `Σwork`, shrinking scarce-holders' shares of a fixed budget —
  model the redistribution, not just the aggregate lift. Joint with stranding:
  what fraction of diverted budget goes unclaimed.
- **Stage 3 — the escalation (D2; gated on Stage 2).** `compute_burn_split`
  gains the shard-count operand; `staker_pool_share` becomes the function's floor
  parameter; the `blockchain.cpp:6081` site reads `frozen_segment_count` at the
  pinned read-point through the frontier-check. May spawn its own implementation
  doc.

---

## 6. Escalation design space (Stage 3 — open, for the review)

### 6.0 Governing principle: a wide band with guardrails, anti-swing over anti-drift

This is **not** the usual monetary-control problem of pinning a variable to a
narrow band for efficiency. Shekyl's stance (rule 75, self-regulating design) is
a **wide band that lets the economy organically regulate itself between
guardrails** — the floor and the asymptote are the guardrails, and the *level*
inside them is allowed to move. What the design actively resists is **rapid
swings and unpredictable churn** — the rate of change, not the level — because
that is where market manipulation lives (pump-and-dump, whale diving,
reflexive feedback). *(Scope note: this principle governs the Stage-3 staker-share
function only; it is not a mandate to re-tune the wider economy.)*

The chosen operand already serves this by construction, and it is the strongest
argument for it over a participation-derived signal:

- **Monotone** — shard count only increases in the canonical chain (§2), so the
  share ratchets one way; there is no down-swing to manipulate.
- **Slow** — it advances with *output volume* (frozen segments of 25,992
  outputs), not with a price or a poll, so it cannot be moved in a burst.
- **Unmanipulable by acting** — a chain-state fact, not participation-derived
  (sybil-splitting shard-holding does not move `frozen_segment_count`).
- **Predictable** — a slow monotone ratchet is *visible in advance*, which
  directly defeats the "unpredictable churn" vector; operators can see the share
  drift coming rather than being whipsawed by it.

Consequences for the function shape (below): prefer a **smooth, bounded-slope**
form with **no cliffs** — the priority is damping the *rate* of change, not
hitting a precise target share. The Stage-2 sim evaluates the band's width and
its swing behavior (rate per unit shard growth), not only "does it clear the
burden."

- **Operand: `frozen_segment_count`, read through the frontier-check.** A
  chain-state fact (not participation-derived, so not manipulable by acting),
  dense from 0, pop-symmetric with existing differential-test + tripwire
  discipline. The **read-point is an open decision**: the burn split fires
  per-block, and `frozen_segment_count` derives from `leaf_count`, which *this
  block's own outputs* advance — the same ordering hazard §3.1 already documents
  (the pre-F-B1a shape *"left the final block of every epoch out of its own
  `budget(E)`"*). Pin whether this block's own leaves count toward its own split,
  explicitly, through the frontier-check, never the cached counter.
- **Function shape:** floor at the current 25%, **asymptote `< 100%`** — a burn
  floor must survive forever, because burn is also the deflation lever. This is a
  three-way allocation between stakers, deflation, and (via `actually_destroyed`)
  holders. Linear-to-saturation hits 100%-of-burn at a finite chain size and then
  silently saturates; a saturating form (asymptote below 100%) keeps deflation
  alive. The sim (Stage 2) picks the shape and asymptote; this doc does not
  pre-pin them.
- **Monotonicity:** shards only increase in the canonical chain (§2), so the lift
  ratchets up and is pop-symmetric on reorg — no ratchet-down object to reason
  about beyond the reorg path already handled.

---

## 7. The red property test (authorized, test-only)

Written **red** against current code, asserting **only** the fix-shape-agnostic
property so it cannot prejudge micro-vs-nano-vs-aggregate (that is the round's
call):

> An archiver holding `N` shards all at `r_market > g` scores `work_P > 0` and
> proportional to `N`.

Mechanics: `#[ignore = "RED: documents D1 aggregate-truncation; un-ignores when
the Stage-1 micro fix lands (design round first)"]` — CI stays green, and
un-ignoring it **is** Stage 1's acceptance gate. It documents the defect
executably (not just in prose) and gates the fix without encoding a design
decision.

---

## 8. Freeze posture and rule-21 reopens

- **Freeze posture** (`bond_duration` precedent — *"shape genesis-frozen;
  numerics provisional, re-pin at testnet"*): Stage-1 work-precision **function
  shape genesis-frozen**; Stage-3 escalation **shape frozen, numerics provisional**
  per the sim.
- **Reopens to name in the frozen text:**
  - (a) redo the width and error-bound arithmetic (F-B/F-C) if
    `MAX_HOLDINGS_SHARDS` is ever raised;
  - (b) the `stake_factor` decision happens in **Stage 0**, not V3.1 — the
    `FOLLOWUPS.md:5255` item's own `> 10⁻³·SCALE` / V3.1 reopen is **superseded**
    by D2 touching this math pre-freeze.

---

## 9. Wargame

| # | Adversary | Defense | Armed? |
| --- | --- | --- | --- |
| W1 | Bulk-holder sybil via `max(1,·)` tail | No tail; micro preserves the hyperbola; multi-bond fan-out pays the true marginal sum (F-A: ≥ 4 bonds to plateau) | ✅ by construction |
| W2 | Sub-micro truncation harvesting | Error ≤ 4,096 micro/bond ≈ 0.026% plateau (F-B) | ✅ (bounded) |
| W3 | Per-shard/total scale split weakening `WorkTotalMismatch` | Single floor-site shared by close + verify; aggregate compare in micro-space (F-E) | ⏳ arms when F-E lands (Stage 1) |
| W4 | Old-format (milli) entries valid under new rules | Zero-tolerance recompute rejects; `-v2` separator adds belt (F-E) | ✅ (recompute) + belt |
| W5 | Stacked stake-responsive multipliers on `staker_pool_amount` | Delete `stake_factor` in Stage 0 (F-D) | ✅ by disposition |
| W6 | Distributional dilution: D1 fix moves ex-zero archivers into `Σwork`, shrinking scarce-holders' shares of fixed budget | Stage-2 sim models the shift, not just aggregate lift | ⏳ sim-arm scope |
| W7 | Cached `frozen_segment_count` drift at the D2 read-point | Pinned read through frontier-check (M1 §11.8 M3-1) | ✅ carried |
| W8 | Swing/churn manipulation of the staker share (pump-and-dump, whale dive, reflexive feedback) | Operand is monotone, slow (output-volume-paced), unmanipulable-by-acting, and predictable (§6.0); function is smooth/bounded-slope, no cliffs — there is no fast-swinging lever to whipsaw | ⏳ shape-dependent (Stage 2/3) |

---

## 10. Surfaces touched (blast radius)

Consensus arithmetic (`reward_arithmetic.rs`, `consensus_state.rs`); the emission
work-claim wire (`emission_wire.rs` — field rename + width + varint codec); verify
(`emission_verify.rs` — both compares, in micro-space); the auth-msg digest
binding (`-v2`); the FFI epoch-close boundary (`archival_ffi.rs`) and its C++
callers if the contribution crosses in micro; `economics/burn.rs` +
`blockchain.cpp` (F-D delete; D2 escalation at Stage 3); the KAT fixtures listed
in §5; a rule-42 persisted-schema snapshot check. Pre-genesis: **no fork
surface**; genesis-freeze-class throughout.
