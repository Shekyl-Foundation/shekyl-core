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
work_P = Σ_s  floor( g_milli(age_s) / r_market_s )   // truncate-then-sum, milli
```

`g_milli = 1000 + floor(age_weight_milli · age_milli / 1000)` (milli scale, per
`g_age_milli`), with `age_milli ∈ [0, 1000]` by construction
(`shard_age_milli`, `:229–246`) and `age_weight_milli = 2000`
(`consensus_constants.json:36`, band `[1500, 2500]`), so `g_milli ∈ [1000, 3000]`
today. Therefore any shard with `r_market > g_milli` contributes **exactly 0**.

**Consequence.** An archiver whose shards each exceed the co-holder cliff scores
`work_P = 0` — no reward, permanently — regardless of how much correctly-served
data they hold. Worst *representable* case (see F-A): **4,096 shards ≈ 13.6 GB**
of served data, every challenge passed, `work_P = 0`. The cliff sits at
`r_market > g_milli`: **1,000 for a fresh shard, up to 3,000 at max age.**

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

The §6.0 wide-band framing **retroactively strengthens** the delete: `stake_factor`
is a *fast, participation-keyed* multiplier — precisely the manipulable-axis,
swing-prone family §6.0 excludes — while `n` is *slow chain structure*. Keeping it
would stack a swing-prone lever under a swing-resistant one, not just two levers.
One lever, one honest measure, wide guardrails.

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
  separator bump. Surfaces: `reward_arithmetic.rs`, `consensus_state.rs`,
  `emission_wire.rs` (field + varint codec), `emission_verify.rs` (both
  compares), `shekyl-ffi/archival_ffi.rs` epoch-close, C++ callers if the FFI
  signature moves; auth-msg binding. Fixture regen (expected to dominate the
  diff): `emission_verify_kat`, `emission_connect_kat`, `consensus_state_kat`,
  `kat_emission_auth_msg`, `EMISSION_KAT_SHAPE`; rule-42 snapshot check.
  Acceptance gate: the §7 red test un-ignores and passes. **Review check
  (§11.5):** the diff must *demonstrate* every rounding in the new micro path
  floors **against the claimant** (error favours the protocol) — the ERC-4626
  rounding-direction post-mortem discipline, not merely implied.
- **Stage 1b — the `stake_factor` delete (F-D), its own atomic commit.** The
  FOLLOWUPS item this round supersedes says *"not a ride-along edit"* — the
  **review** requirement is met (this round is that review), but the **edit** is
  a distinct burn-math change and must not be blended into the emission-wire
  precision diff (the F-11 own-adjacent-commit pattern, applied with more force
  here since this is consensus burn math). It lands as its **own commit** within
  the Stage-1 PR (promote to its own PR if it grows), carrying: the
  `stake_factor` removal from `calc_burn_pct` (`economics/burn.rs`) and its
  signature change, the three `blockchain.cpp` call sites, the FFI wrapper, the
  **`shekyl-economics-sim`** consumer (compile-time ripple — parity is
  self-enforcing, and Stage 2's evidence-validity argument *depends* on
  sim/production formula parity), and the `:1663` stale-comment fix. Numerically
  inert at genesis (`stake_ratio = 0 ⇒ ×1`).
- **Stage 2 — the sim arm (needs Stage 1).** `shekyl-economics-sim` budget arm:
  sweep shard-count trajectories against both decay curves (emission `>>21`,
  staker share `×0.9/yr`) and answer whether a 25%-floor + shard-indexed lift
  clears the archival burden in the fee era, or whether burn runs out first.
  **Extend scope to the distributional shift (W6):** the D1 fix moves ex-zero
  archivers into `Σwork`, shrinking scarce-holders' shares of a fixed budget —
  model the redistribution, not just the aggregate lift. Joint with stranding:
  what fraction of diverted budget goes unclaimed. **And the durable-stuffing
  sweep (W9, §6.2):** `scenario_4_stuffing_attack` gains an output-heavy variant
  (segment-freeze rate, not the volume metric), crossed with
  `scenario_7_bootstrap` (steepest early-chain slope), measuring cost-per-shard
  vs the permanent Δshare captured — **calibrated against the March-2024
  output-flood incident's cost profile** (§11.3), not an abstract stuffer — the
  sweep that confirms the burden-coupling argument leaves no early-chain regime
  where Δshare outruns Δburden. **Cross-chain-precedent arms (§11):**
  - **Proxy-cost arm (W10, §11.1):** proxy cost (fetch-within-grace from public
    daemons, per the gate-4 window) vs honest cost (hold ~13.6 GB) vs the
    **post-D1/D2** reward — confirm the §7.4 fetch-cost-vs-deadline margin still
    binds after D1 restores bulk-holder pay and D2 escalates the pool. If it does
    not, the disposition is gate-4 grace tightening or PoRep-reopen acceleration,
    not a D2 redesign.
  - **A ninth scenario — high-history / low-activity (§11.2):** large `n`, low
    current volume (the post-boom settled chain), the quadrant none of the
    existing eight cover (`scenario_8_late_tail` is high-history but busy).
  - **An explicit storage-cost-decline (Kryder) parameter**, so the arm's
    conclusion *states* its cost-decline assumption rather than embedding it.
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
- **Not participation-derived** — holding, sybil-splitting, and staking do not
  move `frozen_segment_count`; it is a chain-state fact. (The *one* action that
  does move it is output creation — the durable channel W9 prices, §6.2 — not a
  "swing" lever.)
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

### 6.1 Shape constraints (the frozen set)

The constraints §6.0 and the operand imply, to be pinned at Stage 3:

1. **Monotone in `n`** (shards only increase).
2. **Floor at the current 25%** (never below today's `staker_pool_share`).
3. **Asymptote strictly below 100%** — the deflation channel
   (`actually_destroyed`) survives forever.
4. **Banded piecewise-linear in integer fixed-point**, per the `curve_milli`
   precedent (`reward_arithmetic.rs` — the same shape the reward curve already
   uses; bit-exact, no float on the consensus path).
5. **No time-derivative or smoothing terms.** Smoothness is *inherited from the
   operand* (monotone + slow, §6.0); an EMA, rate-limiter, or any stateful
   controller on top would be exactly the narrow-band control machinery §6.0
   rejects — and it would add per-block state to a function that should be a pure
   map of `n`.

### 6.2 The ratchet cuts both ways — durable output-stuffing (wargame W9)

The same monotonicity that defeats fast-swing manipulation (W8) *enables* a
durable one, and it deserves its own row. Unlike volume-stuffing — whose effect
**decays** when the stuffing stops — a stuffed shard raises `n` **forever**. And
the ratified anti-stuffing analysis (`DESIGN_CONCEPTS.md` §6) **does not cover
this channel**: it keys the stuffer's cost to *transaction count* — `tx_volume`
is a tx count (`burn.rs:35`), and the `√(tx_volume/baseline)` damper escalates
against that metric. The D2 operand keys to **outputs** (leaves). An
output-maximizing stuffer inflates leaf count while barely moving `tx_volume`, so
the sqrt damper does **not** escalate against them — only weight-proportional
fees do.

**Why it should still price out — and why it must still be swept.** The operand
is not a *proxy*. `tx_volume` proxies demand, and a proxy can be fed cheaply;
`frozen_segment_count` **is the archival burden** — the exact quantity the
escalation exists to fund. A stuffer who mints 26k outputs creates a real
~3.33 MB shard that every archiver must hold and serve **forever**; they raise
the share and the cost it compensates **together**, in the mechanically coupled
ratio. Manipulating an honest measure of the funded quantity mostly just… funds
the quantity. That is the *argument*; the *sim's* job (Stage 2) is to confirm no
regime exists where the marginal Δshare briefly outruns the marginal burden. The
danger zone is early chain / low `n` / steepest share slope — where any
saturating curve is steepest — so **`scenario_4_stuffing_attack` gains an
output-heavy variant** (targeting segment-freeze rate rather than the volume
metric it currently keys on), **crossed with `scenario_7_bootstrap`**, measuring
**cost-per-shard** (25,992 outputs of weight-fees + burn) against the **permanent
Δshare** the stuffer captures through their stake fraction of the pool.

---

## 7. The red property test (authorized, test-only)

Written **red** against current code, asserting **only** the fix-shape-agnostic
property so it cannot prejudge micro-vs-nano-vs-aggregate (that is the round's
call):

> An archiver holding `N` shards all at `r_market > g_milli` scores `work_P > 0` and
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
- **The asymptote re-pin is a freeze-decision, not a tuning (§11.4).** The
  escalation asymptote's *shape* is frozen but its *number* is provisional-until-
  testnet, and it is the one capture point in this design — no post-genesis
  governance can relitigate it, so the testnet re-pin is the last moment it can be
  captured, and stakeholder pressure runs one way (higher). Treat the re-pin with
  **GF-7-threshold ceremony**: the adversary-advantage argument is committed
  *before* the number, and the number is decision-anchored.
- **Reopens to name in the frozen text:**
  - (a) redo the width and error-bound arithmetic (F-B/F-C) if
    `MAX_HOLDINGS_SHARDS` is ever raised;
  - (b) the `stake_factor` decision happens in **Stage 0**, not V3.1 — the
    `FOLLOWUPS.md:5255` item's own `> 10⁻³·SCALE` / V3.1 reopen is **superseded**
    by D2 touching this math pre-freeze;
  - (c) **a per-output fee-floor term** pricing the perpetual set-growth
    externality at output creation (§11.3) — out of this round's pinned scope
    (staker share only), **trigger:** the W9 sweep showing weight-fees alone do
    not clear cost-of-burden;
  - (d) **the §7.4 on-demand-serving equilibrium** (§11.1) — reopens via the doc's
    own economics-reopens (traffic-proportional pay §0.3, or PoRep durability
    fork) **trigger:** the W10 proxy-cost arm showing the fetch-cost-vs-deadline
    margin no longer binds under the D1/D2 economics.

---

## 9. Wargame

| # | Adversary | Defense | Armed? |
| --- | --- | --- | --- |
| W1 | Bulk-holder sybil via `max(1,·)` tail | No tail; micro preserves the hyperbola; multi-bond fan-out pays the true marginal sum (F-A: ≥ 4 bonds to plateau) | ✅ by construction |
| W2 | Sub-micro truncation harvesting | Error ≤ 4,096 micro/bond ≈ 0.026% plateau (F-B) | ✅ (bounded) |
| W3 | Per-shard/total scale split weakening `WorkTotalMismatch` | Single floor-site shared by close + verify; aggregate compare in micro-space (F-E) | ✅ landed (Stage 1) — `work_milli_from_micro` is the sole floor; `emission_verify` compares `entry_sum` vs `work_micro_p` pre-floor |
| W4 | Old-format (milli) entries valid under new rules | Zero-tolerance recompute rejects; `-v2` separator adds belt (F-E) | ✅ landed (Stage 1) — recompute + `-v2` belt (auth customizations bumped; `EMISSION_AUTH_MSG_V1` regenerated) |
| W5 | Stacked stake-responsive multipliers on `staker_pool_amount` | Delete `stake_factor` (F-D) | ⏳ arms when the F-D delete lands (Stage 1b) |
| W6 | Distributional dilution: D1 fix moves ex-zero archivers into `Σwork`, shrinking scarce-holders' shares of fixed budget | Stage-2 sim models the shift, not just aggregate lift | ⏳ sim-arm scope |
| W7 | Cached `frozen_segment_count` drift at the D2 read-point | Pinned read through frontier-check (M1 §11.8 M3-1) | ✅ carried |
| W8 | **Fast-swing** manipulation of the staker share (pump-and-dump, whale dive, reflexive feedback) | The operand is monotone + slow + predictable (§6.0) and the function is a pure map of `n` with no controller (§6.1) — pump/dump/whale have **no lever** on a monotone chain-state operand; the only lever is the durable one (W9) | ✅ by operand (fast-swing has no lever) |
| W9 | **Durable output-stuffing** — mint outputs to inflate leaf count → segment-freeze rate → `n` → share, permanently (the ratchet cuts both ways, §6.2). Not covered by `DESIGN_CONCEPTS.md` §6, which keys the stuffer's cost to `tx_volume` (a tx count) via the sqrt damper, which does not escalate against output count. **Live precedent**: Monero's suspected March-2024 output-flood; Bitcoin's 2015 dust floods (§11.3) | Burden-coupling: the operand *is* the funded quantity, so a stuffer raises the share and the real cost (a permanent ~3.33 MB shard held forever) in the coupled ratio — "manipulating an honest measure of the funded quantity mostly funds the quantity"; only weight-fees escalate against outputs | ⏳ pending Stage-2 sweep — **calibrated against the March-2024 incident's cost profile** (`scenario_4` output variant × `scenario_7` bootstrap, §6.2); rule-21 reopen if weight-fees alone don't clear (§8) |
| W10 | **Proxy free-riding on the on-demand-serving ruling** (§11.1) — a thin proxy re-fetches challenged data cheaply within the gate-4 grace window instead of holding it; D1 now *pays* that profile (was zero under truncation) and D2 escalates the pool it drains, re-pricing the §7.4 free-rider equilibrium that was closed under the old economics | Fetch-cost-vs-deadline margin must still bind (the §7.4/L14 judgment). If the Stage-2 arm shows it doesn't: tighten the gate-4 grace window or accelerate the PoRep reopen (the doc's own named economics-reopens) — **not** redesign D2 | ⏳ pending Stage-2 proxy-cost arm (§5) |

---

## 10. Surfaces touched (blast radius)

Consensus arithmetic (`reward_arithmetic.rs`, `consensus_state.rs`); the emission
work-claim wire (`emission_wire.rs` — field rename + width + varint codec); verify
(`emission_verify.rs` — both compares, in micro-space); the auth-msg digest
binding (`-v2`); the FFI epoch-close boundary (`archival_ffi.rs`) and its C++
callers if the contribution crosses in micro; `economics/burn.rs` +
`blockchain.cpp` + the FFI wrapper + **`shekyl-economics-sim`** (F-D delete —
the `calc_burn_pct` signature change ripples into the sim at compile time, which
is *good*: it makes sim/production formula parity self-enforcing, and Stage 2's
evidence validity depends on that parity; D2 escalation at Stage 3); the KAT
fixtures listed in §5; a rule-42 persisted-schema snapshot check. Pre-genesis:
**no fork surface**; genesis-freeze-class throughout.

---

## 11. Cross-chain precedent review (Stage 0 — importing others' scar tissue)

Stage 0 is the last cheap place to import failures other chains paid for. Three
directions searched: mechanisms we touch that failed elsewhere; settled decisions
of ours that D1/D2 silently re-price; things we are *not* doing that backfired.
Two genuine gaps (folded into the plan below), three precedent-anchored cautions,
and a clean bill on the rest.

### 11.1 Gap — D1/D2 re-price the on-demand-serving ruling without reopening it (→ W10, Stage-2 arm)

The Filecoin lesson: when data is publicly reconstructible, "prove you have it"
degenerates into "fetch it when challenged" — generation/outsourcing attacks are
why PoRep needs per-provider *sealed replicas*. Shekyl already confronted this and
ruled coherently (`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md` §7.5: the paid good
is **response to demand, not 24/7 disk attestation**; *"Foundation owns
durability; market owns reach"*; PoRep a named non-genesis path). **But §7.4
explicitly rejects** the "lazy re-fetch is orthogonal" dismissal: *"if re-fetch is
cheap, the challenge **is** the free-rider equilibrium"* (the L14
challenge-faking-cost residue, verified verbatim). That equilibrium was priced
against **today's** reward levels — under a frozen 25% share **and** the D1
truncation that paid bulk holders **zero**. D1 restores full pay to exactly the
bulk-holding profile a thin proxy would fake, and D2 escalates the pool such a
proxy would drain. This is Method-Note-5's inherited-pin pattern pointed at *our
own* project: a closed gate's ruling is a claim about the economics it was written
for, and we are changing those economics. **The check must be named now** —
nobody re-checks a closed gate. If the margin fails to bind, the answer is **not**
redesigning D2; it is tightening the gate-4 grace window or accelerating the PoRep
reopen — both already the doc's own named economics-reopens
(`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`: *"traffic-proportional pay (§0.3) or
PoRep durability fork"*). Folded: **W10** (§9) and a **Stage-2 arm** (§5). The
reciprocal pointer lands in the closed gate itself — `8C` §7.4 and §9.1 reopen
(d) now flag this equilibrium as under re-measurement (**X-1**), so a reader of
`8C` sees it, not only a reader of this doc: the correction lands where the claim
is *consumed*, not only where it is argued.

### 11.2 Gap — the missing sim quadrant: long history, low activity (→ scenario 9, Kryder param)

Permanent storage funded by *current* activity flows is the least-validated
economic mechanism in production crypto (Arweave's endowment-drawdown bet against
assumed storage-cost decline, with Kryder's-law slowdown its named risk; Filecoin's
other failure face — provider exodus when token rewards fell against fiat hardware
costs). Shekyl's structure: burden grows with **cumulative** history (shards are
forever), funding comes from **current** burn; the ratio degrades unless activity
grows or storage costs fall. Verified: all eight sim scenarios assume the mature
chain is **busy** — `scenario_8_late_tail` runs 180–300 tx/block against a 50
baseline. The dangerous quadrant — **large `n`, low current volume**, the chain
that had its boom and settled — is in **none** of them, and it is precisely where
a 25%-floor-plus-escalation either saves the archival layer or demonstrably
cannot. Folded: a **ninth scenario** (high-history / low-activity) and an explicit
**storage-cost-decline parameter** (§5), so the conclusion *states* its Kryder
assumption instead of embedding it.

### 11.3 Caution — W9 has a live precedent on our own lineage (→ W9 calibration, rule-21 reopen)

W9's adversary is not hypothetical. Bitcoin's 2015 dust floods demonstrated the
general form — outputs carry a *perpetual* set-growth externality that one-time
byte fees underprice — and Monero itself absorbed a suspected black-marble
output-flood in **March 2024** (mass-minted outputs on a CryptoNote chain, cheaply,
for weeks). On Monero the damage was decoy poisoning, which FCMP++ eliminates — but
on Shekyl **every flooded output becomes a permanently-funded leaf under D2**. And
our fee model is weight-priced with **no per-output perpetuity term** (verified:
`predict_weight` sums wire bytes; an output pays its weight-share once), so it
prices the flood exactly as Bitcoin did in 2015. The burden-coupling defense (§6.2)
may still hold, but the **W9 sweep must be calibrated against that incident's
actual cost profile**, not an abstract stuffer. A **named deferred option**, out of
this round's pinned scope (staker share only) and therefore a **rule-21 reopen, not
Stage 3**: a per-output fee-floor term pricing the perpetual externality at
creation — trigger: the W9 sweep showing weight-fees alone do not clear
cost-of-burden (§8).

### 11.4 Caution — burn redirection's political economy: the asymptote is the capture point (→ §8 ceremony)

Ethereum has repeatedly declined to redirect EIP-1559 burn toward public goods
(pure destruction is credibly neutral; any redirection creates a permanent
rent-seeking target). Shekyl's mitigations are the strong version: the redirection
is **algorithmic** (no governance surface to capture), **work-gated** (you archive
into the pool, you cannot lobby into it), and **fail-safe deflationary** (unclaimed
budget reverts to destruction — the opposite of Terra/Anchor, which promised a rate
and drained a reserve; we share revenue and never promise). The one place the
precedent still bites: the **asymptote numeric**. Its shape is frozen but its
number is provisional-until-testnet, and that is where every future stakeholder
pressure concentrates — stakers always want it higher, and there is no
post-genesis governance to relitigate it, so the **testnet re-pin is the last
moment it can be captured**. Treat it with **freeze-decision ceremony** (§8):
adversary-advantage argument first, then the number — the GF-7-threshold
discipline.

### 11.5 Caution — the rounding fix is validated by an exploited class (→ Stage-1 review check)

Per-share-vs-aggregate rounding mismatches and rounding-direction errors are a
repeatedly-exploited DeFi category (the ERC-4626 inflation attacks; lending-market
rounding drains). Our F-B/F-E treatment — single floor-site shared by close and
verify, floor-toward-zero so error always favours the protocol, per-entry compare
so a wrong split cannot hide behind a right total — is the converged post-mortem
answer from that history. **Stage-1 review check** (§5): confirm every rounding in
the new micro path floors **against the claimant** — the doc implies it; the diff
must demonstrate it.

### 11.6 Clean bill (surveyed, cleared)

No promised yield rate (Anchor). No usefulness oracle / notary layer to corrupt
(Filecoin Plus's fake-verified-deals — we pay for consensus-defined chain data,
nothing to adjudicate). No governance-settable economic knob (Curve gauge wars).
No asymmetric adjustment on a reversible input (BCH's EDA oscillated because its
input could swing; our operand cannot). Tail emission retained against fee-only
security instability (Carlsten).
