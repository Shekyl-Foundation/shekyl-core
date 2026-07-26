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
- **Stage 1 — the precision fix (D1). ✅ landed (`699876d89`).** `scarcity_micro (u32)`; single floor-site
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
- **Stage 1b — the `stake_factor` delete (F-D), its own atomic commit. ✅ landed (`7256962`).** The
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
    not clear cost-of-burden. **🔴 FIRED (Stage 2 · A4 · cp4b `d4026efe3`, cp4c).**
    The W9 served-work sweep fails ROI < 1 even at the rational honest
    equilibrium (2.8× baseline → 17.8× late-tail; §12.5). Promoted from named
    reopen to a **Stage-3 hard input**, denominated in **weight** (a per-output
    virtual-weight surcharge that rides the fee market and flows through the
    existing weight/fee/burn machinery with zero new consensus fields — not a
    frozen atomic constant), and **paired** with the capture-side **D3** fix
    (reopen (e)) — each closes the regime the other cannot;
  - (e) **the archival-reward per-bond curve-cap dodgeability (D3)** — the
    `curve_milli` plateau caps per *bond* while the bond floor is per *shard*, so
    holdings split into small bonds at no extra bond cost dodge the cap; a naive
    big-bond archiver self-caps while a splitter (attacker or savvy honest) is
    uncapped. **Surfaced by A4** (Stage 2, cp4b) and **load-bearing for W9** (it
    ~2× the stuffer's ROI at the capped-honest end), it is its own defect at the
    archival-reward layer needing its own design round (fix space: per-*persona*
    curve application, per-bond bond floors, or bond-proportional plateaus).
    Filed `FOLLOWUPS.md`;
  - (d) **the §7.4 on-demand-serving equilibrium** (§11.1) — reopens via the doc's
    own economics-reopens (traffic-proportional pay §0.3, or PoRep durability
    fork) **trigger:** the W10 proxy-cost arm showing the fetch-cost-vs-deadline
    margin no longer binds under the D1/D2 economics. **🔴 FIRED (Stage 2 · A5 ·
    cp5a `49cf160e9`).** The margin is negative at the current grace window (the
    cheap ~3 KB opening re-fetches for ≪ the cost of holding 13.6 GB; §12.6). The
    named remedy applies: **tighten the gate-4 grace window** to force a re-fetch-
    failure rate `q ≥ q*` (`q* ≈ 0.085–0.26` — the m-of-n slash crossover),
    **or** accelerate the **PoRep** reopen (`q → 1`, sealed possession). **Not** a
    D2 redesign. NB: the corrected m-of-n slash (`ARCHIVAL_FAILURE_CONFIRMATION_PIN`,
    a single miss absorbed) *weakens* the deterrent vs a single-strike, so `q*` is
    a floor.

---

## 9. Wargame

| # | Adversary | Defense | Armed? |
| --- | --- | --- | --- |
| W1 | Bulk-holder sybil via `max(1,·)` tail | No tail; micro preserves the hyperbola; multi-bond fan-out pays the true marginal sum (F-A: ≥ 4 bonds to plateau) | ✅ by construction |
| W2 | Sub-micro truncation harvesting | Error ≤ 4,096 micro/bond ≈ 0.026% plateau (F-B) | ✅ (bounded) |
| W3 | Per-shard/total scale split weakening `WorkTotalMismatch` | Single floor-site shared by close + verify; aggregate compare in micro-space (F-E) | ✅ landed (Stage 1) — `work_milli_from_micro` is the sole floor; `emission_verify` compares `entry_sum` vs `work_micro_p` pre-floor |
| W4 | Old-format (milli) entries valid under new rules | Zero-tolerance recompute rejects; `-v2` separator adds belt (F-E) | ✅ landed (Stage 1) — recompute + `-v2` belt (auth customizations bumped; `EMISSION_AUTH_MSG_V1` regenerated) |
| W5 | Stacked stake-responsive multipliers on `staker_pool_amount` | Delete `stake_factor` (F-D) | ✅ landed (Stage 1b, `7256962`) — `stake_factor` + the `stake_ratio` parameter deleted through Rust + FFI + C++; burn rate is now `activity × supply` |
| W6 | Distributional dilution: D1 fix moves ex-zero archivers into `Σwork`, shrinking scarce-holders' shares of fixed budget | Stage-2 sim models the shift, not just aggregate lift | ⏳ sim-arm scope |
| W7 | Cached `frozen_segment_count` drift at the D2 read-point | Pinned read through frontier-check (M1 §11.8 M3-1) | ✅ carried |
| W8 | **Fast-swing** manipulation of the staker share (pump-and-dump, whale dive, reflexive feedback) | The operand is monotone + slow + predictable (§6.0) and the function is a pure map of `n` with no controller (§6.1) — pump/dump/whale have **no lever** on a monotone chain-state operand; the only lever is the durable one (W9) | ✅ by operand (fast-swing has no lever) |
| W9 | **Durable output-stuffing** — mint outputs to inflate leaf count → segment-freeze rate → `n` → share, permanently (the ratchet cuts both ways, §6.2). Not covered by `DESIGN_CONCEPTS.md` §6, which keys the stuffer's cost to `tx_volume` (a tx count) via the sqrt damper, which does not escalate against output count. **Live precedent**: Monero's suspected March-2024 output-flood; Bitcoin's 2015 dust floods (§11.3) | Burden-coupling: the operand *is* the funded quantity, so a stuffer raises the share and the real cost (a permanent ~3.33 MB shard held forever) in the coupled ratio — "manipulating an honest measure of the funded quantity mostly funds the quantity"; only weight-fees escalate against outputs | 🔴 **FAILS** (Stage 2, A4 cp4b/cp4c). Served-work ROI is 2.8×–17.8× at the rational honest equilibrium (§12.5): the coupled bond burden is real but ~1% of cost, and the weight-fee at the `300`/byte floor is cheap against the Δpool a flood unlocks. Diagnosis: **pure fee-flow-volume leverage** (first-mover premium ≈ 1.0 — *not* a concentration attack at the realistic end); the cross-regime `fee×→1` spread (2.8→17.8) is volume/share-slope, so a floor cannot be one number. Disposition: reopen (c) **FIRED** — weight-denominated per-output fee-floor + the **D3** capture-side companion (reopen (e)); **not** a D2 redesign (§8). |
| W10 | **Proxy free-riding on the on-demand-serving ruling** (§11.1) — a thin proxy re-fetches challenged data cheaply within the gate-4 grace window instead of holding it; D1 now *pays* that profile (was zero under truncation) and D2 escalates the pool it drains, re-pricing the §7.4 free-rider equilibrium that was closed under the old economics | Fetch-cost-vs-deadline margin must still bind (the §7.4/L14 judgment). If the Stage-2 arm shows it doesn't: tighten the gate-4 grace window or accelerate the PoRep reopen (the doc's own named economics-reopens) — **not** redesign D2 | 🔴 **FAILS** (Stage 2, A5 cp5a; §12.6). The margin is negative at the current grace: the challenge is a cheap ~3 KB opening (GATE2 §0–3: *fetch-on-demand IS service*), re-fetchable for ≪ the cost of holding 13.6 GB. Disposition (§8 reopen (d), **FIRED**): tighten gate-4 grace to force `q ≥ q* ≈ 0.085–0.26`, or accelerate PoRep (`q→1`) — **not** a D2 redesign. |

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

---

## 12. Stage 2 — the sim arm (design, ratified)

Stage 1/1b landed (`699876d89` / `725696210`); the work model is now honest and
sim/production burn parity holds. Stage 2 is the **evidence** D2's escalation
shape is ratified against. Before building six sim arms, this section pins their
structure, their pass/fail criteria, and the calibration decisions — the same
design-round-first discipline that made Stage 0 → 1 clean. Nothing here touches
consensus code; the output is a recommendation Stage 3 freezes.

**✅ Ratified** (review round, DQ-2A..2H). Folded that round: **N-1** — the
`reward_P` (SKL) vs `burden_cost` (fiat) units mismatch → an explicit exogenous
`SKL/fiat` price parameter, swept like Kryder, with the trend-vs-absolute honesty
corollary (DQ-2A); **N-2** — A4's gate is **attacker ROI < 1** (not
`Δshare/Δburden`) and A5's margin is **named** (§12.2); **DQ-2C resolved with
data** (the Rucknium March-2024 report, not a fallback); **DQ-2H** gains a
heavy-tailed variant + per-class-margin reporting + a rule-21 exit-dynamics
reopen. Build is **authorized against this section — `shekyl-economics-sim` only**
(DQ-2F boundary).

### 12.0 What Stage 2 decides, and the Stage-2 → Stage-3 boundary

**Stage 2 measures; Stage 3 freezes.** Stage 2 answers *"does a 25%-floor +
shard-indexed lift, drawn from a decaying budget, clear the archival burden — and
if so, in which regimes and under which storage-cost assumption?"* Its output is
a **recommended (shape, asymptote) envelope** over the §6.1-conformant family,
plus the wargame verdicts (W6/W9/W10). Stage 3 picks the number from the
survivors under the §11.4 ceremony and implements it in `compute_burn_split`.
Stage 2 does **not** pin the asymptote number, and does **not** write consensus
code — if it writes any Rust, it is `shekyl-economics-sim` only.

**Why the sequence is forced (already argued §5):** D1 corrupted the exact
denominator the burden model measures against, and 1b removed the stake-keyed
burn multiplier that would have double-counted. Both landed, so the sim now runs
on the shipping formulas — evidence validity, not convenience.

### 12.1 What the harness already has, and what is new

Grounded in `shekyl-economics-sim`:

- **Funding side — exists.** `budget.rs` already models `budget(E) =
  emission_leg + fee_leg` per the `blockchain.cpp:6081` accrual: the emission leg
  decays at `staker_emission_decay = 0.90/yr` off a `staker_emission_share = 15%`
  base (release-modulated, floored at `release_min = 0.8×`), and the fee leg is
  `compute_burn_split(...).staker_pool_amount` at the frozen `staker_pool_share =
  25%`. Scenarios 1–8 (`scenarios.rs`) drive it; the F-B1c-c2 disposition-(a/b)
  swing machinery is reusable.
- **Burden side — new, the bulk of Stage 2.** The harness has **no** shard-count
  trajectory and **no** storage-cost model. New: `frozen_segment_count(E)` driven
  by each scenario's output volume (`SEGMENT_LEAF_COUNT = 25,992` outputs/shard,
  ~3.33 MB, §2), a storage-cost curve with the Kryder parameter (DQ-2B), and a
  per-archiver reward/cost model (DQ-2H) so W6 and stranding are expressible.
- **Escalation family — new.** A §6.1-conformant candidate generator (banded-PL,
  floor 25%, monotone in `n`, asymptote `A`), evaluated in the integer
  `curve_milli` form so the recommended shape is bit-implementable (DQ-2G).

### 12.2 The arms and their criteria

| Arm | Question | Metric | Pass / report criterion (DQ-2E) |
| --- | --- | --- | --- |
| **A1 burden clearance** | Does the escalated pool keep the staker's reward above the cost of their **growing locked-bond capital** through the fee era? (F-G: storage alone is trivially met) | `budget_skl(candidate)` vs `opp_cost_skl(n, rate) + storage/price`, over the trajectory, ∀ opp-cost rate in the band | **Report** the (rate, shape, scenario) region where `budget ≥ burden` sustained; a shape "clears" iff it holds under the **binding 10%/yr** rate (and 0%/yr Kryder for the minor storage term). The dominant term is price-independent |
| **A2 distributional shift (W6)** | The D1 fix moves ex-zero bulk holders into `Σwork`, diluting scarce-holders' shares of a fixed budget | Scarce-holder share pre- vs post-D1 across the archiver distribution | **Descriptive** — quantify the redistribution; **flag** if it strands scarce holders below their marginal cost |
| **A3 stranding** | What fraction of diverted budget goes unminted? | Σ unclaimed `reward_P` past `MAX_CLAIM_AGE_W = 26` epochs ÷ Σ budget | **Report** the stranded fraction; joint with A1 (stranded budget is not burden-clearing) |
| **A4 output-stuffing (W9)** | Does stuffing pay the attacker — is there an early-chain regime where their manipulation profits? | **attacker ROI** = marginal captured revenue (their **served-work first-mover slice** of the Δpool over the horizon) ÷ marginal cost (weight-fees + the coupled bond). ⚠️ **Retraction (§12.5):** the ratified D-2 wording "*stake-fraction* of the Δpool" was wrong at source — the staker pool distributes by **capped served work per bond** (`reward_share_floor`), *not* by stake; the capture term was written without re-walking the disbursement path. The correction makes the attack **stronger** (r=1 first-mover work-capture is a sharper lever than any stake fraction). On `scenario_4`(output-variant) × `scenario_7`(bootstrap); `Δshare/Δburden` reported as a coherence **diagnostic** | **Pass** iff attacker **ROI < 1** everywhere in the sweep — the executable form of "stuffing it funds it" (§6.2); calibrated to the March-2024 profile (DQ-2C). **Result: FAILS (§12.5)** → the §11.3 rule-21 per-output fee-floor reopen (c, FIRED) + the D3 companion (reopen e), **not** a D2 redesign |
| **A5 proxy free-riding (W10)** | Does the §7.4 fetch-cost-vs-deadline margin still bind after D1 restores bulk pay and D2 escalates the pool? | **margin** = expected proxy cost/epoch − honest storage cost/epoch, where proxy cost includes within-grace re-fetch feasibility (gate-4 window) **and** the L14 challenge-failure exposure; against the **post-D1/D2** reward on ~13.6 GB held | **Pass** iff margin `> 0` (§7.4: "if re-fetch is cheap, the challenge *is* the free-rider equilibrium"). Fail → tighten gate-4 grace or accelerate PoRep reopen (§11.1), **not** a D2 redesign |
| **A6 swing / band width (§6.0)** | Is the lift a wide-but-slow band, not a cliff? | `d(share)/d(n)` across the sweep | **Report** the rate; **flag** any cliff (bounded-slope is the §6.1 requirement) |

**Scenario 9 (new, §11.2):** high-history / low-activity — large `n`, low current
volume, the post-boom settled chain none of scenarios 1–8 cover (`scenario_8` is
high-history but *busy*, 180–300 tx/block vs 50 baseline). This is the quadrant
where a 25%-floor-plus-escalation either saves the archival layer or demonstrably
cannot; A1 runs on it as the binding case.

### 12.3 Design questions (recommended dispositions; ratify or correct)

- **DQ-2A — burden cost model + "clears". ⚠ REFINED by a Stage-2 finding (F-G,
  ratified) — see below; the original storage-dominant form is retained as a
  minor term.** *Original:* `burden_cost(E) = n(E) · shard_bytes ·
  storage_fiat_per_byte(E)` (Kryder-declining), serve-bandwidth a secondary
  sensitivity. "Clears" = the pool's reward `≥` the burden, sustained.
  - **F-G (Stage-2 A1 finding, ratified) — storage is *not* the binding
    constraint; the locked-bond opportunity cost is.** Building A1 showed
    storage-cost clearance is met by **4–6 orders of magnitude even for flat-25**
    (whole-network storage ≈ `$2/yr` at 10k shards; the budget's emission leg
    alone is millions of SKL/yr for a decade). So D2 is **not** justified by
    storage clearance. The binding staker cost is the **opportunity cost of
    locked bond capital**: `locked_skl(n) = bond_floor (0.75 SKL) · R (6) · n`,
    at an exogenous rate. It grows `∝ n` like storage but is **~100× larger**,
    and **crosses the flat-25 fee leg around `n ≈ 50–110k` shards** — exactly
    where escalation earns its keep (the mechanism gap the D2 premise names,
    made quantitative). **Reshape:** `burden = bond_opp_cost + storage +
    serving`, bond-opp-cost-**dominant**; storage/serving retained as minor
    terms. A1 "clears" iff `budget_skl(candidate) ≥ opp_cost_skl(n, rate) +
    storage_fiat/price`, sustained, under the binding rate.
  - **Opportunity-cost rate band (new exogenous, ratified):** sweep
    `{2%, 5%, 10%}/yr` — risk-free / moderate-alt / high; **10% is the binding
    case** (highest bar for staking to clear). Reported conditional on the rate,
    like Kryder.
  - **The binding clearance is price-independent** (a robustness bonus): reward
    and bond-opp-cost are both SKL (`budget_skl ≥ locked_skl · rate`), so the
    N-1 `SKL/fiat` price **cancels** in the dominant term — it survives only in
    the minor storage term. So the A1 verdict is robust to the least-knowable
    price; the price band still sweeps the storage remainder.
  - **N-1 fix — the exchange unit is exogenous, and must be named.** `reward_P` is
    atomic **SKL**; the *storage* term is **fiat** (Kryder is a fiat `$/byte`
    decline). They are not commensurable without an exchange assumption, and
    burying one is exactly the silent-embed the Kryder parameter exists to
    prevent. So the sim carries an **explicit exogenous `SKL/fiat` (price)
    parameter, constant per run, swept like Kryder**, and the report flags it as
    a **least-knowable input**. This is also where the **Filecoin
    provider-exodus face** lives — token price collapsing against fiat hardware
    costs — correctly modeled as a *swept exogenous parameter*, not a dynamic.
    **Honesty corollary, stated in the report:** the robust outputs are the
    **trend comparisons** (burden growth vs budget decay, regime boundaries,
    which shapes dominate which); **absolute clearance is conditional on the
    exogenous bands** and is reported as such, never as a point claim.
  - **N-1 fix — the exchange unit is exogenous, and must be named.** `reward_P` is
    atomic **SKL**; `burden_cost` is **fiat** (Kryder is a fiat `$/byte` decline).
    They are not commensurable without an exchange assumption, and burying one is
    exactly the silent-embed the Kryder parameter exists to prevent. So the sim
    carries an **explicit exogenous `SKL/fiat` (price) parameter, constant per
    run, swept like Kryder**, and the report flags it as the **least-knowable
    input**. This is also where the **Filecoin provider-exodus face** lives —
    token price collapsing against fiat hardware costs — correctly modeled as a
    *swept exogenous parameter*, not a dynamic. **Honesty corollary, stated in the
    report:** the robust outputs are the **trend comparisons** (burden growth vs
    budget decay, regime boundaries, which shapes dominate which); **absolute
    clearance is conditional on the price band** and is reported as such, never as
    a point claim.
- **DQ-2B — Kryder band. ✅ ratified.** Sweep **{0%/yr flat, 10%/yr, 25%/yr}** —
  0% is the **binding** clearance case. **Provenance (state in the report, not bare
  numbers):** ~25%/yr is the long-run historical `$/GB` decline, ~10%/yr the
  post-2010s slowdown, 0% the Kryder-stall / Arweave failure face. The conclusion
  must *state* which band members it holds under, never embed one (§11.2). This is
  the single most assumption-laden input **after** the DQ-2A price parameter.
- **DQ-2C — March-2024 W9 calibration. ✅ RESOLVED with data.** Source:
  Rucknium, *Monero Black Marble Flood* (`github.com/Rucknium/misc-research`,
  `Monero-Black-Marble-Flood/pdf/monero-black-marble-flood.pdf`, §6). Vendor these
  figures + the derivation into the sim's calibration module with the source
  pinned:

  | Quantity | Value (report §6) |
  | --- | --- |
  | Duration | **23 days** (Mar 4–27, 2024) — weeks-sustained, not a burst |
  | Spam shape | **1-in / 2-out** at the **minimum fee tier** (20 nanoneros/byte) |
  | Total spam fees | **61.5 XMR** (81.3 under the wider 20-or-320 definition) |
  | Total spam bytes | **3.08 GB** (3.12 wider) |

  Internal check: 20 nanoneros/byte × 3.08 GB ≈ 61.6 XMR ✓. Derived: ~1.9 kB per
  1in/2out tx → ≈1.6 M txs → ≈3.2 M outputs → ≈1.9×10⁻⁵ XMR ≈ **a quarter-cent per
  output**; total attacker spend ≈ **\$8–11k** for a **~6× sustained flood**
  (15–25k → 115–140k tx/day). **Three calibration directives the report itself
  dictates:**
  1. **Fee floor, not average.** The stuffer pays the minimum fee tier and sustains
     — so A4 sweeps the Shekyl stuffer at the **minimum weight-fee**, not average
     fees.
  2. **Incident is an *upper bound* on cost-per-output.** The report notes an
     adversary would use a **2-in / 16-out** shape to maximize black-marble outputs
     per byte; the incident's 1in/2out is therefore not the cheapest. The
     **Shekyl-binding case is the output-maximizing tx shape at `TX_WEIGHT_LIMIT`**,
     strictly cheaper per output than the incident paid.
  3. **Duration prior: weeks-sustained.** Model the flood as multi-week, not a
     single-block burst.

  Shekyl's fee schedule differs, so calibrate to a **point + range**: the derived
  per-output cost is the anchor, the parameterized sweep is a band around it.

  **Scope guardrail — the *cost* half only; the ring model does not transfer.** The
  Black-Marble report has two separable halves. Its **privacy-damage** half
  (decoy poisoning, effective-ring-size collapse, the OSPEAD-adjacent
  decoy-distribution attack) is a **ring-signature artifact FCMP++ eliminates** —
  no ring, nothing to poison — and is **out of scope**: the W9 sim must not model
  it. Only its **incident-forensics** half (how cheaply, at what fee tier, for how
  long a real adversary sustains a mass-output flood) is used, and that is
  anonymity-scheme-independent. Consequently the calibration module **must
  re-derive the per-output cost from Shekyl's own `predict_weight`** over the
  FCMP++ tx layout — the expensive per-input object is a curve-tree membership
  proof, not a 16-decoy ring, so the outputs-per-byte optimum (directive 2) and
  the per-output cost differ from Monero's. The Monero figures are an
  **order-of-magnitude anchor + proof-of-willingness**, never a number to
  hard-code; no ring-sig byte economics enter the sim.
  - **A4 build pins (ratified round D-1..D-5):** the cost is single-sourced
    through the production **`predict_size_and_weight`** (a byte-mirror of
    `Transaction::write`) for a **1-in / 16-out** stuffer — a tx *shape* (1
    input minimises the per-input FCMP membership proof; 16 = `MAX_OUTPUTS` =
    `2^4`, zero BP+ padding, maximises leaves/tx), **not** a black-marble/decoy
    construct (FCMP++ has no rings; the leaves inflate `frozen_segment_count`,
    they do not poison a decoy pool). Fee floor `FEE_PER_BYTE = 300` atomic
    (genesis-provisional); net cost carries the fee-rebate term. Revenue is
    attacker-favouring (r=1 first-mover capture, undiscounted `H ∈ {1,5,10}`,
    high `w_a`); gate is **attacker ROI < 1** everywhere.
  - **F-H (Stage-2 finding, verified at source) — the coinbase channel is
    fee-free leaves; needs a consensus cap.** Coinbase outputs are curve-tree
    leaves that count toward `frozen_segment_count` **and pay no fee**, so the
    fee-path cost model prices only one of two stuffing channels. Verified: the
    miner-tx validation path (`prevalidate_miner_transaction`,
    `validate_miner_transaction`, blockchain.cpp:1594/1634) checks overflow,
    output type, key validity, commitment mask, and decomposed amount — **no
    output-*count* bound** on a foreign coinbase (the honest template pins
    `max_outs = 1`, but that binds only the builder). **Disposition:** add a
    consensus coinbase output-count cap in `prevalidate_miner_transaction` — a
    pre-genesis genesis-freeze item (Stage-3-adjacent), the cheapest
    unrepresentable-state fix. It **forecloses the miner channel, so A4 stays
    fee-path-only** (no miner-stuffer arm). **Principle (pinned now, value at
    implementation):** the bound is decided on **consensus grounds; the test
    harness conforms to it, never the reverse** — `chaingen`/`block_reward`
    building multi-out coinbases is inherited Monero scaffolding and gets fixed
    to match, the cap is not inflated to spare test churn. **Recommended cap =
    1** on the merits: the staker pool accrues **off-coinbase**
    (`blockchain.cpp:6081` accrual), the template has only ever built 1, and a
    uniform coinbase shape is the privacy-consistent choice. **Rule-21 reopen —
    sole legitimate trigger:** a consensus consumer that *structurally* requires
    a multi-output coinbase, reviewed as its own design round.
- **DQ-2D — escalation-family parameterization. ✅ ratified.** Banded-PL, floor
  25%, monotone in `n`, saturating to asymptote `A ∈ {50%, 75%, 90%}` (all `<
  100%`), swept over knee position `n_k` and initial slope. Integer `curve_milli`
  form. Stage 3 picks from survivors; Stage 2 never emits a single "answer" curve,
  only the envelope.
- **DQ-2E — per-arm criteria. ✅ ratified** (with the N-2 rewording folded into
  §12.2): A1 binds on **0%/yr Kryder**; A4's gate is **attacker ROI < 1** (with
  `Δshare/Δburden` demoted to a reported diagnostic); A5's margin is **named**
  (proxy cost/epoch − honest storage cost/epoch, incl. within-grace re-fetch + the
  L14 exposure).
- **DQ-2F — Stage-2 → 3 boundary. ✅ ratified.** §12.0. Stage 2 recommends; Stage 3
  freezes the number under §11.4 ceremony and writes consensus.
- **DQ-2G — the integer-seam rule (STRENGTHENED from preference to rule).** This
  is the D1 lesson pointed the other way: D1 was integer arithmetic diverging
  from the intended math; a float mid-`budget→share→reward→clearance` is **sim
  math diverging from the integer arithmetic that ships** — "the margin you
  proved is not the margin you deployed." The rule, in the form the sim enforces:
  - **Three zones, one conversion each way.** Float lives only in the **scenario
    layer** (demand trajectories, Kryder decline, `SKL/fiat` price, opp-cost
    rate, population weights, horizon-in-years) and the **report layer**
    (clearance ratios, margins, tables). Everything between — every quantity that
    mirrors something Shekyl computes or will compute — runs in the **same
    integer arithmetic as production**; floats cross in **exactly once**, at a
    named input boundary (a volume curve → integer tx count/epoch; a Kryder curve
    → integer cost/byte/epoch), never mid-chain.
  - **Strongest form — dep, don't mirror.** Where a production implementation
    exists, the sim **depends on it** rather than re-expressing it: burn
    (`calc_burn_pct_from_activity`/`compute_burn_split`, parity secured by the
    Stage-1b delete), tx weights (`shekyl-tx-weight`, hoisted D-1), the
    escalation candidates (`curve_milli`-exact family), and — **required for
    A2/A3** — the work/scarcity/curve arithmetic (`scarcity_micro`,
    `work_milli_from_micro`, `curve_milli`, the plateau caps in
    `shekyl-archival-retention`): the sim deps that crate and calls those
    functions for the distributional and stranding arms, not a re-expression. We
    made that arithmetic honest at micro precision in Stage 1; A2's redistribution
    verdict is computed by the exact functions whose behaviour it predicts.
  - **Compiler-enforced, not conventional.** The sim's core-loop functions take
    and return the **integer types** (atomic `u64`/`u128`, milli/micro); scenario
    structs hold the `f64` parameters; the conversion lives at the named
    boundary. A float cannot drift into the algorithm zone if the signatures
    won't accept one — the unrepresentable-state pattern applied to the sim, which
    is fitting since it is about to become evidence a genesis freeze cites.
  - **Retro-audit (done):** A1's algorithm zone had two f64 seams — the
    emission/burn legs summed in `f64` SKL, and the escalation share applied as
    `total_burn_skl × share_fraction` instead of the integer
    `mul_scale(whole_burn_atomic, share_milli)` production runs. Re-run through the
    integer path (`u128` accumulation; `mul_scale` share; f64 only at the reported
    ratio and the rate/price boundaries): **the verdict held exactly** — scenario 9
    flat-25 `0.66×`, escalation `2.36×`. The margin was wide enough the seam
    didn't flip it, but "wide enough" is the phrase this rule exists to eliminate.
- **DQ-2H — archiver population model (needed for W6 + stranding). ✅ ratified,
  two amendments.** A parameterized distribution anchored to the GF-7 measured
  floor `N ≈ 10/20` (M1 §4 founder schedule); W6 *is* the redistribution across it,
  so its shape is a first-class input.
  1. **Add a heavy-tailed (Pareto-ish) variant** alongside the bulk-vs-scarce
     binary — real archiver populations are Pareto-ish, and W6's redistribution
     verdict can differ *qualitatively* between a two-class and a heavy-tailed
     population. `N ≈ 10/20` sets the scale for both.
  2. **Static population, but A1/A2 report per-class margin** — which archiver
     classes sit underwater, and when — not only aggregates. A **dynamic exit
     model is a named non-goal** (scope creep) with a **rule-21 reopen:** if any
     class is *persistently* below marginal cost **inside the recommended
     envelope**, the exit-dynamics arm gets built **before Stage 3 freezes**.

### 12.4 Output artifact

A sim report (render in `main.rs` per the debug-macro CI gate,
[`fb1c-c2` precedent]) carrying: the A1 clearance region as a (Kryder × shape ×
scenario) table; the A2 redistribution and A3 stranding fractions; the A4/A5
pass/fail with their margins; the A6 rate-of-change curve; and the **recommended
(shape, asymptote) envelope** — the survivors that clear under the pessimistic
Kryder floor without failing W9/W10 — that Stage 3 ratifies. Where an arm cannot
clear, it names the disposition its own §11 caution already fixed (rule-21
per-output fee-floor for W9; gate-4/PoRep for W10), never a D2 redesign.

Registration: the Stage-2 sim build gets an `IMPLEMENTATION_INDEX.md` row at
birth (rule 94); this design round does not (it lives in this doc).

### 12.5 A4 (W9) result — the escalation fails the stuffing gate; reopen (c) FIRED

**Built:** cp4a (`11452248f`, leaf-stuffer cost via the production `predict_weight`
hoist, D-1), cp4b (`d4026efe3`, served-work ROI + the DQ-2H population), cp4c
(decomposition + replication-response). `shekyl-economics-sim --stage2`.

**Channel correction (the D-2 retraction, §12.2).** The D2 `staker_pool` is the
*archival* reward pool: `epoch_close_compute` distributes it by **capped served
work per bond** (`reward_share_floor(pool, my_capped_work, Σwork)`), not by stake.
The attacker captures the raised pool only by **archiving** the shards it stuffs —
the §6.2 coupling, which a stake-capture model deletes. The first model cut used
free stake capture (a phantom) and was corrected at source; the served-work model
is the honest gate, and the correction makes the attack *stronger* (r=1 first-mover
work-capture beats any stake fraction).

**Metric — the manipulation premium, not the whole capture.** W9 asks whether
gaming the escalation share *adds* profit, not whether archiving pays (that is A1).
Revenue is the attacker's served-work slice of the **Δpool the share increase
creates** × horizon; **flat-25 reads exactly 0** (no share lever), so the premium
is purely the escalation's.

**Verdict: FAILS.** At the rational honest equilibrium (small bonds, `hHold=4`) the
served-work ROI is **2.8× (baseline) → 17.8× (late-tail)** after the coupled bond.
Decomposition (cp4c):

- **First-mover premium ≈ 1.0** at the realistic end — *no* concentration premium;
  capture is exactly proportional (the r-independence invariant). The attack is
  **pure fee-flow-volume leverage**: cheap stuffing unlocks a large Δpool, and the
  attacker's proportional slice of it dwarfs the stuffing cost.
- **Cost is ~99% fees** (the coupled bond is real but ~1%). The weight-fee at the
  `FEE_PER_BYTE=300` floor is the whole lever, and it is too cheap.
- **`fee×→1` spans 2.8→17.8** across regimes. The fee-*rate* cancels in that ratio,
  so the spread is volume/share-slope variation — a single per-output floor sized
  for late-tail over-charges benign multi-output txs ~6× (the remedy's real cost).
- **Replication response** (r:1→R after a 2 y lag; first-order, *not* gating) cuts
  ROI ~3×: baseline → 0.93 (passes), late-tail → 5.9× (**fails robustly**, not only
  under the r=1-forever assumption).

**Disposition (both pre-committed; no D2 redesign).**
1. **Reopen (c) FIRED** — a **weight-denominated** per-output fee-floor (a virtual-
   weight surcharge that rides the fee market and flows through the existing
   weight/fee/burn machinery with zero new consensus fields; the D-1 predictor
   hoist now serves both consensus-adjacent code and the sim). Promoted to a
   Stage-3 hard input. An atomic-unit constant is rejected (the Bitcoin-dust-limit
   mistake — right idea, wrong denomination, rots within years).
2. **Reopen (e) — D3** (new): the per-bond `curve_milli` cap is dodgeable at no
   bond cost (bond floor is per-shard), so it is **load-bearing for W9** — it ~2×
   the stuffer's ROI at the capped-honest end (`hHold=512`). Its own defect / design
   round (per-persona cap, per-bond floors, or bond-proportional plateaus). Filed
   `FOLLOWUPS.md`. The pair — fee-floor (fee-flow regime) + D3 (concentration
   regime) — each closes what the other cannot.

**Freeze note:** the FAIL stands at the binding case, the correct pre-genesis
standard. The `ROI(resp)` row is reported so Stage 3 sees how much is "market never
responds" — but a freeze decision cannot *rely* on market-response speed.

### 12.6 A5 (W10) result — the proxy free-rides; reopen (d) FIRED

**Built:** cp5a (`49cf160e9`, `shekyl-economics-sim::proxy`). This is the
**reopen-trigger** arm, and it is deliberately **GATE2-conformant** — it models
the cheap opening the genesis spec chose, not the whole-shard challenge.

**Scope (why it does not model actual possession).** GATE2 §0–3: the serve-
challenge is a `VerifyPath` **opening** (128-B leaf + a *shallow* segment
co-path), and *"fetch-on-demand at test time **is** providing the service"* —
serve-credit is *"not continuous storage"*, *"not claimed: continuous offline
possession."* §11.1: *"foundation owns durability; market owns reach"*, with
**PoRep a named non-genesis path**. So a proxy that holds nothing and re-fetches
the ~3 KB opening on demand passes **by design**. A5's job is not to forbid that
(that would deviate from GATE2, in the opposite direction) but to test whether
the §7.4 fetch-cost-vs-deadline **margin still binds** under the post-D1/D2
economics — a FAIL being the §11.1 trigger for the whole-shard/PoRep reopen.

**Corrected L14 exposure.** The slash is the ratified sliding-window **m-of-n**
(`ARCHIVAL_FAILURE_CONFIRMATION_PIN`, `m=11`/`n=13` provisional) — a single missed
re-fetch is **absorbed**. An earlier draft modelled single-strike; the correction
*weakens* the deterrent (only sustained failure slashes), so the free-rider is
**more** viable, and every `q*` below is a floor. (Aside: that pin is itself
**unbuilt in consensus** — filed `FOLLOWUPS.md`, a separate pre-genesis gap.)

**Verdict: FAILS.** `margin/epoch = proxy(re-fetch + P(m-of-n slash)·loss) −
honest storage`; pass iff `> 0`.

- Honest storage ≈ **$0.0052/epoch** (hold `MAX_HOLDINGS_SHARDS · SHARD_BYTES` ≈
  13.6 GB at `1e-11 $/B/yr`).
- Proxy re-fetch ≈ **$0.0001–0.0013/epoch** (4,096 openings × ~3 KB at
  `$0.01–0.10/GB`) — **4–40× cheaper**. So at the current grace window (`q≈0`,
  re-fetch reliable) `margin < 0`: honest holding is the *dearer* strategy.
- **Crossover `q*`** — the per-epoch re-fetch-failure rate gate-4 grace must
  force to flip the margin: **≈ 0.26** on bond exposure alone, **≈ 0.085** once
  the forgone post-D2 reward stream is folded in (the escalated reward is the one
  way D2 *helps* here — a bigger forfeit). The current hours-long grace gives
  `q≈0 ≪ q*`, so it does not bind.

**Disposition (§8 reopen (d), FIRED; not a D2 redesign).** Tighten the gate-4
grace window to force `q ≥ q*` (a far tighter response deadline), **or**
accelerate the **PoRep** reopen (`q→1`: sealed per-provider replicas, where
re-fetch cannot substitute for possession — the whole-shard/actual-possession
test). PoRep is the named non-genesis durability fork; A5's FAIL is the evidence
that promotes it from "if needed" to "triggered."
