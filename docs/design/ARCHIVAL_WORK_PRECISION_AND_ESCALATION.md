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

> **⚠️ Revised by §12.7 (A3, Stage 2) — D1's half of this claim is falsified.**
> The binding variable is the **replication ratio** `archivers × holdings / n`,
> **not** scale. The "bites at scale" reading silently assumed archivers grow
> *with* the corpus; under **bootstrap-heavy** population growth (population
> outrunning corpus) `r` crosses the co-holder cliff **from day one**, and pre-D1
> then strands **100 %** of the budget — in precisely the window that most needs
> archivers paid. D1 is therefore **not** latent-then-structural but
> **earliest-biting**, which *strengthens* its urgency classification rather than
> softening it. D2's half stands as written.

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

> **⚠️ Amended by §12.10 (A6, Stage 2) — "cannot be moved in a burst" is measured,
> and it is not quite true. Three layers, separated by what excludes each:**
>
> 1. **Reversal and oscillation: structurally excluded — unchanged, and this is
>    the property that actually matters here.** This section's scope is *swings*:
>    pump-and-dump, whale diving, reflexive feedback — manipulation that profits
>    from a **reversal**. The lever A6 found can only **accelerate the monotone
>    ratchet**: `+1.41` (penalty-free) to `+2.82` points/epoch at the block-weight
>    ceiling against `−0.10` at the *full* reorg bound, one-directional always. No reversal, no
>    oscillation, no whipsaw. **W8 stays armed by operand.**
> 2. **Acceleration: economically closed — and *conditionally*.** The slew is real
>    (a W9 flood buys `n` at the block-weight ceiling: ~2 714 shards/epoch
>    early-chain penalty-free — **`+1.41` pts/epoch**, or **`+2.82`** if the flooder
>    also compensates the miner-reward penalty to use the legal `2×` limit,
>    ~45 k SKL/epoch in fees) and it is closed by **price**, not by structure. The
>    measurement splits it into **two tiers with two different closers**:
>    - **penalty-free tier (`+1.41`)** — ~~closed by the **reopen-(c) per-output
>      fee-floor**, and **open until (c) lands**~~ **REOPENED AS ITS OWN ITEM
>      (2026-07-27): see §12.11.1.** Reopen (c) is closed with **no mechanism**
>      (§12.11), so this tier has **no fee-floor closer** — but it does not need
>      one, because it never depended on stuffing being *profitable*: an
>      unprofitable stuffer (or a grudge-donor) can still move `n`. The live
>      question is the **rate**, and the expected closer is **structural**:
>      `frozen_segment_count` is monotone non-decreasing, reversible only to reorg
>      depth, so there is **no oscillation to arbitrage** — only one-directional
>      drift the escalation is designed to track. "**One missing mechanism, two
>      failures**" is therefore **half-retired**: W9's profit gate is gone, and
>      this is the surviving half, to be discharged on its own terms.
>    - **legal-`2×` tier (`+2.82`)** — closed **already, independently of (c)**, by
>      the block-reward penalty: at `B = 2M` the production formula
>      (`get_block_reward`) pays the miner *exactly zero*, so the flooder must fund
>      ~**10.24 M SKL/epoch** of compensation — **114×** the fee cost. Doubling the
>      slew costs ~114× more, so the upper tier is not a live lever.
> 3. **Hardening with depth: improves unattended.** The slew ceiling **falls** as
>    the tree deepens (deeper tree ⇒ heavier FCMP proofs ⇒ fewer leaves per block),
>    so the operand becomes *harder* to move over time. Pinned in a test.
>
> **"Slow" therefore holds in the sense the section needs** — no burst can reverse
> or oscillate the operand — **but not in the absolute sense the original wording
> implies.** The honest statement: *monotone, bounded, depth-hardening, and priced.*

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
2. **Floor at the current 25%** (never below today's `staker_pool_share`) —
   and the floor being *today's* value is itself a frozen guarantee, not an
   accident of the current numbers (review N-2): at every `n` the escalated
   share is ≥ what the flat constant paid, the miner leg is structurally
   untouched (§12.11.1 Leg 1), and the delta comes only out of
   `actually_destroyed` — so the escalation **strictly improves** the archival
   input at every point rather than ever redistributing away from one.
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


> **§12.10 consequence (A6).** The **no-controller** constraint survives with a
> *shifted justification*. It was: smoothness inherited from an operand that
> cannot move. It is now: **the operand moves only monotonically, at a bounded and
> depth-falling slew, at a price that already does not pay** (2026-07-27: the
> clause originally read "*at a price the reopen-(c) fee floor makes
> unprofitable*"; (c) closed with **no mechanism**, §12.11 — stuffing is
> **negative-sum without any floor**, so this justification is *strengthened*,
> not weakened: the ratchet does not pay on its own economics) —
> and a rate-limiter would only slow a *paid, one-way ratchet that already does not
> pay*, while adding exactly the stateful machinery this section forbids. Same
> conclusion; honest premises.
>
> **§11.5a addendum (2026-07-29, `ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`) — a
> third and better grounding.** Both justifications above argue the operand
> cannot move fast enough to need damping. The stronger reason is that **it
> should not be steered at all**: the staking share is **governance by tacit
> vote** — stakers pull the economy toward staking, miners toward mining, and
> where it settles is the participants' answer, not a set-point a controller
> should correct toward. A rate-limiter would not merely be redundant
> machinery; it would **override the vote**. This is why the constraint
> survives every re-derivation of its premises: the premises were never load-
> bearing.
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
  per the sim. **Implemented:** the shape is not merely frozen on paper — it is
  built (Stage 3a) and wired live on the consensus path (Stage 3b), shipped
  genesis-neutral; §12.12 is the implementation record.
- **The asymptote re-pin is a freeze-decision, not a tuning (§11.4).** The
  escalation asymptote's *shape* is frozen but its *number* is provisional-until-
  testnet, and it is the one capture point in this design — no post-genesis
  governance can relitigate it, so the testnet re-pin is the last moment it can be
  captured, and stakeholder pressure runs one way (higher). Treat the re-pin with
  **GF-7-threshold ceremony**: the adversary-advantage argument is committed
  *before* the number, and the number is decision-anchored.
- **Reopen (d) runs PARALLEL to the shape freeze — with one named contingency on
  the *numeric* re-pin (ruled 2026-07-26).** The decomposition: **W9** attacks the
  **split itself**, so reopen (c) blocks anything touching `compute_burn_split` —
  no argument. **(Amended 2026-07-27: reopen (c) is CLOSED with no mechanism
  (§12.11), so it blocks nothing. W9 does not attack the split — the stuffer is
  negative-sum under no-exclusivity — and the §6.0 rate residual that outlived it
  is tracked at §12.11.1, which likewise does not touch `compute_burn_split`.)** **W10** attacks **what the split purchases**, and neither of its
  dispositions touches the share function's *form*: grace-tightening is a
  challenge-protocol change and PoRep is a proof-system change, so the **shape**
  (monotone · floor · asymptote-exists · banded-PL · no controller) freezes without
  waiting on (d).
  **The contingency — the PoRep branch reaches back into the numerics.** If the
  joint round takes PoRep, per-replica **sealing cost** is added to honest archival,
  which changes **A1's burden model**, which changes **which asymptote clears
  scenario 9** — the exact arithmetic the numeric pin reads. The already-ratified
  freeze posture absorbs this: *shape genesis-frozen now, numerics provisional to
  the testnet re-pin*. So: **if the joint round takes the PoRep branch, A1 re-runs
  with sealing costs BEFORE the asymptote number is pinned.** This belongs in the
  ceremony because the re-pin **is** the capture point, and an unpriced burden
  change is precisely what slips through a captured one.
- **Reopens to name in the frozen text:**
  - (a) redo the width and error-bound arithmetic (F-B/F-C) if
    `MAX_HOLDINGS_SHARDS` is ever raised;
  - (b) the `stake_factor` decision happens in **Stage 0**, not V3.1 — the
    `FOLLOWUPS.md:5255` item's own `> 10⁻³·SCALE` / V3.1 reopen is **superseded**
    by D2 touching this math pre-freeze;
  - (c) **a per-output fee-floor term** pricing the perpetual set-growth
    externality at output creation (§11.3) — out of this round's pinned scope
    (staker share only), **trigger:** the W9 sweep showing weight-fees alone do
    not clear cost-of-burden. **✅ CLOSED — NO MECHANISM (2026-07-27, §12.11).**
    The trigger fired on a **mismeasurement** and is retracted: A4 asked *"is
    stuffing profitable"*, but `ROI > 1` is the definition of a working archival
    incentive; the exploit question is excess return over honest archiving, and
    with **no exclusivity** in the shard market the stuffer funds `(1 − w_a)` of
    the lift for competitors who spent nothing — **negative-sum, anti-scaling**.
    There is no externality left for a floor to price, and a floor would have
    **taxed protective cover traffic** (§12.11 privacy axis). **No fee floor
    ships; Stage 3 loses this input.** Historical record of the FIRED reasoning
    follows. 🔴 ~~FIRED (Stage 2 · A4 · cp4b `d4026efe3`, cp4c).~~
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
    failure rate `q ≥ q*` (`q* ≈ 0.098–0.278` — the m-of-n slash crossover),
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
| W9 | **Durable output-stuffing** — mint outputs to inflate leaf count → segment-freeze rate → `n` → share, permanently (the ratchet cuts both ways, §6.2). Not covered by `DESIGN_CONCEPTS.md` §6, which keys the stuffer's cost to `tx_volume` (a tx count) via the sqrt damper, which does not escalate against output count. **Live precedent**: Monero's suspected March-2024 output-flood; Bitcoin's 2015 dust floods (§11.3) | Burden-coupling: the operand *is* the funded quantity, so a stuffer raises the share and the real cost (a permanent ~3.33 MB shard held forever) in the coupled ratio — "manipulating an honest measure of the funded quantity mostly funds the quantity"; only weight-fees escalate against outputs | 🔴 **FAILS** (Stage 2, A4 cp4b/cp4c). Served-work ROI is 2.8×–17.8× at the rational honest equilibrium (§12.5): the coupled bond burden is real but ~1% of cost, and the weight-fee at the `300`/byte floor is cheap against the Δpool a flood unlocks. Diagnosis: **pure fee-flow-volume leverage** (first-mover premium ≈ 1.0 — *not* a concentration attack at the realistic end); the cross-regime `fee×→1` spread (2.8→17.8) is volume/share-slope, so a floor cannot be one number. Disposition: ~~reopen (c) **FIRED** — weight-denominated per-output fee-floor~~ **RETRACTED 2026-07-27 → ✅ CLEARS (§12.11)**: the FAIL measured *profit*, not *theft*. Netted for the no-exclusivity subsidy the stuffer is **negative-sum** and the play **anti-scales**; reopen (c) is **CLOSED with NO MECHANISM**. The **D3** capture-side companion (reopen (e)) landed independently (§12.9.1, PR #371). |
| W10 | **Proxy free-riding on the on-demand-serving ruling** (§11.1) — a thin proxy re-fetches challenged data cheaply within the gate-4 grace window instead of holding it; D1 now *pays* that profile (was zero under truncation) and D2 escalates the pool it drains, re-pricing the §7.4 free-rider equilibrium that was closed under the old economics | Fetch-cost-vs-deadline margin must still bind (the §7.4/L14 judgment). If the Stage-2 arm shows it doesn't: tighten the gate-4 grace window or accelerate the PoRep reopen (the doc's own named economics-reopens) — **not** redesign D2 | 🔴 **FAILS** (Stage 2, A5 cp5a; §12.6). The margin is negative at the current grace: the challenge is a cheap ~3 KB opening (GATE2 §0–3: *fetch-on-demand IS service*), re-fetchable for ≪ the cost of holding 13.6 GB. Disposition (§8 reopen (d), **FIRED**): tighten gate-4 grace to force `q ≥ q* ≈ 0.098–0.278`, or accelerate PoRep (`q→1`) — **not** a D2 redesign. |

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

> **⚠️ CLOSED 2026-07-27 (§12.11) — the transfer is partial, and the half that
> does not transfer is the decisive one.** The March-2024 incident transfers its
> **cost profile** (the DQ-2C calibration, which remains valid) but **not** its
> **privacy mechanism**: Rucknium's black-marble attack poisons a *decoy ring*,
> and FCMP++ has no rings — whole-tree membership plus a single admissible output
> type (`CTTypeFcmpPlusPlusPqc`, enforced at
> `tx_verification_utils.cpp:124`) means a flood cannot re-partition the
> anonymity set. Under Shekyl a generic flood is **paid cover traffic**, so the
> fee floor contemplated here would have **taxed the protective traffic**. No
> mechanism ships.

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

> **⚠️ Amended (Stage-2 close) — "picks from the survivors" is false as written.**
> Stage 2's finding is that **no candidate survives unconditionally**: A4/W9 and
> A5/W10 both **FAIL** (§12.5, §12.6), so the recommended envelope is *conditional*
> on its named companions, not a survivor set. **Stage 3's entry condition, stated
> explicitly:** survivors exist **conditional on reopen (c) landed** (the
> weight-denominated per-output fee-floor — load-bearing twice, for W9's profit
> gate *and* §6.0's anti-swing property). **Stage 3 opens when that condition is
> discharged, not before.** Reopen (d) runs parallel to the *shape* freeze, with
> the PoRep contingency on the *numeric* re-pin (§8).
> **Lane structure:** the **D3 implementing round** (plateau deletion + admission
> predicate — the *reward path*) and the **(c) design round** (the fee floor — the
> *weight/fee model*) are **different consensus surfaces**, both under rule 26,
> **neither blocking the other**; Stage 3 waits on **both**.
>
> **⚠️ SUPERSEDED (2026-07-27, §12.11) — the (c) half of this entry condition is
> DISCHARGED BY CLOSURE, not by landing a mechanism.** W9's profit gate was a
> **mismeasurement**: A4 tested *"is stuffing profitable"* when the exploit
> question is *"is stuffing more profitable than honest archiving"*, and on the
> no-exclusivity accounting the stuffer is **negative-sum**. Reopen (c) is
> **CLOSED with NO MECHANISM**; there is no fee floor to wait for and **no (c)
> lane to run**. What survives is the *other* half of "load-bearing twice" —
> §6.0's anti-swing property, which never depended on stuffing being profitable
> and was the lone residual — **now also CLOSED with no mechanism (§12.11.1,
> 2026-07-27)**, on two legs: the *level* carries no harm to prevent (`n` is
> integer division of leaf count, so share can never mis-track burden; the
> ceiling is the sanctioned asymptote; and `staker_pool_share` cannot reach
> `miner_fee_income` at all), and *oscillation* — which would be real harm — is
> structurally impossible, since `revert_archival_segment_freezes` is the only
> writer that deletes segment rows and it fires only on block pop. **D3 is
> implemented** (§12.9.1, PR #371). **Stage 3 has NO outstanding hard inputs and
> opens now**; reopen (d) remains parallel to the *shape* freeze per §8.
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
| **A3 stranding** | What fraction of diverted budget goes unminted? | Σ unclaimed `reward_P` past `MAX_CLAIM_AGE_W = 26` epochs ÷ Σ budget | ✅ **REPORTED** (Stage 2, cp5b; §12.7). Pre-D1 strands **100%** past the co-holder cliff (an **early-chain** regime) — the §1 Stage-0 claim confirmed and stronger than stated; post-D1 ≈ 0 except a **residual**: D1 *scales* the cliff to `r > ~1000 × shards_held`, so small holders still zero at extreme replication. Joint with A1: stranded budget is not burden-clearing |
| **A4 output-stuffing (W9)** | Does stuffing pay the attacker — is there an early-chain regime where their manipulation profits? | **attacker ROI** = marginal captured revenue (their **served-work first-mover slice** of the Δpool over the horizon) ÷ marginal cost (weight-fees + the coupled bond). ⚠️ **Retraction (§12.5):** the ratified D-2 wording "*stake-fraction* of the Δpool" was wrong at source — the staker pool distributes by **capped served work per bond** (`reward_share_floor`), *not* by stake; the capture term was written without re-walking the disbursement path. The correction makes the attack **stronger** (r=1 first-mover work-capture is a sharper lever than any stake fraction). On `scenario_4`(output-variant) × `scenario_7`(bootstrap); `Δshare/Δburden` reported as a coherence **diagnostic** | **Pass** iff attacker **ROI < 1** everywhere in the sweep — the executable form of "stuffing it funds it" (§6.2); calibrated to the March-2024 profile (DQ-2C). ~~**Result: FAILS (§12.5)**~~ **→ RETRACTED 2026-07-27 (§12.11): the GATE ITSELF was wrong.** "ROI < 1" tests whether archiving *pays*, and it must — `ROI > 1` is the definition of a working archival incentive. The exploit question is **excess return over honest archiving**, on which the stuffer strictly loses (they pay to manufacture burden an honest archiver is handed free, then keep only `w_a` of the lift). Reopen (c) **CLOSED, no mechanism**; the D3 companion (reopen e) landed separately (§12.9.1). |
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

#### 12.4.1 Arm status — **FINAL synthesis, Stage 2 closed**

Every arm landed. Verdicts, with the numbers as re-measured at their corrected
models (each cell links its section).

| Arm | Verdict | Result |
| --- | --- | --- |
| **A1** clearance | ✅ **clears** | Escalation earns its keep in the far tail: scenario 9 flat-25 **0.66×** (fails) vs best candidate **2.36×** at the binding 10 % opportunity-cost rate, 0 %/yr Kryder. A non-event while emission dominates. |
| **A2** distribution (W6) | ✅ **clears** (§12.10) | Scarce-holder share `1.0000 → 0.9998` — **0.02 %** dilution, **zero** scarce holders stranded below marginal cost. |
| **A3** stranding | ✅ **reported** (§12.7) | Pre-D1 strands **100 %** past the co-holder cliff — the §1 coupling claim confirmed and *understated*. Post-D1 ≈ 0 outside the quantization corner. |
| **A4** stuffing (W9) | ~~🔴 FAILS~~ → ✅ **CLEARS (§12.11)** | **Verdict retracted 2026-07-27**: the arm measured *profit*, not *theft*; netted for the no-exclusivity subsidy the stuffer is **negative-sum** and the play **anti-scales**. Figures below are historical. Served-work ROI **2.8×–17.8×** at the rational equilibrium. Pure fee-flow-volume leverage (premium ≈ 1.0), cost ~99 % fees, `fee×→1` spread 2.8→17.8. Under R2, ROI **0.6671**, `fee×→1` **0.7** (§12.9 OQ-4). |
| **A5** proxy (W10) | 🔴 **FAILS** (§12.6) | Re-fetching a ~3 KB opening beats holding 13.6 GB by **4–40×**; crossover `q* ≈ 0.098–0.278`. |
| **A6** swing | ✅ **no cliff** / ⚠️ **slew priced** (§12.10) | Monotone, no discontinuity, down-swing ≤ **0.1014** pts. Adversarial slew ceiling **1.41 pts/epoch penalty-free** (~~closed **economically** by reopen (c)~~ — **(c) closed with no mechanism (§12.11); this tier CLOSED structurally at §12.11.1**) or **2.82 pts/epoch at the legal 2× limit** (~~already priced out by the block-reward penalty, ~10.24 M SKL/epoch, **114×** the fees~~ — **that is also a price argument and blind to a griefer; this tier closes on the same structural grounds, §12.11.1**). **Both tiers are now descriptive bounds on how fast the chain can be pushed toward a sanctioned state, not residual risk.** See the §6.0 amendment. |

**The through-line: one theorem, three independent confirmations.** A4's
`prem ≈ 1.0`, OQ-1's `|Δ| = 0` at the partition optimum, and A2's `0.02 %`
dilution are **the same total-work invariance** seen from three directions (a
shard's work is `r`-independent in total, so each replica carries `~1/r`). Read
them as one mechanism verified three ways, not three small numbers.

**The survivor envelope is CONDITIONAL — and that is Stage 2 succeeding.** Stage 2
was to hand Stage 3 the `(shape, asymptote)` survivors clearing A1 without failing
W9/W10. **Both wargame arms fail**, so no candidate survives on the escalation's
own terms: the escalation is **securable but not free**.

> **⚠️ Amended 2026-07-27 (§12.11): "both wargame arms fail" no longer holds.**
> **W9's FAIL is RETRACTED** — it measured *profit*, and profit is not theft. The
> exploit question is excess return over honest archiving, and on that question
> stuffing **strictly loses** (no exclusivity ⇒ the stuffer funds `(1 − w_a)` of
> the lift for competitors who spent nothing). Only **W10** still fails, so the
> envelope is conditional on **one** companion — reopen (d) — not two. The envelope is
conditional on its two companions, which Stage 3 inherits as **hard inputs, not
options**:

1. ~~**Reopen (c) — weight-denominated per-output fee-floor.** Now load-bearing
   **twice over**: it closes W9's profit gate (§12.5) *and* it is what closes
   §6.0's anti-swing property (§12.10 / §6.0 amendment). **One missing mechanism
   would be two failures.**~~ — **STRUCK 2026-07-27 (§12.11): reopen (c) is
   CLOSED with NO MECHANISM.** The W9 profit gate is **retracted** — `ROI > 1` is
   the definition of a working archival incentive, not a vulnerability, and
   netted for the no-exclusivity subsidy the stuffer is **negative-sum**. "Load-
   bearing twice" is therefore **half-retired**: only §6.0's anti-swing property
   survives, and it became its own item (**§12.11.1**) rather than a fee-floor
   dependency — **and that item is now CLOSED too**, structurally and with no
   mechanism. Stage 3 **loses this hard input entirely**.
2. **Reopen (d) — gate-4 grace tightening to `q ≥ q*`, or PoRep** (§12.6).
3. **D3 — resolved** (§12.9): plateau deleted, admission predicate, cadence
   monitored. Its outcome is *already folded into* the numbers above.

A synthesis that presented a clean survivor set would have been the
green-by-construction failure at report level; the conditionality **is** the
finding, bought for the price of a sim rather than a mainnet.

**Historical, not live — read with care.** The **`hHold` sweep column** in §12.5
is **retired**: it was evidence for the plateau, which R2 deletes, so it documents
*why the mechanism was removed* rather than a live regime. Likewise the
**pre-D1** columns throughout are counterfactual. Recomputing against either is
recomputing against a ghost.

**Method record (five catches, one discipline).** *Always-split* as "rational";
the **two-point partition proof** (proposed by the reviewer, falsified by
exhaustive check); A6's **invented pass/fail threshold**; the **un-propagated
measurement** (C-1 — corrected at its origin, stale at two of three consumers);
and the **mirrored mechanism** (below). Each was a claim promoted past its
verification, and each was caught by the same rule — *measure before recording,
regardless of which side of the review table the claim came from.* Carried into
Stage 3's freeze reviews: **"proven" means exhaustively checked or mechanically
derived**, and **a measurement is not landed until every consumer quotes it.**

**The unit's accidental controlled experiment — dep vs. mirror.** Every arm that
**depped production arithmetic** (`scarcity_micro`, `curve_milli`,
`predict_weight`, and now `failure_window_slashable`) either needed **no
correction** or now **re-prices itself automatically**. The one arm that
**mirrored a mechanism still in flight** (A5's hand-written binomial) was wrong
**within days** of that mechanism shipping (#368) — and wrong in the **semantics**,
not the values, which is precisely the failure a coefficient audit would never
catch. `dep-don't-mirror` (DQ-2G) was argued from drift *theory* at the D-1
hoist; this is its empirical confirmation, and the fix is **structural** rather
than corrective: the Round-2 re-pin will re-price the arm instead of silently
diverging from it.

### 12.5 A4 (W9) result — the escalation fails the stuffing gate; reopen (c) FIRED

> **⚠️ SUPERSEDED 2026-07-27 by §12.11 — verdict RETRACTED, measurements retained.**
> This section's numbers are sound; its **verdict is not**. It gates on
> `ROI < 1`, which asks whether archiving pays — and it must. The exploit
> question is *excess* return over honest archiving, and the stuffer pays to
> manufacture burden the honest archiver receives free while keeping only `w_a`
> of a lift they funded entirely. **Reopen (c) is CLOSED with NO MECHANISM.**
> Read what follows as the measurement record, **not** as a live disposition.

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

> **Post-merge correction (PR #368 shipped the window).** A5 first modelled the
> hazard as a plain binomial `P(≥ m of n)`. The **shipped predicate**
> (`failure_window_slashable`) is only consulted when the current epoch is itself
> a miss, so the true per-epoch hazard is `q · P(≥ m−1 of the other n−1)` —
> **~0.85×** the naive binomial across the whole crossover band. A5 therefore
> *overstated* the slash exposure by ~18 %; lower exposure means a **weaker**
> deterrent and a **more** viable free-rider, so the correction moves against the
> comfortable direction. The arm now **calls the shipped predicate** over the full
> 2¹³ sequence space rather than re-expressing it (DQ-2G), and `m`/`n` are deps on
> `FAILURE_WINDOW_M/N`, not local copies. Band: `q* ≈ 0.088–0.26 → 0.098–0.278`.
> **Verdict unchanged — W10 still FAILS.**

**Corrected L14 exposure.** The slash is the ratified sliding-window **m-of-n**
(`ARCHIVAL_FAILURE_CONFIRMATION_PIN`, `m=11`/`n=13` provisional) — a single missed
re-fetch is **absorbed**. An earlier draft modelled single-strike; the correction
*weakens* the deterrent (only sustained failure slashes), so the free-rider is
**more** viable, and every `q*` below is a floor. (Aside: that pin is itself
**unbuilt in consensus** — filed `FOLLOWUPS.md`, a separate pre-genesis gap.)

**Slash *scope* — per-shard, and the distinction a future reader must not
re-conflate.** For a **`ShardSetCompact`** record (the *market* archiver modelled
here) a failed challenge on shard `s` slashes ***shard `s`'s bond*; other shards
stay bonded**, post-slash holding *"still bonded on remaining shards"*
(`FOUNDATION_GENESIS_IDENTITY_SET.md` §3.2, per-shard bonds). Only the
foundation's **`CompleteTree`** kind takes the *whole* bond ("floor-or-whole").
The record-level bad interval `[E_slash, ∞)` is the **serve-credit** consequence
(it blocks `good_through` until `Rebond`) — **not** the collateral scope; the two
are separate. **This correction is aggregate-neutral for the margin**, and the
reason is scope-matching: the margin weighs a *full holding* proxied vs held, and
each of the `MAX_HOLDINGS_SHARDS` shards is challenged and slashed
**independently** (per-`(P, shard)` m-of-n windows), so the exposure sums as
`shards · P(m-of-n) · per_shard_loss` — algebraically the whole-holding bond ×
`P`. Pairing *one* shard's loss against a *whole* holding's storage saving would
understate the deterrent by `MAX_HOLDINGS_SHARDS`× (guarded by a test).

**Verdict: FAILS.** `margin/epoch = proxy(re-fetch + P(m-of-n slash)·loss) −
honest storage`; pass iff `> 0`.

- Honest storage ≈ **$0.0052/epoch** (hold `MAX_HOLDINGS_SHARDS · SHARD_BYTES` ≈
  13.6 GB at `1e-11 $/B/yr`).
- Proxy re-fetch ≈ **$0.0001–0.0013/epoch** (4,096 openings × ~3 KB at
  `$0.01–0.10/GB`) — **4–40× cheaper**. So at the current grace window (`q≈0`,
  re-fetch reliable) `margin < 0`: honest holding is the *dearer* strategy.
> **Aggregation FIXED, not labelled (the approximation is gone).** A slashed
> `(P, shard)` is an **absorbing state** — the open bad interval bars a second
> forfeiture of the same bond — so the earlier per-epoch-hazard **sum**
> double-counted and *overstated the deterrent*. That overstatement was
> direction-safe only at today's `(m, n)` and today's band, and this arm now
> **re-prices automatically** at the Round-2 re-pin: an aggregation-layer
> overstatement could silently flip a marginal verdict exactly where a well-tuned
> grace decision would land it (`q*` **is** a crossover). Shipping an arm that
> re-prices its hazard exactly while approximating its aggregation would be *half
> a fix wearing a whole fix's justification*, so the aggregation was made exact.
>
> The horizon sum is replaced by an **absorbing Markov chain** over the trailing
> `n−1 = 12` observations (4 096 states): each epoch the head misses with `q` and
> **absorbs** if the *production predicate* says slash, else shifts in. Loss is
> priced at the **actual first-slash epoch** (bond + the stream forgone from that
> epoch onward), not a horizon lump. **`dep-don't-mirror` is preserved rather than
> traded away**: the absorption condition is a 4 096-entry table built by *calling*
> `failure_window_slashable`. The 2¹³ enumeration survives as an independent
> **test oracle** — `dp_one_step_hazard_matches_enumeration` asserts the DP's
> stationary one-step hazard equals `q · P(≥ m−1 of n−1)`, two constructions
> guarding each other (the hoist-parity pattern).
>
> **Measured effect: `q* ≈ 0.098–0.278 → 0.098–0.278`** (+~10 %, proxy-favouring —
> first-slash-only is a smaller expected loss than the repeatable-slash sum).
> **Verdict unchanged: W10 still FAILS**; both branches of reopen (d) stand.
> *Scope: the sim's aggregation layer only — consensus, the predicate and #368 are
> untouched, and the free-rider verdict's remedies remain in reopen (d)'s lane.*

- **Crossover `q*`** — the per-epoch re-fetch-failure rate gate-4 grace must
  force to flip the margin: **≈ 0.278** on bond exposure alone, **≈ 0.098** once
  the forgone post-D2 reward stream is folded in (the escalated reward is the one
  way D2 *helps* here — a bigger forfeit). The current hours-long grace gives
  `q≈0 ≪ q*`, so it does not bind. (The per-shard scope correction left this band
  unchanged — see above; the residual `0.085 → 0.088` came from restricting the
  per-shard reward max to years with `n ≥ MAX_HOLDINGS_SHARDS`, so a small-`n`
  per-shard reward is never paired with 4,096 shards that do not yet exist.)

**Equilibrium — why the FAIL degrades reach, not the corpus, and what the grace
knob actually selects.** The scalar margin above is evaluated at `φ ≈ 0` (the
proxy fraction), which is the **proxy-favouring binding case**, so no `φ`-sweep is
needed for the verdict. But `q` is **endogenous in `φ`**: proxies re-fetch *from
honest holders*, so as `φ` rises the sources thin and `q` rises toward `q*`. The
all-proxy collapse is therefore **self-limiting** — the system settles at the
honest fraction `φ*` where `q(φ*) = q*`. Two consequences. First, per §11.1's own
scoping (*foundation owns durability*), a free-rider equilibrium degrades **reach**
(how many independent pseudonyms can serve), **not corpus survival** — that is the
honest severity reading of this FAIL. Second, grace-tightening acquires **target
semantics**: raising `q` at fixed `φ` moves `φ*` toward more honest holding, so the
Stage-3 decision is *not* "how flaky should re-fetch be" but **"which honest-serving
fraction do we want to pin"** — `q*` is the dial that selects it.

**Disposition (§8 reopen (d), FIRED; not a D2 redesign).** Tighten the gate-4
grace window to force `q ≥ q*` (a far tighter response deadline), **or**
accelerate the **PoRep** reopen (`q→1`: sealed per-provider replicas, where
re-fetch cannot substitute for possession — the whole-shard/actual-possession
test). PoRep is the named non-genesis durability fork; A5's FAIL is the evidence
that promotes it from "if needed" to "triggered."

**Coordination (joint tuning — do not pin `m`/`n` alone).** The gate-4 grace
window and the failure-confirmation `m`/`n` are **one design surface**:
`slash_prob(q, m, n)` is the shared function, so the `m`/`n` chosen for honest
transient false-slash (`ARCHIVAL_FAILURE_CONFIRMATION_PIN` Round-1 target ≈ 0.002)
*moves* `q*`. Pinning against either objective alone manufactures immediate
rework. Both belong in **one** round — false-slash ≤ target **and** `q*` reachable
at an implementable grace — with this arm's crossover surface as its input. If no
`(grace, m, n)` satisfies both, that infeasibility is itself the finding and it
promotes the **PoRep** branch over grace-tightening.

### 12.7 A3 (stranding) result — the §1 coupling claim confirmed, and stronger

**Built:** cp5b (`9a7071ead`, `shekyl-economics-sim::stranding`). Scored under
**both** work scorings, so the Stage-0 coupling claim is evidence, not assertion.
Post-D1 is **called** through the production chain (`scarcity_micro` →
`work_milli_from_micro` → `curve_milli` → `reward_share_floor`); the pre-D1
counterfactual is re-expressed and labelled as such, D1 having deleted it from
production (a *deleted* function's counterfactual is not a live mirror, DQ-2G).

**What strands.** `budget(E)` is a **minting entitlement**: unclaimed past
`MAX_CLAIM_AGE_W = 26` it is *"supply never created"* (`ARCHIVAL_BUDGET_SCHEDULE.md`
§4, ratified). Two channels are modelled — **structural-zero work** (nothing
claimable) and **rational non-claim** (reward below the cost of one claim
transaction, priced through the production weight predictor, not a guessed
constant).

**Finding 1 — the §1 claim holds, and understates.** §1 says D2-without-D1 *"would
enlarge a pool that **partly** evaporates."* Measured: wherever mean replication
crosses the co-holder cliff (`r_market > g_milli ≈ 1000`), pre-D1 strands
**100%** of the epoch's budget — *every* class floors to zero, so the whole
entitlement is supply-never-created. The coupling was real and the direction was
right; only the magnitude was understated.

**Finding 2 — the cliff is an *early-chain* regime.** Replication is *derived*
(`archivers · holdings / n`), not pinned, which is what exposed this: early on,
few shards exist and many archivers hold them, so `r ≫ 1000`. The defect
therefore bit hardest in exactly the **bootstrap window that most needs archivers
paid** — and a large archiver population re-enters the regime at any `n` (60 k
archivers still cross the cliff at `n = 10 k`). A corpus grows *out* of it; a
growing archiver population grows *into* it.

**Finding 3 — the residual is a *quantization floor*, not a remaining defect.**
D1 does **not** abolish structural zeros; it **scales the cliff with holdings
size**, to `r > ~1000 × shards_held` (the per-bond micro sum must reach one
milli). Unreachable for a bulk holder (4,096 shards ⇒ `r > 4 M`), but a 16-shard
hobbyist still zeroes at `r > ~16 k`.

**Name it correctly, or a future round will "fix" it by breaking a frozen
constant.** Sub-milli work is **unrepresentable** under the genesis-frozen
`WORK_MILLI_SCALE`; the small-holder zero at extreme replication is therefore the
**consensus quantization floor**, and its honest reading is a **minimum viable
holding threshold** — *"below this many shards, at this replication depth, your
work does not round to a representable unit"* — not a bug awaiting a patch. It is
**not** on the fix list. Any future proposal to eliminate it is a proposal to
change `WORK_MILLI_SCALE`, which is frozen; the legitimate levers are holdings
size and replication depth, both of which the archiver controls.

This is nonetheless a **holdings-size** effect, and it is the third force in the
triangle the **D3** round (reopen (e)) must resolve — see §12.8.

**Joint with A1.** Stranded budget is **not burden-clearing**: any A1 clearance
ratio is an upper bound to the extent budget fails to mint. Post-D1 the residual
is small outside the extreme-replication corner, so A1's verdicts stand; the
pre-D1 counterfactual is recorded only as the evidence that D1 had to land first.

### 12.8 D3 round charter — the holdings-size force triangle

**Status:** charter, amended (G-1…G-4) and ratified. D3 (§8 reopen (e)) is its own
design round on the **archival-reward** layer; this section states the problem it
must start from, not its answer. Filed `FOLLOWUPS.md` (V3.0, pre-genesis).

**Objective (G-4) — named, so it is not decided implicitly by the first mechanism
proposed.** The selection criterion is **maximal reach** — archiver count and shard
coverage — **subject to** (i) the §12.6 durability scoping (*foundation owns
durability; market owns reach*, so reach is the market layer's actual product) and
(ii) closure of W9's **concentration** regime (§12.5). Manipulation resistance and
the viability floors are **constraints, not co-objectives**: a design that
maximises them at reach's expense has optimised the wrong quantity.

**Why a charter at all.** D3 entered the record as "the per-bond `curve_milli` cap
is dodgeable at no bond cost." True but *partial*: it names one force acting on
holdings size and invites a fix aimed at the cap in isolation. Stage 2 has since
measured **two more** forces pushing the opposite way.

**The triangle (all three empirically anchored).**

| Force | Direction on holdings | Source | Anchor |
| --- | --- | --- | --- |
| **Dodgeable curve cap** — `curve_milli` plateaus **per bond** while `bond_floor` scales **per shard**, so splitting holdings across many small bonds dodges the plateau at *zero* extra bond cost | **↓ pushes holdings down** (splitting pays) | §8 reopen (e); A4 | A4 `hHold` columns: capped-honest doubles the stuffer's ROI (§12.5) |
| **Milli quantization** — a bond's per-shard micro work must sum to ≥ 1 milli, else the holding scores **zero** | **↑ pushes holdings up** (too small ⇒ unrepresentable) | §12.7 Finding 3 | A3: 16-shard holder zeroes at `r > ~16 k` |
| **Claim-cost economics** — a reward below the cost of one claim transaction is rationally never claimed, and unclaimed is *supply never created* | **↑ pushes holdings up**, but **weakly** (see G-3) | §12.7; `ARCHIVAL_BUDGET_SCHEDULE.md` §4 | A3 `noclm%`, priced at the rational batching cadence |

**G-3 — force three is cadence-dependent and weaker than first reported.** Rewards
batch: claiming once per `MAX_CLAIM_AGE_W` window amortises **one** claim
transaction across 26 epochs of accrued reward, lowering the claim-cost viability
floor by up to **26×** — purely archiver-side behaviour, **no consensus change**,
which makes it the cheapest lever available and a fourth (behavioural) one. A3
originally priced cadence `1` implicitly and so *overstated* this force by that
factor; the model now takes cadence explicitly and reports at the rational bound.
**Re-run finding:** at the batching cadence the swept regimes show
`noclm% == zero_work%` — i.e. **none** of the observed non-claiming is
claim-cost-driven; all of it is quantization. Force three is real but has **not**
been shown to bind anywhere yet, and the round should not size against it as if it
had.

**Inherited constraints (hard).**

- **G-1 — cross-bond aggregation is forbidden by the privacy architecture.**
  "Apply the cap per persona/principal" requires consensus to **link a principal's
  bonds**, and per-persona unlinkability is a deliberate privacy property under
  priority #1 (§`00-mission`). Both branches are dead: **mandatory** linkage is a
  privacy regression the priority order forbids outright; **voluntary** linkage is
  unenforceable against anyone who declines, reproducing the exact pathology one
  level up — *a cap that binds only the honest*. Therefore: **any cap can bind at
  most per bond.** This is not a narrowing of the fix space but an honest map of
  it — and it **removes what the first draft listed as the leading candidate**.
- **`WORK_MILLI_SCALE` is genesis-frozen** — the quantization floor is *not*
  eliminable; it is a parameter of the problem, not a target (§12.7 Finding 3).
- ~~**Load-bearing for W9** (§12.5): D3 closes the concentration regime the
  per-output fee-floor cannot reach, so it is **paired** with reopen (c), not
  sequenced after it.~~ **STRUCK 2026-07-27 (§12.11): there is no partner.** The
  fee floor never shipped — W9's FAIL was a mismeasurement of profit-vs-theft —
  so D3 was never half of a pair. It stands on its own merits (a bond must not be
  admitted into a position the frozen scale cannot pay) and landed at §12.9.1.

**Live lever families (post-G-1).**

1. **Per-bond friction / admission viability** — **resolved as R3, see §12.9
   OQ-2**: not a frozen minimum size (a forecast about `r`, wrong somewhere on any
   trajectory) but an **admission-time predicate** — admit a bond iff its holdings
   score non-zero under the production work path at connect height
   (`work_milli(bond) ≥ k`, `k = 1` milli, parent-block read-point). Self-sizing,
   single-sourced with the payment path, and gaming it awards a registered zero.
2. **Curve reshaping within the bond** — alter the plateau's shape/position, the
   only cap surface that remains enforceable.
3. **Cap deletion (G-2) — first-class, not a straw option.** The charter must not
   presuppose "a cap design." The branch's own evidence argues for weighing
   removal: at the realistic end (everyone splitting, effectively uncapped) A4
   measures **prem ≈ 1.0** — the concentration premium *vanishes* by total-work
   invariance; at the capped-honest end the stuffer's ROI **doubles**, because the
   plateau binds naive-honest work while the attacker splits past it. So against
   rational actors the plateau is (i) dodgeable, (ii) unenforceable above the bond
   (G-1), and (iii) **actively harmful in the regime where it binds**. Meanwhile
   `MAX_HOLDINGS_SHARDS = 4096` already imposes a hard, wire-enforced per-bond work
   ceiling, and per-shard bond floors already price holdings in capital. *A rule
   that costs distortion when it works and protects nothing when it doesn't is a
   [`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc)
   candidate.* Option: **delete the plateau**, let work run linear to the wire cap,
   and let capital (bond floors) + the fee-floor companion carry concentration
   pricing.
4. **Claim cadence** (behavioural, free) — see G-3; no consensus change.

**The A2 circularity, and its resolution.** The honest counter to G-2 is that the
curve may serve a **distributional** purpose that A2 (W6) would reveal — and A2 is
*held on D3* (§12.4.1), which is a genuine chicken-and-egg. **Resolution:** the
round runs a **provisional A2 probe under both cap-kept and cap-deleted** before
deciding, rather than letting the hold become a circular blocker.

**Empirical anchors.** The A3 table (§12.7) and the A4 `hHold` sweep (§12.5) are
the round's starting data; re-run `--stage2` rather than transcribing numbers.

### 12.9 D3 round — OQ-1 probe and OQ-3 census results

The two results the round said could change its recommendation. **Neither does —
both strengthen R2.**

#### OQ-1 — deletion is distribution-neutral in equilibrium ✅ (sim `fcc79eb2f`)

Per-class pool shares across `{naive-unsplit, split-dodge, rational best-response,
plateau-deleted}` × DQ-2H classes × a replication sweep, all scored through the
**production** chain so the split-dodge meets the quantization floor rather than
being assumed free.

| `r_market` | kept, NAIVE (unsplit) | kept, RATIONAL best-resp | PLATEAU DELETED | `\|Δ\|` rat−del |
| --- | --- | --- | --- | --- |
| 6 | 0.437 / 0.469 / 0.094 | 0.040 / 0.229 / 0.731 | 0.040 / 0.229 / 0.731 | **0.0000** |
| 100 | 0.097 / 0.556 / 0.347 | 0.040 / 0.229 / 0.731 | 0.040 / 0.229 / 0.731 | **0.0000** |
| 5 000 | 0.038 / 0.228 / 0.734 | 0.038 / 0.228 / 0.734 | 0.038 / 0.228 / 0.734 | **0.0000** |
| 100 000 | 0.000 / 0.200 / 0.800 | 0.000 / 0.200 / 0.800 | 0.000 / 0.200 / 0.800 | **0.0000** |

**Verdict: OQ-1 confirmed at every depth — G-2's distributional
counter-consideration is empirically discharged.** It holds by **two different
routes**, which is what makes it robust: at shallow `r` the actor **splits** and
escapes the cap; at deep `r` splitting would **quantize to zero** so the actor does
*not* split — and there the cap does not bind anyway (work sits below the knee).
Either way **the plateau is inert against an optimizing actor**.

**Modelling correction, recorded because it nearly produced the opposite answer.**
"Rational" must be **best response** (`max(unsplit, split)`), not *always split*.
Modelling it as always-split slandered the rational actor at deep `r` — where
splitting zeroes out — and produced a spurious `|Δ|` of 0.73–0.80. The
`SplitDodge` regime is retained precisely because its deep-`r` zeros are the
evidence **R3's `min_holding` must be sized against**: the dodge is
**self-limiting**, not unconditional.

**Partition optimality — a proposed proof REFUTED, and the stronger theorem that
replaces it (sim `392cc36f6`).** The natural reviewer challenge is *"what about
intermediate split sizes?"* **The reviewer's own proposed proof** closed it with a
two-boundary argument — recorded here as *proposed by the reviewer and falsified by
exhaustive check*, so the record shows which direction the correction flowed: the
4-split viability boundary sits at `r ≈ 4·g ≈ 4 000`, the cap-binding boundary at
`r < holdings/4 ≤ 1 024`, they never cross, so `max(unsplit, split-at-4)` is the
full optimum. **Exhaustive search over every granularity falsifies it:**

| `r` | `h` | best `k` | optimum | two-point max |
| --- | --- | --- | --- | --- |
| 700 | 4 096 | 243 | **5 849** | 5 120 (**−14 %**) |
| 1 023 | 4 096 | 130 | 4 001 | 4 000 |
| 6 | 4 096 | 23 | 682 607 | 681 984 |

The boundary arithmetic is *correct*; what it misses is that the binding trade-off
is **not** "cap binds vs split viable". It is **curve compression vs per-bond
flooring waste** — fine bonds escape the plateau but each discards a sub-milli
remainder, so the optimum is the **largest** granularity whose per-bond work still
lands in the curve's linear region: an **interior** point, neither extreme. (At
`r = 700` a 4-split discards ~712 micro across 1 024 bonds; a 243-split discards
~4 micro across 16.)

> **Corrected theorem (asserted in test).** The partition optimum **equals the
> plateau-deleted linear value**, up to accumulated per-bond flooring residue. *An
> optimising actor can always recover the linear value by choosing granularity.*
>
> **The residue bound, stated by regime** — measured, not asserted:
> - **Exact (0.0000 %) in every swept regime but one**, including *all* cap-inert
>   regimes (both sides take the **same single floor**, so it cancels) *and* the
>   coarse-split regimes where accumulated residue stays **sub-milli**
>   (`r = 700`: 17 bonds × ~4 micro).
> - **≤ 0.1 % where the cap forces a fine split** — worst observed **0.0082 %** at
>   `r = 6`, the shallowest point, where per-shard work is largest and the knee
>   forces ~179 bonds, so ~318 micro of residue per bond accumulates past a milli.
>
> **Do not read this as a bound on absolute flooring discard.** At deep `r` a
> *single* floor can discard a large fraction of a small total (`r = 100 000`:
> 40 960 micro → 40 milli, ~2.3 % discarded) — but that floor falls **identically on
> both sides** and therefore cancels. The bound is on the **difference** between the
> optimum and the linear-deleted value, which is what OQ-1 turns on.

That is the sharpest available statement of "the plateau is inert against an
optimiser", and strictly stronger than the two-point claim it replaces — **it makes
`|Δ| = 0` a corollary rather than a measurement**: if the optimiser recovers the
linear value everywhere, the cap-kept-optimal distribution *is* the deleted
distribution by identity, and the full-granularity sweep confirming it at every `r`
is the theorem checking itself. `|Δ| = 0` above is therefore measured **at the
optimum**, not at sampled strategies — the
probe's `RationalBestResponse` searches all granularities, and a test pins that the
two-point max is *strictly beaten* at `r = 700`, so the full search is not
gold-plating. The refuted argument is recorded rather than deleted, for the same
reason `SplitDodge` was kept: otherwise the next reader re-derives it.

**What the naive column shows.** The plateau's only observable effect is
redistribution **from** the large class **to** smalls (`0.437/0.469/0.094` vs
`0.040/0.229/0.731` at `r = 6`) — but strictly **over the naive fraction**. Sweep
at `r = 6`: `f=0.0 → 0.0000`, `0.2 → 0.0143`, `0.4 → 0.0367`, `0.6 → 0.0770`,
`0.8 → 0.1709`, `1.0 → 0.6377`. So *"the curve protects smalls"* is true exactly
to the extent smalls **fail to optimize** — R1's distortion wearing a defense's
name, now quantified.

#### OQ-3 — deletion blast-radius census ✅

- **Consensus/reward path:** `reward_arithmetic.rs` (`curve_milli`, plateau
  consts), `consensus_state.rs` (`BandedCurveParams`).
- **Build-generated, not hand-pinned:** `build.rs` reads
  `archival_reward_plateau_{value,work}_milli` from `config/` — so deletion is a
  **generated-params** change and joins that digest surface
  ([`42-serialization-policy`](../../.cursor/rules/42-serialization-policy.mdc)).
- **FFI:** `archival_ffi.rs` constructs `BandedCurveParams` **internally** from the
  generated constants — the plateau **does not cross the FFI signature**
  (`shekyl_archival_epoch_close_compute` takes bonds/shards/credit-pairs only).
- **C++: source-unchanged but behaviourally live.** `db_lmdb.cpp` and
  `blockchain_db.h` call the curve-bearing FFI entry points, so C++ needs **no
  edit** while its results change. *State this explicitly in the implementing PR* —
  "no C++ changes" would otherwise be misread as "no C++ impact."
- **KAT fixtures embedding plateau values (regenerate):**
  `consensus_state_kat_v1.json`, `gate4_lifecycle_kat_v1.json`; plus
  `reward_arithmetic_determinism_kat.rs`, `emission_verify_kat.rs`,
  `gate4_lifecycle_kat.rs`, `consensus_state_kat.rs`, `tests/common/mod.rs`.
- **Other consumers:** `shekyl-engine-core::emission_claim` (wallet-side),
  `shekyl-staking-sim::reward`, and this doc's sims.
- **⚠️ `curve_milli` the *function* survives deletion.** D2's escalation share
  reuses it in its continuous `pv = pw/2` form (§6.1, `escalation.rs`), so
  *deleting the plateau from the reward path is not deleting `curve_milli`*. The
  implementing PR must keep the function and remove only the **reward-path
  application** — the idiom is cited, the plateau is not.

#### OQ-5 — failure-confirmation interaction ✅ (as expected)

The m-of-n window is keyed **per `(P_id, shard)`** (composite key), so window
*semantics* are holdings-size-independent. Holdings size changes only the *number*
of windows a principal carries. **The joint grace + `m`/`n` round should still be
told** that `min_holding` (R3) may shift the population's bond-count/holdings shape,
which changes challenge *volume* per bond even though per-window tuning is
unaffected.

#### OQ-2 — **dissolved**: the floor is a predicate, not a number ✅

The sizing exercise ran (boundary `min_holding(r) = ceil(r/1000)`; swept 1–8
shards; a 2× safety multiple would give 16) — **and the exercise is what showed the
numeric to be the wrong instrument.** A frozen `min_holding` is a **forecast about
`r`**, and `r` is dynamic and capacity-driven, so any number is wrong somewhere on
the trajectory. That is precisely why the sizing kept demanding an `r`-forecast we
do not have. **The 16-shard recommendation is struck.**

> **R3, restated: admit a bond iff its holdings score non-zero under the production
> work path, evaluated at connect height** — literally `work_milli(bond) ≥ k`, via
> the same `scarcity_micro` → `work_milli_from_micro` chain that *pays*.

The viability condition never needed forecasting: it is **computable from chain
state at admission time**. Three properties follow by construction:

- **Self-sizing.** The cliff moves with `r`; the floor moves with it, forever.
- **Single-source.** The admission predicate **is** the payment predicate, so they
  cannot drift (the F-E discipline that D1 established, applied to a second
  consumer).
- **Right motivation.** It converts R3 from *"pick a number"* to *"make
  bonding-into-a-known-zero **unrepresentable**"*, which was always the point.

**Manipulation analysis — recorded as decided-unless-contested.** The design target
is *cheap computation, worthless prize*, **not** an expensive predicate: the
validator pays the computation at every bond-connect, so expense would be a
consensus **DoS surface**, not a tax on the manipulator. The predicate hits the
target inherently:

1. **No new oracle.** `r_market` is already consensus state the payment path
   consumes every epoch through the same code. Admission is a second,
   *strictly smaller-stakes* consumer of an already-priced quantity. Anyone able to
   move `r` profitably would attack the recurring epoch-close payout instead —
   orders of magnitude larger, and exactly the surface W9/A4 swept (moving `r`
   means bonding real copies or minting real leaves, and inflating `r` lowers
   scarcity payouts on those shards *including the manipulator's own*).
2. **Per-epoch re-scoring voids admission gaming** — the killer. Depress `r`,
   admit, restore `r`: the position then scores **zero at every subsequent close**.
   All value flows through per-epoch scoring, which admission timing cannot touch.
   The attacker has paid unbond/exit costs, forgone rewards, and bond churn to
   acquire **a registered zero**. The gain is not small; it is **structurally nil**.
3. **Prize pinned to ≈ 0.** The gate sits *at* the zero-work cliff, so the only
   contested positions are worth ~one milli per epoch. **Consequence — keep
   `k = 1` milli in consensus and put headroom margins in the *wallet* as
   warnings.** A consensus `k` meaningfully above 1 lifts the gate onto positions
   with real value, growing the prize from nil to small. No reason to donate that.
4. **Denial is capacity-priced and routable-around.** Inflating `r` to block
   applicants is untargeted: the applicant picks other shards, or simply holds
   *more* of the same ones (the predicate is over the holding's **sum**). Blanket
   denial means pushing `r` up across every viable shard set — capacity-scale
   bonding cost — and every copy bonded lowers the griefer's own scarcity income.
5. **Timing is killed by the read-point.** Evaluate against **parent-block state
   (`H−1`)** — the same discipline as the `frozen_segment_count` frontier-read and
   the M3-1 drift ruling — so intra-block ordering is irrelevant and every
   validator computes an identical verdict. (Bonding right after a *genuine* mass
   unbond is not manipulation; that is reading true state, and the admitted
   position really is viable at that state.)
6. **Validator-cheap.** One pass over the holding: at most `MAX_HOLDINGS_SHARDS`
   (4 096) `mul_div_floor` operations — the same per-bond work epoch-close already
   does. The asymmetry runs in the defender's favour.

**Two pins for the implementing round (decided unless contested):** **`k = 1`
milli**, and **read-point = parent-block state**. Both are rulings, not forecasts.
**Named caveats:** the `r_market` read-point must be pinned against the M3-1
cached-counter drift class; and the predicate eliminates **known-zero admission,
not lifetime viability** — post-admission degradation (`r` rising later) remains
possible, with the wallet carrying the margin warning. Genesis-frozen consensus
**shape**, so it lands inside the R2+R3 implementing round's design surface, not as
a rider.

**Clustering (the sizing exercise's one surviving result).** None, structurally:
under R2 credited work is **linear**, so bond count is credit-neutral — the
splitting incentive that motivated D3 is *gone* — and independent per-bond flooring
means splitting weakly **loses**. Consolidation is mildly preferred; nobody is
pushed to sit at the floor.

#### OQ-4 — A4 under deletion: prediction confirmed exactly ✅

| honest regime | ROI | `fee× → 1` |
| --- | --- | --- |
| kept, small bonds (`h=4`) | 0.6671 | 0.7 |
| kept, **capped** (`h=512`) | **1.1963** | 1.2 |
| **DELETED** (`h` irrelevant) | **0.6671** | **0.7** |

Deletion reproduces the small-bond row **bit-for-bit**: with no cap to dodge the
honest-holdings axis stops mattering, and A4 has *one* number per regime instead
of a naive/rational spread. **`fee_mult_to_close` is unchanged**, so reopen (c)'s
sizing evidence **survives deletion** (it was sized at the realistic end already).
*(2026-07-27: this remains a true statement about the measurement, but it now
sizes nothing — reopen (c) closed with no mechanism, §12.11. Retained as evidence
that deletion was orthogonal to the fee-flow regime, not as a live input.)*
The capped row is precisely what deletion removes — a penalty falling on
non-optimizing honest archivers that *doubled* the stuffer's relative capture, and
here pushes ROI **above 1** where deletion leaves it below.

> **The `hHold` sweep column is formally RETIRED.** It was evidence for a mechanism
> that, under R2, no longer exists; leaving it in the report invites recomputing
> against a ghost. Under deletion the realistic end is the **only** end, and A4
> carries one number per regime. The A4 tables in §12.5 are to be read as historical
> — the capped column documents *why the plateau was removed*, not a live regime.

#### A3 correction (found while deriving OQ-2)

`mean_replication` did not clamp a class's holdings to `n`, so early-chain rows
credited archivers with 4,096 shards out of a 1,011-shard corpus — replication
inflated ≈ 2.2×. Clamped. §12.7's cliff findings are **qualitatively unchanged**
(`r` still crosses 1,000 at scale), but the early-chain `r` figures are now honest.

**Round CLOSED — all five open questions discharged (OQ-1…OQ-5).** The resolution:

- **R2** — delete the plateau's **reward-path application** (not `curve_milli` the
  function; §6.1's escalation reuses the idiom).
- **R3** — an **admission-time viability predicate**, not a frozen number:
  `work_milli(bond) ≥ k` at connect height. Pins for the implementing round
  (decided unless contested): **`k = 1` milli**, **parent-block read-point**.
- **R4** — claim cadence: **monitored, not designed for** (real in principle,
  binding nowhere yet; §12.7 G-3).
- Concentration pricing is carried by the **wire cap + bonded capital** ~~+ the
  reopen-(c) fee-floor~~ *(the fee-floor leg struck 2026-07-27: (c) closed with no
  mechanism, §12.11. The first two carry it alone, which OQ-4 already showed —
  the sizing evidence was orthogonal to deletion, and is now orthogonal to
  everything shipping.)*

**A2 and A6 unblock**: the probe showed distribution is deletion-invariant *at the
optimum*, so both can now build on a settled surface. The implementing PR inherits
the §12.9 census — rule-42 digest membership, the **"C++ source-unchanged yet
behaviourally live"** callout (mandatory PR language), the KAT/fixture regeneration
list, and the **`curve_milli`-survives** carve-out for §6.1.

#### 12.9.1 Implementing round — **R2 + R3 BUILT**

Both landed on `feat/archival-d3-reward-path`, split on the consensus/FFI
boundary. R2 deleted the plateau's reward-path application at all **three**
production sites (`consensus_state.rs`, `emission_verify.rs`, `archival_ffi.rs` —
the census undercounted twice before grounding caught the third), retired
`EpochCloseInputs.curve`, and deleted the generated constants and config keys.
Production now names the per-`P` term honestly as `credited_work_milli` (linear
membership gate; C ABI `out_credited_work_milli`). The banded-PL
`curve_milli` / `BandedCurveParams` remain **sim/counterfactual only**. The
rule-42 digest claim was **retracted on verification** — the C++ generator
requires 13 keys, none of them plateau, so no bump was owed.

R3 shipped as `shekyl-archival-retention::admission` with a dedicated FFI module
(`archival_admission_ffi.rs`), attached **alongside** the JoinMarket vin verify
(the `bond_post_block_unique` idiom) rather than threaded through it, so no
existing signature moved. The last-settled epoch key and age derivation live in
Rust (`last_settled_epoch_as_of_parent`, `parent_state_shards_from_gather`); C++
only marshals LMDB rows. Both ratified pins hold: `k = 1` milli, parent-block
read-point. Two things the build surfaced that this round did **not** anticipate,
both now load-bearing:

1. **The applicant counts itself — `r_market + 1`.** `shard_work_micro` returns
   `0` for `r_market == 0` (correct on the paying path: a bond with no serve
   credit is not in the market). Scored naively, the predicate inverts twice
   over: the first archiver on a rare shard — the *maximal-scarcity, most
   valuable* participant — is refused, and at genesis, where no epoch has closed
   and every `r_market` reads `0`, **no bond is ever admissible** while serve
   credit cannot be earned without bonding. `r_market` counts every `P` with a
   serve-credit row, which includes the applicant once it serves, so `+1` is the
   correct model and not a bootstrap patch. Both failures are pinned as tests.

2. **The gather's two fields have different read-points, and the weaker
   governs.** `r_market` is *settled-epoch* state — written at epoch close, fixed
   for a whole epoch, ordering-immune by construction. `age_milli` is
   *height-derived*, and a shard's freeze height can be written by the very block
   under validation. So the parent-height discipline is required **because of the
   age term**, which is why the gather type is named for the parent block rather
   than the settled epoch. Naming it for the epoch would have been precise about
   `r_market`, wrong about `age_milli`, and would have told the dispatch author to
   pass the wrong height.

`CompleteTree` is admitted without a gather, on **dominance, not triviality**: it
holds a superset of every compact holding. The honest limitation is recorded
rather than hidden — it *can* score zero where the corpus is smaller than its
replication, but there *every* position scores zero, so refusing the whole-corpus
holder would refuse the entire market. That is a corpus-scale pathology, not the
per-bond mistake the gate catches. The short-circuit is also what keeps the
predicate bounded: scoring it would mean reading the whole corpus, the one
unbounded path in the design.

**R4** stays monitored, not designed for. ~~**Stage 3 remains gated on reopen
(c).**~~ — **(c) CLOSED with no mechanism 2026-07-27 (§12.11).** Stage 3's lone
remaining input was **§12.11.1** (the §6.0 anti-swing residual) — **also closed,
2026-07-27. Stage 3 opens with no outstanding hard inputs.**

### 12.10 A2 (W6) and A6 (swing) results — the last two arms

Both unblocked by the D3 closure (§12.9); deletion removed the behavioural axis
each would otherwise have needed.

#### A2 — distributional shift: **W6 clears** (sim `88cb1a956`)

Population crosses the DQ-2H **size** classes with a **holding-scarcity**
dimension, because *"scarce-holder" is about what you hold, not how much* — the
diluting cohort is defined by holding *common* (high-`r`) shards, which size alone
cannot express. Bands straddle the co-holder cliff, so the last band is a
structural zero pre-D1 and paid post-D1: the whole W6 mechanism.

> **Scarce-holder aggregate share: PRE-D1 `1.0000` → POST-D1 `0.9998`** — a
> **0.02 %** dilution. **Zero** scarce holders stranded below marginal cost (bond
> opportunity cost at the binding 10 % + storage).

**Why the number is small — the total-work invariance, third appearance.** This is
*the same theorem* that produced A4's `prem ≈ 1.0` and OQ-1's `|Δ| = 0`: a shard's
work is `r`-independent in total, so each replica carries `~1/r`. The ex-zero
cohort therefore enters `Σwork` carrying **very little**, and admitting it barely
moves the denominator. Stage 3 should read these as **one mechanism verified three
independent ways**, not three coincidentally small numbers.

**Recorded, outside the W6 flag:** all three past-cliff (`r = 3 000`) cells sit
**under water** post-D1 — reward `0.002 / 0.034 / 0.55` SKL against cost
`0.046 / 0.73 / 11.74`. D1 pays them *something*; scarcity weighting keeps that
below the bond opportunity cost. That is the market signal working as designed
(*do not over-replicate*), and it dovetails with **A3**: these are exactly the
cells whose rewards fall under the claim-cost floor.

#### A6 — swing: **cliff no, slew rate yes** (sim `4d238ccba`)

Binding input is a **W9 flood at the block-weight surge ceiling**
(`300 000 B × 50`), not organic growth — a stuffer buying leaves at the ceiling is
the fastest `n` can physically move, so it is the honest worst case for a
no-controller constraint. Stuffer weight comes from the production predictor.

| `n` | `Δn`/epoch | `Δshare` %pts/ep (penalty-free) | %pts/ep (legal 2× limit) | reorg `Δshare` %pt |
| --- | --- | --- | --- | --- |
| 0 | 2 714 | **1.4112 %** | **2.8230 %** | 0.1014 % |
| 25 000 | 2 554 | 1.3312 % | 2.6629 % | 0.0956 % |
| 250 000 | 2 554 | 0.0000 % | 0.0000 % | 0.0000 % |

**The two claims must be separated** — see the §6.0 amendment for the ruling form.
Structurally, **no cliff**: monotone, no single-shard discontinuity, only
down-swing bounded at `0.1014` points. Economically, the slew ceiling has **two
tiers, closed by two different mechanisms** — which the first pass conflated:

- **Penalty-free** (`≤` the effective median): **`1.41` pts/epoch**, ~`45 k`
  SKL/epoch in stuffing fees. ~~**Closed by the reopen-(c) fee-floor, and open
  until it lands** — this is the conditional layer.~~ **AMENDED 2026-07-27
  (§12.11 / §12.11.1): there is no fee floor to wait for.** Reopen (c) closed
  with **no mechanism**, so this tier has **no economic closer** — and it never
  needed one, because the anti-swing property does not depend on stuffing being
  *profitable*: a negative-sum stuffer, or a grudge-donor indifferent to loss,
  can still buy this slew. The live question is the **rate**, not the price, and
  the expected closer is **structural** — `frozen_segment_count` is monotone
  non-decreasing and reversible only to reorg depth, so there is no oscillation
  to arbitrage, only one-directional drift the escalation is built to track.
  **CLOSED at §12.11.1 (2026-07-27)** — on both legs, and note the upper tier's
  "priced out at 114×" closer above is *also* a price argument, equally blind to
  a loss-indifferent griefer; both tiers close structurally instead.
- **Legal `2×` limit**: **`2.82` pts/epoch**, ~`90 k` SKL/epoch in fees **plus
  ~`10.24 M` SKL/epoch of miner-reward penalty compensation** — at `B = 2M` the
  production formula pays the miner *exactly zero*, so the flooder funds the whole
  block reward every block. That is **114×** the fee cost, and it prices the upper
  tier out **already, independent of (c)**. Doubling the slew costs ~114× more.

And the ceiling **falls with tree depth**, so the operand hardens unattended.

**Method note.** A6's first pass gated on *"under 1 point per epoch"* — a threshold
**invented by the test author**, not §6.1's requirement (which is monotone +
bounded-slope, i.e. *no discontinuity*). The test now asserts the specification;
the slew rate is **reported**, not gated. This is the third instance of the same
discipline in this arc (always-split as "rational"; the two-point partition proof;
now an invented pass/fail bound) — **separating what the spec requires from what
the test author assumed is how a made-up number gets caught before it freezes.**

### 12.11 (RESOLVED) — Reopen (c) closes: NO MECHANISM, on the no-exclusivity accounting

**Disposition: reopen (c) is closed with no fee-floor mechanism.** The `T`-first
re-analysis showed the threat (c) was chartered against does not survive contact
with the system's *existing* design. This is prior work doing its job: FCMP++
whole-tree membership, output uniformity, the scarcity hyperbola (Stage 1), and
the no-exclusivity structure of the shard market jointly make output-stuffing a
*non-exploit*, so there is nothing for a fee floor to price. (c) is retired;
**Stage 3 loses this hard input** and gets simpler.

#### The accounting that closes it — three stuffer strategies, all self-refuting

1. **Raise `n`, serve nothing (shed the burden).** The share-lift is distributed
   by *served work*
   ([`consensus_state.rs::market_member_at_epoch`](../../rust/shekyl-archival-retention/src/consensus_state.rs)
   → `Σwork`). A stuffer serving none of the new work collects only `w_a` of the
   lift on their **pre-existing** holdings, while every other archiver collects
   `(1 − w_a)` for free. The stuffer pays 100 % of the cost to buy the whole
   market a raise. Pure subsidy — and note the sign: **the most-shedding case is
   the most-subsidizing, not the most dangerous.** This corrects the prior
   framing that named separability "the exploit if it survives"; that had the
   sign backwards.
2. **Raise `n`, serve the created shards.** Strictly dominated by honest
   archiving: identical organic demand is available at **zero** creation cost, so
   paying to manufacture demand you then serve is pure loss against serving what
   already exists.
3. **Cherry-pick rare shards.** No exclusivity — any shard created is servable by
   any archiver — so no rare position is capturable. And raising `n` does not
   dilute rare-shard value: scarcity pays on `1/r`, and adding *common* shards
   adds no co-holders to the rare one, so its yield is undiminished. Marginal
   common data has ≈ zero marginal contribution **by construction** — the Stage-1
   hyperbola pricing marginal contribution, doing exactly its job. Bulk-stuffed
   outputs are common-by-construction, the opposite of rare.

**The theorem under all three.** Because there is no exclusivity, every unit the
stuffer spends to move `n` lifts a pool that pays `(1 − w_a)` of the lift to
participants who spent nothing. The stuffer is always the **worst-positioned**
actor to profit from their own stuffing: the play is **negative-sum for the
stuffer** at any market size above trivial, and it **anti-scales** — the
healthier the market, the worse the trade. *You cannot out-compete free by
paying.*

#### Privacy axis (priority #1) — confirms the closure and inverts the concern

Proofs anchor to the whole accumulated tree at a reference height
(`CURVE_TREE_CLIENT.md` §5.1 `select_reference_height`: `tip − REF_ANCHOR_AGE`;
`MIN`/`MAX_AGE` is reorg/staleness control, **not** an anonymity-set bound), and
`CTTypeFcmpPlusPlusPqc` is the only admissible output type — enforced at
consensus in
[`tx_verification_utils.cpp:124`](../../src/cryptonote_core/tx_verification_utils.cpp#L124)
(and `:141`), not merely described in an RPC schema. So there is no narrow window
a burst can dominate, and uniform outputs cannot be re-partitioned into
flood/not-flood by a third party.

A generic flood is therefore **paid cover traffic**. A flood made legible enough
to subtract from others' privacy identifies only itself, revealing to a
whole-tree observer only *"not-you"* — free information. **A fee floor would have
taxed the cover traffic this analysis shows is protective.** The Rucknium
black-marble attack transfers its *cost profile* (the W9 calibration, DQ-2C) but
**not** its privacy mechanism: FCMP++ membership plus output uniformity deletes
the ring-side half outright.

#### A4's W9 "FAIL" — RETRACTED and re-labeled

A4 measured `ROI > 1` and recorded it as a vulnerability. **`ROI > 1` is the
definition of a working archival incentive** — it is why anyone archives at all.
The exploit question is not *"is stuffing profitable"* but *"does the stuffer
earn more per unit of genuine work than an honest archiver"*, and netted for the
no-exclusivity subsidy that question resolves **negative-sum for the stuffer**.

The W9 FAIL is **superseded** by this accounting. The prior §12.4 / §12.5 /
§12.10 W9 rows are **historical**: they record a real measurement of profit, and
profit was never the theft question. **Do not re-open (c) off the stale FAIL.**

#### Method note

The **A4′ excess-return sweep** drafted for this round (`R_stuffer / W_stuffer`
vs `R_honest / W_honest` across the A4 sweep) was **demoted before building**:
the no-exclusivity ledger closes the question analytically, so the sweep would
confirm an accounting identity rather than discover a boundary. Recorded as an
instance of *check the ledger before measuring it* — the exact reverse of the D1
lesson, where the arithmetic **hid** the defect; here the arithmetic **reveals
the non-defect**.

---

### 12.11.1 (RESOLVED) — the §6.0 anti-swing dependency closes: NO MECHANISM

**Disposition: §6.0's anti-swing property is discharged structurally, with no
slew-control mechanism.** This was the lone residual left standing when reopen
(c) closed (§12.11) — it survived (c)'s price argument because §6.0 never
depended on stuffing being *profitable*, and a negative-sum stuffer or a
loss-indifferent grudge-donor moves `n` just as fast as a profiteer would.

It closes on **two legs with two different arguments**, because the concern was
two questions wearing one name. **Stage 3 now has no outstanding hard inputs.**

#### Leg 1 — the *level*, and its rate of arrival: there is no harm to prevent

The question §6.0 was really asking is "can an adversary move the staker share?"
The prior question — never asked — is **"what breaks if they do?"** Nothing does,
and three source facts say so.

**(i) The harm channel is exactly one, and it is not the security budget.**
[`burn.rs::compute_burn_split`](../../rust/shekyl-economics/src/burn.rs) computes:

```rust
burned_amount      = total_fees * burn_pct
staker_pool_amount = burned_amount * staker_pool_share
actually_destroyed = burned_amount - staker_pool_amount
miner_fee_income   = total_fees - burned_amount
```

`staker_pool_share` — the *only* quantity `n` moves — applies to `burned_amount`
and **does not appear in `miner_fee_income`**. Miner income is a function of
`total_fees` and `burn_pct` alone. So the obvious harm ("shrink the security
budget, cheapen a 51 %") is **structurally unreachable**, not merely expensive.
The single channel is `actually_destroyed`: coins that would have been burned are
paid to archivers instead.

**(ii) `n` cannot rise without burden rising — this is an arithmetic identity,
not a design intention.**
[`segment_freeze.rs:71`](../../rust/shekyl-archival-retention/src/segment_freeze.rs#L71):

```rust
pub const fn frozen_segment_count(leaf_count: u64) -> u64 {
    leaf_count / SEGMENT_LEAF_COUNT
}
```

`n` is integer division of the chain's leaf count. There is **no free variable**:
every unit of `n` is `SEGMENT_LEAF_COUNT` real outputs, really stored, forever.
§6.2's burden-coupling ("the operand *is* the funded quantity") is therefore not
an approximation that could drift — the operand cannot lie about the quantity it
measures. **Share tracking `n` is never mispricing.**

**(iii) The ceiling is a state the design already sanctions.** The escalation is
bounded by its asymptote (the object Stage 3 selects). Once share is at the
asymptote, further stuffing moves nothing. Maximum achievable effect is therefore
`(asymptote − current_share) × burned_amount` — *arriving early at the value we
call correct for a mature, high-burden chain*.

Put together, the "attack" reads: **pay to create real archival work, and cause
the protocol to correctly compensate the people who do it** — while funding
miners and the burn out of the same fees, and keeping only `w_a` of a lift paid
for entirely. There is no victim in that sentence. Rate is irrelevant because the
destination is sanctioned and the path cannot overshoot it; speed changes only
*when* the chain arrives, never *where*.

> **The same error twice, and worth naming as a pattern.** A4 measured `ROI > 1`
> and recorded a working incentive as a vulnerability (§12.11). §6.0 asked whether
> the share could rise quickly and treated the rise itself as harm. Both mistake
> **the mechanism functioning for the mechanism failing**, and both survived
> because the question was framed as *"can the adversary move this?"* rather than
> *"what breaks if they do?"* **Adversary-can-move-it is not a finding. Name the
> harm first, or there is nothing to price.**

#### Leg 2 — *oscillation*: real harm, structurally impossible

Unlike the level, oscillation would be **genuine** harm: a share that swings
wrecks archiver planning (bond commitments are long-lived and priced against
expected share) and opens real pump-and-dump arbitrage — which is precisely what
§6.0/W8 were written to prevent. This leg is closed by structure, not by absence
of harm.

`frozen_segment_count` is monotone non-decreasing per branch
(`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` **O-2**: "connects only append; pops are
branch switches"), and the **single** decrease path is **O-3 pop-symmetry** —
verified at source: `BlockchainLMDB::revert_archival_segment_freezes`
([`db_lmdb.cpp:7525`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L7525)) is the only
writer that deletes segment rows, is explicitly the pop hook, derives its bound
from the same Rust entry point as the connect hook, and requires an active write
txn (`throw` otherwise), so it fires only on block pop. **No path exists to
decrease `n` faster than reorg depth.** An attacker can push `n` up (funded,
non-exclusive, negative-sum per §12.11) but **cannot pull it back**, so there is
no second side of a swing to run. What remains is one-directional drift, which
the escalation *should* follow because it tracks genuine burden growth.

#### Consequences

- **No slew-control mechanism ships.** Mirrors (c): the residual dissolved rather
  than got built.
- **The §6.0 amendment's "load-bearing twice" framing is fully retired.** W9's
  profit gate went at §12.11; this was the surviving half, and it is now closed
  on its own terms. Both slew tiers are covered: the penalty-free `1.41`
  pts/epoch tier (which lost its (c) closer) and the legal-`2×` `2.82` tier —
  whose "already priced out by the block-reward penalty (**114×**)" claim was
  *also* a price argument and inherits the same blindness to a griefer. Neither
  tier needs a price closer, because neither tier's arrival is harmful.
- **A6's slew measurement stands as a measurement** (`1.41`/`2.82` pts/epoch,
  hardening with tree depth) and is now a **descriptive bound on how fast the
  chain can be pushed toward a sanctioned state**, not a residual risk.
- **Stage 3 opens.** No outstanding hard inputs: (c) closed with no mechanism
  (§12.11), D3 implemented (§12.9.1, PR #371), and this residual discharged.
  Reopen (d) remains parallel to the *shape* freeze per §8, unchanged.

#### The falsifier — state it, because everything rests on it

Leg 1 stands entirely on **`n` ≡ burden**. If a path ever exists where
`frozen_segment_count` rises without a corresponding permanent storage
obligation — a change making it anything other than a pure function of realized
leaf count — then share would rise without burden, the escalation *would* be
mispricing, and this disposition reopens. That is a **one-line invariant to
guard**, and it is guarded today by the definition itself: any edit to
`segment_freeze.rs:71` that introduces a second variable is the trigger. Leg 2
reopens if any writer other than `revert_archival_segment_freezes` learns to
delete segment rows.

### 12.12 Stage 3 implementation record — 3a shape SHIPPED, 3b wiring LIVE (PR #373)

Stage 3 shipped as **two deliberately separate artifacts**, so the freeze
reviewer can see exactly what is frozen, what is live, and what is *not*
shipped:

**Stage 3a — the shape (frozen).** The §6.1 five-constraint set as executable
code: the banded-PL body lives in `shekyl-units` (`banded_pl.rs` — single body,
two consensus consumers, `shekyl-archival-retention` re-exports);
`staker_pool_share_at(n)` in `shekyl-economics/escalation.rs` with the five
constraints as tests; `EscalationParams` + load-time validation
(`params.rs` — an `asymptote < floor` parameterization is refused at load, the
first of the two fail-closed layers); persisted-params digest `0x01`→`0x02`
(rule 42). The sim **deps** the consensus share rather than computing its own
(dep-don't-mirror, both in the sweep and in `SimParams::default()`).

**Stage 3b — the wiring (live consensus C++).** The escalated split is the
*only* split on the consensus path: `economics.h::compute_fee_burn` routes
`shekyl_compute_burn_split_escalated(total_fees, burn_pct, n)`, so **no share
constant crosses the FFI boundary** — Rust derives the share from `n` and the
shipped `EconomicParams`, and `SHEKYL_STAKER_POOL_SHARE` is deleted from the
generated C++ header (the JSON key remains, as the Rust floor's source). The
flat `shekyl_compute_burn_split` export is retained solely as the
genesis-neutrality pin's differential oracle (it holds no constant; the share
is an argument). The operand read-point:

- `Blockchain::parent_frozen_segment_count(block_height)` is the single
  asserting reader — `m_db->height() == block_height` proves parent-state
  (add_block grows the tree and advances the height in one write txn;
  pop_block trims both in one write txn), and it **throws** on violation
  rather than logging, because a template/connect divergence prices a coinbase
  that connect's exact-equality money check refuses — a chain halt. The check
  is load-bearing at connect and a tripwire at template build (the template
  caller sets `height = m_db->height()` itself; its guarantee is the shared
  expression, and the tripwire refuses any future non-tip parent).
- **Template:** `create_block_template` computes `n` once and passes it to
  *both* `construct_miner_tx` passes (the retry after the coinbase weight
  change must price the same split). `construct_miner_tx` takes `n` as a
  **required** parameter — a default is a silently-wrong split the moment the
  asymptote is non-neutral.
- **Connect:** `handle_block_to_main_chain` computes `n` once, before
  `validate_miner_transaction` and `m_db->add_block`, and the same value feeds
  the money check and the staker-inflow accrual — verify's operand IS the
  accrual's operand (the F-B1c discipline).
- **The `prev_block` template path was deleted** (the one path that could not
  read its own parent's `n` — no height-indexed leaf count exists), with the
  RPC field RESERVED and loudly refused; reopen named in `FOLLOWUPS.md`.

**NOT shipped — the asymptote numeric.** `asymptote_share == floor_share` in
the shipped config, so the escalation is **genesis-neutral by construction**:
bit-identical to the flat constant at every `n`, pinned by
`escalated_split_is_bit_identical_to_flat_at_the_genesis_parameterization` and
`escalating_the_share_never_touches_miner_income` (Leg 1). The number remains
provisional-until-testnet under the §11.4 ceremony (adversary-advantage
argument committed *before* the number; PoRep branch ⇒ A1 re-runs with sealing
costs first). Nothing in 3a/3b weakens or advances that gate.
