# F-D4 — the a-priori exit-window derivation (Gate-6 §12.6)

**Status: committed a-priori 2026-07-15 — before any `draw_exit_gap` code exists and before any
exit sweep runs. Review round 1 run same day (§10): F-W1 corrected the candidate window,
F-W2 reclassified `σ_L` as a design lever.** This is the artifact Gate-6 §12.6 requires first
in the F-D3/F-D4 build sequence, in the GF7_HOOKS §5.1 ordering: (a) derive the threshold and
the window model from a stated adversary-advantage claim, (b) adversarial review of the rate
model against the correlated-unbond adversary, (c) only then does the sweep run. A failed sweep
is a decorrelation-redesign signal, never a move-the-bar signal.

**Activation provenance:** the F-D3/F-D4 FSM gate fired 2026-07-15 —
`release_cooldown_elapsed` is enforced consensus at `bond_post.rs:369` (`HoldingsUpdate`-drop,
per-shard anchor) and `:627` (`Unbond`, whole-record anchor); landed with the bond FSM
(PR #303/#307). The deterministic cooldown tell F-D3 exists to break is now real.

**What this doc does and does not decide.** It commits: the anchor formula, the threshold, the
regime split, the two-sided window model with its driving rates, the smear-or-delay answer as an
a-priori lemma, the queue predicate that converts the swan-2/W8 open question into a decidable
condition, and a candidate genesis window under stated conservative rate assumptions. It does
**not** commit code (`draw_exit_gap` lands after this doc's rate model passes review) and it does
**not** grade anything (grading is the R4 joint sweep, Gate-6 §12.8).

---

## 1. What is being derived

`DEFAULT_EXIT_GAP_WINDOW` — the `window` argument to the future `draw_exit_gap` (Gate-6 §12.5):
a **one-sided** consumer-side latency draw `s ~ U[0, window]` added *after* the cooldown-pinned
earliest-spend height. No order coin, no inversion — collateral is not spendable before the
cooldown, so one-sidedness is forced (§12.5). The draw is wallet discipline
(consensus-unenforceable; conformance-armed per §12.5), applied per-event to both the terminal
`Unbond` drain and each recurring `HoldingsUpdate`-drop.

### 1.1 The anchor (F-D6 — derived, never hardcoded)

The consensus predicate (`release_cooldown.rs`) is epoch-arithmetic:
`current_settlement_epoch ≥ last_served_epoch + RELEASE_COOLDOWN_EPOCHS`, with
`current_settlement_epoch = height / SETTLEMENT_EPOCH_BLOCKS` (`consensus_state.rs`
`settlement_epoch_at_height`). The earliest height at which the cooldown leg verifies is
therefore the **product of named consts**:

```
H_cd(P) = (last_served_epoch(P) + RELEASE_COOLDOWN_EPOCHS) × SETTLEMENT_EPOCH_BLOCKS
```

The release additionally requires `slashes_settled_through` the same anchor
(`bond_post.rs:372`/`:638`); the deterministic slash scheduler settles at epoch deadlines, so
the effective anchor is

```
H_0(P) = max(H_cd(P), first height at which slashes_settled_through(anchor) holds)
```

— both terms computable by the wallet from public state. The wallet posts at `H_0 + s`. Per
F-D6, `H_0` derives from `bond_floor::RELEASE_COOLDOWN_EPOCHS` (config-generated,
`consensus_constants.json` `release_cooldown_epochs: 2`) and
`constants::SETTLEMENT_EPOCH_BLOCKS` — never a hardcoded `20_000`. The staking-sim
`standoff.rs:93` doc-comment integer is purged when F-D3 builds.

### 1.2 Why the entry `600` cannot be borrowed (the rate-model difference, made precise)

`DEFAULT_ENTRY_GAP_WINDOW = 600` was derived against the **background funding-spend rate**: a
bond post hides among ordinary FCMP++ spends, a dense background, so a two-sided 600-block
spread (1200-block search width) reaches the `TARGET_ANON_SET = 10` cover set cheaply. The exit
seam's observable class is different in kind, not just in rate: an `Unbond` refund is **loud by
design** (gate-4 §4.3/§3.2 — `bond_floor`-derived credit against a public bond record keyed by
`P_canonical_id`; the inflation-audit disposition forecloses hiding it). The cover set for an
exit is therefore **other exit-class events only** — a thin population whose density is driven
by bond-market churn in steady state and by the **correlated-unbond / market-event rate**
(Gate-6 §18.1) in crisis. Both driving rates differ from the entry's by orders of magnitude,
and the crisis rate is *adversarially synchronized*. Two regimes, two different binding
constraints (§4); neither reproduces `600`.

---

## 2. The adversary

Inherited from Gate-6 §12.1/§18.1 and the WI-4 S-3 observer, specialized to the exit seam:

- **Sees:** the full public chain — every `Unbond`/`HoldingsUpdate` connect height, the bond
  record (so `last_served_epoch`, hence **`H_0` is adversary-computable per persona**), the
  refund amount class; plus network-observable principal-side activity timing. Does **not** see
  FCMP++-hidden amounts/sources or circuit interiors (§10.9 isolation is the inherited
  conditioning assumption; the hooks measure the post-isolation residual).
- **Wants:** the `P` ↔ principal link. The exit is the highest-yield event for it: a
  cooldown-expiry release followed by principal-side value re-appearance at a characteristic
  latency.
- **Channels:**
  1. **Fixed-offset tell** — without the draw, the release sits at a deterministic,
     per-persona-computable height `H_0`; any principal-side event at a stable offset from
     `H_0` is attributable.
  2. **Isolation** — an exit that is the only exit-class event within the observer's
     correlation resolution is uniquely pairable with the principal-side event that follows it.
  3. **Co-trigger clustering** — a market event synchronizes many exits; the *cohort
     membership* is public, and the intra-cohort assignment (which P maps to which
     principal-side re-appearance) is the residual the draw must scramble. The shared trigger
     is the catastrophic case (`16→1.01`, entry finding, §12.5).

## 3. The anchor-quantization lemma (the a-priori answer to swan-2/W8's mechanism question)

The W8 wargame asks whether `RELEASE_COOLDOWN_EPOCHS = 2` **smears** a synchronized-exit cohort
or merely **delays** it intact. A-priori answer from the landed predicate's arithmetic:
**it delays and it quantizes — the effect is not a smear but its opposite (anti-smear:
intra-epoch dispersion is erased, concentrating the cohort).**

The cooldown anchors on `last_served_epoch`, an **epoch-quantized** value. A market event at
mid-epoch `E` stops a cohort's serving; every member's anchor lands on `E` (or `E − 1` for
members that had not yet served in `E`). The cohort's `H_cd` values therefore collapse onto **at
most two epoch-boundary heights** `(E + 2) × SEB` and `(E + 1 + 2) × SEB` — the intra-epoch
dispersion of the members' *intent* times (up to `SEB` blocks wide) is **erased** by the epoch
arithmetic. The cooldown concentrates the cohort onto shared anchors ~28 days later; the entire
decorrelation burden falls on `draw_exit_gap`'s window. (The W8 wargame arm confirms this lemma
empirically; if the sim contradicts it, the derivation reopens — §7.)

Corollary: because the cohort shares its anchor, all cohort draws are over the **same** interval
`[H_0, H_0 + W]` — full overlap, which is the best case for intra-cohort mixing. The window
never has to compensate for staggered anchors within a cohort leg; it does have to handle the
two-anchor split (the `E`/`E − 1` seam), which the queue predicate's pooling term covers (§5.3).

## 4. The committed threshold and the regime split

**Threshold (inherited shape, WI-4 §3.2/§13.4/§13.5 — committed here before any correlator or
draw code exists):** per persona, per regime, the observer's additive advantage over blind
guessing must satisfy `A < 1/N ⇔ r < 2` — fewer than one expected excess de-anonymization
across the anonymity set, where `N` is the regime's cover-set size. Per-persona force comes from
exchangeability within a regime row; any subclass with distinct linkability is split into its own
row and graded against the same bound, never averaged (the WI-4 regime-splitting discipline; the
worst row is the reported number). `r < 1` remains pre-rejected (blind guessing achieves
`r = 1`).

**The exit seam has two regimes with opposite window pressure:**

| Regime | Cover set | Driving rate | Window pressure |
|---|---|---|---|
| **X-1 steady-state** (lone or near-lone exit) | Background exit-class events inside the window | Bond-market churn rate `ρ_x` (exit-class events per block, network-wide) | **Lower bound** — `W` must be wide enough to contain a cover set |
| **X-2 crisis cohort** (L17-shaped synchronized exit) | The cohort itself (background ≈ 0 in a trough) | Cohort size `N_x` and the principal-side re-appearance spread `σ_L` | **Upper bound** — `W` must not spread the cohort so thin that members are isolated |

X-2 is the binding row by construction (troughs are where the T-A1 intersection surface is
maximally cheap — the L17 coupling that makes the rate model and the wargame one obligation).

## 5. The window model

### 5.1 X-1 lower bound (anti-isolation via background cover)

A lone exiter's cover is the expected number of other exit-class events landing in its window.
With background exit-class rate `ρ_x` (events/block) and target cover `N_t = TARGET_ANON_SET
= 10` (the inherited posture anchor, `shekyl-staking-sim/src/standoff.rs:116` — a grading
constant of the **sim** crate; nothing of this name lives in the production `shekyl-standoff`
crate, and a bare `standoff.rs` citation is ambiguous between the two):

```
ρ_x × W ≥ N_t − 1        ⇒        W ≥ (N_t − 1) / ρ_x
```

This is the entry derivation's *shape* with the exit's *rate*. `ρ_x` is a pre-testnet unknown
(like the entry harness's background network-event rate — the same conditional-surface flag),
but it is boundable from the bond-market model: at the sim's lean-equilibrium attractor
(`N_P ≈ 79–154` bonded, `STAKER_ARCHIVAL_SIM.md` §L13) with per-epoch voluntary churn fraction
`c` (unbonds + `HoldingsUpdate`-drops per persona per epoch), `ρ_x ≈ N_P × c / SEB`.

**Committed planning instance (conservative):** `N_P = 80`, `c = 0.05/epoch` (the sim's lean
regime is low-churn by construction — `bond_duration(age)` retention plus the cooldown suppress
mobility; 5% is deliberately below the sim's myopic acquire/drop and must be re-anchored by the
wargame's churn read):

```
ρ_x ≈ 80 × 0.05 / 10_000 = 4 × 10⁻⁴ / block
W ≥ 9 / 4×10⁻⁴ = 22_500 blocks ≈ 2.25 SEB ≈ 31 days
```

The scale conclusion is robust to the exact churn number: for any plausible `c ∈ [0.02, 0.2]`,
`W` lands at **SEB scale (≈ 0.6–5.6 SEB), one to two orders of magnitude above the entry 600**.
This is the quantitative form of "the exit window cannot borrow the entry 600."

An SEB-scale window has a second, structural benefit: it **smears the epoch-boundary
quantization spike** (§3) across a full epoch and overlaps adjacent-epoch release populations,
merging the `E`/`E − 1` two-anchor split into one mixed pool.

### 5.2 X-2 upper bound (anti-isolation within the cohort)

In a trough there is no background; the cohort is the cover. `N_x` draws uniform on `[0, W]`
have typical spacing `W / N_x`. The observer's intra-cohort assignment (channel 3) degrades to
blind guessing only while the exits are **mutually confusable against the principal-side
latency spread** `σ_L` (the dispersion of principal-side re-appearance latency after the
refund — wallet-drawn, a coupled-but-separate wallet discipline). `σ_L` is therefore a
**design lever, not a fact of nature** (F-W2): the wallet discipline that draws it does not
exist yet, so its value is *chosen* when that discipline is spec'd, bounded below only by
usability (how long a principal tolerates before re-deploying refunded capital).
Confusability requires neighbor spacing not exceeding the spread:

```
W / N_x ≲ σ_L        ⇒        W ≲ N_x × σ_L
```

L17-shaped trough cohort: bonded population 9–25, 30 % class-correlated exit ⇒ `N_x ≈ 3–8`.
With `N_x = 5` and `σ_L` at a generous days-scale (`σ_L ≈ 2_000` blocks ≈ 2.8 days),
`W ≲ 10_000`. With an hours-scale `σ_L` (`≈ 100` blocks), `W ≲ 500`.

### 5.3 The queue predicate (the swan-2/W8 question, made decidable)

A single window satisfies both regimes iff

```
(N_t − 1) / ρ_x   ≤   N_x × σ_L
```

**This is a joint constraint over `(W, σ_L)`, not a test the world passes or fails** (F-W2).
`ρ_x`, `N_t`, `N_x` are measured (or wargame-read); `W` and `σ_L` are both *chosen* — `W` here,
`σ_L` by the coupled wallet discipline (§5.2). Treating `σ_L` as exogenous and concluding
"the predicate fails ⇒ queue" would sanction the more expensive mechanism without ever costing
the cheaper lever. Two ways to satisfy the constraint, both named, priced on the **same cost
axis** (capital idle after refund — the freeze-harm shape the sim already models, so they are
directly comparable):

- **The `σ_L` lever (wallet discipline, no mechanism change):** spec the principal-side
  re-appearance discipline with `σ_L ≥ W / N_x`. At the §5.4 candidate and the trough
  `N_x = 5`, that is `σ_L ≥ 6_000` blocks ≈ 8.3 days of principal-side re-appearance spread.
  No consensus surface, no draw-domain change; the cost is idle refunded capital on the
  principal side, mean `σ_L / 2` per exiting persona, paid **only by exiters**.
- **The release-queue (the W8 candidate):** crisis unbonds spread over a randomized
  multi-epoch window — formally raising the *effective* `σ_L` by drawing `s` over `k` epochs
  (`W_crisis = k × SEB`) so adjacent cohorts and residual steady-state churn pool into one
  cover population. A **decorrelation redesign** (GF7 §5.1-sanctioned), but its domain widens
  **for everyone, always** (§5.3 one-window pin) — the idle-capital cost lands on every exit,
  not only crisis exits.

Neither is pre-selected. The wargame's `ρ_x`/`σ_L`-feasibility reads price both against the
sim's freeze-harm model; the cheaper constraint-satisfier wins, and the queue is reached only
if the required `σ_L` exceeds what the wallet discipline can plausibly hold (e.g., principals
routinely redeploy within hours, making a days-scale `σ_L` a fiction the sweep would expose).

**One window, not regime-switched:** a wallet must not choose its window based on perceived
crisis (the choice itself would leak crisis-membership timing and re-introduce a two-population
tell inside the cohort). The draw is always `U[0, DEFAULT_EXIT_GAP_WINDOW]`; if the queue is
needed it is a *mechanism* change (the draw's domain widens for everyone, always), not a
conditional branch.

### 5.4 Candidate genesis value (committed, conditional)

```
DEFAULT_EXIT_GAP_WINDOW = 3 × SETTLEMENT_EPOCH_BLOCKS = 30_000 blocks   (≈ 42 days)
```

**F-W1 (review round 1, blocking — resolved by re-derivation):** the first draft committed
`2 × SEB = 20_000` and described it as clearing the X-1 bound. It does not: `20_000 < 22_500`,
11 % *below* the bound — and the shortfall runs the wrong way twice, because the planning
instance's `c = 0.05` is deliberately pessimistic (§5.1), so `22_500` is the *conservative*
end of the bound, and the candidate undershot the conservative end. Describing that as
"clears" was the bar moving to meet the number — the one move GF7_HOOKS §5.1 forbids by name.
The value was picked for being clean (`2 × SEB`, cooldown-symmetric) and the bound was then
narrated as met. The candidate is re-derived: the smallest named-const multiple of `SEB` that
clears the planning-instance bound is `3 × SEB`.

- **Clears the X-1 bound with margin:** `30_000 ≥ 22_500`, 33 % above the planning-instance
  bound (equivalently: clears for any measured `c ≥ 0.0375`, a 25 % cushion below the already-
  pessimistic committed `c = 0.05`). Still *derived from named consts* per F-D6 — the
  multiplier changes, the derivation discipline doesn't.
- Spans three full epochs: merges the two-anchor split (§3), pools adjacent-epoch release
  populations across two boundary seams, and is the natural first `k` for the queue mechanism
  if that leg wins the §5.3 costing.
- Total worst-case exit latency after last service ≈ 2 epochs (consensus cooldown) + up to
  3 epochs (draw), mean 3.5 epochs. The cooldown symmetry of the draft's `2 × SEB` is lost;
  symmetry was an aesthetic, not a derivation input, and does not outrank the bound.
- Implied §5.3 lever requirement at the trough: `σ_L ≥ W / N_x = 6_000` blocks ≈ 8.3 days
  (`N_x = 5`).
- **Conditional on** the wargame's `ρ_x` and `σ_L` reads (§7); the number moves only through
  this doc's §5 model, reviewed — never through the sweep.

## 6. The cost side (named, per 00-mission ordering)

The window's cost is **capital lockup**: collateral stays unspendable up to `W` blocks past
`H_0` (mean `W/2` ≈ 21 days at the candidate). Priority-2 (privacy) buys this from usability
explicitly — the same trade the entry standoff made, at larger scale because the exit's cover is
thinner. Named consequences:

- The wallet surfaces the *drawn* release height, not `H_0`, as "available on" (F-D2's
  UI-default posture extends here: no UI copy that anchors the user's expectation to `H_0`, or
  operators will cancel the draw by posting manually at `H_0` — the conformance harness's
  clustering arm would catch a wallet population doing this, §12.5 negative control).
- No consensus deadline conflicts: an `Unbond` has no expiry, and slashability through the
  anchor is already settled by the verify predicates. Holding the post costs opportunity, not
  risk. (Checked against `bond_post.rs` — no upper-bound predicate exists on the release
  height.)
- The recurring `HoldingsUpdate`-drop leg pays the same lockup on the dropped shard's floor
  fraction only.

## 7. Conditional surface + reopen criteria (rule 21)

Committed as conditional on three pre-testnet unknowns, each a named sweep axis (the
`fetch_latency_per_unit` flag discipline):

| Unknown | Source of truth when it exists | Effect on the model |
|---|---|---|
| `ρ_x` (steady exit-class rate) | Testnet bond-market telemetry; interim: L13 attractor × churn read from the L18-reconciled sim | Moves the X-1 bound linearly |
| `σ_L` (principal-side re-appearance spread) | The coupled wallet-discipline design (not yet spec'd) — a **design lever** (F-W2), chosen when that discipline lands, feasibility-bounded by how fast principals actually redeploy | Moves the X-2 bound linearly; its feasible range decides the §5.3 lever-vs-queue costing |
| `N_x` trough cohort | L17 swan table (9–25 × exit fraction); wargame re-read | Moves the X-2 bound and the queue predicate |

**Reopen criteria:** (a) the W8 wargame contradicts the §3 quantization lemma (e.g., anchor
heterogeneity in real cohorts exceeds two epochs — then the burden re-splits between anchor
spread and draw and the §5 model is re-derived); (b) measured `ρ_x` off the committed planning
instance by more than an order of magnitude in either direction; (c) the principal-side
discipline lands and its feasible `σ_L` range is known (then the §5.3 joint constraint is
priced for real — lever vs queue — and the cheaper satisfier is committed). Re-evaluation
shape: amend this doc + Gate-6 §12.6, adversarial review of the changed leg, before any window
change ships.

## 8. What the sweep must include (pre-registered, so the harness is built to the bar)

1. **X-1 arm:** lone exit against swept `ρ_x`; grade `r` against `< 2` at `N_t = 10`.
2. **X-2 arm (the L17/W8 wargame — one obligation with this doc):** synchronized cohort
   (`N_x ∈ {3, 5, 8}`, both one-anchor and two-anchor splits per §3), swept `σ_L`; grade
   intra-cohort assignment advantage. This arm empirically answers smear-vs-delay and supplies
   the measured inputs for the §5.3 joint-constraint costing (lever vs queue).
3. **Shared-trigger negative control (§12.5 pin):** a cohort with the draw *disabled* (or
   window collapsed) must be **caught** as clustered — clustering-detection, not the entry's
   inversion-detection; a harness that cannot fail this control certifies nothing.
4. **Thin-regime gap-toward-max bias arm:** the one-sided draw at small effective populations —
   the exit-seam analogue of the entry's `1.86` thin-regime finding (Gate-6 §10.12); grade at
   the trough row, not the attractor row.
5. **Threshold ordering:** all arms grade against this doc's committed `r < 2` per regime row;
   worst row reported; no post-hoc thresholds (GF7 §5.1).

## 9. Build order after this doc

1. Adversarial review of §5's rate model against the correlated-unbond adversary (the step
   gating any code). **Round 1 run 2026-07-15 — findings F-W1/F-W2 resolved by amendment
   (§10); code stays gated on review of the amendment.**
2. `draw_exit_gap` in `shekyl-standoff` (one-sided `bounded_uniform`, typed `ExitGap`, golden
   vector on the aarch64 lane, F-D6-derived anchor, conformance + §8.3 negative control).
3. The X-1/X-2 sweep per §8; grading folds into the R4 joint grade (Gate-6 §12.8) — never
   per-axis.

## 10. Review round 1 (2026-07-15) — the rate model vs the correlated-unbond adversary

The §9.1 adversarial review ran same-day. Inputs verified at source first (`TARGET_ANON_SET
= 10.0` at `shekyl-staking-sim/src/standoff.rs:116`; `DEFAULT_ENTRY_GAP_WINDOW = 600` at
`shekyl-standoff/src/draw.rs:73`); the §5.1 arithmetic confirmed. Two findings, both resolved
by amendment in this doc; the review's survival list recorded so later rounds don't relitigate
it.

- **F-W1 (blocking — resolved):** the draft candidate `2 × SEB = 20_000` did not clear its own
  X-1 planning-instance bound (`22_500`) and §5.4 said "clears" — bar-moving, the GF7 §5.1
  named violation, aggravated because the pessimistic `c` makes `22_500` the conservative end.
  Resolution: candidate re-derived to `3 × SEB = 30_000` (33 % margin; clears down to
  `c ≥ 0.0375`); the failure and the correction are recorded in §5.4 rather than erased.
- **F-W2 (load-bearing — resolved):** §5.3 treated `σ_L` as exogenous and pre-sanctioned the
  release-queue on predicted failure, despite §5.2 itself calling `σ_L` wallet-drawn. The
  predicate is a **joint constraint over `(W, σ_L)`**; the `σ_L` wallet-discipline lever
  (`σ_L ≥ W/N_x = 6_000` blocks at the candidate — no mechanism change, cost borne by exiters
  only) must be priced against the queue (domain widens for everyone, always) on the shared
  capital-idle axis before either is committed. §5.2/§5.3/§7 amended; neither option is
  pre-selected.
- **Confirmed sound (survives both fixes):** the §3 anchor-quantization lemma (delays and
  merges, never smears — and it merges `last_served_epoch`, already public, so it leaks
  nothing new); the rate-driven X-1 shape; the X-2 confusability form (`W/N_x ≲ σ_L`);
  committing the §5.3 predicate before any sweep; and the **one-window-not-regime-switched
  pin** (§5.3) — the §16.1 partition trap applied correctly: a wallet choosing its window on
  perceived crisis would sort on state and destroy the cover it buys. Kept verbatim.
- **Precision item (resolved):** the `N_t` citation disambiguated — `standoff.rs` names both a
  sim file and (as a crate) the production draw home; §5.1 now cites the sim path and line.

`draw_exit_gap` remains gated: the window value is the artifact, and code opens only against
the amended §5.4 (review of this amendment is the reopen check, not a new round).

## Related documents

- [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §12.5–12.8 — F-D3 mechanism, F-D6
  anti-drift, R4 joint grade.
- [`ARCHIVAL_BOND_WI4_MEASUREMENT.md`](ARCHIVAL_BOND_WI4_MEASUREMENT.md) — the inherited
  threshold shape (`r < 2`), regime splitting, exchangeability pin, conditional-seal posture.
- [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) §5.1 — threshold-precedes-
  grading ordering.
- [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §2.2 — the L16 floor under
  `RELEASE_COOLDOWN_EPOCHS`.
- [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L13/§L17/§L18 — population attractor,
  swan table, the reconciled mobility model.
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) — swan-2/W8 synchronized-exit wargame (this doc converts its
  mechanism question into the §5.3 predicate; the wargame remains the empirical arm).
