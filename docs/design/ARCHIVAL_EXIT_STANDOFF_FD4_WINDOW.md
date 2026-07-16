# F-D4 — the a-priori exit-window derivation (Gate-6 §12.6)

**Status: committed a-priori 2026-07-15 — before any `draw_exit_gap` code exists and before any
exit sweep runs.** This is the artifact Gate-6 §12.6 requires first in the F-D3/F-D4 build
sequence, in the GF7_HOOKS §5.1 ordering: (a) derive the threshold and the window model from a
stated adversary-advantage claim, (b) adversarial review of the rate model against the
correlated-unbond adversary, (c) only then does the sweep run. A failed sweep is a
decorrelation-redesign signal, never a move-the-bar signal.

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
= 10` (the inherited posture anchor, `standoff.rs`):

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
refund — wallet-drawn, a coupled-but-separate wallet discipline). Confusability requires
neighbor spacing not exceeding the spread:

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

Under the committed planning instance (`22_500 ≰ 5 × σ_L` for any `σ_L < 4_500` blocks ≈ 6.3
days), **the predicate likely fails**: the steady-state row demands an SEB-scale window that
spreads a trough cohort of 3–8 into multi-day isolation. The a-priori conclusion — recorded as
a derivation output, not discovered mid-sweep — is:

- **If the predicate fails at the wargame's measured `ρ_x`/`σ_L`:** the mechanism needs the
  **release-queue** (the W8 candidate): crisis unbonds spread over a randomized multi-epoch
  window — formally, raising the *effective* `σ_L` term by drawing `s` over `k` epochs
  (`W_crisis = k × SEB`) so that adjacent cohorts and residual steady-state churn pool into one
  cover population. The queue is a **decorrelation redesign**, the GF7 §5.1-sanctioned response
  — not a bar adjustment. Its cost axis is §6.
- **If the predicate holds** (dense-enough steady churn or wide-enough principal-side spread),
  a single `DEFAULT_EXIT_GAP_WINDOW` at the X-1 bound suffices and X-2 rides on cohort overlap.

**One window, not regime-switched:** a wallet must not choose its window based on perceived
crisis (the choice itself would leak crisis-membership timing and re-introduce a two-population
tell inside the cohort). The draw is always `U[0, DEFAULT_EXIT_GAP_WINDOW]`; if the queue is
needed it is a *mechanism* change (the draw's domain widens for everyone, always), not a
conditional branch.

### 5.4 Candidate genesis value (committed, conditional)

```
DEFAULT_EXIT_GAP_WINDOW = 2 × SETTLEMENT_EPOCH_BLOCKS = 20_000 blocks   (≈ 28 days)
```

- Clears the X-1 bound at the committed planning rate (`22_500` is within 12 % — and the bound
  itself is the conservative end; the candidate is *derived from named consts*, per F-D6, not a
  bare integer).
- Spans two full epochs: merges the two-anchor split (§3), pools adjacent-epoch cohorts, and is
  the natural first `k` for the queue mechanism if the predicate fails (the crisis and
  steady-state shapes coincide at `k = 2`).
- Symmetric with the cooldown itself (`RELEASE_COOLDOWN_EPOCHS × SEB`): total worst-case exit
  latency after last service ≈ 2 epochs (consensus) + up to 2 epochs (draw), mean 3 epochs.
- **Conditional on** the wargame's `ρ_x` and `σ_L` reads (§7); the number moves only through
  this doc's §5 model, reviewed — never through the sweep.

## 6. The cost side (named, per 00-mission ordering)

The window's cost is **capital lockup**: collateral stays unspendable up to `W` blocks past
`H_0` (mean `W/2` ≈ 14 days at the candidate). Priority-2 (privacy) buys this from usability
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
| `σ_L` (principal-side re-appearance spread) | The coupled wallet-discipline design (not yet spec'd; F-D4 flags it as an *input*, not a deliverable) | Moves the X-2 bound linearly |
| `N_x` trough cohort | L17 swan table (9–25 × exit fraction); wargame re-read | Moves the X-2 bound and the queue predicate |

**Reopen criteria:** (a) the W8 wargame contradicts the §3 quantization lemma (e.g., anchor
heterogeneity in real cohorts exceeds two epochs — then the burden re-splits between anchor
spread and draw and the §5 model is re-derived); (b) measured `ρ_x` off the committed planning
instance by more than an order of magnitude in either direction; (c) the principal-side
discipline lands with `σ_L` structurally pinned (then X-2 becomes computable, and the queue
predicate resolves). Re-evaluation shape: amend this doc + Gate-6 §12.6, adversarial review of
the changed leg, before any window change ships.

## 8. What the sweep must include (pre-registered, so the harness is built to the bar)

1. **X-1 arm:** lone exit against swept `ρ_x`; grade `r` against `< 2` at `N_t = 10`.
2. **X-2 arm (the L17/W8 wargame — one obligation with this doc):** synchronized cohort
   (`N_x ∈ {3, 5, 8}`, both one-anchor and two-anchor splits per §3), swept `σ_L`; grade
   intra-cohort assignment advantage. This arm empirically answers smear-vs-delay and evaluates
   the §5.3 queue predicate.
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
   gating any code).
2. `draw_exit_gap` in `shekyl-standoff` (one-sided `bounded_uniform`, typed `ExitGap`, golden
   vector on the aarch64 lane, F-D6-derived anchor, conformance + §8.3 negative control).
3. The X-1/X-2 sweep per §8; grading folds into the R4 joint grade (Gate-6 §12.8) — never
   per-axis.

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
