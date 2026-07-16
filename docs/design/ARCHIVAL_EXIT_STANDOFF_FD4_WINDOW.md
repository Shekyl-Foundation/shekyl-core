# F-D4 — the a-priori exit-window derivation (Gate-6 §12.6)

**Status: committed a-priori 2026-07-15 — before any `draw_exit_gap` code exists and before any
exit sweep runs. Review rounds 1–3 run same day (§10–§12): F-W2 reclassified `σ_L` as a design
lever; F-W3 converted the genesis value to a `K_COVER`-pattern provisional sentinel with the
decision rule frozen (§5.4) — the value is sealed by the Phase 7.7 stressnet rate read, not
committed here; F-W6 folded the rate-independent X-3 anchor-merge bound (`W ≥ 2 × SEB`,
§5.2a) into the frozen rule with its cost stated.** This is the artifact Gate-6 §12.6
requires first in the F-D3/F-D4 build
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
condition, and — per review rounds 2–3 (F-W3/F-W6) — the **decision rule, its rate-independent
X-3 floor, and the conservatism percentile** that convert the Phase 7.7 stressnet rate read
into the genesis window, with a provisional sentinel shipping in the interim. It does **not**
commit a window value (not derivable pre-measurement, §5.4/§11) and it does **not** grade
anything (grading is the R4 joint sweep, Gate-6 §12.8). `draw_exit_gap` is written against the
sentinel (§9 step 2).

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

**The planning box (F-W3 — the bound is a range, not a number).** Both inputs are pre-testnet
unknowns with stated plausible ranges: `N_P ∈ 79–154` (the L13 attractor) and `c ∈ [0.02, 0.2]`.
Evaluating the corners:

```
N_P =  80, c = 0.02:   ρ_x = 1.6 × 10⁻⁴   ⇒   W ≥ 56_250 blocks ≈ 5.6 SEB
N_P =  80, c = 0.05:   ρ_x = 4.0 × 10⁻⁴   ⇒   W ≥ 22_500 blocks ≈ 2.25 SEB
N_P = 154, c = 0.20:   ρ_x = 3.1 × 10⁻³   ⇒   W ≥  2_922 blocks ≈ 0.3 SEB
```

The bound spans a **~19× box**. Any point picked from it is a point, not a derivation — this is
review round 2's blocking finding (§10 F-W3), and it is why the window's *value* is sealed by
the stressnet read (§5.4) rather than committed here. What the box does establish a-priori: at
**every** corner the bound sits above the entry `600` (≈ 5× at the loosest corner, ≈ 94× at the
tightest), so "the exit window cannot borrow the entry 600" survives the full box even though
the exact scale does not.

The first draft committed a single "conservative planning instance" (`N_P = 80`, `c = 0.05`).
Review round 2 (F-W4) found that instance structurally steered: it stacked two *marginal*
worst cases (low-end `N_P` and a `c` deliberately below the sim's myopic acquire/drop),
yielding a bound more pessimistic than any joint scenario — the mirror image of F-W1's
undershoot, with the same disease (the number being steered). The conservatism level is now
committed a-priori as a **percentile of the joint read** (§5.4), not as hand-picked marginals.

An SEB-scale window has a second, structural benefit: it **smears the epoch-boundary
quantization spike** (§3) across a full epoch. Whether it also *overlaps* adjacent-epoch
release populations is a separate, sharper question with a rate-independent answer — X-3
(§5.2a): overlap requires `W > SEB` at all, and even then coverage is partial, not merged.

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

### 5.2a X-3 — anchor-merge lower bound (rate-independent; review round 3)

*(Inserted by review round 3 as `5.2a`: §5.3/§5.4 are externally cited — Gate-6 §12.6,
`RELEASE_CHECKLIST.md`, FOLLOWUPS — and do not renumber.)*

The §3 lemma already contains a second lower bound, derivable with **no rate input at all**.
Adjacent anchors sit exactly `SEB` apart (`H_close(E+2)`, `H_close(E+3)`, …). A cohort at
anchor `A` occupies `[A, A + W]`; the next occupies `[A + SEB, A + SEB + W]`. They overlap iff

```
W > SEB
```

At `W = 1 × SEB` the overlap is a single point — measure zero, **exactly disjoint**. The
adversary then reads cohort membership straight off the exit height: every exit in
`[A₁, A₁ + SEB)` is cohort `E − 1`, every exit after is cohort `E` — a clean partition of the
crisis cohort, halving its anonymity set. **X-1 never sees this**, because X-1 grades
steady-state background cover, not cohort integrity; a dense `ρ_x` read could satisfy X-1 at
`1 × SEB` while cleanly splitting every straddling cohort. The smallest `SEB` multiple with
`W > SEB` is `2 × SEB` — a cliff at exactly one place, geometric, not aesthetic:

```
X-3 (anchor-merge, rate-independent):   W ≥ 2 × SETTLEMENT_EPOCH_BLOCKS
```

**The coverage boundary — 2 × SEB opens the split, it does not close it.** At `W = 2 × SEB`
the mixed fraction is `(W − SEB) / W = 50 %`: a cohort member landing in the first `SEB` of
its range still has zero cross-anchor neighbours. Mixing improves continuously after the
cliff (`(W − SEB) / W`), with no second cliff. X-3 is a **mixes-at-all** bound, never a
*merged* bound — the §8 arm 2 two-anchor-split runs grade the actual mixed fraction at the
straddle, and no sentence in this doc or its consumers may lean on "2 × SEB merges the
split."

**X-3's cost (the strongest argument against it, stated beside the argument for).** X-3
tightens the §5.3 queue predicate: the LHS acquires a hard floor of `2 × SEB = 20_000`
**regardless of measured rate**. At `N_x = 5` that demands `σ_L ≥ 4_000` blocks (≈ 5.6 days)
even at the dense corner where X-1 alone would have been satisfied by `1 × SEB`. Before X-3,
a dense `ρ_x` read could make the predicate pass and the whole `σ_L`/queue question
evaporate; after X-3 it cannot — **the F-W2 lever-vs-queue costing is load-bearing in every
measured world**, not only the thin ones. Weighed and accepted: a rate-independent partition
of the crisis cohort is precisely the harm this mechanism exists to prevent, and discovering
at seal time that `1 × SEB` cleared X-1 while splitting every straddling cohort would be the
worse outcome. X-3 therefore enters the §5.4 decision rule as a derived bound — not a floor
preferred by narrative.

A single window satisfies all regimes iff both lower bounds (X-1 rate-driven, X-3
anchor-merge) fit under the X-2 upper bound:

```
max( (N_t − 1) / ρ_x ,  2 × SEB )   ≤   N_x × σ_L
```

The X-3 term puts a hard floor of `20_000` on the LHS in every measured world (§5.2a cost
paragraph) — the predicate can no longer evaporate on a dense `ρ_x` read, so the costing
below runs unconditionally.

**This is a joint constraint over `(W, σ_L)`, not a test the world passes or fails** (F-W2).
`ρ_x`, `N_t`, `N_x` are measured (or wargame-read); `W` and `σ_L` are both *chosen* — `W` here,
`σ_L` by the coupled wallet discipline (§5.2). Treating `σ_L` as exogenous and concluding
"the predicate fails ⇒ queue" would sanction the more expensive mechanism without ever costing
the cheaper lever. Two ways to satisfy the constraint, both named, priced on the **same cost
axis** (capital idle after refund — the freeze-harm shape the sim already models, so they are
directly comparable):

- **The `σ_L` lever (wallet discipline, no mechanism change):** spec the principal-side
  re-appearance discipline with `σ_L ≥ W / N_x`. At an SEB-scale window and the trough
  `N_x = 5`, that is days-scale spread (e.g. `σ_L ≥ 4_000` blocks ≈ 5.6 days at `W = 2 × SEB`;
  the exact figure follows the sealed `W`, §5.4). No consensus surface, no draw-domain change;
  the cost is idle refunded capital on the principal side, mean `σ_L / 2` per exiting persona,
  paid **only by exiters**.
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

### 5.4 The value is sealed by measurement; the decision rule is frozen now (F-W3)

**No genesis value is committed here.** Review round 1 (F-W1) replaced one picked point
(`2 × SEB`) with another (`3 × SEB`); review round 2 (F-W3) found the real error one level up:
the §5.1 bound spans a ~19× planning box, so *any* pre-measurement value is a point picked
from a range wide enough that some narration will always make it look derived. `ρ_x` is a
pre-testnet unknown by this doc's own statement — the value cannot be derived before the rate
is measured. The resolution is the project's ratified pattern for exactly this shape:
**`K_COVER`** — a genesis constant gated on a measurement that hasn't run
(`ARCHIVAL_REWARD_GATE_M1.md` §9.3; PF-9 pins its finalization as a Phase 7.7 stressnet-entry
prerequisite).

**Sentinel + refusal (mirrors `k_cover.rs` mechanics, verified at source):**

- `DEFAULT_EXIT_GAP_WINDOW` lands as a **provisional sentinel `0`** with the invariant
  *provisional ⇔ 0, sealed ⇒ ≥ 1* asserted at compile time.
- **Non-test builds refuse the sentinel** (`compile_error!` unless the provisional flag is
  explicitly acknowledged) — the shipping guard is the compile refusal, never the sentinel's
  runtime semantics. Testnet/stressnet builds arm it explicitly; KAT parameterization goes
  through a `for_kat`-style constructor behind a permanent dev-only feature.
- `draw_exit_gap` is **written against the sentinel now** — F-D3's mechanism, typing, golden
  vectors, and conformance harness land without waiting on the value; only shipping waits.

**The decision rule, frozen a-priori (cheap today, expensive after the sweep):**

1. **The rule:** given the measured `(ρ_x, N_x, σ_L)`,

   ```
   W := the smallest multiple of SETTLEMENT_EPOCH_BLOCKS
        ≥ max( (N_t − 1) / ρ_x ,  2 × SEB )
   ```

   The first term is the X-1 rate-driven bound (§5.1); the second is the X-3 anchor-merge
   bound (§5.2a) — **derived** from the §3 lemma with no rate input, folded into the rule by
   review round 3 (F-W6) rather than parked as a preference the seal could quietly invoke or
   quietly drop. Keeps F-D6's derive-from-named-consts. Round 2 had held the `2 × SEB`
   structural argument outside the rule as a tiebreak narrative; round 3 made it precise
   (overlap iff `W > SEB`; measure-zero at equality) and a derived bound belongs in the rule
   with its cost stated (§5.2a), not in the narrative. The rate still decides everything
   above the geometric floor — the number arrives from the rate, never the rate at the
   number.
2. **The conservatism level (F-W4):** the bound is evaluated at a **committed percentile of
   the joint `(N_P, c)` read** — the **10th percentile of measured `ρ_x`** (the window clears
   the bound in ≥ 90 % of jointly-plausible scenarios). Not stacked marginal worst cases: the
   draft's `N_P = 80` × `c = 0.05` compounded two marginal pessimisms into a bound harsher
   than any joint scenario, which is steering with the sign flipped. Committed now so the
   measurement cannot be re-cut later to land on a convenient `W`.
3. **`N_t` re-derived for the exit adversary (F-W5):** `TARGET_ANON_SET = 10` is real but was
   anchored to the *entry* seam, and a constant's meaning is its consumer. The exit-seam
   `N_t` must be re-derived a-priori and taken as it comes — **before** the seal, because the
   dependence is not innocent (`N_t = 9` would make `20_000` exact at the draft's planning
   instance, which is precisely the re-cut temptation rule 2 exists to foreclose).
4. **The §5.3 joint-constraint costing**, already committed: the `σ_L` lever priced against
   the queue on the shared capital-idle axis; the cheaper satisfier wins.

**Why a wallet default gets consensus-constant treatment:** changing a shipped window splits
the wallet population into two draw distributions — the §16.1 partition trap arriving as a
flag day. Technically mutable, practically once-only: **soft-frozen**, sealed once, by the
stressnet read, through this rule.

**Seal event:** the Phase 7.7 stressnet is where `ρ_x`, `N_x`, and `σ_L` get read.
`DEFAULT_EXIT_GAP_WINDOW` finalization rides the same stressnet-entry gate as `K_COVER`
(PF-9 shape; `RELEASE_CHECKLIST.md` entry added beside it). Sealing after stressnet entry
would leave mainnet genesis as the window's first live execution — same argument, same pin.

## 6. The cost side (named, per 00-mission ordering)

The window's cost is **capital lockup**: collateral stays unspendable up to `W` blocks past
`H_0` (mean `W/2` — weeks-scale at any SEB-scale `W`; the exact figure follows the sealed
value, §5.4). Priority-2 (privacy) buys this from usability
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
| `ρ_x` (steady exit-class rate) | **The Phase 7.7 stressnet read — the §5.4 seal event** (joint `(N_P, c)` distribution, 10th-percentile evaluation); interim scale bracket only: L13 attractor × churn from the L18-reconciled sim (the ~19× §5.1 box) | Decides `W` through the frozen §5.4 rule |
| `σ_L` (principal-side re-appearance spread) | The coupled wallet-discipline design (not yet spec'd) — a **design lever** (F-W2), chosen when that discipline lands, feasibility-bounded by how fast principals actually redeploy | Moves the X-2 bound linearly; its feasible range decides the §5.3 lever-vs-queue costing |
| `N_x` trough cohort | L17 swan table (9–25 × exit fraction); wargame re-read | Moves the X-2 bound and the queue predicate |

**Reopen criteria:** (a) the W8 wargame contradicts the §3 quantization lemma (e.g., anchor
heterogeneity in real cohorts exceeds two epochs — then the burden re-splits between anchor
spread and draw and the §5 model is re-derived); (b) the stressnet-measured `ρ_x` falls
outside the §5.1 planning box entirely (below `1.6 × 10⁻⁴` or above `3.1 × 10⁻³`) — then the
box's own model (`ρ_x ≈ N_P × c / SEB`) is wrong, not just its inputs, and §5 is re-derived
rather than re-evaluated; (c) the principal-side discipline lands and its feasible `σ_L` range
is known (then the §5.3 joint constraint is priced for real — lever vs queue — and the cheaper
satisfier is committed). Re-evaluation shape: amend this doc + Gate-6 §12.6, adversarial
review of the changed leg, before any window change ships. **The sealed value itself never
reopens through these criteria — post-seal it is soft-frozen (§5.4); a change is a §16.1
partition event and takes a design round of its own.**

## 8. What the sweep must include (pre-registered, so the harness is built to the bar)

1. **X-1 arm:** lone exit against swept `ρ_x`; grade `r` against `< 2` at the exit-derived
   `N_t` (F-W5 — the re-derivation must land before this arm runs; the entry-inherited `10` is
   not the grading constant).
2. **X-2 arm (the L17/W8 wargame — one obligation with this doc):** synchronized cohort
   (`N_x ∈ {3, 5, 8}`, both one-anchor and two-anchor splits per §3), swept `σ_L`; grade
   intra-cohort assignment advantage. This arm empirically answers smear-vs-delay and supplies
   the measured inputs for the §5.3 joint-constraint costing (lever vs queue). The two-anchor
   runs additionally grade the **X-3 coverage boundary**: measured cross-anchor mixing at the
   straddle against the predicted mixed fraction `(W − SEB) / W` (§5.2a) — the arm certifies
   *mixes-at-all* and reports the fraction; it never certifies "merged".
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
   gating any code). **Rounds 1–3 run 2026-07-15 (F-W1/F-W2; F-W3/F-W4/F-W5; F-W6) —
   resolved by the §5.4 sentinel + frozen-rule reshape and the §5.2a X-3 fold-in (§10–§12).**
2. `draw_exit_gap` in `shekyl-standoff`, **written against the provisional sentinel** (§5.4):
   one-sided `bounded_uniform`, typed `ExitGap`, golden vector on the aarch64 lane,
   F-D6-derived anchor, conformance + §8.3 negative control; compile-refusal wiring per the
   `k_cover.rs` pattern. Unblocked now — the mechanism does not wait on the value.
3. The exit-seam `N_t` re-derivation (F-W5) — before the sweep grades and before the seal.
4. The X-1/X-2 sweep per §8; grading folds into the R4 joint grade (Gate-6 §12.8) — never
   per-axis.
5. **The seal:** Phase 7.7 stressnet read of `(ρ_x, N_x, σ_L)` → the §5.4 frozen rule fixes
   `DEFAULT_EXIT_GAP_WINDOW` → provisional flag cleared (stressnet-entry prerequisite,
   `RELEASE_CHECKLIST.md`, beside `K_COVER`/PF-9).

## 10. Review round 1 (2026-07-15) — the rate model vs the correlated-unbond adversary

The §9.1 adversarial review ran same-day. Inputs verified at source first (`TARGET_ANON_SET
= 10.0` at `shekyl-staking-sim/src/standoff.rs:116`; `DEFAULT_ENTRY_GAP_WINDOW = 600` at
`shekyl-standoff/src/draw.rs:73`); the §5.1 arithmetic confirmed. Two findings, both resolved
by amendment in this doc; the review's survival list recorded so later rounds don't relitigate
it.

- **F-W1 (blocking — resolved, then superseded by F-W3):** the draft candidate
  `2 × SEB = 20_000` did not clear its own X-1 planning-instance bound (`22_500`) and §5.4
  said "clears" — bar-moving, the GF7 §5.1 named violation, aggravated because the pessimistic
  `c` makes `22_500` the conservative end. The round-1 resolution re-derived the candidate to
  `3 × SEB`; round 2 (F-W3) found that fix repeated the category error at a different point.
- **F-W2 (load-bearing — resolved):** §5.3 treated `σ_L` as exogenous and pre-sanctioned the
  release-queue on predicted failure, despite §5.2 itself calling `σ_L` wallet-drawn. The
  predicate is a **joint constraint over `(W, σ_L)`**; the `σ_L` wallet-discipline lever
  (no mechanism change, cost borne by exiters only) must be priced against the queue (domain
  widens for everyone, always) on the shared capital-idle axis before either is committed.
  §5.2/§5.3/§7 amended; neither option is pre-selected.
- **Confirmed sound (survives both fixes):** the §3 anchor-quantization lemma (delays and
  merges, never smears — and it merges `last_served_epoch`, already public, so it leaks
  nothing new); the rate-driven X-1 shape; the X-2 confusability form (`W/N_x ≲ σ_L`);
  committing the §5.3 predicate before any sweep; and the **one-window-not-regime-switched
  pin** (§5.3) — the §16.1 partition trap applied correctly: a wallet choosing its window on
  perceived crisis would sort on state and destroy the cover it buys. Kept verbatim.
- **Precision item (resolved):** the `N_t` citation disambiguated — `standoff.rs` names both a
  sim file and (as a crate) the production draw home; §5.1 now cites the sim path and line.

## 11. Review round 2 (2026-07-15) — the value is not derivable pre-measurement

Round 2 reviewed the round-1 amendment and found the deeper error: F-W1's fix (`3 × SEB`)
corrected a point *within* the same mistake. Three findings, resolved by the §5.4 reshape.

- **F-W3 (blocking — resolved):** the X-1 bound is not a number but a **~19× planning box**
  (§5.1 corners: `2_922` to `56_250` over the doc's own stated ranges `N_P ∈ 79–154`,
  `c ∈ [0.02, 0.2]`). The round-1 planning instance (`22_500`) and both draft candidates are
  points in that box with no better claim than any other; "within 12 %" needed saying
  precisely because a number picked from a range that wide is always within something. `ρ_x`
  is a pre-testnet unknown by this doc's own statement — **the value cannot be derived before
  the rate is measured, and no re-argued candidate changes that.** Resolution: stop picking.
  The project's ratified pattern for a genesis constant gated on an unrun measurement is
  `K_COVER` (M1 §9.3 provisional sentinel + compile-time refusal; PF-9 seal-before-stressnet
  pin). `DEFAULT_EXIT_GAP_WINDOW` is the same shape gated on the same event and rides the
  same Phase 7.7 gate — §5.4 now freezes the **decision rule** and ships the **sentinel**;
  the value arrives from the stressnet rate read. That the constant is a wallet default, not
  consensus, *strengthens* the treatment: changing it post-ship splits the population into
  two draw distributions (the §16.1 partition trap as a flag day), so it is soft-frozen —
  technically mutable, practically once-only.
- **F-W4 (steering-symmetry — resolved):** the round-1 planning instance stacked two
  *marginal* worst cases (`N_P = 80` low end × `c = 0.05` deliberately-below-sim), producing
  a bound more pessimistic than any joint scenario — the mirror image of F-W1 (one direction
  inflates the bound, the other undershoots it; both are the number being steered).
  Resolution: the conservatism level is committed a-priori as the **10th percentile of the
  joint `(N_P, c)` read** (§5.4 rule 2), so the measurement cannot be re-cut to land on a
  convenient `W`.
- **F-W5 (input provenance — pinned, derivation owed):** `N_t = 10` is real at
  `shekyl-staking-sim/src/standoff.rs:116` but was anchored to the **entry** seam; a
  constant's meaning is its consumer. The exit-seam `N_t` must be **re-derived a-priori and
  taken as it comes, before the seal** — the dependence is not innocent (`N_t = 9` would make
  `20_000` exact at the round-1 instance), which is exactly why it settles before the value,
  not after. Owed at §9 step 3; the §8.1 sweep arm grades at the exit-derived `N_t`.
- **Survives round 2:** the `2 × SEB` **structural** argument (two-anchor merging,
  adjacent-epoch pooling, natural `k = 2`) — good and entirely independent of X-1; it may win
  at the seal on structure plus a real measurement, it just cannot be smuggled in as
  "clears X-1" (§5.4 rule 1). Everything on the round-1 survival list stands.

**`draw_exit_gap` is unblocked** — written against the sentinel per §5.4, compiling for
testnet under explicit arming, refusing to ship until the read seals the value. F-D3's
mechanism lands now; the one thing that genuinely cannot be known yet stays honestly unknown.

## 12. Review round 3 (2026-07-15) — the structural argument is a derived bound, not narrative

Round 3 reviewed the round-2 disposition that parked the `2 × SEB` structural argument
outside the rule as a tiebreak narrative. Both halves of that disposition were graded: the
**refusal** to bolt a `max(2 × SEB, …)` floor onto the rule as a preference was correct —
that would have been F-W1's error re-imported (a number we like, wearing the rule's clothes).
The **parking** was not: made precise, the structural argument needs no preference because it
is **derivable** — from the §3 lemma alone, with no rate input (F-W6).

- **F-W6 (resolved — X-3 minted and folded in):** adjacent anchors sit exactly `SEB` apart;
  cohort windows overlap iff `W > SEB`; at `W = 1 × SEB` the overlap is measure-zero and the
  adversary reads cohort membership straight off the exit height — a clean partition of the
  crisis cohort that **X-1 never sees** (X-1 grades background cover, not cohort integrity).
  The smallest `SEB` multiple past the cliff is `2 × SEB`. Registered as **X-3** (§5.2a) and
  folded into the §5.4 rule as `max((N_t − 1)/ρ_x, 2 × SEB)` — in the rule with its cost
  stated, not in the narrative where it could be quietly invoked or quietly dropped. Two
  precision pins carried with it:
  - **Mixes-at-all, never merged:** at `W = 2 × SEB` the mixed fraction is only
    `(W − SEB)/W = 50 %`, improving continuously with no second cliff; the §8 arm 2
    two-anchor runs grade the actual fraction at the straddle.
  - **The cost, recorded beside the benefit:** the §5.3 predicate's LHS acquires a hard
    `20_000` floor in every measured world — a dense `ρ_x` read can no longer make the
    `σ_L`/queue question evaporate, so the F-W2 costing is unavoidable. This is the
    strongest argument against X-3; it was weighed and accepted because a rate-independent
    partition of the crisis cohort is precisely the harm the mechanism exists to prevent,
    and discovering the split at seal time would be the worse outcome.
- **Round-2 residue swept:** §5.1's "merging the two-anchor split into one mixed pool"
  overclaim corrected to the §5.2a mixes-at-all form; §5.4 rule 1 rewritten from
  narrative-tiebreak to the two-term `max`; the §11 "survives round 2" characterization of
  the structural argument ("may win at the seal on structure plus measurement") is
  superseded by this round — the bound now participates in every seal, not only favorable
  ones.

The sentinel, the F-W4 percentile commitment, and the F-W5 `N_t` obligation are untouched by
this round. `draw_exit_gap` remains unblocked; the seal rule it refuses against is now the
two-term form.

## Related documents

- [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §12.5–12.8 — F-D3 mechanism, F-D6
  anti-drift, R4 joint grade.
- [`ARCHIVAL_BOND_WI4_MEASUREMENT.md`](ARCHIVAL_BOND_WI4_MEASUREMENT.md) — the inherited
  threshold shape (`r < 2`), regime splitting, exchangeability pin, conditional-seal posture.
- [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) §5.1 — threshold-precedes-
  grading ordering.
- [`ARCHIVAL_REWARD_GATE_M1.md`](ARCHIVAL_REWARD_GATE_M1.md) §9.3 / §4 — the `K_COVER`
  provisional-sentinel pattern this doc's §5.4 mirrors (sentinel ⇔ 0, compile-time refusal,
  PF-9 seal-before-stressnet ordering).
- [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §2.2 — the L16 floor under
  `RELEASE_COOLDOWN_EPOCHS`.
- [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L13/§L17/§L18 — population attractor,
  swan table, the reconciled mobility model.
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) — swan-2/W8 synchronized-exit wargame (this doc converts its
  mechanism question into the §5.3 predicate; the wargame remains the empirical arm).
