# F-D4 — the a-priori exit-window derivation (Gate-6 §12.6)

**Status: committed a-priori 2026-07-15 — before any `draw_exit_gap` code exists and before any
exit sweep runs. Review rounds 1–3 run same day (§10–§12): F-W2 reclassified `σ_L` as a design
lever; F-W3 converted the genesis value to a `K_COVER`-pattern provisional sentinel with the
decision rule frozen (§5.4) — the value is sealed by the Phase 7.7 stressnet rate read, not
committed here; F-W6 folded the rate-independent X-3 anchor-merge bound (`W ≥ 2 × SEB`,
§5.2a) into the frozen rule with its cost stated.**

**UPDATE 2026-07-16 — round 4 (§15) is a premise audit, and it is blocking: the correlated
observable `T` (the "principal-side re-appearance") was never named, and no candidate
population for it survives the audit within this doc's seam (§2.1). Every bound in §5, the
§5.4 rule, the §13 derivation, and the §14 sweep findings quantify over `T` and are
conditional on its existence. X-3's harm model is retracted (F-W8, §15.3). The sentinel
holds the system in the correct frozen state throughout (§15.7).**

**UPDATE 2026-07-16 (later same day) — round 4 RATIFIED: deletion-with-tripwire (§15.4),
with the harness's deletion sequenced behind the §15.5 gate question, which is handed
forward to Gate-6 R4 with this audit attached — the re-homing call is R4's, not this doc's.
The `RELEASE_CHECKLIST.md` seal entry is removed by the ratification commit; the mechanism
deletion is a separate PR whose reviewer-map is §15.4 item 1.**

This is the artifact Gate-6 §12.6 requires first in the F-D3/F-D4 build
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

## 2. The adversary — and the observable it correlates against (rewritten by round 4)

Inherited from Gate-6 §12.1/§18.1 and the WI-4 S-3 observer, specialized to the exit seam:

- **Sees:** the full public chain — every `Unbond`/`HoldingsUpdate` connect height, the bond
  record (so `last_served_epoch`, hence **`H_0` is adversary-computable per persona**), the
  refund amount class — which is **one point, by construction**: `refund_atomic` is
  CT-balance-enforced on the wire to equal `bond_floor(current holdings)` — the public
  constant times the public shard count (`bond_connect.rs` `UnbondConnect::refund_atomic`,
  `HoldingsUpdateDropConnect::refund_atomic == FLOOR`). "They re-bonded for the exact same
  amount" is mandatory and universal, not a fingerprint; there is no amount channel to close
  because the masking is total by construction. Does **not** see FCMP++-hidden
  amounts/sources or circuit interiors (§10.9 isolation is the inherited conditioning
  assumption; the hooks measure the post-isolation residual).
- **Wants:** the `P` ↔ principal link. Rounds 0–3 modeled the exit as the highest-yield event
  for it: a cooldown-expiry release followed by principal-side value re-appearance at a
  characteristic latency `T`.
- **Channels (each quantifies over `T` — see §2.1):**
  1. **Fixed-offset tell** — without the draw, the release sits at a deterministic,
     per-persona-computable height `H_0`; any principal-side event at a stable offset from
     `H_0` is attributable. *Requires a principal-side event.*
  2. **Isolation** — an exit that is the only exit-class event within the observer's
     correlation resolution is uniquely pairable with the principal-side event that follows it.
     *Requires a principal-side event.*
  3. **Co-trigger clustering** — a market event synchronizes many exits; the *cohort
     membership* is public, and the intra-cohort assignment (which P maps to which
     principal-side re-appearance) is the residual the draw must scramble. The shared trigger
     is the catastrophic case (`16→1.01`, entry finding, §12.5). *Assignment maps onto
     principal-side events; without them there is nothing to assign.*

### 2.1 The correlated observable, named (round 4 — the audit rounds 0–3 never ran)

For any of the three channels to be non-empty, `T` must be a concrete event with a
population that produces it and a cadence. The candidates, exhaustively, with their
foreclosure class — the classes matter because they have **different reopen behavior**
(§15.4):

- **T-1 — a subsequent public bond post (rotation / re-entry).** The only *on-chain public*
  event a principal can produce after an exit. Structurally live as an event class (a
  `JoinMarket` is public), but: the funding link is FCMP++-hidden (the new bond's inputs are
  membership proofs — the chain does not say the refund funded it); the amount is
  FLOOR-shaped like every other bond post; only timing correlation remains — and **the
  population is empty by design.** Shard changes never exit (`HoldingsUpdate` swaps in place,
  bonded throughout); identity rotation is out of scope for V3.0 (**S-5**: long-lived `P`
  committed) and ruled a non-channel regardless (**T-A1**: the shard portfolio is the public
  identity — cosmetic rotation re-links on the portfolio, non-cosmetic rotation abandons the
  income stream); a cash-out leaves and does not return. Who exits and re-enters, why, how
  often: nobody the design gives a reason to, for no reason it doesn't serve better in place,
  at cadence ≈ 0. **Foreclosure class: policy + economics** (S-5 scope decision, T-A1
  economics) — *not* structure; reopens if rotation is ever brought into scope (§15.4).
- **T-2 — watching the refund land or move (on-chain value re-appearance).** **Structurally
  unrepresentable.** `refund_atomic` is the `bond_debit` source term **of the `Unbond`
  transaction itself** — the released value leaves as ordinary hidden outputs *inside the
  same tx that posts the exit*, CT-enforced to the public floor; slashability ends at the
  connect and the refund is never clawed back (`bond_connect.rs`). There is no later release
  event, no refund output whose arrival an adversary can watch, and the outputs' subsequent
  spends are FCMP++-hidden. The exit seam contains **exactly one public event** — the
  `Unbond`/`HoldingsUpdate` connect, P-attributed by construction — and everything after it
  is inside FCMP++. **Foreclosure class: structural** — the chain has no place to express
  this event; reopens only if a design moves the refund out of the posting tx (a scheduled
  release, a deferred-payout mechanism — §15.4 tripwire).
- **T-3 — network-observable principal-side activity.** **Already spent as conditioning.**
  The "Sees" line above inherits §10.9 default-on isolation as its conditioning assumption;
  the same fact cannot be assumed in the conditioning and harvested as the channel.
  **Foreclosure class: conditioning** — reopens only if default-on isolation is weakened
  (foreclosed independently by mission rule 2).
- **T-4 — the off-chain counterparty crossing (exchange deposit, KYC'd receipt).** **Real —
  and not this seam.** It is the `P`→user bridge, Gate-6 §18.13's seam, where the committed
  posture is *widen, not close* (a counterparty saw the money; the channel is irreducible)
  and the grading instrument is the S-2 exposure ledger. An exit-timing spread could serve as
  one widening instrument *there*, sized by *that* seam's analysis — not by this doc's
  on-chain rate model. **Foreclosure class: re-homed** (§15.5 raises whether GF-4's exit seam
  belongs there wholesale).

**The population paragraph rounds 0–3 owed and never wrote: within this doc's seam — on-chain
`P` ↔ principal — there is no concrete public event, no population, and no cadence.** T-1 is
an event class with an empty population; T-2 has no event; T-3 is double-counted; T-4 is
another seam. The three channels above are retained as the historical record of the rounds
0–3 model; each is empty absent `T`.

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
= 10` (the inherited posture anchor, `shekyl-staking-sim/src/standoff.rs:119` — a grading
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
Evaluating the two corners (the middle row is the round-1 planning instance, kept for §10's
audit trail — it is an interior point, not a corner):

```
N_P =  79, c = 0.02:   ρ_x = 1.58 × 10⁻⁴  ⇒   W ≥ 56_962 blocks ≈ 5.7 SEB
N_P =  80, c = 0.05:   ρ_x = 4.0 × 10⁻⁴   ⇒   W ≥ 22_500 blocks ≈ 2.25 SEB
N_P = 154, c = 0.20:   ρ_x = 3.1 × 10⁻³   ⇒   W ≥  2_922 blocks ≈ 0.3 SEB
```

The bound spans a **~19× box**. Any point picked from it is a point, not a derivation — this is
review round 2's blocking finding (§10 F-W3), and it is why the window's *value* is sealed by
the stressnet read (§5.4) rather than committed here. What the box does establish a-priori: at
**every** corner the bound sits above the entry `600` (≈ 5× at the loosest corner, ≈ 95× at the
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

> **RETRACTED — harm model empty (F-W8, round 4, §15.3).** The geometry below is correct and
> the derivation stands as arithmetic; the *harm* it prevents does not exist. "The adversary
> reads cohort membership straight off the exit height" gave the adversary nothing it lacked:
> cohort membership **is** `last_served_epoch`, public on the bond record, and every
> `Unbond` is P-attributed by construction. The partition only ever mattered as an input to
> intra-cohort *assignment*, and assignment is a function of `T` (§2.1) — phantom `T`, empty
> X-3. The bound goes into the §15 audit with everything else; nothing from this section is
> banked on geometry alone.

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

> **CLOSED by round-4 ratification (§15.4, 2026-07-16).** The rule's X-1 term is conditional
> on `T` existing (§2.1) and its X-3 term is retracted (F-W8). The deletion disposition is
> ratified: no seal, no `σ_L` spec, no lever-vs-queue arbitration — the rule survives only
> as the archived record and the §15.4 tripwire's re-run template. The sentinel already
> refuses shipping, so closure required no code change — the system was frozen in the
> correct state by construction (§15.7).

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
- **Unacknowledged builds refuse the sentinel** (`compile_error!` unless the
  `provisional-exit-gap-window` feature explicitly acknowledges the provisional state — every
  build, test or not, must opt in) — the shipping guard is the compile refusal, never the
  sentinel's runtime semantics. Testnet/stressnet builds arm it explicitly; KAT
  parameterization goes through the `kat_inject` constructor behind a permanent dev-only
  feature.
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
   **RESOLVED 2026-07-16 (§13): `N_t(exit) = 10`** — equal by derivation, not inheritance;
   every seam-variant fact lands on `W`, a graded arm, or its own regime row, and the one
   real asymmetry (repetition keyed to the public `P_id`) cannot be priced into a per-event
   anchor (§13.3 — routed to `σ_L` and the S-2 exposure ledger; premise since corrected by
   F-W9, §16: `m` is a bounded lifecycle count, the `σ_L` half of the routing is dead, and
   the S-2 half survives narrowed).
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
   `N_t` (F-W5 — **resolved, §13: `N_t(exit) = 10`, derived not inherited**; the arm carries
   the WI-4 N-sweep form — `r < 2` at every swept `N`, not only the anchor, per §13.4).
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
   **UPDATE 2026-07-16: landed.** `shekyl-standoff/src/exit.rs` — `ExitGapWindow` capability
   newtype (`wallet_default()` reads the sentinel; `kat_inject()` gated behind the permanent
   dev-only `exit-window-kat` feature — named per the `kat_forge` precedent so the PF-6a
   tripwire's `for_kat` grep stays scoped to `KCover`), typed `ExitGap`, `draw_exit_gap` via the shared
   unbiased `bounded_uniform`, no order coin. Sentinel mechanics per the `k_cover.rs`
   pattern: provisional ⇔ 0 (const-asserted), `compile_error!` unless the consumer enables
   the grep-able `provisional-exit-gap-window` acknowledgment feature (deleted at seal).
   Golden vector at a synthetic KAT window (10 007, deliberately not an SEB multiple) with a
   seal tripwire that fails at seal time to force the re-freeze; §8.3 negative control
   (`exit_release_population` shared-trigger arm) + two-property exit grade (uniformity,
   serial independence — no order axis) in `conformance.rs`. The F-D6 anchor landed as
   `shekyl_archival_retention::release_cooldown_anchor_height` — `H_cd` derived from
   `RELEASE_COOLDOWN_EPOCHS × SETTLEMENT_EPOCH_BLOCKS`, boundary-tested against
   `release_cooldown_elapsed` so the wallet's schedule and the consensus predicate cannot
   disagree; the `20_000` doc fossil in `shekyl-staking-sim/src/standoff.rs` is purged.
3. The exit-seam `N_t` re-derivation (F-W5) — before the sweep grades and before the seal.
   **UPDATE 2026-07-16: done (§13) — `N_t(exit) = 10`, derived a-priori; rule and box
   unchanged; the repetition asymmetry routed to `σ_L`/S-2 as a named residual** (routing
   since corrected by F-W9, §16 — `m` bounded, `σ_L` half dead, S-2 half narrowed).
4. The X-1/X-2 sweep per §8; grading folds into the R4 joint grade (Gate-6 §12.8) — never
   per-axis. **UPDATE 2026-07-16: the instrument was built and run** —
   `shekyl-staking-sim --exit-standoff` (`src/exit_standoff.rs`), all five §8 items built to
   the bar before any row ran; `EXIT_TARGET_ANON_SET` minted per §13.4; the §5.4 frozen rule
   encoded once (`frozen_rule_window`, planning-box corners pinned as its KAT). Pre-seal
   structural findings recorded in **§14** — the delivered X-1 cover is latency-gated
   (`ρ_x · σ_L`), and the §5.3 lever must be priced by the observer-derived required `σ_L`,
   not the spacing form. **It never landed on `dev`** — after round 4 (§15.4) the round-4
   record ships docs-only and the harness rides the §15.5 answer from the archive tag
   `archive/feat/fd4-exit-sweep-2026-07-16`.
5. **The seal:** Phase 7.7 stressnet read of `(ρ_x, N_x, σ_L)` → the §5.4 frozen rule fixes
   `DEFAULT_EXIT_GAP_WINDOW` → provisional flag cleared (stressnet-entry prerequisite,
   `RELEASE_CHECKLIST.md`, beside `K_COVER`/PF-9).
6. **UPDATE 2026-07-16 — round 4 inserted between steps 4 and 5, and it is blocking (§15):**
   the premise audit found no population for `T` within this seam (§2.1). Step 5 does not run
   in any branch as written. **RATIFIED same day:** deletion-with-tripwire (§15.4) — the
   `RELEASE_CHECKLIST.md` seal entry is removed by the ratification commit, the mechanism
   deletion is a separate PR (reviewer-map at §15.4 item 1), the harness's fate rides with
   the §15.5 hand-forward to Gate-6 R4. Steps 1–4 stand as the historical record; their
   outputs are conditional per the §1-status banner.

## 10. Review round 1 (2026-07-15) — the rate model vs the correlated-unbond adversary

The §9.1 adversarial review ran same-day. Inputs verified at source first (`TARGET_ANON_SET
= 10.0` at `shekyl-staking-sim/src/standoff.rs:119`; `DEFAULT_ENTRY_GAP_WINDOW = 600` at
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
  (§5.1 corners: `2_922` to `56_962` over the doc's own stated ranges `N_P ∈ 79–154`,
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
  `shekyl-staking-sim/src/standoff.rs:119` but was anchored to the **entry** seam; a
  constant's meaning is its consumer. The exit-seam `N_t` must be **re-derived a-priori and
  taken as it comes, before the seal** — the dependence is not innocent (`N_t = 9` would make
  `20_000` exact at the round-1 instance), which is exactly why it settles before the value,
  not after. Owed at §9 step 3; the §8.1 sweep arm grades at the exit-derived `N_t`.
  **RESOLVED 2026-07-16 — §13: `N_t(exit) = 10`, by derivation.**
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

## 13. F-W5 resolution (2026-07-16) — the exit-seam `N_t`, derived a-priori

> **CONDITIONAL on round 4 (§15) — deletion RATIFIED 2026-07-16.** The derivation is
> internally sound and unretracted, but its subject — the anonymity set an exit event needs —
> quantifies over `T` (§2.1), and the ratified disposition leaves no exit event to size a
> set for. The derivation stands as the record of *how* a seam-specific `N_t` is derived
> (its method survives as the §15.4 tripwire's re-run template).

**Result: `N_t(exit) = 10` — numerically equal to the entry posture anchor, by derivation,
not inheritance.** The trap this section was ordered ahead of the sweep to foreclose (§5.4
rule 3): `N_t = 9` would have made the round-1 planning instance's `20_000` exact. The
derivation below was run against the exit adversary's structure with the `W`-consequences
blinded; `9` has no model support anywhere in it, and the result leaves the §5.1 planning
box and the §5.4 rule exactly as frozen (the X-1 term reads `(10 − 1)/ρ_x`).

### 13.1 What `N_t` is at the exit consumer — and what it is not

The committed privacy bar is **not** `N_t`. It is WI-4's ratio bound `r < 2` per regime row
(`ARCHIVAL_BOND_WI4_MEASUREMENT.md`): adversary advantage strictly under twice blind
guessing, a bound whose *meaning* is N-invariant — committing an absolute `p` instead would
silently tighten or loosen the claim as realized cover moves with traffic. §8 arm 5 already
commits this doc's arms to that bar. `N_t` is the **posture anchor**: the steady-state cover
the window is *sized to deliver* (the §5.4 rule's X-1 term) and the point at which the
absolute instance of the ratio bound is evaluated (`P(link) < 2/N_t`; the entry instance is
`< 0.20` at `N = 10`). Two consumers in this doc: the frozen rule's `(N_t − 1)/ρ_x` term and
the §8.1 grading arm.

### 13.2 The derivation — every seam difference, examined for whether it moves the anchor

The anchor's determinants are the protected secret, the bar, and the advantage semantics.
Examine each seam-variant structural fact and ask where it lands:

- **The protected secret is identical.** Both seams guard the persona↔principal binding; a
  successful link at either endpoint attributes the persona's **entire** record to the
  principal (T-A1's lifetime observation window applies at both ends — there is no
  "prospective-only" entry harm or "retrospective-only" exit harm; the binding is one fact).
  The per-event absolute instance the anchor encodes (`< 0.20` per targeted persona per
  regime row) is a posture about that secret and the adversary's excess over blind guessing
  — seam-invariant.
- **Cover class differs — it moves the rate, not the count.** Entry cover is funding-shaped
  background (class-heterogeneous, high-rate); exit cover is exit-class events only (the
  `Unbond`/drop is publicly typed, so only other exiters are candidates). Under the
  `mean(1/set)` model the set counts true candidates in both cases; the class difference is
  why `ρ_x ≪` the funding rate and therefore why `W ≫ 600` (the §5.1 box) — it is already
  fully spent on `W`. Cover-*quality* differences (are exit-class decoys easier to rule
  out?) are what the WI-4 likelihood-ratio stress arm and the N-sweep pin (`r < 2` at
  **every** swept `N`, not only the anchor) exist to grade; pricing them into the anchor
  a-priori would double-count a measured quantity.
- **One-sidedness moves `W`, not `N_t`.** The one-sided window accumulates background over
  width `W`, not `2W` — an input the X-1 formula already carries — and its thin-regime
  gap-toward-max bias is a pre-registered graded residual (§8 arm 4). Nothing about
  ordering-prior availability changes how much cover constitutes the posture instance.
- **The trough cohort is its own regime row.** `N_x ≈ 3–8 < 10` in a crisis — but WI-4's
  regime-splitting discipline grades low-`N` rows separately and forbids averaging them
  into the steady-state row (a low-`N` pass is a weak absolute guarantee by construction).
  `N_t` anchors the steady-state row only; X-2 owns the trough.

Every seam-variant fact lands on `W`, on a graded arm, or on its own regime row. The
anchor's own determinants are seam-invariant; the anchor carries at `10`. That is the
derivation — not "the entry had 10," but "each candidate mover was examined and none moves
the anchor."

### 13.3 The one real asymmetry — repetition — and why it cannot be priced into `N_t`

> **UPDATE 2026-07-16 (F-W9, §16): the premise below is corrected — `m` is a bounded
> lifecycle count, not a growth variable.** Post-round-4, two of the three listed
> observations (the drop, the terminal drain) had already lost their principal-side
> observable with `T` (F-W7); §16 counts what remains against the landed FSM: **one**
> mandatory observable crossing (`JoinMarket`), two wallet-default-closeable optional
> classes, zero observable exits, rejoin unmodeled. The geometric-collapse clause and the
> `σ_L` half of the routing below do not survive the count; the S-2 half survives,
> narrowed (§16.3). Retained as filed per the additive-update discipline.

The exit seam observes the binding **repeatedly, keyed to the public `P_id`**: each
recurring `HoldingsUpdate`-drop, the terminal drain, and (for the binding as a whole) the
entry event itself — the adversary can intersect candidate sets across all of them. This is
the genuine structural difference from the single-shot entry seam, and it is exactly the
factor that **cannot** be bought with window width:

- **Intersection collapses geometrically.** With per-event principal-side candidate
  fraction `q`, expected decoy survivors after `m` observations `≈ N_pop × q^m`. Holding
  any fixed lifetime floor against growing `m` through per-event cover alone requires the
  per-event set to approach the entire population — no finite `N_t` delivers it.
- **An inflated anchor would re-import F-W3.** The union-bound inflation (`N_t ≈
  10 × (1 + E[m])`) requires `E[m]` — per-persona lifetime exit-event count, a pre-testnet
  unknown (`c ×` lifetime) — a number picked from a box, wearing a constant's clothes. And
  it pays real cost for no defense: `W` scales linearly in `N_t` (capital lockup, §6) while
  the intersection collapse is geometric.
- **Per-event composition is not per-axis multiplication.** Naively multiplying per-event
  linkage across events is the same category error the R4 joint grade exists to forbid
  (the CB-3 / WI-4 per-axis-multiplication error) — composition across observations of one
  binding is a *joint* question.

The repetition exposure therefore **routes where it can be defended**: the principal-side
re-appearance discipline (`σ_L` — what it widens is precisely each observation's
principal-side candidate fraction `q`, the base of the geometric collapse) and the **S-2
exposure ledger** (R5 cross-layer sign-off), whose scope is composition across events and
across seams (entry ∩ exit on the same `P_id`). Named residual, rule-21 shape — **reopen
criterion:** the S-2 composition model, when it lands, shows the per-event anchor (not `q`)
is the binding constraint on lifetime exposure; **re-evaluation shape:** re-derive this
section against that model in a design round of its own, before any window re-seal (a
post-seal `W` change is a §16.1 partition event, §7).

### 13.4 Consequences

- The §5.4 rule's X-1 term is `(10 − 1)/ρ_x = 9/ρ_x`. The §5.1 planning box is unchanged.
- The §8.1 arm grades at `N_t = 10` **and carries the WI-4 N-sweep form** (`r < 2` at every
  swept `N`) — if the exit's score-distribution tail is fatter than the entry's (one-sided
  draw, class-homogeneous cover), the arm fails there and the disposition is
  decorrelation-redesign, never a bar move (GF7 §5.1). The derivation is falsifiable by its
  own sweep.
- **The constant gets its own name at its consumer.** The exit anchor is minted as
  `EXIT_TARGET_ANON_SET` when the §8 sweep harness lands (concrete carrier: the harness PR),
  distinct from the sim's entry `TARGET_ANON_SET` even though numerically equal — a
  constant's meaning is its consumer, and the two anchors must be able to move
  independently. Until the harness exists, this section is the exit anchor's single source;
  no dead constant is pre-provisioned.

## 14. The §8 sweep instrument + pre-seal structural findings (2026-07-16)

> **RE-SCOPED by round 4 (§15) — deletion RATIFIED 2026-07-16.** Every graded number below
> is internally rigorous **and conditional on `T` existing** — the observer that produced
> them is exactly the artifact that exposed `T` as unpopulated (§15.6): the code had to have
> a variable where the prose had a phrase, and "what populates this?" became unavoidable.
> The findings stand as the archived record of what the mechanism would have delivered *if*
> the channel existed — the calibration reference the §15.4 tripwire's re-run inherits; none
> of them prices anything. The harness itself is sequenced behind the §15.5 hand-forward
> (§15.4 item 1). **Landing disposition (2026-07-16): the harness never landed on `dev`.**
> The round-4 record ships docs-only; the instrument lives at the archive tag
> `archive/feat/fd4-exit-sweep-2026-07-16` (branch `feat/fd4-exit-sweep`, HEAD
> `d049dcd27`), recoverable if the §15.5 answer re-homes the seam and wants it
> re-parameterized on the crossing observer. If R4 declines the re-homing, nothing needs
> deleting — not-landing was free; landing-then-deleting would have cost a PR and a fossil.

The pre-registered sweep was built and run as `shekyl-staking-sim --exit-standoff`
(`rust/shekyl-staking-sim/src/exit_standoff.rs`, on the archived branch — never on `dev`):
X-1 over the §5.1 planning-box corners in
the WI-4 N-sweep form, X-2 over `N_x ∈ {3, 5, 8}` × one/two-anchor × swept `σ_L` × the three
frozen-rule windows, the §8.3 shared-trigger negative control, the §8.4 thin-regime bias
statistics, and the §5.3 lever-vs-queue costing — all against this doc's committed `r < 2`,
worst row reported (`x1_rho1.58e-4_n20_sl1000`, `r = 18.49`), no post-hoc thresholds.
`EXIT_TARGET_ANON_SET` is minted at this consumer per §13.4. Every `ρ_x`/`σ_L`/`N_x` row is
a **swept pre-testnet assumption, not a measurement** — the Phase 7.7 read runs through this
same instrument and `frozen_rule_window` (the §5.4 rule's single code home, planning-box
corners pinned as its KAT) to seal the value.

### 14.1 The observer, pre-registered

Support-gated exact Bayes: the adversary sees the release height and the principal-side
re-appearance at latency `L ~ U[0, σ_L]`, and holds every release whose latency support
contains the re-appearance as equally likely — `P(link) = E[1/|support|]`, the optimal
per-event score under the model, no heuristic discount. Committed in the module docs before
any row ran (GF7 §5.1 ordering).

### 14.2 Finding — delivered X-1 cover is latency-gated: `ρ_x · σ_L`, not `ρ_x · W`

The nominal candidate set is everything in the window (`ρ_x · W` — what §5.1 sizes). But the
principal-side re-appearance prunes it: only releases within one latency-support of the
re-appearance survive, so the **delivered** support is `1 + ρ_x · σ_L`, W-independent
(asserted as a harness test). The sweep shows it flatly: at the sparse corner with
`N = 10`, the frozen rule gives `W = 60_000` and nominal cover 9.48, yet at
`σ_L = 1_000` the delivered cover is 1.15 and `r = 9.27`. **The window buys de-quantization
of the anchor and the X-3 merge; latency-gated confusability is bought by `σ_L`.** The §5.1
bound and the §5.4 rule are unchanged — `W` is still necessary (a release outside the cover
population's span has no candidates at all) — but `W` alone was never sufficient, which is
what F-W2's lever reclassification said in cost terms and this observer proves in advantage
terms.

Consequence, priced: the exit clears `r < 2` at the §13 anchor iff `σ_L` satisfies the exact
inversion `E[1/(1 + Pois(ρ_x σ_L))] ≤ 2/N_t` (`required_sigma_l` in the harness):
`31_425` blocks (≈ 43.7 days at 120 s) at the sparse corner, `12_413` (≈ 17.2 days) at the
planning instance, `1_613` (≈ 2.2 days) at the dense corner. The §5.3 spacing form
`σ_L ≥ W / N_x` is **not the right price** — at the sparse corner it asks for 7 500–20 000
where the observer requires 31 425 (under-delivers), at the dense corner it asks for
2 500–6 667 where 1 613 suffices (over-pays). The lever-vs-queue costing table now runs on
the observer-derived `required σ_L`, and at every swept corner the lever (paid by exiters
only, mean `σ_L / 2`) undercuts the queue (`k × SEB / 2` paid by every exit) — the queue is
reached only if the wallet discipline cannot plausibly hold the required spread, exactly the
§5.3 reach condition.

### 14.3 Finding — the X-2 trough is priced, and marginal confusability is not `r < 2`

The §5.2 condition ("expected spacing ≤ σ_L") makes cohort members *confusable at all*; the
sweep shows that under the exact-Bayes observer this delivers marginal advantage reduction,
not the bar: `r < 2` at cohort size `N_x` needs `p_assign < 2/N_x`, i.e. the support must
hold ≈ `N_x / 2` cohort members, which puts `σ_L` on the **`W/2` scale**, not the `W / N_x`
scale. Of the 72 swept X-2 rows exactly one clears (`W = 20_000`, `N_x = 3`, one-anchor,
`σ_L = 12_500` → `r = 1.80`). Rows are reported failing per GF7 §5.1 — and the disposition
is the pre-committed one: this is the **decorrelation-redesign signal surface** the §5.3
costing exists to arbitrate, not a bar move. What the trough actually needs (wide `σ_L`
discipline vs. the W8 queue widening effective `σ_L` for everyone) is the seal-time decision,
now with its numbers; the trough row grades in its own regime per WI-4, never averaged
against the steady state.

### 14.4 Certifications (the instrument can fail, and mixing is as predicted)

- **X-3 coverage boundary:** measured cross-anchor overlap matches `(W − SEB)/W` at all
  three windows (0.500 at `2 × SEB`, 0.667 at `3 × SEB`, 0.833 at `6 × SEB`) — the §5.2a
  *mixes-at-all* claim certified, and only that; cross-anchor confusion grows with `σ_L`
  (0.51 at `N_x = 8`, `σ_L = 12_500`, `W = 60_000`) but never approaches "merged".
- **§8.3 negative control:** a draw-skipping cohort is caught as clustered
  (`max_same_height_share = 1.000` vs `0.200` drawn). Recorded with it: the *assignment*
  observer is provably blind to the skip (`r = 1.00` on the skipped world — all releases at
  one height are symmetric), which is **why the control keys on clustering-detection**, as
  §8.3 required.
- **§8.4 thin regime:** gap positions at the trough row are unbiased (mean fractional
  position 0.502, upper-half share 0.502) — no gap-toward-max analogue of the entry's
  `1.86` finding under the one-sided draw.

### 14.5 What changes and what does not

Nothing in §5.4 moves: the rule, the sentinel, the conservatism percentile, and the anchor
are all as frozen. What the sweep adds is the **required-`σ_L` surface** — the §5.3 joint
constraint now has its exact form (`E[1/(1 + Pois(ρ_x σ_L))] ≤ 2/N_t` for X-1; support ≈
`N_x/2` for the trough) in code beside the rule, so the Phase 7.7 read prices the lever and
the queue mechanically. Grading folds into the R4 joint grade (Gate-6 §12.8) jointly with
amount-band, holdings-stratum, and output-count — never per-axis.

## 15. Review round 4 (2026-07-16) — the premise audit: the observable was never named

Rounds 1–3 audited the rate model, the derivability of the value, and the geometry of the
bounds — each internally rigorous, each downstream of a premise no round examined: **that
the event the adversary correlates against exists.** Round 4 audits the premise. Its verdict
is not that the arithmetic is wrong; it is that the arithmetic is *about nothing* unless `T`
has a population, and the §2.1 audit finds none within this seam. This is not a GF7 §5.1 bar
move — a bar governs how measurements are graded; a premise found false is upstream of every
measurement. Per the standard this round applies: **phantom channels are deleted, not
softened.**

### 15.1 F-W7 — the phantom-`T` finding (blocking)

§2 as written by rounds 0–3 defined the adversary's *sight* with real precision (connect
heights, the bond record, adversary-computable `H_0`, the refund amount class) and defined
the thing it *correlates against* as "network-observable principal-side activity timing" and
"principal-side value re-appearance at a characteristic latency" — never named, never
populated. Every one of §2's three channels quantifies over that event: the fixed-offset
tell needs a principal-side event at a stable offset; isolation needs the principal-side
event that follows; co-trigger clustering needs re-appearances to assign. Remove `T` and all
three are empty. Four rounds of review — the 19× planning box, the sentinel conversion, the
X-3 geometry, the `N_t` derivation, the 71/72 sweep failures, the 17–44-day `required-σ_L`
surface — audited arithmetic downstream of the unexamined existential.

**The wire-shape verification that makes it structural, not merely unnamed** (source:
`bond_connect.rs`): `refund_atomic` is the `bond_debit` source term **of the `Unbond`
transaction itself**, CT-balance-enforced to `bond_floor(current holdings)`; the released
value leaves as hidden outputs inside the same tx that posts the exit; slashability ends at
the connect and the refund is never clawed back. There is no scheduled release, no refund
arrival to watch, and FCMP++ hides every subsequent spend. The seam contains exactly one
public event — the P-attributed connect — and the chain has no place to express a second.

**The amount channel was never open**: every bond post and every refund is the public floor
times the public shard count, the same number for everyone always, enforced by CT balance on
the wire. Cover was never something to add; the masking is total by construction, and the
only cover variable that ever existed was temporal density — which is why the entire model
reduced to `ρ_x`, and why the model's collapse is total when `T` collapses.

### 15.2 The population audit

Run in §2.1, summarized: **T-1** (rotation/re-entry — the only on-chain public candidate)
has an empty population by design — in-place `HoldingsUpdate` removes the reason, S-5 scopes
rotation out, T-A1 prices it as identity-suicide-or-relink; foreclosure class **policy +
economics**. **T-2** (on-chain value re-appearance) is structurally unrepresentable;
foreclosure class **structural**. **T-3** (network) is the conditioning assumption
double-counted; foreclosure class **conditioning**. **T-4** (off-chain counterparty
crossing) is real and belongs to Gate-6 §18.13's seam under its committed widen-not-close
posture, graded by the S-2 ledger; foreclosure class **re-homed**. The classes are kept
distinct deliberately: they have different reopen behavior, and collapsing them is how a
tripwire rots (§15.4).

### 15.3 F-W8 — X-3's harm model, retracted

The §5.2a geometry is correct arithmetic about an empty harm. Cohort membership is
`last_served_epoch` — public on the bond record — and every `Unbond` is P-attributed by
construction, so "the adversary reads cohort membership off the exit height" gave it nothing
it didn't already have; the partition only ever mattered as an input to intra-cohort
*assignment*, which is a function of `T`. This retracts a bound that F-W6 folded into the
§5.4 frozen rule one round earlier — recorded plainly because it is the fourth instance of
the same failure shape in one track (a number acquiring a justification after being liked:
first the rate narration around `20_000`, then the stacked-marginal conservatism, then the
re-cut temptation F-W5 was minted against, now geometry). Banking `2 × SEB` "because the
geometry survives" would have re-committed the failure the round was naming. Nothing from
this track is banked past the audit.

### 15.4 Disposition — deletion with a tripwire (RATIFIED 2026-07-16)

The population paragraph could not be written (§2.1); per this round's standard the channel
is deleted, not softened. **Ratified 2026-07-16, with one sequencing amendment recorded at
item 1.** Rule-21 shape:

1. **The rejection.** The exit-timing decorrelation apparatus guards a channel with no
   population: delete `draw_exit_gap` and its surface (`exit.rs`, the
   `ExitGapWindow`/`ExitGap` newtypes, `DEFAULT_EXIT_GAP_WINDOW` + both features, the exit
   arms in `conformance.rs`, the golden-vector/seal-tripwire tests) and the
   `RELEASE_CHECKLIST.md` seal entry (removed by the ratification commit). Dead mechanism is
   audit surface (rule 15); git history and this doc are the archive — the doc retains every
   number so the record survives the code. The F-D6 anchor derivation
   (`release_cooldown_anchor_height`) and the cooldown itself are **not** in scope: they
   exist for slashability/backlog-claim reasons and predate this analysis. The deletion-scope
   enumeration above is the reviewer-map for the deletion PR; anything it misses is a
   map-failure, not a license.

   **Sequencing amendment (ratification):** the `--exit-standoff` harness is **out of the
   mechanism-deletion PR's scope** — its fate rides with the §15.5 gate question. If Gate-6
   R4 re-homes the seam to §18.13, the harness is the natural instrument for that seam
   (re-parameterized on the crossing observer), and deleting-then-resurrecting would make
   the deletion PR fight the re-homing PR; if R4 declines the re-homing, the harness is
   deleted then. It is **not** kept as a monument to §15.6's finding — the asset is the
   lesson, not the artifact; keeping code alive as a monument is the fossil pattern in a new
   costume. And the rule-15 case for its eventual deletion is stronger than "dead code": a
   harness that grades a phantom channel is a **trigger with no gate** — it will happily
   produce a report, and reports get believed. That is worse than absence.

   **Landing disposition (2026-07-16, same day):** the sequencing resolved in the cheapest
   direction — the harness **never landed on `dev`**. PR #313 carried the mechanism
   (`exit.rs` and its surface, now the deletion PR's real scope) but not the instrument;
   the round-4 record ships docs-only. The branch is preserved at
   `archive/feat/fd4-exit-sweep-2026-07-16` (`feat/fd4-exit-sweep`, HEAD `d049dcd27`):
   if the §15.5 answer re-homes the seam, the instrument is recovered and re-parameterized
   there; if not, it stays unlanded and there is nothing to delete. "Deleted then"
   above therefore reduces to "not resurrected."
2. **The reopen criteria (substrate-anchored).** The finding is conditional on "no public
   principal-side event exists," which is true of the chain **as designed today**. The
   channel reopens — and this analysis is the thing to re-run — if any future design mints
   one: **(a)** identity rotation brought into scope (S-5 revisited, V3.1+/V4); **(b)** any
   mechanism that moves the refund out of the posting transaction (a scheduled release, a
   deferred payout, a claim-then-collect shape); **(c)** any new public wire term keyed to
   the principal rather than to `P`; **(d)** weakening of §10.9 default-on isolation
   (independently foreclosed by mission rule 2, listed for completeness). Delete the
   mechanism, keep the tripwire — otherwise someone re-mints the event in three years and
   nobody remembers the exit standoff was deleted because its channel didn't exist.
3. **The re-evaluation shape.** The reopening design's review round 1 re-runs the §2.1
   population audit *for the newly minted event* — concrete event, population, cadence —
   with the observer **pre-registered as code before any grading** (§15.6). §13 is the
   template for re-deriving the seam's `N_t`; the archived harness is the template for the
   instrument; the archived §14 numbers are the calibration reference. The re-run lands in a
   design round of its own, not as a rider on the minting PR.

Until ratification: no `σ_L` spec, no lever-vs-queue arbitration, no seal preparation, no
downstream status sweeps (Gate-6 §12.5–§12.8, `IMPLEMENTATION_INDEX.md`, `FOLLOWUPS.md`
swan-2/W8, `RELEASE_CHECKLIST.md` — the ratification commit is the named carrier for all of
them, rule-21/rule-94 shape). **DISCHARGED 2026-07-16: the ratification commit carried all
four sweeps** (Gate-6 §12.5/§12.6/§12.8 + revision history + §11.8 method note 2; index rows
95–98; FOLLOWUPS swan-2/W8 closed as posed; the checklist seal entry removed). What remains
owed: the mechanism-deletion PR (item 1's reviewer-map) and the Gate-6 R4 answer to §15.5.

### 15.5 The gate question (HANDED FORWARD to Gate-6 R4, audit attached — 2026-07-16)

If T-4 is the only live channel, then the exit's timing exposure is not `P` ↔ principal at
all — it is the `P` → user crossing, §18.13's seam, whose posture is already *widen, not
close* and whose instrument is the S-2 ledger. F-D1's amount concern (a drain amount
matching a reward subsum, observable at a counterparty) lands at the same crossing — the
on-chain amount channel was already closed by construction (§15.1); what survived of F-D1
was always the off-chain subsum match at a counterparty. If both halves of GF-4's exit seam
reduce to the off-chain crossing, GF-4 is substantially a principal↔user finding wearing a
`P`↔principal label — which would **re-home it, not just re-scope it**.

**Ratification disposition: raised and handed forward, not answered here — the call is not
F-D4's to make.** The re-homing has a consequence this doc cannot absorb: R4's four-axis
joint grade loses its on-chain timing axis, and if the timing input is phantom the joint
grade is not "run it with one fewer term" — it is a **different grade over a different seam
with a different posture** (widen-not-close, graded by the S-2 ledger rather than a rate
model). That is Gate-6 R4's structural decision. This audit travels with the hand-forward
(Gate-6 §12.8 carries the receiving item); the harness's deletion is sequenced behind the
answer per §15.4 item 1. **F-W9 (§16) rides the same hand-forward:** the §13.3 repetition
premise is corrected before R4 takes the question — `m` is a bounded lifecycle count, so
the on-chain composition a re-homed grade would inherit is finite and GF-7-shaped, and the
§16.4 wallet-default proposal (with its growth-gating cost) is part of what R4 receives.

### 15.6 The methodological finding — observer-as-code (the asset this track produced)

Four rounds of prose review never surfaced F-W7. The prose could say "principal-side
re-appearance" indefinitely; **the harness had to declare a variable**, and once the
observer existed as code, "what populates this?" became unavoidable — the §14 instrument is
simultaneously the most rigorous artifact of the track and the one that exposed the track's
premise as empty. Standing requirement, proposed for every seam this project grades from
here on: **the observer is pre-registered as code before any row runs** — not as a
methods paragraph, as an executable artifact whose inputs must be named to compile. This
track is the proof case: the requirement's cost is one module; its yield here was catching a
phantom channel before genesis instead of after, with months of per-operator dead capital on
the line. Recorded beside Gate-6 §11.8's method note ("a constant's meaning is its
consumer") as the same lesson one level up: *a channel's meaning is its observable.*

**Adopted at ratification (2026-07-16)** — with the framing made explicit: this is not a
consolation prize for a deleted track; it is the most reusable thing the track produced.
Four rounds of rigorous arithmetic were worth nothing, and what exposed that was being
forced to write the observer as code with a variable in it. The lesson transfers; the
artifact does not (§15.4 item 1 — the asset is the lesson, not the code).

### 15.7 The `K_COVER` pattern, vindicated

The outcome vindicates the sentinel pattern rather than merely surviving it. At the moment
the premise collapsed, the system was already in the correct state — `DEFAULT_EXIT_GAP_WINDOW`
refuses to compile into anything real, so there is nothing to un-ship, no flag day, no
partition risk, no rollback: the freeze that was built to wait for a *measurement* turns out
to hold equally well while the thing being measured is audited out of existence. A failure
mode the pattern was never designed for, handled by construction. The pattern's claim —
*a plausible-looking provisional value is unrepresentable, not merely discouraged* — is
exactly what kept four rounds of internally-rigorous arithmetic from ever touching a
shipping build.

Mechanically, the refusal was always a turnstile, not a wall: `compile_error!` fires only
on unacknowledged builds; a testnet build enables the grep-able
`provisional-exit-gap-window` feature and runs against the sentinel, so "who is shipping a
provisional value" is a search, not an audit. The planned end-state — read the numbers
early in the Phase 7.7 window → apply the frozen rule → set the constant → delete the flag,
with the golden vector's seal tripwire (pinned at the synthetic `10_007`) failing on
purpose to force the KAT re-freeze — was the `K_COVER` pattern end to end. Round 4
dissolved the question for F-D4 (phantom `T` ⇒ nothing to measure), and the sentinel's
job was precisely to hold the line until that was found out. Which it did.

### 15.8 The measurement-class finding — mechanism vs. economics (added at ratification, 2026-07-16)

A second finding, extracted at ratification, is **bigger than F-D4 and was true before
F-W7**: even had `T` been real, the Phase 7.7 seal would have been unsound, because two of
the three inputs the read was queued to produce are unmeasurable on a testnet **in
principle**, not merely hard:

- **`σ_L`** — the latency to an event that doesn't occur. Empty, not noisy.
- **`N_x`** — a market-panic cohort size. A testnet has no money at stake and therefore
  cannot produce a panic; a scripted synthetic mass-exit measures the script.
- **`ρ_x`** — exit rate, i.e. profit-taking cadence: an economic behavior. On a testnet it
  is whatever the participants' harness decides to do that afternoon.

The Phase 7.7 read would have returned a measurement of our own test plan, echoed back with
the authority of "measured" — and a genesis constant would have been sealed on it.

**The filter (adopted as a standing method posture, second home at Gate-6 §11.8 method
note 3):** before queuing any constant for a stressnet seal, classify the measurement.

- **Mechanism** — does the partition fire, is the draw unbiased, does the determinism KAT
  hold on aarch64, does timing behave under load. A testnet reproduces these faithfully,
  because the software doesn't know the money is fake. `K_COVER`'s §14.4 partition run is
  this class — which is why it is gradeable and why PF-9 is a sound gate.
- **Economics** — exit rate, churn, profit-taking cadence, panic cohort size, mobility.
  A testnet cannot produce these; every one is a function of real value at risk.

If a constant needs an economics number, the stressnet is the wrong instrument, and there
are exactly three honest exits: **derive it structurally** (X-3's instinct — right shape,
even though its particular harm model was empty), **design so the constant isn't needed**,
or **ship it knowingly under-determined with a post-genesis reopen** — which for a
genesis-frozen value means *not shipping it at all*.

The filter was run across the PF-9 / Phase 7.7 queue at adoption (grep-anchored,
2026-07-16): the only seal queued behind stressnet entry is `K_COVER` (mechanism — passes);
the other Phase 7.7 entries (F11-S Windows-midrange bench re-measurement, historical
reference-block/reorg exercise, archival multi-staker path, the `tests/stressnet/README.md`
acceptance criteria) are all mechanism exercises, and the FA-6 wire lock is a sequencing
pin, not a measurement. One live hit: GF-7's *effective-vs-nominal cover* residual is
testnet-gradeable only on its observer machinery — the cover *level* is driven by the
post-isolation network-event rate, an economics number, unfalsifiable pre-genesis, and was
subsequently reclassified as the fifth WI-4 §13.5 standing conditional (Gate-6 §12.8;
the `1.86` was verified computed on nominal cover, so the conditional is load-bearing —
on realized per-event exposure, the sweep below showing the gate's `r` itself is
cover-blind). The hit's follow-through demonstrates the filter's
constructive half: the level is economics, but the *sensitivity sweep* — how the model's
own `r` and `P(link)` move with cover — is mechanism (a property of the model), and was
run the same day (`shekyl-staking-sim --gf7-breakeven`: worst-arm `r` clears the bound
at every row of `N ∈ [2, 16]`, never trending toward the bar as cover thins — `r < 2` is
structurally blind to cover, so cover was never gated by it;
no per-event monitoring threshold exists, the candidate `P(link) ≤ 0.2` being the
nominal-cover assumption restated by identity; full reading WI-4 §13.5, whose instrument
for the conditional is the S-2 lifetime ledger).
`DEFAULT_EXIT_GAP_WINDOW` never would have passed this filter — and absent round 4, that
would have been discovered at the stressnet, after building the harness, instead of now.

## 16. F-W9 (2026-07-16) — the repetition premise re-walked: `m` is a lifecycle count, not a growth variable

> **Scope note.** §13 is stamped conditional-on-round-4 and the mechanism's deletion is
> ratified (§15.4); this section reopens neither. It corrects §13.3's **premise** — a
> correction Gate-6 R4 needs in hand when it answers §15.5, because it changes what the
> re-homed seam would even be composing. Homed here so the audit trail stays in one
> document; travels with the §15.5 hand-forward (Gate-6 §12.8 carries the receiving item).

### 16.1 The finding — nobody counted the exponent

§13.3's intersection argument quantifies over `m`, the number of times the adversary
observes the `P`↔principal binding, and inherited `m` as "grows" (its observation list:
"each recurring `HoldingsUpdate`-drop, the terminal drain, and the entry event itself").
Round 4 had already emptied two of those three: the drop and the terminal drain carry only
a `P`-side timestamp — their principal-side observable was `T`, found phantom (F-W7). What
remained was entry-side repetition, and it was never walked against the state machine.
Walked against the landed FSM (`bond_post.rs`, all four `post_kind`s — there is no fifth;
Gate-6 §10.6's "top-up" is prose for the `HoldingsUpdate`-add *direction*, not a kind):

| Lifecycle event | Occurrence | Principal-side observable? † |
|---|---|---|
| `JoinMarket` | **Mandatory, one per bonded life** (`verify_join_market_bond_post` rejects an existing record, `bond_post.rs:540`) | **Yes — as an event, not an entity**: the funding spend's *existence and timing* are public (key-image spends: the GF-7 seam); its **source is FCMP++-hidden** and carries no identity |
| `HoldingsUpdate`-add | Optional | **Yes** — fresh `bond_credit == FLOOR` (`:257`), funded like a join |
| `Rebond`, standing-only (the common case) | Post-slash | **No** — `bond_credit == 0` by Pin 2 (`:418-420`): the slash burned the FLOOR and removed the shard atomically, so *no value moves at all* |
| `Rebond`, growth / terminal reinstatement | Optional, rare | **Yes** — carries credit; the same funding seam as add |
| Reward emission claim | Recurring | **No** — `P`-side only; reward-output spends carry no `P`-typing on the wire (Gate-6 §10 tx-type table) |
| `HoldingsUpdate`-drop | Optional | **No** — the refund is the in-tx `bond_debit` source term, CT-hidden (§15.1, T-2) |
| `Unbond` (voluntary) | Optional | **No** — same in-tx hidden refund; observably silent |
| Terminal slash | — | **No transaction exists** (`NothingToUnbond`, `:586-588`; collateral burned, nothing returns) |
| Rejoin (new `JoinMarket` after the `Unbond` pop) | Representable | Unmodeled — **self-harm class**: slot-indexed derivation (`archival_p.rs:299`, `(master_seed_64, network, format, p_slot)`) makes fresh-`P` the wallet's structure, and consensus does not gate self-harm (the add-shard precedent, `bond_post.rs:237-240`) |

> **† Every "Yes" in this column names an observable *event*, never an entity.** What is
> public is the funding spend's existence and timing; its source is FCMP++-hidden and
> carries no identity. GF-7's `P(link) ≈ 0.186` is accordingly the chance of linking `P`
> to one **anonymous** transaction — it becomes identity-bearing only if the far end was
> already attributed off-chain (the T-4 crossing, §15.5). Reading a "Yes" as "a
> principal-side *referent* is visible" reconstructs the phantom this track deleted
> (F-W7): the column has events in it, not entities.

**The enumeration: mandatory observable crossings = 1 (`JoinMarket`). Optional crossing
classes = 2 (`HoldingsUpdate`-add; credit-bearing `Rebond`). Observable exits = 0, on both
branches — the voluntary branch is CT-hidden inside the posting tx, the slash branch emits
nothing.** Note the amount channel stays empty across all rows: `bond_credit` is
`bond_floor(holdings)` — FLOOR × shard count for `ShardSetCompact`, a flat FLOOR for
`CompleteTree` (`bond_floor.rs:28-38`) — a pure function of the public holdings
descriptor, so it carries zero grouping signal beyond the wire itself.

### 16.2 What falls in §13.3

- **The geometric-collapse clause needs a growing `m`.** Its own words: "holding any fixed
  lifetime floor against growing `m` … no finite `N_t` delivers it." With `m` a bounded
  count, `N_pop × q^m` is computable per enumerated case; at the mandatory `m = 1` it is
  `N_pop × q` — **GF-7's per-event grade *is* the on-chain lifetime grade**, per persona,
  per observer class, at nominal cover (the cover qualifier is WI-4 §13.5's fifth
  conditional, unchanged by this section).
- **The `E[m]` objection dissolves.** §13.3 rejected union-bound anchor inflation because
  `E[m]` was "per-persona lifetime exit-event count, a pre-testnet unknown" — economics.
  But the *mandatory* count is not economics; it is the lifecycle, readable from the state
  machine — a mechanism-class fact under §15.8's filter. The optional-event *rate* is
  economics, but the optional events are wallet-default-closeable (§16.4), so the
  exponent's bound is a design choice, not a market outcome.
- **The `σ_L` half of the residual's routing was already dead** (§15.4 deleted the lever);
  F-W9 removes the residual's last claim on it. The S-2 half survives, narrowed (§16.3).

### 16.3 The near-miss, recorded — cross-persona intersection, raised and withdrawn

During this correction's own drafting, "the collapse relocates to `k`" was proposed: a
principal running `k` personas makes `k` `JoinMarket` fundings from one wallet —
intersect across them. **Withdrawn for want of a linking key, before ratification.**
§13.3's intersection works because its observations carry a public linking key — "keyed
to the public `P_id`" — telling the adversary *which candidate sets to intersect*. Across
personas no such key exists: funding sources are FCMP++-hidden (spends don't reveal
sources); the amount is publicly determined by the wire (§16.1), zero grouping signal;
entry timing is decorrelated by the per-event independent draw (the shared-trigger case
is the entry standoff's graded arm); network position is spent as §10.9 conditioning.
Absent the key, composing `q^k` presupposes the grouping — which is precisely the
protected secret. Clustering over an unknown partition is a categorically weaker problem
than intersection over a known key, and conflating them is F-W7's shape again: a
mechanism presupposing an observable nobody named. Caught at draft this time, one turn
after the lesson was written — §16.5's check demonstrating on its own author.

What survives is narrower and already owned: **(a)** shared-trigger clustering of
same-principal fundings — not a new seam; the entry standoff's existing graded case,
plus funding-batch spacing as wallet discipline (F-D2's class); **(b)** the off-chain
counterparty (T-4), whose *own books are the linking key* — its cross-persona view is a
sub-case of the §15.5/§18.13 row, not a second row. S-2's cross-persona job re-forms
accordingly: **search for unnamed public linking keys** (e.g. cross-persona portfolio
correlations — shard `s` dropped by `P1` and added by `P2` at nearby heights; probably
weak, since shards are non-exclusive, but exactly the class the search covers),
pre-registered as code per method note 2 — never compose an intersection that was
assumed.

### 16.4 The proposal handed forward — close the optional crossings at the wallet (R4's call)

The GF-4b lineage filter already classifies output lineage and structurally drops
`ExternalTransfer` from emission backing
([`ARCHIVAL_GF4B_BACKING_LINEAGE.md`](ARCHIVAL_GF4B_BACKING_LINEAGE.md); possession of a
`BackingSet` is proof). Aiming the same filter at the two optional-crossing funding paths
(`HoldingsUpdate`-add, credit-bearing `Rebond`) makes **self-funding the only thing an
honest wallet can build** — converting the optional crossings into named deviations and
the exponent's bound from behaviour into the honest-wallet default. Two constraints
stated with the proposal, not after it:

1. **It is a wallet default, not a consensus invariant.** Consensus cannot classify
   FCMP++-hidden funding inputs, and in-circuit lineage is the exact opposite of F-D1's
   strip direction. "Unrepresentable" holds at the honest-builder layer only.
2. **Its cost:** self-funded growth gates portfolio expansion on accumulated rewards
   ≥ FLOOR — a young persona cannot add a shard before its rewards cover one. "Costs a
   rational operator nothing" is true only past that accumulation threshold.

Whether the price is right is the R4 decision this proposal rides to, with §15.5.

### 16.5 The lesson — before grading a composition, enumerate the events that compose

Four rounds of increasing precision on `q`; `m` — the exponent, which dominates — was
inherited as "grows" and never counted. The near-miss in §16.3 is the same lesson
catching its own author one turn after it was named. Recorded beside observer-as-code
(§15.6 / Gate-6 §11.8 method note 2) and the measurement filter (§15.8 / note 3) as
**Gate-6 §11.8 method note 4**. Corollary for R5: with the events enumerable, S-2's
composition question is **finite** — a tractable instrument, not a research project
(relevant to the standing of the S-2 item, "build first" and unbuilt since round 0).

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
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) — swan-2/W8 synchronized-exit wargame (this doc converted its
  mechanism question into the §5.3 predicate; closed as posed by round 4 — the wargame's
  observer correlates against the phantom `T`; reopen rides the §15.4 tripwire, and any
  re-homed crossing wargame is part of the §15.5 hand-forward).
