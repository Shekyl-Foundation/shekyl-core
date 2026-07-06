# WI-4 — GF-7 measurement round: the graded genesis gate

> **Status: design spec / acceptance doc (WI-4 design round 1, 2026-07-05,
> `feat/wi4-gf7-measurement`, stacked on `feat/wi3-dispatch-driver`).**
> Spec-first per rule `05-system-thinking`; process shape per
> `26-sub-pr-design-discipline` (this slice defines the graded genesis gate
> for the coin's core principal↔`P` unlinkability claim — a priority-2
> privacy surface — so it gets an explicit design round *before* any grading
> code lands).
>
> **This document is the a-priori threshold artifact required by
> [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) §5.1
> constraint 1 and by [`ARCHIVAL_BOND_WI3_DISPATCH.md`](ARCHIVAL_BOND_WI3_DISPATCH.md)
> §5 reconvergence-gate leg (a).** The strict-ordering rule it exists to
> honor: **§3's threshold is committed and reviewed BEFORE any correlator is
> built or any sweep is run** (§5.1 constraint 1). A number chosen after
> seeing the correlator's output certifies "we picked a bar the architecture
> clears," not "the architecture clears a bar the adversary can't" — a green
> gate over a false floor, the worst failure shape for a privacy-maximalist
> coin. The §4 correlator spec, §5 controls, §6 distributions, and §7
> dispersal-sweep plan are the pre-committed measurement design that the
> §11 implementation round builds *to*, never *around*.
>
> **Authority:** [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md)
> §10.12 (S-1 the load-bearing seam; S-3 "privacy must be measured";
> `P(link | T_obs)` deliverable) + §10.9 (isolation conditioning) + pass-4
> "conceded function vs. protected linkage";
> [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) §2 (joint
> adversary), §5 (correlator contract), §5.1 (the five binding constraints);
> [`ARCHIVAL_BOND_WI3_DISPATCH.md`](ARCHIVAL_BOND_WI3_DISPATCH.md) §3.2 (the
> intra-tick dispersal draw WI-4 must sweep), §5 (reconvergence gate);
> [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*Funding-seam entry
> standoff* (the funding-axis harness, its recommended posture, and its four
> conditionalities, inherited here as constraints); `docs/FOLLOWUPS.md` GF-7
> genesis-blocker entry. Index row: `WI-4` in
> [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).
>
> **Timeframes (rule 05):** *now* — the graded genesis gate for GF-7
> funding-seam unlinkability; produces the pre-genesis-seal evidence GATE6
> S-3 demands. *Mining-era end* — no coupling: the correlator grades logical
> block-timelines, not economics; the sim re-runs unchanged. *V4* — no
> cryptographic surface: the measurement is sim-side against a modeled
> observer of *public* timing, independent of the signature stack that
> migrates in V4.

## 1. Scope

WI-4 is the **measurement round** the hook spec (§0) deferred until a
bond-post is actually dispatched on a timeline. WI-3 built that dispatch;
WI-4 grades it. In scope:

1. **The a-priori threshold** on `P(link | T_obs)`, derived from a stated
   S-1 adversary-advantage claim and committed here **before grading**
   (§3). This is the review target of this document.
2. **The correlator spec** — the S-3 observer model, the joint-fusion
   requirement, and the three grading arms (modeled S-3, funding-seam-blind
   null, stronger-than-S-3 stress) (§4).
3. **Instrumentation controls** — known-linked / known-independent
   scenarios that gate the run's own validity (§5).
4. **Pessimistic principal-lifecycle distributions**, stated with rationale
   (§6).
5. **Dispersal-draw modeling** — WI-3's `U[0, tick_interval)` intra-tick
   dispersal as a swept synthesis parameter (§7).
6. **The provisional/sealing plan** and the WI-3↔WI-4 reconvergence gate
   (§8).
7. The **acceptance criteria** the implementation round (§11) must satisfy,
   and the **sweep surface** it must cover (§9, §10).

Out of scope: implementing the correlator and running the graded sweep —
that is the §11 implementation round, gated on review of §3–§7 here. The
S-2 fused exposure ledger (a sibling GATE6 deliverable, qualitative);
axes the hooks do not yet emit from production (serve-credit claim cadence
lands with SP-T4b); the exit-seam (GF-4 drain) standoff, a separate
one-sided draw (GATE6 pass-4) with its own future measurement round.

## 2. Substrate (verified at `feat/wi3-dispatch-driver`, 2026-07-05)

| Fact | Where |
| --- | --- |
| Event vocabulary + injected observer trait exist, feature-gated `gf7-hooks` | `shekyl-standoff/src/gf7.rs`: `TimelineEvent` (4 lifecycle + 3 bond-post + 1 per-`P` arms), `BroadcastTimelineObserver::record`, `NoOpObserver` |
| Recording observer + a **deliberately trivial** correlator exist (`--gf7-timeline`) | `shekyl-staking-sim/src/gf7_timeline.rs`: `RecordingObserver`; `nearest_principal` placeholder; two arms (`p_link_blind`, `p_link_funding`); `baseline = 1/n_principals`. Module docs pin it as "pipeline proof, not measurement round" |
| The funding-axis standoff harness + its recommended posture | `shekyl-staking-sim/src/standoff.rs`: Poisson decoy-pool `P(link)=mean(1/set)`, `TARGET_ANON_SET=10`; recommended **600-block uniform-independent window, inversion on** (`STAKER_ARCHIVAL_SIM.md`) |
| WI-3's intra-tick dispersal draw (live driver only) | `shekyl-engine-core/src/engine/pscan/dispatch.rs`: `delay ~ U[0, dispersal_bound)` via `bounded_uniform(OsRng, bound-1)`, `dispersal_bound = tick_interval` (production); emitted `BondPostDispatched { persona, at }` after the sleep |
| Live production emission is 3 event kinds only | `EntryGapDrawConsumed`, `BondPostScheduled` (stake-engine sign path), `BondPostDispatched` (dispatch path). Lifecycle (iii) + per-`P` (ii) axes are **sim-synthesized** until later slices emit them |
| Sim I/O convention | `main.rs`: manual `--flag` dispatch (no clap); **human summary → stderr**, **JSON report → stdout**; no runtime write under `docs/` |
| Build containment | `gf7-hooks` non-default; `.github/workflows/gf7-no-emit-guard.yml` asserts no production dependent pulls `shekyl-staking-sim` and the feature is sim-only |

**Inheritance disposition (rule 16).** The `gf7_timeline.rs` correlator is
Shekyl-authored scaffolding, explicitly labelled a placeholder; WI-4
replaces `nearest_principal`/`run_window` grading, keeps the
`RecordingObserver` + event vocabulary + report-shell shape. The standoff
Poisson model is **not** reused — it grades a decoy-pool candidate set, not
a joint timeline (§4.2).

## 3. The threshold — derived a priori (the review target)

This section is committed **before** any correlator is built or any sweep is
run. Per §5.1 constraint 1, a threshold chosen after grading is not a
threshold; it is a description of what the architecture happens to clear.

### 3.1 The S-1 claim, restated as a measurable bound

S-1 (GATE6 §10.12): principal↔`P` unlinkability is the load-bearing
property the firewall exists for, and a **single** successful
principal↔`P` de-anonymization is a breach. Operationally, the modeled
observer faces a linking decision: given the observed joint timeline
`T_obs`, assign a bond-post to one of `N` candidate principals — the
**anonymity set**, the principals whose lifecycle activity is consistent
with the observed seam. Blind guessing succeeds with probability `1/N`.

GATE6 pass-4 concedes that the pseudonym's *coherence* is public: `1/N` is
the **conceded floor** the firewall does not protect. The firewall protects
the observer's **advantage over that floor**:

```
A(T_obs)  :=  P(link | T_obs)  −  1/N            (additive advantage)
r(T_obs)  :=  P(link | T_obs) · N                (advantage ratio; N-invariant)
```

### 3.2 Derivation of the bound

The S-1-traceable claim (the shape §5.1 constraint 1 names): *a modeled S-3
observer must expect to correctly de-anonymize **fewer than one** persona,
across the anonymity set, in excess of what blind chance already concedes.*

Across an anonymity set of `N` personas each linked with advantage `A` over
the conceded floor, the expected number of **excess** correct
de-anonymizations is `N · A`. The breach threshold is one:

```
N · A  <  1   ⟺   A < 1/N   ⟺   P(link | T_obs) < 2/N   ⟺   r(T_obs) < 2
```

**The committed bound is the N-invariant ratio form:**

> **`r(T_obs) = P(link | T_obs) · N  <  2`** — the modeled observer may at
> most **double** the blind-guessing success rate. Equivalently, additive
> advantage `A < 1/N`.

**Posture-anchored instance.** At the standoff's steady-state anonymity-set
target `N = TARGET_ANON_SET = 10` under the recommended posture (600-block
uniform-independent entry window, inversion on), the ratio bound is the
absolute bound

```
P(link | T_obs)  <  0.20     (N = 10)
```

**Why the ratio, not the absolute number, is the committed bar.** `N` is
not a constant — it is the realized cover, which the standoff proved is
**rate-driven** (background funding/network-event rate), not a wallet
choice. Committing an absolute `p` would silently tighten or loosen the
privacy claim as `N` moves with traffic; committing the ratio keeps the
claim ("advantage ≤ one excess de-anonymization") invariant, and the sweep
reports the realized `N`, `P(link)`, and `r` together so the absolute
number is always interpretable against the cover that produced it.

**Why doubling-chance is the conservative choice, not a lax one.** The
alternative floors are `A < 1/N` (ratio 2, chosen) versus a stricter
`A → 0` (ratio → 1, no advantage tolerated). Ratio 1 is unachievable
against any observer with a nonzero timing channel and would make the gate
a permanent red — it grades the *conceded* floor as a failure. Ratio 2 is
the tightest bound that (a) admits the conceded pseudonym-coherence floor
and (b) still caps the firewall-protected advantage at strictly less than
one breach per anonymity set. It is a bound on the *protected* quantity,
evaluated against the *strongest* modeled observer (§3.4) — that
combination is what makes it conservative, not the constant `2`.

### 3.3 The low-activity / cold-start regime is graded separately

The standoff already found the worst case is a **low-activity principal**
(funds one bond, rarely spends): `N` is small (thin cover), and the
measured funding-axis link there is ≈0.32 with inversion — above the
`N=10` absolute anchor, because `N` is not 10 there. This is the named
pre-seal residual **L12 / GATE6 caveat (iii)** (thinnest genesis traffic +
longest-lived foundational `P`s coincide), not a WI-4 discovery.

WI-4 therefore grades **two regimes and reports them distinctly**:

1. **Steady-state** — `N` at or above the target cover; the ratio bound
   `r < 2` is the pass/fail gate.
2. **Low-activity / cold-start** — `N` small; the ratio bound is reported
   but a low-`N` pass is a **weak absolute guarantee** by construction
   (doubling a large chance is still a large probability). A low-activity
   result is not permitted to relax the steady-state bar; if it fails, the
   disposition is decided at review as *either* a decorrelation-redesign
   signal (more inversion / larger dispersal / isolation) *or* an
   explicitly-accepted named residual (the L12 shape) — **never** a bar
   move (§3.5).

The two-regime split is itself a pre-commitment: the low-activity regime
cannot be dropped from the run to make the steady-state number look
complete.

### 3.4 Conservative under the strongest modeled observer

Per §5.1 constraint 2, a weak correlator's low `P(link)` says nothing about
a strong one. The bound in §3.2 is meaningful **only** when evaluated
against the strongest arm WI-4 fields (§4.3's likelihood-ratio stress arm),
not just the modeled S-3:

- If the **stress arm** clears `r < 2`, the pass is robust.
- If **only the modeled S-3** clears it and the stress arm does not, the
  gate is **model-limited** and the real bar has not been cleared — that
  outcome is a **finding, not a pass** (§5.1 constraint 2).

The funding-seam-blind arm (§4.3) is the null against the §2 named failure
mode: an adversary who ignores the funding seam entirely and correlates on
principal-lifecycle cadence alone. It must be graded against the same bound
— a design that only decorrelates the funding axis and leaves the cadence
axis linkable certifies the wrong gate.

### 3.5 The ordering rule (pinned)

1. §3's bound is committed by this document (done, on review).
2. The §4 correlator is reviewed against the S-3 model, with the
   funding-seam-blind arm as the null and the stress arm as the strong
   observer, for the joint-fusion property (rule-16 adversarial review).
3. **Only then** does the §11 sweep run.
4. A sweep that fails the pre-committed bar is a **decorrelation-redesign
   signal** (against WI-3 §3.2/§3.6 and the standoff posture) — **never** a
   signal to move the bar. Moving the bar after grading voids the gate.

## 4. The correlator (pre-committed spec)

### 4.1 The S-3 observer model

The correlator models the S-3 observer (GATE6 §10.1/§10.12): it

- **sees** public chain events (bond-post arrival blocks, any public
  principal-lifecycle chain footprint) and network-observable arrival times
  of `P`'s broadcasts;
- **does not see** FCMP++/RingCT-hidden funding sources or amounts, or
  circuit interiors — §10.9 client/circuit isolation is a **conditioning
  assumption** inherited from the standoff harness's caveat 2: the numbers
  are `P(link | isolation holds)`. The hooks measure the **post-isolation
  residual**, which is exactly the timing channel;
- is an **observe-and-inject** adversary where modeled (standoff caveat
  iv): the honest-traffic cover is an *upper bound* on `N`; the stress arm
  (§4.3) is where the injected-decoy discount is approximated.

The observer's input is **one joint timeline per scenario run** — all three
event classes (§2 vocabulary) interleaved on logical block time, with the
principal-side ground truth held only on the sim side (§5).

### 4.2 Joint fusion, not per-axis multiplication

Per §2 of the hooks spec and §5.1 constraint 2(a): the correlator fuses the
three axes (standoff window, `P`'s other broadcasts, principal lifecycle)
into **one** linkage score per (bond-post, candidate-principal) pair. A
per-axis likelihood computed independently and multiplied across axes
assumes an independence the co-trigger structure (GATE6 §6/S-1: every drain
is a co-trigger) specifically violates, and understates linkage. The
joint-fusion property is a correlator-spec property **verified in review**,
not an implementation intent — the review reads the scoring function and
confirms it consumes the axes jointly (e.g., a single distance/likelihood
over the full feature vector), never an `axis_a_score * axis_b_score`
product.

This is why the standoff Poisson model is not reused: it grades a
single-axis decoy-pool candidate set. WI-4's candidate set is the set of
principals whose **joint** lifetime timeline is consistent with `T_obs`.

### 4.3 The three grading arms

Every graded scenario runs all three arms against the **same** recorded
timeline; all three are reported; §3's bound is applied to each per §3.4.

| Arm | What it uses | Role |
| --- | --- | --- |
| **Modeled S-3** | joint fusion of all axes the S-3 observer sees (§4.1) | the certified-against observer |
| **Funding-seam-blind null** (§2 named failure mode) | principal-lifecycle cadence only; **ignores** the funding/entry seam | proves the gate is not certified on the axis the entry jitter already handles; a decorrelation win here that leaves this arm high is a finding |
| **Stronger-than-S-3 stress** | a likelihood-ratio correlator over the full joint timeline (near-optimal given the modeled channel) | the robustness check; if it fails while modeled-S-3 passes, the pass is model-limited (§3.4) |

The stress arm is the standoff's "effective cover against observe-and-inject
is lower and unquantified" (caveat iv) made concrete: a likelihood-ratio
scorer is the strongest observer WI-4 can field against the modeled channel
without adding un-modeled side information, so clearing it is the strongest
in-model statement WI-4 can make.

### 4.4 The graded quantity

For each swept parameter point, each arm reports `P(link | T_obs)` — the
fraction of scenario trials in which the arm's top-scored candidate is the
true principal — alongside the realized anonymity-set size `N`, the baseline
`1/N`, and the advantage ratio `r = P(link) · N`. `P(link | T_obs)` is
**conditional on the swept parameter point** (the "`| T_obs`" is the
observed parameterized timeline), so the report is a surface over
parameters, not a single number (§10).

## 5. Instrumentation validity — positive/negative controls (pinned)

Per §5.1 constraint 3: the correlator joins recorded streams to principals
via the sim-side opaque-ordinal ground truth (hooks §3). If that join is
ever broken — ordinals emitted unlinkable even to the sim — the correlator
measures `P(link | axes independent)`, the friendly number, and a pass is an
artifact of broken instrumentation. Two controls run **before any graded
scenario counts**, and the grading run is **invalid** (whatever number it
produces) unless both pass:

1. **Known-linked positive control.** A synthetic scenario with a
   deliberately strong, un-jittered principal↔`P` coupling. The correlator
   **must** come back linked (`P(link)` near 1, well above baseline) — this
   proves the join survived identity-stripping and the scorer can see a
   link that is there. The sim-side analogue of "the tripwire must bite."
2. **Known-independent negative control.** A synthetic scenario where the
   bond-post timeline is drawn **independently** of every principal's
   lifecycle. The correlator **must** come back at chance (`P(link) ≈ 1/N`,
   `r ≈ 1`) — this proves the scorer does not manufacture linkage from
   structure alone (no baseline inflation).

Both controls are reported at the top of the run; a controls-failed run
emits its number marked **INVALID** and does not satisfy any acceptance
criterion. (This mirrors the standoff smoke test and the `certify_draw`
negative-control discipline already in `shekyl-standoff/conformance.rs`.)

## 6. Pessimistic principal-lifecycle distributions (pinned)

Per §5.1 constraint 4: the number is only as trustworthy as the synthetic
principal-lifecycle distributions. They are drawn **pessimistically** — the
least-favorable *plausible* rhythm — and stated here so the run cannot
quietly substitute a conveniently-noisy principal.

| Axis | Pessimistic choice | Rationale |
| --- | --- | --- |
| **Activity rate** | low-activity principal is a first-class regime (§3.3), not an outlier | the standoff's proven worst case; a busy principal is self-covering, so certifying against it would be the "conveniently-noisy principal" §5.1 warns against |
| **Lifecycle regularity** | **regular / near-periodic** session, refresh, and drain cadence (small jitter around a fixed period) | a regular rhythm is the *most* correlatable timeline — an irregular principal hides itself; pessimism is regularity, not noise |
| **Co-trigger coupling** | drains co-triggered with funding/refresh (GATE6 §6/S-1) modeled **on**, not independent | the co-trigger structure is exactly what joint fusion (§4.2) exploits; turning it off would understate linkage |
| **Anonymity-set / background rate** | swept **low** as the anchor (thin cover), with the standoff's rate range as the surface | anonymity is rate-driven; the load-bearing point is the thin end |
| **Isolation** | assumed to **hold** (conditioning, §4.1), and this assumption is stated as a caveat on every reported number | matches standoff caveat 2; WI-4 measures the post-isolation residual, and must not silently claim more |

The acceptance doc for the graded run (the report, §9) restates these and
flags every number as conditional on them — "certified against a
realistic-or-worse principal" is the claim that makes the gate meaningful.

## 7. Dispersal-draw modeling and sweep (pinned; WI-3 R2-3)

Per §5.1 constraint 5 and WI-3 §5 (R2-3): WI-3's intra-tick send-time
dispersal (`delay ~ U[0, dispersal_bound)`, fresh `OsRng` per post,
`dispersal_bound = tick_interval` in production) is a **new timing-entropy
primitive that exists only in the live driver**. The sim's `--gf7-timeline`
synthesis does not contain it unless it is modeled. WI-4's pre-live run
therefore:

1. **Models the dispersal draw** in the synthesized `BondPostDispatched`
   timeline: after the scheduled due block, add `U[0, dispersal_bound)`
   drawn per post from the sim RNG, matching the live `bounded_uniform`
   shape (inclusive `[0, bound-1]` integer draw over the block/tick grid).
2. **Sweeps the dispersal *distribution* — shape and range, not just
   presence** — as a synthesis parameter (`dispersal_bound` values across a
   range bracketing `tick_interval`, including 0 = no dispersal as the
   negative anchor). A "range suffices" conclusion drawn against a
   correlator that never saw dispersal is invalid (WI-3 §5).
3. Marks any pre-live conclusion about the dispersal range as
   **provisional-until-live-re-run** (§8) — exactly the status of the
   synthesized emission itself.

The dispersal draw decorrelates the dispatch from the **sweep phase**, not
from the funding seam (WI-3 §3.2); the correlator must therefore include an
arm or feature that could exploit sweep-phase locking (a wallet-cadence
fingerprint shared across a wallet's personas) so the dispersal's value is
actually graded, not assumed.

## 8. Provisional pass and the reconvergence gate

Per §5.1 constraint 5 and WI-3 §5:

- WI-4's **first pass grades the sim's synthesized `BondPostDispatched`**
  (interim). This pass is the **continue/redesign checkpoint, not the
  seal**. The report marks it **PROVISIONAL (pre-WI-3-live)**.
- The **sealing measurement** re-runs the identical correlator + threshold
  against **WI-3's live `BondPostDispatched` emission** (from
  `pscan/dispatch.rs`, feature `gf7-hooks`), which carries the *actual*
  dispersal timing (§7). Only the sealing re-run closes the gate.
- **The WI-3↔WI-4 reconvergence gate (rule 21):** WI-3's GF-7 acceptance
  closes on leg (a) *this threshold artifact exists* (satisfied by this
  document, on review) **and** leg (b) *the sealing re-run passes under this
  threshold*. WI-4's own pass seals on WI-3's live timeline. This is the
  armed-gate-without-trigger inversion the review pinned: the gate (this
  bound) exists before the thing it gates (the live timeline) is graded,
  never the reverse.

Because `feat/wi4-gf7-measurement` is stacked on the WI-3 branch, the live
`BondPostDispatched` emission and the `set_observer`/dispatch driver are
already present in the tree — so the §11 implementation can wire the sealing
re-run against the live driver in the same round, but the report still marks
the pre-live synthesis pass and the live-driver pass distinctly.

## 9. Acceptance criteria for the WI-4 implementation round (§11)

All must hold for WI-4 to close (and to close WI-3's reconvergence leg b):

1. **Threshold committed before grading.** §3's bound is in this reviewed
   document, dated, ahead of the grading code — auditable by git history
   (this doc lands before the correlator commit).
2. **Correlator is the §4 spec.** Joint fusion (review-verified, not just
   claimed); three arms (modeled S-3, funding-seam-blind null, LR stress);
   the `nearest_principal` placeholder is replaced, not extended.
3. **Controls gate the run.** §5 known-linked and known-independent
   controls run first; a controls-failed run is emitted INVALID and counts
   for nothing.
4. **Pessimistic distributions.** §6's choices are the defaults of the
   graded scenario, restated in the report.
5. **Dispersal swept.** §7's dispersal distribution is a swept synthesis
   parameter; a dispersal-free timeline is only the negative anchor, never
   the graded conclusion.
6. **Report artifact.** The run emits `P(link | T_obs)`, `N`, baseline, and
   ratio `r` per parameter point per arm (stdout JSON), plus the human
   surface + controls status + pessimism caveats (stderr), following the
   sim's I/O convention. The steady-state and low-activity regimes are
   reported distinctly (§3.3).
7. **Provisional marker + sealing re-run.** The pre-live pass is marked
   PROVISIONAL; the live-driver re-run (§8) is present and its result is the
   sealing statement.
8. **Gates.** `cargo fmt --check`, `cargo clippy --all-targets -D
   warnings`, `cargo test -p shekyl-staking-sim` (+ the `gf7-hooks` engine
   emission tests) green, as CI runs them.

## 10. Sweep surface (pre-committed)

The grading is a surface over these parameters (S-3 deliverable: `P(link |
T_obs)` as a function of standoff window / entry jitter / batch size, GATE6
§10.12), extended with the WI-3 dispersal axis and the standoff's
rate-driven finding:

| Parameter | Range / anchors | Source |
| --- | --- | --- |
| Standoff entry window | `0, 60, 300, DEFAULT_ENTRY_GAP_WINDOW (600)` | GF7 §5; standoff anchor |
| Inversion (order-coin) | off / on | standoff (carries the low-activity worst case) |
| Entry-gap draw shape | the real `draw_entry_gap` (uniform-independent) vs. the shared-trigger trap (negative control) | standoff (shared trigger is catastrophic) |
| **WI-3 dispersal bound** | `0` (anchor), fractions of and up to `tick_interval`, and beyond | WI-3 §3.2 / R2-3 (§7) |
| Background network-event rate | the standoff rate range (`0.005…0.10`), as a **conditional** surface | standoff (anonymity is rate-driven; the rate is a pre-testnet unknown, flagged like `fetch_latency_per_unit`) |
| Batch size / catch-up backlog depth | one-per-tick vs. deep-backlog catch-up | WI-3 §3.2 part 2 (one-per-tick), §6(c) |
| Principal activity regime | steady-state vs. low-activity/cold-start | §3.3 / §6 |

The background-rate axis is reported as **conditional** (like the economic
sim's `fetch_latency_per_unit`): the true post-isolation network-event rate
is a pre-testnet unknown, so the gate's pass is stated *at* a rate, and the
report names the rate at which the ratio bound holds.

## 11. The implementation round (gated on review of §3–§10)

Only after §3–§10 are reviewed (rule-16 adversarial review of the threshold
derivation and correlator spec):

1. Replace `gf7_timeline.rs`'s `nearest_principal`/`run_window` with the §4
   joint-fusion correlator + three arms; add §5 controls; add §6
   pessimistic distributions; add §7 dispersal sweep; add the §10 sweep
   surface.
2. Emit the §9 report (stderr surface + stdout JSON), controls-gated.
3. Wire the live-driver sealing re-run (§8) against WI-3's
   `BondPostDispatched`.
4. Docs sweep (rule 91): the `WI-4` index row → graded status; the
   `docs/FOLLOWUPS.md` GF-7 genesis-blocker → measured (provisional/sealed);
   `CHANGELOG.md`; and record whether the sealing re-run closes WI-3's
   reconvergence leg (b).
5. Gates (criterion 9.8).

## 12. Mission note (rule 00) and reversion posture (rule 21)

- **Priority 2 (privacy) binding.** This is the graded genesis gate for the
  coin's core principal↔`P` unlinkability claim. The a-priori-threshold
  ordering (§3.5) is what keeps the gate from certifying a false floor; the
  sim-side / no-production-telemetry containment (hooks §4) is what keeps
  the evidence pipeline from being its own leak. Both are load-bearing.
- **Priority 3 (outlast the team).** The threshold is committed in a
  reviewed doc ahead of code, so a future maintainer cannot retro-fit a bar
  to a passing number without the git history showing the inversion.
- **Reversion clause (§5.1-shaped).** *Moving the threshold after grading*
  is rejected, with a single named reopening criterion: the bound `r < 2`
  reopens **only** if the S-1 model itself is amended (a different
  adversary-advantage claim, argued in GATE6 / a fresh design round), never
  because a sweep failed to clear it. A failed sweep's disposition is
  redesign or a named-and-accepted residual (§3.3), decided at review. The
  low-activity regime's residual status (L12) reopens only on a measured
  improvement to genesis-era cover, not on schedule pressure.
