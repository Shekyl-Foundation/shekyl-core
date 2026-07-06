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

*Disposition exercised (2026-07-06):* the graded low-activity regime
**failed** the bound (§13.2), and the review decision is a third,
stronger shape of the redesign branch — restructure the launch so the
regime is never entered by a privacy-critical persona (§14 founder-cover
posture), with the failed row retained as the counterfactual bracket.

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

#### 4.1.1 Amendment (2026-07-06): the observer is posture-conditioned

The original §4.1 text reads as if the observer's scope were absolute. It is
not — it is **conditioned on the recommended local-daemon posture**, and the
review of the first grading round (§13) forced that condition to the
surface. Restated precisely:

- **`WalletSessionMarker` / `RefreshCycleMarker` are excluded as direct
  anchors, and the exclusion is a posture theorem, not a modeling
  convention.** Under the **local-daemon posture** these are loopback: a
  refresh is the wallet pulling blocks from, and a session is the wallet
  opening against, a daemon on the same host. No chain reader and no
  network-position observer on the host's uplink can see them — the
  daemon's own p2p sync rhythm is continuous and decoupled from wallet
  activity. Scoring them as direct anchors grants the adversary loopback
  vision it cannot have (the pre-fix `r ≈ 5` measurement is that
  over-granted world).
- **Named trust/transport invariant (Axis A), same reopen family as WI-3's
  D-B1 tip-clock invariant (2d-2):** *the correlator excludes direct
  refresh/session markers; sound because under the local-daemon posture
  their traffic is loopback and unobservable to any adversary; a
  **remote or non-isolated-daemon posture reopens this** — the wallet's
  polling cadence becomes network-observable (connection timing / traffic
  volume to a daemon the user does not control, and the remote daemon sees
  the RPC rhythm directly), the markers become live anchors, and the gate
  must be re-graded with them in.* The pre-fix `r ≈ 5` shape is the honest
  expectation for that re-grade: the remote-daemon posture is currently a
  **fail**, named on the verdict (§13.1), not an excluded channel.
- **The indirect channel (Axis B) is not excluded — it is coupled in the
  generator and graded.** Excluding the markers as direct anchors does not
  remove session cadence from the observable world: `simulate_pair` draws
  the funding co-trigger `t0` **from the session lattice**, places the
  drain **on** a session, and (under the `resume` sweep group) lands the
  D-B3 resume resubmit's `BondPostDispatched` **on** a session. The
  chain-visible events the observer scores therefore carry the session
  clock's signature. The graded evidence that this channel is live:
  `blind = 0.237` at window 0 (well above the `0.100` baseline — the
  correlator recovering the principal purely from refresh-shadowed
  observable timing), driven to `≈ 0.13` by the full entry jitter. The
  decorrelation win is measured **against** the coupled world, not against
  a refresh-free one.

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

#### 4.3.1 Amendment (2026-07-06): the stress arm is an oracle-panel with an exact-likelihood member

The first grading round exposed a mis-specification in the single-LR stress
arm as originally fielded: the density-corrected scorer underperformed the
plain MAP, which by the Neyman–Pearson property means the density model was
wrong, not that the adversary is weaker — and papering over it with a bare
two-member union (`lr = MAP ∪ density-corrected`) produced an arm that
tracked `s3` and stressed nothing. Post-review, the arm is respecified as an
**oracle-panel upper bound with three members**, one of which uses the exact
generative model:

1. **MAP** (the modeled S-3 scorer itself);
2. **density-corrected MAP** (`kernel_sum / anchor_count` — discounts
   "near by chance");
3. **seam-consistency-gated MAP** — the exact in-model likelihood filter.
   The generative model (`plan_entry_seam`) puts the first bond dispatch
   within `spread + dispersal ≤ window + dispersal_bound` of the funding
   send; that box is the **true support** of the seam likelihood, so
   candidates outside it have exact likelihood zero. The correlator
   hard-rejects them and runs the MAP among survivors — the
   Neyman–Pearson-honest use of full generative knowledge.

The panel links if **any** member identifies the true principal. The oracle
framing is deliberate and is what makes `lr ≥ s3` a feature rather than a
tautology: the union upper-bounds every realizable per-instance strategy
over these correlators, so the panel can *break* a gate the modeled S-3
clears (the §3.4 model-limitation tripwire) but can never *certify* a floor
the stronger members break. Post-amendment measurement confirms the teeth:
`lr` strictly exceeds `s3` on every gate row (e.g. window-600 `0.186` vs
`0.151`), and the gate is graded against `lr` per §3.4. Amending the arm
*after* the first sweep is safe in this direction only — strengthening the
adversary post-hoc can push the verdict toward fail, never manufacture a
pass — which is why this amendment is recorded rather than silently
substituted.

**The ceiling (pinned so the margin is never over-cited).** The
seam-consistency-gated member is the strongest observer *because it is
handed the true generative support* — the sim defined `plan_entry_seam`,
so the sim's adversary knows it exactly. A real adversary estimates the
support from data; the oracle panel therefore upper-bounds **the
strongest observer of the modeled channel**, which is the right thing to
gate against (if the strongest in-model observer clears the bar, the pass
is robust *within the model*) — but it is **not** a claim about an
adversary operating on side information the model does not emit. The gap
between "strongest observer of the modeled channel" and "strongest
adversary" is exactly the un-emitted axes: axis-(ii) serve-credit claim
cadence once SP-T4b makes it principal-coupled; funding provenance;
address reuse; cross-persona correlation; off-wire distinguishers; and
cross-trial founder re-identification (§14.4's scope boundary). The
§13.1 margin (`r = 1.86` vs `2.0`) must always be cited with this
qualifier.

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

## 13. Result — provisional grading round (implementation 2026-07-05, re-graded 2026-07-06 post-review)

The §11 round landed the correlator, controls, and sweep in
`shekyl-staking-sim/src/gf7_timeline.rs` (binary `--gf7-timeline`). The
2026-07-06 review round then forced three strengthenings — the
posture-conditioned observer restatement (§4.1.1), the oracle-panel stress
arm with the exact-likelihood member (§4.3.1), and the D-B3 `resume` sweep
group — and the surface below is the **re-graded** result under all three.
Run config: `N = 10`, `1000` trials/point, deterministic seed. **Controls
valid** (positive `P(link)=0.996 ≥ 0.80`; negative `P(link)=0.102`,
`|·−0.1|<0.05`), so the graded rows count.

### 13.1 Verdict: PROVISIONAL-PASS (local-daemon posture only; remote-daemon posture unmet, named residual; wall-clock leg (b) open)

The verdict is deliberately narrow, per the review: it certifies the
recommended **local-daemon posture** against a **block-resolution**
observer in **steady state**, and it names what it does not certify — the
remote/non-isolated-daemon posture (Axis A reopen, §4.1.1; the pre-fix
`r ≈ 5` shape is the expected re-grade there) and the wall-clock sub-block
channel (§13.3). Every gate-relevant row clears the bound on **all three
arms**, now including the strengthened panel:

| Gate-relevant row | `blind` | `s3` | `lr` (panel) | `r = lr·N` |
| --- | --- | --- | --- | --- |
| window 600 / disp 0 | 0.128 | 0.151 | 0.186 | **1.86** |
| dispersal 0 (600-win) | 0.130 | 0.149 | 0.183 | **1.83** |
| draw direct / disp 0 | 0.128 | 0.143 | 0.178 | **1.78** |
| regime steady / disp 0 | 0.130 | 0.143 | 0.178 | **1.78** |
| resume off / disp 0 | 0.127 | 0.143 | 0.177 | **1.77** |

The entry-jitter axis carries the gate: `s3` falls `0.996 → 0.636 → 0.242
→ 0.151` across window `0 → 60 → 300 → 600`, reproducing the standoff's
600-block finding. The strengthened panel has real teeth now — `lr`
strictly exceeds `s3` on every gate row (the seam-consistency-gated member
finds links the smooth MAP misses), and the gate margin is honest and
thin: **worst row `r = 1.86` against the bound `2.0`** (7% margin), not
the comfortable-looking 1.43–1.51 of the pre-review single-scorer run.
That margin is **against the strongest observer of the modeled channel,
not the strongest adversary** — the oracle panel is handed the generative
support the sim defined; the un-emitted axes it cannot see are named in
§4.3.1's ceiling statement, and the margin must never be cited without
that qualifier.

The **funding-seam-blind null sits above baseline at ≈ 0.13** (`r ≈ 1.3`)
— and per §4.1.1 that number is the graded *indirect* session channel, not
a refresh-free world: at window 0 the blind arm reaches `0.237` on
session-lattice-coupled observables alone, and the entry jitter is what
drives it down to `≈ 0.13`.

**D-B3 resume channel (`resume on` context row):** `blind = 0.149`,
`s3 = 0.133`, `lr = 0.157`, `r = 1.57` — clears the bound. The
session-lattice resubmit exposure raises the cadence arm (blind
`0.127 → 0.149`, exactly the direction the review predicted: the resubmit
carries the session clock), while the seam arms do not improve (the
resubmit carries no seam information). Graded, not assumed away; under the
bound at posture.

### 13.2 Context rows (not the steady-state gate — §3.2/§3.3)

- **Low-activity / cold-start:** `s3 = 0.265`, panel `lr = 0.354`
  (`r = 3.54`) — **fails the bound**, and harder under the strengthened
  panel than the pre-review `2.65` suggested. Post-review reclassification:
  this is **not an accepted residual**. Cold-start is the genesis regime,
  so a fail here is a launch-window privacy failure and requires an
  explicit **launch-posture decision** before genesis. That decision is
  specified in **§14** (founder-cover posture): the disposition is to
  *refuse to enter* the cold-start regime rather than accept its number.
  The row remains graded as the counterfactual bracket for what the regime
  costs if entered unprotected.
- **Conformance-trap draw:** `s3 = 0.211 > 0.143` (real draw) — the trap is
  more linkable, as designed (negative anchor behaves).
- **Inversion off:** `s3 = 0.251 > 0.237` (on), at window 300 — inversion
  helps, as the standoff found.
- **Block-unit `dispersal > 0`:** a **coarse-tick counterfactual**, not the
  realistic operating point. The live driver's dispersal is `U[0, 60s)`
  (`DEFAULT_PSCAN_CADENCE`), well under one block; and the emitted
  `BondPostDispatched { at }` records the **due-check tip block, captured
  before the dispersal sleep** (`pscan/dispatch.rs`), so the dispersal is
  invisible at block granularity. The realistic block-time gate therefore
  sits at `dispersal = 0`.

### 13.3 Reconvergence leg (b): the wall-clock channel is the primary open uncertainty

The block-time sealing re-run is **confirmatory by construction**: because
the live `BondPostDispatched.at` is the due block (dispersal is sub-block,
never enters `at`), the live block-time timeline reproduces the sim's
`dispersal = 0` surface — already evidenced by the engine emission test
`gf7_emits_bond_post_dispatched_per_submit` (`pscan/dispatch.rs`, feature
`gf7-hooks`).

The review sharpened what that means, and the sharpened form is recorded
here as binding: **the channel the dispersal primitive was built to defend
is exactly the channel this gate has not measured.** A real
network-position adversary timestamps packets at wall-clock, sub-block
resolution; the wall-clock sweep-phase channel (WI-3 §3.2) is what
dispersal decorrelates; and the hooks' block-resolution emission cannot see
it — on either side of the seal, so **no block-resolution live re-run can
close leg (b)**. This is not a routine residual: it is the primary open
uncertainty of the WI-4 verdict, it compounds with the Axis-A posture
condition (the same network-position adversary holds both capabilities the
verdict conditions away), and closing it requires **sub-block wall-clock
emission** (a finer-resolution hook or harness timestamp) followed by a
re-grade. Tracked in `docs/FOLLOWUPS.md` with that closing requirement
named. WI-3's reconvergence gate leg (a) (this threshold artifact exists)
is satisfied; leg (b)'s block-time portion is confirmatory, its wall-clock
portion is the tracked open item.

### 13.4 Threshold provenance (review item (a), settled)

The review asked whether `r < 2` was a-priori or post-hoc, noting the gate
rows sit between 1 and 2. Settled at source: §3.2's derivation (bound the
observer at one excess de-anonymization across the anonymity set, i.e.
additive advantage `A < 1/N ⇔ r < 2`) was committed in the spec commit
**before any correlator code existed**, and §3.2 explicitly pre-rejected
`r < 1` — the ratio-1 bar grades the *conceded floor* (blind guessing
achieves `r = 1`) as a failure and is unachievable against any observer
with a nonzero timing channel. The interpretation of the passing rows under
that bound: worst gate row `r = 1.86` ⇒ `0.86` expected excess links
across the whole set — under the committed "fewer than one excess
de-anonymization" claim, with the margin now honestly thin (§13.1).

### 13.5 The sealed claim is conditional by construction (pinned 2026-07-06)

The ledger against the `1.86` margin is three conditionals, and it is
**asymmetric** in a way the eventual seal must preserve:

- **Leg (b)** (wall-clock channel, §13.3) and the **§14.4 partition run**
  are *buildable*: each has a committed a-priori bound and a build item,
  and each resolves to a measured number that either clears or does not.
- **Isolation conditioning** (§16.9 item 1) is *permanently conditional*: it
  is a transport-layer property that no bond-layer measurement can
  discharge. It never becomes a cleared checkbox; it remains a stated
  assumption on every number in this document, forever.

Consequence for seal-time wording: even when leg (b) and the partition
arm both pass and `K_COVER` is set, the gate's honest form is **not**
"unlinkability holds." It is "unlinkability holds **conditional on
circuit/client isolation, which is enforced and verified at the
transport layer, not here**." Two-of-three-measured must never be read
as three-of-three-cleared: the isolation conditional survives into the
genesis claim itself as a permanent qualifier, and a future reader who
sees "leg-b passed, partition passed, sealed" and drops that qualifier
has dropped the assumption the entire gate rests on. Any seal statement
derived from this document carries the conditional clause on the verdict
line, in the same position the posture condition occupies today.

**No cross-subsidy (the same pin, applied to marginal numbers).** The
steady-state margin is ~7% (`1.86` vs `2.0`) and lends nothing. When the
measurement rounds produce leg-(b) and partition numbers, each stands
or falls against **its own** a-priori bound: a "close enough" grade on
one conditional does not borrow confidence from the steady-state pass,
and the steady-state pass does not absorb a marginal conditional. The
honest-1.86-over-comfortable-1.51 move exists precisely to keep this
temptation visible; reading a marginal conditional as cleared is the
same failure §13.5 forbids for assumed ones.

## 14. Addendum (2026-07-06): the founder-cover launch posture — refusing the cold-start regime

**Status: pre-committed specification, review checkpoint required before
the §14.4 measurement runs** (same §3.5 ordering discipline as the main
gate: bounds in this section are committed by this document ahead of any
partition-arm code or numbers).

### 14.1 The two launch facts, and what they invert

The §13.2 cold-start fail (`r = 3.54` under the panel) assumed genesis
forces privacy-critical personas into the thin window. Two launch facts
break that assumption:

1. **The five founder wallets do not require unlinkability for their
   genesis personas** — they opt out of the privacy claim for these
   specific personas (with the permanence consequence pinned in §14.3.1).
2. **There is no economic reason to stake before shards exist to serve.**
   At genesis there is at most one shard; service capacity and reward
   accrue only as the shard schedule expands. The privacy-seeking staking
   population has no reason to exist in the thin window.

Fact 1 inverts the cover chicken-and-egg: cover normally requires `N`,
and `N` requires participants who pay for the thinness. A wallet that has
opted out of the privacy claim can generate **real** bond/funding/drain
activity — produced by the production dispatch path, indistinguishable at
the observed channel from any other principal's activity *because it is
another principal's activity* — without anyone bearing an unconsented
exposure. This is categorically different from synthetic decoy traffic,
which was rejected in the standoff review because decoys distinguishable
from real traffic add signal, not cover. Founder activity is not a decoy;
it is a genuine participant that happens to have consented to its own
attributability.

Fact 2 means the dangerous cohort — real users needing unlinkability,
minted at genesis, watched forever — is naturally near-empty in the thin
window. The posture's job is to convert "naturally near-empty" into
"structurally empty."

### 14.2 The posture (P1–P4)

The disposition for the §13.2 cold-start fail is **refuse to enter the
regime**, not accept its number and not redesign the decorrelation around
it (§3.3's review-decision clause, exercised):

- **P1 — Founder cover, production-path identical.** The five founder
  wallets stake intermittently through the launch window using the
  **identical** production path a real user would: same dispatch driver,
  same entry-gap draws, same dispersal, same recommended posture. No
  founder-specific code path, cadence profile, or configuration exists —
  indistinguishability by construction, not by discipline.
- **P2 — Staggered, never clustered.** Founder bonds are dispersed across
  the launch window. Five bonds in one block are one co-triggered anchor
  (the §6 trap shape, at launch, on the most-watched blocks of the chain);
  five bonds staggered are five independent contributions to cover. The
  intermittency is decorrelation work, not load spreading.
- **P3 — The shard schedule is the structural gate.** Privacy-critical
  staking is **not available** — not merely not-incentivized — until the
  cover threshold is met. "No reason to stake early" leaves an over-eager
  user free to opt into a cold-start breach the posture assumed they'd
  avoid; the make-bad-states-unrepresentable form closes that gap. The
  gate's opening condition couples the shard schedule to measured cover:
  the second shard (the first real reason to stake) does not open before
  accumulated founder-plus-organic activity puts a newly-minted persona
  into the steady-state regime, so the two curves — "cover thick enough"
  and "reason to stake" — are aligned by construction rather than by hope.
- **P4 — Founder genesis personas are public, forever, by consent.** The
  honest form of "not concerned about linkability": the linkage formed at
  genesis cannot be un-formed later, so the opt-out must be permanent and
  explicit — these personas are treated as **attributable from the start**
  (not merely unprotected), recorded in writing as a named posture
  decision, and nothing downstream may ever assume they were private. If
  any founder might later want a genesis persona to have been private,
  this posture does not and cannot provide that.

### 14.3 Wargames the posture must survive

#### 14.3.1 Founder-exposure permanence

Founder personas minted at genesis are the longest-lived; a genesis
linkage on them is permanent, including retroactively (years later, when
the foundation's genesis stake is a matter of public interest). P4 is the
answer, and it is load-bearing: "not concerned at first" is insufficient —
the consent is to **permanent** attributability of these specific
personas. Founders who need private staking positions create them later,
as ordinary users, through the gated steady-state path, with no linkage to
the genesis personas assumed or required.

#### 14.3.2 The partition adversary (the one that gets measured — §14.4)

Founder cover counts toward a user's `N` **only** to the extent founder
activity is a member of the same indistinguishability class as user
activity at the correlator's channel. If founder bonds are identifiable
(recognizable wallets, distinct cadence, distinct funding pattern, five
wallets in detectable lockstep), the adversary partitions the anonymity
set into {founders} ∪ {users} and discounts the founders to zero: a real
persona's effective `N` is back to the thin real-user count, and the
posture has manufactured cover that evaporates under scrutiny. This is
the load-bearing requirement, it is P1/P2's reason for existing, and it
is a **measured property, not an assertion** — §14.4 specifies the
correlator arm.

#### 14.3.3 Single-shard concentration

With one shard, all early service and reward concentrate on it: a real
persona serving the sole shard is in a service-role set of one,
regardless of timing decorrelation. This is why P3 is structural rather
than economic — the exposure exists for any privacy-critical user who
serves the single-shard phase, so the phase must be closed to them, not
merely unattractive. Founder personas serving the single shard are
covered by P4 (attributable by consent).

### 14.4 The partition-adversary arm (pre-committed spec; hypothesis class widened 2026-07-06, pre-implementation)

A new correlator probe in the GF-7 sim, gating the launch-posture claim
the way §5's controls gate the run. **Bounds committed here, ahead of
implementation, per §3.5.** *(Amended 2026-07-06, before any
implementation code, on a review wargame: the original probe was a single
2-means partition, and the failure modes that actually destroy founder
cover are not limited to two-cluster separability — a single founder
failing to blend, or the founder set being mutually similar enough to
enumerate as "the five", both defeat the posture while leaving a k=2
clustering at chance. The amendment widens the hypothesis class and adds
a marked control per failure mode. Amending a pre-committed spec is
legitimate only in this window — pre-review, pre-code — and only in the
adversary-strengthening direction, same rule as §4.3.1.)*

**The null being tested.** Not "2-means fails" but: *no decision rule the
adversary can field over the observable set recovers the founder/user
labels better than chance.* Quantifying over all rules is vacuous (the
labels themselves are a partition), so the arm fields a **named rule
family `F`** and reports the **maximum label-agreement over `F`**,
calibrated against the permutation distribution **of that same maximized
statistic**. Maximizing before permuting prices in rule selection — the
adversary who picks the partition *after* seeing the data is exactly what
the null distribution then models.

- **Setup.** `M = 5` founder pairs and `N − M` user pairs per trial, all
  synthesized by the **same generator at the same posture** (P1's
  indistinguishability-by-construction, as deployed).
- **The feature dictionary (named, so the implementation cannot
  cherry-pick weak features).** Per pair, over the §4.1.1
  posture-conditioned observables only: the seam gap `|bond − funding|`;
  dispatch phase within the horizon; the sorted inter-event gap vector;
  estimated cadence period (drain/resume spacing); observable event
  count; resume-to-bond spacing where present.
- **The rule family `F`.**
  1. *k-swept clustering* (`k ∈ {2, 3, 4, 5}`): cluster the pairs over
     the feature dictionary; score the best cluster-subset-to-cohort
     assignment against the true labels. (The original 2-means is the
     `k = 2` member.)
  2. *Per-feature outlier set:* for each feature, rank pairs and take the
     top-`M` set; score its overlap with the founder set. Catches the
     four-blend-one-doesn't shape a clustering misses.
  3. *Most-cohesive-subset enumeration:* over all `C(N, M)` subsets
     (252 at `N = 10`), find the subset minimizing mean pairwise feature
     distance; score its overlap with the founder set. This is the
     enumerate-"the five" adversary directly: founders individually
     unremarkable but mutually similar.
- **The statistic.** `T = max over F` of label agreement, per trial,
  averaged over trials.
- **The null.** The permutation distribution of the **same** `T` (labels
  permuted, the full family re-maximized per permutation). Best-assignment
  overlap and max-over-family are both chance-inflated; permuting the
  maximized statistic calibrates both inflations without post-hoc bar
  placement.
- **Marked positive controls — one per failure mode, each must bite.**
  - **M-a (lockstep):** all five founder dispatch anchors clustered — the
    P2 violation. Detected by family member 1.
  - **M-b (outlier):** four founders at posture, one with a distinct
    cadence. Detected by family member 2.
  - **M-c (cohesion):** five founders individually within the user range
    but drawn from a narrow common band. Detected by family member 3.
  A family proven to bite on M-a alone proves nothing about its other
  members; each control validates the member aimed at its failure mode.
- **Pass bounds (a-priori).**
  1. *Deployed posture:* `T` within `0.05` of the permutation-null mean —
     no rule in the family sorts founder from user better than chance.
  2. *Each marked control:* `T` at least `0.30` above the
     permutation-null mean, **per control** (M-a, M-b, M-c separately).
  3. All bounds must hold or the partition measurement is **INVALID**
     (same all-or-nothing shape as §5's controls).
- **What a fail means.** A deployed-posture `T` above bound 1 is a
  **launch-posture blocker**: founder cover is discounted below its
  headcount and P1/P2 must be tightened (and re-measured) before the
  §14.2 posture may be relied on. It is never a reason to relax bound 1.
- **Scope boundary (named).** Per-trial exchangeability is what this arm
  measures; it cannot speak to **cross-trial founder re-identification**
  — a persistent per-founder signature accumulating across successive
  bond posts over the launch window (the same wallet's habits repeating).
  In-model the generator is memoryless so the axis is clean by
  construction; in deployment it is real and sits with the other
  off-model axes named in §4.3.1's ceiling statement (funding provenance,
  address reuse, off-wire distinguishers). Named residual, not absorbed.
- **Two consumers, two disposition rules (pinned 2026-07-06).** Since
  §16.2 Pin 2 placed this arm on `K_COVER`'s critical path, its output
  feeds **two independent decisions that consume different projections
  of the same measurement round**, and a result must be dispositioned
  per consumer or a borderline number will be mis-read:
  1. *Launch-posture validator* (consumes the indistinguishability
     statistic `T` against bound 1): a bound-1 **fail** — founders
     sortable from users better than chance — means the posture is
     **unsound**; the disposition is posture redesign (P1
     indistinguishability, P2 staggering, M3 path-sharing) and
     re-measurement. Never a bar move.
  2. *`K_COVER` calibrator* (consumes the cover-thickness model at the
     measured shard count): a result that is **sound but thin** — `T`
     at chance (bound 1 passes) while cover thickness is marginal at
     the anticipated shard count — is **not a posture failure at all**;
     the disposition is `K_COVER` calibrates higher (the gate opens
     later, cover accumulates longer).
  These are opposite actions on adjacent-looking results. A marginal
  outcome must be read against *which quantity* is marginal: the
  partition statistic (consumer 1's fail) or the thickness at `K`
  (consumer 2's calibration). Force-reading a thin-cover result as a
  posture failure wastes a sound posture; force-reading a
  distinguishability fail as a calibration question ships a partitioned
  anonymity set with a bigger `K` in front of it.

### 14.5 What this does to the §13 verdict, and the reversion clause

The §13.2 cold-start row remains graded and reported as the
**counterfactual bracket** — the cost of entering the regime unprotected.
The launch-posture claim itself becomes: *no privacy-critical persona is
minted into the thin window* (P3 structural gate), *the window's cover is
real and indistinguishable* (P1/P2, measured by §14.4), *and the parties
bearing the window's exposure consented permanently* (P4).

**Reversion clause (rule 21).** The posture is rejected-now-with-reopening
-criteria in both directions:

- The **cold-start-as-accepted-residual** disposition (the pre-review
  §13.2 text) is rejected; it reopens only if the §14 posture is itself
  rejected at review *and* a measured genesis-cover improvement makes the
  regime's number clear the bound without it.
- The **§14 posture** reopens (as a launch blocker) on any of: the §14.4
  partition measurement failing bound 1; the shard schedule decoupling
  from the cover threshold (P3's alignment breaking); or a founder
  requiring retroactive privacy for a genesis persona (P4's consent
  failing, which the posture cannot honor and must therefore surface
  loudly, pre-genesis).

Implementation of §14.4 is the next round, **gated on review of this
section** — the same spec-first checkpoint the main gate ran on.

## 15. Addendum (2026-07-06): the remote-daemon posture — refuse, not accept

**Status: proposed disposition, review checkpoint required before any
implementation.** Same spec-first ordering as §14.

### 15.1 The question "named residual" was carrying implicitly

The §13 verdict names the remote-daemon posture as an unmet residual
(`r ≈ 5` expected re-grade with the §4.1.1 markers observable). Naming it
is honest, but "named residual" carries an unmade decision — the same
work "accepted residual" was doing for cold-start before §14 reframed it.
The decision is binary: is remote-daemon a posture the system **refuses
to enter**, or one whose risk a user **accepts**? For cold-start, §14
found a structural refusal (no early reward, shard-gated availability).
The analogous question here has an analogous answer, because the wallet
is Shekyl's own software and it knows its daemon endpoint.

### 15.2 Proposed disposition: structural refusal at the dispatch driver

The archival-bond dispatch driver (the WI-2/WI-3 surface that arms
funding, bond-post, and drain dispatch) **refuses to arm when the wallet's
daemon connection is not local** (loopback or unix-domain socket). Not a
warning, not a confirm-to-proceed dialog: the bond path is unavailable
under a remote-daemon configuration, the same way early staking is
unavailable under §14's shard gate.

Why refusal rather than informed consent, when §14.2 P4 gives founders
exactly the informed-consent shape: the two cases differ in who bears the
exposure and what the alternative costs. Founder consent (P4) is a
*bounded, enumerated* set of parties accepting exposure so that *others*
gain cover — the exposure is load-bearing for the system. A remote-daemon
user's exposure protects no one, and per `00-mission.mdc` privacy is
never a setting: a warned override is precisely a setting whose off
position is linkability. The one asymmetry that could justify
consent-over-refusal — a user who *cannot* run a local daemon and would
be excluded from staking entirely — is real, and it is priced: exclusion
from archival staking under a posture the gate measures at `r ≈ 5` is the
correct trade under the priority hierarchy (security/privacy over
feature availability). Staking is not required to use the coin.

### 15.3 Honest scope: what the refusal does and does not enforce

The endpoint check is **honest-user protection, not adversarial-user
prevention.** A user can tunnel a remote daemon through loopback (SSH
forward, proxy) and the driver cannot distinguish that from a genuinely
local daemon. The gate therefore enforces: *no one degrades their posture
by accident, by default, or by not reading documentation.* Deliberate
circumvention reconstructs the user-accepted-risk shape — but as an act
of configuration the user built themselves, not a switch the software
offered. That is the honest boundary of what software can enforce about
its own host, and it should be stated in the driver's documentation with
the number: the gate certifies the local posture; a tunneled-remote
configuration silently re-enters the `r ≈ 5` regime the refusal exists to
prevent.

### 15.4 What this does to the verdict, and the reversion clause

On acceptance at review, the §13 verdict's "remote-daemon posture unmet,
named residual" line becomes "remote-daemon posture **structurally
refused** (§15); tunneled circumvention a named residual" — the residual
shrinks from *every remote-daemon user* to *users who deliberately
defeated the gate*, and the Axis-A invariant's precondition becomes
machine-enforced rather than documentation-enforced.

**Reversion clause (rule 21).** The refusal is rejected-now-with-
reopening-criteria, not refused-forever:

- **Reopens** if the wallet↔daemon transport gains measured
  decorrelation — an isolated-circuit RPC transport whose connection
  cadence is demonstrated (by a re-grade of this gate with the §4.1.1
  markers observable) to close the marker channel to within the local
  posture's numbers. The re-evaluation shape is a new GF-7 measurement
  round against the remote transport, graded under the same `r < 2`
  bound; the decision sits with the same review that gates §14.
- **Does not reopen** on user demand for remote-daemon staking
  convenience — that is preference-anchored, not substrate-anchored,
  and the priority hierarchy already adjudicated it (§15.2).

## 16. Addendum (2026-07-06): mechanization — converting the launch posture from policy to structure

**Status: proposed dispositions, review checkpoint required.** M1 is a
consensus-rule change and therefore gets its own design document and
review round per `05-system-thinking.mdc` (spec first) — this section is
its pre-flight pin, not its spec. The rest are graded by mechanism class.
The organizing question: which risks currently held by policy, consent,
or naming can be made unrepresentable instead — in the track's own
pattern (P-1/P-2, F41, gate 11, D-B3): *replace a property held by review
with one held by construction, keyed on a choke point you can enumerate.*

### 16.1 The partition trap (the constraint every mechanism must pass)

Any mechanism that sorts founder-from-user on an observable partitions
the anonymity set: the moment the protocol, the wire, or a broadly
visible internal type can tell a founder bond from a user bond, the
adversary can too, and founder cover collapses to zero for the users it
exists to protect. A mechanism that enforces the right behavior *by
marking the actor it applies to* is worse than no mechanism — it
manufactures the distinguisher the cover depends on hiding. Every item
below is therefore held to: **global and blind** — applied uniformly to
all bonds, keyed off structural chain facts, never off identity. M1 is
the exemplar; the others are graded against its shape.

### 16.2 M1 — reward eligibility gated on shard count (consensus rule; build first)

**What it converts.** The cold-start safety currently rests on an
incentive *fact* — no economic reason to stake pre-shards (§14.1 fact 2,
P3). Incentive facts are game-able: an irrational or adversarial actor
stakes early anyway and mints a cold-start-linkable persona the posture
assumed away. The conversion: staker reward eligibility becomes a
uniform consensus computation — **no reward accrues to any `(P, s, E)`
for epochs where `shard_count < K_COVER`** — so a bond posted into the
thin window earns nothing *by construction*. Posting stays legal
(forbidding it would block the founder cover); the reward gradient
becomes the mechanical sorter, and it is non-partitioning: a uniform
function of chain state, applied identically to every bond, marking none.

**Substrate, verified at source (2026-07-06).** Shards are frozen chain
segments — `archival_shard_segment.freeze_height`, age =
`close_height − freeze_height` (`ARCHIVAL_REWARD_ARITHMETIC.md` §Shard
age) — so `shard_count` is a **deterministic, monotone function of chain
height**. This dissolves the proxy-choice wargame: shard-count and
block-height are not competing proxies, they coincide by construction;
shard-count is simultaneously the semantically correct gate (reward
follows serveable data) and inherits height's non-manipulability — no
actor can inflate it (would require mining the chain forward) and no
actor can stall it (chain growth freezes segments). Cumulative-bond-count
is **rejected**: sybil-inflatable whenever cost-to-post is low.

**The sharp pin: zero accrual, not deferred payout.** `R_market(s, E)`
is per-epoch membership (`ARCHIVAL_CONSENSUS_STATE.md` §R_market) — no
seniority. The gate must preserve that: serve credits and any other
reward-bearing quantity from pre-gate epochs must contribute **nothing**
post-gate. A defer-payout form (accrue now, claim later) preserves the
early-staking yield and hollows the gate — a rational user pre-positions
for deferred reward and the thin window repopulates with exactly the
personas the posture refuses. The invariant to carry into the spec:
**no consensus quantity may accrue from pre-`K_COVER` epochs**, and the
no-first-mover-advantage property (gate opening confers no seniority)
is checked at spec time, not assumed.

**Verified synergy.** The cold-start claim-cohort hazard
(`docs/FOLLOWUPS.md`: at launch a claim's `tier × creation_height`
cohort approaches one) is refused by the same rule in the same window —
zero accrual ⇒ zero claims exist during the thin window, so the
smallest-cohort regime of that separate leak is never entered either.

**Named residuals and shape notes.**
- *Dead-rule note (rule 15 shape):* `shard_count` monotone ⇒ the gate is
  trivially satisfied forever after activation — a permanently-inert
  consensus branch. Named and accepted: it is a pure uniform computation
  with negligible surface, and unlike migration code it cannot misfire
  on live state. A height-sunset alternative is rejected (a second
  genesis-frozen constant to get right, buying nothing).
- *Timeframes (rule 05):* now = the launch mechanics; mining-era-end =
  gate long-dead and inert; V4 = independent of the crypto substrate.
- *Genesis-frozen:* the rule and `K_COVER` must be right the first time.
  `K_COVER`'s derivation is the review object — it must be coupled to
  the same cover model the §14.4 arm measures (P3's alignment), derived
  a-priori, not tuned post-hoc.
- *Where it lands:* `epoch_close_compute`
  (`shekyl-archival-retention/src/consensus_state.rs`) as a uniform
  factor; constant from `config/consensus_constants.json`; CI in the
  existing `check_archival_reward_gates.sh` shape. Own design doc + round
  before any code.

**Two obligations pinned for the M1 design round (2026-07-06 review).**

1. *The activation-boundary test is a first-class deliverable.* The
   dead-rule acceptance above relocates the armed-gate-with-no-trigger
   risk **to time**: the gate fires once, at the activation boundary,
   and is never exercised again — no steady-state test and no runtime
   signal covers the boundary condition after launch, so an off-by-one
   in `shard_count ≥ K_COVER`, the `chain_epochs == 0` genesis edge
   (`shard_age_milli`'s "everything is hot at genesis" zero), or the
   exact epoch at which first accrual becomes non-zero has exactly one
   chance to be right. The M1 spec must therefore carry a consensus
   test pinning behavior **across the exact transition** — accrual
   provably zero at `K_COVER − 1` shards and provably non-zero at
   `K_COVER`, exercised at the boundary epoch — in the crate's existing
   KAT shape (`consensus_state_kat_v1.json` precedent), designed in
   from the start rather than backfilled.
2. *`K_COVER` cannot be finalized ahead of the §14.4 measurement.* The
   derivation chain is explicit: `K_COVER` ← cover-thickness model ←
   founder-cover soundness ← partition-adversary-stays-at-chance ←
   the hypothesis class matching the adversary's (§14.4's widened
   family). A partition arm built at `k = 2` that passes while the real
   adversary fields a richer partition yields a `K_COVER` derived
   against an overoptimistic cover model — the gate that refuses
   cold-start calibrated too loose. Consequence for ordering: **M1's
   design round may spec the rule shape immediately (the genesis-frozen
   machinery), but the constant's finalization gates on the §14.4 run
   with the widened hypothesis class.** The two must not be reviewed
   independently with one silently assuming the other passed.

### 16.3 M2 — cover-gate proxy choice

Resolved into M1 by the substrate verification above: the gate reads
`shard_count`, which is structural, monotonic, and coincides with height.
No live-participant estimate is ever read — the flood-then-withdraw
liveness DoS (keep measured cover below the bar to block posting) has no
sensor to attack.

### 16.4 M3 — one dispatch path, structurally audited

Founder indistinguishability is enforced by the **absence of a founder
branch**, not by founder discipline: founder wallets run the identical
dispatch, entry-gap draw, dispersal, and posture as production because
there is no other code to run. The absence is auditable in the gate-11
shape: extend the single-write-path CI gate
(`scripts/ci/check_pending_post_write_path.sh`) with a **single
dispatch-arm enumeration** — assert exactly one bond-dispatch entry
point, so a future "founder convenience path" fails CI instead of
silently reintroducing the distinguisher. What this cannot mechanize —
off-path distinguishers (funding provenance, address reuse, temporal
clustering) — is exactly what §14.4 measures and M4 caps.

### 16.5 M4 — global anti-clustering during the launch window

"Founders stake intermittently" (P2) is a behavioral instruction; its
mechanical form is a **network-wide minimum-spacing / rate cap on bond
posts during the launch window, applied to all bonds blindly** — five
bonds in one block becomes unrepresentable rather than discouraged, and
because it is global it staggers founders and early organic activity
without partitioning either. This is the WI-3 D-B2 deep-backlog spacing
item (held open, beyond one-per-tick) with a launch-posture rationale
attached: spacing is cover-preservation, not just backlog hygiene — five
co-triggered bonds read as one anchor; five dispersed bonds are five
independent contributions to `N`. Three wargames carry into its round:
1. *Relaxation:* a rate cap is a liveness constraint; its bound must
   relax on the same structural proxy as M1 (`shard_count`), or it is a
   permanent throughput ceiling.
2. *Cap-boundary structure:* queueing behind a cap creates its own
   observable timing lattice (posts clustering at cap slots). The §14.4
   partition arm and the main gate must be **re-run under the cap** —
   the mechanism is part of the measured channel, not outside it.
3. *Enforcement locus:* a consensus form (blocks containing over-cap
   bond posts are invalid) is enforceable but hands miners a
   censorship-adjacent selection lever; a relay-policy form has no
   lever but binds no miner. The choice is the design round's first
   question; both horns are named here so neither is chosen by default.

### 16.6 M5 — the boundary case: founder-persona "public" status stays off-wire

The naive mechanical form is the §16.1 trap in disguise: any observable
`is_founder` fact — type, wire field, dispatch variation — *is* the
partition. So P4's "public by consent" must remain an off-wire,
local-only fact. What **can** be mechanized is the inverse guarantee:
a wallet-local `PublicByConsent` marker on the persona record that
**gates off** downstream privacy assumptions — so no later feature can
accidentally treat a known-public persona as protected and build a false
guarantee on it. Constraints held by construction: the type never
serializes (no serialize impl; F25-style audit that no wire or dispatch
type constructs from it), never affects dispatch shape, never appears in
any observable. The consent itself — "these personas are attributable
forever, and I accept that" — is irreducibly human and permanent (P4);
the mechanism enforces the *non-assumption*, not the consent.

### 16.7 M6 — arm the triggerless gates

The armed-gate-with-no-trigger pattern, applied to the measurement layer:
1. *Partition-adversary arm* — specced with a-priori bounds at §14.4;
   implementation is the next round.
2. *Indirect-channel coupling control* (new, added to the §5 controls
   family): a control scenario that **fails the run as INVALID** if the
   synthetic generator ever produces session-independent chain-visible
   timing. A-priori form: the blind arm at `window = 0` must sit at
   least `2×` above the `1/N` chance floor (measured `0.237` vs chance
   `0.10` at `N = 10`); a future refactor that decouples the generator
   trips the control instead of silently producing the hollow pass
   §4.1.1 warns about. Same shape as the positive control: the tripwire
   must bite.
3. *Leg-(b) wall-clock emission* — the §13.3 closing requirement,
   restated as a build item: sub-block wall-clock emission (finer hook
   or harness timestamp), because a gate that structurally cannot
   observe the channel it certifies is not a gate.

### 16.8 M7 — daemon-tip trust-site enumeration

Completes D-B1's named invariant structurally: an F25-style enumeration
asserting every site that trusts the daemon's claimed tip is in a known,
counted set — a new tip-trusting read fails the audit gate instead of
extending the trust surface silently. Converts "we documented where we
trust the daemon's clock" into "a new place we trust it fails CI" — the
same collapse that made the token sole-origin structural.

### 16.9 The irreducible three (named so this is not oversold)

1. **Isolation conditioning** — every GF-7 number is conditional on
   circuit/client isolation holding; that is a transport-layer guarantee
   verified where it is enforced, not a bond-layer mechanism.
2. **The true post-isolation network rate** driving real `N` — a
   pre-testnet empirical unknown; no mechanism produces it, only
   measurement against a live network (reported as a conditional axis).
3. **Founder consent** (P4) — permanent human agreement. M5 mechanizes
   the non-assumption; the consent cannot be mechanized.

### 16.10 Ordering and reversion

**Build order: M1's spec first, with the spec/constant split explicit.**
M1 is the genesis-frozen item — the one that cannot be patched after
launch — and it converts the load-bearing incentive fact into a protocol
fact. Per §16.2's pinned obligation 2, the round splits: the **rule
shape** (uniform zero-accrual factor, boundary test, CI gate) is specced
immediately; the **`K_COVER` constant** is finalized only after the
§14.4 measurement runs with the widened hypothesis class, because the
cover model that sets it is exactly what that measurement validates.
The §14.4 implementation round therefore sits on M1's critical path.
M6.2 (coupling control) is the cheapest and lands with that same §14.4
round. M3/M7 are CI gates in an existing pattern. M4 needs its own round
(the three named wargames). M5 rides the wallet-side persona-record
work.

**Reversion clause (rule 21).** Each mechanism is
proposed-now-with-reopening-criteria: M1 reopens only on a substrate
change to shard-segment creation (if `shard_count` ever stops being a
pure function of height, the proxy analysis in §16.2 is void and the
gate re-derives); M4's cap reopens on measured cap-boundary structure
exceeding the §14.4 bounds (the mechanism would then be manufacturing
the signal it exists to suppress); M5 reopens only if persona records
gain a serialization path (the never-serialize constraint is the load-
bearing fact). None reopens on convenience.

**The review-closure bar (pinned 2026-07-06).** The §§14–16 review is
the last point where the downstream bounds can be shaped by argument
rather than contested against data — everything below it is committed
before code precisely so this review can scrutinize the bounds without
a passing number in view. Once the §14.4 round produces a number,
every one of these questions becomes anchored to it. The closure is
therefore **not** a consistency check ("are the specs internally
coherent"); it is the adversarial read of whether the bounds themselves
are right, and it must answer at minimum:

1. Is `r < 2` still the honest bar under the oracle panel that now
   reaches `1.86` — or does the panel's strength argue the bar was
   calibrated against a weaker observer class?
2. Is the §14.4 widened hypothesis class actually the adversary's
   class, or still a named subset of it — what rule shapes the family
   omits, and why each omission is safe?
3. Does the `K_COVER` derivation contain a circularity — the cover
   model that sets the constant being validated by the very arm the
   constant gates — and if the dependency is real but non-circular,
   where exactly the cycle breaks?

A closure that does not put these three on the record has rubber-stamped
the a-priori half of everything downstream. The answers must be
**attack-shaped, not affirmation-shaped**: the reviewer actively tries
to show `r < 2` is too loose under the panel, actively tries to
construct an adversary partition outside the widened family, and
actively tries to trace the `K_COVER` cycle *closed* — the bounds pass
by surviving the attempt, not by being agreed with. The review closing
*well* is worth more than it closing *soon*: once a measured number
exists, the first genuinely hostile look at an unexamined bound comes
from an adversary against a live chain, the one place a genesis-frozen
constant cannot be reopened.
