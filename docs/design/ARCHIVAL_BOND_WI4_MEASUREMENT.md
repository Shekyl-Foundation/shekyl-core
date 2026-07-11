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

*Pinned at review closure (2026-07-06, §17.5 — the mean-vs-max
challenge):* the derivation above reads as a **set-average** ("expected
excess across the set"), but the quantity S-1 protects is
**per-persona** — and the step that makes the committed bound
per-persona is **exchangeability**, which was load-bearing and
unstated. In-model, personas are drawn i.i.d. from the same lifecycle
distributions, so every persona faces the same `P(link)`: set-mean,
per-persona value, and per-persona max coincide, and `r < 2` **is** the
bound on any *targeted* persona's link probability (`< 2/N`). That
equivalence fails wherever exchangeability fails — a persona subclass
with distinct linkability (the low-activity principal is the known
instance) has its own, higher `P(link)` that a set average would hide.
The discipline that carries the max, not the mean, is **regime
splitting** (§3.3): any identified subclass is graded as its own regime
row against the same bound, never averaged into the set — exactly how
the cold-start row was surfaced as a fail (§13.2) rather than absorbed
into a passing mean. Reporting already takes the **worst gate row**
(`1.86` is a max, not a mean). The untargeted adversary ("just break
*someone*") is bounded by the same concession structure: blind guessing
already links someone in most sets (the pass-4 conceded floor), so the
protected quantity is the excess, per persona, per regime — which is
what the ratio bound caps.

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

*Pinned at review closure (2026-07-06, §17.1):* the ratio's N-invariance
is a property of the **bound's meaning**, not of the **measurement** —
`r` has only been measured at `N = 10`, and whether measured `r(N)` is
flat in `N` is an empirical question about the score distribution's
tail, not a definitional fact. The next measurement round carries an
in-model N-sweep (§16.7 item 4) with the a-priori form: `r < 2` at
**every** swept `N`, not only the posture anchor.

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
longest-lived founder `P`s coincide), not a WI-4 discovery.

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
   The generative model (`plan_entry_seam`) puts the **first** bond
   dispatch within `spread + dispersal` of the funding send, where
   `spread ~ U[0, window]` (inclusive) and the dispersal draw is
   `U[0, dispersal_bound)` (exclusive — supremum `dispersal_bound − 1`,
   matching the live driver's `bounded_uniform` call); the tight support
   is therefore `window + max(dispersal_bound − 1, 0)`. That box is the
   **true support** of the seam likelihood, so candidates outside it have
   exact likelihood zero. The correlator hard-rejects them — gating on the
   **earliest** recorded dispatch only, since the D-B3 resume resubmit
   lands on the session lattice, not the seam, and admitting a candidate
   on resubmit proximity would widen the gate past the true support — and
   runs the MAP among survivors: the Neyman–Pearson-honest use of full
   generative knowledge.

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
9. **Aggregate verdict is a computed conjunction, never narrated**
   (added 2026-07-06, finding B-1 — the §13.5 no-cross-subsidy pin made
   structural). The report's verdict line is computed as the conjunction
   over **every bound committed at run time** — steady-state `r < 2`
   (per arm, per gate row), and as they land: leg-(b) against its
   wall-clock bound, the §14.4 partition arm against bounds 1–2, the
   §16.7 N-sweep at every swept `N`, the M6.2 coupling control —
   emitting **PASS only if all hold, INVALID if any committed bound's
   measurement is absent, FAIL if any is unmet**, in the same mechanical
   shape as criterion 3's controls. A reviewer must not be *able* to
   wave a marginal conditional through on the strength of the
   steady-state margin: the cross-subsidy §13.5 forbids is
   unrepresentable in the artifact, not merely forbidden in prose.

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
channel (§13.3).

*Scope of the number, pinned at review closure R3 (2026-07-06, §18).*
The `1.86` is honest for what it grades, and the qualifiers that bound
its meaning are load-bearing enough to state on the verdict line, not
bury: it is a bound on **one seam** (the entry/funding→bond-post seam;
the exit/drain seam is GF-4, unmeasured — §18.1), at **one scope**
(per-post, not the per-principal property S-1 actually names — safe as
a per-principal bound only where persona mutual-unlinkability holds,
which is also GF-4 — §18.2), along **one channel** (timing, not the
loud per-epoch reward-amount value channel — §18.5), at **one instant**
(per-post, not cumulative over a persona's observed lifetime — §18.4),
for **one stratum** (unstratified by the observable bond attributes
`bond_floor`/`holdings`/shard that partition `N` — §18.3). None of
these reopens the `1.86`; each names a place the honest number quietly
widens under the next adversarial question, and §18 dispositions them.

Every gate-relevant row clears the bound on **all three arms**, now
including the strengthened panel:

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

The ledger against the `1.86` margin is four conditionals (the fourth
added at R3), and it is **asymmetric** in a way the eventual seal must
preserve:

- **Leg (b)** (wall-clock channel, §13.3) and the **§14.4 partition run**
  are *buildable*: each has a committed a-priori bound and a build item,
  and each resolves to a measured number that either clears or does not.
- **Isolation conditioning** (§16.9 item 1) is *permanently conditional*: it
  is a transport-layer property that no bond-layer measurement can
  discharge. It never becomes a cleared checkbox; it remains a stated
  assumption on every number in this document, forever.
- **Cross-seam / per-principal conditioning (added R3, 2026-07-06,
  §18.2)** is a *second* conditional of the buildable kind, but it
  gates a **scope promotion** the other two do not touch: the measured
  bound is per-**post**, and S-1 is a per-**principal** property. A
  principal holds `K` personas; if they are independently linkable at
  per-post `p`, the per-principal breach probability is `1 − (1 − p)^K`,
  which compounds toward 1 for a prolific principal. The only thing that
  stops the compounding is **persona mutual-unlinkability** — and that
  is exactly the exit/rotation seam GF-4 governs, **unmeasured**. So the
  per-post `1.86` implies a per-principal guarantee **only where GF-4
  holds**, and that dependency is a committed conditional, not an
  assumption to leave implicit.

Consequence for seal-time wording: even when leg (b) and the partition
arm both pass and `K_COVER` is set, the gate's honest form is **not**
"unlinkability holds." It is "the per-persona entry-seam advantage is
bounded (`r < 2`) under the local-daemon posture, **conditional on
(1) circuit/client isolation, verified at the transport layer, not
here, and (2) persona mutual-unlinkability (GF-4), graded separately —
without which the per-post bound does not promote to the per-principal
property S-1 names**." Measured-conditionals-cleared must never be read
as all-conditionals-cleared, and a per-**post** bound must never be read
as a per-**principal** one: both the isolation conditional and the
cross-seam/GF-4 conditional survive into the genesis claim itself as
permanent qualifiers, and a future reader who sees "leg-b passed,
partition passed, sealed" and drops either has dropped an assumption the
gate rests on. Any seal statement derived from this document carries
**both** conditional clauses on the verdict line, in the same position
the posture condition occupies today.

**No cross-subsidy (the same pin, applied to marginal numbers).** The
steady-state margin is ~7% (`1.86` vs `2.0`) and lends nothing. When the
measurement rounds produce leg-(b) and partition numbers, each stands
or falls against **its own** a-priori bound: a "close enough" grade on
one conditional does not borrow confidence from the steady-state pass,
and the steady-state pass does not absorb a marginal conditional. The
honest-1.86-over-comfortable-1.51 move exists precisely to keep this
temptation visible; reading a marginal conditional as cleared is the
same failure §13.5 forbids for assumed ones.
*Made structural (2026-07-06, finding B-1):* this pin as first written
was a discipline a reviewer must remember — the armed-gate-with-no-
trigger shape. It is now enforced by §9 criterion 9: the report's
aggregate verdict is a **computed conjunction** over every committed
bound (INVALID on absence, FAIL on any miss), so yielding to the
temptation is unrepresentable in the artifact rather than forbidden in
prose.

## 14. Addendum (2026-07-06): the founder-cover launch posture — refusing the cold-start regime

**Status: pre-committed specification, review checkpoint required before
the §14.4 measurement runs** (same §3.5 ordering discipline as the main
gate: bounds in this section are committed by this document ahead of any
partition-arm code or numbers).

**Terminology pin (R7, §17.9): three referents, three tokens — no
shared word.** The ambiguity this pin removes let a fictitious attack
be built twice (§17.9):

- **Founder persona** — an anonymous early *user*: a market-member
  staking persona that bonds pre-gate, accrues, and claims exactly as
  any user does (§14.3.4 fact 2). This is the only referent of
  "founder" in §§14–17: the population the timing family, the
  strip-row floors, and the cover-thickness calibration protect.
  Founder personas churn like users and owe no continuity (§17.9).
- **Foundation backstop** — the consensus-mechanized data-loss
  object, categorically outside the anonymity set: holds the
  complete tree, posts one nominal floor bond, is excluded from
  `Market` and reward-invisible by consensus (verified at source:
  `consensus_state.rs` `market_member_at_epoch` returns `false` for
  `is_foundation_complete_tree`; `FOUNDATION_EXCLUDED_FROM_MARKET`;
  `REWARD_EMISSION_LEG.md` §4.2 / gate 5; `ARCHIVAL_BOND_GATE4.md`
  §8.1). Zero accrual severs it from the privacy model at the root —
  it has nothing on the income channel to hide and is not a member
  of the set the calibration protects. Its persistence is what a
  backstop is (infrastructure), never a cover property, and no
  §14/§16 obligation attaches to it.
- **Founding operators** — the humans/entity who run founder
  personas and consent under P4. Never "the foundation" in this
  record: that token is reserved for the backstop object above,
  because operator↔object token collision is the reseed vector for
  the §17.9 category error.

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
- **P2 — Staggered statistically, never coordinated.** Founder bonds are
  dispersed across the launch window. Five bonds in one block are one
  co-triggered anchor (the §6 trap shape, at launch, on the most-watched
  blocks of the chain);
  five bonds staggered are five independent contributions to cover. The
  intermittency is decorrelation work, not load spreading.
  *Amended at distinct-position round R4 (2026-07-10, §17.6 Q2-B):*
  staggering is achieved **statistically, by P1's i.i.d. production
  entry-gap draws themselves** — never by scheduling, coordination, or
  proximity re-draws. As originally headed ("Staggered, never
  clustered"), P2 was jointly unsatisfiable with P1: enforcing "never
  clustered" over i.i.d. draws requires a
  mechanism, and any such mechanism makes the founder set a repulsive
  point process — a signature as detectable as the clustering it
  prevents (family member 7 / control M-e exist to arm exactly this).
  The residual same-block risk under i.i.d. draws is priced by the
  §14.4 **gating lemma** (a-priori absolute-clustering bound, no
  user-cohort reliance — §17.6 finding 1), not asserted. Three companion
  premises are pinned here because §17.3's cycle-break and §16.2's
  monotone floor consume them:
  1. *Timing-law `K`-invariance* — founder entry gaps are production
     draws, never parameterized by the launch-window length (which is
     `f(K_COVER)`); closes §17.6 Q3-C's smuggled-`K`-dependence channel.
  2. *Count `K`-independence* — the observed founder post count at
     gate-open must not be `f(time-to-gate)`. *Tightened at R5 (§17.7
     finding 3):* the gate-open condition is a **fixed pre-gate
     schedule completed before any candidate gate height** — full
     stop. The originally-offered alternative (re-bonding that is
     production-i.i.d. and count-exchangeable) satisfies only
     *distributional* exchangeability: the realized per-founder count
     remains observable, and laundering a realization through
     exchangeability requires the user cover cohort that Q3-A proves
     absent at gate-open. The i.i.d.-re-bonding disjunct therefore
     holds only inside the thin window where that cohort exists; it
     cannot discharge the premise at gate-open. *Wording pin (R6,
     §17.8 finding 3):* the schedule fixes **{count,
     completion-before-gate} only** — inter-post *timing* remains
     P1's i.i.d. production draw, never scheduled times. A reading
     that takes "fixed schedule" to fix post *times* manufactures
     exactly the too-even spacing family member 7 detects: the
     repulsion signature, worn by founders. Interlock recorded (same
     discipline as the Q2-C/Q2-B contingency): a revert-by-reading
     here arms a detector against the population it protects.
  3. *~~Persistence commitment~~ — **withdrawn at R7 (§17.9)**.* The
     premise passed through two forms — never-lose-a-bond (R4;
     unsatisfiable against the involuntary removal paths verified in
     `PRINCIPAL_STAKE_LIFECYCLE.md`) and a maintenance commitment
     (R6; hold live cover ≥ floor, replace attrited personas within
     a named lag) — and both forms share the defect that kills them:
     **an obligation unique to founders is founder-differential
     conduct in a system whose thesis is that founders are users.**
     Two independent sufficient grounds for the withdrawal, either
     alone dispositive:
     *(a) Categorical* — founders churn like users and owe no
     continuity; any continuity obligation contradicts the P1
     production-path-identical posture at the behavioral layer even
     where no chain channel carries it.
     *(b) Fails-in-its-own-design-case* — the obligation's coupling
     class (posting responsive to attrition) is masked only by
     surrounding population flow (entry/exit are epoch-quantized and
     cooldown-decorrelated — see §17.9's substrate verification),
     and that masking is thinnest exactly when the herd is thin,
     which by Q3-A is precisely when the floor would be load-bearing.
     A mechanism that is loudest exactly where it must work is not
     mitigated by its quiet case; it is deleted.
     Floor maintenance moves entirely into calibration: §16.2
     obligation 3's margin derives against adversarial max net
     attrition of the whole anonymous pre-gate herd, founders as
     ordinary members. No founder behavior premise remains here;
     premises 1 and 2 survive because a one-shot pre-gate plan
     ({count, completion-before-gate}) is not an ongoing
     differential obligation and creates no reactive coupling.
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
  *Amended at review closure (2026-07-06, §17.2):* consent-to-risk is
  **not license-to-disclose**. "Attributable" means the founders make no
  privacy claim and can never require retroactive privacy; it does
  **not** mean the persona↔founder mapping is published or publishable.
  P4 therefore carries a **non-disclosure commitment**: the mapping is
  never voluntarily disclosed, by anyone, ever — because the cover the
  founder bonds provide to *users* survives only as long as the founder
  set is non-enumerable (§14.3.4). Voluntary disclosure of any founder
  persona is a named **cover-collapse event**, retroactive in effect,
  and is treated with the same severity as a P4 consent failure in the
  §14.5 reversion clause.

### 14.3 Wargames the posture must survive

#### 14.3.1 Founder-exposure permanence

Founder personas minted at genesis are the longest-lived; a genesis
linkage on them is permanent, including retroactively (years later, when
the founding operators' genesis stake is a matter of public interest). P4 is the
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

#### 14.3.4 Founder enumeration and retroactive cover collapse (added at review closure, 2026-07-06, §17.2)

The §14.3.2 partition adversary sorts founders from users **using the
observable channel**. This wargame is the adversary who gets the labels
**for free** — voluntary disclosure, compelled disclosure, an opsec
failure that identifies which personas were the founding operators'. Two facts
make this the sharpest attack on the posture:

1. **The collapse is retroactive.** Chain timelines are permanent. A
   user minted during the transition window had an anonymity set that
   counted the founder bonds *at mint time*; if the founder set is
   enumerated years later, the adversary re-runs the partition on the
   recorded history with labels known, and that user's **historical**
   effective `N` drops to the organic count. Founder cover is therefore
   only as durable as founder **non-enumeration** — it is not a fact
   established at launch and banked; it is a property that must keep
   holding.
2. **Post-gate behavior is an enumeration channel.** If founder wallets
   post bonds but never claim rewards (staked for cover, not yield),
   then once claims exist post-gate, *claim-absence* sorts them — a
   partition rule needing no timing features at all. The disposition is
   M3's, extended: the single-production-path requirement covers the
   **full persona lifecycle** (post, serve, claim, drain), not only bond
   dispatch (§16.4). Founders accrue and claim exactly as any user does
   — M1's gate is uniform, so this costs nothing and closes the channel.
   During the §14.4-measured window this axis is structurally clean:
   M1's zero-accrual means claims are **uniformly absent for everyone**
   pre-gate, so claim features are out of the arm's dictionary by
   construction, not by omission.

Consequences carried forward: P4 gains the non-disclosure commitment
(§14.2); the `K_COVER` cover model gains a **founder-strip sensitivity
row** (§16.2 obligation 3) quantifying what cover remains if the five
are retroactively enumerated — the stripped number is the durability
floor, and the M1 review decides how much reliance on non-enumeration
the constant is allowed to price in.

### 14.4 The partition-adversary arm (pre-committed spec; hypothesis class widened 2026-07-06 and 2026-07-10, pre-implementation)

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
  4. *Spectral partition on the pairwise-similarity graph* (`k` swept as
     in member 1) — *added at review closure (2026-07-06, §17.2)*:
     members 1–3 assume compact (centroid- or band-shaped) structure;
     a similarity-graph cut catches non-spherical, chain-shaped, or
     manifold-shaped founder structure that k-means and cohesion
     enumeration both miss.
  5. *Seeded nearest-neighbor expansion* — *added at review closure
     (2026-07-06, §17.2)*: the adversary is **granted one true founder
     label** (the realistic partial-compromise: one founder doxxed, one
     opsec failure) and takes the `M − 1` nearest pairs in feature
     space; score the overlap with the remaining founders. Seed drawn
     uniformly over the founder set, averaged. Members 1–4 are all
     unsupervised; this is the semi-supervised shape none of them
     covers, and it is the on-ramp to the §14.3.4 enumeration collapse
     — the arm must show one leaked label does not unravel the rest.
     Calibration: permutation over the **non-seed** labels only.
  6. *Top-`M` by joint-density isolation* — *added at distinct-position
     round R4 (2026-07-10, §17.6 Q2-A)*: rank pairs by isolation in the
     **joint** feature space (k-NN distance over the full dictionary);
     take the top-`M` set; score its overlap with the founder set. The
     multivariate generalization of member 2: catches
     **correlation-breaking** founders — every marginal in-range, the
     combinations out-of-support (the shared-ops-tool shape: plausible
     values in implausible pairings). Members 1–5 all miss it: no
     marginal outlier (2), no mutual similarity (3 — the points can be
     mutually *dissimilar*), no compact or graph-cut cluster (1/4), and
     seeding (5) finds neighbors the shape does not have.
  7. *Most-regular-subset enumeration (repulsion detector)* — *added at
     R4 (§17.6 Q2-B)*: over `M`-subsets, score **spacing regularity**
     (suppressed small gaps; inter-event gap variance low against the
     permutation distribution). The mirror image of member 3: any
     *enforced* staggering — scheduling, coordination, proximity
     re-draws — makes the founder set a repulsive point process, and
     repulsion is as detectable as cohesion. Exists to arm P2 as
     amended (§14.2): staggering must be statistical (i.i.d. draws),
     never mechanized.
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
    but drawn from a narrow common band. Detected by family member 3;
    *at review closure (2026-07-06):* **also** required detected by
    member 5 under seeding (the seed's neighbors are the band — if the
    seeded member cannot recover M-c's remaining four, it does not
    bite), and member 4's bite is checked against whichever of M-a/M-c
    its graph cut is sensitive to, recorded per-run.
  - **M-d (correlation-breaking)** — *added R4 (§17.6 Q2-A)*: five
    founders with every marginal drawn in-range but feature
    *combinations* drawn off the joint support (e.g. cadence period and
    dispatch phase individually typical, jointly impossible). Detected
    by family member 6; members 1–5 checked at chance against it,
    recorded per-run (their blindness is the finding that motivated 6).
  - **M-e (repulsed/scheduled)** — *added R4 (§17.6 Q2-B)*: five founder
    anchors placed by an enforced-staggering mechanism (hard-core
    process: minimum-gap rejection). Detected by family member 7 — the
    P2-as-originally-worded violation, from the opposite direction to
    M-a.
  A family proven to bite on M-a alone proves nothing about its other
  members; each control validates the member aimed at its failure mode.
  **Controls are witness-typed (R4, §17.6 finding 6).** M-a through M-e
  are precisely the worst founder configurations that exist; per the
  PF-2 precedent (a sentinel with no triggering production build config
  is a demonstrated failure class in this codebase), a control fixture
  that could leak onto a production founder path would *be* the
  vulnerability it tests. The implementation must make control
  configurations un-instantiable as production founder configs at the
  type level — a distinct witness type for control fixtures, not a
  flag on the production config struct. *Sharpened at R5 (§17.7
  finding 4):* until code exists this is a documented intention, not a
  property — so the witness type is a **co-first-deliverable of the
  implementation round alongside the gating lemma**, and the round's
  first slice does not close until the control type is
  **un-constructible from the production founder-config constructor
  at compile time** (a runtime assertion does not satisfy this).
- **Pass bounds (a-priori).**
  1. *Deployed posture:* `T` within `0.05` of the permutation-null mean —
     no rule in the family sorts founder from user better than chance.
  2. *Each marked control:* `T` at least `0.30` above the
     permutation-null mean, **per control** (M-a through M-e
     separately).
  3. All bounds must hold or the partition measurement is **INVALID**
     (same all-or-nothing shape as §5's controls).

  > **Pinned question (implementation round, 2026-07-11 — a material
  > under-specification surfaced by the first graded run; pinned, not
  > improvised around).** Bound 2 reads `T` — the **family max** — but
  > two of the five controls are single-member-targeted by their own
  > §14.4 construction, and for those the family-max statistic cannot
  > reach `+0.30` at `N = 10`, `M = 5` for structural reasons the spec
  > itself mandates: **M-b** perturbs one founder of `M`, so any rule's
  > founder-set-overlap gain is bounded near `1/M = 0.20` before the
  > selection-inflated permutation null is even subtracted; **M-d**'s
  > founders are *mutually dissimilar by construction* (the property
  > that keeps members 1–5 at chance — measured max members-1–5 lift
  > `+0.03`), so no whole-set structure exists for the max to seize,
  > while member 6 — the aimed detector — lifts `+0.13` over its own
  > null, exactly the specified bite direction. The whole-set controls
  > (M-a `+0.38`, M-c `+0.36`, M-e `+0.32`) clear bound 2 as written,
  > and the deployed posture holds bound 1 (`−0.005`). Disposition
  > options for the design decision: (a) grade single-member-targeted
  > controls on their **aimed member's own-null lift** (a per-member
  > bite bound, same `+0.30` figure); or (b) respecify bound 2 as
  > per-aimed-member for all five controls. Until decided, the run
  > reports **INVALID-with-pins** (bound 3 as written), never a
  > silent pass; the measured record lives in
  > `shekyl-staking-sim --partition-adversary`.
  >
  > **UPDATE 2026-07-11 — RESOLVED, but not by picking (a) or (b).**
  > Both options above were grading-rule edits; review correctly
  > flagged that the disposition was under-determined by an unmeasured
  > property of the deployed statistic, and required the
  > T-computation-rule fact to be pulled at source *before* any
  > disposition. **The verified T-site fact
  > (`partition_adversary.rs`):** `T` is a raw max over per-member
  > Jaccard agreements — *no* cross-member consensus (the
  > "Jaccard-consensus swallows single-member signal" hypothesis is
  > falsified) — but the operating verdict read only `T − null(T)`,
  > and `null(T)` re-maximizes the family per relabeling, sitting
  > ≈ `0.66` at `N = 10` on the *selection freedom of other members*
  > (member 3 enumerates all `C(10,5) = 252` subsets; members 1/4
  > best-of-`k`; member 2 best-of-feature). A lone member-6/7
  > signature — exactly the Q2-A/Q2-B adversary shapes those members
  > were added for (§17 R4) — must exceed that waterline in *absolute*
  > agreement before it registers in `T` at all. Per-member agreements
  > were recorded but consulted by nothing. **That is the
  > detector-architecture branch:** members 6/7 were armed with no
  > trigger; M-b/M-d failing bound 2 was the alarm firing correctly.
  > Picking (a) or (b) as a wording choice would have laundered the
  > Q2-A/Q2-B detector hole into a green consumed by `K_COVER`
  > sealing. **The fix is the aggregator, not the bar:** an
  > **any-member arm** — per member, the observed trial-mean agreement
  > against its *own* null-of-the-mean draws (permutation `p` averaged
  > across trials), exact rank p-value `(1 + #{null ≥ obs})/(perms+1)`,
  > flagged iff `p ≤ α/7` (Bonferroni) at a-priori family-wise
  > `α = 0.05`. Deployed **bound 1 now requires both arms**:
  > `|T − null| ≤ 0.05` *and* no member flags — closing the symmetric
  > false-clean hazard (a max `T` can pass bound 1 on insensitivity;
  > privacy requires that *no* member resolves the founders, and the
  > max can hide the one that does). **Bound 2 as re-specified:** every
  > control's aimed member must flag under the same any-member rule
  > deployment uses; whole-set controls (M-a/M-c/M-e) *additionally*
  > retain the family-max `+0.30`, which their failure modes genuinely
  > move. No bar was lowered; a detection arm was added. The bar
  > derives from per-member null geometry + the multiple-comparison
  > correction, never from the observed failing scores; `trials` is
  > power-sized a-priori to the single-member effect ceiling (M-b's
  > one-of-`M` perturbation bounds the aimed member's Jaccard shift
  > near `+0.05` by hypergeometric arithmetic; `σ/√trials` sizing gives
  > `trials = 500` at power ≈ 0.9), and `perms` carries a loud
  > resolution guard (`1/(perms+1) ≤ α/7`, i.e. `perms ≥ 139`).
  > **Re-graded record (N=10, 500×200):** deployed passes both bound-1
  > arms (family-max lift `+0.001`; per-member min rank-p `0.264`, no
  > flag); M-a/M-c/M-e clear family-max bound 2 (`+0.38/+0.36/+0.32`)
  > with aimed members flagging at the p-floor `0.005`; M-b's member 2
  > and M-d's member 6 flag at `0.005` (M-d members 1–5 stay at
  > chance, the specified single-member bite shape). Verdict:
  > **PARTITION-PASS** — reached by arming members 6/7's trigger,
  > never by moving a bar. Reopening criterion (rule-21 shape): any
  > family-membership change (new member `⇒` re-derive the Bonferroni
  > divisor), any `N`/`M` geometry change (re-derive the power sizing),
  > or a control observed to flag a *non-aimed* member persistently
  > (an aggregator cross-talk finding — re-open the detector round,
  > not the bar).
- **The gating lemma (a-priori deliverable of the implementation round;
  committed before any sweep grades — same provenance rule as the §3.2
  thresholds).** *An absolute upper bound on the probability that `M`
  i.i.d. production entry-gap draws trip any family member above the
  permutation null under the launch-window geometry, derived with no
  reliance on a contemporaneous user cohort.* Named at R4 (§17.6
  finding 1) because two dispositions consume it and were each
  hand-waving it independently: (a) P2-as-amended's "no enforcement
  mechanism" branch — under i.i.d. draws the trap shape must be
  *derivably* rare, since at gate-open the exchangeability arm ("a user
  subset could cluster too") is void (Q3-A: the contemporaneous cohort
  is structurally absent); and (b) §16.2 obligation 3's strip-row floor,
  which prices founder self-cover with no herd present. One lemma, two
  citation sites; it must not be discharged twice informally. If the
  bound is not derivably small under the production gap geometry, the
  disposition is posture redesign (widen the entry-gap distribution),
  never bar relaxation.
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
  *Second scope boundary (R4, §17.6 Q3-A):* the arm measures
  **concurrent-cohort exchangeability** — founders and users drawn into
  the same trial window. The deployment **tenure asymmetry** (pre-gate
  posters vs. the gate-open herd, sortable by first-post height at zero
  adversary cost) is erased by the generator's concurrent lifecycles
  *by construction*, so a bound-1 green is **uninformative** about it.
  This is an instance of the green-by-construction class (§16.10's
  generator-erases-the-channel failure mode), not a one-off: the tenure
  channel is dispositioned by §16.2 obligation 3's strip-row-primary
  rule, never by this arm's pass.
- **Axis completeness (R4, §17.6 finding 5).** The family covers the
  **timing/metadata axis** of founder identification only. The two
  adjacent axes are closed elsewhere, and are named here so the
  timing-only scope is known complete rather than merely partial:
  - *Amount/value axis:* bond amounts are **not** CT-hidden — the bond
    term is loud-but-constant, consensus-forced to
    `bond_floor(holdings)` (§18.9; `bond_post.rs` `FloorMismatch`), so
    it carries zero bits beyond the public holdings descriptor. The
    residual marginal is the **holdings-descriptor stratum itself**
    (*mechanism corrected at R5, §17.7 finding 1*): "holdings" is the
    archival shard descriptor (`HoldingsDescriptor{kind, shard_ids}`),
    a persona-side configuration choice — `bond_floor` is
    `ARCHIVAL_BOND_FLOOR_ATOMIC × shard_count`, flat `1×` for
    `CompleteTree` (`bond_floor.rs`, verified at source), **never a
    function of treasury wealth** — so a common tier is satisfiable by
    founder config, no holdings-split needed. But the descriptor is a
    richer observable than the amount (the shard profile enumerates
    what a persona serves), founder cover pushes founders toward
    distinctive profiles, and at gate-open the user cohort to be
    common *with* is stripped by the same tenure cause as the timing
    cohort (Q3-A). Promoted at R5 from rider-graded config requirement
    to a **named structural channel**: the strip-row floor extends to
    it (calibrate as if the tier/descriptor stratum provides zero
    founder cover at gate-open), and founder self-cover on this axis
    cites the **gating lemma**, not the §18.3 rider alone. The rider
    still grades the deployed posture inside the thin window.
  - *Network/transport axis:* closed by SP-T per-persona circuit
    isolation with the persona-side Tor requirement structurally
    mandatory (§18.13's compile-time posture).
  Timing family ∪ loud-but-constant amount discipline ∪ SP-T isolation
  jointly cover the on-chain + transport observable surface; the
  remaining residual is §4.3.1's off-model ceiling (funding provenance,
  address reuse, off-wire distinguishers), already named.
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

> **UPDATE 2026-07-11 (implementation round, first slice landed —
> `feat/sim-partition-adversary`, `shekyl-staking-sim`):** the two
> co-first deliverables committed before any sweep grades (gating lemma
> `M·((c+1)/(W+1))^{M−1} = 3.5393e-5` at the launch geometry, code
> derivation + exact-CDF domination test; witness-typed controls —
> `ControlWitness` a distinct type with no constructor or `From` bridge
> from the production `FounderConfig`, compile-time un-constructible per
> §17.7 finding 4). Family members 1–7, the named feature dictionary,
> the max-statistic `T` with its permutation null, and controls M-a…M-e
> are implemented and graded (`--partition-adversary`): deployed bound 1
> holds; whole-set controls clear bound 2; the single-member-targeted
> controls surface the pinned bound-2 question above. Riders landed in
> the same round: §16.7 N-sweep (`r < 2` at every swept `N`; measured
> `r` falls with `N`), the M6.2 coupling control (blind@window-0
> `0.231` ≥ `2/N`), §18.3-narrowed bridge grading (deployed at null,
> coupled control bites), and the §18.4 lifetime-accumulation sweep
> (founder anchor visible at cumulative ≈ 1.0). Out of this slice per
> the round's scope: leg-(b) wall-clock emission, M4/M5/M7, GF-4.

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
3. *The cover model is dynamic and carries two named rows* (added at
   review closure, 2026-07-06, §17.2–§17.3). The model that sets
   `K_COVER` may not be a static founder headcount:
   - **Founder-strip sensitivity row (§14.3.4):** cover at gate-open
     computed both with and without the five founder personas. The
     stripped number is the durability floor under retroactive
     enumeration; the review decides how much reliance on
     non-enumeration the constant prices in, explicitly, rather than
     the with-founders number being used as if unconditional.
     *Elevated at R4 (2026-07-10, §17.6 Q3-A): the stripped number is
     the **primary** calibration input at gate-open, not a
     sensitivity.* First-post height sorts the pre-gate cohort from the
     herd for every adversary at zero cost — no disclosure, no
     statistics — so the with-founders number is valid only inside the
     concurrent window the §14.4 arm actually models. Framed as a
     **worst-case floor, not an empirical premise**: calibrate as if
     founders receive zero cover from the gate-open herd, because
     pre-gate non-founder demand is uncontrolled and uncalibratable.
     The framing does not need "pre-gate posters ≈ founders" to be
     true — it needs it to be conservative, which forecloses the
     "but archival-service demand puts non-founders in the pre-gate
     set" rebuttal instead of inviting it. P3 stays harm-reduction
     only; it is **not load-bearing** for this floor (the circularity
     to refuse: P3 thins non-founder pre-gate posting *and* was being
     invoked to justify the ≈-founders premise — any residual cover P3
     leaves is uncontrolled, so the floor is zero-cover regardless of
     P3). Founder self-cover under the floor is priced by the §14.4
     gating lemma. *Extended at R5 (§17.7 finding 1):* the zero-cover
     floor applies per-channel, not only to timing — the
     holdings-descriptor/tier stratum (§14.4 axis-completeness note)
     is calibrated at zero gate-open cover under the same rule, for
     the same tenure cause.
     *Per-channel reachability (R6, §17.8 finding 2).* The
     thickness-reachability check ("minimal `K` with thickness ≥
     target") runs against the **union of per-channel floors** —
     every named channel, not the timing floor alone — and the
     non-existence behavior is armed **per channel**. The descriptor
     channel additionally needs *classification* before it can be
     floored: a zero-cover floor prices "does not help hide them"; a
     cover-mission-forced distinctive profile is a **positive
     per-founder fingerprint that no `K` can herd**. The cover model
     therefore carries a **profile-commonality check** as a
     calibration input: founder shard profiles at gate-open must be
     common-user-profile-shaped (satisfiable by config per §17.7
     finding 1 — many personas over small common shard sets, never
     one `CompleteTree` persona). If the pre-gate archival-coverage
     mission forces rare-shard service, the rare-shard-server set ≈
     founders persists past gate-open as an active sort; the channel
     then classifies fingerprint-not-zero-cover and routes to the
     non-existence behavior (posture redesign, pre-genesis) — never
     to a larger `K`, which cannot help.
   - **Gate-open cohort dynamics row (§17.3):** at gate-open, pent-up
     demand produces an entry cohort that covers *itself* — the first
     post-gate users are mutually covering, and that herd is
     load-bearing for the transition. Its size is demand-driven and
     empirically unknown pre-testnet (the same conditional axis as
     §16.9 item 2); the model states its demand assumption as a named
     conditional, not as a constant.
     *Sharpened at R4 (§17.6 Q3-B): the conditional names
     **monotonicity**, not just size.* Pent-up demand decays with
     delay (competing venues, fixed-need users lost), so `herd(K)` is
     non-monotone in general and "minimal `K` with thickness ≥ target"
     is not automatically well-defined over the herd term. The
     calibration's well-definedness rests on the **monotone floor
     only** — accumulated founder/structural cover — which is itself
     monotone **only under P2's persistence commitment** (§14.2 as
     amended): bonds are removable pre-gate by voluntary exit, offline
     forfeiture, or slash (`PRINCIPAL_STAKE_LIFECYCLE.md`, verified at
     source), so the floor's monotonicity is a posture commitment with
     a named re-run trigger, not a structural fact. Herd contribution
     is a conditional bonus on top. **Non-existence behavior (named,
     per the get-it-right rule):** if no `K` in the candidate range
     reaches the thickness target under the monotone floor, the gate
     does not open degraded and does not wait unboundedly on a
     non-monotone herd assumption — the disposition is posture
     redesign (more founder/structural cover, or a revised target),
     decided pre-genesis by the cover-model run, never discovered
     live.
     *Re-seated at R7 (§17.9): the guaranteed floor dissolves with
     the persistence/maintenance commitment's withdrawal.* Q3-B's
     "which founder?" question resolves against the anonymous
     reading (the §14 terminology pin): founder personas churn like
     users, so there is no committed floor beneath the herd — and by
     Q3-A founders ≈ the pre-gate herd anyway, so cover is
     **population statistics all the way down**, founders as the
     motivated-to-post subset. Well-definedness re-derives on the
     population process under the adversarial-max-net-attrition
     margin (the R7 margin block below); the Foundation backstop is
     not a floor term (not in the anonymity set). The non-existence
     behavior is unchanged and now also catches the case where no
     `K` reaches target under the margin.
     *Sharpened again at R5 (§17.7 finding 2): the floor is a
     calibration-time premise with no runtime re-check, by
     construction.* The M1 gate reads `frozen_shard_count < K_COVER`
     at exactly one site (`consensus_state.rs`
     `epoch_close_compute`), and `frozen_shard_count` is a structural
     function of curve-tree growth — the gate **never reads live bond
     state**, and `K_COVER` is genesis-frozen, so the
     calibration→open window is the entire pre-gate chain life and an
     involuntary removal inside it cannot trigger a consensus
     re-check (verified at source, `k_cover.rs` /
     `segment_freeze.rs`). The re-run trigger is therefore
     **pre-genesis-actionable only** (adjust `K_COVER` before the
     seal).
     *Margin re-derived at R6 (§17.8 finding 1) — the R5 margin was
     sized for the wrong window.* The trigger quantity is
     **cumulative** (`frozen_segment_count(leaf_count)` is a pure
     function of curve-tree growth with no decrement path on bond
     exit — verified at source, `segment_freeze.rs:71`; the only
     decrement is the `pop_block` reorg revert), while the calibrated
     property is **live** herd thickness — so the two diverge under
     any *permanent* attrition (voluntary unbond, key/infra loss,
     abandonment, unremediated slash), and
     `frozen_shard_count ≥ K_COVER` can hold at open while live
     cover has attrited arbitrarily far below the calibration. The
     R5 margin was parameterized on the cooldown-plus-re-bond
     restoration lag, which covers only *transient* thinning;
     permanent attrition's exposure window is the entire pre-gate
     chain life. **Named plainly: this is a deliberate
     derive-don't-cache exception, not an oversight** — the gate
     reads the structural counter *because* a live-cover sensor is
     the flood-then-withdraw DoS surface M2 refused (§16.3: "no live
     participant estimate is ever read... no sensor to attack");
     priority-1 security refuses the sensor, so the freshness
     compensation must live entirely calibration-side, forever, and
     the margin is the load-bearing element of the gate by design.
     *Re-derived a third and final time at R7 (§17.9) — the R6
     maintenance-commitment shape is withdrawn.* R6 compensated the
     cumulative-vs-live divergence with an obligation on founders
     (restore attrited cover within a named lag); §17.9 establishes
     that any founder-differential obligation is itself a posture
     defect, and — the sharper ground — that the obligation fails in
     its own design case: its observable coupling is masked only by
     surrounding population flow, which is thinnest exactly when the
     floor is thin and the obligation would be load-bearing (Q3-A).
     The R7 shape carries no founder obligation at all:
     1. *The floor is population-statistical, not committed.*
        Founder personas are ordinary members of the anonymous
        pre-gate herd: they churn like users and owe no continuity.
        `K_COVER` calibration prices live cover at gate-open as a
        population process over the whole anonymous herd — entries,
        exits, forfeitures — with founders as the motivated-to-post
        subset, never a guaranteed floor beneath it.
     2. *The margin derives against adversarial max net attrition
        over the full pre-gate window* — not expected churn, and not
        any restoration-lag window. The governing adversary is
        §17.7 finding 2's inducible-forfeiture attacker (off-chain
        DoS around challenge windows; challenges themselves are
        honest-server-unfailable beacon replays), who is *more* in
        scope now that no replacement obligation backstops an
        induced exit: the margin is the sole floor-maintenance
        mechanism, so it is sized for the adversary who depresses
        the floor, not the mean. Derived a-priori under the
        gating-lemma discipline, committed before the calibration
        is accepted.
     3. *Reachability under the margin is the existence check.* If
        no `K_COVER` reaches the thickness target once the
        adversarial-max-attrition margin is applied, that is the
        named non-existence outcome — posture redesign pre-genesis
        (more structural cover, revised target), never a degraded
        open and never a founder obligation reintroduced to paper
        the gap. The Foundation backstop (§14 head) is irrelevant
        to this floor: it is not in the anonymity set and
        contributes nothing to herd thickness; no commitment about
        cover attaches to it.

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

*Scope extended at review closure (2026-07-06, §17.2 / §14.3.4):* the
single-path requirement covers the **full persona lifecycle** — post,
serve, claim, drain — not only bond dispatch. A founder wallet that
posts through the production path but never *claims* is sortable by
claim-absence once claims exist post-gate (a partition rule needing no
timing features). Founders accrue and claim through the identical
production path as any user; the CI enumeration asserts one entry point
per lifecycle stage, not one entry point for dispatch alone.

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
4. *N-sweep* (added at review closure, 2026-07-06, §17.1): the main
   gate re-graded at `N ∈ {10, 20, 50}` in-model, with the a-priori
   bound `r < 2` at **every** swept `N`. The bound's ratio form is
   N-invariant by definition; whether the *measured* `r(N)` is flat is
   an empirical property of the score distribution's tail that has only
   been observed at `N = 10`. A measured `r` that grows with `N` means
   the `N = 10` pass was a small-candidate-set artifact — that outcome
   is a redesign signal, never absorbed. Rides the §14.4 round (same
   generator, one extra sweep axis).

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

*Strengthened (2026-07-06, finding B-2):* two structural requirements
the paragraph above implied but did not pin, without which "attack-
shaped" is satisfiable by affirmation wearing an attack's clothes:

1. **Distinct adversarial position.** A bound survives its author's
   attack trivially — authors do not find their own blind spots, which
   is why adversarial review is a separate role. At least one attack on
   each §16.10 question must come from a position **other than the one
   that set the bound**. An author-conducted round (§17 R1 is one) is a
   legitimate *first* pass that sharpens the record; it does not by
   itself satisfy the closure.
2. **"Survived" is a recorded artifact.** Each attack is recorded as
   *the specific construction attempted and why it failed* (or what
   amendment it forced), on paper, in this document — not a checkbox.
   "I tried to break it and couldn't" without the construction is not
   a record. §17.5 carries the first distinct-position instance.

## 17. Review-closure round R1 (2026-07-06): the three attacks, on the record

**Status: conducted; ratified 2026-07-10.** This section is the §16.10
record — each attack was run to land, not to affirm, and where it
landed the amendment is in place (dated, cross-referenced) rather than
deferred. Distinct-position coverage per B-2 is complete across all
three §16.10 questions (Q1: §17.5/§18; Q2/Q3: §17.6); the standing
review's adjudication of §17.6 (2026-07-10) concurred on every outcome
and strengthened the premises with six findings, all landed in place.
**§§14–16 are closed; the §14.4 implementation round is released**,
carrying the obligations enumerated in §17.4 and the pinned premises
of §17.6 with their reopen criteria. Round R5 (§17.7, same day)
adjudicated the R4 landing itself: four findings landed in place
(nothing reopens). Round R6 (§17.8, same day) adjudicated the R5
landing and closed §17 — but that closure was over text containing
the maintenance commitment, and Round R7 (§17.9, 2026-07-11)
reopened R6's landing specifically: the commitment was a ratified
founder-differential mechanism (a category error — Foundation-backstop
properties applied to anonymous founder-users; see the §14-head
terminology pin), withdrawn on two independent grounds, with
finding 1 re-homed to population-level churn calibration and Q3-B
re-seated on the same basis. **§17 is closed as of R7 (§17.9); the
final Gate-7 gates are §17.9's** (adversarial-max-net-attrition
margin; per-channel reachability). §17 reopens only against the
§17.9 termination bar: a construction that defeats both the
categorical rule and the substrate's decorrelation.

### 17.1 Attack 1 — `r < 2` under the panel that reaches `1.86`

**The attack.** Argue the bar was calibrated against a weaker observer
class: the original sweep cleared at `1.43–1.51` against arms now known
to have been tautologically soft (§4.3.1's pre-amendment union), so
perhaps `2` was only ever "comfortably above what the weak panel
measured" and the honest bar under the oracle panel is lower.

**Outcome: the bar survives; the attack lands elsewhere.** The bound is
**claim-anchored, not observer-anchored**: §3.2 derives `r < 2` from
"fewer than one excess de-anonymization across the anonymity set"
(`N·A < 1`), a statement about the acceptable breach rate that does not
mention the observer at all — and §3.4 committed, pre-sweep, that the
bound is evaluated against the *strongest fielded arm*. Strengthening
the panel therefore moves the **measured number toward the bar** (the
correct direction, `1.51 → 1.86`) and cannot move the bar: the bar
answers "how much linkage does the claim tolerate," the panel answers
"how much linkage does the model exhibit." The git-committed a-priori
ordering (§13.4) confirms the constant `2` predates every measured
number, weak-panel numbers included.

**Where it lands instead.** §3.1's annotation "`r` … N-invariant" is a
property of the *bound's meaning*, not of the *measurement*: measured
`r(N)` exists only at `N = 10`. If the true anchor's score is separable
from the candidate field, `P(link)` stays high as `N` grows and
measured `r` grows ~linearly — the `N = 10` pass would be a
small-candidate-set artifact. This is testable in-model at trivial
cost. **Amendment:** §3.2 pinned note; §16.7 item 4 (N-sweep,
`N ∈ {10, 20, 50}`, bound `r < 2` at every swept `N`, a-priori).

### 17.2 Attack 2 — a partition outside the widened family

**The attack.** Construct adversary rules the §14.4 family (members
1–3) cannot represent, and channels that need no timing rule at all.
Four constructions were attempted; three landed.

1. **Non-compact structure (landed).** Members 1–3 all assume compact
   founder structure (centroids, per-feature ranks, cohesion bands). A
   founder set lying on a chain or manifold in feature space defeats
   all three while being cleanly separable by a similarity-graph cut.
   **Amendment:** family member 4 (spectral partition, k-swept).
2. **Semi-supervised expansion (landed).** All members were
   unsupervised, but the realistic adversary starts with one leaked
   label (a doxxed founder, one opsec failure) and expands by
   nearest-neighbor. One free label must not unravel the other four.
   **Amendment:** family member 5 (seeded expansion, permutation over
   non-seed labels), with M-c required to bite under seeding.
3. **Label-free channels (landed, the sharpest).** Two constructions
   need no partition rule: *(a)* post-gate claim-absence — founder
   wallets that post but never claim are sortable by lifecycle shape
   once claims exist; *(b)* actualized enumeration — voluntary or
   compelled disclosure of the persona↔founder mapping hands the
   adversary the labels, and because chain timelines are permanent the
   collapse is **retroactive**: transition-window users lose their
   historical cover years after mint. **Amendments:** §14.3.4 (new
   wargame), P4 non-disclosure commitment (§14.2), M3 extended to the
   full lifecycle (§16.4), founder-strip sensitivity row in the
   `K_COVER` cover model (§16.2 obligation 3).
4. **Oblique projections (did not land).** Projection-pursuit over
   oblique feature combinations is not a named member, but its
   detectable shapes are covered: axis-aligned projections by member 2,
   correlated-structure projections by members 3–4. Omission recorded
   as safe **within the named dictionary**; an adversary computing
   features outside the dictionary is the §4.3.1 off-model ceiling,
   already named.

**Outcome.** The family as previously widened was still a proper subset
of the practical adversary's class — the attack the §16.10 bar was
designed to force. The family is now five members with per-member bite
requirements; the label-free channels are closed structurally (M3
lifecycle, P4 non-disclosure) or priced explicitly (founder-strip
row), not absorbed into the timing arm they would have invalidated.

### 17.3 Attack 3 — tracing the `K_COVER` cycle closed

**The attack.** Show the derivation is circular: the cover model sets
`K_COVER`, `K_COVER` gates the reward, the reward shapes the population,
and the population is what the §14.4 arm measures — so the constant
validates itself.

**Outcome: the cycle does not close; it breaks at a named joint.** The
two consumers (§14.4's dual-disposition pin) consume **different
projections**, and only one of them depends on `K`:

- The **validation projection** (founder/user exchangeability, bound 1)
  is `K`-independent: the arm measures whether the generator's posture
  makes founders sortable, and nothing in that statistic reads the gate
  constant. The property that licenses counting founders toward `N` is
  established without reference to `K` — this is where the would-be
  cycle breaks.
- The **calibration projection** (cover thickness at gate-open) *is*
  self-referential: thickness is computed under the arrival model the
  gate itself induces (zero organic pre-gate, demand-driven cohort at
  opening). But self-reference here is a **fixed-point condition, not
  a vicious circle**: cover-at-opening is non-decreasing in `K` (later
  opening ⇒ at least as much accumulated founder activity and pent-up
  demand), so "minimal `K` with thickness ≥ target" is well-defined and
  monotone-reachable. A circularity would require the *validation* to
  depend on the constant it licenses; it does not.

**What the attack surfaced anyway.** The calibration projection cannot
be a static founder headcount: at gate-open the entry cohort covers
*itself*, and that herd — not the five founders — is the bulk of the
transition cover. Its size is demand-driven and pre-testnet unknown.
**Amendment:** gate-open cohort dynamics row in the cover model (§16.2
obligation 3), with the demand assumption stated as a named conditional
on the same axis as §16.9 item 2.

*R4 corrections (2026-07-10, §17.6).* Two premises in this section's
outcome were softer than stated. **(Q3-B)** The parenthetical "later
opening ⇒ at least as much accumulated founder activity **and pent-up
demand**" overstated: pent-up demand decays with delay, so the herd
term is non-monotone in general; monotone-reachability rests on the
accumulated founder/structural floor only — itself conditional on
P2-as-amended's persistence commitment (bonds are removable pre-gate
by exit, forfeiture, or slash). §16.2 obligation 3's cohort-dynamics
row carries the sharpened statement, including the named non-existence
behavior. **(Q3-C)** The validation projection's `K`-independence
holds *given* two premises now pinned in P2-as-amended: the founder
timing law is `K`-invariant (production draws, not window-length
parameterized), and the observed founder post count at gate-open is
`K`-independent. Without them, `K`-dependence re-enters through the
generator rather than the statistic, and the cycle-break joint is
illusory.

### 17.4 Disposition

All three §16.10 questions are answered attack-shaped, on the record:
the bar survives with a new instrument (N-sweep), the family survives
only after gaining two members and two structural closures, and the
cycle is traced to its breaking joint with one new model obligation.
No bound was relaxed; every amendment is in the adversary-strengthening
direction, inside the legitimate pre-code window (§14.4's own amendment
rule). *(Amended same day, per §16.10's B-2 strengthening: R1 was
author-conducted — a legitimate first pass that sharpened the record,
not by itself sufficient for closure. §17.5 carries the
distinct-position round.)* *(Second amendment, 2026-07-10: §17.5/§18
covered question 1's bar and the family-completeness rule; §17.6
carries the distinct-position adjudication of questions 2 and 3,
completing B-2's per-question coverage.)* **Ratification of
§§17.1–17.6 together by the standing review closes §§14–16; the §14.4
implementation round (now seven members, five controls with
cross-member bite requirements and witness-typing, plus the N-sweep,
the M6.2 coupling control, the §18.3/§18.4 riders, and the a-priori
gating lemma) is the round that follows closure.**

### 17.5 Distinct-position round R2 (2026-07-06): the mean-vs-max challenge, and two structural findings

**Position.** This round's attacks came from the standing adversarial
reviewer, not from the track that authored the bounds — the first
instance satisfying §16.10's distinct-position requirement (itself
pinned by this round's finding B-2).

**B-1 (landed — structural).** The §13.5 no-cross-subsidy pin stated a
rule with no trigger: a reviewer had to *remember* to apply it when the
leg-(b) and partition numbers arrive — the review-discipline-that-
drifts pattern this track has converted to structure everywhere else
(P-1/P-2, F41, gate 11, the coupling control). Amendment: §9
criterion 9 — the report's aggregate verdict is a **computed
conjunction** over every committed bound, INVALID on absence, FAIL on
any miss. The pin is now a property of the artifact.

**B-2 (landed — structural).** §16.10's attack-shaped requirement was
satisfiable by self-attack ("I tried to break it and couldn't" from the
bound's own author). Amendment: §16.10 now requires at least one attack
per question from a distinct adversarial position, and "survived"
recorded as the specific construction attempted — this section is that
record's first entry.

**The r < 2 mean-vs-max attack (the concrete instance, run to land).**

- *The construction.* §3.2 derives `r < 2` from "expected excess
  de-anonymizations `< 1` per set" — a **mean**. S-1 says a *single*
  successful de-anonymization is a breach. A mean of `0.86` excess
  links per set of 10 has substantial mass at "≥ 1 excess link in this
  set" (`≈ 0.6` under near-independence); an untargeted adversary who
  wants *someone* expects to succeed in most sets; and a set-average
  does not obviously control the probability that a specific targeted
  persona is the one linked. So: honest as a set-average bound,
  potentially too loose as a per-persona breach bound — which does S-1
  demand?
- *Why the bound survives.* Two steps, each of which was true but
  unstated. **(1) Exchangeability makes the bound per-persona
  in-model:** personas are synthesized i.i.d., so `P(link)` is the same
  for every persona — set-mean, per-persona value, and max coincide,
  and `r < 2` **is** the targeted-persona bound (`P(link) < 2/N`,
  advantage `< 1/N` per persona, not per set on average).
  **(2) The untargeted reading was conceded at the floor:** blind
  guessing already links someone in most sets (`≈ 0.65` at `N = 10`);
  S-1's operational form (§3.1) protects the *excess over the conceded
  floor*, because an absolute "nobody is ever linked" is unachievable
  against any nonzero channel — the same argument that rejected
  ratio 1 as a permanent red (§3.2).
- *What it forces anyway.* Exchangeability is the load-bearing step and
  it is **in-model true, deployment false**: a persona subclass with
  distinct linkability has a higher `P(link)` that a set average would
  hide, and the mean-to-max lift is carried by **regime splitting**
  (§3.3) — every identified subclass graded as its own row against the
  same bound, never averaged in. That this discipline already operated
  correctly is checkable: the low-activity subclass was surfaced as a
  **failing row** (§13.2) and dispositioned (§14), not absorbed into a
  passing mean, and reporting already quotes the **worst** gate row.
  Amendment: the §3.2 pin naming exchangeability, the per-regime max
  discipline, and the excess-per-persona-per-regime reading of S-1.

**Disposition.** The bar is not moved; the derivation's unstated step
is now stated and its deployment-side failure mode (subclass
heterogeneity) is bound to the regime-splitting discipline that
carries it. One instrument (§9 criterion 9) and one process property
(§16.10 distinct-position) are added. All amendments
adversary-strengthening, pre-code.

### 17.6 Distinct-position round R4 (2026-07-10): questions 2 and 3 adjudicated

**The lens (stated once, per R5).** The separating principle that
decides Q2-C against Q3-A below is not a tiebreaker for one pair — it
is the classifier for an entire residual family: **channels invisible
to the generator because they are structural rather than temporal**
(tenure, holdings tier, live bond state, realized post count, fixture
identity). No timing statistic and no §14.4 arm can see them; a
bound-1 green is uninformative about every member. The test for each
candidate channel is the same: *is it already named and dispositioned,
or is it an unnamed generator-invisible channel?* Named-and-
dispositioned members are safe residuals; unnamed members are Q3-A-
shaped findings waiting to land. §17.7's four findings are instances
produced by applying this lens to the R4 landing itself.

**Position.** Six constructions against §16.10's questions 2 (family
completeness) and 3 (cycle break) were author-fielded, run to land;
the standing adversarial reviewer's adjudication overturned no outcome
(the four landed constructions stand, the two failures stand, no bound
moves) and contributed six
findings on the premises the amendments rest on — two of them
load-bearing premises the record had been carrying unstated. The
findings are the distinct-position content; per B-2, this completes
per-question coverage (Q1 was §17.5/§18).

**The constructions (outcomes as adjudicated).**

- **Q2-A, joint-isolation adversary (landed).** Correlation-breaking
  founders — marginals in-range, joint combinations out-of-support —
  defeat members 1–5. Amendment: family member 6 (top-`M` by
  joint-density isolation), control M-d.
- **Q2-B, repulsion adversary (landed, structural).** P2 as written
  ("never clustered") was jointly unsatisfiable with P1 (i.i.d.
  draws): any enforcement mechanism makes the founder set a repulsive
  point process, as detectable as the clustering it prevents.
  Amendment: P2 reworded (statistical staggering only), family
  member 7 (most-regular-subset), control M-e.
- **Q2-C, order-sensitive features (did not land).** In-model, order
  features are dead by **exchangeability under the P1-amended timing
  law** — i.i.d. draws in both populations kill every timing
  statistic, sorted or ordered, not merely "same axis as
  within-window drift." The deployment-side drift is the named
  cross-trial persistence residual (§14.4 scope boundary).
  *Contingency (finding 4): this coverage inherits Q2-B-as-amended as
  a premise.* Under enforced staggering, repulsive founders carry
  order structure the sorted vector discards, and Q2-C resurrects on
  an axis distinct from member 7's regularity test — a future revert
  of the P2 amendment silently reopens Q2-C, so the interlock is
  recorded here.
- **Q3-A, tenure channel (landed, structural).** First-post height
  sorts the pre-gate cohort from the gate-open herd at zero adversary
  cost, and the §14.4 generator's concurrent lifecycles erase exactly
  this asymmetry — bound 1 can pass while tenure enumerates founders
  trivially. Amendments: strip-row primary at gate-open (§16.2
  obligation 3, reframed per finding 2 as a worst-case zero-pre-gate-
  cover floor, P3 de-load-borne), §14.4 second scope boundary naming
  the green-by-construction class.
- **Q3-B, monotonicity of the fixed point (landed).** "Cover-at-opening
  non-decreasing in `K`" fails on the herd term (pent-up demand decays
  with delay). Amendment: §16.2 cohort-dynamics row sharpened —
  calibration rests on the monotone floor only; non-existence behavior
  named.
- **Q3-C, `K`-dependence through the founder timing law (landed).**
  If founder draws are parameterized by window length (`= f(K)`), the
  validation projection's `K`-independence is illusory. Resolved by
  the P2 amendment (production draws, `K`-invariant by construction),
  plus the count premise below.

**The adjudication's six findings (all landed).**

1. **(Highest) One gating lemma, two hand-waves.** Q2-B's
   "no-mechanism" disposition rested on i.i.d. clustering being
   *vanishingly rare*; its exchangeability arm ("a user subset could
   cluster too") requires a contemporaneous cohort that Q3-A proves
   structurally absent at gate-open. The two findings stack: the
   absolute-rarity arm carries the disposition alone, and it was
   asserted, never derived. (The dismissed soft middle path closes the
   trap: tail-only rejection-sampling has clip-rate ≈ trap-rate, so
   either the trap is derivably rare — mechanism unnecessary — or the
   clip is frequent enough for member 7 to bite the induced
   repulsion.) Landed: the §14.4 **gating lemma**, a named a-priori
   deliverable cited by both Q2-B's disposition and the strip-row
   floor — the GF-7 threshold-provenance rule applied to itself.
2. **Q3-A's premise reframed from empirical to worst-case floor.**
   "Pre-gate posters ≈ founders" is not robust (pre-gate
   archival-service demand puts non-founders in the pre-gate set);
   the calibration floor — zero pre-gate cover, because pre-gate
   non-founder demand is uncontrolled and uncalibratable — needs only
   conservatism, not truth. P3's circularity removed: it both thins
   non-founder pre-gate posting and was invoked to justify the
   premise; it stays harm-reduction, never load-bearing.
3. **Two smuggled premises, both pinned with reopen criteria (rule
   21).** *(a) Floor persistence:* cover-at-opening is active bonds,
   not cumulative posts; verified at source
   (`PRINCIPAL_STAKE_LIFECYCLE.md`) that unbond is voluntary-only
   **but offline forfeiture and slashing are involuntary removal
   paths** — so the monotone floor is monotone only under P2's
   persistence commitment. Reopen trigger: any founder bond
   exit/forfeit/slash pre-gate ⇒ cover-model re-run. Companion
   liveness gap: non-existence of the fixed point is a named behavior
   (posture redesign pre-genesis), not an underspecified state.
   *(b) Count `K`-independence:* the P2 amendment pinned the per-gap
   law but not the post count; with per-persona re-bonding, observed
   founder post count at gate-open is plausibly `f(time-to-gate) =
   f(K)`. Pinned as P2 companion premise 2. Reopen trigger: any
   founder re-bonding policy that is not either a completed pre-gate
   fixed schedule or production-i.i.d. count-exchangeable.
4. **Q2-C's reason made precise and its contingency recorded** (above,
   in the construction entry). The clean principle separating Q2-C
   from Q3-A: both are generator-invisible deployment channels, but
   Q2-C's is already named and dispositioned (persistence residual)
   while Q3-A's tenure channel was not. Same test, opposite verdicts,
   one rule.
5. **Axis completeness.** The family is timing/metadata-axis only;
   the amount/value axis (loud-but-constant, §18.9 — with the
   founder-tier residual now named) and network/transport axis (SP-T
   isolation, §18.13) are dispositioned in §14.4's axis-completeness
   note so the timing-only scope is known complete.
6. **Controls witness-typed.** M-a–M-e are the worst founder sets
   that exist; per the PF-2 precedent, a control fixture leaking onto
   a production founder path would *be* the vulnerability it tests.
   Landed as the §14.4 witness-typing requirement
   (make-bad-states-unrepresentable, applied to the test apparatus).

**Disposition.** No bound moves. The family lands at seven members and
five controls; P2 is reworded with three companion premises; the
strip row is primary at gate-open under a worst-case floor; the
cohort-dynamics row rests on the monotone floor with named
non-existence behavior; and the gating lemma is the implementation
round's first a-priori deliverable — committed before any sweep
grades. §§17.1–17.6 ratified together 2026-07-10 (§17 header); the
two pinned premises of finding 3 carry their reopen criteria into the
implementation round and must be re-checked before Gate 7 discharges
`K_COVER` into the frozen constant.

### 17.7 Round R5 (2026-07-10): adjudication of the R4 landing — the structural-channel family

**Position.** The standing review's second pass, run against the R4
landing itself rather than the original questions. Concurrence with
the landing (nothing closed reopens; no bound moves); four findings,
all instances of the §17.6-head lens — the same generator-invisible
defect class R4 caught, now found living inside R4's own fixes.
**Findings 1 and 2 gate `K_COVER` discharge at Gate 7.** Both source
verifications demanded by the adjudication were run before
disposition; one refutes the adjudication's worst case, one confirms
it and sharpens it.

**Finding 1 (highest) — the §18.9 tier residual was a config
requirement, which is the PF-2 shape again.** R4 landed "founder
bonds must sit at common user tiers" as a rider-graded config
requirement — a review-discipline gate, not a
make-bad-states-unrepresentable gate, for a channel that is
timing-free, always-on, and every-adversary (structurally identical
to Q3-A's tenure channel).

- *Satisfiability verified at source — the worst case is refuted.*
  `bond_floor(holdings)` is `ARCHIVAL_BOND_FLOOR_ATOMIC ×
  shard_count` (flat `1×` for `CompleteTree`), a function of the
  **archival shard descriptor** — a persona-side configuration
  choice — never of treasury wealth (`bond_floor.rs`,
  `bond_wire.rs::HoldingsDescriptor`). The forced-by-holdings trap
  (founder cannot lower the tier without a personas-split that
  re-leaks) does not exist; a common tier is satisfiable by config.
  The R4 axis-completeness wording ("foundation-scale holdings")
  conflated coin wealth with shard holdings — corrected in place.
- *The thin-cohort arm stands in full.* The descriptor is a richer
  observable than the amount; founder cover pushes founders toward
  distinctive shard profiles; and at gate-open the user cohort to be
  common *with* is stripped by the same tenure cause as the timing
  cohort — finding-1-of-R4's gating lemma with a different
  observable. Landed: the channel is promoted to a **named structural
  channel** (§14.4 axis-completeness note), the strip-row zero-cover
  floor extends to it per-channel (§16.2 obligation 3), and founder
  self-cover on this axis cites the **gating lemma**, not the §18.3
  rider alone.

**Finding 2 (high) — the persistence re-run trigger is reactive, and
the floor is a snapshot by construction.** Verified at source: the M1
gate reads `frozen_shard_count < K_COVER` at exactly one site
(`consensus_state.rs` `epoch_close_compute`), `frozen_shard_count` is
a structural function of curve-tree growth (`segment_freeze.rs`), and
`K_COVER` is genesis-frozen (`k_cover.rs` sealing mechanics) — the
gate **never reads live bond state**, so the floor cannot be derived
at open and the TOCTOU window is the entire pre-gate chain life. No
consensus re-check can exist; the derive-don't-cache disposition is
structurally unavailable here. On inducibility: challenges are
deterministic beacon replays (`challenge.rs`, cSHAKE over
`block_hash(H_seal)`) that an honest online founder cannot fail —
but **off-chain DoS of founder serving infrastructure around
challenge windows induces forfeiture**, so the involuntary-removal
path is adversary-influenceable at the network layer and the floor is
an active attack surface at the decision boundary, not a monotonicity
nuisance. Landed (§16.2 obligation 3): the re-run trigger is
pre-genesis-actionable only; post-genesis levers are the
`Slashed → Bonded` re-bond path (floor drops repairable while the
shard clock ticks) and an **a-priori thinning margin** — calibration
must carry a floor margin above the induced-forfeiture adversary's
maximum achievable transient thinning, with the restoration lag
(cooldown + re-bond) as the exposure window, derived under the
gating-lemma discipline before the calibration is accepted.

**Finding 3 (medium) — premise 2's disjunction hid a live branch.**
The i.i.d.-re-bonding disjunct satisfies only *distributional*
count-exchangeability; the realized per-founder count remains
observable, and laundering a realization through exchangeability
needs the user cohort Q3-A voids at gate-open — the disjunct
collapses into R4 finding 1. Landed (§14.2 premise 2): the OR is
struck; the gate-open condition is the fixed pre-gate schedule, full
stop; the i.i.d. disjunct holds only inside the thin window.

**Finding 4 (low, pre-genesis discount) — witness-typing was a
documented intention, not a property.** A §14.4 requirement with no
code is not make-bad-states-unrepresentable. Landed: the witness type
is a **co-first-deliverable** with the gating lemma; the
implementation round's first slice does not close until the control
type is un-constructible from the production founder-config
constructor at compile time (runtime assertion insufficient).

**Disposition.** No bound moves; nothing closed reopens. Amendment
sites: §17.6 head (the lens, stated once), §14.4 axis-completeness
note (mechanism correction + channel promotion), §14.4
witness-typing (compile-time co-first-deliverable), §14.2 premise 2
(OR struck), §16.2 obligation 3 (per-channel strip floor;
snapshot-by-construction sharpening + thinning margin). **Gate-7
gates:** `K_COVER` does not discharge into the frozen constant until
(a) the tier-channel strip floor and its satisfiability pin are in
the calibration, and (b) the thinning margin is derived a-priori and
carried. Findings 3 and 4 are premise tightening and a first-slice
acceptance condition respectively.

### 17.8 Round R6 (2026-07-10): closing round — the R5 margin was sized for the wrong window

**Position.** The standing review's third pass, run against the R5
landing. Concurrence on findings 3 and 4 (closed clean) and
acceptance of the finding-1 retraction on the merits (shard
descriptor ≠ coin wealth; the forced-tier trap does not exist).
Three residuals, every one derived from R5's own admissions rather
than uncovered surface — the convergence shape of a section closing
(6 → 4 → 3 findings, severity concentrating).

**Finding 1 (high, gates Gate 7) — cumulative trigger, live
property, margin sized for the wrong window.** R5's escalation
("snapshot by construction") created a sharper problem than the one
it closed. The gate fires on *cumulative shards ever frozen*; the
property `K_COVER` is calibrated to guarantee is *live herd
thickness at gate-open*. Those diverge under any **permanent** exit
— voluntary unbond, key/infra loss, abandonment, unremediated slash
— each of which reduces live cover and leaves the counter untouched,
so `frozen_shard_count ≥ K_COVER` can hold at open while live cover
has attrited arbitrarily far below calibration. The R5 margin was
parameterized on the *restoration lag* (transient thinning); the
permanent-attrition exposure window is the entire pre-gate chain
life, and the R4 re-run trigger cannot remedy it post-genesis
(`K_COVER` frozen — nothing to adjust).

- *Source verification (a), demanded by the adjudication:*
  `frozen_segment_count(leaf_count)` is a pure function of
  curve-tree leaf count (`segment_freeze.rs:71`); the sole decrement
  is the `pop_block` reorg revert. **No bond-exit decrement path
  exists.** Confirmed.
- *Source verification (b):* the R5 §16.2 margin text was
  parameterized on "restoration lag (cooldown + re-bond)".
  **Undersized against its governing threat model.** Confirmed.
- *The derive-don't-cache charge, answered with a design fact:* the
  cache is **deliberate** — a live-cover gate input is precisely the
  flood-then-withdraw DoS sensor M2 refused (§16.3: no live
  participant estimate is ever read). Priority-1 security refuses
  the sensor; the freshness compensation must live calibration-side
  forever, which makes the margin the load-bearing element of the
  gate *by design* — confirming the adjudication's conclusion that
  its sizing must carry the lemma discipline against the permanent
  window explicitly.

Landed (§16.2 obligation 3, margin re-derived; §14.2 premise 3,
reshaped): no static margin covers permanent attrition (worst case
is total), so the defense decomposes — the persistence commitment
reshapes to a **maintenance commitment** (live cover held ≥ floor
through gate-open, attrited personas replaced within a named lag;
replacements join the same tenure class, no new observable); the
margin re-derives against **max attrition within the detection +
replacement lag**, the only interval attrition is live under a kept
commitment; and **maintenance breach is the named irreducible
residual** — no post-genesis consensus lever exists without re-arming
the M2 sensor, so the breach case is monitored off-chain and priced
in the record rather than discovered at gate-open.

**Finding 2 (medium-high) — zero-cover prices hiding-failure, not
fingerprinting.** The descriptor channel's zero-cover floor treats
identification; if the cover mission forces founders toward
*distinctive* shard profiles, the channel is a positive per-founder
identifier **no `K` can herd**, routing into the R3 liveness path
(no `K` reaches target ⇒ redesign pre-genesis). Landed (§16.2
obligation 3): the thickness-reachability check runs against the
**union of per-channel floors** with non-existence behavior armed
per channel, and the descriptor channel carries a
**profile-commonality check** as a calibration input — founder
profiles must be common-user-profile-shaped at gate-open
(satisfiable by config per §17.7 finding 1); a
cover-mission-forced-distinctive profile classifies
fingerprint-not-zero-cover and routes to redesign, never to a
larger `K`.

**Finding 3 (low-medium) — "fixed pre-gate schedule" is one reading
from re-arming member 7.** "Schedule" collapses count and timing;
a reader who takes it to fix post *times* manufactures the too-even
spacing member 7 detects — the repulsion signature, worn by
founders. Landed (§14.2 premise 2): the schedule fixes **{count,
completion-before-gate} only**; inter-post timing remains P1's
i.i.d. production draw; the interlock is recorded per the
Q2-C/Q2-B silent-revert discipline.

**Disposition and closure.** No bound moves; nothing closed
reopens. **Final Gate-7 gates (superseding §17.7's):** `K_COVER`
does not discharge into the frozen constant until (a) the margin is
re-derived against the maintenance window with the breach residual
named in the calibration record, and (b) the reachability check has
run against the union of per-channel floors including the
descriptor channel's classification. **§17 closes with this
round.** Reopen criterion (rule-21 shape): a **new channel
construction** — a named observable the §17.6 structural-channel
lens has not classified, with an attack shape attached. A round
that produces findings only by restating the lens against closed
text does not reopen §17; per the standing review's own convergence
note, a sound reviewer with no new shape is indistinguishable from
no reviewer, and the record prefers a dry well named to a §17.9
manufactured for cadence.

*Superseded at R7 (§17.9): this round's finding-1 landing — the
maintenance commitment and the detection-plus-replacement-lag
margin — ratified a founder-differential mechanism and is
withdrawn; the closure above was closed-on-that-text and therefore
reopened and re-closed by §17.9, which also restates the Gate-7
gates. The structural facts of this round (cumulative-vs-live
divergence; no bond-exit decrement path; the deliberate
derive-don't-cache disposition per M2; finding 2's per-channel
reachability and finding 3's wording pin) all survive.*

### 17.9 Round R7 (2026-07-11): the category error — founders are users, and the record now says so with three tokens

**Position.** The standing review's fourth pass, opened by its own
retraction: an R7 linkability construction (peel a replacement
persona back to its operator via an A′-replaces-A succession
relationship) was found void — **no succession relationship exists
in the mechanism**; a persona unbonds and is gone, the next is a new
user, and the operator link is precisely what per-persona bonds
exist to destroy. The construction had presupposed the linkage it
then "discovered." But the word that smuggled it in — *replacement*
— was ratified text: R6's maintenance commitment. The finding was a
correct smell with a wrong mechanism, and tracing it surfaced a
category error that had let a fiction be built twice.

**The category error.** "Founder" was carrying two referents across
the record's edges: the **anonymous founder-user population**
(market members who accrue and claim — the population §§14–17
protect) and the **Foundation backstop** (the E-2/gate-5 object:
complete tree, one nominal floor bond, excluded from `Market`,
reward-invisible — verified at source, `consensus_state.rs`
`market_member_at_epoch` / `FOUNDATION_EXCLUDED_FROM_MARKET`,
`REWARD_EMISSION_LEG.md` §4.2, `ARCHIVAL_BOND_GATE4.md` §8.1). The
two cannot be one object: §14.3.4 fact 2 *requires* founders to
claim exactly as users do, and the backstop *cannot* claim by
consensus. Zero accrual severs the backstop from the privacy model
at the root — it is not in the set the calibration protects, so its
persistence is infrastructure, not an observable against the herd.
The R6 maintenance commitment applied a backstop property
(persist, replace-on-loss) to the anonymous-user object; the R7
attack needed both an anonymous operator *and* a continuity
obligation on one object — a pairing the architecture never
produces. Landed: the §14-head **terminology pin** (three
referents, three tokens: founder persona / Foundation backstop /
founding operators), with the operator usages scrubbed (§14.3.1,
§14.3.4) so no token is shared.

**The withdrawal (P2 premise 3 deleted).** Two independent
sufficient grounds, either alone dispositive:

1. *Categorical.* Any obligation unique to founders is
   founder-differential conduct in a system whose thesis is that
   founders are indistinguishable from users. Founders churn like
   users and owe no continuity. (Pre-staged redundant personas —
   the pre-provisioning alternative — are rejected as strictly
   worse: more founder-specific behavior, a louder fingerprint.)
2. *Fails-in-its-own-design-case.* The obligation's coupling class
   (posting responsive to attrition) is masked only by surrounding
   population flow — and that masking is thinnest exactly when the
   herd is thin, which by Q3-A is precisely when the floor is
   load-bearing. A mechanism that is loudest exactly where it must
   work is not "clean except under a caveat"; it is deleted. This
   is the disposition's basis, not its asterisk.

**The withdrawn channel, on the record.** Before the withdrawal
landed, an exit-correlated-replacement-posting channel was claimed
as a new construction satisfying the §17.8 reopen criterion. It
was refuted at source and is withdrawn: entry effects are
epoch-quantized (`E_join = height / SETTLEMENT_EPOCH_BLOCKS`,
market membership from `E_join + 1`), exit is smeared across
`RELEASE_COOLDOWN_EPOCHS = 2` (~28 days) — a constant whose pinned
rationale names "Unbond decorrelation headroom" — and **no repost
mechanism exists** in the lifecycle. A smeared-and-quantized exit
followed by a boundary-landing post amid the window's flow is
population flow, not trigger-response. **The reopen therefore rests
on the stronger trigger, not the recorded one:** a ratified
founder-differential mechanism that shouldn't exist. The
thin-population edge of the masking argument is not a residual — it
is ground 2 above.

**Finding 1, re-homed a third and final time.** The
cumulative-vs-live gap (§17.8, structural facts intact) resolves by
**population-level calibration**: `K_COVER` priced over the whole
anonymous pre-gate herd's churn process, founders as ordinary
members, margin derived against **adversarial max net attrition
over the full pre-gate window** (the §17.7-finding-2 inducible
adversary, *more* in scope now that no replacement obligation
backstops an induced exit) — never expected churn, which undersizes
against the adversary who depresses the floor. No founder
obligation; no live sensor; M2 intact. Q3-B re-seated on the same
basis (§16.2 cohort row): the guaranteed floor dissolves, cover is
population statistics all the way down, and the non-existence
behavior now also catches margin-inclusive unreachability.
Premises 1 and 2 survive — a one-shot {count,
completion-before-gate} plan creates no reactive coupling.

**Disposition and closure.** §17 was closed at R6 on text
containing the maintenance commitment — closed-on-a-fiction, which
is worse than open — so R6's landing specifically reopened, and
**§17 re-closes on this round, load-bearing rather than by
exhaustion.** **Final Gate-7 gates (superseding §17.8's):**
`K_COVER` does not discharge into the frozen constant until (a)
the margin is derived against adversarial max net attrition over
the full pre-gate window and carried in the calibration record,
and (b) the reachability check has run against the union of
per-channel floors including the descriptor channel's
classification (§17.8 finding 2, unchanged). Termination is
belt-and-suspenders: the categorical rule forbids
founder-differential obligations, and the substrate's own
decorrelation (epoch quantization + cooldown headroom) blunts the
coupling class such obligations would produce even if the rule
were violated. A §17.10 must construct **against the substrate** —
defeat both the rule and the quantization with a named observable
and an attack shape — which is the real-work bar, not the
lens-restatement bar.

## 18. Distinct-position round R3 (2026-07-06): the completeness gap the mean-vs-max disposition left open

**Position.** Standing adversarial reviewer, distinct from the bound's
author (§16.10 requirement). **Result.** The §17.5 mean-vs-max
disposition is *sound but incomplete*: it proved the max is captured
**for the axis it splits on** (activity level) and silently assumed the
heterogeneity-axis enumeration complete. It is not. R3 enumerates the
un-split axes and the un-graded seams, dispositions each, and states
two conditionals that promote the honest `1.86` to less than a reader
would otherwise take it for. **No amendment reopens the `1.86`** — it is
what it honestly is for the entry seam, per-post, timing-channel,
per-instant, unstratified; each finding names a different one of those
five qualifiers.

The five surfaces, ranked by how load-bearing (§18.1–§18.2 are seams the
review intensity had not reached; §18.3–§18.5 are the concrete content
of the completeness gap):

### 18.1 The exit seam (GF-4) is unmeasured — the `1.86` bounds one of two co-equal channels

WI-4 grades the **entry** seam (funding → bond-post). S-1
(principal↔`P`) breaks if an adversary links via the **exit** seam
(drain / persona rotation) just as surely, and GF-4 was deferred as a
separate one-sided draw with its own future round. The genesis claim
rests on the **conjunction** of both seams; only the entry seam has a
number. Worse, the co-trigger principle applies: GF-4 and the
persona-rotation network fire on the **same event** (the drain), so
they cannot be measured independently and multiplied — they must be
**graded jointly**, and the joint observable may leak more than either
alone.

**Disposition.** GF-4 is a **co-equal genesis gate on the sealing
path**, not a deferred someday — it needs the same
a-priori-threshold-then-attack-shaped-measurement treatment GF-7 got.
Recorded as a sealing-path blocker in `docs/FOLLOWUPS.md`. The asymmetry
of attention (a polished entry number, nothing on exit) is the finding;
the seal needs both.

### 18.2 Per-post bound vs per-principal property — the cross-seam conditional (highest-leverage; landed on the verdict line)

`r < 2` is a per-**post** bound; S-1 is a per-**principal** property. A
principal holds `K` personas; breaking the principal needs **any one**
linked, so if personas are independently linkable at per-post `p ≈ 0.19`
the per-principal breach probability is `1 − (1 − p)^K`, compounding
toward 1 with `K`. The only brake is **persona mutual-unlinkability**,
which is **GF-4** (§18.1) — unmeasured. So the per-post bound promotes
to a per-principal guarantee **only where GF-4 holds**, and that was an
unstated dependency.

**Disposition (landed now, this round).** The conditional is stated on
the verdict line (§13.1 scope pin) and in the sealed-claim ledger
(§13.5), structurally parallel to isolation conditioning: a
buildable-kind conditional that gates a **scope promotion**
(post→principal), discharged only by the GF-4 measurement in §18.1.
This is the single most important previously-unstated dependency in the
gate, because S-1 is defined at the principal level and the bound is
measured at the post level — a one-line honesty fix that also makes
GF-4's sealing-path status visible.

### 18.3 Observable bond-attribute strata partition `N` (the concrete completeness gap)

The mean-vs-max disposition's regime split covers activity level; it
does **not** cover the observable attributes that also partition the
anonymity set: at source (verified R3) the bond record carries
**`bond_floor` and `holdings` in cleartext** (C0-visible per
`ARCHIVAL_FIREWALL_THREATS.md`), and, once there are multiple shards,
**which shards a persona serves**. A persona in a rare attribute
stratum sits in a **smaller** effective `N`, so its `r` is higher, and
an unstratified steady-state row averages that exposure away — the exact
mean-vs-max failure, on a different axis.

*Correction to the reviewer's framing, verified at source.* The
concrete lever is **not** a lock-tier multiplier: lock tiers
(1000/25000/150000-block, 1.0×/1.5×/2.0×) belong to the **retired
confidential-staking** path and are **deleted** from the archival
reward leg (`REWARD_EMISSION_LEG.md` §"Delete"; archival collateral is a
flat `bond_floor` per shard, `bond_floor.rs`). The adverse
value↔privacy coupling the reviewer identified is **real but arrives by
a different route**: `holdings` (shard count / `CompleteTree`) scales
`bond_floor` and is the stake-size-bearing observable, and the
work/`scarcity`/`g(age)` economics make a **larger-holdings, older-shard
persona both higher-yield and rarer-stratum** — the most-valuable
personas systematically in the smallest anonymity sets.

**Disposition.** Linkability must be graded **stratified by observable
bond attributes**, with `holdings`/`bond_floor` as the first stratum and
shard-service as the second once multi-shard; the §3.3 regime
enumeration is extended to name these as heterogeneity axes. Rides the
§14.4 measurement round already on the critical path.

> **Narrowed by §18.8 (the P-is-public correction):** the
> "smaller effective `N`" framing treated the pseudonym set as an
> anonymity set; it is not one — `P` is public. Strata are graded as
> candidate **bridge** axes (attribute↔user-side correlate), not as
> crowds `P` hides in. The entry-side amount correlate is closed
> structurally (§18.8 trace).

### 18.4 Linkability accumulates over a persona's lifetime — the gate grades per-instant

Every WI-4 number is per-post; an adversary correlates over a persona's
**entire observable history** (each bond, rebond, serve-credit response,
reward emission, drain is an observation), so cumulative exposure is
`1 − (1 − p)^events`, growing monotonically with lifetime. A per-post
`p ≈ 0.19` is not the exposure of a persona observed across dozens of
events. This **compounds the cold-start finding and is worse than it**:
cold-start is thin cover at birth; accumulation is exposure growing over
the whole life — and the **same founder personas** are
long-lived by construction, so they suffer both.

**Disposition.** Grade **cumulative lifetime linkability** for a
representative long-lived persona, not only per-post, and treat persona
**lifetime as a swept axis** with the founder/long-lived end as the
pessimistic anchor — the §6 pessimistic-distribution discipline
(already applied to activity rate) extended to longevity. Rides the
§14.4 round.

### 18.5 The value channel — loud reward amounts are a recurring, persona-tied, stake-bearing observable (verified at source)

GF-7 grades **timing**; the reward is the one place **amount** re-enters
as a recurring observable, and the reviewer's load-bearing question —
does FCMP++ hide reward amounts the way it hides funding — is answered
**no, by design**, verified at source (R3):

- Reward payout is a **staker-submitted claim tx**
  (`txin_archival_reward_emission`), not coinbase, carrying
  **`reward_amount_plain` per epoch in cleartext**
  (`emission_wire.rs`); the design principle is **"loud reward"** so
  every node can recompute and audit inflation
  (`REWARD_EMISSION_LEG.md` §2) — confidential reward amount is
  explicitly **deleted** (§5.5). Contrast funding, which is
  Pedersen/FCMP++-hidden.
- It is **directly tied to `P`** on-chain via `p_pubkey` /
  `P_canonical_id` and bond-record dedup (`emission_wire.rs`,
  `claimed_epochs.rs`); privacy on the leg is *recipient hiding on the
  output set*, **not** hidden amounts.
- Cadence is **per settlement epoch** (~10,000 blocks), recurring for
  the persona's whole life — so it **compounds §18.4** (a per-epoch
  repeat of the leak) and **repeats the §18.3 partitioning attribute**
  (the loud amount reflects `holdings`-scaled work, once per epoch).
- Implementation status: codec + arithmetic exist; the vin is
  consensus-**inert** until PR-E3 / C-1 (`emission_wire.rs`,
  `IMPLEMENTATION_INDEX.md`), so no reward amounts are on-chain **yet**
  — the channel is a genesis-blocking design fact to grade before the
  leg activates, not a live leak today.

**Disposition.** The value channel is **orthogonal to everything the
timing gate measures** and is **open by design** (loud amounts, P-tied,
recurring). It is not gradable by the GF-7 timing correlator as
constituted; it needs its **own measurement** of how much the loud
per-epoch amount sequence links `P` across epochs and to the
`holdings` stratum — folded into the GF-4 exit-seam round (§18.1) since
both are about what the persona's *non-entry* activity leaks, or its own
round if that proves too large. Recorded in `docs/FOLLOWUPS.md`. This
is the surface most likely to have been genuinely un-thought-about,
because the entire GF apparatus is timing-shaped.

> **Sharpened by §18.8 (the P-is-public correction):** "links `P`
> across epochs" is a non-finding — `P` is public. The channel's real
> content is the `P`→user **amount bridge**: the entry-side form is
> closed structurally (bond amount consensus-forced to
> `bond_floor(holdings)`, §18.8 trace); the surviving form is V-2b —
> `P`'s lifetime total is publicly computable and matchable against
> user-side amount surfaces at exit.

### 18.6 Disposition summary and what stays on the critical path

- **Landed now (verdict-line honesty):** §18.2 cross-seam/per-principal
  conditional (§13.1, §13.5) — the highest-leverage one-line fix.
- **Verified at source, reframed:** §18.5 value channel (loud, P-tied,
  recurring — confirmed open by design); §18.3 attribute strata
  (tier-multiplier route corrected to the `holdings`/`bond_floor`
  route).
- **New sealing-path measurement rounds:** §18.1 GF-4 exit seam
  (co-equal genesis gate) and §18.5 value channel (folded into it or
  its own), both a-priori-threshold-then-attack-shaped.
- **Extensions riding the §14.4 round already on the critical path:**
  §18.3 attribute-stratified grading and §18.4 lifetime-accumulation
  sweep — both are regime-enumeration/pessimistic-distribution
  extensions, not new machinery.

The through-line: R1/R2 drove the **entry seam** to a polished per-post
timing number; R3 finds the seal needs the **exit seam** (GF-4), the
**per-principal** aggregation S-1 actually names (conditional on GF-4),
the **value channel** (loud rewards), the **attribute strata**, and the
**lifetime accumulation** — four of five being scope/channel/time
qualifiers on the honest `1.86`, and the fifth (GF-4) a co-equal gate.
None reopens the number; all five are recorded so the seal cannot read
the entry-seam number as the whole claim.

### 18.7 R3 addendum: tiers vs continuous accrual — the design question, answered at source (2026-07-06)

**The question.** Would replacing discrete lock tiers with a climbing,
duration-based accrual rate (unbond whenever; yield a public function
of elapsed time) reduce the bond-attribute partition — or create *more*
uniqueness, because the payout then encodes exact duration?

**The design-level answer (recorded because the reasoning generalizes).**
The two models leak on different channels, and the channels are not
symmetric. A tier leaks at **two** moments: bond time (the label is on
the post the instant it lands — a forced, frozen, early-bound partition
on the exact entry-seam event GF-7 grades) and unbond time (the payout
reflects it). Continuous accrual leaks at **one**: unbond time, where
the payout back-solves through the public rate schedule to a duration.
But the duration leak is **late-bound and user-shapeable** (the persona
chooses when to unbond, and quantized accrual boundaries let it land in
a duration class shared with everyone else in the window), where the
tier is **early-bound and protocol-forced**. Controllable exposure
dominates structural exposure: continuous-with-quantized-boundaries
reconstructs the bounded-bucket property of tiers, but with the bucket
chosen at exit (invisible at the entry seam) and chosen to maximize
crowd rather than assigned by capital. It also dissolves the adverse
value↔privacy coupling of tiers (highest-yield tier = smallest crowd =
most-valuable personas most linkable). The honest price: the rate-curve
**shape** becomes a privacy parameter (sharp knees → rational unbonders
cluster past each knee → de-facto tiers rebuilt), and the privacy claim
loads more heavily onto the exit seam, where correlated mass-unbonding
(a co-trigger) can thin duration classes — cold-start thinness
relocated to the exit. Verdict: **not more uniqueness — relocated,
controllable uniqueness**, moved off the channel that cannot be
defended (forced bond-time labels) onto one that can (late-bound,
quantizable exit classes), *provided* the class width and curve shape
are a-priori-derived and measured, and the exit seam gets a real gate.

**Verified at source: the shipped archival leg already embodies the
strong form of this disposition, by a cleaner route than the proposal.**

1. **Tiers are gone** (retired with confidential staking; §18.3), and
   the climbing rate exists — but it attaches to **shard age**, not
   persona bond duration: `g(age) = 1 + age_weight · age`
   (`reward_arithmetic.rs::g_age_milli`), a public property of the
   *data* identical for every holder of the shard. The accrual input is
   not a persona attribute at all, which is strictly cleaner than
   persona-duration accrual: the rate schedule cannot fingerprint the
   persona because it does not read the persona.
2. **There is no lump-sum unbond payout to back-solve.** Rewards are
   per-epoch loud claims (§18.5) whose `settlement_epochs` vector
   publishes the persona's bonded epochs **directly**, at
   settlement-epoch granularity (`SETTLEMENT_EPOCH_BLOCKS = 10_000`).
   The prescribed quantized duration classes are therefore
   **structural, not a mitigation to add**: duration resolves to
   ~10k-block classes by construction, never finer, and there is no
   arithmetic bridge sharper than the published class. The
   exit→entry back-solve bridge the wargame feared is capped at class
   width.
3. **The knee wargame is real in the current design — but on the
   holdings axis, not duration.** `g(age)` is linear (no knees ✓), but
   `Curve(work)` is banded piecewise-linear with breakpoints at
   `plateau/4`, `plateau/2`, and the plateau
   (`reward_arithmetic.rs::curve_milli`): rational operators cluster
   holdings at the plateau, i.e. the curve's incentive gradient
   produces clustering on the **observable `holdings` attribute** —
   exactly the §18.3 stratum. Direction is **ambiguous**: clustering at
   the modal point may *thicken* that stratum (good — a bigger crowd)
   while thinning the tails (bad — outlier holdings more linkable).
   Which way it cuts is a measurement question, not a debate.
4. **The residual bond-time attribute survives:** "every bond is
   identical at the seam" is not true of the shipped leg —
   `holdings`/`bond_floor` is cleartext on the post (§18.3). The tier
   channel is deleted; the holdings channel is the remaining bond-time
   partition, already dispositioned to stratified grading.

**Pins forced (all routed to rounds already on the R3 map — no new
machinery):**

- **P-curve (reversion-clause-shaped):** the linearity of `g(age)` and
  the breakpoint structure of `Curve` are **privacy parameters, not
  just economic ones**. Any future amendment that adds knees to the
  age/duration axis, or moves `Curve` breakpoints, re-shapes incentive
  clustering on an observable attribute and requires review under this
  gate (a §14.4/§18.3-style stratified re-grade), not economic review
  alone. Reopening criterion: any PR touching `g_age_milli`,
  `curve_milli`, or their parameters.
- **P-width (a-priori discipline, exit-side analogue of the entry-gap
  window):** `SETTLEMENT_EPOCH_BLOCKS` is the duration-class width.
  The GF-4 round derives the adversary-advantage bound as a function of
  class width — how much does knowing the class narrow the
  funding-seam candidate set — **before** 10_000 is accepted as a
  privacy value rather than an economic one. Same
  threshold-before-measurement ordering as §3.5.
- **P-claim-timing:** each per-epoch emission tx is a **recurring
  timing observable at a new seam** (the claim seam): *when within the
  claimable window* `P` submits is the entry-gap channel's shape,
  repeated per epoch for the persona's life (compounding §18.4). The
  entry-seam dispersal/jitter discipline applies there; graded in the
  GF-4/value-channel round (§18.1/§18.5), including the batching
  (≤ 15 epochs) and forfeiture (`W = 26`) parameters as sweep axes.
- **P-correlated-exit:** mass unbonding is a co-trigger (all founders
  exit at once; a market event fires correlated drains); duration-class
  anonymity must hold under **correlated** exits, not independent ones
  — cold-start thinness relocated to the exit seam and the duration
  axis. Named wargame for the GF-4 round; a further reason GF-4 is
  co-equal (§18.1).

**Net.** The design question is answered and the answer is already
shipped in its strongest form: no persona-duration accrual at all (the
rate reads the shard, not the persona), structural epoch-granularity
duration quantization, a linear age curve. What the analysis adds is
the four pins above — the curve shape and class width become named,
reviewed privacy parameters, and the claim-timing and correlated-exit
observables join the GF-4 round's surface. Nothing here reopens the
`1.86`; everything lands on the exit-seam gate the seal already needs.

> **Superseded in part by §18.8 (the P-is-public correction):** the
> P-curve pin's "privacy parameter, not just economic" framing
> over-escalated — holdings clustering partitions the set of
> *pseudonyms*, which are public objects, and is privacy-relevant only
> through a user-side correlate. See §18.8 for the corrected pin set.

### 18.8 R3 correction round: the P-is-public reframing, retractions, and the amount-bridge trace (2026-07-06)

**The correction (collapses an error running through §§18.3, 18.5,
18.7).** `P` is the pseudonym — it is *supposed* to be visible. Every
on-chain act of `P` (holdings cleartext, `settlement_epochs`, claim
cadence, reward amounts) is attributable to `P` by construction, and
`P` has no anonymity to lose: **the protected object is the `P`→user
link, and nothing else.** Prior sections repeatedly treated
`P`-distinctiveness (a rare holdings value, a recurring claim habit, a
thin stratum) as an exposure in itself. That framing is wrong: a
distinctive attribute on `P` partitions the set of pseudonyms — a set
of public objects — and threatens nothing unless the attribute also
**correlates with something user-identifiable**, i.e. forms a bridge.
Every exposure in this document must be re-asked in exactly one form:
*does this observable help an adversary connect `P` to the user?*

**What survives re-asking (the bridges).** GF-7's entry seam (the
funding event is the *user's* act; timing correlation to the bond post
is the bridge — the `1.86` measures this correctly). The claim-cadence
channel, **re-anchored**: it matters only insofar as `P`'s claim timing
correlates with the *user's* observable rhythm (session clock, refresh
cadence, sibling personas sharing the user's clock) — the co-trigger
structure, not `P`'s habit per se. The exit seam (GF-4): the drain
moves value back toward the user and rotation fires on the user's
event. Lifetime accumulation (§18.4), **re-anchored**: each `P` event
is one more *timing sample against the user's clock*, so exposure still
compounds with lifetime — through the bridge, not through `P`'s
fingerprint.

**Retractions (recorded, not rewritten — the sections stand as the
history of the error):**

- **§18.3's intrinsic-stratification claim is retracted.** "A rare
  holdings stratum has smaller effective `N` so its `r` is higher"
  treated the pseudonym set as an anonymity set. It is not one.
  Holdings distinctiveness on `P` is a **non-finding** absent a
  user-side correlate; the §14.4-round stratified grading obligation is
  **narrowed** to the conditional form: grade strata only as candidate
  *bridge* axes (does the attribute correlate with a user-side
  observable?), not as crowds `P` must hide in.
- **§18.7's P-curve escalation is retracted.** The `Curve` knee does
  not "manufacture the anonymity crowd" — there is no crowd `P` needs,
  because `P` is not hiding. The curve is an **economic** parameter;
  its privacy relevance is contingent on holdings correlating with a
  user-side amount, which the trace below addresses. The reopening
  trigger (PRs touching `g_age_milli`/`curve_milli`) downgrades from
  "stratified privacy re-grade required" to "check the §18.8 bridge
  question if the change alters what is publicly computable about
  value flows."
- **P-width and P-correlated-exit survive** (class width bounds the
  exit→entry *bridge*; correlated exits are *user-event* co-triggers),
  and **P-claim-timing survives re-anchored** as above.

**The amount-bridge trace (the sharpest question, verified at source).**
Does `P`'s public bond amount reveal the user's funding amount? **No —
the bridge is structurally closed at the entry seam, by consensus
rule, in the strongest form (quantization to a protocol constant):**

1. The bond post's public amount is **consensus-forced** to
   `bond_floor(holdings)`: `verify_join_market_bond_post` rejects any
   vin where `bonded_total_atomic != floor || bond_credit != floor`
   (`bond_post.rs::FloorMismatch`), and the builder pins the same
   invariant at construction (`shekyl-archival-bond-builder`
   `bonded_total_atomic == bond_credit == bond_floor(holdings)`). The
   public amount carries **zero bits beyond the holdings descriptor**,
   which is already cleartext in the same vin. It cannot be the
   funding amount forwarded, because consensus fixes it to a value
   chosen before the user decided how much to fund.
2. The funding side is hidden and change is hidden: user→`P` funding
   is ordinary FCMP++ (Pedersen commitments); the assemble path
   (`bond_assembly.rs::sweep_funding_outputs` — renamed from
   `select_funding_outputs` and converted to full-set sweep semantics by
   the GF-4b amendment, `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.1; this
   point's hiddenness argument is extent-independent) consumes `P`-local
   spendable outputs and returns excess to `P` as ordinary hidden
   outputs.
3. No principal reach-across exists in code: the
   `InsufficientFunding` refusal arm names the rule — `P` bonds from
   `P`-local outputs only ("no reach-across to principal outputs;
   that reach-across is the funding-seam linkage the architecture
   firewalls").

**Surviving residuals of the trace (both `P`→user-shaped, both routed
to the GF-4 round):**

- **V-2a — staker-membership prior (entry side).** Because the
  required funding is a universal public constant
  (`bond_floor·k + fee`), an adversary with *user-side off-chain*
  amount visibility (e.g. exchange-withdrawal records) gains a "this
  user is funding an archival bond" prior. It selects no particular
  `P` — every bond costs the same, which is crowd-forming — but it
  sharpens the GF-7 correlator's candidate set. In-model this is
  subsumed by the adversary-knows-candidates assumption; named so the
  subsumption is visible rather than accidental.
- **V-2b — exit lifetime-total match (the value channel's surviving
  form).** `P`'s lifetime value — `bond_floor·k` returned at drain
  plus `Σ reward_amount_plain` — is **publicly computable to the
  atomic unit** from chain data. On-chain re-entry of that value is
  FCMP++-hidden, so the bridge requires user-side amount visibility: a
  user-side deposit matching `P`'s publicly-known lifetime total is an
  amount-certainty bridge, independent of every timing mitigation.
  This is what §18.5's value channel **is**, under the corrected
  framing: not "`P`'s amounts are distinctive" (non-finding) but
  "`P`'s publicly-computable total can be matched against user-side
  amount surfaces." Graded in the GF-4 round; the operational
  mitigation shape (drain splitting/laundering through time) is that
  round's design question.

**Net effect on the R3 map.** GF-4 and the value channel remain
load-bearing, **for the corrected reason**: they are where `P`'s public
activity can bridge to the user — by value (V-2b) and by time
(drain/rotation co-trigger, claim cadence against user rhythm). The
entry-seam `1.86` covers the funding-*timing* bridge; the entry-seam
funding-*amount* bridge is closed structurally (this section); the
un-graded surface is the exit-side pair. §18.3's stratified grading
narrows to bridge-axis screening; §18.7's curve pin downgrades to
economic-with-a-bridge-check. The verdict-line conditionals (§13.1,
§13.5) are unaffected — they were already stated in `P`→user form.

### 18.9 Mechanism pin: the bond term is loud-but-constant, not CT-hidden; the mask wargame is unrepresentable (2026-07-06)

A follow-on review reading proposed a different closure mechanism for
the entry amount bridge — that the bonded amount is a Pedersen/CT
commitment hidden *above* the floor, with the blinding mask as random
or user-configurable padding — and, on that mechanism, proposed a
cross-persona mask-consistency wargame (a user configuring the same
distinctive padding across `P1`/`P2`/`P3` bridges them to a common
configurer). **Verified at source: that mechanism is not the design,
and the record must not absorb it, because the two closures fail
differently and imply different residuals.**

What the code does (`bond_ct_balance.rs`, `bond_post.rs`,
`stake_engine.rs` assemble path):

1. **The bond term enters the CT balance equation as a transparent
   cleartext term.** `verify_bond_post_ct_balance` places
   `BondTerm::Credit(amount)` on the output side as `amount·H` —
   H-only, no blinding factor, structurally identical to the fee term
   (the unit test balances `h_only(BOND_CREDIT)` against
   `Credit(750_000_000)`). The equation's *hidden* legs are the
   funding inputs (pseudo-outs) and the change output (out masks).
   `bond_credit`/`bonded_total_atomic` are cleartext `u64`s on the
   vin, consensus-forced to `bond_floor(holdings)` **exactly** (§18.8;
   `FloorMismatch` rejects both directions). Nothing sits hidden above
   the floor: over-funding exits as hidden **change back to `P`**,
   never as extra bonded amount.
2. **`commitment_mask` is a deterministically-derived Pedersen
   blinding factor, not padding and not configurable.** The input-side
   mask is re-derived via HKDF from the output's shared secret
   (`derive_output_secrets(combined_ss, index) → z`,
   `stake_engine.rs::derive_p_source_secrets_bundle`); the change-side
   mask comes from `construct_output` the same way. No user-facing
   configuration surface for either exists in the repo, and no
   "configurable with warning" path exists.

**Dispositions:**

- **The entry amount bridge stays closed, with §18.8's mechanism:**
  the bond's public amount carries zero bits because it is a
  *constant* (loud but information-free), not because it is *hidden*.
  The funding/change legs are CT-hidden; the bond term is
  quantized-to-constant. The distinction is load-bearing: a
  hidden-amount design would carry mask-management residuals; a
  constant-amount design carries none.
- **The mask-consistency wargame dissolves as
  unrepresentable-by-construction.** The failure mode requires a
  user-chosen mask; the mask is HKDF-derived per output. The
  "remove the configuration option" disposition the wargame reached
  for is the design as built — there is nothing to remove. (Recorded
  because the wargame's *shape* is right and would apply if a future
  change ever made masks or bonded amounts user-chosen; reopening
  criterion: any PR introducing a user-supplied blinding factor or a
  bonded amount above the floor.)
- **"The remaining bridges are timing-only" is pinned with one
  qualifier: on-chain.** On-chain, with the tier channel deleted, the
  bond amount constant, and funding/change CT-hidden, the `P`→user
  bridge classes are timing-shaped (funding-seam timing — graded,
  `1.86`; exit/drain timing, claim cadence against user rhythm,
  co-triggers — GF-4, ungraded), which is exactly what the GF
  apparatus measures. **Off-chain**, the V-2a/V-2b residuals (§18.8)
  survive unchanged, because they depend on the *loud reward amounts*
  and the *universal funding constant* matched against user-side
  amount surfaces (e.g. exchange records) — not on the bond amount.
  V-2b remains on the GF-4 round's surface.

### 18.10 Exit-seam residual inventory: the loud-and-variable frame, resolved at source (2026-07-06)

§18.9's two-closure observation generalizes into the frame that sorts
the remaining surface: **an amount carries user-correlated bits only
where it is loud AND variable.** The bond term is loud-but-constant
(zero bits); the funding/change legs are variable-but-hidden (zero
observable bits); the residuals live in the one remaining quadrant.
Review round R4 enumerated the inventory (R-1..R-5) against that frame
and named two determinative source checks. Both are now resolved.

**Source check 1 — is the reward payout cleartext or CT-committed?
Cleartext, by explicit genesis disposition.** `reward_amount_plain:
Vec<u64>` rides the emission vin loud, per settlement epoch
(`emission_wire.rs` frozen field set (A)); the vout amounts are loud
too (`RewardCommit.amount_plain`, with
`Σ vout.amount_plain == Σ reward_P(E)` enforced).
`REWARD_EMISSION_LEG.md` §5.5: "emission mint is **not confidential**
… the entitled amount is **public** on the vin (loud inflation
check)"; §9's rejected-surfaces table records "Confidential reward
amount — Delete" as a genesis decision. Stronger than the R-1 wargame
anticipated: `reward_P(E) = budget(E)·capped_P(E)/Σwork(E)` is a
deterministic function of *public consensus state* (replication
counts, shard age, serve-credit bits, gate-1 budget), and §4.1 pins
that every verifier recomputes all three channels at zero tolerance —
the adversary does not predict the amount, **consensus requires that
everyone can compute it exactly, ex ante, for every `P`.**

**Source check 2 — is the amount exact or quantized? Exact.**
`reward_share_floor` is `floor(budget·capped/Σwork)` to the atomic
unit (`reward_arithmetic.rs`); the only coarsening is integer flooring
with dust unminted. No grid exists.

**Resolved inventory:**

- **R-1 (reward-amount surface) — real, in its sharpest form, with
  its reach bounded.** Loud, variable, exact, ex-ante computable. But
  the exposure is pinned *at mint* and **severed at first spend**:
  `P`'s subsequent movements (including the drain) are ordinary
  FCMP++ spends — CT amounts, hidden change/fee splits — so the
  computed reward never propagates on-chain. Two consequences. (i)
  Among pseudonyms the amount adds **zero partition bits** — it is a
  function of `P`'s already-public state (holdings, serve bits), so
  per the §18.8 frame it says nothing about `P` that wasn't public.
  (ii) All of its bits live at the **off-chain user-side matching
  surface**: R-1 is V-2b upgraded from "lifetime total computable"
  to "per-epoch schedule computable ex ante — a targeted search with
  a computed target." That is the dominant exit-seam amount residual,
  and it is off-chain-matched, so it is a GF-4-round object.
- **R-2 (constant funding requirement) — scoped down as proposed.**
  The constant closes the on-chain amount bits (and the user-side
  funding *transfer* is itself CT-hidden on-chain); the residual is
  off-chain funding-assembly observability, which rides the §13.5
  isolation conditioning already pinned. Not a new bridge.
- **R-3 (quantization) — absent; named as the open mitigation
  candidate.** A gridded `reward_P` formula remains deterministic and
  zero-tolerance recomputable, so quantization is *compatible* with
  the loud-audit posture — it coarsens the value without hiding it,
  collapsing the user-side match from an exact computed target to a
  bucket shared across personas. It is a consensus economics change
  (grid width interacts with dust/budget conservation), so it is a
  GF-4-round design candidate with the width a-priori derived from
  the adversary-advantage argument (the settlement-epoch-width
  discipline, §18.7, applied to the value axis) — not a wallet knob.
- **R-4 (claim-timing cadence) — stands, joint grading pinned.** The
  pure-timing recurring observable (batching ≤ 15, forfeiture W = 26
  are signed pins, `emission_wire.rs`). Claim timing, reward amount,
  and holdings stratum are co-present on one persona; the GF-4 round
  grades them **jointly** (the §16.2 no-per-axis-multiplication
  obligation, applied to the exit seam).
- **R-5 (the asymmetry) — stands, corrected in one place.** Timing
  can be jittered; a consensus-computed amount cannot. But of the
  three defense classes named, **(b) CT-committing the payout is
  foreclosed, not open**: it is a recorded rejected surface
  (`REWARD_EMISSION_LEG.md` §9) because loud mint is the
  inflation-audit posture — a hidden mint amount makes supply
  unverifiable, which `00-mission` priority 1 rejects regardless of
  the privacy gain. The available classes are **(a)** quantization
  (R-3, open candidate) and **(c)** firewall routing, which
  *partially exists*: the gate-6 backing ladder already pins mint
  outputs as the safest lineage rung ("provenance terminates at
  consensus"), and everything after mint is FCMP++-hidden (§7.3
  invariant). GF-4 is therefore confirmed as a **different problem
  class** from GF-7, not a symmetric second copy: its amount half is
  defended by coarsening and routing, never by decorrelation.

**Frame pin (carried into the GF-4 round):** loud-and-variable
amounts are the only residual bridge class on the value axis, and the
archival leg has exactly one — the reward schedule. Its on-chain
propagation is cut by CT at first spend; its off-chain matching
surface is the load-bearing unknown. The entry-seam toolkit (jitter,
dispersal) does not transfer; the exit-seam toolkit is quantize (R-3)
+ route (gate-6 ladder) + measure (R-4 joint grading).

### 18.11 R-1 disposition: amount-hiding is complete on-chain; the managed residual and its layers (2026-07-06)

R4's inventory left one load-bearing open question: does FCMP++
routing hide the *amount* or only the *linkage*? If a spend's outputs
surfaced computable amounts anywhere on-chain, the precomputed reward
sequence would be matchable however many hops later, and quantization
would be mandatory rather than hardening. **Resolved at source: FCMP++
hides both, at every on-chain hop.**

1. **No non-mint output carries a cleartext amount.** Every ordinary
   output carries a Pedersen commitment `C = z·G + amount·H` plus an
   XOR-encrypted amount recoverable only by the recipient
   (`enc_amount = amount ⊕ k_amount`, keys via hybrid KEM decap —
   `shekyl-crypto-pq/src/output.rs`). What sum comes out of a spend is
   invisible to third parties. The only cleartext amounts on-chain are
   the reward-mint vouts (§18.10, by priority-1 disposition) and the
   bond-term constant (§18.8/§18.9).
2. **`P`'s spend set is not enumerable.** The mint outputs are
   publicly `P`-attributed with loud amounts (the emission tx carries
   `P_pubkey` on the vin; its vouts are the rewards), so the adversary
   knows what `P` holds — but a later spend is an FCMP++ membership
   proof over the whole tree; the key image dedups without identifying
   the consumed output. The adversary cannot observe *when* `P`'s
   reward value moves, along *which* transactions, or *what fees it
   pays*. The sequence signature loses its anchor at hop one.

**The residual, honestly scoped.** The off-chain crossing is not a
rare coincidence — reward value is economically guaranteed to
eventually reach the user, and amount-hiding ends definitionally at
any surface where a counterparty credits a cleartext number. R-1 is
therefore a **managed residual, not a closed one**: a precomputed
amount-signature the value must eventually cross a boundary carrying,
defended by the layers below. Three degradations stand between the
precomputed sequence and an off-chain match:

- **(i) Drain amounts are wallet-chosen — the exact-subsum match is a
  wallet-policy footgun, not a structural leak.** A spend's output
  split is arbitrary and CT-hidden; change absorbs the difference
  between "what moved" and any reward subsum. Nothing forces a drain
  output to equal a computable subsum of `reward_P`; a wallet that
  moves exact epoch-sums has *chosen* to reconstruct the signature the
  chain erased. **New pin (gate-6, firewall-class candidate):
  drain-amount decoupling** — drain amounts user-driven or rounded,
  never computable reward subsums. This closes the accumulate-then-
  move pattern at its only remaining formation point.
- **(ii) No timing anchor.** Because the spend set is unenumerable
  (fact 2), the adversary cannot correlate "value left `P`" with a
  user-side receipt window; the timing half of the exit match starts
  blind.
- **(iii) The unavoidable invariant is the lifetime aggregate,
  approximately.** Total-minted-to-`P` is public and exact; what
  reaches the user is that minus fees and retention across
  unattributable transactions — a band, not a target. V-2b's exact
  form (`bond_floor·k + Σ rewards` to the atomic unit) holds only for
  an adversary who also observes the drain-side fee/retention split,
  which facts 1–2 deny on-chain.

**Recorded mitigation hierarchy (supersedes §18.10's flat listing):**

1. **(c) firewall-routing — primary, and structurally complete
   on-chain.** Amount and linkage both hidden at every post-mint hop;
   spend set unenumerable. The §7.3 obligation extends as R4 demanded:
   not "the first spend is FCMP++" but "the whole mint→user path
   preserves unlinkability, including accumulate-then-move" — and with
   facts 1–2 the on-chain half of that extension holds by
   construction.
2. **Drain-amount decoupling (new wallet-policy pin)** — the cheap
   structural move at the wallet layer; breaks exact-subsum and
   sequence formation before any off-chain surface sees them.
3. **(a) quantization (R-3) — defense-in-depth** for the off-chain
   *aggregate* residual, grid width derived against the
   sequence-match adversary — noting the sequence adversary needs an
   off-chain sequence surface, which layer 2 breaks first, so the
   grid's threat model is primarily the lifetime-aggregate band.

**GF-4 wargame, as pinned by R4:** an adversary with `reward_P(E)`
precomputed for all `E` attempts to identify a user-side value event
as a sum/subsum of a specific `P`'s reward sequence across the hops
the value takes. With this section's facts, the attack's on-chain legs
are dead; the graded question becomes the off-chain boundary under
layers 2–3, jointly with the timing axes (R-4's no-per-axis-
multiplication obligation).

### 18.12 R4 closure: the drain pin tightened to input-level; why the mint is loud (2026-07-06)

The R4 reviewer accepted §18.11's resolution in full and closed the
round with three amendments, all recorded here.

**1. Retraction: the "extend (c) to the whole mint→user path"
obligation is already discharged.** §18.11's facts 1–2 (no non-mint
cleartext amounts; spend set unenumerable) mean the mint→user path is
unlinkable at every on-chain hop **by the base transfer format** —
there is nothing to extend. The whole-length obligation R4 constructed
dissolves; (c)'s status is not "primary mitigation" but "no on-chain
residual exists to manage."

**2. The drain-amount decoupling pin is tightened from output-level
to input-level.** §18.11's formulation ("drain amounts user-driven or
rounded, never computable reward subsums") has two failure modes the
closure round caught:

- *Rounding granularity:* a drain rounded on a grid fine relative to
  the reward-sequence spacing still lands near subsums — rounding
  reduces bits without severing the correlation.
- *"User-driven" reintroduces the footgun:* a user driving drain
  amounts by habit or convenience ("drain what I earned this month")
  produces a computable subsum by choice — the exact self-inflicted
  reconstruction the pin exists to prevent.

**The pin, in its structural form:** the wallet's drain-amount
computation **must not read the reward sequence (or reward-derived
accounting) as an input.** Permitted inputs: a user-specified target,
a fixed cadence, randomness. Forbidden input: anything computable
from `reward_P(E)` (per-epoch amounts, sums-since-last-drain, epoch
counts). The property is checked at the function's *inputs*, not its
*outputs* — the same discipline as the P-1/P-2 mint-site pins: close
it at what the function is allowed to read, so a matchable subsum is
unrepresentable-by-construction rather than kept-far-by-discipline.
**Acceptance test (mechanically checkable when the gate-6 drain
policy lands):** does the drain-amount selection path read any
reward-sequence-derived value? If yes, the footgun is open regardless
of output behavior; if no, closed. Verification at source of the
landed selection path's actual inputs is a named obligation of the
gate-6 policy PR.

**3. Why the mint is loud — recorded so the tradeoff survives its
authors.** After CT closes the funding leg and the constant closes
the bond term, the archival leg's entire `P`→user value exposure
reduces to the loud reward-mint amounts — and those are loud by a
**deliberate priority-1 decision** (inflation auditability: every
verifier recomputes `reward_P(E)` at zero tolerance; a hidden mint
amount makes supply unverifiable, `00-mission` priority 1 over
priority 2). R-1 is therefore **not a defect that failed to close; it
is a priority-ordered tradeoff whose residual is then driven to its
floor** with the tools that don't conflict with the audit posture
(routing — complete on-chain; drain-decoupling — this pin;
quantization — defense-in-depth). A future reviewer must not "fix"
the loud mint by CT-committing it: that silently breaks supply
verifiability. (Same record-the-why shape as the F41 constant-work
invariant: the property's load-bearing reason is written down, not
just the property.)

**Floor statement.** The only unavoidable residual is the lifetime
aggregate as a fee-and-retention-widened band at the definitional
off-chain crossing — bounded not by our mitigations but by the fact
that no counterparty-crossing privacy can exist inside the protocol.
The R4 residual inventory is closed to its floor; the drain-decoupling
pin (input-level form) is the one piece of new structural work the
round produced, and it rides the gate-6 policy PR.

### 18.13 Arc closure: theory ceiling declared; Tor-default trace resolved (2026-07-06)

The review arc (R1–R4 plus the R3 correction round) is closed at its
theory ceiling: everything at or below the `P`↔principal seam is
structurally foreclosed, closed by an input-level pin awaiting one
trace, measured-thin-but-honest (1.86), or a deliberate recorded
tradeoff. The remaining work is implementation against the pinned
design, not further seam analysis. Two verification traces were open
at closure; one resolved immediately, one waits on the gate-6 PR.

**Trace 1 (resolved): default Tor coverage — split verdict.** The
persona side is stronger than default-on: `shekyl-p-transport`
**fails the build** without its SOCKS connector
(`compile_error!`, `rust/shekyl-p-transport/src/lib.rs`), and every
per-`P` request rides its own Tor circuit via a cSHAKE-derived
`IsolateSOCKSAuth` username (fixed-width non-empty by type, redacted
`Debug`, principal-disjoint). "`P` dials clearnet" is not a
misconfiguration — it is unrepresentable. The **principal side is
opt-in**: `shekyl-cli`'s `--proxy` is `Option<String>` defaulting to
`None` (`rust/shekyl-cli/src/main.rs`), so the principal's daemon
connection dials clearnet unless the user configures a proxy; the
p-transport invariants explicitly model the principal as the
no-auth/empty-username circuit, with the principal-side SOCKS
namespace obligation already deferred in FOLLOWUPS. **Disposition:**
the network half of the principal↔user seam is closed by
construction for personas and open by default for the principal.
The named work item is the principal-side default flip
(default-on Tor for principal daemon connections, opt-out loud in
the UI the way the persona-side `compile_error!` is loud in the
build). Until it lands, a passive network observer needs *no user
error* to correlate principal daemon traffic with on-chain events —
the vantage is granted by our default, not by a user mistake.

**Trace 2 (pending, unchanged):** drain-amount selection inputs —
rides the gate-6 policy PR per §18.12's acceptance test.

**The closing frame on the principal↔user seam** (recorded as the
answer to "how hard is this seam in the real world"): against a
chain-only adversary the seam is invisible by construction — FCMP++
spends are untrackable to a principal, amounts recipient-only, spend
sets unenumerable; there is nothing on-chain to trace. The boundary
classes that remain are exactly three, and only one is a user
mistake: (1) the **on-ramp witness** — irreducible, not assistance
but presence; bounded to entry-seam material because the chain goes
dark to the counterparty too; (2) the **network position** — today a
default-defect (ours, not the user's), converted by the default flip
into an intentional-opt-out class; (3) the **enumerated mistake set**
(drain subsums, address reuse, cross-persona correlation) — closed
by safe-by-default coverage, template: the §18.12 input-level pin.
After the default flip, tracing the seam requires being the on-ramp
counterparty or the user's intentional departure from defaults —
both outside the protocol's power, which is the definition of closed
to its floor. Caveat carried: under default-on, the opt-out set
remains a distinguishable minority; acceptable (informed choice),
but the opt-out must be explicit and loud, never ambient.
