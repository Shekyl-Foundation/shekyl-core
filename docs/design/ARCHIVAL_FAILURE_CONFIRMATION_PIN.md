# Archival challenge scheduling — failure-confirmation pin

**Status:** **Disposition pinned (2026-06-08).** Genesis challenge **scheduling after a
baseline miss** is **sliding-window m-of-n**. Escalate-on-failure + recheck window is
**rejected** (§5 — audit rationale only). Per-`P` confirmation FSM is **not** implemented.

**Scope:** Scheduling policy on top of gate-2 baseline challenges
([`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §0). Complements L14/L16 sim
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*L14b*).

**Authority chain:**

| Doc | Role |
|-----|------|
| [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) | Baseline challenge; `serve_credit_bit`; beacon `H_fire` |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `R_market` derivation (§3.3); m-sizing substrate |
| [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) | `CHALLENGE_RESOLUTION_BLOCKS`, SEB |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Round-1 harness + `policy_pin` output |

---

## 1. Pinned policy (genesis)

**Shape.** After each baseline epoch challenge **miss**, consensus maintains a **sliding
window** of recent misses per `(P_id, shard)`. **Slash** when **m** misses occur within the
last **n** baseline observations. No per-`P` confirmation FSM; tallies reuse credit-window
discipline ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) composite keys).

**Property enforced.** **Not-durably-absent** — sustained miss slashes; isolated transient
miss does not (at tuned `m`). Not a reachability SLA; mediocre uptime passes most baselines
untested by design (gate-2 §0).

**Round-1 provisional parameters** (L16 exponential outage, baseline every settlement epoch):

| Parameter | Value | Note |
|-----------|-------|------|
| `m` | **11** | Above p99 single-outage span ≈ 10 baselines (mean down = 2 epochs) |
| `n` | **13** | `n ≥ m + buffer` |
| Transient false-slash (tuned) | **≈ 0.002** | Fair compare vs escalation ≈ 0.025 |
| Dodge slash (mostly-offline `P`) | **1.000** | Every baseline miss counts |

**Shared prerequisite (production).** Baseline fire time **`H_fire` beacon-unpredictable**
(gate-2 §3.4) — fixed-time baselines are gameable for **either** policy. Micro-sim uses a
deterministic epoch grid; production timing is documented in sim `baseline_timing`.

**Rejected.** Escalate-on-failure + randomized recheck window — §5.

---

## 2. Why sliding-window (Round-1 closed)

Decision gate order (all measured on **both** policies where applicable):

1. **Dodge slash** — mostly-offline dodge-`P`: escalation **0.000** (surfaces only for
   predictable post-miss recheck); sliding **1.000** (no recheck surface; misses accumulate).
   Same fact viewed twice: predictable recheck **is** the gaming surface.
2. **Binding** — challenge block-space ≈ **0.8%** of SEB budget (**not binding**);
   slash-latency non-binding for **availability** under foundation durability floor.
3. **Fair transient compare** — sliding `m` tuned **above** single-outage span; tuned
   transient false-slash **beats** escalation (≈ 0.002 vs ≈ 0.025), not the unfair untuned
   `m=2` read (≈ 59%).
4. **Escalation additionally fails** — `volR ≈ 1.74` at L16 `u_eff` (honest Ps
   frequently-down → constant rechecks; escalation **costs more** volume, does not dominate);
   recheck width has no sweet spot (§5.5); per-`P` FSM + reorg surface unjustified.

**Harness.** `cargo run -p shekyl-staking-sim --release -- --failure-confirmation` → JSON
`policy_pin`, `sliding_m_sweep`, paired `dEsc`/`dSl`, `baseline_timing`.

---

## 3. `m` sizing — substrate and Round-2 gate

### 3.1 What `m` trades (not "free latency")

Higher `m` delays **slash** of a durably-dead `P` (Round-1: ~11 baselines ≈ months at
one baseline per settlement epoch). That delay is **not** a trade against availability
when the foundation floor carries deterrence — but it is **not** automatically free against
every cost.

**`R_market` substrate (pinned).** Scarcity uses **serve-credit-weighted** replication
count, not bonded-slot count ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.3):

```text
R_market(shard, E) = |{ P_id : serve_credit_bit(P,s,E) ∧ good_through(P,E) ∧ P ∈ Market }|
```

A dead `P` that stops passing challenges **does not** earn `serve_credit_bit` and **does
not** inflate `R_market` at **E-close** for those epochs — even while bond resolution
awaits slash. Slow slash therefore primarily delays **bond release / holdings cleanup**,
not scarcity-signal accuracy at the emission read. (§5.5 "occupies a slot" wording applied
to **dodge-`P` gaming** under the rejected escalation path, not to `R_market` counting.)

**Round-2 confirmation:** stressnet should verify no alternate code path counts bonded-but-
uncredited `P` into `R_market`; if one exists, the latency trade reopens.

### 3.2 Fat-tail coupling (same caveat as escalation recheck)

Round-1 sized `m=11` from **L16 exponential** p99 single-outage span ≈ 10 baselines. If true
onion outages are **fat-tailed** (§5.4), the p99 span is **larger** — one long-but-transient
outage can span more than 11 baselines → false-slash at tuned `m`.

**Stressnet question (Round-2 gate).** Does the measured outage-duration CDF admit an `m`
that is **simultaneously**:

| Criterion | Requirement |
|-----------|-------------|
| **Tail-robust** | `m` above true p99 (or agreed quantile) single-outage baseline span |
| **Bond-resolution acceptable** | Slash latency bounded for bond/holdings cleanup (and any metric not serve-credit-gated) |
| **Crisis-tail robust (swan-2/W6)** | `m` above the outage **run-length** quantile measured under **induced correlated failure**, not just the normal-times marginal CDF |

If the tail is heavy enough that no `m` satisfies both, resolution is **elsewhere** — e.g.
faster dead-`P` detection decoupled from `m` (separate liveness signal), or accepting priced
pollution on a metric that **is** slot-weighted. Name this gate in stressnet planning; do
not treat Round-1 `m=11` as final without the CDF.

**Gating input.** Outage-duration **CDF** (residual-life derived); steady-state `u_eff` alone
does not pin tail shape.

### 3.3 Enforcement pro-cyclicality (swan-2/W6, 2026-06-11)

During a legitimate crisis (the L17 black-swan regimes,
`STAKER_ARCHIVAL_SIM.md` §L17), honest survivors run **degraded infrastructure** —
crisis outage distributions are exactly the fat-tailed regime §3.2 flags, arriving
*correlated across the population*. An `n − m` margin sized to the normal-times
stressnet CDF then produces **false-slash cascades**: slashes amplify exit, a fifth
loop feeding the death spiral through the enforcement layer itself (on top of the
four L13/P2 loops).

Two consequences pinned into the Round-2 close criteria:

1. **The fix is static margin, not adaptive widening.** The §5 escalation-dodge
   result already establishes that predictable adaptivity is the gaming surface —
   an "emergency widening" rule that loosens `m/n` when outages spike is a free
   dodge for a strategic dropper who can simulate a crisis. Size `n − m` against
   the **crisis-tail run-length** once, statically.
2. **The stressnet measurement campaign must capture outage run-lengths under
   induced correlated failure** (kill a failure domain; measure consecutive-miss
   run-lengths across the surviving population while it degrades), not only the
   marginal single-`P` duration CDF. The marginal CDF under-states the crisis tail
   by construction.

---

## 4. Implementation

| Item | Status | Notes |
|------|--------|-------|
| Sliding-window m-of-n in consensus | **Pinned — implement** | `m`/`n` from Round-2 CDF gate |
| Per-`P` confirmation FSM | **Rejected** | §5 |
| Gate-2 baseline + `serve_credit_bit` wire | In progress | Orthogonal to scheduling choice |
| Round-2 stressnet | **Open** | §3.2 joint `m` feasibility |

Cross-reference: gate-2 §10; challenge **scheduling** is orthogonal to vin verify.

---

## 5. Rejected alternative — escalate-on-failure (audit rationale)

> **Read stratum only.** This section records **why escalation was rejected**, not what to
> build. An implementer must not treat §5 parameters as live consensus knobs.

### 5.1 Policy name (historical)

**Escalate-on-failure with randomized near-term recheck** — not *exponential backoff*.
After baseline miss, scrutiny **tightens** with a **random** recheck in a window — not
widening intervals.

### 5.2 Efficiency principle (refuted at L16)

**Claim (rejected).** Escalation "strictly dominates fixed cadence on challenge volume" by
re-policing only ambiguous `P`s.

**Round-1 refutation.** At L16 `u_eff ≈ 0.634`, honest archivers are **frequently down**;
baseline misses trigger rechecks constantly. **`volR ≈ 1.74`** — escalation issues **more**
challenges on honest renewal than sliding-window, not fewer. Premise assumed healthy ≡
rarely-down; onion breaks it.

### 5.3 Enforcement property (shared with §1)

Credit/slash enforce **not-durably-absent**, not reachability SLA — applies to **both**
policies; not escalation-specific.

### 5.4 Recheck window parameters (why residual-life mattered)

Escalation used two knobs — **window start** (residual-life quantile `p`) and **width `w`**
(gaming). Sizing start from full outage duration (not residual life) overstates false-slash
robustness under fat tails; nominal `1−p` exact only for exponential memoryless case.
**Survives as stressnet discipline** for any policy using outage-derived thresholds — including
sliding `m` (§3.2).

### 5.5 Gaming surface and recheck-width impossibility

Mostly-offline `P` observes baseline miss → **predictable recheck** → surfaces only for
probe → **dodge slash ≈ 0** (Round-1). Dodge-serving earns no `serve_credit_bit` when
monitoring without affirmative pass; under escalation, dodge still **games slash avoidance**
via the recheck window.

**No sweet spot for `w` at L16 outage frequency:** wider `w` raises dodge cost but exposes
honest `P` to secondary independent outages during the window (probe catches second blip →
false-slash). Width sweep cannot satisfy `b_min` and low false-slash simultaneously.

**Contrast sliding-window.** No post-miss recheck → no surface to dodge → **dodge slash ≈ 1**.

### 5.6 Consensus-state cost (why FSM was rejected)

Escalation requires per-`P` **confirmation-sequence FSM** — reorg and `Unbond` mid-sequence
surface in the subsystem this project guards most carefully. Sliding-window reuses miss
tallies with minimal new state.

| | Escalation (rejected) | Sliding (pinned) |
|--|----------------------|----------------|
| Dodge slash | ≈ 0 | ≈ 1 |
| `volR` at L16 | ≈ 1.74 | 1.0 (reference) |
| Consensus FSM | Per-`P` sequence | Near-stateless |
| Transient fs (fair) | ≈ 0.025 | ≈ 0.002 (tuned `m`) |

---

## Changelog

- **2026-06-08:** Initial pin — escalation under evaluation; outage-CDF quantile; sim gate.
- **2026-06-08 (rev):** Residual-life + `w`; tail misspec; binding-first gate; `u` sweep.
- **2026-06-08 (pin):** Sliding-window selected; dodge 0/1; tuned-`m` fair compare.
- **2026-06-08 (doc):** Restructure — §1 pinned policy; §5 rejected alternative stratum;
  `R_market` serve-credit substrate; Round-2 joint `m` feasibility gate.
- **2026-06-11 (swan-2/W6):** §3.3 enforcement pro-cyclicality — crisis-tail criterion
  added to the Round-2 gate (size `n − m` statically against correlated-failure
  run-lengths; adaptive emergency widening rejected per the §5 dodge result); stressnet
  campaign extended to induced-correlated-failure run-length capture.
