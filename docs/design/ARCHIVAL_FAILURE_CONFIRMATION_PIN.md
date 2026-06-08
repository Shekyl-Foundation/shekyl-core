# Archival challenge policy — failure-confirmation pin (pre-implementation)

**Status:** **Disposition pinned (2026-06-08).** Round-1 sim selects **sliding-window
m-of-n** for post-miss scheduling at genesis. Escalate-on-failure + recheck window is
**rejected** — predictable post-miss recheck is a dodge surface; per-`P` confirmation FSM
is unjustified (volume, latency, gaming, reorg cost). **Not** consensus-implemented until
gate-2 baseline + sliding tally wire lands.

**Scope:** How epoch challenges are **scheduled** after a baseline miss — challenge volume
on healthy archivers, transient-vs-durable separation, and the consensus-state cost of
tracking confirmation sequences. Complements gate-2 obligation
([`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §0) and L14/L16 sim layers
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*L14×L15*).

**Authority chain:**

| Doc | Role |
|-----|------|
| [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) | One guaranteed baseline challenge per `(P, s, E)`; affirmative pass → `serve_credit_bit` |
| [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) | `CHALLENGE_RESOLUTION_BLOCKS`, T-A16 transient-DoS margin |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | L14 cadence shape; L16 transport / outage-duration input |

---

## 1. Policy name (load-bearing)

**Escalate-on-failure with randomized near-term recheck** — not *exponential backoff*.

Classic exponential backoff **widens** the interval after each event. Failure-confirmation
does the opposite: after a baseline miss, scrutiny **tightens** with a **random** recheck
delay drawn from the transient-outage distribution. The load-bearing word is **random**
(unpredictable recheck window), not **exponential**.

---

## 2. Efficiency principle

Spend challenge samples only where the outcome is ambiguous; stop early where it is clear.

| Path | Behavior |
|------|----------|
| Healthy `P` | Passes single baseline epoch challenge → scrutiny ends for that epoch |
| Ambiguous `P` | Baseline miss → one randomized recheck → resolves transient blip vs durable absence |

This **strictly dominates** fixed-cadence sampling on challenge volume: good archivers are
not re-policed every epoch; challenge mass concentrates on Ps that just failed — exactly where
the transient-vs-durable question lives.

---

## 3. What it enforces (name the property)

Credit and slash policy enforce **not-durably-absent**, not a **reachability floor** or uptime
SLA.

A `P` with true per-epoch availability `u ≈ 0.7` passes a single baseline challenge ~70% of
the time; **a pass ends scrutiny** for that epoch. Two periods in three, a clearly mediocre
`P` sails through untested. That is a **feature** under the on-demand serving obligation
([`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §0): catch the dead, ignore the
merely blippy. Nobody should later read `serve_credit_bit` as certifying 24/7 reachability —
same discipline as the `retention_bit` → `serve_credit_bit` misnomer fix.

---

## 4. Parameter derivation (recheck window — two knobs)

The recheck is **not** a single delay knob. After a baseline miss:

| Knob | Role | Sized from |
|------|------|------------|
| **Window start** | False-slash vs transient | `Quantile_p(residual_life)` — **not** `Quantile_p(outage_duration)` |
| **Window width `w`** | Gaming resistance (dodge cost) | `b_min` scales with `w`, not with start offset |

**Residual vs full duration.** At miss detection the load-bearing quantity is **remaining
outage life**, not the marginal outage length. For the exponential (memoryless) case only,
residual ≡ full duration and `false_slash ≈ 1 − p` at the chosen quantile is **exact by
construction**. For fat-tailed laws (onion circuit/guard stalls), the inspection paradox makes
residual life longer than `F_θ`; sizing start from `Quantile_p(F_θ)` on full duration
**overstates** false-slash robustness. The Round-1 output that survives to stressnet is
**tail misspecification robustness**: pick start from an assumed residual CDF, measure realized
false-slash under a range of true tails.

**Stressnet gating input.** Calibrating `θ` to match steady-state `u_eff` does **not** pin the
metric — `u_eff` is a scalar; the answer lives in **duration shape and tail**. The measurement
needed is the **outage-duration CDF** (residual-life CDF derived from it), not uptime alone.

---

## 5. Baseline cadence floor (gaming, not statistical power)

Escalation allows **thinning baselines on healthy Ps**, but baseline cadence has a **lower
bound** set by gaming resistance, not by statistical power.

A `P` can observe its own missed challenge on-chain and know a recheck is imminent; it can
**surface only for the recheck** (monitor without serving). Affirmative-pass blunts the profit
motive — dodge-serves earn no `serve_credit_bit` — but the dodge still occupies a shard slot
and inflates `R_market`, degrading everyone else's scarcity signal.

**Defense.** If baselines are frequent enough, a mostly-offline `P` misses most baselines,
triggers a recheck after each, and ends up forced online for all those windows — gaming costs
≈ being available.

**Sim obligation.** Score the **gaming-resistance floor `b_min` on baseline cadence** before
any volume/latency comparison — it constrains **both** policies, not only the FSM path.
Deterministic point recheck (zero width) is not modeled; spread `w` is load-bearing.

---

## 6. Consensus-state trade (decision gate)

The cost escalation shifts is **consensus state**, not challenge volume.

| | Escalate-on-failure + randomized recheck | Sliding-window m-of-n misses |
|--|--|--|
| Challenge volume on healthy `P` | Low | High (oversample) |
| Durable-failure detection latency | Recheck-bound (hours-scale) | ~one baseline interval slower |
| Consensus state | Per-`P` confirmation sequence FSM | Near-stateless (reuse credit-window tallies) |
| Reorg / lifecycle edge cases | Mid-sequence reorg; in-flight `Unbond` | Minimal new surface |

A stateless sliding-window check (`slash on m-of-n misses in the credit window`) delivers
"sustained miss slashes, single miss does not" using tallies already kept for emission — no
new FSM.

Escalation adds a **per-`P` confirmation-sequence state machine** — reorg interactions land in
exactly the part of the system this project is most careful about
([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) composite-key discipline).

**Decision gate (Round-1 closed).** Order of operations:

1. **Dodge slash on both policies** — mostly-offline dodge-P: escalation dodge evades
   (recheck follows miss, slash ≈ 0); sliding accumulates baseline misses → slash ≈ 1.
   Production also requires **beacon-unpredictable** `H_fire` (gate-2 §3.4) so baselines
   are not fixed-time gameable.
2. **Binding check** — absolute block-space ≈ 0.8% of SEB at defaults (**not binding**);
   slash-latency non-binding under foundation durability floor.
3. **Fair transient compare** — sliding `m` tuned above single-outage span (p99 duration /
   baseline interval); higher `m` cost is detection latency only (free when (2) holds).
4. Escalation **rejected** additionally: `volR > 1` at L16 `u_eff` (honest Ps are
   frequently-down → constant rechecks); recheck width has no sweet spot (wide `w` closes
   dodge but reopens false-slash from secondary blips in window).

**Pinned policy:** sliding-window **m-of-n** with `m` above max single-transient baseline
span (Round-1 default: **m=11, n=13** at L16 exponential outage, baseline every epoch).
Enforces **not-durably-absent** with no confirmation FSM, no reorg surface, no dodge window.

---

## 7. Sim plan (before consensus FSM)

Compare on the same outage process (exponential + fat-tail misspec scenarios):

1. **Escalate-on-failure** — baseline per epoch; on miss, recheck window `[start, start+w]`
   with `start = Quantile_p(assumed residual life)`, probe uniform in window; slash on probe
   miss.
2. **Sliding-window m-of-n** — baseline cadence; slash when `m` misses in window `n`.

Report: **`P(slash)` vs honest `u` sweep**; **dodge slash escalate vs sliding**; **sliding
`m` sweep** with `m` above outage span; tuned transient false-slash; **binding analysis**;
`policy_pin` rationale block.

**Round-1 landed (2026-06-08).** `shekyl-staking-sim --failure-confirmation` —
`failure_confirmation.rs`. JSON: `policy_pin`, `sliding_m_sweep`, `baseline_timing`,
`binding`, `u_sweep`, `scenarios`. **Outcome:** pin sliding-window; reject escalation FSM.

---

## 8. Deferred implementation

| Item | Target | Notes |
|------|--------|-------|
| Per-`P` confirmation sequence in consensus | **Rejected** (Round-1) | Escalation dodge-evasion + non-binding volume |
| Sliding-window m-of-n in consensus | **Pinned** — implement | `m`/`n` from outage CDF at stressnet; gate-2 §6 |
| `CHALLENGE_RESOLUTION_BLOCKS` / sliding `m` pin | After stressnet CDF | T-A16 margin; `m` above p99 single-outage span |

Cross-reference: gate-2 §10 step 2 remainder (consensus hook + LMDB bit write) proceeds
independently of this pin; challenge **scheduling** policy is orthogonal to vin verify.

---

## Changelog

- **2026-06-08:** Initial pin — escalate-on-failure + randomized recheck; not-durably-absent
  enforcement claim; outage-CDF quantile → false-slash; sim vs sliding-window decision gate.
- **2026-06-08 (rev):** Residual-life window start + width `w`; tail-misspec robustness;
  `b_min` → binding → relative trade decision order; stressnet outage-duration CDF as gating
  input; `P(slash)` vs `u` sweep.
- **2026-06-08 (pin):** Sliding-window selected; escalation rejected on dodge surface
  (esc slash 0, slide 1), non-binding volume, volR>1 at L16, tuned-m transient parity;
  `policy_pin` in sim report.
