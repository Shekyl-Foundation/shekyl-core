# Archival challenge policy — failure-confirmation pin (pre-implementation)

**Status:** **Design pin (2026-06-08).** Records the escalate-on-failure + randomized
recheck policy under evaluation. **Not** consensus-implemented; sim comparison vs
sliding-window is the decision gate before any per-`P` confirmation FSM lands.

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

## 4. Parameter derivation (recheck delay)

The recheck delay is **not** a free knob. It is read off the **transient-outage-duration
distribution** (L16 transport model now; stressnet-measured CDF later):

```
delay ~ Quantile_p(outage_duration)     // e.g. p = 0.95
false_slash_on_genuine_transient ≈ 1 − p   // tail mass beyond that percentile
```

Pick the percentile → pick the false-slash rate on true transients. A genuine blip has
recovered by the recheck; a durable outage has not.

**Sim simplification.** Instead of sweeping a `(cadence, grace, bar)` surface, the core
question collapses to: **fit a recheck schedule to the outage-duration CDF**, with the CDF as
the empirical input.

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

**Sim obligation.** Score the **gaming-resistance floor on baseline cadence**, not only
recheck transient/durable separation.

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

**Decision gate (pre-implementation).** The sim must show the efficiency win over
sliding-window is **large** before taking on the FSM. Plausible outcome: sliding-window does
~90% of the job with none of the reorg surface; escalation's edge is only "detect a dead `P` in
hours instead of one baseline interval" — which may not matter if the foundation durability
floor is already binding.

---

## 7. Sim plan (before consensus FSM)

Compare on the same L16 outage-duration input:

1. **Escalate-on-failure** — baseline per epoch; on miss, randomized recheck at quantile `p` of
   outage CDF; slash on recheck miss.
2. **Sliding-window m-of-n** — fixed baseline cadence; slash when `m` misses in window `n`.

Report: total challenge volume, false-slash rate vs `p`, gaming-resistance floor on baseline
cadence (recheck-surfacing dodge), durable-failure time-to-slash. **Implement in
`shekyl-staking-sim` only after wire/consensus deserializer path is stable** — does not block
gate-2 §10 deserializer work.

---

## 8. Deferred implementation

| Item | Target | Notes |
|------|--------|-------|
| Per-`P` confirmation sequence in consensus | After sim decision gate | Reorg + `Unbond` mid-sequence spec required first |
| `CHALLENGE_RESOLUTION_BLOCKS` / recheck quantile pin | After sim | T-A16 margin may couple to chosen `p` |
| Sliding-window as fallback production shape | If sim shows thin escalation margin | Document disposition in gate-2 §6 |

Cross-reference: gate-2 §10 step 2 remainder (consensus hook + LMDB bit write) proceeds
independently of this pin; challenge **scheduling** policy is orthogonal to vin verify.

---

## Changelog

- **2026-06-08:** Initial pin — escalate-on-failure + randomized recheck; not-durably-absent
  enforcement claim; outage-CDF quantile → false-slash; sim vs sliding-window decision gate.
