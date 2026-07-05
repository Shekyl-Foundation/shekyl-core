# 2c GF-7 measurement hooks — the evidence pipeline for the genesis gate

**Status: design spec (2c design round, 2026-07-04). Gates the 2c-2b scheduler
wiring PR: the scheduler MUST land with the §3 observer seam and satisfy the §6
acceptance criteria, or it ships unmeasurable and the GF-7 genesis gate has no
evidence pipeline.**

**Authority:** [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md)
§10.12 (GF-7); [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md)
§4 (the genesis-gate disclosure); [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)
§*standoff* (the existing funding-axis harness and its caveats, which this spec
inherits as constraints); `docs/FOLLOWUPS.md` GF-7 genesis-blocker entry.

---

## 0. What this is, and is not

This is the **hook specification**, not the measurement round. The measurement
round — running the modeled observer against the sim and grading
`P(link | T_obs)` under threshold — happens after the 2c-2b scheduler exists,
because 2c is the first point at which a bond-post is actually broadcast on a
timeline (SP-T4a §4). The design debt this spec discharges is narrower and
earlier: **specify what the scheduler must emit, to whom, and under what
build-time containment, before the wiring PR lands.** A scheduler built without
the seam is a retrofit against a live privacy surface; a scheduler built with
it makes the measurement round a sim-side activity that never touches
production code again.

Two framing decisions bind everything below (both from standing priorities,
both restated from the FOLLOWUPS pin):

1. **Sim-facing against a modeled adversary, never production telemetry** (§4).
2. **The adversary model is joint, never per-axis-multiplied** (§2).

---

## 1. The gate, restated operationally

GF-7 is the load-bearing principal↔`P` unlinkability claim (GATE6 §10.12 S-1).
The entry-gap jitter that exists today (`shekyl-standoff::draw_entry_gap`,
drawn in `stake_engine.rs`, unwired) decorrelates the bond-post from **`P`'s
own observable funding/entry event only**. It does nothing about:

- **(ii) `P`'s other broadcasts** — serve-credit claims, future rebond/top-up
  posts, anything else `P` puts on a wire on its own cadence; and
- **(iii) the principal's lifecycle timeline** — the funding sends, drain
  operations, refresh cadence, and wallet-activity rhythm that an observer of
  the principal's node or chain footprint accumulates.

Genesis cannot ship until `P(link | T_obs)` — the probability a modeled
observer links `P` to its principal given the joint observable timeline — is
measured and under threshold (the threshold is the measurement round's to set,
against the S-3 modeled observer, not this spec's). The standoff harness's own
caveat 2 already concedes that its numbers are `P(link | isolation holds)` on
the funding axis alone, with the residual channel being **concurrent network
activity** — which is exactly axes (ii) and (iii). The hooks exist to make
those axes observable to the sim.

## 2. The adversary model the hooks must serve

**Joint, not multiplied.** GF-7 inherits three correlation axes: (i) the
standoff window, (ii) `P`'s other broadcasts, (iii) the principal's lifecycle
timeline. Per the co-triggered-firewalls principle (GATE6 §6/S-1: every
profit-taking drain *is* a co-trigger; PRINCIPAL_STAKE_LIFECYCLE §*second
order*), these axes fire together in real usage — a principal that funds `P`,
drains earnings, and refreshes on a rhythm presents one fused timeline, and an
adversary correlates against the fusion. Measuring each axis independently and
multiplying the link probabilities assumes independence that the co-trigger
structure specifically violates. The correlator consumes **one joint
timeline**; the grading is over the joint observable.

**The named failure mode to wargame the hook design against:** an adversary
who **ignores the funding seam entirely** and correlates purely on
principal-lifecycle cadence — bond-post arrival times against the principal's
activity rhythm. The current jitter does nothing about this adversary; a hook
design that only captures the bond-post↔funding-event axis (the one the jitter
already handles) measures the wrong thing and certifies a gate that is not the
gate. Concretely: if the emitted events cannot reconstruct the principal's
lifecycle cadence alongside `P`'s broadcast times, the hook design fails this
spec and the 2c-2b PR does not land.

## 3. The hook surface — what the scheduler emits

**Shape: an injected observer seam.** The 2c-2b scheduler takes a
`BroadcastTimelineObserver` (name provisional) as an injected dependency, the
same discipline as the pscan `ScanSchedule` (2d-1 DQ6/TM-6: injectable, no
hardwired tick — here, injectable, no hardwired sink). The production
construction path injects the no-op observer; only the sim constructs a
recording one. The trait surface is **typed events in, nothing out** — no I/O,
no serialization, no `std::time` (see §4).

**Event vocabulary.** Three event classes, mirroring the three axes:

| Class | Events (enumerated at wiring time; this is the initial set) | Axis |
| --- | --- | --- |
| **Principal lifecycle** | funding-send dispatched; drain/unbond dispatched; refresh-cycle marker; wallet-session marker | (iii) |
| **`P` bond-post** | entry-gap draw consumed (`spread`, `bond_first`, `window` — the draw parameters, so the sim can grade the draw that actually ran, not a re-derivation); bond-post scheduled (target block/logical time); bond-post dispatched | (i) |
| **`P` other broadcasts** | any other per-`P` submit through the `PerP` arm (serve-credit claims, rebond top-ups as they land in later slices) | (ii) |

**Event payload discipline (what the events must NOT carry):**

- **Logical time only** — block heights and scheduler-logical instants, never
  wall clock. The sim supplies its own clock; a wall-clock field is a
  production-fingerprint hazard and a sim-irrelevance both.
- **Opaque ordinals, not identities** — a persona is an opaque index assigned
  by the observer session, never a `PersonaHandle` content, key, address, or
  txid. The sim joins events to ground truth on its own side (it *is* the
  ground truth); the emission needs correlatable ordinals only. This keeps the
  hook surface secret-free by construction (`36-secret-locality` has nothing
  to inspect here — that is the point).
- **Sweepable parameters ride the events** — window, jitter draw, batch size
  appear as event fields where they were consumed, so the measurement round
  can grade `P(link | T_obs)` *as a function of* those parameters without
  re-instrumenting.

## 4. The no-emit guard — build-time containment, not discipline

A privacy-maximalist coin whose unlinkability evidence pipeline is itself a
surveillance apparatus has already lost the property it is measuring. The
containment is therefore **build-structural**, three layers, each independently
sufficient, none relying on reviewer vigilance:

1. **The trait is inert by type.** `BroadcastTimelineObserver`'s surface takes
   typed events and returns nothing; it owns no writer, no socket, no file.
   A no-op impl is the production default. Even a maliciously-wired observer
   cannot exfiltrate through the seam without also landing a sink — which is
   layer 2's job to keep out.
2. **The only recording impl lives in `shekyl-staking-sim`** — a standalone
   binary crate that no production crate depends on. CI gains a
   dependency-graph assertion (the no-import guard, sibling of the DQ6
   injectable-cadence discipline): `cargo tree` over every production crate
   must not contain `shekyl-staking-sim`; the check is a grep-mechanical CI
   step, same class as the rule-42 schema snapshot check.
3. **The emit path is feature-gated off default builds.** The event types and
   the observer plumbing that carries them live behind a non-default feature
   (working name `gf7-hooks`) on the crate that hosts the seam, the same
   containment shape `shekyl-standoff` already uses for its float-bearing
   `conformance` grading (never compiled into a default build — build-enforced,
   not module-boundary-claimed). Release artifacts build with the feature off;
   CI asserts it (the release lane simply never enables it, and the
   dependency-graph check catches transitive enablement).

Layer 3 has one design consequence worth naming: the scheduler's *call sites*
into the observer compile away with the feature, so the wiring must be
`#[cfg(feature = "gf7-hooks")]`-clean at the seam — the scheduler's control
flow must be identical with and without the feature (no observable behavior
difference, no timing difference beyond the no-op call). The sim builds the
workspace with the feature on; production never does. **Emission home:** the
event types live with the seam; `shekyl-standoff` (GF-7's scoped home per
SP-T4a §4) hosts the shared draw-parameter vocabulary it already owns, so the
sim and the wallet grade the same draw the same way — the same
single-source-of-truth shape as `draw_entry_gap` itself.

## 5. The correlator contract (the measurement round's input, sketched here)

The sim side extends the existing standoff harness
(`shekyl-staking-sim --standoff`) rather than duplicating it. The correlator:

- consumes the joint timeline (all three event classes, one stream per
  scenario run);
- models the S-3 observer: sees public chain events and network-observable
  arrival times; does **not** see FCMP++-hidden funding sources or circuit
  interiors (§10.9 isolation is a *conditioning assumption*, inherited from
  the standoff harness's caveat 2 — the hooks measure the post-isolation
  residual, which is exactly the timing channel);
- **must include the funding-seam-blind adversary variant** (§2's named
  failure mode) as a first-class grading arm, not an afterthought;
- grades `P(link | T_obs)` as a function of the swept parameters: standoff
  window (`DEFAULT_ENTRY_GAP_WINDOW = 600` is the inherited grading anchor),
  entry jitter, batch size, and background network-event rate (the standoff
  harness's rate-driven finding transfers: the rate is a pre-testnet unknown,
  so the grading is a *conditional* surface, flagged like
  `fetch_latency_per_unit`);
- sets the threshold in the measurement round, with the grading surface as
  evidence — this spec deliberately does not pin a number a later round would
  have to re-litigate.

## 6. Acceptance criteria for the 2c-2b wiring PR (the gate this spec places)

1. **Seam present.** The scheduler takes the observer as an injected
   dependency; no hardwired sink; production construction injects the no-op.
2. **Emission complete.** Every broadcast-relevant decision point emits: the
   entry-gap draw consumption (with parameters), bond-post schedule and
   dispatch, every other `PerP` submit, and the principal-lifecycle markers
   the scheduler can see. The PR description enumerates the emitted set
   against §3's table (grep-anchored, the `07`-style evidence discipline).
3. **Joint-axis scenario exists.** `shekyl-staking-sim` gains at least one
   scenario that drives all three event classes through one recorded timeline
   and runs the funding-seam-blind adversary against it — even with trivial
   grading, the pipeline is proven end-to-end before the measurement round
   depends on it.
4. **No-emit guard in CI.** The §4 layer-2 dependency-graph assertion and the
   layer-3 feature-off release build are CI-checked in the same PR that lands
   the seam.
5. **No behavioral delta.** Feature-on and feature-off builds of the scheduler
   are behaviorally identical (the §4 layer-3 consequence); the PR carries a
   test or a build-level argument for it.

## 7. Mission note (rule 00) and reversion posture (rule 21)

- **Priority 2 (privacy) binding:** the hooks are the evidence pipeline for
  the coin's core unlinkability claim; the no-emit guard is what keeps the
  pipeline from being its own leak. Both halves are privacy-load-bearing.
- **Priority 3 (outlast the team):** the seam + feature + CI guard survive
  maintainer turnover — the containment is structural, so a future
  contributor cannot quietly turn the hooks into telemetry without tripping
  two independent CI checks.
- **Reversion clause:** production telemetry through this seam is **rejected,
  with named reopening criteria**: a post-genesis operational need for
  broadcast-health metrics would be a *different seam* (aggregate,
  non-timeline, non-persona-resolved) designed under its own threat-model
  review — this observer's event vocabulary is deliberately unfit for it, and
  that unfitness is a feature. Re-evaluation shape: a fresh design doc citing
  this section, privacy sign-off gate, never a feature-flag flip on
  `gf7-hooks`.
