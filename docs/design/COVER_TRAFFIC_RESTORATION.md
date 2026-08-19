# Cover traffic restoration — audit, plan, and status

**Status: step 1 merged (#498); step 2 is in review on this branch (#508).**
Step 3 is zone fan-out. Step 4 wires notify and deletes the inherited covert
branch. The C++ covert restructure (§2.1 stages 1–3) is not being pursued;
stage 4 enablement is not startable. See §2.9 for the series, §3 for what
has landed.

This document exists because the cover mechanism is **deliberately inert, fully
built, and has no production caller** — which is indistinguishable, to a
dead-code sweep or a new maintainer, from abandoned scaffolding. It is not.
`DAEMON_RELAY_PRIVACY.md` §42 is a standing restoration proposal with a ruled
architecture (§42.3), a ruled backstop (§92), and a scoped implementation
(§42.5a/b).

> **DO NOT DELETE ANY COMPONENT IN §1 ON "NO CALLERS" GROUNDS.** The absence of
> a production caller is *the current state of a two-line configuration
> decision* (§1.1), not evidence of abandonment. The deletion criteria that
> would actually justify removing this machinery are stated in §1.6, and none
> of them is "grep found no callers".

---

## 1. The audit — every component, and why each has no production caller

### 1.1 The mechanism is inert at exactly TWO points

Everything else in this document is live, compiled, tested code that simply
never executes in the shipped configuration. The inertness is entirely produced
by:

1. **The notifier is constructed with a null covert payload**, at both sites —
   `net_node.inl` public zone and anonymity zone. The third `notify{}` ctor
   argument is `epee::byte_slice noise`, passed as `nullptr`. That empties
   `detail::zone::covert_payload`, and the zone is built as
   `make_relay_zone(zone, !covert_payload.empty())` — so **Rust is told covert
   is off**, and `CovertSchedule` correctly has no deadlines.
2. **`disable_noise` is accepted and ignored** (`net_node.cpp`), with a
   `MWARNING` telling the operator the flag has no effect because covert
   channels are off by default. There is deliberately **no flag to turn them
   on** — §41's deletion removed configuration B, and the comment at that site
   records why turning it back on naively would be wrong.

**Restoring cover traffic is, mechanically, changing (1).** Everything below is
what that change would wake up.

### 1.2 C++ inventory

| component | file | state |
| --- | --- | --- |
| `detail::zone::covert_payload` | `levin_notify.cpp` | built; empty in production |
| `detail::zone::channels` (per-channel strands) | `levin_notify.cpp` | built; sized from `CRYPTONOTE_NOISE_CHANNELS` |
| `queue_covert_notify` | `levin_notify.cpp` | complete; posts a covert send to a channel's strand |
| `clear_channel` | `levin_notify.cpp` | complete; nils the binding at an unbound due tick |
| `send_noise` | `levin_notify.cpp` | complete; **owns CV-1's rebind-at-send discard** — the single discard site |
| the covert branch in `send_txs` | `levin_notify.cpp` | complete **and wrong** — see §1.4 |
| `shekyl_relay_zone_covert_enabled` | FFI, called from `levin_notify.cpp` | live call, always returns false today |
| `CRYPTONOTE_NOISE_{MIN_EPOCH,EPOCH_RANGE,MIN_DELAY,DELAY_RANGE,BYTES,CHANNELS}` | `cryptonote_config.h` | six constants, all consumed |

### 1.3 Rust inventory

| component | file | state |
| --- | --- | --- |
| `CovertSchedule` | `shekyl-relay/src/zone/mod.rs` | **one type so "enabled" and "has deadlines" cannot disagree**; channel `i` bound to stem slot `i` (§20.3) |
| `Zone::covert_deadline` / `due_covert_channel` / `covert_deadline_at` / `covert_enabled` | same | complete |
| `inherited::NOISE_CHANNELS` mirror | `shekyl-relay-privacy/src/params.rs` | pins the C++ constant |
| covert linkage instruments | `shekyl-relay-privacy/src/conformance/linkage.rs` | Q-11 Unit 2's substrate |

**The Rust half already models the target architecture** and the C++ half does
not — which is §42.5b's finding: the decision layer is already Rust
(`shekyl_relay_zone_plan_relay_with_refresh`), and the covert branch is the one
path that never asks it.

### 1.4 The covert branch is not merely unused — it is WRONG (§42.5a)

Recorded here so nobody restores it as-is. The branch:

1. puts the **carrier check above the phase switch**, so a carrier is chosen
   *instead of* a phase rather than *for* one;
2. **downgrades a stem to `local`** with `MWARNING("Dandelion++ stem not
   supported over noise networks")` — Monero's posture that noise *replaces*
   Dandelion++, which §89 contradicts;
3. **broadcasts on every channel** rather than the bound stem slot,
   contradicting `CovertSchedule`.

**A naive reconnection would silently switch the anonymity zone from stemming to
not stemming**, reversing §89 and disarming the coherence branch the D9 arc
landed. That is why §1.1's change is the *last* step of the plan, not the first.

### 1.5 What keeps it exercised — the evidence a dead-code sweep would miss

**The machinery is not untested. It is unreachable in the production
*configuration* only.** Three gtests construct notifiers with an explicit
payload via `make_notifier(2048, …)`, bypassing the config path entirely:

- `levin_notify.noise`
- `levin_notify.noise_stem` — **annotated as a tripwire**; it pins §1.4's
  inherited behaviour and must go red when §42.3 lands
- `levin_notify.noise_repoint_discards_in_flight_remainder` — CV-1's only
  witness

Between them they drive `send_noise`, `clear_channel`, `queue_covert_notify`,
the FFI covert dispatch and the covert scheduler. Plus four covert tests on the
Rust side (`zone/tests.rs`, `relay_zone_ffi/tests.rs`), including
`a_covert_deadline_survives_wakes_it_did_not_cause` (CV-3).

**So: coverage exists, callers do not.** A sweep keyed on "no production
caller" deletes a mechanism with live tests and a ruled restoration plan.

### 1.6 The ONLY conditions under which deletion is correct

Not "no callers". Deletion requires **abandoning §42 as a design**, which means
re-opening, in writing:

- **§91.2** — Design A's ruling that Tor-only is a supported posture. Cover
  traffic is what defends the node↔proxy wire; without it the wire-observer row
  of §32.6 is undefended and "supported" weakens.
- **§42.4** — the carrier's narrowed job (deny the count of *originations*).
- **§32.6's grid** — the wire-observer recall cell, which cover is the only
  mechanism addressing.
- **Q-11 Unit 2** — `conformance/linkage.rs` is its substrate.

If a future round rules cover traffic out on its merits, deletion follows and
this document is its record. Until then, **no-production-caller is the design**
(the P-transport precedent: a designed seam is not unwired because it is not yet
called).

---

## 2. The plan

### 2.0 What this plan is NOT — explicit non-scope

**Two unblocked items in the relay arc are deliberately outside this plan and
must not be absorbed into it.** If this document becomes the tracked artifact,
they drift by omission — which is how a queue disappears while attention is on
one page. Each carries its own `IMPLEMENTATION_INDEX` row.

| item | why not here |
| --- | --- |
| **Tor transit measurement** (`ANON_ZONE_TRANSIT_ASSUMPTION_MS`) | **The largest remaining item in the relay arc and blocked on nothing.** §91.6: it is the term that sets `F′`, it is a *labelled assumption* rather than a measurement, and the admissible-region sweep showed it moves the constant ~7× more than `beta` does. Independent of cover. |
| **Flood-suite reconciliation** (5 files) | Adding the transit term moved every anonymity-reach reading ~3× and **no test failed**, because the flood instruments assert *shape*, never *level*. The recorded numbers in `f7_directed`, `flood_convergence`, `d9_alpha`, `d9_floor_locality` and `f_prime_admissible_region` are now transit-less readings sitting beside a transit-bearing instrument. Independent of cover. |

### 2.1 The unblocked slice — and it needs NO covert enablement anywhere

**This is the key structural fact, and §1.5 implies it without stating it.**
`make_notifier(noise_size, …)` takes the payload size **as a parameter**, so
the covert gtests construct notifiers with an explicit payload and bypass the
config path entirely. Therefore:

> **All three §42.5a changes are verifiable with both production notifier sites
> still passing `nullptr` and the mechanism still off.**

There is an existing oracle, a defined red-then-green transition, and **no
production exposure**:

| stage | change | done when |
| --- | --- | --- |
| **1** | Delete the stem→`local` downgrade | `noise_stem` reds; expectation becomes `take_relayed(stem)` per its annotation |
| **2** | Move the carrier decision **below** the phase decision — carrier chosen *for* a phase, not *instead of* one | covert branch consumes `shekyl_relay_zone_plan_relay_with_refresh` rather than bypassing it (§42.5b) |
| **3** | Replace the all-channels broadcast with a **per-stem-slot** send | `noise_stem`'s `notified_size()` becomes **1**; C++ send loop now respects `CovertSchedule`'s `i ↔ i` binding |

Stages 1–3 also carry §42.5b's ownership move: phase, carrier, slot and the
dummy payload become Rust, in **one** crossing per rule 40; strand dispatch,
levin fragmenting and the socket write stay C++ as epee-bound.

**The `noise_stem` annotation is the acceptance test.** Greening it means
changing the expectations to `stem` and `1` — *not* the code. A change that
leaves it green as written has preserved the bypass.

### 2.2 The intermediate state is a REAL done-condition, not partial completion

After stages 1–3 the covert branch is **correct and inert**.

Today it is **wrong and inert**: it refuses to stem, contradicting §89, in code
that would execute the moment anyone passed a payload. Moving from the second
state to the first is a genuine deliverable with a privacy consequence — **it
removes the trap where re-enabling covert silently reverses a consensus-adjacent
ruling** (§42.5a).

**This stage closes.** It is not held open awaiting §2.3.

### 2.3 Stage 4 — enablement, and its unblock criterion is NAMED

Stage 4 is §1.1's two-line change: pass a real payload at both notifier sites.

> **A stage marked merely "blocked" decays exactly as §64.1 did** — read as
> amber, treated as "nearly there", quoted as if current. §64.1 only stopped
> being mis-cited when it was marked **un-citable with the specific
> re-derivation named**. So this stage carries a **checkable** criterion rather
> than a label.

**Stage 4 is unblocked when, and only when, §92.5's disarm scope is ruled.**
That ruling has exactly two components, and a reader can verify each rather than
guess:

1. **The disarm predicate is defined**, and it is not *"received once"* — which
   fails in two directions: a single arrival may be the origin's own echo, and a
   relay's first receipt is its **only** receipt in the common case, so a
   predicate firing on it disarms every node and collapses to branch (c) by
   accident. The property meaning *circulating* is *"this came back from
   somewhere other than where I sent it"* (§92.5c).
2. **(d) probabilistic re-broadcast and (e) fixing the complement's trigger have
   been priced against each other and one chosen.** They are **substitutes**, not
   companions — the complement fires once at boot, so it is a
   reconnection-recovery path, not recurring coverage (§92.5a/b).

Until both hold, stage 4 does not start. §92 ruled the backstop; it explicitly
left the disarm scope open **because the carve-out's sign depends on it**.

### 2.4 Rule 94 registration

This plan, the transit measurement and the suite reconciliation each get an
`IMPLEMENTATION_INDEX` row, so §2.0's non-scope items stay visible from the
index rather than only from this page.

---

## 2.6 SCOPE CHANGE (2026-08-18): the C++ half is not worth building

**The daemon Rust cutover is roughly a month out.** Everything §2.1's stages
touch — `levin_notify.cpp`, `net_node.inl`, the `zone_route` token in
`enums.h`, and every `levin.cpp` gtest — is deleted by it. Work sorted by
lifespan:

| survives the cutover | dies with it |
| --- | --- |
| `RelayCarrier` / `RelayDispatch` and the slot-carrying dispatch | the `levin_notify.cpp` restructure |
| `zone_route::BroadcastAllZones` + its truth table | `net_node.inl`'s broadcast arm |
| this document, §91, §92, §42.5a/b | every covert gtest, incl. `noise_stem` |
| the Rust covert state machine (§2.7 — **unbuilt**) | the C++ `zone_route` token |

**The §42.3 C++ restructure was written, validated, and then discarded.** It
proved the three changes are implementable and that `noise_stem` flips exactly
as its annotation specified — `take_relayed(stem)`, `notified_size() == 1`.
That validation is banked here; the code had a month to live and a flaky test,
and §1.4 already tells a Rust implementer what the covert branch does wrong,
which is what they actually need.

> **The flake is diagnosed and the diagnosis outlives the code.** `noise_stem`
> sends `relay_method::stem`, so `local_origin = false`, and `plan_relay`'s
> predicate is `!fluffing || local_origin` — during a **fluff epoch** the
> transaction correctly fluffs and `take_relayed(stem)` finds nothing. ~40 %
> pass. `noise_repoint` sends `local`, where RD-4 makes the origin always stem,
> and is deterministic. **The inherited covert branch never consulted the
> planner at all**, so the epoch roll never reached the test: routing covert
> through the real Dandelion++ plan exposed a nondeterminism the bypass had been
> hiding. Any future covert test — in any language — needs a determined epoch,
> not a wider drive budget.

**The C++ flood arm is condemned glue, not the deliverable.** It exists so a
node built from this tree implements Design A *until the cutover deletes
`net_node.inl`*. It is on the dies-with-it list above. A reviewer who treats
that loop as the keep, and the Rust truth table / `RelayCarrier` /
`RelayDispatch` / covert queue as optional ceremony, has the polarity
backwards: **all remaining relay logic belongs in Rust; the C++ is what the
series deletes.** Duplicates across the FFI exist for that reason — Rust is
the owner, C++ is a temporary shim — not because the two sides are meant to
keep agreeing in parallel.

The `levin.cpp` migration oracle is retained only while the byte still
crosses the FFI. It dies with the C++ half. The Rust truth table is what
survives.

## 2.7 The Rust covert state machine — the work that survives

**Forced by the cutover regardless of §42.** Step 1 of §2.9 landed the
module split and the CV-4 shape; step 2 (`#508`) is the executor type.
Do not read "no production caller" as "the Rust side does not exist" —
`CovertQueues` is a real port. The C++ inventory is what still *executes*
until step 4 deletes the inherited covert branch.

### What C++ owns today

| state | where |
| --- | --- |
| dummy payload bytes | `detail::zone::covert_payload` |
| per-channel `active` fragment buffer | `noise_channel::active` |
| per-channel pending queue | `noise_channel::queue` |
| per-channel bound peer | `noise_channel::connection` |
| enqueue guard (nil binding) | `queue_covert_notify` |
| unbind: nil the binding, discard buffers | `clear_channel` |
| rebind-at-send + **CV-1 discard** | `send_noise` |

### The invariant that must survive the move, and it is NOT the language split

**CV-4: the covert schedule must carry no information about whether real
traffic is pending.** Cadence that reacts to queue depth is a timing channel,
and constant-rate cover is exactly the thing it defeats.

Today that holds because `Effect::CovertSend` carries no payload discriminant
**and** the Rust scheduler holds no covert queue. Both are true; **neither is a
language fact.** `Zone` already owns the *fluff* queue
(`contexts: BTreeMap<ConnectionId, PeerFluff>`), so there is no rule that
queues live in C++ — the rule is narrower: *the covert scheduler does not see
the covert queue.*

What the FFI boundary actually contributes is **friction, not impossibility**:
today the violating change is a `#[repr(C)]` field or a new entry point — a
cross-language, header-touching edit that is loud in review. In one Rust crate
the same violation is `if self.queue.has_pending() { … }`, one line, and it
reads as a latency improvement. That is §20.2's named failure mode.

> **So the move is permitted and the barrier must be rebuilt in types.** A
> private queue module the scheduler holds no handle to; an effect type that
> structurally cannot name payload state; and **the test that fails when the
> scheduler gains a queue-shaped input.** The module exists on this branch
> (`CovertQueues`). The test is only a barrier if the two depths are an
> input to the cadence under observation — unused locals plus an essay are
> not a substitute for the FFI friction they replace.

### Owned by the cutover, not by §42

The stage-4 gate (`DAEMON_RELAY_PRIVACY.md` §92.5's disarm scope) is unchanged
and still governs *enabling* cover. §2.7 is about *where the mechanism lives*,
which the cutover decides on its own schedule.

### 2.8 PRE-REGISTERED before the number exists: α at the covert hop

**Recorded now, deliberately, because pre-registration is worthless written
afterwards.** §16.4's α gate is this arc's worked example of what it buys — the
rule was frozen before the instrument ran, and it held when the measured
quantity turned out not to be the one the ruling needed.

The outstanding computation is α at the covert hop: four
`full_travel_probability` calls, and the one place the fragment arithmetic
(§2.6's modal transaction of three fragments in a 20-fragment envelope)
and the embargo derivation actually meet.

**The decision rule, fixed before the value is known:**

- A covert hop's added latency is an **input to `F′`**, not a reason to revisit
  [`EMBARGO_FULL_TRAVEL_PROBABILITY`]. The 0.90 pin is a *design input*
  (§16.4): the embargo is solved **for** it. A low α at the shipped embargo
  means the embargo was solved against a hop cost the carrier changes — so the
  embargo re-derives, and 0.90 does not move.
- **Re-opening 0.90 requires its own round**, on privacy grounds, with the
  wire-observer and peer-adversary rows priced separately (§32.6). *"The number
  came out low"* is not such a ground.
- If α at the covert hop is materially below 0.90, the ranked responses are, in
  order: re-derive `F′` with the carrier's hop; reduce fragments per hop (the
  modal transaction is 3 of 20, so there is headroom); and only then question
  whether the stem phase belongs on the carrier at all (§42.3).

**Why this is written first.** A figure in the 0.6s at the shipped embargo is
exactly the shape that invites re-litigating a pin rather than re-deriving a
constant, and the invitation is strongest in the minutes after the number
appears. The rule above is checkable against the value whenever it arrives.

## 2.9 This PR is the first of the relay-logic Rust cutover

**This document is the plan for that series.** It is not a cover-only audit
that happens to mention a cutover in passing, and it is not the whole daemon
rewrite (mempool, p2p, RPC stay out — same discipline as §2.0). It is the
series that moves *the remaining relay logic* into Rust so the ~30-day C++
deletion is a delete, not a rewrite.

Rule 20: new logic and bug fixes belong in Rust; C++ that remains is a
transport/marshaling shim. Every PR in this series is judged on whether it
advances that boundary, not on whether the condemned C++ still "works."

| step | what Rust must own | this PR (`feat/cover-restoration`) | next PR that owns it |
| --- | --- | --- | --- |
| **1** | **The decisions.** Fluff floods every zone (`BroadcastAllZones`). Carrier is a function of phase (`RelayCarrier` / `RelayDispatch`). Covert cadence is queue-blind (CV-4's type barrier). | **This PR.** Truth table, dispatch types (`RelayCarrier::Covert` carries `SlotIndex`), `CovertQueues` as a module `Driver` does not hold, complete `shekyl_relay_zone_plan_dispatch_with_refresh` crossing (header + signature gate + null-handle). The C++ flood arm is a **shim so production is correct until step 3 deletes it** — do not extend it. | Step 2. |
| **2** | **The covert executor.** Per-channel pending, in-flight remainder, bind, CV-1 discard — today's `send_noise` / `queue_covert_notify` / `clear_channel`. | Skeleton only (`CovertQueues`). Must become a real port or stop claiming CV-1. | **This PR (`#508`).** Window is `dummy.len()`; `CovertSend` is epoch-bound; enqueue refuses a non-multiple; CV-4 still hands distinct queues to `covert_cadence`. `Driver::poll` still takes no queue. No production caller — step 4 wires notify. |
| **3** | **Zone fan-out.** Which configured zones receive a fluff. | C++ `broadcast_all_zones` loop in `net_node.inl`. **Delete target.** | The PR that names the zone set in Rust and reduces C++ to "send these bytes on this zone." The loop in `net_node.inl` does not grow another arm. |
| **4** | **Production notify.** `send_txs` consumes `plan_dispatch` (phase + carrier + slot in one call). The inherited covert branch — carrier above phase, stem→`local`, all-channels broadcast — is deleted, not repaired. | FFI exists; no C++ caller. That is step 1's seam, not a finished notify path. | Wire the shim, *or* skip if step 5 lands first and notify is already Rust. Do not restructure `levin_notify.cpp` "for a month of life" — §2.6 already discarded that. |
| **5** | **C++ relay path gone.** `levin_notify.cpp`, `net_node.inl`'s `send_txs` routing, the `zone_route` token in `enums.h`, every `levin.cpp` covert/route oracle, and any `shekyl_relay_zone_*` crossing that exists only for C++. | — | The cutover PR. In-process Rust calls `Zone` / `Driver` directly. A crossing with no remaining C++ consumer is deleted in this step, not kept as a souvenir. |

**How to review a PR in this series.** Ask: does this make the cutover a
smaller delete? If the change is a new C++ branch that the cutover must
re-implement, it is the wrong polarity — even when it makes today's node
behave correctly. If the change is a Rust type with no C++ caller yet, that
is the design (the P-transport precedent), provided the type actually locks
the invariant it names.

**Not in this series** (tracked elsewhere, §2.0): Tor transit measurement,
flood-suite reconciliation, stage-4 cover *enablement* (§2.3 / §92.5).

## 3. Status against the plan

**Verified against this branch (`feat/covert-executor`), 2026-08-19.**

| item | status | evidence |
| --- | --- | --- |
| audit | **done** | §1, this document |
| C++ stages 1–3 (stem→`local`, carrier-below-phase, per-slot send) | **not being pursued in C++** | §2.6 — written, validated, discarded; dies with the cutover |
| 4 — enablement | **not startable** | §2.3's two criteria both unmet |
| **§2.9 step 1 — decisions in Rust** | **landed (#498)** | `BroadcastAllZones` truth table; `RelayCarrier::Covert` carries `SlotIndex`; `CovertQueues` as a module `Driver` does not hold; CV-4 hands distinct queues to `covert_cadence`; FFI export in `shekyl_ffi.h` with null-handle fail-closed. C++ flood arm is the step-3 delete target, present as a shim. |
| **§2.9 step 2 — covert executor (this PR)** | **landed (type)** | `CovertQueues` is a real port: constant window, CV-1 restart, epoch-bound `CovertSend`, enqueue refuses a non-multiple. CV-4 still threads distinct queues through `covert_cadence`. No production caller — that is step 4. C++ `send_noise` still owns the live remainder. |
| §2.9 step 3 — zone fan-out in Rust | **not started** | `net_node.inl` still iterates `m_network_zones` |
| §2.9 step 4 — notify consumes `plan_dispatch` | **not started** | no C++ caller of the new FFI |
| §2.9 step 5 — C++ relay path deleted | **not started** | cutover PR |
| §2.8 α rule | **pre-registered** | no number yet; the rule is the artifact |

**Non-scope, tracked separately (§2.0):** Tor transit measurement — *unblocked,
not started*; flood-suite reconciliation — *unblocked, not started*.
