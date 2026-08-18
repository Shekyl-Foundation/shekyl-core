# Cover traffic restoration — audit, plan, and status

**Status: audit and plan complete; implementation not started. Stages 1–3 are
unblocked, stage 4 is not — see §3.**

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

**Kept deliberately: Design A's C++ arm** (`dc1c57d31`). Cheap, and the
`levin.cpp` migration oracle is the only thing that can prove the new byte
actually crosses the FFI rather than the two sides agreeing separately. Until
the cutover, a node built from this tree really does flood every zone.

## 2.7 The Rust covert state machine — the work that survives

**Unbuilt, unassigned, and forced by the cutover regardless of §42.**

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
> scheduler gains a queue-shaped input** — which does not exist today, because
> the boundary has been doing that test's job. Writing that test is the first
> task of the move, not the last.

### Owned by the cutover, not by §42

The stage-4 gate (`DAEMON_RELAY_PRIVACY.md` §92.5's disarm scope) is unchanged
and still governs *enabling* cover. §2.7 is about *where the mechanism lives*,
which the cutover decides on its own schedule.

## 3. Status against the plan

**Verified against `dev` at the audit commit.**

| stage | status | evidence |
| --- | --- | --- |
| audit | **done** | §1, this document |
| 1 — delete the stem→`local` downgrade | not started | `levin_notify.cpp` covert branch still downgrades |
| 2 — carrier below phase | not started | carrier check still above the `switch (tx_relay)` |
| 3 — per-stem-slot send | not started | send loop still iterates all channels |
| **1–3 done-condition: correct and inert** | **not reached, and not being pursued in C++** | §2.6 — the restructure was written, validated and discarded; the C++ dies with the cutover |
| 4 — enablement | **not startable** | §2.3's two criteria both unmet |
| §2.7 Rust covert state machine | **unbuilt, unassigned** | forced by the cutover regardless of §42; first task is CV-4's missing test |

**Non-scope, tracked separately (§2.0):** Tor transit measurement — *unblocked,
not started*; flood-suite reconciliation — *unblocked, not started*.
