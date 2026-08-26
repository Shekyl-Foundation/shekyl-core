# Cover traffic restoration — audit, plan, and status

**Status: steps 1–4 landed (#498, #508, #513, #515).** Step 5 is **blocked**
on a daemon/p2p cutover this series excludes (§2.9a). The C++ covert
restructure (§2.1 stages 1–3) is not being pursued; stage 4 enablement is
not startable. See §2.9 for the series, §3 for what has landed.

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
> of them is "grep found no callers". **§1.7 states the criteria for keeping
> it**, pre-registered 2026-08-23 before the 17 KiB window is built.

---

## 1. The audit — every component, and why each has no production caller

### 1.1 The mechanism is inert at exactly TWO points

*(Superseded 2026-08-20, #515: the payload argument is gone. C++ cannot
construct a noise zone at all — `make_relay_zone` never sets
`SHEKYL_RELAY_ZONE_NOISE_ENABLED`. The two points below are the audit of
the state this series then deleted.)*

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
| ~~`detail::zone::covert_payload`~~ | ~~`levin_notify.cpp`~~ | **DELETED 2026-08-20 (#515)** with the rest of the C++ carrier |
| ~~`detail::zone::channels`~~ | ~~`levin_notify.cpp`~~ | **DELETED 2026-08-20 (#515)** |
| ~~`queue_covert_notify`~~ | ~~`levin_notify.cpp`~~ | **DELETED 2026-08-19 with the covert branch (§2.9 step 4)** — its one construction site was inside it. The enqueue path is now Rust's `NoiseQueues::enqueue`. |
| ~~`clear_channel`~~ | ~~`levin_notify.cpp`~~ | **DELETED 2026-08-20 (#515)** |
| ~~`send_noise`~~ | ~~`levin_notify.cpp`~~ | **DELETED 2026-08-20 (#515)**. CV-1 lives in `NoiseQueues`. |
| the covert branch in `send_txs` | `levin_notify.cpp` | **DELETED 2026-08-19 (§2.9 step 4)** — see §1.4 for why it was not restored |
| `shekyl_relay_zone_noise_enabled` | FFI, called from `levin_notify.cpp` | live call, always returns false: C++ never sets the flag |
| `CRYPTONOTE_NOISE_{MIN_DELAY,DELAY_RANGE,CHANNELS}` | `cryptonote_config.h` | cadence + channel count. `CRYPTONOTE_NOISE_BYTES` and `CRYPTONOTE_MAX_FRAGMENTS` **DELETED 2026-08-23 (#546)** — derived in `params::carrier`, enforced in `tests/carrier_window.rs`. |

### 1.3 Rust inventory

| component | file | state |
| --- | --- | --- |
| `CovertSchedule` | `shekyl-relay/src/zone/mod.rs` | **one type so "enabled" and "has deadlines" cannot disagree**; channel `i` bound to stem slot `i` (§20.3) |
| `Zone::covert_deadline` / `due_covert_channel` / `covert_deadline_at` / `covert_enabled` | same | complete |
| `inherited::NOISE_CHANNELS` mirror | `shekyl-relay-privacy/src/params.rs` | pins the C++ constant |
| `carrier::WINDOW_BYTES` / `MAX_FRAGMENTS` | `shekyl-relay-privacy/src/params/carrier.rs` | derived window and fragment cap; **not** inherited mirrors |
| `NoiseQueues` | `shekyl-relay/src/noise_queue/mod.rs` | executor; `enqueue` refuses over `MAX_FRAGMENTS` windows |
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

> **Superseded in part by §2.9 step 4 (2026-08-19). The finding stands; the
> C++ half of its evidence does not.** The three gtests named below pinned the
> inherited covert branch, and that branch is now deleted rather than repaired.
> They went with it — a test whose subject no longer exists is not coverage.
> **Read §1.5a for where the protection now lives**, and do not cite the list
> below as current.

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

### 1.5a Where the protection lives after step 4

**The transfer was checked before the C++ witnesses were deleted, not
asserted afterwards.** Each property the three gtests held is now held in
Rust, where it survives the daemon cutover that deletes `levin_notify.cpp`
entirely:

| property | was | is now |
| --- | --- | --- |
| CV-1 — a rebind discards the in-flight remainder | `noise_repoint_discards_in_flight_remainder` | `cv1_a_rebind_restarts_the_message_rather_than_resuming_it` |
| a real fragment is indistinguishable from a dummy | `noise` (length, incidentally) | `a_real_fragment_and_a_dummy_are_indistinguishable_by_length` |
| CV-4 — the cadence carries no queue-depth information | never held in C++ | `cv4_the_cadence_does_not_depend_on_queue_depth`, with its negative control |
| the carrier does not decide the phase | pinned **inverted** (`noise_stem` asserted the downgrade) | `a_noise_carrier_does_not_change_the_phase`, plus `noise_carries_the_stem_and_only_the_stem` |

One C++ witness replaced them rather than none:
`levin_notify.noise_does_not_override_the_phase`. *(Superseded 2026-08-20:
that witness has itself been replaced. Its subject — a noise-enabled C++ zone —
no longer exists, so it gave way to `levin_notify.cpp_cannot_enable_the_noise_carrier`,
which pins the invariant that makes the two remaining noise effect callbacks
unreachable. The phase-versus-carrier property now lives only in Rust, which is
correct: the carrier is only in Rust.)* Its discriminant is the peer
count — a stem reaches **one** peer, and the deleted all-channel broadcast
reached two — which is the assertion the deleted branch would fail. It is
driven on `relay_method::local` because RD-4 makes that arm deterministic;
§2.6 records why the `stem` arm cannot be.

**What this changes for §1.6.** The C++ noise machinery (`send_noise`,
`clear_channel`, the channel ctor loop) is now **superseded rather than
pending**: `NoiseQueues` is the restoration, and the C++ half is step 5's
delete target. `queue_covert_notify` had one construction site — inside the
deleted branch. **Correction (2026-08-20): only the construction site went.**
The class itself survived with zero constructions until it was deleted here,
along with the rest of the superseded C++ machinery. The original claim was
made by grepping, counting six references, and asserting the expected
conclusion without reading what those references were — the
confirm-the-hypothesis failure this arc has produced before, recorded because
the correction is cheap and the habit is not. §1.6's conditions are unchanged and still
protect *the mechanism*; they no longer protect the *C++ implementation of
it*, because a replacement exists and is tested.

### 1.6 The ONLY conditions under which deletion is correct

Not "no callers". Deletion requires **abandoning §42 as a design**, which means
re-opening, in writing:

- **§91.2** — Design A's ruling that Tor-only is a supported posture. Cover
  traffic is what defends the node↔proxy wire; without it the wire-observer row
  of §32.6 is undefended and "supported" weakens.
- **§42.4** — the carrier's narrowed job (deny the count of *originations*).
  **Re-opened 2026-08-23** (§42.4a): the narrowing's "4.3× over capacity" was
  against the carrier's own 492 B/s, so at a window sized to the maximum
  admissible transaction the job is no longer narrowed. Re-opening §42.4 is
  therefore *already done* and is no longer a cost of deletion — but the job it
  restores is **larger**, not smaller.
- **§32.6's grid** — the wire-observer recall cell, which cover is the only
  mechanism addressing.
- **Q-11 Unit 2** — `conformance/linkage.rs` is its substrate.

**The symmetry, added 2026-08-23: §1.7 states the conditions under which
KEEPING it is correct.** §1.6 alone is a one-sided ledger, and a mechanism with
tests and a design doc accrues inertia that a paper proposal does not — so the
keep criteria are pre-registered *before* the 17 KiB window is built rather than
assessed after.

If a future round rules cover traffic out on its merits, deletion follows and
this document is its record. Until then, **no-production-caller is the design**
(the P-transport precedent: a designed seam is not unwired because it is not yet
called).

---

### 1.7 The conditions under which KEEPING it is correct — pre-registered 2026-08-23

§1.6 states what would justify **deleting** the carrier, and nothing states what
would justify **keeping** it. The asymmetry is the trap: a built mechanism with
tests and a design doc has inertia a paper proposal does not, so *"build it,
then decide if we like it"* is exactly the shape pre-registration exists to
prevent. This section is written **before** the 17 KiB window is built, for the
same reason §2.8 was written before α was computed.

#### What is being bought — stated, because a cost bound alone decides nothing

A bound on the cost without a statement of the benefit makes the end-of-build
decision *"is 25.6 minutes acceptable"* with no counterweight, and that is the
shape in which sunk work wins.

The carrier buys **§20.9's charter: wire-observer recall goes to zero for
originations** — §32.6's top-left cell, held as a **structural** property rather
than a statistical one, and it is the only mechanism addressing that cell
(§1.6). At a window sized to the maximum admissible transaction, §42.4's
narrowing no longer applies (re-opened 2026-08-23, `DAEMON_RELAY_PRIVACY.md`
§42.4a), so the cell reads **zero for all traffic** rather than zero-for-
originations / one-for-activity.

**The end-of-build decision therefore compares two stated quantities**, this
guarantee against the axis-1 and axis-2 costs below — not one.

#### Axis 1 — the embargo the carrier may cost: **30 minutes, fixed**

Through `derive_embargo` at α = 0.90. Anonymity rows use
`ANON_ZONE_TRANSIT_ASSUMPTION_MS` at its measured 590.6 ms (§94); the clearnet
row uses `ADOPTED_TRANSIT_ASSUMPTION_MS` at 50 ms. Both add the 124.5 ms
verification floor, and the carrier rows add the scheduling wait on top:

| design | hop | anon embargo |
| --- | --- | --- |
| clearnet ordinary | 0.2 s | 3.2 min |
| **anon, no carrier** | 0.7 s | **5.0 min** |
| anon, 17 KiB / 12.5 s | 7.0 s | **25.6 min** |
| anon, 17 KiB / 16.5 s | 9.0 s | 32.1 min |
| anon, 3 KiB / 12.5 s (§42.1's carrier) | 32.0 s | **107.7 min** |

**Hard bound: the anonymity-zone embargo must not exceed 30 minutes.** One
number, one ground, no soft companion.

**The bound is fixed and derives from no per-zone embargo, and that is the
point.** An earlier draft bounded it by the wallet-facing failure threshold —
the interim worst-zone global, 2297 s. **That bound is circular:** 2297 is a
`max()` over per-zone embargoes, so it rises whenever the quantity it bounds
rises, and can never bind. Taken literally it *inverts* — today's 107.7-minute
carrier would not violate it, it would **raise** it to 107.7 minutes and drag
every clearnet user's failure report along. That is §89.2's objection (*"a 366 s
embargo sized for a rendezvous path they never touch"*) at eighteen times the
magnitude.

30 minutes is chosen on §82 grounds, the same ground the discarded soft bound
used: §89.6.3's middle tier must be able to say *"this may last up to N
minutes"* in a sentence a user accepts. Two bounds where one is a taste call and
the other is circular give zero real constraints; one fixed number binds.

**The real incoherence, recorded because it is not the one the circular bound
described.** A single global wallet timeout **cannot survive a carrier at all**:
the carrier makes the zones differ by roughly 20×, and a `max()` over a 20×
spread is unusable for the fast zone. So **§89.6.3's ask-don't-time status query
moves onto the carrier's critical path** — it is not wallet-track cleanup. A
fixed wallet-facing threshold plus a 20× zone spread is survivable only if the
wallet can ask rather than guess.

#### Axis 2 — cover bandwidth per node: **8 KiB/s**, plus an offset commitment

**Absolute ceiling: 8 KiB/s per node**, exceeded only by a new ruling. That is
rule 76's floor device on a consumer uplink, and ~4 % of the pessimistic
180 KiB/s circuit-throughput floor. The derived 20,480 B / 12.5 s design sits at
**3.20 KiB/s** — a 2.5× margin, so the ceiling constrains a future cadence
proposal without constraining this one, which is the right shape for a ceiling.
*(Updated 2026-08-23 from 17 KiB / 2.72 KiB/s when the window was derived rather
than chosen; the ceiling itself is unchanged.)*

> **Units, stated once because this section mixes bases legitimately.** Byte
> rates here are **binary** (`KiB/s` = 1024 B/s) — the windows are byte slots
> sized in KiB, so binary is the base the arithmetic is actually in. Tor network
> figures are **decimal** (`Gbit/s`), because that is how Tor Metrics reports
> them. The two never enter the same expression: the Tor percentages are
> computed from raw B/s, not from the KiB/s column.

**Relative: the carrier's Tor relay-capacity load must remain fully offset by
committed contribution.** A ratio rather than a fixed number, so it scales with
adoption, and it is the honest form of the entitlement argument — the claim is
not "0.27 % is small" but "we contribute more than we consume."

**Caveat on the 4 %, recorded rather than buried.** The 180 KiB/s floor comes
from a **burst** null result — §94.5(b)'s size slope over an 8 KiB step,
statistically indistinguishable from zero (t = 0.98–1.64). The carrier is
**sustained**. So 4 % is an upper bound *assuming burst and sustained throughput
are comparable*, which nothing has tested. **The rig spike must hold a circuit
at 2.72 KiB/s for a full session and confirm it holds**; that is the one input to
this axis we do not have.

#### Axis 3 — relay co-location does NOT retire the carrier. **Ruled.**

Ruled now rather than measured later, because after the build it becomes an
argument about sunk work.

**Relay cover cannot substitute for the carrier at any measured relay traffic
level**, and the reason is the mission hierarchy rather than a number:

- **Relay operation is optional.** A wire-observer guarantee that holds only for
  operators who relay **is privacy as a setting**, which mission priority 2
  forbids. No measurement changes this, because a measurement can only ever
  describe the operators who opted in.
- **Mandatory relaying does not rescue it.** The **ramp** is unfixable — a fresh
  install carries almost nothing for days, precisely the window in which it is
  most identifiable as a new participant — and rule 76's floor device on a
  consumer uplink cannot be *required* to relay.

**The standing rule this generalises to:** the protocol's guarantees must hold
at **zero** relay participation, and **no constant may be derived against an
assumption of relay cover**. The failure mode is concrete — *"we can lower the
carrier rate because relay operators have cover underneath it"* — and that is
the back door mission priority 2 forbids. Held, the co-location benefit is a
bonus nothing depends on, and the tension between it and constraint (1) below
dissolves.

**Scope of the ruling, narrowed deliberately.** What is foreclosed is relay
cover **substituting** for the carrier or **licensing a weaker constant**. Relay
cover remains available as what operators can do instead **if the carrier fails
axis 1 or axis 2 on its own merits** — that is a different argument (*"the
carrier does not work, and here is what operators can do"*), and this ruling
must not foreclose it by accident.

#### Relay contribution as an operator posture — the four constraints

Recommended, and separate from every guarantee above:

1. **Never route Shekyl traffic through Shekyl-operated relays, and never prefer
   them.** Path selection stays entirely Tor's. Otherwise an adversary running
   Shekyl nodes acquires relay positions *on Shekyl circuits*, which is the
   worst outcome available here.
2. **Non-exit only** — middle or guard, no exit policy, no abuse handling, no
   legal exposure. Stated explicitly, because "run a relay" without the
   qualifier will get an operator an exit and a letter.
3. **Opt-in, and privacy-neutral by construction** (axis 3's standing rule).
4. **Separate process, separate lifecycle.** Relay throughput is externally
   measurable by design — that is how bandwidth authorities work — so a relay
   sharing a process with the daemon makes its uptime a remote probe of daemon
   state. The operator must be able to restart either without the other.

Foundation-operated relays declare a **`MyFamily`** in the consensus: Tor's path
selection then refuses to place two of them in one circuit, and a named family
makes the contribution legible as a fingerprint rather than an assertion.

### 1.8 The 17 KiB window is a trade, not a free win — recorded 2026-08-23

**The mechanism deletion is free; the hop reduction is bought.** At fixed
cadence, 3 KiB → 17 KiB is 5.7× the bandwidth for 32 s → 6.25 s. At **fixed
bandwidth**, a 17 KiB window is **2.06× worse for modal transactions** than an
8.4 KiB one, because a larger slot forces a longer cadence and at `n = 1` the
residual wait is all that remains.

| window | modal tx | max admissible | fragmentation machinery |
| --- | --- | --- | --- |
| 8.4 KiB | whole (`n = 1`) | 2 fragments | **stays** |
| **17 KiB (adopted)** | whole (`n = 1`) | whole (`n = 1`) | **deletes** |

> **CORRECTED 2026-08-23 — the conclusion survives, the justification does
> not, and the number moved.** This table was computed on two sizes that were
> never grounded (§94.5(b)'s correction): no transaction the wire admits
> produces 8,395 B or 16,651 B. Three consequences:
>
> 1. **The 8.4 KiB option is dead on arrival, not a close second.** The
>    smallest possible transaction is 13,042 B, so an 8.4 KiB window gives
>    `n >= 2` for **every transaction that can exist** — there is no `n = 1`
>    case to trade against, and the 2× comparison below had no subject.
> 2. **The machinery does NOT delete.** At any window sized for the modal
>    shape, the 8-input tail still fragments (4–5 windows), so
>    `MAX_FRAGMENTS`, CV-1's discard, epoch-miss and the in-flight remainder
>    all keep their subject. The "five mechanisms with a defect history"
>    argument below is **withdrawn** — it was the justification for paying 2×,
>    and it does not apply.
> 3. **The window is 20,480 B, not 17 KiB.** 17,408 left only 398 B over the
>    modal-at-max-depth transaction *before* its levin envelope; the envelope
>    is 77 B and steps with the length varint, so the window would have
>    silently flipped to `n = 2` as the curve tree deepened. The derived value
>    is `carrier::WINDOW_BYTES`, enforced by `tests/carrier_window.rs`.
>
> **What survives is the `n = 1` conclusion, for the latency reason it always
> had**: at `n = 1` only the residual wait remains, so a window that holds the
> modal transaction whole beats a smaller one at equal bandwidth. The fragment
> cap carries the structural max separately (`carrier::MAX_FRAGMENTS = 5`) —
> two constants, two jobs.

**17 KiB is adopted, and the justification is a track record rather than a
preference.** `CRYPTONOTE_MAX_FRAGMENTS`, CV-1's discard-on-rebind, the
epoch-miss arithmetic, the in-flight remainder and the length leak have **each
produced a real defect in this arc**. Paying 2× modal latency to remove five
mechanisms with that history is an empirical argument; *"fewer moving parts"*
alone would not be.

**The window is derived, never literal.** `n = 1` holds only because the maximum
admissible transaction is 16651 B **today**. The window is computed from the
maximum admissible message size with a compile-time assertion that `n == 1`, so
a consensus change that breaks the invariant **fails the build** rather than
silently reintroducing fragmentation into a tree that deleted the code for it.

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
| **1** | Delete the stem→`local` downgrade | ~~`noise_stem` reds~~ — **superseded by execution 2026-08-19.** §93.1 removed the downgrade's *premise*, so the whole branch was deleted rather than the one line, and `noise_stem` went with it instead of turning red: a test whose subject no longer exists cannot be the criterion. Met instead by `levin_notify.noise_does_not_override_the_phase`, which was **verified red** against the restored branch at 1-peer-vs-2. |
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
`NoiseQueues` is a real port. *(Superseded 2026-08-20: step 4 deleted the
inherited branch and the C++ noise machinery is now deleted too, so there is
no longer a C++ inventory executing the carrier at all.)*

### What C++ owns today

Nothing of the carrier. `NoiseQueues` holds the buffers; C++ is transport
(asio, levin framing, `p2p->send`) until step 5. The two noise effect
callbacks remain as loud failures so a future in-process path cannot drop
a real send on the floor.

*(The table of `covert_payload` / `noise_channel` / `send_noise` that used
to sit here was deleted with those types in #515.)*

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
> (`NoiseQueues`). The test is only a barrier if the two depths are an
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
| **2** | **The covert executor.** Per-channel pending, in-flight remainder, bind, CV-1 discard — today's `send_noise` / `queue_covert_notify` / `clear_channel`. | Skeleton only (`CovertQueues`). Must become a real port or stop claiming CV-1. | **This PR (`#508`).** Window is `dummy.len()`; `CovertSend` is epoch-bound; enqueue refuses a non-multiple; CV-4 still hands distinct queues to `covert_cadence`. `Driver::poll` still takes no queue. No production caller — step 4 wires notify. **[ANNOTATION 2026-08-25 — everything before this marker is the original plan text, unedited]** Step 4 did not wire it, and was never going to. The caller is four pieces, not one: an owner for `NoiseQueues`, an enqueue path, the join for both of `Driver::poll`'s noise effects, and a widened `NoiseSendCb` (no bytes out, no status back, so the non-destructive token cannot be resolved). It also inherits §2.9b's one-transaction-per-notification requirement. §3's status table, the row headed "§2.9 step 2 — covert executor", is the authority. |
| **3** | **Zone fan-out.** Which configured zones receive a fluff. | C++ `broadcast_all_zones` loop in `net_node.inl`. **Delete target.** | The PR that names the zone set in Rust and reduces C++ to "send these bytes on this zone." The loop in `net_node.inl` does not grow another arm. |
| **4** | **Production notify.** `send_txs` consumes `plan_dispatch` (phase + carrier + slot in one call). The inherited covert branch — carrier above phase, stem→`local`, all-channels broadcast — is deleted, not repaired. | FFI exists; no C++ caller. That is step 1's seam, not a finished notify path. | Wire the shim, *or* skip if step 5 lands first and notify is already Rust. Do not restructure `levin_notify.cpp` "for a month of life" — §2.6 already discarded that. **[ANNOTATION 2026-08-25 — everything before this marker is the original plan text, unedited]** The escape clause EXPIRED — step 5 never landed and §2.9a ruled it blocked. For what actually happened, and the independent ground the skip survives on, read this document's §3 status table, the row headed "§2.9 step 4 — the inherited covert branch is deleted", which is the authority. |
| **5** | **C++ relay path gone.** `levin_notify.cpp`, `net_node.inl`'s `send_txs` routing, the `zone_route` token in `enums.h`, every `levin.cpp` noise/route oracle, and any `shekyl_relay_zone_*` crossing that exists only for C++. | — | The cutover PR. In-process Rust calls `Zone` / `Driver` directly. A crossing with no remaining C++ consumer is deleted in this step, not kept as a souvenir. **See §2.9a: this step is NOT startable from this series.** |

**Reading this table.** The plan text is the record of what was decided when
the series opened and is never edited. Where a step's outcome contradicted its
plan, the correction is appended INSIDE the cell behind an
`[ANNOTATION <date> …]` marker: everything before the marker is the original,
everything after is later. It is appended in place rather than filed as a
footnote on purpose — this series' founding defect was a reader who stopped at
the plan text and inherited an expired condition because the correction lived
somewhere else (§3). A correction the reader has to go and find is the bug, not
the fix.

### 2.9b The carrier's caller owes ONE TRANSACTION PER NOTIFICATION (2026-08-23)

> **REASSIGNED 2026-08-26, and it was nearly orphaned.** This section was
> written as *"Step 5 owes …"* and *"a requirement on the cutover caller"*,
> because step 5 was then believed to be what would build the caller. §3's
> step-2 row now records that the caller is owed BEFORE step 5 and does not
> wait on the cutover — which left this requirement filed against a step that
> is blocked and may never happen, while the caller that will actually enqueue
> inherited nothing.
>
> That is the failure mode in its most dangerous form: not a stale claim but a
> **live privacy requirement whose owner was reassigned away from it**. An
> interim enqueue path would have batched transactions per notification with
> the prohibition still sitting on a blocked step, and `NoiseQueues::enqueue`
> takes opaque bytes, so nothing downstream would have noticed.
>
> It binds **whatever caller enqueues**, whenever it is built and by whatever
> step. The argument below is unchanged and never depended on step 5 — it
> depends only on the caller being the last place that still has transactions
> rather than bytes.

**A requirement on the carrier's caller, recorded here because the queue cannot
enforce it and the reason is privacy rather than sizing.** Privacy has to
lead: it survives changes to the sizing. If the window grows, the size cap
moves and the batching prohibition does not. A requirement recorded on the
weaker of two grounds gets re-litigated when that ground moves; recorded on
the stronger, it does not.

`NOTIFY_NEW_TRANSACTIONS` carries a **vector** — `make_tx_message` takes
`std::vector<blobdata>&& txs` — so a notification is not one transaction by
construction. The carrier must normalise to one transaction per notification
before enqueueing.

**The sizing half is already enforced and is not the argument.**
`NoiseQueues::enqueue` refuses anything over `carrier::MAX_FRAGMENTS` windows,
so an oversized batch (two maximum transactions are ~196 KB, ten windows against
a cap of five) is structurally rejected. That is the queue doing what it can with
opaque bytes.

**The argument is that batching correlates what the stem exists to separate.**
Two transactions in one carrier message share **one window, one slot, and one
successor** — they arrive at the same peer, together, from the same sender. That
is precisely the pairwise linkage Dandelion++ denies: each stem transaction is
supposed to carry its own routing decision and its own embargo. A batch makes
the two indistinguishable from a single sender's paired emission, and no cap
size fixes that.

So the requirement is **normalisation at the caller**, which is the only place
that still has transactions rather than bytes. The cap is the backstop, not the
mechanism.

### 2.9a Step 5 is gated on a rewrite this series excludes (2026-08-20)

**Step 5 as written contradicts §2.9's own scope, and this was found by trying
to start it.** The step requires *"in-process Rust calls `Zone`/`Driver`
directly"* — no FFI. But what remains in `levin_notify.cpp` after steps 1–4 is
not decisions: the 20 `shekyl_relay_zone_*` crossings mean Rust already decides
everything. What is left is **asio strand dispatch, levin message construction,
and `p2p->send`** — transport. Deleting it means Rust owns the levin codec and
the connection registry, which is the **p2p layer** that this section's own
scope paragraph excludes ("mempool, **p2p**, RPC stay out").

**There is no daemon/p2p cutover design doc.** `docs/design/` holds
`DAEMON_REDB_STORE`, `DAEMON_RELAY_PRIVACY` and `DAEMON_SUBMIT_VERDICT`, and
none of them designs this.

So step 5 is not a relay-series PR at all — it is **where this series
terminates into a daemon rewrite that has not been designed**. The two honest
next moves are (a) design that cutover, which is the real unblocker, or (b)
keep shrinking the delete surface with changes that need no p2p. **This PR is
(b)**: the superseded C++ noise machinery is pure deletion, needs nothing from
p2p, and is the right polarity by this section's own review test.

What (b) has left after this PR is small — the remaining C++ is transport, and
transport cannot move without p2p. **Treat step 5 as blocked, not pending.**

**How to review a PR in this series.** Ask: does this make the cutover a
smaller delete? If the change is a new C++ branch that the cutover must
re-implement, it is the wrong polarity — even when it makes today's node
behave correctly. If the change is a Rust type with no C++ caller yet, that
is the design (the P-transport precedent), provided the type actually locks
the invariant it names.

**Not in this series** (tracked elsewhere, §2.0): Tor transit measurement,
flood-suite reconciliation, stage-4 cover *enablement* (§2.3 / §92.5).

## 3. Status against the plan

**Verified 2026-08-20 against `dev` after #515.**

| item | status | evidence |
| --- | --- | --- |
| audit | **done** | §1, this document |
| C++ stages 1–3 (stem→`local`, carrier-below-phase, per-slot send) | **not being pursued in C++** | §2.6 — written, validated, discarded; dies with the cutover |
| 4 — enablement | **not startable** | §2.3's two criteria both unmet |
| **§2.9 step 1 — decisions in Rust** | **landed (#498)** | `BroadcastAllZones` truth table; `RelayCarrier::Covert` carries `SlotIndex`; `CovertQueues` as a module `Driver` does not hold; CV-4 hands distinct queues to `covert_cadence`; FFI export in `shekyl_ffi.h` with null-handle fail-closed. C++ flood arm is the step-3 delete target, present as a shim. |
| **§2.9 step 2 — covert executor** | **landed (type)**; **caller now owed in Rust** | `NoiseQueues` is a real port: constant window, CV-1 restart, epoch-bound `CovertSend`, enqueue refuses a non-multiple. CV-4 still threads distinct queues through the cadence. **Corrected 2026-08-25:** the "no production caller" line attributed the gap to an in-process path step 5 must provide. That inference was wrong — the work does not wait on the cutover, and C++ performs the transport for stem and fluff today and can do the same here. **Corrected again 2026-08-26: it is also not one call, and this row said so while being cited as the authority.** The caller is FOUR pieces. (1) An OWNER — nothing constructs or holds `NoiseQueues` outside its own tests. (2) An ENQUEUE path — no production caller ever puts a real fragment in. (3) The JOIN, for BOTH noise effects rather than one — `Driver::poll` emits `Effect::NoiseSend { channel, peer }` and `Effect::NoiseUnbind { channel }`, and neither reaches `NoiseQueues::take_for_send` / `::unbind`; `unbind` is what invalidates outstanding tokens, so omitting it is not a lesser half. (4) A WIDENED `NoiseSendCb` — today `fn(ctx, channel, peer)`, carrying no bytes out and no status back, so the deliberately non-destructive token cannot be resolved (advance on a successful send, leave the queue alone on failure); `on_noise` correspondingly only logs. Three are Rust-internal; the fourth is a boundary change, which widening OUTWARD does not make a CV-4 breach — CV-4 forbids feeding the scheduler traffic-dependent input, and bytes chosen by Rust after the cadence has already picked when and to whom tell it nothing. The caller also inherits §2.9b's one-transaction-per-notification requirement. |
| **§2.9 step 3 — zone fan-out in Rust** | **satisfied by step 1 — reinterpreted, not skipped** | The step asked that Rust "name the zone set" and C++ reduce to "send these bytes on this zone". `ZoneRouteDecision::BroadcastAllZones` **is** that naming: Rust decides, and `net_node.inl` enumerates its own configured map without deciding anything. Under Design A the fan-out is *every* configured zone, so a Rust `fanout(configured) -> configured` behind the FFI would be an **identity function** — machinery with no content, and rule 21's shape. The loop's literal deletion belongs to step 5, where it goes with the rest of the file. **The step's real constraint holds: the loop did not grow another arm.** |
| **§2.9 step 4 — the inherited covert branch is deleted** | **deletion landed; the skip's condition EXPIRED** | The branch is **gone, not repaired**, per the step's own wording. `queue_covert_notify` went with it, and #515 then deleted the rest of the C++ carrier: C++ cannot enable noise at all. **Corrected 2026-08-25.** The shim was recorded as *skipped* under the step's escape clause ("*or* skip if step 5 lands first"). **Step 5 did not land** — §2.9a ruled it blocked — so that clause never fired, and reading the skip as discharged left the carrier looking blocked on a row whose subject is *deleting the C++ relay path*, which is a different thing. The skip is nonetheless still **correct, on an independent ground that did discharge**: #515 removed the C++ carrier entirely, so there is no `levin_notify.cpp` consumer for `plan_dispatch` to feed and the shim would be plumbing to nowhere. What the expiry actually leaves owed is the step-2 caller above — **in Rust**, per `20-rust-vs-cpp-policy`, not as the C++ shim this row skipped. See `.cursor/rules/22-no-lazy-deferral.mdc`, "A deferral's CONDITION can expire". |
| §2.9 step 5 — C++ relay path deleted | **BLOCKED, not pending** | §2.9a — it needs Rust to own the levin codec and the connection registry, i.e. the **p2p layer this series excludes**, and no daemon/p2p cutover design doc exists. Found by trying to start it. |
| **superseded C++ noise machinery deleted** | **landed** | `noise_channel`, `queue_covert_notify`, `clear_channel`, `send_noise`, the `channels` deque, `covert_payload` and `noise_zone_params` are gone. `make_relay_zone` no longer takes a noise flag, so C++ cannot construct a noise zone at all — `get_status().has_noise` reads the Rust-owned fact and is false everywhere. The two noise effect callbacks remain as **loud failures**, not no-ops: a silent drop would lose a real carrier effect the moment the cutover builds the path that can reach them. |
| §2.8 α rule | **pre-registered** | no number yet; the rule is the artifact |

**Non-scope, tracked separately (§2.0):** Tor transit measurement — *unblocked,
not started*; flood-suite reconciliation — *unblocked, not started*.
