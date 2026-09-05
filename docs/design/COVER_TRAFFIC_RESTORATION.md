# Cover traffic restoration — audit, plan, and status

**Status: steps 1–4 landed (#498, #508, #513, #515).** Step 5 is **blocked**
on a daemon/p2p cutover this series excludes (§2.9a). The C++ covert
restructure (§2.1 stages 1–3) is not being pursued; stage 4 enablement is
not startable. See §2.9 for the series, §3 for what has landed.

> **UPDATED 2026-08-29: the mechanism now HAS its production caller** — see
> §3.1a. It is still **inert by default**, behind a development opt-in, so the
> do-not-delete argument below stands unchanged in force; what changed is that
> "no caller" is no longer the reason a caller grep comes up empty.

This document exists because the cover mechanism was **deliberately inert,
fully built, and had no production caller** — which is indistinguishable, to a
dead-code sweep or a new maintainer, from abandoned scaffolding. It was not.
`DAEMON_RELAY_PRIVACY.md` §42 is a standing restoration proposal with a ruled
architecture (§42.3), a ruled backstop (§92), and a scoped implementation
(§42.5a/b).

> **DO NOT DELETE ANY COMPONENT IN §1 ON "NO CALLERS" GROUNDS.** This was
> written when the absence of a production caller was *the current state of a
> two-line configuration decision* (§1.1), not evidence of abandonment. The
> caller exists now; the rule stays, because inertness behind the opt-in still
> makes a runtime trace look empty. The deletion criteria that
> would actually justify removing this machinery are stated in §1.6, and none
> of them is "grep found no callers". **§1.7 states the criteria for keeping
> it**, pre-registered 2026-08-23 before the 17 KiB window is built.

---

## 1. The audit (2026-08-20) — every component, and why each HAD no production caller

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
| `shekyl_relay_zone_noise_enabled` | FFI, called from `levin_notify.cpp` | live call. **Was** "always false: C++ never sets the flag"; since 2026-08-27 `make_relay_zone` sets it for an ENCRYPTED zone when `set_carrier_development(true)` — a process-wide runtime opt-in **defaulting off**, so a shipped build still reads false everywhere |
| `CRYPTONOTE_NOISE_CHANNELS` | `cryptonote_config.h` | channel count. `_MIN_DELAY` and `_DELAY_RANGE` **DELETED 2026-08-28** — zero readers, and the cadence is now `params::carrier::NOISE_MIN_DELAY_MS` / `_DELAY_JITTER_MS` in milliseconds. `CRYPTONOTE_NOISE_BYTES` and `CRYPTONOTE_MAX_FRAGMENTS` **DELETED 2026-08-23 (#546)** — derived in `params::carrier`, enforced in `tests/carrier_window.rs`. |

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
no longer exists, so it gave way to `levin_notify.the_noise_carrier_is_off_by_default` (renamed from `cpp_cannot_enable_the_noise_carrier` when the runtime opt-in made that name false),
which pins the invariant every other `has_noise == false` fixture leans on.
**Superseded again 2026-08-27:** "the two remaining noise effect callbacks are
unreachable" and "the carrier is only in Rust" both stopped being true in the
change that built the executor's caller. There is now ONE noise callback — the
unbind sibling is deleted — it is REACHABLE, and it transports. What the
renamed test pins is the DEFAULT being off, not unreachability; the sibling
`the_development_opt_in_enables_the_carrier_on_an_encrypted_zone` asserts the
other side. The phase-versus-carrier property does still live only in
Rust.)* Its discriminant is the peer
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

> **SUPERSEDED 2026-08-28 — the ceiling is now 16 KiB/s per node.** *"Exceeded
> only by a new ruling"* was the escape clause this section wrote for itself,
> and §3.3 is that ruling: the denominator is per **node**, the cadence is 5 s
> in the mean, and the worst posture (dual zone, four channels) sits at
> **16,384 B/s** — at the ceiling, not under it. The text below is kept as the
> record of the 8 KiB/s argument, which is still the argument the new figure
> has to answer.
>
> **What doubling costs, stated rather than left to be derived.** 16 KiB/s is
> **~8.9 %** of the pessimistic 180 KiB/s circuit-throughput floor, against
> ~4.4 % before — and sustained, it is **~42 GB per month** per node against
> ~21 GB. That is the number a metered-uplink operator feels, and rule 76 says
> it is provisioned at the floor device rather than at the machine that was
> handy. The carrier is behind a development opt-in and defaults off, so
> nothing pays this today; arming it is where the figure lands.
>
> **The burst is not the same number.** 16 KiB/s is the *sustained* rate; the
> shortest interval the cadence draws puts a burst at
> `carrier::PER_NODE_PEAK_BYTES_PER_SEC` = **24,579 B/s**, ~1.50×. Both
> figures are **per node** — four channels aggregated. A *circuit* carries one
> channel and wants `PER_CIRCUIT_PEAK_BYTES_PER_SEC` = **6,145 B/s**; sizing a
> circuit against the node aggregate over-provisions it by 4×. Both peaks
> **round up**: the exact rates are 24 578.46 and 6 144.61 B/s, and a "peak"
> the emitter exceeds is wrong in the one direction a sizing number must not
> be.

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
at 4,096 B/s sustained for a full session, absorbing 6,145 B/s bursts, and
confirm it holds** *(was 2.72 KiB/s pre-#546, then 3.20 KiB/s — corrected 2026-08-26 —
and now 4 KiB/s after the 2026-08-28 cadence change; a circuit carries ONE
noise channel, so the per-channel figure is the one a circuit probe needs:
`carrier::PER_CIRCUIT_SUSTAINED_BYTES_PER_SEC` and
`carrier::PER_CIRCUIT_PEAK_BYTES_PER_SEC`, which exist as named constants for
exactly this reason. The node-level 16 KiB/s and 24,579 B/s are four channels
aggregated and are NOT what this probe sizes. The burst figure is **6,145**,
not "6 KiB/s" — the exact rate is 6 144.61 B/s, so a 6,144 cap is 0.61 B/s
under what one channel emits, and this section requires peaks to round up.)*; that is the one input
to this axis we do not have.

> **This spec has now gone stale three times, each time silently, because it
> transcribes a rate the constants derive.** Every cadence or window change
> moves it, and nothing reds. Whoever runs the rig should read
> `carrier::WINDOW_BYTES`, `MEAN_CADENCE_MS` and `NOISE_MIN_DELAY_MS` at the
> time of the run rather than the numbers above.

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

*(Superseded 2026-08-20 (#515) and again 2026-08-27: `make_notifier` no longer
takes a payload size, and the notifier constructor has no noise argument at all
— it is `notify(service, p2p, zone, pad_txs, core)`, so there is no `nullptr`
for a production site to pass. See §1.2. What follows is the state this slice
was planned against; its CONCLUSION held — the slice landed without enabling
the carrier anywhere, and enablement is now the default-off runtime opt-in.)*

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

~~**The `noise_stem` annotation is the acceptance test.** Greening it means
changing the expectations to `stem` and `1` — *not* the code. A change that
leaves it green as written has preserved the bypass.~~

**Superseded 2026-08-31 — the annotation is gone, and the property it named is
met.** `noise_stem` went with the covert branch (stage 1's row), but its
annotation OUTLIVED it: the block sat stranded above
`levin_notify.command_max_bytes`, an unrelated test, still telling a future
implementer that *that* test must go red when §42.3 lands. It is deleted. What
it asked for holds — the carrier preserves the planned phase rather than
downgrading to `local` (`originated_stays_in_zone` at the record sites), and
one channel binds to one stem slot rather than broadcasting to all. Both are
Rust-side now: `a_noise_carrier_does_not_change_the_phase` and the
`noise_queue` CV-1 tests.

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

> **Component 1 is SETTLED 2026-08-27; component 2 is not, so Stage 4 remains
> blocked — on ONE thing now rather than two.** Recorded here in the landing
> that cleared it, per `IMPLEMENTATION_INDEX.md`'s cleared-gate policy: a
> blocker row that outlives its blocker is how a reader keeps treating settled
> work as open.
>
> The predicate is **F-10**, and it was already built (`StemWatch::seen`
> resolves propagated unless the arrival came from the charged successor).
> §92.5c item 1 carries the settlement and the reason the item stayed open —
> the sentence naming F-10 was written, repeated, and never checked, so a true
> claim could not discharge the item it described.
>
> What this landing added is the CONSUMER, plus its precondition: `add_tx` no
> longer upgrades an entry out of `local` because that entry's own transaction
> came back. Without that, the verdict was written and erased in one call
> chain, and the upgrade put the origin's own transaction on the clear internet
> at MIN_RELAY_TIME — defeating §92's carve-out rather than closing it.

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
callbacks were loud failures so a future in-process path could not drop a
real send on the floor. *(Superseded 2026-08-27: that path was built. The
send callback TRANSPORTS now, and its unbind sibling is deleted — unbind is
consumed inside Rust by `NoiseQueues::unbind`, and C++ has held no channel
state since #515.)*

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

> **ENFORCED 2026-08-26, structurally.** `shekyl_relay_zone_noise_enqueue`
> takes **one transaction blob**, not a vector, and Rust does the levin
> framing. A batch is not something a caller can express at that crossing and
> then be refused for — it is unsayable. This section was reassigned once
> already (below) after nearly being orphaned; a requirement that only exists
> as prose is one reassignment away from reaching nobody, and this one now
> holds whoever enqueues without depending on them having read it.

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
| **§2.9 step 2 — covert executor** | **LANDED 2026-08-29 — the producer is wired and a real transaction rides the carrier** | `NoiseQueues` is a real port: constant window, CV-1 restart, epoch-bound `CovertSend`, enqueue refuses a non-multiple. CV-4 still threads distinct queues through the cadence. **Corrected 2026-08-25:** the "no production caller" line attributed the gap to an in-process path step 5 must provide. That inference was wrong — the work does not wait on the cutover, and C++ performs the transport for stem and fluff today and can do the same here. **Corrected again 2026-08-26: it is also not one call, and this row said so while being cited as the authority.** The caller is FOUR pieces. (1) An OWNER — nothing constructs or holds `NoiseQueues` outside its own tests. (2) An ENQUEUE path — no production caller ever puts a real fragment in. (3) The JOIN, for BOTH noise effects rather than one — `Driver::poll` emits `Effect::NoiseSend { channel, peer }` and `Effect::NoiseUnbind { channel }`, and neither reaches `NoiseQueues::take_for_send` / `::unbind`; `unbind` is what invalidates outstanding tokens, so omitting it is not a lesser half. (4) A WIDENED `NoiseSendCb` — today `fn(ctx, channel, peer)`, carrying no bytes out and no status back, so the deliberately non-destructive token cannot be resolved (advance on a successful send, leave the queue alone on failure); `on_noise` correspondingly only logs. Three are Rust-internal; the fourth is a boundary change, which widening OUTWARD does not make a CV-4 breach — CV-4 forbids feeding the scheduler traffic-dependent input, and bytes chosen by Rust after the cadence has already picked when and to whom tell it nothing. The caller also inherits §2.9b's one-transaction-per-notification requirement. **PARTLY BUILT 2026-08-26/27, and the remainder is named at §3.1a.** Three of the four, plus the enqueue CROSSING but not its caller: `RelayZoneHandle` owns the queue beside `Driver` (never inside — CV-4's barrier as a field); `shekyl_relay_zone_noise_enqueue` takes **one transaction blob** and Rust frames and pads it to a whole window, so §2.9b is structural rather than documented and a batch is *unsayable* at the crossing; `dispatch` joins both effects; and `ShekylRelayNoiseSendCb` carries bytes out and a send status back. `ShekylRelayNoiseUnbindCb` is **deleted** — unbind is consumed in Rust now, and C++ has held no channel state since #515, so it was a callback with no job. Reachable only after `cryptonote::levin::set_carrier_development(true)`, a RUNTIME opt-in defaulting off — the compile-time `SHEKYL_CARRIER_DEVELOPMENT` macro an earlier draft used is gone, because a gate CI never builds cannot test the only configuration that runs the carrier. §3.1 is why the opt-in is a ruling and not caution. **CLOSED 2026-08-29 by the producer.** `dandelionpp_notify` consumes `plan_dispatch_with_refresh` and enqueues on `SHEKYL_RELAY_CARRIER_NOISE`, so the carrier carries real transactions rather than dummies alone. The swap was the small half: an enqueue is NOT a send, so `record_relayed` and the stem observation could not stay where #573 put them, and the queue gained a terminal verdict — `CarrierOutcome::{Sent,Discarded}` against a caller-minted opaque token, reported through `ShekylRelayCarrierResolvedCb`. Both arms are load-bearing: `unbind` clears a channel, so a completion-only signal would leave the pool waiting forever on a record that never fires, and a discard must read as NOT RELAYED so the origin retries on the short grid instead of waiting out 1148 s for a transaction that was never sent (§92.5c item 3, now conditional on the send having happened). §3.1a's reopening criterion is MET: `a_real_transaction_rides_the_carrier_and_records_on_arrival` drives one through the queue onto the wire and asserts both that nothing is recorded at send time and that a relay IS recorded once the carrier drains it. |
| **§2.9 step 3 — zone fan-out in Rust** | **satisfied by step 1 — reinterpreted, not skipped** | The step asked that Rust "name the zone set" and C++ reduce to "send these bytes on this zone". `ZoneRouteDecision::BroadcastAllZones` **is** that naming: Rust decides, and `net_node.inl` enumerates its own configured map without deciding anything. Under Design A the fan-out is *every* configured zone, so a Rust `fanout(configured) -> configured` behind the FFI would be an **identity function** — machinery with no content, and rule 21's shape. The loop's literal deletion belongs to step 5, where it goes with the rest of the file. **The step's real constraint holds: the loop did not grow another arm.** |
| **§2.9 step 4 — the inherited covert branch is deleted** | **deletion landed; skip DISCHARGED 2026-08-29 — after two successive grounds expired** | The branch is **gone, not repaired**, per the step's own wording. `queue_covert_notify` went with it, and #515 then deleted the rest of the C++ carrier, and C++ could not enable noise at all until the default-off development opt-in restored a path (§3.1). **Corrected 2026-08-25.** The shim was recorded as *skipped* under the step's escape clause ("*or* skip if step 5 lands first"). **Step 5 did not land** — §2.9a ruled it blocked — so that clause never fired, and reading the skip as discharged left the carrier looking blocked on a row whose subject is *deleting the C++ relay path*, which is a different thing. The skip is nonetheless still **correct, and as of 2026-08-29 discharged** — though not on the ground this row last gave. That ground (#515 removed the C++ carrier entirely, so there is no `levin_notify.cpp` consumer for `plan_dispatch` to feed and the shim would be plumbing to nowhere) has **itself expired**: `dandelionpp_notify` consumes `plan_dispatch_with_refresh` today, so a consumer exists. What keeps the skip right is that the consumer which exists is **the Rust crossing this row prescribed, not the C++ shim it declined** — the enqueue hands one blob across, and Rust frames it, paces it, and hands the bytes back out for C++ to transport — as C++ already does for stem and fluff — per `20-rust-vs-cpp-policy`. And the item this row named as owed (the step-2 caller above, **in Rust**) is the step-2 row's **CLOSED 2026-08-29**. Two successive grounds expiring under a skip that was correct both times is the argument for recording a skip's GROUND and not just its verdict — a verdict outlives the reason that earned it, and reads as still-load-bearing once that reason is gone. See `.cursor/rules/22-no-lazy-deferral.mdc`, "A deferral's CONDITION can expire". |
| §2.9 step 5 — C++ relay path deleted | **BLOCKED, not pending** | §2.9a — it needs Rust to own the levin codec and the connection registry, i.e. the **p2p layer this series excludes**, and no daemon/p2p cutover design doc exists. Found by trying to start it. |
| **superseded C++ noise machinery deleted** | **landed** | `noise_channel`, `queue_covert_notify`, `clear_channel`, `send_noise`, the `channels` deque, `covert_payload` and `noise_zone_params` are gone. `make_relay_zone` no longer takes a noise flag, so C++ cannot construct a noise zone at all — `get_status().has_noise` reads the Rust-owned fact and is false everywhere. The two noise effect callbacks remain as **loud failures**, not no-ops: a silent drop would lose a real carrier effect the moment the cutover builds the path that can reach them. **Superseded 2026-08-27 on all three counts, by the change that built the executor's caller:** `make_relay_zone` sets the flag again for an ENCRYPTED zone behind `set_carrier_development` (off by default, so `has_noise` is still false in a shipped build); the send callback transports rather than failing loudly; and its unbind sibling is **deleted**, since unbind is consumed inside Rust and C++ has no channel state to clear. |
| §2.8 α rule | **pre-registered** | no number yet; the rule is the artifact |

### 3.1 Why the switch is a DEVELOPMENT FLAG (2026-08-26)

The carrier's executor, join, boundary, enqueue crossing **and producer** are
built (§3.1a, landed 2026-08-29): a real transaction rides the carrier, and the
pool is told only once the transport has accepted every window (not once a
peer has acknowledged one — §3.1d). All of it is reachable only after
`cryptonote::levin::set_carrier_development(true)`, a runtime opt-in defaulting
off — so nothing pays the ~42 GB/month posture until it is armed.

That opt-in is a ruling with reopening criteria, not caution, and the reason
is that an operator switch would ship with an undefined meaning.

**Vocabulary, because this section is where the collapse keeps happening.**
The carrier's precondition is **link secrecy** — it hides by payload
indistinguishability, which needs encryption at step one. That is
`LinkSecrecy`, and it is a different axis from a network's anonymity property.
Tor and I2P happen to be both encrypted *and* anonymizing, which is what lets
"anon zone" pass for "encrypted zone" today; P2P link encryption on a cleartext
zone would separate them, and the reopen condition for the no-cover-on-clearnet
ruling is already on the record. Everything below says **encrypted zone**.

#### The embargo cannot be per-node, and the carrier moves `hop` by ~9×

`shekyl_dandelionpp_embargo_draw_seconds(zone)` takes a zone and nothing else,
so every node on an encrypted zone draws from one distribution. An operator
switch would put two populations on that one constant:

| population | `hop` | embargo (α = 0.90, τ = 250) |
| --- | --- | --- |
| carrier off | ~715 ms | **298 s** (5.0 min) |
| carrier on, modal (`n = 1`) | 6.25 s | **1387 s** (23.1 min) |

**Computed, not scaled** — `derive_embargo` at those hops, because it steps
discontinuously and a linear scaling of the 715 ms figure is not a prediction
of it (§89.3). A ~4.65× spread in the derived embargo.

Provision at the low end and carrier-on nodes run α far below the 0.90 pin.
Provision at the high end and every carrier-off node on that zone pays it.

**A carrier-adaptive embargo is not the escape — and this is the third
application of one argument.** §18 refused a *degree*-adaptive embargo because
embargo length is inferable from fluff timing. §94.9 applied the same argument
to *posture*. Carrier is the third.

The objection that would rescue it — *"carrier-on is already visible, G-1 says
the channel is transparent to the peer decoder"* — **fails on audience**.
Carrier-on is visible to a **directly connected peer**. Embargo length is
inferable by **anyone who can time a fluff**. A carrier-adaptive embargo would
therefore republish an adjacent-peer fact to every network observer. The
audiences are not the same set, so the two facts are not interchangeable.

#### Reopening criteria (rule 21)

The flag becomes a shippable operator switch when **both** hold:

1. **The encrypted zone's embargo is provisioned at its worst carrier
   posture**, which is §94.9's established resolution shape — each zone covers
   its worst posture, collapsing per-posture to determinate values. §44.3
   already ruled over-provisioning privacy-safe (it *reduces* prefix-fire
   leak) and a recovery-latency cost, so this is a liveness bill, not a
   privacy one.
2. **§89.6.3's ask-don't-time status query has landed**, so the long wait is
   *honest rather than silent*. That is §94.10 shape (3) — make the mechanism
   tolerant rather than the constant accurate — and §94.10 already names the
   carrier as one of the two reasons that query belongs on the critical path.

Until both, enabling the carrier is a privacy regression rather than a
configuration, and a switch that reads as a preference would be a footgun.

### 3.1a ~~The producer is owed~~ — **LANDED 2026-08-29**, and what it cost

> **This section is the record of the gap and how it was closed. Everything
> below describes the state BEFORE 2026-08-29 unless it says otherwise; the
> producer is built, and `dandelionpp_notify` enqueues on the carrier.**

`shekyl_relay_zone_noise_enqueue` existed and nothing called it. A
development-flag zone therefore emitted **dummies only**: the cadence ran, the
frames were valid, and no real transaction ever rode the carrier.
`dandelionpp_notify` still sent stem transactions directly through
`make_payload_send_txs`.

**Stated plainly because the first draft of this row said "built".** The
four-piece decomposition was right and the fourth piece is half-done — the
crossing without its caller — which is exactly the shape §92.5c item 1 was
stuck in for weeks: a mechanism whose consumer nobody wired, recorded as
complete because the hard part was.

**The remaining work looked small and its seam already existed.**
`shekyl_relay_zone_plan_dispatch_with_refresh` returns `out_carrier` and
`out_channel`; `dandelionpp_notify` currently calls `plan_relay`, which
returns neither. So the producer is: swap the planning call, and on
`SHEKYL_RELAY_CARRIER_COVERT` enqueue on the returned channel instead of
sending directly. That is §2.9 step 4's own description — *"`send_txs`
consumes `plan_dispatch`"* — reaching its first real use.

**Why it is not in the change that built the executor.** That change shipped
two wire-corrupting defects found in review — a dummy of raw zero bytes, and
single-bucket framing across a fragmenting queue — both of which were
invisible because the test recorded only emission *length*. The producer
swaps the planning call on the **live stem path** for every zone. Landing it
in the same change, on the strength of the same test discipline that missed
those two, is how a third arrives.

It lands once the carrier path is exercisable end to end, which the runtime
opt-in (§3.1) now makes possible and the `#ifdef` it replaced did not: a
compile-time gate put the only carrier-running configuration in a build CI
never makes.

**CORRECTION 2026-08-29: "small" was wrong, and the reason is the pool
record.** The planning swap really is two lines. What that draft did not ask is
what happens to the two records the stem path fires — and both of them break on
the covert path for the same reason.

`record_relayed` and `record_stem_observation` currently fire **inside the
success arm of `make_payload_send_txs`**, deliberately: #573 moved them there
because `set_relayed` writes `meta.relayed`, `local_relay_base` reads exactly
that bit to choose an origin's backoff, and a send that never happened claiming
the long wait is a falsification. **An enqueue is not a send.** The queue
accepts a message; the window goes out later, at a cadence tick, and a roll
that REBINDS the channel restarts the run in flight (CV-1) — a roll on its own
discards nothing, which `a_queued_message_survives_an_epoch_roll` pins.
Recording at enqueue puts back
the defect #573 removed, in a place where the gap between "accepted" and "sent"
is not microseconds but up to a full epoch.

**And the successor is not known at enqueue time either.** F-10 charges an
observation to the peer the stem was given to. On the covert path that is the
channel's bound peer *at send time*, and `NoiseSend::failed` clears `bound` and
bumps the epoch, so a failed send rebinds — possibly to a different peer.
Arming the watch at enqueue charges an observation to a peer that may never
receive it, which is a wrong answer in F-10's tallies rather than a missing
one.

**So the producer needs a completion signal, and the queue is where it lives.**
`NoiseSend::sent` already knows the moment a message fully drains — it is the
`next >= message.len()` branch that pops the message. What it does not have is
the transaction's identity, because the queue holds opaque framed bytes by
design. Carrying the id alongside the message and reporting it on completion is
what lets the two records fire where the send is known to have happened, which
is the invariant #573 established and this path would otherwise be the first to
break.

**And the estimate itself is the lesson worth keeping.** *"Small — swap the
planning call and enqueue instead of sending directly"* was written against the
code's **shape**: one call replaced by another, at a seam that already existed.
It never asked what the two records *mean* once the send is deferred, which is
a question about semantics rather than structure. The next "small — just swap
X" will be written the same way unless the difference is stated: a swap is
small when the thing swapped in has the same completion semantics as the thing
swapped out, and this one does not.

**Not a CV-4 breach**, by the same argument that justified widening
`NoiseSendCb`: this is an OUTPUT after the cadence has already chosen when and
to whom. It tells the scheduler nothing.

The three candidates and why two are refused:

| | what the pool learns | verdict |
| --- | --- | --- |
| record at enqueue | "relayed" for a message that may never leave | **refused** — #573's defect, with an epoch-sized window |
| record nothing | `relayed` stays false, so `local_relay_base` keeps MIN_RELAY_TIME and the origin re-broadcasts at 300 s by another path | **refused** — defeats the carrier |
| **report completion** | the truth, at the moment it becomes true | **chosen** |

**~~Reopening criterion~~ — MET 2026-08-29.** The criterion was *"not marked
landed until a test drives a real transaction through the queue onto the
wire"*, and `a_real_transaction_rides_the_carrier_and_records_on_arrival` is
that test. It asserts both halves, because either alone is satisfiable by the
wrong thing: nothing recorded at send time (which a vanished transaction would
also satisfy) **and** a relay recorded once the carrier drains it (which the
ordinary wire would also satisfy). Together they say it went by the carrier.

Both bites observed red — reverting to `plan_relay` exhausts the epoch re-roll
bound, dropping the completion record fails the second assertion — and
re-verified after the test was restructured to re-roll, since a loop can mask
a failure a straight-line test would show.

### 3.1b Provenance is not a phase, and the type system should say so

**2026-08-29, found while wiring the producer.** The resolution first recorded
`originated_stays_in_zone(relay_method::stem, ...)`. That predicate takes the
method the **caller asked for**, not the one the wire used: an origin asking
for `Local` on an anonymity zone keeps `Local` however it travelled. Passing
`Stem` would have stripped §92's pin off **every carrier-borne origination**,
silently, on the one path where origination is the thing being protected.

**Third instance of one conflation.** `Local` is *provenance* — where the
transaction came from — and `Stem` is *phase* — where it is in the relay walk.
They share an enum, so the compiler treats them as alternatives on one axis:

| | what it was | consequence |
| --- | --- | --- |
| #573 | `add_tx`'s upgrade moved `Local` → `Fluff` | the origin pin stripped by its own transaction returning |
| the covert branch | `tx_relay = local` read as a phase change | a demotion that looked like routing |
| here | the wire's phase passed where the caller's provenance was wanted | the pin stripped off every carrier origination |

**Why this one was catchable at the keyboard**, and the reason generalises: the
predicate is *named* `originated_stays_in_zone`, so handing it something called
`stem` reads wrong on sight. The name carried the axis the type did not.

**The cutover should not rely on a name to do that.** A `RelayMethod`
parameter accepts `Stem` happily, because on the enum's own axis that is a
legal value. A parameter typed for *provenance* — one that only an origination
decision can construct — would not compile here, and none of the three
instances above would have been expressible. That is the same shape as
`LinkSecrecy` (constructible only from a `RelayZone`, so reach and secrecy
cannot be transposed) and as `zone_route`'s token, and it is the design note
this finding contributes to the Rust notify cutover: **carry provenance as its
own type rather than as a position in the phase enum.**

Recorded here rather than in FOLLOWUPS because it is a design input to a round
that has not opened, not a defect owed a fix.

#### 3.1b(i) "Needs the harness" is a claim, and it should be tested first

**2026-08-30.** The split-path review found two defects, and the second — the
fluff fallback sending the batch the carrier had taken — looked unassertable.
The record and the send were separate spans, `take_relayed` can only observe
the record, and the one route into that fallback from a carrier epoch is a stem
send that FAILS, which in the unit fixture tears down the very peers the fluff
would go to. A first draft asserted on the resulting empty payload and was
caught by its own non-vacuity guard.

**So it was filed as a fourth consumer of the `t_core` arrival harness. That
was wrong, and it was wrong in a way worth naming.** The defect had nothing to
do with `t_core`. The record and the send were two statements sharing a
variable, and review had just demonstrated that a variable can be changed in
one and not the other. Passing **one batch to one call** — `fluff_and_record` —
puts the send inside the record's assertion and closes it in place. Rule 50's
second clause: when no check can fail, encode it so the mistake is
unrepresentable.

**The generalisable part is the order of operations.** "This needs a fixture we
do not have" is a claim about the world, and it is cheap to make and expensive
to hold: three consumers had already accumulated behind that one harness, each
having re-derived the same obstacle list and moved on. Attempting the design
change first is what distinguishes a real blocker from a reflex, and here it
took one lambda.

The harness is still owed for the consumers that genuinely need it — the
arrival leg cannot be driven without a chain that admits real transactions.
This is not one of them, and counting it as one would have made the queue look
longer than the work is.

### 3.1c Budget versus actual — pre-registered before the traffic exists

**2026-08-29.** The ~42 GB/month posture is signed off **provisionally**, on
the condition that it be measured once a real transaction rides the carrier —
which the producer now makes possible for the first time. This section names
what the measurement should show **before** anyone runs it, because the first
reading is otherwise free to be read as either confirmation or a defect.

**The arithmetic is not what is in question.** `PER_NODE_CEILING_BYTES_PER_SEC`
is a `const` assert at exact equality: `20 480 × 4 ÷ 5 s = 16 384 B/s` holds by
construction or the build fails. Measuring it would only re-derive it.

**What is in question is whether the observed rate matches, and it will not
match exactly.** Three named reasons, all expected:

| source | direction | why |
| --- | --- | --- |
| jitter over a finite window | **either** | the mean is 5 000 ms; any finite sample's mean sits either side of it, which is the same property §56 requires the cadence to have |
| unbound slots | **under** | a channel with no peer emits nothing (CV-2), so a node that has not filled its stem slots carries less than the ceiling |
| discards and rebinds | **neither** | a restart re-sends windows, so later ticks carry retries instead of dummies — the BYTE rate is unchanged and only the useful throughput falls. Listed because it is the intuitive miscount: it belongs to a throughput reading, not a bandwidth one |

**So the expected finding is: at or slightly under the ceiling, never
meaningfully over.** The ceiling is a sustained mean at the worst posture —
every channel bound, every zone carried — and a real node is usually in a
lesser posture.

**What would be a real defect**, stated so the reading has a bar to clear
rather than an impression to leave:

- **sustained rate above 16 384 B/s** with every channel bound. The emitter has
  no path to exceed its own mean, so this would mean the cadence is not drawing
  what it is documented to draw.
- **per-circuit rate above 6 145 B/s sustained.** That is
  `PER_CIRCUIT_PEAK_BYTES_PER_SEC`, the shortest interval; a *sustained* rate
  at the peak means the jitter is not being applied.
- **a rate that varies with queue depth.** This is the CV-4 breach the whole
  separation exists to prevent, and it is the one measurement worth running
  even if the totals look right — `cv4_the_cadence_does_not_depend_on_queue_depth`
  gates it in Rust, but the wire is where it would be observable to an
  adversary.

**Dummies count.** A window carrying cover is the same 20 480 bytes as a window
carrying a fragment — that is the invariant, not an accounting convenience — so
the budget is spent whether or not anyone is transacting. A measurement taken
on an idle node is therefore a *complete* measurement of the sustained cost,
not a floor for it.

#### 3.1c(i) How to run it (2026-09-05)

**The switch had no operator path until now.** §3.1c was written as a
pre-registration and left the arming to whoever ran it; in fact
`set_carrier_development` had no caller outside `tests/unit_tests/levin.cpp`,
so a stock `shekyld` could not turn the carrier on at all. The measurement was
unrunnable as specified, and would have been run — if at all — off an
uncommitted local patch, which is the one shape a pre-registered measurement
must not have: nobody else can re-run it, so the reading is an impression
again.

`shekyld --carrier-development` arms it. **HIDDEN** — parsed, never in
`--help` — because §3.1 ruled this a development switch and visibility is
exactly what would make it an operator setting. `check_carrier_flag_hidden.sh`
pins the registration site and the default; moving one `add_arg` argument is
all it would take, and it would break no test.

**Three arms, because the CV-4 signature needs a comparison.** The "dummies
count" paragraph below is right that an idle node measures the full sustained
COST — but the third defect is about how the rate responds to load, which one
arm cannot show:

| arm | carrier | load | answers |
| --- | --- | --- | --- |
| A | off | idle | the p2p baseline (timed sync, pings, handshakes) |
| B | **on** | idle | defects 1 and 2, as **B − A** |
| C | **on** | transacting | defect 3, as **C vs B** |

Subtracting A is what keeps ordinary p2p chatter out of the carrier figure
without having to model it.

**Count only payloads of exactly `WINDOW_BYTES`, and EXCLUDE everything else
(2026-09-05).** The earlier draft of this section said to count levin payload
on the node→proxy sockets and said nothing about filtering. That silence was
the defect, and it is arm C's problem specifically.

Arm C is a LOADED run, so fluff releases share its wire with carrier
emissions. PWD-B12 caps what a flush releases, so fluff volume is a moving
quantity — and arm C's job is signature 3, measured as C against B. A change
in fluff volume between the two arms would present as a carrier-rate
difference and **masquerade as the CV-4 breach the arm exists to detect**: a
false positive on the one signature this section calls worth running even if
the totals look right. An oracle that cannot distinguish the defect it names
from an unrelated change in its own environment is not an oracle.

The cure is to EXCLUDE fluff rather than subtract it. Subtracting inherits
every assumption the confound had; excluding removes the dependency, so arm C
stops depending on PWD-B12 at all rather than waiting for it to settle.

**Why the filter is exact rather than a heuristic — do not relax it.** A
carrier emission is always precisely `WINDOW_BYTES`, by construction and not
by tendency:

- `shekyl_relay_zone_noise_enqueue` takes ONE transaction blob, not a vector.
  §2.9b is structural at the crossing: a batch is *unsayable* there, so N
  transactions become N enqueues, each padded to a whole number of windows.
- CV-4 makes the cadence independent of queue depth, so the emission RATE
  does not move with load either.

A reader who sees only "count exact-window-size payloads" will take it for a
convenience and widen it to a range the first time a number looks off. It is
not a convenience; it is the property that makes the arm separable.

**And the emitter is batch-blind structurally, which is why the carrier arms
survive PWD-I1 at all.** `NoiseQueues` is held BESIDE `Driver` in
`RelayZoneHandle` and never inside it, and `Driver` owns `Zone` — so
PWD-B12's subject, `rust/shekyl-relay/src/zone/mod.rs`, cannot reach the
carrier's buffers. Batch composition changes what `Zone` releases; it cannot
change what the carrier emits.

**Arm A is still re-taken after PWD-B12 settles.** The flush cap changes p2p
chatter, and A is the baseline B is measured against. Excluding fluff fixes
arm C; it does not make A's baseline stop moving.

**Count levin PAYLOAD, not IP bytes.** The table above lists three discrepancy
sources — jitter (either way), unbound slots (under), discards (neither) — and
**none of them can produce an over-reading**. So an over-reading looks
unambiguously like defect 1. But counting at the IP layer adds TCP/IP framing
(~2–5 %) and the levin header adds ~33 B per 20 480 B window (~0.16 %),
manufacturing the one direction this section says is impossible. Count at the
node→proxy sockets, at the levin layer.

**Window: 2 hours per arm.** The relative standard error of the aggregate rate
is `0.0963/√n` per channel, with four channels at a 5 s mean: ~5 min resolves a
4 % excess, ~30 min a 1.5 %, and 2 h a 0.75 %. Defect 2 is a 50 % excess and
shows in a minute — the length is for defect 1.

**Confirm all four slots are bound for the whole window**, or the run
under-reads by construction (CV-2, the second row of the table above) and the
under-reading is not a finding.

**PRECONDITION ON THE RESULT, not on the run: the rule that governs boundness
has not been written (2026-09-05).** PWD-I1 routes a same-host outbound cap to
PWD-B9. PWD-B9 **does not exist** — routed, never drafted. Counted on dev
2026-09-05: 24 references across four documents, **17 of them inside
`SHEKYL_P2P_PROTOCOL.md` itself**, and no section heading anywhere in the
repository. The deliverable cites a section it does not contain, seventeen
times. So outbound connection lifecycle on encrypted zones is not
stable-pending-implementation; the rule that decides it is ABSENT.

The consequence is specific and it is not fixed by measuring more carefully. A
reading taken today can satisfy every instruction in this section — four slots
bound, two hours, exact-window filtering — and still not mean what §3.1c's
sign-off assumes, because nobody can yet say whether the boundness observed is
the boundness the settled protocol will produce. **Internally valid, and not
about the thing the sign-off is about.**

So the result carries this as a stated condition: a number taken before PWD-B9
exists is provisional in the same way the budget it tests is provisional, and
it does not discharge §3.1c on its own. Recorded here rather than tracked
elsewhere because **an absent rule is invisible to every check that reads this
document** — no gate, no test and no review can see a section that was never
written, so naming it in the method is the only place it can be seen at all.

**Histogram the intervals, do not only divide bytes by time.** Defect 2's
signature is sharper in the distribution than in the mean: jitter applied gives
a flat `U[3333, 6667]` ms, jitter absent gives a spike at 3333. And defect 3
can modulate timing without changing the total, so compare B and C on the
distribution as well as the rate.

### 3.1d What a carrier verdict of `sent` actually asserts (2026-08-31)

**It asserts transport ACCEPTANCE, not delivery, and the contracts now say
so.** Found in review: `on_noise` returns the result of
`connections::send`, and epee's `connection<T>::send` places the bytes on the
connection's asynchronous write queue (`m_state.data.write.queue`) and calls
`start_write()`. The return means the write was *queued*, not that it left the
socket and certainly not that a peer received it. A connection that fails after
accepting the bytes never comes back through the resolution callback, so
`CarrierOutcome::Sent` fires and the relay record and F-10 observation are
charged anyway.

**The ruling is to define the contract honestly rather than strengthen it, and
the blocker is named.** Reporting true write completion needs a completion
signal epee does not expose; adding one means thickening inherited C++
(`20-rust-vs-cpp-policy`) immediately below the layer scheduled for the daemon
Rust cutover, and even socket-write completion would not be peer receipt. The
reopening criterion is that cutover, where the write path is Rust-owned and
completion is expressible — carried as a `FOLLOWUPS.md` one-liner, per
`21-reversion-clause-discipline`.

**What makes this acceptable today rather than merely deferred.** The carrier
is the STRICTEST recorder on the relay path, not the weakest. `on_fluff` never
inspects its send result, and `fluff_and_record` records *before* sending; the
stem arm records an origination's `local` class "whatever the transport did".
The carrier alone checks the `send` return (`res > 0`) and falls back to fluff
when the transport refuses. So the residual gap — an async failure after
acceptance — is one every relay path in this file shares and none of them can
close from here; the carrier does not widen it.

**The F-10 exposure is latent.** A verdict charged to a successor that never
received the bytes is a wrong entry in the tallies rather than a missing one,
which is the hazard §3.1a's successor argument was written against. It has no
consumer today: the selection tier that reads those tallies is §12.11 and is
unbuilt, and the transport cutover lands before it. That is why this is a
contract correction and not a redesign.

**Naming.** `sent` is kept rather than renamed to `accepted`. It means here
exactly what `send()` means everywhere in this tree, and the C and Rust homes
each state the gap explicitly so the name cannot be read as an overclaim.
Identifiers that asserted the stronger fact — a `delivered` send-status local,
a `delivered_to` test binding, a test named for the peer that "received" it —
were renamed, because a name is a claim the doc above it cannot qualify.

**A vocabulary gate was considered and REJECTED (2026-08-31).** After this
correction propagated to a dozen further sites over two review rounds, a CI
grep forbidding "received"/"reached the wire" across the carrier files looked
attractive. It fails both of the tests such a gate has to pass. The same words
are TRUE two paragraphs away — a fluff peer does receive, and several correct
sentences here are denials that must contain the word — so the check either
fires on legitimate prose or is scoped so narrowly it cannot fire at all, which
is `47-gate-subject-assertion`'s empty-subject failure. And the job it would do
is "new prose must match the defined contract", which is what the contract
homes, `a_queued_message_survives_an_epoch_roll`, and this section already do;
policing vocabulary is not the same as policing correctness
(`no-convention-theater-gates`). Reopen only if the claim recurs in code that
POSTDATES this section — which would mean the homes are not being read.

### 3.1e The pool can change while the carrier holds a transaction (2026-09-01)

**The carrier is the first relay path with a long gap between deciding to send
and sending.** Stem and fluff decide and transport in one call, so the txpool
cannot move underneath them. The carrier accepts a message and emits its
windows over the following cadence ticks — up to about a full epoch later
(§3.1d's backlog bound). In that window the transaction can be mined and
removed by `tx_memory_pool::take_tx`.

**Applying a verdict then is not merely redundant — it CORRUPTS F-10.**
Recording a relay against a pool entry that is gone does nothing useful, but
arming a stem observation does something actively wrong: the watch expects a
re-arrival from the successor, a block removal produces no arrival event, and
the observation expires as a `Silent` charged to a node that behaved
correctly. That is a WRONG entry in the tallies rather than a missing one —
the same distinction the successor-at-enqueue argument turns on (§3.1a). The
stem and fluff paths cannot reach this; the carrier widened the window by
about six orders of magnitude, so the gate belongs to the change that widened
it.

**The gate is pool MEMBERSHIP, checked at verdict time, and it covers the
whole application.** `i_core_events::pool_has_tx` — a read-only query
`cryptonote::core` already implemented for fluffy-block reconstruction, using
`relay_category::all`, because the question is "do we still hold this", not
"in what class". Gating the whole verdict rather than only the observation
also stops the discard arm fluffing a transaction that is already in a block,
and moots what `set_relayed` would do against a missing entry. Pinned by
`a_verdict_for_a_transaction_the_pool_dropped_records_nothing`.

**What is NOT fixed, deliberately: the send still departs.** The gate runs when
the verdict arrives, which is after the windows are on the wire. Cancelling
earlier would need an enqueue-cancellation path — `NoiseQueues` has no such
API, and `unbind` clears a whole channel, so cancelling one message would
discard its channel-mates. **Corrected 2026-09-01: the cost is not one
window.** The gate runs on the VERDICT, which arrives only after the message
completes, so a transaction mined before its first carrier tick still emits
every one of its windows — up to `MAX_FRAGMENTS` (5) × `WINDOW_BYTES`
(20 480) ≈ **100 KiB** of cover carrying a transaction peers already hold and
will drop. An earlier draft said "one window", which understated it by the
fragment cap.

That is still what cover traffic is for, and it is bounded per transaction
rather than per epoch, which is why the conclusion does not change. Reopening
criterion: a cancellation API becomes worth building if some other caller
needs one, or if measured carrier bandwidth (§3.1c) shows mined-while-queued
traffic is a material share of the budget — not on this argument alone.

**The membership gate is not atomic with the recording, and the fix is a
SECOND gate rather than a combined core operation (2026-09-01).**
`pool_has_tx` releases the txpool lock before `on_transactions_relayed`
reacquires it, so a block can be processed between them and take the entry;
`set_relayed` then updates nothing while the observation is armed anyway —
the same false `Silent`, through a window of microseconds instead of an epoch.

Review proposed combining membership and recording into one core call that
reports whether the entry was updated. Rejected: `on_transactions_relayed`
takes a SPAN, so a single success flag is the wrong shape for it, and a
carrier-only variant duplicates a widely-used notification to serve one
caller. What the observation actually needs is cheaper — re-ask the question
after the recording, and arm only if the answer is still yes.

**That pair NARROWS the window; it does not invert the polarity, and saying
it did was wrong (corrected 2026-09-01).** `pool_has_tx` releases the txpool
lock before returning, so a block can take the entry between the second check
and `record_stem` and the observation is armed for a transaction that is gone
— the same false `Silent`. The claim that "the checks can only lose
observations, never invent them" was a property this construction cannot
deliver, and it was stated in the code, this section, and a test docstring.

What is true is the scale, and the comparison to what sits beside it.
Ungated, the exposure was the carrier's whole backlog — up to an epoch of
wall-clock in which any block could take the entry. Gated once, the gap
between the first check and `set_relayed`. Gated twice, the gap between the
second check and the arm. **And the ordinary stem arm does not check the pool
at all** before `record_stem_observation`, so the carrier is the only relay
path here that narrows this even once; it does not introduce the hazard, it
inherits it and shrinks it.

Closing it needs one of two things that do not exist: the txpool cancelling
in-flight observations when it removes a transaction, or `expire` re-asking
membership before it counts a `Silent` — the latter being the better place,
since the `Silent` is what does the damage and expiry is where it is decided.
Both are new plumbing across the FFI into a layer the daemon cutover
replaces. **Reopening criterion:** §12.11, the selection tier that consumes
these tallies, becoming real — it is unbuilt today, so nothing reads the
false entry — or the cutover giving Rust a pool query it can call at expiry.

The first gate is not subsumed by the second: it also stops the discard arm
fluffing a transaction already in a block, which the second runs too late to
prevent. `a_pool_drop_during_recording_arms_no_observation` pins the arm the
gates DO cover — the entry gone by the time the recording runs.

**The wake handler guarantees `arm()` structurally, not site by site.** The
same change that made `apply_carrier_verdicts` `noexcept` also added
`reserve_verdicts` — which allocates — one call above it, in the same gap
before `arm()`. Guarding fallible calls one at a time is how the second one
got there, so the work is now inside a `try` and `arm()` is outside it: the
next wake is scheduled whatever this one did. The timer-error throw stays
outside, because a failed wait is not a failed unit of work and re-arming
against a timer that has reported it cannot fire would be a spin. The
dispatcher keeps its own `noexcept` and per-verdict catch — a different job:
strand survival versus keeping one poisoned verdict from taking the verdicts
behind it.

**A throw during verdict application strands a forwarded stem, and retaining
the record does not fix that (2026-09-01).** Review proposed keeping an
extractable pending node until application succeeds. Taken literally that is
strictly worse: nothing re-drives a verdict — the terminal outcome is already
drained on the Rust side and never reported twice — so the retained node is
never revisited, and the dedup scan then hides the txid from every later offer
while leaking its blob. Stranding plus a leak, in place of stranding.

The version that WOULD recover is a retry list re-driven on a later wake. It is
rejected here, with the ground stated so a future reader can reopen it rather
than re-derive it:

- The only C++ throw source left on that path is `on_transactions_relayed`
  itself, since the allocation we own is now made before the erase. A retry is
  therefore a retry of the thing that just failed, under the memory pressure
  that made it fail.
- The class that suffers is a FORWARDED stem — a transaction this node received
  from a peer. Failing to forward it is precisely the case Dandelion++'s
  embargo exists for: the originator's timer fires and fluffs, so the
  transaction reaches the network by the route the protocol already provisions
  for a stem node that goes away. An ORIGINATION is unaffected — `relayed`
  stays false and the pool re-offers at `MIN_RELAY_TIME`.
- Our own node draws no embargo for it, because `set_relayed` is what draws
  one; the entry sits until it expires from the pool. That is the honest cost,
  and it is a liveness contribution rather than a correctness or privacy
  failure.

Reopening criterion: a second, non-allocating throw source appearing on this
path, or the daemon Rust cutover giving the recording an error return instead
of an exception — at which point recovery is a `Result` to handle rather than
machinery to build.

**And the verdict path must not be able to stop the strand.** `relay_wake`
applies verdicts and then calls `arm()`, which re-arms the zone's wake timer.
Before the producer nothing fallible sat in that gap. An exception escaping
verdict application would skip `arm()` and stop the zone for the rest of the
process — no fluff releases, no cadence, no epoch rolls — so
`apply_carrier_verdicts` is `noexcept` and catches per verdict, the same trade
every effect callback beside it already makes: a dropped relay is recoverable,
a dead strand is not. Pinned by
`a_throwing_verdict_does_not_stop_the_relay_strand`.

### 3.2 The carrier turns a 38 % shape spread into an 8× one (2026-08-26)

`hop` has no shape parameter, and the carrier gives it one by fragmentation.

| shape | bytes | `n` | `hop` | embargo |
| --- | --- | --- | --- | --- |
| modal (1-in/2-out, **genesis** depth) | 13,042 | 1 | 6.25 s | 1387 s (23.1 min) |
| modal (1-in/2-out, **max** depth) | 17,015 | 1 | 6.25 s | 1387 s (23.1 min) |
| 8-input intermediate | 63,683 | 4 | 43.75 s | 8781 s (146.3 min) |
| **structural max (8-in/16-out)** | **97,964** | **5** | **56.25 s** | **11,245 s (187.4 min)** |

Carrier-off, `hop` runs ~715–990 ms across the same shapes — a 38 % spread.
Carrier-on it is **8.1×**, and the binding number is the **structural
maximum**, not the 8-input intermediate: `MAX_FRAGMENTS = 5` is derived as
`ceil(S_max / WINDOW_BYTES)` against 8-in/16-out at max depth, so the worst
admissible shape is `n = 5` and the embargo would have to cover **187 min**,
not the ~110 min a linear scaling of the intermediate suggests.

*(The modal is listed at both depths because this row previously labelled
13,042 B as **max** depth, and that is the **genesis**-depth figure —
17,015 B is max depth (`params/carrier.rs`, enforced by `carrier_window.rs`).
Both are `n = 1`, so hop and embargo are identical and no conclusion in this
section moves: the label was wrong, not the arithmetic. That they agree is not
luck — `WINDOW_BYTES` is sized at max depth precisely so the fragment count
cannot flip from 1 to 2 as the curve tree deepens, which is the whole reason
the two rows can sit here with the same hop.)*

**Does the spread disclose anything?** §89.3 raised the shape-discontinuity
question and left it unruled, noting that fires are ~10 % of transactions and
**shape is public from the transaction anyway**, so the likely answer is no.
The carrier amplifies the magnitude without changing that argument. What it
does change is **provisioning**: one constant with no shape parameter must
cover the worst shape.

**The flat-hop alternative, and it does not fit where it looks like it should.**
Enlarging the window until every admissible shape is `n = 1` collapses the
spread to the residual. A 64 KiB window does **not** achieve that — the
structural max is 97,964 B, so it is still `n = 2`. Only a ~98 KiB window makes
every admissible shape a single fragment. Priced against axis 2's ceiling:

| window | cadence for ≤ 8 KiB/s (2 channels) | resulting `hop` |
| --- | --- | --- |
| 20,480 B (today) | 12.5 s → **3.20 KiB/s** | 6.25 s … 56.25 s |
| 65,536 B | ≥ 16 s | 8 s … 24 s |
| ~98,046 B | ≥ 24 s | **12 s, flat** |

> **Stale as of 2026-08-28 and kept as the record of the argument.** Every row
> is per zone against an 8 KiB/s ceiling; §3.3 ruled the denominator **per
> node** at **16 KiB/s**, and the cadence is now 5 s in the mean rather than
> 12.5 s. The 20,480 B row's live figures are 4 KiB/s per channel and a modal
> `hop` of **2.5 s**. Re-price before quoting any row here as purchasable.

So flat *is* purchasable, at a 12 s floor and **exactly at** the ceiling with
zero margin. **This is analysis, not a proposal — `WINDOW_BYTES` is not
touched here.** It belongs to the window-sizing question, and it needs the
denominator ruling in §3.3 first, because both rows above are per zone.

**A recorded claim this touches.** `params/carrier.rs` says a ~98 KiB window
"at any usable cadence **breaches**" the ceiling. At 24 s it *meets* it. The
claim is imprecise rather than wrong if "usable" excludes a 24 s cadence — and
there is a real argument that it should, since a ceiling whose stated job is
"constraining a future cadence proposal without constraining this one" is not
doing that job at zero margin. Recorded here rather than silently contradicted.

### 3.3 The ceiling is per NODE; the design figure is per ZONE (2026-08-26)

Axis 2 says **8 KiB/s per node**. The figure it checks — 3.20 KiB/s — is
`WINDOW_BYTES × NOISE_CHANNELS / cadence`, and `NOISE_CHANNELS` is documented
as *"max outbound connections **per zone**"*. The two halves of the comparison
are on different denominators.

| node | zones carrying | rate | margin |
| --- | --- | --- | --- |
| Tor only | 1 | 3.20 KiB/s | 2.5× |
| Tor **and** I2P | 2 | **6.40 KiB/s** | **1.25×** |

The ceiling still holds, but 1.25× is not "a ceiling that constrains a future
cadence proposal without constraining this one" — halving the cadence, the
lever this arc has priced repeatedly, **breaches it on a dual-zone node while
looking fine on a single-zone one**.

**~~Owed: a ruling on the denominator.~~ RULED 2026-08-28 — per NODE.** The
alternative was per encrypted zone, which leaves the per-node total unbounded
in the number of zones; a ceiling that grows when you add a transport is not a
ceiling. So the figure is stated at the multi-zone case, which is the posture
that exists.

| | value |
| --- | --- |
| ceiling | **16 KiB/s per node** |
| window | 20,480 B |
| channels | 2 per zone × 2 encrypted zones = **4** |
| mean cadence | **5 000 ms** (`3 333 + U[0, 3 334]`) |
| per channel | **4 KiB/s** |
| worst-posture node rate (**sustained**) | 20,480 × 4 ÷ 5 s = **16,384 B/s** |
| worst-posture **burst** | ceil(20,480 × 4 ÷ 3.333 s) = **24,579 B/s** (~1.50×) |
| sustained cost | **~42 GB/month**, ~8.9 % of the 180 KiB/s circuit floor |

**It holds at exact equality, and the ceiling is now a build break rather than
a table entry.** `params::carrier::PER_NODE_CEILING_BYTES_PER_SEC` carries it
with a `const` assert beside the constants it divides, so shortening the
cadence, widening the window, or adding a third encrypted zone does not go
quietly — it fails to compile.

That is the honest answer to this section's own objection. A 1.25× margin was
*"not constraining a future cadence proposal without constraining this one"*;
1.0× does not pretend to be a bound with slack. What it buys instead is that
the next change has to **move the ceiling explicitly, with a reason**, rather
than discovering afterwards that a figure in a table went stale.

**One uniform cadence, no allocation.** The ceiling is not divided among zones
or channels, and no channel is throttled relative to another: every channel
draws from the same law. A per-zone or per-channel budget would make emission
timing depend on how many zones a node happens to carry — a node fact leaking
into the cadence, which is the CV-4 shape one level up.

**Rebind-on-slow-circuit is the stated handling.** A circuit that cannot
sustain 4 KiB/s is a transport problem, answered by rebinding the channel, not
by slowing the emitter for everyone. Slowing it is what would make the cadence
carry information about the circuit.

**§3.2's trade table is now per node** and both its rows were per zone, so the
admissible windows there halve on a dual-zone node. The table is analysis
rather than a proposal — `WINDOW_BYTES` is untouched — but its rows should be
read against 16 KiB/s per node before any of them is quoted as purchasable.

**Also stale, and it is a measurement spec.** Six lines under the 3.20 KiB/s
figure, axis 2 still instructs: *"the rig spike must hold a circuit at
**2.72 KiB/s** for a full session."* 2.72 is the pre-#546 rate that the same
section's own update note records superseding. The one experiment this axis
waits on would be run at 85 % of the real load. Corrected in place.

**Not swept here, recorded so it is not lost:** the Tor-percentage figures
(~0.06 %, ~0.27 %) were computed at 3 KiB windows and predate #546; and §42.1's
fluff-capacity re-pricing moved the transaction side while the carrier's
capacity side moved too, so the composed ratio wants re-checking rather than
assuming both corrections compose.

**Non-scope, tracked separately (§2.0):** Tor transit measurement — *unblocked,
not started*; flood-suite reconciliation — *unblocked, not started*.
