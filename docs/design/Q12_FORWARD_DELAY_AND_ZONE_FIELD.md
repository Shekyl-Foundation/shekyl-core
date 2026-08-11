# The txpool origin-zone field — with Q-12's disposition as one of its outputs

**Design round, opened 2026-08-10.** Scoped per
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
multi-round, FFI boundary, persisted-layout change. Cited explicitly, as that
rule requires.

**Status: DESIGN, nothing implemented.** Every numeric claim below is subject to
verification at pre-flight (rule 26's B6/B9). Where a number is inherited rather
than derived, it says so.

---

## 1. Charter

**The round is the origin-zone field. Q-12's disposition is one of its
outputs, not its second half.**

Q-12 was registered at §22.2 of [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md)
and has been live — not deferred — since its reopen criterion (a) fired at
Q-11 Unit 0. It owes three things:

1. **Derive the mean** from the stated anonymity-set objective.
2. **Fix the family** from measurement — the draw is Poisson where the
   derivation wants memoryless (the F-2/F-4 signature).
3. **Retire the last `random_poisson_seconds` caller**, and the primitive with it.

§89.8.7 first framed the origin-zone field as a fourth deliverable riding
alongside. **That framing was too weak, and Q12-D1 corrects it**: after the
field, `relay_method::forward` may have **no producers at all**, so items 1 and
2 may have no subject. A round cannot open by deriving a constant for a class
whose existence it is about to decide.

**So this round settles the field, and Q-12 closes in one of three ways as a
consequence** (Q12-D1). Item 3 is the exception and is **split out** — it is
certain in every branch (§5.1).

---

## 2. Ground findings

Verified at source on 2026-08-10, at the pin `6bc65d2a9`.

### 2.1 The coupling is at the line, not merely conceptual

[`tx_pool.cpp:310-312`](../../src/cryptonote_core/tx_pool.cpp#L310-L312) draws
the delay **only** when `tx_relay == relay_method::forward`:

```cpp
if (tx_relay == relay_method::forward)
{
  last_relayed_time = clock::to_time_t(clock::now() + crypto::random_poisson_seconds{forward_delay_average}());
  set_if_less(m_next_check, time_t(last_relayed_time));
}
```

And `forward` is exactly the class §89.8.5 showed is re-relayed to
`zone::public_`. **So the forward delay *is* the bridge timing.** The zone field
does not merely change `forward`'s population in the abstract; it changes what
this specific draw schedules.

### 2.2 Retiring the caller retires the whole primitive

`tx_pool.cpp:312` is the **only** caller of `crypto::random_poisson_seconds`.
`crypto::random_poisson_subseconds` — declared beside it at
[`duration.h:69-70`](../../src/crypto/duration.h#L69-L70) — has **no callers at
all**; F-4/F-5 retired the fluff-delay draw that used it.

> So deliverable 3 is larger than its wording. Removing this one call leaves
> `random_poisson_duration` with zero users, and the Poisson half of
> `duration.h` goes with it. §22.2's phrase *"the primitive's near-death is
> load-bearing"* becomes its actual death.

### 2.3 `FORWARD_DELAY_BASE` still has no consumer

[`cryptonote_config.h:164`](../../src/cryptonote_config.h#L164). It was the
derivation input for `AVERAGE` (`22 ≈ 15 × 3/2`) until Q11-A's decoupling
replaced both with literals, and was kept deliberately as half of a registered
open item. **This round decides whether it dies.**

### 2.4 The pool loop discards the origin zone

[`cryptonote_core.cpp:1091`](../../src/cryptonote_core/cryptonote_core.cpp#L1091)
sends the `stem_req` batch — where `forward` entries land — with
`epee::net_utils::zone::public_` **as a literal**. Not a policy choice: the
txpool stores no origin zone, and the pool loop runs long after the moment that
knew it. The coherence branch keys on `send_txs`'s `origin`, whose only
real-arrival callers are the immediate-relay sites, so it never sees these.

---

## 3. Decisions taken at opening

### Q12-D1 — Q-12 is a consequence of this round, not a half of it. RULED.

The first framing was *"derive against the post-zone-field population, because
the population changes."* **That understates it, and the stronger reason
changes the round's scope rather than its ordering.**

**The mechanism's structure changes, not only its inputs.** After the field,
anonymity-arrived traffic stays in-zone: it stems there, fluffs there under
`OutboundOnly`, and **the bridge moves to the next node** — whichever peer
receives that anonymity fluff and relays it publicly under R-1's exit rule.

`relay_method::forward` is assigned at arrival purely on `zone != public_`
([`cryptonote_protocol_handler.inl`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl),
the `zone == public_ ? stem : forward` line). **If that assignment stops, the
class has no producers and is unreachable.**

> **So rejecting (a) is not "derivable now, wrong later." It is refusing to
> derive a constant for a class that may not exist** — §63.2's failure in its
> purest form, an analysis written against a mechanism that is not there.

**Q-12 therefore closes in one of three ways, all downstream of this round:**

| closure | Q-12's outcome |
| --- | --- |
| `forward` is deleted | closes **by deletion** — no derivation, no constant |
| `forward` survives with a new population | derive **then**, against a defined bridge point |
| a bridge delay is wanted at the new site under a different name | a new derivation carrying the old rationale — a cleaner start than patching the old one |

**Scope consequence, accepted:** this round is **the zone field**, and is
smaller than "the field plus Q-12". It commits to no derivation before knowing
whether there is anything to derive.

**Reopening criteria:** if the field is abandoned or deferred past this round,
Q12-D1 reopens and Q-12 proceeds against the bridge population as it stands,
with an explicit banner saying the derivation is against a mechanism scheduled
for replacement.

### Q12-D1a — The anonymity-set rationale survives the move, and improves

Worth stating because the deletion of a class can read as the deletion of its
purpose. **It is not.** A node bridging an anonymity fluff to clearnet still
leaks timing about which anonymity peer fed it, so the objective the forward
delay was written for still has a subject.

**What changes is favourable, and it is an argument for the field beyond fixing
coherence.** Today a transaction has *one* bridger, holding it under a delay.
After the field, an anonymity fluff reaches **many** peers, so many nodes can
bridge the same transaction — and a delay at each randomises which one goes
first. That is a better structure than single-bridger-with-a-delay: the
anonymity set stops depending on one node's timing draw and starts depending on
a race among several.

### Q12-D2 — The field is reinstated, and §89.2's back-out is not reversed. RULED.

§89.2 removed §65.4's reserved bits, arguing the txpool needs to be *told* the
zone, not to *remember* it. **That finding stands** — the embargo arming site
has the zone in hand and takes it as a parameter beside `tx_relay`.

What was over-generalised is the conclusion (§89.8.6). Two consumers, two
correct answers:

| consumer | when it acts | needs |
| --- | --- | --- |
| embargo draw (`set_relayed`) | synchronously with the relay event | to be **told** — parameter, no field |
| pool re-relay (`relay_txpool_transactions`) | after that moment has passed | to **remember** — a stored origin zone |

The distinguishing question is cheap and belongs in the reviewer's hand:
***does this consumer run while something still knows?***

### Q12-D3 — Zone is a routing choice with a cost, not a property a transaction inherits. RULED.

**Both directions, one mechanism.** Going clearnet→Tor and Tor→clearnet are the
same kind of thing: a selectable path with a latency price. Neither is a special
case of the other, and neither should be special-cased.

> **The rule, entire:** at entry, pick a zone with some probability; coherence
> holds the transaction there; the zone's `hop` prices the path.

**This deletes rather than decides.** Three items on this round's list stop
being questions:

| item | disposition under Q12-D3 |
| --- | --- |
| `relay_method::forward` as a class | **deleted.** It exists only to mean *"arrived somewhere other than clearnet"* — a fact about **provenance**. Under one rule, provenance stops being a routing input, so the class has nothing left to express. This answers Q12-Q3. |
| the fall-through branch | **deleted.** An unusable zone is simply not selectable, exactly like an unavailable peer. No failure *reason* is inspected because none is consulted — which is already `select_anonymity(require_usable=true)`'s existing semantics. |
| Q12-Q2 (what an arrival inherits when its zone is unusable) | **dissolved.** There is no special case left to give a rule to. |

### Q12-D3a — The exit already exists, and it is not at the stem

The structural fact that makes this cheap, **verified at source**
(`net_node.inl`, `send_txs`): `still_stemming` is false for
`relay_method::fluff`, so a fluffed transaction bypasses coherence and reaches
clearnet regardless of origin. A peer receiving an anonymity fluff classes it
`fluff` — the `dandelionpp_fluff` flag overrides its `forward` default — and
relays it publicly on its next hop. **That is R-1's `tx_relay` exit, and
Tor→clearnet bridging already runs through it today, with no stem-phase divert
involved.**

> **So `p_out = 0` is a legitimate setting and still buys the whole
> unification.** Transactions stay on their entry zone until they fluff, then
> leave by the existing rule. The special case dies either way.
>
> Worth stating explicitly, because *"bridge both directions"* reads as
> requiring a nonzero second probability and it does not. Whether stem-phase
> divert-*out* is worth turning on is a **separate and smaller** question, which
> this round can answer on its own evidence rather than as a precondition.

### Q12-D3b — Symmetric mechanism, asymmetric parameters

`p_in` and `p_out` share a mechanism and share nothing else. **They must not be
set equal for symmetry's sake**, and the round should derive them against
separate objectives:

- **`p_in`** is sized for **dilution** — swamping the origin signal on the
  anonymity zone. Clearnet relay volume dwarfs anonymity volume, so R-1's 2 %
  is a *large absolute inflow into a small zone*, which is precisely what makes
  that zone's traffic mixed (§59, §60).
- **`p_out`** is sized for whatever this round decides it is for, if anything.
  The reverse at 2 % is a **negligible outflow** — the same numeral doing an
  entirely different amount of work.

### Q12-D3c — The latency is already priced

A relay on the anonymity zone costs onion-rendezvous latency against clearnet's
direct hop, and **that is exactly what the per-zone `hop` now carries**: 1750 ms
interim against 175 ms (§89.2, and the banner at
`ANON_ZONE_TRANSIT_ASSUMPTION_MS`).

So the unification **adds no new cost axis**. It makes zone selection the thing
that *reads* the existing one — which is why the mechanism can be symmetric
while the prices are not.

### Q12-D4 — `p` cancels. The privacy requirement is the EQUALITY, not the value. RULED.

**The parameter looked hard because it was being derived while holding the
inherited rule that *all* originated traffic goes to the anonymity zone.** Drop
that and it falls out.

Let a node originate at rate `A`. Its stem-phase relay rate is `A/q`: each
transaction traverses `1/q` stem nodes, so network-wide stem-forwards are
`tx_rate/q`, and per node that is `1/q ×` what it originates.

**Current rule** (`p_own = 1`, `p_relay = p`):

```text
precision_anon = A / (A + p·A/q) = q / (q + p)
```

**Unified rule** (the same probability applied to both classes at entry):

```text
precision_anon = p·A / (p·A + p·A/q) = 1 / (1 + 1/q) = q / (1 + q)
```

**`p` cancels.** Computed at `q = 0.2`:

| `p` | current rule | unified rule |
| --- | --- | --- |
| 0.02 (shipped) | **0.9091** | 0.1667 |
| 0.05 | 0.8000 | 0.1667 |
| 0.20 | 0.5000 | 0.1667 |
| 1.00 | 0.1667 | 0.1667 |

`q/(1+q) = 0.1667` is exactly the floor a clearnet-only node already has
(`A/(A + A/q)`). **So the unified rule gives every zone the network's own mix,
for any `p`.**

> **The current configuration is the worst point in the family.** `p_own = 1`
> with `p_relay = 0.02` is *maximal* sorting — 0.909 — and no achievable `p`
> repairs it, because parity under the current rule requires `p = 1`, which is
> the unified rule arrived at by exhaustion.

**Consequences:**

- **Zone selection stops carrying origin information at all.** There is nothing
  left to tune for privacy, so `p` is a **deployment** parameter, not a privacy
  one.
- **It holds per node, at any origination ratio.** A heavy originator still has
  a poor floor — that is C1, inherent — but the zone choice no longer *makes it
  worse*.

> **Say what this is precisely, because the obvious phrasing overclaims.**
> `q/(1+q) = 0.1667` **is** the C1 floor — the same floor clearnet already has,
> the same one §6.9 concedes as irreducible. So **zone selection stops being a
> sorting axis; it does not become a protection.** Both zones now sit *at* the
> floor instead of one sitting above it.
>
> An earlier draft of this section called it *"removed rather than covered"*.
> That reads as a leak closing, and a reviewer who checks finds 0.1667 is
> exactly where clearnet already was. The floor is still covered by nothing —
> because nothing can cover it.

> **The stronger claim is available, and it is about the mechanism rather than
> a number: `p` cancels, so the parameter cannot be set wrong.**
>
> Every other axis this arc made safe was made safe by **provisioning at a
> quantile** — hardware (§78), shape (§80), depth (§82) — and each one needs a
> *value* that a later reviewer could re-derive against typical rather than
> worst case. §81.4 names why that is dangerous: too low is an error with a
> feedback channel, **too high is one nothing reports**.
>
> This axis has no value to get wrong. There is nothing here for a
> well-intentioned reviewer with a benchmark to propose changing, so §81.4's
> asymmetry has no purchase — **the first axis in the arc where that trap does
> not exist**, and it does not exist structurally rather than by being guarded.
- This **dissolves Q12-Q4 and Q12-Q5**: there is no anonymity-set size to
  derive `p` against, so `λ`/`N` are not needed for it and "is 2+ the right
  target" has no target left to grade.

**`p` as a deployment choice, freed from the privacy constraint:**

| setting | meaning |
| --- | --- |
| `p = 1` | Tor-only. Best against a network observer — no IP-to-transaction link at all — highest latency, requires the anon zone for all relay. |
| `p = 0` | clearnet-only, for nodes with no anon zone. |
| intermediate | splits the node's traffic; **both streams carry the correct mix**. |

For a node that runs an anonymity zone at all, **`p = 1` is the natural
default**: the operator configured Tor to avoid IP exposure, and any traffic on
clearnet exposes their IP at the floor. Intermediate values buy latency at the
cost of some IP exposure — a real trade, and **the operator's own rather than a
stranger's**, which is what makes it a configuration rather than a protocol
constant.

### Q12-D4a — Two checks owed before Q12-D4 is ratified

**1. Pin which population the entry roll applies to.**
The `1/q` relay-rate ratio assumes the **stem-phase** population. Verified at
source for the current code — the roll is gated on `still_stemming`
(`net_node.inl`), which is §60's *"pre-fluff traffic only"*. If the divert were
ever applied to *all* relayed traffic, `r_relay` is far larger and **the
cancellation still holds** (it is ratio-preserving either way) — but the zone
**volumes** differ by orders of magnitude.

> That is §60.4's error in a new place: *"2 % of relayed transactions"* and
> *"2 % of pre-fluff forwards"* look alike and differ by ~1000×. The
> cancellation surviving is exactly what would let the volume mistake pass
> unnoticed, so the population is **pinned**, not inferred.

**2. Price `p = 1`'s throughput cost — this is the check that can still move the
design.**
It makes the anonymity zone the node's **only** relay path, so that zone's
capacity and latency become the node's throughput — against per-zone `hop`'s
1750 ms interim versus clearnet's 175 ms. **Priced, not assumed acceptable**,
before `p = 1` is recommended as a default.

> **And if the zone cannot carry the volume, the natural response is an
> intermediate `p` — which is not free, though Q12-D4 invites reading it that
> way.** An intermediate `p` splits the node's traffic across two zones. The
> cancellation **survives** that, since each stream carries the correct mix; the
> equality is unaffected.
>
> But the node's IP then appears on clearnet for `1 − p` of its traffic, which
> is **exactly the exposure the operator ran Tor to avoid**.
>
> So state it in both halves: **`p` is privacy-neutral *between zones*, and not
> privacy-neutral *for the operator*.** Calling it "a deployment parameter"
> invites reading it as costless. It is not — its cost simply lands on the
> operator who sets it rather than on the strangers whose transactions they
> relay, which is what makes it a configuration rather than a protocol
> constant.

---

## 4. Open design questions

> **Q12-Q8 is the round's first question. Everything else falls out of it.**
> The numbering records the order the questions were *raised*, not the order
> they are *answered* — Q12-Q8 was added when Q12-D1 rescoped the round, and
> renumbering registered identifiers to flatter the reading order would be
> worse than a note.

**Q12-Q8 — ~~Where does the clearnet bridge happen~~, and does it need a delay?
— HALF ANSWERED by Q12-D3a**

**The "where" is settled and needed no new mechanism:** the bridge is the
existing `tx_relay` exit at the **fluff boundary**, verified at source. A
fluffed transaction has `still_stemming == false`, so it bypasses coherence and
reaches clearnet regardless of origin; a peer receiving an anonymity fluff
classes it `fluff` and relays it publicly on its next hop. Tor→clearnet
bridging runs through that today.

**What remains open is only whether a delay is wanted there**, and — separately
— whether stem-phase divert-*out* (`p_out > 0`) is worth turning on at all.
Q12-D3a makes `p_out = 0` a legitimate setting that still buys the whole
unification, so this is a smaller question than it was when it opened, and it
is answerable on its own evidence rather than as a precondition for anything
else.

> **The delay's OBJECTIVE changes under this question, and it should be settled
> before anyone derives against the old one.**
>
> *Today:* one bridger holds the transaction, and the delay makes *"2+ incoming
> connections could have sent it"* plausible. An anonymity-set argument about
> **one node's uncertainty**.
>
> *After the field:* an anonymity fluff reaches many peers and each can bridge.
> With **no** delay, first-to-clearnet is decided by network latency — which
> leaks the fluff source's neighbourhood. That is a **topology** leak, not a
> timing one, and it is a different failure than the one the current delay
> defends against. With a delay at each candidate, first-to-clearnet becomes a
> race among independent draws, decoupled from topology.
>
> **So the objective becomes: decouple the first bridger from network
> distance.** The sufficient condition is a delay spread large relative to
> *inter-node latency spread* — plausibly **hundreds of milliseconds, not tens
> of seconds**, because it only has to dominate propagation jitter rather than
> manufacture an anonymity set single-handedly.
>
> **This disposes of Q12-Q5 favourably.** "2+ connections" being one bit stops
> being the target at all, because the set is now the **fluff reach** rather
> than one node's inbound.
>
> **And it sharpens Q12-D1a.** That section says the structure improves; the
> stronger statement is that the **requirement weakens** — a race among many
> needs less randomisation than a single node manufacturing plausibility alone.
> A derivation against the old objective would therefore over-provision by
> roughly two orders of magnitude, which is the concrete cost of Q12-D1's
> rejected option.

**Q12-Q1 — Where does the origin zone live, and how wide?**
§65.4 scoped two reserved bits on `txpool_tx_meta_t` with `zone::invalid == 0`
as the migration-free default, which the epee enum still fits
(`invalid=0 … tor=3`). Reinstate verbatim, or has anything since consumed
`bf_padding`? Rule 42 was verified inapplicable at §89.2 (its globs are
`rust/shekyl-engine-{state,file}/**`); re-verify at pre-flight rather than
inherit.

**Q12-Q2 — ~~What does the pool loop do with it?~~ DISSOLVED by Q12-D3**
There is no special case left to give a rule to: an unusable zone is simply not
selectable, like an unavailable peer, and no failure reason is consulted. The
fail-closed hazard below is **retained as the reason the question was dangerous**,
not as an open item — it is what a provenance-inheriting design would have had
to get right, and Q12-D3 removes the need to.

*Superseded text follows.*

Route `forward` entries back to their origin zone instead of `public_`. Open:
what happens when the origin zone is no longer usable? §59.7's fail-closed rule
governs *originated* traffic (§30.5 — never fall out to clearnet). Relayed
traffic's home was always clearnet. **An anonymity-arrived transaction is
neither**, and this round must say which rule it inherits.

> **Flagged for early answer, not because it is hard but because it is the one
> with a fail-closed hazard.** The two candidate rules differ in exactly the
> direction that matters: originated **fails closed**, relayed **falls through
> to clearnet**. Inheriting the wrong one silently sends anonymity-arrived
> traffic public — which is the precise defect the field exists to fix, so the
> round would ship its own subject as a bug.
>
> It also fails quietly: the transaction propagates, nothing errors, and the
> only symptom is that a class of traffic is on the wrong network. Answer it
> at design time, where the two rules can be compared, rather than at
> implementation time where whichever branch is written first becomes the
> default.

**Q12-Q3 — ~~Does `forward` survive as a class?~~ ANSWERED by Q12-D3: no**
It is deleted. The class exists only to mean *"arrived somewhere other than
clearnet"* — provenance — and Q12-D3 makes provenance stop being a routing
input. Q-12 therefore closes by the **deletion** branch of Q12-D1's table for
the class itself; what remains open is only whether a delay is wanted at the
bridge (Q12-Q8), which is a different question about a different site.

*Superseded text follows.*

If anonymity-arrived traffic stays in-zone, `forward` no longer means "about to
bridge". Either the class narrows to genuine bridging, or the bridge becomes
explicit and `forward` is retired. This decides whether Q-12 derives a delay
for a *smaller* population or for a *different* one.

**Q12-Q4 — ~~What are `λ` and `N`?~~ DISSOLVED by Q12-D4**
They were needed to derive `p` against an anonymity-set size. `p` cancels, so
there is no set size to size it against and neither input is required for it.
(If a delay is later wanted at the bridge — Q12-Q8 — that is a different
quantity against a different objective, and would need its own grounding.)

*Superseded text follows.*

The natural derivation: with `N` incoming anonymity connections each delivering
at rate `λ`, the expected number of **distinct** connections with an arrival in
a window `D` is `N(1 − e^(−λD))`; solve for `D` at the target set size. Both
inputs are needed and neither is currently pinned. `N` may follow from the
outbound floor work (F-8b, `shekyl_relay_zone_min_provisioned_out_peers`), but
**inbound is not outbound** and that substitution must be argued, not assumed.

**Q12-Q5 — ~~Is "2+" the right target?~~ DISSOLVED by Q12-D4**
There is no target left to grade. The privacy requirement is the **equality**
`p_own = p_relay`, not a value, and it is met by construction for any `p`. The
question was well-posed and its answer is that the objective it interrogated
stopped existing.

*Superseded text follows.*

The inherited objective is *"2+ incoming connections could have sent the tx"*.
An anonymity set of two is one bit. Before deriving a mean that satisfies it,
this round should say whether the objective itself is adequate — deriving
precisely against a weak target is how a number acquires unearned authority.

**Q12-Q6 — Which mean, and measured how? — NARROWED, the family half is landed**
The family half is **done and no longer part of this round**: the forward delay
draws memoryless at the unchanged 22 s, and `crypto::random_poisson_duration`
is deleted with its header. Measured on F-4's own instrument — **2.38×**
phase-averaged (2.01× at phase 0, the floor), and the inherited draw reaching
**0.9184** at its worst supported arrival phase against a flat 0.1248, which
reproduces F-4's *"up to 93 % invertible late in the window"* independently on
this delay's parameters.

**What remains is the mean alone**, and it is downstream of Q12-Q8 rather than
of measurement technique: if the objective becomes *decouple the first bridger
from network distance*, the quantity to derive is a delay spread against
inter-node latency spread, not an anonymity-set size. The 22 s carried forward
is the inherited value held constant so the family could move without moving
two things at once — **not** a derived answer, and not evidence for itself.

**Q12-Q7 — Does `FORWARD_DELAY_BASE` die?**
Only if the round concludes `AVERAGE` alone is the parameter (§22.2's own
condition).

---

## 5. Split out, and not in scope

### 5.1 SPLIT OUT — the Poisson primitive dies in every branch

**Deliverable 3 does not wait for the fork, because no branch keeps it.**

- If `forward` is deleted, the call site goes with it.
- If `forward` survives, F-2/F-4 already settled that the family must be
  memoryless, so the draw is not Poisson either.

`crypto::random_poisson_subseconds` is **already caller-free**, so the whole
`random_poisson_duration` template sits **one call site** from deletion
regardless of how Q12-Q8 resolves.

> That is certain **now**, so it is scheduled as its own change rather than
> carried as a rider on a round that may take a while. A deletion whose
> justification is already complete should not inherit an open round's latency.

**Delivered by PR #431** (`fix/forward-delay-memoryless`) — and rescoped on the
way, because "deletion" was the wrong frame. The call site cannot be deleted
without either deleting `forward` (this round's fork) or having a replacement,
so as a deletion it was *not* independent. As **F-4's move one call site later
— fix the family at the unchanged mean** — it is independent, because the mean
is Q-12's and the family was settled by F-2/F-4.

That also makes it a **fix rather than a cleanup**: the Poisson was live on the
tor→clearnet bridge, the one boundary where arrival-time inference pays most.
`duration.h` is deleted in full, since it held nothing but the template and its
two aliases.

**This round keeps the mean** (Q12-Q6), which is downstream of Q12-Q8.

`CRYPTONOTE_FORWARD_DELAY_BASE` is **not** split out and stays pending
correctly: its fate is the same question as `forward`'s (Q12-Q3, Q12-Q7).

### 5.2 Not in scope

- **The coherence end-to-end witness.** Still blocked on a `t_core` mock the
  unit suite lacks (§89.7). The tripwire landed in #427 pins the gap in its
  current state and **fails when this round closes it** — which is the intended
  interlock, not an accident.
- **§64.1's eligibility decision** (R-1's `p`). Separate round; its banner is in
  `params.rs`.
- **The rendezvous `hop` measurement.** §89.8.2 records the anon-zone hop as
  inert because its premise is not shipped. This round makes the premise true;
  the measurement follows it and is not part of it.

---

## 6. Round structure

**The round is Q12-U1.** The rest are its consequences, and two of them may
turn out to be empty.

| unit | subject | gates on | may be empty? |
| --- | --- | --- | --- |
| **Q12-U1** | one entry rule both directions: `p_in`/`p_out` selection, coherence, per-zone `hop` as the price | Q12-Q1, Q12-D3 | no — this is the round |
| **Q12-U2** | delete `relay_method::forward` and the fall-through branch | — (answered by Q12-D3) | no — mechanical, once Q12-U1 lands |
| **Q12-U3** | ~~derive `p`~~ — **enforce `p_own = p_relay`**, and pick `p` as a deployment default | Q12-D4a's two checks | **no derivation** — the equality is the requirement |
| **Q12-U4** | `FORWARD_DELAY_*`'s disposition | Q12-Q7 | **likely empty** — the constants die with the class |

The Poisson primitive's retirement is **not** a unit here; it is split out per
§5.1 and proceeds independently.

**Q12-D3 collapsed the middle of this round.** Q12-U2 stopped being a decision
and became mechanical, and Q12-U3's subject narrowed from "derive a bridge
delay" to "derive `p_in` for dilution, and decide whether `p_out` is nonzero at
all". The units that remain are smaller and fewer than when the round opened,
which is what a unifying rule is supposed to do.
