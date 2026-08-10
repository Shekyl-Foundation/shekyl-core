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

---

## 4. Open design questions

> **Q12-Q8 is the round's first question. Everything else falls out of it.**
> The numbering records the order the questions were *raised*, not the order
> they are *answered* — Q12-Q8 was added when Q12-D1 rescoped the round, and
> renumbering registered identifiers to flatter the reading order would be
> worse than a note.

**Q12-Q8 — After anonymity-arrived traffic stays in-zone, where does the
clearnet bridge happen, and does it need a delay?**
The round's opening question, and the one the rest are downstream of. The
bridge does not disappear — it moves to whichever peer receives an anonymity
fluff and relays it publicly under R-1's exit rule. Answering it settles
whether `forward` survives (Q12-Q3), what Q-12 derives if anything
(Q12-Q4, Q12-Q5), and whether `FORWARD_DELAY_*` dies (Q12-Q7).

**Q12-Q1 — Where does the origin zone live, and how wide?**
§65.4 scoped two reserved bits on `txpool_tx_meta_t` with `zone::invalid == 0`
as the migration-free default, which the epee enum still fits
(`invalid=0 … tor=3`). Reinstate verbatim, or has anything since consumed
`bf_padding`? Rule 42 was verified inapplicable at §89.2 (its globs are
`rust/shekyl-engine-{state,file}/**`); re-verify at pre-flight rather than
inherit.

**Q12-Q2 — What does the pool loop do with it?**
Route `forward` entries back to their origin zone instead of `public_`. Open:
what happens when the origin zone is no longer usable? §59.7's fail-closed rule
governs *originated* traffic (§30.5 — never fall out to clearnet). Relayed
traffic's home was always clearnet. **An anonymity-arrived transaction is
neither**, and this round must say which rule it inherits.

**Q12-Q3 — Does `forward` survive as a class?**
If anonymity-arrived traffic stays in-zone, `forward` no longer means "about to
bridge". Either the class narrows to genuine bridging, or the bridge becomes
explicit and `forward` is retired. This decides whether Q-12 derives a delay
for a *smaller* population or for a *different* one.

**Q12-Q4 — What are `λ` and `N`, and how are they grounded?**
The natural derivation: with `N` incoming anonymity connections each delivering
at rate `λ`, the expected number of **distinct** connections with an arrival in
a window `D` is `N(1 − e^(−λD))`; solve for `D` at the target set size. Both
inputs are needed and neither is currently pinned. `N` may follow from the
outbound floor work (F-8b, `shekyl_relay_zone_min_provisioned_out_peers`), but
**inbound is not outbound** and that substitution must be argued, not assumed.

**Q12-Q5 — Is "2+" the right target?**
The inherited objective is *"2+ incoming connections could have sent the tx"*.
An anonymity set of two is one bit. Before deriving a mean that satisfies it,
this round should say whether the objective itself is adequate — deriving
precisely against a weak target is how a number acquires unearned authority.

**Q12-Q6 — Which memoryless mean, and measured how?**
The family fix is not merely swapping the draw: a Poisson at mean 22 s and an
exponential at mean 22 s have different tails, and the objective is a
tail property. The F-4 instrument (inversion 0.4236 → 0.2165) applies directly
and is the measurement path.

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
| **Q12-U1** | the origin-zone field, pool-loop routing, and where the bridge lands | Q12-Q8, Q12-Q1, Q12-Q2 | no — this is the round |
| **Q12-U2** | `forward`'s disposition: survives, narrows, or is deleted | Q12-Q3 | no, but its answer may be "deleted" |
| **Q12-U3** | a derivation, **if there is a subject for one** | Q12-Q4, Q12-Q5 | **yes** — empty if `forward` is deleted |
| **Q12-U4** | `FORWARD_DELAY_*`'s disposition | Q12-Q7 | **yes** — empty if the constants die with the class |

The Poisson primitive's retirement is **not** a unit here; it is split out per
§5.1 and proceeds independently.

Q12-U3 cannot start before Q12-U2 settles — a derivation needs its population
defined, and per Q12-D1 it may have none.
