# Q-12 — the forward delay, and the txpool origin-zone field

**Design round, opened 2026-08-10.** Scoped per
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
multi-round, FFI boundary, persisted-layout change. Cited explicitly, as that
rule requires.

**Status: DESIGN, nothing implemented.** Every numeric claim below is subject to
verification at pre-flight (rule 26's B6/B9). Where a number is inherited rather
than derived, it says so.

---

## 1. Charter

Q-12 was registered at §22.2 of [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md)
and has been live — not deferred — since its reopen criterion (a) fired at
Q-11 Unit 0. It owes three things:

1. **Derive the mean** from the stated anonymity-set objective.
2. **Fix the family** from measurement — the draw is Poisson where the
   derivation wants memoryless (the F-2/F-4 signature).
3. **Retire the last `random_poisson_seconds` caller**, and the primitive with it.

§89.8.7 added a fourth, and made it the opening unit rather than a rider:

4. **The txpool origin-zone field** — without it, coherence cannot work at all,
   and `forward`'s population is not what the anonymity-set objective assumes.

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

### Q12-D1 — Derive against the post-zone-field population. RULED.

The anonymity-set objective is a claim about *who could have sent this*, which
is a claim about the population of `forward` traffic. That population is about
to change.

**Rejected:** deriving against today's bridge, where every anonymity arrival
crosses to clearnet. It is derivable immediately and wrong the day the field
lands — and this arc has already paid for a constant derived against a posture
that then moved (§63.2's margin, retired at §89.1 as an artifact of the
diffusing posture).

**Consequence, accepted:** Q-12's derivation cannot start until the zone
field's shape is settled. That makes the field the round's **opening unit**,
not its second half.

**Reopening criteria:** if the zone field is abandoned or deferred past this
round, Q12-D1 reopens and the derivation proceeds against the bridge population
with an explicit banner saying so.

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

## 5. Not in scope

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

| unit | subject | gates on |
| --- | --- | --- |
| **Q12-U1** | the origin-zone field + pool-loop routing | Q12-Q1, Q12-Q2 |
| **Q12-U2** | `forward`'s class definition after Q12-U1 | Q12-Q3 |
| **Q12-U3** | the derivation: objective, `λ`/`N`, mean | Q12-Q4, Q12-Q5 |
| **Q12-U4** | the family fix and the primitive's retirement | Q12-Q6, Q12-Q7 |

Q12-U1 is the opening unit by Q12-D1. Q12-U3 cannot start before Q12-U2 settles, because a
derivation needs its population defined.
