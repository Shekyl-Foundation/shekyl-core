# Daemon Relay Privacy — correcting and porting the Dandelion++ timing layer

**Status:** ROUND 3 dispositioned — clean break. The measurement that motivates
this document landed alongside it in the same PR (`rust/shekyl-relay-privacy`, 19
measurement tests + the suite), so every number below is reproducible rather than
asserted. **Round 3 outcome:** reshape is adopted unconditionally as a strict
priority-order improvement (§14); the embargo derivation is held block-time-*unaware*
by construction, with the block-time boundary reconciled at the integration layer
(§15); the W3 residual is measured as `W3(g)` (§12.6); and **`ρ` is
*underspecified*, blocked on Q-10 — the outbound-selection eclipse bound `g_max`**,
which is a **p2p-subsystem** grounding (anchors, white/gray discipline, IP-group
diversity, churn resistance), not a relay-timing one (§7, §13.5). The seal is in the
open where the p2p round owns it. **Scope boundary (§6.9, settled):** this mechanism
defends the *active* adversary (must misbehave or actively position); the *passive,
correctly-behaving* observer is explicitly **not defended** — a known limitation
shared with Dandelion++ and Tor, closable only by p2p redesign (mixnet / cover
traffic / cryptographic sender-anonymity), deliberately out of scope. §6.10 records
the one thing that reaches it: an *economic* deterrent (behaviour-floor + pinning
taxes the observer into being infrastructure, un-budgetable for most covert
institutional adversaries) — effective-population, not theoretical; economics, not
protocol; carve-outs (unconstrained tier, overt participant) intact. Rounds 1–2 raised
findings RD-1…RD-4; **all are accepted and dispositioned in §10**, and their
consequences are folded into the body rather than appended as errata.
RD-1 moved the adopted embargo (31 s → 112 s) and surfaced a fifth defect
(F-5); RD-4 then corrected a stem-length error in the model that both this
crate and the review shared, moving it again to **144 s** (§10.5). Its
follow-on built the preemption-profile and black-hole instruments, inverted the
drafted Q-8 premise, and established that the embargo *mean does not defend the
binding channel* (§10.4, §10.6). RD-2 resolved Q-2. A later pass anchored the *adversary's position* at source
(§6): the origin is the submitting daemon, the wallet↔daemon boundary is out of
scope, and fluff visibility is transport-gated — which makes the passive
adversary **clearnet-only** and the black-hole adversary transport-independent
(§10.8). §6.5 then *quantifies* the Tor benefit — the paper's supernode observer
collapses from π₀≈0.45 (clearnet, 30 % attack) to 0.000 (Tor) — so the Tor
recommendation rests on a measurement, not on reasoning. §11 anchors every finding against the Dandelion++ paper and the Bitcoin
Core source. Decisions D-1…D-7 stand as amended; §7 is the Round-3 agenda.
**Process rule:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(FFI-boundary-moving), and
[`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
§"Migration is a planning activity" — this document exists so the port is not
folded into feature work.
**Spec-first per** [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc).
**Timeframes (rule 05):** *now* — the relay layer is the only privacy
mechanism protecting transaction origin at the network layer, and three of its
four randomized quantities are mis-specified; *mining-era end* — nothing here
carries reward-era assumptions, the parameters are network-topology-driven;
*V4 lattice-only* — relay timing is cryptography-agnostic and survives any
membership-proof successor untouched.

**Not consensus.** Every quantity in this document is node-local relay policy.
Nodes running different delays do not fork, no rule reads these values, and
none of this is genesis-blocking. It is being fixed before ship because it is
*wrong*, not because a deadline forces it.

---

## 0. Problem statement (verified at source and by measurement)

Shekyl inherits a complete Dandelion++ implementation from the Monero
lineage: the stem map in `src/net/dandelionpp.cpp` (**deleted at RP-3a** — see
§16; `dandelionpp.cpp:NNN` citations throughout this document are historical and
resolve against git history, `git log --follow -- src/net/dandelionpp.cpp`),
the epoch/stem/fluff orchestration in
[`src/cryptonote_protocol/levin_notify.cpp`](../../src/cryptonote_protocol/levin_notify.cpp),
and the stem embargo in
[`src/cryptonote_core/tx_pool.cpp`](../../src/cryptonote_core/tx_pool.cpp).
The routing is sound. The *timing* — which is the entire privacy mechanism —
is not, and was never tested.

**The test surface is empty.** `tests/unit_tests/levin.cpp` has 33
`levin_notify` cases. Every one drives the relay path through `run_epoch()`,
`run_stems()` or `run_fluff()`, each of which **cancels the pending timer** to
force immediate execution. The suite verifies who receives what with which
fluff flag. Not one case observes a delay. There is no test, anywhere in the
tree, of any randomized quantity in the relay layer.

Four defects, each verified against source and measured:

| # | Defect | Site | Severity |
| --- | --- | --- | --- |
| **F-1** | The embargo constant does not follow from its own stated derivation | [`tx_pool.cpp:66-87`](../../src/cryptonote_core/tx_pool.cpp#L66-L87) | Medium — wrong value |
| **F-2** | The embargo is drawn from a Poisson; its derivation assumes an exponential. At these means the timer is near-deterministic and effectively never fires | [`tx_pool.cpp:1031`](../../src/cryptonote_core/tx_pool.cpp#L1031), [`duration.h`](../../src/crypto/duration.h) | **High — mechanism absent** |
| **F-3** | The closed form substitutes `E[K]` into an expression in `K(K-1)`; stem length is geometric, so it under-provisions at every fluff probability | [`tx_pool.cpp:66-87`](../../src/cryptonote_core/tx_pool.cpp#L66-L87) | Medium — no constant correction fixes it |
| **F-4** | The **fluff delay** has the same distribution defect as F-2, on the timer every node applies to every transaction | [`levin_notify.cpp:75-90`](../../src/cryptonote_protocol/levin_notify.cpp#L75-L90), [`:439-440`](../../src/cryptonote_protocol/levin_notify.cpp#L439-L440) | **High — mechanism degraded** |
| **F-5** | Because of F-4, the fluff flood itself is ~7× slower than it needs to be — first passage to an arbitrary node takes ~13.75 s (p90) instead of ~2.25 s. A throughput consequence of the same defect, and it feeds back into the embargo derivation | same as F-4 | **High — network-wide latency** |

Two further observations that are not defects but are undocumented choices
the design round must make deliberately (§7): timer **granularity** (O-1) and
the **hop-latency** input the whole derivation rests on (O-2).

**Round 1 correction to the model itself.** The survival equation as first
written ended a stem node's exposure when the terminal node *emitted* the
fluff. The mechanism ends it when that fluff *reaches* the node. See
RD-1 (§10.1) — it
is the largest single correction in this document and it changed the adopted
embargo by a factor of 3.6.

### F-1 — the constant contradicts its own comment

`tx_pool.cpp:66-87` states the derivation inputs and the answer:

> This value was calculated with k=5, ep=0.10, and hop = 175 ms. […] So 175ms
> is the fudge factor for a single hop with 39s being the embargo timer.

Under the Dandelion++ appendix B.5 formula
`Tbase = (-k·(k-1)·hop) / (2·ln(1-ep))`, those inputs give **16.61 s**, not 39.
The 39 s figure is reproduced by substituting a **base-10 logarithm** for the
natural logarithm the formula specifies: that gives 38.245 s, and exactly 39 at
`hop = 178 ms`. The counter-check is executable —
`params::reconciles_under_log10`, asserted in
`params::tests::log10_substitution_reproduces_the_inherited_constant`.

### F-2 — the distribution family is wrong, and it disables the mechanism

The `ln(1-ep)` term is the signature of an **exponential survival function**.
The derivation models each node arming a memoryless timer and asks how likely
it is that none fires early. The daemon draws from
`crypto::random_poisson_seconds` — `std::poisson_distribution`, a discrete
*count*, whose standard deviation is `√λ`. At λ = 39 the coefficient of
variation is 0.16; the timer is very nearly a constant.

Measured (`tests/propagation_measurement.rs`, 200k trials, q=20%, hop=175 ms):

```text
parameter set                 embargo      hops     mean fluff      p99 fluff   full-travel    preempted
shipped: 39s Poisson              39s      3.99          699ms         3500ms        1.0000       0.0000
constant fixed: 17s Poisson       17s      3.99          699ms         3500ms        1.0000       0.0000
as derived: 17s memoryless        17s      3.99          699ms         3500ms        0.8474       0.1526
```

Both Poisson rows sit at full-travel 1.0000 — **the black-hole backstop never
fires**, against a stem that completes in 699 ms mean / 3.5 s p99. The embargo
is a formality, not a mechanism.

Note the second row: **correcting F-1 alone changes nothing measurable.** A
Poisson at 17 s has exactly the defect a Poisson at 39 s has. Fixing the
constant without fixing the distribution would have been wasted work that
looked like a fix.

There is a second consequence beyond the missing backstop. A low-variance
timer means that *when* the embargo does fire, it fires at a predictable
offset from broadcast — so an embargo-released fluff is distinguishable from a
natural one and timestamps the original broadcast. A memoryless timer does not
carry that signal.

### F-3 — the closed form under-provisions, and no constant factor fixes it

The formula substitutes the *expected* stem length `k` into an expression in
`k(k-1)`. Stem length is not fixed; it is geometric. For geometric `K`,

```text
E[K(K-1)] = 2 · E[K] · (E[K] - 1)     exactly, at every fluff probability
```

so the closed form is solving for the wrong quantity by a factor of two —
*before* Jensen's inequality is reached, since the quantity actually wanted is
`E[exp(-c·K(K-1))]` and not `exp(-c·E[K(K-1)])`. Neither substitution is the
answer, and no constant correction factor recovers it.

`derive::tests::the_closed_form_under_provisions_at_every_fluff_probability`
pins this across `q ∈ 1..=50%`.

### F-4 — the same defect on the timer that runs on every transaction

`levin_notify.cpp:84-88` names its reference:

> Bitcoin Core is using 1/2 average seconds for outgoing connections compared
> to incoming.

Bitcoin Core's send timer, `PoissonNextSend`, computes `-ln(U)·mean` — the
**inter-arrival time of a Poisson process**, which is an *exponential*. The
inherited code implements `std::poisson_distribution`, which is the discrete
*count* of a Poisson process. The names coincide; the distributions do not.

This matters more than F-2. The embargo is a rare backstop; the fluff delay is
applied by every node to every transaction, and its entire purpose is to stop
an observer inferring *when a node received a transaction* from *when it
relayed it*.

Measured (`fluff_delay_inference_resistance`) — probability that an adversary
subtracting a fixed optimal offset pins receipt time to within a tolerance:

```text
delay draw                              CV       ±0.25s        ±0.5s          ±1s
inherited: Poisson lambda=20         0.224       0.2623       0.4236       0.6867
memoryless: geometric mean=20        1.025       0.1362       0.2165       0.3554
```

Same 5 s mean; the inherited draw is ~1.96× more invertible at every tolerance
an adversary might pick. A delay with CV 0.22 is not providing randomized
delay — it is providing a constant with a rounding error.

---

## 1. Decision record (as amended by Round 1)

| # | Decision | Rests on |
| --- | --- | --- |
| **D-1** | The embargo is drawn from a **discrete memoryless (geometric)** distribution, not a Poisson | F-2 |
| **D-2** | The embargo mean is **solved exactly** from the survival equation, never hard-coded and never taken from the closed form | F-1, F-3 |
| **D-3** | The fluff delay is drawn from the **same memoryless family**, at the inherited means | F-4 |
| **D-4** | Timer granularity is an **explicit input** to the derivation, defaulting to 250 ms | O-1 |
| **D-5** | Hop latency is an **explicit, conservatively-set input** with a testnet-measurement reopening trigger | O-2 |
| **D-6** | Fluff probability `q` stays at **20%**; it is not demonstrably wrong and re-tuning it is out of scope | §7 Q-3 |
| **D-7** | The Rust core owns *when* and *to whom*; C++ keeps *how to serialize and send*. **No async runtime.** | §4 |

### D-1 — memoryless embargo

The geometric distribution is the exact discrete analogue of the exponential
and the only memoryless discrete distribution. The inherited timer already
works in integer time units, so discretizing costs nothing. Implemented in
`geometric.rs` as a frozen integer inverse-CDF, the same construction the
Poisson table uses.

**Two rationales, not one.** The inversion argument (D-3, §10.2) is one. The
second is the paper's own (§5.3.1, §11): memorylessness makes *the first relay
to broadcast approximately uniform* among the relays holding the tx. A
near-deterministic timer makes the first-fluffer predictable by stem position,
which would deanonymize the black-hole recovery the embargo exists to serve —
so the distribution matters for *who* recovers a stalled tx, not only *whether*
the backstop fires.

*Reversion clause — **withdrawn in Round 1** (RD-2).* The clause named a
shifted geometric (a floor plus a memoryless tail) as the replacement, on a
measurement of "mode-at-zero harm". RD-2 established that no such measurement
can exist: a constant floor is a pure shift, and every inversion metric is a
maximum over sliding windows and therefore shift-invariant by construction, so
the alternative could never beat the incumbent on any instrument in the tree.
That is an armed gate with no trigger.

Measuring it properly *settled* the question rather than merely unblocking it,
so the clause is **deleted rather than weakened**. A floor is dominated in both
framings a latency budget allows: as a pure shift it scores identically
(0.2165) and costs 8 ticks of latency for nothing; held to the same mean it
scores measurably **worse** (0.3298 vs 0.2165), because it buys its offset by
narrowing the random part. See §10.2 and
`residual_inversion_decides_the_distribution_shape`.

The surviving reversion condition for D-1 is narrower and honest: revert only
if the memoryless family is shown to break an invariant the *batching* design
depends on — not on inversion grounds, where it has now been tested and holds.

### D-2 — exact derivation, not a constant

`derive.rs` solves the true survival equation:

```text
P(full travel) = Σ_h  (1-q)^h · q · (1-p)^S(h),   S(h) = Σ_{j=0}^{h} ceil(j·hop/τ)
```

by bisection on the mean, which is monotone. Every term is a product of powers
of `(1-q)` and `(1-p)`, computed by running multiplication — **no `exp`, no
`ln`, no `pow`** — so the derivation is bit-identical on every platform.

**Round 1 amended the equation** (RD-1): each stem node's required exposure is
`(j·hop + F)/τ`, not `j·hop/τ`, where `F` is the fluff flood's return time. The
`j = 0` term stays zero — the terminal node disarms its own embargo at the
moment it fluffs. The correction preserves the running-product structure
exactly, so the derivation is still transcendental-free.

At the inherited inputs with the measured return term it yields **112 s**
(446 ticks) — later corrected to **144 s** (576 ticks) by RD-4, which fixed the
stem-length support (§10.5). The independent Monte-Carlo simulator, corrected
identically at each step, tracks within ~3 % and its survival curves agree to
≤0.0010 across both the mean *and* the tick
(`analytic_derivation_agrees_with_the_simulator`).

| source | value |
| --- | --- |
| closed form (paper, plug-in `k`) | 17 s |
| exact derivation, RD-1 uncorrected | 31 s |
| exact derivation, RD-1 corrected | 112 s |
| **exact derivation, RD-1 + RD-4 (adopted)** | **144 s (576 ticks)** |
| simulator cross-check | 147 s |
| inherited `#define` | 39 s |

The 31 s figure was a lower bound, and a loose one: at the measured return term
it delivers 0.7292, not 0.9002.

The inherited 39 s lands near the right answer *by way of a logarithm-base
error rather than this correction*, and is paired with a distribution under
which the timer barely fires. Two wrongs approximately cancelling is not a
derivation, and the near-miss is why this was never caught by inspection.

### D-3 — memoryless fluff delay

Same family as D-1, at the inherited means (λ = 20 quarter-seconds inbound,
10 outbound). The **quarter-second granularity is retained** — its comment at
`levin_notify.cpp:75-80` is the one derivation in this subsystem that survives
checking, and the reasoning (whole seconds too coarse, milliseconds too tight)
is correct.

The outbound/inbound 1:2 ratio is also retained. It is Bitcoin Core's, the
reasoning is sound (a node controls who it connects *to*), and nothing in the
measurement contradicts it.

**Why memoryless specifically — the argument Round 1 required be stated
(RD-2).** It is *not* "geometric inverts worst." It does not: a uniform delay
over `[0, 2μ]` scores better at phase 0 (0.1220 vs 0.2165). Stating the
decision on raw inversion precision alone would leave it open to exactly that
refutation.

The real argument is structural, and it comes from the code path.
`levin_notify.cpp`'s `fluff_notify` draws a flush deadline **only when a peer's
batch is empty**; a transaction arriving mid-window joins the pending batch and
goes out at the already-drawn deadline. What such a transaction experiences is
therefore the **residual** of a draw that has already survived some phase — not
a fresh draw. Only the memoryless family makes the residual distribution
identical to the full one, which is what makes a single headline inversion
number describe *every* transaction rather than only one that happened to
arrive at window start.

Measured (`residual_inversion_decides_the_distribution_shape`), inversion
precision at ±0.5 s against arrival phase in ticks:

| delay draw | phase 0 | 10 | 20 | 30 |
| --- | --- | --- | --- | --- |
| memoryless geometric (mean 20) | 0.2165 | 0.2165 | 0.2165 | 0.2165 |
| inherited Poisson (λ 20) | 0.4236 | 0.4257 | 0.7041 | **0.9318** |
| uniform `U[0,40]` (mean 20) | **0.1220** | 0.1613 | 0.2381 | 0.4545 |

Uniform's advantage is real at phase 0 and gone by phase 20. Only the
memoryless row is flat. This also sharpens F-4: the inherited Poisson is
**near-perfectly invertible for a transaction arriving late in a window**
(0.9318), which is worse than its phase-0 figure suggested.

### D-4 — granularity is a parameter

The inherited embargo ticks in **whole seconds**, against a stem that
completes in ~700 ms. At that granularity "fires within the first tick"
collapses to "fires at zero", and a measurable share of preemption is rounding
rather than mechanism. Measured convergence (`embargo_tick_granularity_matters`):

```text
tick = 1000ms   full-travel 0.7869
tick =  500ms   full-travel 0.8212
tick =  250ms   full-travel 0.8461
tick =  125ms   full-travel 0.8551
tick =   50ms   full-travel 0.8639
```

250 ms is adopted: it matches the quarter-second precedent already in this
subsystem, and the derivation absorbs the tick, so the choice is about
fidelity rather than correctness — any tick hits the target once solved at
that tick.

### D-5 — hop latency

The entire embargo derivation rests on one input that exists **only inside a
code comment**: `hop = 175 ms`, justified as "a testrun from a recent Intel
laptop took ~80ms […] At least 50ms will be added to the latency if crossing
an ocean." That is a 2019 observation about someone else's network.

The error is asymmetric, and that decides the default. Over-estimating hop
gives a longer embargo: fires less often, slower black-hole recovery.
Under-estimating gives premature fluffing — transactions cut short of their
stem, which is a **privacy loss**. Measured sensitivity
(`embargo_sensitivity_to_hop_latency_assumption`, embargo derived at 175 ms):

```text
actual hop = 175ms   preempted 0.0000
actual hop = 350ms   preempted 0.0009
actual hop = 500ms   preempted 0.0048
actual hop = 1000ms  preempted 0.0428
```

Since the privacy-losing direction is under-estimation, the pre-network
default over-estimates. **Proposed: 350 ms** (2× the inherited assumption).
*Anchored (§11):* the paper measured ~300 ms per added hop on mainnet, so
350 ms is genuinely conservative **for clearnet** — but Shekyl relays over Tor
(SP-T0), whose circuit latency multiplies the per-hop figure, so the reopening
trigger must measure under the real transport, not clearnet. Post-RD-1 this
partly washes out because `F` dominates the hop term.

*Reopening trigger:* the first testnet with representative geography measures
real inter-node relay latency; this input is re-set from that measurement and
the embargo re-derived. Until then 350 ms is a documented placeholder, not a
result.

**Round 1 adds a sibling input (RD-1): the fluff-flood return time `F`.** It
has the same status as hop latency — a topology input, conservatively set from
a high quantile, with the same testnet reopening trigger — and after the RD-1
correction it *dominates* the hop term, so the testnet measurement must capture
fluff-return first passage and not only stem hop latency. It is currently
**2250 ms**, the measured p90 for a memoryless flood at 8 peers
(`simulate_fluff_return`). *Round 1 refinement:* this is the p90 of the
population-*marginal* first passage applied uniformly; `F(j)` actually grows
with stem distance, so it is conservative for near positions and possibly
slightly short for the origin. Negligible at the adopted parameters, but the
Q-5 testnet measurement (and the Q-8 profile work) should measure `F`
conditional on stem distance — see §10.4. Sensitivity, at the 0.90 target:

| `F` | derived embargo |
| --- | --- |
| 0 ms (RD-1 uncorrected) | 31 s |
| 500 ms | 49 s |
| 1500 ms | 85 s |
| **2250 ms (adopted)** | **112 s → 144 s (RD-4)** |
| 4250 ms | 183 s |
| 13750 ms (inherited Poisson flood) | 521 s |

### D-6 — fluff probability stays at 20%

`q = 20%` sits at the permissive end of the paper's own `q ≤ 0.2`
recommendation. It is not demonstrably wrong, and unlike F-1…F-4 there is no
defect to fix. Lowering it lengthens stems (larger anonymity set, higher
broadcast latency, longer embargo — `Tbase` scales with `k(k-1)`); the
trade-off curve is measured in `fluff_probability_trade_curve` and is
available to a later round.

Changing it is a **separate question** from fixing what is incorrect, and
folding it in would make this document's scope unreviewable. *Reopening
trigger:* a threat-model round that quantifies the anonymity-set benefit
against the latency cost for Shekyl's expected topology.

### D-7 — the port seam

Rust decides *when* and *to whom*. C++ keeps *how to serialize and send*:
epee binary serialization, the 1024-byte padding walk, levin framing,
fragmentation and compression. This workspace has no epee or levin
implementation and building one is a separate multi-thousand-line project
(§8).

**No async runtime.** Every type in `schedule.rs` is a plain `&mut self` state
machine returning a deadline in monotonic milliseconds. The daemon's relay
path runs inside a `boost::asio` strand; the Rust core is called from inside
that strand and returns "next deadline", which the existing `steady_timer`
arms. A core that demanded its own reactor would mean reconciling two event
loops for no gain.

---

## 2. What lands where

**RP-1 (landed, this PR).** `rust/shekyl-relay-privacy` — the measurement
instrument and the corrected primitives. Links nothing, replaces nothing,
changes no daemon behaviour.

| module | contents |
| --- | --- |
| `params.rs` | Design inputs; every derived quantity is a method, never a stored field, so a parameter set cannot hold an embargo that disagrees with its own fluff probability |
| `derive.rs` | The exact survival equation and the bisection solve (D-2) |
| `poisson.rs` | Frozen integer inverse-CDF replacing `std::poisson_distribution` |
| `geometric.rs` | The memoryless draw (D-1, D-3) |
| `rng.rs` | `RelayRng` seam; unbiased rejection sampler |
| `stem_map.rs` | Port of `connection_map`, `nil_uuid` sentinel replaced by `Option` in its three distinct roles |
| `schedule.rs` | Epoch / fluff / embargo / noise state machines (D-7) |
| `conformance.rs` | Feature-gated grades, the propagation simulator, the inversion instrument |

**RP-2…RP-4 (not yet scoped — gated on this document converging).** Sketch
only; the sequence is decided in review, not here:

- **RP-2** — FFI + cut `connection_map` over; delete `src/net/dandelionpp.cpp`. *(Done: ported at RP-2a, file deleted at RP-3a.)*
  The `dandelionpp_map` block in `tests/unit_tests/net.cpp` (≈1787–2140) is the
  acceptance gate.
- **RP-3** — cut the epoch/fluff scheduler; `levin_notify.cpp` becomes a
  transport shim. The 33 existing `levin_notify` gtests must pass **unchanged**
  — they exercise the public `notify` API, so they are a free regression oracle
  for the riskiest step.
- **RP-4** — the `tx_pool.cpp` embargo.

---

## 3. Why the distributions are re-implemented rather than bound

`std::poisson_distribution` and `std::uniform_int_distribution` are
**implementation-defined**: the standard fixes the distribution, not the
algorithm. Three consequences shaped RP-1:

1. **No cross-language differential oracle is possible.** libstdc++ and libc++
   emit different sequences from identical entropy, so a port cannot be
   validated by differential replay the way the C++-as-oracle consensus port
   is. That pattern does not transfer here; only a statistical grade is
   available.
2. Two Shekyl nodes built against different standard libraries **already** draw
   different sequences today. Harmless for node-local timing, but it means
   "the C++ behaviour" is not a single well-defined thing to reproduce.
3. The distribution is not a reviewable artifact anywhere in the C++ tree — it
   is whatever the toolchain shipped.

RP-1 makes it one. Both tables are built by recurrences using only `+`, `*`
and `/` — no transcendentals — so they are bit-identical on every platform,
and every draw after construction is integer. The table *is* the distribution:
printable, diffable, and pinned by fingerprint in `tests/golden_vector.rs`.

---

## 4. The FFI surface (RP-2+, sketch)

Everything `levin_notify` reaches outward for is six calls:

```text
p2p.foreach_connection(cb)        → snapshot of (uuid, is_income, remote_height)
p2p.send(blob, uuid)              → bool
p2p.get_out_connections_count()
core->get_current_blockchain_height()
core->is_synchronized()
core->on_transactions_relayed(txs, relay_method)
```

Boost UUIDs are 16 bytes → `ConnectionId([u8; 16])`, a memcpy. For scale
comparison, the existing daemon-submit boundary is 754 lines of C++ shim plus
459 Rust; this one is smaller.

---

## 5. Test obligations

| Gate | Where | Status |
| --- | --- | --- |
| Every distribution graded against its claim | `tests/conformance_grading.rs` | RP-1 ✅ |
| Every grade paired with a **negative control that must fail** | same | RP-1 ✅ |
| Analytic derivation cross-checked against an independent simulator | `analytic_derivation_agrees_with_the_simulator` | RP-1 ✅ |
| Each finding pinned as an executable assertion | `params.rs`, `derive.rs`, `tests/propagation_measurement.rs` | RP-1 ✅ |
| Preemption profile (who preempts) with analytic marginal cross-check | `simulate_preemption_profile`, `marginal_preemption_profile`, `preemption_profile_answers_who_preempts` | Round 1 ✅ |
| Black-hole recovery scales as `M/(j+1)` | `black_hole_recovery_scales_with_holder_count` | Round 1 ✅ |
| Black-hole attribution leak is mean-invariant; passive races are non-leaky | `black_hole_attack_leak_is_mean_invariant` | Round 2 ✅ |
| First-spy diffusion precision π₀ | `first_spy_precision_rises_with_spy_fraction` | Round 2 ✅ |
| Clearnet↔Tor delta: supernode observer collapses on Tor | `tor_collapses_the_supernode_diffusion_observer` | Round 2 (transport) ✅ |
| Clearnet passive channel is real, mean-dependent, zero on Tor | `passive_clearnet_leak_is_mean_dependent_and_zero_on_tor` | Round 3 (ε lever) ✅ |
| ≤0.3% worst-case exposure reachable via reshape, not embargo-lengthening | `origin_exposure_meets_target_via_reshape_not_embargo` | Round 3 (levers) ✅ |
| Origin always stems (unit stem at q=100%) | `always_fluffing_gives_a_unit_stem_the_origin_still_holds` | Round 2 (RD-4) ✅ |
| Frozen reference vectors, cross-architecture | `tests/golden_vector.rs` | RP-1 ✅ |
| 33 `levin_notify` gtests pass unchanged after the cut | `tests/unit_tests/levin.cpp` | RP-3 |
| `dandelionpp_map` gtests pass against the Rust map | `tests/unit_tests/net.cpp` | RP-2 |

The negative controls are not optional. A conformance test that only ever sees
correct input passes whether or not it can detect anything; each grade in RP-1
is run twice, once against the real draw and once against a deliberately
corrupted one that **must** fail.

---

## 6. Adversary position and threat model (anchored at source)

Rounds 1–2 modelled *what a passive adversary can do* across several rounds
before pinning *where that adversary sits in Shekyl's topology* or verifying its
observable exists in code rather than in the paper's abstraction. That was the
wrong order. This section anchors position first, at `file:line`; §10.8 records
the correction and re-scopes the adversary it resized.

### 6.1 Where a transaction becomes a Dandelion++ origin

A wallet-submitted transaction enters this fork's Rust-FFI submit path and is
relayed with `relay_method::local`
([`daemon_submit_ffi.cpp:618`](../../src/rpc/daemon_submit_ffi.cpp#L618): *"relay_method::local
arms the Dandelion++ embargo machinery"*). `local` always stems and is kept out
of the per-epoch fluff coin
([`levin_notify.cpp:560`](../../src/cryptonote_protocol/levin_notify.cpp#L560):
`if (!zone_->fluffing || tx_relay == relay_method::local)`). So **the
Dandelion++ origin is the daemon that accepts the submission**, and it never
self-fluffs by role — the anchored consumer of the C2 retraction (§10.6). The
mechanism protects the origin *daemon's* IP-to-tx link at the P2P layer.

### 6.2 The wallet↔daemon boundary is out of scope, and the code already fought this

**T does not sit between the wallet and the daemon.** The submission FFI is
explicit that the RPC boundary must not leak stem state
([`daemon_submit_ffi.cpp:178-189`](../../src/rpc/daemon_submit_ffi.cpp#L178-L189)):
`in_pool` (internal truth, sees embargoed insertions) is disclosed only to the
owner; `in_pool_broadcast` (post-fluff, carries no embargo secret) to foreign
callers — *"so `POST /submit_transaction` is not a stem-presence oracle."* The
boundary splits into two regimes, **neither of which is this document's job**:

- **Own daemon (the design's assumption):** the wallet↔daemon hop is
  loopback/local. The origin daemon knows its own tx trivially; there is no
  network-layer adversary *there*. The stem mechanism exists to protect that
  daemon's identity from its *peers* onward. Correct scope.
- **Remote/public RPC daemon (light-wallet):** the RPC node *is* the origin and
  learns the submitter's IP from the TCP connection directly. Dandelion++ gives
  that user **nothing** against the RPC node itself — it only obscures the origin
  from downstream peers. That is a real, different threat, and it is the Tor
  transport's job (SP-T0), not the relay-timing channel's. It must not be
  conflated with this mechanism.

### 6.3 The P2P observer, and the constraint that makes it transport-gated

The relay-privacy adversary is a **P2P-network-layer observer of the origin
daemon's peer traffic** — a peer, a set of sybil peers, or a passive network
observer — reached only through the P2P interface, never the RPC one. Its
visibility of a node's *fluff* is gated by transport, at
[`levin_notify.cpp:448-449`](../../src/cryptonote_protocol/levin_notify.cpp#L448-L449):

```text
// When i2p/tor, only fluff to outbound connections
if (source != id && (zone->nzone == public_ || !context.m_is_income))
```

- **Public (clearnet) zone:** `nzone == public_` is true, so a node fluffs to
  **all** peers, inbound and outbound. A spy that opens an *inbound* connection
  to a node — the cheap, unlimited direction; the supernode attack the paper is
  built against — receives that node's fluff with a first-spy timestamp.
- **I2P/Tor zone:** `nzone == public_` is false, so the gate reduces to
  `!context.m_is_income`: fluff goes to **outbound connections only**. A spy
  cannot receive a node's fluff by connecting *in*. Reinforced by the noise/Tor
  path, which *"only send[s] to outgoing connections"*
  ([`levin_notify.cpp:831-832`](../../src/cryptonote_protocol/levin_notify.cpp#L831-L832)).

**This makes an entire adversary class transport-conditional, not universal**
(§10.8): the passive inbound-spy observable is real on clearnet and structurally
absent on the SP-T0 transport, while the active on-path black-hole adversary
(§10.6) needs a stem-*successor* position, which the outbound-only topology does
not prevent and is therefore transport-independent.

### 6.4 Mission framing

Per [`00-mission`](../../.cursor/rules/00-mission.mdc), the binding commitment
is **privacy is the product** — the same guarantees for everyone, never a
setting. F-2 and F-4 are failures of that commitment: the mechanism is
advertised (by its own comments) and structurally present, but measurably not
functioning. That is why this is fixed before ship despite not being consensus
and not genesis-blocking. It is independent of, and complementary to, the
FCMP++ membership privacy that protects on-chain linkage — a transaction can be
perfectly unlinkable on-chain and still have its origin node identified by
timing.

The [`FOLLOWUPS.md`](../FOLLOWUPS.md) §5289 acceptance criteria for claim
broadcast — "a Dandelion++-equivalent stem/fluff phase under the anonymity
network" — depend on this layer being correct, and now on §6.3's transport
gating: a claim broadcast from a Tor origin faces a different (smaller) adversary
than one from a clearnet origin.

### 6.5 The clearnet↔Tor delta, quantified (testing posture)

Tor is **not** frozen as the principal default: a pending decision — embed
[Arti](https://gitlab.torproject.org/tpo/core/arti) vs. drive an external Tor
gateway, and how either is surfaced in the wallet UI/UX — is deliberately not
being taken lightly. So the design cannot lean on "the origin is on Tor." What
it can do is **measure both configurations** and let the recommendation rest on
a number:

- **Clearnet is the weakest allowable configuration** — the floor the mechanism
  must defend, and what a user who declines Tor actually runs.
- **Tor is the likely recommended configuration**, and its additional security
  should be *demonstrable*, not asserted.

`simulate_transport_observation` measures exactly the delta the §6.3 source fact
produces, for the paper's primary adversary — a supernode that opens cheap
*inbound* edges to a fraction of honest nodes and runs the first-spy estimator
(512 nodes, 8 peers, `tor_collapses_the_supernode_diffusion_observer`):

| supernode reach | transport | fluff observed | first-spy π₀ |
| --- | --- | --- | --- |
| dials 5 % | clearnet | 1.0000 | 0.1155 |
| dials 5 % | **Tor/I2P** | **0.0000** | **0.000** |
| dials 10 % | clearnet | 1.0000 | 0.1967 |
| dials 10 % | **Tor/I2P** | **0.0000** | **0.000** |
| dials 30 % | clearnet | 1.0000 | 0.4463 |
| dials 30 % | **Tor/I2P** | **0.0000** | **0.000** |

The delta is stark and structural: a clearnet supernode observes **every** fluff
and attributes the source with the paper's first-spy precision (rising with its
reach to ~0.45 at a 30 % attack); the same supernode over Tor observes
**nothing**, because fluff never traverses its inbound edges
([`levin_notify.cpp:448`](../../src/cryptonote_protocol/levin_notify.cpp#L448)).
That collapse is the measured additional security of the Tor configuration.

**Honest scope of the Tor benefit.** It collapses the *passive*
supernode/diffusion observer — the cheap-inbound adversary the paper is built
against. It does **not** change the *active* black-hole attack, which needs an
on-path stem-*successor* (outbound) position that honest peer selection makes
roughly equiprobable on both transports, and whose leak is mean-invariant
(§10.6). So the story is precise, not "Tor is more private": **Tor eliminates
the cheap inbound supernode; the black-hole channel is unchanged, and remains
the reason the mechanism itself (embargo distribution + Q-8a reshape) must be
correct regardless of transport.**

### 6.6 The clearnet passive channel is real, mean-dependent, and zero on Tor

`simulate_transport_observation` (§6.5) measures the *diffusion-phase* supernode
— what it learns from watching natural fluff. `simulate_passive_neighbor_leak`
measures the *embargo-phase* leak the same inbound supernode gets: when a
stem-prefix node's embargo fires before it is disarmed, a supernode neighbouring
that node catches the early fluff and attributes the source to a prefix member.
Measured (supernode reach φ = 0.10,
`passive_clearnet_leak_is_mean_dependent_and_zero_on_tor`):

| embargo mean | transport | leak rate | origin share of leaks |
| --- | --- | --- | --- |
| 31 s (pre-correction) | clearnet | 0.0465 | 0.21 |
| 144 s (adopted) | clearnet | 0.0114 | 0.20 |
| 300 s | clearnet | 0.0056 | 0.20 |
| 500 s | clearnet | 0.0032 | 0.20 |
| *any* | **Tor/I2P** | **0.0000** | — |

Two properties, both load-bearing for Round 3:

- **It is mean-dependent.** The leaky event is a *real* preemption, whose rate
  falls with the embargo mean (`P(preempt)` scaled down). So a correctly
  provisioned embargo *reduces* this channel — unlike the mean-invariant
  black-hole. **This is what makes `ε` (correct provisioning) a live lever on
  clearnet.**
- **It is structurally zero on Tor.** Fluff never traverses the supernode's
  inbound edges (§6.3), so there is no early fluff to catch.

**Method-evidence (not just a nice consequence).** RD-1 and RD-4 were derived
*purely* against the black-hole backstop — the return-trip disarm and the
stem-support bug — with no thought to the passive clearnet channel, and raising
the embargo 31 s → 144 s cut that channel **~4× anyway**. When a correction made
for one adversary protects a different adversary you were not modelling, that is
usually a sign the correction is aligned with the mechanism's *actual structure*
rather than fitted to a single threat; the failure signature we kept hunting is
the reverse — a fix that helps one channel and quietly worsens another. This is
its opposite, and it is evidence about the method, not the parameter. The reason
is that the embargo length is a **shared parameter** across both channels:
getting it right for the mean-invariant channel moved the mean-dependent one in
the same direction. That coupling is a reason to trust the provisioning — and a
standing obligation on the eventual `ε` derivation: it must check that its chosen
embargo does not *pull the two channels apart* (shorten the passive leak while
under-provisioning the black-hole backstop, or vice versa), because the value's
trustworthiness rests on the two moving together.

So the two channels bind different origins and answer to different levers, and
**neither substitutes for the other**:

| channel | binds | lever | why built |
| --- | --- | --- | --- |
| passive inbound supernode | clearnet origin | **`ε`** (correct embargo provisioning; mean-dependent) | clearnet is supported by the frozen default |
| active on-path black-hole | every origin | **Q-8a** (re-stem-on-embargo; mean-invariant, transport-independent) | the only lever that touches the channel Tor does not collapse |

Picking one lever would leave a real adversary unaddressed for a real
configuration. That, not a "which lever first" trade-off, is why Round 3 opens
with both live — and it opens on the clearnet floor because
[`00-mission`](../../.cursor/rules/00-mission.mdc)'s "same guarantees for
everyone" does not let a supported configuration go undefended.

### 6.7 Can we reach ≤0.3% exposure, and which lever does it efficiently?

The leak event decomposes as a product, and **every term is a separate lever**:

```text
leak = P(preempt)  ×  neighbour(supernode reach)  ×  origin-attribution
```

- **Embargo mean** sets `P(preempt)` — mean-dependent, the lever moved by RD-1/RD-4.
- **Fluff-return `F`** sets the disarm window `h·hop + F`
  ([`tx_pool.cpp` `now + embargo_duration()`](../../src/cryptonote_core/tx_pool.cpp#L1053)):
  a larger `F` gives every prefix embargo longer to fire, so it pushes the leak
  **opposite** to the embargo mean. And `F` is downstream of F-4 — the memoryless
  fix made the return flood ~7× faster (F-5) — so **F-4 was a second, independent
  correction to this channel**, one we made against the black-hole backstop
  without knowing it touched clearnet exposure. *Two* fixes protected clearnet
  origins, not one.
- **`q`** sets the stem-length distribution — how many prefix positions exist and
  how much mass sits at the origin. Deferred (Q-3, D-6) as out of scope for the
  embargo work; that deferral rationale should now note `q` is *also* a lever on
  this channel.
- **Reshape (Q-8a)** does not reduce `P(preempt)`; it changes what a preemption
  *emits* — a stem forward (unicast, invisible to the passive inbound supernode)
  instead of an origin-attributed fluff. So it drives the origin-attribution term
  toward zero without touching the embargo mean.

**Measured, worst case** (`origin_exposure_meets_target_via_reshape_not_embargo`,
a *whole-prefix* supernode — the upper bound, not the independent-neighbour lower
reading of §6.6):

| lever setting | worst-case origin exposure | note |
| --- | --- | --- |
| current (144 s, no reshape) | **2.24 %** | above the ≤0.3% target |
| + reshape, 1 retry | **0.026 %** | **target met**, ~86× drop, *no embargo change* |
| + reshape, 2 retries | ~0.000 % | — |
| F = 13.75 s (inherited Poisson flood) | 9.75 % | what F-4 fixed (→ 2.2 % at F = 2.25 s) |
| embargo-only path to target | needs **~1050 s** | p90 recovery ~2400 s, ~8× `MIN_RELAY_TIME` |

**Answer: yes — and reshape is the efficient lever.** One re-stem retry takes the
worst-case origin exposure from 2.24 % to 0.026 % (≥ 99.97 % protected) with **no
embargo lengthening** — its cost is ~1 extra stem hop of latency, not
embargo-scale liveness. The embargo-only path to the same target needs ~1050 s (7×
the adopted mean), whose p90 black-hole recovery (~2400 s) would break the P2P
liveness the whole mechanism exists to preserve. So the levers tune together as:
**keep the embargo at 144 s** (the black-hole backstop; longer is a liveness
disaster), **`F` already handled by F-4**, **reshape carries the origin-exposure
target**, `q` held in reserve.

This is why the `ε` derivation (Q-9) must treat `ε` as a target on the *composed*
leak with freedom across `(embargo, F, reshape)` — over-constraining the embargo
to carry the whole burden buys the exposure target at a liveness cost the other
levers supply for free.

*Model honesty:* the reshape figure uses a first-order renewal model (the disarm
window is held fixed across re-stems; in reality a re-stem also advances the tx
toward completion, so the true reduction is at least this large). The
whole-prefix reading is the conservative upper bound; the independent-neighbour
reading (§6.6) is lower. The geometric drop in retry count and the direction of
every lever hold under both.

### 6.8 What a leak rate means for *detection* (the intersection math)

A per-transaction leak rate is not a detection probability. A single forced-fluff
sighting is a tuple `(tx, received-from N, timestamp)` that localizes the source
to `N`'s stem prefix — a `~1/q ≈ 5`-node set — and names the *actual origin* only
with the origin-share (`~0.20`). Four times in five the observed node is a relay
and the creator is upstream, unseen. That sighting is also **indistinguishable in
kind** from an ordinary stem-to-spy sighting (C1): it hands the adversary one more
sample of the ambiguous type it already gets, not a new certainty. So on a
*single* event the marginal origin-attribution advantage over the stem channel is
~zero.

The exposure that matters is **joint**, and it passes three independent gates:

```text
detection  =  L (a leak occurs)  ×  labelable (Δ-separability)  ×  linkable (same-origin correlator)
```

- **`L`** — measured (§6.7): 2.24 % current worst-case, 0.3 % target, 0.026 % with
  reshape.
- **labelable** — can the adversary tell a *forced* fluff (early, pre-diffusion)
  from a natural one? Only if the lead over pool-appearance is Δ-separable (§10.6);
  an unlabelable sighting cannot be promoted from "ambiguous first-spy" to
  "confirmed prefix-member."
- **linkable** — can the adversary group sightings as *same-origin*? **FCMP++
  already shuts the on-chain linker**; absent an external side-channel the
  adversary holds a pile of ungrouped `(tx, node)` tuples.

**The intersection attack** (the dangerous amplifier, paper Fig. 5) needs `≥2`
leaks in **distinct epochs** — same-epoch leaks re-confirm the same fixed stem
path, while two cross-epoch `5`-sets share only the origin, so they intersect to
`~{origin}`. This distinct-epoch requirement is the load-bearing assumption of
the whole section, and it is anchored at source:
`get_stem` caches `source → out-index` in `in_mapping_`
and returns it thereafter, so a source egresses on one fixed stem successor for
the life of a `connection_map`; the per-epoch
[`change_channels` rebuild](../../src/cryptonote_protocol/levin_notify.cpp#L711)
(on the ~10-min timer) is what turns the map over and gives distinct epochs.
**Sharper still for the origin:** a node's *own* transactions carry
`source = nil_uuid` ([local submission has no inbound peer](../../src/rpc/daemon_submit_ffi.cpp#L618)),
so they all resolve through the single `in_mapping_[nil]` entry — an origin's
transactions in one epoch do not merely share a `5`-set, they take the
*identical* stem path node-for-node. So same-epoch same-origin leaks carry
**zero** intersection information (they are the same set, not overlapping ones),
and the `≤1`-distinct-epoch count for a bursty origin is conservative in the
right direction.

Assuming the label and link gates are *fully* open (the adversary's best case),
the raw math — `P(≥2 leaks)` as the upper-bound detection probability:

| origin volume | no reshape (2.24 %) | 0.3 % target | reshape R=1 (0.026 %) |
| --- | --- | --- | --- |
| 10 txs | 0.02 | 0.0004 | ~0 |
| 1 000 txs | ~1.0 | **0.80** | 0.03 |
| 100 000 txs | ~1.0 | ~1.0 | ~1.0 |

Steady txs (1/epoch, the *exposed* profile) to reach the 2-leak floor, at a
10-minute epoch:

| | txs for 2-leak floor | time |
| --- | --- | --- |
| no reshape | ~89 | ~1 day |
| 0.3 % target | ~667 | ~5 days |
| reshape R=1 | **~7 700** | **~53 days** |

Three things this says, none of them "the leak is harmless":

1. **Reshape moves the medium origin out of reach.** At the 0.3 % target *without*
   reshape a 1 000-tx origin is 80 % detectable by a perfect-amplifier adversary;
   reshape drops that to 3 %. That is the case reshape exists for.
2. **Velocity matters, and it protects the heavy origin.** The intersection needs
   *distinct* epochs, so a bursty sender clusters its leaks: 100 000 txs in a
   single-epoch burst yields ≤1 distinct-epoch leak — **not intersectable**. The
   exposed profile is the *steady, low-rate* sender over months, not the busy
   service. **The same mechanism cuts both ways, and this must not be read as
   unconditional:** per-epoch path stability is what collapses the bursty origin's
   leaks to one set, *and* it is exactly what makes the steady origin's
   cross-epoch leaks intersect cleanly — each epoch is an independent `5`-set
   draw sharing only the true origin. "Path stability protects origins" is
   therefore conditional on burstiness; the mechanism that saves the heavy sender
   is the one that exposes the slow one.
3. **A heavy steady origin still composes under reshape *if* the amplifiers hold**
   (100 000 steady txs → ~26 distinct-epoch leaks). So reshape is the primary
   *rate* reducer, and the **Δ-separability and unlinkability gates are the
   backstop** — which is why Q-9's quantity is the *increment to joint precision*,
   not the leak rate: a sighting the adversary can neither label nor link adds
   zero, and reshape removes the sighting entirely (a re-stemmed hop produces
   nothing to label or intersect).

So `<0.3 %` is not a detection figure; it is the top gate of a three-gate product
whose other two gates FCMP++ and Δ-separability already narrow, and whose whole
product reshape zeroes at the source for the transactions it re-stems.

### 6.9 NOT DEFENDED — the passive, correctly-behaving observer (an explicit scope boundary)

This clause is written down, not merely agreed, because an unstated scope boundary
is how the review cycle regenerates: without it, every fresh look at reputation or
at the ProxyMark paper re-opens "what about the passive observer?" as if it were an
unsolved bug. It is not a bug. It is a **scope decision**, it is the same boundary
the Dandelion++ paper and Tor draw, and the answer is now recorded so it is not
re-derived each cycle.

**In scope — the active adversary, any size.** The adversary who must *misbehave or
actively position* to gain advantage: black-holing, stem-severing, dropping, or
occupying the origin's outbound stem slots. This is what stem-and-fluff was designed
to defeat and what this arc made actually work (correct memoryless embargo, exact
derivation, reshape). The demonstrated real-world attack — ProxyMark occupancy (W3,
§12) — is active *in the sense that matters here*: it requires the adversary to
position itself into the target's outbound slots. Its defence lives at the
selection / anti-eclipse layer (Q-10, `g_max`), which is **bounded, specified p2p
work with a named deliverable — a design round, not a redesign**.

**Out of scope — the passive, rule-following observer**, and everything downstream
of trying to defeat it. Three independent arguments confirm no mechanism in this
class reaches it:

- **Topological.** The origin's first stem successor, if it is an observer,
  attributes the origin with precision `≈ f` (`Precision(C1)`, §13) — set on the
  *first stem edge, before any timing mechanism engages*. Embargo distribution,
  exact derivation, reshape, granularity: none of them touch `C1`. The passive floor
  is baked into the stem existing at all.
- **Empirical.** The demonstrated mainnet attack is occupancy/active; the
  passive-majority global observer is only ever *modelled*, never the deployed
  attack — because the passive observer's advantage does not require deployment, it
  is already there at `≈ f`.
- **Mechanism-recruitment.** Every selection-layer knob that helps against the
  active adversary *feeds* the passive one. Reputation-as-retention **recruits** the
  patient well-behaved observer (it never misbehaves, so it scores perfectly);
  selection bias toward "good" peers **promotes** it. So even the Q-10 / `g_max`
  work — which correctly defends the active occupancy attacker — does nothing
  against the passive observer, and a naive reputation layer would make it worse.

**Why out of scope is the correct verdict, not a conceded weakness.** Defeating the
passive rule-following observer requires changing *what the network is*: cover
traffic / mixnet-class latency (a different dissemination protocol) or cryptographic
sender-anonymity at the p2p layer (a different network). Both are **P2P redesigns
that trade away the latency budget Dandelion++ exists to preserve**. Declaring the
passive observer out of scope is not conceding a gap — it is refusing to smuggle a
redesign in under a bug-fix's banner, which is the discipline this project runs on
([`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc)). What *does*
narrow the passive channel is orthogonal to this mechanism class and already
recorded: **transport** collapses the cheap-inbound-supernode variant (Tor, §6.5),
and correct provisioning (`ε`) reduces the mean-dependent variant (§6.6) — but the
floor `C1 ≈ f` is untouchable by stem-and-fluff, and closing it is redesign
territory.

**The one sentence that keeps this boundary from being mistaken for a bug.**
Stem-and-fluff displaces the fluff point from the origin *against an adversary who
must actively position or misbehave*; **it does not hide the origin from a passive
observer that already sees the first stem edge, and it never claimed to.** The
failure mode this clause exists to prevent is the LocalMonero-style writeup —
"Dandelion++ hides your origin," full stop — which is true against the active
minority and *dangerously incomplete* against the passive observer. A privacy
system that names the adversary it does not defend against is more trustworthy than
one that lets a reader assume it hides them from a global passive observer it cannot
touch ([`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc)).

**Settled boundary:** active in, passive-honest out, redesign explicitly declined.
The remaining in-scope work is Q-10 (`g_max`, §7) — bounded p2p, not a redesign.

### 6.10 The economic deterrent on the passive observer — effective population, not theoretical

§6.9 concedes the passive observer *structurally*. This section records the one
thing in the arc that reaches it at all — and it reaches it not at the protocol
layer but at the adversary's own institutional accounting. It is a **different kind
of argument** (economic / institutional, not a protocol property), and it is
scoped and flagged as such so no reader upgrades it into a structural defense. It
is attributed to operational experience and **cannot be sourced in the tree**.

**The occupancy defense is scoped to behaviour + pinning; address diversity is
ruled out.** Q-10's defence cannot be built on *who* peers are (address, subnet,
ASN): that family is broken on both transports for opposite reasons — on Tor the
variable does not exist (no meaningful address/subnet/ASN behind circuits), on
clearnet it *lies* (Sybils spread across subnets cheaply, and subnet-diversity
heuristics quietly punish legitimate home users behind shared NAT/CGNAT). So the
defence scopes to *how* peers have behaved (a **behavioural floor**: eviction on
dropping/misbehaviour) and *whether* they have been stably known (**guard-pinning**:
tenure for stably-known peers, of which the existing anchor connections
[`ANCHOR_CONNECTIONS_COUNT = 2`](../../src/cryptonote_config.h#L145) are the seed).
Ruling out the address family is itself useful output: nobody burns a Q-10 round
building subnet-tracking that would punish home users. *(Behavioural floor and
guard-pinning are the Q-10 design **direction**, not existing mechanisms; anchors
exist.)*

**What pinning + floor cost the passive observer.** To hold a pinned stem slot the
adversary must relay honestly — propagate every tx, stay up, never drop —
*continuously*, for the whole duration it wants the vantage, because the floor
evicts it the moment it lapses. So the passive observer is not sneaking in with a
brief good-behaviour costume (the cheap rotate-in/observe/rotate-out of the
un-pinned case); it must be a fully functional high-reliability relay for as long
as it watches. The pin **converts a one-time infiltration into a standing,
non-refundable tax** — observational access made directly proportional to ongoing
contribution to network health, revoked the instant it stops paying.

**Load-bearing premise (state it or the reach evaporates).** This taxes the
*diffuse* passive observer — not only the targeted occupier — *only if
stem-eligibility is itself gated on pinned tenure*: to be a stem successor for any
origin at all, a peer must be a stably-known, well-behaved pin of that origin.
Under that gating even passive sampling at rate `≈ f` requires paying the toll. A
Q-10 design that pins slots *without* gating stem-eligibility on pinned tenure
collapses the deterrent back to targeted-occupancy only, and the diffuse sampler
rotates in free. So this gating is a **design constraint on the Q-10 round**, not a
free property.

**The health axis — conscription, not defense.** This does not stop observation
(conceded). It reframes the passive observer from parasite to *subsidized
participant*: its transactions propagate, its uptime adds capacity, its honest
relaying strengthens exactly the propagation health the black-hole attack
degrades. On a privacy-maximalist chain still short of nodes, an adversary forced
to run a flawless relay to keep watching contributes capacity, redundancy, and
reach it would otherwise not provide. And it raises the floor for everyone: the
pinned set — adversarial and honest alike — all meet the same high behavioural bar,
because that is the price of tenure. The network gets a tier of reliably-behaving
nodes as a structural consequence of the vantage being worth paying for.

**The institutional-legibility deterrent — the part that reaches the passive
observer.** Forced good-citizenship is also a *legibility* problem for the
adversary's own institution. An intelligence line-item that reads "we ran
high-reliability infrastructure that propagated every transaction flawlessly for
eighteen months" must survive an auditor / comptroller / inspector-general / budget
committee asking: *what did we get, and how is this distinguishable from materially
operating the network we are surveilling?* The mechanism need not defeat the
agency; it makes the agency's activity hard to justify in the agency's **own**
accounting — the honest-relay work is real, ongoing, resource-consuming, and from
outside and inside looks like **support**. "Run a surveillance node" becomes
"sponsor the target," and sponsorship of the thing you are countering is a finding
that ends programs regardless of the SIGINT's value.

**Discipline 1 — economic deterrent, not structural defense.** Everything else
load-bearing in this arc is *structural* (outbound-only fluff cannot reach an
inbound spy; `STEMS = 2` is the expander-minimum; the floor demonstrably evicts).
This is different *in kind*: "most adversaries will not pay this cost" is a
statement about adversary economics and institutional behaviour, not a protocol
property. It shrinks the **effective** passive-adversary population; it is **zero**
narrowing of the **theoretical** one. Two distinct claims, both true, and a future
reader must not collapse them: **we deter the *budget-constrained* passive observer,
by economics; we do *not* defend against the *unconstrained* one (NSA /
Five-Eyes-tier), by protocol.**

**Discipline 2 — it binds on *covert* presence specifically.** The deterrent's
double-edge from the institution's side: an adversary willing to be *seen*
reinforcing the network pays the justification cost happily — for a state actor
positioning as a "responsible participant," the reinforcement *is* the cover story
that satisfies the auditor. So it binds hardest on the adversary that needs its
presence **secret** (cannot justify visible support of an anonymity coin) and
barely at all on the overtly-present participant. That is a fine place to land: the
covert budget-constrained observer is deterred; the overt participant is *just a
participant* — and a known participant is far less threatening than a covert one,
because its presence can be reasoned about. But the claim is bounded: **strongest
against covert budget-constrained presence; not the unconstrained tier, and not the
adversary content to be overtly present.**

**The "almost" is load-bearing.** "Almost no one can justify it" is not "no one."
This is the first thing in the arc that reaches the passive adversary at all, and
it reaches it not in what the adversary can *do* but in what it can *explain to its
own auditors* — a reasoned economic argument, flagged as non-protocol and
non-sourceable, with its carve-outs (unconstrained tier, overt participant) intact.

---

## 7. Open questions (the Round-3 agenda)

Round 1 closed Q-2 and Q-7; Round 2 corrected the model (RD-4), reframed Q-8 around the mechanism, and anchored everything against the sources (§11); the position-anchoring pass (§6, §10.8) then made the passive adversary transport-conditional and *measured* the clearnet passive channel (§6.6).

**Round 3 opens with both levers live, not a choice between them** — `ε` defends
the clearnet origin against the passive channel (§6.6), Q-8a defends every origin
against the black-hole (§10.6). Neither substitutes for the other, and the
instruments for both are built or scoped. What remains is the *arguments*:

- **Q-1 — is the stem model right?** *(Round 1 position: single-path is
  correct.)* Each node forwards to one per-source successor, so branching
  shapes the anonymity set, not survival. The case still worth checking is path
  self-intersection: a revisited node re-uses an already-armed timer, which
  strictly *helps* survival, so the equation is conservative there. Likely
  constant-level and dwarfed by RD-1. **Carried, low priority.**
- **Q-3 — is `q = 20%` right for Shekyl?** D-6 defers deliberately; the trade
  curve is measured and on file. Round 1 notes that RD-1's correction lengthens
  the required embargo, which *strengthens* the case for not simultaneously
  lengthening stems. **Round 3 amendment:** the D-6 deferral rationale scoped `q`
  out as an *embargo-work* question, but §6.7 shows `q` is also a lever on the
  passive clearnet channel (it sets the prefix length and origin mass). The
  deferral stands, but on the corrected basis that `q` is held *in reserve*
  behind reshape and `F`, not that it is irrelevant to this channel. **Carried.**
- **Q-4 — is 250 ms the right tick?** The derivation absorbs it, so this is
  fidelity and table size, not correctness. Round 1 position: fine as is.
  **Effectively closed; reopen only on a table-size or timer-resolution
  constraint.**
- **Q-5 — what are Shekyl's real hop latency *and fluff-return* times?**
  Reframed by RD-1: after the correction the return term dominates the hop
  term, so a testnet that measures only hop latency measures the wrong thing.
  D-5's 350 ms and D-5's 2250 ms are both placeholders with named triggers.
  **Open, and now the highest-value measurement.**
- **Q-6 — noise channels (I2P/Tor).** *(Round 1 position: out of scope.)*
  `NoiseCadence` is constant-rate cover traffic — a different mechanism with a
  different analysis, and its bounded `10 s + U[0, 5 s]` cadence must not be
  memoryless-ified as a side effect of this port. RP-1 models the draw so it is
  not invisible; the analysis gets its own document when the port reaches it.
  **Closed here, deferred to its own doc.**
- **Q-8 — is 0.90-on-*any*-preemption the right target, and is the embargo
  mean even the right knob?** Round 1 built the profile instrument
  (`simulate_preemption_profile`) and inverted the drafted premise (§10.4);
  Round 2 built the black-hole instrument and found something sharper (§10.6).
  Three results now frame this question, all measured:
  1. **The gradient is backwards.** The origin is the *modal* preempter (~21% of
     preemptions, ~2.1% of all transactions), so a leakage-weighted target is
     *more* stringent than equal-weight, not less. Weighting alone does not
     license a shorter embargo.
  2. **Weights barely have leverage.** The conditional profile is nearly
     mean-invariant (`E[2⁻ˢᵉᵖ|pre]` moves 0.40→0.34 while `P(preempt)` moves 9×),
     so a fixed `w(i)` cannot re-rank embargo choices — it relabels the axis `ε`
     is stated in. The deliverable collapses from "`ε` and `w(i)`" to "`ε`, with
     `w(i)` as its unit system."
  3. **The embargo mean does not defend the binding channel at all.** The leaky
     channel is the black-hole attack (§10.6), whose attribution leak is *flat*
     across a 10× embargo range (~0.50 origin) — lengthening the embargo only
     raises the adversary's wait. So optimizing the embargo mean against `ε` is
     nearly the wrong optimization; the decision that moves the leak is the
     **mechanism** (re-stem-on-embargo), not the mean.

  With C2 retracted (§10.6), the `ε` reference scale rebuilds around the
  spy-recall floor alone. Two things need their own work before any number is
  swept:
  - **A baseline-relative threshold.** State the target as leakage relative to
    the no-Dandelion baseline (`w[0]`, every tx fluffing at origin), under an
    explicit weight vector `w(i)` and spy fraction `f`. Per the project's own
    GF-7 discipline, the acceptance `ε` must be **derived a priori from an
    adversary-advantage argument, not read off a sweep**. Q-8's first
    deliverable is `ε` and the `w(i)` it is stated in — not a number. The
    profile makes any such `w(i)` a one-line dot product
    ([`PreemptionProfile::weighted_leakage`]).
  - **A knob that reshapes the profile rather than rescaling it (Q-8a).** Since
    §10.6 shows the mean is nearly orthogonal to the binding channel, this is
    where the real leverage is. Two designs, to be wargamed in a round of their
    own: **(a) a two-class embargo** (origin mean ≫ relay mean), which collapses
    the separation-0 row but concentrates its liveness cost at the worst case,
    since a first-hop black hole leaves the origin as sole holder; **(b)
    re-stem-on-embargo** — a holder whose embargo fires re-stems to its *other*
    quasi-4-regular successor instead of fluffing, with a once-per-tx retry cap,
    fluffing on second expiry. Round 2 sharpened (b): it applies to **every
    position, not just the origin** — relays need not know their position to do
    it, so position-blindness is preserved — and it directly attacks the
    black-hole channel by not producing a classifiable forced fluff.
    **Critically, the retry cap must be local state keyed on tx hash, never a
    wire field:** a hop/retry counter on the wire is itself a position leak.
    First-pass wargame: both-successors-black-hole → second-stage fluff recovers
    (worst-case recovery ~doubles); loops → bounded by the once-per-node cap;
    epoch boundary → the re-stem uses the current epoch's map, which D++ already
    tolerates; cost → re-stems are visible to stem spies as ordinary stem hops,
    incrementing the sighting channel by ~`0.10·f`, which the budget prices. The
    *camouflage* alternative (delay a base rate `r` of natural fluffs by
    embargo-scale draws to poison the classifier) prices out immediately — `r`
    must rival the preemption rate, costing ~`r·144 s` of latency across `r` of
    all transactions — but belongs in the wargame table as considered-and-priced.

    **Two source-anchored questions the reshape design must answer against
    `get_stem`, not against the abstraction "forward to another successor"**
    (surfaced by §6.8's `in_mapping_[nil]` reading): (i) an origin's own tx
    resolves through the *single* nil-keyed local mapping, so "the other
    quasi-4-regular successor" must be drawn explicitly from the remaining
    `out_mapping_` entries — re-stemming self-originated traffic then makes a
    *second* stem successor see origin-sourced stem hops, widening the origin's
    per-epoch stem fan-out from 1 to 2, itself a small anonymity change to price;
    and (ii) the retry must **not** re-enter `get_stem(nil)`, which returns the
    *same* cached successor and makes the re-stem a no-op. Neither breaks reshape,
    but both are RD-1/RD-4-class seams — the design must be checked against what
    `get_stem` does for `source = nil`, not against an abstract second successor.

  **Liveness, correctly stated.** The 144 s headline is the *worst case*, not
  the typical one. Black-hole recovery is the minimum over all holders'
  memoryless timers, so a black hole after hop `j` recovers with mean
  `144/(j+1)` s (`black_hole_recovery_scales_with_holder_count`: measured
  144/72/48/29 s for j=0..2,4). The headline applies only to a first-hop black
  hole where the origin holds alone — mean 144 s, p90 ~331 s — which is exactly
  the case Q-8a(b) is shaped to protect. **After RD-4 that p90 now *exceeds*
  `MIN_RELAY_TIME` (300 s)** rather than approaching it, so RP-4 must reconcile
  the two timers when the embargo cut lands — a black-holed origin's first
  MIN_RELAY_TIME re-relay and its embargo recovery can now cross.

- **Q-9 (standing Round-3 obligation) — `ε` must be derived before any sweep,
  and in increment-form.** `simulate_passive_neighbor_leak` turns any
  `(δ, f, β, π₀)` into a leak number instantly, but it cannot choose `δ` — the
  adversary-advantage we refuse to grant — and choosing `δ` *is* the privacy
  decision. Per the project's GF-7 discipline, `δ` (and the `w(i)` it is stated
  in) must come from an a-priori adversary-advantage bound, not from reading the
  instrument's output back as a target. This is the one place in the whole arc
  where the source-anchoring reflex does not help: the anchor is an argument
  about what advantage we deny an adversary, not a fact in the tree.

  **The guard that keeps this from being satisfied lazily:** `δ` must be argued
  in the *same units the instrument reports*, so the derivation and the
  measurement meet at a defined seam. The **amplification-bound form** does this
  — *the embargo channel must not raise the attribution advantage a stem-spy
  sighting already grants by more than `δ`* — because it discounts what the spy
  knew anyway (its predecessor) and prices only the new information (the
  late-fluff classification and the prefix-membership of the fluff source).
  Stated that way `δ` is a decision about **incremental advantage**, which is
  arguable a priori. Stated as a bare precision *level* it collapses back into
  something one is tempted to read off a sweep. So the obligation is not just
  "derive before sweeping" — it is **"derive in a form that names the increment,
  not the level,"** or the seam will not hold. The instrument is the calculator;
  the argument is the input, owed before the calculator is run.

  **And `δ` is a target on the *composed* leak, not on the embargo mean.** §6.7
  shows the leak has at least four levers — embargo, `F`, `q`, reshape — and that
  reshape reaches a ≤0.3% worst-case target at ~1 stem-hop of cost while the
  embargo-only path costs ~1050 s of mean (a liveness break). So the derivation
  has freedom across `(embargo, F, reshape)` to meet `δ`, and it **must not
  over-constrain the embargo** to carry the whole burden — the embargo is fixed
  by the black-hole backstop (D-2), and pushing it further to chase the passive
  target trades away liveness the other levers supply for free. **Resolved in form
  in §13:** `δ` is the precision *increment* `Precision(C1+C3) − Precision(C1)`,
  bounded by a ratio target `ρ` (the one input the human supplies), driven toward
  zero by reshape, with the irreducible W3 residual now measured directly (§12.6).

- **Q-10 (opened Round 3, and `ρ` is *blocked* on it) — the outbound-selection
  eclipse bound on `g`, under repeated adversary-induced refills.** §12.6 measures
  the W3 residual as `W3(g)`, where `g` is the adversary's share of the origin's
  *outbound* pool. `g` is **not** the network fraction `f`: the pool is 70 %
  white-list + 2 anchors
  ([cryptonote_config.h:144](../../src/cryptonote_config.h#L144)) and the white
  list is gossip-fed, so an eclipse-capable adversary drives `g` above `f` by
  cheap peerlist poisoning. So the W3 gate's real seal-condition is *how tightly
  the outbound peer-selection / anti-eclipse posture bounds `g`* — a p2p-subsystem
  question (anchor count, white/gray discipline, IP-group diversity), not a
  relay-timing one, and one no artefact in the tree answers today.

  **The churn path (§12.6, W3c) tightens what Q-10 must deliver.** `connection_map::update()`
  refills a churned stem slot with a *fresh* draw
  (dandelionpp.cpp:160) mid-epoch, and an
  adversary who induces churn re-rolls that draw repeatedly. So the bound Q-10 owes
  is not "`g` in a single initial draw" but **`g` under repeated adversary-induced
  refills** — each induced disconnect is another `~g` chance at the slot, strictly
  more capability than one-shot poisoning. The likely defense lives in the same
  subsystem and is worth naming as the candidate mechanism: **anchor slots**
  ([`P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT = 2`](../../src/cryptonote_config.h#L145)),
  which are *not* fresh gossip-fed draws, so they resist the re-roll — a bound of
  the form "≥ `k` of the `STEMS` slots are anchor-backed and thus not re-rollable"
  is the shape of answer that would unblock `ρ`. (This "repeated-refills" bound is
  the obligation *under the current churn rotation*; the rotation-mechanism redesign
  below **converts** it into a single-draw-**per-epoch** pin-formation bound by
  closing the re-roll — a strictly easier thing to prove. The qualifier is
  load-bearing: the adversary gets one pin-formation draw *per epoch*, not one
  ever — draws recur at epoch turnover and compound through the distinct-epoch
  leak ledger above. Unqualified "single-draw" below is the generic one-shot
  foil in contrasts, not this bound.)

  **`ρ` cannot be honestly chosen until this bound exists**: it must be decided
  against the largest `g` the anti-eclipse posture can *rule out* under repeated
  refills, and against `g = f` never. This is a real blocker (its own grounding,
  likely its own design round), not a deferral of convenience — the honest Round-3
  output on `ρ` is "blocked on Q-10," worth more than a `ρ` resting on `g = f`, an
  assumption the source refutes.

  **The deliverable, stated so it cannot drift — `g_max`.** Q-10 terminates on
  *one number*: `g_max`, the **maximum outbound-selection share an adversary can
  achieve *and hold* under repeated induced churn** against the origin's
  `out_mapping_` pool, given the anchor connections, the white/gray discipline, and
  whatever IP-group diversity peer selection enforces. Not a network-average
  fraction, not a single-draw occupancy — the *sustained, churn-resilient* share,
  because the churn re-roll (`update()`, §12.6/W3c) makes it a "hold" question, not
  a "draw" question. The whole `ρ` chain terminates on it:

  ```text
  ρ  ←  reshape residual δ  ←  W3(g) + W3c(g)  ←  g_max  ←  the anti-eclipse posture
  ```

  Everything left of `g_max` is specified and waiting (§12.6, §13); `g_max` is the
  only unowned link. Three things for the p2p round so it does not restart cold:

  1. **The churn coupling is the non-obvious constraint.** `g_max` is not a static
     peerlist property. `update()`'s fresh `rand_idx` refill
     (dandelionpp.cpp:144,160) re-rolls the
     slot on every disconnect, and the reshape trigger correlates with exactly that
     disconnect. So the round cannot answer with "the white list is N %
     poisonable"; it must answer "an adversary who can force `k` disconnects gets
     `k+1` draws at the slot, and here is what bounds `k` and the per-draw share."
     The load-bearing question is therefore **how much of the origin's
     stem-eligible outbound is anchor-backed versus fresh-drawable** — point the
     round there first.
  2. **The seal-location finding travels with it.** W3's residual moved from
     relay-timing to p2p over three corrections because it was a *peer-selection*
     quantity the whole time. The p2p round should expect the pattern to continue
     inward: if `g_max` turns out to depend on address-manager behaviour or
     seed-node trust, the seal moves *again*, and the round should follow that
     dependency rather than sealing at the first plausible layer. The method-test:
     **a bound that depends on a parameter owned further down is not a bound — it is
     a lower bound wearing a costume.**
  3. **The honest status line, unchanged: `ρ` is *underspecified*, not
     *undecided-pending-judgment*.** Reshape's residual `δ` has no upper *value*
     until `g_max` exists, so there is nothing for a `ρ` judgment to bind against
     yet. This is the distinction that stops someone picking a `ρ` against an
     assumed `g` and calling the chain closed.

  **The defence shape is already narrowed — behaviour + pinning, not addresses.**
  The Q-10 round does not start from a blank space: the entire *address-diversity*
  family (address / subnet / ASN) is ruled out for both transports with concrete
  failure modes (§6.10) — it does not exist on Tor and lies on clearnet. So `g_max`
  is bounded by a **behavioural floor** (eviction on dropping) and **guard-pinning**
  (tenure for stably-known peers, seeded by the existing anchors). Two constraints
  the round inherits: (a) pinning carries the **persistence double-edge** we keep
  hitting — a pinned honest peer is the defence, a pinned adversary is durable, so
  pinning trades some eclipse-exposure for occupancy-resistance and must be scoped
  active-vs-passive like reputation (pin to resist active *re-rolling*; it does
  nothing structural against a patient peer that behaved well enough to get pinned
  — the §6.9 concession, not a new caveat); and (b) the economic deterrent §6.10
  builds on pinning reaches the diffuse passive observer **only if stem-eligibility
  is gated on pinned tenure** — a design constraint, not a free property.

  **Pinning is the *structural* lever on `g_max` — the rotation mechanism is where
  it lives (and this is a different ledger from the §6.10 deterrent).** The
  rotation/churn path is `g_max`-*increasing* today: `update()`'s fresh draw on
  disconnect (W3c, §12.6) gives a churn-inducing adversary repeated chances at the
  slot, so `g_max`-under-repeated-refills is strictly above single-draw `g`.
  Pinning inverts that: a stable stem-eligible set that does not re-roll **closes
  the W3c fresh-draw path**, so `g_max` stops growing through churn and freezes at
  pin-formation composition. That lowers `g_max` **structurally — by removing the
  re-roll amplification — not by economics**, and it is independent of the deterrent
  argument entirely. This is the redesign the arc points at: the rotation mechanism
  is where `g_max` structurally lives, and pinning is the lever that lowers it.

  **It also simplifies what Q-10 owes.** With the re-roll closed, the p2p subsystem
  no longer owes "bound `g` under repeated adversary-induced refills" (the hard
  bound); it owes "bound `g` at pin formation under honest selection" — a
  **single-draw-per-epoch bound, meaningfully more tractable**. The redesign
  does not just lower `g_max`; it shrinks the unowned obligation.

  **Pin + behavioural-floor = *conditional persistence*, which resolves the
  double-edge.** Pure pinning's eclipse cost is that a bad pin is durable; the floor
  makes persistence *conditional*. A pinned **dropper** is evicted the moment it
  black-holes → the floor breaks bad pins, recovering the eclipse-resistance pure
  pinning loses; the durable-bad-pin problem survives only for a *non-dropping* pin
  — which is the §6.10 conscription case (durable, but out of scope for stopping and
  taxed into infrastructure, not re-litigated). So pin + floor is stable enough to
  close the re-roll and lower `g_max`, but not so stable a dropper gets tenure — the
  best eclipse-vs-occupancy position the arc has found, because the floor breaks the
  pin's downside for exactly the active dropper the pin would otherwise shelter.

  **The rotation-mechanism design questions (ground at source before speccing — the
  Q-10 round's agenda, not this doc's work; the substrate is now grounded in §12.8,
  which resolves Q2 to an admission-policy mismatch and reframes Q1 as a measurement):**
  1. **Pin vs. epoch layering.** Dandelion++ already re-rolls the stem mapping every
     ~10-min epoch (`change_channels`, `MIN_EPOCH`). Does pinning sit *under* the
     epoch (the eligible *set* is pinned, per-epoch successor selection still rotates
     within it — preserves per-epoch selection entropy while closing the pool
     re-roll, the probable sweet spot) or *over* it (the successor itself pinned
     across epochs)? Different `g_max`, different privacy profile; needs the analysis.
  2. **The anchor relationship.** Anchors (`ANCHOR_CONNECTIONS_COUNT = 2`,
     [`get_and_empty_anchor_peerlist`](../../src/p2p/net_peerlist.h#L497), restart-
     persistent, `first_seen`-indexed, filled at
     [net_node.inl:1820](../../src/p2p/net_node.inl#L1820)) are **already a partial
     pin** — the eclipse-resistance mechanism is a pinning mechanism under another
     name, so this is *not* greenfield. Is stem-eligibility pinning an extension of
     anchors or a separate layer? And is **`anchors = 2` colliding with `STEMS = 2` a
     hazard** — an adversary that becomes an anchor getting a persistent
     stem-eligible slot for free?
  3. **Pin lifetime / re-formation policy.** Too long → cannot recover from a bad
     (passive) pin, and pins go stale as honest peers genuinely die; too short →
     back to churn and the re-roll reopens. This is the actual tuning knob, and —
     matching the arc's discipline — it must be *derived* against the
     re-roll-vs-staleness trade-off, not inherited or picked.
  4. **Re-draw source at formation.** Even pinned, the pin is *formed* from the
     peerlist, which is enrichable — so `g`-at-pin-time is still the peerlist /
     anti-eclipse problem. Pinning removes the re-roll *amplification*, not the base
     `g`: **Q-10 is simplified, not eliminated.**

  **The deterrent's one legitimate role here, kept in its own ledger.** §6.10 is a
  documented *input* to how aggressively the pin-*lifetime* choice (Q3) weights
  occupancy-resistance vs. eclipse-resistance: if the covert-occupier population is
  economically thinned, the occupancy risk *from that class* is lower relative to
  eclipse risk. That is held as an **explicit, stated economic assumption, never
  baked into `g_max`**, and flagged so a future reader sees exactly which knob rests
  on an adversary-budget assumption rather than on protocol structure. **The clean
  separation the arc keeps having to redraw:** the rotation redesign lowers `g_max`
  *structurally* (worst-case bound); the deterrent shifts the adversary *population*,
  not the bound. Conflating "lowers the bound" with "thins the population" is the
  error caught four times now in different costumes — they stay in separate ledgers.

**Closed in Rounds 1–2:**

- **Q-2 — memoryless mode-at-zero.** Closed by RD-2. A constant floor is
  dominated in both framings a latency budget allows; D-1's reversion clause is
  withdrawn. See §10.2.
- **Q-7 — does the fluff-delay fix interact with the embargo derivation?**
  Closed by RD-1 — and the answer was much bigger than the question. It is not
  that the effective hop time might include the fluff delay; it is that every
  stem node's exposure window gains a diffusion-return term. See §10.1.

---

## 8. Cuprate — recorded so the question is not reopened by accident

`Cuprate` publishes `cuprate-dandelion-tower`, whose `config.rs` independently
reaches D-2's conclusion (derive `Tbase`, do not hard-code it). It is prior
art, credited as such, and worth reading. It is **not** a dependency:

1. **It is not published.** Every Cuprate crate on crates.io —
   `cuprate-levin`, `cuprate-epee-encoding`, `cuprate-wire`,
   `cuprate-dandelion-tower` — exists only as a `0.0.0-placeholder` name
   reservation (verified via the sparse index, 2026-07-23). The real code is
   monorepo-internal with workspace-relative dependencies, so consuming it
   means vendoring at a pinned commit, not `cargo add` — a
   [`17-dependency-discipline`](../../.cursor/rules/17-dependency-discipline.mdc)
   posture change, and a [`10-shekyl-first`](../../.cursor/rules/10-shekyl-first.mdc)
   question about adopting a sibling's application code.
2. **The shape is wrong for this seam.** `dandelion-tower` is a
   `tower::Service` stack over tokio timers and futures streams, and abstracts
   the tx-pool behind traits we would implement against LMDB. D-7 exists
   precisely to keep a second reactor out of the p2p path.

Its `net/levin` and `net/epee-encoding` are a **genuinely different question**.
They would remove the single largest obstacle to ever moving the *full* relay
path into Rust — that this workspace has no epee or levin implementation. Both
are MIT with light dependency lists. That belongs to its own decision, not to
this document, and it is not on the path for RP-2…RP-4.

---

## 9. Reversion clauses (rule 21)

- **D-1**'s original reversion clause is **withdrawn** (RD-2): it was
  untriggerable, and measuring it properly closed the question against the
  named alternative rather than merely unblocking it. What survives is narrow —
  revert only if memorylessness breaks a *batching* invariant, not on inversion
  grounds, where it has now been tested and holds.
- **D-2** has no reversion: an exact solve of the stated equation is not a
  preference. If the *equation* is wrong, the equation is corrected and the
  solve re-run — the mechanism of deriving-rather-than-hardcoding stands. Round
  1 exercised this clause exactly as written: RD-1 showed the equation was
  wrong, the equation was corrected, the solve was re-run, and the adopted
  value moved 31 s → 112 s → 144 s (RD-1 then RD-4) without D-2 itself being
  reopened at any step. A hard-coded
  constant would have needed a decision to change; a derivation needed only a
  corrected input. That is the derive-don't-hardcode argument made empirical —
  and it is also quiet evidence that the equation-vs-mechanism seam (RD-1's
  defect class) is now the *only* place this subsystem can still be wrong, which
  is why Q-8's leakage model deserves the same source-anchored scrutiny the
  survival equation just survived.
- **D-5**'s 350 ms hop and 2250 ms fluff-return are both explicitly
  provisional and revert on the first real measurement. After RD-1 the return
  term dominates, so the measurement that matters most is the one nobody had
  thought to ask for.
- **D-6** reopens on a threat-model round, not on preference.

---

## 10. Round 1 dispositions

All three findings accepted. RD-1 and RD-2 are folded into §0/§1 above; this
section records what was checked and what changed, so a later reader can see
the reasoning without reconstructing it.

### 10.1 RD-1 — the survival equation ended exposure at the wrong event

**Accepted, and larger than sketched.**

*Verified at source.* `tx_pool.cpp`'s `set_relayed` calls
`meta.upgrade_relay_method(method)` and only then tests `meta.dandelionpp_stem`;
if the method has upgraded out of stem, `last_relayed_time` is set to `now`
with no embargo term. The receive path in `add_tx` carries the same upgrade,
under a comment that names it outright: *"synchronize with embargo timer or
stem/fluff out-of-order messages"*. So a stem node's embargo is disarmed when
**it observes the fluff**, not when the terminal node emits it. True exposure is
`(h-i)·hop + F_i`, and the flood's every edge carries a fluff delay.

*Measured.* `simulate_fluff_return` models the flood as first passage on a
random graph with per-edge fluff delays — which is what the daemon does, since
a node draws one flush deadline per peer connection. At 512 nodes, 8 peers:

| fluff delay on each edge | mean | p90 |
| --- | --- | --- |
| inherited: Poisson λ=20 | 11.2 s | 13.75 s |
| memoryless: geometric mean 20 | 1.5 s | 2.25 s |

This is **F-5**, and it confirms the mitigating structure Round 1 predicted:
first passage is a minimum over parallel paths, and a minimum only helps when
the paths differ. Under the inherited near-deterministic delay every path costs
about the same and the flood crawls; under a memoryless delay it is ~7× faster.
**Fixing F-4 substantially repairs the gap that counting `F` opens** — without
it the required embargo would be 521 s rather than 112 s.

*Consequence.* Equation amended (D-2), simulator amended identically so the
cross-check still compares like with like, adopted embargo 31 s → **112 s**
(later 144 s under RD-4, §10.5), and the previously-derived 31 s reassessed at
**0.7292** — inside the 0.61–0.85 band Round 1 sketched. Q-7 is subsumed and
closed.

*What it opens.* A 112 s embargo is a substantial liveness cost, which promotes
Round 1's second mitigating structure from a footnote to the **leading open
question (Q-8)**: the equation weights all preemptions equally, but a
preemption by the last stem node leaks far less than one by the first. That,
not the derivation, is now the assumption most likely to move the number.

### 10.2 RD-2 — the reversion clause was untriggerable

**Accepted; the clause is deleted rather than weakened.**

*Verified.* `inference_precision` is a maximum over sliding windows of the mass
and is therefore **shift-invariant by construction** — not merely empirically.
Any "add a floor" variant scores identically to its unshifted twin. The clause
armed a gate that no instrument in the tree could ever fire.

*Resolved rather than deferred.* Building the non-shift-invariant instrument
Round 1 asked for settled the question instead of just unblocking it. The
instrument is arrival-phase conditioning (`residual_masses`), motivated by the
re-armed batching flush, and under it a floor is dominated in **both** framings
a latency budget allows:

| variant | mean | inversion at ±0.5 s |
| --- | --- | --- |
| plain geometric | 20 ticks | 0.2165 |
| floor 8 + geo 20 — *pure shift* | 28 ticks | 0.2165 (identical, +8 ticks latency for nothing) |
| floor 8 + geo 12 — *same mean budget* | 20 ticks | **0.3298 (worse)** |

A floor buys its offset by narrowing the random part. So Q-2 is **closed
against the floor**, and D-1's reversion clause is withdrawn.

*Also adopted:* Round 1's point that D-3's stated justification was vulnerable
to its own adversarial reading. Uniform genuinely beats geometric at phase 0
(0.1220 vs 0.2165); the argument that survives is the residual/memorylessness
one, and D-3 now states it explicitly with the phase table behind it.

### 10.3 RD-3 — measurement labelling

**Accepted, both halves.**

*The F-2 table conflated two fixes.* The memoryless row ran at 250 ms while the
Poisson rows ran at the inherited whole second, so it moved distribution and
granularity together. The table now labels the tick per row and carries a
tick-held memoryless row, which separates them cleanly: the distribution fix
alone moves full-travel 0.9997 → 0.6002, and the finer tick adds a further
0.0177. D-1 does essentially all the work; D-4 is a fidelity refinement.

*The precision question resolves as noise, but the gate was real.* At 6M trials
the analytic and the simulator agree within ±1σ at **every** tick from 1000 ms
down to 50 ms (max |Δ| = 0.00016). The apparent ~3–4σ gap came from computing σ
against 200k trials, but that granularity test runs at `TRIALS/4` = 50k, where
σ ≈ 1.55e-3 and the gap is ~1.9σ. The underlying criticism stands regardless:
the cross-check only asserted at 250 ms, so a genuine tick-dependent divergence
would have had nothing watching it. It now sweeps the tick as well as the mean.

### 10.4 RD-1 follow-on — the Q-8 gradient, verified and inverted

Round 1 built the preempter-position profile before opining on Q-8, and the
drafted premise ("a position-weighted target permits a *shorter* embargo")
turned out to have the sign backwards. Reproduced independently and pinned in
`preemption_profile_answers_who_preempts` (400k trials, adopted embargo;
profile shares are stable under RD-4's re-derivation to 576 ticks):

| separation from origin | share of first-preemptions | marginal (analytic ✓ sim) |
| --- | --- | --- |
| 0 (the origin itself) | 0.215 | 0.0229 |
| 1 | 0.172 | 0.0183 |
| 2 | 0.136 | 0.0147 |
| 3 | 0.104 | 0.0117 |
| 4+ | 0.373 (decaying) | — |

The origin is the **modal** preempter. The intuition is structural: position
`i` exists only when the stem is longer than `i` (probability `(1-q)^{i+1}`) and
earlier positions hold longest, so conditional on the ~10% tail firing it
disproportionately fires where it hurts most. In absolute terms **~2.1% of all
transactions fluff from their own origin node** at the adopted target. That is
the number Q-8 is about.

Consequence for the design: a decaying-`w(i)` target is *more* stringent per
unit `P(preempt)`, not less, so weighting alone licenses a *longer* embargo.
The question does not resolve to "shorten it"; it resolves to the two work items
now in Q-8 (a stated `ε`/`w(i)`, or a profile-reshaping knob), plus the
liveness reframing recorded there. The profile is now a first-class instrument,
so any `w(i)` Round 2 proposes is a dot product rather than a re-run.

A note logged against `F` while here: `fluff_return_ms` is the p90 of the
**population-marginal** first passage, applied uniformly to every position. But
`F(j)` grows with stem distance and the origin sits at maximum distance, so its
return distribution is stochastically above the marginal — p90-of-marginal is
conservative for near positions and could be neutral-to-slightly-short for the
origin specifically. At 512/8 with graph distances capping around 3–4 this is
noise against the adopted embargo, but Q-8 concentrates exactly at the origin, so when the
profile work lands `F` should be measured **conditional on stem distance**, and
the Q-5 testnet measurement should stratify the same way.

### 10.5 RD-4 — the stem-length support was wrong, in the seam we named

**Accepted; the adopted embargo moves 112 s → 144 s.**

D-2 said the equation-vs-mechanism seam was "now the only place this subsystem
can still be wrong." Round 2 found it wrong there — and found it by checking the
mechanism against its *literature*, because the crate and the review shared the
same buggy premise, so the simulator could not catch it (both models agreed
with each other while both disagreed with the protocol).

*Verified at source.* The origin always stems its own transaction.
`levin_notify.cpp:560` — `if (!zone_->fluffing || tx_relay == relay_method::local)`
— routes a node's own tx (`source` nil) into the stem regardless of the node's
per-epoch fluff role, matching Dandelion++ §4.4: *"Every time a node generates a
transaction of its own, it forwards the transaction, in stem phase, along the
same outbound edge."* The per-epoch diffuser role applies to **relayed**
transactions only.

*The bug.* The fluff coin is therefore flipped by each *relay*, never the
origin. Stem length is geometric on `{1, 2, …}` with mean `1/q = 5` — the model
had it on `{0, 1, …}` with mean `4`, letting the origin fluff its own tx at stem
length 0. Every real stem has the origin holding for at least one hop plus the
return, which the old support under-counted.

*Consequence.* Re-derived under the corrected support (`full_travel_probability`
and all four simulators amended so the origin never draws a fluff coin):
**576 ticks = 144 s** achieving 0.9000, up from 446 ticks / 111.5 s — a +29 %
provisioning miss. The preemption profile is stable (origin share 0.21,
origin self-fluff still ~2.1 % of all transactions), and `q = 100 %` is no longer
certain survival — it now gives a unit stem the origin holds through, which the
`always_fluffing_gives_a_unit_stem_the_origin_still_holds` test pins as the exact
`(1-p)^S(1)`.

*Side effect on RP-4.* At 144 s the origin-alone black-hole recovery p90 (~331 s)
now **exceeds** `MIN_RELAY_TIME` (300 s) rather than approaching it — see the
Q-8 liveness note.

### 10.6 Round 2 — the binding channel is the black-hole attack, and the embargo mean does not defend it

Building the spy-augmented instruments (Round-2 item 1) produced a correction to
the review's own composition table and a decisive result for Q-8.

**Correction: absent a black hole, C3 preemptions do not leak.** The passive-spy
Δ instrument (`simulate_sighting_separability`) shows that an embargo fire which
becomes the *first* fluff must be a small draw — it has to beat the sub-second
natural completion — so it lands at seconds scale, indistinguishable from a
natural fluff (measured misclassification ~6 %, embargo Δ p50 ~2.8 s, not the
144 s the review's C3 row assumed). The 144 s-scale fires happen *after* natural
completion and are redundant races. So C3 is a leak only when the stem is
actually black-holed.

**The genuinely leaky C3 is the adversary-triggered black-hole attack** —
`simulate_blackhole_attack`, which is the classic Dandelion++ attack: an
adversarial stem node drops a tx it sighted, forcing an upstream embargo to
fire and reveal a prefix member. The adversary knows the fluff is forced (it
caused it), so Δ-separability is moot; the leak is the *source attribution*, and
the decisive measurement is that it is **mean-invariant**:

| embargo mean | P(forced source = origin) | adversary wait |
| --- | --- | --- |
| 50 s | 0.498 | 17 s |
| 144 s | 0.498 | 57 s |
| 300 s | 0.494 | 126 s |
| 500 s | 0.497 | 202 s |

The attribution leak is flat (spread < 0.01) across a 10× embargo range while
the adversary's wait scales linearly. **Lengthening the embargo does not defend
C1×C3 — it only raises the adversary's cost.** Only a mechanism that stops
producing a forced fluff (re-stem-on-embargo, Q-8a(b)) reshapes the ~0.50. This
is the strongest form of the "reshape, don't rescale" conclusion: the quantity
Q-8 optimizes (the embargo mean) is nearly orthogonal to the binding channel's
leak.

**π₀ is measured** (`simulate_diffusion_first_spy`): the first-spy diffusion
precision the stem phase defends against — 0.12 / 0.20 / 0.33 at spy fractions
0.05 / 0.10 / 0.20, rising as the first spy lands closer to the source. It
prices the source attribution of *any* fluff and is the baseline the ε argument
references.

**Review retraction, incorporated.** The review's Round-1 "designed 20 %
origin-fluff channel" (its C2) is withdrawn: it was anchored at the epoch-coin
flip (`:709`) without tracing the consumer (`:560`), where own transactions
always stem. There is no designed crowd of origin-fluffs for an embargo-forced
one to hide in — which makes the C1×C3 classifiability concern *stronger*, and
the case for re-stem-on-embargo with it. The ε reference scale rebuilds around
the spy-recall floor alone, not a q-channel.

### 10.7 Verification items surfaced by the sources (named, not yet closed)

- **Loop handling.** The Dandelion++ prototype enters fluff mode on a stem loop.
  If the inherited code instead drops a duplicate stem receipt silently, a loop
  is a self-inflicted black hole recovered only at embargo latency — both a
  liveness event and a preemption-class fluff the model does not count. Needs a
  `tx_pool.cpp` duplicate-stem-receipt check before RP-4.
- **Per-epoch determinism.** The fluff decision is per-node-per-epoch and
  forwarding is one-to-one, so a given origin's stem path and terminal are fixed
  within an epoch. The crate's i.i.d.-per-tx geometric is the correct
  *cross-epoch marginal* for the survival target — but that is a model
  assumption the doc must state, and it matters for Round 3's intersection
  bookkeeping: same-origin transactions in one epoch share their path, terminal,
  and preemption exposure as a block, so β and π₀ must be defined with that
  correlation named rather than assuming per-tx independence.

### 10.8 Anchor position before attack — and the adversary class it resized

**Methodological correction, accepted.** Rounds 1–2 ran two rounds of "what can
the passive adversary do" before pinning *where* that adversary sits in Shekyl's
topology or verifying its observable existed in code. The right order is
position first. §6 now anchors it at `file:line`; this records what the
anchoring changed.

**A proposed passive adversary (call it RD-5) is clearnet-only, verified
structurally — not by simulation.** The candidate was a passive out-neighbour: a
spy that receives a prefix node's *forced fluff* by neighbouring it, whose leak
(unlike the black-hole's) would *scale down* with the embargo mean and so reopen
`ε` as a live lever. Whether that observable exists is decided entirely by who a
fluff reaches, and [`levin_notify.cpp:448-449`](../../src/cryptonote_protocol/levin_notify.cpp#L448-L449)
settles it (§6.3): on the public zone fluff reaches inbound peers, so an
inbound sybil *does* see it — the observable is **real on clearnet**; on I2P/Tor
fluff is outbound-only, so an inbound sybil sees nothing — the observable is
**structurally absent on the SP-T0 transport**. This is a source fact, not a
measurement.

**Consequence — which adversary binds is a function of transport:**

| adversary | needs | transport dependence |
| --- | --- | --- |
| passive inbound-spy (RD-5) | an inbound edge to a prefix node | **clearnet only** — absent on Tor/I2P |
| active black-hole (§10.6) | an on-path stem-*successor* position | **transport-independent** — outbound-only topology does not prevent it |

So for a **Tor-transport origin**, the passive channel vanishes and the
black-hole / mean-invariant result governs → **reshape (Q-8a); `ε` is nearly
inert.** For a **clearnet origin**, the passive channel binds and is
mean-dependent → **`ε` is a live second lever.** The Round-3 ordering question
("`ε` or Q-8a first?") therefore resolves to *which transport is the origin
on?* — a policy anchor the project already holds (own-node / Tor posture,
SP-T0), not a parameter to sweep.

**Honesty flags (two, both mine to own):**

1. RD-5 was asserted from the paper's abstract topology *before* checking
   `fluff_notify`'s income gate. It happened to be real on clearnet, but it
   could as easily have been a phantom on the transport that matters most. The
   source check should have come first — the standing "name T and its channel,
   or no threat model" rule. It now has.
2. **Both transport instruments are now built.** `simulate_transport_observation`
   (§6.5) carries a `Transport` flag zeroing the inbound-spy channel on Tor, so
   the supernode delta is a measurement (π₀ 0.45 → 0.000). And
   `simulate_passive_neighbor_leak` (§6.6) — the narrower mean-dependent
   magnitude — **is built, not deferred**: the §10.8 gate ("build if the origin
   may be on clearnet") resolves to *yes* under the frozen clearnet default, so
   it is Round-3 work, not a conditional. The other reaching-instruments
   (`simulate_fluff_return`, `simulate_sighting_separability`,
   `simulate_diffusion_first_spy`) still model the **public zone**; their rustdoc
   says so. The black-hole instrument is transport-independent and unaffected.

---

## 11. External anchoring (Round 2)

Every finding was checked against the primary sources by the Round-2 review.
This section records the anchors; the paper is Fanti et al., *Dandelion++:
Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees*
(arXiv:1805.11060).

*Note on verification split:* the source-anchoring below was performed by the
reviewer against their copies of the paper and the Bitcoin Core tree; this
sandbox cannot fetch arXiv, so the paper quotations are recorded as the
review's citations. The **mechanism** claims (own-tx-always-stems, the disarm
event) were independently re-verified here at `src/` and are marked ✓-at-source.

| Finding | Anchor |
| --- | --- |
| **F-2** (memoryless embargo) | Paper Eq. (7): `T_out(v) ∼ current_time + exp(1/T_base)`, i.i.d. across relays — exponential. Monero's `std::poisson_distribution` contradicts it directly. |
| **F-2 rationale (new)** | Paper §5.3.1: memorylessness *"ensures that the first relay node to broadcast is approximately uniformly selected among all relays that have received the message."* A near-deterministic draw makes the first-to-fire predictable *by position* — deanonymizing black-hole recovery. This is a second reason for D-1, folded in below. |
| **F-1 / F-3** (the constant) | Paper Prop. 3 uses the natural log, over a *fixed* path of length `k` (a chosen guarantee parameter). Monero committed two transcription errors: the log-base substitution, and plugging `k = 5` (an expected length) into a fixed-`k` bound — the E[K(K−1)] gap F-3 measured. The defects are in the transcription, not the source. |
| **RD-1** (observation-disarm) | Paper §4.4: *"If the relay does not receive an INV … before his timer expires, then the relay diffuses the transaction."* Disarm on receipt — verified ✓-at-source at `tx_pool.cpp`. The paper's Prop-3 bound does not itself account for the INV return trip its cancellation rule requires; RD-1's return term provisions for the spec's stated disarm event more carefully than the paper's own bound. |
| **F-4** (fluff delay) | Paper §4.4 baseline: Bitcoin Core diffusion with *"independent, exponential delays."* Bitcoin Core v0.21 `net.cpp:3058` computes `log1p(-U)·mean·-1`; master renamed the primitive to `MakeExponentiallyDistributed` (`random.cpp:704`) precisely because the "Poisson" name misled. Monero implemented the name, not the distribution. |
| **D-5** (hop latency) | Paper measured ~300 ms per added hop on mainnet (20 trials, stems ≤ 12, 3-message INV/GETDATA/TX over ~110 ms median link). 350 ms is conservative for clearnet — **but Shekyl relays over Tor (SP-T0)**, whose circuit latency multiplies the per-hop figure, so the D-5 reopening trigger must measure under the real transport. Post-RD-1 this partly washes out (F dominates the hop term), but it needs saying. |
| **Epoch length** | Paper: *"epochs on the order of 10 minutes"* — Monero's 600 s ✓. |
| **Q-3 (`q ≤ 0.2`)** | Paper §5.3.1: *"by choosing q ≤ 0.2, we can limit the increase in average precision to 0.1, even when spies connect to every honest node."* `q = 0.2` sits at the recommended boundary; any re-tune moves down, as D-6 assumed. |
| **π₀ / leakage weights (Round 3)** | Paper Thms 2–4: first-spy precision is `Θ(p² log(1/p))` for one-to-one forwarding with unknown graph, `O(p)` known-graph; the diffusion-only baseline `π₀ ≈ 0.3` traces to the paper's *"accuracies over 30 % attacks."* These are the named sources for the ε argument's weights. |

**D-1 gains the uniformity rationale (from §5.3.1):** memorylessness is not only
what makes the embargo *fire* (F-2's measured consequence); it is what makes the
first relay to broadcast approximately uniform among the relays that hold the
tx. A near-deterministic timer makes the first-fluffer predictable by stem
position, which would deanonymize black-hole recovery — the very event the
embargo exists to serve. This is an independent argument for D-1 beyond the
inversion analysis.

---

## 12. Q-8a reshape wargame — re-stem-on-embargo (Round 3, design only)

**Scope.** Design-and-adversarial-analysis, not implementation: this section is a
mechanism spec, a failure-mode table, and rule-21 reopen/halt criteria. No
production code lands with it. It is kept in this document rather than a sibling
so the spec sits beside the measured analysis (§6.6–6.8, §10.6) that justifies
it — a separate doc would re-create the true-seal-in-the-join split, where a spec
drifts from the evidence it rests on.

### 12.1 Decision, and why (a) two-class embargo is rejected

**Adopt (b) re-stem-on-embargo. Reject (a) two-class embargo.** Two measured
reasons — *and a refuted one I record so it is not re-argued*:

- **Liveness (the killer for (a)).** A two-class embargo cuts the origin's
  exposure only by lengthening the origin's own embargo, so it hits the 0.3 %
  target at an origin mean of ~1050 s (§6.7) — origin first-hop black-hole
  recovery p90 ~2400 s, ~8× `MIN_RELAY_TIME`. Same liveness cost as global
  embargo-lengthening, merely concentrated on the origin.
- **Incompleteness.** (a) only touches position 0. Relay-position preemptions
  (separations 1, 2, 3 …) still emit forced fluffs that reveal prefix members, so
  the passive channel stays open for every non-origin position. (b) is
  position-blind: every node re-stems on *its own* embargo fire.
- **Refuted non-finding — (a) does *not* self-label.** I hypothesised that a
  longer origin embargo would make origin forced-fluffs *later* and so labelable
  by their lateness, and measured it: false. A forced fluff exists only if it
  fires *before* disarm (`fire < natural_fluff + F`), so it is disarm-window
  bounded (~seconds) regardless of the embargo *mean*. A longer origin embargo
  lowers the origin's leak *rate*, not its lateness (origin and relay
  forced-fluff median lateness both ~575 ms across origin means 144 s→1050 s).
  So the case against (a) is liveness + incompleteness, not distinguishability;
  the distinguishability argument does not exist and should not be leaned on.

(b) reaches 0.026 % worst-case origin exposure (§6.7) at **no embargo change**
(144 s), which is why it is the efficient lever and the adopted one.

### 12.2 Mechanism spec, pinned to `get_stem` / `connection_map`

> **Anchors retired — read this before following the links below (RP-3a).**
> `src/net/dandelionpp.{h,cpp}` no longer exists: `connection_map` was an
> opaque-handle wrapper over the Rust map, and RP-3a took the whole relay zone
> into Rust, so `shekyl-relay::Zone` now owns a `StemMap` directly. The
> mechanism this section specifies is unchanged; only its address moved.
> `get_stem(source)` is `StemMap::stem_for` in
> [`stem_map.rs`](../../rust/shekyl-relay-privacy/src/stem_map/mod.rs), the cached
> `in_mapping_[source]` is its `inbound` map, and the caller that would choose
> the alternate is `Zone::plan_relay` in
> [`zone.rs`](../../rust/shekyl-relay/src/zone/mod.rs). **The line numbers below are
> kept as written** — they record what was verified at the time, and rewriting
> them would silently re-attribute that verification to code nobody checked.
> RP-2b re-grounds against the Rust source.

1. **Trigger.** A stem holder's embargo fires before disarm (the preemption
   event of the survival model).
2. **Response.** Instead of `fluff_notify`, forward the transaction on the
   *alternate* stem successor.
3. **Selecting the alternate — not via `get_stem` again.** `get_stem(source)`
   returns the cached `in_mapping_[source]` entry
   (dandelionpp.cpp:192,209); calling it
   again re-selects the *same* successor and the re-stem is a no-op (question ii).
   The alternate must be taken explicitly as the *other* live `out_mapping_`
   index. `out_mapping_` holds exactly `CRYPTONOTE_DANDELIONPP_STEMS = 2` entries
   ([config](../../src/cryptonote_config.h#L101),
   ctor), so "the other index" is
   well-defined: the primary is `out_mapping_[in_mapping_[source].second]`, the
   alternate is the remaining index.
4. **Retry cap = `STEMS − 1 = 1`** (derived, §12.3). After the alternate is used,
   fluff.
5. **Retry state is local, keyed on tx hash, never on the wire.** A hop/retry
   counter on the wire is a position leak (an observer counts re-stems → infers
   separation). The count lives in node-local state keyed on the tx hash and is
   never serialized.
6. **Fan-out (question i).** Re-stemming the origin's own transaction routes it
   on the *second* of its two stem successors. The origin's `connection_map`
   already holds both (`STEMS = 2`); its `nil`-keyed mapping normally uses one.
   So the change is "the origin's own traffic reaches 2 of its 2 stem peers
   instead of 1" — reuse of an existing `out_mapping_` entry, **not a new edge**.
   That distinction is a rule-21 halt criterion (§12.5): reshape must never widen
   the origin's peer set beyond `STEMS`.
7. **Degenerate case — and it is adversarially reachable (W3b).** If
   `out_mapping_` has fewer than 2 live entries (a successor disconnected and is
   `nil`), there is no alternate; the node fluffs on embargo fire (the R=0
   behaviour). Reshape is a best-effort overlay, never a reason to hold a
   transaction. But this is not a benign churn case only: an adversary who can
   hold the origin at *one* live stem peer (peer churn it induces, or a partial
   eclipse) converts **every** embargo fire back into an origin fluff — a cheaper
   attack than controlling *both* successors (W3), and the same underlying lever
   (shaping the origin's two-slot stem set). It is tabled as W3b, not folded into
   this fallback line, because `§6.8`'s leak arithmetic does not count it: reshape
   removes the embargo-fired origin fluff *only while a second live stem exists*.

### 12.3 The retry cap is derived, not a magic constant

The question was: derive the cap here, or fix it at 1 provisionally? **Derive it
— and it derives to 1 structurally, not provisionally.**

```text
cap = min( STEMS − 1 ,  smallest R meeting δ )
    = min( 1 ,  1 )   =  1
```

- `STEMS − 1 = 1`: there is one primary and exactly one alternate successor; no
  third exists to try, so the mechanism fluffs after a single re-stem regardless
  of `δ`. The stem graph itself bounds the cap.
- `smallest R meeting δ = 1`: R=1 delivers 0.026 % worst-case (§6.7), inside the
  0.3 % target. So one retry is also *sufficient*.

The cap is therefore neither inherited (like the 39 s) nor swept — it is forced
by `CRYPTONOTE_DANDELIONPP_STEMS` and independently sufficient for the target.
Per Q-9, the cap is *netted*, not counted separately: its fan-out cost (§12.2.6)
lands in the same §6.8 passive-supernode metric as its leak benefit, and because
the fan-out change is *which* of the origin's already-two stem peers see its
traffic (not a new peer), the net is dominated by the ~86× rate reduction.

### 12.4 Failure-mode table

| # | Failure mode | Adversary / trigger | Mechanism response | Residual | Status |
| --- | --- | --- | --- | --- | --- |
| W1 | `get_stem(nil)` no-op (ii) | design bug | select the alternate `out_mapping_` index explicitly, never re-call `get_stem` | none | **closed by spec** |
| W2 | Fan-out 1→2 (i) | passive inbound supernode (§6.8) | reuse the existing 2nd `out_mapping_` entry; net against leak benefit in the §6.8 metric | fan-out cost sub-dominant to the ~86× rate cut | **closed (netted)** |
| W3 | Both-successors-black-hole | adversary occupies *both* of the origin's 2 stem successors | re-stem to the 2nd is also dropped → fluff after the cap; the fluff recovers liveness | origin exposed iff **both** stem slots are adversarial. The two slots are drawn **without replacement** from the origin's *outbound* pool of `D_out = 12` (`out_mapping_`, [`!m_is_income`](../../src/cryptonote_protocol/levin_notify.cpp#L152)); an adversary enters that pool only by being *selected* as an outbound peer (the costly direction). Measured (§12.6): **≈ 0 at baseline `g = f`** (~1 of 12 peers cannot fill two slots), **bounded *above* by the independent draw `(a/D)²`** (no-replacement is anti-correlated, not "worse than independence"), rising only under genuine outbound enrichment `g ≫ f` — ≈ 0.09 even at `g = 0.30`, well under the inbound `π₀ = 0.45`. | **measured (build 1)** — small, gated on the costly outbound-selection capability |
| W3b | Single-live-stem fallback | adversary holds the origin at *one* live stem peer (induced churn / partial eclipse) | no alternate exists → fluff on embargo fire (the §12.2.7 fallback) | **every** embargo fire becomes an origin fluff for that origin — cheaper than W3 (one slot, not two), same lever (shaping the 2-slot stem set). Uncounted by §6.8. | **ceiling measured** — the single-slot occupancy the same instrument reports (§12.6) bounds it; the realized rate is gated on an induced-churn capability |
| W3c | Churn-refilled alternate | adversary induces churn on the origin's stem peer (or *is* the dropping successor), forcing `update()` to refill the slot | `update()` fresh-draws the churned slot from the outbound pool (dandelionpp.cpp:160) mid-epoch; reshape may then forward to a fresh draw | `≈ g` per re-stem, and **churn correlates with the reshape trigger** (a dark successor is why the embargo fires), so it is the operative case, not the edge case. Repeated induced churn re-rolls the draw. | **spec gap named** — RP-2 must make the alternate stable across churn refill (§12.5); the `g`-bound Q-10 owes must hold under *repeated* refills |
| W4 | Loop (revisited node) | topology | once-per-tx local cap bounds re-stemming; matches the paper's "fluff on loop" | bounded by the cap | **closed by cap + local state** |
| W5 | Epoch-boundary straddle | timing | a re-stem after `change_channels` uses the fresh map; D++ already tolerates map turnover mid-flight ([levin_notify.cpp:711](../../src/cryptonote_protocol/levin_notify.cpp#L711)) | tx may re-stem into a rebuilt map | **low — within existing D++ tolerance** |
| W6 | Wire position leak | on-path observer counting re-stems | retry state local, tx-hash-keyed, never serialized | none | **closed by spec (the wire rule)** |

### 12.5 Reopen / halt criteria (rule 21)

- **Cap (W-cap).** Re-derive if `CRYPTONOTE_DANDELIONPP_STEMS` changes (more
  alternates raise the achievable cap) or if `δ` is set tighter than the 0.026 %
  R=1 already delivers.
- **W3 / W3b — measured (Round-3 build 1), and grounding corrected a phantom.**
  Both rest on the *joint* adversary occupancy of the origin's two stem slots. An
  earlier draft called this "a small extension of `simulate_transport_observation`,"
  reading the transport table's `π₀ = 0.45` (§6.5) as single-slot occupancy under
  the same enrichment. **It is not.** `π₀` is the *inbound* diffusion reach — cheap
  edges the spy dials — while `out_mapping_` is built from the origin's *outbound*
  pool (dandelionpp.cpp:103), which an
  adversary enters only by being *selected* as an outbound peer (address-manager /
  sybil bias, the costly direction the node resists). Importing the inbound reach
  would have measured a channel that capability cannot reach — the exact
  ground-before-rigor trap. So `simulate_two_slot_occupancy` is a *separate*
  instrument parameterized by the adversary's *outbound* share `g`, not an
  extension of the inbound one. Result (§12.6): the residual is ≈ 0 at baseline and
  small even under substantial outbound enrichment. Reopen the cap or the mechanism
  only if a supported topology shows `g` can be driven high enough to make the
  joint occupancy material — e.g. bias re-stem selection away from recently-added
  outbound peers, or require ≥2 *established* stem peers before arming.
- **W2 fan-out.** Reopen if the netted §6.8 metric shows the fan-out cost exceeds
  the leak benefit at any *supported* topology (clearnet included, per the frozen
  default).
- **Coupling note — the outbound structure read on two channels (net, don't
  double-count).** Two *distinct* source facts both flow from the origin's use of
  outbound connections: fluff is outbound-only on Tor
  ([levin_notify.cpp:448](../../src/cryptonote_protocol/levin_notify.cpp#L448)),
  which makes the inbound passive supernode structurally absent (§6.3, reshape's
  *friend*); and the stem pool is the outbound set
  (dandelionpp.cpp:103,
  [`:152`](../../src/cryptonote_protocol/levin_notify.cpp#L152)), which is what W3
  occupies. They are related but **not the same fact**, and the earlier "W3's
  residual is *worse* than independence" reading was **backwards**: drawing two
  *distinct* slots from a finite pool is anti-correlated, so W3 sits *below* the
  independent draw, not above it (§12.6). W3's lever is not slot-correlation but
  **outbound enrichment** — raising the per-slot share `g` — and that is the
  *costly* direction, the opposite of the cheap inbound reach Tor collapses, so
  **Tor does not remove W3** (an outbound-selected adversary persists on any
  transport). A future round hardening outbound peer selection against enrichment
  (for W3) must still preserve the outbound-only fluff rule Tor's collapse depends
  on — one structure, two channels, netted.
- **HALT.** If any implementation of "the alternate successor" is found to create
  a **new** stem edge — widening the origin's peer set beyond `STEMS` rather than
  reusing an existing `out_mapping_` entry — halt. That is an anonymity
  regression the spec forbids (§12.2.6), not a tuning question. **This HALT must
  bind on the churn-refill path too (§12.6, W3c):** `connection_map::update()`
  already fresh-draws to refill a churned slot
  (dandelionpp.cpp:160) mid-epoch, so an
  alternate that was a stable peer at arming can silently become a fresh
  g-enriched draw before reshape forwards to it. Reusing "`out_mapping_[other]`"
  is not sufficient if the peer *in* that slot was re-rolled by churn.

**Deferred to implementation (RP-2+, with its own design round per rule 20):**
the actual re-stem wiring in `levin_notify` / `tx_pool`, the tx-hash-keyed retry
store, and the `out_mapping_` alternate-selection helper. This section specifies
*what* must hold; the *how* is a later PR. Acceptance gates: W1 and W6 (closed by
spec — the PR must not reintroduce a `get_stem(nil)` re-entry or a wire retry
counter); **W3/W3b, whose two-slot occupancy instrument is now built and green
(§12.6)** — RP-2 must not regress it; and **W3c (§12.6): reshape's alternate must
be stable across a mid-epoch churn refill, or a refilled slot must be ineligible as
a reshape target within the epoch** — so the re-stem never lands on a fresh
`update()` draw. *Superseded framing (§14):* the
instrument no longer gates *adopting* reshape — §14 adopts it unconditionally as a
strict priority-order improvement — it only quantifies the irreducible W3
residual, which is the sole `δ` left to bound.

### 12.6 W3 residual — measured (Round-3 build 1)

`simulate_two_slot_occupancy` (`two_slot_occupancy_is_the_reshape_residual`)
measures `P(both outbound stem slots adversarial)` at `D_out = 12`
(`P2P_DEFAULT_CONNECTIONS_COUNT`), over the adversary's *outbound* share `g` — the
capability the channel actually requires, not the inbound reach (see the phantom
correction in §12.5):

| `g` (outbound share) | peers `a` | **W3 = P(both slots)** | P(≥1 slot) | independent `(a/D)²` |
| --- | --- | --- | --- | --- |
| 0.10 (= baseline `f`) | 1 | **0.0000** | 0.167 | 0.007 |
| 0.20 | 2 | 0.015 | 0.318 | 0.028 |
| 0.30 | 4 | **0.091** | 0.576 | 0.111 |
| 0.50 | 6 | 0.228 | 0.772 | 0.250 |

Three results, each against the argued framing this section previously carried:

1. **Baseline W3 ≈ 0, not `p²`.** At `g = f = 0.10` the adversary holds ~1 of 12
   outbound peers and *cannot* fill two slots, so W3 is essentially zero — *below*
   `p² = 0.01`, refuting the earlier "bounded below by `p²`."
2. **W3 is bounded *above* by the independent draw, not below it.** Selecting two
   *distinct* slots without replacement is anti-correlated, so `W3 < (a/D)²` at
   every `g` — the "worse than independence" reading was backwards.
3. **W3 rises with `g`, and `g` is the outbound-selection share — not `f`.**
   Lifting W3 to ~0.09 needs `g = 0.30` (4 of 12 outbound peers); to ~0.23 needs
   `g = 0.50`. W3b's ceiling is the `P(≥1 slot)` column, itself gated on an
   additional induced-churn capability. The magnitude of `g` is the whole
   question — see below.

*Correction (numbers revised upward):* building the Q1 layering instrument (§12.8)
surfaced an off-by-one in `simulate_two_slot_occupancy` — `bounded_uniform` is
inclusive `[0, max]`, so the first slot was drawn over `d + 1` values, understating
W3. Corrected, the table now matches the exact hypergeometric `C(a,2)/C(d,2)` to the
digit (0.30 → `6/66 = 0.091`, was 0.077; 0.50 → `15/66 = 0.228`, was 0.192). The
*direction* of all three conclusions is unchanged; the residual is slightly larger
than first reported, which only sharpens the point that `g`, not the count, is the
lever.

**The reading, not the table, is where the honesty gap is — and it is the
phantom one level up.** The table is a function of `g`, the adversary's share of
the origin's *outbound* pool, and **`g` is not bounded by `f`**, the network-wide
adversary fraction. The outbound pool of 12 is filled **70 % from the white list
plus 2 anchors** (`P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT = 70`,
`P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT = 2`,
[cryptonote_config.h:144](../../src/cryptonote_config.h#L144)), and the white list
is populated by gossiped / handshaked addresses — the adversarially-shapeable
surface the anchor and white/gray machinery *exist to resist*. So `g` is an
*outcome* of peerlist composition, and an eclipse-capable adversary who poisons
the origin's white list drives `g` **above** `f` by cheap address-gossip flooding.
Reading `g ≈ f` here repeats, one level up, the phantom §12.5 just corrected:
treating a *selected*, adversarially-fed pool's occupancy as its network average.

**So W3's "small" verdict is conditional, and the condition is not settled here.**
W3 ≈ 0 holds under *honest* peer selection (`g ≈ f`); the `g = 0.30 → 0.091` and
`g = 0.50 → 0.228` rows are what an eclipse-capable adversary *buys*. W3's residual
is therefore **inherited from the eclipse-resistance of outbound peer selection**
(the anchor count, the white/gray discipline, IP-group diversity), and this
instrument measures `W3(g)` **without bounding `g`**. That bound is a *separate
grounding owed by the peer-selection / anti-eclipse posture* — a p2p-subsystem
question, not a relay-timing one — and it does not yet exist. Until it does, **W3's
operative value is unknown above `g = f`**: the true seal-condition of the W3 gate
lives partly in the peerlist subsystem, and §12.6 must not pretend it lives
entirely here (the true-seal-in-the-join guard).

**Consequence for `ρ` — it is blocked, not decided.** `ρ` must be taken against the
largest `g` the anti-eclipse posture can *rule out*, not against `g = f` by
default. If a grounding bounds a non-Sybil adversary to some `g_max`, `ρ` is
decided against `W3(g_max)` with margin. **It cannot bound `g` from what is in the
tree today, so `ρ` is not decided this round — it is blocked on the
outbound-selection eclipse bound (Q-10, §7).** That blocked state is the honest
output; a `ρ` chosen against `g = f` would rest on an assumption the source shows
to be false. The measured `W3(g)` table stands; what is deferred is *which row we
live on*, and the peerlist subsystem gates that, not this instrument.

**W3c — reshape's re-stem target: zero under a *stable* map, `≈ g` under churn
refill, and the churn case is the reshape case.** A natural worry (the same `g`
that threatens W3 also enriches reshape's re-stem target): does the two-slot count
*undercount* by ignoring the re-stem target? **On a stable epoch map it does not** —
the alternate is the fixed second `out_mapping_` slot (§12.2.3), one of the two
slots §12.6 already counts, so reshape leaks iff **both** slots are adversarial (W3),
with no third peer to add a separate `P(re-stem target adversarial) ≈ g`.

**But "the fixed second slot" is fixed only while the map is stable, and the tree
already fresh-draws on churn.** `connection_map::update()`
nils a churned slot (:144) and refills it with
a fresh `crypto::rand_idx` draw from the current outbound pool
(:160); it runs **mid-epoch**, dispatched from
[`new_out_connection` → `update_channels`](../../src/cryptonote_protocol/levin_notify.cpp#L762)
when a replacement outbound peer connects. (`get_stem`'s nil branch
:195 additionally re-maps a source onto the
*other* existing slot via `select_stem` — no fresh peer, but it too breaks slot
stability.) So on churn the alternate can be a **fresh g-enriched draw** — exactly
the fresh-draw case that resurrects `W3c ≈ g`.

**And this is the operative case, not the edge case, because churn correlates with
the reshape trigger.** The embargo fires because a successor went dark; a
disconnected successor is precisely what `update()` nils and refills. An adversary
who *is* the dropping successor, or who induces churn on the origin's stem peer,
forces a fresh g-enriched refill — and can do so *repeatedly*, re-rolling the
enriched draw within an epoch, which is strictly more capability than one-shot
peerlist poisoning. So `W3c ≈ g` reappears in exactly the adversary-triggered
black-hole scenario reshape exists to handle.

**Disposition and the RP-2 checks this adds.** The no-fresh-draw rule is still
correct, but it must bind on the **churn-refill path (`update()`), not only the
reshape-forward path** — the tree fresh-draws where the §12.2.6 HALT was not
looking. So the RP-2 acceptance gains a **sibling** to "reshape forwards to the
fixed alternate index": *reshape's alternate must be stable across a mid-epoch
churn refill — or a refilled slot must not be eligible as a reshape target within
the same epoch* — because an implementation can otherwise satisfy the letter of
"forward to `out_mapping_[other]`" while `out_mapping_[other]` is silently a fresh
draw. This also tightens Q-10: the `g`-bound it owes is a bound under *repeated
adversary-induced refills*, not a single draw (see §7).

### 12.7 Why `STEMS = 2` — the expander-minimum, and why the occupancy attack cannot be fixed by raising it

`CRYPTONOTE_DANDELIONPP_STEMS = 2` is a **bare inherited constant**
([cryptonote_config.h:101](../../src/cryptonote_config.h#L101): `2 // number of
outgoing stem connections per epoch`), sitting directly above the 39 s embargo
(line 106) with the same absence of justification F-1 exposed. Unlike the 39 s,
**the 2 is correct** — but for a reason the tree does not record, and an unrecorded
reason is exactly how the 39 s survived. It is the 39 s's *mirror image*, and more
dangerous in one specific way: a *correct* undocumented constant invites a
well-meaning "improvement" that a wrong one would have invited a fix for. So it must
carry its derivation.

**The 2 is the stem graph's out-degree (branching factor), not "two successors to
pick from."** It is the corner solution of two opposing pressures, and it lands at 2
because 2 is a *topological threshold*, not a tuning preference:

- **Privacy wants 1.** A pure line graph — each node forwards to exactly one fixed
  successor — is the most private honest-case topology: a single thin thread,
  maximal anonymity-set per hop, the least for the backward-wave / first-spy
  estimator to work with. Privacy-max, taken alone, would choose out-degree 1.
- **But out-degree 1 is a black hole's paradise.** A functional graph (every node →
  one successor) is a set of paths and cycles with a **single point of failure per
  stem**: one black-holing node severs the entire stem below it, and the only
  recovery is the embargo timeout → fluff. `STEMS = 1` makes the black-hole attack
  maximally effective — one well-placed dropper kills a whole line.
- **Out-degree ≥ 3 fans the stem toward a tree — a privacy regression.** Every extra
  outgoing stem edge is another node observing your traffic *close to the source*,
  and the paper's guarantee rests on the stem being approximately a **line** so the
  fluff point is genuinely displaced from the origin along a single path. A high
  branching factor fans the tx out early, hands the first-spy estimator more
  early-position samples (the §6.5 channel), and trades privacy for robustness —
  backwards for a privacy-max system.
- **2 is the minimum that buys graph properties instead of line/tree properties.**
  The paper's construction (§11) is an approximately **4-regular** anonymity graph —
  2 in + 2 out per node — chosen because a random 4-regular graph is, with high
  probability, an **expander**: no small cuts (you cannot sever the stem network by
  removing a few nodes) and short average path length (the stem still completes
  quickly). `STEMS = 2` is the **smallest** out-degree at which the stem topology
  stops being severable lines and becomes a low-degree expander — the minimum
  robustness privacy can afford, one edge past which is pure privacy cost.

**The consequence for this arc — and why the seal is `g_max`, not STEMS.** The
demonstrated occupancy attack (W3 / ProxyMark, §12.6) is tractable *because*
`STEMS = 2` — "occupy the target's two outgoing stem slots" is only two to occupy.
The naive fix is "raise STEMS so both-slot occupancy is harder." **That is backwards
on the privacy axis:** raising STEMS fans the stem toward a tree and leaks *more* to
the first-spy channel, and it moves the topology off the expander-minimum. You
cannot fix the occupancy attack by widening the stem, because widening the stem is
itself the privacy regression the count is set to avoid. The count is correctly 2
and pinned by the privacy/robustness corner; the vulnerability is entirely in **who
gets to be the two** — the selection layer (`g`, anchors, anti-eclipse), not the
count layer. That is precisely why Round 3's seal landed on `g_max` (§7, Q-10) and
not on STEMS: the branching factor is not the free variable; peer selection is.

**Guard (matching the 39 s treatment).** `STEMS = 2` must not change without
*re-deriving the expander property and re-pricing the first-spy fan-out*. A
contributor looking at the ProxyMark attack must not "fix" it by bumping STEMS to 4
— that trades a demonstrated active attack for an undemonstrated-but-real passive
leak and moves off the expander-minimum. The constant now carries this reasoning
here, at its C++ definition site, and on the `StemGraph::QuasiFourRegular` variant
the crate uses.

### 12.8 Rotation-mechanism grounding (the substrate the Q-10 round rests on)

Grounded at source before any spec, per the arc's discipline. These four facts are
durable independent of which pinning architecture wins; the Q-10 design (§7) sits on
them.

**G-1 — stem *selection* is public/clearnet-zone only; and Tor is *not* safer on
the occupancy axis — it has no occupancy mechanism at all.** `send_txs`
([levin_notify.cpp:840-851](../../src/cryptonote_protocol/levin_notify.cpp#L840))
routes noise zones (Tor/I2P) through the covert noise channel and **converts a
`stem` relay to `local`** ("Dandelion++ stem not supported over noise networks");
only the public zone runs `dandelionpp_notify` → `get_stem` → `out_mapping_`
selection. So the `out_mapping_` occupancy surface — W3/W3c, `g_max`, the entire
Q-10 target — is a **clearnet mechanism**.

**Do not read "no public `out_mapping_` on Tor" as "Tor is safer on occupancy"** —
that is the arc's first finding (a mechanism's protection is defined by the
*specific* adversary and observable) re-committed at the transport layer, and it is
wrong. The occupancy attack is a **peer-as-adversary** threat: the adversary is one
of your outbound endpoints and reads what you originate. Two orthogonal threats,
and only one gets a mechanism on Tor:

- **Channel observer** (ISP, entry guard, circuit-level traffic analysis) — sees
  the *wire*, not the content. The noise channel (constant-rate cover) defends this,
  legitimately and arguably better than clearnet's jitter. The source comment says
  exactly this: *"good protection against ISP adversaries, but not sybil
  adversaries"* ([levin_notify.cpp:829-833](../../src/cryptonote_protocol/levin_notify.cpp#L829)).
- **Peer as adversary** (the ProxyMark occupier) — is one of your
  `CRYPTONOTE_NOISE_CHANNELS = 2` noise endpoints, **decodes** the covert stream
  (it reassembles and forwards the tx in D++ mode), and reads your originated
  transactions directly. The noise channel is **transparent** to it. Undefended.

And it is *worse* than clearnet on this axis — **the ~2× broadcast penalty, not the
absence of a pool.** Grounded precisely: the 2 noise channels are *selected per
epoch from the ~12-peer Tor outbound pool* (`start_epoch` builds
`connection_map{get_out_connections, count = NOISE_CHANNELS = 2}`; the proxy zone's
`max_out_connection_count` defaults to `P2P_DEFAULT_CONNECTIONS_COUNT = 12`,
[net_node.inl:2683](../../src/p2p/net_node.inl#L2683)) — the *same* 2-from-12
selection structure as clearnet's `out_mapping_`. The difference is the *send*: clearnet
`get_stem` sends the origin's own tx to **one** selected successor, while Tor
**broadcasts it to *both* selected channels**
([send_txs:866-872](../../src/cryptonote_protocol/levin_notify.cpp#L866)). So per
epoch Tor exposes the origin's own-tx stream to **2 of 12**, clearnet to **1 of
12** — Tor is worse by the **broadcast factor (~2×)**, on the *same* pool dilution.
(An earlier draft of this section wrote "no dilution / `D = 2` / undiluted"; that was
wrong — `D_tor ≈ 12` with per-epoch selection, and the penalty is the broadcast, not
a missing pool. The correction came from grounding Tor first, exactly as Q4 requires.)
So the `D/K` pinning analysis (§12.8 Q1) applies on Tor too, with `D_tor ≈ 12`, *plus*
the 2× broadcast; and the Q-10 occupancy work is still what the Tor path needs
*most*, because the broadcast doubles the exposure and the noise channel's genuine
strength on the *other* axis is exactly what camouflages it. And the broadcast is not
a Tor property to patch but a **fork artifact** — the covert path lost the selection
the public path has — so the fix is not a Tor-specific tweak but the *one unified
mechanism* of §12.9, under which the broadcast disappears as a consequence.

*Reconciliation with §6.5/§6.6 (verified at source; those sections are already
pushed):* they model the **fluff phase's** inbound observability — the
*channel-observer* axis — transport-gated at
[levin_notify.cpp:448](../../src/cryptonote_protocol/levin_notify.cpp#L448)
(`fluff_notify` runs per-zone; on Tor it fluffs outbound-only). That is a *different
phase and a different axis* from stem occupancy, so §6.5's "Tor collapses the
inbound supernode" is correct **for the channel-observer axis** and must not be read
as occupancy-axis protection: on the peer-as-adversary axis Tor is *weaker*, per the
above. §6.5's "Tor is the recommended configuration" therefore carries an implicit
axis qualifier that this grounding makes explicit — stronger on the wire/fluff
observer, weaker on the peer-decoder — and the Q-10 occupancy work is what the Tor
path needs *most*, not least.

**G-2 — two re-roll paths, and the churn one fires on exactly the black-hole
trigger.** (a) *Epoch boundary:* `change_channels`
([levin_notify.cpp:587-617](../../src/cryptonote_protocol/levin_notify.cpp#L587))
**replaces the whole `connection_map` with a fresh rebuild** every ~10 min
(`MIN_EPOCH = 10`, `EPOCH_RANGE = 30 s`) — the deliberate per-epoch rotation, and
the cross-epoch independence §6.8's intersection defence rests on. (b) *Mid-epoch
churn:* `update_channels::run` → `map.update()`
([levin_notify.cpp:528-536](../../src/cryptonote_protocol/levin_notify.cpp#L528),
the fresh-draw refill at dandelionpp.cpp:160)
fires on the **stem-send-*failure* retry**
([dandelionpp_notify:575](../../src/cryptonote_protocol/levin_notify.cpp#L575),
"connection list may be outdated, try again") and on `new_out_connection`
([net_node.inl:1349](../../src/p2p/net_node.inl#L1349)). So the W3c re-roll is
triggered by exactly the successor-unreachable case that correlates with the
black-hole / reshape trigger — grounding the §12.6 coupling at its firing site.

**G-3 — the stem pool is all synced outbound, anchors included.**
`get_out_connections`
([levin_notify.cpp:142-159](../../src/cryptonote_protocol/levin_notify.cpp#L142))
returns every `!m_is_income` peer at height ≥ local; `out_mapping_` selects
`STEMS = 2` from it. Anchors are outbound connections, so they sit **inside** the
stem-eligible pool — the mechanism behind the `anchors = 2 ∥ STEMS = 2` hazard.

**G-4 — anchor admission is *any* successful outbound handshake — no behavioural
criterion.** `append_with_peer_anchor`
([net_node.inl:1347](../../src/p2p/net_node.inl#L1347)) is called on **every**
successful outbound handshake, unconditionally; on reconnect the 2 anchor slots are
filled *first* ([net_node.inl:1820](../../src/p2p/net_node.inl#L1820)), then white
(~70 %), then grey. So anchors are a **weak persistent pin populated by any
accepted peer**, not a behavioural-floor pin.

**What the grounding decides for the Q-10 design (framing, not spec):**

- **Q2 is an admission-policy *mismatch*, not a coincidence hazard (lead with this
  — it is grounded and immediate).** Because anchor admission is unfiltered (G-4),
  "extend anchors into stem-eligibility pinning" would import an *unfiltered*
  admission rule into the exact place the design needs a *filtered*
  (behavioural-floor-gated) one. So the stem-eligibility pin must be a **separate,
  stricter layer**, and `anchors = 2 ∥ STEMS = 2` (G-3) must be **broken** — an
  anchor must not auto-confer stem-eligibility.
- **Q1 — measured (`epoch_layering_pinning_amplifies_direct_successor_exposure`):
  pinning to a small `K` is *not* free, and the sign is negative on the axis that
  matters.** Pinning the eligible set to `K` and selecting `STEMS = 2` within it per
  epoch closes the churn re-roll (G-2b: `update()` draws from the pinned set, not
  the enrichable pool), but the cross-epoch successor is then drawn from `K` instead
  of the ~12-pool. The discriminating measurement — an adversary holding a fixed
  peer count `a`, pool (`D = 12`) vs. pinned (`K`) — resolves the two axes:
  - **Direct-successor exposure (occupancy / C1, dominant — precision-1 ID):**
    per-epoch presence is `a/set`, so shrinking `D → K` **amplifies** a captured
    slot by exactly `D/K` (measured: `K=6` → 2.00×, `K=4` → 3.01×, `K=3` → 4.01×,
    `K=2` → 6.01×). A single pinned adversary's presence rises from `1/12` to `1/K`,
    and its P(identified-as-successor over 30 epochs) from 0.93 to ~1.0.
  - **Cross-epoch diversity (intersection, §6.8, secondary):** the pinned set uses
    far fewer distinct successors (11.1 → 3.0 at `K=3`), which *slows* the §6.8
    collapse toward `{origin}` — protective, but it does not offset the dominant
    precision-1 direct-successor amplification.

  So the earlier temptation — "pinning folds occupancy and intersection into one
  bound, a simplification" — is **refuted by measurement**: the collapse is not
  conservative; small `K` *concentrates* the occupancy risk (`D/K`) while only
  helping the weaker axis. **Q1's resolution:** pinning the eligible set is safe only
  if `K` is not `≪ D`, **or** the pin-admission bound (`g_max`, Q4) makes holding `a`
  slots in `K` harder than in `D` by *more than `D/K`*. The layering choice cannot be
  made without the admission bound.

  **The coupling — `D/K` and admission are one constraint, not two gates.** "Safe if
  admission beats `D/K`" reads as two gates you satisfy separately; they are the same
  small-`K` driving both, and they multiply. Admission bounds `g` *at pin formation*,
  but the pin is formed from the enrichable peerlist, and any admission criterion is a
  target the adversary optimises toward (the arc's standing result). So the real
  quantity is not "does admission beat `D/K` against a fixed adversary" — it is "does
  admission beat `D/K` against an adversary *specifically optimising to pass admission
  into the small `K`*." Shrinking `K` makes that **harder**, because each captured
  slot is a larger fraction of a smaller set, so there is more optimisation pressure
  per slot. Tighter pinning raises `D/K` **and** raises the admission difficulty — one
  coupled constraint where small `K` worsens both sides. Q4 must size the admission
  bound against a `D/K` that admission itself is making harder to clear, or it will
  size against the wrong (easier) adversary.

  **Q4 tee-up — ground admission on Tor *first*, and check whether a filter can exist
  there at all before sizing one.** Two reasons, both grounded here: (i) Tor is worse
  on occupancy (the ~2× broadcast, G-1), and it is where the demonstrated attack
  lives, so a filter designed on clearnet's `D = 12` and "extended to Tor" repeats the
  clearnet-first/Tor-as-afterthought pattern that produced the original hole; (ii) on
  Tor the address layer offers **no scarce, forge-resistant signal** — onion addresses
  are free, unlimited, positionless, and subnet/ASN do not exist — so a
  stricter-than-anchor admission filter can key on almost nothing there. It cannot key
  on address/subnet/position; behaviour is *eviction* (the dropper floor), not
  admission, and a patient adversary passes it; that leaves only relationship history
  / proof-of-prior-useful-work (has this onion peer demonstrably relayed for me
  before). **This worry is RESOLVED in §12.10** — the "structural not policy" outcome
  was reached by treating admission as *identity*-filtering (which onion defeats). But
  admission is *select-toward-demonstrated-work*, and relationship-history /
  demonstrated-propagation is not a thin last resort — it is *the* signal, correctly
  signed for disruption, transport-blind (work, not identity), and it *conscripts*
  the observer rather than failing to exclude it. So admission-as-policy **is** viable
  on Tor. What remains below is the original framing, kept for the reasoning trail;
  read it through §12.10. **The honest possible outcome (superseded by §12.10):** no
  admission filter beats `D/K` on a broadcast-to-2 target keying only on
  forgeable-onion-address-plus-behaviour — in which case Q4's answer for Tor is *not*
  a `g_max` number but a **structural finding**: the occupancy fix is architectural,
  not policy — and §12.9 states what that architecture is. (The "is broadcast
  load-bearing for cover uniformity?"
  question raised in an earlier draft is **resolved and closed**: `send_noise` pads
  every channel to a constant rate on its own timer
  [levin_notify.cpp:663](../../src/cryptonote_protocol/levin_notify.cpp#L663), so
  broadcast-to-2 buys *nothing* on the observation axis — it is a fork artifact, not
  a cover feature. See §12.9.)

### 12.9 The transport is a *parameter*, not a *branch* — one mechanism, no fork

The decomposition the whole occupancy arc lands on: **medium is observation,
mechanism is robustness, and they are orthogonal axes.** The medium (public vs
Tor/I2P) does exactly one thing — expose or hide the *wire* to an *external*
observer — and that is entirely on the axis §6.9 scoped out. The mechanism
(selection dilutes occupancy, embargo backstops black-holes, reshape routes around
droppers, admission bounds `g_max`) is the robustness axis, and it is **medium-blind
by construction**: it was never about the thing the medium changes. So "does the
mechanism need a Tor version?" is malformed — the medium doesn't touch the axis the
mechanism operates on.

**The `MWARNING("Dandelion++ stem not supported over noise networks")`
([levin_notify.cpp:849](../../src/cryptonote_protocol/levin_notify.cpp#L849)) is the
fork point** — the line where the inherited design said "I am a separate path now,"
and everything downstream of it is a *second copy diverging from the first*: no
`get_stem` selection, no embargo, no reshape, broadcast-to-2 instead of send-to-one.
**The demonstrated attack exists because of that fork**: the split let the covert
path *lose the occupancy dilution the public path had*. And the reference's stated
obstacle — "the mempool/stempool needs to know the zone a tx originated from to work
properly" ([levin_notify.cpp:836-838](../../src/cryptonote_protocol/levin_notify.cpp#L836))
— is *fork-reconciliation bookkeeping*: it is hard only because there are two paths
to keep agreeing about origin-zone. It largely dissolves under one mechanism, where
the zone is not a branch but a **parameter** telling the single mechanism which pool
to select from and which admission signal to read.

**The architecture, stated once:** one medium-blind occupancy/robustness mechanism —
select a successor from the origin's outbound pool, embargo-backstop, reshape,
admission-bound `g_max` — running identically regardless of origin zone. The **only**
legitimately medium-dependent input is *what admission keys on*, because the
transport exposes a different identifier (onion carries no position; IP carries
broken position). That is a **parameter to the one mechanism, not a fork of it**:
"the mechanism, reading whatever identifier this transport provides," never "public
mechanism + Tor mechanism." Everything else — selection, embargo, reshape, the
`g_max` bound itself — is transport-invisible. Under this mechanism the broadcast-to-2
disappears as a *consequence* (the unified mechanism selects, like the public path;
the constant-rate cover traffic then simply wraps the *selected* send on Tor, an
orthogonal transport-layer concern on the observation axis).

**Why this is the structural-enforcement move, not a preference.** Same discipline
as the `derive.rs` block-time guard and the no-wire-position-field HALT: do not rely
on two copies of a protocol staying in sync by review vigilance — make them **one
copy**, so "the covert path forgot what the public path does" is not a state that can
occur. Unifying deletes the fork, and with it deletes the entire *category* of the
demonstrated attack. It also collapses Q4: it is a **single admission problem** — one
mechanism to bound, reading a transport-dependent signal — not a per-transport pair
to keep in sync. *(Implementation is RP-2+: unify the stem mechanism onto the
anonymity zone, replacing the `MWARNING` fork; the zone survives only as the
pool-and-signal parameter. The `g_max` admission bound Q4 owes — reframed in §12.10 —
is then one bound, keyed on the same medium-blind signal on both transports.)*

### 12.10 `g_max` reframed — select toward demonstrated work, not distinguish adversary from honest

The §6.10 conscription insight applied to admission, correctly signed this time (an
earlier draft filed "the positive signal recruits the patient observer" as a *cost*
— that was the out-of-scope observer dragged back in; the recruiting is the
**objective**). It resolves the pin-vs-churn fork and the §12.8 Tor-admission worry
together.

**Admission is *select-toward-demonstrated-work*, not distinguish-adversary.** The
"distinguish" framing is what drags the out-of-scope observer back in — it should
*not* try to tell adversary from honest. The admissible signal is **demonstrated
propagation / relationship history**: it demands work from *both*, excludes the one
that structurally *cannot* produce it (a disruptor — dropping is the exact opposite
of the signal), and **conscripts** the one that can (the observer earns its vantage
by relaying, on pain of eviction — HUMINT: you don't deny the source you can't deny,
you make being that source cost more than it is worth and get its work in the
bargain). One mechanism, two edges: **admit on demonstrated propagation, evict on
demonstrated dropping** — stem-eligibility as a standing, revocable toll paid in
relay work (the signal and the selection rule are specified in §12.11). It is **transport-blind** (work, not identity), which resolves the §12.8
worry: onion gives *identity*-admission nothing, but *work*-admission everything, on
both transports identically.

**Two `g_max`, and the split is what was mis-computed.** *Observational* `g_max`
(share to occupy-to-**observe**) is out of scope (§6.9, unstoppable) and is the one
pool share governs — so bounding pool-share `g` was bounding the wrong quantity.
*Disruptive* `g_max` (share to occupy-to-**disrupt**) is in scope, and it splits into
**three regimes**:

| regime | in scope? | bounded by | pool-share dependent? |
| --- | --- | --- | --- |
| Observation (any share) | no (§6.9) | — (conceded; the signal *taxes* it) | — |
| Partial disruption (some slots) | yes → **delay only** | the backstop (§14) reduces censorship to delay; the signal + eviction bound the delay-*surface* = **eviction responsiveness × re-entry cost** | **no** |
| Full eclipse (all of O's outbound) | yes → **censorship** | backstop *fails* (no honest path: reshape's alternate and the fluff peers are all adversarial) → **anti-eclipse** = anchors + the conscription cost the signal imposes | **yes** |

So the pool-share bound does **not** fully dissolve: it is out of scope for
observation, backstop-dissolved for partial disruption, and **survives for full
eclipse** — but reframed from "how cheap is enrichment" to "how expensive is it to
*conscript* enough of O's outbound (past the anchors) to eclipse." The positive
signal helps all three (taxes observation, excludes indiscriminate droppers, raises
eclipse cost from enrichment to conscription) but eliminates pool-share only for the
first two.

**This makes pinning safe and dissolves the D/K worry.** Pinning was dangerous only
under "durable slot = durable adversary *vantage*" — the observation worry, out of
scope. Under occupancy-as-conscription, a durable slot held by a peer that must
continuously demonstrate propagation to keep it is the *best* state: a stable tier of
nodes all meeting a high propagation bar as the condition of tenure, evicted the
instant they lapse. The `D/K` amplification was occupancy-as-*observation*; under
occupancy-as-*conscription* a captured slot is one whose holder is forced to relay
flawlessly — which is what you wanted from the slot. And the observer is not
*upgraded*: slot-observation (precision-1) was always achievable via occupancy (that
*is* `g_max`); the signal only taxes its acquisition (cheap enrichment → expensive
conscription), which is costless-or-better on the out-of-scope axis.

**So Q4's deliverable is reframed — two well-posed bounds, not a pool-share `g`:**
(1) the eviction floor's **responsiveness** (and the signal's re-entry cost), which
bounds the partial-disruption delay-surface; and (2) **eclipse-resistance as
conscription cost** (anchors + how expensive it is to conscript enough of O's
outbound), which bounds full-eclipse censorship. Both are dramatically better-posed
than "bound pool-share `g`," because the positive signal is doing the work on both.
Select toward demonstrated work; pin the workers; evict the droppers; let the
observer buy lunch and carry freight.

### 12.11 The selection mechanism — epsilon-greedy over the embargo signal (exploit / explore / cool-down)

§12.10 said "admit on demonstrated propagation, evict on demonstrated dropping."
This section specifies *what the signal is* and *how selection reads it*, and every
piece lands on a mechanism already built or fifty years old — no new oracle, no new
constant to guess.

**A. The signal is the embargo — disarm = success, fire = failure, and it cannot be
laundered.** Three candidate success signals, and the black hole's signature in
each:

- *Handoff* (the successor ACKed the bytes): the black hole **aces** it — it
  receives perfectly, it just does not forward. Useless.
- *Reaches-chain (eventual)*: **laundered.** The black hole drops the tx, but an
  upstream embargo fires and re-fluffs it, so it reaches the chain anyway — and the
  signal credits the successor with a success the *backstop* delivered. The
  mechanism that defeats the black hole is the same one that hides it from a
  reaches-chain oracle. Also slow (~120 s) and validity-confounded (a low-fee tx
  fluffs fine but never mines — not the successor's fault).
- *Embargo state*: **un-launderable, because the fire is the detection event
  itself, not an inference about it.** My embargo fires *precisely because* I did
  not observe the tx diffuse in time. Fast disarm (I observed diffusion before my
  timer, ~`F` ≈ 2 s on fluff-observation, RD-1) = the stem worked; fire = the stem
  failed and I am now the backstop. **The backstop and the detector are one
  mechanism** — the fire that rescues the tx is the same event that indicts the
  successor. The reputation oracle is the embargo derived in RD-1/§13; it is not
  validity-confounded (it measures diffusion, not mining), and it costs nothing new.

**The false-positive rate is known, so "rate separates cleanly" is a number.** The
embargo is provisioned to fire on ~10 % of *successfully-propagating* txs — the
preemption rate, `1 − EMBARGO_FULL_TRAVEL_PROBABILITY = 0.10` (the `ε` provisioning).
So an honest successor's fire-rate floor is ≈ 10 % (preemption) + the ambient
downstream-black-hole rate (the **attribution gap**: my fire indicts my successor S,
but if S is honest and forwards to a black hole T, my fire mis-attributes to S). A
black-hole successor fires ≈ 100 %. The floor (~10–15 %) and the black-hole rate
(~100 %) are widely separated, so the per-successor **rate** launders out *both* the
false positives *and* the attribution noise — the same way the backstop laundered
*in* the black hole's success. Single-event eviction was wrong; rate-threshold is
right; and this reconfirms it from the black-hole direction.

**B. Cause-blind outcome-routing, cooldown-not-eviction (the ARPANET lesson).** For
the routing decision the drop *cause* is irrelevant — outcome is everything. A peer
that fails to propagate fails, whether malicious, overloaded, on a dying Tor
circuit, or on hotel wifi; from the tx's view an honestly-broken peer and a black
hole are identical. So prefer-away is correct regardless of cause, and diagnosing
intent is both impossible (the attribution gap) and unnecessary (the response is
identical) — distance-vector routing never asks "malicious or congested." **There is
no separate "malicious" handling** (that would require diagnosing intent, where
BGP-style trust breaks): one rule — *fail → cool down → retest → aggregate the rate*
— produces route-around-the-black-hole and forgive-the-transient as two *emergent*
outcomes. **Cooldown-not-eviction is what makes cause-blindness fair:** honest and
black hole are identical at the failure event (cool both down), and separate over
time by rate (the honest peer recovers, the black hole keeps firing); retained
history snaps the honest peer back to preference on recovery while the black hole's
rate decays it out. This is the **aggregate** layer — it catches the *indiscriminate*
black hole; a peer that drops the *current* tx is caught per-tx by **reshape** (§14),
not the rate signal. (The "content-selective censor that hides under the threshold" is
a phantom — see part D: Shekyl's privacy layer denies the selector, so the only
selective censorship is origin-censorship, which is the occupancy attack reshape
already targets, not a wide content-selective gap.)

**C. Epsilon-greedy exploration — pure preference ossifies to a *self-inflicted
eclipse*.** Pure exploit (`ε_explore = 0`) selects the top-2 track-record peers
*every time* — measured: the stem graph collapses to **2 of 12 peers and stays
there**. That is not a tendency, it is total, and it is a privacy failure disguised
as a stability success: it collapses the origin's *eligible pool* from 12 to 2,
which makes **full eclipse trivial** — the eclipse target (§12.10 regime 3, the one
surviving pool-share bound) drops from "conscript ~12 of O's outbound" to "be the 2
O actually uses." Even a small explore rate repairs it: `ε_explore = 0.05` restores
**all 12 peers exercised**. So exploration is the anti-ossification input that keeps
the eclipse-resistance bound *meaningful* — an ossified pool has trivial eclipse
resistance regardless of anti-eclipse policy. This is **epsilon-greedy**, and
`ε ≈ 0.05` is not a new guess: it is the classic RL/routing epsilon, derived against
this exact explore/exploit trade-off fifty years ago.

**The unified three-tier selection:**

| tier | pool | rule | role |
| --- | --- | --- | --- |
| **Exploit** (majority of slots) | eligible peers | prefer embargo-disarm rate | stability / conscription (§12.10) |
| **Explore** (`ε ≈ 0.05`, memoryless) | eligible-but-**non-top** | uniform random | restores full-pool diversity → eclipse-resistance (§12.10 regime 3); **is** the bootstrap channel — how an unproven honest peer earns its first embargo-disarm |
| **Excluded** | cooled-down (recently-fired) | — | not eligible for *either* tier until cooldown expires |

Explore *is* §12.10's re-entry cost / unknown-baseline — `ε` sets both bootstrap
generosity and whitewash cost simultaneously, which is why the **cooled-down set is
excluded from explore**: explore among the *unproven*, never the *failed*, or
exploration becomes the whitewash/eviction-launderer (drop → cooldown →
explore-re-admits-before-proven). Three adversarial edges on exploration, all
required:

1. **No re-admit on explore** — draw explore targets from eligible-non-top only,
   never the cooled-down set (above).
2. **Memoryless explore timing** — per-epoch probability `ε`, *not* every-`1/ε`
   epochs; otherwise the explore-slot is a timing fingerprint (it is the slot most
   likely to be a fresh/random peer). A direct port of D-3 (the memoryless fluff
   delay) to the selection layer.
3. **Diffusion-vs-concentration documented** — exploration spreads stem traffic
   across more peers over time, trading a *small* increase in passive-observer
   diffusion (more peers each see a little) for a *large* decrease in occupancy
   concentration (few peers see everything). Net-correct for the threat model: it
   helps against the **occupier** (the demonstrated ProxyMark threat, in scope) and
   only slightly helps the **sampler** (the out-of-scope passive observer). Document
   it so nobody later reads "exploration = more peers see my traffic" as a pure
   regression.

**D. The eviction threshold is derived against the *ambient* honest floor — because
the two adversarial edges collapse under "how," and the system already prices them.**
The threshold's honest floor is *not* adversarially inflatable at a new/cheap cost,
and there is *not* a wide content-selective-censor gap beneath it — two claims that
look plausible until you name the capability each requires (the arc's grounding
discipline, applied in the threat direction, where it is easiest to inflate a
threshold against a phantom):

- **"Induced eviction" (inflate honest S's fire-rate) collapses into the occupancy /
  eclipse bound already priced.** To make S's forwarded tx fail to diffuse, the
  adversary must drop it *below* S (occupy the slot below S — the occupancy attack)
  or suppress the predecessor's diffusion-observation *from every path* (eclipse the
  predecessor — the embargo disarms on diffusion from *any* direction, and a
  few-second delay is nothing against the ~112 s window). A sybil not *on* the tx's
  path cannot drop that tx. So inflating S's floor costs exactly the occupancy/eclipse
  budget §12.10 regime 3 already bounds — **pricing it again in the threshold
  double-counts one capability.** The honest floor is therefore preemption + *genuine
  background* downstream failure (a real, measurable network quantity), not
  preemption plus an adversarial dial.
- **The content-selective censor needs a selector Shekyl's privacy layer erases.**
  FCMP++, confidential amounts, and stealth addresses leave the stem-phase censor an
  encrypted blob with no visible sender, recipient, or amount — *no property to select
  on*. The only visible attributes are: predecessor identity (→ origin/node
  censorship, which is occupancy, and *self-defeating* at the direct-successor
  position because the victim origin sees ~100 % fire-rate from that successor and
  evicts it); and coarse structural/economic fields (tx shape / input-output count if
  unpadded, fee if public) — which permit "censor large txs / low-fee txs" but **not**
  victim-targeting, and are still occupancy-limited and rate-caught. So *every* visible
  selector is occupancy + rate-caught or coarse-non-targeting; the "suppress this
  victim while hiding under the threshold" scenario has **no input**.

**Consequence for the threshold (the 39 s lesson, threat-direction).** The threshold
is a *derivation* against the ambient floor — above (preemption + genuine background
failure), below the indiscriminate-black-hole rate (~100 %) — and it must **not** be
inflated against the induced-eviction floor (double-counts occupancy) nor widened to
leave a large reshape gap for a content-selective censor (which does not exist). The
clean ~10–15 %-vs-~100 % separation is the correct one; the inflated floor was the
phantom. **System-composition principle, stated for the next reviewer:** an adversarial
edge on one mechanism must be grounded by naming the capability it requires; if that
capability is already *priced* by another subsystem (the occupancy/eclipse bound) or
*denied* by another (FCMP++'s confidentiality), it must not be re-defended here — that
is double-counting, and it over-provisions this mechanism's parameters against a
straw adversary. Protection composes; explore every attack, but pay for each capability
once.

**What is measured vs. owed.** The `ε_explore = 0 → 2`, `0.05 → 12` result is now
**reproduced in-crate** (`simulate_epsilon_greedy_selection` /
`epsilon_greedy_pure_preference_ossifies_to_two_peers`), per the §13.5 discipline: pure
exploit ossifies to exactly `STEMS = 2` distinct peers, `ε = 0.05` restores all 12, and
the top-2 still carry ~97.5 % of traffic — so exploration buys full-pool diversity and
the `ε/2` eclipse-escape, not a bulk redistribution. No induced-failure dial was added
(part D: that priced a phantom). The
parameters this specifies are the concrete form of §12.10's two bounds: **cooldown
length + rate-decay threshold** (eviction responsiveness; the threshold clears the
*genuine ambient* honest floor — preemption + real background downstream failure, per
part D — and sits well below the ~100 % indiscriminate-black-hole rate; it is **not**
sized against an induced-eviction floor, which double-counts occupancy) and
**`ε_explore` + retained history** (re-entry cost / bootstrap-vs-whitewash). Derive
them against the honest-recovery vs black-hole-delay vs false-eviction trade-off —
measure, don't pick. The instrument owes the *genuine background failure rate* as the
threshold's real input (a topology measurement, like `F` and hop latency); it does
**not** owe an "induced-failure dial" row — that dial priced a phantom (part D).

**Handoff to RP-2 — two owed measurements, one a reopen-checkpoint not a sweep.**
The `ε → distinct-peers` and top-2-share numbers are in-crate; what remains is
RP-2-adjacent and must be inherited honestly:

- **First move: re-census the anchors before wiring.** §§12.8–12.11 are grounded
  against `get_stem` / `out_mapping_` / the embargo-disarm behaviour of a dev tree
  that will have moved by the time RP-2 begins (staking-consensus work is landing in
  parallel). "Grounded three weeks ago" is exactly the stale-gate class this arc kept
  catching — not a concern with the design, but a reminder that the design's anchors
  decay at the tree's rate. Re-verify them at source before building on them.
- **The genuine background-failure rate** is a plain topology measurement (like `F`,
  hop latency, §7 Q-5) — a knob input.
- **The cooldown/threshold sweep is the empirical *validation* of §12.11's separation
  claim, and it can *reopen*.** The whole reputation mechanism rests on the honest
  floor (~10–15 %) sitting well below the indiscriminate-black-hole rate (~100 %).
  That separation was *argued* against a modelled ambient floor; the sweep measures
  it against the *real* one. If the measured ambient floor comes back materially
  higher (real networks are messier than models — say 25 % rather than 10–15 %), the
  threshold still works but the margin is thinner and the cooldown must be tuned more
  carefully — **which is a finding, not a knob-turn.** So RP-2 must carry this as a
  *checkpoint that can reopen the separation*, not a sweep that can only confirm it.
- **The capability-accounting guard (part D) travels with the wiring.** Everything in
  §§12.10–12.11 is priced against capabilities we bounded (occupancy, eclipse) or
  denied (the content-selector FCMP++ erases). RP-2 wires this into the daemon, and
  *implementation creates observables the design did not have* — a field that leaks
  position, a timing that fingerprints an explore-slot, a fee that turns out visible
  and unpadded such that it composes into a selector. The design is sound on the
  capabilities enumerated; the implementation is where you learn whether the
  enumeration was complete. **Guard for RP-2: every wiring decision that exposes a new
  observable is a new capability — price it before building on it,** the same
  discipline as part D, at the layer where observables are actually created.

---

## 13. The ε adopt-criterion (form only) — superseded as a decision basis by §14

> **⚠ Not a decision variable — read before the table.** §14 supersedes this
> section as a *decision* basis. The δ table below measures the precision
> increment of **fluff-on-expiry**, the mechanism §14 established spends privacy
> for performance and therefore **replaces** with reshape rather than tunes. It
> is retained, verified, and permanently tested per RD-4 (*measure your
> numbers*) — but **verified is not the same as decision-input.** Do **not**
> choose `ρ` or `δ_max` against these numbers: reshape drives every one of them
> to ~0 (§13.4), so a `ρ` picked here would tune a leak we are *removing*, not
> sizing one we are keeping. The only `δ` a `ρ` decision is taken against is the
> **W3 residual** — the irreducible both-slots-adversarial leak that *survives*
> reshape — measured by the two-slot occupancy instrument (§12.5, Round-3
> build 1), not here. The polish of a re-runnable, permanently-tested number is
> exactly what creates the pull to tune it; the pull is wrong, and this banner is
> where it is refused.

Q-9 required `ε` derived as an *increment*, not a level, in the units the
instrument reports, so the derivation and the measurement meet at a defined seam.
Here is the *form*, and the verified increment of the mechanism §14 replaces.

### 13.1 The formula

```text
δ  :=  Precision_joint(C1 + C3)  −  Precision_joint(C1)

adopt the mechanism parameters   iff   δ ≤ δ_max
```

- **`Precision_joint(·)`** — `P(the adversary's single best origin-guess is
  correct, per transaction)`.
- **`C1`** — the stem-spy channel that exists with or without our embargo
  mechanism (the origin's stem successor is a spy).
- **`C3`** — the forced-fluff channel our embargo *adds*.
- **`δ`** — the increment: what our mechanism costs *on top of* the
  deanonymization the adversary already gets from stems existing at all. This is
  the increment-form Q-9 demanded; it discounts what the spy knew anyway (`C1`)
  and prices only the new information (`C3`).
- **`δ_max`** — the one number the human supplies.

### 13.2 The computed left side (lower bound)

At the adopted 144 s embargo, RD-4 stem support, `STEMS = 2`, independent-neighbour
assumptions — **re-run end-to-end by `simulate_precision_increment`
(`precision_increment_reproduces_delta_table`), not composed by hand:**

| `f` | `Precision(C1)` | `Precision(C1+C3)` | `δ` |
| --- | --- | --- | --- |
| 0.05 | 0.0503 | 0.0513 | **+0.0010** |
| 0.10 | 0.1000 | 0.1019 | **+0.0019** |
| 0.30 | 0.3001 | 0.3046 | **+0.0045** |

The mechanism as provisioned adds **0.1–0.45 percentage points** of
origin-identification precision, depending on adversary size. That is `δ` — a
different, larger-denominator quantity than the leak rate, because precision
already folds in the "one sighting names a `5`-set, correct `~20 %` of the time"
discount. It is emphatically *not* the `0.026 %`/`0.3 %` leak-rate numbers.

**`δ` scales with `f` — it is a curve, not a scalar.** A single `δ_max` is
under-specified until it names the `f` it is stated at — exactly the incompleteness
"99.7 %" quietly dropped. Written as a formula, `δ`'s `f`-dependence is visible,
and any scalar target is incomplete without pinning `f`.

### 13.3 The recommended form: a ratio bound

```text
δ / Precision(C1)  ≤  ρ
```

"the embargo channel may not amplify the adversary's *existing* precision by more
than `ρ`." Across the table that ratio is **~1.5–2 %** at every `f`
(`0.0019/0.10`, `0.0045/0.30`) — it is **`f`-invariant**, so it is stated once and
holds at every adversary size, removing the "at what `f`" incompleteness by
construction. This is the form to derive toward. A worst-case bound
(`δ_max ≤ 0.005 at f = 0.30`) is the alternative; the table meets it as-is, but it
carries the `f`-naming burden the ratio form removes.

### 13.4 What reshape is for, in these units

Reshape drives the `C3` term toward zero — a re-stemmed fire emits no fluff to
sight — so it drives `δ → 0`, collapsing `Precision(C1+C3)` back to
`Precision(C1)`. **Reshape's job is to make the adopt-inequality hold with margin,
not to hit a leak-rate target.** After reshape, `δ ≈ 0` for every transaction that
re-stems, and the residual is only the W3/W3b both-slots-adversarial cases (§12) —
which is *why* the two-slot occupancy instrument is the gate: it measures the `δ`
that survives reshape.

### 13.5 The one remaining input, and the verification status

**`ρ` (or `δ_max` at a named `f`) is the human's judgment** — the input no
computation supplies, exactly as Q-9 said it would be. The *form* is resolved and
the left side is computed; the *number* is not owed by the calculator. If `ρ` is
named, the design has its adopt-criterion and the two-slot instrument has its
acceptance threshold, both in the same units, meeting at the seam the formula
defines.

**`ρ` is *underspecified*, not *undecided-pending-judgment* (Q-10).** This is the
precise status, and the distinction is load-bearing. It is not that a human has yet
to exercise judgment on a well-posed `ρ`; it is that **reshape's residual `δ` has no
upper *value* until `g_max` exists** (§7, Q-10), so there is nothing for a `ρ`
judgment to bind against. Naming `ρ` is only half the input; the other half is the
`g` its acceptance is evaluated at, and §12.6 shows `g` is the adversarially-
shapeable outbound-selection share, unbounded from what is in the tree today — and
under churn it is a *sustained-share* question, not a single-draw one. So even a
named `ρ` cannot be *checked*: the acceptance threshold and the residual it is
compared against are stated at different `g`. A provisional `ρ ≈ 2 %` is met before
reshape *at `g = f`*, but that is exactly the assumption Q-10 refutes — a
placeholder squared: not a decision, and not even a defensible-`g` evaluation of
one. The distinction is what stops a `ρ` being picked next month against an assumed
`g` and the chain being called closed.

**Verification status (honest):**
- *Form* — verified: increment-form, in precision units, meeting the measurement
  at a defined seam. This is the Q-9 deliverable and it is complete.
- *Left side* — **re-run and reproduced.** `simulate_precision_increment` measures
  it end-to-end under RD-4/STEMS=2/144 s, and returns δ = 0.0011 / 0.0020 / 0.0047
  at f = 0.05 / 0.10 / 0.30 — the review's 0.0010 / 0.0019 / 0.0045 to within
  Monte-Carlo noise, with `Precision(C1) ≈ f` by construction. Reshape
  (`retry_cap = 1`) collapses δ to ~0.00006, confirming §13.4. The test pins both.
  (The earlier "cross-checked, not re-run" caveat is discharged.)
- *Enriched value* — **measured directly (§12.6), and moot for the decision.** The
  re-run confirms the *independent-neighbour lower bound* of this
  (replaced-mechanism) `δ`; its `f = 0.30` row would rise under outbound
  enrichment, because `simulate_precision_increment` draws the spy-neighbour
  independently at `f` rather than from the enriched outbound pool. But the honest
  enriched quantity is the **W3 residual**, now measured directly by
  `simulate_two_slot_occupancy` (§12.6) as an *outbound-occupancy* channel — not by
  enriching this table, which measures fluff-on-expiry, the mechanism §14 replaces.
  So nothing is left to gate here: the decision `δ` is §12.6's W3 residual, and this
  row is a floor on a number that is no longer the decision input.

So Q-9 is **resolved in form, with the left side re-run and reproduced**: `δ` is a
per-transaction precision increment (measured, not composed), bounded by a ratio
target `ρ` the human names, driven toward zero by reshape.

**Superseded scope (§14).** The *general* `ρ` this section derives toward is
dissolved by §14: fluff-on-expiry's leak buys recovery latency (performance), which
the priority order forbids preferring over privacy, so reshape is adopted
unconditionally and the general `δ` (this table) is what reshape drives to ~0. The
formula stands, but the only `δ` left to *price* is the **W3 residual** — the
both-slots-adversarial fallback where the fluff is genuine last-resort availability
— and that is what the two-slot instrument measures.

---

## 14. Reframe — fluff-on-expiry spends privacy for performance (Round 3)

Stepping back from the `ρ` exercise (§13): the question "how much amplification
do we tolerate" prices a mechanism as if it were load-bearing. It is not. When
you look at what the embargo's fluff *does*, the δ-bounding dissolves, and
reshape stops being a lever we weigh and becomes the mechanism.

### 14.1 What the embargo does on expiry, at source

On embargo expiry the stem transaction is **promoted to fluff**.
`get_relayable_transactions` returns the expired tx tagged with its own relay
method — `stem` ([tx_pool.cpp:998](../../src/cryptonote_core/tx_pool.cpp#L998)) —
and `cryptonote_core` then buckets `stem` into `public_req`
([:1075-1076](../../src/cryptonote_core/cryptonote_core.cpp#L1075)) and relays
`public_req` with **`relay_method::fluff`**
([:1087](../../src/cryptonote_core/cryptonote_core.cpp#L1087)). The loop-detection
twin does the same on receiving a stemmed tx back
([tx_pool.cpp:296](../../src/cryptonote_core/tx_pool.cpp#L296)). So the mechanism's
answer to "I didn't see my tx return" is **fluff it** — and that fluff *is* C3.
(This also confirms the crate's instruments modelled the right event: preemption
= a fluff, not a silent re-stem.)

### 14.2 The embargo defends a different adversary than C3 leaks to

- The embargo defends against the **black-hole / dropping adversary**: your stem
  successor receives your tx and silently drops it, censoring you. Fluff-on-expiry
  is the backstop — get the tx out despite the drop.
- C3 leaks to the **passive deanonymising adversary** (§6.8) — the fluff is
  observable.
- So fluff-on-expiry trades **privacy** (C3) to buy **censorship resistance** (the
  tx propagates despite the drop).

### 14.3 Reshape buys the same censorship resistance without the privacy cost

On embargo fire, reshape re-stems to the *alternate* successor instead of
fluffing — routing *around* the black hole while staying in stem phase. It
provides the **same censorship resistance** (the tx gets out, via successor 2)
with **no C3** (it stayed in stem). Fluff and re-stem defeat the dropping
adversary equally; they differ only in cost:

- **Fluff-on-expiry** recovers *fast* (immediate diffusion) but *leaks* (C3).
- **Reshape** recovers *slower* (another stem hop, or another embargo cycle in
  W3) but stays *private*.

### 14.4 So fluff-on-expiry is backwards from our priority order

Fluff-on-expiry's C3 leak buys **recovery latency** — performance — at the cost of
**privacy**. [`00-mission`](../../.cursor/rules/00-mission.mdc) orders
privacy > security > correctness > performance. A mechanism that spends privacy to
buy performance inverts the top and bottom of the hierarchy. Framed that way, the
`ρ` question was implicitly asking "how much privacy will we spend on faster
recovery," and the priority order's answer is **as little as physically possible,
and we do not tune it — we replace the mechanism that spends it.** Bounding a
general `δ` prices a performance optimisation we are not allowed to prefer over
privacy.

### 14.5 The performance cost is a cost, not a break (measured)

`simulate_reshape_recovery` (`reshape_recovery_is_a_cost_not_a_break`), embargo
144 s, cap = 1:

| recovery of a black-holed tx | p50 | p90 | p99 |
| --- | --- | --- | --- |
| fluff-on-expiry (1 embargo cycle) | 100 s | 331 s | 662 s |
| reshape worst case (W3, 2 cycles) | 241 s | 560 s | **954 s** |

`CRYPTONOTE_MEMPOOL_TX_LIVETIME` is **3 days**. Reshape's worst-case p99 is
**0.37 %** of it, and the re-relay loop retries to `MAX_RELAY_TIME` (4 h)
regardless, so the tx *always* propagates. The cost is real — reshape's worst
case is ~double fluff's, bounded by the cap at `(cap+1)` embargo means — but it is
a **cost** (a slower recovery), not a **break** (a failure to propagate).
Fluff-on-expiry *already* recovers slowly (p99 662 s, because the embargo is a
144 s memoryless timer); reshape's marginal cost is only the rare W3 second cycle.

### 14.6 The one residual where C3 buys something real: W3

When **both** stem successors are black holes (W3, §12), reshape's re-stem has
nowhere to go, and the fallback fluff is the *genuine* last resort — fluff-and-be-
seen, or be-censored-entirely. *There*, and only there, the C3 emission buys
something privacy-relevant: **availability under total stem compromise**. That is
a real privacy-vs-availability trade at the extreme, and a small `δ` is a
defensible price for "your tx still propagates even when both your stem paths are
hostile." So the `δ` worth bounding is not the general leak — it is the
W3-fallback residual, conditioned on total stem compromise, which is exactly what
the two-slot occupancy instrument (§12.5) measures.

### 14.7 Resolution — this supersedes §13's `ρ` framing

1. **Adopt reshape unconditionally** — not instrument-gated, not
   cost-benefit-tuned — because it is a strict priority-order improvement: equal
   censorship resistance, strictly better privacy, at a performance cost the
   hierarchy explicitly permits and §14.5 measures as bounded. This changes §12's
   framing: the two-slot instrument is **no longer a gate on adopting reshape**,
   only on quantifying the irreducible remainder.
2. **Bound `δ` only on the W3 residual** — the both-slots-adversarial fallback,
   where the fluff is genuine last-resort availability. That `δ` is smaller and
   more defensible than §13's general figure because it is conditioned on total
   stem compromise, not on ordinary preemption. §13's formula still holds; its
   *scope* narrows to the W3 fallback, and its `ρ` becomes a bound on that
   residual rather than a general amplification tolerance.
3. **The `ρ` question dissolves.** We do not pick a general tolerance for a leak
   that buys us the wrong thing (performance). §13's `δ` table (the general leak)
   is what reshape drives to ~0; the only `δ` left to price is W3's.

### 14.8 Honest boundary — where this reversal could still be wrong

`§14.5` measures recovery as `(cap+1)` embargo cycles, which assumes the re-stem
completes normally once it reaches an honest successor. If real-network re-stem
propagation is materially worse than that bound — pushing worst-case recovery
past something operational — then the cost crosses from *performance* into
*correctness/liveness*, which **outranks** performance and would force adoption
back open. The priority order says privacy wins the performance trade; it does not
say the performance cost is zero. So the recovery-latency profile must be
**re-measured under RP-2 with the actual re-stem wiring**, not just the
embargo-cycle bound — not to re-litigate adoption, but to confirm the cost stays a
cost. That is the RD-1 discipline applied to this section's own claim: `§14.5` is
where "reshape dominates" could still be wrong.

---

## 15. The block-time seam — the embargo crossed a consensus timescale the derivation wasn't watching (Round 3)

The 39 s pattern, turned on our own number: a value that satisfies the one
constraint someone was watching (preemption probability) sitting near a boundary
nobody put in the formula (block time). The survival equation (§ derive) has no
block-time term, so when RD-4 moved the embargo 112 s → 144 s for correct privacy
provisioning, it silently crossed one block interval — and the derivation could
not articulate whether that was a choice.

### 15.1 The stacked timescales (anchored)

| timescale | value | source |
| --- | --- | --- |
| block target `T` | **120 s** | [`consensus_constants.json`](../../config/consensus_constants.json#L10) `daa_target_seconds` |
| FTL | 540 s | `daa_ftl_seconds` |
| MTP window / `N` | 11 / 90 | `daa_mtp_window` / `daa_window_n` |
| derived embargo | 112 s → **144 s** | §13 (RD-4) |
| `MIN_RELAY_TIME` / `MAX_RELAY_TIME` | 300 s / 4 h | `tx_pool.cpp:94-95` |

At 144 s the embargo **exceeds** the block interval — the three sub-10-minute
timescales are stacked in a narrow band.

### 15.2 The block-inclusion path is clean (verified)

A mined tx is dropped from the pool via `remove_txpool_tx`
([blockchain.cpp:7053](../../src/cryptonote_core/blockchain.cpp#L7053), the
block-connect path), and the embargo lives in that pool entry's
`meta.last_relayed_time`, which `get_relayable_transactions` only reads for
pool-resident txes — so a mined tx **cannot** fire a stale embargo. And the margin
is wide, not close: a tx fluffs in <1 s (F-2's 699 ms mean), is mined, and every
prefix embargo (144 s) disarms via fluff-observation or block-arrival 140+ s
before it could fire. The "cut it close" worry does not bite the happy path — the
embargo is *much longer* than block propagation, not near it.

### 15.3 The seam is black-hole recovery, and it is a distribution, not a cliff

A black-holed tx (dropped by its stem successor, never propagated, so unminable)
sits invisible until an upstream embargo fires and fluffs it. That recovery time
*is* the embargo — which is **memoryless** (geometric, mean 144 s), so recovery is
a wide distribution, not a deterministic 144 s. `P(first-hop recovery within one
120 s block interval)`, from the memoryless CDF over the (tested) geometric
embargo:

| embargo mean | P(recover < 120 s) |
| --- | --- |
| 112 s (pre-RD-4) | 0.657 |
| **144 s (RD-4)** | **0.565** |

RD-4 shifted the "makes the next block interval" probability by **~9 points
(66 % → 56 %)** — *not* to a guaranteed miss; ~56 % still make it. And deeper
black holes recover far faster (`min` over `j+1` holders, `M_eff = 144/(j+1)`):
j=1 → 0.81, j=2 → 0.92 within one block interval. So the seam bites only the
**first-hop** black hole (origin holding alone) — the rarest, worst case — and
even there roughly half still make the next block interval. The failure mode is
"confirms one block later," bounded and minor, and strictly better than the
pre-Dandelion alternative of "censored entirely."

### 15.4 FTL and MIN_RELAY are *not* in this seam (a correction)

FTL (540 s) bounds how far ahead a block's **timestamp** may be relative to the
node's median time — block-timestamp validation, not a tx-propagation or recovery
deadline. Nothing about a black-holed tx's recovery latency "races the FTL
machinery"; they are unrelated timescales. `MIN_RELAY_TIME` (300 s) governs
re-broadcast of an **already-fluffed** tx; during the embargo (and any re-stem)
the tx is stem-governed — a different state — so there is no race there either.
The only consensus timescale this seam actually touches is **block time (120 s)**,
for "which block does recovery make."

### 15.5 Reshape pushes recovery deeper — bounded, and RP-2 gets a specific gate

Reshape (§14) lengthens recovery (a re-stem hop before the eventual fluff). W3
(both successors black-holed, `cap+1 = 2` embargo cycles) recovery, from the
Gamma(2, 144 s) CDF: `P(<120 s) = 0.20`, `P(<300 s) = 0.62`. So a *doubly*
black-holed tx under reshape has a real tail past one block interval — but that is
the rarest case (W3), it stays stem-governed until it fluffs (no `MIN_RELAY`
race), and it is still << the 3-day mempool lifetime (§14.5). §14.8's RP-2
recovery re-measurement now has a specific reference: **does recovery make the
next-block-but-one**, measured against block time — *not* FTL.

### 15.6 The reference frame settles the direction: derive against survival, integrate against consensus

Re-anchored against Dandelion++ (Fanti et al., §11), the block-time collision is
an **embedding artifact, not a design flaw** — because in the reference frame
there is no block-time problem to solve. The paper's embargo lives on the
*propagation* timescale and is never coupled to consensus:

- Its only upper-bound guidance is that the exponential clocks "should be slow
  enough that they only trigger (with high probability) during a black-hole
  attack" — survive the stem, with nothing about fitting under a block interval.
- Its timescale reference is per-hop propagation latency, which it treats as
  negligible ("each of the remaining clocks can be reset assuming propagation
  latency in the stem is negligible").

So the embargo answers to exactly one constraint — survive the stem with
probability `1−ε` against sub-second per-hop latency — and our corrected
112–144 s **is** the paper-faithful number. Block time never enters because the
paper has no blocks: it is a networking-layer anonymity protocol whose terminal
event is "the transaction diffuses." Confirmation, mining and block intervals are
all downstream of where the paper stops.

**This reframes the 39 s.** It is not a deliberate fit to block time — it is the
`log10`-for-`ln` arithmetic error (F-1), which merely *happened* to land at ~⅓ of
a block interval. But by error or by rationalization, **39 s is what "shortened to
fit" looks like**, and it is the antipattern, not the solution. The irony the
paper exposes: the *buggy* 39 s sits comfortably under block time while the
*correct* 144 s collides with it. The bug produced a number wrong for privacy but
incidentally comfortable for integration; our correction fixed the privacy and
surfaced the tension the bug was masking. **Shortening the embargo now to slide
back under 120 s re-commits the exact sin this whole arc undid** — letting a
non-privacy constraint contaminate a privacy-derived number and calling the
result "fit."

The reference does not *solve* the collision; it *dissolves* it, by refusing to
let block time touch the anonymity derivation. We keep that separation, enforced
by construction:

- **Do NOT** add a block-time term that *pulls* the embargo down. The derivation
  stays block-time-**unaware**; it answers to survival and only survival. (This
  supersedes an earlier draft of this section, which called block time a
  "non-binding term of the derivation" — that framing left the contamination door
  ajar, because a "term" a future re-derivation "re-evaluates" is one block time
  could eventually be permitted to *move* the embargo through. Block time is not a
  term of this derivation at any level, binding or not.)
- **Do** record the block-time *awareness* at the **integration layer** (this
  document, not the derivation): the embargo knowingly crosses the 120 s boundary;
  the crossing affects only black-holed transactions, costs them one block of
  confirmation latency on the rare first-hop case, and that cost is dominated by
  the privacy requirement per [`00-mission`](../../.cursor/rules/00-mission.mdc)
  (privacy > performance). The number does not move; we just stop crossing the
  boundary *silently*.
- **Do** verify the crossing does not *cascade* — the one place the separation
  needs active checking in **our** stack, because Monero bolted on timers the
  paper never had. FTL (540 s) and `MIN_RELAY_TIME` (300 s) are ours, not the
  paper's, and the Round-3 recovery-latency measurement (§14.8) must confirm they
  *absorb* the propagation-timescale embargo — that our added timers turn the
  crossing into bounded latency, never a hard failure. **Precision, per §15.4:**
  FTL does not *gate* recovery (it validates block timestamps), so in this check
  it is a reference *scale*, not a constraint with teeth; the checks that actually
  bite are the `MIN_RELAY_TIME` re-broadcast interaction and the mempool-lifetime
  headroom.

**The principle, stated once:** the embargo derivation is block-time-*unaware*;
the integration layer is block-time-*aware*. Derive against survival, integrate
against consensus, and never let the second move the first. That is the difference
from the 39 s ghost — not a boundary the derivation "names and crosses," but a
boundary the derivation *refuses to know about* while the layer above it does the
reconciliation the paper always assumed some layer would.

---

## 16. RP-2a design round — `connection_map` → Rust (the faithful port)

> **Seam retired in RP-3a. This section is lineage, not current structure.**
> The wrapper was designed with `removal target RP-3` written into it, and RP-3a
> reached it: `src/net/dandelionpp.{h,cpp}`, `dandelionpp_ffi.h`, the
> `shekyl_dandelionpp_map_*` exports and the six `dandelionpp_map` gtests are all
> gone, because `shekyl-relay::Zone` owns a `StemMap` directly and a second path
> to the same map is a defect waiting for a reader. Kept in full because the
> *reasoning* is still load-bearing — §16.1's three contracts are why the port
> was faithful, and one of them outlived the seam (see below).

Short design leading the RP-2a implementation commits on `feat/rp2a-connection-map-rust`.

**Scope (the ratified split, §3).** RP-2a ports the `connection_map` *logic* to
Rust; the *selection/reputation* behaviour (the §12.5 W3c churn-stable alternate,
the Q-10 `g_max` mechanism) is RP-2b. The two are separable at the **test
surface**, not by contradiction: the `dandelionpp_map` gtests pin **outcome
invariants** — size, non-nil refill drawn from the live set, even load, mapping
consistency for unaffected links — but they read the mapper's *own* refill choice
(`newly_mapped = *(++mapper.begin())`, [net.cpp:1911]) and never pin it to a
specific fresh `current.back()`, and no test drops the same slot twice. So the
W3c churn-stable change is invisible to them and needs its own repeated-churn
sibling test (RP-2b), while the faithful port rides them unchanged.

**Re-census (§12.11 first move — done).** The C++ RP-2/3/4 surface (`src/net/`,
`levin_notify.cpp`, `tx_pool.cpp`, `src/p2p/`) is **unmoved** since RP-1 — the
parallel staking-consensus work landed in Rust, not here — so the re-census is
line-number verification, and every port anchor holds at source on `origin/dev`:
`CRYPTONOTE_DANDELIONPP_STEMS = 2` (config.h:108, cap = STEMS−1 = 1); the
fresh-draw-on-churn refill at [dandelionpp.cpp:160]; outbound-only fluff on Tor/I2P
at [levin_notify.cpp:448]; fluff-on-expiry at [cryptonote_core.cpp:1087].

**Rust owns the logic; C++ holds an opaque handle (rules 20/40).** `stem_map.rs`
already implements the map. RP-2a reimplements `dandelionpp.cpp`'s ~210 lines of
logic as **forwarding calls** to a map FFI in `shekyl-ffi`, and keeps
`dandelionpp.h`'s class ABI so `levin_notify.cpp` and the `net.cpp` gtests compile
**unchanged**. `levin_notify` must hold the map through *some* C++ handle in either
framing — it cannot hold a bare Rust value — so preserving the existing
`connection_map` ABI as that handle-wrapper costs **no extra C++** and buys the
unchanged-gtest oracle. It is transitional FFI-boundary glue with a named removal
target — **RP-3, when `levin_notify` ports** (rule 15: smallest scope, named
deletion target). No map *logic* is reimplemented in C++.

**The map FFI surface** — `ConnectionId([u8; 16])` (a Boost-UUID memcpy); every
call site is `\pre` inside the zone strand, so the handle is single-threaded by
external serialisation and needs no internal lock:

| C++ call site | FFI |
| --- | --- |
| construct `{connections, stems}` (:714) | `map_new(ids, n, stems) -> *handle` |
| `clone()` in the copy ctor (:600) | `map_clone(*handle) -> *handle` (deep copy) |
| move-assign into the zone (:614) | pointer transfer — no FFI |
| `update(current) -> bool` (:534) | `map_update(*handle, ids, n) -> bool` |
| `get_stem(source) -> uuid` (:565) | `map_get_stem(*handle, id, out) -> bool` |
| `size()` (:514) + `begin()/end()` iteration (:520) | `map_snapshot(*handle, buf, cap) -> count` |
| destructor | `map_free(*handle)` |

`get_stem` mutates (`in_mapping_`/`usage_count_` on a miss); the strand `\pre` is
the ownership rule that keeps that safe across the FFI.

### 16.1 Seam-consumption contracts — three signatures carry more than their types

The six gtests test the map **in isolation**; `levin_notify` consumes three of the
calls in ways the gtests never exercise, so each carries a contract beyond its
signature. All three share one failure shape — green-by-construction: the gtests
(the oracle for the map's *logic*) are structurally blind to the seam's
*consumption* semantics, so a wrong contract passes the oracle and diverges only
in daemon behaviour. Each is verified at the call site, not paraphrased.

- **`map_update` returns the exact re-arm predicate, not "the set differed."**
  `dandelionpp.cpp:169` returns `replace || existing_outs < out_mapping_.size()`
  — *a stem slot was dropped/nil'd, **or** the map grew to fill under-capacity* —
  with an early `false` (`:151`) when nothing dropped and already at width.
  `levin_notify.cpp:534` gates a channel **re-arm** on this bool; a
  reimplementation returning "the connection vector changed" would re-arm
  spuriously (or miss one), and the gtests would still pass. **Verified faithful:**
  `stem_map.rs:180` returns `replaced || existing_outs < self.out.len()` with the
  same early-`false` (`:154`) and nil-remark (`:150`), line-for-line. The FFI
  returns this predicate unchanged, as a `#[must_use]` named type (not a bare
  `bool`) so the seam is self-documenting; micro-test (4) pins it.
- **`map_clone` is a C++ copy-constructor contract, and the copy path is
  production-live.** `change_channels`'s copy-ctor (`levin:599`) calls
  `map_.clone()`, and Boost.Asio copies the posted handler — so the deep copy
  fires **every epoch**, not only in tests. The handle-wrapper's
  **copy-constructor and copy-assignment must both route through `map_clone`**,
  and the shallow defaults must be explicitly **deleted or defined** — a defaulted
  shallow copy shares one Rust handle between two wrappers, and the epoch swap
  (`:614` move-assign) then mutates/frees a map the other wrapper still points at:
  silent corruption the gtests miss (they never drop a slot twice, so never
  exercise divergence-after-copy). Move-ctor/assign transfer the handle and null
  the source; the destructor frees iff non-null. `StemMap` derives `Clone` (deep),
  so the Rust side is correct — this contract lives entirely on the C++ wrapper;
  micro-test (5) arms it as a compile-time guard.
- **`map_snapshot` preserves slot order *including nils*, because a consumer
  indexes by position.** `levin:520–522` iterates `begin()..end()` and computes
  `i = id - begin()` to index the **parallel noise channel** `channels[i]`;
  `begin()/end()` span *all* slots, nils included (`net.cpp:2024` asserts
  `end()-begin()==3` at `size()==2`). So `map_snapshot` returns every slot in `out`
  order with `None → nil-uuid` (zero bytes), index-aligned; the wrapper derives
  `size()` (non-nil count, `:514`) and the iterators from it. An unstable or
  nil-collapsed order passes the map gtests and **misassigns noise channels** in
  the daemon; micro-test (6) pins the order.

**Type security — the migration's dividend (rule 25).** Rust owns the map with
`Option<ConnectionId>` (an empty slot is `None`, not a magic nil UUID) and a
`ConnectionId([u8; 16])` newtype; `stem_for`'s "must fluff" is `None`, not a
sentinel. The FFI maps `None ↔ nil-uuid` **explicitly at the boundary** so zero
bytes never re-enter Rust as a "valid" id, and the C-ABI `bool`/`*handle`/`[u8;16]`
are reconstituted into these types on the first Rust line. The map draws
randomness (`new`/`update`/`stem_for`); the FFI handle **owns a
cryptographically-secure `RelayRng`** matching the C++ `crypto::random_device` /
`rand_idx` — never the deterministic `SplitMix64` the measurement suite uses.

**Acceptance — run the oracle *and* keep the survivor (do both).**

1. The 6 `dandelionpp_map` gtests ([net.cpp:1787–2140]) pass **unchanged** against
   the Rust-backed map — the migration oracle proving behavioural identity to the
   deleted logic (the same C++-as-oracle discipline as the consensus port).
   Translating them *without* first running them unchanged would validate the port
   against a test written *from* the port.
2. The same 6 gtests **translated to Rust** against `stem_map.rs` pass — the
   survivor. The unchanged C++ gtests may then be retired (here or at RP-3,
   whichever keeps the diff clean).
3. The RP-1 `a_slot_emptied_by_an_earlier_update_is_backfilled_later` regression
   still holds.

**Retirement executed at RP-3a, on the option acceptance item 2 reserved.** The
six C++ gtests are gone, and the condition that authorised it was checked rather
than remembered: `gtest_empty`, `gtest_zero_stems`, `gtest_dropped_connection`,
`gtest_dropped_connection_remapped` and `gtest_dropped_all_connections` all live
in `stem_map.rs` — five twins for the five behavioural cases, the sixth
(`traits`) being wrapper move/copy semantics that died with the wrapper it
constrained. Census by grep, not by memory: after the deletion no
`connection_map`, `StemMapHandle`, `shekyl_dandelionpp_map_*` or `net/dandelionpp`
reference remains anywhere in `src/`, `tests/`, `contrib/` or `cmake/`.

**Which of the three contracts survived the seam, and where its witness went.**
Two are moot: `map_update`'s exact re-arm predicate is now `Zone::update_stems`
returning `StemSetChange` with no ABI in between, and `map_clone`'s deep-copy
requirement died with the handle that could be shallow-copied. **Contract 3 did
not die** — a consumer still indexes the parallel noise channel by position, so a
compacted or reordered snapshot still binds covert channels to the wrong
connections. It is now the `SlotsCb` contract at the RP-3a boundary, and its
witness is `stem_slots_cross_in_index_order_with_nils_in_position`.

That check is the reason this retirement took a pass of its own rather than a
tail-end commit. The successor test *carried a "sole witness" seal over a body
that never produced a nil* — three candidates into two slots, both filled. It
would have inherited the seal and not the coverage, and the seal would have told
the next reader the property was already covered. It now empties a slot with no
backfill and is negative-controlled against both compaction and reordering.

The six gtests are **necessary but not sufficient** — they are structurally blind
to the three §16.1 consumption contracts. Three micro-tests arm them (an armed
trigger, not a documented caveat):

4. **update-predicate:** `current` changes but every stem stays live and the map
   is at width → `update` returns **false** (no spurious re-arm); a drop and a
   grow each return **true**.
5. **clone-divergence:** clone a map, `update` one copy → the other is unchanged
   (Rust `StemMap`); and the C++ wrapper's shallow copy-ctor/assign are **deleted**
   — a compile-time guard that no accidental shallow share exists.
6. **snapshot-order:** `map_snapshot` returns slots in `out` order with nils in
   position, so `i = index` maps to the same connection C++ `begin()+i` did.

**Handoff to RP-2b.** The W3c churn-stable alternate (§12.5) + Q-10 selection, its
own design round, its own repeated-induced-churn sibling test + the `g`-bound, and
the three §12.11 obligations: the background-failure-rate measurement, the
cooldown/threshold **reopen-checkpoint** (not a confirm-only sweep), and the
capability-accounting guard for observables the wiring newly exposes.

**And one carried from RP-2a's review: the two nil meanings stay distinguished by
field, never merged.** At the FFI boundary the nil UUID / `None` carries *two*
meanings — "this stem slot is absent (disconnected)" and "this transaction
originated locally" — the same byte value disambiguated only by *which field it
appears in* (a slot position versus `get_stem`'s source argument). That is sound
today precisely because the two never occupy the same field, and RP-2a keeps them
apart structurally (`map_snapshot` emits slot-position nils; `source_from_bytes`
interprets the source argument; a null pointer is neither and fails closed). The
re-stem / churn-stable-alternate logic is exactly where the temptation to unify
them appears — a single "is it nil?" test spanning both roles. It must not:
conflating "no live peer here" with "the origin is us" is a silent routing bug
wearing a legal type, which is the one failure class this seam's design has spent
its whole review budget eliminating. RP-2b keeps the two roles in distinct fields
(or distinct types), and says so in its design.

---

## 17. RP-4 design round — the embargo cut (F-1/F-2/F-3 → Rust)

Short design leading the RP-4 implementation commits on `feat/rp4-embargo-rust`.
This closes the finding the whole arc opened with.

**Scope (ratified).** Embargo *correctness* only: F-1 (the 39 s that does not
follow from its own derivation), F-2 (a Poisson draw under an exponential
survival assumption), F-3 (the closed-form error → the adopted **144 s**), plus
the §15.4 timer reconciliation. The §14 fluff-on-expiry reframe (adopt reshape)
is **not** RP-4: it is a relay-path behaviour change whose `cap = STEMS−1 = 1`
and W3-residual bounds are entangled with RP-2b's selection work, and it needs
its own tests rather than riding the embargo's.

**Re-census (done, at source on `dev` @ `d4bb9b117`).** Unlike RP-2a's, this
surface *has* moved: `40667e701` landed the STEMS=2 derivation — the 39 s's
mirror image — and sets the precedent this round follows (below). The rest holds:

| Anchor | At source |
| --- | --- |
| The 39 s constant | `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE` (`cryptonote_config.h`) |
| The F-1 ghost, in prose | the derivation comment, [tx_pool.cpp:66–86](../../src/cryptonote_core/tx_pool.cpp#L66) — its own formula over `k=5, ep=0.10, hop=175 ms` gives **16.61 s**; 39 s reproduces only under `log10` for `ln` |
| The F-2 draw | `crypto::random_poisson_seconds embargo_duration{…}` ([tx_pool.cpp:1031](../../src/cryptonote_core/tx_pool.cpp#L1031)), applied at [:1053](../../src/cryptonote_core/tx_pool.cpp#L1053) |
| The wallet consumer | `tx_propagation_timeout = EMBARGO_AVERAGE * 3/2` ([wallet2.cpp](../../src/wallet/wallet2.cpp)) — second consumer of the constant; on expiry marks the transfer failed and un-spends key images |
| The other timer | `MIN_RELAY_TIME = 300` ([tx_pool.cpp:94](../../src/cryptonote_core/tx_pool.cpp#L94)) |
| The Rust primitive | `EmbargoTimer::{adopted, inherited, geometric_with_tick, …}` (`schedule.rs`) — already landed, unmoved |

`crypto::random_poisson_seconds` has exactly **two** users, both in `tx_pool.cpp`:
the embargo (removed here) and the `forward` delay ([:307](../../src/cryptonote_core/tx_pool.cpp#L307)).
The forward delay is out of RP-4's scope; it is the last consumer of that header
and a candidate for a later round, named here so it is not forgotten.

### 17.1 Two named obligations, both discharged by verification

Neither needs code. Both were *risks the doc named conditionally*, and the source
answers them — which is the point of re-censusing before building.

- **§10.7 loop handling — discharged.** The item reads "*if* the inherited code
  drops a duplicate stem receipt silently, a loop is a self-inflicted black hole
  recovered only at embargo latency… needs a `tx_pool.cpp` duplicate-stem-receipt
  check **before RP-4**." It does not drop it:
  [tx_pool.cpp:295–296](../../src/cryptonote_core/tx_pool.cpp#L295) converts a
  stem receipt for a tx already in `dandelionpp_stem` state to **fluff** — the
  Dandelion++ prototype behaviour the item asks for. The loop-black-hole failure
  mode does not exist, and RP-4 is therefore unblocked. (This mattered more after
  the cut than before: lengthening the embargo 39 s → 144 s would have *amplified*
  the stall had the code been dropping.)
- **§15.4 / Q-8 timer reconciliation — discharged.** The concern: at 144 s the
  origin-alone black-hole recovery p90 (~331 s) now *exceeds* `MIN_RELAY_TIME`
  (300 s), where at 39 s it did not, so "a black-holed origin's first
  `MIN_RELAY_TIME` re-relay and its embargo recovery can now cross." At the seam
  they cannot: the relay loop dispatches on relay *method*
  ([tx_pool.cpp:969–987](../../src/cryptonote_core/tx_pool.cpp#L969)) —
  `stem`/`forward` are gated **solely** by `last_relayed_time > now` (which for an
  embargoed tx *is* the embargo deadline, a future timestamp), while
  `get_relay_delay`/`MIN_RELAY_TIME` gates only `local`/`fluff`/`block`. The two
  timers are **disjoint by construction**, so the embargo mean cannot race the
  re-broadcast interval while the tx is in stem state. Mempool-lifetime headroom
  is likewise ample: re-relay stops at `max_age / 2` (1.5 days at the 3-day
  lifetime) against an embargo p99 of ~954 s — two orders of magnitude.
  **Because this disjointness is load-bearing rather than incidental, RP-4 arms
  it** (below) instead of leaving it as prose: a future edit that folded stem
  into the `get_relay_delay` branch would silently re-introduce the race.

### 17.2 The cut — Rust owns the draw

Policy decides the shape, not preference: `std::poisson_distribution` is
**implementation-defined** (§3), so the inherited draw is not a reviewable
artifact anywhere in the tree and two nodes on different standard libraries
already draw different sequences. `EmbargoTimer`'s table *is* the distribution —
integer, built by recurrences with no transcendentals, bit-identical across
platforms, and pinned by fingerprint in `tests/golden_vector.rs`. Fixing the
distribution in C++ would re-create debt the migration must pay down (rules
16/20). So the draw moves, and F-1/F-2/F-3 die together: the value, the
distribution, and the derivation all come from one place.

**The seam is smaller than RP-2a's — no handle.** The map needed one because it
holds per-epoch, per-connection state; the embargo distribution is node-local
**policy** (not consensus), fixed for a given parameter set. Two exports share a
process-wide `OnceLock<EmbargoTimer>` (the table is immutable once built) and
the same `OsRng` the map FFI uses:

| C++ call site | FFI |
| --- | --- |
| `embargo_duration()` per stem tx ([tx_pool.cpp](../../src/cryptonote_core/tx_pool.cpp)) | `shekyl_dandelionpp_embargo_draw_seconds() -> u64` |
| `tx_propagation_timeout` in `wallet2` ([wallet2.cpp](../../src/wallet/wallet2.cpp)) | `shekyl_dandelionpp_propagation_timeout_seconds() -> u64` |

`crypto::random_poisson_seconds embargo_duration{…}` and the
`CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE` constant are then **deleted**. The
constant had **two** consumers at re-census: the daemon draw, and the wallet's
`EMBARGO_AVERAGE * 3/2` failed-transfer wait (which un-spends reserved inputs
on expiry). Leaving a stale 39 s next to a Rust-owned 144 s is exactly the ghost
this round exists to remove (rule 15: delete, don't deprecate).

**Wallet wait is a quantile of the same table, not a multiple of the mean.** A
stem transaction is invisible to its sender until it fluffs, so "has it failed?"
is a survival question on the embargo. The inherited `3/2 × mean` is only the
~78th percentile of a memoryless distribution — under F-2 the backstop never
fired so the blunt verdict was moot; once the backstop fires, a short deadline
declares healthy transactions dead mid-recovery. The rate is policy:
`PROPAGATION_FALSE_FAIL_ONE_IN = 100` (at most 1 in 100 embargoes still running).
On the adopted table that is exactly **`ADOPTED_PROPAGATION_TIMEOUT_SECS = 664`**,
pinned by test at the crate and the FFI so the seconds cannot drift from the
table (the F-1 class again if left as a loose bound).

**This round has no unchanged-gtest oracle, and that is not an oversight.**
RP-2a was a *faithful port*, so "the 6 gtests pass unchanged" was the correct
proof. RP-4 is a deliberate **correction**: the behaviour changes on purpose
(39 s Poisson → 144 s geometric), so an unchanged-behaviour oracle would be
proving the wrong thing. The proof burden moves to the crate — the derivation
tests, the analytic-vs-simulator cross-check, and the golden vector already pin
the new distribution — plus the C++-side obligation that nothing *else* regresses.

### 17.3 The derivation travels with the value (the `40667e701` precedent)

STEMS=2 established the treatment: a load-bearing constant carries its derivation
**at every site it is reasoned about**, including a guard comment where a
well-meaning contributor would actually edit. The 39 s is the case that proved
why — an unrecorded reason is how it survived. RP-4 records the 144 s at three
sites, matching:

1. **§17 / §5** — the full derivation (already in the doc: F-3's exact solve,
   RD-1's return term, RD-4's stem-support fix, cross-checked at 147 s).
2. **`cryptonote_config.h`** — at the deleted constant's site, a guard comment
   pointing at the Rust source of truth, so the next person to look for an
   embargo knob finds the derivation instead of a number to tune.
3. **`EmbargoTimer`'s Rust doc** — the value and why, next to the code that
   draws it.

### 17.4 Acceptance

1. The crate's existing derivation gates still hold (analytic ↔ simulator,
   the F-1/F-2/F-3 executable assertions, golden vector).
2. **The disjoint-timer invariant is armed**, not merely documented: tests in
   `tests/unit_tests/txpool_relay_timers.cpp` that a tx in `stem` state is gated
   by its embargo deadline and *never* by `get_relay_delay`/`MIN_RELAY_TIME`, so
   the §15.4 reconciliation cannot rot.
3. **The wallet propagation timeout is pinned**:
   `judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN)` equals
   `ADOPTED_PROPAGATION_TIMEOUT_SECS` (664) at the crate and the FFI export — not
   a loose bound that can drift when the table or rate changes.
4. No C++ test depends on the old 39 s value or the Poisson shape — verified, not
   assumed, during implementation; any that does is re-pinned to the derived value
   with the reason recorded.
5. The daemon builds and the existing `tx_pool` / relay tests pass.

---

## 18. RP-3 design round — the scheduler cut (F-4/F-5 → Rust)

Short design leading the RP-3 implementation commits on
`feat/rp3-levin-scheduler-rust`. This is the arc's last port and its last two
findings.

**Scope and the two decisions already taken.** The relay *loop* moves to Rust
(not "C++ keeps the loop and asks Rust for decisions"), and **Rust owns the zone
state** — `contexts` and their fluff queues, the map, and every timer. C++ keeps
what it is uniquely good at and what no Rust implementation exists for: epee
binary serialization, levin framing, fragmentation, padding, and the socket.
`levin_notify` becomes the transport shim §3 always said it would.

### 18.1 Re-census (at source, on `dev` @ `41ee2c41f`)

The surface is **unmoved** since RP-1: no commit has touched `levin_notify.{cpp,h}`
or `tests/unit_tests/levin.cpp`. Two findings change the round's shape, and the
first corrects a claim made earlier in this arc.

**The 33-gtest oracle survives — the earlier reading was wrong.** It looked like
the tests were asio-coupled beyond rescue: they construct
`cryptonote::levin::notify{io_service_, …}` with their own `io_context` and pump
it with `run_one()`, which a Rust-owned loop would not be on. But the pumping
drains the **transport** queue, not the timers. The tests never wait on a timer
at all: `levin_notify.h:108–115` declares `run_epoch()`, `run_stems()` and
`run_fluff()`, each commented *"Only use in testing"*, the suite calls them **36
times**, and it manipulates a `steady_timer` **zero** times. The oracle is
timing-independent by construction — it forces each scheduled step and asserts on
*routing and payload* (`fluff_without_padding`: nine of ten contexts get exactly
one send, the source gets none, `dandelionpp_fluff` is set). So the 33 tests
remain a free regression oracle across the cut, provided the Rust scheduler
exposes equivalent force-step entry points for those three hooks to forward to.
That is a **requirement on the Rust design**, and it is cheap: the crate's state
machines are already pure `&mut self` steps that return deadlines.

**RP-3 owns F-4 and F-5, so this is a correction and not only a port.** The fluff
delay is still drawn in C++ from `crypto::random_poisson_subseconds`
([`levin_notify.cpp:439–440`](../../src/cryptonote_protocol/levin_notify.cpp#L439-L440),
means at [`:75–90`](../../src/cryptonote_protocol/levin_notify.cpp#L75-L90)) —
F-4, "the same distribution defect as F-2, on the timer every node applies to
every transaction", and with it F-5, the flood that is ~7× slower than it needs
to be (13.75 s vs 2.25 s p90 first passage). Both are **High**. RP-4 closed
F-1/F-2/F-3; this closes the pair that touches every transaction on every node,
and `FluffScheduler` already holds the corrected draw. Because the gtests assert
routing rather than delays, that deliberate behaviour change does not threaten
them — the same reason RP-4's correction needed no unchanged-behaviour oracle.

### 18.2 What moves, what stays, and the seam

`notify`'s public API is the contract that must survive verbatim — callers and
all 33 tests bind to it: `get_status`, `new_out_connection`,
`on_handshake_complete`, `on_connection_close`, `send_txs`, and the three `run_*`
hooks. Each becomes a forwarding call onto a Rust zone handle, exactly as
`connection_map` became a forwarding wrapper in RP-2a.

Rust calls back out through the surface §4 sketched, now verified at source:

| Outward call | Site |
| --- | --- |
| `p2p.foreach_connection(cb)` — connection snapshot | [`:109`](../../src/cryptonote_protocol/levin_notify.cpp#L109), [`:151`](../../src/cryptonote_protocol/levin_notify.cpp#L151) |
| `p2p.send(blob, id)` | [`:211`](../../src/cryptonote_protocol/levin_notify.cpp#L211), [`:666`](../../src/cryptonote_protocol/levin_notify.cpp#L666) |
| `p2p.get_out_connections_count()` | [`:758`](../../src/cryptonote_protocol/levin_notify.cpp#L758) |
| `core->get_current_blockchain_height()` / `is_synchronized()` | [`:133`](../../src/cryptonote_protocol/levin_notify.cpp#L133), [`:134`](../../src/cryptonote_protocol/levin_notify.cpp#L134) |
| `core->on_transactions_relayed(txs, method)` | [`:562`](../../src/cryptonote_protocol/levin_notify.cpp#L562), [`:581`](../../src/cryptonote_protocol/levin_notify.cpp#L581), [`:853`](../../src/cryptonote_protocol/levin_notify.cpp#L853) |

Message construction (`make_payload_send_txs`: epee serialization plus padding to
the next boundary) stays C++ and is called *by* Rust with the peer set it chose.
Batching **content** is transport; batching **time** is privacy — the split
`schedule.rs` has asserted from the start.

**Concurrency: the Rust task replaces the strand.** Today every mutation is
serialized by `zone->strand`, and connection events arrive on asio threads. With
Rust owning the state, the zone task becomes the sole serializer — a stronger
guarantee than the strand, because it is enforced by ownership rather than by
each handler remembering its `\pre`. The RP-2a map contract inverts cleanly with
it: "no internal lock because the zone strand serializes" becomes "no internal
lock because the Rust task owns it". The design obligation is the handoff — every
C++-side event (`on_handshake_complete`, `on_connection_close`, `send_txs`) must
enqueue to that task rather than mutate anything, and the FFI must make the
mutating path the only path.

**Retraction (rule: a dropped path is documented, and every artifact reflects
it).** `schedule.rs`'s module doc and §3 both record the opposite position — *"a
Rust core that demanded its own reactor would mean reconciling two event loops
for no gain. The caller arms whatever timer it already has."* That was written
when C++ was assumed to keep the loop; moving it *replaces* the loop rather than
duplicating it, so the reasoning does not survive its premise. What **does**
survive, and should be said louder, is the rest of that module's claim: the state
machines own *when* and never *how*, and remain pure steps that return deadlines.
That property is exactly what keeps the `run_*` hooks — and therefore the
oracle — available. RP-3 rewrites the paragraph rather than deleting the idea.

**Correction: the retraction is withdrawn — RP-3a is seal-consistent.** An
earlier pass here recorded `lib.rs:100–112`'s reason 2 as reversed, priced as
*"F-4/F-5 buys the second reactor."* **That ledger was wrong**, and following the
error back showed the reversal itself was unnecessary:

- **F-4/F-5 close without any reactor change** — the corrected draw is the
  crate's whether asio or tokio owns the sleep. The gain never required the cost
  it was charged against.
- **RP-3a adds no reactor.** Rust owns the zone state and every timing
  *decision*; the existing asio timer is armed from the returned deadline and
  owns the *sleep*. Rust is a library the p2p path calls, not a loop beside it,
  so the p2p path still has exactly one reactor.
- That is **what reason 2 prescribes**, not a departure from it: *"a plain
  `&mut self` state machine that returns a deadline, precisely so the existing
  timer stays in charge."* RP-3a is that sentence implemented.

For precision, two reactors already coexist in the daemon process — the
Axum/tokio server in `shekyl-daemon-rpc` (`Builder::new_multi_thread()`) — and
always have. Reason 2 was never about the process; it is about the **p2p path**,
which asio-arms leaves intact.

**When the reactor does move: at C++ removal, where it is free.** With asio gone,
tokio is the sole runtime — no second reactor to create, and no transitional
asio/tokio seam to maintain. Moving it earlier would buy that seam and pay for it
until the C++ leaves. So reason 2 is broken by the *removal*, not by RP-3a, and
`schedule.rs`'s "No async runtime" section **also stands unchanged** — its claim
was always that the types never spawn, sleep or await, which remains true.

**No rewrite lands at all now**, which is the doc-tracks-code rule reaching its
cleanest outcome: the module docs never changed, because the code never departed
from what they describe. The retraction that was scheduled for the
implementation commit is simply withdrawn.

`tokio` is already in the daemon image (`shekyl-daemon-rpc`, `features = ["full"]`),
so the runtime is not a new dependency under the single-image contract.

### 18.3 Proposed split

The Dandelion++ path and the covert-traffic path are separable, and only the
first carries findings:

- **RP-3a** — the zone, epoch/fluff/stem scheduling, and the map's ownership move
  to Rust; **F-4/F-5 close here**. The C++ noise channels keep working by reading
  the ordered slot snapshot RP-2a already exposes (`levin_notify.cpp:520` binds
  `channels[i]` to slot `i`; `map_snapshot` is that call).
- **RP-3b** — the noise channels follow, and the snapshot seam is deleted with
  them.

**Standing item for RP-3b: name the action, not the intent.** `run_stems()` does
`for (noise_channel& c : zone_->channels) c.next_noise.cancel()` — it cancels
covert-traffic timers and has nothing to do with stem routing. The name captured
the *caller's intent* in the clearnet configuration, where stems run and noise
does not, so "advance the stem machinery" and "cancel the noise timers"
coincided. Once Tor exists — noise runs, stems do not — the name is **actively
false**, and false on the transport that matters most. It nearly put covert
traffic into the 3a stem branch under a name that made the misplacement
invisible.

The detector is the **three-way disagreement**: name says "run stems", the header
comment says "next stem timeout", the body says "cancel noise timers". Only the
body is executable, and the disagreement itself marks a name written for a world
that no longer exists. These fossils cluster in the covert path — the fluff/stem
vocabulary has been slippery throughout it — so 3b's grounding trusts bodies over
identifiers harder than 3a's did.

The port is a **free rename**: name each Rust function for its body's action, and
where that differs from the C++ name, that difference is a dead assumption being
deleted. The old identifier survives only at the ABI shim where the oracle needs
it (the gtests call `run_stems`) — old names at the boundary, honest names where
the logic lives, exactly as the map port kept the C++ ABI over honestly-typed
Rust. Types stop the machine reasoning wrongly; names stop the human doing it.

Noise is conditionally active (`if (zone->noise.empty()) return`) and carries its
own strand-per-channel model, so it is genuinely a second subsystem rather than
an arbitrary cut. The split is a proposal, not a decision: it stands or falls on
whether 3a lands cleanly with the snapshot seam intact.

### 18.4 Acceptance

1. **The 33 `levin_notify` gtests pass unchanged**, through `run_epoch` /
   `run_stems` / `run_fluff` forwarding into the Rust scheduler. This is the
   round's primary oracle and the reason the riskiest step is tractable.
2. The corrected fluff delay is the crate's (`FluffScheduler`), and the C++
   `random_poisson_subseconds` draw is deleted — F-4/F-5 closed, with the
   derivation guarded at its sites per the STEMS=2 precedent.
3. **The timing correction carries its own oracle, and "wired" is not
   "witnessed".** F-4/F-5 are not closed when the corrected draw is wired —
   they are closed when a test witnesses that the *wired* draw is the corrected
   distribution. The gap is not hypothetical: `FluffScheduler::inherited()`
   constructs with `DelayFamily::Poisson` (the F-4 defect) and
   `FluffScheduler::memoryless()` with `Geometric`, at the same means. A stale
   wire is **one identifier**, and it compiles, fluffs, and passes all 33
   routing gtests — which are blind to timing — plus any "does it fluff" test,
   which is blind to distribution. So the fluff increment's acceptance is a
   **distribution assertion**: the family the zone actually draws from is
   `Geometric` and explicitly not `Poisson`, the inbound/outbound means match
   the configured averages with the outbound halved, and a seeded deadline
   sequence is pinned so *any* rewire of the draw fails the test. Armed trigger,
   not documentation — this is the one gain the routing oracle cannot see, and
   it is the gain the `lib.rs` seal was broken to obtain.

   **Generalised, after the negative control found a hole in this very oracle.**
   Wiring back to `inherited()` failed the family check and the frozen sequence —
   and *passed* the mean check, correctly, because F-4 is a **same-mean
   distribution swap**. The mean assertion is a distribution assertion and looks
   like the rigorous behavioural choice; it is blind, because the defect lives in
   the variance (CV ≈ 1 vs ≈ 0.2) and a mean integrates variance away. Had only
   that assertion been written, F-4 would have shipped through its own oracle.

   That is not specific to distributions. A defect that survived in production
   survived *because it produces plausible behaviour on the obvious metric* —
   F-4 lasted years in the inherited tree by being mean-correct, so its
   camouflage **is** the obvious metric. For **every remaining RP-3 correction**:
   assert on the axis where the defect lives rather than where measurement is
   easiest, and **run the negative control** — reintroduce the defect, confirm
   the oracle fails, and confirm *which* assertions fail. An assertion that stays
   green is blind, and identifying the blind one is worth more than adding a
   fourth.

   The gtests are silent on
   delays by construction, so they cannot witness F-4/F-5 — deliberately, and
   that is what makes them a clean routing oracle across a mixed
   port-plus-correction: they cover exactly the axis that must not change and say
   nothing about the axis that must. The corrected distribution is witnessed the
   way RP-4's embargo was, by the derivation and the crate's frozen tables —
   the conformance grades, their negative controls, and the golden vector — not
   by anything in `levin.cpp`.
4. `crypto::random_poisson_subseconds`' remaining users are enumerated, as RP-4
   did for `random_poisson_seconds`; anything left is named with its round.
5. The zone task is the only writer of zone state — asserted structurally (no
   C++ path mutates it) rather than by convention.
6. `schedule.rs`'s "No async runtime" section and `lib.rs`'s reason 2 are
   **unchanged**, because RP-3a does not depart from either: the types still
   never spawn, sleep or await, and the existing timer stays in charge. The
   earlier retraction is withdrawn.
7. **The §18.5 inventory is an invariant the implementation maintains, not a
   one-time check.** Every piece of relay state has exactly one owner —
   inventoried — or it does not land. `connection_count` is Rust-owned
   single-writer; the map snapshot flows Rust → C++ as a push. Any new shared
   state RP-3a introduces is a new inventory line that must resolve to
   single-owner-or-atomic before merge, and the push-not-pull discipline is
   re-applied to each.

   The "nothing straddles" property is **not self-maintaining** — finding 3 is
   the proof: a call that looked safe was unsafe until ownership was asked of
   it. The invariant survives the withdrawal of the seal-break unchanged, and
   for reasons that never depended on it: `get_status()` is callable from any
   thread, so *something* crosses threads and must be published rather than
   shared; and when the reactor eventually moves at C++ removal, an inventory
   already at single-owner is what makes that move a non-event rather than a
   new concurrency design.
8. **The live scheduler is a new crate, not an extension of
   `shekyl-relay-privacy`.** That crate's stated scope is *"Timing only. Nothing
   here serializes a message, chooses eligible peers, or touches a socket"*, and
   a zone actor does the last two. Keeping the split preserves what makes the
   round tractable: the primitives stay dependency-light, synchronous, and pure
   `&mut self` steps — which is exactly the property the `run_*` force-step
   hooks, and therefore the 33-test oracle, depend on. The new crate owns the
   driver and the transport callbacks and depends on the primitives; rule 25's
   "implement logic in a dedicated crate" points the same way.

### 18.4a The shim is the layer the oracle cannot see

The 33 gtests become the oracle only after the FFI increment, and they reach the
Rust through a C++ forwarding shim. That means they measure **shim ∘ Rust**, and
the shim is the one layer they cannot isolate — new code with no oracle of its
own, sitting inside the thing that is about to carry the whole round's weight.
Two failure modes, neither visible in a green run: a shim error **cancels** a
Rust error and the suite passes while both are wrong (until another call path
hits the same shim bug uncancelled), or a shim error **manufactures** what looks
like a port bug and sends debugging to the wrong layer.

So "the gtests pass" means "the Rust is correct" only if the shim is transparent,
which is a property to design for. Three requirements for that increment:

1. **Pure forwarding, zero logic.** Every shim function is one line: translate
   and call. No branching, no defaulting, no accumulation. A fat shim is where a
   bug hides underneath a green oracle.
2. **The fossil name is contained to that one line.** `notify::run_stems()`
   keeps its C++ identifier so the gtests compile, and forwards to a
   truthfully-named Rust function (it cancels noise timers). Pure forwarding
   matters twice here: it stops the misleading name from ever acquiring
   behaviour, so nobody adds logic *under* a name describing something else.
3. **`connection_count` is the one deliberate cache, and needs its own test.**
   The boundary publishes this derived fact as an atomic for off-task readers —
   a copy, and an exception to derive-don't-cache. It is legitimate because the
   alternative is worse: off-task readers deriving it live would have to reach
   into the map, reintroducing the pull-races-mutation hazard finding 3 closed.
   What keeps it honest is **single writer** — only the zone's owner writes it,
   readers only read. That is the discipline the inherited *"only update in
   strand"* comment asked for, now that the strand is gone and it must live in
   ownership instead. The reused oracle does not cover it, so it carries a test
   that nothing but the owning path writes it.

### 18.4b gtest → Rust-test map, and the honest scope of the oracle

Written **before** the daemon build, because it is cheap now and expensive to
reconstruct under a failing build. Its purpose is failure *attribution*, not
coverage: for a red gtest, the question is whether a Rust test **would fail if
the Rust were wrong in the way that gtest checks**. If such a twin exists and is
green, the failure is isolated to the shim by elimination — no rebuild, no
bisect. A twin that merely covers the same *area* does not support that
inference, so entries are only useful when tightly paired.

The 33 cases are a matrix — `{fluff, stem, local, forward, block, none}` ×
`{padding, no padding}` × `{public, private}` — over about eight behaviours:

| gtest group | Behaviour checked | Tight Rust twin | Pairing |
| --- | --- | --- | --- |
| `fluff_*` (×4) | fluffs to every peer but the source | `fluff_skips_the_source_and_releases_on_deadline` | tight |
| `stem_*` (×4) | routes to exactly one outbound successor | `everything_stems_during_a_stem_epoch`, `a_source_pins_to_one_stem_for_the_epoch` | tight |
| `stem_no_outs_*` (×2) | no routable slot ⇒ fluff fallback | `no_routable_slot_reports_no_route_not_a_fluff_epoch` | tight |
| `local_*` (×4) | **local origin always stems, incl. during a fluff epoch (RD-4)** | `a_local_tx_stems_during_a_fluff_epoch_rd4` | tight, both sides |
| `stem_mappings` | a source stays pinned to one stem for the epoch | `a_source_pins_to_one_stem_for_the_epoch` | tight |
| `fluff_multiple`, `fluff_with_duplicate` | batching accumulates without re-drawing | `a_burst_does_not_push_a_peers_flush_further_out` | tight |
| `forward_*`, `block_*`, `none_*` (×12) | relay-**method** dispatch | — | not zone logic; stays C++ |
| `noise`, `noise_stem` | covert channels | — | RP-3b; in 3a they consume the pushed snapshot |
| `command_max_bytes` | framing/size limit | — | transport; stays C++ permanently |

**Finding 1 — RD-4 is oracle-witnessed, and tightly.** The prediction was that
the 33 might not reach it, leaving the Rust test as sole guard. They do reach it:
`local_without_padding` loops epochs (`has_stemmed |= is_stem; has_fluffed |=
!is_stem; notifier.run_epoch()`) until it has seen **both** roles, and in each it
asserts under the comment *"run \"my\" txes which must always be stem"* that a
local transaction produces exactly **one** send rather than nine, with
`dandelionpp_fluff` false. That is the stem-vs-fluff axis — the axis a reversion
of `|| local` shows on — asserted from the C++ side, pairing tightly with the
Rust twin, which asserts the same axis. Notably the gtest arrives at a
guaranteed fluff epoch by *cycling roles*, the same discipline the Rust twin
reaches by seed search: neither injects the role.

**Finding 2 — StemSlots index-order is *not* oracle-witnessed.** The noise
cases assert **counts** (`EXPECT_EQ(2u, sent)`, `connections_filled`), and
`local_*` asserts only that a stem lands on an *outbound* peer
(`(context - begin()) % 2 == 1`). Nothing in the 33 asserts that noise channel
*i* is bound to stem slot *i*. So contract 3 at the new boundary — order
preserved, nils in position — is witnessed **only** by
`stem_slots_cross_in_index_order_with_nils_in_position` in the FFI seam tests.

That is not a gap to close; it is the oracle's honest scope, and it must be
stated so nobody later reads "33 gtests green" as "everything verified". Green-33
means *the behaviours the gtests reach are correct*. Index-order is correct
because a seam test says so, and the seam test is therefore load-bearing rather
than belt-and-braces — it is the sole witness of the property the RP-3b noise
channels will depend on positionally.

**Consequence for the build.** Every gtest whose behaviour is zone logic has a
tight twin, so a red gtest with a green twin attributes to the shim without
rebuilding. The three groups with no twin (`forward`/`block`/`none` dispatch,
noise, framing) are C++-side behaviour the port does not move — a failure there
attributes to the shim or to the C++ that was already there, not to the Rust.

### 18.4c Outcome — what the oracle caught, and what the map could not

RP-3a is built and green: 33/33 `levin_notify`, and 1017 passed / 0 failed in the
full unit suite. Two results are worth keeping.

**The oracle caught a real privacy regression.** The first pass of the shim lost
one line of `fluff_notify` — *"When i2p/tor, only fluff to outbound
connections"* — and eight `private_*` cases failed together, each reporting nine
peers notified where five belonged. It reads like a delivery detail and is a
privacy rule: on a hidden service an inbound peer is a stranger who dialled us,
so relaying to it hands a transaction to a peer this node never chose — the exact
sybil exposure i2p/tor is standing in for now that Dandelion++ stemming is off.
It is now `FluffReach::OutboundOnly`, a zone-lifetime policy in Rust, with a test
asserting *who* received the batch plus a public-zone negative control.

**But §18.4b's map could not have predicted it, and that is the lesson.** The map
is organised by the behaviours the port *knew it was moving*; the outbound-only
rule appears in none of its rows, because a rule nobody noticed cannot be listed
as one to preserve. The `private_*` cases sat in the matrix as a `{public,
private}` axis over the same eight behaviours — the map treated "private" as a
*configuration* of known behaviours rather than as a column with a behaviour of
its own.

So the map does what it claimed and no more: it **attributes** failures, it does
not **enumerate obligations**. It was still worth writing — the eight failures
were isolated to a single dropped rule in one reading, without a bisect — but a
port's real obligation list is the source it is porting *from*, read line by line,
not a table of what the porter thought was there. The rule that bites is
structurally the one absent from the table, because the table is built from what
was noticed.

**A note on where it was found.** This is also the case for building the oracle
before believing the port. Nothing in the Rust tests, the FFI seam tests, fmt or
clippy could have caught it: every one of them was green while the daemon fluffed
transactions to peers it had no business reaching. Only running the inherited
suite against the new implementation found it, which is what "the C++ is the
oracle until the corpus *is* the spec" means in practice.

**A second dropped rule the oracle did *not* catch — the epoch rebuild.** The
inherited epoch **replaced** the stem map outright (`start_epoch` built a fresh
`connection_map{connections, count}`; `change_channels` assigned it over the old
one), while the mid-epoch refresh **merged** into it
(`connection_map::update`). Two operations. The port put both onto the merge, so
after the first population the stem graph never rotated: successors persisted and
every source stayed pinned to the slot it first drew, for the life of the
process. That is the property epochs exist for, and the embargo derivation
assumes it.

All 33 gtests passed with the graph frozen, and passed again after the fix. They
could not see it: `local_*` cycles roles until it observes both, and
`start_epoch` *does* still re-draw `fluffing`, so role rotation looked healthy;
`stem_mappings` asserts pinning holds *within* an epoch, which a frozen map
satisfies more strongly than a correct one. The oracle asserted the axis the bug
preserved and never the axis it broke — the same shape as the `private_*` rule,
one layer deeper.

It is now two methods, `Zone::update_stems` (merge) and `Zone::rebuild_stems`
(rollover), because a single method whose behaviour depended on a width check is
what let one silently stand in for the other. The witness is a rollover with an
**unchanged** peer set — the one case the two disagree on — asserting that source
pinning resets, since with two slots a re-draw may legitimately choose the same
pair.

**Honest scope, second entry: the production timer path is not exercised by the
33.** Their `io_service_.poll()` runs only *ready* handlers, and the wake deadline
is seconds to minutes out, so no gtest ever fires the wake — every one of them
drives the zone through `run_fluff`/`run_epoch`, which force a step directly. So
`next_wake() -> from_ms() -> fire -> poll() -> re-arm`, and the whole
`pending_wakes` balance that stops a re-armed timer from re-arming itself
forever, have **no C++-side coverage**. The suite not hanging is weak evidence
that the millisecond round-trip is sane, and that is all it is. The FFI half is
covered by `polling_at_the_reported_wake_time_releases_the_batch`; the asio half
is not, and belongs to whatever round next touches that timer.

### 18.5 State inventory — single ownership, and why it outlives the seal question

This section was written to price a seal-break that has since been **withdrawn**
(§18.2): RP-3a adds no reactor, so `lib.rs` reason 2 holds. The ledger it
contained was wrong — F-4/F-5 close without any reactor change — and is deleted
rather than patched.

**The inventory survives the correction, on grounds that never depended on it.**
Single ownership is required because `get_status()` is callable from any thread,
so one fact genuinely crosses threads and must be *published* rather than shared;
and because when the reactor does move at C++ removal, an inventory already at
single-owner makes that a non-event instead of a fresh concurrency design. It
also earned its keep independently: it caught a duplicate-fact bug
(`PeerFluff::flush_at`) in a single-threaded path, because it asks *"who owns
this fact?"* rather than *"can this race?"*.

**The inventory.** Zone state from `levin_notify.cpp`, with today's ownership
taken from the code's own discipline comments:

| State | Owner today | Owner after RP-3a |
| --- | --- | --- |
| `next_epoch`, `flush_txs` (`steady_timer`) | zone strand | **asio** — collapsed to one timer, armed from `next_wake()` |
| `contexts` (`uuid → {fluff_txs, flush_time, m_is_income}`) | zone strand | **Rust** |
| `map`, `fluffing` | zone strand | **Rust** (`map` already Rust-backed, RP-2a) |
| `flush_callbacks` | zone strand | **C++**, as `pending_wakes` — reactor state, not schedule state |
| `strand` | — | **stays** — nothing replaces it |
| `channels` (`deque<noise_channel>`) | *"Never touch after init; only update elements on `noise_channel.strand`"* | **asio** (RP-3b) |
| `noise_channel::{active, queue, next_noise, connection}` | per-channel strand | **asio** (RP-3b) |
| `p2p`, `noise`, `nzone`, `pad_txs` | const after construction | config — no owner needed |
| **`connection_count`** | *"Only update in strand, **can be read at any time**"* | **the one real straddle** — see below |

**Three rows changed when the seal-break was withdrawn**, and they are called out
because the first draft of this table assigned them under the reactor premise —
a Rust task owning the sleep, replacing the strand. With no task:

- **The timers stay asio's.** Rust owns the deadline *value*; asio owns the
  *sleep*. The two timers collapse into one, armed from `next_wake()`, because
  that call returns the earliest deadline and there is nothing left for a second
  timer to hold.
- **The strand stays.** Nothing replaces it, so `deleted` was only ever true of
  the design that is no longer being built.
- **`flush_callbacks` stays C++.** It is not schedule state — it is the guard
  that stops a re-armed timer from re-arming itself forever, so it belongs with
  the timer it guards. It moves in name only, to `pending_wakes`, because one
  timer now covers both kinds of wake and "flush" would misname it.

Assigning these to Rust was not a *safety* error — it was an ownership claim on
state whose owner turned out not to move. Leaving it standing would have left the
implementation and the inventory disagreeing, which is how an invariant quietly
becomes a description.

Three findings, and the third is the one that would have bitten:

1. **`connection_count` is the only genuine straddle.** The code says so itself:
   written on the strand, read from anywhere — `get_status()`
   ([`:755`](../../src/cryptonote_protocol/levin_notify.cpp#L755)) is public API
   callable on any thread, and the tests call it. Resolution: it becomes a
   Rust-owned atomic, written **only** by the zone task, read lock-free through
   the FFI. That preserves the existing read-from-anywhere contract and is
   single-writer by construction rather than by convention.
2. **The 3a/3b split follows a serialization boundary that already exists.**
   Noise channels are not on the zone strand today — each carries its own strand
   and timer, and the comment forbids touching them after init except on that
   strand. So deferring them to 3b splits along a boundary the inherited code
   already draws, rather than inventing one.
3. **The map snapshot must be a push (Rust → C++), not a pull.** During 3a the
   C++ noise channels still need the ordered slot snapshot to bind
   `channels[i]`. Today `update_channels::post`
   ([`:514–524`](../../src/cryptonote_protocol/levin_notify.cpp#L514-L524)) reads
   the map *on the zone strand*, which is what makes it safe. With the strand
   gone and the map owned by the Rust task, a C++-initiated `map_snapshot` call
   would race the task's own mutations — reintroducing exactly the
   second-reactor-in-the-p2p-path hazard the seal warned about. So the task
   **pushes** the snapshot outward when the map changes, and C++ never pulls it.

Finding 3 is why this inventory is an acceptance item and not a paragraph: the
3a/3b split looked safe until the ownership question was asked of it, and the
answer changed the direction of a call.

**Standing obligation.** Any new state added on either side of the boundary is
inventoried before it is written, with a named single owner. "Nothing straddles"
is what keeps the one genuinely cross-thread fact publishable rather than shared,
and what will make the eventual reactor move a non-event — so it is maintained
deliberately rather than assumed to persist.

---

## 19. RP-2b design round — the churn-stable alternate (W3c) and Q-10 selection

Short design leading the RP-2b implementation commits on
`feat/rp2b-churn-stable-alternate`.

RP-2b is the round §12.5 named a **spec gap** for, and it is the last named gap in
this arc: F-1…F-5 all closed (RP-1 measurement, RP-4 embargo, RP-3a scheduler).
Nothing here is genesis-blocking — relay timing is node-local policy, not
consensus — but W3c is a defect in the design's own terms rather than a
consolidation, which is why it precedes RP-3b's covert-channel port.

### 19.1 Re-census — the anchors §§12.8–12.11 rest on, re-verified at source

§12.11's handoff makes this the round's **first move**, in its own words: *"§§12.8
–12.11 are grounded against `get_stem` / `out_mapping_` / the embargo-disarm
behaviour of a dev tree that will have moved by the time RP-2 begins… Re-verify
them at source before building on them."*

That instruction has since become an understatement. RP-3a **rewrote
`levin_notify.cpp` end to end and deleted `src/net/dandelionpp.{h,cpp}`**, so
every one of the eleven `levin_notify.cpp` line anchors and the two
`dandelionpp.cpp` anchors below points at something that has moved or no longer
exists. The line numbers are stale by construction. The question this census
answers is not "do the lines still resolve" but **"is the claim still true, and
where does the fact live now."**

| # | §12.x claim | Anchor as written | Status | Where the fact lives now |
| --- | --- | --- | --- | --- |
| G-1 | Stem *selection* is public/clearnet-zone only; Tor has no occupancy mechanism | `send_txs` `levin_notify.cpp:829-851, 866-872` | **holds** | `send_txs` `:963-1017` — the noise branch still short-circuits before the Dandelion++ branch, so a noise zone never reaches `dandelionpp_notify` |
| G-1 | *"good protection against ISP adversaries, but not sybil adversaries"* | `:829` | **holds, verbatim** | `:974-976` |
| G-1 | `MWARNING("Dandelion++ stem not supported over noise networks")` is the fork point | `:849` | **holds, verbatim** | `:994` |
| G-1 | The reference's stated obstacle is fork-reconciliation bookkeeping | `:836-838` | **holds, verbatim** | `:981-983` |
| G-2a | Epoch boundary **replaces** the whole map with a fresh rebuild | `change_channels` `:587-617` | **holds — and was briefly violated** | `Zone::rebuild_stems` (`zone/mod.rs`). RP-3a first ported this onto the *merge* path, freezing the stem graph; caught and fixed in `d7096527a`, witness `an_epoch_rollover_rebuilds_the_stem_map_rather_than_merging_into_it` |
| G-2b | Mid-epoch churn fresh-draws the churned slot | `update_channels::run` → `map.update()` `:528-536`, `dandelionpp.cpp:160` | **holds — mechanism unchanged** | `Zone::update_stems` → `StemMap::update` (`stem_map.rs`). **This is the W3c gap's site.** |
| G-2b | Trigger: stem-send-failure retry | `dandelionpp_notify:575` | **holds, restructured** | `dandelionpp_notify` `:745-751` — plus a *new* earlier trigger, below |
| G-2b | Trigger: `new_out_connection` | `net_node.inl:1349` | **holds, but noise-only** | `notify::new_out_connection` early-returns on `noise.empty()`, so on the **clearnet path where stem selection actually happens (G-1) this trigger never fires**. It was already noise-only pre-RP-3a; the design's trigger list reads as though both fire on the path W3c is about. |
| G-3 | Stem pool is all synced outbound, anchors included | `get_out_connections:142-159` | **holds** | `:186-192` |
| G-4 | Anchor admission is any successful outbound handshake, no behavioural criterion | `net_node.inl:1347` | **holds, line exact** | unchanged — RP-3a did not touch `net_node.inl` |
| G-4 | On reconnect the 2 anchor slots fill first | `net_node.inl:1820` | **holds, line exact** | unchanged |
| §12.6 | Fluff is transport-gated: on Tor it fluffs outbound-only | `fluff_notify` `:448` | **holds — moved languages** | `FluffReach::OutboundOnly` (`zone/mod.rs`). RP-3a dropped this rule and the eight `private_*` gtests caught it; restored with `a_private_zone_fluffs_only_to_outbound_peers` |
| — | `send_noise` pads every channel to a constant rate on its own timer | `:663` | **holds** | `:780`, `:811` |

**Two findings from the census, neither of which is a line-number update.**

**C-1 — a new mid-epoch re-roll trigger exists that the design does not model.**
RP-3a's review round added `Zone::plan_relay_with_refresh`, which merges the
current outbound set into the map on **any** `NoRoute` and re-plans, before the
transport retry. That was the right move for its own reasons — it keeps
"empty/stale map ⇒ refresh" as zone logic rather than shim logic — but it means
the clearnet re-roll surface is now *two* triggers deep (`NoRoute` refresh, then
send-failure refresh) where §12.6 models one. W3c's requirement is that the
alternate be **stable across churn refill**; a second refresh path is a second
place for the alternate to be re-rolled, so the churn-stability property must be
specified against `StemMap::update` itself rather than against any one caller.
That is the safer place for it regardless — callers multiply, the mechanism does
not.

**C-2 — `new_out_connection` does not fire on the path W3c is about.** The design
lists it beside the send-failure retry as though both drive clearnet churn refill.
It is guarded by `noise.empty()` and so is a no-op on public zones. This does not
weaken W3c — the send-failure retry *is* the black-hole-correlated trigger, and it
fires — but it removes one of the two triggers from the clearnet picture, which
matters when sizing how often an adversary can induce a re-roll. **The
inducement budget is smaller than the design's trigger list implies.**

**What this census does not re-open.** The `ε → distinct-peers` and top-2-share
numbers are in-crate measurements over `StemMap`, not over the C++ that moved;
RP-3a ported that logic faithfully (the six `dandelionpp_map` gtests passed
unchanged against it before they were retired), so those numbers stand. The
remaining §12.11 owes — the genuine background-failure rate, and the
cooldown/threshold sweep as a **reopen-checkpoint rather than a confirm-only
sweep** — are untouched by RP-3a and carry forward as written.

### 19.2 The churn-stable successor — specified over the *sequence*, not the call

**The mechanism, re-read at source (not from §12.5's description).** `StemMap`
pins a source to a **slot index**, not to a peer: `inbound: source → usize`, and
`stem_for` returns `out[index]`. `update()` empties a slot whose peer is gone
(`*slot = None`) and the backfill loop refills it with a uniform draw from the
current outbound pool. The next `stem_for` for that source then takes the
`self.out[index].is_some()` fast path and returns **the new occupant** — no
re-pin branch executes, nothing is logged, and the source's stem traffic moves to
a freshly drawn peer.

That is sharper than W3c as written. The design describes churn re-rolling *the
alternate*; what the code does is re-roll **the source's primary successor**, and
it does so on the one path where no selection code runs. There is a second,
visible path — if `update()` cannot backfill, the slot stays `None`, `stem_for`
takes the re-pin branch and `select_slot`s afresh — but the invisible one is the
common case, because backfill succeeds whenever any candidate is spare.

**Why the property is stated over sequences.** §19.1's C-1 found the clearnet
re-roll surface is two triggers deep: `plan_relay_with_refresh` merges on any
`NoRoute`, and `dandelionpp_notify` refreshes again on send failure. Both flow
through `StemMap::update`. A property that says *"one `update` does not re-roll a
pinned source"* is escaped by their composition — two calls in sequence, each
individually stable, can still hand the source a different peer than it started
with. And W3c's exposure is **cumulative**: an adversary who can induce `k`
re-rolls gets `1 − (1 − g)^k`, not `g`. The per-call framing prices one roll and
the threat model is about the sequence.

**The property.**

> Within an epoch, a source's successor is drawn from the set of peers live in
> the stem map **at that source's first pin**, and that set never grows. Any
> number of `StemMap::update` calls may refill slots for the benefit of
> *unpinned* sources; no already-pinned source may ever be routed to a peer that
> entered the map after it pinned.

Stated this way it is closed under composition by construction — the successor
candidate set is frozen per source at pin time, so no sequence of updates can
introduce a new candidate. It also names the fallback: when a pinned source's
successor churns out, it moves to the next still-live peer **from its own frozen
set** — the *alternate*, in §12.5's sense — and only when that set is exhausted
does it have no successor.

**What this buys, in the threat's terms.** W3c's adversary is the dropping
successor, or induces churn on it; the drop is what triggers the refill. Today
that hands them a fresh draw at ≈ `g`, repeatable. Under the property, dropping
hands the source to a peer that was **already in its set before the adversary
acted** — the adversary gains no new roll, so induced churn stops being an
exposure amplifier and repeated churn buys nothing beyond the first. Exhausting
the frozen set requires churning *every* peer in it, which is the both-successors
case W3 already bounds (`≈ 0` at baseline `g = f`) rather than a new gap.

**What it deliberately does not do.** It does not freeze the *map* — new peers
still backfill empty slots and still serve sources that pin after them, so the
map keeps healing and a node that starts with one outbound peer is not stuck with
it. It does not touch cross-epoch rotation: the frozen set is per-epoch, and
`rebuild_stems` re-draws everything at the boundary (§19.1 G-2a), which is the
rotation §6.8's intersection defence rests on.

**Acceptance.**

1. A measurement, in-crate, of induced-churn exposure against `k` forced
   re-rolls, with both arms driven by the same trial. The gap is *shown* before
   it is closed — the number is the finding, not the fix. **Measured below; it
   corrected this section's first draft, which had asserted the shape.**
2. A structural test that a pinned source never routes to a peer that entered the
   map after it pinned, asserted across a **sequence** of `update` calls, with
   both C-1 triggers represented. Per-call stability is not the property and a
   per-call test would pass on the defect.
3. A negative control on (2): with the frozen set removed, the test must fail.
   The composition is exactly where a stability property looks correct and is
   not, so the control has to exercise the sequence, not one call.

### 19.3 Measured — induced-churn exposure, and two corrections it forced

`simulate_induced_churn_exposure` (`conformance/selection.rs`) runs all three arms
on the same trial. At `D_out = 12`, `STEMS = 2`, 200k trials. The reference column
uses the **effective integer share** `g_eff = round(g · D_out) / D_out` (so
nominal `g = 0.10` becomes `1/12 ≈ 0.0833`), matching how the trial places the
adversary on a discrete outbound pool — not the closed form at nominal `g`.

| `g` | `k` | today (slot-pinned) | §19.2 (frozen set) | `1 − (1−g_eff)^(k+1)` |
| --- | --- | --- | --- | --- |
| 0.10 | 0 | 0.0829 | 0.0829 | 0.0833 |
| 0.10 | 1 | 0.1655 | 0.1674 | 0.1597 |
| 0.10 | 2 | 0.2516 | **0.1665** | 0.2297 |
| 0.10 | 4 | 0.4172 | **0.1665** | 0.3528 |
| 0.10 | 8 | 0.7508 | **0.1663** | 0.5430 |
| 0.10 | 16 | 0.9168 | **0.1675** | 0.7722 |
| 0.25 | 16 | 1.0000 | 0.4546 | 0.9925 |
| 0.30 | 16 | 1.0000 | 0.5759 | 0.9990 |

**The gap is real and it is not marginal.** At the baseline `g = 0.10` an
adversary who can induce ~16 re-rolls reaches the origin's stem path **91.7 %** of
the time, against **16.7 %** if the candidate set is frozen. The frozen arm is
flat in `k` from `k = 2` onward — it saturates once the source has walked its two
initial peers, which is the whole point: **more induced churn buys nothing.**

**Correction 1 — the frozen arm does not flatten to `g`, and §19.2's first draft
said it would.** It flattens to `P(≥ 1 of the source's *initial* stems is
adversarial)` — ≈ `2g` for small `g` (0.167 at `g = 0.10`), not `g` (0.083). The
source can still be handed to an adversarial *alternate*; what it can no longer
be handed is a peer drawn *after* the adversary acted. That is the property, and
it is weaker than the sentence originally written here. The acceptance criterion
that said "show the gap before closing it" is what caught it — the shape was
asserted, then measured, and the measurement disagreed.

**Correction 2 — the closed form *understates* today's compounding.** The
fresh-draw arm sits **above** `1 − (1−g_eff)^(k+1)` at every `k > 0` (0.917 vs
0.772 at `g = 0.10, k = 16`), because churned peers do not return: the spare pool
shrinks and its adversarial fraction rises with each induced churn. The
independent-draw reference is therefore a *lower* bound on the real exposure, not
an estimate of it — so "≈ `g` per re-stem", compounded naively, is optimistic
about the mechanism it prices.

The fresh arm's ceiling is `(D−1)/D = 0.917`, not 1: the one peer it can never be
routed to is the *other* stem slot, which is never churned in this model. That
the measurement lands on `11/12` exactly is the check that the model is the
mechanism and not a caricature of it.

**Correction 3 — there is no partial version of this property, and a third arm
proved it.** §19.2 makes an exhausted frozen set terminal: the source fluffs
until the epoch rolls. That is an availability cost, and the obvious softening is
to allow one fresh pin on exhaustion — the adversary would then have to churn a
source's *entire* set to buy a single new draw. Measured as a third arm
(`frozen_repin_exposure`), it is worth nothing:

| `k` | today | frozen | frozen + re-pin |
| --- | --- | --- | --- |
| 2 | 0.2521 | 0.1666 | 0.2502 |
| 8 | 0.7488 | 0.1666 | 0.7505 |
| 16 | 0.9167 | 0.1657 | 1.0000 |

The re-pin arm tracks the **unfixed** baseline. At `STEMS = 2` a "full sweep" is
two churns and the fresh pin hands back *two* new peers, so the escape hatch
returns the whole amplifier — and at `k = 16` it is worse than doing nothing,
because re-pinning keeps drawing from a pool whose adversarial fraction rises as
honest peers are consumed. The property is all-or-nothing at this stem width.

So the availability cost is not a knob to soften but a price to either pay or
reject. It is paid here, bounded by the epoch (`rebuild_stems` re-draws every pin
at the boundary), and how often honest churn actually reaches a source's whole
set is the ambient-rate measurement §12.11 still owes — the same measurement the
cooldown/threshold work is blocked on.

---

## 20. RP-3b design round — the covert-channel port, and the seam that inverts

Short design leading the RP-3b implementation commits on
`feat/rp3b-covert-channels-rust`. RP-3b is the **last structural round in the
relay arc**: F-1…F-5 are closed (RP-1 measurement, RP-4 embargo, RP-3a
scheduler), W3c is closed (RP-2b), and what remains in `levin_notify.cpp` that is
not transport is the covert path — the noise channels, their timers, and the
`on_slots` push RP-3a built to keep them working across the cut.

Nothing here closes a finding. That is worth stating at the top, because it
changes what the round is *for*: RP-3b is a **consolidation**, and a
consolidation's whole value is that it removes a seam rather than adding a
mechanism. If it ends with the seam still standing under a different name, it did
not happen.

**Identifiers this round registers** (rule 94 — a family registers at birth, and
these are numbered in discovery order, which is not document order):

| ID | Invariant | Defined | Acceptance |
| --- | --- | --- | --- |
| **CV-1** | repointing a channel discards the in-flight remainder | §20.5 | item 2 |
| **CV-2** | an empty slot emits no covert send at that index and shifts no other | §20.3 | item 3 |
| **CV-3** | an armed covert deadline survives wakes it did not cause | §20.2a | item 9 |
| **Q-11** | the covert timing constants owe a derivation | §20.9 | *ranked next, out of round* |

`CV-*` is a **covert-path invariant** — a privacy property of the noise channels
that must survive the port. All three are either untested today (CV-1) or newly
reachable *because* of the port (CV-2, CV-3), which is why they are named here
rather than assumed.

### 20.1 Re-census — the covert path re-verified at source

§18.3 proposed the 3a/3b split against a tree that has since moved twice (RP-3a's
shim rewrite, RP-2b's `Pin` change). Re-verified at today's `dev`:

| Anchor | Site | State |
| --- | --- | --- |
| `noise_channel` | [`:322–344`](../../src/cryptonote_protocol/levin_notify.cpp#L322-L344) | `active`, `queue`, `strand`, `next_noise`, `connection` — unchanged by 3a |
| per-channel strand discipline | [`:374`](../../src/cryptonote_protocol/levin_notify.cpp#L374) | *"Never touch after init; only update elements on `noise_channel.strand`"* — holds |
| the push seam | [`:521–557`](../../src/cryptonote_protocol/levin_notify.cpp#L521-L557) | `on_slots`, positional, nils in position, `assert(count <= channels.size())` |
| covert send loop | [`:768–837`](../../src/cryptonote_protocol/levin_notify.cpp#L768-L837) | `send_noise` — drains `active`, then `queue`, else dummy |
| enqueue | [`:389–421`](../../src/cryptonote_protocol/levin_notify.cpp#L389-L421) | `queue_covert_notify` — drops when the channel is nil |
| repoint | [`:423–450`](../../src/cryptonote_protocol/levin_notify.cpp#L423-L450) | `update_channel` — **restarts the in-flight message** |
| the misnamed hook | [`:939–950`](../../src/cryptonote_protocol/levin_notify.cpp#L939-L950) | `run_stems()` cancels noise timers; 3a left a handoff comment |

One correction to §18.3's framing. It says RP-3b is where *"the noise channels
follow, and the snapshot seam is deleted with them."* The seam is not deleted.
See §20.3 — it **inverts**, and the difference decides the round's shape.

### 20.2 Reconciling §18.5 — the ownership row that has to split

§18.5's inventory assigns `channels` and `noise_channel::{active, queue,
next_noise, connection}` to **asio (RP-3b)**. Read literally that is a null
round: if every field stays where it is, nothing ports. Read as "these do not
move to Rust" it contradicts §18.3, which says the channels follow.

Both readings are wrong because the row is **not decomposed**. It was written
during 3a, about state 3a did not touch, and it records *where the fields live*
rather than *who decides their values* — the distinction 3a's own timer
resolution turned on. Applying that resolution here splits the row cleanly:

| Fact | Owner after RP-3b | Why |
| --- | --- | --- |
| *when* channel `i` next sends | **Rust** (deadline value) | same as `next_wake()`: a schedule fact |
| the *sleep* for that deadline | **asio**, on the **existing single `wake` timer** | see §20.2a — the per-channel `next_noise` timers are removed, not kept |
| the per-channel `strand` | **asio** | still serializes the byte state; see §20.2a |
| *which peer* channel `i` points at | **Rust** | it is stem slot `i` — Rust already owns the map |
| *whether* this send is dummy or real | **Rust** | a schedule decision, not a byte operation |
| `active` / `queue` **bytes** | **C++** | levin fragments; rule 36 — Rust holds no wire payloads it does not need |
| the dummy payload and its size | **config** | see §20.4 — currently three facts in one field |

So RP-3b moves **decisions**, not buffers. §18.5's row is amended to this table
rather than left to be re-read charitably; an inventory that needs charitable
reading has already stopped being an invariant (§18.5's own standing obligation).

### 20.2a Which strand calls the FFI — the question that decides the shape

The table above is not self-executing, and left at that it admits two readings
that differ in safety. The covert timers are **per channel**, each on its own
strand. Moving their deadline *values* to Rust while keeping N timers gives:

- **(a) Rust publishes N deadlines, C++ arms N timers.** Then the zone handle is
  consulted from `CRYPTONOTE_NOISE_CHANNELS` strands instead of one. That is
  §18.5's `connection_count` straddle multiplied by the channel count, and it is
  finding 3 exactly — a C++-initiated read racing the Rust owner's mutations.
  **Rejected.**
- **(b) Covert deadlines fold into `next_wake()`, per-channel timers deleted.**
  One sleep, one caller. But taken naively this also drags `send_noise`'s byte
  work (`active.take_slice`, `queue.pop_front`) onto the zone strand, leaving the
  per-channel strands serializing nothing — and the inherited discipline comment
  ([`:374`](../../src/cryptonote_protocol/levin_notify.cpp#L374)) with no
  referent.

**Adopted: (b), with the dispatch split.** `next_wake()` already returns the
earliest deadline across every scheduled step; covert sends become another kind
of step, so Rust tracks per-channel deadlines internally and folds them into the
same answer. The single `wake` timer fires on the zone strand, which is the
**sole caller into the zone handle** — unchanged from 3a. Rust then emits, per
channel that has come due:

```text
on_covert_send(channel_i, peer, DUMMY | REAL)
```

and the C++ callback **posts that instruction to `channels[i].strand`**, where
the byte work happens exactly as it does today. Nothing reads the zone handle off
a channel strand.

This keeps all three invariants that were in tension:

1. **One FFI caller.** The zone strand, as in 3a. No straddle, no new reactor,
   reason-2 seal untouched.
2. **The per-channel strands keep their job.** They still serialize `active`,
   `queue` and `connection` against the two writers that exist — the dispatch
   post above, and `queue_covert_notify` posted from `send_txs`. The `:374`
   comment stays true and keeps a referent.
3. **Per-channel timing stays independent.** Folding the *sleep* is not folding
   the *schedule*: Rust holds a separate deadline per channel and the wake merely
   asks "what is earliest". This is precisely what 3a did when two zone timers
   became one, and the same argument applies — a second timer would need a second
   deadline, which would be a copy of a fact the zone already holds.

The delta from today is therefore `CRYPTONOTE_NOISE_CHANNELS` timers becoming
zero, not becoming one: the covert path gains no timer of its own and rides the
one that already exists.

**The fold is correct only under deadline stability, and that is a precondition,
not a nice-to-have.**

> **CV-3.** A covert channel's armed deadline is drawn once and survives every
> wake it did not cause. Wakes triggered by the fluff scheduler, an epoch
> rollover, or another channel coming due must leave it untouched.

State it here rather than in an implementation note, because **the fold is what
makes the bug reachable at all** — this is not a general hygiene rule that
happens to apply, it is the specific hazard the fold introduces. With N
independent timers the property is free and the defect is *structurally
unavailable*: nothing but channel `i`'s own timer can reach channel `i`'s
deadline. Folding creates the shared query path, and the shared query path
creates the possibility of resampling on someone else's wake. A future
implementer must be able to read this as the fold's own cost rather than as
boilerplate, or they will fold without preserving. And a redraw on every unrelated wake resamples `noise_min_delay +
U(0, noise_delay_range)` repeatedly and keeps the minimum, which biases the
effective covert interval **short** — a covert channel emitting faster than its
distribution says is a privacy defect, and it is one that:

- no gtest in the tree would catch (§20.5 — the two noise cases assert counts,
  and a biased-short interval still produces the expected count per poll);
- **no conformance test would catch even though one is already aimed here** —
  `grade_uniform`
  ([`grade.rs:96`](../../rust/shekyl-relay-privacy/src/conformance/grade.rs#L96))
  says in its own doc that it applies to *"the epoch jitter and the noise
  cadence"*. An earlier draft of this section claimed the instruments were
  pointed elsewhere; they are not, and the correction strengthens the point
  rather than weakening it: the machinery is already aimed at this draw and
  **still** cannot see the defect, because it grades the draw and the defect is
  in the selection among draws;
- looks like correct behaviour under casual inspection, because each individual
  draw *is* from the right distribution.

That last point determines **what instrument CV-3's witness must be, and what it
must not be.** The defect does not live in the draws; it lives in the *selection
among* draws. Every sample is honestly distributed, and the bias is produced by
repeatedly drawing and keeping the minimum — so a goodness-of-fit test against
`noise_min_delay + U(0, noise_delay_range)` passes on defective and correct
implementations alike. That is one level below where the crate's conformance
instruments point, which is why aiming the existing embargo and fluff-delay
machinery at the covert schedule would **not** catch this even after Q-11 gives
those constants a derivation. CV-3's witness is therefore an *identity*
assertion — this channel fires at the deadline it was armed with — not a
distributional one.

That last property is what makes it worse than option (a)'s races: a race
eventually manifests as a crash or a corrupted send, whereas a biased-short
covert interval simply relays sooner and reports nothing. So CV-3 is the
condition under which folding is *strictly better* than keeping N timers. Without
it, folding is worse than the option this section rejects, and a future
implementer who folds without preserving deadlines should find that written down
rather than have to rediscover it.

**This is an acceptance item, not a note** (§20.7 items 8 and 9), because it is
the one place the round could quietly re-break 3a's seal, and it would do so
invisibly — option (a) compiles, passes both noise gtests, and races only under
load; a deadline-resampling fold passes everything, always.

### 20.3 The seam inverts — and the seal migrates rather than dying

Today Rust pushes an **ordered slot array** and C++ decides what to do with it:

```text
Rust update_stems ──on_slots(slots[], count)──▶ C++ posts update_channel{i, slots[i]}
```

C++ is performing the channel→slot binding. But after §20.2 that binding is a
Rust-owned fact, so the array crossing the boundary is C++ being handed the
*inputs to a decision Rust already made*. The port replaces it with the decision
itself:

```text
Rust covert step ──on_covert_send(channel_i, peer, DUMMY|REAL)──▶ C++ sends bytes
```

The slot array stops crossing. **`SlotsCb` is deleted** — genuinely, not renamed
— and with it the `count <= channels.size()` reconciliation, because Rust no
longer publishes a width for C++ to reconcile against; it addresses a channel
directly or does not.

**What does not go away is the property.** "Covert channel `i` is bound to stem
slot `i`, and an empty slot is a nil in position rather than a compaction" was
true across the FFI and stays true *inside* Rust — it is the same requirement,
one layer in. So `stem_slots_cross_in_index_order_with_nils_in_position`
([`relay_zone_ffi/tests.rs`](../../rust/shekyl-ffi/src/relay_zone_ffi/tests.rs)),
sealed in RP-3a as the sole witness, is **migrated, not deleted**.

**Can Rust actually observe it? Yes — verified at source before relying on it**,
because if it could not, acceptance item 3 would be unsatisfiable and the round
would need a different shape. Three ingredients, all present today:

| Ingredient | Site | Survives the inversion |
| --- | --- | --- |
| ground truth from the owning structure | `Zone::stem_slots() -> &[Option<ConnectionId>]` ([`zone/mod.rs:464`](../../rust/shekyl-relay/src/zone/mod.rs#L464)) | yes — the inversion does not touch `map.slots()` |
| emission capture in a test | `rec_slots` ([`tests.rs:33`](../../rust/shekyl-ffi/src/relay_zone_ffi/tests.rs#L33)), a supplied `extern "C"` collector | yes — a `rec_covert_send` is the same pattern |
| deterministic time | `shekyl_relay_zone_poll(handle, now_ms, …)` | yes — "channel comes due" is driven, not awaited |

The ingredient that matters most is the first: the expectation is still sourced
from the owning structure rather than the transform under test, which is the
discipline that made RP-3a's reversal bug detectable at all.

**But the property does not survive verbatim, and translating the old test
literally would produce one that cannot fail.** Today an array crosses and the
test asserts elementwise equality, nils included — the nil is a *value in a
position*. After the inversion there is no array: Rust emits per due channel, so
an empty slot produces **no emission at all** and "in position" has nothing to be
in. Restated for the shape that will exist:

> **CV-2.** An empty stem slot produces **no covert send at that channel index**,
> and shifts no other channel's index.

The negative controls change with it, and this is the part to get right:

| Failure mode | Shows today as | Shows after inversion as |
| --- | --- | --- |
| compaction | array shorter; peers shift left | channel `i+1`'s send emitted with index `i` |
| reordering | array elements transposed | two live channels' peers swapped |
| index off-by-one | — (not reachable) | every emission shifted by one |

That is arguably a *sharper* observable than the array — the defect surfaces as a
wrong index on a live send rather than as a wrong array element — but it is a
different assertion, and a literal port of the old body would assert about an
array that no longer exists.

One trap, named now because it is the same seal-is-not-coverage shape one layer
down: today the check is **synchronous** on `update_stems`, and after the
inversion it is only observable when channels actually come due. So the successor
must assert that it *saw* an emission for every channel it expects. Without that,
"the binding is correct" and "no channel ever fired" are indistinguishable — a
test that passes by observing nothing is exactly what the RP-3a seal turned out
to be.

The migration is the round's sharpest edge and gets the RP-3a retirement
treatment, in this order and no other:

1. Build the successor witness on the Rust side, asserting **CV-2** where the
   binding now lives — not a transliteration of the array assertion.
2. **Negative-control it plural**: compaction *and* reordering *and* an
   off-by-one in the channel index must each independently fail it, in the
   post-inversion forms tabled above. RP-3a's first version of this same test
   passed while never producing a nil, and its first *fix* passed under reversal
   because the expectation was sourced through the transform under test. Both
   failure modes are on the record; neither is hypothetical here.
3. Confirm the test observes an emission per expected channel, so absence of a
   defect is distinguishable from absence of coverage.
4. Only then remove the old test, in a commit that names the successor.

Deleting the seam and the seal in one commit is the specific thing this round
must not do, because the seal's justification (*"RP-3b consumes it
positionally"*) is retired by the same change that retires its subject, and a
reader reconstructing that later cannot tell whether the property was
re-witnessed or merely dropped.

#### 20.3a The three ways a test is vacuous — stated because this round needs all three checks

The same failure has now appeared three times in this arc wearing three
different costumes, and the third one is above:

| Costume | Instance | What the test lacked | What catches it |
| --- | --- | --- | --- |
| No input to fire on | the RP-3a seal that never produced a nil | a fixture reaching the state it claimed to witness | **fixture requirements** — assert the precondition was constructed |
| No way to fail | its first fix, self-consistent under reversal | ground truth independent of the transform | **negative control**, plural |
| No execution to observe | a time-driven successor that never advances the clock | the code under test actually running | **liveness assertion** — assert the emission happened |

The general form: **a test can be vacuous by lacking input, by lacking
independent ground truth, or by lacking execution.** They are independent
failures with independent remedies, and a test can pass all of one check while
failing another — the RP-3a seal had perfect ground truth and no input; its fix
had input and no independent truth.

This is worth stating once rather than re-deriving, because CV-2's successor
needs **all three at once**: it must construct a genuine hole (input), source
truth from `stem_slots()` rather than the emission stream (ground truth), and
assert it observed an emission per expected channel (execution). Miss any one and
the test is green for a reason unrelated to the property.

The arc has now paid for each of the three separately. That is the argument for
treating them as a checklist rather than as instincts.

### 20.4 `noise` is three facts in one field

[`zone::noise`](../../src/cryptonote_protocol/levin_notify.cpp#L367) is an
`epee::byte_slice` documented as *"`!empty()` means zone is using noise
channels"*. Censused, it carries three distinct facts:

| Fact | Sites | Count |
| --- | --- | --- |
| **enabled?** (`.empty()` as predicate) | `:357`, `:362`, `:529`, `:789`, `:849`, `:882`, `:884`, `:889`, `:985` | 9 |
| **fragment size** (`.size()`) | `:804`, `:808`, `:1003`, `:1005` | 4 |
| **the dummy payload** (`.clone()`) | `:811` | 1 |

The predicate is nine of fourteen uses.

**Correction, made while grounding the port.** An earlier draft of this section
claimed the bit was *already duplicated across the FFI*, reasoning that
[`:357`](../../src/cryptonote_protocol/levin_notify.cpp#L357) passes
`!noise.empty()` into `make_relay_zone`, so Rust had held it since RP-3a. **That
is false, and checking it changed the fix.** `make_relay_zone`
([`:235–244`](../../src/cryptonote_protocol/levin_notify.cpp#L235-L244)) consumes
the bool *C++-side* to choose between `noise_zone_params()` and
`public_zone_params()`; what crosses into `shekyl_relay_zone_new` is the
**resulting parameters**, never the bit. `Zone` has no noise or covert field at
all — verified by grep across `shekyl-relay`, `shekyl-relay-privacy` and
`relay_zone_ffi`.

So the defect is **overloading, not cross-boundary duplication**: one C++ fact,
re-derived at nine sites from a field whose type says "payload". Smaller than the
draft claimed, and a different operation to fix.

**Decision:** split at the port. The payload and its size stay C++ config
(`covert_payload`; its `.size()` remains the fragment unit). The enable bit
**becomes Rust state**, because after the port Rust needs it on its own account —
a covert send cannot be scheduled without knowing whether covert sends exist. It
is therefore *new state acquired by the port*, inventoried with a named owner per
§18.5's standing obligation, and **not** the deletion of an existing duplicate.

Keeping those straight matters: "delete the duplicate" and "move a fact to the
side that needs it" carry different risks. The second *creates* a second copy at
the moment of the move, since construction still passes the payload in. So the
acceptance test is that **no C++ `.empty()` survives as a predicate** — one
owner, rather than two kept in step by the constructor.

**Already built and unwired: `NoiseCadence`.**
[`schedule.rs:690`](../../rust/shekyl-relay-privacy/src/schedule.rs#L690) already
carries the covert cadence — `min_delay_secs`, `jitter_secs`, a `next_send()`
drawing from the same `bounded_uniform` primitive as the epoch jitter, and the
test `noise_cadence_spans_its_band`. It was built during RP-1's measurement pass
and wired to nothing. Its own doc comment says why it sits there: *"it draws from
the same uniform primitive and raises the same conformance question, not because
it is part of Dandelion++."* RP-3b's scheduling port therefore **wires an existing
primitive** rather than writing one, which lowers the port's cost and is the
reason §20.9 can call RP-3b the instrument for Q-11.

### 20.5 The oracle is thinner here than it was for 3a — say so before building

RP-3a had 33 gtests as its primary oracle and §18.4b stated their honest scope.
The covert path has **two**: `noise` ([`levin.cpp:2278`](../../tests/unit_tests/levin.cpp#L2278))
and `noise_stem` ([`:2372`](../../tests/unit_tests/levin.cpp#L2372)). What they
actually assert, read from the bodies rather than the names:

| Reached | Not reached |
| --- | --- |
| `status.has_noise` / `connections_filled` / `has_outgoing` transitions | which channel is bound to which slot — **no positional assertion at all** |
| send **counts** (`EXPECT_EQ(2u, sent)`) | that a *dummy* is a dummy (only that it is not a notification: `notified_size() == 0`) |
| a real tx arrives intact (`EXPECT_EQ(txs, notification.txs)`, `dandelionpp_fluff` false) | timing/dispersion of covert sends |
| — | **fragment restart on repoint** — see below |

So "the two noise gtests pass" is a much weaker statement than "the 33 pass" was,
and it does **not** witness the property this port is most likely to break. Rust
twins for the covert path are budgeted from the start, not discovered at
acceptance. This is §18.4b's discipline applied before the build instead of
after.

**Finding — an inherited privacy invariant with no test anywhere.**
[`update_channel`](../../src/cryptonote_protocol/levin_notify.cpp#L443-L449)
carries this, in the imperative:

> *"This clears the active message so that a message "in-flight" is restarted. DO
> NOT try to send the remainder of the fragments, this additional send time can
> leak that this node was sending out a real notify (tx) instead of dummy
> noise."*

It is a real covert-channel leak: finishing a partially-sent real message after a
repoint makes the send *longer* than a dummy, and length is the one thing the
covert channel exists to hold constant. Nothing tests it. The `make_fragment`
tests ([`levin.cpp:506`](../../tests/unit_tests/levin.cpp#L506)) exercise
`make_fragmented_notify` in isolation — three cases, none of them driving a
channel; no test repoints a channel mid-message and asserts the remainder is
discarded. Verified by grep over the whole gtest file, not by reading the two
noise cases.

This is the same shape as the i2p/tor outbound-only fluff rule RP-3a's first pass
dropped — a one-line privacy rule inside a mechanism whose tests assert
throughput. That one was caught only because eight `private_*` gtests happened to
cover it. **Here nothing does.** So it is named as a porting invariant with its
own witness *in this round*, written before the code moves:

> **CV-1.** Repointing a covert channel discards any in-flight message remainder.
> A real message interrupted by a repoint is restarted from its first fragment or
> dropped — never resumed.

### 20.6 Naming — the free rename, and why it is not the entry point

§18.3's standing item stands: `run_stems()` cancels covert timers and has nothing
to do with stem routing, and the three-way disagreement (name says stems, comment
said stems, body cancels noise) is the dead-assumption detector. RP-3a left the
name alone deliberately and wrote the handoff comment at
[`:944–947`](../../src/cryptonote_protocol/levin_notify.cpp#L944-L947).

The rename lands here, with the boundary rule 3a established: **old names at the
ABI where the oracle needs them, honest names where the logic lives.** The gtests
call `run_stems`, so the public hook keeps its name and gains a comment; the Rust
function it forwards into is named for its body.

It is explicitly **not** the round's entry point. It is the cheapest item and
finishing it first would make the vocabulary sweep feel like the round, when it
is a consequence of the port. Order: §20.4 split → §20.2 scheduling port →
§20.3 seam inversion and seal migration → rename.

### 20.7 Acceptance

1. **`noise` and `noise_stem` pass unchanged**, plus the full 33 — the covert
   port must not disturb the Dandelion++ path. Necessary, and per §20.5 nowhere
   near sufficient.
2. **CV-1 has a witness**, negative-controlled: a channel repointed mid-message
   must fail the test if the remainder is resumed. **It is a gtest, not a Rust
   twin.** After the port the invariant is enforced by whoever clears `active`,
   and `active` stays C++ (§20.2) while only the repoint *decision* is Rust's —
   so a Rust test would be asserting about a buffer it cannot see, measuring the
   shim rather than the property.
3. **CV-2 has a live witness on the Rust side** — the *restated* property
   (§20.3), not a transliteration of the array assertion — negative-controlled
   against compaction, reordering, *and* channel-index off-by-one in their
   post-inversion forms, and asserting that an emission was observed for every
   expected channel. Landed **before** the RP-3a seal test is removed, in a
   commit naming the successor. Satisfiability was verified at source (§20.3):
   `stem_slots()`, a supplied collector, and injectable `now_ms` all survive the
   inversion.
4. **`SlotsCb` and the slot array are gone from the FFI** — deleted, not renamed.
   Checked by command, not by prose, because this is exactly the claim that
   survives while a renamed equivalent ships:

   ```bash
   rg -n 'SlotsCb|on_slots' rust/ src/     # must return nothing
   ```

   If the round ends with an ordered array still crossing the boundary, the
   consolidation did not happen and the round should say so rather than claim it.
5. **`zone::noise`'s enable predicate has one owner.** No `.empty()` test
   re-derives a fact the zone handle already holds.
6. **The §18.5 inventory is amended, not appended to** — the `channels` and
   `noise_channel` rows are replaced by §20.2's decomposition, so the inventory
   describes the tree that exists.
7. Covert-path Rust twins exist for the behaviours §20.5 lists as unreached, or
   the gap is stated in the round's outcome section with the same explicitness
   §18.4b used.
8. **The zone handle is called from exactly one strand** (§20.2a). The
   per-channel `next_noise` timers are gone — `CRYPTONOTE_NOISE_CHANNELS` timers
   become **zero**, not one — and no `shekyl_relay_zone_*` call appears on a
   channel strand. This one is load-bearing because the rejected alternative
   compiles, passes both noise gtests, and races only under load; a green suite
   is not evidence here.
9. **CV-3 (deadline stability) has a witness** — a channel's armed deadline
   survives wakes it did not cause. Driven through `poll(now_ms)`: arm a channel,
   advance time through several unrelated wakes (fluff release, epoch rollover,
   another channel firing), and assert the channel still fires at its **original**
   deadline. Negative control: a re-arm that redraws must fail it. This is the
   condition under which the §20.2a fold is better than the option it rejects
   rather than worse, and unlike item 8 it has **no** load-dependent symptom —
   a resampling fold passes every existing test, always, and relays sooner than
   its own distribution claims.

### 20.8 What this round does not do

- **No change to covert timing parameters** — the constants are ported as-is.
  This is a sequencing decision, not a priority one: see **Q-11** below, which
  ranks the derivation *next* rather than parking it.
- **No reactor.** 3a's reason-2 seal holds; asio keeps every sleep.
- **No Q-10 selection work.** §12.11's three tiers remain unimplemented and
  blocked on the ambient background-failure-rate measurement (§19.3).

### 20.9 Q-11 — the covert timing constants are the arc's last unexamined numbers

`CRYPTONOTE_NOISE_MIN_DELAY`, `CRYPTONOTE_NOISE_DELAY_RANGE` and
`CRYPTONOTE_NOISE_MIN_EPOCH` are ported unchanged by RP-3b, and the reason is
attribution: a port that also re-derives its constants cannot attribute a
behavioural change to either half. That is the same separation RP-3a kept between
the faithful port and the F-4/F-5 correction, and it held.

**But "not in this round" is not "low priority", and the record should not read
as though it were.** Three facts stack, and none of them is speculative:

1. **They are the residue.** F-1…F-5 are closed. The embargo mean, the embargo
   distribution family, the closed-form solve, the fluff delay's family and the
   flood-return term are all now derived, witnessed and negative-controlled.
   These three constants are what is left of the relay path's timing that has
   never been examined.
2. **They share provenance with the ones that were wrong.** Same file, same
   lineage, same era, same absence of any derivation in the tree. The base rate
   on that population *in this arc specifically* is five defects out of five
   examined constants — F-1 (a value that did not follow from its own stated
   derivation), F-2 (the wrong distribution family under a correct-looking name),
   F-3 (a closed form that under-provisioned at every parameter).
3. **They govern the mechanism with the thinnest oracle and the most
   privacy-load-bearing behaviour.** Two count-asserting gtests (§20.5) over a
   channel whose entire function is holding a real emission indistinguishable
   from dummy traffic. An F-2-shaped defect here — a plausible name over the
   wrong distribution — is exactly what that oracle cannot see.

**Epistemic status, stated precisely, because the distinction is the point.**
This is registered as **Q-11**, an *owed derivation*, and deliberately **not** as
F-6. F-1…F-5 were each demonstrated with a measurement; nothing here has been
measured, and numbering it into the F-family would assert a defect that has not
been shown. It is **F-shaped in provenance and priority, Q-shaped in evidence.**
Anyone tempted to promote it to an F should do so by measuring, not by
renumbering.

**RP-3b is what makes it tractable, which is a stronger claim than deferral.**
Once covert deadlines are Rust-owned and driven through `poll(now_ms)` (§20.2a),
these constants become measurable exactly the way the embargo and fluff delay
became measurable: deterministic time, in-crate, negative-controllable, with the
conformance instruments already built. Today they are not cheaply measurable at
all — they live behind N asio timers on N strands. So the port is not merely a
prerequisite by sequencing hygiene; **it is the instrument.**

**Rank: immediately after RP-3b**, ahead of the remaining §12.11 selection work
(which is blocked on a measurement RP-3b does not produce). "Parked" and "next"
are different states and a future reader treats them differently — the same
reason ρ's status line was corrected from "blocked" to "blocked, with the
obligation now single-draw-per-epoch" in §19.
