# Daemon Relay Privacy — correcting and porting the Dandelion++ timing layer

**Status:** ROUND 2 applied. The measurement that motivates this document
landed alongside it in the same PR (`rust/shekyl-relay-privacy`, 87 tests), so
every number below is reproducible rather than asserted. Rounds 1–2 raised
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
lineage: the stem map in [`src/net/dandelionpp.cpp`](../../src/net/dandelionpp.cpp),
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

- **RP-2** — FFI + cut `connection_map` over; delete `src/net/dandelionpp.cpp`.
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
(256 nodes, 8 peers, `tor_collapses_the_supernode_diffusion_observer`):

| supernode reach | transport | fluff observed | first-spy π₀ |
| --- | --- | --- | --- |
| dials 5 % | clearnet | 1.0000 | 0.113 |
| dials 5 % | **Tor/I2P** | **0.0000** | **0.000** |
| dials 10 % | clearnet | 1.0000 | 0.198 |
| dials 10 % | **Tor/I2P** | **0.0000** | **0.000** |
| dials 30 % | clearnet | 1.0000 | 0.451 |
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

---

## 7. Open questions (the Round-3 agenda)

Round 1 closed Q-2 and Q-7; Round 2 corrected the model (RD-4), reframed Q-8 around the mechanism, and anchored everything against the sources (§11); the position-anchoring pass (§6, §10.8) then made the passive adversary transport-conditional. What remains for Round 3:

- **Q-1 — is the stem model right?** *(Round 1 position: single-path is
  correct.)* Each node forwards to one per-source successor, so branching
  shapes the anonymity set, not survival. The case still worth checking is path
  self-intersection: a revisited node re-uses an already-armed timer, which
  strictly *helps* survival, so the equation is conservative there. Likely
  constant-level and dwarfed by RD-1. **Carried, low priority.**
- **Q-3 — is `q = 20%` right for Shekyl?** D-6 defers deliberately; the trade
  curve is measured and on file. Round 1 notes that RD-1's correction lengthens
  the required embargo, which *strengthens* the case for not simultaneously
  lengthening stems. **Carried.**
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
2. **The transport-aware instrument is now built** (`simulate_transport_observation`,
   §6.5), carrying a `Transport` flag that zeroes the inbound-spy channel on the
   Tor path exactly as §6.3 requires — so the clearnet↔Tor delta for the paper's
   supernode observer is a *measurement* (π₀ 0.45 → 0.000). What remains unbuilt
   is the narrower `simulate_passive_neighbor_leak` — the *mean-dependent*
   magnitude of the clearnet passive channel as a function of the embargo mean —
   which is only worth building if Round 3 decides clearnet `ε` is a live lever
   (i.e. if the origin may be on clearnet). The other reaching-instruments
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
