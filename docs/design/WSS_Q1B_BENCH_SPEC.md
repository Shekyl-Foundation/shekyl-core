# `WSS-Q1(b)` bench specification — the corpus, the boundary, and the rig protocol

**Status:** ACTIVE CONTRACT — **written 2026-09-20**, the corpus and protocol
for the two **timed** measurements [`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md)
§6.3.4 makes `WSS-Q1`(b)'s adoption conditional on. **The instrument is built;
the grading run on the pinned rig has not happened**, so `WSS-Q1`(b) remains
adopted-subject-to.

**Ground:** `dev` = `5becc110b8`. Every code citation below was resolved at that
tree.

**Authority:** §6.3.4 rules the budgets, the rig pins and the miss responses.
This document does **not** restate them — it cites them, and specifies the
corpus and protocol §6.3.4 leaves to the bench.

**Instrument:** `rust/shekyl-wss-q1b-bench` (bins `spend_edge`, `open_edge`).

**Identifier family:** `WSS-` — this is bench work under the wallet-side store
round and registers **no new family**
([rule 94](../../.cursor/rules/94-tracking-index.mdc), one lane one family).

---

## 1. What is measured, and what is not

Two ruled quantities, at the ruled boundary.

| Edge | Quantity | Budget (§6.3.4) |
| --- | --- | --- |
| **Spend** | spend-intent through constructed `Path` | `delta ≤ max(2 s, 15 % of proving time)` |
| **Open** | refetching the held buffer at wallet open | `≤ 5 s` absolute, **local** posture |

**The harness never declares `WSS-Q1`(b) discharged.** It emits measurements;
on the pinned rig it applies the ruled arithmetic; the verdict is the
maintainer's. The absolute seconds are reported beside the ratio in every
record, per §6.3.4's third bench obligation.

**Out of scope, and deliberately so:**

- §6.3.4 **rows 1 and 4** — `rollback_to_fork`'s refusal semantics on a reorg
  deeper than `W`, and property tests against `build_layers`. Both are
  behavioural rather than timed, and both belong with the proving-state
  increment, against code §6.3 has not built.
- **Any part of §6.3.** No frontier, no buffer, no membership-path store. The
  bench models the replay (§2); it does not implement it.
- **Any change to a production crate.** The bench reads production constants and
  calls production functions; it writes nothing back.

---

## 2. The model, and its direction of error per term

The §6.3 replay does not exist yet, so the spend-edge delta is measured through
a **proxy**, and the proxy's error is stated per term rather than asserted as a
bound.

**Proxy:** `shekyl_fcmp::tree::build_layers` over the window's leaves —
`shekyl-wss-q1b-bench/src/fixture.rs`'s `replay`.

| Term | Direction | Why |
| --- | --- | --- |
| **Leaf-layer hashing** | **Exact** | Every window leaf is hashed into its Selene chunk once here and once in a frontier advance. This term dominates by roughly the leaf-chunk width (38×) |
| **Upper-layer propagation** | **Under-modelled** | A window tree is 3–4 layers; a real advance at depth 6 propagates ~6 |
| **Net** | **Upper bound** | `build_layers` rehashes *every* upper node from scratch, where a frontier advance touches one node per layer — a saving far larger than the missing layers cost |

**What would invalidate the bound:** a §6.3 design that hashes *more* than one
chunk-insert per leaf at the leaf layer. Nothing in §6.3.2 row 4 suggests one —
it argues the opposite — but the bound is conditional on that and says so.

**Path read-off and `Path` construction** are not proxied: the harness performs
the same walk `shekyl-curve-tree/src/assemble.rs` performs, over the same
layers.

**The denominator is not proxied at all** (§3.3).

---

## 3. The corpus

### 3.1 Canonical transaction shape — 2-in/2-out, by citation

[`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §13 already fixes 2-in/2-out as this
project's budget shape, and `ARCHIVAL_PRUNED_DAEMON_MODE.md` §9 and the firewall
round both cite it. **Reused, never minted.** Per-input proving makes the
denominator shape-dependent, so the shape must be stated — but minting a second
canonical shape beside §13's would be the duplicate-source error.

Pinned in code as `corpus::CANONICAL_INPUTS` / `CANONICAL_OUTPUTS`.

### 3.2 The three block counts, which are three different numbers

An earlier draft of this bench used `725`, `730` and "the `W`-block buffer"
interchangeably. They are three quantities:

| Constant | Value | Meaning | Owner |
| --- | --- | --- | --- |
| `W` | 730 | Finalization depth; `F = tip − W` | `SPENDABLE_AGE_BLOCKS` (10) + `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` (720), `shekyl-curve-tree/src/segment.rs` |
| `REPLAY_WINDOW_BLOCKS` | 725 | `[F, ref]` — what a spend replays | `W − REFERENCE_BLOCK_MIN_AGE` (5), `shekyl-curve-tree/src/reference.rs:50` |
| `HELD_BUFFER_BLOCKS` | **790** | `W + 60` — what the wallet holds and refetches | `W + COINBASE_LOCK_WINDOW`, `shekyl-consensus/src/lib.rs` |

The 60 is §6.3.2 row 2's amendment: replaying drains over `[F, ref]` needs the
outputs those drains spend, and a coinbase output created at `F − 60` matures
exactly at `F`. **The open edge refetches 790 blocks, not 730.**

Each is `const`-asserted at its value in `corpus.rs`, so a constant moving
underneath the bench fails the build rather than silently re-scaling a graded
run.

### 3.3 The delta / proving boundary

**Ruled in §6.3.4 and restated here only because this is where a bench author
looks:** delta is spend-intent through constructed `Path`; the denominator is
the prover invocation, `Path` in and proof bytes out; proof serialization is
charged to neither.

**How the bench holds the boundary.** The denominator is
`shekyl_fcmp::proof::prove` — **the same function
`shekyl-tx-builder/src/sign.rs:171` calls in production**. It is *not* driven
through `sign_transaction`, which would fold the Bulletproof+ range proof
(`sign.rs:113`) and the PQC signing into the denominator, inflating it and
silently loosening the 15 % arm. That is the boundary violation §6.3.4 draws the
seam to prevent, and it is available to commit by accident — an earlier draft of
this bench specified exactly that.

"Never a synthetic prove" therefore means **never a mock prover**. The call is
the production entry point; only the witness is constructed (§3.5).

### 3.4 Worst-case leaf rate — the derivation, shown

The rate is the scale factor of the whole spend-edge measurement, so it is
derived here and computed by *calling* the landed functions, never by restating
a value.

**`config/consensus_constants.json` does not carry a maximum block weight.** It
carries `block_weight_short_term_surge_factor: 4` and nothing else of this
chain; `shekyl_wire::block::MAX_BLOCK_BLOB_SIZE` is a parse-DoS guard, not a
consensus bound. An earlier draft of this spec derived the rate "from the
block-weight constants in `config/consensus_constants.json`" — naming an operand
that does not exist, which is `WSS-Q8`'s error with a different byline.

The chain that does exist:

1. The long-term effective median is floored at the full-reward zone
   `shekyl_wire::transaction::MIN_BLOCK_WEIGHT` = **300 000**.
2. The short-term governor may run it to `S ×` that floor, `S = 4`
   (`shekyl_economics::block_weight::BLOCK_WEIGHT_SURGE_FACTOR`, ratified
   `CONSENSUS_C2_R2_WEIGHT_FEES.md` Q3). `shekyl-economics/src/block_weight.rs`
   records in its own words that for the first ~100 000 blocks this clamp is
   *the only* protection against early-chain weight growth.
3. A block's admissible weight is
   `shekyl_economics::emission::block_weight_limit(median, zone)` =
   `2 × max(median, zone)` — `shekyl-economics/src/emission.rs:265`.

   **Sustained early-chain ceiling = `2 × 4 × 300 000` = 2 400 000 weight.**

4. The densest leaf-producing shape is searched over the type-bounded
   `(n_in, n_out)` grid through `shekyl_tx_weight::predict_weight` — the
   single-sourced structural predictor the wallet's own fee path uses — with
   shapes above `TX_WEIGHT_LIMIT` (149 400) excluded, because the mempool
   refuses them and they cannot appear in a block.
5. **Every output becomes a leaf.** §6.3.2 row 1 verified that maturity is the
   *only* drain gate — `unlock_time` appears nowhere in `shekyl-curve-tree` — so
   there is no second filter to discount by. The coinbase is charged at
   `MAX_OUTPUTS` (16), an upper bound that cannot move a five-figure result.

**Result at depth 6: 1 056 leaves/block**, hence a worst-case replay window of
`1 056 × 725` = **765 600 leaves** (~98 MB of leaf scalars — comfortably within
the 8 GB rig).

**The rate falls as the tree deepens**, because a deeper tree means a larger
`fcmp_proof_size`, a heavier transaction, and fewer of them per block. That is
*not* a reason to grade at the shallowest depth: depth is **determined** by leaf
count, so a high rate sustained at depth 2 describes a tree that is about to
stop being depth 2. The honest pairing is to compute the rate at the depth being
graded. Asserted in `corpus_tests.rs`, not left in prose.

### 3.5 Depth, and why it is a separate axis from the window

Both the denominator and the replay depend on a size, but **not the same size**.
The replay scales with the **window's** leaves; the denominator scales with the
**tree's depth**, which is set by the whole chain's leaf count.

The ladder, derived from `shekyl_fcmp::tree::outputs_per_node` (the production
capacity function) rather than restated:

| Tree depth | Minimum leaves | Leaf scalars |
| --- | --- | --- |
| 3 | 685 | 88 KB |
| 4 | 25 993 | 3.3 MB |
| 5 | 467 857 | 60 MB |
| **6** | **17 778 529** | **2.28 GB** |

§6.3.2 row 4 puts the production target at ~6 layers (~100 M leaves). **A dense
depth-6 corpus is 2.28 GB of leaf scalars before a single layer is allocated**,
on a board the rig pins at 8 GB — hostile to build, and unnecessary.

`proof::prove` takes `tree_depth` directly and the circuit pads each chunk to the
layer width, so a path with one real child per layer should cost what a full one
costs. **The bench does not take that on the padding comment's word.** It runs a
**control experiment** (`fixture::ControlExperiment`, driven by repeatable
`spend_edge --control-depth`):

- **same depth**, dense path off a real tree versus a synthesized sparse path;
- sparsity is the **only** variable, which is what makes a difference
  attributable to it;
- **at two adjacent rungs, not one** — depths 4 and 5 by default.

**Why two rungs.** One rung proves sparse ≈ dense *at that depth* and leaves
every deeper rung an extrapolation off the end of a single point. Two adjacent
rungs show whether the ratio is **flat**, and it is the flatness that licenses
the next rung. Depth 5 (467 857 leaves, 60 MB) is the deepest rung whose dense
arm is cheap, so grading at depth 6 is **one** rung beyond the deepest control —
and the record says exactly that: `path_provenance` names the *distance* from
the deepest control arm rather than claiming the control covered the grading
depth. Every arm must hold; one arm passing while another fails is not a flat
ratio but a depth dependence, which is what would make the extrapolation unsafe.

An earlier draft proposed comparing a **sparse depth-6** path against a **dense
depth-4** one. That varies depth *and* sparsity at once and could not attribute
a difference to either. A later draft ran one rung and called the result a
licence for depth 6 — two layers the experiment never touched.

A synthesized path's root is a genuine hash of the chain below it — the prover
and the verifier both see a well-formed tree. What makes it synthetic is only
that no chain produced it, and nothing in the circuit's cost depends on that.

### 3.6 The correctness gate, and exactly what it claims

**Every measured `Path` round-trips through `shekyl_fcmp::proof::verify`.** A
harness whose artifacts do not verify prints garbage with confidence.

**Scope, stated because the gate is weaker than it looks:** `verify` takes the
root as an *input*, so a self-consistent wrong tree verifies. The round trip
proves **the path and the prover are coherent with each other**. It does **not**
prove the tree matches consensus — that is CT-2's reconstruct-root KAT's claim,
against a real header root.

**Where it runs, and where it must not.** `fixture::prove_and_verify` is called
**once per graded path and once per control arm, outside every timer**. Inside
a timed series it would inflate the denominator with ~35 ms per input of
verification — the same boundary violation that rules out driving
`sign_transaction`, committed by the gate meant to defend the boundary.

*This was a real defect in the first landing, not a hypothetical:* both
binaries set `paths_verified: true` from `prove`'s `Ok`, and `proof::verify`
appeared **nowhere** in either — verification existed only in the unit tests
while this section asserted it of the bench. A record claimed a property the
code did not have.

A third test (`a_proof_does_not_verify_against_a_different_root`) is the control
on the other two: without it, both would pass against a `verify` that ignored
the root.

---

## 4. The open edge — round trips, not bandwidth

### 4.1 Why the model is not throughput × bytes

`DaemonClient::fetch_scannable_block`
(`shekyl-engine-core/src/engine/daemon/mod.rs:266`) resolves to
`engine::block_fetch::fetch_scannable_block_with_form`
(`block_fetch.rs:132`), which is **strictly per-block** and issues, sequentially
and with no pipelining:

1. `get_block` — JSON-RPC; the block arrives **hex-encoded**;
2. `get_transactions` — one call per `TXS_PER_REQUEST` (100) batch, so one call
   for any realistic block and none for an empty one;
3. `get_o_indexes`, inside `compute_first_output_index` (`block_fetch.rs:491`).

Over 790 blocks that is roughly **1 600–2 400 serialized round trips**. On a Pi 4
driving a loopback daemon the fixed per-round-trip cost is very likely to
dominate the byte cost, and a throughput model cannot see it at all.

So the harness measures **round trips and per-block wall time as primary**, with
bytes secondary and **wire-hex and decoded reported separately** — the blob
arrives hex-encoded, so one figure for both would understate the wire by half.
The projection to 790 blocks is built from the **per-block distribution**
(median, with p95 beside it), not from a bandwidth product.

### 4.2 Attribution before remedy

§6.3.4 row 3 pre-registers the miss response as *"the buffer gets its own
companion file"* — a remedy that fits a **volume**-bound cost. If the cost is
**round-trip** bound, the proportionate remedy is a bulk or pipelined fetch, and
the companion file is a much larger change aimed at the wrong term.

**So the harness attributes the cost to a term in the same record as the
measurement**, and `WALLET_SIDE_STORE.md` §6.3.4 row 3 carries the matching
amendment. Amending the remedy *before* the measurement exists keeps it
pre-registered; discovering mid-grading that the remedy does not match the cause
is exactly what pre-registration exists to prevent.

The round-trip floor is **measured directly** (repeated minimal RPC), not
regressed out of the block samples: round trips per block are nearly constant
(2–3), so a two-parameter fit over them is ill-conditioned and would report a
confident number from an under-determined system. A term clears
`DOMINANCE_THRESHOLD` (60 %) or the harness reports `Mixed` and leaves the
attribution to the maintainer.

Round trips are counted **analytically** from each block's shape — the
production fetch exposes no counter — and the accounting is printed in the
record so a reader can check it against `block_fetch.rs` rather than trust it.
Byte accounting rides a **separate, untimed** `get_block`: instrumenting the
timed path would change what is being timed.

### 4.3 Scope

§6.3.4 row 3 grades the **local** posture only. A remote daemon over Tor
refetches more slowly and is not graded by the 5 s threshold — a stated scope,
not an omission. The record carries the posture string.

### 4.4 The corpus density — RULED 2026-09-20, and it differs from the spend edge

**The open edge grades at a stated nominal density: the full-reward zone,
`MIN_BLOCK_WEIGHT` = 300 000 weight per block.** The adversarial window is an
**accepted long-tail**, covered by
[rule 80](../../.cursor/rules/80-usability.mdc) progress indication rather than
by the 5 s budget.

**Why this is a ruling and not an oversight.** Do the arithmetic the spend edge
invites and the open edge's answer is pre-written: 790 blocks at the
2 400 000-weight sustained ceiling is **≈ 1.9 GB decoded** (≈ 3.8 GB on the
wire, which is hex). No hardware refetches that in 5 s. **Grading there would
write §6.3.4 row 3's miss response — the companion file — before measuring
anything**, which is precisely the failure the amendment above was made to
avoid, arrived at from the other direction.

**The test that picks the density: can the measurement still surprise you?**

| Density | Outcome | Verdict as evidence |
| --- | --- | --- |
| Adversarial ceiling (2.4 MB) | ~1.9 GB in 5 s | Foregone **fail** |
| Empty / coinbase-only | ~1.4 kB per block | Foregone **pass** |
| **Full-reward zone (300 kB)** | 790 × 300 kB ≈ **237 MB** in 5 s ⇒ ~47 MB/s decoded | **Genuinely open** |

Whether a Pi 4 sustains that over JSON-RPC with a hex-encoded blob is a real
question, which is what makes the zone the honest place to grade.

**The criterion is general, and is recorded here because this is where it was
first written down.** It is pre-registration applied to corpus selection: *a
graded run whose verdict is foregone in either direction is ceremony, whatever
its density.* It is not specific to block weights, to this budget, or to this
bench — the next measurement that must pick a corpus point, an input size or a
load level should make the same table and reject the rungs whose answer is
already known. The UX argument ("this is the ordinary launch") justifies one
*value*; this criterion justifies the *method*, and survives a change of
budget, hardware or subject. A bench that cannot show both rejected rungs are
foregone has not made the argument.

**Why the two edges may differ, stated so it does not read as inconsistency.**
§6.3.4 row 2 rules the spend edge at worst case for a recorded reason — *"a
measurement taken on a quiet chain would grade green and reopen on a busy
one"*. That argument is about an **architecture**: the spend edge decides
whether the proving state is a store, and the cost is paid **on every spend**.
The open edge decides a **local mitigation** — persist the buffer or refetch it
— and is paid **once per launch**, where a slow path is a progress bar rather
than a broken design. Different stake, different density. The asymmetry is the
ruling.

**The nominal is a stated judgment, not a derivation** — the same class as
§6.3.4's 2 s and 15 % budgets, and labelled as such in
`corpus::nominal_block_weight`. There is no chain history to take a typical
fill from, and the zone is an upper bound on the un-penalized region rather
than a measured average. **Reopening criterion (rule 21):** a measured
distribution of real block weights once a chain exists, or a crossover
measurement showing the 5 s budget breaks below this density.

**The ruling is enforced, not merely written.** `open_edge` measures the
sampled blocks' decoded bytes against the graded weight and **withholds a
verdict** when the corpus is below `MIN_CORPUS_DENSITY_FRACTION` (50 %) of it —
reported as its own `ungraded_because`, separately from the rig check. The
first live run reads *"1432 B/block measured vs 300000 graded (0.5 % — TOO THIN
TO GRADE)"*, so its 0.2 s **cannot** be read as a pass. A sample far below the
density the budget is stated at cannot fail, and a pass over it would be a pass
for the wrong reason.

---

## 5. The rig protocol

### 5.1 The pins, and which of them a process can see

§6.3.4 pins five properties. **Three are observable from inside the process and
two are not.** A gate advertising five checks while enforcing three would pass
for the wrong reason ([rule 47](../../.cursor/rules/47-gate-subject-assertion.mdc)).

| Pin | How it is held | Where |
| --- | --- | --- |
| `aarch64` | **Enforced** — `std::env::consts::ARCH` | `rig::Environment::check_enforceable` |
| 64-bit userland | **Enforced** — pointer width | same |
| 8 GB RAM | **Enforced** — `/proc/meminfo`; **unreadable refuses**, never assumes | same |
| **Pi 4 Model B** | **Enforced** — `/proc/cpuinfo` must name the board (`Raspberry Pi 4`, `BCM2711` or `Cortex-A72`); unreadable refuses | same |
| USB-SSD | **Attested** — `--attest-storage=usb-ssd`, recorded verbatim | `rig::decide` |
| Sustained thermals | **Attested** — `--attest-thermal-steady`, recorded verbatim | same |

The device row was **captured but not checked** in the first landing: any
aarch64 host with 7.5 GB passed as the pinned rig. The string is observable,
so by this section's own rule it belongs on the enforced side. Three markers,
because the field a kernel answers with varies by board — aarch64 Linux
usually omits `model name` and gives `Model` / `Hardware` instead.

The record separates `enforced` from `attested`, so a reader grading a run can
see which claims carry machine evidence and which carry a human's word.

**Measurement is never refused** — a dev-box run is useful, and refusing it would
push the schema's first review to the rig, which is the worst place to discover
a problem with it. Only *grading* is gated.

### 5.1.1 Everything grading refuses

A verdict is evidence, so every condition under which it would mean less than
it appears to is a refusal rather than a footnote. Beyond the rig pins above:

| Condition | Why a verdict would be worthless |
| --- | --- |
| `--window-leaves` given with `--grade` | `--grade --window-leaves 1` would emit `rig.grading: true` for a corpus that is not the ruled 725-block worst case — the open edge's thin-corpus defect, on the other edge |
| Sampled blocks below half the graded density (open edge) | A corpus that cannot fail cannot pass for a good reason |
| Any timing series unconverged | §5.2's contract says an unconverged series is *reported*, never substituted for a converged one |
| The prover failed in the timed loop | A fast repeated failure yields a small median that grades as a pass; there is no denominator without a proof |
| The graded path did not verify | See §3.6 |
| Grading depth more than one rung above the deepest control | Flatness across adjacent rungs licenses *the next* rung and no further |
| Sparse unlicensed **and** the dense fallback misses the requested depth | The fallback is the *window's* tree, whose depth is set by the leaf count, so a refused control would silently move the denominator to another depth |
| Control depths repeated, non-adjacent, or below the ladder floor | A set that cannot express flatness across adjacent rungs cannot license anything |
| A non-loopback daemon with `--grade` (open edge) | §6.3.4 row 3's budget is defined for the local posture and the record hard-codes that claim; grading a remote daemon against it is a category error, not a slow run |
| `--json` was requested and could not be written | A pass or miss with no artifact behind it is worse than no run |

Argument validity is checked **before** the rig gate: an unusable control set
is unusable on a dev box too, and discovering it only on the rig wastes the
session the rig exists for.

**What this rig grades, and what it does not.** The pins grade **obligation-A**
quantities — the principal's proving path, which every wallet walks, and which
is why rule 76's floor is the right subject for them. **No serving-path
measurement grades on this rig**, conservative baseline notwithstanding: an
archiver runs a bonded persona with a Tor service and multi-gigabyte holdings,
and sizing that box is a separate question with its own reference class, owed
when the software package structure settles (`FOLLOWUPS.md`). Budgeting a
serving path against a Pi is a deliberate over-conservatism and a sound default;
it is not a verdict this bench issues.

### 5.2 "Sustained" is a convergence criterion, not an iteration count

§6.3.4: *"run to steady state before measuring"*, because *"a burst measurement
grades a machine that does not exist after a minute"*. A fixed iteration count
cannot express that — it is too few on a board that throttles late and wasted
minutes on one that never throttles.

The loop runs until **two consecutive running medians agree within 5 %**, with a
warm-up phase discarded first. A series that never settles is reported
`converged: false` rather than looped forever or quietly summarized, and the
record names **why** it stopped — a noisy fast workload and a slow one call for
different responses.

**There are two hard stops, and both are needed.** An iteration cap alone is not
a bound: the worst-case replay is a multi-minute operation on the rig, so 60
unconverged iterations of it is *hours* — a harness that could run for an
unbounded time on the very machine it exists to measure. So each loop stops at
**60 iterations or 30 minutes, whichever comes first**. The wall budget is a
parameter rather than only a constant, so a test can reach it: a limit no test
can exercise is a limit nobody has seen work.

**The cap is per series, not per run** — stated because it is the kind of
detail a reader would otherwise assume the other way. A `spend_edge` run times
three series (replay, path construction, proving) plus two per control arm, so
a fully unconverged run is bounded by that count times the budget, not by the
budget. Each series reports its own `stopped_because`, so a run that took the
long path says which measurement did it.

**The whole per-iteration series is in the record**, so a reader can watch the
throttle happen instead of taking the converged figure on trust.

### 5.3 The run record

JSON, `schema_version` 1, plus a human summary on stderr. The `FOLLOWUPS`
discharge will cite runs by this schema, so it is versioned: a record whose
shape moves silently cannot be compared across the prover-pin re-grades §6.3.4
requires.

Every record carries: the environment; `enforced` vs `attested`; the **prover
pin** (crate, version, revision — §6.3.4 re-grades on a material prover-pin
change, and a record that does not name its prover cannot tell a later reader
whether it still applies); the full corpus derivation including every term of
the leaf rate; per-iteration series; **absolute delta seconds beside the ratio**;
the threshold and **which arm binds**; and the verdict
(`pass` / `miss` / `ungraded`).

**Which arm binds is part of the output on purpose.** At shallow depths the
relative arm is tiny and `max(2 s, …)` collapses to the **2 s absolute floor** —
so early-chain grading turns on the absolute number, not the ratio. A
ratio-only record would misreport that case.

---

## 6. Placement and lifecycle

`rust/shekyl-wss-q1b-bench`, a non-production crate with two `[[bin]]`s.

**This is not a `-spike`.** The disposable measurement crates in this workspace
(`shekyl-sp-t3-spike`, `shekyl-tor-transit-spike`) carry a deletion trigger at
birth under [rule 15](../../.cursor/rules/15-deletion-and-debt.mdc). This crate
carries the **opposite** obligation: §6.3.4 requires a re-grade on a material
prover-pin change, so it must outlive its first run and keep compiling.
`shekyl-economics-sim` is the precedent, and the workspace-member comment says
so at the registration site.

Criterion is the wrong instrument here: it iterates, a Pi prove is tens of
seconds, and it has no notion of a ruled threshold or a rig gate.

**Nothing in the production dependency graph may depend on this crate.** That is
enforced by `scripts/ci/check_bench_not_a_dependency.py`, with its own
`--selftest` — a crate-doc sentence is not a check.

### 6.1 Verification status of the two binaries, stated separately

They are **not** equally exercised, and a spec that implied otherwise would be
the kind of claim this lane exists to refuse.

| | `spend_edge` | `open_edge` |
| --- | --- | --- |
| Unit tests | Covered — corpus, ladder, timing, fixture, `verify` round trip | Covered — projection and attribution, over synthetic samples |
| Run end to end | **Yes**, at the worst-case window on an x86 dev box | **Yes**, against a live `shekyld --regtest` |
| Refusal paths run live | Off-rig grading refused, exit 2 | Off-rig grading refused (exit 2), unreachable daemon refused (exit 4) |

Both binaries have now been run. `open_edge`'s RPC surface is additionally
compile-checked against the **shared** wire types — `GetBlockRequest` /
`GetBlockResponse`, the same types `block_fetch.rs` deserializes — so a renamed
field breaks this build exactly as it breaks the wallet's.

**One live-run detail worth carrying:** `shekyld` exits on stdin EOF. A
background job inherits its parent's stdin, so a shell driver must hold a pipe
open (the Rust harness gives it a piped stdin and keeps the handle). A driver
that does not gets a daemon that binds its RPC port, logs
*"EOF on stdin, exiting"*, and is gone before the first request.

---

## 7. First runs — 2026-09-20, x86 dev box

**Measurements, not verdicts.** Both records are `"verdict": "ungraded"`: this
is not the rig. They are recorded because the schema and the model are easier
to review against real output than against a description of it, and because two
of them say something the rig run will not change.

### 7.1 Spend edge — the worst-case window misses by a wide margin

| Term | Value |
| --- | --- |
| Window | 765 600 leaves over 725 blocks (1 056 leaves/block at depth 6) |
| Replay | **73.9 s**, converged |
| Path read-off + `Path` construction | 0.001 s |
| **Delta** | **73.9 s** |
| **Per-block amortized advance** | **102 ms** |
| **Denominator** (`proof::prove`, 2-in, depth 6) | **1.105 s**, converged |
| Threshold | **2.0 s** — the **absolute floor** binds, the 15 % arm is 0.17 s |
| Ratio | 6 694 % |
| Graded path verified | **yes** — see below |

**The figures above are from the run that verifies.** The review pass found
that `paths_verified` had been set from `prove`'s `Ok` and that `proof::verify`
appeared nowhere in either binary (§3.6), so every earlier run measured work it
had never shown to be real. The corpus was re-run under the verify gate; these
are those numbers.

**What the re-run establishes, precisely.** The **depth-6 sparse path verifies
against its own root**, and so does each control arm — the first time the
graded path has been checked at all, at any depth, by anything but the unit
tests (which reach depth 3). That makes the artifact real. It does **not**
extend the *cost-equivalence* claim: sparse ≈ dense is still licensed by the
two-rung control at depths 4 and 5, one rung below the grading depth, exactly
as §3.5 says.

**The replay reproduced to 0.09 %** across the two quiet runs (73.871 s and
73.939 s) and the denominator to 1.2 % (1.118 s and 1.105 s) — the measurement
is stable, and nothing in the review pass moved it, because nothing the fixes
touched was inside a timer.

**A third run, and the rig protocol arguing for itself.** An earlier run of the
same corpus measured **96.8 s** — 31 % higher — because it was sharing the box
with a C++ daemon compile. Reported rather than dropped: the swing is larger
than many thresholds are, which is the concrete case for §5.2's *sustained,
quiet, to steady state* discipline. **A run that shares its machine measures
the other job too.**

**Read it as: ~37× over budget on hardware far faster than the rig.** The
direction is not in doubt even though the magnitude on a Cortex-A72 is, so
§6.3.4 row 2's pre-registered miss response — **amortized replay first** — is
the likely landing, and `WSS-Q1`(b) reopens only if the amortized form also
fails. This bench does not settle that: the amortized form is unbuilt, and the
rig grades.

**Note which arm binds.** At a 1.1 s denominator, 15 % is 0.17 s, so the
**2 s floor is the whole threshold**. A ratio-only record would have reported
"6 694 % of proving" and hidden that the budget being missed is an absolute
one — which is exactly why §6.3.4 asks for the seconds beside the ratio.

**The byproduct §6.3.4 wanted:** FCMP++ proving time for a 2-in canonical
transaction at depth 6 is **1.105 s on x86** (1.105–1.118 s across runs). Not the Cortex-A72 figure the
project wants — that needs the rig — but the first measured number of its kind
here, and the rig run yields the A72 one for free.

**The sparse-path control held at every rung, and the ratio is flat across
two.** In the verified run: **−1.5 % at depth 4** (25 993 leaves) and
**−1.1 % at depth 5** (467 857 leaves), both arms verified. Across all runs the
divergence sits in **−1.5 % … +0.9 %** — reported as a range because at that
magnitude a single run's figure is noise, not precision, and the claim that
matters is that the ratio does not *trend* with depth. Flatness across adjacent
rungs licenses the next one, so the record reads *"synthesized sparse, one rung
above the deepest control arm"* — the claim it is entitled to, not "licensed by
the control".

### 7.2 Open edge — comfortably inside budget, and round-trip bound

Against a live `shekyld --regtest`, 40 blocks mined, 30 sampled.

| Term | Value |
| --- | --- |
| Round-trip floor | **224 µs** (50 samples, loopback) |
| Per block | median 0.2 ms, p95 0.3 ms |
| Projected over 790 blocks | **1 580 round trips, 0.197 s** |
| Threshold | 5.0 s |
| Attribution | **round-trip bound** — 0.197 s round trips, ~0.000 s volume |

**This confirms the model correction empirically**: the cost is in round trips,
and the volume term is not where it lives. That is what §6.3.4 row 3's
amendment was made for.

**Three reasons this is not the whole answer, stated because the number looks
reassuring:**

1. **Regtest blocks are coinbase-only, so the fetch makes 2 round trips per
   block, not 3** — the record says `2.0` exactly. `get_transactions` is never
   called because there are no non-miner transactions. A real chain pays the
   third call, so the round-trip count is ~50 % higher (≈ 2 370).
2. **The volume term is untested, not measured as zero.** These blocks carry
   **1 432 B** decoded apiece. A worst-case chain block is three orders of
   magnitude larger, and at that size the volume term is a different quantity
   entirely. The `round-trip bound` attribution here is as much an artifact of
   an empty corpus as a finding about the path. **Owed: a corpus with realistic
   block weights**, which regtest coinbase mining cannot produce — it needs a
   wallet spending into the blocks.
3. **Loopback on a fast x86.** The Pi's per-round-trip floor will be higher, and
   1 580–2 370 round trips multiply it.

Even so, the headroom is large: the floor would have to rise ~25× before the
round-trip term alone reached 5 s.

## 8. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-20 | Open edge measured as **round trips, not throughput** — the landed fetch path is per-block with 2–3 sequential RPCs, so a bandwidth model grades the wrong term. Carries a §6.3.4 row 3 amendment: attribution before remedy |
| 2026-09-20 | The three block counts separated: replay window **725**, held buffer **790** (`W + 60`, §6.3.2 row 2), `W` **730**. Const-asserted |
| 2026-09-20 | Depth and window are **independent axes**. Dense depth-6 (17 778 529 leaves, 2.28 GB) is out of reach on the rig; the sparse path is licensed by a **same-depth** control, not by the padding comment |
| 2026-09-20 | Denominator is `proof::prove` directly — driving `sign_transaction` would fold BP+ and PQC signing into it |
| 2026-09-20 | Leaf rate derived from `block_weight_limit` + the surge clamp + `predict_weight`, **not** from `config/consensus_constants.json`, which carries no weight ceiling |
| 2026-09-20 | Rig gate split into **enforced** (arch, userland, RAM) and **attested** (storage, thermals); "sustained" became a convergence criterion |
| 2026-09-20 | **Review pass: the harness graded things it should have refused, and claimed a check it never ran.** Seventeen findings, all valid on inspection. The two that mattered most: `proof::verify` appeared **nowhere** in either binary while `paths_verified: true` was emitted from `prove`'s `Ok` and §3.6 asserted the round trip — now run once per graded path and per control arm, outside every timer; and the build script watched `../../.git/HEAD`, which in a **worktree** is not a directory at all (`.git` is a file), so the re-grade pin's staleness guard was inert in the setup every lane uses — now resolved through `git rev-parse --git-path`, watching HEAD, the branch ref and `packed-refs`. The rest became refusals (§5.1.1): a corpus override under `--grade`, unconverged series, prover failure, unlicensed extrapolation, a dense fallback at the wrong depth, malformed control sets, a remote daemon under `--grade`, and an unwritable artifact. The device pin moved from captured-but-unchecked to **enforced**. The dependency gate moved from a key regex to TOML with resolved package names, closing renamed and workspace-inherited edges (red-bitten live). |
| 2026-09-20 | **The open edge grades at a stated nominal density (the full-reward zone), not at the adversarial ceiling** (§4.4). 790 blocks at the ceiling is ≈ 1.9 GB decoded, so grading there writes the companion-file miss response before measuring it. The zone is the density at which the measurement can still surprise you. The asymmetry with the spend edge is deliberate: that edge decides an architecture and is paid per spend, this one decides a local mitigation and is paid once per launch. Enforced by a corpus-density gate that withholds the verdict rather than by a sentence |
| 2026-09-20 | **`per_block_advance_worst_case_s` added to the record**: the replay term over the blocks it covers. It is what decides whether a spend-edge miss kills the design or moves the work, and a reader should not need a calculator to see it |
| 2026-09-20 | **A wall-clock stop added beside the iteration cap**, found by running the harness rather than by reading it: the first worst-case run made plain that 60 unconverged iterations of a multi-minute replay is hours on the rig. The count bounds a fast noisy workload; only the clock bounds a slow one |
