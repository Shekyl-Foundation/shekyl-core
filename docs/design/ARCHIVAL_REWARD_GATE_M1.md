# M1 — Reward eligibility gated on shard count (consensus rule)

**Status: design rounds 1–3 closed (§9, §10, §11 records), plus the
§11.8 round-3 amendment (count-pass discipline, M3-1..M3-3) and the
§11.9 implementation-gates decision. IMPLEMENTED (2026-07-06, §11.10
record): the §6 pinned sequence executed steps 1–5 on
`feat/m1-reward-gate-design` after the pre-flight pass at the audit
pin, on the §1.3 second branch (fixture rows). The §1.3 merge
condition is satisfied: the segment-freeze pipeline design round
OPENED 2026-07-06
([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md),
round 1 draft carrying the O-1..O-3 discharge arguments in its §3).
`K_COVER` sealing remains gated on the §14.4 partition run (§4).** Per
`05-system-thinking.mdc` (specification first) and
`26-sub-pr-design-discipline.mdc` (cited: consensus-critical sub-PR
with design rounds before implementation; the pre-flight pass applies
between the rounds' closure and the first production commit).

**Provenance.** This document is the design round that
`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §16.2 pins as required — that section
is the pre-flight pin, this is the spec. The launch-posture context
(founder cover, cold-start refusal, the partition trap) lives in WI-4
§14–§16 and is not restated here; this doc owns the consensus rule.
**Location note (round 3, §11 M2-4; resolved 2026-07-06):** the WI-4
doc merged to `dev` via PR #262 (`1e89df832`) mid-implementation-arc —
every "WI-4 §…" pointer in this spec now resolves on `dev`. The
merge-ordering dependency ("before or with this spec's implementation
PR", §11.9 sequence slot 0) is **satisfied**: WI-4 landed on `dev`
before this branch's implementation PR opens.

**Timeframes (rule 05).** *Now:* the launch mechanics — the gate is the
structural form of cold-start refusal. *Mining-era end:* the gate is
long-dead and inert (see §7 dead-rule note). *V4:* independent of the
crypto substrate — the gate reads chain structure, not signatures.

---

## 1. What the rule is

> **For any settlement epoch `E` whose gate input `shard_count(E)` is
> below `K_COVER`, the archival reward for every persona is zero:
> `reward_P(E) = 0` for all `P`, by consensus computation.**

Posting a bond during the gated window stays **legal** (forbidding it
would block the founder cover per WI-4 §14); the bond simply earns
nothing for gated epochs. The reward gradient is the mechanical sorter,
and it is non-partitioning: a uniform function of chain state, applied
identically to every bond, marking none (§16.1 partition-trap
constraint — **global and blind**).

### 1.1 The gate input, defined (re-anchored at round 3, §11 M2-1)

`shard_count(E)` = the number of archival shards with a **frozen
segment at or before the close height** — concretely, the count of
rows in the **segment table** (`m_archival_shard_segment`,
`LMDB_SCHEMA.md`) whose `freeze_height ≤ H_close(E)`, taken inside
the same write transaction that performs the close.

**Explicitly not the gate input:** the epoch-close gather's
`EpochCloseInputs::shards` (`EpochCloseShard { has_segment, .. }`).
Rounds 1–2 anchored the definition there; round 3 found the anchor
pins a **different quantity** than the prose properties describe. The
gather enumerates serve-credit rows for epoch `E` — a shard enters
`shards` iff at least one `P` with a decodable bond earned a credit
on it that epoch (`db_lmdb.cpp`, gather phase) — so the gathered
count is `|{distinct s : ∃ credit(P,s,E)}|`, a **participation
measurement**: exactly the sensor class §1.2 declares absent. Under
that reading the gate is not monotone (an epoch where fewer than
`K_COVER` distinct shards happen to be served re-gates with no
adversary — a liveness bug), and a withdraw-service cartel or a
challenge-suppression DoS becomes a repeatable global griefing
lever. The segment-table count has neither defect. One asymmetry is
worth recording: the gathered count is bounded above by the
segment-table count, so the divergence is only ever downward — the
harmful direction.

**Threading (consequence for §2.1/§6):** `epoch_close_compute`
cannot derive the segment-table count from its current inputs, so
`EpochCloseInputs` gains a `frozen_shard_count: u64` field, the FFI
entry point gains the corresponding parameter, and the C++ gather
gains a segment-table count pass (a cursor walk filtered on
`freeze_height ≤ H_close(E)` — the filter is **explicit**, mirroring
the height guard the read path already applies; bare row existence
is not the predicate, per §11 M2-3).

**Count-pass discipline (round-3 amendment, §11.8 M3-1/M3-2).** The
count pass is the gate operand's *production site* and gets the same
structural protection as the predicate site:

- **One named helper, one call site.** The filter lives in a single
  function — `count_frozen_shards_at_close(h_close)` — called only
  from the close gather. No second counting read over
  `m_archival_shard_segment` may exist anywhere (an RPC "corpus
  size" surface, a verification-path recount, or a cached counter
  lacking O-3 pop-symmetry are the named drift adversaries); the §6
  tripwire's scope covers this, not just `K_COVER` comparisons.
- **Boundary inclusivity is consensus.** `freeze_height == H_close(E)`
  **counts** (the filter is `≤`, not `<`). An off-by-one edit here is
  a consensus fork at exactly the boundary class the Rust KAT cannot
  reach — G-10 injects `frozen_shard_count` and never executes the
  C++ filter — so the boundary is pinned by a C++ unit case (§5)
  with freeze heights strictly below, equal to, and above
  `H_close(E)`.
- **Decode failure is a loud abort.** The count pass must decode
  every row to read `freeze_height`; an undecodable row aborts the
  close — the same FATAL class as the gather's existing
  decode-failure discipline, never a lenient skip. A lenient-skip
  implementation silently lowers the count on one malformed row
  while a strict node aborts: two nodes disagreeing on `gated(E)` —
  a fork, in the gating direction.

Substrate properties (WI-4 §16.2 "Substrate"): shards are frozen
chain segments (`freeze_height`), so the segment-table count is a
**deterministic, monotone-per-branch function of chain height**. No
actor can inflate it (that requires mining the chain forward) and no
actor can stall it (chain growth freezes segments).
Cumulative-bond-count was evaluated and **rejected** as the gate
input: sybil-inflatable whenever cost-to-post is low. **Status
correction (round 3, §11 M2-2): these are import obligations, not
source facts** — see §1.3.

### 1.2 The gate predicate

```text
gated(E)  ⇔  shard_count(E) < K_COVER
```

Both operands are consensus facts every verifier derives identically:
`shard_count(E)` from the segment table at `H_close(E)` (§1.1),
`K_COVER` from `config/consensus_constants.json` (§4). There is no
sensor, no estimate, and no live-participant measurement anywhere in
the predicate — the flood-then-withdraw liveness DoS (keep a measured
cover below the bar) has no sensor to attack (WI-4 §16.3 / M2,
resolved into this rule). Round 3 is what makes this paragraph true
rather than aspirational: the rounds-1–2 anchor (the credit-derived
gather count) *was* a live-participant measurement; the §1.1
re-anchoring removes it (§11 M2-1).

### 1.3 Substrate obligations on the segment-freeze pipeline (round 3, §11 M2-2)

The segment table's **writer does not exist in production**.
`put_archival_shard_segment` is called only by the unit-test fixture
(`tests/unit_tests/archival_substrate_lmdb.cpp`); the
curve-tree-checkpoint writer `LMDB_SCHEMA.md` names is unbuilt, and
**no delete path exists** — segment writes are not connect/revert
paired today. §1.1's properties therefore cannot be "verified at
source"; they are **named obligations the segment-freeze design
round must discharge** (rule-21 shape — this round's arguments are
explicitly conditioned on them):

- **O-1 (determinism):** segment freezing is a pure function of
  chain content at the freeze height — same chain, same rows, every
  node.
- **O-2 (monotonicity per branch):** segments freeze as the chain
  grows and are never unfrozen or deleted on a single branch.
- **O-3 (pop-symmetry):** segment writes are connect/revert-paired —
  a reorg that pops the freeze height deletes the row, and re-apply
  recreates it bit-identically. Without O-3, a reorg near a freeze
  boundary leaves a stale row carrying the orphaned branch's
  `segment_subroot_rk`, which breaks retention-proof correctness
  generally — not just this gate. (The §9.4 reorg argument's step 1
  asserts this pairing; it holds today only vacuously, because
  nothing writes the table.)

The pre-flight pass **cannot sign off implementation of the gate
against a table nothing populates**: either the freeze pipeline's
design round precedes the gate's implementation PR, or the gate PR
lands with the KAT exercising fixture-written rows and O-1..O-3
pinned as blocking items on the pipeline round. Discharge is
recorded in the pipeline round's record, cross-referenced here.

**Decision (§11.9): the second branch.** The gate implements now, on
fixture-written rows, with O-1..O-3 blocking on the pipeline round.
The fork was wargamed rather than defaulted: what could the pipeline
round discover that invalidates gate work built against fixture
rows? The exposure is small because the count helper's contract
binds to the **table schema**, not to pipeline behavior — and the
schema is already fixed in `LMDB_SCHEMA.md` (key `BE(shard_id)`, 8
bytes, `CREATE`-only ⇒ single row per shard, no version component;
value carries `freeze_height`). Enumerated:

- *Future-dated freeze heights* — handled by the `≤ H_close(E)`
  filter; a row frozen "in the future" simply doesn't count yet.
- *Non-dense shard IDs* — handled by walk-not-watermark, which the
  count-pass discipline above already chose (the cached-counter
  alternative is a named drift adversary).
- *Versioned segments* — unrepresentable under the existing key; a
  pipeline design that needed them would be a schema change, which
  reopens far more than this gate.

The genuinely dangerous obligation — O-3 pop-symmetry — is
**chain-wide** (retention-proof correctness generally, per the O-3
entry above), not gate-specific: serializing the gate behind the
pipeline round buys the gate almost nothing while delaying the item
this spec ranks first *because it cannot be patched after seal*.
**Condition:** O-1..O-3 remain blocking items on the pipeline
round's record, cross-referenced both ways, and **the pipeline round
opens before the gate PR merges** — so a surprise discovered there
can still reopen this spec cheaply, while the work proceeds in
parallel.

**Condition satisfied (2026-07-06):** the pipeline design round
opened as
[`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
(round 1 draft). Its §3 carries the O-1..O-3 discharge arguments —
freezing as a first-crossing rule over the consensus curve-tree leaf
count, inheriting determinism/monotonicity/pop-symmetry from the
tree machinery already inside the block write txn (drain journal +
`trim_curve_tree`). Its §9 pop-symmetry test is the arming condition;
discharge finalizes when that round's rounds close and the tests
land. Its §6.2 additionally retires the `archival_shard_leaf` table
(derived copy of `m_curve_tree_leaves`) under the maintainer's
schema-restructure authorization for that round.

---

## 2. Enforcement locus: one canonical computation, one inherited check

The rule is enforced at **exactly one canonical point**, and every
other consumer inherits it by recomputation — never by a parallel
reimplementation of the predicate.

### 2.1 Canonical: the epoch-close computation

`epoch_close_compute` (`consensus_state.rs`) gains the gate as a
uniform factor at the **top** of the computation, fed by the new
`EpochCloseInputs::frozen_shard_count` field (§1.1 threading — the
segment-table count at `H_close(E)`, supplied by the C++ gather's
count pass; **not** derived from `inputs.shards`):

```text
if inputs.frozen_shard_count < K_COVER:
    EpochCloseResult = { r_market_by_shard: [0; n], sigma_work_milli: 0 }
```

**Output naming corrected at round 2 (§10 M1-3).** `EpochCloseResult`
carries exactly two fields — `r_market_by_shard` and
`sigma_work_milli` (`consensus_state.rs`); per-`P` work
(`work_by_bond`) is internal derived data, dropped after the `Σwork`
fold, deliberately **not** consensus-visible (the
`REWARD_EMISSION_VIN_PLAN.md` M-2 schema pin: the vin reconstructs
the numerator; per-`P` `capped_P` is never a stored record). The
round-1 draft's "`work_P(E) = 0` for every bond `P`" described a
field the function does not emit. The corrected statement: the gate
returns the zero result **without computing the internal
derivation** — there is no per-`P` intermediate to leak because
there is no per-`P` output at all. The gate widens no
consensus-visible surface, changes no FFI signature, and touches no
LMDB schema.

Zeroing at the top (rather than zeroing only `reward_share_floor`)
is deliberate: it guarantees **no consensus quantity derived from a
gated epoch is ever non-zero**, so no downstream consumer can
accidentally re-derive value from a gated epoch's state (the §3
invariant, enforced structurally rather than at each consumer).

**Zero through the normal close path — never skip the close (round-2
pin, §10 M1-5).** The tempting implementation — an early return at
the top of `process_archival_epoch_close_at_height` for gated
epochs — is **forbidden**. The store phase after the compute writes
three things whose absence breaks non-gate machinery: the sigma row
(stored unconditionally, including zero — a skipped close leaves
NOTFOUND instead of stored-zero), the **epoch-close log row** that
`revert_archival_epoch_close_at_height` keys its pop-symmetry on,
and the **prune advance**. The gate zeroes the *compute outputs*;
the close materialization runs unchanged. (The existing writer
already skips zero `r_market` rows at store, so a gated close
persists a zero sigma row and no `r_market` rows — the same store
shape as a legitimately-empty epoch.)

**The store cannot represent gatedness, and nothing needs it to
(round-2 fact, §10).** Zero `r_market` rows are skipped at store and
the sigma getter launders `MDB_NOTFOUND` to 0 (`db_lmdb.cpp`), so
gated, legitimately-zero, and (through the launder) never-closed
epochs are bitwise-identical to every store reader. This is
acceptable **because no consumer ever needs to read gatedness back**:
the claimability rule (§2.3) operates at the value level with no
gate predicate, and unclosed epochs are excluded by the explicit
`h > h_close(E)` structural bound (F-E1), not by row presence.

### 2.2 Inherited: emission verification (scope corrected at round 2)

The emission vin's `reward_amount_plain` is compared against the
verifier's ex-ante recomputation at **zero tolerance**
(`REWARD_EMISSION_LEG.md` §5.4/§5.5). Because the recomputation's
denominator is the **stored finalized `Σwork(E)` row** — zeroed by
§2.1 for gated epochs — a vin claiming any non-zero amount for a
gated epoch fails the existing compare with **no new validation
branch**.

**Inheritance scope, pinned precisely (§10 M1-4).** The inheritance
flows through the zeroed *store*, and only through it:

- The **economics compare** (verify step 5) inherits fully — its
  `Σwork(E)` is the stored row, zero for gated epochs, so
  `reward_P(E) = 0` by `reward_share_floor`'s zero-normalizer
  short-circuit.
- The **work-claim recompute** (verify step 4) inherits partially —
  its as-of-E inputs include `R_market(s,E)` (a zeroed gate output)
  but also serve-credit primaries, which the gate deliberately does
  **not** zero (§3: zero accrual, not zero accountability).
- Rejection of a gated claim therefore does **not** depend on
  verifier step ordering: whatever step 4 concludes, step 5's compare
  fails against any wire-representable (strictly positive, §2.3)
  claimed amount.

**The load-bearing discipline this makes doubly load-bearing:** the
verifier's `Σwork(E)` source is the **stored finalized row, never a
recompute from serve-credit primaries** (the §4.5 lagged-read pin;
the M-2 as-of-E sourcing pin). Pre-gate, that discipline protected
supply conservation against denominator drift. Post-gate it *also*
carries the entire non-claimability guarantee: a future refactor that
recomputes `Σwork` from primaries would silently bypass the gate
(primaries are non-zero during gated epochs). Any such refactor
reopens this design round.

### 2.3 Zero-share epochs are non-claimable (spec decision, amended at round-1 closure)

A claim batching gated epochs at amount zero would pass the §2.2
compare while carrying zero economic content — a pure timing signal
(the claim's existence and cadence) with no reward attached, in
exactly the window where claim-cohort thinness is the co-hazard the
gate refuses (WI-4 §16.2 "Verified synergy").

**The rule (uniform, sited at the wire — round-1 form composed with
round-2 M1-2):** **every entry of `reward_amount_plain` must be
strictly positive.** `ArchivalRewardEmissionVin::validate()`
(`emission_wire.rs`) rejects a vin carrying any zero amount —
stateless, at deserialization/validation, before any store read,
same error class as the existing structural wire errors. Combined
with the unchanged zero-tolerance compare (§2.2), this yields the
semantic rule round 1 stated — *every claimed epoch's recomputed
share must be strictly positive* — as a derived property: a
zero-share epoch can only pass the compare at claimed amount zero,
and zero is now unrepresentable on the wire.

Round 1 sited this rule at the verifier's recompute; round 2's M1-2
relocated it to the wire, which is strictly better: earlier
(rejection needs no state), ordering-independent (no dependence on
which verify step runs first), and it converts the beacon from
*rejected* to *unencodable*. The round-1 rationale carries over
intact, verified at source across both rounds:

1. **The vin never learns about `K_COVER`.** Zero-at-top (§2.1) makes
   gated epochs zero-share; wire positivity plus the compare then
   makes them non-claimable through pure data flow. `K_COVER` is
   compared at **exactly one site in the codebase**
   (`epoch_close_compute`) — see the §6 grep tripwire that keeps it
   at one.
2. **It closes the whole zero-row class, not just the gated case.**
   `Σwork(E) = 0` is already a legitimate pre-gate state (an epoch
   with no serve credits), a `P` can legitimately floor to zero
   (tiny `capped` against a large `Σwork` —
   `reward_share_floor` exact-floor), and the store's
   NOTFOUND-to-0 launder makes even unclosed epochs read as zero.
   All of these admitted a zero-amount claim row that passes
   `0 == 0`; all become unrepresentable under one wire predicate.
   (Unclosed epochs are additionally excluded by the explicit F-E1
   `h > h_close(E)` bound — two independent layers.)
3. **The wallet-side builder needs no second predicate** (§9 R1-Q2
   disposition, unchanged by the resiting). The builder must already
   recompute expected shares for the zero-tolerance compare; "omit
   zero-share epochs" is the same computation on the same data —
   and the wire now refuses to encode the alternative.

**Test-corpus consequence (round 2):** the current wire test corpus
treats a zero amount as well-formed (`emission_wire.rs` sample vin,
`reward_amount_plain: vec![1_000_000, 2_000_000, 0]`). The
implementation PR updates the corpus alongside the `validate()`
change; a KAT case pins the reject (§5 G-7).

Consequences, confirmed: the claim-window arithmetic
(`max_claim_age_w = 26`) never forces a claimant to include a
zero-share epoch — the window constrains only epochs actually
claimed. The batching bound
(`max_settlement_epochs_per_emission = 15`) is unaffected.

**Error-genericity non-requirement (§9 R1-D2 pushback, recorded so it
is not re-litigated):** the reject needs no privacy-motivated generic
wording. Gatedness is a deterministic public function of public chain
state (`shard_count` at `H_close(E)` vs `K_COVER`); any observer
computes the gated epoch set ex ante without submitting anything, so
a distinguishable error variant reveals nothing not already globally
derivable. Under the uniform rule the error is "claimed epoch has
zero computed share," which is not gate-specific by construction —
and a named, specific error is the `82-failure-mode-ux` disposition.

---

## 3. The zero-accrual invariant (the sharp pin)

> **No consensus quantity may accrue from pre-`K_COVER` epochs.**
> (WI-4 §16.2 "The sharp pin: zero accrual, not deferred payout.")

A defer-payout form (accrue now, claim after the gate opens) preserves
the early-staking yield and hollows the gate: a rational actor
pre-positions for deferred reward and the thin window repopulates with
exactly the personas the posture refuses. The gate must therefore
confer **no first-mover advantage** — the gate opening grants no
seniority to bonds posted before it.

Enumeration of the consensus quantities and why each satisfies the
invariant under §2.1 (each row is a review obligation — check the
claim against source, not against this table):

| Quantity | Carrier | Cross-epoch? | Disposition under the gate |
| --- | --- | --- | --- |
| `R_market(s, E)` | per-epoch membership count (`ARCHIVAL_CONSENSUS_STATE.md` §3.3) | No — recomputed per epoch, no seniority by design | Zeroed at §2.1 for gated `E`; contributes nothing anywhere |
| `work_P(E)` | per-epoch Σ over credited held shards | No | Zeroed at §2.1 |
| `Σwork(E)` | per-epoch normalizer | No | Zeroed at §2.1 |
| `reward_P(E)` | `reward_share_floor(budget, Curve(work_P), Σwork)` | No | 0 (inputs zero) |
| Serve credits | per-`(P, shard, E)` ledger rows | Rows exist per epoch; consumed only by that epoch's close | Rows may exist for gated epochs (serving is legal); they contribute nothing because the epoch's close is gated. **Review check:** no other consumer reads serve-credit rows across epochs |
| `join_settlement_epoch` | bond attribute | Yes — persists | Confers membership *from* join onward, never retroactive value; a pre-gate join earns nothing during gated epochs and starts from the same zero as a gate-open join. **Review check:** `market_member_at_epoch` and every consumer treat join epoch as eligibility-start only, never as an accrual multiplier |
| Shard age / `g(age)` | shard attribute (`freeze_height`) | Yes — persists | Persona-independent by construction (WI-4 §18.7: age is keyed to the *shard*, public and identical for every holder). Ages accrued during the gated window benefit every post-gate holder identically — not a first-mover asymmetry |
| Claim window (`max_claim_age_w`) | emission validation | Yes — 26-epoch look-back | Gated epochs are non-claimable (§2.3); nothing to age out |

The invariant's review form: for each row marked "Review check," the
round verifies at source that the stated property holds. Any quantity
found to accrue across the boundary is a spec violation, not an
implementation detail. (Both checks discharged at source — §9.1
round 1, re-confirmed with the C++ consumer enumeration at §10 round
2.)

### 3.1 Zero accrual is not zero accountability (round-2 pin, §10 M1-5)

The gate zeroes **outputs**, never inputs or liabilities. During
gated epochs, all of the following remain fully live, and an
implementation that no-ops any of them as a gated-epoch
"optimization" is a spec violation:

- **Serve-credit writes** — serving is legal and recorded; the rows
  simply feed a close that computes zero.
- **Bad-interval accrual and slashing** — `market_member_at_epoch`
  reads `bad_intervals` independently of any gate
  (`consensus_state.rs`), so misbehavior during the cover window
  poisons post-activation membership exactly as it would in the open
  regime, and the principal remains slashable throughout.

The cover window must not be implementable as a free-misbehavior
sandbox. The §3 invariant is *zero accrual*, not *zero
accountability*.

---

## 4. `K_COVER`: the spec/constant split

**The machinery lands now; the constant finalizes later.** (WI-4 §16.2
obligation 2.) The derivation chain is explicit and order-enforcing:

```text
K_COVER ← cover-thickness model ← founder-cover soundness
        ← partition-adversary-stays-at-chance
        ← §14.4 hypothesis class matching the adversary's (widened family)
```

A partition arm built at `k = 2` that passes while the real adversary
fields a richer partition yields a `K_COVER` derived against an
overoptimistic cover model — the gate calibrated too loose. Therefore:

1. **This design round specs the rule shape** (everything above and
   below this section) and may proceed to implementation of the
   machinery once the round closes.
2. **The constant's finalization gates on the §14.4 partition run**
   with the widened hypothesis class, feeding the dynamic cover model
   with its two named rows (WI-4 §16.2 obligation 3: founder-strip
   sensitivity, gate-open cohort dynamics).
3. The two reviews **must not** be conducted independently with one
   silently assuming the other passed.

**Placement.** `k_cover` enters `config/consensus_constants.json`
(the single source of truth for consensus constants whose C++/Rust
drift would cause silent wrong-output — exactly this constant's
failure class) under an `_comment_archival_launch` block. Until the
§14.4-derived value lands, the entry carries a **provisional sentinel
value and an explicit `PROVISIONAL — NOT GENESIS-READY` comment**;
the genesis-readiness checklist (WI-4 §13.5 sealing conditions) lists
the constant's finalization as a blocker.

**Sentinel mechanics (amended at round-1 closure, §9 R1-D3): the
build refuses, not just the checklist.** A runtime small-value
sentinel is rejected — a real-looking tiny `K_COVER` could be
silently treated as legitimate by any future `if threshold`-shaped
code, and a checklist is a human gate where a compile gate is
available. The JSON entry carries a companion flag
(`k_cover_provisional: true`); the constants generation
(`build.rs` / `generate_consensus_constants.py`) propagates it, and
the gate code emits a **compile-time refusal in non-test builds**
unless the flag is cleared — the same mechanism precedent as
`shekyl-p-transport`'s `compile_error!` absent the `tor-socks`
feature. Test and KAT builds enable a `provisional-k-cover` feature
explicitly (the KAT parameterizes `K_COVER` anyway, §5); a release
or genesis-config build with the provisional flag set does not
compile. The machinery is thereby testable end-to-end while
shipping-with-sentinel is refused **by code**, with the checklist as
the second layer rather than the only one.

**Preferred in-crate idiom (round 2, §10 M1-6, convergent with the
above):** mirror the frozen-constant tripwire already in
`reward_arithmetic.rs` — a `const _: () = assert!(...)` guard in the
release/genesis profile that fails until the §14.4-sealed value
lands, so the refusal lives next to the constant it guards in the
same shape the crate already uses for `WORK_MILLI_SCALE`.

**Genesis-frozen.** Both the rule and the constant must be right the
first time — post-activation there is no runtime signal (§7). This is
why the rule ranks first in the implementation path: it is the item
that cannot be patched after seal.

---

## 5. The activation-boundary KAT (first-class deliverable)

(WI-4 §16.2 obligation 1.) The §7 dead-rule acceptance relocates the
armed-gate-with-no-trigger risk **to time**: the gate fires once, at
the activation boundary, and is never exercised again. No steady-state
test and no runtime signal covers the boundary after launch, so the
following have exactly one chance to be right:

- the comparison direction and off-by-one in `shard_count ≥ K_COVER`;
- the `chain_epochs == 0` genesis edge (`shard_age_milli` returns 0 —
  "everything is hot at genesis" — `consensus_state.rs`
  `shard_age_milli`);
- the exact epoch at which first accrual becomes non-zero.

**Deliverable:** a consensus KAT in the crate's existing shape
(`tests/consensus_state_kat.rs` + `fixtures/consensus_state_kat_v1.json`
precedent; new fixture `reward_gate_kat_v1.json`) pinning behavior
**across the exact transition**:

| Case | `frozen_shard_count` (§11.8 M3-1 rebind — fixture authors bind names; the old `shard_count` column bound the pre-round-3 quantity) | Expected |
| --- | --- | --- |
| G-1 | `K_COVER − 1` | `Σwork = 0`, all `R_market = 0`, `reward_P = 0` for every `P` — provably zero |
| G-2 | `K_COVER` | non-zero accrual for a credited member — provably non-zero, and equal to the ungated computation's output (the gate at/above threshold is the identity) |
| G-3 | boundary epoch — the first `E` with `frozen_shard_count(E) ≥ K_COVER` | first non-zero accrual lands at exactly this `E`; the prior epoch's is zero |
| G-4 | genesis edge — `chain_epochs == 0` | gate composes with the `shard_age_milli` zero without masking or double-zeroing; result is well-defined zero |
| G-5 | §2.3 — emission vin claiming a zero-share epoch (gated case *and* the legitimately-empty case, per the uniform rule) | rejected structurally (not a zero-amount pass) |
| G-6 | gated-close **result shape** | `EpochCloseResult == { r_market_by_shard: [0; n], sigma_work_milli: 0 }` exactly — no field escapes the zeroing |
| G-7 | wire positivity (§2.3) | vin with any `reward_amount_plain[i] == 0` rejected at `validate()`, stateless |
| G-8 | batch spanning the boundary | `settlement_epochs = [K_COVER_boundary − 1, K_COVER_boundary]` with positive amounts: rejected whole (compare fails on the gated epoch); `[K_COVER_boundary]` alone with the correct amount: accepted — the §8 Q2 batching corner, executable |
| G-9 | `K_COVER = 0` degenerate | gate is the identity everywhere, including composed with G-4's `chain_epochs == 0` edge — the two zeros must compose without masking |
| G-10 | participation-independence (§11 M2-1, executable) | `frozen_shard_count ≥ K_COVER` while credits touch **fewer than `K_COVER` distinct shards**: **not gated** — accrual is non-zero for the credited member. The gate reads the segment table, never the served set |

**Fixture requirements (round 3):** the KAT fixture supplies
`frozen_shard_count` explicitly (it is an input, not derived from the
credit rows); the C++ store-side tests write segment rows via the
existing fixture writer. Per §11 M2-5, G-2's "equal to the ungated
computation" and G-3's "first non-zero accrual" are exercised with a
fixture shard **frozen during the gated window**, so the boundary
identity is tested with the age term live rather than degenerately
zero (gated epochs deliberately accrue shard age — §3's age row).

Added at round 2 (§10 M1-7), alongside the KAT but **in the C++ unit
suite** (`tests/unit_tests/archival_substrate_lmdb.cpp` — every real
consumer reads the store, not `EpochCloseResult`):

- **Stored-shape assertion for a gated close** — sigma row *present
  and equal to zero* (not NOTFOUND), zero `r_market` rows, close-log
  row written (the §2.1 never-skip-the-close pin, made executable).
- **Reorg round-trip** — close at the boundary epoch, revert via the
  close log, re-apply; assert bit-identical store (the §9.4 argument's
  connect/revert pairing, exercised at exactly the gate boundary).

Added at the round-3 amendment (§11.8 M3-1/M3-2), same suite — the
count-pass cases the Rust KAT structurally cannot reach (G-10
injects `frozen_shard_count`; only C++ executes the filter):

- **Filter boundary** — segment rows with `freeze_height` strictly
  below, **equal to**, and strictly above `H_close(E)`: the count
  includes the equal row (`≤`, §1.1 count-pass discipline) and
  excludes the above row. This pins the off-by-one that would be a
  consensus fork at the exact boundary class.
- **Malformed segment row** — an undecodable row in
  `m_archival_shard_segment` aborts the close loudly (the §1.1
  decode-failure pin, armed): never a lenient skip that silently
  lowers the count.

The KAT is **designed in from the start**, not backfilled; it is
parameterized over `K_COVER` so it survives the §4 constant
finalization without rewrite. CI wires it into the existing
`scripts/ci/check_archival_reward_gates.sh` shape.

---

## 6. Surface enumeration (implementation scope, grep-anchored)

The eventual implementation PR's complete surface, enumerated in
advance (criterion-3 shape from `07-consensus-atomic-cutovers.mdc`,
adopted here as evidence discipline; whether that rule's exception is
*invoked* is a PR-time decision — the current expectation is that the
implementation fits the standard 5-day/10-commit guidance and does
not need it):

| Surface | File | Change |
| --- | --- | --- |
| Canonical gate | `rust/shekyl-archival-retention/src/consensus_state.rs` (`epoch_close_compute`, `EpochCloseInputs`) | Gate factor at top of compute; `K_COVER` threading; **new `frozen_shard_count: u64` input field** (§1.1 round-3 re-anchor — the gate input is the segment-table count, not derivable from `inputs.shards`) |
| Constant | `config/consensus_constants.json` + `rust/shekyl-archival-retention/build.rs` (or the crate's constants surface, `src/constants.rs`) | `k_cover` entry + `k_cover_provisional` flag, compile-refusal plumbing (§4 sentinel mechanics), generated-constant contract per the file's existing C++/Rust generation |
| Emission validation | `rust/shekyl-archival-retention/src/emission_wire.rs` (`validate()`) — resited at round 2; the wire check is share-agnostic (pure value positivity), the semantic rule derives via the §2.2 compare | §2.3 wire positivity: reject any `reward_amount_plain[i] == 0`; update the test corpus (the sample vin currently carries a zero amount) |
| Predicate + operand tripwire | new `scripts/ci/` grep gate (shape precedent: `check_pending_post_write_path.sh`) | §10 M1-1: refuse any `K_COVER` comparison outside `epoch_close_compute` (+ the constants surface). **Extended at §11.8 M3-1:** also refuse any counting read over `m_archival_shard_segment` outside the single `count_frozen_shards_at_close` helper — the operand's production site gets the same one-site guarantee as the predicate site (§11.1's own pattern applied to the surface round 3 created) |
| Store-shape + reorg tests | `tests/unit_tests/archival_substrate_lmdb.cpp` | §5 round-2 additions: gated-close stored shape (sigma present-and-zero, no `r_market` rows, close-log row written); boundary-epoch close/revert/re-apply bit-identical |
| Wallet claim builder | future engine-side emission assembly (does not exist yet — verified at round 1, no `build_emission`/claim-builder site in `rust/`) | **Forward obligation, pinned here:** the builder derives claimable epochs from the same positive-share recompute (and can never encode a zero-amount row anyway, §2.3); carried as a spec requirement into the builder's own design round |
| KAT | `rust/shekyl-archival-retention/tests/reward_gate_kat.rs` + `fixtures/reward_gate_kat_v1.json` | §5 cases G-1..G-10 (G-6..G-9 added at round 2, G-10 at round 3) |
| CI | `scripts/ci/check_reward_gate_predicate_sites.sh`, wired as invariant 5 of `check_consensus_invariants.sh` (this is the landed form of the tripwire row above); the KAT runs in the crate's normal `cargo test` lane | Gate checks in the existing consensus-invariants shape |
| FFI/daemon | `shekyl-ffi` epoch-close entry point + `db_lmdb.cpp` gather (`process_archival_epoch_close_at_height`) | **Corrected at round 3 (§11 M2-1) — the rounds-1–2 "expected zero-change" was wrong.** The FFI signature gains a `frozen_shard_count` parameter; the C++ gather calls the single `count_frozen_shards_at_close(h_close)` helper (§1.1 count-pass discipline: explicit `freeze_height ≤ H_close(E)` filter — equality counts; decode failure aborts loudly; one call site) |
| Count-pass boundary + decode tests | `tests/unit_tests/archival_substrate_lmdb.cpp` | §11.8 M3-1/M3-2: filter boundary (below/equal/above `H_close`, equality counts) + malformed-row loud abort — the cases the Rust KAT structurally cannot reach |
| Docs | `ARCHIVAL_CONSENSUS_STATE.md`, `REWARD_EMISSION_LEG.md`, `docs/FOLLOWUPS.md`, `docs/CHANGELOG.md`, `docs/design/IMPLEMENTATION_INDEX.md` | Gate section + cross-references |

Pre-flight (per `26-sub-pr-design-discipline.mdc`) re-checks this
enumeration against the substrate at the audit pin before the first
production commit; growth beyond it during implementation is scope
creep and reopens the round.

**The audit pin is the dev head at pre-flight time, not `69af41a`
(§11.9).** The design rounds verified against the dev head current at
each round; dev has had merges land mid-arc before, and the pass
exists precisely to catch what landed since. Concretely re-verified
at the pin: exactly one `epoch_close_compute` call site; the gather
anchors (`process_archival_epoch_close_at_height` shape); **no new
readers of the stored sigma/`r_market` rows have appeared** (the
§11.6 R2-2 enumeration re-run, since a new reader is a new consumer
of the gate's zeroed outputs); plus the three named items below. The
§11.1 pattern applies to the pass itself — every operand at its
production site, as it exists at the pin, not as it existed when the
rounds closed.

**Named pre-flight items** (beyond the enumeration re-check):

1. The §2.2 lagged-read clause (standing item, §11.6 R2-1).
2. **`K_COVER` derivation input check (§11.8 M3-3):** the round-3
   re-anchor deliberately moved the gate input further from directly
   measuring what the gate protects (cohort thickness), pushing the
   entire proxy burden into the `K_COVER` derivation. The WI-4 §14.4
   calibration must derive the constant against the **segment
   count** — not any served/participation quantity — or the
   calibration reintroduces, at constant-derivation time, exactly
   the sensor the gate input shed. Verifiable once the WI-4 doc
   merges per the Provenance ordering pin.
3. The §1.3 substrate condition (O-1..O-3 status at the audit pin).

**Implementation sequence (§11.9).** The ordering below is pinned;
it is not a suggestion:

0. **WI-4 doc merge gets an explicit slot** — `feat/wi4-gf7-measurement`
   merges to `dev` before or with the implementation PR, per the
   Provenance ordering pin. Without a named slot the pin is
   aspirational and the implementation PR's provenance dangles on
   `dev` exactly as the round-2 review sweep experienced. The
   pipeline design round (§1.3 decision condition) **opens** before
   the gate PR merges.
1. **Constants plumbing + compile-refusal first**, before the
   `k_cover` identifier exists anywhere else in the tree. The §4
   sentinel's refusal must be armed before there is anything for it
   to guard — landing the identifier first opens a window where a
   plausible provisional value is loose in the tree with no trigger,
   which is precisely the silent-ship class the sentinel exists to
   refuse.
2. **Count helper + threading** — `count_frozen_shards_at_close` in
   the C++ gather, the FFI parameter, `EpochCloseInputs::frozen_shard_count`,
   the §2.1 zero-at-top factor.
3. **Wire positivity + the test-corpus fix** — the `validate()`
   reject and the existing sample vin that carries a zero amount
   (§6 emission-validation row), in the same commit: the corpus must
   flip with the rule, not before or after it.
4. **KATs (G-1..G-10) + the C++ store-side tests** — stored-shape,
   boundary-reorg, filter-boundary, malformed-row.
5. **Tripwire scripts last** — the grep gates need the final site
   names to grep for; landing them earlier hard-codes names that
   steps 1–4 may still move.

- **Dead rule, named and accepted** (rule 15 shape): `shard_count`
  monotone ⇒ the gate is trivially satisfied forever after activation —
  a permanently-inert consensus branch. Accepted because it is a pure
  uniform computation with negligible surface, and unlike migration
  code it cannot misfire on live state. A **height-sunset alternative
  is rejected**: it adds a second genesis-frozen constant to get right
  while buying nothing.
- **Reversion clause** (rule 21 shape). *Rejection:* no relaxation,
  sunset, or alternate gate input. *Reopening criteria:* a substrate
  change to shard-segment creation — specifically, if `shard_count`
  ever stops being a deterministic monotone function of chain height
  (e.g., shard deletion, dynamic resharding, or segment unfreezing
  enters the design). *Re-evaluation shape:* a fresh design round on
  this document, before the substrate change lands, since the gate's
  non-manipulability proof (§1.1) is what the reopening event
  invalidates.
- **Reorg-argument reversion clause (round 2, §10 M1-8; snapshot
  re-anchored at round 3, §11 M2-1).** The §9.4 reorg argument is
  trivial *because* the gate predicate reads only the close-height
  snapshot — the **segment table** filtered to
  `freeze_height ≤ H_close(E)`, store state whose connect/revert
  pairing is obligation O-3 (§1.3) — against a frozen constant. If
  the §14.4 partition run ever tempts a corpus-size- or
  participation-triggered activation instead of a frozen epoch
  constant, **the reorg argument must be rebuilt from zero** — that
  design change reopens §9.4 explicitly, not implicitly. This is the
  same input restriction the §6 grep tripwire guards, load-bearing
  twice. **Round-3 trigger addition (§11 M2-2):** the reversion
  clause's reopening list gains *the segment-freeze pipeline landing
  without O-3 pop-symmetry* — if segment writes ship without paired
  deletion, both §9.4 and the retention-proof correctness argument
  are void and this round reopens.
- **Lagged-read tripwire is permanent (round 3, §11 R2-1).** The §2.2
  reopen-on-refactor clause (never recompute `Σwork` from primaries)
  is checked in every future PR touching the close or verify path —
  a standing pre-flight item, not a one-time note.
- **Gated-epoch prune optimization — rejected (round 2, §10 M1-9,
  rule 21 shape).** Gated epochs are never claimable, so their
  serve-credit and `r_market` rows could in principle be pruned
  immediately after close (safe: bad intervals live in bond records,
  not serve-credit rows, so slash history survives). *Rejected*
  because it adds a second prune rule — permanent code — for storage
  bounded by a finite, one-time window (the gate is forever-inert
  after activation, §7 dead-rule note; the same logic that rejects
  migration code for one-time state). *Reopening criterion:* the
  gated window's serve-credit storage is shown material in a testnet
  rehearsal. *Re-evaluation shape:* a scoped follow-up against the
  prune table, not a reopening of this round.
- **What the gate does not cover** (named, owned elsewhere): off-path
  distinguishers — funding provenance, address reuse, temporal
  clustering — are M3/M4's surface (WI-4 §16.4–§16.5) and §14.4's
  measurement object. The gate refuses the cold-start *regime*; it
  does not grade the cover inside the open regime.

---

## 8. Round-1 review questions (as posed; dispositions in §9)

The questions this round answered before closure (each is a
disposition recorded in §9, not an open musing):

1. **§2.1 zero-at-top vs zero-at-share.** The spec chooses zeroing the
   whole epoch-close output. Confirm no consumer of
   `EpochCloseResult` (FFI shim, daemon state store) treats
   `sigma_work_milli == 0` as an error or divide-by-zero hazard rather
   than a valid gated-epoch state (`reward_share_floor` already
   returns 0 on `sigma_work_milli == 0` — verify the remaining
   consumers).
2. **§2.3 non-claimable form.** Confirm rejecting gated epochs in
   `settlement_epochs` composes with the claim-window and batching
   arithmetic with no forced-inclusion corner (the §2.3 stated check).
3. **§3 table review checks.** The two rows marked "Review check"
   (serve-credit cross-epoch consumers; `join_settlement_epoch` as
   eligibility-only) verified at source.
4. **§4 sentinel mechanics.** Whether the provisional `k_cover`
   sentinel is a real small value (testable, dangerous if shipped) or
   an explicitly-invalid marker the build refuses at genesis-config
   assembly (safer, more plumbing). The genesis-readiness checklist
   entry exists either way; the question is defense-in-depth.
5. **Activation semantics under reorg.** `shard_count` is monotone in
   height on one chain, but a reorg across the activation boundary
   replays the gate's one firing. Confirm the gate needs no special
   reorg handling beyond the existing epoch-close recomputation
   discipline (`archival_reorg_depth_blocks = 720` vs
   `settlement_epoch_blocks = 10_000` — the boundary sits inside one
   epoch; state the argument, don't wave it).

---

## 9. Round-1 record (closed)

The round ran as an adversarial wargame over the four highlighted
decisions (findings R1-1..R1-4) plus the five §8 questions
(R1-Q1..Q5). Dispositions, with source evidence; retained finding
IDs match the review's.

### 9.1 R1-D1 — Q1/Q3: the consumer walk (findings R1-Q1-1, R1-Q3-1, both High as posed; both resolved, one dissolves)

The review's concern: a consumer written against the invariant
"`Σwork` present ⟹ the epoch contributed to emission" is silently
broken by gated zeros. Walked at source:

- **`epoch_close_compute` has exactly one production call site:**
  `BlockchainLMDB::process_archival_epoch_close_at_height`
  (`src/blockchain_db/lmdb/db_lmdb.cpp`, via
  `shekyl_archival_epoch_close_compute` in
  `rust/shekyl-ffi/src/archival_ffi.rs`). Outputs persist to two LMDB
  tables (`archival_r_market`, `archival_sigma_work`). The only
  readers are `get_archival_r_market` /
  `get_archival_sigma_work_milli` — and **no production code calls
  them yet**. The emission verify that will (PR-E3) is unbuilt, and
  its plan already mandates explicit structural bounds
  (`h > h_close(E)`, `E ≥ C − W`) over row-absence proxies
  (`REWARD_EMISSION_VIN_PLAN.md` finding F-E1). There is no pre-gate
  consumer holding the broken invariant, because there is no
  consumer at all.
- **The invariant was already false pre-gate.** An epoch with no
  serve credits stores a legitimate `Σwork = 0` row today; gated
  epochs reuse an existing state class rather than introducing one.
  `reward_share_floor` short-circuits to 0 on a zero normalizer
  (`reward_arithmetic.rs` — no divide-by-zero path; `mul_div_floor`
  additionally guards `d == 0`).
- **`join_settlement_epoch` is eligibility-only, confirmed:**
  `serve_credit_epoch_ok` (`serve_eligibility.rs`) is a pure
  `E ≥ E_join + 1` predicate; its one consumer
  (`blockchain.cpp` serve-credit acceptance) uses it as
  accept/reject only. Serve-credit rows are *inputs* to epoch close
  (gathered per epoch at `H_close`), not readers of it; no reward
  arithmetic exists outside `epoch_close_compute` and the future
  verify-side recompute. §3's two "Review check" rows are
  discharged.

### 9.2 R1-D2 — Q2 + the R1-2 residual: the non-claimable rule made uniform

The walk in 9.1 surfaced that zero-share is a legitimate
pre-existing state, which converts the draft's gate-specific
non-claimable rule into the **uniform positive-share rule** now in
§2.3 — the vin path never consults `K_COVER`; gated epochs become
non-claimable through §2.1's data flow alone; and the
previously-representable zero-amount claim row for a
legitimately-empty epoch becomes unrepresentable as a side effect.
R1-Q2-1 (Medium — wallet builder must refuse too) is discharged by
the same move: the builder already recomputes shares for the
zero-tolerance compare, so zero-share skipping is the same predicate
on the same data; pinned as a forward obligation in §6 since no
builder exists yet (verified: no claim-construction site in `rust/`).

R1-2's error-genericity residual is **rejected with a mechanism
argument** (recorded in §2.3): gatedness is a deterministic public
function of public chain state, computable ex ante by any observer,
so error-message distinguishability discloses nothing — and the
uniform rule's natural error ("zero computed share") is not
gate-specific anyway. Named errors stay, per `82-failure-mode-ux`.

### 9.3 R1-D3 — Q4: sentinel is build-refused (finding R1-Q4-1, accepted)

Accepted in full; §4 "Sentinel mechanics" amended. Runtime
small-value sentinel rejected (future `if threshold` code could
treat it as legitimate); compile-time refusal in non-test builds via
a `k_cover_provisional` flag propagated through constants
generation, `compile_error!`-precedent from `shekyl-p-transport`.
The checklist becomes the second layer, not the only one.

### 9.4 R1-D4 — Q5: the reorg argument, written out (finding R1-Q5-1)

The invariant the review demanded — "a reorg that would change an
epoch's gated status is either impossible past finality or explicitly
handled" — holds via case (a) of the review's dichotomy, through
machinery that already exists. The argument, with the exact
constants:

1. **Gated status is connect/revert-paired state, not a one-way
   latch.** `gated(E)` is a pure function of the frozen-segment rows
   at `H_close(E)`, and the epoch-close materialization is
   symmetric: `process_archival_epoch_close_at_height` writes the
   `R_market`/`Σwork` rows when the close block connects;
   `revert_archival_epoch_close_at_height` deletes them when it pops
   (`db_lmdb.cpp`; `ARCHIVAL_CONSENSUS_STATE.md` §4 invariant 2).
   A reorg across `H_close(E)` reverts the close and recomputes it
   on the new chain deterministically — both branches agree with
   themselves, always.
2. **No citing emission can outlive the close it cites.** An
   emission claiming `E` is valid only in blocks **strictly above**
   `H_close(E)` (`REWARD_EMISSION_LEG.md` §4.5: "reorg revert cannot
   strand a citing emission — all citing emissions sit strictly
   above `h_close(E)` and are popped before the finalization
   reverts"). So any reorg deep enough to change `gated(E)` pops
   every emission that relied on the old status *before* it pops the
   status itself. There is no window in which a mint from an
   epoch-gated-on-the-new-chain survives onto the new chain.
3. **Depth bound.** `ARCHIVAL_REORG_DEPTH_BLOCKS = 720 ≪
   SETTLEMENT_EPOCH_BLOCKS = 10_000`: a processable reorg can cross
   at most one epoch-close boundary, and only when the tip is within
   720 blocks of it — the same bound the claimed-epoch prune already
   leans on (§6.6 of the emission leg).
4. **The double-spend limb.** A reward vout minted on the orphaned
   branch does not exist on the new chain; a spend of it is invalid
   for output-nonexistence, and its FCMP++ key images were never
   recorded on the new chain (key-image state is popped with the
   spending blocks). Additionally, outputs only become spendable
   after deferred curve-tree insertion at maturity
   (`shekyl_types.h` pending-tree machinery), so the exposure window
   is further narrowed. None of this is gate-specific — it is the
   standard reorg property of every output on the chain; the gate
   adds no new surface to it.
5. **The supply-audit limb.** Loud mint amounts are per-chain state;
   the audit sums the canonical chain. Since (1)–(2) guarantee each
   chain is internally consistent about gated status and citing
   emissions, no cross-branch inconsistency is observable on any
   single chain — a reorg replaces one consistent view with another.

Consequence for §5: **no sixth KAT case is required** — the KAT pins
the pure function's boundary behavior; reorg consistency is the
connect/revert pairing's property and is already exercised by the
existing epoch-close revert tests (`revert_archival_epoch_close_at_height`
coverage). The pre-flight pass verifies that pairing covers the
gate-added zeroing (it does trivially: the gate changes the values
written, not the write/revert shape).

### 9.5 Findings accepted without amendment

R1-1 (zero-at-top correct; residual covered by 9.1), R1-3 (split
well-articulated; sentinel hardened further by 9.3 anyway), R1-4
(KAT parameterization survives finalization; reorg pressure resolved
by 9.4).

---

## 10. Round-2 record (closed)

Round 2 was a second independent review (findings M1-1..M1-9),
conducted against the four decisions and five §8 questions as stated
— the round-1 closure commit was unpushed, so the reviewer could not
see the §9 amendments. Several findings therefore converge with §9;
two compose with it into dispositions better than either round alone
(the shape the review itself asked for: "a nuanced combination yields
additional improvements"). All source claims in the review were
re-verified before disposition.

**The structural fact the round contributed, adopted into §2.1:** the
store cannot represent gatedness. Zero `r_market` rows are skipped at
store, the sigma getter launders NOTFOUND to 0 — gated,
legitimately-zero, and never-closed epochs are bitwise-identical to
every store reader. The design is sound against this *because* no
consumer needs to read gatedness back (see M1-1's disposition), but
the fact had to be stated, and it drives the stored-shape test (§5).

### 10.1 M1-1 (high) — dissolved-and-exceeded: predicate-site count is one, not two-made-consistent

The finding's premise — "the vin reject must independently evaluate
the gate predicate, so there are two predicate sites by
construction" — was true of the round-1 *draft* rule ("reject gated
epochs in `settlement_epochs`") but is dissolved by the §9
R1-D2 amendment as composed with M1-2: wire positivity (§2.3) plus
the zero-tolerance compare against the zeroed stored `Σwork` reject
every gated claim **with no gate predicate in the vin path at all**.
A gated claim with a positive amount dies at the compare; a zero
amount is unencodable. `K_COVER` is compared at exactly one site
(`epoch_close_compute`) — satisfying M1-1's single-source-of-truth
invariant at N=1 rather than N=2. The finding's guard is adopted
anyway: the §6 grep tripwire refuses inline `K_COVER` comparisons
outside the canonical site, keeping the count at one against future
drift (the off-by-one-at-`K_COVER±1` consensus-fork adversary the
finding names). The spec's "no second predicate site" wording, which
the finding correctly called misleading under the draft rule, is now
literally true and stated with its mechanism in §2.2/§2.3.

One precision correction to the finding's proposed shape: the
canonical predicate's inputs are `(shard_count(E), K_COVER)` where
`shard_count(E)` is the gathered frozen-segment snapshot at
`H_close(E)` — connect/revert-paired store state — not
`(settlement_epoch, K_COVER)` as literally stated; the gather is
chain state by construction. The purity that matters (and that the
tripwire + §7 reversion clause guard) is *no live/tip state beyond
the close-height snapshot, no participation counters, frozen
constant threshold*.

> **Re-corrected at round 3 (§11 M2-1):** this note pinned the wrong
> snapshot. "The gathered frozen-segment snapshot" is credit-derived —
> a participation counter, violating the very purity requirement the
> note states. The correct snapshot is the **segment table** filtered
> to `freeze_height ≤ H_close(E)` (§1.1 as re-anchored). The purity
> statement itself stands; the quantity it was attached to did not.

### 10.2 M1-2 (high) — adopted as the primary form of the §2.3 rule

Round 1 had independently derived the same uniform rule but sited it
at the verifier's recompute; M1-2's wire-level form
(`reward_amount_plain[i] == 0` rejected at `validate()`) is adopted
as strictly better: stateless, earlier, ordering-independent, and it
makes the zero-row beacon unencodable rather than rejected. The
round-1 positive-share statement survives as the derived semantic
property. §2.3 rewritten accordingly; test-corpus consequence named
(the sample vin's zero amount); G-7 pins the reject. The finding's
enumeration of the beacon class beyond the gated case
(legitimately-zero `Σwork`, floor-to-zero `P`, NOTFOUND-laundered
unclosed epochs) is adopted into §2.3's rationale — it is the
complete argument for why the rule must be uniform and value-level.

### 10.3 M1-3 (medium-high) — accepted, disposition (a): wording fix

Verified at source: `EpochCloseResult` is two fields; `work_by_bond`
is internal and dropped; the FFI exports exactly the two fields;
per-`P` `capped_P` is deliberately non-consensus-visible
(VIN_PLAN M-2 schema pin). §2.1 rewritten — the gate returns the
zero result without computing the internal derivation; no surface
widening, no FFI/schema change. Alternative (b) rejected without a
wargame because nothing needs it.

### 10.4 M1-4 (medium) — adopted with a mechanism correction

The finding's conclusion (inheritance is not whole-vin; scope the
claim) is right and §2.2 is rewritten to carry it. The mechanism is
corrected: verify step 4's as-of-E inputs include `R_market(s,E)` —
a zeroed gate output — so the work channel *partially* inherits;
the load-bearing fact is sharper than an ordering pin. Rejection of
gated claims needs no step ordering at all (step 5's compare against
stored-zero `Σwork` fails any wire-representable amount); what it
does need is the **lagged-read discipline** — stored `Σwork`, never
a primary recompute — which the gate makes load-bearing for a second
reason (pre-gate: supply conservation; post-gate: the entire
non-claimability guarantee). Pinned in §2.2 with an explicit
reopen-on-refactor clause.

### 10.5 M1-5 (medium) — adopted in full, two pins

(a) §2.1 "zero through the normal close path": the early-return
implementation is forbidden by name — it would skip the close-log
row (breaking `revert_archival_epoch_close_at_height`'s pop
symmetry), skip the prune advance, and leave sigma NOTFOUND instead
of stored-zero. Verified at source that all three writes sit below
the compute in `process_archival_epoch_close_at_height`.
(b) §3.1 "zero accrual is not zero accountability": serve-credit
writes, bad-interval accrual, and slashing remain fully live during
gated epochs; `market_member_at_epoch` reads `bad_intervals`
independently of any gate, so cover-window misbehavior poisons
post-activation membership. The cover window is not a
free-misbehavior sandbox.

### 10.6 M1-6 (medium) — convergent with §9.3; idiom addition adopted

Round 1 had already moved the sentinel to compile-time refusal
(R1-D3). M1-6 independently reached the same disposition and adds
the concrete in-crate idiom: mirror the `WORK_MILLI_SCALE`
`const _: () = assert!(...)` tripwire (`reward_arithmetic.rs`) in
the release/genesis profile. Adopted into §4's mechanics as the
preferred implementation shape alongside the feature-gated
provisional value.

### 10.7 M1-7 (low-medium) — KAT additions adopted, with placement split

G-6 (result shape), G-7 (wire positivity), G-8 (batch spanning the
boundary — the §8 Q2 corner made executable), G-9 (`K_COVER = 0`
degenerate composing with the genesis edge) added to §5. The
stored-shape assertion and the reorg round-trip are adopted but
placed in the C++ unit suite (`archival_substrate_lmdb.cpp`), not
the Rust KAT — the Rust KAT exercises the pure function, and the
store shape is C++ writer behavior; the finding's observation that
"every real consumer reads the store" is exactly why the store-side
test carries the assertion.

### 10.8 M1-8 (low) — convergent with §9.4; reversion clause adopted

The reorg argument as written in §9.4 already rests on the
connect/revert pairing; M1-8's contribution is naming the condition
under which it collapses — a corpus-size- or participation-triggered
activation instead of a frozen constant — and requiring the argument
be rebuilt from zero in that world. Adopted as an explicit rule-21
reversion clause in §7, cross-anchored to the same input restriction
the grep tripwire guards.

### 10.9 M1-9 (low) — rejected with a reversion clause

The gated-epoch prune optimization is safe (verified: bad intervals
live in bond records, not serve-credit rows) but adds a second prune
rule — permanent code for a finite one-time window, the same shape
rule 15 rejects for migration code. Rejected; reopening criterion
(storage shown material in a testnet rehearsal) and re-evaluation
shape (scoped prune follow-up, not a round reopen) recorded in §7.

### 10.10 §8 Q1/Q3 — convergent answers, C++ enumeration adopted

The round's Q1/Q3 answers match §9.1 and extend it with the complete
C++ serve-credit consumer enumeration (challenge-path point ops,
epoch-close gather cursor, prune cursor — no cross-epoch reader at
close time), which is adopted into the record. The remaining Q3
exposure is the future PR-E3 verifier, carried by §2.2's lagged-read
pin (10.4).

---

## 11. Round-3 record (closed)

Round 3 ran as two parallel reviews against the pushed spec text at
`f7621540d`: a closure review (findings R2-1..R2-4, all low/watch)
and a deep source pass (findings M2-1..M2-5) that surfaced a
**critical defect the first two rounds missed**. Every source claim
in both reviews was re-verified before disposition; all held, and
one (M2-4) resolved more precisely than stated.

### 11.1 M2-1 (critical) — accepted in full; §1.1 re-anchored to the segment table

The two-quantity defect is real and rounds 1–2 own it: §1.1's prose
properties (deterministic, monotone, sensorless) describe the
**global segment-table count**, while its concrete anchor — and
§10.1's precision note — pinned the **epoch-close gather count**,
which is credit-derived (a shard enters `EpochCloseInputs::shards`
only via a serve-credit row from a decodable bond; verified in the
gather phase of `process_archival_epoch_close_at_height`). The
gathered count is a participation measurement: exactly the sensor
§1.2 claims does not exist. Consequences as the finding states: (a)
non-monotone — a low-participation epoch re-gates with no adversary,
falsifying §7's dead-rule claim under that reading; (b) the
withdraw-service / challenge-suppression lever exists — a repeatable
global griefing instrument; (c) the divergence asymmetry (gathered ≤
global) means manipulation is downward-only — the harmful direction;
(d) G-2/G-3 and §9.4 silently assumed the global reading.

**Fix landed:** §1.1 redefines `shard_count(E)` over
`m_archival_shard_segment` with the explicit
`freeze_height ≤ H_close(E)` filter; §2.1 threads it as
`EpochCloseInputs::frozen_shard_count` (the compute cannot derive it
from current inputs); §6's FFI/daemon row corrected from "expected
zero-change" to the enumerated signature + gather-count-pass changes;
§10.1's precision note re-corrected in place; G-10 added (the
participation-independence property, executable: high segment count +
low served-shard diversity ⇒ **not** gated). The finding's own note
is confirmed: M1-1's dissolution (one predicate site, no vin
predicate) is orthogonal to which quantity the one site compares —
it survives unchanged.

**Why rounds 1–2 missed it:** both rounds verified the *consumers*
of the gate (vin path, store semantics, zeroing locus) against
source, but took the gate *input's* anchor from the round-1 draft
without walking the gather that populates it. The rule-16 lesson
("what does this deliver against the threat model?") applied to the
predicate's output side but not its input side. Recorded as a
pattern for pre-flight: **verify the definition of every operand of
a consensus predicate at its production site, not just the
predicate's consumers.**

### 11.2 M2-2 (critical, pre-flight blocker) — accepted; §1.3 obligations named

Verified: `put_archival_shard_segment` has no production caller
(unit-test fixture only; the `LMDB_SCHEMA.md` "curve-tree
checkpoint / genesis seed" writer is unbuilt), and no deletion path
exists against `m_archival_shard_segment` anywhere in the tree —
segment writes are not connect/revert-paired today. §1.1's
"verified at source" was verifying unbuilt code's intended
properties. Fix landed: §1.3 restates the properties as named
obligations O-1 (determinism), O-2 (per-branch monotonicity), O-3
(pop-symmetry) on the future segment-freeze design round, rule-21
shape; the §9.4 reorg argument is explicitly conditioned on O-3; the
§7 reversion clause gains the pipeline-lands-without-O-3 trigger;
and the status header carries the pre-flight condition — the gate
implementation PR may precede the pipeline only with fixture-driven
KATs and the obligations pinned as blockers on the pipeline round.
The O-3 note generalizes beyond the gate: a stale
`segment_subroot_rk` from an orphaned branch breaks retention-proof
correctness wholesale.

### 11.3 M2-3 (high) — accepted; filter made explicit

Verified: the gather sets `has_segment = 1` on bare row existence,
while the read path guards `at_height < freeze_height`. Under the
M2-1 fix the gate's count applies the filter explicitly (§1.1, §6);
the residual hazard (a consensus predicate's meaning depending on an
acceptance check in another module) is thereby removed from the gate
input. The finding's mitigant is confirmed at source
(`shard_age_milli` returns 0 for `close ≤ freeze_height`), which
bounds the residual for the gather's *remaining* uses of
`has_segment` to a unit of count in quantities that are not the gate
input.

### 11.4 M2-4 (medium) — resolved more precisely: a merge-ordering dependency, not a missing doc

`ARCHIVAL_BOND_WI4_MEASUREMENT.md` exists and is verifiable — on
`feat/wi4-gf7-measurement`, pushed to `origin`, unmerged to `dev`;
the round-3 review searched `dev` and this branch only. No pointer
in this spec is stale-named. Fix landed: the Provenance section
names the branch and pins the merge-ordering dependency (WI-4 doc
merges before or with this spec's implementation PR).
**Dependency satisfied 2026-07-06:** WI-4 merged to `dev` via #262
(`1e89df832`) — see the Provenance note and §11.10.

### 11.5 M2-5 (low) — adopted as fixture requirements

G-2/G-3 exercised with a fixture shard frozen during the gated
window so the boundary identity runs with the age term live (§5
fixture-requirements paragraph).

### 11.6 R2-1..R2-4 (closure review) — dispositions

- **R2-1 (lagged-read refactor risk):** adopted — §7 gains the
  "tripwire is permanent" item; every close/verify-path PR re-checks
  the §2.2 clause at pre-flight.
- **R2-2 (enumerate stored-close readers):** adopted into this
  record as the auditable list. Readers of the stored close shape
  today: `get_archival_r_market` and `get_archival_sigma_work_milli`
  (`db_lmdb.cpp`), called by **no production code** — the unit suite
  exercises them, and the first production reader will be PR-E3's
  verify (stored-Σwork lagged read, §2.2). Any new reader added
  after this round must not assume "sigma row present ⟹ epoch
  contributed to emission" (gated, legitimately-empty, and — via the
  NOTFOUND launder — unclosed epochs all read zero; §2.1). The §5
  stored-shape test makes that assumption fail fast.
  **Enumeration amended at implementation (§11.10):** the step-4 test
  work added `has_archival_sigma_work_row` (test-support reader that
  distinguishes present-and-zero from `MDB_NOTFOUND`, which
  `get_archival_sigma_work_milli` deliberately launders to 0 — needed
  to assert the stored shape at all) and
  `put_archival_shard_segment_raw_for_corruption_test` (test-support
  raw writer that plants an undecodable segment row, arming the M3-2
  decode-failure abort — `put_archival_shard_segment` funnels through
  `encode()` and cannot write a malformed row). Both are
  test-support-only, no production caller; neither reads gatedness
  (which remains unrepresentable, §2.1).
- **R2-3 (reorg crossing a claim attempt):** adopted as a **forward
  obligation on the wallet claim builder / PR-E3**, not a store
  test: a claim built against branch A, mined on branch B where the
  boundary moved, is *correctly rejected* by the compare (each
  branch's store is internally consistent — §9.4); the wallet-side
  obligation is handling that rejection (rebuild against the new
  branch, no resubmit-loop), recorded alongside the §6
  wallet-claim-builder row's forward obligation.
- **R2-4 (claim-era wire retirement interaction):** **closed at
  source.** `2615c0d` (dev) retired the claim-era confidential-
  staking system (`txin_stake_claim`/`txout_to_staked_key`, stake-
  ratio cache, staker accrual → `block_burn`); its scope statement
  itself pins genesis staking as archival bonds plus the 2b
  reward-emission leg, and names the reward-emission C-1 cutover as
  the redirect point for the burned staker inflow. The archival
  close/emission path (this spec's entire surface) shares no wire
  type, no LMDB table, and no consensus path with the retired
  system; this branch is cut from a dev head containing the
  retirement, and every source line this round verified post-dates
  it. No adjustment to the non-claimability rule needed.

### 11.7 Net

Rounds 1–2's closures on the vin path, store semantics, zeroing
locus, and sentinel are untouched. Round 3 re-anchored the gate
input (the one operand the earlier rounds never walked to its
production site), converted the substrate claims into named
cross-round obligations, and closed the residual watch items. The
design is closed from a specification standpoint; implementation
remains conditioned on §1.3.

### 11.8 Round-3 amendment (post-closure pin, not a fourth round)

The round-3 closure review (two reviewers, tip `eaeddb84f`) accepted
the round's core in full and surfaced three findings against the
surface round 3 itself created — the count pass. All three are this
spec's own doctrine (§11.1's pattern: the operand's production site
deserves the same protection as the predicate's) applied to the new
site; none touches the design's shape. Per the design-round closure
discipline (`21-reversion-clause-discipline.mdc` — a
substrate-completeness amendment is not a new round), they are folded
in as an amendment:

- **M3-1 (medium, accepted)** — the count pass was a new load-bearing
  production site with no structural guard: the §6 tripwire covered
  only `K_COVER` comparisons, nothing exercised the C++ filter, and
  G-10 structurally cannot (it injects `frozen_shard_count`). Fixed:
  §1.1 count-pass discipline names the single helper
  (`count_frozen_shards_at_close`, one call site), the §6 tripwire
  extends to refuse any other counting read over
  `m_archival_shard_segment`, and §5 gains the C++ filter-boundary
  case (below/equal/above `H_close(E)`; **equality counts**, per
  `≤`). The named drift adversaries: a second count site with a
  divergent filter (RPC corpus-size surface, verification-path
  recount, cached counter lacking O-3 pop-symmetry), and an
  off-by-one edit to the filter itself. Wording sweep folded in:
  G-1..G-3 rebound from the old `shard_count` name to
  `frozen_shard_count` — fixture authors bind names.
- **M3-2 (medium, accepted)** — count-pass decode-failure semantics
  were unpinned, and the failure mode is a consensus divergence in
  the gating direction (lenient-skip node counts low and gates;
  strict node aborts). Fixed: §1.1 pins decode failure as a loud
  abort, same class as the gather's FATAL; §5 gains the
  malformed-row case arming it.
- **M3-3 (low, accepted)** — the re-anchor moved the gate input
  further from directly measuring cohort thickness, pushing the
  entire proxy burden into the `K_COVER` derivation; if the WI-4
  §14.4 calibration derives against a served/participation quantity,
  it reintroduces at constant-derivation time exactly the sensor the
  gate input shed. Fixed: named pre-flight item 2 in §6, verifiable
  once WI-4 merges per the Provenance ordering pin.

### 11.9 Implementation gates decided (spec → implementation handoff)

Three gates, all from the spec's own text, decided at the handoff
rather than left open for the implementer to re-derive:

1. **The §1.3 fork: second branch taken.** Gate implements now on
   fixture-written rows; O-1..O-3 blocking on the pipeline round.
   The decision was wargamed, not defaulted — the invalidation
   surface a future pipeline round could expose against fixture-built
   gate work is enumerated in §1.3's decision block, and it is small
   because the count helper binds to the `LMDB_SCHEMA.md`-fixed
   table schema, not to pipeline behavior. The dangerous obligation
   (O-3) is chain-wide, so serializing the gate behind it buys
   almost nothing while delaying the item the spec ranks first
   because it cannot be patched after seal. Condition attached: the
   pipeline round **opens before the gate PR merges**, keeping the
   reopen path cheap.
2. **The audit pin is the dev head at pre-flight time** — not
   `69af41a`, the head the rounds happened to verify against. The
   §6 pre-flight block names what re-verifies: the enumeration
   (single `epoch_close_compute` call site, gather anchors, no new
   sigma/`r_market` readers) plus the three named items, with the
   M3-3 calibration check running against WI-4 once mergeable. The
   §11.1 pattern applies to the pass itself.
3. **WI-4 merge ordering gets an explicit sequence slot** (§6
   implementation sequence, step 0) — the Provenance pin ("before or
   with the implementation PR") is otherwise aspirational, and the
   provenance dangles on `dev` exactly as the round-2 sweep
   experienced.

**Intra-PR ordering pinned** (§6 implementation sequence, steps
1–5), with the load-bearing one first: constants plumbing +
compile-refusal land before the `k_cover` identifier exists anywhere
else in the tree — the refusal is armed before there is anything for
it to guard, closing the window where a plausible provisional value
is loose with no trigger. Then helper + threading, wire positivity +
corpus fix (same commit), KATs + C++ store tests, tripwire scripts
last (they grep for final site names).

### 11.10 Pre-flight pass + implementation record (2026-07-06)

**Pre-flight pass (§11.9 gate 2).** Run at the dev head at pre-flight
time — which was still `69af41a5a`; PRs #261 (RandomX differential)
and #262 (WI-4 measurement doc) merged to `dev` mid-arc, ~30 minutes
after step 1 landed. The §6 enumeration held: single
`epoch_close_compute` call site (the FFI shim), gather anchors
unchanged, no new sigma/`r_market` readers. Re-verified at the docs
step against `dev` = `1e89df832`: the mid-arc merges touch only
docs, simulation crates, and RandomX parity tests — zero hits on
`epoch_close_compute`/sigma/`r_market`/`m_archival_shard_segment`.
The three named items:

- **Lagged-read clause (R2-1):** §2.2 sourcing unchanged at both pins.
- **Stored-close readers (R2-2):** no new production reader; the two
  test-support additions are recorded in the §11.6 amendment.
- **M3-3 (K_COVER calibration input): discharged.** WI-4 merged to
  `dev` (#262, `1e89df832`) — sequence slot 0 (§11.9 gate 3)
  **satisfied** before the implementation PR opens. Checked against
  the merged text: WI-4 §16.3 pins `shard_count` as "structural,
  monotonic, and coincides with height. No live-participant estimate
  is ever read," and the §16.2 derivation chain anchors `K_COVER` on
  the cover-thickness model over segment count, not any
  served/participation quantity. The calibration does not
  reintroduce the sensor the round-3 re-anchor removed.

**Steps 1–5, executed in the §11.9 pinned order** (branch
`feat/m1-reward-gate-design`):

| Step | Commit(s) | Delivered |
| --- | --- | --- |
| 1. Constants + compile refusal | `a2292b23c`, `6194ab7a7` | `k_cover` + `k_cover_provisional` in `consensus_constants.json`; `build.rs` validation; generated `k_cover.rs` with `compile_error!` absent the `provisional-k-cover` feature — armed before the identifier existed anywhere else |
| 2. Helper + threading | `f65d3d89d` | `count_frozen_shards_at_close(h_close)` (`db_lmdb.cpp`, one production call site in the close gather); FFI `frozen_shard_count` param; `EpochCloseInputs::{frozen_shard_count, k_cover}`; zero-at-top gate factor in `epoch_close_compute` |
| 3. Wire positivity + corpus fix | `cc28bee37` | `WireError::RewardAmountZero` at both `validate()` and `read_payload()` (zero unencodable *and* undecodable); `EMISSION_AUTH_MSG_V1` corpus zero-amount row replaced, four pinned digests regenerated (same commit, §2.3) |
| 4. KATs + store tests | `e0a0cfd11` | `reward_gate_kat.rs` + fixture, G-1..G-10; C++ cases: filter boundary (below/equal/above, equality counts), malformed-row loud abort, txn precondition, zero-output stored shape + reorg round-trip |
| 5. Tripwires | `31f133e5e` | `check_reward_gate_predicate_sites.sh` wired as invariant 5 of `check_consensus_invariants.sh`: single `K_COVER` comparison site (+ constants surface), single counting read over `m_archival_shard_segment` (`mdb_stat` refused outright), `≤` boundary operator pinned with strict-`<` refused, positive controls guarding the guards |

**Implementation-time deltas from the spec text** (each within the
rounds' dispositions; none touches the design's shape):

1. **Sentinel refined to gate-identity `0` (`6194ab7a7`).** §4's
   provisional value landed first as fail-closed `u64::MAX`, which
   gated every close and de-exercised the store-write paths across
   the existing C++ corpus — a vacuous-green inversion (the tests go
   red, so the paths go untested). Refined to `0`:
   `frozen_shard_count < 0` is never true, so pre-seal behavior is
   exactly pre-gate behavior and the corpus stays live end-to-end.
   `build.rs` enforces provisional ⇔ `0` and sealed ⇒ `≥ 1`;
   `k_cover.rs` carries the matching `const` assert. The shipping
   guard is unchanged — the compile refusal, never the sentinel's
   runtime semantics (§4's own hierarchy).
2. **`k_cover` as an `EpochCloseInputs` field.** Consequence of (1):
   with the sentinel at `0` the gated branch is unreachable through
   the constant, so the KATs inject `k_cover` per-case. The
   production FFI threads the constant verbatim (`k_cover: K_COVER`)
   — a tripwire positive control pins that exact spelling, so the
   parameterization cannot silently become a second value source.
3. **Test-support store surface.** Two additions, recorded in the
   §11.6 R2-2 amendment: `has_archival_sigma_work_row` (stored-shape
   probe past the NOTFOUND launder) and
   `put_archival_shard_segment_raw_for_corruption_test` (raw writer
   arming the M3-2 abort, unreachable through `encode()`).
4. **Gated-close stored shape tested via a legitimately-empty
   epoch.** With the provisional `0`, no C++ test can drive the gate
   branch through production code. Per §2.1 the store cannot
   represent gatedness — a gated close and a legitimately-zero close
   are bitwise-identical by construction — so the stored-shape and
   reorg round-trip cases (G-6/G-9's C++ side) assert the identical
   zero-output shape (sigma present-and-zero, no `r_market` rows,
   close-log row written, revert/re-apply bit-identical) via an
   empty-credit epoch. **Forward item, named:** when `K_COVER` seals
   `≥ 1`, add the direct gated-path close test (drive
   `frozen_shard_count < K_COVER` through the gather) — carried in
   `docs/FOLLOWUPS.md` with the sealing entry.

**Outstanding before the gate PR merges** (unchanged from §11.9):
the segment-freeze pipeline design round **opens** (§1.3 condition;
`docs/FOLLOWUPS.md` entry); `K_COVER` sealing remains gated on the
WI-4 §14.4 partition run and is not blocked by (and does not block)
the PR itself — the compile refusal holds the seam.

---

## 12. Cross-references

- `ARCHIVAL_BOND_WI4_MEASUREMENT.md` §14 (launch posture), §16.1
  (partition trap), §16.2 (M1 pre-flight pin and its three
  obligations), §17.2–§17.3 (dynamic cover-model rows), §13.5
  (sealing conditions).
- `ARCHIVAL_CONSENSUS_STATE.md` §3.3, §3.5 (the computation the gate
  factors into).
- `REWARD_EMISSION_LEG.md` §4–§5 (the zero-tolerance compare the gate
  is inherited by).
- `26-sub-pr-design-discipline.mdc` (process frame; pre-flight pass
  before production commits).
- `07-consensus-atomic-cutovers.mdc` (surface-enumeration evidence
  discipline; exception not invoked at spec time).
