# M1 — Reward eligibility gated on shard count (consensus rule)

**Status: design round 1 closed (§9 record). Spec amended in place per
the round's dispositions; implementation may proceed after the
pre-flight pass.** Per `05-system-thinking.mdc` (specification first)
and `26-sub-pr-design-discipline.mdc` (cited: consensus-critical sub-PR
with design rounds before implementation; the pre-flight pass applies
between this round's closure and the first production commit).

**Provenance.** This document is the design round that
`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §16.2 pins as required — that section
is the pre-flight pin, this is the spec. The launch-posture context
(founder cover, cold-start refusal, the partition trap) lives in WI-4
§14–§16 and is not restated here; this doc owns the consensus rule.

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

### 1.1 The gate input, defined

`shard_count(E)` = the number of archival shards with a **frozen
segment** at `H_close(E)` — concretely, the count of
`EpochCloseShard { has_segment: true, .. }` rows in the epoch-close
gather (`rust/shekyl-archival-retention/src/consensus_state.rs`,
`EpochCloseInputs::shards`).

Substrate properties, verified at source (WI-4 §16.2 "Substrate"):
shards are frozen chain segments (`freeze_height`), so `shard_count`
is a **deterministic, monotone function of chain height**. No actor
can inflate it (that requires mining the chain forward) and no actor
can stall it (chain growth freezes segments). Cumulative-bond-count
was evaluated and **rejected** as the gate input: sybil-inflatable
whenever cost-to-post is low.

### 1.2 The gate predicate

```text
gated(E)  ⇔  shard_count(E) < K_COVER
```

Both operands are consensus facts every verifier derives identically:
`shard_count(E)` from the shard set at `H_close(E)`, `K_COVER` from
`config/consensus_constants.json` (§4). There is no sensor, no
estimate, and no live-participant measurement anywhere in the
predicate — the flood-then-withdraw liveness DoS (keep a measured
cover below the bar) has no sensor to attack (WI-4 §16.3 / M2,
resolved into this rule).

---

## 2. Enforcement locus: one canonical computation, one inherited check

The rule is enforced at **exactly one canonical point**, and every
other consumer inherits it by recomputation — never by a parallel
reimplementation of the predicate.

### 2.1 Canonical: the epoch-close computation

`epoch_close_compute` (`consensus_state.rs`) gains the gate as a
uniform factor at the **top** of the computation:

```text
if shard_count(E) < K_COVER:
    R_market(s, E) = 0   for every shard s
    work_P(E)      = 0   for every bond P
    Σwork(E)       = 0
```

Equivalently: a gated epoch's `EpochCloseResult` is
`{ r_market_by_shard: [0; n], sigma_work_milli: 0 }`. Zeroing at the
top (rather than zeroing only `reward_share_floor`) is deliberate: it
guarantees **no consensus quantity derived from a gated epoch is ever
non-zero** — not `R_market`, not per-`P` work, not `Σwork` — so no
downstream consumer can accidentally re-derive value from a gated
epoch's intermediate state (the §3 invariant, enforced structurally
rather than at each consumer).

### 2.2 Inherited: emission verification

The emission vin's `reward_amount_plain` is compared against the
verifier's ex-ante recomputation at **zero tolerance**
(`REWARD_EMISSION_LEG.md` §5.4/§5.5;
`rust/shekyl-archival-retention/src/emission_wire.rs`). Because the
recomputation flows through §2.1's canonical gate, a vin claiming any
non-zero amount for a gated epoch fails the existing compare with **no
new validation branch**. The gate adds no second predicate site.

### 2.3 Zero-share epochs are non-claimable (spec decision, amended at round-1 closure)

A claim batching gated epochs at amount zero would pass the §2.2
compare while carrying zero economic content — a pure timing signal
(the claim's existence and cadence) with no reward attached, in
exactly the window where claim-cohort thinness is the co-hazard the
gate refuses (WI-4 §16.2 "Verified synergy").

**The rule (uniform, not gate-specific — amended per §9 R1-D2):**
**every epoch in an emission's `settlement_epochs` must have a
strictly positive recomputed reward share.** Validation rejects the
vin (structural error, same class as `FloorMismatch`) when any
claimed epoch's ex-ante recomputation yields zero.

The round-1 draft stated this as "must not include a *gated* epoch,"
which would have required the vin path to consult the gate predicate
directly. The uniform positive-share form is strictly better on
three counts, each verified at source during the round (§9):

1. **The vin never learns about `K_COVER`.** Zero-at-top (§2.1) makes
   gated epochs zero-share; the positive-share rule then makes them
   non-claimable through pure data flow. One predicate site (§2.1),
   no parallel gate check to drift.
2. **It closes a pre-existing hole the gate-specific form missed.**
   `Σwork(E) = 0` is already a legitimate pre-gate state — an epoch
   with no serve credits stores a genuine zero, and
   `reward_share_floor` already returns 0 on a zero normalizer
   (`reward_arithmetic.rs`). Under the draft rule, a zero-amount
   claim row for a legitimately-empty epoch (`0 == 0` passes the
   §2.2 compare) remained representable. Under the uniform rule,
   zero-amount claim rows are unrepresentable everywhere — gated,
   empty, or slashed-to-zero alike.
3. **The wallet-side builder needs no second predicate** (§9 R1-Q2
   disposition). The claim builder must already recompute expected
   shares from public state to satisfy the zero-tolerance compare;
   "skip zero-share epochs" is the same computation on the same
   data, not a separate eligibility check that can drift from the
   consensus rule.

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
implementation detail.

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

| Case | `shard_count` | Expected |
| --- | --- | --- |
| G-1 | `K_COVER − 1` | `Σwork = 0`, all `R_market = 0`, `reward_P = 0` for every `P` — provably zero |
| G-2 | `K_COVER` | non-zero accrual for a credited member — provably non-zero, and equal to the ungated computation's output (the gate at/above threshold is the identity) |
| G-3 | boundary epoch — the first `E` with `shard_count(E) ≥ K_COVER` | first non-zero accrual lands at exactly this `E`; the prior epoch's is zero |
| G-4 | genesis edge — `chain_epochs == 0` | gate composes with the `shard_age_milli` zero without masking or double-zeroing; result is well-defined zero |
| G-5 | §2.3 — emission vin claiming a zero-share epoch (gated case *and* the legitimately-empty case, per the uniform rule) | rejected structurally (not a zero-amount pass) |

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
| Canonical gate | `rust/shekyl-archival-retention/src/consensus_state.rs` (`epoch_close_compute`, `EpochCloseInputs`) | Gate factor at top of compute; `K_COVER` threading |
| Constant | `config/consensus_constants.json` + `rust/shekyl-archival-retention/build.rs` (or the crate's constants surface, `src/constants.rs`) | `k_cover` entry + `k_cover_provisional` flag, compile-refusal plumbing (§4 sentinel mechanics), generated-constant contract per the file's existing C++/Rust generation |
| Emission validation | the PR-E3 verify path (`REWARD_EMISSION_VIN_PLAN.md`; the recompute site, not `emission_wire.rs` — the wire layer stays share-agnostic) | §2.3 uniform positive-share check (structural reject of any claimed epoch whose recomputed share is zero) |
| Wallet claim builder | future engine-side emission assembly (does not exist yet — verified at round 1, no `build_emission`/claim-builder site in `rust/`) | **Forward obligation, pinned here:** the builder derives claimable epochs from the same positive-share recompute; carried as a spec requirement into the builder's own design round |
| KAT | `rust/shekyl-archival-retention/tests/` + `fixtures/reward_gate_kat_v1.json` | §5 cases G-1..G-5 |
| CI | `scripts/ci/check_archival_reward_gates.sh` | KAT wired into the existing gate-check shape |
| FFI/daemon | `shekyl-ffi` epoch-close entry point (consumer of `epoch_close_compute`) | **Expected zero-change** — the gate lives inside the canonical computation; verify at pre-flight, not assume |
| Docs | `ARCHIVAL_CONSENSUS_STATE.md`, `REWARD_EMISSION_LEG.md`, `docs/FOLLOWUPS.md`, `docs/CHANGELOG.md`, `docs/design/IMPLEMENTATION_INDEX.md` | Gate section + cross-references |

Pre-flight (per `26-sub-pr-design-discipline.mdc`) re-checks this
enumeration against the substrate at the audit pin before the first
production commit; growth beyond it during implementation is scope
creep and reopens the round.

---

## 7. Dead-rule note, named residuals, reversion clause

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

## 10. Cross-references

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
