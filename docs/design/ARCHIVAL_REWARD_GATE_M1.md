# M1 — Reward eligibility gated on shard count (consensus rule)

**Status: design round 1 — specification for review. No code lands until
this round closes.** Per `05-system-thinking.mdc` (specification first)
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

### 2.3 Gated epochs are non-claimable (spec decision, round 1)

A claim batching gated epochs at amount zero would pass the §2.2
compare while carrying zero economic content — a pure timing signal
(the claim's existence and cadence) with no reward attached, in
exactly the window where claim-cohort thinness is the co-hazard the
gate refuses (WI-4 §16.2 "Verified synergy"). The disposition, in the
make-bad-states-unrepresentable shape: **an emission's
`settlement_epochs` must not include a gated epoch.** Validation
rejects the vin (structural error, same class as
`FloorMismatch`), rather than accepting a zero row.

Consequences to check at review: the claim-window arithmetic
(`max_claim_age_w = 26`) never forces a claimant to include a gated
epoch — it cannot, because gated epochs produce nothing to claim and
the window constrains only epochs actually claimed. The batching
bound (`max_settlement_epochs_per_emission = 15`) is unaffected.

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
the constant's finalization as a blocker. The machinery reading a
provisional constant is testable end-to-end (the KAT parameterizes
`K_COVER`, §5); shipping genesis with the sentinel is refused by the
checklist, not by code.

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
| G-5 | §2.3 — emission vin including a gated epoch | rejected structurally (not a zero-amount pass) |

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
| Constant | `config/consensus_constants.json` + `rust/shekyl-archival-retention/build.rs` (or the crate's constants surface, `src/constants.rs`) | `k_cover` entry, provisional-sentinel comment, generated-constant plumbing per the file's existing C++/Rust generation contract |
| Emission validation | `rust/shekyl-archival-retention/src/emission_wire.rs` | §2.3 non-claimable check (structural reject of gated epochs in `settlement_epochs`) |
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

## 8. Round-1 review questions

The questions this round must answer before closure (each is a
disposition to record, not an open musing):

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

## 9. Cross-references

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
