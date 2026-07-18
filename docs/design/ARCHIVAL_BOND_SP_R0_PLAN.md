# Bond-PR SP-R0 — the done-side reconcile GC (Round 0 scoping)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
§3.6. SP-R0 is the reconcile-GC half of 2d-2, consuming the 2d-1
[`PReconcileSet`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) (SP-6) evidence. This doc is the
architecture round for that GC; it **consolidates** design already pinned across
[`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) (SP-6, the
trust-anchor resolution, the records-driven-retirement done-side ledger),
[`ARCHIVAL_GF4B_BACKING_LINEAGE.md`](ARCHIVAL_GF4B_BACKING_LINEAGE.md) §3.2 (the
`SpentRecordsDurablyPruned` witness gate), [`ARCHIVAL_BOND_WI2_ASSEMBLY.md`](ARCHIVAL_BOND_WI2_ASSEMBLY.md)
§3.2/§3.4 (the sweep + the deferred key-image watch), and
[`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) §14 (the
SP-R0 transport pins). It does **not** restate those; it cites them and designs the
one genuinely-new piece (the key-image-watch funding prune) and the build order.

**Status:** ROUND 0 (scoping) — for review; no code. **Process rule:**
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(firewall-load-bearing: an over-eager GC drops live collateral / strands live funds,
so the confirmed-absence discipline is decided first and the rest derives from it).

**Priority note (`00-mission`).** SP-R0's funding arm is **V3.0 pre-genesis** (the
assemble path is genesis-live, D-3; FOLLOWUPS "if WI-2 assemble must be live at
genesis, this item is pulled into the V3.0 pre-genesis queue"), and arm #3 was already
V3.0 at source (`FOLLOWUPS.md:2013` — "must land before genesis freezes the absence of
GC"). Genesis freezes *the absence of GC*, so the reconcile discipline must be right
before launch. **But "before genesis" is a floor, not a licence to land first** — see
§0 F-1 and DQ-F: an SP-R0 arm that compiles green and never fires in production is
strictly worse than an unlanded one, because its reopen line reads discharged.

---

## 0. Why this is a real round (what grounding the code changed)

The [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) reads SP-R0 as "mint the
witness." Source verification at `dev = 40805d7d0` changed the shape:

1. **Spent-ness is not derivable from anything persisted today.** The P-scan records
   `bond_post_matches` as `(height, p_canonical_id, post_kind)` only — no key image,
   no link from a confirmed post to the `gindex`es it consumed (`pscan/scan_step.rs`
   arm (b); `pscan_state.rs` `BondPostRecord`). `PReconcileSet` answers *"did persona X
   post within `covered`?"* (presence-of-persona), never *"which output was spent."* So
   SP-R0 must **detect the spend** — new scan machinery, not a filter of existing data.
2. **`funding_outputs` is append-only end to end.** `PScanAccrual::ingest` only
   `extend`s; nothing removes on confirmed spend. This is the poison the witness guards:
   under sweep semantics one stale confirmed-spent record is in *every* later sweep
   (GF4b §3.2).
3. **SP-6 is built.** `PReconcileSet` (`reconcile.rs:67`) + `VerifiedRange`
   (`exhaustiveness.rs:64`) exist on `dev`, both `#[allow(dead_code)]` "consumer is 2d-2
   SP-R0." The FOLLOWUPS "SP-6 unbuilt, 0 files, 2026-06-28" gate note (`FOLLOWUPS.md:8338`)
   is **stale** — a fourth stale-gate instance, and it is mis-homed in V3.x. Correct it.
4. **The key-image primitive is built.** `stake_engine.rs:1876`
   (`key_image = biased_hash_to_point(output_key) * x_scalar`) /
   `crypto-pq/output.rs:1245 compute_output_key_image`. So arm #1's new machinery is
   **watch + prune-at-ingest + witness mint**, not the derivation.

### F-1 (spine) — the persona stack is production-inert at genesis; the front is the activation driver

`start_pscan`/`start_pscan_if_staker` are the scan driver; `spawn_stake_engine_if_staker`
(`lifecycle.rs:779`, wired into production open) is the derivation driver. Both are
**staker-gated**, and at source **nothing in production sets `staking_enabled`**:
`persist_bond_record` (`stake_persist.rs:147`, the sole setter) has **zero production
callers** (all `#[cfg(test)]`/`regtest_e2e`), and **no stake/bond RPC exists** in
`shekyl-wallet-rpc`. So in production: no staker → no StakeEngine → no personas derived
→ no scan → no bond posts. The scan driver WI-1 adds (`shekyl-wallet-rpc/src/lifecycle.rs`,
PR #329, not yet on `dev`) is **necessary but dormant** until a staker can exist.

**Consequence for this round:** the genesis front is the **production staker-activation
path** — the `(b) RPC stake entry` co-gate the FOLLOWUPS rule-21 witness note already
names — *not* any SP-R0 arm. Until it lands, arm #1's watch, arm #2's reconcile, and
arm #3's phantom-slot GC are all inert (they reconcile state that production never
produces). "Persona scanning lands" (arm #3's reopen trigger) is satisfied in the
*code-exists* sense and **false in the runs-in-prod sense**; landing arm #3 against
that premise freezes a non-firing GC and reads its reopen line as discharged — the
`pscan/mod.rs:28` fossil, one document over. Build order and per-arm close conditions
(§5 DQ-C/DQ-F) are written around this.

---

## 1. The landed substrate SP-R0 sits on

- **The witness + its five consumers.** `SpentRecordsDurablyPruned` (`bond_assembly.rs`,
  zero production constructors; `#[cfg(test)] for_test()` only) gates
  `sweep_funding_outputs`, and transitively `BackingSet` fee-sweep,
  `BondOrchestrator::assemble_bond_post`, the claim orchestrator, and the CB-3
  claim-dispatch seam. The self-parsing tripwire asserts no production constructor.
  SP-R0 arm #1 (D-1) is "add the sole production mint."
- **SP-6 evidence.** `PReconcileSet { covered: VerifiedRange, matched_posts }`, `covered`
  = **exhaustiveness only** (2d1 plan SP-6 type + "Trust-anchor resolution"): GC a slot
  only if height ∈ `covered` and no matched post claims it — never inferred from absence.
- **The done-side ledger, already designed.** 2d1 plan "Records-driven retirement"
  formalizes `pending_unbonds` (PR-B) + SP-6's durable removal into one **authoritative
  done-side ledger in `PScanState`** (retired-records + high-water mark), with
  `StakingBlock.bonded_slots` staying the **live hint**; `spawn_stake_engine_if_staker`
  subtracts retired slots from the derive-forward set. SP-R0 arm #2 **implements** this;
  it does not reopen the frozen hint-not-truth decision.
- **Canonicity, already resolved.** `VerifiedRange` = exhaustiveness only; the
  irreversible `bonded_slots` GC consumes `VerifiedRange` **plus a canonicity token**;
  the **funding view inherits daemon-trust** (a fork there is *recoverable*, like the
  principal's refresh) — no wallet-side PoW (Trust-anchor resolution, 2026-06-29).

---

## 2. Locked decisions (Round-0 ratified with the maintainer, 2026-07-18)

- **D-1 — Disposition (a): durable prune.** Detect spent funding outputs, remove them,
  and **add the sole production constructor** of `SpentRecordsDurablyPruned` (witness
  stays). Rejected (b) reservation retention: unbounded state growth over a long-lived
  staker (`00-mission` priority 3).
- **D-2 — Spend-detection: key-image watch, prune at ingest.** The scan matches each tx
  input's key image against the key images of P's held `funding_outputs` and removes a
  record the moment the spending block is ingested (already ≥ `ARCHIVAL_REORG_DEPTH_BLOCKS`
  = 720 deep, §4). **No `PSCAN_STATE_VERSION` bump.** Justification (airtight form):
  `funding_outputs` stays a postcard `Seq` (element removal is wire-identical), **and**
  pre-genesis every wallet fresh-syncs from block 0 with the watch on — so there is no
  pre-watch record for absence-as-evidence to miss (the "nothing persisted" argument
  alone leaves an upgrade-mid-life gap this closes). Rejected own-post→gindex linkage:
  common-case only (misses external / second-instance spends — WI2 §3.4's deferred case)
  and needs a persisted map (a 6→7 bump).
- **D-3 — Genesis-live.** The assemble path is required live at genesis → SP-R0's funding
  arm is V3.0 pre-genesis (subject to F-1: "before genesis" ≠ "first").

---

## 3. Decomposition — three arms + the activation front

The three arms share the reconcile pass and the atomic prune-on-retire step but touch
different persisted structures **and have different real gates** (rule 19 applied to the
dependency graph, not just the validation surface):

| Arm | GC | Structure | Real gate | Canonicity | Unblocks |
|-----|----|-----------|-----------|------------|----------|
| **#1** | Spent `funding_outputs` prune (key-image watch) → **mint the witness** | `PScanState` (v6) | the watch/prune/witness machinery (**not SP-6**; derivation exists, §0.4) | inherited — 720-block ingest ceiling (§4); **no token** | assemble go-live (the 5 witness consumers) |
| **#2** | Phantom `bonded_slots`/`p_slot` GC (done-side ledger; retired-records + subtract-at-derive) | `PScanState` retired-records + `StakingBlock` hint | **SP-6** (built) + an explicit **canonicity token** (open) | required; records-driven so token = corroboration | correct derive-forward set |
| **#3** | `bonded_slots`/`p_slot` **wallet-local full-scan** phantom drop | `StakingBlock` (hint) | **none in code** (no SP-6); **live-gated** on the activation driver (F-1) | inherited — recoverable | correct monotone cursor |
| **front** | — production **staker-activation** path (`(b) RPC stake entry`) — *not an SP-R0 arm* | — | — | — | **every arm's production effect** |

**Prune-on-retire is atomic** (correctness, not optional; transport plan §14): on retire,
one seal drops a persona's `funding_outputs`, `bond_post_matches`, `pending_unbonds`, and
writes its retired-record — else `bond_post_matches` grows unbounded. Shared plumbing
across #1 and #2.

---

## 4. The new design — arm #1, key-image-watch funding prune

The piece the docs deferred (WI2 §3.4: "external-spend detection (key-image watch) is 2d-2
full-scan reconcile scope"). Everything else in §3 formalizes already-sketched design.

**The shape.** Today's dual extractor runs (a) view-key funding recovery + (b) cleartext
bond-post detection (`pscan/scan_step.rs`). Arm #1 adds a **third arm (c): spent-key-image
match** over each scanned tx's `prefix.inputs`, against a watch-set of the key images of
P's held `funding_outputs`. A hit removes that record from the in-memory accrual before the
next seal.

**Canonicity is inherited, not invented (F-3).** The pscan ingest ceiling already trails
tip by `ARCHIVAL_REORG_DEPTH_BLOCKS` = 720 (`start.rs:93`, `dispatch.rs:186-206`), so
anything ingested is already ≥720 deep: **prune-at-ingest is prune-when-already-buried.** A
spent key image is a **presence** event (SP-6's positive-confirmation discipline), and the
funding view is recoverable on a deep reorg exactly as the principal's balance is (Trust-anchor
scope-limiter; funding-side analog at `cover_discovery.rs:123`). So arm #1 needs **no
canonicity token** and does not consume SP-6 — it needs its watch to run on the ceiling-trailed
pass, which is a source check on the existing horizon, not a new primitive. The token
(`min(claimed_tip, verified_frontier + reorg_depth)`, the WI-3 reserve) belongs to arm #2 only.

---

## 5. Design questions to resolve in this round (proposed dispositions — ratify or redirect)

### DQ-A — where the key image is derived, without widening the secret surface (DQ1/DQ5)

A key image needs the output's one-time **spend** key (not just `view_sk`), in the persona
secret domain (`ArchivalPKeys`, StakeEngine vault); the offloaded scan-step must not gain
spend-key material. **Proposed (A1):** the actor derives key images of P's held funding
outputs **in-actor** (the built primitive, §0.4) and hands the offloaded scan-step an opaque
**public** watch-set of key images (a key image is a public on-chain value once derived);
arm (c) matches inputs against that public set. Secret never crosses the boundary. Cache by
`gindex` (stable), derive-on-add / drop-on-prune, no persistence (re-derivable at open).

### DQ-B — prune-at-ingest vs prune-at-seal

**Proposed (B1):** prune-at-ingest (drop from the in-memory accrual the moment arm (c)
matches; already behind the 720 ceiling). Absence from the next seal is the durable record
→ no marker, no bump (D-2). Confirm B1.

### DQ-C — sequencing (rewritten after F-1)

The genesis front is the **production staker-activation path** (`(b) RPC stake entry`), a
distinct co-gate, **not** an SP-R0 arm. Until it lands, all three arms are production-inert.
**Proposed (C1):** activation-driver **first** (its own work item); then arm #1 (funding
prune + witness — unblocks assemble); then arm #2 (transport GC + token) and arm #3
(StakingBlock phantom GC), each landing only when it can be shown to **fire** in a
prod-representative path (DQ-F). Arm #3's "buildable now, land first" framing is retracted:
buildable ≠ firing, and freezing a non-firing V3.0 GC is worse than not landing it.

*Open:* does the activation path itself create `bonded_slots` (via `persist_bond_record`)
before a full post? If so, arm #3's phantoms arise from activation and #3 sequences right
behind the front; if not, #3 waits on the assemble path (arm #1). Pin against the RPC-stake-
entry design when it exists.

### DQ-D — per-arm canonicity (rewritten after F-3)

**Proposed (D1):** arm #1 — no token; inherits the 720 ceiling (§4). arm #2 — the canonicity
token, sourced from the 2d-2 sweep-corroborated tip clamp
`min(claimed_tip, verified_frontier + reorg_depth)`, and there as **corroboration**
(records-driven retirement), not trigger. arm #3 — inherited (recoverable). Confirm the token
is an arm-#2-only concern; do **not** generalize the clamp across arms.

### DQ-E — `anchor_t0` enrollment (moved after F-4)

`anchor_t0` is an **assemble-time** consumer of the untrusted tip → the transport/assemble
tip discipline, which is **arm #2's** surface, not arm #1's. **Proposed (E1):** enroll it in
arm #2's tip clamp; note here so the 2d-2 clamp work picks it up.

### DQ-F — fossil-trap disposition: never mark a non-firing GC discharged

**Proposed (F1):** each SP-R0 arm's FOLLOWUPS reopen line closes **only** when a
prod-representative test drives the arm through the activation driver and observes the GC
**fire** (a real phantom collected / a real spent record pruned) — not when the code lands
green against test-only staker construction. Until then the line stays open with an explicit
"lands inert; fires-in-prod pending activation driver" status. This is the direct counter to
the `pscan/mod.rs:28` / WI-1 fossil class.

---

## 6. FOLLOWUPS / doc obligations that ride with this round

- **[front, distinct work item]** the production **staker-activation path** (`(b) RPC stake
  entry`) — the genesis prerequisite F-1 surfaces; without it every SP-R0 arm is inert.
- **[close on landing — with the DQ-F fire condition]** FOLLOWUPS "2d-1 WI-2 durable removal
  of SPENT funding outputs" (#1), "2d-2 SP-R0 reconcile GC" (#2), "2d full-scan reconciliation
  of bonded_slots/p_slot" (#3, V3.0 `FOLLOWUPS.md:2013`).
- **[correct now]** the stale "SP-6 unbuilt, 0 files, 2026-06-28" note (`FOLLOWUPS.md:8338`,
  and its V3.x home) and the `IMPLEMENTATION_INDEX.md` SP-R0 status lines.
- **[carry]** GF4b §5 item 4 (witness zero-production-constructors → arm #1 adds the one) and
  item 5 (assemble change-split / tx-size bound); the GF4b-5 structural gate closes when arm
  #1 mints the witness.
- **[carry]** the rule-21 `#[allow(dead_code)]` on the five consumers: **(a) SP-R0 pruning AND
  (b) RPC stake entry** — neither retires alone; arm #1 retires (a) only.
- **[enroll]** `anchor_t0` in arm #2's 2d-2 tip clamp (DQ-E).

---

## 7. Round-0 exit

Round 0 closes when DQ-A…DQ-F are ratified. Then: correct the stale status lines, register
the arms as index rows (rule 94; SP-R0 identifier exists), and implement in the §5 C1 order
— **activation driver first**, each arm gated on the DQ-F fire condition.
