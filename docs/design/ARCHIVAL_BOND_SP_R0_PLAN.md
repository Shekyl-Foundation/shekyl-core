# Bond-PR SP-R0 — the done-side reconcile GC (Round 0 scoping)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
§3.6. SP-R0 is the reconcile-GC half of 2d-2, consuming the 2d-1
[`PReconcileSet`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) (SP-6) evidence. This doc **consolidates**
design already pinned across [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md)
(SP-6, the trust-anchor resolution, the records-driven-retirement ledger),
[`ARCHIVAL_GF4B_BACKING_LINEAGE.md`](ARCHIVAL_GF4B_BACKING_LINEAGE.md) §3.2 (the
`SpentRecordsDurablyPruned` witness gate), [`ARCHIVAL_BOND_WI2_ASSEMBLY.md`](ARCHIVAL_BOND_WI2_ASSEMBLY.md)
§3.2/§3.4 (the sweep + the deferred key-image watch), and
[`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) §14 (the SP-R0
transport pins). It cites those and designs the one genuinely-new piece (the key-image-watch
funding prune) and the build order.

**The genesis front is NOT in this doc.** SP-R0's arms are all production-inert until the
**production staker-activation path** lands (§0 F-1); that path is its own round —
[`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md) — and SP-R0's
arm-landing sequences behind it via the DQ-F fire condition.

**Status:** ROUND 0 — DQ-A…DQ-F **ratified 2026-07-18** (dispositions inline in §5).
Round-0 exit tasks in §7. **Process rule:**
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(firewall-load-bearing: an over-eager GC drops live collateral / strands live funds).

**Priority note (`00-mission`).** SP-R0's funding arm is **V3.0 pre-genesis** (assemble is
genesis-live, D-3), and arm #3 was already V3.0 at source (`FOLLOWUPS.md:2013` — "must land
before genesis freezes the absence of GC"). But "before genesis" is a **floor, not a licence
to land first**: an arm that compiles green and never fires in production is strictly worse
than an unlanded one, because its reopen line reads discharged (§0 F-1, DQ-F).

---

## 0. Why this is a real round (what grounding the code changed)

The [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) reads SP-R0 as "mint the witness."
Source verification at `dev = 40805d7d0` changed the shape:

1. **Spent-ness is not derivable from anything persisted.** `bond_post_matches` is
   `(height, p_canonical_id, post_kind)` only — no key image, no confirmed-post→consumed-
   `gindex` link (`pscan/scan_step.rs` arm (b); `pscan_state.rs`). `PReconcileSet` is
   presence-of-persona, never which-output-spent. SP-R0 must **detect** the spend.
2. **`funding_outputs` is append-only.** `PScanAccrual::ingest` only `extend`s; nothing
   removes on confirmed spend — the poison the witness guards (GF4b §3.2).
3. **SP-6 is built.** `PReconcileSet` (`reconcile.rs:67`) + `VerifiedRange`
   (`exhaustiveness.rs:64`) exist on `dev`. The FOLLOWUPS "SP-6 unbuilt, 0 files,
   2026-06-28" note (`FOLLOWUPS.md:8338`) is **stale** — correct it.
4. **The key-image primitive is built, and the scan-step is same-process.** `stake_engine.rs:1876`
   (`biased_hash_to_point(output_key) * x_scalar`) / `crypto-pq/output.rs:1245`. And the
   "offloaded scan-step" is `run_dual_extractor` on `spawn_blocking` — a **same-process
   compute offload**, not a cross-process boundary — whose closure **already holds `view_sk`**
   (funding scanners live inside it, drop at its end; `scan_step.rs:23-28`). Both facts feed
   DQ-A. Arm #1's new work is thus **watch + prune-at-ingest + witness mint**, not derivation.

### F-1 (spine) — the persona stack is production-inert at genesis; the front is the activation driver

`start_pscan`/`start_pscan_if_staker` (scan driver) and `spawn_stake_engine_if_staker`
(`lifecycle.rs:779`, derivation driver, wired into prod open) are **staker-gated**, and at
source **nothing in production sets `staking_enabled`**: `persist_bond_record`
(`stake_persist.rs:147`, the sole setter) has **zero production callers** (all
`#[cfg(test)]`/`regtest_e2e`), and **no stake/bond RPC exists**. Verified at `dev` **and every
open PR** (#328 drain planner "no consumer yet"; #329 scan driver, names "no RPC stake entry";
#330 unrelated — the open-PR list is exactly those three). So in production: no staker → no
StakeEngine → no personas → no scan → no posts. The whole archival-`P` production wiring
(scan, drain, assemble, the SP-R0 GCs) is a **constellation of built-unwired pieces** gated on
one missing front. "Persona scanning lands" (arm #3's reopen trigger) is true in the
*code-exists* sense, **false in the runs-in-prod sense**; landing arm #3 on that premise
freezes a non-firing GC — the `pscan/mod.rs:28` fossil, one doc over. The front is the
**production staker-activation path** ([`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md),
the `(b) RPC stake entry` co-gate), **not** an SP-R0 arm.

---

## 1. The landed substrate SP-R0 sits on

- **The witness + five consumers.** `SpentRecordsDurablyPruned` (`bond_assembly.rs`, zero
  production constructors) gates `sweep_funding_outputs` and transitively `BackingSet`
  fee-sweep, `BondOrchestrator::assemble_bond_post`, the claim orchestrator, the CB-3
  claim-dispatch seam. Arm #1 (D-1) adds the sole production mint.
- **SP-6 evidence.** `PReconcileSet { covered: VerifiedRange, matched_posts }`, `covered` =
  **exhaustiveness only**: GC a slot only if height ∈ `covered` and no matched post claims it.
- **The done-side ledger, already designed.** 2d1 plan "Records-driven retirement": the
  authoritative done-side ledger in `PScanState` (retired-records + high-water mark), with
  `StakingBlock.bonded_slots` the **live hint**. SP-R0 arm #2 implements it.
- **Canonicity, already resolved.** `VerifiedRange` = exhaustiveness only; the irreversible
  `bonded_slots` GC needs a **canonicity token**; the **funding view inherits daemon-trust**
  (a fork there is recoverable) — no wallet PoW (Trust-anchor resolution, 2026-06-29).

---

## 2. Locked decisions (ratified with the maintainer, 2026-07-18)

- **D-1 — Disposition (a): durable prune.** Detect spent funding outputs, remove them, add the
  sole production constructor of `SpentRecordsDurablyPruned` (witness stays). Rejected (b)
  reservation retention: unbounded state growth (`00-mission` priority 3).
- **D-2 — Spend-detection: key-image watch, prune at ingest.** Match each tx input's key image
  against P's held funding-output key images; remove a record when its spending block is
  ingested (already ≥ `ARCHIVAL_REORG_DEPTH_BLOCKS` = 720 deep). **No `PSCAN_STATE_VERSION`
  bump** — `funding_outputs` stays a postcard `Seq` (element removal wire-identical) **and**
  pre-genesis every wallet fresh-syncs from block 0 with the watch on, so there is no
  pre-watch record for absence-as-evidence to miss (the airtight form; "nothing persisted"
  alone leaves an upgrade-mid-life gap this closes). Rejected own-post→gindex linkage:
  common-case only + a persisted map (a 6→7 bump).
- **D-3 — Genesis-live** (subject to F-1: "before genesis" ≠ "first").

---

## 3. Decomposition — three arms + the activation front

| Arm | GC | Structure | Real gate | Canonicity | Unblocks |
|-----|----|-----------|-----------|------------|----------|
| **#1** | Spent `funding_outputs` prune (key-image watch) → **mint the witness** | `PScanState` (v6) | the watch/prune/witness machinery (**not SP-6**; derivation exists) | inherited — 720 ingest ceiling; **no token** | assemble go-live |
| **#2** | Phantom `bonded_slots`/`p_slot` GC (done-side ledger) | `PScanState` retired-records + `StakingBlock` hint | **SP-6** (built) + a **canonicity token** | required; records-driven → token = corroboration | correct derive-forward set |
| **#3** | `bonded_slots`/`p_slot` wallet-local full-scan phantom drop | `StakingBlock` (hint) | **live-gated on the activation front** (F-1); phantoms arise at activation (DQ-C) | inherited — recoverable | correct monotone cursor |
| **front** | production **staker-activation** path — *its own round, not an SP-R0 arm* | — | — | — | **every arm's production effect** |

**Prune-on-retire is atomic** (transport plan §14): one seal drops a persona's
`funding_outputs`, `bond_post_matches`, `pending_unbonds`, and writes its retired-record —
else `bond_post_matches` grows unbounded. Shared plumbing across #1 and #2.

---

## 4. The new design — arm #1, key-image-watch funding prune

The piece WI2 §3.4 deferred ("external-spend detection (key-image watch) is 2d-2 reconcile
scope"). Today's dual extractor runs (a) view-key funding recovery + (b) cleartext bond-post
detection (`pscan/scan_step.rs`). Arm #1 adds a **third arm (c): spent-key-image match** over
each scanned tx's `prefix.inputs`, against a watch-set of the key images of P's held
`funding_outputs`. A hit removes that record from the in-memory accrual before the next seal.

**Canonicity is inherited, not invented (F-3).** The ingest ceiling already trails tip by 720
(`start.rs:93`, `dispatch.rs:186-206`), so anything ingested is ≥720 deep: **prune-at-ingest is
prune-when-already-buried.** A spent key image is a **presence** event (SP-6's positive-
confirmation discipline), and the funding view is recoverable on a deep reorg like the
principal's balance (funding-side analog at `cover_discovery.rs:123`). So arm #1 needs **no
canonicity token** and does not consume SP-6; the token (`min(claimed_tip, verified_frontier +
reorg_depth)`) is an **arm-#2-only** concern.

---

## 5. Design questions — ratified dispositions (2026-07-18)

### DQ-A — key-image derivation + watch-set containment — RATIFIED (mechanism), justification corrected

**Mechanism (ratified).** The StakeEngine actor derives the key images of P's held funding
outputs **in-actor** from the vault (the built primitive, §0.4) and hands the scan closure a
**key-image watch-set**; spend material never enters the closure. Cache by `gindex` (stable),
derive-on-add / drop-on-prune, no persistence (re-derivable at open).

**Architecture (corrected).** The scan closure is `run_dual_extractor` on `spawn_blocking` — a
same-process **compute** offload — and it **already holds `view_sk`** (`scan_step.rs:23-28`),
which recovers *every* one of P's funding outputs. A set of those outputs' key images is
**strictly ≤** what the closure already holds; the watch-set does not widen the surface.

**Justification corrected (the load-bearing fix).** The watch-set is **not** safe because "a
key image is a public on-chain value." A key image is derivable by the holder anytime but
**only public once its output is spent**; the watch-set is key images of *unspent* outputs —
**pre-publication** values, and as a *set* a correlated fingerprint of P's live UTXO. That is
the firewall's "public-on-chain but correlated-and-co-located-off-chain is the leak" shape. It
is safe **only** because it is `≤ view_sk`, transient, same-process, and dropped at closure
end — a **contingent** fact about this architecture, not a property of key images. "It's
public" would wave the leak through the first refactor that moved the scan-step to a real
boundary (separate process, a log line, the principal domain).

**Make the contingency structural (make-bad-states-unrepresentable).** The watch-set type gets
a **redacting `Debug`** (the `bond_post_matches` idiom, `accrual.rs:152` / `BondPostRecord`)
and **no `Serialize`** impl — so it cannot be persisted or cross a wire, and a future refactor
that tries to send it over a boundary is a **compile error, not a leak**. That is the
genesis-frozen guarantee worth freezing — not the sentence about key images being public.

### DQ-B — prune-at-ingest — RATIFIED

Prune-at-ingest; absence from the next seal is the durable record → no marker, no bump. Crash
window (actor drops the record, process dies before seal) **self-heals**: the seal is **one
atomic write** of cursor + accruals + `funding_outputs` (`accrual.rs:29-32` — "there is no
ordering between two writes to get wrong, because there is one write"), and the cursor advances
only at seal, so a crash before seal loses the prune *and* the cursor advance together →
restart re-scans the unsealed block, re-detects the spend, re-prunes. Verified at the seal site.

### DQ-C — sequencing — RATIFIED (C1), sub-question resolved at source

Front = the production staker-activation path (its own round), **not** an SP-R0 arm; until it
lands all three arms are production-inert. Order: **activation round first**; then arm #1
(funding prune + witness — unblocks assemble); then arms #2/#3 — each landing only when it can
be shown to **fire** in a prod-representative path (DQ-F). Arm #3's "buildable now, land first"
is retracted.

**Sub-question resolved:** `persist_bond_record` (`stake_persist.rs:145-154`) sets
`staking_enabled` **and** writes the `bonded_slots` entry under one write guard + one
crash-atomic `save_state` — becoming a staker *is* persisting the first bond. So arm #3's
phantom domain includes **activation-time** crashes, and #3 sequences **right behind the
front**, not behind assemble. (That same fact — `staking_enabled` gates
`spawn_stake_engine_if_staker` at `lifecycle.rs:894`, yet is only set by a persist that needs a
derived persona that needs the engine — is the first-stake **chicken-and-egg** the activation
round owns; carried to [`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md).)

### DQ-D / DQ-E — RATIFIED

D: per-arm canonicity — arm #1 no token (720 ceiling); arm #2 the token, as **corroboration**
(records-driven), sourced from the 2d-2 sweep-corroborated tip clamp; arm #3 inherited. Do
**not** generalize the clamp across arms. E: `anchor_t0` is assemble-time → **arm #2's** tip
clamp, not arm #1.

### DQ-F — fires-in-prod, CI-asserted (RATIFIED, recursion closed)

Each arm's FOLLOWUPS reopen line closes **only** when a prod-representative integration lane
drives the arm **through the activation driver** and **CI asserts the GC fired** — a
fire-counter / observer the lane asserts non-zero (a real phantom collected / a real spent
record pruned). Not "a reviewer confirms a firing test exists" (that is the reviewer-discipline
layer DQ-F exists to escape) and not mere test-existence: the reopen line cannot be marked
closed until **CI has watched the arm fire**. Specify the CI wiring (the observer + the
non-zero assertion) in each arm's landing PR.

---

## 6. FOLLOWUPS / doc obligations that ride with this round

- **[front — its own round]** the production **staker-activation path**
  ([`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md)); without it every
  SP-R0 arm is inert. Cross-linked both ways (that round references this doc's DQ-F).
- **[close on landing — with the DQ-F CI fire condition]** FOLLOWUPS "2d-1 WI-2 durable removal
  of SPENT funding outputs" (#1), "2d-2 SP-R0 reconcile GC" (#2), "2d full-scan reconciliation
  of bonded_slots/p_slot" (#3, V3.0 `FOLLOWUPS.md:2013`).
- **[correct now]** the stale "SP-6 unbuilt, 0 files, 2026-06-28" note (`FOLLOWUPS.md:8338`, and
  its V3.x home) and the `IMPLEMENTATION_INDEX.md` SP-R0 status lines.
- **[carry]** GF4b §5 item 4 (witness zero-production-constructors → arm #1 adds the one) and
  item 5 (assemble change-split / tx-size bound); the GF4b-5 structural gate closes when arm #1
  mints the witness.
- **[carry]** the rule-21 `#[allow(dead_code)]` on the five consumers: **(a) SP-R0 pruning AND
  (b) RPC stake entry** — arm #1 retires (a); the activation round retires (b).
- **[enroll]** `anchor_t0` in arm #2's 2d-2 tip clamp (DQ-E).

---

## 7. Round-0 exit

DQ-A…DQ-F ratified. Remaining Round-0 tasks: correct the stale status lines (§6), register the
three arms as index rows (rule 94; SP-R0 identifier exists), and open the activation round.
**Executed 2026-07-18 (this branch + companion PR):** the three stale FOLLOWUPS entries
corrected (the "SP-6 unbuilt" gate — stale since 2026-06-29 — plus the arm-#1 gate header
and arm #3's "persona scanning lands" reopen trigger, re-pointed at the DQ-F fire
condition); SP-R0 + arm rows and the activation-round row registered in
`IMPLEMENTATION_INDEX.md`; the activation round is **open as its own round** — PR #332
([`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md), Round-0 with
SA-DQ-1…5, carrying the two named genesis gates SA-DQ-4 (GF4b-2 funding-input-count
discipline) and SA-DQ-5 (the GF-7 broadcast-before/after-reopen fork)).
Implementation sequences **behind the activation round**, each arm gated on the DQ-F CI fire
condition; the DQ-A watch-set lands with its redacting-`Debug`/no-`Serialize` containment from
the first commit.
