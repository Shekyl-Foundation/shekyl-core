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
arms land **logic-proven** behind the DQ-F fire harness, while their **production
behavior** lands behind that round (the DQ-F split, precisified 2026-07-18 — §5 DQ-F).

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
   (`exhaustiveness.rs:64`) exist on `dev`. The FOLLOWUPS note that read "SP-6
   unbuilt, 0 files, 2026-06-28" was **stale** — anchor by that phrase, not a
   line number (it sat at `:8338` when first found and had already drifted to
   `:8366` by PR #327 — the grep-not-hardcode rule). **Corrected on this branch**
   (`d605f07b5`: the entry now reads gate CLEARED, re-keyed as arm #2).
4. **The key-image primitive is built, and the scan-step is same-process.** `stake_engine.rs:1876`
   (`biased_hash_to_point(output_key) * x_scalar`) /
   `shekyl-crypto-pq/src/output.rs:1245` (`compute_output_key_image`). And the
   "offloaded scan-step" is `run_dual_extractor` on `spawn_blocking` — a **same-process
   compute offload**, not a cross-process boundary — whose closure **already holds `view_sk`**
   (funding scanners live inside it, drop at its end; `scan_step.rs:23-28`). Both facts feed
   DQ-A. Arm #1's new work is thus **watch + prune-at-ingest + witness mint**, not derivation.

### F-1 (spine) — the persona stack is production-inert at genesis; the front is the activation driver

`start_pscan`/`start_pscan_if_staker` (scan driver) and `spawn_stake_engine_if_staker`
(`engine/lifecycle.rs:779`, derivation driver, wired into prod open) are **staker-gated**, and at
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

**Consumer registration (rule 21; pre-merge fold 2026-07-18).** The safety argument above
makes arm #1's prune-permanence a **consumer of `ARCHIVAL_REORG_DEPTH_BLOCKS` — the
constant's *semantics*, not just its identifier** (the M1 §11.8 method; the
`fcmp_reference_block_max_age` / `retention_horizon_blocks` failure class): prune-at-ingest
is reorg-safe *only because* the ingest ceiling trails tip by this depth. **Lowering the
constant reopens arm #1's prune-at-ingest safety** — a smaller ceiling prunes funding
records before they are reorg-safe, silently, with the wallet's durable state as the blast
radius. The coupling is registered at the definition site too
(`config/consensus_constants.json`, `_comment_archival_timing`), so a faster-finality
retune meets the warning where the retune happens.

**BUILD RECORD (2026-07-18, `feat/sp-r0-arm1-funding-prune`) — arm #1 BUILT +
LOGIC-DISCHARGED.** As designed above, plus one addition the design round did not
anticipate: the **in-step blind spot**. An output discovered at height `h` can be spent at
`h' > h` *within the same scan step*, and its key image is derivable only in-actor after
the closure returns — a watch gap that would have broken D-2's absence-as-evidence
argument for large catch-up batches. Closed structurally: the extractor collects the
post-first-discovery spend key images (`DualExtractOutput::trailing_key_images`, empty in
the no-discovery common case) and the handler derives the step's discoveries and matches
them before returning. Landed surfaces: extractor arm (c) (`scan_step.rs`), the
`KeyImageWatchSet` with DQ-A containment (redacting `Debug`, no `Serialize`,
self-parse tripwire), the in-actor derive-on-add/drop-on-prune cache
(`stake_engine.rs` `refresh_watch_cache`/`derive_watch_key_image` — same
`derive_p_source_secrets_bundle` leg as assemble), prune-at-ingest with the DQ-F fire
counter (`accrual.rs` `spent_pruned_total`), the **sole production
`SpentRecordsDurablyPruned` constructor** (`arm1_watch_pruning_live`; tripwire now
asserts exactly-one), and the DQ-F fire lane
(`shekyl-engine-core/tests/sp_r0_arm1_fire.rs`; harness compiled
`feature = "test-helpers"` + `not(test)` so Guard 1 — no `for_test()` on the path under
test — is a compile-time fact; CI asserts both prune paths fire and the
production-witness sweep refuses post-prune). Guard-2 status: **logic-discharged;
production-firing gated on the staker-activation round (#332)**.
**UPDATE 2026-07-18 (PR-4b): PRODUCTION-DISCHARGED.** The activation entry landed
(#336) and PR-4b landed the daemon bond-post battery + promoted the regtest
tripwire: the e2e now stakes through the production `Engine::first_stake` entry
(the `arm1_watch_pruning_live` witness minted inside it), the sealed post is
re-lifted and submitted over real RPC, the bond confirms on-chain, and the scan
observes the confirmed post and **prunes the swept funding records from the
sealed state** — the DQ-F production fire, asserted live
(`regtest_e2e.rs::e2e_staker_bond_post_reaches_the_daemon_submit_gap`).

**BUILD RECORD (2026-07-18, `feat/sp-r0-arm2-retire-gc`) — arm #2 BUILT.** The done-side
ledger landed as designed (2d-1 §"Records-driven retirement"): `RetiredPersonaRecord`
rows in `PScanState` (**`PSCAN_STATE_VERSION` 6 → 7**, snapshot regenerated per rule 42),
written by the **atomic retire-time prune** `PScanAccrual::retire_persona` — the
persona's `bond_post_matches` rows and the `pending_unbonds` trigger leave in the same
mutation that appends the record, sealed by the task's one atomic write (the §15 pin; the
bound on `bond_post_matches` growth). The slot's `funding_outputs` are **not** pruned
here — see the funded-gate in the review-sweep addendum below.
**DQ-D consumed as designed:** the durable prune fires only under the sweep-corroborated
tip clamp `min(claimed_tip, verified_frontier + reorg_depth)` — the WI-3 R2-1 reserve,
consumed as *corroboration*; a low-claiming source merely defers the prune (fail-safe),
and the actor key-wipe keeps its frontier basis. **The open path** applies the
records-driven clean before derive ("stop deriving slot N"): retired slots leave the
live hint, an emptied hint reverts the wallet to a non-staker, and the derive-forward
subtraction follows from the monotone cursor (no second mechanism). **DQ-E:** the clamp
primitive now exists at the retire site; `anchor_t0`'s enrollment stays with its named
FOLLOWUPS item (the 2d-2 tip-consumer enrollment note). **Guard-2 status, stated
honestly for ratification:** arm #2 is **logic-discharged at the task/accrual/lifecycle
test level** — the ~270k-block claim-window reachability makes a `not(test)`
fire-harness lane impractical (evidence construction uses the cfg(test) batch
constructor; a conscious, disclosed deviation from the arm-#1/#3 lane form) — and
**production-discharge — corrected at source (2026-07-19): NOT yet drivable.**
The prior "drivable now" claim was wrong: arm #2's retire trigger is a confirmed
`Unbond` post, and while the consensus **block-path** verifies for non-JoinMarket
kinds exist (`shekyl-archival-retention` runs them today), the **submit-side**
fact sets are JoinMarket-only (`DAEMON_SUBMIT_VERDICT.md` §8.7.1 pins the JM BP
rows only) and **no wallet constructs these kinds yet** — so no Unbond can reach
a regtest chain through any production path. Named blockers: the non-JoinMarket
submit battery (the PR-4b sibling for `Unbond`/`Rebond`/`HoldingsUpdate` rows)
**and** the wallet-side unbond entry. The armed settlement-epoch override for
the W-lapse rides whichever lands last. Arm #3's production-discharge leg, by
contrast, needs no post at all and **LANDED 2026-07-19**
(`e2e_arm3_phantom_slot_collected_at_open`: the SA-DQ-3 persist-then-no-broadcast
crash against the live chain, collected by the production open; SHEKYLD_BIN
cadence, the same gating as the promoted arm-#1 lane).

**REVIEW-SWEEP ADDENDUM (2026-07-19, high-effort review of PR #339).** Six findings
addressed; the load-bearing one is a stranded-funds gap.

- **Funded-gate (correctness — the one that changes behavior).** The witness gates only the
  *reward-collateral* stuck-funds dimension (`Unbond` + `W`-lapse). It did **not** gate the
  *funding-output* dimension: a slot reaching retire could still hold unspent
  `funding_outputs` (a post-`Unbond` emission arrival, a reorg re-add, an incomplete drain —
  draining is amount-targeted `select_for_drain`, not a lump sweep). The actor wipe is
  irreversible and the open path stops deriving a retired slot, so wiping a *funded* slot
  strands spendable `P` funds. **Fix:** the retire handler now refuses the wipe for a funded
  slot — a new `RetireOutcome::SkippedFunded` gated on a `FundedSlots` operand the task
  derives from `accrual.funding_outputs()` — and defers (leaving the durable `pending_unbonds`
  trigger) until the funding drains (arm #1 prunes the last output on its spend). This makes
  the invariant `retire_persona` assumed (a drained slot) **structural**: the function now
  never prunes `funding_outputs`, guarded by a `debug_assert`. The claim-window witness and
  the funded-gate are the two complementary halves of "never wipe a persona while spendable
  value remains behind its keys."
- **Held-funding cache freshness (correctness).** The task now re-snapshots the actor's
  held-funding watch list after any pruning dispatch (defensive under the funded-gate, which
  already keeps retire from mutating `funding_outputs`).
- **`RetiredLedger` (efficiency/security).** The per-retire idempotency check is now an
  O(log n) index (a `BTreeSet` derived from the records, rebuilt on load, never separately
  serialized) instead of an O(n) scan over the append-only vector, wrapped with the records so
  the two cannot desync; redacting `Debug`. The vector's unbounded growth is inherent (it is
  the durable "stop deriving slot N" source) and documented as such, not a leak.
- **Docs/cleanup.** The two per-step seals are documented as both load-bearing (cursor-durability
  vs prune-durability, the second firing only on a rare pruning step) rather than merged; the
  uncorroborated-retire re-fire comment corrected ("re-fires after a **restart**", not "a later
  sweep" — the session dedup blocks that); a dead `let _ = corroborated;` discard removed; the
  `PScanState.funding_outputs` / `pending_unbonds` field docs reconciled with the funded-gate
  (retire no longer prunes funding; the drain is amount-targeted, not a sweep).

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
is retracted. **Precisified 2026-07-18 (DQ-F split):** "activation round first" binds the
**production discharge**, not the landing — arms may land **logic-discharged** in parallel with
#332 under CI-observed fire (DQ-F guards 1–2); production behavior still lands behind #332.

**Sub-question resolved:** `persist_bond_record` (`stake_persist.rs:145-154`) sets
`staking_enabled` **and** writes the `bonded_slots` entry under one write guard + one
crash-atomic `save_state` — becoming a staker *is* persisting the first bond. So arm #3's
phantom domain includes **activation-time** crashes, and #3 sequences **right behind the
front**, not behind assemble. (That same fact — `staking_enabled` gates
`spawn_stake_engine_if_staker` at `engine/lifecycle.rs:894`, yet is only set by a persist that needs a
derived persona that needs the engine — is the first-stake **chicken-and-egg** the activation
round owns; carried to [`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md).)

### DQ-D / DQ-E — RATIFIED

D: per-arm canonicity — arm #1 no token (720 ceiling); arm #2 the token, as **corroboration**
(records-driven), sourced from the 2d-2 sweep-corroborated tip clamp; arm #3 inherited. Do
**not** generalize the clamp across arms. E: `anchor_t0` is assemble-time → **arm #2's** tip
clamp, not arm #1. **Reopen (rule-21 parity, added 2026-07-18):** DQ-D's arm-#2 token
sourcing rides the 2d-2 sweep-corroborated tip clamp as designed there — if the clamp's
semantics change (the 2d-2 remote/untrusted-daemon reopen family, WI-3 R2-1 / D-B6), the
sourcing decision reopens with it.

### DQ-F — fires-in-prod, CI-asserted; split the claim (RATIFIED + precisified 2026-07-18)

The pscan/mod.rs:28 fossil bundled two claims — *the GC fires* (logic) and *production
drives it* (wiring) — asserting both when neither held. The fix is claim exactly what
is proven, so DQ-F splits:

- **Logic-discharged** — a CI fire harness drives the arm on the production code path and
  CI asserts the GC fired (fire-counter/observer, non-zero: a real phantom collected /
  spent record pruned). The harness's only stand-in is staker creation at the top
  (`make_staker_for_test`) — which IS #332; everything downstream (real derive primitive,
  key-image match, prune, witness mint) is production code. So logic-discharged = proven
  from staker-exists downward, and the sole stand-in is the exact gate being deferred.
  This is what WI-4 §19.1 licenses ("harness exercises production code without the
  embedder") and no more.
- **Production-discharged** — the #332 RPC path drives the arm. The F-1 answer at the
  production edge; gated on #332.

Arms may land logic-discharged in parallel with #332 under CI-observed fire — not
strictly behind the front. Two guards:

- **Guard 1 — no `for_test()` on the path under test.** The harness drives the real
  `persist_bond_record`, the real `derive_archival_p_keys` (SA-DQ-2 derive-equivalence
  bites), and the real production `SpentRecordsDurablyPruned` constructor — never
  `for_test()`. Checkable: the harness runs where `for_test()` is `#[cfg(test)]`-unavailable,
  so only the production constructor satisfies it. Tell — delete `for_test()`; still
  passes ⇒ real, breaks ⇒ proving nothing.
- **Guard 2 — the split travels with the status.** Every reopen line / index row states
  which discharge: "logic-discharged (CI harness, production code path);
  production-firing gated on #332." A bare "discharged" is forbidden.

**Genesis-safety (checked):** landing arm #1 ahead of #332 mints the production witness and
lifts the assemble compile-block — safe, because assemble stays unreachable in
production without a staker (`staking_enabled`-gated; #332 sets it). Reachable-in-
principle, unreachable-in-practice until #332; the witness stays sound. Genesis-safe.

Specify the CI wiring (the observer + the non-zero assertion) in each arm's landing PR.

---

## 6. FOLLOWUPS / doc obligations that ride with this round

- **[front — its own round]** the production **staker-activation path**
  ([`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`](ARCHIVAL_STAKE_ACTIVATION_PLAN.md)); without it every
  SP-R0 arm is inert. Cross-linked both ways (that round references this doc's DQ-F).
- **[close on landing — with the DQ-F CI fire condition]** FOLLOWUPS "2d-1 WI-2 durable removal
  of SPENT funding outputs" (#1), "2d-2 SP-R0 reconcile GC" (#2), "2d full-scan reconciliation
  of bonded_slots/p_slot" (#3 — the V3.0 `StakingBlock`-frozen item; grep FOLLOWUPS for the
  phrase, line refs drift).
- **[corrected — `d605f07b5`, this branch]** the stale "SP-6 unbuilt, 0 files, 2026-06-28"
  note (content-anchored — grep `docs/FOLLOWUPS.md` for the phrase; the hardcoded `:8338` this
  task originally carried had already drifted before the sweep ran) and its V3.x home, plus
  the `IMPLEMENTATION_INDEX.md` SP-R0 status lines.
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
Implementation lands **logic-proven behind the DQ-F fire harness** (arms may land in
parallel with #332; production behavior lands behind #332 — the DQ-F split), each arm gated on the DQ-F CI fire
condition; the DQ-A watch-set lands with its redacting-`Debug`/no-`Serialize` containment from
the first commit.
