# CT-6 — the proving-state discharge

**Status:** DESIGN ROUND — **Round 1 disposed 2026-09-22**. Every question in
§5 carries a terminal status *in its own row*; the round holds no blanket
"ruled". **`Q1`, `Q2` and `Q3` RULED; `Q5` CLOSED by dissolution; `Q6` a named
dependency; `Q4` PENDING AS DERIVATION** on the re-pointed advance field.
**`Q1` was ruled 2026-09-28 by the derivation §9 records — and the derivation
deleted the geometry it was asked to size.**
**Increment 4 is built (§10): one dense ring over the reorg horizon, the
armed examiner grading the two real tiers, and `Q4`'s field re-derived from
the measured advance. `Q4`'s threshold is still not graded — that needs the
pinned rig, and increment 6 is its seat.**
A derivation whose inputs are named and unmeasured is not a ruling, and the
banner says so rather than letting the map run ahead of the territory.
Opened and pinned at `dev@91705e5882` (2026-09-20); disposed against
`dev@5b2d4c6d6`. **Product of this round is a contract plus a work breakdown;
it authorizes no implementation.** Each increment in §6 is separately
authorized.

**Design of record:** [`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) §6.3 —
*the principal's proving state is not a store* (`WSS-Q1`(b), RULED 2026-09-19,
adopted subject to §6.3.4's four measurements). This document does **not**
restate §6.3. It is the implementation contract that discharges the two
residue rows §6.3 was ruled to supersede, and it inherits §6.3's authority on
every question §6.3 already settled.

**What it discharges.** The two reversion-clause-routed rows carried in
[`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §"What REMAINS", from
[`CT5_SERIES_CLOSEOUT.md`](../completed/CT5_SERIES_CLOSEOUT.md):

- **(a) per-input reconstruction reuse** — `assemble_path` re-runs
  `build_layers` per input; *"reopens at mainnet scale"*;
- **(b) store-backed / pruned-tree assembly (F5)** — already marked
  *"superseded in design by `WALLET_SIDE_STORE.md` §6.3"*.

---

## 1. Why this is a discharge and not a new family

The round arrived briefed as a new document with a new identifier family
(`WPS-`). It is not, and three reasons converge (ruled 2026-09-20):

1. **The tree already names this work.** Both residue rows exist, are
   reversion-clause-routed, and (b) is explicitly routed to §6.3 — the parent
   of this round. A new name beside a tracked one does not add an identifier;
   it splits one.
2. **One lane, one family.** Minting `WPS-` beside an existing tracked name is
   the second-name error, in the same shape as the `PR-D`/`PR-E` collision that
   `SH-` was minted to escape and the bare-`CT-` ambiguity that `CT-ACT-`
   was minted to escape ([`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md)
   §"CT-ACT-": *"a bare `CT-4` would be ambiguous in exactly the place it would
   be read"*).
3. **Rule 94 registration is irreversible-ish**, which is exactly why the
   pre-flight ran before the registration and not after it. It found that the
   name already existed (§3).

### 1.1 Registration mechanics

**`CT-6` extends the registered `CT-` curve-tree family (CT-1…CT-5); no new
prefix is minted.** Extending a registered family is not a second name for one
thing — it is the family's next member, and the uniqueness check `CT-` already
passed carries.

The `CT-ACT-` precedent cuts *for* this and not against it: that round was
denied a bare `CT-` number because it touched the curve-tree store while being
a *different programme* (CompleteTree activation). CT-6 is the curve-tree
programme's own next slice — the one CT-5's closeout routed forward.

| Artifact | Disposition |
| --- | --- |
| This document | **New, living.** Home for `CT-6` and its questions |
| [`CT5_SERIES_CLOSEOUT.md`](../completed/CT5_SERIES_CLOSEOUT.md) §5 | **Not amended** — it is a completed record of what *was*. The residue row stays as written |
| [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §"What REMAINS" | **Re-points** (a) and (b) to this document. Owed by the registering PR |
| [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) | **The existing `CT-1…CT-5` family row is amended to `CT-1…CT-6`** (rule 94 §1) — *not* a new row. `check_index_prefix_uniqueness` holds one row per prefix and rejected a separate `CT-6` row as a `CT` collision, which is this section's ruling restated as a gate: extending a family and minting one are different edits, and the index can tell them apart |
| `assemble.rs:106`'s comment | Named this work *"the store-backed / per-input-reconstruction assembly follow-up"*. **Re-pointed at implementation (increment 3, 2026-09-24):** the comment described a follow-up that has now landed, so it states the shape that is there — the positions are indexed once for the batch — rather than naming itself as owed work |

---

## 2. Scope

**In.** The principal's proving state: how the frontier advances, what is
snapshotted, how a `Path` is produced at a reference height, and what happens
on a reorg. The graded quantities are §6.3.4 rows 2 and 3, already measured for
the **naive** form by [`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md).

**Out.** `P`'s serving store (Tier 2, its own lane — and see F5 below); any
change to proving cryptography; any change to the reference-age constants
(**foreclosed by F1**); the rig grading of the naive form (parallel,
unaffected); implementation.

---

## 3. Round-0 pre-flight — the verified substrate

Six items were briefed for verification before proposing. **Three of the six
refuted or re-scoped their own premise.** Verified at `dev@91705e5882`.

### F1 — reference-height selection is landed and privacy-ratified (REFUTES)

The brief held that reference-height selection was "currently unlocatable",
with production choice possibly unmade, and asked this round to propose a
convention plus a uniformity argument. All three premises are false.

- `reference.rs:83` — `REF_ANCHOR_AGE = FCMP_REFERENCE_BLOCK_MIN_AGE + 1 = 6`,
  with `const _: () = assert!(REF_ANCHOR_AGE == 6)` at `:110` and JSON-drift
  sentinels at `:62`, `:68`.
- `reference.rs:124` — `select_reference_height(tip) = tip − REF_ANCHOR_AGE`.
- `reference.rs:17` — the uniformity argument **is already written**: *"Every
  honest wallet uses the same offset — the age is observable on every tx, so a
  per-wallet offset would fingerprint the wallet (`00-mission` priority 2; same
  uniformity logic as dust `K_DUST`)."*
- `reference.rs:83` — and it **already carries its rule-21 reversion clause**:
  *"Re-derived only on a substrate change (observed depth-6 reorg rate, or a
  `MIN_AGE` consensus change), not by preference."*
- Production consumer: `bond_orchestrator.rs:442` `anchored_reference_block`,
  whose doc says *"**Not** a hand-rolled `tip − FCMP_REFERENCE_BLOCK_MIN_AGE`"*
  — reached from `drain_orchestrator.rs:756`, `release_dispatch.rs:502`,
  `drain_read.rs:245`. `reference.rs:~165` `two_sided_reference_height` is the
  shared two-arm gate.

**Consequence, and it is why this matters beyond bookkeeping.** The brief's
proposed default was *"likely `tip − min_age` at assembly time"* — **tip−5**.
Landed is **tip−6**. Adopting the default would have moved a privacy-canonical
constant by one block with no substrate change, tripping the very reversion
clause written to prevent it. The `+1` is reorg margin.

**The residue is refuted too.** The brief observed that `signing_assembly.rs:196`
copies `tree.reference_block` and that the only assignment it could find was
test support. The production assignment is `assemble.rs:209`
(`reference_block: reference.block_hash`) inside `assemble_path`;
`signing_assembly.rs:196` is a field copy downstream of it.

**Effect on the round: item 3 is removed, not answered.** `CT-6` proposes no
reference-height convention. Anything built here consumes
`select_reference_height` / `two_sided_reference_height`.

### F2 — the proposed shape is ~half landed as CT-1 (RE-SCOPES)

The brief proposed "finalized chunks are immutable, plus a frontier" and a ring
"covering the reorg horizon (720)" as new design. Both exist:

- `store/ops.rs:39` `mixed_composition_root(leaf_count, frozen_r, tail)` —
  frozen `R_k` sub-roots plus a partial tail. That **is** the finalized-chunks
  mechanism, landed and pinned in
  [`CT1_ROUND1_PINS.md`](../completed/CT1_ROUND1_PINS.md).
- `shekyl-fcmp/src/tree.rs:640` `SEGMENT_LAYER_J = 2`, so
  `leaves_per_segment() = outputs_per_node(2) = 38 × 18 × 38 = 25 992` leaves
  per segment.
- `segment.rs:37` — `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` **is**
  `ARCHIVAL_REORG_DEPTH_BLOCKS`, generated from the `archival_reorg_depth_blocks`
  key of `config/consensus_constants.json`, the same JSON the retention crate
  reads.

**Effect on the round: the 720 is consumed, never restated.** Any horizon this
design needs **is** `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`, read from the one JSON
authority. A second literal `720` in this programme would be the three-copies
defect with the copies in different crates.

**The difference that survives, and it is the real one:** CT-1's segments are
**leaf-count-aligned**, not **height-aligned**, and freeze on **burial**, not on
finalization. That gap is F3.

### F3 — the unamortized locus is not where the brief aimed (THE FINDING)

Two costs, conflated by the brief.

**(a) Root-at-`h` is *not* amortized inside the reorg horizon.**
`redb_backend.rs:1214` `root_at_count` walks every **complete** segment; on a
`FROZEN_SEGMENTS_TABLE` miss it falls back to `recompute_segment_r_k` over that
segment's 25 992 leaves (`:1245`). Freeze requires 730-block burial
(`segment.rs:61`: `SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`
= 10 + 720). **The reference window `[tip−100, tip−6]` lies entirely inside the
unfrozen zone.** At the bench's worst-case leaf rate (1 056 leaves/block at
depth 6), 730 blocks ≈ 771 000 leaves ≈ **29 complete-but-unfrozen segments
recomputed on every `root_at` call**. There is also a full-rebuild fallback at
`:1253` (`TailTooShortForLayerJ` → `full_build_root` over all leaves).

So the snapshot idea **is** right for root-at-`h`. It is **CT-1's unfrozen-tail
problem**, not a new mechanism — which is what makes this an extension of the
curve-tree family rather than a new one.

**(b) Path assembly is unamortized and unbounded.** `assemble.rs:93` runs
`build_layers` over the whole drained stream, **once per input**, and
`client.rs:293` `entries: Vec<LeafEntry>` holds every drained + pending leaf,
rebuilt wholesale by `rebuild_from_store`. `assemble.rs:106` already names the
fix: *"reconstruct `drained`/`layers` once per transaction and reuse across its
inputs (and key the lookup by an ingest-time `gindex → drain-position` index)"*.

**These are the two residue rows.** (b) here is closeout row (a); (a) here is
closeout row (b). That correspondence is what identifies this round.

### F4 — item 4 (pending set at lagged heights): no defect found

Inclusion is **height-keyed, not tip-keyed**: `client.rs:964`
`drained_through(h) = h − 1` (KAT at `:1363`), and
`assemble_leaf_stream(&entries, cutoff)` / `drained_sorted` filter on that
cutoff. `drained_through_counts` caches `(height → leaf count)` keyed by exact
cutoff and *"misses to the maturity index rather than interpolating"*.

**The invariant a snapshot must carry** is therefore
`drained_leaf_count_at(drained_through(h))` — and it is already the `n` that
`root_and_depth_at` pins root and depth to together (CT-5c Q1). A snapshot that
reproduces `n` reproduces both.

### F5 — item 5's premise is contradicted by a ruling already made

The brief asked this round to propose an ownership-neutral delta shape because
*"one advance computation feeds two private path sets (principal's, `P`'s)"*.

`WSS-Q1`(a) **RULED 2026-09-19** ([`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md)
§6.1): `P`'s serving store is its own file, owned by the `StakeEngine`, and is
*"the wallet's only redb"*. What `P` holds there is **serve-set pins** — a
bonded serving obligation — not membership paths for proving. **So the
two-consumer advance is not established.**

This does **not** dissolve the concern, it relocates it: §6.3.3 stated the
identity-split discipline (*"the frontier advance is public and identity-free;
path capture is a per-identity filter over the same public stream"* — wording
§6.3.3 carried until it was **re-derived 2026-09-30**, after `Q5` removed its
premise) as the answer to `WSS-13`-in-a-new-location. The *public,
identity-free advance* half stands and this round inherits it; the
*per-identity* half is what the dissolution below took the subject out of. What F5 left narrower — whether `P` proves its own outputs at
all, and therefore whether a second capture side exists to build — was carried
as **CT-6 Q5** and is **CLOSED by dissolution (2026-09-22, §5)**: `P` proves
nothing as a distinct actor, so there is no second capture side and the
question has no subject. F5's reading is unchanged; what changed is that the
narrower question it opened has since been answered in the negative.

**Already recorded; not re-minted here:** `WSS-12` — `entries` is RAM-resident
and grows with the chain, *"a device-floor question at the Pi-4 provisioning
floor that no round has asked"*.

### F6 — item 6 (blast radius) holds; two citations corrected

The actor message set is confirmed in `curve_tree_actor.rs`: `IngestBlock`
`:146`, `RollbackToFork` `:160`, `VerifyRoot` `:293` (handler `:437`),
`RootAndDepthAt` `:310` (handler `:462`), `AssembleTx` `:~320`. §6.3.2 row 6's
count of **eight** messages is the authority and is unchanged.

Corrections to the brief: `VerifyRoot` is not in `merge.rs` (that is
`scan.rs:86`, which carries leaves *to* the actor); `RootAndDepthAt` is `:310`,
not `:311`.

**The engine-swap-behind-the-handle argument holds.** `AssembleTx`'s handler
doc already states the serialization the design would rely on: *"Because the
actor processes messages serially, no `IngestBlock` / `RollbackToFork`
interleaves mid-assembly — the read-path snapshot atomicity (E1) is the handler
invocation itself, not a discipline the caller must uphold."*

---

## 4. The contract

What any implementation must satisfy. These are not questions; they are the
round's fixed points, each inherited from a verified source.

| # | Contract clause | Source |
| --- | --- | --- |
| **C1** | **Snapshot-derived root at height `h` equals `build_layers`' root at `h`, for every `h`.** The existing full-tree implementation is the oracle | §6.3.4 row 4 (*"any mismatch reopens (b) outright"*) |
| **C2** | The oracle is **consumed, not built.** `full_build_root` (`redb_backend.rs:1253`) and the composition-vs-`build_layers` KAT pattern (`store/ops.rs:~207`) are the landed form of C1 for `root_at_count`. CT-6 **extends** them to height-keyed snapshots | F2 |
| **C3** | A snapshot at `h` reproduces `drained_leaf_count_at(drained_through(h))`; root and depth stay pinned to that one `n` | F4; CT-5c Q1 |
| **C4** | Every horizon **is** `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` read from the JSON authority. No second literal | F2 |
| **C5** | Reference-height selection is `select_reference_height` / `two_sided_reference_height`, unchanged | F1 |
| **C6** | The frontier advance is **public and identity-free**; path capture filters it to the wallet's own outputs. **`identity-free` is a claim about the bytes, never about access**: that the content reveals no ownership does not make the file carrying it shared, and a design that reads public content out of another identity's sealed file is `WSS-13` relocated, not C6 satisfied. **Amended 2026-09-30 — the clause read *"a per-identity filter"* and *"no component sees two identities' ownership"*.** `Q5`'s dissolution (2026-09-22) established there is no second proving consumer, and records in its own row that *"C6's second capture side is not built"* — so that half has **no subject**, not a smaller one. The bytes-vs-access half is untouched and is the part that survives, because it governs **persistence** (`Q3`) rather than the number of capture sides | §6.3.3 |
| **C7** | A reorg deeper than the horizon **refuses**; it never silently produces a wrong tree, and it says so as a rule-82 failure mode (the remedy is a full resync: remove the `.curvetree` file and then clear scan history; neither alone lifts the refusal). **BUILT 2026-09-30 (increment 5).** The horizon is `W` = `FINALITY_DEPTH_BLOCKS`, not the ring's `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`: between the two a rollback is past the snapshot tier and still repairable by folding, so the bound is `> W`. The seats are the producer's fork walk and the ingest backstop (`engine::reorg_finality`), **not** `LeafStore::rollback_to_fork` — the store must perform a deep truncation correctly (F9; the replica generator depends on it), and the policy is about whether a wallet refresh may ask. The walk confirms a fork only when a stored hash matches inside `W`; a short record on a tall chain is not a confirmed fork. Rule-82 copy reaches the caller as `ResyncRequired` (`-29211`, contract 0.10.0; `-29204` is `REFRESH_CANCELLED`) carrying the depth, `W`, and whether the depth was measured. A rescan reports the same code with `history_cleared`, rather than the server-side log `internal_detail` would have left the remedy in | §6.3.4 row 1 |
| **C8** | Everything here is derived-from-canon: recovery is **refuse-and-resync**, never a migration. Persistence is a cache | `WSS` R3 |
| **C9** | The graded quantity is §6.3.4 rows 2 and 3, on rule 76's floor, by the landed `shekyl-wss-q1b-bench` harness | §6.3.4; `WSS_Q1B_BENCH_SPEC.md` |

---

## 5. The question list — Round 1's disposition

**No blanket status.** Each row carries its own terminal word, because two of
the six are **derivations whose inputs are named and not yet measured**, and a
table headed "ruled" would assert a judgment where an arithmetic is owed. The
statuses in use: **RULED** (decided), **CLOSED** (no subject), **NAMED
DEPENDENCY** (owned elsewhere, not scheduled here), **PENDING AS DERIVATION**
(its terms are named; it resolves by computation, not preference).

| # | Question | Disposition |
| --- | --- | --- |
| **CT-6 Q1** | **Snapshot geometry.** Dense span, sparse spacing `s`, eviction. `s` bounds the worst rewind | **RULED 2026-09-28 — by derivation, and the derivation deletes the geometry it was asked to size.** `s = ⌊budget / rate⌋ = ⌊2.000 / 0.53759⌋ = **3 blocks** (§9). At `s = 3` a sparse tier holds 241 snapshots against a dense ring's 721 — **4.25 MB** bought at the price of a spacing constant, an eviction policy, a dense/sparse boundary and the reader logic across it, on an 8 GB rig. **Ruled: one dense ring over the reorg horizon; the tier geometry, the spacing constant, the eviction policy and the dense/sparse reader logic are deleted from the design.** A rule-21 reopening of this row's own Round-1 shape on its derivation's substrate — the measurement did not fill the constant in, it removed the structure the constant was for. **Scope:** the collapse deletes **`Q1`'s intra-ring geometry only**. `Q2`'s seam and its armed examiner are unaffected — frozen segments remain the landed tier, the ring remains the unfrozen tail's answerer, and the examiner grades exactly as armed at #838 |
| **CT-6 Q2** | **Alignment.** CT-1 segments are leaf-count-aligned and freeze on burial; snapshots are height-keyed. Do they stay two mechanisms, or does the snapshot subsume the unfrozen-segment recompute (F3a)? | **RULED 2026-09-22 — two mechanisms, one reader**, as proposed. Segments keep the frozen tier; snapshots cover the unfrozen tail; `root_at_count` reads whichever covers the height. Subsuming would rewrite a landed consensus-adjacent boundary to fix a cache, and C4 already forbids the second literal. **The invariant is `total, and identical where both answer` — not `total and non-overlapping`.** The freeze boundary is a *burial condition* (`SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`, `segment.rs:61`) that advances as blocks arrive, and it joins two coordinate systems — leaf-count-aligned segments against height-keyed snapshots. **Demanding non-overlap would force eviction (Q1's subject) to track freezing (this row's boundary) in lockstep, re-welding the two mechanisms this ruling separates.** Permitting overlap and requiring agreement keeps them independent, and C1's oracle already supplies the agreement test. Increment 2's red-bite states it in this form |
| **CT-6 Q3** | **Persistence.** What rides which file, and at which save points | **RULED 2026-09-22, scoped.** Snapshots and the buffer ride the **ledger**; path sets ride the sealed file at existing save points; crash ⇒ rebuild from last save + refetch (C8). **The scope is part of the ruling:** it governs the wallet's **single proving state**, which is what Q5's dissolution establishes there is. **The reason the scope is stated rather than assumed:** C6's `identity-free` is a claim about *bytes*, not *access* (C6 as amended). Public content does not make the file it rides shared, so under a second proving consumer this default would have forced either a read of another identity's sealed file — `WSS-13` relocated, the defect §6.3.3 exists to foreclose — or a duplicate of the public state. Neither was stated, and the default read as though C6 licensed the first. Q5's dissolution removes the second consumer, so the question does not arise; **this row records why the scope is load-bearing rather than incidental** |
| **CT-6 Q4** | **The advance budget** — the amortized form's own graded quantity: worst-case per-block advance as a fraction of block cadence, on the floor | **PENDING AS DERIVATION — pre-registered at ≤ 10 % of cadence, gated on a re-point.** Pre-registration ahead of the cost is methodologically what §6.3.4 rows 2 and 3 already are, and it carries their rule-21 reopener. **But the field it pre-registers against does not yet measure the quantity it names.** `per_block_advance_worst_case_s` was computed as `replay_median / REPLAY_WINDOW_BLOCKS` — a **quotient of the spend replay**, which is a legitimate *pre-build model estimate* (uniform hashing over the window) and an **illegitimate grade afterwards**, because the built advance does work the replay never did: snapshot writes and path capture. **So the pre-registration carries its own condition: increment 4 re-derives the field from the actual advance before anything is graded against this threshold**, rather than inheriting the quotient. A name that matches with a derivation that does not is the defect this catches one increment before it ships. **The re-point is built (increment 4, §10.4):** the field is now the median of a measured series `AdvanceRig` takes over the built advance — frontier fold, snapshot encode, ring commit — and the retired quotient rides beside it as `per_block_advance_retired_quotient_s` so the two are comparable within one run. Record `schema_version` bumps 2 → 3, because the field changed derivation under an unchanged name, which is this row's own defect class. **Still PENDING:** the threshold is graded on the pinned rig, and increment 4 did not run there. Increment 6 is that seat |
| **CT-6 Q5** | **Does `P` prove its own outputs?** F5 shows the two-consumer advance is assumed, not established | **CLOSED 2026-09-22 — by dissolution, not by ruling.** `P` proves nothing as a distinct actor; the proving state is **identity-blind**; there is **no second capture side**. The question therefore has **no subject**, and C6's second capture side is not built. **This is recorded as a dissolution rather than a negative ruling** because nothing was weighed: the premise F5 flagged as *assumed* is simply absent. **Rule-21 reopener, attached here to the dissolution itself rather than left as a live question:** this reopens only if a design gives `P` membership paths for proving — a substrate change, not a preference. Until then increment 5 builds one capture side and §6's graph carries no gate on this row |
| **CT-6 Q6** | **`.curvetree` retirement sequencing.** The end state deletes the file (`WSS-18`'s closure), but `P`'s pins move out via the Tier-2 P-store lane | **NAMED DEPENDENCY.** Unchanged: name the dependency, do not race it. CT-6's last increment is gated on the P-store lane's unwind of `WSS-13`; this round does not schedule it. **That lane is itself daemon-gated** (the `b_*` partition on S-PRUNE's forward pass, and `WSS-22`'s bond-add answer), which is why increment 7 sits outside this round's daemon-independent envelope while increments 1–6 sit inside it |

---

## 6. Work breakdown

Each increment separately authorized (rule 06). Ordered by what the next one
needs, not by size.

**The Q3←Q5 inversion is resolved, and it is worth recording as a graph
defect rather than a wording one.** Q3 fed increment 4 while Q5 gated
increment 5, yet Q3's *answer* depended on Q5's — a question scheduled after
the one that needed it. Q5's dissolution removes the dependency rather than
re-ordering around it; had Q5 stayed live, the correct repair was to scope Q3
to the principal and name Q5 as its reopener, **not** to wait on Q5, because
Q5's seat is the P-store lane and that lane is daemon-gated — waiting would
have re-imported the dependency this round exists outside of.

| # | Increment | Discharges | Gated on |
| --- | --- | --- | --- |
| **1** | **Registration + this document.** The `CT-1…CT-5` family row is **amended to `CT-1…CT-6`** (rule 94 §1) — not a new row, per §1.1; `CURVE_TREE_CLIENT.md` re-point | — | **Tripped 2026-09-22** by Q2 and Q3's rulings together with Q5's dissolution and Q6's named dependency: a complete Round-1 disposition, with Q1 and Q4 pending **as derivations with named inputs** rather than as open judgments |
| **2** | **The C1 oracle, height-keyed.** At every fixture height `h`, root, depth, and drained-leaf count equal `assemble_leaf_stream` + `root_from_scalars` over the leaves drained through `h - 1`. That cutoff is written in the test, not read from `drained_through`. Depth is graded at the two leaf counts where `layer_count_for_leaves` steps (`0`, and `SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH`). **Q2 examiner armed here, graded at increment 4:** `examine_tier_readings` compares a `TierReading` (root and depth) per tier. `TierCoverage::OutsideSpan` is the only non-answer; a tier error has no variant to hide in. Agreeing overlap is success, a root or depth mismatch is `Disagree`, and a height in neither `HeightSpan` is `Uncovered`. The 2026-09-23 decision-log row records why the examiner is armed before its tiers exist | §6.3.4 row 4; Q2 | Q2 (**ruled**); Q1's *shape* only — its constants are not inputs to the oracle |
| **3** | **Per-transaction reconstruction reuse.** `drained`/`layers` once per tx, `gindex → drain-position` index | **Closeout (a)** — F3b | 2 |
| **4** | **The snapshot ring + advance — BUILT (§10).** One dense ring over the reorg horizon, total by construction (`Q1` RULED 2026-09-28, §9) — no tiers, no spacing, no eviction. `shekyl_curve_tree::frontier::Frontier` advances inside `ingest_block`; the ring is the `frontier_snapshots` table of the wallet's own `LeafStore`, written and evicted in the block's own transaction; `root_and_depth_at` reads it for in-horizon heights and falls through to `root_at_count` elsewhere. `per_block_advance_worst_case_s` is **re-derived from the built advance** (Q4). The increment-2 examiner grades the real segment tier against the real snapshot tier, **unmodified** | **Closeout (b)** — F3a | 2, 3; Q2, Q3 (**ruled**); **`Q1` RULED by derivation (§9); `Q4` pre-registered with its re-point as a landing condition** — the gate is open |
| **5** | **Path capture** — **one capture side, not two** (Q5 closed) — and the reorg refusal path (C7) with its rule-82 copy. **C7 BUILT 2026-09-30** (the fork walk and the tree-tip backstop share one comparison; the hash window holds `W` plus the kept block; `ResyncRequired` is `-29211`; a rescan sets `history_cleared`; §10.3's framing corrected); **path capture is BUILT** — its *instrument* landed first (the structural red-bite, the O(chain) before-figure, and §11.6's gate spec, PRs #927/#931), and **§11.6's integrity gate is BUILT**: `verify_path_against_its_branches` recomputes the root from an assembled path's own branches and refuses with `PathRootMismatch`, so the artifact is checked rather than the store compared with itself. **The capture mechanism is BUILT** (PR #945): the fold captures every chunk that closes over a registered output, reconciliation backfills what a late registration is owed, and assembly reads captures and the frontier snapshot without touching `entries` — `assembly_today_depends_on_every_foreign_leaf` is at **state 3 of 3** as `capture::a_path_from_captures_equals_the_rebuilt_one_with_every_foreign_leaf_gone`. **The registrant is BUILT** (PR #966, its own by rule 19) and **the rebuild is deleted**: the curve-tree actor registers a spend's inputs in the same handler invocation that assembles them, and the refresh's ingest offers everything the wallet will hold once it has merged — ledger, the persona's funding outputs, and that result's own detections — between its rollback and its first fold, so a found output is captured as it folds and a resume is a mass late registration, cheap because a held pair is `AlreadyHeld` — §11.12. `assemble_paths` has no fallback; an unregistered input is refused by name. The §6.3.3 precondition this row used to carry is **discharged** — that sentence was reconciled on `dev` (`WALLET_SIDE_STORE.md` §6.3.3 now reads *"There is one capture side, not two"*), so nothing waits on it | §6.3.3; C7; §11.6 | 4. **Q5's gate is removed**: the dissolution leaves nothing for this increment to wait on |
| **6** | **Re-grade rows 2 and 3** on the amortized form, same harness, same rig — **and it is also `Q4`'s only seat.** Increment 4 re-derived the advance field and measured it off-rig; a fraction of cadence computed anywhere but the pinned Pi 4 is a property of the machine that computed it (rule 76). The blocker is the board, not the code | §6.3.4; Q4 | 4 |
| **7** | **`.curvetree` retirement** | `WSS-18` | **P-store lane** (Q6) |

---

## 7. Decision log

| Date | Decision | Ground |
| --- | --- | --- |
| 2026-09-20 | **Discharge, not a new family.** `CT-6` extends `CT-`; `WPS-` not minted | §1 — the tree already names the work; one lane, one family; rule 94 registration is irreversible-ish |
| 2026-09-20 | **Item 3 removed from the round, not answered** | F1 — landed, privacy-canonical, reversion-clause-carrying. The brief's default would have moved `REF_ANCHOR_AGE` from 6 to 5 |
| 2026-09-20 | **The reorg horizon is consumed as a constant, never restated** | F2 — `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` is `ARCHIVAL_REORG_DEPTH_BLOCKS` from one JSON authority |
| 2026-09-20 | **The round's subject is the unfrozen tail, not "root-at-`h` is unsolved"** | F3 — `root_at_count` amortizes past the freeze horizon and recomputes ~29 segments per call inside it |
| 2026-09-20 | **Item 5 becomes `CT-6 Q5` rather than a design task** | F5 — `WSS-Q1`(a) ruled `P`'s store is serving-only; a second proving consumer is assumed, not established |
| 2026-09-22 | **`Q2` RULED — two mechanisms, one reader; invariant is `total, and identical where both answer`** | The freeze boundary is a burial condition joining two coordinate systems; non-overlap would couple eviction to burial and re-weld the mechanisms the ruling separates. C1's oracle supplies the agreement test |
| 2026-09-22 | **`Q3` RULED, scoped to the wallet's single proving state** | C6's `identity-free` is a claim about bytes, not access. The unscoped default would have forced a read of another identity's sealed file (`WSS-13` relocated) or a duplicate of the public state |
| 2026-09-22 | **`Q5` CLOSED by dissolution; the rule-21 reopener attaches to the dissolution, not to a live question** | `P` proves nothing as a distinct actor; the proving state is identity-blind; no second capture side exists, so the question has no subject. Recorded as a dissolution because nothing was weighed |
| 2026-09-22 | **`Q1` and `Q4` are PENDING AS DERIVATIONS, and the banner says so per row** | `s` is derivable from §6.3.4 row 2's already-ruled budget once the rig supplies two terms; `Q4`'s threshold needs its field re-pointed from the replay quotient to the built advance. A banner reading "ruled" over either would put the map ahead of the territory |
| 2026-09-28 | **`Q1` RULED by derivation, and the derivation deletes the geometry** — one dense ring over the reorg horizon; tier, spacing, eviction and dense/sparse reader logic removed | §9. `s = ⌊2.000 / 0.53759⌋ = 3`; at `s = 3` the tier buys 4.64 MB and costs four moving parts (**that figure was corrected to 4.25 MB on 2026-09-29** — §9.4's dated note; the row keeps what the 2026-09-28 derivation computed, and the ruling is unchanged either way). Rule-21 reopening of the row's own Round-1 shape on its derivation's substrate. Scope: `Q1`'s intra-ring geometry only — `Q2`'s seam and examiner unaffected |
| 2026-09-28 | **Increment 4 built: one dense ring, the examiner unmodified, `Q4`'s field re-derived** | §10. The ring is a store table rather than a RAM structure because Q3 rules snapshots ride the ledger and because a rollback then deletes ring rows in the same transaction that truncates the leaves. The examiner is graded in **two passes** — one where the segment tier answers the whole chain (the pass that can `Disagree`) and one where it answers nothing, which is what this fixture's freeze cursor actually is (the only pass in which a hole reaches `Uncovered`) |
| 2026-09-23 | **`Q2`'s red-bite is armed at increment 2 against an injected subject, not deferred and not placeholdered** | Both offered shapes were defective: a placeholder is green by construction, and deferring it makes the subject's author write its own examiner. The armed examiner is `examine_tier_readings`. Each tier contributes a `TierReading` (root and depth together — C3) or `TierCoverage::OutsideSpan` where its `HeightSpan` does not cover the height. Agreeing overlap is success; a root mismatch and a depth mismatch are both `Disagree`; a height in neither span is `Uncovered`. A tier that errors does not fit `TierCoverage`, so a failure cannot be recorded as a gap. Increment 4 passes the segment tier and the snapshot tier through this function |
| 2026-09-22 | **The `Q3`←`Q5` graph inversion is recorded, not merely fixed** | Q3 fed increment 4 while Q5 gated increment 5, yet Q3's answer depended on Q5's. Waiting on Q5 would have re-imported the daemon dependency this round sits outside of |

---

## 9. `Q1`'s derivation — and why it deletes the thing it sized

**Ground:** the pinned-rig session, [`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md)
§7.3, records under `docs/benchmarks/wss-q1b/` at schema v2. **Every input below
is a ruled budget or a converged measurement.** The memo contains one proposal,
ruled at the end, and no judgments in the chain.

### 9.1 Ruled inputs

- **The spend-edge budget** — `max(2 s, 15 % of proving)`, ruled 2026-09-19,
  graded at worst-case density on the pinned rig (§6.3.4 row 2).
- **`Q1`'s Round-1 shape** — dense over the reference window plus margin, sparse
  beyond, constants as stated judgments with rule-21 reopeners.

### 9.2 Measured terms

**Proving denominator: `6.055 s`** on the ruled rig, converged, reproduced
across four runs at 6.052–6.062 s. The 15 % arm is `0.908 s`, so **the 2 s
absolute floor binds** — as it has on every machine measured, across a 5.5×
speed range.

**Per-block replay rate: `537.59 ms`** at worst-case density.

| Window | Tail median | Per block | Converged |
| --- | --- | --- | --- |
| 50 blocks | 26.938 s | 538.75 ms | yes, `n = 6` |
| 100 blocks | 53.680 s | 536.80 ms | yes, `n = 6` |
| 200 blocks | 107.443 s | 537.21 ms | yes, `n = 6` |

Flat to **0.36 %**. Three properties make the rate usable rather than merely
measured:

1. **Full-scale cross-check.** `537.59 ms × 725 = 389.750 s` against the capped
   full-window run's `388.822 s` — **0.24 %**. The series that could *not* be
   graded becomes the proof that the graded quantity extrapolates: linearity is
   verified across **50 → 725 blocks**, not extrapolated 14× off the short end.
2. **One memory regime.** Working sets are 6.76 / 13.52 / 27.03 MB against the
   A72's **1 MB** L2 — every window is **≥ 6.76×** past it, as is the 98 MB full
   window. No cache cliff hides between the measured range and the extrapolated
   one.
3. **Thermal drift excluded by direction, not by assurance.** The smallest
   window — the only one whose early samples could clear
   `MIN_CONDITIONING_SECONDS` while the board was still cool — came in
   **fastest** (538.75 ms). A cool-board bias produces the opposite sign. And at
   ~27 s per iteration, six iterations is 162 s against a 60 s conditioning
   floor, so convergence could not be declared before the board was warm.
   Tail medians are compared rather than whole-series medians, because the
   graded quantity under a sustained-thermal pin is the steady-state tail.

### 9.3 The derivation

`s = ⌊budget / rate⌋ = ⌊2.000 / 0.53759⌋ = **3 blocks**` at worst-case density.

### 9.4 What that licenses — the structure, not the constant

At `s = 3` over the reorg horizon, the frontier encoding to **8 840 B**
(the leaf count, then one partial chunk per layer, each one child short of folding —
§10.1 derives it):

| | Snapshots | Size |
| --- | --- | --- |
| Sparse at `s = 3` | 241 | **2.13 MB** |
| Dense over the horizon | 721 | **6.37 MB** |

The two-tier structure buys **4.24 MB** on an 8 GB rig, and costs a spacing
constant, an eviction policy, a dense/sparse boundary, and the reader logic that
chooses across it.

> **Corrected 2026-09-29.** This section was written on 2026-09-28 reading
> **9.44 KB** / 2.32 MB / 6.96 MB. That per-snapshot figure was a transcription
> of §6.3.2 row 4 that **inverted its Selene and Helios counts** above the leaf
> chunk — three 1 216 B chunks where the widths give three 576 B — and counted
> every chunk at capacity. Row 4 is correct as written: **9 024 B for a path**.
> A frontier is not a path; it holds each partial chunk one child short of
> folding. The same day's first correction encoded that to **8 848 B** / 6.38 MB
> / a **4.25 MB** delta, counting an 11 B header and a width byte per partial
> layer, and moved the row counts for a second reason: the retained run
> `[h - horizon, h]` is **closed**, so the ring holds `horizon + 1` = 721 rows,
> not 720. Those header and width bytes restated `expected_shape`, so they left
> before schema 6 froze. The encoding that ships is the 8 B leaf count plus the
> scalars and nodes that count implies: **8 840 B**, a dense ring of **6.37 MB**,
> and a delta of **4.24 MB** (8 840 × (721 − 241)).
> **The ruling does not move** — each correction makes the dense ring cheaper
> than the figure it was ruled against, so the argument it was ruled on only
> strengthens.

**RULED 2026-09-28: one dense ring over the reorg horizon**
(`SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`, cited and never restated — C4). The tier
geometry, the spacing constant, the eviction policy and the dense/sparse reader
logic are **deleted from the design**, and `s` ceases to exist as a quantity the
round carries.

**The rewind bound follows from totality, not from the spacing.** With a
snapshot at every height in the horizon, the worst in-horizon rewind is one
block's replay — **0.538 s, 3.72× inside the 2 s budget**. That bound is a
consequence of the ring being *total over the horizon*, which is precisely the
property `Q2`'s armed examiner already grades; it is not a separate obligation
increment 4 must invent.

This is a **rule-21 reopening of `Q1`'s Round-1 shape on its own derivation's
substrate**. The measurement did not fill in the constant — it removed the
structure the constant was for.

### 9.5 Scope, stated so increment 4 inherits it correctly

**The collapse deletes `Q1`'s intra-ring geometry only.** `Q2`'s seam and its
armed examiner are **unaffected**: frozen segments remain the landed
consensus-adjacent tier, the ring remains the unfrozen tail's answerer, and the
examiner grades the ring against the C1 oracle exactly as armed at #838. Its two
subjects are `row.segment` and `row.snapshot` — the **moving freeze boundary** —
and neither is an intra-ring sparse/dense seam. Nothing `Q2` ruled and nothing
the examiner guards lapses here.

### 9.6 Standing conditions

- **`Q4` is unchanged.** `per_block_advance_worst_case_s` — of which `537.59 ms`
  is now the rig-measured **pre-build bound** — is **re-derived from the actual
  advance** before anything is graded against `Q4`'s threshold.
  **Discharged as a derivation by increment 4 (§10.4); still owed as a grade,
  which is increment 6's.**
- **Reopeners.** A material prover-pin move re-grades the denominator (the
  existing §6.3.4 clause). A change to the leaf-hash path re-measures the rate.
  The ring's 6.37 MB is bounded by construction and carries no reopener.

### 9.7 Effect

Increment 4's gate opens on a **simpler subject than the round planned for**:
one ring, total over the horizon, one seam — and that seam is the one already
guarded by an examiner armed before its subject existed.

---

## 10 — Increment 4 as built

**Status:** BUILT 2026-09-28. Every row below states what **is** in the tree,
not what was planned. The one thing this section does **not** carry is a grade
against `Q4`'s threshold — see §10.4.

### 10.1 The ring

`rust/shekyl-curve-tree/src/frontier.rs`. A `Frontier` is the partial chunks of
an append-only curve tree: the leaf scalars not yet hashed into a layer-0 node,
and at each layer `k` the layer-`k` nodes not yet hashed into their layer-`k+1`
parent. Its `leaf_count` is **intrinsic** — advanced by `push_leaf`, and the
number `depth()` is taken from — so a frontier cannot be paired with someone
else's `n` (C3).

**It is not a second composition.** Every fold is a call into the canonical
primitives: `hash_grow_selene` for a leaf chunk, `try_promote_to_layer` for one
layer step, and `try_build_upper_layers` for the close — which is where the
*"single node at layer ≥ 1"* stop condition comes from rather than from a
second copy of it. The pair is nonetheless a *reachable* disagreement, so it is
graded against `build_layers` at every count through two leaf-chunk folds and
at the first cascade, and height by height by the `Q2` examiner.

**Capacity is the parent layer's width**, `chunk_width(k + 1)` — the off-by-one
this design offers, and the subject of its own assertion.

**Size, derived and not restated.** A production-depth frontier whose every
partial chunk is one child short of folding encodes to
`8 + (LEAF_CHUNK_SCALARS − 1)·32 + Σ_{k<5} ((chunk_width(k+1) − 1)·32)`
= **8 840 B**. §6.3.2 row 4 states **9 024 B**, and is correct — but it sizes a
**path**, and a frontier is not a path: it holds each partial chunk one child
short of folding and carries an 8 B leaf count, so the two differ by 184 B. Row 4's
one overreach is the sentence that follows its arithmetic, “the frontier is the
same size”; it is corrected there. The **9 664 B** §9.4 first carried was neither
figure but a transcription of row 4 that inverted its Selene and Helios counts,
corrected and dated in place. Over the horizon — a **closed** run, so
`horizon + 1` rows — this is **6.37 MB**.

**Corrected 2026-09-29, twice.** The first pass quoted **8 848 B** / 176 B /
6.38 MB, which still stored a scalar count, a layer count, and a width byte on
each partial layer. Those fields restated `Frontier::expected_shape` and left
before schema 6 froze. No clause of the ruling moves.

### 10.2 Where it persists (`Q3`)

The `frontier_snapshots` table of the wallet's **own** `LeafStore` — the public,
identity-free proving state, which is what `Q3` ruled rides the ledger. One row
per height, keyed by a `BlockHeightKey` whose distinct redb `TypeName` is what
stops a tree position or a gindex indexing it.

**The bound is the write, not a policy.** `append_block_with_snapshot` inserts the
height it ingests and, in the same statement, removes everything *below*
`height − SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` — so there is no eviction policy
for anything to hold (`Q1` RULED 2026-09-28). `append_block_deltas` performs the
leaf, pending, and tip writes and cannot insert a ring row. An optional snapshot
on that path would let a caller omit the row the ring's totality depends on.

**The run is closed at the bottom, and the fencepost is derived rather than
chosen.** A reorg of depth `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` *replaces* that
many blocks, so its **fork** sits at `tip − horizon` — the block the replaced
ones build on — and §10.3's rewind restores from the row **at** the fork. A
half-open `(tip − horizon, tip]` would drop exactly that row and send the
deepest legal rewind down the fold path, which is the one case the bound exists
for. So the ring holds `[tip − horizon, tip]`: one height per replaceable block
plus the one they fork from. The wrap test takes its expected span from that
sentence and not from the delete's own bound, which would have asserted the
implementation back at itself.

**`SCHEMA_VERSION` 5 → 6, and the reason is C8.** **A pre-ring (≤5) store is
refused at open and re-synced.** `check_schema_version` runs before
`init_tables`, so a ≤5 store never reaches the code that would create
`frontier_snapshots`; there is no one-way upgrade and none is wanted
pre-genesis (rule 15). That refusal *is* the upgrade path.

What the ring being a **cache** buys is therefore not compatibility but the
absence of migration code: after the re-sync the table starts empty, every
height falls through to `root_at_count`, and the ring refills as blocks
arrive. Nothing has to be reconstructed.

**Corrected 2026-09-29.** This paragraph read "*Reading* a pre-ring store
needs no migration", which described a path the exact-version guard makes
unreachable — the store is refused before any read of it happens. The bump's
*motivation* was stated correctly and its *consequence* was not.

The motivation is a pre-ring **writer**: it cannot see
`frontier_snapshots`, so it can roll back and replay while leaving rows above
the new tip untouched, and a stale row can carry the leaf count §10.3's C3
check expects while composing the abandoned branch's root. Nothing in-band
stops a writer that cannot see the table, so the version cell is the only
mechanism that closes it — and refusing the store is precisely what C8 already
prescribes: *recovery is refuse-and-resync, never a migration*.

**Corrected 2026-09-29.** This section read "no store schema-version bump, and
the reason is C8" until the review round. That inverted C8: a bump costs a
resync, and a resync is the recovery C8 names.

**The horizon is inherited, not owned — and the inheritance should be recorded
as one.** `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` is
`ARCHIVAL_REORG_DEPTH_BLOCKS` (`segment.rs`), which makes the ring the third
reader of that config key. But the ring's retention is justified here as *"the
deepest legal reorg"*, and that is the **reorg cap's** job — which #861 moved
onto `RuleSet::reorg_cap`. The two are equal today at 720, so the ring is
correct; they are equal by inheritance rather than by identity, and
`SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` is an armed FAKECHAIN override, so a
network that moves its cap through the rule set would not move the ring's
horizon with it.

**Nothing changes here.** Re-homing this reader belongs to #861's split, not to
an increment whose subject is the ring — the named blocker is that the split
has not landed its re-homing pass. Recorded so the ring appears on the list of
readers when it does, rather than being found by the first divergence.

### 10.3 Serving and rewinding

`root_and_depth_at` reads the ring first. A hit checks the snapshot's **own**
leaf count against the drain index's and **refuses** on a mismatch — root and
depth are both read off that count, so a snapshot over the wrong `n` would be
self-consistent and wrong. A miss falls through to `root_at_count`, unchanged.

**The frozen tier is untouched.** `root_at_count` is not modified and
`reference.rs` is not touched (F1).

**Why the dispatch is one level above §6's wording.** §6's increment-4 row says
*"`root_at_count` reads it"*. `root_at_count` is **count**-keyed and the ring is
**height**-keyed, and C3 pins root and depth to one `n` *at a height*; putting
the dispatch inside `root_at_count` would mean threading a height through a
count-keyed API, which is the same seam one level lower and one type worse. The
reader §6 names is `root_and_depth_at`, and `root_at` already delegates to it,
so both production read paths go through the one dispatcher.

**A reorg deeper than the horizon is not refused here, and that is C7's
seat, not this increment's.** A `rollback_to_fork` below `tip − horizon`
succeeds today by folding the whole drained prefix. Increment 5 owns C7's
refusal and its rule-82 copy; what increment 4 owes it is the seam, which is
the ring's span.

**Corrected 2026-09-30, when increment 5 built it.** This paragraph read
*"correct, slow, and loud about nothing"*, which understates the store's
behaviour in one direction and overstates what C7 may change in the other.
`truncate_internals` **deletes frozen segment rows**, so a rollback below
`F = tip − W` unmakes sealed state rather than merely re-folding a large
prefix. And the store is *required* to do that correctly — F9 pins it, and the
replica generator (`shekyl_curve_tree_replica_rollback_to_fork`) forks
arbitrarily deep on purpose — so **C7's bound is not a guard on the
primitive.** It is a policy about whether a *wallet refresh* may ask for such a
rollback. Two seats share that comparison (`engine::reorg_finality`): the
producer's fork walk, and the ingest backstop against the tree tip, because
the tree and the ledger do not share a tip. Both statements hold at once, one
per layer: the store must perform a deep truncation correctly; the wallet must
never request one. A scan that overlaps the tree without a rewind — a rescan — uses that same comparison on the shared root: a match leaves the file, a keep inside `W` folds, and a walk past `W` or off the scanned roots refuses. The caller's remedy removes the file and then clears scan history. The walk reads the ledger's hash record before ingest, so the file alone leaves the next refresh on the same refusal.

**Rewind.** `truncate_internals` — the shared core under both
`rollback_to_fork` and `truncate_from_tree_position` — deletes every ring row
above the new tip **inside the caller's transaction**, so no committed store
holds a row for a height it has rolled back past. The live frontier is then
restored from the ring's row at the fork: an `O(depth)` decode, which is what
makes an in-horizon rewind *the fork's snapshot plus the replay forward* rather
than a fold over the whole drained prefix. The fold remains, and is the path
for a store the ring does not cover.

### 10.4 `Q4`'s field, re-derived

`per_block_advance_worst_case_s` is now the median of a **measured** series over
the built advance — frontier fold, snapshot encode, ring commit — through the
harness's existing `sustained_within_conditioned`
(`shekyl-wss-q1b-bench/src/advance.rs`). The retired quotient rides beside it as
`per_block_advance_retired_quotient_s` so the two are comparable **within the
run that produced them**. The measured advance is what a later run may compare.
The quotient is an observation of that run's replay; it does not speak for the
pinned rig. Record `schema_version` bumps **2 → 3**: the field changed derivation
under an unchanged name, which is `Q4`'s own defect class.

**A second defect the re-point surfaced.** The retired quotient divided by
`REPLAY_WINDOW_BLOCKS` — the constant — while the corpus size is a `--window-leaves`
flag. At the default window the two agree by construction; under an override the
field divided a shrunken replay by the full window and emitted the result under
a worst-case name. The denominator is now `replayed_blocks`, the blocks the
corpus actually covers (`window_leaves / leaves_per_block`).

**What is measured and what is not.** One iteration is one worst-case block's
advance. It does **not** include the leaf and pending table writes, block decode
or leaf collection: those are unchanged by this increment, and the quantity
`Q4` pre-registers is the advance the amortization adds and removes — the same
scope `537.59 ms` was modelled at, which also counted no table writes.

**The grade is not here.** `Q4`'s threshold is a fraction of block cadence on
rule 76's floor. Increment 4 ran off-rig, so the record carries the figure, the
ratio and `rig.grading: false`; **increment 6 is the seat for the graded run**,
and the blocker is the board rather than the code.

**What the off-rig run says, and what it does not.** One run on an otherwise
idle x86_64 box (`--window-leaves 105600`, 1 056 leaves/block at depth 6, 586
timed blocks after a 721-block untimed prefill —
`docs/benchmarks/wss-q1b/spend_edge_20260929T133841Z.json`). The board is
attested by the run's **own** controls rather than by the operator: two
dense/sparse pairs doing identical work, diverging at most **1.6 %** against a
10 % bound (`per_block_advance_load_control`).

| Term, same run | Value |
| --- | --- |
| Measured advance | **102.75 ms/block**, converged |
| Retired model, same run | **102.03 ms/block** |
| Measured ÷ model | **1.01×** |

> **Two records superseded here, and the second one retires a claim of mine.**
>
> The **2026-09-28** record read 124.72 / 180.63 / **0.69×**. Its ring was never
> full — the first row cannot fall out until block 721 and it converged at 479 —
> *and* its model term was 63 % slower than this one's for identical work, which
> is a loaded board. Both grounds, not just the first.
>
> A **2026-09-29** replacement read 105.11 / 110.95 / **0.95×** and narrowed
> §10.4's old claim that the ratio "is a property of the work and not of the
> machine" to: *the ratio travels from a quiet board.* **That narrowed claim is
> now refuted too.** Both of those runs were quiet by this section's own test,
> and their ratios are **6.3 % apart** (0.95 vs 1.01), because the model term
> kept moving between them — 110.95 → 102.03 — while the advance barely did.
>
> **So the ratio is retired as a travelling quantity, not narrowed again.** What
> reproduces is the *measured advance*: 105.29 / 105.11 / 102.75 across three
> runs, a **2.5 %** spread, against a model term that moved 77 % across the same
> three. The advance is `fsync`-bound and stable; the replay is
> memory-bandwidth-bound and is not, and no mechanism for its residual drift
> between two quiet runs is offered here because none has been measured. Any
> future statement of the form "the ratio shows X" needs its own evidence; this
> section no longer supplies it.
>
> The superseded figures are kept above as what was measured. A third
> narrowing would be the wrong move: the claim has now failed twice, and the
> quantity that keeps surviving is the one the increment actually built.

**The direction the harness predicted no longer holds, and that is worth
saying plainly.** `replay`'s own `proxy_note` says the model is *"net an upper
bound, since `build_layers` rehashes every upper node where a frontier advance
touches one per layer"*. At **1.01×** the built advance sits *fractionally
above* it, so the model is **not** an upper bound on this run — the earlier
0.69× reading that appeared to confirm the note came from the loaded board.
The gap is 0.7 %, well inside the drift the model term shows between quiet
runs, so this is **not** a claim that the note is wrong either: it is a claim
that a 0.7 % ordering across two quantities of differing stability establishes
nothing in either direction, and the note should be re-tested on the rig rather
than treated as confirmed.

**No Pi figure is derived**, and now for two reasons rather than one: the
advance has an `fsync`'d ring commit in it, which does not scale with the A72
the way curve hashing does, *and* the ratio such an extrapolation would use has
been retired above. `537.59 ms × <ratio>` was always an arithmetic with one
term that does not travel; it is now an arithmetic with two. The pre-build
bound stands until the rig re-runs it.

**A contamination lesson that is now a gate.** Every figure this section has
had to retire was retired for board state, so the controls are read on this
side too: `LoadControl` carries the worst dense/sparse divergence into the
record, and a **graded** run whose board is not quiet is refused rather than
reported (armed here; increment 6 is the run it grades). A run can no longer be
read as clean after the fact — the evidence rides with it. The first off-rig
attempt had the depth-5 sparse/dense control diverge **111 %** and refuse the
sparse path; a
second run on a quiet box gave **−1.0 %** on the same arm. The first was taken
while this worktree was building. A timing harness measures the box it is on,
including whatever else is on it.

### 10.5 The examiner

`examine_tier_readings`, `TierReading`, `TierCoverage`, `TierFault` and
`HeightSpan` are **unmodified**. What increment 4 replaced is the *source* of
the rows: `InjectedTier` gives way to the landed `root_at_count` composition on
one side and the ring on the other. The injected-tier tests stay — they are the
proof the examiner's three verdicts fire, and a real tier cannot prove that,
because a real tier that disagrees is a defect being shipped.

**Two passes, because one of them cannot see a hole.**

| Pass | Segment tier | What it can catch |
| --- | --- | --- |
| Agreement | the landed `root_at_count` over the whole ingested chain | `Disagree` — the ring's root or depth against the composition's, at every height |
| Totality | `OutsideSpan` at every height, which is what this fixture's freeze cursor **is** (asserted, not assumed) | `Uncovered` — with the segment tier answering, the store masks every hole |

Neither tier is read through `root_and_depth_at`. That is the *dispatcher*: it
picks one tier and returns it, so feeding it to both columns would compare the
picked tier to itself.

### 10.6 The one axis a real-data red-bite cannot reach

On the production read, C3 forces the snapshot's leaf count and the client's to
be equal, so a depth taken from the wrong one is **invisible there**. The tier
reader the examiner consumes has no such check, and the weld is asserted against
directly — a snapshot over a count on the far side of a layer step must report
that count's depth. Recorded here rather than left as a green that proves less
than it looks like it does.

## 11 — Increment 5's capture half: the instrument, before the subject

`C7` is increment 5's other half and is built (§4, row C7). This section is the
capture half, and what it records is an **instrument**, not capture. Capture has
no code yet. The instrument came first deliberately: capture's claim is a
*quantitative* one, and a claim graded by a criterion first seen after the
change has been fitted to the curve it is meant to judge.

### 11.1 Nothing measured the subject

`assemble_paths` had never been timed. The spend-edge rig proves against
**synthesized** paths (`shekyl-wss-q1b-bench`'s `fixture::synth_sparse_path`),
so assembly is bypassed and its cost was unmeasured — which also means
"today's slope is the evidence for capture" was, until now, an argument with no
measurement behind it. `shekyl-wss-q1b-bench`'s `assembleedge` module and
`assemble_edge` bin drive the real, store-backed `CurveTreeClient`.

### 11.2 The cost is O(chain), and every neighbouring figure is windowed

This is the finding, and it corrects a line in production:

> `assemble.rs`: "…`n` the drained leaf count (765 600 at the graded worst
> case)."

765 600 is `worst_case_window_leaves` — the **725-block replay window**, about
one day of chain at a 120 s target. Assembly is not bounded by it.
`CurveTreeClient::entries` is append-only (`extend` on ingest, replaced
wholesale only by a rollback's rebuild, never `retain`ed, `drain`ed or
`truncate`d); `rebuild_from_store` reloads the **whole** drained set; and a
resume from a store whose frozen segments were pruned is refused outright
(`ClientError::ResumeFromPrunedStore`, `F5`) rather than resumed from a partial
one. Every drained leaf since genesis is in memory, and every spend rebuilds
every layer over all of them.

**Measured 2026-10-02**
(`docs/benchmarks/wss-q1b/assemble_edge_20261002T052942Z.json`). The per-leaf
cost is **flat at 220–221 µs across every arm**, which is the signature of a
pure linear term:

| arm | `n` | depth | `k` | s/call | µs/leaf |
| --- | --- | --- | --- | --- | --- |
| `rung_below` | 467 856 | 4 | 2 | 103.43 | 221.1 |
| `rung_floor` | 467 857 | 5 | 2 | 102.91 | 220.0 |
| `rung_top` | 765 600 | 5 | 2 | 169.36 | 221.2 |
| `input_cap` | 765 600 | 5 | 8 | 168.86 | 220.6 |

**The cost is `n`, and almost nothing else.** Three readings say so:

- **Linear in `n`.** The population ratio across the same-rung pair is
  `1.6364`; the cost ratio is `1.6457` — **0.57 % from perfect linearity**.
  The criterion read `SameRungSlope` at 64.6 % against its 10 % bound, which
  is the expected pre-capture reading and now a measured one.
- **Depth costs nothing measurable.** The cross-rung pair differs by **one
  leaf** and one whole layer, and by `0.995×` in cost. Isolating depth from
  population was the point of choosing a rung floor and its predecessor, and
  the layer term does not survive it.
- **`k` is lost in `n`.** Raising the owned count from 2 to `MAX_INPUTS` at a
  fixed population costs **−0.30 %** — cheaper, i.e. inside the noise. That is
  `#842`'s `n + k` measured for the first time, and it says `k` is not a term
  at this scale.

**Dated note (registrant PR).** Everything above is the record of the
*rebuild* era: `assemble_paths` no longer rebuilds, so the per-spend figures
in this section describe a cost the wallet no longer pays. A spend whose
inputs were registered by the refresh assembles from captures; one whose
inputs were never registered pays one reconciliation at the actor (span-
bounded, §11.10), never the chain. The instrument now times the capture
path, and the figure it owes is increment 6's graded run on the floor.

### What the control covers, and what it does not

**This is an observational before-figure, not an attested one.** The record's
`rig.attested` reads `["not requested"]`, and the word *attested* in this
project means the rule-76 rig pins, which this run neither requested nor
carries. The claim was overstated when this section first landed and is
corrected here.

What the run does establish:

- **every series converged** — each arm was internally stable across its own
  timing window, and `stopped_because` says `converged` for all four;
- **the board was stable at the close** — `rung_top` was re-timed back to back
  on the same client, diverging **0.7 %** against a 5 % bound.

What it does **not** establish is the comparability of samples taken hours
apart. The arms are timed in sequence across 3 h 38 m, and the control brackets
only the last of them. So the same-rung, cross-rung and `k` readings rest on
*uncontrolled* between-arm stability. The design makes that deliberate rather
than accidental: a control spanning the arms would mean holding `rung_top`'s
client resident while `rung_floor` is timed, which is the residency bias §11.5
records two discarded runs for.

There is a bracket that escapes that trade, and **increment 6 should carry it**:
re-time a *small* fixed arm — the depth-4 rung floor is 25 993 leaves, a few
seconds a call — between every measured arm. Same `assemble_paths` work, so one
sensitivity profile; a working set around 3 % of the top arm's, so the
residency it reintroduces is not the residency that biased those runs. That
brackets each compared sample for minutes, not hours. It is what would turn a
reading like this one into a controlled one, and it is the control a *graded*
capture figure will need.

Corroboration, flagged as such: per-leaf cost agrees to **0.5 %** across four
arms measured hours apart, which a materially drifting board would be unlikely
to produce. That is **not** an independent control — per-leaf constancy is the
proposition under test, so a drifting board and a non-linear cost could in
principle compensate. It is weak evidence pointing the same way, not a
substitute for the bracket.

### Whose seconds these are

**221 µs/leaf is the staker-class x86 host's figure, and nothing else's.**
The host *role* is named beside every number below — rule 37 keeps the host
itself in `shekyl-dev` — because this project uses *floor* for the Pi (rule
76), and `min_leaves_for_depth(6)` is also called a rung **floor**. An
unqualified "floor" beside a duration invites a reader to merge a staker
measurement with a floor-device one. They are different numbers on different
hardware.

Projecting each per-leaf rate at 760 320 leaves/day:

| assembly population | `n` | staker-class x86 (observed, 221 µs/leaf) | floor device, projected (509 µs/leaf) |
| --- | --- | --- | --- |
| replay window, ~1 day of chain | 765 600 | **169 s** (measured) | ~6.5 min |
| `min_leaves_for_depth(6)`, ~23 days | 17 778 529 | ~65 min | ~2.5 h |
| one year of chain | 277 516 800 | ~17 h | ~39 h |

The staker column is the **observed before-figure**. The floor-device column is
a **projection and only that**: 509 µs/leaf is `537.59 ms` ÷ `1 056`
leaves/block, the per-block replay rate §9 already carries, and no Pi has run
this instrument. It is here to size the gap, not to grade anything.

**Increment 6 does not owe a Pi measurement of today's cost.** Rule 76 pins a
*graded* figure to the floor device, and what increment 6 grades is capture —
the form that replaces this one. Measuring O(chain) on the Pi would spend half
a day of a contended host to price code that is being deleted.

These numbers are **worse** than the ~102 µs/leaf this section previously
carried. That came from a busy dev box with no control at all; this host is
slower, and is a **virtualised** x86 guest (`QEMU Virtual
CPU`), so the constant stays machine-specific. What travels between hosts is
the **shape** — flat per-leaf cost, therefore linear in chain length — and the
mission argument rests on the shape, not the constant. A 2.3× spread between
two x86 hosts changes no conclusion that "linear fails at some chain age"
already supports.

**Provenance caveat on this record.** Its `environment.git_revision` reads
`1ab4664cb`, one commit behind the binary that produced it. The binary was
cross-built from the tree that became `11a0c8451` while that change was still
uncommitted, and Cargo reused the cached build-script output — a `.rs` edit is
not one of the files `build.rs` watches — so the stamp is both stale *and*
missing its `-dirty` suffix. `build.rs` anticipates "a clean revision behind a
dirty prover" for *dependency* edits and names runtime capture as the
mitigation, but `AssembleEdgeRecord` carries only the build-time stamp. The
delta `1ab4664cb..11a0c8451` is confined to `bin/assemble_edge.rs`'s
plan-resolution wiring and does not touch the measured path, and the deployed
binary was confirmed to carry that change behaviourally (both modes refused an
unrepresentable `--rung`). The measurement stands; the stamp is wrong, and
`FOLLOWUPS.md` carries the remedy.

**This is a mission-hierarchy failure, not a budget miss.** Commitment 3 — the
system must outlast the team — is the binding one: a cost linear in chain
length fails it at *some* chain age whatever the present budget says, so the
remedy cannot be a faster board. That is the argument for capture, and it is
stronger than the slope framing this increment was opened under.

It also means **"worst case" cannot be derived here.** It is a ruling about how
old a chain the wallet must still be able to spend on. Until that is ruled, no
plan in the instrument is the graded plan: `plan_at_replay_window` is named for
what it measures, `plan_at_depth` establishes shape on a cheap rung, and
`AssembleEdgeRecord::plan` says which ran. **Blocked on that ruling (rule 22).**

### 11.3 Three depths, which are not one

A conflation worth keeping separate, because it already produced a wrong
reading once in this session:

| axis | value | what it is |
| --- | --- | --- |
| rate model | `GRADED_TREE_DEPTH` = 6 | what a path's proof weight is priced at, which fixes a block's leaf rate |
| replay window | 5 | the depth of the tree 765 600 leaves makes — and it is 5 at every model depth 3…7, since the leaf rate moves 4.5 % across them while a rung needs 38× |
| the chain | grows | what the curve tree actually is; it crosses `min_leaves_for_depth(6)` after ~23 days, so `GRADED_TREE_DEPTH`'s stated band is satisfied in weeks and its rule-21 reopener was never unsatisfiable |

Two set relations are pinned by test so the conflation cannot return: the
window's leaf count stays strictly below the floor of the rung the rate model
names, and no plan may sit at or above it.

### 11.4 The criterion, fixed in advance

Flat does not mean one constant across every depth — a deeper path may cost
one more layer's walk — so the criterion has two halves:

- **within a depth rung**, cost constant within noise however much `n` grows;
- **across a rung boundary**, the deeper arm costs no more than one layer's
  work, within the same tolerance. The check is a ceiling. A cheaper step
  still passes, and that pass is not evidence the step matched
  `expected_cross_rung_ratio`. The model treats every layer as the same cost.

The populations are chosen so both are observable, and derived from the
production ladder rather than restated: the cross-rung pair differs by **one
leaf** (a rung floor and its predecessor), which isolates the layer step from
the population term entirely, and the same-rung pair separates ≥ 1.5×, where a
linear term shows as ≥ 50 % against a 10 % bound.

`expected_cross_rung_ratio` is a **uniform-layer model** and says so: Selene
nodes are 38 wide and Helios 18, so the true step is in chunk work. It is right
for *this* question, where the hypotheses differ by orders of magnitude, and
explicitly **not** good enough to grade a passing capture — increment 6 must
widen the bound or derive from `chunk_width`. Named blocker.

### 11.5 What this round does not establish

- **No graded figure.** The board control times `rung_top` twice, back to
  back, on the same client, after every other arm has been measured and its
  rig dropped. Both timings are then the only resident population, so
  whatever separates them is the board. The control does not span the earlier
  arms: holding the top client across them would time `rung_floor` beside the
  larger working set and shrink the same-rung spread toward `Flat`. The first
  shape run **diverged 69.1 % against a 5 % bound and was discarded**, with
  the arms showing why it had to be (one *more* leaf came out 38 % faster;
  `k = 8` came out cheaper than `k = 2`). The dev box is shared (rule 38), so a
  figure-producing run is a claimed-host activity; §11.2's figure came from a
  claimed, idle staker-class x86 host. **It is an *observational*
  before-figure** — `rig.attested` reads `not requested`, and the control
  brackets only the last arm, so between-arm comparability is uncontrolled
  (§11.2 states the scope and the cheap bracket that would close it). It is
  not a graded figure either: grading means a budget on the rule-76 rig, and
  there is no budget for this form because capture replaces it — what
  increment 6 grades is capture, on the floor device. Two further runs were discarded before the kept one, both for the
  same cause: the **harness** differed between two samples that are only
  comparable if it does not, first by holding every arm's rig at once and then
  by timing `rung_top` alone against `rung_floor` beside it. Neither is
  detectable by the board control, because the control is part of what moved.
- **The integrity gate's verdict.** The rig takes its reference root from the
  client, so `assemble_paths`'s root gate is green by construction; the rig
  measures what it costs, never whether it is right. Root agreement is graded
  in-crate by the height-keyed C1 oracle (`client::ct6_oracle`, increments 2
  and 4) against a replay oracle this crate cannot reach — `entries` is
  `pub(crate)`, `store::ops` is private, the oracle is `#[cfg(test)]`. Widening
  any of them would publish a second root mechanism a production caller could
  gate against, which `assemble.rs` rules out by design. What the rig does
  assert is its own subject (rule 47): the client drained exactly the
  population fed, and reports the depth that count implies.

### 11.6 The gate did not cover the path material — and now does

**Current state:** `assemble_paths` refuses a path that does not commit to
the root it claims, with `ClientError::PathRootMismatch`. The refusing step
is `PathRootFault`: `ChildAbsent` when the leaf's scalar is missing from its
parent branch, `RootDisagrees` when the folded root is not the claimed root.
The check runs for every assembled path.

**What it closed, in the past tense it belongs in.** Building §11.5's red-bite
turned up the gap. With `entries` reduced to the owned leaf alone,
`assemble_paths` *did not refuse*: it returned a path whose `tree_root` was
the real consensus root while every branch below it came from a one-leaf tree
— a leaf chunk of 1 under a root committing to 44.

The red-bite therefore has **three states**. The gate moved it to the second:
it asserts `PathRootFault::RootDisagrees`. Capture moved it to the third.
`capture::a_path_from_captures_equals_the_rebuilt_one_with_every_foreign_leaf_gone`
asserts the path equals the full-tree path. The chunk-length witnesses of the
pre-gate failure were removed with the gate: the call no longer returns a
path to measure. State 3's edit was that equality.

The cause was that the two mechanisms never met. The gate is
`root_and_depth_at`: it checks the reference's root and supplies the depth
both routes stamp on `tree_depth`. The branches come from the capture
table and the frontier snapshot — the one route; an unregistered input is
refused by name since the registrant landed (§11.12). `tree_root` is copied from the gated reference, so the gate's
answers do not see the branches. The docstring that said the paths came from
"the same `layers` that gate approved" was withdrawn 2026-10-01.

**The check that closes it is not a comparison of two store reads.**
`root_and_depth_at` answers both root and depth from the store tier, so
comparing it against `tree_root` compares the store with itself and leaves the
branches unchecked — which is the thing that can actually drift. The sound form
**recomputes the root from the path's own branches** (an `O(depth)` hash walk)
and refuses on disagreement. That verifies the artifact, so it catches every way
the branches can diverge rather than the one case a test happened to construct.

**Built as the capture build's first production commit.**
`verify_path_against_its_branches` runs after each path is assembled. It
hashes the leaf chunk to a Selene point, then at each layer requires that
point's converted scalar to be **present in the branch** before hashing the
branch to the next point, and finally compares against `TreeContext::tree_root`.
The membership step is what binds the path to *this* leaf — without it, a
correct root over another leaf's branches would pass. Those two refusals are
`PathRootFault::ChildAbsent` and `PathRootFault::RootDisagrees`. Each node is
hashed with `shekyl-fcmp`'s `hash_grow_*` at offset 0 from the layer's init
point, the same call `try_build_layers` makes per node. The fold is
path-shaped, so it is not a call to `try_build_layers`, and it is the only
such fold: the assembly KAT does not carry a second copy. Cost is `O(depth)`.

The gap it closes was *latent*:
`entries` is append-only and a pruned-store resume is refused (`F5`), so
production never assembles from a truncated set. It is *live* now that capture
is a second branch source — captured chunks plus a frontier snapshot — whose
mutual consistency is exactly what can drift. So this is **capture's
integrity gate**, and it landed as the first production commit of that build,
policing the source it exists for.

Threat model, kept proportionate: **no funds are at risk.** An inconsistent path
yields a proof that fails after ~6 s of proving on the floor device, or a
malformed transaction the daemon rejects. That is a rule-82 failure-clarity cost
plus a small behavioural tell — proportionate to a cheap check, not to a round
of its own.

### 11.7 A reading is withheld from a run that cannot support one

`LoadControl` already says a non-quiet run "cannot claim its figure is a
property of the work rather than of the machine" — which is precisely the claim
a grade makes. The record nevertheless serialized a `FlatnessGrade`
unconditionally, so a contaminated run could have reported **`Flat`**: the one
reading capture is trying to earn, handed over by a moving board.

The record carries one `FlatnessReading`: the same-rung spread, the cross-rung
ratio, the expected ceiling, and a `FlatnessOutcome` — `Graded(..)`, or
`Withheld(BoardNotQuiet | SeriesUnconverged)`, with the reason part of the value
(rule 82). `read_flatness` fills all four, so the published ratio is the ratio
the criterion judged, including the zero-arm guard. Withholding the judgment
is not withholding the data: the numbers and every series stay in the record,
which is what lets a later reader re-judge the run rather than take a verdict's
word.

This is deliberately **not** `Verdict::Ungraded`. `Verdict` answers *did the
figure meet its budget on the pinned rig*, and its `Ungraded` means "measured
somewhere else"; this answers *does the cost track `n`*, and withholds for
contamination rather than provenance. Two questions with different inputs, so
two types — collapsing them would give `Ungraded` a second meaning.

One related correction: the `k` arm's field was an **absolute** spread, so a
`MAX_INPUTS` arm that came in *cheaper* — which the discarded run's did — was
reported as a 70 % *cost*, inverting `#842`'s `n + k` finding. It is now a
signed change, and a negative value reads as what it is: the `k` term lost in
the noise of `n`.

### 11.8 The capture table, as a reader dumping it will find it

`captured_chunks` is **plaintext on purpose** (RULED by Rick, 2026-10-02):
nothing but testnet exists to expose, and a bug in capture's reorg behaviour
is far cheaper to find in a readable table than behind a seal. Sealed
persistence is PR3, and `FOLLOWUPS.md` carries the row that retires this
table before genesis — **deleted, not migrated** (rule 15), testnet wallets
resync. That row is a *tracked promise with a grep surface*, not an
enforcement: the FOLLOWUPS gates check a row's target, owner and prose, never
its discharge.

**No nettype branch exists or may be added.** A table that refused on mainnet
would be `nettype` selecting a code path on `rust/**`, which rule 71 forbids —
and it would defeat the reason for plaintext, since testnet would then never
exercise the persistence mainnet ships.

| | |
| --- | --- |
| key | `TreePositionKey` — the leaf position at which the chunk **closed** |
| value | `layer u8 ‖ len u32le ‖ bytes`, repeated |
| schema | `SCHEMA_VERSION` 6 → **7** |

**Why the key is `end_leaf`.** A chunk's identity is `(layer, index)`, but
that pair does not fit a `u64` — at layer 0 the index reaches ~`1.0e17`
against the `2^56` a packed `(u8, u56)` leaves — and every other key in this
store is a `u64` newtype. `end_leaf` is *derivable* from what a reader has
(for an owned leaf at `p` and layer `L`, the chunk is `p / outputs_per_node(L)`
and ends at `(index + 1) * outputs_per_node(L) - 1`), so a spend-time lookup
stays a direct key read. And truncation becomes the **same**
`delete_pos_keys_batched(start)` call every other position-keyed table uses,
in the ring's own transaction — one undo path literally, not by analogy.

**Two value shapes, and `I` is not stored.** The `layer` byte says which:

| layer | contents | size |
| --- | --- | --- |
| `0` | the leaf chunk's siblings as **identities**: `O ‖ C ‖ CM.x`, 96 B each | 38 × 96 = **3 648 B** stored |
| `>= 1` | the node chunk as the frontier folded it, 32 B per child | 18 × 32 = 576 B (Helios) or 38 × 32 = **1 216 B** (Selene) |

Layer 0 is identities rather than the frontier's scalars because a path needs
the siblings as compressed points and `O.x` is a one-way projection of `O`.
The prover consumes four fields per sibling (`O`, `I`, `C`, `CM.x` — 128 B,
which is the leaf term in row 4's 9 024 B path figure), but **`I` is not
stored**: it is `Hp(O)`, derived at assembly. A stored copy of a recomputable
value is a second copy that can disagree, and the re-derivation is one
hash-to-point per sibling against ~6 s of proving.

A fold cascade closes several layers on one leaf; those chunks share a key,
because they became final at one instant and a rollback un-finalizes them at
one instant.

**Writes merge by layer; they do not replace.** They do not always arrive
together, and the coordinates are shared: layer-0 chunk 17 and layer-1 chunk 0
both end at leaf **683**. So an output discovered *late*, whose layer-0 chunk
ends there, would silently erase another output's layer-1 chunk already at that
key. A first revision replaced, on the reasoning that the chunk set is a
property of the leaf count — it is not: it is a property of the leaf count
**and of which outputs are owned**, and ownership can be learned after the
fold, which is precisely what the backfill does.

Re-offering identical bytes is a **no-op**, so reconciliation may recompute
freely. Offering *different* bytes for one `(end_leaf, layer)` is refused with
`StoreError::ConflictingCapture`: a chunk's contents are fixed by the leaves
under it, so one coordinate has one correct value, and two sources disagreeing
is the condition a capture exists to be trusted against rather than a merge to
resolve in either direction.

**Cross-reference note.** `CURVE_TREE_STORE_SHAPES.md` §3 enumerates the
store's tables *at the CTS round's own pin*, where `SCHEMA_VERSION` was 5.
This table arrived after it. Neither document is wrong; the enumeration is
dated, and it is not edited here because rewriting a pinned list would make
the pin a fiction.

### 11.9 The client side: ownership is registered, and the fold writes

Capture rides the **fold**, and a chunk folds once. That single sentence
settles the whole shape of this side.

**Ownership is registered, never derived.** `CurveTreeClient` sees every
output on the chain and cannot tell which are the wallet's — that is the
scanner's knowledge, and putting it here would mean either a second view-key
consumer or a guess. So `register_owned(gindex, output_key)` is the input —
the index and the one-time key, because a `gindex` alone is a name that a
reorg can hand to a different output — and it returns what the call *bought*:

| | |
| --- | --- |
| `OwnedRegistration::BeforeDrain` | the leaf has not drained; every chunk over it is captured as the fold closes it |
| `OwnedRegistration::AfterDrain` | the leaf had drained; chunks that already closed are **owed to reconciliation**, and no future fold reports them |

The two are not cosmetic. A late registration that returned `()` would read
exactly like a working one, and the thing it silently did not do is the thing
capture exists for. An unseen `gindex` is `BeforeDrain`, not an error: the
scanner may identify an output from a block this client has not ingested, and
the registry is matched at each leaf's own drain, so an early registration
simply works.

**The registry does not persist.** `resume` starts empty. A copy of the
wallet's output list kept here would be the copy that rots when the two
diverge; the wallet re-registers what it holds. The consequence is stated
rather than hidden: after every resume, each held output is `AfterDrain`, and
what that leaves owed is reconciliation's whole job.

**Positions come from the fold, because the fold is the one instrument.** A
leaf's position is its index in drain order, which is what the frontier counts
as it pushes. `ingest_block` resolves this block's owned positions before the
advance — a chunk closing here may hold a leaf draining in the same block —
and commits them beside the frontier. Resolving a position a second way, from
the maturity index, would be a second instrument over one field with no
cross-check between them.

**A rollback keeps the registry and cuts the positions.** Opposite failure
directions, so both are asserted. Losing the registry stops capture for every
held output after the first reorg, silently, because the fold finds nothing
registered. Keeping a position past the cut leaves a coordinate that now names
a *different* leaf, so a chunk holding nothing of the wallet's reads as owned.
Truncation deletes `range(start..)` and shifts nothing, so a surviving leaf
keeps its position and a removed one re-resolves when it re-drains:
`owned_positions.retain(|p| p < surviving_leaf_count)`, the same coordinate
`FoldedChunk::end_leaf` is compared against (§11.8).

One case a registry keyed on `gindex` alone does not cover: a reorg past the
owned output's *creation*, not merely its drain. `gindex` is re-derived from
the replayed block sequence, so on the new chain that number may name a
different output. That registry keeps the number and captures the stranger's
chunks — an **over-capture**. That is the failure the `(gindex, O)` pair
below closed. It was never a wrong proof: assembly resolves by `gindex` and
refuses a leaf that does not carry the expected `(output_key, commitment)`
(`ClientError::IdentityMismatch`). The wallet's rescan rebinds the
registration. The reorg red-bite is
`a_reorg_past_creation_retires_the_registration_and_rebinds_it`.

**A `gindex` is a name, not an identity — and that is the whole lesson.**
Three rules tried to work out, *after* a rollback, which output a number used
to point to. Each failed differently, and the pattern is the finding:

*Candidate 1 — `gindex >= surviving_leaf_count`.* The tempting tidy-up: the
same inequality on the same quantity as the positions. It mixes units.
`surviving_leaf_count` counts drained **positions**, while a `gindex` is a
global output index that skips values consumed by leaf-ineligible outputs
(`types.rs`, `LeafEntry::gindex`). `a_gindex_is_not_a_position` builds a block
with a `TargetKind::Other` output and shows a valid leaf whose `gindex` equals
the drained count.

*Candidate 2 — `gindex < next_gindex && !entries.contains(gindex)`.* This one
typechecks. Its first clause protects a registration for an output the scanner
found in a block this client has not ingested, which sits above `next_gindex`.
It is **inert**: a rollback removes the chain's *tail*, and
`rebuild_from_store` sets `next_gindex` to `entries.last() + 1` over the
survivors, so every removed output lands inside the band that clause protects.
Substituting it fails the same passes as performing no trim at all —
`a_removed_gindex_sits_above_the_rebuilt_next_gindex`.

*Candidate 3 — the set difference on `gindex` alone, taken across the
rollback.* Correct for a removed output, and it **misses rebinding**: a
rollback that gives the gindex to a *different* output leaves it present, so
the difference sees nothing gone.

*And the case none of them could reach.* A registration made **before** this
client ingests the output's creation block is not in the held set at all, so
no cross-the-rollback rule touches it — correctly, because until the fork it
was a legitimate registration for a block not yet seen. If the reorg goes past
that creation, the arriving chain can hand the gindex to another output, and a
registry keyed on the number marks a stranger's leaf as owned. Nothing
financial breaks (spending is driven by the wallet's ledger, which never holds
it) but the registry and the plaintext capture table would be wrong and
nothing would correct them.

**So the registration carries `(gindex, O)`, and ownership is tested by
identity.** `O` is a one-time key, so the pair names one specific output. A
leaf is owned only if the registry holds *its* key at *its* gindex, which
makes the rebinding case impossible by construction rather than detectable
afterwards. Registration refuses a key the client disagrees with
(`ClientError::RegistrationIdentityMismatch`) — the same inter-component
invariant `IdentityMismatch` guards at assembly, raised at registration rather
than at the spend that needed the capture — and a re-registration *replaces*,
so a rescan rebinds a gindex with no separate retraction.

**Inherited by the registrant.** `RegistrationIdentityMismatch` is raised in
**normal operation**: a caller whose view is still the pre-reorg chain offers
the old key for a gindex that now names a different output, and the client
correctly refuses it — exactly what happened to the first draft of the reorg
red-bite below. The caller that can be behind is the **ledger**, not the
persona scan: the tree's ingest is acknowledged before the ledger's merge
commits, so a merge that loses its race leaves the tree on the new chain and
the ledger — and any spend selected from it — on the old one. (The persona
scan is behind by construction rather than by accident: it sweeps only
blocks `ARCHIVAL_REORG_DEPTH_BLOCKS` behind the tip and treats them as final,
so a pair it seals is rebound only by a reorg deeper than that. The tree's
own window, `FINALITY_DEPTH_BLOCKS`, is one lock window wider, so such a
reorg is not unrepresentable — and the verdict it would get is this one.)
The registrant classifies it as *the caller's view is stale* and nothing
else: the batch form `sync_owned`
collects such pairs in `OwnershipSync::stale`, registers the rest, reconciles
once if anything is owed, poisons nothing, and the rescan re-offers the right
key.

Two tests grade it, at two layers. The client's
`a_batch_registers_reconciles_once_and_reports_stale_pairs` offers a wrong key
by hand: reported, still reported on a re-offer, and the right key then
accepted and reconciled. That shows the verdict; it does not show a reorg.
The actor's
`a_view_behind_a_reorg_is_reported_stale_and_recovers_on_the_rescan` does: a
chain is ingested and its outputs registered, the tree is rolled back to the
fork and a different chain ingested over the same gindexes, and then, through
the handle, (1) the old pair is reported stale *alone* — the pair below the
fork in the same batch is still held; (2) a spend of the old pair is refused
`OutputNotRegistered`, which the re-anchor classifier maps to reselection;
(3) the rescan's pair registers, and its reconciliation rebuilds **exactly**
the one leaf chunk the reorg replaced; (4) both outputs assemble against the
new root. The equality in (3) is the witness that nothing was left behind:
with the rollback's capture truncation removed, the old chain's row answers
for that chunk and the figure reads 0, which is how that mutation fails the
test.

The engine's refresh never sees a stale pair as an error — it is logged with
a count — which is also why it adds no `RefreshError` variant and so no
wallet-RPC contract bump. The re-anchor classifier keeps the variant in the
reselection family, as #945 placed it: the caller's view is stale, a rescan
re-registers against the chain it now sees, and discarding the selection is
what that rescan does.

The rollback trim stays, but it is now **cleanup, not correctness**: it keeps
the registry from accumulating dead rows, and it is the candidate-3 difference
widened to the pair, so it catches rebinding too. Correctness is the identity
test, and `an_early_registration_does_not_claim_a_strangers_output` is where
that is graded — the one case the trim cannot reach, and the mutation that
reverts ownership to `gindex` alone fails exactly it.

**And the rebinding is what the reorg red-bite checks.** Retiring a stale
registration is half the claim; the other half is that what replaces it is
right. `a_reorg_past_creation_retires_the_registration_and_rebinds_it` forks
below the output's creation, re-ingests a *different* chain so the same gindex
names a different output, refuses a re-offer of the **old** key, re-registers
with the new one as a rescan would, and compares the capture against the path
`assemble_paths` builds from the post-reorg tree.

### 11.10 Reconciliation is the backfill, and the list of its causes is short

A capture that is **due and missing** is a late registration, whatever made it
late, so `reconcile_captures` is one mechanism rather than a repair beside a
backfill.

**Two triggers, not four.** The working list carried four, and two of them do
not survive grounding:

| cause | status |
| --- | --- |
| **Resume** — the registry does not persist, so every held output returns `AfterDrain` | **real, and the mass case** |
| **Late discovery** — the scanner identifies an output after its chunks closed, including a lagging scan | **real** |
| A pre-capture (`SCHEMA_VERSION` 6) store opened by this binary | **unreachable.** The version cell is a strict equality check; such a store is refused at open and re-synced, not migrated |
| A crash between a fold and its capture | **unreachable.** Captures ride the block's own transaction beside the leaves and the ring snapshot, so the two commit together or neither does |

Recorded as a correction rather than silently dropped, because the four-case
list is the kind of thing a later reader re-inherits from a summary.

**Due is the same one comparison.** A chunk over owned position `p` at layer
`L` ends at `(p / outputs_per_node(L) + 1) * outputs_per_node(L) - 1`, and it
is due exactly when that end is **strictly below** the drained leaf count —
the same `end_leaf < surviving_leaf_count` a rollback applies and the table is
keyed on (§11.8). One quantity, three readers.

That strictness is a fencepost, and it was shown to be load-bearing the hard
way: `<=` instead of `<` passed every other pass in the file, because the
fixture drains a whole number of chunks and so never puts a chunk's end *at*
the drained count. `an_unclosed_chunk_is_not_due` is the boundary, at both
shapes — one leaf short of a layer-0 chunk, and one short of a layer-1 node —
because they fail differently. Layer 0 reads past the end of the drained
entries; layer 1's node slice stays in bounds and would write a **wrong**
chunk silently.

**It also checks the fold.** The owned positions are recomputed from
`drained_sorted` — the order assembly resolves against — rather than trusted
from `owned_positions`, which the fold wrote leaf by leaf. The recomputed set
must *contain* every held position, and is a superset because it also covers
registrations the fold never saw. A held position it does not produce is
`ClientError::OwnedPositionDrift`, not a silent overwrite: two orders over one
field with no comparison between them is how a wrong coordinate survives, and
a capture keyed on the wrong leaf is a path that fails after the prover has
run.

**The oracle is the fold, not assembly.** Reconciliation and assembly both go
through `drained_sorted` + `build_layers`, so comparing them compares a
function with itself. The fold is the independent producer: it writes from the
store's committed rows plus the block in hand, while reconciliation rebuilds
the layer stack from `entries`. `a_reconciled_row_equals_the_folded_one`
registers early on one client and late on another and requires the rows to be
**byte-equal**.

**And the cascade rule gets its end-to-end bite.** Leaf 0's layer-1 node and
leaf 683's layer-0 chunk both end at leaf 683, with different owners. Leaf 0
is registered early so the fold writes layer 1; leaf 683 is registered late so
reconciliation writes layer 0 at the same key. Replacing instead of merging
drops leaf 0's branch, and
`a_late_layer_zero_capture_does_not_erase_a_folded_layer_one` is what notices
— the hazard §11.8 names, now exercised through both producers rather than at
the store alone.

**Cost: lazy, and bounded by what is missing.** Due coordinates are
arithmetic, so the call first asks the table what it already holds — one read
per distinct `end_leaf`, no hashing. On a normal resume every due chunk is
present, and that is the whole cost: `O(owned × depth)` reads and
`leaves_rebuilt == 0`. Only a **missing** chunk is rebuilt, and only from the
leaves under it — 38 at layer 0, 684 at layer 1. The bound is the chunk's own
span, never the chain's length.

Above layer 0 the children are rebuilt rather than read, because the store
holds leaves and captures, not interior nodes. `build_layers` over an aligned
span reproduces the real tree's nodes within it: `outputs_per_node(L)` is
`outputs_per_node(L - 1) · chunk_width(L)`, so the grouping is the one the
whole-tree build would have made.

**This is a correction, and the reason it matters is the arc's own.** A first
revision rebuilt the entire layer stack before comparing anything against the
table, then wrote the difference — so "only the delta is written" held for the
writes and not for the work. Since the registry does not persist, **a resume is
a call to this**, which put §11.2's figures — ~65 min at
`min_leaves_for_depth(6)` on the staker-class host, ~2.5 h projected on the
floor device — on every wallet open, where they hurt more than at spend, a
spend being a deliberate act and opening a wallet not. That is precisely the
cost capture exists to remove. It was recorded here as a population
reconciliation *inherits*; it is not inherited, because nothing requires the
rebuild when the captures are already there, and on a normal resume they are.

The cost is a **reported field** rather than an implementation detail for that
reason: a pass asserting only "wrote nothing" passes the rebuilding revision
unchanged. `reconciling_twice_rebuilds_nothing_the_second_time` asserts
`leaves_rebuilt` is exactly the missing chunks' spans — an equality, not
"fewer than the chain", because at this fixture's size a layer-1 span *is*
most of the tree, so an inequality would measure the fixture rather than the
bound — and `a_resume_with_nothing_owed_hashes_nothing` is where it reaches
zero.

**Span-bounded is not the same as cheap, and the worst case belongs here
beside the zero.** A missing chunk's rebuild scales with its *layer*, because
that is what its span is:

| missing chunk at layer | leaves rebuilt | at §11.2's observed rate |
| --- | --- | --- |
| 0 | 38 | negligible |
| 1 | 684 | ~0.2 s |
| 2 | 25 992 | ~6 s |
| 3 | 467 856 | ~1.7 min |
| 4 | 17 778 528 | ~65 min |

The seconds are the **assembly** rate (221 µs/leaf) used as a proxy; assembly
does more per leaf than this rebuild does, so they are an upper bound on the
hashing and are quoted to an order, not a figure. The leaf counts are exact —
`outputs_per_node(layer)`.

So a late registration under a long-finalized high-layer chunk can still cost
tens of minutes, the same order as the old per-spend figure. It is bounded by
the chunk rather than the chain — a chunk's span does not grow once it has
closed, while the chain does. But it is the worst case that remains, and
"span-bounded" should not be read as "cheap".

**How often depends on whose output it is.** For the principal it is rare:
ownership has to be learned long after the fact for a *high* chunk to be the
missing one, and §11.12 registers a detection before its leaf folds. For the
persona it is the **only** case, because the persona's scan learns of every
output about 710 blocks after it drained (§11.12). An earlier revision of
this paragraph said "it is rare" without the qualifier, and was written
before anyone had asked when the persona's scan runs.

What stays `O(n)` is `drained_sorted`, for the positions and the drift check.
It is a sort, not a hash, and it goes with `entries` at increment 7.

One pass serves every late registration. That is why `register_owned` does
not resolve positions itself, and why a caller registers everything it holds
and then reconciles **once**. Every chunk is computed before the write opens
and the whole batch commits in one transaction, so a failure part-way leaves
the store untouched. Only the delta is written: a reconcile with nothing owed
opens no write transaction, which is the steady state and is pinned by
`reconciling_twice_rebuilds_nothing_the_second_time`.

The resolved positions then **become** the fold's. Without that the backfill
would be a one-shot — the chunks already closed get written and every chunk
closing afterwards is missed, leaving the leaf silently unprotected from the
backfill onward. `reconciliation_resolves_the_position_so_the_fold_continues`
grows the fixture to the chunk count that closes a layer-1 node after the
reconcile, because that is the only way to observe it.

### 11.12 The registrant: two sites, one batch call, no fallback

**Where ownership enters the tree.** Two sites, both through one client call,
`sync_owned(&[(gindex, O)])`, which registers what it can, reconciles **once**
iff anything was owed, and reports — not refuses — the pairs whose key the
tree disagrees with.

| site | when | what it buys |
| --- | --- | --- |
| the refresh's ingest (`merge::curve_tree_ingest_scan_result`) | every refresh, between the ingest's rollback and its first fold, with everything the wallet will hold once this refresh has merged (`Engine::owned_outputs`) | **registration before the leaf folds**, so the chunk is captured as it closes and nothing is rebuilt; and **resume as a mass late registration** — the registry does not persist, so the first refresh after open is one reconcile (zero hashing when the captures are there) and every later one is all `AlreadyHeld` |
| the curve-tree actor's `AssembleTx` handler | before every assembly, in the same handler invocation (E1: no ingest or rollback interleaves) | **the capture path is total.** A spend's inputs already carry `(gindex, O)`; the handler registers them and then assembles. Whatever reached the actor — a spend, a claim, a bond, a release — assembles from captures, whether the refresh registered it earlier or not. A held pair is `AlreadyHeld` and costs a map lookup |

**Why inside the ingest, and why at that point.** One scan result spans
everything from the ledger's height to the tip (`local_refresh.rs`:
`scan_start = synced_height + 1`, `scan_end = chain_tip.next_height()`), and a
leaf drains one lock window (`DEFAULT_LOCK_WINDOW`, 10 blocks) after its
block. So any result longer than the lock window carries outputs that are
*found and drained inside it* — a wallet that was offline for a day, or one
being restored, sees almost nothing else. This PR's first revision registered
after the ingest (what the ledger held) and again after the merge (what the
merge inserted). That is right for a wallet sitting at the tip and late for
every output in a catch-up: the fold had already passed them, so each one was
`AfterDrain` and its chunks were rebuilt by §11.10's table — on the one path
every restore takes.

The registration is now a step of the ingest, and each side of where it sits
is load-bearing:

- **after the rollback**, because a reorg rebinds gindexes. Offered before
  it, the new chain's pair is compared with the old chain's leaf at that
  gindex, reported stale and dropped;
- **before the first fold**, for the reason above;
- **inside the respawn-aware wrapper**, because a respawned actor starts with
  an empty registry: the retry re-offers the set before it folds the rest of
  the range. This is also what the earlier ordering rule — "register after
  the respawn-aware ingest, so a dead actor has been healed" — was for. A
  dead actor fails this call with the same respawn-recoverable fault the
  ingest's own calls raise, and the ordering that rule asked for would have
  let a respawned actor fold the whole range unregistered.

Since the placement is only visible in what the registration *cost*, the
ingest returns the `OwnershipSync` it got. The first draft of the tests below
probed the tree after the ingest and passed with the registration moved back
behind the fold — by then the late path had reconciled, and "held and
served" was true either way. They assert on the returned report instead:
`before_drain == 1`, no reconciliation.

**What is offered.** Everything the wallet will hold once this result has
merged, from three sources:

1. the ledger's unspent transfers **below the result's range**. A row at or
   above the range start is one this result re-derives — the range starts at
   the fork on a reorg and one past the ledger's height otherwise — so
   offering it would register a pair the merge is about to rewind;
2. the persona's held funding outputs (below);
3. what the result detected, less what it also saw spent. These are not in
   the ledger yet, because the merge follows the ingest, and they are the
   outputs the fold is about to reach.

Source 3 means an output is named twice — from the detection, then from its
ledger row on every later refresh — by two derivations over two types.
`merge::tests::a_detection_and_its_ledger_row_name_one_pair` holds them
equal; nothing else would notice them drift, and the registry is keyed on
the pair.

**The persona's outputs, and why its scan has no site.** The staking
persona's funding outputs live in its sealed scan state and never enter the
ledger, and the drain, the claim, the release and the bond-post spend them
through the same actor. Before this section's second revision nothing
offered them: the tree first heard of a persona output when the drain's own
`AssembleTx` registered it, which put the whole late-registration rebuild
inside the persona's exit.

The obvious site — the persona scan registers each output as it finds it —
does not do what it appears to. That scan sweeps only blocks
`ARCHIVAL_REORG_DEPTH_BLOCKS` (720) behind the tip (`pscan/start.rs`), and a
leaf drains 10 blocks after its block, so the scan learns of an output about
**710 blocks after it drained**. A registration made there is late too. It
would also not survive a restart: the registry is not persisted and the scan
names each output once. So the refresh carries them, from the seal, on every
pass.

That makes the persona's first registration **structurally late**, and what
it costs is §11.10's table read at the chunks that closed in the meantime.
The bound is the trail, not the output's age: registered at the first
refresh after the scan sealed it, the output is under whatever closed in
roughly 710 blocks, and every chunk closing afterwards is captured by the
fold. At §10's worst-case leaf rate (1 056 leaves/block) that window is about
750 000 leaves — past a layer-3 span (467 856), so layers 0–3 are missing and
the rebuild is of the order of the table's layer-3 row, once per layer-3
chunk rather than once per output; and it reaches a layer-4 span
(17 778 528) for the outputs within 750 000 leaves of one's end, about one in
twenty-four. On a lightly loaded chain the same arithmetic gives
proportionally less. None of it is in the drain any more, and none of it
grows with how long the persona held the output. The dependency this creates
on the store's leaf rows is §11.11's third item.

An unreadable persona seal is **read as empty and reported** — the opposite
of every staking read, deliberately. Those reads decide what the wallet tells
its user it holds, so they fail closed. This one decides only when captures
are written, and the `AssembleTx` handler still registers a spend's inputs;
failing would stop the principal's refresh on the state of the persona's
file. But reading it as empty also puts the persona back on the spend-time
registration this section exists to remove, silently, so the state is
carried out of the read (`OwnedSet::persona_seal_unreadable`) and the refresh
raises `RefreshDiagnostic::PersonaSealUnreadable` for it — the consequence,
named, on the engine's diagnostic surface. The cause reaches the user
through the staking read, which opens the same file the same way and fails
closed on it; the test asserts both on one fixture. The diagnostic surface's
only production sink today is the tracing projection, so the event is typed
and testable but is not yet something a wallet UI renders.

One conversion, `ownership::p_assemble_input`, now turns a funding record
into the tree's types. The four persona spend paths each carried a copy;
they call it, and the registration pair is its first two fields, so what
the persona registers and what it spends cannot differ.

**The persona's rows are in the plaintext table from the refresh after
discovery**, where before they appeared at its spend. Same table, same §11.8
ruling, same retirement row, and the same home afterwards: Q3 governs *the
wallet's single proving state*, which is what Q5's dissolution established
there is, and rules that path sets ride the sealed file. The persona's
captures are part of that one proving state — not a second home, any more
than the principal's are. The retirement row used to say the path set rides
"the wallet's own ledger", which is narrower than the ruling it carries out
and does not hold the persona's outputs; it now names the sealed proving
state Q3 names (RULED by Rick, 2026-10-05, on the review's reading of the
row).

**And the rebuild is deleted.** #945's dispatch comment promised the registrant
PR would retire the fallback, and the first site is what makes that honest
rather than a tense change: with registration only at refresh, a wallet that
opened and spent before its first refresh would have taken the `O(chain)`
rebuild through a door nothing closed. Now `assemble_paths` has one path.
An input with no resolved position is refused by name —
`OutputNotRegistered` if the pair is not held (a direct caller that skipped
the sync, or a pair the sync reported stale), `OutputNotDrained` if it is
held and simply has not drained yet. The three oracle passes that exercised
the rebuild register their inputs first, as the actor does. The reference
derivation the state-3 oracle compares against lives in the test module as
`rebuilt_path`, built from the tree primitives — where a reference derivation
belongs once production stops doing it.

**`AlreadyHeld` is the third state, and it is what makes a per-refresh
re-offer free.** A re-offer of a held pair is `AfterDrain` only when the leaf
has drained *and* its position is not resolved — "held" and "served" diverged,
and the captures are owed. Otherwise it is `AlreadyHeld` and triggers nothing.
`a_re_offer_after_a_rollback_is_already_held_and_already_captured` grades the
one case where that could go wrong: a rollback past the drain trims the
position but keeps the pair, the re-drain's fold re-resolves it and writes the
chunks, and the re-offer is held *with the captures present* — asserted on the
rows, not the verdict, because the verdict alone would also come from a rule
that never reconciled.

**Unspent only**, in all three sources: the ledger's flag, the seal's own
pruning of spent funding records, and the result's observed key images.
Capture serves spending, and a spent output's chunks are plaintext rows for
nothing. The set is offered every refresh, so an output a reorg makes
unspent again is picked up when its flag flips.

**What the instrument times now.** `shekyl-wss-q1b-bench`'s `assemble_once`
timed the rebuild through #931; it now registers the rig's inputs outside the
timed call (the one-off reconcile is the cost of building the fixture, not the
subject) and times the capture path alone — the quantity §11.4's criterion
was pre-registered for. §11.2's before-figure stays as the record of the
rebuild era; it is not a number the rig can still produce.

**Where this is graded.** Client: the batch's four verdicts and the stale
report; the rollback re-offer above; a resumed mass registration reconciling
once then `AlreadyHeld`; an unregistered input refused by name. Actor:
`SyncOwned` round-trips; `AssembleTx` registers before it assembles — pinned
by an unregistered input on an empty tree refusing as *not drained*, which
only the handler's own sync can produce; and §11.9's stale view across a real
rollback. Engine, in `ownership::tests`, each named for what it holds and
each failed by the mutation beside it:

| test | mutation that fails it |
| --- | --- |
| `an_output_found_and_drained_within_one_scan_result_is_captured_as_it_folds` | the registration moved behind the fold (`after_drain` reads 1) |
| `a_reorged_result_registers_against_the_chain_it_keeps` | the registration moved ahead of the rollback (the new pair is reported stale) |
| `a_respawned_actor_is_re_offered_the_set_before_it_folds` | the respawn retry offering nothing |
| `a_detection_spent_within_the_same_result_is_not_registered` | the spent filter removed |
| `a_ledger_row_the_result_supersedes_is_not_offered_from_the_ledger` | the range filter removed; the result's observed spends ignored |
| `refresh::start_refresh_integration_tests::refresh_registers_a_found_output_before_the_fold_reaches_it` | the refresh task handing the ingest an empty set |
| `a_persona_funding_output_is_registered_by_the_refresh_not_by_its_spend` | the persona's set left out of the offer |
| `an_undecodable_persona_seal_is_offered_without_and_reported` | the unreadable-seal arm made to fail; the report firing regardless; the unreadable state dropped before it reaches the set |

The last row is the production refresh itself: a chain that pays the
wallet at height 2 and runs on past the lock window, scanned by the real
scanner in one result, leaves the output held with nothing owed — the task
built the set from the result's own detections and the ingest registered
it before the fold reached its leaf. The engine-level rows drive
`ingest_scan_result_into_curve_tree`, which builds its own set; only this
row sees what `run_refresh_task` hands over.

"Unspent" is read against the result as well as the ledger's flag: a row
the merge has not yet flagged, or a detection, whose key image the result
saw spent is left out. The result's key images are every input in its
range, unfiltered, so the wallet's own key images are collected once and the
result's list walked once against them — linear in the result, not the
product of the two.

The persona test is the one that carries the claim above: registered by a
refresh, the output rebuilds **exactly** its one closed leaf chunk
(`leaves_rebuilt == 38`); two more chunks then drain, closing its layer-1
chunk; and the sync the handler makes at the spend finds it held with no
reconciliation, after which the path assembles from a layer-1 chunk nobody
was asked to write. Over the consistent ledger-and-tree fixture in
`transfer_pending_tx_tests`, a registration pass reconciles once, a re-offer
is held, and a spend assembles through the actor from captures with no
rebuild to fall back to; the real-proof builds there run through the syncing
handler as well.

### 11.11 What capture still does not do

**Two FOLLOWUPS rows keep their rationale here, not in the queue (rule 95).**

*The sibling-points question (rule 30).* The tree commits only
x-coordinates, so the leaf-layer hash needs only scalars — yet the prover's
API takes sibling compressed points (`ProveInputLeafChunk.leaf_outputs`,
three per sibling) beside `leaf_cm_x`. If the gadget reads only the
x-coordinates, the points are an API artefact: capture can take its layer-0
chunk from the frontier fold like every other layer, one value shape, and no
identity tail is owed when `entries` retires. If the points are load-bearing,
the tail is permanent. It must be read off the gadget's source, not inferred
from the API.

*The identity account before `entries` retires (increment 7).* Two things
still read from it. A path whose owned leaf sits in the **open** leaf chunk at
the reference height needs that chunk's sibling *points*, which no snapshot
holds — the frontier keeps scalars and `O.x` is a one-way projection; with
the anchor fixed at `tip - REF_ANCHOR_AGE` that is a bounded tail of a few
chunks, not a window of history, and today it is a ranged read of at most
`SELENE_CHUNK_WIDTH - 1` leaf rows. And the owned positions reconciliation
recomputes come from `drained_sorted` over `entries` (§11.10); without
`entries`, those come from the store. Both say one thing: retiring `entries`
needs a precise account of which identities the wallet must still be able to
produce, each case supplied or refused.

A third reader is not of `entries` but belongs in the same account, because
it is the standing consumer of the late path: **the persona's registration is
always late** (§11.12). Its rebuild reads the store's drained leaf rows over
the missing chunk's own span (`read_drained_range`), so it survives the
retirement of the in-memory vector as it stands — and it stops working the
day those rows are pruned below a chunk a persona output has yet to be
registered under. Whatever increment 7 does to the leaf rows has to keep
them for at least the persona scan's trail plus its catch-up, or give the
persona a way to name its outputs before they drain.

Two limits the oracle does not cover, named so a later commit does not
inherit them silently. The fixture's depth puts only layer 1 under a closed
chunk. A layer-2 chunk needs 25 992 leaves, so the state-3 passes grade a
captured branch at layer 1 and open branches at layers 1 and 2. That covers
both parities and both sources, and it does not cover a *captured* Selene
layer.

**A fixture-wide blind spot, found by the mutation sweep and wider than
capture.** `coinbase_raw()` gives every output the Ed25519 basepoint as *both*
`O` and `C`, and it has twenty call sites. Every oracle built on it
distinguishes leaves only by `cm_x`, which `leaf_blob` seeds by **in-block
index** — so leaves at the same index in different blocks are identical too.
Permutations are therefore invisible to those passes: sibling order, `O`/`C`
swaps, and **drain order**, which is consensus-critical, since reordering
identical leaves produces the same root. This is a test blind spot over
consensus-adjacent code, not a defect in the code under test, and the fix is
the generator rather than the tests — a seeded helper already sits beside it.
Its own change, not this one's.
