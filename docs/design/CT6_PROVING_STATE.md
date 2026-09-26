# CT-6 — the proving-state discharge

**Status:** DESIGN ROUND — **Round 1 disposed 2026-09-22**. Every question in
§5 carries a terminal status *in its own row*; the round holds no blanket
"ruled". **`Q2` and `Q3` RULED; `Q5` CLOSED by dissolution; `Q6` a named
dependency; `Q1` and `Q4` PENDING AS DERIVATIONS with their inputs named** —
`Q1` on the bench's per-iteration series, `Q4` on the re-pointed advance field.
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
(`segment.rs:69`: `SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`
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

This does **not** dissolve the concern, it relocates it: §6.3.3 states the
identity-split discipline (*"the frontier advance is public and identity-free;
path capture is a per-identity filter over the same public stream"*) as the
answer to `WSS-13`-in-a-new-location. That discipline stands and this round
inherits it. What F5 left narrower — whether `P` proves its own outputs at
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
| **C6** | The frontier advance is **public and identity-free**; path capture is a per-identity filter over it. No component sees two identities' ownership. **`identity-free` is a claim about the bytes, never about access**: that the content reveals no ownership does not make the file carrying it shared, and a design that reads public content out of another identity's sealed file is `WSS-13` relocated, not C6 satisfied | §6.3.3 |
| **C7** | A reorg deeper than the horizon **refuses**; it never silently produces a wrong tree, and it says so as a rule-82 failure mode (the remedy is a full resync) | §6.3.4 row 1 |
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
| **CT-6 Q1** | **Snapshot geometry.** Dense span, sparse spacing `s`, eviction. `s` bounds the worst rewind | **PENDING AS DERIVATION.** `s` is **not a stated judgment**: it is the largest spacing whose worst-case rewind fits the budget already ruled at §6.3.4 row 2 (`delta ≤ max(2 s, 15 % of proving time)`, RULED 2026-09-19). Rewind cost is `s × leaf-rate × per-leaf`; the leaf rate is already derived (`worst_case_leaves_per_block`, depth-parameterised), and the remaining two terms — the proving denominator and the per-leaf replay cost — fall out of the bench's per-iteration series. **Minting `s` as a fresh judgment would risk an `s` inconsistent with a ruling that already exists, and would forfeit the reopener it inherits for free:** `s` re-derives when the budget or the leaf rate moves, never by preference. Dense over the reference window plus margin, sparse beyond to `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` (C4), remains the **shape**; the constants wait on the rig |
| **CT-6 Q2** | **Alignment.** CT-1 segments are leaf-count-aligned and freeze on burial; snapshots are height-keyed. Do they stay two mechanisms, or does the snapshot subsume the unfrozen-segment recompute (F3a)? | **RULED 2026-09-22 — two mechanisms, one reader**, as proposed. Segments keep the frozen tier; snapshots cover the unfrozen tail; `root_at_count` reads whichever covers the height. Subsuming would rewrite a landed consensus-adjacent boundary to fix a cache, and C4 already forbids the second literal. **The invariant is `total, and identical where both answer` — not `total and non-overlapping`.** The freeze boundary is a *burial condition* (`SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`, `segment.rs:69`) that advances as blocks arrive, and it joins two coordinate systems — leaf-count-aligned segments against height-keyed snapshots. **Demanding non-overlap would force eviction (Q1's subject) to track freezing (this row's boundary) in lockstep, re-welding the two mechanisms this ruling separates.** Permitting overlap and requiring agreement keeps them independent, and C1's oracle already supplies the agreement test. Increment 2's red-bite states it in this form |
| **CT-6 Q3** | **Persistence.** What rides which file, and at which save points | **RULED 2026-09-22, scoped.** Snapshots and the buffer ride the **ledger**; path sets ride the sealed file at existing save points; crash ⇒ rebuild from last save + refetch (C8). **The scope is part of the ruling:** it governs the wallet's **single proving state**, which is what Q5's dissolution establishes there is. **The reason the scope is stated rather than assumed:** C6's `identity-free` is a claim about *bytes*, not *access* (C6 as amended). Public content does not make the file it rides shared, so under a second proving consumer this default would have forced either a read of another identity's sealed file — `WSS-13` relocated, the defect §6.3.3 exists to foreclose — or a duplicate of the public state. Neither was stated, and the default read as though C6 licensed the first. Q5's dissolution removes the second consumer, so the question does not arise; **this row records why the scope is load-bearing rather than incidental** |
| **CT-6 Q4** | **The advance budget** — the amortized form's own graded quantity: worst-case per-block advance as a fraction of block cadence, on the floor | **PENDING AS DERIVATION — pre-registered at ≤ 10 % of cadence, gated on a re-point.** Pre-registration ahead of the cost is methodologically what §6.3.4 rows 2 and 3 already are, and it carries their rule-21 reopener. **But the field it pre-registers against does not yet measure the quantity it names.** `per_block_advance_worst_case_s` is computed as `replay_median / REPLAY_WINDOW_BLOCKS` (`spend_edge.rs:386`) — a **quotient of the spend replay**, which is a legitimate *pre-build model estimate* (uniform hashing over the window) and an **illegitimate grade afterwards**, because the built advance does work the replay never did: snapshot writes and path capture. **So the pre-registration carries its own condition: increment 4 re-derives the field from the actual advance before anything is graded against this threshold**, rather than inheriting the quotient. A name that matches with a derivation that does not is the defect this catches one increment before it ships |
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
| **4** | **The snapshot tier + advance.** Frontier advance inside ingest; snapshot ring; `root_at_count` reads it for unfrozen heights. **Re-derives `per_block_advance_worst_case_s` from the actual advance** before anything is graded against Q4's threshold (Q4). Grades the increment-2 examiner: the segment tier and the snapshot tier are passed to `examine_tier_readings` | **Closeout (b)** — F3a | 2, 3; Q2, Q3 (**ruled**); **Q1 and Q4 as derivations — this increment cannot start until the rig run supplies their terms** |
| **5** | **Path capture** — **one capture side, not two** (Q5 closed) — and the reorg refusal path (C7) with its rule-82 copy | §6.3.3; C7 | 4. **Q5's gate is removed**: the dissolution leaves nothing for this increment to wait on |
| **6** | **Re-grade rows 2 and 3** on the amortized form, same harness, same rig | §6.3.4 | 4 |
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
| 2026-09-23 | **`Q2`'s red-bite is armed at increment 2 against an injected subject, not deferred and not placeholdered** | Both offered shapes were defective: a placeholder is green by construction, and deferring it makes the subject's author write its own examiner. The armed examiner is `examine_tier_readings`. Each tier contributes a `TierReading` (root and depth together — C3) or `TierCoverage::OutsideSpan` where its `HeightSpan` does not cover the height. Agreeing overlap is success; a root mismatch and a depth mismatch are both `Disagree`; a height in neither span is `Uncovered`. A tier that errors does not fit `TierCoverage`, so a failure cannot be recorded as a gap. Increment 4 passes the segment tier and the snapshot tier through this function |
| 2026-09-22 | **The `Q3`←`Q5` graph inversion is recorded, not merely fixed** | Q3 fed increment 4 while Q5 gated increment 5, yet Q3's answer depended on Q5's. Waiting on Q5 would have re-imported the daemon dependency this round sits outside of |
