# Store-invariant register (`SI-`)

**Status:** **LIVING CONTRACT** — minted 2026-09-14 by
[`CONSENSUS_C2_R8_STORE_PLACEMENT.md`](../completed/CONSENSUS_C2_R8_STORE_PLACEMENT.md)
Q1/Q2/Q6; last verified 2026-09-14 at `943592a61` (PR #749's head). Gated
by `scripts/ci/check_store_invariant_register.py` (§4).
**Identifier family:** `SI-1…SI-N`, registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth.
**Owner:** the `shekyl-chain-store` crate. A row's `Status` cell is written
only by the increment that builds it (rule 94 §6).

---

## 1. What a row is

A row is a statement that passes **arm B** of the C2-R8 category test:
*it would still have to hold if the consensus rules changed.* It is about the
store's own coherence — a table that is a set, a foreign key, a cell that
decodes, an accumulator that does not wrap. It is **not** a consensus rule
(arm A lives in the census and the validation crate) and it **never decides
an outcome the caller sees**: breaking it is `StoreInvariantViolated`,
fatal, never converted to `InvalidBlock` (C2-R8 Q2, gated by
`check_store_error_conversion_ban.py`).

Two consequences of "never decides":

- a row may have a **consensus twin** — the rule in the validation crate
  whose correct implementation makes the invariant hold by construction.
  When it does, the row is a belt behind that rule, and a violation means
  the validator has a hole. When it does not, a violation means the file is
  corrupt or the store's own write path is wrong;
- a row is enforced at a **site**, not by a scan. There is no "check
  invariants" pass over the file. Two sites:
  - **write** — an `InsertTable::insert` on a present key, a root that does
    not match, a fold that would wrap. Most rows.
  - **validator read** — a rule walked the store and found it incoherent
    (`Fault::Corrupt`); `WriteBatch::refuse_corrupt` arms the row and
    poisons the batch. **SI-10** is the first: the inconsistency is already
    recorded, so a connect-time insert belt cannot see it. The observation
    arrives because a rule read the cells it needs.

## 2. The register

`Status` ∈ {`ruled`, `built`, `retired`}. `ruled` / `built` are the live
states; `retired` is the deleting-PR status (the id is not reused — rule 23).
`Anchor` is the `StoreInvariant::` variant that carries the row once built
(empty while `ruled` or `retired`). `Origin` names the census row or C2-R8
question the row came from.

| Id | Invariant | Table / surface | Consensus twin | Origin | Status | Anchor |
| --- | --- | --- | --- | --- | --- | --- |
| SI-1 | `spent_keys` is a set: inserting a key image already present is fatal — built S-CHAIN-W commit 6 (`connect` → `spent_keys` insert) | `spent_keys` | CEN-I7 (chain-wide) + CEN-L1 as minted (intra-block) | CEN-L1 | built | `StoreInvariant::KeyImageNotFresh` |
| SI-2 | A connecting block's parent is the block recorded at height−1, and that block is the tip; one block per height — built S-CHAIN-W commit 6 (`connect` parent-is-tip pre-check; `blocks` / `block_heights` / `block_info` / `hf_versions` / `block_burn` inserts) | `block_heights` / `block_info` | CEN-A2 | CEN-L2 | built | `StoreInvariant::TipMismatch` |
| SI-3 | `tx_indices` is keyed by tx hash: inserting a hash already present is fatal (cell corrected 2026-09-15 from `txs`, which is `u64 → blob`, zero-write and unported — `LMDB_WRITE_ATOMICITY_AUDIT.md` DRS-W4; the invariant C2-R8 §7.1 ruled is unchanged) — built S-CHAIN-W commit 6 (`connect` → `tx_indices` insert) | `tx_indices` | CEN-G1 (listed txs); CEN-F5 corollary (miner tx — reversion clause in C2-R8 §7.1) | CEN-L3 | built | `StoreInvariant::TxHashNotFresh` |
| SI-4 | The curve-tree root at height *h*+1 is written exactly once per connect (declared `insert`) and is the root the consensus transition handed `connect` — built S-CHAIN-W commit 6 (`connect` → `curve_tree_roots[h+1]` insert) | curve-tree roots | CEN-B5 reads it | C2-R8 Q4 (ruled `insert`); CEN-L14 curve-root heights (R8b-7 confirms; a rewrite case reopens this row under the ruling's §13, it does not silently override) | built | `StoreInvariant::RootRewritten` |
| SI-5 | After a pop trims the tree to height *h*, the tree's root equals the recorded root at *h* | curve tree | CEN-B5 (the recorded root is the oracle) | C2-R8 Q5; CEN-L13 trim bounds | ruled |  |
| SI-6 | The undo log's top entry is the tip height; a pop consumes exactly that entry — armed where the journal and the tables can disagree: sealing a height whose row is already recorded (`RowAlreadyRecorded`), and replaying an entry whose target is not in the state the entry left (`EntryNotReversible`); the top-is-tip check itself arms at `pop` (S-CHAIN-W commit 7) | `undo_log` | — | C2-R8 Q5; CEN-L13 journal-vs-tip belts | built | `StoreInvariant::UndoLogIncoherent` |
| SI-7 | Every cell read decodes under its canonical codec; an undecodable or missing sealed cell is fatal | all typed cells | — | CEN-L13 serve-credit re-parse; enforced for `properties` cells since PR #749 (as a flat `StoreError::CellCorrupt`), re-homed under the enum at increment 2.5. **UPDATE 2026-09-17 (DRS §11.1(f)):** a `Coded<V>` table reports `V::FIXED_WIDTH` to redb, which asserts it at write — so for a fixed-width codec whose only check is its width (`BlockInfo`, `CurveRoot`, the scalars) the `Undecodable` arm has **no representable instance** in a file the engine accepted; it keeps its instances on variable-width codecs' content checks and on `Blob` kinds (`blocks` that do not parse or do not hash to `block_info.hash`). `Absent` is unchanged — and gains a subject: **S-CHAIN-R commit 2b (A2, SCR-17)**, a sealed file lacking a table the seal creates (every non-`Unshaped` table) is `CellCorrupt { key: <table>, fault: Absent }` at `header::verify`, so *or a declared table* joins *cell* in this row's subject. | built | `StoreInvariant::CellCorrupt` |
| SI-8 | Accumulator arithmetic never wraps: every fold uses checked arithmetic and an overflow is fatal, never a saturate or a mint — built S-CHAIN-W commit 6 (`connect` → `total_burned` `checked_add`; `block_info.cumulative_rct_outputs` likewise); **S-CHAIN-R commit 2b:** `block_info.cumulative_tx_count` — the parent's row plus this block's listed transactions, `checked_add`, `FoldOverflow { cell: "block_info.cumulative_tx_count" }` | accumulator cells | — | CEN-L13 bond-counter overflow | built | `StoreInvariant::FoldOverflow` |
| SI-9 | Store-derived ids are dense in their **primary** and fresh in **every** table keyed by them: `tx_id` is `txs_pruned`'s entry count, `output_id` is `output_txs`'s, `amount_index` is the row count under that amount in `output_amounts` (each derived from that one table at write time), and the slot an `insert` targets under one — primary or side table — is absent. **UPDATE 2026-09-18 (S-OUT-KI layout v6, SOK-Q2):** `output_amounts` is a keyed `(amount, amount_index)` table, so a duplicate index is unrepresentable and the belt is density, `last + 1 == len` — exact only after the table's first and last keys carry that bucket's amount (a hole compensated by a foreign-bucket row, `(0,0), (0,2), (7,x)`, sums to the right length; the length alone is not self-guarding). `connect` mints the slot as `next_output_slot` — one dense bucket whose next index is this `output_id` — or poisons SI-9. A second bucket or a SOK-2 divergence (`amount_index != output_id`) is `IdNotFresh`, the validator's hole, never a verdict. Side tables under a shared id (`txs_pqc_auths`, `txs_prunable_hash`, and from S-CHAIN-R commit 2b `txs_pqc_auth_hash` — present ⇔ the txid is 4-part, `PDM-Q-F26`) are **sparse by design** (no PQC auths on the miner tx, no prunable hash on a v1 tx); SI-9 asserts their slots are fresh, not that they are dense *(wording tightened 2026-09-15 on PR #756 review)* — built S-CHAIN-W commit 6 (`connect` → `txs_*[tx_id]`, `tx_outputs[tx_id]`, `output_txs[output_id]`, `output_amounts[(amount, amount_index)]` inserts) | primaries: `txs_pruned` (`tx_id`), `output_txs` (`output_id`), `output_amounts` (`amount_index`); side tables under `tx_id`: `txs_pqc_auths` / `txs_prunable` / `txs_prunable_hash` / `tx_outputs` / `txs_pqc_auth_hash` (S-CHAIN-R commit 2b; present ⇔ 4-part txid) | — (pure storage integrity; deliberately **not** folded into SI-3, whose twin is CEN-G1 — R8-Q1's three-arm test needs rule-twinned belts and pure invariants to stay distinguishable) | S-CHAIN-W pre-flight SCW-4 ([`DRS_E1_SCHAIN_W.md`](../completed/DRS_E1_SCHAIN_W.md) §6), ruled 2026-09-15 | built | `StoreInvariant::IdNotFresh` |
| SI-10 | Recorded cumulative work **strictly increases** with height: `block_info[h].cumulative_difficulty > block_info[h−1].cumulative_difficulty` for every recorded `h ≥ 1`, because every block's target is at least one (CEN-D6; `Target` is `NonZeroU128`). **The first row armed by the validator reading the store, not by a store write site** (DRS-E2 RD-Q4, ruled 2026-09-19): the store records the work the verdict carries and computes none (C2-R8 Q4), so it cannot observe the violation itself; CEN-D4's window walk over `BatchView` does — a height whose work is not above its parent's, a decrease or an equal pair (`Corrupt::CumulativeDifficultyNotMonotone { at }`; strict since `0476a22ab`) — and the ingest pipeline hands the `Fault::Corrupt` to `WriteBatch::refuse_corrupt`, which arms this row and poisons the batch; `complete` halts the writer at the connecting height (§3.6.2). **A zero next-block target is not this row and never was a store matter** (RD-F17, 2026-09-20): LWMA-1 has no output floor and a conforming slow chain derives zero, so it is CEN-D6's *refusal* of the block — a verdict the validator returns and the store never sees; the `Corrupt::ZeroTarget` arm that first mapped here is deleted. `Corrupt::CumulativeDifficultyOverflow` maps to **SI-8** (`FoldOverflow { cell: "block_info.cumulative_difficulty" }`), not here — it is the fold the store would have caught had it computed the value. Refusing a `Corrupt` is chain work: the method notes the connecting height if nothing in the batch did — built DRS-E2 commit 1 (`refuse_corrupt`, minted with its caller; the API #785's commit 9 shed) | `block_info` (`cumulative_difficulty`, per height) | CEN-D4 (the LWMA-1 window reads consecutive cumulative work), CEN-D6 (a non-zero target is what makes the increase strict) | DRS-E2 pre-flight RD-Q4 ([`DRS_E2_REPLAY_DRIVER.md`](DRS_E2_REPLAY_DRIVER.md) §4), ruled 2026-09-19 | built | `StoreInvariant::WorkNotIncreasing` |
| SI-11 | `curve_tree_leaves` is **dense over `[0, leaf_count)`**: the summary row's `leaf_count` (`curve_tree_meta`'s one `CurveTreeState` row, `SCU-Q1`) equals the leaf table's entry count, and every position below it has a row. The C++ wrote count and leaves in one grow (`db_lmdb.cpp:8936–8966`) and every reader took the count as the bound (`:9231`'s `get_curve_tree_leaves` "positions beyond `leaf_count` are absent"); here the reads **assert** what those readers assumed (S-CURVE §3.3, SCU-3). Armed by the reads — the grow path is DRS-E3's and not yet built. `curve_tree()` reports `LeafDensity::Length { count, rows }` when the summary's count is not the table's length; `leaves(range)` reports `LeafDensity::Hole { position }` at the first missing position in the range it walked. A length-preserving hole (a missing position made up for by a row at or past the count) is visible to the walk and not to the length comparison. The absence discriminator per `CHAIN_RULES_SLICE_2.md` §2: a position **at or above** the count is the caller's error (`AboveCount`, a typed refusal, not this row); a position **below** it with no row is this row — built DRS-E1 S-CURVE (`codec/curve.rs` shapes; `store/curve_reads.rs` arms) | `curve_tree_leaves` / `curve_tree_meta` | — (pure storage integrity; the tree's *content* is CEN-B5's via the recorded root, SI-4/SI-5) | S-CURVE pre-flight SCU-3 ([`DRS_E1_SCURVE.md`](DRS_E1_SCURVE.md) §3.3), ruled 2026-09-21 | built | `StoreInvariant::LeavesNotDense` |
| SI-12 | A grown `curve_tree_meta` summary — any `CurveTreeState` other than the seal's `EMPTY` — carries the live root: `curve_tree_roots[tip + 1]`, or `CurveTreeRoot::EMPTY` when the chain has no tip. The seal's `EMPTY` is not that claim. `connect` records `curve_tree_roots` on every connect, grown or not (SI-4); the grow path (DRS-E3) is what replaces `EMPTY`, and until it does the summary stays the seal's row while the roots table moves. `curve_tree()` compares the two once the summary is grown — built DRS-E1 S-CURVE review (`store/curve_reads.rs`) | `curve_tree_meta` / `curve_tree_roots` | — (pure storage integrity of the denormalized copy; CEN-B5 reads the roots table, which SI-4 writes) | S-CURVE implementation review (PR #818) | built | `StoreInvariant::SummaryRootDiverged` |

Rows are **appended**, never renumbered. A row whose table is deleted is
marked `retired` in its `Status` cell in the deleting PR with the PR number —
not removed — so the id is not silently re-minted (rule 23).

## 3. `StoreError` is classed structurally

Since DRS-E1 increment 2.5 the class is the **outer variant** of
`StoreError` (`rust/shekyl-chain-store/src/store/error.rs`), and
`StoreError::class()` is a projection of it, not a judgement made beside it:

| `StoreError` arm | `class()` | Payload | Meaning |
| --- | --- | --- | --- |
| `Engine(EngineError)` | `Engine` | `Open`, `BeginWrite`, `BeginRead`, `Durability`, `Commit`, `Table`, `Storage` | the redb layer failed and the operation did not happen |
| `Cannot(StoreCannot)` | `Cannot` | `SchemaVersionAbsent`, `SchemaVersionMismatch`, `PropertiesAreTyped`, `ReadOnly`, `WriteInProgress`, `EmptyApplyStub`, `FamilyStubbed` | a refusal before the write: not a verdict, not incoherence. An incompatible file is not an incoherent one — rebuild. Retryability is per variant; `WriteInProgress` is a contract violation and **must not** be retried, per its doc comment |
| `InvariantViolated(StoreInvariant)` | `Invariant` | one variant per `built` row of §2 (the gate in §4 holds the bijection) | an `SI-` row broke; fatal |

The payload columns above are a **reading** of the three enums, not a second
source: where they and the code disagree, the code is right and this table is
stale. Before 2.5 the taxonomy was a table here classing a flat enum (which
also carried an `Abort` arm — deleted with the closure-commit API, an abort is
a drop). The wrapper is transparent: `Display` and `source()` pass through to
the inner type, so a class adds no line to an error chain.

No variant is a consensus verdict, and none ever will be: the crate does not
name `InvalidBlock` (ban clause 2).

**How a violation is produced, and what it does to the batch** (increment
2.5, `store/keyed.rs`, `store/write.rs`). A keyed table opens as
`InsertTable` or `UpsertTable` — the verb is the handle. `open_insert_table`
binds the `SI-` row the site is enforcing; `InsertTable::insert` is fatal on
a present key and returns `InvariantViolated` for that bound row. `upsert`
is the declared overwrite and names no row. Every `InvariantViolated`
produced or observed through a `WriteBatch` (a refused `insert`; a
`get_property` on a cell that fails SI-7) **poisons** it: the first row to
arm is kept and `complete` refuses with it on **both** the closure's `Ok`
and `Err` arms, so a caller that swallows the violation — or maps it to a
different error — still lands nothing and still surfaces the row. That is
what makes "fatal, never converted" a property of the batch rather than of
each call site. SI-1 / SI-3 / SI-4 stayed `ruled` until S-CHAIN-W opened
their tables — the insert handle existed first, and the increment that first
opened a table with each row added the variant (§5 step 1); **as of
S-CHAIN-W commit 6 (2026-09-15) every row but SI-5 is `built`**, SI-5 waiting
on S-CURVE's trim.

## 4. The gate

`scripts/ci/check_store_invariant_register.py` (in `docs-gates.yml`) holds
this file to the crate in both directions, the same shape as
`check_redb_schema_bijection.py`:

- **Subject assertions** (rule 47): §2 parses with ≥ 1 row; ids are
  `SI-1…SI-n`, dense and unique; every `Status` is in the closed vocabulary
  {`ruled`, `built`, `retired`}; a `built` row has a non-empty `Anchor` of
  the form `StoreInvariant::Name`, a `ruled` row has none.
- **Register → code:** every `built` row's anchor is a variant of
  `pub enum StoreInvariant` in `rust/shekyl-chain-store/src/`. If any row is
  `built` and the enum cannot be parsed, the gate fails — the enum is the
  subject, and an absent subject is a failure, not an empty pass.
- **Code → register:** every variant of `StoreInvariant` is named by exactly
  one `built` row.

At birth every row is `ruled` and the enum does not exist: the gate passes
on its subject assertions alone and says so in its output. **Flipping a row
to `built` without adding the variant, or adding a variant without a row,
is red.** `--selftest` exercises each failure class against synthetic inputs.

## 5. How a row moves

1. The increment that first enforces the invariant adds the
   `StoreInvariant` variant, makes the write site produce
   `StoreError::InvariantViolated(StoreInvariant::Name)`, and flips the
   row's `Status` to `built` with the anchor — one PR.
2. A row is never weakened to accommodate a validator that fails it: that
   is the validator's hole, and the fatal is the finding.
3. A new invariant is added **here first** (`ruled`) by the design that
   needs it, then built. An invariant that exists in code without a row is
   the gate's other red.
