# Curve-tree `LeafStore` rewrite — typed value shapes, one codec contract, decomposition: plan and Round-0 pre-flight

**Status:** OPEN — **Round 0 (pre-flight) executed 2026-09-18** at `dev` =
`d89f99791` (the #772 merge). Round 1 questions (§8) are proposed, not ruled;
implementation does not start until they are. Rule-26 sub-PR discipline is
invoked by this document (`26-sub-pr-design-discipline.mdc`): a multi-commit
store-format change behind a stable API, with a substrate re-check and an
artifact run before each cut.

**Identifier family:** `CTS-1…CTS-N` (findings), `CTS-Q1…CTS-QN` (round
questions) — registered in `IMPLEMENTATION_INDEX.md` §2 by this PR.

**What this is not.** Not a transcription of `redb_backend.rs` into smaller
files. The wallet-side store was written before the project had a stated
position on how a value is stored, and it shows: values are anonymous byte
arrays with offsets in prose, two tables of identical type carry different
meanings, a set is stored as a `u32` that is always `1`, a 192-byte record has
70 dead bytes, and one 4 196-line file holds the schema, six codecs, the error
enum, two handle types, and every operation. The daemon store settled the
value-side convention on PR #772 (`DAEMON_REDB_STORE.md` §11.1(f)); this
increment gives the wallet store the same convention **from one shared codec
contract**, redesigns the records it stores rather than re-encoding the old
offsets, and decomposes the crate along what the store *does* — the three
things the user's brief named: proper types, DRY, decomposition.

---

## 1. Preconditions, as found at the pin

| Precondition | State at `d89f99791` |
| --- | --- |
| §11.1(f) ruled and landed for the daemon store | **landed** (PR #772, 2026-09-18): `Coded<V>` / `Blob<K>` / `Present` / `Unshaped`, `Encoded<'_, V>` from `Canonical::encoded` (`rust/shekyl-chain-store/src/codec/{mod,shape}.rs`); the `check_row` insertion boundary (`src/store/keyed.rs`); `Restorable` and its `SEALED` (`src/store/undo.rs`). |
| The shared-crate move is named, not done | §11.1(f) last bullet: `Canonical`, `CodecError` and the shapes "will move to a redb-only shared crate when the wallet-side curve-tree backend adopts them — as the first commit of *that* PR, with `shekyl-chain-store` re-exporting so import paths move once. What does **not** travel: (b)'s bump obligation, the snapshot gate and the `impl Canonical` source scan." This document is that PR's plan. |
| Curve-tree store design-of-record | `CURVE_TREE_CLIENT.md` §3.6 — the **CT-1 decision** (redb; valid store = ACID + oracle-validated leaf encoding, **not** daemon layout parity), reused as ruled. Its body is Round-0 prose preserved as design-of-record and speaks of the store in the future tense ("does not exist yet"); this PR adds the in-line UPDATE at §3.6 that says the store exists and points here, so the two documents do not contradict each other line-locally. `CT1_ROUND1_PINS.md` (archived). Nothing here reopens CT-1. |
| Store layout version | `SCHEMA_VERSION = 5` (PL-D3), in-band `meta["schema_version"]`; refuse-on-mismatch already the posture (`15-deletion-and-debt.mdc`: pre-genesis, delete and re-sync). |
| Dependency direction | `shekyl-chain-store` and `shekyl-curve-tree` do not depend on each other. `shekyl-curve-tree` depends on `shekyl-fcmp` (the leaf type) and `redb`. Nine crates depend on `shekyl-curve-tree` (`engine-core`, `p-host`, `p-serve`, `ffi`, `archival-retention`, `daemon-rpc`, `wire`, `p-fetch`, `economics-sim`). |
| External API surface (the contract this PR keeps) | `LeafStore::{open, open_ephemeral, clear, leaf_count, sync_tip_height, next_freeze_seg, prune_disabled, set_prune_disabled, pruned_frozen_segments, members_missing_pins, append_drained, append_block_deltas, read_pending_candidates, read_drained_entries, maybe_freeze_segments, root_at_count, truncate_from_tree_position, rollback_to_fork, pin_segment_for_serving, pin_serve_set, pinned_shard_ids, release_pins, prune_frozen, frozen_segment, open_frozen_segment_body}`; `ServingReader::{new, open_frozen_segment_body, sync_tip_height, members_missing_pins, prune_disabled, next_freeze_seg, pruned_frozen_segments, same_store}`; `FrozenSegmentBody`, `FrozenSegmentRecord`, `SegmentPin`, `PostureDeclaration`, `StoreError`. Verified by grep across the nine dependents (§7). |

---

## 2. Scope

### 2.1 In

**A. The shared codec crate — `shekyl-store-codec`** (new, `rust/shekyl-store-codec`; depends on `redb`, `shekyl-types`, `shekyl-units` — CTS-13).
Moves, verbatim in semantics: `Canonical` (+ `encoded()`), `CodecError`, `exact`,
the value shapes — `Coded<V>`, `Encoded<'_, V>`, `EncodedBuf<V>`, `Blob<K>`,
`BlobKind`, `Raw<'_, K>`, `Present`, `Unshaped`, `NoRow` — and **every
`Canonical` impl whose type is not the daemon store's own**: the primitives
(`u8`, `u64`; adds `bool` strict `0`/`1` and `u32` LE) and the vocabulary
codecs (`BlockHeight`, `CurveTreeRoot`, `PrunableHash`, `PqcAuthHash` from
`shekyl-types`; `AtomicUnits` from `shekyl-units`). The orphan rule decides
this, not taste (CTS-13, PR #776 review): once the trait is foreign to
`shekyl-chain-store`, those impls can live only where the trait or the type
lives, and the vocabulary crates are `no_std` and must not depend on `redb` —
so the codec crate depends on the vocabulary and hosts the codecs **once**, for
both stores (the wallet store's `SyncTipCell: BlockHeight` and `CurveTreeRoot`
reads want exactly these). `NAME` strings do not change, so no `TypeName`
moves and `tables.snap` is byte-identical. **The one exception:** `RuleSetId`
is `shekyl-chain-rules`' type, and the codec crate must not depend on the rules
crate (direction: the rules crate is consensus, the codec crate is storage);
`hf_versions` gets a chain-store-local column codec `RuleSetInForce(RuleSetId)`
with `NAME = "rule_set_id"` — one adapter, named, its reason on its doc comment.
`shekyl-chain-store` re-exports every moved item at its current path
(`crate::codec::*`), so no daemon-side caller moves.
**Stays in `shekyl-chain-store`:** its own column codecs (`BlockInfo`, `TxIndex`,
`OutTx`, `OutKey`, `TxOutputIndices`, `UndoLog`, `CoverageGaps`,
`PassedThroughFacts`, `SchemaVersion`, `SettlementEpochBlocks`, `FamilySet`,
`Hash32`), `Restorable` (+ `SEALED`, its impls for the shapes — the trait is
local, the types foreign, orphan-rule-clean), `check_row`, `PropertyCell`, the
snapshot gate and the `impl Canonical` source scan — **which still pin the
moved codecs' bytes:** `snapshotted_codecs!` names types by path and keeps
`BlockHeight`, `AtomicUnits`, … in its list, so a byte change in the codec
crate fails the daemon's snapshot test and demands its bump; the scan (impls
*in* chain-store's tree) simply no longer sees them — and §11.1(b)'s bump
obligation, which lives where the digest is.

**B. The wallet store's tables get named value shapes and redesigned records** (§3).
Every `TableDefinition` value is `Coded<T>`, `Present`, or — for the one
per-key-codec table, `meta` — `Blob<K>`; no `&[u8; N]`, no bare integer, no
`()` remains. Records are **designed**, not re-encoded: dense
layouts, LE integers throughout (the shared `u64` codec), one codec per meaning,
and composition where the store composes (`PendingLeaf = Leaf ‖ LeafMeta`).
`SCHEMA_VERSION 5 → 6`; rebuild-never-migrate as before.

**C. Decomposition of `store/redb_backend.rs`** (4 196 lines → a `store/` module
tree, §4) along the store's workflows — schema, codecs, meta cells, ingest,
freeze, serving/pins, reorg, prune — with tests beside the module they pin.
`LeafStore`'s public method set is unchanged; the file it lives in is not.

**D. The `meta` table becomes typed cells** (`MetaCell` trait in the crate:
`KEY`, `Value: Canonical`), replacing five `&str → u64` constants read with
`unwrap_or` defaults and a `bool` stored as `u64` `0`/`1`.

**E. Docs:** this document; `CURVE_TREE_CLIENT.md` §3.6 pointer; DRS §11.1(f)
last bullet flips from "will move" to "moved"; index rows; CHANGELOG one line.

### 2.2 Out (named, so it is not scope shed by omission)

- **Any change to `LeafStore` / `ServingReader` method signatures or semantics.**
  The nine dependents compile unchanged. A typestate handle for servable
  segments is **CTS-Q1**, not assumed.
- **`shekyl-chain-store` adopting a shared cell trait.** Its `PropertyCell` is
  sealed and carries `Scope` (digest domain); generalising it is a later,
  daemon-side decision. The wallet store's `MetaCell` is the smaller sibling
  and stays in `shekyl-curve-tree`.
- **The curve-tree math** (`ops.rs`, `recon.rs`, `assemble.rs`, `client.rs`).
  Untouched; the store KATs (`tests/store_kat.rs`, `recon_kat.rs`) are the
  denominator, not the subject.
- **A flat-mmap leaf array** (CT-1's rejected alternative, with its reversion
  clause). Not reopened; the access pattern argument is unchanged.
- **Daemon-side `curve_tree_*` tables** (`Unshaped` in `shekyl-chain-store`;
  E3's). They take their shapes when E3 writes them; this PR makes the codecs
  they will want (`Leaf`, `FrozenSegmentRecord`) live in a crate both can reach,
  which is why the shared crate is not `shekyl-chain-store`.

### 2.3 What lands where (two PRs)

- **PR A — `codec: shekyl-store-codec, moved from shekyl-chain-store; re-exported`.**
  One mechanical commit plus the `bool`/`u32` primitives. Every chain-store test
  green unchanged; `tables.snap` unchanged (the `TypeName` strings do not move
  with the module). Lands first because PR B and, later, E3 depend on it, and
  because a move mixed with a rewrite is unreviewable.
- **PR B — the curve-tree store rewrite** (§6 commit sequence, ≤ 9 commits).

---

## 3. The tables, as found and as proposed

Every line is at `d89f99791`, `rust/shekyl-curve-tree/src/store/redb_backend.rs`.

| Table | Key (typed already) | Value as found | Finding | Value as proposed | Record (LE) |
| --- | --- | --- | --- | --- | --- |
| `leaves` | `TreePosition` | `&[u8; 128]` (`:22`) | CTS-3 | `Coded<Leaf>` | `Leaf` — 4 × 32-byte Selene scalars `{O.x, I.x, C.x, CM.x}`; decode checks each scalar is in the field (a bit pattern that names no scalar is `CodecError::Invalid`), **not** the Selene-hash canonicality check — that is a validation `LeafStore` runs where it always has (`leaf_bytes_are_canonical`, on ingest and pending decode), not a decode. A newtype over `shekyl_fcmp::ShekylLeaf` (CTS-Q3). |
| `owned_identities` | `TreePosition` | `&[u8; 128]` (`:27`) — **the same type as `leaves`** | CTS-1 | `Coded<OwnedLeaf>` | The retained leaf of an owned output after prune (`prune_frozen`, `:1820`). Same bytes as `Leaf`, **different codec name** — `owned_leaf` — so the two tables have different `TypeName`s and a definition drifting onto the wrong one is refused at open. This is the exact hazard §11.1(f) was written against, in the table that motivated it. |
| `leaf_meta` | `TreePosition` | `&[u8; 192]` (`:23`); layout `gindex[0..8] ‖ maturity[8..16] ‖ output_key[16..48] ‖ tag[48] ‖ commitment[49..81] ‖ cm[81..113] ‖ target[113] ‖ dead[114..122] ‖ creation_height[122..130] ‖ zero[130..192]` (`:2184`–`:2203`), BE integers | CTS-2 | `Coded<LeafMeta>` | **Dense, 122 bytes:** `gindex u64 ‖ maturity u64 ‖ creation_height u64 ‖ output_key [32] ‖ commitment_tag u8 ‖ commitment [32] ‖ cm [32] ‖ target u8`. Tag `0` requires a zero commitment field (strict: one encoding per value); `target` is the `TargetKind` byte with `2` refused (retired claim-era tag, CTS-6). 70 bytes of padding and the BE integers go. |
| `frozen_segments` | `SegmentId` | `&[u8; 56]` (`:25`), BE (`:2160`–`:2181`) | CTS-4 | `Coded<FrozenSegmentRecord>` | `r_k [32] ‖ end_tree_pos u64 ‖ end_block_height u64 ‖ frozen_at_height u64`, LE. Same fields, same width; the type carries the layout. |
| `pending` | `GindexKey` | `&[u8; 320]` = `leaf[128] ‖ leaf_meta[192]` (`:37`, `:2242`) | CTS-5 | `Coded<PendingLeaf>` | `PendingLeaf { leaf: Leaf, meta: LeafMeta }` — **composition of the two codecs** (`encode_into` calls both; `decode` splits at `Leaf::FIXED_WIDTH`), 250 bytes. "One layout, two tables" stays true by construction instead of by comment. |
| `pinned_segments` | `SegmentId` | `u32`, always `1` (`:1630`) | CTS-7 | `Present` | A set. The shape #772 minted for `spent_keys`; the `u32` was a set with a sentinel. |
| `meta` | `&str` | `u64` (`:41`); five keys; `prune_disabled` is a `bool` stored `0`/`1` (`:47`–`:51`) | CTS-8 | `Blob<MetaCellBytes>` + typed `MetaCell`s | `LeafCountCell: u64`, `SyncTipCell: BlockHeight`, `NextFreezeSegCell: u64` (bounded by `NEXT_FREEZE_SEG_MAX`, checked at decode), `SchemaVersionCell: u64`, `PruneDisabledCell: bool` (strict `0`/`1`). Per-key codec, like the daemon's `properties`; reads are `get::<C>()`, writes `put::<C>()`. |

Seven tables, seven named shapes. `TypeName`s on disk: `shekyl::Coded<leaf>`,
`shekyl::Coded<owned_leaf>`, `shekyl::Coded<leaf_meta>`,
`shekyl::Coded<frozen_segment>`, `shekyl::Coded<pending_leaf>`,
`shekyl::Present`, `shekyl::Blob<meta_cell>`. **How a pre-6 file is refused,
precisely.** `LeafStore::open` keeps its order — `check_schema_version` on an
existing file *before* `init_tables` (`:623`–`:639`), so nothing is created or
written in a file that is refused — but the version check itself opens `meta`
under its v6 definition (`Blob<MetaCellBytes>`), and a v5 file's `meta` is
stored as `&str → u64`: redb refuses that open with a type-name mismatch
**before any cell is read**. `open` names that as `StoreError::LayoutForeign
{ expected: 6 }` (the #772 shape) — not as a `SchemaVersionMismatch`, because
the file cannot say which version it is. A file whose `meta` opens (v6
layout) but whose cell disagrees is `SchemaVersionMismatch`; a file with no
cell is `SchemaVersionAbsent`. The `IMPLICIT_SCHEMA_VERSION = 1` fallback
(`:91`) and the five-version prose (`:53`–`:80`) are deleted: a version-6
store carries its version cell from creation, and there is no file the store
should read leniently (CTS-9). A test plants a v5-shaped `meta` table through
the raw engine and asserts `LayoutForeign` with the file unmodified.

---

## 4. Decomposition — `store/` as a module tree

As found: `store/mod.rs` (19 lines), `store/ops.rs` (217, the root math),
`store/redb_backend.rs` (**4 196**: schema + six codecs + `StoreError` +
`LeafStore` + `ServingReader` + `FrozenSegmentBody` + ~2 000 lines of tests).

Proposed, cut along what the store does (numbers are envelopes, verified at
pre-flight B6/B9 — a module over its envelope is a finding, not a fact):

| Module | Owns | Envelope |
| --- | --- | --- |
| `store/mod.rs` | `LeafStore` struct, `open`/`open_ephemeral`/`clear`, re-exports | ≤ 150 |
| `store/schema.rs` | the seven `TableDefinition`s, `SCHEMA_VERSION`, `tables!`-style catalogue (one list, the seal opens it) | ≤ 120 |
| `store/codec/{leaf,leaf_meta,frozen_segment,pending}.rs` | the four record types and their `Canonical` impls, each with its layout test and fixtures | ≤ 150 each |
| `store/meta.rs` | `MetaCell` trait, the five cells, `get`/`put`, schema-version check | ≤ 180 |
| `store/error.rs` | `StoreError` and the `From<redb::*>` impls | ≤ 200 |
| `store/ingest.rs` | `append_drained`, `append_block_deltas`, `read_pending_candidates`, `read_drained_entries` | ≤ 350 |
| `store/freeze.rs` | `maybe_freeze_segments[_in_txn]`, `next_freeze_seg`, `verify_frozen_tail`, `recompute_next_freeze_seg` | ≤ 250 |
| `store/serving.rs` | `ServingReader`, `FrozenSegmentBody`, `open_frozen_segment_body`, `scan_leaf_range` / `read_leaf_bytes_range*` | ≤ 350 |
| `store/pins.rs` | `pin_segment_for_serving`, `pin_serve_set`, `pinned_shard_ids`, `release_pins`, `members_missing_pins`, `SegmentPin` | ≤ 250 |
| `store/prune.rs` | `prune_frozen`, `pruned_frozen_segments`, `set_prune_disabled`, `PostureDeclaration` | ≤ 220 |
| `store/reorg.rs` | `truncate_from_tree_position`, `truncate_internals`, `present_suffix_start`, `rollback_to_fork`, the batched deleters | ≤ 400 |
| `store/root.rs` | `root_at_count` (over `ops.rs`) | ≤ 100 |
| `store/*_tests.rs` | one per module, beside it | — |

Two DRY moves the decomposition forces rather than permits: the three
`read_leaf_bytes_range*` variants (`:2134`–`:2158`) collapse onto one generic
over `ReadableTable` (the `chain_reads::ReadTables` pattern from #764), and the
`delete_*_batched` trio (`:1950`–`:2011`) collapses onto one generic over the
key type. Every `open_table(X)?` in an operation goes through one
`Tables<'txn>` helper that opens what the operation names, so a table is never
opened twice in one transaction under two bindings.

---

## 5. What this delivers against the threat model (rule 16)

The wallet store holds no secret and no consensus value: `Leaf` and `LeafMeta`
are public tree state; `OwnedLeaf` marks ownership *positions*, not keys. So the
security surface here is **integrity**, and the property this increment buys is
the one §11.1(f) bought the daemon: a file the engine accepts is a file whose
every row decodes under exactly one codec, and two tables cannot be confused
at open. Concretely, after this lands: a serving persona cannot serve
`owned_identities` bytes as `leaves` bytes through a drifted definition
(CTS-1); a `leaf_meta` row with a stray bit in its dead range cannot exist
(CTS-2 — there is no dead range); and the `prune_disabled` posture flag — the
one-way declaration `PostureDeclaration` exists to detect the loss of — is a
`bool` with two encodings, not a `u64` with 2⁶⁴ (CTS-8). None of this touches
privacy (`00-mission.mdc` #2): the stored fields are unchanged in meaning.

---

## 6. Commit sequence (PR B; rule 90 — one unit per commit, ≤ 9)

1. `curve-tree: store/{schema,error} — tables as a catalogue, StoreError in its own module` — pure move, no behaviour change; `redb_backend.rs` shrinks by what moved. Tests green unchanged.
2. `curve-tree: store/codec — Leaf, OwnedLeaf, LeafMeta, FrozenSegmentRecord, PendingLeaf as Canonical` — the records and their layout tests (each pins width, field offsets, and one strict-refusal per field that has one). **Not yet wired** to the tables (the codecs are testable alone, and the wiring is a layout change that wants its own commit).
3. `curve-tree: store/meta — typed MetaCells; prune_disabled is a bool` — the trait, five cells, `get`/`put`; `check_schema_version` and `init_tables` rewritten over them.
4. `curve-tree: layout v6 — every table value is a named shape; SCHEMA_VERSION 5 → 6` — the seven definitions retyped, every read/write site rewired onto the codecs, `IMPLICIT_SCHEMA_VERSION` and the version prose deleted, the pre-6 refusal test. **The one layout commit.**
5. `curve-tree: store/{ingest,freeze}` — moves + the `read_leaf_bytes_range` collapse.
6. `curve-tree: store/{serving,pins,prune}` — moves + `Tables<'txn>`.
7. `curve-tree: store/{reorg,root}` — moves + the `delete_*_batched` collapse; `redb_backend.rs` is deleted.
8. `curve-tree: tests beside their modules` — the ~2 000 test lines split to `*_tests.rs`; no test deleted, no assertion weakened (the diff is a move; a reviewer can check it as one).
9. `docs: CTS landed` — §10.

Commits 5–7 are moves whose only logic changes are the two named collapses;
each is reviewable as "does the moved body equal the old body modulo the
collapse". Commit 4 is the one a reviewer reads line by line.

---

## 7. Denominator — what must stay green, what must be extended

- `cargo test -p shekyl-curve-tree` including `tests/{store_kat,recon_kat,recon_tier_b,assemble_kat}.rs` — the KATs pin **roots and reconstructions**, not on-disk bytes, so they survive the layout change unchanged. Verified at pre-flight: `store_kat.rs` compares `LeafStore` hot-path roots to the recon oracle (`rust/shekyl-curve-tree/tests/store_kat.rs:6`).
- The nine dependents compile and their tests pass — `shekyl-p-host/tests/composition.rs` (44 references) and `shekyl-p-serve/tests/store_axis.rs` (15) are the external store consumers with the most reach.
- `cargo test -p shekyl-chain-store` unchanged after PR A; `schemas/*.snap` byte-identical (the re-export keeps every `TypeName` string).
- **Extended:** one layout test per record (commit 2); one strict-refusal test per shape (`Leaf` out-of-field scalar, `LeafMeta` bad tag / non-zero commitment under tag 0 / target 2, `FrozenSegmentRecord` wrong width, `PendingLeaf` short, `bool` `2`); the pre-6 refusal at open (commit 4); a module-size check in CI (`scripts/ci/check_file_size_ratchet.sh`-shaped, or the existing decomposition ratchet if it admits this crate — CTS-Q4).

---

## 8. Round-1 questions (proposed; each ruling to be written line-local)

| Q | Question | Default | Why it is a question |
| --- | --- | --- | --- |
| **CTS-Q1** | Does `open_frozen_segment_body` take a `FrozenSegment` handle obtainable only from `frozen_segment(id)` / the freeze, making "only frozen segments are servable" a compile-time fact (the `WriteBatch<'id>` brand pattern)? | **No, in this PR.** `SegmentPin` already makes the three servability states a value, and the handle is an external API change across `p-host`/`p-serve`. | Named in the §11.1(f) discussion as worth doing; the question is *where* — a typestate belongs to the increment that defines servability (S-ARCH for the daemon), and for the wallet store it is an API round of its own. Reopen when `p-host`'s serve-set code is next touched. |
| **CTS-Q2** | Crate name and home: `shekyl-store-codec` at `rust/shekyl-store-codec`, depending on `redb` + `shekyl-types` + `shekyl-units`? | **Yes.** | Alternatives considered: folding into `shekyl-types` (rejected — it depends on `redb`, and `shekyl-types` is `no_std` vocabulary); into `shekyl-curve-tree` (rejected — wrong direction for the daemon); `redb`-only (rejected on PR #776 review — the orphan rule then strands every vocabulary codec, CTS-13). |
| **CTS-Q6** | Where do the `Canonical` impls for vocabulary types live once the trait moves? | **In `shekyl-store-codec`**, which depends on the vocabulary crates; `RuleSetId` alone gets a chain-store-local adapter (`RuleSetInForce`). | The orphan rule leaves three homes: the trait's crate, the type's crate, or a local newtype per use. The type's crates are `no_std` and must not learn about `redb`; a newtype per vocabulary type per store is the duplication the shared crate exists to end; so the trait's crate hosts them, and the one type whose crate the codec crate must not depend on (the rules crate) is the one adapter. |
| **CTS-Q3** | Is `Leaf` a newtype over `shekyl_fcmp::ShekylLeaf`, or does `shekyl-fcmp` implement `Canonical` itself? | **Newtype in `shekyl-curve-tree`.** | The orphan rule forces the impl into `shekyl-fcmp` or the codec crate otherwise; a crypto crate depending on a store-codec crate is the wrong direction, and the codec crate depending on `shekyl-fcmp` is worse. |
| **CTS-Q4** | Does the module-envelope table (§4) become a CI ratchet for this crate? | **Yes**, via the existing file-size ratchet conf if it takes a per-crate entry; else a one-line gate. | A decomposition that is not held decomposes again. |
| **CTS-Q5** | Do `frozen_segments` integers move BE → LE? | **Yes.** | Values carry no ordering (that was the key-side reason for BE); every other record here and in the daemon store is LE via the shared `u64` codec; one integer codec, not two. The bump pays for it. |

---

## 9. Round-0 findings

| ID | Finding (at `d89f99791`) | Disposition |
| --- | --- | --- |
| **CTS-1** | `leaves` and `owned_identities` are both `TableDefinition<TreePosition, &[u8; 128]>` (`:22`, `:27`): identical `TypeName`s, different meanings; redb's open-time guard cannot tell them apart. | `Coded<Leaf>` vs `Coded<OwnedLeaf>` — distinct codec names over identical bytes (§3). |
| **CTS-2** | `leaf_meta` is 192 bytes of which 70 are dead or padding (`:2184`–`:2203`), integers BE, `creation_height` at `[122..130)` because it landed "in the formerly-free range" at schema v2 — the layout is the accretion history. | `LeafMeta`, dense 122 bytes, LE, designed once (§3). |
| **CTS-3** | `Leaf` is `[u8; 128]` on `LeafEntry` and in the table; `shekyl_fcmp::ShekylLeaf` (`leaf.rs:138`) already names the four scalars and PL-D3's `cm_x`. Two shapes for one leaf. | One `Leaf` codec; `LeafEntry.leaf` becomes `Leaf` (CTS-Q3). |
| **CTS-4** | `FrozenSegmentRecord` is encoded by hand at `:2160`–`:2181`, BE, with `expect("8 bytes")` on every field. | `Canonical` impl; LE (CTS-Q5). |
| **CTS-5** | `pending` = `leaf ‖ leaf_meta` by hand (`:2242`–`:2268`) with the invariant "one layout, two tables" stated in a comment. | `PendingLeaf` composes the two codecs; the invariant is structural. |
| **CTS-6** | `TargetKind` tag `2` (claim-era `StakedKey`) is documented as retired and "never contains it" (`:2289`–`:2297`) but the decoder's refusal is the generic `bad target tag`. | The `LeafMeta` decoder names it: `Invalid { reason: "target tag 2 is the retired claim-era StakedKey" }` — a refusal that says what it refuses (rule 82). |
| **CTS-7** | `pinned_segments: SegmentId → u32` stores `1` for every member (`:1630`); the value is never read for its content. | `Present`. |
| **CTS-8** | `meta` is `&str → u64` with five string keys, `unwrap_or` defaults at every read, and a `bool` as `0`/`1` in a `u64` (`:41`–`:51`, `:2020`–`:2042`). | Typed `MetaCell`s with per-key codecs; `bool` strict. |
| **CTS-9** | `IMPLICIT_SCHEMA_VERSION = 1` (`:91`) and `check_schema_version` treat an absent cell / absent table as "version 1" so the mismatch can be named — a format-detection affordance for files no current build wrote (rule 15). | Deleted. A v6 store writes its cell at creation; an absent cell is `SchemaVersionAbsent`; a foreign table type is `LayoutForeign` (the #772 shape). |
| **CTS-10** | `redb_backend.rs` is 4 196 lines: schema, six codecs, `StoreError` (17 variants), three handle types, every operation, and ~2 000 lines of tests in one file. | §4. |
| **CTS-11** | `read_leaf_bytes_range` × 3 (`_in`, plain, `_read`; `:2134`–`:2158`) and `delete_*_batched` × 3 (`:1950`–`:2011`) — three copies each of one loop, differing in the transaction or key type. | One generic each (§4). |
| **CTS-12** | The vocabulary types are already the shared ones — `types.rs:135` re-exports `BlockHeight`, `GlobalOutputIndex`, `OneTimePubkey`, `CommitmentBytes`, `CurveTreeRoot` from `shekyl_types` (RTN-4), and `Gindex = GlobalOutputIndex` (`:142`). `TreePosition` and `SegmentId` are crate-local, correctly: they are this store's coordinates, not chain vocabulary. | No change; recorded so the newtype question is not re-asked for these. |
| **CTS-13** | **(PR #776 review.)** PR A as first drafted (`shekyl-store-codec` depending on `redb` only) cannot be implemented: with `Canonical` foreign to `shekyl-chain-store`, its `impl Canonical for BlockHeight` / `CurveTreeRoot` / `PrunableHash` / `PqcAuthHash` / `AtomicUnits` / `RuleSetId` are foreign-trait-on-foreign-type, and a `redb`-only crate cannot host them. | The codec crate depends on `shekyl-types` and `shekyl-units` and hosts the vocabulary codecs once (§2.1 A, CTS-Q6); `RuleSetId` gets the one local adapter. Recorded so the next shared-trait move asks the orphan question at design time. |

---

## 10. Documentation owed (rule 91)

- `DAEMON_REDB_STORE.md` §11.1(f) last bullet: "will move … when the wallet-side curve-tree backend adopts them" → moved (PR A, #); the daemon store re-exports; the wallet store adopted (PR B, #).
- `CURVE_TREE_CLIENT.md` §3.6: one pointer paragraph — the store's value side follows §11.1(f); layout v6; this document as the record.
- `IMPLEMENTATION_INDEX.md`: `CTS-` family row (this PR); §7 document row (this PR); `CT-1…CT-5` row `UPDATE` when PR B lands.
- `docs/CHANGELOG.md`: one Unreleased line at PR B (wallet curve-tree store layout v6 — delete and re-sync; the `LeafStore` API is unchanged).
- This document: banner flips to landed at PR B; archive-or-contract per index §8 once E3 (the daemon's curve-tree tables) has read it.

---

## 11. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-18 | **PR #776 review (Copilot: 1 open + 5 suppressed; 6 taken, 0 refuted).** The open one reshaped PR A: with `Canonical` foreign to `shekyl-chain-store`, its vocabulary-type impls are orphan-rule violations, and a `redb`-only codec crate cannot host them — so `shekyl-store-codec` depends on `shekyl-types` + `shekyl-units` and hosts those codecs once for both stores, with `RuleSetId` as the one named local adapter (CTS-13, CTS-Q6). Suppressed, all valid: `Restorable`/`check_row` locations; `Blob<K>` missing from the allowed-shapes sentence; the pre-6 refusal stated precisely (the v6 `meta` open inside `check_schema_version` is where a v5 file is refused, before any cell is read — `LayoutForeign`; open order and no-mutation preserved); `CURVE_TREE_CLIENT.md` §3.6's "does not exist yet" gets an in-line UPDATE now; DRS §11.1(f)'s "three shapes" → four. |
| 2026-09-18 | **Round 0 executed at `d89f99791`.** Twelve findings, five questions with defaults, a two-PR split (shared crate first), a nine-commit sequence for PR B with one layout commit, and a module tree with envelopes to be held by a ratchet. The brief: proper types, DRY, decomposition — not transcription. The one thing deliberately *not* proposed is any change to what the nine dependents call. |
