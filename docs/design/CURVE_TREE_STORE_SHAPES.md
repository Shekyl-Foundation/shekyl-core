# Curve-tree `LeafStore` rewrite — typed value shapes, one codec contract, decomposition: plan and Round-0 pre-flight

**Status:** **CLOSED AS RECORD 2026-09-18 — superseded by unit.** Successor:
[`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md), which partitions this
document's `CTS-1…13` / `CTS-Q1…Q6` by unit in its §8 and carries the
unit-independent work forward as its increment 1. **Read this document as the
record of what was ruled on 2026-09-18 against the *leaf* unit**, not as a
live plan: `PDM-Q12` (`ARCHIVAL_PRUNED_DAEMON_MODE.md`, ruled and amended the
same day) retires the segment-freeze pipeline and re-keys the store's serving
half from leaves to prunable bodies, so `CTS-Q1`'s subject
(`open_frozen_segment_body`) and `CTS-4`/`CTS-Q5`'s `FrozenSegmentRecord` are
on that ruling's deletion surface. **The rulings below are not reversed; their
subjects are retired.** Closed as record rather than amended in place on
steering's ground (2026-09-18): *"CTS as-is was an initial design, but the
daemon DRS series has refined that design. In essence, the daemon is canon,
and the wallet store serves to securely serve a SLICE of that canonical
data."* One document holding a ruled leaf-unit design and a body-unit
supersession of it is how a contract starts lying.

**What retains its clearance: PR A alone** (`shekyl-store-codec`, §2.1 A /
§2.3), cleared ahead of the successor round by steering the same day — it is
the only piece here that survives every answer to the successor's `WSS-Q1`,
it is a mechanical move with re-exports and no behaviour change, and DRS-E3
wants it too. **No other implementation PR from this document lands.**

*Original status, retained:* OPEN — **Round 0 (pre-flight) executed 2026-09-18** at `dev` =
`d89f99791` (the #772 merge). **Round 1 ruled 2026-09-18** (maintainer, on PR
#776; §8, each ruling line-local): CTS-Q1 ruled to a third option — type the
**return** of `open_frozen_segment_body`, not the handle (§2.1 F, §3.1);
CTS-Q2…Q6 stand as defaulted. Implementation may start, PR A first. Rule-26
sub-PR discipline is
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
| The shared-crate move is named, not done | §11.1(f) last bullet: `Canonical`, `CodecError` and the shapes "will move to a redb-only shared crate when the wallet-side curve-tree backend adopts them — as the first commit of *that* PR, with `shekyl-chain-store` re-exporting so import paths move once. What does **not** travel: (b)'s bump obligation, the snapshot gate and the `impl Canonical` source scan." This document is that PR's plan. **UPDATE 2026-09-20:** done — PR A landed as PR #794 (`rust/shekyl-store-codec`), ahead of wallet adoption rather than as that PR's first commit, and not `redb`-only (CTS-13: it depends on `shekyl-types` and `shekyl-units`); `DAEMON_REDB_STORE.md` §11.1(f)'s last bullet is now the current statement, and DRS-D3d records the one admitted edge. |
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
`unwrap_or` defaults and a `bool` stored as `u64` `0`/`1`. Justified by the
class in §3.1, not by taste: an `unwrap_or` default is an absence read as a
value.

**F. Servability is a case (CTS-Q1, ruled).** `open_frozen_segment_body`
returns `Result<SegmentAvailability, StoreError>` with

```rust
#[must_use]
pub enum SegmentAvailability {
    /// Frozen, bytes present: serve it.
    Servable(FrozenSegmentBody),
    /// Not frozen yet (no committed `R_k`): will be. Ask again after the freeze.
    NotYetFrozen,
    /// Frozen, bytes pruned, no pin: never ask again — the store must be
    /// rebuilt by chain replay before this segment can be served.
    Pruned { id: SegmentId },
}
```

— the read-time twin of `SegmentPin` (`PinnedServable` / `PinnedNotYetFrozen`
/ `AlreadyPruned`), same three states, same words. `StoreError::
FrozenSegmentPruned` is deleted (its case is now an arm, not an error — 17
variants → 16); `CorruptMeta("pinned frozen segment is missing leaf bytes")`
stays an error, because a pinned segment losing bytes is an invariant
violation, not a servability state. **What this buys, stated at the
substrate rather than from the doc comments:** today the three states are
already distinct on the wire of the return — `Ok(Some)` / `Ok(None)` /
`Err(FrozenSegmentPruned)` — and `p-serve` maps the third by name
(`provider.rs:83`), so no caller is retrying forever *now*. What is wrong is
the *shape*: a legitimate state ("not yet") travels as an absence whose
meaning lives in a `witness.rs:427` doc comment, and the rebuild-required
instruction is one variant among seventeen, kept only by a caller that
matches that variant — any `other =>` arm loses it silently, and the compiler
will not say so. An exhaustive enum makes both instructions cases the caller
must write an arm for. This is the one `ServingReader` / `LeafStore` API
change in scope (§2.2 amended): `ServingReader::open_frozen_segment_body`
mirrors it; `p-serve`'s `StoreShardProvider::shard_bytes` maps `Servable` →
`Some(body)`, `NotYetFrozen` → `None`, `Pruned` → the existing
`ProviderError::FrozenSegmentPruned` (the `ShardProvider` trait and the serve
protocol are unchanged — that contract already names the case); `p-host`'s
witness reads the arm it names. One test pins the twins: for every segment in
a fixture, `pin_segment_for_serving`'s outcome and `open_frozen_segment_body`'s
arm agree.

**E. Docs:** this document; `CURVE_TREE_CLIENT.md` §3.6 pointer; DRS §11.1(f)
last bullet flips from "will move" to "moved"; index rows; CHANGELOG one line.

### 2.2 Out (named, so it is not scope shed by omission)

- **Any change to `LeafStore` / `ServingReader` method signatures or
  semantics, except the one ruled:** `open_frozen_segment_body`'s return
  (§2.1 F, CTS-Q1). Every other method is unchanged; seven of the nine
  dependents compile untouched, `p-serve` and `p-host` change at the two call
  sites named in §2.1 F. A typestate *handle* for servable segments remains
  out (CTS-Q1's ruling says why, and what reopens it).
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
| `meta` | `&str` | `u64` (`:41`); five keys; `prune_disabled` is a `bool` stored `0`/`1` (`:47`–`:51`) | CTS-8 | `Blob<MetaCellBytes>` + typed `MetaCell`s | `LeafCountCell: u64`, `SyncTipCell: BlockHeight`, `NextFreezeSegCell: u64` (bounded by `NEXT_FREEZE_SEG_MAX`, checked at decode), `SchemaVersionCell: u64`, `PruneDisabledCell: bool` (strict `0`/`1`). Per-key codec, like the daemon's `properties`; reads are `get::<C>()` returning the cell's **absence as a case** (§3.1), writes `put::<C>()`. |

### 3.1 Absence is a case, never a value — the class, stated once

Three times now this codebase has stored or returned an absence as a value
that sits inside the type's valid range, and each time the reader downstream
could not tell it from data:

1. **`curve_tree_roots`, daemon (CEN-I12):** a missing key returned a
   zero-initialised array on `MDB_NOTFOUND` (`src/blockchain_db/lmdb/db_lmdb.cpp:9745`–`:9760`),
   which decodes to the identity point *O* — and a proof anchored at
   `ref_height = 0` was verified against it. Consequence-free by a
   discrete-log argument, not by design (`CONSENSUS_STORE_RECONCILIATION.md`
   §5.4.1 CEN-I12).
2. **`top_block_hash`, daemon (SCR-4):** an empty chain hands back `UINT64_MAX`
   beside `null_hash` — two sentinels, neither distinguishable from data
   ([`DRS_E1_SCHAIN_R.md`](../completed/DRS_E1_SCHAIN_R.md) §3.4).
3. **`meta`, this store (CTS-8):** five `unwrap_or` defaults, so a missing
   `leaf_count` reads as `0`, a missing `prune_disabled` as `false`, and a
   missing `sync_tip` as height `0` — each a value the store could legitimately
   hold.
4. **`curve_tree_meta`, daemon (S-CURVE SCU-1, 2026-09-21) — the worst of the
   four:** three string-keyed cells defaulted three ways (`root` → Selene
   `hash_init`, `depth` → `0`, `leaf_count` → `0`; `db_lmdb.cpp:9259`–`:9313`),
   and the root read *documented* its own ambiguity — "callers should compare
   against `hash_init` or check `get_curve_tree_leaf_count()`" (`:9264`) — an
   API whose contract is "this return is ambiguous, disambiguate with a second
   read the caller may skip." One table over, a caller did skip it (instance 1).
   Closed in Rust by one typed row whose `EMPTY` is **written at store
   creation**, so absence is SI-7 and emptiness is a value
   ([`DRS_E1_SCURVE.md`](DRS_E1_SCURVE.md) §3.3).

The discriminator is already written where the rules crate reads by height
(`rust/shekyl-chain-rules/src/view.rs` §"Absence is a case, not a `None`",
`AtHeight`): **absence earns a type when its case carries caller-actionable
semantics** — when the caller must *do something different* on absence than
on any value, the absence is an arm the caller writes, never a default it
arrives at by `unwrap_or` or `?`. Two applications in this plan follow from
it, and both are justified by the class rather than argued afresh:

- **`MetaCell` reads return absence as a case** (`CellRead<C::Value>::{Recorded(v),
  Absent}`, or the cell's own error where absence is an invariant violation —
  `schema_version` absent is `SchemaVersionAbsent`; `leaf_count` absent on a
  sealed file is `CorruptMeta`). No `MetaCell` has a default.
- **`open_frozen_segment_body` returns `SegmentAvailability`** (§2.1 F):
  "not yet, retry" and "never, rebuild" are two instructions, and an `Option`
  can carry one.

Where the default *is* the semantics — a fresh file's `leaf_count` is zero
because the tree is empty — `init_tables` writes the cell; the reader still
does not default. The counter-rule stands too: `Option` stays `Option` where
the absent value lies *outside* the type's range and no arm differs
([`DRS_E1_SCHAIN_R.md`](../completed/DRS_E1_SCHAIN_R.md) §3.4, "`Option` stays `Option` (ruled)").

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
`bool` with two encodings, not a `u64` with 2⁶⁴ (CTS-8). One availability
property rides along (§2.1 F): a serving host cannot lose the
rebuild-required instruction to an `other =>` arm, because it is a case of
the return, not a variant of the error. None of this touches privacy
(`00-mission.mdc` #2): the stored fields are unchanged in meaning.

---

## 6. Commit sequence (PR B; rule 90 — one unit per commit, 10)

1. `curve-tree: store/{schema,error} — tables as a catalogue, StoreError in its own module` — pure move, no behaviour change; `redb_backend.rs` shrinks by what moved. Tests green unchanged.
2. `curve-tree: store/codec — Leaf, OwnedLeaf, LeafMeta, FrozenSegmentRecord, PendingLeaf as Canonical` — the records and their layout tests (each pins width, field offsets, and one strict-refusal per field that has one). **Not yet wired** to the tables (the codecs are testable alone, and the wiring is a layout change that wants its own commit).
3. `curve-tree: store/meta — typed MetaCells, absence as a case; prune_disabled is a bool` — the trait, five cells, `get`/`put` (§3.1); `check_schema_version` and `init_tables` rewritten over them.
4. `curve-tree: layout v6 — every table value is a named shape; SCHEMA_VERSION 5 → 6` — the seven definitions retyped, every read/write site rewired onto the codecs, `IMPLICIT_SCHEMA_VERSION` and the version prose deleted, the pre-6 refusal test. **The one layout commit.**
5. `curve-tree: servability is a case — SegmentAvailability replaces Option + FrozenSegmentPruned` — §2.1 F; the store, `ServingReader`, the two callers in `p-serve` / `p-host`, the twins test. **The one API commit**, on its own so the caller diff is read as a caller diff. No layout change.
6. `curve-tree: store/{ingest,freeze}` — moves + the `read_leaf_bytes_range` collapse.
7. `curve-tree: store/{serving,pins,prune}` — moves + `Tables<'txn>`.
8. `curve-tree: store/{reorg,root}` — moves + the `delete_*_batched` collapse; `redb_backend.rs` is deleted.
9. `curve-tree: tests beside their modules` — the ~2 000 test lines split to `*_tests.rs`; no test deleted, no assertion weakened (the diff is a move; a reviewer can check it as one).
10. `docs: CTS landed` — §10.

Commits 6–8 are moves whose only logic changes are the two named collapses;
each is reviewable as "does the moved body equal the old body modulo the
collapse". Commits 4 and 5 are the ones a reviewer reads line by line. Ten
commits is rule 06's ceiling, not a target; if 6–8 prove trivially
reviewable as one move they merge, never the other way.

---

## 7. Denominator — what must stay green, what must be extended

- `cargo test -p shekyl-curve-tree` including `tests/{store_kat,recon_kat,recon_tier_b,assemble_kat}.rs` — the KATs pin **roots and reconstructions**, not on-disk bytes, so they survive the layout change unchanged. Verified at pre-flight: `store_kat.rs` compares `LeafStore` hot-path roots to the recon oracle (`rust/shekyl-curve-tree/tests/store_kat.rs:6`).
- The nine dependents compile and their tests pass — `shekyl-p-host/tests/composition.rs` (44 references) and `shekyl-p-serve/tests/store_axis.rs` (15) are the external store consumers with the most reach. Seven compile untouched; `p-serve` (`provider.rs:288`) and `p-host` (`serve_set/witness.rs`) change at the `open_frozen_segment_body` call sites only (commit 5), and `p-serve`'s existing `ProviderError::FrozenSegmentPruned` tests are the assertion that the `Pruned` arm still reaches the serve protocol by name.
- `cargo test -p shekyl-chain-store` unchanged after PR A; `schemas/*.snap` byte-identical (the re-export keeps every `TypeName` string).
- **Extended:** one layout test per record (commit 2); one strict-refusal test per shape (`Leaf` out-of-field scalar, `LeafMeta` bad tag / non-zero commitment under tag 0 / target 2, `FrozenSegmentRecord` wrong width, `PendingLeaf` short, `bool` `2`); the pre-6 refusal at open (commit 4); a module-size check in CI (`scripts/ci/check_file_size_ratchet.sh`-shaped, or the existing decomposition ratchet if it admits this crate — CTS-Q4).

---

## 8. Round-1 questions — RULED 2026-09-18 (maintainer, PR #776; each row carries its ruling)

| Q | Question | Default → **Ruling** | Why it is a question |
| --- | --- | --- | --- |
| **CTS-Q1** | Does `open_frozen_segment_body` take a `FrozenSegment` handle obtainable only from `frozen_segment(id)` / the freeze, making "only frozen segments are servable" a compile-time fact (the `WriteBatch<'id>` brand pattern)? | Default was **no, in this PR**. **RULED 2026-09-18: a third option — type the *return*, not the handle.** `Result<SegmentAvailability, StoreError>` with `Servable(body)` / `NotYetFrozen` / `Pruned { id }` (§2.1 F), the read-time twin of `SegmentPin`. The typestate handle would prevent serving a non-frozen segment, which the runtime check already prevents; the typed return makes "retry later" and "rebuild required" two arms a caller must write, which nothing forces now. One return type, not a type parameter threaded through the handle; still an API change, but one that buys the thing worth buying. **Premise correction, recorded (rule 16's corollary):** the ruling as posed said `Ok(None)` collapses retry-later with rebuild-required; at the source it does not — pruned is `Err(FrozenSegmentPruned)` (`redb_backend.rs:1895`) and `p-serve` maps it by name (`provider.rs:83`). The ruling stands on the shape argument in §2.1 F, not on a live liveness defect. | The question was aimed one notch from the gap: servability was already a value (`Option`), just the wrong one. The **handle** stays out; it reopens on a named trigger, not on the next touch: **when `open_frozen_segment_body` gains a caller or loses one, or when a fourth servability state is added** — falsify by `rg open_frozen_segment_body rust/ --type rust` returning a call site not listed in §2.1 F. |
| **CTS-Q2** | Crate name and home: `shekyl-store-codec` at `rust/shekyl-store-codec`, depending on `redb` + `shekyl-types` + `shekyl-units`? | **Yes — RULED 2026-09-18, stands.** | Alternatives considered: folding into `shekyl-types` (rejected — it depends on `redb`, and `shekyl-types` is `no_std` vocabulary); into `shekyl-curve-tree` (rejected — wrong direction for the daemon); `redb`-only (rejected on PR #776 review — the orphan rule then strands every vocabulary codec, CTS-13). |
| **CTS-Q6** | Where do the `Canonical` impls for vocabulary types live once the trait moves? | **In `shekyl-store-codec`**, which depends on the vocabulary crates; `RuleSetId` alone gets a chain-store-local adapter (`RuleSetInForce`). **RULED 2026-09-18, stands** (ruled with Q2; it is Q2's dependency list, decided). | The orphan rule leaves three homes: the trait's crate, the type's crate, or a local newtype per use. The type's crates are `no_std` and must not learn about `redb`; a newtype per vocabulary type per store is the duplication the shared crate exists to end; so the trait's crate hosts them, and the one type whose crate the codec crate must not depend on (the rules crate) is the one adapter. |
| **CTS-Q3** | Is `Leaf` a newtype over `shekyl_fcmp::ShekylLeaf`, or does `shekyl-fcmp` implement `Canonical` itself? | **Newtype in `shekyl-curve-tree` — RULED 2026-09-18, stands.** | The orphan rule forces the impl into `shekyl-fcmp` or the codec crate otherwise; a crypto crate depending on a store-codec crate is the wrong direction, and the codec crate depending on `shekyl-fcmp` is worse. |
| **CTS-Q4** | Does the module-envelope table (§4) become a CI ratchet for this crate? | **Yes — RULED 2026-09-18, stands**, via the existing file-size ratchet conf if it takes a per-crate entry; else a one-line gate. | A decomposition that is not held decomposes again. |
| **CTS-Q5** | Do `frozen_segments` integers move BE → LE? | **Yes — RULED 2026-09-18, stands.** | Values carry no ordering (that was the key-side reason for BE); every other record here and in the daemon store is LE via the shared `u64` codec; one integer codec, not two. The bump pays for it. |

---

## 9. Round-0 findings

| ID | Finding (at `d89f99791`) | Disposition |
| --- | --- | --- |
| **CTS-1** | `leaves` and `owned_identities` are both `TableDefinition<TreePosition, &[u8; 128]>` (`:22`, `:27`): identical `TypeName`s, different meanings; redb's open-time guard cannot tell them apart. | `Coded<Leaf>` vs `Coded<OwnedLeaf>` — distinct codec names over identical bytes (§3). |
| **CTS-2** | `leaf_meta` is 192 bytes of which 70 are dead or padding (`:2184`–`:2203`), integers BE, `creation_height` at `[122..130)` because it landed "in the formerly-free range" at schema v2 — the layout is the accretion history. | `LeafMeta`, dense 122 bytes, LE, designed once (§3). *Round 1:* the clearest single argument in the sweep for why PR B is a rewrite and not a cleanup — a field placed where a range happened to be free is a layout nobody designed. |
| **CTS-3** | `Leaf` is `[u8; 128]` on `LeafEntry` and in the table; `shekyl_fcmp::ShekylLeaf` (`leaf.rs:138`) already names the four scalars and PL-D3's `cm_x`. Two shapes for one leaf. | One `Leaf` codec; `LeafEntry.leaf` becomes `Leaf` (CTS-Q3). |
| **CTS-4** | `FrozenSegmentRecord` is encoded by hand at `:2160`–`:2181`, BE, with `expect("8 bytes")` on every field. | `Canonical` impl; LE (CTS-Q5). |
| **CTS-5** | `pending` = `leaf ‖ leaf_meta` by hand (`:2242`–`:2268`) with the invariant "one layout, two tables" stated in a comment. | `PendingLeaf` composes the two codecs; the invariant is structural. |
| **CTS-6** | `TargetKind` tag `2` (claim-era `StakedKey`) is documented as retired and "never contains it" (`:2289`–`:2297`) but the decoder's refusal is the generic `bad target tag`. | The `LeafMeta` decoder names it: `Invalid { reason: "target tag 2 is the retired claim-era StakedKey" }` — a refusal that says what it refuses (rule 82). |
| **CTS-7** | `pinned_segments: SegmentId → u32` stores `1` for every member (`:1630`); the value is never read for its content — a set wearing a map. | `Present`, reused from #772: one shape for one concept across both stores. |
| **CTS-8** | `meta` is `&str → u64` with five string keys, `unwrap_or` defaults at every read, and a `bool` as `0`/`1` in a `u64` (`:41`–`:51`, `:2020`–`:2042`). A missing key reads as a default indistinguishable from a stored value — the third instance of the class in §3.1. | Typed `MetaCell`s with per-key codecs, absence returned as a case (§3.1); `bool` strict. |
| **CTS-9** | `IMPLICIT_SCHEMA_VERSION = 1` (`:91`) and `check_schema_version` treat an absent cell / absent table as "version 1" so the mismatch can be named — dead compatibility for a version that exists nowhere: it advertises coverage for a case that cannot occur (rule 15). | Deleted. A v6 store writes its cell at creation; an absent cell is `SchemaVersionAbsent`; a foreign table type is `LayoutForeign` (the #772 shape). |
| **CTS-10** | `redb_backend.rs` is 4 196 lines: schema, six codecs, `StoreError` (17 variants), three handle types, every operation, and ~2 000 lines of tests in one file. | §4. |
| **CTS-11** | `read_leaf_bytes_range` × 3 (`_in`, plain, `_read`; `:2134`–`:2158`) and `delete_*_batched` × 3 (`:1950`–`:2011`) — three copies each of one loop, differing in the transaction or key type. | One generic each (§4). |
| **CTS-12** | The vocabulary types are already the shared ones — `types.rs:135` re-exports `BlockHeight`, `GlobalOutputIndex`, `OneTimePubkey`, `CommitmentBytes`, `CurveTreeRoot` from `shekyl_types` (RTN-4), and `Gindex = GlobalOutputIndex` (`:142`). `TreePosition` and `SegmentId` are crate-local, correctly: they are this store's coordinates, not chain vocabulary. | No change; recorded so the newtype question is not re-asked for these. |
| **CTS-13** | **(PR #776 review.)** PR A as first drafted (`shekyl-store-codec` depending on `redb` only) cannot be implemented: with `Canonical` foreign to `shekyl-chain-store`, its `impl Canonical for BlockHeight` / `CurveTreeRoot` / `PrunableHash` / `PqcAuthHash` / `AtomicUnits` / `RuleSetId` are foreign-trait-on-foreign-type, and a `redb`-only crate cannot host them. | The codec crate depends on `shekyl-types` and `shekyl-units` and hosts the vocabulary codecs once (§2.1 A, CTS-Q6); `RuleSetId` gets the one local adapter. Recorded so the next shared-trait move asks the orphan question at design time. |

---

## 10. Documentation owed (rule 91)

- `DAEMON_REDB_STORE.md` §11.1(f) last bullet: "will move … when the wallet-side curve-tree backend adopts them" → moved (PR A, #); the daemon store re-exports; the wallet store adopted (PR B, #).
- `CURVE_TREE_CLIENT.md` §3.6: one pointer paragraph — the store's value side follows §11.1(f); layout v6; this document as the record.
- `IMPLEMENTATION_INDEX.md`: `CTS-` family row (this PR); §7 document row (this PR); `CT-1…CT-5` row `UPDATE` when PR B lands.
- `docs/CHANGELOG.md`: one Unreleased line at PR B (wallet curve-tree store layout v6 — delete and re-sync; one `LeafStore` / `ServingReader` API change: `open_frozen_segment_body` returns `SegmentAvailability`).
- This document: banner flips to landed at PR B; archive-or-contract per index §8 once E3 (the daemon's curve-tree tables) has read it.

---

## 11. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-18 | **Closed as record; superseded by unit.** `PDM-Q12` retires the segment-freeze pipeline and rebuilds the store's serving half around prunable bodies keyed by shard, which retires `CTS-Q1`'s subject and `CTS-4`/`CTS-Q5`'s record. Successor round opened the same day: [`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md), family `WSS-`, which partitions this document's findings and questions into unit-independent (its increment 1), superseded-by-the-body-unit, and `WSS-Q1`-dependent buckets (§8 there). Steering ruled successor-round over scope-amendment: the daemon is canon and the wallet store serves a slice of it, so a document ruled against the leaf unit stays a record rather than becoming a contract that contradicts itself. PR A (`shekyl-store-codec`) keeps its clearance and lands as the successor's increment 1; nothing else here is built. |
| 2026-09-18 | **Round 1 ruled (maintainer, on PR #776).** CTS-Q1 to a third option: type the return of `open_frozen_segment_body` — `SegmentAvailability { Servable, NotYetFrozen, Pruned }`, the twin of `SegmentPin` — rather than a typestate handle; the handle would prevent what the runtime check already prevents, the typed return makes retry-later and rebuild-required two arms a caller must write. Premise correction recorded in the row: at source the pruned case is already `Err(FrozenSegmentPruned)` and `p-serve` names it, so the defect is shape (a state as an absence; an instruction as one error variant among seventeen), not a live retry-forever. Handle reopening sharpened from "when serve-set code is next touched" to a named trigger with a falsifier. **§3.1 added — "absence is a case, never a value"** — the class stated once with its three instances (`curve_tree_roots` → *O*, CEN-I12; `top_block_hash` `UINT64_MAX`, SCR-4; `meta` `unwrap_or`, CTS-8) and the rules crate's discriminator; `MetaCell` justified by it. CTS-Q2…Q6 stand; CTS-7/8/9 dispositions sharpened as ruled (set wearing a map; third instance; coverage for a case that cannot occur). Commit sequence gains the one API commit (10). Implementation may start, PR A first. |
| 2026-09-18 | **PR #776 review (Copilot: 1 open + 5 suppressed; 6 taken, 0 refuted).** The open one reshaped PR A: with `Canonical` foreign to `shekyl-chain-store`, its vocabulary-type impls are orphan-rule violations, and a `redb`-only codec crate cannot host them — so `shekyl-store-codec` depends on `shekyl-types` + `shekyl-units` and hosts those codecs once for both stores, with `RuleSetId` as the one named local adapter (CTS-13, CTS-Q6). Suppressed, all valid: `Restorable`/`check_row` locations; `Blob<K>` missing from the allowed-shapes sentence; the pre-6 refusal stated precisely (the v6 `meta` open inside `check_schema_version` is where a v5 file is refused, before any cell is read — `LayoutForeign`; open order and no-mutation preserved); `CURVE_TREE_CLIENT.md` §3.6's "does not exist yet" gets an in-line UPDATE now; DRS §11.1(f)'s "three shapes" → four. |
| 2026-09-18 | **Round 0 executed at `d89f99791`.** Twelve findings, five questions with defaults, a two-PR split (shared crate first), a nine-commit sequence for PR B with one layout commit, and a module tree with envelopes to be held by a ratchet. The brief: proper types, DRY, decomposition — not transcription. The one thing deliberately *not* proposed is any change to what the nine dependents call. |
