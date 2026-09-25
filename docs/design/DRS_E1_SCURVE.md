# DRS-E1 S-CURVE — curve-tree reads: increment plan and Round-0 pre-flight

**Status:** LANDED — **implemented 2026-09-21** on the S-CURVE PR cut from
`dev` @ `fdb5db954` (three commits, §7); **Round 0 executed 2026-09-21** at
`b680d59e0`, **Round 1 RULED 2026-09-21** (maintainer, on PR #815; §9, each
row line-local): **SCU-Q1 one row, SCU-Q2 move to `shekyl-types` and write
the rule down (done: `18-type-placement.mdc`), SCU-Q3 overridden to a tuple
key, SCU-Q4 now with E3 named; SCU-1 regraded the worst of its class.** This
file stays in `design/` as the E3 boundary statement (§2.3) until E3's plan
owns that statement; then it archives (rule 95). Implements *from*
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7 (the S-CURVE row:
extraction order **6**, "reads only; the arithmetic lives in `shekyl-fcmp`,
not here; depends on chain state but nothing depends on it, so it can move
once the chain surfaces are stable" — they are, §1), §7.6 (parity first; the
comparator projects logical content) and the E3 boundary (§7.5 table 2:
CEN-I19 / CEN-L11 / CEN-L12 are **E3 S-CURVE** — the *grow* path is E3's, and
this increment mints the shapes it will write into); from
[`DRS_E1_SCHAIN_R.md`](../completed/DRS_E1_SCHAIN_R.md) (the read handle,
`AtHeight`, the fault policy — this surface is more reads on `ReadSnapshot`);
from [`DRS_E1_SOUT_KI.md`](../completed/DRS_E1_SOUT_KI.md) (`AtIndex<T>` for
the one dense-position read here); from
[`DRS_E1_STX.md`](../completed/DRS_E1_STX.md) §3.3 (three absence shapes, one
discriminator — applied, not re-derived, in §3.3; and the Q3 re-ruling that a
range read over a keyed dense table is completeness, not a feature, which
decides the chunk read's fate in §6 item 2); and from
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) **`PDM-Q3`**
and **`PDM-Q12`** (the serve-credit verifier and the segment-freeze pipeline
are retired by ruling and die at E4 / S-ARCH) — the two rulings that decide
which of this surface's C++ callers are already dead. Process per
`26-sub-pr-design-discipline.mdc`; identifier families **`SCU-`** (findings)
and **`SCU-Q`** (round questions) registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by the PR that adds
this file (rule 94 §1; `check_index_prefix_uniqueness.py` branch (a): the two
parse to distinct prefixes and clear the 91 registered).

**Two stores, stated once so they are not conflated.** The *daemon's*
curve tree — the consensus accumulator every node grows per accepted output
(CEN-L11) — lives in the daemon store's `curve_tree_*` tables and is this
surface. The *wallet-side* store ([`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md),
`rust/shekyl-curve-tree/src/store/`) is a serving store rebuilt around
prunable bodies (`PDM-Q12`); it shares the tree's **vocabulary**
(`TreePosition`, the 128-byte leaf) and nothing else. §3.4 and `SCU-Q2` are
about sharing that vocabulary without coupling the stores.

---

## 1. Preconditions, as found at the pin

| Precondition | State at `b680d59e0` |
|---|---|
| S-TXN … S-TX (E1 increments 1–6) | landed (#740, #749, #757, #772, #783, #800) |
| `ReadSnapshot`, `AtHeight`, `AtIndex`, `chain_reads::cell`, the fault policy | landed (S-CHAIN-R, S-OUT-KI) |
| `curve_tree_roots` shaped: `TableDefinition<u64, Coded<CurveTreeRoot>>` (`schema.rs:478`), written by `connect` from `root_after` (SCW-19), read by `ReadSnapshot::live_root` for the E2 digest (`read.rs:584`) and by `ChainView::root_at` (`store/view.rs:196`) | landed |
| `curve_tree_leaves`, `curve_tree_layers`, `curve_tree_meta`, `curve_tree_checkpoints`: `Unshaped` (`schema.rs:463–475`) | **this increment shapes the first three; the fourth is E3's (§2.2)** |
| Layout `SCHEMA_VERSION = 8` (`codec/schema_version.rs:80`); rule-42 snapshot gate | landed — this increment bumps to 9 |
| `shekyl-store-codec` (PR A, #794): vocabulary codecs live with the vocabulary (CTS-13) | landed |
| `PDM-Q3`, `PDM-Q12` | RULED 2026-09-18 |

The stated dependency is S-CHAIN-R (height context for `root_at`) and nothing
from a later surface. Unblocked on that ground.

---

## 2. Scope

### 2.1 In — the census, method by method

Five methods (`blockchain_db.h:2659–2732`), every caller outside the DB layer
enumerated by `rg` at the pin and classified. **Class** is what happens to the
caller: *validator* (the C++ validation path E6 replaces), *RPC* (a served
route whose Rust home is `shekyl-daemon-rpc` through the facts FFI), *E2*
(the LMDB-side oracle, dies with LMDB), *retired* (dead by ruling, live in
code, deleted at the named increment), *E3* (the grow path's own reads).

| # | Method | Callers outside the DB layer | Class | Rust read |
|---|---|---|---|---|
| 1 | `get_curve_tree_root()` → `[u8;32]` (Selene `hash_init` when `"root"` is absent) | `blockchain.cpp:1882`, `:5437` (template / verify: the tip root) — *validator*; `core_rpc_server.cpp:1421` (`get_curve_tree_info`) — *RPC*; `logical_state_digest.cpp:81`, `blockchain_db.cpp:644` — *E2 / add_block internals* | mixed | **C1** (`curve_tree()` summary, §3.2) |
| 2 | `get_curve_tree_depth()` → `u8` (0 when `"depth"` is absent) | `blockchain.cpp:3766`, `:3915`, `:4186` (FCMP reference depth) — *validator*; `core_rpc_server.cpp:1424` — *RPC*; `daemon_submit_ffi.cpp:420` (`facts.tree_depth`) — *RPC facts FFI* | mixed | **C1** |
| 3 | `get_curve_tree_leaf_count()` → `u64` (0 when absent) | `core_rpc_server.cpp:1425` — *RPC*; `archival_shard_coverage.cpp:33` and `blockchain.cpp:1502` (both feed `shekyl_archival_frozen_segment_count`) — **retired** (`PDM-Q12`: the freeze pipeline; SCU-3); `blockchain_db.cpp:862` — *add_block internals* | mixed | **C1** |
| 4 | `get_curve_tree_leaf_chunk(first, count, out)` → `bool` (whole-chunk miss on any gap or short row) | `blockchain.cpp:4956` (serve-credit challenge over a frozen segment) — **retired** (`PDM-Q3`: the serve-credit verifier dies at E4; SCU-2); `blockchain_db.cpp:1691` is the base-class default | retired | **C3** (`leaves(range)`, §3.2 — on completeness grounds, SCU-2) |
| 5 | `get_curve_tree_root_at_height(h)` → `[u8;32]` (**all-zero when absent**) | `blockchain.cpp:3765`, `:3914`, `:4176` (FCMP reference root) — *validator*; `daemon_submit_ffi.cpp:417` (`facts.root` at `ref_height`) — *RPC facts FFI*; `shekyl_e2_trace_export.cpp:137` — *E2* | mixed | **C2** — already `ChainView::root_at` → `AtHeight<CurveTreeRoot>` (`view.rs:191`); this increment makes the store's public read the one the view impl calls |

Two methods the census does **not** list under S-CURVE and this increment
does not port: `get_curve_tree_leaf_by_tree_position` and
`get_curve_tree_leaf_by_output_index` (`db_lmdb.cpp:9315`, `:9385`). They are
not in the §7 row's five; their only reader is the path assembler the wallet
now owns (SOK-10) — recorded in §2.2 so their absence is a decision, not an
omission.

### 2.2 Out (named, so it is not scope shed by omission)

- **The grow path** — `grow_curve_tree`, `trim_curve_tree`,
  `store_curve_tree_root_at_height`, `remove_curve_tree_root_at_height`
  (`db_lmdb.cpp:8760–8970`, `:9395`, `:9425`) and everything under
  `pending_tree_leaves` / `pending_tree_drain` / `block_pending_additions` /
  `output_to_leaf` / `leaf_to_output`. **E3** (§7.5 table 2: CEN-L11, CEN-L12,
  CEN-I19). This increment mints the shapes E3 writes into and nothing E3
  decides.
- **`curve_tree_checkpoints`** (`schema.rs:472`, accumulator class `Derived`).
  No read in the census; written and read by the grow path only
  (`db_lmdb.cpp:9584`, `:9600`). Stays `Unshaped`; E3's.
- **The two leaf-by-* reads** (§2.1 tail). Not in the row; consumer is the
  wallet.
- **The wallet-side store** (`WALLET_SIDE_STORE.md`). Different store,
  different unit; shares vocabulary only (§3.4, `SCU-Q2`).
- **The C++ callers' deletions.** Validator callers die with E6's cutover;
  retired callers die at E4 / S-ARCH; RPC callers move when
  `shekyl-daemon-rpc` reads the redb store. None is this increment's, and no
  daemon is built until the redb conversion is complete.

### 2.3 What E3 gets from this increment

The three tables it will write, **typed**: `curve_tree_leaves[TreePosition] →
TreeLeaf`, `curve_tree_layers[LayerChunk] → LayerHash`, `curve_tree_meta` as
one `CurveTreeState` row (§3.4). E3 writes what these reads read; it does not
get to choose a second shape for the same byte.

**What E3 is asked for (E6 slice 6, 2026-09-25 — CEN-I13's operand).** A
**height-keyed depth read**: the tree's depth **at** chain height `h` — the
depth after the block at `h − 1` connected, before the block at `h` drained
its leaves — keyed exactly as `curve_tree_roots[h]` is (SCW-19), so a spend
whose reference is `ref_height` is measured against the depth of the tree
its proof was built over, not the depth of whatever tree exists when the
block is judged. Surface: `ChainView::depth_at(height) -> AtHeight<TreeDepth>`
beside `root_at`, the per-height record written by the same connect that
writes the root (a `(root, depth)` row at `h`, or a second table keyed the
same way — E3's shape to choose; the ask is the *keying*). Why height-keyed
and not the current depth the C++ reads (`get_curve_tree_depth()`,
`blockchain.cpp:4162`): `CHAIN_RULES_SLICE_6.md` §3.3 and Q8 — current depth
is correct only under three dependencies, one of which is an ordering
argument (I10 refuses a `ref_height` a reorg removed before I13 reaches it),
and ordering arguments have been wrong twice this month; the height-keyed
read removes the dependency rather than documenting it. **Until it exists,
CEN-I13 is slice 6's named successor** (`CHAIN_RULES_SLICE_6.md` §5 row 6;
`FOLLOWUPS.md`), not a current-depth read taken early. Falsify by:
`rg 'fn depth_at' rust/shekyl-chain-rules/src/view.rs` → the trait method,
with `BatchView`'s impl in `store/view.rs`.

### 2.4 What DRS-E2 gets

Nothing new to compare — `digest_v0`'s root family already reads
`curve_tree_roots[tip + 1]` (`read.rs:505`). What moves: `live_root` stops
being a private helper of the digest read and becomes the surface's **C1**
root, so the digest reads the same public cell every other consumer does
(one read, one absence rule).

### 2.5 What this pre-flight closes

- S-TX's index row said that plan "stays in `design/` until S-CURVE's
  pre-flight has read it." Read (§3.3 applies its discriminator); archived to
  `completed/` by the PR that adds this file (§10).

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the reads live

`rust/shekyl-chain-store/src/store/curve_reads.rs`, methods on
`ReadSnapshot`, faults through `chain_reads::cell` (the fault names its
table, as S-TX's dedupe left it). No new handle, no new error enum.

### 3.2 The mapping — 5 methods, 3 reads

| Read | Signature | Replaces | Semantics |
|---|---|---|---|
| **C1** | `curve_tree(&self) -> Result<CurveTreeState, StoreError>` | #1, #2, #3 | The tree's summary as **one row**: `root: CurveTreeRoot`, `depth: TreeDepth`, `leaf_count: LeafCount`. The three C++ reads are always consumed together (`core_rpc_server.cpp:1421–1425` reads all three; the validator reads root + depth) and the C++ writes them together (`db_lmdb.cpp:8936–8966`, one grow). Three string-keyed cells that must agree become one value that cannot disagree. `SCU-Q1`. |
| **C2** | `root_at(&self, h: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, StoreError>` | #5 | `curve_tree_roots[h]` is **the tree state going into block `h`** — written by the connect of `h − 1`; row 0 is `CurveTreeRoot::EMPTY`; rows `1..=tip + 1` are present (SI-7 otherwise); the live root is the row at `tip + 1` (`store/view.rs:191–205`, already documented there; E2's exporter reads `h + 1` for "after `h`", `shekyl_e2_trace_export.cpp:137`). The table's own key, stated once. `AboveTip` for `h > tip + 1`. This is exactly the shape and contract `ChainView::root_at` already has; the increment makes it the store's **public** read and the view impl delegates to it — one read, one absence rule, no private twin. |
| **C3** | `leaves(&self, range: Range<TreePosition>) -> Result<AtIndex<Vec<TreeLeaf>>, StoreError>` | #4 | A bounded walk over `curve_tree_leaves` in the table's own key order. **Dense by invariant** (SCU-SI, §5): a gap or short row inside `[0, leaf_count)` is `StoreInvariant`, exactly what the C++ meant by "registry/tree disagreement" and reported as a whole-chunk `false`. `AtIndex::AboveCount` when the range reaches past `leaf_count`. Ported on **completeness grounds** (S-TX Q3 re-ruling): a range read is part of what makes a keyed dense table a table; its C++ consumer is retired (SCU-2) and its Rust consumer is **E3**, which needs to read back what it writes — named here (rule 23 STAGED). |

### 3.3 Absence, faults, and what a read may not do — the S-TX discriminator applied

S-TX §3.3's rule: absence earns a type when its case carries caller-actionable
semantics; otherwise `Option`. Applied:

- **An empty tree is a case, not a set of defaults.** The C++ reads default on
  absence three different ways — `root` → Selene `hash_init`
  (`db_lmdb.cpp:9270`), `depth` → `0`, `leaf_count` → `0` — and the comment
  at `:9264` tells callers to *compare against `hash_init`* to tell an empty
  tree from a root that happens to be the identity. That is the
  absence-as-value class this program has now met four times
  (`curve_tree_roots`' zero root reaching FCMP verification, `top_block_hash`'s
  `UINT64_MAX`, the wallet-side `meta`'s `unwrap_or`, and here), stated once
  in `CURVE_TREE_STORE_SHAPES.md` CTS-8 / `CTS-Q1` — and this instance is
  the worst of them, because the ambiguity is *documented* and the
  disambiguation is delegated to a second read the caller may skip (SCU-1). **C1 returns
  `CurveTreeState`; the empty tree is `CurveTreeState::EMPTY`** (root
  `CurveTreeRoot::EMPTY`, depth 0, count 0) **written as a row at store
  creation**, so a missing `curve_tree_meta` row is `StoreInvariant`, never a
  default. No caller compares against `hash_init` again.
- **`root_at` above the tip** is `AtHeight::AboveTip` — the shape S-CHAIN-R
  minted and `ChainView` already uses. The C++'s all-zero root on
  `MDB_NOTFOUND` (`db_lmdb.cpp:9415`) is the same class; E2's exporter had to
  document it (SCU-4). Gone in Rust by the type.
- **A leaf position past the count** is `AtIndex::AboveCount` (S-OUT-KI's
  shape); a position *inside* the count with no row is `StoreInvariant`
  (§5). The C++ collapsed both into `false`.
- **What a read may not do:** synthesise a default, read `curve_tree_meta`
  by string key, or return a root the table does not hold.

### 3.4 Types this increment adds — and where they live (`SCU-Q2`)

| Type | Shape | Home (default) | Why |
|---|---|---|---|
| `TreePosition` | dense position in drain order, `u64` | **exists**: `shekyl_curve_tree::types::TreePosition` (`types.rs:168`, redb key via `redb_delegated_key!`) | The wallet-side store keys `leaves` by it already (`redb_backend.rs:22`). One vocabulary word, two stores (DRS-D3c wants exactly this). **Placement is the question:** the daemon store cannot depend on `shekyl-curve-tree` (it pulls `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-consensus`; `Cargo.toml:30–41`), so either the word moves to `shekyl-types` beside `CurveTreeRoot`, or the daemon store mints a twin. Default: **move it** (rule 18: a foundational newtype two crates key on is `shekyl-types`' — one definition, both stores). |
| `TreeLeaf` | `[u8; 128]` — `{O.x, I.x, C.x, CM.x}`, four Selene scalars (`CT_LEAF_SIZE`; `LeafEntry.leaf`, `types.rs:197`) | new, beside `TreePosition` | Today a bare array in both stores (`LeafEntry.leaf`; `LEAVES_TABLE: &[u8; 128]`). A newtype with a `Canonical` codec in the vocabulary crate (CTS-13's orphan rule, via `shekyl-store-codec`). |
| `LayerChunk` | key of `curve_tree_layers`: **a tuple key `(TreeLayer, ChunkIndex)`** — `u8` layer, `u64` chunk — ordered component-wise by delegated compare (SOK-Q1's mechanism), i.e. layer-major, the same order the C++'s `(layer << 56) \| chunk` packing produced (`db_lmdb.cpp:8745`; SCU-7) | new, daemon store (`ids.rs`) | `SCU-Q3` RULED: the packing existed because LMDB needs one integer key and redb does not; a tuple key gives identical behaviour with nothing to pin, and a layer's chunks are `range((layer, 0)..(layer + 1, 0))`. No 56-bit chunk ceiling. |
| `LayerHash` | `[u8; 32]` Selene chunk hash | new, daemon store | The value of `curve_tree_layers`; `hash_init` for a chunk that was never written is a *grow-path* default (E3's), never a read's. |
| `TreeDepth` | `u8`, "layers above the leaf; `fcmp_layers = depth + 1`" (`db_lmdb.cpp:8957`) | new, `shekyl-types` or daemon store | Stated once with its off-by-one so no caller re-derives it. No Rust rule reads depth (`rg depth rust/shekyl-chain-rules/src/rules/` → none); its consumers are RPC. |
| `LeafCount` | `u64` | new | `leaves.len()` by invariant. |
| `CurveTreeState` | `{ root, depth, leaf_count }`, one `Coded` row under one fixed key in `curve_tree_meta` | new, daemon store | C1's return and the table's whole content (§3.2). `EMPTY` is a real row. |

### 3.5 What this surface inherits, and for how long

- **`curve_tree_meta` as three string-keyed cells** (`"root"`, `"depth"`,
  `"leaf_count"`) — inherited from the C++, replaced by one typed row at this
  layout bump. Accumulator class `Small` (`class.rs:146`); `digest_v0` does
  not read it (the root family is `curve_tree_roots`), so the E2 digest is
  unaffected; the per-table accumulator's bytes change with the shape and the
  rule-42 snapshot moves with `SCHEMA_VERSION` 8 → 9.
- **The layer key's packing** — **not inherited** (`SCU-Q3` RULED: tuple
  key). The comparator's per-table projection of `curve_tree_layers`
  therefore differs from LMDB's key bytes, as `zerokval` tables already do;
  the comparator projects logical content (§7.6), and layer-major order is
  preserved.
- **The off-by-one in `curve_tree_roots`** — inherited as the table's key
  semantics, documented once at C2; not re-keyed here (re-keying would move
  the digest's root family, and that is E2's domain, not a read's).

---

## 4. The read set, table by table

| Table | Key → value at v8 | After this increment (v9) | Read |
|---|---|---|---|
| `curve_tree_meta` | `&[u8]` (`"root"` / `"depth"` / `"leaf_count"`) → `Unshaped` | one key → `Coded<CurveTreeState>` | C1 |
| `curve_tree_roots` | `u64` → `Coded<CurveTreeRoot>` | unchanged | C2 (and the digest) |
| `curve_tree_leaves` | `u64` → `Unshaped` (128 bytes) | `TreePosition` → `Coded<TreeLeaf>` | C3 |
| `curve_tree_layers` | `u64` (packed `(layer << 56) \| chunk`) → `Unshaped` (32) | `(u8, u64)` via `LayerChunk::key` → `Coded<LayerHash>` | none in the census — shaped because E3 writes it and the key's shape must exist *before* a writer does |
| `curve_tree_checkpoints` | `u64` → `Unshaped` | unchanged | none — E3's (§2.2) |

---

## 5. Store invariants this increment builds or restates

| Row | Statement | Armed where |
|---|---|---|
| **SI-11** | **The tree is dense and its summary is its count:** `curve_tree_leaves` holds exactly the positions `[0, leaf_count)` and `CurveTreeState.leaf_count == leaves.len()`. Two observations, one row: `LeafDensity::Length { count, rows }` when the lengths differ (C1, which does not know the missing position), `LeafDensity::Hole { position }` when a walk finds the first missing position in its range (C3). | C1 (length) and C3 (the hole); E3 on write (the count and the rows move in one batch) |
| **SI-12** | **A grown summary carries the live root.** Any `CurveTreeState` other than the seal's `EMPTY` has `root == curve_tree_roots[tip + 1]` (`CurveTreeRoot::EMPTY` when there is no tip). `EMPTY` is not that claim: `connect` records roots grown or not (SI-4), and E3 is what replaces the seal's row. | C1, once the summary is not `EMPTY` |
| **SI-7** (restated) | A `curve_tree_meta` row that does not decode, or is absent, is `CellCorrupt` — `EMPTY` is a written row, not a default. | C1 |

SI-11's register row landed with commit 1; SI-12 with the review on the implementation PR (`STORE_INVARIANT_REGISTER.md`).

---

## 6. Round-0 findings

- **SCU-1 — three cells, three defaults, one tree; and an API that documents
  its own ambiguity and asks the caller to resolve it with a second read.**
  `get_curve_tree_root` / `_depth` / `_leaf_count` read three string keys of
  `curve_tree_meta` and each invents a value on absence
  (`db_lmdb.cpp:9259–9313`); the writer stores all three in one grow
  (`:8936–8966`). **Graded the worst of the class's four instances, not the
  fourth:** `db_lmdb.cpp:9264–9265` does not merely default a missing key to
  `hash_init` — it *states* that the return is ambiguous and instructs
  callers to "compare against `hash_init` or check
  `get_curve_tree_leaf_count()`" to tell an empty tree from a root that is
  the identity. A caller who skips the second read gets corruption reading
  as an empty tree, and one table over a caller did exactly that: CEN-I12's
  zero root reaching FCMP verification is the same shape with the same
  outcome. Absence read as a value the documentation then asks the caller to
  disentangle. The reason C1 is one row with a written `EMPTY` (§3.3).
- **SCU-2 — the chunk read's only daemon consumer is retired.**
  `blockchain.cpp:4956` reads a leaf chunk to answer a serve-credit challenge
  over a frozen segment; `PDM-Q3` rules the serve-credit verifier the C++
  residual that dies at E4, `PDM-Q12` retires the freeze. So `#4` has no live
  consumer in Rust — the #782 shape — **and** it is a range read over a keyed
  dense table, which S-TX Q3 re-ruled is completeness, not a feature. Both
  apply; the second decides (§3.2 C3), with E3 as the named reader.
- **SCU-3 — `frozen_segment_count(leaf_count)` is dead by ruling, live in
  code.** `archival_shard_coverage.cpp:33–34` and `blockchain.cpp:1502` derive
  frozen-segment counts from the leaf count; `PDM-Q12` retired segments.
  Recorded for E4 / S-ARCH's deletion surface; not this increment's.
- **SCU-4 — `root_at_height`'s absence is thirty-two zero bytes.**
  `db_lmdb.cpp:9407–9422`; E2's exporter had to write a comment about it
  (`shekyl_e2_trace_export.cpp:130`). Rust already types it
  (`AtHeight<CurveTreeRoot>`); this increment makes that the public read.
- **SCU-5 — no Rust rule reads the tree depth.** Verified: `rg depth
  rust/shekyl-chain-rules/src/rules/ rust/shekyl-chain-rules/src/view.rs` →
  nothing. The C++ validator reads it as the FCMP reference depth; the Rust
  rules take layer count from the proof. Depth's Rust consumer is RPC
  (`get_curve_tree_info`, the submit facts FFI).
- **SCU-6 — the vocabulary exists in the wallet-side crate with a redb key
  impl.** `TreePosition` + `redb_delegated_key!` (`types.rs:93`, `:168`);
  `LEAVES_TABLE: TableDefinition<TreePosition, &[u8; 128]>`
  (`redb_backend.rs:22`). The daemon store keys the same table by bare `u64`.
  `SCU-Q2`.
- **SCU-7 — the layer key's packing is a local function, and nothing pins
  it.** `ct_layer_chunk_key(layer, chunk) = (layer << 56) | chunk`
  (`db_lmdb.cpp:8745`, declared `:7696`; the prefix scan `:9703`; the
  comment `db_lmdb.h:916`) — three sites, all inside the LMDB backend,
  crossing no boundary. **Disposition (`SCU-Q3` RULED): remove the thing that
  needs pinning rather than pin it** — the packing exists because LMDB needs
  one integer key; redb's tuple key gives the same layer-major order with
  nothing to KAT.
- **SCU-8 — `curve_tree_checkpoints` has no reader in the census.** Written
  and read by the grow path only (`db_lmdb.cpp:9584`, `:9600`); accumulator
  class `Derived`. Out (§2.2).
- **SCU-9 — the digest is untouched by any of this.** `digest_v0`'s root
  family is `curve_tree_roots` (`read.rs:505`); the three tables this
  increment shapes are `Small` / `AppendMostly` / `Derived` classes of the
  per-table accumulator, not families of the E2 digest. The rule-42 snapshot
  moves; E2's MATCH does not.

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None. The three absence defaults are **not** reproduced (§3.3); the root
table's key semantics are inherited and documented (§3.5), not a deviation.

---

## 7. Commit sequence (rule 90; one PR, ≤ 4 commits, cut from `dev` after this document merges)

1. **Vocabulary and shapes.** `TreePosition` moves to `shekyl-types` and
   `TreeLeaf` is minted beside it (`SCU-Q2`), with the placement sentence
   written beside the `hash32!` family; `shekyl-curve-tree` re-exports and
   its `LEAVES_TABLE` adopts `TreeLeaf`; `LayerChunk` as the tuple key
   `(TreeLayer, ChunkIndex)` (`SCU-Q3`), `LayerHash`, `TreeDepth`,
   `LeafCount`, `CurveTreeState` with `Canonical` codecs; the three tables
   re-typed in `schema.rs`; `SCHEMA_VERSION` 9; snapshot regenerated
   (rule 42); `CurveTreeState::EMPTY` written at store creation; SI-11 in the
   register.
2. **The reads.** `store/curve_reads.rs`: C1, C2, C3; `live_root` re-homed on
   C2's `root_row` (decision log 2026-09-21, not C1 as first written);
   `ChainView::root_at` delegates to C2; tests: empty store, planted
   rows, `AboveTip`, `AboveCount`, the SI-11 gap, a decoded `CurveTreeState`
   round trip.
3. **Docs** (rule 91): §7 row flip in `DAEMON_REDB_STORE.md`, index rows,
   `STORE_INVARIANT_REGISTER.md`, this file's status; CTS-8's class
   statement gains the daemon-store instance and its grade (SCU-1).

---

## 8. Denominator — what must stay green, what must be extended

- `check_chain_rules_no_store.sh` (the rules crate reaches no store).
- Rule-42 schema snapshot: **must move**, and only by the three tables +
  version (the gate's diff is the review).
- `check_conformance_coverage.py`: no register row is touched — the curve
  reads are storage, not a consensus rule (§7 row: "storage only; math in
  `shekyl-fcmp`").
- `check_store_unlock_time_projection.py`: unchanged.
- E2's `pipeline_tests` and `digest_read_tests`: unchanged in outcome (SCU-9);
  they are the belt that proves it.

---

## 9. Round-1 questions — RULED 2026-09-21 (maintainer, on PR #815; each row line-local)

| Q | Question | Ruling | Why |
|---|---|---|---|
| **SCU-Q1** | Is `curve_tree_meta` one typed row (`CurveTreeState`) or three typed cells? | **RULED: one row** (default held). | The C++ writes the three together and reads them together; three cells reintroduce a state where they can disagree. It also composes with SCU-1's fix: with three cells the written-`EMPTY` repair is applied three times and the three can still disagree about whether the tree is empty — one row makes emptiness a single state. Write amplification is 48 bytes; not a consideration. |
| **SCU-Q2** | Where does the shared vocabulary live — move `TreePosition` (and mint `TreeLeaf`) into `shekyl-types`, or twin it in the daemon store? | **RULED: move to `shekyl-types`, and write the rule down.** | Third instance of one argument — `KeyImage`, `CurveTreeRoot`, now `TreePosition` / `TreeLeaf`. The general form is now in `18-type-placement.mdc` §"Where each shape lives" (this PR) and lands beside the `hash32!` family in `shekyl-types` with commit 1: *a type both stores need lives in `shekyl-types`; the computation lives in the owning crate.* The daemon store cannot take `shekyl-curve-tree`'s graph; a twin is CTS-3 reborn. |
| **SCU-Q3** | Does `LayerChunk` keep the C++ packing `(layer << 56) \| chunk` as its encoding, or become a tuple key at the layout bump? | **RULED: tuple key — the default is overridden.** | The packing appears at exactly three sites, all inside the LMDB backend (`db_lmdb.cpp:8745` the key builder, `:9703` the prefix scan, `db_lmdb.h:916` the comment) and crosses no boundary: it exists because LMDB needs one integer key, and redb does not — SOK-Q1 already established that a tuple key orders component-wise through delegated compare, the same layer-major order the shift produces; the prefix scan becomes `range((layer, 0)..(layer + 1, 0))`. The real comparison is *packing + newtype + KAT* against *tuple + nothing* for identical behaviour, and SCU-7 — nothing pins the packing — argues for removing the thing that needs pinning rather than pinning it. The 56-bit chunk ceiling was a limit nobody chose. Byte-parity with LMDB's key was never the constraint (`zerokval` already diverges; the comparator projects — S-CHAIN-R Q4's correction). No DRS-X reopener needed. |
| **SCU-Q4** | Does C3 (`leaves(range)`) land now, with E3 as its named reader, or does E3 mint it with its writer? | **RULED: now, E3 named** (default held). | S-TX Q3's precedent, applied for the same reason: a range read over a keyed dense table is what makes it a table. `EMPTY`-tree and `AboveCount` cases are testable today without a writer. |

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md` §7: S-CURVE row → LANDED with the mapping.
- `IMPLEMENTATION_INDEX.md`: `SCU-` / `SCU-Q` rows lead with status; this
  document's row.
- `STORE_INVARIANT_REGISTER.md`: SI-11.
- `DRS_E1_STX.md` → `docs/completed/` (§2.5; **this PR**).
- `CURVE_TREE_STORE_SHAPES.md` CTS-8's class statement gains the daemon-store
  instance (one line; the class is already stated there).
- CHANGELOG: one entry (schema layout 9; the typed curve-tree reads).

---

## 11. Decision log

| Date | Entry |
|---|---|
| 2026-09-21 | **Review, on the implementation PR.** Three corrections, each toward a type the store already had. **(1)** `LayerChunk`, `TreeLayer`, and `ChunkIndex` live in `ids.rs` beside `OutputSlot` — private fields, `key` / `from_key`, and `layer_range` returning `RangeInclusive<(u8, u64)>` built only through `key()`. The table stays `(u8, u64)`. `to_tuple` / `from_tuple` are gone; `layer_range` returns `RangeInclusive<(u8, u64)>`, the range `table.range` takes. The newtypes stay because a layer is not a `TreeDepth` and a chunk index is not a `TreePosition`; E3 is their caller and is not built yet. **(2)** SI-11's payload is `LeafDensity`: `Length { count, rows }` from the summary read, `Hole { position }` from the walk. The length belt no longer names `leaf_count` as if it were the missing row. **(3)** SI-12 `SummaryRootDiverged`: once the summary is not the seal's `EMPTY`, its root is the live root (`curve_tree_roots[tip + 1]`, or `EMPTY` with no tip). `EMPTY` stays quiet after `connect`, because connect records roots grown or not (SI-4) and E3 is what replaces the seal's row — arming the comparison on `EMPTY` would call today's connect output corrupt. The digest still reads C2. The wallet-side `TreePositionKey` field is private, with `from_raw` / `to_raw`, matching `GindexKey`. |
| 2026-09-21 | **Implemented** (three commits on the S-CURVE PR, cut from `dev` @ `fdb5db954`). Two departures from the letter of §7, both toward the store's own conventions and disclosed here: **(a)** table keys stay bare `u64` / `(u8, u64)` / `()` at the redb layer per `ids.rs`'s key contract ("table keys stay `u64`; convert at the decoded handle" — as `output_amounts`' bare `(u64, u64)` does), so `LayerChunk` is the *API* type with `to_tuple`/`from_tuple` and `TreePosition` is the handle's type, not a redb `Key` wrapper in the daemon store; the wallet-side store, whose tables were already typed-keyed, wraps the moved `TreePosition` in a store-local `TreePositionKey` (the `GindexKey` precedent, orphan rule) with its `TypeName` unchanged so existing wallet files open. **(b)** the wallet-side `LeafEntry.leaf` stays `[u8; 128]` rather than adopting `TreeLeaf` now — that row is being re-laid-out by the WSS lane (`WALLET_SIDE_STORE.md`, PDM-Q12), which adopts the word when it lays the row out; a rename against a table about to move would be re-done (rule 22: named owner, disclosed in commit 1). `live_root` re-homes on C2's `root_row` rather than on C1 (§7 item 2 said C1): the digest reads the root *at the tip it already decoded*, which is `curve_tree_roots[tip + 1]`, C2's table — C1's row is the same value only while E3 keeps them in step, and a read that is right only while a belt holds is the wrong read (SOK O2's argument). SI-11 armed by C1 (count = table length) and C3 (the walk names the first missing position). **Gate consequence of `SCU-Q3`:** `check_redb_schema_key_types.py`'s INTEGERKEY rule was `u64` only; it gains a fact-derived arm — a shift-or key builder `(uintA_t hi << (64 − A)) \| lo` read off `db_lmdb.cpp` (`ct_layer_chunk_key`, `:8744`) and bound to the table its callers address admits the order-equivalent tuple `(uA, u64)`; a shift that is not `64 − A` mints nothing, and a builder bound to zero or two tables is a raise, not a guess. No table-name allowlist (the gate's own rule). |
| 2026-09-21 | **Round 1 RULED** (maintainer, PR #815). Three defaults held (Q1 one row — it composes with SCU-1's fix, emptiness becomes a single state; Q2 move to `shekyl-types`, with the general form written into `18-type-placement.mdc` so the fourth instance is a lookup; Q4 now, E3 named). **Q3 overridden: tuple key.** The packing has three sites, all inside the LMDB backend, crossing no boundary; it exists because LMDB needs one integer key and redb does not; SOK-Q1's delegated compare gives the same layer-major order; SCU-7's "nothing pins it" argues for removing the thing that needs pinning. Byte-parity with LMDB's key was never the constraint (`zerokval`; S-CHAIN-R Q4). **SCU-1 regraded:** not the fourth instance but the worst — the C++ documents the ambiguity and delegates its resolution to a second read the caller may skip; CEN-I12 is what happens when one does. |
| 2026-09-21 | **Round 0 executed** at `b680d59e0`. Nine findings (SCU-1…SCU-9); four questions posed with defaults (SCU-Q1…Q4). The surface's five C++ reads map to three Rust reads; two of the five have only retired consumers (SCU-2, SCU-3) and one is already typed in Rust (SCU-4). The E3 boundary is stated: this increment mints the shapes, E3 writes them. S-TX read and archived (§2.5). |
