# DRS-E1 S-CURVE — curve-tree reads: increment plan and Round-0 pre-flight

**Status:** OPEN — **Round 0 executed 2026-09-21** against `dev` @
`b680d59e0` (the tree that merged PR #811, DRS-E2 increment 2). Round 1
questions §9 are posed with defaults; implementation starts when this
document merges and the rulings are line-local in §9. Implements *from*
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
`get_curve_tree_leaf_by_output_index` (`db_lmdb.cpp:9317`, `:9383`). They are
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
- **`curve_tree_checkpoints`** (`schema.rs:474`, accumulator class `Derived`).
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
  (`db_lmdb.cpp:9276`), `depth` → `0`, `leaf_count` → `0` — and the comment
  at `:9264` tells callers to *compare against `hash_init`* to tell an empty
  tree from a root that happens to be the identity. That is the
  absence-as-value class this program has now met four times
  (`curve_tree_roots`' zero root reaching FCMP verification, `top_block_hash`'s
  `UINT64_MAX`, the wallet-side `meta`'s `unwrap_or`, and here), stated once
  in `CURVE_TREE_STORE_SHAPES.md` CTS-8 / `CTS-Q1`. **C1 returns
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
| `TreeLeaf` | `[u8; 128]` — `{O.x, I.x, C.x, CM.x}`, four Selene scalars (`CT_LEAF_SIZE`; `LeafEntry.leaf`, `types.rs:196`) | new, beside `TreePosition` | Today a bare array in both stores (`LeafEntry.leaf`; `LEAVES_TABLE: &[u8; 128]`). A newtype with a `Canonical` codec in the vocabulary crate (CTS-13's orphan rule, via `shekyl-store-codec`). |
| `LayerChunk` | key of `curve_tree_layers`: `(layer: u8, chunk: u64)` packed as `(layer << 56) \| chunk` (`db_lmdb.cpp:7696` — the packing is implicit in a local `n()`; SCU-7) | new, daemon store (`ids.rs`) | A typed key whose encoding **is** the C++ packing — layout-preserving, so parity holds byte for byte, and pinned by a KAT so the shift cannot drift. `SCU-Q3` asks whether to keep the packing or move to a tuple key at the layout bump. |
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
- **The layer key's packing** — inherited if `SCU-Q3` keeps it.
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
| `curve_tree_layers` | `u64` (packed) → `Unshaped` (32) | `LayerChunk` → `Coded<LayerHash>` | none in the census — shaped because E3 writes it and `LayerChunk`'s packing must be pinned *before* a writer exists |
| `curve_tree_checkpoints` | `u64` → `Unshaped` | unchanged | none — E3's (§2.2) |

---

## 5. Store invariants this increment builds or restates

| Row | Statement | Armed where |
|---|---|---|
| **SI-11** (new) | **The tree is dense and its summary is its count:** `curve_tree_leaves` holds exactly the positions `[0, leaf_count)` and `CurveTreeState.leaf_count == leaves.len()`. A missing position inside the count, or a row at or past it, is the invariant. | C3 on read (a gap inside the range); E3 on write (the count and the rows move in one batch) |
| **SI-7** (restated) | A `curve_tree_meta` row that does not decode, or is absent, is `CellCorrupt` — `EMPTY` is a written row, not a default. | C1 |

Register rows land with commit 1 (`STORE_INVARIANT_REGISTER.md`).

---

## 6. Round-0 findings

- **SCU-1 — three cells, three defaults, one tree.** `get_curve_tree_root` /
  `_depth` / `_leaf_count` read three string keys of `curve_tree_meta` and each
  invents a value on absence (`db_lmdb.cpp:9259–9313`); the writer stores all
  three in one grow (`:8936–8966`). The absence-as-value class (§3.3), and the
  reason C1 is one row.
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
- **SCU-7 — the layer key's packing is a local function.**
  `ct_layer_chunk_key(layer, chunk) = (layer << 56) | chunk` lives in an
  anonymous namespace (`db_lmdb.cpp:7696`) — the one place the layout is
  stated, and nothing pins it. `LayerChunk`'s codec + KAT pin it. `SCU-Q3`.
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

1. **Vocabulary and shapes.** `TreePosition` to its ruled home (`SCU-Q2`);
   `TreeLeaf`, `LayerChunk` (+ KAT for the packing), `LayerHash`, `TreeDepth`,
   `LeafCount`, `CurveTreeState` with `Canonical` codecs; the three tables
   re-typed in `schema.rs`; `SCHEMA_VERSION` 9; snapshot regenerated
   (rule 42); `CurveTreeState::EMPTY` written at store creation; SI-11 in the
   register.
2. **The reads.** `store/curve_reads.rs`: C1, C2, C3; `live_root` re-homed on
   C1; `ChainView::root_at` delegates to C2; tests: empty store, planted
   rows, `AboveTip`, `AboveCount`, the SI-11 gap, a decoded `CurveTreeState`
   round trip.
3. **Docs** (rule 91): §7 row flip in `DAEMON_REDB_STORE.md`, index rows,
   `STORE_INVARIANT_REGISTER.md`, this file's status; the wallet-side store's
   `LEAVES_TABLE` adopts `TreeLeaf` **only if `SCU-Q2` rules the shared
   home** (otherwise that is WSS's own increment and is named there).

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

## 9. Round-1 questions — posed 2026-09-21 with defaults

| Q | Question | Default | Why |
|---|---|---|---|
| **SCU-Q1** | Is `curve_tree_meta` one typed row (`CurveTreeState`) or three typed cells? | **One row.** | The C++ writes the three together and reads them together; three cells reintroduce a state where they can disagree, and SI-11 would need a fourth belt to say they don't. One row makes the coherence a property of the type. |
| **SCU-Q2** | Where does the shared vocabulary live — move `TreePosition` (and mint `TreeLeaf`) into `shekyl-types`, or twin it in the daemon store? | **Move to `shekyl-types`.** | Two stores key the same table by the same word (SCU-6); rule 18 puts a foundational newtype two crates depend on in `shekyl-types`, beside `CurveTreeRoot`. The daemon store cannot take `shekyl-curve-tree` as a dependency (its graph); a twin is CTS-3's "two shapes for one leaf" reborn. Cost: a `shekyl-curve-tree` re-export edit and one WSS table signature. |
| **SCU-Q3** | Does `LayerChunk` keep the C++ packing `(layer << 56) \| chunk` as its encoding, or become a tuple key `(u8, u64)` at the layout bump? | **Keep the packing, typed and KAT-pinned.** | Parity first (§7.6): the comparator's per-table projection of `curve_tree_layers` stays byte-identical to LMDB, and E3's grow port has one fewer thing to re-derive. A tuple key is cleaner Rust and changes nothing in semantics; the reopening criterion is the LMDB comparator's retirement (DRS-X), when byte parity stops being a property anyone checks. |
| **SCU-Q4** | Does C3 (`leaves(range)`) land now, with E3 as its named reader, or does E3 mint it with its writer? | **Now.** | S-TX Q3's re-ruling: a range read over a keyed dense table is what makes it a table. Its C++ consumer is dead (SCU-2) but E3 needs to read back what it writes, and minting the read with its shape keeps E3 from choosing a second one. `EMPTY`-tree and `AboveCount` cases are testable today without a writer. |

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
| 2026-09-21 | **Round 0 executed** at `b680d59e0`. Nine findings (SCU-1…SCU-9); four questions posed with defaults (SCU-Q1…Q4). The surface's five C++ reads map to three Rust reads; two of the five have only retired consumers (SCU-2, SCU-3) and one is already typed in Rust (SCU-4). The E3 boundary is stated: this increment mints the shapes, E3 writes them. S-TX read and archived (§2.5). |
