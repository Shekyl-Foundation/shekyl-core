# Segment-freeze pipeline — the production writer for `m_archival_shard_segment`

**Status: round 1 draft (2026-07-06) — open for adversarial review.
This document is the design round `ARCHIVAL_REWARD_GATE_M1.md` §1.3
requires to open before the M1 gate PR merges; it must discharge the
named obligations O-1 (determinism), O-2 (per-branch monotonicity),
O-3 (pop-symmetry), recorded here and cross-referenced from M1 §1.3.**
Per `05-system-thinking.mdc` (specification first) and
`26-sub-pr-design-discipline.mdc` (cited: consensus-critical sub-PR —
the freeze rule is a consensus-state writer feeding the M1 gate and
the gate-2 challenge verifier).

**Provenance.** Opened by M1 §1.3 / `docs/FOLLOWUPS.md`
("Segment-freeze pipeline — design round required", 2026-07-06). The
substrate facts in §2 were verified at source on
`feat/m1-reward-gate-design` @ `2cd18ecb6` (which carries `dev` @
`1e89df832` plus the M1 implementation), per the §11.1 pre-flight
pattern: every operand at its production site. **Scope
authorization:** the maintainer explicitly opened LMDB schema
restructuring and further FFI boundary advancement on the daemon to
this round (pre-genesis posture: no running testnet daemon during the
wallet-rewrite month; `rm -rf ~/.shekyl` is the migration path per
`15-deletion-and-debt.mdc`). §6 exercises that authorization once
(one table deleted); §5 advances the FFI boundary per
`20-rust-vs-cpp-policy.mdc`.

**Timeframes (rule 05).** *Now:* the writer that makes the M1 gate's
input and the gate-2 challenge registry real. *Mining-era end:*
segments keep freezing as long as outputs are created; the rule has
no era dependence. *V4:* the freeze rule reads tree structure (leaf
counts and sub-root hashes), not signatures — independent of the
crypto substrate, though `R_k`'s hash function follows whatever the
curve tree becomes (a V4 tree migration reopens this pipeline by
construction, since it reopens the tree itself).

---

## 1. What the pipeline is

> **Archival shard `k` (the curve-tree segment covering leaf
> positions `[k·E, (k+1)·E)`, `E = SEGMENT_LEAF_COUNT`) is frozen on
> a branch iff the branch's curve-tree leaf count has reached
> `(k+1)·E`. Its `freeze_height` is the height of the block whose
> connect first satisfied that. Its `R_k` is the level-2 sub-root the
> tree's own grow computed for that completed subtree. The segment
> row is written in the same LMDB write transaction as the block
> connect that crossed the boundary, and deleted in the same write
> transaction as a block pop that un-crosses it.**

The rule is a **first-crossing rule over the consensus leaf count**
— nothing else. No participation input, no wall-clock input, no
checkpoint-interval input, no operator action. That is what makes
O-1..O-3 dischargeable by inheritance from the tree machinery that
already exists (§3).

### 1.1 What a segment is (inherited, not chosen here)

Segment geometry is pinned by `CURVE_TREE_CLIENT.md` §7.2 and
consumed by gate 2 (`ARCHIVAL_RETENTION_GATE2.md` §2): a
subtree-aligned position range with a frozen sub-root `R_k` that is
permanent the moment the subtree completes (Merkle-mountain-range
property of append-only `hash_grow`). This round does not revisit
that choice; it builds the writer the choice implies.

**`E = SEGMENT_LEAF_COUNT = 25 992`** — the level-2 subtree leaf
count under the production widths (`38 · 18 · 38`;
`curve_tree_freeze.rs`: "j=0 → 38, j=1 → 684, j=2 → 25 992").
Gate 2's "Genesis provisional: subtree level 2 (~26k)" becomes a
pinned numeric constant here (§5.2). Note `E` is a multiple of the
leaf-chunk width 38, so segment bases are leaf-chunk-aligned — §6.2's
direct-read derivation depends on this and it holds by construction
(any level's leaf count is a product that includes the level-0
width).

**Shard ids are dense from 0** on every branch: segment `k` freezes
only after `k−1` (leaf count is one number). The registry rows are
`0..frozen_segment_count` with no holes. M1 §11.8 M3-1 named the
*cached counter* as a drift adversary; the persisted counter that
backs the gate operand (§4.4) is admissible because it carries the
property M3-1's adversary lacked — O-3 pop-symmetry enforced at the
row-mutation sites, differential-tested against the walk, with the
mutation surface tripwire-pinned. Density is a property, not a
license: the reader still frontier-checks (§4.4) rather than
trusting the count blindly.

---

## 2. Substrate facts, verified at source

The load-bearing discovery of the pre-round investigation: **the
daemon already delivers O-1..O-3 for the quantity that drives
freezing.** The pipeline inherits, rather than constructs, its hard
properties.

1. **The curve tree is consensus state maintained inside the block
   write txn.** `BlockchainDB::add_block` (`blockchain_db.cpp`)
   drains maturity-gated pending leaves (`drain_pending_tree_leaves`,
   journaled per block) and calls `grow_curve_tree` before
   `process_archival_epoch_close_at_height`. Leaf count
   (`m_curve_tree_meta["leaf_count"]`) is a deterministic pure
   function of chain content: outputs enter the tree exactly at
   maturity, in consensus order.
2. **The pop path is already exactly symmetric.**
   `BlockchainDB::pop_block` reads the drain journal, calls
   `trim_curve_tree(drained_count)`, and restores pending leaves —
   inside the same write txn as the block removal, with the explicit
   invariant comment that partial commit is a consensus split.
3. **`R_k` is already computed, by Rust, in the same txn.**
   `grow_curve_tree` recomposes *every* layer above the leaf layer
   via `shekyl_curve_tree_grow_upper_layers` (== `shekyl-fcmp`'s
   `build_layers`; equality is itself tested,
   `grow_upper_layers_ffi_equals_build_layers`). For a **complete**
   level-2 subtree `k`, the layer-2 chunk hash at index `k`
   (`m_curve_tree_layers[ct_layer_chunk_key(2, k)]`) is built from
   exactly the layer-1 chunks of exactly that segment's leaves — it
   **is** `R_k`, the same value the freeze harness computes. MMR
   finality: later grows never change it.
4. **Intermediate-layer pruning cannot race the freeze read.**
   `prune_curve_tree_intermediate_layers` deletes layer 1..depth−2
   chunks *below the previous checkpoint* (interval 10 000 blocks);
   the freeze reads a chunk the same-txn grow just wrote at the
   frontier. Layer 0 is never pruned, and grow re-persists all upper
   layers each block, so even the reorg re-apply path reads a
   freshly-written chunk.
5. **The daemon retains every leaf forever.** `m_curve_tree_leaves`
   is deleted only by `trim_curve_tree` (reorg). This is already
   consensus-required — serve-credit vin verification needs leaf
   scalars at arbitrary challenged indices — and it is what makes
   §6.2's table deletion sound.
6. **The segment table and its codec are already fixed.**
   `LMDB_SCHEMA.md`: key `BE(shard_id)`, value
   `ArchivalShardSegmentValue` v1 (`freeze_height`,
   `segment_leaf_count`, `R_k[32]`), CREATE-only.
   `put_archival_shard_segment` exists (fixture-only caller);
   `get_archival_shard_segment_at_height` gates reads on
   `at_height ≥ freeze_height` — inclusive, consistent with M1's
   `freeze_height ≤ h_close`. The M1 count pass and its tripwire
   (`check_reward_gate_predicate_sites.sh`) bind to this schema.

---

## 3. Discharging O-1..O-3

- **O-1 (determinism).** Freezing is
  `frozen_segment_count(leaf_count) = ⌊leaf_count / E⌋` with
  `freeze_height` = first crossing. Leaf count is consensus (fact
  §2.1); `E` is a compile-time constant (§5.2); `R_k` is the output
  of the consensus tree composition (fact §2.3). Same chain ⇒ same
  rows, bit-identical, every node. **Discharged by the rule's
  shape** — there is no input a node could disagree on.
- **O-2 (per-branch monotonicity).** Leaf count is non-decreasing on
  a single branch (connects only append; pops are branch switches),
  so `frozen_segment_count` is non-decreasing and rows are never
  deleted on one branch. Writes are CREATE-only rows keyed by dense
  `k`; nothing ever rewrites an existing row (the one-writer
  tripwire, §8, makes an overwrite grep-visible). **Discharged.**
- **O-3 (pop-symmetry).** The delete rule is *derived from the same
  function*: after `trim_curve_tree`, delete every row with
  `shard_id ≥ frozen_segment_count(new_leaf_count)`. No freeze
  journal is needed — the drain journal already restores leaf count
  exactly, and first-crossing gives the survival argument:
  - Row `k` frozen at height `f` means `leaf_count(f) ≥ (k+1)·E` and
    `leaf_count(f−1) < (k+1)·E`.
  - Pop to height `p ≥ f`: `leaf_count(p) ≥ leaf_count(f)` ⇒ row
    survives, and its stored `freeze_height = f ≤ p` remains
    consistent.
  - Pop to height `p < f`: `leaf_count(p) ≤ leaf_count(f−1) <
    (k+1)·E` ⇒ row deleted.
  - Re-apply of the same blocks recreates every row bit-identically
    by O-1 (same heights, same leaf counts, same layer-2 chunks). A
    different branch produces that branch's rows — which is the
    *correct* behavior M1 §1.3 names (no stale orphaned-branch
    `R_k`). **Discharged**, conditional on the §9 pop-boundary test
    arming it.

**The M1 §9.4 reorg-argument step 1** ("segment writes are
connect/revert-paired") stops holding vacuously and starts holding
by this mechanism. That closes the last conditional in M1's reorg
argument.

---

## 4. Mechanics

### 4.1 Connect hook

In `BlockchainDB::add_block` (`blockchain_db.cpp`), inside the
existing `HF_VERSION_FCMP_PLUS_PLUS_PQC` block, **immediately after
`grow_curve_tree` and before `process_archival_epoch_close_at_height`**
(ordering is load-bearing: a segment completed at height `H` must be
countable by an epoch close at `H` — M1 §1.1 takes the count "inside
the same write transaction that performs the close" with
`freeze_height ≤ H_close` inclusive):

```text
process_archival_segment_freezes_at_height(height):
  leaf_count   = m_curve_tree_meta["leaf_count"]            # just written by grow
  complete     = shekyl_archival_frozen_segment_count(leaf_count)   # Rust, §5.1
  next         = last segment key + 1 via reverse cursor (empty table ⇒ 0)
  for k in [next, complete):
      rk = m_curve_tree_layers[ct_layer_chunk_key(2, k)]     # loud abort if absent
      put_archival_shard_segment(k, height, rk, SEGMENT_LEAF_COUNT)
```

Called unconditionally (no-op when no boundary crossed; a block
whose drain completes several segments freezes all of them at the
same `freeze_height` — the loop handles it). The `next` read is a
one-row reverse-cursor `MDB_LAST` peek on the table the function
itself owns — the writer deriving its own resume point from its own
table is not the M1 count pass and is tripwire-exempted by name
(§8). A missing layer-2 chunk for `k < complete` is a **loud abort**
(`DB_ERROR`), same class as the M1 count pass's decode-failure
discipline — it means the tree and the freeze rule disagree, which
is corruption, not a skippable row.

### 4.2 Pop hook

In `BlockchainDB::pop_block`, inside the same FCMP block, **after
`trim_curve_tree`** (and after `revert_archival_epoch_close_at_height`,
which already runs first — the close revert must see the segment
rows the close saw):

```text
revert_archival_segment_freezes():
  leaf_count = m_curve_tree_meta["leaf_count"]               # post-trim
  complete   = shekyl_archival_frozen_segment_count(leaf_count)   # same Rust entry point
  reverse-cursor from MDB_LAST: while key ≥ complete, mdb_del; stop at first key < complete
```

O(popped segments + 1) per pop. No journal (§3 O-3). Decode is not
needed on this path (keys suffice); a key that fails the dense-id
expectation is left to the §9 tests, not silently tolerated.

### 4.3 What does *not* change

- `process_archival_epoch_close_at_height` and the M1 count pass:
  untouched. The gate starts counting real rows instead of (only)
  fixture rows; G-1..G-10 and the C++ count-pass tests remain valid.
- `put_archival_shard_segment`: unchanged signature; gains its first
  production caller.
- `get_archival_shard_segment_at_height`: unchanged; its
  `at_height ≥ freeze_height` read gate now has real rows to gate.
- Checkpoint machinery (`save_curve_tree_checkpoint`,
  `prune_curve_tree_intermediate_layers`): untouched. The
  `LMDB_SCHEMA.md` "curve-tree checkpoint / genesis seed" writer
  annotation was aspirational and is superseded — the writer is the
  boundary-crossing rule, not a checkpoint hook; there is no genesis
  seed (genesis has zero leaves ⇒ zero segments ⇒
  `frozen_shard_count = 0` ⇒ early epochs gated once `K_COVER`
  seals, which is exactly M1's cold-start refusal).

### 4.4 Persisted pop-symmetric counter (the O(1) operand, V8)

The M1 gate operand `frozen_shard_count` is backed by a persisted
counter in the `properties` table under `"archival_frozen_shard_count"`
(schema V8; pre-V8 databases are refused at open with a
delete-and-resync directive — `15-deletion-and-debt.mdc`, no
pre-genesis migration code).

M1 §11.8's M3-1 named a *cached counter* as a drift adversary and
refused it. What M3-1's adversary lacked — and this counter has —
is **O-3 pop-symmetry enforced structurally**:

- **+1 in the row writer.** `put_archival_shard_segment` puts with
  `MDB_NOOVERWRITE` (rows are CREATE-only; `MDB_KEYEXIST` is a loud
  abort, discharging O-2 at the mutation site) and increments the
  counter in the same write transaction. One production caller
  (§4.1's connect hook); the tripwire pins the site count.
- **−1 per deleted row in the pop revert.** §4.2's reverse walk
  counts its deletions and decrements by exactly that number, with
  an underflow abort. Counter and table move in lockstep or the
  transaction dies.
- **No third mutation site.** The key literal and the setter call
  sites are tripwire-pinned (M1 script invariant 6); a new mutation
  site is a CI failure, not a review-attention item.

The reader `count_frozen_shards_at_close(h_close)` becomes O(1):
read the counter, then run a one-row **frontier check** — the
`MDB_LAST` row must decode (walk-not-watermark's corruption
tripwire, preserved at the frontier) and must satisfy
`freeze_height ≤ h_close` (a future-dated frontier means the
caller's transaction snapshot and the counter disagree — loud
abort, not a filtered count). Counter/table divergence (counter
nonzero with empty table, or vice versa) is likewise a loud abort.
This is sound *because* rows are dense-id CREATE-only with
monotonically non-decreasing `freeze_height` (§1.1, O-2): if the
frontier row satisfies the boundary, every row does.

The O(N) walk survives as `count_frozen_shard_rows_by_walk_for_test`
— a test-support differential oracle with zero production callers
(tripwire-enforced). §9's differential test drives freeze/pop/
re-apply cycles and asserts counter == walk at every step.

---

## 5. FFI boundary advancement (rule 20, authorized)

### 5.1 Rust owns the freeze rule

`⌊leaf_count / E⌋` is one division — and it is consensus logic with
**two production call sites** (connect §4.1, pop §4.2), which is
precisely the M1-1 off-by-one-drift shape: two sites computing the
same predicate independently fork at the boundary. Per
`20-rust-vs-cpp-policy.mdc` (new consensus logic belongs in a
`shekyl_*` Rust entry point) and the M1 single-source discipline:

- `shekyl-archival-retention` gains
  `frozen_segment_count(leaf_count: u64) -> u64` next to the gate
  predicate it feeds, with `SEGMENT_LEAF_COUNT` as a crate constant
  (§5.2).
- `shekyl-ffi` exports `shekyl_archival_frozen_segment_count`.
- C++ **never performs the division inline** — both hooks call the
  FFI. The tripwire (§8) refuses `/ SEGMENT_LEAF_COUNT` and
  `% SEGMENT_LEAF_COUNT` spellings in `src/`.

The LMDB reads/writes themselves stay C++ (rule 20 "C++ if all of"
#4: epee/LMDB re-exposure; the marshaling-shim shape, same as the M1
count pass).

### 5.2 `SEGMENT_LEAF_COUNT` joins the constants pipeline

Same shape as `K_COVER` minus the sentinel (the value is *not*
provisional — it is derived from pinned production widths):
`config/consensus_constants.json` entry, `build.rs` emission,
`SEGMENT_LEAF_COUNT: u64 = 25_992` with a compile-time assert tying
it to the width product (`38 * 18 * 38`) so a width change cannot
silently strand it, and doc-comment rationale (level-2 per gate-2's
sizing provisional; `CURVE_TREE_CLIENT.md` §7.2.2).

**Reversion clause (rule 21).** Rejected: making `E` a per-row-only
value with no global constant ("flexibility" for future re-sizing).
Every segment at genesis has one geometry; the per-row
`segment_leaf_count` field remains as the *registry's* copy (gate-2
verifiers read geometry from the row, and the row must stay
self-describing), but the writer always writes the constant.
Reopening criteria: a CT sizing re-review before genesis moves the
level (re-evaluation: constants bump + fixture regen + this doc's §1.1
amendment — bounded, pre-genesis only); or a post-genesis tree
migration (V4) that changes widths (re-evaluation: that migration's
own design round, which reopens the tree itself and this pipeline
with it).

**Fixture reconciliation.** Gate-2 fixtures
(`gate2_serve_credit_kat_v1.json`, `gate4_lifecycle_kat_v1.json`)
carry `segment_leaf_count: 26 000` — a placeholder predating this
pin. They are geometry *inputs* to the verifier and stay valid as
KATs (the verifier reads the row, not the constant), but the
placeholder must not outlive this round: regenerate at `25 992` so
no fixture teaches a reader the wrong number. One-commit item in §7.

---

## 6. Schema dispositions (the restructure authorization, exercised)

### 6.1 `archival_shard_segment` — **keep, unchanged**

The M1 wargame (§1.3) already checked this binding: key
`BE(shard_id)`, single row, no version component, value v1 carrying
`freeze_height`. The pipeline writes exactly that shape. Dropping
the per-row `segment_leaf_count` (redundant under a global `E`) was
considered and rejected: it saves 8 bytes/row, breaks the
row-as-self-describing-registry property gate-2 reads, and re-touches
the codec + M1 count pass + tests the gate PR just landed, for
nothing. Reopening criterion: a second geometry generation actually
existing (which per §5.2 is a tree migration, not a field tweak).

### 6.2 `archival_shard_leaf` — **delete the table**

The genuine restructure this round's authorization unlocks. The
table (`BE(shard_id) ‖ BE(leaf_index_in_segment)` → flat Selene
leaf-layer scalars) is a **derived copy of `m_curve_tree_leaves`**:

- The challenge verifier needs the leaf-layer chunk containing
  challenged index `ℓ` of shard `k`
  (`verify_segment_path`'s `leaf_layer_scalars`, 4×38 scalars).
- That chunk is exactly leaves
  `[⌊(k·E + ℓ)/38⌋·38, +38)` of `m_curve_tree_leaves` — global
  positions, 128 bytes each, concatenated. Segment bases are
  chunk-aligned (38 | E, §1.1) and a complete segment's chunks are
  all full, so the derivation has no partial-chunk edge.
- The daemon retains every leaf forever (fact §2.5), and a frozen
  segment's leaf range is immutable per branch (leaves change only
  by trim, which un-freezes the segment first — §3 O-3). Reading
  live leaves *is* reading as-of-`H_fire`.

The table's own design was already straining: its fixture writes
one row per *challenged index*, meaning the unbuilt production
writer would have had to either pre-materialize every chunk of
every shard (a full second copy of the leaf layer) or know
challenge indices in advance. Under rules 15/16 (dead code touching
consensus data; derived-copy divergence class runs forever) the
disposition is delete, not build:

- Drop the table open, `LMDB_ARCHIVAL_SHARD_LEAF`, both accessors
  (`put_/get_archival_shard_leaf_layer_scalars`) across
  `blockchain_db.h/.cpp`, `db_lmdb.h/.cpp`, `testdb.h`, and the
  fixture test.
- Replace the read at the serve-credit verify site
  (`blockchain.cpp` ~4324) with a chunk read over
  `m_curve_tree_leaves` derived from `(shard_id, ℓ, E)`; the
  position arithmetic (`global = k·E + ℓ`, chunk bounds) is one
  more consensus computation and goes in the **same Rust entry
  point family** (§5.1) — C++ receives start/count, reads leaves,
  concatenates.
- `LMDB_SCHEMA.md`: remove the table section; renumber/annotate the
  table index list; bump the LMDB `VERSION` if the schema snapshot
  discipline requires it (pre-genesis: no migration code, `rm -rf`
  per rule 15 — a version bump only refuses old DBs loudly).

**What this buys:** one fewer unbuilt writer pipeline (with its own
O-1..O-3-shaped obligations), one fewer permanent
copy-vs-source-of-truth divergence surface, and a challenge path
that is automatically consistent with the tree it proves against.
**Cost:** one verify-site rewire plus test updates, all pre-genesis.

**Reversion clause (rule 21).** Reopening criteria: a future
pruned-daemon mode that drops leaf ranges a validator still needs
for challenge verification (re-evaluation: that mode's design round
must either exclude frozen-segment leaves from pruning or reintroduce
a materialized chunk store *with* a designed writer); or profiling
showing the 38-leaf gather is a verify-path bottleneck (it is one
LMDB range read of ~4.9 KB — not credible, named only to be
dismissable with evidence).

### 6.3 Explicitly out of scope

Challenge scheduling/firing, shard distribution and gossip
(`R_k`-as-content-address), wallet-side freeze/prune
(`shekyl-curve-tree` store — already landed per CT-1), `K_COVER`
sealing, and any change to the epoch-close path. Per rule 15, items
spotted here go to `FOLLOWUPS.md`, not this PR.

---

## 7. Implementation plan (single PR, `06-branching.mdc`-sized)

Commit order (each independently buildable; sentinel-style ordering
not needed — no provisional constants):

1. **Constants:** `SEGMENT_LEAF_COUNT` through
   `config/consensus_constants.json` + `build.rs` + crate constant +
   width-product compile assert. Rust
   `frozen_segment_count` + leaf-chunk-bounds helpers with unit
   tests (boundary: `(k+1)·E − 1`, `(k+1)·E`, multi-segment jumps,
   0).
2. **FFI:** `shekyl_archival_frozen_segment_count` (+ chunk-bounds
   export), `cbindgen`/header regen.
3. **Writer:** `process_archival_segment_freezes_at_height` +
   `revert_archival_segment_freezes` in `db_lmdb`, wired into
   `add_block`/`pop_block` per §4; loud-abort on missing layer-2
   chunk.
4. **Shard-leaf deletion:** §6.2 wholesale — table, accessors,
   verify-site rewire to the chunk read, test updates.
5. **Tests:** §9 suite.
6. **Tripwires:** §8 extension to the M1 script (site names now
   final).
7. **Docs:** `LMDB_SCHEMA.md` (writer annotation + table removal),
   M1 §1.3 discharge cross-reference, gate-2 fixture regen at
   `25 992`, `CHANGELOG.md`, `FOLLOWUPS.md` closure (rule 91).

---

## 8. Tripwire extensions (M1 script, invariant discipline)

Extend `scripts/ci/check_reward_gate_predicate_sites.sh` (or a
sibling under the same consensus-invariants umbrella):

- **Writer one-site:** `mdb_put` against `m_archival_shard_segment`
  appears exactly once in production (`put_archival_shard_segment`);
  `mdb_del` against it exactly once
  (`revert_archival_segment_freezes`);
  `put_archival_shard_segment(` has exactly one production caller
  (the freeze processor). The corruption-test raw writer keeps its
  existing named exemption.
- **Cursor accounting:** the invariant-2 expected cursor count over
  the segment table goes from 2 to 5 (operand frontier probe, slash
  scan, freeze processor's resume peek, pop revert walk, and the
  §4.4 differential-walk test oracle) — each pinned by name, same
  shape as today's list.
- **Counter mutation surface (invariant 6):** the
  `"archival_frozen_shard_count"` key literal appears exactly twice
  in `src/` (getter + setter definitions); the setter has exactly
  two call sites (writer +1, revert −1); the differential-walk
  oracle has zero production callers.
- **Division one-site:** no `SEGMENT_LEAF_COUNT`-adjacent `/` or `%`
  in `src/` — the boundary arithmetic lives only in the Rust entry
  point (positive control: the FFI call site exists in both hooks).
- **Positive controls:** the freeze processor and revert exist under
  their exact names; a rename fails the gate rather than de-arming
  it.

---

## 9. Test plan

**Rust (unit + KAT):**
- `frozen_segment_count` boundary table (0, E−1, E, 2E−1, 2E,
  multi-segment jump).
- Chunk-bounds helper: alignment at segment base, last chunk of a
  segment, cross-checked against `E % 38 == 0`.

**C++ (`tests/unit_tests/`, new `archival_segment_freeze.cpp` or
extending `archival_substrate_lmdb.cpp`):**
- **First-crossing:** blocks draining to `E−1` write nothing; the
  block reaching `E` writes row 0 with that block's height; a
  subsequent zero-drain block does not move `freeze_height`.
- **Multi-segment single block:** a drain crossing two boundaries
  writes both rows, same `freeze_height`, `R_k` values distinct and
  correct.
- **`R_k` correctness:** row's `R_k` equals an independent
  `build_layers` composition over exactly the segment's leaves (via
  the existing FFI — the same cross-check shape as
  `grow_upper_layers_ffi_equals_build_layers`).
- **Pop-symmetry (arms O-3):** connect past a boundary, pop back
  across it — row deleted; re-apply — row bit-identical (encoded
  bytes compared, not fields). Pop that stays above the boundary —
  row untouched, `freeze_height` unchanged.
- **Missing-chunk loud abort:** corrupt/remove the layer-2 chunk
  under a boundary crossing (raw-write test surface) — connect
  throws, no partial row.
- **Integration with M1:** an epoch close after real freezes
  produces `frozen_shard_count` equal to the pipeline's row count —
  the gate's operand now exercised end-to-end against
  production-written rows (fixture-row tests retained; M1 §11.10's
  fixture caveat discharged).
- **Challenge-path read (§6.2):** serve-credit verify resolves
  `leaf_layer_scalars` from `m_curve_tree_leaves` for a challenged
  index in a frozen segment and round-trips `verify_segment_path`;
  the deleted table's corruption test is retired with it.

---

## 10. Open questions for round 1 review

1. **Freeze-lag: none (proposed).** The daemon freezes at first
   crossing with O-3 handling reorgs exactly; the wallet-side
   freeze-lag (`CURVE_TREE_CLIENT.md` §4, `end_block_height`
   height-gating) is a client prune-safety discipline, not a
   consensus input. A daemon-side lag constant would add a second
   tunable with no property O-3 doesn't already deliver, and would
   *delay* M1 coverage growth for nothing. Confirm or challenge.
2. **Placement of the pop hook relative to
   `revert_archival_epoch_close_at_height`** — proposed order (close
   revert first, then tree trim, then segment revert) keeps "the
   close revert sees what the close saw" and "the segment revert
   sees the post-trim leaf count". The close revert does not read
   the segment table today (it replays the close log), so the
   ordering is belt-and-braces; confirm no future close-revert
   reader breaks it (candidate for the §8 positive-control list).
3. **`testdb.h` and non-LMDB backends:** the freeze processor lives
   at the `BlockchainDB` level but reads `m_curve_tree_*` tables
   that are LMDB-specific — proposed as LMDB-virtual with a no-op
   test-db default, same as the existing archival substrate methods.
4. **Does gate-2's verifier need `segment_leaf_base`?** §6.1 keeps
   the row shape; base stays derivable (`k·E`). The gate-2 doc calls
   it "optional audit"; nothing reads it. Confirm it stays dead.

---

## 11. Round record

- **Round 1 (2026-07-06):** draft opened. Findings and dispositions
  to be recorded here.

---

## Related documents

- [`ARCHIVAL_REWARD_GATE_M1.md`](ARCHIVAL_REWARD_GATE_M1.md) §1.3 —
  the obligations O-1..O-3 this round discharges (§3); the gate PR
  merge condition this round's opening satisfies.
- [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2 — segment
  geometry, frozen `R_k`, level derivation (§7.2.2).
- [`ARCHIVAL_RETENTION_GATE2.md`](../completed/ARCHIVAL_RETENTION_GATE2.md)
  — the challenge verifier consuming the registry row and (via §6.2)
  the leaf chunk.
- [`LMDB_SCHEMA.md`](../LMDB_SCHEMA.md) — segment table schema
  (kept), shard-leaf table (deleted by §6.2), writer annotations
  (corrected by §4.3).
- [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.2
  — the shard registry contract this pipeline materializes.
