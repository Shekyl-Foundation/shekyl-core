# CT-1 Round 1 pins — LeafStore (redb)

Round-1 disposition for `shekyl-curve-tree` `LeafStore` (CT-1). Locks the
persistence engine, leaf encoding contract, segment-freeze gate, and schema
fields that downstream commits implement against.

## Persistence engine: **redb** (locked)

**Pin:** `redb = "4.1.0"` (workspace `[workspace.dependencies]`). Pre-genesis
greenfield uses v3 file format only (`Database::create`); no v2 migration path.
Requires rustc ≥ 1.89; workspace MSRV 1.94 is pinned intentionally (RandomX
PoW + redb); `Box::new_zeroed_slice` (stable 1.92.0) is already covered.

| Factor | Rationale |
|--------|-----------|
| **Shekyl-first** | Pure Rust, no C FFI, no MSVC LMDB build risk (`10-shekyl-first.mdc`) |
| **Operational** | File grows automatically; freed pages reused on later writes. **Cosmetic only:** large prune-to-`R_k` does not shrink the file on disk; footprint may stay elevated until later growth reuses pages. **Not** a correctness hazard — unlike heed `map_size`, where `MDB_MAP_FULL` is a hard failure. |
| **ACID reorg** | Single write transaction across leaves + segment metadata; `truncate_from_tree_position` atomic by construction |
| **Correctness > perf** | Transactional store over mmap micro-opts pre-genesis; flat-mmap remains bench-gated per `CURVE_TREE_CLIENT.md` §3.6 |
| **Untrusted input** | Neutral — §7.3 `verify_segment` before write; storage never parses adversarial bytes |
| **Not a reason** | Daemon `curve_tree_leaves` parity — forbidden as a decision driver (`CURVE_TREE_CLIENT.md` §3.6) |

**heed rejected for CT-1** on supply-chain + presize correctness hazard; LMDB
maturity alone does not outweigh Shekyl-first alignment for a greenfield
wallet-only store.

**Reversion clause:** reopen engine choice only if (a) measured hot-path
regression vs flat-mmap at projected mainnet leaf count **and** (b) flat-mmap
+ sidecar design preserves ACID reorg atomicity — same shape as
`CURVE_TREE_CLIENT.md` §3.6.

## Leaf encoding contract

Canonical **4×32-byte Selene scalar** leaf record (recon's drained scalars →
`build_layers` → oracle root). **Binding constraint is the recon / `store_kat`
oracle**, not conformance to daemon C struct layout. Bytes coincide with daemon
`curve_tree_leaves` today but the wallet follows **recon**, not
`shekyl_types.h` drift.

## Segment freeze gate (height-based)

```text
SEGMENT_FREEZE_REORG_MARGIN_BLOCKS = 720  // ARCHIVAL_REORG_DEPTH_BLOCKS
SPENDABLE_AGE = DEFAULT_LOCK_WINDOW = 10  // block counts

segment may freeze when:
  tip_height − segment.end_block_height ≥ SPENDABLE_AGE + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS
```

**Unit correction:** margin and `SPENDABLE_AGE` are **block** counts. Gating on
tree **positions** under-protects by the drain-rate factor. Gate on **heights**.

**Schema:** `frozen_segments` carries `end_block_height` — the block height at
which `end_tree_pos` (the segment's newest leaf) entered the tree.
`frozen_at_height` records **when the segment was frozen**, not when its last
leaf drained.

## Provisional constants

- Segment sub-root layer `j = 2` (outputs per node `E = outputs_per_node(j)`).
- `TreePosition` = dense `u64` drain-order index.
- `O.x` → position index deferred (`CURVE_TREE_CLIENT.md` §8 #2).

## Cross-refs

- `docs/design/CURVE_TREE_CLIENT.md` §3.4 (reorg / freeze-lag), §3.6 (engine)
- `docs/design/ARCHIVAL_TIMING_CONSTANTS.md` (`ARCHIVAL_REORG_DEPTH_BLOCKS`)
- `docs/FOLLOWUPS.md` — `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` dedup (PHASE_2B)
