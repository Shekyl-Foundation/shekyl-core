# CT-1 Round 1 close-out (2026-06-09)

**Status:** Round 1 closed. `LeafStore` on **redb** is landed with Tier-A store
KAT, mixed-composition unit KAT, and `CurveTreeClient` ingest mirroring.

**Authoritative pins:** [`CT1_ROUND1_PINS.md`](CT1_ROUND1_PINS.md),
[`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §3.4 / §3.6 / §9.

---

## 1. Landed scope

| Item | Disposition |
|------|-------------|
| Persistence engine | **redb** (`Database::create`, ACID write txns) |
| Leaf encoding | 128 bytes = 4×32-byte Selene scalars; oracle = recon → `build_layers` |
| Segment layer `j` | `2` (provisional); `E = outputs_per_node(j)` |
| Freeze gate | Height-based: `tip − end_block_height ≥ SPENDABLE_AGE + 720` |
| Hot path | `mixed_composition_root` + `full_build_root` fallback when tail too short for layer `j` |
| Reorg | `truncate_from_tree_position` in one write txn |
| Pin / prune | `pin_segment`, `prune_frozen` + owned-chunk table; smoke-tested |
| Client wire | `CurveTreeClient` appends drained leaves to ephemeral `LeafStore` on ingest |

## 2. Test gates (workspace)

From `rust/`:

```bash
cargo fmt --all -- --check
cargo clippy -p shekyl-curve-tree --all-targets -- -D warnings
cargo test -p shekyl-curve-tree
```

| Test | Role |
|------|------|
| `recon_kat` | CT-2 oracle unchanged; client uses store-backed `root_at` |
| `assemble_kat` | CT-4 path assembly unchanged |
| `store_kat` | Store root == recon oracle + header; reorg prefix replay |
| `upper_layers_kat` | Mixed composition mechanism at `j=0` (CI scale) |

## 3. Deferred (not Round 1)

- On-disk `LeafStore::open(path)` wiring in engine / sync (CT-3, CT-5).
- Full-segment freeze + prune retention KAT at production `j=2` leaf count (~26k leaves/segment).
- redb file shrink after prune (cosmetic; documented in pins).
- `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` codegen dedup (PHASE_2B; `FOLLOWUPS.md`).

## 4. Reversion clause (engine choice)

Reopen persistence engine only if (a) measured hot-path regression vs flat-mmap at
projected mainnet leaf count **and** (b) flat-mmap + sidecar design preserves ACID
reorg atomicity (`CURVE_TREE_CLIENT.md` §3.6).
