# CT-1 Round 1 close-out (2026-06-09)

**Status:** Round 1 closed. `LeafStore` on **redb** is landed with Tier-A store
KAT, mixed-composition unit KAT, and `CurveTreeClient` ingest mirroring.
Amended 2026-06-10 by the §5 robustness hardening (production-tip root
contract; ahead-of-ingest machinery removed).

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

## 5. Robustness hardening amendment (2026-06-10)

Twelve Copilot review rounds against the Round 1 branch kept surfacing
critical findings in the same area: the store-sync paths that existed to
support `root_at` at heights *beyond* the ingested chain tip. That feature
was test-only convenience — production reference selection
(`reference.rs`) always anchors `REF_ANCHOR_AGE` blocks *behind* the tip,
so no production caller can ask for an ahead-of-ingest root. Per the
all-tests-drive-the-production-path principle, the disposition is
deletion, not further patching.

### 5.1 Production-tip root contract

- `root_at(H)` (and `verify_root`, `assemble_path` by composition)
  **requires `H ≤ ingested_tip`**; otherwise
  `ClientError::ReferenceBeyondIngestedTip`. A client that has ingested
  nothing rejects every query.
- All three are now `&self` queries — computing a root can no longer
  mutate client or store state.
- Store sync is **append-only and monotonic**: `sync_store` runs at ingest
  time only, appends exactly the newly-matured drain bucket (or heals a
  shortfall from a prior failed ingest by appending the missing suffix),
  and never rebuilds or truncates outside reorg handling. Deleted
  wholesale: `sync_store_to`, `sync_store_append`,
  `must_rebuild_store_prefix`, `incremental_drain_on_ingest`,
  `rebuild_store_drained_prefix`, and the `last_synced_drained_key`
  tracking field.
- Consequence: the segment-freeze clock (`maybe_freeze_segments`) is
  driven only by ingested, oracle-verifiable heights — an attacker-supplied
  `reference_height` can no longer advance freezing/pruning.

### 5.2 Store hardening

- **Write-time leaf validation.** `append_drained` rejects any 128-byte
  leaf whose four 32-byte limbs are not canonical Selene scalars
  (`StoreError::InvalidLeafBytes { batch_index }`); the write transaction
  aborts with no partial state. Read-time `CorruptMeta` detection remains
  as the defense-in-depth backstop for on-disk corruption.
- **Single-snapshot bounds checks.** `maybe_freeze_segments`,
  `root_at_count`, and `truncate_from_tree_position` read
  `META_LEAF_COUNT` inside the same transaction that performs the
  operation, eliminating the check/use gap of the previous
  separate-transaction reads.

### 5.3 Test posture

Unit tests and KATs that previously exercised ahead-of-ingest queries now
ingest real consecutive blocks to the queried height — the production
path. New coverage: rejection at/beyond the tip, canonical drain order
against the recon oracle under mixed maturities, historical-root
stability as the chain extends, and write-time rejection of non-canonical
leaf bytes.
