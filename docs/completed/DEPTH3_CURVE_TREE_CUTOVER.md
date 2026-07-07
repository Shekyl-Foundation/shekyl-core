# Depth-3+ curve-tree root — consensus cutover

**Status:** **IMPLEMENTED + validated, 2026-06-27** (PR #197,
`fix/depth3-curve-tree-recon`). Both producers (`grow_curve_tree`,
`trim_curve_tree`) recompose every upper layer narrow (`== build_layers`) via the
Rust `shekyl_curve_tree_grow_upper_layers` FFI; validated end-to-end against a
locally-built daemon. This note is the cutover bookkeeping the FOLLOWUPS depth-3
entry called for — what changed, what is provably unaffected, and why no
version bump / migration is required.

**Mission framing.** FCMP++ membership is the privacy mechanism (mission #2 —
privacy is the product). A wallet can only spend if its **native** curve-tree
reconstruction (`build_layers`) agrees with the daemon's per-height header root,
which the daemon's consensus `shekyl_fcmp_verify` checks the proof against. A
divergence at depth-3+ means a wallet **cannot sync or spend** once the tree
grows past one Helios branch (~684 drained outputs) — which a real chain reaches
almost immediately. So this is a genesis-blocking consensus-correctness fix, not
an optimization.

---

## 1. What was wrong

The daemon stored the curve tree in LMDB and, on each block, propagated the new
outputs **up the layers in place**, editing each parent chunk by the
`old_scalar → new_scalar` difference of its changed child (`hash_grow(parent, pos,
old, new, …)`). At a layer **boundary** — the block that first creates a new
parent node one layer up (a *deepen*) — that incremental edit started the new
parent from an init/empty hash and folded in only the *newly created* child,
**dropping the pre-existing sibling(s)** that already belonged under that parent.

The wallet, by contrast, always rebuilt narrow: `build_layers` composes each
parent from **all** its converted children at once
(`hash_grow(init, 0, ZERO, [all children])`). So at depth-3+ (the first layer-2
Selene branch, ≈ `SELENE_CHUNK_WIDTH × HELIOS_CHUNK_WIDTH = 38 × 18 = 684`
leaves) the daemon's header root **diverged** from the wallet's `build_layers`,
and verify-at-ingest failed with `CurveTreeIngest: curve-tree root mismatch vs
header`. This was the #162 reopening trigger firing.

Depth-0/1/2 never hit a *deepen-with-existing-sibling*, so the daemon and
`build_layers` agreed there — which is why every depth-2 fixture and the offline
recon KATs were (and remain) correct.

## 2. The fix (producer-side, in Rust)

Per rule 16 / the #162-retraction discipline, the **producer** was fixed, not the
reference: conforming `build_layers` to the daemon would have frozen the consensus
defect at genesis. The tree-grow orchestration moved into Rust as
`shekyl_curve_tree_grow_upper_layers` (a thin FFI over `build_layers`'
`try_build_upper_layers`), and both daemon producers were rewired to it:

- **`grow_curve_tree`** ([`db_lmdb.cpp`](../../src/blockchain_db/lmdb/db_lmdb.cpp)):
  read the leaf-chunk layer, recompose every upper layer narrow, persist the
  recomposed chunks + root + depth.
- **`trim_curve_tree`** (the reorg path): the leaf loop trims the boundary leaf
  chunk; then delete every existing upper-layer chunk (`layer ≥ 1`) and recompose
  identically. Trim *shrinks* the tree, so stale upper chunks must not survive.

The dead in-place incremental propagation and the now-unused `ct_layer_is_selene`
helper were removed (rule 15).

## 3. What changed — and what is provably unaffected

| Surface | Effect |
|---|---|
| **Depth-3+ header roots** | **Changed** — now the narrow-recompose root (`== build_layers`). |
| Depth-0/1/2 roots | **Unaffected** — the daemon was already correct; `recon_kat` (6/6) + `recon_tier_b` (3/3) reconstruct the depth-2 fixtures unchanged against the fixed code. |
| Genesis (block 0) | **Unaffected** — depth-0/1; no upper layers. |
| Persisted block **wire format** | **Unchanged** — same serialization; only the depth-3+ root *value* differs, and it is derived from blocks by the fixed code. No schema-snapshot delta (rule 42). |
| Wallet `build_layers` | **Unchanged** — it was always the correct reference. |
| Tier-A / Tier-B fixtures | **Unaffected** — both are depth-2 (Tier-A ≈ 151 leaves at height 210; Tier-B ≈ 22–35). No depth-3+ fixture exists, so none needs regeneration. |

## 4. No version bump, no migration

- **No persisted-wire-format change (rule 42).** The block/header serialization is
  byte-identical; only the *computed* depth-3+ root differs. The schema-snapshot
  check is unaffected.
- **No daemon DB-version bump / no migration.** Pre-genesis, no live chain exists
  past depth-2 — only ephemeral regtest DBs. A daemon syncing from genesis on the
  fixed code computes correct depth-3+ roots from the start; there is no historical
  data to migrate. (A pre-fix regtest data-dir that already grew past depth-3 holds
  wrong derived roots and must be wiped, not upgraded — but that is dev-local
  ephemeral state, not consensus history.)
- **No wallet store (`redb`) bump.** `build_layers` was always correct, so any
  wallet-side cached roots were already right; `SCHEMA_VERSION` is untouched.

## 5. Validation (all local, against a rebuilt `shekyld`)

- **Grow** — [`e2e_fcmp_spend_over_depth3_tree`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs):
  mine to a real depth-3 tree (daemon depth 2, ~701 leaves); the wallet `refresh`
  succeeds over it (the root mismatch is gone) and the daemon **accepts** a
  wallet-built FCMP++ spend over that tree.
- **Trim** — `e2e_trim_curve_tree_restores_grow_root`: grow to depth-2 across a
  Selene leaf-chunk boundary, grow further, then `pop_blocks` back — the trimmed
  root equals the grow root **exactly** (`trim == grow⁻¹`; grow is the proven
  `== build_layers` reference).
- **Freeze replica** — [`curve_tree_freeze.rs`](../../rust/shekyl-fcmp/tests/curve_tree_freeze.rs):
  a faithful replica of the daemon's old incremental propagation reproduces the
  drop-the-sibling divergence at the depth-3 deepen, and the corrected recompose
  telescopes to `build_layers`.
- **Depth-2 unchanged** — `recon_kat` + `recon_tier_b` pass against the fixed code.

## 6. Consensus implication

From genesis, depth-3+ curve-tree roots are the narrow-recompose roots
(`== build_layers`), produced identically by `grow` and `trim`. The construction
is now frozen as the genesis behavior. There is no migration because there is no
pre-genesis chain; the only action for a developer holding a pre-fix regtest
data-dir grown past depth-3 is to wipe it before re-running.

**References.** PR #197;
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (depth-3 entry, now resolved);
[`docs/V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) (binding entry,
2026-06-27).
