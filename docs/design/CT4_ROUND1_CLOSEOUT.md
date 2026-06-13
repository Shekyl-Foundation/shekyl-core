# CT-4 Round 1 close-out (2026-06-13)

**Status:** Round 1 closed. The two CT-4 surfaces are landed and KAT-gated:
(1) **membership-path assembly** — `CurveTreeClient::assemble_path` produces the
`AssembledPath` an FCMP++ membership proof consumes, gated on the §3.3 integrity
match; (2) **reference-block selection + validity-horizon arithmetic** —
`reference.rs` as total, side-effect-free functions over heights. Both landed
ahead of their decomposition slot (assembly with CT-1/CT-2; the horizon
arithmetic added subsequently and hardened by the CT-3↔CT-4 audit cleanup that
folded the reference-block hash into `ReferenceBlock`). The store-backed /
pruned-tree assembly substrate is deferred-with-recorded-shape per its reversion
clause; it lands with the prune-policy PR, not in CT-4.

**Authoritative spec:** [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §3.5
(assemble contract) and §5 (reference-block selection + horizon). **Parent:**
§9 CT-4 row.

---

## 1. Landed scope

| Surface | Disposition | Key files |
|---------|-------------|-----------|
| **Membership-path assembly** | `assemble_path(&id, &reference) → AssembledPath`: runs the §3.3 integrity gate first (store-backed `root_at`, no replay-oracle fallback), then extracts the leaf chunk (`ChunkLeaf` tuples: `O`, `I = Hp(O)`, `C`, `h_pqc`) and the bottom-to-top branch chunks (`c1_layers`/`c2_layers` as node x-coordinate scalars, full child chunk, root excluded). Path layout pinned at source to the FCMP++ prover's `Path`. C3 invariant `c1 + c2 + 1 == tree_depth` self-checked. | `assemble.rs`, `types.rs` (`AssembledPath`/`ChunkLeaf`/`TreeContext`), `tests/assemble_kat.rs` |
| **Reference-block selection + horizon** | `reference.rs` total arithmetic over heights: `select_reference_height` (`tip − REF_ANCHOR_AGE`), `reference_block_age`, `proof_submittable`, `proof_expired`, `should_reanchor`. Constants `REF_ANCHOR_AGE = 6`, `PROOF_VALIDITY_HORIZON = 94`, `REBUILD_AT = 50`, with `REFERENCE_BLOCK_{MIN,MAX}_AGE` emitted from `config/consensus_constants.json` by `build.rs` (same JSON authority as the C++ header) and const-eval sentinels guarding the 5/100 baseline. **Not** methods on `CurveTreeClient` — the client stores no header roots, so selection is height arithmetic the caller drives, and binding height→root→hash stays the caller's job (§3.5). | `reference.rs` |
| **`ReferenceBlock` anchor hardening** (CT-3↔CT-4 audit, commit on this branch) | The reference-block hash folded into `ReferenceBlock.block_hash`; `assemble_path` dropped its loose positional `[u8; 32]`. The caller now supplies the full consensus anchor (`height`, `curve_tree_root`, `block_hash`) as one value — removing a positional-swap footgun among four `[u8; 32]` semantic types and matching the §5 two-arg API. | `types.rs`, `assemble.rs` |

## 2. Test gates (workspace)

From `rust/`:

```bash
cargo fmt --all -- --check
cargo clippy -p shekyl-curve-tree -p shekyl-archival-retention --all-targets -- -D warnings
cargo test -p shekyl-curve-tree -p shekyl-archival-retention
```

| Test | Role |
|------|------|
| `assemble_kat::assembled_path_recomputes_to_consensus_root` | **Primary assembly gate** — assemble at the tip reference, then *independently* re-hash the returned branches (leaf chunk + `c1`/`c2` layers) and assert the recomputed root equals the consensus header root, for founder / mid-tree / last-drained targets |
| `assemble_kat::assemble_path_rejects_undrained_output` | Undrained output ⇒ `OutputNotDrained` (lookup miss, not a forged path) |
| `assemble_kat::assemble_path_rejects_root_mismatch` | Wrong consensus root ⇒ `RootMismatch` before any path is built (§3.3 gate) |
| `reference::tests::*` (7 tests) | Selection (`tip − REF_ANCHOR_AGE`, pre-maturity `None`), acceptance-window boundaries (MIN/MAX inclusive), full proof-aging progression, re-anchor-before-expiry ordering, reorg-below-reference re-anchor; derived constants pinned independently of the const-eval sentinels |
| `assembled_path_crosscheck.rs` (shekyl-archival-retention) | CT-4 path cross-check against the archival verify crate |
| `gate2_serve_credit_kat.rs` (shekyl-archival-retention) | Assembled path consumed by the Gate-2 serve/credit path |

## 3. DoD mapping (§3.5 assemble contract + §5)

| Item | Disposition |
|------|-------------|
| Membership path in the prover's `Path` shape (`c1`/`c2` scalars, full chunk, root excluded) | **Landed** — pinned at source, C3 invariant self-checked |
| Assembly gated on a correct root at the reference height | **Landed** — §3.3 integrity gate runs first (`RootMismatch`/`OutputNotDrained`) |
| Leaf chunk carries compressed `O`/`I`/`C`/`h_pqc` (F6) | **Landed** — `OutputIdentity` retained per drained leaf; `I = Hp(O)` derived in-crate via `key_image_generator` |
| Reference-height selection (canonical, privacy-uniform) | **Landed** — `select_reference_height`, §5.1 |
| Proof validity horizon + proactive re-anchor bound | **Landed** — `proof_expired`/`should_reanchor`, `PROOF_VALIDITY_HORIZON`/`REBUILD_AT`, §5.2 |
| Reference-block reorg handling | **Landed** — age-`None` ⇒ `should_reanchor`/`proof_expired` true, §5.3 |
| 2A §3.7.5 C2 terminology correction (two ages not conflated) | **Landed** (Round-1 cross-edit into `PHASE_2A_SEND_PATH.md`), §5.4 |
| Store-backed / pruned-tree assembly | **Deferred-with-recorded-shape** (§5), rides the prune-policy PR |

## 4. Design pins (at source)

- **Path layout** mirrors `shekyl-oxide/crypto/fcmps/src/prover/mod.rs`'s `Path`
  (`C1 = Selene`, `C2 = Helios`, `OC = Ed25519`): the leaf chunk hashes to a
  Selene node, whose x-coordinates feed a Helios node, alternating upward. So
  odd tree layers (1, 3, …) are Helios → `c2_layers`, even internal layers
  (2, 4, …) are Selene → `c1_layers`; each branch is the **full child chunk**
  (siblings not excluded); the root point is excluded (supplied separately as
  `TreeContext::tree_root`). C3: `c1_layers.len() + c2_layers.len() + 1 ==
  tree_depth`.
- **Reference selection is canonical convention, not free choice** (privacy):
  the reference age is observable on every tx, so a per-wallet offset would
  fingerprint the wallet. Every honest wallet uses `REF_ANCHOR_AGE = MIN_AGE +
  1`. Cannot be consensus-enforced (the daemon accepts any age in
  `[MIN_AGE, MAX_AGE]`); canonical convention is the ceiling. §5.1 reversion
  clause: re-derived only on a substrate change (observed depth-6 reorg rate)
  or a `MIN_AGE` consensus change, never by preference.

## 5. Deferred with reversion clauses (FOLLOWUPS-routed)

Per `21-reversion-clause-discipline.mdc`, each carries a named reopening
trigger; none is "refused forever."

- **Store-backed / pruned-tree path assembly — F5 / R1-Q6.** `assemble` reads
  the in-memory entry vec; whole-tree-in-memory is correct at Tier-A scale and
  the V3.0 substrate (resume rebuilds it from the store). **Reopens** when the
  prune-policy PR lands, where in-memory-only assembly breaks for pruned wallets
  by construction. (`FOLLOWUPS.md`, `CT3_SYNC.md` §3 R1-Q6.)
- **C++ path-RPC crypto contract (`hash_to_p3`) — Rust-forward.**
  `on_get_curve_tree_path` recomputes `I = Hp(O)` in C++ instead of the existing
  `shekyl_compute_output_key_image` FFI. **Reopens** with the daemon
  path-assembler migration, or any PR that touches `on_get_curve_tree_path` for
  another reason. (`FOLLOWUPS.md`, recorded by the CT-3↔CT-4 audit.)

## 6. What Round 1 ungates

- **CT-5 (engine/2A signer wiring).** `assemble_path` + the reference/horizon
  predicates are the contract CT-5 consumes to replace 2A's synthetic vectors
  with the production client (§3.5). CT-5 selects the reference height, builds
  the `ReferenceBlock` anchor from its chain view, assembles the path, and
  drives the proactive re-anchor loop off `should_reanchor`.
- **Archival verify cross-checks** already consume `assemble_path`
  (`assembled_path_crosscheck.rs`, Gate-2 serve/credit), so the CT-4 surface is
  exercised outside the curve-tree crate.

## 7. Explicitly not Round 1

- Store-backed assembly for pruned wallets (rides prune-policy).
- The daemon-side path-assembler FFI migration (`assemble_tree_path_for_output`
  / `on_get_curve_tree_path`), a Stage 4/5 planning activity.
- CT-5 engine wiring itself (the consumer, not the contract).
