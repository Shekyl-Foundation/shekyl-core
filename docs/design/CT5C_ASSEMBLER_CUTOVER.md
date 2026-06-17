# CT-5c — assembler cutover: real `assemble_path` into the 2A signer (design round)

**Status:** Design round conducted 2026-06-17, three forks resolved (§4). This
doc is the frozen contract the CT-5c implementation cuts against, per
[`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc) (spec first,
code second) and the design-round discipline of
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
It refines — does not supersede — [`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md)
§3.4 / §3.7 (T1–T3) / §5.1 (X3); where this doc adds scope (§3, the fee-path
depth finding) it is called out explicitly.

**Predecessors landed:** CT-5a (CurveTreeActor + ingest), CT-5b (§3.3 ingest
verify + reference-block selection + C2 spendability gate, PR #149), CT-5c/X5
(`eligible_height` floors on additional-timelock + stake-lock, PR #151 — the
small slice that precedes this cutover per the agreed sequencing).

**Mission framing.** This slice retires the last cryptographic placeholder on
the spend path: it replaces fabricated FCMP++ membership vectors with the real
curve-tree path the daemon will verify. Binding commitment is **#1
security** — a wallet that submits a proof against a synthetic root cannot
spend on a real chain; until this lands, the send path is structurally
incapable of producing a valid transaction against a populated tree.

---

## 1. Where we are: the path is still synthetic, in two places

CT-5b made the *reference* real — [`local_pending_tx.rs:1468`](../../rust/shekyl-engine-core/src/engine/local_pending_tx.rs)
binds a real `ReferenceBlock { height, curve_tree_root (re-derived via
`root_at`), block_hash }`, and the C2 gate selects against it. But the
membership *path* is fabricated, and there are **two clobber sites**, not one:

1. [`signing_assembly.rs:51,100`](../../rust/shekyl-engine-core/src/engine/signing_assembly.rs)
   — `synthetic_tree_context(...)` and per-input `enrich_input_tree(vec![leaf], depth)`
   fabricate the leaf chunk, branch layers, and root; `synthetic_h_pqc_bytes` /
   `key_image_gen_bytes` fabricate per-leaf fields.
2. [`sign_bridge.rs:301–320`](../../rust/shekyl-engine-core/src/engine/sign_bridge.rs)
   — **re-runs `enrich_input_tree` and overwrites `tree_root`** with
   `synthetic_tree_root_from_leaf_chunk`, *discarding whatever `signing_assembly`
   produced*.

**Consequence for scoping:** cutting over only `signing_assembly` would leave
`sign_bridge` silently overwriting the real path with a synthetic root. Both
must change in the same commit. This is the single largest "looks like one site,
is actually two" trap in the slice.

The whole synthetic surface to delete:
[`engine/synthetic_tree.rs`](../../rust/shekyl-engine-core/src/engine/synthetic_tree.rs)
(`placeholder_selene_sibling`, `placeholder_helios_sibling`,
`synthetic_h_pqc_bytes`, `synthetic_tree_context`, `enrich_input_tree`,
`synthetic_tree_root_from_leaf_chunk`). Per
[`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc) /
[`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc) it is
pre-genesis scaffolding with no users once `assemble_path` is the producer —
**deleted, not gated** (R1-Q5).

---

## 2. The adapter is a field copy (verified against source)

The producer is [`CurveTreeClient::assemble_path`](../../rust/shekyl-curve-tree/src/assemble.rs)
→ `AssembledPath { leaf_chunk: Vec<ChunkLeaf>, c1_layers, c2_layers, tree: TreeContext }`.
The engine consumes it through a trivial field copy:

| curve-tree (public, no secrets) | tx-builder (signer-facing) | shape |
|---|---|---|
| `ChunkLeaf { output_key, key_image_gen, commitment, h_pqc }` | `LeafEntry { output_key, key_image_gen, commitment, h_pqc }` | 4 × `[u8;32]` |
| `TreeContext { reference_block, tree_root, tree_depth }` | `TreeContext { reference_block, tree_root, tree_depth }` | identical |
| `AssembledPath.c1_layers / c2_layers` | `TxInputSigningContext.c1_layers / c2_layers` | `Vec<Vec<[u8;32]>>` |

`ChunkLeaf` was authored to mirror `tx_builder::LeafEntry`'s field names
([`curve-tree/types.rs:166`](../../rust/shekyl-curve-tree/src/types.rs) docstring),
so the adapter is a struct-to-struct copy, no transform.

**Secret-locality unchanged.** `AssembledPath` carries only public on-chain
material. Secrets are still added only at `sign_bridge → SpendInput`. The cutover
moves *public path material* from a fabricator to the real client; it does not
move any secret across the FFI/engine boundary
([`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc) intact). The
real `h_pqc` / `key_image_gen` now come from the tree's drained leaf, replacing
the fabricated values.

---

## 3. The architectural seam, and a scope finding the umbrella doc under-specified

### 3.1 Async assembly vs. sync selection

`build_assemble_sync` ([`:634`](../../rust/shekyl-engine-core/src/engine/local_pending_tx.rs))
is **synchronous**: it does output selection *and* calls `assemble_tx_to_sign`
(synthetic) under the pending-tx state lock. The real `assemble_path` is a
`&self` read behind the **async** `CurveTreeActor`. The batch `AssembleTx` (T3)
therefore cannot be dispatched from inside `build_assemble_sync`.

The cutover splits the async `build` ([`:1420`](../../rust/shekyl-engine-core/src/engine/local_pending_tx.rs)):

```text
build (async):
  1. fee_snapshot      = fee_snapshot_source.fetch().await
  2. tree_gate         = handle.ingested_tip_height().await
  3. (root, depth)     = handle.reference_root_and_depth(reference_height).await   [Q1 — §4]
     reference         = ReferenceBlock { height, curve_tree_root: root, block_hash }
  4. select_sync(.., tree_depth = depth)   ← selection ONLY; real depth feeds fees
       └─ creates the reservation, drops the state lock
       → returns { selected_indices, assemble_inputs, fee_directive, meta }
  5. paths: Vec<AssembledPath> = handle.assemble_tx(reference, assemble_inputs).await   [T3]
  6. tx_to_sign = assemble_tx_to_sign(network, request, selected_tds, &paths, fee_directive)
       ← SYNC fold; T1/T2 (no [u8;32] reference, no free depth); asserts paths[0].tree.tree_depth == depth
  7. signed = signer.sign_transfer(tx_to_sign).await ; commit_built_sync(..)
```

The existing `BuildReservationCleanup` guard ([`:1509`](../../rust/shekyl-engine-core/src/engine/local_pending_tx.rs))
already releases the reservation on any post-selection failure; it moves up to
wrap the `assemble_tx` await, so an assembly error frees the locked outputs.

### 3.2 Scope finding: `tree_depth` is load-bearing in **fee estimation**

`CT5_ENGINE_WIRING.md` §3.7 T2 says "derive `tree_depth` from `AssembledPath`;
delete the free `tree_depth` parameter." That is correct for the *signer-facing*
param — but it is only half the story, because **depth also drives fee
estimation, which runs before assembly**:

- [`tx_fee_model.rs:47`](../../rust/shekyl-engine-core/src/engine/tx_fee_model.rs)
  `fcmp_proof_size` scales the proof by
  `(tree_depth − 1) × FCMP_PROOF_BYTES_PER_DEPTH_LAYER`.
- Today [`local_pending_tx.rs:914`](../../rust/shekyl-engine-core/src/engine/local_pending_tx.rs)
  hardcodes `tree_depth = 1u8`. On a real depth-> 1 tree this **under-estimates
  the fee**, and an underpaid tx is rejected by the daemon's weight check.

The dependency is circular: fee → selection → `AssembleTx` inputs → depth. So the
real depth must be read **before** selection, not derived from the assembled
path. T2 is satisfied at the signer boundary (the path carries depth), but the
fee path needs its own pre-assembly read.

**Why this is safe and consistent.** Depth at a *fixed historical*
`reference_height` is invariant under forward ingest: a block at height `h >
reference_height` only creates outputs whose maturity is `≥ h + 10 >
reference_height`, so they never drain into the tree as-of `reference_height`.
Depth at `reference_height` changes only on a rollback *below* `reference_height`
— which invalidates the reference itself (the proof would be re-anchored,
CT-5d). Therefore the pre-selection depth and `paths[0].tree.tree_depth` are
**provably equal whenever the reference is valid**; the fold (step 6) asserts
equality as a defense-in-depth tautology (DoS-never-theft: a mismatch means the
tree moved under a reference it should not have, so refuse — never sign).

This finding is **new scope** beyond the umbrella doc's T1/T2/T3 and is the
reason a combined root+depth read (Q1) is introduced rather than reusing the
bare `root_at`.

---

## 4. Resolved design forks (locked 2026-06-17)

### Q1 — how to obtain the real depth: **combined root+depth read**

Add a `RootAndDepthAt { height } -> (root: [u8;32], depth: u8)` actor message and
a `CurveTreeHandle::reference_root_and_depth` method; `build`'s reference-binding
uses it in place of the bare `root_at` await — one snapshot, one round-trip, both
values pinned to the same `reference_height`. The client gains
`root_and_depth_at(height)`; the existing `root_at` becomes a thin wrapper that
discards depth, so the **CT-5a oracle KAT** (which asserts the ingest path
reproduces the consensus header root and consumes `RootAt`) is left untouched.
Depth is `build_layers(...).len()` — the exact same reconstruction
`assemble_path` uses, so equality with the assembled depth is by construction,
not by a parallel formula that could drift.

*Rejected:* a separate `DepthAt` message (two round-trips, two reads at one
height) and a cheap `ceil(log_width(leaf_count))` depth (risks off-by-one vs.
`build_layers`, would need its own equality KAT).

### Q2 — where the batch lives: **actor-handler loop**

No client-side batch method. The actor message
`AssembleTx { reference: ReferenceBlock, inputs: Vec<AssembleInput> } -> Result<Vec<AssembledPath>, ClientError>`
loops `assemble_path` per input **inside one handler invocation**. kameo
processes messages serially, so no `IngestBlock` / `RollbackToFork` can interleave
mid-assembly — the E1 read-atomicity hazard is structurally unrepresentable (the
handler is the snapshot), with no new client API surface. The
`MAX_INPUTS` bound (from `shekyl-tx-builder` / `shekyl-fcmp` — note the umbrella
doc's `FCMP_MAX_INPUTS_PER_TX` is an approximate name; the real constant is
`MAX_INPUTS`) is checked engine-side before dispatch.

*Rejected:* a `CurveTreeClient::assemble_tx` batch method — it would add API
surface for an atomicity guarantee the actor already provides via serial
dispatch.

### Q3 — gindex resolution mismatch: **hard error**

X3: `assemble_path` ([`assemble.rs:92`](../../rust/shekyl-curve-tree/src/assemble.rs))
stops matching the owned leaf by `(output_key, commitment)` content and instead
resolves `leaf_pos = drained.position(|e| e.gindex == Gindex(G))`, with `G =
TransferDetails.global_output_index` ([`transfer.rs:91`](../../rust/shekyl-engine-state/src/transfer.rs)) —
the tree's unique key, so resolution is total (no collision case; X3 §5.1). A new
query type carries it:

```rust
pub struct AssembleInput {
    pub gindex: Gindex,
    pub identity: OutputIdentity,   // for the post-resolution consistency check
}
```

After resolving by `gindex`, the leaf's `(output_key, commitment)` is **hard-checked**
against `identity`; a mismatch returns a new `ClientError::IdentityMismatch {
gindex }` and refuses to build. A gindex that resolves to an unexpected output
means store corruption or scanner/tree desync — fail loudly rather than assemble
a wrong-leaf proof (DoS-never-theft, mirroring `OutputNotDrained`). The `(O, C)`
content-match is deleted from the owned-output path.

*Rejected:* `debug_assert` only — a release-mode desync would silently assemble
against the wrong leaf.

---

## 5. T1 / T2 deletions (umbrella §3.7)

- **T1** — `assemble_tx_to_sign` drops `reference_block: [u8;32]`. The real
  `TreeContext` (including `reference_block = ReferenceBlock.block_hash`) rides
  the `AssembledPath`; the lone-`[u8;32]` slot that let a *tip hash* and a
  *reference hash* share a type is removed, so the §3.4 tip-as-reference bug
  becomes a type error.
- **T2** — `assemble_tx_to_sign` drops `tree_depth: u8`; depth comes from
  `paths[0].tree.tree_depth`. The fee path's depth is the separate real read
  (§3.2), not a hardcoded `1u8`.

Both are deletions, not bypasses ([`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc)):
the call paths cease to exist (grep-clean is part of the DoD).

---

## 6. Commit plan (one PR, branched off `dev` after #151/X5 merges)

The PR branches off `dev`-with-X5 (not stacked on #151) per the agreed
"X5 first, then cutover" sequencing — mirroring how CT-5b waited on CT-5a.

1. **curve-tree X3** — add `AssembleInput { gindex, identity }`; switch
   `assemble_path` to gindex resolution + post-resolution `(O,C)` hard-check; new
   `ClientError::IdentityMismatch`; migrate the one `assemble_kat.rs` call site.
   *Self-contained, curve-tree only.*
2. **client + actor read API** — `CurveTreeClient::root_and_depth_at`
   (`root_at` thin-wraps it); actor messages `RootAndDepthAt` and `AssembleTx` +
   `CurveTreeHandle::reference_root_and_depth` / `assemble_tx`. *Adds the reads,
   no consumer yet — `assert_send` structural test as in CT-5a/b.*
3. **engine cutover** — split `build` (§3.1); thread real fee depth;
   `assemble_tx_to_sign` consumes `&[AssembledPath]` (T1/T2); delete the
   `sign_bridge` synthetic clobber (§1); **delete `synthetic_tree.rs`**.
4. **test migration + DoD + doc closure** — migrate synthetic-dependent engine
   tests to the real client over the CT-2 fixture / `TestDaemon`; add the X3 KAT
   and the real-root build+submit KAT; record this round's closure (the §3.2
   fee-depth finding + the Q1–Q3 resolutions) into `CT5_ENGINE_WIRING.md` and mark
   this doc closed.

Commit slicing is provisional; commits 1–2 are cleanly separable and could each
be confirmed green independently before commit 3 lands the consumer.

---

## 7. Test migration & Definition of Done

**DoD (from `CT5_ENGINE_WIRING.md` CT-5c row, made concrete here):**

- A real-root proof **builds and submits** in the `TestDaemon` harness (the
  harness fakes the daemon, not the tree, so its proof-validity coverage becomes
  real for the first time).
- The **C3 invariant** `c1_layers.len() + c2_layers.len() + 1 == tree_depth` holds
  on the assembled path (already a `debug_assert` inside `assemble_path`; the
  engine fold re-asserts the depth equality of §3.2).
- **Grep-clean:** no `reference_block: [u8;32]` assembly param and no free
  `tree_depth: u8` param remain; `synthetic_tree.rs` is gone.
- **X3 KAT:** an owned output resolves to the correct `gindex` (total resolution
  — there is no collision case to test, per X3 §5.1).
- **X5 KAT:** already landed in #151 (a coinbase whose reference height sits
  between `+SPENDABLE_AGE` and the coinbase lock is not selected as spendable, so
  no wrong-leaf assembly is attempted).

**Test blast radius (the chief risk, §8).** Deleting `synthetic_tree` forces
every engine test that built a synthetic path to migrate to the real client over
the CT-2 fixture. This is the largest unknown in the slice and the most likely
place review rounds concentrate; the migration is itself part of the value
(synthetic-vector tests were asserting against a fabricator, not the prover).

---

## 8. Risks

- **Two clobber sites (§1).** `signing_assembly` *and* `sign_bridge` both
  fabricate; they must cut over together or the root is silently synthetic.
  *Mitigation:* both land in commit 3; the build+submit KAT would fail if either
  remained.
- **Test migration scope (§7).** Largest unknown. *Mitigation:* commit 4 is
  scoped to it explicitly; the real client + CT-2 fixture are already exercised
  by the CT-2 KATs, so the harness exists.
- **Fee/depth consistency seam (§3.2).** A new cross-await pairing
  (`reference_root_and_depth` then `assemble_tx`, both at `reference_height`).
  *Mitigation:* invariance under forward ingest is argued in §3.2; the fold
  assert turns any violation into a refusal, never a bad signature.

---

## 9. Cross-references

- [`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md) §3.4 (real path assembly), §3.7
  (T1–T3 type-enforced contracts), §5.1 X3 (gindex resolution), R1-Q5 (delete
  `synthetic_tree`).
- [`CT2_DRAIN_ORDER.md`](CT2_DRAIN_ORDER.md) — drain order / gindex numbering the
  resolution keys on.
- [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §3.5 / §4.3 — path layout and the
  caller-supplies-root integrity model `assemble_path` enforces.
