# CT-5c — assembler cutover: real `assemble_path` into the 2A signer (design round)

**Status:** **IMPLEMENTED + closed, 2026-06-18** (`feat/ct-5c-assembler-cutover`).
Design round conducted 2026-06-17, three forks resolved (§4); implemented per
this contract. Closure notes (§10) record what the implementation surfaced
beyond the design: a latent FCMP++ layer-parity bug in `shekyl-tx-builder`, the
PF7 unblock that made the measured fee table possible, and two scoped
refinements (the A4 `synthetic_tree` demotion and the minimal `AssembleInput`
shape). This doc refined — did not supersede — [`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md)
§3.4 / §3.7 (T1–T3) / §5.1 (X3).

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
| --- | --- | --- |
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

**Why this is safe and consistent.** Two independent properties make the
pre-selection depth and the assembled depth equal:

1. *Same height, stable count.* Depth at a *fixed historical* `reference_height`
   is invariant under forward ingest: a block at height `h > reference_height`
   only creates outputs whose maturity is `≥ h + 10 > reference_height`, so they
   never drain into the tree as-of `reference_height`. The count `n` changes only
   on a rollback *below* `reference_height` — which invalidates the reference
   itself (the proof would be re-anchored, CT-5d).
2. *Same function of `n`.* The pre-selection depth is `layer_count_for_leaves(n)`
   and the assembled depth is `build_layers(<the n leaves>).len()`; both are the
   same deterministic function of `n` (Q1), pinned equal by the
   `layer_count_for_leaves` drift KAT.

Therefore the two depths are **provably equal whenever the reference is valid**;
the fold (step 6) asserts equality as a defense-in-depth tautology
(DoS-never-theft: a mismatch means the tree moved under a reference it should not
have, so refuse — never sign).

This finding is **new scope** beyond the umbrella doc's T1/T2/T3 and is the
reason a combined root+depth read (Q1) is introduced rather than reusing the
bare `root_at`.

---

## 4. Resolved design forks (locked 2026-06-17)

### Q1 — how to obtain the real depth: **combined root+depth read**

Add a `RootAndDepthAt { height } -> (root: [u8;32], depth: u8)` actor message and
a `CurveTreeHandle::reference_root_and_depth` method; `build`'s reference-binding
uses it in place of the bare `root_at` await — one snapshot, one round-trip, both
values pinned to the same `reference_height`.

**Why read exact depth at all (the privacy reason, not the performance one).**
The un-enumerated alternative is *don't read depth*: over-estimate the fee with a
max-depth assumption, assemble, take the real depth from the path, accept a small
overpay. It is correctly avoidable — but the binding reason is **not** round-trips
or waste. Fee is **on-chain-visible**, and a systematically conservative fee is a
**non-canonical** fee: a wallet that pays above the canonical weight-derived
amount is fingerprintable as *this* wallet implementation. Exact depth → canonical
fee → privacy-aligned ([`00-mission`](../../.cursor/rules/00-mission.mdc) #2,
privacy is the product, dominates the performance argument). This rationale is
recorded so a future reader does not "optimize away" the read on a performance
ledger that misses the privacy cost.

**Source-verification result (Q1 pin — the framing in an earlier draft was
wrong).** An earlier draft claimed `root_at` materializes the full layer vector,
so `depth = layers.len()` is free and `root_at` could become a thin discard-wrapper
of a cached root. **Verified false at source:**

- `CurveTreeClient::root_at` ([`client.rs:709`](../../rust/shekyl-curve-tree/src/client.rs))
  is the **store hot path** — `self.store.root_at_count(n)`, which composes frozen
  per-segment roots `R_k` with a freshly-built tail
  ([`mixed_composition_root`](../../rust/shekyl-curve-tree/src/store/redb_backend.rs#L636)).
  It does **not** build the whole tree's layer vector.
- `assemble_path` ([`assemble.rs:85,99`](../../rust/shekyl-curve-tree/src/assemble.rs))
  *does* build layers (`build_layers(assemble_leaf_stream(..))`) for branch
  extraction, and takes `depth = layers.len()` from that — but the root it gates
  on still comes from the store `root_at` hot path, not from the rebuilt layers.

So depth is free from **neither** path. The correct framing:

- **Depth is a pure function of the leaf count `n`** (it depends only on how many
  times `n` reduces through the fixed `chunk_width` ladder, never on leaf values).
- The combined read computes **`n` exactly once** —
  `n = drained_leaf_count_at(drained_through(height))`, already the input to
  `root_at_count` — and derives **both** the root (`root_at_count(n)`) and the
  depth from that same `n`. **The single source of truth is `n`, not a shared
  layer build.** Two reads keyed on one `n` cannot disagree about which tree state
  they describe.
- Depth derivation gets a new pure function `layer_count_for_leaves(n) -> u8` in
  `shekyl_fcmp::tree`, **next to `build_layers` and reusing the same `chunk_width`
  primitive**, pinned by a KAT asserting
  `layer_count_for_leaves(n) == build_layers(<n leaves>).len()` across a range of
  `n`. That KAT is the drift guard — it is exactly the off-by-one risk that
  rejected the ad-hoc `ceil(log_width(n))` formula, now closed by pinning the
  derivation to `build_layers` in one place rather than re-deriving widths.

**Single-reconstruction pin (Q1).** `RootAt` and `RootAndDepthAt` must both sit on
the *one* `root_at_count(n)` reconstruction — `RootAndDepthAt` returns
`root_at_count(n)` paired with `layer_count_for_leaves(n)`, while `RootAt` returns
`root_at_count(n)` alone (depth dropped). The
existing `root_at` is **unchanged** (the CT-5a oracle KAT that consumes `RootAt`
is untouched), and neither message recomputes the root by an independent route. So
the two messages share the root reconstruction (`root_at_count`) and the depth
function is single-sourced in `shekyl_fcmp` — no parallel-formula drift on either
value.

*Rejected:* a separate `DepthAt` message (two round-trips, two reads at one
height); the max-depth over-estimate (non-canonical fee, above); a cheap
`ceil(log_width(n))` depth re-derived inline (the drift risk the
`layer_count_for_leaves` + KAT closes by construction).

### Q2 — where the batch lives: **actor-handler loop**

No client-side batch method. The actor message
`AssembleTx { reference: ReferenceBlock, inputs: Vec<AssembleInput> } -> Result<Vec<AssembledPath>, ClientError>`
loops `assemble_path` per input **inside one handler invocation**. kameo
processes messages serially, so no `IngestBlock` / `RollbackToFork` can interleave
mid-assembly — the E1 read-atomicity hazard is structurally unrepresentable (the
handler is the snapshot), with no new client API surface.

**The tradeoff, named explicitly** (the thing a reviewer will ask about): the loop
**blocks the actor for the whole assembly duration** — up to `MAX_INPUTS`
iterations, each a `build_layers` over the in-memory entries vec — so no ingest
makes progress while a tx assembles. That is acceptable here: wallet ingest is not
latency-critical, and `MAX_INPUTS` bounds the stall to a small constant. Trading
"ingest progress during assembly" for **free atomicity** is the right call under
privacy/correctness > performance.

*Un-enumerated alternative — per-input dispatch with a snapshot-epoch token.* Each
`AssembleInput` would carry the tree generation it was selected against; the actor
rejects the call on a generation change, letting `IngestBlock` interleave between
inputs. This is the design to reach for *if* ingest-progress-during-assembly
mattered. It does not (above), and it trades the structural atomicity for a
runtime check — so the handler-loop dominates. Recorded so the reversion has its
story if ingest latency ever becomes load-bearing.

**Bound at the actor boundary, not only engine-side (Q2 refinement).** The
`MAX_INPUTS` bound (from `shekyl-tx-builder` / `shekyl-fcmp` — note the umbrella
doc's `FCMP_MAX_INPUTS_PER_TX` is an approximate name; the real constant is
`MAX_INPUTS`) is checked engine-side before dispatch **and re-checked in the
`AssembleTx` handler**, rejecting `inputs.len() > MAX_INPUTS` before the loop. If
the engine check were the only guard, a future caller or a bug could dispatch an
over-length `AssembleTx` and spin the handler unbounded — a DoS-on-self that
stalls the actor. The bad state is made unrepresentable at the actor boundary, not
merely upstream of it.

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
gindex }` and refuses to build (DoS-never-theft, mirroring `OutputNotDrained`).
The `(O, C)` content-match is deleted as the *resolution* mechanism on the
owned-output path, but retained as a *verification* of the gindex resolution.

**What this check actually guards (the real finding under Q3).** Calling it
"defense-in-depth against store corruption" undersells it. Gindex totality rests
on an inter-component invariant: the curve tree's `next_output_seq` numbering is
**identical** to the scanner's `global_output_index` numbering. **No single
component owns that invariant** — the tree assigns gindex in consensus drain
order, the scanner assigns `global_output_index` independently, and CT-5c makes
them the resolution key. The `(O, C)` hard-check is its **only runtime guard**.
The classic way the two numberings silently diverge is a **new output class
entering the tree and shifting the count** — coinbase already forced exactly this
alignment (X5); bond-post / archival outputs are the next candidates. So the check
is load-bearing against a foreseeable future change, not just against disk rot.

**Two records that follow from this:**

- **Strengthen the X3 KAT beyond "resolves to the correct `gindex`."** Add a
  *numbering-equivalence-across-output-classes* case: a block mixing coinbase,
  regular, and (when it lands) bond-post outputs, asserting tree `gindex` ==
  scanner `global_output_index` for **each**. The "no collision case to test"
  framing (X3 §5.1) is true for *collisions* but skips the invariant that is
  actually load-bearing — the cross-component numbering equivalence.
- **Reopening trigger ([`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
  style).** *Any new output class that enters the curve tree must re-verify
  `global_output_index ↔ tree gindex` equivalence before merge.* This is recorded
  as a standing precondition (and added to `FOLLOWUPS.md` at slice close) precisely
  because it is the "same until someone adds a class" gap that bites later.

**Honesty boundary — do not over-credit the check.** Both the lookup key
(`gindex`) and the check value (`identity`) come from the **same**
`TransferDetails`. So the check catches a **tree ↔ scanner desync** (the two
numberings disagree), but it does **not** catch a `TransferDetails` that is
internally consistent yet wrong versus the actual chain (e.g. a scanner that
mis-recorded both `gindex` and `(O, C)` together). That failure is out of this
check's reach and belongs to scan-correctness, not assembly.

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
2. **depth primitive + client + actor read API** — add
   `shekyl_fcmp::tree::layer_count_for_leaves(n) -> u8` (reusing `chunk_width`)
   with its drift KAT (`== build_layers(<n>).len()` over a range of `n`, Q1);
   `CurveTreeClient::root_and_depth_at` (shares `root_at_count(n)`; `root_at`
   unchanged); actor messages `RootAndDepthAt` and `AssembleTx` (handler-side
   `MAX_INPUTS` bound, Q2) + `CurveTreeHandle::reference_root_and_depth` /
   `assemble_tx`. *Adds the reads, no consumer yet — `assert_send` structural test
   as in CT-5a/b.*
3. **engine cutover** — split `build` (§3.1); thread real fee depth;
   `assemble_tx_to_sign` consumes `&[AssembledPath]` (T1/T2); delete the
   `sign_bridge` synthetic clobber (§1); **delete `synthetic_tree.rs`**.
4. **test migration + DoD + doc closure** — migrate synthetic-dependent engine
   tests to the real client over the CT-2 fixture / `TestDaemon`; add the X3 KAT
   **including the numbering-equivalence-across-output-classes case (Q3)** and the
   real-root build+submit KAT; add the `global_output_index ↔ tree gindex`
   reopening trigger to `FOLLOWUPS.md` (Q3); record this round's closure (the §3.2
   fee-depth finding + the Q1–Q3 resolutions, including the corrected
   depth-derivation framing) into `CT5_ENGINE_WIRING.md` and mark this doc closed.

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
  — there is no collision case to test, per X3 §5.1), **plus** the
  numbering-equivalence-across-output-classes case (Q3): a block mixing output
  classes asserts tree `gindex` == scanner `global_output_index` for each.
- **`layer_count_for_leaves` drift KAT:** `layer_count_for_leaves(n) ==
  build_layers(<n leaves>).len()` across a range of `n` (Q1) — the single-source
  guard that lets the fee path read depth without building the tree.
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

---

## 10. Closure notes (what implementation surfaced)

- **Latent FCMP++ layer-parity bug (found + fixed).** `shekyl-tx-builder`'s
  `validate_inputs` expected the first branch above the leaf to be C1 (Selene);
  the real curve tree and the prover (`prover/mod.rs`: "curve_2_layers is
  populated before curve_1_layers") are **C2 (Helios)-first**, so the correct
  split is `c2 = ceil(B/2)`, `c1 = floor(B/2)`. The pre-cutover synthetic
  generator (`enrich_input_tree`) shared the *same* inversion, so the validator
  and the fixtures agreed with each other while both disagreed with the real
  tree — a wrong-layout proof the daemon would reject, invisible until the real
  `assemble_path` produced a genuine path. Fixed in `validate.rs`, the synthetic
  generator, and the tx-builder KATs. This is the class of bug the cutover
  exists to surface (synthetic self-consistency hiding a real-path defect).

- **PF7 unblock → measured fee table.** The §3.2 fee-depth finding deepened: the
  proof-size measurement harness ran on the synthetic path, whose single-chunk
  root is only a consistent FCMP++ witness at depth 1 (`AcProveError(InconsistentWitness)`
  above it — the documented PF7 block). Resolved by `consistent_synthetic_path`:
  a **single-path** synthetic tree (one node per layer, hashed upward) that is a
  valid witness at any depth without an astronomically large tree, with per-layer
  padding identical to a full tree. With PF7, the `[n_in][depth]` grid is
  measurable; `fcmp_proof_size` is now a measured lookup table (non-monotonic in
  depth — a closed-form increment is impossible). Cross-validated two ways: the
  depth-1 column equals the prior measured row, and the depth-2 `(n_in=1)` cell
  matches the real-tree proof in `build_then_submit_marks_outputs_spent`.

- **A4 reversion clause fired (`synthetic_tree` retained, test-only).** R1-Q5 /
  §1 expected `synthetic_tree` deletable ("no non-daemon test surface needs
  synthetic vectors"). Two do — the tx-weight KAT and the `local_keys` signing
  KATs need depth-controlled fixtures a real tree can't cheaply provide. So per
  the A4 clause the module is **retained `#[cfg(test)]`** (production grep-clean),
  not deleted. DoD adjusted: "no *production* synthetic references."

- **`AssembleInput` is minimal, not a full `OutputIdentity` (§5 Q3 refinement).**
  Resolution uses only `gindex` and the check only `(output_key, commitment)`, so
  a full `OutputIdentity` would force the engine to fabricate `h_pqc`/`target` it
  does not hold for an owned output (the real `h_pqc` returns *from* the drained
  leaf). `AssembleInput { gindex, output_key, commitment }` carries exactly what
  is used (rule 18).

- **Reopening trigger (rule-21, Q3).** Any new output class that enters the curve
  tree must re-verify `global_output_index ↔ tree gindex` numbering equivalence
  before merge — the `(O, C)` post-resolution check is the only runtime guard of
  that unowned inter-component invariant. Recorded in `FOLLOWUPS.md`.

- **Test migration (§7).** Success-path engine tests moved to a consistent
  ledger+tree fixture (`funded_ledger_and_tree` / `funded_pending_tx*`): the
  tree's leaves *are* the ledger's owned outputs, so the real `assemble_path`
  resolves them. A new `build_without_curve_tree_is_refused` pins the
  no-synthetic-fallback behavior.
