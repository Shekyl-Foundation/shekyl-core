# Curve-tree client (design — Round 0)

**Status:** design, Round 0. Named prerequisite extracted from
`PHASE_2A_SEND_PATH.md` §3.0.4. This is its own phase; 2A does not implement it.

**Why it exists.** FCMP++ membership proofs require the wallet to assemble the
curve-tree branch path (`leaf_chunk` + `c1_layers` + `c2_layers`) for the output
it spends, **locally**, never querying the daemon for a specific output's path
(spend-revealing — `PHASE_2A_SEND_PATH.md` §3.0.1, binding). This component is
what produces a verified, locally-computed `{leaf_chunk, c1_layers, c2_layers,
TreeContext}` for the signer. It is the F1 prerequisite that ungates **real-root
mainnet validity** (DoD #1 / §3.0.5; mainnet still also gated on Phase 6).

**What it closes.** Two adversarial-pass findings parked on this phase:

- **#3** — `TransferDetails` field enumeration: what supplies the path lookup
  vs. the actor's secret derivation (now two distinct field sets, §4).
- **#5** — proof validity horizon + reference-block selection (§5).

**Binding inputs (already decided upstream — do not re-litigate here):**

- `PHASE_2A_SEND_PATH.md` §3.0.1 — no per-output path query, ever (privacy >
  security > features).
- §3.0.2 — daemon serves bulk/contiguous data; wallet assembles locally.
- §3.0.3 — the one RPC addition is **bulk leaves**, not a path endpoint.
- §3.0.6 — path data is **public** owned `Vec<[u8; 32]>`; the only spend-path
  secrets stay engine-side (`spend_key_x/y`, source-secret scratch).
- C1 (§3.7.5) — **one** `TreeContext` per tx (tx-level, never per-input); the
  reference block is selected **once** and threaded immutably.

---

## 1. Scope and definition of done

### In scope

1. A wallet-local **leaf store** anchored at a known checkpoint, persistent
   across runs, with reorg rollback at the wallet tier.
2. **Delta sync** of contiguous leaf ranges via the bulk RPC (§6), never a
   per-output query.
3. **Local layer recomputation** via `shekyl-fcmp::tree` primitives.
4. **Root verification** of the locally-computed root against the consensus
   anchor (block-header `curve_tree_root` at the reference height — §3.3).
5. **Reference-block selection** (§5) — the single tx-level anchor.
6. **Path extraction** — the wallet's own output's `{leaf_chunk, c1_layers,
   c2_layers, TreeContext}`, located by **local content match** (§4.3), not a
   stored tree position and not a query.
7. The **interface** 2A's signer codes against (§3.5).

### Out of scope

- Signing, proof construction, encoding (2A: `shekyl-tx-builder` / §4 wire
  adapter).
- The daemon-side bulk-leaf RPC **implementation** (C++ PR; this doc specifies
  its contract + KAT for `SHEKYLD_PREREQUISITES.md`).
- Secret derivation (engine-side `KeyActor`; this client is **public-data
  only** and holds **no secrets** — §4.2).

### DoD

- Given an owned output (identity) and a synced leaf store, the client returns a
  `{leaf_chunk, c1_layers, c2_layers, TreeContext}` whose root **equals** the
  reference block's header `curve_tree_root`, with `c1_layers.len() +
  c2_layers.len() + 1 == tree_depth` (the C3 invariant the actor re-checks,
  §3.7.6 of 2A).
- A reconstruct-root KAT (matches a fixed checkpoint root over a known leaf set)
  passes — this is the same KAT that gates the bulk RPC (§6).

---

## 2. Substrate (verified)

Daemon-side (C++ LMDB + JSON-RPC) **already landed**:

- `curve_tree_leaves` — all UTXO leaves preserved, `global_output_index →
  128-byte {O.x, I.x, C.x, h_pqc}` (`LMDB_SCHEMA.md` §`curve_tree_leaves`).
- `curve_tree_checkpoints` — `root[32] || depth[1] || leaf_count[8]` every
  `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL = 10000` blocks
  (`db_lmdb.cpp` `save_curve_tree_checkpoint`).
- `prune_curve_tree_intermediate_layers` — intermediate layers are
  **recomputable** and pruned; leaves preserved. This is exactly why
  "serve leaves, recompute layers wallet-side" is sound.
- RPCs: `get_curve_tree_checkpoint(height) → {root, depth, leaf_count, height}`,
  `get_curve_tree_info() → {root, depth, leaf_count, height}`. **Missing:** the
  bulk-leaf range RPC (§6).
- **Per-block** `curve_tree_root` in every block header (verified on connect) —
  the verification anchor for arbitrary reference heights.

Rust-side primitives **already exist** (`shekyl-fcmp::tree`):

- `construct_leaf(O, C, h_pqc) -> Option<[u8; 128]>`.
- `hash_grow_selene` / `hash_grow_helios`, `hash_trim_*`.
- `selene_point_to_helios_scalar` / `helios_point_to_selene_scalar`,
  `ed25519_point_to_selene_scalar`.
- `chunk_width(layer)`, `layer_is_selene(layer)`, `proof_size(n_in, depth)`,
  `SELENE_CHUNK_WIDTH` / `HELIOS_CHUNK_WIDTH` / `SCALARS_PER_LEAF`.

**Gap:** no Rust path-assembler (`get_curve_tree_path`-shape) exists; layer walk
+ sibling extraction into `c1_layers`/`c2_layers` is the new work.

The two **age** constants (distinct — do not conflate, §5.4):

| Constant | Value | Role |
|----------|-------|------|
| `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (`SPENDABLE_AGE`) | 10 | Output **maturity** — block_height+10 = `eligible_height`, when the leaf enters the tree |
| `FCMP_REFERENCE_BLOCK_MIN_AGE` | 5 | Reorg margin — the tx reference block must be ≥ this deep |
| `FCMP_REFERENCE_BLOCK_MAX_AGE` | 100 | Stale reference block rejected at verify |

---

## 3. Architecture

### 3.1 New crate: `shekyl-curve-tree` (proposed)

A dedicated crate is justified (`15-deletion-and-debt.mdc` — not ceremony): it
carries persistent state (leaf store), a sync/reorg state machine, and parses
**untrusted daemon input** (`20-rust-vs-cpp-policy.mdc` → Rust). It is a distinct
concern from signing (`shekyl-tx-builder`) and scanning (`shekyl-scanner`).
Reuses `shekyl-fcmp::tree` for crypto.

**Holds no secrets** (§4.2) — so no `ZeroizeOnDrop` surface; all state is public
chain data. This is an explicit invariant with a structural test (mirrors 2A's
C5 boundary assertion).

The `LeafStore` is **segment-addressable** by design: its segment unit is also the
archival shard and the visual unit, so this same store is the V3.x archival
substrate (§7). Designing it segment-aware now is what keeps the archival
`ArchivalEngine` additive rather than a restructure.

### 3.2 Components

```text
shekyl-curve-tree
├── recon      block-derived leaf reconstruction: S1 index, leaf-skip predicate,
│              tx_extra 0x07 parse (reuse shekyl-scanner Extra), S2 drain
│              (maturity, gindex) → ordered leaf stream (CT2_DRAIN_ORDER.md §7)
├── store      LeafStore: segment-addressable leaves + anchors (§7.2 unit)
├── sync       source-agnostic segment fetch; reorg rollback; root verify
├── assemble   layer recompute (shekyl-fcmp::tree build_layers) → path extraction
└── client     public API (§3.5): select ref block, assemble path
```

`recon` is the block-derived default's heart (`CT2_DRAIN_ORDER.md`): it replays
the C++ drain ordering bit-exactly. Its leaf-skip predicate (target-variant ∧
`i < outPk.size()` ∧ `construct_leaf`-ok) and `tx_extra` `0x07` parser are both
**resolved at source** ahead of CT-2 (CT2 §2.2, §3.1) so they don't churn
mid-build; coinbase is trivially include-all (`outPk` populated), which is what
keeps the Tier-A coinbase tree non-empty.

**Implementation status** (module-level milestones per the crate's module
docstrings; *distinct* from the §9 work-phase `CT-N` sequencing labels, which
this note does not renumber). `recon` is **landed and KAT-verified** by the
CT-2 reconstruct-root KAT (`tests/recon_kat.rs`). The `client` orchestration
is **landed**: `CurveTreeClient` ingests blocks reduced at the caller's
decode boundary (`BlockLeaves`/`TxLeafInputs`/`RawOutput`, carrying the
scanner-`Extra`-parsed `0x07` blob), resolves `h_pqc`, threads the global
output index (derive-don't-accumulate; reorg = rebuild via `from_blocks`),
owns the reference-height → drain-cutoff mapping (`drained_through = H − 1`),
and applies the §3.3 integrity gate (`verify_root`). The Tier-A KAT now also
runs end-to-end through this production path. `assemble` (membership-path
extraction) is **landed** (CT-4). `store` (frozen-`R_k` cache and persistence,
CT-1) Round 1 closed on `redb` per [`CT1_ROUND1_PINS.md`](./CT1_ROUND1_PINS.md) and
[`CT1_ROUND1_CLOSEOUT.md`](./CT1_ROUND1_CLOSEOUT.md).

### 3.3 Integrity model (load-bearing)

A lying or partial daemon **cannot forge a tree**, only deny service:

- The client recomputes the root from leaves and **verifies it equals the
  reference block's header `curve_tree_root`** (per-block consensus commitment).
  A daemon that serves wrong/withheld leaves produces a root mismatch → the
  client rejects and refuses to build (loud failure, not a silent bad proof).
- Withholding leaves / serving a short range is a **liveness** attack
  (DoS), not an integrity attack — the missing-leaf case fails the root check or
  the content-match (§4.3) cleanly.
- Checkpoints are **sync accelerators** (skip ahead, verify root once), not the
  trust anchor — the per-block header root is the anchor, so arbitrary reference
  heights (not just checkpoint multiples) are verifiable.

### 3.4 Reorg handling

Leaf positions are **append-only by drain order**; a reorg below the synced tip
can change which leaves exist. But tree leaves only change on reorgs deeper than
`SPENDABLE_AGE = 10` (shallower reorgs reshuffle only undrained
`pending_tree_leaves`), and a deep reorg touches only the most-recently-drained
positions — the **active frontier segment** (§7.2.1 #4). So completed
subtree-aligned segments are **reorg-frozen**, and the rollback unit is the active
frontier segment, not "up to the last 10k checkpoint." The store tracks
`(height, leaf_count, R_k)` per segment, rolls back only the frontier on
divergence, and re-syncs forward. **Freeze-lag:** a segment is not frozen/pruned
until buried beyond max plausible reorg depth in **block** terms:

```text
tip_height − segment.end_block_height ≥ SPENDABLE_AGE + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS
```

(`SEGMENT_FREEZE_REORG_MARGIN_BLOCKS = 720`, same numeric value as
`ARCHIVAL_REORG_DEPTH_BLOCKS`; height-gated, not position-gated — see
[`CT1_ROUND1_PINS.md`](./CT1_ROUND1_PINS.md).) `frozen_segments` records
`end_block_height` (when the segment's newest leaf entered the tree) and
`frozen_at_height` (when the freeze was applied). The active frontier stays
unpruned and absorbs reorg churn; freezing lags the tip. The reference block at
`tip − REF_ANCHOR_AGE` (§5) is within this unfrozen frontier by construction; a
reorg deeper than the margin forces ref-block re-selection (§5.3).

**Reorg strategy (coverage attribution).** The wallet `LeafStore` reorgs by
**truncate-the-leaf-array + rebuild the surviving prefix** via `build_layers` — it
carries no stateful frontier and never calls the incremental `hash_trim` primitive
(§7.7 pin). The *daemon* maintains the consensus tree incrementally and `hash_trim`
*is* its reorg primitive. Both paths are tested, so the question is attribution,
not coverage: `freeze_under_prefix_rebuild` exercises the **wallet's** actual code;
the Tier-2 `chunk_replace_*` / `undeepen_*` / `reorg_*` tests (§7.7) exercise the
**daemon's** incremental path.

### 3.5 Public API (the contract 2A codes against)

```rust
/// Public chain data only — no secrets, no ZeroizeOnDrop. Owned by this
/// crate (F2): the secret-bearing `shekyl_tx_builder::SpendInput` is a
/// *different* struct, and the engine/2A signer maps `AssembledPath` →
/// `SpendInput` by adding secrets internally. The crate stays lean (no
/// `shekyl-tx-builder` dependency); the duplicated public `ChunkLeaf` /
/// `TreeContext` reverts to a shared low-level types crate only if the
/// duplication causes drift (`21-reversion-clause-discipline.mdc`).
pub struct AssembledPath {
    pub leaf_chunk:  Vec<ChunkLeaf>,     // the path leaf node's outputs, incl. target
    pub c1_layers:   Vec<Vec<[u8; 32]>>, // Selene-node chunks, x-coords, bottom→top
    pub c2_layers:   Vec<Vec<[u8; 32]>>, // Helios-node chunks, x-coords, bottom→top
    pub tree:        TreeContext,        // { reference_block, tree_root, tree_depth }
}

/// One output in the path's Selene leaf chunk. Mirrors the field names of
/// `shekyl_tx_builder::types::LeafEntry` so the engine adapter is trivial.
/// Carries compressed **points** (O, I, C), not x-coordinate scalars: the
/// FCMP++ prover's `Path.leaves` consumes the points (F1, F6).
pub struct ChunkLeaf {
    pub output_key:    [u8; 32],         // O (compressed)
    pub key_image_gen: [u8; 32],         // I = Hp(O) (compressed; derived in-crate)
    pub commitment:    [u8; 32],         // C (compressed)
    pub h_pqc:         [u8; 32],         // per-output PQC leaf hash
}

pub struct TreeContext {                 // mirrors shekyl_tx_builder::types::TreeContext
    pub reference_block: [u8; 32],       // reference block hash
    pub tree_root:       [u8; 32],       // header-committed curve_tree_root
    pub tree_depth:      u8,             // derived: build_layers(stream).len() (F4)
}

pub struct OutputIdentity {           // public; what the client matches on (§4.3)
    pub output_key:  [u8; 32],        // O (compressed) — primary match key
    pub commitment:  [u8; 32],        // C (compressed) — disambiguation
}

// Reference-block selection (§5) is NOT a CurveTreeClient method: the
// client stores no header roots, so selection is height arithmetic the
// caller drives against its own chain view (landed in `reference.rs`).
mod reference {
    /// Canonical reference height for a proof built at `tip`:
    /// `tip − REF_ANCHOR_AGE` (§5.1). `None` in the pre-maturity window.
    pub fn select_reference_height(tip: u64) -> Option<u64>;
    /// `tip_now − reference_height`; `None` if the ref is above the tip (reorg).
    pub fn reference_block_age(tip_now: u64, reference_height: u64) -> Option<u64>;
    /// In the daemon acceptance window `MIN_AGE ≤ age ≤ MAX_AGE` (§5.2).
    pub fn proof_submittable(tip_now: u64, reference_height: u64) -> bool;
    /// Aged past `MAX_AGE` (or ref above tip) — daemon rejects as too stale.
    pub fn proof_expired(tip_now: u64, reference_height: u64) -> bool;
    /// Reached `REBUILD_AT` (or ref above tip) — re-anchor proactively (§5.2).
    pub fn should_reanchor(tip_now: u64, reference_height: u64) -> bool;
}

impl CurveTreeClient {
    /// Assemble the path for one owned output at a chosen reference block.
    /// `c1_layers.len() + c2_layers.len() + 1 == tree.tree_depth` on success.
    pub fn assemble_path(
        &self,
        id: &OutputIdentity,
        reference: &ReferenceBlock,
    ) -> Result<AssembledPath, ClientError>;
}
```

`ReferenceBlock = { height, curve_tree_root }` (the implemented shape);
`tree_depth` is **derived** during assembly (`build_layers(stream).len()`, F4),
not carried on `ReferenceBlock`, and packed into `TreeContext`. The C3 invariant
`c1_layers.len() + c2_layers.len() + 1 == tree_depth` is then a self-check (the
leaf layer is the `+1`; the root layer is excluded — it is the prover's
`TreeRoot`). In 2A tests this contract is satisfied by **synthetic vectors**; in
production by this client. The C1 single-snapshot guarantee is preserved because
all inputs of one tx call `assemble_path` with the **same** `ReferenceBlock`.

**CT-4 design round (pinned at source).** The membership-path format is the
FCMP++ prover's `Path` (`shekyl-oxide/crypto/fcmps/src/prover/mod.rs`; canonical
builder `random_path`, `tests.rs`). With `C::C1 = Selene`, `C::C2 = Helios`,
`C::OC = Ed25519`: `c1_layers`/`c2_layers` are **scalars (node x-coordinates),
not points**, each layer the **full chunk including the path node** (siblings
not excluded), root layer excluded. The leaf chunk hashes to a **C1 (Selene)**
node; its x-coordinates feed a **C2 (Helios)** node; then C1, C2, … alternating.
So the **odd** tree layers (1, 3, …) are Helios → `c2_layers`, and the **even**
internal layers (2, 4, …) are Selene → `c1_layers`; the two vectors interleave
in tree-layer order (`c2_layers[0]`, `c1_layers[0]`, `c2_layers[1]`, …). The
implementation maps straight onto these field names (`c1_layers ≡
Path::curve_1_layers`, `c2_layers ≡ Path::curve_2_layers`), so the engine
adapter is a field copy. Extraction reuses the public `build_layers` (full layer
stack), `layer_is_selene` / `chunk_width`, and the
`selene_point_to_helios_scalar` / `helios_point_to_selene_scalar` conversions.
`leaf_chunk` needs the compressed `O`/`I`/`C` identities (F6), so the client
retains the per-drained-leaf `OutputIdentity` alongside the x-coord leaf and
derives the compressed `I = Hp(O)` via `shekyl_fcmp::tree::key_image_generator`
(a thin wrapper over the same `biased_hash_to_point` `construct_leaf` uses,
added so the lean crate need not depend on `shekyl-generators` directly).

### 3.6 `LeafStore` persistence — greenfield, not a migration

The "we're about to touch storage, do it in Rust" instinct does **not** apply
here as a migration, and it is worth setting down why:

- **The daemon LMDB stays through V3.x.** The only daemon-side C++ the CT work
  needs is the optional bulk-leaf accelerator (§6); under the block-derived
  default (§6) even that is optional. So CT/archival *shrinks* the daemon's new
  C++ surface, it doesn't grow it — touching one optional RPC is not leverage for
  a consensus-DB rewrite. An engine change for the daemon is a **V4,
  consensus-invisible** question; defer with confidence.
- **The wallet `LeafStore` is greenfield Rust.** It does not exist yet (new
  `shekyl-curve-tree` crate) and is Rust by default under the
  untrusted-input→Rust policy (`20-rust-vs-cpp-policy.mdc`). So "shift to heed"
  is not a migration question — it is *which Rust persistence for a new
  component*, decided on the wallet store's own merits.

The access pattern is unusually regular, and that drives the real first question:

- Dense integer positions → **fixed 128-byte records** (`{O.x, I.x, C.x, h_pqc}`),
  append-mostly forward, contiguous range reads for segment serving,
  delete-recent for reorg, delete-old-non-owned for prune-to-`R_k`.

"Leaf at position `p`" is literally offset `p·128` in a flat array — a
memory-mapped leaf file beats any B-tree lookup, and the sparse metadata (frozen
`R_k` per segment, the owned-position index, sync cursor, reorg checkpoints) is
small enough for a tiny sidecar store. So the honest first question is **flat
mmap'd leaf array + small metadata store vs a general KV engine for the whole
thing** — not heed-vs-LMDB. If a single KV engine is chosen for everything, then
**heed** (LMDB format/semantics, mmap zero-copy, single-writer fits the one sync
task) vs **redb** (pure-Rust, no C/FFI, `10-shekyl-first.mdc`-aligned, no
pre-sized map) is the real choice — but decided on this store, not as a referendum
on the daemon's engine.

**CT-1 outcome (locked):** **`redb`** — pure-Rust ACID transactional store for
the greenfield wallet `LeafStore`. Rationale: Shekyl-first (no LMDB FFI),
automatic file growth (no `map_size` correctness hazard), single write txn for
reorg atomicity. Valid transactional-store choice is ACID + oracle-validated
leaf encoding; **not** daemon `curve_tree_leaves` layout parity. heed is out of
scope for CT-1. Operational note: prune-to-`R_k` may leave elevated on-disk
footprint until pages are reused (cosmetic only). Reversion clause: reopen only
on measured hot-path regression vs flat-mmap **and** a flat-mmap + sidecar
design that preserves ACID reorg atomicity. See [`CT1_ROUND1_PINS.md`](./CT1_ROUND1_PINS.md).

---

## 4. #3 — Data-source field enumeration (two distinct field sets)

The adversarial finding: branch layers (`c1_layers`/`c2_layers`) and `leaf_chunk`
are **not** sourced from `TransferDetails` — the client computes them. What
`TransferDetails` supplies splits into two non-overlapping sets.

### 4.1 Set A — client path-lookup inputs (PUBLIC, identity only)

What the **client** (this crate) needs from the owned output to locate + assemble
its path. All public; the client holds nothing else.

| Need | `TransferDetails` field | Use |
|------|------------------------|-----|
| Locate the leaf | `key: EdwardsPoint` (O) | compress → `O.x`, **content-match** against the leaf range (§4.3) |
| Disambiguate | `commitment: Commitment` (C) | match `C.x` if two leaves share `O.x` (vanishingly rare) |
| Bound the search window | `block_height: u64` | the leaf was drained ~`block_height + SPENDABLE_AGE`; narrows which range to fetch (optimization, not correctness) |
| Spendability gate | `eligible_height: u64` | reject if `eligible_height > reference_height` (§4.4) |

`h_pqc` is **read from the matched leaf** (it is in the public 128-byte tuple);
the client does **not** derive it. So Set A is `{O, C, block_height,
eligible_height}` — pure public identity/position metadata.

**Block-derived path — `h_pqc` is an additional public input.** Under the
bulk-leaf RPC path the daemon hands the client finished 128-byte leaves, so
`h_pqc` arrives inside the tuple as above. Under the **block-derived** default
(`CT2_DRAIN_ORDER.md`; the wallet reconstructs leaves from blocks it already
syncs), the client *builds* the leaf itself and therefore needs `h_pqc` as an
input. `h_pqc` is **not derivable from the bare public output** — it is the hash
of the *hybrid public key*, carried **on-chain in a single `tx_extra` `0x07`
field** (`tx_extra_pqc_leaf_hashes`: one concatenated blob, `32` bytes per
output in vout order), sliced per-output at `i*32` with a **zero-fallback** when
the field is absent, the blob length is not a multiple of 32, or the blob is
shorter than the vout count (`CT2_DRAIN_ORDER.md` §3, `blockchain_db.cpp:341-364`).
It is fully public (already on the chain), so it **joins Set A** for the
block-derived path — but as a *parsed `tx_extra` input*, not a `TransferDetails`
field and not a secret. **Parser ownership is resolved: reuse
`shekyl_scanner::extra::Extra`** (it already decodes `0x07` →
`PqcLeafHashes`, `extra.rs:40,60,226`); the leaf builder layers the daemon's
`extract_leaf_hashes` validation on top — no new parser
(`CT2_DRAIN_ORDER.md` §3.1). The leaf itself is then built by the shared
`construct_leaf` FFI primitive (`CT2_DRAIN_ORDER.md` §3.2), identical to the
daemon. (Bulk-leaf path unaffected.)

### 4.2 Set B — actor secret-derivation inputs (SECRET, engine-side; NOT this crate)

What the **`KeyActor`** needs to derive spend secrets and reconstruct the leaf
for proving. **Listed for boundary clarity only — this crate never touches
them.** Sourced via the `output_handle` (per 2A F2/C4):

| Need | Source | Note |
|------|--------|------|
| `spend_key_x`, `spend_key_y` | derived in-actor from `output_handle` → `SourceSecretsBundle` | engine-only secret |
| `output_index` (for PQC key) | recovered with `combined_ss` from the **same** handle (2A §3.9 C) | co-located to avoid desync |
| commitment mask / amount | engine-recovered (2A §3.7.2) | off-message |

**Boundary invariant (structural test):** `OutputIdentity` and `AssembledPath`
carry only Set-A / public-layer data; no `output_handle`, no `Scalar`, no mask.
The curve-tree client and the `KeyActor` meet only at the **public**
`AssembledPath`. This is the §3.0.6 pin made enforceable here.

**Landed (Round-1 grep-driven enumeration).** Audited the derivation surface at
`rust/shekyl-engine-core/src/engine/traits/key.rs`. The complete engine-side
secret set is:

- `SourceSecretsBundle` (engine-internal; post-M3b never crosses the trait
  boundary): `spend_key_x`, `spend_key_y`, `commitment_mask`, `combined_ss` —
  all `Zeroizing` — plus `output_index` (the lone non-secret).
- `OutputClaim` reply (`ZeroizeOnDrop`): `amount_atomic_units` (secret),
  `handle` (`OutputHandle`, opaque + privacy-linkable), `key_image`
  (privacy-linkable / public after spend).
- Stack-frame-only intermediates inside `try_claim_output` / `sign_transaction`
  (per the trait's "no secret material crosses the boundary" docstring): the
  X25519 raw shared secret, the 64-byte hybrid shared secret, HKDF intermediate
  keying material, the per-output secret-key derivative, and the amount-blinding
  factor.

**Result — no leak.** Set A = `{O, C, block_height, eligible_height}` is sourced
entirely from `TransferDetails` public identity/position fields; it is **disjoint**
from the secret set above. The only claim-time → spend-time carrier is the opaque
`OutputHandle`, and it routes to `TxInputSigningContext.handle` (the `KeyActor`),
**never** to the curve-tree client. The client therefore cannot hold, and is not
on a path to, any Set-B field. (The enumeration is the audit evidence; the split
above is the design.)

### 4.3 Locating the leaf without a query or a stored position — the key move

`TransferDetails` stores `global_output_index` but **not** `tree_position`
(the daemon maps via `output_to_leaf`). Rather than persist a position or query
for it (spend-revealing), the client **content-matches**: it scans the
downloaded contiguous leaf array for the tuple whose first 32 bytes equal the
output's `O.x` (disambiguating on `C.x`). The match index *is* the tree position
(`start_index + offset`), and the matched 128-byte tuple yields the full leaf
(incl. `h_pqc`) directly — no reconstruction, no stored field, no query.

This is the privacy property restated structurally: **the wallet learns its
position by reading bulk public data it already downloaded, never by asking.**
It also means `TransferDetails` needs **no new persisted tree-position field**
(closes the §3 substrate gap without a schema change).

### 4.4 Spendability-at-reference gate (C2, corrected)

A leaf is in the tree at the reference block iff its insertion (drain) height
≤ `reference_height`. Enforced at three sites (2A C2):

1. **Selection** (coin-select, off this crate): don't pick outputs with
   `eligible_height > reference_height`.
2. **Assembly** (this crate): if the content-match (§4.3) finds no leaf at/below
   the reference range, return `LeafNotYetInTree { eligible_height,
   reference_height, wait_blocks }` — **not** an opaque miss.
3. **Actor** (off this crate): the C3 precondition re-checks shape before
   proving.

---

## 5. #5 — Proof validity horizon + reference-block selection

**Status: landed** in `rust/shekyl-curve-tree/src/reference.rs` as total,
side-effect-free arithmetic over heights (`select_reference_height`,
`reference_block_age`, `proof_submittable`, `proof_expired`,
`should_reanchor`) plus the constants `REF_ANCHOR_AGE` (6),
`PROOF_VALIDITY_HORIZON` (94 — the proof stays submittable through
`tip_build + 94` inclusive, where the age is exactly `MAX_AGE`), and
`REBUILD_AT` (50).
`REFERENCE_BLOCK_{MIN,MAX}_AGE` are emitted from
`config/consensus_constants.json` by the crate's `build.rs` (same JSON
authority as the C++ header), with const-eval sentinels guarding the
5/100 baseline. The functions are **not** methods on
[`CurveTreeClient`]: the client stores no header roots, so selection is
height arithmetic the caller drives against its own chain view, and
binding a height to a consensus root stays the caller's responsibility
(the caller-supplies-root integrity model, §3.5).

### 5.1 Reference-block selection (canonical convention)

**Rule:** `reference_height = tip − REF_ANCHOR_AGE`, with
`REF_ANCHOR_AGE = FCMP_REFERENCE_BLOCK_MIN_AGE + 1 = 6`.

- Matches the daemon's existing `get_curve_tree_path` anchor
  (`top_height − (MIN_AGE + 1)`), so wallet-assembled and daemon-assembled paths
  agree on the anchor.
- Reorg-safe: ≥ `MIN_AGE` deep, so the reference block is unlikely to be
  reorged out (and §5.3 handles the residual).
- Maximizes the submit window (§5.2): closest legal block to the tip.

**Why canonical, not free choice (privacy).** The reference-block age is
observable on every tx (the verifier sees `reference_height`). If wallets chose
different offsets, the offset would **fingerprint the wallet** — the same
uniformity logic as dust `K_DUST` and the `enc_label` slot
(`PHASE_2A_SEND_PATH.md` §3.8.5, §3.10.2). So every honest wallet computes the
**identical** offset. This **cannot** be consensus-enforced (the daemon accepts
any `reference_height ∈ [tip−MAX_AGE, tip−MIN_AGE]`); the strongest available
form is canonical convention — the ceiling privacy sets, not a gap to close.

**Reversion clause:** `REF_ANCHOR_AGE` is re-derived only if the observed reorg
depth distribution shows depth-6 reference blocks reorging at a non-negligible
rate (substrate change), or if `FCMP_REFERENCE_BLOCK_MIN_AGE` changes (consensus
event). Not a per-wallet knob.

### 5.2 Proof validity horizon (the proactive bound)

A built proof is submittable while its reference block satisfies
`tip_now − reference_height ≤ FCMP_REFERENCE_BLOCK_MAX_AGE (100)` (inclusive).
Built at `tip_build` with `reference_height = tip_build − 6`, the reference
age is `6 + N` after `N` blocks, so the proof stays submittable **through**
`tip_build + 94` inclusive (age exactly `MAX_AGE`) and is rejected as too
stale only at `tip_build + 95` (age `101`):

```text
horizon = MAX_AGE − REF_ANCHOR_AGE = 100 − 6 = 94 blocks
```

≈ 94 × target-block-time of submittable lifetime. This is the proactive bound
§9 #5 of 2A left "unbounded in Round 0."

**Proactive rebuild rule:** if a built-but-unconfirmed tx reaches a **rebuild
threshold** of `REBUILD_AT = MAX_AGE / 2 = 50` blocks of reference-block age, the
wallet **re-anchors** (re-selects the reference block at the current tip,
re-assembles paths, re-proves) rather than risk a `MAX_AGE` rejection mid-flight.
The half-`MAX_AGE` margin leaves room for propagation + a confirmation attempt.
`REBUILD_AT` is a **local wallet-hygiene** parameter (not consensus, not
privacy-observable — it only changes *when* a wallet rebuilds, not the
on-wire reference age), so unlike `REF_ANCHOR_AGE` it is tunable without a
uniformity cost; pinned with a documented default.

This complements 2A §3.6's **reactive** `ProofStale` signal: reactive catches
a root that went stale unexpectedly; the horizon is the proactive bound that
keeps the wallet from building doomed proofs.

### 5.3 Reference-block reorg

If a reorg drops the chain below `reference_height`, the reference block may no
longer be canonical. The client detects this (the store's `(height, root)` no
longer matches the daemon/header), rolls back (§3.4), and **re-selects** the
reference block at the new tip. Any in-flight unsubmitted proof anchored to the
orphaned block is invalidated and rebuilt. The `MIN_AGE = 5` margin makes this
rare; it is handled, not assumed away.

### 5.4 Terminology correction surfaced for `PHASE_2A_SEND_PATH.md`

2A's C2 (spendability gate, §3.7.5) originally wrote the bound as
`eligible_height ≤ tip − MIN_AGE`, using "`MIN_AGE`" loosely. There are **two**
ages (§2):

- `SPENDABLE_AGE = 10` governs **tree insertion** (`eligible_height =
  block_height + 10`).
- `REF_ANCHOR_AGE = MIN_AGE + 1 = 6` governs **reference-block depth**.

The correct C2 bound is `eligible_height ≤ reference_height` where
`reference_height = tip − REF_ANCHOR_AGE` (§5.1), **not** `tip − SPENDABLE_AGE`.
Numerically `tip − 6`, not `tip − 10`.

**Landed (Round-1 cross-edit).** 2A now references `reference_height` /
`REF_ANCHOR_AGE` at all four C2-gate sites — the §3.7.1 snapshot-locality note,
the §3.7.5 gate prose (with the explicit "two ages must not be conflated"
caveat), the error table, and the §9 C2 summary — so the two ages no longer read
as one. The gate lives in §3.7.5 (C2); §3.7.6 is C3 (actor path precondition).

---

## 6. Bulk-leaf RPC prerequisite (`SHEKYLD_PREREQUISITES.md`)

The one daemon addition (`PHASE_2A_SEND_PATH.md` §3.0.3), specified here:

```text
get_curve_tree_leaves { start_index: u64, count: u64 }
  -> { leaves: [128B …],           // contiguous tree-position order
       start_index, reference_block, curve_tree_root,
       reference_height, leaf_count }
```

- **Non-revealing because contiguous/bulk** — the daemon cannot tell which leaf
  in the range is a spend (same property as block-sync). `count` is capped
  (DoS); a maximal client fetches the whole tree, an incremental client fetches
  checkpoint + delta.
- **Not** `get_curve_tree_path`; takes a position **range**, never per-output
  spend indices.
- **KAT:** reconstructing the root over the returned leaf set (via
  `shekyl-fcmp::tree`) equals the `curve_tree_root` for `reference_height`
  (against the checkpoint root, and against the block header root). This KAT is
  the §1 DoD gate and lives with the prerequisite.
- **C++ PR**, separate from this Rust client. Per `10-shekyl-first.mdc` the
  client design (Rust, shekyl-core) is primary; the daemon endpoint is the
  lower-priority enabling change.

**Block-derived alternative (still open):** the wallet already scans every block
and could derive leaves itself (zero new RPC), at the cost of replicating the
consensus drain ordering (`pending_tree_leaves` → drain → `tree_pos`). Rejected
as the default (§3.0.3) because that ordering is consensus-sensitive; reopened if
this phase finds the replication cheap and well-tested (strictly more private).

---

## 7. Archival-staking alignment (storage / retrieval unification)

**The archival concept docs are inputs, not constraints.** `V3_STAKER_ARCHIVAL.md`
and `V3_SHARD_VISUALIZATION.md` were written before this planning; per the design
owner they **adapt to the best structure here**, not the reverse. This section
makes the curve-tree client's storage/retrieval the canonical structure and says
how archival layers onto it. Where a concept-doc detail conflicts (e.g. a
per-output `assemble_tree_path_for_output` RPC, §7.5), this design governs and the
concept doc is adapted.

### 7.1 The two needs are one data plane

- **CT client (consumer):** assembling a private path needs the leaves from
  genesis up to the reference height — the tree is cumulative, and the sibling
  hashes along any one path collectively cover the whole leaf set (§3, §4.3). So
  path assembly is inherently a **whole-history-leaf** operation — exactly the
  archival problem `V3_STAKER_ARCHIVAL.md` §"Problem 2" names.
- **ArchivalEngine (provider):** stakers hold partitioned leaf ranges (shards —
  shaped per §7.2) and serve them.

Same bytes, two roles. Design consequence: **one segmented leaf store, not two.**

### 7.2 The segment is a subtree-aligned position range (frozen sub-root `R_k`)

The boundary is **pure tree-position, aligned to a subtree (tree-level)
boundary** — *not* height-epoch. The choice is load-bearing, not stylistic: a
position-aligned segment has a **frozen, reusable sub-root**; a height-aligned one
does not, and five mechanisms below depend on that one difference existing.

- **Range:** leaves at tree positions `[k·E, (k+1)·E)`, where `E` is a
  **subtree-level leaf count** — a product of the alternating Selene/Helios chunk
  widths, i.e. exactly one tree-level node. (See §7.2.2 for deriving `E`.)
- **Frozen sub-root `R_k`.** A curve tree built by append (`hash_grow`) has the
  Merkle-mountain-range property: once a left subtree is full its hash is final —
  deepening the tree adds a parent *above* it and never re-hashes a completed
  child. So a subtree-aligned segment `k` has a sub-root `R_k` that is **permanent
  the moment the segment completes** and never changes as the chain grows.
- **Contrast (the rejected fork):** a height-epoch segment is a *variable-length*
  position range (block windows hold variable output counts), so its boundaries
  cut across subtrees — it has **no single frozen sub-root**, and the only anchor
  available is the per-height whole-tree header root. That inherits a cross-shard
  dependency the position case eliminates.

This one unit is simultaneously the CT client's **sync/reorg/cache/prune** unit,
the ArchivalEngine's **shard**, and `shekyl-shard-visual`'s render input
(`shard_content_hash` = `R_k`; the concept's `(shard_id, shard_content_hash)`
cache key is already this). The concept's "~10,000-block shard" adapts to "the
subtree level nearest the target shard scale" (§7.2.2) — the same re-derivation
discipline applied to `K_DUST` (drew Bitcoin's concept, re-derived the constant).

#### 7.2.1 What the frozen `R_k` buys, mechanism by mechanism

1. **Challenge-response becomes shard-self-contained.** The archival concept's
   proof-of-storage challenge (`V3_STAKER_ARCHIVAL.md` §"challenge") is "produce
   the Merkle path for block `H`'s tree root proving output `O` is in range" —
   anchored to the **whole-tree** root at `H`, so a staker holding shard `k`
   cannot answer from shard `k` alone (it needs every *other* shard's sibling
   sub-roots to reach the whole-tree root). With `R_k` the challenge becomes
   "produce the path from a random position in shard `k` to `R_k`" — answerable
   from the shard's own bytes, no cross-shard context. This resolves the concept's
   own open "shard granularity" question and makes proof-of-storage **local**.
2. **Multi-source distribution becomes content-addressed.** Height-aligned
   segments have no per-segment integrity tag, so a malicious peer's wrong bytes
   are caught only *after* recomputing against a whole-tree root (expensive, and
   you don't learn which peer lied). `R_k` is a **content address**: request
   "segment `k` matching `R_k`," reject non-matching bytes **on receipt**,
   BitTorrent-style — `R_k` is the infohash the concept's gossip layer wants.
3. **The reward market gets a clean rarity signal.** Reward is inverse to
   replication count, so pay should track rarity, not size. Uniform-size
   (fixed-`E`-leaf) position segments make per-shard reward track replication
   cleanly and proof-of-storage cost uniform (fair per-shard burden).
   Height-aligned segments vary wildly in leaf count (a busy epoch dwarfs a quiet
   one), confounding size with rarity and breaking the balanced-portfolio model.
4. **Reorg and pruning share the boundary.** Tree leaves change only on reorgs
   deeper than `SPENDABLE_AGE = 10` (shallower reorgs reshuffle only undrained
   `pending_tree_leaves`), and deep reorgs touch only the most-recently-drained
   positions — the **active frontier segment**. So completed segments are
   **reorg-frozen**; the rollback unit is "the active frontier segment," not "up
   to a 10k-block checkpoint." The same boundary is the **prune** unit: once a
   segment freezes to `R_k`, a non-archiving wallet drops its non-owned leaves and
   keeps only `R_k` (§7.6).
5. **Pruned-but-assemblable.** Because `R_k` plus the wallet's owned chunks
   suffice to assemble owned-output paths, the frozen segment is exactly the line
   that lets a non-staker stay lean without losing assembly capability (§7.6).

#### 7.2.2 Deriving `E` (subtree level, not 10,000)

Pick the **tree level** whose leaf count (the running product of the alternating
chunk widths) lands nearest the target shard scale, rather than fixing `E` to a
block count. This keeps shards subtree-clean (every segment is one frozen node).
The concept's "~10k blocks" is the target the level approximates, not the
boundary itself.

**The levels are coarse — `~10k` is not hit exactly.** With the fork's real widths
(`SELENE_CHUNK_WIDTH = LAYER_ONE_LEN = 38`, `HELIOS_CHUNK_WIDTH = LAYER_TWO_LEN =
18`), the leaf counts per subtree level are: level 0 = **38** outputs, level 1 =
`38·18` = **684**, level 2 = `38·18·38` = **25,992**, level 3 ≈ 468k, … So
"nearest 10k leaves" is level 2 (≈26k, ~2.6× over) vs level 1 (684, ~15× under) —
there is no clean 10k level. The realized shard size is a genuine tradeoff (shard
count × per-shard storage × proof-of-storage cost), decided at CT-1 once the
mainnet leaf-growth rate sets the disk budget; the doc records that the boundary
is a subtree level, with level 2 the provisional choice pending that sizing.

#### 7.2.3 Position↔height is a presentation lookup

"Which dates does shard `k` cover," the visualization's block-range intuition, and
the concept's "block `H`" challenge phrasing all become position↔height
conversions via checkpoint `leaf_count`s — a presentation cost, not a correctness
one. The concept docs' height-framed language (challenge "block `H`," shard "block
ranges") is the specific text that adapts.

### 7.3 Source-agnostic retrieval; integrity makes untrusted sources safe

The §6 bulk-leaf fetch is the retrieval primitive, and the sync layer is
**source-agnostic**: a segment may come from the wallet's own daemon, a
foundation `--no-prune` floor node, or an **untrusted** staker peer. Safety does
not depend on trusting the source — and with the frozen `R_k` (§7.2) the check is
**content-addressed**: request "segment `k` matching `R_k`" (the per-block header
root chain still anchors `R_k` itself, §3.3), and reject non-matching bytes **on
receipt** rather than after a whole-tree recompute. A malicious staker can only
**deny service** (withhold/short a segment), never forge one, and the rejection is
cheap and per-peer attributable. So "multi-source archival" **falls out** of the
integrity model rather than needing a retrofit, and `R_k` is the infohash the
concept's BitTorrent-style gossip layer wants. The V3.0-surface requirement
`V3_STAKER_ARCHIVAL.md` §"V3 architectural requirements" (4)/(5) names ("query
historical state from a staker peer or a foundation node") is met by making the
**one** bulk primitive peer-pluggable — no separate multi-peer RPC pre-built.

### 7.4 Privacy gradient under multi-source (the property to protect)

Distributing the serving role multiplies the parties who can observe queries —
the metadata FCMP++ protects. The key correction over a naive reading: **a
steady-state minimal wallet is query-free too, not just a staker.** Once a wallet
has done one forward sync and cached the frozen sub-root **frontier** (one hash
per completed shard) plus its own owned-output chunks, it assembles owned paths
from local data — own chunks + cached siblings — with no query. Its ongoing fetch
is **forward segment sync** (sync-progress-based, output-independent → non-
revealing). The prune rule that preserves this: **prune non-owned leaves of frozen
segments; keep owned-output chunks forever.** With that rule, even a non-archiving
wallet never makes a spend-revealing fetch. Privacy ordering, best → worst:

1. **Archiver ≈ steady-state minimal wallet — query-free.** The archiver holds
   full segments and serves others at zero query cost; the minimal wallet, after
   one forward sync, assembles its own spends from {sub-root frontier, owned
   chunks, active frontier} with no query. Both are the FCMP++ analog of "run your
   own node," made structural — "if you stake, you archive" is then a
   bandwidth-and-altruism tier *on top of* a baseline where everyone is private,
   not the only private tier.
2. **Cold / long-offline non-forward catch-up (acceptable, over Tor).** Pulling a
   *specific old* segment you previously pruned leaks only "this peer fetched
   shard `k`" — never which leaf, never a per-output index (§4.3). This only
   arises if a wallet discarded a chunk it later needs; the prune rule above keeps
   it rare. Routed through the anonymizing infra `V3_STAKER_ARCHIVAL.md`
   §"Privacy" mandates; cover-traffic is the stronger later form.
3. **Per-output path query (forbidden, §3.0.1).** Reveals the exact spent leaf —
   forbidden on the private path, and *worse* under distributed archival (many
   untrusted stakers would see it).

The §3.0.1 "bulk, never per-output" decision is therefore **more** load-bearing
under archival, not less; this store/retrieval design preserves it by
construction (segment-granular fetch, content-match-local lookup).

### 7.5 `assemble_tree_path_for_output` reconciliation

`FCMP_PLUS_PLUS.md` §"layer loop" references `assemble_tree_path_for_output` as
"(test/RPC path assembly)," and `V3_STAKER_ARCHIVAL.md` §req(4) frames its routing
as a multi-source **RPC**. Under this design that name resolves to the
**wallet-local** assembly primitive — the CT client's `assemble_path` (§3.5) —
**not** a staker-served per-output RPC (forbidden, §3.0.1). Multi-source routing
applies to the **bulk leaf segment** fetch (§7.3); **assembly stays local**. The
concept's "`assemble_tree_path_for_output` RPC routing" adapts to "bulk-segment
routing + local assembly."

### 7.6 Storage unification: one store, three consumers; V3.0 surface, V3.x additive

It is **one schema, footprint varies** — *not* "same bytes." The store is
segment-addressable and shared across three consumers (minimal-wallet path
assembly, archiver serving, `shekyl-shard-visual` rendering), but they hold
different subsets — the visual consumer needs only `R_k` per shard, while the
storage consumers differ as follows:

- **Minimal wallet (non-staker):** holds `{sub-root frontier (one R_k per
  completed shard — small), owned-output chunks (kept forever), active frontier
  segment (unpruned)}`. That is the minimum to forward-sync and assemble its own
  spend paths. The prune boundary that lets it stay lean is exactly the **frozen
  segment** (§7.2.1 #4–5) — the strongest argument for position-alignment, since a
  height-aligned segment gives neither a clean frozen rollback unit nor a clean
  prune-to-`R_k` commitment.
- **Archiver (staker, V3.x additive):** holds **full** segment leaves for its
  pinned shard set; **serves** them (the §6 endpoint, now also outbound) and
  prices/challenges them (challenge answered from `R_k`, §7.2.1 #1). It adds
  segment **pin + serve + market** — *not* a new store or schema; it simply
  retains full leaves where the minimal wallet pruned to `R_k`. `is_active_staker`
  / `stake_tier` gate eligibility; the data plane and schema are unchanged.

This is the concrete answer to "how does archival affect storage/retrieval":
**it doesn't restructure the schema — the CT client's segmented, source-agnostic,
self-verifying store is already the archival substrate; the staker just keeps
more of it.** Building it position-aligned in V3.0 is what makes the V3.x archival
ship additive (matching the archival doc's own "no V3.0 refactor" requirement) —
satisfied by this store design rather than by pre-building unspecified RPC
boundaries.

**Adaptations the concept docs should take (proposed; applied when those docs are
next revised, not silently here):**

- `V3_STAKER_ARCHIVAL.md`: shard ≡ CT `LeafStore` **subtree-aligned position
  segment** (not a block-range), keyed by frozen `R_k`; "query historical state" =
  source-agnostic **bulk-segment** fetch, not per-output;
  `assemble_tree_path_for_output` is **local** (§7.5); the challenge re-anchors
  from "Merkle path for **block H**'s whole-tree root" to "path from a random
  position in shard `k` to **`R_k`**" (§7.2.1 #1) — shard-self-contained,
  prover-held, no wallet-exposed query surface and no cross-shard context. The
  "~10k-block shard" → "subtree level nearest 10k leaves" (§7.2.2); all "block H /
  block range" phrasing becomes a position↔height lookup (§7.2.3).
- `V3_SHARD_VISUALIZATION.md`: `shard_content_hash` = `R_k`; the
  `(shard_id, shard_content_hash)` cache key already matches (§7.2). Block-range
  intuition is a position↔height presentation lookup (§7.2.3) — no structural
  change beyond naming the segment as the shard.

### 7.7 CT-0 gate: G1 (value-invariance) vs G2 (extractability)

The CT-0 gate is **two invariants, not one**, with different blast radii. The doc
elsewhere frames it as "never re-hash completed nodes"; that conflates a hard gate
with a recoverable detail.

- **G1 — value-invariance (the real gate).** A completed subtree's root *value*
  is invariant under (a) appending leaves to its right and (b) trimming leaves to
  its right. This is the append-only/MMR property `R_k`-as-permanent-commitment
  rests on. The claim is about the **value**, not about whether any node is
  cached — we cache `R_k` ourselves. **If G1 fails, `R_k` evaporates and the
  boundary reopens to height-anchored.** This is the only collapse case.
- **G2 — extractability (recoverable if it fails).** Can the client obtain `R_k`,
  and is it the value the full tree commits to? Two paths: *capture-at-completion*
  (read the frontier node when segment `k`'s last leaf lands) or *standalone
  recompute* (build a fresh tree from segment `k`'s `E` leaves, read its root).
  Standalone recompute is correct iff the node hash is **context-free up to curve
  parity** — not domain-separated by absolute layer index. If neither path works,
  `R_k` still *exists* (G1 can hold while G2 is awkward); you add a small
  internal-node accessor to `shekyl-fcmp`. That is a CT-1 API line, **not** a
  boundary reopening.

**Strengthened prior from the real API (`rust/shekyl-fcmp/src/tree.rs`).** Reading
the fork (not a proxy) sharpens both:

- The Rust surface is **white-box per-chunk**: `hash_grow_{selene,helios}` /
  `hash_trim_{selene,helios}` operate on **one chunk's** hash, with a **fixed**
  generator set (`SELENE_FCMP_GENERATORS` / `HELIOS_FCMP_GENERATORS`) and **no
  absolute layer index** — only an offset *within* the chunk. A node value is
  therefore `f(curve, children)`, context-free across layers and positions. The
  C++ LMDB layer owns whole-tree *structure*; Rust owns the per-chunk *hash*.
- **G1 is near-structural here.** The wallet's tree builder feeds a completed
  chunk's value *upward* (via `selene_point_to_helios_scalar` /
  `helios_point_to_selene_scalar`) as a child of the next layer and **never
  re-passes it to `hash_grow`/`hash_trim`**. A completed chunk is, by API shape,
  untouched by right-side growth or trim. The spike still *proves* this against
  the real upstream `fcmps::tree::hash_grow/hash_trim` rather than asserting it.
- **G2 largely collapses into CT-2.** Because the API is white-box and
  layer-index-free, *standalone recompute is the wallet's normal mode* — the
  "accessor" G2 worried about already exists (it is the builder, Appendix A
  `build_layers`). The only residual G2 risk is that the **Rust-composed root
  differs from the C++ consensus header root** (e.g. C++ salts by layer where Rust
  does not). That is exactly **CT-2's reconstruct-root KAT against a real header
  root** (§3.3) — *not* a CT-0 blocker. CT-0 therefore owns **G1**; CT-2 owns the
  Rust↔consensus agreement.

**Decision tree out of CT-0:**

1. **G1 fails** → reopen to height-anchored (the only true collapse; §7.2 fallback).
2. **G1 passes, standalone-recompute mismatches an internal node** → add a
   `shekyl-fcmp` internal-node accessor as a CT-1 dependency; no architecture
   change.
3. **G1 passes, recompute matches** → §7 stands; CT-1 schema unblocked; Rust↔C++
   agreement proven separately by CT-2's KAT.

The proptest/rand harness that settles G1 (and the within-Rust extractability
check) is **Appendix A**, written against the real symbols above and ready to drop
into `rust/shekyl-fcmp/tests/` as the CT-0 scratch artifact (a test, not
production — no `src/` change pre-gate).

**RESULT (CT-0 run, 2026-06): G1 PASSES — boundary is settled, no reopen.**
The harness landed at `rust/shekyl-fcmp/tests/curve_tree_freeze.rs` (12 tests,
lint-clean) and compiled against the real fork unmodified.

**Pinned assembly strategy (this is what the harness encodes).** The **wallet**
assembles segments by *batch composition* (`build_layers`) and reorgs by
*truncate-the-leaf-array + rebuild the surviving prefix*. It carries no stateful
frontier and never calls the incremental `hash_grow`(prev/offset/old/new) or
`hash_trim` primitives. A wallet is not the daemon: it is not perf-bound at
consensus scale, and prefix-rebuild is simpler than stateful rollback — freeze
(G1) guarantees the buried `R_k` survive a right-side truncation, so prefix-rebuild
*is* freeze-under-grow restricted to a shorter input. The incremental
`hash_grow`/`hash_trim` primitives are the **daemon's** path. Two consequences:

1. **`build_layers` is promoted into `shekyl-fcmp::tree`** (no longer a test-local
   fn) as the *single canonical* composition. The wallet's segment assembler, the
   CT-0 gate, and CT-2's reconstruct-root KAT all call this one function rather
   than reimplementing it.

   **This is canonical-composition + agreement-tested, NOT a type-level lock — do
   not bank false structural confidence.** Single-composition cannot be enforced
   by the type system here: the per-chunk primitives (`hash_grow_*`, `hash_trim_*`)
   must stay `pub` because the daemon's incremental path needs them over FFI, so a
   future maintainer *can* compose them into a second path and nothing in the types
   prevents it. What actually prevents silent divergence is (a) `build_layers`
   existing as the obvious canonical `pub` function so no one reaches for a
   hand-roll, and (b) the cross-impl agreement tests (`incremental_grow_equals_batch`,
   the Tier-2 trim/replace tests, CT-2's KAT) catching divergence between the two
   paths that exist. The limit, stated honestly: a *third* composition is not
   caught by the agreement tests (they compare only the two known paths) — it is
   caught by review, or not at all. Per "code is law, not docs," the guarantee is
   the test suite; the doc-comment is a signpost.

   **Scope limit — single-composition holds for from-leaves consumers only.** The
   wallet's steady-state hot path is rebuild-from-cached-`R_k` (hash frozen
   sub-roots up the *upper* layers), which reuses only the upper half of
   `build_layers`'s loop. Calling `build_layers(all_leaves)` per root is O(whole
   tree) — untenable at mainnet scale. Until that upper half is factored into a
   shared `build_upper_layers(layer_j_nodes) → root` the wallet calls directly, the
   wallet must re-implement the upper walk and the two-impls hazard reopens *above*
   the leaf layer. **`build_upper_layers` factor is a CT-1 item** (the assembler),
   not a CT-0 blocker — recorded in the §9 CT-1 row and §8 open questions.
2. **`freeze_under_trim_g1` is renamed `freeze_under_prefix_rebuild`** — it is the
   wallet's actual reorg path (truncate + rebuild), and deliberately does **not**
   exercise the `hash_trim` primitive. A reviewer must not read CT-0 as "trim is
   covered"; incremental trim is daemon-side and covered by the Tier-2 agreement
   tests + CT-2's KAT.

**Gate (batch composition — the wallet's path):**

- `freeze_under_grow_g1` (j=0, j=1; 16 trials each crossing ≥1 deepen) — completed
  `R_k` invariant under right-side append. ✓
- `freeze_at_exact_boundaries` — `R_0` invariant at the exact-boundary totals
  `{E, E+1, 2E, 2E+1, 3E}` (deepen off-by-ones live exactly here). ✓
- `freeze_under_prefix_rebuild` (j=0, j=1; 16 trials, prefix strictly inside the
  frontier) — buried `R_k` invariant under truncate-and-rebuild. ✓
- `extract_matches_in_tree` (looped: j=0 ×16, j=1 ×4) — standalone recompute of
  segment `k` byte-equals the in-tree node at `(layer j, index k)`; **decision-tree
  branch 2 does not fire** (index-free, fixed-generator API → no absolute-layer
  domain separation → no accessor). ✓
- `node_conversions_are_total` — over a size sweep spanning several deepen
  boundaries, every point↔scalar conversion the assembler relies on returns
  `Some` (the `expect`s in `build_layers` cannot fire on valid leaf sets — no
  tree-assembly liveness bug). ✓
- `frontier_changes_on_append` (negative sanity) — the partial rightmost chunk
  *does* change on append, so G1 is non-trivial. ✓
- `freeze_under_grow_g1_level2` (`#[ignore]`, ~25,992-output segment) — G1 holds
  at the layer-2 segment scale. Mechanism-complete coverage is `LEVELS = [0,1]`
  (both deepen types: Helios-over-Selene and Selene-over-Helios); level-2 is
  shard-size realism for CT-2's KAT, deliberately out of the fast gate. ✓

**Tier 2 (the daemon's incremental reorg primitive reproduces the canonical tree
under *replacement* — consensus-grade de-risking).** This is **higher-stakes than
CT-1 hygiene**: the daemon maintains the consensus curve tree in C++ and calls
these Rust primitives over FFI, so incremental `hash_trim` **is** the consensus
reorg primitive. If it ever produces a tree whose root diverges from a rebuild,
every membership proof anchored after that reorg is invalid — a consensus
catastrophe. So Tier 2 is worth landing on its own merits, co-located with the
freeze harness in `rust/shekyl-fcmp/tests/`. It is **complementary to, not
redundant with**, the wallet's path: the wallet's truncate-and-rebuild reorg is
gated by `freeze_under_prefix_rebuild`; Tier 2 owns the daemon's incremental path.

The load-bearing correction: **reorgs replace, they do not truncate.** A reorg
orphans `B_{k+1..tip}` and substitutes `B'_{k+1..tip'}`; orphaned leaves are
removed and new leaves are written at the same vacated positions with *different*
values. So the consensus-relevant chunk op is trim-to-offset-then-grow-different,
and the tree op is undeepen-and-reopen — not "remove the tip."

*Tier 2a — chunk-level algebra:*

- `incremental_grow_equals_batch_selene` / `..._helios` — appending children one
  at a time via the stateful grow signature equals the batch chunk hash. ✓
- `grow_update_equals_rebatch_selene` — the non-zero old-child (in-place update)
  path equals rebuilding the chunk with the new child. ✓
- `chunk_replace_equals_fresh_selene` / `..._helios` — **the actual reorg**: trim
  suffix `[fork..n)`, grow a *different* suffix at the vacated positions, assert
  byte-equal to a fresh build of `prefix ++ new_suffix` (32 trials, swept fork).
  The single-scalar-inverse and pure-truncation cases never reach this. ✓
- `chunk_trim_to_empty_and_multi_selene` — multi-element trim → prefix, and
  trim-all → `init` (the to-empty case undeepen needs at the chunk level). ✓
- `chunk_path_independence_selene` / `..._helios` — two different grow schedules
  to the same final children give the same hash, and the same subsequent trim
  agrees. Catches a primitive that carries grow-history into the trim result —
  exactly the bug class a stateful primitive can have and a rebuild cannot. ✓

*Tier 2b — tree-level undeepen (both collapse types) + compound + capstone, all
asserting the **full layer vector** against `build_layers`, not just the root:*

- `undeepen_helios_collapse_39_to_38` — 39→38 drops a **Helios** layer; root
  reverts to a Selene leaf node. ✓
- `undeepen_selene_collapse_685_to_684` — 685→684 drops a **Selene** layer
  (layer 2) over two Helios nodes; root reverts to a Helios node. Distinct curve
  at the dropped layer and at the resulting root — a separate code path. ✓
- `reorg_compound_45_to_35` — the realistic multi-block reorg: trims away the
  partial frontier chunk, undeepens (drops the Helios parent), **and** re-opens
  the first leaf chunk from full (38) to partial (35). `== build_layers(35)`. ✓
- `reorg_capstone_replace_at_boundary_39` — the nastiest case: grow to 39
  (deepened) → trim the 39th (undeepen to 38) → grow a *different* 39′
  (re-deepen), carrying the frozen `leaf0` untouched through the whole cycle;
  `== build_layers(base ++ 39′)`. A reorg landing exactly on a deepen boundary
  with different new content. ✓
- `empty_tree_is_a_ct2_boundary` — makes the empty disagreement executable
  (below). ✓

**What Tier 2 does NOT verify (folds into CT-2, not assumed here).** Tier 2b
asserts the undeepened tree against `build_layers`, which bakes in the **drop**
model: an emptied trailing chunk is a *removed node* (the layer drops it, and
when a layer reduces to one node the layer collapses), not an *init-valued node*
kept as a child. That is the standard curve-tree model and almost certainly the
daemon's, but it is a **C++ maintainer choice the Rust primitive does not fix** —
nothing here rules out a daemon that keeps an init-valued child (which would give
a *different* root). So Tier 2 proves the per-chunk primitives compose to
`build_layers` and that `build_layers`'s drop-model is self-consistent; it does
**not** prove `build_layers`'s drop-model equals consensus. That equality is a
**CT-2 reconstruct-root KAT obligation**.

The sharpest corner is the **empty / early-height** case, and the two notions of
"empty" disagree — **now resolved by reading the daemon** (see
`CT2_DRAIN_ORDER.md` §5):

- An emptied *chunk* equals the init point — the **real** `hash_trim` result
  (driven, not shimmed; see `chunk_trim_to_empty_and_multi_selene`).
- An empty *tree* is **not** `build_layers([]) == [[]]`. The daemon emits the
  **`selene_hash_init` point** for an empty tree — `get_curve_tree_root()`
  returns it on `MDB_NOTFOUND` and the genesis header is pre-set to it
  (`db_lmdb.cpp:5909-5921`, `cryptonote_tx_utils.cpp:821`). `build_layers([]) ==
  [[]]` is a zero-node structure that panics on `[j][0]` and **must never be
  indexed for a root**. The wallet special-cases `if leaf_count == 0 { root =
  selene_hash_init() }`.

The empty-tree window is heights **0..=60**, **not** `0..SPENDABLE_AGE` (0..9).
The genesis founder allocations are **coinbase** outputs (`RCTTypeNull`,
`unlock_time = 60`), so they mature at `+60`
(`CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`) — maturity height 60 — and a matured
leaf enters the tree on connection of the **next** block
(`drained_through = H − 1`), so the **first non-empty tree and first `R_0`
material is at height 61**, not height 10. (The CT-2 KAT pins this boundary
exactly — `recon_kat::empty_window_then_first_drain_at_61`; an earlier draft
said "height 60".) No regular tx can exist before height 61
(spending needs a non-empty tree for FCMP membership, which doesn't exist until
the founder coinbase first drains into the tree at 61), so the window is
**structural**, not
chain-content-dependent. The regular-output `+10` rule (`SPENDABLE_AGE`) is
unchanged and correct; the early-height empty window is specifically the
coinbase case. CT-2's KAT pins the empty-window **boundary** at
`last_empty=60` / `first_drain=61` (`recon_kat::empty_window_then_first_drain_at_61`)
against `selene_hash_init` and the live header — not interior heights that leave
the S2 off-by-one surface unasserted. The first non-empty root at height 61 is a **single leaf wrapped into the
layer-1 Helios node** — the Selene leaf layer is never itself the root (every
non-empty tree is depth ≥ 2; `CT2_DRAIN_ORDER.md` §5, `shekyl-fcmp::tree`).
`empty_tree_is_a_ct2_boundary` keeps the chunk-empty/tree-empty distinction
executable in the suite; its consensus resolution is now pinned in
`CT2_DRAIN_ORDER.md` §5.

Outcome is **branch 3**: §7 position-aligned segment boundary stands; CT-1 schema
is unblocked with no `shekyl-fcmp` accessor dependency. Under the batch pin there
is **no separate "Tier 3" wallet-incremental fuzz** — the wallet has no stateful
path to fuzz (its reorg is prefix-rebuild, already gated by
`freeze_under_prefix_rebuild`). The daemon's *full* incremental↔batch agreement
against the live C++ tree is owned end-to-end by **CT-2's reconstruct-root KAT**
(Rust `build_layers` root == C++ consensus header root); Tier 2 is the within-Rust
proof, against the real primitives, that the incremental path reproduces the
canonical tree under replacement at both deepen boundaries.

---

## 8. Round 0 open questions (for Round 1)

1. **Leaf-store persistence engine (§3.6).** Greenfield, not a migration:
   flat-mmap leaf array + small metadata sidecar (default lean) vs a single KV
   engine (heed vs redb). Decided at CT-1 on the store's own merits; mainnet leaf
   count × 128 B sets the disk/memory budget and the prune/window policy. Not a
   daemon-engine question and not a C++ rewrite.
2. **Match-cost at scale (§4.3).** Linear `O.x` scan over a multi-million-leaf
   range is the naive cost. Is an in-store `O.x → position` index (built locally
   from downloaded leaves, never queried) warranted? It is wallet-local so it
   leaks nothing; it is a perf/΅memory tradeoff, not a privacy one.
3. **`REBUILD_AT` default (§5.2).** `MAX_AGE/2 = 47` is a first cut; confirm
   against expected propagation + confirmation latency.
4. **Set-B enumeration (§4.2). CLOSED (2026-06).** Grep-driven audit at
   `key.rs` enumerated the full engine-side secret set (`SourceSecretsBundle`
   fields, `OutputClaim`'s `amount`/`handle`/`key_image`, plus the stack-frame
   X25519/HKDF/blinding intermediates); all are disjoint from Set A, and the sole
   claim→spend carrier (`OutputHandle`) routes to the `KeyActor`, not the client.
   No leak.
5. **Phase 2b cross-check.** Stake/unstake proofs share the reference-block
   horizon (§5); confirm `PHASE_2B_STAKE_LIFECYCLE.md` consumes the same client
   contract (§3.5) rather than re-deriving selection. **`CONFIDENTIAL_STAKING.md`
   is registered but off the Tier-A path** — the staked maturity class is the
   Tier-B KAT case (spend-dependent; `CT2_DRAIN_ORDER.md` §8.2), and the
   confidential redesign is 2b-adjacent. A proper adversarial pass on it belongs
   at the confidential redesign or when the Tier-B staked case is wired, **not at
   Round-1 readiness**.
6. **Block-derived leaves (§6). CLOSED (CT-3 Round 1, 2026-06-13).** The
   reversion criterion was met — CT-2 landed the replication as the
   production client path, KAT-verified against real headers — so
   block-derived forward sync is the confirmed default and the bulk-leaf RPC
   is repositioned to non-forward catch-up + archival, deferred with the
   prune-policy PR (R1-Q1). Disposition and the repositioned RPC role are in
   [`CT3_SYNC.md`](./CT3_SYNC.md) §3 R1-Q1; closeout in
   [`CT3_ROUND1_CLOSEOUT.md`](./CT3_ROUND1_CLOSEOUT.md) §4.
7. **GATE — G1 value-invariance (§7.7). CLOSED: G1 PASSES (CT-0 run, 2026-06).**
   *Decided: pure tree-position, subtree-aligned (§7.2), and now gate-confirmed.*
   The harness (`rust/shekyl-fcmp/tests/curve_tree_freeze.rs`) ran against the real
   fork: grow/trim invariance and within-Rust extractability all pass, including
   the layer-2 segment scale. Decision-tree **branch 3** — §7 stands, no
   `shekyl-fcmp` accessor needed, CT-1 schema unblocked. Reopening criterion
   remains G1 (would require a future `shekyl-fcmp::tree` change that moves a
   completed subtree's root value); none observed. The only residual is CT-2's
   Rust↔C++ reconstruct-root KAT (end-to-end G2).
8. **Derive `E` as a subtree level (§7.2.2).** Levels are coarse: 38 / 684 /
   25,992 / … leaves. No clean ~10k level — level 2 (≈26k) is provisional; confirm
   against mainnet leaf-growth and the shard-count × per-shard-storage tradeoff.
9. **Pin vs evict / prune policy (§7.6).** Minimal wallet prunes non-owned leaves
   of frozen segments to `R_k` but keeps owned-output chunks forever; staker pins
   full shards. The `LeafStore` API must expose both without a V3.x restructure —
   confirm the pin/prune seam is in CT-1's type design, not deferred.
10. **Freeze-lag depth (§3.4). CLOSED (CT-1 Round 1).** Margin is
    `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS = 720` (`ARCHIVAL_REORG_DEPTH_BLOCKS`,
    block counts). Gate is **height-based:**
    `tip_height − end_block_height ≥ SPENDABLE_AGE + 720`. Not position-based.
    Pinned in [`CT1_ROUND1_PINS.md`](./CT1_ROUND1_PINS.md).
11. **Anonymized segment fetch (§7.4).** Wire the source-agnostic fetch to the
    Tor/I2P routing layer so non-forward catch-up fetches inherit mandatory
    anonymization; confirm the seam against `ANONYMITY_NETWORKS.md` rather than
    bolting it on at V3.x.
12. **`build_upper_layers` factor (§7.7, CT-1).** Single-composition holds today
    only for from-leaves consumers. The wallet's steady-state hot path is
    from-cached-`R_k` (O(whole tree) per root if it calls `build_layers(all_leaves)`),
    so factor `build_upper_layers(layer_j_nodes) → root` out of `build_layers` and
    have the cached path call it directly — otherwise the two-impls hazard reopens
    above the leaf layer. On the CT-1 list (§9), not a CT-0 blocker.
13. **CT-2 is the block-derived correctness rock, not just a KAT (§7.7, §9 CT-2).
    Round-0 spike LANDED → [`CT2_DRAIN_ORDER.md`](./CT2_DRAIN_ORDER.md).**
    The privacy-maximal block-derived default commits the wallet to replicating
    the C++ drain ordering (`{maturity, global_output_index}`); that replication
    is where the wallet tree can silently diverge from consensus. CT-2's
    reconstruct-root KAT against real headers is the proof, and it absorbs the
    undeepen drop-model and the empty/early-height root (the genesis corner of the
    same "wallet composition == C++ consensus" question). The Round-0 enumeration
    pinned every divergence surface to source in `CT2_DRAIN_ORDER.md`: S1 (index
    assignment), S1-leaf (coinbase/`h_pqc` on-chain in `tx_extra 0x07`), S2 (drain
    trigger + `(maturity, gindex)` batch, all three maturity classes, empty-tree
    root = `selene_hash_init`), S3 (reorg, which **folds into S1/S2** for the
    wallet via derive-don't-accumulate — no journal replica). Two framing
    corrections landed (coinbase `+60`, empty-root resolution) and the torsion
    concern was **resolved as not-a-divergence-surface** (shared `construct_leaf`
    FFI; `Hp(O)` clears cofactor). The two Tier-A critical-path items are also
    **resolved at source** ahead of build (CT2 §2.2, §3.1): the **leaf-skip
    predicate** (coinbase include-all via `outPk` population) and **`tx_extra`
    `0x07` parser ownership** (reuse `shekyl_scanner::extra::Extra`). Round 1
    implements the replication with `build_layers` + the Tier-A fixture-chain KAT
    (header root = truth, RPC-cross-checked; assert at 5/59, not unverified h0).

---

## 9. PR decomposition (provisional)

| PR | Scope | Key files |
|----|-------|-----------|
| **CT-0** | **Gate spike — DONE, G1 PASSES.** 19-test harness (+1 `#[ignore]`) proved **G1** value-invariance + exact-boundary freeze + within-Rust extractability + conversion totality (batch path) **and** consensus-grade daemon-reorg de-risking (Tier 2: incremental `hash_grow`/`hash_trim` reproduce `build_layers` under *replacement* — chunk replace/to-empty/path-independence + tree undeepen at **both** collapse types (39→38 Helios, 685→684 Selene) + compound 45→35 + replace-at-boundary capstone, full-layer asserts) against the real fork; layer-2 scale included. Branch 3: §7 stands, no accessor, CT-1 unblocked. Pinned **batch/prefix-rebuild** wallet strategy; **promoted `build_layers` into `shekyl-fcmp::tree`** as the single composition; renamed trim test → `freeze_under_prefix_rebuild`. | `rust/shekyl-fcmp/tests/curve_tree_freeze.rs` (landed) + `rust/shekyl-fcmp/src/tree.rs` (`build_layers`) |
| **CT-1** | **Round 1 closed** — see [`CT1_ROUND1_CLOSEOUT.md`](CT1_ROUND1_CLOSEOUT.md). `LeafStore` on **redb** (`CT1_ROUND1_PINS.md`): subtree-aligned segment cache keyed by `R_k` (pin/prune seam, §7.6), height-gated freeze (`end_block_height`), canonical 4×32 Selene-scalar leaf encoding, `build_upper_layers` mixed-composition hot path + `upper_layers_kat`, ACID reorg truncate, `store_kat` Tier A. `CurveTreeClient` mirrors drained leaves into the store on ingest. Remaining: on-disk path wiring (CT-3/CT-5), full-segment freeze KAT at `j=2` scale. | `shekyl-curve-tree/store`, `tests/store_kat.rs`, `tests/upper_layers_kat.rs` |
| **CT-2** | **Round 1 closed** — see [`CT2_ROUND1_CLOSEOUT.md`](CT2_ROUND1_CLOSEOUT.md). Reconstruct-root KAT (`recon_kat.rs`) + production client path (`client.rs`) over `ct2_tier_a.json`: Rust root == C++ header root at every height on `main`, `reorg_deep`, `reorg_shallow`. Tier A pins empty-window boundary (`last_empty=60`, `first_drain=61`), coinbase `+60`, undeepen via `reorg_deep` (fork 140), freeze-lag via shallow reorg. Tier B `#[ignore]` scaffold in `recon_tier_b.rs`. CT-4 `assemble` and CT-1 `store` landed ahead of schedule. Remaining: CT-3 sync, CT-5 engine wiring. | `recon`, `client`, `assemble`, `tests/recon_kat.rs`, `tests/recon_tier_b.rs` |
| **CT-3** | **Round 1 closed** — see [`CT3_ROUND1_CLOSEOUT.md`](CT3_ROUND1_CLOSEOUT.md). Persistent client lifecycle landed across CT-3a (store schema, PR #128), CT-3b (`open(path)` + resume + delta ingest, `SCHEMA_VERSION` 2→3), CT-3c (`rollback_to_fork`, drain-cutoff partition, frozen-tail `R_k` recheck, PR #132). Block-derived forward sync is the confirmed default (R1-Q1 — the §6 reversion criterion fired: CT-2 landed the replication, KAT-verified); the bulk-leaf RPC (R1-Q1) and `SegmentSource` seam (R1-Q5) are deferred-with-recorded-shape, landing with the post-prune refetch path. Remaining: CT-5 engine wiring consumes the resume+ingest+rollback API. | `client`, `store`, `tests/recon_kat.rs` |
| **CT-4** | Reference-block selection + horizon/rebuild (§5); `select_reference_block` | `client` |
| **CT-5** | Wire into 2A signer behind the §3.5 contract (replaces synthetic vectors); 2A §3.7.6 terminology correction (§5.4) | `shekyl-engine-core`, `PHASE_2A_SEND_PATH.md` |
| **C++** | `get_curve_tree_leaves` endpoint + KAT (`SHEKYLD_PREREQUISITES.md`) | `core_rpc_server`, separate PR |

CT-0 is the gate (§8 #7): if **G1** fails (§7.7), the boundary choice reopens
before any schema lands; a G2-shaped finding does not. CT-1/CT-2 are then pure-Rust and
synthetic-testable (no daemon dependency), mirroring 2A's split: the
crypto/assembly lands and is KAT-gated before the daemon endpoint exists. The
V3.x `ArchivalEngine` (pin + serve + market, §7.6) is **out of CT scope** — but
CT-1's `LeafStore` API must not foreclose it (the pin/prune + outbound-serve seam
is the only forward requirement).

---

## 10. Review checklist

- [ ] §3.3 integrity model — root verified against per-block header
  `curve_tree_root` (not only checkpoints); lying daemon = DoS only.
- [ ] §4.1/§4.2 two field sets disjoint; client holds **no** secrets (structural
  test).
- [ ] §4.3 content-match locates position with no query and no stored
  tree-position field.
- [ ] §4.4 spendability-at-reference gate at all three sites; clean
  `LeafNotYetInTree` error.
- [ ] §5.1 `REF_ANCHOR_AGE = 6` canonical convention + reversion clause.
- [ ] §5.2 horizon = 94 blocks; `REBUILD_AT` proactive rule; complements 2A
  reactive `ProofStale`.
- [ ] §5.4 cross-edit `PHASE_2A_SEND_PATH.md` §3.7.6 (two ages, not one).
- [ ] §6 bulk RPC contract + reconstruct-root KAT in `SHEKYLD_PREREQUISITES.md`.
- [ ] §3.5 contract matches the synthetic vectors 2A already codes against.
- [x] **GATE** §7.7 G1 value-invariance confirmed by CT-0 (2026-06): G1 PASSES
  against the real fork (branch 3 — §7 stands, no accessor). Reopening criterion is
  G1 only (G2 → accessor / CT-2 KAT, not reopen); `E` derived as a subtree level
  (38/684/25,992), not a block count.
- [x] **Assembly strategy pinned (CT-0):** wallet = batch `build_layers` +
  truncate-and-rebuild reorg; daemon = incremental `hash_grow`/`hash_trim`.
  `build_layers` promoted into `shekyl-fcmp::tree` as the single composition (CT-1
  assembler / CT-2 KAT / production all call it). Tier-2 tests prove
  incremental↔batch agreement; CT-2 KAT owns it end-to-end (no separate Tier 3).
- [ ] §7.2 segment = subtree-aligned position range keyed by frozen `R_k`; shard =
  visual unit; position↔height is presentation lookup.
- [ ] §7.3 content-addressed fetch (`R_k` = infohash, reject on receipt);
  untrusted source = DoS-only.
- [ ] §7.4 corrected gradient: archiver ≈ steady-state minimal wallet (query-free)
  > non-forward catch-up (Tor) > per-output (forbidden); prune rule keeps owned
  chunks forever.
- [ ] §3.4/§7.2.1#4 rollback + prune unit = frozen segment; freeze lags tip by
  reorg margin.
- [ ] §7.6 one schema, footprint varies (minimal = frontier + owned chunks +
  active frontier; archiver = full segments).
- [ ] §7.5 `assemble_tree_path_for_output` is local assembly, not a staker RPC.
- [ ] §7.6 `LeafStore` segment-addressable so V3.x `ArchivalEngine` is additive;
  pin/evict seam present in CT-1.

---

## Appendix A. CT-0 harness (G1 + within-Rust extractability)

**LANDED and PASSING (2026-06). The authoritative artifact is the file
`rust/shekyl-fcmp/tests/curve_tree_freeze.rs` (19 tests + 1 `#[ignore]`,
lint-clean) — not the snapshot below.** It uses `rand` + `rand_chacha` (already
dev-deps); `proptest` is
**not** a workspace dep, so this is `rand`-driven and seeded for reproducibility
(add `proptest` only if input shrinking is wanted — a dependency-discipline
decision, not a requirement). The test run was the law (§7.7) and confirmed the
prior: G1 holds.

> **The fenced snapshot below is the pre-review draft and is SUPERSEDED.** The
> landed file differs in three ways pinned during CT-0 review (see §7.7 RESULT):
> (1) `build_layers` was **promoted into `shekyl-fcmp::tree`** and is imported, not
> defined locally; (2) `freeze_under_trim_g1` was **renamed
> `freeze_under_prefix_rebuild`** (it is truncate-and-rebuild, the wallet's reorg
> path — not the `hash_trim` primitive); (3) the file adds `freeze_at_exact_boundaries`,
> `node_conversions_are_total`, a looped `extract_matches_in_tree`, the `#[ignore]`
> level-2 test, and the **Tier-2** daemon-incremental↔batch *replacement* tests:
> chunk-level `incremental_grow_equals_batch_{selene,helios}`,
> `grow_update_equals_rebatch_selene`, `chunk_replace_equals_fresh_{selene,helios}`,
> `chunk_trim_to_empty_and_multi_selene`, `chunk_path_independence_{selene,helios}`,
> `empty_tree_is_a_ct2_boundary` (the chunk-empty == init / tree-empty == `[[]]`
> disagreement made executable; the empty/early-height root is now **resolved** to
> the daemon's `selene_hash_init` per `CT2_DRAIN_ORDER.md` §5, confirmed by the
> CT-2 KAT — never `build_layers([])`); tree-level
> `helios_root_shrinks_39_to_38_without_undeepening` (corrected from the former
> `undeepen_helios_collapse_39_to_38` once CT-2 proved the Selene leaf layer is
> never the root — 39→38 is a within-depth-2 Helios fan-in shrink, not a layer
> drop), `undeepen_selene_collapse_685_to_684`, `reorg_compound_45_to_35`,
> `reorg_capstone_replace_at_boundary_39` (full-layer asserts).
> Read the file for the current harness; the snapshot is retained only to show the
> minimal G1 core. Run the heavy level-2 case with
> `cargo test -p shekyl-fcmp --test curve_tree_freeze -- --ignored`.
>
> **Superseded by CT-2:** the snapshot's `while …len() > 1` stop returns the
> bare layer-0 Selene leaf node as the root for a single-chunk tree. CT-2's
> reconstruct-root KAT proved against a real header root that the daemon always
> wraps the leaf chunk into the layer-1 Helios node — the Selene leaf layer is
> never the root — so `shekyl-fcmp::tree::build_upper_layers` now stops at
> "single node at layer ≥ 1" and a non-empty tree is depth ≥ 2.

```rust
//! CT-0 gate: G1 value-invariance (frozen subtree) + within-Rust extractability.
//! G1 fail => boundary reopens to height-anchored (§7.2). G2 (Rust↔consensus
//! root agreement) is CT-2's reconstruct-root KAT, not this file (§7.7).

use ciphersuite::{group::ff::{Field, PrimeField}, Ciphersuite};
use helioselene::Selene;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use shekyl_fcmp::tree::{
    hash_grow_helios, hash_grow_selene, helios_hash_init, helios_point_to_selene_scalar,
    layer_is_selene, selene_hash_init, selene_point_to_helios_scalar, HELIOS_CHUNK_WIDTH,
    LEAF_CHUNK_SCALARS, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};

const ZERO: [u8; 32] = [0u8; 32];

fn seeded(s: u64) -> ChaCha20Rng { ChaCha20Rng::seed_from_u64(s) }

/// A random *valid* (canonical) Selene base-field element — leaf scalars must be.
fn rand_scalar(rng: &mut ChaCha20Rng) -> [u8; 32] {
    <Selene as Ciphersuite>::F::random(rng).to_repr()
}

/// `n_outputs` worth of leaf scalars (SCALARS_PER_LEAF each), flat.
fn rand_leaves(rng: &mut ChaCha20Rng, n_outputs: usize) -> Vec<[u8; 32]> {
    (0..n_outputs * SCALARS_PER_LEAF).map(|_| rand_scalar(rng)).collect()
}

/// Build every internal layer from a flat leaf-scalar stream using ONLY the
/// per-chunk primitives — the same composition CT-2's local assembler will use.
/// `layers[0]` = leaf-layer Selene nodes; alternating Helios/Selene above; the
/// final layer holds the single root.
fn build_layers(leaf_scalars: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let leaf_nodes: Vec<[u8; 32]> = leaf_scalars
        .chunks(LEAF_CHUNK_SCALARS)
        .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c).expect("leaf chunk"))
        .collect();
    let mut layers = vec![leaf_nodes];

    let mut layer_idx: u8 = 1;
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let next: Vec<[u8; 32]> = if layer_is_selene(layer_idx) {
            // even layer (Selene): children are x-coords of the Helios pts below
            let s: Vec<[u8; 32]> =
                prev.iter().map(|p| helios_point_to_selene_scalar(p).expect("h->s")).collect();
            s.chunks(SELENE_CHUNK_WIDTH)
                .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c).expect("selene node"))
                .collect()
        } else {
            // odd layer (Helios): children are x-coords of the Selene pts below
            let s: Vec<[u8; 32]> =
                prev.iter().map(|p| selene_point_to_helios_scalar(p).expect("s->h")).collect();
            s.chunks(HELIOS_CHUNK_WIDTH)
                .map(|c| hash_grow_helios(&helios_hash_init(), 0, &ZERO, c).expect("helios node"))
                .collect()
        };
        layers.push(next);
        layer_idx += 1;
    }
    layers
}

/// Outputs covered by one node at sub-root layer `j` (= segment size E).
/// Levels: j=0 -> 38, j=1 -> 684, j=2 -> 25_992 (real fork widths).
fn outputs_per_node(j: usize) -> usize {
    let mut e = SELENE_CHUNK_WIDTH; // chunk_width(0)
    for layer in 1..=j {
        e *= if layer_is_selene(layer as u8) { SELENE_CHUNK_WIDTH } else { HELIOS_CHUNK_WIDTH };
    }
    e
}

// Sub-root layers swept by the fast tests. Level 2 (≈26k outputs) is heavy;
// add a separate `#[ignore]` test for it if desired.
const LEVELS: [usize; 2] = [0, 1];

#[test]
fn freeze_under_grow_g1() {
    // G1(a): a completed subtree's value is invariant under right-side append.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        for trial in 0..16u64 {
            let mut rng = seeded(1_000 + (j as u64) * 100 + trial);
            let seg0 = rand_leaves(&mut rng, e);
            let small = build_layers(&seg0);
            let r0 = small[j][0]; // segment 0 alone: its root sits at layer j
            let extra = e + (rng.next_u32() as usize % (3 * e + 1)); // crosses deepen pts
            let mut big_scalars = seg0.clone();
            big_scalars.extend(rand_leaves(&mut rng, extra));
            let big = build_layers(&big_scalars);
            assert!(big.len() >= small.len(), "big tree must be ≥ as deep");
            assert_eq!(r0, big[j][0], "G1 grow: completed R_0 moved (j={j}, trial={trial})");
        }
    }
}

#[test]
fn freeze_under_trim_g1() {
    // G1(b): a buried subtree's value is invariant under right-side trim (reorg).
    // Trim modelled as rebuild-from-surviving-prefix; completed left segments are
    // never re-passed to hash_trim, so R_0 must be unchanged. (CT-1 additionally
    // proves the incremental hash_trim path == rebuild-from-prefix.)
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        for trial in 0..16u64 {
            let mut rng = seeded(2_000 + (j as u64) * 100 + trial);
            let l = 2 * e + (rng.next_u32() as usize % (2 * e + 1));
            let full = rand_leaves(&mut rng, l);
            let r0 = build_layers(&full)[j][0];
            // L' strictly inside the frontier: e < L' < l (segment 0 untouched).
            let lp = e + 1 + (rng.next_u32() as usize % (l - e - 1).max(1));
            let trimmed = build_layers(&full[..lp * SCALARS_PER_LEAF]);
            assert!(lp > e && lp < l);
            assert_eq!(r0, trimmed[j][0], "G1 trim: buried R_0 moved (j={j}, trial={trial})");
        }
    }
}

#[test]
fn extract_matches_in_tree() {
    // Within-Rust extractability: standalone recompute of segment k's E leaves ==
    // the internal node at (layer j, index k) of the full tree. Catches absolute-
    // layer domain separation, which the fixed-generator, index-free API lacks.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        let mut rng = seeded(3_000 + j as u64);
        let n = 3;
        let all = rand_leaves(&mut rng, n * e);
        let big = build_layers(&all);
        for k in 0..n {
            let seg = &all[k * e * SCALARS_PER_LEAF..(k + 1) * e * SCALARS_PER_LEAF];
            assert_eq!(
                build_layers(seg)[j][0], big[j][k],
                "extractability: standalone segment {k} root != in-tree node (j={j})"
            );
        }
    }
}

#[test]
fn frontier_changes_on_append() {
    // Negative sanity: the partial rightmost chunk DOES change on append — proves
    // G1 is non-trivial (not "everything is constant").
    let mut rng = seeded(4_000);
    let s = rand_leaves(&mut rng, 1); // 4 scalars, well under one full chunk (152)
    let a = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s[..3]).unwrap();
    let b = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s[..4]).unwrap();
    assert_ne!(a, b, "appending to a partial frontier chunk must change its hash");
}
```

**What each test settles (current landed file).** `freeze_under_grow_g1`,
`freeze_at_exact_boundaries`, and `freeze_under_prefix_rebuild` are **G1** — the
gate (append, exact-boundary, and the wallet's truncate-and-rebuild reorg).
`extract_matches_in_tree` (looped) is the within-Rust extractability / context-free
check (the API's fixed generators + no layer index predict it passes; if it failed,
add an accessor, not a reopen — it passed, so no accessor). `node_conversions_are_total`
rules out an assembler liveness bug in the point↔scalar `expect`s.
`frontier_changes_on_append` proves the frozen-subtree claim is non-trivial. The
**Tier-2** tests prove the daemon's incremental `hash_grow`/`hash_trim` agree
byte-for-byte with the wallet's batch `build_layers` (what `R_k` content-addressing
needs). End-to-end G2 (Rust-composed root == C++ consensus header root) is **CT-2's
reconstruct-root KAT against a real header**, not this harness.
