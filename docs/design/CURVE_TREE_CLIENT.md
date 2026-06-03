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
├── store      LeafStore: segment-addressable leaves + anchors (§7.2 unit)
├── sync       source-agnostic segment fetch; reorg rollback; root verify
├── assemble   layer recompute (shekyl-fcmp::tree) → path extraction
└── client     public API (§3.5): select ref block, assemble path
```

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
can change which leaves exist. The store tracks `(height, leaf_count, root)` and
rolls back to the last agreeing checkpoint/header on divergence, then re-syncs.
The reference block sits at `tip − REF_ANCHOR_AGE` (§5) so it is reorg-margin
protected; a reorg deeper than that forces ref-block re-selection (§5.3).

### 3.5 Public API (the contract 2A codes against)

```rust
/// Public chain data only — no secrets, no ZeroizeOnDrop.
pub struct AssembledPath {
    pub leaf_chunk:  Vec<[u8; 32]>,   // the output's Selene chunk peers
    pub c1_layers:   Vec<Vec<[u8; 32]>>, // Selene sibling hashes, bottom→top
    pub c2_layers:   Vec<Vec<[u8; 32]>>, // Helios sibling hashes, bottom→top
    pub tree:        TreeContext,     // { reference_block, tree_root, tree_depth }
}

pub struct OutputIdentity {           // public; what the client matches on (§4.3)
    pub output_key:  [u8; 32],        // O (compressed) — primary match key
    pub commitment:  [u8; 32],        // C (compressed) — disambiguation
}

impl CurveTreeClient {
    /// Select the single tx-level reference block (§5), once per tx.
    pub fn select_reference_block(&self) -> Result<ReferenceBlock, ClientError>;

    /// Assemble the path for one owned output at a chosen reference block.
    /// `c1_layers.len() + c2_layers.len() + 1 == tree.tree_depth` on success.
    pub fn assemble_path(
        &self,
        id: &OutputIdentity,
        reference: &ReferenceBlock,
    ) -> Result<AssembledPath, ClientError>;
}
```

`ReferenceBlock = { height, block_hash, tree_root, tree_depth, leaf_count }`. In
2A tests this contract is satisfied by **synthetic vectors**; in production by
this client. The C1 single-snapshot guarantee is preserved because all inputs of
one tx call `assemble_path` with the **same** `ReferenceBlock`.

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

**Round-1 task (grep-driven):** enumerate the exact engine-side fields feeding
Set B at the `key.rs` derivation site, to confirm none leak onto Set A. (The
enumeration is the audit evidence; the split above is the design.)

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
`tip_now − reference_height ≤ FCMP_REFERENCE_BLOCK_MAX_AGE (100)`. Built at
`tip_build` with `reference_height = tip_build − 6`, the proof **expires** after:

```text
horizon = MAX_AGE − REF_ANCHOR_AGE = 100 − 6 = 94 blocks
```

≈ 94 × target-block-time of submittable lifetime. This is the proactive bound
§9 #5 of 2A left "unbounded in Round 0."

**Proactive rebuild rule:** if a built-but-unconfirmed tx reaches a **rebuild
threshold** of `REBUILD_AT = MAX_AGE / 2 ≈ 47` blocks of reference-block age, the
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

2A §3.7.6 (C2) writes the spendability bound as `eligible_height ≤ tip − MIN_AGE`,
using "`MIN_AGE`" loosely. There are **two** ages (§2):

- `SPENDABLE_AGE = 10` governs **tree insertion** (`eligible_height =
  block_height + 10`).
- `REF_ANCHOR_AGE = MIN_AGE + 1 = 6` governs **reference-block depth**.

The correct C2 bound is `eligible_height ≤ reference_height` where
`reference_height = tip − REF_ANCHOR_AGE` (§4.4), **not** `tip − SPENDABLE_AGE`.
Numerically `tip − 6`, not `tip − 10`. **Action:** correct 2A §3.7.6 to reference
`reference_height` (and this doc's §5.1) rather than the bare "`MIN_AGE`" token,
so the two ages don't read as one. Tracked as a Round-1 cross-edit, not silently
changed here.

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
- **ArchivalEngine (provider):** stakers hold epoch-partitioned leaf ranges
  (shards) and serve them.

Same bytes, two roles. Design consequence: **one segmented leaf store, not two.**

### 7.2 The segment is the common unit (shard ≡ CT store segment ≡ visual unit)

Define the store's unit as an **epoch-aligned segment**:

- **Range:** leaves at tree positions `[leaf_count(H_start), leaf_count(H_end))`
  for an epoch `[H_start, H_end)` with `E = FCMP_CURVE_TREE_CHECKPOINT_INTERVAL
  (10,000)` blocks. Position-addressed store, height-addressed epoch — the
  checkpoint's `leaf_count` is the deterministic bridge (note the position≠height
  duality: leaves drain by maturity, not receipt height).
- **Contents:** the segment's 128-byte leaf tuples + the per-height
  `curve_tree_root`s spanning the epoch (verification anchors, §3.3) + the
  epoch-boundary checkpoint root.
- **Self-verifying:** recompute the segment's leaves into the running tree and
  check against the carried per-height roots; a bad segment fails loudly
  regardless of source.

This one unit is simultaneously the CT client's **sync/reorg/cache** unit, the
ArchivalEngine's **shard**, and `shekyl-shard-visual`'s render input (its
`shard_content_hash` = the segment content hash; the concept doc's visual cache
key `(shard_id, shard_content_hash)` is already the segment's). The archival
concept's "per-epoch ~10,000-block shard" is **adopted because** it aligns with
the checkpoint interval the store already uses — not as an independent pick.

### 7.3 Source-agnostic retrieval; integrity makes untrusted sources safe

The §6 bulk-leaf fetch is the retrieval primitive, and the sync layer is
**source-agnostic**: a segment may come from the wallet's own daemon, a
foundation `--no-prune` floor node, or an **untrusted** staker peer. Safety does
not depend on trusting the source — §3.3's root-against-header verification means
a malicious staker can only **deny service** (withhold/short a segment → fails
the content-match or root check), never forge a tree. So "multi-source archival"
**falls out** of the integrity model rather than needing a retrofit: the client
already verifies every segment against consensus. The V3.0-surface requirement
`V3_STAKER_ARCHIVAL.md` §"V3 architectural requirements" (4)/(5) names ("query
historical state from a staker peer or a foundation node") is met by making the
**one** bulk primitive peer-pluggable — no separate multi-peer RPC pre-built.

### 7.4 Privacy gradient under multi-source (the property to protect)

Distributing the serving role multiplies the parties who can observe queries —
the metadata FCMP++ protects. Privacy ordering, best → worst:

1. **Segment-holding wallet — no query at all (best).** A staking wallet's
   ArchivalEngine already holds segments locally; the CT client reads them with
   **zero** network exposure. "If you stake, you archive" makes a staker's own
   path assembly query-free — the FCMP++ analog of "run your own node," made
   structural.
2. **Bulk segment fetch over Tor/I2P (acceptable).** Leaks only "this peer
   fetched epoch E's segment" — never which leaf, never a per-output index
   (§4.3). Routed through the anonymizing infra `V3_STAKER_ARCHIVAL.md`
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

`LeafStore` (§3.1) is designed **segment-addressable** so the V3.x
`ArchivalEngine` is purely additive:

- **V3.0 (this client):** `LeafStore` holds segments for the wallet's own path
  assembly (full or a recent window); source-agnostic fetch; per-segment
  verification; reorg rollback by segment.
- **V3.x (`ArchivalEngine`, additive):** **pins** a chosen segment set (the
  staker's shards), **serves** them to peers (the §6 endpoint, now also
  outbound), and prices/challenges them. It adds segment **pin + serve + market**
  — *not* a new store; it reads/writes the same `LeafStore` segments. The
  `is_active_staker` / `stake_tier` cross-actor queries gate eligibility, but the
  data plane is unchanged.

This is the concrete answer to "how does archival affect storage/retrieval":
**it doesn't restructure them — the CT client's segmented, source-agnostic,
self-verifying leaf store is already the archival substrate.** Building it that
way in V3.0 is what makes the V3.x archival ship additive (matching the archival
doc's own "no V3.0 refactor" requirement) — satisfied by this store design rather
than by pre-building unspecified RPC boundaries.

**Adaptations the concept docs should take (proposed; applied when those docs are
next revised, not silently here):**

- `V3_STAKER_ARCHIVAL.md`: shard ≡ CT `LeafStore` segment; "query historical
  state" = source-agnostic **bulk-segment** fetch, not per-output;
  `assemble_tree_path_for_output` is **local** (§7.5); the challenge-response
  "produce the Merkle path for block H showing leaf X" is a **prover-held** proof
  the staker computes from its own segments, not a wallet-exposed query surface.
- `V3_SHARD_VISUALIZATION.md`: shard content hash = segment content hash; the
  `(shard_id, shard_content_hash)` cache key already matches (§7.2) — no change
  beyond naming the segment as the shard.

---

## 8. Round 0 open questions (for Round 1)

1. **Leaf-store persistence + size.** All-leaves vs checkpoint+window. Mainnet
   leaf count × 128 B sets the disk/memory budget; an incremental
   checkpoint-anchored window may be required. Decide the store's eviction
   policy and its reorg-rollback depth.
2. **Match-cost at scale (§4.3).** Linear `O.x` scan over a multi-million-leaf
   range is the naive cost. Is an in-store `O.x → position` index (built locally
   from downloaded leaves, never queried) warranted? It is wallet-local so it
   leaks nothing; it is a perf/΅memory tradeoff, not a privacy one.
3. **`REBUILD_AT` default (§5.2).** `MAX_AGE/2 = 47` is a first cut; confirm
   against expected propagation + confirmation latency.
4. **Set-B enumeration (§4.2).** Grep-driven confirmation at the `key.rs`
   derivation site that no secret field leaks onto Set A.
5. **Phase 2b cross-check.** Stake/unstake proofs share the reference-block
   horizon (§5); confirm `PHASE_2B_STAKE_LIFECYCLE.md` consumes the same client
   contract (§3.5) rather than re-deriving selection.
6. **Block-derived leaves (§6).** Re-evaluate the zero-RPC alternative once the
   drain-ordering replication cost is known.
7. **Segment boundary alignment (§7.2).** Does `E = 10,000` blocks land on a
   curve-tree chunk boundary, or is the segment a pure tree-position range that
   straddles chunk boundaries? If the former, segment sub-roots are reusable
   verification anchors; if the latter, only the per-height header roots anchor.
   Confirm against `shekyl-fcmp::tree` chunk width.
8. **Pin vs evict policy (§7.6).** A non-staking wallet evicts old segments
   (keeps a window); a staking wallet pins its shard set. The `LeafStore` API
   must expose both without a V3.x restructure — confirm the pin/evict seam is in
   CT-1's type design, not deferred.
9. **Anonymized segment fetch (§7.4).** Wire the source-agnostic fetch to the
   Tor/I2P routing layer so multi-source archival queries inherit the mandatory
   anonymization; confirm the seam against `ANONYMITY_NETWORKS.md` rather than
   bolting it on at V3.x.

---

## 9. PR decomposition (provisional)

| PR | Scope | Key files |
|----|-------|-----------|
| **CT-1** | `shekyl-curve-tree` crate skeleton + **segment-addressable** `LeafStore` (pin/evict seam, §7.6) + types (`AssembledPath`, `OutputIdentity`, `ReferenceBlock`) + no-secrets structural test | new crate |
| **CT-2** | Layer recompute + path extraction (`assemble`) over a **synthetic** leaf set; reconstruct-root KAT; C3-shape invariant | `assemble`, `shekyl-fcmp::tree` |
| **CT-3** | **Source-agnostic** bulk-segment fetch + delta sync + per-segment root verify against header; reorg rollback by segment | `sync`, peer-pluggable client |
| **CT-4** | Reference-block selection + horizon/rebuild (§5); `select_reference_block` | `client` |
| **CT-5** | Wire into 2A signer behind the §3.5 contract (replaces synthetic vectors); 2A §3.7.6 terminology correction (§5.4) | `shekyl-engine-core`, `PHASE_2A_SEND_PATH.md` |
| **C++** | `get_curve_tree_leaves` endpoint + KAT (`SHEKYLD_PREREQUISITES.md`) | `core_rpc_server`, separate PR |

CT-1/CT-2 are pure-Rust and synthetic-testable now (no daemon dependency),
mirroring 2A's split: the crypto/assembly lands and is KAT-gated before the
daemon endpoint exists. The V3.x `ArchivalEngine` (pin + serve + market, §7.6) is
**out of CT scope** — but CT-1's `LeafStore` API must not foreclose it (the
pin/evict + outbound-serve seam is the only forward requirement).

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
- [ ] §7.2 segment = shard = visual unit (one data plane); position≠height duality
  bridged by checkpoint `leaf_count`.
- [ ] §7.3 source-agnostic fetch; untrusted staker source = DoS-only (integrity by
  per-segment root verification).
- [ ] §7.4 privacy gradient preserved: segment-holder no-query > Tor segment fetch
  > per-output (forbidden); §3.0.1 bulk-not-per-output more load-bearing here.
- [ ] §7.5 `assemble_tree_path_for_output` is local assembly, not a staker RPC.
- [ ] §7.6 `LeafStore` segment-addressable so V3.x `ArchivalEngine` is additive;
  pin/evict seam present in CT-1.
