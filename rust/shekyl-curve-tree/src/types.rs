// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Public data types for the curve-tree client.
//!
//! Every type here carries only public on-chain material — output public
//! keys, amount commitments, PQC leaf hashes, tree roots, and indices.
//! None carry secrets, so all are `Copy` (a secret-bearing type would be
//! non-`Copy` for wipe-on-drop, per `35-secure-memory.mdc`). Secret
//! material never enters this crate; it lives behind the engine boundary
//! (`36-secret-locality.mdc`, `16-architectural-inheritance.mdc`).

/// The kind of an output's target, mirroring the `vout.target` variant
/// matched in `blockchain_db.cpp::collect_outputs`. Determines the
/// maturity height and whether the output is a tree-leaf candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TargetKind {
    /// `txout_to_tagged_key` — the standard V3 output target.
    TaggedKey,
    /// `txout_to_key` — untagged key target. Mirrored for daemon
    /// leaf-set parity; the wallet never *creates* these, it only
    /// replicates the daemon's leaf inclusion. Unreachable in a
    /// V3-from-genesis chain, but handled identically so reconstruction
    /// is bit-exact if the daemon ever indexes one.
    Key,
    /// `txout_to_staked_key` — staking output. `lock_blocks` is the
    /// tier-resolved lock duration (`shekyl_stake_lock_blocks(lock_tier)`),
    /// resolved at the decode boundary against `shekyl-staking` so this
    /// crate does not duplicate the tier→blocks table. Off the Tier-A
    /// path (CT2_DRAIN_ORDER.md §8.2, Tier B).
    StakedKey {
        /// Tier-resolved lock duration in blocks.
        lock_blocks: u64,
    },
    /// Any other target variant — not a leaf candidate (the C++ `else
    /// continue`). The output still consumes a global output index.
    Other,
}

/// An output's leaf-relevant facts, extracted from a decoded transaction
/// output at the block-decode boundary. Public material only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutputIdentity {
    /// Compressed Ed25519 output public key (`O`).
    pub output_key: [u8; 32],
    /// Amount commitment mask (`C = rct_signatures.outPk[i].mask`).
    /// `None` when the output has no commitment slot
    /// (`i >= outPk.size()`), which makes it leaf-ineligible (the C++
    /// skip (b)).
    pub commitment: Option<[u8; 32]>,
    /// Per-output PQC leaf hash (`h_pqc`), already resolved with the
    /// zero-fallback applied (see [`crate::recon::per_output_h_pqc`]).
    pub h_pqc: [u8; 32],
    /// Output target kind.
    pub target: TargetKind,
}

/// Dense tree position in drain order (`(maturity, gindex)` sort).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TreePosition(pub u64);

/// A drained tree leaf: its global output index, its maturity height, the
/// 128-byte curve-tree leaf (`{O.x, I.x, C.x, h_pqc}`), and the public
/// output identity it was built from. Tree position is determined by drain
/// order `(maturity, gindex)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeafEntry {
    /// Global output index — assigned to *every* `vout` in C++ drain
    /// order (coinbase first, then block txs; `vout` order within each),
    /// monotonically. Secondary drain sort key. The leaf set is a subset
    /// of the indexed set, so a `LeafEntry`'s `gindex` may skip values
    /// consumed by leaf-ineligible outputs (CT2_DRAIN_ORDER.md §2.2).
    pub gindex: u64,
    /// Maturity height at which this leaf drains into the tree. Primary
    /// drain sort key.
    pub maturity: u64,
    /// The constructed 128-byte leaf (4 × 32-byte Selene scalars), cached
    /// as the x-coordinate form `build_layers` consumes (the hot path that
    /// rebuilds the root at a reference height).
    pub leaf: [u8; 128],
    /// The public output identity this leaf was built from, retained so
    /// the membership-path assembler can rebuild the leaf chunk's
    /// compressed `O`/`I`/`C` points (the prover's `Path.leaves`, F6).
    /// The cached `leaf` only holds x-coordinates, which cannot be
    /// decompressed back to points; `identity` carries the compressed `O`
    /// and `C` so the assembler derives `I = Hp(O)` and emits a
    /// [`crate::types::ChunkLeaf`]. Co-located with the entry so it rides
    /// the drain-order sort without desync.
    pub identity: OutputIdentity,
}

/// One output in a path's Selene leaf chunk — the public per-output tuple
/// the FCMP++ prover's `Path.leaves` consumes. Mirrors the field names of
/// `shekyl_tx_builder::types::LeafEntry` so the engine adapter that builds
/// `SpendInput` is a trivial field copy. Carries compressed **points**
/// (`O`, `I`, `C`), not x-coordinate scalars.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkLeaf {
    /// Compressed Ed25519 output public key (`O`).
    pub output_key: [u8; 32],
    /// Key image generator `I = Hp(O)` (compressed), derived in-crate.
    pub key_image_gen: [u8; 32],
    /// Compressed amount commitment (`C`).
    pub commitment: [u8; 32],
    /// Per-output PQC leaf hash (`h_pqc`).
    pub h_pqc: [u8; 32],
}

/// Curve-tree context for one transaction's membership proof, shared by
/// every input (the C1 single-snapshot guarantee). Mirrors
/// `shekyl_tx_builder::types::TreeContext`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeContext {
    /// Hash of the reference block (echoed into `rctSig.referenceBlock`).
    pub reference_block: [u8; 32],
    /// Header-committed curve-tree root at the reference height.
    pub tree_root: [u8; 32],
    /// Tree depth (number of layers), derived from the reconstructed
    /// layer stack (`build_layers(stream).len()`), not carried on
    /// [`ReferenceBlock`].
    pub tree_depth: u8,
}

/// A locally-assembled FCMP++ membership path for one owned output, public
/// material only (no secrets, no `ZeroizeOnDrop`). The secret-bearing
/// `shekyl_tx_builder::types::SpendInput` is a *different* type; the
/// engine/2A signer maps this path into a `SpendInput` by adding secrets.
///
/// `c1_layers`/`c2_layers` are node x-coordinate scalars, each layer the
/// **full chunk including the path node** (siblings are not excluded),
/// ordered bottom-to-top, matching the FCMP++ prover's `Path`. The C3
/// invariant `c1_layers.len() + c2_layers.len() + 1 == tree.tree_depth`
/// holds on a successful assembly (the leaf layer is the `+1`; the root
/// layer is excluded — it is the prover's `TreeRoot`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssembledPath {
    /// The path leaf node's outputs (including the target), in chunk order.
    pub leaf_chunk: Vec<ChunkLeaf>,
    /// Selene-node chunks as x-coordinate scalars, bottom-to-top.
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios-node chunks as x-coordinate scalars, bottom-to-top.
    pub c2_layers: Vec<Vec<[u8; 32]>>,
    /// The single tree context shared by the whole transaction.
    pub tree: TreeContext,
}

/// A reference block the wallet anchors a membership proof to: the height
/// and the consensus curve-tree root committed in that block's header.
///
/// The reconstructed root (see [`crate::recon::root_from_scalars`]) must
/// byte-equal `curve_tree_root` — the CT-2 reconstruct-root KAT. The
/// header-committed value is the source of truth; height 0 is an
/// unverified genesis constant, so KAT assertions anchor at heights ≥ 5
/// (CT2_DRAIN_ORDER.md §8.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReferenceBlock {
    /// Block height.
    pub height: u64,
    /// Header-committed curve-tree root (consensus value to match).
    pub curve_tree_root: [u8; 32],
}
