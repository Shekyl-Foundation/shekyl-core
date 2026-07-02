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

/// A request to assemble one owned output's membership path (X3, CT-5c).
///
/// Carries the **`gindex`** — the tree's unique key, equal to the wallet's
/// `TransferDetails.global_output_index` — as the resolution key, plus the
/// `(output_key, commitment)` the caller expects at that gindex for the
/// post-resolution consistency check. Resolving by `gindex` is total (the
/// owned output is always a drained leaf), eliminating the `(output_key,
/// commitment)` content-match's collision case; the carried pair is then used
/// only to *verify* the resolution, not to perform it (a mismatch is
/// [`crate::ClientError::IdentityMismatch`]).
///
/// Deliberately **not** a full [`OutputIdentity`]: resolution uses only
/// `gindex` and the check uses only `(output_key, commitment)`, so carrying
/// `h_pqc` / `target` would force the engine to fabricate two fields it does
/// not hold for an owned output (the real `h_pqc` comes back *from* the
/// drained leaf in [`ChunkLeaf`]). Public material only — `Copy`, no secrets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssembleInput {
    /// Global output index (`= TransferDetails.global_output_index`), the
    /// tree's unique resolution key.
    pub gindex: Gindex,
    /// Compressed Ed25519 output public key (`O`) the caller expects at
    /// `gindex`.
    pub output_key: [u8; 32],
    /// Amount commitment (`C`) the caller expects at `gindex`. Non-optional:
    /// an owned output is always leaf-eligible and commitment-bearing.
    pub commitment: [u8; 32],
}

/// Implement `redb::Value` + `redb::Key` for an integer newtype by
/// delegating every operation to the inner primitive's impl.
///
/// Delegation (rather than hand-rolled byte twiddling) guarantees the
/// on-disk byte layout and key ordering are byte-identical to a raw
/// `u64`/`u32` table — range scans, ordered iteration, and batched
/// range-deletes behave exactly as before the typed-key retrofit. Only
/// the `TypeName` differs, which is the point: redb refuses to open a
/// table whose stored key type disagrees, so a position, height, gindex,
/// and segment id can never index each other's tables.
macro_rules! redb_delegated_key {
    ($ty:ty, $inner:ty, $name:literal) => {
        impl redb::Value for $ty {
            type SelfType<'a> = $ty;
            type AsBytes<'a> = <$inner as redb::Value>::AsBytes<'a>;

            fn fixed_width() -> Option<usize> {
                <$inner as redb::Value>::fixed_width()
            }

            fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
            where
                Self: 'a,
            {
                Self(<$inner as redb::Value>::from_bytes(data))
            }

            fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
            where
                Self: 'b,
            {
                <$inner as redb::Value>::as_bytes(&value.0)
            }

            fn type_name() -> redb::TypeName {
                redb::TypeName::new($name)
            }
        }

        impl redb::Key for $ty {
            fn compare(data1: &[u8], data2: &[u8]) -> core::cmp::Ordering {
                <$inner as redb::Key>::compare(data1, data2)
            }
        }
    };
}
pub(crate) use redb_delegated_key;

/// Block height on the Shekyl chain. Typed so a height can never be
/// swapped with a tree position, gindex, or leaf count at a store seam —
/// the compiler rejects the mix-up rather than a KAT catching it later.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlockHeight(pub u64);

redb_delegated_key!(BlockHeight, u64, "shekyl_curve_tree::BlockHeight");

/// Global output index (the daemon's `next_output_seq` counter), assigned
/// to every `vout` in C++ drain order. Typed for the same swap-rejection
/// reason as [`BlockHeight`]; keys the pending-candidates table.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Gindex(pub u64);

redb_delegated_key!(Gindex, u64, "shekyl_curve_tree::Gindex");

/// Dense tree position in drain order (`(maturity, gindex)` sort).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TreePosition(pub u64);

redb_delegated_key!(TreePosition, u64, "shekyl_curve_tree::TreePosition");

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
    pub gindex: Gindex,
    /// Maturity height at which this leaf drains into the tree. Primary
    /// drain sort key.
    pub maturity: BlockHeight,
    /// Block height the output was created at. The lock offset from
    /// creation to `maturity` varies by output class (coinbase +60,
    /// regular +10, stake tiers), so maturity is **not** invertible to
    /// creation height — the rollback two-class partition (CT3_SYNC.md
    /// R1-Q3/F4) filters on this field directly.
    pub creation_height: BlockHeight,
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

/// A reference block the wallet anchors a membership proof to: the height,
/// the consensus curve-tree root committed in that block's header, and the
/// block's own hash.
///
/// All three are public consensus values the caller holds from its synced
/// chain view; the struct is the single anchor [`crate::CurveTreeClient::assemble_path`]
/// consumes, so the caller cannot positionally swap one 32-byte value for
/// another (output keys, commitments, roots, and block hashes are all
/// `[u8; 32]`). Binding a height to its consensus root and hash is the
/// caller's responsibility (the caller-supplies-root integrity model,
/// `CURVE_TREE_CLIENT.md` §3.5); reference-block *selection* is the height
/// arithmetic in [`crate::reference`], which deliberately does not construct
/// a `ReferenceBlock` (it stores no header roots).
///
/// The reconstructed root (see [`crate::recon::root_from_scalars`]) must
/// byte-equal `curve_tree_root` — the CT-2 reconstruct-root KAT. The
/// header-committed value is the source of truth; height 0 is an
/// unverified genesis constant, so KAT assertions anchor at heights ≥ 5
/// (CT2_DRAIN_ORDER.md §8.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReferenceBlock {
    /// Block height.
    pub height: BlockHeight,
    /// Header-committed curve-tree root (consensus value to match).
    pub curve_tree_root: [u8; 32],
    /// Hash of the block at [`Self::height`], echoed into
    /// [`TreeContext::reference_block`] for the eventual
    /// `rctSig.referenceBlock`. A consensus value the caller holds from the
    /// synced header alongside [`Self::curve_tree_root`].
    pub block_hash: [u8; 32],
}
