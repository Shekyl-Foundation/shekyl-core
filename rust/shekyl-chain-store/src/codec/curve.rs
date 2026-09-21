// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The curve tree's stored shapes — DRS-E1 S-CURVE
//! (`DRS_E1_SCURVE.md` §3.4, §4).
//!
//! Three tables the C++ left as raw bytes gain types here; the grow path
//! (DRS-E3) will write what these describe and may not choose a second
//! shape for the same byte. The vocabulary two stores share —
//! [`TreePosition`], [`TreeLeaf`] — lives in `shekyl-types` with its codec
//! in `shekyl-store-codec` (`SCU-Q2`); what is here is the daemon store's
//! own: the tree's summary row, the layer table's key and value, and the two
//! redb key wrappers.
//!
//! # `curve_tree_meta` is one row (`SCU-Q1`)
//!
//! The C++ kept three string-keyed cells — `"root"`, `"depth"`,
//! `"leaf_count"` — and each read invented a value when its key was absent
//! (`db_lmdb.cpp:9259–9313`: `hash_init`, `0`, `0`), then documented that
//! the root read was therefore ambiguous and told callers to disambiguate
//! with a second read (SCU-1). Here the table holds **one**
//! [`CurveTreeState`] under the unit key: the three facts the C++ wrote in
//! one grow (`:8936–8966`) cannot disagree, and **the empty tree is a
//! written row** — [`CurveTreeState::EMPTY`], put by the seal at store
//! creation — so an absent row is [`StoreInvariant::CellCorrupt`]
//! (`crate::store::StoreInvariant`), never a default. No caller compares a
//! root against `hash_init` to learn whether the tree is empty.
//!
//! # `curve_tree_layers`'s key is a tuple (`SCU-Q3`)
//!
//! The C++ packed `(layer << 56) | chunk` into one `u64` because LMDB needs
//! one integer key. redb does not: [`LayerChunk`] is a `(u8, u64)` tuple key
//! whose byte-lexicographic order over redb's fixed-width encodings **is**
//! layer-major then chunk order — the order the shift produced — so a
//! layer's chunks are `range(LayerChunk::layer_range(l))` and no chunk
//! ceiling was inherited. Nothing here needs a KAT to pin a shift.
//!
//! # Where the types stop
//!
//! [`TreeDepth`] and [`LeafCount`] are the summary's own fields, named so a
//! depth is never a count. The arithmetic — the Selene hash that turns a
//! chunk of leaves into a [`LayerHash`], the drain order that assigns a
//! position — is `shekyl-curve-tree`'s and `shekyl-fcmp`'s; this module
//! holds the words and their bytes.

use shekyl_store_codec::{exact, Canonical, CodecError};
use shekyl_types::{CurveTreeRoot, TreePosition};

// ---------------------------------------------------------------------------
// Summary row
// ---------------------------------------------------------------------------

/// The tree's depth: the number of hashed layers **above the leaf layer**
/// (`db_lmdb.cpp:8957` — "depth = number of layers above the leaf;
/// `fcmp_layers = depth + 1`"). `0` for an empty tree. Stated once, here,
/// with its off-by-one; no consumer re-derives it. Fits a `u8` because the
/// C++ refuses a grow past 255 (`:8955`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct TreeDepth(u8);

impl TreeDepth {
    /// An empty tree has no layers above its (empty) leaf layer.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw depth (a store decode, an FFI edge).
    #[must_use]
    pub const fn from_raw(layers_above_leaves: u8) -> Self {
        Self(layers_above_leaves)
    }

    /// Layers above the leaf layer.
    #[must_use]
    pub const fn to_raw(self) -> u8 {
        self.0
    }

    /// The FCMP++ proof's layer count for a tree of this depth: the leaf
    /// layer plus every layer above it. The one place the `+ 1` lives.
    #[must_use]
    pub const fn fcmp_layers(self) -> u16 {
        self.0 as u16 + 1
    }
}

/// How many leaves the tree holds — `curve_tree_leaves` holds exactly the
/// positions `[0, count)` (SI-11). Named so a count is never a position and
/// never a depth.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct LeafCount(u64);

impl LeafCount {
    /// No leaves.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw count.
    #[must_use]
    pub const fn from_raw(count: u64) -> Self {
        Self(count)
    }

    /// The count.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }

    /// The position the next leaf would take — the exclusive end of the
    /// dense range this count describes.
    #[must_use]
    pub const fn next_position(self) -> TreePosition {
        TreePosition::from_raw(self.0)
    }

    /// Whether `position` is inside `[0, count)`.
    #[must_use]
    pub const fn holds(self, position: TreePosition) -> bool {
        position.to_raw() < self.0
    }
}

/// The tree's summary — `curve_tree_meta`'s one row (module docs).
///
/// Layout (41 bytes): `root`[32] ‖ `depth` u8 ‖ `leaf_count` u64 LE.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CurveTreeState {
    /// The live root — the same value `curve_tree_roots[tip + 1]` holds
    /// after the last connect; kept here so the summary is one read.
    pub root: CurveTreeRoot,
    /// Layers above the leaf layer.
    pub depth: TreeDepth,
    /// Leaves in the tree.
    pub leaf_count: LeafCount,
}

impl CurveTreeState {
    /// The empty tree: the identity root, no layers, no leaves. **Written**
    /// at store creation, so that an empty tree and a missing row are
    /// different facts (module docs; SCU-1).
    pub const EMPTY: Self = Self {
        root: CurveTreeRoot::EMPTY,
        depth: TreeDepth::ZERO,
        leaf_count: LeafCount::ZERO,
    };

    const ROOT: core::ops::Range<usize> = 0..32;
    const DEPTH: usize = Self::ROOT.end;
    const LEAF_COUNT: core::ops::Range<usize> = Self::DEPTH + 1..Self::DEPTH + 1 + 8;
    const LEN: usize = Self::LEAF_COUNT.end;
}

impl Canonical for CurveTreeState {
    const NAME: &'static str = "curve_tree_state";
    const FIXED_WIDTH: Option<usize> = Some(Self::LEN);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.root.as_bytes());
        out.push(self.depth.to_raw());
        out.extend_from_slice(&self.leaf_count.to_raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let bytes = exact::<{ Self::LEN }>(Self::NAME, bytes)?;
        let root = CurveTreeRoot::from_bytes(
            bytes[Self::ROOT]
                .try_into()
                .expect("ROOT is 32 bytes by construction"),
        );
        let depth = TreeDepth::from_raw(bytes[Self::DEPTH]);
        let leaf_count = LeafCount::from_raw(u64::from_le_bytes(
            bytes[Self::LEAF_COUNT]
                .try_into()
                .expect("LEAF_COUNT is 8 bytes by construction"),
        ));
        Ok(Self {
            root,
            depth,
            leaf_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/// A hashed layer's index above the leaf layer: `0` is the first layer of
/// chunk hashes over leaves, `depth - 1` the layer under the root.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TreeLayer(u8);

impl TreeLayer {
    /// The layer of chunk hashes directly over the leaves.
    pub const FIRST: Self = Self(0);

    /// Wrap a raw layer index.
    #[must_use]
    pub const fn from_raw(layer: u8) -> Self {
        Self(layer)
    }

    /// The layer index.
    #[must_use]
    pub const fn to_raw(self) -> u8 {
        self.0
    }
}

/// A chunk's index within its layer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ChunkIndex(u64);

impl ChunkIndex {
    /// The layer's first chunk.
    pub const FIRST: Self = Self(0);

    /// Wrap a raw chunk index.
    #[must_use]
    pub const fn from_raw(chunk: u64) -> Self {
        Self(chunk)
    }

    /// The chunk index.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// `curve_tree_layers`'s key: one chunk hash's coordinates (module docs,
/// `SCU-Q3`). Ordered layer-major, then by chunk — as a tuple compares.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LayerChunk {
    /// Which hashed layer.
    pub layer: TreeLayer,
    /// Which chunk within it.
    pub chunk: ChunkIndex,
}

impl LayerChunk {
    /// The key for `chunk` of `layer`.
    #[must_use]
    pub const fn new(layer: TreeLayer, chunk: ChunkIndex) -> Self {
        Self { layer, chunk }
    }

    /// Every key of one layer, as the half-open range a table scan takes:
    /// `(layer, 0) ..= (layer, u64::MAX)`. Inclusive at the top so the last
    /// layer (`u8::MAX`) has a range too — the tuple order makes the next
    /// layer's first key the exclusive successor otherwise, and there is no
    /// layer after 255.
    #[must_use]
    pub const fn layer_range(layer: TreeLayer) -> core::ops::RangeInclusive<Self> {
        Self::new(layer, ChunkIndex::FIRST)..=Self::new(layer, ChunkIndex(u64::MAX))
    }

    /// The redb tuple this key is stored as.
    #[must_use]
    pub const fn to_tuple(self) -> (u8, u64) {
        (self.layer.0, self.chunk.0)
    }

    /// From the stored tuple.
    #[must_use]
    pub const fn from_tuple((layer, chunk): (u8, u64)) -> Self {
        Self::new(TreeLayer(layer), ChunkIndex(chunk))
    }
}

/// `curve_tree_layers[key]` — one chunk's Selene hash, 32 bytes. A
/// **derived** value (accumulator class `Derived`): recomputable from the
/// leaves; `hash_init` for a chunk never hashed is the grow path's default
/// to write, never a read's to invent.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LayerHash([u8; 32]);

impl LayerHash {
    /// Wrap 32 stored bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for LayerHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LayerHash(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

impl Canonical for LayerHash {
    const NAME: &'static str = "layer_hash";
    const FIXED_WIDTH: Option<usize> = Some(32);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<32>(Self::NAME, bytes).map(Self::from_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_round_trips_and_empty_is_a_real_row() {
        let empty = CurveTreeState::EMPTY;
        let bytes = empty.encode();
        assert_eq!(bytes.len(), 41);
        assert_eq!(CurveTreeState::decode(&bytes).expect("decodes"), empty);
        let grown = CurveTreeState {
            root: CurveTreeRoot::from_bytes([0xc1; 32]),
            depth: TreeDepth::from_raw(3),
            leaf_count: LeafCount::from_raw(0x0102_0304_0506_0708),
        };
        let bytes = grown.encode();
        assert_eq!(&bytes[..32], &[0xc1; 32]);
        assert_eq!(bytes[32], 3);
        assert_eq!(&bytes[33..], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(CurveTreeState::decode(&bytes).expect("decodes"), grown);
        assert!(matches!(
            CurveTreeState::decode(&bytes[..40]),
            Err(CodecError::Length {
                codec: "curve_tree_state",
                expected: 41,
                actual: 40
            })
        ));
    }

    #[test]
    fn depth_states_its_off_by_one_once_and_count_bounds_positions() {
        assert_eq!(TreeDepth::ZERO.fcmp_layers(), 1);
        assert_eq!(TreeDepth::from_raw(255).fcmp_layers(), 256);
        let three = LeafCount::from_raw(3);
        assert!(three.holds(TreePosition::from_raw(2)));
        assert!(!three.holds(TreePosition::from_raw(3)));
        assert_eq!(three.next_position(), TreePosition::from_raw(3));
    }

    #[test]
    fn layer_chunk_orders_layer_major_and_a_layer_range_holds_exactly_its_chunks() {
        let a = LayerChunk::new(TreeLayer::from_raw(0), ChunkIndex::from_raw(u64::MAX));
        let b = LayerChunk::new(TreeLayer::from_raw(1), ChunkIndex::from_raw(0));
        assert!(a < b, "every chunk of layer 0 precedes layer 1's first");
        assert_eq!(LayerChunk::from_tuple(a.to_tuple()), a);
        let range = LayerChunk::layer_range(TreeLayer::from_raw(1));
        assert!(range.contains(&b));
        assert!(!range.contains(&a));
        assert!(!range.contains(&LayerChunk::new(TreeLayer::from_raw(2), ChunkIndex::FIRST)));
        // The last layer has a range too — no successor layer needed.
        let last = LayerChunk::layer_range(TreeLayer::from_raw(u8::MAX));
        assert!(last.contains(&LayerChunk::new(
            TreeLayer::from_raw(u8::MAX),
            ChunkIndex::from_raw(7)
        )));
    }
}
