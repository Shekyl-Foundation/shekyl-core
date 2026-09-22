// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Store-local dense identifiers (RTN-2).
//!
//! These are **not** chain identities. `TxStorageId` is the transaction's
//! position in the `txs_*` tables; `OutputStorageId` is the global
//! `output_txs` key; `AmountIndex` is the per-amount dense member prefix
//! of `output_amounts`. Confusing any of them with
//! [`shekyl_types::GlobalOutputIndex`] / [`shekyl_types::OutputIndexInTx`]
//! / [`shekyl_types::TxHash`] is the error they exist to make unrepresentable.
//!
//! Table **keys** stay primitive at redb (`u64`, `(u64, u64)`, `(u8, u64)`):
//! that is the order contract. Convert at the handle. A scalar id converts
//! through `from_raw` / `to_raw`. A composite key has one named shape, and
//! that shape is the only place the tuple is assembled:
//!
//! - [`OutputSlot`] — `output_amounts`' `(amount, amount_index)`
//! - [`LayerChunk`] — `curve_tree_layers`' `(layer, chunk)`

use core::fmt;

use shekyl_units::AtomicUnits;

macro_rules! store_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Wrap a raw table id. An *edge* constructor.
            #[must_use]
            pub const fn from_raw(raw: u64) -> Self {
                Self(raw)
            }

            /// Unwrap to the raw table id. An *edge* accessor.
            #[must_use]
            pub const fn to_raw(self) -> u64 {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

store_id! {
    /// Position of a transaction in the `txs_*` tables (LMDB `tx_id`).
    TxStorageId
}

store_id! {
    /// Global output id — the `output_txs` primary key (LMDB `output_id`).
    OutputStorageId
}

store_id! {
    /// Dense member index within one `output_amounts` bucket (LMDB
    /// `amount_index`).
    AmountIndex
}

/// A slot in `output_amounts`: the **bucket** (an amount) and the dense
/// position within it (an [`AmountIndex`]). The table's redb key is the
/// tuple `(amount, amount_index)` — LMDB's `DUPSORT` pair as a key
/// (S-OUT-KI SOK-1, layout v6) — and every place that builds or bounds one
/// goes through this type, so the tuple's field order is written once.
///
/// Shekyl has **one bucket**: every miner and emission vout is stored under
/// [`Self::CONFIDENTIAL_AMOUNT`] with its ct-base commitment, and CEN-H14
/// makes every other vout's amount `0`. The bucket dimension is carried,
/// not chosen, while R8b-2 is open (`DRS_E1_SOUT_KI.md` §3.4); the read
/// surface takes a [`shekyl_types::GlobalOutputIndex`] and resolves it to
/// [`Self::confidential`], which is where the "one bucket" premise lives
/// as code rather than as a comment. Fields are private: the tuple is
/// assembled only through [`Self::new`] / [`Self::confidential`] /
/// [`Self::from_key`], and bounded only through [`Self::bucket`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OutputSlot {
    amount: AtomicUnits,
    index: AmountIndex,
}

impl OutputSlot {
    /// The bucket every confidential output lives in — and, on a valid
    /// chain, the only bucket. Miner and emission vouts are stored here
    /// regardless of their loud amount (`connect`, SCW-8).
    pub const CONFIDENTIAL_AMOUNT: AtomicUnits = AtomicUnits::ZERO;

    /// A slot in an arbitrary bucket. The writer's constructor: `connect`
    /// stores under whatever amount the vout carries after the miner /
    /// emission zeroing.
    #[must_use]
    pub const fn new(amount: AtomicUnits, index: AmountIndex) -> Self {
        Self { amount, index }
    }

    /// The slot a chain-wide output index names: position `index` in the
    /// confidential bucket. Under one bucket `amount_index == output_id ==
    /// GlobalOutputIndex` (SI-9 / SOK-2, enforced at every connect), which
    /// is what lets a reader turn a global index into a slot.
    #[must_use]
    pub const fn confidential(index: shekyl_types::GlobalOutputIndex) -> Self {
        Self::new(
            Self::CONFIDENTIAL_AMOUNT,
            AmountIndex::from_raw(index.to_raw()),
        )
    }

    /// The redb key. An *edge* accessor: the tuple is the engine's shape,
    /// not the store's vocabulary.
    #[must_use]
    pub const fn key(self) -> (u64, u64) {
        (self.amount.to_raw(), self.index.to_raw())
    }

    /// A slot from the redb key. An *edge* constructor.
    #[must_use]
    pub const fn from_key((amount, index): (u64, u64)) -> Self {
        Self::new(AtomicUnits::from_raw(amount), AmountIndex::from_raw(index))
    }

    /// The bucket this slot sits in.
    #[must_use]
    pub const fn amount(self) -> AtomicUnits {
        self.amount
    }

    /// The dense position within the bucket.
    #[must_use]
    pub const fn index(self) -> AmountIndex {
        self.index
    }

    /// The key range covering every slot in `amount`'s bucket. The bound
    /// that keeps the tuple's field order in this type: a ranger that
    /// spelled `(amount, 0)..=(amount, u64::MAX)` would duplicate `key()`.
    /// Not the SI-9 end-peek — that read is the table's first and last so
    /// a foreign-bucket row is visible (`next_output_slot`).
    #[must_use]
    pub const fn bucket(amount: AtomicUnits) -> core::ops::RangeInclusive<(u64, u64)> {
        let lo = Self::new(amount, AmountIndex::from_raw(0)).key();
        let hi = Self::new(amount, AmountIndex::from_raw(u64::MAX)).key();
        lo..=hi
    }
}

// ---------------------------------------------------------------------------
// curve_tree_layers — (layer, chunk). In flight for the grow path (DRS-E3):
// no writer calls these yet. The types are the key's shape, so E3 assembles
// the tuple here and cannot spell a second order.
// ---------------------------------------------------------------------------

/// A hashed layer's index above the leaf layer: `0` is the layer of chunk
/// hashes directly over the leaves. A `u8`, and not a
/// [`crate::codec::TreeDepth`]: a depth is how many such layers the tree
/// has, a layer is which one this chunk sits in.
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

/// A chunk's index within its [`TreeLayer`]. Not a
/// [`shekyl_types::TreePosition`]: a position names a leaf, a chunk index
/// names one hash in the layer above the leaves.
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

/// `curve_tree_layers`'s key: which chunk of which layer (S-CURVE `SCU-Q3`).
///
/// The table's redb key is the tuple `(layer, chunk)`. The C++ packed that
/// pair into one `u64` because LMDB needs one integer; redb orders the tuple
/// layer-major, which is the order the shift produced, with no 56-bit chunk
/// ceiling. Fields are private: the tuple is assembled only through
/// [`Self::key`] / [`Self::from_key`], and a layer's scan is only
/// [`Self::layer_range`], the same discipline as [`OutputSlot`].
///
/// `TreeLayer` is a `u8` and `ChunkIndex` is a `u64`, so the two components
/// cannot be swapped inside the tuple. The newtypes still earn their place:
/// a layer is not a [`crate::codec::TreeDepth`] (also a `u8`), and a chunk
/// index is not a [`shekyl_types::TreePosition`] (also a `u64`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LayerChunk {
    layer: TreeLayer,
    chunk: ChunkIndex,
}

impl LayerChunk {
    /// The key for `chunk` of `layer`.
    #[must_use]
    pub const fn new(layer: TreeLayer, chunk: ChunkIndex) -> Self {
        Self { layer, chunk }
    }

    /// Which layer.
    #[must_use]
    pub const fn layer(self) -> TreeLayer {
        self.layer
    }

    /// Which chunk within the layer.
    #[must_use]
    pub const fn chunk(self) -> ChunkIndex {
        self.chunk
    }

    /// The redb key. An *edge* accessor: the tuple is the engine's shape,
    /// not the store's vocabulary.
    #[must_use]
    pub const fn key(self) -> (u8, u64) {
        (self.layer.to_raw(), self.chunk.to_raw())
    }

    /// A chunk key from the redb tuple. An *edge* constructor.
    #[must_use]
    pub const fn from_key((layer, chunk): (u8, u64)) -> Self {
        Self::new(TreeLayer::from_raw(layer), ChunkIndex::from_raw(chunk))
    }

    /// Every key of one layer, as the inclusive range a table scan takes:
    /// `(layer, 0) ..= (layer, u64::MAX)`. Inclusive at the top so the last
    /// layer (`u8::MAX`) has a range too — there is no layer after 255 whose
    /// first key could be the exclusive end. Both ends go through [`Self::key`],
    /// so the field order is written once.
    #[must_use]
    pub const fn layer_range(layer: TreeLayer) -> core::ops::RangeInclusive<(u8, u64)> {
        let lo = Self::new(layer, ChunkIndex::FIRST).key();
        let hi = Self::new(layer, ChunkIndex::from_raw(u64::MAX)).key();
        lo..=hi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bucket_range_is_this_amount_then_every_index() {
        let amount = AtomicUnits::from_raw(7);
        let r = OutputSlot::bucket(amount);
        assert_eq!(
            *r.start(),
            OutputSlot::new(amount, AmountIndex::from_raw(0)).key()
        );
        assert_eq!(
            *r.end(),
            OutputSlot::new(amount, AmountIndex::from_raw(u64::MAX)).key()
        );
        assert!(
            OutputSlot::new(AtomicUnits::from_raw(6), AmountIndex::from_raw(0)).key() < *r.start(),
            "a lesser amount sorts before this bucket"
        );
        assert!(
            OutputSlot::new(AtomicUnits::from_raw(8), AmountIndex::from_raw(0)).key() > *r.end(),
            "a greater amount sorts after this bucket"
        );
    }

    #[test]
    fn layer_chunk_key_is_layer_then_chunk_and_a_layer_range_is_that_key() {
        let layer0_last = LayerChunk::new(TreeLayer::from_raw(0), ChunkIndex::from_raw(u64::MAX));
        let layer1_first = LayerChunk::new(TreeLayer::from_raw(1), ChunkIndex::FIRST);
        assert!(
            layer0_last.key() < layer1_first.key(),
            "every chunk of layer 0 precedes layer 1's first"
        );
        assert_eq!(LayerChunk::from_key(layer0_last.key()), layer0_last);
        let range = LayerChunk::layer_range(TreeLayer::from_raw(1));
        assert_eq!(*range.start(), layer1_first.key());
        assert_eq!(
            *range.end(),
            LayerChunk::new(TreeLayer::from_raw(1), ChunkIndex::from_raw(u64::MAX)).key()
        );
        assert!(range.contains(&layer1_first.key()));
        assert!(!range.contains(&layer0_last.key()));
        assert!(!range.contains(&LayerChunk::new(TreeLayer::from_raw(2), ChunkIndex::FIRST).key()));
        // The last layer has a range too — no successor layer to exclude against.
        let last = LayerChunk::layer_range(TreeLayer::from_raw(u8::MAX));
        assert!(last.contains(
            &LayerChunk::new(TreeLayer::from_raw(u8::MAX), ChunkIndex::from_raw(7)).key()
        ));
    }
}
