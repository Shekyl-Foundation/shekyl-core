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
//! Table **keys** stay `u64` (the redb / LMDB order contract). Convert at
//! the decoded handle via [`Self::from_raw`] / [`Self::to_raw`]. The one
//! composite key, `output_amounts`' `(amount, amount_index)`, has a named
//! shape — [`OutputSlot`] — so the tuple is assembled in exactly one place.

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
}
