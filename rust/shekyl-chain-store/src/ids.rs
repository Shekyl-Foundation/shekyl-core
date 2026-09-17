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
//! the decoded handle via [`Self::from_raw`] / [`Self::to_raw`].

use core::fmt;

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
