// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Incremental accumulator primitives (DRS-0 slice A, `DAEMON_REDB_STORE.md`
//! §6.2).
//!
//! [`digest_v0`](crate::digest_v0) is a **full-domain** oracle: it rescans
//! every element on every call, which is `O(n)` per block and `O(n²)` over a
//! sync. §6.2 freezes the incremental replacements. This module is the two
//! *incremental* classes; the other three need no state.
//!
//! | §6.2 class | Type here | Why |
//! |---|---|---|
//! | Set-shaped | [`SetAccumulator`] | order-independent XOR fold |
//! | Append-mostly | [`AppendAccumulator`] | running chained hash |
//! | Small | — | full-domain digest every block; nothing to carry |
//! | `derived` | — | recomputed from a named source at checkpoints |
//! | `excluded` | — | not folded |
//!
//! The per-table assignment is [`TABLE_CLASSES`] / [`class_for_table`],
//! matching the `Accumulator class` column of
//! [`docs/LMDB_WRITE_ATOMICITY_AUDIT.md`](../../../docs/LMDB_WRITE_ATOMICITY_AUDIT.md)
//! §10. Set-shaped write contracts (where the Rust store must read before
//! the C++ does) are [`SET_SHAPED_CONTRACTS`].
//!
//! # What these types fold
//!
//! **A canonical encoding of the decoded logical value, never storage
//! bytes.** This is forced by DRS-E2: the C++ LMDB store and the Rust redb
//! store must produce the *same* digest for the same logical state, and they
//! will never agree on layout. Both accumulators therefore take `&[u8]`
//! element encodings and say nothing about how a row is stored.
//!
//! # The reversal rule these types cannot enforce
//!
//! Fold the value **read from the store**, never the caller's argument.
//! DRS-W13 is why — the curve pop *reconstructs* `TreePosition`
//! arithmetically, so a fold over the caller's argument would inherit the
//! reconstruction.
//!
//! The C++ delete path does **not** always have that value in hand. Of the
//! fifteen [`AccumulatorClass::SetShaped`] tables, six delete by key
//! alone (`mdb_del(…, nullptr)`) and ten overwrite without reading
//! (`mdb_put(…, 0)`). [`SetShapedContract`] records which is which.
//! redb can always read first; a port that transliterates the C++ as-is
//! desynchronizes the accumulator silently.
//!
//! # Relationship to the shipped v0 oracle
//!
//! [`SetAccumulator`] over
//! [`digest_v0::SPENT_ELEM_CUSTOMIZATION`](crate::digest_v0::SPENT_ELEM_CUSTOMIZATION)
//! reproduces [`digest_v0::spent_accumulator`](crate::digest_v0::spent_accumulator)
//! byte for byte — asserted by test, so the incremental form is a drop-in
//! for the full-domain one and DRS-E2 can compare across the two.
//!
//! [`AppendAccumulator`] is **not** equivalent to
//! [`digest_v0::chain_component`](crate::digest_v0::chain_component): that
//! function folds the block count into its preimage and hashes the whole
//! height-ordered sequence in one pass, which is a different shape from a
//! per-element chain. Adopting [`AppendAccumulator`] for `blocks` is
//! therefore a [`DIGEST_FORMAT_VERSION`](crate::digest_v0::DIGEST_FORMAT_VERSION)
//! bump, not a refactor, and DRS-E1 must not assume equivalence.
//!
//! [`SetAccumulator::remove`] cannot detect a wrong argument. It XORs
//! whatever it is given, and XORing an element that was never inserted
//! silently *adds* it — the operation is an involution, not a set
//! difference. That is the property that makes it pop-symmetric and the
//! property that makes it unable to detect a wrong argument. Detection is
//! the checkpoint reconciliation's job (§6.2's fourth row), not this
//! type's.

mod append;
mod class;
mod domain;
mod set;

pub use append::{AppendAccumulator, Checkpoint, RewindError};
pub use class::{
    class_for_table, AccumulatorClass, SetShapedContract, SetShapedDelete, SetShapedInsert,
    UnknownAccumulatorClass, SET_SHAPED_CONTRACTS, TABLE_CLASSES,
};
pub use domain::AccumulatorDomain;
pub use set::SetAccumulator;
