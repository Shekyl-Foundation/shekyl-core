// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Absence at a dense index is a case, not a `None` (S-OUT-KI,
//! `DRS_E1_SOUT_KI.md` §3.3).
//!
//! Output ids are dense: `output_id` is `output_txs`' entry count at write
//! time and `amount_index` the amount-0 bucket's (SI-9), so the only absence
//! a by-index read can report is *at or beyond the count* — the same
//! structure as a height above the tip. A row missing **below** the count is
//! not absence; it is SI-9's hole, and comes back as
//! [`StoreError::InvariantViolated`](super::StoreError::InvariantViolated),
//! never as [`AtIndex::BeyondCount`], which a caller would read as "not
//! yet" and act on.
//!
//! This is `AtHeight`'s discipline (`shekyl-chain-rules`, G11) at a second
//! dense index, and the fourth application of the class stated once in
//! `CURVE_TREE_STORE_SHAPES.md` §3.1: absence earns a type when its case
//! carries caller-actionable semantics. It is a second type rather than a
//! generalisation of `AtHeight` on purpose (rule 21): two instances are not
//! yet a pattern worth an abstraction, and the two have different owners —
//! heights are the rules crate's vocabulary, indices are the store's. The
//! third dense index generalises.

/// A by-index lookup against a dense table.
///
/// Matched exhaustively. Deliberately **not** convertible to `Option`, and
/// without `map` / `unwrap_or_*` / `?` — the shapes by which an absence
/// becomes a silent pass in a diff that reads entirely reasonably:
///
/// ```compile_fail
/// # use shekyl_chain_store::store::AtIndex;
/// let at: AtIndex<u8> = AtIndex::Recorded(1);
/// let _: Option<u8> = at.into(); // no such conversion
/// ```
///
/// ```compile_fail
/// # use shekyl_chain_store::store::AtIndex;
/// fn read(at: AtIndex<u8>) -> Option<u8> { Some(at?) } // nothing for `?` to take
/// ```
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtIndex<T> {
    /// The table recorded `T` at that index.
    Recorded(T),
    /// No row has been recorded at that index: it is at or beyond the
    /// table's count. Indices below the count are dense (SI-9, the store's
    /// invariant), so this is the only absence a read can report — a hole
    /// below the count is `InvariantViolated`, not this.
    BeyondCount,
}
