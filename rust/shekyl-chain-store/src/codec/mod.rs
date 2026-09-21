// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! This store's canonical value codecs (DRS-E1 increment 2).
//!
//! # One encoding, two consumers
//!
//! DRS-0 slice A ruled that the accumulator folds *"a canonical encoding of
//! the decoded logical value, never storage bytes"*, and
//! [`DAEMON_REDB_STORE.md`](../../../../docs/design/DAEMON_REDB_STORE.md)
//! §11.1(b) ruled that the redb value codec **is** that canonical encoding —
//! so a codec change is digest-visible, not a refactor, and bumps
//! [`SCHEMA_VERSION`]. [`Canonical`] is where both rulings become one trait:
//! the encoding a value is *stored* under and the encoding the digest
//! *folds*. There is no second function to drift from the first.
//!
//! # The trait is shared; the obligation is not
//!
//! [`Canonical`], [`CodecError`], [`exact`] and the four value shapes live
//! in `shekyl-store-codec`, which both stores reach, together with the
//! codecs for types neither store owns — the scalars and the
//! `shekyl-types` / `shekyl-units` vocabulary. The orphan rule decides
//! that, not taste: with the trait foreign here, those impls can live only
//! where the trait lives, and the vocabulary crates are `no_std` and must
//! not depend on `redb` (`CURVE_TREE_STORE_SHAPES.md` CTS-13). This module
//! re-exports every moved item at its existing path, so no call path in
//! this crate or on the daemon side moved with it.
//!
//! What stayed is what §11.1(f)'s last bullet says must: this store's own
//! column codecs, (b)'s bump obligation, the committed fixture snapshots
//! and the `impl Canonical` source scan. The consensus obligation lives
//! where the digest is, and a general-purpose trait must not look like the
//! thing someone could later relax for the wallet store's convenience.
//!
//! # Strictness is the contract
//!
//! [`Canonical::decode`] is total over its input and refuses anything that
//! is not exactly one encoding: wrong length, trailing bytes, and bit
//! patterns that name nothing are all [`CodecError`], never a lenient
//! read. A consensus store that tolerated a malformed cell would be
//! accepting a state it cannot reproduce, which is the failure the digest
//! exists to detect — so the codecs refuse first.
//!
//! # The gate
//!
//! Every `impl Canonical` in this crate has a committed fixture snapshot
//! under `rust/shekyl-chain-store/schemas/`, asserted by the
//! `codec_snapshot` tests in [`snapshot_tests`](self) and paired against
//! [`SCHEMA_VERSION`] by `.github/workflows/schema-snapshot.yml` — which
//! also triggers on `rust/shekyl-store-codec/**`, because the moved
//! codecs' fixtures are still committed here and their bytes are still the
//! digest's fold input. That is the rule-42 ratchet §11.1(e) recorded as
//! owed: an encoding cannot move without the version moving in the same PR.

mod chain;
mod curve;
mod evidence;
mod primitives;
mod property;
mod schema_version;
mod settlement_epoch;
mod undo;

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod snapshot_tests;

pub(crate) use chain::stored_timelock;
pub use chain::{
    BlockBody, BlockInfo, OutKey, OutTx, RuleSetInForce, TxIndex, TxOutputIndices,
    TxPqcAuthsSegment, TxPrunableSegment, TxPrunedSegment,
};
pub use curve::{
    ChunkIndex, CurveTreeState, LayerChunk, LayerHash, LeafCount, TreeDepth, TreeLayer,
};
pub use evidence::{CoverageGaps, PassedThroughFacts, FACT_FIELDS};
#[cfg(test)]
pub(crate) use property::ProbeCell;
pub use property::{
    ApplyPolicyCell, CellScope, ChainState, CoverageGapsCell, EngineLocal, PassedThroughFactsCell,
    PropertyCell, PropertyCellBytes, PropertyCellSpec, SchemaVersionCell, Scope,
    SettlementEpochBlocksCell, TotalBurnedCell, PROPERTY_CELLS,
};
pub use schema_version::{SchemaVersion, SCHEMA_VERSION};
pub use settlement_epoch::SettlementEpochBlocks;
pub use undo::{post_image, UndoEntry, UndoLog, POST_IMAGE_DST};

// The shared contract, re-exported at its existing path: `crate::codec::X`
// resolves for every caller it did before the move.
pub use shekyl_store_codec::{
    exact, Blob, BlobKind, Canonical, CodecError, Coded, Encoded, EncodedBuf, NoRow, Present, Raw,
    Unshaped,
};

/// Name arbitrary bytes as a row of a `Coded<V>` table **without** going
/// through `V::encode`, for the tests that prove a corrupt row is SI-7.
///
/// This is not a hole the shared crate leaves open: `redb::Value::from_bytes`
/// is a public trait method, so any caller of `redb` can already do this —
/// which is exactly why the guarantee is the insertion boundary
/// ([`store::keyed::check_row`](crate::store)) and not constructor
/// visibility (`shape` module docs, *Two guards*). The helper only spells
/// that reachable path once, in test code, so a planted row reads as
/// deliberate.
#[cfg(test)]
pub(crate) fn forged<V: Canonical + 'static>(bytes: &[u8]) -> Encoded<'_, V> {
    <Coded<V> as redb::Value>::from_bytes(bytes)
}
