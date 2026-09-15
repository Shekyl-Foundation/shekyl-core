// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The narrow, read-only view a rule reads the recorded chain through.
//!
//! [`ChainView`] is the whole of what a rule may know about the chain beyond
//! the candidate in its hand. The store implements it over its
//! `WriteBatch<'_, 'id>` (S-CHAIN-W); the test harness implements it over a
//! `BTreeMap`. A rule is generic over it and is therefore testable with no
//! database (`CONSENSUS_C2_R8_STORE_PLACEMENT.md` §9.1). Methods grow with
//! the increment that consumes them, each justified by a named census row
//! (round-1 ruling Q3): narrowness is what keeps rules mockable and the mock
//! smaller than the store.
//!
//! # Three answers, three positions
//!
//! Every method returns `Result<_, Self::Fault>`. The `Err` is the view's
//! **substrate** failing — a redb read error in the store's projection,
//! [`Infallible`](core::convert::Infallible) in the mock — and is not a
//! verdict: `validate` hands it back *outside* its `Result<ChainValid,
//! InvalidBlock>`, and the caller halts. Inside a rule, `?` therefore
//! propagates a fault and only a fault; a refusal is written out at the site
//! that judged, naming its row. The fault type is opaque here by genericity
//! — no bound, so nothing in this crate can inspect, match, or convert it —
//! which is the conversion ban (G2) held by the type system and not by the
//! gate alone.
//!
//! # Absence is a case, not a `None`
//!
//! By-height reads return [`AtHeight`], not `Option`. Heights at or below the
//! tip are dense — the store's invariant — so the only absence a view can
//! report is *above the tip*, and a rule that reads the parent, the preceding
//! timestamps, or the membership anchor must say, at that arm, what it does
//! about it. `AtHeight` has nothing to fall through: an absent block is a
//! refusal the rule writes, never a pass it arrives at by `?` or
//! `unwrap_or_default`.

use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::BlockHeader;

/// A by-height lookup against the recorded chain.
///
/// Matched exhaustively. Deliberately **not** convertible to `Option`, and
/// without `map` / `unwrap_or_*` / `?` — the shapes by which an absence
/// becomes a silent pass in a diff that reads entirely reasonably:
///
/// ```compile_fail
/// # use shekyl_chain_rules::AtHeight;
/// let at: AtHeight<u8> = AtHeight::Recorded(1);
/// let _: Option<u8> = at.into(); // no such conversion
/// ```
///
/// ```compile_fail
/// # use shekyl_chain_rules::AtHeight;
/// fn read(at: AtHeight<u8>) -> Option<u8> { Some(at?) } // nothing for `?` to take
/// ```
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtHeight<T> {
    /// The chain recorded `T` at that height.
    Recorded(T),
    /// No block has been recorded at that height: it is above the tip.
    /// Heights at or below the tip are dense (the store's invariant, not a
    /// view fact), so this is the only absence a view can report.
    AboveTip,
}

/// A block the chain has recorded, as a rule reads it.
///
/// Every field is here because a named row reads it (round-1 ruling Q3):
/// `hash` — CEN-A2 (`prev_id` is the tip's hash), CEN-A4 (the parent is a
/// known block); `header` — CEN-C2, CEN-C3 (the timestamps of the eleven
/// preceding blocks). Fields grow with rows — cumulative difficulty and
/// weight arrive with 4.D / 4.G — never ahead of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedBlock {
    /// The block's identity, derived once when it was recorded (CEN-B6).
    pub hash: BlockHash,
    /// The header as recorded.
    pub header: BlockHeader,
}

/// The narrow, read-only view a rule consumes.
///
/// `'id` is the transaction brand (`WriteBatch<'_, 'id>`): a `ChainValid<'id>`
/// is minted only against a `ChainView<'id>` of the same `'id`, so a verdict
/// reached against one transaction's view cannot be honoured by another. The
/// trait has no `'id`-carrying method — the brand lives in the implementor's
/// type and in the verdict; the parameter is what ties the two together in
/// `validate`'s signature.
///
/// Implementors answer about the **recorded** chain only. A pool decorator
/// (DRS-E5) that also knows the pool's own key images implements this trait
/// over an inner view; this crate never names it.
pub trait ChainView<'id> {
    /// What the view's substrate can fail with. Opaque to every rule (no
    /// bound): the store's engine error for its projection,
    /// [`Infallible`](core::convert::Infallible) for the mock. A fault is
    /// not a verdict — see the module docs.
    type Fault;

    /// Whether `key_image` has been spent on the recorded chain.
    ///
    /// CEN-I7 (chain-wide key-image uniqueness); the chain half of CEN-L1.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Self::Fault>;

    /// The block recorded at `height`.
    ///
    /// CEN-A2, CEN-A4 (the parent, by hash); CEN-C2, CEN-C3 (the preceding
    /// timestamps).
    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Self::Fault>;

    /// The curve-tree root **as recorded after** the block at `height` — the
    /// membership anchor a spend that references `height` is verified against.
    ///
    /// CEN-I12.
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Self::Fault>;
}
