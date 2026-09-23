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

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_units::AtomicUnits;
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

/// The last recorded block: its height and identity.
///
/// `ChainView::tip()` returns `Option<Tip>` — `None` is the empty chain, and
/// the candidate is genesis. **`Option`, not a bespoke absence enum** (slice
/// 1, Q1, ruled 2026-09-16): a custom absence type earns its keep when its
/// absence case carries semantics the caller must act on — `AtHeight::
/// AboveTip` does (walk back; the state is not there) — and an empty chain
/// is one behaviour with no valid-looking alternative, so `None` cannot be
/// read as data. What `Option` does rule out is the C++ shape:
/// `top_block_hash` hands back **two** sentinels on an empty chain,
/// `null_hash` and `*block_height = UINT64_MAX`, neither distinguishable
/// from a recorded value (`db_lmdb.cpp:3185–3191`). The store's own read
/// (`RecordedTip { tip: Tip, connect }`, S-CHAIN-R) composes this struct.
///
/// Fields justified per ruling Q3: `hash` — CEN-A2 (`previous` must be the
/// tip's hash); `height` — the connecting height height-indexed rules
/// read (B5 here via [`Tip::connecting_height`]; 4.C and CEN-F5 later).
/// B1 does not read this: the rule set in force is an input the caller
/// chose with `rules_at(height)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    /// The tip's height.
    pub height: BlockHeight,
    /// The tip's identity (CEN-B6).
    pub hash: BlockHash,
}

impl Tip {
    /// The height a candidate connecting onto `tip` will have: `0` for an
    /// empty chain, `tip.height + 1` otherwise. Derived from the view and
    /// never from the candidate (CEN-F5: `txin_gen.height` is producer-
    /// chosen; the height operand is caller-derived), so every rule that is
    /// stated at "this block's height" reads it from one place.
    ///
    /// `u64::MAX` is unreachable — a dense chain of 2^64 blocks — so the
    /// saturation can never be observed; it is written rather than
    /// `unwrap`ped so no rule carries a panic path.
    ///
    /// Crate-private (`CHAIN_RULES_SLICE_1.md` §2): the connecting height is
    /// a rule's operand, and the store derives its own from `block_info`'s
    /// last key at `connect` (SI-2). A second consumer would be a reason to
    /// reopen, documented with its call site (rule 21), not a `pub` in
    /// advance.
    #[must_use]
    pub(crate) fn connecting_height(tip: Option<&Self>) -> BlockHeight {
        tip.map_or(BlockHeight::ZERO, |t| {
            BlockHeight::from_raw(t.height.to_raw().saturating_add(1))
        })
    }
}

/// A block the chain has recorded, as a rule reads it.
///
/// Every field is here because a named row reads it (round-1 ruling Q3):
/// `hash` — CEN-A2 (`prev_id` is the tip's hash), CEN-A4 (the parent is a
/// known block), CEN-D3 (the seed block's identity); `header` — CEN-C2,
/// CEN-C3 (the timestamps of the eleven preceding blocks), CEN-D4 (the
/// LWMA-1 window's timestamps); `cumulative_difficulty` — CEN-D4 (the
/// window's work); `coins_generated` — CEN-F13 (the parent's accumulator
/// is the subsidy curve's operand); `cumulative_tx_count` — CEN-F20 (two
/// prefix sums make the volume window). Weight arrives with 4.G; fields
/// grow with rows, never ahead of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedBlock {
    /// The block's identity, derived once when it was recorded (CEN-B6).
    pub hash: BlockHash,
    /// The header as recorded.
    pub header: BlockHeader,
    /// Work through this block: the parent's plus this block's target
    /// (`block_info.cumulative_difficulty`). Strictly increasing along the
    /// chain (SI-10); a rule that sees a decrease *or an equal pair*
    /// reports
    /// [`Corrupt::CumulativeDifficultyNotMonotone`](crate::Corrupt::CumulativeDifficultyNotMonotone).
    pub cumulative_difficulty: CumulativeDifficulty,
    /// Gross emission through this block (`block_info.coins_generated`):
    /// the parent's plus this block's paid reward. CEN-F13's operand — the
    /// subsidy curve reads the **parent's** value for a candidate at
    /// `parent + 1`. Gross, not net of burn: the curve is a function of
    /// what was issued (FL-R16c's net operand is the *burn ratio's*, a
    /// different quantity).
    pub coins_generated: AtomicUnits,
    /// Transactions listed in blocks `0..=this`, a prefix sum
    /// (`block_info.cumulative_tx_count`, S-CHAIN-W). CEN-F20's operand:
    /// `Σ tx_hashes.len()` over the prior `min(h, W)` blocks is the
    /// difference of two of these.
    pub cumulative_tx_count: u64,
}

/// The narrow, read-only view a rule consumes.
///
/// `'id` is the transaction brand (`WriteBatch<'_, 'id>`). `validate` mints
/// `ChainValid<'id, V>` so the verdict is branded with **both** the batch
/// lifetime and the view *type*. An unbranded `impl<'id> ChainView<'id> for
/// Evil` can still pick up a batch's `'id`, but `connect` will demand
/// `ChainValid<'id, StoreView<'_, 'id>>` and `Evil` will not unify. The trait
/// has no `'id`-carrying method — well-behaved implementors (the store
/// projection, the crate's test mock) put `'id` in their type; G4 is
/// closed at the token, not by sealing the trait (the store crate must
/// implement it, and this crate cannot name the store).
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

    /// The curve-tree state **at** chain height `height` — the root after
    /// the block at `height − 1` connected and **before** the block at
    /// `height` drained its own leaves. It is the membership anchor a spend
    /// that references `height` is verified against, and the root the header
    /// at `height` must carry (CEN-B5).
    ///
    /// Not the root *after* the block at `height`: that is the anchor for a
    /// reference to `height + 1`. The daemon keys this state at `height`
    /// (`store_curve_tree_root_at_height(prev_height + 1, …)` from the
    /// parent's connect), so an implementation reads its per-height table at
    /// `height`, never `height + 1` (S-CHAIN-W SCW-19).
    ///
    /// CEN-I12.
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Self::Fault>;

    /// The last recorded block, or `None` for an empty chain (genesis
    /// admission). See [`Tip`] for why `Option`.
    ///
    /// CEN-A2 (`hash`); B5 and later 4.C / CEN-F5 (`height`, via
    /// [`Tip::connecting_height`]).
    fn tip(&self) -> Result<Option<Tip>, Self::Fault>;
}
