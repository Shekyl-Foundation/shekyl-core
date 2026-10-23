// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-credit bundle rule: the pure verifier and the view it reads.
//!
//! Design: `docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §9.1 (admission, the ordered checks) and §9.6 (the verifier and its two
//! contracts). Three functions:
//!
//! - [`check_section`] — form, the window, then the budget. The references
//!   are in strictly ascending `h`, the header root recomputes from them,
//!   each names an `h` with `h < h_incl ≤ h + W₂` (`SCS-P41`), and their
//!   charges — `max(count, 1)` each, from the count each reference states
//!   (`SCS-P39`, `SCS-P40`) — fit `section_budget` over the largest `D`
//!   among the section's own epochs. `D` is
//!   [`DrawableEpoch::len`](shekyl_archival_retention::DrawableEpoch::len),
//!   read here from [`BundleView::drawable_epoch`]. The function takes no
//!   cap.
//! - [`check_section_until_switch`] — the same form and window checks at
//!   arrival, when this chain does not yet hold those epochs (`SCS-P23`).
//!   An empty section is admitted. Any other section that passes them
//!   waits: the budget comparison is [`check_section`]'s, at the switch.
//! - [`verify_bundle`] — everything else, for one bundle, against a
//!   [`BundleView`]: the window, one bundle per `h`, the bitmap and the
//!   record count, the `0x0C` opening, the witness signature, every draw's
//!   pair, and every record's receipt. It returns [`Admitted`]: the kept
//!   projection and every derived draw, which is all
//!   [`admission_plan`](crate::admission_plan) needs (`SCS-P37`).
//!
//! All three are pure. None names a store type, and none writes.
//!
//! # Disposition: STAGED — nothing on the connect path calls this
//!
//! Rule `23-disposition-visibility`: staged work is code with a named consumer in a live plan.
//!
//! - **What is here:** the verifier, [`judge_bundles`], the view trait, the
//!   fixture, and the unbound rule types `rules::bundle_admission::J29`
//!   through `J37`. Increment 4a also implements the view on the store
//!   (`shekyl-chain-store`'s `StoreBundleView`, the batch view plus the
//!   drawable memo). The census rows stay `pending`.
//! - **What is not:** `form` and `validate` do not call them. The rule
//!   types are not bound. A block that carries a bundle section is not
//!   judged by this module today.
//! - **Who calls it, and when:** increment 4b, after the DRS-X flip
//!   (`docs/design/ARCHIVAL_SETTLEMENT_WRITER.md` §16; `SCS-P31`): it calls
//!   [`judge_bundles`] from `validate`, binds the rows, and deletes the
//!   attestation path (CEN-B4). [`check_section`] takes that view, the
//!   block's height and its rule set; the cap is the section's. DRS-E5 is transport
//!   (`docs/design/DRS_E5_POOL_ALT_PRUNE.md` §2.2, §2.3). Its alternative
//!   tier has landed ([`crate::alt_against`]) and does not call this
//!   module: an alternative block's row still carries the attestation
//!   witness, not bundle references. When E5 replaces that with
//!   references, an arrival that can see the chain calls [`open_reference`]
//!   and [`check_section`]: an epoch above the fork has no `D`, and one
//!   such epoch waits the whole section (`SCS-P23`). The window check
//!   comes first, so only an epoch of a reference inside the window can do
//!   that (`SCS-P41`).
//!   [`check_section_until_switch`] is that form when the arrival has no
//!   view. At the switch, `validate` runs [`check_section`] and
//!   [`verify_bundle`] over the switch's batch view, on which E5 implements
//!   [`BundleView`]. A body that cannot be fetched before the switch is no
//!   switch and no verdict, which is [`BundleRefused::BodyNotReferenced`]'s
//!   side of the same line. The body store and the bundle queue are not
//!   built; the queue will run these functions against the tip.
//! - **The census rows** these refusals name, CEN-J29 through CEN-J37, are
//!   registered `pending` for the same reason: a `pending` row is in the
//!   denominator and no rule type is bound to it. The cutover flips them.
//! - **The falsifier of "staged":** `nothing_on_the_connect_path_calls_the_bundle_verifier`
//!   reads every non-test source of this crate but the fixture, the
//!   registry, `archival/bundle.rs`, `archival/bundle_records.rs` and
//!   `archival/bundle_section.rs`, and fails when any other names this
//!   module's functions, apart from the one `pub use` in `archival/mod.rs`
//!   and `lib.rs` that exports them.
//!   The section file stays exempt only while it holds `check_section`.
//!   It requires `validate.rs`,
//!   `block.rs`, `alt.rs`, `header_ladder.rs`, `drain.rs`, `archival/mod.rs`
//!   and `rules/mod.rs` by name, so the walk cannot shrink silently. The
//!   cutover deletes that test in the change that wires them.
//!
//! # One name: `DrawableEpoch`
//!
//! The `h_open(E)` value is `shekyl_archival_retention::DrawableEpoch`,
//! the read is [`BundleView::drawable_epoch`], the hole is
//! [`BundleUnanswered::DrawableEpoch`], and the fixture's read log and map
//! carry the same word. The specification's §9.6 first called this value
//! `EpochSnapshot`. This crate already uses that name for the emission
//! gather in `archival/close.rs`, a different value the same judgement
//! reaches at the cutover, so the verifier's type is `DrawableEpoch`.
//!
//! # What the cutover's view has to read, as `dev` stands
//!
//! `SO-D12`'s increment 1 landed the state two of the view's six reads
//! come from; this module names it so the cutover's `BundleView` impl is
//! a projection and not a design.
//!
//! - [`BundleView::draw_count`] and [`BundleView::revealed`] are one row:
//!   `ChainView::block_draws(h)`, a `BlockDraws` whose `count` is already
//!   the `u32` this trait asks for and whose `revealed` is the
//!   one-per-`h` flag. The window check has already put `h` below
//!   `h_incl`, so `h` is a block of this chain, and a height with no row is
//!   the view failing to answer: [`BundleUnanswered::DrawCount`], not a
//!   verdict (`SCS-P42`). No block writes the row before admission lands,
//!   so a cutover that left a height without one would otherwise refuse
//!   honest bundles. `carry` and `shortfall` on the same row are the count
//!   rule's, and this rule does not read them.
//! - [`BundleView::draw_commitment`] is the coinbase's singular `0x0C`
//!   field. Above the tip the view answers `None`, and the rule returns
//!   [`BundleUnanswered::DrawCommitment`]. A recorded block whose extra
//!   does not yield exactly one commitment is the store's halt (SI-38),
//!   not a verdict: [`BundleInvalid::Commitment`] is the mismatch and
//!   nothing else. The coinbase grammar (CEN-I20) is `form`'s, and this
//!   read does not re-run it.
//! - `ChainView::drawable_digest(E)` is **not** one of this rule's reads.
//!   It is the settlement writer's check that `D` did not drift
//!   (specification §9.5, check 2). What this rule reads of `D` is
//!   [`BundleView::drawable_epoch`]: its length is the section budget's
//!   `D`, and the bundle rule indexes the same value. Its builder is
//!   `SO-D12`'s increment 2.
//! - [`BundleView::block_hash`] is the recorded block's hash, and
//!   [`BundleView::visibly_short`] is a count over the issued-draw index
//!   with `h_reveal < h`; neither table read is new with this rule.
//!
//! # Why this module and not `rules/`
//!
//! `rules/` holds one unit type per census row, each a `Rule` that `form`
//! or `validate` runs from a list and that the registry pins with
//! `implemented(path)`. These functions are neither run nor pinned, and
//! their view is not [`crate::ChainView`]. `archival/` already holds the
//! builder of the drawable set this rule indexes
//! ([`drawable_epoch_walked_back`](super::drawable_epoch_walked_back)) and
//! the settlement fold that consumes what admission writes. The rule types
//! that succeed CEN-B4 land in `rules/` at the cutover and call into here.
//!
//! # Precondition on the rule set: `W₂ + L ≤` anchor depth
//!
//! Step 8 refuses a record whose `anchor_height` is not below `h`
//! (CEN-J36, `SCS-P32`). An honest read satisfies that only because the
//! response window plus the anchor lag does not exceed the anchor depth,
//! and `W₂` is rule-set data. The relation is
//! [`RuleSet::anchor_covers_response_window`], and it is held where rule
//! sets are made, not here: on the production constants where they are
//! defined (`shekyl-archival-retention`, `pass_anchor.rs`), on every
//! issued set at compile time, and on a Fakechain set by
//! `FakechainSchedule::new`, which refuses a pair that breaks it with a
//! typed error. So every `rule_set` this function can be
//! handed satisfies it. [`verify_bundle`] does not re-check it: under a
//! set that broke it the rule would still be the rule, and honest
//! producers would be the ones refused.
//!
//! # Three answers, three positions
//!
//! As everywhere in this crate, a refusal is not a fault
//! (`view.rs`, "Three answers, three positions"). [`BundleRefused`] keeps
//! them in separate arms, and only one of them is a verdict:
//!
//! - [`BundleRefused::Invalid`] — judged and refused. A
//!   [`BundleInvalid`] names its census row and, for a record, the draw.
//! - [`BundleRefused::BodyNotReferenced`] — the body offered is not the
//!   body the reference names. Nothing was judged: the caller holds the
//!   wrong bytes and fetches again.
//! - [`BundleRefused::Unanswered`] — the view answered for `h` and then
//!   had no answer for something a chain that holds `h` must hold. A
//!   state no conforming view presents; never a verdict.
//! - [`BundleRefused::View`] — the view's own fault.
//!
//! # The order of the checks
//!
//! §9.1 fixes it, and the order decides which refusal a caller observes.
//! [`verify_bundle`] reads the view lazily, each read at the step that
//! needs it, so a bundle refused at step `n` has cost no read and no
//! signature verification of a later step. In particular a body the
//! producer did not sign costs one witness-signature verification and no
//! receipt verification (§9.1, "What a forged bundle can cost a node").

use core::fmt;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use shekyl_archival_retention::{
    draw_commit, select_draw, BundleBody, BundleKept, BundleRef, BundleWireError, DrawableEpoch,
    DrawablePair,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{SignatureScheme as _, SCHEME_DOMAIN_WITNESS_BUNDLE};
use shekyl_types::archival::{DrawCommitment, ReceiptSignPk};
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId, SettlementEpoch};

use crate::census::CenRow;
use crate::rule_set::RuleSet;

/// Everything the bundle rule reads: one method for each thing §9.1 reads,
/// and nothing else (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.6).
///
/// Every answer is a function of the chain through `h`, except
/// [`revealed`](Self::revealed), which is the one-per-`h` rule. That is
/// §9.1's reorg property stated as an interface: a bundle that was valid
/// in a popped block is valid again on any chain that keeps `h`, while its
/// window lasts.
///
/// `D`, as a number, is the drawable epoch's length. The view has no second
/// source for it.
///
/// The store's view, the switch's batch view and the test fixture each
/// implement this. None exists in production yet (module docs).
pub trait BundleView {
    /// The view's own failure to answer. Never a verdict.
    type Fault;

    /// `count(h)`, as written when `h` connected (§4.3). `None`: the view
    /// holds no count for `h`. Every `h` this is asked about is below the
    /// including block, so that is the view's failure, never a verdict
    /// ([`BundleUnanswered::DrawCount`]).
    ///
    /// A draw index `j` is 32 bits (§3), so a count is. A store that holds
    /// it wider refuses a value that does not fit; it does not truncate.
    fn draw_count(&self, h: BlockHeight) -> Result<Option<u32>, Self::Fault>;

    /// `h`'s `0x0C` commitment (§4.2), as a [`DrawCommitment`]. `None` is
    /// the view failing to answer, not an absent field: CEN-I20 puts one
    /// on every coinbase, and the all-zero genesis commitment is still one.
    fn draw_commitment(&self, h: BlockHeight) -> Result<Option<DrawCommitment>, Self::Fault>;

    /// The hash of the block at `height` on this chain. Read twice: at
    /// `h`, for the selection and the nonce, and at each record's
    /// `anchor_height`, for the receipt's transcript.
    fn block_hash(&self, height: BlockHeight) -> Result<Option<BlockHash>, Self::Fault>;

    /// Whether the pair at `index` in `D` is visibly short at `h`: fewer
    /// than 3 of its draws in `epoch(h)` issued by bundles admitted in
    /// blocks below `h` (§3). This is the issued counts visible at `h`, in
    /// the one form the selection asks for.
    fn visibly_short(&self, h: BlockHeight, index: u64) -> Result<bool, Self::Fault>;

    /// Whether a bundle for `h` is already admitted on this chain.
    fn revealed(&self, h: BlockHeight) -> Result<bool, Self::Fault>;

    /// The [`DrawableEpoch`] at `h_open(E)`: `D`, and each pair's receipt key,
    /// as one value (`SCS-P19`).
    fn drawable_epoch(&self, epoch: SettlementEpoch)
        -> Result<Option<&DrawableEpoch>, Self::Fault>;

    /// How many support draws `h` issued, as written when `h` connected.
    /// `None` is the view's hole, the same way a missing economy count is:
    /// a written zero is a block that issued none, and an absent row is
    /// not that zero.
    fn support_count(&self, h: BlockHeight) -> Result<Option<u32>, Self::Fault>;

    /// The complete trees scheduled at `h`, in persona order. Bit `j` of
    /// the support bitmap is entry `j`. `None` is the view's hole. The
    /// verifier asks only when [`Self::support_count`] is not zero.
    fn support_roster(&self, h: BlockHeight) -> Result<Option<Vec<SupportSeat>>, Self::Fault>;

    /// The archive width the support draw selects a shard from. `None` is
    /// the view's hole. Asked only when the block issued support draws.
    fn archive_width(&self, h: BlockHeight) -> Result<Option<u64>, Self::Fault>;
}

/// One complete tree scheduled at a block: the persona and the receipt
/// key the support bitmap's bit verifies under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportSeat {
    /// The tree.
    pub persona: PCanonicalId,
    /// Its receipt key, as the bond record carries it.
    pub receipt_key: ReceiptSignPk,
}

/// The section checker: form, the window, then the budget. The only
/// admission path. `bundle_section::inside_window` is the window
/// [`verify_bundle`] asks too.
#[path = "bundle_section.rs"]
mod bundle_section;

/// The attempt, anchor and receipt passes both streams share.
#[path = "bundle_records.rs"]
mod records;

pub use bundle_section::{
    check_section, check_section_until_switch, open_reference, SectionCharge, SectionCheckFailed,
    SectionRefused, SectionStanding,
};

/// `epoch`'s drawable epoch, if the view holds the one filed for it. A
/// value filed under another epoch is not this epoch's `D`, and the
/// caller treats it as absent.
fn drawable_for<V: BundleView>(
    view: &V,
    epoch: SettlementEpoch,
) -> Result<Option<&DrawableEpoch>, V::Fault> {
    Ok(view
        .drawable_epoch(epoch)?
        .filter(|drawable| drawable.epoch() == epoch))
}

/// Why one bundle is refused: the verdict. Each arm names its census row
/// ([`Self::row`]) and, for a record, the draw that failed
/// ([`Self::draw`]).
///
/// The arms are in the order [`verify_bundle`] can raise them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BundleInvalid {
    /// The prunable part is not the witness key, the witness signature and
    /// whole records. Raised by [`open_body`] alone. CEN-J32.
    BodyMalformed,
    /// Not `h < h_incl ≤ h + W₂` — or the rule set's epoch is too short to
    /// have a window, and nothing is inside a window that does not exist.
    /// CEN-J31.
    OutsideWindow,
    /// A bundle for `h` is already admitted on this chain. CEN-J31.
    AlreadyRevealed,
    /// The count the reference states is not the chain's `count(h)`
    /// (`SCS-P39`). The bitmap is exactly as long as its stated count by
    /// construction, so this is the whole of "the bitmap is exactly
    /// `count(h)` bits" — and it is what refuses a reference that
    /// understated its count to pass the section budget. CEN-J32.
    Count,
    /// The number of records is not the number of set bits. CEN-J32.
    RecordCount,
    /// `draw_commit(witness_pk, seed)` is not `h`'s `0x0C`. A view that has
    /// no `0x0C` for `h` is not this arm: every coinbase carries one
    /// (CEN-I20), so that is [`BundleUnanswered::DrawCommitment`]. CEN-J33.
    Commitment,
    /// The witness key or signature is not a scheme-3 key or signature, or
    /// the signature does not verify over the bundle commitment. CEN-J34.
    WitnessSignature,
    /// A record's `attempt` is `K` or more. CEN-J35.
    Attempt {
        /// The draw whose record it is.
        draw: u32,
    },
    /// A record's `anchor_height` is not below `h` (`SCS-P32`). CEN-J36.
    Anchor {
        /// The draw whose record it is.
        draw: u32,
    },
    /// A record's receipt is not a scheme-3 signature, or does not verify
    /// under the derived pair's receipt key over the transcript. CEN-J37.
    Receipt {
        /// The draw whose record it is.
        draw: u32,
    },
}

impl BundleInvalid {
    /// The census row this refusal is a verdict under.
    #[must_use]
    pub const fn row(&self) -> CenRow {
        match self {
            Self::OutsideWindow | Self::AlreadyRevealed => CenRow::J31,
            Self::BodyMalformed | Self::Count | Self::RecordCount => CenRow::J32,
            Self::Commitment => CenRow::J33,
            Self::WitnessSignature => CenRow::J34,
            Self::Attempt { .. } => CenRow::J35,
            Self::Anchor { .. } => CenRow::J36,
            Self::Receipt { .. } => CenRow::J37,
        }
    }

    /// The draw `j` whose record failed, for a refusal of one record.
    #[must_use]
    pub const fn draw(&self) -> Option<u32> {
        match self {
            Self::Attempt { draw } | Self::Anchor { draw } | Self::Receipt { draw } => Some(*draw),
            _ => None,
        }
    }
}

impl fmt::Display for BundleInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} refused: ", self.row())?;
        match self {
            Self::BodyMalformed => f.write_str("the body is not a witness and whole records"),
            Self::OutsideWindow => {
                f.write_str("the including block is outside the bundle's window")
            }
            Self::AlreadyRevealed => f.write_str("a bundle for this block is already admitted"),
            Self::Count => f.write_str("the reference's count is not the block's draw count"),
            Self::RecordCount => f.write_str("the records are not one per set bit"),
            Self::Commitment => {
                f.write_str("the witness key and seed do not open the block's 0x0C")
            }
            Self::WitnessSignature => f.write_str("the witness signature does not verify"),
            Self::Attempt { draw } => write!(f, "draw {draw}'s record names a read past the last"),
            Self::Anchor { draw } => write!(f, "draw {draw}'s record is anchored at or above h"),
            Self::Receipt { draw } => write!(f, "draw {draw}'s receipt does not verify"),
        }
    }
}

impl std::error::Error for BundleInvalid {}

/// Something a chain that holds block `h` must hold, and the view did not
/// answer for. Not a verdict ([`BundleRefused::Unanswered`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BundleUnanswered {
    /// No draw count for `h`, which the window check has put below the
    /// including block, so it is a block of this chain and its count was
    /// written when it connected (`SCS-P42`).
    DrawCount {
        /// The block asked about: `h`.
        height: BlockHeight,
    },
    /// No drawable epoch for the epoch of a block that has draws — or
    /// one of another epoch.
    DrawableEpoch {
        /// `epoch(h)`.
        epoch: SettlementEpoch,
    },
    /// No `0x0C` commitment for `h`, whose draw count the view answered.
    /// The coinbase grammar requires exactly one in every block
    /// (CEN-I20), so a block of the chain cannot lack it.
    DrawCommitment {
        /// The block asked about: `h`.
        height: BlockHeight,
    },
    /// No hash for a block at or below `h`.
    BlockHash {
        /// The height asked.
        height: BlockHeight,
    },
    /// A block has draws and its epoch's drawable set is empty, or the
    /// selection named an index the drawable epoch does not hold.
    Draw {
        /// The draw that could not be derived.
        draw: u32,
    },
}

/// What [`verify_bundle`] returns when it does not admit: the verdict, or
/// one of three things that are not a verdict (module docs, "Three
/// answers, three positions").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleRefused<F> {
    /// Judged and refused: the bundle is invalid, and so is the block that
    /// includes it.
    Invalid(BundleInvalid),
    /// The body's prunable hash is not the reference's. The reference is
    /// what the block committed to, so this says nothing about the block:
    /// the caller holds the wrong bytes. A body is accepted on hash
    /// equality (§7.5); a block whose body cannot be had is never
    /// connected, not refused.
    BodyNotReferenced,
    /// The view answered for `h` and then did not answer for something a
    /// chain that holds `h` must hold. A view defect, never a verdict.
    Unanswered(BundleUnanswered),
    /// The view faulted.
    View(F),
}

impl<F> BundleRefused<F> {
    /// The verdict, if this is one.
    #[must_use]
    pub const fn verdict(&self) -> Option<&BundleInvalid> {
        match self {
            Self::Invalid(invalid) => Some(invalid),
            _ => None,
        }
    }
}

impl<F> From<F> for BundleRefused<F> {
    /// A view method's error, lifted into its own arm. It cannot become a
    /// verdict by `?`: the verdict arm is written at the site that judged.
    fn from(fault: F) -> Self {
        Self::View(fault)
    }
}

impl<F: fmt::Display> fmt::Display for BundleRefused<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(invalid) => write!(f, "{invalid}"),
            Self::BodyNotReferenced => f.write_str("the body is not the one the reference names"),
            Self::Unanswered(BundleUnanswered::DrawCount { height }) => {
                write!(f, "the view has no draw count at height {height}")
            }
            Self::Unanswered(BundleUnanswered::DrawableEpoch { epoch }) => {
                write!(f, "the view has no drawable epoch for epoch {epoch}")
            }
            Self::Unanswered(BundleUnanswered::DrawCommitment { height }) => {
                write!(f, "the view has no 0x0C commitment at height {height}")
            }
            Self::Unanswered(BundleUnanswered::BlockHash { height }) => {
                write!(f, "the view has no block hash at height {height}")
            }
            Self::Unanswered(BundleUnanswered::Draw { draw }) => {
                write!(f, "draw {draw} has no pair in the view's drawable epoch")
            }
            Self::View(fault) => write!(f, "view fault: {fault}"),
        }
    }
}

impl<F: fmt::Debug + fmt::Display> std::error::Error for BundleRefused<F> {}

/// One draw of `h`: the pair it selected and whether it passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedDraw {
    /// The pair's position in `D`.
    pub index: u64,
    /// The pair, as the drawable epoch holds it at that position.
    pub pair: DrawablePair,
    /// The draw's bit in the bundle's bitmap.
    pub passed: bool,
}

/// What the verifier returns on success, and all
/// [`admission_plan`](crate::admission_plan) needs
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.6, `SCS-P37`).
///
/// [`admission_plan`](crate::admission_plan) turns `draws` into index rows
/// `(E, P, s, h, j) → (h_incl, passed)`, the epoch digest's terms, the
/// heights revealed and `issued_short`. The store journals that plan and
/// derives none of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The bundle's kept bytes, parsed: the reference's content.
    pub kept: BundleKept,
    /// One entry per economy draw `j` of `h`, in order — passes and misses both.
    pub draws: Vec<DerivedDraw>,
    /// One entry per support draw of `h`. Not serve credit: the writer
    /// that turns [`Self::draws`] into credit rows does not read this.
    pub support: Vec<SupportObservation>,
}

/// A support draw the verifier accepted. It is not an economy draw and
/// it writes no serve credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportObservation {
    /// The tree.
    pub persona: PCanonicalId,
    /// The shard the draw named.
    pub shard: shekyl_types::ShardId,
    /// Its index in the block's support bitmap.
    pub draw: u32,
    /// Whether the bitmap says it passed.
    pub passed: bool,
}

/// The body a reference names, from bytes a store or a peer returned.
///
/// Checked by hash first, so a mutated body is refused before it is
/// parsed (§9.1); then parsed. The hash decides whether these are the
/// reference's bytes at all; the parse decides whether the block that
/// committed to them is valid.
///
/// # Errors
///
/// [`BundleRefused::BodyNotReferenced`] when the bytes do not hash to the
/// reference's prunable hash; [`BundleInvalid::BodyMalformed`] when they
/// do and are not a witness key, a witness signature and whole records.
pub fn open_body<F>(reference: &BundleRef, bytes: &[u8]) -> Result<BundleBody, BundleRefused<F>> {
    if shekyl_archival_retention::bundle_prunable_hash(bytes) != *reference.prunable_hash() {
        return Err(BundleRefused::BodyNotReferenced);
    }
    BundleBody::decode(bytes)
        .map_err(|_: BundleWireError| BundleRefused::Invalid(BundleInvalid::BodyMalformed))
}

/// Everything but the section check, for one bundle: §9.1 steps 3 to 8, in
/// that order. Receipts included.
///
/// `h_incl` is the block that includes the bundle. `view` is the chain it
/// connects to, and `rule_set` the set in force there: the window `W₂` and
/// `epoch(h)` are read off its settlement schedule, never off a constant.
///
/// Before step 3 the body is held to the reference's prunable hash
/// ([`BundleRefused::BodyNotReferenced`]). Then:
///
/// 3. **Structure.** `h < h_incl ≤ h + W₂`; no bundle for `h` is admitted;
///    the count the reference states is `count(h)` (its bitmap is that
///    many bits, padding clear, since it was decoded); the records are one
///    per set bit.
/// 4. **Commitment.** `draw_commit(witness_pk, seed)` is `h`'s `0x0C`.
/// 5. **Witness signature.** It verifies under the witness key, scheme 3,
///    `SCHEME_DOMAIN_WITNESS_BUNDLE`, over the bundle commitment.
/// 6. **Every draw's pair** — for all `j < count(h)`, not only the set
///    bits, because [`Admitted::draws`] carries every draw — by
///    `select_draw` over the drawable epoch's length and the view's
///    `visibly_short`.
/// 7. **Each record's structure**, on both streams, before any receipt.
///    `attempt` is below `K`. Then `anchor_height < h`, and the view has
///    that block's hash. Economy set bits, then support set bits.
/// 8. **Each record's receipt**, in that same order: the 113-byte
///    transcript `stream ‖ nonce ‖ anchor_height_le ‖
///    block_hash(anchor_height) ‖ shard_id_le ‖ delivery_digest` verifies
///    under that stream's receipt key, scheme 3,
///    `SCHEME_DOMAIN_RECEIPT`, with the nonce recomputed from `(seed,
///    block_hash(h), j, attempt)`. The transcript and the domain are
///    [`shekyl_archival_retention::verify_receipt_transcript`]'s, the one
///    body the fetch client's scheme-3 target also calls; this module
///    builds neither.
///
/// Step 7 runs over every record of both streams before step 8 runs over
/// any: a bundle with an inadmissible `attempt` or anchor is refused for
/// it whatever its receipts say. The receipt key is opened in step 8, so
/// a missing key cannot hide an earlier attempt or anchor.
///
/// # Errors
///
/// [`BundleRefused`]: the verdict naming the first check that failed, or
/// one of its three non-verdict arms.
pub fn verify_bundle<V: BundleView>(
    reference: &BundleRef,
    body: &BundleBody,
    h_incl: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Admitted, BundleRefused<V::Fault>> {
    let invalid = |why: BundleInvalid| Err(BundleRefused::Invalid(why));
    let h = reference.h();
    let schedule = rule_set.settlement_schedule();

    if body.prunable_hash() != *reference.prunable_hash() {
        return Err(BundleRefused::BodyNotReferenced);
    }

    // 3. Structure. `W₂` is the only window; there is no read window.
    if !bundle_section::inside_window(h, h_incl, schedule) {
        return invalid(BundleInvalid::OutsideWindow);
    }
    if view.revealed(h)? {
        return invalid(BundleInvalid::AlreadyRevealed);
    }
    // `h` is below `h_incl`, so it is a block of this chain and its count
    // was written when it connected: no count is the view's hole, not a
    // verdict (`SCS-P42`).
    let Some(count) = view.draw_count(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::DrawCount {
            height: h,
        }));
    };
    if reference.count() != count {
        return invalid(BundleInvalid::Count);
    }
    let kept = reference.kept().clone();
    // Zero is a count on both streams. An empty support bitmap over a
    // block that issued support draws is the same refusal as an economy
    // bitmap that understates `count(h)`, and it is refused here, before
    // the commitment, rather than accepted as an empty observation list.
    support_width(view, h, kept.support.count())?;
    let economy_records = usize::try_from(kept.passes.popcount()).unwrap_or(usize::MAX);
    let support_records = usize::try_from(kept.support.popcount()).unwrap_or(usize::MAX);
    if economy_records.saturating_add(support_records) != body.record_count() {
        return invalid(BundleInvalid::RecordCount);
    }

    // 4. Commitment. Until the producer releases its bundle nobody else
    // can open `h`'s `0x0C`, so this is checked before either signature.
    // No `0x0C` for a block the view just gave a draw count for is the
    // view's hole, not the block's defect: CEN-I20 puts one in every
    // coinbase.
    let Some(committed) = view.draw_commitment(h)? else {
        return Err(BundleRefused::Unanswered(
            BundleUnanswered::DrawCommitment { height: h },
        ));
    };
    if DrawCommitment::from_bytes(draw_commit(body.witness_public_key(), &kept.seed)) != committed {
        return invalid(BundleInvalid::Commitment);
    }

    // 5. Witness signature, before any receipt.
    let scheme = HybridEd25519FnDsa;
    let (Ok(witness_key), Ok(witness_signature)) = (
        FnDsaHybridPublicKey::from_canonical_bytes(body.witness_public_key()),
        FnDsaHybridSignature::from_canonical_bytes(body.witness_signature()),
    ) else {
        return invalid(BundleInvalid::WitnessSignature);
    };
    let commitment = kept.commitment(body.records_bytes());
    if scheme
        .verify(
            &witness_key,
            SCHEME_DOMAIN_WITNESS_BUNDLE,
            &commitment,
            &witness_signature,
        )
        .is_err()
    {
        return invalid(BundleInvalid::WitnessSignature);
    }

    // A block with no economy draws issues nothing on that stream
    // (`SCS-P33`). The support width was matched above, so an empty
    // support bitmap here is a block that issued none of those either.
    // Both streams' records are judged together below, so a support
    // `attempt` is not hidden behind an economy receipt.
    let (draws, drawable, hash_at_h) = if count == 0 {
        if kept.support.count() == 0 {
            return Ok(Admitted {
                kept,
                draws: Vec::new(),
                support: Vec::new(),
            });
        }
        let Some(hash_at_h) = view.block_hash(h)? else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::BlockHash {
                height: h,
            }));
        };
        (Vec::new(), None, hash_at_h)
    } else {
        // 6. Every draw's pair, at the issued counts visible at `h`.
        let epoch = schedule.epoch_at(h);
        let Some(drawable) = drawable_for(view, epoch)? else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::DrawableEpoch {
                epoch,
            }));
        };
        let Some(hash_at_h) = view.block_hash(h)? else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::BlockHash {
                height: h,
            }));
        };
        let draws = derive_draws(view, drawable, &kept, hash_at_h.as_bytes(), count)?;
        (draws, Some(drawable), hash_at_h)
    };

    let mut passes = Vec::new();
    records::bind_economy(&mut passes, &kept, body, &draws)?;
    let support = records::bind_support(
        view,
        &kept,
        body,
        hash_at_h.as_bytes(),
        economy_records,
        &mut passes,
    )?;
    // 7 then 8. Both streams: attempts, then anchors, then receipts.
    records::judge_passes(view, &kept, hash_at_h.as_bytes(), &passes, drawable)?;

    Ok(Admitted {
        kept,
        draws,
        support,
    })
}

/// The support bitmap's width against the count the block issued.
///
/// Called once, with the economy count already matched, and before the
/// commitment. A written zero is a block that issued none, so an
/// economy-only bundle still admits. `None` is the view's hole, the same
/// way a missing economy count is: it is not a written zero.
fn support_width<V: BundleView>(
    view: &V,
    h: BlockHeight,
    stated: u32,
) -> Result<(), BundleRefused<V::Fault>> {
    let Some(issued) = view.support_count(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::DrawCount {
            height: h,
        }));
    };
    if stated != issued {
        return Err(BundleRefused::Invalid(BundleInvalid::Count));
    }
    Ok(())
}

/// Step 6: draw `j`'s pair for every `j < count`, by the production
/// selection over the drawable epoch's length.
///
/// `select_draw` asks whether an index is visibly short and returns that
/// read's fault as its own error, so a fault is not a selection. Answers
/// are remembered for the bundle: an index asked twice is read once.
fn derive_draws<V: BundleView>(
    view: &V,
    drawable: &DrawableEpoch,
    kept: &BundleKept,
    hash_at_h: &[u8; 32],
    count: u32,
) -> Result<Vec<DerivedDraw>, BundleRefused<V::Fault>> {
    let mut asked: BTreeMap<u64, bool> = BTreeMap::new();
    let mut short = |index: u64| -> Result<bool, V::Fault> {
        match asked.entry(index) {
            Entry::Occupied(known) => Ok(*known.get()),
            Entry::Vacant(slot) => {
                let answer = view.visibly_short(kept.h, index)?;
                slot.insert(answer);
                Ok(answer)
            }
        }
    };

    // A `u32` into a `usize` is lossless on every target the workspace
    // builds for.
    let mut draws = Vec::with_capacity(count as usize);
    for draw in 0..count {
        let selected = select_draw(&kept.seed, hash_at_h, draw, drawable.len(), &mut short)
            .map_err(BundleRefused::View)?;
        let unanswered = BundleRefused::Unanswered(BundleUnanswered::Draw { draw });
        let Some(selected) = selected else {
            return Err(unanswered);
        };
        let Some(pair) = drawable.pair(selected.index) else {
            return Err(unanswered);
        };
        draws.push(DerivedDraw {
            index: selected.index,
            pair,
            passed: kept.passes.get(draw),
        });
    }
    Ok(draws)
}

/// Why [`judge_bundles`] stopped. A section refusal is J29–J31; a bundle
/// refusal is the verifier's, at the reference it stopped on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionFault<F> {
    /// The section check refused the block before any bundle was opened.
    Section(SectionRefused),
    /// Some epoch's `D` is not on this view. A connected chain's view does
    /// not answer that way: a memo miss is [`Self::View`].
    Awaiting,
    /// [`BundleView`] faulted. A memo miss on the store view is this.
    View(F),
    /// Bundle `at` in section order was refused.
    Bundle {
        /// The reference's position.
        at: usize,
        /// The verifier's refusal.
        refused: BundleRefused<F>,
    },
}

impl<F> AdmissionFault<F> {
    /// The census row, when the fault is a verdict. A view fault and a
    /// body the reference does not name have none.
    #[must_use]
    pub fn row(&self) -> Option<CenRow> {
        match self {
            Self::Section(refused) => Some(refused.row()),
            Self::Bundle {
                refused: BundleRefused::Invalid(invalid),
                ..
            } => Some(invalid.row()),
            Self::Awaiting | Self::View(_) | Self::Bundle { .. } => None,
        }
    }
}

/// Section first, then each body in section order, stopping at the first
/// refusal (`SO-D12` increment 4a).
///
/// The block wire does not carry a section yet (4b), so the staged entry
/// takes the references and bodies the section will hold. Tests call this.
/// `form` and `validate` do not.
///
/// # Errors
///
/// The first section or bundle refusal, or the view's fault.
pub fn judge_bundles<V: BundleView>(
    refs: &[BundleRef],
    bodies: &[BundleBody],
    header_root: &[u8; 32],
    h_incl: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Vec<Admitted>, AdmissionFault<V::Fault>> {
    match check_section(refs, header_root, h_incl, view, rule_set) {
        Ok(SectionStanding::Admitted(_)) => {}
        Ok(SectionStanding::Awaiting(_)) => return Err(AdmissionFault::Awaiting),
        Err(SectionCheckFailed::Refused(refused)) => {
            return Err(AdmissionFault::Section(refused));
        }
        Err(SectionCheckFailed::View(fault)) => return Err(AdmissionFault::View(fault)),
    }
    if bodies.len() != refs.len() {
        return Err(AdmissionFault::Bundle {
            at: bodies.len().min(refs.len()),
            refused: BundleRefused::BodyNotReferenced,
        });
    }
    let mut admitted = Vec::with_capacity(refs.len());
    for (at, (reference, body)) in refs.iter().zip(bodies.iter()).enumerate() {
        match verify_bundle(reference, body, h_incl, view, rule_set) {
            Ok(one) => admitted.push(one),
            Err(refused) => return Err(AdmissionFault::Bundle { at, refused }),
        }
    }
    Ok(admitted)
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod bundle_tests;

#[cfg(test)]
#[path = "bundle_section_tests.rs"]
mod bundle_section_tests;

#[cfg(test)]
#[path = "bundle_staging_tests.rs"]
mod bundle_staging_tests;

#[cfg(test)]
#[path = "bundle_admission_tests.rs"]
mod bundle_admission_tests;
