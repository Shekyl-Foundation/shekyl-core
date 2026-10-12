// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-credit bundle rule: the pure verifier and the view it reads.
//!
//! Design: `docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §9.1 (admission, the ordered checks) and §9.6 (the verifier and its two
//! contracts). Two functions:
//!
//! - [`check_section`] — stateless: a block's references are in strictly
//!   ascending `h`, the header root recomputes from them, and their
//!   charges — `max(count, 1)` each, from the count each reference states
//!   (`SCS-P39`, `SCS-P40`) — fit the section budget when the budget is
//!   known. It reads no chain, so it runs on an alternative block at
//!   arrival (`SCS-P23`), and it returns the section's charge either way,
//!   for the caller that learns `D` only at the switch.
//! - [`verify_bundle`] — everything else, for one bundle, against a
//!   [`BundleView`]: the window, one bundle per `h`, the bitmap and the
//!   record count, the `0x0C` opening, the witness signature, every draw's
//!   pair, and every record's receipt. It returns [`Admitted`]: the kept
//!   projection and every derived draw, which is all the writer needs
//!   (`SCS-P37`).
//!
//! Both are pure. Neither names a store type, and neither writes.
//!
//! # Disposition: STAGED — nothing on the connect path calls this
//!
//! Rule `23-disposition-visibility`: staged work is code with a named consumer in a live plan.
//!
//! - **What is here:** the two functions, their refusal types, the view
//!   trait, and their tests against a fixture view (`harness::bundle`).
//! - **What is not:** `form` and `validate` do not call either function;
//!   no `Rule` type binds them; nothing implements [`BundleView`], on a
//!   store or over [`crate::ChainView`]. A block that carries a bundle
//!   section is not judged by this module today.
//! - **Who calls it, and when:** `SO-D12`'s cutover increment
//!   (`docs/design/ARCHIVAL_SETTLEMENT_WRITER.md` §16; `SCS-P31`): it implements [`BundleView`] on its store, calls
//!   [`check_section`] and [`verify_bundle`] at admission from a block
//!   rule, writes what [`Admitted`] carries, and deletes the attestation
//!   path (CEN-B4). DRS-E5 is transport
//!   (`docs/design/DRS_E5_POOL_ALT_PRUNE.md` §2.2, §2.3). Its alternative
//!   tier has landed ([`crate::alt_against`]) and does not call this
//!   module: an alternative block's row still carries the attestation
//!   witness, not bundle references. When E5 replaces that with
//!   references it calls [`open_reference`] and [`check_section`] at an
//!   alternative block's arrival, and nothing else of this module there;
//!   at the switch the full `validate` runs [`verify_bundle`] over the
//!   switch's batch view, on which E5 implements [`BundleView`]. A body
//!   that cannot be fetched before the switch is no switch and no verdict,
//!   which is [`BundleRefused::BodyNotReferenced`]'s side of the same
//!   line. The body store and the bundle queue are not built; the queue
//!   will run both functions against the tip.
//! - **The census rows** these refusals name, CEN-J29 through CEN-J37, are
//!   registered `pending` for the same reason: a `pending` row is in the
//!   denominator and no rule type is bound to it. The cutover flips them.
//! - **The falsifier of "staged":** `nothing_on_the_connect_path_calls_the_bundle_verifier`
//!   in this module's tests reads `validate.rs`, `block.rs` and the
//!   `rules` tree and fails when any of them names this module's
//!   functions. The cutover deletes that test in the change that wires
//!   them.
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
//!   one-per-`h` flag. A height with no row has no count, and the rule
//!   refuses it as [`BundleInvalid::UnknownBlock`]. No block writes the
//!   row before admission lands, so until the cutover every height reads
//!   that way. `carry` and `shortfall` on the same row are the count
//!   rule's, and this rule does not read them.
//! - [`BundleView::draw_commitment`] is the coinbase's `0x0C` field. The
//!   coinbase grammar (CEN-I20) now requires exactly one, so a block of
//!   the chain always has it. A `None` for a block whose draw count the
//!   view just answered is therefore the view failing to answer, and the
//!   rule returns [`BundleUnanswered::DrawCommitment`], not a verdict:
//!   calling the block invalid would turn a store's hole into a consensus
//!   rule. [`BundleInvalid::Commitment`] is the mismatch and nothing else.
//! - `ChainView::drawable_digest(E)` is **not** one of this rule's reads.
//!   It is the settlement writer's check that `D` did not drift
//!   (specification §9.5, check 2). What this rule reads of `D` is
//!   [`BundleView::snapshot`], whose builder is `SO-D12`'s increment 2.
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
//! other pure archival judgement of this slice that has no caller yet
//! ([`DrawableSet`](super::DrawableSet)) and the settlement fold that
//! consumes what admission writes. The rule types that succeed CEN-B4
//! land in `rules/` at the cutover and call into here.
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

use core::cell::RefCell;
use core::fmt;
use std::collections::BTreeMap;

use shekyl_archival_retention::{
    bundle_root, challenge_nonce, draw_commit, pass_countersignature_message, select_draw,
    BundleBody, BundleKept, BundleRef, BundleWireError, DrawablePair, EpochSnapshot,
    CHALLENGE_READS,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{
    SignatureScheme as _, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_BUNDLE,
};
use shekyl_types::{BlockHash, BlockHeight, SettlementEpoch};

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
/// `D`, as a number, is the snapshot's length. The view has no second
/// source for it.
///
/// The store's view, the switch's batch view and the test fixture each
/// implement this. None exists in production yet (module docs).
pub trait BundleView {
    /// The view's own failure to answer. Never a verdict.
    type Fault;

    /// `count(h)`, as written when `h` connected (§4.3). `None`: no such
    /// block on this chain.
    ///
    /// A draw index `j` is 32 bits (§3), so a count is. A store that holds
    /// it wider refuses a value that does not fit; it does not truncate.
    fn draw_count(&self, h: BlockHeight) -> Result<Option<u32>, Self::Fault>;

    /// `h`'s `0x0C` commitment (§4.2).
    fn draw_commitment(&self, h: BlockHeight) -> Result<Option<[u8; 32]>, Self::Fault>;

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

    /// The `h_open(E)` snapshot: `D`, and each pair's receipt key.
    fn snapshot(&self, epoch: SettlementEpoch) -> Result<Option<&EpochSnapshot>, Self::Fault>;
}

/// Why a block's bundle section is refused before any bundle is opened.
/// Each arm is a verdict and names its census row ([`Self::row`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SectionRefused {
    /// The bytes at `position` are not a reference: not `76 + ⌈count /
    /// 8⌉` bytes for the count they state, or a padding bit is set
    /// (§9.1 step 1, "each reference parses"). Raised by
    /// [`open_reference`], where a section's references are decoded.
    /// CEN-J29.
    Malformed {
        /// The offending reference's position in the section.
        position: usize,
    },
    /// The reference at `position` does not name a higher `h` than the one
    /// before it. Strictly ascending `h` is what makes "no `h` repeats" a
    /// property of the order. CEN-J29.
    OutOfOrder {
        /// The offending reference's position in the section.
        position: usize,
    },
    /// The header's root is not the root over these references. CEN-J29.
    Root,
    /// The references' charges sum past the section budget. CEN-J30.
    OverBudget {
        /// The section's charge: the sum of `max(count, 1)`.
        charge: SectionCharge,
        /// `c · (⌊9·D / SEB⌋ + 1)`, as the caller computed it.
        budget: u64,
    },
}

impl SectionRefused {
    /// The census row this refusal is a verdict under.
    #[must_use]
    pub const fn row(&self) -> CenRow {
        match self {
            Self::Malformed { .. } | Self::OutOfOrder { .. } | Self::Root => CenRow::J29,
            Self::OverBudget { .. } => CenRow::J30,
        }
    }
}

impl fmt::Display for SectionRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} refused: ", self.row())?;
        match self {
            Self::Malformed { position } => {
                write!(f, "bundle reference #{position} does not parse")
            }
            Self::OutOfOrder { position } => {
                write!(
                    f,
                    "bundle reference #{position} is not above its predecessor's h"
                )
            }
            Self::Root => f.write_str("the header root is not the root over the references"),
            Self::OverBudget { charge, budget } => {
                write!(
                    f,
                    "the section's charge of {} exceeds its budget of {budget}",
                    charge.get()
                )
            }
        }
    }
}

impl std::error::Error for SectionRefused {}

/// A section's charge against its budget: the sum, over its references, of
/// `max(count, 1)` from the count each states (§7.4, `SCS-P40`).
///
/// What [`check_section`] returns. Where the budget was not known — an
/// alternative block whose epoch's `D` lies above the fork point — the
/// caller keeps this and asks [`Self::within`] at the switch. The counts
/// it sums are the references' own; [`verify_bundle`] holds each to the
/// chain's `count(h)`, so a reference that understates its count to shrink
/// this sum is an invalid block (`SCS-P39`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionCharge(u64);

impl SectionCharge {
    /// The charge of `refs`: one addition per bundle
    /// (`shekyl_archival_retention::bundle_charge`), saturating.
    #[must_use]
    pub fn of(refs: &[BundleRef]) -> Self {
        Self(
            refs.iter()
                .fold(0u64, |sum, r| sum.saturating_add(r.charge())),
        )
    }

    /// The charge, in draws.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether the charge fits `budget` (`section_budget(c, d_max, seb)`).
    #[must_use]
    pub const fn within(self, budget: u64) -> bool {
        self.0 <= budget
    }
}

/// One reference of a section, from the bytes the block carries for it.
///
/// The boundary where a section's references are decoded: a reference
/// that does not parse — wrong length for the count it states, or a set
/// padding bit — is §9.1 step 1's refusal, a verdict on the block under
/// CEN-J29, and this is where it is given its type. How a block lays its
/// references out is the block format's (`SO-D12`'s rule-42 bump); a
/// reference is self-delimiting, so whatever that layout is, each is cut
/// by its own stated count and handed here with its position.
///
/// # Errors
///
/// [`SectionRefused::Malformed`] at `position`.
pub fn open_reference(position: usize, bytes: &[u8]) -> Result<BundleRef, SectionRefused> {
    BundleRef::decode(bytes).map_err(|_: BundleWireError| SectionRefused::Malformed { position })
}

/// The stateless section check: §9.1 steps 1 and 2, in that order.
///
/// 1. **Form.** `refs` is in strictly ascending `h`, so no `h` repeats,
///    and `header_root` is [`bundle_root`] over it. That each reference
///    parses is already true of a [`BundleRef`]: its bitmap's length and
///    padding were checked against its stated count when it was decoded
///    ([`open_reference`]).
/// 2. **Budget.** The section's charge — the sum of `max(count, 1)` over
///    `refs` — is at most `budget` when one is given. `None` means `D` is
///    not known here, and the comparison waits for the switch.
///
/// `budget` is `section_budget(c, d_max, seb)` with `d_max` the largest
/// `D` among the epochs of the bundles in the section
/// (`shekyl_archival_retention::section_budget`; `SCS-P33`).
///
/// Both steps are computed from the references and nothing else: a
/// reference states its own count (`SCS-P39`). The charge is returned
/// whether or not a budget was given.
///
/// # Errors
///
/// [`SectionRefused`], naming the first check that failed.
pub fn check_section(
    refs: &[BundleRef],
    header_root: &[u8; 32],
    budget: Option<u64>,
) -> Result<SectionCharge, SectionRefused> {
    if let Some(offender) = refs.windows(2).position(|w| w[0].h() >= w[1].h()) {
        return Err(SectionRefused::OutOfOrder {
            position: offender + 1,
        });
    }
    if bundle_root(refs) != *header_root {
        return Err(SectionRefused::Root);
    }
    let charge = SectionCharge::of(refs);
    match budget {
        Some(budget) if !charge.within(budget) => {
            Err(SectionRefused::OverBudget { charge, budget })
        }
        _ => Ok(charge),
    }
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
    /// The chain has no block `h`: the view has no draw count for it.
    /// CEN-J31.
    UnknownBlock,
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
            Self::OutsideWindow | Self::AlreadyRevealed | Self::UnknownBlock => CenRow::J31,
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
            Self::UnknownBlock => f.write_str("the bundle names a block this chain does not have"),
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
    /// No snapshot for the epoch of a block that has draws — or a snapshot
    /// of another epoch.
    Snapshot {
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
    /// selection named an index the snapshot does not hold.
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
            Self::Unanswered(BundleUnanswered::Snapshot { epoch }) => {
                write!(f, "the view has no snapshot of epoch {epoch}")
            }
            Self::Unanswered(BundleUnanswered::DrawCommitment { height }) => {
                write!(f, "the view has no 0x0C commitment at height {height}")
            }
            Self::Unanswered(BundleUnanswered::BlockHash { height }) => {
                write!(f, "the view has no block hash at height {height}")
            }
            Self::Unanswered(BundleUnanswered::Draw { draw }) => {
                write!(f, "draw {draw} has no pair in the view's snapshot")
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
    /// The pair, as the snapshot holds it at that position.
    pub pair: DrawablePair,
    /// The draw's bit in the bundle's bitmap.
    pub passed: bool,
}

/// What the verifier returns on success, and all the writer needs
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.6, `SCS-P37`).
///
/// The writer turns `draws` into index rows `(E, P, s, h, j) → (h_incl,
/// passed)`, folds each into the epoch's digest, marks `h` revealed and
/// updates the visible counts. It derives nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The bundle's kept bytes, parsed: the reference's content.
    pub kept: BundleKept,
    /// One entry per draw `j` of `h`, in order — passes and misses both.
    pub draws: Vec<DerivedDraw>,
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
///    `select_draw` over the snapshot's length and the view's
///    `visibly_short`.
/// 7. **Each record's `attempt`** is below `K`.
/// 8. **Each record's receipt**, ascending `j`: `anchor_height < h`, then
///    the 112-byte transcript `nonce ‖ anchor_height_le ‖
///    block_hash(anchor_height) ‖ shard_id_le ‖ delivery_digest` verifies
///    under the derived pair's receipt key, scheme 3,
///    `SCHEME_DOMAIN_RECEIPT`, with the nonce recomputed from `(seed,
///    block_hash(h), j, attempt)`.
///
/// Step 7 runs over every record before step 8 runs over any: a bundle
/// with an inadmissible `attempt` is refused for it whatever its receipts
/// say.
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
    let Some(window) = schedule.challenge_response_blocks() else {
        return invalid(BundleInvalid::OutsideWindow);
    };
    match h_incl.to_raw().checked_sub(h.to_raw()) {
        Some(distance) if distance >= 1 && distance <= window.get() => {}
        _ => return invalid(BundleInvalid::OutsideWindow),
    }
    if view.revealed(h)? {
        return invalid(BundleInvalid::AlreadyRevealed);
    }
    let Some(count) = view.draw_count(h)? else {
        return invalid(BundleInvalid::UnknownBlock);
    };
    if reference.count() != count {
        return invalid(BundleInvalid::Count);
    }
    let kept = reference.kept().clone();
    if usize::try_from(kept.passes.popcount()).ok() != Some(body.record_count()) {
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
    if draw_commit(body.witness_public_key(), &kept.seed) != committed {
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

    // A block with no draws issues nothing: its bundle marks `h` revealed
    // and that is all (`SCS-P33`). Nothing below has anything to read.
    if count == 0 {
        return Ok(Admitted {
            kept,
            draws: Vec::new(),
        });
    }

    // 6. Every draw's pair, at the issued counts visible at `h`.
    let epoch = schedule.epoch_at(h);
    let snapshot = match view.snapshot(epoch)? {
        Some(snapshot) if snapshot.epoch() == epoch => snapshot,
        _ => {
            return Err(BundleRefused::Unanswered(BundleUnanswered::Snapshot {
                epoch,
            }))
        }
    };
    let Some(hash_at_h) = view.block_hash(h)? else {
        return Err(BundleRefused::Unanswered(BundleUnanswered::BlockHash {
            height: h,
        }));
    };
    let draws = derive_draws(view, snapshot, &kept, hash_at_h.as_bytes(), count)?;

    // 7. `attempt < K`, for every record, before any receipt is verified.
    for (draw, record) in kept.passes.iter_set().zip(body.records()) {
        if record.attempt >= CHALLENGE_READS {
            return invalid(BundleInvalid::Attempt { draw });
        }
    }

    // 8. Receipts, ascending `j`.
    for (draw, record) in kept.passes.iter_set().zip(body.records()) {
        // `SCS-P32`: what makes "nothing above `h` enters a bundle's
        // validity" a property of this rule and not of today's constants.
        if record.anchor_height >= h {
            return invalid(BundleInvalid::Anchor { draw });
        }
        let Some(anchor_hash) = view.block_hash(record.anchor_height)? else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::BlockHash {
                height: record.anchor_height,
            }));
        };
        let derived = draws[draw as usize];
        let Some(receipt_key) = snapshot.receipt_key(derived.index) else {
            return Err(BundleRefused::Unanswered(BundleUnanswered::Draw { draw }));
        };
        let nonce = challenge_nonce(&kept.seed, hash_at_h.as_bytes(), draw, record.attempt);
        let transcript = pass_countersignature_message(
            &nonce,
            record.anchor_height,
            anchor_hash.as_bytes(),
            derived.pair.shard_id,
            &record.delivery_digest,
        );
        let Ok(receipt) = FnDsaHybridSignature::from_canonical_bytes(&record.receipt) else {
            return invalid(BundleInvalid::Receipt { draw });
        };
        if scheme
            .verify(receipt_key, SCHEME_DOMAIN_RECEIPT, &transcript, &receipt)
            .is_err()
        {
            return invalid(BundleInvalid::Receipt { draw });
        }
    }

    Ok(Admitted { kept, draws })
}

/// Step 6: draw `j`'s pair for every `j < count`, by the production
/// selection over the snapshot's length.
///
/// `select_draw` asks whether an index is visibly short through a plain
/// predicate, and the view's answer can fault. The first fault is kept
/// and the predicate answers `true` from then on, which ends the
/// selection at once; the draw it returns is discarded and the fault is
/// what this function returns. A faulted read is never a selection.
/// Answers are remembered for the bundle, so an index asked twice is read
/// once.
fn derive_draws<V: BundleView>(
    view: &V,
    snapshot: &EpochSnapshot,
    kept: &BundleKept,
    hash_at_h: &[u8; 32],
    count: u32,
) -> Result<Vec<DerivedDraw>, BundleRefused<V::Fault>> {
    let fault: RefCell<Option<V::Fault>> = RefCell::new(None);
    let asked: RefCell<BTreeMap<u64, bool>> = RefCell::new(BTreeMap::new());
    let short = |index: u64| -> bool {
        if fault.borrow().is_some() {
            return true;
        }
        if let Some(known) = asked.borrow().get(&index) {
            return *known;
        }
        match view.visibly_short(kept.h, index) {
            Ok(answer) => {
                asked.borrow_mut().insert(index, answer);
                answer
            }
            Err(raised) => {
                *fault.borrow_mut() = Some(raised);
                true
            }
        }
    };

    let mut draws = Vec::with_capacity(count as usize);
    for draw in 0..count {
        let selected = select_draw(&kept.seed, hash_at_h, draw, snapshot.len(), short);
        if let Some(raised) = fault.borrow_mut().take() {
            return Err(BundleRefused::View(raised));
        }
        let unanswered = BundleRefused::Unanswered(BundleUnanswered::Draw { draw });
        let Some(selected) = selected else {
            return Err(unanswered);
        };
        let Some(pair) = snapshot.pair(selected.index) else {
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

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod bundle_tests;
