// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The section half of the bundle rule: form, the window, then the budget.
//!
//! [`check_section`] and [`check_section_until_switch`] are the only
//! admission results. [`fill_section`] is the template's selection, and
//! the references it returns are a section [`check_section`] admits. The
//! charge arithmetic is [`SectionCharge`]; a cap compared there is not a
//! section result. The per-bundle verifier asks the same window through
//! [`inside_window`].
//!
//! Staged with the parent module: nothing on the connect path calls this.
//! The disposition is the parent module's.

use core::fmt;

use shekyl_archival_retention::{
    bundle_root, section_budget, section_d_max, ArchivalParams, BundleRef, BundleWireError,
    DrawableEpoch, SectionBudget, SettlementEpochBlocks, SettlementSchedule, TooManyReferences,
};
use shekyl_types::{BlockHeight, SettlementEpoch};

use super::BundleView;
use crate::census::CenRow;
use crate::rule_set::RuleSet;

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
    /// The section holds 2³² references or more: the root counts them in
    /// four bytes (§7.3), so no root exists for it to recompute to. A
    /// verdict, not a panic (`shekyl_archival_retention::TooManyReferences`
    /// is where the wire states the bound). CEN-J29.
    TooManyReferences {
        /// The references in the section.
        found: usize,
    },
    /// The header's root is not the root over these references. CEN-J29.
    Root,
    /// The reference at `position` names an `h` the including block is not
    /// inside the window of: not `h < h_incl ≤ h + W₂`, or the rule set's
    /// epoch is too short to have a window. The section's copy of
    /// [`super::BundleInvalid::OutsideWindow`], checked before the budget so that
    /// no reference outside the window reaches the budget's reads
    /// (`SCS-P41`). CEN-J31.
    OutsideWindow {
        /// The offending reference's position in the section.
        position: usize,
    },
    /// The references' charges sum past the section budget. CEN-J30.
    OverBudget {
        /// The section's charge: the sum of `max(count, 1)`.
        charge: SectionCharge,
        /// The cap the charge exceeded.
        budget: shekyl_archival_retention::SectionBudget,
    },
}

impl SectionRefused {
    /// The census row this refusal is a verdict under.
    #[must_use]
    pub const fn row(&self) -> CenRow {
        match self {
            Self::Malformed { .. }
            | Self::OutOfOrder { .. }
            | Self::TooManyReferences { .. }
            | Self::Root => CenRow::J29,
            Self::OverBudget { .. } => CenRow::J30,
            Self::OutsideWindow { .. } => CenRow::J31,
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
            Self::TooManyReferences { found } => {
                write!(
                    f,
                    "the section's {found} references are more than the header root can count"
                )
            }
            Self::Root => f.write_str("the header root is not the root over the references"),
            Self::OutsideWindow { position } => {
                write!(
                    f,
                    "bundle reference #{position} names a block the including block is \
                     outside the window of"
                )
            }
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

/// A section's charge: the sum, over its references, of `max(count, 1)`
/// from the count each states (§7.4, `SCS-P40`). What a
/// [`SectionStanding`] carries.
///
/// The counts are the references' own. [`super::verify_bundle`] holds each to the
/// chain's `count(h)`, so a reference that understates its count to shrink
/// this sum is an invalid block (`SCS-P39`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionCharge(u64);

impl SectionCharge {
    /// The charge of no references: the identity of [`Self::and_reference`].
    const ZERO: Self = Self(0);

    /// The charge of `refs`: one addition per bundle
    /// (`shekyl_archival_retention::bundle_charge`), saturating.
    #[must_use]
    pub fn of(refs: &[BundleRef]) -> Self {
        refs.iter().fold(Self::ZERO, Self::and_reference)
    }

    /// [`Self::of`]'s addition: this charge plus `reference`'s draws, saturating.
    fn and_reference(self, reference: &BundleRef) -> Self {
        self.and_draws(reference.charge())
    }

    /// This charge plus `draws`, saturating. The same addition as
    /// [`Self::and_reference`], for room held open for a witness.
    fn and_draws(self, draws: u64) -> Self {
        Self(self.0.saturating_add(draws))
    }

    /// The charge, in draws.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether the charge is at most `cap`. [`check_section`] is what
    /// chooses the cap.
    #[must_use]
    pub const fn within(self, cap: shekyl_archival_retention::SectionBudget) -> bool {
        self.0 <= cap.get()
    }
}

/// Form held. Whether the budget comparison has been applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SectionStanding {
    /// The charge fits the section's budget, or the section names no epoch
    /// and the comparison does not apply.
    Admitted(SectionCharge),
    /// Some epoch's `D` is not on this chain. The charge is what
    /// [`check_section`] compares once it is.
    Awaiting(SectionCharge),
}

impl SectionStanding {
    /// The section's charge, admitted or still awaiting its budget.
    #[must_use]
    pub const fn charge(self) -> SectionCharge {
        match self {
            Self::Admitted(charge) | Self::Awaiting(charge) => charge,
        }
    }
}

/// Why [`check_section`] returned no standing: a verdict, or the view's
/// own failure. An unknown `D` is [`SectionStanding::Awaiting`], not an
/// arm here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionCheckFailed<F> {
    /// Judged and refused.
    Refused(SectionRefused),
    /// [`BundleView::drawable_epoch`] faulted.
    View(F),
}

impl<F: fmt::Display> fmt::Display for SectionCheckFailed<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refused) => write!(f, "{refused}"),
            Self::View(fault) => write!(f, "view fault: {fault}"),
        }
    }
}

impl<F: fmt::Debug + fmt::Display> std::error::Error for SectionCheckFailed<F> {}

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

/// §9.1 steps 1 and 2, in that order: form and the window, then the
/// budget.
///
/// The cap is [`section_budget`] over [`section_d_max`] of these
/// references. `c` is [`BUNDLE_SECTION_BUDGET_MULTIPLE`]; `seb` and `W₂`
/// are `rule_set`'s. `D` is the drawable epoch's length, and it counts only
/// when that epoch is the one asked. An empty section is
/// [`SectionStanding::Admitted`] and is not read. Any other unknown `D` is
/// [`SectionStanding::Awaiting`] for the whole section. Every reference is
/// inside the window before any `D` is read (`SCS-P41`), so the epochs
/// asked are those of the `W₂` blocks below `h_incl`: an unknown one is an
/// alternative chain's epoch above its fork point, not a reference that
/// names a block nobody could hold.
///
/// # Errors
///
/// [`SectionCheckFailed::Refused`] for the first form, window or budget
/// check that failed. [`SectionCheckFailed::View`] when a drawable-epoch
/// read faults. A fault is not a verdict.
pub fn check_section<V: BundleView>(
    refs: &[BundleRef],
    header_root: &[u8; 32],
    h_incl: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
) -> Result<SectionStanding, SectionCheckFailed<V::Fault>> {
    let schedule = rule_set.settlement_schedule();
    let charge =
        section_form(refs, header_root, h_incl, schedule).map_err(SectionCheckFailed::Refused)?;
    if refs.is_empty() {
        return Ok(SectionStanding::Admitted(charge));
    }
    let d_max = section_d_max(refs, schedule, |epoch| {
        Ok(super::drawable_for(view, epoch)?.map(DrawableEpoch::len))
    })
    .map_err(SectionCheckFailed::View)?;
    let Some(d_max) = d_max else {
        return Ok(SectionStanding::Awaiting(charge));
    };
    let cap = section_budget(
        shekyl_archival_retention::archival_params(),
        d_max,
        schedule.blocks(),
    );
    if charge.within(cap) {
        Ok(SectionStanding::Admitted(charge))
    } else {
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge,
            budget: cap,
        }))
    }
}

/// [`check_section`]'s form and window checks when the arrival has no view
/// (`SCS-P23`).
///
/// An empty section is [`SectionStanding::Admitted`]. Any other section
/// that passes them is [`SectionStanding::Awaiting`]: there is no `D`
/// here, so there is no budget refusal.
///
/// # Errors
///
/// [`SectionRefused`], naming the first form or window check that failed.
pub fn check_section_until_switch(
    refs: &[BundleRef],
    header_root: &[u8; 32],
    h_incl: BlockHeight,
    rule_set: &RuleSet,
) -> Result<SectionStanding, SectionRefused> {
    let charge = section_form(refs, header_root, h_incl, rule_set.settlement_schedule())?;
    if refs.is_empty() {
        Ok(SectionStanding::Admitted(charge))
    } else {
        Ok(SectionStanding::Awaiting(charge))
    }
}

/// The references a template puts in the next block's section.
///
/// `queued` is walked in ascending `h` — the bundle queue's order. A
/// reference that repeats or precedes a height already walked is passed
/// over, whether or not that height was kept. Of what remains, every
/// reference inside the window of `h_incl` whose epoch's `D` the view
/// holds is a candidate. A candidate whose `D` is unknown is passed over:
/// its bundle could not be judged, so a section holding it would wait
/// (`SCS-P23`). Each epoch is read once.
///
/// The candidates span at most two epochs, because the window is shorter
/// than an epoch (`W₂ < SEB`). They are packed oldest-first under the
/// budget the epochs actually kept earn: [`section_budget`] of the largest
/// `D` among those epochs, the cap [`check_section`] applies. A reference
/// that would exceed that budget is passed over. When the two epochs differ
/// in `D`, the pack is the oldest of the three shapes that cap allows — the
/// earlier epoch, the later epoch, and both — and a reference is also
/// passed over when keeping it would crowd out the epoch that earns the
/// larger `D`.
///
/// The result is a section [`check_section`] admits at `h_incl` under the
/// root [`bundle_root`] computes over it.
///
/// **STAGED** (`SO-D12` 4b prep, `ARCHIVAL_SETTLEMENT_WRITER.md` §16.3
/// item 4): the block template (`shekyl-chain-ingest`'s `template.rs`)
/// calls it at the switch, over the bundle queue's references and the
/// store's bundle view of the template's snapshot. Nothing calls it before
/// then.
///
/// # Errors
///
/// The view's fault, when reading an epoch's `D` faults. Nothing is selected.
pub fn fill_section<V: BundleView>(
    queued: &[BundleRef],
    h_incl: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Vec<BundleRef>, V::Fault> {
    let schedule = rule_set.settlement_schedule();
    let mut walk = CandidateWalk::default();
    for reference in queued {
        walk.see(reference, h_incl, view, schedule)?;
    }
    Ok(walk.finish(schedule))
}

/// §9.1 step 1 and the section's window: [`section_shape`], then every
/// reference inside the window.
///
/// The window is step 3's `h < h_incl ≤ h + W₂`, asked here of every
/// reference: it reads `h_incl` and the schedule and nothing of the chain,
/// so it is as stateless as the rest of the form (`SCS-P41`). Because the
/// references' heights ascend strictly inside it, a section that passes
/// holds at most `W₂` of them.
fn section_form(
    refs: &[BundleRef],
    header_root: &[u8; 32],
    h_incl: BlockHeight,
    schedule: SettlementSchedule,
) -> Result<SectionCharge, SectionRefused> {
    let charge = section_shape(refs, header_root)?;
    if let Some(position) = refs
        .iter()
        .position(|r| !inside_window(r.h(), h_incl, schedule))
    {
        return Err(SectionRefused::OutsideWindow { position });
    }
    Ok(charge)
}

/// §9.1 step 1: order, then a root the count can name, then the charge.
fn section_shape(
    refs: &[BundleRef],
    header_root: &[u8; 32],
) -> Result<SectionCharge, SectionRefused> {
    if let Some(offender) = refs.windows(2).position(|w| w[0].h() >= w[1].h()) {
        return Err(SectionRefused::OutOfOrder {
            position: offender + 1,
        });
    }
    // The one refusal `bundle_root` has, mapped by name: a section the
    // root cannot count is a verdict here, never a panic.
    let root = bundle_root(refs)
        .map_err(|TooManyReferences { found }| SectionRefused::TooManyReferences { found })?;
    if root != *header_root {
        return Err(SectionRefused::Root);
    }
    Ok(SectionCharge::of(refs))
}

/// `h < h_incl ≤ h + W₂`, with `W₂` the schedule's. A schedule whose epoch
/// is too short to have a window has nothing inside one. §9.1 step 3's
/// window, asked by the section and by [`super::verify_bundle`] alike.
pub(super) fn inside_window(
    h: BlockHeight,
    h_incl: BlockHeight,
    schedule: SettlementSchedule,
) -> bool {
    let Some(window) = schedule.challenge_response_blocks() else {
        return false;
    };
    matches!(
        h_incl.to_raw().checked_sub(h.to_raw()),
        Some(distance) if distance >= 1 && distance <= window.get()
    )
}

/// The queue walk: heights already seen, one `D` per epoch, and the
/// candidates those reads admit. Packing is [`CandidateWalk::finish`],
/// after the walk, so a reference is not judged under a `D` the walk has
/// not finished opening.
#[derive(Default)]
struct CandidateWalk<'a> {
    refs: Vec<&'a BundleRef>,
    span: SpannedEpochs,
    last_seen: Option<BlockHeight>,
    /// The epoch last asked. A second reference of it is not a second read.
    asked: Option<AskedEpoch>,
}

/// The epochs one window can hold. The window is shorter than an epoch
/// (`W₂ < SEB`), so it crosses at most one boundary. A later epoch is
/// opened only from [`Self::One`], so a later epoch with no earlier one
/// cannot be named.
#[derive(Clone, Copy, Default)]
enum SpannedEpochs {
    #[default]
    None,
    One(OpenedEpoch),
    Two {
        earlier: OpenedEpoch,
        later: OpenedEpoch,
        /// Index of `later`'s first candidate in the walk's references.
        split: usize,
    },
}

/// An epoch the walk opened, and the `D` the view held for it.
#[derive(Clone, Copy)]
struct OpenedEpoch {
    epoch: SettlementEpoch,
    /// `D`: the drawable pairs filed for [`Self::epoch`].
    d: u64,
}

/// The view's answer for one epoch.
#[derive(Clone, Copy)]
enum EpochDraws {
    /// The view holds this epoch's `D`.
    Known(u64),
    /// The view has no `D` for this epoch. A reference of it is passed over.
    Unknown,
}

/// The epoch last asked, and the answer, so the walk reads each epoch once.
#[derive(Clone, Copy)]
struct AskedEpoch {
    epoch: SettlementEpoch,
    draws: EpochDraws,
}

/// One end of a two-epoch window: where a candidate sits, and which epoch
/// a larger `D` belongs to.
#[derive(Clone, Copy)]
enum WindowEnd {
    Earlier,
    Later,
}

/// Draws held open while earlier references are chosen, so the epoch that
/// earns a larger budget can still be kept.
///
/// [`Self::NONE`] holds nothing open. That is the reservation when the
/// budget does not depend on a later reference: one epoch, equal `D`, or
/// the earlier epoch's `D` being the larger one.
#[derive(Clone, Copy)]
struct ReservedDraws(u64);

impl ReservedDraws {
    /// No draws held open.
    const NONE: Self = Self(0);

    fn of(draws: u64) -> Self {
        Self(draws)
    }

    fn get(self) -> u64 {
        self.0
    }
}

impl<'a> CandidateWalk<'a> {
    /// Account for `reference`. A height already walked is passed over
    /// before the window and before any read.
    ///
    /// # Errors
    ///
    /// The view's fault, when this reference's epoch is asked and the read
    /// faults. An epoch already asked is not read again.
    fn see<V: BundleView>(
        &mut self,
        reference: &'a BundleRef,
        h_incl: BlockHeight,
        view: &V,
        schedule: SettlementSchedule,
    ) -> Result<(), V::Fault> {
        if self.last_seen.is_some_and(|seen| reference.h() <= seen) {
            return Ok(());
        }
        self.last_seen = Some(reference.h());
        if !inside_window(reference.h(), h_incl, schedule) {
            return Ok(());
        }
        let epoch = schedule.epoch_at(reference.h());
        if let EpochDraws::Known(d) = self.epoch_draws(view, epoch)? {
            self.accept(reference, epoch, d);
        }
        Ok(())
    }

    fn epoch_draws<V: BundleView>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<EpochDraws, V::Fault> {
        if let Some(asked) = self.asked {
            if asked.epoch == epoch {
                return Ok(asked.draws);
            }
        }
        let draws = match super::drawable_for(view, epoch)?.map(DrawableEpoch::len) {
            Some(d) => EpochDraws::Known(d),
            None => EpochDraws::Unknown,
        };
        self.asked = Some(AskedEpoch { epoch, draws });
        Ok(draws)
    }

    /// Keep `reference` on the epoch it opens. A third epoch inside one
    /// window would cross `W₂ < SEB`, so the reference is passed over.
    fn accept(&mut self, reference: &'a BundleRef, epoch: SettlementEpoch, d: u64) {
        match self.span {
            SpannedEpochs::Two { later, .. } if later.epoch != epoch => return,
            SpannedEpochs::One(earlier) if earlier.epoch != epoch => {
                self.span = SpannedEpochs::Two {
                    earlier,
                    later: OpenedEpoch { epoch, d },
                    split: self.refs.len(),
                };
            }
            SpannedEpochs::None => {
                self.span = SpannedEpochs::One(OpenedEpoch { epoch, d });
            }
            SpannedEpochs::One(_) | SpannedEpochs::Two { .. } => {}
        }
        self.refs.push(reference);
    }

    /// The oldest pack the candidates' epochs earn.
    fn finish(self, schedule: SettlementSchedule) -> Vec<BundleRef> {
        let params = shekyl_archival_retention::archival_params();
        let seb = schedule.blocks();
        match self.span {
            SpannedEpochs::None => Vec::new(),
            SpannedEpochs::One(opened) => {
                keep_within(
                    &self.refs,
                    &[],
                    section_budget(params, opened.d, seb),
                    ReservedDraws::NONE,
                )
                .refs
            }
            SpannedEpochs::Two {
                earlier,
                later,
                split,
            } => pack_two(&self.refs, split, earlier.d, later.d, params, seb),
        }
    }
}

/// The references kept under one budget, in walk order, and which end of
/// the window contributed one.
struct Pack {
    refs: Vec<BundleRef>,
    charge: SectionCharge,
    kept_earlier: bool,
    kept_later: bool,
}

impl Pack {
    fn new() -> Self {
        Self {
            refs: Vec::new(),
            charge: SectionCharge::ZERO,
            kept_earlier: false,
            kept_later: false,
        }
    }

    /// Keep each reference that fits `budget` with `reserved` draws still
    /// free. A reference that does not fit is passed over, and the charge
    /// stays where it was, so a later smaller one can still be taken.
    fn take(
        &mut self,
        refs: &[&BundleRef],
        budget: SectionBudget,
        reserved: ReservedDraws,
        end: WindowEnd,
    ) {
        for reference in refs {
            let added = self.charge.and_reference(reference);
            if !added.and_draws(reserved.get()).within(budget) {
                continue;
            }
            self.refs.push((*reference).clone());
            self.charge = added;
            self.mark(end);
        }
    }

    fn mark(&mut self, end: WindowEnd) {
        match end {
            WindowEnd::Earlier => self.kept_earlier = true,
            WindowEnd::Later => self.kept_later = true,
        }
    }

    fn kept(&self, end: WindowEnd) -> bool {
        match end {
            WindowEnd::Earlier => self.kept_earlier,
            WindowEnd::Later => self.kept_later,
        }
    }
}

/// Oldest-first under one budget. `reserved` draws stay free while the
/// earlier references are chosen. The later references then spend that
/// room: their reservation is [`ReservedDraws::NONE`].
fn keep_within(
    earlier: &[&BundleRef],
    later: &[&BundleRef],
    budget: SectionBudget,
    reserved: ReservedDraws,
) -> Pack {
    let mut pack = Pack::new();
    pack.take(earlier, budget, reserved, WindowEnd::Earlier);
    pack.take(later, budget, ReservedDraws::NONE, WindowEnd::Later);
    pack
}

/// The smallest later charge that fits `budget` on its own.
///
/// Holding that much back leaves the most room for older references while
/// still letting the later epoch earn `budget`. After the earlier
/// references are chosen, the room left is at least this charge, so either
/// the reference that costs it, or an earlier reference of the later epoch
/// that fits in the same room, is kept.
fn reserved_for(later: &[&BundleRef], budget: SectionBudget) -> Option<ReservedDraws> {
    later
        .iter()
        .map(|reference| reference.charge())
        .filter(|draws| SectionCharge::ZERO.and_draws(*draws).within(budget))
        .min()
        .map(ReservedDraws::of)
}

/// Two epochs, oldest-first, under the budget the kept epochs earn.
///
/// Equal `D` is one budget over the whole queue: the section does not have
/// to represent either epoch. When the `D`s differ, the section is the
/// oldest of three shapes — the earlier epoch under its own budget, the
/// later epoch under its own, or both under the larger one. Both keeps a
/// reference of the epoch whose `D` is the larger one, which is what earns
/// that budget.
fn pack_two(
    refs: &[&BundleRef],
    split: usize,
    earlier_d: u64,
    later_d: u64,
    params: &ArchivalParams,
    seb: SettlementEpochBlocks,
) -> Vec<BundleRef> {
    // `split` is the index the later epoch's first reference was pushed at.
    debug_assert!(split < refs.len(), "the later epoch opened on a candidate");
    let earlier_budget = section_budget(params, earlier_d, seb);
    let later_budget = section_budget(params, later_d, seb);
    let (earlier, later) = refs.split_at(split);
    if earlier_d == later_d {
        return keep_within(earlier, later, earlier_budget, ReservedDraws::NONE).refs;
    }
    let earlier_only = keep_within(earlier, &[], earlier_budget, ReservedDraws::NONE).refs;
    let later_only = keep_within(&[], later, later_budget, ReservedDraws::NONE).refs;
    let both = if later_d > earlier_d {
        pack_both(earlier, later, later_budget, WindowEnd::Later)
    } else {
        pack_both(earlier, later, earlier_budget, WindowEnd::Earlier)
    };
    older(older(earlier_only, later_only), both)
}

/// Both epochs under `budget`, which `earned_by`'s `D` sets. The pack is
/// empty when no reference of that end was kept: the budget was not earned,
/// and a shape under an epoch's own `D` is what remains.
fn pack_both(
    earlier: &[&BundleRef],
    later: &[&BundleRef],
    budget: SectionBudget,
    earned_by: WindowEnd,
) -> Vec<BundleRef> {
    let reserved = match earned_by {
        WindowEnd::Later => {
            let Some(reserved) = reserved_for(later, budget) else {
                return Vec::new();
            };
            reserved
        }
        WindowEnd::Earlier => ReservedDraws::NONE,
    };
    let pack = keep_within(earlier, later, budget, reserved);
    if !pack.kept(earned_by) {
        return Vec::new();
    }
    pack.refs
}

/// `right`, when it keeps an older bundle than `left` or the same prefix
/// and then more. Otherwise `left`. An empty pack is older than nothing.
fn older(left: Vec<BundleRef>, right: Vec<BundleRef>) -> Vec<BundleRef> {
    let right_is_older = match right.iter().zip(&left).find(|(a, b)| a.h() != b.h()) {
        Some((a, b)) => a.h() < b.h(),
        None => right.len() > left.len(),
    };
    if right_is_older {
        right
    } else {
        left
    }
}
