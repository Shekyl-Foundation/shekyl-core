// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The section half of the bundle rule: form, the window, then the budget.
//!
//! [`check_section`] and [`check_section_until_switch`] are the only
//! admission results. The charge arithmetic is [`SectionCharge`]; a cap
//! compared there is not a section result. The per-bundle verifier asks
//! the same window through [`inside_window`].
//!
//! Staged with the parent module: nothing on the connect path calls this.
//! The disposition is the parent module's.

use core::fmt;

use shekyl_archival_retention::{
    bundle_root, section_budget, section_d_max, BundleRef, BundleWireError, DrawableEpoch,
    SettlementSchedule, TooManyReferences, BUNDLE_SECTION_BUDGET_MULTIPLE,
};
use shekyl_types::BlockHeight;

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
    let cap = section_budget(BUNDLE_SECTION_BUDGET_MULTIPLE, d_max, schedule.blocks());
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
