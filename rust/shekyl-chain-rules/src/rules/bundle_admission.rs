// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block's bundle section, CEN-J29 through CEN-J37 (`SO-D12` 4b, C3;
//! `ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.1).
//!
//! [`admit`] is the one call `validate` makes. It opens each reference
//! (J29's parse), files the epochs the block's window names, and then runs
//! [`judge_bundles`]: the section check, then [`verify_bundle`] per
//! bundle. Each type here names the refusal the verifier raises
//! ([`BundleInvalid::row`], [`SectionRefused::row`]); none adds a check.
//!
//! **Order.** After the clock and before the anchor, the slot the deleted
//! CEN-B4 held: J29 is its successor (the header root against the
//! references, `SCS-P34`), and the census's statements of the ladder's
//! order name that slot.
//!
//! **The filing comes first, with the memo borrowed mutably; admission
//! reads it after, through `&`.** The memo's contract (`archival::memo`) is
//! that the admission view never rebuilds: every epoch a section inside
//! `W₂` can name is filed before it reads. [`remember_window_epochs`] files
//! exactly the epochs of `h_incl − W₂ … h_incl − 1`, rebuilding a cold one
//! from the view and keeping it only when it matches the recorded digest.
//! The window never names the epoch `h_incl` opens: every bundle's `h` is
//! below `h_incl`.
//!
//! **What is not a verdict.** A body that is not its reference's is the
//! caller's wrong bytes ([`Stale::BundleBody`]). A view that cannot answer
//! for a block it holds is this node's rows ([`Corrupt::BundleUnanswered`]).
//! A view fault is the view's. None of them refuses the block.
//!
//! [`BundleInvalid::row`]: crate::archival::BundleInvalid::row
//! [`verify_bundle`]: crate::archival::verify_bundle

use shekyl_archival_retention::BundleRef;
use shekyl_network::NetworkId;
use shekyl_types::BlockHeight;

use crate::archival::{
    check_section_stateless, judge_bundles, open_reference, remember_window_epochs, AdmissionFault,
    Admitted, BundleRefused, BundleUnanswered, BundleView, DrawableMemo, SectionRefused,
};
use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, Fault, FormAttempt, Stale};
use crate::rule_set::RuleSet;
use crate::rules::Rule;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::ChainView;

macro_rules! bundle_row {
    ($name:ident, $row:ident) => {
        /// The rule type for this census row: a refusal [`admit`] returns.
        pub(crate) struct $name;

        impl Rule for $name {
            const ROW: CenRow = CenRow::$row;
        }
    };
}

bundle_row!(J29, J29);
bundle_row!(J30, J30);
bundle_row!(J31, J31);
bundle_row!(J32, J32);
bundle_row!(J33, J33);
bundle_row!(J34, J34);
bundle_row!(J35, J35);
bundle_row!(J36, J36);
bundle_row!(J37, J37);

/// The nine rows [`admit`] judges, in census order. Every block records all
/// nine: a block with no references has an empty section, and an empty
/// section passes each of them vacuously.
const ROWS: [CenRow; 9] = [
    J29::ROW,
    J30::ROW,
    J31::ROW,
    J32::ROW,
    J33::ROW,
    J34::ROW,
    J35::ROW,
    J36::ROW,
    J37::ROW,
];

/// What a block's section admits on `view`, at `connecting`.
///
/// `memo` is the connect loop's, or `None` for a caller that holds none: a
/// section that is not empty then files into a memo local to this call. An
/// empty section names no epoch, so it files nothing and reads nothing,
/// the same as [`crate::archival::check_section`] reads nothing for it.
///
/// # Errors
///
/// [`Fault::View`] for the view's own fault; [`Fault::Corrupt`] when the
/// filing finds a drifted or unrebuildable set, or the bundle view does not
/// answer for a block it holds; [`Fault::Stale`] when the candidate's bodies
/// are not its references'.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit<'id, V: ChainView<'id>>(
    candidate: &Candidate,
    connecting: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
    network: &NetworkId,
    attempt: FormAttempt,
    memo: Option<&mut DrawableMemo>,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<Vec<Admitted>>, Fault<V::Fault>> {
    for row in ROWS {
        coverage.insert(row);
    }
    let header_root = candidate.block.header.bundle_root.as_bytes();
    // No references is the empty section: its root is still compared
    // (J29, the A3 falsifier), and it names no epoch, so nothing is filed
    // and no row is read.
    let Some(section) = candidate.bundle_references.as_ref() else {
        return Ok(
            check_section_stateless(&[], header_root, connecting, rule_set)
                .map(|_standing| Vec::new())
                .map_err(section_refusal),
        );
    };
    let mut refs = Vec::with_capacity(section.as_slice().len());
    for (position, bytes) in section.as_slice().iter().enumerate() {
        match open_reference(position, bytes) {
            Ok(reference) => refs.push(reference),
            Err(refused) => return Ok(Err(section_refusal(refused))),
        }
    }

    let mut local = None;
    let memo: &mut DrawableMemo = match memo {
        Some(memo) => memo,
        None => local.insert(DrawableMemo::new()),
    };
    remember_window_epochs(view, connecting, rule_set, memo)?;
    let schedule = rule_set.settlement_schedule();
    let bundles = view.bundles(memo, connecting, schedule);
    let judged = judge_bundles(
        &refs,
        &candidate.bundle_bodies,
        header_root,
        connecting,
        &bundles,
        rule_set,
        network,
    );
    match judged {
        Ok(admitted) => Ok(Ok(admitted)),
        Err(AdmissionFault::Section(refused)) => Ok(Err(section_refusal(refused))),
        Err(AdmissionFault::Bundle {
            at,
            refused: BundleRefused::Invalid(invalid),
        }) => Ok(Err(InvalidBlock::new(
            invalid.row(),
            Locus::Bundle { position: at },
        ))),
        Err(AdmissionFault::Bundle {
            at,
            refused: BundleRefused::BodyNotReferenced,
        }) => Err(Fault::Stale(Stale::BundleBody {
            position: at,
            retry: attempt.next(),
        })),
        Err(AdmissionFault::Bundle {
            refused: BundleRefused::Unanswered(why),
            ..
        }) => Err(Fault::Corrupt(Corrupt::BundleUnanswered {
            including: connecting,
            why,
        })),
        Err(
            AdmissionFault::View(fault)
            | AdmissionFault::Bundle {
                refused: BundleRefused::View(fault),
                ..
            },
        ) => Err(Fault::View(fault)),
        Err(AdmissionFault::Awaiting) => Err(Fault::Corrupt(Corrupt::BundleUnanswered {
            including: connecting,
            why: unanswered_epoch(&refs, &bundles, schedule).map_err(Fault::View)?,
        })),
    }
}

/// The section's stateless half, for a body that arrives with no view:
/// each reference parses (J29), the references ascend and are counted by
/// the root the header commits (J29), and each names a block the including
/// block is inside the window of (J31) — [`check_section_stateless`]
/// (`SCS-P23`). The budget (J30) and the bundles (J32 through J37) need the
/// chain and are [`admit`]'s.
///
/// A session that is sent a body whose references do not match its
/// header's root closes here, before the block costs a `validate`.
///
/// # Errors
///
/// The first section refusal, at the reference it names.
pub(crate) fn bind_section(
    references: &[Vec<u8>],
    header_root: &[u8; 32],
    h_incl: BlockHeight,
    rule_set: &RuleSet,
) -> Verdict<()> {
    let mut refs = Vec::with_capacity(references.len());
    for (position, bytes) in references.iter().enumerate() {
        refs.push(open_reference(position, bytes).map_err(section_refusal)?);
    }
    check_section_stateless(&refs, header_root, h_incl, rule_set)
        .map(|_standing| ())
        .map_err(section_refusal)
}

/// The epoch a view answered as awaiting: the first of the section's epochs
/// whose drawable set it does not hold, after the filing put every one in
/// the memo. A view that then answers every one has contradicted itself,
/// and the first reference's epoch names the section it did that for.
fn unanswered_epoch<B: BundleView>(
    refs: &[BundleRef],
    bundles: &B,
    schedule: shekyl_archival_retention::SettlementSchedule,
) -> Result<BundleUnanswered, B::Fault> {
    for reference in refs {
        let epoch = schedule.epoch_at(reference.h());
        if bundles.drawable_epoch(epoch)?.is_none() {
            return Ok(BundleUnanswered::DrawableEpoch { epoch });
        }
    }
    let first = refs.first().map_or(BlockHeight::from_raw(0), BundleRef::h);
    Ok(BundleUnanswered::DrawableEpoch {
        epoch: schedule.epoch_at(first),
    })
}

/// A section refusal, at the reference it names, or at the block when it is
/// about the section as a whole (its root, its count, its budget).
fn section_refusal(refused: SectionRefused) -> InvalidBlock {
    let locus = match refused {
        SectionRefused::Malformed { position }
        | SectionRefused::OutOfOrder { position }
        | SectionRefused::OutsideWindow { position } => Locus::Bundle { position },
        SectionRefused::TooManyReferences { .. }
        | SectionRefused::Root
        | SectionRefused::OverBudget { .. } => Locus::Block,
    };
    InvalidBlock::new(refused.row(), locus)
}

#[cfg(test)]
#[path = "bundle_admission_tests.rs"]
mod bundle_admission_tests;
