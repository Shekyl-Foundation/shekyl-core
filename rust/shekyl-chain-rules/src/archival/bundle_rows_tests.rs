// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle rows' census registration: each refusal names its row, and
//! each rule type `validate` runs is the verifier's name for it.
//!
//! Sibling of `bundle_tests`, `bundle_section_tests`, and
//! `bundle_fill_tests`. Every test names the edit that turns it red.

use shekyl_archival_retention::{BundleRef, PassBitmap};
use shekyl_types::BlockHeight;

use super::*;

/// One reference of `count` draws, for a charge that only needs a count.
fn reference_of(count: u32) -> BundleRef {
    BundleRef::new(
        shekyl_archival_retention::BundleKept {
            h: BlockHeight::from_raw(100),
            seed: [0x5E; 32],
            passes: PassBitmap::from_passes(count, []).expect("no passes"),
            support: PassBitmap::none(),
        },
        [0xAB; 32],
    )
}

/// Every refusal names its census row, and a record's refusal its draw.
/// Red edit: move an arm to another row in `BundleInvalid::row`.
#[test]
fn every_refusal_names_its_census_row() {
    use BundleInvalid as B;
    assert_eq!(
        SectionRefused::OutOfOrder { position: 1 }.row(),
        CenRow::J29
    );
    assert_eq!(SectionRefused::Root.row(), CenRow::J29);
    assert_eq!(SectionRefused::Malformed { position: 0 }.row(), CenRow::J29);
    assert_eq!(
        SectionRefused::OverBudget {
            charge: SectionCharge::of(std::slice::from_ref(&reference_of(3))),
            budget: shekyl_archival_retention::SectionBudget::from_draws(2)
        }
        .row(),
        CenRow::J30
    );
    assert_eq!(
        SectionRefused::TooManyReferences { found: usize::MAX }.row(),
        CenRow::J29
    );
    assert_eq!(
        SectionRefused::OutsideWindow { position: 0 }.row(),
        CenRow::J31
    );
    let rows: [(B, CenRow, Option<u32>); 10] = [
        (B::OutsideWindow, CenRow::J31, None),
        (B::AlreadyRevealed, CenRow::J31, None),
        (B::BodyMalformed, CenRow::J32, None),
        (B::Count, CenRow::J32, None),
        (B::RecordCount, CenRow::J32, None),
        (B::Commitment, CenRow::J33, None),
        (B::WitnessSignature, CenRow::J34, None),
        (B::Attempt { draw: 7 }, CenRow::J35, Some(7)),
        (B::Anchor { draw: 8 }, CenRow::J36, Some(8)),
        (B::Receipt { draw: 9 }, CenRow::J37, Some(9)),
    ];
    for (refusal, row, draw) in rows {
        assert_eq!(refusal.row(), row, "{refusal:?}");
        assert_eq!(refusal.draw(), draw, "{refusal:?}");
        assert!(
            refusal.to_string().starts_with(row.as_str()),
            "{refusal}: the message leads with the row"
        );
    }
}

/// The rows are registered `pending`: in the denominator and bound to no
/// rule type, so no verdict's coverage holds them. Red edit: flip one to
/// `implemented(...)` without wiring it — and this test is then the
/// cutover's to delete, with the next one.
/// Each rule type's row is the verifier's name for that refusal: the row
/// `validate` reports is the row the census binds.
#[test]
fn the_rule_types_name_the_verifier_rows() {
    use crate::census::CenRow;
    use crate::rules::bundle_admission::{J29, J30, J31, J32, J33, J34, J35, J36, J37};
    use crate::rules::Rule;
    use shekyl_archival_retention::SectionBudget;

    let charge = SectionCharge::of(&[]);
    let budget = SectionBudget::from_draws(0);
    let section = [
        (SectionRefused::Malformed { position: 0 }.row(), J29::ROW),
        (SectionRefused::OutOfOrder { position: 1 }.row(), J29::ROW),
        (
            SectionRefused::TooManyReferences { found: usize::MAX }.row(),
            J29::ROW,
        ),
        (SectionRefused::Root.row(), J29::ROW),
        (
            SectionRefused::OverBudget { charge, budget }.row(),
            J30::ROW,
        ),
        (
            SectionRefused::OutsideWindow { position: 0 }.row(),
            J31::ROW,
        ),
    ];
    for (named, row) in section {
        assert_eq!(named, row);
    }
    let bundles = [
        (BundleInvalid::OutsideWindow.row(), J31::ROW),
        (BundleInvalid::AlreadyRevealed.row(), J31::ROW),
        (BundleInvalid::BodyMalformed.row(), J32::ROW),
        (BundleInvalid::Count.row(), J32::ROW),
        (BundleInvalid::RecordCount.row(), J32::ROW),
        (BundleInvalid::Commitment.row(), J33::ROW),
        (BundleInvalid::WitnessSignature.row(), J34::ROW),
        (BundleInvalid::Attempt { draw: 0 }.row(), J35::ROW),
        (BundleInvalid::Anchor { draw: 0 }.row(), J36::ROW),
        (BundleInvalid::Receipt { draw: 0 }.row(), J37::ROW),
    ];
    for (named, row) in bundles {
        assert_eq!(named, row);
    }
    assert_eq!(J29::ROW, CenRow::J29);
    assert_eq!(J37::ROW, CenRow::J37);
}
