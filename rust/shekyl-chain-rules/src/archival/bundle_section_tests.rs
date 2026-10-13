// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `check_section` and `open_reference`: order, the header root, and the
//! section budget (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.1 steps 1 and 2,
//! `SCS-P39`, `SCS-P40`).
//!
//! Sibling of `bundle_tests`, which judges one bundle. Every test names
//! the edit that turns it red.

use shekyl_archival_retention::{
    bundle_root, section_budget, BundleRef, PassBitmap, BUNDLE_SECTION_BUDGET_MULTIPLE,
};
use shekyl_types::BlockHeight;

use super::*;
use crate::rule_set::SettlementEpochBlocks;

/// `reference` naming another prunable hash.
fn with_hash(reference: &BundleRef, prunable_hash: [u8; 32]) -> BundleRef {
    BundleRef::new(reference.kept().clone(), prunable_hash)
}

/// A reference at `h` to a bundle of `count` draws, none passed.
fn reference_at(h: u64, count: u32) -> BundleRef {
    BundleRef::new(
        shekyl_archival_retention::BundleKept {
            h: BlockHeight::from_raw(h),
            seed: [0x5E; 32],
            passes: PassBitmap::from_passes(count, []).expect("no passes"),
        },
        [0xAB; 32],
    )
}

/// A section of bundles with these counts, at ascending heights.
fn section_of(counts: &[u32]) -> Vec<BundleRef> {
    counts
        .iter()
        .zip(100u64..)
        .map(|(count, h)| reference_at(h, *count))
        .collect()
}

/// `check_section` on a section whose root is its own, as its charge.
fn charged(refs: &[BundleRef], budget: Option<u64>) -> Result<u64, SectionRefused> {
    check_section(refs, &bundle_root(refs), budget).map(SectionCharge::get)
}

/// References are in strictly ascending `h`, so none repeats. Red edit:
/// `>` for `>=` admits two references to one `h`.
#[test]
fn a_section_out_of_order_or_repeating_an_h_refuses() {
    let a = reference_at(100, 8);
    let b = reference_at(101, 3);
    let c = reference_at(250, 0);
    let check = |refs: &[BundleRef]| charged(refs, None);

    assert_eq!(check(&[]), Ok(0));
    assert_eq!(check(std::slice::from_ref(&a)), Ok(8));
    assert_eq!(check(&[a.clone(), b.clone(), c.clone()]), Ok(8 + 3 + 1));

    assert_eq!(
        check(&[a.clone(), a.clone()]),
        Err(SectionRefused::OutOfOrder { position: 1 }),
        "one h twice"
    );
    // Two different bundles for one `h` are still one `h` twice.
    let a_other = reference_at(100, 9);
    assert_eq!(
        check(&[a.clone(), a_other]),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    assert_eq!(
        check(&[b.clone(), a.clone(), c.clone()]),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    assert_eq!(
        check(&[a, c, b]),
        Err(SectionRefused::OutOfOrder { position: 2 })
    );
}

/// §9.1 step 1, "each reference parses": bytes that are not a reference —
/// the wrong length for the count they state, or a set padding bit — are
/// a typed section refusal at the reference's position, raised where a
/// section's references are decoded. Red edit: let `open_reference`
/// return the wire error; the block that carried the bytes then has no
/// verdict.
#[test]
fn a_reference_that_does_not_parse_is_a_section_refusal_at_its_position() {
    let good = reference_at(100, 12).encode();
    assert_eq!(open_reference(0, &good), Ok(reference_at(100, 12)));

    let malformed = |bytes: &[u8]| {
        let refused = open_reference(3, bytes).expect_err("not a reference");
        assert_eq!(refused, SectionRefused::Malformed { position: 3 });
        assert_eq!(refused.row(), CenRow::J29);
    };
    malformed(&[]);
    malformed(&good[..good.len() - 1]);
    let mut long = good.clone();
    long.push(0);
    malformed(&long);
    // The stated count says thirteen bytes of bitmap; two are there.
    let mut restated = good.clone();
    restated[40..44].copy_from_slice(&97u32.to_le_bytes());
    malformed(&restated);
    // Twelve bits, and bit 12 of the bitmap set.
    let mut padded = good.clone();
    padded[45] |= 0x10;
    malformed(&padded);
}

/// The header root recomputes from the references. Red edit: skip the
/// comparison; or compare against the root of the references sorted.
#[test]
fn a_section_whose_root_does_not_recompute_refuses() {
    let a = reference_at(100, 8);
    let b = reference_at(101, 3);
    let refs = [a.clone(), b.clone()];
    let root = bundle_root(&refs);
    assert_eq!(
        check_section(&refs, &root, None).map(SectionCharge::get),
        Ok(11)
    );

    let mut wrong = root;
    wrong[5] ^= 1;
    assert_eq!(
        check_section(&refs, &wrong, None),
        Err(SectionRefused::Root)
    );
    // The root of a section that omits a reference, or adds one.
    assert_eq!(
        check_section(&refs, &bundle_root(std::slice::from_ref(&a)), None),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section(std::slice::from_ref(&a), &root, None),
        Err(SectionRefused::Root)
    );
    // One field of one reference: a different prunable hash, and a
    // different stated count over the same bitmap bytes.
    assert_eq!(
        check_section(&[a.clone(), with_hash(&b, [0xAC; 32])], &root, None),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section(&[a, reference_at(101, 4)], &root, None),
        Err(SectionRefused::Root),
        "three draws and four are one byte of bitmap and two roots"
    );
    // An empty section commits the empty root, and no other.
    assert_eq!(charged(&[], None), Ok(0));
    assert_eq!(
        check_section(&[], &[0; 32], None),
        Err(SectionRefused::Root)
    );
}

/// Red edit 3 of the specification's §11: **a budget sum one over.** The
/// charges of a section sum to at most `c · (⌊9·D / SEB⌋ + 1)`: exactly at
/// the budget admits, one over refuses — at the count cap of a large `D`,
/// and at a `D` so small that `⌊9·D / SEB⌋` is zero and the budget is the
/// `+ 1` alone (`SCS-P33`). A bundle with draws is charged its draws, so
/// two bundles at the count cap are still what a section holds. Red
/// edits: `>=` for `>` refuses a section at its budget; drop the `+ 1`
/// and the small network's budget is zero.
#[test]
fn a_section_at_its_budget_admits_and_one_over_refuses() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let c = BUNDLE_SECTION_BUDGET_MULTIPLE;
    let check = |counts: &[u32], budget: u64| charged(&section_of(counts), Some(budget));
    let over = |charge: u64, budget: u64| {
        Err(SectionRefused::OverBudget {
            charge: SectionCharge::of(&section_of(&[u32::try_from(charge).expect("small")])),
            budget,
        })
    };

    // `D` = 8: `⌊72 / 10,000⌋` is zero, the count cap is 1, the budget 2.
    let small = section_budget(c, 8, seb);
    assert_eq!(small, 2);
    assert_eq!(check(&[1, 1], small), Ok(2));
    assert_eq!(check(&[2], small), Ok(2));
    assert_eq!(check(&[1, 2], small), over(3, small));
    assert_eq!(check(&[1, 1, 1], small), over(3, small));

    // `D` = 324,000: the count cap is 292 and the budget two of them.
    let large = section_budget(c, 324_000, seb);
    assert_eq!(large, 584);
    assert_eq!(check(&[292, 292], large), Ok(584), "two bundles at the cap");
    assert_eq!(check(&[100, 192, 292], large), Ok(584));
    assert_eq!(check(&[292, 293], large), over(585, large));
}

/// **A bundle is charged `max(count, 1)`** (`SCS-P40`): a zero-draw bundle
/// is admissible and costs one, so it cannot be used to fill a section
/// for free. A section of zero-draw bundles is admitted exactly at the
/// budget and refused one over — on a small network, where the budget is
/// 2 and zero-draw blocks are common, and on a large one. A mixed section
/// pays for both kinds.
///
/// **Red edit: sum `count` instead of the charge** (`r.count()` for
/// `r.charge()` in `SectionCharge::of`). Every zero-draw section below
/// then charges nothing and is admitted whatever its length: the "one
/// over" assertions fail, and so does the 500-bundle one.
#[test]
fn a_zero_draw_bundle_costs_one_and_a_section_of_them_is_bounded() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let c = BUNDLE_SECTION_BUDGET_MULTIPLE;
    let zeros = |n: usize| section_of(&vec![0u32; n]);
    let over = |refs: &[BundleRef], budget: u64| {
        Err(SectionRefused::OverBudget {
            charge: SectionCharge::of(refs),
            budget,
        })
    };

    // The small network: budget 2, so two zero-draw bundles and no third.
    let small = section_budget(c, 8, seb);
    assert_eq!(small, 2);
    assert_eq!(charged(&zeros(1), Some(small)), Ok(1));
    assert_eq!(charged(&zeros(2), Some(small)), Ok(2));
    assert_eq!(charged(&zeros(3), Some(small)), over(&zeros(3), small));
    assert_eq!(SectionCharge::of(&zeros(3)).get(), 3);
    // What `SCS-P40` closes: one for every zero-draw block of the last
    // `W₂`, 500 of them, under a budget of 2.
    assert_eq!(SectionCharge::of(&zeros(500)).get(), 500);
    assert_eq!(charged(&zeros(500), Some(small)), over(&zeros(500), small));

    // The large network: 584 zero-draw bundles and no more.
    let large = section_budget(c, 324_000, seb);
    assert_eq!(charged(&zeros(584), Some(large)), Ok(584));
    assert_eq!(charged(&zeros(585), Some(large)), over(&zeros(585), large));

    // Mixed: a zero-draw bundle beside bundles with draws costs its one.
    let mixed = section_of(&[0, 1, 0]);
    assert_eq!(charged(&mixed, Some(3)), Ok(3));
    assert_eq!(charged(&mixed, Some(2)), over(&mixed, 2));
    let at_cap = section_of(&[292, 0, 291]);
    assert_eq!(charged(&at_cap, Some(large)), Ok(584));
    let one_more = section_of(&[292, 0, 292]);
    assert_eq!(charged(&one_more, Some(large)), over(&one_more, large));
    // And a bundle with draws is charged exactly its draws: two at the
    // count cap fit, as before the amendment.
    assert_eq!(charged(&section_of(&[292, 292]), Some(large)), Ok(584));
}

/// With no budget the charge is still taken and returned: `D` is not
/// known where an alternative block arrives above the fork point, so the
/// comparison waits for the switch and is made on this value (`SCS-P23`,
/// `SCS-P39`). Red edit: return a zero charge when no budget is given —
/// the switch would then compare nothing.
#[test]
fn a_section_with_no_budget_still_returns_its_charge() {
    let refs = section_of(&[292, 0, 293]);
    let charge = check_section(&refs, &bundle_root(&refs), None).expect("form holds");
    assert_eq!(charge.get(), 586);
    assert_eq!(charge, SectionCharge::of(&refs));
    // At the switch, with `D` known.
    assert!(!charge.within(584));
    assert!(charge.within(586));
    assert!(charge.within(u64::MAX));
}

/// The section's checks in §9.1's order: form (order, then root) before
/// budget. Red edit: check the budget first.
#[test]
fn of_two_section_defects_the_earlier_check_refuses() {
    let a = reference_at(100, 8);
    let b = reference_at(101, 8);
    let swapped = [b.clone(), a.clone()];
    // Out of order, a wrong root, and over budget at once.
    assert_eq!(
        check_section(&swapped, &[0; 32], Some(0)),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    // In order, a wrong root, and over budget.
    assert_eq!(
        check_section(&[a.clone(), b.clone()], &[0; 32], Some(0)),
        Err(SectionRefused::Root)
    );
    let refs = [a, b];
    assert_eq!(
        check_section(&refs, &bundle_root(&refs), Some(15)),
        Err(SectionRefused::OverBudget {
            charge: SectionCharge::of(&refs),
            budget: 15
        })
    );
    assert_eq!(SectionCharge::of(&refs).get(), 16);
}
