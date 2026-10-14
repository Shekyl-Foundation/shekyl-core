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

use std::sync::OnceLock;

use shekyl_archival_retention::{
    bundle_root, section_budget, BundleRef, DrawableEpoch, DrawablePair, PassBitmap,
    BUNDLE_SECTION_BUDGET_MULTIPLE,
};
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_types::{BlockHeight, SettlementEpoch};

use super::*;
use crate::harness::bundle::{with_hash, BundleRead, BundleReadFaulted, FixtureBundleView};
use crate::rule_set::{SettlementEpochBlocks, SettlementSchedule};

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

/// [`bundle_root`] over a section a test holds: far fewer than 2³²
/// references, so its one refusal is not this helper's.
fn root_of(refs: &[BundleRef]) -> [u8; 32] {
    bundle_root(refs).expect("a test section's count fits 32 bits")
}

/// The comparison tests' cap. [`check_section`] computes the real one from
/// the section's epochs; this door exists so a test can name a cap.
pub(super) fn check_section_at_cap(
    refs: &[BundleRef],
    header_root: &[u8; 32],
    cap: u64,
) -> Result<SectionCharge, SectionRefused> {
    let charge = super::section_form(refs, header_root)?;
    if charge.within(cap) {
        Ok(charge)
    } else {
        Err(SectionRefused::OverBudget {
            charge,
            budget: cap,
        })
    }
}

/// The comparison seam: a section whose root is its own, judged at `cap`.
fn charged(refs: &[BundleRef], cap: u64) -> Result<u64, SectionRefused> {
    check_section_at_cap(refs, &root_of(refs), cap).map(SectionCharge::get)
}

/// Arrival, before any `D` is known. A non-empty section waits.
fn awaiting(refs: &[BundleRef]) -> Result<SectionStanding, SectionRefused> {
    check_section_until_switch(refs, &root_of(refs))
}

/// References are in strictly ascending `h`, so none repeats. Red edit:
/// `>` for `>=` admits two references to one `h`.
#[test]
fn a_section_out_of_order_or_repeating_an_h_refuses() {
    let a = reference_at(100, 8);
    let b = reference_at(101, 3);
    let c = reference_at(250, 0);
    let check = |refs: &[BundleRef]| awaiting(refs).map(|standing| standing.charge().get());

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

/// The J29 arm's row and message. Driving `check_section` into the arm
/// would take a section of 2³² references; the bound itself is
/// `shekyl-archival-retention`'s `a_section_the_root_cannot_count_has_no_root`.
/// Red edit: file the arm under J30.
#[test]
fn a_section_the_root_cannot_count_is_a_j29_refusal() {
    // `usize::MAX` rather than 2³²: the arm is data, and the literal has to
    // exist on a 32-bit target too.
    let found = usize::MAX;
    let refused = SectionRefused::TooManyReferences { found };
    assert_eq!(refused.row(), CenRow::J29);
    assert_eq!(
        refused.to_string(),
        format!(
            "CEN-J29 refused: the section's {found} references are more than the header root can \
             count"
        )
    );
}

/// The header root recomputes from the references. Red edit: skip the
/// comparison; or compare against the root of the references sorted.
#[test]
fn a_section_whose_root_does_not_recompute_refuses() {
    let a = reference_at(100, 8);
    let b = reference_at(101, 3);
    let refs = [a.clone(), b.clone()];
    let root = root_of(&refs);
    assert_eq!(
        check_section_until_switch(&refs, &root),
        Ok(SectionStanding::Awaiting(SectionCharge::of(&refs)))
    );

    let mut wrong = root;
    wrong[5] ^= 1;
    assert_eq!(
        check_section_until_switch(&refs, &wrong),
        Err(SectionRefused::Root)
    );
    // The root of a section that omits a reference, or adds one.
    assert_eq!(
        check_section_until_switch(&refs, &root_of(std::slice::from_ref(&a))),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section_until_switch(std::slice::from_ref(&a), &root),
        Err(SectionRefused::Root)
    );
    // One field of one reference: a different prunable hash, and a
    // different stated count over the same bitmap bytes.
    assert_eq!(
        check_section_until_switch(&[a.clone(), with_hash(&b, [0xAC; 32])], &root),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section_until_switch(&[a, reference_at(101, 4)], &root),
        Err(SectionRefused::Root),
        "three draws and four are one byte of bitmap and two roots"
    );
    // An empty section commits the empty root, and no other. It names no
    // epoch, so arrival admits it.
    assert_eq!(
        check_section_until_switch(&[], &root_of(&[])),
        Ok(SectionStanding::Admitted(SectionCharge::of(&[])))
    );
    assert_eq!(
        check_section_until_switch(&[], &[0; 32]),
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
    let check = |counts: &[u32], budget: u64| charged(&section_of(counts), budget);
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
    assert_eq!(charged(&zeros(1), small), Ok(1));
    assert_eq!(charged(&zeros(2), small), Ok(2));
    assert_eq!(charged(&zeros(3), small), over(&zeros(3), small));
    assert_eq!(SectionCharge::of(&zeros(3)).get(), 3);
    // What `SCS-P40` closes: one for every zero-draw block of the last
    // `W₂`, 500 of them, under a budget of 2.
    assert_eq!(SectionCharge::of(&zeros(500)).get(), 500);
    assert_eq!(charged(&zeros(500), small), over(&zeros(500), small));

    // The large network: 584 zero-draw bundles and no more.
    let large = section_budget(c, 324_000, seb);
    assert_eq!(charged(&zeros(584), large), Ok(584));
    assert_eq!(charged(&zeros(585), large), over(&zeros(585), large));

    // Mixed: a zero-draw bundle beside bundles with draws costs its one.
    let mixed = section_of(&[0, 1, 0]);
    assert_eq!(charged(&mixed, 3), Ok(3));
    assert_eq!(charged(&mixed, 2), over(&mixed, 2));
    let at_cap = section_of(&[292, 0, 291]);
    assert_eq!(charged(&at_cap, large), Ok(584));
    let one_more = section_of(&[292, 0, 292]);
    assert_eq!(charged(&one_more, large), over(&one_more, large));
    // And a bundle with draws is charged exactly its draws: two at the
    // count cap fit, as before the amendment.
    assert_eq!(charged(&section_of(&[292, 292]), large), Ok(584));
}

/// At arrival the charge is still taken: `D` is not known where an
/// alternative block arrives above the fork point, so a non-empty section
/// awaits and the switch compares this charge (`SCS-P23`, `SCS-P39`). An
/// empty section does not await. Red edit: admit the non-empty section at
/// arrival, or return a zero charge — the switch would then compare
/// nothing.
#[test]
fn a_section_awaiting_its_budget_keeps_its_charge() {
    let refs = section_of(&[292, 0, 293]);
    let standing = awaiting(&refs).expect("form holds");
    assert_eq!(
        standing,
        SectionStanding::Awaiting(SectionCharge::of(&refs))
    );
    let charge = standing.charge();
    assert_eq!(charge.get(), 586);
    // The number the switch's cap is compared with.
    assert!(!charge.within(584));
    assert!(charge.within(586));
    assert!(charge.within(u64::MAX));

    assert_eq!(
        check_section_until_switch(&[], &root_of(&[])),
        Ok(SectionStanding::Admitted(SectionCharge::of(&[])))
    );
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
        check_section_at_cap(&swapped, &[0; 32], 0),
        Err(SectionRefused::OutOfOrder { position: 1 })
    );
    // In order, a wrong root, and over budget.
    assert_eq!(
        check_section_at_cap(&[a.clone(), b.clone()], &[0; 32], 0),
        Err(SectionRefused::Root)
    );
    let refs = [a, b];
    assert_eq!(
        check_section_at_cap(&refs, &root_of(&refs), 15),
        Err(SectionRefused::OverBudget {
            charge: SectionCharge::of(&refs),
            budget: 15
        })
    );
    assert_eq!(SectionCharge::of(&refs).get(), 16);
}

const PERSONA: [u8; 32] = [0x41; 32];

/// One receipt key, generated once. A drawable epoch parses it.
fn receipt_key() -> &'static Vec<u8> {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        HybridEd25519FnDsa::keypair_from_seeds(&[0x41; 32], &[0x42; 32])
            .expect("fixture receipt key")
            .0
            .to_canonical_bytes()
    })
}

/// Epoch `epoch` with `pairs` shards of one persona. `pairs` is `D`.
fn drawable(epoch: u64, pairs: u64) -> DrawableEpoch {
    let epoch = SettlementEpoch::from_raw(epoch);
    let keys = (pairs > 0).then(|| (PERSONA, receipt_key().clone()));
    DrawableEpoch::new(
        epoch,
        keys,
        (0..pairs).map(|shard_id| DrawablePair {
            p_id: PERSONA,
            shard_id,
        }),
    )
    .expect("one persona, distinct shards")
}

fn view_holding(epochs: &[(u64, u64)]) -> FixtureBundleView {
    let mut view = FixtureBundleView::default();
    for &(epoch, pairs) in epochs {
        view.drawable_epochs
            .insert(SettlementEpoch::from_raw(epoch), drawable(epoch, pairs));
    }
    view
}

/// The cap is the largest `D` among the section's own epochs, read as
/// [`DrawableEpoch::len`]. A section spans the epoch boundary: `D = 0` on
/// the earlier epoch budgets 2, and `D` of one pair per block of the epoch
/// budgets 20. Charge 4 fits only the larger. Red edits: take the first
/// epoch's `D` (this section is then over budget 2); take a partial
/// maximum when the later epoch is missing (that is also over budget 2,
/// and the section must await).
#[test]
fn the_cap_is_the_largest_d_among_the_sections_epochs() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let schedule = SettlementSchedule::new(seb);
    let boundary = seb.get();
    // Two references in the earlier epoch, one in the later. Three
    // references, two epochs: each epoch is asked once.
    let spanning = [
        reference_at(boundary - 2, 2),
        reference_at(boundary - 1, 1),
        reference_at(boundary, 1),
    ];
    assert_eq!(SectionCharge::of(&spanning).get(), 4);
    let small_cap = section_budget(BUNDLE_SECTION_BUDGET_MULTIPLE, 0, seb);
    let large_cap = section_budget(BUNDLE_SECTION_BUDGET_MULTIPLE, boundary, seb);
    assert_eq!((small_cap, large_cap), (2, 20));

    let both = view_holding(&[(0, 0), (1, boundary)]);
    both.take_reads();
    assert_eq!(
        check_section(&spanning, &root_of(&spanning), &both, schedule),
        Ok(SectionStanding::Admitted(SectionCharge::of(&spanning)))
    );
    assert_eq!(
        both.take_reads(),
        [BundleRead::DrawableEpoch, BundleRead::DrawableEpoch]
    );

    // The earlier epoch alone, with the same charge, is over its own cap.
    let earlier = [reference_at(boundary - 2, 2), reference_at(boundary - 1, 2)];
    let only_small = view_holding(&[(0, 0)]);
    assert_eq!(
        check_section(&earlier, &root_of(&earlier), &only_small, schedule),
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge: SectionCharge::of(&earlier),
            budget: small_cap,
        }))
    );

    // The later epoch missing is not the earlier epoch's cap. It waits.
    let later_unknown = view_holding(&[(0, 0)]);
    assert_eq!(
        check_section(&spanning, &root_of(&spanning), &later_unknown, schedule),
        Ok(SectionStanding::Awaiting(SectionCharge::of(&spanning)))
    );
}

/// An empty section is admitted without a read. A drawable epoch filed
/// under the wrong epoch is not that epoch's `D`. A view fault is the
/// fault. Form still refuses before any read. Red edits: budget an empty
/// section as awaiting; accept a drawable epoch whose `epoch()` is not the
/// one asked; map a fault to `Awaiting`.
#[test]
fn an_empty_section_is_admitted_and_an_unreadable_epoch_is_not_a_cap() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let schedule = SettlementSchedule::new(seb);
    let boundary = seb.get();
    let spanning = [reference_at(boundary - 1, 2), reference_at(boundary, 2)];

    let mut faulting = view_holding(&[]);
    faulting.fault = Some(BundleRead::DrawableEpoch);
    faulting.take_reads();
    assert_eq!(
        check_section(&[], &root_of(&[]), &faulting, schedule),
        Ok(SectionStanding::Admitted(SectionCharge::of(&[])))
    );
    assert!(faulting.take_reads().is_empty());

    let mut mismatched = FixtureBundleView::default();
    mismatched
        .drawable_epochs
        .insert(SettlementEpoch::from_raw(0), drawable(9, boundary));
    mismatched
        .drawable_epochs
        .insert(SettlementEpoch::from_raw(1), drawable(1, boundary));
    assert_eq!(
        check_section(&spanning, &root_of(&spanning), &mismatched, schedule),
        Ok(SectionStanding::Awaiting(SectionCharge::of(&spanning)))
    );

    faulting.take_reads();
    assert_eq!(
        check_section(&spanning, &root_of(&spanning), &faulting, schedule),
        Err(SectionCheckFailed::View(BundleReadFaulted(
            BundleRead::DrawableEpoch
        )))
    );

    let swapped = [spanning[1].clone(), spanning[0].clone()];
    faulting.take_reads();
    assert_eq!(
        check_section(&swapped, &root_of(&spanning), &faulting, schedule),
        Err(SectionCheckFailed::Refused(SectionRefused::OutOfOrder {
            position: 1
        }))
    );
    assert!(faulting.take_reads().is_empty());
}
