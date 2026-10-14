// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `check_section` and `open_reference`: order, the header root, the
//! window, then the section budget (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.1
//! steps 1 and 2, `SCS-P39`, `SCS-P40`, `SCS-P41`).
//!
//! Admission in this file is [`check_section`] or
//! [`check_section_until_switch`]. [`SectionCharge`] is the arithmetic
//! and is not a section result. Sibling of `bundle_tests`, which judges
//! one bundle. Every test names the edit that turns it red.

use std::sync::OnceLock;

use shekyl_archival_retention::{
    bundle_root, section_budget, BundleRef, DrawableEpoch, DrawablePair, PassBitmap,
    BUNDLE_SECTION_BUDGET_MULTIPLE,
};
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_types::{BlockHeight, SettlementEpoch};

use super::*;
use crate::harness::bundle::{with_hash, BundleRead, BundleReadFaulted, FixtureBundleView};
use crate::rule_set::{FakechainSchedule, SettlementEpochBlocks};
use shekyl_types::BlockCount;

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

/// The including block for `refs`: one above the last. The oldest
/// reference then sits `refs.len()` blocks below it, so a section of
/// consecutive heights longer than `W₂` fails the window at position 0.
/// An empty section is included at 101.
fn h_incl_of(refs: &[BundleRef]) -> BlockHeight {
    BlockHeight::from_raw(refs.last().map_or(101, |r| r.h().to_raw() + 1))
}

/// A Fakechain rule set whose epoch is `blocks` long, so `W₂` is
/// `blocks / 20`, with a reorg cap of 10.
pub(in crate::archival::bundle) fn rules_of(blocks: u64) -> RuleSet {
    RuleSet::fakechain(
        None,
        FakechainSchedule::new(
            SettlementEpochBlocks::new(blocks).expect("non-zero"),
            BlockCount::from_raw(10),
        )
        .expect("0 < cap < SEB, and W₂ + L within the anchor depth"),
    )
}

/// [`check_section`] over `refs`, rooted from them, included one above the
/// last. The cap is the one `view`'s `D` and `rules` derive.
fn judged(
    refs: &[BundleRef],
    view: &FixtureBundleView,
    rules: &RuleSet,
) -> Result<SectionStanding, SectionCheckFailed<BundleReadFaulted>> {
    check_section(refs, &root_of(refs), h_incl_of(refs), view, rules)
}

/// Arrival, before any `D` is known. A non-empty section waits.
fn awaiting(refs: &[BundleRef]) -> Result<SectionStanding, SectionRefused> {
    check_section_until_switch(refs, &root_of(refs), h_incl_of(refs), &RuleSet::GENESIS)
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
    // Every section here is of references at 100 and 101, or empty.
    let incl = BlockHeight::from_raw(102);
    let a = reference_at(100, 8);
    let b = reference_at(101, 3);
    let refs = [a.clone(), b.clone()];
    let root = root_of(&refs);
    assert_eq!(
        check_section_until_switch(&refs, &root, incl, &RuleSet::GENESIS),
        Ok(SectionStanding::Awaiting(SectionCharge::of(&refs)))
    );

    let mut wrong = root;
    wrong[5] ^= 1;
    assert_eq!(
        check_section_until_switch(&refs, &wrong, incl, &RuleSet::GENESIS),
        Err(SectionRefused::Root)
    );
    // The root of a section that omits a reference, or adds one.
    assert_eq!(
        check_section_until_switch(
            &refs,
            &root_of(std::slice::from_ref(&a)),
            incl,
            &RuleSet::GENESIS
        ),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section_until_switch(std::slice::from_ref(&a), &root, incl, &RuleSet::GENESIS),
        Err(SectionRefused::Root)
    );
    // One field of one reference: a different prunable hash, and a
    // different stated count over the same bitmap bytes.
    assert_eq!(
        check_section_until_switch(
            &[a.clone(), with_hash(&b, [0xAC; 32])],
            &root,
            incl,
            &RuleSet::GENESIS
        ),
        Err(SectionRefused::Root)
    );
    assert_eq!(
        check_section_until_switch(&[a, reference_at(101, 4)], &root, incl, &RuleSet::GENESIS),
        Err(SectionRefused::Root),
        "three draws and four are one byte of bitmap and two roots"
    );
    // An empty section commits the empty root, and no other. It names no
    // epoch, so arrival admits it.
    assert_eq!(
        check_section_until_switch(&[], &root_of(&[]), incl, &RuleSet::GENESIS),
        Ok(SectionStanding::Admitted(SectionCharge::of(&[])))
    );
    assert_eq!(
        check_section_until_switch(&[], &[0; 32], incl, &RuleSet::GENESIS),
        Err(SectionRefused::Root)
    );
}

/// Red edit 3 of the specification's §11: **a budget sum one over.** The
/// charges of a section sum to at most `c · (⌊9·D / SEB⌋ + 1)`: exactly at
/// the budget admits, one over refuses — at the count cap of a `D` this
/// fixture can hold, and at a `D` so small that `⌊9·D / SEB⌋` is zero and
/// the budget is the `+ 1` alone (`SCS-P33`). A bundle with draws is
/// charged its draws, so two bundles at the count cap are still what a
/// section holds. The cap is the one [`check_section`] derives from `D`.
/// Red edits: `>=` for `>` refuses a section at its budget; drop the `+ 1`
/// and the small network's budget is zero.
#[test]
fn a_section_at_its_budget_admits_and_one_over_refuses() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let c = BUNDLE_SECTION_BUDGET_MULTIPLE;
    let rules = rules_of(seb.get());
    let over = |counts: &[u32], budget: u64| {
        let refs = section_of(counts);
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge: SectionCharge::of(&refs),
            budget,
        }))
    };
    let admit = |counts: &[u32], view: &FixtureBundleView| {
        let refs = section_of(counts);
        assert_eq!(
            judged(&refs, view, &rules),
            Ok(SectionStanding::Admitted(SectionCharge::of(&refs)))
        );
    };

    // `D` = 8: `⌊72 / 10,000⌋` is zero, the count cap is 1, the budget 2.
    let small = section_budget(c, 8, seb);
    assert_eq!(small, 2);
    let small_view = view_holding(&[(0, 8)]);
    admit(&[1, 1], &small_view);
    admit(&[2], &small_view);
    assert_eq!(
        judged(&section_of(&[1, 2]), &small_view, &rules),
        over(&[1, 2], small)
    );
    assert_eq!(
        judged(&section_of(&[1, 1, 1]), &small_view, &rules),
        over(&[1, 1, 1], small)
    );

    // `D` = 10,000: the count cap is 10 and the budget two of them.
    // `D` = 324,000 is the large network's cap of 292 and budget of 584;
    // that figure is [`section_budget`]'s, and a section of 584 references
    // does not fit the window (the zero-draw test).
    let wide = section_budget(c, 10_000, seb);
    assert_eq!(wide, 20);
    let wide_view = view_holding(&[(0, 10_000)]);
    admit(&[10, 10], &wide_view);
    admit(&[4, 6, 10], &wide_view);
    assert_eq!(
        judged(&section_of(&[10, 11]), &wide_view, &rules),
        over(&[10, 11], wide)
    );
    let large = section_budget(c, 324_000, seb);
    assert_eq!(large, 584);
    assert!(SectionCharge::of(&section_of(&[292, 292])).within(large));
    assert!(!SectionCharge::of(&section_of(&[292, 293])).within(large));
}

/// **A bundle is charged `max(count, 1)`** (`SCS-P40`): a zero-draw bundle
/// is admissible and costs one, so it cannot be used to fill a section
/// for free. On the small network the budget is 2, so two zero-draw
/// bundles are admitted and a third is over budget — and so are 500 of
/// them, one for every block of `W₂`. A section inside the window holds
/// at most `W₂` references. The large network's budget of 584 is
/// [`section_budget`]'s figure; a section of 584 zero-draw bundles does
/// not fit the window, and both section checks refuse it at CEN-J31
/// before any `D` is read (`SCS-P41`). The charge of 584 is arithmetic.
/// A mixed section pays for both kinds, against the budget
/// [`check_section`] derives — every such budget is even.
///
/// **Red edit: sum `count` instead of the charge** (`r.count()` for
/// `r.charge()` in `SectionCharge::of`). Every zero-draw section below
/// then charges nothing: the one- and two-bundle sections are admitted
/// with a zero charge, and the 500-bundle section fits budget 2.
#[test]
fn a_zero_draw_bundle_costs_one_and_a_section_of_them_is_bounded() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let c = BUNDLE_SECTION_BUDGET_MULTIPLE;
    let rules = rules_of(seb.get());
    let zeros = |n: usize| section_of(&vec![0u32; n]);
    let over = |refs: &[BundleRef], budget: u64| {
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge: SectionCharge::of(refs),
            budget,
        }))
    };
    let admit = |refs: &[BundleRef], view: &FixtureBundleView| {
        assert_eq!(
            judged(refs, view, &rules),
            Ok(SectionStanding::Admitted(SectionCharge::of(refs)))
        );
    };

    // The small network: budget 2. Five hundred zero-draw bundles are
    // inside `W₂` and over that budget.
    let small = section_budget(c, 8, seb);
    assert_eq!(small, 2);
    let view = view_holding(&[(0, 8)]);
    admit(&zeros(1), &view);
    admit(&zeros(2), &view);
    assert_eq!(judged(&zeros(3), &view, &rules), over(&zeros(3), small));
    assert_eq!(SectionCharge::of(&zeros(3)).get(), 3);
    assert_eq!(SectionCharge::of(&zeros(500)).get(), 500);
    assert_eq!(judged(&zeros(500), &view, &rules), over(&zeros(500), small));

    // 584 is the large network's budget, and it is not an admission: 501
    // and 584 references put the oldest outside `W₂`.
    let large = section_budget(c, 324_000, seb);
    assert_eq!(large, 584);
    let priced = SectionCharge::of(&zeros(584));
    assert_eq!(priced.get(), 584);
    assert!(priced.within(large));
    assert!(!SectionCharge::of(&zeros(585)).within(large));
    let outside = SectionRefused::OutsideWindow { position: 0 };
    for n in [501usize, 584] {
        view.take_reads();
        let refs = zeros(n);
        assert_eq!(
            judged(&refs, &view, &rules),
            Err(SectionCheckFailed::Refused(outside)),
            "{n} zero-draw bundles"
        );
        assert!(
            view.take_reads().is_empty(),
            "{n}: refused before any D is read"
        );
        assert_eq!(awaiting(&refs), Err(outside), "{n} at arrival");
    }
    // Five hundred fit the window, so arrival keeps the charge and does
    // not apply a budget.
    assert_eq!(awaiting(&zeros(500)).map(|s| s.charge().get()), Ok(500));

    // A zero-draw bundle beside a bundle with draws costs its one. Charge
    // 3 is over budget 2. It is not compared with an odd cap.
    let mixed = section_of(&[0, 1, 0]);
    assert_eq!(SectionCharge::of(&mixed).get(), 3);
    assert_eq!(judged(&mixed, &view, &rules), over(&mixed, small));
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
        check_section_until_switch(&[], &root_of(&[]), h_incl_of(&[]), &RuleSet::GENESIS),
        Ok(SectionStanding::Admitted(SectionCharge::of(&[])))
    );
}

/// The section's checks in §9.1's order, each as [`check_section`]'s
/// result: order, then the root, then the window, then the budget. A
/// reference that is also outside the window is still refused for order.
/// Red edit: check the budget first, or the window before the order.
#[test]
fn of_two_section_defects_the_earlier_check_refuses() {
    let rules = rules_of(10_000);
    // `D` = 8, so the budget is 2. Two references of eight draws charge 16.
    let view = view_holding(&[(0, 8)]);
    let a = reference_at(100, 8);
    let b = reference_at(101, 8);
    let h_incl = BlockHeight::from_raw(102);
    let judge = |refs: &[BundleRef], root: &[u8; 32]| {
        view.take_reads();
        let outcome = check_section(refs, root, h_incl, &view, &rules);
        (outcome, view.take_reads())
    };

    // Out of order, a wrong root, and over budget at once. Order is first,
    // and it reads nothing.
    let swapped = [b.clone(), a.clone()];
    let (outcome, reads) = judge(&swapped, &[0; 32]);
    assert_eq!(
        outcome,
        Err(SectionCheckFailed::Refused(SectionRefused::OutOfOrder {
            position: 1
        }))
    );
    assert!(reads.is_empty());

    // The first reference is also outside the window (`h` 1000, included
    // at 102). Order still wins: a window-first check would refuse
    // position 0.
    let far = [reference_at(1000, 8), reference_at(100, 8)];
    let (outcome, reads) = judge(&far, &[0; 32]);
    assert_eq!(
        outcome,
        Err(SectionCheckFailed::Refused(SectionRefused::OutOfOrder {
            position: 1
        }))
    );
    assert!(reads.is_empty());

    // In order, a wrong root, and over budget. The root is next.
    let refs = [a, b];
    let (outcome, reads) = judge(&refs, &[0; 32]);
    assert_eq!(
        outcome,
        Err(SectionCheckFailed::Refused(SectionRefused::Root))
    );
    assert!(reads.is_empty());

    // In order, the right root: the budget is the check that reads `D`.
    assert_eq!(SectionCharge::of(&refs).get(), 16);
    let (outcome, reads) = judge(&refs, &root_of(&refs));
    assert_eq!(
        outcome,
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge: SectionCharge::of(&refs),
            budget: 2,
        }))
    );
    assert_eq!(reads, [BundleRead::DrawableEpoch]);
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

pub(in crate::archival::bundle) fn view_holding(epochs: &[(u64, u64)]) -> FixtureBundleView {
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
    let rules = rules_of(seb.get());
    let boundary = seb.get();
    let h_incl = BlockHeight::from_raw(boundary + 1);
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
        check_section(&spanning, &root_of(&spanning), h_incl, &both, &rules),
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
        check_section(&earlier, &root_of(&earlier), h_incl, &only_small, &rules),
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge: SectionCharge::of(&earlier),
            budget: small_cap,
        }))
    );

    // The later epoch missing is not the earlier epoch's cap. It waits.
    let later_unknown = view_holding(&[(0, 0)]);
    assert_eq!(
        check_section(
            &spanning,
            &root_of(&spanning),
            h_incl,
            &later_unknown,
            &rules
        ),
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
    let rules = rules_of(seb.get());
    let boundary = seb.get();
    let h_incl = BlockHeight::from_raw(boundary + 1);
    let spanning = [reference_at(boundary - 1, 2), reference_at(boundary, 2)];

    let mut faulting = view_holding(&[]);
    faulting.fault = Some(BundleRead::DrawableEpoch);
    faulting.take_reads();
    assert_eq!(
        check_section(&[], &root_of(&[]), h_incl, &faulting, &rules),
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
        check_section(&spanning, &root_of(&spanning), h_incl, &mismatched, &rules),
        Ok(SectionStanding::Awaiting(SectionCharge::of(&spanning)))
    );

    faulting.take_reads();
    assert_eq!(
        check_section(&spanning, &root_of(&spanning), h_incl, &faulting, &rules),
        Err(SectionCheckFailed::View(BundleReadFaulted(
            BundleRead::DrawableEpoch
        )))
    );

    let swapped = [spanning[1].clone(), spanning[0].clone()];
    faulting.take_reads();
    assert_eq!(
        check_section(&swapped, &root_of(&spanning), h_incl, &faulting, &rules),
        Err(SectionCheckFailed::Refused(SectionRefused::OutOfOrder {
            position: 1
        }))
    );
    assert!(faulting.take_reads().is_empty());
}

/// **Every reference is inside the window before the budget reads any `D`**
/// (`SCS-P41`). A reference outside it is refused at CEN-J31, at its
/// position, by both section checks. The case this closes: a section whose
/// own epochs are held and over budget, plus one reference to a block the
/// window does not reach, in an epoch nobody holds. Before, that one
/// reference turned the whole section to `Awaiting` and the budget was
/// never compared; now the section is refused for the reference.
///
/// Red edits: drop the window from the section's form — the
/// future-epoch section is then `Awaiting` and the stale one over budget;
/// check the window after the budget — the stale one is then refused at
/// CEN-J30, not J31; `<` for `≤` at `h + W₂` — the edge reference at
/// exactly `W₂` is refused.
#[test]
fn a_reference_outside_the_window_is_refused_before_the_budget() {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    let rules = rules_of(seb.get());
    let window = rules
        .settlement_schedule()
        .challenge_response_blocks()
        .expect("a 10,000-block epoch has a window")
        .get();
    assert_eq!(window, 500);
    let boundary = seb.get();
    let h_incl = BlockHeight::from_raw(boundary + 1);
    // Epoch 1 holds D = 0, so its budget is 2; these charge 4.
    let over = [reference_at(boundary - 1, 2), reference_at(boundary, 2)];
    let view = view_holding(&[(0, 0), (1, 0)]);
    assert_eq!(
        check_section(&over, &root_of(&over), h_incl, &view, &rules),
        Err(SectionCheckFailed::Refused(SectionRefused::OverBudget {
            charge: SectionCharge::of(&over),
            budget: 2,
        }))
    );

    // The same section and one reference to a block above the including
    // one, in an epoch the view does not hold.
    let future = [
        over[0].clone(),
        over[1].clone(),
        reference_at(boundary + seb.get(), 0),
    ];
    let refused = Err(SectionRefused::OutsideWindow { position: 2 });
    view.take_reads();
    assert_eq!(
        check_section(&future, &root_of(&future), h_incl, &view, &rules),
        refused.map_err(SectionCheckFailed::Refused)
    );
    assert!(view.take_reads().is_empty(), "refused before any D is read");
    assert_eq!(
        check_section_until_switch(&future, &root_of(&future), h_incl, &rules),
        refused
    );

    // A reference older than the window, ahead of an over-budget pair: the
    // window refuses it, at its position, before the budget.
    let stale = [
        reference_at(boundary - window - 1, 1),
        reference_at(boundary - window, 9),
    ];
    let at_edge = BlockHeight::from_raw(boundary);
    assert_eq!(
        check_section(&stale, &root_of(&stale), at_edge, &view, &rules),
        Err(SectionCheckFailed::Refused(SectionRefused::OutsideWindow {
            position: 0
        }))
    );
    // A reference exactly `W₂` below is inside, and the section reaches
    // the budget.
    let edge = [reference_at(boundary - window, 1)];
    assert_eq!(
        check_section(&edge, &root_of(&edge), at_edge, &view, &rules).map(SectionStanding::charge),
        Ok(SectionCharge::of(&edge))
    );
    // The including block itself is not inside its own window.
    let itself = [reference_at(boundary, 1)];
    assert_eq!(
        check_section_until_switch(&itself, &root_of(&itself), at_edge, &rules),
        Err(SectionRefused::OutsideWindow { position: 0 })
    );
}

/// A rule set whose epoch has no response window refuses every reference,
/// as [`verify_bundle`] refuses every bundle under it (§9.1 step 3). An
/// empty section names no block and is admitted. Red edit: treat a missing
/// window as unbounded.
#[test]
fn no_window_admits_no_reference() {
    let rules = rules_of(19);
    assert!(rules
        .settlement_schedule()
        .challenge_response_blocks()
        .is_none());
    let one = [reference_at(100, 1)];
    let h_incl = BlockHeight::from_raw(101);
    assert_eq!(
        check_section_until_switch(&one, &root_of(&one), h_incl, &rules),
        Err(SectionRefused::OutsideWindow { position: 0 })
    );
    assert_eq!(
        check_section_until_switch(&[], &root_of(&[]), h_incl, &rules),
        Ok(SectionStanding::Admitted(SectionCharge::of(&[])))
    );
}
