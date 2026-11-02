// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`fill_section`]: the references a template puts in the next block's
//! section. Sibling of `bundle_section_tests`, which admits a section.
//! Every test names the edit that turns it red.

use shekyl_archival_retention::BundleRef;
use shekyl_types::BlockHeight;

use super::bundle_section_tests::{reference_at, root_of, rules_of, section_of, view_holding};
use super::*;
use crate::harness::bundle::{BundleRead, BundleReadFaulted, FixtureBundleView};
use crate::rule_set::SettlementEpochBlocks;

/// The template's section over `queued`, included at `h_incl`.
fn filled(
    queued: &[BundleRef],
    h_incl: u64,
    view: &FixtureBundleView,
    rules: &RuleSet,
) -> Vec<BundleRef> {
    fill_section(queued, BlockHeight::from_raw(h_incl), view, rules).expect("the view answers")
}

/// The heights a section holds, in order.
fn heights(refs: &[BundleRef]) -> Vec<BlockHeight> {
    refs.iter().map(BundleRef::h).collect()
}

/// An epoch of 10,000 blocks: `W₂` is 500, and `D` of 0 or 8 budgets 2
/// while `D` of 10,000 budgets 20. The boundary is epoch 1's first block.
fn epoch() -> (u64, RuleSet) {
    let seb = SettlementEpochBlocks::new(10_000).expect("non-zero");
    (seb.get(), rules_of(seb.get()))
}

/// `counts` split across `boundary`: the first half below it, the rest at
/// and above it.
fn across_boundary(counts: &[u32], boundary: u64) -> Vec<BundleRef> {
    let mid = counts.len() / 2;
    counts
        .iter()
        .enumerate()
        .map(|(i, count)| {
            let i = u64::try_from(i).expect("a queue index");
            let mid = u64::try_from(mid).expect("a queue index");
            let h = if i < mid {
                boundary - (mid - i)
            } else {
                boundary + (i - mid)
            };
            reference_at(h, *count)
        })
        .collect()
}

/// What the template fills is a section the rule admits. The queues straddle
/// the epoch boundary, half below it and half at or above it. Red edit:
/// charge a reference its count rather than `max(count, 1)` — zero-draw
/// bundles then ride free, and the section of them is over the budget
/// `check_section` derives.
#[test]
fn a_filled_section_is_one_check_section_admits() {
    let (boundary, rules) = epoch();
    // Epoch 0 has `D` = 8 (budget 2), epoch 1 `D` = 10,000 (budget 20).
    let view = view_holding(&[(0, 8), (1, 10_000)]);
    let h_incl = boundary + 10;
    for counts in [
        vec![0u32, 0, 0],
        vec![1, 1, 1, 1],
        vec![2, 0, 9, 11, 3],
        vec![10, 10, 10],
        vec![20, 1],
        vec![5, 5, 5, 5, 5],
    ] {
        let queued = across_boundary(&counts, boundary);
        let queued_heights = heights(&queued);
        assert!(
            queued_heights.iter().any(|h| h.to_raw() < boundary)
                && queued_heights.iter().any(|h| h.to_raw() >= boundary),
            "counts {counts:?} stay in one epoch"
        );
        let section = filled(&queued, h_incl, &view, &rules);
        assert_eq!(
            check_section(
                &section,
                &root_of(&section),
                BlockHeight::from_raw(h_incl),
                &view,
                &rules
            ),
            Ok(SectionStanding::Admitted(SectionCharge::of(&section))),
            "counts {counts:?} filled {:?}",
            heights(&section)
        );
    }
}

/// Oldest first, and a reference that would pass the budget is passed
/// over while a later smaller one still fits. Budget 20: 15 is taken, 10
/// would make 25 and is passed over, 5 makes 20 and is taken. One epoch is
/// one read. Red edit: stop at the first reference that does not fit — the
/// 5 is then left out.
#[test]
fn a_filled_section_takes_the_oldest_first_and_fills_what_is_left() {
    let (_, rules) = epoch();
    let view = view_holding(&[(0, 10_000)]);
    let queued = section_of(&[15, 10, 5, 1]);
    view.take_reads();
    assert_eq!(
        heights(&filled(&queued, 104, &view, &rules)),
        [100, 102].map(BlockHeight::from_raw)
    );
    assert_eq!(view.take_reads(), [BundleRead::DrawableEpoch]);
    // Budget 2 (`D` = 8): the two oldest one-draw bundles, and nothing after.
    let small = view_holding(&[(0, 8)]);
    let ones = section_of(&[1, 1, 1]);
    assert_eq!(
        heights(&filled(&ones, 103, &small, &rules)),
        [100, 101].map(BlockHeight::from_raw)
    );
}

/// A reference outside the window of the including block is not taken:
/// one at or above `h_incl`, and one more than `W₂` below it. `W₂` is 500
/// on this epoch. Red edit: drop the window check — both are taken, and
/// the section is refused at CEN-J31.
#[test]
fn a_filled_section_holds_only_references_inside_the_window() {
    let (_, rules) = epoch();
    let view = view_holding(&[(0, 10_000)]);
    let queued = [
        reference_at(99, 1),
        reference_at(100, 1),
        reference_at(599, 1),
        reference_at(600, 1),
    ];
    // At 600: 99 is 501 below, outside; 100 is 500 below, inside; 600 is
    // the including block itself.
    assert_eq!(
        heights(&filled(&queued, 600, &view, &rules)),
        [100, 599].map(BlockHeight::from_raw)
    );
}

/// A reference whose epoch's `D` the view does not hold is passed over,
/// and so is one that does not strictly follow the last height the walk
/// has seen — a duplicate, a descent, or a lower height after one the
/// window or an unknown `D` already passed over. The section stays
/// strictly ascending. Red edits: take a reference of an unknown `D` —
/// the section then awaits; track the last height kept rather than the
/// last height seen — the lower height after a skipped one is taken.
#[test]
fn a_filled_section_passes_over_an_unknown_d_and_a_height_already_seen() {
    let (boundary, rules) = epoch();
    // Epoch 1's `D` is not held.
    let view = view_holding(&[(0, 10_000)]);
    let queued = [
        reference_at(boundary - 2, 1),
        reference_at(boundary - 2, 2),
        reference_at(boundary - 3, 1),
        reference_at(boundary - 1, 1),
        reference_at(boundary, 1),
    ];
    let section = filled(&queued, boundary + 1, &view, &rules);
    assert_eq!(
        heights(&section),
        [boundary - 2, boundary - 1].map(BlockHeight::from_raw)
    );
    assert_eq!(
        section[0].count(),
        1,
        "the first reference for an h is the one kept"
    );

    // 600 is the including block, outside the window. 500 is inside it
    // and lower, and is not taken after 600 was seen.
    assert!(filled(
        &[reference_at(600, 1), reference_at(500, 1)],
        600,
        &view,
        &rules
    )
    .is_empty());
    // Epoch 1's `D` is unknown. The lower height in epoch 0 comes after
    // it in the walk, so it is not taken either.
    assert!(filled(
        &[reference_at(boundary, 1), reference_at(boundary - 1, 1),],
        boundary + 1,
        &view,
        &rules
    )
    .is_empty());
}

/// A reference of a later epoch with a larger `D` raises the budget for
/// the whole section, so it is taken after the earlier epoch's budget was
/// already spent. Budget 2 below the boundary (`D` = 8), 20 above it.
/// Red edit: keep the first reference's `D` — the later bundle of five is
/// then left out of a block it fits.
#[test]
fn a_larger_d_epoch_in_the_section_raises_its_budget() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, 8), (1, 10_000)]);
    let queued = [
        reference_at(boundary - 2, 1),
        reference_at(boundary - 1, 1),
        reference_at(boundary, 5),
    ];
    assert_eq!(
        heights(&filled(&queued, boundary + 1, &view, &rules)),
        [boundary - 2, boundary - 1, boundary].map(BlockHeight::from_raw)
    );
}

/// The budget is the largest `D` of the epochs the section keeps. Charges
/// 2, 1 and 1 are the section `the_cap_is_the_largest_d_among_the_sections_epochs`
/// admits: the earlier epoch budgets 2, so the second reference fits only
/// once the later epoch (budget 20) is kept. Each epoch is read once.
/// Red edit: judge an earlier reference against the `D` already kept — the
/// charge-1 reference in the earlier epoch is left out.
#[test]
fn a_later_larger_d_keeps_the_earlier_bundles_that_fit_beside_it() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, 0), (1, boundary)]);
    let queued = [
        reference_at(boundary - 2, 2),
        reference_at(boundary - 1, 1),
        reference_at(boundary, 1),
    ];
    view.take_reads();
    assert_eq!(
        heights(&filled(&queued, boundary + 1, &view, &rules)),
        [boundary - 2, boundary - 1, boundary].map(BlockHeight::from_raw)
    );
    assert_eq!(
        view.take_reads(),
        [BundleRead::DrawableEpoch, BundleRead::DrawableEpoch]
    );
}

/// An earlier reference that fills the raised budget leaves no room for
/// the later epoch that earns it, so it is passed over. Budget 20 against
/// 2: the two charge-10 bundles would fill 20, and the later charge-1 is
/// what makes 20 the budget. The first charge-10 is kept with it; the
/// second is passed over. Red edit: take an earlier reference whenever it
/// fits the raised budget before the witness — the second charge-10 crowds
/// the witness out, and the section falls back to the later charge-1 alone.
#[test]
fn an_earlier_bundle_that_crowds_out_the_earning_epoch_is_passed_over() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, 0), (1, boundary)]);
    let queued = [
        reference_at(boundary - 2, 10),
        reference_at(boundary - 1, 10),
        reference_at(boundary, 1),
    ];
    assert_eq!(
        heights(&filled(&queued, boundary + 1, &view, &rules)),
        [boundary - 2, boundary].map(BlockHeight::from_raw)
    );
}

/// The oldest bundle that fits its own epoch's budget stays when the later
/// bundle does not fit beside it. Budget 2 against 20: charge 1 fits 2,
/// charge 20 fits 20, and 21 fits neither raised section. Red edit: spend
/// the raised budget on the later bundle — the charge-1, nearest the
/// window's end, is left out.
#[test]
fn the_oldest_fitting_bundle_is_not_spent_on_a_later_one() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, 0), (1, boundary)]);
    let queued = [reference_at(boundary - 1, 1), reference_at(boundary, 20)];
    assert_eq!(
        heights(&filled(&queued, boundary + 1, &view, &rules)),
        [boundary - 1].map(BlockHeight::from_raw)
    );
}

/// An earlier bundle that fits the raised budget only by excluding the
/// later epoch does not earn that budget. The later charge-1 earns budget
/// 20 on its own and is kept; the earlier charge-20 fits neither shape
/// beside it. Red edit: once the raised pack kept no later reference, pack
/// the earlier epoch alone and drop the later one — the charge-1 is left out.
#[test]
fn a_later_bundle_is_kept_when_the_earlier_one_only_fits_alone() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, 0), (1, boundary)]);
    let queued = [reference_at(boundary - 1, 20), reference_at(boundary, 1)];
    assert_eq!(
        heights(&filled(&queued, boundary + 1, &view, &rules)),
        [boundary].map(BlockHeight::from_raw)
    );
}

/// A larger later `D` raises nothing when no reference of that epoch fits
/// its budget. Budget 2 against 20: charge 21 does not fit 20, so the
/// earlier epoch packs under 2. Charge 3 is passed over and charge 1 is
/// kept. Red edit: pack under the later budget with no witness of it —
/// charge 3 is kept, and `check_section` refuses the section at CEN-J30.
#[test]
fn a_later_d_that_nothing_fits_does_not_raise_the_earlier_budget() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, 0), (1, boundary)]);
    let queued = [
        reference_at(boundary - 2, 3),
        reference_at(boundary - 1, 1),
        reference_at(boundary, 21),
    ];
    assert_eq!(
        heights(&filled(&queued, boundary + 1, &view, &rules)),
        [boundary - 1].map(BlockHeight::from_raw)
    );
}

/// A larger earlier `D` raises the later epoch's budget only when an
/// earlier reference is kept. Neither charge-21 fits budget 20, so the
/// later epoch packs under its own budget of 2: charge 5 is passed over
/// and charge 1 is kept. Red edit: keep the later bundles under the
/// earlier budget anyway — charge 5 is kept, and `check_section` refuses.
#[test]
fn an_earlier_d_that_is_not_kept_does_not_raise_the_later_budget() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, boundary), (1, 0)]);
    let queued = [
        reference_at(boundary - 2, 21),
        reference_at(boundary - 1, 21),
        reference_at(boundary, 5),
        reference_at(boundary + 1, 1),
    ];
    assert_eq!(
        heights(&filled(&queued, boundary + 2, &view, &rules)),
        [boundary + 1].map(BlockHeight::from_raw)
    );
}

/// Equal `D` is one budget over both epochs. Charge 1 is kept and charge
/// 20, which would make 21, is passed over; charge 21 does not fit, and
/// the later charge 1 still does. Red edit: treat the later epoch as
/// earning a higher cap, or require an earlier reference before using the
/// shared one — one of the two charge-1 bundles is then left out.
#[test]
fn an_equal_d_across_the_boundary_is_one_budget() {
    let (boundary, rules) = epoch();
    let view = view_holding(&[(0, boundary), (1, boundary)]);
    assert_eq!(
        heights(&filled(
            &[reference_at(boundary - 1, 1), reference_at(boundary, 20)],
            boundary + 1,
            &view,
            &rules
        )),
        [boundary - 1].map(BlockHeight::from_raw)
    );
    assert_eq!(
        heights(&filled(
            &[reference_at(boundary - 1, 21), reference_at(boundary, 1)],
            boundary + 1,
            &view,
            &rules
        )),
        [boundary].map(BlockHeight::from_raw)
    );
}

/// A drawable-epoch read that faults is the view's fault. An empty queue
/// and a queue outside the window do not read. The first reference inside
/// the window faults, and the reference after it is not a second read or a
/// partial section. Red edit: turn the fault into an empty section — the
/// in-window reference is then omitted with no error.
#[test]
fn a_faulting_drawable_read_is_not_a_section() {
    let (_, rules) = epoch();
    let mut view = view_holding(&[(0, 10_000)]);
    view.fault = Some(BundleRead::DrawableEpoch);
    let h_incl = BlockHeight::from_raw(600);
    view.take_reads();
    assert!(fill_section(&[], h_incl, &view, &rules)
        .expect("an empty queue asks nothing")
        .is_empty());
    assert!(view.take_reads().is_empty());
    // 99 is 501 below 600, outside; 600 is the including block.
    assert!(fill_section(
        &[reference_at(99, 1), reference_at(600, 1)],
        h_incl,
        &view,
        &rules
    )
    .expect("an out-of-window queue asks nothing")
    .is_empty());
    assert!(view.take_reads().is_empty());

    let queued = [
        reference_at(99, 1),
        reference_at(100, 1),
        reference_at(101, 1),
    ];
    assert_eq!(
        fill_section(&queued, h_incl, &view, &rules),
        Err(BundleReadFaulted(BundleRead::DrawableEpoch))
    );
    assert_eq!(view.take_reads(), [BundleRead::DrawableEpoch]);
}

/// A small deterministic generator (SplitMix64), so every run sweeps the
/// same queues and a red run names its case.
struct Cases(u64);

impl Cases {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> T {
        from[usize::try_from(self.below(from.len() as u64)).expect("a small index")]
    }
}

/// One generated case: the two epochs' `D` (or none the view holds), the
/// including block and a queue in ascending order of generation.
struct Case {
    view: FixtureBundleView,
    held: [Option<u64>; 2],
    h_incl: u64,
    queued: Vec<BundleRef>,
}

/// `count` cases on [`epoch`]'s schedule. Each queue holds up to eight
/// references around the epoch boundary: inside the window on both sides,
/// some outside it, some repeating a height; counts cluster around the two
/// budgets (2 and 20) so the three packing shapes all arise. Epoch 0's and
/// epoch 1's `D` are each 8 (budget 2), 10,000 (budget 20) or not held.
fn cases(count: usize) -> Vec<Case> {
    let (boundary, _) = epoch();
    let mut gen = Cases(0x5EC7_10F1);
    let charges = [0u32, 1, 1, 2, 3, 5, 9, 10, 11, 18, 19, 20, 21];
    let ds = [Some(8u64), Some(10_000), None];
    (0..count)
        .map(|_| {
            let held = [gen.pick(&ds), gen.pick(&ds)];
            let epochs: Vec<(u64, u64)> = held
                .iter()
                .enumerate()
                .filter_map(|(e, d)| d.map(|d| (e as u64, d)))
                .collect();
            let h_incl = boundary + gen.below(40);
            let n = 1 + gen.below(8);
            let mut heights: Vec<BlockHeight> = (0..n)
                .map(|_| {
                    // Mostly inside `(h_incl - 500, h_incl)`, now and then
                    // just outside it at either end.
                    BlockHeight::from_raw(match gen.below(10) {
                        0 => h_incl - 500 - gen.below(3),
                        1 => h_incl + gen.below(2),
                        _ => h_incl - 1 - gen.below(60),
                    })
                })
                .collect();
            heights.sort_unstable();
            let queued = heights
                .into_iter()
                .map(|h| reference_at(h.to_raw(), gen.pick(&charges)))
                .collect();
            Case {
                view: view_holding(&epochs),
                held,
                h_incl,
                queued,
            }
        })
        .collect()
}

/// Whether `section` is one [`check_section`] admits at `h_incl`.
fn admitted(section: &[BundleRef], h_incl: u64, view: &FixtureBundleView, rules: &RuleSet) -> bool {
    check_section(
        section,
        &root_of(section),
        BlockHeight::from_raw(h_incl),
        view,
        rules,
    ) == Ok(SectionStanding::Admitted(SectionCharge::of(section)))
}

/// Every fill over a sweep of queues is a section [`check_section`]
/// admits: across the boundary, with each `D` known or not, with
/// references outside the window and repeated heights. Red edit: drop the
/// crowding reservation in the two-epoch pack (an earlier bundle then
/// spends the raised budget before the epoch that earns it is kept, and
/// the section is over the budget it actually earns).
#[test]
fn every_filled_section_is_one_check_section_admits() {
    let (_, rules) = epoch();
    let cases = cases(2_000);
    let mut nonempty = 0;
    for (n, case) in cases.iter().enumerate() {
        let section = filled(&case.queued, case.h_incl, &case.view, &rules);
        nonempty += usize::from(!section.is_empty());
        assert!(
            admitted(&section, case.h_incl, &case.view, &rules),
            "case {n}: D {:?}, h_incl {}, queued {:?} filled {:?}",
            case.held,
            case.h_incl,
            case.queued
                .iter()
                .map(|r| (r.h().to_raw(), r.count()))
                .collect::<Vec<_>>(),
            heights(&section)
        );
    }
    assert!(
        nonempty > 1_000,
        "the subject exists: most cases fill something ({nonempty})"
    );
}

/// The fill is exactly the oldest admissible section: of every subset of
/// the queue [`check_section`] admits, the one that keeps the earliest
/// reference it can, then the next, and so on (the lexicographically
/// greatest inclusion vector in walk order), over the first reference at
/// each height, which is what the fill walks. Brute force over every subset
/// of queues of up to eight. The sweep must reach the packing's hard
/// cases, so it counts them: sections that keep both epochs under
/// different `D`, and queues where a reference that fits on its own is
/// left out of the oldest section (rule 47). Red edit: drop the crowding
/// reservation in the two-epoch pack (an earlier bundle then spends the
/// raised budget, the earning epoch is crowded out, and the fill falls back
/// to a younger shape than the oracle's).
#[test]
fn the_fill_is_the_oldest_admissible_section() {
    let (boundary, rules) = epoch();
    let cases = cases(600);
    let mut spans_both = 0;
    let mut crowded = 0;
    for (n, case) in cases.iter().enumerate() {
        // The fill walks the queue in ascending order and passes over a
        // height it has already seen; the candidates are the first
        // reference at each height.
        let mut q: Vec<BundleRef> = Vec::new();
        for reference in &case.queued {
            if q.last().is_none_or(|last| last.h() < reference.h()) {
                q.push(reference.clone());
            }
        }
        let size = q.len();
        let mut best: Option<Vec<bool>> = None;
        for mask in 0u32..(1 << size) {
            let keep: Vec<bool> = (0..size)
                .map(|i| mask & (1 << (size - 1 - i)) != 0)
                .collect();
            let subset: Vec<BundleRef> = q
                .iter()
                .zip(&keep)
                .filter(|(_, k)| **k)
                .map(|(r, _)| r.clone())
                .collect();
            if !admitted(&subset, case.h_incl, &case.view, &rules) {
                continue;
            }
            if best.as_ref().is_none_or(|b| keep > *b) {
                best = Some(keep);
            }
        }
        let oracle: Vec<BundleRef> = q
            .iter()
            .zip(best.as_ref().expect("the empty section is admitted"))
            .filter(|(_, k)| **k)
            .map(|(r, _)| r.clone())
            .collect();
        if case.held[0].is_some()
            && case.held[1].is_some()
            && case.held[0] != case.held[1]
            && oracle.iter().any(|r| r.h().to_raw() < boundary)
            && oracle.iter().any(|r| r.h().to_raw() >= boundary)
        {
            spans_both += 1;
        }
        if q.iter().any(|r| {
            admitted(std::slice::from_ref(r), case.h_incl, &case.view, &rules)
                && oracle.iter().all(|kept| kept.h() != r.h())
        }) {
            crowded += 1;
        }
        let section = filled(&case.queued, case.h_incl, &case.view, &rules);
        assert_eq!(
            heights(&section),
            heights(&oracle),
            "case {n}: D {:?}, h_incl {}, queued {:?}",
            case.held,
            case.h_incl,
            q.iter()
                .map(|r| (r.h().to_raw(), r.count()))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        spans_both > 20 && crowded > 20,
        "the sweep reaches the two-epoch shapes ({spans_both}) and crowding ({crowded})"
    );
}
