// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`fill_section`]: the references a template puts in the next block's
//! section. Sibling of `bundle_section_tests`, which admits a section.
//! Every test names the edit that turns it red.

use shekyl_archival_retention::{section_budget, BundleRef};
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

/// How many ways one epoch's `D` is held. The sweep's views are the
/// square of this: one view per pair of answers.
const HELD_COUNT: usize = 3;

/// Unique heights one sample may carry. The oracle visits every subset,
/// and eight heights is 256 subsets.
const SAMPLE_HEIGHTS: usize = 8;

/// Heights every sample carries: the window's last block, the first block
/// outside it, the including block, and one block of each epoch. The rest
/// of [`SAMPLE_HEIGHTS`] is drawn inside the window.
const ANCHORED_HEIGHTS: usize = 5;

/// Admission is one [`check_section`] per sample, so the sweep is wide.
const ADMISSION_SAMPLES: usize = 2_000;

/// The oracle checks every subset, so its sweep is the shorter one that
/// still reaches both packing shapes.
const ORACLE_SAMPLES: usize = 600;

/// Fewer samples than this of a shape the sweep claims to reach, and the
/// generator missed that shape (rule 47).
const SHAPE_FLOOR: usize = 20;

/// SplitMix64. One seed, so a red run names the same case every time.
struct Sampler(u64);

const SWEEP_SEED: u64 = 0x5EC7_10F1;

impl Sampler {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `0..n`. `n` is the number of choices.
    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "a sample bound is at least one");
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> T {
        let n = u64::try_from(from.len()).expect("a short list");
        let index = usize::try_from(self.below(n)).expect("the index fits");
        from[index]
    }
}

/// What the view holds for one epoch of the window.
///
/// The three answers are the sweep's whole input. A new answer is a new
/// arm here and a new entry of [`Self::ALL`]; the view grid is the square
/// of that list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeldDraws {
    /// The greatest positive `D` the count cap still reads as one, so the
    /// section budget stays `c`.
    Floor,
    /// One pair per block of the epoch. The count cap reads its base and
    /// the section budget is `c` times one more than that base.
    OnePerBlock,
    /// The view holds no drawable epoch. A reference of it is passed over.
    Absent,
}

impl HeldDraws {
    const ALL: [Self; HELD_COUNT] = [Self::Floor, Self::OnePerBlock, Self::Absent];

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|held| *held == self)
            .expect("every held value is listed")
    }

    /// The `D` the view stores, or [`None`] when the epoch is not held.
    fn draws(self, seb: u64) -> Option<u64> {
        match self {
            Self::Floor => Some(floor_draws(seb)),
            Self::OnePerBlock => Some(seb),
            Self::Absent => None,
        }
    }
}

/// The window's two epochs, each with its own answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeldEpochs {
    /// The epoch below the boundary.
    earlier: HeldDraws,
    /// The epoch that opens on the boundary.
    later: HeldDraws,
}

impl HeldEpochs {
    fn index(self) -> usize {
        self.earlier.index() * HELD_COUNT + self.later.index()
    }

    /// The pair at `index` in the view grid. [`Self::index`] is the inverse.
    fn at(index: usize) -> Self {
        Self {
            earlier: HeldDraws::ALL[index / HELD_COUNT],
            later: HeldDraws::ALL[index % HELD_COUNT],
        }
    }

    fn any_absent(self) -> bool {
        self.earlier == HeldDraws::Absent || self.later == HeldDraws::Absent
    }

    /// Both epochs are held, and not at the same `D`.
    fn budgets_differ(self) -> bool {
        !self.any_absent() && self.earlier != self.later
    }
}

/// The greatest positive `D` whose count cap is still one.
///
/// `floor(multiple · D / SEB) == 0` exactly when `multiple · D < SEB`, so
/// the last such `D` is `(SEB − 1) / multiple`. One pair more raises the cap.
fn floor_draws(seb: u64) -> u64 {
    let multiple = shekyl_archival_retention::archival_params().count_cap_base_multiple();
    assert!(multiple > 0, "the count cap has a base");
    (seb - 1) / multiple
}

/// Charges around the two budgets the sweep's `D` values earn: zero (charged
/// as one), the floor budget and its neighbors, and the raised budget and
/// its neighbors. One is listed twice so a one-draw bundle stays common.
fn sweep_charges(floor_budget: u64, raised_budget: u64) -> Vec<u32> {
    [
        0,
        1,
        1,
        floor_budget.saturating_sub(1),
        floor_budget,
        floor_budget.saturating_add(1),
        raised_budget / 2,
        raised_budget.saturating_sub(2),
        raised_budget.saturating_sub(1),
        raised_budget,
        raised_budget.saturating_add(1),
    ]
    .into_iter()
    .map(|draws| u32::try_from(draws).expect("a section budget fits a reference count"))
    .collect()
}

/// One sample: which `D` each epoch holds, the including block, and a queue
/// in ascending height. The view is not here. Every sample borrows one of
/// the sweep's nine.
struct Sample {
    held: HeldEpochs,
    h_incl: u64,
    queued: Vec<BundleRef>,
}

/// The nine views, built once, and the samples that borrow them.
struct Sweep {
    rules: RuleSet,
    /// Epoch 1's first block. The window straddles it.
    boundary: u64,
    views: [FixtureBundleView; HELD_COUNT * HELD_COUNT],
    samples: Vec<Sample>,
}

impl Sweep {
    /// `count` samples on [`epoch`]'s schedule.
    ///
    /// Each queue carries the anchors ([`ANCHORED_HEIGHTS`]): the window's
    /// last block, the first block outside it, the including block, and one
    /// block of each epoch. The heights left under [`SAMPLE_HEIGHTS`] are
    /// drawn inside the window, and a second reference repeats the window's
    /// last block. Counts are [`sweep_charges`].
    fn generate(count: usize) -> Self {
        let (boundary, rules) = epoch();
        let schedule = rules.settlement_schedule();
        let window = schedule
            .challenge_response_blocks()
            .expect("the sweep epoch has a window")
            .get();
        assert!(window > 1, "the window has to hold both epochs");
        assert_eq!(schedule.blocks().get(), boundary);
        let params = shekyl_archival_retention::archival_params();
        let seb = schedule.blocks();
        let floor = floor_draws(boundary);
        let floor_budget = section_budget(params, floor, seb).get();
        let raised_budget = section_budget(params, boundary, seb).get();
        assert!(
            floor > 0 && floor_budget < raised_budget,
            "floor D {floor} budgets {floor_budget}; one pair per block budgets {raised_budget}"
        );
        let charges = sweep_charges(floor_budget, raised_budget);
        let views = std::array::from_fn(|index| {
            let held = HeldEpochs::at(index);
            assert_eq!(held.index(), index, "the view grid is its own index");
            view_for(held, boundary)
        });
        let mut gen = Sampler(SWEEP_SEED);
        let extra = u64::try_from(SAMPLE_HEIGHTS - ANCHORED_HEIGHTS).expect("the anchors fit");
        let samples = (0..count)
            .map(|_| sample(&mut gen, boundary, window, &charges, extra, &rules))
            .collect();
        Self {
            rules,
            boundary,
            views,
            samples,
        }
    }
}

/// Epoch below the boundary. Height `0` opens it.
const EARLIER_EPOCH: u64 = 0;
/// Epoch that opens on the boundary.
const LATER_EPOCH: u64 = 1;

/// The view that holds `held`, borrowing nothing: the drawable epochs are
/// built here, once per grid cell.
fn view_for(held: HeldEpochs, seb: u64) -> FixtureBundleView {
    let mut epochs = Vec::with_capacity(2);
    for (epoch, draws) in [(EARLIER_EPOCH, held.earlier), (LATER_EPOCH, held.later)] {
        if let Some(pairs) = draws.draws(seb) {
            epochs.push((epoch, pairs));
        }
    }
    view_holding(&epochs)
}

/// One queue. The anchors are checked against the window predicate, so a
/// window whose edge moved fails here rather than in a packed section.
fn sample(
    gen: &mut Sampler,
    boundary: u64,
    window: u64,
    charges: &[u32],
    extra: u64,
    rules: &RuleSet,
) -> Sample {
    // `h_incl` is in epoch 1, and the window still reaches epoch 0.
    let h_incl = boundary + 1 + gen.below(window - 1);
    let last_inside = h_incl
        .checked_sub(window)
        .expect("the including block is past the window");
    let first_outside = last_inside
        .checked_sub(1)
        .expect("the window is past genesis");
    let earlier_block = boundary
        .checked_sub(1)
        .expect("the boundary is past genesis");
    let anchors: [u64; ANCHORED_HEIGHTS] =
        [last_inside, first_outside, h_incl, earlier_block, boundary];
    assert!(
        in_window(last_inside, h_incl, rules),
        "distance W₂ is inside the window"
    );
    assert!(
        !in_window(first_outside, h_incl, rules),
        "distance W₂ + 1 is outside the window"
    );
    assert!(
        !in_window(h_incl, h_incl, rules),
        "the including block is outside the window"
    );
    assert!(
        in_window(earlier_block, h_incl, rules) && in_window(boundary, h_incl, rules),
        "the window holds a block of each epoch"
    );
    let mut queued: Vec<BundleRef> = anchors
        .into_iter()
        .map(|h| reference_at(h, gen.pick(charges)))
        .collect();
    let n_extra = gen.below(extra + 1);
    for _ in 0..n_extra {
        queued.push(reference_at(
            last_inside + gen.below(window),
            gen.pick(charges),
        ));
    }
    // The walk keeps the first reference at a height. This second one is
    // the repeat every sample has.
    queued.push(reference_at(last_inside, gen.pick(charges)));
    queued.sort_by_key(BundleRef::h);
    Sample {
        held: HeldEpochs {
            earlier: gen.pick(&HeldDraws::ALL),
            later: gen.pick(&HeldDraws::ALL),
        },
        h_incl,
        queued,
    }
}

/// `h` inside the window of `h_incl`, by the predicate the fill uses.
fn in_window(h: u64, h_incl: u64, rules: &RuleSet) -> bool {
    super::bundle_section::inside_window(
        BlockHeight::from_raw(h),
        BlockHeight::from_raw(h_incl),
        rules.settlement_schedule(),
    )
}

/// A height the queue lists twice. The queue is ascending.
fn repeats_height(queued: &[BundleRef]) -> bool {
    queued.windows(2).any(|pair| pair[0].h() == pair[1].h())
}

/// A reference the window does not hold.
fn has_outside(queued: &[BundleRef], h_incl: u64, rules: &RuleSet) -> bool {
    queued
        .iter()
        .any(|reference| !in_window(reference.h().to_raw(), h_incl, rules))
}

/// The window itself holds a block below the boundary and a block at or
/// above it. References outside the window do not count.
fn crosses_boundary(queued: &[BundleRef], h_incl: u64, boundary: u64, rules: &RuleSet) -> bool {
    let mut earlier = false;
    let mut later = false;
    for reference in queued {
        if !in_window(reference.h().to_raw(), h_incl, rules) {
            continue;
        }
        if reference.h().to_raw() < boundary {
            earlier = true;
        } else {
            later = true;
        }
    }
    earlier && later
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

/// The first reference at each height, which is the queue the fill walks.
fn first_at_height(queued: &[BundleRef]) -> Vec<BundleRef> {
    let mut firsts = Vec::new();
    for reference in queued {
        if firsts
            .last()
            .is_none_or(|last: &BundleRef| last.h() < reference.h())
        {
            firsts.push(reference.clone());
        }
    }
    firsts
}

/// `candidate` keeps an earlier bundle than `incumbent`, or the same
/// prefix and then more. The empty section is the incumbent the search
/// starts from, and it is not older than itself.
fn older_than(candidate: &[BundleRef], incumbent: &[BundleRef]) -> bool {
    match candidate
        .iter()
        .zip(incumbent)
        .find(|(candidate, incumbent)| candidate.h() != incumbent.h())
    {
        Some((candidate, incumbent)) => candidate.h() < incumbent.h(),
        None => candidate.len() > incumbent.len(),
    }
}

/// Of every subset of `firsts` that [`check_section`] admits, the oldest.
fn oldest_admitted(
    firsts: &[BundleRef],
    h_incl: u64,
    view: &FixtureBundleView,
    rules: &RuleSet,
) -> Vec<BundleRef> {
    assert!(
        firsts.len() <= SAMPLE_HEIGHTS,
        "{} heights: the oracle enumerates every subset",
        firsts.len()
    );
    let bits = u32::try_from(firsts.len()).expect("the cap fits a mask");
    let mut best = Vec::new();
    for mask in 0..1u32 << bits {
        let subset: Vec<BundleRef> = firsts
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                let bit = u32::try_from(*index).expect("the index fits");
                mask & (1 << bit) != 0
            })
            .map(|(_, reference)| reference.clone())
            .collect();
        if older_than(&subset, &best) && admitted(&subset, h_incl, view, rules) {
            best = subset;
        }
    }
    best
}

/// Every fill over the sweep is a section [`check_section`] admits. Every
/// sample sits across the boundary, may leave a `D` unheld, repeats a
/// height, and carries a reference outside the window. Red edit: drop the
/// kept-earning-epoch guard in the two-epoch pack (an earlier bundle
/// spends the raised budget, the earning epoch is not kept, and the
/// section is over the budget its own epochs earn).
#[test]
fn every_filled_section_is_one_check_section_admits() {
    let sweep = Sweep::generate(ADMISSION_SAMPLES);
    let Sweep {
        rules,
        boundary,
        views,
        samples,
    } = &sweep;
    let mut nonempty = 0;
    let mut outside = 0;
    let mut repeated = 0;
    let mut crosses = 0;
    let mut unknown = 0;
    for (n, sample) in samples.iter().enumerate() {
        let view = &views[sample.held.index()];
        let section = filled(&sample.queued, sample.h_incl, view, rules);
        nonempty += usize::from(!section.is_empty());
        outside += usize::from(has_outside(&sample.queued, sample.h_incl, rules));
        repeated += usize::from(repeats_height(&sample.queued));
        crosses += usize::from(crosses_boundary(
            &sample.queued,
            sample.h_incl,
            *boundary,
            rules,
        ));
        unknown += usize::from(sample.held.any_absent());
        assert!(
            admitted(&section, sample.h_incl, view, rules),
            "case {n}: D {:?}, h_incl {}, queued {:?} filled {:?}",
            sample.held,
            sample.h_incl,
            sample
                .queued
                .iter()
                .map(|reference| (reference.h().to_raw(), reference.count()))
                .collect::<Vec<_>>(),
            heights(&section)
        );
    }
    let count = samples.len();
    assert_eq!(
        (outside, repeated, crosses),
        (count, count, count),
        "every sample is outside, repeated, and across the boundary"
    );
    assert!(
        unknown > count / HELD_COUNT,
        "the sweep holds epochs the view does not ({unknown})"
    );
    assert!(
        nonempty * 2 > count,
        "most samples fill something ({nonempty})"
    );
}

/// The fill is the oldest section [`check_section`] admits: the first
/// differing height is the smaller one, or the same prefix and then more.
/// The candidates are the first reference at each height. The sweep counts
/// its hard cases (rule 47): sections that keep both epochs under different
/// `D`, and queues where a reference that fits on its own is left out.
/// Red edit: drop the crowding reservation in the two-epoch pack (an
/// earlier bundle spends the raised budget, the earning epoch is crowded
/// out, the pack is discarded, and the fill falls back to a younger shape).
#[test]
fn the_fill_is_the_oldest_admissible_section() {
    let sweep = Sweep::generate(ORACLE_SAMPLES);
    let Sweep {
        rules,
        boundary,
        views,
        samples,
    } = &sweep;
    let mut spans_both = 0;
    let mut crowded = 0;
    for (n, sample) in samples.iter().enumerate() {
        let view = &views[sample.held.index()];
        let firsts = first_at_height(&sample.queued);
        let oracle = oldest_admitted(&firsts, sample.h_incl, view, rules);
        if sample.held.budgets_differ()
            && oracle
                .iter()
                .any(|reference| reference.h().to_raw() < *boundary)
            && oracle
                .iter()
                .any(|reference| reference.h().to_raw() >= *boundary)
        {
            spans_both += 1;
        }
        if firsts.iter().any(|reference| {
            admitted(std::slice::from_ref(reference), sample.h_incl, view, rules)
                && oracle.iter().all(|kept| kept.h() != reference.h())
        }) {
            crowded += 1;
        }
        let section = filled(&sample.queued, sample.h_incl, view, rules);
        assert_eq!(
            heights(&section),
            heights(&oracle),
            "case {n}: D {:?}, h_incl {}, queued {:?}",
            sample.held,
            sample.h_incl,
            firsts
                .iter()
                .map(|reference| (reference.h().to_raw(), reference.count()))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        spans_both > SHAPE_FLOOR && crowded > SHAPE_FLOOR,
        "the sweep reaches the two-epoch shapes ({spans_both}) and crowding ({crowded})"
    );
}
