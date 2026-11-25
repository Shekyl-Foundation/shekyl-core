// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two input classes and how each contrast builds them.
//!
//! Two rules, each learnt on 2026-10-24 from a false class difference on
//! operations BINSEC had proved branchless, shape everything here:
//!
//! - Every input of a timed batch exists before that batch's clock starts.
//!   Building one class in the gap after the previous timed batch hands the
//!   two classes different cache and predictor state.
//! - No value repeats inside a timed batch where a contrast does not mean
//!   it to: a value repeated back-to-back runs measurably faster through
//!   the short `HelioseleneField` operations, whatever the value is. So a
//!   "fixed" class is a SET of `BATCH` distinct values, not one value.
//!
//! [`Retention`] applies the rules. A small operand keeps every batch
//! ([`Retention::Complete`]), which is how the recorded field runs were
//! measured. A large operand uses a windowed schedule ([`Retention::Windowed`]):
//! the window is built, then timed, and its slots are reused. An independent
//! buffer is read between input construction and timing to reduce cache
//! residency from construction. Cache residency remains platform-dependent.

use core::hint::black_box;

use crate::rng::{Rng, Seed};

/// Operations per timed sample.
pub const BATCH: usize = 32;

/// Largest operand [`Retention::Complete`] retains.
///
/// A field element is 32 bytes and a product pair is 64, which is what the
/// recorded field runs held in full. The ML-KEM ciphertext pair is 2,176
/// and sits above this.
pub const COMPLETE_OPERAND_MAX: usize = 256;

/// Target size for one window's operands and for the separate cache pad.
/// The pad applies the same cache pressure before each window. Its size
/// does not establish the measured operands' cache residency.
pub const WINDOW_BYTES: usize = 64 * 1024 * 1024;

/// Read one byte per 64-byte stride when touching the cache pad.
const CACHE_STRIDE: usize = 64;

/// How a row's batches are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Every batch exists before the first clock read.
    Complete,
    /// A window exists before its clock reads. The slots are then reused.
    Windowed,
}

impl Retention {
    /// `operand_bytes` is `size_of` of one timed input.
    pub const fn for_operand(operand_bytes: usize) -> Self {
        if operand_bytes <= COMPLETE_OPERAND_MAX {
            Retention::Complete
        } else {
            Retention::Windowed
        }
    }
}

/// Whether a visited batch is a sample.
///
/// A warmup batch is timed so the next recorded batch is preceded by the
/// timing loop. It is not a sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchRole {
    Record,
    Warmup,
}

/// dudect's two classes. "Fixed" is the class a contrast varies (a fixed
/// set, a constant, a shape); "Random" is the reference it is compared to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Fixed,
    Random,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Fixed => "fixed",
            Class::Random => "random",
        }
    }
}

/// What the two classes of a row are.
pub enum Contrast<I> {
    /// dudect's test: a fixed set of `BATCH` distinct values, rebuilt for
    /// every fixed batch, against fresh values.
    FixedSet,
    /// The equal-familiarity companion of `FixedSet`: two different fixed
    /// sets, so both classes are equally familiar to the CPU and only the
    /// operands can separate them. A row that differs fixed-against-fresh
    /// but not here is familiarity, not operand dependence.
    FixedPair,
    /// Both classes fresh: the null control, which must show no difference
    /// or the threshold means nothing on this device.
    Null,
    /// One value repeated through every fixed batch, against fresh values.
    /// The positive controls need an extreme value here: a fixed SET of
    /// random loop lengths has the same mean as fresh ones and shows
    /// nothing.
    Constant(I),
    /// Fresh values from a structured distribution (an operand shape)
    /// against fresh values from the row's own.
    Shaped(Box<dyn Fn(&mut Rng) -> I>),
}

/// Where one class's batches come from, resolved for one run.
enum Source<'a, I> {
    /// Fresh draws from the row's distribution, per element.
    Fresh(&'a dyn Fn(&mut Rng) -> I),
    /// `BATCH` draws from the row's distribution under a seed fixed for the
    /// run: the same values every batch, rebuilt through the same path and
    /// a fresh allocation like a fresh batch, so the classes differ in
    /// their values only, not in how their memory was built.
    FixedSet {
        draw: &'a dyn Fn(&mut Rng) -> I,
        seed: Seed,
    },
    /// One value, repeated.
    Repeated(&'a I),
}

impl<I: Clone> Source<'_, I> {
    /// The batch the complete schedule stores. One allocation of [`BATCH`]
    /// elements, the same draws [`Self::write_batch`] performs.
    fn batch(&self, rng: &mut Rng) -> Vec<I> {
        let mut into = Vec::with_capacity(BATCH);
        self.write_batch(&mut into, rng);
        into
    }

    /// Refill `into` for a reused window slot.
    fn write_batch(&self, into: &mut Vec<I>, rng: &mut Rng) {
        into.clear();
        into.reserve(BATCH);
        match self {
            Source::Fresh(draw) => {
                for _ in 0..BATCH {
                    into.push(draw(rng));
                }
            }
            Source::FixedSet { draw, seed } => {
                let mut replay = Rng::from_seed(*seed);
                for _ in 0..BATCH {
                    into.push(draw(&mut replay));
                }
            }
            Source::Repeated(value) => {
                into.extend(std::iter::repeat_with(|| (*value).clone()).take(BATCH));
            }
        }
    }
}

/// The two sources of one contrast, in class order.
struct ClassSources<'a, I> {
    fixed: Source<'a, I>,
    random: Source<'a, I>,
}

impl<'a, I> ClassSources<'a, I> {
    fn bind(contrast: &'a Contrast<I>, draw: &'a dyn Fn(&mut Rng) -> I, rng: &mut Rng) -> Self {
        let first_set = rng.seed();
        let second_set = rng.seed();
        let (fixed, random) = match contrast {
            Contrast::FixedSet => (
                Source::FixedSet {
                    draw,
                    seed: first_set,
                },
                Source::Fresh(draw),
            ),
            Contrast::FixedPair => (
                Source::FixedSet {
                    draw,
                    seed: first_set,
                },
                Source::FixedSet {
                    draw,
                    seed: second_set,
                },
            ),
            Contrast::Null => (Source::Fresh(draw), Source::Fresh(draw)),
            Contrast::Constant(value) => (Source::Repeated(value), Source::Fresh(draw)),
            Contrast::Shaped(shaped) => (Source::Fresh(shaped.as_ref()), Source::Fresh(draw)),
        };
        ClassSources { fixed, random }
    }

    fn source(&self, class: Class) -> &Source<'a, I> {
        match class {
            Class::Fixed => &self.fixed,
            Class::Random => &self.random,
        }
    }
}

/// Every batch of a row, in the random order they are timed in.
pub struct Schedule<I> {
    pub batches: Vec<(Class, Vec<I>)>,
}

impl<I: Clone> Schedule<I> {
    /// `samples_per_class` batches of each class, interleaved at random,
    /// every input built now.
    pub fn build(
        contrast: &Contrast<I>,
        draw: &dyn Fn(&mut Rng) -> I,
        samples_per_class: usize,
        rng: &mut Rng,
    ) -> Self {
        let sources = ClassSources::bind(contrast, draw, rng);
        let batches = shuffled_classes(samples_per_class, rng)
            .into_iter()
            .map(|class| (class, sources.source(class).batch(rng)))
            .collect();
        Schedule { batches }
    }
}

/// The same shuffled class order for complete and windowed schedules.
fn shuffled_classes(samples_per_class: usize, rng: &mut Rng) -> Vec<Class> {
    let mut order: Vec<Class> = std::iter::repeat_n(Class::Fixed, samples_per_class)
        .chain(std::iter::repeat_n(Class::Random, samples_per_class))
        .collect();
    rng.shuffle(&mut order);
    order
}

/// Visit every batch of one row.
///
/// A small operand is built before the first `visit` call. A large operand
/// is built one window at a time: the first window before the first call,
/// and each later window between calls. A one-class profile's wall-clock
/// span therefore includes those later rebuilds. The t-statistic path does
/// not print that span.
pub fn visit_batches<I: Clone>(
    contrast: &Contrast<I>,
    draw: &dyn Fn(&mut Rng) -> I,
    samples_per_class: usize,
    rng: &mut Rng,
    visit: impl FnMut(Class, &[I], BatchRole),
) {
    visit_batches_with(
        contrast,
        draw,
        samples_per_class,
        rng,
        Retention::for_operand(size_of::<I>()),
        WINDOW_BYTES,
        visit,
    );
}

fn visit_batches_with<I: Clone>(
    contrast: &Contrast<I>,
    draw: &dyn Fn(&mut Rng) -> I,
    samples_per_class: usize,
    rng: &mut Rng,
    retention: Retention,
    window_bytes: usize,
    mut visit: impl FnMut(Class, &[I], BatchRole),
) {
    match retention {
        Retention::Complete => {
            let schedule = Schedule::build(contrast, draw, samples_per_class, rng);
            for (class, batch) in &schedule.batches {
                visit(*class, batch, BatchRole::Record);
            }
        }
        Retention::Windowed => {
            visit_windows(
                contrast,
                draw,
                samples_per_class,
                rng,
                window_bytes,
                &mut visit,
            );
        }
    }
}

/// At least one recorded batch, with anything smaller than a full batch
/// rounded up so the same path works for the final short window.
fn recorded_batches(operand_bytes: usize, window_bytes: usize) -> usize {
    window_bytes
        .div_ceil(BATCH.saturating_mul(operand_bytes).max(1))
        .max(1)
}

/// Read the independent pad after preparing a window. Keep the read
/// observable even when the harness is built with fat LTO.
#[inline(never)]
fn touch_cache_pad(pad: &[u8]) {
    let mut sum = 0u64;
    for &byte in black_box(pad).iter().step_by(CACHE_STRIDE) {
        sum = sum.wrapping_add(u64::from(byte));
    }
    black_box(sum);
}

fn visit_windows<I: Clone>(
    contrast: &Contrast<I>,
    draw: &dyn Fn(&mut Rng) -> I,
    samples_per_class: usize,
    rng: &mut Rng,
    window_bytes: usize,
    visit: &mut dyn FnMut(Class, &[I], BatchRole),
) {
    let sources = ClassSources::bind(contrast, draw, rng);
    let order = shuffled_classes(samples_per_class, rng);
    let limit = recorded_batches(size_of::<I>(), window_bytes).min(order.len());
    let pad = vec![1u8; window_bytes];
    let mut warmup = Vec::with_capacity(BATCH);
    let mut slots: Vec<Vec<I>> = (0..limit).map(|_| Vec::with_capacity(BATCH)).collect();
    for classes in order.chunks(limit.max(1)) {
        let warmup_class = [Class::Fixed, Class::Random][rng.below(2)];
        sources.source(warmup_class).write_batch(&mut warmup, rng);
        for (&class, slot) in classes.iter().zip(&mut slots) {
            sources.source(class).write_batch(slot, rng);
        }
        touch_cache_pad(&pad);
        visit(warmup_class, &warmup, BatchRole::Warmup);
        for (&class, slot) in classes.iter().zip(&slots) {
            visit(class, slot, BatchRole::Record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operand::Sample;
    use helioselene::HelioseleneField;

    type F = HelioseleneField;

    fn schedule(contrast: Contrast<F>) -> Schedule<F> {
        Schedule::build(&contrast, &F::sample, 50, &mut Rng::from_os())
    }

    fn class_batches(s: &Schedule<F>, class: Class) -> Vec<&Vec<F>> {
        s.batches
            .iter()
            .filter(|(c, _)| *c == class)
            .map(|(_, b)| b)
            .collect()
    }

    fn distinct(batch: &[F]) -> bool {
        batch
            .iter()
            .enumerate()
            .all(|(i, a)| batch[i + 1..].iter().all(|b| a != b))
    }

    #[test]
    fn each_class_gets_its_share_of_batches() {
        let s = schedule(Contrast::Null);
        assert_eq!(class_batches(&s, Class::Fixed).len(), 50);
        assert_eq!(class_batches(&s, Class::Random).len(), 50);
        assert!(s.batches.iter().all(|(_, b)| b.len() == BATCH));
    }

    #[test]
    fn a_fixed_set_is_the_same_distinct_values_every_batch() {
        let s = schedule(Contrast::FixedSet);
        let fixed = class_batches(&s, Class::Fixed);
        assert!(fixed.windows(2).all(|w| w[0] == w[1]));
        assert!(distinct(fixed[0]));
        let random = class_batches(&s, Class::Random);
        assert_ne!(random[0], random[1]);
    }

    #[test]
    fn a_fixed_pair_is_two_different_fixed_sets() {
        let s = schedule(Contrast::FixedPair);
        let (fixed, other) = (
            class_batches(&s, Class::Fixed),
            class_batches(&s, Class::Random),
        );
        assert!(fixed.windows(2).all(|w| w[0] == w[1]));
        assert!(other.windows(2).all(|w| w[0] == w[1]));
        assert_ne!(fixed[0], other[0]);
    }

    #[test]
    fn a_constant_repeats_its_value() {
        let value = F::sample(&mut Rng::from_os());
        let s = schedule(Contrast::Constant(value));
        assert!(class_batches(&s, Class::Fixed)
            .iter()
            .all(|b| b.iter().all(|v| *v == value)));
    }

    #[test]
    fn the_classes_are_interleaved() {
        let s = schedule(Contrast::Null);
        let switches = s.batches.windows(2).filter(|w| w[0].0 != w[1].0).count();
        assert!(
            switches > 10,
            "classes not interleaved: {switches} switches"
        );
    }

    /// A field element is 32 bytes; the mul rows time a pair of them.
    const FIELD_PAIR_BYTES: usize = 64;

    #[test]
    fn operand_size_selects_retention() {
        assert_eq!(
            Retention::for_operand(FIELD_PAIR_BYTES),
            Retention::Complete
        );
        assert_eq!(
            Retention::for_operand(COMPLETE_OPERAND_MAX),
            Retention::Complete
        );
        assert_eq!(
            Retention::for_operand(COMPLETE_OPERAND_MAX + 1),
            Retention::Windowed
        );
    }

    #[test]
    fn a_window_records_enough_batches_to_match_the_pad() {
        // 100 bytes of pad, batches of 64: one batch is short of the pad.
        let recorded = recorded_batches(2, 100);
        assert_eq!(BATCH * 2, 64);
        assert_eq!(recorded, 2);
        assert!(recorded * BATCH * 2 >= 100);
    }

    #[test]
    fn a_window_records_at_least_one_batch() {
        assert_eq!(recorded_batches(32, 0), 1);
    }

    #[test]
    fn a_small_operand_is_built_before_any_batch_is_timed() {
        use std::cell::Cell;
        let draws = Cell::new(0usize);
        let draw = |rng: &mut Rng| {
            draws.set(draws.get() + 1);
            rng.byte()
        };
        let samples = 10;
        let mut visits = 0;
        let mut built = None;
        visit_batches(
            &Contrast::Null,
            &draw,
            samples,
            &mut Rng::from_os(),
            |_, batch, role| {
                assert_eq!(role, BatchRole::Record);
                assert_eq!(batch.len(), BATCH);
                if built.is_none() {
                    built = Some(draws.get());
                }
                assert_eq!(draws.get(), built.unwrap());
                visits += 1;
            },
        );
        assert_eq!(visits, samples * 2);
        assert_eq!(built.unwrap(), samples * 2 * BATCH);
    }

    #[test]
    fn a_window_is_built_before_its_batches_are_timed() {
        use std::cell::Cell;
        let draws = Cell::new(0usize);
        let draw = |rng: &mut Rng| {
            draws.set(draws.get() + 1);
            rng.next_u64()
        };
        let window_bytes = BATCH * size_of::<u64>();
        let mut at_visit = Vec::new();
        visit_batches_with(
            &Contrast::Null,
            &draw,
            4,
            &mut Rng::from_os(),
            Retention::Windowed,
            window_bytes,
            |class, batch, role| {
                assert_eq!(batch.len(), BATCH);
                at_visit.push((role, class, draws.get()));
            },
        );
        // Warmup and one recorded batch. The pad is bytes, not draws.
        let stage_draws = (1 + 1) * BATCH;
        let (role, _, built) = at_visit[0];
        assert_eq!(role, BatchRole::Warmup);
        assert_eq!(built, stage_draws);
        let (role, _, built) = at_visit[1];
        assert_eq!(role, BatchRole::Record);
        assert_eq!(built, stage_draws);
        let (role, _, built) = at_visit[2];
        assert_eq!(role, BatchRole::Warmup);
        assert_eq!(built, stage_draws * 2);
        let records: Vec<Class> = at_visit
            .iter()
            .filter(|(role, _, _)| *role == BatchRole::Record)
            .map(|(_, class, _)| *class)
            .collect();
        assert_eq!(records.iter().filter(|c| **c == Class::Fixed).count(), 4);
        assert_eq!(records.iter().filter(|c| **c == Class::Random).count(), 4);
    }
}
