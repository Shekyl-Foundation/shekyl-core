// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two input classes and how each contrast builds them.
//!
//! Two rules, each learnt on 2026-10-24 from a false class difference on
//! operations BINSEC had proved branchless, shape everything here:
//!
//! - Every input of every sample exists BEFORE the timing loop starts.
//!   Building the random class's inputs right before its batch hands the
//!   two classes different cache and predictor state.
//! - No value repeats inside a timed batch where a contrast does not mean
//!   it to: a value repeated back-to-back runs measurably faster through
//!   the short `HelioseleneField` operations, whatever the value is. So a
//!   "fixed" class is a SET of `BATCH` distinct values, not one value.

use crate::rng::{Rng, Seed};

/// Operations per timed sample.
pub const BATCH: usize = 32;

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
    fn batch(&self, rng: &mut Rng) -> Vec<I> {
        match self {
            Source::Fresh(draw) => (0..BATCH).map(|_| draw(rng)).collect(),
            Source::FixedSet { draw, seed } => {
                let mut replay = Rng::from_seed(*seed);
                (0..BATCH).map(|_| draw(&mut replay)).collect()
            }
            Source::Repeated(value) => vec![(*value).clone(); BATCH],
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
        let mut order: Vec<Class> = std::iter::repeat_n(Class::Fixed, samples_per_class)
            .chain(std::iter::repeat_n(Class::Random, samples_per_class))
            .collect();
        rng.shuffle(&mut order);
        let batches = order
            .into_iter()
            .map(|class| {
                let source = match class {
                    Class::Fixed => &fixed,
                    Class::Random => &random,
                };
                (class, source.batch(rng))
            })
            .collect();
        Schedule { batches }
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
}
