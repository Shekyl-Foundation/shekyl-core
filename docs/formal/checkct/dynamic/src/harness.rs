// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Times one row: builds its schedule, runs the timed loop, reports.
//!
//! The timed loop is part of the experiment, not plumbing: what the timer
//! sees depends on how consecutive operations overlap in the pipeline
//! (CA-2), so its shape is fixed. The operation is a statically dispatched
//! closure the loop is monomorphised over, each input passes through
//! `black_box` and each result into a wrapping sum that reaches
//! `black_box` after the loop, and nothing else runs between the two clock
//! reads.

use core::hint::black_box;
use std::time::{Instant, SystemTime};

use crate::classes::{Class, Contrast, Schedule, BATCH};
use crate::cli::{ClassSelection, Config};
use crate::rng::Rng;
use crate::stats::{Comparison, DUDECT_T_THRESHOLD, TAIL_CROP_PERCENT};

/// Row names are padded to this width so the columns line up; a longer
/// name pushes its line out rather than being cut.
const NAME_WIDTH: usize = 34;

/// What the row list is run against. The row list (`suite::run`) only
/// declares rows; a `Bench` decides what declaring one does: the
/// [`Harness`] times it, a test catalogue records its name.
pub trait Bench {
    /// Opens a section of related rows.
    fn section(&mut self, heading: &str);

    /// The row `name`: `op` on operands from `draw` (the row's own
    /// distribution, which the random class and the fixed sets draw from),
    /// with `contrast` saying what the other class is.
    fn row<I: Clone, O: FnMut(&I) -> u64>(
        &mut self,
        name: &str,
        contrast: Contrast<I>,
        draw: impl Fn(&mut Rng) -> I,
        op: O,
    );
}

/// The bench that times rows.
pub struct Harness {
    config: Config,
}

impl Harness {
    pub fn new(config: Config) -> Self {
        Harness { config }
    }

    pub fn print_header(&self) {
        println!(
            "ct-dynamic: {} samples/class x {BATCH} ops; dudect threshold |t| > {DUDECT_T_THRESHOLD}; target {}",
            self.config.samples.get(),
            std::env::consts::ARCH
        );
    }
}

impl Bench for Harness {
    fn section(&mut self, heading: &str) {
        println!("-- {heading}");
    }

    fn row<I: Clone, O: FnMut(&I) -> u64>(
        &mut self,
        name: &str,
        contrast: Contrast<I>,
        draw: impl Fn(&mut Rng) -> I,
        mut op: O,
    ) {
        let config = &self.config;
        if !config.filter.admits(name) {
            return;
        }
        let samples = config.samples.get();
        let schedule = Schedule::build(&contrast, &draw, samples, &mut Rng::from_os());
        let mut fixed = Vec::with_capacity(samples);
        let mut random = Vec::with_capacity(samples);
        let mut sink = 0u64;
        let window_start = SystemTime::now();
        for (class, batch) in &schedule.batches {
            if !config.classes.times(*class) {
                continue;
            }
            let start = Instant::now();
            for input in batch {
                sink = sink.wrapping_add(op(black_box(input)));
            }
            let ns = start.elapsed().as_nanos() as f64;
            match class {
                Class::Fixed => fixed.push(ns),
                Class::Random => random.push(ns),
            }
        }
        black_box(sink);
        let window = TimingWindow {
            start: window_start,
            end: SystemTime::now(),
        };
        report(name, config.classes, &fixed, &random, window);
    }
}

/// When a row's timed batches ran, on the wall clock: the span a profiler
/// sampling the same core (turbostat's `Time_Of_Day_Seconds`) is joined on.
/// Both ends lie outside the timed loop; the input generation before it is
/// excluded.
struct TimingWindow {
    start: SystemTime,
    end: SystemTime,
}

impl TimingWindow {
    fn unix_seconds(at: SystemTime) -> f64 {
        at.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(f64::NAN, |d| d.as_secs_f64())
    }
}

fn report(
    name: &str,
    classes: ClassSelection,
    fixed: &[f64],
    random: &[f64],
    window: TimingWindow,
) {
    if let ClassSelection::Only(class) = classes {
        println!(
            "{name:<NAME_WIDTH$} only one class run ({}); batches {}; timed {:.3}..{:.3} unix s",
            class.label(),
            fixed.len() + random.len(),
            TimingWindow::unix_seconds(window.start),
            TimingWindow::unix_seconds(window.end),
        );
        return;
    }
    let c = Comparison::of(fixed, random);
    println!(
        "{name:<NAME_WIDTH$} t={:>8.2}  t(crop {TAIL_CROP_PERCENT}%)={:>8.2}  mean ns {}/{} {:>9.0}/{:>9.0}  {}",
        c.t_full,
        c.t_cropped,
        Class::Fixed.label(),
        Class::Random.label(),
        c.mean_fixed,
        c.mean_random,
        c.verdict(),
    );
}
