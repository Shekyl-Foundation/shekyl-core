// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The process clock's source. That it leaves a sleep out is shown on a
//! real sleep (`TOR_SUPERVISOR.md` §10, `TSR-M8`); these show that it is
//! the source named and that an awake span keeps its length and its
//! resolution. On Windows they run in `tor-pin-verify`'s Windows entry.

use std::time::{Duration, Instant};

use super::{Clock, MonotonicClock};

/// The smallest step the clock is seen to take: readings until it moves.
fn smallest_step(clock: &MonotonicClock) -> u64 {
    let mut smallest = u64::MAX;
    for _ in 0..50 {
        let start = clock.now().get();
        let mut next = clock.now().get();
        while next == start {
            next = clock.now().get();
        }
        smallest = smallest.min(next - start);
    }
    smallest
}

/// **An awake span keeps its length, and a short one its resolution.**
/// Over a 200 ms wait the clock moves what `Instant` moves, within 5 ms,
/// and it steps by less than 100 µs. Fails if the source is the unbiased
/// interrupt time's plain call, which moves only at each clock tick (0.5
/// to 15.6 ms), or a source in other units.
#[test]
fn an_awake_span_keeps_its_length_and_resolution() {
    let clock = MonotonicClock::new();
    let step = smallest_step(&clock);
    assert!(
        step < 100_000,
        "the clock steps by {step} ns: too coarse for a short timing"
    );
    let begun = Instant::now();
    let from = clock.now().get();
    std::thread::sleep(Duration::from_millis(200));
    let moved = clock.now().get() - from;
    let real = u64::try_from(begun.elapsed().as_nanos()).unwrap_or(u64::MAX);
    assert!(
        moved.abs_diff(real) < 5_000_000,
        "the clock moved {moved} ns while 200 ms passed awake ({real} ns)"
    );
}

/// **On Windows the origin is an unbiased reading.** The test reads the
/// units that reading stored. An origin of `Instant` has none, so this
/// does not compile against that source.
///
/// The 100 ms comparison is the awake rate and the scale, not a suspend.
/// This thread sleeping does not suspend the machine, so `Instant` and
/// the unbiased counter advance together and the comparison alone would
/// still pass if the clock read `Instant`. It fails if the clock stops
/// tracking that counter, or drops the conversion from its 100 ns units.
/// A suspend staying out of the clock is a real sleep (`TSR-M8`).
#[cfg(windows)]
#[test]
fn on_windows_the_origin_is_an_unbiased_reading() {
    let clock = MonotonicClock::new();
    let origin = clock.origin.units();
    let counted = super::source::unbiased_interrupt_time();
    assert!(
        origin <= counted,
        "the origin {origin} is ahead of the unbiased counter {counted}"
    );
    let from = clock.now().get();
    std::thread::sleep(Duration::from_millis(100));
    let moved = clock.now().get() - from;
    let count = super::source::unbiased_interrupt_time()
        .saturating_sub(counted)
        .saturating_mul(100);
    assert!(
        moved.abs_diff(count) < 1_000_000,
        "the clock moved {moved} ns and the unbiased count {count} ns"
    );
}
