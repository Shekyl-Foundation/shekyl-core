// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Arm and poll cost against the number of owners.
//!
//! Sizes are powers of four through 2^18, so the curve is visible and no
//! operating point is baked in. The number this daemon actually holds is
//! `InboundCeiling`, recorded with the Pi 4 run, not a constant here.
//!
//! The engine is built once per sample. Criterion chooses how many times to
//! repeat the timed call from the measured duration, and that call is cheap,
//! so rebuilding inside each repeat would either hold many engines at once
//! or spend the run in setup.

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shekyl_timing_engine::{Engine, ManualClock, OwnerClass, OwnerId, Tick};

fn sizes() -> impl Iterator<Item = usize> {
    // 4^0 .. 4^9. 4^9 = 2^18.
    (0..=9).map(|power| 1usize << (power * 2))
}

fn armed(n: usize) -> (Engine<ManualClock>, Vec<OwnerId>) {
    let mut engine = Engine::new(ManualClock::new(Tick::new(0)));
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = engine.register(OwnerClass::Transport).unwrap();
        engine
            .arm(id, Tick::new(1_000_000 + u64::try_from(i).unwrap()))
            .unwrap();
        ids.push(id);
    }
    (engine, ids)
}

fn time_earlier_arms(n: usize, iters: u64) -> Duration {
    let (mut engine, ids) = armed(n);
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        engine.clear(ids[0]).unwrap();
        engine.arm(ids[0], Tick::new(u64::MAX / 2)).unwrap();
        let start = Instant::now();
        black_box(engine.arm(ids[0], Tick::new(1)).unwrap());
        total += start.elapsed();
    }
    total
}

fn time_one_due_poll(n: usize, iters: u64) -> Duration {
    let (mut engine, ids) = armed(n);
    engine.clock_mut().set(Tick::new(1_000_000));
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        engine.arm(ids[0], Tick::new(1_000_000)).unwrap();
        let start = Instant::now();
        black_box(engine.poll());
        total += start.elapsed();
    }
    total
}

fn bench_arm_and_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("wake_hints");
    // Ten is criterion's minimum. The sweep goes to 2^18 owners, and this
    // bench is meant to finish on a Pi 4.
    group.sample_size(10);
    for n in sizes() {
        group.bench_function(format!("arm_earlier/{n}"), |b| {
            b.iter_custom(|iters| time_earlier_arms(n, iters));
        });
        group.bench_function(format!("poll_one_due/{n}"), |b| {
            b.iter_custom(|iters| time_one_due_poll(n, iters));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_arm_and_poll);
criterion_main!(benches);
