// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Arm and poll cost against the number of owners.
//!
//! Sizes are powers of four through 2^18, so the curve is visible and no
//! operating point is baked in. The number this daemon actually holds is
//! `InboundCeiling`, recorded with the Pi 4 run, not a constant here.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use shekyl_timing_engine::{Engine, ManualClock, OwnerClass, Tick};

fn sizes() -> impl Iterator<Item = usize> {
    // 4^0 .. 4^9. 4^9 = 2^18.
    (0..=9).map(|power| 1usize << (power * 2))
}

fn armed(n: usize) -> (Engine<ManualClock>, Vec<shekyl_timing_engine::OwnerId>) {
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

fn bench_arm_and_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("wake_hints");
    // Ten is criterion's minimum. The sweep goes to 2^18 owners, and this
    // bench is meant to finish on a Pi 4.
    group.sample_size(10);
    for n in sizes() {
        group.bench_function(format!("arm_earlier/{n}"), |b| {
            b.iter_batched(
                || armed(n),
                |(mut engine, ids)| {
                    black_box(engine.arm(ids[0], Tick::new(1)).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(format!("poll_one_due/{n}"), |b| {
            b.iter_batched(
                || {
                    let (mut engine, ids) = armed(n);
                    engine.clock_mut().set(Tick::new(1_000_000));
                    (engine, ids)
                },
                |(mut engine, ids)| {
                    black_box(engine.poll());
                    black_box(ids);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_arm_and_poll);
criterion_main!(benches);
