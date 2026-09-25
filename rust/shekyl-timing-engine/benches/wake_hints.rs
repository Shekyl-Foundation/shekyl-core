// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Arm and poll cost against the number of owners.
//!
//! The top of the range is the usual descriptor soft limit times the
//! deadlines one connection holds: idle, gap, and timed sync. The inbound
//! ceiling is headroom under that soft limit, so it cannot exceed it.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use shekyl_timing_engine::{Engine, ManualClock, OwnerClass, Tick};

const DEADLINES_PER_CONNECTION: usize = 3;
const DESCRIPTOR_SOFT_LIMIT: usize = 1024;

fn sizes() -> [usize; 5] {
    [
        1,
        16,
        256,
        DESCRIPTOR_SOFT_LIMIT,
        DESCRIPTOR_SOFT_LIMIT * DEADLINES_PER_CONNECTION,
    ]
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
