// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C5 — crypto cost of the transport handshake, of seal/open, and of one
//! rekey. The figures are an input to D9 and to D10.3. They are not a budget.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use shekyl_p2p_transport::c5_bench::{self, OpenInit, Session};

fn initiator(iters: u64) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let (init, message1) = OpenInit::message1();
        let message1_done = Instant::now();
        let message2 = c5_bench::responder_message2(&message1);
        let finish = Instant::now();
        init.finish(&message2);
        total += (message1_done - start) + finish.elapsed();
    }
    total
}

fn responder(iters: u64) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let (_init, message1) = OpenInit::message1();
        let start = Instant::now();
        let message2 = c5_bench::responder_message2(&message1);
        total += start.elapsed();
        black_box(message2);
    }
    total
}

fn seal_open(len: usize, iters: u64) -> Duration {
    let mut session = Session::connected();
    let plaintext = vec![0xA5u8; len];
    let start = Instant::now();
    for _ in 0..iters {
        black_box(session.seal_open(&plaintext));
    }
    start.elapsed()
}

fn rekey(iters: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        c5_bench::rekey_once();
    }
    start.elapsed()
}

fn bench_c5(c: &mut Criterion) {
    let mut group = c.benchmark_group("c5");
    group.sample_size(10);
    group.bench_function("initiator", |b| b.iter_custom(initiator));
    group.bench_function("responder", |b| b.iter_custom(responder));
    for len in [64usize, 1_024, 16_384, 65_535] {
        group.bench_function(format!("seal_open/{len}"), |b| {
            b.iter_custom(|iters| seal_open(len, iters))
        });
    }
    group.bench_function("rekey", |b| b.iter_custom(rekey));
    group.finish();
}

criterion_group!(benches, bench_c5);
criterion_main!(benches);
