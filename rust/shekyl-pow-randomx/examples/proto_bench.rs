// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PROTOTYPE: hash time for the rounding comparison, on the production
//! verification path (`compute_hash` over a `PreparedCache`, light mode).
//!
//! Single-thread: ROUNDS passes over INPUTS fixed inputs, median ms/hash.
//! Full-machine: one thread per CPU, each hashing for SECONDS, total
//! hashes per second. Same seedhash and inputs for every build.
//!
//! cargo run --release --example proto_bench [--features proto-rounding-X] -- INPUTS ROUNDS SECONDS [THREADS]

use std::time::{Duration, Instant};

use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let n_inputs: usize = a.first().map_or(32, |s| s.parse().expect("inputs"));
    let rounds: usize = a.get(1).map_or(5, |s| s.parse().expect("rounds"));
    let seconds: u64 = a.get(2).map_or(20, |s| s.parse().expect("seconds"));
    let threads: usize = a
        .get(3)
        .map(|s| s.parse().expect("threads"))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()));
    let build = if cfg!(feature = "proto-rounding-c-int") {
        "c-int"
    } else if cfg!(feature = "proto-rounding-c") {
        "c"
    } else if cfg!(feature = "proto-rounding-b") {
        "b"
    } else {
        "baseline"
    };
    let prepared = PreparedCache::derive(Seedhash::from_bytes([0xB7; 32]));
    let inputs: Vec<Vec<u8>> = (0..n_inputs as u32).map(|i| [i.to_le_bytes(), [0x42; 4]].concat()).collect();

    // warm-up
    for d in inputs.iter().take(4) {
        let _ = compute_hash(&prepared, d);
    }
    let mut per_round = Vec::new();
    let mut check = 0u8;
    for _ in 0..rounds {
        let t = Instant::now();
        for d in &inputs {
            check ^= compute_hash(&prepared, d)[0];
        }
        per_round.push(t.elapsed().as_secs_f64() * 1e3 / n_inputs as f64);
    }
    per_round.sort_by(f64::total_cmp);
    let median = per_round[per_round.len() / 2];

    let deadline = Duration::from_secs(seconds);
    let counts: Vec<u64> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let prepared = &prepared;
                s.spawn(move || {
                    let start = Instant::now();
                    let mut n = 0u64;
                    let mut i = t as u32;
                    while start.elapsed() < deadline {
                        let d = [i.to_le_bytes(), [0x43; 4]].concat();
                        let _ = compute_hash(prepared, &d);
                        n += 1;
                        i = i.wrapping_add(threads as u32);
                    }
                    n
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("worker")).collect()
    });
    let total: u64 = counts.iter().sum();
    println!(
        "build={build} single_thread_ms_per_hash_median={median:.3} (rounds {:?}) full_machine_threads={threads} hashes_per_s={:.2} check={check:02x}",
        per_round.iter().map(|x| (x * 1000.0).round() / 1000.0).collect::<Vec<_>>(),
        total as f64 / seconds as f64
    );
}
