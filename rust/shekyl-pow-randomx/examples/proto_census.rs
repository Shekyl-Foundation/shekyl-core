// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PROTOTYPE: count every RandomX FP op by op and rounding mode, and
//! classify inputs and results, over random seedhashes and inputs.
//!
//! cargo run --release --example proto_census \
//!   --features proto-fp-census,proto-rounding-c -- SEEDHASHES INPUTS_PER_SEEDHASH

use shekyl_pow_randomx::fp_proto::census::{take, Census};
use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn merge(a: &mut Census, b: &Census) {
    for o in 0..5 {
        for m in 0..4 {
            a.ops[o][m] += b.ops[o][m];
        }
    }
    a.result_subnormal += b.result_subnormal;
    a.result_zero += b.result_zero;
    a.result_inf += b.result_inf;
    a.result_nan += b.result_nan;
    a.input_subnormal += b.input_subnormal;
    a.input_inf += b.input_inf;
    a.c_slow_path += b.c_slow_path;
    a.c_overflow += b.c_overflow;
    a.c_adjusted += b.c_adjusted;
    a.min_e_result = a.min_e_result.min(b.min_e_result);
    a.min_f_result = a.min_f_result.min(b.min_f_result);
    a.max_f_result = a.max_f_result.max(b.max_f_result);
    a.max_runs_per_instruction = a.max_runs_per_instruction.max(b.max_runs_per_instruction);
    a.max_fdiv_runs_per_e_register = a.max_fdiv_runs_per_e_register.max(b.max_fdiv_runs_per_e_register);
    a.max_fdiv_instrs_per_e_register = a.max_fdiv_instrs_per_e_register.max(b.max_fdiv_instrs_per_e_register);
    a.iterations += b.iterations;
}

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).map(|s| s.parse().expect("count")).collect();
    let (n_seeds, n_inputs) = (args.first().copied().unwrap_or(4), args.get(1).copied().unwrap_or(16));
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut total = Census { min_e_result: f64::INFINITY, min_f_result: f64::INFINITY, ..Default::default() };
    let mut rng = 0xCE45_0001u64;
    let mut hashes = 0usize;
    for _ in 0..n_seeds {
        let mut seed = [0u8; 32];
        for c in seed.chunks_mut(8) {
            c.copy_from_slice(&splitmix(&mut rng).to_le_bytes());
        }
        let prepared = PreparedCache::derive(Seedhash::from_bytes(seed));
        let inputs: Vec<Vec<u8>> = (0..n_inputs)
            .map(|_| {
                let len = 1 + (splitmix(&mut rng) % 128) as usize;
                (0..len).map(|_| splitmix(&mut rng) as u8).collect()
            })
            .collect();
        let parts: Vec<Census> = std::thread::scope(|s| {
            let hs: Vec<_> = inputs
                .chunks(inputs.len().div_ceil(threads))
                .map(|chunk| {
                    let prepared = &prepared;
                    s.spawn(move || {
                        let _ = take();
                        for d in chunk {
                            let _ = compute_hash(prepared, d);
                        }
                        take()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().expect("worker")).collect()
        });
        for p in &parts {
            merge(&mut total, p);
        }
        hashes += inputs.len();
    }
    let names = ["add", "sub", "mul", "div", "sqrt"];
    let all: u64 = total.ops.iter().flatten().sum();
    println!("hashes {hashes}, program iterations {}, FP ops (packed) {all}", total.iterations);
    println!("op      nearest        down          up      toward0   non-nearest%");
    for (o, n) in names.iter().enumerate() {
        let r = total.ops[o];
        let s: u64 = r.iter().sum();
        println!(
            "{n:5} {:>11} {:>11} {:>11} {:>11}   {:.3}",
            r[0],
            r[1],
            r[2],
            r[3],
            100.0 * (s - r[0]) as f64 / s.max(1) as f64
        );
    }
    let nn: u64 = total.ops.iter().map(|r| r[1] + r[2] + r[3]).sum();
    println!("non-nearest share of all FP ops: {:.3}%", 100.0 * nn as f64 / all.max(1) as f64);
    println!(
        "results (per lane): subnormal {} zero {} inf {} nan {}; inputs: subnormal {} inf {}",
        total.result_subnormal, total.result_zero, total.result_inf, total.result_nan, total.input_subnormal, total.input_inf
    );
    println!(
        "(c) lanes adjusted by one step {}, overflow rule {}, slow integer path {}",
        total.c_adjusted, total.c_overflow, total.c_slow_path
    );
    println!(
        "min |E result| {:e} (2^{:.1}); F nonzero |result| in [{:e}, {:e}]",
        total.min_e_result,
        total.min_e_result.log2(),
        total.min_f_result,
        total.max_f_result
    );
    println!(
        "max runs of one instruction per iteration {}; max FDIV_M runs on one E register per iteration {}; max FDIV_M instructions on one E register per program {}",
        total.max_runs_per_instruction, total.max_fdiv_runs_per_e_register, total.max_fdiv_instrs_per_e_register
    );
}
