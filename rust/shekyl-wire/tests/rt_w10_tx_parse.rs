// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-W10: what parsing one listed transaction's pruned base costs.
//!
//! Ignored. The registered method is
//! `docs/benchmarks/rt_w10_request_cost_20261102.md`. `RT_W10_OUT` is the
//! directory; the test writes `parse.tsv` and `constants.tsv` and does not
//! overwrite them. Linux only: the clock is `CLOCK_THREAD_CPUTIME_ID`.

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use shekyl_wire::transaction::{COINBASE_RESERVE, MIN_BLOCK_WEIGHT};
use shekyl_wire::{Ct, Transaction};

const WARMUP: usize = 5;
const SAMPLES: usize = 100;
const HEADER: &str = "series\titeration\tbytes\twall_ns\tcpu_ns";
const PENALTY_MULTIPLE: u64 = 2;

const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
}

fn cpu_now() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a `timespec` this function owns, and the clock id
    // is Linux's thread CPU clock.
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    assert_eq!(rc, 0, "the thread CPU clock is readable");
    let seconds = u64::try_from(ts.tv_sec).expect("the thread CPU clock is non-negative");
    let nanos = u64::try_from(ts.tv_nsec).expect("the thread CPU clock is non-negative");
    seconds * 1_000_000_000 + nanos
}

fn timed(call: impl FnOnce()) -> (u64, u64) {
    let cpu_before = cpu_now();
    let wall_before = Instant::now();
    call();
    let wall_ns = u64::try_from(wall_before.elapsed().as_nanos()).expect("a sample fits u64");
    let cpu_ns = cpu_now() - cpu_before;
    (wall_ns, cpu_ns)
}

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fee_of(tx: &Transaction) -> u64 {
    match &tx.ct {
        Ct::Fcmp { fee, .. } => *fee,
        Ct::Null(_) => panic!("the parity spend is an FCMP++ transaction"),
    }
}

#[test]
#[ignore = "RT-W10 floor-device listed-tx parse; docs/benchmarks/rt_w10_request_cost_20261102.md"]
fn rt_w10_listed_tx_parse() {
    let out =
        PathBuf::from(std::env::var("RT_W10_OUT").expect("RT_W10_OUT is the output directory"));
    fs::create_dir_all(&out).expect("the output directory can be created");
    let parse_path = out.join("parse.tsv");
    let constants_path = out.join("constants.tsv");
    assert!(
        !parse_path.exists(),
        "parse.tsv already exists; a run does not overwrite"
    );
    assert!(
        !constants_path.exists(),
        "constants.tsv already exists; a run does not overwrite"
    );

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pruned_tx_hash_parity_v1.json");
    let pin: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&fixture).expect("fixture")).expect("json");
    let full = hex_bytes(pin["tx_hex"].as_str().expect("tx_hex"));
    let tx = Transaction::from_bytes(&full).expect("the parity spend parses");
    // The `txs_pruned` row: `write_segments().pruned`, which is what
    // `fees_at` passes to `Transaction::read`.
    let pruned = tx.write_segments().expect("segments").pruned;
    let parsed = Transaction::read(&mut pruned.as_slice()).expect("fees_at's parse");
    let expected = fee_of(&parsed);

    let mut rows = String::new();
    rows.push_str(HEADER);
    rows.push('\n');
    for _ in 0..WARMUP {
        let tx = Transaction::read(&mut pruned.as_slice()).expect("warmup");
        black_box(fee_of(&tx));
    }
    for iteration in 1..=SAMPLES {
        let (wall_ns, cpu_ns) = timed(|| {
            let tx = Transaction::read(&mut pruned.as_slice()).expect("parse");
            assert_eq!(fee_of(&tx), expected);
        });
        rows.push_str(&format!(
            "pruned\t{iteration}\t{}\t{wall_ns}\t{cpu_ns}\n",
            pruned.len()
        ));
    }

    let mut parse = BufWriter::new(File::create(&parse_path).expect("create parse.tsv"));
    parse.write_all(rows.as_bytes()).expect("write parse.tsv");
    parse.flush().expect("flush parse.tsv");
    let constants = format!(
        "min_block_weight\t{MIN_BLOCK_WEIGHT}\ncoinbase_reserve\t{COINBASE_RESERVE}\npruned_len\t{}\npenalty_multiple\t{PENALTY_MULTIPLE}\n",
        pruned.len()
    );
    fs::write(&constants_path, constants).expect("write constants.tsv");
}
