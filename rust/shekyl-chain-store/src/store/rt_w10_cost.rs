// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-W10: what one height of `get_coinbase_tx_sum` reads from the store.
//!
//! Ignored. The registered method is
//! `docs/benchmarks/rt_w10_request_cost_20261102.md`. `RT_W10_OUT` is the
//! directory; the test writes `coinbase.tsv` and does not overwrite it.
//! Linux only: the clock is `CLOCK_THREAD_CPUTIME_ID`.

use std::fs::{self, File};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use shekyl_chain_rules::AtHeight;
use shekyl_types::BlockHeight;

use super::connect_fixtures::{connect_chain, prefix_to};
use super::store_tests::{cleanup, tmp, EPOCH};
use super::ChainStore;

const CHAIN_BLOCKS: u64 = 32;
const WARMUP: usize = 5;
const SAMPLES: usize = 100;
const HEADER: &str = "series\titeration\tbytes\twall_ns\tcpu_ns";

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

struct Sample {
    wall_ns: u64,
    cpu_ns: u64,
}

fn timed(call: impl FnOnce()) -> Sample {
    let cpu_before = cpu_now();
    let wall_before = Instant::now();
    call();
    let wall_ns = u64::try_from(wall_before.elapsed().as_nanos()).expect("a sample fits u64");
    let cpu_ns = cpu_now() - cpu_before;
    Sample { wall_ns, cpu_ns }
}

#[test]
#[ignore = "RT-W10 floor-device coinbase span; docs/benchmarks/rt_w10_request_cost_20261102.md"]
fn rt_w10_coinbase_span_cost() {
    let out =
        PathBuf::from(std::env::var("RT_W10_OUT").expect("RT_W10_OUT is the output directory"));
    fs::create_dir_all(&out).expect("the output directory can be created");
    let path = out.join("coinbase.tsv");
    assert!(
        !path.exists(),
        "{} already exists; a run does not overwrite",
        path.display()
    );

    let store_path = tmp("rt-w10-coinbase");
    let store = ChainStore::create(&store_path, EPOCH).expect("create");
    let listed = prefix_to(BlockHeight::from_raw(CHAIN_BLOCKS), Vec::new());
    connect_chain(&store, &listed);
    let snap = store.begin_read().expect("read");
    let genesis = match snap.block(BlockHeight::ZERO).expect("genesis") {
        AtHeight::Recorded(body) => body,
        AtHeight::AboveTip => panic!("genesis is recorded"),
    };
    let miner = genesis.block.miner_transaction.hash();

    let mut rows = String::new();
    rows.push_str(HEADER);
    rows.push('\n');

    for _ in 0..WARMUP {
        let height = BlockHeight::from_raw(0);
        let _ = black_box(snap.block(height).expect("warmup block"));
        let _ = black_box(snap.block_info(height).expect("warmup info"));
        let _ = black_box(snap.tx_record(&miner).expect("warmup tx"));
    }
    for iteration in 1..=SAMPLES {
        let height = BlockHeight::from_raw(
            u64::try_from((iteration - 1) % usize::try_from(CHAIN_BLOCKS).expect("32 fits"))
                .expect("a height index fits u64"),
        );
        let block = timed(|| {
            let _ = black_box(snap.block(height).expect("block"));
        });
        let info = timed(|| {
            let _ = black_box(snap.block_info(height).expect("info"));
        });
        let tx = timed(|| {
            let _ = black_box(snap.tx_record(&miner).expect("tx"));
        });
        for (series, sample) in [("block", block), ("block_info", info), ("tx_get", tx)] {
            rows.push_str(&format!(
                "{series}\t{iteration}\t0\t{}\t{}\n",
                sample.wall_ns, sample.cpu_ns
            ));
        }
    }

    let mut file = BufWriter::new(File::create(&path).expect("create coinbase.tsv"));
    file.write_all(rows.as_bytes()).expect("write coinbase.tsv");
    file.flush().expect("flush coinbase.tsv");
    drop(snap);
    drop(store);
    cleanup(&store_path);
}
