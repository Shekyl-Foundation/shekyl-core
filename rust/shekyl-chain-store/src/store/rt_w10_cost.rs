// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-W10: what one height of `get_coinbase_tx_sum` reads from the store.
//!
//! Ignored. The registered method is
//! `docs/benchmarks/rt_w10_request_cost_20261102.md`. `RT_W10_OUT` is the
//! directory; the test writes `coinbase.tsv` and does not overwrite it.
//! Unset, warmup is [`SCRATCH_WARMUP`] and the sample count is
//! [`SCRATCH_SAMPLES`]: a fresh temporary directory this test owns, removed
//! when the run ends. That is the nightly `store-ignored` lane, and it
//! measures nothing (`scripts/ci/ignored_set_chain_store.sh`). With
//! `RT_W10_OUT` set, warmup is [`WARMUP`] and the sample count is
//! [`SAMPLES`]: that is the measurement.
//! Linux only: the clock is `CLOCK_THREAD_CPUTIME_ID`.

use std::fs::{self, File};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use shekyl_chain_rules::AtHeight;
use shekyl_types::BlockHeight;

use super::connect_fixtures::{connect_chain, prefix_to};
use super::store_tests::{tmp, EPOCH};
use super::ChainStore;

const CHAIN_BLOCKS: u64 = 32;
/// Measurement warmup, used when `RT_W10_OUT` is set. Not recorded.
const WARMUP: usize = 5;
/// Measurement samples, used when `RT_W10_OUT` is set.
const SAMPLES: usize = 100;
/// Scratch-run warmup. One call enters the timed path. The measurement
/// uses [`WARMUP`].
const SCRATCH_WARMUP: usize = 1;
/// Scratch-run samples: enough to read every series through the writer,
/// which is what that run proves. It measures nothing. The measurement
/// uses [`SAMPLES`].
const SCRATCH_SAMPLES: usize = 3;
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

/// The value recorded at a height this run holds. [`AtHeight`] is matched
/// so a height above the tip fails the run instead of being dropped.
fn recorded<T, E: std::fmt::Debug>(read: Result<AtHeight<T>, E>, what: &'static str) -> T {
    match read.expect(what) {
        AtHeight::Recorded(value) => value,
        AtHeight::AboveTip => panic!("{what} is above the tip"),
    }
}

#[test]
#[ignore = "RT-W10 floor-device coinbase span; docs/benchmarks/rt_w10_request_cost_20261102.md"]
fn rt_w10_coinbase_span_cost() {
    // `var_os`: a set value is a path, and need not be UTF-8. Unset, the run
    // writes into a directory it creates under a random name and owns; it is
    // removed by `close` below, or on a panic when it drops.
    let (out, scratch) = match std::env::var_os("RT_W10_OUT") {
        Some(dir) => (PathBuf::from(dir), None),
        None => {
            let dir = tempfile::Builder::new()
                .prefix("shekyl-chain-store-rt-w10-")
                .tempdir()
                .expect("create the scratch output directory");
            (dir.path().to_path_buf(), Some(dir))
        }
    };
    let (warmup, samples) = if scratch.is_some() {
        (SCRATCH_WARMUP, SCRATCH_SAMPLES)
    } else {
        (WARMUP, SAMPLES)
    };
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
    let genesis = recorded(snap.block(BlockHeight::ZERO), "genesis");
    let miner = genesis.block.miner_transaction.hash();

    let mut rows = String::new();
    rows.push_str(HEADER);
    rows.push('\n');

    for _ in 0..warmup {
        let height = BlockHeight::from_raw(0);
        black_box(recorded(snap.block(height), "warmup block"));
        black_box(recorded(snap.block_info(height), "warmup info"));
        let _ = black_box(snap.tx_record(&miner).expect("warmup tx"));
    }
    for iteration in 1..=samples {
        let height = BlockHeight::from_raw(
            u64::try_from((iteration - 1) % usize::try_from(CHAIN_BLOCKS).expect("32 fits"))
                .expect("a height index fits u64"),
        );
        let block = timed(|| {
            black_box(recorded(snap.block(height), "block"));
        });
        let info = timed(|| {
            black_box(recorded(snap.block_info(height), "info"));
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
    if let Some(scratch) = scratch {
        assert_eq!(
            fs::read_to_string(&path)
                .expect("read coinbase.tsv")
                .lines()
                .count(),
            1 + 3 * samples,
            "the header and three series of every sample"
        );
        scratch
            .close()
            .expect("remove the scratch output directory");
    }
}
