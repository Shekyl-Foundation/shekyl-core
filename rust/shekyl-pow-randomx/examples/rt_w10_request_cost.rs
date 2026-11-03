// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-W10: what one `calc_pow` and one header hash cost on the floor device.
//!
//! The registered method is
//! `docs/benchmarks/rt_w10_request_cost_20261102.md`. This binary writes
//! `hashes.tsv`. `scripts/bench/rt_w10_summary.py` is the statistics and
//! the derivation, and it refuses a file that is not the registered shape.
//!
//! Linux runs the measurement. Any other host exits without writing a run:
//! the registered clock is the Linux thread CPU clock, and the host is the
//! Pi 4. `cargo test` still builds the example everywhere.
//!
//! ```text
//! cargo run --release -p shekyl-pow-randomx --example rt_w10_request_cost -- <out-dir>
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "rt-w10 measures the floor device, which is Linux (the Pi 4). This host is {}.",
            std::env::consts::OS
        );
        ExitCode::from(2)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File};
    use std::hint::black_box;
    use std::io::{BufWriter, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::time::Instant;

    use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

    /// [`shekyl_wire::block::MIN_POW_BLOB_SIZE`]. A header's PoW preimage.
    /// The wire crate's test `the_shortest_pow_blob_is_the_named_minimum`
    /// holds this literal equal to the constant.
    const HEADER_POW_BYTES: usize = 136;

    /// [`shekyl_wire::block::MAX_BLOCK_BLOB_SIZE`]: `MAX_TX_SIZE` +
    /// `READ_LEN_CAP * 32` + `MAX_BLOCK_HEADER_SIZE`. The longest blob
    /// `calc_pow` hashes. Held by the same wire test.
    const MAX_BLOCK_BLOB_BYTES: usize = 33_000_128;

    /// Registered counts. The summary refuses any other length.
    const WARMUP: usize = 5;
    const SAMPLES: usize = 100;

    const HASHES_FILE: &str = "hashes.tsv";
    const HEADER: &str = "series\titeration\tbytes\twall_ns\tcpu_ns";

    /// Linux `CLOCK_THREAD_CPUTIME_ID`.
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
        // SAFETY: `ts` is a `timespec` this function owns, and the clock
        // id is Linux's thread CPU clock.
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

    /// CPU brackets the wall read, so the CPU sample includes the two
    /// wall-clock reads and the wall sample does not include `clock_gettime`.
    fn timed(call: impl FnOnce()) -> Sample {
        let cpu_before = cpu_now();
        let wall_before = Instant::now();
        call();
        let wall_ns = u64::try_from(wall_before.elapsed().as_nanos()).expect("a sample fits u64");
        let cpu_ns = cpu_now() - cpu_before;
        Sample { wall_ns, cpu_ns }
    }

    pub(super) fn run() -> ExitCode {
        let mut args = std::env::args_os().skip(1);
        let Some(out) = args.next() else {
            eprintln!("usage: rt_w10_request_cost <out-dir>");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("usage: rt_w10_request_cost <out-dir>");
            return ExitCode::from(2);
        }
        let out = PathBuf::from(out);
        if let Err(error) = fs::create_dir_all(&out) {
            eprintln!("cannot create {}: {error}", out.display());
            return ExitCode::from(1);
        }
        let hashes_path = out.join(HASHES_FILE);
        if hashes_path.exists() {
            eprintln!(
                "{} already exists; a run does not overwrite",
                hashes_path.display()
            );
            return ExitCode::from(1);
        }

        let seed = Seedhash::from_bytes([0x11; 32]);
        let derive_started = Instant::now();
        let cache = PreparedCache::derive(seed);
        let derive_wall_ns = derive_started.elapsed().as_nanos();
        eprintln!("cache_derive_wall_ns={derive_wall_ns}");

        let header = vec![0xA5_u8; HEADER_POW_BYTES];
        let max_blob = vec![0xA5_u8; MAX_BLOCK_BLOB_BYTES];

        let mut rows = String::new();
        rows.push_str(HEADER);
        rows.push('\n');
        write_series(&mut rows, "header", &cache, &header);
        write_series(&mut rows, "max", &cache, &max_blob);

        let mut file = match File::create(&hashes_path) {
            Ok(file) => BufWriter::new(file),
            Err(error) => {
                eprintln!("cannot create {}: {error}", hashes_path.display());
                return ExitCode::from(1);
            }
        };
        if let Err(error) = file.write_all(rows.as_bytes()).and_then(|()| file.flush()) {
            eprintln!("cannot write {}: {error}", hashes_path.display());
            return ExitCode::from(1);
        }
        ExitCode::SUCCESS
    }

    fn write_series(rows: &mut String, series: &str, cache: &PreparedCache, blob: &[u8]) {
        for _ in 0..WARMUP {
            black_box(compute_hash(cache, blob));
        }
        for iteration in 1..=SAMPLES {
            let sample = timed(|| {
                black_box(compute_hash(cache, blob));
            });
            rows.push_str(&format!(
                "{series}\t{iteration}\t{}\t{}\t{}\n",
                blob.len(),
                sample.wall_ns,
                sample.cpu_ns
            ));
        }
    }
}
