// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dynamic timing test for the CA-1 field arithmetic (dudect's method), on
//! the devices BINSEC cannot decode and on the x86_64 hosts where CA-2 was
//! found.
//!
//! Each row times one operation on two input classes interleaved at random
//! (`classes`), every input built before the clock starts, a batch of
//! `BATCH` operations per sample (`harness`), and compares the classes'
//! timings with Welch's t, full and tail-cropped, against dudect's
//! threshold (`stats`). The row list (`suite`) carries its own controls:
//! null rows that must stay flat and positive controls that must cross, or
//! the run says nothing on that device.
//!
//! This is evidence of a different kind from the static BINSEC verdicts:
//! it sees this device, this binary and this run, and it cannot prove the
//! absence of a branch, only fail to observe one. Its rows are recorded as
//! `dynamic`, never as a checkct pass.
//!
//! Usage: see `cli`.

mod classes;
mod cli;
mod field;
mod harness;
mod operand;
mod rng;
mod stats;
mod suite;

use std::process::ExitCode;

use cli::Config;
use harness::Harness;

fn main() -> ExitCode {
    let config = match Config::parse(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ct-dynamic: {error}\nusage: {}", cli::USAGE);
            return ExitCode::from(cli::USAGE_EXIT_CODE);
        }
    };
    let mut harness = Harness::new(config);
    harness.print_header();
    suite::run(&mut harness);
    ExitCode::SUCCESS
}
