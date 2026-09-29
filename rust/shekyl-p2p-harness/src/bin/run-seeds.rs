// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `run-seeds EPEE_HOST`
//!
//! Every harness seed against the seam (in-process) and the epee recording
//! binary. Owns the seed list. A mismatch keeps transcripts under
//! `p2p-harness-fail/`.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), shekyl_p2p_harness::Error> {
    let mut args = env::args().skip(1);
    let epee = args
        .next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new("usage: run-seeds EPEE_HOST"))?;
    if args.next().is_some() {
        return Err(shekyl_p2p_harness::Error::new("usage: run-seeds EPEE_HOST"));
    }
    shekyl_p2p_harness::run_all(&PathBuf::from(epee))
}
