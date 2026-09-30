// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `check-goldens DIR`
//!
//! Every harness seed against the seam, compared to the recorded parity
//! goldens. The epee host is not in this process.

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
    let dir = args
        .next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new("usage: check-goldens DIR"))?;
    if args.next().is_some() {
        return Err(shekyl_p2p_harness::Error::new("usage: check-goldens DIR"));
    }
    shekyl_p2p_harness::check_goldens(&PathBuf::from(dir))
}
