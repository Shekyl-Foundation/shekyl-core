// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `record-goldens EPEE_HOST DIR`
//!
//! Run every seed against the epee host and write the parity scope:
//! wire bytes and the session outcome, one peer file and one host file
//! per seed. Events and a send-over suffix past the script's handshake
//! response are not written. The six deferred invariants are not in a
//! transcript.

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
        .ok_or_else(|| shekyl_p2p_harness::Error::new("usage: record-goldens EPEE_HOST DIR"))?;
    let dir = args
        .next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new("usage: record-goldens EPEE_HOST DIR"))?;
    if args.next().is_some() {
        return Err(shekyl_p2p_harness::Error::new(
            "usage: record-goldens EPEE_HOST DIR",
        ));
    }
    shekyl_p2p_harness::record_goldens(&PathBuf::from(epee), &PathBuf::from(dir))
}
