// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `record-goldens DIR`
//!
//! Run every seed against the seam and write the parity scope: wire bytes
//! and the session outcome, one peer file and one host file per seed.
//! Events and a send-over suffix past the script's handshake response are
//! not written. The six deferred invariants are not in a transcript.
//!
//! The epee host is deleted (D13). This re-records the goldens after a
//! ruled wire change, in the same pull request, with the ruling cited; the
//! diff of the committed files is the review. *Records-was:*
//! `record-goldens EPEE_HOST DIR`, against the epee host.

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
        .ok_or_else(|| shekyl_p2p_harness::Error::new("usage: record-goldens DIR"))?;
    if args.next().is_some() {
        return Err(shekyl_p2p_harness::Error::new("usage: record-goldens DIR"));
    }
    shekyl_p2p_harness::record_goldens_from_seam(&PathBuf::from(dir))
}
