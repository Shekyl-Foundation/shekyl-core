// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `seam-host SEED TRANSCRIPT`
//!
//! Bind on loopback, print `host:port` on stdout, serve one connection,
//! and write the host transcript.

use std::env;
use std::io::{self, Write};
use std::path::Path;
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
    let seed: u64 = args
        .next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new("missing seed"))?
        .parse()
        .map_err(|_| shekyl_p2p_harness::Error::new("seed"))?;
    let path = args
        .next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new("missing transcript"))?;
    let host = shekyl_p2p_harness::serve_seam_once(seed)?;
    writeln!(io::stdout(), "{}", host.addr()).map_err(shekyl_p2p_harness::Error::from)?;
    let transcript = host.finish()?;
    transcript.write(Path::new(&path))
}
