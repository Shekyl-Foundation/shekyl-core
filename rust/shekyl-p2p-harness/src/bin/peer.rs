// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `peer ADDR SEED TRANSCRIPT`
//!
//! Connect to ADDR, run SEED, write the peer transcript.

use std::env;
use std::net::SocketAddr;
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
    let addr: SocketAddr = next(&mut args, "address")?
        .parse()
        .map_err(|_| shekyl_p2p_harness::Error::new("address"))?;
    let seed: u64 = next(&mut args, "seed")?
        .parse()
        .map_err(|_| shekyl_p2p_harness::Error::new("seed"))?;
    let path = next(&mut args, "transcript")?;
    let transcript = shekyl_p2p_harness::run_peer(addr, seed)?;
    transcript.write(Path::new(&path))
}

fn next(
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, shekyl_p2p_harness::Error> {
    args.next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new(format!("missing {name}")))
}
