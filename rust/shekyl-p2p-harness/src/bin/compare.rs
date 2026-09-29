// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `compare PEER_A HOST_A PEER_B HOST_B`
//!
//! Diff two seeded runs. A parity mismatch exits 1 and names the seed
//! and the field. [`shekyl_p2p_harness::Field::ByteBounds`] is classified
//! away. An unknown version line is a parse failure.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use shekyl_p2p_harness::{diff, Run, Transcript};

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, shekyl_p2p_harness::Error> {
    let mut args = env::args().skip(1);
    let peer_a = read(&mut args, "peer a")?;
    let host_a = read(&mut args, "host a")?;
    let peer_b = read(&mut args, "peer b")?;
    let host_b = read(&mut args, "host b")?;
    let findings = diff(
        &Run {
            peer: peer_a,
            host: host_a,
        },
        &Run {
            peer: peer_b,
            host: host_b,
        },
    );
    if findings.is_empty() {
        return Ok(true);
    }
    for finding in findings {
        eprintln!("{finding}");
    }
    Ok(false)
}

fn read(
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<Transcript, shekyl_p2p_harness::Error> {
    let path = args
        .next()
        .ok_or_else(|| shekyl_p2p_harness::Error::new(format!("missing {name}")))?;
    Transcript::read(Path::new(&path))
}
