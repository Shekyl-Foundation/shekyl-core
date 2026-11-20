// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `miner-kat <blob-ascii> [expected-hash-hex]`
//!
//! The miner-shaped known answer (`RANDOMX_V2_PHASE3_PLAN.md` §7.2 #3):
//! the C library alone, as a miner runs it, hashes `<blob-ascii>` under
//! seed `0x01..=0x20`. The VM is [`FullDatasetVm`]. Nothing else is
//! called: no Rust verifier, no harness corpus, no consensus code. With
//! `[expected-hash-hex]` (64 hex digits) the run fails unless the hash
//! equals it; without, it prints the hash (capture).

use std::env;
use std::process::ExitCode;

use shekyl_randomx_differential::full_dataset::FullDatasetVm;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (blob, expected) = match args.as_slice() {
        [blob] => (blob.as_bytes(), None),
        [blob, hex] if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
            (blob.as_bytes(), Some(hex.to_ascii_lowercase()))
        }
        _ => {
            eprintln!("usage: miner-kat <blob-ascii> [expected-hash-hex (64 hex digits)]");
            return ExitCode::FAILURE;
        }
    };
    println!("RandomX v2 miner-shaped full-dataset known answer [pin aaafe71]");
    println!(
        "  seed 0x01..0x20, blob {} bytes, one ~2 080 MiB dataset",
        blob.len()
    );
    let seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i + 1).expect("32 fits u8"));
    let vm = match FullDatasetVm::build(&seed) {
        Ok(vm) => vm,
        Err(err) => {
            eprintln!("FATAL: {err}");
            return ExitCode::FAILURE;
        }
    };
    let got: String = vm.hash(blob).iter().map(|b| format!("{b:02x}")).collect();
    match expected {
        None => {
            println!("CAPTURE: {got}");
            ExitCode::SUCCESS
        }
        Some(want) if want == got => {
            println!("PASS: the full-dataset hash is the expected {got}");
            ExitCode::SUCCESS
        }
        Some(want) => {
            eprintln!("FAIL: the full-dataset hash is {got}, expected {want}");
            ExitCode::FAILURE
        }
    }
}
