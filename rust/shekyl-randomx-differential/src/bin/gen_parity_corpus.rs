// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parity-corpus generator binary for the Phase 3a Hole-1 C++ parity
//! gate (`tests/randomx_v2_parity/`, `corpus` mode).
//!
//! Emits the full nightly random corpus + canonical pins in the
//! [`shekyl_randomx_differential::parity_corpus`] v1 file format.
//! The corpus is deterministic (R6-D1 fixed ChaCha20 seed), so the
//! output is byte-identical on every run at the same corpus revision;
//! the `parity_corpus` module's whole-file SHA-256 pin asserts exactly
//! that per-PR. The CI consumer is the `full-parity` job in
//! `.github/workflows/randomx-v2-differential.yml`, which runs this
//! binary and hands the file to `randomx-v2-full-parity corpus`.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --locked -p shekyl-randomx-differential \
//!     --bin gen-parity-corpus -- --out <path>
//! ```
//!
//! With no `--out`, writes to stdout (the file is ~150 MiB; prefer
//! `--out` outside of pipelines). Progress goes to stderr.

use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::ExitCode;

use shekyl_randomx_differential::corpus_random::{
    NIGHTLY_DATA_PER_SEEDHASH, NIGHTLY_SEEDHASH_COUNT,
};
use shekyl_randomx_differential::parity_corpus::write_parity_corpus;

fn print_help() {
    eprintln!(
        "gen-parity-corpus: emit the nightly parity corpus + canonical pins\n\
         for the Phase 3a full-dataset parity gate.\n\
         \n\
         Usage: gen-parity-corpus [--out <path>]\n\
         \n\
         --out <path>   write to <path> (default: stdout)"
    );
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    let mut out_path: Option<String> = None;
    let mut args = argv[1..].iter();
    while let Some(arg) = args.next() {
        if arg == "--out" {
            match args.next() {
                Some(p) => out_path = Some(p.clone()),
                None => {
                    eprintln!("error: --out requires a path; pass --help for usage");
                    return ExitCode::FAILURE;
                }
            }
        } else if arg == "--help" || arg == "-h" {
            print_help();
            return ExitCode::SUCCESS;
        } else {
            eprintln!("error: unknown argument '{arg}'; pass --help for usage");
            return ExitCode::FAILURE;
        }
    }

    eprintln!(
        "gen-parity-corpus: emitting {NIGHTLY_SEEDHASH_COUNT} seedhashes × \
         {NIGHTLY_DATA_PER_SEEDHASH} data = {} pinned pairs",
        NIGHTLY_SEEDHASH_COUNT * NIGHTLY_DATA_PER_SEEDHASH
    );

    let result = match &out_path {
        Some(path) => File::create(path)
            .map_err(|e| format!("create {path}: {e}"))
            .and_then(|f| {
                let mut w = BufWriter::new(f);
                write_parity_corpus(&mut w)
                    .and_then(|()| w.flush())
                    .map_err(|e| format!("write {path}: {e}"))
            }),
        None => {
            let stdout = std::io::stdout();
            let mut w = BufWriter::new(stdout.lock());
            write_parity_corpus(&mut w)
                .and_then(|()| w.flush())
                .map_err(|e| format!("write stdout: {e}"))
        }
    };

    match result {
        Ok(()) => {
            eprintln!(
                "gen-parity-corpus: done ({})",
                out_path.as_deref().unwrap_or("stdout")
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
