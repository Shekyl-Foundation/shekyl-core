// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `full-parity genesis | canonical | corpus <seed-index> <seed-count>`
//!
//! The Phase 3a Hole-1 gate (`RANDOMX_V2_PHASE3_PLAN.md` §7): the C
//! library's full-dataset hash against the Rust verifier's light-cache
//! hash, one mode and one dataset (~2 080 MiB) per invocation
//! ([`shekyl_randomx_differential::full_parity`]). `corpus` takes one seed
//! group of the nightly random corpus; `<seed-count>` is the number of
//! groups the caller runs, and the run refuses when the corpus has a
//! different number, so a resized corpus cannot leave seeds unrun.
//!
//! Exit 0 on parity and pins; 1 otherwise, the message saying which.

use std::env;
use std::process::ExitCode;

use shekyl_randomx_differential::corpus_random::NIGHTLY_SEEDHASH_COUNT;
use shekyl_randomx_differential::full_parity::{
    canonical_corpus, genesis_corpus, random_corpus_group, run, verdict, Corpus, Verdict,
};

const USAGE: &str = "usage: full-parity genesis | canonical | corpus <seed-index> <seed-count>";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn corpus_from(args: &[String]) -> Result<(String, Corpus), String> {
    match args {
        [mode] if mode == "genesis" => Ok(("genesis".into(), genesis_corpus()?)),
        [mode] if mode == "canonical" => Ok(("canonical".into(), canonical_corpus())),
        [mode, index, count] if mode == "corpus" => {
            let index: usize = index.parse().map_err(|_| USAGE.to_string())?;
            let count: usize = count.parse().map_err(|_| USAGE.to_string())?;
            if count != NIGHTLY_SEEDHASH_COUNT {
                return Err(format!(
                    "the corpus has {NIGHTLY_SEEDHASH_COUNT} seeds and the caller runs {count}: \
                     cover every seed"
                ));
            }
            Ok((format!("corpus seed {index}"), random_corpus_group(index)?))
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (mode, corpus) = match corpus_from(&args) {
        Ok(found) => found,
        Err(err) => {
            eprintln!("FATAL: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("RandomX v2 full-dataset (C) vs light-cache (Rust) parity gate [{mode}]");
    println!("  pin: external/randomx-v2 @ aaafe71  (RANDOMX_V2_PHASE3_PLAN.md §7)");
    println!("  allocates one ~2 080 MiB dataset for this run");
    println!("seed {} : building the full dataset ...", hex(&corpus.seed));
    let outcomes = match run(&corpus) {
        Ok(outcomes) => outcomes,
        Err(err) => {
            eprintln!("FATAL: {err}");
            return ExitCode::FAILURE;
        }
    };
    for o in &outcomes {
        let state = match (o.parity(), o.pinned()) {
            (true, true) => "OK",
            (false, _) => "*** MISMATCH ***",
            (true, false) => "*** PIN MISMATCH ***",
        };
        println!(
            "  [{:<20}] C-full={} rust-light={}  {state}",
            o.label,
            hex(&o.c_full),
            hex(&o.rust_light)
        );
    }
    match verdict(&outcomes) {
        Verdict::Pass => {
            println!(
                "PASS [{mode}]: C full-dataset == Rust light-cache across {} case(s)",
                outcomes.len()
            );
            ExitCode::SUCCESS
        }
        Verdict::Divergence => {
            eprintln!(
                "HALT-ON-RED (RANDOMX_V2_PHASE3_PLAN.md §7.3) [{mode}]: the C full dataset and \
                 the Rust light cache diverge at pin aaafe71. This is not a test bug: the light \
                 verifier cannot validate full-dataset-mined blocks. Halt and escalate."
            );
            ExitCode::FAILURE
        }
        Verdict::PinDrift => {
            eprintln!(
                "PIN DRIFT [{mode}]: C full == Rust light, but a committed pin does not hold. \
                 The substrate changed under the pins; audit before proceeding."
            );
            ExitCode::FAILURE
        }
    }
}
