// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical-output generator binary for the Phase 2g differential
//! test harness (§5.2.6 + R4-D7 + §3.18 R6-D4).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §4.6 M1 + R4-D7 +
//! §3.18 R6-D4, this binary produces the contents of
//! `rust/shekyl-randomx-differential/src/canonical_outputs.rs` by
//! invoking the C reference (via `randomx-v2-sys`) against every
//! `(seedhash, data)` pair in the random corpus generated at
//! nightly sizing per §5.1.5 + R1-D4 §F2 and every seedhash's
//! cache-memory SHA-256 fingerprint per R1-D14. The output is
//! written to stdout as a Rust source file that the operator
//! pastes into the `canonical_outputs.rs` module; stderr carries
//! progress and diagnostic information.
//!
//! ## Output shape (§3.18 R6-D4 flat arrays)
//!
//! Per §3.18 R6-D4 substrate-correction, the canonical-output
//! shape is two flat hash arrays indexed by corpus position:
//!
//! - `CANONICAL_RANDOM_HASHES: &[[u8; 32]]` — the *i*-th entry is
//!   the C oracle's hash for the *i*-th pair in
//!   `generate_random_corpus(N, M).iter().enumerate()`.
//! - `CANONICAL_CACHE_SHAS: &[[u8; 32]]` — the *j*-th entry is the
//!   SHA-256 of the 256-MiB cache memory for the *j*-th unique
//!   seedhash in the corpus.
//!
//! The harness re-derives `(seedhash, data)` from the deterministic
//! corpus generator at test time; the canonical only commits
//! hashes (not data) per the R6-D4 file-sizing discipline. The
//! pre-R6-D4 shape (embedded `data: &'static [u8]` per pair) would
//! produce a ~150 MB canonical_outputs.rs at nightly cadence; the
//! flat-array shape is bounded at ~200 KB.
//!
//! ## Invocation
//!
//! ```text
//! RANDOMX_V2_INSTALL_DIR=/path/to/install \
//!     cargo run --release \
//!         --bin gen-canonical-outputs \
//!         -p shekyl-randomx-differential \
//!         > canonical_outputs.rs.new
//! ```
//!
//! The operator reviews `canonical_outputs.rs.new` against
//! `canonical_outputs.rs` and commits the new content alongside
//! the corpus and a refreshed `CANONICAL_OUTPUTS_GENERATOR_VERSION`
//! marker.
//!
//! ## Sizing
//!
//! Default sizing matches the nightly cadence
//! `(NIGHTLY_SEEDHASH_COUNT, NIGHTLY_DATA_PER_SEEDHASH)` = `(32, 32)`
//! per R1-D4 §F2 — 1024 pairs. Operators can override via
//! `--random-corpus-seedhashes=<N>` /
//! `--random-corpus-data-per-seedhash=<M>` for diagnostic
//! regeneration, but the committed canonical must always be at the
//! nightly cadence so per-PR runs can subset to the first 128
//! pairs without re-running the C reference per §3.18 R6-D4.
//!
//! ## Safety
//!
//! The binary calls unsafe C FFI functions (`randomx_alloc_cache`,
//! `randomx_init_cache`, …); per the §5.1.8 + R4-D5 lifecycle, each
//! seedhash gets one cache + one VM allocated; the VM is reused
//! across all data values for the seedhash; both are released
//! before the next seedhash. NULL-pointer checks on
//! `randomx_alloc_cache` / `randomx_create_vm` per §5.1.8.

use std::env;
use std::ffi::c_void;
use std::process::ExitCode;
use std::ptr;

use randomx_v2_sys::{
    randomx_alloc_cache, randomx_calculate_hash, randomx_create_vm, randomx_destroy_vm,
    randomx_get_cache_memory, randomx_init_cache, randomx_release_cache, RANDOMX_FLAG_DEFAULT,
};
use sha2::{Digest, Sha256};
use shekyl_pow_randomx::Seedhash;
use shekyl_randomx_differential::corpus_random::{
    generate_random_corpus, RandomCorpusPair, NIGHTLY_DATA_PER_SEEDHASH, NIGHTLY_SEEDHASH_COUNT,
};

/// 256 MiB — `RANDOMX_ARGON_MEMORY (262144) × ArgonBlockSize (1024)`
/// per the C reference's `common.hpp:88`. Used to slice the
/// `randomx_get_cache_memory` return into a fixed-size byte view
/// before SHA-256 hashing.
const RANDOMX_CACHE_SIZE_BYTES: usize = 262_144 * 1024;

/// Hash output width per `randomx_calculate_hash`'s contract.
const RANDOMX_HASH_SIZE: usize = 32;

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    let mut seedhash_count: usize = NIGHTLY_SEEDHASH_COUNT;
    let mut data_per_seedhash: usize = NIGHTLY_DATA_PER_SEEDHASH;
    for arg in &argv[1..] {
        if let Some(v) = arg.strip_prefix("--random-corpus-seedhashes=") {
            match v.parse() {
                Ok(n) => seedhash_count = n,
                Err(e) => {
                    eprintln!("error: --random-corpus-seedhashes: {e}");
                    return ExitCode::FAILURE;
                }
            }
        } else if let Some(v) = arg.strip_prefix("--random-corpus-data-per-seedhash=") {
            match v.parse() {
                Ok(n) => data_per_seedhash = n,
                Err(e) => {
                    eprintln!("error: --random-corpus-data-per-seedhash: {e}");
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
        "gen-canonical-outputs: generating {} seedhashes × {} data \
         = {} pairs",
        seedhash_count,
        data_per_seedhash,
        seedhash_count * data_per_seedhash
    );
    let corpus = generate_random_corpus(seedhash_count, data_per_seedhash);
    match generate(&corpus) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "gen-canonical-outputs — Phase 2g canonical-output generator\n\
         \n\
         Generates the contents of canonical_outputs.rs by invoking\n\
         the external/randomx-v2 C reference against every\n\
         (seedhash, data) pair in the random corpus per\n\
         RANDOMX_V2_PHASE2G_PLAN.md §5.1.5 + §5.1.17 + §3.18 R6-D4.\n\
         \n\
         USAGE:\n  \
             RANDOMX_V2_INSTALL_DIR=<dir> cargo run --release \\\n  \
                 --bin gen-canonical-outputs \\\n  \
                 -p shekyl-randomx-differential > canonical_outputs.rs.new\n\
         \n\
         FLAGS:\n  \
             --random-corpus-seedhashes=<N>          (default: 32)\n  \
             --random-corpus-data-per-seedhash=<M>   (default: 32)\n  \
             --help, -h                              Print this message\n"
    );
}

fn generate(corpus: &[RandomCorpusPair]) -> Result<(), String> {
    println!("// Copyright (c) 2025-2026, The Shekyl Foundation");
    println!("//");
    println!("// All rights reserved.");
    println!("// BSD-3-Clause");
    println!();
    println!("// Generated by `cargo run --bin gen-canonical-outputs`");
    println!("// per RANDOMX_V2_PHASE2G_PLAN.md §5.2.6 + R4-D7 + §3.18 R6-D4.");
    println!("// Do not edit by hand; re-run the generator and");
    println!("// commit the new output. See §5.7's canonical-output");
    println!("// regeneration discipline.");
    println!("//");
    println!("// Indexed by corpus position: the i-th entry of");
    println!("// CANONICAL_RANDOM_HASHES corresponds to the i-th pair");
    println!("// in generate_random_corpus(N, M).iter().enumerate();");
    println!("// the j-th entry of CANONICAL_CACHE_SHAS is the");
    println!("// SHA-256 of the 256-MiB cache memory for the j-th");
    println!("// unique seedhash in the corpus's seedhash sequence.");
    println!();
    println!("pub const CANONICAL_RANDOM_HASHES: &[[u8; 32]] = &[");

    // Group corpus by seedhash so cache+VM allocation is per-seedhash
    // (R4-D5 lifecycle); within each group the VM is reused.
    let mut grouped: Vec<(Seedhash, Vec<&[u8]>)> = Vec::new();
    for pair in corpus {
        match grouped.last_mut() {
            Some((s, datas)) if s == &pair.seedhash => {
                datas.push(&pair.data);
            }
            _ => {
                grouped.push((pair.seedhash, vec![&pair.data]));
            }
        }
    }

    let mut cache_shas: Vec<[u8; 32]> = Vec::new();
    for (i, (seedhash, datas)) in grouped.iter().enumerate() {
        eprintln!(
            "  seedhash {}/{} ({}): {} data values",
            i + 1,
            grouped.len(),
            seedhash,
            datas.len()
        );
        // SAFETY: each FFI call is documented in randomx-v2-sys's
        // safety section; lifecycle follows R4-D5 (cache + VM
        // allocated per seedhash; VM reused across datas; released
        // before next seedhash). NULL checks on alloc returns.
        unsafe {
            let cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
            if cache.is_null() {
                return Err(format!(
                    "randomx_alloc_cache returned NULL for seedhash {seedhash}"
                ));
            }
            let seedhash_bytes = seedhash.as_bytes();
            randomx_init_cache(
                cache,
                seedhash_bytes.as_ptr().cast::<c_void>(),
                seedhash_bytes.len(),
            );

            // Compute cache SHA-256 from C oracle's view per R1-D14.
            let cache_mem = randomx_get_cache_memory(cache);
            if cache_mem.is_null() {
                randomx_release_cache(cache);
                return Err(format!(
                    "randomx_get_cache_memory returned NULL for seedhash {seedhash}"
                ));
            }
            let cache_bytes =
                std::slice::from_raw_parts(cache_mem.cast::<u8>(), RANDOMX_CACHE_SIZE_BYTES);
            let mut hasher = Sha256::new();
            hasher.update(cache_bytes);
            let cache_sha: [u8; 32] = hasher.finalize().into();
            cache_shas.push(cache_sha);

            let vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, ptr::null_mut());
            if vm.is_null() {
                randomx_release_cache(cache);
                return Err(format!(
                    "randomx_create_vm returned NULL for seedhash {seedhash}"
                ));
            }

            for data in datas {
                let mut output = [0u8; RANDOMX_HASH_SIZE];
                randomx_calculate_hash(
                    vm,
                    data.as_ptr().cast::<c_void>(),
                    data.len(),
                    output.as_mut_ptr().cast::<c_void>(),
                );
                emit_hash_row(&output);
            }

            randomx_destroy_vm(vm);
            randomx_release_cache(cache);
        }
    }
    println!("];");
    println!();
    println!("pub const CANONICAL_CACHE_SHAS: &[[u8; 32]] = &[");
    for sha in &cache_shas {
        emit_hash_row(sha);
    }
    println!("];");
    Ok(())
}

fn emit_hash_row(bytes: &[u8; 32]) {
    print!("    [");
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(" 0x{byte:02x}");
    }
    println!("],");
}
