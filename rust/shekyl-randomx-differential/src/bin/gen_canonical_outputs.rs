// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical-output generator binary for the Phase 2g differential
//! test harness (§5.2.6 + R4-D7 + §3.18 R6-D4) — extended at
//! Phase 2h C5 to also emit the Family-1 adversarial canonicals
//! (R1-D4 close + R2-D1 attack-class split close).
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
//! ## Phase 2h C5 extension: Family-1 adversarial canonicals
//!
//! Per `docs/design/RANDOMX_V2_PHASE2H_PLAN.md` R1-D4 close, the
//! binary is extended (not duplicated) to also emit the contents
//! of [`adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`].
//! The `--include-family-1` flag enables the extension; when
//! present, the binary additionally:
//!
//! 1. Reads
//!    [`shekyl_randomx_differential::adversarial::get_corpus()`].
//! 2. For each unique base seedhash in the corpus, allocates a C
//!    cache via `randomx_alloc_cache` + `randomx_init_cache` and
//!    reads back the 256-MiB cache memory via
//!    `randomx_get_cache_memory`.
//! 3. For each recipe, applies the recipe's modifications to the
//!    base cache bytes via
//!    [`shekyl_randomx_differential::adversarial::interpreter::evaluate`].
//! 4. Computes the SHA-256 of the evaluated bytes per R1-D4's
//!    expanded-bytes-SHA discipline.
//! 5. Emits the resulting `[u8; 32]` array as the body of
//!    `FAMILY_1_RECIPE_OUTPUTS` + the per-array meta-SHA as
//!    `FAMILY_1_RECIPE_SHA256`.
//!
//! The C-reference path is the **independent-substrate
//! regeneration** path per
//! [`adversarial::canonical`](../adversarial/canonical.rs)'s
//! module-doc rationale: the Rust-subject path (used at C5 initial
//! population) and the C-reference path here are
//! cache-equivalent-precondition-guaranteed to produce the same
//! canonical bytes; the binary's independent path catches
//! Rust-side bugs in `PreparedCache::derive` that the cache-
//! equivalence precondition might mask.
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
    RANDOMX_FLAG_V2,
};
use sha2::{Digest, Sha256};
use shekyl_pow_randomx::Seedhash;
use shekyl_randomx_differential::adversarial::{
    get_corpus, interpreter::evaluate, types::BaseSeedhash,
};
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
    let mut include_family_1: bool = false;
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
        } else if arg == "--include-family-1" {
            include_family_1 = true;
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
    if let Err(msg) = generate(&corpus) {
        eprintln!("error: {msg}");
        return ExitCode::FAILURE;
    }
    if include_family_1 {
        eprintln!("gen-canonical-outputs: generating Family-1 adversarial canonicals");
        if let Err(msg) = generate_family_1() {
            eprintln!("error: family-1 generation failed: {msg}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
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
             --include-family-1                      Also emit Phase 2h\n  \
                                                     Family-1 adversarial\n  \
                                                     canonicals\n  \
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
        //
        // Flag selection (per verifier-divergence FOLLOWUP closure):
        // cache allocation passes RANDOMX_FLAG_DEFAULT (V2 bit is
        // masked at alloc per `randomx.cpp:79`, so it'd be inert);
        // VM creation passes RANDOMX_FLAG_V2 to select the v2
        // algorithm — without this, the generator would emit C-v1
        // hashes and pin Rust-v2 against them, the original divergence.
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

            let vm = randomx_create_vm(RANDOMX_FLAG_V2, cache, ptr::null_mut());
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

/// Generate the Phase 2h C5 Family-1 adversarial canonical-output
/// array via the C reference's `randomx_get_cache_memory` for each
/// recipe's base seedhash, applying the recipe's modifications,
/// and computing the SHA-256 of the evaluated bytes.
///
/// Output shape mirrors the
/// [`adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`]
/// array body — one `[u8; 32]` row per recipe in
/// [`get_corpus`]'s emission order, with a per-recipe inline
/// comment carrying the recipe name + a rationale excerpt. The
/// per-array meta-SHA (matching
/// [`adversarial_canonical_outputs::FAMILY_1_RECIPE_SHA256`]) is
/// emitted after the array body.
fn generate_family_1() -> Result<(), String> {
    let corpus = get_corpus();
    eprintln!(
        "  Family-1 corpus size: {} recipes (R1-D4 close discipline)",
        corpus.len()
    );

    // Dedup base seedhashes — each unique base requires one C
    // cache allocation/init/release cycle. The C4 starter corpus
    // has 3 unique bases across 8 recipes per the
    // adversarial::recipes module's bases (all-0x42, all-zeros,
    // all-0x01).
    let mut unique_bases: Vec<BaseSeedhash> = Vec::new();
    for recipe in &corpus {
        if !unique_bases.iter().any(|b| b.bytes == recipe.base.bytes) {
            unique_bases.push(recipe.base);
        }
    }
    eprintln!(
        "  Family-1 unique base seedhashes: {} (amortized across {} recipes)",
        unique_bases.len(),
        corpus.len()
    );

    // Derive each unique base's 256-MiB cache bytes via the C
    // reference (independent-substrate path per the module-doc
    // rationale). Stored as Vec<u8> for the recipe evaluator to
    // consume.
    let mut base_caches: Vec<(BaseSeedhash, Vec<u8>)> = Vec::with_capacity(unique_bases.len());
    for (i, base) in unique_bases.iter().enumerate() {
        eprintln!(
            "    base {}/{} ({}): deriving via C reference",
            i + 1,
            unique_bases.len(),
            base.name
        );
        let seedhash = Seedhash::from_bytes(base.bytes);
        let seedhash_bytes = seedhash.as_bytes();
        // SAFETY: the FFI lifecycle mirrors generate()'s pattern;
        // randomx_alloc_cache + randomx_init_cache + read via
        // randomx_get_cache_memory + randomx_release_cache. NULL
        // checks on alloc returns.
        let bytes = unsafe {
            let cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
            if cache.is_null() {
                return Err(format!(
                    "randomx_alloc_cache returned NULL for base seedhash {} ({})",
                    base.name, seedhash
                ));
            }
            randomx_init_cache(
                cache,
                seedhash_bytes.as_ptr().cast::<c_void>(),
                seedhash_bytes.len(),
            );
            let cache_mem = randomx_get_cache_memory(cache);
            if cache_mem.is_null() {
                randomx_release_cache(cache);
                return Err(format!(
                    "randomx_get_cache_memory returned NULL for base seedhash {} ({})",
                    base.name, seedhash
                ));
            }
            let slice =
                std::slice::from_raw_parts(cache_mem.cast::<u8>(), RANDOMX_CACHE_SIZE_BYTES);
            let owned = slice.to_vec();
            randomx_release_cache(cache);
            owned
        };
        base_caches.push((*base, bytes));
    }

    println!();
    println!("// Phase 2h C5 Family-1 adversarial canonicals — paste body into");
    println!("// adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS.");
    println!("#[rustfmt::skip]");
    println!("pub const FAMILY_1_RECIPE_OUTPUTS: &[[u8; 32]] = &[");

    let mut canonicals: Vec<[u8; 32]> = Vec::with_capacity(corpus.len());
    for (recipe_idx, recipe) in corpus.iter().enumerate() {
        let base_bytes = &base_caches
            .iter()
            .find(|(b, _)| b.bytes == recipe.base.bytes)
            .expect("base cache for recipe was derived above")
            .1;
        let evaluated = evaluate(recipe, base_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&evaluated.cache_bytes);
        let canonical: [u8; 32] = hasher.finalize().into();
        canonicals.push(canonical);

        // UTF-8-safe truncation: `&recipe.rationale[..60]` would
        // panic if byte index 60 falls inside a multi-byte char (any
        // non-ASCII content in a future rationale). `chars().take(N)`
        // truncates on char-boundaries by construction. The 60-char
        // bound is the human-readability comment-width pin; the unit
        // is chars (visible glyphs for ASCII; codepoints for non-
        // ASCII), not bytes.
        const RATIONALE_EXCERPT_CHARS: usize = 60;
        let rationale_excerpt = if recipe.rationale.chars().count() > RATIONALE_EXCERPT_CHARS {
            let truncated: String = recipe
                .rationale
                .chars()
                .take(RATIONALE_EXCERPT_CHARS)
                .collect();
            format!("{truncated}…")
        } else {
            recipe.rationale.to_string()
        };
        println!(
            "    // recipe[{recipe_idx}]: {} — {rationale_excerpt}",
            recipe.name
        );
        emit_hash_row(&canonical);
    }
    println!("];");

    // Emit the per-array meta-SHA.
    let mut meta_hasher = Sha256::new();
    for canonical in &canonicals {
        meta_hasher.update(canonical);
    }
    let meta: [u8; 32] = meta_hasher.finalize().into();
    println!();
    println!("// FAMILY_1_RECIPE_SHA256 meta-pin (SHA-256 of array contents).");
    println!("pub const FAMILY_1_RECIPE_SHA256: [u8; 32] = [");
    print!("    ");
    for (i, byte) in meta.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{byte:02x}");
    }
    println!(",");
    println!("];");

    Ok(())
}
