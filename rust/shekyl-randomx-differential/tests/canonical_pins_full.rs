// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Full 1024-pin re-check of the Rust verifier against the committed
//! canonical table — the pin vehicle for the native-aarch64 CI lane
//! (RandomX v2 test-regime hardening PR-2 / audit item F5).
//!
//! ## What this asserts, and why it exists
//!
//! For every `(seedhash, data)` pair in the nightly random corpus
//! (32 seedhashes × 32 blobs, §5.1.5 + R1-D4), the verifier's
//! [`RustSubjectSession::compute_hash`] must reproduce
//! [`CANONICAL_RANDOM_HASHES`] exactly. This is the **Rust-vs-canonical
//! leg only** — no C oracle — which makes it runnable anywhere `cargo`
//! runs, including the `ubuntu-24.04-arm` lane where it is the first CI
//! execution the `fpu_rounding` FPCR path has ever had (every RandomX
//! program flips rounding modes via `CFROUND`, so walking all 1024 pins
//! exercises the mode-encoding swap on real silicon, not qemu softfloat,
//! which would mask a genuine FP-rounding divergence). The full
//! three-leg runtime differential (`--mode=correctness`) remains the
//! runtime-mode wiring change's scope; this test is the arch-portable
//! pin floor beneath it.
//!
//! ## Triage posture (decided in advance, per the F5 finding)
//!
//! A mismatch on the aarch64 lane is a plausible REAL consensus finding
//! — the two shipping arches disagreeing on a consensus hash — not lane
//! flakiness: treat it as halt-and-escalate
//! (`RANDOMX_V2_PHASE3_PLAN.md` §7.3 discipline), starting with the
//! rounding-mode encoding (`fpu_rounding.rs`: modes 1 and 2 swap
//! between the x86 MXCSR and AArch64 FPCR encodings).
//!
//! ## Cadence
//!
//! Release-mode only, as a dedicated workflow step (the T2 house
//! pattern): 1024 interpreted light hashes are minutes in release and
//! hours in debug, so the default debug `cargo test` step skips this
//! test by name (`--skip canonical_pins_full_rust_leg`). The
//! `--no-tests=error`-style guard here is the assert on the corpus
//! sizing itself: if the nightly sizing or the pin table ever change
//! shape, this test fails loudly rather than walking a subset.

use std::thread;

use shekyl_randomx_differential::canonical_outputs::CANONICAL_RANDOM_HASHES;
use shekyl_randomx_differential::corpus_random::{
    generate_random_corpus, NIGHTLY_DATA_PER_SEEDHASH, NIGHTLY_SEEDHASH_COUNT,
};
use shekyl_randomx_differential::rust_subject::RustSubjectSession;

/// Upper bound on concurrent workers: each worker holds one derived
/// light cache (~256 MiB), so 4 workers bound peak cache memory at
/// ~1 GiB — comfortable on the 16 GB CI runners while still cutting
/// the wall clock by ~4× over a serial walk.
const MAX_WORKERS: usize = 4;

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("String write cannot fail");
    }
    s
}

#[test]
fn canonical_pins_full_rust_leg() {
    let corpus = generate_random_corpus(NIGHTLY_SEEDHASH_COUNT, NIGHTLY_DATA_PER_SEEDHASH);
    assert_eq!(
        corpus.len(),
        CANONICAL_RANDOM_HASHES.len(),
        "nightly corpus size and canonical-pin table size diverged"
    );
    assert_eq!(
        corpus.len(),
        NIGHTLY_SEEDHASH_COUNT * NIGHTLY_DATA_PER_SEEDHASH,
        "corpus generator emitted an unexpected pair count"
    );

    let workers = MAX_WORKERS
        .min(thread::available_parallelism().map_or(1, usize::from))
        .max(1);

    // Seed-major corpus: group g covers flat indices
    // [g * NIGHTLY_DATA_PER_SEEDHASH, (g + 1) * NIGHTLY_DATA_PER_SEEDHASH).
    // Workers take strided groups so each derives ~equal cache counts.
    let mismatches: Vec<String> = thread::scope(|scope| {
        let corpus = &corpus;
        let mut handles = Vec::with_capacity(workers);
        for w in 0..workers {
            handles.push(scope.spawn(move || {
                let mut bad = Vec::new();
                for group in (w..NIGHTLY_SEEDHASH_COUNT).step_by(workers) {
                    let base = group * NIGHTLY_DATA_PER_SEEDHASH;
                    let session = RustSubjectSession::derive(corpus[base].seedhash);
                    for j in 0..NIGHTLY_DATA_PER_SEEDHASH {
                        let flat = base + j;
                        let got = session.compute_hash(&corpus[flat].data);
                        if got != CANONICAL_RANDOM_HASHES[flat] {
                            bad.push(format!(
                                "pin {flat} (seed group {group}, blob {j}): got {} expected {}",
                                hex_lower(&got),
                                hex_lower(&CANONICAL_RANDOM_HASHES[flat]),
                            ));
                        }
                    }
                }
                bad
            }));
        }
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("pin worker panicked"))
            .collect()
    });

    assert!(
        mismatches.is_empty(),
        "{} of {} canonical pins diverged on {} — a consensus-hash divergence \
         between the verifier and the committed pins; treat as HALT-AND-ESCALATE \
         (see this file's triage-posture doc), starting with fpu_rounding.rs \
         mode encoding:\n{}",
        mismatches.len(),
        CANONICAL_RANDOM_HASHES.len(),
        std::env::consts::ARCH,
        mismatches.join("\n"),
    );
}
