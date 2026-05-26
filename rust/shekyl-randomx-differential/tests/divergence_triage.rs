// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D1 substrate triage for the universal-divergence FOLLOWUP.
//!
//! Per the interim-branch plan recorded against
//! `arbeit/randomx-v2-compute-hash-divergence-diagnostic`, D1's
//! goal is to determine whether the `t16` (seedhash, data) pair
//! from
//! `shekyl-pow-randomx::vm::tests::t16_vm_compute_hash_real_matches_fork_reference`
//! agrees Rust-subject ↔ C-oracle ↔ static-fixture *under the
//! Phase 2g differential harness's substrate* — i.e., when the
//! C reference is the harness's separately-built `librandomx.a`
//! at the submodule pin (verified at branch-open as
//! `aaafe71322df6602c21a5c72937ac284724ae561`, matching the t16
//! fixture's "fork pin `aaafe71`").
//!
//! ## Three possible outcomes
//!
//! - **(A) Three-way agreement.** All three values (Rust-subject
//!   `compute_hash`, C-oracle `calculate_hash`, static fixture)
//!   are byte-identical. This confirms the V3.0 FOLLOWUP
//!   characterization: the t16 fixture *is* current with the
//!   harness's C reference, and the universal-divergence surface
//!   engages on inputs *other than* the canonical (seedhash, data)
//!   pair. D2 (checkpoint instrumentation) becomes the next step.
//!
//! - **(B) Rust agrees with fixture but disagrees with C oracle.**
//!   The fixture is stale relative to the harness's `librandomx.a`
//!   build even though both name the same fork pin. Likely
//!   surface: build-time configuration drift (compile flags,
//!   feature defaults, JIT enablement) makes the two C-side
//!   binaries semantically non-equivalent. Reshapes the
//!   investigation toward the C-build-config delta rather than
//!   the Rust VM.
//!
//! - **(C) Other (no two agree, or unexpected pattern).** Record
//!   exact bytes for analysis; the divergence story is more
//!   complex than either of the above hypotheses.
//!
//! ## How to invoke
//!
//! The test is `#[ignore]`'d because it derives a 256-MiB
//! Argon2d-512 cache (~10–30 s on `ubuntu-latest`-class
//! hardware) and links against the C reference (requires
//! `RANDOMX_V2_INSTALL_DIR` to be set per the harness build
//! contract). Run with:
//!
//! ```bash
//! RANDOMX_V2_INSTALL_DIR=<install-prefix> \
//!   cargo test --release --locked \
//!     -p shekyl-randomx-differential \
//!     --test divergence_triage \
//!     -- --ignored --nocapture
//! ```
//!
//! `--nocapture` is required to surface the hash bytes regardless
//! of pass/fail outcome — the bytes themselves are the D1
//! deliverable.

use shekyl_pow_randomx::Seedhash;
use shekyl_randomx_differential::c_oracle::COracleSession;
use shekyl_randomx_differential::rust_subject::RustSubjectSession;

/// Mirror of `shekyl-pow-randomx::vm::tests::CANONICAL_SEEDHASH_BYTES`
/// at `rust/shekyl-pow-randomx/src/vm.rs:3158`. Re-declared here
/// because the source is `mod tests` (test-only, not re-exported);
/// the byte values are pinned by the t16 fixture's provenance and
/// the constant is treated as substrate by the diagnostic.
const CANONICAL_SEEDHASH_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Mirror of `shekyl-pow-randomx::vm::tests::T8_DATA_INPUT` at
/// `rust/shekyl-pow-randomx/src/vm.rs:3465`. 192 bytes per the
/// `t8_data_input_is_192_bytes` invariant. Re-declared here for
/// the same reason as `CANONICAL_SEEDHASH_BYTES`.
const T8_DATA_INPUT: &[u8] = b"phase2c-t8-end-to-end-stub-nop-hash-canonical-data-input-padding-to-256-bytes-so-the-blake2b-input-spans-multiple-blocks-and-the-fillaes1rx4-scratchpad-init-consumes-a-non-trivial-seed.....END";

/// Static fixture from
/// `shekyl-pow-randomx::vm::tests::t16_vm_compute_hash_real_matches_fork_reference`
/// at `rust/shekyl-pow-randomx/src/vm.rs:3497`. The 32-byte
/// expected output of `compute_hash(canonical_prepared_cache,
/// T8_DATA_INPUT)` per the t16 provenance meta file.
const T16_FIXTURE: &[u8; 32] = include_bytes!(
    "../../shekyl-pow-randomx/tests/vectors/reference/vm/t16_vm_compute_hash_real.bin"
);

/// Lowercase hex without separators, matching the harness's
/// `hex_lower` utility shape so diagnostic output is grep-able
/// against existing canonical-output records.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to String cannot fail");
    }
    s
}

#[test]
#[ignore = "D1 substrate triage: derives a 256-MiB Argon2d-512 cache \
            (~10-30s on ubuntu-latest); requires RANDOMX_V2_INSTALL_DIR. \
            Run with `cargo test --ignored t16_substrate_triage -- --nocapture`."]
fn t16_substrate_triage_three_way_byte_equality() {
    assert_eq!(
        T8_DATA_INPUT.len(),
        192,
        "T8 data invariant locked at 192 B"
    );
    assert_eq!(
        T16_FIXTURE.len(),
        32,
        "t16 fixture invariant locked at 32 B"
    );

    let seedhash = Seedhash::from_bytes(CANONICAL_SEEDHASH_BYTES);
    let rust = RustSubjectSession::derive(seedhash);
    let c = COracleSession::new(seedhash).expect("C oracle allocation");

    let rust_hash = rust.compute_hash(T8_DATA_INPUT);
    let c_hash = c.calculate_hash(T8_DATA_INPUT);

    eprintln!();
    eprintln!("=== D1 substrate triage three-way byte-equality ===");
    eprintln!("seedhash       : {}", hex_lower(seedhash.as_bytes()));
    eprintln!("data len       : {}", T8_DATA_INPUT.len());
    eprintln!("rust_hash      : {}", hex_lower(&rust_hash));
    eprintln!("c_hash         : {}", hex_lower(&c_hash));
    eprintln!("t16 fixture    : {}", hex_lower(T16_FIXTURE));
    eprintln!();

    let rust_eq_c = rust_hash == c_hash;
    let rust_eq_fix = &rust_hash == T16_FIXTURE;
    let c_eq_fix = &c_hash == T16_FIXTURE;

    eprintln!("rust == c       : {rust_eq_c}");
    eprintln!("rust == fixture : {rust_eq_fix}");
    eprintln!("c == fixture    : {c_eq_fix}");
    eprintln!();

    let outcome = match (rust_eq_c, rust_eq_fix, c_eq_fix) {
        (true, true, true) => "A: three-way agreement (fixture current; universal-divergence surface engages elsewhere)",
        (false, true, false) => "B: rust agrees with fixture; C oracle diverges (fixture stale vs. harness librandomx.a)",
        (false, false, true) => "B': C oracle agrees with fixture; Rust diverges (Rust VM is the surface)",
        (true, false, false) => "C: rust == c but neither matches fixture (fixture stale, both implementations converged elsewhere)",
        _ => "C: unexpected pattern; see bytes above",
    };
    eprintln!("D1 outcome      : {outcome}");
    eprintln!();

    assert!(
        rust_eq_c && rust_eq_fix && c_eq_fix,
        "D1 substrate triage: outcome was \"{outcome}\"; \
         three-way agreement required for outcome A. \
         rust_eq_c={rust_eq_c}, rust_eq_fix={rust_eq_fix}, c_eq_fix={c_eq_fix}. \
         Hash bytes are in the eprintln! output above (re-run with `-- --nocapture`).",
    );
}
