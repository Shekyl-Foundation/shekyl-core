// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Three-way byte-equality regression guard for the V3.0 canonical
//! `(seedhash, data)` pair (post-PR-#79 closure).
//!
//! ## Present-tense role
//!
//! The test asserts that all three RandomX-v2 substrate layers agree
//! byte-for-byte on the canonical
//! `(CANONICAL_SEEDHASH_BYTES, T8_DATA_INPUT)` input:
//!
//! 1. Rust subject ([`RustSubjectSession::compute_hash`]).
//! 2. C oracle ([`COracleSession::compute_hash`], the harness's
//!    separately-built `librandomx.a` at the submodule pin).
//! 3. Static fixture (`t16_vm_compute_hash_real.bin` — the bytes
//!    that pinned the V3.0 verifier-correctness expectation).
//!
//! A pass means the three-layer chain is intact at the canonical
//! input. A failure identifies *which* layer regressed: the
//! `--nocapture` output prints each layer's hash bytes so the
//! offending pair is mechanically visible, and the panic message
//! names the disagreement class (Rust↔C, Rust↔fixture, C↔fixture).
//!
//! ## Historical context (D1 substrate triage)
//!
//! The test was originally written as the D1 substrate triage tool
//! for the V3.0 verifier-divergence FOLLOWUP, distinguishing three
//! candidate hypotheses for the universal Rust↔C disagreement:
//! (A) three-way agreement (Rust↔C↔fixture), (B) fixture-vs-C-build
//! drift, (C) other. Outcome (A) was confirmed at D1; D2 instrumented
//! the checkpoint chain to identify *which* `compute_hash` substep
//! diverged on non-canonical inputs; that diagnosis ended with
//! [PR #79](https://github.com/Shekyl-Foundation/shekyl-core/pull/79)
//! (`989610cac`, 2026-05-26), which closed the FOLLOWUP by passing
//! `RANDOMX_FLAG_V2` at `randomx_create_vm` time. PR #78's post-
//! rebase commit (`c71ce2413`) extended the same fix to
//! [`COracleSession::from_raw_for_testing`](shekyl_randomx_differential::c_oracle::COracleSession::from_raw_for_testing)
//! and added T17 (`tests/c_oracle_session_round_trip.rs`) as the
//! constructor-equivalence backstop.
//!
//! The investigation tool now serves as a regression guard: the
//! three-way agreement that confirmed at D1 is the invariant the
//! test asserts forward. The reopening criterion per
//! [`21-reversion-clause-discipline.mdc`](../../../.cursor/rules/21-reversion-clause-discipline.mdc)
//! is substrate-anchored: a regression that re-introduces
//! divergence at the canonical input fails this test fast and points
//! the next diagnostic at the offending layer.
//!
//! ## Why still `#[ignore]`'d
//!
//! The test derives a 256-MiB Argon2d-512 cache (~10-30 s on
//! `ubuntu-latest`-class hardware) and links against the C reference
//! (requires `RANDOMX_V2_INSTALL_DIR` to be set per the harness
//! build contract). The `#[ignore]` gate persists for runtime-cost
//! reasons unrelated to the now-closed FOLLOWUP; T17's lighter-
//! weight round-trip backstop (~negligible after base-cache
//! amortization) carries the per-PR cadence load for constructor
//! equivalence. T16 stays manually-invoked / nightly:
//!
//! ```bash
//! RANDOMX_V2_INSTALL_DIR=<install-prefix> \
//!   cargo test --release --locked \
//!     -p shekyl-randomx-differential \
//!     --test divergence_triage \
//!     -- --ignored --nocapture
//! ```
//!
//! `--nocapture` is required to surface the per-layer hash bytes
//! regardless of pass/fail outcome — the bytes themselves are the
//! diagnostic deliverable on a regression.

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
#[ignore = "T16 three-way byte-equality regression guard (Rust↔C↔fixture at \
            canonical input): derives a 256-MiB Argon2d-512 cache \
            (~10-30s on ubuntu-latest), requires RANDOMX_V2_INSTALL_DIR. \
            Runtime-cost gated only; the post-PR-#79 FOLLOWUP-gating is lifted. \
            Run with `cargo test --release --ignored t16_substrate_triage -- --nocapture`."]
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
