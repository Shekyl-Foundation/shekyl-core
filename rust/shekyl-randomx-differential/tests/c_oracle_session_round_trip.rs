// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! T17 — `c_oracle_session_round_trip_equivalence`.
//!
//! Asserts functional equivalence between
//! [`COracleSession::new(seedhash)`] and
//! [`COracleSession::from_raw_for_testing(seedhash, cache_bytes)`]
//! when `cache_bytes` is the live cache memory of a fresh
//! `new(seedhash)` session. Two equivalence-class properties are
//! verified:
//!
//! 1. **Cache-byte parity.** The two sessions' cache memory regions
//!    hash to the same SHA-256 (sanity: `from_raw_for_testing`'s
//!    `copy_nonoverlapping` faithfully reproduces `new`'s
//!    Argon2d-derived 256-MiB cache).
//! 2. **Hash parity.** For a fixed payload, both sessions'
//!    `calculate_hash` outputs are byte-identical (the load-bearing
//!    assertion).
//!
//! ## Why this test exists (the substrate context)
//!
//! `from_raw_for_testing` is a new unsafe-heavy path introduced at
//! Phase 2h C2 (allocate → init_cache → overwrite cache memory →
//! create_vm), parallel to `new`'s production allocate → init_cache
//! → create_vm path. The two paths can drift in any FFI parameter
//! (cache allocation flag, `init_cache` invocation shape, VM
//! creation flag) without compilation breaking, because each
//! parameter is locally consistent at its callsite.
//!
//! The PR-#78 R3-F4 review surfaced exactly this drift before this
//! test existed:
//! [`#79`](https://github.com/Shekyl-Foundation/shekyl-core/pull/79)
//! landed `RANDOMX_FLAG_V2` at `new`'s `randomx_create_vm` callsite
//! (closing the V3.0 verifier-divergence FOLLOWUP), but PR #78's
//! `from_raw_for_testing` was branched pre-PR-#79 and still used
//! `RANDOMX_FLAG_DEFAULT` (V1 algorithm) at its `randomx_create_vm`
//! callsite. The two callsites were each locally consistent but
//! mutually divergent; the failure mode would have surfaced only at
//! runtime as a hash mismatch in T2 / T6, with no compile-time guard.
//!
//! Per [`21-reversion-clause-discipline.mdc`](../../../.cursor/rules/21-reversion-clause-discipline.mdc),
//! this test is the structural reopening criterion for any future
//! flag-drift between the two constructors: if a future commit
//! desynchronizes either site's flag choice from the canonical shape
//! documented in `c_oracle.rs` (`## Flags` section), the hash parity
//! assertion below diverges by exactly the algorithm-version bit and
//! surfaces the drift loudly. The reopening trigger is mechanical
//! (the test runs in the `--ignored` runtime-test cohort whenever
//! the harness is exercised against `RANDOMX_V2_INSTALL_DIR`); the
//! re-evaluation shape is the round-trip's `assert_eq!` failure with
//! a diagnostic message naming the most-likely-cause flag-drift.
//!
//! ## Why not run by default
//!
//! Each session does a ~10 s Argon2d-512 cache derivation; the test
//! runs two of them sequentially for a total ~20 s and ~512 MiB peak
//! resident memory (both sessions hold their 256-MiB cache regions
//! concurrently for the parity assertions). The test also requires
//! the harness's `librandomx.a` substrate at `RANDOMX_V2_INSTALL_DIR`.
//! `#[ignore]` is the same operational gating shape used by
//! `t16_substrate_triage_three_way_byte_equality` (`divergence_triage.rs`)
//! and T2 / T6 (`adversarial_corpus_byte_equality.rs` /
//! `worst_case_ratio.rs`).
//!
//! ## How to invoke
//!
//! ```bash
//! RANDOMX_V2_INSTALL_DIR=<install-prefix> \
//!   cargo test --release --locked \
//!     -p shekyl-randomx-differential \
//!     --test c_oracle_session_round_trip \
//!     -- --ignored --nocapture
//! ```
//!
//! `--nocapture` is required to surface the diagnostic hash bytes
//! regardless of pass/fail outcome — they are the diagnostic
//! deliverable when the assertion fires.

use shekyl_pow_randomx::Seedhash;
use shekyl_randomx_differential::c_oracle::COracleSession;

/// Fixed seedhash for deterministic test execution. Distinct from
/// `divergence_triage.rs`'s `CANONICAL_SEEDHASH_BYTES` and from any
/// adversarial-corpus seedhash to keep this test's diagnostic output
/// independent of other tests' failure modes — a regression at one
/// substrate surface should not cascade into another test's output.
const ROUND_TRIP_SEEDHASH_BYTES: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
];

/// Fixed 32-byte payload for the `calculate_hash` parity assertion.
/// Length matches the adversarial-corpus `ADVERSARIAL_RATIO_DATA`
/// shape (32 bytes) to keep the test's hash-domain coverage
/// consistent with T2's payload size; the exact byte content is
/// arbitrary as long as it is fixed (deterministic) across runs.
const ROUND_TRIP_PAYLOAD: &[u8; 32] = b"shekyl-c_oracle-round-trip-test\n";

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to String cannot fail");
    }
    s
}

#[test]
#[ignore = "round-trip parity: two ~10s Argon2d-512 derivations + FFI; \
            requires RANDOMX_V2_INSTALL_DIR. Run with \
            `cargo test --ignored c_oracle_session_round_trip -- --nocapture`."]
fn t17_c_oracle_session_round_trip_equivalence() {
    let seedhash = Seedhash::from_bytes(ROUND_TRIP_SEEDHASH_BYTES);

    // Session A: production path (`new`). Argon2d-derives the cache
    // memory from `seedhash` and creates a V2-flagged VM bound to it.
    let session_a = COracleSession::new(seedhash).expect("COracleSession::new failed");

    // Session B: test-internals path (`from_raw_for_testing`). Takes
    // session A's just-derived cache bytes directly as the seed for
    // the overwrite, so the two sessions are post-construction
    // equivalent by construction — the cache bytes are byte-identical
    // by construction; any divergence beyond that point pins a
    // non-cache parameter (init_cache invocation, VM creation flag,
    // VM cache-binding semantics). `session_a` outlives this call;
    // `from_raw_for_testing` internally `copy_nonoverlapping`s the
    // cache bytes into its own owned 256-MiB region, so the borrow
    // is bounded by the call duration.
    let session_b = COracleSession::from_raw_for_testing(seedhash, session_a.cache_bytes())
        .expect("COracleSession::from_raw_for_testing failed");

    let cache_sha_a = session_a.cache_sha256();
    let cache_sha_b = session_b.cache_sha256();
    let hash_a = session_a.calculate_hash(ROUND_TRIP_PAYLOAD);
    let hash_b = session_b.calculate_hash(ROUND_TRIP_PAYLOAD);

    eprintln!();
    eprintln!("=== T17 c_oracle session round-trip equivalence ===");
    eprintln!("seedhash      : {}", hex_lower(seedhash.as_bytes()));
    eprintln!("payload (32B) : {}", hex_lower(ROUND_TRIP_PAYLOAD));
    eprintln!("cache_sha A   : {}", hex_lower(&cache_sha_a));
    eprintln!("cache_sha B   : {}", hex_lower(&cache_sha_b));
    eprintln!("hash A        : {}", hex_lower(&hash_a));
    eprintln!("hash B        : {}", hex_lower(&hash_b));
    eprintln!();

    // Cache-byte parity (sanity): `from_raw_for_testing` fed
    // session A's own cache bytes must reproduce A's cache memory.
    // A divergence here pins a `copy_nonoverlapping` / cache-binding
    // bug in `from_raw_for_testing`, independent of any VM-creation
    // parameter.
    assert_eq!(
        cache_sha_a, cache_sha_b,
        "T17 cache-byte parity violated: from_raw_for_testing did not faithfully reproduce new's cache memory. \
         This points at a `copy_nonoverlapping` size mismatch, an `init_cache` ordering bug, or a `randomx_get_cache_memory` lifecycle issue \
         in `from_raw_for_testing` — not at a VM-creation flag issue.",
    );

    // Hash parity (the load-bearing assertion): both sessions must
    // execute the same algorithm version against the (now-confirmed-
    // equivalent) cache state. A divergence here, given cache parity
    // above, pins flag-drift between the `randomx_create_vm`
    // callsites in `new` vs. `from_raw_for_testing`. This is the
    // exact failure mode that produced R3-F4 (PR #78) before this
    // test existed; the test is the structural backstop against
    // future recurrences of the same pattern.
    assert_eq!(
        hash_a, hash_b,
        "T17 hash parity violated (with cache parity passing): new and from_raw_for_testing produce different hashes \
         for the same (seedhash, payload). Most likely cause: flag-drift between the two sites' `randomx_create_vm` callsites \
         (e.g., one site uses RANDOMX_FLAG_V2 selecting the v2 algorithm, the other RANDOMX_FLAG_DEFAULT selecting v1). \
         See `c_oracle.rs` module docs (`## Flags` section) for the canonical flag-choice shape that both constructors must mirror.",
    );
}
