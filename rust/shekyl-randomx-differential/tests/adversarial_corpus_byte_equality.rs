// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! T2 — `adversarial_corpus_byte_equality`.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D6 close (test reactivation cadence): T2 reactivates
//! at C7 of the Phase 2h implementation commit plan, once the
//! recipe corpus exists (C4) and the
//! [`from_raw_for_testing`](shekyl_randomx_differential::rust_subject::RustSubjectSession::from_raw_for_testing)
//! /
//! [`from_raw_for_testing`](shekyl_randomx_differential::c_oracle::COracleSession::from_raw_for_testing)
//! accessor pair landed (C6).
//!
//! ## What T2 asserts
//!
//! For every recipe in
//! [`shekyl_randomx_differential::adversarial::get_corpus`]:
//!
//! 1. Evaluate the recipe via the first-class recipe interpreter to
//!    obtain `(seedhash, cache_bytes)`.
//! 2. Construct paired Rust and C sessions over the *same*
//!    `(seedhash, cache_bytes)` via the symmetric
//!    `from_raw_for_testing` accessors (Phase 2h R1-D2 close).
//! 3. Compute one RandomX hash on each side using a fixed
//!    deterministic data input.
//! 4. Assert byte-equality between the two sides.
//!
//! T2 is the leg-3 (rare-input coverage) byte-equality companion to
//! the Phase 2g random-corpus byte-equality assertion in
//! `mode_correctness`. Together they constitute the harness's
//! divergence-detection surface for the Phase 2h adversarial corpus.
//!
//! ## Cadence
//!
//! Per R1-D6 close Reframe 2 (cadence-corpus alignment): T2 runs
//! **per-PR** while the full corpus fits within
//! `T2_PER_PR_BUDGET_MS`. At the C4 starter-corpus size (8 recipes,
//! each ~150–200 ms Argon2d base-cache derivation + one ~25 ms
//! RandomX hash per side), the per-PR cost is a few seconds; well
//! within the per-PR runtime budget.
//!
//! If the corpus expands past the per-PR budget, the cadence policy
//! demotes T2 to a per-PR smoke subset + nightly full corpus per
//! R1-D6 close Reframe 2 — but that demotion is corpus-state-driven
//! and adjusts at policy time, not by editing this file.
//!
//! ## Active per-PR cadence (post-PR-#79 closure)
//!
//! T2 originally landed `#[ignore]`-gated behind the V3.0 verifier-
//! divergence FOLLOWUP: C7 diagnostics surfaced that the Rust
//! verifier's [`shekyl_pow_randomx::compute_hash`] diverged from the
//! C reference's `randomx_calculate_hash` for *every* `(seedhash,
//! data)` pair tested while the cache-byte SHA precondition passed —
//! a substrate-broken state, not a methodology gap.
//!
//! The FOLLOWUP closed on `dev` via
//! [PR #79](https://github.com/Shekyl-Foundation/shekyl-core/pull/79)
//! (merge commit `989610cac`, 2026-05-26). Post-merge substrate
//! triage (`tests/divergence_triage.rs` D1) identified the root
//! cause as the V1 algorithm bit being selected at
//! `randomx_create_vm` time when the surrounding substrate (Argon2d
//! cache, finalize hash) is V2-shaped; passing `RANDOMX_FLAG_V2` at
//! VM creation closes the divergence. PR #78's post-rebase commit
//! extended the same fix to
//! [`COracleSession::from_raw_for_testing`](shekyl_randomx_differential::c_oracle::COracleSession::from_raw_for_testing)
//! (the constructor T2 exercises) and lifted T2's `#[ignore]`
//! attribute as the operational close.
//!
//! Per [`21-reversion-clause-discipline.mdc`](../../../.cursor/rules/21-reversion-clause-discipline.mdc),
//! the reopening criterion for re-`#[ignore]`'ing T2 is **substrate-
//! anchored**: a regression that reintroduces post-cache
//! hash-composition divergence between
//! [`shekyl_pow_randomx::compute_hash`] and
//! `randomx_calculate_hash`. Preference-anchored re-gating ("the
//! test is slow", "fails intermittently in CI") is rejected by the
//! same rule — the test exists to surface real substrate breakage,
//! and `#[ignore]`-ing it for non-substrate reasons hides exactly
//! the failure mode it was designed to catch.
//!
//! ### R1-D6 close Reframe 1: substrate-broken vs ignore-ladder
//!
//! The pre-lift deferral was *not* the `#[ignore]`-ladder
//! anti-pattern that R1-D6 close Reframe 1 rejected for
//! corpus-availability deferrals ("test exists but ignored pending
//! a methodology decision that will eventually land"). The
//! verifier-divergence deferral was a substrate-broken deferral:
//! the substrate the test exercises (`compute_hash` ↔
//! `randomx_calculate_hash` agreement) was known-broken and the
//! FOLLOWUP's named scope was fixing it. The substrate was
//! repaired (PR #79 + this PR's post-rebase commit); the gate
//! lifted; the distinction between substrate-broken (defer
//! legitimately, lift on substrate fix) and corpus-availability
//! (anti-pattern, never defer this way) is recorded here as the
//! discipline's authoritative instance.
//!
//! ## Actionable failure semantics (R1-D6 close Reframe 3)
//!
//! On byte-equality failure the assertion message contains:
//!
//! - Recipe name (cites the rare-path target).
//! - Recipe rationale (cites the audit substrate or coverage
//!   attestation per R1-D8).
//! - Recipe category (1, 2, or 3 per R1-D8 evidence taxonomy).
//! - Seedhash (the value passed to both
//!   `from_raw_for_testing` accessors).
//! - Both sides' hash outputs, lowercase-hex.
//!
//! Per R1-D6 close: *if a test failure isn't mechanically actionable,
//! the test isn't fully implemented.* The message routes a reviewer
//! directly to the recipe + audit citation without requiring them
//! to spelunk the differential harness.

#![cfg(unix)]

use shekyl_randomx_differential::adversarial::canonical::derive_base_cache_bytes;
use shekyl_randomx_differential::adversarial::get_corpus;
use shekyl_randomx_differential::adversarial::interpreter::evaluate;
use shekyl_randomx_differential::c_oracle::COracleSession;
use shekyl_randomx_differential::mode_adversarial_ratio::{
    recipe_category, ADVERSARIAL_RATIO_DATA,
};
use shekyl_randomx_differential::rust_subject::RustSubjectSession;

/// Format a 32-byte hash as lowercase hex without separators.
///
/// Matches the canonical [`shekyl_pow_randomx::Seedhash`] display
/// shape so failure-output hashes paste directly into the
/// `--seedhash=<hex>` argument of any future diagnostic harness
/// invocation; same convention as
/// [`shekyl_randomx_differential::corpus_random`]'s hex helpers.
fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[test]
fn t2_adversarial_corpus_byte_equality() {
    let corpus = get_corpus();
    assert!(
        !corpus.is_empty(),
        "T2 requires a non-empty adversarial corpus; \
         get_corpus() returned 0 recipes. The Phase 2h C4 starter \
         corpus must be populated for T2 to assert anything."
    );

    // Base-cache amortization keyed by `recipe.base.bytes`, mirroring
    // the pattern in `mode_adversarial_ratio::run` (per the
    // adversarial-ratio binary's `base_cache_cache` comment). The C4
    // starter corpus has 3 unique base byte patterns across 8
    // recipes; without amortization T2 pays the ~10s Argon2d-fill +
    // 256-MiB allocation cost 8 times (~80s + 2 GiB peak) instead of
    // 3 times (~30s + 768 MiB peak). The Vec<(key, bytes)> shape
    // matches the binary's identical structure for grep-ability;
    // when a third consumer emerges this lifts to a shared helper.
    let mut base_cache_cache: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    for recipe in &corpus {
        let base_bytes = match base_cache_cache
            .iter()
            .find(|(key, _)| key == &recipe.base.bytes)
        {
            Some((_, bytes)) => bytes,
            None => {
                let new_bytes = derive_base_cache_bytes(&recipe.base);
                base_cache_cache.push((recipe.base.bytes, new_bytes));
                &base_cache_cache
                    .last()
                    .expect("base_cache_cache non-empty after push")
                    .1
            }
        };
        let evaluated = evaluate(recipe, base_bytes);
        let category = recipe_category(recipe);

        let rust =
            RustSubjectSession::from_raw_for_testing(evaluated.seedhash, &evaluated.cache_bytes);
        let c = COracleSession::from_raw_for_testing(evaluated.seedhash, &evaluated.cache_bytes)
            .unwrap_or_else(|err| {
                panic!(
                    "T2: failed to construct C oracle session for recipe `{name}` \
                     (category {category}); error: {err}. The C-side allocator failed \
                     before the byte-equality assertion could run; this is a \
                     C-oracle-setup substrate finding, not a Rust/C divergence.",
                    name = recipe.name,
                )
            });

        let rust_hash = rust.compute_hash(&ADVERSARIAL_RATIO_DATA);
        let c_hash = c.calculate_hash(&ADVERSARIAL_RATIO_DATA);

        assert_eq!(
            rust_hash,
            c_hash,
            "T2: Rust/C byte-equality divergence on recipe `{name}` \
             (category {category}).\n\
             rationale: {rationale}\n\
             seedhash:  {seedhash}\n\
             rust_hash: {rust_hex}\n\
             c_hash:    {c_hex}\n\
             data: ADVERSARIAL_RATIO_DATA (mode_adversarial_ratio.rs)\n\
             The recipe's `from_raw_for_testing`-injected cache bytes \
             produce divergent hashes between the Rust verifier and \
             the C reference. Per R1-D8 evidence-category {category}: \
             investigate via the recipe's rationale citation; if the \
             divergence is a true verifier finding, file an audit \
             follow-up under the M5 citation-validation discipline.",
            name = recipe.name,
            category = category,
            rationale = recipe.rationale,
            seedhash = hex_lower(evaluated.seedhash.as_bytes()),
            rust_hex = hex_lower(&rust_hash),
            c_hex = hex_lower(&c_hash),
        );
    }
}
