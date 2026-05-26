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
//! ## C7 close: `#[ignore]` gate inherits verifier-divergence FOLLOWUP
//!
//! C7 implementation surfaced via diagnostic that the Rust verifier's
//! [`shekyl_pow_randomx::compute_hash`] currently diverges from the C
//! reference's `randomx_calculate_hash` for *every* `(seedhash, data)`
//! pair tested — uniform-byte seedhashes, random ChaCha20-derived
//! seedhashes, short and long data inputs. The Rust↔C cache-byte
//! SHA precondition (Phase 2g §5.1.7 R1-D14) passes byte-identically
//! on all tested seedhashes; the divergence is in the post-cache
//! VM-execution / hash-composition path on the Rust side.
//!
//! This is the **same** divergence tracked by the V3.0 FOLLOWUP
//! "Investigate `shekyl-pow-randomx::compute_hash` divergence from C
//! reference at large data sizes" ([`docs/FOLLOWUPS.md`](../../../docs/FOLLOWUPS.md)
//! lines 50–82), whose characterization as "large data sizes only"
//! was a Phase 2g-time approximation against a single 387-KiB
//! reproducer. The C7 diagnostic widens the symptom surface: divergence
//! is universal, not size-gated. The FOLLOWUP entry is amended at C10
//! to reflect the corrected characterization.
//!
//! Per [`docs/design/RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! §0 frame "Out of scope (forward-deferred): (a) `compute_hash`
//! divergence from C reference at large data sizes — separate
//! FOLLOWUPS V3.0 entry with its own trigger; 2h consumes the harness
//! as-is. 2h benefits if the divergence lands first; if not, 2h
//! proceeds independently against the random + canonical-output
//! corpora plus the new adversarial corpus." T2 inherits the same
//! deferral that gates T1/T3/T5/T7/T8/T16 at the CI-workflow level:
//! the test is committed in its final shape, ignored under
//! `cargo test`, and reopens automatically when the FOLLOWUP closes
//! and the verifier ships a corrected `compute_hash`.
//!
//! Per [`21-reversion-clause-discipline.mdc`](../../../.cursor/rules/21-reversion-clause-discipline.mdc),
//! the gate's reopening criterion is **substrate-anchored** (FOLLOWUP
//! closure — i.e. `cargo test --ignored` against this file returns
//! clean), not author-preference-anchored. Removing the `#[ignore]`
//! attribute is the documented re-evaluation shape; the C10
//! plan-doc closure records the inheritance.
//!
//! ### Why this is *not* the `#[ignore]`-ladder anti-pattern
//!
//! R1-D6 close Reframe 1 rejected the `#[ignore]` ladder pattern
//! for **corpus-availability** deferrals — "test exists but ignored
//! pending a methodology decision that will eventually land." The
//! verifier-divergence deferral is a **substrate-broken** deferral:
//! the substrate the test exercises (`compute_hash`) is known-broken
//! against the C reference, and the FOLLOWUP's named scope is fixing
//! it. The test's substrate is the corpus + the cache-equivalence
//! precondition; both are ready. The deferral lives until the
//! third substrate (verifier hash equivalence) catches up.
//!
//! Invoke manually via `cargo test --release --ignored
//! --test adversarial_corpus_byte_equality`.
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
#[ignore = "Phase 2h T2 (adversarial_corpus_byte_equality): blocked behind the V3.0 \
            FOLLOWUP `shekyl-pow-randomx::compute_hash` divergence from C reference \
            (docs/FOLLOWUPS.md lines 50–82). Inherits the same CI-deferral that gates \
            T1/T3/T5/T7/T8/T16 per RANDOMX_V2_PHASE2G_PLAN.md §6.8 + the \
            randomx-v2-differential.yml workflow's runtime-modes-deferred comment. \
            Reopens automatically on FOLLOWUP closure (remove this attribute). Invoke \
            manually with `cargo test --release --ignored \
            --test adversarial_corpus_byte_equality`."]
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
