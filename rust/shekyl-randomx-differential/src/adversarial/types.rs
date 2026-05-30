// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Recipe data types for the Phase 2h adversarial corpus
//! (R1-D3 close).
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D3 close (declarative C1 recipes primary form), the
//! committed substrate for the adversarial corpus is **recipe data**:
//! a small declarative DSL describing `(base_seedhash, modifications)`
//! pairs that the [`super::interpreter::evaluate`] function expands
//! into the `(seedhash, cache_bytes)` pair consumed by
//! [`shekyl_pow_randomx::PreparedCache::from_raw_for_testing`] (the
//! R1-D2 close cache-level test-internals accessor landed at C2).
//!
//! # Recipe-as-substrate principle
//!
//! Per the R1-D3 close, *recipes constitute an executable
//! specification of the rare-path coverage* — the project's audit
//! story for leg-3 (rare-input coverage) cites the recipe directory
//! as the evidence, with each recipe's [`CacheRecipe::rationale`]
//! field serving as the audit-trail anchor. This is the broader
//! "substrate is documented in the code that implements it, not in
//! narrative docs that drift" pattern applied to the corpus.
//!
//! # Declarative-first; imperative escape hatch
//!
//! Declarative [`CacheRecipe`] entries (Sub-C C1 form per the R1-D3
//! close) are the primary form. Imperative recipes (Rust functions
//! producing equivalent data) are reserved for cases the declarative
//! form cannot express; each imperative recipe carries a
//! substrate-anchored justification for its imperativeness per
//! [`21-reversion-clause-discipline.mdc`](../../../../.cursor/rules/21-reversion-clause-discipline.mdc).
//! No imperative recipes ship at Phase 2h C3 (deferred to C4 if the
//! initial corpus surfaces a case the declarative form does not
//! cover).

/// Named anchor for a base seedhash from which a [`CacheRecipe`]'s
/// cache is derived.
///
/// The `name` field carries the audit-trail anchor (e.g.,
/// `"all-zeros"`, `"all-0x42-byte-pattern"`); the `bytes` field is
/// the actual 32-byte seedhash passed to the C reference's
/// `randomx_init_cache` for base-cache derivation.
///
/// # Why a named wrapper rather than a bare `[u8; 32]`
///
/// Per the R1-D3 close audit-trail discipline: a base seedhash
/// appearing in multiple recipes shares its name across all
/// citations, so a reviewer reading the recipe directory can
/// identify which base-derivation work is shared without comparing
/// 32-byte arrays. The named wrapper keeps
/// [`super::interpreter::base_cache_cache_key`]'s byte-equality
/// key human-readable in diagnostic output.
///
/// Per-consumer base-cache amortization (per
/// [`super`]'s "Base-cache amortization" module-level docs) keys
/// off `bytes` (not `name`); the per-consumer
/// `Vec<(base_bytes_key, derived_bytes)>` lookup amortizes the
/// ~150-200 ms Argon2d-fill cost (per `Cache::derive`'s documented
/// baseline) across all recipes sharing the same base seedhash.
/// Two recipes citing the same `bytes` under different `name`s
/// share an amortization entry but report distinct names in
/// diagnostics — the name is a label, not a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseSeedhash {
    /// Audit-trail anchor for the base seedhash. Surfaces in
    /// failure-output diagnostics, debug prints, and the rationale-
    /// citation grep targets per Phase 2h R2-D3 / R2-D4.
    pub name: &'static str,
    /// 32-byte seedhash passed to
    /// [`shekyl_pow_randomx::Seedhash::from_bytes`] and to the
    /// C reference's `randomx_init_cache` for base-cache derivation.
    pub bytes: [u8; 32],
}

/// A declarative adversarial-corpus recipe per the Phase 2h R1-D3
/// close Sub-C C1 form.
///
/// A [`CacheRecipe`] describes a `(base_seedhash, modifications)`
/// pair that the [`super::interpreter::evaluate`] function expands
/// into a `(seedhash, cache_bytes)` pair consumed by
/// [`shekyl_pow_randomx::PreparedCache::from_raw_for_testing`] (the
/// R1-D2 close accessor landed at C2). The expanded cache state
/// drives `compute_hash` against a spec-faithful rare-path target
/// without requiring statistical-grinding-of-seedhashes (the
/// Phase 2g R7-D1 finding).
///
/// # Field discipline
///
/// - **`name`** — short kebab-case identifier; used in failure
///   diagnostics and as the recipe's key for amortized base-cache
///   lookup.
/// - **`rationale`** — multi-sentence audit-trail anchor citing the
///   three-evidence-category structure per R1-D8: Category 1
///   (audit-anchored spec silence; cites a specific
///   `RANDOMX_V2_PHASE2D_PLAN.md §3.4 spec-silence #N` or
///   equivalent), Category 2 (coverage-metric-attested; cites a
///   coverage gap snapshot committed alongside the recipe), or
///   Category 3 (substrate-derived; cites a specific V2
///   configuration constant or boundary value). The format is
///   syntactically validated by the M5 citation-validation script
///   landing at C9; semantic correctness is reviewer-checked per
///   R2-D3 Mitigation C.
/// - **`base`** — see [`BaseSeedhash`].
/// - **`modifications`** — sequential byte overrides applied to the
///   base cache: each `(offset, value)` pair sets
///   `cache_bytes[offset] = value`. Later entries supersede
///   earlier entries at the same offset; out-of-range offsets are
///   a recipe-author bug and panic at evaluation with a diagnostic
///   message (per R1-D3 close: "fewer corners than imperative
///   code; the interpreter is auditable end-to-end").
///
/// # Fill-pattern + boundary-value primitives
///
/// The R1-D3 close framing names *fill patterns and boundary-value
/// primitives* as part of the DSL surface. Phase 2h C3 lands only
/// the byte-override primitive (`modifications: &'static [(usize,
/// u8)]`); higher-level primitives (fill ranges, repeating patterns,
/// dataset-item-boundary writes) are introduced if the initial
/// recipe corpus at C4 surfaces a need that byte-overrides cannot
/// express ergonomically. Per
/// [`21-reversion-clause-discipline.mdc`](../../../../.cursor/rules/21-reversion-clause-discipline.mdc):
/// reject-with-reopening — reopen if C4 demonstrates a recipe
/// pattern that requires >100 byte-override entries to express
/// what a single primitive could express.
///
/// # Determinism
///
/// All fields are `&'static` references to compiled-in data; the
/// [`CacheRecipe`] is `Copy`-able and contains no runtime
/// allocations. The interpreter's `evaluate` function produces a
/// deterministic output for any `(recipe, base_cache_bytes)` pair —
/// the M1 canonical-output discipline (per R1-D4 close) pins the
/// expanded SHA-256 alongside the expected hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheRecipe {
    /// Short kebab-case identifier (see field-discipline rustdoc).
    pub name: &'static str,
    /// Multi-sentence audit-trail anchor (see field-discipline
    /// rustdoc + R1-D8 three-evidence-category structure).
    pub rationale: &'static str,
    /// Named base seedhash anchor (see [`BaseSeedhash`]).
    pub base: BaseSeedhash,
    /// Sequential byte overrides applied to the base cache (see
    /// field-discipline rustdoc).
    pub modifications: &'static [(usize, u8)],
}

/// The expanded `(seedhash, cache_bytes)` pair produced by
/// [`super::interpreter::evaluate`] from a [`CacheRecipe`].
///
/// Held as an owned `Vec<u8>` rather than borrowed to support the
/// hot-path discipline where the harness materializes once and
/// reuses across many `compute_hash` invocations (per R1-D5 close
/// latency-measurement methodology). The 256-MiB allocation cost is
/// amortized across the per-recipe sample count
/// (`SAMPLE_BUDGET_PER_RECIPE` from the C1 measurement bundle).
///
/// # Why not borrow the cache bytes
///
/// Returning `Vec<u8>` ownership rather than `&'a [u8]` against an
/// internal buffer keeps the evaluator stateless: each `evaluate`
/// call is independent, no `&mut self` interpreter handle, no
/// lifetime threading. The 256-MiB allocation per call is bounded
/// by the per-recipe sample count rather than per-invocation;
/// callers that want to amortize hold the [`EvaluatedRecipe`] in a
/// local binding across the sample loop.
#[derive(Debug, Clone)]
pub struct EvaluatedRecipe {
    /// Echoes [`CacheRecipe::name`] for diagnostic correlation
    /// against the source recipe (e.g., in
    /// [`super::interpreter::evaluate`]'s panic paths and the M5
    /// citation-validation script's reverse mapping).
    pub recipe_name: &'static str,
    /// Seedhash derived from [`CacheRecipe::base`]'s bytes, ready
    /// for passing to
    /// [`shekyl_pow_randomx::PreparedCache::from_raw_for_testing`].
    pub seedhash: shekyl_pow_randomx::Seedhash,
    /// Cache memory bytes after the recipe's modifications have
    /// been applied to the base cache. Length always equals
    /// `CACHE_SIZE` (256 MiB); the
    /// [`shekyl_pow_randomx::PreparedCache::from_raw_for_testing`]
    /// length contract is satisfied by construction.
    pub cache_bytes: Vec<u8>,
}
