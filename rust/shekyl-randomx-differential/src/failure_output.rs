// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structured failure output schema (§5.1.14, R1-D11).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.14 + R1-D11
//! close (Round 3 §4.5 / §4.6 A4 substrate-completeness amendment),
//! the harness emits a structured JSON failure record on stderr
//! whenever a divergence is detected (byte-equality mismatch,
//! cache-precondition failure, worker-hash divergence, RSS-bound
//! violation, etc.). The schema is fixed at 11 fields per R1-D11
//! (`seedhash`, `data`, `rust_hash`, `c_hash`, `rust_cache_sha256`,
//! `c_cache_sha256`, `mode`, `class_tag`, `timestamp`,
//! `harness_version`, `fork_pin`); T11 (per §6.5 + R4-D8) round-
//! trips a synthetic [`FailureOutput`] through `serde_json` to
//! assert all 11 fields are present and the schema is JSON-clean.
//!
//! ## Why a fixed schema rather than ad-hoc per-mode error strings
//!
//! Per §4.5 T-A4 active-threat-surface ("schema drift hides
//! diagnostics") + §4.6 A4 mitigation: ad-hoc error strings are
//! reviewer-attention-bound; structured JSON is `grep`-friendly and
//! amenable to mechanical diagnosis (a CI failure that diffs a JSON
//! field is easier to triage than a multi-line prose error). The
//! schema is **always emitted** on failure (no verbosity flag-
//! gating per R1-D11 close: the cost is zero on the success path,
//! the benefit is asymmetric to the failure path).
//!
//! ## R4-D8: unit test, not a binary mode
//!
//! Per R4-D8 close, T11 is a `#[cfg(test)]` unit test inside this
//! module — **not** a `--mode=test-failure` binary mode. The earlier
//! Round-1 sketch had a binary mode to exercise the schema; R4-D8
//! collapsed it to a unit test because the schema is pure data
//! shaping with no mode-dispatch infrastructure to test. The unit
//! test is in `#[cfg(test)] mod tests` below.
//!
//! ## Output contract
//!
//! - JSON line emitted to **stderr** (one JSON per failure for
//!   grep-friendliness) via [`FailureOutput::emit_stderr`].
//! - Human-readable formatted block emitted to **stdout** via the
//!   [`fmt::Display`] impl (which the C7+ mode error variants'
//!   `Display` impls drive directly; this module retains the
//!   structured schema for the JSON path and for forward
//!   reviewer-facing diagnostics if mode-error reporting later
//!   extends to JSON-line emission per R1-D11's reopening clause).
//! - First failure aborts the corpus pass per R1-D11 "no
//!   continue-on-failure" pin.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Phase 2g fork-pin SHA per §1.7 ("Fork pin |
/// `external/randomx-v2` at `aaafe71` (v2.0.1); unchanged by 2g per
/// the hard-constraint substrate"). The SHA is the abbreviated form
/// used throughout the plan-doc; T15 asserts the
/// `[package.metadata.shekyl]` `fork-pin-sha` field in
/// `randomx-v2-sys/Cargo.toml` matches `external/randomx-v2`'s
/// HEAD at the same prefix length. Carrying it as a const here so
/// the failure-output schema's `fork_pin` field is
/// substrate-anchored and a fork-pin advance per §1.7's reopening
/// clause flags this constant for review.
pub const FORK_PIN_SHA: &str = "aaafe71";

/// Harness crate version surfaced into the schema's `harness_version`
/// field per R1-D11 close. Read from `CARGO_PKG_VERSION` at compile
/// time so a divergence's failure output captures the harness build
/// that produced it (audit trail for the §4.5 T-A8 "harness tamper"
/// class — the version field doesn't *prevent* tampering but it
/// surfaces "the failure happened against this harness version"
/// for forward reviewer attribution).
pub const HARNESS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Structured failure record per §5.1.14 / R1-D11 / T11. The 11
/// fields are an invariant: removing or renaming any field breaks
/// the T11 round-trip assertion; adding a field requires a
/// plan-doc amendment per the reopening criteria in R1-D11.
///
/// ## Field semantics
///
/// - `seedhash` — 64-char lowercase hex of the seedhash that
///   produced the divergence (`RandomCorpusPair::seedhash` /
///   `AdversarialPair::seedhash` / the worst-case-mode seedhash;
///   carried even on RSS / wall-clock failures whose proximate
///   cause is non-seedhash so a reviewer can correlate the
///   failure-point with the corpus iteration).
/// - `data` — lowercase hex of the data buffer that produced the
///   divergence; empty string when the failure is not tied to a
///   specific data value (e.g., cache-precondition failure pre-
///   compute-hash; RSS / wall-clock failure).
/// - `rust_hash` / `c_hash` — 64-char lowercase hex of the
///   verifier output / oracle output; empty string for failures
///   that occur before hash computation (cache-precondition,
///   resource-allocation, RSS / wall-clock).
/// - `rust_cache_sha256` / `c_cache_sha256` — 64-char lowercase
///   hex of the SHA-256 fingerprint of the Rust / C cache
///   per R1-D14 precondition; carried even on post-precondition
///   failures so the reviewer can confirm the precondition held
///   at test time. Empty string when the failure occurs before
///   cache derivation completes.
/// - `mode` — one of `correctness` / `worst-case` / `latency` /
///   `concurrent` per [`crate::Mode`]'s `as_str()`. Worst-case
///   is wired in the schema for forward-compatibility even though
///   `--mode=worst-case` is deferred per §3.19 R7-D4.
/// - `class_tag` — adversarial-corpus class tag per R1-D5/R1-D6
///   (e.g., `"heavy-cfround"`, `"heavy-fdiv-m"`); empty string
///   for non-worst-case modes and for the empty adversarial
///   scaffold the C5b commit landed (per §3.19 R7-D4 deferral).
/// - `timestamp` — UNIX epoch seconds at failure-output
///   construction time (`SystemTime::now()`).
/// - `harness_version` — [`HARNESS_VERSION`] (compile-time
///   `CARGO_PKG_VERSION`).
/// - `fork_pin` — [`FORK_PIN_SHA`] (`aaafe71`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureOutput {
    /// 64-char lowercase hex of the seedhash; carried even when
    /// the failure isn't directly attributable to a specific
    /// seedhash so the corpus iteration is reconstructable.
    pub seedhash: String,
    /// Lowercase hex of the data buffer; empty string when not
    /// applicable (pre-compute-hash failure path).
    pub data: String,
    /// 64-char lowercase hex of the Rust verifier output; empty
    /// string when no hash was computed before the failure.
    pub rust_hash: String,
    /// 64-char lowercase hex of the C oracle output; empty
    /// string when no hash was computed before the failure.
    pub c_hash: String,
    /// 64-char lowercase hex of the SHA-256 fingerprint of the
    /// Rust cache; empty string for pre-cache failures.
    pub rust_cache_sha256: String,
    /// 64-char lowercase hex of the SHA-256 fingerprint of the
    /// C cache; empty string for pre-cache failures.
    pub c_cache_sha256: String,
    /// Mode tag: `correctness` / `worst-case` / `latency` /
    /// `concurrent` per [`crate::Mode::as_str`].
    pub mode: String,
    /// Adversarial-corpus class tag; empty string for non-worst-
    /// case modes.
    pub class_tag: String,
    /// UNIX epoch seconds at failure-output construction time.
    pub timestamp: u64,
    /// Harness crate version per [`HARNESS_VERSION`].
    pub harness_version: String,
    /// Fork-pin SHA per [`FORK_PIN_SHA`].
    pub fork_pin: String,
}

impl FailureOutput {
    /// Construct a [`FailureOutput`] with the substrate-anchored
    /// fields (`timestamp`, `harness_version`, `fork_pin`) auto-
    /// populated. The caller supplies the failure-specific
    /// fields. Strings that don't apply to the failure class
    /// are passed as empty strings (`""`) per the per-field
    /// semantics in the struct doc-comment.
    ///
    /// The `timestamp` field is `SystemTime::now()` measured at
    /// epoch-seconds resolution; a clock-skewed system that
    /// returns a time before `UNIX_EPOCH` saturates to `0`
    /// rather than panicking (the saturation is benign because
    /// the timestamp is for forward audit-trail, not for
    /// reproducibility — the `cargo_repro_invocation`-style
    /// reproducibility is carried by `seedhash` + `data`).
    ///
    /// The 8 caller-supplied arguments mirror the 8 of the
    /// 11 R1-D11 schema fields that aren't auto-populated
    /// (`timestamp`, `harness_version`, `fork_pin` are derived
    /// inside this function from substrate constants). The
    /// clippy `too_many_arguments` lint is suppressed below
    /// because the 1:1 field-to-argument mapping is the schema
    /// shape; refactoring into a builder or struct-literal would
    /// add ceremony without reducing the parameter count and
    /// would hide the R1-D11 pinning from callers.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        seedhash: String,
        data: String,
        rust_hash: String,
        c_hash: String,
        rust_cache_sha256: String,
        c_cache_sha256: String,
        mode: &str,
        class_tag: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            seedhash,
            data,
            rust_hash,
            c_hash,
            rust_cache_sha256,
            c_cache_sha256,
            mode: mode.to_string(),
            class_tag,
            timestamp,
            harness_version: HARNESS_VERSION.to_string(),
            fork_pin: FORK_PIN_SHA.to_string(),
        }
    }

    /// Serialize the failure record to a single-line JSON string
    /// suitable for stderr emission per R1-D11 "JSON-formatted to
    /// stderr (one-failure-per-line for grep-friendliness)".
    ///
    /// Returns the JSON-encoded string. The encoding is infallible
    /// in practice (all 11 fields are plain `String` / `u64`,
    /// `serde_json` cannot fail to encode them) — but the
    /// `Result` is propagated rather than `unwrap()`'d so the
    /// caller can attribute a future schema change that violates
    /// the infallibility property.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the schema acquires a
    /// type that `serde_json` cannot encode (e.g., a future
    /// field of type `f64::NAN` per IEEE-754 nonconformance to
    /// JSON). The current schema cannot trigger this.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Emit the JSON line to stderr per R1-D11 "JSON-formatted
    /// to stderr". Wraps [`Self::to_json_line`] and writes via
    /// `eprintln!`; a serialization error is itself logged to
    /// stderr (with the prefix `error: failure_output serialize
    /// failed:`) and absorbed — the caller's failure path must
    /// not be blocked by an output-side hiccup. Returns `true`
    /// when the JSON was emitted, `false` when the serialization
    /// failed.
    pub fn emit_stderr(&self) -> bool {
        match self.to_json_line() {
            Ok(json) => {
                eprintln!("{json}");
                true
            }
            Err(err) => {
                eprintln!("error: failure_output serialize failed: {err}");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T11 (`failure_output_schema_round_trip`) per §6.5: synthetic
    /// [`FailureOutput`] with all 11 required fields set to test
    /// values; assert JSON serializes cleanly, round-trips through
    /// `serde_json::to_string` + `serde_json::from_str`, and the
    /// serialized form contains every required field name as a
    /// JSON key. Per R4-D8 close, this is a `#[cfg(test)]` unit
    /// test in this module (no `--mode=test-failure` binary mode).
    #[test]
    fn t11_failure_output_schema_round_trip() {
        let original = FailureOutput::new(
            "a3b2c1d04e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b".to_string(),
            "deadbeef".to_string(),
            "4b6f98ae01d418ca13671ccdac8fd1752015e8d9c715d514ab4826abf14f2c0b".to_string(),
            "95457eb75fb5c626546eb5f677a6975844ff8a09fd8950a3c9e7fdfb0cbf1517".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
            "correctness",
            String::new(),
        );

        // Serialize.
        let json = original.to_json_line().expect("serialize succeeds");

        // All 11 required field names from R1-D11 must appear as
        // JSON keys per T11. We assert the JSON-key form
        // (`"<name>":`) so a partial substring match on the value
        // can't mask a missing key.
        for required_field in [
            "\"seedhash\":",
            "\"data\":",
            "\"rust_hash\":",
            "\"c_hash\":",
            "\"rust_cache_sha256\":",
            "\"c_cache_sha256\":",
            "\"mode\":",
            "\"class_tag\":",
            "\"timestamp\":",
            "\"harness_version\":",
            "\"fork_pin\":",
        ] {
            assert!(
                json.contains(required_field),
                "T11: required field '{required_field}' missing from JSON: {json}"
            );
        }

        // Round-trip back through `serde_json`.
        let recovered: FailureOutput = serde_json::from_str(&json).expect("deserialize succeeds");
        assert_eq!(
            recovered, original,
            "T11: round-trip must reproduce the original FailureOutput byte-for-byte"
        );
    }

    /// The auto-populated `harness_version` field matches
    /// `CARGO_PKG_VERSION` at compile time. Catches a future
    /// regression that swaps the const for a stale literal.
    #[test]
    fn harness_version_matches_cargo_pkg_version() {
        let f = FailureOutput::new(
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "correctness",
            String::new(),
        );
        assert_eq!(f.harness_version, env!("CARGO_PKG_VERSION"));
    }

    /// The auto-populated `fork_pin` matches the §1.7 fork-pin
    /// SHA. A future fork-pin advance per §1.7 reopens this
    /// assertion at the same time the `randomx-v2-sys`
    /// metadata advances.
    #[test]
    fn fork_pin_matches_section_1_7() {
        let f = FailureOutput::new(
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "correctness",
            String::new(),
        );
        assert_eq!(f.fork_pin, "aaafe71");
    }

    /// Timestamp is monotonic-non-decreasing across two
    /// constructions within the same test (`SystemTime::now()` is
    /// not guaranteed monotonic in general, but on a CI runner
    /// with stable wall-clock the two constructions cannot
    /// reorder by epoch-second granularity). Catches a future
    /// regression that hard-codes the timestamp to `0`.
    #[test]
    fn timestamp_increases_across_constructions() {
        let f1 = FailureOutput::new(
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "correctness",
            String::new(),
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
        let f2 = FailureOutput::new(
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "correctness",
            String::new(),
        );
        assert!(
            f2.timestamp >= f1.timestamp,
            "timestamp non-monotonic: f1={}, f2={}",
            f1.timestamp,
            f2.timestamp
        );
        assert!(
            f2.timestamp > 0,
            "timestamp saturated to zero: clock-skew sentinel hit"
        );
    }

    /// All four [`crate::Mode`] variants serialize as valid
    /// `mode` field values. The harness's CLI accepts these four
    /// strings; the failure-output schema mirrors them.
    #[test]
    fn all_modes_serialize() {
        for mode in ["correctness", "worst-case", "latency", "concurrent"] {
            let f = FailureOutput::new(
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                mode,
                String::new(),
            );
            let json = f.to_json_line().expect("serialize");
            assert!(
                json.contains(&format!("\"mode\":\"{mode}\"")),
                "mode '{mode}' missing from JSON: {json}"
            );
        }
    }

    /// The class_tag field accepts both empty strings (non-
    /// worst-case modes) and adversarial-corpus class tags
    /// (worst-case mode per R1-D5/R1-D6). Round-trip preserves
    /// the distinction.
    #[test]
    fn class_tag_round_trips_empty_and_populated() {
        for tag in ["", "heavy-cfround", "heavy-fdiv-m", "u128-edge"] {
            let f = FailureOutput::new(
                "a".repeat(64),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "worst-case",
                tag.to_string(),
            );
            let json = f.to_json_line().expect("serialize");
            let recovered: FailureOutput = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(recovered.class_tag, tag, "class_tag round-trip");
        }
    }
}
