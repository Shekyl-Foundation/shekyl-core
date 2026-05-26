// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--mode=correctness` orchestrator (§5.1.10, T1, T16).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.10 + §3.15.4
//! orchestration lifecycle, this module runs the harness's
//! per-`(seedhash, data)` byte-equality check across the random
//! corpus (§5.1.5 + R1-D4), prefaced by the R1-D14 cache-equivalence
//! precondition (§5.1.7). The §4.6 M1 canonical pin
//! ([`crate::canonical_outputs::CANONICAL_RANDOM_HASHES`] +
//! [`crate::canonical_outputs::CANONICAL_CACHE_SHAS`]) is asserted
//! alongside the live `rust == c` byte-equality, producing the
//! three-leg comparison that closes T16 (defends against T-A1,
//! T-A2, T-A3, T-A10).
//!
//! ## Per-seedhash flow (§3.15.4 lifecycle, correctness arm)
//!
//! For each unique seedhash in the requested subset:
//!
//! 1. Construct [`RustSubjectSession`] via
//!    `PreparedCache::derive(seedhash)` (~5–10 s release-mode
//!    Argon2d-512 cost; per-seedhash, amortized across the
//!    seedhash's data pairs).
//! 2. Construct [`COracleSession`] via `randomx_alloc_cache +
//!    randomx_init_cache + randomx_create_vm`.
//! 3. Run [`assert_equivalent`] (T3, §5.1.7). On mismatch, surface
//!    [`CorrectnessError::Precondition`] and abort the corpus pass
//!    for that seedhash (per R1-D14 fail-fast pin).
//! 4. Assert the rust + c SHA-256 fingerprints against
//!    [`CANONICAL_CACHE_SHAS`]`[nightly_seedhash_index]` (T16 leg-3).
//! 5. For each `(seedhash, data, canonical_index)` triple under
//!    this seedhash: compute `rust_hash` + `c_hash`, assert
//!    `rust_hash == c_hash`, and (T16 leg-3)
//!    `rust_hash == CANONICAL_RANDOM_HASHES[canonical_index]`.
//! 6. Drop both sessions; release C cache + VM; PreparedCache's
//!    drop discipline wipes the Rust-side 256-MiB cache.
//!
//! ## Adversarial-corpus iteration (R7-D4)
//!
//! Per §3.19 R7-D4, the adversarial corpus (§5.1.6) is scaffolded
//! empty through 2g ship; the methodology + corpus land in a
//! post-2g design round. The iteration code in [`run`] still walks
//! the [`crate::adversarial_corpus::iter_adversarial_seedhashes`]
//! iterator structurally, so the path lights up when the corpus
//! fills without an additional code change. At C7, the iterator
//! yields zero items and the per-pair body never executes.
//!
//! ## §3.18 R6-D4 corpus indexing
//!
//! The random corpus is **always** generated at the nightly
//! sizing (32 seedhashes × 32 data values = 1024 pairs); the
//! `--random-corpus-seedhashes` + `--random-corpus-data-per-seedhash`
//! flags (per R4-D6) select a 2D `(i ∈ [0, req_S), j ∈ [0, req_M))`
//! subset. The canonical pin's flat index
//! `i * NIGHTLY_DATA_PER_SEEDHASH + j` is computed by
//! [`crate::corpus_random::generate_correctness_subset`] and
//! attached to each yielded pair so this module's canonical
//! lookups are O(1).
//!
//! ## Failure surfacing
//!
//! At C7 the failure path emits a human-readable diagnostic via
//! [`std::fmt::Display`] (matched against `cargo test` failure
//! output) and exits non-zero through `main.rs`'s `ExitCode`. The
//! §5.1.14 structured-JSON failure schema lands at C9; this module
//! carries enough context in each error variant for the C9 schema
//! to populate without re-running the failing test.
//!
//! ## `--debug-cache-divergence` invocation
//!
//! When [`run`] is invoked with `debug_cache_divergence_seedhash`
//! set, the per-seedhash precondition check upgrades from SHA-256
//! comparison (T3) to byte-by-byte diff (T4) **only** for the
//! matching seedhash; all other seedhashes run the cheaper SHA-256
//! path. The diagnostic path is the only path that surfaces a
//! [`ByteDivergence`] result; the SHA-256 path surfaces only the
//! digest pair.

use std::fmt;

use shekyl_pow_randomx::Seedhash;

use crate::adversarial_corpus::{iter_adversarial_data, iter_adversarial_seedhashes};
use crate::c_oracle::{COracleError, COracleSession};
use crate::cache_precondition::{
    assert_equivalent, byte_diff, ByteDivergence, PreconditionMismatch,
};
use crate::canonical_outputs::{CANONICAL_CACHE_SHAS, CANONICAL_RANDOM_HASHES};
use crate::corpus_random::{generate_correctness_subset, NIGHTLY_DATA_PER_SEEDHASH};
use crate::rust_subject::RustSubjectSession;

/// Successful run summary surfaced on the stdout report path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrectnessReport {
    /// Number of unique seedhashes whose `(rust_cache, c_cache)`
    /// SHA-256 precondition + `(rust_hash, c_hash, canonical_hash)`
    /// three-leg byte-equality both held. One entry per seedhash
    /// in the requested subset.
    pub seedhashes_checked: usize,
    /// Number of `(seedhash, data)` pairs whose
    /// `rust_hash == c_hash == canonical_hash` three-leg byte-
    /// equality (T1 + T16) held. Equals `requested_seedhashes *
    /// requested_data_per_seedhash` on success.
    pub random_pairs_checked: usize,
    /// Number of adversarial pairs checked at this run. Zero at
    /// C7 per §3.19 R7-D4 (adversarial corpus deferred to a
    /// post-2g design round); non-zero once the corpus fills.
    pub adversarial_pairs_checked: usize,
}

impl fmt::Display for CorrectnessReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "correctness mode: seedhashes_checked={}, random_pairs_checked={}, \
             adversarial_pairs_checked={}",
            self.seedhashes_checked, self.random_pairs_checked, self.adversarial_pairs_checked
        )
    }
}

/// All failure modes the correctness orchestrator can surface.
/// Each variant carries enough context for the C9 §5.1.14 JSON
/// schema to attribute the failure without re-running the test.
#[derive(Debug)]
pub enum CorrectnessError {
    /// C oracle resource allocation failed (cache / VM / cache
    /// memory pointer). Wraps the [`COracleError`] from
    /// [`COracleSession::new`].
    COracle(COracleError),
    /// T3 / R1-D14 cache-equivalence precondition failed: the Rust
    /// verifier's 256-MiB Argon2d-derived cache does not match the
    /// C reference's at the SHA-256 fingerprint level.
    Precondition(PreconditionMismatch),
    /// T4 diagnostic: the `--debug-cache-divergence` byte-by-byte
    /// diff surfaced the first divergent offset and a ±64-byte
    /// window. Surfaced only when [`run`] is invoked with
    /// `debug_cache_divergence_seedhash` matching the failing
    /// seedhash.
    PreconditionByteDiff(ByteDivergence),
    /// T16 leg-3: the Rust + C agreed-upon cache SHA-256 does
    /// not match the committed [`CANONICAL_CACHE_SHAS`] entry
    /// for this seedhash's nightly index. Indicates either a
    /// canonical-pin staleness or a substrate change that
    /// invalidates the prior canonical run.
    CanonicalCacheMismatch {
        /// Seedhash whose cache-SHA mismatched the canonical.
        seedhash: Seedhash,
        /// Seedhash's position in the nightly corpus (0..32);
        /// the canonical index.
        nightly_seedhash_index: usize,
        /// SHA-256(Rust cache) == SHA-256(C cache); both agreed
        /// at the precondition step.
        actual_sha: [u8; 32],
        /// The committed canonical SHA-256 pinned at C5a.
        canonical_sha: [u8; 32],
    },
    /// T1: `rust_hash != c_hash` for a `(seedhash, data)` pair.
    /// The deepest divergence the harness can surface — indicates
    /// a divergence in the program-execution, JIT, or scratchpad
    /// path beyond the cache-derivation step.
    HashMismatch {
        /// Seedhash of the failing pair.
        seedhash: Seedhash,
        /// Flat canonical index `i * NIGHTLY_DATA_PER_SEEDHASH + j`
        /// per R6-D4 indexing; the data is re-derivable by
        /// calling `generate_correctness_subset` at the requested
        /// sizing. Set to `usize::MAX` for adversarial pairs
        /// (which the random corpus's canonical index space
        /// doesn't cover).
        canonical_index: usize,
        /// Data length the failing pair ran against (the data
        /// itself is corpus-derived; the C9 JSON schema can
        /// re-derive it without storing it).
        data_len: usize,
        /// Rust verifier's `compute_hash` output.
        rust_hash: [u8; 32],
        /// C reference's `randomx_calculate_hash` output.
        c_hash: [u8; 32],
    },
    /// T16 leg-3: `rust_hash == c_hash` but neither equals
    /// `CANONICAL_RANDOM_HASHES[canonical_index]`. The two
    /// implementations agree but disagree with the committed
    /// canonical — investigate the canonical's provenance per
    /// §5.7 + §8.3 regeneration discipline.
    CanonicalHashMismatch {
        /// Seedhash of the failing pair.
        seedhash: Seedhash,
        /// Flat canonical index per R6-D4.
        canonical_index: usize,
        /// Hash both Rust and C agreed on.
        actual_hash: [u8; 32],
        /// The committed canonical hash pinned at C5a.
        canonical_hash: [u8; 32],
    },
}

impl fmt::Display for CorrectnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::COracle(e) => write!(f, "c-oracle setup failed: {e}"),
            Self::Precondition(e) => write!(f, "{e}"),
            Self::PreconditionByteDiff(e) => write!(f, "{e}"),
            Self::CanonicalCacheMismatch {
                seedhash,
                nightly_seedhash_index,
                actual_sha,
                canonical_sha,
            } => write!(
                f,
                "canonical-cache mismatch for seedhash {seedhash} \
                 (nightly index {nightly_seedhash_index}): \
                 actual_sha={}, canonical_sha={}",
                hex_lower(actual_sha),
                hex_lower(canonical_sha)
            ),
            Self::HashMismatch {
                seedhash,
                canonical_index,
                data_len,
                rust_hash,
                c_hash,
            } => write!(
                f,
                "hash mismatch for seedhash {seedhash} \
                 (canonical_index {canonical_index}, data_len {data_len}): \
                 rust_hash={}, c_hash={}",
                hex_lower(rust_hash),
                hex_lower(c_hash)
            ),
            Self::CanonicalHashMismatch {
                seedhash,
                canonical_index,
                actual_hash,
                canonical_hash,
            } => write!(
                f,
                "canonical-hash mismatch for seedhash {seedhash} \
                 (canonical_index {canonical_index}): \
                 actual_hash={}, canonical_hash={}",
                hex_lower(actual_hash),
                hex_lower(canonical_hash)
            ),
        }
    }
}

impl std::error::Error for CorrectnessError {}

impl From<COracleError> for CorrectnessError {
    fn from(e: COracleError) -> Self {
        Self::COracle(e)
    }
}

/// Run `--mode=correctness` per §5.1.10 + §3.15.4.
///
/// Returns [`CorrectnessReport`] on success; the first failure
/// short-circuits the run per the §3.15.4 + R1-D14 fail-fast
/// discipline. `requested_seedhashes` and
/// `requested_data_per_seedhash` are clamped against
/// `NIGHTLY_SEEDHASH_COUNT` / `NIGHTLY_DATA_PER_SEEDHASH` by the
/// caller (`main.rs::parse_args`).
///
/// # Errors
///
/// Surfaces the first [`CorrectnessError`] across the precondition
/// + per-pair flow per the §3.15.4 fail-fast discipline.
pub fn run(
    requested_seedhashes: usize,
    requested_data_per_seedhash: usize,
    debug_cache_divergence_seedhash: Option<[u8; 32]>,
) -> Result<CorrectnessReport, CorrectnessError> {
    let subset = generate_correctness_subset(requested_seedhashes, requested_data_per_seedhash);
    let mut seedhashes_checked: usize = 0;
    let mut random_pairs_checked: usize = 0;

    // Group the flat subset by nightly_seedhash_index. The
    // `generate_correctness_subset` emission order is row-major
    // over `(i, j)` (per its rustdoc + tests), so each seedhash's
    // pairs arrive contiguously: a single linear pass over `subset`
    // with a `[start, end)` window per seedhash is sufficient.
    let mut start: usize = 0;
    while start < subset.len() {
        let nightly_seedhash_index = subset[start].0 / NIGHTLY_DATA_PER_SEEDHASH;
        let mut end = start + 1;
        while end < subset.len()
            && subset[end].0 / NIGHTLY_DATA_PER_SEEDHASH == nightly_seedhash_index
        {
            end += 1;
        }
        let this_seedhash_pairs = &subset[start..end];
        let seedhash = this_seedhash_pairs[0].1.seedhash;

        let rust = RustSubjectSession::derive(seedhash);
        let c = COracleSession::new(seedhash)?;

        // T3 — upgrade to T4 byte-diff if the operator's
        // --debug-cache-divergence flag targets this seedhash and
        // the SHA-256 path fails.
        if let Err(mismatch) = assert_equivalent(&rust, &c) {
            if let Some(target) = debug_cache_divergence_seedhash {
                if target == *seedhash.as_bytes() {
                    return match byte_diff(&rust, &c) {
                        // SHA-256 said mismatch but byte-diff
                        // found none. Surface the SHA-256
                        // mismatch result; the contradiction would
                        // indicate a SHA-256 update bug or harness
                        // wiring drift, not a cache divergence.
                        Ok(()) => Err(CorrectnessError::Precondition(mismatch)),
                        Err(div) => Err(CorrectnessError::PreconditionByteDiff(div)),
                    };
                }
            }
            return Err(CorrectnessError::Precondition(mismatch));
        }

        // T16 leg-3: rust_sha == c_sha == canonical_cache_sha.
        // `assert_equivalent` returned `Ok` so both sides agreed
        // on a shared SHA; re-derive it from the C side (a single
        // 256-MiB pass per seedhash, ~150–250 ms) for the
        // canonical comparison. Cost is bounded inside the §5.5.1
        // / §5.5.2 budget. If a future budget review wants the
        // saving, `assert_equivalent` can return the agreed SHA
        // on `Ok`; the change is local to `cache_precondition.rs`.
        let actual_sha = c.cache_sha256();
        if let Some(canonical_sha) = CANONICAL_CACHE_SHAS.get(nightly_seedhash_index) {
            if actual_sha != *canonical_sha {
                return Err(CorrectnessError::CanonicalCacheMismatch {
                    seedhash,
                    nightly_seedhash_index,
                    actual_sha,
                    canonical_sha: *canonical_sha,
                });
            }
        }
        // (else: canonical index out of bounds — only possible if
        // NIGHTLY_SEEDHASH_COUNT diverges from CANONICAL_CACHE_SHAS
        // length, which `canonical_arrays_match_nightly_sizing`
        // catches at test time.)

        // Per-data byte-equality (T1) + canonical hash check (T16).
        for &(canonical_index, ref pair) in this_seedhash_pairs {
            let rust_hash = rust.compute_hash(&pair.data);
            let c_hash = c.calculate_hash(&pair.data);
            if rust_hash != c_hash {
                return Err(CorrectnessError::HashMismatch {
                    seedhash,
                    canonical_index,
                    data_len: pair.data.len(),
                    rust_hash,
                    c_hash,
                });
            }
            if let Some(canonical_hash) = CANONICAL_RANDOM_HASHES.get(canonical_index) {
                if rust_hash != *canonical_hash {
                    return Err(CorrectnessError::CanonicalHashMismatch {
                        seedhash,
                        canonical_index,
                        actual_hash: rust_hash,
                        canonical_hash: *canonical_hash,
                    });
                }
            }
            random_pairs_checked += 1;
        }

        seedhashes_checked += 1;
        start = end;
    }

    // Adversarial-corpus structural iteration (§3.19 R7-D4: empty
    // at C7; the loop yields zero items, but the code path is
    // wired so a future post-2g design round's filled corpus
    // lights up without a separate code change).
    let mut adversarial_pairs_checked: usize = 0;
    for (_class_tag, seedhash) in iter_adversarial_seedhashes() {
        let rust = RustSubjectSession::derive(seedhash);
        let c = COracleSession::new(seedhash)?;
        if let Err(mismatch) = assert_equivalent(&rust, &c) {
            return Err(CorrectnessError::Precondition(mismatch));
        }
        for (_data_class_tag, data) in iter_adversarial_data() {
            let rust_hash = rust.compute_hash(data);
            let c_hash = c.calculate_hash(data);
            if rust_hash != c_hash {
                return Err(CorrectnessError::HashMismatch {
                    seedhash,
                    // Adversarial pairs use a sentinel canonical
                    // index (the random corpus owns canonical
                    // indices 0..1024); the C9 failure-output
                    // schema distinguishes adversarial pairs by
                    // the absent canonical lookup. The post-2g
                    // adversarial-corpus design round lands a
                    // class-indexed canonical table per §3.18
                    // R6-D4 adversarial-corpus paragraph.
                    canonical_index: usize::MAX,
                    data_len: data.len(),
                    rust_hash,
                    c_hash,
                });
            }
            adversarial_pairs_checked += 1;
        }
    }

    Ok(CorrectnessReport {
        seedhashes_checked,
        random_pairs_checked,
        adversarial_pairs_checked,
    })
}

/// Lower-case hex string formatter for 32-byte arrays. Used by the
/// [`CorrectnessError`] `Display` impl. Duplicated from
/// [`crate::cache_precondition`] rather than re-exported to keep
/// the two modules' display formatting independent (a future
/// reshape of one doesn't perturb the other).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus_random::NIGHTLY_SEEDHASH_COUNT;

    /// Sanity: the `NIGHTLY_*` constants match the canonical
    /// arrays' lengths. A drift would break the
    /// `canonical_index = i * NIGHTLY_DATA_PER_SEEDHASH + j`
    /// formula in [`run`]. The structural T16 stub in
    /// `canonical_outputs.rs` also asserts the random-hash
    /// length; pinning both invariants from this side too means a
    /// drift catches in both places.
    #[test]
    fn canonical_arrays_match_nightly_sizing() {
        assert_eq!(
            CANONICAL_RANDOM_HASHES.len(),
            NIGHTLY_SEEDHASH_COUNT * NIGHTLY_DATA_PER_SEEDHASH,
            "canonical hash array sized for nightly cadence"
        );
        assert_eq!(
            CANONICAL_CACHE_SHAS.len(),
            NIGHTLY_SEEDHASH_COUNT,
            "canonical cache-SHA array sized for nightly cadence"
        );
    }

    /// `CorrectnessError::Display` emits the seedhash, indices,
    /// and hex bytes for each variant. The string-content checks
    /// are deliberately loose (substring) so a future format-string
    /// reshape doesn't churn the tests.
    #[test]
    fn correctness_error_display_includes_attribution() {
        let seedhash = Seedhash::from_bytes([0x42; 32]);

        let e = CorrectnessError::HashMismatch {
            seedhash,
            canonical_index: 17,
            data_len: 256,
            rust_hash: [0xaa; 32],
            c_hash: [0xbb; 32],
        };
        let s = format!("{e}");
        assert!(s.contains("hash mismatch"), "got: {s}");
        assert!(s.contains("canonical_index 17"), "got: {s}");
        assert!(s.contains("data_len 256"), "got: {s}");
        assert!(s.contains("aaaaaaaa"), "got: {s}");
        assert!(s.contains("bbbbbbbb"), "got: {s}");

        let e = CorrectnessError::CanonicalCacheMismatch {
            seedhash,
            nightly_seedhash_index: 5,
            actual_sha: [0xcc; 32],
            canonical_sha: [0xdd; 32],
        };
        let s = format!("{e}");
        assert!(s.contains("canonical-cache mismatch"), "got: {s}");
        assert!(s.contains("nightly index 5"), "got: {s}");

        let e = CorrectnessError::CanonicalHashMismatch {
            seedhash,
            canonical_index: 33,
            actual_hash: [0xee; 32],
            canonical_hash: [0xff; 32],
        };
        let s = format!("{e}");
        assert!(s.contains("canonical-hash mismatch"), "got: {s}");
        assert!(s.contains("canonical_index 33"), "got: {s}");
    }

    /// `hex_lower` round-trips a 32-byte array to a 64-char string
    /// of lowercase hex. Pins the display format that
    /// `CorrectnessError::Display` emits.
    #[test]
    fn hex_lower_round_trips() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let s = hex_lower(&bytes);
        assert_eq!(s.len(), 64);
        assert_eq!(
            s,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
    }
}
