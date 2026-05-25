// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! R1-D14 cache-equivalence precondition (§5.1.7).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.7, §3 R1-D14,
//! and §3.17 R5-D1, this module asserts that the Rust verifier's
//! 256-MiB Argon2d-derived cache memory is byte-identical to the C
//! reference's `randomx_get_cache_memory(cache)` return for the
//! same seedhash. The byte-equality of the cache is the precondition
//! for the §5.1.10 T1 / T5 hash byte-equality tests; a divergent
//! cache produces divergent program execution and divergent hashes,
//! and the per-PR run aborts the corpus pass for that seedhash
//! before the per-data tests run.
//!
//! ## Two paths (§5.1.7 + T3 + T4)
//!
//! - **Default path: SHA-256 fingerprint comparison (T3, R1-D14 §F1).**
//!   [`assert_equivalent`] streams both sides' cache memory through
//!   [`Sha256`] (one 32-byte digest each) and compares the digests.
//!   Per-iteration memory cost is 1 KiB (Rust side; the C side
//!   borrows the cache view from [`COracleSession::cache_bytes`] in
//!   one chunk because the C cache memory is contiguous). Per-PR
//!   cadence; failure surfaces a [`PreconditionMismatch`].
//! - **Diagnostic path: byte-by-byte diff (T4, R1-D14 §F1's
//!   `--debug-cache-divergence` extension).** [`byte_diff`] walks
//!   both sides in 1-KiB blocks and, on the first divergent byte,
//!   returns a [`ByteDivergence`] with the absolute offset and a
//!   ±64-byte window of both caches surrounding the offset. The
//!   diagnostic path is invoked manually post-T3-failure via the
//!   `--debug-cache-divergence --seedhash <hex>` flag combination
//!   (wired in `main.rs`); per-PR runs do not pay the byte-diff
//!   memory cost.
//!
//! ## Why streaming, not bulk allocation
//!
//! The Rust side's [`PreparedCache::cache_block_bytes_for_testing`]
//! is a visitor-style 1-KiB-block iterator per §5.3.3's drop-discipline
//! memory budget (no `Vec<u8>` materialization of the full 256 MiB).
//! The harness consumes the iterator directly through `Sha256::update`
//! per call site without buffering. The C side's
//! `randomx_get_cache_memory` returns a single 256-MiB `&[u8]` view
//! through [`COracleSession::cache_bytes`]; the C cache is already
//! contiguous in memory so the view costs nothing.
//!
//! Per the §3.17 R5-D1 amendment, the only `test-internals`-gated
//! consumption in the harness is this module's call to
//! `prepared.cache_block_bytes_for_testing()`. The §3.18 R6-D4
//! canonical-output discipline pins the expected SHA-256 in
//! [`crate::canonical_outputs::CANONICAL_CACHE_SHAS`]; T16 (§6
//! cadence per-PR) cross-checks the Rust side against the canonical
//! pin in addition to the C side's runtime fingerprint.

use std::fmt;

use sha2::{Digest, Sha256};
use shekyl_pow_randomx::{PreparedCache, Seedhash};

use crate::c_oracle::{COracleSession, RANDOMX_CACHE_SIZE_BYTES};
use crate::rust_subject::RustSubjectSession;

/// Number of bytes to include on either side of the first divergent
/// offset when surfacing a [`ByteDivergence`] (T4 §F1 +
/// §5.1.7's "first divergent offset + ±64-byte window logged"
/// disposition).
///
/// The 64-byte choice is pinned per R1-D14 §F1: aligned with the
/// Argon2d block-substructure (each Argon2d "block" is 1024 B, so
/// 128 B of context spans two 64-B sub-rows that the C reference's
/// `argon2_core.c` mixing function operates on). A larger window
/// risks log-output bloat on cascading divergences; a smaller
/// window may not surface the upstream cause of a substitution
/// mismatch.
pub const DIVERGENCE_WINDOW_HALF_WIDTH: usize = 64;

/// SHA-256 fingerprint of the Rust verifier's 256-MiB Argon2d-derived
/// cache memory for the seedhash `prepared` was derived from.
///
/// Streams the [`PreparedCache::cache_block_bytes_for_testing`]
/// visitor iterator through [`Sha256`]; per-iteration stack cost is
/// 1 KiB; total digest is 32 bytes. Matches the C-side
/// [`COracleSession::cache_sha256`] under the R1-D14 precondition
/// when both sides agree on the cache memory.
///
/// **`test-internals` consumption site.** This is the only call to
/// `PreparedCache::cache_block_bytes_for_testing` in the harness;
/// the §3.17 R5-D1 discipline + §5.7 scope-creep rejection criterion
/// require any new call site outside this module to surface in a
/// plan-doc round.
pub fn rust_cache_sha256(prepared: &PreparedCache) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for block in prepared.cache_block_bytes_for_testing() {
        hasher.update(block);
    }
    hasher.finalize().into()
}

/// Default-path precondition failure: SHA-256(Rust cache) !=
/// SHA-256(C cache). Surfaced by [`assert_equivalent`] (T3).
///
/// Carries both digests + the seedhash so the eventual C9 §5.1.14
/// failure-output JSON schema can serialize the failure without
/// re-running the precondition. The `Display` impl emits a
/// human-readable form for `cargo test` failure output; the JSON
/// form is added at C9 alongside the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionMismatch {
    /// Seedhash whose `(rust, c)` caches diverged.
    pub seedhash: Seedhash,
    /// SHA-256 of the Rust verifier's cache memory.
    pub rust_sha: [u8; 32],
    /// SHA-256 of the C reference's cache memory.
    pub c_sha: [u8; 32],
}

impl fmt::Display for PreconditionMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cache-precondition mismatch for seedhash {}: rust_sha={}, c_sha={}",
            self.seedhash,
            hex_lower(&self.rust_sha),
            hex_lower(&self.c_sha)
        )
    }
}

impl std::error::Error for PreconditionMismatch {}

/// Assert that the Rust subject's cache memory has the same SHA-256
/// digest as the C oracle's cache memory.
///
/// Default-path precondition per §5.1.7 + R1-D14 + T3. Both sessions
/// must have been constructed from the same seedhash; this function
/// also asserts that invariant (the seedhash field comes from the
/// Rust subject, but a mismatch between the two sides' seedhash
/// fields would indicate a mode-module wiring error, not a
/// precondition failure, and is therefore a `debug_assert!`).
///
/// # Errors
///
/// Returns [`PreconditionMismatch`] if the two digests disagree.
///
/// # Cost
///
/// One full traversal of the 256-MiB cache through SHA-256 on each
/// side (~150–250 ms per side on a 2026-era x86-64 release build).
/// Per-PR cadence; the cost is amortized across the per-seedhash
/// data tests that run after the precondition succeeds.
pub fn assert_equivalent(
    rust_subject: &RustSubjectSession,
    c_oracle: &COracleSession,
) -> Result<(), PreconditionMismatch> {
    debug_assert_eq!(
        rust_subject.seedhash(),
        c_oracle.seedhash(),
        "cache-precondition called with mismatched session seedhashes"
    );
    let rust_sha = rust_cache_sha256(rust_subject.prepared());
    let c_sha = c_oracle.cache_sha256();
    if rust_sha == c_sha {
        Ok(())
    } else {
        Err(PreconditionMismatch {
            seedhash: *rust_subject.seedhash(),
            rust_sha,
            c_sha,
        })
    }
}

/// Diagnostic-path precondition failure: first divergent offset +
/// ±[`DIVERGENCE_WINDOW_HALF_WIDTH`] context window. Surfaced by
/// [`byte_diff`] when invoked under `--debug-cache-divergence`.
///
/// The windows are bounded to the cache's actual range (`0 ..
/// RANDOMX_CACHE_SIZE_BYTES`) so divergences near the cache's
/// start or end produce a smaller (but still informative) window
/// rather than indexing out of bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteDivergence {
    /// Seedhash whose `(rust, c)` caches diverged.
    pub seedhash: Seedhash,
    /// Absolute byte offset of the first divergent byte
    /// (`0 .. RANDOMX_CACHE_SIZE_BYTES`).
    pub offset: usize,
    /// Inclusive start offset of the window in both caches.
    pub window_start: usize,
    /// Rust verifier's bytes from `window_start` to (at most)
    /// `window_start + 2 * DIVERGENCE_WINDOW_HALF_WIDTH + 1`.
    pub rust_window: Vec<u8>,
    /// C reference's bytes over the same range.
    pub c_window: Vec<u8>,
}

impl fmt::Display for ByteDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "cache-precondition byte-diff divergence for seedhash {}:",
            self.seedhash
        )?;
        writeln!(
            f,
            "  first divergent offset: {} (0x{:08x}); window: [{}, {})",
            self.offset,
            self.offset,
            self.window_start,
            self.window_start + self.rust_window.len()
        )?;
        writeln!(f, "  rust: {}", hex_lower(&self.rust_window))?;
        write!(f, "  c:    {}", hex_lower(&self.c_window))
    }
}

impl std::error::Error for ByteDivergence {}

/// Byte-by-byte diff of the two caches; on first divergence returns
/// a [`ByteDivergence`] with the offset + ±64-byte window.
///
/// Diagnostic-path precondition per §5.1.7 + R1-D14 + T4. Invoked
/// manually post-T3-failure via the `--debug-cache-divergence
/// --seedhash <hex>` flag combination.
///
/// # Cost
///
/// One full traversal of the 256-MiB cache on each side, plus the
/// 1-KiB-per-iteration block-compare cost. Roughly comparable to
/// the SHA-256 default path but with no hashing overhead. The
/// peak-memory cost is bounded at 1 KiB on the Rust side (the
/// visitor iterator yields one block at a time) and ~256 MiB on
/// the C side (the contiguous cache view), well within the
/// strict-mode 512-MiB peak per R1-D14 §F1.
///
/// # Errors
///
/// Returns [`ByteDivergence`] on first divergent byte.
pub fn byte_diff(
    rust_subject: &RustSubjectSession,
    c_oracle: &COracleSession,
) -> Result<(), ByteDivergence> {
    debug_assert_eq!(
        rust_subject.seedhash(),
        c_oracle.seedhash(),
        "byte_diff called with mismatched session seedhashes"
    );
    let c_bytes = c_oracle.cache_bytes();
    debug_assert_eq!(c_bytes.len(), RANDOMX_CACHE_SIZE_BYTES);
    let mut absolute_offset: usize = 0;
    for rust_block in rust_subject.prepared().cache_block_bytes_for_testing() {
        let block_len = rust_block.len();
        let c_block = &c_bytes[absolute_offset..absolute_offset + block_len];
        if let Some(offset_in_block) = find_first_divergence(&rust_block, c_block) {
            let divergent_offset = absolute_offset + offset_in_block;
            let (window_start, rust_window, c_window) =
                build_divergence_window(divergent_offset, rust_subject, c_bytes);
            return Err(ByteDivergence {
                seedhash: *rust_subject.seedhash(),
                offset: divergent_offset,
                window_start,
                rust_window,
                c_window,
            });
        }
        absolute_offset += block_len;
    }
    debug_assert_eq!(absolute_offset, RANDOMX_CACHE_SIZE_BYTES);
    Ok(())
}

/// Return the index of the first divergent byte between two equal-
/// length slices, or `None` if the slices are equal.
///
/// Pulled out as a free function so the C6 unit tests can exercise
/// the comparison logic without paying the full 256-MiB cache cost.
fn find_first_divergence(rust: &[u8], c: &[u8]) -> Option<usize> {
    debug_assert_eq!(rust.len(), c.len());
    rust.iter().zip(c.iter()).position(|(a, b)| a != b)
}

/// Build the ±[`DIVERGENCE_WINDOW_HALF_WIDTH`] window for a byte
/// divergence at `offset` in both caches.
///
/// The Rust side re-iterates `cache_block_bytes_for_testing` to
/// reach the window's blocks (the iterator is consumed once per
/// pass; the second pass is bounded to the at-most-two 1-KiB blocks
/// that overlap the window, not the full 256 MiB). The C side
/// slices directly from the contiguous `cache_bytes` view.
fn build_divergence_window(
    offset: usize,
    rust_subject: &RustSubjectSession,
    c_bytes: &[u8],
) -> (usize, Vec<u8>, Vec<u8>) {
    let window_start = offset.saturating_sub(DIVERGENCE_WINDOW_HALF_WIDTH);
    let window_end = (offset + DIVERGENCE_WINDOW_HALF_WIDTH + 1).min(RANDOMX_CACHE_SIZE_BYTES);
    let window_len = window_end - window_start;
    let c_window = c_bytes[window_start..window_end].to_vec();
    let mut rust_window: Vec<u8> = Vec::with_capacity(window_len);
    let mut absolute: usize = 0;
    for rust_block in rust_subject.prepared().cache_block_bytes_for_testing() {
        let block_len = rust_block.len();
        let block_start = absolute;
        let block_end = absolute + block_len;
        if block_end <= window_start {
            absolute = block_end;
            continue;
        }
        if block_start >= window_end {
            break;
        }
        let copy_start = window_start.saturating_sub(block_start);
        let copy_end = (window_end - block_start).min(block_len);
        rust_window.extend_from_slice(&rust_block[copy_start..copy_end]);
        absolute = block_end;
    }
    debug_assert_eq!(rust_window.len(), window_len);
    (window_start, rust_window, c_window)
}

/// Format bytes as lowercase-hex without separators. Used by both
/// `PreconditionMismatch::Display` and `ByteDivergence::Display`
/// to keep the failure output consistent across the two paths.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Equal slices return `None`.
    #[test]
    fn find_first_divergence_equal_slices_returns_none() {
        let a = [0u8; 64];
        let b = [0u8; 64];
        assert_eq!(find_first_divergence(&a, &b), None);
    }

    /// Divergence at index 0 returns `Some(0)`.
    #[test]
    fn find_first_divergence_at_start() {
        let a = [0u8; 16];
        let mut b = [0u8; 16];
        b[0] = 1;
        assert_eq!(find_first_divergence(&a, &b), Some(0));
    }

    /// Divergence in the middle returns the first index.
    #[test]
    fn find_first_divergence_in_middle() {
        let a = [0u8; 16];
        let mut b = [0u8; 16];
        b[7] = 1;
        b[9] = 1; // a second divergence is ignored
        assert_eq!(find_first_divergence(&a, &b), Some(7));
    }

    /// Divergence at the last index returns the correct index.
    #[test]
    fn find_first_divergence_at_end() {
        let a = [0u8; 16];
        let mut b = [0u8; 16];
        b[15] = 1;
        assert_eq!(find_first_divergence(&a, &b), Some(15));
    }

    /// `PreconditionMismatch`'s `Display` impl is self-describing.
    #[test]
    fn precondition_mismatch_display_contains_both_digests() {
        let mismatch = PreconditionMismatch {
            seedhash: Seedhash::from_bytes([0x11; 32]),
            rust_sha: [0x22; 32],
            c_sha: [0x33; 32],
        };
        let s = format!("{mismatch}");
        assert!(s.contains("rust_sha="), "got: {s}");
        assert!(s.contains("c_sha="), "got: {s}");
        // 64-char lowercase-hex for both
        assert!(s.contains(&"22".repeat(32)), "got: {s}");
        assert!(s.contains(&"33".repeat(32)), "got: {s}");
    }

    /// `ByteDivergence`'s `Display` impl includes the offset (both
    /// decimal and hex), the window range, and the two hex byte
    /// windows.
    #[test]
    fn byte_divergence_display_contains_offset_and_windows() {
        let div = ByteDivergence {
            seedhash: Seedhash::from_bytes([0xaa; 32]),
            offset: 0x1234,
            window_start: 0x11f4,
            rust_window: vec![0x55; 129],
            c_window: vec![0x66; 129],
        };
        let s = format!("{div}");
        assert!(s.contains("4660"), "decimal offset; got: {s}");
        assert!(s.contains("0x00001234"), "hex offset; got: {s}");
        assert!(s.contains(&"55".repeat(129)), "rust window; got: {s}");
        assert!(s.contains(&"66".repeat(129)), "c window; got: {s}");
    }

    /// `DIVERGENCE_WINDOW_HALF_WIDTH` matches the R1-D14 §F1 64-byte
    /// pin. Pinned here so a future refactor that changes the
    /// constant has to update both this assertion and the doc-comment.
    #[test]
    fn divergence_window_half_width_pinned_at_64() {
        assert_eq!(DIVERGENCE_WINDOW_HALF_WIDTH, 64);
    }

    /// `hex_lower` emits the expected format for a known input.
    #[test]
    fn hex_lower_emits_lowercase_no_separator() {
        assert_eq!(hex_lower(&[0x0a, 0xb1, 0xc2]), "0ab1c2");
        assert_eq!(hex_lower(&[]), "");
    }
}
