// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D4 — the served payload: a **real archival shard**, pre-loaded to memory.
//!
//! # Shape and provenance
//!
//! An archival shard is one frozen level-2 curve-tree segment:
//! `SEGMENT_LEAF_COUNT` = 25 992 leaves × 128 bytes ≈ 3.33 MB
//! (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §5.2; the leaf width is pinned by
//! `shekyl_fcmp::tree::construct_leaf`, which packs `O.x ‖ I.x ‖ C.x ‖ h_pqc`).
//!
//! The ruling for this spike is that the payload is a **real shard from a regtest
//! chain, not synthetic bytes**, and this module refuses to paper over that: it
//! loads a fixture file produced by the extraction step and **fails loudly** if
//! the file is absent or the wrong size. There is deliberately no
//! `synthetic_shard()` fallback — a fallback is exactly how a measurement quietly
//! stops measuring what it claims to.
//!
//! # Why the load is outside the timed path
//!
//! The measurement is of a *transport*. [`ShardFixture::load`] reads the file once
//! into an [`Arc<Vec<u8>>`] which every connection then serves from memory, so no
//! disk read sits inside a timed fetch. This is recorded because a disk read in
//! the timed path would inflate the tail with an artefact of the measuring host
//! rather than of Tor.
//!
//! # Feasibility, measured rather than assumed (the D4 pre-flight)
//!
//! Both halves of the charter's pre-flight were checked at source and on the box:
//!
//! - **Can regtest produce ≥ 25 992 leaves in reasonable wall-clock?** Yes.
//!   Measured on this box at `--fixed-difficulty 1`: **≈ 0.65 s/block**, with
//!   `leaf_count` tracking height 1:1 behind a constant ~60-block maturity lag
//!   (`DEFAULT_LOCK_WINDOW`). Shard 0 additionally needs the freeze gate
//!   `tip − end_block_height ≥ SPENDABLE_AGE(60) + REORG_MARGIN(720)`, so the
//!   target height is ≈ 25 992 + 60 + 780 ≈ 26 832 blocks.
//! - **Does an extraction path exist?** Yes, and it is a *batched* RPC rather than
//!   the 684 round-trips a per-chunk read would imply:
//!   `COMMAND_RPC_GET_CURVE_TREE_PATH` takes a **vector** of `output_indices` and
//!   returns, per entry, a `chunk_outputs_blob` of `[O:32][I:32][C:32][h_pqc:32]`
//!   for every leaf in that leaf-chunk (`core_rpc_server_commands_defs.h`). Those
//!   are compressed Ed25519 points, so the 128-byte *leaf* is then rebuilt
//!   locally with `shekyl_fcmp::tree::construct_leaf` — the same function
//!   `shekyl_curve_tree::recon::try_build_leaf` uses on the wallet path.
//!
//! So D4 is a cost, not a blocker, and the halt does not fire.

use std::path::Path;
use std::sync::Arc;

/// Leaves in one frozen level-2 segment (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`
/// §5.2: `SELENE_CHUNK_WIDTH · HELIOS_CHUNK_WIDTH · SELENE_CHUNK_WIDTH`
/// = 38 · 18 · 38).
///
/// Duplicated as a literal rather than imported: this crate is disposable and
/// must not become a consumer that a future constants change has to sweep. The
/// authoritative value is `shekyl_archival_retention::segment_freeze`'s
/// `SEGMENT_LEAF_COUNT`, and [`ShardFixture::load`]'s size check is what catches a
/// drift between them.
pub const SEGMENT_LEAF_COUNT: usize = 25_992;

/// Bytes per curve-tree leaf (`construct_leaf`: four 32-byte fields).
pub const LEAF_BYTES: usize = 128;

/// Exact size of a shard payload — the number the §8.3 gate is about.
pub const SHARD_BYTES: usize = SEGMENT_LEAF_COUNT * LEAF_BYTES;

/// Why a fixture could not be loaded. Every arm is loud and actionable (rule 82);
/// none of them degrade to a synthetic payload.
#[derive(Debug)]
pub enum FixtureError {
    /// The fixture file is not present. The measurement cannot run: produce it
    /// with the extraction step first.
    Missing {
        /// The path that was tried.
        path: String,
    },
    /// The file exists but is not a whole shard. Either the extraction stopped
    /// early or `SEGMENT_LEAF_COUNT` has drifted from the consensus constant.
    WrongSize {
        /// Bytes actually read.
        got: usize,
        /// Bytes a shard must be.
        want: usize,
    },
    /// The file could not be read.
    Io(std::io::Error),
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { path } => write!(
                f,
                "shard fixture not found at {path}: the PD-F-2 measurement serves a REAL \
                 regtest shard and has no synthetic fallback -- run the extraction step \
                 (mine a regtest chain past the shard-0 freeze, then batch-read the \
                 segment's leaf chunks) and write the {SHARD_BYTES}-byte fixture"
            ),
            Self::WrongSize { got, want } => write!(
                f,
                "shard fixture is {got} bytes, not {want}: extraction stopped early, or \
                 SEGMENT_LEAF_COUNT drifted from the consensus constant"
            ),
            Self::Io(e) => write!(f, "shard fixture read failed: {e}"),
        }
    }
}

impl std::error::Error for FixtureError {}

/// A shard payload held in memory, ready to serve.
pub struct ShardFixture {
    bytes: Arc<Vec<u8>>,
}

impl ShardFixture {
    /// Load a shard fixture, refusing anything that is not exactly one shard.
    ///
    /// The size check is the honesty gate: it is what makes "we measured a 3.33 MB
    /// shard fetch" a checkable claim rather than a description of intent.
    pub fn load(path: &Path) -> Result<Self, FixtureError> {
        if !path.exists() {
            return Err(FixtureError::Missing {
                path: path.display().to_string(),
            });
        }
        let bytes = std::fs::read(path).map_err(FixtureError::Io)?;
        if bytes.len() != SHARD_BYTES {
            return Err(FixtureError::WrongSize {
                got: bytes.len(),
                want: SHARD_BYTES,
            });
        }
        Ok(Self {
            bytes: Arc::new(bytes),
        })
    }

    /// The payload, shareable across connections without copying.
    #[must_use]
    pub fn bytes(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.bytes)
    }

    /// Payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always `false` for a loaded fixture (a zero-length one cannot pass
    /// [`Self::load`]); present because clippy asks for it beside `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for ShardFixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardFixture")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn shard_size_is_the_gate_s_number() {
        // 25 992 × 128 = 3 326 976 B ≈ 3.33 MB — the size §8.3 asks about. If this
        // number moves, the measurement is answering a different question.
        assert_eq!(SHARD_BYTES, 3_326_976);
        // "≈ 3.33 MB" as the design docs state it, checked in integer bytes so
        // the assertion needs no lossy usize→f64 cast.
        assert!((3_320_000..3_340_000).contains(&SHARD_BYTES));
    }

    #[test]
    fn a_missing_fixture_fails_loudly_and_names_the_remedy() {
        // The no-silent-fallback property: absence must be an error whose message
        // tells the operator what to produce, never a synthetic payload.
        let err = ShardFixture::load(Path::new("/nonexistent/shard.bin"))
            .expect_err("a missing fixture must not load");
        assert!(matches!(err, FixtureError::Missing { .. }));
        let msg = err.to_string();
        assert!(msg.contains("no synthetic fallback"));
        assert!(msg.contains(&SHARD_BYTES.to_string()));
    }

    #[test]
    fn a_short_fixture_is_refused() {
        // Catches a truncated extraction — the failure mode that would otherwise
        // produce a fast, wrong measurement.
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(&vec![0u8; SHARD_BYTES - 128]).expect("write");
        let err = ShardFixture::load(f.path()).expect_err("a short fixture must not load");
        match err {
            FixtureError::WrongSize { got, want } => {
                assert_eq!(want, SHARD_BYTES);
                assert_eq!(got, SHARD_BYTES - 128);
            }
            other => panic!("expected WrongSize, got {other:?}"),
        }
    }

    #[test]
    fn an_exact_shard_loads() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(&vec![0xABu8; SHARD_BYTES]).expect("write");
        let fixture = ShardFixture::load(f.path()).expect("an exact-size fixture loads");
        assert_eq!(fixture.len(), SHARD_BYTES);
        assert!(!fixture.is_empty());
        // Shared, not copied: two handles to one buffer.
        assert!(Arc::ptr_eq(&fixture.bytes(), &fixture.bytes()));
    }
}
