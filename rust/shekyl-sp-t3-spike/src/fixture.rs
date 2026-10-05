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
//! `shekyl_fcmp::tree::construct_leaf`, which packs `O.x ‖ I.x ‖ C.x ‖ CM.x`
//! — the 4th scalar is the `PL-D3` leaf commitment's x-coordinate).
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
//! - **Does an extraction path exist?** It did at the time of the measurement
//!   (records-was; the RPC below was removed 2026-09-18 — `SOK-10` Q7 → A, see
//!   `bins/extract_shard.rs`). It was a *batched* RPC rather than
//!   the 684 round-trips a per-chunk read would imply:
//!   `COMMAND_RPC_GET_CURVE_TREE_PATH` takes a **vector** of `output_indices` and
//!   returns, per entry, a `chunk_outputs_blob` of `[O:32][I:32][C:32][CM.x:32]`
//!   for every leaf in that leaf-chunk (`core_rpc_server_commands_defs.h`). The
//!   first three fields are compressed Ed25519 points and the 4th is the leaf's
//!   scalar as the chunk carries it (`PL-D3`: the commitment point itself is not
//!   served), so the 128-byte *leaf* is rebuilt locally with
//!   `shekyl_fcmp::tree::leaf_from_chunk_entry` — the constructor for exactly
//!   this served-chunk shape.
//!
//! So D4 is a cost, not a blocker, and the halt does not fire.

use std::path::Path;
use std::sync::Arc;

use shekyl_p_serve::{ProviderError, ShardBody, ShardProvider};

/// Leaves in one frozen level-2 segment (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`
/// §5.2: `SELENE_CHUNK_WIDTH · HELIOS_CHUNK_WIDTH · SELENE_CHUNK_WIDTH`
/// = 38 · 18 · 38), read from its one owner. `shekyl-archival-retention`'s
/// consensus `SEGMENT_LEAF_COUNT` is const-asserted equal to the same function,
/// so the fixture's size and the server's unit cannot drift apart.
pub const SEGMENT_LEAF_COUNT: usize = shekyl_fcmp::tree::leaves_per_segment();

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
    /// early or the file was extracted under another segment size.
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
                 the file was extracted under another segment size"
            ),
            Self::Io(e) => write!(f, "shard fixture read failed: {e}"),
        }
    }
}

impl std::error::Error for FixtureError {}

/// A shard payload held in memory, ready to serve.
pub struct ShardFixture {
    bytes: Arc<[u8]>,
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
            bytes: Arc::from(bytes.into_boxed_slice()),
        })
    }

    /// The payload, shareable across connections without copying — the
    /// exact shape `shekyl_p_serve::ShardBody::flat` takes, so serving it
    /// costs an `Arc` clone and nothing else.
    #[must_use]
    pub fn bytes(&self) -> Arc<[u8]> {
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

/// Serves the one pre-loaded payload for **every** shard id — the spike's
/// half of `shekyl_p_serve`'s [`ShardProvider`] seam.
///
/// The production provider (`shekyl_p_serve::StoreShardProvider`) selects a
/// frozen segment by id out of a real store. This crate measures a
/// *transport*: the fixture **is** the shard, the id is only the part of the
/// URL the timing is taken around, and no store exists to select from. That
/// difference is the whole reason the seam is a trait — it is what lets the
/// spike drive the production serving loop, byte for byte, instead of
/// carrying a second copy of it that drifts (as it did, until the copy was
/// deleted).
pub struct FixtureShardProvider {
    /// The served objects, indexed by shard id.
    objects: Vec<Arc<[u8]>>,
}

impl FixtureShardProvider {
    /// Wrap one pre-loaded payload, served as shard 0.
    #[must_use]
    pub fn new(payload: Arc<[u8]>) -> Self {
        Self::with_objects(vec![payload])
    }

    /// Serve several payloads, shard `i` being `objects[i]`. An id past the
    /// end is the ordinary miss.
    #[must_use]
    pub fn with_objects(objects: Vec<Arc<[u8]>>) -> Self {
        Self { objects }
    }
}

impl ShardProvider for FixtureShardProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        // `flat` refuses a payload that is not a whole number of leaves —
        // the served frame declares a leaf count, so such bytes have no
        // representable header. [`ShardFixture::load`] already enforces
        // exactly [`SHARD_BYTES`], so the `None` arm is the guard for a
        // payload handed to [`FixtureShardProvider::new`] directly, and it
        // renders the ordinary miss rather than a body no witness could
        // verify.
        let Some(payload) = usize::try_from(shard_id)
            .ok()
            .and_then(|i| self.objects.get(i))
        else {
            return Ok(None);
        };
        Ok(ShardBody::flat(Arc::clone(payload)))
    }
}

impl std::fmt::Debug for FixtureShardProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lens: Vec<usize> = self.objects.iter().map(|o| o.len()).collect();
        f.debug_struct("FixtureShardProvider")
            .field("lens", &lens)
            .finish()
    }
}

/// The multi-size W₂ run's objects (`ARCHIVAL_SHARD_T_DERIVATION.md` §4.1): the real
/// shard and two sizes derived from **its own bytes**, served as shard ids
/// `0` (the shard, 1×), `1` (its first half, ½×) and `2` (its first quarter, ¼×) —
/// a 4× byte span, every size a whole number of leaves.
///
/// The shard is the top of the ladder because it is the largest object the
/// production frame can carry: `ServedFrameHeader::for_segment` refuses a leaf
/// count past one segment, so a larger object is unservable, not merely unusual
/// (the client's `max_body_bytes` bound of two segments is headroom for padding,
/// not a second segment).
///
/// Nothing here is synthetic in the sense the honesty gate forbids: every byte
/// served is a byte of the extracted shard. What varies is only how many of them
/// are sent, and a Tor transit of opaque, uncompressed bytes does not depend on
/// their values — so the size is the one variable the ladder moves.
#[must_use]
pub fn size_ladder(fixture: &ShardFixture) -> Vec<Arc<[u8]>> {
    let one = fixture.bytes();
    let half: Arc<[u8]> = Arc::from(&one[..one.len() / 2]);
    let quarter: Arc<[u8]> = Arc::from(&one[..one.len() / 4]);
    vec![one, half, quarter]
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

    /// The body a reader actually receives is the frame header plus the
    /// shard, and the apparatus derives that number through the production
    /// contract rather than taking it from a caller. Pinned here because the
    /// first version of the harness compared against `SHARD_BYTES` directly,
    /// and when RF-D4's frame landed every probe went stale at once.
    ///
    /// `4` is the hand-derived header for a full unpadded segment
    /// (`88 CB 01 00`, `ARCHIVAL_RESPONSE_FORMAT.md` §3.5).
    #[test]
    fn served_body_is_the_frame_plus_the_shard() {
        let payload: std::sync::Arc<[u8]> = vec![0u8; SHARD_BYTES].into();
        let body = shekyl_p_serve::ShardBody::flat(payload).expect("a full shard is framable");
        assert_eq!(body.header().framed_len(), (SHARD_BYTES + 4) as u64);
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

    fn patterned_fixture() -> ShardFixture {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        let bytes: Vec<u8> = (0..SHARD_BYTES)
            .map(|i| u8::try_from(i % 251).expect("below 251"))
            .collect();
        f.write_all(&bytes).expect("write");
        ShardFixture::load(f.path()).expect("an exact-size fixture loads")
    }

    /// The ladder is 1×, ½×, ¼× of the real shard, a 4× span; every size is a
    /// whole number of leaves and framable by the production frame, and every
    /// byte is the shard's.
    #[test]
    fn the_size_ladder_is_the_shard_at_one_half_and_quarter() {
        let fixture = patterned_fixture();
        let ladder = size_ladder(&fixture);
        let lens: Vec<usize> = ladder.iter().map(|o| o.len()).collect();
        assert_eq!(lens, [SHARD_BYTES, SHARD_BYTES / 2, SHARD_BYTES / 4]);
        for object in &ladder {
            assert_eq!(
                object.len() % LEAF_BYTES,
                0,
                "{} is not whole leaves",
                object.len()
            );
            assert!(shekyl_p_serve::ShardBody::flat(Arc::clone(object)).is_some());
        }
        let one = fixture.bytes();
        assert!(
            Arc::ptr_eq(&ladder[0], &one),
            "shard 0 is the fixture itself"
        );
        assert_eq!(&ladder[1][..], &one[..SHARD_BYTES / 2]);
        assert_eq!(&ladder[2][..], &one[..SHARD_BYTES / 4]);
        // One leaf past a segment is unservable — why the shard tops the ladder.
        let past: Arc<[u8]> = vec![0u8; SHARD_BYTES + LEAF_BYTES].into();
        assert!(shekyl_p_serve::ShardBody::flat(past).is_none());
    }

    /// Shard `i` is object `i`; past the end is the ordinary miss.
    #[test]
    fn the_provider_serves_each_object_by_shard_id() {
        let objects: Vec<Arc<[u8]>> = vec![
            vec![1u8; LEAF_BYTES].into(),
            vec![2u8; 2 * LEAF_BYTES].into(),
        ];
        let provider = FixtureShardProvider::with_objects(objects);
        for (id, leaves) in [(0u64, 1u64), (1, 2)] {
            let body = provider.shard_bytes(id).expect("ok").expect("served");
            let payload = leaves * u64::try_from(LEAF_BYTES).expect("fits");
            assert!(body.header().framed_len() > payload);
        }
        assert!(provider.shard_bytes(2).expect("ok").is_none());
    }
}
