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

use shekyl_p_fetch::ExpectedShard;
use shekyl_p_serve::{ProviderError, ShardBody, ShardProvider};
use shekyl_types::{ArchivalLength, ShardId, TxHash, SHARD_LENGTH};
use shekyl_wire::shard_frame::{encode_frame, rows_of, FrameTx};
use shekyl_wire::TxidParts;

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

/// The txid every framed object's one row carries. Not on the wire and
/// not checked against anything but itself: the client's content check is
/// the row's hashes, and the txid is what the view hash binds them to.
const OBJECT_TXID: TxHash = TxHash::from_bytes([0x5a; 32]);

/// One served object as the wire now carries it (`SF-D8` amendment
/// 2026-10-08): the payload framed as a **single transaction's prunable
/// region** in `shekyl_wire::shard_frame`, with the one row a requester
/// holds for it.
///
/// The rig measures a transport, and the transport since the amendment is
/// a tx-range frame the client takes apart against rows it already holds.
/// Framing the payload as one transaction keeps every served byte a byte
/// of the extracted shard (plus a handful of frame bytes) and gives the
/// client a real expectation to verify, so the production content check
/// is in the timed path exactly as it is for a daemon.
#[derive(Clone, Debug)]
pub struct FramedObject {
    frame: Arc<[u8]>,
    payload_len: usize,
    row: TxidParts,
}

impl FramedObject {
    /// Frame `payload` as one transaction with no `pqc_auths`.
    #[must_use]
    pub fn new(payload: &[u8]) -> Self {
        let tx = FrameTx {
            pqc_auth_count: 0,
            pqc_auths: &[],
            prunable: payload,
        };
        let (pqc_auth_hash, prunable_hash, archival_len) = rows_of(&tx);
        Self {
            frame: Arc::from(encode_frame(&[tx])),
            payload_len: payload.len(),
            row: TxidParts {
                hash: OBJECT_TXID,
                pqc_auth_hash,
                prunable_hash,
                archival_len,
            },
        }
    }

    /// The bytes the endpoint writes ahead of the envelope.
    #[must_use]
    pub fn frame(&self) -> Arc<[u8]> {
        Arc::clone(&self.frame)
    }

    /// The payload's length: the archival length the client verifies and
    /// returns, and the figure the apparatus compares a fetch against.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// What a requester expects of this object served as shard `shard_id`:
    /// the one row, placed so the range closes the shard — at the shard's
    /// start when the payload is `W` or longer, else `W` short of its end.
    ///
    /// # Panics
    ///
    /// If `shard_id` is past the last representable shard. The rig serves
    /// shards `0..3`.
    #[must_use]
    pub fn expectation(&self, shard_id: u64) -> ExpectedShard {
        let w = SHARD_LENGTH.to_raw();
        let start = shard_id.checked_mul(w).expect("shard start fits");
        let end = start.checked_add(w).expect("shard end fits");
        let cum_before = end
            .saturating_sub(self.row.archival_len.to_raw())
            .max(start);
        ExpectedShard::new(
            ShardId::from_raw(shard_id),
            ArchivalLength::from_raw(cum_before),
            vec![self.row],
        )
        .expect("one row closing its shard")
    }
}

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

    /// The payload, shareable without copying. [`FramedObject::new`] frames
    /// it once; serving it then costs an `Arc` clone and nothing else.
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
    /// The served objects, framed, indexed by shard id.
    objects: Vec<FramedObject>,
}

impl FixtureShardProvider {
    /// Wrap one pre-loaded payload, served as shard 0.
    #[must_use]
    pub fn new(payload: Arc<[u8]>) -> Self {
        Self::with_objects(&[payload])
    }

    /// Serve several payloads, shard `i` being `objects[i]`. An id past the
    /// end is the ordinary miss.
    #[must_use]
    pub fn with_objects(objects: &[Arc<[u8]>]) -> Self {
        Self::with_framed(objects.iter().map(|o| FramedObject::new(o)).collect())
    }

    /// Serve objects already framed — the apparatus frames once and hands
    /// the same objects to every persona.
    #[must_use]
    pub fn with_framed(objects: Vec<FramedObject>) -> Self {
        Self { objects }
    }

    /// The object served as `shard_id`, or `None` past the end.
    #[must_use]
    pub fn object(&self, shard_id: u64) -> Option<&FramedObject> {
        usize::try_from(shard_id)
            .ok()
            .and_then(|i| self.objects.get(i))
    }
}

impl ShardProvider for FixtureShardProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        // The serve loop is body-agnostic: it writes the frame as held. An
        // id past the served objects renders the ordinary miss.
        Ok(self.object(shard_id).map(|o| ShardBody::flat(o.frame())))
    }
}

impl std::fmt::Debug for FixtureShardProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lens: Vec<usize> = self.objects.iter().map(FramedObject::payload_len).collect();
        f.debug_struct("FixtureShardProvider")
            .field("payload_lens", &lens)
            .finish()
    }
}

/// The multi-size W₂ run's objects (`ARCHIVAL_SHARD_T_DERIVATION.md` §4.1): the real
/// shard and two sizes derived from **its own bytes**, served as shard ids
/// `0` (the shard, 1×), `1` (its first half, ½×) and `2` (its first quarter, ¼×) —
/// a 4× byte span, every size a whole number of leaves.
///
/// The shard is the top of the ladder because it is the size the W₂
/// question asks about (`SHARD_BYTES`); the serve loop itself is
/// body-agnostic and would stream a larger object, and the client's
/// response ceiling — derived from the expectation's rows
/// (`ExpectedShard::max_response_len`) — is the one bound a larger object
/// would meet.
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

    /// The body a reader actually receives is the shard's bytes framed as
    /// one transaction — the serve loop writes nothing of its own ahead of
    /// them — and the apparatus derives what to expect from the same
    /// object the endpoint serves rather than taking a number from a
    /// caller. Pinned here because the first version of the harness
    /// compared against `SHARD_BYTES` directly, and when the since-retired
    /// `RF-D4` frame landed every probe went stale at once; the derivation
    /// is what keeps the next wire move from doing the same.
    #[test]
    fn served_body_is_the_shard_through_the_production_contract() {
        let object = FramedObject::new(&vec![0u8; SHARD_BYTES]);
        let body = shekyl_p_serve::ShardBody::flat(object.frame());
        // Frame overhead: version, count 1, auth count 0, pqc len 0, and the
        // prunable length as LEB128 (four bytes for 3.3 MB).
        assert_eq!(body.len(), SHARD_BYTES as u64 + 1 + 1 + 1 + 1 + 4);
        assert_eq!(object.payload_len(), SHARD_BYTES);
        // The expectation is the one row, and the client's ceiling covers
        // the frame.
        let expected = object.expectation(0);
        assert_eq!(expected.tx_count(), 1);
        assert_eq!(expected.archival_len().to_raw(), SHARD_BYTES as u64);
        assert!(
            body.len() + shekyl_p_fetch::SIGNATURE_ENVELOPE_LEN as u64
                <= expected.max_response_len()
        );
    }

    /// A payload longer than `W` is placed at its shard's start; a shorter
    /// one is placed `W` short of the shard's end. Both close the shard.
    #[test]
    fn a_framed_object_closes_whichever_shard_it_is_served_as() {
        let w = SHARD_LENGTH.to_raw();
        let long = FramedObject::new(&vec![0u8; SHARD_BYTES]);
        assert!(
            SHARD_BYTES as u64 > w,
            "the extracted shard is longer than W"
        );
        for shard in 0..3u64 {
            assert_eq!(long.expectation(shard).shard_id().to_raw(), shard);
        }
        let short = FramedObject::new(&[0u8; LEAF_BYTES]);
        for shard in 0..3u64 {
            assert_eq!(short.expectation(shard).shard_id().to_raw(), shard);
        }
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
            assert_eq!(FramedObject::new(object).payload_len(), object.len());
        }
        let one = fixture.bytes();
        assert!(
            Arc::ptr_eq(&ladder[0], &one),
            "shard 0 is the fixture itself"
        );
        assert_eq!(&ladder[1][..], &one[..SHARD_BYTES / 2]);
        assert_eq!(&ladder[2][..], &one[..SHARD_BYTES / 4]);
    }

    /// Shard `i` is object `i`; past the end is the ordinary miss.
    #[test]
    fn the_provider_serves_each_object_by_shard_id() {
        let objects: Vec<Arc<[u8]>> = vec![
            vec![1u8; LEAF_BYTES].into(),
            vec![2u8; 2 * LEAF_BYTES].into(),
        ];
        let provider = FixtureShardProvider::with_objects(&objects);
        for (id, leaves) in [(0u64, 1u64), (1, 2)] {
            let body = provider.shard_bytes(id).expect("ok").expect("served");
            let payload = leaves * u64::try_from(LEAF_BYTES).expect("fits");
            assert_eq!(
                body.len(),
                u64::try_from(provider.object(id).unwrap().frame().len()).unwrap()
            );
            assert_eq!(
                provider.object(id).unwrap().payload_len(),
                usize::try_from(payload).unwrap()
            );
        }
        assert!(provider.shard_bytes(2).expect("ok").is_none());
        assert!(provider.object(2).is_none());
    }
}
