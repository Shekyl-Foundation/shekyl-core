// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SF-D8 pass-countersignature transcript and admission window.
//!
//! Design: [`ARCHIVAL_SHARD_FETCH.md`](../../../docs/design/ARCHIVAL_SHARD_FETCH.md)
//! `SF-D8`. Record codec and [`verify_pass_countersignature`](crate::verify_pass_countersignature)
//! live in [`crate::attestation_wire`].
//!
//! Inland clocks are ordinal [`BlockHeight`]; depths and lags are
//! [`BlockCount`]. The 72-byte header still carries `anchor_height` as
//! eight LE bytes (C1); [`PassRequestHeader::from_bytes`] /
//! [`pass_request_header_bytes`] are the punch.
//!
//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: predecessor is ordinal, depth is a span.
//! use shekyl_archival_retention::pass_anchor::{
//!     PassAnchorWindow, PASS_ANCHOR_DEPTH_BLOCKS,
//! };
//! let _ = PassAnchorWindow::shape_for_predecessor(PASS_ANCHOR_DEPTH_BLOCKS);
//! ```
//!
//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: decoded header height is ordinal, not a count.
//! use shekyl_archival_retention::PassRequestHeader;
//! use shekyl_types::ChainCount;
//! let _ = PassRequestHeader::from_parts([0u8; 32], ChainCount::from_raw(1), [0u8; 32]);
//! ```

use shekyl_types::{BlockCount, BlockHeight};

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

use crate::bond_floor::{ARCHIVAL_ATTESTATION_ANCHOR_LAG_BLOCKS, ARCHIVAL_REORG_DEPTH_BLOCKS};

/// Requester-random nonce `P` signs over (`SF-D5`: exactly 32 bytes).
pub const PASS_NONCE_LEN: usize = 32;

/// Little-endian anchor height in the header, transcript, record, and witness.
pub const PASS_ANCHOR_HEIGHT_LEN: usize = 8;

/// Anchor block hash in the header and transcript. Not carried on the record —
/// admission looks it up from the connecting chain.
pub const PASS_ANCHOR_HASH_LEN: usize = 32;

/// Decoded request header: `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
pub const PASS_REQUEST_HEADER_LEN: usize =
    PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN + PASS_ANCHOR_HASH_LEN;

/// The delivery digest `P` signs and the pass record carries
/// ([`pass_delivery_digest`]).
pub const PASS_DELIVERY_DIGEST_LEN: usize = 32;

/// cSHAKE256 customization for [`pass_delivery_digest`] (rule 30: one label,
/// one function, versioned).
pub const PASS_DELIVERY_DIGEST_CUSTOMIZATION: &[u8] = b"shekyl/archival-pass-delivery-digest-v1";

/// Signed transcript: 72-byte header, `shard_id` as 8 LE bytes, then the
/// 32-byte delivery digest.
pub const PASS_COUNTERSIGNATURE_MESSAGE_LEN: usize =
    PASS_REQUEST_HEADER_LEN + 8 + PASS_DELIVERY_DIGEST_LEN;

/// Requester anchors at `tip − depth`; admission's upper bound is `h − depth`.
/// This is `archival_reorg_depth_blocks` (720). Generated config stays `u64`
/// (C4); the inland constant is the span.
pub const PASS_ANCHOR_DEPTH_BLOCKS: BlockCount = BlockCount::from_raw(ARCHIVAL_REORG_DEPTH_BLOCKS);

/// Window lag `L` (PROVISIONAL 4). Same `L` on P's pre-sign gate (`RF-R1`).
pub const PASS_ANCHOR_LAG_BLOCKS: BlockCount =
    BlockCount::from_raw(ARCHIVAL_ATTESTATION_ANCHOR_LAG_BLOCKS);

/// Lowest predecessor with a window: genesis plus depth plus lag.
/// A predecessor below this has no admissible anchor. The sum is
/// checked, so an overflowing pair fails to compile.
pub const PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT: BlockHeight = {
    match BlockHeight::ZERO.checked_add(PASS_ANCHOR_DEPTH_BLOCKS) {
        Some(after_depth) => match after_depth.checked_add(PASS_ANCHOR_LAG_BLOCKS) {
            Some(floor) => floor,
            None => panic!("pass anchor floor depth + lag overflowed BlockHeight"),
        },
        None => panic!("pass anchor floor depth + lag overflowed BlockHeight"),
    }
};

/// Heights (and hashes) in one window: `L + 1`.
pub const PASS_ANCHOR_WINDOW_LEN: usize = {
    assert!(PASS_ANCHOR_LAG_BLOCKS.to_raw() <= u32::MAX as u64);
    #[allow(clippy::cast_possible_truncation)]
    let lag = PASS_ANCHOR_LAG_BLOCKS.to_raw() as usize;
    lag + 1
};

/// Window construction failed: genesis boundary, or the caller's table is the
/// wrong length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassAnchorWindowError {
    #[error(
        "no pass anchor window below predecessor height {PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT} \
         (got {predecessor_height})"
    )]
    BelowThreshold { predecessor_height: BlockHeight },
    #[error("pass anchor hash table has {got} entries, expected {expected}")]
    WrongLength { expected: usize, got: usize },
}

/// Connecting-chain hashes for `[h − depth − L, h − depth]`, `hashes[i]` at
/// `first + i`. Length is [`PASS_ANCHOR_WINDOW_LEN`] in the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassAnchorWindow {
    first: BlockHeight,
    hashes: [[u8; PASS_ANCHOR_HASH_LEN]; PASS_ANCHOR_WINDOW_LEN],
}

impl PassAnchorWindow {
    /// `(first_height, len)` the caller must fill, or `None` below
    /// [`PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT`].
    #[must_use]
    pub fn shape_for_predecessor(predecessor_height: BlockHeight) -> Option<(BlockHeight, usize)> {
        if predecessor_height < PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT {
            return None;
        }
        // The floor is genesis + depth + lag, so both spans fit. A floor
        // that does not match these subtractions panics here.
        let last = predecessor_height - PASS_ANCHOR_DEPTH_BLOCKS;
        let first = last - PASS_ANCHOR_LAG_BLOCKS;
        Some((first, PASS_ANCHOR_WINDOW_LEN))
    }

    /// Build from the caller's table for `predecessor_height`. The slice must
    /// be exactly [`PASS_ANCHOR_WINDOW_LEN`] hashes, ascending from `first`.
    pub fn from_table(
        predecessor_height: BlockHeight,
        hashes: &[[u8; PASS_ANCHOR_HASH_LEN]],
    ) -> Result<Self, PassAnchorWindowError> {
        let Some((first, _)) = Self::shape_for_predecessor(predecessor_height) else {
            return Err(PassAnchorWindowError::BelowThreshold { predecessor_height });
        };
        let hashes: [[u8; PASS_ANCHOR_HASH_LEN]; PASS_ANCHOR_WINDOW_LEN] = hashes
            .try_into()
            .map_err(|_| PassAnchorWindowError::WrongLength {
                expected: PASS_ANCHOR_WINDOW_LEN,
                got: hashes.len(),
            })?;
        Ok(Self { first, hashes })
    }

    #[must_use]
    pub const fn first(&self) -> BlockHeight {
        self.first
    }

    /// Inclusive end of the window (`first + L`).
    ///
    /// Panics if the sum overflows. [`Self::from_table`] cannot build
    /// such a window: `first` was produced by subtracting `L`.
    #[must_use]
    pub const fn last(&self) -> BlockHeight {
        match self.first.checked_add(PASS_ANCHOR_LAG_BLOCKS) {
            Some(last) => last,
            None => panic!("pass anchor window end overflowed BlockHeight"),
        }
    }

    /// Connecting-chain hash at `anchor_height`, or `None` outside the window.
    #[must_use]
    pub fn hash_at(&self, anchor_height: BlockHeight) -> Option<&[u8; PASS_ANCHOR_HASH_LEN]> {
        let offset = anchor_height.checked_sub(self.first)?;
        let i = usize::try_from(offset.to_raw()).ok()?;
        self.hashes.get(i)
    }
}

/// Decoded `SF-D5` header: `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
#[must_use]
pub fn pass_request_header_bytes(
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
) -> [u8; PASS_REQUEST_HEADER_LEN] {
    const HEIGHT_END: usize = PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;
    let mut out = [0u8; PASS_REQUEST_HEADER_LEN];
    out[0..PASS_NONCE_LEN].copy_from_slice(nonce);
    out[PASS_NONCE_LEN..HEIGHT_END].copy_from_slice(&anchor_height.to_raw().to_le_bytes());
    out[HEIGHT_END..].copy_from_slice(anchor_hash);
    out
}

/// The decoded 72-byte request header.
///
/// One type for both ends of the route: the fetch client mints one, the
/// serve loop splits the same bytes, and the transcript both sign and
/// verify is [`Self::transcript`]. Layout owner is this module; the
/// textual carrier (lowercase hex) is `serving_route`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassRequestHeader {
    nonce: [u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
}

impl PassRequestHeader {
    /// Assemble from the three fields. Infallible: lengths are in the types.
    #[must_use]
    pub const fn from_parts(
        nonce: [u8; PASS_NONCE_LEN],
        anchor_height: BlockHeight,
        anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
    ) -> Self {
        Self {
            nonce,
            anchor_height,
            anchor_hash,
        }
    }

    /// Split a decoded header. Infallible: the length is in the type.
    #[must_use]
    pub fn from_bytes(header: &[u8; PASS_REQUEST_HEADER_LEN]) -> Self {
        const HEIGHT_END: usize = PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;
        let mut nonce = [0u8; PASS_NONCE_LEN];
        nonce.copy_from_slice(&header[..PASS_NONCE_LEN]);
        let mut height_le = [0u8; PASS_ANCHOR_HEIGHT_LEN];
        height_le.copy_from_slice(&header[PASS_NONCE_LEN..HEIGHT_END]);
        let mut anchor_hash = [0u8; PASS_ANCHOR_HASH_LEN];
        anchor_hash.copy_from_slice(&header[HEIGHT_END..]);
        Self {
            nonce,
            anchor_height: BlockHeight::from_raw(u64::from_le_bytes(height_le)),
            anchor_hash,
        }
    }

    /// The nonce — what the pass record carries beside `anchor_height`.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; PASS_NONCE_LEN] {
        &self.nonce
    }

    /// The requester's anchor height (`tip − 720` at mint time).
    #[must_use]
    pub const fn anchor_height(&self) -> BlockHeight {
        self.anchor_height
    }

    /// The requester's block hash at [`Self::anchor_height`].
    #[must_use]
    pub const fn anchor_hash(&self) -> &[u8; PASS_ANCHOR_HASH_LEN] {
        &self.anchor_hash
    }

    /// The decoded 72-byte wire layout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PASS_REQUEST_HEADER_LEN] {
        pass_request_header_bytes(&self.nonce, self.anchor_height, &self.anchor_hash)
    }

    /// The SF-D8 transcript for this header, `shard_id`, and the digest of
    /// the bytes delivered under this header's nonce.
    #[must_use]
    pub fn transcript(
        &self,
        shard_id: u64,
        delivery_digest: &[u8; PASS_DELIVERY_DIGEST_LEN],
    ) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(
            &self.nonce,
            self.anchor_height,
            &self.anchor_hash,
            shard_id,
            delivery_digest,
        )
    }
}

/// Digest of one delivered response, salted by the request's nonce:
/// `cSHAKE256(PASS_DELIVERY_DIGEST_CUSTOMIZATION, nonce ‖ framed)[..32]`.
///
/// `framed` is exactly the response body `P` sends ahead of its
/// countersignature — the `RF-D4` frame header, the payload and any padding,
/// byte for byte as it goes on the wire. `P` signs this digest inside the
/// transcript ([`pass_countersignature_message`]), so the signature commits
/// to the bytes delivered for *this* request.
///
/// **The nonce is the salt.** It is requester-random, so `P` cannot compute
/// the digest before the request arrives, and a digest made for one request
/// answers no other. It leads the preimage and has a fixed width, so the
/// split between salt and body is unambiguous without a length field.
///
/// **What this does not claim.** It does not show that `P` stores the bytes:
/// a `P` that fetches them from a co-holder on demand produces the same
/// digest (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §9.4 (ii)); the route's
/// topology prices that, not this. And admission cannot recompute it — the
/// body is off chain — so the pass record carries it and the requester, who
/// holds the body, is the party that checks it against the bytes.
///
/// Every read is hashed the same way, so a challenge read and an ordinary
/// one remain indistinguishable to `P`.
#[must_use]
pub fn pass_delivery_digest(
    nonce: &[u8; PASS_NONCE_LEN],
    framed: &[u8],
) -> [u8; PASS_DELIVERY_DIGEST_LEN] {
    let mut hasher = PassDeliveryHasher::new(nonce);
    hasher.update(framed);
    hasher.finalize()
}

/// [`pass_delivery_digest`] computed incrementally, for a body read in
/// chunks: the serving persona hashes a shard as it reads it and never
/// holds the whole of it. Feeding the same bytes in any chunking gives the
/// one-shot digest, and this type is the one-shot function's own body, so
/// the two cannot differ.
pub struct PassDeliveryHasher(CShake256);

impl PassDeliveryHasher {
    /// Start a digest salted with `nonce`.
    #[must_use]
    pub fn new(nonce: &[u8; PASS_NONCE_LEN]) -> Self {
        let mut hasher: CShake256 =
            CoreWrapper::from_core(CShake256Core::new(PASS_DELIVERY_DIGEST_CUSTOMIZATION));
        hasher.update(nonce);
        Self(hasher)
    }

    /// Absorb the next bytes of the framed body.
    pub fn update(&mut self, framed: &[u8]) {
        self.0.update(framed);
    }

    /// The 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; PASS_DELIVERY_DIGEST_LEN] {
        let mut out = [0u8; PASS_DELIVERY_DIGEST_LEN];
        self.0.finalize_xof().read(&mut out);
        out
    }
}

/// Transcript `P` signs: [`pass_request_header_bytes`] ‖ `shard_id_le[8]` ‖
/// [`pass_delivery_digest`]. Plain concatenation of fixed-width fields.
/// Domain is
/// [`SCHEME_DOMAIN_ATTESTATION`](shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION).
#[must_use]
pub fn pass_countersignature_message(
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    shard_id: u64,
    delivery_digest: &[u8; PASS_DELIVERY_DIGEST_LEN],
) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    const SHARD_END: usize = PASS_REQUEST_HEADER_LEN + 8;
    let mut out = [0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN];
    out[..PASS_REQUEST_HEADER_LEN].copy_from_slice(&pass_request_header_bytes(
        nonce,
        anchor_height,
        anchor_hash,
    ));
    out[PASS_REQUEST_HEADER_LEN..SHARD_END].copy_from_slice(&shard_id.to_le_bytes());
    out[SHARD_END..].copy_from_slice(delivery_digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 5000;

    const fn bh(n: u64) -> BlockHeight {
        BlockHeight::from_raw(n)
    }

    fn chain_hash(height: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&height.to_le_bytes());
        h[8] = 0xC4;
        h
    }

    fn window_at(predecessor_height: u64) -> PassAnchorWindow {
        let (first, len) =
            PassAnchorWindow::shape_for_predecessor(bh(predecessor_height)).expect("window");
        let hashes: Vec<_> = (0..len as u64)
            .map(|i| chain_hash(first.to_raw() + i))
            .collect();
        PassAnchorWindow::from_table(bh(predecessor_height), &hashes)
            .expect("table sized to the window")
    }

    #[test]
    fn pass_request_header_splits_and_rejoins() {
        let h = PassRequestHeader::from_parts([0x11; 32], bh(0x0102_0304_0506_0708), [0x22; 32]);
        let bytes = h.to_bytes();
        assert_eq!(PassRequestHeader::from_bytes(&bytes), h);
        assert_eq!(&bytes[..32], &[0x11; 32]);
        assert_eq!(
            &bytes[32..40],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&bytes[40..], &[0x22; 32]);
        assert_eq!(
            h.transcript(9, &[0x33; 32]),
            pass_countersignature_message(
                &[0x11; 32],
                bh(0x0102_0304_0506_0708),
                &[0x22; 32],
                9,
                &[0x33; 32]
            )
        );
    }

    /// The delivery digest against an implementation that is not this
    /// crate's: a standalone Keccak-f[1600] / SP 800-185 cSHAKE256 written
    /// for the purpose and checked against NIST's cSHAKE256 samples #3 and
    /// #4 before these two values were taken from it. `nonce = [0x03; 32]`.
    #[test]
    fn delivery_digest_matches_an_independent_cshake256() {
        let nonce = [0x03u8; 32];
        assert_eq!(
            hex::encode(pass_delivery_digest(&nonce, b"")),
            "383cb87634c654105464750338339c6e4d88260a46599eac0e46ef09a9ac9806",
            "empty framed body: the preimage is the nonce alone"
        );
        let framed: Vec<u8> = (1u8..=48).collect();
        assert_eq!(
            hex::encode(pass_delivery_digest(&nonce, &framed)),
            "0758cedb256259dd3d372560884dcaec515857360ed434155bae0bbb4c85a6bb",
            "nonce, then the framed bytes 0x01..=0x30"
        );
    }

    /// The incremental hasher against the one-shot digest, at every split of
    /// a body: the server hashes in chunks and the client in one call, so a
    /// chunk boundary must not be able to move the digest.
    #[test]
    fn the_incremental_hasher_equals_the_one_shot_digest_at_every_split() {
        let nonce = [0x03u8; 32];
        let body: Vec<u8> = (0u8..200).collect();
        let whole = pass_delivery_digest(&nonce, &body);
        for split in 0..=body.len() {
            let mut hasher = PassDeliveryHasher::new(&nonce);
            hasher.update(&body[..split]);
            hasher.update(&body[split..]);
            assert_eq!(hasher.finalize(), whole, "split at {split}");
        }
        // Many small chunks, and none at all.
        let mut hasher = PassDeliveryHasher::new(&nonce);
        for chunk in body.chunks(7) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), whole);
        assert_eq!(
            PassDeliveryHasher::new(&nonce).finalize(),
            pass_delivery_digest(&nonce, &[])
        );
    }

    #[test]
    fn delivery_digest_is_salted_by_the_nonce_and_covers_every_byte() {
        let framed: Vec<u8> = (1u8..=48).collect();
        let d = pass_delivery_digest(&[0x03; 32], &framed);
        // Another request's nonce over the same bytes is another digest.
        assert_ne!(d, pass_delivery_digest(&[0x04; 32], &framed));
        // One flipped byte anywhere in the body is another digest.
        for i in [0, framed.len() / 2, framed.len() - 1] {
            let mut other = framed.clone();
            other[i] ^= 1;
            assert_ne!(d, pass_delivery_digest(&[0x03; 32], &other), "byte {i}");
        }
        // The split between salt and body is fixed: moving a byte across it
        // is a different preimage.
        let mut shifted_nonce = [0x03u8; 32];
        shifted_nonce[31] = framed[0];
        assert_ne!(d, pass_delivery_digest(&shifted_nonce, &framed[1..]));
        // A truncated body is another digest.
        assert_ne!(d, pass_delivery_digest(&[0x03; 32], &framed[..47]));
    }

    #[test]
    fn request_header_and_message_are_the_pinned_concatenation() {
        let nonce = [0xAAu8; 32];
        let hash = [0xBBu8; 32];
        let header = pass_request_header_bytes(&nonce, bh(0x0102_0304_0506_0708), &hash);
        assert_eq!(header.len(), PASS_REQUEST_HEADER_LEN);
        assert_eq!(&header[..32], &nonce);
        assert_eq!(
            &header[32..40],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&header[40..72], &hash);

        let digest = [0xCCu8; 32];
        let shard = 0x1112_1314_1516_1718;
        let height = bh(0x0102_0304_0506_0708);
        let msg = pass_countersignature_message(&nonce, height, &hash, shard, &digest);
        assert_eq!(msg.len(), PASS_COUNTERSIGNATURE_MESSAGE_LEN);
        assert_eq!(PASS_COUNTERSIGNATURE_MESSAGE_LEN, 112);
        assert_eq!(&msg[..72], &header);
        assert_eq!(
            &msg[72..80],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(
            &msg[80..],
            &digest,
            "the delivery digest closes the transcript"
        );
        // Every term moves the message.
        assert_ne!(
            msg,
            pass_countersignature_message(&[0xABu8; 32], height, &hash, shard, &digest)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, bh(1), &hash, shard, &digest)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, height, &[0xBCu8; 32], shard, &digest)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, height, &hash, 1, &digest)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, height, &hash, shard, &[0xCDu8; 32])
        );
    }

    #[test]
    fn anchor_window_heights_are_depth_and_lag_below_the_predecessor() {
        assert_eq!(PASS_ANCHOR_DEPTH_BLOCKS, BlockCount::from_raw(720));
        assert_eq!(PASS_ANCHOR_LAG_BLOCKS, BlockCount::from_raw(4));
        assert_eq!(PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, bh(724));
        assert_eq!(PASS_ANCHOR_WINDOW_LEN, 5);

        let (first, len) = PassAnchorWindow::shape_for_predecessor(bh(H)).unwrap();
        assert_eq!((first, len), (bh(H - 724), 5));
        let w = window_at(H);
        assert_eq!((w.first(), w.last()), (bh(H - 724), bh(H - 720)));
        assert_eq!(w.hash_at(bh(H - 724)), Some(&chain_hash(H - 724)));
        assert_eq!(w.hash_at(bh(H - 720)), Some(&chain_hash(H - 720)));
        assert_eq!(w.hash_at(bh(H - 725)), None);
        assert_eq!(w.hash_at(bh(H - 719)), None);

        assert_eq!(PassAnchorWindow::shape_for_predecessor(bh(723)), None);
        let (first, _) = PassAnchorWindow::shape_for_predecessor(bh(724)).unwrap();
        assert_eq!(first, bh(0));
        assert_eq!(PassAnchorWindow::shape_for_predecessor(bh(0)), None);
    }

    #[test]
    fn anchor_window_table_must_match_the_window_exactly() {
        assert_eq!(
            PassAnchorWindow::from_table(bh(723), &[[0u8; 32]; 5]).unwrap_err(),
            PassAnchorWindowError::BelowThreshold {
                predecessor_height: bh(723)
            }
        );
        assert_eq!(
            PassAnchorWindow::from_table(bh(H), &[[0u8; 32]; 4]).unwrap_err(),
            PassAnchorWindowError::WrongLength {
                expected: 5,
                got: 4
            }
        );
        assert_eq!(
            PassAnchorWindow::from_table(bh(H), &[[0u8; 32]; 6]).unwrap_err(),
            PassAnchorWindowError::WrongLength {
                expected: 5,
                got: 6
            }
        );
    }
}
