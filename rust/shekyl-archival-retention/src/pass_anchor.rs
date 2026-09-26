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

/// Signed transcript: 72-byte header followed by `shard_id` as 8 LE bytes.
pub const PASS_COUNTERSIGNATURE_MESSAGE_LEN: usize = PASS_REQUEST_HEADER_LEN + 8;

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

    /// The SF-D8 transcript for this header and `shard_id`.
    #[must_use]
    pub fn transcript(&self, shard_id: u64) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&self.nonce, self.anchor_height, &self.anchor_hash, shard_id)
    }
}

/// Transcript `P` signs: [`pass_request_header_bytes`] ‖ `shard_id_le[8]`.
/// Plain concatenation, not a hash. Domain is
/// [`SCHEME_DOMAIN_ATTESTATION`](shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION).
#[must_use]
pub fn pass_countersignature_message(
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    shard_id: u64,
) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    let mut out = [0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN];
    out[..PASS_REQUEST_HEADER_LEN].copy_from_slice(&pass_request_header_bytes(
        nonce,
        anchor_height,
        anchor_hash,
    ));
    out[PASS_REQUEST_HEADER_LEN..].copy_from_slice(&shard_id.to_le_bytes());
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
            h.transcript(9),
            pass_countersignature_message(&[0x11; 32], bh(0x0102_0304_0506_0708), &[0x22; 32], 9)
        );
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

        let msg = pass_countersignature_message(
            &nonce,
            bh(0x0102_0304_0506_0708),
            &hash,
            0x1112_1314_1516_1718,
        );
        assert_eq!(msg.len(), PASS_COUNTERSIGNATURE_MESSAGE_LEN);
        assert_eq!(&msg[..72], &header);
        assert_eq!(
            &msg[72..80],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                &[0xABu8; 32],
                bh(0x0102_0304_0506_0708),
                &hash,
                0x1112_1314_1516_1718
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, bh(1), &hash, 0x1112_1314_1516_1718)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                &nonce,
                bh(0x0102_0304_0506_0708),
                &[0xBCu8; 32],
                0x1112_1314_1516_1718
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, bh(0x0102_0304_0506_0708), &hash, 1)
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
