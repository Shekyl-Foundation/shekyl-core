// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one request header (`SF-D5`, second amendment): what the requester
//! puts on the wire and what `P` signs over.

//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: request-header height is ordinal, not a count.
//! use shekyl_p_fetch::RequestHeader;
//! use shekyl_types::ChainCount;
//! let _ = RequestHeader::with_nonce([0u8; 32], ChainCount::from_raw(1), [0u8; 32]);
//! ```

use shekyl_archival_retention::pass_anchor::{
    PassRequestHeader, PASS_ANCHOR_HASH_LEN, PASS_NONCE_LEN, PASS_REQUEST_HEADER_LEN,
};
use shekyl_curve_tree::serving_route::{encode_request_header, REQUEST_HEADER_BYTES};
use shekyl_types::BlockHeight;

// The textual carrier (`serving_route`) and the signed layout (`pass_anchor`)
// are owned by different crates on purpose; this is where they must agree.
const _: () = assert!(REQUEST_HEADER_BYTES == PASS_REQUEST_HEADER_LEN);

/// The decoded `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]` a fetch
/// carries.
///
/// Thin wrapper over [`PassRequestHeader`]: entropy and the hex carrier
/// live here (a consensus crate does not mint nonces or speak HTTP). The
/// layout and the transcript are the inner type's.
///
/// The requester builds one per fetch from **its own** chain view: a fresh
/// random nonce and the hash of its block at `tip − 720`
/// (`PASS_ANCHOR_DEPTH_BLOCKS`) — the same shape for a challenge fetch and
/// an organic one, so the header does not distinguish callers (`SF-D1`).
///
/// **Stall retries of the same `P` reuse the same header** (`SF-D6`): the
/// value is a plain `Copy`, so the caller holds it across attempts rather
/// than minting a nonce per dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeader(PassRequestHeader);

impl RequestHeader {
    /// A header with a fresh OS-random nonce over the caller's anchor.
    ///
    /// # Errors
    ///
    /// The OS entropy source failed. There is no fallback: a header with a
    /// predictable nonce is a pass record an adversary can pre-compute.
    pub fn fresh(
        anchor_height: BlockHeight,
        anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
    ) -> Result<Self, getrandom::Error> {
        let mut nonce = [0u8; PASS_NONCE_LEN];
        getrandom::getrandom(&mut nonce)?;
        Ok(Self::with_nonce(nonce, anchor_height, anchor_hash))
    }

    /// A header over a caller-chosen nonce.
    ///
    /// For tests and for callers that persist a header across a process
    /// restart mid-retry. Production callers minting a *new* header use
    /// [`Self::fresh`]; a nonce that is not OS-random is a pass record an
    /// adversary can pre-compute.
    #[must_use]
    pub const fn with_nonce(
        nonce: [u8; PASS_NONCE_LEN],
        anchor_height: BlockHeight,
        anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
    ) -> Self {
        Self(PassRequestHeader::from_parts(
            nonce,
            anchor_height,
            anchor_hash,
        ))
    }

    /// The nonce — what the pass record carries beside `anchor_height`.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; PASS_NONCE_LEN] {
        self.0.nonce()
    }

    /// The requester's anchor height (`tip − 720` at mint time).
    #[must_use]
    pub const fn anchor_height(&self) -> BlockHeight {
        self.0.anchor_height()
    }

    /// The requester's block hash at [`Self::anchor_height`].
    #[must_use]
    pub const fn anchor_hash(&self) -> &[u8; PASS_ANCHOR_HASH_LEN] {
        self.0.anchor_hash()
    }

    /// The decoded 72-byte wire layout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PASS_REQUEST_HEADER_LEN] {
        self.0.to_bytes()
    }

    /// The header value as it travels: lowercase hex of [`Self::to_bytes`].
    #[must_use]
    pub fn wire_value(&self) -> String {
        encode_request_header(&self.to_bytes())
    }

    /// The 80-byte transcript `P` countersigns for `shard_id`.
    #[must_use]
    pub fn transcript(
        &self,
        shard_id: u64,
    ) -> [u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        self.0.transcript(shard_id)
    }
}

impl From<PassRequestHeader> for RequestHeader {
    fn from(inner: PassRequestHeader) -> Self {
        Self(inner)
    }
}

impl From<RequestHeader> for PassRequestHeader {
    fn from(header: RequestHeader) -> Self {
        header.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_curve_tree::serving_route::decode_request_header;

    #[test]
    fn the_wire_value_round_trips_to_the_signed_bytes() {
        let h = RequestHeader::with_nonce(
            [7; 32],
            BlockHeight::from_raw(0x0102_0304_0506_0708),
            [9; 32],
        );
        let bytes = h.to_bytes();
        assert_eq!(&bytes[..32], &[7; 32]);
        assert_eq!(&bytes[32..40], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&bytes[40..], &[9; 32]);
        assert_eq!(decode_request_header(&h.wire_value()), Some(bytes));
        assert_eq!(
            PassRequestHeader::from_bytes(&bytes),
            PassRequestHeader::from(h)
        );
    }

    #[test]
    fn the_transcript_is_the_header_then_the_shard_id() {
        let h = RequestHeader::with_nonce([1; 32], BlockHeight::from_raw(5), [2; 32]);
        let t = h.transcript(0x0a0b);
        assert_eq!(&t[..72], &h.to_bytes());
        assert_eq!(&t[72..], &[0x0b, 0x0a, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn fresh_headers_do_not_share_a_nonce() {
        let a = RequestHeader::fresh(BlockHeight::from_raw(1), [0; 32]).expect("entropy");
        let b = RequestHeader::fresh(BlockHeight::from_raw(1), [0; 32]).expect("entropy");
        assert_ne!(a.nonce(), b.nonce());
        assert_eq!(a.anchor_height(), BlockHeight::from_raw(1));
        assert_eq!(a.anchor_hash(), &[0; 32]);
    }
}
