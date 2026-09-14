// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one request header (`SF-D5`, second amendment): what the requester
//! puts on the wire and what `P` signs over.

use shekyl_archival_retention::pass_anchor::{
    pass_countersignature_message, pass_request_header_bytes, PASS_ANCHOR_HASH_LEN,
    PASS_COUNTERSIGNATURE_MESSAGE_LEN, PASS_NONCE_LEN, PASS_REQUEST_HEADER_LEN,
};
use shekyl_curve_tree::serving_route::{encode_request_header, REQUEST_HEADER_BYTES};

// The textual carrier (`serving_route`) and the signed layout (`pass_anchor`)
// are owned by different crates on purpose; this is where they must agree.
const _: () = assert!(REQUEST_HEADER_BYTES == PASS_REQUEST_HEADER_LEN);

/// The decoded `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]` a fetch
/// carries.
///
/// The requester builds one per fetch from **its own** chain view: a fresh
/// random nonce and the hash of its block at `tip − 720`
/// (`PASS_ANCHOR_DEPTH_BLOCKS`) — the same shape for a challenge fetch and
/// an organic one, so the header does not distinguish callers (`SF-D1`).
/// `P` gates `anchor_height` against its own height and refuses outside
/// `[p − 720 − L, p − 720 + L]` with the identical 404; a requester whose
/// anchor is stale relative to `P` reads that as a miss, not a stall.
///
/// **Stall retries of the same `P` reuse the same header** (`SF-D6`): the
/// value is a plain `Copy`, so the caller holds it across attempts rather
/// than minting a nonce per dial. A new nonce is a new pass record, and a
/// record for an exchange that never completed would be noise in the
/// admission set.
///
/// What is signed is the **decoded** 72 bytes ‖ `shard_id_le[8]`
/// ([`Self::transcript`]), never the hex text; a lenient server and a
/// strict client therefore cannot sign different transcripts for one
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeader {
    nonce: [u8; PASS_NONCE_LEN],
    anchor_height: u64,
    anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
}

impl RequestHeader {
    /// A header with a fresh OS-random nonce over the caller's anchor.
    ///
    /// # Errors
    ///
    /// The OS entropy source failed. There is no fallback: a header with a
    /// predictable nonce is a pass record an adversary can pre-compute.
    pub fn fresh(
        anchor_height: u64,
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
        anchor_height: u64,
        anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
    ) -> Self {
        Self {
            nonce,
            anchor_height,
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
    pub const fn anchor_height(&self) -> u64 {
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

    /// The header value as it travels: lowercase hex of [`Self::to_bytes`].
    #[must_use]
    pub fn wire_value(&self) -> String {
        encode_request_header(&self.to_bytes())
    }

    /// The 80-byte transcript `P` countersigns for `shard_id`
    /// (`SF-D8`): [`Self::to_bytes`] ‖ `shard_id_le[8]`.
    #[must_use]
    pub fn transcript(&self, shard_id: u64) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&self.nonce, self.anchor_height, &self.anchor_hash, shard_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_curve_tree::serving_route::decode_request_header;

    #[test]
    fn the_wire_value_round_trips_to_the_signed_bytes() {
        let h = RequestHeader::with_nonce([7; 32], 0x0102_0304_0506_0708, [9; 32]);
        let bytes = h.to_bytes();
        assert_eq!(&bytes[..32], &[7; 32]);
        assert_eq!(&bytes[32..40], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&bytes[40..], &[9; 32]);
        assert_eq!(decode_request_header(&h.wire_value()), Some(bytes));
    }

    #[test]
    fn the_transcript_is_the_header_then_the_shard_id() {
        let h = RequestHeader::with_nonce([1; 32], 5, [2; 32]);
        let t = h.transcript(0x0a0b);
        assert_eq!(&t[..72], &h.to_bytes());
        assert_eq!(&t[72..], &[0x0b, 0x0a, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn fresh_headers_do_not_share_a_nonce() {
        let a = RequestHeader::fresh(1, [0; 32]).expect("entropy");
        let b = RequestHeader::fresh(1, [0; 32]).expect("entropy");
        assert_ne!(a.nonce(), b.nonce());
        assert_eq!(a.anchor_height(), 1);
        assert_eq!(a.anchor_hash(), &[0; 32]);
    }
}
