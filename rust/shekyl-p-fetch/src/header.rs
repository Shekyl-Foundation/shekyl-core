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
use shekyl_socks::SocksUsername;
use shekyl_types::BlockHeight;

/// The SOCKS password every read presents. The username is what tells two
/// reads apart; see [`RequestHeader::socks_credentials`].
const READ_SOCKS_PASSWORD: &[u8] = b"shekyl-fetch";

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
///
/// **The nonce is the read.** A new read carries a new nonce, for every
/// caller, and everything that must be one-per-read hangs off it: `P`'s
/// transcript, and the SOCKS credentials the dial presents
/// ([`Self::socks_credentials`]). A caller cannot give two reads one circuit
/// or one read two, because it never chooses the credentials.
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
    /// Organic reads mint with [`Self::fresh`]. A challenge supplies the
    /// nonce `challenge_nonce` derived (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
    /// §5.2): indistinguishable from random until the seed is revealed.
    /// A nonce that is neither is a pass record an adversary can
    /// pre-compute.
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

    /// The SOCKS credentials this read's dials present (`SF-D3`, as ruled
    /// 2026-10-07): the nonce in lowercase hex as the username, and the
    /// fixed password [`READ_SOCKS_PASSWORD`].
    ///
    /// Tor's `IsolateSOCKSAuth` isolates on the pair, so a username no other
    /// read presents is a pair no other read presents. `P` cannot tie two
    /// reads together by the circuit they arrive on. The password is the
    /// same for every read and carries no isolation: a Tor that compared
    /// only the password would not separate reads. A stall retry presents
    /// the header it retries, so it presents the same pair. A retry with a
    /// fresh anchor keeps the nonce, so it does too.
    ///
    /// The pair never leaves this host: SOCKS credentials go to the local
    /// Tor and no further. That Tor already carries the request, nonce
    /// included. A local controller subscribed to `STREAM` events can read
    /// the username there; nothing in this crate logs it, and
    /// [`SocksUsername`] redacts itself in `Debug`.
    pub(crate) fn socks_credentials(&self) -> SocksUsername {
        let mut username = [0u8; 2 * PASS_NONCE_LEN];
        for (pair, byte) in username.chunks_exact_mut(2).zip(self.nonce()) {
            pair[0] = HEX[usize::from(byte >> 4)];
            pair[1] = HEX[usize::from(byte & 0x0f)];
        }
        SocksUsername::new(&username, READ_SOCKS_PASSWORD)
            .expect("a 64-byte username and a short password are in range")
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

    /// The transcript `P` countersigns for `shard_id` and the digest of the
    /// bytes it delivered under this header's nonce.
    #[must_use]
    pub fn transcript(
        &self,
        shard_id: u64,
        delivery_digest: &[u8; shekyl_archival_retention::pass_anchor::PASS_DELIVERY_DIGEST_LEN],
    ) -> [u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        self.0.transcript(shard_id, delivery_digest)
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

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
    fn the_transcript_is_the_header_the_shard_id_then_the_delivery_digest() {
        let h = RequestHeader::with_nonce([1; 32], BlockHeight::from_raw(5), [2; 32]);
        let t = h.transcript(0x0a0b, &[3; 32]);
        assert_eq!(&t[..72], &h.to_bytes());
        assert_eq!(&t[72..80], &[0x0b, 0x0a, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&t[80..], &[3; 32]);
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
