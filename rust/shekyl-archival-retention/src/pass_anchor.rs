// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SF-D8 pass transcript, its anchor depth and lag, and the receipt verify.
//!
//! Design: [`ARCHIVAL_SHARD_FETCH.md`](../../../docs/design/ARCHIVAL_SHARD_FETCH.md)
//! `SF-D8`. A persona's receipt key signs the [`PassTranscript`] under the
//! receipt domain, and [`verify_receipt_transcript`] is the one check of it.
//!
//! Inland clocks are ordinal [`BlockHeight`]; depths and lags are
//! [`BlockCount`]. The 73-byte header still carries `anchor_height` as
//! eight LE bytes (C1); [`PassRequestHeader::from_bytes`] /
//! [`pass_request_header_bytes`] are the punch.
//!
//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: decoded header height is ordinal, not a count.
//! use shekyl_archival_retention::{PassRequestHeader, PassStream};
//! use shekyl_types::ChainCount;
//! let _ = PassRequestHeader::from_parts(
//!     PassStream::Economy,
//!     [0u8; 32],
//!     ChainCount::from_raw(1),
//!     [0u8; 32],
//! );
//! ```

use core::num::NonZeroU64;

use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT};

use crate::bond_floor::{ARCHIVAL_PASS_ANCHOR_LAG_BLOCKS, ARCHIVAL_REORG_DEPTH_BLOCKS};

/// Requester-random nonce `P` signs over (`SF-D5`: exactly 32 bytes).
pub const PASS_NONCE_LEN: usize = 32;

/// Little-endian anchor height in the header, transcript, record, and witness.
pub const PASS_ANCHOR_HEIGHT_LEN: usize = 8;

/// Anchor block hash in the header and transcript. Not carried on the record —
/// admission looks it up from the connecting chain.
pub const PASS_ANCHOR_HASH_LEN: usize = 32;

/// Which draw stream a request belongs to. The first byte of the header
/// and of the transcript `P` signs (`ARCHIVAL_SUPPORT_DRAW.md` §5).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassStream {
    /// An economy draw. Byte `0`.
    Economy = 0,
    /// A complete-tree support draw. Byte `1`.
    Support = 1,
}

impl PassStream {
    /// The wire byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// The stream this byte names. `None` for any other byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Economy),
            1 => Some(Self::Support),
            _ => None,
        }
    }
}

/// Decoded request header: `stream[1] ‖ nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
pub const PASS_REQUEST_HEADER_LEN: usize =
    1 + PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN + PASS_ANCHOR_HASH_LEN;

/// The delivery digest `P` signs and the pass record carries
/// ([`pass_delivery_digest`]).
pub const PASS_DELIVERY_DIGEST_LEN: usize = 32;

/// cSHAKE256 customization for [`pass_delivery_digest`] (rule 30: one label,
/// one function, versioned).
pub const PASS_DELIVERY_DIGEST_CUSTOMIZATION: &[u8] = b"shekyl/archival-pass-delivery-digest-v1";

/// Signed transcript: the 73-byte header, `shard_id` as 8 LE bytes, then the
/// 32-byte delivery digest.
pub const PASS_COUNTERSIGNATURE_MESSAGE_LEN: usize =
    PASS_REQUEST_HEADER_LEN + 8 + PASS_DELIVERY_DIGEST_LEN;

/// Requester anchors at `tip − depth`; admission's upper bound is `h − depth`.
/// This is `archival_reorg_depth_blocks` (720). Generated config stays `u64`
/// (C4); the inland constant is the span.
pub const PASS_ANCHOR_DEPTH_BLOCKS: BlockCount = BlockCount::from_raw(ARCHIVAL_REORG_DEPTH_BLOCKS);

/// Anchor lag `L` (PROVISIONAL 4): the half-width of P's pre-sign gate
/// (`RF-R1`), and the margin `W₂ + L ≤` depth keeps between an honest
/// read's anchor and the block it answers for.
pub const PASS_ANCHOR_LAG_BLOCKS: BlockCount =
    BlockCount::from_raw(ARCHIVAL_PASS_ANCHOR_LAG_BLOCKS);

/// Whether an honest read under `schedule` is anchored below the block it
/// answers for: `W₂ + L ≤` anchor depth (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
/// §9.1, `SCS-P32`).
///
/// Bundle admission refuses a record whose `anchor_height` is not below
/// `h`. A challenge read of block `h`'s draw is made inside `h`'s window,
/// by a requester whose tip is at most `h + W₂`, and every requester
/// anchors at its tip minus the depth. So the highest anchor an honest
/// read carries is `h + W₂ − depth`, and the ruled relation holds it at
/// least `L` below `h` — the same `L` the persona's gate allows between
/// its own tip and the requester's.
///
/// `W₂` is the schedule's
/// ([`SettlementSchedule::challenge_response_blocks`](crate::SettlementSchedule::challenge_response_blocks)),
/// so this is rule-set data and is asked of every rule set (rule 71); `L`
/// and the depth are [`PASS_ANCHOR_LAG_BLOCKS`] and
/// [`PASS_ANCHOR_DEPTH_BLOCKS`]. A schedule whose epoch is too short to
/// have a window satisfies it: no bundle is admissible under it at all.
#[must_use]
pub const fn anchor_depth_covers_response_window(schedule: crate::SettlementSchedule) -> bool {
    response_window_outrunning_anchor(schedule).is_none()
}

// The production triple, asserted where the anchor's constants are. A
// re-pin of the epoch (and so of `W₂`), of `L` or of the depth that lets
// an honest read anchor at or above the block it answers for stops the
// build here, not at an admission refusal on a live chain.
const _: () = assert!(
    anchor_depth_covers_response_window(crate::SettlementSchedule::GENESIS),
    "W2 + L > the pass-anchor depth on the genesis schedule: an honest challenge read could \
     carry an anchor at or above the block it answers for, and bundle admission refuses \
     anchor_height >= h (ARCHIVAL_SERVE_CREDIT_SPEC.md SCS-P32); re-pin one with the others"
);

/// The response window that outruns the anchor depth under `schedule`,
/// when one does: `Some(W₂)` where `W₂ + L >` anchor depth, `None` where
/// the relation holds. The one body behind
/// [`anchor_depth_covers_response_window`]; a caller that must *name* the
/// offending window — a rule set's typed refusal of an epoch — reads it
/// here, so the window it reports is the window that failed and never a
/// stand-in.
///
/// A schedule too short to have a window is `None`: the relation holds
/// vacuously (no bundle is admissible under it), and there is no window to
/// name. Absence is `None`, not a zero (rule 43).
#[must_use]
pub const fn response_window_outrunning_anchor(
    schedule: crate::SettlementSchedule,
) -> Option<NonZeroU64> {
    match schedule.challenge_response_blocks() {
        None => None,
        Some(window) => match window.get().checked_add(PASS_ANCHOR_LAG_BLOCKS.to_raw()) {
            Some(reach) if reach <= PASS_ANCHOR_DEPTH_BLOCKS.to_raw() => None,
            // Past the depth, or `W₂ + L` does not fit a `u64`: either way
            // the window reaches past the anchor.
            Some(_) | None => Some(window),
        },
    }
}

/// Decoded header: `stream[1] ‖ nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
#[must_use]
pub fn pass_request_header_bytes(
    stream: PassStream,
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
) -> [u8; PASS_REQUEST_HEADER_LEN] {
    const NONCE_END: usize = 1 + PASS_NONCE_LEN;
    const HEIGHT_END: usize = NONCE_END + PASS_ANCHOR_HEIGHT_LEN;
    let mut out = [0u8; PASS_REQUEST_HEADER_LEN];
    out[0] = stream.byte();
    out[1..NONCE_END].copy_from_slice(nonce);
    out[NONCE_END..HEIGHT_END].copy_from_slice(&anchor_height.to_raw().to_le_bytes());
    out[HEIGHT_END..].copy_from_slice(anchor_hash);
    out
}

/// The decoded 73-byte request header.
///
/// One type for both ends of the route: the fetch client mints one, the
/// serve loop splits the same bytes, and the transcript both sign and
/// verify is [`Self::transcript`]. Layout owner is this module; the
/// textual carrier (lowercase hex) is `serving_route`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassRequestHeader {
    stream: PassStream,
    nonce: [u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: BlockHash,
}

impl PassRequestHeader {
    /// Assemble from the stream, the nonce, the anchor height and the anchor
    /// hash. Infallible: lengths are in the types.
    #[must_use]
    pub const fn from_parts(
        stream: PassStream,
        nonce: [u8; PASS_NONCE_LEN],
        anchor_height: BlockHeight,
        anchor_hash: BlockHash,
    ) -> Self {
        Self {
            stream,
            nonce,
            anchor_height,
            anchor_hash,
        }
    }

    /// The stream this request names.
    #[must_use]
    pub const fn stream(&self) -> PassStream {
        self.stream
    }

    /// Split a decoded header. `None` when the stream byte is neither
    /// economy nor support.
    #[must_use]
    pub fn from_bytes(header: &[u8; PASS_REQUEST_HEADER_LEN]) -> Option<Self> {
        const NONCE_END: usize = 1 + PASS_NONCE_LEN;
        const HEIGHT_END: usize = NONCE_END + PASS_ANCHOR_HEIGHT_LEN;
        let stream = PassStream::from_byte(header[0])?;
        let mut nonce = [0u8; PASS_NONCE_LEN];
        nonce.copy_from_slice(&header[1..NONCE_END]);
        let mut height_le = [0u8; PASS_ANCHOR_HEIGHT_LEN];
        height_le.copy_from_slice(&header[NONCE_END..HEIGHT_END]);
        let mut anchor_hash = [0u8; PASS_ANCHOR_HASH_LEN];
        anchor_hash.copy_from_slice(&header[HEIGHT_END..]);
        Some(Self {
            stream,
            nonce,
            anchor_height: BlockHeight::from_raw(u64::from_le_bytes(height_le)),
            anchor_hash: BlockHash::from_bytes(anchor_hash),
        })
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
    pub const fn anchor_hash(&self) -> &BlockHash {
        &self.anchor_hash
    }

    /// The decoded 73-byte wire layout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PASS_REQUEST_HEADER_LEN] {
        pass_request_header_bytes(
            self.stream,
            &self.nonce,
            self.anchor_height,
            self.anchor_hash.as_bytes(),
        )
    }

    /// The SF-D8 transcript for this header, `shard_id`, and the digest of
    /// the bytes delivered under this header's nonce.
    #[must_use]
    pub const fn transcript(
        &self,
        shard_id: u64,
        delivery_digest: [u8; PASS_DELIVERY_DIGEST_LEN],
    ) -> PassTranscript {
        PassTranscript {
            header: *self,
            shard_id,
            delivery_digest,
        }
    }
}

/// What `P` signs, typed: the request header (whose anchor is a
/// [`BlockHash`]), the shard the route named, and the digest of the bytes
/// delivered. Every function that applies the receipt domain to a pass
/// takes this, never the bytes, so the anchor reaches the domain as a block
/// hash. [`Self::message`] is the 113-byte layout the signature covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassTranscript {
    header: PassRequestHeader,
    shard_id: u64,
    delivery_digest: [u8; PASS_DELIVERY_DIGEST_LEN],
}

impl PassTranscript {
    /// The transcript of `header`, `shard_id` and `delivery_digest`; the
    /// same as [`PassRequestHeader::transcript`].
    #[must_use]
    pub const fn new(
        header: PassRequestHeader,
        shard_id: u64,
        delivery_digest: [u8; PASS_DELIVERY_DIGEST_LEN],
    ) -> Self {
        header.transcript(shard_id, delivery_digest)
    }

    /// The request header.
    #[must_use]
    pub const fn header(&self) -> &PassRequestHeader {
        &self.header
    }

    /// The shard the route named.
    #[must_use]
    pub const fn shard_id(&self) -> u64 {
        self.shard_id
    }

    /// The digest of the bytes delivered under the header's nonce.
    #[must_use]
    pub const fn delivery_digest(&self) -> &[u8; PASS_DELIVERY_DIGEST_LEN] {
        &self.delivery_digest
    }

    /// The 113-byte message a signature covers
    /// ([`pass_countersignature_message`]).
    #[must_use]
    pub fn message(&self) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(
            self.header.stream,
            &self.header.nonce,
            self.header.anchor_height,
            self.header.anchor_hash.as_bytes(),
            self.shard_id,
            &self.delivery_digest,
        )
    }
}

/// Digest of one delivered response, salted by the request's nonce:
/// `cSHAKE256(PASS_DELIVERY_DIGEST_CUSTOMIZATION, nonce ‖ body)[..32]`.
///
/// `body` is exactly the response body `P` sends ahead of its
/// countersignature — the `shekyl_wire::shard_frame` body over the shard's
/// archival good, byte for byte as it goes on the wire (`SF-D8` amendment
/// 2026-10-08; the serve loop prepends nothing). `P` signs this digest
/// inside the transcript ([`pass_countersignature_message`]), so the
/// signature commits to the bytes delivered for *this* request.
///
/// **The nonce is the salt.** It is requester-random, so `P` cannot compute
/// the digest before the request arrives, and a digest made for one request
/// answers no other. It leads the preimage and has a fixed width, so the
/// split between salt and body is unambiguous without a length field.
///
/// **The whole body.** Every byte of `body` enters the preimage. `SF-D8`
/// (`ARCHIVAL_SHARD_FETCH.md`) relies on that flat hash: a later holder of
/// the shard recomputes a recorded pass from the shard's archival good and
/// the nonce, and a hash of a precomputable summary can be signed after
/// the bytes are gone and still match.
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
    body: &[u8],
) -> [u8; PASS_DELIVERY_DIGEST_LEN] {
    let mut hasher = PassDeliveryHasher::new(nonce);
    hasher.update(body);
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
/// The persona's receipt key signs it under
/// [`SCHEME_DOMAIN_RECEIPT`], and [`verify_receipt_transcript`] checks it
/// on the fetch client and in the bundle verifier's step 8
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §6, `FN_DSA_HYBRID.md` §9).
#[must_use]
pub fn pass_countersignature_message(
    stream: PassStream,
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    shard_id: u64,
    delivery_digest: &[u8; PASS_DELIVERY_DIGEST_LEN],
) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    const SHARD_END: usize = PASS_REQUEST_HEADER_LEN + 8;
    let mut out = [0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN];
    out[..PASS_REQUEST_HEADER_LEN].copy_from_slice(&pass_request_header_bytes(
        stream,
        nonce,
        anchor_height,
        anchor_hash,
    ));
    out[PASS_REQUEST_HEADER_LEN..SHARD_END].copy_from_slice(&shard_id.to_le_bytes());
    out[SHARD_END..].copy_from_slice(delivery_digest);
    out
}

/// A receipt that does not verify over its transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("receipt does not verify over the pass transcript")]
pub struct ReceiptRefused;

/// Verify a **receipt** over the pass transcript: the 113-byte transcript,
/// signed by the persona's receipt key (Ed25519 + FN-DSA-1024, hybrid
/// scheme 3) under [`SCHEME_DOMAIN_RECEIPT`] (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
/// §6; `FN_DSA_HYBRID.md` §9).
///
/// It has two callers: the fetch client's target (`shekyl-p-fetch`,
/// `target.rs`), which every drawn holder's target is, and the bundle
/// verifier's step 8 (`shekyl-chain-rules`, `archival::bundle::verify_bundle`),
/// which admission runs. Neither builds the message or names the domain
/// itself, so the receipt a persona signs at serve time and the receipt
/// admission verifies cannot drift.
///
/// The transcript's delivery digest is the caller's, recomputed from the
/// body it received ([`pass_delivery_digest`]), so a signature over other
/// bytes fails here.
///
/// # Errors
///
/// [`ReceiptRefused`] if the signature does not verify under
/// `receipt_pubkey`, the receipt domain and this transcript.
pub fn verify_receipt_transcript(
    receipt_pubkey: &FnDsaHybridPublicKey,
    transcript: &PassTranscript,
    signature: &FnDsaHybridSignature,
) -> Result<(), ReceiptRefused> {
    HybridEd25519FnDsa
        .verify(
            receipt_pubkey,
            SCHEME_DOMAIN_RECEIPT,
            &transcript.message(),
            signature,
        )
        .map_err(|_| ReceiptRefused)
}

#[cfg(test)]
#[path = "receipt_transcript_tests.rs"]
mod receipt_transcript_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const fn bh(n: u64) -> BlockHeight {
        BlockHeight::from_raw(n)
    }

    #[test]
    fn pass_request_header_splits_and_rejoins() {
        let h = PassRequestHeader::from_parts(
            PassStream::Economy,
            [0x11; 32],
            bh(0x0102_0304_0506_0708),
            shekyl_types::BlockHash::from_bytes([0x22; 32]),
        );
        let bytes = h.to_bytes();
        assert_eq!(PassRequestHeader::from_bytes(&bytes), Some(h));
        assert_eq!(bytes[0], PassStream::Economy.byte());
        assert_eq!(&bytes[1..33], &[0x11; 32]);
        assert_eq!(
            &bytes[33..41],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&bytes[41..], &[0x22; 32]);
        let mut bad = bytes;
        bad[0] = 2;
        assert!(PassRequestHeader::from_bytes(&bad).is_none());
        assert_eq!(
            h.transcript(9, [0x33; 32]).message(),
            pass_countersignature_message(
                PassStream::Economy,
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
        let header = pass_request_header_bytes(
            PassStream::Economy,
            &nonce,
            bh(0x0102_0304_0506_0708),
            &hash,
        );
        assert_eq!(header.len(), PASS_REQUEST_HEADER_LEN);
        assert_eq!(header[0], 0);
        assert_eq!(&header[1..33], &nonce);
        assert_eq!(
            &header[33..41],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&header[41..73], &hash);

        let digest = [0xCCu8; 32];
        let shard = 0x1112_1314_1516_1718;
        let height = bh(0x0102_0304_0506_0708);
        let msg = pass_countersignature_message(
            PassStream::Economy,
            &nonce,
            height,
            &hash,
            shard,
            &digest,
        );
        assert_eq!(msg.len(), PASS_COUNTERSIGNATURE_MESSAGE_LEN);
        assert_eq!(PASS_COUNTERSIGNATURE_MESSAGE_LEN, 113);
        assert_eq!(&msg[..73], &header);
        assert_eq!(
            &msg[73..81],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(
            &msg[81..],
            &digest,
            "the delivery digest closes the transcript"
        );
        // Every term moves the message. Red edit: drop the stream byte.
        assert_ne!(
            msg,
            pass_countersignature_message(
                PassStream::Support,
                &nonce,
                height,
                &hash,
                shard,
                &digest
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                PassStream::Economy,
                &[0xABu8; 32],
                height,
                &hash,
                shard,
                &digest
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                PassStream::Economy,
                &nonce,
                bh(1),
                &hash,
                shard,
                &digest
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                PassStream::Economy,
                &nonce,
                height,
                &[0xBCu8; 32],
                shard,
                &digest
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(PassStream::Economy, &nonce, height, &hash, 1, &digest)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                PassStream::Economy,
                &nonce,
                height,
                &hash,
                shard,
                &[0xCDu8; 32]
            )
        );
    }

    #[test]
    fn anchor_depth_and_lag_are_the_generated_constants() {
        assert_eq!(PASS_ANCHOR_DEPTH_BLOCKS, BlockCount::from_raw(720));
        assert_eq!(PASS_ANCHOR_LAG_BLOCKS, BlockCount::from_raw(4));
    }
    /// The window a refusal names is the window that outran the anchor,
    /// and nothing else: `None` where the relation holds, including the
    /// epoch too short to have a window, and `Some(W₂)` — the schedule's
    /// own window — from the first epoch whose `W₂ + L` passes the depth.
    /// The boolean predicate is this read's `is_none`. Red edits: `<` for
    /// `<=` names the boundary window; `None` for the overflow arm
    /// accepts a `W₂ + L` that does not fit a `u64`.
    #[test]
    fn the_outrunning_window_is_the_schedules_own_or_none() {
        use crate::constants::W2_EPOCH_DIVISOR;
        use crate::SettlementSchedule;
        use shekyl_types::archival::SettlementEpochBlocks;

        let schedule =
            |seb: u64| SettlementSchedule::new(SettlementEpochBlocks::new(seb).expect("non-zero"));
        let depth = PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
        let lag = PASS_ANCHOR_LAG_BLOCKS.to_raw();
        // The widest window the depth covers, and the last epoch that has it.
        let widest = depth - lag;
        let last_covered = (widest + 1) * W2_EPOCH_DIVISOR - 1;
        let first_past = last_covered + 1;

        assert_eq!(
            response_window_outrunning_anchor(SettlementSchedule::GENESIS),
            None
        );
        assert!(anchor_depth_covers_response_window(
            SettlementSchedule::GENESIS
        ));

        let windowless = schedule(W2_EPOCH_DIVISOR - 1);
        assert_eq!(windowless.challenge_response_blocks(), None);
        assert_eq!(response_window_outrunning_anchor(windowless), None);
        assert!(anchor_depth_covers_response_window(windowless));

        assert_eq!(
            schedule(last_covered).challenge_response_blocks(),
            NonZeroU64::new(widest)
        );
        assert_eq!(
            response_window_outrunning_anchor(schedule(last_covered)),
            None
        );

        for seb in [first_past, first_past * 3, u64::MAX] {
            let named = response_window_outrunning_anchor(schedule(seb))
                .expect("an epoch this long outruns the anchor");
            assert_eq!(Some(named), schedule(seb).challenge_response_blocks());
            assert!(named.get() > widest, "SEB {seb}");
            assert!(!anchor_depth_covers_response_window(schedule(seb)));
        }
    }
}
