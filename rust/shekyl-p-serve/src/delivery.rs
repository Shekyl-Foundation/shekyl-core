// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which bytes a pass countersignature digests.
//!
//! The store is read twice per response, and both reads digest through this
//! type. The decision of 2026-10-04
//! (`docs/V3_WALLET_DECISION_LOG.md`) is why there are two: `P` must know
//! the digest before it signs, it signs before the first response byte so a
//! refusal is the shared 404, and it does not retain the shard between those
//! moments — one resident shard per in-flight connection would make the
//! serve ceiling a whole-shard memory budget. The second read is the one
//! that is written. Its digest is this same fold, and the signature is
//! released only when the two digests are equal.
//!
//! One fold, rather than a hasher opened by hand at each call site, so the
//! signed bytes and the sent bytes are defined once: the `RF-D4` frame
//! header, then every payload chunk, and nothing else. A body that is not
//! exactly the length its frame declares has no digest.

use shekyl_archival_retention::{PassDeliveryHasher, PASS_DELIVERY_DIGEST_LEN, PASS_NONCE_LEN};
use shekyl_curve_tree::served_frame::ServedFrameHeader;

/// Running digest of the framed body ahead of the countersignature.
pub(super) struct FramedDigest {
    hasher: PassDeliveryHasher,
    /// The frame header bytes. Absorbed into [`Self::hasher`] at
    /// [`Self::start`], and retained so the sender writes the bytes it hashed.
    frame_bytes: Vec<u8>,
    /// [`ServedFrameHeader::framed_len`]: header, payload, and padding.
    expect: u64,
    /// Bytes absorbed so far, including the frame header.
    read: u64,
}

impl FramedDigest {
    /// Start a digest of `frame` under `nonce`, with the frame header already
    /// absorbed.
    ///
    /// `None` if the header's length does not fit the running total. A frame
    /// this crate can build does not hit that; the `Option` is the overflow
    /// the addition is not allowed to ignore.
    pub(super) fn start(frame: &ServedFrameHeader, nonce: &[u8; PASS_NONCE_LEN]) -> Option<Self> {
        let frame_bytes = frame.to_bytes();
        let read = u64::try_from(frame_bytes.len()).ok()?;
        let mut hasher = PassDeliveryHasher::new(nonce);
        hasher.update(&frame_bytes);
        Some(Self {
            hasher,
            frame_bytes,
            expect: frame.framed_len(),
            read,
        })
    }

    /// The frame header bytes absorbed at [`Self::start`].
    pub(super) fn frame_bytes(&self) -> &[u8] {
        &self.frame_bytes
    }

    /// Absorb the next payload chunk.
    ///
    /// `None` when the chunk would carry the running total past the frame's
    /// declared length, or when its length does not fit a `u64`. The digest
    /// is left unchanged in that case, so the caller stops rather than
    /// signing or sending a body the frame does not describe.
    pub(super) fn absorb(&mut self, chunk: &[u8]) -> Option<()> {
        let len = u64::try_from(chunk.len()).ok()?;
        let read = self.read.checked_add(len)?;
        if read > self.expect {
            return None;
        }
        self.hasher.update(chunk);
        self.read = read;
        Some(())
    }

    /// The digest, if the absorbed bytes are exactly the frame's declared
    /// length. A short body is `None`: it is not a prefix someone may sign.
    pub(super) fn finish(self) -> Option<[u8; PASS_DELIVERY_DIGEST_LEN]> {
        if self.read != self.expect {
            return None;
        }
        Some(self.hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use shekyl_archival_retention::pass_delivery_digest;

    use super::*;

    fn one_leaf() -> (ServedFrameHeader, Vec<u8>) {
        let frame = ServedFrameHeader::for_segment(1).expect("one leaf is a segment");
        let payload_len =
            usize::try_from(frame.framed_len()).expect("length fits") - frame.encoded_len();
        (frame, vec![0x5a; payload_len])
    }

    #[test]
    fn the_digest_is_the_frame_then_the_payload_at_every_split() {
        let (frame, payload) = one_leaf();
        let nonce = [0x03u8; PASS_NONCE_LEN];
        let mut whole = FramedDigest::start(&frame, &nonce).expect("start");
        assert_eq!(whole.frame_bytes(), frame.to_bytes());
        whole.absorb(&payload).expect("payload fits the frame");
        let digest = whole.finish().expect("exact length");
        let mut framed = frame.to_bytes();
        framed.extend_from_slice(&payload);
        assert_eq!(
            digest,
            pass_delivery_digest(&nonce, &framed),
            "the fold is the one-shot digest of the bytes ahead of the signature"
        );

        for split in 0..=payload.len() {
            let mut running = FramedDigest::start(&frame, &nonce).expect("start");
            running.absorb(&payload[..split]).expect("prefix fits");
            running.absorb(&payload[split..]).expect("rest fits");
            assert_eq!(running.finish(), Some(digest), "split at {split}");
        }
    }

    #[test]
    fn a_short_body_and_a_long_one_have_no_digest() {
        let (frame, payload) = one_leaf();
        let nonce = [0x03u8; PASS_NONCE_LEN];

        let mut short = FramedDigest::start(&frame, &nonce).expect("start");
        short
            .absorb(&payload[..payload.len() - 1])
            .expect("prefix fits");
        assert!(short.finish().is_none(), "a short body is not signed");

        let mut long = FramedDigest::start(&frame, &nonce).expect("start");
        long.absorb(&payload).expect("exact payload fits");
        assert!(
            long.absorb(&[0]).is_none(),
            "a byte past the frame is refused before it is absorbed"
        );
    }

    #[test]
    fn an_empty_segment_digests_to_its_header_alone() {
        let frame = ServedFrameHeader::for_segment(0).expect("empty segment");
        let nonce = [0x03u8; PASS_NONCE_LEN];
        let running = FramedDigest::start(&frame, &nonce).expect("start");
        assert_eq!(
            u64::try_from(running.frame_bytes().len()).expect("header length"),
            frame.framed_len()
        );
        assert_eq!(
            running.finish(),
            Some(pass_delivery_digest(&nonce, &frame.to_bytes()))
        );
    }
}
