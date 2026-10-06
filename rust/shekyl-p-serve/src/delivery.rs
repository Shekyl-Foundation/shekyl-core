// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which bytes a pass countersignature digests.
//!
//! The store is read once per response. Each chunk is folded through this
//! type as it is written, and the signature is made over the finished
//! digest and appended. So the signed bytes are the sent bytes by
//! construction, and no more than one chunk of a shard is resident: the
//! serve ceiling stays a count of connections, not a whole-shard memory
//! budget.
//!
//! Signing therefore comes after the body. A signer that fails then cannot
//! change the status — the 200 is already out — so the envelope is written
//! as the refusal trailer in place of the signature. A persona that knows
//! before the first byte that it has no key answers 503 and sends nothing.
//!
//! One fold, rather than a hasher opened by hand at the call site, so the
//! signed bytes are defined once: the `RF-D4` frame header, then every
//! payload chunk, and nothing else. A body that is not exactly the length
//! its frame declares has no digest.

use shekyl_archival_retention::{PassDeliveryHasher, PASS_DELIVERY_DIGEST_LEN, PASS_NONCE_LEN};
use shekyl_curve_tree::served_frame::ServedFrameHeader;

/// Running digest of the framed body ahead of the countersignature.
pub(super) struct FramedDigest {
    hasher: PassDeliveryHasher,
    /// The frame header bytes. Absorbed into [`Self::hasher`] at
    /// [`Self::start`], and retained so the sender writes the bytes it hashed.
    frame_bytes: Vec<u8>,
    /// [`ServedFrameHeader::framed_len`]: header, payload, and padding.
    framed_len: u64,
    /// Bytes absorbed so far, including the frame header.
    absorbed: u64,
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
        let absorbed = u64::try_from(frame_bytes.len()).ok()?;
        let mut hasher = PassDeliveryHasher::new(nonce);
        hasher.update(&frame_bytes);
        Some(Self {
            hasher,
            frame_bytes,
            framed_len: frame.framed_len(),
            absorbed,
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
        let absorbed = self.absorbed.checked_add(len)?;
        if absorbed > self.framed_len {
            return None;
        }
        self.hasher.update(chunk);
        self.absorbed = absorbed;
        Some(())
    }

    /// The digest, if the absorbed bytes are exactly the frame's declared
    /// length. A short body is `None`: it is not a prefix someone may sign.
    pub(super) fn finish(self) -> Option<[u8; PASS_DELIVERY_DIGEST_LEN]> {
        if self.absorbed != self.framed_len {
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
    fn a_later_holder_rebuilds_the_write_zero_frame_from_the_leaves() {
        let nonce = [0x11u8; PASS_NONCE_LEN];
        for leaves in [0usize, 1, 3] {
            let frame = ServedFrameHeader::for_segment(leaves).expect("in range");
            let payload_len = usize::try_from(frame.segment_bytes()).expect("length fits");
            let payload = vec![0x5a; payload_len];
            let rebuilt =
                ServedFrameHeader::for_segment(payload.len() / shekyl_curve_tree::LEAF_BYTES)
                    .expect("the leaf count is the byte length");
            assert_eq!(
                rebuilt, frame,
                "write-zero padding makes the header a function of the leaves"
            );
            let mut framed = rebuilt.to_bytes();
            framed.extend_from_slice(&payload);
            let mut running = FramedDigest::start(&rebuilt, &nonce).expect("start");
            running.absorb(&payload).expect("payload fits the frame");
            assert_eq!(
                running.finish(),
                Some(pass_delivery_digest(&nonce, &framed)),
                "{leaves} leaves: the holder recomputes the digest from the leaves and the nonce"
            );
        }
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
