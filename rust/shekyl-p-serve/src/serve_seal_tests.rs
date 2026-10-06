// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The countersignature's place in the response: it is the last bytes, it
//! covers the bytes ahead of it, and a held shard whose signer fails goes
//! out as a body with no signature. Split out of the endpoint suite so that
//! file stays under a thousand lines.

use std::sync::Arc;

use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::ServedFrameHeader;
use shekyl_types::BlockHeight;

use super::{
    bind, fetch, head_of, leaves, render_not_found, FixtureProvider, PServeEndpoint, ANCHOR_HASH,
    IN_GATE_ANCHOR, NONCE, OWN_HEIGHT, SIGNATURE_ENVELOPE_LEN,
};
use crate::countersign::{PassKey, PassSigner, SignRefused};

#[tokio::test]
async fn the_countersignature_is_released_only_after_the_whole_frame() {
    // The signature is released last. It is exactly the response's last
    // bytes, and no copy of it appears anywhere ahead of them — so every
    // proper prefix of the response, which is all a reader that stops early
    // can have, is without it.
    let payload = leaves(9, 0x40);
    let (ep, signer) = bind(FixtureProvider::new([(0, payload.clone())])).await;
    let r = fetch(ep.addr(), "/shard/0").await;

    let end = r
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head")
        + 4;
    let (before, sealed) = r.split_at(r.len() - SIGNATURE_ENVELOPE_LEN);
    let signature =
        HybridSignature::from_canonical_bytes(sealed).expect("the last bytes are the signature");
    verify_pass_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        0,
        &pass_delivery_digest(&NONCE, &before[end..]),
        &signature,
    )
    .expect("the closing signature covers this request and the bytes ahead of it");

    // The first body bytes are the frame, not a signature.
    let mut framed = &before[end..];
    let frame = ServedFrameHeader::read(&mut framed).expect("the body opens with the frame");
    assert_eq!(frame.segment_bytes(), payload.len() as u64);
    assert_eq!(framed, &payload[..], "frame header, then the whole segment");

    // No earlier copy: a prefix reader never sees the signature.
    assert!(
        !before.windows(SIGNATURE_ENVELOPE_LEN).any(|w| w == sealed),
        "the signature must not appear ahead of the frame it seals"
    );
}

/// A signer that holds no key: it knows its height and refuses to sign.
struct Refusing;
impl PassKey for Refusing {
    fn sign_pass(
        &self,
        _: &[u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new("not resident"))
    }
}
impl PassSigner for Refusing {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

#[tokio::test]
async fn a_signer_that_refuses_leaves_a_whole_body_with_no_signature() {
    // The signature covers the bytes sent, so it is asked for after them.
    // A signer that refuses then cannot be a 404: the shard is held, the
    // 200 and the whole frame are already out. The response ends there,
    // short of its `content-length` by exactly one envelope, which a
    // fetcher reads as a read this persona failed.
    let payload = leaves(9, 0x40);
    let signer: Arc<dyn PassSigner> = Arc::new(Refusing);
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload.clone())]), signer)
        .await
        .expect("bind");
    let r = fetch(ep.addr(), "/shard/0").await;

    assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    let end = r
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head")
        + 4;
    let mut framed = &r[end..];
    let frame = ServedFrameHeader::read(&mut framed).expect("the body opens with the frame");
    assert_eq!(
        framed,
        &payload[..],
        "the whole segment, and nothing after it"
    );
    assert_eq!(
        (r.len() - end) as u64,
        frame.framed_len(),
        "the response stops at the end of the frame: no envelope follows"
    );
    assert!(
        head_of(&r).contains(&format!(
            "content-length: {}",
            frame.framed_len() + SIGNATURE_ENVELOPE_LEN as u64
        )),
        "so it is short of its declared length by exactly one signature"
    );
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);

    // An unheld shard is the ordinary 404 — neither a lookup failure nor a
    // sign failure: the signer is never asked about a shard that is not
    // sent.
    let r = fetch(ep.addr(), "/shard/9").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
}
