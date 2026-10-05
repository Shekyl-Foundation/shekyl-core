// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two-read seal: the countersignature is the response's last bytes,
//! and it is withheld when the sent body is not the body that was signed.
//! Split out of the endpoint suite so that file stays under a thousand lines.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::ServedFrameHeader;
use shekyl_types::BlockHeight;

use super::{
    bind, fetch, head_of, leaves, render_not_found, FixtureProvider, ANCHOR_HASH, IN_GATE_ANCHOR,
    NONCE, SIGNATURE_ENVELOPE_LEN,
};
use crate::provider::{ProviderError, ShardBody, ShardProvider};

/// Provider that answers the first `shard_bytes` with one body and every
/// later call with another. A conforming store cannot do this: it is the
/// fault the two-read serve has to survive, built by wrapper (rule 50).
struct ShiftingProvider {
    first: Arc<[u8]>,
    later: Option<Arc<[u8]>>,
    calls: AtomicUsize,
}

impl ShiftingProvider {
    fn new(first: Vec<u8>, later: Option<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            first: Arc::from(first.into_boxed_slice()),
            later: later.map(|b| Arc::from(b.into_boxed_slice())),
            calls: AtomicUsize::new(0),
        })
    }
}

impl ShardProvider for ShiftingProvider {
    fn shard_bytes(&self, _shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let bytes = if call == 0 {
            Some(Arc::clone(&self.first))
        } else {
            self.later.clone()
        };
        Ok(bytes.and_then(ShardBody::flat))
    }
}

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

#[tokio::test]
async fn a_body_that_changes_between_the_signed_read_and_the_sent_one_gets_no_signature() {
    // The persona hashes the body, signs, then streams a second read. If
    // the store answers that second read with other bytes, the signature
    // describes bytes that were not sent — so it must not be sent either.
    // The response ends after the body, short of its `content-length`,
    // which a fetcher reads as a truncated transfer.
    let signed_for = leaves(9, 0x40);
    let mut sent = signed_for.clone();
    *sent.last_mut().expect("nine leaves") ^= 1;
    let (ep, signer) = bind(ShiftingProvider::new(
        signed_for.clone(),
        Some(sent.clone()),
    ))
    .await;
    let r = fetch(ep.addr(), "/shard/0").await;

    assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    let end = r
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head")
        + 4;
    let mut framed = &r[end..];
    let frame = ServedFrameHeader::read(&mut framed).expect("the body opens with the frame");
    assert_eq!(framed, &sent[..], "the body on the wire is the second read");
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
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.lookup_failure_count(), 1);
    assert_eq!(ep.sign_failure_count(), 0);
    let _ = signer;
}

#[tokio::test]
async fn a_shard_that_vanishes_between_the_two_reads_is_the_identical_404() {
    // Signed for, then gone before it could be sent: nothing has been
    // written, so this is still the shared miss, counted as a store fault.
    let (ep, _) = bind(ShiftingProvider::new(leaves(9, 0x40), None)).await;
    let r = fetch(ep.addr(), "/shard/0").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.lookup_failure_count(), 1);

    // And a shard whose frame changed (a different length) between them.
    let (ep, _) = bind(ShiftingProvider::new(
        leaves(9, 0x40),
        Some(leaves(8, 0x40)),
    ))
    .await;
    let r = fetch(ep.addr(), "/shard/0").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(ep.lookup_failure_count(), 1);
}
