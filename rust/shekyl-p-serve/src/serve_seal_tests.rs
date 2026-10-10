// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The countersignature's place in the response: it is the last bytes, it
//! covers the bytes ahead of it, a signer that fails after the body leaves
//! the refusal trailer there, and a persona with no key sends no shard. Split out of the endpoint suite so that
//! file stays under a thousand lines.

use std::sync::Arc;

use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_types::BlockHeight;

use super::{
    bind, fetch, filler, head_of, is_refusal_trailer, render_not_found, render_unavailable,
    FixtureProvider, PServeEndpoint, ANCHOR_HASH, IN_GATE_ANCHOR, NONCE, OWN_HEIGHT,
    REFUSAL_TRAILER_BYTE, SIGNATURE_ENVELOPE_LEN,
};
use crate::countersign::{PassKey, PassSigner, SignRefused};

#[tokio::test]
async fn the_countersignature_is_released_only_after_the_whole_body() {
    // The signature is released last. It is exactly the response's last
    // bytes, and no copy of it appears anywhere ahead of them — so every
    // proper prefix of the response, which is all a reader that stops early
    // can have, is without it.
    let payload = filler(9 * 128, 0x40);
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

    // The body is the provider's bytes from the first one, not a signature.
    assert_eq!(
        &before[end..],
        &payload[..],
        "the whole body, and nothing ahead of it"
    );

    // No earlier copy: a prefix reader never sees the signature.
    assert!(
        !before.windows(SIGNATURE_ENVELOPE_LEN).any(|w| w == sealed),
        "the signature must not appear ahead of the body it seals"
    );
}

/// A signer that says it can sign and then refuses: the fault that is only
/// discovered after the body has gone out.
struct RefusesLate;
impl PassKey for RefusesLate {
    fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }
    fn sign_pass(
        &self,
        _: &[u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new("signer went away"))
    }
}
impl PassSigner for RefusesLate {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

#[tokio::test]
async fn a_signer_that_fails_after_the_body_closes_it_with_the_refusal_trailer() {
    // The signature covers the bytes sent, so it is asked for after them.
    // A signer that refuses then cannot change the status. The persona
    // says so itself: the envelope is the refusal trailer, and the response
    // is its full declared length. A requester never has to infer a refusal
    // from a response that stopped.
    let payload = filler(9 * 128, 0x40);
    let signer: Arc<dyn PassSigner> = Arc::new(RefusesLate);
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
    let (before, trailer) = r.split_at(r.len() - SIGNATURE_ENVELOPE_LEN);
    assert_eq!(&before[end..], &payload[..], "the whole body went out");
    assert!(
        head_of(&r).contains(&format!("content-length: {}", r.len() - end)),
        "the response is exactly its declared length"
    );
    assert_eq!(r.len() - end, payload.len() + SIGNATURE_ENVELOPE_LEN);
    assert!(is_refusal_trailer(trailer));
    assert_eq!(trailer, [REFUSAL_TRAILER_BYTE; SIGNATURE_ENVELOPE_LEN]);
    assert!(
        HybridSignature::from_canonical_bytes(trailer).is_err(),
        "the trailer can never be read as a signature"
    );
    assert_eq!(ep.late_sign_failure_count(), 1);
    assert_eq!(
        ep.sign_failure_count(),
        0,
        "not a pre-flight refusal: the key said yes and the shard went out"
    );
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
}

#[test]
fn a_real_signature_is_never_the_refusal_trailer() {
    // The other direction of the same disjointness: a good read's envelope
    // is not mistaken for a refusal.
    let signer = crate::countersign::TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT));
    let signature = signer
        .sign_pass(
            &[0x5a; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN],
        )
        .expect("sign")
        .to_canonical_bytes()
        .expect("canonical");
    assert_eq!(signature.len(), SIGNATURE_ENVELOPE_LEN);
    assert!(!is_refusal_trailer(&signature));
    assert!(!is_refusal_trailer(&[]));
}

/// A persona with no resident key: it knows before the first byte.
struct Keyless;
impl PassKey for Keyless {
    fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> {
        Err(SignRefused::new("not resident"))
    }
    fn sign_pass(
        &self,
        _: &[u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new("not resident"))
    }
}
impl PassSigner for Keyless {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

#[tokio::test]
async fn a_persona_with_no_key_answers_503_and_sends_no_shard() {
    // No key is known before the first byte, so the shard is not sent only
    // to go uncountersigned. A held shard never 404s: the answer is the
    // bare 503. An unheld shard is still the 404, and an invalid request
    // still the 400 — the key is not what decides either.
    let signer: Arc<dyn PassSigner> = Arc::new(Keyless);
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, filler(9 * 128, 0x40))]), signer)
        .await
        .expect("bind");
    assert_eq!(
        fetch(ep.addr(), "/shard/0").await,
        render_unavailable().as_bytes()
    );
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.late_sign_failure_count(), 0, "no shard was sent");
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);

    assert_eq!(
        fetch(ep.addr(), "/shard/9").await,
        render_not_found().as_bytes()
    );
    assert_eq!(ep.sign_failure_count(), 1, "an unheld shard asks no key");
}
