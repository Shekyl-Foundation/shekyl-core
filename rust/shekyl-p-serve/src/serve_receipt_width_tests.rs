// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve loop at the **receipt** width (hybrid scheme 3, 1,356 bytes) —
//! STAGED: no production endpoint is bound at it (`FN_DSA_HYBRID.md` §9).
//!
//! The loop names no width of its own, so everything it writes that
//! depends on one must follow the signer it was bound with. These tests
//! bind it with a receipt signer and hold each such place: the envelope's
//! length and position, the content length, and the refusal trailer's
//! fill. The live width's bytes are held separately, against captured
//! fixtures, in `serve_wire_pin_tests.rs`.

use std::sync::Arc;

use shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_archival_retention::{pass_delivery_digest, verify_receipt_transcript};
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_types::BlockHeight;

use super::{
    filler, good_get_shard_0, is_refusal_trailer, request_raw, serve_one_in_memory,
    FixtureProvider, InMemoryServe, PServeEndpoint, ANCHOR_HASH, IDENTITY_ENVELOPE_LEN,
    IN_GATE_ANCHOR, NONCE, OWN_HEIGHT, REFUSAL_TRAILER_BYTE,
};
use crate::countersign::{
    PassKey, PassSigner, SignRefused, TestReceiptKeySigner, RECEIPT_ENVELOPE_LEN,
};

/// The receipt envelope's width, as a number.
const RECEIPT_LEN: usize = 1_356;

fn head_end(response: &[u8]) -> usize {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head")
        + 4
}

fn content_length_of(response: &[u8]) -> usize {
    String::from_utf8_lossy(&response[..head_end(response)])
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("a content length")
        .parse()
        .expect("a number")
}

#[test]
fn the_two_widths_are_the_two_schemes_lengths() {
    assert_eq!(RECEIPT_ENVELOPE_LEN, RECEIPT_LEN);
    assert_eq!(RECEIPT_ENVELOPE_LEN, FnDsaHybridSignature::CANONICAL_LEN);
    assert_eq!(IDENTITY_ENVELOPE_LEN, 3_385);
    assert_eq!(IDENTITY_ENVELOPE_LEN, HybridSignature::CANONICAL_LEN);
}

#[tokio::test]
async fn an_endpoint_bound_with_a_receipt_signer_closes_with_a_receipt() {
    let payload = filler(9 * 128, 0x40);
    let signer = Arc::new(TestReceiptKeySigner::ephemeral(BlockHeight::from_raw(
        OWN_HEIGHT,
    )));
    let endpoint = PServeEndpoint::bind(
        FixtureProvider::new([(0, payload.clone())]),
        Arc::clone(&signer) as Arc<dyn PassSigner<RECEIPT_ENVELOPE_LEN>>,
    )
    .await
    .expect("bind");
    let response = request_raw(endpoint.addr(), &good_get_shard_0()).await;

    // The content length counts the body and a receipt-width envelope, and
    // the response is exactly that long behind its head.
    let body_start = head_end(&response);
    assert_eq!(content_length_of(&response), payload.len() + RECEIPT_LEN);
    assert_eq!(response.len() - body_start, payload.len() + RECEIPT_LEN);

    // The envelope is the last 1,356 bytes, a canonical scheme-3 signature
    // over this request and the bytes ahead of it, under the receipt
    // domain. It is not an identity signature.
    let (ahead, envelope) = response.split_at(response.len() - RECEIPT_LEN);
    assert_eq!(&ahead[body_start..], &payload[..]);
    let receipt = FnDsaHybridSignature::from_canonical_bytes(envelope).expect("a receipt");
    verify_receipt_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        0,
        &pass_delivery_digest(&NONCE, &ahead[body_start..]),
        &receipt,
    )
    .expect("the receipt verifies under the receipt key");
    assert!(HybridSignature::from_canonical_bytes(envelope).is_err());
    assert_eq!(endpoint.served_count(), 1);

    // The in-memory composition writes the same shape.
    let mut composed = Vec::new();
    let outcome = serve_one_in_memory(
        &*FixtureProvider::new([(0, payload.clone())]),
        &*signer as &dyn PassSigner<RECEIPT_ENVELOPE_LEN>,
        good_get_shard_0().as_bytes(),
        &mut composed,
    );
    assert_eq!(outcome, InMemoryServe::Served);
    assert_eq!(composed.len(), response.len());
    assert_eq!(composed[..ahead.len()], *ahead);
}

/// A receipt signer that says it can sign and then refuses.
struct ReceiptRefusesLate;
impl PassKey<RECEIPT_ENVELOPE_LEN> for ReceiptRefusesLate {
    fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }
    fn sign_pass(
        &self,
        _: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        Err(SignRefused::new("signer went away"))
    }
}
impl PassSigner<RECEIPT_ENVELOPE_LEN> for ReceiptRefusesLate {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

#[tokio::test]
async fn the_refusal_trailer_is_the_signers_width() {
    let payload = filler(9 * 128, 0x40);
    let signer: Arc<dyn PassSigner<RECEIPT_ENVELOPE_LEN>> = Arc::new(ReceiptRefusesLate);
    let endpoint = PServeEndpoint::bind(FixtureProvider::new([(0, payload.clone())]), signer)
        .await
        .expect("bind");
    let response = request_raw(endpoint.addr(), &good_get_shard_0()).await;

    let body_start = head_end(&response);
    assert_eq!(content_length_of(&response), payload.len() + RECEIPT_LEN);
    assert_eq!(response.len() - body_start, payload.len() + RECEIPT_LEN);
    let (ahead, trailer) = response.split_at(response.len() - RECEIPT_LEN);
    assert_eq!(trailer, [REFUSAL_TRAILER_BYTE; RECEIPT_LEN]);
    assert!(is_refusal_trailer(trailer));
    // Exactly the receipt's width of fill: the byte ahead of it is the
    // body's last, not a 3,385-byte trailer's first.
    assert_eq!(&ahead[body_start..], &payload[..]);
    assert_eq!(endpoint.late_sign_failure_count(), 1);
    assert_eq!(endpoint.served_count(), 0);
}
