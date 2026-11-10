// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve loop's envelope: the receipt (hybrid scheme 3, 1,356 bytes,
//! `FN_DSA_HYBRID.md` §9).
//!
//! These tests bind the loop with a receipt signer and hold each place
//! the envelope's width reaches: its length and position, the content
//! length, and the refusal trailer's fill.

use std::sync::Arc;

use shekyl_archival_retention::{pass_delivery_digest, verify_receipt_transcript};
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_types::BlockHeight;

use super::{
    filler, good_get_shard_0, is_refusal_trailer, request_raw, serve_one_in_memory,
    FixtureProvider, InMemoryServe, PServeEndpoint, ANCHOR_HASH, IN_GATE_ANCHOR, NONCE, OWN_HEIGHT,
    REFUSAL_TRAILER_BYTE,
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
fn the_envelope_is_a_receipts_length() {
    assert_eq!(RECEIPT_ENVELOPE_LEN, RECEIPT_LEN);
    assert_eq!(RECEIPT_ENVELOPE_LEN, FnDsaHybridSignature::CANONICAL_LEN);
}

#[tokio::test]
async fn an_endpoint_bound_with_a_receipt_signer_closes_with_a_receipt() {
    let payload = filler(9 * 128, 0x40);
    let signer = Arc::new(TestReceiptKeySigner::ephemeral(BlockHeight::from_raw(
        OWN_HEIGHT,
    )));
    let endpoint = PServeEndpoint::bind(
        FixtureProvider::new([(0, payload.clone())]),
        Arc::clone(&signer) as Arc<dyn PassSigner>,
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
        &shekyl_archival_retention::PassTranscript::new(
            shekyl_archival_retention::PassRequestHeader::from_parts(
                shekyl_archival_retention::PassStream::Economy,
                NONCE,
                BlockHeight::from_raw(IN_GATE_ANCHOR),
                shekyl_types::BlockHash::from_bytes(ANCHOR_HASH),
            ),
            0,
            pass_delivery_digest(&NONCE, &ahead[body_start..]),
        ),
        &receipt,
    )
    .expect("the receipt verifies under the receipt key");
    assert!(HybridSignature::from_canonical_bytes(envelope).is_err());
    assert_eq!(endpoint.served_count(), 1);

    // The in-memory composition writes the same shape.
    let mut composed = Vec::new();
    let outcome = serve_one_in_memory(
        &*FixtureProvider::new([(0, payload.clone())]),
        &*signer as &dyn PassSigner,
        good_get_shard_0().as_bytes(),
        &mut composed,
    );
    assert_eq!(outcome, InMemoryServe::Served);
    assert_eq!(composed.len(), response.len());
    assert_eq!(composed[..ahead.len()], *ahead);
}

/// A receipt signer that says it can sign and then refuses.
struct ReceiptRefusesLate;
impl PassKey for ReceiptRefusesLate {
    fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }
    fn sign_pass(&self, _: &crate::PassTranscript) -> Result<FnDsaHybridSignature, SignRefused> {
        Err(SignRefused::new("signer went away"))
    }
}
impl PassSigner for ReceiptRefusesLate {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

#[tokio::test]
async fn the_refusal_trailer_is_the_signers_width() {
    let payload = filler(9 * 128, 0x40);
    let signer: Arc<dyn PassSigner> = Arc::new(ReceiptRefusesLate);
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
