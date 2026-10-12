// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **A target is one scheme, decided by its key's type** — held end to end,
//! against the real serving endpoint (`FN_DSA_HYBRID.md` §9, `FND-19`).
//!
//! The serve loop takes its envelope's width from the signer it was bound
//! with, and the fetch client takes the width it reads, the signature it
//! parses and the check it runs from the type of the target's key. Here the
//! two real stacks are put together in all four combinations of the two
//! schemes:
//!
//! | Endpoint signs with | Target's key | Outcome |
//! | --- | --- | --- |
//! | identity key (scheme 1, 3,385) | identity key | verified |
//! | receipt key (scheme 3, 1,356) | receipt key | verified |
//! | identity key | receipt key | refused |
//! | receipt key | identity key | refused |
//!
//! The two refusals are the ruling's "no dual-scheme acceptance": nothing in
//! the client tries the other scheme, measures the response to guess one,
//! or holds a key of either. A response of the other scheme's width fails
//! this scheme's reading of it, and the fetch ends there.
//!
//! The receipt half is STAGED: no production endpoint signs with a receipt
//! key and no production target carries one.

use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, HybridEd25519FnDsa};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey};
use shekyl_p_fetch::{FetchError, PassVerifyingKey};
use shekyl_p_loopback::{
    endpoint_and_client, fetch_target, fixture_body, fixture_expectation, request_header,
    DiscardTxs, PFetchClient, PServeEndpoint, Timeouts, VerifiedShard, FIXTURE_SHARD_ID,
};
use shekyl_p_serve::{
    PassSigner, TestKeySigner, TestReceiptKeySigner, IDENTITY_ENVELOPE_LEN, RECEIPT_ENVELOPE_LEN,
};
use shekyl_types::BlockHeight;

const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

fn timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(1_000),
        body_stall: Duration::from_millis(1_000),
        body_total: Duration::from_millis(2_000),
    }
}

/// A real endpoint that signs with a fresh identity key, and that key.
async fn identity_endpoint() -> (PServeEndpoint, PFetchClient, HybridPublicKey) {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let public = signer.public_key().clone();
    let (endpoint, client) = endpoint_and_client(
        FIXTURE_SHARD_ID,
        fixture_body(),
        signer as Arc<dyn PassSigner<IDENTITY_ENVELOPE_LEN>>,
        timeouts(),
    )
    .await;
    (endpoint, client, public)
}

/// A real endpoint that signs with a fresh receipt key, and that key.
async fn receipt_endpoint() -> (PServeEndpoint, PFetchClient, FnDsaHybridPublicKey) {
    let signer = Arc::new(TestReceiptKeySigner::ephemeral(BlockHeight::from_raw(
        OWN_HEIGHT,
    )));
    let public = signer.public_key().clone();
    let (endpoint, client) = endpoint_and_client(
        FIXTURE_SHARD_ID,
        fixture_body(),
        signer as Arc<dyn PassSigner<RECEIPT_ENVELOPE_LEN>>,
        timeouts(),
    )
    .await;
    (endpoint, client, public)
}

async fn fetch<K: PassVerifyingKey>(
    client: &PFetchClient,
    key: K,
) -> Result<VerifiedShard<K>, FetchError> {
    client
        .fetch(
            &fetch_target(key),
            &request_header(BlockHeight::from_raw(ANCHOR)),
            &fixture_expectation(FIXTURE_SHARD_ID),
            Arc::new(DiscardTxs),
        )
        .await
}

fn other_identity_key() -> HybridPublicKey {
    HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("keygen")
        .0
}

fn other_receipt_key() -> FnDsaHybridPublicKey {
    HybridEd25519FnDsa::generate_keypair().expect("keygen").0
}

#[tokio::test]
async fn each_scheme_verifies_against_its_own_endpoint() {
    let (identity, identity_client, identity_key) = identity_endpoint().await;
    let shard = fetch(&identity_client, identity_key)
        .await
        .expect("an identity target accepts an identity endpoint");
    assert_eq!(
        shard
            .signature()
            .to_canonical_bytes()
            .expect("canonical")
            .len(),
        3_385
    );
    assert_eq!(identity.served_count(), 1);

    let (receipt, receipt_client, receipt_key) = receipt_endpoint().await;
    let shard = fetch(&receipt_client, receipt_key)
        .await
        .expect("a receipt target accepts a receipt endpoint");
    assert_eq!(shard.signature().to_canonical_bytes().len(), 1_356);
    assert_eq!(shard.shard_id().to_raw(), FIXTURE_SHARD_ID);
    assert_eq!(receipt.served_count(), 1);
}

/// The control that makes the refusals below mean something: within one
/// scheme, the wrong key is a bad countersignature. So a refusal across
/// schemes is not this.
#[tokio::test]
async fn the_wrong_key_of_the_right_scheme_is_a_bad_countersignature() {
    let (_identity, client, _) = identity_endpoint().await;
    let err = fetch(&client, other_identity_key()).await.unwrap_err();
    assert!(matches!(err, FetchError::BadCountersignature), "{err:?}");

    let (_receipt, client, _) = receipt_endpoint().await;
    let err = fetch(&client, other_receipt_key()).await.unwrap_err();
    assert!(matches!(err, FetchError::BadCountersignature), "{err:?}");
}

/// The fixture shard is small, so both refusals come from the head, before
/// a body byte is read: the declared length cannot be this scheme's frame
/// plus this scheme's envelope. (Shards large enough to pass the head are
/// refused further in; `client_scheme_tests.rs` scripts those.)
#[tokio::test]
async fn a_receipt_target_refuses_an_identity_endpoints_response() {
    let (_endpoint, client, _) = identity_endpoint().await;
    let err = fetch(&client, other_receipt_key()).await.unwrap_err();
    // More than the frame's ceiling plus a receipt: 3,385 bytes of envelope
    // do not fit where 1,356 are expected.
    assert!(
        matches!(
            err,
            FetchError::Malformed(shekyl_p_fetch::Malformed::Oversize { .. })
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_identity_target_refuses_a_receipt_endpoints_response() {
    let (_endpoint, client, _) = receipt_endpoint().await;
    let err = fetch(&client, other_identity_key()).await.unwrap_err();
    // Fewer bytes than an identity envelope alone.
    assert!(
        matches!(
            err,
            FetchError::Malformed(shekyl_p_fetch::Malformed::EnvelopeShort { .. })
        ),
        "{err:?}"
    );
}

/// Not even the right key helps across schemes — there is no such thing:
/// the endpoint's own key is of the other type and cannot be put in this
/// target. What can be shown at run time is that the refusal does not
/// depend on which key of the target's scheme is asked: it is the same
/// for every one, because it is decided before any key is consulted.
#[tokio::test]
async fn the_cross_scheme_refusal_is_decided_before_any_key_is_consulted() {
    let (_endpoint, client, _) = identity_endpoint().await;
    let first = fetch(&client, other_receipt_key()).await.unwrap_err();
    let second = fetch(&client, other_receipt_key()).await.unwrap_err();
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
}
