// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **STAGED** — the resident **receipt** key behind the real serving
//! endpoint, answering the real fetch client, verified under the persona's
//! receipt public key (`FN_DSA_HYBRID.md` §9).
//!
//! The receipt-scheme counterpart of [`super::round_trip_tests`], and the
//! proof that what is left for the cutover is selection: the capability is
//! handed to the endpoint as its signer, the endpoint closes its responses
//! with scheme-3 receipts at the receipt width, and a fetch target built
//! over the receipt key accepts them. Nothing here is on the live path —
//! the serving task is not started with this capability.
//!
//! It also holds the two properties the staging rests on from the outside:
//! the two schemes do not accept each other's responses in either
//! direction, and a receipt key that does not decode costs one response its
//! signature and every later request a bare 503.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_p_host::{signer_at_synced_tip, PassKey, IDENTITY_ENVELOPE_LEN, RECEIPT_ENVELOPE_LEN};
use shekyl_p_loopback::{
    endpoint_and_client, fetch_target, fixture_body, fixture_expectation, request_header,
    DiscardTxs, FetchError, PFetchClient, PServeEndpoint, PassVerifyingKey, Timeouts,
    VerifiedShard, FIXTURE_SHARD_ID,
};
use shekyl_types::BlockHeight;

use super::pass_key::ResidentPassKey;
use super::receipt_key::ResidentReceiptKey;
use crate::engine::stake_engine::handle::StakeEngineHandle;
use crate::engine::stake_engine::receipt_test_fixtures::{slot, OTHER_SLOT, SLOT};
use crate::engine::stake_engine::test_fixtures::{derive_bundle, ephemeral_body_store, spawn_over};

const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const TIP_MAX_AGE: Duration = Duration::from_secs(120);

/// As [`super::round_trip_tests`]' bounds: one hybrid sign and a mailbox
/// round-trip on a slow host — and here the first receipt also decodes the
/// key.
fn proving_timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(2_000),
        body_stall: Duration::from_millis(5_000),
        body_total: Duration::from_millis(10_000),
    }
}

/// The real endpoint over the fixture shard, signing with the receipt
/// capability for `raw`, and a client aimed at it.
async fn receipt_endpoint(stake: &StakeEngineHandle, raw: u32) -> (PServeEndpoint, PFetchClient) {
    let key: Arc<dyn PassKey<RECEIPT_ENVELOPE_LEN>> = ResidentReceiptKey::new(stake, slot(raw));
    let signer = signer_at_synced_tip(key, BlockHeight::from_raw(OWN_HEIGHT), TIP_MAX_AGE);
    endpoint_and_client(FIXTURE_SHARD_ID, fixture_body(), signer, proving_timeouts()).await
}

/// The same endpoint signing with the live capability, the identity key.
async fn identity_endpoint(stake: &StakeEngineHandle, raw: u32) -> (PServeEndpoint, PFetchClient) {
    let key: Arc<dyn PassKey<IDENTITY_ENVELOPE_LEN>> = ResidentPassKey::new(stake, slot(raw));
    let signer = signer_at_synced_tip(key, BlockHeight::from_raw(OWN_HEIGHT), TIP_MAX_AGE);
    endpoint_and_client(FIXTURE_SHARD_ID, fixture_body(), signer, proving_timeouts()).await
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

/// The capability, as the endpoint's signer, produces a response the fetch
/// client accepts under the persona's receipt key — and under no other
/// receipt key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_client_accepts_a_receipt_the_resident_key_signed() {
    let stake = spawn_over(&[SLOT, OTHER_SLOT], &[SLOT], Some(SLOT));
    let (endpoint, client) = receipt_endpoint(&stake, SLOT).await;

    let shard = fetch(&client, derive_bundle(SLOT).receipt_sign_pk.clone())
        .await
        .expect("the receipt verifies under the persona's receipt key");
    assert_eq!(shard.shard_id().to_raw(), FIXTURE_SHARD_ID);
    assert_eq!(shard.signature().to_canonical_bytes().len(), 1_356);
    assert_eq!(endpoint.served_count(), 1);
    assert_eq!(endpoint.sign_failure_count(), 0);
    assert_eq!(endpoint.late_sign_failure_count(), 0);

    let err = fetch(&client, derive_bundle(OTHER_SLOT).receipt_sign_pk.clone())
        .await
        .expect_err("another persona's receipt key refuses the same receipt");
    assert!(matches!(err, FetchError::BadCountersignature), "{err}");
}

/// One persona, both capabilities, both directions. A target built over
/// the bond identity refuses the receipt endpoint, and a target built over
/// the receipt key refuses the identity endpoint — and each accepts its
/// own, so the live scheme is seen working beside the staged one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_two_schemes_do_not_accept_each_others_endpoints() {
    let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
    let bundle = derive_bundle(SLOT);
    let identity_key = bundle.hybrid_bond_id().clone();
    let receipt_key = bundle.receipt_sign_pk.clone();

    let (_receipts, receipt_client) = receipt_endpoint(&stake, SLOT).await;
    let (_passes, identity_client) = identity_endpoint(&stake, SLOT).await;

    fetch(&identity_client, identity_key.clone())
        .await
        .expect("the live scheme: identity target, identity endpoint");
    fetch(&receipt_client, receipt_key.clone())
        .await
        .expect("the staged scheme: receipt target, receipt endpoint");

    let err = fetch(&receipt_client, identity_key)
        .await
        .expect_err("an identity target refuses a receipt endpoint");
    assert!(matches!(err, FetchError::Malformed(_)), "{err}");
    let err = fetch(&identity_client, receipt_key)
        .await
        .expect_err("a receipt target refuses an identity endpoint");
    assert!(matches!(err, FetchError::Malformed(_)), "{err}");
}

/// The obligation the cutover inherits, seen from the wire. The receipt key
/// is decoded by the first signature, so an undecodable key is found by the
/// first reader: that response goes out whole and is closed with the
/// refusal trailer. From then on the capability's pre-flight refuses, and
/// every reader gets the bare 503 before any shard byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecodable_receipt_key_costs_one_response_then_refuses_at_pre_flight() {
    let mut bundle = derive_bundle(SLOT);
    bundle.receipt_sign_sk.corrupt_fn_dsa_half_for_tests();
    let receipt_key = bundle.receipt_sign_pk.clone();
    let stake = StakeEngineHandle::spawn(
        BTreeMap::from([(slot(SLOT), bundle)]),
        BTreeSet::from([slot(SLOT)]),
        Some(slot(SLOT)),
        ephemeral_body_store(),
    );
    let (endpoint, client) = receipt_endpoint(&stake, SLOT).await;

    let first = fetch(&client, receipt_key.clone())
        .await
        .expect_err("the first reader finds the key");
    assert!(matches!(first, FetchError::Unsigned), "{first}");
    assert_eq!(endpoint.late_sign_failure_count(), 1);
    assert_eq!(endpoint.sign_failure_count(), 0);

    for expected_refusals in 1..=2 {
        let later = fetch(&client, receipt_key.clone())
            .await
            .expect_err("later readers are refused before any shard byte");
        assert!(matches!(later, FetchError::Unavailable), "{later}");
        assert_eq!(endpoint.sign_failure_count(), expected_refusals);
    }
    assert_eq!(
        endpoint.late_sign_failure_count(),
        1,
        "no second shard was sent unsigned"
    );
    assert_eq!(endpoint.served_count(), 0);
}
