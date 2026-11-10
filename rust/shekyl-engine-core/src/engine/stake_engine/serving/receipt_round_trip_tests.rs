// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SH-2's proving test: the persona's resident **receipt** key behind the
//! real serving endpoint, answering the real fetch client, verified under
//! the persona's receipt public key — the key the bond record publishes
//! (`FN_DSA_HYBRID.md` §9).
//!
//! What only this layer can prove is that the receipt the wallet produces
//! is the one the daemon's client *accepts*: same transcript bytes, same
//! envelope, same anchor gate. The loopback is `shekyl-p-loopback`
//! (`SH2_RESIDENT_KEY_AUDIT.md` §3 Q4). It also holds, from the outside,
//! that a receipt key that does not decode costs one response per
//! capability and every later request through that capability a bare 503.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_p_host::{signer_at_synced_tip, PassKey};
use shekyl_p_loopback::{
    endpoint_and_client, fetch_target, fixture_body, fixture_expectation, request_header,
    DiscardTxs, FetchError, PFetchClient, PServeEndpoint, Timeouts, VerifiedShard,
    FIXTURE_SHARD_ID,
};
use shekyl_types::BlockHeight;

use super::receipt_key::ResidentReceiptKey;
use crate::engine::stake_engine::handle::StakeEngineHandle;
use crate::engine::stake_engine::receipt_test_fixtures::{slot, OTHER_SLOT, SLOT};
use crate::engine::stake_engine::test_fixtures::{derive_bundle, ephemeral_body_store, spawn_over};

const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const TIP_MAX_AGE: Duration = Duration::from_secs(120);

/// One hybrid sign and a mailbox round-trip on a slow host, and the first
/// receipt also decodes the key.
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
    let key: Arc<dyn PassKey> = ResidentReceiptKey::new(stake, slot(raw));
    let signer = signer_at_synced_tip(key, BlockHeight::from_raw(OWN_HEIGHT), TIP_MAX_AGE);
    endpoint_and_client(FIXTURE_SHARD_ID, fixture_body(), signer, proving_timeouts()).await
}

async fn fetch(
    client: &PFetchClient,
    key: FnDsaHybridPublicKey,
) -> Result<VerifiedShard, FetchError> {
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

/// The obligation the cutover inherits, seen from the wire. The receipt key
/// is decoded by the first signature, so an undecodable key is found by the
/// first reader: that response goes out whole and is closed with the
/// refusal trailer. From then on this capability's pre-flight refuses, and
/// every reader gets the bare 503 before any shard byte. (The memory is the
/// capability's: one endpoint, one capability, one such response.)
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
        [0; 16],
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
