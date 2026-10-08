// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two HTTP stacks speaking to each other.
//!
//! `shekyl-p-fetch` cannot depend on `shekyl-p-serve` on the shipped graph
//! (`SF-D4`). This is a *dev* edge: `shekyl-p-loopback`'s SOCKS5 shim in
//! front of a real `PServeEndpoint`, so a mismatch in envelope layout,
//! header set, or request grammar fails here instead of in the field.

use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_curve_tree::ServedFrameHeader;
use shekyl_p_fetch::{FetchError, NextMove, PFetchClient, Timeouts};
use shekyl_p_loopback::{
    endpoint_and_client, fetch_target, one_leaf, request_header, AcceptAny, PServeEndpoint,
    FIXTURE_SHARD_ID,
};
use shekyl_p_serve::{
    PassKey, PassSigner, SignRefused, TestKeySigner, PASS_COUNTERSIGNATURE_MESSAGE_LEN,
};
use shekyl_types::BlockHeight;

const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

/// Bounds for an ephemeral signer. The sign is local, so the body window
/// is the short one. The resident-key proving test waits on the stake
/// actor and uses a wider body window.
fn ephemeral_timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(1_000),
        body_stall: Duration::from_millis(1_000),
        body_total: Duration::from_millis(2_000),
    }
}

/// A real endpoint holding [`FIXTURE_SHARD_ID`] behind `signer`, and a
/// client aimed at it through the shim.
async fn stacks(signer: Arc<dyn PassSigner>) -> (PServeEndpoint, PFetchClient) {
    endpoint_and_client(FIXTURE_SHARD_ID, one_leaf(), signer, ephemeral_timeouts()).await
}

#[tokio::test]
async fn fetch_client_accepts_a_real_served_body() {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let public: HybridPublicKey = signer.public_key().clone();
    let (_ep, client) = stacks(Arc::clone(&signer) as Arc<dyn PassSigner>).await;
    let shard = client
        .fetch(
            &fetch_target(public, FIXTURE_SHARD_ID),
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect("the two stacks speak the same contract");
    assert_eq!(shard.shard_id(), FIXTURE_SHARD_ID);
    // Envelope already stripped; remaining bytes are RF-D4 then the
    // segment. The transport crate does not parse the frame — this test
    // does, so a swapped envelope/frame order fails here.
    let mut rest = shard.body();
    let frame = ServedFrameHeader::read(&mut rest).expect("RF-D4 frame ahead of the envelope");
    assert_eq!(frame.leaf_count(), 1);
    assert_eq!(rest, one_leaf().as_ref());
}

#[tokio::test]
async fn the_bare_answers_and_a_good_read_reach_the_client_as_typed_outcomes() {
    // The serve side's answers and the client's taxonomy, end to end: an
    // out-of-gate anchor is the 400 whether or not the shard is held, a
    // valid request for an unheld shard is the 404, and a held shard is
    // the read.
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let public: HybridPublicKey = signer.public_key().clone();
    let (ep, client) = stacks(Arc::clone(&signer) as Arc<dyn PassSigner>).await;

    for shard in [FIXTURE_SHARD_ID, FIXTURE_SHARD_ID + 1] {
        let err = client
            .fetch(
                &fetch_target(public.clone(), shard),
                &request_header(BlockHeight::from_raw(OWN_HEIGHT)),
                Arc::new(AcceptAny),
            )
            .await
            .expect_err("an anchor at the tip is outside the gate");
        assert!(matches!(err, FetchError::Rejected), "shard {shard}: {err}");
        assert_eq!(err.next_move(false), NextMove::RetryFreshAnchor);
        assert_eq!(err.next_move(true), NextMove::FailedRead);
    }

    let err = client
        .fetch(
            &fetch_target(public.clone(), FIXTURE_SHARD_ID + 1),
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect_err("not held");
    assert!(matches!(err, FetchError::Miss), "{err}");
    assert_eq!(err.next_move(false), NextMove::NotHeld);

    // The retry the 400 earns: same `P`, a fresh in-gate anchor.
    client
        .fetch(
            &fetch_target(public, FIXTURE_SHARD_ID),
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect("a fresh anchor inside the gate is served");
    assert_eq!(ep.served_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
}

/// A signer with a height and no key: it knows before the first byte.
struct Keyless;

impl PassKey for Keyless {
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Err(SignRefused::new("no key"))
    }

    fn sign_pass(
        &self,
        _message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new("no key"))
    }
}

impl PassSigner for Keyless {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

/// A signer that says it can sign and then fails: found out after the body.
struct RefusesLate;

impl PassKey for RefusesLate {
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }

    fn sign_pass(
        &self,
        _message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new("signer went away"))
    }
}

impl PassSigner for RefusesLate {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

fn any_key() -> HybridPublicKey {
    TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT))
        .public_key()
        .clone()
}

#[tokio::test]
async fn a_persona_with_no_key_is_unavailable_and_sends_no_shard() {
    // `P` holds the shard and has no key. It says so up front with the 503:
    // a failed read, not a miss — a held shard never 404s — and no shard
    // crosses the wire to go uncountersigned.
    let (ep, client) = stacks(Arc::new(Keyless)).await;
    let err = client
        .fetch(
            &fetch_target(any_key(), FIXTURE_SHARD_ID),
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect_err("no key");
    assert!(matches!(err, FetchError::Unavailable), "{err}");
    assert_eq!(err.next_move(false), NextMove::FailedRead);
    assert!(!err.retries_same_p());
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn a_signer_that_fails_after_the_body_is_a_failed_read() {
    // `P` sends all of the shard; its signer then refuses, and `P` closes
    // the response with the refusal trailer. The client reads `P`'s own
    // statement: a failed read, not a miss and not a stall to retry.
    let (ep, client) = stacks(Arc::new(RefusesLate)).await;
    let err = client
        .fetch(
            &fetch_target(any_key(), FIXTURE_SHARD_ID),
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect_err("no signature");
    assert!(matches!(err, FetchError::Unsigned), "{err}");
    assert_eq!(err.next_move(false), NextMove::FailedRead);
    assert!(!err.retries_same_p());
    assert_eq!(ep.late_sign_failure_count(), 1);
    assert_eq!(ep.sign_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
}
